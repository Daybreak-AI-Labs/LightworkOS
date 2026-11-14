"""Seal existing plaintext data after at-rest encryption is enabled.

Enabling at-rest encryption (``[encryption] at_rest``) only seals **new** writes;
rows written before are left plaintext and read back transparently (lazy
migration). This module force-seals that pre-existing plaintext so the whole
store is encrypted, not just new data. It is **idempotent** — already-bound
values are skipped and legacy sealed values are rebound — so it is safe to re-run.

The reseal happens **in place**. SQLite shreds the pre-encryption plaintext residue
(``secure_delete`` + VACUUM); Postgres uses a tenant-scoped transaction and marker.
SQLite operators who need a rollback copy may explicitly opt in to a
transactionally-consistent **plaintext backup** (:func:`backup_world_db`).

Exposed as ``maverick encryption migrate [--dry-run] [--backup]``.
"""
from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path

from .crypto_at_rest import (
    EncryptionUnavailable,
    at_rest_enabled,
    is_bound_str,
    is_sealed_str,
    seal_bound_to_str,
    seal_to_str,
    unseal_from_str,
)
from .file_lock import atomic_create_bytes, ensure_private_file, prepare_private_directory

log = logging.getLogger(__name__)

# (table, text-column) pairs that at-rest encryption seals. Names come from this
# fixed allow-set -- never user input -- so the f-string interpolation below is
# injection-free (same discipline as audit/retention.py).
_SEALED_COLUMNS: tuple[tuple[str, str], ...] = (
    ("turns", "content"),
    ("facts", "value"),
    ("messages", "content"),
    ("questions", "question"),
    ("questions", "answer"),
    ("goals", "title"),
    ("goals", "description"),
    ("goals", "result"),
    ("goal_events", "content"),
    ("episodes", "summary"),
    ("episodes", "outcome"),
    ("approvals", "action"),
    ("approvals", "scope"),
    ("approvals", "detail"),
    ("signoffs", "note"),
    ("artifacts", "content"),
    ("projects", "name"),
    ("projects", "description"),
    ("fact_history", "value"),
    ("goals", "connection_selection"),
    ("webhook_deliveries", "body"),
)

# fact_history rows are copies of fact values and are read with the facts
# binding; every other column is bound to its own name.
_BOUND_CONTEXT_ALIASES = {("fact_history", "value"): "facts.value"}


def bound_context(table: str, column: str) -> str:
    """The ``table.column`` binding a sealed value in that cell carries."""
    return _BOUND_CONTEXT_ALIASES.get((table, column), f"{table}.{column}")


def backup_world_db(db_path: Path) -> Path:
    """Write a private, transactionally-consistent snapshot of the world DB.

    Returns the backup path. Taken before an in-place reseal so a crash or key
    problem mid-migration is recoverable. The snapshot is a *pre-encryption* copy
    and therefore **plaintext**, so it is created ``0600`` and the operator should
    delete it once the migration is verified. Uses SQLite's online backup API, so
    the copy is consistent even with a live WAL sidecar.
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    dest = db_path.with_name(f"{db_path.name}.pre-encrypt-{ts}.bak")
    n = 1
    while dest.exists():  # avoid clobbering a same-second backup
        dest = db_path.with_name(f"{db_path.name}.pre-encrypt-{ts}.{n}.bak")
        n += 1
    # SQLite needs a pathname to back up into. Publish an empty, private regular
    # file with the shared no-follow atomic writer before any plaintext lands,
    # and require a private parent so SQLite sidecars inherit that boundary.
    # ``db_path`` is caller-selected; never silently change its parent ACL.
    prepare_private_directory(dest.parent)
    atomic_create_bytes(dest, b"")
    src = sqlite3.connect(str(db_path))
    try:
        dst = sqlite3.connect(str(dest))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    ensure_private_file(dest)
    return dest


def migrate_world_db(
    db_path: Path, *, dry_run: bool = False, backup: bool = False
) -> dict[str, int]:
    """Seal any remaining plaintext in the world DB's sensitive columns.

    Returns a ``{"table.column": rows_sealed}`` report. Requires at-rest
    encryption to be enabled (so the key is configured); raises
    :class:`EncryptionUnavailable` otherwise, or if the crypto backend / key is
    missing -- this never writes plaintext.

    By default no plaintext backup is written. If ``backup`` is True (and
    ``dry_run`` is not set), a plaintext snapshot of the DB is written via
    :func:`backup_world_db` before any row is resealed, so the in-place migration
    is recoverable. The backup is skipped when there is no plaintext to seal, so
    idempotent re-runs don't litter identical copies.
    """
    if not at_rest_enabled():
        raise EncryptionUnavailable(
            "at-rest encryption is not enabled; set [encryption] at_rest = true "
            "(or MAVERICK_ENCRYPT_AT_REST=1) before migrating"
        )
    report: dict[str, int] = {}
    if not db_path.exists():
        return report
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        # Phase 1 -- read-only scan: find the plaintext rows. No transaction/lock
        # is held after this (default isolation only locks on DML), so the backup
        # below can open its own connection cleanly.
        work: list[tuple[str, str, int, str]] = []
        for table, col in _SEALED_COLUMNS:
            try:
                rows = conn.execute(
                    f"SELECT rowid AS rid, {col} AS val FROM {table}"
                ).fetchall()
            except sqlite3.OperationalError:
                continue  # table/column absent on an older schema
            sealed = 0
            for r in rows:
                val = r["val"]
                # Plaintext, and tokens sealed before binding existed
                # (unbound MVKAR1), both need the bound seal.
                if val is None or is_bound_str(val):
                    continue
                sealed += 1
                if not dry_run:
                    work.append((table, col, r["rid"], val))
            report[f"{table}.{col}"] = sealed
        try:
            rows = conn.execute(
                "SELECT rowid AS rid, row AS val FROM harness_corpus "
                "WHERE kind IN ('pending', 'rejected')"
            ).fetchall()
        except sqlite3.OperationalError:
            pass  # corpus table absent on an older schema
        else:
            sealed = 0
            for r in rows:
                val = r["val"]
                if val is None or is_sealed_str(val):
                    continue
                sealed += 1
                if not dry_run:
                    work.append(("harness_corpus", "row", r["rid"], val))
            report["harness_corpus.row"] = sealed
        if dry_run or not work:
            log.info("encryption migrate (dry_run=%s): %s", dry_run, report)
            if not dry_run:
                if _has_message_index(conn):
                    # A store sealed before the index rebuild existed can still
                    # hold plaintext terms there; clear them on any re-run.
                    _clear_leftover_index(conn)
                _mark_if_sealed(conn, db_path)
            return report
        # Phase 2 -- optionally back up the plaintext, then reseal in place.
        if backup:
            path = backup_world_db(db_path)
            log.info("encryption migrate: backed up world DB to %s before reseal", path)
        # Zero freed cells as rows are re-sealed in place, so the pre-encryption
        # plaintext can't be recovered from the DB file's free list.
        conn.execute("PRAGMA secure_delete=ON")
        # The scan above intentionally holds no writer reservation (the backup
        # uses another connection). Never overwrite work edited after that scan.
        # Reports count only rows this execution actually changed; a subsequent
        # scan can find newer plaintext without mistaking it for a completed seal.
        report = dict.fromkeys(report, 0)
        for table, col, rid, val in work:
            if table == "harness_corpus":
                resealed = seal_to_str(val)
            else:
                plain = unseal_from_str(val) if is_sealed_str(val) else val
                resealed = seal_bound_to_str(plain, bound_context(table, col), bind_tenant=False)
            changed = conn.execute(
                f"UPDATE {table} SET {col} = ? WHERE rowid = ? AND {col} IS ?",
                (resealed, rid, val),
            )
            report[f"{table}.{col}"] += changed.rowcount
        _rebuild_message_index(conn)
        conn.commit()
        _shred_residue(conn, report)
        _mark_if_sealed(conn, db_path)
    finally:
        conn.close()
    log.info("encryption migrate (dry_run=%s): %s", dry_run, report)
    return report


def _mark_if_sealed(conn: sqlite3.Connection, db_path: Path) -> None:
    """Write the migrated marker only if no plaintext remains now: a write
    that landed after the scan must not be covered by the strict-read marker."""
    if not _unsealed_remaining(conn):
        _mark_migrated(db_path)


def _unsealed_remaining(conn: sqlite3.Connection) -> bool:
    """True while any sealed column still holds plaintext or an unbound token
    (a concurrent write that landed after the scan, say)."""
    for table, col in _SEALED_COLUMNS:
        try:
            rows = conn.execute(f"SELECT {col} AS val FROM {table}").fetchall()
        except sqlite3.OperationalError:
            continue
        if any(r["val"] is not None and not is_bound_str(r["val"]) for r in rows):
            return True
    try:
        rows = conn.execute(
            "SELECT row AS val FROM harness_corpus WHERE kind IN ('pending', 'rejected')"
        ).fetchall()
    except sqlite3.OperationalError:
        return False
    return any(r["val"] is not None and not is_sealed_str(r["val"]) for r in rows)


def _mark_migrated(db_path: Path) -> None:
    """Record next to the DB that no plaintext remains, so reads turn strict by
    themselves (see ``world_model.auto_strict_at_rest``)."""
    import json
    import time

    from .file_lock import atomic_write_text
    from .world_model import migrated_marker_path

    marker = migrated_marker_path(db_path)
    try:
        atomic_write_text(marker, json.dumps({
            "migrated_at": time.time(), "bound": True, "db": db_path.name,
        }) + "\n", mode=0o600)
    except OSError as exc:
        log.warning("encryption migrate: could not write %s (%s); reads stay "
                    "lenient until [encryption] strict is set", marker, exc)


def postgres_migration_scope(tenant: str | None) -> str:
    """Collision-free marker identity, including legacy rows without a tenant."""
    return "n:" if tenant is None else "t:" + tenant


def _postgres_column_scope(table: str, tenant: str | None) -> tuple[str, list]:
    # Mutations require exact ownership, not compatibility reads' NULL fallback.
    if table in {"goals", "facts", "approvals", "projects", "fact_history"}:
        return "s.tenant_id IS NOT DISTINCT FROM %s", [tenant]
    if table == "webhook_deliveries":
        # Scoped by the raw tenant id in ``workspace`` ('' when unbound), the
        # value webhook_subscriptions writes, not the path-encoded tenant_id.
        from .webhook_subscriptions import workspace_id

        workspace = workspace_id()
        if (tenant is None) != (workspace == ""):
            raise EncryptionUnavailable("the webhook workspace does not match the migrated tenant")
        return "s.workspace = %s", [workspace]
    parent, foreign_key = (("conversations", "conversation_id") if table == "turns"
                           else ("goals", "goal_id"))
    predicate = (f"EXISTS (SELECT 1 FROM {parent} p WHERE p.id=s.{foreign_key} "
                 "AND p.tenant_id IS NOT DISTINCT FROM %s)")
    # A NULL parent is legacy/unbound, but a parent hidden by RLS is NOT.
    if tenant is None and table in {"messages", "questions"}:
        predicate = f"(s.{foreign_key} IS NULL OR {predicate})"
    return predicate, [tenant]


def migrate_postgres_world(world, *, dry_run: bool = False) -> dict[str, int]:
    """Rebind the active tenant's sealed columns and atomically record completion.

    Locks the affected tables against writes during resealing, so a concurrent
    legacy writer cannot insert a missed row before the marker commits. Other
    tenants and legacy NULL-owned rows are never claimed by a named tenant.
    PostgreSQL retains old bytes in WAL/backups under its own retention policy.
    """
    if not at_rest_enabled():
        raise EncryptionUnavailable(
            "at-rest encryption is not enabled; set [encryption] at_rest = true "
            "(or MAVERICK_ENCRYPT_AT_REST=1) before migrating"
        )
    from .world_model_backends.postgres import _active_tenant

    tenant = _active_tenant()
    if world._rls and tenant is None:
        raise EncryptionUnavailable("Postgres RLS migration requires an active tenant")
    report: dict[str, int] = {}
    with world._tx() as cur:
        if not dry_run:
            tables = sorted({table for table, _ in _SEALED_COLUMNS}
                            | {"conversations", "harness_corpus", "encryption_migrations"})
            cur.execute("LOCK TABLE " + ", ".join(tables) + " IN SHARE ROW EXCLUSIVE MODE")
        for table, column in _SEALED_COLUMNS:
            scope, params = _postgres_column_scope(table, tenant)
            row_key = "goal_id" if table == "signoffs" else "id"
            cur.execute(f"SELECT s.{row_key}, s.{column} FROM {table} s WHERE {scope}", params)
            rows = [(key, value) for key, value in cur.fetchall()
                    if value is not None and not is_bound_str(value)]
            report[f"{table}.{column}"] = len(rows)
            if dry_run:
                continue
            for key, value in rows:
                plain = unseal_from_str(value) if is_sealed_str(value) else value
                sealed = seal_bound_to_str(plain, bound_context(table, column), bind_tenant=True)
                cur.execute(f"UPDATE {table} s SET {column}=%s WHERE s.{row_key}=%s AND {scope}",
                            [sealed, key, *params])
        # Pending/rejected corpus entries share SQLite's unbound sealing format.
        cur.execute("SELECT kind, key, seq, row FROM harness_corpus "
                    "WHERE tenant_id IS NOT DISTINCT FROM %s AND kind IN ('pending','rejected')",
                    (tenant,))
        corpus = [row for row in cur.fetchall() if not is_sealed_str(row[3])]
        report["harness_corpus.row"] = len(corpus)
        if not dry_run:
            for kind, key, seq, value in corpus:
                cur.execute("UPDATE harness_corpus SET row=%s WHERE kind=%s AND key=%s AND seq=%s "
                            "AND tenant_id IS NOT DISTINCT FROM %s",
                            (seal_to_str(value), kind, key, seq, tenant))
            cur.execute("INSERT INTO encryption_migrations(scope, tenant_id, migrated_at) "
                        "VALUES(%s,%s,%s) ON CONFLICT (scope) DO NOTHING",
                        (postgres_migration_scope(tenant), tenant, time.time()))
    if not dry_run:
        # Publish only after COMMIT; a failed decrypt/write must not enable strict reads.
        from .world_model import _POSTGRES_STORE_POSTURES
        _POSTGRES_STORE_POSTURES[(world._posture_identity, tenant)] = True
    return report


def _has_message_index(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages_fts'"
    ).fetchone() is not None


def _clear_leftover_index(conn: sqlite3.Connection) -> None:
    """Rebuild the leftover ``messages_fts`` index and shred what it freed.

    Raises :class:`EncryptionUnavailable` with a plain instruction when the
    database is in use, so the caller stops before writing the migrated
    marker: that marker must not claim no plaintext remains while the
    leftover index may still hold it."""
    try:
        conn.execute("PRAGMA secure_delete=ON")
        _rebuild_message_index(conn)
        conn.commit()
    except sqlite3.OperationalError as exc:
        if "locked" not in str(exc) and "busy" not in str(exc):
            raise
        conn.rollback()
        raise EncryptionUnavailable(
            "the message search index left by an earlier version may still hold "
            "text written before encryption, and it can only be rebuilt while "
            "the database is not in use; stop the application and run the "
            "migration again"
        ) from exc
    _shred_residue(conn, {"messages_fts": 1})


def _rebuild_message_index(conn: sqlite3.Connection) -> None:
    """Rebuild the pre-v49 ``messages_fts`` index when it is still present.

    Its update trigger deletes the old row and indexes the sealed token, but
    FTS5 keeps the deleted plaintext terms in its segment pages until they are
    merged. A rebuild discards the whole index, so the freed pages are zeroed
    by ``secure_delete`` and dropped by the VACUUM that follows."""
    try:
        conn.execute("INSERT INTO messages_fts(messages_fts) VALUES('rebuild')")
    except sqlite3.OperationalError as exc:
        if "no such table" not in str(exc):
            raise


def _shred_residue(conn: sqlite3.Connection, report: dict[str, int]) -> None:
    """Make the pre-encryption plaintext unrecoverable from the DB file.

    ``secure_delete=ON`` already zeroed the freed cells as rows were re-sealed in
    place; this additionally flushes + truncates the WAL sidecar (which can still
    hold pre-migration plaintext frames) and VACUUMs to rebuild the file with no
    residual free pages. Best-effort: if the DB is locked (e.g. the agent is
    running) the rebuild is skipped with a warning -- the in-place zeroing stands.
    """
    if not any(report.values()):
        return
    conn.isolation_level = None   # autocommit: VACUUM / checkpoint need no open txn
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.OperationalError as e:
        log.warning(
            "encryption migrate: could not VACUUM/checkpoint to shred residue "
            "(%s); freed pages were still zeroed in place via secure_delete", e,
        )


__all__ = ["backup_world_db", "migrate_world_db", "migrate_postgres_world"]
