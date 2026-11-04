"""Seal existing plaintext data after at-rest encryption is enabled.

Enabling at-rest encryption (``[encryption] at_rest``) only seals **new** writes;
rows written before are left plaintext and read back transparently (lazy
migration). This module force-seals that pre-existing plaintext so the whole
store is encrypted, not just new data. It is **idempotent** — already-sealed
values are skipped — so it is safe to re-run.

The reseal happens **in place** and shreds the pre-encryption plaintext residue
(``secure_delete`` + VACUUM). Operators who need a rollback copy may explicitly
opt in to a transactionally-consistent **plaintext backup** of the DB
(:func:`backup_world_db`).

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
    is_sealed_str,
    seal_to_str,
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
)


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
                if val is None or is_sealed_str(val):
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
            changed = conn.execute(
                f"UPDATE {table} SET {col} = ? WHERE rowid = ? AND {col} IS ?",
                (seal_to_str(val), rid, val),
            )
            report[f"{table}.{col}"] += changed.rowcount
        conn.commit()
        _shred_residue(conn, report)
    finally:
        conn.close()
    log.info("encryption migrate (dry_run=%s): %s", dry_run, report)
    return report


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


__all__ = ["backup_world_db", "migrate_world_db"]
