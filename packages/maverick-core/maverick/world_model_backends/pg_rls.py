"""Guided opt-in for Postgres Row-Level Security (RLS).

Enabling RLS (``[world_model] rls = true`` / ``MAVERICK_PG_RLS=1``) makes the
database itself enforce the tenant boundary -- defense in depth over the
app-layer ``_tenant_scope`` predicate. But the policy is strict, fail-closed
equality: a row is visible/writable only when its ``tenant_id`` equals the active
tenant (``postgres._rls_policy_sql``). That has two sharp edges, so RLS must not
be flipped on blindly:

  - **Legacy unscoped rows vanish.** Pre-tenancy rows carry ``tenant_id IS NULL``
    (the event inbox and receipts use the empty string);
    ``NULL = <tenant>`` is never true, so once RLS is *forced* those rows become
    invisible **and** frozen (they also fail the ``WITH CHECK``).
  - **Only the table owner may install the policy.** ``_apply_rls`` runs
    ``ALTER TABLE ... ENABLE/FORCE ROW LEVEL SECURITY`` + ``CREATE POLICY``;
    a non-owner connection raises at startup instead.

This module is the safe on-ramp run *before* enabling RLS:

  - :func:`preflight` reports, per tenant-scoped table, whether the current role
    owns it (can install the policy) and how many legacy unscoped rows remain.
  - :func:`backfill` assigns those rows to a chosen tenant so RLS scopes
    them to that tenant instead of hiding them. Idempotent.

Exposed as ``maverick tenant rls-preflight`` and ``maverick tenant backfill``.

Table names come from the fixed :data:`_PREFLIGHT_TABLES` allow-set -- never
user input -- so the f-string interpolation here is injection-free (same
discipline as the rest of the backend); the tenant id is always a bound param.
"""
from __future__ import annotations

import os
from typing import Any

from .postgres import _RLS_RAW_TENANT_TABLES, _RLS_STAMPED_TABLES, _RLS_TABLES, _RLS_TENANT_COLUMN

_EMPTY_TENANT_TABLES = ("event_goal_admissions", "event_trigger_batches")
# Unbound writers stamp the empty string, not NULL, in these tables (the event
# inbox and receipts, and the workspace-keyed webhook/deadline tables).
_EMPTY_SCOPE_TABLES = (*_EMPTY_TENANT_TABLES, *_RLS_TENANT_COLUMN)
# Every table the RLS policy is forced on, so nothing it would hide goes
# unreported or un-backfilled. ``encryption_migrations`` is excluded: its scope
# key is derived from the tenant and is managed by the backend itself. So are
# events and episodes: their tenant is a copy of their goal's, and follows it.
_PREFLIGHT_TABLES = tuple(t for t in _RLS_TABLES
                          if t != "encryption_migrations" and t not in _RLS_STAMPED_TABLES)


def _column(table: str) -> str:
    return _RLS_TENANT_COLUMN.get(table, "tenant_id")


def _legacy_scope(table: str) -> str:
    col = _column(table)
    return f"({col} IS NULL OR {col} = '')" if table in _EMPTY_SCOPE_TABLES else f"{col} IS NULL"


def _stored_tenant(table: str, tenant_id: str) -> str:
    """The value the backend itself writes for ``tenant_id`` in ``table``.

    ``tenant_id`` columns hold the path-encoded segment
    (``paths.current_tenant_strict``); the workspace-keyed and learning-store
    tables hold the raw id. Binding anything else assigns rows to a value no
    tenant queries with.
    """
    from ..paths import _tenant_segment, canonical_tenant_id

    canonical = canonical_tenant_id(tenant_id.strip())
    raw = table in _RLS_TENANT_COLUMN or table in _RLS_RAW_TENANT_TABLES
    return canonical if raw else _tenant_segment(canonical)

def resolve_dsn(dsn: str | None = None) -> str:
    """Resolve the Postgres DSN: explicit arg > ``MAVERICK_PG_DSN`` > config
    ``[world_model] dsn``. Returns ``""`` when none is configured."""
    if dsn:
        return dsn
    env = os.environ.get("MAVERICK_PG_DSN")
    if env:
        return env
    try:
        from ..config import load_config
        v = (load_config() or {}).get("world_model", {}).get("dsn")
    except Exception:
        v = None
    return str(v) if v else ""


def connect(dsn: str, *, autocommit: bool = False):
    """Open a raw psycopg connection. Read-only callers (:func:`preflight`) pass
    ``autocommit=True`` so a per-statement error never poisons later statements;
    :func:`backfill` uses a transaction (``autocommit=False``) and commits once."""
    try:
        import psycopg
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "psycopg not installed. Run: python -m pip install -e './packages/maverick-core[postgres]'"
        ) from e
    return psycopg.connect(dsn, autocommit=autocommit)


#: How :func:`preflight` counted a table's rows, in plain words. ``None``
#: (not counted) means the policies hide rows from this login, so any count
#: it made would be too low.
COUNT_METHODS = {
    "bypass": "this login bypasses row-level security",
    "no_policy": "row-level security is off for this table",
    "owner": "this login owns the table and the policy is not forced",
    "owner_no_force": "this login owns the table; the policy was lifted for the count "
                      "inside a transaction that was then rolled back",
}
#: How long the count waits for writers before giving up on one table.
_COUNT_LOCK_TIMEOUT_SECONDS = 5


def _count_method(bypass: bool, owned: bool, rls_on: bool, forced: bool) -> str | None:
    if bypass:
        return "bypass"
    if not rls_on:
        return "no_policy"
    if owned:
        return "owner_no_force" if forced else "owner"
    return None


def _count_legacy(cur, table: str) -> tuple[int, int]:
    col = _column(table)
    cur.execute(f"SELECT count(*) FROM {table} WHERE {col} IS NULL")
    nulls = int(cur.fetchone()[0])
    empty = 0
    if table in _EMPTY_SCOPE_TABLES:
        cur.execute(f"SELECT count(*) FROM {table} WHERE {col} = ''")
        empty = int(cur.fetchone()[0])
    return nulls, empty


def _count_legacy_without_force(conn, table: str) -> tuple[int, int] | None:
    """Count as the owner with FORCE lifted, in a transaction that is always
    rolled back, so the policy hides nothing and nothing is changed. ``None``
    when writers held the table for longer than the lock timeout."""
    try:
        with conn.transaction(force_rollback=True):
            cur = conn.cursor()
            cur.execute(f"SET LOCAL lock_timeout = '{int(_COUNT_LOCK_TIMEOUT_SECONDS)}s'")
            cur.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
            return _count_legacy(cur, table)
    except Exception as exc:
        if getattr(exc, "sqlstate", None) == "55P03":
            return None
        raise


def preflight(conn, *, only: tuple[str, ...] | None = None) -> dict[str, Any]:
    """Read-only readiness report for enabling RLS.

    For each tenant-scoped table: its owner, whether the *current* role owns it
    (only the owner can ALTER / CREATE POLICY), and the count of legacy
    NULL-tenant rows and empty-tenant event rows that RLS would hide.

    A login the policies apply to sees none of those rows, so the count is
    made where they are visible: as a superuser or BYPASSRLS login, on a table
    with no policy, or as the owner of a table whose policy is not forced. For
    a forced table the owner counts with FORCE lifted inside a transaction
    that is rolled back. ``counted_by`` names the way (:data:`COUNT_METHODS`);
    ``None`` means the rows could not be counted, and the counts are ``None``.

    ``ready`` is True only when every table exists, is owned by the current
    role, was counted, and has no unscoped rows. ``only`` limits the report to
    a subset of :data:`_PREFLIGHT_TABLES` (the boot gate skips tables already
    protected).
    """
    cur = conn.cursor()
    cur.execute("SELECT current_user")
    role = cur.fetchone()[0]
    cur.execute("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
    row = cur.fetchone()
    bypass = bool(row and row[0] is True)
    tables: dict[str, dict[str, Any]] = {}
    ready = True
    for t in _PREFLIGHT_TABLES if only is None else only:
        # to_regclass returns NULL (no error) for a table that isn't there yet,
        # so a pre-migration DB reports cleanly instead of raising.
        cur.execute("SELECT to_regclass(%s)", (t,))
        if cur.fetchone()[0] is None:
            tables[t] = {"owner": None, "owned_by_current_role": False,
                         "null_tenant_rows": 0, "empty_tenant_rows": 0, "missing": True,
                         "counted_by": None}
            ready = False
            continue
        cur.execute(
            "SELECT pg_get_userbyid(relowner), relrowsecurity, relforcerowsecurity "
            "FROM pg_class WHERE oid = %s::regclass",
            (t,),
        )
        owner, rls_on, forced = cur.fetchone()
        owned = owner == role
        method = _count_method(bypass, owned, bool(rls_on), bool(forced))
        counts: tuple[int, int] | None = None
        if method == "owner_no_force":
            counts = _count_legacy_without_force(conn, t)
            if counts is None:
                method = None
        elif method is not None:
            counts = _count_legacy(cur, t)
        nulls, empty = counts if counts is not None else (None, None)
        tables[t] = {"owner": owner, "owned_by_current_role": owned,
                     "null_tenant_rows": nulls, "empty_tenant_rows": empty,
                     "counted_by": method}
        if not owned or counts is None or nulls or empty:
            ready = False
    return {"role": role, "tables": tables, "ready": ready}


def _sealed_legacy_scope(table: str) -> str:
    """SQL for "this row of a sealed table belongs to a row backfill assigns".

    A child table (events, artifacts, questions, turns, ...) has no tenant
    column; its tenant is its parent goal's or conversation's."""
    if table in _PREFLIGHT_TABLES:
        return _legacy_scope(table)
    parent, key = ("conversations", "conversation_id") if table == "turns" else ("goals", "goal_id")
    return (f"EXISTS (SELECT 1 FROM {parent} p WHERE p.id = {table}.{key} "
            "AND p.tenant_id IS NULL)")


def _existing(cur, tables) -> list[str]:
    found = []
    for table in tables:
        cur.execute("SELECT to_regclass(%s)", (table,))
        if cur.fetchone()[0] is not None:
            found.append(table)
    return found


#: Values read from the server, opened and written back per round trip.
_RESEAL_BATCH = 1000
#: How long the backfill waits for the writers of the sealed tables to finish.
#: It then stops with nothing changed: a lock request left waiting holds up
#: every later write to those tables, behind however long a transaction runs.
_LOCK_TIMEOUT_SECONDS = 10


class BackfillReport(dict):
    """``{table: rows assigned}``; ``encrypted_values`` is how many sealed
    values were re-sealed (in a dry run: would be)."""

    encrypted_values: int = 0


def _open_legacy_value(value: str, context: str, tenant: str, keys: dict) -> str | None:
    """Plaintext of a value sealed with the empty binding, to be re-sealed;
    ``None`` when it already opens for ``tenant``. Raises
    ``EncryptionUnavailable`` when neither binding opens it.

    The row has no tenant, so an unbound writer sealed it: the empty binding
    is the expected one and is tried first."""
    from .. import crypto_at_rest
    from ..paths import tenant_scope

    try:
        with crypto_at_rest.unbound_row_scope():
            return crypto_at_rest.unseal_bound_from_str(value, context, keys)
    except crypto_at_rest.EncryptionUnavailable:
        with tenant_scope(tenant=tenant):
            crypto_at_rest.unseal_bound_from_str(value, context, keys)
        return None


def _reseal_column(conn, table: str, column: str, tenant: str, keys: dict, *,
                   dry_run: bool) -> tuple[int, list[str]]:
    """Re-seal one column's legacy values; return how many, and the rows whose
    value could not be opened. Rows are read through a server-side cursor and
    written back a batch at a time, so memory does not grow with the table."""
    from ..crypto_at_rest import _BOUND_STR_PREFIX, EncryptionUnavailable, seal_bound_to_str
    from ..encryption_migrate import bound_context
    from ..paths import tenant_scope

    key = "goal_id" if table == "signoffs" else "id"
    context = bound_context(table, column)
    done, stuck = 0, []
    # WITH HOLD only for a dry run on an autocommit connection, which has no
    # transaction for the cursor to live in.
    reader = conn.cursor(name=f"maverick_backfill_{table}_{column}",
                         withhold=bool(getattr(conn, "autocommit", False)))
    writer = conn.cursor()
    try:
        reader.execute(f"SELECT {key}, {column} FROM {table} "
                       f"WHERE {column} LIKE '{_BOUND_STR_PREFIX}%' AND {_sealed_legacy_scope(table)}")
        while rows := reader.fetchmany(_RESEAL_BATCH):
            batch = []
            for row_key, value in rows:
                try:
                    plain = _open_legacy_value(value, context, tenant, keys)
                except EncryptionUnavailable:
                    stuck.append(f"{table}.{column}, {key} {row_key}")
                    continue
                if plain is not None:
                    batch.append((plain, row_key))
            done += len(batch)
            if batch and not dry_run and not stuck:
                with tenant_scope(tenant=tenant):
                    sealed = [(seal_bound_to_str(plain, context, bind_tenant=True,
                                                 key_cache=keys), row_key)
                              for plain, row_key in batch]
                writer.executemany(f"UPDATE {table} SET {column} = %s WHERE {key} = %s", sealed)
    finally:
        reader.close()
        writer.close()
    return done, stuck


def _reseal_legacy_values(conn, tenant_id: str, *, dry_run: bool) -> int:
    """Re-seal the encrypted values of legacy rows for the tenant they go to.

    An unbound writer sealed them with the empty tenant binding. Once the row
    belongs to ``tenant_id`` its reads open values with that tenant's binding
    only, so without this the assigned records would read as withheld. A value
    that already opens for the tenant is left alone; plaintext and the older
    unbound format need no binding. A bound value that neither binding opens
    was sealed with a key this process lacks, or for another tenant: the
    backfill stops rather than assign a record its new owner could never read.

    Returns the number of values re-sealed (in a dry run: that would be).
    Writers of the sealed tables wait from here until the caller commits.
    """
    from ..encryption_migrate import _SEALED_COLUMNS
    from ..paths import canonical_tenant_id

    tenant = canonical_tenant_id(tenant_id.strip())
    cur = conn.cursor()
    tables = _existing(cur, sorted({table for table, _ in _SEALED_COLUMNS}))
    if not dry_run and tables:
        # No unbound writer may add a legacy row between this pass and the
        # assignment that follows (the same lock `maverick encryption migrate`
        # takes). The timeout also bounds the row locks of that assignment.
        locked = sorted({*tables, *_existing(cur, ("conversations",))})
        cur.execute(f"SET LOCAL lock_timeout = '{int(_LOCK_TIMEOUT_SECONDS)}s'")
        cur.execute("LOCK TABLE " + ", ".join(locked) + " IN SHARE ROW EXCLUSIVE MODE")
    keys: dict = {}
    done, stuck = 0, []
    for table, column in _SEALED_COLUMNS:
        if table in tables:
            count, failed = _reseal_column(conn, table, column, tenant, keys, dry_run=dry_run)
            done += count
            stuck += failed
    if stuck:
        raise ValueError(
            f"{len(stuck)} encrypted value(s) in records without a workspace cannot be "
            f"opened (first: {stuck[0]}). Either the encryption key on this computer is "
            "not the one Lightwork uses, or the value was saved for another workspace. "
            "No rows were reassigned. If it is the key, run this command on the computer "
            "that runs Lightwork, with the same encryption settings."
        )
    return done


def _policies_hide_legacy_rows(cur) -> bool:
    """True when row policies apply to this login on a table backfill assigns.

    The policies show a row only to its own tenant, so this login sees no
    legacy row: it could assign none and would count none."""
    cur.execute(
        "SELECT NOT (r.rolsuper OR r.rolbypassrls) AND EXISTS ("
        "SELECT 1 FROM pg_class c WHERE c.oid = ANY(SELECT to_regclass(t) FROM unnest(%s::text[]) t) "
        "AND c.relrowsecurity "
        "AND (c.relforcerowsecurity OR pg_get_userbyid(c.relowner) <> r.rolname)) "
        "FROM pg_roles r WHERE r.rolname = current_user",
        (list(_PREFLIGHT_TABLES),),
    )
    row = cur.fetchone()
    return bool(row) and row[0] is True


class BackfillCommitUncertain(Exception):
    """The database connection ended while the backfill was being committed,
    so it may or may not have taken effect."""

    sqlstate = "commit"


def database_error_message(exc: BaseException) -> str | None:
    """Plain words for a database error that stopped :func:`backfill`, or
    ``None`` when ``exc`` is not one. The backfill is one transaction: an error
    before its commit changed nothing; one during the commit may not have."""
    if isinstance(exc, BackfillCommitUncertain):
        return ("The connection to the database ended while the backfill was finishing, "
                "so it may have finished. Run it again to check: it does not change "
                "records it already assigned.")
    if not hasattr(exc, "sqlstate"):
        return None
    state = getattr(exc, "sqlstate", None)
    if state == "55P03":
        why = (f"Lightwork was busy writing to these records for more than "
               f"{int(_LOCK_TIMEOUT_SECONDS)} seconds, so the backfill stopped.")
    elif state == "40P01":
        why = "The database stopped the backfill because it collided with other work."
    else:
        detail = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        why = f"The database stopped the backfill ({detail})."
    return (f"{why} Nothing was changed. You can run it again: pick a quiet period, "
            "or stop Lightwork first.")


def backfill(conn, tenant_id: str, *, dry_run: bool = False) -> BackfillReport:
    """Assign legacy NULL-tenant rows and empty-tenant event rows to a tenant.

    So forcing RLS scopes those pre-tenancy rows to ``tenant_id`` instead of
    hiding them. Idempotent (already-scoped rows are untouched). Returns
    ``{table: rows_assigned}``; ``--dry-run`` counts without writing.
    A destination-key conflict rolls back the entire migration; observed event
    batches and receipts are never merged or discarded to make it succeed.
    Encrypted values of the assigned rows are re-sealed for ``tenant_id`` in
    the same transaction (:func:`_reseal_legacy_values`); a value this process
    cannot open stops the backfill, in a dry run too. Writers of the sealed
    tables wait while it runs. A login that row policies apply to cannot see
    legacy rows and is refused, rather than told that none were assigned.
    """
    if not str(tenant_id or "").strip():
        raise ValueError("backfill requires a non-empty tenant id")
    if not dry_run and getattr(conn, "autocommit", False):
        raise ValueError("backfill requires a connection with autocommit disabled")
    cur = conn.cursor()
    report = BackfillReport()
    try:
        if _policies_hide_legacy_rows(cur):
            raise ValueError(
                "Row-level security is on, and this database login cannot see records "
                "that have no workspace. It can neither assign them nor tell whether any "
                "remain. Nothing was changed. Run the backfill with a login that bypasses "
                "row-level security (a superuser or a BYPASSRLS role)."
            )
        report.encrypted_values = _reseal_legacy_values(conn, tenant_id, dry_run=dry_run)
        for t in _PREFLIGHT_TABLES:
            cur.execute("SELECT to_regclass(%s)", (t,))
            if cur.fetchone()[0] is None:
                report[t] = 0  # table not migrated yet -- nothing to assign
                continue
            if dry_run:
                cur.execute(f"SELECT count(*) FROM {t} WHERE {_legacy_scope(t)}")
                report[t] = int(cur.fetchone()[0])
            else:
                cur.execute(
                    f"UPDATE {t} SET {_column(t)} = %s WHERE {_legacy_scope(t)}",
                    (_stored_tenant(t, tenant_id),),
                )
                report[t] = cur.rowcount
        if not dry_run:
            try:
                conn.commit()
            except Exception as exc:
                if hasattr(exc, "sqlstate"):
                    raise BackfillCommitUncertain(str(exc)) from exc
                raise
    except Exception as exc:
        if not dry_run:
            try:
                conn.rollback()
            except Exception:  # a dropped connection has nothing left to roll back
                pass
        if getattr(exc, "sqlstate", None) == "23505":
            raise ValueError(
                "legacy tenant records conflict with the destination tenant; "
                "no rows were reassigned; reconcile the conflicting records before retrying"
            ) from exc
        raise
    return report


#: Most legacy rows :func:`shared_legacy_rows` counts per table, so the
#: doctor's read stays small on a store that holds millions of them.
_LEGACY_COUNT_CAP = 1000


def _named_workspace_known() -> bool:
    """A workspace is active, or the roster lists one."""
    from ..paths import current_tenant_id_strict
    from ..tenant.registry import list_tenants

    return bool(current_tenant_id_strict()) or bool(list_tenants())


#: The tables whose legacy rows a tenant's reads include in compatibility
#: mode (``postgres._tenant_scope``), and so the ones the doctor counts. The
#: other tables backfill assigns (message markers, receipts, the approval
#: outbox, event and webhook rows) are read by exact tenant only.
_SHARED_LEGACY_TABLES = ("goals", "facts", "fact_history", "conversations", "approvals", "projects")


def shared_legacy_rows(world) -> dict[str, Any] | None:
    """Legacy rows that every workspace reads in compatibility mode.

    The finding behind the ``maverick doctor`` warning, or ``None`` when there
    is nothing to warn about: strict isolation is on, no row lacks a workspace,
    or no named workspace exists (none is active, the roster lists none and the
    store holds no row of one). It uses the predicate of :func:`backfill` on
    :data:`_SHARED_LEGACY_TABLES`, counted up to :data:`_LEGACY_COUNT_CAP` per
    table (``capped``). ``maverick tenant backfill --dry-run`` reports more
    rows: it also assigns rows no other workspace reads.

    One statement, marked as a deployment-wide read; it counts rows and selects
    no record content. Under forced row-level security a login the policies
    apply to sees none of these rows, so nothing is reported for it.
    """
    from .postgres import _strict_tenant_isolation

    if _strict_tenant_isolation():
        return None
    counts = ", ".join(
        f"(SELECT count(*) FROM (SELECT 1 FROM {t} WHERE {_legacy_scope(t)} "
        f"LIMIT {_LEGACY_COUNT_CAP}) s)"
        for t in _SHARED_LEGACY_TABLES
    )
    named = " OR ".join(
        f"EXISTS (SELECT 1 FROM {t} WHERE {_column(t)} > '')" for t in _PREFLIGHT_TABLES
    )
    row = world.query(f"SELECT {counts}, ({named})", (), system=True)[0]
    found = [int(n) for n in row[:-1]]
    if not sum(found) or not (row[-1] or _named_workspace_known()):
        return None
    return {"rows": sum(found), "capped": _LEGACY_COUNT_CAP in found}


__all__ = ["resolve_dsn", "connect", "preflight", "backfill", "shared_legacy_rows", "COUNT_METHODS",
           "database_error_message", "BackfillReport", "BackfillCommitUncertain"]
