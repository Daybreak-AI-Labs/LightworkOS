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

from .postgres import _RLS_TABLES, _RLS_TENANT_COLUMN

_EMPTY_TENANT_TABLES = ("event_goal_admissions", "event_trigger_batches")
# Unbound writers stamp the empty string, not NULL, in these tables (the event
# inbox and receipts, and the workspace-keyed webhook/deadline tables).
_EMPTY_SCOPE_TABLES = (*_EMPTY_TENANT_TABLES, *_RLS_TENANT_COLUMN)
# Every table the RLS policy is forced on, so nothing it would hide goes
# unreported or un-backfilled. ``encryption_migrations`` is excluded: its scope
# key is derived from the tenant and is managed by the backend itself.
_PREFLIGHT_TABLES = tuple(t for t in _RLS_TABLES if t != "encryption_migrations")


def _column(table: str) -> str:
    return _RLS_TENANT_COLUMN.get(table, "tenant_id")


def _legacy_scope(table: str) -> str:
    col = _column(table)
    return f"({col} IS NULL OR {col} = '')" if table in _EMPTY_SCOPE_TABLES else f"{col} IS NULL"


def _stored_tenant(table: str, tenant_id: str) -> str:
    """The value the backend itself writes for ``tenant_id`` in ``table``.

    ``tenant_id`` columns hold the path-encoded segment
    (``paths.current_tenant_strict``); the workspace-keyed tables hold the raw
    id. Binding anything else assigns rows to a value no tenant queries with.
    """
    from ..paths import _tenant_segment, canonical_tenant_id

    canonical = canonical_tenant_id(tenant_id.strip())
    return canonical if table in _RLS_TENANT_COLUMN else _tenant_segment(canonical)

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


def preflight(conn) -> dict[str, Any]:
    """Read-only readiness report for enabling RLS.

    For each tenant-scoped table: its owner, whether the *current* role owns it
    (only the owner can ALTER / CREATE POLICY), and the count of legacy
    NULL-tenant rows and empty-tenant event rows that RLS would hide. ``ready``
    is True only when every table exists, is owned by the current role, and has
    no unscoped rows.
    """
    cur = conn.cursor()
    cur.execute("SELECT current_user")
    role = cur.fetchone()[0]
    tables: dict[str, dict[str, Any]] = {}
    ready = True
    for t in _PREFLIGHT_TABLES:
        # to_regclass returns NULL (no error) for a table that isn't there yet,
        # so a pre-migration DB reports cleanly instead of raising.
        cur.execute("SELECT to_regclass(%s)", (t,))
        if cur.fetchone()[0] is None:
            tables[t] = {"owner": None, "owned_by_current_role": False,
                         "null_tenant_rows": 0, "empty_tenant_rows": 0, "missing": True}
            ready = False
            continue
        cur.execute(
            "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = %s::regclass",
            (t,),
        )
        owner = cur.fetchone()[0]
        col = _column(t)
        cur.execute(f"SELECT count(*) FROM {t} WHERE {col} IS NULL")
        nulls = int(cur.fetchone()[0])
        empty = 0
        if t in _EMPTY_SCOPE_TABLES:
            cur.execute(f"SELECT count(*) FROM {t} WHERE {col} = ''")
            empty = int(cur.fetchone()[0])
        owned = owner == role
        tables[t] = {"owner": owner, "owned_by_current_role": owned,
                     "null_tenant_rows": nulls, "empty_tenant_rows": empty}
        if not owned or nulls or empty:
            ready = False
    return {"role": role, "tables": tables, "ready": ready}


def backfill(conn, tenant_id: str, *, dry_run: bool = False) -> dict[str, int]:
    """Assign legacy NULL-tenant rows and empty-tenant event rows to a tenant.

    So forcing RLS scopes those pre-tenancy rows to ``tenant_id`` instead of
    hiding them. Idempotent (already-scoped rows are untouched). Returns
    ``{table: rows_assigned}``; ``--dry-run`` counts without writing.
    A destination-key conflict rolls back the entire migration; observed event
    batches and receipts are never merged or discarded to make it succeed.
    """
    if not str(tenant_id or "").strip():
        raise ValueError("backfill requires a non-empty tenant id")
    if not dry_run and getattr(conn, "autocommit", False):
        raise ValueError("backfill requires a connection with autocommit disabled")
    cur = conn.cursor()
    report: dict[str, int] = {}
    try:
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
            conn.commit()
    except Exception as exc:
        if not dry_run:
            conn.rollback()
        if getattr(exc, "sqlstate", None) == "23505":
            raise ValueError(
                "legacy tenant records conflict with the destination tenant; "
                "no rows were reassigned; reconcile the conflicting records before retrying"
            ) from exc
        raise
    return report


__all__ = ["resolve_dsn", "connect", "preflight", "backfill"]
