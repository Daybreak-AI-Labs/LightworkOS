"""Database-level tenant isolation for the shared governed-records table.

Runs only on the dedicated CI ``postgres`` job (``MAVERICK_PG_DSN`` set); the
mock-based SQL/policy assertions live in ``test_governed_records.py``. This
proves the real thing: ``governed_records`` carries an unconditional FORCED
row-level-security policy keyed on the transaction-local ``maverick.tenant``
GUC, so one tenant's control records are invisible AND unforgeable to another
at the DATABASE layer -- not merely through the app-layer predicate.

RLS is bypassed for superusers and for a table owner WITHOUT force, so (like
the world-model RLS proof in ``test_postgres_world.py``) this connects as a
dedicated NON-superuser NOBYPASSRLS role to actually exercise the policy.
"""
from __future__ import annotations

import os

import pytest

_DSN = os.environ.get("MAVERICK_PG_DSN")
pytestmark = pytest.mark.skipif(
    not _DSN, reason="MAVERICK_PG_DSN not set (no Postgres service)"
)

# The table + policy the Postgres governed-record backend installs (kept in
# sync with governed_records.PostgresGovernedRecordBackend._policy_sql).
_DDL = (
    "CREATE TABLE IF NOT EXISTS governed_records ("
    " tenant_id TEXT NOT NULL, namespace TEXT NOT NULL,"
    " record_id TEXT NOT NULL, revision BIGINT NOT NULL,"
    " record_json TEXT NOT NULL,"
    " created_at DOUBLE PRECISION NOT NULL,"
    " updated_at DOUBLE PRECISION NOT NULL,"
    " PRIMARY KEY (tenant_id, namespace, record_id))"
)
_POLICY = (
    "CREATE POLICY mvk_tenant_isolation ON governed_records "
    "USING (tenant_id = nullif(current_setting('maverick.tenant', true), '')) "
    "WITH CHECK (tenant_id = nullif(current_setting('maverick.tenant', true), ''))"
)
_INSERT = (
    "INSERT INTO governed_records"
    " (tenant_id, namespace, record_id, revision, record_json,"
    "  created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s)"
)


def _bind(cur, tenant: str) -> None:
    # The exact parameterizable, transaction-local GUC the backend sets.
    cur.execute("SELECT set_config('maverick.tenant', %s, true)", (tenant,))


def test_governed_records_rls_isolates_tenants_at_db_level():
    import psycopg
    from psycopg.conninfo import make_conninfo

    # 1. Owner (the superuser CI DSN) installs the table + FORCED policy and a
    #    non-superuser app role that is actually subject to it.
    with psycopg.connect(_DSN, autocommit=True) as c, c.cursor() as cur:
        cur.execute(_DDL)
        cur.execute("ALTER TABLE governed_records ENABLE ROW LEVEL SECURITY")
        cur.execute("ALTER TABLE governed_records FORCE ROW LEVEL SECURITY")
        cur.execute("DROP POLICY IF EXISTS mvk_tenant_isolation ON governed_records")
        cur.execute(_POLICY)
        cur.execute("DROP ROLE IF EXISTS mvk_gr_app")
        cur.execute(
            "CREATE ROLE mvk_gr_app LOGIN PASSWORD 'grpw' "  # pragma: allowlist secret
            "NOSUPERUSER NOBYPASSRLS"
        )
        cur.execute("GRANT ALL ON governed_records TO mvk_gr_app")

    app_dsn = make_conninfo(_DSN, user="mvk_gr_app", password="grpw")  # pragma: allowlist secret
    try:
        with psycopg.connect(app_dsn, autocommit=False) as conn:
            # alpha and beta each write one record; WITH CHECK ties each write
            # to the bound tenant.
            with conn.cursor() as cur:
                _bind(cur, "gr_alpha")
                cur.execute(_INSERT, ("gr_alpha", "ns", "recA", 1, "{}", 1.0, 1.0))
            conn.commit()
            with conn.cursor() as cur:
                _bind(cur, "gr_beta")
                cur.execute(_INSERT, ("gr_beta", "ns", "recB", 1, "{}", 1.0, 1.0))
            conn.commit()

            # A RAW read (no app-layer tenant predicate) under beta sees ONLY
            # beta's row -- the database, not the app, enforces the boundary.
            with conn.cursor() as cur:
                _bind(cur, "gr_beta")
                cur.execute("SELECT record_id FROM governed_records")
                assert [r[0] for r in cur.fetchall()] == ["recB"]
            conn.rollback()
            with conn.cursor() as cur:
                _bind(cur, "gr_alpha")
                cur.execute("SELECT record_id FROM governed_records")
                assert [r[0] for r in cur.fetchall()] == ["recA"]
            conn.rollback()

            # No active tenant -> empty GUC -> the policy matches no rows.
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM governed_records")
                assert int(cur.fetchone()[0]) == 0
            conn.rollback()

            # alpha cannot forge a row onto beta's tenant (WITH CHECK).
            with conn.cursor() as cur:
                _bind(cur, "gr_alpha")
                with pytest.raises(psycopg.errors.Error):
                    cur.execute(
                        _INSERT, ("gr_beta", "ns", "recX", 1, "{}", 1.0, 1.0)
                    )
            conn.rollback()
    finally:
        with psycopg.connect(_DSN, autocommit=True) as c, c.cursor() as cur:
            cur.execute(
                "DELETE FROM governed_records "
                "WHERE tenant_id IN ('gr_alpha', 'gr_beta')"
            )
            cur.execute("REASSIGN OWNED BY mvk_gr_app TO CURRENT_USER")
            cur.execute("DROP OWNED BY mvk_gr_app")
            cur.execute("DROP ROLE IF EXISTS mvk_gr_app")
