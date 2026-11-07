"""Postgres backend: versioned-migration planner + tenant read-scoping.

These exercise the *pure* Postgres logic (no live Postgres, no psycopg) plus
real SQLite upgrades of the two draft histories that used different v42 schemas.
The upgrade ladder and tenant predicates remain covered without a DB service.
The full round-trip lives in test_postgres_world.py (skipped without a DSN).
"""
from __future__ import annotations

from contextlib import contextmanager

import maverick.world_model_backends.postgres as pg
import pytest
from maverick import migration_governance, world_model
from maverick.deadline_alerts import SQLITE_SCHEMA as DEADLINE_SCHEMA
from maverick.webhook_subscriptions import SQLITE_SCHEMA as WEBHOOK_SCHEMA


def test_pending_from_fresh_db_applies_everything():
    pending = pg.pending_migrations(0)
    versions = [v for v, _ in pending]
    assert versions == sorted(versions)  # ascending
    assert versions[0] == 1  # base schema first
    assert pg._PG_SCHEMA_VERSION in versions  # tenant migration included


def test_pending_skips_already_applied():
    # A DB already at the latest version has nothing to do.
    assert pg.pending_migrations(pg._PG_SCHEMA_VERSION) == []
    # A DB at v1 still needs the tenant migrations (v10 columns, v11 uniques),
    # approval-claims (v13), goal-domain (v14), projects (v15), artifacts (v16),
    # share/signoff/origin (v17), temporal fact_history (v18), rate_events (v19),
    # N-of-M dual control (v21), cluster-wide halt (v22), provider spend (v23),
    # facts provenance columns (v24), fleet learning store (v25),
    # corpus family (v26), episode cache-token spend columns (v27), and
    # per-principal goal ownership (v28), erasure receipts (v29), and the
    # approval-audit transactional outbox (v30), and the 64-bit fact write
    # sequence (v31), execution principal binding (v32), and the shared-HALT
    # compare-and-delete generation (v33), and the event-admission request
    # digest + sealed contract columns (v41).
    pending = pg.pending_migrations(1)
    assert [v for v, _ in pending] == [
        10, 11, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v10 still needs the remaining upgrades.
    assert [v for v, _ in pg.pending_migrations(10)] == [
        11, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v11 still needs the rest of the ladder.
    assert [v for v, _ in pg.pending_migrations(11)] == [
        13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v13 still needs goal-domain + projects + artifacts + share/etc.
    assert [v for v, _ in pg.pending_migrations(13)] == [
        14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v14 still needs projects + artifacts + share/signoff/origin.
    assert [v for v, _ in pg.pending_migrations(14)] == [
        15, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v15 still needs artifacts + share/signoff/origin + fact_history.
    assert [v for v, _ in pg.pending_migrations(15)] == [
        16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v16 still needs the share/signoff/origin + fact_history migrations.
    assert [v for v, _ in pg.pending_migrations(16)] == [
        17, 18, 19, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v17 still needs fact_history + rate_events.
    assert [v for v, _ in pg.pending_migrations(17)] == [
        18, 19, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v18 still needs the rate_events migration.
    assert [v for v, _ in pg.pending_migrations(18)] == [
        19, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v19 still needs dual-control + halt + provider-spend + facts trust.
    assert [v for v, _ in pg.pending_migrations(19)] == [
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v21 still needs halt + provider-spend + facts trust.
    assert [v for v, _ in pg.pending_migrations(21)] == [
        22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v22 still needs provider-spend + facts trust.
    assert [v for v, _ in pg.pending_migrations(22)] == [
        23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v23 still needs the facts provenance migration + the store.
    assert [v for v, _ in pg.pending_migrations(23)] == [
        24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ]
    # A DB at v24 still needs the fleet learning store + corpus family.
    assert [v for v, _ in pg.pending_migrations(24)] == [25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51]
    # A DB at v25 still needs the corpus family.
    assert [v for v, _ in pg.pending_migrations(25)] == [26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51]


def test_pending_is_ordered_with_custom_ladder():
    ladder = [(3, ["c"]), (1, ["a"]), (2, ["b"])]
    assert pg.pending_migrations(0, ladder) == [(1, ["a"]), (2, ["b"]), (3, ["c"])]
    assert pg.pending_migrations(1, ladder) == [(2, ["b"]), (3, ["c"])]


def test_tenant_migration_adds_column_and_index_for_root_tables():
    stmts = dict(pg.MIGRATIONS)[10]
    joined = "\n".join(stmts)
    for table in pg._TENANT_TABLES:
        assert f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS tenant_id TEXT" in joined
        assert f"idx_pg_{table}_tenant" in joined


def test_tenant_unique_migration_makes_constraints_tenant_aware():
    stmts = dict(pg.MIGRATIONS)[11]
    joined = "\n".join(stmts)
    # The global UNIQUEs are dropped and replaced with COALESCE(tenant_id,'')
    # expression indexes so single-tenant (NULL) dedup is preserved.
    assert "DROP CONSTRAINT IF EXISTS facts_key_key" in joined
    assert "uq_pg_facts_tenant_key" in joined
    assert "uq_pg_conversations_tenant_chan_user" in joined
    assert "uq_pg_processed_tenant_chan_ext" in joined
    assert joined.count("COALESCE(tenant_id, '')") == 3  # one per unique table


def test_approval_claims_migration_adds_collaboration_columns():
    stmts = dict(pg.MIGRATIONS)[13]
    joined = "\n".join(stmts)
    assert "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS claimed_by TEXT" in joined
    assert "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS claimed_at DOUBLE PRECISION" in joined
    assert "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS decided_by TEXT" in joined


def test_schema_version_is_latest_migration():
    # v49 retires the unused message-search index (reviewed in migration
    # governance); v50 adds the per-task question index; v51 records which
    # approval decisions can still be undone.
    assert pg._PG_SCHEMA_VERSION == 51
    assert max(v for v, _ in pg.MIGRATIONS) == pg._PG_SCHEMA_VERSION
    ladder = dict(pg.MIGRATIONS)
    # Only the derived search index is retired; authoritative data is untouched.
    assert ladder[49] == ["DROP INDEX IF EXISTS idx_pg_messages_fts"]
    assert ladder[50] == ["CREATE INDEX IF NOT EXISTS idx_pg_questions_goal_id ON questions(goal_id, id)"]


@pytest.mark.parametrize("version", [41, 42, 46])
def test_combined_postgres_migration_reconciles_both_draft_histories(version):
    pending = pg.pending_migrations(version)
    # v48 adds approval_checks after the reconciliation; v49-v51 follow.
    assert [v for v, _ in pending][-5:] == [47, 48, 49, 50, 51]
    statements = dict(pending)[47]
    assert len(statements) == 8
    joined = "\n".join(statements)
    for table in (
        "goal_mutation_receipts", "webhook_subscriptions",
        "webhook_deliveries", "deadline_alerts",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in joined
    assert all(statement.startswith((
        "CREATE TABLE IF NOT EXISTS", "CREATE INDEX IF NOT EXISTS",
        "CREATE UNIQUE INDEX IF NOT EXISTS",
    )) for statement in statements)
    assert migration_governance.version_checksum(dict(pg.MIGRATIONS)[42]) == "2c22dea0a5f80cca"
    assert migration_governance.version_checksum(world_model.MIGRATIONS[42]) == "2c22dea0a5f80cca"
    assert len({v for v, _ in pg.MIGRATIONS}) == len(pg.MIGRATIONS)


@pytest.mark.parametrize("history,version", [
    ("fresh", None), ("baseline", 41), ("companion", 42),
    ("teardown", 42), ("companion", 46),
])
def test_combined_sqlite_upgrade_preserves_both_draft_histories(
    tmp_path, monkeypatch, history, version,
):
    database = tmp_path / "combined-world.db"
    prior_goal = None
    if version is not None:
        prior_ladder = {
            number: statements for number, statements in world_model.MIGRATIONS.items()
            if number <= version
        }
        if history == "teardown":
            prior_ladder[42] = [*WEBHOOK_SCHEMA, *DEADLINE_SCHEMA]
        with monkeypatch.context() as prior:
            prior.setattr(world_model, "SCHEMA_VERSION", version)
            prior.setattr(world_model, "MIGRATIONS", prior_ladder)
            with world_model.WorldModel(path=database) as old:
                assert old.schema_version == version
                cursor = old.conn.execute(
                    "INSERT INTO goals(title, description, status, created_at, updated_at, owner) "
                    "VALUES('Retained draft task', '', 'pending', 1800000000, 1800000000, 'operator')"
                )
                prior_goal = cursor.lastrowid
                if history == "teardown":
                    assert old.conn.execute(
                        "SELECT name FROM sqlite_master WHERE name='goal_mutation_receipts'"
                    ).fetchone() is None
                    old.conn.execute(
                        "INSERT INTO webhook_subscriptions(id, url, created_at, updated_at) "
                        "VALUES('retained-subscription', 'https://example.invalid/events', 1800000000, 1800000000)"
                    )
                old.conn.commit()

    with world_model.WorldModel(path=database) as upgraded:
        assert upgraded.schema_version == 51
        tables = {row[0] for row in upgraded.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        assert {
            "goal_mutation_receipts", "webhook_subscriptions",
            "webhook_deliveries", "deadline_alerts", "approval_checks",
        } <= tables
        if prior_goal is not None:
            assert tuple(upgraded.conn.execute(
                "SELECT title, connection_selection FROM goals WHERE id=?", (prior_goal,),
            ).fetchone()) == ("Retained draft task", "")
        else:
            prior_goal = upgraded.create_goal("Fresh task", owner="operator")
        if history == "teardown":
            assert upgraded.conn.execute(
                "SELECT url FROM webhook_subscriptions WHERE id='retained-subscription'"
            ).fetchone()[0] == "https://example.invalid/events"
        upgraded.conn.execute(
            "INSERT INTO goal_mutation_receipts(goal_id, kind, operation_id, actor, "
            "request_hash, receipt, created_at) VALUES(?, 'edit', 'upgrade-receipt', "
            "'operator', 'request-hash', 'retained-receipt', 1800000000)",
            (prior_goal,),
        )
        upgraded.conn.commit()

    with world_model.WorldModel(path=database) as reopened:
        assert reopened.schema_version == 51
        assert [tuple(row) for row in reopened.conn.execute(
            "SELECT receipt FROM goal_mutation_receipts WHERE operation_id='upgrade-receipt'"
        ).fetchall()] == [("retained-receipt",)]


def test_attachment_submission_migration_is_additive_tenant_scoped_and_cascaded():
    statement = "\n".join(dict(pg.MIGRATIONS)[38])
    assert "CREATE TABLE IF NOT EXISTS attachment_submissions" in statement
    assert "tenant_id TEXT" in statement and "owner TEXT NOT NULL" in statement
    assert "REFERENCES goals(id) ON DELETE CASCADE" in statement
    assert "attachment_submissions" in pg._RLS_TABLES


def test_fact_write_clock_migration_is_64_bit_and_indexed():
    joined = "\n".join(dict(pg.MIGRATIONS)[31])
    assert "write_seq BIGSERIAL" in joined
    assert "idx_pg_facts_write_seq" in joined


def test_goal_owner_migration_is_additive_and_backfills_legacy_rows():
    assert dict(pg.MIGRATIONS)[28] == [
        "ALTER TABLE goals ADD COLUMN IF NOT EXISTS owner "
        "TEXT NOT NULL DEFAULT '';",
    ]
    assert [v for v, _ in pg.pending_migrations(27)] == [28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51]


def test_erasure_receipt_migration_is_tenant_scoped_and_immutable():
    joined = "\n".join(dict(pg.MIGRATIONS)[29])
    assert "CREATE TABLE IF NOT EXISTS erasure_receipts" in joined
    assert "PRIMARY KEY (tenant_id, receipt_id)" in joined
    assert "erasure_receipts_no_update" in joined
    assert "erasure_receipts_no_early_delete" in joined
    assert [v for v, _ in pg.pending_migrations(28)] == [29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51]


def test_goal_execution_principal_migration_is_additive():
    assert dict(pg.MIGRATIONS)[32] == [
        "ALTER TABLE goals ADD COLUMN IF NOT EXISTS execution_principal "
        "TEXT NOT NULL DEFAULT '';",
    ]


def test_halt_generation_migration_is_additive_and_precedes_attempt_claims():
    assert dict(pg.MIGRATIONS)[33] == [
        "ALTER TABLE halt ADD COLUMN IF NOT EXISTS generation "
        "TEXT NOT NULL DEFAULT '';",
    ]
    assert [v for v, _ in pg.pending_migrations(32)] == [33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51]


def test_event_admission_contract_migration_is_additive():
    statements = dict(pg.MIGRATIONS)[41]
    assert all("ADD COLUMN IF NOT EXISTS" in s or "CREATE INDEX IF NOT EXISTS" in s for s in statements)
    assert [v for v, _ in pg.pending_migrations(40)] == [41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51]


def test_provider_operation_attempt_migration_is_global_and_additive():
    joined = "\n".join(dict(pg.MIGRATIONS)[35])
    assert "CREATE TABLE IF NOT EXISTS provider_operation_attempts" in joined
    assert "PRIMARY KEY (scope_sha256, operation_id, attempt_no)" in joined
    assert "UNIQUE (provider, period_key, request_id)" in joined
    assert "provider_operation_attempt_backfill" in joined


def test_postgres_halt_clear_is_generation_bound(monkeypatch):
    executed = []
    cleared = []

    class _Cursor:
        rowcount = 0
        selected_generation = "different-generation"

        def execute(self, statement, params=None):
            executed.append((statement, params))

        def fetchone(self):
            return (self.selected_generation,)

    cursor = _Cursor()

    @contextmanager
    def _tx():
        yield cursor

    world = object.__new__(pg.PostgresWorldModel)
    monkeypatch.setattr(world, "_tx", _tx)

    assert world.disarm_halt(
        expected_generation="observed-generation",
        durable_clear=lambda: cleared.append("unexpected"),
    ) is False
    assert "SELECT generation" in executed[-1][0]
    assert "FOR UPDATE" in executed[-1][0]
    assert cleared == []

    cursor.selected_generation = "current-generation"
    cursor.rowcount = 1
    assert world.disarm_halt(
        expected_generation="current-generation",
        durable_clear=lambda: cleared.append("cleared"),
    ) is True
    assert cleared == ["cleared"]
    assert "DELETE FROM halt" in executed[-1][0]
    assert "generation = %s" in executed[-1][0]
    assert executed[-1][1] == ("current-generation",)


def test_goal_decoder_keeps_owner_and_execution_principal_distinct(monkeypatch):
    monkeypatch.setattr(pg, "_unseal", lambda value, context=None: value)

    goal = pg._dec_goal_row(
        (
            7,
            None,
            "title",
            "description",
            "pending",
            1.0,
            2.0,
            None,
            None,
            "user:human-owner",
            "agent:worker",
        )
    )

    assert goal.owner == "user:human-owner"
    assert goal.execution_principal == "agent:worker"


def test_rate_events_migration_adds_table():
    joined = "\n".join(dict(pg.MIGRATIONS)[19])
    assert "CREATE TABLE IF NOT EXISTS rate_events" in joined
    assert "idx_pg_rate_events_key_ts" in joined


def test_artifacts_migration_adds_table():
    assert "CREATE TABLE IF NOT EXISTS artifacts" in "\n".join(dict(pg.MIGRATIONS)[16])


def test_share_signoff_origin_migration_adds_tables():
    joined = "\n".join(dict(pg.MIGRATIONS)[17])
    assert "CREATE TABLE IF NOT EXISTS share_links" in joined
    assert "CREATE TABLE IF NOT EXISTS signoffs" in joined
    assert "CREATE TABLE IF NOT EXISTS goal_origins" in joined


def test_goal_domain_migration_adds_domain_column():
    stmts = dict(pg.MIGRATIONS)[14]
    assert "ALTER TABLE goals ADD COLUMN IF NOT EXISTS domain TEXT" in "\n".join(stmts)


def test_projects_migration_adds_table_and_goal_fk():
    joined = "\n".join(dict(pg.MIGRATIONS)[15])
    assert "CREATE TABLE IF NOT EXISTS projects" in joined
    assert "ALTER TABLE goals ADD COLUMN IF NOT EXISTS project_id INTEGER" in joined


def test_tenant_scope_limits_unbound_reads_to_legacy_rows(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: None)
    assert pg._tenant_scope() == ("tenant_id IS NULL", [])
    assert pg._tenant_scope("g.tenant_id") == ("g.tenant_id IS NULL", [])


def test_erasure_scope_never_turns_unbound_admin_view_into_global_delete(
    monkeypatch,
):
    monkeypatch.setattr(pg, "_active_tenant", lambda: None)
    frag, params = pg._erasure_tenant_scope("g.tenant_id")
    assert frag == "g.tenant_id IS NULL"
    assert params == []


def test_fact_mutation_scope_is_exact_when_unbound_or_bound(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: None)
    assert pg._mutation_tenant_scope() == ("tenant_id IS NULL", [])

    monkeypatch.setattr(pg, "_active_tenant", lambda: "Acme")
    assert pg._mutation_tenant_scope("f.tenant_id") == (
        "f.tenant_id = %s",
        ["Acme"],
    )


def test_open_fact_history_uses_exact_mutation_scope(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "Acme")
    cursor = _RetentionCursor()
    model = pg.PostgresWorldModel.__new__(pg.PostgresWorldModel)

    _row, fragment, params = model._locked_open_fact_history(
        cursor, "shared-key", "Acme",
    )

    assert fragment == "tenant_id = %s"
    assert params == ["Acme"]
    sql, query_params = cursor.calls[1]
    assert "tenant_id = %s" in sql
    assert "OR tenant_id IS NULL" not in sql
    assert query_params == ("shared-key", "Acme")


@pytest.mark.parametrize(
    ("tenant", "scope", "params"),
    [
        (None, "tenant_id IS NULL", ("shared-key",)),
        ("Acme", "tenant_id = %s", ("shared-key", "Acme")),
    ],
)
def test_delete_fact_uses_exact_mutation_scope(
    monkeypatch, tenant, scope, params,
):
    from maverick import world_model as wm

    monkeypatch.setattr(pg, "_active_tenant", lambda: tenant)
    monkeypatch.setattr(wm, "_temporal_memory_enabled", lambda: False)
    cursor = _RetentionCursor()
    cursor.rowcount = 1
    model = pg.PostgresWorldModel.__new__(pg.PostgresWorldModel)
    monkeypatch.setattr(model, "_tx", lambda: _RetentionTx(cursor))

    assert model.delete_fact("shared-key") == 1
    assert "pg_advisory_xact_lock" in cursor.calls[0][0]
    sql, query_params = next(call for call in cursor.calls if call[0].lstrip().startswith("DELETE"))
    assert scope in sql
    assert "OR tenant_id IS NULL" not in sql
    assert query_params == params


def test_compatibility_precedence_prefers_active_tenant(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "Acme")
    fragment, params = pg._tenant_precedence("f.tenant_id")
    assert fragment == "CASE WHEN f.tenant_id = %s THEN 0 ELSE 1 END"
    assert params == ["Acme"]


def test_invalid_explicit_tenant_cannot_become_unscoped():
    from maverick.paths import InvalidTenantError, reset_tenant, set_tenant

    token = set_tenant("x" * 201)
    try:
        with pytest.raises(InvalidTenantError, match="too long"):
            pg._tenant_scope()
    finally:
        reset_tenant(token)


def test_corrupt_client_resolution_cannot_become_unscoped(monkeypatch):
    from maverick import client

    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(
        client,
        "_raw_client_id",
        lambda: (_ for _ in ()).throw(client.ClientBindingError("corrupt binding")),
    )
    with pytest.raises(client.ClientBindingError, match="corrupt binding"):
        pg._tenant_scope()


class _RetentionCursor:
    rowcount = 3

    def __init__(self):
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((sql, params))

    def fetchone(self):
        return (4,)


class _RetentionTx:
    def __init__(self, cursor):
        self.cursor = cursor

    def __enter__(self):
        return self.cursor

    def __exit__(self, exc_type, exc, tb):
        return False


@pytest.mark.parametrize(
    ("method_name", "table"),
    [
        ("purge_episodes_before", "episodes"),
        ("purge_goal_events_before", "goal_events"),
        ("purge_messages_before", "messages"),
    ],
)
def test_retention_requires_exact_active_tenant(monkeypatch, method_name, table):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "Acme")
    monkeypatch.setattr(pg, "_strict_tenant_isolation", lambda: False)
    cursor = _RetentionCursor()
    model = pg.PostgresWorldModel.__new__(pg.PostgresWorldModel)
    monkeypatch.setattr(model, "_tx", lambda: _RetentionTx(cursor))

    assert getattr(model, method_name)(123.0) == 3
    sql, params = cursor.calls[0]
    assert f"DELETE FROM {table}" in sql
    assert "tenant_id = %s" in sql
    assert "OR tenant_id IS NULL" not in sql
    assert params == (123.0, "Acme")


@pytest.mark.parametrize(
    "method_name",
    [
        "purge_episodes_before",
        "purge_goal_events_before",
        "purge_messages_before",
        "prune_goal_events",
        "prune_processed_messages",
        "prune_conversations",
    ],
)
def test_retention_refuses_unbound_execution(monkeypatch, method_name):
    from maverick.paths import TenantPolicyError

    monkeypatch.setattr(pg, "_active_tenant", lambda: None)
    model = pg.PostgresWorldModel.__new__(pg.PostgresWorldModel)
    monkeypatch.setattr(
        model,
        "_tx",
        lambda: (_ for _ in ()).throw(AssertionError("must not open transaction")),
    )

    with pytest.raises(TenantPolicyError, match="refusing unbound"):
        getattr(model, method_name)(123.0)


def test_legacy_prune_methods_use_exact_tenant(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "Acme")
    monkeypatch.setattr(pg.time, "time", lambda: 200.0)
    cursor = _RetentionCursor()
    model = pg.PostgresWorldModel.__new__(pg.PostgresWorldModel)
    monkeypatch.setattr(model, "_tx", lambda: _RetentionTx(cursor))

    assert model.prune_goal_events(older_than_seconds=50.0) == 3
    event_sql, event_params = cursor.calls[0]
    assert "tenant_id = %s" in event_sql
    assert "OR tenant_id IS NULL" not in event_sql
    assert event_params == (150.0, "Acme")

    cursor.calls.clear()
    assert model.prune_processed_messages(older_than_seconds=50.0) == 3
    processed_sql, processed_params = cursor.calls[0]
    assert "tenant_id = %s" in processed_sql
    assert "IS NULL" not in processed_sql
    assert processed_params == (150.0, "Acme")


def test_conversation_prune_uses_exact_tenant_for_parent_and_children(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "Acme")
    monkeypatch.setattr(pg.time, "time", lambda: 200.0)
    cursor = _RetentionCursor()
    model = pg.PostgresWorldModel.__new__(pg.PostgresWorldModel)
    monkeypatch.setattr(model, "_tx", lambda: _RetentionTx(cursor))

    assert model.prune_conversations(idle_for_seconds=50.0) == 3
    assert len(cursor.calls) == 2
    for sql, params in cursor.calls:
        assert "tenant_id = %s" in sql
        assert "IS NULL" not in sql
        assert params == (150.0, "Acme")


def test_tenant_scope_filters_to_active_tenant_null_tolerant(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "acme")
    monkeypatch.setattr(pg, "_strict_tenant_isolation", lambda: False)
    frag, params = pg._tenant_scope()
    assert frag == "(tenant_id = %s OR tenant_id IS NULL)"
    assert params == ["acme"]


def test_strict_tenant_isolation_excludes_legacy_null(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "acme")
    monkeypatch.setattr(pg, "_strict_tenant_isolation", lambda: True)
    frag, params = pg._tenant_scope()
    # Strict mode: only the tenant's own rows, no NULL-legacy tolerance.
    assert frag == "tenant_id = %s"
    assert params == ["acme"]


def test_strict_isolation_reads_env(monkeypatch):
    monkeypatch.delenv("MAVERICK_STRICT_TENANT_ISOLATION", raising=False)
    assert pg._strict_tenant_isolation() is False
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "1")
    assert pg._strict_tenant_isolation() is True
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "off")
    assert pg._strict_tenant_isolation() is False


def test_tenant_scope_custom_column(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "acme")
    frag, _ = pg._tenant_scope("goals.tenant_id")
    assert frag == "(goals.tenant_id = %s OR goals.tenant_id IS NULL)"


def test_create_goal_persists_owner_with_tenant(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "tenant-a")
    monkeypatch.setattr(pg.time, "time", lambda: 123.0)
    monkeypatch.setattr(pg, "_seal", lambda value, context=None: value)

    class FakeCursor:
        def __init__(self):
            self.calls = []

        def execute(self, sql, params=()):
            self.calls.append((sql, params))

        def fetchone(self):
            return (99,)

    class FakeTx:
        def __init__(self, cursor):
            self.cursor = cursor

        def __enter__(self):
            return self.cursor

        def __exit__(self, exc_type, exc, tb):
            return False

    cursor = FakeCursor()
    model = pg.PostgresWorldModel.__new__(pg.PostgresWorldModel)
    monkeypatch.setattr(model, "_tx", lambda: FakeTx(cursor))

    assert model.create_goal(
        "owned goal",
        "description",
        parent_id=4,
        owner="user:alice",
        execution_principal="agent:worker",
    ) == 99
    parent_sql, parent_params = cursor.calls[0]
    assert "tenant_id = %s FOR SHARE" in parent_sql
    assert parent_params == (4, "tenant-a")
    sql, params = cursor.calls[-1]
    # domain/project_id joined the
    # column list (signature parity with the SQLite backend), between
    # execution_principal and tenant_id.
    assert "owner, execution_principal, domain, project_id, tenant_id, connection_selection" in sql
    assert sql.count("%s") == len(params)
    assert params == (
        4,
        "owned goal",
        "description",
        123.0,
        123.0,
        "user:alice",
        "agent:worker",
        "",     # domain default
        None,   # project_id default
        "tenant-a",
        "",     # no selected connection references; no implicit authority
    )


def test_execution_binding_atomically_backfills_legacy_null_tenant(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "tenant-a")
    monkeypatch.setattr(pg, "_strict_tenant_isolation", lambda: False)
    cursor = _RetentionCursor()
    cursor.rowcount = 1
    model = pg.PostgresWorldModel.__new__(pg.PostgresWorldModel)
    monkeypatch.setattr(model, "_tx", lambda: _RetentionTx(cursor))

    assert model.bind_goal_execution_principal(42, "agent:worker") is True
    sql, params = cursor.calls[0]
    assert "execution_principal=%s" in sql
    assert "tenant_id=COALESCE(tenant_id, %s)" in sql
    assert "(tenant_id = %s OR tenant_id IS NULL)" in sql
    assert params == (
        "agent:worker",
        "tenant-a",
        42,
        "agent:worker",
        "tenant-a",
    )


def test_execution_binding_strict_tenant_cannot_claim_legacy_null(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "tenant-a")
    monkeypatch.setattr(pg, "_strict_tenant_isolation", lambda: True)
    cursor = _RetentionCursor()
    cursor.rowcount = 0
    model = pg.PostgresWorldModel.__new__(pg.PostgresWorldModel)
    monkeypatch.setattr(model, "_tx", lambda: _RetentionTx(cursor))

    assert model.bind_goal_execution_principal(42, "agent:worker") is False
    sql, params = cursor.calls[0]
    assert "tenant_id = %s" in sql
    assert "OR tenant_id IS NULL" not in sql
    assert params == (
        "agent:worker",
        "tenant-a",
        42,
        "agent:worker",
        "tenant-a",
    )


def test_owner_aware_claim_uses_exact_tenant_compare_and_swap(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "tenant-a")
    monkeypatch.setattr(pg, "_strict_tenant_isolation", lambda: False)
    monkeypatch.setattr(pg.time, "time", lambda: 123.0)
    cursor = _RetentionCursor()
    cursor.rowcount = 1
    # This goal has no event origin; the execution guard's SELECT must see no
    # event row before the owner/tenant compare-and-swap UPDATE.
    cursor.fetchone = lambda: None
    model = pg.PostgresWorldModel.__new__(pg.PostgresWorldModel)
    monkeypatch.setattr(model, "_tx", lambda: _RetentionTx(cursor))

    assert model.claim_goal_for_run(42, expected_owner="agent:worker") is True
    assert "goal_origins" in cursor.calls[0][0]
    assert "FOR UPDATE OF g,o" in cursor.calls[1][0]
    sql, params = cursor.calls[2]
    assert "status='pending' AND owner=%s" in sql
    assert "tenant_id = %s" in sql
    assert "OR tenant_id IS NULL" not in sql
    assert params == (123.0, 42, "agent:worker", "tenant-a")


def test_list_episodes_combines_owner_goal_and_tenant_scopes(monkeypatch):
    """Owner filtering must narrow, never replace, the tenant boundary."""
    monkeypatch.setattr(pg, "_active_tenant", lambda: "tenant-a")
    monkeypatch.setattr(pg, "_strict_tenant_isolation", lambda: False)

    class FakeCursor:
        def __init__(self):
            self.calls = []

        def execute(self, sql, params=()):
            self.calls.append((sql, params))

        def fetchall(self):
            return []

    class FakeTx:
        def __init__(self, cursor):
            self.cursor = cursor

        def __enter__(self):
            return self.cursor

        def __exit__(self, exc_type, exc, tb):
            return False

    cursor = FakeCursor()
    model = pg.PostgresWorldModel.__new__(pg.PostgresWorldModel)
    monkeypatch.setattr(model, "_tx", lambda: FakeTx(cursor))

    assert model.list_episodes(limit=7, goal_id=42, owner="user:alice") == []

    sql, params = cursor.calls[0]
    assert sql.count("JOIN goals g ON g.id = e.goal_id") == 1
    assert "e.goal_id = %s" in sql
    assert "g.owner = %s" in sql
    assert "(g.tenant_id = %s OR g.tenant_id IS NULL)" in sql
    assert params == (42, "user:alice", "tenant-a", 7)


def test_list_projects_applies_owner_and_tenant_scope(monkeypatch):
    monkeypatch.setattr(pg, "_active_tenant", lambda: "tenant-a")
    monkeypatch.setattr(pg, "_strict_tenant_isolation", lambda: False)

    class FakeCursor:
        def __init__(self):
            self.calls = []
            self._rows = [(7, "name", "desc", "alice", "eng", "active", 123.0)]

        def execute(self, sql, params=()):
            self.calls.append((sql, params))

        def fetchall(self):
            return self._rows

        def fetchone(self):
            return (2,)

    class FakeTx:
        def __init__(self, cursor):
            self.cursor = cursor

        def __enter__(self):
            return self.cursor

        def __exit__(self, exc_type, exc, tb):
            return False

    cursor = FakeCursor()
    model = pg.PostgresWorldModel.__new__(pg.PostgresWorldModel)
    monkeypatch.setattr(model, "_tx", lambda: FakeTx(cursor))

    projects = model.list_projects(owner="alice")

    assert projects[0]["owner"] == "alice"
    assert projects[0]["goal_count"] == 2
    project_sql, project_params = cursor.calls[0]
    assert "WHERE owner=%s AND (tenant_id = %s OR tenant_id IS NULL)" in project_sql
    assert project_params == ("alice", "tenant-a")
    goal_count_sql, goal_count_params = cursor.calls[1]
    assert goal_count_sql == (
        "SELECT COUNT(*) FROM goals WHERE project_id=%s "
        "AND (tenant_id = %s OR tenant_id IS NULL)"
    )
    assert goal_count_params == (7, "tenant-a")
