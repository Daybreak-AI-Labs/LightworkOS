from __future__ import annotations

import importlib.util
import inspect
import logging
import threading
from contextlib import contextmanager

import pytest
from maverick.world_model_backends import postgres
from maverick.world_model_backends.postgres import PostgresWorldModel

_HAS_PSYCOPG = importlib.util.find_spec("psycopg") is not None


class RecordingCursor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...] | None]] = []

    def execute(self, sql: str, params: tuple[object, ...] | None = None) -> None:
        self.calls.append((sql, params))

    def fetchone(self):
        return (None,)


class RetentionCursor(RecordingCursor):
    rowcount = 2

    def fetchone(self):
        return (2,)


class FactWriteCursor(RecordingCursor):
    def fetchone(self):
        return (7,) if "RETURNING write_seq" in self.calls[-1][0] else None


class TemporalDeleteCursor(RecordingCursor):
    rowcount = 1

    def fetchone(self):
        return None


class FactTrustSnapshotCursor(RecordingCursor):
    def fetchall(self):
        return [("risk:vendor", "external value", 0)]


class EmptyFactCursor(RecordingCursor):
    def fetchone(self):
        return None

    def fetchall(self):
        return []


class ErasureReceiptCursor(RecordingCursor):
    def fetchone(self):
        return (2,)

    def fetchall(self):
        return [(201,), (202,)]


class SubjectFactPurgeCursor(RecordingCursor):
    def fetchall(self):
        # An own + compatibility-legacy row may share the same natural key.
        return [
            ("user:sms:alice:email",),
            ("user:sms:alice:email",),
            ("user:sms:alice:phone",),
        ]


class FactHistoryCursor(RecordingCursor):
    def fetchall(self):
        return [
            (1, "k", "legacy", 300.0, None, "old", 2, "internal", None),
            (2, "k", "own", 200.0, 300.0, "new", 3, "internal", "acme"),
        ]


def test_effective_history_splits_legacy_only_across_own_overlap():
    rows = [
        (1, "user:sms:alice:email", "legacy", 100.0, None, "old", 2, "internal", None),
        (2, "user:sms:alice:email", "own", 200.0, 300.0, "new", 3, "internal", "acme"),
    ]

    projected = postgres._effective_fact_history_rows(rows, "acme")

    assert [
        (row[2], row[3], row[4], row[8])
        for row in projected
    ] == [
        ("legacy", 100.0, 200.0, None),
        ("own", 200.0, 300.0, "acme"),
        ("legacy", 300.0, None, None),
    ]
    # The unbound administrative history keeps its prior raw multi-tenant view.
    assert postgres._effective_fact_history_rows(rows, None) == rows


def test_subject_fact_purge_locks_tables_and_accounts_returned_keys(monkeypatch):
    monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
    monkeypatch.setattr(postgres, "_strict_tenant_isolation", lambda: False)
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = SubjectFactPurgeCursor()

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)

    assert world.delete_facts_matching("sms:alice") == [
        "user:sms:alice:email",
        "user:sms:alice:phone",
    ]
    assert len(cur.calls) == 3
    lock_sql, lock_params = cur.calls[0]
    live_sql, live_params = cur.calls[1]
    history_sql, history_params = cur.calls[2]
    assert lock_sql == (
        "LOCK TABLE fact_history, facts IN SHARE ROW EXCLUSIVE MODE"
    )
    assert lock_params is None
    assert live_sql.startswith("DELETE FROM facts")
    assert live_sql.endswith("RETURNING key")
    assert history_sql.startswith("DELETE FROM fact_history")
    for sql in (live_sql, history_sql):
        assert "(tenant_id = %s OR tenant_id IS NULL)" in sql
    assert live_params == ("user:sms:alice:%", "acme")
    assert history_params == ("user:sms:alice:%", "acme")


def test_compatibility_history_projects_before_database_side_limit(monkeypatch):
    monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
    monkeypatch.setattr(postgres, "_strict_tenant_isolation", lambda: False)
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = FactHistoryCursor()

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)

    history = world.fact_history("k", limit=2)

    assert [version.value for version in history] == ["legacy", "own"]
    [(sql, params)] = cur.calls
    assert "WITH scoped AS" in sql
    assert "JOIN LATERAL" in sql
    assert "LAG(id) OVER (ORDER BY segment_start)" in sql
    assert sql.endswith("ORDER BY MIN(segment_start) DESC, id DESC LIMIT %s")
    assert params == ("k", "acme", "acme", 2)


def test_fact_upsert_advances_write_order_sequence(monkeypatch):
    """A same-timestamp update must sort after a newer key on Postgres too."""
    monkeypatch.setattr(postgres, "_active_tenant", lambda: None)
    monkeypatch.setattr(
        "maverick.world_model._temporal_memory_enabled", lambda: False
    )
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = FactWriteCursor()

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)
    world.upsert_fact("older-key", "updated last")

    sql, _ = cur.calls[-1]
    assert "write_seq = EXCLUDED.write_seq" in sql
    assert "SET id =" not in sql
    source = inspect.getsource(PostgresWorldModel.upsert_fact)
    assert '"SELECT MAX(updated_at)' not in source
    assert "fact-write-order:" not in source
    recall_source = inspect.getsource(PostgresWorldModel.get_facts)
    assert "ORDER BY write_seq DESC" in recall_source


def test_fact_upsert_refuses_the_withheld_placeholder_before_any_write(monkeypatch):
    """Strict at-rest mode reads a legacy plaintext fact back as a placeholder; sealing
    that placeholder over the stored value (a tag edit does) would destroy it."""
    from maverick.world_model import _UNSEALED_WITHHELD

    monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = FactWriteCursor()

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)
    with pytest.raises(ValueError, match="encryption migrate"):
        world.upsert_fact("hours", _UNSEALED_WITHHELD, tags=["finance"], expected_revision=3)
    assert cur.calls == []


def test_fact_revision_conflict_does_not_write_or_touch_history(monkeypatch):
    from maverick.fact_revision import FactConflict

    monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
    monkeypatch.setattr("maverick.world_model._temporal_memory_enabled", lambda: True)
    world = PostgresWorldModel.__new__(PostgresWorldModel)

    class CurrentCursor(RecordingCursor):
        def fetchone(self):
            return (9,)

    cur = CurrentCursor()

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)
    with pytest.raises(FactConflict):
        world.upsert_fact("hours", "stale", expected_revision=8)
    assert len(cur.calls) == 2
    assert "pg_advisory_xact_lock" in cur.calls[0][0]
    assert cur.calls[0][1] == ("fact:acme:hours",)
    assert "tenant_id = %s" in cur.calls[1][0]
    assert cur.calls[1][1] == ("hours", "acme")


def test_shared_fact_history_uses_exact_ownership_even_in_compatibility_mode(monkeypatch):
    monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
    monkeypatch.setattr(postgres, "_strict_tenant_isolation", lambda: False)
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = EmptyFactCursor()

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)
    assert world.fact_history("hours", owned_only=True) == []
    [(sql, params)] = cur.calls
    assert "tenant_id = %s" in sql and "tenant_id IS NULL" not in sql
    assert params == ("hours", "acme", 50)


def test_fact_value_and_trust_share_one_snapshot(monkeypatch):
    """A recall cannot splice a value and trust tier from separate writes."""
    monkeypatch.setattr(postgres, "_active_tenant", lambda: None)
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = FactTrustSnapshotCursor()
    tx_count = 0

    @contextmanager
    def tx():
        nonlocal tx_count
        tx_count += 1
        yield cur

    monkeypatch.setattr(world, "_tx", tx)

    assert world.get_facts_with_trust() == {
        "risk:vendor": ("external value", 0)
    }
    assert tx_count == 1
    assert len(cur.calls) == 1
    sql, params = cur.calls[0]
    assert "SELECT key, value, trust_tier FROM (" in sql
    assert "FROM facts" in sql
    assert "ORDER BY write_seq DESC" in sql
    assert params == ()


@pytest.mark.parametrize(
    ("method", "args", "kwargs", "expected_order"),
    [
        ("get_facts", (), {}, "ORDER BY write_seq DESC"),
        ("get_facts_with_trust", (), {}, "ORDER BY write_seq DESC"),
        ("get_fact", ("missing",), {}, "ORDER BY write_seq DESC LIMIT 1"),
        (
            "get_fact",
            ("missing",),
            {"as_of": 100.0},
            "ORDER BY valid_from DESC, id DESC LIMIT 1",
        ),
        ("list_facts", ("prefix:",), {}, "ORDER BY write_seq DESC"),
        (
            "search_facts",
            ("prefix:", "needle"),
            {},
            "ORDER BY write_seq DESC",
        ),
    ],
)
def test_unbound_fact_reads_omit_tenant_precedence(
    monkeypatch,
    method,
    args,
    kwargs,
    expected_order,
):
    """Unbound Postgres reads must never emit invalid ``ORDER BY 0`` SQL."""
    monkeypatch.setattr(postgres, "_active_tenant", lambda: None)
    monkeypatch.setattr(
        "maverick.crypto_at_rest.at_rest_enabled",
        lambda: False,
    )
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = EmptyFactCursor()

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)

    getattr(world, method)(*args, **kwargs)

    [(sql, _params)] = cur.calls
    assert expected_order in sql
    assert "tenant_id IS NULL" in sql
    assert "ORDER BY 0" not in sql
    assert "CASE WHEN" not in sql
    assert postgres._tenant_precedence() == ("", [])


def test_erasure_receipt_episode_count_scopes_through_parent_goal(monkeypatch):
    monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
    monkeypatch.setattr(postgres, "_strict_tenant_isolation", lambda: False)
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = ErasureReceiptCursor()

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)

    assert world.count_erasure_receipt_store(
        "episodes",
        conversation_ids=[1],
        goal_ids=[11],
    ) == 2

    assert len(cur.calls) == 2
    select_sql, select_params = cur.calls[0]
    count_sql, count_params = cur.calls[1]
    for sql in (select_sql, count_sql):
        assert "FROM episodes e JOIN goals g ON g.id = e.goal_id" in sql
        assert "(g.tenant_id = %s OR g.tenant_id IS NULL)" in sql
        assert "e.tenant_id" not in sql
    assert select_params == ([11], "acme")
    assert count_params == ([201, 202], "acme")


def test_temporal_delete_uses_same_per_key_advisory_lock(monkeypatch):
    monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
    monkeypatch.setattr(
        "maverick.world_model._temporal_memory_enabled", lambda: True
    )
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = TemporalDeleteCursor()

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)
    assert world.delete_fact("shared-key") == 1

    sql = [statement for statement, _params in cur.calls]
    lock_index = next(
        index
        for index, statement in enumerate(sql)
        if "pg_advisory_xact_lock" in statement
    )
    delete_index = next(
        index
        for index, statement in enumerate(sql)
        if statement.startswith("DELETE FROM facts")
    )
    assert lock_index < delete_index
    assert "fact:acme:shared-key" in str(cur.calls[lock_index][1])


def test_rls_sets_fail_closed_sentinel_without_active_tenant(monkeypatch):
    monkeypatch.setattr(postgres, "_active_tenant", lambda: None)
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    world._rls = True
    cur = RecordingCursor()

    world._set_tenant_guc(cur)

    assert cur.calls == [
        ("SELECT set_config('maverick.tenant', %s, true)", ("__maverick_no_tenant__",))
    ]


def test_rls_binds_the_active_tenant_on_every_transaction(monkeypatch):
    # The GUC the RLS policy keys on must carry the ACTIVE tenant verbatim, set
    # transaction-locally (is_local=true), so the database enforces the boundary
    # even on a query that carries no app-layer predicate.
    monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    world._rls = True
    cur = RecordingCursor()

    world._set_tenant_guc(cur)

    assert cur.calls == [
        ("SELECT set_config('maverick.tenant', %s, true)", ("acme",))
    ]


def test_no_guc_is_written_when_rls_is_off(monkeypatch):
    # With RLS off the app-layer _tenant_scope predicate is the boundary and the
    # backend must not touch the GUC (nothing to fail-close against).
    monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    world._rls = False
    cur = RecordingCursor()

    world._set_tenant_guc(cur)

    assert cur.calls == []


@pytest.mark.parametrize(
    "method,table",
    [
        ("purge_episodes_before", "episodes"),
        ("purge_goal_events_before", "goal_events"),
        ("purge_messages_before", "messages"),
    ],
)
def test_retention_purge_uses_exact_active_tenant(monkeypatch, method, table):
    monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = RetentionCursor()

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)

    assert getattr(world, method)(123.0, dry_run=True) == 2
    sql, params = cur.calls[0]
    assert f"FROM {table}" in sql
    assert "tenant_id = %s" in sql
    assert "IS NULL" not in sql
    assert params == (123.0, "acme")


def test_retention_purge_rejects_missing_active_tenant(monkeypatch):
    from maverick.paths import TenantPolicyError

    monkeypatch.setattr(postgres, "_active_tenant", lambda: None)
    world = PostgresWorldModel.__new__(PostgresWorldModel)

    with pytest.raises(TenantPolicyError, match="refusing unbound Postgres"):
        world.purge_goal_events_before(123.0)


def test_rls_policy_does_not_allow_unset_tenant_bypass():
    sql = PostgresWorldModel._rls_policy_sql("goals").lower()

    assert "current_setting('maverick.tenant'" in sql
    assert "tenant_id = nullif" in sql
    assert " with check " in f" {sql} "
    assert " or " not in sql
    assert "is null" not in sql


def test_rls_apply_raises_when_policy_cannot_be_installed_or_verified(monkeypatch):
    world = PostgresWorldModel.__new__(PostgresWorldModel)

    @contextmanager
    def failing_tx():
        raise PermissionError("no alter table")
        yield  # pragma: no cover

    monkeypatch.setattr(postgres, "_TENANT_TABLES", ["goals"])
    monkeypatch.setattr(world, "_tx", failing_tx)
    monkeypatch.setattr(world, "_rls_policy_is_active", lambda table: False)

    with pytest.raises(RuntimeError, match="could not be installed or verified on goals"):
        world._apply_rls()

def test_rls_covers_tables_added_after_the_v10_tenant_migration():
    # projects (v15) and fact_history (v18) carry tenant_id but were
    # absent from the RLS set, so a PG deployment left them app-layer-only. They
    # must be RLS-scoped, while staying OUT of the v10 column-add migration list.
    assert "projects" in postgres._RLS_TABLES
    assert "fact_history" in postgres._RLS_TABLES
    assert "erasure_receipts" in postgres._RLS_TABLES
    assert "approval_audit_outbox" in postgres._RLS_TABLES
    assert "projects" not in postgres._TENANT_TABLES      # not in the v10 ALTER set
    assert "fact_history" not in postgres._TENANT_TABLES
    assert "erasure_receipts" not in postgres._TENANT_TABLES
    assert "approval_audit_outbox" not in postgres._TENANT_TABLES
    # Every v10 tenant table is still RLS-covered.
    assert set(postgres._TENANT_TABLES).issubset(set(postgres._RLS_TABLES))


def test_rls_covers_the_workspace_scoped_webhook_and_alert_tables():
    # v42's webhook_subscriptions / webhook_deliveries / deadline_alerts carry
    # the active tenant id in a column called ``workspace``; they are
    # RLS-scoped on that column with the same fail-closed policy.
    for table in ("webhook_subscriptions", "webhook_deliveries", "deadline_alerts"):
        assert table in postgres._RLS_TABLES
        assert table not in postgres._TENANT_TABLES
        sql = PostgresWorldModel._rls_policy_sql(table).lower()
        assert f"policy mvk_tenant_isolation on {table}" in sql
        assert "workspace = nullif(current_setting('maverick.tenant', true), '')" in sql
        assert "tenant_id" not in sql
        assert sql.count("nullif(current_setting('maverick.tenant', true), '')") == 2
    # Every other RLS table still keys on tenant_id.
    assert "tenant_id = nullif" in PostgresWorldModel._rls_policy_sql("approvals")


def test_rls_policy_verification_reads_the_table_specific_column(monkeypatch):
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    # pg_get_expr's own rendering of the stock policy for webhook_deliveries.
    workspace = "(workspace = NULLIF(current_setting('maverick.tenant'::text, true), ''::text))"
    tenant_id = "(tenant_id = NULLIF(current_setting('maverick.tenant'::text, true), ''::text))"

    def policy(expression, name="mvk_tenant_isolation", permissive=True):
        # relrowsecurity, relforcerowsecurity, polname, polcmd, polpermissive,
        # polroles (0 = PUBLIC), USING, WITH CHECK
        return (True, True, name, "*", permissive, [0], expression, expression)

    def verify(rows):
        class _Cur:
            def execute(self, *_a, **_k):
                pass

            def fetchall(self):
                return rows

        @contextmanager
        def tx():
            yield _Cur()

        monkeypatch.setattr(world, "_tx", tx)
        return world._rls_policy_is_active("webhook_deliveries")

    assert verify([policy(workspace)]) is True
    # The generic tenant_id column is not this table's isolation column.
    assert verify([policy(tenant_id)]) is False
    # Another permissive policy could OR around isolation.
    assert verify([policy(workspace), policy("true", name="extra")]) is False
    # An additional restrictive policy only narrows access.
    assert verify([policy(workspace), policy("true", name="extra", permissive=False)]) is True
    # Without FORCE the table owner bypasses the policy.
    assert verify([(True, False, *policy(workspace)[2:])]) is False


# --- #51/#57: enterprise auto-on for strict isolation + RLS ----------------

@pytest.fixture
def _clean_toggle_env(monkeypatch):
    for var in ("MAVERICK_STRICT_TENANT_ISOLATION", "MAVERICK_PG_RLS"):
        monkeypatch.delenv(var, raising=False)
    # No config and not enterprise unless a test opts in.
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)


def test_toggles_default_off_without_enterprise(_clean_toggle_env):
    assert postgres._strict_tenant_isolation() is False
    assert postgres._rls_enabled() is False
    assert postgres._rls_explicitly_set() is False


def test_toggles_auto_on_under_enterprise(_clean_toggle_env, monkeypatch):
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)
    assert postgres._strict_tenant_isolation() is True
    assert postgres._rls_enabled() is True
    # Auto-on is NOT an explicit operator choice -> the boot preflight applies.
    assert postgres._rls_explicitly_set() is False


def test_explicit_env_off_overrides_enterprise(_clean_toggle_env, monkeypatch):
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "off")
    assert postgres._rls_enabled() is False
    assert postgres._strict_tenant_isolation() is False
    assert postgres._rls_explicitly_set() is True


def test_list_goals_filters_by_domain_and_project_id(monkeypatch):
    # SQLite's list_goals accepts domain=/project_id= (used by the
    # dashboard's project-detail page and domain-scoped inbox); the Postgres
    # port didn't, so both callers 500'd with a TypeError on this backend.
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = RecordingCursor()
    cur.fetchall = list

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)

    world.list_goals(domain="finance_sox", project_id=7, order="desc")

    assert len(cur.calls) == 1
    sql, params = cur.calls[0]
    assert "domain = %s" in sql
    assert "project_id = %s" in sql
    assert params == ("finance_sox", 7)


def test_list_goals_omits_domain_and_project_id_predicates_when_unset(monkeypatch):
    # No false positives: a plain call must not filter on either column.
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = RecordingCursor()
    cur.fetchall = list

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)

    world.list_goals()

    sql, params = cur.calls[0]
    assert "domain, project_id FROM goals" in sql
    assert "domain = %s" not in sql
    assert "project_id = %s" not in sql
    assert params == ()


def test_list_goals_can_exclude_unbound_legacy_rows(monkeypatch):
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = RecordingCursor()
    cur.fetchall = list

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)
    monkeypatch.setattr(postgres, "_active_tenant", lambda: "tenant-a")
    monkeypatch.setattr(postgres, "_strict_tenant_isolation", lambda: False)
    world.list_goals(owner="user:alice", strict_tenant=True)
    sql, params = cur.calls[0]
    assert "tenant_id = %s" in sql and "tenant_id IS NULL" not in sql
    assert params == ("user:alice", "tenant-a")


def test_board_approval_queries_require_exact_tenant(monkeypatch):
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    cur = RecordingCursor()
    cur.fetchall = list

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)
    monkeypatch.setattr(postgres, "_active_tenant", lambda: "tenant-a")
    monkeypatch.setattr(postgres, "_strict_tenant_isolation", lambda: False)
    world.pending_unattached_approval_ids("user:alice", limit=10)
    world.pending_goal_approval_ids([1, 2], limit=10)
    for sql, params in cur.calls:
        assert "tenant_id = %s" in sql and "tenant_id IS NULL" not in sql
        assert "tenant-a" in params


def test_explicit_env_on_is_explicit(_clean_toggle_env, monkeypatch):
    monkeypatch.setenv("MAVERICK_PG_RLS", "1")
    assert postgres._rls_enabled() is True
    assert postgres._rls_explicitly_set() is True


def test_config_toggle_resolves_when_env_absent(_clean_toggle_env, monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"world_model": {"rls": True, "strict_tenant_isolation": "yes"}},
    )
    assert postgres._rls_enabled() is True
    assert postgres._strict_tenant_isolation() is True
    assert postgres._rls_explicitly_set() is True


def test_preflight_refuses_boot_on_legacy_null_rows_when_auto_on(monkeypatch):
    # Enterprise auto-on (not explicit) + a table with NULL-tenant rows -> refuse.
    monkeypatch.setattr(postgres, "_rls_explicitly_set", lambda: False)
    monkeypatch.setattr(
        "maverick.world_model_backends.pg_rls.preflight",
        lambda conn, **kw: {"role": "app", "ready": False, "tables": {
            "goals": {"null_tenant_rows": 3, "owned_by_current_role": True},
            "facts": {"null_tenant_rows": 0, "owned_by_current_role": True},
        }},
    )
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    world._pool = None
    world.conn = object()
    with pytest.raises(RuntimeError, match="tenant backfill"):
        world._preflight_rls_or_die()


def test_preflight_passes_when_no_null_rows(monkeypatch):
    monkeypatch.setattr(postgres, "_rls_explicitly_set", lambda: False)
    monkeypatch.setattr(
        "maverick.world_model_backends.pg_rls.preflight",
        lambda conn, **kw: {"role": "app", "ready": True, "tables": {
            "goals": {"null_tenant_rows": 0, "owned_by_current_role": True},
        }},
    )
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    world._pool = None
    world.conn = object()
    world._preflight_rls_or_die()  # no raise


def test_preflight_refuses_boot_on_empty_tenant_event_batches(monkeypatch):
    monkeypatch.setattr(postgres, "_rls_explicitly_set", lambda: False)
    monkeypatch.setattr(
        "maverick.world_model_backends.pg_rls.preflight",
        lambda conn, **kw: {"tables": {"event_trigger_batches": {
            "null_tenant_rows": 0, "empty_tenant_rows": 1,
        }}},
    )
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    world._pool = None
    world.conn = object()
    with pytest.raises(RuntimeError, match="event_trigger_batches=1"):
        world._preflight_rls_or_die()


def test_preflight_failure_refuses_boot_when_auto_on(monkeypatch):
    # The auto-on gate exists to stop RLS hiding legacy rows; a preflight that
    # could not count them must not let the policy be forced anyway.
    monkeypatch.setattr(postgres, "_rls_explicitly_set", lambda: False)

    def _fails(conn, **kw):
        raise TimeoutError("statement timeout")

    monkeypatch.setattr("maverick.world_model_backends.pg_rls.preflight", _fails)
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    world._pool = None
    world.conn = object()
    with pytest.raises(RuntimeError, match="preflight could not run"):
        world._preflight_rls_or_die()


def test_preflight_counts_only_tables_not_yet_protected(monkeypatch):
    # Tables whose policy is already installed and forced are not re-counted;
    # when every table is protected the preflight (and its failure) is skipped.
    monkeypatch.setattr(postgres, "_rls_explicitly_set", lambda: False)
    from maverick.world_model_backends import pg_rls

    seen = {}

    def _preflight(conn, *, only=None):
        seen["tables"] = only
        raise TimeoutError("statement timeout")

    monkeypatch.setattr("maverick.world_model_backends.pg_rls.preflight", _preflight)
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    world._pool = None
    world.conn = object()
    monkeypatch.setattr(PostgresWorldModel, "_rls_policy_is_active",
                        lambda self, t, **kw: True)
    world._preflight_rls_or_die()  # all protected: no count, no refusal
    assert "tables" not in seen

    monkeypatch.setattr(PostgresWorldModel, "_rls_policy_is_active",
                        lambda self, t, **kw: t != "projects")
    with pytest.raises(RuntimeError, match="preflight could not run"):
        world._preflight_rls_or_die()
    assert seen["tables"] == ("projects",)
    assert "projects" in pg_rls._PREFLIGHT_TABLES


def test_preflight_skipped_when_explicitly_opted_in(monkeypatch):
    # Explicit MAVERICK_PG_RLS=1 keeps the old fail-closed path: no boot refusal
    # even with NULL rows present (operator knowingly opted in).
    monkeypatch.setattr(postgres, "_rls_explicitly_set", lambda: True)
    called = {"preflight": False}

    def _should_not_run(conn, **kw):  # pragma: no cover -- asserted not called
        called["preflight"] = True
        return {"tables": {}}

    monkeypatch.setattr(
        "maverick.world_model_backends.pg_rls.preflight", _should_not_run)
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    world._pool = None
    world.conn = object()
    world._preflight_rls_or_die()
    assert called["preflight"] is False


@pytest.mark.skipif(not _HAS_PSYCOPG, reason="psycopg not installed")
class TestReconnectOnBrokenConnection:
    """The single shared (non-pooled) connection must self-heal after
    a managed-Postgres failover or idle-connection reset instead of raising
    OperationalError on every call until the process restarts."""

    class _FakeCursor:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, params=None):
            self._conn.statements.append((sql, params))

        def close(self):
            pass

    class _FakeConnection:
        def __init__(self, *, breaks_on_cursor=False):
            self.closed = 0
            self._breaks_on_cursor = breaks_on_cursor
            self.committed = False
            self.rolled_back = False
            self.statements = []

        def cursor(self):
            if self._breaks_on_cursor:
                import psycopg
                raise psycopg.OperationalError(
                    "server closed the connection unexpectedly")
            return TestReconnectOnBrokenConnection._FakeCursor(self)

        def commit(self):
            self.committed = True

        def rollback(self):
            self.rolled_back = True

        def close(self):
            self.closed = 1

    def _world(self):
        world = PostgresWorldModel.__new__(PostgresWorldModel)
        world._pool = None
        world._rls = False
        world._lock = threading.RLock()
        world._tx_depth = threading.local()
        world._dsn = "postgresql://fake"
        world._connect_kwargs = {"autocommit": False}
        world._io_timeout_seconds = 0.25
        return world

    def test_already_closed_connection_is_reopened_before_use(self, monkeypatch):
        world = self._world()
        world._rls = True
        monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
        dead = self._FakeConnection()
        dead.closed = 1  # e.g. explicitly closed by a prior broken _tx()
        world.conn = dead
        fresh = self._FakeConnection()
        connect_calls = []

        def _fake_connect(dsn, *, io_timeout_seconds, autocommit=False):
            connect_calls.append((dsn, autocommit, io_timeout_seconds))
            return fresh

        from maverick.postgres_io import BoundedConnection
        monkeypatch.setattr(BoundedConnection, "connect", _fake_connect)

        with world._tx() as cur:
            cur.execute("SELECT 1")

        assert connect_calls == [("postgresql://fake", False, 0.25)]
        assert world.conn is fresh
        assert fresh.committed is True
        assert fresh.statements == [
            ("SELECT set_config('maverick.tenant', %s, true)", ("acme",)),
            ("SELECT 1", None),
        ]

    def test_connection_broken_mid_transaction_is_closed_not_left_dangling(
        self, monkeypatch,
    ):
        world = self._world()
        dying = self._FakeConnection(breaks_on_cursor=True)
        world.conn = dying
        import psycopg

        with pytest.raises(psycopg.OperationalError):
            with world._tx():
                pass  # never reached -- cursor() raises first

        assert dying.closed == 1  # explicitly closed, not left half-dead

    def test_next_tx_reconnects_after_a_broken_transaction(self, monkeypatch):
        world = self._world()
        world._rls = True
        monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
        dying = self._FakeConnection(breaks_on_cursor=True)
        world.conn = dying
        import psycopg

        with pytest.raises(psycopg.OperationalError):
            with world._tx():
                pass

        fresh = self._FakeConnection()
        connect_calls = []

        def _fake_connect(dsn, *, io_timeout_seconds, autocommit=False):
            connect_calls.append((dsn, autocommit, io_timeout_seconds))
            return fresh

        from maverick.postgres_io import BoundedConnection
        monkeypatch.setattr(BoundedConnection, "connect", _fake_connect)

        with world._tx() as cur:
            cur.execute("SELECT 1")

        assert world.conn is fresh
        assert fresh.committed is True
        assert connect_calls == [("postgresql://fake", False, 0.25)]
        assert fresh.statements == [
            ("SELECT set_config('maverick.tenant', %s, true)", ("acme",)),
            ("SELECT 1", None),
        ]


class _RoleCursor:
    """Answers the login-role lookup; any other statement is accepted silently."""

    def __init__(self, conn):
        self._conn = conn
        self._row = None

    def execute(self, sql, params=None):
        if "pg_roles" in sql:
            if self._conn.lookup_fails:
                raise RuntimeError("permission denied for table pg_roles")
            self._row = self._conn.role_row
        else:
            self._row = None

    def fetchone(self):
        return self._row

    def fetchall(self):
        return []

    def close(self):
        pass


class _RoleConnection:
    def __init__(self, role_row=(False, False), lookup_fails=False):
        self.closed = 0
        self.role_row = role_row
        self.lookup_fails = lookup_fails

    def cursor(self):
        return _RoleCursor(self)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        self.closed = 1


def _open_as(monkeypatch, *, conn=None, rls=False, enterprise=False):
    """Open a Postgres world on a fake login: no server, no migrations, no RLS DDL."""
    from maverick.postgres_io import BoundedConnection

    conn = conn or _RoleConnection()
    monkeypatch.setattr(BoundedConnection, "connect", lambda *args, **kwargs: conn)
    monkeypatch.setattr(postgres, "_rls_enabled", lambda: rls)
    monkeypatch.setattr(postgres, "_enterprise_default", lambda: enterprise)
    monkeypatch.setattr(postgres, "_pool_size", lambda: 0)
    monkeypatch.setattr(PostgresWorldModel, "_migrate", lambda self: None)
    monkeypatch.setattr(PostgresWorldModel, "_preflight_rls_or_die", lambda self: None)
    monkeypatch.setattr(PostgresWorldModel, "_apply_rls", lambda self: None)
    return PostgresWorldModel("postgresql://fake")


def _role_warnings(caplog):
    return [r for r in caplog.records
            if r.levelno == logging.WARNING and "row-level security" in r.getMessage()]


@pytest.mark.skipif(not _HAS_PSYCOPG, reason="psycopg not installed")
class TestDatabaseLoginBypassingRls:
    """A superuser or BYPASSRLS login skips every RLS policy, FORCE included, so
    the tenant policies protect nothing for it. Checked once, when the backend
    first connects."""

    def test_a_superuser_login_warns_once_and_is_reported(self, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger=postgres.__name__):
            world = _open_as(monkeypatch, conn=_RoleConnection(role_row=(True, False)), rls=True)

        assert len(_role_warnings(caplog)) == 1
        assert "superuser" in _role_warnings(caplog)[0].getMessage()
        assert "NOSUPERUSER NOBYPASSRLS" in _role_warnings(caplog)[0].getMessage()
        assert "superuser" in world.rls_bypass_reason

    def test_a_bypassrls_login_warns_once_and_is_reported(self, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger=postgres.__name__):
            world = _open_as(monkeypatch, conn=_RoleConnection(role_row=(False, True)), rls=True)

        assert len(_role_warnings(caplog)) == 1
        assert "BYPASSRLS" in world.rls_bypass_reason

    def test_a_login_with_neither_privilege_is_silent(self, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger=postgres.__name__):
            world = _open_as(monkeypatch, conn=_RoleConnection(role_row=(False, False)), rls=True)

        assert _role_warnings(caplog) == []
        assert world.rls_bypass_reason is None

    def test_enterprise_mode_relying_on_rls_refuses_to_open(self, monkeypatch):
        conn = _RoleConnection(role_row=(True, False))

        with pytest.raises(RuntimeError, match="row-level security.*superuser"):
            _open_as(monkeypatch, conn=conn, rls=True, enterprise=True)

        assert conn.closed == 1  # refused before any DDL, and the connection is released

    def test_rls_without_enterprise_mode_only_warns(self, monkeypatch, caplog):
        conn = _RoleConnection(role_row=(True, False))
        with caplog.at_level(logging.WARNING, logger=postgres.__name__):
            world = _open_as(monkeypatch, conn=conn, rls=True, enterprise=False)

        assert conn.closed == 0
        assert len(_role_warnings(caplog)) == 1
        assert "superuser" in world.rls_bypass_reason

    def test_enterprise_mode_without_rls_only_warns(self, monkeypatch, caplog):
        # Without the policies in use, the app-layer predicates still isolate
        # tenants, so refusing would be a stricter rule than the one written down.
        with caplog.at_level(logging.WARNING, logger=postgres.__name__):
            world = _open_as(monkeypatch, conn=_RoleConnection(role_row=(True, False)),
                             rls=False, enterprise=True)

        assert len(_role_warnings(caplog)) == 1
        # No policy is in use, so nothing is bypassed: the health check stays ok.
        assert world.rls_bypass_reason is None

    def test_a_failed_role_check_warns_once_and_never_crashes_the_open(self, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger=postgres.__name__):
            world = _open_as(monkeypatch, conn=_RoleConnection(lookup_fails=True),
                             rls=True, enterprise=True)

        assert world.rls_bypass_reason is None
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "Could not check" in warnings[0]


def test_create_approval_notifies_with_the_committing_world(monkeypatch):
    # The kernel notifier takes the world that committed the row first
    # (``_notify_approval_created(world, approval_id, provenance)``); the
    # Postgres backend must call it with the same shape, or every live
    # create_approval dies with a TypeError after the row is durable.
    monkeypatch.setattr(postgres, "_active_tenant", lambda: "acme")
    monkeypatch.setattr(postgres, "_strict_tenant_isolation", lambda: False)
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    rows = iter([None, (42,)])  # no context goal, then RETURNING id

    class _Cur(RecordingCursor):
        def fetchone(self):
            return next(rows)

    cur = _Cur()

    @contextmanager
    def tx():
        yield cur

    monkeypatch.setattr(world, "_tx", tx)
    seen: list[tuple[int, str | None, object]] = []

    def fake_created(approval_id, *, provenance=None, world=None):
        seen.append((approval_id, provenance, world))

    import maverick.approval_notify as approval_notify

    monkeypatch.setattr(approval_notify, "approval_created", fake_created)

    assert world.create_approval("payment", detail="support", provenance="slack") == 42
    assert seen == [(42, "slack", world)]
    insert_sql, insert_params = cur.calls[-1]
    assert insert_sql.startswith("INSERT INTO approvals(")
    assert insert_params[4] == "slack"


# ---- approval webhook events (the SQLite world announces these; so must this one) ----


class _ScriptedCursor(RecordingCursor):
    """Answers fetchone() from a script and reports one affected row."""

    rowcount = 1

    def __init__(self, answers) -> None:
        super().__init__()
        self.answers = list(answers)

    def fetchone(self):
        return self.answers.pop(0) if self.answers else None


def _approval_world(monkeypatch, cur):
    """A world whose transactions record whether one is open, and an event spy."""
    monkeypatch.setattr(postgres, "_active_tenant", lambda: None)
    monkeypatch.setattr(postgres, "_strict_tenant_isolation", lambda: False)
    world = PostgresWorldModel.__new__(PostgresWorldModel)
    state = {"open": False}
    told: list[tuple[str, int, dict, bool]] = []

    @contextmanager
    def tx():
        state["open"] = True
        try:
            yield cur
        finally:
            state["open"] = False

    def emit(event, **kwargs):
        told.append((event, int(kwargs["record_id"]), kwargs["payload"], state["open"]))
        return 0

    import maverick.webhook_events as webhook_events

    monkeypatch.setattr(world, "_tx", tx)
    monkeypatch.setattr(webhook_events, "emit", emit)
    return world, told


def test_create_approval_announces_it_to_webhook_subscribers_after_commit(monkeypatch):
    import maverick.approval_notify as approval_notify

    monkeypatch.setattr(approval_notify, "approval_created", lambda *args, **kwargs: None)
    world, told = _approval_world(monkeypatch, _ScriptedCursor([None, (42,)]))
    assert world.create_approval("payment", risk="high", detail="support") == 42
    assert told == [("approval.created", 42, {"risk": "high", "action": "payment"}, False)]


def test_a_single_approver_decision_is_announced_after_commit_and_a_refusal_is_not(monkeypatch):
    from maverick.world_model import Approval

    appr = Approval(id=5, action="payment", risk="high", scope=None, detail=None, provenance=None,
                    status="pending", requested_at=1.0, decided_at=None, approvals_required=1)
    world, told = _approval_world(monkeypatch, _ScriptedCursor([]))
    monkeypatch.setattr(world, "get_approval", lambda approval_id: appr)
    assert world.decide_approval(5, "approved", decided_by="user:dana") is True
    assert told == [("approval.decided", 5,
                     {"status": "approved", "decided_by": "user:dana", "action": "payment"}, False)]

    refused = _ScriptedCursor([])
    refused.rowcount = 0  # the audit outbox already owns this approval
    world, told = _approval_world(monkeypatch, refused)
    monkeypatch.setattr(world, "get_approval", lambda approval_id: appr)
    assert world.decide_approval(5, "approved", decided_by="user:dana") is False
    assert told == []


def test_a_single_approver_decision_locks_the_row_before_reading_the_outbox(monkeypatch):
    # The audited path locks the approval FOR UPDATE and inserts the outbox row
    # without touching the approval. A legacy UPDATE that waited on that lock
    # keeps its old snapshot, so the outbox must be read AFTER taking the lock.
    from maverick.world_model import Approval

    appr = Approval(id=5, action="payment", risk="high", scope=None, detail=None, provenance=None,
                    status="pending", requested_at=1.0, decided_at=None, approvals_required=1)
    audited = _ScriptedCursor([(1,)])  # the outbox row committed while we waited
    world, told = _approval_world(monkeypatch, audited)
    monkeypatch.setattr(world, "get_approval", lambda approval_id: appr)
    assert world.decide_approval(5, "denied", decided_by="system:consent") is False
    statements = [sql for sql, _ in audited.calls]
    assert "FOR UPDATE" in statements[0] and "approval_audit_outbox" in statements[1]
    assert not any(sql.startswith("UPDATE approvals") for sql in statements)
    assert told == []


def _delivery_answers():
    event = ("evt", 7, "approved", "user:dana", "approved", 10.0, None)
    return [event, None, ("approved", "user:dana", 10.0)]  # event, nothing else pending, the final vote


def test_a_delivered_final_vote_is_announced_only_after_the_guard_and_the_commit(monkeypatch):
    world, told = _approval_world(monkeypatch, _ScriptedCursor(_delivery_answers()))
    calls = []

    def guard():
        calls.append(1)
        if len(calls) == 2:  # the guard that runs just before the commit
            raise PermissionError("authority changed")

    with pytest.raises(PermissionError):
        world.mark_approval_audit_delivered("evt", effect_guard=guard)
    assert told == []

    world, told = _approval_world(monkeypatch, _ScriptedCursor(_delivery_answers()))
    assert world.mark_approval_audit_delivered("evt") is True
    assert told == [("approval.decided", 7, {"status": "approved", "decided_by": "user:dana"}, False)]


def test_receipt_tenant_accepts_the_raw_id_of_an_encoded_tenant(tmp_path, monkeypatch):
    # The manifest carries the raw tenant id; the backend's active tenant is
    # the path-encoded segment. A tenant like "acme:eu" must still store its
    # own receipts, and another tenant's id must still be refused.
    from maverick.paths import tenant_scope

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    with tenant_scope(tenant="acme:eu"):
        assert PostgresWorldModel._receipt_tenant("acme:eu") == "acme%3Aeu"
        with pytest.raises(ValueError, match="another tenant"):
            PostgresWorldModel._receipt_tenant("acme")
        with pytest.raises(ValueError, match="another tenant"):
            PostgresWorldModel._receipt_tenant("shared")
