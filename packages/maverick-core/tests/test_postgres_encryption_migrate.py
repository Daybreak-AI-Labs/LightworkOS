"""Live Postgres rebinding, tenant ownership and durable read posture."""
from __future__ import annotations

import pytest
from maverick import crypto_at_rest as car
from maverick import encryption_migrate as migration
from maverick import world_model as wm
from maverick.paths import reset_tenant, set_tenant, tenant_scope
from maverick.world_model_backends.postgres import PostgresWorldModel


@pytest.fixture
def world(postgres_test_dsn, monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "keys" / "at_rest.key")
    monkeypatch.setattr(wm, "_MIGRATED_STORES", set())
    monkeypatch.setattr(wm, "_LEGACY_STORES", set())
    monkeypatch.setattr(wm, "_UNREBOUND_BACKENDS", set())
    monkeypatch.setattr(wm, "_POSTGRES_STORE_POSTURES", {})
    with PostgresWorldModel(postgres_test_dsn) as model:
        yield model


def _seed(world, tenant):
    """One legacy value in every sealed column, including each ownership join."""
    with tenant_scope(tenant=tenant), world._tx() as cur:
        cur.execute("INSERT INTO goals(title, description, result, connection_selection, created_at, "
                    "updated_at, tenant_id) VALUES('title','description','result','selection',1,1,%s) RETURNING id",
                    (tenant,))
        goal = cur.fetchone()[0]
        cur.execute("INSERT INTO conversations(channel,user_id,created_at,last_seen,tenant_id) "
                    "VALUES('test','user',1,1,%s) RETURNING id", (tenant,))
        conversation = cur.fetchone()[0]
        specs = {
            "turns": dict(conversation_id=conversation, role="user", content="turn", ts=1),
            "facts": dict(key="legacy", value=car.seal_to_str("fact"), updated_at=1, tenant_id=tenant),
            "messages": dict(goal_id=goal, role="user", content="message", ts=1),
            "questions": dict(goal_id=goal, question="question", answer="answer", asked_at=1),
            "goal_events": dict(goal_id=goal, agent="test", kind="test", content="event", ts=1),
            "episodes": dict(goal_id=goal, started_at=1, summary="summary", outcome="outcome"),
            "approvals": dict(action="action", scope="scope", detail="detail", requested_at=1, tenant_id=tenant),
            "signoffs": dict(goal_id=goal, decision="approved", note="note", created_at=1),
            "artifacts": dict(goal_id=goal, content="artifact", created_at=1),
            "projects": dict(name="project", description="project description", created_at=1, tenant_id=tenant),
            "fact_history": dict(key="legacy", value="history", valid_from=1, tenant_id=tenant),
            "harness_corpus": dict(kind="pending", key="case", seq=1, row='{"prompt":"private"}', tenant_id=tenant),
        }
        for table, values in specs.items():
            columns = ",".join(values)
            placeholders = ",".join(["%s"] * len(values))
            cur.execute(f"INSERT INTO {table}({columns}) VALUES({placeholders})", list(values.values()))
    return goal


def _values(world, tenant):
    with tenant_scope(tenant=tenant), world._tx() as cur:
        result = {}
        for table, column in migration._SEALED_COLUMNS:
            scope, params = migration._postgres_column_scope(table, tenant)
            cur.execute(f"SELECT s.{column} FROM {table} s WHERE {scope}", params)
            result[f"{table}.{column}"] = cur.fetchone()[0]
        return result


def test_rebind_all_columns_is_tenant_scoped_and_enables_durable_strict_reads(world, monkeypatch):
    own_goal = _seed(world, "own")
    _seed(world, "other")
    _seed(world, None)
    own_before = _values(world, "own")
    other_before, null_before = _values(world, "other"), _values(world, None)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    with tenant_scope(tenant="own"):
        assert "postgres" not in wm._UNREBOUND_BACKENDS
        assert not wm.auto_strict_at_rest()
        expected = {f"{table}.{column}": 1 for table, column in migration._SEALED_COLUMNS}
        expected["harness_corpus.row"] = 1
        assert migration.migrate_postgres_world(world, dry_run=True) == expected
        assert _values(world, "own") == own_before
        with world._tx() as cur:
            cur.execute("SELECT COUNT(*) FROM encryption_migrations")
            assert cur.fetchone()[0] == 0
        assert migration.migrate_postgres_world(world) == expected
        assert wm.auto_strict_at_rest()
        for key, value in _values(world, "own").items():
            table, column = key.split(".")
            assert car.bound_str_context(value) == migration.bound_context(table, column)
            previous = own_before[key]
            assert car.unseal_from_str(value) == (car.unseal_from_str(previous) if car.is_sealed_str(previous) else previous)
        assert not any(migration.migrate_postgres_world(world).values())
        assert world.get_fact("legacy") == "fact"
        assert world.get_goal(own_goal).title == "title"
        with world._tx() as cur:
            cur.execute("UPDATE facts SET value=%s WHERE tenant_id='own'", (car.seal_to_str("injected"),))
            cur.execute("UPDATE goals SET title='injected' WHERE id=%s", (own_goal,))
        # Simulate a process reopening after another process completed migration.
        wm._POSTGRES_STORE_POSTURES.clear()
        with PostgresWorldModel(world._dsn) as reopened:
            assert reopened.get_fact("legacy") == wm._UNSEALED_WITHHELD
            assert reopened.get_goal(own_goal).title == wm._UNSEALED_WITHHELD
        # An already-open handle refreshes the same durable marker on its next transaction.
        wm._POSTGRES_STORE_POSTURES[(world._posture_identity, "own")] = False
        assert world.get_fact("legacy") == wm._UNSEALED_WITHHELD
    assert _values(world, "other") == other_before
    assert _values(world, None) == null_before
    with tenant_scope(tenant="other"):
        assert not wm.auto_strict_at_rest()
        assert world.get_fact("legacy") == "fact"
        own_bound = _values(world, "own")["messages.content"]
        with pytest.raises(car.EncryptionUnavailable):
            car.unseal_from_str(own_bound)
    with tenant_scope(tenant=None):
        assert migration.migrate_postgres_world(world) == expected
        assert world.get_fact("legacy") == "fact"


def test_failed_rebind_rolls_back_values_and_completion(world, monkeypatch):
    _seed(world, "own")
    before = _values(world, "own")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")

    def unavailable(value):
        raise car.EncryptionUnavailable("old key unavailable")

    monkeypatch.setattr(migration, "unseal_from_str", unavailable)
    with tenant_scope(tenant="own"):
        with pytest.raises(car.EncryptionUnavailable, match="old key unavailable"):
            migration.migrate_postgres_world(world)
        # turns.content was resealed before the legacy facts token failed.
        assert _values(world, "own") == before
        with world._tx() as cur:
            cur.execute("SELECT COUNT(*) FROM encryption_migrations")
            assert cur.fetchone()[0] == 0
        assert not wm.auto_strict_at_rest()


def test_rls_rebinding_records_only_visible_tenant_and_refuses_unbound_scope(world, monkeypatch):
    import secrets

    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    _seed(world, "own")
    _seed(world, "other")
    _seed(world, None)
    other_before, null_before = _values(world, "other"), _values(world, None)
    role = "mvk_rebind_" + secrets.token_hex(8)
    password = secrets.token_hex(24)
    with world._tx() as cur:
        cur.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
            sql.Identifier(role), sql.Literal(password)))
        cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
        cur.execute(sql.SQL("GRANT ALL ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(role)))
        cur.execute(sql.SQL("GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {}").format(sql.Identifier(role)))
    try:
        world._apply_rls()
        monkeypatch.setenv("MAVERICK_PG_RLS", "1")
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
        with tenant_scope(tenant="own"), PostgresWorldModel(
            make_conninfo(world._dsn, user=role, password=password)
        ) as scoped:
            assert scoped.rls_bypass_reason is None
            assert sum(migration.migrate_postgres_world(scoped).values()) == 21
            assert scoped.get_fact("legacy") == "fact"
            with scoped._tx() as cur:
                cur.execute("SELECT tenant_id FROM encryption_migrations")
                assert cur.fetchall() == [("own",)]
            with tenant_scope(tenant="other"), scoped._tx() as cur:
                cur.execute("SELECT tenant_id FROM encryption_migrations")
                assert cur.fetchall() == []
            token = set_tenant(None)
            try:
                with pytest.raises(car.EncryptionUnavailable, match="active tenant"):
                    migration.migrate_postgres_world(scoped)
            finally:
                reset_tenant(token)
        # The administrator can still inspect the rows hidden from the scoped role.
        assert _values(world, "other") == other_before
        assert _values(world, None) == null_before
    finally:
        with world._tx() as cur:
            cur.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            cur.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
