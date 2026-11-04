"""Execution threads retain tenant and credential authority without sibling leakage."""
from __future__ import annotations

import asyncio
import hashlib
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick.connections import bind_principal, current_principal
from maverick.flow.ir import Flow, FlowNode
from maverick.flow.runner import run_flow
from maverick.paths import current_tenant_id_strict, tenant_scope


def _flow(shape, kind="action"):
    work = FlowNode("work", kind, tool="http_get", brief="Fixture", output="seen",
                    timeout=0.001 if shape in {"timed", "nested"} else 0)
    child = Flow("child", "Child", "work", {"work": work})
    if shape in {"serial", "timed"}:
        return child
    if shape in {"foreach", "sequential"}:
        node = FlowNode("fan", "foreach", body=child, items="items",
                        concurrent=shape == "foreach", output="rows")
    else:
        node = FlowNode("fan", "parallel", branches=[child] if shape == "single" else [child, child.copy()], output="rows")
    return Flow(shape, shape, "fan", {"fan": node})


@pytest.mark.parametrize("shape", ["serial", "timed", "foreach", "parallel", "nested", "single", "sequential"])
@pytest.mark.parametrize("kind", ["agent", "action"])
def test_execution_hops_preserve_authority(shape, kind):
    def capture(*_):
        return (current_tenant_id_strict(), current_principal()), 1.0

    with tenant_scope(tenant="customer-alpha"), bind_principal("user:alice"):
        result = run_flow(_flow(shape, kind), agent_fn=capture, action_fn=capture,
                          data={"items": [1, 2]})
        assert result.status == "completed"
        rows = result.data.get("rows", [result.data])
        assert all(row["seen"] == ("customer-alpha", "user:alice") for row in rows)
        assert current_tenant_id_strict() == "customer-alpha"
        assert current_principal() == "user:alice"


def test_distinct_callers_and_siblings_never_share_context():
    def caller(name):
        def capture(*_):
            before = current_tenant_id_strict(), current_principal()
            with tenant_scope(tenant="temporary"), bind_principal("user:temporary"):
                pass
            assert (current_tenant_id_strict(), current_principal()) == before
            return before, 1.0
        with tenant_scope(tenant=name), bind_principal(f"user:{name}"):
            result = run_flow(_flow("nested"), agent_fn=capture, action_fn=capture)
            assert result.status == "completed"
            return [row["seen"] for row in result.data["rows"]]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(caller, ["alpha", "beta"]))
    assert results == [[("alpha", "user:alpha")] * 2, [("beta", "user:beta")] * 2]


@pytest.mark.parametrize("inside_loop", [False, True])
@pytest.mark.parametrize("raises", [False, True])
def test_workflow_async_adapter_retains_authority_and_propagates_errors(inside_loop, raises):
    from maverick.workflow import _drive

    async def work():
        assert current_tenant_id_strict() == "customer-alpha"
        assert current_principal() == "user:alice"
        if raises:
            raise ValueError("fixture failure")
        return "ok"

    def call():
        with tenant_scope(tenant="customer-alpha"), bind_principal("user:alice"):
            if raises:
                with pytest.raises(ValueError, match="fixture failure"):
                    _drive(work())
            else:
                assert _drive(work()) == "ok"
            assert current_principal() == "user:alice"

    async def outer():
        call()

    if inside_loop:
        asyncio.run(outer())
    else:
        call()


@pytest.mark.parametrize("shape", ["serial", "timed", "parallel", "foreach", "nested"])
def test_production_agent_admission_never_mutates_same_id_in_another_world(tmp_path, monkeypatch, shape):
    from maverick.flow.execution import default_agent_runner, execute
    from maverick.world_model import open_world

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr("maverick.client.client_id", lambda: None)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", world_model._INITIAL_DEFAULT_DB)
    with tenant_scope(tenant=None):
        root = open_world()
        root_id = root.create_goal("Unrelated root work", owner="user:bob")
        original = root.get_goal(root_id)
    with tenant_scope(tenant="unrelated"):
        other = open_world()
        other_id = other.create_goal("Unrelated tenant work", owner="user:carol")
        other_original = other.get_goal(other_id)
    with tenant_scope(tenant="customer-alpha"):
        world = open_world()
        # Zero wall allowance stops before any provider or sandbox construction.
        agent = default_agent_runner(world, owner="user:alice", user_id="alice", budget_wall_seconds=0)
        execute(_flow(shape, "agent"), agent_runner=agent, action_runner=lambda *_: ("unused", 1.0),
                owner="user:alice", data={"items": [1, 2]})
        goal = world.get_goal(1)
        assert goal.status == "blocked"
        assert goal.execution_principal == "user:alice"
        world.close()
    with tenant_scope(tenant=None):
        assert root.get_goal(root_id) == original
        root.close()
    with tenant_scope(tenant="unrelated"):
        assert other.get_goal(other_id) == other_original
        other.close()


@pytest.fixture
def governed_pg_dsn(postgres_test_dsn, monkeypatch):
    """Run admission reads Postgres governed records: least-privilege role plus the shared key."""
    import psycopg
    from maverick import crypto_at_rest
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    role = "mvk_flow_" + uuid.uuid4().hex[:12]
    password = secrets.token_urlsafe(24)
    with psycopg.connect(postgres_test_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE")
                      .format(sql.Identifier(role), sql.Literal(password)))
        admin.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(sql.Identifier(role), sql.Identifier(role)))
    key = hashlib.sha256(b"flow-thread-context-pg-fixture").digest()
    monkeypatch.setenv("MAVERICK_PG_DSN", make_conninfo(postgres_test_dsn, user=role, password=password,
                                                        options=f"-c search_path={role}"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + hashlib.sha256(key).hexdigest())
    crypto_at_rest._reset_shared_key_identity_for_testing()
    try:
        yield
    finally:
        crypto_at_rest._reset_shared_key_identity_for_testing()
        with psycopg.connect(postgres_test_dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


@pytest.mark.parametrize("shape", ["serial", "timed", "parallel", "foreach", "nested"])
def test_postgres_agent_admission_preserves_tenant_without_rls(governed_pg_dsn, monkeypatch, shape):
    from maverick.flow.execution import default_agent_runner, execute
    from maverick.world_model import open_world

    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_RLS", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr("maverick.client.client_id", lambda: None)
    with tenant_scope(tenant=None):
        world = open_world()
        unrelated = world.create_goal("Unrelated legacy work", owner="user:bob")
        original = world.get_goal(unrelated)
    with tenant_scope(tenant="customer-alpha"):
        agent = default_agent_runner(world, owner="user:alice", user_id="alice", budget_wall_seconds=0)
        execute(_flow(shape, "agent"), agent_runner=agent, action_runner=lambda *_: ("unused", 1.0),
                owner="user:alice", data={"items": [1, 2]})
        goals = world.list_goals(owner="user:alice")
        assert goals
        assert all(goal.status == "blocked" and goal.execution_principal == "user:alice" for goal in goals), [(g.id, g.status, g.owner, g.execution_principal) for g in goals]
        assert all(goal.owner == "user:alice" for goal in goals)
    with tenant_scope(tenant=None):
        assert world.get_goal(unrelated) == original
    world.close()
