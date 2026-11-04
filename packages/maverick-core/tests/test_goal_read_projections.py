"""Owner/root filtering precedes bounded title-only decoding on both backends."""
from __future__ import annotations

from contextlib import contextmanager

import pytest
from maverick import world_model


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    value = world_model.WorldModel(tmp_path / "world.db")
    yield value
    value.close()


def _backend(world, name, monkeypatch):
    if name == "sqlite":
        return world, []
    from maverick.world_model_backends import postgres

    calls = []
    with world._writing() as connection:
        connection.execute("ALTER TABLE goals ADD COLUMN tenant_id TEXT DEFAULT 'acme'")

    class Cursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def execute(self, sql, params):
            calls.append((sql, params))
            return self.cursor.execute(sql.replace("%s", "?"), params)

        def fetchall(self):
            return self.cursor.fetchall()

        def fetchone(self):
            return self.cursor.fetchone()

    @contextmanager
    def transaction():
        with world._writing() as connection:
            yield Cursor(connection.cursor())

    backend = object.__new__(postgres.PostgresWorldModel)
    monkeypatch.setattr(backend, "_tx", transaction)
    monkeypatch.setattr(postgres, "_tenant_scope", lambda: ("tenant_id=%s", ["acme"]))
    return backend, calls


@pytest.mark.parametrize("backend_name", ["sqlite", "postgres-contract"])
@pytest.mark.parametrize("encrypted", [False, True])
def test_root_survives_newer_children_and_decodes_only_visible_titles(world, monkeypatch, backend_name, encrypted):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1" if encrypted else "0")
    root = world.create_goal("Visible root", "private description", owner="alice")
    for _ in range(81):
        world.create_goal("Child", "private child", parent_id=root, owner="alice")
    world.create_goal("Other owner", "hidden", owner="bob")
    world.set_goal_status(root, "done", "large private result")
    if encrypted:
        assert world._read_one("SELECT title FROM goals WHERE id=?", (root,))["title"] != "Visible root"
    backend, calls = _backend(world, backend_name, monkeypatch)
    real_decode = world_model._dec_fields
    decrypted = []

    def observed(values):
        result = real_decode(values)
        decrypted.extend(result)
        return result

    monkeypatch.setattr(world_model, "_dec_fields", observed)
    rows = backend.conversation_summaries(owner="alice", limit=25)
    assert [(row.id, row.title, row.status) for row in rows] == [(root, "Visible root", "done")]
    assert decrypted == ["Visible root"]
    assert not hasattr(rows[0], "description") and not hasattr(rows[0], "result")
    if calls:
        sql, parameters = calls[0]
        assert "parent_id IS NULL" in sql.split("LIMIT")[0]
        assert "tenant_id=%s" in sql and parameters == ("alice", "acme", 25)


@pytest.mark.parametrize("backend_name", ["sqlite", "postgres-contract"])
def test_keyset_pagination_root_creation_order_and_owner_scope(world, monkeypatch, backend_name):
    ids = [world.create_goal(f"Root {i}", owner="alice") for i in range(5)]
    world.create_goal("Bob", owner="bob")
    backend, _calls = _backend(world, backend_name, monkeypatch)
    first = backend.conversation_summaries(owner="alice", limit=2)
    world.create_goal("New root while paging", owner="alice")
    world.set_goal_status(ids[0], "done", "Old root activity does not reorder creation")
    second = backend.conversation_summaries(owner="alice", limit=2, before_id=first[-1].id)
    assert [row.id for row in first + second] == ids[:0:-1]
    assert all(row.owner == "alice" for row in first + second)


@pytest.mark.parametrize("backend_name", ["sqlite", "postgres-contract"])
def test_stream_projection_decrypts_no_body_until_result_requested(world, monkeypatch, backend_name):
    goal = world.create_goal("secret title", "secret description", owner="alice")
    world.set_goal_status(goal, "done", "the result")
    backend, _calls = _backend(world, backend_name, monkeypatch)
    real_decode = world_model._dec_field
    values = []

    def observed(value):
        result = real_decode(value)
        values.append(result)
        return result

    monkeypatch.setattr(world_model, "_dec_field", observed)
    assert backend.goal_stream_state(goal).status == "done"
    assert values == []
    assert backend.goal_stream_state(goal, include_result=True).result == "the result"
    assert values == ["the result"]


def test_postgres_contract_filters_foreign_tenant_before_decrypt(world, monkeypatch):
    own = world.create_goal("Own", owner="alice")
    other = world.create_goal("Other tenant", owner="alice")
    backend, _calls = _backend(world, "postgres-contract", monkeypatch)
    with world._writing() as connection:
        connection.execute("UPDATE goals SET tenant_id='other' WHERE id=?", (other,))
    assert [row.id for row in backend.conversation_summaries(owner="alice")] == [own]
    assert backend.goal_stream_state(other) is None


def test_sidebar_calls_root_summary_query_with_active_selection(world, monkeypatch):
    from maverick_dashboard import app, auth
    from starlette.requests import Request

    request = Request({"type": "http", "method": "GET", "path": "/chat", "headers": []})
    monkeypatch.setattr(auth, "_authorization_principal", lambda _request: "alice")
    root = world.create_goal("Root", owner="alice")
    for _ in range(81):
        world.create_goal("Child", parent_id=root, owner="alice")
    monkeypatch.setattr(app, "goal_owner_filter", lambda _request: "alice")
    monkeypatch.setattr(world, "list_goals", lambda **_kwargs: pytest.fail("sidebar loaded complete goals"))
    assert app._chat_threads(request, world, active_root=root)[0] == {
        "id": root, "target_id": root, "title": "Root", "status": "pending", "state_label": "Queued",
        "active": True, "pinned": False, "archived": False, "stop_kind": "",
        "updated_at": world.get_goal(root).updated_at,
    }
