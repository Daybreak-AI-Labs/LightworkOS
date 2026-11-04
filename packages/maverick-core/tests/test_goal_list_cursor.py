"""An immutable ID boundary survives changes ahead of an authorized task page."""
from __future__ import annotations

from contextlib import contextmanager

import pytest
from maverick.paths import tenant_scope
from maverick.world_model import WorldModel


@pytest.fixture(params=["sqlite", "postgres"])
def world(request, tmp_path):
    if request.param == "postgres":
        from maverick.world_model_backends.postgres import PostgresWorldModel

        database = PostgresWorldModel(dsn=request.getfixturevalue("postgres_test_dsn"))
    else:
        database = WorldModel(tmp_path / "world.db")
    with tenant_scope(tenant="cursor-fixture"):
        try:
            yield database
        finally:
            database.close()


def change_goal(world, statement, params):
    """Model an independently committed deletion/ownership change."""
    if hasattr(world, "_read_all"):
        with world._writing() as connection:
            connection.execute(statement, params)
    else:
        with world._tx() as cursor:
            cursor.execute(statement.replace("?", "%s"), params)


def test_cursor_reaches_oldest_of_125_after_insert_and_deleted_anchor(world, monkeypatch):
    original = [world.create_goal(f"Task {index}", owner="user:alice") for index in range(125)]
    first = world.list_goals(owner="user:alice", order="desc", limit=50)
    boundary = first[-1].id
    change_goal(world, "DELETE FROM goals WHERE id=?", (boundary,))
    world.create_goal("New task ahead of cursor", owner="user:alice")
    monkeypatch.setattr(world, "get_goal", lambda *_: pytest.fail("cursor must not read its anchor"))

    second = world.list_goals(owner="user:alice", order="desc", limit=50, before_id=boundary)
    third = world.list_goals(owner="user:alice", order="desc", limit=50, before_id=second[-1].id)
    ids = [goal.id for goal in [*first[:-1], *second, *third]]
    assert ids == [goal_id for goal_id in reversed(original) if goal_id != boundary]
    assert len(ids) == len(set(ids)) == 124
    assert third[-1].id == original[0]


def test_cursor_keeps_filters_and_current_owner_after_revocation(world, monkeypatch):
    project = world.create_project("Scoped project", owner="user:alice", domain="finance")
    allowed = [world.create_goal(f"Allowed {index}", owner="user:alice", domain="finance", project_id=project)
               for index in range(4)]
    world.create_goal("Other owner", owner="user:bob", domain="finance", project_id=project)
    world.create_goal("Other domain", owner="user:alice", domain="legal", project_id=project)
    world.create_goal("Other project", owner="user:alice", domain="finance")
    done = world.create_goal("Other status", owner="user:alice", domain="finance", project_id=project)
    world.set_goal_status(done, "done")
    change_goal(world, "UPDATE goals SET owner=? WHERE id=?", ("user:bob", allowed[1]))
    monkeypatch.setattr(world, "get_goal", lambda *_: pytest.fail("no unscoped anchor lookup"))

    rows = world.list_goals(owner="user:alice", status="pending", domain="finance",
                            project_id=project, order="desc", limit=50, before_id=done + 1)
    assert [goal.id for goal in rows] == [allowed[3], allowed[2], allowed[0]]


def test_cursor_is_id_bound_even_in_ascending_order_and_preserves_legacy_offset(world):
    ids = [world.create_goal(f"Task {index}", owner="user:alice") for index in range(5)]
    assert [goal.id for goal in world.list_goals(owner="user:alice", before_id=ids[3])] == ids[:3]
    assert [goal.id for goal in world.list_goals(owner="user:alice", order="desc", limit=2, offset=2)] == ids[1:3][::-1]


@pytest.mark.parametrize("before_id", [0, -1, 2**63])
def test_invalid_cursor_refuses_before_query(world, monkeypatch, before_id):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid cursor reached database")

    monkeypatch.setattr(world, "_read_all" if hasattr(world, "_read_all") else "_tx", unexpected)
    with pytest.raises(ValueError, match="before_id"):
        world.list_goals(before_id=before_id)


def test_cursor_retains_current_workspace(world, tmp_path):
    own = world.create_goal("Current workspace", owner="user:alice")
    if hasattr(world, "_read_all"):
        with tenant_scope(tenant="other-cursor-fixture"):
            other = WorldModel(tmp_path / "other-workspace.db")
            try:
                other.create_goal("Other workspace", owner="user:alice")
            finally:
                other.close()
        boundary = own + 1
    else:
        with tenant_scope(tenant="other-cursor-fixture"):
            foreign = world.create_goal("Other workspace", owner="user:alice")
        boundary = foreign + 1
    rows = world.list_goals(owner="user:alice", order="desc", before_id=boundary)
    assert [(goal.id, goal.title) for goal in rows] == [(own, "Current workspace")]


def test_postgres_query_binds_cursor_after_owner_filters_and_retains_tenant(monkeypatch):
    from maverick.world_model_backends.postgres import PostgresWorldModel

    calls = []

    class Cursor:
        def execute(self, sql, params):
            calls.append((sql, params))

        def fetchall(self):
            return []

    @contextmanager
    def transaction():
        yield Cursor()

    database = PostgresWorldModel.__new__(PostgresWorldModel)
    monkeypatch.setattr(database, "_tx", transaction)
    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "1")
    with tenant_scope(tenant="cursor-fixture"):
        assert database.list_goals(owner="user:alice", status="pending", domain="finance",
                                   project_id=3, before_id=17, limit=6, order="desc") == []
    assert len(calls) == 1
    sql, params = calls[0]
    assert "status = %s AND owner = %s AND domain = %s AND project_id = %s AND id < %s AND tenant_id = %s" in sql
    assert "ORDER BY id DESC LIMIT %s OFFSET %s" in sql
    assert params == ("pending", "user:alice", "finance", 3, 17, "cursor-fixture", 6, 0)
