"""PostgresWorldModel.recent_goals_by_domain against a recording cursor.

The live round trip against a real server is in ``test_postgres_world.py`` (it
only runs where ``MAVERICK_PG_DSN`` is set). This file needs no server: it pins
the shape of the one grouped statement and how its rows become goals.
"""
from __future__ import annotations

import contextlib

import pytest
from maverick.paths import tenant_scope
from maverick.world_model_backends.postgres import PostgresWorldModel


class _Cursor:
    def __init__(self, rows):
        self.rows = rows
        self.calls: list[tuple[str, tuple]] = []

    def execute(self, sql, params=()):
        self.calls.append((sql, tuple(params)))

    def fetchall(self):
        return self.rows


def _world(rows=()):
    cursor = _Cursor(list(rows))
    world = PostgresWorldModel.__new__(PostgresWorldModel)

    @contextlib.contextmanager
    def tx():
        yield cursor

    world._tx = tx
    return world, cursor


def _row(goal_id, domain, owner=""):
    # id, parent_id, title, description, status, created_at, updated_at,
    # deadline, result, owner, execution_principal, domain, project_id
    return (goal_id, None, f"goal {goal_id}", "", "done", 1.0, 2.0, None, "ok",
            owner, "", domain, None)


@pytest.fixture(autouse=True)
def _plain_text(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")


def test_one_statement_for_every_domain_with_the_cap_applied_per_domain():
    world, cursor = _world([_row(9, "b"), _row(8, "a"), _row(7, "b")])
    got = world.recent_goals_by_domain(["b", "a", "b", ""], per_domain=5)
    assert len(cursor.calls) == 1
    sql, params = cursor.calls[0]
    assert params == (["a", "b"], 5)
    assert sql.count("%s") == len(params)
    assert "domain = ANY(%s)" in sql
    assert "ROW_NUMBER() OVER (PARTITION BY domain ORDER BY id DESC)" in sql
    assert sql.rstrip().endswith("ORDER BY id DESC")
    assert {domain: [goal.id for goal in goals] for domain, goals in got.items()} == {
        "b": [9, 7],
        "a": [8],
    }


def test_owner_and_tenant_filters_go_inside_the_ranking():
    world, cursor = _world()
    with tenant_scope(tenant="acme"):
        assert world.recent_goals_by_domain(["a"], owner="user:alice", per_domain=3) == {}
    sql, params = cursor.calls[0]
    ranked = sql.split("FROM goals WHERE ", 2)[2].split(") ranked")[0]
    assert "owner = %s" in ranked and "tenant_id" in ranked
    assert params == (["a"], "user:alice", "acme", 3)
    assert sql.count("%s") == len(params)


def test_nothing_to_look_up_runs_no_statement():
    world, cursor = _world()
    assert world.recent_goals_by_domain([]) == {}
    assert world.recent_goals_by_domain(["", ""]) == {}
    assert cursor.calls == []
