"""Goal result sets resolve the at-rest encryption policy once per query."""
from __future__ import annotations

from maverick import crypto_at_rest, world_model


def test_list_goals_checks_at_rest_policy_once_per_query(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    wm = world_model.WorldModel(tmp_path / "w.db")
    for i in range(25):
        wm.create_goal(f"goal {i}", "")
    calls = {"n": 0}
    original = crypto_at_rest.at_rest_enabled

    def counting():
        calls["n"] += 1
        return original()

    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", counting)
    goals = wm.list_goals(limit=100)
    assert len(goals) == 25
    assert calls["n"] == 1


def test_goal_rows_still_decrypt_when_at_rest_is_on(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    wm = world_model.WorldModel(tmp_path / "w.db")
    gid = wm.create_goal("sealed title", "sealed description")
    goal = wm.get_goal(gid)
    assert goal.title == "sealed title"
    assert goal.description == "sealed description"
    assert wm.list_goals(limit=5)[0].title == "sealed title"
    import sqlite3

    with sqlite3.connect(tmp_path / "w.db") as conn:
        raw = conn.execute("SELECT title FROM goals WHERE id=?", (gid,)).fetchone()[0]
    assert raw != "sealed title"


def test_personal_alert_goals_check_at_rest_policy_once_per_page(tmp_path, monkeypatch):
    # The notification badge reads this page on every page view; one policy
    # read per task made it grow with the owner's task count.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    wm = world_model.WorldModel(tmp_path / "w.db")
    for i in range(25):
        wm.create_goal(f"goal {i}", "", owner="user:a")
    calls = {"n": 0}
    original = crypto_at_rest.at_rest_enabled

    def counting():
        calls["n"] += 1
        return original()

    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", counting)
    rows = wm.personal_alert_goals("user:a", since=0)
    assert [goal.title for goal, _state, _result in rows] == [f"goal {i}" for i in range(25)]
    assert calls["n"] == 1


def test_personal_alert_goals_still_decrypt_when_at_rest_is_on(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    wm = world_model.WorldModel(tmp_path / "w.db")
    wm.create_goal("sealed title", "sealed description", owner="user:a")
    [(goal, state_revision, result_revision)] = wm.personal_alert_goals("user:a", since=0)
    assert (goal.title, goal.description) == ("sealed title", "sealed description")
    assert isinstance(state_revision, int) and isinstance(result_revision, int)


def test_postgres_personal_alert_goals_decode_a_page_at_once(monkeypatch, tmp_path):
    import os
    import uuid

    import pytest
    dsn = os.environ.get("MAVERICK_PG_DSN")
    if not dsn:
        pytest.skip("MAVERICK_PG_DSN is not set")
    psycopg = pytest.importorskip("psycopg")
    from maverick.world_model_backends import postgres
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    db = "mvk_alert_rows_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db)))
    own = make_conninfo(dsn, dbname=db)
    monkeypatch.setenv("MAVERICK_PG_DSN", own)
    try:
        world = postgres.PostgresWorldModel(own)
        for i in range(5):
            world.create_goal(f"sealed {i}", "private", owner="user:a")
        pages = []
        original = postgres._dec_goal_rows
        monkeypatch.setattr(postgres, "_dec_goal_rows", lambda rows: pages.append(len(rows)) or original(rows))
        rows = world.personal_alert_goals("user:a", since=0)
        assert [goal.title for goal, _state, _result in rows] == [f"sealed {i}" for i in range(5)]
        assert all(goal.description == "private" for goal, _state, _result in rows)
        assert pages == [5]
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(db)))
