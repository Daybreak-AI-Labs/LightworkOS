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
