"""Projects ("matters"): a workspace grouping related goals (schema v19)."""
from __future__ import annotations

import sqlite3

from maverick.world_model import SCHEMA_VERSION, WorldModel


def test_create_list_and_count(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    pid = w.create_project("Q3 Close", description="quarterly close", owner="user:a", domain="finance_sox")
    p = w.get_project(pid)
    assert p["name"] == "Q3 Close" and p["description"] == "quarterly close"
    assert p["domain"] == "finance_sox" and p["status"] == "active"
    w.create_goal("Reconcile", domain="finance_sox", project_id=pid)
    w.create_goal("Flux", domain="finance_sox", project_id=pid)
    listed = w.list_projects()
    assert listed[0]["id"] == pid and listed[0]["goal_count"] == 2


def test_list_goals_project_filter_and_filing(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    pid = w.create_project("P")
    a = w.create_goal("a", project_id=pid)
    b = w.create_goal("b")  # unfiled
    assert {g.id for g in w.list_goals(project_id=pid)} == {a}
    assert w.get_goal(b).project_id is None
    w.set_goal_project(b, pid)                         # file it
    assert {g.id for g in w.list_goals(project_id=pid)} == {a, b}
    w.set_goal_project(a, None)                        # unfile it
    assert {g.id for g in w.list_goals(project_id=pid)} == {b}


def test_status_counts(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    pid = w.create_project("P")
    g1 = w.create_goal("a", project_id=pid)
    w.create_goal("b", project_id=pid)
    w.set_goal_status(g1, "done", result="ok")
    assert w.project_status_counts(pid) == {"done": 1, "pending": 1}


def test_owner_scoped_listing(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    w.create_project("mine", owner="user:a")
    w.create_project("theirs", owner="user:b")
    assert [p["name"] for p in w.list_projects(owner="user:a")] == ["mine"]
    assert len(w.list_projects()) == 2  # None = all


def test_migration_from_v18_adds_project_id(tmp_path):
    # A pre-projects (v18) DB: goals without project_id, version pinned 18.
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE goals(
            id INTEGER PRIMARY KEY AUTOINCREMENT, parent_id INTEGER,
            title TEXT NOT NULL, description TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at REAL NOT NULL, updated_at REAL NOT NULL,
            deadline REAL, result TEXT,
            owner TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '');
        CREATE TABLE schema_version(version INTEGER);
        INSERT INTO schema_version(version) VALUES(18);
        INSERT INTO goals(title, status, created_at, updated_at)
            VALUES('legacy', 'done', 0, 0);
        """
    )
    conn.commit()
    conn.close()
    w = WorldModel(db)  # opening runs the v19 (projects) migration + any later
    assert w.schema_version == SCHEMA_VERSION
    assert w.get_goal(1).project_id is None          # legacy goal: unfiled
    pid = w.create_project("New")
    w.set_goal_project(1, pid)                        # and it can now be filed
    assert w.get_goal(1).project_id == pid
