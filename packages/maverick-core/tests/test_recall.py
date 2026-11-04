"""Tests for the recall_past_goals tool (maverick.tools.recall)."""
from __future__ import annotations

import time

import pytest

# ---------- recall_past_goals ----------

@pytest.fixture
def world_with_history(tmp_path):
    """A WorldModel with a few finished goals to recall against."""
    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "wm.sqlite")
    # Insert via direct SQL (we control the schema fields).
    # Statuses use the vocabulary the orchestrator actually writes
    # (done/blocked/active), not the never-written succeeded/failed/in_progress.
    goals = [
        (1, None, "Refactor auth module", "Replace JWT with sessions in app/auth.py", "done", "Migrated auth to sessions, all tests pass."),
        (2, None, "Fix bug in payment flow", "Stripe webhook crashes on negative amounts", "done", "Added input validation; webhook stable."),
        (3, None, "Refactor authentication", "Same as #1 essentially", "blocked", "Hit a deadlock; reverted."),
        (4, None, "Write tests for cart", "Add coverage for shopping cart edge cases", "done", "Cart now at 85% coverage."),
        (5, None, "Database migration", "Move from SQLite to Postgres", "active", None),
    ]
    now = time.time()
    for gid, parent, title, desc, status, result in goals:
        world.conn.execute(
            "INSERT INTO goals(id, parent_id, title, description, status, "
            "created_at, updated_at, result) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (gid, parent, title, desc, status, now - gid * 100, now - gid * 100, result),
        )
    world.conn.commit()
    yield world
    world.close()


def test_recall_excludes_running_by_default(world_with_history):
    from maverick.tools.recall import recall_past_goals
    matches = recall_past_goals(
        "refactor auth",
        world=world_with_history,
        num_results=10,
        include_running=False,
    )
    ids = [g.id for _, g in matches]
    assert 5 not in ids  # "Database migration" is active


def test_recall_finds_relevant_by_jaccard(world_with_history):
    """Without fastembed, jaccard should still rank refactor-auth as top."""
    from maverick.tools.recall import recall_past_goals
    matches = recall_past_goals(
        "auth refactor session",
        world=world_with_history,
        num_results=3,
    )
    assert matches, "expected at least one match"
    top_ids = [g.id for _, g in matches[:2]]
    # Goal 1 or 3 (both auth-related) should be in top 2.
    assert 1 in top_ids or 3 in top_ids


def test_recall_returns_empty_on_empty_world(tmp_path):
    from maverick.tools.recall import recall_past_goals
    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "empty.sqlite")
    try:
        out = recall_past_goals("anything", world=world)
        assert out == []
    finally:
        world.close()


def test_recall_default_does_not_close_cached_tenant_world(tmp_path, monkeypatch):
    import maverick.world_model as wm
    from maverick.paths import tenant_scope
    from maverick.tools.recall import recall_past_goals

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    with tenant_scope(tenant="recall-tenant"):
        cached = wm.world_for_tenant("recall-tenant")
        assert recall_past_goals("anything") == []
        assert wm.world_for_tenant("recall-tenant") is cached
        assert cached.list_goals() == []
    cached.close()
    wm._tenant_worlds.pop(str(cached.path), None)


def test_recall_tool_factory():
    from maverick.tools.recall import recall
    tool = recall()
    assert tool.name == "recall_past_goals"
    assert "query" in tool.input_schema["properties"]


def test_recall_tool_runner_empty_query():
    from maverick.tools.recall import _run_recall
    assert "query is required" in _run_recall({"query": ""}).lower()


def test_recall_includes_running_when_asked(world_with_history):
    from maverick.tools.recall import recall_past_goals
    matches = recall_past_goals(
        "database",
        world=world_with_history,
        num_results=10,
        include_running=True,
    )
    ids = [g.id for _, g in matches]
    assert 5 in ids
