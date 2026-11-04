"""Tests for the monitor snapshot (maverick.monitor)."""
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


# ---------- monitor ----------

def test_monitor_snapshot_empty_db(tmp_path):
    from maverick.monitor import snapshot
    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "wm.sqlite")
    try:
        assert snapshot(world) is None
    finally:
        world.close()


def test_monitor_snapshot_resolves_active_goal(world_with_history):
    """Without explicit goal_id, picks the most-recent active goal."""
    from maverick.monitor import snapshot
    state = snapshot(world_with_history)
    assert state is not None
    # Goal #5 is the only active one.
    assert state.goal.id == 5


def test_monitor_snapshot_fallback_uses_updated_at_not_id(tmp_path):
    """Without an in-flight goal, picks the most-recently-touched terminal goal."""
    from maverick.monitor import snapshot
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "wm.sqlite")
    try:
        older_id = world.create_goal("older id, touched last")
        newer_id = world.create_goal("newer id, stale")
        world.set_goal_status(newer_id, "done")
        time.sleep(0.01)
        world.set_goal_status(older_id, "done")

        state = snapshot(world)
        assert state is not None
        assert state.goal.id == older_id
    finally:
        world.close()


def test_monitor_snapshot_explicit_goal(world_with_history):
    from maverick.monitor import snapshot
    state = snapshot(world_with_history, goal_id=1)
    assert state is not None
    assert state.goal.id == 1


def test_monitor_render_contains_key_fields(world_with_history):
    from maverick.monitor import render, snapshot
    state = snapshot(world_with_history, goal_id=2)
    text = render(state)
    assert "Goal #2" in text
    assert "done" in text.lower()
    assert "payment" in text.lower()


def test_monitor_render_shows_children(world_with_history):
    """If a goal has subgoals, the plan tree appears."""
    from maverick.monitor import render, snapshot
    # Add a child of goal 5.
    world_with_history.conn.execute(
        "INSERT INTO goals(id, parent_id, title, description, status, "
        "created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
        (10, 5, "Spin up Postgres", "Local docker pg", "active",
         time.time(), time.time()),
    )
    world_with_history.conn.commit()
    state = snapshot(world_with_history, goal_id=5)
    assert len(state.children) == 1
    assert state.children[0].id == 10
    rendered = render(state)
    assert "Plan tree" in rendered
    assert "Spin up Postgres" in rendered
