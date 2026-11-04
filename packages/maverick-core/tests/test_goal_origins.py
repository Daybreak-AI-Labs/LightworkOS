"""WorldModel automation provenance: which schedule/trigger spawned each goal.

Backs the dashboard Automations run-history view. The schema table is added via
SCHEMA (idempotent CREATE) + a SCHEMA_VERSION bump, so a fresh DB just has it.
"""
from __future__ import annotations

from maverick.world_model import WorldModel


def test_record_and_query_goal_origins(tmp_path):
    w = WorldModel(tmp_path / "world.db")
    try:
        a = w.create_goal("run A", "x")
        b = w.create_goal("run B", "y")
        c = w.create_goal("other", "z")
        w.record_goal_origin(a, "schedule", "s1")
        w.record_goal_origin(b, "schedule", "s1")
        w.record_goal_origin(c, "trigger", "t1")
        w.set_goal_status(a, "done")
        w.set_goal_status(b, "failed")
        # most-recent first, scoped to the (kind, ref)
        assert [g.id for g in w.goals_for_origin("schedule", "s1")] == [b, a]
        assert w.origin_status_counts("schedule", "s1") == {"done": 1, "failed": 1}
        assert [g.id for g in w.goals_for_origin("trigger", "t1")] == [c]
        # unknown refs are empty, not errors
        assert w.goals_for_origin("schedule", "missing") == []
        assert w.origin_status_counts("schedule", "missing") == {}
    finally:
        w.close()


def test_record_goal_origin_is_idempotent_per_goal(tmp_path):
    # INSERT OR REPLACE keyed on goal_id: re-recording never duplicates a run.
    w = WorldModel(tmp_path / "world.db")
    try:
        g = w.create_goal("g", "x")
        w.record_goal_origin(g, "trigger", "t1")
        w.record_goal_origin(g, "trigger", "t1")
        assert len(w.goals_for_origin("trigger", "t1")) == 1
    finally:
        w.close()


def test_goals_for_origin_respects_limit(tmp_path):
    w = WorldModel(tmp_path / "world.db")
    try:
        for i in range(5):
            w.record_goal_origin(w.create_goal(f"g{i}", "x"), "schedule", "s1")
        assert len(w.goals_for_origin("schedule", "s1", limit=3)) == 3
    finally:
        w.close()
