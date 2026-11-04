"""Query-plan regression guard.

The world model ships indexes for its hot access paths (goal_events by goal_id,
turns by conversation_id, episodes by goal_id, approvals by status, ...). A
dropped or shadowed index silently turns those into full table scans that only
bite at scale. This test pins the plan: each hot query must SEARCH **using an
index**, never a full SCAN of the target table.

Robust by construction: an equality filter on an indexed column makes SQLite's
planner pick the index regardless of row count or version, so we assert the
stable "USING INDEX" / "SEARCH" shape rather than a version-fragile exact plan.
"""
from __future__ import annotations

from maverick.world_model import open_world

# (label, sql, table-that-must-not-be-full-scanned)
_HOT_QUERIES = [
    ("goal_events by goal_id",
     "SELECT * FROM goal_events WHERE goal_id = 1 ORDER BY id", "goal_events"),
    ("turns by conversation_id",
     "SELECT * FROM turns WHERE conversation_id = 1 ORDER BY id", "turns"),
    ("episodes by goal_id",
     "SELECT * FROM episodes WHERE goal_id = 1", "episodes"),
    ("approvals by status",
     "SELECT * FROM approvals WHERE status = 'pending' ORDER BY id", "approvals"),
    ("attachments by goal_id",
     "SELECT * FROM attachments WHERE goal_id = 1", "attachments"),
    ("goals by status",
     "SELECT * FROM goals WHERE status = 'active'", "goals"),
]


def _plan(conn, sql: str) -> str:
    rows = conn.execute("EXPLAIN QUERY PLAN " + sql).fetchall()
    # The human-readable step is the last column ("detail") of each row.
    return " | ".join(str(r[-1]) for r in rows)


def test_hot_queries_use_an_index(tmp_path):
    w = open_world(tmp_path / "world.db")
    try:
        for label, sql, table in _HOT_QUERIES:
            detail = _plan(w.conn, sql).upper()
            assert "USING" in detail, f"{label}: no index used -> {detail!r}"
            # And specifically not a full scan of the target table.
            assert f"SCAN {table.upper()}" not in detail, \
                f"{label}: full table scan of {table} -> {detail!r}"
    finally:
        w.close()


def test_a_genuinely_unindexed_query_does_scan(tmp_path):
    # Control: a filter on a non-indexed column DOES full-scan, proving the
    # assertion above actually distinguishes indexed from unindexed plans
    # (so it can't silently pass on a degraded plan).
    w = open_world(tmp_path / "world.db")
    try:
        detail = _plan(w.conn, "SELECT * FROM goals WHERE title = 'x'").upper()
        assert "SCAN GOALS" in detail and "USING" not in detail, detail
    finally:
        w.close()
