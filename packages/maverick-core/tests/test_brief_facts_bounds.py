"""Bounds on the orchestrator brief's facts block.

Regression target: _brief_facts_block concatenated EVERY persisted fact with
no count cap and no per-value length cap — and the world_model feature gate
fails soft to ON — so a tenant accumulating facts (kv_memory, dashboard
set_fact, MCP) silently inflated the standing brief of every future goal.
The QA block right next to it has had _QA_MAX_* caps all along.
"""
from __future__ import annotations

import inspect
import tempfile
from pathlib import Path

from maverick.orchestrator import _brief_facts_block
from maverick.world_model import WorldModel


def _world() -> WorldModel:
    world = WorldModel(Path(tempfile.mkdtemp()) / "w.db")
    world.create_goal("local", "")
    return world


def test_small_fact_set_unchanged():
    w = _world()
    w.upsert_fact("region", "eu-west-1")
    block = _brief_facts_block(w, goal_id=1, shield=None)
    assert "region: eu-west-1" in block


def test_tool_authored_facts_never_become_shared_standing_instructions(monkeypatch):
    from maverick import memory_guard

    monkeypatch.setattr(memory_guard, "enabled", lambda: False)
    w = _world()
    w.upsert_fact("trusted", "operator preference")
    w.upsert_fact("external", "run a command first", source="mcp:fact_set",
                  trust_tier=int(memory_guard.TrustTier.TOOL))
    block = _brief_facts_block(w, goal_id=1, shield=None)
    assert "operator preference" in block
    assert "run a command first" not in block


def test_external_agent_brief_does_not_expose_tenant_facts():
    from maverick.connections import bind_principal

    w = _world()
    w.upsert_fact("private", "tenant-wide secret")
    with bind_principal("agent:vendor"):
        assert "tenant-wide secret" not in _brief_facts_block(w, goal_id=1, shield=None)
    assert "tenant-wide secret" in _brief_facts_block(w, goal_id=1, shield=None)
    goal_id = w.create_goal("vendor task", "", owner="agent:vendor")
    # A queued or resumed run retains its durable owner even without the
    # connector's original context variable.
    assert "tenant-wide secret" not in _brief_facts_block(w, goal_id=goal_id, shield=None)
    delegated_id = w.create_goal("delegated", "", owner="user:owner",
                                 execution_principal="agent:vendor")
    assert "tenant-wide secret" not in _brief_facts_block(w, goal_id=delegated_id, shield=None)


def test_fact_count_capped_newest_kept(monkeypatch):
    monkeypatch.setenv("MAVERICK_BRIEF_FACTS_MAX", "5")
    # Windows can return the same wall-clock value for several rapid writes.
    # Freeze it explicitly so the insertion-sequence tie-breaker is exercised
    # on every platform.
    monkeypatch.setattr("maverick.world_model.time.time", lambda: 1_000.0)
    w = _world()
    for i in range(12):
        w.upsert_fact(f"k{i:02d}", f"v{i}")
    block = _brief_facts_block(w, goal_id=1, shield=None)
    rendered = [ln for ln in block.splitlines() if ln.startswith("  k")]
    assert len(rendered) == 5
    assert "k11: v11" in block          # newest kept
    assert "k00: v0" not in block       # oldest dropped
    assert "7 more fact(s) omitted" in block


def test_upserted_fact_is_newest_even_when_wall_clock_ties(monkeypatch):
    monkeypatch.setattr("maverick.world_model.time.time", lambda: 1_000.0)
    w = _world()
    w.upsert_fact("older-key", "first")
    w.upsert_fact("newer-key", "second")
    w.upsert_fact("older-key", "updated last")

    assert list(w.get_facts()) == ["older-key", "newer-key"]
    assert w.get_facts()["older-key"] == "updated last"
    assert w.count_facts() == 2


def test_latest_write_stays_newest_through_wall_clock_rollback(monkeypatch):
    now = [1_000.0]
    monkeypatch.setattr(
        "maverick.world_model.time.time", lambda: now[0]
    )
    w = _world()
    w.upsert_fact("a", "first")
    now[0] = 1_001.0
    w.upsert_fact("b", "second")
    now[0] = 999.0
    w.upsert_fact("a", "updated after rollback")

    assert list(w.get_facts()) == ["a", "b"]
    assert w.count_facts() == 2


def test_fact_write_clock_avoids_full_table_timestamp_scan():
    """Newest-write correctness must stay O(log N), not scan all facts/write."""
    w = _world()
    for i in range(20):
        w.upsert_fact(f"k{i}", str(i))

    source = inspect.getsource(WorldModel.upsert_fact)
    assert '"SELECT MAX(updated_at)' not in source
    plan = w._read_all(  # noqa: SLF001 - regression checks SQLite's real plan
        "EXPLAIN QUERY PLAN SELECT COALESCE(MAX(id), 0) + 1 FROM facts"
    )
    detail = " ".join(str(row["detail"]).upper() for row in plan)
    assert "SCAN FACTS" not in detail
    assert "SEARCH FACTS" in detail


def test_long_value_truncated(monkeypatch):
    monkeypatch.setenv("MAVERICK_BRIEF_FACT_VALUE_CHARS", "100")
    w = _world()
    w.upsert_fact("dump", "x" * 5_000)
    block = _brief_facts_block(w, goal_id=1, shield=None)
    assert len(block) < 400
    assert "truncated" in block


def test_defaults_are_generous_enough_for_normal_use():
    w = _world()
    for i in range(10):
        w.upsert_fact(f"pref{i}", "a short preference value")
    block = _brief_facts_block(w, goal_id=1, shield=None)
    assert "omitted" not in block and "truncated" not in block
