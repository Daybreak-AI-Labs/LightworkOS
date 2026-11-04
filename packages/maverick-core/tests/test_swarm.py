"""Tests for the swarm spawn cap (maverick.swarm)."""
from __future__ import annotations

# --- per-goal spawn cap ---

def test_swarm_total_spawn_cap():
    from maverick.swarm import SwarmContext
    ctx = SwarmContext(
        llm=None, world=None, budget=None, blackboard=None,
        sandbox=None, goal_id=1, max_total_spawns=3,
    )
    assert ctx.try_reserve_spawns(2) is True
    assert ctx.try_reserve_spawns(1) is True
    assert ctx.try_reserve_spawns(1) is False  # would exceed cap of 3
