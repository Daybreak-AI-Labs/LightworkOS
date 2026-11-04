"""Swarm scale: the per-goal agent cap is configurable past 64, and a large
swarm's model calls are bounded so it queues instead of stampeding the provider."""
from __future__ import annotations

import asyncio
import types

import pytest
from maverick import config
from maverick.agent import Agent
from maverick.budget import Budget
from maverick.swarm import SwarmContext


def _ctx(**kw):
    return SwarmContext(llm=None, world=None, budget=None, blackboard=None,
                        sandbox=None, goal_id=1, **kw)


@pytest.fixture
def swarm_cfg(monkeypatch):
    monkeypatch.delenv("MAVERICK_MAX_TOTAL_SPAWNS", raising=False)
    monkeypatch.delenv("MAVERICK_MAX_CONCURRENT_MODEL_CALLS", raising=False)
    section: dict = {}
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"swarm": section})
    return section


def test_defaults_keep_historical_behaviour(swarm_cfg):
    assert config.get_swarm() == {"max_total_spawns": 64, "max_concurrent_model_calls": 0,
                                  "finding_post_max_chars": 1500}
    ctx = _ctx()
    assert ctx.max_total_spawns == 64 and ctx.max_concurrent_model_calls == 0


def test_config_raises_the_cap_past_64(swarm_cfg):
    swarm_cfg.update(max_total_spawns=500, max_concurrent_model_calls=8)
    ctx = _ctx()
    assert ctx.max_total_spawns == 500 and ctx.max_concurrent_model_calls == 8
    assert ctx.try_reserve_spawns(400) and ctx.try_reserve_spawns(100)
    assert not ctx.try_reserve_spawns(1)


def test_env_wins_and_bad_values_fall_back(swarm_cfg, monkeypatch):
    swarm_cfg.update(max_total_spawns=500, max_concurrent_model_calls="lots")
    monkeypatch.setenv("MAVERICK_MAX_TOTAL_SPAWNS", "80")
    assert _ctx().max_total_spawns == 80
    assert config.get_swarm()["max_concurrent_model_calls"] == 0
    monkeypatch.setenv("MAVERICK_MAX_TOTAL_SPAWNS", "junk")
    assert _ctx().max_total_spawns == 500


class _CountingLLM:
    def __init__(self):
        self.live = self.peak = 0

    async def complete_async(self, **kw):
        self.live += 1
        self.peak = max(self.peak, self.live)
        await asyncio.sleep(0.01)
        self.live -= 1
        return "ok"


def _agent(ctx):
    obj = types.SimpleNamespace(ctx=ctx, _HALT_POLL_SECONDS=0.02)
    obj._await_wall_clock_guarded = Agent._await_wall_clock_guarded.__get__(obj)
    return obj


@pytest.mark.parametrize("bound, expected_peak", [(3, 3), (0, 12)])
def test_model_calls_are_bounded_across_the_swarm(swarm_cfg, bound, expected_peak, tmp_path):
    from maverick.world_model import WorldModel

    llm = _CountingLLM()
    ctx = _ctx(max_concurrent_model_calls=bound)
    ctx.llm, ctx.budget = llm, Budget(max_wall_seconds=30)
    # Each guarded call re-reads the goal's cancel/handoff state from the world.
    ctx.world = WorldModel(tmp_path / "world.db")
    ctx.goal_id = ctx.world.create_goal("swarm", "")
    agents = [_agent(ctx) for _ in range(12)]

    async def _drive():
        return await asyncio.gather(*(Agent._complete_guarded(a) for a in agents))

    try:
        assert asyncio.run(_drive()) == ["ok"] * 12
    finally:
        ctx.world.close()
    assert llm.peak == expected_peak
