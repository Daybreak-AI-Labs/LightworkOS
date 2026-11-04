"""Recursive fan-out keeps budget for synthesis, so a deep task delivers an
artifact instead of paying in full for nothing.

The levers, all unit-tested here (a deep-task confirmation needs a live-API
run): a depth-decaying fan-out cap, a synthesis-reserve spawn gate, a
per-worker soft-stop that yields the reserve, and a leaf-by-default worker
prompt.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick.agent import WORKER_SYSTEM_TEMPLATE, Agent, _last_assistant_text
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.tools.spawn import (
    MAX_SWARM_FANOUT,
    _fanout_cap_for_depth,
    _synthesis_reserve_block,
    spawn_subagent_tool,
    spawn_swarm_tool,
)
from maverick.world_model import WorldModel


def test_fanout_cap_decays_with_depth():
    assert _fanout_cap_for_depth(0) == MAX_SWARM_FANOUT
    assert _fanout_cap_for_depth(1) == MAX_SWARM_FANOUT // 2
    assert _fanout_cap_for_depth(2) == MAX_SWARM_FANOUT // 4
    assert _fanout_cap_for_depth(99) == 1  # floor, never zero


def test_worker_prompt_is_leaf_by_default():
    t = WORKER_SYSTEM_TEMPLATE
    assert "Do the work YOURSELF by default" in t
    assert "leaf" in t.lower()
    # The old "decomposes into 2+ ... prefer spawn_swarm" guidance is gone.
    assert "prefer `spawn_swarm` for speed" not in t


def test_last_assistant_text():
    msgs = [
        {"role": "user", "content": "q"},
        {"role": "assistant", "content": [{"type": "text", "text": "hello"}]},
        {"role": "user", "content": "more"},
    ]
    assert _last_assistant_text(msgs) == "hello"
    assert _last_assistant_text([{"role": "assistant", "content": "plain"}]) == "plain"
    assert _last_assistant_text([{"role": "user", "content": "x"}]) == ""


def _fake_parent(depth: int, budget: Budget):
    ctx = SimpleNamespace(
        budget=budget, blackboard=Blackboard(), max_depth=3,
        try_reserve_spawns=lambda n: True,
    )
    return SimpleNamespace(depth=depth, name="p", ctx=ctx)


@pytest.mark.asyncio
async def test_spawn_refused_past_synthesis_ceiling():
    # Reserve is 0.25 by default -> ceiling at 0.75 of the cap.
    bud = Budget(max_dollars=1.0)
    bud.dollars = 0.8  # past the ceiling
    tool = spawn_swarm_tool(_fake_parent(depth=0, budget=bud))
    out = await tool.fn({"agents": [{"role": "researcher", "task": "x"}]})
    assert "ERROR" in out
    assert "reserve" in out.lower() and "synthes" in out.lower()


def test_synthesis_reserve_block_helper():
    # Below the 0.75 ceiling: spawning allowed (None). Past it: refusal string.
    bud = Budget(max_dollars=1.0)
    bud.dollars = 0.5
    assert _synthesis_reserve_block(_fake_parent(depth=0, budget=bud)) is None
    bud.dollars = 0.8
    blocked = _synthesis_reserve_block(_fake_parent(depth=0, budget=bud))
    assert blocked is not None and "synthes" in blocked.lower()


@pytest.mark.asyncio
async def test_spawn_subagent_refused_past_synthesis_ceiling():
    # The reserve gate must cover spawn_subagent too -- a depth-0 orchestrator's
    # sequential spawn chain is NOT caught by the depth>0 per-worker soft-stop.
    bud = Budget(max_dollars=1.0)
    bud.dollars = 0.8  # past the 0.75 ceiling
    tool = spawn_subagent_tool(_fake_parent(depth=0, budget=bud))
    out = await tool.fn({"role": "researcher", "task": "x"})
    assert "ERROR" in out
    assert "reserve" in out.lower() and "synthes" in out.lower()


@pytest.fixture
def ctx(tmp_path: Path, fake_llm):
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("test goal", "")
    return SwarmContext(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=gid, max_depth=2, use_skills=False,
    )


@pytest.mark.asyncio
async def test_worker_yields_reserve_without_llm_call(ctx, fake_llm, make_llm_response):
    # A depth>0 worker already past the 0.75 ceiling must stop BEFORE the next
    # LLM call, returning its partial work so the reserve survives for synthesis.
    ctx.budget.dollars = 0.9
    fake_llm.scripted = [make_llm_response(text="FINAL: should not be reached")]
    worker = Agent(ctx=ctx, role="researcher", brief="deep research", depth=1)
    result = await worker.run()
    assert result.error is None
    assert "reserve" in (result.final or "").lower() or result.final == (
        "(stopped early to reserve synthesis budget)"
    )
    assert fake_llm.calls == []  # never spent into the reserve


@pytest.mark.asyncio
async def test_depth0_does_not_yield_reserve(ctx, fake_llm, make_llm_response):
    # The top-level (depth 0) agent keeps the reserve to synthesize -- it does
    # NOT stop at the ceiling, so it proceeds to its LLM call and finalizes
    # (contrast with the depth>0 worker, which yields without any LLM call).
    ctx.budget.dollars = 0.9
    fake_llm.scripted = [make_llm_response(text="FINAL: synthesized answer")]
    top = Agent(ctx=ctx, role="researcher", brief="write the report", depth=0)
    result = await top.run()
    assert len(fake_llm.calls) >= 1  # did NOT short-circuit at the ceiling
    assert "synthesized answer" in (result.final or "")
