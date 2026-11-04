"""A running agent sees what other agents posted since its last turn.

Everything posted after the first-turn brief -- fan-out cap notices,
quarantine seals, sibling findings -- must reach a running agent, not only
what flows back through a tool result. Each tool-running turn appends a
bounded delta of other agents' posts to the tool_results message.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.llm import ToolCall
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel


@pytest.fixture
def ctx(tmp_path: Path, fake_llm):
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("test goal", "")
    return SwarmContext(
        llm=fake_llm, world=world, budget=Budget(max_dollars=5.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id, max_depth=2, use_skills=False,
    )


def _text_blocks(message) -> list[str]:
    content = message["content"]
    if isinstance(content, str):
        return [content]
    return [b["text"] for b in content if isinstance(b, dict) and b.get("type") == "text"]


class _SiblingPostingLLM:
    """Turn 1 returns a tool call and, while the tool runs, a sibling posts a
    finding; turn 2 must see it and returns FINAL."""

    model = "fake:test"

    def __init__(self, bb: Blackboard, make, own_name: str = ""):
        self.bb, self.make, self.calls, self.own_name = bb, make, [], own_name

    async def complete_async(self, **kwargs):
        # Snapshot: the agent keeps appending to the same history list.
        self.calls.append({**kwargs, "messages": copy.deepcopy(kwargs["messages"])})
        if len(self.calls) == 1:
            self.bb.post("researcher", "finding", "the vendor was acquired last week")
            self.bb.post(self.own_name or "self", "note", "my own bookkeeping note")
            return self.make(
                text="checking",
                tool_calls=[ToolCall(id="t1", name="shell", input={"cmd": "echo hi"})],
            )
        return self.make(text="FINAL: done")


@pytest.mark.asyncio
async def test_other_agents_posts_reach_the_next_turn(ctx, make_llm_response):
    agent = Agent(ctx=ctx, role="coder", brief="do the thing")
    ctx.llm = _SiblingPostingLLM(ctx.blackboard, make_llm_response, own_name=agent.name)
    result = await agent.run()
    assert result.final is not None
    assert len(ctx.llm.calls) == 2
    turn2_last_user = ctx.llm.calls[1]["messages"][-1]
    assert turn2_last_user["role"] == "user"
    texts = "\n".join(_text_blocks(turn2_last_user))
    assert "New on the swarm blackboard since your last turn" in texts
    assert "[researcher/finding] the vendor was acquired last week" in texts
    # The agent's own posts are not echoed back to it.
    assert "my own bookkeeping note" not in texts
    # The first turn's brief carried the pre-run state only (nothing to add).
    assert "New on the swarm blackboard" not in "\n".join(
        _text_blocks(ctx.llm.calls[0]["messages"][-1]))


@pytest.mark.asyncio
async def test_no_delta_block_when_nothing_new(ctx, fake_llm, make_llm_response):
    fake_llm.scripted = [
        make_llm_response(text="checking",
                          tool_calls=[ToolCall(id="t1", name="shell", input={"cmd": "echo hi"})]),
        make_llm_response(text="FINAL: done"),
    ]
    await Agent(ctx=ctx, role="researcher", brief="quiet run").run()
    texts = "\n".join(_text_blocks(fake_llm.calls[1]["messages"][-1]))
    assert "New on the swarm blackboard" not in texts


@pytest.mark.asyncio
async def test_delta_can_be_disabled(ctx, make_llm_response, monkeypatch):
    from maverick import agent as agent_mod

    monkeypatch.setattr(agent_mod, "_BB_TURN_DELTA_ENTRIES", 0)
    ctx.llm = _SiblingPostingLLM(ctx.blackboard, make_llm_response)
    await Agent(ctx=ctx, role="coder", brief="do the thing").run()
    texts = "\n".join(_text_blocks(ctx.llm.calls[1]["messages"][-1]))
    assert "New on the swarm blackboard" not in texts
