"""Concurrent tool execution in the agent loop.

When a single model turn emits 2+ tool calls and EVERY one is
``parallel_safe`` (pure reads), the loop runs them with asyncio.gather
instead of awaiting each in sequence. A turn with any stateful tool falls
back to the serial path, preserving side-effect ordering and the
``ask_user`` block-on-user semantics.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.llm import LLMResponse, ToolCall
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.tools import Tool, base_registry
from maverick.world_model import WorldModel


@pytest.fixture
def ctx(tmp_path: Path, fake_llm):
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("test goal", "")
    return SwarmContext(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(),
        sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id,
        max_depth=1,
        use_skills=False,
    )


class _Tracker:
    """Records peak concurrency across the tools it hands out."""

    def __init__(self) -> None:
        self.active = 0
        self.max_active = 0

    def tool(self, name: str, parallel_safe: bool) -> Tool:
        async def fn(args: dict) -> str:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            await asyncio.sleep(0.05)
            self.active -= 1
            return f"ok:{name}"

        return Tool(
            name=name,
            description="x",
            input_schema={"type": "object", "properties": {}},
            fn=fn,
            parallel_safe=parallel_safe,
        )


def _two_calls(name_a: str, name_b: str) -> list[LLMResponse]:
    return [
        LLMResponse(
            text="working",
            thinking=None,
            stop_reason="tool_use",
            tool_calls=[
                ToolCall(id="a", name=name_a, input={}),
                ToolCall(id="b", name=name_b, input={}),
            ],
        ),
        LLMResponse(
            text="FINAL: done", thinking=None,
            stop_reason="end_turn", tool_calls=[],
        ),
    ]


class TestParallelToolExecution:
    def test_read_tools_are_marked_parallel_safe(self, ctx):
        reg = base_registry(ctx.world, ctx.sandbox)
        for name in ("read_file", "list_dir", "repo_map", "dep_graph"):
            assert reg.get(name).parallel_safe is True, name
        # Stateful tools must stay serial.
        for name in ("write_file", "shell", "ask_user"):
            assert reg.get(name).parallel_safe is False, name

    @pytest.mark.asyncio
    async def test_all_parallel_safe_run_concurrently(self, ctx, fake_llm):
        tracker = _Tracker()
        fake_llm.scripted = _two_calls("p1", "p2")
        agent = Agent(ctx=ctx, role="researcher", brief="read two files")
        agent.tools.register(tracker.tool("p1", parallel_safe=True))
        agent.tools.register(tracker.tool("p2", parallel_safe=True))
        result = await agent.run()
        assert result.final == "done"
        assert tracker.max_active == 2  # both ran at once

    @pytest.mark.asyncio
    async def test_mixed_turn_falls_back_to_serial(self, ctx, fake_llm):
        tracker = _Tracker()
        fake_llm.scripted = _two_calls("p1", "s1")
        agent = Agent(ctx=ctx, role="researcher", brief="read then write")
        agent.tools.register(tracker.tool("p1", parallel_safe=True))
        agent.tools.register(tracker.tool("s1", parallel_safe=False))
        result = await agent.run()
        assert result.final == "done"
        assert tracker.max_active == 1  # serial: one tool at a time

    @pytest.mark.asyncio
    async def test_env_var_disables_parallelism(self, ctx, fake_llm, monkeypatch):
        monkeypatch.setenv("MAVERICK_PARALLEL_TOOLS", "0")
        tracker = _Tracker()
        fake_llm.scripted = _two_calls("p1", "p2")
        agent = Agent(ctx=ctx, role="researcher", brief="read two files")
        agent.tools.register(tracker.tool("p1", parallel_safe=True))
        agent.tools.register(tracker.tool("p2", parallel_safe=True))
        result = await agent.run()
        assert result.final == "done"
        assert tracker.max_active == 1

    @pytest.mark.asyncio
    async def test_result_order_matches_call_order(self, ctx, fake_llm):
        tracker = _Tracker()
        fake_llm.scripted = _two_calls("p1", "p2")
        agent = Agent(ctx=ctx, role="researcher", brief="read two files")
        agent.tools.register(tracker.tool("p1", parallel_safe=True))
        agent.tools.register(tracker.tool("p2", parallel_safe=True))
        await agent.run()
        # The second LLM call carries the tool_results; their ids must be
        # in the same order the model requested them.
        ids = [
            b["tool_use_id"]
            for m in fake_llm.calls[1]["messages"]
            for b in (m["content"] if isinstance(m["content"], list) else [])
            if isinstance(b, dict) and b.get("type") == "tool_result"
        ]
        assert ids == ["a", "b"]

    def test_make_tool_result_flags_errors(self):
        assert Agent._make_tool_result("x", "ERROR: boom")["is_error"] is True
        assert Agent._make_tool_result("x", "BLOCKED by Shield: nope")["is_error"] is True
        assert "is_error" not in Agent._make_tool_result("x", "ok")
