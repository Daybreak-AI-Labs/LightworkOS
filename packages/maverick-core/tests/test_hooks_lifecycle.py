"""Tests for the agent/goal lifecycle hook events.

The hook *machinery* (registry, dispatch, config/entry-point loading) is
covered by test_hooks.py. These tests cover the lifecycle seams beyond
PreToolUse/PostToolUse: ensure_loaded(), SessionStart, SessionEnd,
UserPromptSubmit (blocking), Stop, and SubagentStop.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import hooks
from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.hooks import HookEvent
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.tools.spawn import spawn_subagent_tool
from maverick.world_model import WorldModel


@pytest.fixture(autouse=True)
def _clean_hooks():
    """Each test owns the global registry; clear before and after so hooks
    don't leak across tests (and reset the ensure_loaded latch)."""
    hooks.clear()
    yield
    hooks.clear()


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
        max_depth=2,
        use_skills=False,
    )


@pytest.mark.asyncio
async def test_emit_dispatches_lifecycle_event_with_context():
    seen: list[hooks.HookContext] = []
    hooks.register(HookEvent.STOP, lambda c: seen.append(c) or True)

    allowed = await hooks.emit(
        HookEvent.STOP, goal_id=7, agent_role="coder", extra={"final": "done"}
    )

    assert allowed is True
    assert len(seen) == 1
    assert seen[0].event is HookEvent.STOP
    assert seen[0].goal_id == 7
    assert seen[0].agent_role == "coder"
    assert seen[0].extra["final"] == "done"


@pytest.mark.asyncio
async def test_ensure_loaded_fires_session_start_once():
    calls: list[int] = []
    hooks.register(HookEvent.SESSION_START, lambda c: calls.append(1) or True)

    await hooks.ensure_loaded()
    await hooks.ensure_loaded()  # idempotent: must not re-fire

    assert calls == [1]


def test_session_end_noop_without_hook_then_fires_with_hook():
    # Sync test (no running loop) so _emit_session_end's asyncio.run works.
    hooks.clear()
    # No SessionEnd hook registered -> no-op, must not raise.
    hooks._emit_session_end()

    fired: list[int] = []
    hooks.register(HookEvent.SESSION_END, lambda c: fired.append(1) or True)
    hooks._emit_session_end()
    assert fired == [1]


@pytest.mark.asyncio
async def test_user_prompt_submit_hook_can_block_goal(tmp_path: Path, fake_llm):
    # A falsy UserPromptSubmit hook blocks the goal before any LLM call.
    hooks.register(HookEvent.USER_PROMPT_SUBMIT, lambda c: False)

    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("do something", "")
    out = await run_goal(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        goal_id=gid,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    assert "BLOCKED" in out
    assert world.get_goal(gid).status == "blocked"
    # Hook blocked before the orchestrator ran, so the LLM was never called.
    assert fake_llm.calls == []


@pytest.mark.asyncio
async def test_stop_hook_fires_when_agent_finalizes(ctx, fake_llm, make_llm_response):
    fired: list[hooks.HookContext] = []
    hooks.register(HookEvent.STOP, lambda c: fired.append(c) or True)

    fake_llm.scripted = [make_llm_response(text="FINAL: the answer is 42")]
    agent = Agent(ctx=ctx, role="researcher", brief="compute the answer")
    result = await agent.run()

    assert result.final == "the answer is 42"
    assert len(fired) == 1
    assert fired[0].agent_role == "researcher"
    assert fired[0].extra["final"] == "the answer is 42"


@pytest.mark.asyncio
async def test_subagent_stop_hook_fires_on_spawn(ctx, fake_llm, make_llm_response):
    fired: list[hooks.HookContext] = []
    hooks.register(HookEvent.SUBAGENT_STOP, lambda c: fired.append(c) or True)

    # Child (depth 1) returns FINAL on its first turn; depth>0 skips the
    # LLM verifier, so a single scripted response is enough.
    fake_llm.scripted = [make_llm_response(text="FINAL: child result")]
    parent = Agent(ctx=ctx, role="orchestrator", brief="root", depth=0)
    out = await spawn_subagent_tool(parent).fn({"role": "coder", "task": "do it"})

    assert out == "child result"
    assert len(fired) == 1
    assert fired[0].event is HookEvent.SUBAGENT_STOP
    assert fired[0].agent_role == "coder"
    assert fired[0].extra["final"] == "child result"
