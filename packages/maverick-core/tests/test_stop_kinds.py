"""Structured stop reasons and the provider usage-accounting stop.

The orchestrator used to classify any agent error containing "halt" as
"a HALT file is present -- run maverick unhalt", which is what a
review-checkpoint stop (a reviewer declining to continue) was reported as.
And a gateway that mis-reported token usage surfaced as "budget exceeded",
sending operators to raise max_dollars. Both now carry a structured
``AgentResult.stop_kind`` the orchestrator branches on.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import killswitch
from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget, UsageAccountingError
from maverick.llm import ToolCall
from maverick.orchestrator import run_goal
from maverick.review_checkpoint import CheckpointPolicy, ReviewCheckpoint
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel


@pytest.fixture(autouse=True)
def _quiet(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setattr("maverick.audit.record", lambda *a, **k: None)


@pytest.fixture
def ctx(tmp_path: Path, fake_llm):
    world = WorldModel(path=tmp_path / "world.db")
    goal_id = world.create_goal("test goal", "")
    return SwarmContext(
        llm=fake_llm, world=world, budget=Budget(max_dollars=5.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id, max_depth=1, use_skills=False,
    )


class _AccountingBrokenLLM:
    model = "fake:test"

    def __init__(self):
        self.calls = 0

    async def complete_async(self, **kwargs):
        self.calls += 1
        raise UsageAccountingError("invalid OpenAI usage.prompt_tokens: None")


# ---- agent level ----

@pytest.mark.asyncio
async def test_agent_reports_malformed_usage_as_a_provider_fault(ctx):
    ctx.llm = _AccountingBrokenLLM()
    result = await Agent(ctx=ctx, role="researcher", brief="...").run()
    assert result.stop_kind == "usage_accounting"
    assert result.error.startswith("provider usage accounting:")
    assert "budget" not in result.error.lower()
    assert "prompt_tokens" in result.stop_detail


@pytest.mark.asyncio
async def test_agent_tags_a_review_checkpoint_stop(ctx, fake_llm, make_llm_response):
    fake_llm.scripted = [make_llm_response(text="FINAL: never reached")]
    agent = Agent(ctx=ctx, role="orchestrator", brief="long run")
    # A reviewer that declines to continue once 1 tool call has been made.
    agent._review_checkpoint = ReviewCheckpoint(
        CheckpointPolicy(tool_calls=1), review=lambda event: False)
    ctx.budget.tool_calls = 1
    result = await agent.run()
    assert result.stop_kind == "review_checkpoint"
    assert result.stop_detail == "tool_calls=1"
    assert "review checkpoint" in result.error
    assert fake_llm.calls == []          # stopped before the next model call


@pytest.mark.asyncio
async def test_agent_tags_a_killswitch_stop(ctx, fake_llm, make_llm_response):
    fake_llm.scripted = [make_llm_response(text="FINAL: never reached")]
    killswitch.halt("test halt")
    try:
        result = await Agent(ctx=ctx, role="researcher", brief="...").run()
    finally:
        killswitch.clear()
    assert result.stop_kind == "killswitch"
    assert "halted" in result.error


# ---- orchestrator level ----

def _goal(tmp_path):
    world = WorldModel(path=tmp_path / "world.db")
    return world, world.create_goal("do the thing", "")


@pytest.mark.asyncio
async def test_review_checkpoint_stop_is_not_reported_as_a_halt_file(
    tmp_path, fake_llm, make_llm_response, monkeypatch,
):
    # Opt-in checkpoint every tool call; the consent reviewer denies without an
    # explicit approval, so the run stops after its first tool call.
    monkeypatch.setenv("MAVERICK_REVIEW_CHECKPOINT_TOOL_CALLS", "1")
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-approve")
    fake_llm.scripted = [
        make_llm_response(
            text="working",
            tool_calls=[ToolCall(id="t1", name="shell", input={"cmd": "echo hi"})],
        ),
        make_llm_response(text="FINAL: should not be reached"),
    ]
    world, gid = _goal(tmp_path)
    out = await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=5.0), goal_id=gid,
        sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )
    assert "review checkpoint" in out
    assert "tool_calls=1" in out
    assert f"maverick resume {gid}" in out
    assert "HALT file" not in out and "unhalt" not in out
    goal = world.get_goal(gid)
    assert goal.status == "blocked"
    assert goal.result.startswith("stopped at review checkpoint")


@pytest.mark.asyncio
async def test_killswitch_mid_run_still_gets_the_unhalt_advice(
    tmp_path, make_llm_response,
):
    class _HaltingLLM:
        model = "fake:test"

        async def complete_async(self, **kwargs):
            killswitch.halt("halt during think")
            return make_llm_response(
                text="acting",
                tool_calls=[ToolCall(id="t1", name="shell", input={"cmd": "echo hi"})],
            )

    world, gid = _goal(tmp_path)
    try:
        out = await run_goal(
            llm=_HaltingLLM(), world=world, budget=Budget(max_dollars=5.0),
            goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
        )
    finally:
        killswitch.clear()
    assert "halted mid-run" in out and "maverick unhalt" in out
    assert world.get_goal(gid).result == "halted"


@pytest.mark.asyncio
async def test_malformed_usage_is_reported_as_a_provider_fault_not_a_cap(tmp_path):
    world, gid = _goal(tmp_path)
    out = await run_goal(
        llm=_AccountingBrokenLLM(), world=world, budget=Budget(max_dollars=5.0),
        goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )
    assert "invalid usage accounting" in out
    assert "prompt_tokens" in out
    assert "spending or time limit" not in out
    assert "raising the cap will not fix it" in out
    goal = world.get_goal(gid)
    assert goal.status == "blocked"
    assert goal.result.startswith("provider usage accounting:")


def test_cli_humaniser_names_the_gateway_fault():
    from maverick.cli import _humanize_run_error

    text = _humanize_run_error(UsageAccountingError("invalid OpenAI usage.prompt_tokens: nan"))
    assert "invalid usage accounting" in text
    assert "not a budget problem" in text
    assert "prompt_tokens" in text
