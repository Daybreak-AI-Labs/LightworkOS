"""Per-call token exchange at the agent tool chokepoint.

With ``[capabilities] per_call_tokens`` on, every tool call mints a single-tool,
short-lived, signed token and verifies it before dispatch. A valid exchange is
transparent (the tool runs); a verification failure fail-closes (the tool does
not run). Off by default it is a pure no-op.

Mirrors ``tests/test_capability_path_enforcement.py``'s ``_agent`` + ``_run_tool``
harness; hermetic (no real LLM, no network).
"""
import pytest
from maverick.capability import Capability
from maverick.tools import Tool


def _agent(tmp_path):
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("g", "")
    ctx = SwarmContext(
        llm=None, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id, use_skills=False,
    )
    return Agent(ctx=ctx, role="coder", brief="b")


def _spy_tool(name: str, calls: list) -> Tool:
    return Tool(
        name=name,
        description="spy",
        fn=lambda args: calls.append(args) or "ran",
        input_schema={"type": "object", "properties": {}},
    )


@pytest.mark.asyncio
async def test_valid_exchange_is_transparent(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TOOL_TOKENS", "1")
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1")
    calls: list = []
    agent.tools.register(_spy_tool("read_file", calls))

    out = await agent._run_tool("read_file", {})
    assert "ran" in out
    assert "DENIED" not in out
    assert calls == [{}]  # the tool ran exactly once


@pytest.mark.asyncio
async def test_failed_verification_fail_closes(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TOOL_TOKENS", "1")
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1")
    calls: list = []
    agent.tools.register(_spy_tool("read_file", calls))

    # Force verification to fail (e.g. an out-of-process verifier rejecting the
    # token): the tool must not run and the model gets a non-leaky refusal.
    monkeypatch.setattr(
        "maverick.tool_token.verify_tool_token", lambda *a, **k: False
    )
    out = await agent._run_tool("read_file", {})
    assert "DENIED by capability policy" in out
    assert "per-call token" in out
    assert calls == []  # the tool did not run


@pytest.mark.asyncio
async def test_disabled_is_a_noop(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_TOOL_TOKENS", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1")
    calls: list = []
    agent.tools.register(_spy_tool("read_file", calls))

    # Even if minting would fail, the disabled path must never call it.
    def _boom(*a, **k):  # pragma: no cover -- must not be reached
        raise AssertionError("token exchange ran while disabled")

    monkeypatch.setattr("maverick.tool_token.mint_tool_token", _boom)
    out = await agent._run_tool("read_file", {})
    assert "ran" in out
    assert "DENIED" not in out
    assert calls == [{}]
