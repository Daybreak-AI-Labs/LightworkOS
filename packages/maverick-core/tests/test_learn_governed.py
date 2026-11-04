"""learn_capability routes its nested tool calls through the gated _run_tool
chokepoint (shield + capability + governance + hooks), not the bare registry --
closing a control-plane bypass where an agent granted `learn` could otherwise
drive web_search / openapi_runner ungoverned.
"""
from __future__ import annotations

import pytest
from maverick.tools import Tool


def _agent(tmp_path):
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("g", "")
    ctx = SwarmContext(
        llm=None, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=gid, use_skills=False,
    )
    return Agent(ctx=ctx, role="coder", brief="b")


@pytest.mark.asyncio
async def test_find_api_web_search_routes_through_run_tool(monkeypatch, tmp_path):
    from maverick import self_learning
    from maverick.tools.learn import learn_capability

    agent = _agent(tmp_path)
    agent.tools.register(Tool(
        name="web_search", description="search", fn=lambda a: "hits",
        input_schema={"type": "object", "properties": {}},
    ))
    monkeypatch.setattr(self_learning, "probe_openapi_spec", lambda *a, **k: None)
    monkeypatch.setattr(self_learning, "discover_openapi_spec", lambda *a, **k: "")

    gated: list[str] = []
    real = agent._run_tool

    async def _spy(name, args):
        gated.append(name)
        return await real(name, args)

    monkeypatch.setattr(agent, "_run_tool", _spy)

    await learn_capability(agent).fn({"op": "find_api", "need": "weather api"})
    # web_search executed through the gated chokepoint, not the bare registry.
    assert "web_search" in gated


@pytest.mark.asyncio
async def test_find_api_web_search_blocked_by_capability(monkeypatch, tmp_path):
    from maverick import self_learning
    from maverick.capability import Capability
    from maverick.tools.learn import learn_capability

    agent = _agent(tmp_path)
    ran = {"web_search": False}
    agent.tools.register(Tool(
        name="web_search", description="search",
        fn=lambda a: ran.__setitem__("web_search", True) or "hits",
        input_schema={"type": "object", "properties": {}},
    ))
    # The capability denies web_search -> the chokepoint must block the nested
    # call, so the underlying tool never actually runs.
    agent.capability = Capability(
        principal="agent:x", deny_tools=frozenset({"web_search"}))
    monkeypatch.setattr(self_learning, "probe_openapi_spec", lambda *a, **k: None)
    monkeypatch.setattr(self_learning, "discover_openapi_spec", lambda *a, **k: "")

    out = await learn_capability(agent).fn({"op": "find_api", "need": "weather api"})
    assert ran["web_search"] is False           # denied at the gate, never executed
    assert "Could not auto-discover" in out     # degrades gracefully
