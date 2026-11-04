"""Per-agent autonomy levels wired into the agent tool chokepoint.

Exercises ``_run_tool`` directly (no live LLM): the hire's autonomy rung gates a
*consequential* tool -- OBSERVE denies, SUGGEST stages, REQUEST asks a human, AUTO
runs -- composed strictest-wins with org governance. Off by default and
low-risk tools are never gated.
"""
from __future__ import annotations

import pytest
from maverick.agent_autonomy import AutonomyLevel, AutonomyProfile
from maverick.tools import Tool


def _agent(tmp_path, profile, *, role="fin_clerk"):
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
    agent = Agent(ctx=ctx, role=role, brief="b", autonomy=profile)
    agent.capability = None  # isolate from the capability layer
    agent.tools.register(Tool(
        name="act", description="a consequential action", fn=lambda args: "done",
        input_schema={"type": "object", "properties": {}},
    ))
    agent.tools.register(Tool(
        name="look", description="a read", fn=lambda args: "data",
        input_schema={"type": "object", "properties": {}},
    ))
    return agent


@pytest.fixture
def _high_risk_act(monkeypatch):
    """Classify ``act`` as high-risk and ``look`` as low, everywhere the gate or
    resolver looks ``tool_risk`` up."""
    import importlib

    import maverick.agent_autonomy as aa
    tr = importlib.import_module("maverick.safety.tool_risk")
    fake = lambda n, *a, **k: "high" if n == "act" else "low"  # noqa: E731
    monkeypatch.setattr(tr, "tool_risk", fake)          # the gate's `from ... import`
    monkeypatch.setattr(aa, "tool_risk", fake)          # resolver's module-level copy


def _enable(monkeypatch, agents=None):
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "1")
    monkeypatch.setattr(
        "maverick.config.get_workforce",
        lambda: {"levels": True, "agents": agents or {}},
    )
    # no org governance policy configured
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    # Accept the keyword form (`include_tenant=False`) the deployment-global
    # enterprise check uses; `dict(include_tenant=False)` is a non-empty error map.
    monkeypatch.setattr("maverick.config.config_source_errors", lambda *a, **k: {})


@pytest.mark.asyncio
async def test_off_by_default_runs(monkeypatch, tmp_path, _high_risk_act):
    monkeypatch.delenv("MAVERICK_WORKFORCE_LEVELS", raising=False)
    monkeypatch.setattr("maverick.config.get_workforce", lambda: {"levels": False, "agents": {}})
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    agent = _agent(tmp_path, AutonomyProfile(default=AutonomyLevel.OBSERVE, onboarding=False))
    out = await agent._run_tool("act", {})
    assert "done" in out  # disabled => historical behaviour, not gated here


@pytest.mark.asyncio
async def test_auto_runs(monkeypatch, tmp_path, _high_risk_act):
    _enable(monkeypatch)
    agent = _agent(tmp_path, AutonomyProfile(default=AutonomyLevel.AUTO, onboarding=False))
    out = await agent._run_tool("act", {})
    assert "done" in out


@pytest.mark.asyncio
async def test_enabled_autonomy_evaluation_error_fails_closed(
    monkeypatch, tmp_path, _high_risk_act
):
    import maverick.agent_autonomy as aa

    _enable(monkeypatch)

    def _broken_decision(*args, **kwargs):
        raise RuntimeError("profile evaluator unavailable")

    monkeypatch.setattr(aa, "decide", _broken_decision)
    agent = _agent(
        tmp_path,
        AutonomyProfile(default=AutonomyLevel.AUTO, onboarding=False),
    )

    out = await agent._run_tool("act", {})

    assert "done" not in out
    assert "DENIED" in out
    assert "evaluation was unavailable" in out


@pytest.mark.asyncio
async def test_observe_denies_consequential(monkeypatch, tmp_path, _high_risk_act):
    _enable(monkeypatch)
    agent = _agent(tmp_path, AutonomyProfile(default=AutonomyLevel.OBSERVE, onboarding=False))
    out = await agent._run_tool("act", {})
    assert "done" not in out
    assert "DENIED" in out


@pytest.mark.asyncio
async def test_suggest_stages_without_execution(monkeypatch, tmp_path, _high_risk_act):
    _enable(monkeypatch)
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-approve")  # silent auto != a human
    agent = _agent(tmp_path, AutonomyProfile(default=AutonomyLevel.SUGGEST, onboarding=False))
    out = await agent._run_tool("act", {})
    assert "done" not in out
    from maverick.agent import _NotExecutedToolResult
    assert isinstance(out, _NotExecutedToolResult)
    assert "no approval to run it was requested" in out.lower()
    saved = agent.ctx.world.artifacts_for_goal(agent.ctx.goal_id)
    assert len(saved) == 1
    assert saved[0]["title"] == "Suggested action for a person"
    assert '"a consequential action"' in saved[0]["content"]


@pytest.mark.asyncio
async def test_low_risk_never_gated(monkeypatch, tmp_path, _high_risk_act):
    """Even an OBSERVE hire may freely use low-risk (read) tools."""
    _enable(monkeypatch)
    agent = _agent(tmp_path, AutonomyProfile(default=AutonomyLevel.OBSERVE, onboarding=False))
    out = await agent._run_tool("look", {})
    assert "data" in out


@pytest.mark.asyncio
async def test_client_override_grants_auto(monkeypatch, tmp_path, _high_risk_act):
    """A pack default of SUGGEST is lifted to AUTO by a [workforce.agents] override."""
    _enable(monkeypatch, agents={"fin_clerk": {"default": "auto", "onboarding": False}})
    agent = _agent(tmp_path, AutonomyProfile(default=AutonomyLevel.SUGGEST, onboarding=True))
    out = await agent._run_tool("act", {})
    assert "done" in out


@pytest.mark.asyncio
async def test_spawned_child_role_cannot_broaden_inherited_autonomy(
    monkeypatch, tmp_path, _high_risk_act
):
    """A model-selected child role must not re-anchor workforce overrides.

    The child inherits the parent's low-authority profile; choosing a configured
    high-authority role name during ad-hoc spawn must not layer that role's
    override over the inherited profile.
    """
    from maverick.agent import Agent

    _enable(
        monkeypatch,
        agents={"trusted_auto": {"default": "auto", "onboarding": False}},
    )
    parent = _agent(
        tmp_path,
        AutonomyProfile(default=AutonomyLevel.OBSERVE, onboarding=False),
        role="low_parent",
    )
    child = Agent(
        ctx=parent.ctx,
        role="trusted_auto",
        brief="child",
        depth=parent.depth + 1,
        parent=parent,
    )
    child.capability = None
    child.tools.register(Tool(
        name="act", description="a consequential action", fn=lambda args: "done",
        input_schema={"type": "object", "properties": {}},
    ))

    out = await child._run_tool("act", {})

    assert child._autonomy is parent._autonomy
    assert child._autonomy_name == "low_parent"
    assert "done" not in out
    assert "DENIED" in out


@pytest.mark.asyncio
async def test_coordination_not_gated_by_dial(monkeypatch, tmp_path, _high_risk_act):
    """Even an OBSERVE hire with levels on may spawn/message peers -- the
    coordination control-plane is exempt from the autonomy dial."""
    _enable(monkeypatch)
    agent = _agent(tmp_path, AutonomyProfile(default=AutonomyLevel.OBSERVE, onboarding=False))
    agent.tools.register(Tool(
        name="spawn_specialist", description="spawn a peer", fn=lambda args: "spawned",
        input_schema={"type": "object", "properties": {}},
    ))
    out = await agent._run_tool("spawn_specialist", {})
    assert "spawned" in out  # not gated despite OBSERVE + high-risk classification


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
