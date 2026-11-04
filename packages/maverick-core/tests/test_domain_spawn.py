"""spawn-from-profile: a DomainProfile -> a live Agent.

Constructs a real Agent, so it needs the full maverick-core install (run in CI,
not in the lightweight local subset).
"""
from __future__ import annotations

import pytest
from maverick.agent_autonomy import AutonomyLevel, AutonomyProfile
from maverick.capability import Capability
from maverick.domain import DomainProfile, agent_from_profile


def _ctx(tmp_path):
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("g", "")
    return SwarmContext(
        llm=None, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id, use_skills=False,
    )


@pytest.mark.parametrize("allow_tools,max_risk", [
    ([], None),
    (["read_file"], None),
    ([], "low"),
    (["read_file"], "unlimited"),
])
def test_agent_from_profile_rejects_missing_or_invalid_envelope(allow_tools, max_risk):
    with pytest.raises(ValueError, match="Domain .* (allow_tools|max_risk)"):
        agent_from_profile(
            DomainProfile(name="unsafe", allow_tools=allow_tools, max_risk=max_risk),
            None,
            "work",
        )


def test_agent_from_profile_rejects_malformed_deny_list_before_spawn():
    with pytest.raises(ValueError, match="deny_tools"):
        agent_from_profile(
            DomainProfile(name="unsafe", allow_tools=["shell"],
                          deny_tools="shell", max_risk="high"),
            None, "work",
        )


def test_agent_from_profile_sets_domain_persona_and_capability(tmp_path):
    ctx = _ctx(tmp_path)
    profile = DomainProfile(
        name="finance", compartment="finance",
        persona="You are a finance specialist. Cite every figure.",
        allow_tools=["read_file"], deny_tools=["shell"], max_risk="medium",
    )
    agent = agent_from_profile(profile, ctx, "Analyze Q3 revenue")

    assert agent.role == "finance"
    assert agent.domain == "finance"                 # sector tag for Rung 2
    assert "finance specialist" in agent.system      # persona injected
    assert agent.capability is not None
    assert agent.capability.permits("read_file") is True
    assert agent.capability.permits("shell") is False  # envelope enforced


def test_agent_from_profile_uses_active_handoff_grant_for_parent(tmp_path):
    ctx = _ctx(tmp_path)
    parent = agent_from_profile(
        DomainProfile(
            name="parent",
            allow_tools=["shell", "spawn_specialist"], max_risk="high",
        ),
        ctx,
        "parent task",
    )
    parent._handoff_capability = Capability(
        principal="agent:delegate",
        allow_tools=frozenset({"spawn_specialist"}),
    )
    profile = DomainProfile(
        name="finance",
        compartment="finance",
        allow_tools=["shell", "spawn_specialist"], max_risk="high",
    )

    child = agent_from_profile(profile, ctx, "Analyze Q3 revenue", parent=parent, depth=1)

    assert child.capability is not None
    assert child.capability.permits("spawn_specialist") is True
    assert child.capability.permits("shell") is False


def test_root_specialist_is_bounded_by_the_run_capability(tmp_path):
    """The depth-0 specialist root runs under the pack's envelope AND the run's
    own grant (``ctx.capability``: for a fleet agent, its role + the caller's
    grant). It used to mint the pack's envelope alone, so a narrower run grant
    was silently widened back out to everything the pack allows. The run's
    principal is kept, so the oversight control plane still governs the work
    as the agent that was dispatched."""
    ctx = _ctx(tmp_path)
    ctx.capability = Capability(
        principal="agent:dept-ops.finance",
        allow_tools=frozenset({"read_file"}),
        max_risk="low",
    )
    profile = DomainProfile(
        name="finance", compartment="finance",
        persona="You are a finance specialist. Cite every figure.",
        allow_tools=["read_file", "web_search", "write_file"],
        deny_tools=["shell"], max_risk="high",
    )

    root = agent_from_profile(profile, ctx, "Analyze Q3 revenue")

    assert root.capability.permits("read_file") is True
    assert root.capability.permits("web_search") is False  # pack allows it, run grant does not
    assert root.capability.permits("write_file") is False
    assert root.capability.max_risk == "low"
    assert root.capability.principal == "agent:dept-ops.finance"


def test_root_specialist_without_a_run_capability_keeps_its_own_envelope(tmp_path):
    ctx = _ctx(tmp_path)
    assert ctx.capability is None
    profile = DomainProfile(
        name="finance", compartment="finance",
        allow_tools=["read_file", "web_search"], max_risk="medium",
    )

    root = agent_from_profile(profile, ctx, "Analyze Q3 revenue")

    assert root.capability.permits("web_search") is True
    assert root.capability.principal == "agent:finance-0"


def test_agent_from_profile_no_autonomy_block_uses_own_suite_default(tmp_path):
    ctx = _ctx(tmp_path)
    parent = agent_from_profile(
        DomainProfile(
            name="parent",
            allow_tools=["read_file"], max_risk="low",
            autonomy=AutonomyProfile(default=AutonomyLevel.AUTO, onboarding=False),
        ),
        ctx,
        "parent task",
    )
    profile = DomainProfile(
        name="bank_wire_review",
        allow_tools=["read_file"], max_risk="low",
        autonomy=None,
    )

    child = agent_from_profile(profile, ctx, "Review transfer", parent=parent, depth=1)

    assert child._autonomy is not parent._autonomy
    assert child._autonomy.default is AutonomyLevel.SUGGEST
    assert child._autonomy.onboarding is True


def test_children_inherit_parent_domain(tmp_path):
    from maverick.agent import Agent

    ctx = _ctx(tmp_path)
    profile = DomainProfile(name="finance", compartment="finance",
                            allow_tools=["read_file"], max_risk="low")
    parent = agent_from_profile(profile, ctx, "parent task")

    child = Agent(ctx=ctx, role="researcher", brief="sub", depth=1, parent=parent)
    assert child.domain == "finance"  # inherited -> a sector seal catches the sub-tree
    assert child.knowledge_sources == parent.knowledge_sources  # inherited too


def test_agent_from_profile_sets_knowledge_sources(tmp_path):
    ctx = _ctx(tmp_path)
    profile = DomainProfile(name="finance", knowledge_sources=["finance"],
                            allow_tools=["read_file"], max_risk="low")
    agent = agent_from_profile(profile, ctx, "task")
    assert agent.knowledge_sources == ["finance"]


def test_agent_from_profile_depth_zero_root_is_goal_root(tmp_path):
    # Run_goal's domain-routed root (orchestrator.py) always calls
    # agent_from_profile with no parent, at depth 0 -- role=profile.name,
    # e.g. "finance_controller", never "orchestrator". Every kernel
    # mechanic gated on "is this the goal's root" must still fire for it.
    ctx = _ctx(tmp_path)
    profile = DomainProfile(name="finance_controller", allow_tools=["read_file"], max_risk="low")
    root = agent_from_profile(profile, ctx, "close the books")
    assert root.role == "finance_controller"
    assert root._is_goal_root is True

    child = agent_from_profile(profile, ctx, "sub-task", parent=root, depth=1)
    assert child._is_goal_root is False  # a nested domain spawn is not the root


def test_domain_routed_root_gets_orchestrator_template_with_persona(tmp_path):
    # select_base_template must not pick the WORKER template
    # ("You are a specialist agent... depth 0") for ANY role other than
    # literally "orchestrator" -- or a domain pack's root would never get the
    # orchestrator framing that tells it to decompose/delegate/verify. The
    # persona is layered on separately (apply_role_overlays), so fixing the
    # base template must not lose it.
    ctx = _ctx(tmp_path)
    profile = DomainProfile(
        name="finance_controller",
        persona="You are the finance controller. Cite every figure.",
        allow_tools=["read_file"], max_risk="low",
    )
    root = agent_from_profile(profile, ctx, "close the books")
    assert "You are the orchestrator of a Lightwork swarm" in root.system
    assert "specialist agent" not in root.system
    assert "finance controller" in root.system  # persona preserved


@pytest.mark.asyncio
async def test_domain_routed_root_invokes_the_final_verifier(tmp_path, monkeypatch):
    # End-to-end regression: a domain-routed root's FINAL must not be
    # accepted with verifier_confidence=1.0 and no verifier LLM call at all -- indistinguishable from a genuinely-verified answer to
    # every downstream consumer (trajectory donation, the autonomy servo,
    # the dashboard). This reproduces run_goal's real path (agent_from_profile
    # at depth 0, no parent) rather than a bare Agent(role=...) construction.
    monkeypatch.setenv("MAVERICK_REHEARSAL", "0")
    from maverick.llm import LLMResponse

    class _ScriptedLLM:
        model = "fake:test"

        def __init__(self, scripted):
            self.scripted = list(scripted)
            self.calls = []

        async def complete_async(self, **kwargs):
            self.calls.append(kwargs)
            if self.scripted:
                return self.scripted.pop(0)
            return LLMResponse(text="FINAL: (exhausted)", thinking=None,
                               tool_calls=[], stop_reason="end_turn")

    ctx = _ctx(tmp_path)
    ctx.llm = _ScriptedLLM([
        LLMResponse(text="FINAL: books closed", thinking=None,
                    tool_calls=[], stop_reason="end_turn"),
        LLMResponse(
            text='{"confidence":0.95,"accepts":true,"critique":"ok","issues":[]}',
            thinking=None, tool_calls=[], stop_reason="end_turn",
        ),
    ])
    profile = DomainProfile(name="finance_controller", allow_tools=["read_file"], max_risk="low")
    root = agent_from_profile(profile, ctx, "close the books")

    result = await root.run()

    assert result.final == "books closed"
    assert len(ctx.llm.calls) == 2  # FINAL + the verifier that actually ran
    assert result.verifier_confidence == pytest.approx(0.95)


def test_build_intake_agent_assembles_interviewer(tmp_path):
    from maverick.intake import build_intake_agent
    ctx = _ctx(tmp_path)
    agent, session = build_intake_agent(ctx)
    tool_names = {tool.name for tool in agent.tools.all()}
    assert agent.role == "intake"
    assert "onboarding specialist" in agent.system  # the intake persona is in the prompt
    assert tool_names == {
        "record_business", "add_goal", "add_document", "finalize_intake",
    }
    assert "shell" not in tool_names
    assert "read_file" not in tool_names
    assert "write_file" not in tool_names


def _one_pack_per_suite():
    # A representative built-in pack from each suite -- enough to exercise the
    # spawn path (persona + discipline + workflow render + capability) for every
    # suite without constructing 1,118 Agents.
    from maverick.domain import builtin_dir, load_domains, suite_for
    packs = load_domains(builtin_dir())
    sample = {}
    for name, p in sorted(packs.items()):
        sample.setdefault(suite_for(name) or "generic", (name, p))
    return [v for v in sample.values()]


def test_every_suite_spawns_with_workflow_and_envelope(tmp_path, monkeypatch):
    # Smoke test: a pack from each suite spawns to a live Agent whose system
    # prompt carries its persona and rendered playbook, under an enforced
    # envelope. Catches a pack whose appended [[workflow]] breaks the spawn path.
    ctx = _ctx(tmp_path)
    sample = _one_pack_per_suite()
    assert len(sample) >= 25, f"only {len(sample)} suites sampled"
    # This test covers persona/envelope construction in a provisioned deployment.
    # Abstract customer adapters are explicit fixtures; the separate pack contract
    # tests prove missing adapters refuse deployment before model work starts.
    from maverick.agent import Agent
    from maverick.tools import Tool
    build_tools = Agent._build_tools
    required = {tool for _, profile in sample for step in profile.workflow for tool in step.tools}

    def provisioned_tools(agent):
        registry = build_tools(agent)
        for name in required - {tool.name for tool in registry.all()}:
            registry.register(Tool(name=name, description="Offline customer adapter fixture",
                                   input_schema={"type": "object"}, fn=lambda args: "fixture"))
        return registry

    monkeypatch.setattr(Agent, '_build_tools', provisioned_tools)
    for name, profile in sample:
        agent = agent_from_profile(profile, ctx, "Do your job for the period.")
        assert agent.role == name
        if profile.workflow:
            assert "Workflow" in agent.system, f"{name}: playbook not in system prompt"
            assert profile.workflow[0].name in agent.system, f"{name}: step missing"
        # Envelope still enforced regardless of the new content.
        assert agent.capability.permits("read_file") is True, name
        if "shell" not in profile.allow_tools:
            assert agent.capability.permits("shell") is False, name


def test_pack_effort_tier_flows_to_agent(tmp_path, monkeypatch):
    # A pack's authored effort tier reaches the live agent -- but only when the
    # effort feature is enabled (off by default, so no behaviour change).
    from maverick import effort as effort_mod
    ctx = _ctx(tmp_path)
    profile = DomainProfile(
        name="finance_sox", persona="You audit SOX controls. Cite evidence.",
        allow_tools=["read_file"], deny_tools=["shell", "write_file"],
        max_risk="low", effort="high",
        models={"x": "claude-opus-4-8"},
    )
    # Feature OFF -> pack tier ignored.
    monkeypatch.setattr(effort_mod, "_config_effort", dict)
    a_off = agent_from_profile(profile, ctx, "Test the access controls.")
    assert a_off.effort is None
    # Feature ON -> pack tier applied (clamped to the model).
    monkeypatch.setattr(effort_mod, "_config_effort", lambda: {"enabled": True})
    a_on = agent_from_profile(profile, ctx, "Test the access controls.")
    assert a_on.effort == "high"


def test_refusals_reach_the_agent_system_prompt(tmp_path):
    # A spawned HR agent carries its hard refusals (Art-5) in the system prompt,
    # independent of the model following persona prose.
    ctx = _ctx(tmp_path)
    profile = DomainProfile(
        name="hr_screening", persona="You screen resumes against the rubric.",
        allow_tools=["read_file"], deny_tools=["shell", "write_file"], max_risk="low",
        refuse=["never rank candidates by a credit score"],
    )
    agent = agent_from_profile(profile, ctx, "Screen these five resumes.")
    assert "Hard refusals" in agent.system
    assert "emotion" in agent.system           # suite (Art-5) refusal injected
    assert "credit score" in agent.system      # pack-specific refusal injected
