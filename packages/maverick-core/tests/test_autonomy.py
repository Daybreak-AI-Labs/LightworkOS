"""Autonomy gate: the servo that ties the evaluator to the autonomy slider.

Covers the three loops we wired:
  - Loop 1: high swarm disagreement escalates FINAL verification (and sets the
    ctx flag the agent loop reads).
  - Loop 2: low run-trust tightens the effective risk ceiling so high-risk
    tools are gated.
  - Loop 3 / unified gate: gate_tool composes per-tool risk with the servo.
"""
from __future__ import annotations

import pytest
from maverick import autonomy


# --------------------------------------------------------------------------
# unit: decision logic (off by default; env master-switch flips it on)
# --------------------------------------------------------------------------
class TestEnabledDefault:
    def test_off_by_default(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_AUTONOMY_GATE", raising=False)
        # No config file in a clean test home -> defaults -> disabled.
        assert autonomy.autonomy_enabled() is False

    def test_env_enables(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "1")
        assert autonomy.autonomy_enabled() is True

    def test_env_disables(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "0")
        assert autonomy.autonomy_enabled() is False


class TestAssumeWhenHeadless:
    def test_off_by_default(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_AUTONOMOUS", raising=False)
        # Clean test home -> no config -> blocks on ask_user (safe default).
        assert autonomy.assume_when_headless() is False

    def test_env_enables(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTONOMOUS", "1")
        assert autonomy.assume_when_headless() is True

    def test_config_enables_when_env_unset(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_AUTONOMOUS", raising=False)
        monkeypatch.setattr(autonomy, "_resolve", lambda: {"headless_assume": True})
        assert autonomy.assume_when_headless() is True

    def test_env_off_overrides_config_on(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTONOMOUS", "0")
        monkeypatch.setattr(autonomy, "_resolve", lambda: {"headless_assume": True})
        assert autonomy.assume_when_headless() is False

    def test_independent_of_verification_gate(self, monkeypatch):
        # Assume-and-proceed is a distinct axis: it does NOT require the
        # verification gate (MAVERICK_AUTONOMY_GATE) to be enabled.
        monkeypatch.delenv("MAVERICK_AUTONOMY_GATE", raising=False)
        monkeypatch.setenv("MAVERICK_AUTONOMOUS", "1")
        assert autonomy.autonomy_enabled() is False
        assert autonomy.assume_when_headless() is True


class TestShouldEscalate:
    def test_disabled_never_escalates(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_AUTONOMY_GATE", raising=False)
        assert autonomy.should_escalate_verification(0.99) is False

    def test_high_disagreement_escalates_when_enabled(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "1")
        assert autonomy.should_escalate_verification(0.8) is True

    def test_low_disagreement_does_not_escalate(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "1")
        assert autonomy.should_escalate_verification(0.1) is False


class TestTightenCeiling:
    _S = {
        "enable": True, "min_confidence": 0.5, "disagreement_high": 0.5,
        "escalate_verification": True, "tighten_on_low_trust": True,
    }

    def test_no_deficit_leaves_ceiling_unchanged(self):
        out = autonomy.tighten_ceiling(
            "high", disagreement=0.1, verifier_confidence=0.9, settings=self._S,
        )
        assert out == "high"

    def test_high_disagreement_drops_one_rank(self):
        out = autonomy.tighten_ceiling(
            None, disagreement=0.9, verifier_confidence=1.0, settings=self._S,
        )
        # None == no cap (treated as high); one deficit -> medium.
        assert out == "medium"

    def test_low_confidence_drops_one_rank(self):
        out = autonomy.tighten_ceiling(
            "high", disagreement=0.0, verifier_confidence=0.2, settings=self._S,
        )
        assert out == "medium"

    def test_both_conditions_drop_two_ranks(self):
        out = autonomy.tighten_ceiling(
            None, disagreement=0.9, verifier_confidence=0.1, settings=self._S,
        )
        assert out == "low"

    def test_never_below_low(self):
        out = autonomy.tighten_ceiling(
            "low", disagreement=0.9, verifier_confidence=0.1, settings=self._S,
        )
        assert out == "low"

    def test_only_tightens_never_broadens(self):
        # A medium ceiling with low trust must not become high.
        out = autonomy.tighten_ceiling(
            "medium", disagreement=0.9, verifier_confidence=1.0, settings=self._S,
        )
        assert out == "low"


class TestGateTool:
    def test_disabled_allows_everything(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_AUTONOMY_GATE", raising=False)
        v = autonomy.gate_tool("shell", disagreement=0.99, verifier_confidence=0.0)
        assert v.allowed is True

    def test_low_risk_never_gated(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "1")
        # read_file is classified low-risk; even at max distrust it runs.
        v = autonomy.gate_tool("read_file", disagreement=0.99, verifier_confidence=0.0)
        assert v.allowed is True

    def test_high_risk_gated_on_high_disagreement(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "1")
        v = autonomy.gate_tool("shell", disagreement=0.9, verifier_confidence=1.0)
        assert v.allowed is False
        assert v.effective_max_risk == "medium"
        assert "trust is low" in v.reason

    def test_high_risk_allowed_on_consensus(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "1")
        v = autonomy.gate_tool("shell", disagreement=0.0, verifier_confidence=1.0)
        assert v.allowed is True

    def test_medium_risk_survives_one_notch_drop(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "1")
        # One deficit drops a None ceiling to medium. A deliberately medium-rated
        # tool is == the tightened ceiling -> allowed. (An unrated name is not
        # medium any more: it takes the high refusal floor.)
        from maverick.safety.tool_risk import tool_risk
        assert tool_risk("kv_memory", overrides={}) == "medium"
        v = autonomy.gate_tool(
            "kv_memory", disagreement=0.9, verifier_confidence=1.0,
        )
        assert v.allowed is True

    def test_configured_ceiling_composes(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "1")
        # An operator ceiling of medium + one deficit -> low; a high-risk tool is gated
        # even though disagreement alone from None would only reach medium.
        v = autonomy.gate_tool(
            "shell", disagreement=0.9, verifier_confidence=1.0,
            configured_max_risk="medium",
        )
        assert v.allowed is False
        assert v.effective_max_risk == "low"


# --------------------------------------------------------------------------
# integration: the gate is actually wired into Agent._run_tool (Loop 2)
# --------------------------------------------------------------------------
def _ctx(tmp_path, fake_llm):
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("test", "")
    return SwarmContext(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(),
        sandbox=LocalBackend(workdir=tmp_path),
        goal_id=gid, max_depth=1,
    )


class TestAgentGateIntegration:
    @pytest.mark.asyncio
    async def test_high_risk_tool_gated_under_disagreement(
        self, tmp_path, fake_llm, monkeypatch,
    ):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "1")
        from maverick.agent import Agent

        ctx = _ctx(tmp_path, fake_llm)
        ctx.last_disagreement = 0.9  # the swarm couldn't agree
        agent = Agent(ctx=ctx, role="orchestrator", brief="t", depth=0)

        # shell is high-risk: gated before execution, so the command never runs.
        out = await agent._run_tool("shell", {"command": "echo SHOULD_NOT_RUN"})
        assert "GATED by autonomy" in out
        assert "SHOULD_NOT_RUN" not in out

    @pytest.mark.asyncio
    async def test_gate_off_does_not_interfere(self, tmp_path, fake_llm, monkeypatch):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "0")
        from maverick.agent import Agent

        ctx = _ctx(tmp_path, fake_llm)
        ctx.last_disagreement = 0.9
        agent = Agent(ctx=ctx, role="orchestrator", brief="t", depth=0)
        # With the gate off, _run_tool must not return the autonomy refusal.
        out = await agent._run_tool("shell", {"command": "echo hi"})
        assert "GATED by autonomy" not in out


# --------------------------------------------------------------------------
# integration: spawn_swarm escalates on disagreement (Loop 1)
# --------------------------------------------------------------------------
class TestSwarmEscalation:
    @pytest.mark.asyncio
    async def test_divergent_swarm_sets_escalation(
        self, tmp_path, fake_llm, monkeypatch,
    ):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "1")
        import maverick.agent as agent_mod
        from maverick.agent import Agent, AgentResult
        from maverick.tools.spawn import spawn_swarm_tool

        ctx = _ctx(tmp_path, fake_llm)
        parent = Agent(ctx=ctx, role="orchestrator", brief="t", depth=0)

        # Stub each child's run() to return a DISTINCT final -> max entropy.
        counter = {"n": 0}

        async def _fake_run(self):
            counter["n"] += 1
            return AgentResult(
                final=f"answer-variant-{counter['n']}",
                role=self.role, name=self.name,
            )

        monkeypatch.setattr(agent_mod.Agent, "run", _fake_run)

        tool = spawn_swarm_tool(parent)
        out = await tool.fn({"agents": [
            {"role": "researcher", "task": "a"},
            {"role": "researcher", "task": "b"},
            {"role": "researcher", "task": "c"},
        ]})

        assert ctx.escalate_verification is True
        assert ctx.last_disagreement > 0.5
        assert "reconcile" in out.lower()

    @pytest.mark.asyncio
    async def test_consensus_swarm_does_not_escalate(
        self, tmp_path, fake_llm, monkeypatch,
    ):
        monkeypatch.setenv("MAVERICK_AUTONOMY_GATE", "1")
        import maverick.agent as agent_mod
        from maverick.agent import Agent, AgentResult
        from maverick.tools.spawn import spawn_swarm_tool

        ctx = _ctx(tmp_path, fake_llm)
        parent = Agent(ctx=ctx, role="orchestrator", brief="t", depth=0)

        async def _fake_run(self):
            return AgentResult(final="the same answer", role=self.role, name=self.name)

        monkeypatch.setattr(agent_mod.Agent, "run", _fake_run)

        tool = spawn_swarm_tool(parent)
        await tool.fn({"agents": [
            {"role": "researcher", "task": "a"},
            {"role": "researcher", "task": "b"},
        ]})
        assert ctx.escalate_verification is False
        assert ctx.last_disagreement == 0.0


# --------------------------------------------------------------------------
# unit: verify_final routes to the ensemble when forced (Loop 1 plumbing)
# --------------------------------------------------------------------------
class TestVerifyFinalRouting:
    @pytest.mark.asyncio
    async def test_force_ensemble_routes_to_panel(self, monkeypatch):
        import maverick.verifier as v
        called = {"ensemble": False, "single": False}

        async def _ens(*a, **k):
            called["ensemble"] = True
            return v.VerifierVerdict.accept_unconditionally()

        async def _single(*a, **k):
            called["single"] = True
            return v.VerifierVerdict.accept_unconditionally()

        monkeypatch.setattr(v, "verify_proposal_ensemble", _ens)
        monkeypatch.setattr(v, "verify_proposal", _single)
        await v.verify_final("b", "p", object(), None, force_ensemble=True)
        assert called["ensemble"] is True
        assert called["single"] is False

    @pytest.mark.asyncio
    async def test_default_routes_to_structured(self, monkeypatch):
        # The rubric judge is the default now; without ensemble it routes there.
        import maverick.verifier as v
        called = {"ensemble": False, "single": False, "structured": False}

        async def _ens(*a, **k):
            called["ensemble"] = True
            return v.VerifierVerdict.accept_unconditionally()

        async def _single(*a, **k):
            called["single"] = True
            return v.VerifierVerdict.accept_unconditionally()

        async def _structured(*a, **k):
            called["structured"] = True
            return v.VerifierVerdict.accept_unconditionally()

        monkeypatch.setattr(v, "verify_proposal_ensemble", _ens)
        monkeypatch.setattr(v, "verify_proposal", _single)
        monkeypatch.setattr(v, "verify_proposal_structured", _structured)
        monkeypatch.setattr(v, "_ensemble_enabled", lambda: False)
        monkeypatch.setattr(v, "_structured_verify_enabled", lambda: True)
        await v.verify_final("b", "p", object(), None, force_ensemble=False)
        assert called["structured"] is True
        assert called["single"] is False and called["ensemble"] is False

    @pytest.mark.asyncio
    async def test_routes_to_scalar_single_when_structured_disabled(self, monkeypatch):
        # Opting out of the rubric judge falls back to the scalar single verifier.
        import maverick.verifier as v
        called = {"ensemble": False, "single": False, "structured": False}

        async def _ens(*a, **k):
            called["ensemble"] = True
            return v.VerifierVerdict.accept_unconditionally()

        async def _single(*a, **k):
            called["single"] = True
            return v.VerifierVerdict.accept_unconditionally()

        async def _structured(*a, **k):
            called["structured"] = True
            return v.VerifierVerdict.accept_unconditionally()

        monkeypatch.setattr(v, "verify_proposal_ensemble", _ens)
        monkeypatch.setattr(v, "verify_proposal", _single)
        monkeypatch.setattr(v, "verify_proposal_structured", _structured)
        monkeypatch.setattr(v, "_ensemble_enabled", lambda: False)
        monkeypatch.setattr(v, "_structured_verify_enabled", lambda: False)
        await v.verify_final("b", "p", object(), None, force_ensemble=False)
        assert called["single"] is True
        assert called["ensemble"] is False and called["structured"] is False


def test_a_recorded_zero_confidence_is_not_read_as_full_confidence():
    from types import SimpleNamespace

    from maverick.swarm import verifier_confidence

    assert verifier_confidence(SimpleNamespace(last_verifier_confidence=0.0)) == 0.0
    assert verifier_confidence(SimpleNamespace()) == 1.0
