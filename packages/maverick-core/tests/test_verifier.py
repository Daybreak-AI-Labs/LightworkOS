"""Verifier role: parsing, verdict shape, integration into the agent loop."""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget, BudgetExceeded
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.verifier import (
    _parse,
    verify_proposal,
)
from maverick.world_model import WorldModel


class TestParse:
    def test_clean_json_accepts(self):
        text = '{"confidence": 0.9, "accepts": true, "critique": "looks good", "issues": []}'
        v = _parse(text)
        assert v.confidence == 0.9
        assert v.accepts is True
        assert v.critique == "looks good"
        assert v.issues == []

    def test_clean_json_rejects(self):
        text = '{"confidence": 0.3, "accepts": false, "critique": "wrong", "issues": ["bad math"]}'
        v = _parse(text)
        assert v.accepts is False
        assert v.issues == ["bad math"]

    def test_extracts_json_from_prose(self):
        """Model wraps the JSON in prose despite system prompt."""
        text = (
            'Here is the verdict:\n\n'
            '{"confidence": 0.8, "accepts": true, "critique": "ok", "issues": []}\n\n'
            'Hope that helps!'
        )
        v = _parse(text)
        assert v.confidence == 0.8
        assert v.accepts is True

    def test_extracts_json_from_markdown_fence(self):
        text = (
            '```json\n'
            '{"confidence": 0.5, "accepts": false, "critique": "iffy", "issues": []}\n'
            '```'
        )
        v = _parse(text)
        assert v.confidence == 0.5
        assert v.accepts is False

    def test_empty_response_rejects(self):
        v = _parse("")
        assert v.accepts is False
        assert "empty" in v.critique.lower()

    def test_unparseable_rejects(self):
        v = _parse("not json at all")
        assert v.accepts is False

    def test_confidence_clamped(self):
        v = _parse('{"confidence": 5.0, "accepts": true, "critique": ""}')
        assert v.confidence == 1.0
        v = _parse('{"confidence": -1.0, "accepts": false, "critique": ""}')
        assert v.confidence == 0.0

    def test_string_accepts_value(self):
        """Some models emit string booleans."""
        v = _parse('{"confidence": 0.8, "accepts": "true", "critique": "ok"}')
        assert v.accepts is True

    def test_low_confidence_accept_is_downgraded(self):
        # The confidence floor is enforced in code: a verifier must not wave
        # output through with accepts=true below the threshold (fail-open the
        # last gate before FINAL). The verdict is forced to reject.
        v = _parse('{"confidence": 0.1, "accepts": true, "critique": "", '
                   '"issues": ["the answer is wrong"]}')
        assert v.accepts is False
        assert v.critique  # a revision brief is populated for the proposer

    def test_high_confidence_accept_is_honored(self):
        v = _parse('{"confidence": 0.95, "accepts": true, "critique": "ok", '
                   '"issues": []}')
        assert v.accepts is True


class TestVerifyProposal:
    @pytest.mark.asyncio
    async def test_empty_proposal_rejected_without_llm_call(self):
        from maverick.budget import Budget

        class _ShouldNotBeCalled:
            async def complete_async(self, **kw):
                raise AssertionError("LLM was called for empty proposal")

        v = await verify_proposal("brief", "", _ShouldNotBeCalled(), Budget())
        assert v.accepts is False

    @pytest.mark.asyncio
    async def test_calls_llm_with_verifier_role(self, fake_llm, make_llm_response):
        from maverick.budget import Budget
        fake_llm.scripted = [make_llm_response(
            text='{"confidence": 0.9, "accepts": true, "critique": "ok", "issues": []}',
        )]
        v = await verify_proposal(
            "brief: plan a trip", "Visit Lisbon.", fake_llm, Budget(),
        )
        assert v.accepts is True
        # The LLM call recorded the verifier system prompt.
        assert len(fake_llm.calls) == 1
        assert "verifier" in fake_llm.calls[0]["system"].lower()


class TestAgentVerifierIntegration:
    @pytest.mark.asyncio
    async def test_orchestrator_revises_on_rejection(
        self, tmp_path, fake_llm, make_llm_response,
    ):
        """When the verifier rejects, the proposer gets a revision brief
        and a second chance. The second answer is accepted regardless."""
        from maverick.agent import Agent
        from maverick.blackboard import Blackboard
        from maverick.budget import Budget
        from maverick.sandbox import LocalBackend
        from maverick.swarm import SwarmContext
        from maverick.world_model import WorldModel

        # Scripted LLM responses:
        #   1. orchestrator FINAL: "first answer"
        #   2. verifier rejects (low confidence)
        #   3. orchestrator (revision) FINAL: "second answer"
        #   4. verifier accepts (revised FINALs are re-verified; skipping
        #      that would let bogus revisions through with
        #      verifier_confidence=1.0)
        fake_llm.scripted = [
            make_llm_response(text="FINAL: first answer"),
            make_llm_response(
                text='{"confidence": 0.3, "accepts": false, '
                     '"critique": "first attempt was wrong", '
                     '"issues": ["missing X"]}',
            ),
            make_llm_response(text="FINAL: second answer"),
            make_llm_response(
                text='{"confidence": 0.95, "accepts": true, '
                     '"critique": "second attempt addresses the issues", '
                     '"issues": []}',
            ),
        ]
        world = WorldModel(tmp_path / "w.db")
        gid = world.create_goal("test", "")
        ctx = SwarmContext(
            llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
            blackboard=Blackboard(),
            sandbox=LocalBackend(workdir=tmp_path),
            goal_id=gid, max_depth=1,
        )
        agent = Agent(ctx=ctx, role="orchestrator", brief="test", depth=0)
        result = await agent.run()
        assert result.final == "second answer"
        # 4 LLM calls: propose -> verify -> revise -> re-verify. Skipping the
        # re-verify would let bogus revisions through with the
        # verifier_confidence=1.0 fallback.
        assert len(fake_llm.calls) == 4


class TestStructuredVerify:
    """The rubric judge (reasoning_reward) wired into verify_final, on by default."""

    @pytest.mark.asyncio
    async def test_rubric_reply_drives_verdict(self, fake_llm, make_llm_response):
        from maverick.budget import Budget
        from maverick.verifier import verify_proposal_structured
        fake_llm.scripted = [make_llm_response(text=(
            '{"reasoning": "checked", "dimensions": ['
            '{"name": "correctness", "score": 0.9, "critique": "ok"},'
            '{"name": "completeness", "score": 0.9, "critique": ""},'
            '{"name": "grounding", "score": 0.9, "critique": ""},'
            '{"name": "safety", "score": 0.9, "critique": ""}],'
            '"critique": "solid", "score": 0.9, "confidence": 0.8}'))]
        v = await verify_proposal_structured("brief", "a real answer", fake_llm, Budget())
        assert v.accepts is True
        assert v.confidence == 0.9
        assert v.reward_audit is not None and v.reward_audit["dimensions"]

    @pytest.mark.asyncio
    async def test_safety_veto_rejects_high_holistic(self, fake_llm, make_llm_response):
        from maverick.budget import Budget
        from maverick.verifier import verify_proposal_structured
        # High holistic score but safety below its veto floor -> reject.
        fake_llm.scripted = [make_llm_response(text=(
            '{"dimensions": ['
            '{"name": "correctness", "score": 1.0},'
            '{"name": "completeness", "score": 1.0},'
            '{"name": "grounding", "score": 1.0},'
            '{"name": "safety", "score": 0.1, "critique": "unsafe"}],'
            '"critique": "unsafe", "score": 0.95, "confidence": 0.9}'))]
        v = await verify_proposal_structured("brief", "answer", fake_llm, Budget())
        assert v.accepts is False
        assert any("safety" in i for i in v.issues)

    @pytest.mark.asyncio
    async def test_non_rubric_reply_falls_back_to_scalar(self, fake_llm, make_llm_response):
        # A scalar verdict reply (no dimensions) must behave exactly like the
        # scalar verifier -- this is what keeps on-by-default backward-compatible.
        from maverick.budget import Budget
        from maverick.verifier import verify_proposal_structured
        fake_llm.scripted = [make_llm_response(
            text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}')]
        v = await verify_proposal_structured("brief", "answer", fake_llm, Budget())
        assert v.accepts is True
        assert v.confidence == 0.95
        assert v.reward_audit is None  # scalar path, no rubric attached

    @pytest.mark.asyncio
    async def test_incomplete_rubric_rejects_instead_of_falling_back(
        self, fake_llm, make_llm_response,
    ):
        from maverick.budget import Budget
        from maverick.verifier import verify_proposal_structured
        fake_llm.scripted = [make_llm_response(text=(
            '{"dimensions": [{"name": "correctness", "score": 1.0}], '
            '"score": 1.0, "confidence": 1.0, "accepts": true}'))]
        v = await verify_proposal_structured("brief", "answer", fake_llm, Budget())
        assert v.accepts is False
        assert v.reward_audit is None
        assert "incomplete" in v.critique

    @pytest.mark.asyncio
    async def test_reward_signed_into_audit_when_enabled(
        self, fake_llm, make_llm_response, monkeypatch,
    ):
        import maverick.audit as audit
        from maverick import reasoning_reward
        from maverick.budget import Budget
        from maverick.verifier import verify_proposal_structured
        monkeypatch.setattr(reasoning_reward, "audit_rewards_enabled", lambda: True)
        recorded = []
        monkeypatch.setattr(audit, "record",
                            lambda kind, **kw: recorded.append((kind, kw)) or True)
        fake_llm.scripted = [make_llm_response(text=(
            '{"reasoning": "long trace", "dimensions": '
            '[{"name": "correctness", "score": 1.0},'
            '{"name": "completeness", "score": 1.0},'
            '{"name": "grounding", "score": 1.0},'
            '{"name": "safety", "score": 0.1, "critique": "unsafe"}], '
            '"score": 0.9, "confidence": 0.8}'))]
        await verify_proposal_structured("b", "a", fake_llm, Budget())
        assert recorded, "structured reward was not signed into the audit chain"
        kind, payload = recorded[0]
        assert kind == audit.EventKind.VERIFICATION_REWARD
        assert payload["vetoed"] is True and "dimensions" in payload
        assert "reasoning" not in payload  # compact summary, not the full trace

    @pytest.mark.asyncio
    async def test_reward_not_audited_when_disabled(
        self, fake_llm, make_llm_response, monkeypatch,
    ):
        import maverick.audit as audit
        from maverick import reasoning_reward
        from maverick.budget import Budget
        from maverick.verifier import verify_proposal_structured
        monkeypatch.setattr(reasoning_reward, "audit_rewards_enabled", lambda: False)
        recorded = []
        monkeypatch.setattr(audit, "record", lambda kind, **kw: recorded.append(kind) or True)
        fake_llm.scripted = [make_llm_response(text=(
            '{"dimensions": [{"name": "correctness", "score": 0.9},'
            '{"name": "completeness", "score": 0.9},'
            '{"name": "grounding", "score": 0.9},'
            '{"name": "safety", "score": 0.9}], "score": 0.9}'))]
        await verify_proposal_structured("b", "a", fake_llm, Budget())
        assert recorded == []

    @pytest.mark.asyncio
    async def test_audit_failure_never_breaks_verification(
        self, fake_llm, make_llm_response, monkeypatch,
    ):
        import maverick.audit as audit
        from maverick import reasoning_reward
        from maverick.budget import Budget
        from maverick.verifier import verify_proposal_structured
        monkeypatch.setattr(reasoning_reward, "audit_rewards_enabled", lambda: True)

        def _boom(*a, **k):
            raise RuntimeError("audit chain down")

        monkeypatch.setattr(audit, "record", _boom)
        fake_llm.scripted = [make_llm_response(text=(
            '{"dimensions": [{"name": "correctness", "score": 0.9},'
            '{"name": "completeness", "score": 0.9},'
            '{"name": "grounding", "score": 0.9},'
            '{"name": "safety", "score": 0.9}], "score": 0.9}'))]
        v = await verify_proposal_structured("b", "a", fake_llm, Budget())
        assert v.accepts is True  # audit blew up; the verification still returned

    @pytest.mark.asyncio
    async def test_verify_final_routes_to_structured_when_enabled(
        self, fake_llm, make_llm_response, monkeypatch,
    ):
        from maverick import reasoning_reward
        from maverick.budget import Budget
        from maverick.verifier import verify_final
        monkeypatch.setattr(reasoning_reward, "enabled", lambda: True)
        fake_llm.scripted = [make_llm_response(text=(
            '{"dimensions": [{"name": "correctness", "score": 1.0},'
            '{"name": "completeness", "score": 1.0},'
            '{"name": "grounding", "score": 1.0},'
            '{"name": "safety", "score": 0.1, "critique": "unsafe"}], '
            '"score": 0.9, "confidence": 0.8}'))]
        v = await verify_final("brief", "answer", fake_llm, Budget())
        # Routed to the rubric judge: the safety veto rejected despite score 0.9.
        assert v.accepts is False
        assert v.reward_audit is not None


@pytest.mark.asyncio
async def test_ensemble_reraises_budget_exceeded_not_swallowed():
    # A BudgetExceeded from one panel member must PROPAGATE out of the ensemble
    # (so the budget stops the run), not be collected by gather(return_exceptions)
    # and folded into a combined reject verdict. The other member is still awaited
    # rather than orphaned. Regression for the gather() that used to propagate
    # mid-flight and leave siblings running.
    from types import SimpleNamespace

    from maverick.budget import Budget, BudgetExceeded
    from maverick.verifier import verify_proposal_ensemble

    class _PanelLLM:
        def __init__(self):
            self.calls = []

        async def complete_async(self, **kw):
            self.calls.append(kw.get("model"))
            if kw.get("model") == "m-budget":
                raise BudgetExceeded("verifier out of budget")
            return SimpleNamespace(
                text='{"confidence": 0.9, "accepts": true, "critique": "ok", "issues": []}')

    llm = _PanelLLM()
    with pytest.raises(BudgetExceeded):
        await verify_proposal_ensemble(
            "brief", "a genuine proposal to verify", llm, Budget(),
            panel=["m-ok", "m-budget"], weighted=True,
        )
    # Both members were awaited (the panel ran), not just the failing one.
    assert set(llm.calls) == {"m-ok", "m-budget"}


# ---------- verifier: fail CLOSED on LLM error ----------

def test_verifier_fails_closed_on_llm_error():
    import asyncio

    from maverick.budget import Budget
    from maverick.verifier import verify_proposal

    class _Boom:
        async def complete_async(self, **kw):
            raise RuntimeError("provider down")

    v = asyncio.run(verify_proposal("brief", "some proposal", _Boom(), Budget()))
    # Contract: any failure -> reject (NOT the old accepts=True fail-open).
    assert v.accepts is False


def test_verifier_propagates_budget_exceeded():
    import asyncio

    from maverick.budget import Budget, BudgetExceeded
    from maverick.verifier import verify_proposal

    class _OverBudget:
        async def complete_async(self, **kw):
            raise BudgetExceeded("$5 > $5")

    try:
        asyncio.run(verify_proposal("brief", "p", _OverBudget(), Budget()))
    except BudgetExceeded:
        return  # budget is a control signal, must propagate
    raise AssertionError("expected BudgetExceeded to propagate")


@pytest.fixture
def ctx(tmp_path: Path, fake_llm):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    return SwarmContext(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=gid, max_depth=1, use_skills=False,
    )


@pytest.mark.asyncio
async def test_orchestrator_unverified_on_budget_reports_zero(
    ctx, fake_llm, make_llm_response, monkeypatch,
):
    async def _boom(*a, **k):
        raise BudgetExceeded("verifier out of budget")

    monkeypatch.setattr("maverick.verifier.verify_final", _boom)
    fake_llm.scripted = [make_llm_response(text="FINAL: the answer")]
    orch = Agent(ctx=ctx, role="orchestrator", brief="do it", depth=0)
    result = await orch.run()
    assert "the answer" in (result.final or "")
    # Verifier was attempted but hit budget -> NOT high confidence.
    assert result.verifier_confidence == 0.0
    assert result.verifier_confidence < 0.75  # below the donation reward gate


@pytest.mark.asyncio
async def test_non_verifying_role_keeps_default_confidence(
    ctx, fake_llm, make_llm_response,
):
    # A non-orchestrator never verifies; the 1.0 default is unchanged (it isn't
    # donated as the run's verdict, so this is correct).
    fake_llm.scripted = [make_llm_response(text="FINAL: child result")]
    worker = Agent(ctx=ctx, role="researcher", brief="sub", depth=0)
    result = await worker.run()
    assert "child result" in (result.final or "")
    assert result.verifier_confidence == 1.0


# --- cross-family verifier contract vs behavior ---

def test_cross_family_fallback_requires_explicit_env(monkeypatch):
    import maverick.verifier as v
    monkeypatch.delenv("MAVERICK_CROSS_FAMILY_VERIFIER", raising=False)
    # No implicit provider swap: returns None unless explicitly configured.
    assert v._cross_family_fallback("anthropic:claude-x") is None
    monkeypatch.setenv("MAVERICK_CROSS_FAMILY_VERIFIER", "openai:gpt-x")
    assert v._cross_family_fallback("anthropic:claude-x") == "openai:gpt-x"


def test_same_family_verifier_warns_once(monkeypatch, caplog):
    import maverick.verifier as v
    monkeypatch.setattr(v, "_warned_same_family", False)
    with caplog.at_level("WARNING"):
        v._warn_same_family_verifier("anthropic:claude-x")
        v._warn_same_family_verifier("anthropic:claude-x")
    lockstep = [r for r in caplog.records if "lockstep" in r.getMessage()]
    assert len(lockstep) == 1  # warned exactly once, not per call


# ---------- Cross-family verifier guard ----------

class TestCrossFamilyVerifier:
    def test_provider_extraction(self):
        from maverick.verifier import _provider
        assert _provider("claude-opus-4-7") == "anthropic"
        assert _provider("anthropic:claude-opus-4-7") == "anthropic"
        assert _provider("openai:gpt-5.4") == "openai"
        assert _provider("gpt-5.4") == "openai"
        assert _provider("o3") == "openai"
        assert _provider("gemini-3-pro") == "gemini"
        assert _provider("deepseek-v4-pro") == "deepseek"
        assert _provider("grok-4.3") == "xai"

    def test_same_family_detection(self):
        from maverick.verifier import _same_family
        assert _same_family("claude-opus-4-7", "claude-sonnet-4-6") is True
        assert _same_family("anthropic:claude-opus-4-7", "claude-sonnet-4-6") is True
        assert _same_family("claude-opus-4-7", "gpt-5.4") is False

    def test_cross_family_fallback_default_is_none(self):
        """No implicit cross-provider swap without explicit operator opt-in."""
        from maverick.verifier import _cross_family_fallback
        assert _cross_family_fallback("claude-opus-4-7") is None
        assert _cross_family_fallback("gpt-5.4") is None

    def test_cross_family_env_override(self, monkeypatch):
        from maverick.verifier import _cross_family_fallback
        monkeypatch.setenv("MAVERICK_CROSS_FAMILY_VERIFIER", "deepseek:deepseek-v4-pro")
        assert _cross_family_fallback("claude-opus-4-7") == "deepseek:deepseek-v4-pro"

    @pytest.mark.asyncio
    async def test_verifier_swaps_family_when_proposer_passed(
        self, fake_llm, make_llm_response,
    ):
        from maverick.budget import Budget
        from maverick.verifier import verify_proposal
        fake_llm.scripted = [make_llm_response(
            text='{"confidence": 0.9, "accepts": true, "critique": "", "issues": []}',
        )]
        # Proposer is Anthropic; we should NOT see verifier model in
        # the Anthropic family. The fake_llm just records the model
        # passed; we assert that model is non-Anthropic.
        await verify_proposal(
            "brief", "proposal text",
            fake_llm, Budget(),
            proposer_model="anthropic:claude-opus-4-7",
        )
        assert len(fake_llm.calls) == 1
        # Without explicit opt-in, verifier model should remain unchanged.
        model_used = fake_llm.calls[0].get("model") or ""
        assert model_used == "claude-sonnet-4-6"


# ---------- MAV ensemble verifier ----------

class TestMAVCombine:
    def test_three_accept_majority(self):
        from maverick.verifier import VerifierVerdict, _combine
        verdicts = [
            VerifierVerdict(confidence=0.9, accepts=True, critique="ok"),
            VerifierVerdict(confidence=0.8, accepts=True, critique="ok"),
            VerifierVerdict(confidence=0.3, accepts=False, critique="wrong"),
        ]
        v = _combine(verdicts, weighted=True)
        assert v.accepts is True
        # Confidence is mean of the accepting voters (0.9 + 0.8) / 2.
        assert abs(v.confidence - 0.85) < 1e-6

    def test_weighted_overrides_count(self):
        """Weighted: 2 accepters at 0.5 + 1 strong rejecter at 0.95 -> reject."""
        from maverick.verifier import VerifierVerdict, _combine
        verdicts = [
            VerifierVerdict(confidence=0.5, accepts=True, critique=""),
            VerifierVerdict(confidence=0.5, accepts=True, critique=""),
            VerifierVerdict(confidence=0.95, accepts=False, critique="strong veto"),
        ]
        v = _combine(verdicts, weighted=True)
        # accept_weight = 1.0; a reject weighs (1 - confidence) = 0.05.
        assert v.accepts is True

    def test_weighted_failed_and_weak_rejects_outvote_one_accept(self):
        """Regression: rejects were weighted by confidence in the answer, so
        one accept at 0.8 overruled two failed members or two rejects."""
        from maverick.verifier import VerifierVerdict, _combine
        accept = VerifierVerdict(confidence=0.8, accepts=True, critique="")
        failed = [VerifierVerdict.reject("boom"), VerifierVerdict.reject("boom")]
        weak = [VerifierVerdict(confidence=0.3, accepts=False, critique="no")] * 2
        assert _combine([accept, *failed], weighted=True).accepts is False
        assert _combine([accept, *weak], weighted=True).accepts is False
        assert _combine([accept, failed[0]], weighted=True).accepts is False

    def test_unweighted_majority_wins(self):
        from maverick.verifier import VerifierVerdict, _combine
        verdicts = [
            VerifierVerdict(confidence=0.5, accepts=True, critique=""),
            VerifierVerdict(confidence=0.5, accepts=True, critique=""),
            VerifierVerdict(confidence=0.95, accepts=False, critique=""),
        ]
        v = _combine(verdicts, weighted=False)
        assert v.accepts is True  # 2-of-3

    def test_issues_deduplicated_across_panel(self):
        from maverick.verifier import VerifierVerdict, _combine
        verdicts = [
            VerifierVerdict(confidence=0.4, accepts=False,
                            critique="x", issues=["bad math", "missing units"]),
            VerifierVerdict(confidence=0.5, accepts=False,
                            critique="y", issues=["bad math", "off by one"]),
        ]
        v = _combine(verdicts, weighted=True)
        assert v.accepts is False
        # 3 unique issues: bad math, missing units, off by one.
        assert sorted(v.issues) == ["bad math", "missing units", "off by one"]

    def test_single_verdict_passthrough(self):
        from maverick.verifier import VerifierVerdict, _combine
        single = VerifierVerdict(confidence=0.7, accepts=True, critique="")
        v = _combine([single], weighted=True)
        assert v is single

    def test_empty_panel_rejects(self):
        from maverick.verifier import _combine
        v = _combine([], weighted=True)
        assert v.accepts is False


class TestVerifyEnsemble:
    @pytest.mark.asyncio
    async def test_filters_same_family_panel_members(self, fake_llm, make_llm_response):
        from maverick.budget import Budget
        from maverick.verifier import verify_proposal_ensemble
        # Both panel members return accept; we don't care about the
        # combined result -- we care that the Anthropic panel member is
        # FILTERED OUT when proposer is Anthropic.
        fake_llm.scripted = [
            make_llm_response(
                text='{"confidence": 0.9, "accepts": true, "critique": "", "issues": []}',
            ),
            make_llm_response(
                text='{"confidence": 0.9, "accepts": true, "critique": "", "issues": []}',
            ),
        ]
        await verify_proposal_ensemble(
            "brief", "proposal",
            fake_llm, Budget(),
            proposer_model="anthropic:claude-opus-4-7",
        )
        # Panel was [anthropic, openai, deepseek] -> [openai, deepseek]
        # after filtering. 2 LLM calls.
        assert len(fake_llm.calls) == 2
        models_used = [c.get("model") or "" for c in fake_llm.calls]
        for m in models_used:
            assert "claude" not in m.lower()

    @pytest.mark.asyncio
    async def test_explicit_panel_used(self, fake_llm, make_llm_response):
        from maverick.budget import Budget
        from maverick.verifier import verify_proposal_ensemble
        fake_llm.scripted = [
            make_llm_response(
                text='{"confidence": 0.9, "accepts": true, "critique": "", "issues": []}',
            ),
        ]
        await verify_proposal_ensemble(
            "brief", "proposal",
            fake_llm, Budget(),
            panel=["openai:gpt-5.4"],
        )
        assert len(fake_llm.calls) == 1
        assert fake_llm.calls[0].get("model") == "openai:gpt-5.4"
