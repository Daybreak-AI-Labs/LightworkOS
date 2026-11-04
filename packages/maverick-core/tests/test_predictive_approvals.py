"""Predictive approvals: suggestion logic, confidence, safety guards, grouping."""
from __future__ import annotations

from maverick.predictive_approvals import (
    SUGGEST_APPROVE,
    SUGGEST_ASK,
    SUGGEST_DENY,
    render,
    suggest,
    suggest_all,
)


def _recs(n, decision):
    return [{"decision": decision} for _ in range(n)]


def test_small_sample_always_ask():
    s = suggest("git-push", "low", _recs(4, "approve"))
    assert s.suggestion == SUGGEST_ASK
    assert "need 5" in s.reason


def test_dominant_approve_is_candidate():
    s = suggest("git-push", "low", _recs(10, "approve"))
    assert s.suggestion == SUGGEST_APPROVE
    assert s.approve_rate == 1.0 and s.sample == 10
    assert s.confidence > 0.6


def test_dominant_deny_is_candidate():
    s = suggest("rm-rf-root", "medium", _recs(10, "deny"))
    assert s.suggestion == SUGGEST_DENY
    assert s.approve_rate == 0.0


def test_mixed_record_always_ask():
    recs = _recs(6, "approve") + _recs(6, "deny")
    s = suggest("ambiguous", "low", recs)
    assert s.suggestion == SUGGEST_ASK
    assert "mixed" in s.reason


def test_high_risk_never_auto_approve_even_if_unanimous():
    s = suggest("force-push-main", "high", _recs(50, "approve"))
    assert s.suggestion == SUGGEST_ASK
    assert "human-gated" in s.reason


def test_critical_risk_never_auto_approve():
    s = suggest("wipe-prod", "critical", _recs(50, "approve"))
    assert s.suggestion == SUGGEST_ASK


def test_high_risk_can_still_suggest_auto_deny():
    # erring toward blocking is the safe direction, so auto-deny is allowed
    s = suggest("sketchy", "high", _recs(20, "deny"))
    assert s.suggestion == SUGGEST_DENY


def test_confidence_grows_with_sample():
    small = suggest("a", "low", _recs(5, "approve")).confidence
    big = suggest("a", "low", _recs(50, "approve")).confidence
    assert big > small


def test_record_shapes_status_and_boolean():
    by_status = suggest("a", "low", [{"status": "approved"}] * 10)
    by_bool = suggest("a", "low", [{"granted": True}] * 10)
    assert by_status.suggestion == SUGGEST_APPROVE
    assert by_bool.suggestion == SUGGEST_APPROVE


def test_pending_records_excluded_from_sample():
    recs = _recs(5, "approve") + [{"status": "pending"}, {"decision": "weird"}]
    s = suggest("a", "low", recs)
    assert s.sample == 5  # only decided records counted


def test_unknown_risk_normalised_to_medium():
    s = suggest("a", "banana", _recs(10, "approve"))
    assert s.risk == "medium"


def test_suggest_all_groups_and_sorts_by_confidence():
    history = (
        [{"action": "push", "risk": "low", "decision": "approve"}] * 20
        + [{"action": "rm", "risk": "medium", "decision": "approve"}] * 6
        + [{"action": "noop"}]  # no action -> skipped
    )
    out = suggest_all(history)
    actions = [s.action for s in out]
    assert "push" in actions and "rm" in actions
    # higher-confidence (larger, more lopsided) push sorts before rm
    assert actions.index("push") < actions.index("rm")


def test_suggest_all_accepts_object_with_records():
    class _Hist:
        def records(self):
            return [{"action": "a", "risk": "low", "decision": "approve"}] * 10

    out = suggest_all(_Hist())
    assert out and out[0].action == "a" and out[0].suggestion == SUGGEST_APPROVE


def test_never_emits_a_binding_decision():
    # The whole surface returns suggestions; the constants are advisory labels,
    # not grant/deny verbs the consent layer would act on directly.
    s = suggest("x", "low", _recs(10, "approve"))
    assert s.suggestion in (SUGGEST_APPROVE, SUGGEST_DENY, SUGGEST_ASK)
    assert "candidate" in s.suggestion or s.suggestion == SUGGEST_ASK


def test_render_is_advisory():
    out = render(suggest_all([{"action": "a", "risk": "low", "decision": "approve"}] * 10))
    assert "suggestions only" in out and "never auto-applied" in out


def test_render_empty():
    assert "no history" in render([])
