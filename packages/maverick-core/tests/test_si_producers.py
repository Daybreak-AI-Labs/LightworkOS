"""Tests for the per-rung self-improvement producers (Phases 1-6 -> one gate)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from maverick.self_improvement import PromotionLedger, SelfImprovementController
from maverick.si_producers import (
    ToolOutcomeTracker,
    propose_code,
    propose_policy,
    propose_tool,
    propose_verifier,
    propose_weights,
)


def _ctrl(tmp_path, *, max_auto_rung="policy"):
    return SelfImprovementController(
        frozen_fn=lambda: False, audit_fn=lambda **k: None,
        ledger=PromotionLedger(path=tmp_path / "led.json"),
        max_auto_rung=max_auto_rung,
    )


# -- Tool outcome tracker + promotion --------------------------------------

def test_tool_tracker_counts_and_rate(tmp_path):
    t = ToolOutcomeTracker(path=tmp_path / "to.json")
    for _ in range(4):
        t.record("mk_tool", True)
    t.record("mk_tool", False)
    assert t.samples("mk_tool") == 5
    assert abs(t.success_rate("mk_tool") - 0.8) < 1e-9


def test_tool_tracker_persists(tmp_path):
    p = tmp_path / "to.json"
    ToolOutcomeTracker(path=p).record("x", True)
    assert ToolOutcomeTracker(path=p).samples("x") == 1
    from maverick.file_lock import private_path_is_restricted
    assert private_path_is_restricted(p)


def test_tool_tracker_serializes_independent_writers(tmp_path):
    path = tmp_path / "to.json"
    trackers = [ToolOutcomeTracker(path=path) for _ in range(12)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda tracker: tracker.record("shared", True), trackers))
    reloaded = ToolOutcomeTracker(path=path)
    assert reloaded.samples("shared") == len(trackers)
    assert reloaded.success_rate("shared") == 1.0


def test_propose_tool_promotes_when_it_beats_baseline(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    t = ToolOutcomeTracker(path=tmp_path / "to.json")
    for _ in range(6):
        t.record("good_tool", True)
    v = propose_tool("good_tool", t, baseline_success=0.3, rollback="snap",
                     capability_widens=False, controller=_ctrl(tmp_path))
    assert v.ok


def test_propose_tool_rejected_when_it_widens_capability(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    t = ToolOutcomeTracker(path=tmp_path / "to.json")
    for _ in range(6):
        t.record("greedy_tool", True)
    v = propose_tool("greedy_tool", t, baseline_success=0.3, rollback="snap",
                     capability_widens=True, controller=_ctrl(tmp_path))
    assert not v.ok


def test_propose_tool_rejected_without_capability_proof(tmp_path, monkeypatch):
    # Regression: with no explicit non-escalation proof, capability_widens is
    # UNPROVEN (None), not an asserted False, so the tool rung fails closed --
    # a synthesized tool can't sail through the capability gate by default.
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    t = ToolOutcomeTracker(path=tmp_path / "to.json")
    for _ in range(6):
        t.record("unproven_tool", True)
    v = propose_tool("unproven_tool", t, baseline_success=0.3, rollback="snap",
                     controller=_ctrl(tmp_path))          # no capability_widens
    assert not v.ok
    assert any(g.gate == "capability" and not g.ok for g in v.gates)


# -- Verifier / policy / prompt producers ----------------------------------

def test_propose_verifier_adopts_better_discriminator(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    common = dict(
        baseline_discrimination=0.15,
        candidate_discrimination=0.31,
        samples=12,
        rollback="head-v1",
    )
    blocked = propose_verifier(
        "retrained head", controller=_ctrl(tmp_path), **common)
    assert blocked.rung == "evaluator" and not blocked.ok
    assert any(gate.gate == "human_approval" and not gate.ok
               for gate in blocked.gates)

    allowed = propose_verifier(
        "retrained head",
        controller=_ctrl(tmp_path, max_auto_rung="evaluator"),
        **common,
    )
    assert allowed.rung == "evaluator" and allowed.ok


def test_propose_verifier_accepts_external_signed_approval(tmp_path, monkeypatch):
    from maverick import approval_signing

    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    monkeypatch.setattr(approval_signing, "signing_enforced", lambda: True)
    monkeypatch.setattr(
        approval_signing, "verify_candidate",
        lambda candidate: "approver-key" if candidate.approval_signature == "signed" else None,
    )
    requests = []

    def approve(request):
        requests.append(request)
        return "signed"

    verdict = propose_verifier(
        "retrained head", baseline_discrimination=0.15,
        candidate_discrimination=0.31, samples=12, rollback="head-v1",
        approve=approve, controller=_ctrl(tmp_path),
        artifact_sha256="a" * 64,
    )

    assert verdict.ok and verdict.rung == "evaluator"
    assert verdict.approver_id == "approver-key"
    assert len(requests) == 1 and requests[0].rung == "evaluator"


def test_propose_policy_requires_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    v = propose_policy("rl adapter", baseline=0.5, candidate=0.51, samples=2,
                       rollback="adapter-v0", controller=_ctrl(tmp_path))
    assert not v.ok  # too few samples for the policy rung


# -- Code self-modification through the validate seam ----------------------

def test_propose_code_blocked_by_failing_validate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    v = propose_code("rewrite tool", validate=lambda: (False, "import failed in sandbox"),
                     eval_before=0.5, eval_after=0.9, samples=10, rollback="commit-abc",
                     approved=True, capability_widens=False, controller=_ctrl(tmp_path))
    assert not v.ok
    assert any(g.gate == "validate" for g in v.gates)


def test_propose_code_requires_human_even_when_valid(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    common = dict(validate=lambda: (True, ""), eval_before=0.5, eval_after=0.9,
                  samples=10, rollback="commit-abc", capability_widens=False)
    assert not propose_code("rewrite", approved=False, controller=_ctrl(tmp_path), **common).ok
    verdict = propose_code("rewrite", approved=True, controller=_ctrl(tmp_path), **common)
    assert not verdict.ok and "signature" in verdict.blocking_reason.lower()


# -- Weights ---------------------------------------------------------------

def test_propose_weights_is_human_gated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    common = dict(eval_before=0.6, eval_after=0.75, samples=20, rollback="ckpt-1")
    assert not propose_weights("finetune", approved=False, controller=_ctrl(tmp_path), **common).ok
    verdict = propose_weights("finetune", approved=True, controller=_ctrl(tmp_path), **common)
    assert not verdict.ok and "signature" in verdict.blocking_reason.lower()


def test_disabled_engine_blocks_all_producers(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "0")
    from maverick.self_improvement import reset_shared
    reset_shared()
    v = propose_policy("x", baseline=0.1, candidate=0.9, samples=20, rollback="r")
    assert not v.ok
