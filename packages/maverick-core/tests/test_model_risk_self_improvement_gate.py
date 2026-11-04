"""Exact-payload Model Risk authority in the DGM promotion pipeline."""

from __future__ import annotations

from typing import Any

import pytest
from maverick.approval_signing import payload_digest
from maverick.self_improvement import (
    ArtifactRevision,
    Candidate,
    PromotionLedger,
    SelfImprovementController,
)


def _candidate(*, payload: Any = "candidate-v1", **overrides: Any) -> Candidate:
    values: dict[str, Any] = {
        "rung": "config",
        "summary": "bounded configuration candidate",
        "baseline_score": 0.5,
        "candidate_score": 0.7,
        "samples": 5,
        "payload": payload,
        "rollback": "snapshot-1",
    }
    values.update(overrides)
    return Candidate(**values)


def _controller(verifier: Any) -> SelfImprovementController:
    return SelfImprovementController(
        frozen_fn=lambda: False,
        audit_fn=lambda **_payload: None,
        model_risk_verifier=verifier,
        now=lambda: 1_726_000_000.0,
    )


def _artifact(label: str) -> ArtifactRevision:
    return ArtifactRevision(
        identity="model-risk-test:artifact",
        sha256=payload_digest(label),
        version=label,
    )


def test_model_risk_gate_receives_exact_candidate_authority_tuple() -> None:
    received: dict[str, Any] = {}

    def verify(**request: Any) -> tuple[bool, str]:
        received.update(request)
        return True, "current governed authorization"

    candidate = _candidate(payload={"temperature": 0.2}, id="candidate-42")
    verdict = _controller(verify).evaluate(candidate)

    assert verdict.ok
    assert received == {
        "candidate_id": "candidate-42",
        "rung": "config",
        "payload_sha256": payload_digest({"temperature": 0.2}),
        "now": 1_726_000_000.0,
    }
    assert any(gate.gate == "model_risk_assurance" and gate.ok for gate in verdict.gates)


def test_model_risk_gate_ignores_stale_self_reported_payload_digest() -> None:
    approved_digest = payload_digest("benign-candidate")
    received: dict[str, Any] = {}

    def verify(**request: Any) -> tuple[bool, str]:
        received.update(request)
        if request["payload_sha256"] == approved_digest:
            return True, ""
        return False, "exact payload is not authorized"

    candidate = _candidate(
        payload="swapped-candidate",
        payload_sha256=approved_digest,
        id="candidate-swapped",
    )
    verdict = _controller(verify).evaluate(candidate)

    assert not verdict.ok
    assert received["payload_sha256"] == payload_digest("swapped-candidate")
    assert received["payload_sha256"] != approved_digest
    assert any(
        gate.gate == "model_risk_assurance"
        and not gate.ok
        and gate.reason == "exact payload is not authorized"
        for gate in verdict.gates
    )


def test_verifier_cannot_swap_candidate_payload_before_prepare(
    tmp_path,
    monkeypatch,
) -> None:
    from maverick import self_improvement as si

    monkeypatch.setattr(si, "enabled", lambda: True)
    candidate = _candidate(
        id="candidate-verifier-swap",
        payload={"temperature": 0.2},
    )
    approved_digest = payload_digest(candidate.payload)

    def verify(**request: Any) -> tuple[bool, str]:
        assert request["payload_sha256"] == approved_digest
        candidate.payload = {"temperature": 2.0}
        return True, "current governed authorization"

    controller = _controller(verify)
    controller.ledger = PromotionLedger(path=tmp_path / "promotions.json")
    preparation = controller.prepare_promotion(
        candidate,
        before=_artifact("before"),
        after=_artifact("after"),
    )

    assert not preparation.ok
    assert "changed during model-risk verification" in preparation.blocking_reason
    assert controller.ledger.transactions() == []


@pytest.mark.parametrize(
    "verifier",
    [
        lambda **_request: (_ for _ in ()).throw(RuntimeError("store unavailable")),
        lambda **_request: True,
        lambda **_request: (1, "not a strict boolean"),
        lambda **_request: (False, 7),
    ],
)
def test_model_risk_gate_fails_closed_on_verifier_failure(verifier: Any) -> None:
    verdict = _controller(verifier).evaluate(_candidate())

    assert not verdict.ok
    assert any(gate.gate == "model_risk_assurance" and not gate.ok for gate in verdict.gates)


def test_preapply_revalidation_aborts_when_authority_is_revoked(
    tmp_path,
    monkeypatch,
) -> None:
    from maverick import self_improvement as si

    monkeypatch.setattr(si, "enabled", lambda: True)
    state = {"allowed": True}

    def verify(**_request: Any) -> tuple[bool, str]:
        return (
            (True, "current governed authorization")
            if state["allowed"]
            else (False, "authorization revoked")
        )

    ledger_path = tmp_path / "promotions.json"
    controller = _controller(verify)
    controller.ledger = PromotionLedger(path=ledger_path)
    candidate = _candidate(id="candidate-preapply-revocation")
    before, after = _artifact("before"), _artifact("after")
    preparation = controller.prepare_promotion(
        candidate,
        before=before,
        after=after,
    )
    assert preparation.ok
    persisted = PromotionLedger(path=ledger_path).transaction(preparation.transaction_id)
    assert persisted is not None
    assert persisted.record.model_risk_payload_sha256 == payload_digest(candidate.payload)

    state["allowed"] = False
    verdict = controller.authorize_prepared(preparation, artifact=before)

    assert not verdict.ok
    assert "revoked" in verdict.blocking_reason
    transaction = controller.ledger.transaction(preparation.transaction_id)
    assert transaction is not None and transaction.state == "aborted"
    assert controller.ledger.get(candidate.id) is None


def test_commit_and_recovery_reread_current_model_risk_authority(
    tmp_path,
    monkeypatch,
) -> None:
    from maverick import self_improvement as si

    monkeypatch.setattr(si, "enabled", lambda: True)
    state = {"allowed": True}

    def verify(**_request: Any) -> tuple[bool, str]:
        return (
            (True, "current governed authorization")
            if state["allowed"]
            else (False, "authorization expired")
        )

    controller = _controller(verify)
    controller.ledger = PromotionLedger(path=tmp_path / "promotions.json")
    candidate = _candidate(id="candidate-commit-expiry")
    before, after = _artifact("before"), _artifact("after")
    preparation = controller.prepare_promotion(
        candidate,
        before=before,
        after=after,
    )
    assert preparation.ok
    assert controller.authorize_prepared(preparation, artifact=before).ok

    state["allowed"] = False
    verdict = controller.commit_prepared(preparation, artifact=after)
    assert not verdict.ok
    assert "expired" in verdict.blocking_reason
    transaction = controller.ledger.transaction(preparation.transaction_id)
    assert transaction is not None and transaction.state == "prepared"
    assert controller.ledger.get(candidate.id) is None

    recovered = controller.recover_promotions(lambda _identity: after)
    assert [transaction.state for transaction in recovered] == ["prepared"]
    assert controller.ledger.get(candidate.id) is None

    state["allowed"] = True
    recovered = controller.recover_promotions(lambda _identity: after)
    assert [transaction.state for transaction in recovered] == ["committed"]
    assert controller.ledger.get(candidate.id) is not None
