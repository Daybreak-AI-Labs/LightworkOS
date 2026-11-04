from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from maverick import self_harness as sh
from maverick import self_improvement as si
from maverick.audit.errors import AuditRefused


def _artifact(content: str) -> si.ArtifactRevision:
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return si.ArtifactRevision("prompt-addenda:test", digest, digest[:16])


def _candidate() -> si.Candidate:
    return si.Candidate(
        id="audit-outbox-candidate",
        rung="config",
        summary="durable audit outbox",
        baseline_score=0.2,
        candidate_score=0.8,
        samples=5,
        rollback="snapshot:before",
        audit_payload={"producer": "test"},
    )


def _controller(path: Path, recorder) -> si.SelfImprovementController:
    return si.SelfImprovementController(
        frozen_fn=lambda: False,
        audit_fn=recorder,
        ledger=si.PromotionLedger(path=path),
        model_risk_verifier=lambda **_kwargs: (True, ""),
    )


def _journal(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in Path(f"{path}.journal").read_text(encoding="utf-8").splitlines()
    ]


@pytest.mark.parametrize("sign", [False, True])
def test_learning_update_sink_is_append_once_across_rollover(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sign: bool,
) -> None:
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog, _prepare_private_audit_file

    audit_dir = tmp_path / ("signed-audit" if sign else "audit")
    first_path = audit_dir / "2026-07-29.ndjson"
    second_path = audit_dir / "2026-07-30.ndjson"
    _prepare_private_audit_file(first_path)
    _prepare_private_audit_file(second_path)
    payload = {
        "event_id": "learning-update-v1-stable",
        "decision": "promote",
        "candidate_id": "candidate-a",
        "phase": "apply",
    }
    first = AuditLog(audit_dir, sign=sign)
    monkeypatch.setattr(first, "_rotate_if_needed", lambda: first_path)
    assert first.record(
        AuditEvent(
            ts=1.0,
            kind=EventKind.LEARNING_UPDATE,
            payload=payload,
        )
    )

    retried = AuditLog(audit_dir, sign=sign)
    monkeypatch.setattr(retried, "_rotate_if_needed", lambda: second_path)
    assert retried.record(
        AuditEvent(
            ts=2.0,
            kind=EventKind.LEARNING_UPDATE,
            payload=payload,
        )
    )
    assert second_path.read_text(encoding="utf-8") == ""

    conflict = dict(payload, decision="rollback")
    assert not retried.record(
        AuditEvent(
            ts=3.0,
            kind=EventKind.LEARNING_UPDATE,
            payload=conflict,
        )
    )
    rows = [
        json.loads(line)
        for path in (first_path, second_path)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert sum(
        row.get("event_id") == payload["event_id"]
        and row.get("kind") == EventKind.LEARNING_UPDATE
        for row in rows
    ) == 1


def test_refused_commit_audit_is_durable_and_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(si, "enabled", lambda: True)
    path = tmp_path / "promotions.json"
    attempted: list[str] = []

    def refuse_promote(**payload):
        if payload.get("decision") == "promote":
            attempted.append(payload["event_id"])
            raise AuditRefused("signed audit chain unavailable")
        return True

    controller = _controller(path, refuse_promote)
    candidate = _candidate()
    before, after = _artifact("before"), _artifact("after")
    prepared = controller.prepare_promotion(candidate, before=before, after=after)

    assert prepared.ok and prepared.needs_apply
    assert controller.commit_prepared(prepared, artifact=after).ok
    assert controller.ledger is not None
    assert controller.ledger.get(candidate.id) is not None
    assert controller.ledger.pending_audit_count() == 1
    assert [event["event"] for event in _journal(path)] == ["prepare", "commit"]

    accepted: list[str] = []
    restarted = si.PromotionLedger(path=path)
    assert restarted.pending_audit_count() == 1
    assert restarted.flush_audit_outbox(
        lambda **payload: accepted.append(payload["event_id"]) or True
    ) == 1
    assert attempted == accepted
    assert restarted.pending_audit_count() == 0
    assert si.PromotionLedger(path=path).pending_audit_count() == 0
    assert restarted.flush_audit_outbox(lambda **_payload: True) == 0

    events = _journal(path)
    assert [event["event"] for event in events] == [
        "prepare", "commit", "audit_ack",
    ]
    assert events[1]["audit"]["event_id"] == events[2]["audit_event_id"]


def test_crash_after_sink_acceptance_retries_the_same_event_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(si, "enabled", lambda: True)
    path = tmp_path / "promotions.json"
    first_attempt: list[str] = []

    def crash_after_acceptance(**payload):
        if payload.get("decision") == "promote":
            first_attempt.append(payload["event_id"])
            raise SystemExit("crash after audit sink acceptance")
        return True

    candidate = _candidate()
    before, after = _artifact("before"), _artifact("after")
    controller = _controller(path, crash_after_acceptance)
    prepared = controller.prepare_promotion(candidate, before=before, after=after)

    with pytest.raises(SystemExit, match="after audit sink acceptance"):
        controller.commit_prepared(prepared, artifact=after)

    restarted_ledger = si.PromotionLedger(path=path)
    assert restarted_ledger.get(candidate.id) is not None
    assert restarted_ledger.pending_audit_count() == 1
    retried: list[str] = []
    restarted = _controller(
        path,
        lambda **payload: retried.append(payload["event_id"]) or True,
    )

    # The same prepare call is the public crash-retry path. It observes the
    # committed transaction and drains, rather than appending another COMMIT.
    retry = restarted.prepare_promotion(candidate, before=before, after=after)
    assert retry.ok and retry.committed and not retry.needs_apply
    assert first_attempt == retried
    assert restarted.ledger is not None
    assert restarted.ledger.pending_audit_count() == 0
    assert [event["event"] for event in _journal(path)] == [
        "prepare", "commit", "audit_ack",
    ]


def test_self_harness_apply_audit_uses_the_committed_outbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(si, "enabled", lambda: True)
    from maverick import audit, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    with world_model.WorldModel() as world:
        source_id = world.create_goal("shared export rehearsal", owner="")
        world.set_goal_status(source_id, "done", result="bounded export completed")

    store = tmp_path / "addenda.json"
    ledger_path = tmp_path / "promotions.json"
    refused: list[dict] = []

    def refuse(_kind, **payload):
        if payload.get("event_id"):
            refused.append(payload)
        raise AuditRefused("off-host signer unavailable")

    monkeypatch.setattr(audit, "record", refuse)
    controller = si.SelfImprovementController(
        frozen_fn=lambda: False,
        ledger=si.PromotionLedger(path=ledger_path),
        model_risk_verifier=lambda **_kwargs: (True, ""),
    )
    proposal = sh.HarnessProposal(
        model_id="model-a",
        signature="timeout on unbounded export",
        addendum_line="Bound the export window before starting.",
        rationale="prevents the recurring timeout",
        hypothesis="unbounded exports exhaust the deadline",
        source_goal_ids=(source_id,),
    )
    validation = sh.ValidationResult(
        accepted=True,
        held_in_delta=0.4,
        held_out_delta=0.5,
        reason="improved",
        baseline_score=0.4,
        candidate_score=0.9,
        samples=5,
        held_in_samples=2,
        held_out_samples=5,
        effect_ci_low=0.1,
    )

    assert sh._gate_and_apply(
        proposal,
        validation,
        controller=controller,
        path=store,
    ) == (True, "promoted")
    assert "Bound the export window" in sh.recall_addendum("model-a", store)
    assert controller.ledger is not None
    assert controller.ledger.pending_audit_count() == 1
    assert len(refused) == 1
    assert refused[0]["phase"] == "apply"
    assert refused[0]["signature"] == proposal.signature
    assert refused[0]["rationale"] == proposal.rationale

    delivered: list[dict] = []
    monkeypatch.setattr(
        audit,
        "record",
        lambda _kind, **payload: delivered.append(payload) or True,
    )
    restarted = si.PromotionLedger(path=ledger_path)
    assert restarted.flush_audit_outbox(si._default_audit_fn) == 1
    assert delivered[0]["event_id"] == refused[0]["event_id"]
    assert delivered[0]["hypothesis"] == proposal.hypothesis
    assert restarted.pending_audit_count() == 0


def test_combined_audit_payload_is_reserved_before_external_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(si, "enabled", lambda: True)
    path = tmp_path / "promotions.json"
    controller = _controller(path, lambda **_payload: True)
    candidate = _candidate()
    candidate.provenance = {"large_provenance": "x" * 18_000}
    candidate.audit_payload = {"large_diagnostic": "y" * 18_000}

    result = controller.prepare_promotion(
        candidate,
        before=_artifact("before"),
        after=_artifact("after"),
    )

    assert not result.ok
    assert "persistence failed" in result.blocking_reason
    assert controller.ledger is not None
    assert controller.ledger.transactions() == []
    assert not Path(f"{path}.journal").exists()
