"""Governed Model Risk approval projection into the evidence graph."""

from __future__ import annotations

import time
from typing import Any

import pytest
from maverick import evidence_graph
from maverick import model_risk_assurance as model_risk


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)


def _approved_evidence() -> dict[str, Any]:
    now = time.time()
    payload_sha256 = "a" * 64
    return {
        "id": "MRE-governed-evaluation",
        "schema": model_risk.EVIDENCE_SCHEMA,
        "revision": 2,
        "asset_id": "MAS-evaluated-model",
        "source_id": "evaluation-run-17",
        "evidence_kind": "evaluation",
        "result": "passed",
        "scope_digest": "b" * 64,
        "artifact_digest": "c" * 64,
        "evaluator_digest": "d" * 64,
        "evaluator_asset_id": "MAS-governed-evaluator",
        "evaluator_binding": {
            "record_id": "MAO-governed-evaluator",
            "revision": 1,
            "record_sha256": "e" * 64,
            "relation": "produced_evidence",
        },
        "summary": "The bounded evaluation met its declared acceptance criteria.",
        "metrics": {"pass_rate": 0.99},
        "observed_at": now - 60,
        "valid_until": now + 3600,
        "payload_sha256": payload_sha256,
        "evidence_node_id": "EGN-raw-observation",
        "review": {
            "decision": "approved",
            "reviewer": "model-risk-owner",
            "rationale": "Scope, evaluator identity, and result were independently reviewed.",
            "reviewed_at": now - 30,
            "payload_sha256": payload_sha256,
            "legal_certification": False,
        },
        "status": "approved",
        "freshness": "current",
        "legal_certification": False,
    }


def _install_authority(monkeypatch, state: dict[str, Any]) -> None:
    state.setdefault(
        "asset",
        {
            "id": "MAO-governed-target",
            "revision": 1,
            "asset_id": state["record"]["asset_id"],
            "version_digest": state["record"]["artifact_digest"],
        },
    )
    state.setdefault(
        "evaluator",
        {
            "id": "MAO-governed-evaluator",
            "revision": 1,
            "asset_id": state["record"]["evaluator_asset_id"],
            "version_digest": state["record"]["evaluator_digest"],
        },
    )
    state["record"]["evaluator_binding"]["record_sha256"] = (
        model_risk._record_sha(state["evaluator"])  # noqa: SLF001
    )
    monkeypatch.setattr(
        model_risk,
        "list_evidence",
        lambda: [dict(state["record"])],
    )
    monkeypatch.setattr(
        model_risk,
        "get_evidence",
        lambda evidence_id: (
            dict(state["record"])
            if evidence_id == state["record"]["id"]
            else None
        ),
    )
    monkeypatch.setattr(
        model_risk,
        "get_observation",
        lambda asset_id: (
            dict(state["asset"])
            if asset_id == state["asset"]["asset_id"]
            else (
                dict(state["evaluator"])
                if asset_id == state["evaluator"]["asset_id"]
                else None
            )
        ),
    )


def test_projection_rereads_authority_and_public_ingest_cannot_inherit_approval(
    monkeypatch,
):
    state = {"record": _approved_evidence()}
    _install_authority(monkeypatch, state)

    untrusted = evidence_graph.ingest(
        source="model_risk_assurance",
        source_id="caller-asserted-approval",
        evidence_type="approved_ai_assurance_evaluation",
        title="Caller-asserted evaluation",
        summary="A public caller cannot create inherited approval provenance.",
        controls=["AI-RMF:MEASURE"],
        attributes={"result": "passed"},
        actor="untrusted-caller",
    )
    assert untrusted["status"] == "pending_review"
    assert untrusted["review"] is None

    projected = evidence_graph.project_model_risk_evidence(
        state["record"]["id"],
        actor="model-risk-projector",
    )
    current = evidence_graph.get(projected["id"])
    assert current is not None
    assert current["status"] == "approved"
    assert current["freshness"] == "current"
    assert current["source"] == "model_risk_assurance"
    assert current["source_id"] == (
        f"{state['record']['id']}:{state['record']['payload_sha256']}:review:2"
    )
    assert current["review"]["inherited_from"] == state["record"]["id"]
    assert current["review"]["authority_revision"] == 2
    assert current["review"]["authority_schema"] == model_risk.EVIDENCE_SCHEMA
    assert len(current["review"]["authority_sha256"]) == 64
    assert current["authority_validation"]["status"] == "current"
    assert current["attributes"]["evidence_payload_sha256"] == "a" * 64

    collected = evidence_graph.collect_model_risk_evidence(actor="collector")
    assert [node["id"] for node in collected] == [projected["id"]]
    assert evidence_graph.coverage_report(["AI-RMF:MEASURE"])[
        "coverage_percent"
    ] == 100.0


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("revision", "source_revision_changed"),
        ("revoked", "source_not_approved"),
        ("decision", "source_not_approved"),
        ("decision_content", "source_decision_changed"),
        ("payload_binding", "source_authority_invalid"),
        ("artifact", "source_artifact_authority_stale"),
        ("evaluator", "source_evaluator_authority_stale"),
        ("evaluator_content", "source_evaluator_authority_stale"),
        ("expiry", "source_expired"),
    ],
)
def test_projected_authority_fails_closed_after_source_drift(
    monkeypatch,
    mutation,
    reason,
):
    state = {"record": _approved_evidence()}
    _install_authority(monkeypatch, state)
    projected = evidence_graph.project_model_risk_evidence(
        state["record"]["id"],
        actor="model-risk-projector",
    )

    if mutation == "revision":
        state["record"]["revision"] += 1
    elif mutation == "revoked":
        state["record"]["status"] = "revoked"
    elif mutation == "decision":
        state["record"]["review"] = {
            **state["record"]["review"],
            "decision": "rejected",
        }
    elif mutation == "decision_content":
        state["record"]["review"] = {
            **state["record"]["review"],
            "rationale": "Changed without a governed revision.",
        }
    elif mutation == "payload_binding":
        state["record"]["review"] = {
            **state["record"]["review"],
            "payload_sha256": "e" * 64,
        }
    elif mutation == "artifact":
        state["asset"]["version_digest"] = "f" * 64
    elif mutation == "evaluator":
        state["evaluator"]["version_digest"] = "f" * 64
    elif mutation == "evaluator_content":
        state["evaluator"]["display_name"] = "Changed without a revision"
    elif mutation == "expiry":
        state["record"]["valid_until"] = time.time() - 1
        state["record"]["freshness"] = "stale"

    current = evidence_graph.get(projected["id"])
    assert current is not None
    assert current["status"] == "authority_stale"
    assert current["freshness"] == "stale"
    assert current["authority_validation"]["reason"] == reason
    assert evidence_graph.coverage_report(["AI-RMF:MEASURE"])[
        "coverage_percent"
    ] == 0.0
    pack = evidence_graph.render_pack(required_controls=["AI-RMF:MEASURE"])
    packed = next(node for node in pack["nodes"] if node["id"] == projected["id"])
    assert packed["status"] == "authority_stale"
    assert packed["authority_validation"]["reason"] == reason

    persisted = evidence_graph._STORE.get(projected["id"])  # noqa: SLF001
    assert persisted is not None
    assert persisted["status"] == "approved"
    assert persisted["review"]["authority_revision"] == 2


def test_collection_is_bounded_and_rereads_each_governed_id(monkeypatch):
    forged = _approved_evidence()
    monkeypatch.setattr(
        model_risk,
        "list_evidence",
        lambda: [forged],
    )
    monkeypatch.setattr(model_risk, "get_evidence", lambda _evidence_id: None)
    with pytest.raises(ValueError, match="source_not_found"):
        evidence_graph.collect_model_risk_evidence(actor="collector")

    monkeypatch.setattr(
        model_risk,
        "list_evidence",
        lambda: [forged] * 2049,
    )
    with pytest.raises(ValueError, match="2048-record projection limit"):
        evidence_graph.collect_model_risk_evidence(actor="collector")


@pytest.mark.parametrize("producer", [None, "MODEL-RISK-OWNER"])
def test_red_team_projection_requires_independent_server_bound_producer(
    monkeypatch,
    producer,
):
    record = _approved_evidence()
    record["id"] = "MRE-governed-red-team"
    record["evidence_kind"] = "red_team"
    if producer is not None:
        record["producer_actor"] = producer
    state = {"record": record}
    _install_authority(monkeypatch, state)

    with pytest.raises(ValueError, match="source_review_separation_invalid"):
        evidence_graph.project_model_risk_evidence(
            record["id"],
            actor="collector",
        )
    with pytest.raises(ValueError, match="source_review_separation_invalid"):
        evidence_graph.collect_model_risk_evidence(actor="collector")
