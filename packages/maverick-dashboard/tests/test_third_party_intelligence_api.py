from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import third_party_intelligence as intelligence
from maverick_dashboard import third_party_intelligence_api as api

NOW = 1_800_000_000.0
API = "/api/v1/third-party/intelligence"
AUTO_KINDS = sorted(intelligence.MANDATORY_AUTOAPPROVAL_KINDS)


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    clock = Clock()
    store = intelligence.ThirdPartyIntelligenceStore(
        tmp_path / "third-party-intelligence.sqlite3",
        config_gate=lambda: None,
        clock=clock,
        token_factory=lambda: "x" * 43,
    )
    state: dict[str, object] = {
        "enabled": True,
        "tenant": "tenant-a",
        "factory_calls": [],
    }

    def require_enabled() -> None:
        if not state["enabled"]:
            raise intelligence.ThirdPartyIntelligenceConfigError("disabled for test")

    monkeypatch.setattr(intelligence, "require_enabled", require_enabled)
    monkeypatch.setattr(intelligence, "enabled", lambda: bool(state["enabled"]))
    monkeypatch.setattr(api, "_tenant_id", lambda: str(state["tenant"]))
    # Vendor writes recheck the live workspace at the effect boundary.
    from maverick_dashboard import vendor_profile

    monkeypatch.setattr(vendor_profile, "current_tenant_id_strict", lambda: str(state["tenant"]))
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(
        api,
        "require_global_permission",
        lambda _request, _permission: None,
    )

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(
            sub=request.headers.get("X-Test-Subject", "vendor-owner")
        )
        return await call_next(request)

    def store_factory(**kwargs):
        calls = state["factory_calls"]
        assert isinstance(calls, list)
        calls.append(kwargs)
        return store

    app.state.third_party_intelligence_store_factory = store_factory
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "vendor-owner"},
    )
    return client, store, clock, state


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _citation(label: str) -> list[dict[str, str]]:
    return [
        {
            "citation_id": f"citation-{label}",
            "title": "Licensed provider evidence",
            "uri": f"https://intelligence.example/evidence/{label}",
            "pinpoint": "record-1",
        }
    ]


def _ok(response, status: int = 200) -> dict:
    assert response.status_code == status, response.text
    return response.json()


def _saved_recipient(store, address: str = "risk-ops@example.test", recipient_id: str = "risk-ops") -> str:
    """A watch sends only to a saved, reviewed recipient; its opaque reference."""
    saved = store.save_alert_recipient(
        "tenant-a", recipient_id=recipient_id, name="Risk operations", address=address,
        actor_ref="vendor-owner", idempotency_key=f"save-{recipient_id}", external_use_reviewed=True)
    return saved["destination_ref"]


def _vendor_body(*, identity: str = "vendor-1", revision: int = 0) -> dict:
    return {
        "display_label": f"Pseudonymous {identity}",
        "entity_identity_sha256": _digest(f"identity:{identity}"),
        "encrypted_profile_ref": f"vault-cipher-{identity}",
        "profile_key_ref": f"kms-key-{identity}",
        "territories": ["EU", "US"],
        "service_categories": ["cloud_service"],
        "inherent_risk_level": 1,
        "criticality": 1,
        "data_access_level": "limited",
        "expected_revision": revision,
        "idempotency_key": f"vendor-{identity}-{revision}",
    }


def _create_vendor(
    client: TestClient,
    vendor_id: str = "vendor-1",
    *,
    identity: str | None = None,
) -> dict:
    return _ok(
        client.put(
            f"{API}/vendors/{vendor_id}",
            json=_vendor_body(identity=identity or vendor_id),
        )
    )


def _source_body(kind: str, suffix: str = "v1") -> dict:
    return {
        "provider": f"fixture-{kind}",
        "kind": kind,
        "provenance_uri": f"https://intelligence.example/{kind}",
        "credential_env": f"{kind.upper()}_TOKEN",
        "license_ref": f"license-{kind}-{suffix}",
        "rights_basis": "Approved screening, monitoring, EDD, and exchange use.",
        "purposes": [
            "screening",
            "monitoring",
            "risk_scoring",
            "edd",
            "exchange",
        ],
        "territories": ["EU", "US"],
        "retention_seconds": 86_400,
        "expected_revision": 0,
        "idempotency_key": f"enroll-{kind}-{suffix}",
    }


def _enroll_source(
    client: TestClient,
    kind: str,
    *,
    suffix: str = "v1",
) -> tuple[dict, dict]:
    source_id = f"source-{kind}-{suffix}"
    source = _ok(client.put(f"{API}/sources/{source_id}", json=_source_body(kind, suffix)))
    approved = _ok(
        client.post(
            f"{API}/sources/{source_id}/approval",
            headers={"X-Test-Subject": "source-counsel"},
            json={
                "expected_revision": source["revision"],
                "approved": True,
                "rationale": "License, territory, purpose, and retention reviewed.",
                "idempotency_key": f"approve-{kind}-{suffix}",
            },
        )
    )
    snapshot_id = f"snapshot-{kind}-{suffix}"
    snapshot = _ok(
        client.put(
            f"{API}/sources/{source_id}/snapshots/{snapshot_id}",
            json={
                "dataset_revision": f"dataset-{suffix}",
                "observed_at": NOW - 10.0,
                "valid_until": NOW + 3_600.0,
                "completeness": 1.0,
                "record_count": 100,
                "evidence_sha256": _digest(f"snapshot:{kind}:{suffix}"),
                "citations": _citation(f"{kind}-{suffix}"),
                "provenance_uri": f"https://intelligence.example/{kind}",
                "idempotency_key": f"snapshot-{kind}-{suffix}",
            },
        )
    )
    return approved, snapshot


def _start_run(
    client: TestClient,
    vendor: dict,
    snapshots: dict[str, str],
    *,
    run_id: str = "run-1",
) -> dict:
    return _ok(
        client.put(
            f"{API}/screening/runs/{run_id}",
            json={
                "vendor_id": vendor["vendor_id"],
                "subject_identity_sha256": vendor["entity_identity_sha256"],
                "snapshot_bindings": snapshots,
                "requested_kinds": sorted(snapshots),
                "idempotency_key": f"start-{run_id}",
            },
        )
    )


def test_status_routes_injection_and_exact_default_off(environment) -> None:
    client, _store, _clock, state = environment
    status = _ok(client.get(f"{API}/status"))
    assert status["enabled"] is True
    assert status["bundled_corpus"] is False
    assert status["live_feed_configured"] is False
    assert status["provider_acceptance_verified"] is False
    assert status["external_operations_accepted"] is False
    # Alerts resolve only saved, reviewed recipients; that resolver is built in.
    assert status["delivery_destination_resolver_configured"] is True
    assert status["silent_pep_sanctions_adverse_dismissal_allowed"] is False
    assert status["low_risk_autoapproval_requires_complete_fresh_evidence"] is True
    assert status["exchange_anonymity_assumed"] is False
    assert status["raw_credentials_accepted"] is False
    assert status["principal_ref"].startswith("tpi-principal-")

    _create_vendor(client)
    calls = state["factory_calls"]
    assert isinstance(calls, list) and calls
    assert calls[-1]["tenant_id"] == "tenant-a"
    assert isinstance(calls[-1]["request"], Request)

    state["enabled"] = False
    assert _ok(client.get(f"{API}/status"))["enabled"] is False
    response = client.get(f"{API}/vendors/vendor-1")
    assert response.status_code == 403


def test_strict_current_tenant_boundary_rejects_raw_and_actor_fields(environment) -> None:
    client, _store, _clock, state = environment
    source = _source_body("sanctions")
    for forbidden, value in (
        ("tenant_id", "tenant-b"),
        ("actor_ref", "forged-admin"),
        ("credential_value", "raw-secret"),
        ("raw_profile", {"legal_name": "Secret Vendor"}),
    ):
        response = client.put(
            f"{API}/sources/source-sanctions",
            json={**source, forbidden: value},
        )
        assert response.status_code == 422

    numeric_string = {**source, "retention_seconds": "86400"}
    assert client.put(f"{API}/sources/source-sanctions", json=numeric_string).status_code == 422
    vendor = _vendor_body()
    assert (
        client.put(
            f"{API}/vendors/vendor-1",
            json={**vendor, "owner_ref": "forged-owner"},
        ).status_code
        == 422
    )
    assert client.get(f"{API}/vendors/vendor%201").status_code == 422

    _create_vendor(client)
    state["tenant"] = "tenant-b"
    assert client.get(f"{API}/vendors/vendor-1").status_code == 404


def test_sources_vendors_relationships_and_four_eyes(environment) -> None:
    client, _store, _clock, _state = environment
    vendor = _create_vendor(client)
    related = _create_vendor(client, "subprocessor-1")
    assert _ok(client.get(f"{API}/vendors/{vendor['vendor_id']}")) == vendor
    relationship = _ok(
        client.put(
            f"{API}/relationships/relationship-1",
            json={
                "vendor_id": vendor["vendor_id"],
                "related_vendor_id": related["vendor_id"],
                "relationship_type": "subprocessor",
                "scope_ref": "service-scope-1",
                "criticality": 2,
                "data_access_level": "limited",
                "expected_revision": 0,
                "idempotency_key": "relationship-1-create",
            },
        )
    )
    assert _ok(client.get(f"{API}/relationships/relationship-1")) == relationship
    listed = _ok(client.get(f"{API}/vendors/vendor-1/relationships"))
    assert listed["count"] == 1

    body = _source_body("sanctions")
    source = _ok(client.put(f"{API}/sources/source-sanctions-v1", json=body))
    approval = {
        "expected_revision": source["revision"],
        "approved": True,
        "rationale": "Independent rights review complete.",
        "idempotency_key": "approve-sanctions-v1",
    }
    same_human = client.post(
        f"{API}/sources/source-sanctions-v1/approval",
        json=approval,
    )
    assert same_human.status_code == 403
    approved = _ok(
        client.post(
            f"{API}/sources/source-sanctions-v1/approval",
            headers={"X-Test-Subject": "source-counsel"},
            json=approval,
        )
    )
    assert approved["state"] == "active"
    snapshot = _ok(
        client.put(
            f"{API}/sources/source-sanctions-v1/snapshots/snapshot-sanctions-v1",
            json={
                "dataset_revision": "dataset-v1",
                "observed_at": NOW - 10.0,
                "valid_until": NOW + 600.0,
                "completeness": 1.0,
                "record_count": 12,
                "evidence_sha256": _digest("sanctions-snapshot"),
                "citations": _citation("sanctions"),
                "provenance_uri": body["provenance_uri"],
                "idempotency_key": "snapshot-sanctions-v1",
            },
        )
    )
    assert _ok(client.get(f"{API}/snapshots/{snapshot['snapshot_id']}")) == snapshot
    revoked = _ok(
        client.post(
            f"{API}/sources/source-sanctions-v1/revoke",
            json={
                "expected_revision": approved["revision"],
                "rationale": "Provider agreement ended.",
                "idempotency_key": "revoke-sanctions-v1",
            },
        )
    )
    assert revoked["state"] == "revoked"
    assert _ok(client.get(f"{API}/sources/{source['source_id']}")) == revoked


def test_screening_mandatory_review_never_silently_dismisses(environment) -> None:
    client, _store, _clock, _state = environment
    vendor = _create_vendor(client)
    _source, snapshot = _enroll_source(client, "sanctions")
    run = _start_run(client, vendor, {"sanctions": snapshot["snapshot_id"]})
    finding = _ok(
        client.put(
            f"{API}/screening/runs/{run['run_id']}/findings/finding-sanctions",
            headers={"X-Test-Subject": "screening-detector"},
            json={
                "source_id": snapshot["source_id"],
                "kind": "sanctions",
                "candidate_ref": "candidate-sanctions-1",
                "match_confidence": 0.25,
                "severity": "low",
                "observed_at": NOW,
                "valid_until": NOW + 300.0,
                "evidence_sha256": _digest("finding-sanctions"),
                "citations": _citation("finding-sanctions"),
                "idempotency_key": "finding-sanctions-create",
            },
        )
    )
    assert finding["disposition"] == "pending_review"
    incomplete = client.post(
        f"{API}/screening/runs/{run['run_id']}/complete",
        json={
            "expected_revision": run["revision"],
            "idempotency_key": "premature-completion",
        },
    )
    assert incomplete.status_code == 409
    review = {
        "disposition": "not_a_match",
        "expected_revision": finding["revision"],
        "rationale": "Independent evidence comparison ruled out the candidate.",
        "idempotency_key": "review-finding-sanctions",
    }
    same_detector = client.post(
        f"{API}/screening/findings/{finding['finding_id']}/review",
        headers={"X-Test-Subject": "screening-detector"},
        json=review,
    )
    assert same_detector.status_code == 403
    reviewed = _ok(
        client.post(
            f"{API}/screening/findings/{finding['finding_id']}/review",
            headers={"X-Test-Subject": "screening-reviewer"},
            json=review,
        )
    )
    assert reviewed["disposition"] == "not_a_match"
    completed = _ok(
        client.post(
            f"{API}/screening/runs/{run['run_id']}/complete",
            json={
                "expected_revision": run["revision"],
                "idempotency_key": "complete-screening-run",
            },
        )
    )
    assert completed["state"] == "complete"
    assert _ok(client.get(f"{API}/screening/runs/{run['run_id']}")) == completed
    findings = _ok(client.get(f"{API}/screening/runs/{run['run_id']}/findings"))
    assert findings["count"] == 1
    assert _ok(client.get(f"{API}/screening/findings/{finding['finding_id']}"))["reviewed_by"]


def test_approved_policy_and_complete_fresh_evidence_gate_autoapproval(
    environment,
) -> None:
    client, _store, _clock, _state = environment
    vendor = _create_vendor(client)
    snapshots: dict[str, str] = {}
    for kind in AUTO_KINDS:
        _source, snapshot = _enroll_source(client, kind)
        snapshots[kind] = snapshot["snapshot_id"]
    run = _start_run(client, vendor, snapshots, run_id="autoapproval-run")
    run = _ok(
        client.post(
            f"{API}/screening/runs/{run['run_id']}/complete",
            json={
                "expected_revision": run["revision"],
                "idempotency_key": "complete-autoapproval-run",
            },
        )
    )
    weights = dict.fromkeys(intelligence.RISK_FACTOR_KEYS, 0)
    policy = _ok(
        client.put(
            f"{API}/risk/policies/low-risk-policy",
            headers={"X-Test-Subject": "risk-author"},
            json={
                "required_source_kinds": AUTO_KINDS,
                "maximum_source_age_seconds": 300,
                "minimum_completeness": 0.95,
                "factor_weights": weights,
                "maximum_autoapproval_score": 10,
                "allow_low_risk_autoapproval": True,
                "allowed_territories": ["EU", "US"],
                "maximum_vendor_criticality": 2,
                "maximum_data_access_level": "limited",
                "expected_latest_version": 0,
                "idempotency_key": "author-low-risk-policy",
            },
        )
    )
    approval = {
        "approved": True,
        "rationale": "Complete-evidence hard stops and score bounds reviewed.",
        "idempotency_key": "approve-low-risk-policy",
    }
    self_approval = client.post(
        f"{API}/risk/policies/{policy['policy_id']}/versions/1/approval",
        headers={"X-Test-Subject": "risk-author"},
        json=approval,
    )
    assert self_approval.status_code == 403
    premature = _ok(
        client.put(
            f"{API}/risk/decisions/premature-decision/evaluate",
            json={
                "vendor_id": vendor["vendor_id"],
                "run_id": run["run_id"],
                "policy_id": policy["policy_id"],
                "policy_version": policy["version"],
                "idempotency_key": "premature-policy-evaluation",
            },
        )
    )
    assert premature["autoapproved"] is False
    assert premature["status"] == "human_review"
    approved = _ok(
        client.post(
            f"{API}/risk/policies/{policy['policy_id']}/versions/1/approval",
            headers={"X-Test-Subject": "risk-approver"},
            json=approval,
        )
    )
    assert approved["state"] == "approved"
    assert _ok(client.get(f"{API}/risk/policies/low-risk-policy/versions/1"))["approved_by"]
    decision = _ok(
        client.put(
            f"{API}/risk/decisions/risk-decision-1/evaluate",
            json={
                "vendor_id": vendor["vendor_id"],
                "run_id": run["run_id"],
                "policy_id": policy["policy_id"],
                "policy_version": policy["version"],
                "idempotency_key": "evaluate-risk-decision-1",
            },
        )
    )
    assert decision["status"] == "auto_approved"
    assert decision["autoapproved"] is True
    override = _ok(
        client.post(
            f"{API}/risk/decisions/{decision['decision_id']}/overrides/manual-reject",
            json={
                "status": "rejected",
                "expected_revision": decision["revision"],
                "rationale": "New contractual evidence requires rejection.",
                "idempotency_key": "manual-reject",
            },
        )
    )
    assert override["status"] == "rejected"
    rollback = _ok(
        client.post(
            f"{API}/risk/decisions/{override['decision_id']}/rollbacks/rollback-reject",
            json={
                "restore_decision_id": decision["decision_id"],
                "rationale": "Contractual evidence belonged to another vendor.",
                "idempotency_key": "rollback-reject",
            },
        )
    )
    assert rollback["status"] == decision["status"]
    assert rollback["autoapproved"] is False
    assert _ok(client.get(f"{API}/risk/decisions/{rollback['decision_id']}")) == rollback


def test_edd_tasks_evidence_and_independent_decision(environment) -> None:
    client, _store, _clock, _state = environment
    vendor = _create_vendor(client)
    _source, snapshot = _enroll_source(client, "compliance")
    case = _ok(
        client.put(
            f"{API}/edd/cases/edd-1",
            json={
                "vendor_id": vendor["vendor_id"],
                "reason": "Enhanced control validation required.",
                "severity": "high",
                "idempotency_key": "open-edd-1",
            },
        )
    )
    case = _ok(
        client.put(
            f"{API}/edd/cases/{case['case_id']}/tasks/verify-control",
            json={
                "title": "Verify compliance control",
                "assignee_ref": "edd-analyst",
                "due_at": NOW + 600.0,
                "status": "complete",
                "evidence_sha256": _digest("task-evidence"),
                "expected_revision": case["revision"],
                "idempotency_key": "complete-edd-task",
            },
        )
    )
    case = _ok(
        client.put(
            f"{API}/edd/cases/{case['case_id']}/evidence/control-evidence",
            json={
                "snapshot_id": snapshot["snapshot_id"],
                "evidence_sha256": _digest("edd-evidence"),
                "citations": _citation("edd-evidence"),
                "summary": "Evidence is retained under the encrypted vault reference.",
                "expected_revision": case["revision"],
                "idempotency_key": "add-edd-evidence",
            },
        )
    )
    decision = {
        "decision": "approved",
        "rationale": "Tasks and licensed evidence independently reviewed.",
        "expected_revision": case["revision"],
        "idempotency_key": "approve-edd-1",
    }
    assert (
        client.post(f"{API}/edd/cases/{case['case_id']}/decision", json=decision).status_code == 403
    )
    decided = _ok(
        client.post(
            f"{API}/edd/cases/{case['case_id']}/decision",
            headers={"X-Test-Subject": "edd-reviewer"},
            json=decision,
        )
    )
    assert decided["decision"] == "approved"
    assert _ok(client.get(f"{API}/edd/cases/{case['case_id']}")) == decided


def test_monitor_alert_outbox_retry_ack_and_revoke(environment) -> None:
    client, store, clock, _state = environment
    vendor = _create_vendor(client)
    source, snapshot = _enroll_source(client, "breach_intelligence")
    unsaved = client.put(f"{API}/monitors/unsaved-monitor", json={
        "vendor_id": vendor["vendor_id"], "source_bindings": {"breach_intelligence": source["source_id"]},
        "destination_ref": "third-party-alert-sink", "cadence_seconds": 60, "idempotency_key": "create-unsaved"})
    assert unsaved.status_code == 404 and "saved alert recipient" in unsaved.text
    destination = _saved_recipient(store)
    monitor = _ok(
        client.put(
            f"{API}/monitors/breach-monitor",
            json={
                "vendor_id": vendor["vendor_id"],
                "source_bindings": {"breach_intelligence": source["source_id"]},
                "destination_ref": destination,
                "cadence_seconds": 60,
                "idempotency_key": "create-breach-monitor",
            },
        )
    )
    assert _ok(client.get(f"{API}/monitoring/due"))["count"] == 1
    baseline = _ok(
        client.post(
            f"{API}/monitors/{monitor['monitor_id']}/observations",
            json={
                "snapshot_bindings": {"breach_intelligence": snapshot["snapshot_id"]},
                "observation_sha256": _digest("monitor-baseline"),
                "evidence_sha256": _digest("monitor-baseline-evidence"),
                "citations": _citation("monitor-baseline"),
                "expected_revision": monitor["revision"],
                "idempotency_key": "monitor-baseline",
            },
        )
    )
    assert baseline["changed"] is False
    clock.advance(60)
    changed = _ok(
        client.post(
            f"{API}/monitors/{monitor['monitor_id']}/observations",
            json={
                "snapshot_bindings": {"breach_intelligence": snapshot["snapshot_id"]},
                "observation_sha256": _digest("monitor-changed"),
                "evidence_sha256": _digest("monitor-changed-evidence"),
                "citations": _citation("monitor-changed"),
                "expected_revision": baseline["monitor"]["revision"],
                "idempotency_key": "monitor-changed",
            },
        )
    )
    assert changed["changed"] is True
    alert = changed["alert"]
    assert _ok(client.get(f"{API}/monitoring/alerts/{alert['alert_id']}")) == alert
    delivery = _ok(client.post(f"{API}/outbox/claim", json={"limit": 10, "lease_seconds": 30.0}))[
        "items"
    ][0]
    failed = _ok(
        client.post(
            f"{API}/outbox/{delivery['delivery_id']}/fail",
            json={
                "lease_token": delivery["lease_token"],
                "error_code": "temporary_outage",
                "backoff_seconds": 10.0,
            },
        )
    )
    assert failed["state"] == "pending"
    clock.advance(10)
    retry = _ok(client.post(f"{API}/outbox/claim", json={"limit": 10, "lease_seconds": 30.0}))[
        "items"
    ][0]
    delivered = _ok(
        client.post(
            f"{API}/outbox/{retry['delivery_id']}/acknowledge",
            json={"lease_token": retry["lease_token"]},
        )
    )
    assert delivered["state"] == "delivered"
    revoked = _ok(
        client.post(
            f"{API}/monitors/{monitor['monitor_id']}/revoke",
            json={
                "expected_revision": changed["monitor"]["revision"],
                "idempotency_key": "revoke-monitor",
            },
        )
    )
    assert revoked["state"] == "revoked"
    assert _ok(client.get(f"{API}/monitors/{monitor['monitor_id']}")) == revoked


def test_explicit_delivery_worker_fails_closed_then_acknowledges_without_recipient_leak(
    environment,
) -> None:
    client, store, clock, _state = environment
    vendor = _create_vendor(client, "delivery-vendor")
    source, snapshot = _enroll_source(client, "breach_intelligence", suffix="delivery")
    destination = _saved_recipient(store)
    monitor = _ok(
        client.put(
            f"{API}/monitors/delivery-monitor",
            json={
                "vendor_id": vendor["vendor_id"],
                "source_bindings": {"breach_intelligence": source["source_id"]},
                "destination_ref": destination,
                "cadence_seconds": 60,
                "idempotency_key": "create-delivery-monitor",
            },
        )
    )
    baseline = _ok(
        client.post(
            f"{API}/monitors/{monitor['monitor_id']}/observations",
            json={
                "snapshot_bindings": {"breach_intelligence": snapshot["snapshot_id"]},
                "observation_sha256": _digest("delivery-baseline"),
                "evidence_sha256": _digest("delivery-baseline-evidence"),
                "citations": _citation("delivery-baseline"),
                "expected_revision": monitor["revision"],
                "idempotency_key": "delivery-baseline",
            },
        )
    )
    clock.advance(60)
    changed = _ok(
        client.post(
            f"{API}/monitors/{monitor['monitor_id']}/observations",
            json={
                "snapshot_bindings": {"breach_intelligence": snapshot["snapshot_id"]},
                "observation_sha256": _digest("delivery-change"),
                "evidence_sha256": _digest("delivery-change-evidence"),
                "citations": _citation("delivery-change"),
                "expected_revision": baseline["monitor"]["revision"],
                "idempotency_key": "delivery-change",
            },
        )
    )
    assert changed["changed"] is True

    from maverick import third_party_intelligence_delivery as delivery

    # Sending is a reviewed batch on the page (outbox/review then outbox/run);
    # the delivery worker beneath it is exercised directly here.
    sent: list[dict[str, str]] = []

    class Transport:
        def send(self, **kwargs) -> None:
            sent.append(dict(kwargs))

    def unavailable(_tenant_id, _destination_ref):
        raise delivery.DestinationResolutionError("no current recipient")

    batch = dict(tenant_id="tenant-a", worker_id="worker", transport=Transport(), limit=10, lease_seconds=30.0,
                 base_backoff_seconds=10.0, maximum_backoff_seconds=60.0)
    refused = delivery.deliver_alert_batch(store, resolve_destination=unavailable, **batch)
    assert refused.claimed == 1 and refused.acknowledged == 0 and sent == []
    clock.advance(60)

    def saved_only(tenant_id, destination_ref):
        return store.resolve_alert_recipient(tenant_id, destination_ref)["address"]

    result = delivery.deliver_alert_batch(store, resolve_destination=saved_only, **batch)
    assert result.claimed == 1
    assert result.acknowledged == 1
    assert result.retry_pending == 0
    assert result.acknowledgement_ambiguous == 0
    assert len(sent) == 1
    assert sent[0]["recipient"] == "risk-ops@example.test"
    assert sent[0]["idempotency_key"] == result.outcomes[0].delivery_id
    assert "risk-ops@example.test" not in str(result)
    listed = _ok(client.get(f"{API}/outbox"))
    assert "risk-ops@example.test" not in str(listed)


def test_exchange_claims_are_false_without_independent_proof_and_withdrawable(
    environment,
) -> None:
    client, _store, _clock, _state = environment
    vendor = _create_vendor(client)
    _source, snapshot = _enroll_source(client, "performance")
    audience = _ok(client.get(f"{API}/status", headers={"X-Test-Subject": "exchange-member"}))[
        "principal_ref"
    ]
    consent = _ok(
        client.put(
            f"{API}/exchange/consents/exchange-consent",
            json={
                "vendor_id": vendor["vendor_id"],
                "audience": audience,
                "purpose": "benchmarking",
                "allowed_metrics": ["availability_band"],
                "explicit_consent": True,
                "expires_at": NOW + 86_400.0,
                "idempotency_key": "exchange-consent",
            },
        )
    )
    review = {
        "inclusion_approved": True,
        "privacy_review_ref": "privacy-review-1",
        "anonymity_proof_ref": None,
        "expected_revision": consent["revision"],
        "rationale": "Purpose-bound non-anonymous disclosure reviewed.",
        "idempotency_key": "review-exchange-consent",
    }
    assert (
        client.post(
            f"{API}/exchange/consents/{consent['consent_id']}/review",
            json=review,
        ).status_code
        == 403
    )
    consent = _ok(
        client.post(
            f"{API}/exchange/consents/{consent['consent_id']}/review",
            headers={"X-Test-Subject": "privacy-reviewer"},
            json=review,
        )
    )
    assert consent["privacy_reviewed"] is True
    assert consent["anonymity_proven"] is False
    contribution = _ok(
        client.put(
            f"{API}/exchange/consents/{consent['consent_id']}"
            "/contributions/availability-contribution",
            json={
                "metric_id": "availability_band",
                "value_band": "high",
                "audience": audience,
                "purpose": "benchmarking",
                "evidence_sha256": _digest("availability-evidence"),
                "lineage_refs": [f"snapshot:{snapshot['snapshot_id']}"],
                "retention_seconds": 86_400,
                "idempotency_key": "availability-contribution",
            },
        )
    )
    assert contribution["anonymous"] is False
    queried = _ok(
        client.post(
            f"{API}/exchange/query",
            headers={"X-Test-Subject": "exchange-member"},
            json={
                "audience": audience,
                "purpose": "benchmarking",
                "metric_id": "availability_band",
                "limit": 100,
            },
        )
    )
    assert queried["count"] == 1
    assert queried["anonymity_independently_proven_for_every_item"] is False
    assert queried["privacy_independently_reviewed_for_every_item"] is True
    wrong_principal = client.post(
        f"{API}/exchange/query",
        headers={"X-Test-Subject": "unrelated-member"},
        json={
            "audience": audience,
            "purpose": "benchmarking",
            "metric_id": "availability_band",
            "limit": 100,
        },
    )
    assert wrong_principal.status_code == 403
    assert (
        _ok(client.get(f"{API}/exchange/contributions/{contribution['contribution_id']}"))
        == contribution
    )
    withdrawn = _ok(
        client.post(
            f"{API}/exchange/consents/{consent['consent_id']}/withdraw",
            json={
                "expected_revision": consent["revision"],
                "rationale": "Vendor withdrew contribution consent.",
                "idempotency_key": "withdraw-exchange-consent",
            },
        )
    )
    assert withdrawn["state"] == "withdrawn"
    empty = _ok(
        client.post(
            f"{API}/exchange/query",
            headers={"X-Test-Subject": "exchange-member"},
            json={
                "audience": audience,
                "purpose": "benchmarking",
                "metric_id": "availability_band",
                "limit": 100,
            },
        )
    )
    assert empty["count"] == 0
    assert empty["anonymity_independently_proven_for_every_item"] is False
    assert (
        _ok(client.get(f"{API}/exchange/consents/{consent['consent_id']}"))["state"] == "withdrawn"
    )


def test_retention_integrity_and_complete_mount_surface(environment) -> None:
    client, _store, clock, _state = environment
    _create_vendor(client)
    _source, snapshot = _enroll_source(client, "compliance")
    integrity = _ok(client.get(f"{API}/integrity"))
    assert integrity["valid"] is True
    assert integrity["verified_records"] >= 3
    clock.advance(86_401)
    purged = _ok(client.post(f"{API}/retention/purge"))
    assert purged["source_snapshots"] == 1
    assert client.get(f"{API}/snapshots/{snapshot['snapshot_id']}").status_code == 404

    paths = client.app.openapi()["paths"]
    scoped = [path for path in paths if path.startswith(API)]
    # 45 governed operations, 11 read-only list routes for the page, and five
    # paths for saved alert recipients and the reviewed outbox.
    assert len(scoped) == 61
    assert len(api.router.routes) == 69
    expected_fragments = {
        "/status",
        "/provider-runtime/",
        "/sources/",
        "/snapshots/",
        "/vendors/",
        "/relationships/",
        "/screening/",
        "/risk/",
        "/edd/",
        "/monitors/",
        "/monitoring/",
        "/outbox/",
        "/outbox/review",
        "/alert-recipients",
        "/exchange/",
        "/retention/",
        "/integrity",
    }
    assert all(any(fragment in path for path in scoped) for fragment in expected_fragments)


def test_record_lists_load_for_the_page_and_stay_in_the_workspace(environment) -> None:
    client, _store, _clock, state = environment
    _create_vendor(client)
    _enroll_source(client, "sanctions")
    assert client.put(f"{API}/risk/policies/standard", json={
        "required_source_kinds": ["sanctions"], "maximum_source_age_seconds": 86_400,
        "minimum_completeness": 0.9, "factor_weights": dict.fromkeys(("inherent_risk", "criticality", "sanctions", "pep", "watchlist", "adverse_media", "cyber_posture", "breach_intelligence", "compliance", "performance"), 1),
        "maximum_autoapproval_score": 10, "allow_low_risk_autoapproval": False,
        "allowed_territories": ["EU"], "maximum_vendor_criticality": 2,
        "maximum_data_access_level": "limited", "expected_latest_version": 0,
        "idempotency_key": "policy-list"}).status_code == 200
    lists = {path: client.get(f"{API}{path}").json()["items"] for path in (
        "/sources", "/snapshots", "/vendors", "/screening/runs", "/risk/policies",
        "/risk/decisions", "/edd/cases", "/monitors", "/monitoring/alerts", "/exchange/consents")}
    assert [v["vendor_id"] for v in lists["/vendors"]] == ["vendor-1"]
    assert [s["state"] for s in lists["/sources"]] == ["active"]
    assert len(lists["/snapshots"]) == 1
    assert [(p["policy_id"], p["version"], p["state"]) for p in lists["/risk/policies"]] == [
        ("standard", 1, "pending")]
    assert lists["/screening/runs"] == [] and lists["/exchange/consents"] == []
    me = client.get(f"{API}/me").json()["principal_ref"]
    assert me.startswith("tpi-principal-")
    state["tenant"] = "tenant-b"
    assert client.get(f"{API}/vendors").json() == {"items": []}
    assert client.get(f"{API}/risk/policies").json() == {"items": []}


def test_record_lists_are_off_with_the_feature(environment) -> None:
    client, _store, _clock, state = environment
    state["enabled"] = False
    for path in ("/sources", "/vendors", "/risk/policies", "/exchange/consents"):
        assert client.get(f"{API}{path}").status_code == 403


def test_record_lists_need_view_permission(environment, monkeypatch) -> None:
    client, _store, _clock, _state = environment
    from fastapi import HTTPException

    seen = []

    def deny(_request, permission):
        seen.append(permission)
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(api, "require_permission", deny)
    assert client.get(f"{API}/vendors").status_code == 403
    assert seen == ["view"]
