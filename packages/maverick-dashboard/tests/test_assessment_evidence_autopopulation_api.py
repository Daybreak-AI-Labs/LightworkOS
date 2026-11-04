from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import assessment_evidence_autopopulation as autopop
from maverick_dashboard import assessment_evidence_autopopulation_api as api

BASE = "/api/v1/assessment-evidence-autopopulation"


class FakeService:
    def __init__(self):
        self.calls = []
        self.record = {
            "id": "AEP-proposal",
            "assessment": {"id": "assessment-one", "revision": 4},
            "status": "pending_review",
            "revision": 1,
            "created_at": 1.0,
            "updated_at": 1.0,
            "retained_until": 100.0,
            "proposal_sha256": "a" * 64,
            "candidates": [
                {"question_id": "pia_security", "eligible_for_apply": True}
            ],
        }

    def create_proposal(self, assessment_id, analysis_ids, **kwargs):
        self.calls.append(("create", assessment_id, analysis_ids, kwargs))
        return dict(self.record)

    def get_proposal(self, proposal_id):
        self.calls.append(("get", proposal_id))
        if proposal_id == "missing":
            raise autopop.AssessmentEvidenceNotFound("proposal missing")
        return dict(self.record)

    def list_proposals(self, *, limit):
        self.calls.append(("list", limit))
        return [dict(self.record)]

    def review_proposal(self, proposal_id, **kwargs):
        self.calls.append(("review", proposal_id, kwargs))
        result = dict(self.record)
        result["status"] = "approved" if kwargs["decision"] == "approve" else "rejected"
        result["revision"] = 2
        return result

    def apply_proposal(self, proposal_id, **kwargs):
        self.calls.append(("apply", proposal_id, kwargs))
        result = dict(self.record)
        result["status"] = "applied"
        result["revision"] = 3
        return result

    def purge_expired(self, **kwargs):
        self.calls.append(("purge", kwargs))
        return ("AEP-expired",)

    def verify_integrity(self):
        self.calls.append(("integrity",))
        return autopop.AssessmentEvidenceIntegrityReport(
            schema=autopop.INTEGRITY_SCHEMA,
            tenant_sha256="b" * 64,
            records=1,
            pending_review=1,
            approved=0,
            applied=0,
            rejected=0,
            expired=0,
            pending_audit_receipts=0,
            terminal_sha256="c" * 64,
            verified=True,
        )

    def status(self):
        self.calls.append(("status",))
        return {"enabled": True, "ready": True}


@pytest.fixture()
def environment(monkeypatch):
    state = SimpleNamespace(enabled=True, service_calls=0, permissions=[])
    service = FakeService()
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(api, "_actor_ref", lambda _request, _tenant: "actor-ref")
    monkeypatch.setattr(
        api,
        "require_permission",
        lambda _request, permission: state.permissions.append(permission),
    )

    def factory(_tenant, _actor, _request):
        state.service_calls += 1
        return service

    dependencies = api.AssessmentEvidenceDependencies(
        service_for=factory,
        enabled_probe=lambda _tenant: state.enabled,
        readiness_probe=lambda _tenant, _request: {
            "schema": "lightwork.assessment-evidence-readiness.v1",
            "enabled": True,
            "configured": True,
            "ready": True,
            "status_probe_opened_store": False,
        },
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="user:operator")
        return await call_next(request)

    app.include_router(
        api.create_assessment_evidence_autopopulation_router(dependencies),
        prefix="/api/v1",
    )
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), state, service


def test_status_is_store_free_and_disabled_is_literal(environment):
    client, state, service = environment
    response = client.get(f"{BASE}/status")
    assert response.status_code == 200
    assert response.json()["ready"] is True
    assert response.json()["status_probe_opened_store"] is False
    assert state.service_calls == 0 and service.calls == []

    state.enabled = False
    disabled = client.get(f"{BASE}/status")
    assert disabled.status_code == 200
    assert disabled.json() == {
        "schema": "lightwork.assessment-evidence-status.v1",
        "enabled": False,
        "configured": False,
        "ready": False,
    }


def test_create_review_and_apply_are_three_separate_routes(environment):
    client, _state, service = environment
    created = client.post(
        f"{BASE}/proposals",
        json={
            "assessment_id": "assessment-one",
            "analysis_ids": ["analysis-one"],
            "idempotency_key": "create-one",
        },
    )
    assert created.status_code == 201
    assert created.json()["status"] == "pending_review"

    reviewed = client.post(
        f"{BASE}/proposals/AEP-proposal/review",
        json={
            "decision": "approve",
            "selected_question_ids": ["pia_security"],
            "rationale": "reviewed citations",
            "expected_revision": 1,
            "idempotency_key": "review-one",
        },
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "approved"

    applied = client.post(
        f"{BASE}/proposals/AEP-proposal/apply",
        json={
            "expected_revision": 2,
            "expected_assessment_revision": 4,
            "idempotency_key": "apply-one",
        },
    )
    assert applied.status_code == 200
    assert applied.json()["status"] == "applied"
    assert [call[0] for call in service.calls] == ["create", "review", "apply"]


def test_list_detail_integrity_purge_permissions_and_error_translation(environment):
    client, state, _service = environment
    assert client.get(f"{BASE}/proposals").json()["count"] == 1
    assert client.get(f"{BASE}/proposals/AEP-proposal").status_code == 200
    missing = client.get(f"{BASE}/proposals/missing")
    assert missing.status_code == 404
    assert client.get(f"{BASE}/integrity").json()["verified"] is True
    purge = client.post(f"{BASE}/maintenance/purge", json={"limit": 10})
    assert purge.json() == {"purged_ids": ["AEP-expired"], "purged": 1}
    assert {"operate", "audit", "admin"}.issubset(set(state.permissions))


def test_schema_rejects_caller_authority_and_malformed_review(environment):
    client, _state, _service = environment
    response = client.post(
        f"{BASE}/proposals",
        json={
            "assessment_id": "assessment-one",
            "analysis_ids": ["analysis-one"],
            "idempotency_key": "create-one",
            "tenant_id": "attacker",
            "actor_ref": "attacker",
        },
    )
    assert response.status_code == 422
    malformed = client.post(
        f"{BASE}/proposals/AEP-proposal/review",
        json={
            "decision": "approve",
            "selected_question_ids": ["NOT ALLOWED"],
            "rationale": "reviewed",
            "expected_revision": 1,
            "idempotency_key": "review-one",
        },
    )
    assert malformed.status_code == 422
