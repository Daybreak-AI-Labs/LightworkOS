from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import compliance_scoping as scoping
from maverick_dashboard import compliance_scoping_api as api

API = "/api/v1/compliance/scoping"
NOW = 2_100_000_000.0
SIGNING_SECRET = b"scope-signing-secret-value-never-persisted-123456"


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state: dict[str, object] = {
        "enabled": True,
        "tenant": "tenant-a",
        "factory_calls": [],
        "permission_calls": [],
    }
    database = tmp_path / "compliance-scoping.sqlite3"

    def require_enabled() -> None:
        if not state["enabled"]:
            raise scoping.ComplianceScopingConfigError("disabled for test")

    def tenant_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("tenant", permission))

    def global_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("global", permission))

    monkeypatch.setattr(scoping, "require_enabled", require_enabled)
    monkeypatch.setattr(scoping, "enabled", lambda: bool(state["enabled"]))
    monkeypatch.setattr(api, "_tenant_id", lambda: str(state["tenant"]))
    monkeypatch.setattr(api, "require_permission", tenant_permission)
    monkeypatch.setattr(api, "require_global_permission", global_permission)

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        subject = request.headers.get("X-Test-Subject", "author")
        request.state.principal = SimpleNamespace(principal=f"user:{subject}")
        return await call_next(request)

    def store_factory(**kwargs):
        calls = state["factory_calls"]
        assert isinstance(calls, list)
        calls.append(kwargs)
        return scoping.ComplianceScopingStore(
            database,
            config_gate=lambda: None,
            principal_resolver=kwargs["principal_resolver"],
            signing_key_resolver=lambda _tenant, _ref: SIGNING_SECRET,
            clock=lambda: NOW,
        )

    app.state.compliance_scoping_store_factory = store_factory
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "author"},
    )
    return client, database, state


def _questions() -> list[dict[str, object]]:
    return [
        {
            "question_id": "q_org_size",
            "question_ref": "ref:question-org-size",
            "domain": "organization",
            "answer_type": "integer",
            "options": [],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_industry",
            "question_ref": "ref:question-industry",
            "domain": "industry",
            "answer_type": "single_choice",
            "options": ["finance", "software"],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_jurisdiction",
            "question_ref": "ref:question-jurisdiction",
            "domain": "jurisdiction",
            "answer_type": "multi_choice",
            "options": ["eu", "us"],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_data",
            "question_ref": "ref:question-data",
            "domain": "data",
            "answer_type": "single_choice",
            "options": ["none", "personal", "regulated"],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_system",
            "question_ref": "ref:question-system",
            "domain": "system",
            "answer_type": "boolean",
            "options": [],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_vendor",
            "question_ref": "ref:question-vendor",
            "domain": "vendor",
            "answer_type": "boolean",
            "options": [],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_ai",
            "question_ref": "ref:question-ai",
            "domain": "ai",
            "answer_type": "boolean",
            "options": [],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_ai_model",
            "question_ref": "ref:question-ai-model",
            "domain": "ai",
            "answer_type": "opaque_ref",
            "options": [],
            "required": True,
            "condition": {
                "question_id": "q_ai",
                "operator": "equals",
                "value": True,
            },
        },
        {
            "question_id": "q_operational",
            "question_ref": "ref:question-operational",
            "domain": "operational",
            "answer_type": "single_choice",
            "options": ["critical", "standard"],
            "required": True,
            "condition": None,
        },
    ]


def _rules() -> list[dict[str, object]]:
    return [
        {
            "rule_id": "rule_baseline",
            "conditions": [],
            "framework_ref": "framework-baseline",
            "control_refs": ["control-inventory"],
            "overlap_refs": ["overlap-asset-register"],
            "reason_code": "baseline_scope",
        },
        {
            "rule_id": "rule_eu",
            "conditions": [
                {
                    "question_id": "q_jurisdiction",
                    "operator": "contains",
                    "value": "eu",
                }
            ],
            "framework_ref": "framework-eu-privacy",
            "control_refs": ["control-data-rights"],
            "overlap_refs": ["overlap-privacy-program"],
            "reason_code": "eu_operations",
        },
    ]


def _questionnaire_body() -> dict[str, object]:
    return {
        "questions": _questions(),
        "rules": _rules(),
        "expected_latest_version": 0,
        "idempotency_key": "questionnaire-create",
    }


def _create_and_publish(client: TestClient) -> dict:
    created = client.put(
        f"{API}/questionnaires/scope-v1/versions",
        headers={"X-Test-Subject": "author"},
        json=_questionnaire_body(),
    )
    assert created.status_code == 200, created.text
    published = client.post(
        f"{API}/questionnaires/scope-v1/versions/1/publish",
        headers={"X-Test-Subject": "reviewer"},
        json={
            "expected_revision": created.json()["revision"],
            "idempotency_key": "questionnaire-publish",
        },
    )
    assert published.status_code == 200, published.text
    return published.json()


def _create_assessment(client: TestClient) -> dict:
    response = client.put(
        f"{API}/assessments/assessment-a",
        headers={"X-Test-Subject": "operator"},
        json={
            "questionnaire_id": "scope-v1",
            "questionnaire_version": 1,
            "retained_until": NOW + 600,
            "idempotency_key": "assessment-create",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _answer_all(client: TestClient, assessment: dict) -> dict:
    values: dict[str, object] = {
        "q_org_size": 250,
        "q_industry": "finance",
        "q_jurisdiction": ["eu", "us"],
        "q_data": "regulated",
        "q_system": True,
        "q_vendor": True,
        "q_ai": True,
        "q_ai_model": "ref:model-catalog-entry",
        "q_operational": "critical",
    }
    current = assessment
    for index, (question_id, value) in enumerate(values.items(), start=1):
        evidence_digest = hashlib.sha256(f"private evidence {question_id}".encode()).hexdigest()
        response = client.post(
            f"{API}/assessments/assessment-a/responses/{question_id}",
            headers={"X-Test-Subject": "operator"},
            json={
                "value": value,
                "evidence_sha256": evidence_digest,
                "evidence_ref": f"evidence:receipt-{question_id}",
                "expected_revision": current["revision"],
                "idempotency_key": f"response-{index}",
            },
        )
        assert response.status_code == 200, response.text
        current = response.json()
    return current


def test_status_is_store_free_honest_and_gate_off_is_403(environment) -> None:
    client, _database, state = environment
    response = client.get(f"{API}/status")
    assert response.status_code == 200
    status = response.json()
    for boundary in (
        "licensed_framework_text_included",
        "legal_advice",
        "automatic_external_discovery",
        "certification",
        "live_provider_acceptance_verified",
        "free_text_evidence_persisted",
        "secret_values_persisted",
        "network_io",
        "provider_writes",
        "external_discovery_performed",
        "certification_performed",
        "live_acceptance_verified",
        "live_customer_acceptance_verified",
        "status_request_external_network_io",
    ):
        assert status[boundary] is False
    assert status["signing_input_is_reference_only"] is True
    assert state["factory_calls"] == []

    state["enabled"] = False
    assert client.get(f"{API}/status").json()["enabled"] is False
    assert client.get(f"{API}/assessments/missing").status_code == 403


def test_exact_tenant_principal_binding_and_identity_spoof_rejection(environment) -> None:
    client, _database, state = environment
    expected_principal = (
        "cs-principal-"
        + hashlib.sha256(
            b"lightwork.compliance-scoping.identity.v1:tenant-a:user:author"
        ).hexdigest()[:32]
    )
    assert client.get(f"{API}/status").json()["principal_ref"] == expected_principal

    created = client.put(
        f"{API}/questionnaires/scope-v1/versions",
        json=_questionnaire_body(),
    )
    assert created.status_code == 200, created.text
    assert created.json()["tenant_id"] == "tenant-a"
    assert created.json()["created_by"] == expected_principal
    calls = state["factory_calls"]
    assert isinstance(calls, list) and calls
    assert calls[-1]["tenant_id"] == "tenant-a"
    assert calls[-1]["principal_ref"] == expected_principal
    assert calls[-1]["principal_resolver"]() == expected_principal

    state["tenant"] = "tenant-b"
    assert client.get(f"{API}/questionnaires/scope-v1/versions/1").status_code == 404

    for field in ("tenant", "tenant_id", "actor", "actor_ref"):
        spoofed = client.put(
            f"{API}/questionnaires/spoof-{field}/versions",
            json={**_questionnaire_body(), field: "forged"},
        )
        assert spoofed.status_code == 422


def test_strict_closed_bodies_reject_raw_text_secrets_and_type_coercion(
    environment,
) -> None:
    client, _database, _state = environment
    nested_text = _questionnaire_body()
    nested_text["questions"][0]["question_text"] = "licensed framework prose"
    assert (
        client.put(f"{API}/questionnaires/raw-question/versions", json=nested_text).status_code
        == 422
    )

    unsupported = _questionnaire_body()
    unsupported["questions"][0]["domain"] = "finance"
    assert (
        client.put(f"{API}/questionnaires/unsupported/versions", json=unsupported).status_code
        == 422
    )
    wrong_type = {
        **_questionnaire_body(),
        "expected_latest_version": "0",
    }
    assert (
        client.put(f"{API}/questionnaires/string-version/versions", json=wrong_type).status_code
        == 422
    )
    raw_evidence = client.post(
        f"{API}/assessments/assessment-a/responses/q_data",
        json={
            "value": "regulated",
            "evidence_sha256": "a" * 64,
            "evidence_ref": "evidence:receipt",
            "raw_evidence": "customer secret document",
            "expected_revision": 1,
            "idempotency_key": "raw-evidence",
        },
    )
    assert raw_evidence.status_code == 422
    secret_value = client.put(
        f"{API}/scopes/scope-a/exports/export-a",
        json={
            "signing_key_ref": "literal-key-value",
            "retained_until": NOW + 120,
            "idempotency_key": "bad-key",
        },
    )
    assert secret_value.status_code == 422
    secret_field = client.put(
        f"{API}/scopes/scope-a/exports/export-a",
        json={
            "signing_key_ref": "vault:scope-key",
            "signing_key": "literal-key-value",
            "retained_until": NOW + 120,
            "idempotency_key": "bad-key-field",
        },
    )
    assert secret_field.status_code == 422


def test_required_traversal_four_eyes_projections_and_signed_export(environment) -> None:
    client, database, state = environment
    created = client.put(
        f"{API}/questionnaires/scope-v1/versions",
        headers={"X-Test-Subject": "author"},
        json=_questionnaire_body(),
    )
    assert created.status_code == 200, created.text
    self_publish = client.post(
        f"{API}/questionnaires/scope-v1/versions/1/publish",
        headers={"X-Test-Subject": "author"},
        json={
            "expected_revision": created.json()["revision"],
            "idempotency_key": "self-publish",
        },
    )
    assert self_publish.status_code == 403
    published = client.post(
        f"{API}/questionnaires/scope-v1/versions/1/publish",
        headers={"X-Test-Subject": "reviewer"},
        json={
            "expected_revision": created.json()["revision"],
            "idempotency_key": "publish",
        },
    )
    assert published.status_code == 200, published.text

    assessment = _create_assessment(client)
    required = client.get(
        f"{API}/assessments/assessment-a/required-questions",
        headers={"X-Test-Subject": "operator"},
    )
    assert required.status_code == 200, required.text
    assert required.json()["count"] == 8
    answered = _answer_all(client, assessment)
    assert answered["revision"] == 10
    assert (
        client.get(
            f"{API}/assessments/assessment-a/required-questions",
            headers={"X-Test-Subject": "operator"},
        ).json()["count"]
        == 0
    )

    computed = client.put(
        f"{API}/assessments/assessment-a/scopes/scope-a",
        headers={"X-Test-Subject": "operator"},
        json={
            "responsibility_assignments": {
                "first_line": "ref:business-owner",
                "second_line": "ref:risk-owner",
                "control_owner": "ref:control-owner",
                "evidence_owner": "ref:evidence-owner",
            },
            "expected_assessment_revision": answered["revision"],
            "idempotency_key": "compute",
        },
    )
    assert computed.status_code == 200, computed.text
    scope = computed.json()
    assert scope["overlaps"] == scope["crosswalks"]
    assert scope["responsibility_assignments"]["first_line"] == "ref:business-owner"

    self_approve = client.post(
        f"{API}/scopes/scope-a/approve",
        headers={"X-Test-Subject": "operator"},
        json={
            "expected_revision": scope["revision"],
            "idempotency_key": "self-approve",
        },
    )
    assert self_approve.status_code == 403
    approved = client.post(
        f"{API}/scopes/scope-a/approve",
        headers={"X-Test-Subject": "approver"},
        json={
            "expected_revision": scope["revision"],
            "idempotency_key": "approve",
        },
    )
    assert approved.status_code == 200, approved.text
    wrong_finalizer = client.post(
        f"{API}/scopes/scope-a/finalize",
        headers={"X-Test-Subject": "approver"},
        json={
            "expected_revision": approved.json()["revision"],
            "idempotency_key": "wrong-finalizer",
        },
    )
    assert wrong_finalizer.status_code == 403
    finalized = client.post(
        f"{API}/scopes/scope-a/finalize",
        headers={"X-Test-Subject": "operator"},
        json={
            "expected_revision": approved.json()["revision"],
            "idempotency_key": "finalize",
        },
    )
    assert finalized.status_code == 200, finalized.text
    assert finalized.json()["status"] == "finalized"

    for projection in ("overlaps", "crosswalks", "responsibilities"):
        response = client.get(
            f"{API}/scopes/scope-a/{projection}",
            headers={"X-Test-Subject": "auditor"},
        )
        assert response.status_code == 200, response.text
    exported = client.put(
        f"{API}/scopes/scope-a/exports/export-a",
        headers={"X-Test-Subject": "operator"},
        json={
            "signing_key_ref": "vault:scope-signing-key-v1",
            "retained_until": NOW + 300,
            "idempotency_key": "export",
        },
    )
    assert exported.status_code == 200, exported.text
    assert exported.json()["signing_key_ref"] == "vault:scope-signing-key-v1"
    assert exported.json()["signature_hmac_sha256"]
    assert SIGNING_SECRET.decode() not in exported.text
    fetched = client.get(f"{API}/exports/export-a", headers={"X-Test-Subject": "auditor"})
    assert fetched.status_code == 200, fetched.text
    assert fetched.json() == exported.json()
    integrity = client.get(f"{API}/integrity", headers={"X-Test-Subject": "auditor"})
    assert integrity.status_code == 200, integrity.text
    assert integrity.json()["valid"] is True
    purge = client.post(
        f"{API}/retention/purge",
        headers={"X-Test-Subject": "retention-admin"},
        json={"cutoff": NOW, "idempotency_key": "purge"},
    )
    assert purge.status_code == 200, purge.text
    assert purge.json() == {"exports": 0, "assessments": 0}

    persisted = database.read_bytes()
    wal = Path(f"{database}-wal")
    if wal.exists():
        persisted += wal.read_bytes()
    assert SIGNING_SECRET not in persisted
    assert b"private evidence q_data" not in persisted
    calls = state["permission_calls"]
    assert isinstance(calls, list)
    assert ("global", "admin") in calls
    assert ("global", "audit") in calls
    assert calls.count(("tenant", "operate")) >= 4


def test_all_core_operations_are_mounted_and_adapter_has_no_network_client(
    environment,
) -> None:
    client, _database, _state = environment
    paths = set(client.app.openapi()["paths"])
    expected = {
        f"{API}/questionnaires/{{questionnaire_id}}/versions",
        f"{API}/questionnaires/{{questionnaire_id}}/versions/{{version}}",
        f"{API}/questionnaires/{{questionnaire_id}}/versions/{{version}}/publish",
        f"{API}/assessments/{{assessment_id}}",
        f"{API}/assessments/{{assessment_id}}/required-questions",
        f"{API}/assessments/{{assessment_id}}/responses/{{question_id}}",
        f"{API}/assessments/{{assessment_id}}/scopes/{{scope_id}}",
        f"{API}/scopes/{{scope_id}}",
        f"{API}/scopes/{{scope_id}}/overlaps",
        f"{API}/scopes/{{scope_id}}/crosswalks",
        f"{API}/scopes/{{scope_id}}/responsibilities",
        f"{API}/scopes/{{scope_id}}/approve",
        f"{API}/scopes/{{scope_id}}/finalize",
        f"{API}/scopes/{{scope_id}}/exports/{{export_id}}",
        f"{API}/exports/{{export_id}}",
        f"{API}/retention/purge",
        f"{API}/integrity",
    }
    assert expected <= paths
    source = Path(api.__file__).read_text(encoding="utf-8")
    for primitive in ("requests.", "httpx.", "urllib.request", "socket."):
        assert primitive not in source


def test_records_list_every_kind_for_the_workspace_and_report_uses_the_default_key(
    environment,
) -> None:
    client, _database, state = environment
    empty = client.get(f"{API}/records")
    assert empty.status_code == 200
    assert empty.json() == {"questionnaires": [], "assessments": [], "scopes": [], "reports": []}
    _create_and_publish(client)
    assessment = _answer_all(client, _create_assessment(client))
    computed = client.put(
        f"{API}/assessments/assessment-a/scopes/scope-a",
        headers={"X-Test-Subject": "operator"},
        json={
            "responsibility_assignments": {
                "first_line": "ref:business-owner",
                "second_line": "ref:risk-owner",
                "control_owner": "ref:control-owner",
                "evidence_owner": "ref:evidence-owner",
            },
            "expected_assessment_revision": assessment["revision"],
            "idempotency_key": "compute",
        },
    ).json()
    listed = client.get(f"{API}/records").json()
    assert [q["status"] for q in listed["questionnaires"]] == ["published"]
    assert listed["assessments"][0]["assessment_id"] == "assessment-a"
    assert listed["assessments"][0]["answered"] == 9
    assert listed["scopes"][0]["scope_id"] == "scope-a"
    assert listed["scopes"][0]["revision"] == computed["revision"]
    assert ("tenant", "view") in state["permission_calls"]

    approved = client.post(
        f"{API}/scopes/scope-a/approve",
        headers={"X-Test-Subject": "approver"},
        json={"expected_revision": computed["revision"], "idempotency_key": "approve"},
    ).json()
    client.post(
        f"{API}/scopes/scope-a/finalize",
        headers={"X-Test-Subject": "operator"},
        json={"expected_revision": approved["revision"], "idempotency_key": "finalize"},
    )
    report = client.post(
        f"{API}/scopes/scope-a/report",
        headers={"X-Test-Subject": "operator"},
        json={"idempotency_key": "report-1"},
    )
    assert report.status_code == 200, report.text
    assert report.json()["signing_key_ref"] == api.DEFAULT_REPORT_SIGNING_KEY_REF
    assert client.get(f"{API}/records").json()["reports"][0]["scope_id"] == "scope-a"

    state["tenant"] = "tenant-b"
    assert client.get(f"{API}/records").json()["scopes"] == []
