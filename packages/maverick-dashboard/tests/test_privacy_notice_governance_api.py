from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import privacy_notice_governance as notice
from maverick_dashboard import privacy_notice_governance_api as api
from maverick_dashboard import privacy_notice_proposals as proposals

API = "/api/v1/privacy/notices"
NOW = 2_200_000_000.0
SIGNING_SECRET = b"notice-signing-secret-never-persisted-123456789"


class MutableClock:
    def __init__(self, value: float = NOW) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    clock = MutableClock()
    state: dict[str, object] = {
        "enabled": True,
        "tenant": "tenant-a",
        "factory_calls": [],
        "permission_calls": [],
        "clock": clock,
    }
    database = tmp_path / "privacy-notice-governance.sqlite3"

    def require_enabled() -> None:
        if not state["enabled"]:
            raise notice.PrivacyNoticeConfigError("disabled secret detail")

    def tenant_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("tenant", permission))

    def global_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("global", permission))

    monkeypatch.setattr(notice, "require_enabled", require_enabled)
    monkeypatch.setattr(notice, "enabled", lambda: bool(state["enabled"]))
    monkeypatch.setattr(api, "_tenant_id", lambda: str(state["tenant"]))
    monkeypatch.setattr(api, "require_permission", tenant_permission)
    monkeypatch.setattr(api, "require_global_permission", global_permission)

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        if request.headers.get("X-Test-No-Principal") == "1":
            request.state.principal = SimpleNamespace(principal=None, sub=None)
        else:
            subject = request.headers.get("X-Test-Subject", "author")
            request.state.principal = SimpleNamespace(principal=f"user:{subject}")
        return await call_next(request)

    def store_factory(**kwargs):
        calls = state["factory_calls"]
        assert isinstance(calls, list)
        calls.append(kwargs)
        return notice.PrivacyNoticeGovernanceStore(
            database,
            config_gate=lambda: None,
            principal_resolver=kwargs["principal_resolver"],
            signing_key_resolver=lambda _tenant, _ref: SIGNING_SECRET,
            regulatory_reference_resolver=lambda _tenant, document, source, evidence: (
                document.startswith("regdoc:")
                and source.startswith("regsource:")
                and len(evidence) == 64
            ),
            clock=clock,
            token_factory=lambda: "lease:test-token",
        )

    app.state.privacy_notice_governance_store_factory = store_factory
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "author"},
    )
    return client, database, state


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _create_policy(client: TestClient) -> dict:
    response = client.put(
        f"{API}/approval-policies/notice-policy",
        headers={"X-Test-Subject": "policy-admin"},
        json={
            "required_roles": ["privacy", "legal"],
            "quorum": 2,
            "approval_ttl_seconds": 300,
            "expected_revision": 0,
            "idempotency_key": "policy-create",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _create_release(client: TestClient) -> dict:
    response = client.put(
        f"{API}/releases/privacy-main/versions",
        headers={"X-Test-Subject": "author"},
        json={
            "property_id": "property-main",
            "jurisdictions": ["eu", "us-ca"],
            "locales": ["en-US", "fr-FR"],
            "policy_sha256": _digest("policy-v1"),
            "content_sha256": _digest("content-v1"),
            "configuration_sha256": _digest("configuration-v1"),
            "consent_publication_ref": "consent-publication:1",
            "approval_policy_id": "notice-policy",
            "effective_from": NOW,
            "effective_until": NOW + 300,
            "retained_until": NOW + 400,
            "update_proposal_ref": None,
            "expected_latest_version": 0,
            "idempotency_key": "release-create",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_status_is_store_free_honest_exact_gate_and_authenticated(
    environment, monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _database, state = environment
    response = client.get(f"{API}/status")
    assert response.status_code == 200
    status = response.json()
    for boundary in (
        "network_io",
        "provider_writes",
        "legal_advice",
        "maintained_notice_content",
        "sdk_deployment",
        "site_mutation",
        "accessibility_acceptance",
        "legal_acceptance",
        "customer_acceptance",
        "automatic_legal_applicability_inference",
        "automatic_publication",
        "raw_html_persisted",
        "pii_persisted",
        "secret_values_persisted",
        "live_acceptance_verified",
        "status_request_external_network_io",
    ):
        assert status[boundary] is False
    assert status["publication_transport_worker_implemented"] is True
    assert status["publication_runtime_configured"] is False
    assert status["provider_neutral"] is True
    assert status["publication_intents_are_worker_intent_only"] is True
    assert status["regulatory_reference_resolver_required"] is True
    assert status["claim_is_only_live_lease_token_response"] is True
    assert state["factory_calls"] == []

    state["enabled"] = False
    disabled_status = client.get(f"{API}/status")
    assert disabled_status.status_code == 200
    assert disabled_status.json()["enabled"] is False
    blocked = client.get(f"{API}/approval-policies/missing")
    assert blocked.status_code == 403
    assert blocked.json() == {"detail": "privacy-notice governance is disabled"}
    assert "secret" not in blocked.text

    state["enabled"] = True
    monkeypatch.setattr("maverick_dashboard.auth.anonymous_local_access_allowed", lambda: False)
    monkeypatch.setattr("maverick_dashboard.auth._dashboard_token_authenticated", lambda _r: False)
    unauthenticated = client.get(
        f"{API}/status",
        headers={"X-Test-No-Principal": "1"},
    )
    assert unauthenticated.status_code == 401


def test_status_grants_a_synthetic_operator_ref_under_genuine_auth_off(environment) -> None:
    """A missing principal is not ALWAYS a 401: genuine local auth-off mode
    and a valid static dashboard bearer are both already-authenticated
    shapes require_permission() itself accepts."""
    client, _database, _state = environment
    response = client.get(
        f"{API}/status",
        headers={"X-Test-No-Principal": "1"},
    )
    assert response.status_code == 200


def test_publication_runtime_status_and_run_once_are_tenant_derived(
    environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _database, state = environment
    requested: list[str] = []
    client.app.state.privacy_notice_publication_readiness_probe = lambda tenant: {
        "schema": "lightwork.privacy-notice-publication-readiness.v1",
        "tenant_id": tenant,
        "configured": True,
        "configuration_preflight_ready": True,
        "status_opened_tenant_store": False,
    }
    client.app.state.privacy_notice_publication_scheduler_status = lambda: {
        "schema": "lightwork.privacy-notice-publication-scheduler-status.v1",
        "running": True,
        "status_opened_tenant_store": False,
    }
    from maverick_dashboard import privacy_notice_publication_scheduler as scheduler

    def run_once(_app, tenant):
        requested.append(tenant)
        return {
            "tenants_considered": 1,
            "tenants_executed": 1,
            "applied": 1,
            "provider_network_io": False,
        }

    monkeypatch.setattr(scheduler, "run_once_for_tenant", run_once)
    status = client.get(f"{API}/publication-runtime/status")
    assert status.status_code == 200
    assert status.json()["readiness"]["tenant_id"] == "tenant-a"
    assert status.json()["provider_network_io"] is False

    rejected = client.post(
        f"{API}/publication-runtime/run-once",
        json={"tenant_id": "tenant-b", "property_id": "wrong"},
    )
    assert rejected.status_code == 422
    assert requested == []

    executed = client.post(f"{API}/publication-runtime/run-once", json={})
    assert executed.status_code == 200
    assert requested == ["tenant-a"]
    assert executed.json()["request_selected_target"] is False
    assert executed.json()["site_mutation"] is False
    assert ("global", "admin") in state["permission_calls"]


def test_exact_tenant_principal_binding_spoof_rejection_and_generic_not_found(
    environment,
) -> None:
    client, _database, state = environment
    expected_principal = (
        "png-principal-"
        + hashlib.sha256(b"lightwork.privacy-notice.identity.v1:tenant-a:user:author").hexdigest()[
            :32
        ]
    )
    assert client.get(f"{API}/status").json()["principal_ref"] == expected_principal

    _create_policy(client)
    created = _create_release(client)
    assert created["tenant_id"] == "tenant-a"
    assert created["created_by"] == expected_principal
    calls = state["factory_calls"]
    assert isinstance(calls, list) and calls
    assert calls[-1]["tenant_id"] == "tenant-a"
    assert calls[-1]["principal_ref"] == expected_principal
    assert calls[-1]["principal_resolver"]() == expected_principal

    state["tenant"] = "tenant-b"
    hidden = client.get(f"{API}/releases/privacy-main/versions/1")
    assert hidden.status_code == 404
    assert hidden.json() == {"detail": "privacy-notice record was not found"}
    assert "release" not in hidden.json()["detail"]

    state["tenant"] = "tenant-a"
    for field in ("tenant", "tenant_id", "actor", "actor_ref", "principal_ref"):
        spoofed = client.put(
            f"{API}/releases/spoof-{field}/versions",
            json={
                "property_id": "property-main",
                "jurisdictions": ["eu"],
                "locales": ["en-US"],
                "policy_sha256": _digest("p"),
                "content_sha256": _digest("c"),
                "configuration_sha256": _digest("x"),
                "consent_publication_ref": "consent-publication:1",
                "approval_policy_id": "notice-policy",
                "effective_from": NOW,
                "effective_until": NOW + 300,
                "retained_until": NOW + 400,
                "expected_latest_version": 0,
                "idempotency_key": f"spoof-{field}",
                field: "forged",
            },
        )
        assert spoofed.status_code == 422


def test_strict_closed_bodies_reject_content_secrets_and_type_coercion(
    environment,
) -> None:
    client, _database, _state = environment
    _create_policy(client)

    base = {
        "property_id": "property-main",
        "jurisdictions": ["eu"],
        "locales": ["en-US"],
        "policy_sha256": _digest("policy"),
        "content_sha256": _digest("content"),
        "configuration_sha256": _digest("configuration"),
        "consent_publication_ref": "consent-publication:1",
        "approval_policy_id": "notice-policy",
        "effective_from": NOW,
        "effective_until": NOW + 300,
        "retained_until": NOW + 400,
        "expected_latest_version": 0,
        "idempotency_key": "strict-release",
    }
    for field in (
        "notice_content",
        "raw_content",
        "raw_html",
        "personal_data",
        "signing_key_value",
    ):
        response = client.put(
            f"{API}/releases/unsafe-{field}/versions",
            json={**base, field: "sensitive value"},
        )
        assert response.status_code == 422
        assert response.json() == {"detail": "privacy-notice request is invalid"}
        assert "sensitive value" not in response.text

    unsafe_ref = client.put(
        f"{API}/releases/unsafe-ref/versions",
        json={**base, "consent_publication_ref": "<p>notice text</p>"},
    )
    assert unsafe_ref.status_code == 422
    assert unsafe_ref.json() == {"detail": "privacy-notice request is invalid"}
    assert "notice text" not in unsafe_ref.text
    wrong_type = client.put(
        f"{API}/releases/string-version/versions",
        json={**base, "expected_latest_version": "0"},
    )
    assert wrong_type.status_code == 422
    literal_key = client.put(
        f"{API}/releases/privacy-main/exports/export-a",
        json={
            "signing_key_ref": "literal-secret-value",
            "retained_until": NOW + 300,
            "idempotency_key": "bad-export",
        },
    )
    assert literal_key.status_code == 422
    assert "literal-secret-value" not in literal_key.text
    extra_key = client.put(
        f"{API}/releases/privacy-main/exports/export-b",
        json={
            "signing_key_ref": "vault:notice-key",
            "signing_key": "literal-secret-value",
            "retained_until": NOW + 300,
            "idempotency_key": "bad-export-field",
        },
    )
    assert extra_key.status_code == 422


def test_four_eyes_publication_intent_recovery_effective_export_and_integrity(
    environment,
) -> None:
    client, database, state = environment
    _create_policy(client)
    release = _create_release(client)
    submitted = client.post(
        f"{API}/releases/privacy-main/versions/1/submit",
        headers={"X-Test-Subject": "author"},
        json={
            "expected_revision": release["state_revision"],
            "idempotency_key": "submit-review",
        },
    )
    assert submitted.status_code == 200, submitted.text

    self_approval = client.post(
        f"{API}/releases/privacy-main/versions/1/approvals",
        headers={"X-Test-Subject": "author"},
        json={
            "role": "privacy",
            "expected_release_sha256": release["definition_sha256"],
            "expected_revision": submitted.json()["state_revision"],
            "idempotency_key": "self-approval",
        },
    )
    assert self_approval.status_code == 403
    assert self_approval.json() == {"detail": "privacy-notice operation is not permitted"}
    assert "author" not in self_approval.text

    privacy_approval = client.post(
        f"{API}/releases/privacy-main/versions/1/approvals",
        headers={"X-Test-Subject": "privacy-approver"},
        json={
            "role": "privacy",
            "expected_release_sha256": release["definition_sha256"],
            "expected_revision": submitted.json()["state_revision"],
            "idempotency_key": "privacy-approval",
        },
    )
    assert privacy_approval.status_code == 200, privacy_approval.text
    inflated = client.post(
        f"{API}/releases/privacy-main/versions/1/approvals",
        headers={"X-Test-Subject": "privacy-approver"},
        json={
            "role": "legal",
            "expected_release_sha256": release["definition_sha256"],
            "expected_revision": privacy_approval.json()["state_revision"],
            "idempotency_key": "approval-inflation",
        },
    )
    assert inflated.status_code == 403

    approved = client.post(
        f"{API}/releases/privacy-main/versions/1/approvals",
        headers={"X-Test-Subject": "legal-approver"},
        json={
            "role": "legal",
            "expected_release_sha256": release["definition_sha256"],
            "expected_revision": privacy_approval.json()["state_revision"],
            "idempotency_key": "legal-approval",
        },
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["state"] == "approved"

    scheduled = client.post(
        f"{API}/releases/privacy-main/versions/1/schedule",
        headers={"X-Test-Subject": "scheduler"},
        json={
            "activate_at": NOW + 1,
            "expected_release_sha256": release["definition_sha256"],
            "max_attempts": 3,
            "expected_revision": approved.json()["state_revision"],
            "idempotency_key": "schedule-release",
        },
    )
    assert scheduled.status_code == 200, scheduled.text
    clock = state["clock"]
    assert isinstance(clock, MutableClock)
    clock.advance(1)

    claimed = client.post(
        f"{API}/publication-intents/claim",
        headers={"X-Test-Subject": "publication-worker"},
        json={"limit": 1, "lease_seconds": 30},
    )
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["count"] == 1
    intent = claimed.json()["items"][0]
    lease_token = intent["lease_token"]
    assert lease_token == "lease:test-token"

    failed = client.post(
        f"{API}/publication-intents/{intent['intent_id']}/fail",
        headers={"X-Test-Subject": "publication-worker"},
        json={
            "lease_token": lease_token,
            "error_code": "adapter_unavailable",
            "retry_delay_seconds": 0,
            "expected_revision": intent["revision"],
            "idempotency_key": "fail-publication",
        },
    )
    assert failed.status_code == 200, failed.text
    assert "lease_token" not in failed.json()
    assert lease_token not in failed.text

    reclaimed = client.post(
        f"{API}/publication-intents/claim",
        headers={"X-Test-Subject": "publication-worker"},
        json={"limit": 1, "lease_seconds": 30},
    )
    assert reclaimed.status_code == 200, reclaimed.text
    final_intent = reclaimed.json()["items"][0]
    acknowledged = client.post(
        f"{API}/publication-intents/{final_intent['intent_id']}/acknowledge",
        headers={"X-Test-Subject": "publication-worker"},
        json={
            "lease_token": final_intent["lease_token"],
            "acknowledgement_sha256": _digest("publication receipt"),
            "acknowledgement_ref": "publication-ack:final",
            "expected_revision": final_intent["revision"],
            "idempotency_key": "acknowledge-publication",
        },
    )
    assert acknowledged.status_code == 200, acknowledged.text
    assert acknowledged.json()["state"] == "acked"
    assert "lease_token" not in acknowledged.json()

    effective = client.get(
        f"{API}/effective/property-main",
        params={"jurisdiction": "eu", "locale": "en-US"},
        headers={"X-Test-Subject": "viewer"},
    )
    assert effective.status_code == 200, effective.text
    assert effective.json()["version"] == 1
    assert effective.json()["state"] == "published"

    exported = client.put(
        f"{API}/releases/privacy-main/exports/export-a",
        headers={"X-Test-Subject": "export-operator"},
        json={
            "signing_key_ref": "vault:notice-key-v1",
            "retained_until": NOW + 200,
            "idempotency_key": "export-notice",
        },
    )
    assert exported.status_code == 200, exported.text
    assert "lease_token" not in exported.text
    assert "lease:test-token" not in exported.text
    assert SIGNING_SECRET.decode() not in exported.text
    fetched = client.get(
        f"{API}/exports/export-a",
        headers={"X-Test-Subject": "auditor"},
    )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json() == exported.json()

    integrity = client.get(
        f"{API}/integrity",
        headers={"X-Test-Subject": "auditor"},
    )
    assert integrity.status_code == 200, integrity.text
    assert integrity.json()["valid"] is True
    purge = client.post(
        f"{API}/retention/purge",
        headers={"X-Test-Subject": "retention-admin"},
        json={"cutoff": NOW, "idempotency_key": "purge-current"},
    )
    assert purge.status_code == 200, purge.text
    assert purge.json() == {"exports": 0, "proposals": 0, "releases": 0}

    persisted = database.read_bytes()
    wal = Path(f"{database}-wal")
    if wal.exists():
        persisted += wal.read_bytes()
    assert SIGNING_SECRET not in persisted
    assert b"publication receipt" not in persisted
    assert b"<p>notice text</p>" not in persisted
    calls = state["permission_calls"]
    assert isinstance(calls, list)
    assert ("global", "admin") in calls
    assert ("global", "audit") in calls
    assert ("tenant", "operate") in calls
    assert ("tenant", "view") in calls


class _ResearchCorpus:
    """Stands in for the installed regulatory research store (its own lock only)."""

    def _connect(self):
        return sqlite3.connect(":memory:")

    def _begin(self, connection) -> None:
        connection.execute("BEGIN IMMEDIATE")


def _approved_reference(_tenant, document, source, evidence) -> bool:
    return document.startswith("regdoc:") and source.startswith("regsource:") and len(evidence) == 64


@pytest.fixture()
def proposal_sources(environment, monkeypatch: pytest.MonkeyPatch):
    """The proposal save checks the current consent publication and approved
    research references through the installed stores; stand those in, with
    the same permission recorder and the same approved-reference rule."""
    _client, _database, state = environment

    def permission(_request, value):
        state["permission_calls"].append(("tenant", value))

    monkeypatch.setattr(proposals.auth, "require_permission", permission)
    monkeypatch.setattr(proposals, "context_for", lambda _request: "context-a")
    monkeypatch.setattr(proposals, "corpus", lambda _tenant: _ResearchCorpus())
    monkeypatch.setattr(proposals.regulatory, "_ops", lambda: None)
    monkeypatch.setattr(proposals.consent, "_ops", lambda: None)
    monkeypatch.setattr(proposals.consent, "_store", lambda _ops, _tenant: _ResearchCorpus())
    monkeypatch.setattr(proposals, "publications", lambda _tenant, _store: [
        {"property_id": "property-main", "publication_id": "consent-publication:2"}])
    monkeypatch.setattr(proposals, "reference_allowed", _approved_reference)
    return environment


def test_update_proposal_requires_independent_review_and_approved_citations(
    proposal_sources,
) -> None:
    client, _database, _state = proposal_sources
    _create_policy(client)
    _create_release(client)
    created = client.put(
        f"{API}/update-proposals/proposal-2",
        headers={"X-Test-Subject": "proposal-author"},
        json={
            "notice_id": "privacy-main",
            "base_version": 1,
            "policy_sha256": _digest("policy-v2"),
            "content_sha256": _digest("content-v2"),
            "configuration_sha256": _digest("configuration-v2"),
            "consent_publication_ref": "consent-publication:2",
            "regulatory_citations": [
                {
                    "document_ref": "regdoc:approved-1",
                    "source_ref": "regsource:authority-1",
                    "evidence_sha256": _digest("approved regulatory evidence"),
                }
            ],
            "reason_codes": ["regulatory_change_review"],
            "retained_until": NOW + 200,
            "idempotency_key": "proposal-create",
        },
    )
    assert created.status_code == 200, created.text
    assert created.json()["status"] == "pending_review"
    fetched = client.get(
        f"{API}/update-proposals/proposal-2",
        headers={"X-Test-Subject": "viewer"},
    )
    assert fetched.status_code == 200
    assert fetched.json() == created.json()

    self_review = client.post(
        f"{API}/update-proposals/proposal-2/review",
        headers={"X-Test-Subject": "proposal-author"},
        json={
            "decision": "approved",
            "expected_revision": created.json()["revision"],
            "idempotency_key": "proposal-self-review",
        },
    )
    assert self_review.status_code == 403
    assert self_review.json() == {"detail": "privacy-notice operation is not permitted"}
    reviewed = client.post(
        f"{API}/update-proposals/proposal-2/review",
        headers={"X-Test-Subject": "proposal-reviewer"},
        json={
            "decision": "approved",
            "expected_revision": created.json()["revision"],
            "idempotency_key": "proposal-review",
        },
    )
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["status"] == "approved"


def test_all_core_operations_are_mounted_and_adapter_has_no_network_client(
    environment,
) -> None:
    client, _database, _state = environment
    paths = set(client.app.openapi()["paths"])
    expected = {
        f"{API}/status",
        f"{API}/approval-policies/{{policy_id}}",
        f"{API}/releases/{{notice_id}}/versions",
        f"{API}/releases/{{notice_id}}/versions/{{version}}",
        f"{API}/releases/{{notice_id}}/versions/{{version}}/submit",
        f"{API}/releases/{{notice_id}}/versions/{{version}}/approvals",
        f"{API}/releases/{{notice_id}}/versions/{{version}}/approvals/{{role}}/revoke",
        f"{API}/releases/{{notice_id}}/versions/{{version}}/schedule",
        f"{API}/publication-intents/claim",
        f"{API}/publication-intents/{{intent_id}}/fail",
        f"{API}/publication-intents/{{intent_id}}/requeue",
        f"{API}/publication-intents/{{intent_id}}/acknowledge",
        f"{API}/releases/{{notice_id}}/versions/{{version}}/rollback",
        f"{API}/releases/{{notice_id}}/versions/{{version}}/withdraw",
        f"{API}/effective/{{property_id}}",
        f"{API}/update-proposals/{{proposal_id}}",
        f"{API}/update-proposals/{{proposal_id}}/review",
        f"{API}/releases/{{notice_id}}/exports/{{export_id}}",
        f"{API}/exports/{{export_id}}",
        f"{API}/retention/purge",
        f"{API}/integrity",
    }
    assert expected <= paths

    # A proposal is saved through the reviewed proposal module, under its
    # current-source fence; every other operation reaches the store here.
    source = Path(api.__file__).read_text(encoding="utf-8") + Path(proposals.__file__).read_text(encoding="utf-8")
    for method in (
        "set_approval_policy",
        "get_approval_policy",
        "create_release",
        "get_release",
        "submit_for_review",
        "approve_release",
        "revoke_approval",
        "schedule_release",
        "claim_publication_intents",
        "fail_publication_intent",
        "requeue_publication_intent",
        "ack_publication_intent",
        "rollback_release",
        "withdraw_release",
        "current_effective_release",
        "create_update_proposal",
        "review_update_proposal",
        "get_update_proposal",
        "export_notice",
        "get_export",
        "purge_expired",
        "verify_integrity",
    ):
        assert f"store.{method}" in source
    for primitive in ("requests.", "httpx.", "urllib.request", "socket."):
        assert primitive not in source


def test_records_list_rules_versions_and_approvals_per_workspace(environment) -> None:
    client = environment[0] if isinstance(environment, tuple) else environment
    empty = client.get(f"{API}/records")
    assert empty.status_code == 200, empty.text
    assert empty.json()["releases"] == [] and empty.json()["queue"] == {}
    _create_policy(client)
    created = _create_release(client)
    listed = client.get(f"{API}/records").json()
    assert [p["policy_id"] for p in listed["policies"]] == ["notice-policy"]
    release = listed["releases"][0]
    assert release["notice_id"] == "privacy-main" and release["state"] == "draft"
    assert release["release_sha256"] == created["definition_sha256"]
    assert release["revision"] == created["state_revision"]
    assert "lease_token" not in client.get(f"{API}/records").text
    record = client.post(
        f"{API}/releases/privacy-main/record",
        json={"retained_until": NOW + 100, "idempotency_key": "record-1"},
    )
    assert record.status_code == 200, record.text
    assert record.json()["signing_key_ref"] == api.DEFAULT_NOTICE_SIGNING_KEY_REF
    assert client.get(f"{API}/records").json()["records"][0]["notice_id"] == "privacy-main"
