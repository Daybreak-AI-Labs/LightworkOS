from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import privacy_regulatory_intelligence as intelligence
from maverick_dashboard import privacy_regulatory_intelligence_api as api

API = "/api/v1/privacy/regulatory-intelligence"


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from maverick import mailer

    database = tmp_path / "privacy-intelligence.sqlite3"
    store = intelligence.PrivacyRegulatoryIntelligenceStore(
        database,
        config_gate=lambda: None,
    )
    monkeypatch.setattr(intelligence, "require_enabled", lambda: None)
    monkeypatch.setattr(mailer, "configured", lambda: False)
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(
        api,
        "require_global_permission",
        lambda _request, _permission: None,
    )
    dependencies = api.PrivacyIntelligenceDependencies(store_for=lambda _tenant: store)
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(
            sub=request.headers.get("X-Test-Subject", "research-admin")
        )
        return await call_next(request)

    app.include_router(
        api.create_privacy_intelligence_router(dependencies),
        prefix="/api/v1",
    )
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "research-admin"},
    )
    return client, store, monkeypatch


def _source() -> dict[str, object]:
    return {
        "name": "Primary law corpus",
        "license_ref": "tenant-license-2026",
        "rights_basis": "Tenant may use retained official text for internal research.",
        "allowed_uses": ["search", "research", "compare", "alerts", "reports"],
        "provenance_uri": "https://authority.example/official",
        "jurisdictions": ["US-CA", "EU"],
        "authorities": ["CA-AG", "EU-DPA"],
        "document_types": ["law", "regulation", "authority_guidance"],
        "languages": ["en"],
        "retention_seconds": 86_400,
        "expected_revision": 0,
        "idempotency_key": "enroll-primary-law-v1",
    }


def _document() -> dict[str, object]:
    content = (
        "A consumer may submit a verified access request. The business must "
        "respond within the timing established by the governing law."
    )
    return {
        "source_id": "primary-law",
        "title": "California access timing",
        "jurisdiction": "US-CA",
        "authority": "CA-AG",
        "document_type": "law",
        "language": "en",
        "publication_date": "2026-08-01",
        "effective_date": "2026-08-15",
        "superseded_date": None,
        "citations": [
            {
                "citation_id": "official-section-1",
                "title": "Official Section 1",
                "uri": "https://authority.example/official/section-1",
                "pinpoint": "Section 1",
            }
        ],
        "content": content,
        "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
        "expected_latest_version": 0,
        "idempotency_key": "ingest-access-law-v1",
    }


def test_full_grounded_flow_and_stable_four_eyes_identity(environment) -> None:
    client, _store, _monkeypatch = environment
    enrolled = client.put(f"{API}/sources/primary-law", json=_source())
    assert enrolled.status_code == 200, enrolled.text

    review = {
        "expected_revision": 1,
        "rationale": "License and provenance checked against tenant rights.",
        "approved": True,
        "idempotency_key": "approve-primary-law-v1",
    }
    same_caller = client.post(f"{API}/sources/primary-law/review", json=review)
    assert same_caller.status_code == 403

    approved = client.post(
        f"{API}/sources/primary-law/review",
        json=review,
        headers={"X-Test-Subject": "privacy-counsel"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["state"] == "active"

    ingested = client.put(f"{API}/documents/access-law", json=_document())
    assert ingested.status_code == 200, ingested.text
    assert "content" not in ingested.json()

    researched = client.post(
        f"{API}/research",
        json={
            "query": "verified access request timing",
            "jurisdictions": ["US-CA"],
            "minimum_evidence": 1,
            "limit": 10,
            "as_of": None,
        },
    )
    assert researched.status_code == 200, researched.text
    body = researched.json()
    assert body["abstained"] is False
    assert body["citations"]
    assert body["legal_advice"] is False

    no_evidence = client.post(
        f"{API}/research",
        json={
            "query": "biometric employment surveillance",
            "jurisdictions": ["EU"],
            "minimum_evidence": 1,
            "limit": 10,
            "as_of": None,
        },
    )
    assert no_evidence.status_code == 200, no_evidence.text
    assert no_evidence.json()["abstained"] is True


def test_strict_contract_tenant_isolation_revocation_and_status(environment) -> None:
    client, store, monkeypatch = environment
    status = client.get(f"{API}/status").json()
    assert status == {
        "schema": "lightwork.privacy-regulatory-intelligence-status.v1",
        "enabled": True,
        "licensed_corpus_bundled": False,
        "corpus_grounded_only": True,
        "legal_advice": False,
        "live_source_acceptance_verified": False,
        "delivery_destination_resolver_configured": False,
        "smtp_sender_configured": False,
    }

    forged = _source()
    forged["tenant_id"] = "tenant-b"
    assert client.put(f"{API}/sources/forged", json=forged).status_code == 422

    assert client.put(f"{API}/sources/primary-law", json=_source()).status_code == 200
    approved = client.post(
        f"{API}/sources/primary-law/review",
        json={
            "expected_revision": 1,
            "rationale": "Independently accepted licensed-use constraints.",
            "approved": True,
            "idempotency_key": "approve-primary-law-v1",
        },
        headers={"X-Test-Subject": "privacy-counsel"},
    )
    assert approved.status_code == 200, approved.text
    assert client.put(f"{API}/documents/access-law", json=_document()).status_code == 200

    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-b")
    assert client.get(f"{API}/sources").json()["items"] == []
    assert client.get(f"{API}/documents/access-law").status_code == 404
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")

    revoked = client.post(
        f"{API}/sources/primary-law/revoke",
        json={
            "expected_revision": 2,
            "reason": "Tenant license ended.",
            "idempotency_key": "revoke-primary-law-v1",
        },
    )
    assert revoked.status_code == 200, revoked.text
    hidden = client.post(
        f"{API}/search",
        json={
            "query": "verified access request",
            "jurisdictions": ["US-CA"],
            "limit": 20,
            "as_of": None,
        },
    )
    assert hidden.status_code == 200, hidden.text
    assert hidden.json()["items"] == []
    assert store.verify_integrity("tenant-a").verified_records > 0


def test_tracker_delivery_retry_report_and_integrity(environment) -> None:
    client, _store, _monkeypatch = environment
    assert client.put(f"{API}/sources/primary-law", json=_source()).status_code == 200
    assert (
        client.post(
            f"{API}/sources/primary-law/review",
            json={
                "expected_revision": 1,
                "rationale": "Independent rights review complete.",
                "approved": True,
                "idempotency_key": "approve-primary-law-v1",
            },
            headers={"X-Test-Subject": "privacy-counsel"},
        ).status_code
        == 200
    )
    assert client.put(f"{API}/documents/access-law", json=_document()).status_code == 200

    tracker = client.put(
        f"{API}/subscriptions/access-updates",
        json={
            "query": "access request",
            "jurisdictions": ["US-CA"],
            "destination_ref": "privacy-alert-channel",
            "cadence_seconds": 300,
            "expected_revision": 0,
            "idempotency_key": "tracker-access-v1",
        },
    )
    assert tracker.status_code == 200, tracker.text
    alerts = client.post(
        f"{API}/documents/access-law/alerts",
        json={"version": 1},
    )
    assert alerts.status_code == 200, alerts.text
    assert alerts.json()["count"] == 1

    claim = client.post(
        f"{API}/deliveries/claim",
        json={"limit": 10, "lease_seconds": 60.0},
    )
    assert claim.status_code == 200, claim.text
    delivery = claim.json()["items"][0]
    failed = client.post(
        f"{API}/deliveries/{delivery['delivery_id']}/fail",
        json={
            "lease_token": delivery["lease_token"],
            "error_code": "transport_unavailable",
            "backoff_seconds": 1.0,
        },
    )
    assert failed.status_code == 200, failed.text
    assert failed.json()["state"] == "pending"

    report = client.put(
        f"{API}/reports/access-report",
        json={
            "query": "access request timing",
            "jurisdictions": ["US-CA"],
            "retention_seconds": 86_400,
            "idempotency_key": "report-access-v1",
        },
    )
    assert report.status_code == 200, report.text
    assert report.json()["citations"]
    integrity = client.get(f"{API}/integrity")
    assert integrity.status_code == 200, integrity.text
    assert integrity.json()["valid"] is True


def test_configured_delivery_worker_sends_and_acknowledges_without_recipient_leak(
    environment,
) -> None:
    client, _store, _monkeypatch = environment
    assert client.put(f"{API}/sources/primary-law", json=_source()).status_code == 200
    assert (
        client.post(
            f"{API}/sources/primary-law/review",
            json={
                "expected_revision": 1,
                "rationale": "Independent rights review complete.",
                "approved": True,
                "idempotency_key": "approve-primary-law-v1",
            },
            headers={"X-Test-Subject": "privacy-counsel"},
        ).status_code
        == 200
    )
    assert client.put(f"{API}/documents/access-law", json=_document()).status_code == 200
    assert (
        client.put(
            f"{API}/subscriptions/access-updates",
            json={
                "query": "access request",
                "jurisdictions": ["US-CA"],
                "destination_ref": "privacy-alert-channel",
                "cadence_seconds": 300,
                "expected_revision": 0,
                "idempotency_key": "tracker-access-v1",
            },
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"{API}/documents/access-law/alerts",
            json={"version": 1},
        ).json()["count"]
        == 1
    )

    sent: list[dict[str, str]] = []

    class Transport:
        def send(self, **kwargs):
            sent.append(kwargs)

    client.app.state.privacy_intelligence_destination_resolver = (
        lambda tenant, ref: (
            "counsel@example.com"
            if (tenant, ref) == ("tenant-a", "privacy-alert-channel")
            else ""
        )
    )
    client.app.state.privacy_intelligence_delivery_transport = Transport()
    status = client.get(f"{API}/status")
    assert status.status_code == 200, status.text
    assert status.json()["delivery_destination_resolver_configured"] is True

    response = client.post(
        f"{API}/deliveries/run",
        json={
            "limit": 10,
            "lease_seconds": 60.0,
            "base_backoff_seconds": 30.0,
            "maximum_backoff_seconds": 86_400.0,
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["acknowledged"] == 1
    assert result["semantics"] == "at_least_once"
    assert "counsel@example.com" not in response.text
    assert sent[0]["recipient"] == "counsel@example.com"


def test_delivery_worker_fails_closed_without_destination_resolver(environment) -> None:
    client, _store, _monkeypatch = environment
    response = client.post(
        f"{API}/deliveries/run",
        json={"limit": 10, "lease_seconds": 60.0},
    )
    assert response.status_code == 503
    assert "destination resolver" in response.json()["detail"]


def test_records_list_documents_trackers_and_reports_without_text(environment) -> None:
    client, _store, _monkeypatch = environment
    assert client.get(f"{API}/records").json() == {"documents": [], "trackers": [], "reports": []}
    client.put(f"{API}/sources/primary-law", json=_source())
    client.post(
        f"{API}/sources/primary-law/review",
        json={"expected_revision": 1, "rationale": "Checked.", "approved": True,
              "idempotency_key": "approve-1"},
        headers={"X-Test-Subject": "privacy-counsel"},
    )
    assert client.put(f"{API}/documents/access-law", json=_document()).status_code == 200
    saved = client.put(
        f"{API}/subscriptions/access-tracker",
        json={"query": "access request", "jurisdictions": ["US-CA"],
              "destination_ref": "privacy-team", "cadence_seconds": 86_400,
              "expected_revision": 0, "idempotency_key": "tracker-1"},
    )
    assert saved.status_code == 200, saved.text
    listed = client.get(f"{API}/records")
    assert listed.status_code == 200
    body = listed.json()
    assert [d["title"] for d in body["documents"]] == ["California access timing"]
    assert body["trackers"][0]["subscription_id"] == "access-tracker"
    assert "respond within the timing" not in listed.text
