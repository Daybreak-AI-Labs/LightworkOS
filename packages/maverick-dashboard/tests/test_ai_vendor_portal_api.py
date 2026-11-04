from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from maverick import config
from maverick_dashboard import external_gateway, model_risk_api
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """[evidence_graph]
enable = true

[model_risk_assurance]
enable = true

[ai_vendor_risk]
enable = true
portal_enable = true
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(model_risk_api, "_human_principal", lambda _request: "user:admin")
    monkeypatch.setattr(external_gateway, "_rate_times", {})
    config.reset_config_cache()
    from maverick.tenant.registry import create_tenant
    create_tenant("tenant-a")
    yield
    config.reset_config_cache()


def _portal_headers(token: str, *, tenant: str = "tenant-a") -> dict[str, str]:
    return {
        "Authorization": f"VendorPortal {token}",
        "X-Lightwork-Tenant": tenant,
        "Content-Type": "application/json",
    }


def _answers(questionnaire: dict) -> dict[str, dict[str, str]]:
    return {
        question["id"]: {"answer": "unknown", "note": "Pending evidence."}
        for question in questionnaire["questions"]
    }


def test_unknown_vendor_tenants_do_not_create_namespace_claims(tmp_path):
    claims = tmp_path / "home" / ".tenant-namespaces"
    before = set(claims.rglob("*.json")) if claims.exists() else set()
    for index in range(10):
        response = client.get("/api/v1/external/ai-vendor/questionnaire",
                              headers=_portal_headers("fake-token", tenant=f"unknown-{index}"))
        assert response.status_code == 401
    after = set(claims.rglob("*.json")) if claims.exists() else set()
    assert after == before


def test_vendor_portal_http_roundtrip_is_token_scoped_and_review_gated() -> None:
    created = client.post(
        "/api/v1/security/assurance/ai-vendor/portal/invitations",
        json={"vendor": "Acme AI", "expires_in_seconds": 7200},
    )
    assert created.status_code == 201, created.text
    invitation = created.json()["invitation"]
    token = created.json()["token"]
    assert token.startswith("aivp1.")
    assert created.json()["tenant_ref"] == "tenant-a"

    listed = client.get(
        "/api/v1/security/assurance/ai-vendor/portal/invitations"
    )
    assert listed.status_code == 200, listed.text
    assert token not in json.dumps(listed.json())

    questionnaire_response = client.get(
        "/api/v1/external/ai-vendor/questionnaire",
        headers=_portal_headers(token),
    )
    assert questionnaire_response.status_code == 200, questionnaire_response.text
    assert questionnaire_response.headers["cache-control"] == "no-store"
    questionnaire = questionnaire_response.json()["questionnaire"]
    assert questionnaire["template_digest"] == invitation["questionnaire_digest"]
    assert len(questionnaire["questions"]) == 8

    payload = {
        "answers": _answers(questionnaire),
        "respondent_ref": "security-lead",
        "attested": True,
        "idempotency_key": "acme-response-1",
    }
    submitted = client.post(
        "/api/v1/external/ai-vendor/submissions",
        headers=_portal_headers(token),
        json=payload,
    )
    assert submitted.status_code == 201, submitted.text
    assert "answers" not in submitted.json()
    assert submitted.json()["status"] == "pending_import"

    retry = client.post(
        "/api/v1/external/ai-vendor/submissions",
        headers=_portal_headers(token),
        json=payload,
    )
    assert retry.status_code == 201, retry.text
    assert retry.json()["submission_id"] == submitted.json()["submission_id"]

    submissions = client.get(
        "/api/v1/security/assurance/ai-vendor/portal/submissions"
    )
    assert submissions.status_code == 200, submissions.text
    internal = submissions.json()["items"][0]
    assert internal["answers"] == payload["answers"]

    imported = client.post(
        "/api/v1/security/assurance/ai-vendor/portal/submissions/"
        f"{internal['submission_id']}/import",
        json={"expected_revision": internal["revision"]},
    )
    assert imported.status_code == 200, imported.text
    assert imported.json()["assessment"]["status"] == "pending_review"
    assert {
        answer["source"]
        for answer in imported.json()["assessment"]["answers"].values()
    } == {"vendor_attested"}


def test_vendor_portal_external_auth_is_generic_and_tenant_bound() -> None:
    created = client.post(
        "/api/v1/security/assurance/ai-vendor/portal/invitations",
        json={"vendor": "Acme AI"},
    ).json()
    token = created["token"]

    missing = client.get("/api/v1/external/ai-vendor/questionnaire")
    assert missing.status_code == 401
    assert missing.json()["detail"] == "invalid invitation"

    bearer = client.get(
        "/api/v1/external/ai-vendor/questionnaire",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Lightwork-Tenant": "tenant-a",
        },
    )
    assert bearer.status_code == 401
    assert bearer.json()["detail"] == "invalid invitation"

    wrong_tenant = client.get(
        "/api/v1/external/ai-vendor/questionnaire",
        headers=_portal_headers(token, tenant="tenant-b"),
    )
    assert wrong_tenant.status_code == 401
    assert wrong_tenant.json()["detail"] == "invalid invitation"


def test_vendor_portal_external_body_is_bounded_before_model_parsing() -> None:
    created = client.post(
        "/api/v1/security/assurance/ai-vendor/portal/invitations",
        json={"vendor": "Acme AI"},
    ).json()
    response = client.post(
        "/api/v1/external/ai-vendor/submissions",
        headers={
            **_portal_headers(created["token"]),
            "Content-Length": str(128 * 1024 + 1),
        },
        content=b"{}",
    )
    assert response.status_code == 413
