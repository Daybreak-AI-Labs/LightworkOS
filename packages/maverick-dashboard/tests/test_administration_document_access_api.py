"""Strict mounted-contract tests for document access administration."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick import administration_document_access as access
from maverick_dashboard.administration_document_access_api import (
    DocumentAccessDependencies,
    create_administration_document_access_router,
)


class Clock:
    def __init__(self) -> None:
        self.value = 2_000_000_000.0

    def __call__(self) -> float:
        return self.value


def _config():
    return access.DocumentAccessConfig(
        enable=True,
        default_ttl_seconds=30,
        max_ttl_seconds=120,
        max_uses=2,
        delivery_grant_ttl_seconds=10,
        retention_seconds=60,
    )


def _client(monkeypatch, tmp_path, *, enabled=True, include_service=True, readiness=None):
    monkeypatch.setattr(
        "maverick.paths.current_tenant_id_strict",
        lambda: "tenant-a",
    )
    clock = Clock()
    calls = {"service": 0, "resolver": [], "issuer": []}
    services = {}

    def service_for(tenant_id, principal_ref, _request):
        calls["service"] += 1
        key = (tenant_id, principal_ref)
        if key not in services:

            def resolver(resolved_tenant, resolved_principal, document_ref):
                calls["resolver"].append((resolved_tenant, resolved_principal, document_ref))
                return access.DocumentAuthority(
                    tenant_id=resolved_tenant,
                    principal_ref=resolved_principal,
                    document_ref=document_ref,
                    product_area="privacy_automation",
                    record_type="incident_attachment",
                    safe_display_name="evidence.pdf",
                    media_type="application/pdf",
                    byte_size=100,
                    content_sha256="a" * 64,
                    authority_revision=1,
                    authority_sha256="b" * 64,
                    download_allowed=True,
                )

            def issuer(claim):
                calls["issuer"].append(claim)
                return access.DeliveryGrant(
                    grant="api_delivery_grant_" + "g" * 40,
                    expires_at=claim.grant_expires_at,
                )

            store = access.DocumentAccessStore(
                tmp_path / f"{principal_ref}.sqlite3",
                tenant_id=tenant_id,
                clock=clock,
            )
            services[key] = access.DocumentAccessService(
                store=store,
                config=_config(),
                principal_resolver=lambda: principal_ref,
                document_resolver=resolver,
                delivery_grant_issuer=issuer,
                clock=clock,
            )
        return services[key]

    dependencies = DocumentAccessDependencies(
        service_for=service_for if include_service else None,
        enabled_probe=lambda _tenant: enabled,
        readiness_probe=readiness,
    )
    app = FastAPI()
    app.include_router(create_administration_document_access_router(dependencies))
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    return client, calls, services


def test_disabled_status_is_side_effect_free_and_mutations_fail_closed(monkeypatch, tmp_path):
    client, calls, _services = _client(monkeypatch, tmp_path, enabled=False)
    response = client.get("/administration/document-access/status")
    assert response.status_code == 200
    assert response.json()["enabled"] is False
    assert response.json()["configured"] is False
    assert response.json()["ready"] is False
    assert response.json()["limits"]["raw_download_tokens_persisted"] is False
    assert calls["service"] == 0
    assert not list(tmp_path.glob("*.sqlite3"))

    denied = client.post(
        "/administration/document-access/tokens",
        json={"document_ref": "doc-1", "idempotency_key": "mint-1"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "administration_document_access_disabled"
    assert calls["service"] == 0


def test_enabled_but_missing_dependencies_reports_not_ready(monkeypatch, tmp_path):
    client, calls, _services = _client(
        monkeypatch,
        tmp_path,
        enabled=True,
        include_service=False,
        readiness=lambda _tenant, _request: {
            "configured": False,
            "document_resolver_factory_installed": False,
            "delivery_grant_issuer_factory_installed": False,
        },
    )
    result = client.get("/administration/document-access/status")
    assert result.status_code == 200
    assert result.json()["enabled"] is True
    assert result.json()["configured"] is False
    assert result.json()["ready"] is False
    assert calls["service"] == 0
    assert not list(tmp_path.glob("*.sqlite3"))


def test_strict_api_mints_once_filters_catalog_and_redeems_only_grant(monkeypatch, tmp_path):
    client, calls, _services = _client(monkeypatch, tmp_path)
    mint_body = {
        "document_ref": "incident-doc-1",
        "ttl_seconds": 45,
        "max_uses": 1,
        "idempotency_key": "mint-api-1",
    }
    minted = client.post("/administration/document-access/tokens", json=mint_body)
    assert minted.status_code == 201
    payload = minted.json()
    raw_token = payload["download_token"]
    token_id = payload["token"]["token_id"]
    assert payload["idempotent_replay"] is False
    assert payload["token"]["document_ref"] == "incident-doc-1"
    assert "principal_sha256" not in payload["token"]
    assert "token_sha256" not in payload["token"]

    replay = client.post("/administration/document-access/tokens", json=mint_body)
    assert replay.status_code == 201
    assert replay.json()["idempotent_replay"] is True
    assert "download_token" not in replay.json()
    assert replay.json()["token"]["token_id"] == token_id
    assert len(calls["resolver"]) == 1

    catalog = client.get(
        "/administration/document-access/event-types",
        params={"product_area": "administration", "record_type": "document_attachment"},
    )
    assert catalog.status_code == 200
    assert catalog.json()["catalog_version"] == access.CATALOG_VERSION
    assert catalog.json()["caller_registration_supported"] is False
    assert {item["record_type"] for item in catalog.json()["items"]} == {"document_attachment"}
    assert client.post("/administration/document-access/event-types", json={}).status_code == 405

    claimed = client.post(
        "/administration/document-access/tokens/redeem",
        json={"download_token": raw_token, "idempotency_key": "claim-api-1"},
    )
    assert claimed.status_code == 200
    assert set(claimed.json()) == {"schema", "delivery_grant", "expires_at"}
    assert claimed.json()["delivery_grant"].startswith("api_delivery_grant_")
    assert len(calls["issuer"]) == 1

    replay_claim = client.post(
        "/administration/document-access/tokens/redeem",
        json={"download_token": raw_token, "idempotency_key": "claim-api-1"},
    )
    assert replay_claim.status_code == 409
    assert replay_claim.json()["detail"] == "document_access_claim_replay"

    token = client.get(f"/administration/document-access/tokens/{token_id}")
    assert token.status_code == 200
    assert token.json()["state"] == "exhausted"
    integrity = client.get("/administration/document-access/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["ok"] is True
    audit = client.get("/administration/document-access/audit/events")
    assert audit.status_code == 200
    assert audit.json()["count"] >= 4

    status = client.get("/administration/document-access/status")
    assert status.status_code == 200
    assert status.json()["enabled"] is True
    assert status.json()["configured"] is True
    assert status.json()["ready"] is True
    assert status.json()["live_relying_workflow_verified"] is False
    assert status.json()["external_object_store_custody_verified"] is False


def test_api_forbids_authority_fields_paths_and_non_strict_numbers(monkeypatch, tmp_path):
    client, calls, _services = _client(monkeypatch, tmp_path)
    attempts = (
        {
            "document_ref": "doc-1",
            "tenant_id": "tenant-b",
            "idempotency_key": "mint-extra",
        },
        {
            "document_ref": "../secret",
            "idempotency_key": "mint-path",
        },
        {
            "document_ref": "doc-1",
            "max_uses": "1",
            "idempotency_key": "mint-string",
        },
        {
            "document_ref": "doc-1",
            "record_type": "caller_selected",
            "idempotency_key": "mint-metadata",
        },
    )
    for body in attempts:
        response = client.post("/administration/document-access/tokens", json=body)
        assert response.status_code == 422
    assert calls["resolver"] == []
    assert calls["issuer"] == []


def test_event_catalog_filters_are_strict(monkeypatch, tmp_path):
    client, _calls, _services = _client(monkeypatch, tmp_path)
    assert (
        client.get(
            "/administration/document-access/event-types",
            params={"product_area": "made_up"},
        ).status_code
        == 422
    )
    assert (
        client.get(
            "/administration/document-access/event-types",
            params={"record_type": "../../etc"},
        ).status_code
        == 422
    )
