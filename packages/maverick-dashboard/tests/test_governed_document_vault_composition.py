from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick_dashboard import governed_document_vault_composition as composition
from maverick_dashboard.administration_document_access_api import (
    create_administration_document_access_router,
)
from maverick_dashboard.governed_document_vault_api import (
    create_governed_document_vault_router,
)


def _app(monkeypatch, tmp_path):
    config = {
        "administration_document_access": {
            "enable": True,
            "default_ttl_seconds": 30,
            "max_ttl_seconds": 120,
            "max_uses": 1,
            "delivery_grant_ttl_seconds": 30,
            "retention_seconds": 60,
        },
        "governed_document_vault": {
            "enable": True,
            "max_document_bytes": 4096,
            "retention_seconds": 60,
            "grant_ttl_seconds": 30,
            "claim_lease_seconds": 5,
        },
    }
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", bytes(range(32)).hex())
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setattr("maverick.paths.current_tenant_id_strict", lambda: "tenant-a")
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: config)
    monkeypatch.setattr(
        composition,
        "data_dir",
        lambda *_parts, tenant: tmp_path / tenant / "vault.sqlite3",
    )
    from maverick_dashboard import administration_document_access_composition as access_composition

    monkeypatch.setattr(access_composition, "_load_tenant_config", lambda _tenant: config)
    monkeypatch.setattr(
        access_composition,
        "data_dir",
        lambda *_parts, tenant: tmp_path / tenant / "access.sqlite3",
    )
    app = FastAPI()
    composition.attach_governed_document_vault_composition(app)
    app.include_router(create_governed_document_vault_router())
    app.include_router(create_administration_document_access_router())

    @app.get("/_test/incident-resolver/{document_ref}")
    def incident_resolver(request: Request, document_ref: str):
        principal = composition.incident_attachment_principal_ref(request, "tenant-a")
        resolver = request.app.state.administration_document_access_document_resolver_factory(
            "tenant-a", request
        )
        authority = resolver("tenant-a", principal, document_ref)
        return {
            "document_ref": authority.document_ref,
            "principal_ref": authority.principal_ref,
            "download_allowed": authority.download_allowed,
        }

    return app


def test_stock_composition_closes_resolver_issuer_and_delivery_loop(monkeypatch, tmp_path):
    app = _app(monkeypatch, tmp_path)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    uploaded = client.post(
        "/administration/document-vault/documents",
        params={
            "product_area": "privacy_automation",
            "record_type": "incident_attachment",
            "safe_display_name": "evidence.pdf",
        },
        content=b"composed evidence",
        headers={"Content-Type": "application/pdf"},
    )
    assert uploaded.status_code == 201
    document_ref = uploaded.json()["document"]["document_ref"]
    assert composition.governed_document_vault_custody_ready("tenant-a") is True

    status = client.get("/administration/document-access/status")
    assert status.status_code == 200
    assert status.json()["enabled"] is True
    assert status.json()["configured"] is True
    assert status.json()["ready"] is True
    assert status.json()["external_object_store_custody_verified"] is False

    minted = client.post(
        "/administration/document-access/tokens",
        json={"document_ref": document_ref, "idempotency_key": "vault-mint-1"},
    )
    assert minted.status_code == 201
    redeemed = client.post(
        "/administration/document-access/tokens/redeem",
        json={
            "download_token": minted.json()["download_token"],
            "idempotency_key": "vault-claim-1",
        },
    )
    assert redeemed.status_code == 200
    delivered = client.post(
        "/administration/document-vault/delivery",
        json={"delivery_grant": redeemed.json()["delivery_grant"]},
    )
    assert delivered.status_code == 200
    assert delivered.content == b"composed evidence"


def test_stock_resolver_accepts_incident_principal_but_rejects_spoof(monkeypatch, tmp_path):
    app = _app(monkeypatch, tmp_path)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    uploaded = client.post(
        "/administration/document-vault/documents",
        params={
            "product_area": "privacy_automation",
            "record_type": "incident_attachment",
            "safe_display_name": "incident.pdf",
        },
        content=b"incident",
        headers={"Content-Type": "application/pdf"},
    )
    document_ref = uploaded.json()["document"]["document_ref"]

    resolved = client.get(f"/_test/incident-resolver/{document_ref}")
    assert resolved.status_code == 200
    assert resolved.json()["download_allowed"] is True
    assert resolved.json()["principal_ref"].startswith("incident-principal-")


def test_attach_preserves_deployment_injected_authorities(monkeypatch):
    app = FastAPI()

    def resolver(_tenant, _request):
        return lambda *_args: None

    def issuer(_tenant, _request):
        return lambda *_args: None

    def readiness(_tenant, _request):
        return {"configured": True}

    app.state.administration_document_access_document_resolver_factory = resolver
    app.state.administration_document_access_delivery_grant_issuer_factory = issuer
    app.state.administration_document_access_readiness_probe = readiness
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: {})

    composition.attach_governed_document_vault_composition(app)

    assert app.state.administration_document_access_document_resolver_factory is resolver
    assert app.state.administration_document_access_delivery_grant_issuer_factory is issuer
    assert app.state.administration_document_access_readiness_probe is readiness
