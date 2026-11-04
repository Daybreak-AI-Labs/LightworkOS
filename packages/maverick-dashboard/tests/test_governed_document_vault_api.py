from __future__ import annotations

import hashlib

from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick import administration_document_access as access
from maverick import governed_document_vault as vault
from maverick_dashboard.governed_document_vault_api import (
    create_governed_document_vault_router,
)


class Clock:
    def __init__(self) -> None:
        self.value = 2_000_000_000.0

    def __call__(self) -> float:
        return self.value


def _client(monkeypatch, tmp_path, *, enabled=True):
    monkeypatch.setattr("maverick.paths.current_tenant_id_strict", lambda: "tenant-a")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", bytes(range(32)).hex())
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    store = vault.GovernedDocumentVault(
        tmp_path / "vault-private" / "vault.sqlite3",
        tenant_id="tenant-a",
        config=vault.GovernedDocumentVaultConfig(
            enable=True,
            retention_seconds=60,
            grant_ttl_seconds=30,
            claim_lease_seconds=5,
            max_document_bytes=4096,
        ),
        clock=Clock(),
    )
    app = FastAPI()
    app.state.governed_document_vault_enabled_probe = lambda _tenant: enabled
    app.state.governed_document_vault_store_factory = (
        lambda _tenant, _request: store
    )
    app.include_router(create_governed_document_vault_router())
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), store


def test_disabled_status_and_ingestion_fail_without_touching_authority(monkeypatch, tmp_path):
    client, store = _client(monkeypatch, tmp_path, enabled=False)

    assert client.get("/administration/document-vault/status").json() == {
        "schema": "lightwork.governed-document-vault-status.v1",
        "enabled": False,
        "configured": False,
        "ready": False,
        "external_object_store_custody_verified": False,
        "live_relying_workflow_verified": False,
    }
    denied = client.post(
        "/administration/document-vault/documents",
        params={
            "product_area": "privacy_automation",
            "record_type": "incident_attachment",
            "safe_display_name": "evidence.pdf",
        },
        content=b"pdf",
        headers={"Content-Type": "application/pdf"},
    )
    assert denied.status_code == 403
    assert store.list_documents() == []


def test_ingest_list_status_revoke_and_integrity(monkeypatch, tmp_path):
    client, _store = _client(monkeypatch, tmp_path)
    created = client.post(
        "/administration/document-vault/documents",
        params={
            "product_area": "privacy_automation",
            "record_type": "incident_attachment",
            "safe_display_name": "evidence.pdf",
        },
        content=b"approved evidence",
        headers={"Content-Type": "application/pdf"},
    )

    assert created.status_code == 201
    document = created.json()["document"]
    assert document["document_ref"].startswith("doc_")
    assert document["content_sha256"] == hashlib.sha256(b"approved evidence").hexdigest()
    assert "path" not in document
    assert "locator" not in document
    listed = client.get("/administration/document-vault/documents").json()
    assert listed["count"] == 1
    assert listed["items"][0]["document_ref"] == document["document_ref"]
    status = client.get("/administration/document-vault/status").json()
    assert status["ready"] is True
    assert status["external_object_store_custody_verified"] is False
    revoked = client.post(
        f"/administration/document-vault/documents/{document['document_ref']}/revoke",
        json={"expected_revision": 1},
    )
    assert revoked.status_code == 200
    assert revoked.json()["state"] == "revoked"
    assert client.get("/administration/document-vault/integrity").json()["ok"] is True


def test_ingestion_rejects_unapproved_media_oversize_and_path_name(monkeypatch, tmp_path):
    client, _store = _client(monkeypatch, tmp_path)
    params = {
        "product_area": "privacy_automation",
        "record_type": "incident_attachment",
        "safe_display_name": "evidence.pdf",
    }
    assert client.post(
        "/administration/document-vault/documents",
        params=params,
        content=b"binary",
        headers={"Content-Type": "application/x-executable"},
    ).status_code == 415
    assert client.post(
        "/administration/document-vault/documents",
        params=params,
        content=b"x" * 4097,
        headers={"Content-Type": "application/pdf"},
    ).status_code == 413
    assert client.post(
        "/administration/document-vault/documents",
        params={**params, "safe_display_name": "../secret.pdf"},
        content=b"pdf",
        headers={"Content-Type": "application/pdf"},
    ).status_code == 422


def test_delivery_is_authenticated_post_stream_and_one_time(monkeypatch, tmp_path):
    client, store = _client(monkeypatch, tmp_path)
    record = store.ingest(
        b"stream me",
        principal_ref="actor",
        product_area="privacy_automation",
        record_type="incident_attachment",
        safe_display_name="evidence.pdf",
        media_type="application/pdf",
    )
    principal_digest = hashlib.sha256(
        b"lightwork.document-access.api-principal.v1:tenant-a:authorized-local-operator"
    ).hexdigest()
    principal = f"document-access-api.{principal_digest[:40]}"
    claim = access.DeliveryClaim(
        tenant_id="tenant-a",
        principal_ref=principal,
        token_id="token-1",
        claim_id="claim-1",
        document_ref=record.document_ref,
        product_area=record.product_area,
        record_type=record.record_type,
        safe_display_name=record.safe_display_name,
        media_type=record.media_type,
        byte_size=record.byte_size,
        content_sha256=record.content_sha256,
        authority_revision=record.authority_revision,
        authority_sha256=record.authority_sha256,
        grant_expires_at=2_000_000_020.0,
    )
    issued = store.issue_delivery_grant(claim)

    delivered = client.post(
        "/administration/document-vault/delivery",
        json={"delivery_grant": issued.grant},
    )
    assert delivered.status_code == 200
    assert delivered.content == b"stream me"
    assert delivered.headers["cache-control"] == "no-store"
    assert delivered.headers["x-content-sha256"] == record.content_sha256
    replay = client.post(
        "/administration/document-vault/delivery",
        json={"delivery_grant": issued.grant},
    )
    assert replay.status_code == 409


def test_delivery_contract_rejects_get_and_extra_fields(monkeypatch, tmp_path):
    client, _store = _client(monkeypatch, tmp_path)
    assert client.get("/administration/document-vault/delivery").status_code == 405
    response = client.post(
        "/administration/document-vault/delivery",
        json={
            "delivery_grant": "lwdvg_v1_" + "a" * 43,
            "object_locator": "s3://forbidden",
        },
    )
    assert response.status_code == 422
