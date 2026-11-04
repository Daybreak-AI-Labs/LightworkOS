from __future__ import annotations

import base64
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick.consent_native_sdk import NativeConsentDenied
from maverick_dashboard import consent_native_admin_api as native_api


def _admin_app(monkeypatch):
    application = FastAPI()
    calls: dict[str, dict] = {}
    permissions: list[str] = []

    @application.middleware("http")
    async def authenticated_principal(request, call_next):
        request.state.principal = SimpleNamespace(sub="operator@example.test")
        return await call_next(request)

    def operation(name: str, result: dict):
        def invoke(**kwargs):
            calls[name] = kwargs
            return result

        return invoke

    application.state.consent_native_admin_register = operation(
        "register",
        {"application_ref": "mobile-prod", "revision": 1},
    )
    application.state.consent_native_admin_rotate_receipt_key = operation(
        "receipt-key",
        {"application_ref": "mobile-prod", "directory_revision": 2},
    )
    application.state.consent_native_admin_rotate_device = operation(
        "device-rotate",
        {"device_id": "device-one", "revision": 2},
    )
    application.state.consent_native_admin_revoke_device = operation(
        "device-revoke",
        {"device_id": "device-one", "revision": 3, "status": "revoked"},
    )
    application.state.consent_native_admin_readiness = operation(
        "readiness",
        {"enabled": True, "ready": False, "reasons": ["attestation_verifier_unavailable"]},
    )
    application.state.consent_native_admin_integrity = operation(
        "integrity",
        {"valid": True, "applications": 1},
    )
    application.include_router(native_api.router, prefix="/api/v1")
    monkeypatch.setattr(native_api, "current_tenant_id_strict", lambda: "tenant-alpha")
    monkeypatch.setattr(
        native_api,
        "require_global_permission",
        lambda _request, permission: permissions.append(permission),
    )
    return application, calls, permissions


def test_admin_routes_derive_tenant_and_principal_and_preserve_exact_cas(monkeypatch) -> None:
    application, calls, permissions = _admin_app(monkeypatch)
    client = TestClient(application, base_url="http://127.0.0.1")

    forbidden_authority = client.post(
        "/api/v1/consent/native/applications",
        json={
            "tenant_id": "attacker",
            "public_client_ref": "service-client",
            "minimum_sdk_version": 4,
            "expected_revision": 0,
        },
    )
    assert forbidden_authority.status_code == 422

    registered = client.post(
        "/api/v1/consent/native/applications",
        json={
            "public_client_ref": "service-client",
            "minimum_sdk_version": 4,
            "expected_revision": 0,
        },
    )
    assert registered.status_code == 201, registered.text
    registration = calls["register"]
    assert registration["tenant_id"] == "tenant-alpha"
    assert registration["principal_ref"].startswith("native-consent-admin-")
    assert "operator@example.test" not in registration["principal_ref"]
    assert registration["expected_revision"] == 0

    key_rotation = client.post(
        "/api/v1/consent/native/applications/mobile-prod/receipt-key/rotate",
        json={"expected_directory_revision": 1},
    )
    assert key_rotation.status_code == 200, key_rotation.text
    assert calls["receipt-key"]["expected_directory_revision"] == 1
    assert calls["receipt-key"]["tenant_id"] == "tenant-alpha"

    material = b"fresh-platform-attestation"
    encoded = base64.urlsafe_b64encode(material).rstrip(b"=").decode()
    rotated = client.post(
        "/api/v1/consent/native/applications/mobile-prod/devices/device-one/rotate",
        json={
            "expected_revision": 1,
            "public_key_hex": "a" * 64,
            "attestation_nonce": "nonce-one",
            "attestation_evidence_sha256": "b" * 64,
            "attestation_material_b64url": encoded,
            "issued_at": 1_800_000_000,
            "expires_at": 1_800_000_120,
        },
    )
    assert rotated.status_code == 200, rotated.text
    assert calls["device-rotate"]["attestation_material"] == material
    assert calls["device-rotate"]["expected_revision"] == 1
    assert "tenant_id" not in rotated.request.content.decode()

    revoked = client.post(
        "/api/v1/consent/native/applications/mobile-prod/devices/device-one/revoke",
        json={"expected_revision": 2, "evidence_sha256": "c" * 64},
    )
    assert revoked.status_code == 200, revoked.text
    assert calls["device-revoke"]["expected_revision"] == 2

    readiness = client.get("/api/v1/consent/native/readiness")
    assert readiness.status_code == 200
    assert readiness.json()["ready"] is False
    assert readiness.headers["cache-control"].startswith("no-store")
    integrity = client.get("/api/v1/consent/native/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is True
    assert permissions == ["admin", "admin", "admin", "admin", "view", "audit"]


def test_list_routes_are_audit_gated_and_tenant_derived(monkeypatch) -> None:
    application, calls, permissions = _admin_app(monkeypatch)

    def applications(**kwargs):
        calls["applications"] = kwargs
        return {"items": [{"application_ref": "mobile-prod", "directory_revision": 1}]}

    def devices(**kwargs):
        calls["devices"] = kwargs
        return {"items": [{"device_id": "device-one", "revision": 2, "status": "active"}]}

    application.state.consent_native_admin_applications = applications
    application.state.consent_native_admin_devices = devices
    client = TestClient(application, base_url="http://127.0.0.1")

    listed = client.get("/api/v1/consent/native/applications?tenant_id=attacker")
    assert listed.status_code == 200, listed.text
    assert listed.json()["items"][0]["application_ref"] == "mobile-prod"
    assert listed.headers["cache-control"].startswith("no-store")
    assert calls["applications"]["tenant_id"] == "tenant-alpha"

    device_rows = client.get("/api/v1/consent/native/applications/mobile-prod/devices")
    assert device_rows.status_code == 200, device_rows.text
    assert device_rows.json()["items"][0]["revision"] == 2
    assert calls["devices"]["application_ref"] == "mobile-prod"
    assert calls["devices"]["tenant_id"] == "tenant-alpha"
    assert client.get(
        "/api/v1/consent/native/applications/..%2Fother/devices"
    ).status_code in {404, 422}
    assert permissions == ["audit", "audit"]


def test_list_routes_require_an_active_workspace(monkeypatch) -> None:
    application, _calls, _permissions = _admin_app(monkeypatch)
    application.state.consent_native_admin_applications = lambda **_kwargs: {"items": []}
    monkeypatch.setattr(native_api, "current_tenant_id_strict", lambda: None)
    response = TestClient(application, base_url="http://127.0.0.1").get("/api/v1/consent/native/applications")
    assert response.status_code == 409


def test_public_receipt_keys_are_discoverable_without_ambient_authority(
    monkeypatch,
) -> None:
    application = FastAPI()
    rate_calls: list[tuple[str, str]] = []
    application.state.consent_native_public_rate_limit = (
        lambda subject, operation: rate_calls.append((subject, operation))
    )
    application.state.consent_native_public_receipt_keys = lambda application_ref: {
        "schema": "lightwork.native-consent-receipt-keys.v1",
        "application_ref": application_ref,
        "directory_revision": 2,
        "keys": [
            {
                "key_id": "native-receipt",
                "key_revision": 2,
                "public_key_hex": "d" * 64,
                "current": True,
            }
        ],
    }
    application.include_router(native_api.create_consent_native_public_metadata_router())
    client = TestClient(application, base_url="http://127.0.0.1")
    discovery_path = "/api/v1/public/consent/native/receipt-keys"
    path = "/api/v1/public/consent/native/receipt-keys/mobile-prod"

    discovery = client.get(discovery_path)
    assert discovery.status_code == 200, discovery.text
    assert discovery.json() == {
        "schema": "lightwork.native-consent-receipt-key-discovery.v1",
        "method": "GET",
        "application_ref_required": True,
        "endpoint_template": (
            "/api/v1/public/consent/native/receipt-keys/{application_ref}"
        ),
    }
    assert discovery.headers["access-control-allow-origin"] == "*"
    assert client.get(f"{discovery_path}?tenant_id=attacker").status_code == 404

    discovered = client.get(path)
    assert discovered.status_code == 200, discovered.text
    assert discovered.json()["keys"][0]["current"] is True
    assert discovered.headers["access-control-allow-origin"] == "*"
    assert rate_calls[0][1] == "receipt-keys"
    assert client.get(path, headers={"Authorization": "Bearer ambient"}).status_code == 401
    assert client.get(f"{path}?tenant_id=attacker").status_code == 404

    application.state.consent_native_public_rate_limit = lambda *_args: (_ for _ in ()).throw(
        NativeConsentDenied("rate limit reached")
    )
    limited = client.get(path)
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"
