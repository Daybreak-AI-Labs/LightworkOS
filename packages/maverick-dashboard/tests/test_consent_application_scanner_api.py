from __future__ import annotations

import asyncio
import base64
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import consent_application_scanner as scanner
from maverick_dashboard import consent_application_scanner_api as api

BASE = "/api/v1/consent/application-scans"


class _StreamingRequest:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.reads = 0

    async def stream(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    async def body(self):
        raise AssertionError("bounded transport must not call unbounded Request.body")


class Service:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def register_application(self, **payload):
        self.calls.append(("register", payload))
        return {"id": "CAP-0123456789abcdef01234567", "revision": 1, **payload}

    def get_application(self, application_id):
        self.calls.append(("get_application", application_id))
        return {"id": application_id, "revision": 1}

    def list_applications(self, *, limit):
        self.calls.append(("list_applications", limit))
        return []

    def revoke_application(self, application_id, **payload):
        self.calls.append(("revoke", (application_id, payload)))
        return {"id": application_id, "status": "revoked", "revision": 2}

    def scan(self, application_id, files, **payload):
        self.calls.append(("scan", (application_id, files, payload)))
        return {"id": "CAS-0123456789abcdef01234567", "status": "pending_review", "revision": 1}

    def get_scan(self, scan_id):
        self.calls.append(("get_scan", scan_id))
        return {"id": scan_id, "revision": 1}

    def list_scans(self, *, limit):
        self.calls.append(("list_scans", limit))
        return []

    def review(self, scan_id, **payload):
        self.calls.append(("review", (scan_id, payload)))
        return {"id": scan_id, "status": payload["decision"], "revision": 2}

    def verify_integrity(self, *, limit):
        self.calls.append(("integrity", limit))
        return {"ok": True, "applications": 0, "scans": 0}


@pytest.fixture()
def environment(monkeypatch):
    service = Service()
    state = SimpleNamespace(enabled=True, ready=True, permissions=[], maintenance_calls=[])
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(
        api,
        "require_permission",
        lambda _request, permission: state.permissions.append(("tenant", permission)),
    )

    def maintenance(request, tenant, **kwargs):
        state.maintenance_calls.append((request, tenant, kwargs))
        return {"inspected": 1, "purged": 1}

    deps = api.ConsentApplicationScannerDependencies(
        service_factory=lambda _request, _tenant: service,
        enabled_probe=lambda _tenant: state.enabled,
        readiness_probe=lambda _request, _tenant: state.ready,
        maintenance=maintenance,
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="user:admin")
        return await call_next(request)

    app.include_router(api.create_consent_application_scanner_router(deps), prefix="/api/v1")
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), state, service


def test_api_is_strict_role_gated_and_decodes_transient_manifest_bytes(environment) -> None:
    client, state, service = environment
    created = client.post(
        f"{BASE}/applications",
        json={
            "platform": "android",
            "bundle_id": "com.example.mobile",
            "display_name": "Example Mobile",
            "idempotency_key": "register-001",
        },
    )
    assert created.status_code == 201
    application_id = created.json()["id"]
    manifest = b"<manifest package='com.example.mobile' />"
    scanned = client.post(
        f"{BASE}/applications/{application_id}/scans",
        json={
            "expected_application_revision": 1,
            "idempotency_key": "scan-001",
            "files": [
                {
                    "path": "AndroidManifest.xml",
                    "media_type": "application/xml",
                    "content_base64": base64.b64encode(manifest).decode("ascii"),
                }
            ],
        },
    )
    assert scanned.status_code == 201
    scan_call = next(value for name, value in service.calls if name == "scan")
    assert scan_call[1][0].content == manifest
    assert scan_call[2]["actor"].startswith("consent-app-scanner-")
    reviewed = client.post(
        f"{BASE}/scans/{scanned.json()['id']}/review",
        json={
            "decision": "accepted",
            "expected_revision": 1,
            "review_note_code": "manifest_reviewed",
        },
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "accepted"
    assert client.get(f"{BASE}/applications").status_code == 200
    assert client.get(f"{BASE}/scans").status_code == 200
    assert client.get(f"{BASE}/integrity").json()["ok"] is True
    assert ("tenant", "admin") in state.permissions
    assert ("tenant", "audit") in state.permissions
    assert created.headers["cache-control"] == "no-store, private, max-age=0"


def test_disabled_unready_and_caller_authority_fields_fail_closed(environment) -> None:
    client, state, service = environment
    state.ready = False
    assert client.get(f"{BASE}/applications").status_code == 503
    assert service.calls == []
    state.ready = True
    state.enabled = False
    assert client.get(f"{BASE}/applications").status_code == 403
    assert service.calls == []
    state.enabled = True
    state.ready = 1
    response = client.get(f"{BASE}/readiness")
    assert response.status_code == 503
    assert response.json() == {"enabled": True, "ready": False}

    state.ready = True
    response = client.post(
        f"{BASE}/applications",
        json={
            "platform": "android",
            "bundle_id": "com.example.mobile",
            "display_name": "Example Mobile",
            "idempotency_key": "register-001",
            "tenant_id": "attacker",
            "actor": "attacker",
            "retention_seconds": 999999,
        },
    )
    assert response.status_code == 422
    assert service.calls == []


def test_transport_rejects_bad_base64_media_and_oversized_json(environment) -> None:
    client, _state, service = environment
    application_id = "CAP-0123456789abcdef01234567"
    bad = client.post(
        f"{BASE}/applications/{application_id}/scans",
        json={
            "expected_application_revision": 1,
            "idempotency_key": "scan-001",
            "files": [
                {
                    "path": "AndroidManifest.xml",
                    "media_type": "application/xml",
                    "content_base64": "not-base64!",
                }
            ],
        },
    )
    assert bad.status_code == 422
    assert service.calls == []
    over_one_mib = client.post(
        f"{BASE}/applications/{application_id}/scans",
        json={
            "expected_application_revision": 1,
            "idempotency_key": "scan-oversized-file",
            "files": [
                {
                    "path": "AndroidManifest.xml",
                    "media_type": "application/xml",
                    "content_base64": base64.b64encode(b"x" * 1_048_578).decode("ascii"),
                }
            ],
        },
    )
    assert over_one_mib.status_code == 422
    assert service.calls == []
    wrong_media = client.post(
        f"{BASE}/applications/{application_id}/scans",
        content=b"{}",
        headers={"Content-Type": "text/plain"},
    )
    assert wrong_media.status_code == 415
    oversized = b'{"padding":"' + (b"x" * (6 * 1_024 * 1_024)) + b'"}'
    response = client.post(
        f"{BASE}/applications",
        content=oversized,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_transport_streams_only_the_declared_bounded_body() -> None:
    request = _StreamingRequest([b'{"ok":', b"true}"])
    asyncio.run(api._read_bounded_json_body(request, 11))
    assert request._body == b'{"ok":true}'
    assert request.reads == 2

    mismatched = _StreamingRequest([b"{}", b"never-read"])
    with pytest.raises(api.HTTPException) as caught:
        asyncio.run(api._read_bounded_json_body(mismatched, 1))
    assert caught.value.status_code == 400
    assert mismatched.reads == 1


def test_core_conflict_details_are_not_reflected(environment, monkeypatch) -> None:
    client, _state, service = environment

    def conflict(**_kwargs):
        raise scanner.ConsentApplicationScanConflict("sensitive provider state")

    monkeypatch.setattr(service, "register_application", conflict)
    response = client.post(
        f"{BASE}/applications",
        json={
            "platform": "android",
            "bundle_id": "com.example.mobile",
            "display_name": "Example Mobile",
            "idempotency_key": "register-001",
        },
    )
    assert response.status_code == 409
    assert response.json()["detail"] == ("consent application-scanner state or authority conflicts")
    assert "sensitive" not in response.text

    def backend_failure(**_kwargs):
        raise RuntimeError("credential-bearing backend failure")

    monkeypatch.setattr(service, "register_application", backend_failure)
    unavailable = client.post(
        f"{BASE}/applications",
        json={
            "platform": "android",
            "bundle_id": "com.example.mobile",
            "display_name": "Example Mobile",
            "idempotency_key": "register-002",
        },
    )
    assert unavailable.status_code == 503
    assert unavailable.json() == {"detail": "consent application scanning is unavailable"}
    assert "credential-bearing" not in unavailable.text


def test_maintenance_is_server_tenant_and_actor_bound(environment) -> None:
    client, state, _service = environment
    response = client.post(
        f"{BASE}/maintenance/purge",
        json={"limit": 10},
    )
    assert response.status_code == 200
    assert response.json() == {"inspected": 1, "purged": 1}
    _request, tenant, payload = state.maintenance_calls[0]
    assert tenant == "tenant-a"
    assert payload["actor"].startswith("consent-app-scanner-")
    assert "now" not in payload

    caller_clock = client.post(
        f"{BASE}/maintenance/purge",
        json={"now": 2_000_000_000.0, "limit": 10},
    )
    assert caller_clock.status_code == 422
    assert len(state.maintenance_calls) == 1
