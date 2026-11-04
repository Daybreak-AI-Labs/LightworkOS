from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import consent_web_publish_settings as web
from maverick_dashboard import consent_web_publish_settings_api as api


class _Service:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _result(self, operation: str, **kwargs):
        self.calls.append((operation, kwargs))
        return {
            "property_id": kwargs.get("property_id", "website-main"),
            "head_revision": 2,
            "state": "active",
            "version_id": kwargs.get("version_id") or kwargs.get("target_version_id") or "wps-1",
            "active_version_id": "wps-1",
            "latest_version_id": "wps-1",
            "idempotent_replay": False,
        }

    def create_version(self, **kwargs): return self._result("create", **kwargs)
    def activate_version(self, **kwargs): return self._result("activate", **kwargs)
    def rollback(self, **kwargs): return self._result("rollback", **kwargs)
    def withdraw(self, **kwargs): return self._result("withdraw", **kwargs)
    def purge_version(self, **kwargs): return self._result("purge", **kwargs)
    def get_head(self, **kwargs): return self._result("get_head", **kwargs)
    def get_version(self, **kwargs):
        result = self._result("get_version", **kwargs)
        result["created_by_sha256"] = "f" * 64
        return result
    def list_versions(self, **kwargs): return [self.get_version(version_id="wps-1", **kwargs)]
    def audit_history(self, **kwargs): return [{"event_type": "created", "actor_sha256": "f" * 64}]
    def verify_integrity(self): return {"valid": True, "browser_property_acceptance_verified": False}
    def recovery_status(self): return {"ready": True, "external_backup_restore_verified": False}


def _settings() -> dict[str, object]:
    return {
        "sdk_version": "2.4.1",
        "geolocation_reconsent": [
            {"jurisdiction": "US", "reconsent_after_days": 365}
        ],
        "analytics_tracking_enabled": True,
        "analytics_category_assignments": [
            {"tracker": "google_analytics", "category": "analytics"}
        ],
        "common_trackers": ["google_analytics"],
        "cookie_same_site": "lax",
        "cookie_domain_separation": "host_only",
        "spa_reload_on_route_change": True,
        "csp_nonce_required": True,
        "automatic_refresh_seconds": 300,
    }


def _client(monkeypatch, *, ready: bool = True):
    service = _Service()
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    deps = api.WebPublishSettingsDependencies(
        service_for=lambda **_kwargs: service,
        enabled_probe=lambda _tenant: True,
        readiness_probe=lambda _tenant: ready,
    )
    app = FastAPI()

    @app.middleware("http")
    async def _principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="admin-1")
        return await call_next(request)

    app.include_router(api.create_consent_web_publish_settings_router(deps))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), service


def test_status_is_candid_and_store_free(monkeypatch) -> None:
    client, service = _client(monkeypatch)
    response = client.get("/consent/publish-settings/status")
    assert response.status_code == 200
    assert response.json() == {
        "schema": "lightwork.consent-web-publish-settings.status.v1",
        "enabled": True,
        "configured": True,
        "ready": True,
        "immutable_versions": True,
        "cas_heads": True,
        "publication_pins_server_resolved": True,
        "csp_nonce_values_accepted": False,
        "browser_property_acceptance_verified": False,
    }
    assert service.calls == []


def test_create_accepts_only_closed_settings_and_server_resolves_pins(monkeypatch) -> None:
    client, service = _client(monkeypatch)
    body = {
        "expected_head_revision": 0,
        "idempotency_key": "create:website:1",
        "settings": _settings(),
    }
    response = client.post(
        "/consent/publish-settings/properties/website-main/versions", json=body
    )
    assert response.status_code == 201
    operation, forwarded = service.calls[-1]
    assert operation == "create"
    assert forwarded["property_id"] == "website-main"
    assert forwarded["settings"] == _settings()
    for forbidden in (
        "tenant_id",
        "principal_ref",
        "property_revision",
        "property_sha256",
        "publication_revision",
        "publication_sha256",
        "csp_nonce",
    ):
        assert forbidden not in forwarded


def test_extra_authority_and_nonce_value_fields_are_rejected(monkeypatch) -> None:
    client, service = _client(monkeypatch)
    body = {
        "expected_head_revision": 0,
        "idempotency_key": "create:website:2",
        "property_revision": 77,
        "settings": {**_settings(), "csp_nonce": "browser-secret"},
    }
    response = client.post(
        "/consent/publish-settings/properties/website-main/versions", json=body
    )
    assert response.status_code == 422
    assert service.calls == []


def test_lifecycle_routes_forward_exact_cas_contract(monkeypatch) -> None:
    client, service = _client(monkeypatch)
    revision = {
        "expected_head_revision": 3,
        "idempotency_key": "activate:website:3",
    }
    assert client.post(
        "/consent/publish-settings/properties/website-main/versions/wps-1/activate",
        json=revision,
    ).status_code == 200
    assert client.post(
        "/consent/publish-settings/properties/website-main/rollback",
        json={**revision, "idempotency_key": "rollback:website:3", "target_version_id": "wps-1"},
    ).status_code == 200
    assert client.post(
        "/consent/publish-settings/properties/website-main/withdraw",
        json={**revision, "idempotency_key": "withdraw:website:3"},
    ).status_code == 200
    assert [call[0] for call in service.calls] == ["activate", "rollback", "withdraw"]


def test_reads_strip_actor_digest_but_audit_keeps_digest_evidence(monkeypatch) -> None:
    client, _service = _client(monkeypatch)
    version = client.get(
        "/consent/publish-settings/properties/website-main/versions/wps-1"
    )
    assert version.status_code == 200
    assert "created_by_sha256" not in version.json()
    history = client.get(
        "/consent/publish-settings/operations/history?property_id=website-main"
    )
    assert history.status_code == 200
    assert history.json()["items"][0]["actor_sha256"] == "f" * 64


def test_not_ready_fails_closed_before_service_creation(monkeypatch) -> None:
    client, service = _client(monkeypatch, ready=False)
    response = client.get("/consent/publish-settings/properties/website-main")
    assert response.status_code == 503
    assert service.calls == []


def test_public_router_returns_only_validated_projection(monkeypatch) -> None:
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    projection = {
        "schema": web.PUBLIC_PROJECTION_SCHEMA,
        "enabled": True,
        "ready": False,
        "reason": "settings_not_ready",
        "property_id": "website-main",
        "browser_property_acceptance_verified": False,
    }
    deps = api.WebPublishSettingsDependencies(
        public_projection=lambda tenant, property_id, request: {
            **projection,
            "property_id": property_id,
        }
    )
    app = FastAPI()
    app.include_router(api.create_consent_web_publish_settings_public_router(deps))
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.get("/consent/publish-settings/website-main")
    assert response.status_code == 200
    assert response.json() == projection
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert "tenant" not in response.text


def test_public_router_rejects_expanded_or_nonce_bearing_projection(monkeypatch) -> None:
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    deps = api.WebPublishSettingsDependencies(
        public_projection=lambda tenant, property_id, request: {
            "schema": web.PUBLIC_PROJECTION_SCHEMA,
            "enabled": True,
            "ready": False,
            "reason": "settings_not_ready",
            "property_id": property_id,
            "browser_property_acceptance_verified": False,
            "nonce_value": "must-not-escape",
        }
    )
    app = FastAPI()
    app.include_router(api.create_consent_web_publish_settings_public_router(deps))
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.get("/consent/publish-settings/website-main")
    assert response.status_code == 503
    assert "must-not-escape" not in response.text


def test_mutations_require_json_and_are_request_bounded(monkeypatch) -> None:
    client, _service = _client(monkeypatch)
    path = "/consent/publish-settings/properties/website-main/versions"
    assert client.post(path, content="plain").status_code == 415
    response = client.post(
        path,
        content=b"{" + (b" " * (64 * 1024)),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
