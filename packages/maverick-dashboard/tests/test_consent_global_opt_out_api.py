from __future__ import annotations

import hashlib
import time
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import consent_global_opt_out as goo
from maverick_dashboard import consent_global_opt_out_api as api


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _config() -> dict:
    return {
        "consent_preferences": {
            "enable": True,
            "global_opt_out": {
                "enable": True,
                "retention_seconds": 3_600,
                "submission_ttl_seconds": 300,
                "max_records": 100,
            },
        }
    }


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(api, "current_tenant_id_strict", lambda: "alpha")
    monkeypatch.setattr(api, "require_global_permission", lambda _request, _name: None)
    subject = "operator@example.test"
    principal = "global-opt-out-admin-" + hashlib.sha256(
        f"lightwork.global-opt-out.identity.v1:alpha:{subject}".encode()
    ).hexdigest()[:32]
    now = time.time()
    authority = goo.issue_application_authority(
        tenant_id="alpha",
        application_ref="public-client-main",
        public_client_revision=3,
        public_client_record_sha256=_digest("client"),
        property_revision=2,
        property_sha256=_digest("property"),
        publication_sha256=_digest("publication"),
        publication_bundle_sha256=_digest("bundle"),
        configuration_sha256=_digest("configuration"),
        policy_id="public-consent",
        policy_version=4,
        policy_sha256=_digest("policy"),
        channel="browser-origin",
        origin_or_service_sha256=_digest("origin"),
        valid_until=now + 3_600,
        revoked=False,
    )
    store = goo.GlobalOptOutStore(
        tenant_id="alpha",
        principal_ref=principal,
        application_authority_resolver=lambda *_args: authority,
        principal_resolver=lambda: principal,
        config_gate=_config,
        limits=goo.load_global_opt_out_limits(_config()),
        maintenance_authorizer=lambda: True,
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal_middleware(request: Request, call_next):
        request.state.principal = SimpleNamespace(sub=subject)
        return await call_next(request)

    app.state.global_opt_out_admin_store_factory = lambda **_kwargs: store
    app.state.global_opt_out_enabled_probe = lambda tenant_id: tenant_id == "alpha"
    app.state.global_opt_out_readiness_probe = lambda _tenant: {
        "ready": True,
        "privacy_rights_intake_available": True,
        "live_device_acceptance": False,
        "live_customer_acceptance": False,
    }
    app.include_router(api.router, prefix="/api/v1")
    return TestClient(app, base_url="http://127.0.0.1"), store


def _create_body() -> dict:
    return {
        "application_ref": "public-client-main",
        "locale": "en-US",
        "mobile_ui": {
            "enabled": True,
            "title": "Privacy choice",
            "body": "Submit an opt-out request.",
            "submit_label": "Opt out",
            "success_message": "Request accepted.",
        },
        "email_ui": {
            "enabled": True,
            "title": "Privacy request",
            "body": "Submit a verified opt-out request.",
            "submit_label": "Submit",
            "success_message": "Request accepted.",
        },
        "supported_devices": ["browser", "ios"],
        "supported_services": ["website", "email"],
        "expires_at": None,
        "expected_revision": 0,
        "idempotency_key": "create-global-opt-out",
    }


def test_admin_api_versioned_lifecycle_integrity_and_status(client):
    http, _store = client
    status = http.get("/api/v1/consent/global-opt-out/status")
    assert status.status_code == 200
    assert status.json()["enabled"] is True
    assert status.json()["product_boundaries"]["raw_case_identifiers_persisted"] is False
    assert status.json()["product_boundaries"]["live_device_delivery_proven"] is False

    created = http.post(
        "/api/v1/consent/global-opt-out/configurations",
        json=_create_body(),
    )
    assert created.status_code == 201
    value = created.json()
    assert value["state"] == "draft"
    assert value["configuration_version"] == 1
    configuration_id = value["configuration_id"]

    activated = http.post(
        f"/api/v1/consent/global-opt-out/configurations/{configuration_id}/activate",
        json={
            "expected_revision": value["revision"],
            "idempotency_key": "activate-global-opt-out",
        },
    )
    assert activated.status_code == 200
    assert activated.json()["state"] == "active"

    history = http.get(
        f"/api/v1/consent/global-opt-out/configurations/{configuration_id}/history"
    )
    assert history.status_code == 200
    assert [item["action"] for item in history.json()["history"]] == [
        "created",
        "active",
    ]
    integrity = http.get("/api/v1/consent/global-opt-out/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["ok"] is True


def test_admin_api_rejects_selectors_outside_closed_contract(client):
    http, _store = client
    body = _create_body()
    body["tenant_id"] = "alpha"
    response = http.post(
        "/api/v1/consent/global-opt-out/configurations",
        json=body,
    )
    assert response.status_code == 422


def test_admin_api_returns_explicit_authority_stale_code(client):
    http, store = client
    store._application_authority = lambda *_args: (_ for _ in ()).throw(  # noqa: SLF001
        goo.GlobalOptOutAuthorityStale("publication changed")
    )
    response = http.post(
        "/api/v1/consent/global-opt-out/configurations",
        json=_create_body(),
    )
    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "global_opt_out_authority_stale",
        "message": "publication changed",
    }


def test_store_creation_runs_off_event_loop_with_the_requested_identity(client):
    import asyncio

    http, store = client
    calls = []

    def factory(**kwargs):
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        calls.append(kwargs)
        return store

    http.app.state.global_opt_out_admin_store_factory = factory
    response = http.get("/api/v1/consent/global-opt-out/configurations")
    assert response.status_code == 200
    assert calls[0]["tenant_id"] == "alpha"
    assert calls[0]["principal_ref"].startswith("global-opt-out-admin-")


@pytest.mark.parametrize("failure,status,code", [
    (goo.GlobalOptOutDisabled("module is disabled"), 403, "global_opt_out_disabled"),
    (goo.GlobalOptOutIntegrityError("authority is unavailable"), 503, "global_opt_out_integrity_failure"),
])
def test_store_creation_errors_use_the_operation_error_contract(client, failure, status, code):
    http, _store = client

    def factory(**_kwargs):
        raise failure

    http.app.state.global_opt_out_admin_store_factory = factory
    response = http.get("/api/v1/consent/global-opt-out/configurations")
    assert response.status_code == status
    assert response.json()["detail"]["code"] == code
