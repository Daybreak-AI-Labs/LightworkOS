"""Actual API gates separate workspace consent from operator registration."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import config, connection_oauth, connections
from maverick.paths import tenant_scope
from maverick_dashboard import connection_setup_api as api
from maverick_dashboard import rbac


@pytest.fixture
def client(tmp_path, monkeypatch):
    import os
    for key in tuple(os.environ):
        if key.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    config.config_path().write_text("[connections]\nenable=true\n[oauth]\nvault=true\n")
    rbac.set_role("user:operator", "admin")
    rbac.set_role("user:customer", "viewer")
    rbac.set_tenant_role("tenant-a", "user:customer", "admin")
    rbac.set_tenant_role("tenant-b", "user:customer", "admin")
    monkeypatch.setattr(connection_oauth, "_post_token", lambda *a: pytest.fail("Unexpected provider request"))
    monkeypatch.setattr(connection_oauth, "_provider_identity", lambda provider, token, **_identity_inputs: {
        "provider": provider, "subject": "registration-fixture-account",
        "display_name": "Registration Fixture", "email": "registration@example.test",
        "email_verified": True, "hosted_domain": "example.test",
    })
    app = FastAPI()
    @app.middleware("http")
    async def identity(request: Request, call_next):
        name = request.headers.get("X-Test-User", "customer")
        request.state.principal = SimpleNamespace(principal="user:" + name, sub=name)
        with tenant_scope(tenant=request.headers.get("X-Test-Tenant", "tenant-a")):
            return await call_next(request)
    app.include_router(api.router)
    with TestClient(app, base_url="https://lightwork.example", headers={"Origin": "https://lightwork.example"}) as value:
        yield value
    config.reset_config_cache()


def overview(client, **headers):
    response = client.get("/api/v1/connection-setup", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def register(client):
    headers = {"X-Test-User": "operator"}
    current = overview(client, **headers)
    response = client.put("/api/v1/connection-setup/application", headers=headers, json={"confirm": True, "context": current["context"], "provider": "google", "client_id": "synthetic-operator-client", "client_secret": "synthetic-operator-secret"})
    assert response.status_code == 200, response.text
    return response.json()


def test_operator_registration_customer_availability_and_real_consent(client, monkeypatch):
    operator = register(client)
    assert operator["can_manage_applications"] is True
    assert operator["applications"][0]["client_id"] == "synthetic-operator-client"
    current = overview(client)
    assert current["can_manage_applications"] is False
    assert len(current["workspace_context"]) == 64
    assert current["workspace_context"] != operator["workspace_context"]
    assert current["applications"] == [{"provider": "google", "configured": True, "registration_scope": "workspace"}]
    assert "synthetic-operator" not in str(current)
    started = client.post("/api/v1/connection-setup/authorize", json={"confirm": True, "context": current["context"], "profile": "google-drive", "name": "drive"})
    assert started.status_code == 200, started.text
    monkeypatch.setattr(connection_oauth, "_post_token", lambda *a: {"access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "expires_in": 3600})
    response = client.post("/api/v1/connection-setup/exchange", json={"confirm": True, "context": current["context"], "state": started.json()["state"], "code": "synthetic-code"})
    assert response.status_code == 200, response.text
    assert response.json()["connection"]["owner"] == "user:customer"
    assert "synthetic-access" not in response.text
    with tenant_scope(tenant="tenant-a"):
        assert connections.get_connection("drive")["oauth"]["application_key"]


@pytest.mark.parametrize("path", ["enable", "application"])
def test_workspace_admin_cannot_write_operator_settings(client, monkeypatch, path):
    current = overview(client)
    monkeypatch.setattr(connection_oauth, "save_workspace_application", lambda *a, **k: pytest.fail("Unauthorized registration write"))
    monkeypatch.setattr(api.settings_store, "_locked", lambda *a, **k: pytest.fail("Unauthorized configuration mutation"))
    payload = {"confirm": True, "context": current["context"]}
    if path == "application":
        payload.update(provider="google", client_id="synthetic-client", client_secret="synthetic-secret")
    response = client.request("PUT" if path == "application" else "POST", "/api/v1/connection-setup/" + path, json=payload)
    assert response.status_code == 403


def test_workspace_demotion_denies_before_store_reads_even_for_global_admin(client, monkeypatch):
    rbac.set_tenant_role("tenant-a", "user:operator", "viewer")
    reads = []
    monkeypatch.setattr(connection_oauth, "available_applications", lambda *a: reads.append(a) or [])
    monkeypatch.setattr(connection_oauth, "managed_applications", lambda *a: reads.append(a) or [])
    response = client.get("/api/v1/connection-setup", headers={"X-Test-User": "operator"})
    assert response.status_code == 403
    assert reads == []


def test_shared_registration_never_crosses_workspace(client):
    register(client)
    current = overview(client, **{"X-Test-Tenant": "tenant-b"})
    assert current["applications"] == []
    response = client.post("/api/v1/connection-setup/authorize", headers={"X-Test-Tenant": "tenant-b"}, json={"confirm": True, "context": current["context"], "profile": "google-drive", "name": "drive"})
    assert response.status_code == 409
    assert "synthetic-operator" not in response.text


def test_operators_legacy_personal_registration_is_explicit_availability_not_shared_edit(client):
    with tenant_scope(tenant="tenant-a"):
        connection_oauth.save_application("user:operator", provider="google", client_id="synthetic-legacy-client", client_secret="synthetic-legacy-secret", expected_revision="")
    operator = overview(client, **{"X-Test-User": "operator"})
    assert operator["applications"] == [{"provider": "google", "configured": True, "registration_scope": "legacy_owner"}]
    assert overview(client)["applications"] == []
