"""HTTP setup uses server-owned callback/state and never returns provider secrets."""
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
    rbac.set_role("user:owner", "admin")
    rbac.set_role("user:other", "operator")
    monkeypatch.setattr(connection_oauth, "_post_token", lambda *a: pytest.fail("Unexpected provider request"))
    monkeypatch.setattr(connection_oauth, "_provider_identity", lambda provider, token, **_identity_inputs: {
        "provider": provider, "subject": "fixture-account", "display_name": "Fixture Account",
        "email": "fixture@example.test", "email_verified": True, "hosted_domain": "example.test",
    })
    application = FastAPI()
    @application.middleware("http")
    async def identity(request: Request, call_next):
        name = request.headers.get("X-Test-User", "owner")
        request.state.principal = SimpleNamespace(principal="user:" + name, sub=name)
        with tenant_scope(tenant=request.headers.get("X-Test-Tenant", "tenant-a")):
            return await call_next(request)
    application.include_router(api.router)
    with TestClient(application, base_url="https://lightwork.example", headers={"Origin": "https://lightwork.example"}) as value:
        yield value
    config.reset_config_cache()


def state(client):
    response = client.get("/api/v1/connection-setup")
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "private, no-store"
    return response.json()


def enable(client):
    before = state(client)
    response = client.post("/api/v1/connection-setup/enable", json={"confirm": True, "context": before["context"]})
    assert response.status_code == 200, response.text
    after = state(client)
    assert after["enabled"] and after["context"] != before["context"]
    return after


def app(client):
    current = enable(client)
    response = client.put("/api/v1/connection-setup/application", json={"confirm": True, "context": current["context"], "provider": "google", "client_id": "synthetic-client", "client_secret": "synthetic-client-secret"})
    assert response.status_code == 200, response.text
    assert "synthetic-client-secret" not in response.text
    return response.json()


def test_actual_http_consent_return_and_named_store(monkeypatch, client):
    current = app(client)
    body = {"confirm": True, "context": current["context"], "profile": "google-drive", "name": "customer-drive"}
    authorized = client.post("/api/v1/connection-setup/authorize", json=body)
    assert authorized.status_code == 200, authorized.text
    assert "verifier" not in authorized.text
    assert "redirect_uri=https%3A%2F%2Flightwork.example%2Fconnections" in authorized.json()["authorize_url"]
    monkeypatch.setattr(connection_oauth, "_post_token", lambda *a: {"access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "expires_in": 3600})
    response = client.post("/api/v1/connection-setup/exchange", json={"confirm": True, "context": current["context"], "state": authorized.json()["state"], "code": "synthetic-code"})
    assert response.status_code == 200, response.text
    assert response.json()["connection"]["name"] == "customer-drive"
    assert response.json()["live_provider_verified"] is False
    assert all(secret not in response.text for secret in ("synthetic-access", "synthetic-refresh", "synthetic-client-secret"))
    with tenant_scope(tenant="tenant-a"):
        assert connections.get_connection("customer-drive")["token"] == "synthetic-access"


def test_cross_site_context_role_and_unknown_payload_are_denied_before_exchange(client):
    current = app(client)
    payload = {"confirm": True, "context": current["context"], "profile": "google-drive", "name": "customer-drive"}
    assert client.post("/api/v1/connection-setup/authorize", json=payload, headers={"Origin": "https://attacker.example"}).status_code == 403
    assert client.post("/api/v1/connection-setup/authorize", json=payload, headers={"X-Test-User": "other"}).status_code == 403
    assert client.post("/api/v1/connection-setup/authorize", json=payload, headers={"X-Test-Tenant": "tenant-b"}).status_code == 409
    assert client.post("/api/v1/connection-setup/authorize", json={**payload, "redirect_uri": "https://attacker.example/connections"}).status_code == 422
    assert client.get("/api/v1/connection-setup", headers={"X-Test-Tenant": "tenant-b", "X-Lightwork-Connection-Context": current["context"]}).status_code == 409


def test_a_non_ascii_context_header_is_refused_like_any_other_wrong_one(client):
    # Header text arrives decoded as latin-1, so e-acute is a non-ASCII str.
    for value in ("0" * 64, b"caf\xe9"):
        refused = client.get("/api/v1/connection-setup", headers={"X-Lightwork-Connection-Context": value})
        assert refused.status_code == 409, (value, refused.status_code, refused.text)


def test_provider_failure_is_redacted_and_cannot_replay_consent(client, monkeypatch):
    current = app(client)
    authorized = client.post("/api/v1/connection-setup/authorize", json={"confirm": True, "context": current["context"], "profile": "google-drive", "name": "customer-drive"}).json()
    calls = []
    def fail(*args):
        calls.append(args)
        raise RuntimeError("synthetic-secret-provider-response")
    monkeypatch.setattr(connection_oauth, "_post_token", fail)
    payload = {"confirm": True, "context": current["context"], "state": authorized["state"], "code": "synthetic-code"}
    response = client.post("/api/v1/connection-setup/exchange", json=payload)
    assert response.status_code == 503 and "synthetic-secret-provider-response" not in response.text
    assert client.post("/api/v1/connection-setup/exchange", json=payload).status_code == 409
    assert len(calls) == 1


@pytest.mark.parametrize("name", ["MAVERICK_CONNECTIONS", "LIGHTWORK_CONNECTIONS", "MAVERICK_OAUTH_VAULT", "LIGHTWORK_OAUTH_VAULT"])
def test_enable_respects_current_deployment_denial(client, monkeypatch, name):
    monkeypatch.setenv(name, "0")
    current = state(client)
    response = client.post("/api/v1/connection-setup/enable", json={"confirm": True, "context": current["context"]})
    assert response.status_code == 409
    assert not config.dashboard_overrides_path().exists()


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: rows.append({"kind": kind, **payload}) or True)
    return rows


def test_turning_account_sign_in_off_keeps_saved_connections_and_is_audited(client, audit_rows):
    current = enable(client)
    with tenant_scope(tenant="tenant-a"):
        connections.set_connection("team-jira", connector="jira", base_url="https://example.atlassian.net",
                                   token="synthetic-private-token", owner="user:owner")
    denied = client.post("/api/v1/connection-setup/disable", json={"confirm": True, "context": current["context"], "scope": "all"}, headers={"X-Test-User": "other"})
    assert denied.status_code == 403
    assert client.post("/api/v1/connection-setup/disable", json={"confirm": False, "context": current["context"]}).status_code == 422
    response = client.post("/api/v1/connection-setup/disable", json={"confirm": True, "context": current["context"]})
    assert response.status_code == 200, response.text
    assert response.json() == {"enabled": False, "connections_enabled": True, "reload_required": True}
    after = state(client)
    assert after["enabled"] is False and after["connections_enabled"] is True
    assert [row["name"] for row in after["connections"]] == ["team-jira"]
    assert [(row["section"], row["key"], row["old"], row["new"]) for row in audit_rows] == [("oauth", "vault", True, False)]
    assert audit_rows[0]["_global"] is True and audit_rows[0]["actor"] == "user:owner"
    everything = client.post("/api/v1/connection-setup/disable", json={"confirm": True, "context": after["context"], "scope": "all"})
    assert everything.status_code == 200, everything.text
    assert everything.json()["connections_enabled"] is False
    assert audit_rows[-1]["section"] == "connections" and len(audit_rows) == 2
    with tenant_scope(tenant="tenant-a"):
        assert connections.get_connection("team-jira")["token"] == "synthetic-private-token"
    enable(client)
    assert [row["name"] for row in state(client)["connections"]] == ["team-jira"]


def test_desktop_return_turns_off_on_its_own(client, audit_rows):
    current = enable(client)
    turned_on = client.post("/api/v1/connection-setup/desktop-return/enable", json={"confirm": True, "context": current["context"]})
    assert turned_on.status_code == 200, turned_on.text
    current = state(client)
    assert current["desktop_return_enabled"] is True
    response = client.post("/api/v1/connection-setup/desktop-return/disable", json={"confirm": True, "context": current["context"]})
    assert response.status_code == 200, response.text
    after = state(client)
    assert after["desktop_return_enabled"] is False and after["enabled"] is True
    assert [(row["section"], row["key"]) for row in audit_rows] == [("oauth", "desktop_return")]


@pytest.mark.parametrize("name", ["MAVERICK_OAUTH_VAULT", "LIGHTWORK_OAUTH_VAULT"])
def test_turning_off_respects_a_deployment_that_keeps_it_on(client, monkeypatch, audit_rows, name):
    current = enable(client)
    monkeypatch.setenv(name, "1")
    current = state(client)
    response = client.post("/api/v1/connection-setup/disable", json={"confirm": True, "context": current["context"]})
    assert response.status_code == 409
    assert "Deployment settings" in response.json()["detail"]
    assert state(client)["enabled"] is True and audit_rows == []


def test_a_refused_audit_record_undoes_turning_off(client, monkeypatch):
    import maverick.audit as audit

    current = enable(client)

    def refuse(kind, **payload):
        raise audit.AuditRefused("audit sink unavailable")

    monkeypatch.setattr(audit, "audit_event", refuse)
    response = client.post("/api/v1/connection-setup/disable", json={"confirm": True, "context": current["context"]})
    assert response.status_code == 503
    assert state(client)["enabled"] is True


def test_employee_self_connection_cannot_manage_app_registration(monkeypatch, client):
    monkeypatch.setattr(connection_oauth, "self_connect_profiles", lambda: frozenset({"google-drive"}))
    response = client.get("/api/v1/connection-setup", headers={"X-Test-User": "other"})
    assert response.status_code == 200
    data = response.json()
    assert [row["id"] for row in data["profiles"]] == ["google-drive"]
    assert data["can_manage_applications"] is False
    assert data["can_manage_keys"] is False
    denied = client.put("/api/v1/connection-setup/application", headers={"X-Test-User": "other"}, json={
        "confirm": True, "context": data["context"], "provider": "google", "client_id": "not-allowed"})
    assert denied.status_code == 403


def test_employee_overview_refuses_when_self_connection_is_not_approved(monkeypatch, client):
    monkeypatch.setattr(connection_oauth, "self_connect_profiles", lambda: frozenset())
    response = client.get("/api/v1/connection-setup", headers={"X-Test-User": "other"})
    assert response.status_code == 403


def test_self_connection_policy_fails_closed_when_disabled(monkeypatch):
    monkeypatch.setattr(config, "config_source_errors", lambda **kwargs: [])
    monkeypatch.setattr(config, "load_config", lambda: {"connections": {"allow_self_connect": False, "self_connect_profiles": "google-drive"}})
    assert not connection_oauth.self_connect_profiles()
    with pytest.raises(PermissionError):
        connection_oauth._self_connect_allowed("google-drive")
