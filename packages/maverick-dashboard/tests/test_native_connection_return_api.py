"""Native callback profile over authenticated API and real sealed local stores."""
from __future__ import annotations

import os
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import config, connection_oauth, connections
from maverick.paths import tenant_scope
from maverick_dashboard import connection_setup_api as api
from maverick_dashboard import rbac

NATIVE = "http://127.0.0.1:8766/connections"


@pytest.fixture
def client(tmp_path, monkeypatch):
    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_DESKTOP_OAUTH_TICKET_KEY", "07" * 32)
    config.config_path().write_text("[connections]\nenable=true\n[oauth]\nvault=true\ndesktop_return=true\n")
    rbac.set_role("user:owner", "admin")
    monkeypatch.setattr(connection_oauth, "_post_token", lambda *a: pytest.fail("Unexpected provider request"))
    app = FastAPI()

    @app.middleware("http")
    async def identity(request: Request, call_next):
        name = request.headers.get("X-Test-User", "owner")
        request.state.principal = SimpleNamespace(principal="user:" + name, sub=name)
        with tenant_scope(tenant=request.headers.get("X-Test-Tenant", "tenant-a")):
            return await call_next(request)

    app.include_router(api.router)
    with TestClient(app, base_url="http://127.0.0.1:8765", headers={"Origin": "http://127.0.0.1:8765"}) as value:
        yield value
    config.reset_config_cache()


def registration(client, *, native=True):
    context = client.get("/api/v1/connection-setup").json()["context"]
    response = client.put("/api/v1/connection-setup/application", json={
        "confirm": True, "context": context, "provider": "google", "client_id": "synthetic-client",
        "client_secret": "synthetic-secret", "desktop_return": native,  # pragma: allowlist secret
    })
    assert response.status_code == 200, response.text
    return response.json()


def prepare(client, current, *, name="drive"):
    return client.post("/api/v1/connection-setup/desktop-return/prepare", json={
        "confirm": True, "context": current["context"], "profile": "google-drive", "name": name,
    })


def start(client, current, *, name="drive", handle="d" * 64, ticket=None):
    if ticket is None:
        prepared = prepare(client, current, name=name)
        if prepared.status_code != 200:
            return prepared
        ticket = prepared.json()["prepare_ticket"]
    response = client.post("/api/v1/connection-setup/authorize", json={
        "confirm": True, "context": current["context"], "profile": "google-drive", "name": name,
        "return_profile": "desktop-loopback-v1", "native_handle": handle, "prepare_ticket": ticket,
    })
    return response


def test_native_callback_requires_reviewed_registration_and_exact_profile(client, monkeypatch):
    current = registration(client)
    started = start(client, current)
    assert started.status_code == 200, started.text
    assert parse_qs(urlsplit(started.json()["authorize_url"]).query)["redirect_uri"] == [NATIVE]
    calls = []
    monkeypatch.setattr(connection_oauth, "_post_token", lambda *a: calls.append(a) or {
        "access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "expires_in": 3600,
    })
    monkeypatch.setattr(connection_oauth, "_provider_identity", lambda *a, **_identity_inputs: {
        "provider": "google", "subject": "native-fixture-account",
        "display_name": "Native Fixture", "email": "native@example.test",
        "email_verified": True, "hosted_domain": "example.test",
    })
    payload = {"confirm": True, "context": current["context"], "state": started.json()["state"], "code": "synthetic-code"}
    assert client.post("/api/v1/connection-setup/exchange", json=payload).status_code == 409
    assert not calls
    response = client.post("/api/v1/connection-setup/exchange", json={**payload, "return_profile": "desktop-loopback-v1"})
    assert response.status_code == 200, response.text
    assert len(calls) == 1 and calls[0][1]["redirect_uri"] == NATIVE
    assert "synthetic-access" not in response.text
    assert client.post("/api/v1/connection-setup/exchange", json={**payload, "return_profile": "desktop-loopback-v1"}).status_code == 409
    assert len(calls) == 1


def test_native_tickets_bind_dashboard_identity_consent_pkce_and_receiver_before_consent(client):
    current = registration(client)
    prepared = prepare(client, current)
    assert prepared.status_code == 200, prepared.text
    ticket = prepared.json()["prepare_ticket"]
    with tenant_scope(tenant="tenant-a"):
        assert connection_oauth._load()["consents"] == {}
    prepare_payload = connection_oauth._read_native_ticket(ticket, "prepare")
    assert prepare_payload["context"] == current["context"]
    assert prepare_payload["tenant_sha256"] == connection_oauth._digest("tenant-a")
    assert prepare_payload["principal_sha256"] == connection_oauth._digest("user:owner")
    assert prepare_payload["client_id_sha256"] == connection_oauth._digest("synthetic-client")
    assert prepare_payload["scopes"] == connection_oauth.PROFILES["google-drive"]["scopes"]

    tampered = ticket[:-1] + ("0" if ticket[-1] != "0" else "1")
    assert start(client, current, ticket=tampered).status_code == 409
    assert start(client, current, name="other-drive", ticket=ticket).status_code == 409
    with tenant_scope(tenant="tenant-a"):
        assert connection_oauth._load()["consents"] == {}

    started = start(client, current, ticket=ticket)
    assert started.status_code == 200, started.text
    result = started.json()
    launch = connection_oauth._read_native_ticket(result["native_launch_ticket"], "launch")
    query = parse_qs(urlsplit(result["authorize_url"]).query)
    assert launch["consent_sha256"] == connection_oauth._digest(result["state"])
    assert launch["state"] == result["state"]
    assert launch["pkce_challenge"] == query["code_challenge"][0]
    assert launch["authorize_url_sha256"] == connection_oauth._digest(result["authorize_url"])
    assert launch["native_handle_sha256"] == connection_oauth._digest("d" * 64)
    assert launch["prepare_ticket_sha256"] == connection_oauth._digest(ticket)


def test_native_profile_off_or_registration_not_confirmed_denies_before_consent(client):
    current = registration(client, native=False)
    assert start(client, current).status_code == 409
    with tenant_scope(tenant="tenant-a"):
        assert connection_oauth._load()["consents"] == {}
    config.config_path().write_text("[connections]\nenable=true\n[oauth]\nvault=true\n")
    config.reset_config_cache()
    current = client.get("/api/v1/connection-setup").json()
    assert start(client, current).status_code == 409


def test_native_cancellation_retires_only_original_context_and_cannot_exchange(client):
    current = registration(client)
    started = start(client, current).json()
    payload = {"confirm": True, "context": current["context"], "state": started["state"], "return_profile": "desktop-loopback-v1"}
    assert client.post("/api/v1/connection-setup/cancel", json=payload, headers={"X-Test-Tenant": "tenant-b"}).status_code == 409
    response = client.post("/api/v1/connection-setup/cancel", json=payload)
    assert response.status_code == 200 and response.json()["cancelled"] is True
    # A committed cancellation whose HTTP response was lost remains
    # confirmable on reload without reopening provider authority.
    repeated = client.post("/api/v1/connection-setup/cancel", json=payload)
    assert repeated.status_code == 200 and repeated.json()["cancelled"] is True
    assert client.post("/api/v1/connection-setup/exchange", json={**payload, "code": "synthetic-code"}).status_code == 409
    with tenant_scope(tenant="tenant-a"):
        assert connections.list_connections() == []


def test_thirty_two_denial_cycles_retire_every_consent_without_changing_saved_credentials(client):
    current = registration(client)
    with tenant_scope(tenant="tenant-a"):
        connections.set_connection("preserved", connector="gdrive", base_url="https://www.googleapis.com",
                                   token="synthetic-existing-token", owner="user:owner")
        before = connections._load()["preserved"]
    states, tickets = set(), set()
    for _ in range(32):
        prepared = prepare(client, current)
        assert prepared.status_code == 200, prepared.text
        started = start(client, current, ticket=prepared.json()["prepare_ticket"])
        assert started.status_code == 200, started.text
        result = started.json()
        states.add(result["state"])
        tickets.add(result["native_launch_ticket"])
        cancelled = client.post("/api/v1/connection-setup/cancel", json={
            "confirm": True, "context": current["context"], "state": result["state"],
            "return_profile": "desktop-loopback-v1",
        })
        assert cancelled.status_code == 200 and cancelled.json()["cancelled"] is True
        with tenant_scope(tenant="tenant-a"):
            retained = connection_oauth._load()["consents"]
            assert retained
            assert all(row.get("retired") is True for row in retained.values())
            assert len(retained) <= connection_oauth._RETIRED_CONSENT_LIMIT
            assert connections._load()["preserved"] == before
    assert len(states) == 32 and len(tickets) == 32


def test_cancelled_attempt_cannot_exchange_after_a_new_attempt_starts(client, monkeypatch):
    current = registration(client)
    first = start(client, current).json()
    cancel = {"confirm": True, "context": current["context"], "state": first["state"],
              "return_profile": "desktop-loopback-v1"}
    assert client.post("/api/v1/connection-setup/cancel", json=cancel).json()["cancelled"] is True
    second = start(client, current).json()
    calls = []
    monkeypatch.setattr(connection_oauth, "_post_token", lambda *args: calls.append(args))
    late = client.post("/api/v1/connection-setup/exchange", json={
        **cancel, "code": "synthetic-late-code",
    })
    assert late.status_code == 409 and calls == []
    assert client.post("/api/v1/connection-setup/cancel", json={
        **cancel, "state": second["state"],
    }).json()["cancelled"] is True


@pytest.mark.parametrize("origin", ["http://localhost:8765", "http://127.0.0.1:9999", "https://lightwork.example"])
def test_remote_or_alternate_dashboard_origin_cannot_select_native_return(client, origin):
    current = registration(client)
    response = client.post(origin + "/api/v1/connection-setup/authorize", headers={"Origin": origin}, json={
        "confirm": True, "context": current["context"], "profile": "google-drive", "name": "drive",
        "return_profile": "desktop-loopback-v1",
    })
    assert response.status_code == 409


@pytest.mark.parametrize("change", ["registration", "principal", "tenant", "role", "environment", "connection"])
def test_native_finish_rechecks_current_authority_and_revisions_before_provider(client, monkeypatch, change):
    current = registration(client)
    started = start(client, current).json()
    headers = {}
    if change == "registration":
        row = current["applications"][0]
        result = client.put("/api/v1/connection-setup/application", json={
            "confirm": True, "context": current["context"], "provider": "google",
            "client_id": "rotated-client", "expected_revision": row["revision"], "desktop_return": True,
        })
        assert result.status_code == 200
    elif change == "principal":
        rbac.set_role("user:other", "admin")
        headers["X-Test-User"] = "other"
    elif change == "tenant":
        headers["X-Test-Tenant"] = "tenant-b"
    elif change == "role":
        rbac.set_tenant_role("tenant-a", "user:owner", "viewer")
    elif change == "environment":
        # Still enabled, but a newly explicit deployment policy must invalidate
        # the previously reviewed context rather than silently reusing it.
        monkeypatch.setenv("MAVERICK_OAUTH_DESKTOP_RETURN", "1")
    else:
        with tenant_scope(tenant="tenant-a"):
            connections.set_connection("drive", connector="gdrive", base_url="https://www.googleapis.com",
                                        token="synthetic-existing-token", owner="user:owner")
    response = client.post("/api/v1/connection-setup/exchange", headers=headers, json={
        "confirm": True, "context": current["context"], "state": started["state"], "code": "synthetic-code",
        "return_profile": "desktop-loopback-v1",
    })
    assert response.status_code in {403, 409}, response.text


def test_only_operator_can_enable_native_profile_and_explicit_policy_denies_before_write(client, monkeypatch):
    rbac.set_role("user:customer", "viewer")
    rbac.set_tenant_role("tenant-a", "user:customer", "admin")
    headers = {"X-Test-User": "customer"}
    current = client.get("/api/v1/connection-setup", headers=headers).json()
    def blocked_writes(*args, **kwargs):
        pytest.fail("Unauthorized configuration write")
    with monkeypatch.context() as scope:
        scope.setattr(api.settings_store, "_locked", blocked_writes)
        response = client.post("/api/v1/connection-setup/desktop-return/enable", headers=headers,
                               json={"confirm": True, "context": current["context"]})
        assert response.status_code == 403
        scope.setenv("MAVERICK_OAUTH_DESKTOP_RETURN", "0")
        current = client.get("/api/v1/connection-setup").json()
        response = client.post("/api/v1/connection-setup/desktop-return/enable",
                               json={"confirm": True, "context": current["context"]})
        assert response.status_code == 409
    config.config_path().write_text("[connections]\nenable=true\n[oauth]\nvault=true\n")
    config.reset_config_cache()
    current = client.get("/api/v1/connection-setup").json()
    assert current["desktop_return_enabled"] is False
    result = client.post("/api/v1/connection-setup/desktop-return/enable", json={"confirm": True, "context": current["context"]})
    assert result.status_code == 200 and result.json() == {"enabled": True, "reload_required": True}
    refreshed = client.get("/api/v1/connection-setup").json()
    assert refreshed["desktop_return_enabled"] is True and refreshed["context"] != current["context"]
