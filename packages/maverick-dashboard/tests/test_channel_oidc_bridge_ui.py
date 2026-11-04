"""A person must confirm the observed chat account in a live OIDC session."""
from __future__ import annotations

import re
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import channel_oidc_bridge as bridge
from maverick_dashboard.app import app
from maverick_dashboard.oidc_login import SESSION_COOKIE, mint_browser_session

ISSUER = "https://identity.example.test"
AUDIENCE = "lightwork"
SECRET = "0123456789abcdef0123456789abcdef"  # pragma: allowlist secret
ACCOUNT = "a" * 64


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import audit, config, world_model
    from maverick_dashboard import app as app_mod

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("")
    monkeypatch.setenv("MAVERICK_OIDC_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("MAVERICK_OIDC_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_ID", "test-client")
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("MAVERICK_OIDC_REDIRECT_URI", "http://127.0.0.1/auth/callback")
    monkeypatch.setenv("MAVERICK_OIDC_SESSION_SECRET", SECRET)
    monkeypatch.setenv("MAVERICK_OIDC_AUTHORIZATION_ENDPOINT", ISSUER + "/authorize")
    monkeypatch.setenv("MAVERICK_OIDC_TOKEN_ENDPOINT", ISSUER + "/token")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    monkeypatch.setattr(audit, "audit_event", lambda *args, **kwargs: True)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app_mod._world_cache.clear()
    config.reset_config_cache()
    from maverick_dashboard import rbac

    for principal in ("alice", "bob", "attacker", "victim"):
        rbac.set_role(f"user:{principal}", "operator")
    result = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"},
                        follow_redirects=False)
    yield result
    app_mod._world_cache.clear()
    config.reset_config_cache()


def _sign_in(client, sub="alice", issuer=ISSUER):
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"),
                              headers={"user-agent": "test"})
    cookie = mint_browser_session(
        request, sub=sub, secret=SECRET, via="session", mfa=False, ttl=3600,
        extra={"oidc_issuer": issuer, "oidc_audience": AUDIENCE},
    )
    client.cookies.set(SESSION_COOKIE, cookie)


def test_signed_in_person_confirms_the_exact_observed_account(client):
    _sign_in(client)
    started = client.post("/me/channels/oidc/start", data={"channel": "slack"})
    assert started.status_code == 200, started.text
    assert started.headers["cache-control"] == "no-store"
    code = re.search(r"LIGHTWORK CONNECT ([A-Za-z0-9_-]{43})", started.text).group(1)
    assert bridge.observe("slack", ACCOUNT, "TABC123", "UABC123",
                          "LIGHTWORK CONNECT " + code).startswith("Account found")
    pending = bridge.pending("alice", ISSUER, AUDIENCE)
    page = client.get("/me")
    assert "Confirm the account we found" in page.text
    assert "UABC123" in page.text
    assert client.post("/me/channels/oidc/confirm", data={
        "challenge_id": pending[0]["id"],
    }).status_code == 303
    assert bridge.resolve("slack", ACCOUNT, "TABC123", "UABC123") == "user:alice"
    row = bridge.links_for("alice", ISSUER, AUDIENCE)[0]
    assert client.post("/me/channels/oidc/unlink", data={"link_id": row["id"]}).status_code == 303
    assert bridge.resolve("slack", ACCOUNT, "TABC123", "UABC123") is None


def test_viewer_can_disconnect_but_is_not_offered_connect_or_confirm(client):
    from maverick_dashboard import rbac

    _sign_in(client)
    linked = bridge.begin("alice", ISSUER, AUDIENCE, "slack")
    bridge.observe("slack", ACCOUNT, "TABC123", "UABC123",
                   "LIGHTWORK CONNECT " + linked["code"])
    active = bridge.confirm("alice", ISSUER, AUDIENCE, linked["id"])
    pending = bridge.begin("alice", ISSUER, AUDIENCE, "teams")
    bridge.observe("teams", ACCOUNT, "11111111-1111-1111-1111-111111111111",
                   "22222222-2222-2222-2222-222222222222",
                   "LIGHTWORK CONNECT " + pending["code"])
    rbac.set_role("user:alice", "viewer", actor="user:admin")

    page = client.get("/me")
    assert page.status_code == 200
    assert 'action="/me/channels/oidc/start"' not in page.text
    assert 'action="/me/channels/oidc/confirm"' not in page.text
    assert 'action="/me/channels/oidc/unlink"' in page.text
    assert client.post("/me/channels/oidc/start", data={"channel": "slack"}).status_code == 403
    assert client.post("/me/channels/oidc/confirm", data={
        "challenge_id": pending["id"],
    }).status_code == 403
    assert client.post("/me/channels/oidc/unlink", data={
        "link_id": active["id"],
    }).status_code == 303


def test_get_url_cannot_substitute_another_persons_connection_code(client):
    _sign_in(client, sub="attacker")
    started = client.post("/me/channels/oidc/start", data={"channel": "slack"})
    attacker_code = re.search(r"LIGHTWORK CONNECT ([A-Za-z0-9_-]{43})", started.text).group(1)
    _sign_in(client, sub="victim")
    page = client.get(
        f"/me?bridge_code={attacker_code}&bridge_channel=slack"
        "&code=ATTACK12&channel=slack"
    )
    assert page.status_code == 200
    assert attacker_code not in page.text
    assert "ATTACK12" not in page.text
    assert "LIGHTWORK CONNECT" not in page.text


def test_other_session_and_missing_or_stale_oidc_session_cannot_confirm(client):
    assert client.post("/me/channels/oidc/start", data={"channel": "slack"}).status_code in {401, 403}
    _sign_in(client)
    started = client.post("/me/channels/oidc/start", data={"channel": "slack"})
    code = re.search(r"LIGHTWORK CONNECT ([A-Za-z0-9_-]{43})", started.text).group(1)
    bridge.observe("slack", ACCOUNT, "TABC123", "UABC123", "LIGHTWORK CONNECT " + code)
    challenge_id = bridge.pending("alice", ISSUER, AUDIENCE)[0]["id"]
    _sign_in(client, sub="bob")
    assert client.post("/me/channels/oidc/confirm", data={
        "challenge_id": challenge_id,
    }).status_code == 409
    assert bridge.resolve("slack", ACCOUNT, "TABC123", "UABC123") is None
    _sign_in(client, issuer="https://stale.example.test")
    assert client.post("/me/channels/oidc/start", data={"channel": "slack"}).status_code == 403
    _sign_in(client)
    assert client.post("/me/channels/oidc/confirm", data={
        "challenge_id": challenge_id,
    }, headers={"Origin": "http://other.example.test"}).status_code == 403
    assert client.post("/me/channels/oidc/confirm", data={
        "challenge_id": challenge_id,
    }, headers={"Authorization": "Bearer invalid.jwt"}).status_code == 401


@pytest.mark.parametrize("source", ["principal_selection", "principal_isolation"])
def test_selected_or_virtual_workspace_cannot_issue_bot_code(client, source):
    from maverick_dashboard import me_api

    _sign_in(client)
    request = SimpleNamespace(state=SimpleNamespace(workspace_tenant_source=source))
    assert me_api._bridge_identity(request) is None
    with pytest.raises(HTTPException, match="not connected to the selected workspace") as exc:
        me_api._require_bridge_identity(request)
    assert exc.value.status_code == 409


def test_slack_only_channels_page_can_revoke_confirmed_link(client, monkeypatch):
    from maverick_dashboard import settings_store

    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:alice")
    monkeypatch.setattr(settings_store, "CHANNELS",
                        [spec for spec in settings_store.CHANNELS if spec["name"] == "slack"])
    _sign_in(client)
    started = bridge.begin("alice", ISSUER, AUDIENCE, "slack")
    bridge.observe("slack", ACCOUNT, "TABC123", "UABC123",
                   "LIGHTWORK CONNECT " + started["code"])
    link = bridge.confirm("alice", ISSUER, AUDIENCE, started["id"])
    page = client.get("/channels")
    assert page.status_code == 200, page.text
    assert "Chat account connections" in page.text
    assert "UABC123" in page.text and 'action="/channels/oidc/revoke"' in page.text
    revoked = client.post("/channels/oidc/revoke", data={"link_id": link["id"]})
    assert revoked.status_code == 303
    assert bridge.resolve("slack", ACCOUNT, "TABC123", "UABC123") is None


def test_channels_page_reports_unreadable_bridge_store(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:alice")
    _sign_in(client)

    def unreadable():
        raise bridge.BridgeError("corrupt store")

    monkeypatch.setattr(bridge, "all_links", unreadable)
    page = client.get("/channels")
    assert page.status_code == 200
    assert "Chat account connection records are unavailable" in page.text
    assert "No chat accounts are connected for tasks" not in page.text
