"""A provider receipt plus explicit OIDC confirmation is needed for chat work."""
from __future__ import annotations

import asyncio
import json

import pytest
from maverick import channel_identities, oidc
from maverick import channel_oidc_bridge as bridge
from maverick.server import Server
from maverick_channels.base import IncomingMessage

ISSUER = "https://identity.example.test"
AUDIENCE = "lightwork-chat"
TEAM = "TABC123"
SENDER = "UABC123"
ACCOUNT = "a" * 64
TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
AAD_ID = "12345678-abcd-abcd-abcd-1234567890ab"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import audit
    from maverick_dashboard import auth, rbac, scim_groups, session_revocation

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    monkeypatch.setattr(bridge, "load_oidc_config", lambda: oidc.OIDCConfig(
        enabled=True, issuer=ISSUER, audience=AUDIENCE,
    ))
    monkeypatch.setattr(audit, "audit_event", lambda *args, **kwargs: True)
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "operator")
    monkeypatch.setattr(rbac, "get_tenant_role", lambda tenant, principal: "operator")
    monkeypatch.setattr(scim_groups, "active_for_principal", lambda principal: True)
    monkeypatch.setattr(session_revocation, "is_revoked", lambda sub, iat: False)


def _confirmed(channel="slack", account=ACCOUNT, tenant=TEAM, sender=SENDER):
    started = bridge.begin("alice", ISSUER, AUDIENCE, channel)
    assert bridge.observe(channel, account, tenant, sender,
                          "LIGHTWORK CONNECT " + started["code"]).startswith("Account found")
    assert bridge.resolve(channel, account, tenant, sender) is None
    pending = bridge.pending("alice", ISSUER, AUDIENCE)
    assert [item["id"] for item in pending] == [started["id"]]
    bridge.confirm("alice", ISSUER, AUDIENCE, started["id"])
    return started


def test_slack_requires_confirmation_and_exact_provider_tuple(monkeypatch):
    from maverick_dashboard import rbac, scim_groups, session_revocation

    # A legacy admin mapping and a correct one-time code are each insufficient.
    channel_identities.link("slack", SENDER, "user:alice", actor="admin")
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) is None
    started = _confirmed()
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) == "user:alice"
    assert bridge.observe("slack", ACCOUNT, TEAM, "UOTHER",
                          "LIGHTWORK CONNECT " + started["code"]).startswith("That connection code")
    for account, tenant, sender in [("b" * 64, TEAM, SENDER), (ACCOUNT, "TOTHER", SENDER),
                                    (ACCOUNT, TEAM, "UOTHER")]:
        assert bridge.resolve("slack", account, tenant, sender) is None
    monkeypatch.setattr(scim_groups, "active_for_principal", lambda principal: False)
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) is None
    monkeypatch.setattr(scim_groups, "active_for_principal", lambda principal: True)
    monkeypatch.setattr(rbac, "get_tenant_role", lambda tenant, principal: "viewer")
    monkeypatch.setattr("maverick_dashboard.auth.global_role_for_principal", lambda principal: "viewer")
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) is None
    monkeypatch.setattr(rbac, "get_tenant_role", lambda tenant, principal: "operator")
    monkeypatch.setattr("maverick_dashboard.auth.global_role_for_principal", lambda principal: "operator")
    monkeypatch.setattr(session_revocation, "is_revoked", lambda sub, iat: True)
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) is None


def test_teams_uses_immutable_entra_sender_and_relink_after_revoke(monkeypatch):
    _confirmed("teams", "c" * 64, TENANT_ID, AAD_ID)
    assert bridge.resolve("teams", "c" * 64, TENANT_ID, AAD_ID) == "user:alice"
    assert bridge.resolve("teams", "c" * 64, TENANT_ID, "99999999-abcd-abcd-abcd-1234567890ab") is None
    with pytest.raises(bridge.BridgeError, match="immutable Entra"):
        bridge.resolve("teams", "c" * 64, TENANT_ID, "alice@example.test")
    row = bridge.links_for("alice", ISSUER, AUDIENCE)[0]
    assert bridge.revoke(row["id"], actor="user:admin")
    assert bridge.resolve("teams", "c" * 64, TENANT_ID, AAD_ID) is None
    _confirmed("teams", "c" * 64, TENANT_ID, AAD_ID)
    assert bridge.resolve("teams", "c" * 64, TENANT_ID, AAD_ID) == "user:alice"
    row = bridge.links_for("alice", ISSUER, AUDIENCE)[0]
    assert bridge.unlink("alice", ISSUER, AUDIENCE, row["id"])
    assert bridge.resolve("teams", "c" * 64, TENANT_ID, AAD_ID) is None


def test_workspace_and_oidc_policy_changes_refuse_old_link(monkeypatch):
    _confirmed()
    monkeypatch.setenv("MAVERICK_TENANT", "another-workspace")
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) is None
    monkeypatch.delenv("MAVERICK_TENANT")
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    with pytest.raises(bridge.BridgeError, match="workspace-bound"):
        bridge.resolve("slack", ACCOUNT, TEAM, SENDER)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER")
    monkeypatch.setattr(bridge, "load_oidc_config", lambda: oidc.OIDCConfig(
        enabled=True, issuer="https://different.example.test", audience=AUDIENCE,
    ))
    with pytest.raises(bridge.BridgeError, match="provider has changed"):
        bridge.resolve("slack", ACCOUNT, TEAM, SENDER)


def test_bound_workspace_uses_global_role_only_when_no_workspace_role(monkeypatch):
    from maverick_dashboard import auth, rbac

    monkeypatch.setenv("MAVERICK_TENANT", "bound-workspace")
    monkeypatch.setattr(rbac, "get_tenant_role", lambda tenant, principal: None)
    _confirmed()
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) == "user:alice"

    monkeypatch.setattr(rbac, "get_tenant_role", lambda tenant, principal: "viewer")
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) is None
    with pytest.raises(bridge.BridgeError, match="role cannot start"):
        bridge.begin("alice", ISSUER, AUDIENCE, "teams")

    def unreadable(tenant, principal):
        raise RuntimeError("tenant roles unavailable")

    monkeypatch.setattr(rbac, "get_tenant_role", unreadable)
    with pytest.raises(bridge.BridgeError, match="access could not be checked"):
        bridge.resolve("slack", ACCOUNT, TEAM, SENDER)
    monkeypatch.setattr(auth, "is_dashboard_admin", lambda principal: True)
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) == "user:alice"


def test_corrupt_store_and_other_installation_fail_closed(monkeypatch, tmp_path):
    _confirmed()
    bridge.store_path().write_text("{broken", encoding="utf-8")
    with pytest.raises(bridge.BridgeError, match="unavailable"):
        bridge.resolve("slack", ACCOUNT, TEAM, SENDER)
    bridge.store_path().write_text(json.dumps({
        "installation": "elsewhere", "challenges": {}, "links": {},
    }), encoding="utf-8")
    with pytest.raises(bridge.BridgeError, match="unavailable"):
        bridge.resolve("slack", ACCOUNT, TEAM, SENDER)


def test_store_bounds_and_expired_challenge_pruning(monkeypatch):
    monkeypatch.setattr(bridge, "MAX_CHALLENGES", 1)
    first = bridge.begin("alice", ISSUER, AUDIENCE, "slack")
    with pytest.raises(bridge.BridgeError, match="busy"):
        bridge.begin("bob", ISSUER, AUDIENCE, "slack")
    monkeypatch.setattr(bridge, "CHALLENGE_TTL", -1)
    bridge.begin("alice", ISSUER, AUDIENCE, "slack")
    monkeypatch.setattr(bridge, "CHALLENGE_TTL", 600)
    second = bridge.begin("bob", ISSUER, AUDIENCE, "slack")
    assert first["id"] not in bridge._read()["challenges"]
    assert second["id"] in bridge._read()["challenges"]
    bridge.store_path().write_text("x" * (bridge.MAX_STORE_BYTES + 1), encoding="utf-8")
    with pytest.raises(bridge.BridgeError, match="safe size"):
        bridge.resolve("slack", ACCOUNT, TEAM, SENDER)


def test_failed_write_or_confirmation_audit_never_activates_link(monkeypatch):
    started = bridge.begin("alice", ISSUER, AUDIENCE, "slack")
    bridge.observe("slack", ACCOUNT, TEAM, SENDER,
                   "LIGHTWORK CONNECT " + started["code"])
    real_write = bridge._write
    real_audit = bridge._audit
    events = []

    def record(action, **kwargs):
        events.append(action)

    monkeypatch.setattr(bridge, "_audit", record)
    monkeypatch.setattr(bridge, "_write", lambda data: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        bridge.confirm("alice", ISSUER, AUDIENCE, started["id"])
    assert events == ["link_confirmation_requested"]
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) is None

    monkeypatch.setattr(bridge, "_write", real_write)

    def fail_confirmed(action, **kwargs):
        if action == "link_confirmation_recorded":
            raise bridge.BridgeError("audit unavailable")
        real_audit(action, **kwargs)

    monkeypatch.setattr(bridge, "_audit", fail_confirmed)
    with pytest.raises(bridge.BridgeError, match="audit unavailable"):
        bridge.confirm("alice", ISSUER, AUDIENCE, started["id"])
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) is None
    assert bridge.pending("alice", ISSUER, AUDIENCE)[0]["id"] == started["id"]
    monkeypatch.setattr(bridge, "_audit", real_audit)
    bridge.confirm("alice", ISSUER, AUDIENCE, started["id"])
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) == "user:alice"


def test_failed_revocation_audit_leaves_account_disabled(monkeypatch):
    _confirmed()
    link_id = bridge.links_for("alice", ISSUER, AUDIENCE)[0]["id"]
    real_audit = bridge._audit

    def fail_completed(action, **kwargs):
        if action == "access_revoked":
            raise bridge.BridgeError("audit unavailable")
        real_audit(action, **kwargs)

    monkeypatch.setattr(bridge, "_audit", fail_completed)
    with pytest.raises(bridge.BridgeError, match="Access was revoked, but"):
        bridge.revoke(link_id, actor="user:admin")
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) is None
    assert bridge.all_links()[0]["status"] == "revoked"
    monkeypatch.setattr(bridge, "_audit", real_audit)
    assert bridge.revoke(link_id, actor="user:admin")
    assert bridge.all_links() == []


@pytest.mark.parametrize("how", ["revoke", "unlink"])
def test_no_audit_at_all_never_keeps_a_chat_account_connected(monkeypatch, how):
    """Cutting access off must not wait for the audit log: a compromised chat
    account stays disabled even when every audit write fails."""
    _confirmed()
    link_id = bridge.links_for("alice", ISSUER, AUDIENCE)[0]["id"]
    real_audit = bridge._audit

    def unavailable(action, **kwargs):
        raise bridge.BridgeError("The identity change could not be recorded.")

    monkeypatch.setattr(bridge, "_audit", unavailable)
    with pytest.raises(bridge.BridgeError, match="Access was revoked, but"):
        if how == "revoke":
            bridge.revoke(link_id, actor="user:admin")
        else:
            bridge.unlink("alice", ISSUER, AUDIENCE, link_id)
    assert bridge.resolve("slack", ACCOUNT, TEAM, SENDER) is None
    monkeypatch.setattr(bridge, "_audit", real_audit)
    assert bridge.revoke(link_id, actor="user:admin")        # repeating finishes the removal
    assert bridge.all_links() == []


def test_server_accepts_only_verified_receipt_and_bad_jwt_never_falls_back(monkeypatch):
    _confirmed()
    monkeypatch.setattr(oidc, "oidc_enabled", lambda: True)
    server = object.__new__(Server)
    server._shield = None
    server._message_tenant_world = lambda msg, principal: (None, None)

    async def handled(msg, *, principal_id, tenant, world):
        return principal_id

    server._handle_message_in_tenant = handled
    msg = IncomingMessage("C123", "Please do this", channel="slack", sender_id=SENDER,
                          provider_tenant_id=TEAM, provider_sender_id=SENDER)
    assert "Connect this chat account" in asyncio.run(server._handle_message(msg))
    msg._verified_channel_account_sha256 = ACCOUNT
    assert asyncio.run(server._handle_message(msg)) == "user:alice"
    msg.id_token = "invalid.jwt"

    def invalid(token):
        raise oidc.OIDCError("bad token")

    monkeypatch.setattr(oidc, "verify_oidc_token", invalid)
    assert "OIDC token is missing or invalid" in asyncio.run(server._handle_message(msg))
    msg.id_token = ""
    assert "OIDC token is missing or invalid" in asyncio.run(server._handle_message(msg))
