"""A local invitation must not take over an identity the IdP already confers.

With SCIM on and ``[dashboard] group_roles`` mapping a group to a role, a
person the IdP pushed into that group holds that role at their principal
``user:<email>`` before they ever sign in here. A workspace invitation writes
no installation role, so letting it through would hand the invited session the
group's role: a workspace administrator would become that person.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

_TOKEN = "scim-secret-token-xyz"  # pragma: allowlist secret
CFO = "cfo@example.com"
PASSPHRASE_FORM = {"password": "synthetic workspace invite passphrase",  # pragma: allowlist secret
                   "password2": "synthetic workspace invite passphrase"}  # pragma: allowlist secret


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.setenv("MAVERICK_SCIM_TOKEN", _TOKEN)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from maverick_dashboard import app as dash_app

    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _map_groups(monkeypatch, roles=None, suites=None):
    from maverick_dashboard import scim_groups

    tables = {"group_roles": roles or {}, "group_suites": suites or {}}
    monkeypatch.setattr(scim_groups, "_config_table", lambda key: tables.get(key, {}))


def _scim(client, path, body):
    # The IdP is its own caller: no browser session, no selected workspace.
    idp = TestClient(client.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = idp.post(path, json=body, headers={"Authorization": f"Bearer {_TOKEN}"})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _push_user(client, external_id=CFO, *, user_name=CFO, active=True):
    return _scim(client, "/scim/v2/Users", {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": user_name, "externalId": external_id,
        "emails": [{"value": user_name, "primary": True}], "active": active})


def _push_group(client, name, members):
    return _scim(client, "/scim/v2/Groups", {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": name, "members": [{"value": m} for m in members]})


def _workspace_admin(client, email="alice@example.com"):
    """A global viewer who administers the workspace acme and nothing else."""
    from maverick.tenant import registry
    from maverick_dashboard import invites, rbac, workspace_tenants

    registry.create_tenant("acme", display_name="Acme")
    principal = f"user:{email}"
    rbac.set_role(principal, "viewer")
    rbac.set_tenant_role("acme", principal, "admin")
    workspace_tenants.set_selection(principal, "acme")
    client.cookies.set("mvk_session", invites.mint_local_session(email))
    return principal


def _invite(client, email, role="viewer"):
    return client.post("/users/workspace-invite", data={
        "_expected_tenant": "acme", "tenant": "acme", "email": email, "role": role})


def _link(response):
    match = re.search(r'id="workspace-invite-link"[^>]*value="([^"]+)"', response.text)
    assert match, response.text[:1000]
    return "/auth/invite/" + match.group(1).rsplit("/auth/invite/", 1)[1]


def _stranger(client):
    return TestClient(client.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_a_workspace_admin_cannot_invite_a_person_the_idp_made_a_global_admin(client, monkeypatch):
    from maverick_dashboard import auth, invites, local_passphrases

    _map_groups(monkeypatch, roles={"Admins": "admin"})
    _workspace_admin(client)
    _push_group(client, "Admins", [_push_user(client)])
    assert auth.global_role_for_principal("user:" + CFO) == "admin"   # the premise
    assert invites.local_login_mode()

    refused = _invite(client, CFO)
    assert refused.status_code == 409, refused.text
    assert not any(inv.email == CFO for inv in invites.list_invites())
    assert not local_passphrases.has_account(CFO)


def test_a_link_made_before_the_idp_promoted_the_person_is_refused_when_used(client, monkeypatch):
    from maverick_dashboard import invites, local_passphrases

    _map_groups(monkeypatch, roles={"Admins": "admin"})
    _workspace_admin(client)
    minted = _invite(client, CFO)                                   # nobody knows this person yet
    assert minted.status_code == 200, minted.text
    path = _link(minted)
    _push_group(client, "Admins", [_push_user(client)])             # then the IdP promotes them

    attacker = _stranger(client)
    redeemed = attacker.post(path, data=PASSPHRASE_FORM, follow_redirects=False)
    assert redeemed.status_code == 409, redeemed.text
    assert "mvk_session" not in attacker.cookies
    assert not local_passphrases.has_account(CFO)
    assert invites.peek_invite(path.rsplit("/", 1)[1]) is not None   # the link was not used up


def test_a_genuinely_new_person_is_still_invited_and_signs_in(client, monkeypatch):
    from maverick_dashboard import local_passphrases, rbac

    _map_groups(monkeypatch, roles={"Admins": "admin"})
    _workspace_admin(client)
    _push_group(client, "Admins", [_push_user(client)])             # the IdP knows other people

    minted = _invite(client, "new@example.com")
    assert minted.status_code == 200, minted.text
    newcomer = _stranger(client)
    accepted = newcomer.post(_link(minted), data=PASSPHRASE_FORM, follow_redirects=False)
    assert accepted.status_code == 303, accepted.text
    assert local_passphrases.has_account("new@example.com")
    assert rbac.get_tenant_role("acme", "user:new@example.com") == "viewer"
    assert rbac.get_stored_role("user:new@example.com") is None


def test_a_person_known_to_the_idp_only_by_name_is_invited_as_usual(client, monkeypatch):
    """Names and emails carry no access, so they are not a reason to refuse."""
    from maverick_dashboard import auth, invites

    _map_groups(monkeypatch, roles={"Admins": "admin"})
    _workspace_admin(client)
    _push_group(client, "Admins", [_push_user(client, external_id="00u-opaque-okta-subject")])
    assert auth.global_role_for_principal("user:" + CFO) is None
    assert invites.existing_local_account(CFO) is False
    assert _invite(client, CFO).status_code == 200


@pytest.mark.parametrize("source", ["active_user", "deactivated_user", "retired_user",
                                    "viewer_group_role", "department_grant"])
def test_every_identity_source_that_knows_the_person_refuses_the_invitation(client, monkeypatch, source):
    from maverick_dashboard import invites, subject_directory, suite_grants

    if source == "active_user":
        _push_user(client)
    elif source == "deactivated_user":
        _push_user(client, active=False)
    elif source == "retired_user":
        subject_directory.retire([CFO])
    elif source == "viewer_group_role":
        _map_groups(monkeypatch, roles={"Everyone": "viewer"})
        _push_group(client, "Everyone", [_push_user(client)])
    else:
        suite_grants.set_suites("user:" + CFO, ["finance"], actor="user:owner")
    assert invites.existing_local_account(CFO) is True
    assert invites.existing_local_account("someone.else@example.com") is False


def test_unreadable_identity_state_refuses_rather_than_invites(client, monkeypatch):
    from maverick_dashboard import invites, scim_groups

    def broken(principal):
        raise RuntimeError("the SCIM roster cannot be read")

    monkeypatch.setattr(scim_groups, "active_for_principal", broken)
    assert invites.existing_local_account("someone.else@example.com") is True
