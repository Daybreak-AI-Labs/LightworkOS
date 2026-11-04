"""Existing-workspace invitations grant membership without global access."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient


def _client(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT_BY_USER", raising=False)
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from maverick_dashboard import app as dash_app

    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _as_workspace_admin(client, email="alice@example.com", role="admin"):
    from maverick_dashboard import invites, rbac, workspace_tenants

    principal = f"user:{email}"
    rbac.set_role(principal, "viewer")
    rbac.set_tenant_role("acme", principal, role)
    workspace_tenants.set_selection(principal, "acme")
    client.cookies.set("mvk_session", invites.mint_local_session(email))
    return principal


def _as_global_admin(client, email="owner@example.com"):
    from maverick_dashboard import invites, rbac

    principal = f"user:{email}"
    rbac.set_role(principal, "admin")
    client.cookies.set("mvk_session", invites.mint_local_session(email))
    return principal


def test_api_reference_requires_session_and_loads_with_invite_cookie(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    paths = ["/docs", "/redoc", "/openapi.json", "/static/swagger-ui-5.33.1.css",
             "/static/swagger-ui-5.33.1-bundle.js"]
    for path in paths:
        assert client.get(path, follow_redirects=False).status_code in (401, 403, 307)
    _as_global_admin(client)
    for path in paths:
        assert client.get(path).status_code == 200


def test_probe_details_require_global_admin_invite_session(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    _as_workspace_admin(client)
    assert client.get("/api/v1/admin/system/probe-details").status_code == 403
    _as_global_admin(client)
    response = client.get("/api/v1/admin/system/probe-details")
    assert response.status_code in (200, 503)
    assert "checks" in response.json()
    assert response.headers["cache-control"] == "private, no-store"


def test_workspace_admin_spending_page_does_not_show_global_or_other_roster(monkeypatch, tmp_path):
    from maverick import spending_limits
    from maverick.paths import tenant_scope
    from maverick.quotas import UsageLedger
    from maverick.tenant import registry
    from maverick_dashboard import rbac

    client = _client(monkeypatch, tmp_path)
    registry.create_tenant("acme", display_name="Acme")
    registry.create_tenant("outside", display_name="Outside")
    rbac.set_role("user:global-secret@example.com", "viewer")
    rbac.set_tenant_role("acme", "user:member@example.com", "viewer")
    rbac.set_tenant_role("outside", "user:other@example.com", "viewer")
    with tenant_scope(tenant="acme"):
        UsageLedger().record("user:former@example.com", 1.0, 0, 0)
        spending_limits.set_user_limit("user:former@example.com", 5, "day", actor="user:owner")
    _as_workspace_admin(client)
    page = client.get("/spending-limits")
    assert page.status_code == 200
    assert "user:member@example.com" in page.text
    assert "user:former@example.com" in page.text
    assert "user:global-secret@example.com" not in page.text
    assert "user:other@example.com" not in page.text
    response = client.post("/spending-limits/person", data={
        "_expected_tenant": "acme", "principal": "user:member@example.com", "amount": "3", "period": "day",
    }, follow_redirects=False)
    assert response.status_code == 303
    _as_global_admin(client)
    assert "user:global-secret@example.com" in client.get("/spending-limits").text


def _invitation_path(response):
    match = re.search(r'id="workspace-invite-link"[^>]*value="([^"]+)"', response.text)
    assert match, response.text[:1000]
    return "/auth/invite/" + match.group(1).rsplit("/auth/invite/", 1)[1]


def _global_invitation_path(response):
    match = re.search(r'id="invite-link"[^>]*value="([^"]+)"', response.text)
    assert match, response.text[:1000]
    return "/auth/invite/" + match.group(1).rsplit("/auth/invite/", 1)[1]


def _invitee(client):
    return TestClient(client.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


PASSPHRASE_FORM = {"password": "synthetic workspace invite passphrase",  # pragma: allowlist secret
                   "password2": "synthetic workspace invite passphrase"}  # pragma: allowlist secret


def _accept(client, path, *, follow_redirects=True):
    return client.post(path, data=PASSPHRASE_FORM, follow_redirects=follow_redirects)


def test_global_admin_can_invite_first_member_of_existing_workspace(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import rbac

    registry.create_tenant("acme", display_name="Acme")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "workspace-setup-token")  # pragma: allowlist secret
    headers = {"Authorization": "Bearer workspace-setup-token"}
    assert 'action="/users/workspace-invite"' in client.get("/users", headers=headers).text
    minted = client.post("/users/workspace-invite", headers=headers, data={
        "tenant": "acme", "email": "first@example.com", "role": "admin",
    })
    assert minted.status_code == 200, minted.text
    path = _invitation_path(minted)
    assert "Acme workspace" in client.get(path).text
    accepted = _accept(client, path, follow_redirects=False)
    assert accepted.status_code == 303
    assert rbac.get_tenant_role("acme", "user:first@example.com") == "admin"
    assert rbac.get_stored_role("user:first@example.com") is None


def test_scoped_admin_invites_only_in_managed_workspace_and_can_cancel(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import invites, rbac

    registry.create_tenant("acme", display_name="Acme")
    registry.create_tenant("outside", display_name="Outside")
    rbac.set_custom_role("member-admin", ["view", "admin"])
    _as_workspace_admin(client, role="member-admin")
    page = client.get("/users")
    assert page.status_code == 200, page.text
    assert 'action="/users/workspace-invite"' in page.text
    assert 'value="outside"' not in page.text
    assert '<option value="operator">' not in page.text.split('id="wi-role"', 1)[1].split("</select>", 1)[0]
    refused = client.post("/users/workspace-invite", data={
        "_expected_tenant": "acme", "tenant": "outside", "email": "new@example.com", "role": "viewer",
    })
    assert refused.status_code == 403
    refused = client.post("/users/workspace-invite", data={
        "_expected_tenant": "acme", "tenant": "acme", "email": "new@example.com", "role": "operator",
    })
    assert refused.status_code == 409
    minted = client.post("/users/workspace-invite", data={
        "_expected_tenant": "acme", "tenant": "acme", "email": "new@example.com", "role": "viewer",
    })
    assert minted.status_code == 200, minted.text
    assert "new@example.com" in minted.text and "Outside" not in minted.text
    path = _invitation_path(minted)
    pending = next(inv for inv in invites.list_invites() if inv.pending)
    assert pending.tenant == "acme" and pending.workspace_admin_invite
    revoked = client.post("/users/workspace-invite/revoke", data={
        "_expected_tenant": "acme", "invite_id": pending.id,
    },
                          follow_redirects=False)
    assert revoked.status_code == 303
    assert _accept(_invitee(client), path).status_code == 410


def test_scoped_invite_rechecks_issuer_and_workspace_on_accept(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import invites, rbac

    registry.create_tenant("acme")
    principal = _as_workspace_admin(client)
    minted = client.post("/users/workspace-invite", data={
        "_expected_tenant": "acme", "tenant": "acme", "email": "new@example.com", "role": "operator",
    })
    assert minted.status_code == 200, minted.text
    path = _invitation_path(minted)
    rbac.remove_tenant_role("acme", principal)
    assert _accept(_invitee(client), path).status_code == 410
    assert invites.peek_invite(path.rsplit("/", 1)[1]) is not None
    assert rbac.get_tenant_role("acme", "user:new@example.com") is None

    rbac.set_tenant_role("acme", principal, "admin")
    minted = client.post("/users/workspace-invite", data={
        "_expected_tenant": "acme", "tenant": "acme", "email": "other@example.com", "role": "viewer",
    })
    path = _invitation_path(minted)
    registry.suspend_tenant("acme")
    assert _accept(_invitee(client), path).status_code == 410
    assert rbac.get_tenant_role("acme", "user:other@example.com") is None


def test_scoped_invite_cannot_remove_last_admin_on_accept(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import rbac

    registry.create_tenant("acme")
    from maverick_dashboard import invites

    # A link issued while alice could not yet sign in here...
    _inv, token = invites.create_invite("alice@example.com", "viewer",
                                        created_by="local-admin", tenant="acme")
    principal = _as_workspace_admin(client)  # ...and she is now the only admin.
    # She cannot invite herself to a lower role, and the old link cannot be
    # accepted over her account: either would remove the last admin.
    minted = client.post("/users/workspace-invite", data={
        "_expected_tenant": "acme", "tenant": "acme", "email": "alice@example.com", "role": "viewer",
    })
    assert minted.status_code == 409, minted.text
    assert _accept(_invitee(client), f"/auth/invite/{token}").status_code == 410
    assert rbac.get_tenant_role("acme", principal) == "admin"


def test_scoped_admin_cannot_see_or_revoke_other_invitations(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import invites

    registry.create_tenant("acme")
    registry.create_tenant("outside")
    _as_workspace_admin(client)
    global_invite, _ = invites.create_invite("global@example.com", "viewer", created_by="owner")
    outside_invite, _ = invites.create_invite("outside@example.com", "viewer",
                                             created_by="owner", tenant="outside")
    own_invite, _ = invites.create_invite("own@example.com", "viewer",
                                         created_by="owner", tenant="acme")
    page = client.get("/users")
    assert page.status_code == 200
    assert "own@example.com" in page.text
    assert "global@example.com" not in page.text
    assert "outside@example.com" not in page.text
    for record, expected in ((global_invite, 404), (outside_invite, 403)):
        response = client.post("/users/workspace-invite/revoke", data={
            "_expected_tenant": "acme", "invite_id": record.id,
        }, follow_redirects=False)
        assert response.status_code == expected
        assert record.id in {inv.id for inv in invites.list_invites()}
    assert own_invite.id in {inv.id for inv in invites.list_invites()}


def test_scoped_invite_cannot_outlive_a_role_ceiling_change(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import rbac

    registry.create_tenant("acme")
    principal = _as_workspace_admin(client)
    minted = client.post("/users/workspace-invite", data={
        "_expected_tenant": "acme", "tenant": "acme", "email": "new@example.com", "role": "operator",
    })
    assert minted.status_code == 200
    rbac.set_custom_role("member-admin", ["view", "admin"])
    rbac.set_tenant_role("acme", principal, "member-admin")
    assert _accept(_invitee(client), _invitation_path(minted)).status_code == 410
    assert rbac.get_tenant_role("acme", "user:new@example.com") is None


def test_sso_workspace_invite_requires_current_provider_email_match(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick.oidc import VerifiedPrincipal
    from maverick.tenant import registry
    from maverick_dashboard import invite_routes, invites, rbac

    registry.create_tenant("acme")
    _, token = invites.create_invite("right@example.com", "viewer",
                                     created_by="owner", tenant="acme")
    path = f"/auth/invite/{token}"
    monkeypatch.setattr(invites, "local_login_mode", lambda: False)
    signed_in = VerifiedPrincipal(sub="opaque-sub", issuer="oidc-session", audience="",
                                  claims={"idp_email": "wrong@example.com"})
    monkeypatch.setattr(invite_routes, "_session_principal", lambda _request: signed_in)
    assert client.get(path).status_code == 403
    assert client.post(path).status_code == 403
    assert invites.peek_invite(token) is not None
    assert rbac.get_tenant_role("acme", "user:opaque-sub") is None
    signed_in = VerifiedPrincipal(sub="opaque-sub", issuer="oidc-session", audience="",
                                  claims={"idp_email": "RIGHT@example.com"})
    assert client.post(path, follow_redirects=False).status_code == 303
    assert rbac.get_tenant_role("acme", "user:opaque-sub") == "viewer"


def test_provider_email_is_from_current_signed_login_not_historical_alias():
    from maverick_dashboard.oidc_login import _oidc_invite_email, session_claims
    from maverick_dashboard.saml import SamlIdentity, _saml_invite_email

    assert _oidc_invite_email({"email": "RIGHT@EXAMPLE.COM"}) == "right@example.com"
    assert _oidc_invite_email({"email": "right@example.com", "email_verified": False}) == ""
    assert _oidc_invite_email({"preferred_username": "right@example.com"}) == "right@example.com"
    assert _saml_invite_email(SamlIdentity("opaque", {"mail": ["right@example.com"]})) == "right@example.com"
    import time
    # A session cookie needs its signed issue time; one without it is refused.
    assert session_claims({"idp_email": "RIGHT@example.com"}, None, via="session") is None
    fresh = {"idp_email": "RIGHT@example.com", "iat": time.time()}
    assert session_claims(fresh, None, via="session")["idp_email"] == "right@example.com"
    assert "idp_email" not in session_claims({"idp_email": "right@example.com"}, None, via="invite")


def _failed_acceptance(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import invite_routes, invites, rbac

    registry.create_tenant("acme")
    _, token = invites.create_invite("new@example.com", "viewer",
                                     created_by="owner", tenant="acme")
    monkeypatch.setattr(invite_routes, "_bind_role", lambda *_: (_ for _ in ()).throw(ValueError("store failed")))
    response = _accept(client, f"/auth/invite/{token}")
    assert response.status_code == 503
    assert invites.peek_invite(token) is None
    assert rbac.get_tenant_role("acme", "user:new@example.com") is None
    return " ".join(response.text.split())


def test_bind_failure_with_a_saved_passphrase_points_to_the_users_page(monkeypatch, tmp_path):
    """The passphrase is saved before the access, and an invitation for that
    email is refused as an existing account, so a replacement link would not help."""
    text = _failed_acceptance(monkeypatch, tmp_path)
    assert "Users page" in text and "passphrase you chose" in text
    assert "new invitation link" not in text


def test_bind_failure_without_passphrases_explains_a_replacement_link_is_needed(monkeypatch, tmp_path):
    from maverick_dashboard import local_passphrases

    monkeypatch.setattr(local_passphrases, "available", lambda: False)
    assert "new invitation link" in _failed_acceptance(monkeypatch, tmp_path)


def test_saml_only_deployment_does_not_accept_invite_as_local_login(monkeypatch, tmp_path):
    _client(monkeypatch, tmp_path)
    from maverick_dashboard import invites, saml

    monkeypatch.setattr(saml, "saml_enabled", lambda: True)
    assert invites.local_login_mode() is False


def test_named_global_issuer_must_still_administer_at_acceptance(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick_dashboard import invites, rbac

    issuer = _as_global_admin(client)
    minted = client.post("/users/invite", data={"email": "new@example.com", "role": "operator"})
    assert minted.status_code == 200, minted.text
    path = _global_invitation_path(minted)
    pending = next(inv for inv in invites.list_invites() if inv.pending)
    assert pending.created_by == issuer and pending.tenant == ""
    rbac.set_role("user:recovery@example.com", "admin")
    rbac.set_role(issuer, "viewer")
    assert _accept(_invitee(client), path).status_code == 410
    assert invites.peek_invite(path.rsplit("/", 1)[1]) is not None
    assert rbac.get_stored_role("user:new@example.com") is None
    rbac.set_role(issuer, "admin")
    assert _accept(_invitee(client), path, follow_redirects=False).status_code == 303
    assert rbac.get_stored_role("user:new@example.com") == "operator"


def test_first_member_invite_requires_current_global_issuer_authority(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick_dashboard import invites, rbac

    issuer = _as_global_admin(client)
    made = client.post("/api/v1/admin/workspace-ops/onboard", json={
        "display_name": "Acme", "admin_email": "first@example.com", "role": "admin",
    })
    assert made.status_code == 201, made.text
    workspace = made.json()["workspace"]["id"]
    token = made.json()["invite_link"].rsplit("/auth/invite/", 1)[1]
    pending = invites.peek_invite(token)
    assert pending is not None and pending.created_by == issuer and pending.tenant == workspace
    rbac.set_role("user:recovery@example.com", "admin")
    rbac.set_role(issuer, "viewer")
    assert _accept(_invitee(client), f"/auth/invite/{token}").status_code == 410
    assert invites.peek_invite(token) is not None
    assert rbac.get_tenant_role(workspace, "user:first@example.com") is None
    rbac.set_role(issuer, "admin")
    assert _accept(_invitee(client), f"/auth/invite/{token}", follow_redirects=False).status_code == 303
    assert rbac.get_tenant_role(workspace, "user:first@example.com") == "admin"


def test_principal_less_and_legacy_invites_keep_their_existing_contract(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick_dashboard import invites, rbac

    _legacy, token = invites.create_invite("legacy@example.com", "viewer", created_by="local-admin")
    assert _accept(_invitee(client), f"/auth/invite/{token}", follow_redirects=False).status_code == 303
    assert rbac.get_stored_role("user:legacy@example.com") == "viewer"


def test_a_workspace_admin_cannot_reset_a_members_passphrase(monkeypatch, tmp_path):
    """Whoever resets a passphrase chooses who sets the next one, so only the
    installation owner may; never a workspace administrator."""
    import json

    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import invites, local_passphrases, passphrase_resets

    registry.create_tenant("acme", display_name="Acme")
    _inv, token = invites.create_invite("member@example.com", "operator",
                                        created_by="local-admin", tenant="acme")
    assert _accept(_invitee(client), f"/auth/invite/{token}", follow_redirects=False).status_code == 303
    before = json.loads(local_passphrases.path().read_text(encoding="utf-8"))
    _as_workspace_admin(client)
    page = client.get("/users")
    assert page.status_code == 200 and 'action="/users/passphrase-reset"' not in page.text
    refused = client.post("/users/passphrase-reset", data={
        "_expected_tenant": "acme", "email": "member@example.com", "confirm": "reset",
    })
    assert refused.status_code == 403, refused.text
    assert json.loads(local_passphrases.path().read_text(encoding="utf-8")) == before
    assert not passphrase_resets.path().exists()


def test_scoped_admin_cannot_invite_an_existing_member_to_take_over_their_account(monkeypatch, tmp_path):
    """Accepting a local invitation sets a passphrase and signs in as the invited
    email, so an invitation for someone who can already sign in is refused."""
    import json

    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import invites, local_passphrases, rbac

    registry.create_tenant("acme", display_name="Acme")
    _inv, token = invites.create_invite("member@example.com", "operator",
                                        created_by="local-admin", tenant="acme")
    assert _accept(_invitee(client), f"/auth/invite/{token}", follow_redirects=False).status_code == 303

    def credential():
        return json.loads(local_passphrases.path().read_text(encoding="utf-8"))["accounts"]["member@example.com"]

    before = credential()
    pending = len(invites.list_invites())
    _as_workspace_admin(client)
    refused = client.post("/users/workspace-invite", data={
        "_expected_tenant": "acme", "tenant": "acme", "email": "member@example.com", "role": "viewer",
    })
    assert refused.status_code == 409, refused.text
    # A workspace administrator is not told why: the same words for everyone.
    assert "could not be created for that email address" in refused.text
    assert "already has a sign-in" not in refused.text
    assert "/auth/invite/inv_" not in refused.text
    assert len(invites.list_invites()) == pending
    assert credential() == before
    assert rbac.get_tenant_role("acme", "user:member@example.com") == "operator"
    # A brand-new person can still be invited by the same admin.
    minted = client.post("/users/workspace-invite", data={
        "_expected_tenant": "acme", "tenant": "acme", "email": "newcomer@example.com", "role": "viewer",
    })
    assert minted.status_code == 200, minted.text


def _invite_attempt(client, email, *, background=False):
    headers = {"Accept": "application/json"} if background else {}
    return client.post("/users/workspace-invite", headers=headers, data={
        "_expected_tenant": "acme", "tenant": "acme", "email": email, "role": "viewer"})


def _message(response):
    detail = response.json()["detail"]
    return detail["message"] if isinstance(detail, dict) else detail


def test_a_workspace_admin_cannot_tell_who_has_an_account_or_where(monkeypatch, tmp_path):
    """Every reason an invitation cannot be made reads the same to a workspace
    administrator: a passphrase account, a member of another workspace, a role
    holder, an installation administrator and the owner are indistinguishable."""
    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import invites, local_passphrases, rbac

    registry.create_tenant("acme", display_name="Acme")
    registry.create_tenant("beta", display_name="Beta")
    _inv, token = invites.create_invite("colleague@example.com", "operator",
                                        created_by="local-admin", tenant="beta")
    assert _accept(_invitee(client), f"/auth/invite/{token}", follow_redirects=False).status_code == 303
    rbac.set_tenant_role("beta", "user:member@example.com", "viewer")
    rbac.set_role("user:roleholder@example.com", "viewer")
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root@example.com")
    monkeypatch.setattr(local_passphrases, "owner_of", lambda email: email == "owner@example.com")
    _as_workspace_admin(client)

    existing = ["colleague@example.com", "member@example.com", "roleholder@example.com",
                "root@example.com", "owner@example.com"]
    answers = [_invite_attempt(client, email) for email in existing]
    assert {r.status_code for r in answers} == {409}
    messages = {_message(r) for r in answers}
    assert messages == {local_passphrases.NOT_INVITABLE}     # one message for every reason
    for word in ("beta", "Beta", "passphrase", "already", "sign-in"):
        assert word not in local_passphrases.NOT_INVITABLE
    # The page script gets one business error, with its own code.
    background = _invite_attempt(client, "member@example.com", background=True)
    assert background.status_code == 409 and background.json()["detail"]["code"] == "invite_not_created"
    # An address nobody knows gets a link, which is the one difference that remains.
    fresh = _invite_attempt(client, "nobody@example.com")
    assert fresh.status_code == 200 and "/auth/invite/" in fresh.text


def test_an_installation_admin_is_told_why_an_invitation_cannot_be_made(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import local_passphrases, rbac

    registry.create_tenant("acme", display_name="Acme")
    rbac.set_role("user:roleholder@example.com", "viewer")
    _as_global_admin(client)
    refused = _invite_attempt(client, "roleholder@example.com")
    assert refused.status_code == 409
    assert _message(refused) == local_passphrases.ACCOUNT_EXISTS
    background = _invite_attempt(client, "roleholder@example.com", background=True)
    assert background.json()["detail"]["code"] == "invite_existing_account"


def test_a_workspace_admin_cannot_test_a_list_of_addresses(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import invites, rbac

    monkeypatch.setattr(invites, "ISSUE_ATTEMPTS", 3)
    registry.create_tenant("acme", display_name="Acme")
    rbac.set_role("user:roleholder@example.com", "viewer")
    _as_workspace_admin(client)

    assert _invite_attempt(client, "roleholder@example.com").status_code == 409
    assert _invite_attempt(client, "one@example.com").status_code == 200
    assert _invite_attempt(client, "two@example.com").status_code == 200
    limited = _invite_attempt(client, "three@example.com")
    assert limited.status_code == 429, limited.text
    assert limited.headers["Retry-After"] == "600"
    assert "Wait a few minutes" in _message(limited)
    # A known address and an unknown one now get the same answer.
    assert _invite_attempt(client, "roleholder@example.com").status_code == 429
    assert not any(inv.email == "three@example.com" for inv in invites.list_invites())
    assert _invite_attempt(client, "four@example.com", background=True).json()["detail"]["code"] == "invite_rate_limited"

    # Installation administrators already see the whole roster, so they are not limited.
    _as_global_admin(client)
    for number in range(6):
        assert _invite_attempt(client, f"bulk{number}@example.com").status_code == 200


def test_workspace_member_has_no_implicit_root_authority(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry
    from maverick_dashboard import invites, rbac

    registry.create_tenant("acme", display_name="Acme")
    principal = "user:member@example.com"
    rbac.set_tenant_role("acme", principal, "viewer")
    client.cookies.set("mvk_session", invites.mint_local_session("member@example.com"))

    assert client.get("/api/v1/goals/search", params={"q": "x"}).status_code == 403
    assert client.get("/workspace/tenant").status_code == 200
    selected = client.put("/api/v1/workspace/active-tenant", json={"tenant_id": "acme"})
    assert selected.status_code == 200, selected.text
    assert client.get("/api/v1/goals/search", params={"q": "x"}).status_code == 200
    cleared = client.put("/api/v1/workspace/active-tenant", json={"tenant_id": None},
                         headers={"X-Lightwork-Expected-Tenant": "acme"})
    assert cleared.status_code == 200, cleared.text
    assert client.get("/api/v1/goals/search", params={"q": "x"}).status_code == 403

    rbac.remove_tenant_role("acme", principal)
    assert client.get("/api/v1/goals/search", params={"q": "x"}).status_code == 403
    rbac.set_role(principal, "viewer")
    assert client.get("/api/v1/goals/search", params={"q": "x"}).status_code == 200
