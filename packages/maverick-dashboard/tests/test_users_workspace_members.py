"""Users page: assign members to any workspace, show invitees as people."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    # Local mode (auth off): the page is reachable exactly as in the RBAC
    # tests. Invite records are written through the store directly, so the
    # invites feature flag (which would demand a signed-in identity) stays off.
    monkeypatch.delenv("MAVERICK_DASHBOARD_INVITES", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_members_section_offers_every_active_workspace_without_switching(monkeypatch, tmp_path):
    """Assigning someone to a workspace used to require first switching your
    own selected workspace; the section now carries a picker of its own."""
    c = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry as tr
    tr.create_tenant("acme", display_name="Acme Inc")
    tr.create_tenant("beta")
    tr.suspend_tenant("beta")
    text = c.get("/users").text
    assert 'id="wm-tenant"' in text
    assert '<option value="acme" selected>Acme Inc</option>' in text
    assert 'value="beta"' not in text  # suspended workspaces are not offered
    assert 'data-tenant="acme"' in text
    assert "before managing its members" not in text


def test_members_section_points_at_the_workspaces_page_when_none_exist(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    text = c.get("/users").text
    assert 'id="wm-tenant"' not in text
    assert 'href="/tenants"' in text and "No workspace yet" in text and "Create a workspace" in text


def test_people_who_accepted_an_invite_are_shown_by_email(monkeypatch, tmp_path):
    """A federated subject like ``google-oauth2|1000...`` means nothing to the
    owner; the invite they accepted knows their email, so the roster, the
    member list labels and the colleague picker show that email first."""
    c = _client(monkeypatch, tmp_path)
    from maverick.tenant import registry as tr
    tr.create_tenant("acme", display_name="Acme Inc")  # so the colleague picker renders
    from maverick_dashboard import invites, rbac
    _inv, token = invites.create_invite("dab@example.com", "admin", created_by="user:owner")
    sub = "user:google-oauth2|100000000000000424242"
    assert invites.consume_invite(token, used_by=sub) is not None
    rbac.set_role(sub, "admin")
    rbac.set_role("user:plain@example.com", "viewer")
    text = c.get("/users").text
    # Roster row: the email, never the raw sign-in identity.
    assert "dab@example.com" in text
    visible = text.split('<main id="content"', 1)[1]
    import re
    visible = re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style)\b.*?</\1>", " ", visible, flags=re.DOTALL))
    assert "424242" not in visible and "google-oauth2" not in visible
    # Labels reach the member script (data attribute) and the colleague picker.
    assert '"user:google-oauth2|100000000000000424242": "dab@example.com"' in text
    assert '<option value="user:google-oauth2|100000000000000424242">dab@example.com</option>' in text
    # Someone with no accepted invite renders exactly as before.
    assert "plain@example.com" in text


def test_workspace_admin_page_lists_only_managed_workspaces_and_current_members(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    from maverick.paths import reset_tenant, set_tenant
    from maverick.tenant import registry as tr
    from maverick_dashboard import auth, rbac

    for tenant in ("acme", "beta", "outside"):
        tr.create_tenant(tenant)
    rbac.set_role("user:alice", "viewer")
    rbac.set_role("user:global-only", "operator")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    rbac.set_tenant_role("beta", "user:alice", "admin")
    rbac.set_tenant_role("acme", "user:acme-member", "viewer")
    rbac.set_tenant_role("beta", "user:beta-member", "operator")
    rbac.set_tenant_role("outside", "user:outside-member", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")

    token = set_tenant("acme")
    try:
        response = c.get("/users")
    finally:
        reset_tenant(token)
    assert response.status_code == 200
    text = response.text
    assert 'value="acme"' in text and 'value="beta"' in text
    assert 'value="outside"' not in text
    assert 'user:acme-member' in text and 'user:beta-member' in text
    assert 'user:outside-member' not in text and 'user:global-only' not in text
    assert 'data-global-admin="false"' in text
    assert 'data-role-options=' in text
