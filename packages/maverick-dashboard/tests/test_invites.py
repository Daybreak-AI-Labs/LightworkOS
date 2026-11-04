"""Email invite links: mint/peek/consume store semantics, the fail-closed
feature gate, the scanner-proof GET/POST accept flow, local (no-IdP) session
sign-in, and the RBAC binding. See maverick_dashboard/invites.py."""
from __future__ import annotations

import json

import pytest

fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    """Scratch HOME (invite/rbac/session stores) + world DB, invites OFF."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_INVITES", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


@pytest.fixture
def client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


# Accepting an invitation in local mode sets the colleague's passphrase.
PASSPHRASE_FORM = {"password": "synthetic invite passphrase",  # pragma: allowlist secret
                   "password2": "synthetic invite passphrase"}  # pragma: allowlist secret


def _admin_auth(monkeypatch) -> dict[str, str]:
    token = "invite-admin-test-token"  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", token)
    return {"Authorization": f"Bearer {token}"}


# ---------- store + gate (no HTTP) ----------

def test_disabled_by_default():
    from maverick_dashboard import invites
    assert invites.invites_enabled() is False


def test_create_peek_consume_roundtrip(monkeypatch):
    from maverick_dashboard import invites
    inv, token = invites.create_invite("Bob@Corp.com", "operator", created_by="me")
    assert inv.email == "bob@corp.com" and inv.pending
    # the raw token never lands on disk — only its hash
    stored = json.loads(invites.store_path().read_text())
    assert token not in json.dumps(stored)
    assert invites.peek_invite(token).id == inv.id       # peek does NOT consume
    assert invites.peek_invite(token) is not None
    used = invites.consume_invite(token)
    assert used.used_by == "user:bob@corp.com"
    assert invites.consume_invite(token) is None          # single-use
    assert invites.peek_invite(token) is None


def test_expired_invite_is_dead():
    from maverick_dashboard import invites
    _inv, token = invites.create_invite("a@b.co", "viewer", created_by="me",
                                        ttl_hours=-1)
    assert invites.peek_invite(token) is None
    assert invites.consume_invite(token) is None


def test_revoke_kills_the_link():
    from maverick_dashboard import invites
    inv, token = invites.create_invite("a@b.co", "viewer", created_by="me")
    assert invites.revoke_invite(inv.id) is True
    assert invites.peek_invite(token) is None


def test_validation():
    from maverick_dashboard import invites
    with pytest.raises(ValueError):
        invites.create_invite("not-an-email", "viewer", created_by="me")
    with pytest.raises(ValueError):
        invites.create_invite("a@b.co", "superuser", created_by="me")
    with pytest.raises(ValueError):
        invites.create_invite("a@b.co", "viewer", created_by="me", ttl_hours=float("inf"))


def test_corrupt_invite_store_fails_closed_and_is_not_overwritten():
    from maverick_dashboard import invites

    path = invites.store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    original = '{"invite_x":{"id":"invite_x","role":"admin"}}'
    path.write_text(original, encoding="utf-8")
    with pytest.raises(invites.InviteStoreError):
        invites.list_invites()
    with pytest.raises(invites.InviteStoreError):
        invites.create_invite("new@example.com", "viewer", created_by="admin")
    assert path.read_text(encoding="utf-8") == original


def test_local_session_secret_is_persistent_and_private(tmp_path):
    from maverick.file_lock import private_path_is_restricted
    from maverick_dashboard import invites
    s1 = invites.local_session_secret()
    s2 = invites.local_session_secret()
    assert s1 == s2 and len(s1) >= 32
    key = invites._session_secret_path()
    assert key.exists() and private_path_is_restricted(key)


# ---------- HTTP: fail-closed while disabled ----------

def test_routes_404_when_disabled(client):
    assert client.get("/auth/invite/inv_whatever").status_code == 404
    assert client.post("/auth/invite/inv_whatever").status_code == 404
    # admin mint form is also closed
    r = client.post("/users/invite", data={"email": "a@b.co", "role": "viewer"})
    assert r.status_code == 404


# ---------- HTTP: local (no-IdP) accept flow ----------

def test_local_accept_flow_signs_in_and_binds_role(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    from maverick_dashboard import invites, rbac
    inv, token = invites.create_invite("bob@corp.com", "viewer", created_by="me")
    # GET renders the confirmation page and must NOT consume (scanner prefetch)
    r = client.get(f"/auth/invite/{token}")
    assert r.status_code == 200 and "bob@corp.com" in r.text
    assert invites.peek_invite(token) is not None
    # POST consumes: sets the passphrase, signs the browser in + binds the role
    r = client.post(f"/auth/invite/{token}", data=PASSPHRASE_FORM, follow_redirects=False)
    assert r.status_code == 303
    assert "mvk_session=" in r.headers.get("set-cookie", "")
    assert rbac.get_stored_role("user:bob@corp.com") == "viewer"
    # single-use: replaying the link only reads the original result
    replay = client.post(f"/auth/invite/{token}")
    assert replay.status_code == 200 and "it does not give access again" in replay.text
    assert "mvk_session=" not in replay.headers.get("set-cookie", "")
    # the cookie now establishes a principal whose role gates admin pages
    assert client.get("/users").status_code == 403      # viewer ≠ admin
    client.cookies.clear()
    assert client.get("/users").status_code == 401      # invites on => no anonymous admin


def test_sso_global_invite_requires_current_provider_email_match(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    from maverick.oidc import VerifiedPrincipal
    from maverick_dashboard import invite_routes, invites, rbac

    _inv, token = invites.create_invite("right@corp.com", "admin", created_by="owner")
    path = f"/auth/invite/{token}"
    monkeypatch.setattr(invites, "local_login_mode", lambda: False)
    signed_in = VerifiedPrincipal(sub="opaque-sub", issuer="oidc-session", audience="", claims={})
    monkeypatch.setattr(invite_routes, "_session_principal", lambda _request: signed_in)
    assert client.post(path).status_code == 403
    assert invites.peek_invite(token) is not None
    # An email-shaped subject alone is not proof of the address asserted in
    # this signed session; the login callback must have saved that assertion.
    signed_in = VerifiedPrincipal(sub="right@corp.com", issuer="oidc-session", audience="", claims={})
    assert client.post(path).status_code == 403
    assert invites.peek_invite(token) is not None
    signed_in = VerifiedPrincipal(sub="opaque-sub", issuer="oidc-session", audience="",
                                  claims={"idp_email": "wrong@corp.com"})
    assert client.get(path).status_code == 403
    assert client.post(path).status_code == 403
    assert invites.peek_invite(token) is not None
    assert rbac.get_stored_role("user:opaque-sub") is None
    signed_in = VerifiedPrincipal(sub="opaque-sub", issuer="oidc-session", audience="",
                                  claims={"idp_email": "RIGHT@corp.com"})
    assert client.post(path, follow_redirects=False).status_code == 303
    assert rbac.get_stored_role("user:opaque-sub") == "admin"


def test_accept_post_requires_same_origin(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    from maverick_dashboard import invites
    _inv, token = invites.create_invite("bob@corp.com", "viewer", created_by="me")
    from maverick_dashboard.app import app
    hostile = TestClient(app, base_url="http://127.0.0.1")                            # no Origin/Referer at all
    assert hostile.post(f"/auth/invite/{token}").status_code == 400
    evil = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://evil.example"})
    assert evil.post(f"/auth/invite/{token}").status_code == 400
    assert invites.peek_invite(token) is not None        # nothing was consumed


def test_tampered_session_cookie_is_ignored(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    from maverick.web_session import sign_session
    from maverick_dashboard import invites
    forged = sign_session({"sub": "eve@corp.com", "iat": 0, "exp": 2**33},
                          "not-the-real-secret")
    client.cookies.set("mvk_session", forged)

    class _Req:
        cookies = {"mvk_session": forged}
    assert invites.local_session_principal(_Req()) is None


@pytest.mark.parametrize("subject", ["alice ", "alice\n", "x" * 252])
def test_signed_invite_session_rejects_invalid_subject_domain(monkeypatch, subject):
    import time

    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    from maverick.web_session import sign_session
    from maverick_dashboard import invites

    now = int(time.time())
    raw = sign_session(
        {"sub": subject, "iat": now, "exp": now + 3600},
        invites.local_session_secret(),
    )

    class _Req:
        cookies = {"mvk_session": raw}

    assert invites.local_session_principal(_Req()) is None


# ---------- HTTP: admin mint + revoke on /users ----------

def test_admin_mints_and_revokes_links(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    headers = _admin_auth(monkeypatch)
    from maverick_dashboard import invites
    r = client.post("/users/invite", data={"email": "new@corp.com",
                                           "role": "operator"}, headers=headers)
    assert r.status_code == 200
    assert "/auth/invite/inv_" in r.text                 # link shown once
    pending = [i for i in invites.list_invites() if i.pending]
    assert [i.email for i in pending] == ["new@corp.com"]
    r = client.post("/users/invite/revoke", data={"invite_id": pending[0].id},
                    headers=headers, follow_redirects=False)
    assert r.status_code == 303
    assert not [i for i in invites.list_invites() if i.pending]


def test_mint_rejects_bad_input(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    r = client.post(
        "/users/invite",
        data={"email": "nope", "role": "viewer"},
        headers=_admin_auth(monkeypatch),
    )
    assert r.status_code == 400


# ---------- emailing the link ----------

def test_mint_emails_the_link_when_configured(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    headers = _admin_auth(monkeypatch)
    monkeypatch.setenv("EMAIL_USER", "sender@daybreak.example")
    monkeypatch.setenv("EMAIL_APP_PASSWORD", "pw")  # pragma: allowlist secret
    from maverick import mailer
    sent = {}

    def fake_send(to, subject, body, **kw):
        sent.update(to=to, subject=subject, body=body)
    monkeypatch.setattr(mailer, "send", fake_send)
    r = client.post("/users/invite", data={"email": "new@corp.com",
                                           "role": "viewer"}, headers=headers)
    assert r.status_code == 200
    assert sent["to"] == "new@corp.com"
    assert "/auth/invite/inv_" in sent["body"]        # the link rides the email
    assert "viewer" in sent["body"]
    assert "emailed to" in r.text                      # UI reflects the send


def test_mint_falls_back_to_copy_link_on_smtp_failure(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    headers = _admin_auth(monkeypatch)
    monkeypatch.setenv("EMAIL_USER", "sender@daybreak.example")
    monkeypatch.setenv("EMAIL_APP_PASSWORD", "pw")  # pragma: allowlist secret
    from maverick import mailer

    def fake_send(*a, **kw):
        raise mailer.MailerError("smtp send failed: ConnectionRefusedError")
    monkeypatch.setattr(mailer, "send", fake_send)
    r = client.post("/users/invite", data={"email": "new@corp.com",
                                           "role": "viewer"}, headers=headers)
    assert r.status_code == 200                        # fail-soft: still minted
    assert "/auth/invite/inv_" in r.text               # copyable link still shown
    assert "We couldn't email the invite" in r.text


def test_mint_without_sender_keeps_copy_link_flow(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    headers = _admin_auth(monkeypatch)
    r = client.post("/users/invite", data={"email": "new@corp.com",
                                           "role": "viewer"}, headers=headers)
    assert r.status_code == 200
    assert "Copy this link" in r.text                  # unconfigured = old UX


def test_invite_email_knob_opts_out(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config",
                        lambda *a, **k: {"dashboard": {"invite_email": False}})
    from maverick_dashboard import invites
    inv = invites.Invite(id="i", email="a@b.co", role="viewer", created_by="me",
                         created_at=0.0, expires_at=7 * 86400.0)
    sent, note = invites.send_invite_email(inv, "https://x/auth/invite/t",
                                           invited_by="me")
    assert sent is False and "disabled" in note


# ---------- require_auth integration ----------

def test_invites_satisfy_require_auth_boot_guard(monkeypatch):
    import maverick_dashboard.app as app_mod
    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "1")
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: False)
    monkeypatch.setattr("maverick.proxy_auth.proxy_auth_enabled", lambda: False)
    with pytest.raises(RuntimeError):
        app_mod._assert_dashboard_auth_configured()
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    app_mod._assert_dashboard_auth_configured()          # invites count


def test_require_auth_fails_closed_without_session(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", "1")
    from maverick_dashboard import invites
    _inv, token = invites.create_invite("bob@corp.com", "admin", created_by="me")
    assert client.get("/goals").status_code == 401       # anonymous → closed
    assert client.get(f"/auth/invite/{token}").status_code == 200  # link exempt
    r = client.post(f"/auth/invite/{token}", data=PASSPHRASE_FORM, follow_redirects=False)
    assert r.status_code == 303                          # accept works
    assert client.get("/users").status_code == 200       # admin session opens it
