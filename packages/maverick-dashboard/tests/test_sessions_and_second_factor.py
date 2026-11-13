"""Browser sign-in with a required second factor, step-up on sensitive
actions, and the Sessions page/API (list, sign out a device, sign out
everywhere). Hermetic like test_oidc_login: env-configured login, the token
exchange and ID-token verification monkeypatched."""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import maverick_dashboard.oidc_login as ol
import pytest
from fastapi.testclient import TestClient
from maverick import config, world_model
from maverick.oidc import VerifiedPrincipal
from maverick.web_session import verify_session
from maverick_dashboard import mfa_policy, session_registry
from maverick_dashboard.app import app

AUTH_ENDPOINT = "https://idp.example.com/authorize"
TOKEN_ENDPOINT = "https://idp.example.com/token"
SESSION_SECRET = "unit-test-session-secret"  # pragma: allowlist secret
ISSUER = "https://idp.example.com"
ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture(autouse=True)
def login_env(monkeypatch, tmp_path):
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_OIDC_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("MAVERICK_OIDC_AUDIENCE", "maverick")
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("MAVERICK_OIDC_REDIRECT_URI", "http://127.0.0.1/auth/callback")
    monkeypatch.setenv("MAVERICK_OIDC_SESSION_SECRET", SESSION_SECRET)
    monkeypatch.setenv("MAVERICK_OIDC_AUTHORIZATION_ENDPOINT", AUTH_ENDPOINT)
    monkeypatch.setenv("MAVERICK_OIDC_TOKEN_ENDPOINT", TOKEN_ENDPOINT)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:admin-1")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_MFA_REQUIRE",
                 "MAVERICK_MFA_STEP_UP_MINUTES", "MAVERICK_IP_ALLOWLIST"):
        monkeypatch.delenv(name, raising=False)
    ol._CONSUMED_TX_IDS.clear()
    config.reset_config_cache()
    yield
    ol._CONSUMED_TX_IDS.clear()
    config.reset_config_cache()


def _login(client, monkeypatch, *, sub="user-xyz", claims=None, path="/auth/login"):
    """Run the whole browser flow with an ID token carrying ``claims``."""
    resp = client.get(path, follow_redirects=False)
    assert resp.status_code == 302, resp.text
    q = parse_qs(urlparse(resp.headers["location"]).query)
    state, nonce = q["state"][0], q["nonce"][0]

    async def _fake_exchange(*a, **k):
        return {"id_token": "fake.id.token"}

    monkeypatch.setattr(ol, "_exchange_code_for_tokens", _fake_exchange)
    token_claims = {"sub": sub, "nonce": nonce, **(claims or {})}
    monkeypatch.setattr(ol, "verify_oidc_token", lambda token: VerifiedPrincipal(
        sub=sub, issuer=ISSUER, audience="maverick", claims=token_claims))
    return client.get(f"/auth/callback?code=c&state={state}", follow_redirects=False), q


@pytest.fixture
def client():
    return TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)


# ---- sign-in with a second factor --------------------------------------------


def test_session_records_second_factor_and_appears_on_the_page(client, monkeypatch):
    resp, _ = _login(client, monkeypatch, claims={"amr": ["pwd", "otp"]})
    assert resp.status_code == 303
    payload = verify_session(client.cookies.get(ol.SESSION_COOKIE), SESSION_SECRET)
    assert payload["mfa"] is True and payload["sid"] and payload["mfa_at"] == payload["iat"]
    record = session_registry.get(payload["sid"])
    assert record.principal == "user:user-xyz" and record.mfa and record.via == "session"
    page = client.get("/settings/sessions", headers={"Accept": "text/html"})
    assert page.status_code == 200
    assert "(this device)" in page.text and "Company sign-in" in page.text
    api = client.get("/api/v1/sessions").json()["sessions"]
    assert len(api) == 1 and api[0]["sid"] == payload["sid"] and api[0]["current"] is True


def test_policy_off_accepts_a_sign_in_without_a_second_factor(client, monkeypatch):
    resp, _ = _login(client, monkeypatch, claims={"amr": ["pwd"]})
    assert resp.status_code == 303
    payload = verify_session(client.cookies.get(ol.SESSION_COOKIE), SESSION_SECRET)
    assert payload["mfa"] is False and "mfa_at" not in payload
    assert client.get("/metrics").status_code == 200


def test_policy_on_refuses_a_sign_in_without_a_second_factor(client, monkeypatch):
    from urllib.parse import parse_qs, urlsplit

    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "1")
    resp, _ = _login(client, monkeypatch, claims={"amr": ["pwd"]})
    assert resp.status_code == 303
    location = urlsplit(resp.headers["location"])
    assert location.path == "/auth/error"
    assert parse_qs(location.query) == {"return_to": ["/"], "reason": ["mfa"]}
    assert not client.cookies.get(ol.SESSION_COOKIE)
    page = client.get("/auth/error?reason=mfa", headers={"Accept": "text/html"})
    assert page.status_code == 403
    assert "include a second factor" in page.text
    assert "/auth/login?fresh=1" in page.text
    # An unknown reason stays a generic, detail-free recovery page.
    generic = client.get("/auth/error?reason=signature")
    assert generic.status_code == 401
    assert "Sign-in could not finish" in generic.text
    assert "signature" not in generic.text


def test_policy_on_accepts_amr_and_configured_acr(client, monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "1")
    (tmp_path / "home").mkdir(exist_ok=True)
    (tmp_path / "home" / "config.toml").write_text(
        "[auth.mfa]\nacr_values = [\"urn:x:mfa\"]\n", encoding="utf-8")
    config.reset_config_cache()
    resp, q = _login(client, monkeypatch, claims={"amr": ["pwd"], "acr": "urn:x:mfa"})
    assert resp.status_code == 303 and resp.headers["location"] == "/"
    # The configured context was also requested from the provider.
    assert q["acr_values"] == ["urn:x:mfa"]
    fresh = TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)
    resp, _ = _login(fresh, monkeypatch, claims={"amr": ["mfa"]})
    assert resp.status_code == 303 and resp.headers["location"] == "/"


def test_fresh_login_asks_the_provider_to_authenticate_again(client):
    resp = client.get("/auth/login?fresh=1&return_to=/users", follow_redirects=False)
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["prompt"] == ["login"] and q["max_age"] == ["0"]
    plain = TestClient(app, base_url="http://127.0.0.1").get("/auth/login", follow_redirects=False)
    assert "prompt" not in parse_qs(urlparse(plain.headers["location"]).query)


def test_policy_turned_on_later_refuses_an_existing_session(client, monkeypatch):
    _login(client, monkeypatch, claims={"amr": ["pwd"]})
    assert client.get("/metrics").status_code == 200
    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "1")
    refused = client.get("/metrics")
    assert refused.status_code == 403
    assert refused.json()["detail"] == mfa_policy.MFA_MISSING_MESSAGE
    page = client.get("/users", headers={"Accept": "text/html"})
    assert page.status_code == 403 and "Sign in again" in page.text
    # Signing out still works so the person can start over.
    assert client.post("/auth/logout", follow_redirects=False).status_code == 303


# ---- step-up ------------------------------------------------------------------


def test_step_up_fresh_session_passes_and_stale_session_is_refused(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "1")
    _login(client, monkeypatch, sub="admin-1", claims={"amr": ["mfa"]})
    ok = client.post("/users/set", data={"principal": "user:bob", "role": "viewer"},
                     follow_redirects=False)
    assert ok.status_code == 303
    monkeypatch.setattr(mfa_policy, "step_up_seconds", lambda: -1)  # everything is stale
    refused = client.post("/users/set", data={"principal": "user:bob", "role": "admin"},
                          headers={"Referer": "http://127.0.0.1/users?tab=roles"},
                          follow_redirects=False)
    assert refused.status_code == 403
    body = refused.json()
    assert body["detail"].startswith("This action needs a recent sign-in")
    # Back to the page the form was on: /users/set itself has no GET route.
    assert body["reauthenticate"] == "/auth/login?fresh=1&return_to=%2Fusers%3Ftab%3Droles"
    assert refused.headers["X-Reauthenticate"] == body["reauthenticate"]
    # The stale session may still read.
    assert client.get("/users", headers={"Accept": "text/html"}).status_code == 200


def test_step_up_does_not_apply_without_the_policy_or_without_named_sign_in(client, monkeypatch):
    _login(client, monkeypatch, sub="admin-1", claims={"amr": ["pwd"]})
    ok = client.post("/users/set", data={"principal": "user:bob", "role": "viewer"},
                     follow_redirects=False)
    assert ok.status_code == 303
    # Auth-off local mode: no principal, nothing to step up, even with the switch on.
    for name in ("MAVERICK_OIDC_ENABLED", "MAVERICK_DASHBOARD_ADMINS"):
        monkeypatch.delenv(name)
    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "1")
    local = TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)
    assert local.post("/users/set", data={"principal": "user:bob", "role": "viewer"},
                      follow_redirects=False).status_code == 303


# ---- the second factor is dated by the provider's auth_time ------------------------


def _session_payload(client):
    return verify_session(client.cookies.get(ol.SESSION_COOKIE), SESSION_SECRET)


def test_old_auth_time_with_an_mfa_amr_is_not_a_fresh_second_factor(client, monkeypatch):
    # A provider that silently reuses its own SSO session returns amr=mfa for a
    # sign-in that happened hours ago; the callback's clock must not re-date it.
    import time as _time

    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "1")
    old = int(_time.time()) - 6 * 3600
    resp, _ = _login(client, monkeypatch, sub="admin-1",
                     claims={"amr": ["mfa"], "auth_time": old})
    assert resp.status_code == 303 and resp.headers["location"] == "/"
    payload = _session_payload(client)
    assert payload["mfa"] is True and payload["mfa_at"] == old
    assert session_registry.get(payload["sid"]).mfa_at == old
    refused = client.post("/users/set", data={"principal": "user:bob", "role": "admin"},
                          follow_redirects=False)
    assert refused.status_code == 403
    assert refused.json()["reauthenticate"].startswith("/auth/login?fresh=1")


def test_recent_auth_time_dates_the_second_factor(client, monkeypatch):
    import time as _time

    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "1")
    recent = int(_time.time()) - 120
    _login(client, monkeypatch, sub="admin-1", claims={"amr": ["mfa"], "auth_time": recent})
    assert _session_payload(client)["mfa_at"] == recent
    ok = client.post("/users/set", data={"principal": "user:bob", "role": "viewer"},
                     follow_redirects=False)
    assert ok.status_code == 303


def test_unusable_auth_time_falls_back_to_the_sign_in_time(client, monkeypatch):
    import time as _time

    for n, bad in enumerate(("soon", True, _time.time() + 3600, float("nan"))):
        other = TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)
        ol._CONSUMED_TX_IDS.clear()
        _login(other, monkeypatch, claims={"amr": ["mfa"], "auth_time": bad})
        payload = _session_payload(other)
        assert payload["mfa"] is True and payload["mfa_at"] == payload["iat"], n


@pytest.mark.parametrize("claims", [
    {"amr": ["mfa"]},                                         # no auth_time at all
    {"amr": ["mfa"], "auth_time": 1_000_000},                 # years old
    {"amr": ["mfa"], "auth_time": "not-a-time"},
])
def test_step_up_sign_in_without_a_fresh_auth_time_is_refused(client, monkeypatch, claims):
    # ``?fresh=1`` asked the provider to authenticate again (max_age=0); an ID
    # token that cannot show it did is no proof of a fresh second factor.
    from urllib.parse import urlsplit

    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "1")
    resp, _ = _login(client, monkeypatch, claims=claims, path="/auth/login?fresh=1")
    assert resp.status_code == 303
    location = urlsplit(resp.headers["location"])
    assert location.path == "/auth/error" and parse_qs(location.query)["reason"] == ["mfa"]
    assert not client.cookies.get(ol.SESSION_COOKIE)


def test_step_up_sign_in_with_a_new_auth_time_gives_a_fresh_session(client, monkeypatch):
    import time as _time

    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "1")
    now = int(_time.time())
    resp, _ = _login(client, monkeypatch, sub="admin-1", path="/auth/login?fresh=1",
                     claims={"amr": ["mfa"], "auth_time": now - 5})
    assert resp.status_code == 303 and resp.headers["location"] == "/"
    assert _session_payload(client)["mfa_at"] == now - 5
    ok = client.post("/users/set", data={"principal": "user:bob", "role": "viewer"},
                     follow_redirects=False)
    assert ok.status_code == 303


# ---- sessions: sign out a device, sign out everywhere ------------------------------


def _audit_rows(monkeypatch):
    rows: list[dict] = []
    from maverick import audit

    def _capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", _capture)
    return rows


def test_sign_out_this_device_ends_only_that_session(client, monkeypatch):
    rows = _audit_rows(monkeypatch)
    _login(client, monkeypatch, claims={"amr": ["mfa"]})
    other = TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)
    _login(other, monkeypatch, claims={"amr": ["mfa"]})
    mine = client.get("/api/v1/sessions").json()["sessions"]
    assert len(mine) == 2
    other_sid = next(s["sid"] for s in mine if not s["current"])
    resp = client.delete(f"/api/v1/sessions/{other_sid}")
    assert resp.status_code == 200 and resp.json() == {
        "revoked": 1, "principal": "user:user-xyz", "current": False}
    assert other.get("/metrics").status_code == 401   # that device is out
    assert client.get("/metrics").status_code == 200  # this one is not
    assert [r["verb"] for r in rows if r["kind"] == "control_plane_action"] == ["revoke_sessions"]
    assert rows[-1]["session"] == other_sid and rows[-1]["principal"] == "user:user-xyz"


def test_sign_out_everywhere_ends_every_session_and_legacy_cookies(client, monkeypatch):
    rows = _audit_rows(monkeypatch)
    _login(client, monkeypatch, claims={"amr": ["mfa"]})
    legacy = TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)
    import time as _time

    from maverick.web_session import sign_session

    now = int(_time.time()) - 5
    legacy.cookies.set(ol.SESSION_COOKIE, sign_session(
        {"sub": "user-xyz", "iat": now, "exp": now + 3600}, SESSION_SECRET))
    assert legacy.get("/metrics").status_code == 200  # untracked, still valid
    resp = client.post("/settings/sessions/revoke-all", data={"principal": "user:user-xyz"},
                       follow_redirects=False)
    assert resp.status_code == 303 and resp.headers["location"] == "/"
    assert client.get("/metrics").status_code == 401
    assert legacy.get("/metrics").status_code == 401
    assert rows[-1]["detail"] == "signed out everywhere" and rows[-1]["count"] == 1


def test_only_an_administrator_sees_or_ends_other_peoples_sessions(client, monkeypatch):
    _login(client, monkeypatch, claims={"amr": ["mfa"]})
    admin = TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)
    _login(admin, monkeypatch, sub="admin-1", claims={"amr": ["mfa"]})
    assert client.get("/api/v1/sessions?principal=user:admin-1").status_code == 403
    assert client.get("/api/v1/sessions?all=1").json()["sessions"][0]["principal"] == "user:user-xyz"
    everyone = admin.get("/api/v1/sessions?all=1").json()["sessions"]
    assert {s["principal"] for s in everyone} == {"user:user-xyz", "user:admin-1"}
    theirs = admin.get("/api/v1/sessions?principal=user:user-xyz").json()["sessions"]
    assert len(theirs) == 1
    admin_sid = next(s["sid"] for s in everyone if s["principal"] == "user:admin-1")
    assert client.delete(f"/api/v1/sessions/{admin_sid}").status_code == 403
    assert admin.delete(f"/api/v1/sessions/{theirs[0]['sid']}").status_code == 200
    assert client.get("/metrics").status_code == 401
    page = admin.get("/settings/sessions", headers={"Accept": "text/html"})
    assert page.status_code == 200 and "Sign out everywhere" in page.text


def test_revoke_is_a_sensitive_action(client, monkeypatch):
    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "1")
    _login(client, monkeypatch, claims={"amr": ["mfa"]})
    sid = client.get("/api/v1/sessions").json()["sessions"][0]["sid"]
    monkeypatch.setattr(mfa_policy, "step_up_seconds", lambda: -1)
    resp = client.delete(f"/api/v1/sessions/{sid}")
    assert resp.status_code == 403 and "reauthenticate" in resp.json()


def test_a_session_whose_record_is_unknown_is_not_a_session(client, monkeypatch):
    _login(client, monkeypatch, claims={"amr": ["mfa"]})
    session_registry._path().unlink()  # the record is gone: fail closed
    assert client.get("/metrics").status_code == 401


def test_sessions_page_works_in_local_mode(monkeypatch):
    for name in ("MAVERICK_OIDC_ENABLED", "MAVERICK_DASHBOARD_ADMINS"):
        monkeypatch.delenv(name)
    local = TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)
    page = local.get("/settings/sessions", headers={"Accept": "text/html"})
    assert page.status_code == 200 and "No active sessions are recorded" in page.text
    assert local.get("/api/v1/sessions").json() == {"sessions": []}
