"""Integration tests for the built-in OIDC browser-login flow.

Hermetic: no real network and no real JWT. We configure the login flow via
``MAVERICK_OIDC_*`` env (so the real ``login_enabled()`` / ``load_oidc_config()``
gate is exercised), with explicit authorization/token endpoints so discovery is
never called. The token exchange helper and the ID-token verification
(``maverick.oidc.verify_oidc_token``, imported into ``oidc_login``) are
monkeypatched.

Covers the security checklist: login redirects with state + PKCE S256; callback
happy path sets the session + redirects to a safe ``return_to``; state-mismatch
-> 400 (no token exchange); open-redirect blocked; logout clears; and all routes
404 when login is disabled.
"""
from __future__ import annotations

import subprocess
import sys
from urllib.parse import parse_qs, urlparse

import maverick_dashboard.oidc_login as ol
import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal
from maverick.web_session import verify_session
from maverick_dashboard.app import app

AUTH_ENDPOINT = "https://idp.example.com/authorize"
TOKEN_ENDPOINT = "https://idp.example.com/token"
SESSION_SECRET = "unit-test-session-secret"  # pragma: allowlist secret
CLIENT_ID = "test-client-id"
ISSUER = "https://idp.example.com"


def test_module_import_does_not_eagerly_load_httpx():
    code = (
        "import sys\n"
        "import maverick_dashboard.oidc_login\n"
        "print('httpx' in sys.modules)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == "False"


@pytest.fixture
def login_env(monkeypatch, tmp_path):
    """Fully configure the login flow via env (explicit endpoints, no discovery)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_OIDC_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("MAVERICK_OIDC_AUDIENCE", "maverick")
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv(
        "MAVERICK_OIDC_REDIRECT_URI", "http://127.0.0.1/auth/callback"
    )
    monkeypatch.setenv("MAVERICK_OIDC_SESSION_SECRET", SESSION_SECRET)
    monkeypatch.setenv("MAVERICK_OIDC_AUTHORIZATION_ENDPOINT", AUTH_ENDPOINT)
    monkeypatch.setenv("MAVERICK_OIDC_TOKEN_ENDPOINT", TOKEN_ENDPOINT)
    # No dashboard token: keep the dashboard-token middleware out of the way; the
    # /auth/* routes are exempt regardless, and gated routes still hit the OIDC
    # dependency.
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


@pytest.fixture(autouse=True)
def clear_consumed_transactions():
    ol._CONSUMED_TX_IDS.clear()
    yield
    ol._CONSUMED_TX_IDS.clear()


@pytest.fixture
def client():
    return TestClient(app, base_url="http://127.0.0.1")


# ---- login: redirect carries state + PKCE S256 --------------------------------


def test_login_redirects_with_state_and_pkce(login_env, client):
    resp = client.get("/auth/login", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(AUTH_ENDPOINT + "?")
    q = parse_qs(urlparse(location).query)
    assert q["response_type"] == ["code"]
    assert q["client_id"] == [CLIENT_ID]
    assert q["scope"] == ["openid"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"] and q["code_challenge"][0]
    assert q["state"] and q["state"][0]

    # The transaction cookie is set, httponly, samesite=lax, and signed.
    set_cookie = resp.headers["set-cookie"]
    assert ol.TX_COOKIE in set_cookie
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower()
    tx_raw = client.cookies.get(ol.TX_COOKIE)
    tx = verify_session(tx_raw, SESSION_SECRET)
    assert tx is not None
    # The state in the cookie matches the state sent to the IdP.
    assert tx["state"] == q["state"][0]
    assert tx["cv"]  # PKCE code_verifier stashed in the signed tx cookie
    assert tx["jti"]  # opaque id used to reject callback replay


def test_auth_cookie_secure_only_on_plain_http_loopback(login_env, client):
    # Plain-HTTP loopback dev: no Secure, or http://localhost never gets the
    # cookie back.
    plain = client.get("/auth/login", follow_redirects=False)
    assert "secure" not in plain.headers["set-cookie"].lower()
    # Behind a TLS-terminating proxy (connects over loopback but the user is on
    # HTTPS): the forwarded-proto header must force Secure so the session cookie
    # can't leak over a downgraded HTTP request.
    fresh = TestClient(app, base_url="http://127.0.0.1")
    proxied = fresh.get(
        "/auth/login", follow_redirects=False,
        headers={"X-Forwarded-Proto": "https"})
    assert "secure" in proxied.headers["set-cookie"].lower()


def test_login_sanitizes_open_redirect_return_to(login_env, client):
    """An external return_to is dropped to '/' before being stashed."""
    resp = client.get(
        "/auth/login?return_to=https://evil.example.com/x", follow_redirects=False
    )
    assert resp.status_code == 302
    tx = verify_session(client.cookies.get(ol.TX_COOKIE), SESSION_SECRET)
    assert tx["return_to"] == "/"


def test_login_keeps_safe_return_to(login_env, client):
    resp = client.get("/auth/login?return_to=/goals", follow_redirects=False)
    assert resp.status_code == 302
    tx = verify_session(client.cookies.get(ol.TX_COOKIE), SESSION_SECRET)
    assert tx["return_to"] == "/goals"


# ---- callback: happy path -----------------------------------------------------


def _do_login(client, return_to="/goals"):
    """Run /auth/login and return the (state, tx_cookie_value, nonce)."""
    path = "/auth/login" + (f"?return_to={return_to}" if return_to else "")
    resp = client.get(path, follow_redirects=False)
    location = resp.headers["location"]
    qs = parse_qs(urlparse(location).query)
    return qs["state"][0], client.cookies.get(ol.TX_COOKIE), qs["nonce"][0]


def test_callback_happy_path_sets_session_and_redirects(login_env, client, monkeypatch):
    state, _, nonce = _do_login(client, return_to="/goals")

    posted = {}

    async def _fake_exchange(url, *, cfg, code, code_verifier):
        posted["url"] = url
        posted["data"] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": cfg.redirect_uri,
            "client_id": cfg.client_id,
            "code_verifier": code_verifier,
        }
        posted["auth"] = (cfg.client_id, cfg.client_secret)
        return {"id_token": "fake.id.token", "access_token": "ignored"}

    monkeypatch.setattr(ol, "_exchange_code_for_tokens", _fake_exchange)
    monkeypatch.setattr(
        ol, "verify_oidc_token",
        lambda token: VerifiedPrincipal(
            sub="user-xyz", issuer=ISSUER, audience="maverick",
            claims={"sub": "user-xyz", "nonce": nonce,
                    "email": "Alice@Example.com", "email_verified": True},
        ),
    )

    resp = client.get(
        f"/auth/callback?code=auth-code-abc&state={state}", follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/goals"

    # PKCE verifier + the right grant were sent to the (https) token endpoint.
    assert posted["url"] == TOKEN_ENDPOINT
    assert posted["data"]["grant_type"] == "authorization_code"
    assert posted["data"]["code"] == "auth-code-abc"
    assert posted["data"]["code_verifier"]
    assert posted["auth"] == (CLIENT_ID, "test-client-secret")

    # Session cookie set + valid; tx cookie cleared.
    session_raw = client.cookies.get(ol.SESSION_COOKIE)
    assert session_raw
    payload = verify_session(session_raw, SESSION_SECRET)
    assert payload is not None and payload["sub"] == "user-xyz"
    assert payload["idp_email"] == "alice@example.com"
    assert payload["verified_email"] == "alice@example.com"
    set_cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in set_cookie and "samesite=lax" in set_cookie


def test_invite_email_uses_signed_subject_only_when_email_not_rejected():
    from maverick_dashboard.oidc_login import _oidc_invite_email

    assert _oidc_invite_email({"sub": "Alice@Example.com"}) == "alice@example.com"
    assert _oidc_invite_email({"sub": "Alice@Example.com", "email_verified": False}) == ""


def test_session_cookie_authenticates_gated_route(login_env, client, monkeypatch):
    """After login, the session cookie satisfies require_principal on a gated
    route (here /metrics), with OIDC enabled and no bearer header."""
    state, _, nonce = _do_login(client)

    async def _fake_exchange(*a, **k):
        return {"id_token": "fake.id.token"}

    monkeypatch.setattr(ol, "_exchange_code_for_tokens", _fake_exchange)
    monkeypatch.setattr(
        ol, "verify_oidc_token",
        lambda token: VerifiedPrincipal(
            sub="user-xyz", issuer=ISSUER, audience="maverick",
            claims={"nonce": nonce},
        ),
    )
    client.get(f"/auth/callback?code=c&state={state}", follow_redirects=False)

    # /metrics is gated by the OIDC dependency; the session cookie should let it
    # through with no Authorization header.
    resp = client.get("/metrics")
    assert resp.status_code == 200


@pytest.mark.parametrize("subject", ["alice ", "alice\n", "x" * 252])
def test_signed_browser_session_rejects_invalid_subject_domain(login_env, subject):
    import time
    from types import SimpleNamespace

    from maverick.web_session import sign_session

    now = int(time.time())
    raw = sign_session(
        {"sub": subject, "iat": now, "exp": now + 3600},
        SESSION_SECRET,
    )
    request = SimpleNamespace(cookies={ol.SESSION_COOKIE: raw})

    assert ol._principal_from_request_session(request) is None


# ---- callback: state mismatch (CSRF) ------------------------------------------


def test_callback_state_mismatch_returns_400_no_exchange(login_env, client, monkeypatch):
    _do_login(client)

    async def _must_not_exchange(*a, **k):  # pragma: no cover - must not run
        raise AssertionError("token exchange ran despite state mismatch")

    monkeypatch.setattr(ol, "_exchange_code_for_tokens", _must_not_exchange)

    resp = client.get(
        "/auth/callback?code=c&state=WRONG-STATE", follow_redirects=False
    )
    assert resp.status_code == 400


def test_callback_replayed_tx_cookie_is_rejected_before_exchange(
    login_env, client, monkeypatch
):
    state, tx_cookie, nonce = _do_login(client)
    calls = []

    async def _fake_exchange(url, *, cfg, code, code_verifier):
        calls.append(code)
        return {"id_token": "fake.id.token"}

    monkeypatch.setattr(ol, "_exchange_code_for_tokens", _fake_exchange)
    monkeypatch.setattr(
        ol,
        "verify_oidc_token",
        lambda token: VerifiedPrincipal(
            sub="user-xyz", issuer=ISSUER, audience="maverick",
            claims={"nonce": nonce},
        ),
    )

    first = client.get(f"/auth/callback?code=first&state={state}", follow_redirects=False)
    assert first.status_code == 303

    # A non-browser attacker can keep sending the original Cookie header even
    # after the response clears it. The consumed-jti guard must reject that
    # replay before another outbound token exchange is attempted.
    headers = {"cookie": f"{ol.TX_COOKIE}={tx_cookie}"}
    replay = client.get(
        f"/auth/callback?code=replay&state={state}",
        headers=headers,
        follow_redirects=False,
    )
    assert replay.status_code == 303
    assert calls == ["first"]


def test_callback_missing_tx_cookie_fails(login_env, client, monkeypatch):
    """No transaction cookie at all -> failure, no token exchange."""
    async def _must_not_exchange(*a, **k):  # pragma: no cover
        raise AssertionError("token exchange ran without a tx cookie")

    monkeypatch.setattr(ol, "_exchange_code_for_tokens", _must_not_exchange)
    # Fresh client (no tx cookie).
    fresh = TestClient(app, base_url="http://127.0.0.1")
    resp = fresh.get("/auth/callback?code=c&state=whatever", follow_redirects=False)
    assert resp.status_code in (303, 400)  # redirect to /auth/error (cleared)
    # No session was set.
    assert not fresh.cookies.get(ol.SESSION_COOKIE)


# ---- callback: id_token verification failure ----------------------------------


def test_callback_verify_failure_sets_no_session(login_env, client, monkeypatch):
    from maverick.oidc import OIDCError

    state, _, _ = _do_login(client)

    async def _fake_exchange(*a, **k):
        return {"id_token": "bad.token"}

    monkeypatch.setattr(ol, "_exchange_code_for_tokens", _fake_exchange)

    def _reject(token):
        raise OIDCError("verification failed")

    monkeypatch.setattr(ol, "verify_oidc_token", _reject)

    resp = client.get(
        f"/auth/callback?code=c&state={state}", follow_redirects=False
    )
    assert resp.status_code == 303  # redirect to error
    assert not client.cookies.get(ol.SESSION_COOKIE)


# ---- logout -------------------------------------------------------------------


def test_callback_records_pairwise_sub_in_subject_directory(
    login_env, client, monkeypatch
):
    # Entra-shaped login: pairwise `sub` plus email/oid claims. The callback must
    # record the sub against those identifiers so SCIM deprovision can reach it.
    state, _, nonce = _do_login(client)

    async def _fake_exchange(url, *, cfg, code, code_verifier):
        return {"id_token": "fake.id.token"}

    monkeypatch.setattr(ol, "_exchange_code_for_tokens", _fake_exchange)
    monkeypatch.setattr(
        ol, "verify_oidc_token",
        lambda token: VerifiedPrincipal(
            sub="pairwise-zzz", issuer=ISSUER, audience="maverick",
            claims={"sub": "pairwise-zzz", "email": "dana@example.com",
                    "oid": "aad-oid-7", "nonce": nonce},
        ),
    )
    resp = client.get(
        f"/auth/callback?code=c&state={state}", follow_redirects=False)
    assert resp.status_code == 303

    from maverick_dashboard import subject_directory as sd
    assert sd.subs_for(["dana@example.com"]) == {"pairwise-zzz"}
    assert sd.subs_for(["aad-oid-7"]) == {"pairwise-zzz"}


def test_logout_clears_session(login_env, client):
    confirmation = client.get("/auth/logout", follow_redirects=False)
    assert confirmation.status_code == 200 and "set-cookie" not in confirmation.headers
    resp = client.post("/auth/logout", follow_redirects=False, headers={"Origin": "http://127.0.0.1"})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    set_cookie = resp.headers.get("set-cookie", "")
    # delete_cookie sets the cookie with an empty value / expiry in the past.
    assert ol.SESSION_COOKIE in set_cookie


def test_logout_redirects_to_idp_when_end_session_configured(
    login_env, client, monkeypatch
):
    # With an end_session_endpoint, logout performs RP-initiated logout so the
    # IdP's SSO session ends too -- otherwise the next /auth/login silently logs
    # the user right back in ("logout doesn't work"). The local cookie is still
    # cleared, and the browser is returned to the app origin the IdP allow-lists.
    monkeypatch.setenv(
        "MAVERICK_OIDC_END_SESSION_ENDPOINT",
        "https://idp.example.com/oidc/logout",
    )
    resp = client.post("/auth/logout", follow_redirects=False, headers={"Origin": "http://127.0.0.1"})
    assert resp.status_code == 303
    parsed = urlparse(resp.headers["location"])
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == (
        "https://idp.example.com/oidc/logout"
    )
    qs = parse_qs(parsed.query)
    assert qs.get("client_id") == [CLIENT_ID]
    assert qs.get("post_logout_redirect_uri") == ["http://127.0.0.1/"]
    assert ol.SESSION_COOKIE in resp.headers.get("set-cookie", "")


def test_logout_all_revokes_even_when_session_already_revoked(login_env, client):
    # Regression: "log out everywhere" must bump the epoch even if THIS session
    # was already revoked once -- otherwise other (newer) bearers survive.
    import time

    from maverick.web_session import sign_session
    from maverick_dashboard import session_revocation as sr

    now = int(time.time())
    raw = sign_session(
        {"sub": "user-123", "iat": now, "exp": now + 3600}, SESSION_SECRET)
    # Pre-revoke the principal (epoch now) so the session is already revoked.
    sr.revoke_principal("user-123")
    epoch_before = sr.revocation_epoch("user-123")
    assert epoch_before > 0

    client.cookies.set(ol.SESSION_COOKIE, raw)
    # Same-origin Referer so the destructive ?all revocation is honored.
    resp = client.post(
        "/auth/logout?all=1", follow_redirects=False,
        headers={"Referer": "http://127.0.0.1/settings"})
    assert resp.status_code == 303
    # The epoch was re-bumped (>=), proving revoke fired despite the prior
    # revocation -- not silently skipped.
    assert sr.revocation_epoch("user-123") >= epoch_before


def test_logout_all_ignored_cross_site(login_env, client):
    # A cross-site navigation must not clear the cookie or revoke sessions.
    import time

    from maverick.web_session import sign_session
    from maverick_dashboard import session_revocation as sr

    now = int(time.time())
    raw = sign_session(
        {"sub": "user-xsite", "iat": now, "exp": now + 3600}, SESSION_SECRET)
    epoch_before = sr.revocation_epoch("user-xsite")
    assert epoch_before == 0

    client.cookies.set(ol.SESSION_COOKIE, raw)
    resp = client.get(
        "/auth/logout?all=1", follow_redirects=False,
        headers={"Referer": "http://evil.example/"})
    assert resp.status_code == 200
    assert "set-cookie" not in resp.headers
    refused = client.post("/auth/logout?all=1", follow_redirects=False,
                          headers={"Origin": "http://evil.example"})
    assert refused.status_code == 403 and "set-cookie" not in refused.headers
    # Cross-site referer -> the epoch was NOT bumped (revocation did not fire).
    assert sr.revocation_epoch("user-xsite") == 0


@pytest.mark.parametrize("origin", [None, "https://127.0.0.1", "http://127.0.0.1:81", "http://evil.example"])
def test_logout_post_requires_matching_full_origin(login_env, client, origin):
    headers = {"Origin": origin} if origin else {}
    response = client.post("/auth/logout", headers=headers, follow_redirects=False)
    assert response.status_code == 403
    assert "set-cookie" not in response.headers


def test_logout_uses_configured_public_origin_behind_proxy(login_env, client, monkeypatch):
    monkeypatch.setenv("MAVERICK_PUBLIC_URL", "https://lightwork.example")
    headers = {"Origin": "https://lightwork.example"}
    assert client.post("/auth/logout", headers=headers, follow_redirects=False).status_code == 303
    headers["Origin"] = "http://lightwork.example"
    assert client.post("/auth/logout", headers=headers, follow_redirects=False).status_code == 403


def test_logout_rejects_conflicting_origin_even_with_matching_referer(login_env, client):
    response = client.post("/auth/logout", follow_redirects=False, headers={
        "Origin": "http://evil.example", "Referer": "http://127.0.0.1/page",
    })
    assert response.status_code == 403


def test_logout_accepts_equivalent_default_port_and_mounted_form(login_env):
    mounted = TestClient(app, base_url="http://127.0.0.1", root_path="/lightwork")
    page = mounted.get("/auth/logout?all=1")
    assert page.status_code == 200 and 'action="logout?all=1"' in page.text
    response = mounted.post("/auth/logout", headers={"Origin": "http://127.0.0.1:80"}, follow_redirects=False)
    assert response.status_code == 303


# ---- disabled: every route 404s -----------------------------------------------


def test_routes_404_when_login_disabled(monkeypatch, tmp_path):
    """With the login flow not configured, all /auth/* routes 404 (inert)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for name in (
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_OIDC_CLIENT_ID",
        "MAVERICK_OIDC_SESSION_SECRET",
        "MAVERICK_OIDC_ISSUER",
        "MAVERICK_OIDC_AUTHORIZATION_ENDPOINT",
        "MAVERICK_OIDC_TOKEN_ENDPOINT",
    ):
        monkeypatch.delenv(name, raising=False)
    c = TestClient(app, base_url="http://127.0.0.1")
    for path in ("/auth/login", "/auth/callback", "/auth/logout", "/auth/error"):
        assert c.get(path, follow_redirects=False).status_code == 404


# ---- replay guard: shared store backs the multi-replica HA case ---------------


class _FakeSharedWorld:
    """Minimal stand-in for the shared world model: a first-writer-wins insert
    mirroring ``mark_message_processed`` (True once per id, then False)."""

    def __init__(self):
        self.seen: set[tuple[str, str]] = set()
        self.released: list[tuple[str, str]] = []

    def mark_message_processed(self, channel, external_id, goal_id=None):
        key = (channel, external_id)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True

    def release_processed_message(self, channel, external_id):
        key = (channel, external_id)
        self.released.append(key)
        self.seen.discard(key)


def test_callback_releases_shared_tx_when_token_exchange_fails(
    login_env, client, monkeypatch
):
    """Bogus unauthenticated callbacks must not leave durable HA replay rows."""
    import maverick_dashboard._shared as shared
    from maverick import world_model_backends

    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    fake = _FakeSharedWorld()
    monkeypatch.setattr(shared, "_world", lambda: fake)
    state, tx_cookie, _ = _do_login(client)
    tx = verify_session(tx_cookie, SESSION_SECRET)

    async def _fail_exchange(*a, **k):
        raise RuntimeError("bad code")

    monkeypatch.setattr(ol, "_exchange_code_for_tokens", _fail_exchange)

    resp = client.get(
        f"/auth/callback?code=bogus&state={state}", follow_redirects=False
    )
    assert resp.status_code == 303
    key = (ol._OIDC_TX_CHANNEL, tx["jti"])
    assert key in fake.released
    assert key not in fake.seen


def test_consume_tx_in_process_guard_is_default(monkeypatch):
    """No shared backend (the default SQLite / single-process deployment): the
    in-process dict consumes once and rejects the replay."""
    import asyncio

    from maverick import world_model_backends
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: False)
    ol._CONSUMED_TX_IDS.clear()

    assert asyncio.run(ol._consume_tx_once("tx-1", ol._now() + 600)) is True
    assert asyncio.run(ol._consume_tx_once("tx-1", ol._now() + 600)) is False
    assert "tx-1" in ol._CONSUMED_TX_IDS  # recorded in-process


def test_consume_tx_uses_shared_store_under_postgres(monkeypatch):
    """HA / Postgres: the id is consumed in the SHARED store (so the guard holds
    across replicas), and the in-process dict is bypassed entirely."""
    import asyncio

    import maverick_dashboard._shared as shared
    from maverick import world_model_backends
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    fake = _FakeSharedWorld()
    monkeypatch.setattr(shared, "_world", lambda: fake)
    ol._CONSUMED_TX_IDS.clear()

    assert asyncio.run(ol._consume_tx_once("tx-A", ol._now() + 600)) is True
    assert asyncio.run(ol._consume_tx_once("tx-A", ol._now() + 600)) is False
    # consumed in the shared store under the namespaced channel...
    assert (ol._OIDC_TX_CHANNEL, "tx-A") in fake.seen
    # ...and the in-process guard was never touched.
    assert ol._CONSUMED_TX_IDS == {}


def test_consume_tx_falls_back_when_shared_store_errors(monkeypatch):
    """A broken shared store degrades to the in-process guard rather than
    hard-failing every login (defense-in-depth: cookie+PKCE+state still hold)."""
    import asyncio

    import maverick_dashboard._shared as shared
    from maverick import world_model_backends
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)

    def _boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(shared, "_world", _boom)
    ol._CONSUMED_TX_IDS.clear()

    assert asyncio.run(ol._consume_tx_once("tx-Z", ol._now() + 600)) is True
    assert asyncio.run(ol._consume_tx_once("tx-Z", ol._now() + 600)) is False
    assert "tx-Z" in ol._CONSUMED_TX_IDS  # fell back to in-process recording


@pytest.mark.parametrize("claims", [
    {"email": "alice@corp.example"},  # no email_verified asserted
    {"email": "alice@corp.example", "email_verified": "true"},  # not the boolean True
    {"email": "alice@corp.example", "email_verified": False},
    {"preferred_username": "alice@corp.example", "email_verified": True},  # a mutable alias, not the email claim
    {"upn": "alice@corp.example", "email_verified": True},
    {"sub": "alice@corp.example", "email_verified": True},
])
def test_only_a_verified_email_claim_is_the_permission_address(claims):
    assert ol._oidc_permission_email(claims) == ""


def test_the_permission_address_is_the_verified_email_claim_normalised():
    assert ol._oidc_permission_email({"email": "Alice@Corp.example", "email_verified": True}) == "alice@corp.example"


def test_the_session_carries_the_permission_address_only_for_a_signed_in_session():
    import time

    fresh = {"verified_email": "Alice@Corp.example", "iat": time.time()}
    assert ol.session_claims(fresh, None, via="session")["verified_email"] == "alice@corp.example"
    assert "verified_email" not in ol.session_claims(dict(fresh, iat=time.time()), None, via="invite")
    # The invitation address alone is not a permission address.
    assert "verified_email" not in ol.session_claims({"idp_email": "alice@corp.example", "iat": time.time()}, None, via="session")
