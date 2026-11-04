"""Dashboard auth + CSRF + headers + skill-install gate."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick.oidc import OIDCError, VerifiedPrincipal


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


# ---------- bearer auth: query-token branch deleted ----------

def test_query_token_no_longer_accepted(monkeypatch, tmp_path):
    """`?token=...` would leak via Referer/history/access logs, so it is refused."""
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    client = _client()
    resp = client.get("/?token=sekret")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "unauthorized"


def test_header_token_still_accepted(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    client = _client()
    resp = client.get("/", headers={"Authorization": "Bearer sekret"})
    assert resp.status_code == 200


def test_unauth_request_blocked_when_token_set(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    client = _client()
    resp = client.get("/")
    assert resp.status_code == 401


def test_healthz_still_exempt(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    client = _client()
    resp = client.get("/livez")
    assert resp.status_code == 200


# ---------- same-origin: fail-closed on missing headers ----------

def test_is_same_origin_fails_closed_on_post_without_headers(monkeypatch, tmp_path):
    """Prior fail-open let any same-machine tab POST to /chat/send via no-cors fetch."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    # No Origin, no Referer — the previous fail-open branch let this through.
    resp = client.post("/chat/send", data={"title": "x"})
    assert resp.status_code == 403
    assert "cross-site" in resp.json()["detail"]


def test_is_same_origin_accepts_with_matching_origin(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.post(
        "/chat/send",
        data={"title": "x"},
        headers={"Origin": "http://127.0.0.1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


def test_safe_methods_skip_csrf(monkeypatch, tmp_path):
    """GET/HEAD/OPTIONS bypass the same-origin check — they don't mutate."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.get("/")  # No Origin, no Referer
    assert resp.status_code == 200


# ---------- same-origin now covers /api/v1 mutations (launch review) ----------

def test_api_v1_mutation_blocks_forged_origin(monkeypatch, tmp_path):
    """The /api/v1 mutating routes (cancel/resume/halt/disable/enable/purge,
    POST facts) skipped the same-origin check that /chat/send enforced. In
    no-token (loopback) mode a malicious page could disable safety tools, arm
    the killswitch, or purge caches via an ambient cross-site POST. Now gated
    centrally in bearer_auth."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.post(
        "/api/v1/facts",
        json={"key": "x", "value": "y"},
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 403
    assert "cross-site" in resp.json()["detail"]


def test_api_v1_mutation_blocks_missing_origin(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.post("/api/v1/facts", json={"key": "x", "value": "y"})
    assert resp.status_code == 403
    assert "Origin header" in resp.json()["detail"]
    assert "Account > API keys" in resp.json()["detail"]


def test_api_v1_mutation_allows_matching_origin(monkeypatch, tmp_path):
    """A legitimate same-origin request passes the gate and reaches the handler."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.post(
        "/api/v1/facts",
        json={"key": "city", "value": "Lisbon"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert resp.status_code == 204


def test_oidc_bearer_api_mutation_does_not_require_browser_origin(
    monkeypatch, tmp_path,
):
    """An explicit verified bearer is API authority, not an ambient CSRF risk."""
    from maverick import world_model
    from maverick_dashboard import auth as auth_mod

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth_mod, "oidc_enabled", lambda: True)
    monkeypatch.setattr(
        auth_mod,
        "verify_oidc_token",
        lambda _token: VerifiedPrincipal(
            sub="api-client",
            issuer="https://issuer.example",
            audience="lightwork",
            claims={"iat": 1},
        ),
    )
    monkeypatch.setattr(auth_mod, "_enforce_scim_active", lambda _principal: None)
    monkeypatch.setattr(auth_mod, "_pin_tenant_from_principal", lambda *_args: None)
    monkeypatch.setattr(auth_mod, "role_for_principal", lambda _principal: "operator")

    response = _client().post(
        "/api/v1/facts",
        json={"key": "api", "value": "authorized"},
        headers={"Authorization": "Bearer valid-oidc-token"},
    )

    assert response.status_code == 204


def test_invalid_oidc_bearer_without_origin_is_401_not_cookie_fallback(
    monkeypatch, tmp_path,
):
    """CSRF bypass is conditional on the bearer dependency authenticating it."""
    from maverick import world_model
    from maverick_dashboard import auth as auth_mod

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(auth_mod, "oidc_enabled", lambda: True)
    monkeypatch.setattr(
        auth_mod,
        "_session_principal",
        lambda _request: VerifiedPrincipal(
            sub="ambient-cookie-user",
            issuer="browser-session",
            audience="lightwork",
            claims={"via": "session", "iat": 1},
        ),
    )

    def _reject(_token):
        raise OIDCError("invalid token")

    monkeypatch.setattr(auth_mod, "verify_oidc_token", _reject)

    response = _client().post(
        "/api/v1/facts",
        json={"key": "api", "value": "rejected"},
        headers={"Authorization": "Bearer invalid-oidc-token"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid OIDC token"


@pytest.mark.parametrize("identity_kind", ["oidc_session", "proxy", "saml", "invite"])
def test_static_token_composes_with_ambient_identity(
    monkeypatch, tmp_path, identity_kind,
):
    """A recovery/operator token must not disable configured enterprise SSO."""
    from maverick import world_model
    from maverick_dashboard import auth as auth_mod
    from maverick_dashboard import invites, saml

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-operator-token")
    monkeypatch.setattr(auth_mod, "oidc_enabled", lambda: False)
    monkeypatch.setattr(auth_mod, "proxy_auth_enabled", lambda: False)
    monkeypatch.setattr(auth_mod, "_session_principal", lambda _request: None)
    monkeypatch.setattr(auth_mod, "_invite_session_principal", lambda _request: None)
    monkeypatch.setattr(auth_mod, "_saml_policy_configured", lambda: False)
    monkeypatch.setattr(invites, "invites_enabled", lambda: False)
    monkeypatch.setattr(saml, "saml_enabled", lambda: False)
    monkeypatch.setattr(auth_mod, "_enforce_scim_active", lambda _principal: None)
    monkeypatch.setattr(auth_mod, "_pin_tenant_from_principal", lambda *_args: None)
    monkeypatch.setattr(auth_mod, "role_for_principal", lambda _principal: "operator")

    principal = VerifiedPrincipal(
        sub=f"{identity_kind}-user",
        issuer="https://issuer.example",
        audience="lightwork",
        claims={"via": "invite" if identity_kind == "invite" else "session", "iat": 1},
    )
    headers = {"Origin": "http://127.0.0.1"}
    if identity_kind == "oidc_session":
        monkeypatch.setattr(auth_mod, "oidc_enabled", lambda: True)
        monkeypatch.setattr(auth_mod, "_session_principal", lambda _request: principal)
    elif identity_kind == "proxy":
        monkeypatch.setattr(auth_mod, "proxy_auth_enabled", lambda: True)
        monkeypatch.setattr(auth_mod, "proxy_trusts", lambda _host: True)
        monkeypatch.setattr(auth_mod, "proxy_header_name", lambda: "X-Forwarded-User")
        headers["X-Forwarded-User"] = "proxy-user"
    elif identity_kind == "saml":
        monkeypatch.setattr(saml, "saml_enabled", lambda: True)
        monkeypatch.setattr(auth_mod, "_session_principal", lambda _request: principal)
    else:
        monkeypatch.setattr(invites, "invites_enabled", lambda: True)
        monkeypatch.setattr(auth_mod, "_invite_session_principal", lambda _request: principal)

    response = _client().post(
        "/api/v1/facts",
        json={"key": identity_kind, "value": "authorized"},
        headers=headers,
    )

    assert response.status_code == 204


def test_static_token_composes_with_explicit_oidc_bearer_without_origin(
    monkeypatch, tmp_path,
):
    """Either valid explicit credential works in a mixed static/OIDC deploy."""
    from maverick import world_model
    from maverick_dashboard import auth as auth_mod

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-operator-token")
    monkeypatch.setattr(auth_mod, "oidc_enabled", lambda: True)
    monkeypatch.setattr(
        auth_mod,
        "verify_oidc_token",
        lambda _token: VerifiedPrincipal(
            sub="api-client",
            issuer="https://issuer.example",
            audience="lightwork",
            claims={"iat": 1},
        ),
    )
    monkeypatch.setattr(auth_mod, "_enforce_scim_active", lambda _principal: None)
    monkeypatch.setattr(auth_mod, "_pin_tenant_from_principal", lambda *_args: None)
    monkeypatch.setattr(auth_mod, "role_for_principal", lambda _principal: "operator")

    response = _client().post(
        "/api/v1/facts",
        json={"key": "mixed", "value": "authorized"},
        headers={"Authorization": "Bearer valid-oidc-token"},
    )

    assert response.status_code == 204


def test_invalid_explicit_bearer_cannot_fall_back_in_mixed_auth(
    monkeypatch, tmp_path,
):
    """A bad explicit credential overrides, rather than borrowing, a cookie."""
    from maverick import world_model
    from maverick_dashboard import auth as auth_mod

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-operator-token")
    monkeypatch.setattr(auth_mod, "oidc_enabled", lambda: True)
    monkeypatch.setattr(
        auth_mod,
        "_session_principal",
        lambda _request: VerifiedPrincipal(
            sub="ambient-cookie-user",
            issuer="browser-session",
            audience="lightwork",
            claims={"via": "session", "iat": 1},
        ),
    )

    def _reject(_token):
        raise OIDCError("invalid token")

    monkeypatch.setattr(auth_mod, "verify_oidc_token", _reject)

    response = _client().post(
        "/api/v1/facts",
        json={"key": "mixed", "value": "rejected"},
        headers={"Authorization": "Bearer invalid-explicit-token"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid OIDC token"


# ---------- no-token mode refuses proxied requests (launch review) ----------

def test_no_token_proxied_request_requires_token(monkeypatch, tmp_path):
    """A reverse proxy on the same host connects over loopback, so trusting the
    loopback peer in no-token mode would serve the control surface
    unauthenticated behind a public proxy. Any forwarding header => require a
    token (fail closed)."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.get("/", headers={"X-Forwarded-For": "203.0.113.7"})
    assert resp.status_code == 401
    assert "MAVERICK_DASHBOARD_TOKEN" in resp.json()["detail"]


def test_no_token_proxied_via_forwarded_header_requires_token(monkeypatch, tmp_path):
    """The RFC 7239 ``Forwarded`` header is honored too, not just X-Forwarded-*."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.get("/", headers={"Forwarded": "for=203.0.113.7"})
    assert resp.status_code == 401


def test_no_token_direct_loopback_still_served(monkeypatch, tmp_path):
    """Direct local use (no proxy headers) is unaffected by the proxy guard."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.get("/")
    assert resp.status_code == 200


# ---------- baseline security headers ----------

def test_security_headers_present_on_every_response(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.get("/")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Referrer-Policy"] == "same-origin"
    assert resp.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert "microphone=(self)" in resp.headers["Permissions-Policy"]
    assert "camera=()" in resp.headers["Permissions-Policy"]
    # Authenticated HTML must not be left in a shared/back-forward cache.
    assert resp.headers["Cache-Control"] == "no-store"


def test_static_assets_keep_explicit_caching(monkeypatch, tmp_path):
    # setdefault("Cache-Control", "no-store") must not clobber the public
    # caching the static-asset routes set for themselves. An unversioned
    # controller URL is cacheable but revalidated against its content ETag.
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    resp = _client().get("/static/lightwork.css")
    assert resp.status_code == 200
    assert resp.headers["Cache-Control"] == "public, no-cache"
    assert resp.headers["ETag"]
    assert "no-store" not in resp.headers["Cache-Control"]


def test_hsts_only_on_https(monkeypatch, tmp_path):
    # Plain-HTTP (loopback dev) must not get HSTS — it would pin http hosts to
    # https and break local use. The forwarded-proto header opts in.
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    assert "Strict-Transport-Security" not in client.get("/").headers
    resp = client.get("/", headers={"X-Forwarded-Proto": "https"})
    assert "max-age=" in resp.headers["Strict-Transport-Security"]


# ---------- skill install gate ----------

def test_skill_install_blocked_by_default(monkeypatch, tmp_path):
    """POST /api/v1/skills was one-shot RCE for anyone past auth. Now opt-in."""
    monkeypatch.delenv("MAVERICK_ALLOW_SKILL_INSTALL", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.post(
        "/api/v1/skills",
        json={"source": "gh:attacker/skill"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert resp.status_code == 403
    assert "MAVERICK_ALLOW_SKILL_INSTALL" in resp.json()["detail"]


def test_skill_install_enabled_by_env(monkeypatch, tmp_path):
    """With the opt-in flag, the endpoint reaches install_skill (and fails on bad URL)."""
    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.post(
        "/api/v1/skills",
        json={"source": "gh:not/real/path/that/will/fail"},
        headers={"Origin": "http://127.0.0.1"},
    )
    # 400 = install_skill raised ValueError (bad URL); we're past the gate.
    assert resp.status_code in (400, 404, 500)
    assert resp.status_code != 403
