"""OIDC bearer-auth gate tests for the dashboard.

Hermetic: no real crypto/JWT/network. We monkeypatch the OIDC seam
(``maverick_dashboard.auth.oidc_enabled`` and
``maverick_dashboard.auth.verify_oidc_token``) so the tests exercise the
FastAPI dependency wiring, not PyJWT.

The route under test is ``/metrics``: it is gated (not in the OIDC exempt
set), returns a deterministic 200 without touching the DB or network, so a
status code change is attributable purely to the auth gate.
"""
from __future__ import annotations

import maverick_dashboard.auth as auth
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")

GATED_ROUTE = "/metrics"


def test_disabled_allows_request_without_auth_header(monkeypatch):
    """OIDC off (default): a gated route is reachable with no auth header.

    This is the load-bearing default-OFF guarantee -- enabling the gate must
    never change behaviour while OIDC is disabled.
    """
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    # If verify_oidc_token is ever called while disabled, fail loudly.
    def _boom(*a, **k):  # pragma: no cover - must not run
        raise AssertionError("verify_oidc_token called while OIDC disabled")
    monkeypatch.setattr(auth, "verify_oidc_token", _boom)

    resp = client.get(GATED_ROUTE)
    assert resp.status_code == 200


def test_enabled_no_token_returns_401(monkeypatch):
    """OIDC on + no Authorization header: fail closed with 401."""
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)

    resp = client.get(GATED_ROUTE)
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


def test_enabled_invalid_token_returns_401(monkeypatch):
    """OIDC on + a token the verifier rejects: 401 (opaque detail)."""
    from maverick.oidc import OIDCError

    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)

    def _reject(token, **k):
        raise OIDCError("token verification failed")

    monkeypatch.setattr(auth, "verify_oidc_token", _reject)

    resp = client.get(GATED_ROUTE, headers={"Authorization": "Bearer not-a-real-jwt"})
    assert resp.status_code == 401
    # Detail must not leak the underlying failure reason.
    assert resp.json()["detail"] == "invalid OIDC token"


def test_enabled_valid_token_allows_and_exposes_principal(monkeypatch):
    """OIDC on + a token the verifier accepts: 200, principal available.

    Monkeypatch ``verify_oidc_token`` to return a VerifiedPrincipal so the
    test needs no real crypto. Capture the token the dependency forwards to
    prove the Bearer header was parsed and threaded through.
    """
    seen: dict[str, str] = {}
    principal = VerifiedPrincipal(
        sub="abc123",
        issuer="https://issuer.example",
        audience="maverick",
        claims={"sub": "abc123", "email": "u@example.com"},
    )

    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)

    def _accept(token, **k):
        seen["token"] = token
        return principal

    monkeypatch.setattr(auth, "verify_oidc_token", _accept)

    resp = client.get(GATED_ROUTE, headers={"Authorization": "Bearer good.jwt.here"})
    assert resp.status_code == 200
    # The dependency parsed the Bearer header and forwarded the raw JWT.
    assert seen["token"] == "good.jwt.here"
    # And the verified principal maps to the expected identity convention.
    assert principal.principal == "user:abc123"


def test_enabled_health_endpoints_stay_open(monkeypatch):
    """OIDC on: liveness/health probes remain reachable without a token.

    LB/k8s probes can't present an ID token, so the gate exempts them.
    """
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    def _boom(*a, **k):  # pragma: no cover - exempt paths must not verify
        raise AssertionError("verify_oidc_token called on an exempt path")
    monkeypatch.setattr(auth, "verify_oidc_token", _boom)

    assert client.get("/livez").status_code == 200


def test_enabled_webhooks_exempt_from_oidc(monkeypatch):
    """OIDC on: HMAC-signed webhooks bypass the OIDC gate (external senders
    can't present an ID token; they're authenticated by their own signature).
    The gate must NOT reject them and must NOT call verify_oidc_token."""
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)

    def _boom(*a, **k):  # pragma: no cover - exempt paths must not verify
        raise AssertionError("verify_oidc_token called on an exempt webhook path")
    monkeypatch.setattr(auth, "verify_oidc_token", _boom)

    resp = client.post("/webhook/start", json={})
    # If the gate had run verify, _boom would surface as a 500; and the OIDC
    # gate's own 401 detail must never be what rejects a webhook.
    assert resp.status_code != 500
    assert resp.json().get("detail") != "OIDC bearer token required"
