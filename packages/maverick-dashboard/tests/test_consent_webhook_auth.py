"""The signed consent webhook must work on a deployment with sign-in turned on.

A consent management platform delivers with an HMAC signature and never holds a
dashboard credential. The route authenticates the delivery itself, so the global
dashboard-identity dependency and page-visibility policy must leave it alone.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

_SECRET = "whsec-0123456789abcdef"  # pragma: allowlist secret
_CONFIG = (
    "[consent_registry]\nenable = true\nwebhook_enable = true\n"
    'subject_salt = "dashboard-test-salt-0123456789"\n'
)


@pytest.fixture(autouse=True)
def _consent_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in (
        "MAVERICK_CONNECTIONS", "MAVERICK_ENTERPRISE",
        "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH",
        "MAVERICK_GRAPH_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_CONSENT_WEBHOOK_SECRET", _SECRET)
    (tmp_path / "config.toml").write_text(_CONFIG, encoding="utf-8")
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    api._world_cache.clear()


def _signed(body: bytes) -> dict[str, str]:
    ts = int(time.time())
    signature = hmac.new(
        _SECRET.encode(), f"{ts}.".encode() + body, hashlib.sha256,
    ).hexdigest()
    return {"X-Lightwork-Signature": signature, "X-Lightwork-Timestamp": str(ts)}


_BODY = json.dumps({
    "subject": "alice@example.com", "purpose": "marketing", "status": "granted",
}).encode()


def test_signed_delivery_is_accepted_when_dashboard_sign_in_is_on(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "dashboard-token")  # pragma: allowlist secret
    cmp_client = TestClient(app, base_url="http://127.0.0.1")  # no dashboard bearer, no Origin: the HMAC is the credential
    resp = cmp_client.post("/consent/webhook", content=_BODY, headers=_signed(_BODY))
    assert resp.status_code == 202, resp.text
    assert resp.json() == {"imported": 1, "skipped": 0}


def test_bad_signature_is_still_refused_when_dashboard_sign_in_is_on(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "dashboard-token")  # pragma: allowlist secret
    cmp_client = TestClient(app, base_url="http://127.0.0.1")
    headers = _signed(_BODY)
    headers["X-Lightwork-Signature"] = "0" * 64
    resp = cmp_client.post("/consent/webhook", content=_BODY, headers=headers)
    assert resp.status_code == 401
    # The refusal comes from the signature check, not the dashboard identity gate.
    assert "authenticated identity required" not in resp.text


def test_signed_delivery_is_accepted_with_proxy_sign_in_on(monkeypatch):
    monkeypatch.setenv("MAVERICK_PROXY_AUTH", "1")
    cmp_client = TestClient(app, base_url="http://127.0.0.1")
    resp = cmp_client.post("/consent/webhook", content=_BODY, headers=_signed(_BODY))
    assert resp.status_code == 202, resp.text


def test_self_authenticated_set_lists_the_consent_webhook():
    from maverick_dashboard import app as app_mod
    from maverick_dashboard import auth
    assert auth._self_authenticated_path("/consent/webhook")
    # The two lists of self-authenticating routes (the bearer middleware's and the
    # identity gate's) drifted apart once: a route in only one of them is refused
    # by the other. They must stay identical.
    assert set(app_mod._AUTH_EXEMPT) == set(auth._SELF_AUTH_EXEMPT_PATHS)
    # Only the exact route is exempt; the page and its other subpaths stay behind sign-in.
    assert not auth._self_authenticated_path("/consent")
    assert not auth._self_authenticated_path("/consent/webhook/extra")
    assert not auth._self_authenticated_path("/consent/publishing")
