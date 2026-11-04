"""Config-extension + discovery tests for the OIDC browser-login flow.

Covers the new ``[auth.oidc]`` fields (client_id/client_secret/redirect_uri/
session_secret + explicit endpoints), the env overrides, the ``login_enabled()``
fail-closed gate, and endpoint resolution (explicit-wins, discovery-fills,
https-only, fail-soft). No network: httpx is monkeypatched.
"""
from __future__ import annotations

import pytest
from maverick import oidc
from maverick.oidc import (
    OIDCConfig,
    OIDCError,
    load_oidc_config,
    login_enabled,
    resolve_endpoints,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    """Isolate from the host config + any MAVERICK_OIDC_* env, and clear the
    process-wide discovery cache between tests."""
    monkeypatch.setenv("HOME", str(tmp_path))  # no config.toml -> empty config
    for name in (
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_OIDC_ISSUER",
        "MAVERICK_OIDC_AUDIENCE",
        "MAVERICK_OIDC_JWKS_URI",
        "MAVERICK_OIDC_ALGORITHMS",
        "MAVERICK_OIDC_CLIENT_ID",
        "MAVERICK_OIDC_CLIENT_SECRET",
        "MAVERICK_OIDC_REDIRECT_URI",
        "MAVERICK_OIDC_SESSION_SECRET",
        "MAVERICK_OIDC_AUTHORIZATION_ENDPOINT",
        "MAVERICK_OIDC_TOKEN_ENDPOINT",
    ):
        monkeypatch.delenv(name, raising=False)
    oidc._DISCOVERY_CACHE.clear()
    yield
    oidc._DISCOVERY_CACHE.clear()


# ---- config field loading -----------------------------------------------------


def test_login_fields_default_empty():
    cfg = load_oidc_config()
    assert cfg.client_id == ""
    assert cfg.client_secret == ""
    assert cfg.redirect_uri == ""
    assert cfg.session_secret == ""
    assert cfg.authorization_endpoint == ""
    assert cfg.token_endpoint == ""


def test_login_fields_from_config(monkeypatch, tmp_path):
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "config.toml").write_text(
        "[auth.oidc]\n"
        "enabled = true\n"
        'issuer = "https://idp.example.com"\n'
        'audience = "maverick"\n'
        'client_id = "cid-123"\n'
        'client_secret = "sekret"\n'  # pragma: allowlist secret
        'redirect_uri = "https://dash.example.com/auth/callback"\n'
        'session_secret = "hmac-key"\n'  # pragma: allowlist secret
    )
    cfg = load_oidc_config()
    assert cfg.client_id == "cid-123"
    assert cfg.client_secret == "sekret"  # pragma: allowlist secret
    assert cfg.redirect_uri == "https://dash.example.com/auth/callback"
    assert cfg.session_secret == "hmac-key"  # pragma: allowlist secret


def test_env_overrides_login_fields(monkeypatch):
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_ID", "env-cid")
    monkeypatch.setenv("MAVERICK_OIDC_CLIENT_SECRET", "env-secret")
    monkeypatch.setenv("MAVERICK_OIDC_REDIRECT_URI", "https://x/auth/callback")
    monkeypatch.setenv("MAVERICK_OIDC_SESSION_SECRET", "env-hmac")
    cfg = load_oidc_config()
    assert cfg.client_id == "env-cid"
    assert cfg.client_secret == "env-secret"  # pragma: allowlist secret
    assert cfg.redirect_uri == "https://x/auth/callback"
    assert cfg.session_secret == "env-hmac"  # pragma: allowlist secret


# ---- login_enabled() fail-closed gate -----------------------------------------


def _full(**overrides) -> OIDCConfig:
    base = dict(
        enabled=True,
        issuer="https://idp.example.com",
        audience="maverick",
        client_id="cid",
        client_secret="client-secret",  # pragma: allowlist secret
        redirect_uri="https://dash.example.com/auth/callback",
        session_secret="hmac",  # pragma: allowlist secret
    )
    base.update(overrides)
    return OIDCConfig(**base)


def test_login_disabled_by_default():
    assert login_enabled() is False


def test_login_enabled_requires_oidc_enabled():
    assert login_enabled(_full(enabled=False)) is False


def test_login_enabled_requires_client_id():
    assert login_enabled(_full(client_id="")) is False


def test_login_enabled_requires_callback_secret_and_audience():
    for field in ("redirect_uri", "client_secret", "audience"):
        assert login_enabled(_full(**{field: ""})) is False


def test_login_enabled_requires_session_secret():
    assert login_enabled(_full(session_secret="")) is False


def test_login_enabled_with_issuer():
    assert login_enabled(_full()) is True


def test_login_disabled_with_explicit_endpoints_but_no_issuer():
    cfg = _full(
        issuer="",
        authorization_endpoint="https://idp.example.com/authorize",
        token_endpoint="https://idp.example.com/token",
    )
    assert login_enabled(cfg) is False


def test_login_disabled_without_issuer_or_endpoints():
    # No issuer and only one endpoint -> can't resolve, stays off.
    cfg = _full(issuer="", authorization_endpoint="https://idp.example.com/authorize")
    assert login_enabled(cfg) is False


# ---- endpoint resolution ------------------------------------------------------


def test_resolve_explicit_endpoints_skip_discovery(monkeypatch):
    """Explicit endpoints are used verbatim; discovery is never called."""
    def _boom(*a, **k):  # pragma: no cover - must not run
        raise AssertionError("discovery should not run when endpoints are explicit")

    monkeypatch.setattr(oidc, "_discover_endpoints", _boom)
    cfg = _full(
        authorization_endpoint="https://idp.example.com/authorize",
        token_endpoint="https://idp.example.com/token",
    )
    got = resolve_endpoints(cfg)
    assert got["authorization_endpoint"] == "https://idp.example.com/authorize"
    assert got["token_endpoint"] == "https://idp.example.com/token"


def test_resolve_via_discovery(monkeypatch):
    """With no explicit endpoints, discovery fills them from the issuer doc."""
    captured = {}

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "authorization_endpoint": "https://idp.example.com/auth",
                "token_endpoint": "https://idp.example.com/tok",
            }

    def _fake_get(url, **kwargs):
        captured["url"] = url
        return _Resp()

    import httpx

    monkeypatch.setattr(httpx, "get", _fake_get)
    got = resolve_endpoints(_full())
    assert got["authorization_endpoint"] == "https://idp.example.com/auth"
    assert got["token_endpoint"] == "https://idp.example.com/tok"
    assert captured["url"] == (
        "https://idp.example.com/.well-known/openid-configuration"
    )


def test_discovery_is_cached(monkeypatch):
    calls = {"n": 0}

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "authorization_endpoint": "https://idp.example.com/auth",
                "token_endpoint": "https://idp.example.com/tok",
            }

    def _fake_get(url, **kwargs):
        calls["n"] += 1
        return _Resp()

    import httpx

    monkeypatch.setattr(httpx, "get", _fake_get)
    resolve_endpoints(_full())
    resolve_endpoints(_full())
    assert calls["n"] == 1  # second call served from cache


def test_discovery_rejects_non_https_issuer():
    cfg = _full(issuer="http://idp.example.com")
    with pytest.raises(OIDCError):
        resolve_endpoints(cfg)


def test_discovery_rejects_non_https_discovered_endpoint(monkeypatch):
    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "authorization_endpoint": "http://idp.example.com/auth",  # not https
                "token_endpoint": "https://idp.example.com/tok",
            }

    import httpx

    monkeypatch.setattr(httpx, "get", lambda url, **k: _Resp())
    with pytest.raises(OIDCError):
        resolve_endpoints(_full())


def test_discovery_network_failure_is_oidcerror(monkeypatch):
    def _boom(url, **kwargs):
        raise RuntimeError("connection refused")

    import httpx

    monkeypatch.setattr(httpx, "get", _boom)
    with pytest.raises(OIDCError):
        resolve_endpoints(_full())
