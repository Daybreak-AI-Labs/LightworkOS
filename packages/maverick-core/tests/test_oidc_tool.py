"""Generic OIDC tool."""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from maverick.tools.oidc_tool import build_authorize_url, exchange_code, oidc_tool


def test_build_authorize_url():
    url = build_authorize_url(
        "https://idp.example.com/authorize", "client-1",
        "https://app/callback", scope="openid email", state="xyz")
    q = parse_qs(urlparse(url).query)
    assert q["response_type"] == ["code"]
    assert q["client_id"] == ["client-1"]
    assert q["redirect_uri"] == ["https://app/callback"]
    assert q["scope"] == ["openid email"]
    assert q["state"] == ["xyz"]


def test_build_authorize_url_appends_to_existing_query():
    url = build_authorize_url("https://idp/auth?foo=bar", "c", "https://app/cb")
    assert "foo=bar&" in url and "client_id=c" in url


def test_build_authorize_url_validates():
    with pytest.raises(ValueError):
        build_authorize_url("", "c", "https://app/cb")


def test_exchange_code_with_mock_fetch():
    captured = {}

    def fake_fetch(token_url, data):
        captured["url"] = token_url
        captured["data"] = data
        return {"access_token": "tok-abc", "token_type": "Bearer", "expires_in": 3600}

    resp = exchange_code("https://idp/token", "client-1", "auth-code",
                         "https://app/cb", client_secret="s3cret",  # pragma: allowlist secret
                         fetch=fake_fetch)
    assert resp["access_token"] == "tok-abc"
    assert captured["data"]["grant_type"] == "authorization_code"
    assert captured["data"]["code"] == "auth-code"
    assert captured["data"]["client_secret"] == "s3cret"  # pragma: allowlist secret


def test_exchange_code_requires_https():
    with pytest.raises(ValueError):
        exchange_code("http://idp/token", "c", "code", "https://app/cb")


def test_exchange_code_default_fetch_uses_ssrf_guard(monkeypatch):
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    with pytest.raises(ValueError, match="SSRF guard|blocked address|private"):
        exchange_code("https://127.0.0.1/token", "c", "code", "https://app/cb")


def test_exchange_code_rejects_missing_access_token():
    with pytest.raises(ValueError):
        exchange_code("https://idp/token", "c", "code", "https://app/cb",
                      fetch=lambda u, d: {"error": "invalid_grant"})


def test_tool_authorize_op():
    out = oidc_tool().fn({
        "op": "authorize", "authorize_url": "https://idp/auth",
        "client_id": "c", "redirect_uri": "https://app/cb"})
    assert out.startswith("https://idp/auth?")


def test_tool_rejects_exchange_without_sending_credentials(monkeypatch):
    import maverick.tools.oidc_tool as mod
    calls = []
    monkeypatch.setattr(mod, "_default_fetch", lambda u, d: calls.append((u, d)))
    out = oidc_tool().fn({"op": "exchange", "token_url": "https://idp/token",
                          "client_id": "c", "code": "x", "client_secret": "secret",
                          "redirect_uri": "https://app/cb"})
    assert out.startswith("ERROR:") and calls == [] and "secret" not in out
