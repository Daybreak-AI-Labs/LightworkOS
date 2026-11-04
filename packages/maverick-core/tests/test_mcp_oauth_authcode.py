"""OAuth 2.1 authorization-code grant + PKCE for remote MCP servers.

The user-redirect flow's protocol logic is pure and tested offline with an
injected token endpoint; only the live browser redirect + real-IdP validation
need an authorization server.
"""
from __future__ import annotations

import base64
import hashlib
import urllib.parse

import pytest
from maverick.mcp_client import MCPServerSpec, StreamableHttpMCPClient
from maverick.mcp_oauth import (
    AuthorizationCodeProvider,
    OAuthConfig,
    OAuthTokenProvider,
    build_authorization_url,
    generate_pkce,
)


def _cfg(**over):
    d = {
        "token_url": "https://idp.example/token",
        "authorize_url": "https://idp.example/authorize",
        "client_id": "client-123",
        "redirect_uri": "https://app.example/callback",
        "grant_type": "authorization_code",
        "scope": "mcp.read mcp.write",
    }
    d.update(over)
    return OAuthConfig.from_dict(d)


# ---- config -----------------------------------------------------------------

def test_config_accepts_authorization_code():
    c = _cfg()
    assert c.grant_type == "authorization_code"
    assert c.authorize_url == "https://idp.example/authorize"
    assert c.redirect_uri == "https://app.example/callback"


@pytest.mark.parametrize("over", [
    {"authorize_url": ""},                              # missing authorize_url
    {"redirect_uri": ""},                               # missing redirect_uri
    {"authorize_url": "http://idp.example/authorize"},  # not https
])
def test_config_rejects_bad_authcode(over):
    with pytest.raises(ValueError):
        _cfg(**over)


# ---- PKCE -------------------------------------------------------------------

def test_pkce_challenge_is_s256_of_verifier():
    verifier, challenge = generate_pkce()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode()
    assert challenge == expected
    assert "=" not in verifier and "=" not in challenge  # url-safe, unpadded
    # Fresh each call.
    assert generate_pkce()[0] != verifier


# ---- authorization URL ------------------------------------------------------

def test_build_authorization_url_has_required_params():
    url = build_authorization_url(_cfg(), code_challenge="CH", state="ST")
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert q["response_type"] == "code"
    assert q["client_id"] == "client-123"
    assert q["redirect_uri"] == "https://app.example/callback"
    assert q["code_challenge"] == "CH"
    assert q["code_challenge_method"] == "S256"
    assert q["state"] == "ST"
    assert q["scope"] == "mcp.read mcp.write"


# ---- provider: start / complete / refresh -----------------------------------

class _FakePost:
    """Records token-endpoint calls and returns scripted responses."""

    def __init__(self, *responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, token_url, data):
        self.calls.append((token_url, data))
        return self._responses.pop(0)


def test_start_returns_url_state_verifier():
    p = AuthorizationCodeProvider(_cfg())
    url, state, verifier = p.start()
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert q["state"] == state
    # The challenge in the URL is the S256 of the returned verifier.
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert q["code_challenge"] == expected


def test_complete_exchanges_code_and_returns_token():
    post = _FakePost({"access_token": "AT1", "refresh_token": "RT1", "expires_in": 3600})
    p = AuthorizationCodeProvider(_cfg(), post=post)
    tok = p.complete("auth-code-xyz", "verifier-abc", now=1000.0)
    assert tok == "AT1"
    _url, data = post.calls[0]
    assert data["grant_type"] == "authorization_code"
    assert data["code"] == "auth-code-xyz"
    assert data["code_verifier"] == "verifier-abc"
    assert data["redirect_uri"] == "https://app.example/callback"
    # Cached: a token() read before expiry does not re-hit the endpoint.
    assert p.token(now=1100.0) == "AT1"
    assert len(post.calls) == 1


def test_token_refreshes_via_refresh_grant_after_expiry():
    post = _FakePost(
        {"access_token": "AT1", "refresh_token": "RT1", "expires_in": 3600},
        {"access_token": "AT2", "expires_in": 3600},  # refresh omits refresh_token
        {"access_token": "AT3", "expires_in": 3600},  # second refresh
    )
    p = AuthorizationCodeProvider(_cfg(), post=post)
    p.complete("code", "verifier", now=0.0)
    # Past expiry (3600 - skew): refresh.
    assert p.token(now=4000.0) == "AT2"
    _url, refresh_data = post.calls[1]
    assert refresh_data["grant_type"] == "refresh_token"
    assert refresh_data["refresh_token"] == "RT1"
    # The omitted refresh_token is preserved: the next refresh reuses RT1.
    assert p.token(now=8000.0) == "AT3"
    assert post.calls[2][1]["refresh_token"] == "RT1"


def test_token_before_completion_raises():
    p = AuthorizationCodeProvider(_cfg(), post=_FakePost())
    with pytest.raises(ValueError):
        p.token(now=1.0)


def test_provider_requires_authcode_grant():
    cc = OAuthConfig.from_dict({"token_url": "https://idp/token", "client_id": "c"})
    with pytest.raises(ValueError):
        AuthorizationCodeProvider(cc)


def test_client_authcode_flow_uses_authorization_code_provider(monkeypatch):
    calls = []

    def fake_post(token_url, data):
        calls.append((token_url, data))
        return {"access_token": "AT1", "refresh_token": "RT1", "expires_in": 9999999999}

    monkeypatch.setattr("maverick.mcp_oauth._default_token_post", fake_post)
    spec = MCPServerSpec(
        name="s",
        url="https://h/mcp",
        oauth={
            "token_url": "https://idp.example/token",
            "authorize_url": "https://idp.example/authorize",
            "client_id": "client-123",
            "redirect_uri": "https://app.example/callback",
            "grant_type": "authorization_code",
            "scope": "mcp.read",
        },
    )
    client = StreamableHttpMCPClient(spec)

    url, _state, verifier = client.oauth_authorization_start()
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert q["response_type"] == "code"
    assert q["code_challenge_method"] == "S256"

    assert client.oauth_authorization_complete("auth-code", verifier, now=100.0) == "AT1"
    assert client._bearer() == "AT1"
    assert isinstance(client._oauth_provider, AuthorizationCodeProvider)
    assert calls == [(
        "https://idp.example/token",
        {
            "grant_type": "authorization_code",
            "code": "auth-code",
            "redirect_uri": "https://app.example/callback",
            "client_id": "client-123",
            "code_verifier": verifier,
        },
    )]


def test_client_authcode_bearer_requires_completion():
    spec = MCPServerSpec(
        name="s",
        url="https://h/mcp",
        oauth={
            "token_url": "https://idp.example/token",
            "authorize_url": "https://idp.example/authorize",
            "client_id": "client-123",
            "redirect_uri": "https://app.example/callback",
            "grant_type": "authorization_code",
        },
    )
    client = StreamableHttpMCPClient(spec)
    with pytest.raises(ValueError, match="complete"):
        client._bearer()
    assert isinstance(client._oauth_provider, AuthorizationCodeProvider)


def test_client_credentials_provider_rejects_authcode_config():
    with pytest.raises(ValueError, match="client_credentials"):
        OAuthTokenProvider(_cfg())
