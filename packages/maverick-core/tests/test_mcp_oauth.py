"""OAuth 2.1 client-credentials for remote MCP servers."""
from __future__ import annotations

import pytest
from maverick import mcp_oauth
from maverick.mcp_client import MCPServerSpec, StreamableHttpMCPClient
from maverick.mcp_oauth import OAuthConfig, OAuthTokenProvider

# ---- config validation ------------------------------------------------------

def test_config_valid():
    c = OAuthConfig.from_dict(
        {"token_url": "https://idp/token", "client_id": "c", "scope": "a b"})
    assert c.client_id == "c" and c.scope == "a b" and c.grant_type == "client_credentials"


@pytest.mark.parametrize("bad", [
    {"client_id": "c"},                                          # no token_url
    {"token_url": "https://idp/token"},                          # no client_id
    {"token_url": "http://idp/token", "client_id": "c"},         # not https
    {"token_url": "https://idp/token", "client_id": "c",
     "grant_type": "authorization_code"},                        # unsupported grant
])
def test_config_rejects(bad):
    with pytest.raises(ValueError):
        OAuthConfig.from_dict(bad)


# ---- token provider: fetch / cache / refresh / error ------------------------

def _counting_fetch(ttl=3600):
    state = {"n": 0}
    def fetch(cfg):
        state["n"] += 1
        return {"access_token": f"tok{state['n']}", "expires_in": ttl}
    fetch.calls = state
    return fetch


def test_token_fetched_then_cached():
    fetch = _counting_fetch(ttl=3600)
    p = OAuthTokenProvider(OAuthConfig("https://i/t", "c"), fetch=fetch)
    assert p.token(now=0) == "tok1"
    assert p.token(now=10) == "tok1"      # within validity -> cached
    assert fetch.calls["n"] == 1          # only one network call


def test_token_refreshed_past_skew_window():
    fetch = _counting_fetch(ttl=100)      # expires_at = now+100, skew 60s
    p = OAuthTokenProvider(OAuthConfig("https://i/t", "c"), fetch=fetch)
    assert p.token(now=0) == "tok1"
    assert p.token(now=50) == "tok2"      # 50 >= 100-60 -> refresh
    assert fetch.calls["n"] == 2


def test_missing_access_token_raises():
    p = OAuthTokenProvider(OAuthConfig("https://i/t", "c"), fetch=lambda cfg: {})
    with pytest.raises(ValueError, match="access_token"):
        p.token(now=0)


# ---- MCPServerSpec parsing + client _bearer wiring --------------------------

def test_from_config_roundtrips_oauth():
    spec = MCPServerSpec.from_config("s", {
        "url": "https://h/mcp",
        "oauth": {"token_url": "https://i/t", "client_id": "c"}})
    assert spec.oauth == {"token_url": "https://i/t", "client_id": "c"}
    assert spec.to_dict()["oauth"]["client_id"] == "c"


def test_oauth_rejects_plaintext_mcp_url():
    with pytest.raises(ValueError, match="https:// when oauth"):
        MCPServerSpec.from_config("s", {
            "url": "http://h/mcp",
            "oauth": {"token_url": "https://i/t", "client_id": "c"},
        })


def test_bearer_uses_oauth(monkeypatch):
    monkeypatch.setattr(mcp_oauth, "_default_fetch",
                        lambda cfg: {"access_token": "tok-oauth", "expires_in": 3600})
    spec = MCPServerSpec(name="s", url="https://h/mcp",
                         oauth={"token_url": "https://i/t", "client_id": "c"})
    assert StreamableHttpMCPClient(spec)._bearer() == "tok-oauth"


def test_bearer_static_fallback():
    spec = MCPServerSpec(name="s", url="https://h/mcp", auth_token="static-tok")
    assert StreamableHttpMCPClient(spec)._bearer() == "static-tok"


def test_bearer_none_when_unset():
    spec = MCPServerSpec(name="s", url="https://h/mcp")
    assert StreamableHttpMCPClient(spec)._bearer() is None


def test_request_headers_carry_the_current_oauth_token(monkeypatch):
    tokens = iter(["tok-1", "tok-2"])
    monkeypatch.setattr(mcp_oauth, "_default_fetch",
                        lambda cfg: {"access_token": next(tokens), "expires_in": 0})
    spec = MCPServerSpec(name="s", url="https://h/mcp",
                         oauth={"token_url": "https://i/t", "client_id": "c"})
    client = StreamableHttpMCPClient(spec)
    import asyncio
    asyncio.run(client._refresh_bearer())
    assert client._headers()["Authorization"] == "Bearer tok-1"
    asyncio.run(client._refresh_bearer())  # expired: refreshed off the loop
    assert client._headers()["Authorization"] == "Bearer tok-2"


def test_fresh_oauth_token_is_reused_without_a_fetch(monkeypatch):
    calls = []
    monkeypatch.setattr(mcp_oauth, "_default_fetch", lambda cfg: calls.append(1) or
                        {"access_token": "tok", "expires_in": 3600})
    spec = MCPServerSpec(name="s", url="https://h/mcp",
                         oauth={"token_url": "https://i/t", "client_id": "c"})
    client = StreamableHttpMCPClient(spec)
    import asyncio
    for _ in range(3):
        asyncio.run(client._refresh_bearer())
    assert calls == [1]
