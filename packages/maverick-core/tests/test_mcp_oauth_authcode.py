"""The authorization-code grant is not offered for remote MCP servers.

Nothing in Lightwork could complete the sign-in (no step opened the
authorization page or received the code, and tokens were memory-only), so a
server configured with it only ever failed to start. The option is refused
with the choices that work. The PKCE helper stays: connection sign-in uses it.
"""
from __future__ import annotations

import base64
import hashlib

import pytest
from maverick.mcp_client import MCPServerSpec, StreamableHttpMCPClient
from maverick.mcp_oauth import OAuthConfig, generate_pkce

_AUTHCODE = {
    "token_url": "https://idp.example/token",
    "authorize_url": "https://idp.example/authorize",
    "client_id": "client-123",
    "redirect_uri": "https://app.example/callback",
    "grant_type": "authorization_code",
    "scope": "mcp.read mcp.write",
}


def test_authorization_code_grant_is_refused_with_the_choices_that_work():
    with pytest.raises(ValueError) as refused:
        OAuthConfig.from_dict(_AUTHCODE)
    message = str(refused.value)
    assert "authorization_code" in message
    assert "client_credentials" in message and "auth_token" in message


def test_a_server_configured_with_it_reports_that_reason_and_has_no_sign_in_step():
    client = StreamableHttpMCPClient(MCPServerSpec(name="s", url="https://h/mcp", oauth=dict(_AUTHCODE)))
    with pytest.raises(ValueError, match="client_credentials"):
        client._bearer()
    assert not hasattr(client, "oauth_authorization_start")
    assert not hasattr(client, "oauth_authorization_complete")


def test_pkce_challenge_is_s256_of_verifier():
    verifier, challenge = generate_pkce()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode()
    assert challenge == expected
    assert "=" not in verifier and "=" not in challenge  # url-safe, unpadded
    # Fresh each call.
    assert generate_pkce()[0] != verifier
