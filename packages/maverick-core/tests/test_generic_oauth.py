"""generic_oauth: offline OAuth2 wire-artifact builder. No network."""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from maverick.tools.generic_oauth import generic_oauth


def _run(**kw):
    return generic_oauth().fn(kw)


def test_client_credentials_body_and_headers():
    out = _run(
        op="client_credentials_request",
        token_url="https://auth.example.com/token",
        client_id="abc",
        scope="read write",
    )
    lines = out.splitlines()
    assert lines[0] == "POST https://auth.example.com/token"
    assert "Content-Type: application/x-www-form-urlencoded" in lines
    body = parse_qs(lines[-1])
    assert body["grant_type"] == ["client_credentials"]
    assert body["client_id"] == ["abc"]
    assert body["scope"] == ["read write"]


def test_client_credentials_rejects_non_https():
    out = _run(
        op="client_credentials_request",
        token_url="http://auth.example.com/token",
        client_id="abc",
    )
    assert out.startswith("ERROR") and "https" in out


def test_authorize_url_basic():
    out = _run(
        op="authorize_url",
        authorize_endpoint="https://auth.example.com/authorize",
        client_id="abc",
        redirect_uri="https://app.example.com/cb",
        scope="openid",
        state="xyz",
    )
    assert out.startswith("https://auth.example.com/authorize?")
    q = parse_qs(urlsplit(out).query)
    assert q["response_type"] == ["code"]
    assert q["client_id"] == ["abc"]
    assert q["redirect_uri"] == ["https://app.example.com/cb"]
    assert q["scope"] == ["openid"]
    assert q["state"] == ["xyz"]
    assert "code_challenge" not in q  # no pkce supplied


def test_authorize_url_pkce_challenge_deterministic():
    verifier = "test_verifier_1234567890_abcdefghijklmnop"  # pragma: allowlist secret
    expected = "EdVq-8vtKdkYHS1o-eSpM5J9rBWnHnrxmYnvXHWgS8k"  # pragma: allowlist secret
    a = _run(
        op="authorize_url",
        authorize_endpoint="https://auth.example.com/authorize",
        client_id="abc",
        redirect_uri="https://app.example.com/cb",
        pkce=verifier,
    )
    b = _run(
        op="authorize_url",
        authorize_endpoint="https://auth.example.com/authorize",
        client_id="abc",
        redirect_uri="https://app.example.com/cb",
        pkce=verifier,
    )
    assert a == b  # deterministic
    q = parse_qs(urlsplit(a).query)
    assert q["code_challenge"] == [expected]
    assert q["code_challenge_method"] == ["S256"]


def test_authorize_url_rejects_non_https():
    out = _run(
        op="authorize_url",
        authorize_endpoint="http://auth.example.com/authorize",
        client_id="abc",
        redirect_uri="https://app.example.com/cb",
    )
    assert out.startswith("ERROR") and "https" in out


def test_errors():
    t = generic_oauth()
    assert t.fn({"op": "client_credentials_request", "client_id": "x"}).startswith("ERROR")
    assert t.fn({"op": "authorize_url", "client_id": "x"}).startswith("ERROR")
    assert t.fn({"op": "nope"}).startswith("ERROR")
