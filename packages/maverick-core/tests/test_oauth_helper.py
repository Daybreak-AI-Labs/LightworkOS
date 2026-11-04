"""Generic OAuth helper: PKCE authorize URL, code exchange, refresh — with a
fake transport; tokens are never echoed."""
from __future__ import annotations

from maverick.tools.oauth_helper import oauth_helper


def _t():
    return oauth_helper()


def test_authorize_url_includes_pkce():
    out = _t().fn({"op": "authorize_url", "authorize_url": "https://x/auth",
                   "client_id": "cid", "redirect_uri": "https://app/cb",
                   "scope": "repo read:user", "state": "s1"})
    assert out.startswith("open: https://x/auth?")
    assert "response_type=code" in out and "code_challenge_method=S256" in out
    assert "scope=repo+read%3Auser" in out and "state=s1" in out
    assert "pkce_verifier: " in out


def test_agent_cannot_send_credentials_or_replace_vault(monkeypatch, tmp_path):
    import maverick.tools.oauth_helper as mod
    from maverick import oauth_vault

    calls = []
    monkeypatch.setattr(mod, "_post_form", lambda *a, **kw: calls.append((a, kw)))
    monkeypatch.setattr(oauth_vault, "get_vault", lambda: (_ for _ in ()).throw(
        AssertionError("agent call must not access vault")))
    out_file = tmp_path / "tokens.json"
    monkeypatch.setenv("MAVERICK_OAUTH_OUT", str(out_file))
    monkeypatch.setenv("MAVERICK_OAUTH_VAULT", "1")
    for op in ("exchange", "refresh"):
        out = _t().fn({"op": op, "provider": "google", "token_url": "https://attacker.example/token",
                       "client_id": "client", "client_secret": "secret", "refresh_token": "token",
                       "code": "code", "redirect_uri": "https://example.org/callback"})
        assert out.startswith("ERROR:")
        assert "secret" not in out
    assert calls == []
    assert not out_file.exists()


def test_unknown_operation_is_rejected():
    assert _t().fn({"op": "bogus"}).startswith("ERROR")


def test_token_post_requires_https_before_network():
    import maverick.tools.oauth_helper as mod
    import pytest

    with pytest.raises(ValueError, match="token_url must be https"):
        mod._post_form("http://127.0.0.1/token", {"grant_type": "refresh_token"})


def test_token_post_rejects_private_resolved_host(monkeypatch):
    import socket

    import maverick.tools.oauth_helper as mod
    import pytest
    from maverick.tools._ssrf import BlockedHost

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    with pytest.raises(BlockedHost):
        mod._post_form("https://localhost/token", {"grant_type": "refresh_token"})


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "oauth_helper" in names
