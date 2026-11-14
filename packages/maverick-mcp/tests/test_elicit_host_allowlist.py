"""URL-mode elicitation host allowlist.

The elicitation URL is model-influenced, so a prompt injection could aim the
user at an attacker site to harvest the credential the flow protects. When
[mcp] elicit_allowed_hosts / MAVERICK_MCP_ELICIT_ALLOWED_HOSTS is set, only
those hosts (and their subdomains) are allowed.
"""
from __future__ import annotations

from maverick_mcp.server import _elicit_allowed_hosts, _elicit_host_allowed


def test_empty_allowlist_allows_any():
    assert _elicit_host_allowed("https://anything.example.com/x", frozenset()) is True


def test_exact_and_subdomain_match():
    allowed = frozenset({"accounts.google.com", "github.com"})
    assert _elicit_host_allowed("https://accounts.google.com/o/oauth2", allowed) is True
    assert _elicit_host_allowed("https://api.github.com/x", allowed) is True   # subdomain
    assert _elicit_host_allowed("https://github.com", allowed) is True


def test_non_allowed_host_rejected():
    allowed = frozenset({"github.com"})
    assert _elicit_host_allowed("https://evil.example.com/harvest", allowed) is False
    # a look-alike suffix must not pass (notgithub.com endswith 'github.com'? no,
    # the check uses '.'+a so only true subdomains match)
    assert _elicit_host_allowed("https://notgithub.com/x", allowed) is False
    assert _elicit_host_allowed("https://github.com.evil.com/x", allowed) is False


def test_allowlist_from_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_ELICIT_ALLOWED_HOSTS", "a.com, B.COM ")
    assert _elicit_allowed_hosts() == frozenset({"a.com", "b.com"})


def test_allowlist_from_config(monkeypatch):
    monkeypatch.delenv("MAVERICK_MCP_ELICIT_ALLOWED_HOSTS", raising=False)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"mcp": {"elicit_allowed_hosts": ["x.io", "y.io"]}},
    )
    assert _elicit_allowed_hosts() == frozenset({"x.io", "y.io"})


def test_allowlist_default_empty(monkeypatch):
    monkeypatch.delenv("MAVERICK_MCP_ELICIT_ALLOWED_HOSTS", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    assert _elicit_allowed_hosts() == frozenset()


def test_elicitation_rejects_backslashes_and_userinfo_even_without_allowlist():
    for allowed in (frozenset({"accounts.google.com"}), frozenset()):
        for url in ("https://evil.example\\@accounts.google.com/x",
                    "https://user@accounts.google.com/x", "https://@accounts.google.com/x"):
            assert _elicit_host_allowed(url, allowed) is False
