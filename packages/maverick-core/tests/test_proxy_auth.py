"""Reverse-proxy SSO: honor a forwarded identity header only from a trusted peer.

The security-critical bit is :func:`proxy_trusts` -- a forwarded header is
spoofable by a direct client, so it must be accepted only when the request's
network peer is the trusted upstream.
"""
from __future__ import annotations

import logging

import pytest
from maverick.proxy_auth import (
    principal_from_proxy,
    proxy_auth_enabled,
    proxy_header_name,
    proxy_trusts,
    uvicorn_launch_kwargs,
    warn_if_untrusted_proxy_config,
)


def _cfg(monkeypatch, cfg):
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: cfg)


def test_disabled_by_default(monkeypatch):
    _cfg(monkeypatch, {})
    monkeypatch.delenv("MAVERICK_PROXY_AUTH", raising=False)
    assert proxy_auth_enabled() is False


def test_enabled_via_config(monkeypatch):
    monkeypatch.delenv("MAVERICK_PROXY_AUTH", raising=False)
    _cfg(monkeypatch, {"auth": {"proxy": {"enabled": True}}})
    assert proxy_auth_enabled() is True


def test_enabled_via_env(monkeypatch):
    _cfg(monkeypatch, {})
    monkeypatch.setenv("MAVERICK_PROXY_AUTH", "1")
    assert proxy_auth_enabled() is True


def test_header_default_and_override(monkeypatch):
    monkeypatch.delenv("MAVERICK_PROXY_AUTH_HEADER", raising=False)
    _cfg(monkeypatch, {})
    assert proxy_header_name() == "X-Forwarded-User"
    _cfg(monkeypatch, {"auth": {"proxy": {"header": "X-Auth-Request-Email"}}})
    assert proxy_header_name() == "X-Auth-Request-Email"


def test_unpinned_peer_is_untrusted_by_default(monkeypatch):
    # #11: with no trusted_proxies pin and trust_loopback unset, NO peer is
    # trusted -- a co-located loopback process must not be able to spoof
    # X-Forwarded-User just by living on 127.0.0.1. Explicit opt-in required.
    _cfg(monkeypatch, {})
    assert proxy_trusts("127.0.0.1") is False
    assert proxy_trusts("::1") is False
    assert proxy_trusts("10.0.0.9") is False   # a remote peer is not trusted
    assert proxy_trusts("") is False           # unknown peer fails closed
    assert proxy_trusts(None) is False


def test_trusts_loopback_only_with_explicit_opt_in(monkeypatch):
    # trust_loopback = true is the explicit opt-in for the same-host proxy.
    _cfg(monkeypatch, {"auth": {"proxy": {"trust_loopback": True}}})
    assert proxy_trusts("127.0.0.1") is True
    assert proxy_trusts("::1") is True
    assert proxy_trusts("10.0.0.9") is False   # opt-in is loopback-only
    # An explicit false is honored the same way an unset value is (no trust).
    _cfg(monkeypatch, {"auth": {"proxy": {"trust_loopback": False}}})
    assert proxy_trusts("127.0.0.1") is False


def test_trusts_configured_proxies_replace_default(monkeypatch):
    _cfg(monkeypatch, {"auth": {"proxy": {"trusted_proxies": ["10.0.0.5"]}}})
    assert proxy_trusts("10.0.0.5") is True
    # An explicit list is exact: it replaces the loopback default so a stray
    # local process can't assert identity unless you listed loopback too.
    assert proxy_trusts("127.0.0.1") is False


def test_trusts_configured_proxies_by_cidr(monkeypatch):
    # A proxy pool / load balancer can't be pinned by one exact IP.
    _cfg(monkeypatch, {"auth": {"proxy": {"trusted_proxies": ["10.0.0.0/24"]}}})
    assert proxy_trusts("10.0.0.5") is True
    assert proxy_trusts("10.0.0.254") is True
    assert proxy_trusts("10.0.1.1") is False   # outside the range
    assert proxy_trusts("127.0.0.1") is False


def test_trusts_configured_proxies_normalizes_ipv4_mapped_ipv6(monkeypatch):
    # A dual-stack listener reports an IPv4 peer as ::ffff:10.0.0.5, which is
    # not string-equal to a plain "10.0.0.5" pin.
    _cfg(monkeypatch, {"auth": {"proxy": {"trusted_proxies": ["10.0.0.5"]}}})
    assert proxy_trusts("::ffff:10.0.0.5") is True
    assert proxy_trusts("::ffff:10.0.0.6") is False


def test_trusts_configured_proxies_ignores_unparsable_entry(monkeypatch, caplog):
    _cfg(monkeypatch, {"auth": {"proxy": {
        "trusted_proxies": ["not-an-ip", "10.0.0.5"],
    }}})
    with caplog.at_level(logging.WARNING, logger="maverick.proxy_auth"):
        assert proxy_trusts("10.0.0.5") is True
        assert proxy_trusts("not-an-ip") is False
    assert any("not-an-ip" in r.message for r in caplog.records)


def test_uvicorn_launch_kwargs_disables_proxy_headers_when_enabled(monkeypatch):
    # Uvicorn's default ProxyHeadersMiddleware rewrites
    # request.client.host from X-Forwarded-For for any peer it trusts
    # (127.0.0.1 by default), in place, with the original peer unrecoverable.
    # That both lets a co-located loopback peer spoof its way past a pinned
    # non-loopback trusted_proxies pin, and breaks a pinned-loopback-proxy
    # setup outright. proxy_trusts() needs the raw, unrewritten peer.
    monkeypatch.delenv("MAVERICK_PROXY_AUTH", raising=False)
    _cfg(monkeypatch, {"auth": {"proxy": {"enabled": True, "trusted_proxies": ["10.0.0.5"]}}})
    assert uvicorn_launch_kwargs() == {"proxy_headers": False}


def test_uvicorn_launch_kwargs_preserves_peer_when_proxy_auth_disabled(monkeypatch):
    monkeypatch.delenv("MAVERICK_PROXY_AUTH", raising=False)
    _cfg(monkeypatch, {})
    assert uvicorn_launch_kwargs() == {"proxy_headers": False}


async def _run_asgi(app, *, client_host, headers):
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": (client_host, 12345),
        "server": ("testserver", 80),
        "scheme": "http",
        "query_string": b"",
    }
    result: dict = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.body":
            result["body"] = message.get("body", b"")

    await app(scope, receive, send)
    return result


def test_proxy_headers_middleware_can_spoof_a_pinned_proxy_by_default(monkeypatch):
    """ASGI-level proof: uvicorn's ProxyHeadersMiddleware (installed
    by default with trusted_hosts=127.0.0.1) rewrites scope["client"] in
    place from X-Forwarded-For for any loopback peer, so a co-located
    loopback process can present as the pinned proxy to proxy_trusts()."""
    import asyncio

    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    _cfg(monkeypatch, {"auth": {"proxy": {"trusted_proxies": ["10.0.0.5"]}}})

    async def inner_app(scope, receive, send):
        trusted = proxy_trusts(scope["client"][0] if scope.get("client") else None)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"trusted" if trusted else b"untrusted"})

    # uvicorn's actual default wiring: proxy_headers=True, trusted_hosts=127.0.0.1.
    vulnerable = ProxyHeadersMiddleware(inner_app, trusted_hosts="127.0.0.1")
    result = asyncio.run(_run_asgi(
        vulnerable, client_host="127.0.0.1", headers={"X-Forwarded-For": "10.0.0.5"},
    ))
    assert result["body"] == b"trusted"  # a loopback peer spoofed the pinned proxy

    # uvicorn_launch_kwargs()'s fix: proxy_headers=False means this middleware
    # is never installed, so the raw (unspoofable) peer always reaches
    # proxy_trusts() -- the same loopback peer is refused.
    result = asyncio.run(_run_asgi(
        inner_app, client_host="127.0.0.1", headers={"X-Forwarded-For": "10.0.0.5"},
    ))
    assert result["body"] == b"untrusted"


def test_warn_if_untrusted_proxy_config(monkeypatch, caplog):
    monkeypatch.delenv("MAVERICK_PROXY_AUTH", raising=False)

    # Off by default -> silent.
    _cfg(monkeypatch, {})
    with caplog.at_level(logging.WARNING, logger="maverick.proxy_auth"):
        warn_if_untrusted_proxy_config()
    assert caplog.records == []

    # Enabled but neither pinned nor trust_loopback set -> loud warning.
    _cfg(monkeypatch, {"auth": {"proxy": {"enabled": True}}})
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="maverick.proxy_auth"):
        warn_if_untrusted_proxy_config()
    assert any(r.levelno == logging.WARNING for r in caplog.records)
    assert "trusted_proxies" in caplog.text

    # Pinned -> silent (a peer is configured).
    _cfg(monkeypatch, {"auth": {"proxy": {"enabled": True, "trusted_proxies": ["10.0.0.5"]}}})
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="maverick.proxy_auth"):
        warn_if_untrusted_proxy_config()
    assert caplog.records == []

    # Explicit trust_loopback -> silent (operator opted in deliberately).
    _cfg(monkeypatch, {"auth": {"proxy": {"enabled": True, "trust_loopback": True}}})
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="maverick.proxy_auth"):
        warn_if_untrusted_proxy_config()
    assert caplog.records == []


def test_principal_from_proxy_maps_to_user():
    p = principal_from_proxy("alice@example.com")
    assert p.principal == "user:alice@example.com"
    assert p.claims.get("via") == "proxy"


@pytest.mark.parametrize("subject", [" alice", "alice ", "alice\n", "x" * 252])
def test_principal_from_proxy_rejects_invalid_subject_domain(subject):
    with pytest.raises(ValueError, match="authenticated subject"):
        principal_from_proxy(subject)


def test_principal_from_proxy_accepts_full_principal_length_boundary():
    subject = "x" * 251
    assert len(principal_from_proxy(subject).principal) == 256
