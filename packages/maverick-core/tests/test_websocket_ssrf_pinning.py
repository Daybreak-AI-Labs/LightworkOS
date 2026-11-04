"""websocket_tool must pin the connection to a validated IP (no DNS rebind).

If _check_url resolved the host once to validate and websockets.connect(url)
re-resolved the same name independently, a DNS-rebinding TOCTOU would let a
short-TTL/hostile resolver pass validation with a public IP and then connect
to 169.254.169.254 / 127.0.0.1. The tool pins via _ssrf.resolve_pinned_ip and
connects to that exact IP. websockets
isn't a default dependency, so a fake module captures the connect kwargs to
assert the SSRF-critical contract.
"""
from __future__ import annotations

import asyncio

import maverick.tools.websocket_tool as wst


class _FakeWS:
    async def send(self, _m):  # pragma: no cover - not exercised here
        pass

    async def recv(self):
        return "pong"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _install_fake_websockets(captured: dict):
    def connect(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return _FakeWS()

    return connect


def test_connects_to_pinned_ip_not_hostname(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(wst, "_safe_connector", lambda: _install_fake_websockets(captured))
    # The validated/pinned IP the resolver returns.
    monkeypatch.setattr(wst, "urlparse", wst.urlparse)  # keep real urlparse
    import maverick.tools._ssrf as ssrf
    monkeypatch.setattr(ssrf, "resolve_pinned_ip", lambda host: "93.184.216.34")

    out = asyncio.run(wst._run({"url": "wss://example.com:8443/feed", "recv": True}))
    assert out == "pong"
    # SSRF-critical: the TCP target is the pinned IP, not the re-resolvable name.
    assert captured["kwargs"]["host"] == "93.184.216.34"
    assert captured["kwargs"]["port"] == 8443
    # wss keeps the real hostname for cert validation (no cert bypass).
    assert captured["kwargs"]["server_hostname"] == "example.com"


def test_rebind_to_private_ip_is_refused(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(wst, "_safe_connector", lambda: _install_fake_websockets(captured))
    import maverick.tools._ssrf as ssrf

    def _blocked(host):
        raise ssrf.BlockedHost(f"{host!r} resolves to non-public address 169.254.169.254")

    monkeypatch.setattr(ssrf, "resolve_pinned_ip", _blocked)
    out = asyncio.run(wst._run({"url": "wss://rebind.attacker.test/x"}))
    assert out.startswith("ERROR: refusing to connect")
    assert "kwargs" not in captured  # never reached connect


def test_default_port_for_ws(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(wst, "_safe_connector", lambda: _install_fake_websockets(captured))
    import maverick.tools._ssrf as ssrf
    monkeypatch.setattr(ssrf, "resolve_pinned_ip", lambda host: "203.0.113.7")
    # This test exercises default-port selection, not the SSRF guard. The host
    # is a non-resolvable placeholder; the pre-flight host check now fails
    # closed on a DNS failure, so allow private to short-circuit it (the pinned
    # resolver is already stubbed above) and let _run reach connect().
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    asyncio.run(wst._run({"url": "ws://plain.example/x", "recv": True}))
    assert captured["kwargs"]["port"] == 80
    assert "server_hostname" not in captured["kwargs"]  # ws (no TLS)
