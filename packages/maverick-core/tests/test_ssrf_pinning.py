"""SSRF-safe fetch: resolve-once + connection pinning (DNS-rebind defense)."""
from __future__ import annotations

import asyncio
import socket

import pytest
from maverick.tools import _ssrf


def _fake_getaddrinfo(*ips):
    def _inner(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]
    return _inner


def test_resolve_pinned_ip_returns_public(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    assert _ssrf.resolve_pinned_ip("example.com") == "93.184.216.34"


def test_resolve_pinned_ip_rejects_loopback(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.resolve_pinned_ip("evil.test")


def test_resolve_pinned_ip_rejects_metadata_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.resolve_pinned_ip("metadata.test")


def test_resolve_pinned_ip_rejects_mixed_records(monkeypatch):
    # A rebinding resolver returning one public + one private record must be
    # refused outright -- we can't trust any of the answers.
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34", "127.0.0.1"))
    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.resolve_pinned_ip("rebind.test")


def test_resolve_pinned_ip_unresolvable(monkeypatch):
    def _boom(*a, **k):
        raise socket.gaierror("nope")
    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.resolve_pinned_ip("does-not-exist.test")


def test_allow_private_override(monkeypatch):
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    # With the override the loopback IP is returned (and still pinned).
    assert _ssrf.resolve_pinned_ip("localhost") == "127.0.0.1"


def test_public_only_client_ignores_private_override(monkeypatch):
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.safe_client("https://internal.example", require_public=True)


def test_public_only_resolution_ignores_scoped_private_hosts(monkeypatch):
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    with _ssrf.allow_private_hosts({"127.0.0.1"}):
        with pytest.raises(_ssrf.BlockedHost):
            _ssrf.resolve_pinned_ip("127.0.0.1", require_public=True)


def test_scoped_private_host_is_exact_and_resets(monkeypatch):
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))

    with _ssrf.allow_private_hosts({"127.0.0.1"}):
        assert _ssrf.resolve_pinned_ip("127.0.0.1") == "127.0.0.1"
        with pytest.raises(_ssrf.BlockedHost):
            _ssrf.resolve_pinned_ip("localhost")

    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.resolve_pinned_ip("127.0.0.1")


def test_scoped_private_literal_rejects_mismatched_resolver_answer(monkeypatch):
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.2"))

    with _ssrf.allow_private_hosts({"127.0.0.1"}):
        with pytest.raises(_ssrf.BlockedHost, match="exact loopback literal"):
            _ssrf.resolve_pinned_ip("127.0.0.1")


def test_scoped_private_host_propagates_to_worker_but_not_concurrent_task(monkeypatch):
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))

    async def _run():
        entered = asyncio.Event()

        async def admitted():
            with _ssrf.allow_private_hosts({"127.0.0.1"}):
                entered.set()
                await asyncio.sleep(0)
                return await asyncio.to_thread(_ssrf.resolve_pinned_ip, "127.0.0.1")

        async def denied():
            await entered.wait()
            with pytest.raises(_ssrf.BlockedHost):
                await asyncio.to_thread(_ssrf.resolve_pinned_ip, "127.0.0.1")

        allowed, _ = await asyncio.gather(admitted(), denied())
        return allowed

    assert asyncio.run(_run()) == "127.0.0.1"


@pytest.mark.parametrize("host", ["localhost", "10.0.0.1", "169.254.169.254"])
def test_scoped_private_host_rejects_non_loopback_literals(host):
    with pytest.raises(ValueError, match="loopback IP literals"):
        with _ssrf.allow_private_hosts({host}):
            pass


def test_safe_client_rejects_bad_scheme():
    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.safe_client("file:///etc/passwd")


def test_pinned_transport_rewrites_to_ip_and_preserves_host():
    """The transport must connect to the validated IP while keeping the Host
    header + TLS SNI bound to the original hostname."""
    import httpx

    captured = {}

    class _Inner:
        def handle_request(self, request):
            captured["host"] = request.url.host
            captured["sni"] = request.extensions.get("sni_hostname")
            captured["host_header"] = request.headers.get("Host")
            return httpx.Response(200, text="ok")

    t = _ssrf._PinnedTransport("example.com", "example.com", "93.184.216.34", _Inner())
    req = httpx.Request("GET", "https://example.com/path")
    resp = t.handle_request(req)

    assert resp.status_code == 200
    assert captured["host"] == "93.184.216.34"          # connects to the IP
    assert captured["sni"] == "example.com"             # TLS SNI = real host
    assert captured["host_header"] == "example.com"     # Host header = real host


def test_safe_client_builds_pinned_client(monkeypatch):
    import httpx

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    client = _ssrf.safe_client("https://example.com/x", timeout=5.0)
    assert isinstance(client, httpx.Client)
    assert isinstance(client._transport, _ssrf._PinnedTransport)
    client.close()


def test_safe_get_strips_follow_redirects(monkeypatch):
    # A caller passing follow_redirects=True must NOT be able to re-enable
    # redirect following on the pinned client: a 3xx would escape to an
    # unvalidated/unpinned host, which is the exact SSRF safe_get prevents.
    seen: dict = {}

    class _FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, **kwargs):
            seen["kwargs"] = kwargs
            return "resp"

    monkeypatch.setattr(_ssrf, "safe_client", lambda url, **kw: _FakeClient())
    out = _ssrf.safe_get("https://example.com/x", follow_redirects=True, params={"a": 1})
    assert out == "resp"
    assert "follow_redirects" not in seen["kwargs"]
    # Genuine request kwargs are still forwarded untouched.
    assert seen["kwargs"].get("params") == {"a": 1}


@pytest.mark.parametrize("ip", ["100.100.100.200", "100.64.0.1", "100.127.255.254"])
def test_resolve_pinned_ip_rejects_shared_address_space(monkeypatch, ip):
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(ip))
    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.resolve_pinned_ip("cgnat.test")


def test_resolve_pinned_ip_keeps_the_neighbours_of_shared_space_public(monkeypatch):
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    for ip in ("100.63.255.255", "100.128.0.1"):
        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(ip))
        assert _ssrf.resolve_pinned_ip("public.test") == ip


@pytest.mark.parametrize("ip", ["169.254.169.254", "fe80::1", "100.100.100.200", "224.0.0.1", "0.0.0.0"])
def test_private_override_never_opens_metadata_or_link_local(monkeypatch, ip):
    """'Let agents read addresses inside your network' means RFC1918/loopback,
    not the cloud metadata service: link-local, the Alibaba metadata literal,
    multicast, reserved and unspecified stay blocked under the override."""
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(ip))
    assert _ssrf.address_is_always_blocked(__import__("ipaddress").ip_address(ip))
    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.resolve_pinned_ip("metadata.internal")


def test_private_override_still_admits_rfc1918(monkeypatch):
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("10.0.0.5"))
    assert _ssrf.resolve_pinned_ip("intranet.example") == "10.0.0.5"
