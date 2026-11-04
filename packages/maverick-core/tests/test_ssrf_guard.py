"""SSRF consolidation: skill install and catalog fetch now go through the
same ``guarded_urlopen`` host check the http_fetch tool already uses, so a
user/model-supplied URL can't be pointed at a private/loopback/metadata
address. Loopback literals resolve without DNS, so these stay hermetic.
"""
from __future__ import annotations

import urllib.request

import httpx
import pytest


def test_guarded_urlopen_blocks_loopback():
    from maverick.tools.http_fetch import guarded_urlopen
    with pytest.raises(ValueError) as ei:
        guarded_urlopen("https://127.0.0.1/x", timeout=1)
    assert "SSRF" in str(ei.value) or "private/loopback" in str(ei.value)


def test_guarded_urlopen_rejects_non_https_scheme():
    from maverick.tools.http_fetch import guarded_urlopen
    with pytest.raises(ValueError) as ei:
        guarded_urlopen("http://example.com/x", timeout=1)
    assert "http" in str(ei.value).lower()
    with pytest.raises(ValueError):
        guarded_urlopen("ftp://example.com/x", timeout=1)


def test_guarded_urlopen_allow_http_still_blocks_private():
    """allow_http=True relaxes only the scheme gate, not the SSRF host gate."""
    from maverick.tools.http_fetch import guarded_urlopen
    with pytest.raises(ValueError) as ei:
        guarded_urlopen("http://127.0.0.1/x", timeout=1, allow_http=True)
    # The SSRF message, not the "insecure http" one -> scheme gate passed.
    assert "private/loopback" in str(ei.value)


def test_guarded_urlopen_allows_public_host(monkeypatch):
    from maverick.tools import http_fetch

    seen = {}

    # guarded_urlopen now fetches through a custom opener (so it can
    # revalidate every redirect hop against the SSRF guard), so patch the
    # opener's open() rather than urllib.request.urlopen.
    def _fake_open(self, url, timeout=None):
        seen["url"] = url
        return object()

    monkeypatch.setattr(http_fetch, "is_blocked_host", lambda _h: False)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", _fake_open)

    out = http_fetch.guarded_urlopen("https://example.com/data", timeout=5)
    assert out is not None
    assert seen["url"] == "https://example.com/data"


def test_guarded_urlopen_installs_an_explicit_empty_proxy_handler(monkeypatch):
    """Build_opener's default ProxyHandler reads HTTP(S)_PROXY and
    rewrites the connection target to the proxy host -- the pinned
    connect() then validates THAT address instead of the real, already-
    validated destination. A corporate proxy is nearly always on a
    private/loopback address, so this made every guarded fetch fail with
    a "blocked address" error naming the PROXY, not the target. Assert
    guarded_urlopen passes build_opener an explicit, empty ProxyHandler so
    HTTP(S)_PROXY is never consulted (matching _ssrf.safe_client, whose
    explicit httpx transport likewise never honors it). Inspecting the
    call to build_opener rather than the resulting opener's handler list:
    urllib silently omits a ProxyHandler with no configured proxies from
    that list, so its mere presence there can't be asserted directly.
    """
    from maverick.tools import http_fetch

    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1/")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1/")
    monkeypatch.setattr(http_fetch, "is_blocked_host", lambda _h: False)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open",
                        lambda self, url, timeout=None: object())

    real_build_opener = urllib.request.build_opener
    captured = {}

    def _capturing_build_opener(*handlers):
        captured["handlers"] = handlers
        return real_build_opener(*handlers)

    monkeypatch.setattr(urllib.request, "build_opener", _capturing_build_opener)
    out = http_fetch.guarded_urlopen("https://example.com/data", timeout=5)
    assert out is not None
    proxy_handlers = [h for h in captured["handlers"]
                      if isinstance(h, urllib.request.ProxyHandler)]
    assert proxy_handlers, "expected an explicit ProxyHandler passed to build_opener"
    assert all(not h.proxies for h in proxy_handlers), (
        "guarded_urlopen must not honor HTTP(S)_PROXY -- the destination is "
        "already validated by _check_url_allowed; the proxy hop is not")


def test_pinned_https_handler_uses_runtime_ssl_context(monkeypatch):
    """The handler must work across urllib versions without private attrs."""
    from maverick.tools import http_fetch

    handler = http_fetch._PinnedHTTPSHandler()
    seen = {}

    def fake_do_open(connection, request, **kwargs):
        seen.update(connection=connection, request=request, kwargs=kwargs)
        return object()

    monkeypatch.setattr(handler, "do_open", fake_do_open)
    request = object()
    assert handler.https_open(request) is not None
    assert seen == {
        "connection": http_fetch._PinnedHTTPSConnection,
        "request": request,
        "kwargs": {"context": handler._context},
    }


def test_skill_fetch_url_refuses_private_host():
    from maverick.skills import _fetch_url
    with pytest.raises(ValueError):
        _fetch_url("https://127.0.0.1/SKILL.md")


def test_catalog_index_blocked_host_degrades_to_none(tmp_path, monkeypatch):
    from maverick import catalog
    # Keep any cache lookups/writes off the real ~/.maverick dir.
    monkeypatch.setattr(catalog, "_cache_path", lambda url: tmp_path / "idx.json")
    # A loopback index URL is refused by the guard; the fetch degrades to
    # None (no entries) rather than raising.
    assert catalog._fetch_index_raw("https://127.0.0.1/catalog") is None


# ---------- DNS-rebind connection pinning ----------
# The guard resolves the host once, validates every returned address, and pins
# that exact IP for the socket so the connection layer can't re-resolve to a
# different (internal) address between check and connect.

def _gai(*ips):
    """Build a fake socket.getaddrinfo returning the given IPv4 literals."""
    import socket as _s
    return lambda host, *a, **k: [
        (_s.AF_INET, _s.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips
    ]


def test_resolve_pinned_returns_ip_for_public(monkeypatch):
    from maverick.tools import http_fetch
    monkeypatch.setattr(http_fetch.socket, "getaddrinfo", _gai("93.184.216.34"))
    assert http_fetch._resolve_pinned("example.com") == "93.184.216.34"


def test_resolve_pinned_blocks_loopback(monkeypatch):
    from maverick.tools import http_fetch
    monkeypatch.setattr(http_fetch.socket, "getaddrinfo", _gai("127.0.0.1"))
    with pytest.raises(ValueError, match="blocked address"):
        http_fetch._resolve_pinned("evil.example")


def test_resolve_pinned_blocks_if_any_resolved_addr_is_private(monkeypatch):
    """A rebind set where one record is public and another is the metadata IP
    must be refused — every address is validated, not just the first."""
    from maverick.tools import http_fetch
    monkeypatch.setattr(
        http_fetch.socket, "getaddrinfo", _gai("93.184.216.34", "169.254.169.254"),
    )
    with pytest.raises(ValueError, match="blocked address"):
        http_fetch._resolve_pinned("rebind.example")


def test_resolve_pinned_fails_closed_on_resolution_error(monkeypatch):
    import socket as _s

    from maverick.tools import http_fetch

    def _boom(*a, **k):
        raise _s.gaierror("name resolution failed")

    monkeypatch.setattr(http_fetch.socket, "getaddrinfo", _boom)
    with pytest.raises(ValueError, match="DNS resolution failed"):
        http_fetch._resolve_pinned("nope.invalid")


def test_resolve_pinned_override_returns_host_unchanged(monkeypatch):
    from maverick.tools import http_fetch
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    # No resolution happens under the override; the hostname passes through.
    assert http_fetch._resolve_pinned("127.0.0.1") == "127.0.0.1"
    assert http_fetch._resolve_pinned("internal.svc") == "internal.svc"


def test_pinned_connection_opens_socket_to_validated_ip(monkeypatch):
    """The socket is opened to the pinned IP, but self.host (Host header / SNI
    / cert verification) stays the real hostname."""
    from maverick.tools import http_fetch

    captured = {}

    class _FakeSock:
        def setsockopt(self, *a, **k):
            pass

        def settimeout(self, *a, **k):
            pass

    def _fake_create(address, *a, **k):
        captured["address"] = address
        return _FakeSock()

    conn = http_fetch._PinnedHTTPConnection("example.com", 80, timeout=5)
    conn._create_connection = _fake_create
    monkeypatch.setattr(http_fetch, "_resolve_pinned", lambda h: "93.184.216.34")
    conn.connect()
    assert captured["address"] == ("93.184.216.34", 80)
    assert conn.host == "example.com"


# --- SSRF: IDN/punycode host must still be pinned (no rebinding bypass) -------

def test_request_host_matches_reconciles_idn_forms():
    from maverick.tools._ssrf import _request_host_matches
    req = httpx.Request("GET", "https://xn--e1afmkfd.xn--p1ai/x")  # punycode URL
    # httpx decodes url.host to Unicode; the validated host is the punycode form.
    assert _request_host_matches(req, "xn--e1afmkfd.xn--p1ai")
    assert not _request_host_matches(req, "evil.example.com")


def test_pinned_transport_refuses_mismatched_host():
    from maverick.tools._ssrf import BlockedHost, _PinnedTransport

    class _Inner:
        def handle_request(self, r):
            raise AssertionError("must not reach the inner transport on a mismatch")

    t = _PinnedTransport("good.example.com", "good.example.com", "1.2.3.4", _Inner())
    with pytest.raises(BlockedHost):
        t.handle_request(httpx.Request("GET", "https://evil.example.com/x"))
