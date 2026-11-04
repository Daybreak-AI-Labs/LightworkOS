"""Tests for the http_fetch tool: the SSRF guard, redirect revalidation, body
caps and the web_archive guarded fetch.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

# --- SSRF guard must block metadata/reserved/multicast/unspecified ---

@pytest.mark.parametrize(
    "host",
    ["169.254.169.254", "127.0.0.1", "10.0.0.1", "192.168.1.1",
     "0.0.0.0", "224.0.0.1", "::1"],
)
def test_is_private_ip_blocks_unsafe_ranges(host):
    from maverick.tools.http_fetch import _is_private_ip
    assert _is_private_ip(host) is True


def test_is_private_ip_allows_public_literal():
    from maverick.tools.http_fetch import _is_private_ip
    # Literal public IP -> resolves to itself, no DNS needed.
    assert _is_private_ip("93.184.216.34") is False


# --- SSRF override is honored uniformly ---

def test_is_blocked_host_respects_override(monkeypatch):
    from maverick.tools.http_fetch import is_blocked_host
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    assert is_blocked_host("127.0.0.1") is True
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    assert is_blocked_host("127.0.0.1") is False


# ---------- http_fetch ----------

def test_http_fetch_rejects_empty_url():
    from maverick.tools.http_fetch import http_fetch
    assert "url is required" in http_fetch().fn({"url": ""}).lower()


def test_http_fetch_rejects_non_http_scheme():
    from maverick.tools.http_fetch import http_fetch
    out = http_fetch().fn({"url": "file:///etc/passwd"})
    assert "only http/https" in out.lower()


def test_http_fetch_rejects_private_ip_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    from maverick.tools.http_fetch import _is_private_ip
    # 127.0.0.1 / localhost should be detected as private.
    assert _is_private_ip("127.0.0.1") is True


def test_http_fetch_allow_private_override(monkeypatch):
    """With MAVERICK_FETCH_ALLOW_PRIVATE=1, private addrs are not rejected."""
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    from maverick.tools import http_fetch as hf

    class _Resp:
        status_code = 200
        reason_phrase = "OK"
        encoding = "utf-8"
        url = "http://localhost/"
        headers = {"content-type": "text/plain"}
        content = b"hello"

        def raise_for_status(self): pass
        def iter_bytes(self, chunk_size=None): yield self.content
        def __enter__(self): return self
        def __exit__(self, *a): return False

    class _Client:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def stream(self, *a, **kw): return _Resp()

    import httpx
    with patch.object(httpx, "Client", _Client):
        out = hf.http_fetch().fn({"url": "http://127.0.0.1/", "render": "raw"})
    assert "hello" in out


def test_http_fetch_markdown_render(monkeypatch):
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    from maverick.tools import http_fetch as hf

    html = "<h1>Title</h1><p>Hello <a href='https://x.example'>x</a></p>"

    class _Resp:
        status_code = 200
        reason_phrase = "OK"
        encoding = "utf-8"
        url = "http://localhost/"
        headers = {"content-type": "text/html"}
        content = html.encode()

        def raise_for_status(self): pass
        def iter_bytes(self, chunk_size=None): yield self.content
        def __enter__(self): return self
        def __exit__(self, *a): return False

    class _Client:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def stream(self, *a, **kw): return _Resp()

    import httpx
    with patch.object(httpx, "Client", _Client):
        out = hf.http_fetch().fn({"url": "http://127.0.0.1/", "render": "markdown"})
    assert "# Title" in out
    assert "[x](https://x.example)" in out


# --- REST + GraphQL connectors pin the host IP --------------------

@pytest.fixture(autouse=True)
def _no_allow_private(monkeypatch):
    # The SSRF guard honours MAVERICK_FETCH_ALLOW_PRIVATE=1 (on-prem opt-in);
    # make sure these tests run with the guard armed regardless of host env.
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)


# --- web_archive fetches go through the guarded opener ---------------

def test_web_archive_routes_through_guarded_urlopen(monkeypatch):
    import json as _json

    from maverick.tools import http_fetch, web_archive

    called = {}

    class _FakeResp:
        status = 200

        def read(self):
            return _json.dumps({"archived_snapshots": {}}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_guarded(req, *, timeout, allow_http=False):
        called["url"] = req.full_url
        return _FakeResp()

    monkeypatch.setattr(http_fetch, "guarded_urlopen", _fake_guarded)
    code, data = web_archive._http_get_json(web_archive._avail_url("https://x.test"))
    assert called.get("url", "").startswith("https://archive.org/wayback/available")
    assert code == 200
    assert data == {"archived_snapshots": {}}


# ---------- SSRF redirect revalidation ----------

def test_guarded_urlopen_revalidates_redirect_to_metadata(monkeypatch):
    from maverick.tools import http_fetch

    handler = http_fetch._RevalidatingRedirectHandler(allow_http=True)

    class _Req:
        def get_full_url(self):
            return "https://example.com/"

    # A 302 to the cloud metadata endpoint must be refused mid-redirect.
    with pytest.raises(ValueError):
        handler.redirect_request(
            _Req(), None, 302, "Found", {},
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        )


def test_guarded_urlopen_allows_redirect_to_public(monkeypatch):
    from maverick.tools import http_fetch

    monkeypatch.setattr(http_fetch, "is_blocked_host", lambda _h: False)
    handler = http_fetch._RevalidatingRedirectHandler(allow_http=False)

    class _Req:
        def get_full_url(self):
            return "https://example.com/"

        def get_method(self):
            return "GET"

        @property
        def headers(self):
            return {}

        unredirected_hdrs: dict = {}
        data = None
        origin_req_host = "example.com"
        unverifiable = False

    # A redirect to a normal public https URL is allowed (returns a Request).
    out = handler.redirect_request(
        _Req(), None, 302, "Found", {}, "https://other.example.org/next",
    )
    assert out is not None
