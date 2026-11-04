"""robots.txt must be fetched through the pinned SSRF client, not a raw
httpx.get that re-resolves + follows redirects (DNS-rebind / redirect side door
around the guard the main fetch already uses)."""
from __future__ import annotations

import sys
import types

from maverick.tools import _ssrf
from maverick.tools.http_fetch import _check_robots


class _Resp:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


def _install_fake_httpx(monkeypatch):
    # _check_robots gates on `import httpx`; inject a stub so the body runs
    # without the real dependency (safe_get is mocked below regardless).
    monkeypatch.setitem(sys.modules, "httpx", types.ModuleType("httpx"))


def test_robots_fetched_via_safe_get_and_disallow_respected(monkeypatch):
    _install_fake_httpx(monkeypatch)
    seen: dict = {}

    def fake_safe_get(url, **kw):
        seen["url"] = url
        return _Resp(200, "User-agent: *\nDisallow: /private")

    monkeypatch.setattr(_ssrf, "safe_get", fake_safe_get)

    # The pinned client was used, for the right host's /robots.txt.
    assert _check_robots("https://example.com/private/x") is False
    assert seen["url"] == "https://example.com/robots.txt"
    # A path outside the Disallow is permitted.
    assert _check_robots("https://example.com/open/y") is True


def test_robots_blockedhost_defers_to_allowed(monkeypatch):
    _install_fake_httpx(monkeypatch)

    def boom(url, **kw):
        raise _ssrf.BlockedHost("resolves to a private address")

    monkeypatch.setattr(_ssrf, "safe_get", boom)
    # A blocked robots host must not crash the fetch decision; the main fetch's
    # own pinned client is the real gate, so robots defers to "allowed".
    assert _check_robots("https://example.com/anything") is True
