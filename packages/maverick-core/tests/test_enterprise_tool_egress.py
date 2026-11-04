"""Enterprise mode locks *tool* egress (http_fetch / web_search), not just LLM calls."""
from __future__ import annotations

import pytest
from maverick.enterprise import egress_permitted, enterprise_egress_denial


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def _enterprise(monkeypatch, allowed=None):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    if allowed is not None:
        monkeypatch.setattr(
            "maverick.config.load_config",
            lambda *a, **k: {"enterprise": {"allowed_hosts": allowed}},
        )


def test_egress_permitted_when_enterprise_off():
    assert egress_permitted("https://anywhere.example.com/x") is True
    assert enterprise_egress_denial("https://anywhere.example.com/x") is None


def test_public_host_denied_under_enterprise(monkeypatch):
    _enterprise(monkeypatch)
    assert egress_permitted("https://exfil.example.com/x") is False
    deny = enterprise_egress_denial("https://exfil.example.com/x", tool="http_fetch")
    assert deny and "exfil.example.com" in deny and "allowed_hosts" in deny


def test_local_endpoint_permitted_under_enterprise(monkeypatch):
    _enterprise(monkeypatch)
    assert egress_permitted("http://localhost:8080/x") is True
    assert egress_permitted("http://127.0.0.1/x") is True
    assert enterprise_egress_denial("http://localhost:8080/x") is None


def test_imds_is_not_local_and_is_denied_under_enterprise(monkeypatch):
    # Cloud IMDS is link-local but leaks instance credentials -- it must NOT be
    # treated as a local service that bypasses the egress lock.
    _enterprise(monkeypatch)
    for url in ("http://169.254.169.254/latest/meta-data/",
                "http://[fd00:ec2::254]/", "https://169.254.169.254/"):
        assert egress_permitted(url) is False, url
        assert enterprise_egress_denial(url) is not None, url
    # A non-IMDS link-local (APIPA) host is still treated as local (no regression).
    assert egress_permitted("http://169.254.1.5/x") is True


def test_allow_listed_host_permitted_under_enterprise(monkeypatch):
    _enterprise(monkeypatch, allowed=["api.tavily.com"])
    assert egress_permitted("https://api.tavily.com/search") is True
    assert egress_permitted("https://other.example.com/x") is False


def test_http_fetch_blocks_egress_under_enterprise(monkeypatch):
    _enterprise(monkeypatch)
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")   # skip DNS, isolate the gate
    from maverick.tools.http_fetch import _run_fetch
    out = _run_fetch({"url": "https://exfil.invalid/steal"})
    assert out.startswith("ERROR:") and "enterprise mode" in out and "boundary" in out


def test_http_fetch_enterprise_denial_happens_before_robots(monkeypatch):
    _enterprise(monkeypatch)
    monkeypatch.setenv("MAVERICK_FETCH_RESPECT_ROBOTS", "1")
    from maverick.tools import http_fetch

    def fail_if_called(_url):
        raise AssertionError("robots.txt was checked before enterprise denial")

    monkeypatch.setattr(http_fetch, "_check_robots", fail_if_called)
    out = http_fetch._run_fetch({"url": "https://exfil.invalid/steal"})
    assert out.startswith("ERROR:") and "enterprise mode" in out and "boundary" in out


def test_websocket_tool_blocks_egress_under_enterprise(monkeypatch):
    # Websockets.connect is not wrapped by egress_guard (httpx/requests/
    # urllib only), so without a manual check the enterprise tool-egress lock
    # never saw a websocket connection at all.
    import asyncio

    _enterprise(monkeypatch)
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")  # isolate the gate
    from maverick.tools.websocket_tool import _run
    out = asyncio.run(_run({"url": "wss://exfil.invalid/steal", "recv": False}))
    assert out.startswith("ERROR:") and "enterprise mode" in out and "boundary" in out


def test_websocket_tool_enterprise_denial_happens_before_connect(monkeypatch):
    import asyncio

    import maverick.tools._ssrf as ssrf_mod

    _enterprise(monkeypatch)
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    from maverick.tools import websocket_tool

    def fail_if_called(host):
        raise AssertionError("resolve_pinned_ip was called before enterprise denial")

    monkeypatch.setattr(ssrf_mod, "resolve_pinned_ip", fail_if_called)
    out = asyncio.run(websocket_tool._run({"url": "wss://exfil.invalid/steal", "recv": False}))
    assert out.startswith("ERROR:") and "enterprise mode" in out


def test_websocket_tool_allows_local_endpoint_under_enterprise(monkeypatch):
    import asyncio

    _enterprise(monkeypatch)
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    from maverick.tools.websocket_tool import _run
    out = asyncio.run(_run({"url": "ws://127.0.0.1:1/x", "recv": False}))
    # Not blocked by the enterprise gate -- whatever it fails on next (no
    # listener there, or websockets missing) is a different, later error.
    assert "enterprise mode" not in out


def test_websocket_tool_allow_listed_host_permitted_under_enterprise(monkeypatch):
    import asyncio

    _enterprise(monkeypatch, allowed=["api.example.com"])
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    from maverick.tools.websocket_tool import _run
    out = asyncio.run(_run({"url": "wss://api.example.com/socket", "recv": False}))
    assert "enterprise mode" not in out


def test_web_search_disabled_under_enterprise_without_allowlist(monkeypatch):
    _enterprise(monkeypatch)
    from maverick.tools.web_search import _run_search
    out = _run_search({"query": "sensitive patient data"})
    assert "disabled in enterprise mode" in out


def test_web_search_allows_an_allow_listed_backend(monkeypatch):
    # Allow-listing tavily lets it past the gate (it then fails on no API key, not on
    # the enterprise gate -- proving the gate permitted it rather than blocking all).
    _enterprise(monkeypatch, allowed=["api.tavily.com"])
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    from maverick.tools.web_search import _run_search
    out = _run_search({"query": "x"})
    assert "disabled in enterprise mode" not in out


# ---------- browser tool ----------
#
# The browser tool (Playwright) gets the same enterprise/tenant egress check
# as every sibling outbound-request tool, so a prompt-injected page cannot
# navigate anywhere with enterprise mode on.


class _FakeBrowserPage:
    url = "about:blank"

    def goto(self, url, timeout, wait_until):
        raise AssertionError(
            "page.goto must not be called once egress denies the URL up front"
        )


class _FakeBrowserSession:
    def __init__(self):
        self._page = _FakeBrowserPage()

    @property
    def page(self):
        return self._page

    def save_state(self):
        return True


def test_browser_navigate_blocks_egress_under_enterprise(monkeypatch):
    _enterprise(monkeypatch)
    monkeypatch.setenv("MAVERICK_BROWSER_DISABLE", "0")
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")  # isolate the enterprise gate from DNS
    from maverick.tools import browser as browser_mod
    monkeypatch.setattr(browser_mod, "_get_session", lambda: _FakeBrowserSession())
    # Fresh human consent is covered by test_action_gate. Bypass it here so
    # this test reaches the enterprise egress boundary it owns.
    monkeypatch.setattr(browser_mod, "gate_browser_action", lambda *_a, **_kw: None)
    out = browser_mod._run_browser_action(
        {"action": "navigate", "url": "https://exfil.invalid/steal"},
    )
    assert out.startswith("ERROR:") and "enterprise mode" in out and "boundary" in out


def test_browser_navigate_allows_allow_listed_host_under_enterprise(monkeypatch):
    _enterprise(monkeypatch, allowed=["api.example.com"])
    monkeypatch.setenv("MAVERICK_BROWSER_DISABLE", "0")
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    from maverick.tools import browser as browser_mod

    class _AllowedPage(_FakeBrowserPage):
        def goto(self, url, timeout, wait_until):
            self.url = url

    class _AllowedSession(_FakeBrowserSession):
        def __init__(self):
            self._page = _AllowedPage()

    monkeypatch.setattr(browser_mod, "_get_session", lambda: _AllowedSession())
    monkeypatch.setattr(browser_mod, "gate_browser_action", lambda *_a, **_kw: None)
    out = browser_mod._run_browser_action(
        {"action": "navigate", "url": "https://api.example.com/x"},
    )
    assert out.startswith("navigated to")
