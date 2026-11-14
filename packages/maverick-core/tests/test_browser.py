"""Tests for the browser tool: session persistence, the egress route guard,
redirect handling and the fill_form action.
"""
from __future__ import annotations

import maverick.tools.browser as browser_mod
from maverick.tools.browser import (
    _BrowserSession,
    _persist_enabled,
    _restore_state_arg,
    _state_path,
    browser,
)

# ---------- save_state on the session ----------

class _FakeContext:
    def __init__(self):
        self.calls = 0

    def storage_state(self):
        self.calls += 1
        # Playwright returns the state mapping when no path is supplied.
        return {"cookies": [], "origins": []}


# ---------- action wiring (mocked session, no playwright) ----------

class _FakePage:
    url = "about:blank"

    def goto(self, url, timeout, wait_until):
        self.url = getattr(self, "goto_url", url)


class _FakeSession:
    def __init__(self):
        self._page = _FakePage()
        self.save_calls = 0

    @property
    def page(self):
        return self._page

    def save_state(self):
        self.save_calls += 1
        return True


class _FakeRequest:
    def __init__(self, url):
        self.url = url


class _FakeRoute:
    def __init__(self):
        self.aborted = False
        self.continued = False

    def abort(self):
        self.aborted = True

    def continue_(self):
        self.continued = True


# ---------- path / toggle helpers (pure) ----------

def test_state_path_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_BROWSER_STATE", raising=False)
    p = _state_path()
    assert p.name == "state.json"
    assert p.parent.name == "browser"


def test_state_path_override(monkeypatch, tmp_path):
    target = tmp_path / "profileA.json"
    monkeypatch.setenv("MAVERICK_BROWSER_STATE", str(target))
    assert _state_path() == target


def test_persist_enabled_requires_explicit_state(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_BROWSER_NO_PERSIST", raising=False)
    monkeypatch.delenv("MAVERICK_BROWSER_STATE", raising=False)
    assert _persist_enabled() is False

    monkeypatch.setenv("MAVERICK_BROWSER_STATE", str(tmp_path / "profile.json"))
    assert _persist_enabled() is True

    monkeypatch.setenv("MAVERICK_BROWSER_NO_PERSIST", "1")
    assert _persist_enabled() is False


def test_restore_arg_requires_explicit_state(monkeypatch, tmp_path):
    target = tmp_path / "nope.json"
    monkeypatch.delenv("MAVERICK_BROWSER_STATE", raising=False)
    monkeypatch.delenv("MAVERICK_BROWSER_NO_PERSIST", raising=False)
    monkeypatch.setattr(browser_mod, "_DEFAULT_STATE_PATH", target)
    target.write_text("{}")
    assert _restore_state_arg() is None  # implicit global profile is never restored

    monkeypatch.setenv("MAVERICK_BROWSER_STATE", str(target))
    assert _restore_state_arg() == str(target)
    monkeypatch.setenv("MAVERICK_BROWSER_NO_PERSIST", "1")
    assert _restore_state_arg() is None  # disabled wins even when file exists


def test_save_state_writes_file_with_secure_perms(monkeypatch, tmp_path):
    from maverick.file_lock import private_path_is_restricted
    target = tmp_path / "sub" / "state.json"
    monkeypatch.setenv("MAVERICK_BROWSER_STATE", str(target))
    monkeypatch.delenv("MAVERICK_BROWSER_NO_PERSIST", raising=False)

    sess = _BrowserSession()
    sess._context = _FakeContext()
    assert sess.save_state() is True
    assert target.exists()
    assert private_path_is_restricted(target)


def test_save_state_noop_without_context(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_BROWSER_STATE", str(tmp_path / "s.json"))
    sess = _BrowserSession()
    assert sess.save_state() is False  # no context started


def test_save_state_noop_without_explicit_state(monkeypatch):
    monkeypatch.delenv("MAVERICK_BROWSER_STATE", raising=False)
    monkeypatch.delenv("MAVERICK_BROWSER_NO_PERSIST", raising=False)
    sess = _BrowserSession()
    sess._context = _FakeContext()
    assert sess.save_state() is False


def test_save_state_noop_when_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_BROWSER_STATE", str(tmp_path / "s.json"))
    monkeypatch.setenv("MAVERICK_BROWSER_NO_PERSIST", "1")
    sess = _BrowserSession()
    sess._context = _FakeContext()
    assert sess.save_state() is False


def test_navigate_checkpoints_session(monkeypatch):
    monkeypatch.setenv("MAVERICK_BROWSER_DISABLE", "0")
    fake = _FakeSession()
    monkeypatch.setattr(browser_mod, "_get_session", lambda: fake)
    monkeypatch.setattr(browser_mod, "gate_browser_action", lambda *_a, **_kw: None)
    out = browser_mod._run_browser_action({"action": "navigate", "url": "https://example.com"})
    assert out.startswith("navigated to https://example.com")
    assert fake.save_calls == 1


def test_save_session_action(monkeypatch):
    monkeypatch.setenv("MAVERICK_BROWSER_DISABLE", "0")
    fake = _FakeSession()
    monkeypatch.setattr(browser_mod, "_get_session", lambda: fake)
    monkeypatch.setattr(browser_mod, "gate_browser_action", lambda *_a, **_kw: None)
    out = browser_mod._run_browser_action({"action": "save_session"})
    assert out == "session saved"
    assert fake.save_calls == 1


def test_save_session_reports_when_not_saved(monkeypatch):
    monkeypatch.setenv("MAVERICK_BROWSER_DISABLE", "0")

    class _NoSaveSession(_FakeSession):
        def save_state(self):
            return False

    monkeypatch.setattr(browser_mod, "_get_session", lambda: _NoSaveSession())
    monkeypatch.setattr(browser_mod, "gate_browser_action", lambda *_a, **_kw: None)
    out = browser_mod._run_browser_action({"action": "save_session"})
    assert "not saved" in out.lower()


def test_schema_includes_save_session():
    actions = browser().input_schema["properties"]["action"]["enum"]
    assert "save_session" in actions


def test_navigate_denies_disallowed_redirect_final_host(monkeypatch):
    monkeypatch.setenv("MAVERICK_BROWSER_DISABLE", "0")
    # allowed.example.com is a non-resolvable placeholder; the SSRF pre-flight
    # fails closed on DNS failure, so use the documented escape hatch to let
    # navigation reach the capability-based redirect check this test exercises.
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    fake = _FakeSession()
    fake.page.goto_url = "https://evil.com/private"
    monkeypatch.setattr(browser_mod, "_get_session", lambda: fake)
    monkeypatch.setattr(browser_mod, "gate_browser_action", lambda *_a, **_kw: None)
    closed = []
    monkeypatch.setattr(browser_mod, "close_browser", lambda: closed.append(True))

    out = browser_mod._run_browser_action({
        "action": "navigate",
        "url": "https://allowed.example.com/redirect",
        "_capability_allow_hosts": ("*.example.com",),
    })

    assert "DENIED by capability" in out
    assert "evil.com" in out
    assert fake.save_calls == 0
    assert closed == [True]


def test_url_less_browser_action_denies_disallowed_current_host(monkeypatch):
    monkeypatch.setenv("MAVERICK_BROWSER_DISABLE", "0")
    fake = _FakeSession()
    fake.page.url = "https://evil.com/private"
    monkeypatch.setattr(browser_mod, "_get_session", lambda: fake)
    closed = []
    monkeypatch.setattr(browser_mod, "close_browser", lambda: closed.append(True))

    out = browser_mod._run_browser_action({
        "action": "extract_text",
        "_capability_allow_hosts": ("*.example.com",),
    })

    assert "DENIED by capability" in out
    assert "evil.com" in out
    assert closed == [True]


# ---------- egress checks ----------
#
# Previously the browser tool ran outside both the enterprise egress lock
# and the per-tenant egress plane entirely -- no check at all, unlike every
# sibling outbound-request tool (http_fetch, websocket). See
# test_enterprise_tool_egress.py / test_tenant_egress.py for the
# enterprise-mode / tenant-plane integration tests; these cover the
# mechanics: the post-hoc close-on-landed-redirect path, and the
# network-level `page.route` backstop that also covers subresources a
# page's own JS fetches in the background (which never show up as
# ``page.url`` at all).

def test_deny_and_close_current_page_closes_on_enterprise_denial(monkeypatch):
    monkeypatch.setattr(
        browser_mod, "_egress_denial",
        lambda url: "enterprise mode: refusing tool egress to 'evil.com'",
    )
    closed = []
    monkeypatch.setattr(browser_mod, "close_browser", lambda: closed.append(True))

    class _Page:
        url = "https://evil.com/private"

    out = browser_mod._deny_and_close_current_page(_Page(), ())
    assert out is not None
    assert "enterprise mode" in out and "session was closed" in out
    assert closed == [True]


def test_deny_and_close_current_page_allows_when_egress_permits(monkeypatch):
    monkeypatch.setattr(browser_mod, "_egress_denial", lambda url: None)
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")  # isolate from real DNS
    closed = []
    monkeypatch.setattr(browser_mod, "close_browser", lambda: closed.append(True))

    class _Page:
        url = "https://ok.example.com/x"

    assert browser_mod._deny_and_close_current_page(_Page(), ()) is None
    assert closed == []


def test_route_guard_continues_non_http_schemes():
    route = _FakeRoute()
    browser_mod._route_guard(route, _FakeRequest("data:image/png;base64,AAAA"))
    assert route.continued and not route.aborted


def test_route_guard_aborts_loopback_subresource():
    route = _FakeRoute()
    browser_mod._route_guard(route, _FakeRequest("http://127.0.0.1/steal"))
    assert route.aborted and not route.continued


def test_route_guard_aborts_localhost_subresource():
    route = _FakeRoute()
    browser_mod._route_guard(route, _FakeRequest("http://localhost:9/steal"))
    assert route.aborted and not route.continued


def test_route_guard_allows_public_host(monkeypatch):
    monkeypatch.setattr("maverick.tools.http_fetch.is_blocked_host", lambda h: False)
    route = _FakeRoute()
    browser_mod._route_guard(route, _FakeRequest("https://cdn.example.com/img.png"))
    assert route.continued and not route.aborted


def test_route_guard_aborts_under_enterprise_denial(monkeypatch):
    monkeypatch.setattr("maverick.tools.http_fetch.is_blocked_host", lambda h: False)
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", lambda *a, **k: {})
    route = _FakeRoute()
    browser_mod._route_guard(route, _FakeRequest("https://cdn.example.com/img.png"))
    assert route.aborted and not route.continued


def test_route_guard_aborts_under_tenant_egress_deny(monkeypatch):
    monkeypatch.setattr("maverick.tools.http_fetch.is_blocked_host", lambda h: False)
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    import maverick.config as cfg
    monkeypatch.setattr(
        cfg, "load_config",
        lambda *a, **k: {"egress": {"deny": ["cdn.example.com"]}},
    )
    route = _FakeRoute()
    browser_mod._route_guard(route, _FakeRequest("https://cdn.example.com/img.png"))
    assert route.aborted and not route.continued


def test_ensure_started_registers_route_guard_on_the_context(monkeypatch):
    """Regression guard for the registration call itself -- everything above
    tests `_route_guard`'s logic, but nothing exercises it if it's never
    wired onto a context/page."""
    import sys
    import types

    captured = {"route": None}

    class _FakeContext:
        def route(self, pattern, handler):
            captured["route"] = (pattern, handler)

        def new_page(self):
            return _FakePage()

    class _FakeBrowser:
        def new_context(self, **kwargs):
            return _FakeContext()

    class _FakeChromium:
        def launch(self, **kwargs):
            captured["launch"] = kwargs
            return _FakeBrowser()

    class _FakePlaywrightHandle:
        chromium = _FakeChromium()

        def stop(self):
            pass

    class _FakeSyncPlaywright:
        def start(self):
            return _FakePlaywrightHandle()

    fake_sync_api = types.ModuleType("playwright.sync_api")
    fake_sync_api.sync_playwright = lambda: _FakeSyncPlaywright()
    fake_playwright = types.ModuleType("playwright")
    fake_playwright.sync_api = fake_sync_api
    monkeypatch.setitem(sys.modules, "playwright", fake_playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_sync_api)
    monkeypatch.setenv("MAVERICK_BROWSER_NO_PERSIST", "1")

    sess = _BrowserSession()
    sess._ensure_started()

    assert captured["route"] == ("**/*", browser_mod._route_guard)
    assert captured["launch"]["proxy"]["server"].startswith("socks5://127.0.0.1:")
    sess.close()


class _FakeFormPage:
    def __init__(self, fail=()):
        self.filled: list[tuple[str, str]] = []
        self.timeouts: list[int] = []
        self._fail = set(fail)

    def fill(self, selector, value, timeout):
        self.timeouts.append(timeout)
        if selector in self._fail:
            raise RuntimeError("element not found")
        self.filled.append((selector, value))


class _FakeFormSession:
    def __init__(self, page):
        self._page = page

    @property
    def page(self):
        return self._page

    def save_state(self):
        return True


def _use(monkeypatch, page):
    monkeypatch.setenv("MAVERICK_BROWSER_DISABLE", "0")
    monkeypatch.setattr(browser_mod, "_get_session", lambda: _FakeFormSession(page))
    monkeypatch.setattr(browser_mod, "gate_browser_action", lambda *args, **kwargs: None)


def test_fill_form_fills_all_fields(monkeypatch):
    page = _FakeFormPage()
    _use(monkeypatch, page)
    out = browser_mod._run_browser_action({
        "action": "fill_form",
        "fields": {"#user": "alice", "#pass": "hunter2", "#email": "a@b.co"},
    })
    assert out == "filled 3/3 field(s)"
    assert page.filled == [("#user", "alice"), ("#pass", "hunter2"), ("#email", "a@b.co")]


def test_fill_form_preserves_order_and_coerces_values(monkeypatch):
    page = _FakeFormPage()
    _use(monkeypatch, page)
    browser_mod._run_browser_action({
        "action": "fill_form",
        "fields": {"#a": 1, "#b": "two"},
    })
    assert page.filled == [("#a", "1"), ("#b", "two")]


def test_fill_form_reports_partial_failure(monkeypatch):
    page = _FakeFormPage(fail={"#missing"})
    _use(monkeypatch, page)
    out = browser_mod._run_browser_action({
        "action": "fill_form",
        "fields": {"#ok": "x", "#missing": "y"},
    })
    assert out.startswith("filled 1/2 field(s)")
    assert "failed:" in out and "#missing" in out
    assert page.filled == [("#ok", "x")]


def test_fill_form_requires_fields(monkeypatch):
    page = _FakeFormPage()
    _use(monkeypatch, page)
    assert "requires a non-empty" in browser_mod._run_browser_action(
        {"action": "fill_form"}).lower()
    assert "requires a non-empty" in browser_mod._run_browser_action(
        {"action": "fill_form", "fields": {}}).lower()


def test_fill_form_rejects_non_dict_fields(monkeypatch):
    page = _FakeFormPage()
    _use(monkeypatch, page)
    out = browser_mod._run_browser_action(
        {"action": "fill_form", "fields": ["#a", "#b"]})
    assert out.startswith("ERROR")


def test_fill_form_rejects_too_many_fields(monkeypatch):
    page = _FakeFormPage()
    _use(monkeypatch, page)
    fields = {f"#field-{idx}": "x" for idx in range(browser_mod._MAX_FILL_FORM_FIELDS + 1)}
    out = browser_mod._run_browser_action({"action": "fill_form", "fields": fields})
    assert out == f"ERROR: fill_form supports at most {browser_mod._MAX_FILL_FORM_FIELDS} fields"
    assert page.filled == []


def test_fill_form_caps_per_field_timeout(monkeypatch):
    page = _FakeFormPage(fail={"#missing"})
    _use(monkeypatch, page)
    out = browser_mod._run_browser_action({
        "action": "fill_form",
        "fields": {"#ok": "x", "#missing": "y"},
        "timeout_ms": 60_000,
    })
    assert out.startswith("filled 1/2 field(s)")
    assert page.timeouts == [browser_mod._MAX_FILL_FORM_FIELD_TIMEOUT_MS] * 2


def test_fill_form_stops_at_batch_deadline(monkeypatch):
    page = _FakeFormPage()
    _use(monkeypatch, page)
    times = iter([0.0, 0.0, 6.0])
    monkeypatch.setattr(browser_mod, "_monotonic", lambda: next(times))
    out = browser_mod._run_browser_action({
        "action": "fill_form",
        "fields": {"#a": "1", "#b": "2", "#c": "3"},
        "timeout_ms": 60_000,
    })
    assert out.startswith("filled 1/3 field(s)")
    assert "batch timeout" in out
    assert page.filled == [("#a", "1")]


def test_fill_form_rejects_oversized_selector_and_value(monkeypatch):
    page = _FakeFormPage()
    _use(monkeypatch, page)
    long_selector = "#" + "a" * browser_mod._MAX_FILL_FORM_SELECTOR_LENGTH
    long_value = "x" * (browser_mod._MAX_FILL_FORM_VALUE_LENGTH + 1)
    out = browser_mod._run_browser_action({
        "action": "fill_form",
        "fields": {long_selector: "ok", "#ok": long_value},
    })
    # Refused before approval and dispatch, so the approved single-task
    # dispatch path is bounded too.
    assert out.startswith("ERROR: fill_form selectors are limited")
    assert page.filled == []
    out = browser_mod._run_browser_action({
        "action": "fill_form", "fields": {"#ok": long_value},
    })
    assert out.startswith("ERROR: fill_form values are limited")
    assert page.filled == []


def test_timeout_ms_is_clamped(monkeypatch):
    seen = []
    monkeypatch.setenv("MAVERICK_BROWSER_DISABLE", "0")
    monkeypatch.setattr(browser_mod, "_get_session", lambda: _FakeFormSession(_FakeFormPage()))
    monkeypatch.setattr(browser_mod, "gate_browser_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(browser_mod, "_dispatch_browser_action",
                        lambda action, session, page, args, timeout, hosts: seen.append(timeout) or "ok")
    browser_mod._run_browser_action({"action": "wait_for", "selector": "#x", "timeout_ms": 2**31 - 1})
    assert seen == [browser_mod._MAX_TIMEOUT_MS]


def test_schema_includes_fill_form_limits():
    schema = browser().input_schema
    assert "fill_form" in schema["properties"]["action"]["enum"]
    fields_schema = schema["properties"]["fields"]
    assert fields_schema["maxProperties"] == browser_mod._MAX_FILL_FORM_FIELDS
    assert fields_schema["propertyNames"]["maxLength"] == browser_mod._MAX_FILL_FORM_SELECTOR_LENGTH
    assert fields_schema["additionalProperties"]["maxLength"] == browser_mod._MAX_FILL_FORM_VALUE_LENGTH


class TestBrowserSSRF:
    def test_decimal_and_loopback_blocked_public_allowed(self):
        from maverick.tools.browser import _is_safe_browser_url
        # Decimal/octal-int encodings of 127.0.0.1 resolve to loopback but
        # do not parse via ipaddress.ip_address -- the old literal-only
        # check let them through.
        assert _is_safe_browser_url("http://2130706433/") is False
        assert _is_safe_browser_url("http://127.0.0.1/") is False
        assert _is_safe_browser_url("http://localhost/") is False
        assert _is_safe_browser_url("https://example.com/") is True

    def test_post_nav_blocks_redirect_to_internal_host(self, monkeypatch):
        # page.goto/click follow 3xx transparently; a redirect that lands on the
        # metadata IP must be caught AFTER navigation and the session closed so
        # screenshot/extract can't read it.
        from types import SimpleNamespace

        from maverick.tools import browser
        monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
        closed = {"n": 0}
        monkeypatch.setattr(browser, "close_browser",
                            lambda: closed.__setitem__("n", closed["n"] + 1))
        page = SimpleNamespace(url="http://169.254.169.254/latest/meta-data/")
        denial = browser._deny_and_close_current_page(page, ())
        assert denial is not None and "private/internal" in denial
        assert closed["n"] == 1

    def test_post_nav_allows_public_host(self, monkeypatch):
        from types import SimpleNamespace

        from maverick.tools import browser
        flag = {"closed": False}
        monkeypatch.setattr(browser, "close_browser",
                            lambda: flag.__setitem__("closed", True))
        page = SimpleNamespace(url="https://example.com/page")
        assert browser._deny_and_close_current_page(page, ()) is None
        assert flag["closed"] is False

    def test_post_nav_ignores_non_http_url(self, monkeypatch):
        from types import SimpleNamespace

        from maverick.tools import browser
        flag = {"closed": False}
        monkeypatch.setattr(browser, "close_browser",
                            lambda: flag.__setitem__("closed", True))
        # about:blank (fresh tab / failed nav) is not an internal-host exfil.
        page = SimpleNamespace(url="about:blank")
        assert browser._deny_and_close_current_page(page, ()) is None
        assert flag["closed"] is False
