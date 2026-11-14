"""ARIA-first navigation — offline, fake-page tests."""
from __future__ import annotations

import pytest
from maverick.tools import aria_navigate as mod
from maverick.tools.aria_navigate import aria_navigate

TREE = {
    "role": "WebArea", "name": "Login — Example",
    "children": [
        {"role": "heading", "name": "Sign in"},
        {"role": "textbox", "name": "Email"},
        {"role": "textbox", "name": "Password"},
        {"role": "button", "name": "Sign in"},
        {"role": "link", "name": "Forgot password?"},
    ],
}


class FakeAccessibility:
    def __init__(self, tree):
        self.tree = tree
        self.calls = 0

    def snapshot(self):
        self.calls += 1
        return self.tree


class FakeElement:
    def __init__(self, page):
        self.page = page

    def click(self):
        self.page.actions.append("click")

    def focus(self):
        self.page.actions.append("focus")


class FakeLocator:
    def __init__(self, page, n):
        self.page = page
        self.n = n

    def count(self):
        return self.n

    @property
    def first(self):
        return FakeElement(self.page)


class FakePage:
    def __init__(self, tree=TREE, matches=1):
        self.accessibility = FakeAccessibility(tree)
        self.matches = matches
        self.actions: list[str] = []
        self.locator_queries: list[tuple] = []

    def get_by_role(self, role, name=None, exact=False):
        self.locator_queries.append((role, name, exact))
        return FakeLocator(self, self.matches)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("MAVERICK_BROWSER_DISABLE", raising=False)
    with mod._nodes_lock:
        mod._nodes.clear()
    yield


def _use(monkeypatch, page):
    monkeypatch.setattr(mod, "_page", lambda: page)
    return aria_navigate().fn


def test_snapshot_compact_tree_with_stable_ids(monkeypatch):
    page = FakePage()
    run = _use(monkeypatch, page)
    out = run({"op": "snapshot"})
    lines = out.splitlines()
    assert lines[0] == "n1 [WebArea] 'Login — Example'"
    assert lines[3] == "n4   [textbox] 'Password'"
    assert len(lines) == 6
    # Stable: the same tree yields the same ids on a re-snapshot.
    assert run({"op": "snapshot"}) == out


def test_find_by_role_and_name(monkeypatch):
    run = _use(monkeypatch, FakePage())
    out = run({"op": "find", "role": "textbox", "name": "email"})
    assert out == "n3 [textbox] 'Email'"


def test_find_role_only_lists_all(monkeypatch):
    out = _use(monkeypatch, FakePage())({"op": "find", "role": "textbox"})
    assert "n3 [textbox] 'Email'" in out
    assert "n4 [textbox] 'Password'" in out


def test_find_no_match(monkeypatch):
    out = _use(monkeypatch, FakePage())({"op": "find", "role": "checkbox"})
    assert out.startswith("no node matches")


def test_find_requires_role_or_name(monkeypatch):
    assert _use(monkeypatch, FakePage())({"op": "find"}).startswith("ERROR")


def _route_clicks(monkeypatch, page):
    """Stand in for the browser tool's gated click path."""
    def gated(args):
        page.actions.append(("gated", args["selector"]))
        return f"clicked {args['selector']!r} on https://example.com/"
    monkeypatch.setattr(mod, "_gated_click", gated)


def test_activate_clicks_via_role_locator(monkeypatch):
    page = FakePage()
    run = _use(monkeypatch, page)
    _route_clicks(monkeypatch, page)
    run({"op": "snapshot"})
    out = run({"op": "activate", "node_id": "n5"})  # the Sign in button
    assert out == "click: n5 [button] 'Sign in'"
    assert page.actions == [("gated", 'role=button[name="Sign in"s]')]
    assert page.locator_queries == [("button", "Sign in", True)]


def test_activate_click_needs_browser_approval(monkeypatch):
    # The click goes through the browser tool's approval gate: with no human
    # decision it is refused and nothing reaches the page.
    from maverick.tools import browser as browser_mod

    page = FakePage()
    page.url = "https://example.com/"
    page.locator = lambda selector: FakeLocator(page, 1)

    class Session:
        def __init__(self):
            self.page = page

        def approval_context(self, action, args):
            return {"target_summary": "Sign in", "target_state_sha256": "0" * 64}

    monkeypatch.setattr(browser_mod, "_get_session", lambda: Session())
    run = _use(monkeypatch, page)
    out = run({"op": "activate", "node_id": "n5"})
    assert out.startswith("ERROR") and "not approved" in out
    assert page.actions == []


def test_activate_refuses_focus_and_reports_landed_page_denial(monkeypatch):
    page = FakePage()
    run = _use(monkeypatch, page)
    run({"op": "snapshot"})
    out = run({"op": "activate", "node_id": "n3", "action": "focus"})
    assert out.startswith("ERROR") and page.actions == []  # focus is never ungated
    denial = "⚠ DENIED: navigation landed on a private/internal host '10.0.0.1'"
    monkeypatch.setattr(mod, "_gated_click", lambda args: denial)
    assert run({"op": "activate", "node_id": "n5"}) == denial


def test_activate_without_prior_snapshot_resolves_itself(monkeypatch):
    page = FakePage()
    run = _use(monkeypatch, page)
    _route_clicks(monkeypatch, page)
    out = run({"op": "activate", "node_id": "n6"})
    assert out == "click: n6 [link] 'Forgot password?'"
    assert page.accessibility.calls == 1  # auto-snapshot happened


def test_activate_unknown_id_errors(monkeypatch):
    out = _use(monkeypatch, FakePage())({"op": "activate", "node_id": "n99"})
    assert "ERROR" in out and "snapshot" in out


def test_activate_stale_node_errors(monkeypatch):
    page = FakePage(matches=0)  # page changed; locator finds nothing
    run = _use(monkeypatch, page)
    run({"op": "snapshot"})
    out = run({"op": "activate", "node_id": "n5"})
    assert "ERROR" in out and "re-snapshot" in out


def test_disabled_env_short_circuits(monkeypatch):
    monkeypatch.setenv("MAVERICK_BROWSER_DISABLE", "1")

    def boom():
        raise AssertionError("page must not be touched when disabled")

    monkeypatch.setattr(mod, "_page", boom)
    out = aria_navigate().fn({"op": "snapshot"})
    assert "disabled" in out


def test_missing_playwright_reported(monkeypatch):
    def raise_import():
        raise ImportError("playwright not installed. Run: pip install 'maverick-agent[browser]'")

    monkeypatch.setattr(mod, "_page", raise_import)
    out = aria_navigate().fn({"op": "snapshot"})
    assert out.startswith("ERROR: playwright not installed")


def test_factory_shape():
    tool = aria_navigate()
    assert tool.name == "aria_navigate"
    assert set(tool.input_schema["properties"]["op"]["enum"]) == {"snapshot", "find", "activate"}
