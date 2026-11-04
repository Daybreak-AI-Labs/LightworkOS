"""The two browser tools share one Playwright worker only inside one goal scope."""
from __future__ import annotations

import asyncio
import inspect
import threading

from maverick.connections import bind_principal
from maverick.logging_config import reset_goal_context, set_goal_context
from maverick.paths import reset_tenant, set_tenant
from maverick.tools import ToolRegistry, _register_optional_tools
from maverick.tools import aria_navigate as aria_mod
from maverick.tools import browser as browser_mod


def test_production_registration_uses_the_shared_browser_worker():
    registry = ToolRegistry()
    _register_optional_tools(
        registry, None, enable_web_search=False,
        enable_computer_use=False, enable_browser=True,
    )
    assert inspect.iscoroutinefunction(registry._tools["browser"].fn)
    assert inspect.iscoroutinefunction(registry._tools["aria_navigate"].fn)


def test_browser_and_aria_stay_on_their_own_goal_worker(monkeypatch, tmp_path):
    state_file = tmp_path / "shared-state.json"
    monkeypatch.setenv("MAVERICK_BROWSER_STATE", str(state_file))
    monkeypatch.setattr(browser_mod, "_deny_and_close_current_page", lambda *_a: None)
    monkeypatch.setattr(browser_mod, "gate_browser_action", lambda *_a, **_kw: None)
    closed = []

    class Page:
        def __init__(self, name):
            self.name = name
            self.url = "https://example.com/" + name
            self.accessibility = self

        def snapshot(self):
            return {"role": "button", "name": self.name}

        def get_by_role(self, role, *, name, exact):
            assert role == "button" and exact and name == self.name
            return self

        def count(self):
            return 1

        @property
        def first(self):
            return self

        def click(self):
            pass

    class Session:
        def __init__(self):
            self.owner_thread = threading.get_ident()
            self.scope = browser_mod._session_scope()
            self.page_value = Page(str(self.scope[1]))
            assert browser_mod._persist_enabled() is False

        @property
        def page(self):
            assert threading.get_ident() == self.owner_thread
            return self.page_value

        def save_state(self):
            assert threading.get_ident() == self.owner_thread
            return False

        def close(self):
            assert threading.get_ident() == self.owner_thread
            closed.append(self.scope)

    monkeypatch.setattr(browser_mod, "_BrowserSession", Session)

    async def scenario():
        browser = browser_mod.browser(managed=True)
        aria = aria_mod.aria_navigate(managed=True)
        tenant = set_tenant("alpha")
        goal = set_goal_context(goal_id=41)
        try:
            with bind_principal("user:alice"):
                assert "user:alice" in await browser.fn({"action": "current_url"})
                assert "user:alice" in await aria.fn({"op": "snapshot"})
            with bind_principal("user:bob"):
                assert "user:bob" in await browser.fn({"action": "current_url"})
                assert "user:bob" in await aria.fn({"op": "snapshot"})
            with bind_principal("user:alice"):
                # Bob's later snapshot must not replace Alice's node ledger.
                assert "user:alice" in await aria.fn({"op": "activate", "node_id": "n1"})
            await browser_mod.close_goal_browsers(41)
        finally:
            reset_goal_context(goal)
            reset_tenant(tenant)

        tenant = set_tenant("alpha")
        goal = set_goal_context(goal_id=42)
        try:
            with bind_principal("user:alice"):
                assert "user:alice" in await browser.fn({"action": "current_url"})
            await browser_mod.close_goal_browsers(42)
        finally:
            reset_goal_context(goal)
            reset_tenant(tenant)

        tenant = set_tenant("beta")
        goal = set_goal_context(goal_id=41)
        try:
            with bind_principal("user:alice"):
                assert "user:alice" in await browser.fn({"action": "current_url"})
            await browser_mod.close_goal_browsers(41)
        finally:
            reset_goal_context(goal)
            reset_tenant(tenant)

    asyncio.run(scenario())
    assert set(closed) == {
        ("alpha", "user:alice", 41), ("alpha", "user:bob", 41),
        ("alpha", "user:alice", 42), ("beta", "user:alice", 41),
    }
    assert not state_file.exists()
    assert not browser_mod._workers
    assert not browser_mod._sessions
