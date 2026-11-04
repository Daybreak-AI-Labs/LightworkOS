"""The read-only ``observe`` action: semantic page snapshot for the browser tool.

``observe`` returns title + url + Playwright accessibility tree + a BOUNDED list
of interactive elements so the agent can act on meaning, not pixels. It is
READ-ONLY: it must never be gated and must never appear in the mutating
allowlist. Playwright is not importable in this env, so the dispatch wiring is
exercised with a fake page object exposing the handful of methods the handler
uses (``.title()``, ``.url``, ``.accessibility.snapshot()``, ``query_selector_all``).
"""
from __future__ import annotations

import json
import logging

from maverick.safety import action_gate
from maverick.tools import browser

# --- read-only: never gated ------------------------------------------------

def test_observe_is_not_a_mutating_action():
    assert "observe" not in action_gate._BROWSER_MUTATING


def test_observe_gate_and_risk_are_noop():
    # A read action: the per-action gate returns None (proceed) and the risk
    # classifier returns None (never escalates / never gated).
    assert action_gate.gate_browser_action("observe", {}) is None
    assert action_gate.browser_action_risk("observe", {}) is None


def test_observe_in_schema_enum():
    enum = browser._BROWSER_INPUT_SCHEMA["properties"]["action"]["enum"]
    assert "observe" in enum


# --- fake page so we don't need a real browser -----------------------------

class _FakeAX:
    def __init__(self, snap):
        self._snap = snap

    def snapshot(self):
        return self._snap


class _FakeEl:
    def __init__(self, *, tag="button", attrs=None, text=""):
        self._tag = tag
        self._attrs = attrs or {}
        self._text = text

    def get_attribute(self, name):
        return self._attrs.get(name)

    def inner_text(self):
        return self._text

    def evaluate(self, _expr):
        # Only used for `e => e.tagName`.
        return self._tag.upper()


class _FakePage:
    def __init__(self, *, title="Example", url="https://example.com/", ax=None, els=None):
        self._title = title
        self.url = url
        self.accessibility = _FakeAX(ax if ax is not None else {"role": "WebArea", "name": title})
        self._els = els or []

    def title(self):
        return self._title

    def query_selector_all(self, _selector):
        return self._els


def test_observe_returns_structured_snapshot():
    page = _FakePage(
        title="Login",
        url="https://example.com/login",
        ax={"role": "WebArea", "name": "Login", "children": [{"role": "button", "name": "Sign in"}]},
        els=[
            _FakeEl(tag="button", attrs={"id": "submit"}, text="Sign in"),
            _FakeEl(tag="input", attrs={"name": "user", "placeholder": "Username"}),
            _FakeEl(tag="a", attrs={"href": "/help"}, text="Help"),
        ],
    )
    out = browser._browser_observe(page)
    data = json.loads(out)

    assert data["title"] == "Login"
    assert data["url"] == "https://example.com/login"
    assert data["interactive_truncated"] is False

    els = data["interactive_elements"]
    assert len(els) == 3
    # id -> #selector hint; role falls back to tag name; name from inner_text.
    assert els[0] == {"role": "button", "name": "Sign in", "selector": "#submit"}
    # placeholder is the accessible name when there's no aria-label/text.
    assert els[1]["role"] == "input" and els[1]["name"] == "Username"
    assert els[1]["selector"] == "[name='user']"
    assert els[2]["name"] == "Help"

    # Accessibility tree round-trips as JSON text and isn't truncated here.
    assert data["accessibility_truncated"] is False
    ax = json.loads(data["accessibility_tree"])
    assert ax["role"] == "WebArea"


def test_observe_bounds_element_count_and_name_length():
    long_name = "x" * 500
    els = [_FakeEl(tag="button", attrs={"id": f"b{i}"}, text=long_name) for i in range(250)]
    page = _FakePage(els=els)
    data = json.loads(browser._browser_observe(page))

    assert len(data["interactive_elements"]) == browser._MAX_OBSERVE_ELEMENTS
    assert data["interactive_truncated"] is True
    # Each accessible name is truncated to the cap.
    assert all(len(e["name"]) <= browser._MAX_OBSERVE_NAME_LENGTH for e in data["interactive_elements"])


def test_observe_truncates_huge_accessibility_tree():
    huge = {"role": "WebArea", "name": "n", "children": [{"role": "text", "name": "y" * 1000} for _ in range(200)]}
    page = _FakePage(ax=huge)
    data = json.loads(browser._browser_observe(page))
    assert data["accessibility_truncated"] is True
    assert len(data["accessibility_tree"]) <= browser._MAX_OBSERVE_AXTREE_CHARS


def test_observe_survives_a_broken_page():
    # Accessibility snapshot raising and element query raising must not crash
    # the handler -- it degrades to an empty snapshot.
    class _Broken:
        url = "https://example.com/"

        def title(self):
            raise RuntimeError("no title")

        class accessibility:  # noqa: N801 - mimic Playwright attribute
            @staticmethod
            def snapshot():
                raise RuntimeError("boom")

        def query_selector_all(self, _s):
            raise RuntimeError("boom")

    data = json.loads(browser._browser_observe(_Broken()))
    assert data["interactive_elements"] == []
    assert data["accessibility_tree"] == ""


def test_dispatch_routes_observe_to_handler():
    page = _FakePage(title="Dispatch", url="https://example.com/d", els=[])
    out = browser._dispatch_browser_action(
        "observe", session=None, page=page, args={}, timeout=30_000, allow_hosts=(),
    )
    data = json.loads(out)
    assert data["title"] == "Dispatch" and data["url"] == "https://example.com/d"


def test_observe_and_current_url_redact_flow_decision_tokens(caplog):
    token = "eyJ" + "A" * 32 + "." + "b" * 64
    page = _FakePage(
        title=f"Review {token}",
        url=f"https://example.com/flow/approve?token={token}",
        ax={"role": "WebArea", "name": token},
        els=[_FakeEl(tag="a", attrs={"href": f"?token={token}"}, text=token)],
    )

    with caplog.at_level(logging.INFO, logger=browser.__name__):
        observed = browser._browser_observe(page)
    current = browser._dispatch_browser_action(
        "current_url", session=None, page=page, args={}, timeout=30_000,
        allow_hosts=(),
    )

    assert token not in observed + current + caplog.text
    assert "REDACTED:lightwork_flow_approval_token" in observed + current


def test_extract_text_redacts_lightwork_tokens():
    token = "lw-rest-" + "C" * 43

    class _Body:
        @staticmethod
        def inner_text():
            return f"connection capability: {token}"

    class _Page:
        @staticmethod
        def query_selector(_selector):
            return _Body()

    result = browser._browser_extract_text(_Page(), {})

    assert token not in result
    assert "REDACTED:lightwork_agent_token" in result


def test_observe_redacts_tokens_from_degraded_exception_logs(caplog):
    token = "eyJ" + "D" * 32 + "." + "e" * 64

    class _Broken:
        url = "https://example.com/"

        @staticmethod
        def title():
            return "Review"

        class accessibility:  # noqa: N801 - mimic Playwright attribute
            @staticmethod
            def snapshot():
                raise RuntimeError(f"approval failed for {token}")

        @staticmethod
        def query_selector_all(_selector):
            raise RuntimeError(f"selector failed for {token}")

    with caplog.at_level(logging.DEBUG, logger=browser.__name__):
        browser._browser_observe(_Broken())

    assert token not in caplog.text
    assert "REDACTED:lightwork_flow_approval_token" in caplog.text
