"""web_recorder: deterministic Playwright codegen from a step list."""
from __future__ import annotations

from maverick.tools.web_recorder import web_recorder


def test_codegen_emits_runnable_script():
    out = web_recorder().fn({"op": "playwright", "steps": [
        {"action": "goto", "url": "https://example.com"},
        {"action": "fill", "selector": "#q", "text": "hello"},
        {"action": "click", "selector": "button[type=submit]"},
        {"action": "wait", "selector": ".results"},
        {"action": "assert_text", "text": "Results"},
        {"action": "screenshot", "path": "out.png"},
    ]})
    assert "from playwright.sync_api import sync_playwright" in out
    assert "page.goto('https://example.com')" in out
    assert "page.fill('#q', 'hello')" in out
    assert "page.click('button[type=submit]')" in out
    assert "page.wait_for_selector('.results')" in out
    assert "assert 'Results' in page.content()" in out
    assert "page.screenshot(path='out.png')" in out
    assert "browser.close()" in out
    # The generated script must be valid Python.
    compile(out, "<gen>", "exec")


def test_headless_flag_and_wait_ms():
    out = web_recorder().fn({"op": "playwright", "headless": False,
                             "steps": [{"action": "wait", "ms": 250}]})
    assert "launch(headless=False)" in out
    assert "page.wait_for_timeout(250)" in out


def test_string_escaping_prevents_injection():
    payload = "a') ; import os # "
    out = web_recorder().fn({"op": "playwright", "steps": [
        {"action": "fill", "selector": "#x", "text": payload},
    ]})
    # The payload must appear only inside a safe Python string literal...
    assert f"page.fill('#x', {payload!r})" in out
    # ...and the whole script must still be valid (escaped, not executable).
    compile(out, "<gen>", "exec")


def test_errors():
    t = web_recorder()
    assert t.fn({"op": "playwright", "steps": []}).startswith("ERROR")
    assert t.fn({"op": "playwright", "steps": [{"action": "teleport"}]}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "web_recorder" in names
