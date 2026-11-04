"""Web automation recorder/codegen tool.

Turns a high-level list of browser steps into a runnable **Playwright** script
(sync API). It's the "recorder" half done as codegen: describe the flow once
(goto / click / fill / press / wait / assert_text / select / screenshot) and get
a deterministic, reviewable script you can save, diff, and re-run — no live
browser or driver needed to produce it.

ops:
  - playwright(steps[, headless])  — emit a Python Playwright script.

Each step is ``{action, ...}``. Selectors and text are escaped into safe Python
string literals.
"""
from __future__ import annotations

from typing import Any

from . import Tool

_INDENT = "        "  # inside `with sync_playwright()` + page block


def _lit(s: Any) -> str:
    """A safe single-quoted Python string literal."""
    return repr("" if s is None else str(s))


def _step_line(step: dict) -> str | None:
    action = (step.get("action") or "").lower()
    if action == "goto":
        return f"page.goto({_lit(step.get('url'))})"
    if action == "click":
        return f"page.click({_lit(step.get('selector'))})"
    if action == "fill":
        return f"page.fill({_lit(step.get('selector'))}, {_lit(step.get('text'))})"
    if action == "type":
        return f"page.type({_lit(step.get('selector'))}, {_lit(step.get('text'))})"
    if action == "press":
        return f"page.press({_lit(step.get('selector'))}, {_lit(step.get('key'))})"
    if action == "select":
        return f"page.select_option({_lit(step.get('selector'))}, {_lit(step.get('value'))})"
    if action == "wait":
        if step.get("selector"):
            return f"page.wait_for_selector({_lit(step.get('selector'))})"
        try:
            ms = int(step.get("ms", 1000))
        except (TypeError, ValueError):
            ms = 1000
        return f"page.wait_for_timeout({ms})"
    if action == "assert_text":
        return f"assert {_lit(step.get('text'))} in page.content()"
    if action == "screenshot":
        return f"page.screenshot(path={_lit(step.get('path') or 'shot.png')})"
    return None


def _codegen(steps: list[dict], headless: bool) -> tuple[str, list[str]]:
    body: list[str] = []
    errors: list[str] = []
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            errors.append(f"step {i}: not an object")
            continue
        line = _step_line(step)
        if line is None:
            errors.append(f"step {i}: unknown action {step.get('action')!r}")
            continue
        body.append(_INDENT + line)
    script = (
        "from playwright.sync_api import sync_playwright\n\n"
        "with sync_playwright() as p:\n"
        f"    browser = p.chromium.launch(headless={bool(headless)})\n"
        "    page = browser.new_page()\n"
        "    try:\n"
        + ("\n".join(body) if body else _INDENT + "pass") + "\n"
        "    finally:\n"
        "        browser.close()\n"
    )
    return script, errors


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "playwright"):
        return f"ERROR: unknown op {args.get('op')!r}"
    steps = args.get("steps")
    if not isinstance(steps, list) or not steps:
        return "ERROR: steps must be a non-empty array of {action, ...}"
    script, errors = _codegen(steps, bool(args.get("headless", True)))
    if errors:
        return "ERROR: " + "; ".join(errors)
    return script


_ACTIONS = ["goto", "click", "fill", "type", "press", "select", "wait",
            "assert_text", "screenshot"]

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["playwright"]},
        "steps": {
            "type": "array",
            "description": "ordered browser steps",
            "items": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": _ACTIONS},
                    "url": {"type": "string"}, "selector": {"type": "string"},
                    "text": {"type": "string"}, "key": {"type": "string"},
                    "value": {"type": "string"}, "ms": {"type": "integer"},
                    "path": {"type": "string"},
                },
                "required": ["action"],
            },
        },
        "headless": {"type": "boolean", "description": "launch headless (default true)"},
    },
    "required": ["steps"],
}


def web_recorder() -> Tool:
    return Tool(
        name="web_recorder",
        description=(
            "Generate a runnable Playwright (sync) script from a list of browser "
            "steps: goto, click, fill, type, press, select, wait, assert_text, "
            "screenshot. op=playwright with 'steps' (each {action, ...}). "
            "Deterministic codegen with escaped literals; no live browser needed "
            "to produce the script."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
