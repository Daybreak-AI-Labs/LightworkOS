"""Apple Shortcuts integration.

Build the ``shortcuts://`` URLs that launch an Apple Shortcut from Lightwork on
macOS/iOS — both the plain ``run-shortcut`` form and the ``x-callback-url`` form
that names a success URL to return to. This only constructs the URL (correctly
percent-encoded); opening it is a separate, deliberate step. Deterministic;
offline; pure stdlib (urllib). No disk, no network.

ops:
  - run_url(name, input?)            -> shortcuts://run-shortcut?name=...&input=...
  - xcallback(name, input?, x_success?) -> shortcuts://x-callback-url/run-shortcut?...
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlencode

from . import Tool


def _run_url(args: dict[str, Any]) -> str:
    name = args.get("name")
    if not isinstance(name, str) or not name.strip():
        return "ERROR: name is required"
    params: list[tuple[str, str]] = [("name", name.strip())]
    text = args.get("input")
    if isinstance(text, str) and text != "":
        params.append(("input", text))
    return "shortcuts://run-shortcut?" + urlencode(params, quote_via=quote)


def _xcallback(args: dict[str, Any]) -> str:
    name = args.get("name")
    if not isinstance(name, str) or not name.strip():
        return "ERROR: name is required"
    params: list[tuple[str, str]] = [("name", name.strip())]
    text = args.get("input")
    if isinstance(text, str) and text != "":
        params.append(("input", text))
    success = args.get("x_success")
    if isinstance(success, str) and success.strip():
        params.append(("x-success", success.strip()))
    return (
        "shortcuts://x-callback-url/run-shortcut?"
        + urlencode(params, quote_via=quote)
    )


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "run_url":
        return _run_url(args)
    if op == "xcallback":
        return _xcallback(args)
    return f"ERROR: unknown op {op!r} (expected run_url or xcallback)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["run_url", "xcallback"]},
        "name": {"type": "string", "description": "the Shortcut's name"},
        "input": {"type": "string", "description": "text passed as the shortcut input (optional)"},
        "x_success": {"type": "string", "description": "x-callback success URL for op=xcallback (optional)"},
    },
    "required": ["op", "name"],
}


def apple_shortcuts() -> Tool:
    return Tool(
        name="apple_shortcuts",
        description=(
            "Build Apple Shortcuts launch URLs (does not open them). "
            "op=run_url {name, input?} -> shortcuts://run-shortcut?name=...&input=...; "
            "op=xcallback {name, input?, x_success?} -> "
            "shortcuts://x-callback-url/run-shortcut?... . Names/inputs are "
            "percent-encoded. Deterministic; offline; stdlib urllib only."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
