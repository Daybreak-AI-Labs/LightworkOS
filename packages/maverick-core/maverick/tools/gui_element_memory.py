"""GUI element memory.

Computer-use and browser automation waste turns re-finding the same controls.
This is the bookkeeping half: a deterministic store of element locators keyed
by (app, screen, name), so a later step can recall "the Submit button on the
checkout screen" without re-scanning the UI. The caller owns persistence — it
passes the current memory in and gets the updated memory back — so this stays
offline and stateless, mirroring the other *_memory tools.

ops:
  - put(memory, app, screen, name, selector[, bbox])  — upsert a locator.
  - get(memory, app, screen, name)                    — recall one locator.
  - list(memory[, app, screen])                       — list known locators.
"""
from __future__ import annotations

import json
from typing import Any

from . import Tool


def _as_entries(memory: Any) -> tuple[list[dict[str, Any]] | None, str]:
    if memory in (None, ""):
        return [], ""
    if isinstance(memory, list):
        for e in memory:
            if not isinstance(e, dict):
                return None, "ERROR: memory entries must be objects"
        return list(memory), ""
    return None, "ERROR: memory must be an array of locator entries (or omitted)"


def _key(e: dict[str, Any]) -> tuple[str, str, str]:
    return (str(e.get("app", "")), str(e.get("screen", "")), str(e.get("name", "")))


def _put(args: dict[str, Any]) -> str:
    entries, err = _as_entries(args.get("memory"))
    if err:
        return err
    assert entries is not None
    for req in ("app", "screen", "name", "selector"):
        if not args.get(req):
            return f"ERROR: {req} is required for put"
    new = {
        "app": str(args["app"]),
        "screen": str(args["screen"]),
        "name": str(args["name"]),
        "selector": str(args["selector"]),
    }
    if "bbox" in args:
        new["bbox"] = args["bbox"]
    out = [e for e in entries if _key(e) != _key(new)]
    out.append(new)
    out.sort(key=_key)
    return json.dumps(out, ensure_ascii=False)


def _get(args: dict[str, Any]) -> str:
    entries, err = _as_entries(args.get("memory"))
    if err:
        return err
    assert entries is not None
    want = (str(args.get("app", "")), str(args.get("screen", "")), str(args.get("name", "")))
    for e in entries:
        if _key(e) == want:
            return json.dumps(e, ensure_ascii=False)
    return "NOT FOUND"


def _list(args: dict[str, Any]) -> str:
    entries, err = _as_entries(args.get("memory"))
    if err:
        return err
    assert entries is not None
    app = args.get("app")
    screen = args.get("screen")
    rows = [
        e for e in entries
        if (app is None or str(e.get("app", "")) == str(app))
        and (screen is None or str(e.get("screen", "")) == str(screen))
    ]
    rows.sort(key=_key)
    if not rows:
        return "(empty)"
    return "\n".join(f"{_key(e)[0]}/{_key(e)[1]}/{_key(e)[2]}: {e.get('selector', '')}" for e in rows)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "put":
        return _put(args)
    if op == "get":
        return _get(args)
    if op == "list":
        return _list(args)
    return f"ERROR: unknown op {op!r} (expected put/get/list)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["put", "get", "list"]},
        "memory": {"type": "array", "description": "current locator store (array of entries); omit for empty"},
        "app": {"type": "string"},
        "screen": {"type": "string"},
        "name": {"type": "string"},
        "selector": {"type": "string", "description": "the locator (CSS/xpath/accessibility id)"},
        "bbox": {"description": "optional bounding box [x, y, w, h]"},
    },
    "required": ["op"],
}


def gui_element_memory() -> Tool:
    return Tool(
        name="gui_element_memory",
        description=(
            "Remember GUI element locators across steps, offline. op=put upserts "
            "a locator keyed by (app, screen, name) and returns the updated store; "
            "op=get recalls one (or NOT FOUND); op=list lists known locators, "
            "optionally filtered by app/screen. The caller persists the returned "
            "store. Deterministic; no UI scan."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
