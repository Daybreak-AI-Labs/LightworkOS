"""ARIA-first browser navigation.

Drives the shared Playwright browser session through the ACCESSIBILITY TREE
instead of pixels or raw CSS selectors:

  - ``snapshot`` distills ``page.accessibility.snapshot()`` into a compact
    role/name outline with stable node ids (``n1``, ``n2``, … assigned in
    depth-first order, so the same tree always yields the same ids);
  - ``find`` matches nodes by ARIA role and/or accessible-name substring;
  - ``activate`` clicks (or focuses) a node by id, resolving it back to the
    live page via Playwright's role+name locator (``page.get_by_role``) —
    the same query a screen reader makes.

Why: the accessibility tree is a fraction of the page's HTML, is robust to
markup/styling churn, and targets elements the way accessible apps are
*meant* to be driven. The static-HTML counterpart is ``tools/a11y_tree.py``
(extract-only, stdlib parser); this module is the live, interactive version
and shares the ``browser`` tool's persistent chromium session.

Playwright is imported lazily (inside the shared session), so this module
imports — and its tests run — without the ``browser`` extra installed.
Offline tests inject a fake page via ``_page``.

Registered alongside ``browser`` when that optional capability is enabled.
"""
from __future__ import annotations

import os
import threading
from typing import Any

from . import Tool

_MAX_NODES = 800
_MAX_FIND_HITS = 50

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["snapshot", "find", "activate"],
            "description": "snapshot the a11y tree, find nodes by role/name, or activate a node by id.",
        },
        "role": {"type": "string", "description": "ARIA role to match exactly (find)."},
        "name": {
            "type": "string",
            "description": "Accessible-name substring, case-insensitive (find).",
        },
        "node_id": {"type": "string", "description": "Node id from snapshot/find (activate)."},
        "action": {
            "type": "string",
            "enum": ["click", "focus"],
            "description": "What activate does (default click).",
        },
    },
    "required": ["op"],
}


def _page():
    """The live page from the shared browser session (lazy playwright)."""
    from .browser import _get_session
    return _get_session().page


# Keep node ids with their browser scope. A global ledger could expose one
# customer's accessible names or resolve an id against another customer's page.
_nodes: dict[tuple[str | None, str | None, int | None], dict[str, tuple[str, str]]] = {}
_nodes_lock = threading.Lock()


def _scope() -> tuple[str | None, str | None, int | None]:
    from .browser import _session_scope

    return _session_scope()


def _clear_scope(scope: tuple[str | None, str | None, int | None]) -> None:
    with _nodes_lock:
        _nodes.pop(scope, None)


def _walk(node: dict, depth: int, lines: list[str], ledger: dict[str, tuple[str, str]]) -> None:
    if len(ledger) >= _MAX_NODES:
        return
    role = str(node.get("role") or "")
    name = str(node.get("name") or "")
    nid = f"n{len(ledger) + 1}"
    ledger[nid] = (role, name)
    indent = "  " * depth
    lines.append(f"{nid} {indent}[{role}] {name!r}" if name else f"{nid} {indent}[{role}]")
    for child in node.get("children") or []:
        if isinstance(child, dict):
            _walk(child, depth + 1, lines, ledger)


def _take_snapshot(page) -> list[str]:
    """Snapshot the page's a11y tree; refresh the id ledger; return the outline."""
    tree = page.accessibility.snapshot()
    lines: list[str] = []
    ledger: dict[str, tuple[str, str]] = {}
    if isinstance(tree, dict):
        _walk(tree, 0, lines, ledger)
    with _nodes_lock:
        _nodes[_scope()] = ledger
    return lines


def _activate(page, args: dict[str, Any]) -> str:
    nid = (args.get("node_id") or "").strip()
    if not nid:
        return "ERROR: activate requires node_id (from snapshot/find)"
    with _nodes_lock:
        node = _nodes.get(_scope(), {}).get(nid)
    if node is None:
        _take_snapshot(page)  # no (or stale) ledger: refresh once and retry
        with _nodes_lock:
            node = _nodes.get(_scope(), {}).get(nid)
    if node is None:
        return f"ERROR: unknown node id {nid!r}; run op=snapshot and use an id from it"
    role, name = node
    if not role:
        return f"ERROR: node {nid} has no role; cannot build an ARIA locator"
    locator = page.get_by_role(role, name=name, exact=True) if name else page.get_by_role(role)
    count = locator.count()
    if count == 0:
        return (
            f"ERROR: no live element for {nid} ([{role}] {name!r}); "
            "the page changed — re-snapshot"
        )
    target = locator.first
    action = (args.get("action") or "click").strip().lower()
    if action == "focus":
        target.focus()
    else:
        action = "click"
        target.click()
    suffix = f" (first of {count} matches)" if count > 1 else ""
    return f"{action}: {nid} [{role}] {name!r}{suffix}"


def _run(args: dict[str, Any]) -> str:
    if os.environ.get("MAVERICK_BROWSER_DISABLE") == "1":
        return "ERROR: browser tools disabled by MAVERICK_BROWSER_DISABLE=1"
    op = args.get("op")
    try:
        page = _page()
    except ImportError as e:
        return f"ERROR: {e}"

    if op == "snapshot":
        lines = _take_snapshot(page)
        if not lines:
            return "accessibility tree is empty (is a page loaded?)"
        return "\n".join(lines)

    if op == "find":
        role = (args.get("role") or "").strip().lower()
        name = (args.get("name") or "").strip().lower()
        if not role and not name:
            return "ERROR: find requires role and/or name"
        _take_snapshot(page)  # refresh so the ids match the live page
        with _nodes_lock:
            hits = [
                f"{nid} [{r}] {n!r}"
                for nid, (r, n) in _nodes.get(_scope(), {}).items()
                if (not role or r.lower() == role) and (not name or name in n.lower())
            ]
        if not hits:
            return f"no node matches role={role!r} name~={name!r}"
        return "\n".join(hits[:_MAX_FIND_HITS])

    if op == "activate":
        return _activate(page, args)

    return f"ERROR: unknown op {op!r}"


def aria_navigate(*, managed: bool = False) -> Tool:
    """Factory: ARIA-first navigation over the shared browser session."""
    async def managed_action(args: dict[str, Any]) -> str:
        from .browser import run_on_browser_worker

        return await run_on_browser_worker(_run, args)

    return Tool(
        name="aria_navigate",
        description=(
            "Drive the browser via the accessibility tree instead of pixels or "
            "CSS: snapshot for a compact role/name outline with node ids, find "
            "to match nodes by ARIA role + accessible name, activate to click "
            "or focus a node by id. Robust to markup churn; use alongside the "
            "'browser' tool (same session)."
        ),
        input_schema=_SCHEMA,
        fn=managed_action if managed else _run,
    )


__all__ = ["aria_navigate"]
