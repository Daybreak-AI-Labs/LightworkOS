"""Tool-output cache admin tool.

An operator-facing surface over the tool-output cache (``tool_cache``): inspect
hit/miss/size, or purge entries — all of them, or just one tool's — when its
underlying data has changed and a stale memoized result would mislead.

ops:
  - stats          — hits / misses / size + hit-rate.
  - purge[tool]    — drop all cached entries, or only those for ``tool``;
                     returns how many were removed.
"""
from __future__ import annotations

from typing import Any

from ..cache import tool as tool_cache
from . import Tool


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "stats":
        s = tool_cache.stats()
        total = s["hits"] + s["misses"]
        rate = (s["hits"] / total * 100) if total else 0.0
        state = "on" if tool_cache.enabled() else "off"
        return (
            f"cache: {state}\nsize: {s['size']}\nhits: {s['hits']}\n"
            f"misses: {s['misses']}\nhit_rate: {rate:.1f}%"
        )
    if op == "purge":
        tool = str(args.get("tool") or "").strip() or None
        removed = tool_cache.purge(tool)
        scope = f" for {tool!r}" if tool else ""
        return f"purged {removed} cached entr{'y' if removed == 1 else 'ies'}{scope}"
    return f"ERROR: unknown op {op!r} (expected stats|purge)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["stats", "purge"]},
        "tool": {"type": "string", "description": "purge only this tool's entries (op=purge)"},
    },
    "required": ["op"],
}


def cache_admin() -> Tool:
    return Tool(
        name="cache_admin",
        description=(
            "Inspect or purge the tool-output cache. ops: stats (hits/misses/"
            "size/hit-rate), purge (drop all cached entries, or pass 'tool' to "
            "drop only that tool's — e.g. after its underlying data changed)."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=False,  # purge mutates shared cache state
    )
