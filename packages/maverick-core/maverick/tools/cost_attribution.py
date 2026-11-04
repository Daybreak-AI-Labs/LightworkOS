"""Cost-attribution API.

Aggregate a flat list of cost line-items along one or more dimensions
(principal / tenant / tool / tag / model) into a ranked breakdown with each
dimension's share of total spend. Deterministic and offline — the reporting
half that turns the usage ledger into a "who/what spent it" answer.

ops:
  - report(items, [by], [top])  — items: [{cost, principal?, tool?, tag?, ...}].
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from . import Tool

_DIMS = ("principal", "tenant", "tool", "tag", "model", "role")


def _report(items: list[dict], by: list[str], top: int) -> str:
    total = 0.0
    for it in items:
        if not isinstance(it, dict):
            return "ERROR: each item must be an object {cost, ...dims}"
        try:
            total += float(it.get("cost", 0) or 0)
        except (TypeError, ValueError):
            return "ERROR: every item needs a numeric 'cost'"
    if total <= 0:
        return "OK total=$0.0000 — nothing to attribute"

    blocks: list[str] = [f"total=${total:.4f} over {len(items)} item(s)"]
    for dim in by:
        sums: defaultdict[str, float] = defaultdict(float)
        for it in items:
            key = str(it.get(dim, "(unattributed)"))
            sums[key] += float(it.get("cost", 0) or 0)
        ranked = sorted(sums.items(), key=lambda kv: kv[1], reverse=True)[:top]
        lines = [f"    {k}: ${v:.4f} ({v / total:.1%})" for k, v in ranked]
        blocks.append(f"by {dim}:\n" + "\n".join(lines))
    return "OK " + "\n".join(blocks)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "report"):
        return f"ERROR: unknown op {args.get('op')!r}"
    items = args.get("items")
    if not isinstance(items, list) or not items:
        return "ERROR: items (list of {cost, ...dims}) is required"
    by = args.get("by") or ["principal"]
    if not isinstance(by, list):
        return "ERROR: by must be a list of dimension names"
    bad = [d for d in by if d not in _DIMS]
    if bad:
        return f"ERROR: unknown dimension(s) {bad}; choose from {list(_DIMS)}"
    try:
        top = int(args.get("top", 10))
    except (TypeError, ValueError, OverflowError):
        return "ERROR: top must be an integer"
    return _report(items, by, max(1, top))


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["report"]},
        "items": {
            "type": "array",
            "description": "Cost line-items: {cost, principal?, tenant?, tool?, tag?, model?, role?}",
            "items": {"type": "object"},
        },
        "by": {
            "type": "array",
            "description": f"Dimensions to break down by; any of {list(_DIMS)}",
            "items": {"type": "string"},
        },
        "top": {"type": "integer", "description": "Rows per dimension (default 10)"},
    },
    "required": ["items"],
}


def cost_attribution() -> Tool:
    return Tool(
        name="cost_attribution",
        description=(
            "Attribute spend across dimensions. op=report with 'items' "
            "([{cost, principal?, tenant?, tool?, tag?, model?, role?}]), "
            "optional 'by' (default [principal]) and 'top'. Returns total + a "
            "ranked per-dimension breakdown with shares. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
