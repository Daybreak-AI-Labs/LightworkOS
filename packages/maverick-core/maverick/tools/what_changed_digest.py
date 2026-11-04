"""\"What changed\" digest.

Given two snapshots of the same structured state — two runs' metrics, two
config dumps, a before/after of any flat key→value map — produce a compact,
human-readable digest of what was added, removed, and changed. The UX layer
uses it for the "what changed since you last looked" summary; deterministic
so the same pair always renders the same digest.

ops:
  - diff(before, after[, numeric_delta])  — both flat objects. Reports added /
    removed / changed keys; with numeric_delta=true, changed numbers show the
    signed delta.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _fmt(v: Any) -> str:
    if isinstance(v, float):
        return f"{v:g}"
    return str(v)


def _diff(args: dict[str, Any]) -> str:
    before = args.get("before")
    after = args.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return "ERROR: before and after must both be objects (key->value maps)"
    numeric_delta = bool(args.get("numeric_delta", False))

    bkeys, akeys = set(before), set(after)
    added = sorted(akeys - bkeys)
    removed = sorted(bkeys - akeys)
    changed = sorted(k for k in bkeys & akeys if before[k] != after[k])

    lines: list[str] = []
    if added:
        lines.append("added:")
        lines.extend(f"  + {k} = {_fmt(after[k])}" for k in added)
    if removed:
        lines.append("removed:")
        lines.extend(f"  - {k} (was {_fmt(before[k])})" for k in removed)
    if changed:
        lines.append("changed:")
        for k in changed:
            ov, nv = before[k], after[k]
            suffix = ""
            if numeric_delta and _is_num(ov) and _is_num(nv):
                d = float(nv) - float(ov)
                suffix = f"  ({'+' if d >= 0 else ''}{d:g})"
            lines.append(f"  ~ {k}: {_fmt(ov)} -> {_fmt(nv)}{suffix}")

    if not lines:
        return "no changes"
    summary = f"{len(added)} added, {len(removed)} removed, {len(changed)} changed"
    return summary + "\n" + "\n".join(lines)


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op", "diff")
    if op != "diff":
        return f"ERROR: unknown op {op!r}"
    return _diff(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["diff"]},
        "before": {"type": "object", "description": "earlier snapshot (flat key->value)"},
        "after": {"type": "object", "description": "later snapshot (flat key->value)"},
        "numeric_delta": {"type": "boolean", "description": "show signed delta for changed numbers"},
    },
    "required": ["before", "after"],
}


def what_changed_digest() -> Tool:
    return Tool(
        name="what_changed_digest",
        description=(
            "Summarise what changed between two snapshots. op=diff with "
            "'before' and 'after' (flat key->value objects) reports added / "
            "removed / changed keys; numeric_delta=true adds signed deltas for "
            "changed numbers. Deterministic; no model."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
