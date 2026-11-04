"""\"What changed\" digest tool.

Turn a before/after snapshot into the human-readable summary a reviewer wants:
which keys were added, removed, or changed (with old->new values), or — for two
blobs of text — a one-line tally of the unified diff. Deterministic and offline:
dict diffing is pure set/compare logic; text diffing uses ``difflib``.

ops:
  - diff(before, after)            — key-level digest of two flat objects.
  - diff_text(before_str, after_str) — unified-diff summary (+/- line counts).
"""
from __future__ import annotations

import difflib
from typing import Any

from . import Tool


def _fmt(v: Any) -> str:
    """Compact, stable rendering of a scalar/collection value for the digest."""
    if isinstance(v, str):
        return v
    return repr(v)


def _diff_dicts(before: dict, after: dict) -> str:
    bkeys = set(before)
    akeys = set(after)
    added = sorted(akeys - bkeys)
    removed = sorted(bkeys - akeys)
    changed = sorted(
        k for k in (bkeys & akeys) if before[k] != after[k]
    )

    if not (added or removed or changed):
        return "NO CHANGES: before and after are identical"

    lines = [
        f"CHANGED: +{len(added)} added, -{len(removed)} removed, "
        f"~{len(changed)} changed"
    ]
    for k in added:
        lines.append(f"+ {k}: {_fmt(after[k])}")
    for k in removed:
        lines.append(f"- {k}: {_fmt(before[k])}")
    for k in changed:
        lines.append(f"~ {k}: {_fmt(before[k])} -> {_fmt(after[k])}")
    return "\n".join(lines)


def _diff_text(before: str, after: str) -> str:
    b_lines = before.splitlines()
    a_lines = after.splitlines()
    diff = list(
        difflib.unified_diff(b_lines, a_lines, lineterm="")
    )
    # Count body +/- lines, excluding the +++/--- file headers.
    added = sum(
        1 for ln in diff if ln.startswith("+") and not ln.startswith("+++")
    )
    removed = sum(
        1 for ln in diff if ln.startswith("-") and not ln.startswith("---")
    )
    if added == 0 and removed == 0:
        return "NO CHANGES: text is identical"
    return f"CHANGED: +{added} line(s) added, -{removed} line(s) removed"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op in (None, "diff"):
        before = args.get("before")
        after = args.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            return "ERROR: diff needs 'before' and 'after' objects (key:value maps)"
        return _diff_dicts(before, after)
    if op == "diff_text":
        before = args.get("before_str")
        after = args.get("after_str")
        if not isinstance(before, str) or not isinstance(after, str):
            return "ERROR: diff_text needs 'before_str' and 'after_str' strings"
        return _diff_text(before, after)
    return f"ERROR: unknown op {op!r}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["diff", "diff_text"]},
        "before": {"type": "object", "description": "prior state, a {key: value} map"},
        "after": {"type": "object", "description": "new state, a {key: value} map"},
        "before_str": {"type": "string", "description": "prior text (for diff_text)"},
        "after_str": {"type": "string", "description": "new text (for diff_text)"},
    },
}


def whats_changed() -> Tool:
    return Tool(
        name="whats_changed",
        description=(
            "Human-readable 'what changed' digest. op=diff with 'before' and "
            "'after' objects returns added/removed/changed keys with old->new "
            "values. op=diff_text with 'before_str'/'after_str' returns a "
            "unified-diff summary (counts of +/- lines). Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
