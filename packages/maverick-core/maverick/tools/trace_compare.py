"""Comparative replay — trace diff.

Two runs of the same goal should follow the same shape; when they don't, the
interesting thing is *where they first diverged*. This tool aligns two replay
traces (the ``{seq, t, kind, ...}`` event lists from ``replay_trace``) step by
step and reports the first divergence, the matched-prefix length, and the
per-step differences — the data behind a side-by-side replay view.

Deterministic; compares structure, ignores timestamps (``t``) by default.

ops:
  - compare(a, b[, key])  — a/b: event lists. 'key' (default "kind") is the
    field compared per step. Reports divergence point + step diffs.
"""
from __future__ import annotations

from typing import Any

from . import Tool

_IGNORE = {"t", "seq"}  # wall-clock + sequence are not semantic differences


def _step_repr(ev: dict[str, Any], key: str) -> str:
    return str(ev.get(key, "")) if isinstance(ev, dict) else str(ev)


def _fields_diff(a: dict[str, Any], b: dict[str, Any]) -> list[str]:
    keys = sorted((set(a) | set(b)) - _IGNORE)
    out = []
    for k in keys:
        if a.get(k) != b.get(k):
            out.append(f"{k}: {a.get(k)!r} != {b.get(k)!r}")
    return out


def _compare(args: dict[str, Any]) -> str:
    a = args.get("a")
    b = args.get("b")
    if not isinstance(a, list) or not isinstance(b, list):
        return "ERROR: a and b must both be arrays of trace events"
    key = str(args.get("key", "kind"))

    n = max(len(a), len(b))
    matched = 0
    diverge_at: int | None = None
    diffs: list[str] = []
    for i in range(n):
        ea = a[i] if i < len(a) else None
        eb = b[i] if i < len(b) else None
        if ea is None or eb is None:
            diverge_at = i if diverge_at is None else diverge_at
            which = "a" if ea is None else "b"
            other = eb if ea is None else ea
            diffs.append(f"[{i}] only in {'b' if which == 'a' else 'a'}: {_step_repr(other, key)}")
            continue
        if not isinstance(ea, dict) or not isinstance(eb, dict):
            same = ea == eb
        else:
            same = _step_repr(ea, key) == _step_repr(eb, key) and not _fields_diff(ea, eb)
        if same:
            matched += 1
        else:
            if diverge_at is None:
                diverge_at = i
            ka, kb = _step_repr(ea, key), _step_repr(eb, key)
            if ka != kb:
                diffs.append(f"[{i}] {key}: {ka!r} != {kb!r}")
            else:
                for d in _fields_diff(ea, eb):
                    diffs.append(f"[{i}] {ka}: {d}")

    lines = [
        f"a-steps: {len(a)}  b-steps: {len(b)}",
        f"matched: {matched}/{n}",
        f"diverge-at: {diverge_at if diverge_at is not None else 'none (identical shape)'}",
    ]
    if diffs:
        lines.append("differences:")
        lines.extend(f"  {d}" for d in diffs[:20])
        if len(diffs) > 20:
            lines.append(f"  ... and {len(diffs) - 20} more")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op", "compare")
    if op != "compare":
        return f"ERROR: unknown op {op!r}"
    return _compare(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["compare"]},
        "a": {"type": "array", "description": "first trace's event list ({seq,t,kind,...})"},
        "b": {"type": "array", "description": "second trace's event list"},
        "key": {"type": "string", "description": "event field compared per step (default 'kind')"},
    },
    "required": ["a", "b"],
}


def trace_compare() -> Tool:
    return Tool(
        name="trace_compare",
        description=(
            "Diff two replay traces step by step. op=compare with 'a' and 'b' "
            "(event lists from replay_trace) reports the first divergence index, "
            "matched-prefix length, and per-step field differences. Ignores "
            "wall-clock 't'. Deterministic; no model."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
