"""Diff-to-expected comparator.

Compare an actual value against an expected value and report MATCH or DIFF with
a precise description of the first/all mismatches. Deterministic and offline:
the caller supplies both values and a comparison mode; this resolves the verdict.

modes:
  - exact      — strict equality of the (stringified) values.
  - json       — parse both as JSON and deep-diff (keys added/removed/changed).
  - numeric    — compare as numbers (default abs tolerance 0 = exact).
  - tolerance  — alias of numeric with an explicit ``tol`` (abs or rel).

For numeric/tolerance, ``tol`` is the allowed absolute difference; if ``rel``
is true, ``tol`` is a relative fraction of ``|expected|``.

ops:
  - compare(actual, expected[, mode][, tol][, rel])
"""
from __future__ import annotations

import json
from typing import Any

from . import Tool


def _to_number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _diff_numeric(actual: Any, expected: Any, tol: float, rel: bool) -> str:
    a = _to_number(actual)
    e = _to_number(expected)
    if a is None or e is None:
        return f"DIFF: not numeric (actual={actual!r}, expected={expected!r})"
    delta = abs(a - e)
    allowed = abs(e) * tol if rel else tol
    kind = "rel" if rel else "abs"
    if delta <= allowed:
        return f"MATCH: |{a:g} - {e:g}| = {delta:g} <= {allowed:g} ({kind} tol)"
    return f"DIFF: |{a:g} - {e:g}| = {delta:g} > {allowed:g} ({kind} tol)"


def _deep_diff(actual: Any, expected: Any, path: str = "$") -> list[str]:
    """Recursively collect human-readable differences between two JSON values."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        diffs: list[str] = []
        for key in expected:
            if key not in actual:
                diffs.append(f"{path}.{key}: missing (expected {expected[key]!r})")
            else:
                diffs.extend(_deep_diff(actual[key], expected[key], f"{path}.{key}"))
        for key in actual:
            if key not in expected:
                diffs.append(f"{path}.{key}: unexpected (got {actual[key]!r})")
        return diffs
    if isinstance(expected, list) and isinstance(actual, list):
        diffs = []
        if len(actual) != len(expected):
            diffs.append(f"{path}: length {len(actual)} != expected {len(expected)}")
        for i in range(min(len(actual), len(expected))):
            diffs.extend(_deep_diff(actual[i], expected[i], f"{path}[{i}]"))
        return diffs
    if actual != expected:
        return [f"{path}: {actual!r} != expected {expected!r}"]
    return []


def _diff_json(actual: Any, expected: Any) -> str:
    def _coerce(v: Any) -> Any:
        if isinstance(v, str):
            try:
                return json.loads(v)
            except (json.JSONDecodeError, ValueError, RecursionError):
                return v
        return v

    # Both parsing (json.loads) and the deep-diff walk recurse, so a hostile
    # deeply-nested value can blow the stack; surface it as a DIFF rather than
    # letting RecursionError escape the "returns MATCH or DIFF" contract.
    try:
        diffs = _deep_diff(_coerce(actual), _coerce(expected))
    except RecursionError:
        return "DIFF: values too deeply nested to compare"
    if not diffs:
        return "MATCH: JSON structures are equal"
    return "DIFF:\n" + "\n".join(f"- {d}" for d in diffs)


def _diff_exact(actual: Any, expected: Any) -> str:
    if str(actual) == str(expected):
        return "MATCH: exact"
    return f"DIFF: {actual!r} != expected {expected!r}"


def _compare(args: dict[str, Any]) -> str:
    mode = str(args.get("mode") or "exact").strip().lower()
    actual = args.get("actual")
    expected = args.get("expected")
    if mode == "exact":
        return _diff_exact(actual, expected)
    if mode == "json":
        return _diff_json(actual, expected)
    if mode in ("numeric", "tolerance"):
        tol = _to_number(args.get("tol"))
        if tol is None:
            tol = 0.0
        return _diff_numeric(actual, expected, abs(tol), bool(args.get("rel", False)))
    return f"ERROR: unknown mode {mode!r}"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "compare"):
        return f"ERROR: unknown op {args.get('op')!r}"
    if "actual" not in args or "expected" not in args:
        return "ERROR: both 'actual' and 'expected' are required"
    return _compare(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["compare"]},
        "actual": {"description": "the value produced"},
        "expected": {"description": "the value expected"},
        "mode": {"type": "string", "enum": ["exact", "json", "numeric", "tolerance"]},
        "tol": {"type": "number", "description": "allowed difference for numeric/tolerance"},
        "rel": {"type": "boolean", "description": "treat tol as a relative fraction of |expected|"},
    },
    "required": ["actual", "expected"],
}


def diff_to_expected() -> Tool:
    return Tool(
        name="diff_to_expected",
        description=(
            "Compare an actual value to an expected value. op=compare with "
            "'actual', 'expected', and 'mode' (exact|json|numeric|tolerance). "
            "json deep-diffs nested structures; numeric/tolerance compare as "
            "numbers within 'tol' (set 'rel' for a relative tolerance). Returns "
            "MATCH or DIFF with a precise description. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
