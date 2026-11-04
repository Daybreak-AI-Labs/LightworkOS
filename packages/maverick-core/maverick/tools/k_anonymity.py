"""k-anonymity / l-diversity checker for a released dataset (privacy &
data-minimization; complements the noise-adding ``differential_privacy`` /
``dp_stats`` with a *grouping*-based de-identification check).

Groups rows by their quasi-identifier values and verifies every group has at
least ``k`` records — the standard k-anonymity guarantee that no individual is
distinguishable within a group smaller than k. With a sensitive attribute it
also checks l-diversity (each group must contain at least ``l`` distinct
sensitive values), catching the homogeneity attack k-anonymity alone misses.
Pure grouping/counting — deterministic and offline.

ops:
  - check(rows, quasi_identifiers, k, [sensitive], [l])  — reports PASS/FAIL on
    k-anonymity (min group size + the offending quasi-identifier groups) and,
    when ``sensitive`` + ``l`` are given, on l-diversity.
"""
from __future__ import annotations

import json
from typing import Any

from . import Tool

_MAX_LISTED = 10
_MISSING = object()


def _value_key(value: Any) -> tuple[str, str, str]:
    """Return a hashable, sortable key that preserves JSON value identity."""
    if value is _MISSING:
        return ("missing", "", "")
    return (
        "present",
        type(value).__name__,
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
    )


def _display_value(value_key: tuple[str, str, str]) -> str:
    state, type_name, encoded = value_key
    if state == "missing":
        return "(absent)"
    if type_name == "str":
        try:
            return str(json.loads(encoded))
        except json.JSONDecodeError:
            return encoded
    return encoded


def _key_str(qis: list[str], key: tuple[tuple[str, str, str], ...]) -> str:
    return ", ".join(f"{q}={_display_value(v)}" for q, v in zip(qis, key, strict=False))


def _check(rows: list, qis: list[str], k: int, sensitive: str | None, l_min: int | None) -> str:
    groups: dict[tuple, list[dict]] = {}
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            return f"ERROR: row {i} must be an object"
        key = tuple(_value_key(row[q] if q in row else _MISSING) for q in qis)
        groups.setdefault(key, []).append(row)

    sizes = {key: len(members) for key, members in groups.items()}
    min_size = min(sizes.values())
    violating = sorted(
        (key for key, n in sizes.items() if n < k),
        key=lambda key: (sizes[key], key),
    )

    if violating:
        lines = [
            f"K-ANONYMITY FAIL: {len(violating)} of {len(groups)} groups below "
            f"k={k} (min group size {min_size}):"
        ]
        for key in violating[:_MAX_LISTED]:
            lines.append(f"  {{{_key_str(qis, key)}}} -> {sizes[key]}")
        if len(violating) > _MAX_LISTED:
            lines.append(f"  ... and {len(violating) - _MAX_LISTED} more")
    else:
        lines = [
            f"K-ANONYMITY PASS: {len(groups)} groups, all >= k={k} "
            f"(min group size {min_size})"
        ]

    if sensitive is not None:
        diversity = {
            key: {_value_key(r[sensitive] if sensitive in r else _MISSING) for r in members}
            for key, members in groups.items()
        }
        ldiv_viol = sorted(
            (key for key, vals in diversity.items() if len(vals) < l_min),
            key=lambda key: (len(diversity[key]), key),
        )
        min_div = min(len(v) for v in diversity.values())
        if ldiv_viol:
            lines.append(
                f"L-DIVERSITY FAIL: {len(ldiv_viol)} of {len(groups)} groups below "
                f"l={l_min} on {sensitive!r} (min diversity {min_div}):"
            )
            for key in ldiv_viol[:_MAX_LISTED]:
                lines.append(f"  {{{_key_str(qis, key)}}} -> {len(diversity[key])} distinct")
            if len(ldiv_viol) > _MAX_LISTED:
                lines.append(f"  ... and {len(ldiv_viol) - _MAX_LISTED} more")
        else:
            lines.append(
                f"L-DIVERSITY PASS: all groups >= l={l_min} on {sensitive!r} "
                f"(min diversity {min_div})"
            )
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    rows = args.get("rows")
    if not isinstance(rows, list) or not rows:
        return "ERROR: rows must be a non-empty array of objects"
    qis = args.get("quasi_identifiers")
    if not isinstance(qis, list) or not qis:
        return "ERROR: quasi_identifiers must be a non-empty array of field names"
    qis = [str(q) for q in qis]
    k = args.get("k")
    try:
        k = int(k)
    except (TypeError, ValueError):
        return "ERROR: k must be an integer"
    if k < 1:
        return "ERROR: k must be >= 1"

    sensitive = args.get("sensitive")
    l_min = args.get("l")
    if sensitive is not None:
        sensitive = str(sensitive)
        if l_min is None:
            return "ERROR: l is required when sensitive is given"
        try:
            l_min = int(l_min)
        except (TypeError, ValueError):
            return "ERROR: l must be an integer"
        if l_min < 1:
            return "ERROR: l must be >= 1"
    return _check(rows, qis, k, sensitive, l_min)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "rows": {"type": "array", "description": "dataset records (objects)", "items": {"type": "object"}},
        "quasi_identifiers": {
            "type": "array",
            "description": "field names that together could re-identify a record",
            "items": {"type": "string"},
        },
        "k": {"type": "integer", "description": "minimum allowed group size"},
        "sensitive": {"type": "string", "description": "optional sensitive attribute for l-diversity"},
        "l": {"type": "integer", "description": "minimum distinct sensitive values per group (with 'sensitive')"},
    },
    "required": ["rows", "quasi_identifiers", "k"],
}


def k_anonymity() -> Tool:
    return Tool(
        name="k_anonymity",
        description=(
            "Check a released dataset for k-anonymity (and optional l-diversity). "
            "op=check with 'rows', 'quasi_identifiers', 'k', and optional "
            "'sensitive'+'l'. Groups rows by quasi-identifier values and reports "
            "PASS/FAIL with the min group size and the offending groups; with a "
            "sensitive attribute, also flags groups below l distinct values. "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
