"""Right-to-explanation + right-to-rectification record builder.

Two pure helpers for the GDPR-style "right to an explanation" (Art. 22) and
"right to rectification" (Art. 16) of an automated decision:

  - explain(decision, factors) — rank the contributing factors by absolute
    weight and render a human-readable explanation of which ones drove the
    decision and in which direction.
  - rectify(record, corrections) — apply field corrections to a record and
    emit an audit note listing exactly what changed (old -> new).

Deterministic and offline. ``factors`` is a list of ``{name, weight, value}``;
``record`` and ``corrections`` are flat objects.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _explain(decision: str, factors: list[dict]) -> str:
    parsed: list[tuple[str, float, Any]] = []
    for f in factors:
        if not isinstance(f, dict):
            return "ERROR: each factors[] entry must be an object {name, weight, value}"
        name = str(f.get("name") or "").strip()
        if not name:
            return "ERROR: each factors[] entry needs a non-empty 'name'"
        try:
            weight = float(f.get("weight"))
        except (TypeError, ValueError):
            return f"ERROR: factor {name!r} has a non-numeric weight"
        parsed.append((name, weight, f.get("value")))

    # Rank by descending absolute influence; ties keep input order (stable sort).
    ranked = sorted(parsed, key=lambda t: -abs(t[1]))
    lines = [f"decision: {decision}", "explanation (factors ranked by influence):"]
    for i, (name, weight, value) in enumerate(ranked, 1):
        direction = "increased" if weight > 0 else "decreased" if weight < 0 else "no effect on"
        val = "" if value is None else f" (value={value})"
        lines.append(f"{i}. {name}{val}: weight {weight:+g} — {direction} the outcome")
    return "\n".join(lines)


def _rectify(record: dict, corrections: dict) -> str:
    if not corrections:
        return "ERROR: corrections must be a non-empty object"
    updated = dict(record)
    changes: list[str] = []
    for key, new in corrections.items():
        old = record.get(key, "<absent>")
        updated[key] = new
        if old != new:
            changes.append(f"- {key}: {old!r} -> {new!r}")

    lines = ["corrected record:"]
    for k in sorted(updated):
        lines.append(f"- {k}: {updated[k]!r}")
    lines.append("audit note:")
    if changes:
        lines.extend(changes)
    else:
        lines.append("- no fields changed (corrections matched existing values)")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op not in (None, "explain", "rectify"):
        return f"ERROR: unknown op {op!r} (expected explain or rectify)"
    if op == "rectify":
        record = args.get("record")
        corrections = args.get("corrections")
        if not isinstance(record, dict):
            return "ERROR: record (object) is required for op=rectify"
        if not isinstance(corrections, dict) or not corrections:
            return "ERROR: corrections (non-empty object) is required for op=rectify"
        return _rectify(record, corrections)
    # explain (default)
    decision = args.get("decision")
    factors = args.get("factors")
    if not isinstance(decision, str) or not decision.strip():
        return "ERROR: decision (string) is required for op=explain"
    if not isinstance(factors, list) or not factors:
        return "ERROR: factors (non-empty array of {name, weight, value}) is required"
    return _explain(decision, factors)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["explain", "rectify"]},
        "decision": {"type": "string", "description": "the decision to explain (op=explain)"},
        "factors": {
            "type": "array",
            "description": "contributing factors; each {name, weight, value} (op=explain)",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "weight": {"type": "number"},
                    "value": {},
                },
                "required": ["name", "weight"],
            },
        },
        "record": {"type": "object", "description": "record to correct (op=rectify)"},
        "corrections": {"type": "object", "description": "field -> new value (op=rectify)"},
    },
}


def right_to_explanation() -> Tool:
    return Tool(
        name="right_to_explanation",
        description=(
            "Build automated-decision transparency records. "
            "op=explain(decision, factors=[{name,weight,value}]) ranks factors "
            "by absolute weight into a human-readable explanation of what drove "
            "the decision. op=rectify(record, corrections) returns the corrected "
            "record plus an audit note of every old->new change. Pure, "
            "deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
