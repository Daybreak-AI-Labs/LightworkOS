"""Right-to-rectification applier.

GDPR Art. 16 lets a data subject have inaccurate personal data corrected and
incomplete data completed. ``audit/erase.py`` already covers Art. 17 erasure;
this is the rectification counterpart: validate a set of requested field changes
against a mutability policy and produce the corrected record plus an auditable
diff. Immutable fields (ids, keys) are rejected, no-op changes are dropped, and
adding brand-new fields is gated. Pure dict work — deterministic and offline.

ops:
  - apply(record, changes, [immutable], [allow_new])  — ``record`` and
    ``changes`` are objects. Reports APPLIED / PARTIAL / REJECTED, the accepted
    changes (field: old -> new), any rejected ones with a reason, and the
    corrected record as JSON. ``immutable`` is a list of un-rectifiable fields;
    ``allow_new`` (default false) permits completing fields absent from
    ``record``.
"""
from __future__ import annotations

import json
from typing import Any

from . import Tool


def _apply(record: dict, changes: dict, immutable: set, allow_new: bool) -> str:
    corrected = dict(record)
    applied: list[str] = []
    rejected: list[str] = []

    for field in sorted(changes):
        new = changes[field]
        if field in immutable:
            rejected.append(f"{field}: immutable")
            continue
        if field not in record and not allow_new:
            rejected.append(f"{field}: not in record (set allow_new to complete it)")
            continue
        old = record.get(field, "(absent)")
        if field in record and old == new:
            rejected.append(f"{field}: unchanged")
            continue
        corrected[field] = new
        applied.append(f"{field}: {old!r} -> {new!r}")

    if applied and rejected:
        verdict = "PARTIAL"
    elif applied:
        verdict = "APPLIED"
    else:
        verdict = "REJECTED"

    lines = [f"{verdict}: {len(applied)} applied, {len(rejected)} rejected"]
    if applied:
        lines.append("changes:")
        lines.extend(f"  {a}" for a in applied)
    if rejected:
        lines.append("rejected:")
        lines.extend(f"  {r}" for r in rejected)
    lines.append("corrected record: " + json.dumps(corrected, sort_keys=True, default=str))
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "apply"):
        return f"ERROR: unknown op {args.get('op')!r}"
    record = args.get("record")
    changes = args.get("changes")
    if not isinstance(record, dict):
        return "ERROR: record must be an object"
    if not isinstance(changes, dict) or not changes:
        return "ERROR: changes must be a non-empty object"
    immutable = args.get("immutable", [])
    if not isinstance(immutable, list):
        return "ERROR: immutable must be an array of field names"
    allow_new = bool(args.get("allow_new", False))
    return _apply(record, changes, {str(f) for f in immutable}, allow_new)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["apply"]},
        "record": {"type": "object", "description": "the current record {field: value}"},
        "changes": {"type": "object", "description": "requested corrections {field: new_value}"},
        "immutable": {
            "type": "array",
            "description": "fields that may not be rectified (e.g. id, keys)",
            "items": {"type": "string"},
        },
        "allow_new": {
            "type": "boolean",
            "description": "allow completing fields absent from record (default false)",
        },
    },
    "required": ["record", "changes"],
}


def rectification() -> Tool:
    return Tool(
        name="rectification",
        description=(
            "Apply a right-to-rectification (GDPR Art. 16) request: validate "
            "requested field corrections against a mutability policy. op=apply "
            "with 'record', 'changes', optional 'immutable' (un-rectifiable "
            "fields) and 'allow_new' (complete absent fields). Reports "
            "APPLIED/PARTIAL/REJECTED, the accepted diff (field: old -> new), "
            "rejected changes with reasons, and the corrected record. "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
