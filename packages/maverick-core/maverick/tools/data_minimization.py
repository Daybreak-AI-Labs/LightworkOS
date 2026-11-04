"""Data-minimization / purpose-limitation checker (GDPR Art. 5(1)(c): personal
data must be adequate, relevant, and limited to what is necessary for the
purpose).

Compares the fields actually collected against the allowlist a declared purpose
permits, and flags **over-collection** (fields gathered beyond what the purpose
needs). With a ``required`` set it also flags **under-collection** (necessary
fields missing). Pure set logic — deterministic and offline. Distinct from
``retention_check`` (storage limitation) and ``k_anonymity`` (de-identification).

ops:
  - check(collected, allowed, [required], [purpose])  — ``collected`` and
    ``allowed`` are lists of field names (``collected`` may also be an object
    whose keys are used). Reports MINIMAL or the excess fields, plus any missing
    required fields.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _as_fields(value: Any) -> list[str] | None:
    if isinstance(value, dict):
        return [str(k) for k in value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return None


def _check(collected: list[str], allowed: list[str], required: list[str] | None, purpose: str) -> str:
    collected_set = set(collected)
    allowed_set = set(allowed)
    excess = sorted(collected_set - allowed_set)
    missing = sorted(set(required) - collected_set) if required is not None else []

    label = f" for purpose {purpose!r}" if purpose else ""
    if not excess and not missing:
        return f"MINIMAL: {len(collected_set)} field(s), all within what is necessary{label}"

    parts = []
    if excess:
        parts.append(f"{len(excess)} beyond purpose")
    if missing:
        parts.append(f"{len(missing)} required missing")
    lines = [f"VIOLATION: {', '.join(parts)}{label}:"]
    if excess:
        lines.append(f"  over-collected (not permitted): {', '.join(excess)}")
    if missing:
        lines.append(f"  under-collected (required, absent): {', '.join(missing)}")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    collected = _as_fields(args.get("collected"))
    if collected is None:
        return "ERROR: collected must be a list of field names or an object"
    allowed = _as_fields(args.get("allowed"))
    if allowed is None:
        return "ERROR: allowed must be a list of field names"
    required_arg = args.get("required")
    if required_arg is not None:
        required = _as_fields(required_arg)
        if required is None:
            return "ERROR: required must be a list of field names"
    else:
        required = None
    purpose = str(args.get("purpose", ""))
    return _check(collected, allowed, required, purpose)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "collected": {
            "description": "fields actually collected (array of names, or an object whose keys are used)",
        },
        "allowed": {
            "type": "array",
            "description": "fields the purpose permits collecting",
            "items": {"type": "string"},
        },
        "required": {
            "type": "array",
            "description": "fields that must be present (flags under-collection)",
            "items": {"type": "string"},
        },
        "purpose": {"type": "string", "description": "purpose label for the report"},
    },
    "required": ["collected", "allowed"],
}


def data_minimization() -> Tool:
    return Tool(
        name="data_minimization",
        description=(
            "Check collected fields against a purpose's allowlist (GDPR data "
            "minimization). op=check with 'collected' (list or object) and "
            "'allowed' (list), plus optional 'required' and 'purpose'. Reports "
            "MINIMAL or the over-collected fields beyond the purpose and any "
            "missing required fields. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
