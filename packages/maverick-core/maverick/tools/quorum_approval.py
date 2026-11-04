"""Quorum approval tool — M-of-N sign-off on a sensitive change.

Decide whether a sensitive change has collected at least M distinct approvals
out of the N supplied, optionally spanning M distinct roles. Deterministic and
offline; the caller passes the collected approvals and the threshold. Approvers
are deduplicated case-insensitively so the same person can't pad the count.

ops:
  - check(approvals, required[, require_distinct_roles])
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _check(args: dict[str, Any]) -> str:
    approvals = args.get("approvals")
    if not isinstance(approvals, list):
        return "ERROR: approvals must be an array of {approver, role?}"
    try:
        required = int(args.get("required"))
    except (TypeError, ValueError, OverflowError):
        return "ERROR: required (M, a positive integer) is required"
    if required < 1:
        return "ERROR: required must be >= 1"
    require_roles = bool(args.get("require_distinct_roles", False))

    approvers: set[str] = set()
    roles: set[str] = set()
    for a in approvals:
        if not isinstance(a, dict):
            continue
        who = str(a.get("approver") or "").strip().lower()
        if not who:
            continue
        approvers.add(who)
        role = str(a.get("role") or "").strip().lower()
        if role:
            roles.add(role)

    have = len(approvers)
    if have < required:
        return f"BLOCKED: {have} distinct approver(s), need {required}"
    if require_roles and len(roles) < required:
        return (
            f"BLOCKED: {len(roles)} distinct role(s) among {have} approver(s), "
            f"need {required}"
        )
    detail = f"{have} distinct approver(s) >= {required}"
    if require_roles:
        detail += f", {len(roles)} distinct role(s)"
    return f"SATISFIED: {detail}"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r} (expected check)"
    if not isinstance(args.get("approvals"), list):
        return "ERROR: approvals (array of {approver, role?}) is required"
    return _check(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "approvals": {
            "type": "array",
            "description": "collected approvals; each {approver, role?}",
            "items": {
                "type": "object",
                "properties": {
                    "approver": {"type": "string"},
                    "role": {"type": "string"},
                },
                "required": ["approver"],
            },
        },
        "required": {"type": "integer", "description": "M — distinct approvers required"},
        "require_distinct_roles": {
            "type": "boolean",
            "description": "also require M distinct roles",
        },
    },
    "required": ["approvals", "required"],
}


def quorum_approval() -> Tool:
    return Tool(
        name="quorum_approval",
        description=(
            "M-of-N quorum check for a sensitive change. op=check with "
            "'approvals' (each {approver, role?}), 'required' (M), and optional "
            "'require_distinct_roles'. Approvers are deduped case-insensitively; "
            "with require_distinct_roles the threshold also applies to distinct "
            "roles. Returns SATISFIED/BLOCKED with counts. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
