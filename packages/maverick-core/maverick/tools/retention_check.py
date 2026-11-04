"""Data-retention / storage-limitation checker (GDPR Art. 5(1)(e): personal
data kept no longer than necessary).

Given records tagged with a category and an age, and a retention policy mapping
category -> maximum days, this flags records that are **over-retained** (past
their limit and due for deletion/anonymization) and records with **no governing
policy**. Each record's age comes from an explicit ``age_days`` or is derived
from a ``created`` date against ``today``. Pure date arithmetic — deterministic
and offline.

ops:
  - check(records, policy, [today])  — ``records`` is
    ``[{id, category, created|age_days}]``; ``policy`` is
    ``{category: max_days}`` with an optional ``default``. Reports COMPLIANT or
    the over-retained / no-policy records with the overdue days.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any

from . import Tool

_MAX_LISTED = 20


def _age_days(rec: dict, rid: str, today: date) -> int:
    if "age_days" in rec:
        try:
            return int(rec["age_days"])
        except (TypeError, ValueError):
            raise ValueError(f"record {rid} age_days must be an integer") from None
    if "created" in rec:
        try:
            created = date.fromisoformat(str(rec["created"]))
        except ValueError:
            raise ValueError(f"record {rid} created is not an ISO date (YYYY-MM-DD)") from None
        return today.toordinal() - created.toordinal()
    raise ValueError(f"record {rid} needs 'created' or 'age_days'")


def _check(records: list, policy: dict, today: date) -> str:
    over: list[tuple[str, str, int, int]] = []  # id, category, age, limit
    no_policy: list[tuple[str, str, int]] = []

    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or "id" not in rec or "category" not in rec:
            return f"ERROR: record {i} needs 'id' and 'category'"
        rid = str(rec["id"])
        category = str(rec["category"])
        age = _age_days(rec, rid, today)

        if category in policy:
            limit = int(policy[category])
        elif "default" in policy:
            limit = int(policy["default"])
        else:
            no_policy.append((rid, category, age))
            continue

        if age > limit:
            over.append((rid, category, age, limit))

    over.sort(key=lambda t: (-(t[2] - t[3]), t[0]))
    no_policy.sort(key=lambda t: t[0])

    if not over and not no_policy:
        return f"COMPLIANT: all {len(records)} records within retention (as of {today.isoformat()})"

    parts = []
    if over:
        parts.append(f"{len(over)} over-retained")
    if no_policy:
        parts.append(f"{len(no_policy)} without policy")
    lines = [f"VIOLATION: {', '.join(parts)} ({len(records)} records, as of {today.isoformat()}):"]
    for rid, category, age, limit in over[:_MAX_LISTED]:
        lines.append(f"  [OVER_RETAINED] {rid} ({category}): age {age}d > {limit}d limit, overdue {age - limit}d")
    for rid, category, age in no_policy[:_MAX_LISTED]:
        lines.append(f"  [NO_POLICY] {rid} ({category}): age {age}d, no retention policy")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    records = args.get("records")
    if not isinstance(records, list) or not records:
        return "ERROR: records must be a non-empty array of {id, category, created|age_days}"
    policy = args.get("policy")
    if not isinstance(policy, dict) or not policy:
        return "ERROR: policy must be a non-empty object {category: max_days}"
    try:
        for cat in policy:
            int(policy[cat])
    except (TypeError, ValueError):
        return "ERROR: policy values must be integer day counts"
    today_arg = args.get("today")
    try:
        today = date.fromisoformat(str(today_arg)) if today_arg is not None else datetime.now(timezone.utc).date()
    except ValueError:
        return "ERROR: today is not a valid ISO date (YYYY-MM-DD)"
    try:
        return _check(records, policy, today)
    except ValueError as e:
        return f"ERROR: {e}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "records": {
            "type": "array",
            "description": "records to audit; each {id, category, created|age_days}",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "category": {"type": "string"},
                    "created": {"type": "string", "description": "ISO date the record was created"},
                    "age_days": {"type": "integer", "description": "explicit age in days (overrides created)"},
                },
                "required": ["id", "category"],
            },
        },
        "policy": {
            "type": "object",
            "description": "category -> max retention days (optional 'default')",
        },
        "today": {"type": "string", "description": "ISO date to age against; defaults to system date"},
    },
    "required": ["records", "policy"],
}


def retention_check() -> Tool:
    return Tool(
        name="retention_check",
        description=(
            "Audit records against a data-retention policy (GDPR storage "
            "limitation). op=check with 'records' ([{id, category, "
            "created|age_days}]) and 'policy' ({category: max_days}, optional "
            "'default'). Reports COMPLIANT or the over-retained records (with "
            "overdue days) and records with no governing policy. Deterministic, "
            "offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
