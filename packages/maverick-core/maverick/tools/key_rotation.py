"""Key rotation planner.

Given a set of signing/encryption keys (each with a creation date and a maximum
age) and a reference "today", decide which keys are OK, DUE, or OVERDUE for
rotation, and emit a staggered rotation schedule with overlap windows so two
keys are never rotated on the same day (avoids a fleet-wide outage). Uses
``datetime`` only; deterministic and offline. No disk, no network.

ops:
  - plan(keys, today[, stagger_days][, overlap_days])

A key is OVERDUE when age > max_age_days, DUE when within ``stagger_days`` of
the deadline (age >= max_age_days - stagger_days), else OK. DUE/OVERDUE keys are
scheduled most-urgent-first, ``stagger_days`` apart starting from today.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any

from . import Tool


def _parse_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _classify(age: int, max_age: int, stagger: int) -> str:
    if age > max_age:
        return "OVERDUE"
    if age >= max_age - stagger:
        return "DUE"
    return "OK"


def _plan(args: dict[str, Any]) -> str:
    today = _parse_date(args.get("today"))
    if today is None:
        return "ERROR: today must be an ISO date (YYYY-MM-DD)"
    keys = args.get("keys")
    if not isinstance(keys, list) or not keys:
        return "ERROR: keys (non-empty list of {id, created_iso, max_age_days}) is required"

    try:
        stagger = int(args.get("stagger_days", 1))
    except (TypeError, ValueError):
        stagger = 1
    stagger = max(1, stagger)
    try:
        overlap = int(args.get("overlap_days", 7))
    except (TypeError, ValueError):
        overlap = 7
    overlap = max(0, overlap)

    rows: list[tuple[str, int, int, str]] = []  # (id, age, deadline_offset, status)
    for k in keys:
        if not isinstance(k, dict):
            return "ERROR: each key must be an object {id, created_iso, max_age_days}"
        kid = str(k.get("id") or "").strip()
        if not kid:
            return "ERROR: each key needs an id"
        created = _parse_date(k.get("created_iso"))
        if created is None:
            return f"ERROR: key {kid!r} has an invalid created_iso"
        try:
            max_age = int(k.get("max_age_days"))
        except (TypeError, ValueError):
            return f"ERROR: key {kid!r} needs an integer max_age_days"
        age = (today - created).days
        status = _classify(age, max_age, stagger)
        # Days from today until the rotation deadline (can be negative = past).
        deadline_offset = max_age - age
        rows.append((kid, age, deadline_offset, status))

    overdue = sum(1 for r in rows if r[3] == "OVERDUE")
    due = sum(1 for r in rows if r[3] == "DUE")
    ok = sum(1 for r in rows if r[3] == "OK")

    lines = [
        f"PLAN: {overdue} overdue, {due} due, {ok} ok "
        f"(today={today.isoformat()}, stagger={stagger}d, overlap={overlap}d)",
        "keys:",
    ]
    for kid, age, deadline_offset, status in rows:
        lines.append(
            f"  - {kid}: {status} (age {age}d, deadline in {deadline_offset}d)"
        )

    # Schedule only keys needing rotation, most urgent (smallest deadline) first.
    needs = sorted(
        [r for r in rows if r[3] in ("OVERDUE", "DUE")],
        key=lambda r: (r[2], r[0]),
    )
    lines.append("schedule:")
    if not needs:
        lines.append("  - none due")
    else:
        for i, (kid, _age, _off, status) in enumerate(needs):
            rotate_on = today + timedelta(days=i * stagger)
            retire_on = rotate_on + timedelta(days=overlap)
            lines.append(
                f"  - {kid}: rotate {rotate_on.isoformat()}, "
                f"retire old {retire_on.isoformat()} ({status})"
            )
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "plan"):
        return f"ERROR: unknown op {args.get('op')!r} (expected plan)"
    if not isinstance(args.get("keys"), list):
        return "ERROR: keys (list of {id, created_iso, max_age_days}) is required"
    return _plan(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["plan"]},
        "keys": {
            "type": "array",
            "description": "keys; each {id, created_iso (YYYY-MM-DD), max_age_days}",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "created_iso": {"type": "string"},
                    "max_age_days": {"type": "integer"},
                },
                "required": ["id", "created_iso", "max_age_days"],
            },
        },
        "today": {"type": "string", "description": "reference date, ISO YYYY-MM-DD"},
        "stagger_days": {
            "type": "integer",
            "description": "days between scheduled rotations (default 1)",
        },
        "overlap_days": {
            "type": "integer",
            "description": "old-key overlap window after rotation (default 7)",
        },
    },
    "required": ["keys", "today"],
}


def key_rotation() -> Tool:
    return Tool(
        name="key_rotation",
        description=(
            "Key rotation planner. op=plan with 'keys' (each {id, created_iso, "
            "max_age_days}) and 'today' (ISO date), optional 'stagger_days' "
            "(default 1) and 'overlap_days' (default 7). Classifies each key "
            "OK/DUE/OVERDUE and emits a staggered rotation schedule with overlap "
            "windows. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
