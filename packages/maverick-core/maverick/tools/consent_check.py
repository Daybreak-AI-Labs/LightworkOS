"""Consent-validity checker (GDPR Art. 7 — demonstrable, withdrawable consent).

Evaluates a set of consent records and reports, per processing purpose, whether
valid consent currently exists. A record is only VALID if it was granted, not
withdrawn, not expired, and not granted after ``now``; otherwise it is
NOT_GRANTED, NOT_YET_GRANTED, WITHDRAWN, or EXPIRED. When several records share a purpose the most recent (by
``granted_at``) governs, so a fresh re-grant supersedes an older withdrawal;
a withdrawal on any record dated on or after that grant still withdraws it.
Pure date logic — deterministic and offline. Distinct from the
``voice_cloning_consent`` single-purpose gate.

ops:
  - check(consents, [now], [purpose])  — ``consents`` is
    ``[{purpose, granted, [granted_at], [expires], [withdrawn_at]}]`` (ISO
    dates). Reports per-purpose VALID/INVALID with the reason; ``purpose``
    narrows the report to one purpose.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any

from . import Tool


def _parse(value: Any, field: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        raise ValueError(f"{field} is not an ISO date (YYYY-MM-DD): {value!r}") from None


def _status(rec: dict, now: date) -> tuple[str, str]:
    """Return (state, detail) for one consent record."""
    if rec.get("granted") is not True:
        return "NOT_GRANTED", "consent was not granted"
    if rec.get("granted_at"):
        g = _parse(rec["granted_at"], "granted_at")
        if g > now:
            return "NOT_YET_GRANTED", f"granted_at {g.isoformat()} is after {now.isoformat()}"
    if rec.get("withdrawn_at"):
        w = _parse(rec["withdrawn_at"], "withdrawn_at")
        if w <= now:
            return "WITHDRAWN", f"withdrawn {w.isoformat()}"
    if rec.get("expires"):
        e = _parse(rec["expires"], "expires")
        if e <= now:
            return "EXPIRED", f"expired {e.isoformat()}"
    return "VALID", "granted, active"


def _later_withdrawal(rec: dict, withdrawals: list[date]) -> date | None:
    """A withdrawal on another record of the purpose, dated on or after the
    governing grant (same day counts: the order within a day is unknown)."""
    ga = rec.get("granted_at")
    granted = _parse(ga, "granted_at") if ga else date.min
    later = [w for w in withdrawals if w >= granted]
    return max(later) if later else None


def _check(consents: list, now: date, only: str | None) -> str:
    # Most recent grant at or before ``now`` per purpose governs. A record
    # dated after ``now`` cannot hide a current grant: it is considered only
    # when the purpose has no record at or before ``now`` (NOT_YET_GRANTED).
    latest: dict[str, tuple[tuple[int, int], dict]] = {}
    withdrawals: dict[str, list[date]] = {}
    for i, rec in enumerate(consents):
        if not isinstance(rec, dict) or "purpose" not in rec:
            return f"ERROR: consent {i} needs a 'purpose'"
        purpose = str(rec["purpose"])
        if only is not None and purpose != only:
            continue
        if rec.get("withdrawn_at"):
            w = _parse(rec["withdrawn_at"], f"consent {i} withdrawn_at")
            if w <= now:
                withdrawals.setdefault(purpose, []).append(w)
        ga = rec.get("granted_at")
        when = _parse(ga, f"consent {i} granted_at").toordinal() if ga else -1
        key = (0 if when > now.toordinal() else 1, when)
        prev = latest.get(purpose)
        if prev is None or key >= prev[0]:
            latest[purpose] = (key, rec)

    if only is not None and only not in latest:
        return f"NO_RECORD: no consent on file for purpose {only!r}"
    if not latest:
        return "ERROR: no consent records to evaluate"

    rows = []
    for purpose in sorted(latest):
        rec = latest[purpose][1]
        state, detail = _status(rec, now)
        if state == "VALID" and (w := _later_withdrawal(rec, withdrawals.get(purpose, []))):
            state, detail = "WITHDRAWN", f"withdrawn {w.isoformat()} (on a record for this purpose)"
        rows.append((purpose, state, detail))

    valid = sum(1 for _, s, _ in rows if s == "VALID")
    verdict = "VALID" if valid == len(rows) else "INVALID"
    lines = [f"{verdict}: {valid}/{len(rows)} purpose(s) with active consent (as of {now.isoformat()}):"]
    for purpose, state, detail in rows:
        lines.append(f"  [{state}] {purpose}: {detail}")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "check"):
        return f"ERROR: unknown op {args.get('op')!r}"
    consents = args.get("consents")
    if not isinstance(consents, list) or not consents:
        return "ERROR: consents must be a non-empty array of records"
    only = args.get("purpose")
    only = str(only) if only is not None else None
    now_arg = args.get("now")
    try:
        now = _parse(now_arg, "now") if now_arg is not None else datetime.now(timezone.utc).date()
        return _check(consents, now, only)
    except ValueError as e:
        return f"ERROR: {e}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["check"]},
        "consents": {
            "type": "array",
            "description": "consent records; each {purpose, granted, [granted_at], [expires], [withdrawn_at]}",
            "items": {
                "type": "object",
                "properties": {
                    "purpose": {"type": "string"},
                    "granted": {"type": "boolean"},
                    "granted_at": {"type": "string"},
                    "expires": {"type": "string"},
                    "withdrawn_at": {"type": "string"},
                },
                "required": ["purpose"],
            },
        },
        "now": {"type": "string", "description": "ISO date to evaluate against; defaults to system date"},
        "purpose": {"type": "string", "description": "narrow the report to a single purpose"},
    },
    "required": ["consents"],
}


def consent_check() -> Tool:
    return Tool(
        name="consent_check",
        description=(
            "Evaluate consent records for active validity (GDPR Art. 7). op=check "
            "with 'consents' ([{purpose, granted, [granted_at], [expires], "
            "[withdrawn_at]}]), optional 'now' and 'purpose'. Per purpose the most "
            "recent grant governs; reports VALID/INVALID with NOT_GRANTED / "
            "WITHDRAWN / EXPIRED reasons. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
