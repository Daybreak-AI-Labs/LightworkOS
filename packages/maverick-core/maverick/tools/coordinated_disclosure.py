"""Coordinated-disclosure log.

Run a coordinated vulnerability disclosure (CVD) process offline: track a
whole report set's embargo timelines, check one report's window, and render
a public advisory. Pure date arithmetic — deterministic, no network, no DB;
the caller persists records however it likes and passes them back in.

ops:
  - status(records[, today, policy, embargo_days])  — per-report status
    (EMBARGOED / DUE_SOON / OVERDUE / PATCHED / DISCLOSED), deadline, and
    days remaining, plus a summary count. ``records`` is a list of
    ``{id, reported, [severity], [patched], [disclosed]}`` with ISO dates;
    ``policy`` maps severities to embargo days (optional ``default``);
    ``embargo_days`` sets a flat window when no policy is given (90 default).
  - status(reported, embargo_days[, today])  — single-report form: the
    disclosure date and whether the embargo is OPEN or EXPIRED.
  - advisory(id, severity, summary, reported, embargo_days[, today,
    reporter, fixed_in, cve])  — render an advisory block.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from . import Tool

_SEVERITIES = ("low", "medium", "high", "critical")
_DEFAULT_EMBARGO = 90
_DUE_SOON = 14  # days


# ---- shared parsing ---------------------------------------------------------

def _parse_date_err(value: Any, field: str) -> tuple[date | None, str]:
    if not isinstance(value, str):
        return None, f"ERROR: {field} must be an ISO date string (YYYY-MM-DD)"
    try:
        return date.fromisoformat(value), ""
    except ValueError:
        return None, f"ERROR: {field} is not a valid ISO date (YYYY-MM-DD): {value!r}"


def _embargo_days_err(value: Any) -> tuple[int | None, str]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None, "ERROR: embargo_days must be an integer >= 0"
    return value, ""


# ---- single-report window (+ advisory) --------------------------------------

def _window(args: dict[str, Any]) -> tuple[date, date, date, str]:
    reported, err = _parse_date_err(args.get("reported"), "reported")
    if err:
        return date.min, date.min, date.min, err
    days, err = _embargo_days_err(args.get("embargo_days"))
    if err:
        return date.min, date.min, date.min, err
    assert reported is not None and days is not None
    disclose = reported + timedelta(days=days)
    if "today" in args:
        today, err = _parse_date_err(args.get("today"), "today")
        if err:
            return date.min, date.min, date.min, err
        assert today is not None
    else:
        today = datetime.now(timezone.utc).date()
    return reported, disclose, today, ""


def _single_status(args: dict[str, Any]) -> str:
    reported, disclose, today, err = _window(args)
    if err:
        return err
    remaining = (disclose - today).days
    state = "EXPIRED" if today >= disclose else "OPEN"
    lines = [
        f"reported: {reported.isoformat()}",
        f"disclose-on: {disclose.isoformat()}",
        f"today: {today.isoformat()}",
        f"embargo: {state}",
    ]
    if state == "OPEN":
        lines.append(f"days-remaining: {remaining}")
    return "\n".join(lines)


def _advisory(args: dict[str, Any]) -> str:
    for req in ("id", "summary"):
        if not args.get(req):
            return f"ERROR: {req} is required for advisory"
    severity = str(args.get("severity", "")).lower()
    if severity not in _SEVERITIES:
        return f"ERROR: severity must be one of {', '.join(_SEVERITIES)}"
    reported, disclose, today, err = _window(args)
    if err:
        return err
    state = "EXPIRED" if today >= disclose else "OPEN"
    lines = [
        f"# Advisory {args['id']}  [{severity.upper()}]",
        f"Summary: {args['summary']}",
        f"Reported: {reported.isoformat()}",
        f"Coordinated-disclosure date: {disclose.isoformat()} (embargo {state})",
    ]
    if args.get("reporter"):
        lines.append(f"Reporter: {args['reporter']}")
    if args.get("fixed_in"):
        lines.append(f"Fixed in: {args['fixed_in']}")
    if args.get("cve"):
        lines.append(f"CVE: {args['cve']}")
    return "\n".join(lines)


# ---- multi-record timeline tracker -------------------------------------------

def _parse_date(value: Any, field: str) -> date:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO date string (YYYY-MM-DD)")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ValueError(f"{field} is not a valid ISO date (YYYY-MM-DD): {value!r}") from None


def _embargo_for(severity: str | None, policy: dict, flat: int) -> int:
    # Case-insensitive, as the advisory op is ("High" finds {"high": 7}).
    lowered = {str(k).lower(): v for k, v in policy.items()}
    if severity is not None and severity.lower() in lowered:
        return int(lowered[severity.lower()])
    if "default" in policy:
        return int(policy["default"])
    return flat


def _records_status(records: list, today: date, policy: dict, flat: int) -> str:
    rows = []
    for i, r in enumerate(records):
        if not isinstance(r, dict) or "id" not in r or "reported" not in r:
            return f"ERROR: record {i} needs at least 'id' and 'reported'"
        rid = str(r["id"])
        reported = _parse_date(r["reported"], f"record {rid} 'reported'")
        severity = r.get("severity")
        severity = None if severity is None else str(severity)
        window = _embargo_for(severity, policy, flat)
        if window < 0:
            return f"ERROR: record {rid} embargo window is negative ({window})"
        deadline = date.fromordinal(reported.toordinal() + window)
        remaining = deadline.toordinal() - today.toordinal()

        if r.get("disclosed"):
            d = _parse_date(r["disclosed"], f"record {rid} 'disclosed'")
            status, detail = "DISCLOSED", f"public on {d.isoformat()}"
        elif r.get("patched"):
            d = _parse_date(r["patched"], f"record {rid} 'patched'")
            status, detail = "PATCHED", f"fixed {d.isoformat()}; disclosure permitted"
        elif remaining <= 0:
            # The deadline day itself ends the embargo, as in the single form
            # (today >= disclose-on is EXPIRED).
            status, detail = "OVERDUE", f"deadline {deadline.isoformat()} passed {-remaining}d ago; disclosure permitted"
        elif remaining <= _DUE_SOON:
            status, detail = "DUE_SOON", f"{remaining}d to deadline {deadline.isoformat()}"
        else:
            status, detail = "EMBARGOED", f"{remaining}d to deadline {deadline.isoformat()}"
        rows.append((rid, status, detail))

    order = {"OVERDUE": 0, "DUE_SOON": 1, "EMBARGOED": 2, "PATCHED": 3, "DISCLOSED": 4}
    rows.sort(key=lambda x: (order.get(x[1], 9), x[0]))

    counts: dict[str, int] = {}
    for _, status, _ in rows:
        counts[status] = counts.get(status, 0) + 1
    summary = ", ".join(f"{counts[s]} {s}" for s in sorted(counts, key=lambda s: order.get(s, 9)))

    lines = [f"as of {today.isoformat()}: {summary}"]
    for rid, status, detail in rows:
        lines.append(f"  [{status}] {rid}: {detail}")
    return "\n".join(lines)


def _run_records_status(args: dict[str, Any]) -> str:
    records = args.get("records")
    if not isinstance(records, list):
        return "ERROR: records must be an array of {id, reported, ...}"
    if "today" in args:
        today, err = _parse_date_err(args.get("today"), "today")
        if err:
            return err
        assert today is not None
    else:
        today = datetime.now(timezone.utc).date()
    policy = args.get("policy")
    if policy is not None and not isinstance(policy, dict):
        return "ERROR: policy must be an object of {severity: days}"
    flat = args.get("embargo_days", _DEFAULT_EMBARGO)
    if isinstance(flat, bool) or not isinstance(flat, int) or flat < 0:
        return "ERROR: embargo_days must be an integer >= 0"
    try:
        return _records_status(records, today, policy or {}, flat)
    except ValueError as e:
        return f"ERROR: {e}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "status":
        # Two converged 'status' shapes: a record SET (timeline tracker) vs a
        # single report's window. The payload disambiguates.
        if "records" in args:
            return _run_records_status(args)
        return _single_status(args)
    if op == "advisory":
        return _advisory(args)
    return f"ERROR: unknown op {op!r} (expected 'status' or 'advisory')"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["status", "advisory"]},
        "records": {
            "type": "array",
            "description": "status (timeline form): [{id, reported, severity?, patched?, disclosed?}]",
        },
        "policy": {"type": "object", "description": "status: {severity: embargo_days, default?: days}"},
        "id": {"type": "string", "description": "advisory id (advisory op)"},
        "severity": {"type": "string", "enum": list(_SEVERITIES)},
        "summary": {"type": "string"},
        "reported": {"type": "string", "description": "ISO date (single-report status / advisory)"},
        "embargo_days": {"type": "integer", "description": "embargo length in days (>=0; 90 default for records)"},
        "today": {"type": "string", "description": "ISO date to evaluate against (default: today)"},
        "reporter": {"type": "string"},
        "fixed_in": {"type": "string"},
        "cve": {"type": "string"},
    },
    "required": ["op"],
}


def coordinated_disclosure() -> Tool:
    return Tool(
        name="coordinated_disclosure",
        description=(
            "Run a coordinated vulnerability disclosure (CVD) process offline. "
            "op=status with 'records' tracks a report set's timelines "
            "(EMBARGOED/DUE_SOON/OVERDUE/PATCHED/DISCLOSED, per-severity "
            "policy); op=status with 'reported'+'embargo_days' checks one "
            "report's window (OPEN/EXPIRED); op=advisory renders an advisory "
            "block. Deterministic date math; no network."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
