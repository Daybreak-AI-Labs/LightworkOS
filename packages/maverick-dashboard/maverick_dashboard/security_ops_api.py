"""Security checks on Lightwork's own activity (/security/threats).

The ``maverick security posture``, ``maverick security detections``,
``maverick hunt`` and ``maverick remediate`` commands as buttons:

* ``GET  /api/v1/security/own/posture`` -- which defenses are switched on
  (``operate``, like the page).
* ``GET  /api/v1/security/own/detections`` -- security events from the
  activity log, newest first, with how complete the sweep was (``audit``:
  it reads the activity log).
* ``POST /api/v1/security/own/sweep`` -- look through the activity log for
  signs of attack over a chosen period (``audit``).
* ``GET  /api/v1/security/own/fixes`` -- the gaps and the proposed fix for
  each (a dry run: nothing changes) (``audit``).
* ``POST /api/v1/security/own/fixes/apply`` -- apply one automatic fix to
  Lightwork's own settings (installation administrators, confirmed). The
  activity log records who asked before anything changes, and the kernel
  records the applied change itself.

Every route calls the kernel function the terminal command calls; the exact
kernel wording is only returned as ``technical`` for a collapsed section.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_global_permission, require_permission

router = APIRouter(prefix="/api/v1/security/own", tags=["security-own-activity"])

_MAX_DETECTIONS = 500
_MAX_SWEEP_DAYS = 366

DEFENSES = {
    "shield": ("Harmful requests are screened", "/safety"),
    "capabilities": ("Tool limits are enforced", "/permissions"),
    "audit_signing": ("The activity log is tamper-evident", "/compliance"),
    "agent_trust": ("Unlisted outside agents are turned away", "/trust"),
    "egress_control": ("Outgoing connections are blocked", "/compliance"),
}

KIND_LABELS = {
    "injection": "Attempt to trick an assistant",
    "exfiltration": "Secret caught before it was saved",
    "capability_breach": "Assistant tried a tool it is not allowed",
    "policy_breach": "Action stopped by a company rule",
    "trust_breach": "Unlisted outside agent turned away",
    "egress_breach": "Data stopped from leaving",
    "control_event": "Work stopped or an action refused",
}

SIGNAL_LABELS = {
    "shield_block": "Harmful request blocked",
    "egress_blocked": "Attempt to send data out blocked",
    "capability_denied": "Assistant tried to go beyond its limits",
    "governance_denied": "Action stopped by a company rule",
    "halt": "All work was stopped",
    "secret_redacted": "Secret caught before it was saved",  # pragma: allowlist secret
    "consent_result": "Risky action refused or not approved in time",
}

SEVERITY_LABELS = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical",
                   "clear": "Nothing found"}

#: Plain wording and the page with the switch, per gap the plan names.
FIX_TEXT = {
    "Tamper-evident audit": ("Make the activity log tamper-evident", "/compliance"),
    "Storage limitation (retention)": ("Delete old records on a schedule", "/compliance#cmp-retention"),
    "Data-egress control": ("Keep AI requests on models you run yourself", "/compliance"),
    "Encryption at rest": ("Encrypt stored data", "/compliance"),
    "Human oversight (consent gating)": ("Ask a person before risky actions", "/compliance"),
}


class SweepIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    since: str | None = Field(default=None, max_length=10)
    until: str | None = Field(default=None, max_length=10)


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    control: str = Field(min_length=1, max_length=120)
    confirm: bool = False


def _day(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return _dt.datetime.strptime(value, "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=422, detail="Choose dates from the calendar.") from None


def _posture() -> dict[str, Any]:
    from maverick.agent_edr import posture

    p = posture().to_dict()
    rows = [{"key": key, "label": label, "on": bool(p.get(key)), "href": href}
            for key, (label, href) in DEFENSES.items()]
    off = [r for r in rows if not r["on"]]
    summary = ("Every defense is switched on." if not off else
               f"{len(off)} defense{'s are' if len(off) != 1 else ' is'} off. While a defense is off it records "
               "nothing, so a quiet log does not mean nothing happened.")
    return {"defenses": rows, "summary": summary,
            "technical": [str(n)[:300] for n in p.get("notes") or []][:20]}


def _detections(severity: str) -> dict[str, Any]:
    from maverick.agent_edr import scan, summary

    swept = scan(min_severity=severity, limit=_MAX_DETECTIONS)
    from .identity_format import humanize_principal

    rows = []
    for d in swept.found:
        rows.append({
            "when": d.ts,
            "day": d.day,
            "what": KIND_LABELS.get(d.kind, d.kind.replace("_", " ").capitalize()),
            "severity": SEVERITY_LABELS.get(d.severity, d.severity.capitalize()),
            "who": humanize_principal(d.subject).name if d.subject else "Unknown",
        })
    totals = summary(swept.found)
    notes = []
    if swept.truncated:
        notes.append(f"Only the newest {_MAX_DETECTIONS} events are shown; older ones exist.")
    if swept.unsigned_rows:
        notes.append(f"{swept.unsigned_rows} entr{'y was' if swept.unsigned_rows == 1 else 'ies were'} "
                     "recorded before the log was tamper-evident, so they cannot be proven unchanged.")
    if swept.unreadable_days:
        notes.append(f"{len(swept.unreadable_days)} day{'s' if len(swept.unreadable_days) != 1 else ''} "
                     "of the log could not be read, so this list may be incomplete.")
    if swept.root_missing:
        notes.append("Nothing has been recorded yet.")
    return {
        "detections": rows,
        "total": totals["total"],
        "by_severity": {SEVERITY_LABELS.get(k, k): v for k, v in totals["by_severity"].items()},
        "complete": not (swept.truncated or swept.unreadable_days or swept.root_missing),
        "proven": bool(swept.evidence_is_signed),
        "notes": notes,
    }


def _sweep(since: str | None, until: str | None) -> dict[str, Any]:
    from maverick.threat_hunt import hunt

    report = hunt(all_days=(since is None and until is None), since=since, until=until)
    findings = [{
        "what": SIGNAL_LABELS.get(f.kind, f.title),
        "severity": SEVERITY_LABELS.get(f.severity, f.severity.capitalize()),
        "count": int(f.count),
        "assistants": len(f.agents),
        "last_seen": f.last_seen,
    } for f in report.findings]
    risk = SEVERITY_LABELS.get(report.risk_rating, report.risk_rating.capitalize())
    summary = ("No signs of attack were found in the activity for these dates."
               if not findings else
               f"{len(findings)} kind{'s' if len(findings) != 1 else ''} of warning sign found. "
               f"Overall risk: {risk}.")
    return {"findings": findings, "entries_checked": int(report.events_scanned),
            "risk": risk, "summary": summary}


def _fixes() -> dict[str, Any]:
    from maverick.remediation import apply_remediation, plan

    p = plan(include_breaches=False)
    rows = []
    for gap in p.gaps:
        label, href = FIX_TEXT.get(gap.control, (gap.title, "/compliance"))
        preview = apply_remediation(gap, dry_run=True) if gap.auto and p.auto_fix_enabled else None
        rows.append({
            "control": gap.control,
            "label": label,
            "automatic": bool(gap.auto),
            "can_apply": bool(preview is not None and preview.dry_run),
            "href": href,
            "why_not": ("" if preview is None or preview.dry_run else
                        "This setting was already changed by hand, so apply it from the settings page."),
            "technical": (preview.block if preview is not None else "")[:600],
        })
    return {
        "fixes": rows,
        "automatic_fixes_on": bool(p.auto_fix_enabled),
        "summary": ("No security gaps were found." if not rows else
                    f"{len(rows)} gap{'s' if len(rows) != 1 else ''} found. "
                    + ("Fixes marked automatic can be applied here." if p.auto_fix_enabled else
                       "Automatic fixes are off, so use the button next to each gap to change it yourself.")),
    }


def _record(request: Request, action: str, **detail: Any) -> None:
    from maverick.audit import AuditRefused, audit_event

    try:
        audit_event("control_plane_action", agent="dashboard", _global=True, action=action,
                    actor=caller_principal(request) or "local administrator", **detail)
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail=(
            "This could not be added to the activity log, so nothing was changed.")) from exc


def _apply(control: str) -> dict[str, Any]:
    from maverick.remediation import apply_remediation, plan

    p = plan(include_breaches=False)
    gap = next((g for g in p.gaps if g.control == control), None)
    if gap is None:
        return {"applied": False, "message": "This gap is already closed."}
    result = apply_remediation(gap, dry_run=False)
    if result.applied:
        return {"applied": True, "message": "Fixed. It takes effect after Lightwork restarts.",
                "technical": result.undo[:300]}
    return {"applied": False, "message": "This fix could not be applied here. Use the settings page instead.",
            "technical": result.reason[:300]}


@router.get("/posture")
async def posture(request: Request) -> dict:
    require_permission(request, "operate")
    return await run_in_threadpool(_posture)


@router.get("/detections")
async def detections(request: Request,
                     severity: str = Query(default="low", pattern="^(low|medium|high)$")) -> dict:
    require_permission(request, "audit")
    return await run_in_threadpool(_detections, severity)


@router.post("/sweep")
async def sweep(request: Request, body: SweepIn) -> dict:
    require_permission(request, "audit")
    since, until = _day(body.since), _day(body.until)
    if since and until:
        if since > until:
            raise HTTPException(status_code=422, detail="The start date must be before the end date.")
        span = (_dt.date.fromisoformat(until) - _dt.date.fromisoformat(since)).days
        if span > _MAX_SWEEP_DAYS:
            raise HTTPException(status_code=422, detail="Choose a period of one year or less.")
    return await run_in_threadpool(_sweep, since, until)


@router.get("/fixes")
async def fixes(request: Request) -> dict:
    require_permission(request, "audit")
    return await run_in_threadpool(_fixes)


@router.post("/fixes/apply")
async def apply_fix(request: Request, body: ApplyIn) -> dict:
    require_global_permission(request, "admin")
    if body.confirm is not True:
        raise HTTPException(status_code=409, detail="Confirm the fix to continue. Nothing was changed.")
    if body.control not in FIX_TEXT:
        raise HTTPException(status_code=422, detail="Choose a gap from the list.")
    await run_in_threadpool(_record, request, "security_fix_apply", control=body.control)
    return await run_in_threadpool(_apply, body.control)


__all__ = ["DEFENSES", "FIX_TEXT", "KIND_LABELS", "router"]
