"""Plain labels and buttons for the Activity log (/audit).

The labels turn raw activity-log rows into words a person reads (event names,
field names, people). The routes are the ``maverick audit`` / ``maverick
attest`` commands that were CLI-only: check the log is intact, download it,
send it to the configured security system, encrypt older days, copy them to
write-once storage, make a new signing key and download a signed proof bundle.

Reading and checking need the ``audit`` permission (like the page). Anything
that changes files, sends data out or signs needs ``admin``; a new signing key
is deployment-wide, so it needs a global administrator.
"""
from __future__ import annotations

import csv
import datetime as _dt
import io
import re
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_global_permission, require_permission
from .identity_format import humanize, humanize_principal

router = APIRouter(tags=["audit-actions"])

KIND_LABELS: dict[str, str] = {
    "goal_start": "Task started", "goal_end": "Task finished",
    "episode_start": "Step started", "episode_end": "Step finished",
    "tool_call": "Used a tool", "tool_result": "Tool answered",
    "shield_block": "Stopped by the safety filter", "ifc_flow": "Sensitive data check",
    "capability_denied": "Tool not allowed", "sandbox_denied": "Blocked by the safe workspace",
    "token_exchange": "Sign-in passed to a service", "governance_denied": "Held by a company rule",
    "finance_sod_finding": "Finance duties not separated",
    "autonomy_escalated": "Asked for more freedom", "autonomy_gated": "Waited for permission",
    "egress_blocked": "Data not allowed to leave", "consent_prompt": "Asked for consent",
    "consent_result": "Consent answered", "secret_redacted": "Hid a secret", "erase": "Data erased",  # pragma: allowlist secret
    "trust_receipt_prepared": "Receipt prepared", "trust_receipt_issued": "Receipt issued",
    "retention_purge": "Old records deleted by policy", "halt": "Emergency stop",
    "config_remediated": "Setting fixed automatically", "tenant_plan_changed": "Workspace plan changed",
    "tenant_quota_changed": "Workspace limits changed",
    "spending_limits_changed": "Spending limits changed", "tenant_created": "Workspace created",
    "tenant_default_registered": "Default workspace registered",
    "workspace_selected": "Workspace chosen", "access_grant_changed": "Access changed",
    "federation_delegate": "Access passed to a partner", "agent_trust_denied": "Outside assistant not trusted",
    "control_plane_action": "Administrator action", "learning_update": "Learning changed",
    "tenant_suspended": "Workspace paused", "tenant_resumed": "Workspace resumed",
    "tenant_deleted": "Workspace removed",
    "codebase_action": "Code project action", "immune_action": "Safety monitoring action",
    "approval_decision": "Approval decided", "approval_requested": "Approval requested",
    "channel_approval_decision": "Approval decided in a chat app",
}
# Approval steps recorded as consent results, named for what the person did.
APPROVAL_ACTION_LABELS: dict[str, str] = {
    "approval_decision_undone": "Approval decision undone",
    "approval_confirmation": "Approval confirmed",
    "approval_rejection_reason": "Rejection reason recorded",
    "approval_revision_requested": "Sent back for changes",
    "approval_decided_via_channel": "Approval decided in a chat app",
}
FIELD_LABELS: dict[str, str] = {
    "goal_id": "Task", "tool": "Tool", "name": "Name", "reason": "Reason", "detail": "Details",
    "principal": "Person", "actor": "Done by", "user": "Person", "requested_by": "Requested by",
    "decision": "Decision", "action": "Action", "stage": "Stage", "provider": "Service",
    "rule": "Company rule", "input_summary": "Input", "output_summary": "Result",
    "status": "Status", "risk": "Risk", "cost_dollars": "Cost", "model_id": "Model",
    "obligation_id": "Rule reference", "regulation": "Regulation", "article": "Article",
    "obligations_checked": "Rules checked", "source": "Source", "tenant": "Workspace",
    "tenant_id": "Workspace", "labels": "Kinds of data", "outcome": "Outcome", "line": "Lesson",
    "phase": "Step", "repo": "Code project", "proposal": "Change",
    "email": "Email", "channel": "Chat app", "enabled": "Turned on", "suites": "Departments",
    "occurred_at": "Occurred at", "approval_id": "Approval", "scope": "Recorded in",
    "decided_by": "Decided by", "previously_decided_by": "Earlier decision by",
    "self_approval": "Approved own request",
}
_HIDDEN = {"v", "ts", "kind", "agent", "goal_id", "hash", "prev_hash", "sig", "key_id", "projection",
           "decided_by_person"}
# Machine identifiers (event ids, fingerprints, 64-hex tokens) are kept for
# support staff under "Technical details" instead of in the readable row.
_TECHNICAL_KEYS = {"approval_event_id", "event_id", "request_id", "idempotency_key",
                   "session_id", "trace_id", "correlation_id", "digest", "sha256", "artifact_sha256",
                   "row_hash", "previous_tenant"}
_TECHNICAL_VALUE = re.compile(r"^(?:[a-z0-9_-]+-)?[0-9a-f]{32,}$", re.IGNORECASE)
# Epoch timestamps recorded alongside the event (never shown as a raw float).
_TIME_KEYS = {"occurred_at", "created_at", "decided_at", "expires_at", "started_at",
              "ended_at", "finished_at", "updated_at", "requested_at", "at"}
_PERSON_KEYS = ("principal", "actor", "user", "requested_by", "decided_by", "owner")
# Shown as a person's name too, but never the row's "Who" (an undo row's Who is
# the person who undid it).
_NAMED_KEYS = frozenset(_PERSON_KEYS) | {"previously_decided_by"}
_SLUG_KEYS = {"name", "tool", "action", "stage", "provider", "rule", "outcome", "status",
              "decision", "risk", "source", "phase", "labels", "agent", "channel"}
_SLUG = re.compile(r"[a-z][a-z0-9]*(?:[_.:-][a-z0-9]+)*")


def kind_label(kind: object) -> str:
    return KIND_LABELS.get(str(kind or ""), humanize(kind) or "Activity")


def event_label(event: dict) -> str:
    """Name a known administrator action without exposing arbitrary audit text."""
    if event.get("kind") == "consent_result":
        action = event.get("action")
        if action is None and isinstance(event.get("payload"), dict):
            action = event["payload"].get("action")
        if isinstance(action, str) and action in APPROVAL_ACTION_LABELS:
            return APPROVAL_ACTION_LABELS[action]
    if event.get("kind") == "control_plane_action":
        from .content_access import VISIBLE_CONTROL_ACTIONS

        action = event.get("action")
        if action is None and isinstance(event.get("payload"), dict):
            action = event["payload"].get("action")
        if isinstance(action, str) and action in VISIBLE_CONTROL_ACTIONS:
            return humanize(action)
    return kind_label(event.get("kind"))


def field_label(key: object) -> str:
    return FIELD_LABELS.get(str(key), humanize(key))


def value_text(key: str, value: Any) -> str:
    if value is None or value == "":
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if key in _NAMED_KEYS and isinstance(value, str):
        return humanize_principal(value).name
    if key == "scope" and value == "deployment":
        return "Deployment-wide record (all workspaces)"
    if key in _SLUG_KEYS and isinstance(value, str) and _SLUG.fullmatch(value):
        return humanize(value)
    if isinstance(value, float):
        return f"{value:.2f}" if key == "cost_dollars" else f"{value:g}"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(value_text(key, v) for v in list(value)[:20]) or "—"
    if isinstance(value, dict):
        parts = [f"{field_label(k)}: {value_text(str(k), v)}" for k, v in list(value.items())[:12]]
        return "; ".join(parts) or "—"
    return str(value)


def event_person(event: dict) -> str:
    for key in _PERSON_KEYS:
        value = event.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def is_time_key(key: object) -> bool:
    key = str(key)
    return key in _TIME_KEYS or key.endswith(("_at", "_ts"))


def _technical(key: str, value: Any) -> bool:
    if key in _TECHNICAL_KEYS:
        return True
    return isinstance(value, str) and bool(_TECHNICAL_VALUE.fullmatch(value.strip()))


def event_details(event: dict) -> list[tuple[str, str, str]]:
    """``[(raw key, label, text)]`` for the readable detail fields of an event."""
    # An approval step's action is already the event's name ("Approval confirmed").
    named = event.get("kind") == "consent_result" and event.get("action") in APPROVAL_ACTION_LABELS
    return [(str(k), field_label(k), value_text(str(k), v))
            for k, v in event.items() if k not in _HIDDEN and not _technical(str(k), v)
            and not (named and k == "action")]


def event_technical(event: dict) -> list[tuple[str, str, str]]:
    """The machine identifiers of an event, shown under "Technical details"."""
    return [(str(k), field_label(k), value_text(str(k), v))
            for k, v in event.items() if k not in _HIDDEN and _technical(str(k), v)]


def event_who(event: dict) -> str:
    person = event_person(event)
    if person:
        return humanize_principal(person).name
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    if event.get("decided_by_person") is True or payload.get("decided_by_person") is True:
        # A person decided, but the recorded name can't be shown as text.
        return "A person (name not shown)"
    agent = event.get("agent")
    return humanize(agent) if agent else "Lightwork"


def page_helpers() -> dict:
    return {"kind_label": kind_label, "event_label": event_label,
            "event_details": event_details, "event_who": event_who,
            "event_technical": event_technical, "is_time_key": is_time_key}


def _day(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = _dt.datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=422, detail="Choose a date from the calendar.") from None
    return parsed.strftime("%Y-%m-%d")


def _audit_event(request: Request, action: str, **payload: Any) -> None:
    from maverick.audit import AuditRefused, audit_event
    try:
        audit_event("control_plane_action", agent="dashboard", action=action,
                    actor=caller_principal(request) or "local", **payload)
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail="The activity log refused this change.") from exc


def _siem_dest() -> str:
    import os
    dest = os.environ.get("MAVERICK_SIEM_DEST") or ""
    if not dest:
        try:
            from maverick.config import load_config
            dest = str(((load_config() or {}).get("audit") or {}).get("siem_dest") or "")
        except Exception:  # noqa: BLE001
            dest = ""
    return dest.strip()


def _export_allowed() -> bool:
    try:
        from maverick.billing import feature_allowed
        return bool(feature_allowed("audit_export"))
    except Exception:  # noqa: BLE001 -- the export route re-checks
        return False


class CheckIn(BaseModel):
    since: str | None = None
    until: str | None = None


class PreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preview: bool = True
    review: str | None = Field(default=None, pattern=r"^AAR-[a-f0-9]{32}$")
    operation: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    reconcile: bool = False
    acknowledge_uncertain: bool = False


class ForwardIn(BaseModel):
    since: str | None = None
    until: str | None = None


@router.get("/audit/actions")
async def actions_state(request: Request) -> dict:
    require_permission(request, "audit")

    def _read() -> dict:
        try:
            from maverick.audit.signing import _have_crypto
            crypto = bool(_have_crypto())
        except Exception:  # noqa: BLE001
            crypto = False
        try:
            from maverick.crypto_at_rest import at_rest_enabled
            at_rest = bool(at_rest_enabled())
        except Exception:  # noqa: BLE001
            at_rest = False
        return {"security_system_connected": bool(_siem_dest()), "download_allowed": _export_allowed(),
                "signing_available": crypto, "encryption_on": at_rest}
    return await run_in_threadpool(_read)


@router.post("/audit/check")
async def check_log(request: Request, body: CheckIn) -> dict:
    """Walk the signed chain of the chosen days plus the cross-day ledger."""
    require_permission(request, "audit")
    since, until = _day(body.since), _day(body.until)

    def _run() -> dict:
        from maverick.audit import verify_anchors, verify_chain
        from maverick.audit.signing import retention_purged_days
        from maverick.paths import data_dir
        audit_dir = data_dir("audit")
        paths = [p for p in sorted(audit_dir.glob("*.ndjson")) if p.name != "anchors.ndjson"] \
            if audit_dir.exists() else []
        paths = [p for p in paths if (not since or p.stem >= since) and (not until or p.stem <= until)]
        if len(paths) > 400:
            raise HTTPException(status_code=422, detail=(
                "Choose a smaller date range. Up to four hundred recorded days can be checked at once; "
                "split this range into separate checks."))
        problems: list[str] = []
        unsigned = 0
        try:
            from maverick.soc2 import _audit_signing_expected
            signing_expected = _audit_signing_expected()
        except Exception:
            signing_expected = True
        for path in paths[-400:]:
            breaks = verify_chain(path, max_breaks=20)
            if breaks and all(b.reason == "unsigned" for b in breaks) and not signing_expected:
                unsigned += 1
            elif breaks:
                problems.append(f"{path.stem}: {len(breaks)} "
                                + ("entry was" if len(breaks) == 1 else "entries were")
                                + " changed or could not be confirmed.")
        anchor_breaks = verify_anchors(audit_dir) if audit_dir.exists() else []
        if anchor_breaks:
            problems.append("The record that links the days together shows a day was removed or changed.")
        retired = retention_purged_days(audit_dir) if audit_dir.exists() and not anchor_breaks else []
        return {"days_checked": len(paths[-400:]), "intact": not problems and not unsigned,
                "problems": problems[:50], "unsigned_days": unsigned,
                "removed_by_policy": len(retired)}
    return await run_in_threadpool(_run)


def csv_safe(value: object) -> object:
    """A spreadsheet cell that is never run as a formula (names and details
    come from chat users and connected systems)."""
    from maverick.tools.spreadsheet import _neutralize_formula

    return _neutralize_formula(value)


def _rows(since: str | None, until: str | None, fmt: str) -> Iterator[str]:
    from maverick.audit.export import iter_audit_events, to_cef, to_jsonl

    from .content_access import audit_metadata
    events = iter_audit_events(since=since, until=until) if (since or until) else iter_audit_events(all_days=True)
    events = (audit_metadata(event) for event in events)
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Time (UTC)", "Event", "Who", "Task", "Details"])
        yield buf.getvalue()
        for ev in events:
            buf.seek(0)
            buf.truncate()
            ts = ev.get("ts")
            when = (_dt.datetime.fromtimestamp(float(ts), _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                    if isinstance(ts, (int, float)) else "")
            details = "; ".join(f"{label}: {text}" for _k, label, text in event_details(ev))
            writer.writerow([when, csv_safe(event_label(ev)), csv_safe(event_who(ev)),
                             ev.get("goal_id") if ev.get("goal_id") is not None else "",
                             csv_safe(details)])
            yield buf.getvalue()
        return
    render = to_cef if fmt == "cef" else to_jsonl
    for ev in events:
        yield render(ev) + "\n"


@router.get("/audit/download")
async def download(request: Request, fmt: Literal["csv", "json", "cef"] = Query("csv", alias="format"),
                   since: str | None = None, until: str | None = None) -> StreamingResponse:
    require_permission(request, "audit")
    since, until = _day(since), _day(until)
    if fmt != "csv" and not await run_in_threadpool(_export_allowed):
        raise HTTPException(status_code=403, detail="Your plan does not include downloads for security tools.")
    _audit_event(request, "audit_download", format=fmt, since=since, until=until)
    ext = {"csv": "csv", "json": "jsonl", "cef": "cef"}[fmt]
    name = f"activity-{since or 'start'}-to-{until or 'today'}.{ext}"
    media = {"csv": "text/csv", "json": "application/x-ndjson", "cef": "text/plain"}[fmt]
    return StreamingResponse(_rows(since, until, fmt), media_type=media + "; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{name}"',
                                      "Cache-Control": "no-store"})


@router.post("/audit/forward")
async def forward(request: Request, body: ForwardIn) -> dict:
    require_permission(request, "admin")
    since, until = _day(body.since), _day(body.until)
    dest = await run_in_threadpool(_siem_dest)
    if not dest:
        raise HTTPException(status_code=409, detail="No security monitoring system is connected yet.")
    if not await run_in_threadpool(_export_allowed):
        raise HTTPException(status_code=403, detail="Your plan does not include sending to security tools.")

    def _run() -> int:
        from maverick.audit import forwarder
        from maverick.audit.export import iter_audit_events, to_jsonl
        forwarder.parse_dest(dest)
        events = iter_audit_events(since=since, until=until) if (since or until) else iter_audit_events(all_days=True)
        from .content_access import audit_metadata
        return forwarder.forward((to_jsonl(audit_metadata(ev)) for ev in events), dest)
    try:
        sent = await run_in_threadpool(_run)
    except Exception as exc:  # noqa: BLE001 -- a transport failure is reported plainly
        raise HTTPException(status_code=502, detail=(
            "Lightwork could not reach your security monitoring system. Nothing was lost; try again later.")) from exc
    _audit_event(request, "audit_forward", sent=sent)
    return {"sent": sent}


@router.post("/audit/seal")
async def seal(request: Request, body: PreviewIn) -> dict:
    return await _maintenance(request, body, "seal")


@router.post("/audit/rotate-key")
async def rotate_key(request: Request) -> dict:
    require_global_permission(request, "admin")
    from .step_up import require_recent_mfa

    require_recent_mfa(request, "rotate_keys")
    from maverick.audit.signing import _have_crypto, rotate_audit_keypair
    if not _have_crypto():
        raise HTTPException(status_code=503, detail="Signing is not available on this installation.")
    await run_in_threadpool(rotate_audit_keypair)
    _audit_event(request, "audit_rotate_key")
    return {"rotated": True}


@router.post("/audit/write-once/push")
async def worm_push(request: Request, body: PreviewIn) -> dict:
    return await _maintenance(request, body, "copy")


async def _maintenance(request: Request, body: PreviewIn, action: str) -> dict:
    from . import audit_action_service as native
    if body.preview:
        return await _maintenance_call(native.prepare, request, action, reconcile=body.reconcile)
    if not body.review or not body.operation:
        raise HTTPException(409, "Review the exact closed days and destination before continuing. No maintenance action was started.")
    return await _maintenance_call(native.execute, request, action, body.review, body.operation,
                                   acknowledge_uncertain=body.acknowledge_uncertain)


async def _maintenance_call(function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except HTTPException:
        raise
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(503, "The saved maintenance result could not be read. Keep the original review and read it again before considering another action.") from exc


@router.get("/audit/action-reviews")
async def maintenance_reviews(request: Request) -> dict:
    from . import audit_action_service as native
    return await _maintenance_call(native.inventory, request)


@router.get("/audit/action-reviews/{review}")
async def maintenance_result(request: Request, review: str) -> dict:
    from . import audit_action_service as native
    return await _maintenance_call(native.receipt, request, review)


@router.post("/audit/action-reviews/{review}/cancel")
async def cancel_maintenance(request: Request, review: str) -> dict:
    from . import audit_action_service as native
    return await _maintenance_call(native.cancel, request, review)


@router.get("/audit/action-reviews/{review}/evidence")
async def maintenance_evidence(request: Request, review: str):
    from fastapi.responses import JSONResponse

    from . import audit_action_service as native
    return JSONResponse(await _maintenance_call(native.evidence, request, review), headers={
        "Content-Disposition": 'attachment; filename="activity-maintenance-review.json"', "Cache-Control": "private, no-store"})


@router.get("/audit/write-once/check")
async def worm_check(request: Request) -> dict:
    from . import audit_action_service as native
    return await _maintenance_call(native.check_copies, request)


@router.get("/audit/proof-key")
async def proof_key(request: Request) -> dict:
    require_permission(request, "audit")
    from maverick.attestation import publisher_key
    try:
        key_id, pub = await run_in_threadpool(lambda: publisher_key(create=False))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=409, detail="No unambiguous signing key has been provisioned yet. Turn on tamper-evident records before sharing its existing public key.") from exc
    return {"key_name": key_id, "key": pub}


@router.post("/audit/proof-bundle")
async def proof_bundle(request: Request) -> StreamingResponse:
    require_permission(request, "admin")
    from maverick.attestation import export

    def _build() -> bytes:
        from maverick.authority_effects import authority_effect_fence
        with authority_effect_fence():
            require_permission(request, "admin")
            with tempfile.TemporaryDirectory(prefix="lw-attest-") as tmp:
                path = export(Path(tmp) / "proof.json")
                return path.read_bytes()
    try:
        data = await run_in_threadpool(_build)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=(
            "The signed bundle could not be created. Check signing and key access on the Compliance page.")) from exc
    return StreamingResponse(iter([data]), media_type="application/json",
                             headers={"Content-Disposition": 'attachment; filename="lightwork-proof.json"',
                                      "Cache-Control": "no-store"})


__all__ = ["KIND_LABELS", "event_details", "event_label", "event_person", "event_who", "kind_label",
           "page_helpers", "router"]
