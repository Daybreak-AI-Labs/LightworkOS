"""Exact, expiring, owner-only diagnostic documents with acknowledged audit reads."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response
from maverick import crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.governed_records import GovernedRecordStore
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from .draft_api import context_for
from .product_errors import product_error

router = APIRouter()
REPORTS = GovernedRecordStore("owned_task_diagnostics", "OTD", "owned_task_diagnostics")
TTL = 900
EVENT_KINDS = {"error", "blocked", "cancelled", "completed", "budget_exceeded", "approval", "question", "answer", "tool_error", "status", "started"}


def _app():
    from . import app
    return app


def _goal(request, identity):
    from maverick.config import get_features
    auth.require_permission(request, "view")
    if not get_features().get("employee_task_diagnostics", True):
        raise product_error(403, "diagnostics_disabled", "Employee task reports are disabled by your administrator.")
    principal = auth.caller_principal(request)
    goal = _app()._world().get_goal(identity)
    if goal is None:
        raise product_error(404, "diagnostic_task_missing", "This task is no longer available.")
    auth.assert_goal_access(request, goal)
    if (goal.owner or "") != (principal or ""):
        raise product_error(403, "diagnostic_owner_required", "Only the task owner can prepare or download its employee diagnostic report.")
    return principal or "", goal


def _document(world, goal, identity):
    from maverick.cost_provenance import for_goal
    rows = world.query("SELECT id,kind,ts FROM goal_events WHERE goal_id=? ORDER BY id DESC LIMIT 20", (goal.id,))
    events = [{"id": row[0], "kind": row[1] if row[1] in EVENT_KINDS else "other", "time_utc": datetime.fromtimestamp(row[2], timezone.utc).isoformat()} for row in rows]
    costs = for_goal(goal.id)
    pending = [row for row in costs["receipts"] if row["state"] != "settled"]
    status = goal.status if goal.status in {"draft", "pending", "running", "active", "blocked", "failed", "done", "cancelled"} else "unknown"
    failure = {"failed": "execution_failed", "blocked": "waiting_for_prerequisite", "cancelled": "cancellation_requested"}.get(status, "no_terminal_failure_recorded")
    return {"schema": "lightwork.task-diagnostics.v1", "correlation_id": identity, "task_id": goal.id,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(), "status": status, "failure_class": failure,
        "retry_state": "No retry was initiated. Inspect the current task controls; each explicit resume rechecks ownership, policy and budget.",
        "external_effects": "Unknown outcomes remain possible." if pending or costs["state"] != "available" else "Receipt state is local accounting evidence, not a guarantee that every external business effect was delivered.",
        "dependency_evidence": [{"reference": row["reference"], "provider": row["provider"], "period": row["period"], "state": row["state"]} for row in costs["receipts"]],
        "dependency_coverage": costs["state"], "recent_event_metadata": events,
        "event_coverage": "Latest 20 event identities/kinds/times only. Message bodies, tool arguments and raw provider errors are excluded.",
        "excluded": ["Task text and results", "Attachments", "Configuration", "Credentials", "Other people's tasks", "Raw logs and provider payloads"],
        "next_steps": ["Open this task to inspect the current question or review control.", "Open Your budget for accounting blocks.", "Review this exact document before manually sharing the downloaded file with your approved support contact."]}


@router.get("/tasks/{goal_id}/diagnostics")
def page(request: Request, goal_id: int):
    from .navigation_api import areas_redirect

    _goal(request, goal_id)
    moved = areas_redirect(request)
    if moved is not None:
        return moved
    return _app().templates.TemplateResponse(request, "task_diagnostics.html", {"goal_id": goal_id, "diagnostic_context": context_for(request)},
        headers={"Cache-Control": "private, no-store"})


@router.get("/goals/{goal_id}/diagnostics")
def goal_page(request: Request, goal_id: int):
    """The same report page under its task's address (areas mode only)."""
    from .navigation_api import areas_on

    if not areas_on(request):
        raise HTTPException(404, "Not Found")
    _goal(request, goal_id)
    return _app().templates.TemplateResponse(request, "task_diagnostics.html", {"goal_id": goal_id, "diagnostic_context": context_for(request)},
        headers={"Cache-Control": "private, no-store"})


class PrepareIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(max_length=128)


@router.post("/api/v1/tasks/{goal_id}/diagnostics")
def prepare(request: Request, goal_id: int, body: PrepareIn):
    return prepare_report(request, goal_id, body)


def report_result(request, row):
    owner, _ = _goal(request, row["goal_id"])
    if row["owner"] != owner or row["context"] != context_for(request):
        raise product_error(403, "diagnostic_context_mismatch", "This report belongs to another account or workspace context.")
    if row["expires_at"] <= time.time():
        raise product_error(410, "diagnostic_link_expired", "Prepare a new report; this report link has expired.")
    document = crypto_at_rest.unseal_from_str(row["sealed"])
    if not hmac.compare_digest(hashlib.sha256(document.encode()).hexdigest(), row["sha256"]):
        raise product_error(409, "diagnostic_preview_changed", "This stored report could not be verified. Prepare a new report.")
    return {"id": row["id"], "preview": document, "sha256": row["sha256"], "expires_at": row["expires_at"],
        "download_href": "/api/v1/task-diagnostics/" + row["id"] + "/download?sha256=" + row["sha256"],
        "audit_pending": bool(row.get("_audit_pending"))}


def prepare_report(request, goal_id, body, *, operation_id=None):
    with authority_effect_fence():
        _app()._require_same_origin(request)
        if not auth.constant_time_equals(body.context, context_for(request)):
            raise product_error(409, "diagnostic_context_changed", "Your account or workspace changed. Reopen this task before preparing a report.")
        owner, goal = _goal(request, goal_id)
        identity = "OTD-" + (hashlib.sha256(operation_id.encode()).hexdigest()[:48] if operation_id else secrets.token_hex(16))
        existing = REPORTS.get(identity) if operation_id else None
        if existing:
            return report_result(request, existing)
        document = json.dumps(_document(_app()._world(), goal, identity), indent=2, ensure_ascii=False) + "\n"
        if len(document.encode()) > 256000:
            raise product_error(409, "diagnostic_report_limit", "This report exceeds the safe preview size. Keep the task reference and contact support through the approved channel.")
        sealed = crypto_at_rest.seal_to_str(document)
        if not crypto_at_rest.is_sealed_str(sealed):
            raise product_error(503, "diagnostic_storage_unavailable", "Encrypted report storage is unavailable. Nothing was shared.")
        record = {"id": identity, "owner": owner, "goal_id": goal_id,
            "context": body.context, "sealed": sealed, "sha256": hashlib.sha256(document.encode()).hexdigest(),
            "expires_at": time.time() + TTL}
        from maverick.privacy_ops import RecordConflict
        try:
            row = REPORTS.create(record, action="prepare_report", actor=owner or "local", max_records=10000)
        except RecordConflict:
            row = REPORTS.get(identity)
            if row is None:
                raise product_error(409, "diagnostic_report_changed", "The report changed while saving. Refresh its status.") from None
        _goal(request, goal_id)
        return report_result(request, row)


@router.get("/api/v1/task-diagnostics/{identity}/download")
def download(request: Request, identity: str, sha256: str):
    from maverick.audit import record as audit
    with authority_effect_fence():
        auth.require_permission(request, "view")
        row = REPORTS.get(identity)
        if not row or row["expires_at"] <= time.time():
            raise product_error(410, "diagnostic_link_expired", "This report link expired or is unavailable. Prepare a fresh preview from the task.")
        owner, _ = _goal(request, row["goal_id"])
        if row["owner"] != owner or row["context"] != context_for(request):
            raise product_error(403, "diagnostic_context_mismatch", "This report belongs to a different account or workspace context.")
        document = crypto_at_rest.unseal_from_str(row["sealed"])
        digest = hashlib.sha256(document.encode()).hexdigest()
        if not hmac.compare_digest(digest, row["sha256"]) or not auth.constant_time_equals(digest, sha256):
            raise product_error(409, "diagnostic_preview_changed", "The reviewed report does not match. Prepare and inspect a fresh preview.")
        if row.get("_audit_pending") or audit("owned_task_diagnostic_download", actor=owner or "local", agent=owner or "local",
            report_id=identity, task_id=row["goal_id"], sha256=digest) is not True:
            raise product_error(503, "diagnostic_audit_pending", "The download audit receipt is unavailable. The report is retained; retry its current link before it expires.")
        return Response(document.encode(), media_type="application/json", headers={"Cache-Control": "private, no-store",
            "Content-Disposition": f'attachment; filename="task-diagnostics-{identity}.json"', "X-Content-SHA256": digest})
