"""Owned budget previews and a minimal, audited accounting escalation journey."""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime

from fastapi import APIRouter, Query, Request, Response
from maverick import budget_guidance as guidance
from maverick.authority_effects import authority_effect_fence
from maverick.governed_records import GovernedRecordStore
from maverick.privacy_ops import RecordConflict
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from .draft_api import context_for
from .product_errors import next_action, product_error

router = APIRouter()
CASES = GovernedRecordStore("budget_accounting_cases", "BAC", "budget_accounting_case")


def _app():
    from . import app
    return app


def _actor(request, *, named=False):
    auth.require_permission(request, "view")
    actor = auth.caller_principal(request)
    if named and not actor:
        raise product_error(403, "named_account_required", "Sign in with your own account to request accounting help.")
    return actor


def _goal(request, goal_id):
    if goal_id is None:
        return None
    goal = _app()._world().get_goal(goal_id)
    if goal is None:
        raise product_error(404, "task_unavailable", "That task is no longer available.")
    auth.assert_goal_access(request, goal)
    # A content exception does not authorize disclosing an employee's quota or
    # subscribing to their accounting history.
    if (goal.owner or "") != (_actor(request) or ""):
        raise product_error(403, "own_budget_only", "Open a task that belongs to your account to inspect its budget receipts.")
    return goal


def _forecast(actor, projection):
    from maverick.job_queue import JobQueue
    from maverick.schedule_definitions import list_definitions
    if not actor:
        return {"state": "unidentified", "items": []}
    try:
        reset = datetime.fromisoformat(projection["reset_at"]).timestamp()
        definitions = list_definitions(JobQueue(), owner=actor)
        rows = [row for row in definitions if row.get("owner") == actor
                and row.get("state") == "active" and 0 < row.get("next_run", 0) <= reset]
        return {"state": "available", "items": [{"id": row["definition_id"], "title": row["title"],
            "due_at": row["next_run"], "href": "/automations",
            "risk": "Admission currently blocked" if not projection["admission_allowed"] else "Allowance may change before this run",
            "detail": "Admission rechecks current policy at the next start. A paused or uncertain occurrence is never automatically replayed."}
            for row in rows], "price_basis": "Schedule ceilings are limits, not predicted prices; this forecast does not add them to charges."}
    except (ValueError, OSError, RuntimeError):
        return {"state": "unavailable", "items": [], "message": "Upcoming schedules could not be read; no empty or safe forecast is assumed. Refresh the page and try again."}


def _projection(request, *, max_dollars=None, max_wall_seconds=None, goal_id=None):
    actor = _actor(request)
    _goal(request, goal_id)
    try:
        value = guidance.preview(actor, max_dollars=max_dollars, max_wall_seconds=max_wall_seconds, goal_id=goal_id)
    except ValueError as exc:
        raise product_error(422, "budget_preview_unavailable", str(exc),
                            next_action=next_action("Review budget policy", "/budget")) from exc
    value["forecast"] = _forecast(actor, value)
    value["context"] = context_for(request)
    value["admin"] = auth.has_global_permission(request, "admin")
    value["goal_id"] = goal_id
    try:
        guidance.observe_warnings(actor, value)
        value["warnings"] = guidance.warning_sources(actor)
        value["warnings_state"] = "available"
    except (ValueError, OSError, RuntimeError):
        value["warnings"], value["warnings_state"] = [], "unavailable"
    if actor != _actor(request):
        raise product_error(409, "budget_account_changed", "Your account changed. Refresh the budget preview.")
    _goal(request, goal_id)
    return value


def _practice_cost(actor) -> str:
    """Today's practice spending for this person, on its own line: it costs
    real provider money but never counts against their limits."""
    from maverick import practice, practice_costs
    try:
        state = practice.spending(actor or "user:local")  # runs are charged to user:local
    except Exception:  # noqa: BLE001 -- the page still renders without the line
        return ""
    if not state["spent_today"]:
        return ""
    return (f"Practice: ${state['spent_today']:,.2f} today, within its ${state['cap']:,.2f} daily practice limit "
            f"({practice_costs.NOT_COUNTED})")


@router.get("/budget")
def page(request: Request, goal_id: int | None = None):
    actor = _actor(request)
    _goal(request, goal_id)
    from maverick.spending_limits import spend_recorded_at
    return _app().templates.TemplateResponse(request, "budget_guidance.html", {
        "goal_id": goal_id, "spend_recorded_at": spend_recorded_at(), "practice_cost": _practice_cost(actor)},
        headers={"Cache-Control": "private, no-store"})


@router.get("/api/v1/budget/preview")
def preview(request: Request, response: Response,
            max_dollars: float | None = Query(default=None, ge=0, allow_inf_nan=False),
            max_wall_seconds: float | None = Query(default=None, ge=0, allow_inf_nan=False),
            goal_id: int | None = Query(default=None, gt=0)):
    response.headers["Cache-Control"] = "private, no-store"
    with authority_effect_fence():
        return _projection(request, max_dollars=max_dollars, max_wall_seconds=max_wall_seconds, goal_id=goal_id)


def _public(row):
    # A case carries accounting metadata only. Never attach prompts, task names,
    # complete global ledgers or provider credentials to an escalation.
    return {key: row.get(key) for key in ("id", "revision", "provider", "period", "state", "assigned_to",
        "created_at", "updated_at", "verified_at", "evidence_requested", "verification", "_audit_pending")}


def _case_rows(request):
    actor = _actor(request, named=True)
    rows = CASES.list(limit=10001)
    if len(rows) > 10000:
        raise product_error(503, "budget_case_capacity", "Accounting requests could not be read completely. Contact the installation administrator.")
    admin = auth.has_global_permission(request, "admin")
    return [_public(row) for row in rows if admin or row.get("owner") == actor]


@router.get("/api/v1/budget/cases")
def cases(request: Request, response: Response):
    response.headers["Cache-Control"] = "private, no-store"
    with authority_effect_fence():
        return {"items": _case_rows(request), "context": context_for(request),
                "admin": auth.has_global_permission(request, "admin")}


class CaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(max_length=128)
    provider: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,127}$")
    period: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}(?:-[0-9]{2})?$")
    goal_id: int | None = Field(default=None, gt=0)


def _binding(request, context):
    _app()._require_same_origin(request)
    if not auth.constant_time_equals(context_for(request), context):
        raise product_error(409, "budget_context_changed", "Your account or workspace changed. Refresh before continuing.")


@router.post("/api/v1/budget/cases")
def request_help(request: Request, body: CaseIn):
    with authority_effect_fence():
        _binding(request, body.context)
        actor = _actor(request, named=True)
        value = _projection(request, goal_id=body.goal_id)
        provider = next((row for row in value["providers"] if row["provider"] == body.provider
                         and row["period"] == body.period and row["state"] in {"blocked", "unavailable"}), None)
        if provider is None:
            raise product_error(409, "budget_block_changed", "This accounting block changed. Refresh the current evidence before requesting help.")
        identity = "BAC-" + hashlib.sha256(json.dumps([actor, body.provider, body.period, body.goal_id]).encode()).hexdigest()[:48]
        row = CASES.get(identity)
        if row is not None and row.get("state") == "verified":
            try:
                row = CASES.update(identity, lambda current: current.update(state="requested", verified_at=None,
                    verification="A new block was observed after the previous review. Fresh accounting evidence is needed; nothing was refunded."),
                    expected_revision=row["revision"], action="reopen_accounting_review", actor=actor)
            except RecordConflict as exc:
                raise product_error(409, "budget_case_changed", "The accounting request changed. Refresh before requesting review.") from exc
        if row is None:
            try:
                row = CASES.create({"id": identity, "owner": actor, "provider": body.provider, "period": body.period,
                    "state": "requested", "assigned_to": None, "goal_id": body.goal_id,
                    "receipt_references": [r["reference"] for r in value["task_receipts"] if r["provider"] == body.provider and r["period"] == body.period],
                    "evidence_requested": False, "verification": "Pending installation administrator review; no reservation was released."},
                    action="request_accounting_review", actor=actor, max_records=10000)
            except RecordConflict:
                row = CASES.get(identity)
        return {"case": _public(row), "context": context_for(request)}


class ProgressIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(max_length=128)
    expected_revision: int = Field(ge=1)
    action: str = Field(pattern=r"^(claim|request_evidence|verify)$")


@router.post("/api/v1/budget/cases/{identifier}")
def progress(request: Request, identifier: str, body: ProgressIn):
    from maverick import provider_spending_recovery
    with authority_effect_fence():
        _binding(request, body.context)
        auth.require_global_permission(request, "admin")
        actor = _actor(request, named=True)
        row = CASES.get(identifier)
        if row is None:
            raise product_error(404, "budget_case_missing", "That accounting request is unavailable in this workspace. Refresh the page to see the latest.")
        if body.action != "claim" and row.get("assigned_to") != actor:
            raise product_error(409, "budget_case_unassigned", "Claim this request before changing its progress.")
        changes = {"assigned_to": actor}
        if body.action == "claim":
            changes.update(state="assigned", verification="An installation administrator is reviewing accounting evidence; no allowance was increased.")
        elif body.action == "request_evidence":
            changes.update(state="evidence_needed", evidence_requested=True,
                verification="Provide the final provider receipt or invoice to the assigned administrator through your approved support channel. Do not include task content or credentials.")
        else:
            # Verify the ORIGINAL period. Advancing the clock or raising a cap
            # cannot resolve its unknown receipts or justify a refund claim.
            projection = provider_spending_recovery.status(row["period"], provider=row["provider"])
            state = projection["providers"][0] if projection["available"] and projection["providers"] else None
            verified = bool(state and state["allowed"] and not state["unresolved"] and state["holds_total"] == 0)
            changes.update(state="verified" if verified else "reviewing", verified_at=time.time() if verified else None,
                verification="Original-period accounting is readable with no unresolved or pending reservations. This does not claim a provider refund or replay work. Admission still checks current limits."
                if verified else "Original-period accounting is still blocked, pending or unavailable. No charge was refunded and no work was replayed.")
        try:
            saved = CASES.update(identifier, lambda current: current.update(changes), expected_revision=body.expected_revision,
                                 action="accounting_" + body.action, actor=actor)
        except RecordConflict as exc:
            raise product_error(409, "budget_case_changed", "Another reviewer changed this request. Refresh its current state.") from exc
        return {"case": _public(saved), "context": context_for(request)}
