"""Create schedules from a plain timetable instead of a typed cron line.

``maverick schedule add`` in the app. The page sends choices (every day,
weekday, week or month at a time, in a chosen time zone); the server turns
them into the cron line with :func:`maverick.scheduler.timetable_cron` and
checks it with :func:`maverick.scheduler.next_run` before anything is queued.
A custom cron line is still accepted, but only from the page's Technical
details and only after the same server check.

Saved workflows and described tasks go through the existing
``POST /api/v1/schedules`` handler (owner stamping, department limits,
template rendering). Re-running an earlier task queues the built-in
``run_goal`` job exactly like ``maverick schedule add <cron> run_goal``, after
the per-task access check. Every schedule writes one audit row first.
"""
from __future__ import annotations

import json
import math
import re
import time
from functools import lru_cache
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .auth import (
    assert_goal_access,
    caller_principal,
    caller_suites,
    execution_user_id_from_request,
    goal_owner_filter,
    require_permission,
)

router = APIRouter(tags=["schedules"])
MAX_ZONE = 64


@lru_cache(maxsize=1)
def _zones() -> tuple[str, ...]:
    try:
        from zoneinfo import available_timezones

        zones = {z for z in available_timezones() if "/" in z and not z.startswith(("Etc/", "SystemV/", "posix/", "right/"))}
    except Exception:  # pragma: no cover - platform without tz data
        zones = set()
    return tuple(sorted(zones | {"UTC"}))


def valid_zone(zone: str) -> bool:
    """Whether ``zone`` is a known time zone name (never guessed or defaulted)."""
    return isinstance(zone, str) and 0 < len(zone) <= MAX_ZONE and zone in _zones()


class TimetableIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repeat: Literal["hourly", "daily", "weekdays", "weekly", "monthly"] = "daily"
    at: str = Field("09:00", pattern=r"^\d{2}:\d{2}$")
    days: list[int] = Field(default_factory=list, max_length=7)
    day_of_month: int = Field(1, ge=1, le=31)
    every_hours: int = Field(1, ge=1, le=12)
    zone: str = Field("UTC", min_length=1, max_length=MAX_ZONE)
    # Technical details only: a custom five-part timetable, checked on the server.
    advanced: str | None = Field(None, max_length=120)


class PreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timetable: TimetableIn


class ScheduleAddIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    what: Literal["workflow", "task", "rerun"]
    template: str | None = Field(None, max_length=120)
    params: dict[str, str] | None = None
    text: str | None = Field(None, max_length=16_000)
    title: str | None = Field(None, max_length=200)
    goal_id: int | None = Field(None, ge=1)
    timetable: TimetableIn
    review_reference: str | None = Field(None, max_length=524288)
    confirmed: bool = False


class ScheduleReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    schedule: ScheduleAddIn


class ScheduleOriginalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference: str = Field(min_length=1, max_length=524288)


_CREATE_PURPOSE = "lightwork.schedule-create.v1"


def _creation_authority(request, expected=None, *, write=False):
    from maverick import config
    from maverick.governed_operations import digest
    from maverick.paths import current_tenant_id_strict

    from . import auth
    from .api_flow_operator_review import _workspace_authority
    from .app import require_page_visible
    from .draft_api import context_for

    with auth.fresh_configuration():
        principal = getattr(request.state, "principal", None)
        claims = getattr(principal, "claims", None) or {}
        via = claims.get("via")
        fresh = principal
        if via == "api_key":
            fresh = auth._authenticate_api_key(request, auth._api_key_bearer(request))
        elif via in {"session", "invite", "proxy"}:
            fresh = {"session": auth._session_principal, "invite": auth._invite_session_principal,
                     "proxy": auth._proxy_principal}[via](request)
        if principal is not None:
            if fresh is None or fresh.principal != principal.principal:
                raise HTTPException(401, "Sign in again before reviewing this schedule.")
            expiry = claims.get("exp")
            if expiry is not None and (type(expiry) not in {int, float} or not time.time() < expiry < math.inf):
                raise HTTPException(401, "Sign in again before reviewing this schedule.")
            auth._enforce_scim_active(fresh)
            auth._enforce_workspace_policies(request, fresh)
        require_permission(request, "operate")
        auth.require_page_permission(request, "/automations")
        require_page_visible(request, "/automations")
        context = context_for(request)
        if expected is not None and context != expected:
            raise HTTPException(409, "Your account or workspace changed. Reload Automations before continuing.")
        actor, tenant = caller_principal(request) or "", current_tenant_id_strict() or ""
        suites, scopes = caller_suites(request), auth.api_key_scopes(request)
        access = digest([_workspace_authority(request, actor, tenant), auth.caller_role(request),
                         sorted(suites) if suites is not None else None, sorted(scopes) if scopes is not None else None])
        if write:
            from .schedule_policy import require_scheduling as _require_scheduling
            if config.config_source_errors(include_tenant=True):
                raise HTTPException(503, "Current schedule settings could not be checked. Your entered work is kept.")
            try:
                _require_scheduling()
            except HTTPException as exc:
                raise HTTPException(exc.status_code, "Schedule creation is turned off. An administrator can manage it in Settings; original requests remain readable.") from exc
        return {"context": context, "actor": actor, "tenant": tenant, "access": access}


def _creation_body(body):
    return body.model_dump(mode="json", exclude={"review_reference", "confirmed"})


def _creation_material(request, body, schedule_id):
    from dataclasses import asdict

    from maverick.governed_operations import digest

    from .api import _prepare_schedule
    from .api_schemas import ScheduleIn

    cron, zone, runs = _cron(body.timetable)
    if body.what != "rerun":
        if body.what == "workflow" and not (body.template or "").strip():
            raise HTTPException(400, "Choose a saved workflow to schedule.")
        if body.what == "task" and not (body.text or "").strip():
            raise HTTPException(400, "Describe the task to run on this schedule.")
        payload = _prepare_schedule(request, ScheduleIn(cron=cron, tz=zone, title=body.title,
            template=body.template if body.what == "workflow" else None,
            params=body.params if body.what == "workflow" else None,
            text=body.text if body.what == "task" else None), schedule_id=schedule_id)
        return "start_goal", payload, runs
    goal = _world_goal(request, body.goal_id)
    payload = {"goal_id": goal.id, "title": (body.title or goal.title or "Run an earlier task again")[:200],
               "__cron__": cron, "__tz__": zone, "schedule_id": schedule_id, "owner": caller_principal(request) or "",
               "schedule_source_revision": digest(asdict(goal))}
    suites = caller_suites(request)
    if suites is not None:
        payload["allowed_suites"] = sorted(suites)
    user_id = execution_user_id_from_request(request)
    if user_id:
        payload.update(channel="api", user_id=user_id)
    return "run_goal", payload, runs


def _world_goal(request, identity):
    from .app import _world
    if identity is None:
        raise HTTPException(400, "Choose the earlier task to run again.")
    goal = _world().get_goal(identity)
    if goal is None:
        raise HTTPException(404, "The earlier task is unavailable.")
    assert_goal_access(request, goal)
    return goal


def _creation_open(reference):
    from maverick import crypto_at_rest
    try:
        if not crypto_at_rest.is_sealed_str(reference):
            raise ValueError
        with crypto_at_rest.deployment_key_scope():
            value = json.loads(crypto_at_rest.unseal_from_str(reference))
        if (set(value) != {"purpose", "operation", "authority", "expires", "body", "kind", "payload", "runs"}
                or value["purpose"] != _CREATE_PURPOSE or not re.fullmatch(r"[a-f0-9]{32}", value["operation"])
                or type(value["expires"]) not in {int, float} or not math.isfinite(value["expires"])
                or value["kind"] not in {"start_goal", "run_goal"} or not isinstance(value["payload"], dict)
                or set(value["authority"]) != {"context", "actor", "tenant", "access"}
                or not isinstance(value["runs"], list) or len(value["runs"]) != 3
                or any(type(run) not in {int, float} or not math.isfinite(run) for run in value["runs"])):
            raise ValueError
        ScheduleAddIn.model_validate(value["body"])
        return value
    except Exception as exc:
        raise HTTPException(409, "This original schedule reference could not be verified. Nothing was repeated.") from exc


def _creation_key(value):
    from maverick.governed_operations import digest
    return "schedule-create:" + digest([value["authority"]["tenant"], value["authority"]["actor"],
                                        value["authority"]["context"], value["operation"]])


def _creation_owned(request, value):
    current = _creation_authority(request, value["authority"]["context"])
    if any(current[key] != value["authority"][key] for key in ("actor", "tenant", "context")):
        raise HTTPException(404, "This original schedule belongs to another account or workspace.")
    return current


def _creation_source_visible(request, value):
    from maverick.templates import load_template

    from .auth import assert_template_access
    try:
        body = ScheduleAddIn.model_validate(value["body"])
        if body.what == "workflow":
            assert_template_access(request, load_template(body.template))
        elif body.what == "rerun":
            _world_goal(request, body.goal_id)
        return True
    except (HTTPException, OSError, ValueError):
        return False


def _creation_original(request, value):
    from maverick.authority_effects import authority_effect_fence
    from maverick.job_queue import JobQueue
    with authority_effect_fence():
        _creation_owned(request, value)
        queue = JobQueue()
        try:
            identity = queue.admission_receipt(value["kind"], value["payload"], idempotency_key=_creation_key(value))
        except ValueError as exc:
            raise HTTPException(409, "The retained admission belongs to different work. Nothing was repeated.") from exc
        visible = _creation_source_visible(request, value)
        result = {"found": identity is not None, "context": value["authority"]["context"],
                  "operation": value["operation"], "admission": "confirmed" if identity is not None else "unconfirmed",
                  "message": ("The original schedule was created. This check did not create or run it again."
                              if identity is not None else "No admission for this exact request is confirmed. It may still be underway; check current schedules before separately reviewing another creation."),
                  "execution": "Future runs and their results are separate from this creation receipt.",
                  "source_visible": visible}
        if identity is not None:
            result.update(id=identity, schedule_id=value["payload"]["schedule_id"], next_run=value["runs"][0])
        if visible:
            result["title"] = value["payload"]["title"]
        else:
            result["source_notice"] = "Private source details are unavailable in this view. The historical creation outcome is checked separately."
        _creation_owned(request, value)
        return result


@router.post("/api/v1/schedules/create-original")
def schedule_create_original(request: Request, body: ScheduleOriginalIn) -> dict:
    from .app import _require_same_origin
    _require_same_origin(request)
    return _creation_original(request, _creation_open(body.reference))


@router.post("/api/v1/schedules/create-review")
def schedule_create_review(request: Request, body: ScheduleReviewIn) -> dict:
    from maverick import crypto_at_rest
    from maverick.authority_effects import authority_effect_fence

    from .app import _require_same_origin
    _require_same_origin(request)
    if body.schedule.review_reference or body.schedule.confirmed:
        raise HTTPException(422, "Review fresh schedule choices before confirming them.")
    with authority_effect_fence():
        current = _creation_authority(request, body.context, write=True)
        operation = uuid4().hex
        kind, payload, runs = _creation_material(request, body.schedule, operation)
        payload["schedule_creation"] = {"purpose": _CREATE_PURPOSE, "operation": operation,
                                        "actor": current["actor"], "context": current["context"]}
        value = {"purpose": _CREATE_PURPOSE, "operation": operation, "authority": current,
                 "expires": time.time() + 600, "body": _creation_body(body.schedule),
                 "kind": kind, "payload": payload, "runs": runs}
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(encoded.encode()) > 262144 or len(body.schedule.params or {}) > 100:
            raise HTTPException(422, "This complete schedule is too large to review here. Use fewer inputs; nothing was created.")
        with crypto_at_rest.deployment_key_scope():
            reference = crypto_at_rest.seal_to_str(encoded)
        if not crypto_at_rest.is_sealed_str(reference):
            raise HTTPException(503, "The original request could not be protected. No schedule was created.")
        if current != _creation_authority(request, body.context, write=True):
            raise HTTPException(409, "Your access changed. Review current schedule choices again.")
        earlier = _world_goal(request, body.schedule.goal_id) if body.schedule.what == "rerun" else None
        return {"context": current["context"], "operation": operation, "reference": reference,
                "title": payload["title"], "work": payload.get("text") or ((earlier.description or earlier.title) if earlier else payload["title"]),
                "earlier_task": earlier.title if earlier else None,
                "inputs": body.schedule.params or {}, "timetable": body.schedule.timetable.model_dump(),
                "next_runs": runs, "kind": body.schedule.what,
                "notice": "This saves recurring work for its next scheduled start, using current permissions and limits. If the reply is interrupted, choose Check original before creating again."}


def _creation_apply(request, body):
    from maverick.authority_effects import authority_effect_fence
    from maverick.governed_operations import digest
    from maverick.job_queue import JobQueue
    value = _creation_open(body.review_reference)
    if not body.confirmed or digest(_creation_body(body)) != digest(value["body"]):
        raise HTTPException(409, "These choices do not match the complete review. Your draft is kept; nothing was repeated.")
    with authority_effect_fence():
        prior = _creation_original(request, value)
        if prior["found"]:
            return prior
        def current():
            if _creation_authority(request, value["authority"]["context"], write=True) != value["authority"]:
                raise HTTPException(409, "Your access changed. Review current schedule choices again.")
            kind, payload, _ = _creation_material(request, ScheduleAddIn.model_validate(value["body"]), value["operation"])
            payload["schedule_creation"] = value["payload"]["schedule_creation"]
            if kind != value["kind"] or digest(payload) != digest(value["payload"]):
                raise HTTPException(409, "The selected work or connected account changed. Review the current schedule again.")
            if _creation_authority(request, value["authority"]["context"], write=True) != value["authority"]:
                raise HTTPException(409, "Your access changed. Review current schedule choices again.")
            if time.time() >= min(value["expires"], value["runs"][0]):
                raise HTTPException(409, "This review expired or its first run time passed. No new schedule was created; review the current choices again.")
        current()
        _audit(request, event="schedule_creation_requested", what=value["body"]["what"], cron=value["payload"]["__cron__"],
               zone=value["payload"].get("__tz__") or "UTC", operation=value["operation"])
        try:
            JobQueue().enqueue_once(value["kind"], value["payload"], idempotency_key=_creation_key(value),
                                    run_at=value["runs"][0], effect_guard=current)
        except ValueError as exc:
            raise HTTPException(409, "This original admission does not match the reviewed schedule. Nothing was repeated.") from exc
        return _creation_original(request, value)


def _cron(timetable: TimetableIn) -> tuple[str, str, list[float]]:
    """(cron, zone, next three runs) or a plain 400."""
    from maverick.scheduler import CronError, timetable_cron, upcoming_runs

    if not valid_zone(timetable.zone):
        raise HTTPException(400, "Choose a time zone from the list.")
    try:
        if timetable.advanced and timetable.advanced.strip():
            cron = " ".join(timetable.advanced.split())
        else:
            cron = timetable_cron(timetable.repeat, at=timetable.at, days=timetable.days,
                                  day_of_month=timetable.day_of_month, every_hours=timetable.every_hours)
        runs = upcoming_runs(cron, tz=timetable.zone, count=3)
    except (CronError, ValueError) as exc:
        raise HTTPException(400, "That timetable isn't valid. Check the days and time, or clear the custom "
                                 "timetable in Technical details.") from exc
    return cron, timetable.zone, runs


def _audit(request: Request, *, event="schedule_created", **data) -> None:
    from maverick.audit import AuditRefused, audit_event

    try:
        audit_event(event, agent="dashboard", actor=caller_principal(request) or "local", **data)
    except AuditRefused as exc:
        raise HTTPException(503, "The activity log couldn't record this schedule, so it wasn't created.") from exc


@router.get("/api/v1/schedules/options")
def schedule_options(request: Request) -> dict:
    """What a person can schedule and the time zones to choose from."""
    from maverick.config import get_features

    from .app import _world, template_market_entries

    require_permission(request, "operate")
    try:
        workflows = [{"name": e["name"], "title": e.get("title") or e["name"], "params": list(e.get("params") or [])}
                     for e in template_market_entries(caller_principal(request))][:200]
    except Exception:  # an unreadable template folder still lets people schedule tasks
        workflows = []
    try:
        goals = _world().list_goals(owner=goal_owner_filter(request), limit=50)
        tasks = [{"id": g.id, "title": (g.title or "Untitled task")[:200]} for g in goals]
    except Exception:
        tasks = []
    current = _creation_authority(request)
    return {"enabled": bool(get_features().get("scheduling", True)), "context": current["context"], "zones": list(_zones()),
            "workflows": workflows, "tasks": tasks}


@router.post("/api/v1/schedules/preview")
def schedule_preview(request: Request, body: PreviewIn) -> dict:
    """The next three run times for a timetable. Nothing is saved."""
    require_permission(request, "operate")
    cron, zone, runs = _cron(body.timetable)
    return {"cron": cron, "zone": zone, "next_runs": runs}


@router.post("/api/v1/schedules/add", status_code=201)
async def schedule_add(request: Request, body: ScheduleAddIn) -> dict:
    """Arm a recurring schedule from plain choices."""
    from .api import create_schedule
    from .api_schemas import ScheduleIn
    from .app import _require_same_origin, _world
    from .schedule_policy import require_scheduling as _require_scheduling

    if body.review_reference:
        from starlette.concurrency import run_in_threadpool
        _require_same_origin(request)
        return await run_in_threadpool(_creation_apply, request, body)
    require_permission(request, "operate")
    _require_same_origin(request)
    _require_scheduling()
    cron, zone, _ = _cron(body.timetable)
    if body.what != "rerun":
        if body.what == "workflow" and not (body.template or "").strip():
            raise HTTPException(400, "Choose a saved workflow to schedule.")
        if body.what == "task" and not (body.text or "").strip():
            raise HTTPException(400, "Describe the task to run on this schedule.")
        _audit(request, what=body.what, cron=cron, zone=zone)
        payload = ScheduleIn(cron=cron, tz=zone, title=body.title,
                             template=(body.template or None) if body.what == "workflow" else None,
                             params=body.params if body.what == "workflow" else None,
                             text=body.text if body.what == "task" else None)
        return (await create_schedule(request, payload)).model_dump()
    if body.goal_id is None:
        raise HTTPException(400, "Choose the earlier task to run again.")
    goal = _world().get_goal(body.goal_id)
    if goal is None:
        raise HTTPException(404, "no such goal")
    assert_goal_access(request, goal)
    from maverick.job_queue import JobQueue
    from maverick.scheduler import schedule_cron

    schedule_id = uuid4().hex
    title = (body.title or goal.title or "Run an earlier task again")[:200]
    job_payload = {"goal_id": int(body.goal_id), "title": title, "__cron__": cron, "__tz__": zone,
                   "schedule_id": schedule_id}
    owner = caller_principal(request) or ""
    job_payload["owner"] = owner
    suites = caller_suites(request)
    if suites is not None:
        job_payload["allowed_suites"] = sorted(suites)
    user_id = execution_user_id_from_request(request)
    if user_id:
        job_payload["channel"] = "api"
        job_payload["user_id"] = user_id
    _audit(request, what="rerun", goal=int(body.goal_id), cron=cron, zone=zone)
    job_id, run_at = schedule_cron(JobQueue(), cron, "run_goal", job_payload)
    return {"id": job_id, "cron": cron, "kind": "run_goal", "title": title, "next_run": run_at,
            "schedule_id": schedule_id, "zone": zone}


class ScheduleChangeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=1, strict=True)
    state: Literal["active", "paused", "retired"]
    title: str | None = Field(None, min_length=1, max_length=200)
    timetable: TimetableIn | None = None
    confirm: bool = False


class RecurrenceRecoveryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    expected_attempts: int = Field(ge=0, strict=True)
    expected_evidence: str = Field(pattern=r"^[a-f0-9]{64}$")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    successor_id: int | None = Field(None, ge=1, strict=True)
    rearm: bool = False
    rationale: str = Field(min_length=5, max_length=1000)
    confirm: bool = False


class RecurrenceReceiptIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    reference: str = Field(min_length=1, max_length=8000)


class RecurrenceCopilotReferenceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=64000)


@router.post("/api/v1/schedules/definitions/{identity}")
def change_schedule(request: Request, identity: str, body: ScheduleChangeIn) -> dict:
    from maverick.job_queue import JobQueue
    from maverick.schedule_definitions import change_definition

    from .app import _require_same_origin
    from .schedule_policy import require_scheduling as _require_scheduling

    require_permission(request, "operate")
    _require_same_origin(request)
    _require_scheduling()
    if not body.confirm:
        raise HTTPException(422, "Review the effect on future runs and confirm the change.")
    changes = {}
    if body.timetable:
        cron, zone, _ = _cron(body.timetable)
        changes.update(cron=cron, zone=zone)
    try:
        return change_definition(JobQueue(), identity, expected_revision=body.expected_revision,
                                 state=body.state, title=body.title, owner=goal_owner_filter(request),
                                 actor=caller_principal(request) or "local", **changes)
    except KeyError as exc:
        raise HTTPException(404, "Schedule is unavailable.") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/api/v1/schedules/recovery/{job_id}")
def recurrence_recovery_review(request: Request, job_id: int) -> dict:
    from maverick.job_queue import JobQueue
    from maverick.schedule_definitions import recovery_evidence

    from .draft_api import context_for

    require_permission(request, "admin")
    queue = JobQueue()
    with queue._conn() as connection:
        row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None or not row["recurrence_reconcile_required"]:
            raise HTTPException(409, "This occurrence no longer needs recurrence recovery. Refresh schedules.")
        candidates = connection.execute(
            "SELECT id,status,scheduled_at FROM jobs WHERE id>? AND kind=? AND recurrence_payload=? ORDER BY id LIMIT 101",
            (job_id, row["kind"], row["recurrence_payload"]),
        ).fetchall()
        evidence = recovery_evidence(connection, row)
        import json
        definition = connection.execute("SELECT payload FROM schedule_definitions WHERE id=?", (row["recurrence_id"],)).fetchone()
        payload = json.loads(definition["payload"] if definition is not None else row["recurrence_payload"] or "{}")
        return {"job_id": job_id, "attempts": row["attempts"], "context": context_for(request),
                "definition_id": row["recurrence_id"], "title": str(payload.get("title") or payload.get("template") or "Scheduled work")[:200],
                "expected_evidence": evidence, "scheduled_at": row["scheduled_at"],
                "status": row["status"], "problem": "An earlier run was attempted before its continuation was reliably recorded. Review the retained execution evidence and investigate that historical result separately.",
                "external_outcome": "unknown", "successors": [dict(item) for item in candidates[:100]],
                "successors_complete": len(candidates) <= 100,
                "consequence": "Only future recurrence is repaired. The historical action is never replayed. Confirm old workers are stopped before continuing."}


@router.get("/api/v1/schedules/recovery-context")
def recurrence_recovery_context(request: Request) -> dict:
    from .draft_api import context_for
    require_permission(request, "admin")
    return {"context": context_for(request)}


@router.get("/api/v1/schedules/definitions/{identity}/recovery-options")
def recurrence_recovery_choices(request: Request, identity: str) -> dict:
    from maverick.job_queue import JobQueue

    from .draft_api import context_for
    require_permission(request, "admin")
    with JobQueue()._conn() as connection:
        rows = connection.execute("SELECT id,status,scheduled_at FROM jobs WHERE recurrence_id=? "
                                  "AND recurrence_reconcile_required=1 ORDER BY id DESC LIMIT 101", (identity,)).fetchall()
    return {"context": context_for(request), "occurrences": [dict(row) for row in rows[:100]], "complete": len(rows) <= 100}


def recurrence_receipt_reference(request: Request, job_id: int, body: RecurrenceRecoveryIn, *, review_current=True) -> str:
    """Protect the exact read-only receipt recipe, never mutation authority."""
    import hmac
    import json

    from maverick import crypto_at_rest
    from maverick.job_queue import JobQueue

    from .draft_api import context_for

    require_permission(request, "admin")
    if body.context != context_for(request) or not body.operation_id:
        raise HTTPException(409, "Your account or workspace changed. Open the schedule and review its recovery again.")
    if body.confirm is not True or body.rearm == (body.successor_id is not None):
        raise HTTPException(422, "Choose one future occurrence, explain the repair and confirm that old workers are stopped.")
    if review_current:
        current = recurrence_recovery_review(request, job_id)
        if current["attempts"] != body.expected_attempts or not hmac.compare_digest(current["expected_evidence"], body.expected_evidence):
            raise HTTPException(409, "The recovery evidence changed. Refresh and review the schedule again.")
    material = {"purpose": "lightwork.schedule-recovery-receipt.v1", "job_id": job_id,
                "actor": caller_principal(request) or "local", "context": body.context,
                "operation_id": body.operation_id,
                "request_hash": JobQueue._recovery_fingerprint(body.expected_attempts, body.successor_id,
                                                               body.rearm, body.expected_evidence, body.rationale)}
    reference = crypto_at_rest.seal_to_str(json.dumps(material, sort_keys=True))
    if not crypto_at_rest.is_sealed_str(reference):
        raise HTTPException(503, "The original-request reference could not be protected. No repair was started.")
    return reference


@router.post("/api/v1/schedules/recovery/{job_id}/reference")
def recurrence_recovery_reference(request: Request, job_id: int, body: RecurrenceRecoveryIn) -> dict:
    from .app import _require_same_origin
    _require_same_origin(request)
    return {"reference": recurrence_receipt_reference(request, job_id, body), "context": body.context}


@router.post("/api/v1/schedules/recovery/receipt")
def recurrence_recovery_receipt(request: Request, body: RecurrenceReceiptIn) -> dict:
    """Read the exact native receipt even when the source is no longer parked."""
    import json

    from maverick import crypto_at_rest
    from maverick.job_queue import JobQueue

    from .app import _require_same_origin
    from .draft_api import context_for

    _require_same_origin(request)
    require_permission(request, "admin")
    try:
        if not crypto_at_rest.is_sealed_str(body.reference):
            raise ValueError
        material = json.loads(crypto_at_rest.unseal_from_str(body.reference))
        if (set(material) != {"purpose", "job_id", "actor", "context", "operation_id", "request_hash"}
                or material["purpose"] != "lightwork.schedule-recovery-receipt.v1"
                or material["actor"] != (caller_principal(request) or "local") or material["context"] != context_for(request)):
            raise ValueError
        if (type(material["job_id"]) is not int or material["job_id"] < 1
                or not isinstance(material["operation_id"], str) or len(material["operation_id"]) != 32
                or any(character not in "0123456789abcdef" for character in material["operation_id"])):
            raise ValueError
    except Exception as exc:
        raise HTTPException(404, "This original request is unavailable in your current account and workspace.") from exc
    queue = JobQueue()
    try:
        successor = queue.recovery_receipt_commitment(material["job_id"], actor=material["actor"],
            operation_id=material["operation_id"], request_hash=material["request_hash"])
    except ValueError as exc:
        raise HTTPException(409, "The original receipt does not match this reviewed decision. Nothing was repeated.") from exc
    if successor is None:
        return {"found": False, "message": "No receipt for this exact repair is recorded yet. This does not prove that a request still underway failed. Review current schedules before another repair.",
                "historical_replayed": False, "external_outcome": "unknown"}
    with queue._conn() as connection:
        row = connection.execute("SELECT status,scheduled_at FROM jobs WHERE id=?", (successor,)).fetchone()
    return {"found": True, "message": "The exact future recurrence repair is recorded. This receipt check did not repeat it. The historical business result remains unknown.",
            "historical_replayed": False, "external_outcome": "unknown",
            "future_occurrence": {"status": row["status"], "scheduled_at": row["scheduled_at"]} if row else None}


@router.post("/api/v1/schedules/recovery/copilot-reference")
def recurrence_copilot_reference(request: Request, body: RecurrenceCopilotReferenceIn) -> dict:
    from .app import _require_same_origin
    from .product_operations import _context, _gate, _open, enabled_families
    from .product_operations_connections import RepairInput

    _require_same_origin(request)
    _gate(request)
    require_permission(request, "admin")
    material = _open(body.token)
    if (material["operation"] != "schedules.repair" or material["page"] != "/automations"
            or material["context"] != _context(request) or "schedules" not in enabled_families()):
        raise HTTPException(409, "This schedule review is unavailable. Review its current recovery again.")
    arguments = RepairInput.model_validate(material["arguments"])
    if not arguments.old_workers_stopped:
        raise HTTPException(422, "Confirm old workers are stopped before continuing.")
    decision = RecurrenceRecoveryIn(**material["native"], successor_id=arguments.successor_id,
        rearm=arguments.action == "rearm", rationale=arguments.rationale, confirm=True,
        operation_id=material["operation_id"])
    return {"reference": recurrence_receipt_reference(request, arguments.job_id, decision), "context": decision.context}


@router.post("/api/v1/schedules/recovery/{job_id}")
def recurrence_recovery_apply(request: Request, job_id: int, body: RecurrenceRecoveryIn) -> dict:
    import hmac

    from maverick.authority_effects import authority_effect_fence
    from maverick.job_queue import JobQueue

    from .app import _require_same_origin
    from .draft_api import context_for

    require_permission(request, "admin")
    _require_same_origin(request)
    if not body.operation_id:
        raise HTTPException(422, "Open the schedule's recovery form and review this repair before continuing.")
    if not hmac.compare_digest(body.context, context_for(request)):
        raise HTTPException(409, "Account or workspace changed. Review recovery again.")
    try:
        with authority_effect_fence():
            require_permission(request, "admin")
            if not hmac.compare_digest(body.context, context_for(request)):
                raise HTTPException(409, "Account or workspace changed. Review recovery again.")
            successor = JobQueue().reconcile_recurrence(job_id, expected_attempts=body.expected_attempts,
                successor_id=body.successor_id, rearm=body.rearm, confirm=body.confirm,
                expected_evidence=body.expected_evidence, actor=caller_principal(request) or "local",
                rationale=body.rationale, operation_id=body.operation_id)
    except (ValueError, KeyError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return {"repaired": True, "job_id": job_id, "successor_id": successor,
            "historical_replayed": False, "external_outcome": "unknown"}


@router.get("/api/v1/schedules/definitions/{identity}/history")
def schedule_history(request: Request, identity: str) -> dict:
    from maverick.job_queue import JobQueue
    from maverick.schedule_definitions import list_definitions

    require_permission(request, "view")
    queue = JobQueue()
    selected = next((item for item in list_definitions(queue, owner=goal_owner_filter(request)) if item["definition_id"] == identity), None)
    if selected is None:
        raise HTTPException(404, "Schedule is unavailable.")
    with queue._conn() as connection:
        versions = connection.execute(
            "SELECT revision,state,actor,rationale,created_at FROM schedule_definition_versions WHERE id=? ORDER BY revision",
            (identity,),
        ).fetchall()
    return {"schedule": selected, "versions": [dict(item) for item in versions],
            "historical_execution_replay": "never performed by schedule management"}
