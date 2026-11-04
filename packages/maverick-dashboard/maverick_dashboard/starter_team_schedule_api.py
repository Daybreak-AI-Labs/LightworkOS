"""Exact reviewed schedule and inbox operations shared by page and Copilot."""
from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from maverick import crypto_at_rest
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import starter_teams_api as native
from .product_operations import StrictInput

router = APIRouter(prefix="/api/v1/starter-team-schedules", tags=["starter-team-schedules"])
PURPOSE = "lightwork.starter-team-schedule-review.v1"
TTL = 600
NOTICE = ("Schedules can dispatch only individually reviewed evidence packages within their "
          "approved time, run and spending limits. They cannot collect new records or approve new "
          "work. AI execution needs a configured provider and current authority. A saved schedule "
          "alone does not prove that a background worker is running.")


class ScheduleInput(StrictInput):
    setup_id: str = Field(min_length=1, max_length=80)
    interval_hours: int = Field(ge=1, le=8760)
    start_at: float = Field(ge=0, allow_inf_nan=False)
    end_at: float = Field(ge=0, allow_inf_nan=False)
    max_runs: int = Field(ge=1, le=100)
    max_dollars_per_run: float = Field(gt=0, le=100, allow_inf_nan=False)
    max_total_dollars: float = Field(gt=0, le=1000, allow_inf_nan=False)
    max_wall_seconds: int = Field(default=300, ge=1, le=1800)


class ScheduleSelection(StrictInput):
    schedule_id: str = Field(min_length=1, max_length=80)


class ItemInput(ScheduleSelection):
    as_of: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    tables: dict[str, str] = Field(min_length=1, max_length=12)


class PauseInput(ScheduleSelection):
    paused: bool


class ReviewInput(StrictInput):
    action: Literal["schedule", "item", "pause", "tick"]
    arguments: dict = Field(max_length=20)
    expected_context: str = Field(pattern=r"^[a-f0-9]{64}$")


INPUTS = {"schedule": ScheduleInput, "item": ItemInput,
          "pause": PauseInput, "tick": ScheduleSelection}


def service(request):
    from maverick.starter_team_schedule import StarterTeamScheduleService
    from maverick.starter_teams import get_team

    from .starter_team_scheduler import register_runtime_authorizer

    register_runtime_authorizer()
    bound = native.context(request)

    def authorize(candidate, operation, team):
        if candidate.binding() != native.context(request).binding():
            return False
        if operation not in {"read", "runtime_read"} and (
            getattr(getattr(request, "state", None), "api_key_id", None) or auth.api_key_scopes(request) is not None
        ):
            raise HTTPException(403, "Sign in to review scheduled work. An API key cannot grant continuing schedule authority.")
        if team:
            try:
                native.require_team(request, get_team(team) if isinstance(team, str) else team)
            except HTTPException as exc:
                if exc.status_code in {402, 403, 404}:
                    return False
                raise
        return operation in {"read", "setup", "run", "pause", "runtime_review",
                             "runtime_start", "runtime_read", "runtime_approve"}

    return StarterTeamScheduleService(bound, authorize, workspace_id="tenant:" + bound.tenant)


def _date(value):
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def available_schedules(request):
    """Unconfirmed previews remain audit records, not operational schedules."""
    return [row for row in service(request).list_schedules() if row["status"] != "awaiting_confirmation"]


def public_schedule(row):
    return {"Starts": _date(row["start_at"]), "Ends": _date(row["end_at"]),
            "Hours between runs": row["interval_hours"], "Maximum runs": row["max_runs"],
            "Maximum dollars per run": row["max_dollars_per_run"],
            "Maximum total dollars": row["max_total_dollars"],
            "Maximum seconds per run": row["max_wall_seconds"], "Meaning": NOTICE}


def _item_preview(row):
    from .plain_labels import pack_display_name

    review = row["runtime_review"]
    return {"Scope": review.get("scope", ""), "Responsible person": review.get("owner_label", ""),
            "Source references": review.get("source_scope", []),
            "Specialists": [pack_display_name(name) for name in review.get("specialists", [])],
            "Specialist work": review.get("phases", []),
            "Permitted tools": [{"knowledge_search": "Search authorized workspace knowledge",
                                 "find_controls": "Find controls in the local catalog"}.get(name, name)
                                for name in review.get("allowed_tools", [])],
            "Maximum dollars": review.get("max_dollars"),
            "Maximum seconds": review.get("max_wall_seconds"),
            "Deliverable": review.get("deliverable", "Review the source-linked specialist output"),
            "Meaning": "Approval covers this exact evidence package and specialist plan only. "
                       "It does not approve future inputs, outside actions or additional spending."}


def _tick_material(workflow, schedule):
    if schedule.get("active_item_id"):
        item = workflow.get_item(schedule["active_item_id"])
        return {"schedule_id": schedule["id"], "expected_revision": schedule["revision"],
                "expected_item_id": item["id"]}, item
    items = workflow.list_items(schedule["id"])
    approved = [item for item in items if item.get("status") == "approved"]
    approved.sort(key=lambda item: (item["approved_at"], item["id"]))
    item = approved[0] if approved else None
    if item is None:
        raise ValueError("Approve an evidence package before reviewing a scheduled run")
    return {"schedule_id": schedule["id"], "expected_revision": schedule["revision"],
            "expected_item_id": item["id"]}, item


def prepare_operation(request, action, arguments):
    from maverick.starter_teams import get_team

    args = INPUTS[action].model_validate(arguments).model_dump()
    workflow = service(request)
    if action == "schedule":
        review = workflow.preview_schedule(**args)
        public = public_schedule(args)
        setup = native.service(request).get_setup(args["setup_id"])
        public.update({"Team": get_team(setup["team_id"])["title"], "Scope": setup["scope"]})
        material = {"review": review}
    else:
        schedule = workflow.get_schedule(args["schedule_id"])
        material = {"schedule_id": schedule["id"], "expected_revision": schedule["revision"]}
        public = public_schedule(schedule)
        if action == "item":
            setup = native.service(request).get_setup(schedule["setup_id"])
            team = get_team(setup["team_id"])
            tables = native.csv_tables(team, args["tables"])
            review = workflow.preview_item(schedule["id"], tables, as_of=args["as_of"],
                                           idempotency_key=secrets.token_hex(16))
            material = {"review": review}
            public = _item_preview(review)
            public["Supplied records"] = {table["label"]: tables[table["key"]] for table in team["inputs"]}
        elif action == "pause":
            material["paused"] = args["paused"]
            public["New state"] = "Paused" if args["paused"] else "Ready for approved packages"
        else:
            material, item = _tick_material(workflow, schedule)
            public.update(_item_preview(item))
            public["Consequence"] = "Check whether this reviewed package is due and, if permitted, start its specialist work. Provider charges may occur within the approved limits."
    return {"action": action, "native": material, "context": native.context(request).binding()}, public


def recover_operation(request, material, operation_id):
    if material["context"] != native.context(request).binding():
        raise HTTPException(409, "Return to the original account and workspace to check this result.")
    workflow, args = service(request), material["native"]
    action = material["action"]
    if action == "schedule":
        row = workflow.schedule_for_review(args["review"])
        return {"schedule": row} if row else None
    if action == "item":
        row = workflow.item_for_review(args["review"])
        return {"item": row} if row and row.get("status") in {"approved", "running", "completed", "blocked", "uncertain"} else None
    if action == "pause":
        row = workflow.get_pause_for_key(args["schedule_id"], operation_id)
        return {"pause_receipt": row} if row else None
    row = workflow.tick_for_key(args["schedule_id"], operation_id)
    return {"tick": row} if row else None


def execute_operation(request, material, operation_id):
    prior = recover_operation(request, material, operation_id)
    if prior is not None:
        return prior
    workflow, args = service(request), material["native"]
    if material["action"] == "schedule":
        return {"schedule": workflow.save_schedule(args["review"], confirmed=True)}
    if material["action"] == "item":
        return {"item": workflow.approve_item(args["review"], confirmed=True)}
    if material["action"] == "pause":
        return {"pause_receipt": workflow.set_paused(**args, idempotency_key=operation_id)}
    return {"tick": workflow.tick(**args, idempotency_key=operation_id)}


def public_outcome(value):
    if "schedule" in value:
        return {"Result": "Reviewed schedule saved", **public_schedule(value["schedule"])}
    if "item" in value:
        return {"Result": "Exact evidence package approved for its scheduled slot", "Meaning": NOTICE}
    if "pause_receipt" in value:
        return {"Result": "Schedule state recorded", "Meaning": "Pausing prevents new dispatches; already-started work retains its original limits."}
    tick = value["tick"]
    reasons = {
        "schedule_review_required": "Confirm the schedule before running work.",
        "paused": "The schedule is paused; no new work started.",
        "not_due": "The next run is not due; no new work started.",
        "schedule_window_ended": "The reviewed schedule period has ended; no new work started.",
        "waiting_for_approved_inputs": "Approve a fresh evidence package before the next run.",
        "run_limit_reached": "The reviewed run limit has been reached; no new work started.",
        "total_budget_reserved": "The reviewed spending allowance is fully reserved; no new work started.",
        "input_requires_review": "This evidence package needs review before it can run.",
    }
    status = reasons.get(tick.get("reason"), {
        "completed": "Specialist work completed; inspect its saved evidence and review the result.",
        "blocked": "Specialist work stopped at a prerequisite or authority boundary. Review the saved work.",
        "uncertain": "The outcome needs reconciliation. Check the original result before another run.",
        "running": "The reviewed specialist work is running.",
    }.get(tick.get("runtime_status"), "The run check is recorded. Its completion is not yet confirmed."))
    return {"Result": "Scheduled run check recorded", "Status": status, "Meaning": NOTICE}


def _result(value):
    return {**value, "outcome": public_outcome(value)}


@router.get("")
def read_schedules(request: Request):
    from .starter_team_scheduler import worker_status

    return native._response(native.call(lambda: {"schedules": available_schedules(request),
        "context": digest(native.context(request).binding()), "notice": NOTICE, "worker": worker_status()}))


@router.get("/{schedule_id}/items")
def read_items(request: Request, schedule_id: str):
    return native._response(native.call(lambda: {"items": service(request).list_items(schedule_id)}))


@router.post("/review")
def review(request: Request, body: ReviewInput):
    native._origin(request)
    if body.expected_context != digest(native.context(request).binding()):
        raise HTTPException(409, "Your account, workspace or access changed. Reload before reviewing this work.")
    material, public = native.call(lambda: prepare_operation(request, body.action, body.arguments))
    material.update(purpose=PURPOSE, expires_at=time.time() + TTL, operation_id=secrets.token_hex(16))
    serialized = json.dumps(material, sort_keys=True, allow_nan=False)
    if len(serialized.encode("utf-8")) > 1_000_000:
        raise HTTPException(422, "This review is too large. Use a smaller set of records and review again.")
    token = crypto_at_rest.seal_to_str(serialized)
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "The review could not be secured. Nothing was approved.")
    return native._response({"token": token, "preview": public})


def open_token(token, *, recovery=False):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if value["purpose"] != PURPOSE or value["action"] not in INPUTS:
            raise ValueError
        if not recovery and not time.time() < value["expires_at"] <= time.time() + TTL:
            raise ValueError
        return value
    except Exception as exc:
        raise HTTPException(409, "This review expired or could not be verified. Prepare a new review.") from exc


@router.post("/confirm")
def confirm(request: Request, body: native.TokenInput):
    native._origin(request)
    if body.confirmed is not True:
        raise HTTPException(422, "Review the planned work and its limits, then confirm it.")
    material = open_token(body.token)
    return native._response(native.call(lambda: _result(execute_operation(request, material, material["operation_id"]))))


@router.post("/original")
def original(request: Request, body: native.TokenInput):
    native._origin(request)
    material = open_token(body.token, recovery=True)
    value = native.call(lambda: recover_operation(request, material, material["operation_id"]))
    return native._response(_result(value) if value else {"status": "unconfirmed", "message": "The original result is not confirmed. No run or approval was repeated. Refresh the current schedule before another review."})
