"""Named-account controls for obtaining actual recorded model instructions."""
from __future__ import annotations

import hmac
import re
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from maverick import instruction_capture as source
from maverick.governed_records import GovernedRecordCapacityError
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from .draft_api import context_for
from .learning_ops_api import _world
from .plain_labels import model_label

router = APIRouter(prefix="/api/v1/learning/instructions", tags=["learning-instructions"])
page_router = APIRouter()
_ID = re.compile(r"ISC-[a-f0-9]{32}\Z")


class Confirmed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirm: bool


class Capture(Confirmed):
    task: int = Field(ge=1, le=2**63 - 1)
    operation: str = Field(pattern=r"^[a-f0-9]{32}$")


class Withdraw(Confirmed):
    revision: int = Field(ge=1)


class Setup(Confirmed):
    enabled: bool
    previous: bool


def _bound(request, payload=None):
    auth.require_permission(request, "operate")
    tenant, actor, context = current_tenant_id_strict(), auth.caller_principal(request), context_for(request)
    if not tenant or not actor or not actor.startswith("user:"):
        raise HTTPException(403, "Sign in with a named account and select your workspace.")
    if payload is not None:
        from .app import _require_same_origin
        _require_same_origin(request)
        if not hmac.compare_digest(payload.context, context):
            raise HTTPException(409, "Your account or workspace changed. Refresh before continuing.")
        if payload.confirm is not True:
            raise HTTPException(422, "Review and confirm this instruction-recording action.")
    return tenant, actor, context, _world()


def _call(function):
    try:
        return function()
    except HTTPException:
        raise
    except GovernedRecordCapacityError as exc:
        raise HTTPException(409, "This workspace's instruction-recording capacity has been reached. Existing records are kept; you can review, download or withdraw them. Ask your installation administrator to review the retention and storage plan before recording more.") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "The instruction record could not be checked. Refresh before trying again.") from exc


def _plain(row, *, usable=True):
    state = row["state"]
    pending = source.result_pending(row)
    if pending:
        state = "uncertain"
    if state in {"waiting", "prepared"} and row["expires_at"] <= datetime.now(timezone.utc).timestamp():
        state = "expired"
    label = {"prepared": "Capture request needs completion", "waiting": "Waiting for the next completed model call", "captured": "Instructions captured from actual work",
             "uncertain": "Call completed; instruction receipt needs review", "withheld": "Completed call; instructions withheld", "withdrawn": "Withdrawn; instructions unavailable", "expired": "Request expired without a capture"}.get(state, "Needs review")
    if not usable:
        label = "Original source permission unavailable; instructions withheld"
    captured = row.get("captured_at")
    return {"id": row["id"], "revision": row["revision"], "title": row["title"], "status": label,
            "captured": state == "captured" and usable, "can_withdraw": state != "withdrawn", "can_finish": state in {"prepared", "uncertain"} and usable,
            "result_pending": pending,
            "model": model_label(row["model"]) if row["model"] else "Not recorded yet",
            "specialist": row["role"].replace("_", " ").replace("-", " ").title() if row["role"] else "Not recorded yet",
            "when": datetime.fromtimestamp(captured or row["created_at"], timezone.utc).strftime("%b %d, %Y at %H:%M UTC"),
            "explanation": row.get("reason", "")}


def choices(request):
    _tenant, actor, context, world = _bound(request)
    # Native status-filtered SQL keeps finished history from hiding live work.
    # Each read is bounded; merge by immutable goal identity before the UI cap.
    goals = {goal.id: goal for status in ("pending", "active", "blocked")
             for goal in world.list_goals(status=status, owner=actor, limit=100, order="desc")}
    tasks = [{"value": goal.id, "label": goal.title} for goal in sorted(goals.values(), key=lambda goal: goal.id, reverse=True)[:100]
             if source.source_allowed(goal.id, actor, world=world)]
    rows = []
    for row in sorted(source.records().list(limit=512), key=lambda row: row["created_at"], reverse=True):
        if row.get("owner") != actor:
            continue
        try:
            source.visible(world, row["id"], actor)
            usable = True
        except ValueError:
            usable = False
        rows.append(_plain(row, usable=usable))
    return {"context": context, "enabled": source.enabled(), "can_configure": auth.has_global_permission(request, "admin"), "tasks": tasks, "records": rows,
            "detail": "Authorize one task's next successful AI call that starts after your consent, then review its recorded instructions. No extra AI call is made."}


def authorize(request, body):
    _tenant, actor, _context, world = _bound(request, body)
    row = _call(lambda: source.authorize(world, body.task, actor, body.operation))
    return {"record": _plain(row), "detail": "Capture is authorized for this task's next successful model call started after authorization, within 24 hours. An already running call cannot be captured. Work is not started by this request."}


def inspect(request, identity):
    _tenant, actor, context, world = _bound(request)
    if _ID.fullmatch(identity) is None:
        raise HTTPException(404, "Choose a saved instruction record.")
    row = _call(lambda: source.visible(world, identity, actor))
    result = {**_plain(row), "context": context,
              "detail": "These are the instructions Lightwork gave your AI connection for this completed call. The AI service may process them further. This record does not show that these instructions are still in use or prove accurate answers or improved results."}
    if row["state"] == "captured":
        result["instructions"] = row["instructions"]
    return result


def withdraw(request, identity, body):
    _tenant, actor, _context, _world_value = _bound(request, body)
    if _ID.fullmatch(identity) is None:
        raise HTTPException(404, "Choose a saved instruction record.")
    row = _call(lambda: source.withdraw(identity, actor, body.revision))
    return {"record": _plain(row), "detail": "This capture is withdrawn. Its instructions can no longer be reviewed or downloaded here. Its decision record is kept."}


@router.get("")
def options(request: Request):
    return JSONResponse(_call(lambda: choices(request)), headers={"Cache-Control": "private, no-store"})


@router.post("")
def request_capture(request: Request, body: Capture):
    return authorize(request, body)


def setup(request, body):
    _bound(request, body)
    auth.require_global_permission(request, "admin")
    from . import settings_store
    from .learning_ops_api import _record
    with settings_store._locked(strict=True):
        if source.enabled() != body.previous:
            raise HTTPException(409, "The recording setting changed. Refresh and review it again.")
        _record(request, "instruction_capture_setting", installation=True, enabled=body.enabled)
        settings_store.set_catalog_values({("instruction_capture", "enable"): body.enabled})
        if source.enabled() != body.enabled:
            raise HTTPException(409, "The installation did not accept this setting. Refresh to check the effective setting.")
    return {"enabled": source.enabled(), "detail": "Instruction recording is on. Every task still needs separate consent." if body.enabled else
            "Instruction recording is off. Existing records can still be reviewed or withdrawn; no new text will be retained."}


@router.post("/setup")
def set_setup(request: Request, body: Setup):
    return _call(lambda: setup(request, body))


@router.get("/{identity}")
def read_capture(request: Request, identity: str):
    return JSONResponse(inspect(request, identity), headers={"Cache-Control": "private, no-store"})


@router.post("/{identity}/withdraw")
def withdraw_capture(request: Request, identity: str, body: Withdraw):
    return withdraw(request, identity, body)


def finish(request, identity, body):
    _tenant, actor, _context, world = _bound(request, body)
    row = _call(lambda: source.visible(world, identity, actor))
    if source.result_pending(row):
        result = _call(lambda: source.resolve(identity, actor, body.revision))
        return {"record": _plain(result), "detail": "The completed call's capture is resolved as withheld. No call was repeated and no later call was captured."}
    if row["state"] != "prepared" or row["revision"] != body.revision:
        raise HTTPException(409, "This capture request changed. Refresh before finishing it.")
    result = _call(lambda: source.authorize(world, row["goal_id"], actor, identity[4:]))
    return {"record": _plain(result), "detail": "The original capture request is ready. No new work was started."}


@router.post("/{identity}/finish")
def finish_capture(request: Request, identity: str, body: Withdraw):
    return finish(request, identity, body)


@router.get("/{identity}/download")
def download_capture(request: Request, identity: str):
    value = inspect(request, identity)
    if not value["captured"]:
        raise HTTPException(409, "This record has no available captured instructions to download.")
    from .learning_ops_api import _record
    _record(request, "instruction_capture_download", installation=False, capture=identity)
    return Response(value["instructions"], media_type="text/plain; charset=utf-8",
                    headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff",
                             "Content-Disposition": 'attachment; filename="lightwork-recorded-instructions.txt"'})


@page_router.get("/learning/instructions")
def instruction_page(request: Request):
    _bound(request)
    from .app import templates
    return templates.TemplateResponse(request, "instruction_capture.html", {"request": request})


@page_router.get("/static/lightwork-instruction-capture.js")
def instruction_asset():
    from .app import _STATIC_DIR
    return FileResponse(_STATIC_DIR / "lightwork-instruction-capture.js", media_type="application/javascript",
                        headers={"Cache-Control": "public, max-age=300"})
