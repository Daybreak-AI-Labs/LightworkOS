"""Own-account native conversation inbox; uploads never grant task authority."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from maverick.authority_effects import authority_effect_fence
from maverick.conversation_inbox import ConversationInbox, file_record, policy
from maverick.goal_mutations import GoalMutationConflict
from maverick.privacy_ops import RecordConflict
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth
from .draft_api import context_for


def _private_response(response: Response):
    response.headers["Cache-Control"] = "private, no-store"


router = APIRouter(dependencies=[Depends(_private_response)])


def service(request, *, write=True):
    from .app import _world
    auth.require_permission(request, "operate" if write else "view")
    principal = auth.caller_principal(request)
    if not principal:
        raise HTTPException(403, "Sign in with a named account to use the conversation inbox")
    def authorize(goal):
        auth.require_permission(request, "operate" if write else "view")
        auth.assert_goal_access(request, goal)
        if write:
            from maverick.conversation_inbox import current_authority
            current_authority(goal)
        if auth.caller_principal(request) != principal:
            raise HTTPException(403, "The current account changed")
    return ConversationInbox(_world(), principal=principal, authorize=authorize)


def _translate(call):
    try:
        return call()
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except (RecordConflict, GoalMutationConflict) as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def state(request, goal_id):
    inbox = service(request, write=False)
    limits = policy()
    defaults = {"mode": "queue", "detail": "balanced"}
    from maverick import experience_preferences
    if experience_preferences.enabled():
        values = experience_preferences.state(inbox.principal)["values"]
        defaults = {"mode": values.get("conversation_mode", "queue"), "detail": values.get("conversation_detail", "balanced")}
    value = {**inbox.state(goal_id), "context": context_for(request), "enabled": limits["enabled"],
             "policy": limits, "defaults": defaults, "can_cancel": auth.has_permission(request, "operate")}
    service(request, write=False).target(goal_id, write=False)
    return value


@router.get("/api/v1/conversation-inbox/{goal_id}")
def get_state(request: Request, goal_id: int):
    return _translate(lambda: state(request, goal_id))


@router.get("/api/v1/conversation-inbox/{goal_id}/receipts/{operation_id}")
def get_receipt(request: Request, goal_id: int, operation_id: str):
    return _translate(lambda: {**state(request, goal_id), **service(request, write=False).receipt(goal_id, operation_id)})


def _context(request, context):
    from .app import _require_same_origin
    _require_same_origin(request)
    if context != context_for(request):
        from .product_errors import product_error
        raise product_error(409, "context_changed", "The account or workspace changed; reopen the conversation before sending")


def submit_native(request, goal_id, *, context, operation_id, mode, text, files=(), item_id=None,
                  expected_revision=None, keep_files=(), independent_context="none", expected_generation=0, expected_snapshot="", task_model="", task_effort="", task_model_context=""):
    with authority_effect_fence():
        _context(request, context)
        inbox = service(request)
        from .task_model_selection_api import selection
        task_selection = selection(request, task_model, task_effort, task_model_context)
        item = inbox.submit(goal_id, operation_id=operation_id, mode=mode, text=text, files=files,
                            item_id=item_id, expected_revision=expected_revision, keep_files=keep_files,
                            independent_context=independent_context, expected_generation=expected_generation, expected_snapshot=expected_snapshot,
                            task_selection=task_selection)
        result = {**state(request, goal_id), "item": item, "received": True}
    from .conversation_inbox_scheduler import wake
    wake()
    return result


@router.post("/api/v1/conversation-inbox/{goal_id}")
async def submit(request: Request, goal_id: int, context: str = Form(...), operation_id: str = Form(...),
                 mode: str = Form(...), text: str = Form(...), files: list[UploadFile] = File(default=[]),
                 item_id: str = Form(""), expected_revision: int | None = Form(None),
                 keep_files: str = Form("[]"), independent_context: str = Form("none"), expected_generation: int = Form(0), expected_snapshot: str = Form(""),
                 task_model: str = Form(""), task_effort: str = Form(""), task_model_context: str = Form("")):
    _context(request, context)
    _translate(lambda: service(request).target(goal_id))
    try:
        retained = json.loads(keep_files)
        if not isinstance(retained, list) or len(retained) > 10 or any(not isinstance(row, str) for row in retained):
            raise ValueError("Choose retained attachments from the current pending message")
        if len(files) > 10:
            raise ValueError("Choose up to ten files")
        selected, total = [], 0
        for upload in files:
            if not upload.filename:
                continue
            content = bytearray()
            while chunk := await upload.read(min(65536, policy()["max_total_bytes"] - total + 1)):
                total += len(chunk)
                if total > policy()["max_total_bytes"]:
                    raise ValueError("Pending attachments must total at most 4 MiB")
                content.extend(chunk)
            if content:
                selected.append(await run_in_threadpool(file_record, upload.filename,
                    upload.content_type or "application/octet-stream", bytes(content)))
        return await run_in_threadpool(_translate, lambda: submit_native(request, goal_id, context=context,
            operation_id=operation_id, mode=mode, text=text, files=selected, item_id=item_id or None,
            expected_revision=expected_revision, keep_files=retained, independent_context=independent_context, expected_generation=expected_generation, expected_snapshot=expected_snapshot,
            task_model=task_model, task_effort=task_effort, task_model_context=task_model_context))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


class Change(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(min_length=1, max_length=500)
    operation_id: str = Field(min_length=16, max_length=100)
    expected_revision: int = Field(ge=1, strict=True)
    action: str
    decision: str | None = None
    expected_review: str | None = Field(default=None, max_length=64)


def change_native(request, goal_id, item_id, body):
    with authority_effect_fence():
        _context(request, body.context)
        item = service(request).change(goal_id, item_id, **body.model_dump(exclude={"context"}))
        result = {**state(request, goal_id), "item": item, "received": True}
    from .conversation_inbox_scheduler import wake
    wake()
    return result


@router.patch("/api/v1/conversation-inbox/{goal_id}/{item_id}")
def change(request: Request, goal_id: int, item_id: str, body: Change):
    return _translate(lambda: change_native(request, goal_id, item_id, body))
