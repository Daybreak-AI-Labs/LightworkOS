"""Same-origin protected Chat alternative controls; all effects use native admission."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import chat_message_actions as native
from .api_schemas import GOAL_DESCRIPTION_MAX_LENGTH

router = APIRouter(prefix="/chat/message-actions", tags=["chat-message-actions"])


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    goal: int = Field(ge=1)
    action: Literal["retry", "edit", "branch"]
    turn: int | None = Field(default=None, ge=1)
    source: str = Field(pattern=r"^[a-f0-9]{64}$")
    message: str = Field(min_length=1, max_length=GOAL_DESCRIPTION_MAX_LENGTH)
    answer_only: bool = True


class OriginalIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=1048576)


class ApplyIn(OriginalIn):
    confirmed: bool


def _same_origin(request):
    from .app import _require_same_origin
    _require_same_origin(request)


@router.get("/context")
def context(request: Request, context: str):
    value = native.authority(request, context)
    from . import auth
    return {"context": value["context"], "may_start": auth.has_permission(request, "operate")}


@router.get("/{goal_id}/source")
def source(request: Request, goal_id: int, action: Literal["retry", "edit", "branch"],
           context: str, turn: int | None = None):
    return native.source(request, goal_id, action, context, turn)


@router.post("/review")
def review(request: Request, body: ReviewIn):
    _same_origin(request)
    return native.review(request, body.model_dump())


@router.post("/original")
def original(request: Request, body: OriginalIn):
    _same_origin(request)
    return native.original(request, body.token)


@router.post("/apply")
def apply(request: Request, body: ApplyIn):
    _same_origin(request)
    if body.confirmed is not True:
        raise HTTPException(422, "Review the complete conversation and confirm this separate attempt first.")
    result, background = native.apply(request, body.token)
    return JSONResponse(result, background=background, headers={"Cache-Control": "no-store, private"})
