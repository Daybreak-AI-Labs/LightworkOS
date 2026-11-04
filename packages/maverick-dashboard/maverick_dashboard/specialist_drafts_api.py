"""Protected ordinary draft authoring and exact original specialist decisions."""
from __future__ import annotations

import secrets
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import specialist_drafts as native

router = APIRouter(prefix=native.API, tags=["specialist-drafts"])


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=128)
    action: Literal["save", "try", "check", "publish", "restore", "promote", "rollback"]
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    entered: dict | None = None
    selected: str | None = Field(default=None, pattern=r"^SPD-[a-f0-9]{32}$")
    task: str = Field(default="", max_length=4000)
    title: str = Field(default="", max_length=120)
    reason: str = Field(default="", max_length=300)
    acknowledge_previous: bool = False


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=2000000)
    confirmed: Literal[True]


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


@router.get("")
def inventory(request: Request, name: str):
    return response(native.inventory(request, name))


@router.get("/trials")
def trial_list(request: Request):
    return response(native.trials(request))


@router.get("/drafts/{identifier}")
def draft(request: Request, identifier: str):
    row = native.saved_draft(request, identifier)
    return response({"context": row["context"], "name": row["name"], "patch": row["patch"], "profile": row["profile"],
                     "title": row["title"], "revision": row["revision"]})


@router.get("/originals/{operation}")
def original(request: Request, operation: str):
    return response(native.original(request, operation))


@router.get("/history")
def original_history(request: Request):
    return response(native.original_history(request))


@router.post("/preview")
def preview(request: Request, body: ReviewIn):
    if body.action != "save":
        raise HTTPException(422, "Preview the complete entered draft before deciding what to do.")
    prepared = native.prepare(request, **body.model_dump())
    return response({"context": prepared["context"], "changes": native.changes(request, prepared),
                     "notice": native.NOTICE, "message": "This is the complete entered draft. It has not been saved, tried or published."})


@router.post("/review")
def review(request: Request, body: ReviewIn):
    prepared = native.prepare(request, **body.model_dump())
    operation = secrets.token_hex(16)
    return response({"context": prepared["context"], "operation": operation,
                     "token": native.seal(prepared, operation), "changes": native.changes(request, prepared), "notice": native.NOTICE})


@router.post("/apply")
def apply(request: Request, body: ApplyIn):
    native.authority(request, write=True)
    value = native.open_review(body.token)
    return response(native.apply(request, value["prepared"], value["operation"]))
