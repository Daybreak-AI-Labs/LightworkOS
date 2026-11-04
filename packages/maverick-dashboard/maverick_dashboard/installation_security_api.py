"""Ordinary focused installation-policy review and original-attempt recovery."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.concurrency import run_in_threadpool

from . import installation_security as service

router = APIRouter(prefix="/api/v1/admin/installation-security", tags=["installation-security"])
page_router = APIRouter()


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    setting: str = Field(min_length=3, max_length=120)
    value: str | bool | int | float | list[str] | None = None
    inherit: bool = False

    @field_validator("value")
    @classmethod
    def bounded(cls, value):
        items = value if isinstance(value, list) else [value]
        if len(items) > 100 or any(isinstance(item, str) and len(item) > 512 for item in items):
            raise ValueError("Choose at most 100 short values; longer lists use All settings.")
        return value


class Apply(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(max_length=16000)
    confirmed: bool


class Acknowledge(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    operation: str = Field(pattern=r"^[a-f0-9]{32}$")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirmed: bool


def mutation(request):
    from .app import _require_same_origin
    _require_same_origin(request)
    service.authority(request)


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "no-store"})


def call(function):
    try:
        return function()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Installation policy could not be checked. Read current settings and the saved original attempt before retrying a change.") from exc


@router.get("")
def status(request: Request):
    return response(call(lambda: service.state(request)))


@router.post("/review")
def review(request: Request, body: Review):
    mutation(request)
    if body.context != service.context_for(request):
        raise HTTPException(409, "Your account or workspace changed. Refresh before reviewing.")
    return response(call(lambda: service.review(request, body.setting, body.value, body.revision, inherit=body.inherit)))


@router.post("/apply")
def apply(request: Request, body: Apply):
    mutation(request)
    return response(call(lambda: service.apply(request, body.token, confirmed=body.confirmed)))


@router.get("/attempt/{operation}")
def readback(request: Request, operation: str):
    if len(operation) != 32 or any(char not in "0123456789abcdef" for char in operation):
        raise HTTPException(404, "Choose the original saved attempt.")
    return response(call(lambda: service.readback(request, operation)))


@router.post("/attempt/review")
def acknowledge(request: Request, body: Acknowledge):
    mutation(request)
    if body.context != service.context_for(request) or body.confirmed is not True:
        raise HTTPException(409, "Review current policy and confirm this original attempt.")
    return response(call(lambda: service.acknowledge(request, body.operation)))


@router.post("/check/{kind}")
async def check(request: Request, kind: Literal["work-area", "company-signin", "single-signon"]):
    mutation(request)
    return response(await run_in_threadpool(call, lambda: service.check(request, kind)))


@page_router.get(service.PAGE)
def page(request: Request):
    service.authority(request)
    from .app import templates
    result = templates.TemplateResponse(request, "installation_security.html", {"request": request})
    result.headers["Cache-Control"] = "no-store"
    return result


@page_router.get("/static/lightwork-installation-security.js", include_in_schema=False)
def script():
    from pathlib import Path
    return FileResponse(Path(__file__).parent / "static" / "lightwork-installation-security.js",
                        media_type="application/javascript", headers={"Cache-Control": "public, max-age=300"})
