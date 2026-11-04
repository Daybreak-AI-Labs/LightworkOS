"""Ordinary full review and exact original recovery for joint local rules."""
from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import local_flow_promotions as release
from . import procedure_interactions as native
from .scalar_wire import exact_integers

router = APIRouter()
PURPOSE = "lightwork.procedure-interactions-review.v1"


class ReviewIn(native.Choices):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=2 * 1024 * 1024)
    confirmed: bool


def response(value):
    return JSONResponse(exact_integers(value), headers={"Cache-Control": "no-store, private"})


@router.get(native.PAGE)
def page(request: Request):
    from .app import templates
    native.authority(request)
    return templates.TemplateResponse(request, "procedure_interactions.html", {}, headers={"Cache-Control": "no-store, private"})


@router.get(native.API)
def listing(request: Request, first: str = "", second: str = ""):
    native.authority(request, request.headers.get("X-Lightwork-Joint-Context"))
    return response(release._native_call(lambda: native.listing(request, first, second)))


@router.get(native.API + "/history")
def history(request: Request):
    native.authority(request, request.headers.get("X-Lightwork-Joint-Context"))
    return response(native.history(request))


@router.get(native.API + "/original/{identifier}")
def original(request: Request, identifier: str):
    native.authority(request, request.headers.get("X-Lightwork-Joint-Context"))
    return response(release._native_call(lambda: native.original(request, identifier)))


@router.post(native.API + "/review")
def review(request: Request, body: ReviewIn):
    native.authority(request, body.context, write=True)
    if body.kind == "qualify" and native.listing(request, body.first, body.second)["revision"] != body.revision:
        raise HTTPException(409, "The current rules or original cases changed. Entered work is kept; refresh and review current choices.")
    value, changes = release._native_call(lambda: native.prepare(request, body.model_dump(exclude={"context", "revision"}), context=body.context))
    operation = native.operation()
    token = native.custody.seal({"purpose": PURPOSE, "prepared": value, "operation": operation})
    return response({"context": value["context"], "token": token, "operation": "PJI-" + operation, "changes": changes})


@router.post(native.API + "/apply")
async def apply(request: Request, body: ApplyIn):
    native.authority(request, write=True)
    if body.confirmed is not True:
        raise HTTPException(422, "Review both complete rules, original cases, shared starting bounds and the full local calculation first.")
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(value) != {"purpose", "prepared", "operation"} or value["purpose"] != PURPOSE:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This complete joint review is unavailable. Read its original request without repeating work.") from exc
    result = await run_in_threadpool(release._native_call, lambda: native.apply(request, value["prepared"], value["operation"]))
    return response(result)
