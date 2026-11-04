"""Ordinary full protected author form and original request-local outcomes."""
from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import request_program as native
from .scalar_wire import exact_integers

router = APIRouter()
PURPOSE = "lightwork.request-program-review.v1"


class ReviewIn(native.Choices):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class TokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=2 * 1024 * 1024)


class ApplyIn(TokenIn):
    confirmed: Literal[True]


def response(value):
    return JSONResponse(exact_integers(value), headers={"Cache-Control": "no-store, private"})


def material(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if set(value) != {"purpose", "prepared"} or value["purpose"] != PURPOSE:
            raise ValueError
        return value["prepared"]
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(409, "This complete review cannot be verified. Read the original request or review current choices again.") from exc


@router.get(native.PAGE)
def page(request: Request):
    from .app import templates
    native.authority(request)
    return templates.TemplateResponse(request, "request_program.html", {}, headers={"Cache-Control": "no-store, private"})


@router.get(native.API)
def listing(request: Request, flow: str = ""):
    native.authority(request, request.headers.get("X-Lightwork-Request-Context"))
    return response(native.call(lambda: native.listing(request, flow)))


@router.post(native.API + "/review")
def review(request: Request, body: ReviewIn):
    native.authority(request, body.context, write=True)
    if native.listing(request, body.flow).get("revision") != body.revision:
        raise HTTPException(409, "The available rules or original cases changed. Refresh choices before review; your entered work is kept.")
    value, changes = native.call(lambda: native.prepare(request, body.model_dump(exclude={"context", "revision"}), body.context))
    token = native.seal({"purpose": PURPOSE, "prepared": value})
    return response({"context": value["context"], "id": value["operation"], "token": token, "changes": changes})


@router.post(native.API + "/review-status")
def review_status(request: Request, body: TokenIn):
    value = material(body.token)
    native.call(lambda: native.guard(request, value))
    return response({"context": value["context"], "current": True})


@router.post(native.API + "/apply")
async def apply(request: Request, body: ApplyIn):
    value = await run_in_threadpool(native.call, lambda: native.apply(request, material(body.token)))
    return response(value)


@router.get(native.API + "/original/{identifier}")
def original(request: Request, identifier: str):
    native.authority(request, request.headers.get("X-Lightwork-Request-Context"))
    return response(native.call(lambda: native.original(request, identifier)))
