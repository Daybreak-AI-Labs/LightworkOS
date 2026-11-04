"""Protected ordinary controls for native component evidence and rechecks."""
from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import flow_requalification as native
from . import local_flow_promotions as release
from .scalar_wire import exact_integers

router = APIRouter()
PURPOSE = "lightwork.rule-requalification-review.v1"


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    kind: Literal["retain", "recheck", "withdraw"]
    flow: str = Field(min_length=1, max_length=128)
    practice: str = Field(default="", max_length=128)
    evidence: str = Field(default="", max_length=64)
    semantic_reuse: bool = False


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=120000)
    confirmed: Literal[True]


class ReviewStatusIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=120000)


def response(value):
    return JSONResponse(exact_integers(value), headers={"Cache-Control": "private, no-store"})


@router.get(native.PAGE)
def page(request: Request):
    from .app import templates
    native.authority(request)
    return templates.TemplateResponse(request, "flow_requalification.html", {}, headers={"Cache-Control": "private, no-store"})


@router.get(native.API)
def listing(request: Request, flow: str = ""):
    native.authority(request, request.headers.get("X-Lightwork-Requalification-Context"))
    return response(release._native_call(lambda: native.listing(request, flow)))


@router.get(native.API + "/history")
def history(request: Request):
    native.authority(request, request.headers.get("X-Lightwork-Requalification-Context"))
    return response(native.history(request))


@router.get(native.API + "/original/{identifier}")
def original(request: Request, identifier: str):
    native.authority(request, request.headers.get("X-Lightwork-Requalification-Context"))
    return response(release._native_call(lambda: native.original(request, identifier)))


@router.post(native.API + "/review")
def review(request: Request, body: ReviewIn):
    prepared, changes = release._native_call(lambda: native.prepare(request, body.kind, body.flow, body.practice, body.evidence, context=body.context, semantic_reuse=body.semantic_reuse))
    operation = native.operation()
    token = crypto_at_rest.seal_to_str(json.dumps({"purpose": PURPOSE, "prepared": prepared, "operation": operation}, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 120000:
        raise HTTPException(413, "The complete review exceeds this protected form's limit. Choose a smaller rule workflow or use its complete comparison.")
    return response({"context": prepared["context"], "operation": "FRQ-" + operation, "token": token, "changes": changes})


def material(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if value["purpose"] != PURPOSE or set(value) != {"purpose", "prepared", "operation"}:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "The complete reviewed rule check could not be verified. Read the original result or review current choices.") from exc
    return value


@router.post(native.API + "/review-status")
def review_status(request: Request, body: ReviewStatusIn):
    value = material(body.token)
    release._native_call(lambda: native._guard(request, value["prepared"]))
    return response({"context": value["prepared"]["context"], "current": True})


@router.post(native.API + "/apply")
def apply(request: Request, body: ApplyIn):
    native.authority(request, write=True)
    value = material(body.token)
    return response(release._native_call(lambda: native.apply(request, value["prepared"], value["operation"])))
