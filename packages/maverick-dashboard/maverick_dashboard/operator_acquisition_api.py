"""Ordinary complete teaching-question reviews, native effects and recovery."""
from __future__ import annotations

import json
import secrets

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from maverick import config, crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import operator_acquisition as native
from .tools_ops_api import same_origin

router = APIRouter(tags=["operator-acquisition"])
PURPOSE = "lightwork.operator-acquisition-review.v1"


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    flow: str = Field(min_length=1, max_length=256)
    id: str = Field(default="", pattern=r"^(?:OAC-[a-f0-9]{32})?$")
    action: str = Field(pattern=r"^(create|plan|answer|test|qualify|scope|withdraw|acknowledge|remove)$")
    arguments: dict


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=6000000)
    confirmed: bool


def call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except HTTPException:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(422, "Check the complete source, answer and supported teaching bounds. An unknown result is not a policy; nothing was shortened.") from exc
    except Exception as exc:
        raise HTTPException(503, "No complete result is available. If a request was admitted, read its original before a separate reviewed intent; no work repeats automatically.") from exc


def response(value):
    return JSONResponse(native.public(value), headers={"Cache-Control": "private, no-store"})


@router.get(native.PAGE, response_class=HTMLResponse)
def page(request: Request):
    from .app import templates
    actor, context = native.authority(request, historical=True)
    enabled = not config.config_source_errors(include_tenant=True) and config.get_features().get(native.FEATURE) is True
    return templates.TemplateResponse(request, "operator_acquisition.html", {"request": request, "enabled": enabled, "context": context, "actor": actor},
        headers={"Cache-Control": "private, no-store"})


@router.get(native.API + "/choices")
def choices(request: Request, flow: str = Query(default="", max_length=256)):
    return response(call(native.listing, request, flow))


@router.get(native.API + "/history")
def history(request: Request):
    return response(call(native.history, request))


@router.get(native.API + "/author")
def author(request: Request, flow: str = Query(min_length=1, max_length=256), context: str = Query(pattern=r"^[a-f0-9]{64}$"), binding: str = Query(pattern=r"^[a-f0-9]{64}$")):
    return response(call(native.author_handoff, request, flow, context, binding))


@router.get(native.API + "/{identifier}/draft")
def draft(request: Request, identifier: str):
    return response(call(native.draft, request, identifier))


@router.get(native.API + "/{identifier}")
def read(request: Request, identifier: str):
    return response(call(native.view, request, identifier))


@router.get(native.API + "/original/{identifier}/{operation}")
def original(request: Request, identifier: str, operation: str):
    return response(call(native.original, request, identifier, operation))


@router.post(native.API + "/review")
def review(request: Request, body: ReviewIn):
    same_origin(request)
    native.authority(request, body.context, historical=body.action in {"withdraw", "remove", "acknowledge"})
    prepared = call(native.prepare, request, body.flow, body.id, body.action, body.arguments)
    operation = secrets.token_hex(16)
    token = crypto_at_rest.seal_to_str(json.dumps({"purpose": PURPOSE, "prepared": prepared, "operation": operation}, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 6000000:
        raise HTTPException(413, "The full review could not be retained securely. Nothing was omitted or confirmed.")
    return response({"context": prepared["context"], "id": prepared["id"], "operation": operation, "token": token, "changes": call(native.changes, prepared)})


@router.post(native.API + "/apply")
def apply(request: Request, body: ApplyIn):
    same_origin(request)
    if body.confirmed is not True:
        raise HTTPException(409, "Confirm the complete current source and question review first.")
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(value) != {"purpose", "prepared", "operation"} or value["purpose"] != PURPOSE:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This full review could not be verified. Read its original or prepare a current review.") from exc
    return response(call(native.apply, request, value["prepared"], value["operation"]))
