"""Ordinary Promise addition reviews and original-result recovery."""
from __future__ import annotations

import json
import secrets

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import commitment_capability_store as native
from .tools_ops_api import same_origin

router = APIRouter(tags=["commitment-capability"])
PURPOSE = "lightwork.commitment-capability-review.v1"
API = "/api/v1/commitment-capability"


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    parent: str = Field(pattern=r"^CMV-[a-f0-9]{48}$")
    action: str = Field(pattern=r"^(create|edit|report|test|scope|withdraw|release|remove)$")
    arguments: dict


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=2500000)
    confirmed: bool


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


def call(function, *args):
    try:
        return function(*args)
    except HTTPException:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(422, "Check the complete entered review or supported local rule test. Unknown outcomes are not observations; no fields were truncated.") from exc
    except Exception as exc:
        raise HTTPException(503, "The exact original result is uncertain. Read its retained request before any separate reviewed test; nothing will repeat automatically.") from exc


@router.get(API + "/choices")
def choices(request: Request):
    return response(call(native.test_choices, request))


@router.get(API + "/history")
def history(request: Request):
    return response(call(native.history, request))


@router.get(API + "/author/{parent}")
def author(request: Request, parent: str, context: str = Query(pattern=r"^[a-f0-9]{64}$"),
           parent_binding: str = Query(pattern=r"^[a-f0-9]{64}$")):
    return response(call(native.author_handoff, request, parent, context, parent_binding))


@router.get(API + "/{parent}")
def read(request: Request, parent: str):
    return response(call(native.view, request, parent))


@router.get(API + "/original/{identifier}/{operation}")
def original(request: Request, identifier: str, operation: str):
    return response(call(native.original, request, identifier, operation))


@router.post(API + "/review")
def review(request: Request, body: ReviewIn):
    same_origin(request)
    native.authority(request, body.context)
    prepared = call(native.prepare, request, body.parent, body.action, body.arguments)
    operation = secrets.token_hex(16)
    value = {"purpose": PURPOSE, "prepared": prepared, "operation": operation}
    token = crypto_at_rest.seal_to_str(json.dumps(value, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 2500000:
        raise HTTPException(413, "The complete review could not be retained securely. Nothing was confirmed or dropped.")
    return response({"context": prepared["context"], "id": prepared["id"], "operation": operation, "token": token, "changes": call(native.changes, prepared)})


@router.post(API + "/apply")
def apply(request: Request, body: ApplyIn):
    same_origin(request)
    if body.confirmed is not True:
        raise HTTPException(409, "Confirm the complete accepted-work and qualification review first.")
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(value) != {"purpose", "prepared", "operation"} or value["purpose"] != PURPOSE:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This complete review could not be verified. Read its original or prepare a current review.") from exc
    return response(call(native.apply, request, value["prepared"], value["operation"]))
