"""Ordinary protected form and pure original-result reads."""
from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import recovery_visibility as native

router = APIRouter()
PURPOSE = "lightwork.recovery-visibility-review.v1"


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    quorum: int = Field(ge=1, le=2)
    steps: int = Field(ge=1, le=3)
    observations: list[str] = Field(min_length=1, max_length=5)


class TokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=8192)


class ApplyIn(TokenIn):
    confirmed: Literal[True]


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


def material(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError("protected review required")
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if type(value) is not dict or set(value) != {"purpose", "prepared"} or value["purpose"] != PURPOSE:
            raise ValueError("unsupported review")
        return value["prepared"]
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(409, "The protected practice review cannot be verified. Read the original result or review current choices.") from exc


@router.get(native.PAGE)
def page(request: Request):
    from .app import templates
    native.authority(request)
    return templates.TemplateResponse(request, "recovery_visibility.html", {"observations": native.engine.OBSERVATIONS}, headers={"Cache-Control": "private, no-store"})


@router.get(native.API)
def listing(request: Request):
    native.authority(request, request.headers.get("X-Lightwork-Visibility-Context"))
    return response(native.call(lambda: native.listing(request)))


@router.post(native.API + "/review")
def review(request: Request, body: ReviewIn):
    value, changes = native.call(lambda: native.prepare(request, body.model_dump(exclude={"context"}), body.context))
    token = crypto_at_rest.seal_to_str(json.dumps({"purpose": PURPOSE, "prepared": value}, allow_nan=False))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 8192:
        raise HTTPException(503, "The complete practice review could not be protected. Nothing ran.")
    return response({"context": value["context"], "id": value["operation"], "token": token, "changes": changes})


@router.post(native.API + "/review-status")
def review_status(request: Request, body: TokenIn):
    value = material(body.token)
    native.call(lambda: native._guard(request, value))
    return response({"context": value["context"], "current": True})


@router.post(native.API + "/apply")
def apply(request: Request, body: ApplyIn):
    return response(native.call(lambda: native.apply(request, material(body.token))))


@router.get(native.API + "/original/{identifier}")
def original(request: Request, identifier: str):
    native.authority(request, request.headers.get("X-Lightwork-Visibility-Context"))
    return response(native.call(lambda: native.original(request, identifier)))
