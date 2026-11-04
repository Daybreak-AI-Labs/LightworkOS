"""Ordinary current-version removal review and original result routes."""
from __future__ import annotations

import json
import secrets
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import manual_skill_removal as native

router = APIRouter(prefix="/manual-skill-removals", tags=["manual-skill-removals"])
PURPOSE = "lightwork.manual-skill-removal.v1"


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=96)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


class RemoveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=24000)
    confirmed: Literal[True]


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


@router.get("")
def catalog(request: Request):
    return response(native.catalog(request))


@router.get("/requests/{operation}")
def original(request: Request, operation: str):
    return response(native.original(request, operation))


@router.post("/review")
def review(request: Request, body: ReviewIn):
    prepared = native.prepare(request, body.name, context=body.context)
    material = {"purpose": PURPOSE, "prepared": prepared, "operation": secrets.token_hex(16)}
    token = crypto_at_rest.seal_to_str(json.dumps(material, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 24000:
        raise HTTPException(503, "This complete removal review could not be retained securely. Nothing was removed.")
    return response({"context": prepared["context"], "operation": material["operation"], "token": token,
                     "changes": native.changes(request, prepared), "notice": native.NOTICE})


def remove_sealed(request, body, *, expected_name=None):
    native.authority(request, write=True)
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        material = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(material) != {"purpose", "prepared", "operation"} or material["purpose"] != PURPOSE:
            raise ValueError
        if expected_name is not None and material["prepared"]["name"] != expected_name:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This removal review could not be verified. Review the current skill or read its original result.") from exc
    return response(native.apply(request, material["prepared"], material["operation"]))


@router.post("/remove")
def remove(request: Request, body: RemoveIn):
    return remove_sealed(request, body)
