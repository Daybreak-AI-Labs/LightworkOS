"""Ordinary reviewed generated-tool stopping and pure original readers."""
from __future__ import annotations

import json
import secrets
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import generated_tool_removal as native

router = APIRouter(prefix=native.API, tags=["generated-tool-removals"])
PURPOSE = "lightwork.generated-tool-removal.v1"


class ReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tool: str = Field(pattern=r"^[a-f0-9]{64}$")
    action: Literal["remove", "cleanup"]
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    acknowledge_unknown: bool = False


class ApplyInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=64000)
    confirmed: Literal[True]


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


@router.get("")
def listing(request: Request):
    return response(native.listing(request))


@router.get("/history")
def history(request: Request):
    return response(native.history(request))


@router.get("/original/{reference}")
def original(request: Request, reference: str):
    return response(native.original(request, reference))


@router.post("/review")
def review(request: Request, body: ReviewInput):
    prepared = native.prepare(request, body.tool, body.action, context=body.context, acknowledge_unknown=body.acknowledge_unknown)
    operation = secrets.token_hex(16)
    material = {"purpose": PURPOSE, "prepared": prepared, "operation": operation}
    token = crypto_at_rest.seal_to_str(json.dumps(material, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 64000:
        raise HTTPException(503, "The complete private removal review could not be retained. No change was admitted.")
    native._guard(request, prepared, native.budget(), exact=True)
    return response({"context": prepared["context"], "reference": prepared["id"] + "|" + operation,
                     "token": token, "changes": native.changes(prepared)})


@router.post("/apply")
def apply(request: Request, body: ApplyInput):
    native.authority(request, write=True)
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        material = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(material) != {"purpose", "prepared", "operation"} or material["purpose"] != PURPOSE:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This complete review could not be verified. Read the original or review current files again.") from exc
    return response(native.apply(request, material["prepared"], material["operation"]))
