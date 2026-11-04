"""Sealed full current vendor identity and activation reviews."""
from __future__ import annotations

import json
import re
import secrets
import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import vendor_profile as native

router = APIRouter(prefix="/vendor-profiles", tags=["vendor-profiles"])
TTL = 600


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["bind", "activate"]
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    intelligence: str | None = Field(default=None, max_length=128)
    lifecycle: str | None = Field(default=None, max_length=128)
    reason: str = Field(min_length=8, max_length=500)


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=2000000)
    confirmed: Literal[True]


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


def call(function):
    try:
        return function()
    except HTTPException:
        raise
    except (ValueError, native.vm.VendorManagementError) as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "The current vendor outcome could not be confirmed. Read its original before a separate new decision.") from exc


def seal(request, prepared):
    native.authority(request, write=True, admin=prepared["action"] == "bind")
    operation = secrets.token_hex(16)
    value = {"schema": "lightwork.vendor-profile-review.v1", "prepared": prepared, "operation": operation, "expires": time.time() + TTL}
    token = crypto_at_rest.seal_to_str(json.dumps(value, sort_keys=True, allow_nan=False))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "Enable at-rest encryption before retaining complete vendor reviews.")
    return {"context": prepared["context"], "operation": operation, "token": token,
            "changes": native.changes(prepared), "notice": native.NOTICE}


def open_review(request, token, *, original=False):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError("Unsealed vendor review")
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if value["schema"] != "lightwork.vendor-profile-review.v1" or not re.fullmatch(r"[a-f0-9]{32}", value["operation"]):
            raise ValueError("Unknown vendor review")
        prepared = value["prepared"]
        tenant, actor, context = native.authority(request, write=not original, admin=not original and prepared["action"] == "bind")
        if (tenant, actor, context) != (prepared["tenant"], prepared["actor"], prepared["context"]):
            raise HTTPException(403, "This vendor decision belongs to another account or workspace.")
        if not original and not time.time() < value["expires"] <= time.time() + TTL:
            raise HTTPException(409, "This vendor review expired. Read its original before a new intent.")
        return value
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(409, "The retained complete vendor review is unavailable.") from exc


@router.get("/{identifier}")
def profile(request: Request, identifier: str):
    return response(call(lambda: native.profile(request, identifier)))


@router.post("/{identifier}/review")
def review(request: Request, identifier: str, body: ReviewIn):
    return response(call(lambda: seal(request, native.prepare(request, identifier, **body.model_dump()))))


@router.post("/apply")
def apply(request: Request, body: ApplyIn):
    value = open_review(request, body.token)
    return response(call(lambda: native.apply(request, value["prepared"], value["operation"])))


@router.post("/read-original")
def original(request: Request, body: ApplyIn):
    value = open_review(request, body.token, original=True)
    return response(call(lambda: native.original(request, value["prepared"], value["operation"])))
