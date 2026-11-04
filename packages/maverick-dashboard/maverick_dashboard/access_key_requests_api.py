"""Protected native access-key form review and original metadata."""
from __future__ import annotations

import json
import secrets
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import access_key_requests as native

router = APIRouter(prefix="/access-key-requests", tags=["access-key-requests"])
PURPOSE = "lightwork.access-key-request.v1"


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    action: Literal["create", "rotate", "revoke"]
    label: str | None = Field(default=None, max_length=80)
    scopes: list[str] | None = Field(default=None, max_length=6)
    owner: str | None = Field(default=None, max_length=512)
    expires_in_days: int | None = Field(default=None, ge=1)
    workspace: str = Field(default="", max_length=128)
    key_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{16}$")


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=24000)
    confirmed: Literal[True]


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


@router.get("")
def catalog(request: Request):
    return response(native.api_keys_api._run(native.catalog, request))


@router.get("/requests/{operation}")
def original(request: Request, operation: str):
    return response(native.api_keys_api._run(native.original, request, operation))


@router.post("/review")
def review(request: Request, body: ReviewIn):
    prepared, material = native.api_keys_api._run(native.prepare, request, body.model_dump(exclude_none=True))
    operation = secrets.token_hex(16)
    token = crypto_at_rest.seal_to_str(json.dumps({"purpose": PURPOSE, "operation": operation, "prepared": prepared}, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 24000:
        raise HTTPException(503, "This complete review could not be retained securely. No key was changed.")
    return response({"context": prepared["context"], "operation": operation, "token": token, "changes": native.review_rows(material)})


def apply_sealed(request, body, *, action=None, key_id=None):
    native.authority(request, write=True)
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(value) != {"purpose", "operation", "prepared"} or value["purpose"] != PURPOSE:
            raise ValueError
        if action is not None and value["prepared"]["body"]["action"] != action:
            raise ValueError
        if key_id is not None and value["prepared"]["body"]["key_id"] != key_id:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This exact review is unavailable. Review current choices or read its original record.") from exc
    return response(native.api_keys_api._run(native.apply, request, value["prepared"], value["operation"]))


@router.post("/apply")
def apply(request: Request, body: ApplyIn):
    return apply_sealed(request, body)
