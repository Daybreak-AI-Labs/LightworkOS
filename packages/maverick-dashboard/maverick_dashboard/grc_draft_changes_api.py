"""Protected complete-blueprint review, save and pure original receipt lookup."""
from __future__ import annotations

import json
import secrets
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import grc_draft_changes as native

router = APIRouter(prefix="/compliance/grc-draft-changes", tags=["grc-draft-changes"])
PURPOSE = "lightwork.grc-draft-save.v1"


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    kind: Literal["create", "replace"]
    studio: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    body: dict[str, Any]


class OriginalIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=240000)


class SaveIn(OriginalIn):
    confirmed: Literal[True]


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"})


def material(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if set(value) != {"purpose", "prepared", "operation"} or value["purpose"] != PURPOSE:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This complete save review could not be verified. Keep your entered work and review current choices; nothing was repeated.") from exc
    return value


@router.get("")
def catalog(request: Request):
    return response(native.catalog(request))


@router.post("/review")
def review(request: Request, body: ReviewIn):
    value, changes = native.prepare(request, body.kind, body.studio, body.body, body.context)
    saved = {"purpose": PURPOSE, "prepared": value, "operation": secrets.token_hex(16)}
    token = crypto_at_rest.seal_to_str(json.dumps(saved, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 240000:
        raise HTTPException(413, "The complete protected blueprint review is too large. Keep your entered work and use a smaller blueprint; nothing was saved.")
    return response({"context": value["context"], "operation": saved["operation"], "token": token, "changes": changes, "notice": native.NOTICE})


@router.post("/save")
def save(request: Request, body: SaveIn):
    value = material(body.token)
    return response(native.call(lambda: native.apply(request, value["prepared"], value["operation"])))


@router.post("/original")
def original(request: Request, body: OriginalIn):
    value = material(body.token)
    return response(native.call(lambda: native.original(request, value["prepared"], value["operation"])))


@router.post("/choices")
def choices(request: Request, body: OriginalIn):
    value = material(body.token)["prepared"]
    native.authority(request, value["context"])
    native.catalog(request)
    result = {"context": value["context"], "kind": value["kind"], "studio": value["studio"], "inputs": value["inputs"]}
    native.authority(request, value["context"])
    return response(result)


@router.post("/review-status")
def review_status(request: Request, body: OriginalIn):
    value = material(body.token)["prepared"]
    native.call(lambda: native._guard(request, value, native.store(request)))
    native.authority(request, value["context"])
    return response({"context": value["context"], "current": True})
