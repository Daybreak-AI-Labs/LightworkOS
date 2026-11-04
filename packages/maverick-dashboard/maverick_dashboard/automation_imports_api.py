"""Protected ordinary automation export/account review and original receipts."""
from __future__ import annotations

import json
import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import automation_imports as native

router = APIRouter()
PURPOSE = "lightwork.automation-import-review.v1"


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=3_000_000)
    confirmed: bool


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


@router.get(native.API)
def catalog(request: Request):
    native.authority(request, request.headers.get("X-Lightwork-Import-Context"))
    return response(native.native_call(lambda: native.catalog(request)))


@router.get(native.API + "/history")
def history(request: Request):
    native.authority(request, request.headers.get("X-Lightwork-Import-Context"))
    return response(native.native_call(lambda: native.history(request)))


@router.get(native.API + "/original/{identifier}")
def original(request: Request, identifier: str):
    native.authority(request, request.headers.get("X-Lightwork-Import-Context"))
    return response(native.native_call(lambda: native.original(request, identifier)))


@router.post(native.API + "/review")
async def review(request: Request, body: native.Choices):
    prepared = await run_in_threadpool(native.native_call, lambda: native.prepare(request, body.model_dump()))
    operation = secrets.token_hex(16)
    rows = native.review_rows(prepared)
    return response({"context": prepared["context"], "operation": "AIR-" + operation, "token": native.seal({"purpose": PURPOSE, "prepared": prepared, "operation": operation}),
                     "changes": rows, "existing": [{"value": item["name"], "label": item["title"]} for item in prepared["items"] if item["prior"]]})


@router.post(native.API + "/review-activation")
def review_activation(request: Request, body: native.Activation):
    prepared = native.native_call(lambda: native.activation_material(request, body.model_dump(), require_unadmitted=True))
    operation = secrets.token_hex(16)
    return response({"context": prepared["context"], "operation": "AIR-" + operation, "token": native.seal({"purpose": PURPOSE, "prepared": prepared, "operation": operation}), "changes": native.activation_rows(prepared), "existing": [], "activation": True})


@router.post(native.API + "/apply")
async def apply(request: Request, body: ApplyIn):
    native.authority(request, write=True)
    if body.confirmed is not True:
        raise HTTPException(422, "Review every instruction, replacement and visual step before saving.")
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(value) != {"purpose", "prepared", "operation"} or value["purpose"] != PURPOSE:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "The complete import review is unavailable. Read its original record; nothing repeats automatically.") from exc
    action = native.activate if value["prepared"]["kind"] == "activate" else native.apply
    return response(await run_in_threadpool(native.native_call, lambda: action(request, value["prepared"], value["operation"])))
