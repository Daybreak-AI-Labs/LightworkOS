"""Complete native checker reviews and pure original reads."""
from __future__ import annotations

import json
import secrets
import time

from fastapi import APIRouter, HTTPException, Query, Request
from maverick import crypto_at_rest
from pydantic import Field
from starlette.concurrency import run_in_threadpool

from . import learning_calibration as native
from .learning_loop_api import ReviewedPassIn, _pass_response

router = APIRouter(prefix="/api/v1/learning-calibration", tags=["learning"])


class ReviewIn(native.Choices):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


@router.get("/current")
async def current(request: Request):
    return _pass_response(await run_in_threadpool(native.catalog, request))


@router.get("/context")
async def context(request: Request):
    return _pass_response({"context": native.authority(request)})


@router.get("/questions")
async def questions(request: Request, model: str = Query(max_length=200), offset: int = Query(default=0, ge=0)):
    return _pass_response(await run_in_threadpool(native.browse, request, model, offset))


@router.post("/review")
async def review(request: Request):
    native.authority(request)
    from .app import _require_same_origin
    _require_same_origin(request)
    parts, size = [], 0
    async for part in request.stream():
        size += len(part)
        if size > 1024 * 1024:
            raise HTTPException(413, "The complete checker review is limited to 1 MB and 64 labelled responses. Your draft is kept.")
        parts.append(part)
    try:
        body = ReviewIn.model_validate_json(b"".join(parts))
    except ValueError as exc:
        raise HTTPException(422, "Choose current questions, enter each complete response and its independent correct or incorrect label and basis.") from exc
    prepared = await run_in_threadpool(native.prepare, request, body.model_dump(exclude={"context", "revision"}), context=body.context, revision=body.revision)
    value = {"purpose": "lightwork.checker-calibration.v1", "operation": secrets.token_hex(16),
             "expires": time.time() + native.passes.TTL, "prepared": prepared}
    token = crypto_at_rest.seal_to_str(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 6 * 1024 * 1024:
        raise HTTPException(409, "The complete review could not be protected. Check encryption in Settings; no check was started.")
    return _pass_response({"context": prepared["context"], "token": token, "operation": value["operation"],
                           "review": native.review_rows(prepared), "expires": value["expires"]})


@router.post("/start")
async def start(request: Request, body: ReviewedPassIn):
    native.authority(request)
    from .app import _require_same_origin
    _require_same_origin(request)
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(value) != {"purpose", "operation", "expires", "prepared"} or value["purpose"] != "lightwork.checker-calibration.v1":
            raise ValueError
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(409, "This review could not be checked. Read the original request before preparing another answer check.") from exc
    return _pass_response(await run_in_threadpool(native.start, request, value["prepared"], value["operation"], expires=value["expires"]))


@router.get("/requests/{operation}")
async def original(request: Request, operation: str):
    return _pass_response(await run_in_threadpool(native.original, request, operation))
