"""Protected complete native review and original lesson-test reads."""
from __future__ import annotations

import json
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from maverick import crypto_at_rest
from pydantic import ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import learning_transfers as native
from .learning_loop_api import ReviewedPassIn, _pass_response

router = APIRouter(prefix="/api/v1/learning-transfers", tags=["learning"])


class ReviewIn(native.Choices):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class StartIn(ReviewedPassIn):
    model_config = ConfigDict(extra="forbid", strict=True)


@router.get("/current")
async def current(request: Request):
    return _pass_response(await run_in_threadpool(native.catalog, request))


@router.post("/review")
async def review(request: Request):
    native.authority(request)
    from .app import _require_same_origin
    _require_same_origin(request)
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > 3 * 1024 * 1024:
            raise HTTPException(413, "Choose a plain text instructions copy up to 1 MB.")
        chunks.append(chunk)
    try:
        body = ReviewIn.model_validate_json(b"".join(chunks))
    except ValueError as exc:
        raise HTTPException(422, "Choose two current models and enter the receiving model's standing instructions.") from exc
    prepared = await run_in_threadpool(native.prepare, request,
        body.model_dump(exclude={"context", "revision"}), context=body.context, revision=body.revision)
    value = {"purpose": "lightwork.lesson-transfer.v1", "operation": secrets.token_hex(16),
             "expires": time.time() + native.passes.TTL, "prepared": prepared}
    token = crypto_at_rest.seal_to_str(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 6 * 1024 * 1024:
        raise HTTPException(409, "The complete review could not be protected. Check encryption in Settings; your draft is kept and no test was started.")
    return _pass_response({"context": prepared["context"], "token": token, "operation": value["operation"], "review": native.review_rows(prepared)})


@router.post("/start")
async def start(request: Request, body: StartIn):
    native.authority(request)
    from .app import _require_same_origin
    _require_same_origin(request)
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(value) != {"purpose", "operation", "expires", "prepared"} or value["purpose"] != "lightwork.lesson-transfer.v1":
            raise ValueError
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(409, "The review could not be checked. Read the original request before preparing another test.") from exc
    return _pass_response(await run_in_threadpool(native.start, request, value["prepared"], value["operation"], expires=value["expires"]))


@router.get("/requests/{operation}")
async def original(request: Request, operation: str):
    return _pass_response(await run_in_threadpool(native.original, request, operation))
