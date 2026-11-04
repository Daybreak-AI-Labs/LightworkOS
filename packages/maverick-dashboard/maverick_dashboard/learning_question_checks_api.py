"""Protected complete question checks and pure retained-original reads."""
from __future__ import annotations

import base64
import json
import secrets
import time

from fastapi import APIRouter, HTTPException, Query, Request
from maverick import crypto_at_rest
from pydantic import Field
from starlette.concurrency import run_in_threadpool

from . import learning_question_checks as native
from .learning_loop_api import ReviewedPassIn, _pass_response

router = APIRouter(prefix="/api/v1/learning-question-checks", tags=["learning"])


class ReviewIn(native.Choices):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


@router.get("/current")
async def current(request: Request):
    return _pass_response(await run_in_threadpool(native.catalog, request))


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
        if size > 65536:
            raise HTTPException(413, "Choose at most 16 saved questions for one complete review. Your choices are kept.")
        parts.append(part)
    try:
        body = ReviewIn.model_validate_json(b"".join(parts))
    except ValueError as exc:
        raise HTTPException(422, "Choose a current model, saved questions and the number of answers to check.") from exc
    prepared = await run_in_threadpool(native.prepare, request, body.model_dump(exclude={"context", "revision"}), context=body.context, revision=body.revision)
    operation = secrets.token_hex(16)
    value = {"purpose": "lightwork.question-quality.v1", "operation": operation, "expires": time.time() + native.passes.TTL, "prepared": prepared}
    with crypto_at_rest.deployment_key_scope():
        sealed = crypto_at_rest.seal_bound(json.dumps(value, ensure_ascii=False).encode(), "question-quality:" + operation)
    token = operation + ":" + base64.b64encode(sealed).decode()
    return _pass_response({"context": prepared["context"], "operation": operation, "token": token,
                           "review": native.review_rows(prepared), "expires": value["expires"]})


@router.post("/start")
async def start(request: Request, body: ReviewedPassIn):
    native.authority(request)
    from .app import _require_same_origin
    _require_same_origin(request)
    try:
        operation, encoded = body.token.split(":", 1)
        native.questions._request_id(operation)
        with crypto_at_rest.deployment_key_scope():
            value = json.loads(crypto_at_rest.unseal_bound(base64.b64decode(encoded, validate=True), "question-quality:" + operation))
        if set(value) != {"purpose", "operation", "expires", "prepared"} or value["purpose"] != "lightwork.question-quality.v1" or value["operation"] != operation:
            raise ValueError
    except (ValueError, TypeError, KeyError, HTTPException, crypto_at_rest.EncryptionUnavailable) as exc:
        raise HTTPException(409, "This review could not be checked. Read the original question check before starting another one.") from exc
    return _pass_response(await run_in_threadpool(native.start, request, value["prepared"], operation, expires=value["expires"]))


@router.get("/requests/{operation}")
async def original(request: Request, operation: str):
    return _pass_response(await run_in_threadpool(native.original, request, operation))
