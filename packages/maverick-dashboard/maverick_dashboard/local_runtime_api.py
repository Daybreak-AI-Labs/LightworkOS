"""Ordinary, reviewed controls for the existing locally installed Launcher."""
from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import local_runtime_service as native

router = APIRouter(tags=["local-ai"])
BASE = "/api/v1/admin/local-ai"
PURPOSE = "lightwork.local-ai-review.v1"
TTL = 600


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    action: Literal["start", "stop", "configure"]
    enabled: bool | None = None
    engine: Literal["llamacpp", "vllm", "tgi"] | None = None
    model: str | None = Field(default=None, max_length=1024)


class ExecuteIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=12000)
    confirmed: bool


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "no-store, private"})


@router.get(native.PAGE, include_in_schema=False)
def page(request: Request):
    native.authority(request)
    from .app import templates
    return templates.TemplateResponse(request, "local_runtime.html", {})


@router.get("/static/lightwork-local-runtime.{extension}", include_in_schema=False)
def asset(extension: Literal["js", "css"]):
    return FileResponse(Path(__file__).parent / "static" / ("lightwork-local-runtime." + extension),
                        media_type="application/javascript" if extension == "js" else "text/css",
                        headers={"Cache-Control": "public, max-age=300"})


@router.get(BASE)
def current(request: Request):
    original = native.authority(request)
    state = native.state(request)
    state["models"] = [{"value": value, "label": label} for value, label in native.model_choices()]
    if native.authority(request) != original:
        raise HTTPException(409, "Your account or workspace changed. Refresh local AI.")
    return response(state)


@router.get(BASE + "/health")
def health(request: Request):
    return response(native.health(request))


@router.get(BASE + "/requests/{identifier}")
def receipt(request: Request, identifier: str):
    if not native._reference(identifier):
        raise HTTPException(404, "This local AI request is not available.")
    saved = native.receipt(request, identifier)
    if saved is None:
        raise HTTPException(404, "This request has no saved admission or result. Refresh current status before preparing another change.")
    return response(saved)


@router.post(BASE + "/review")
def review(request: Request, body: ReviewIn):
    native.authority(request, write=True)
    current = native.state(request)
    if current["context"] != body.context or current["revision"] != body.revision:
        raise HTTPException(409, "Your account, settings or service state changed. Refresh and review again.")
    if body.action == "configure":
        if body.enabled is None or body.engine is None or body.model is None:
            raise HTTPException(422, "Choose the program, model and whether local AI is on.")
        prepared = native.prepare_configuration(request, enabled=body.enabled, engine=body.engine, model=body.model)
    else:
        if body.enabled is not None or body.engine is not None or body.model is not None:
            raise HTTPException(422, "Review settings separately before starting or stopping the server.")
        prepared = native.prepare(request, body.action)
    if prepared["revision"] != body.revision or native.state(request)["revision"] != body.revision:
        raise HTTPException(409, "Local AI changed during preparation. Refresh and review again.")
    material = {"purpose": PURPOSE, "expires_at": time.time() + TTL, "review": prepared}
    try:
        token = crypto_at_rest.seal_to_str(json.dumps(material, sort_keys=True, allow_nan=False))
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
    except Exception as exc:
        raise HTTPException(503, "The review could not be protected. Nothing was started or changed.") from exc
    return response({"token": token, "request_id": prepared["id"], "summary": prepared["summary"], "expires_at": material["expires_at"]})


@router.post(BASE + "/execute")
def execute(request: Request, body: ExecuteIn):
    native.authority(request, write=True)
    if body.confirmed is not True:
        raise HTTPException(409, "Confirm this reviewed change. Nothing was changed.")
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        material = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if (type(material) is not dict or set(material) != {"purpose", "expires_at", "review"}
                or material["purpose"] != PURPOSE or type(material["expires_at"]) not in {int, float}
                or not math.isfinite(material["expires_at"]) or not time.time() < material["expires_at"] <= time.time() + TTL
                or type(material["review"]) is not dict):
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This review expired or cannot be verified. Check its saved request before preparing another change.") from exc
    return response(native.apply(request, material["review"]))
