"""Ordinary reviewed distinction discovery and retained native comparison cells."""
from __future__ import annotations

import json
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from maverick.audit.errors import AuditRefused
from maverick.governed_records import RecordConflict
from pydantic import BaseModel, ConfigDict, Field

from . import learning_distinctions as native
from . import local_flow_comparisons as comparisons

router = APIRouter()
API = "/api/v1/learning/distinctions"
PURPOSE = "lightwork.learning-distinction-review.v1"


class ReviewIn(native.Choices):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class BuildIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=2 * 1024 * 1024)
    confirmed: bool


class RegionsIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    flow_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    comparisons: list[str] = Field(min_length=1, max_length=20)


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "no-store, private"})


def call(function):
    try:
        return function()
    except HTTPException:
        raise
    except PermissionError as exc:
        raise HTTPException(403, "Current access, learning permission or a source is unavailable. Refresh before continuing.") from exc
    except LookupError as exc:
        raise HTTPException(404, "The selected retained evidence is unavailable.") from exc
    except (RecordConflict, AuditRefused) as exc:
        raise HTTPException(409, "A source, learning permission or its saved review is no longer current. Refresh before continuing; nothing was repeated.") from exc
    except (TypeError, ValueError) as exc:
        raise HTTPException(409, "These examples do not fit the supported two-action teaching rules. Choose matching reviewed inputs and action contracts; nothing was published.") from exc
    except Exception as exc:
        raise HTTPException(503, "The current evidence could not be checked. Your selection is kept. Check the original request before another attempt.") from exc


@router.get(native.PAGE)
def page(request: Request):
    from .app import templates
    native.authority(request)
    return templates.TemplateResponse(request, "learning_distinctions.html", {}, headers={"Cache-Control": "no-store, private"})


@router.get(API)
def catalog(request: Request, flow_id: str = ""):
    return response(call(lambda: native.options(request, flow_id) if flow_id else native.flows(request)))


def prepared(request, body):
    native.authority(request, body.context)
    if native.options(request, body.flow_id)["revision"] != body.revision:
        raise HTTPException(409, "The workflow or examples changed. Refresh before reviewing; your selection is kept.")
    return native.source(request, body.model_dump(exclude={"context", "revision"}), context=body.context)


@router.post(API + "/inspect")
async def inspect(request: Request):
    body = await native.teach._body(request, ReviewIn, 16384)
    return response(call(lambda: native.preview(prepared(request, body))))


@router.post(API + "/review")
async def review(request: Request):
    body = await native.teach._body(request, ReviewIn, 16384)
    selected = call(lambda: prepared(request, body))
    if selected["fields"] is None:
        return response({"review": native.preview(selected), "ready": False})
    material = {"purpose": PURPOSE, "prepared": selected, "operation": secrets.token_hex(16), "expires": time.time() + native.TTL}
    token = crypto_at_rest.seal_to_str(json.dumps(material, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 2 * 1024 * 1024:
        raise HTTPException(503, "This complete review could not be prepared securely. Choose fewer or smaller examples.")
    return response({"token": token, "operation": material["operation"], "context": selected["context"], "review": native.preview(selected), "ready": True})


@router.post(API + "/build")
async def build(request: Request):
    body = await native.teach._body(request, BuildIn, 2 * 1024 * 1024 + 4096)
    if body.confirmed is not True:
        raise HTTPException(422, "Review and confirm the complete examples and proposed observations first.")
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        material = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(material) != {"purpose", "prepared", "operation", "expires"} or material["purpose"] != PURPOSE:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This review is unavailable. Review current examples again.") from exc
    return response(call(lambda: native.build(request, material["prepared"], material["operation"], expires=material["expires"])))


@router.get(API + "/original/{operation}")
def original(request: Request, operation: str):
    return response(call(lambda: native.original(request, operation)))


@router.get(API + "/original/{operation}/package")
def download(request: Request, operation: str):
    row = call(lambda: native.owned(request, operation))
    if row is None or row["state"] != "saved" or row.get("_audit_pending"):
        raise HTTPException(409, "The original package is not confirmed as saved.")
    payload = call(lambda: native.package(request, row))
    return JSONResponse(payload["package"], headers={"Cache-Control": "no-store, private", "Content-Disposition": 'attachment; filename="reviewed-learning-package.json"'})


@router.get(API + "/comparisons")
def retained_comparisons(request: Request, flow_id: str):
    native.authority(request)
    return response(call(lambda: comparisons.history(request, flow_id)))


@router.post(API + "/regions")
async def regions(request: Request):
    body = await native.teach._body(request, RegionsIn, 16384)
    native.authority(request, body.context)
    return response(call(lambda: native.regions(request, body.flow_id, body.comparisons)))
