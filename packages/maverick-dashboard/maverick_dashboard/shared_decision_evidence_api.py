"""Ordinary finite decision review and original-result recovery."""
from __future__ import annotations

import json
import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import config, crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from . import shared_decision_evidence_store as native
from .draft_api import context_for
from .tools_ops_api import same_origin

router = APIRouter(tags=["shared-decision-evidence"])
PURPOSE = "lightwork.shared-decision-review.v1"


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    action: str = Field(pattern=r"^(create|edit|consent|withdraw|refresh|acquire|answer|remove|qualify|acquire_batch|acknowledge)$")
    arguments: dict
    id: str | None = Field(default=None, pattern=r"^SDE-[a-f0-9]{32}$")


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=600000)
    confirmed: bool


def _response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


def _call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except HTTPException:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(422, "The complete model or saved evidence could not be validated. Check every entered field; no data was truncated.") from exc
    except Exception as exc:
        raise HTTPException(503, "The original result is uncertain. Read its saved original request before another change; nothing will repeat automatically.") from exc


@router.get("/decision-evidence")
def page(request: Request):
    from .app import templates
    auth.require_permission(request, "operate")
    enabled = not config.config_source_errors(include_tenant=True) and config.get_features().get("shared_decision_evidence") is True
    return templates.TemplateResponse(request, "decision_evidence.html",
        {"decision_enabled": enabled, "decision_context": context_for(request) if enabled else "", "notice": native.NOTICE},
        headers={"Cache-Control": "private, no-store"})


@router.get("/api/v1/decision-evidence")
def listing(request: Request):
    return _response(_call(native.listing, request))


@router.get("/api/v1/decision-evidence/history")
def history(request: Request):
    return _response(_call(native.historical_requests, request))


@router.get("/api/v1/decision-evidence/author")
def author(request: Request, review: str = ""):
    return _response(_call(native.author_handoff, request, review))


@router.get("/api/v1/decision-evidence/{identifier}")
def read(request: Request, identifier: str):
    return _response(_call(native.view, request, identifier))


@router.get("/api/v1/decision-evidence/{identifier}/requests/{operation}")
def original(request: Request, identifier: str, operation: str):
    return _response(_call(native.original, request, identifier, operation))


@router.post("/api/v1/decision-evidence/review")
def review(request: Request, body: ReviewIn):
    same_origin(request)
    native.authority(request, body.context)
    prepared = _call(native.prepare, request, body.action, body.arguments, body.id)
    operation = secrets.token_hex(16)
    material = {"purpose": PURPOSE, "prepared": prepared, "operation": operation}
    token = crypto_at_rest.seal_to_str(json.dumps(material, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 600000:
        raise HTTPException(503, "This complete review could not be retained securely. Nothing was confirmed.")
    identifier = prepared["id"] or native._identifier(prepared["context"], prepared["actor"], operation)
    return _response({"context": prepared["context"], "id": identifier, "operation": operation,
                      "token": token, "changes": native.review_changes(prepared)})


@router.post("/api/v1/decision-evidence/apply")
def apply(request: Request, body: ApplyIn):
    same_origin(request)
    if body.confirmed is not True:
        raise HTTPException(409, "Confirm the complete reviewed model or change first.")
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(value) != {"purpose", "prepared", "operation"} or value["purpose"] != PURPOSE:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This reviewed change could not be verified. Read its original result or prepare a current review.") from exc
    return _response(_call(native.apply, request, value["prepared"], value["operation"]))
