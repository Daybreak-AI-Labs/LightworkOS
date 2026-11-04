"""Ordinary fixed private-check authoring, review, custody and approved download."""
from __future__ import annotations

import json
import secrets

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from maverick import config, crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from . import private_task_computation_store as native
from .draft_api import context_for
from .tools_ops_api import same_origin

router = APIRouter(tags=["private-task-computation"])
API, PAGE, PURPOSE = "/api/v1/private-task-computation", "/private-task-computation", "lightwork.private-task-review.v1"


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    identifier: str | None = Field(default=None, pattern=r"^PTC-[a-f0-9]{32}$")
    action: str = Field(pattern=r"^(create|edit|run|release|withdraw|scope|acknowledge|remove)$")
    arguments: dict


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=1500000)
    confirmed: bool


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


def call(function, *arguments):
    try:
        return function(*arguments)
    except HTTPException:
        raise
    except native.knowledge_task_context.SourceContextUnavailable as exc:
        raise HTTPException(403, "Current inherited source permission does not allow this analysis or release. No entered consent can override it.") from exc
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise HTTPException(422, "Check the complete CSV, declared possibilities and conditions. Missing, duplicate or out-of-range values are refused; no source was shortened.") from exc
    except Exception as exc:
        raise HTTPException(503, "The requested result could not be confirmed. If a request was admitted, read its exact original; it will not repeat automatically.") from exc


@router.get(PAGE, include_in_schema=False)
def page(request: Request):
    from .app import templates
    auth.require_permission(request, "operate")
    enabled = not config.config_source_errors(include_tenant=True) and config.get_features().get(native.FEATURE) is True
    return templates.TemplateResponse(request, "private_task_computation.html", {"private_check_context": context_for(request),
        "private_check_enabled": enabled, "private_check_notice": native.NOTICE}, headers={"Cache-Control": "private, no-store"})


@router.get(API + "/choices")
def choices(request: Request):
    return response(call(native.choices, request))


@router.get(API + "/source")
def source(request: Request, goal: int = Query(ge=1), attachment: int = Query(ge=1)):
    return response(call(native.inspect_source, request, goal, attachment))


@router.get(API + "/history")
def history(request: Request):
    return response(call(native.history, request))


@router.get(API + "/author")
def author(request: Request, context: str = Query(pattern=r"^[a-f0-9]{64}$"),
           identifier: str | None = Query(default=None, pattern=r"^PTC-[a-f0-9]{32}$"),
           binding: str | None = Query(default=None, pattern=r"^[a-f0-9]{64}$")):
    native.authority(request, context)
    value = call(native.author_handoff, request, identifier)
    if value["binding"] != binding:
        raise HTTPException(409, "The complete current intent changed before opening its form.")
    return response(value)


@router.get(API + "/original/{identifier}/{operation}")
def original(request: Request, identifier: str, operation: str):
    return response(call(native.original, request, identifier, operation))


@router.get(API + "/download/{identifier}")
def download(request: Request, identifier: str):
    data = call(native.download, request, identifier)
    # No dynamic filename, source identifiers, hashes, traces, private names or
    # input values enter this outward file or its identifying headers.
    return Response(data, media_type="text/csv", headers={"Cache-Control": "private, no-store",
        "Content-Disposition": 'attachment; filename="approved-result.csv"', "X-Content-Type-Options": "nosniff"})


@router.get(API + "/{identifier}")
def read(request: Request, identifier: str):
    return response(call(native.view, request, identifier))


@router.post(API + "/review")
def review(request: Request, body: ReviewIn):
    same_origin(request)
    native.authority(request, body.context)
    prepared = call(native.prepare, request, body.identifier, body.action, body.arguments)
    operation = secrets.token_hex(16)
    token = crypto_at_rest.seal_to_str(json.dumps({"purpose": PURPOSE, "prepared": prepared, "operation": operation}, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 1500000:
        raise HTTPException(413, "This complete review could not be retained securely. No fields were dropped or confirmed.")
    return response({"context": prepared["context"], "id": prepared["id"], "operation": operation, "token": token, "changes": native.changes(prepared)})


@router.post(API + "/apply")
def apply(request: Request, body: ApplyIn):
    same_origin(request)
    if body.confirmed is not True:
        raise HTTPException(409, "Confirm the complete fixed source, conditions, permission and action review first.")
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(value) != {"purpose", "prepared", "operation"} or value["purpose"] != PURPOSE:
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "The complete reviewed intent could not be verified. Read its original or prepare a current review.") from exc
    return response(call(native.apply, request, value["prepared"], value["operation"]))
