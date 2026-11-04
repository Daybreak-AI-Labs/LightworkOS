"""Named-recipient bundle preparation, acceptance, revocation and portable export."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from maverick import config
from maverick.deliverable_bundles import BundleDenied, DeliverableBundles, decoded_items
from maverick.paths import current_tenant_id_strict
from maverick.privacy_ops import RecordConflict
from pydantic import BaseModel, ConfigDict, Field

from . import auth, rbac
from .draft_api import context_for
from .identity_format import humanize_principal
from .product_errors import product_error

router = APIRouter(tags=["deliverable-bundles"])
BASE = "/api/v1/deliverable-bundles"


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    artifact_ids: list[int] = Field(default_factory=list, max_length=30)
    attachment_ids: list[int] = Field(default_factory=list, max_length=30)
    include_result: bool = False
    name: str = Field(min_length=1, max_length=160)
    recipient: str = Field(min_length=6, max_length=256)
    note: str = Field(min_length=1, max_length=4000)
    unresolved: str = Field(default="", max_length=4000)
    lifetime: Literal[3600, 86400, 604800] = 86400


class ShareInput(Choices):
    expected_review: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{12,100}$")


class RespondInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["accept", "revoke"]
    note: str = Field(default="", max_length=4000)
    expected_revision: int = Field(ge=1)
    operation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{12,100}$")


def service(request, *, write=False):
    from .app import _require_same_origin, _world
    from .project_reviews_api import _eligible

    auth.require_permission(request, "operate" if write else "view")
    if config.config_source_errors(include_tenant=True) or config.get_features().get("deliverable_bundles") is not True:
        raise product_error(403, "bundles_disabled", "Selected deliverable bundles are disabled or their configuration is unavailable.")
    if write:
        _require_same_origin(request)
    supplied = request.headers.get("X-Lightwork-Bundle-Context")
    if (write or supplied is not None) and not auth.constant_time_equals(supplied or "", context_for(request)):
        raise product_error(409, "context_changed", "Your account or workspace changed. Reload bundles before continuing.")
    tenant = current_tenant_id_strict()
    try:
        return DeliverableBundles(_world(), actor=auth.caller_principal(request),
                                   eligible=lambda actor, suite, permission, member: _eligible(tenant, actor, suite, permission, member))
    except BundleDenied as exc:
        raise product_error(403, "bundle_identity_required", str(exc)) from exc


def call(operation):
    try:
        return operation()
    except BundleDenied as exc:
        raise product_error(404, "bundle_unavailable", str(exc)) from exc
    except RecordConflict as exc:
        raise product_error(409, "bundle_changed", str(exc)) from exc
    except ValueError as exc:
        raise product_error(422, "bundle_input", str(exc)) from exc


def response(request, value):
    return JSONResponse({"context": context_for(request), **value}, headers={"Cache-Control": "private, no-store"})


def _public(record):
    payload = record["payload"]
    # Captured binary evidence is served only by a separately authorized file
    # response. The inventory does not turn it into conversation/model context.
    return {**record, "payload": {**payload, "items": [{k: v for k, v in item.items() if k != "content_base64"}
                                                        for item in payload["items"]]}}


@router.get("/deliverable-bundles")
def page(request: Request, goal: int | None = None):
    from .app import templates

    source = service(request)
    if goal is not None:
        call(lambda: source.candidates(goal))
    return templates.TemplateResponse(request, "deliverable_bundles.html",
                                      {"bundle_context": context_for(request), "bundle_goal": goal or ""},
                                      headers={"Cache-Control": "private, no-store"})


@router.get(BASE)
def inbox(request: Request):
    source = service(request)
    return response(request, {"items": call(source.inbox)})


@router.get(BASE + "/sources/{goal_id}")
def candidates(request: Request, goal_id: int):
    source = service(request)
    result = call(lambda: source.candidates(goal_id))
    goal = source.world.get_goal(goal_id)
    recipients = []
    for actor in rbac.list_tenant_roles(source.tenant):
        if actor == source.actor:
            continue
        try:
            source._allowed(actor, goal.domain, "view")
        except BundleDenied:
            continue
        identity = humanize_principal(actor)
        recipients.append({"id": actor, "name": identity.name + (" · " + identity.detail if identity.detail else "")})
    return response(request, {"source": result, "recipients": recipients})


@router.post(BASE + "/sources/{goal_id}/preview")
def preview(request: Request, goal_id: int, body: Choices):
    source = service(request, write=True)
    prepared = call(lambda: source.prepare(goal_id, **body.model_dump()))
    return response(request, {"preview": {**prepared, "items": [{k: v for k, v in item.items() if k != "content_base64"}
                                                               for item in prepared["items"]]}})


@router.post(BASE + "/sources/{goal_id}/share")
def share(request: Request, goal_id: int, body: ShareInput):
    source = service(request, write=True)
    record = call(lambda: source.create(goal_id, **body.model_dump()))
    return response(request, {"bundle": _public(record)})


@router.get(BASE + "/{bundle_id}")
def get(request: Request, bundle_id: str):
    source = service(request)
    return response(request, {"bundle": _public(call(lambda: source.get(bundle_id)))})


@router.post(BASE + "/{bundle_id}/respond")
def respond(request: Request, bundle_id: str, body: RespondInput):
    source = service(request, write=True)
    return response(request, {"bundle": _public(call(lambda: source.respond(bundle_id, **body.model_dump())))})


def _prepared_file(request, bundle_id, build):
    source = service(request)
    record = call(lambda: source.get(bundle_id))
    content = call(lambda: build(record))
    fresh = call(lambda: source.get(bundle_id))
    if fresh["revision"] != record["revision"] or fresh["stale"] != record["stale"]:
        raise product_error(409, "bundle_changed", "The bundle or its source changed during export. Your saved bundle is intact; prepare another download.")
    return content


@router.get(BASE + "/{bundle_id}/export")
def export(request: Request, bundle_id: str):
    from maverick.deliverable_bundle_export import export_zip

    content = _prepared_file(request, bundle_id, export_zip)
    return Response(content, media_type="application/zip", headers={"Cache-Control": "private, no-store",
                    "Content-Disposition": 'attachment; filename="selected-deliverable-bundle.zip"', "X-Content-Type-Options": "nosniff"})


@router.get(BASE + "/{bundle_id}/render")
def render(request: Request, bundle_id: str):
    from maverick.deliverable_bundle_export import rendered_preview

    content = _prepared_file(request, bundle_id, rendered_preview)
    return HTMLResponse(content, headers={"Cache-Control": "private, no-store",
                        "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'"})


@router.get(BASE + "/{bundle_id}/files/{item_key}")
def file(request: Request, bundle_id: str, item_key: str):
    from .attachment_headers import (
        attachment_content_disposition as _attachment_content_disposition,
    )

    source = service(request)
    record = call(lambda: source.get(bundle_id))
    selected = next(((item, data) for item, data in call(lambda: decoded_items(record)) if item["key"] == item_key), None)
    if selected is None:
        raise HTTPException(404, "This file is not part of the selected bundle.")
    call(lambda: source.get(bundle_id))
    item, content = selected
    return Response(content, media_type="application/octet-stream", headers={"Cache-Control": "private, no-store",
                    "Content-Disposition": _attachment_content_disposition(item["title"]), "X-Content-Type-Options": "nosniff"})
