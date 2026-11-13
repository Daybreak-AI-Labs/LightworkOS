"""Explicit browser approval and the native pairing/renewal protocol."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from . import device_pairing as service
from .device_actions import router as device_actions_router
from .device_work_actions import router as device_work_router
from .draft_api import context_for
from .reviewed_stop import router as reviewed_stop_router

router = APIRouter()

router.include_router(device_actions_router)
router.include_router(device_work_router)
router.include_router(reviewed_stop_router)


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Begin(Input):
    label: str = Field(min_length=1, max_length=80)


class Confirm(Input):
    code: str = Field(pattern=r"^[A-Z2-9]{12}$")
    context: str = Field(min_length=1, max_length=128)
    allow_actions: bool = False
    allow_new_tasks: bool = False
    allow_approvals: bool = False


class Remove(Input):
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    context: str = Field(min_length=1, max_length=128)


class Renew(Input):
    generation: int = Field(ge=1, le=10000)


def _private(response):
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Referrer-Policy"] = "no-referrer"


def _principal(request):
    actor = auth.caller_principal(request)
    # An API key must not approve, list or revoke devices: a paired device is a
    # longer-lived credential that would outlive the key's scope and revocation.
    if (not actor or getattr(request.state, "paired_device_id", None)
            or auth.api_key_permissions(request) is not None):
        raise HTTPException(403, "Sign in to your named account to manage paired devices.")
    auth.require_permission(request, "view")
    return actor


def _binding(request, context):
    from .app import _require_same_origin
    _require_same_origin(request)
    if not auth.constant_time_equals(context, context_for(request)):
        raise HTTPException(409, "Your account or workspace changed. Review pairing again.")


@router.post("/api/v1/devices/pairing/begin")
def begin(request: Request, response: Response, body: Begin):
    _private(response)
    if not body.label.isprintable() or body.label != body.label.strip():
        raise HTTPException(422, "Give this device a short name without hidden characters.")
    # The connected network peer is a rate bucket, never forwarded identity.
    return service.begin(body.label, request.client.host if request.client else "unknown")


@router.post("/api/v1/devices/pairing/poll")
def poll(request: Request, response: Response):
    _private(response)
    return service.poll(auth._bearer_token(request))


@router.get("/devices")
def page(request: Request):
    from .app import templates
    _principal(request)
    return templates.TemplateResponse(request, "devices.html", {},
        headers={"Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer"})


@router.get("/api/v1/devices")
def state(request: Request, response: Response):
    _private(response)
    return {"devices": service.devices(_principal(request)), "context": context_for(request)}


@router.get("/api/v1/devices/review")
def review(request: Request, response: Response, code: str):
    _private(response)
    return {**service.review(_principal(request), code), "context": context_for(request)}


@router.post("/api/v1/devices/confirm")
def confirm(request: Request, response: Response, body: Confirm):
    _private(response)
    _binding(request, body.context)
    return service.confirm(_principal(request), body.code, actions=body.allow_actions,
                           new_tasks=body.allow_new_tasks, approvals=body.allow_approvals)


@router.post("/api/v1/devices/remove")
def remove(request: Request, response: Response, body: Remove):
    _private(response)
    _binding(request, body.context)
    return service.revoke(_principal(request), body.id)


@router.post("/api/v1/devices/renew")
def renew(request: Request, response: Response, body: Renew):
    _private(response)
    if not getattr(request.state, "paired_device_id", None):
        raise HTTPException(403, "Only a paired device can renew its own connection.")
    return service.renew(auth._bearer_token(request), body.generation)


@router.post("/api/v1/devices/remove-self")
def remove_self(request: Request, response: Response):
    _private(response)
    ident = getattr(request.state, "paired_device_id", None)
    if not ident:
        raise HTTPException(403, "Only a paired device can remove its own connection.")
    return service.revoke(auth.caller_principal(request), ident)
