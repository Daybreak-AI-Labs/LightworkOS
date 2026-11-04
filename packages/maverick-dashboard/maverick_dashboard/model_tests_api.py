"""Native administrator controls for explicit, bounded model generation tests."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import model_tests as service
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field
from starlette.background import BackgroundTask

from . import auth
from .draft_api import context_for

router = APIRouter(prefix="/api/v1/models/tests", tags=["model-tests"])


class ContextIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReviewIn(ContextIn):
    model: str = Field(min_length=1, max_length=200)
    kind: str = Field(pattern=r"^(generation|vision)$")


class ExecuteIn(ContextIn):
    confirmed: bool


def authority(request, expected=None):
    auth.require_global_permission(request, "admin")
    actor = auth._authorization_principal(request)
    if expected is not None and context_for(request) != expected:
        raise HTTPException(409, "The signed-in account or workspace changed. Reopen Models before proceeding.")
    return actor


def guard_for(request, expected):
    def guard():
        from maverick.authority_effects import authority_effect_fence
        with authority_effect_fence():
            authority(request, expected)
    return guard


def _same_origin(request):
    from .app import _require_same_origin
    _require_same_origin(request)


def _response(value, background=None):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"}, background=background)


def call(function, *args):
    try:
        return function(*args)
    except HTTPException:
        raise
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "Model test storage or policy is unavailable. No repeat request was sent; check the existing test history.") from exc


@router.get("")
def status(request: Request):
    authority(request)
    context = context_for(request)
    reason = ""
    try:
        service.policy()
    except (PermissionError, ValueError):
        reason = "Bounded model tests are turned off or their settings are unavailable. Enable them in All settings. Existing receipts remain available."
    values = call(service.history, context)
    authority(request, context)
    return _response({"context": context, "enabled": not reason, "blocked": reason,
                      "kinds": service.KINDS, "checks": [service.public(row) for row in reversed(values)]})


@router.post("/review")
def review(request: Request, body: ReviewIn):
    _same_origin(request)
    authority(request, body.context)
    row = call(service.prepare, body.context, body.model, body.kind, guard_for(request, body.context))
    authority(request, body.context)
    return _response({"check": service.public(row)})


def start(request, context, identity, confirmed):
    if confirmed is not True:
        raise HTTPException(400, "Review and confirm the potentially paid model test first.")
    actor = authority(request, context)
    from maverick.authority_effects import authority_effect_fence
    with authority_effect_fence():
        row, claimed = call(service.claim, context, identity, guard_for(request, context))
    background = BackgroundTask(service.run, context, identity, actor, current_tenant_id_strict(), guard_for(request, context)) if claimed else None
    return {"check": service.public(row), "recovered": not claimed}, background


@router.post("/{identity}/execute")
def execute(request: Request, identity: str, body: ExecuteIn):
    _same_origin(request)
    result, background = start(request, body.context, identity, body.confirmed)
    authority(request, body.context)
    return _response(result, background)


@router.post("/{identity}/cancel")
def cancel(request: Request, identity: str, body: ContextIn):
    _same_origin(request)
    authority(request, body.context)
    row = call(service.cancel, body.context, identity, guard_for(request, body.context))
    return _response({"check": service.public(row)})
