"""Named administrator controls for departure inventory and retained handoffs."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from maverick.authority_effects import authority_effect_fence
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from . import employee_departures as departures
from .content_access_api import _call

router = APIRouter(tags=["employee-departures"])


class PreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    principal: str = Field(min_length=6, max_length=400)


class BeginIn(PreviewIn):
    custodian: str = Field(min_length=6, max_length=400)
    snapshot: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirm_preservation: Literal[True]


class RevisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: int = Field(ge=1)


class HandoffIn(RevisionIn):
    item_key: str = Field(min_length=1, max_length=64)
    owner: str = Field(min_length=6, max_length=400)
    disposition: Literal["retained", "transfer_reported", "revocation_reported"]
    evidence: str = Field(min_length=10, max_length=1000)


def _authority(request, *, write=False):
    auth.require_global_permission(request, "admin")
    actor = auth.caller_principal(request)
    if not actor:
        raise HTTPException(403, "Use a named installation administrator for employee departures.")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
        if not departures.enabled():
            raise HTTPException(403, "Employee departure controls are off. Enable them in Settings before making changes.")
    return actor


@router.get("/users/departures", response_class=HTMLResponse)
def page(request: Request):
    _authority(request)
    from .app import templates
    return templates.TemplateResponse(request, "employee_departures.html", {})


@router.get("/api/v1/employee-departures")
async def status(request: Request):
    _authority(request)
    def read():
        return {"enabled": departures.enabled(), "people": departures.candidates(),
                "cases": [departures.public(row) for row in departures.STORE.list()]}
    return await _call(read)


@router.post("/api/v1/employee-departures/preview")
async def preview(request: Request, body: PreviewIn):
    _authority(request, write=True)
    return await _call(lambda: departures.preview(body.principal))


@router.post("/api/v1/employee-departures")
async def begin(request: Request, body: BeginIn):
    actor = _authority(request, write=True)
    def apply():
        row = departures.begin(body.principal, body.custodian, body.snapshot, actor,
                               lambda: _authority(request, write=True))
        return departures.public(row)
    return await _call(apply)


@router.post("/api/v1/employee-departures/{case_id}/handoff")
async def handoff(request: Request, case_id: str, body: HandoffIn):
    actor = _authority(request, write=True)
    def save():
        row = departures.record_handoff(case_id, body.expected_revision,
            item_key=body.item_key, owner=body.owner, disposition=body.disposition,
            evidence=body.evidence, actor=actor, authorize=lambda: _authority(request, write=True))
        if row is None:
            raise HTTPException(404, "No such departure case.")
        return departures.public(row)
    return await _call(save)


@router.post("/api/v1/employee-departures/{case_id}/retry-audit")
async def retry_audit(request: Request, case_id: str, body: RevisionIn):
    # A no-op revision update drains the existing outbox. It never repeats an
    # uncertain identity, connection or scheduler effect.
    actor = _authority(request, write=True)
    def retry():
        with authority_effect_fence():
            _authority(request, write=True)
            row = departures.STORE.update(case_id, lambda _: None,
                expected_revision=body.expected_revision, action="departure_audit_retry", actor=actor)
            if row is None:
                raise HTTPException(404, "No such departure case.")
            return departures.public(row)
    return await _call(retry)


class CloseIn(RevisionIn):
    snapshot: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirm_retained_obligations: Literal[True]


@router.post("/api/v1/employee-departures/{case_id}/refresh-inventory")
async def refresh_inventory(request: Request, case_id: str, body: RevisionIn):
    actor = _authority(request, write=True)
    return await _call(lambda: departures.public(departures.refresh_inventory(
        case_id, body.expected_revision, actor, lambda: _authority(request, write=True))))


@router.post("/api/v1/employee-departures/{case_id}/closure-preview")
async def closure_preview(request: Request, case_id: str, body: RevisionIn):
    _authority(request, write=True)
    return await _call(lambda: departures.closure_preview(case_id, body.expected_revision))


@router.post("/api/v1/employee-departures/{case_id}/close")
async def close_case(request: Request, case_id: str, body: CloseIn):
    actor = _authority(request, write=True)
    return await _call(lambda: departures.public(departures.close_case(
        case_id, body.expected_revision, body.snapshot, actor, lambda: _authority(request, write=True))))
