"""Officer-only review of a collected package and operator-recorded secure handoff."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import dsar_export_handoff as native
from maverick import privacy_ops
from pydantic import BaseModel, ConfigDict, Field

from . import auth

router = APIRouter(prefix="/api/v1/privacy/dsar", tags=["privacy-package-handoff"])


class HandoffIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    binding: str = Field(pattern=r"^[0-9a-f]{64}$")
    channel: Literal["secure_portal", "encrypted_email", "approved_transfer", "in_person"]
    handed_at: str = Field(min_length=10, max_length=50)
    reference: str = Field(min_length=3, max_length=200)
    reviewed: bool = Field(strict=True)
    identity_checked: bool = Field(strict=True)
    sent: bool = Field(strict=True)


class SavedStatementIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    receipt_id: str = Field(pattern=r"^[0-9a-f]{64}$")


def authority(request):
    # A custom privacy-officer role can hold both atoms. Ordinary operators
    # and read-only auditors cannot attest a personal-data package handoff.
    auth.require_permission(request, "operate")
    auth.require_permission(request, "audit")
    if not privacy_ops.enabled():
        from .feature_gate import feature_off
        raise feature_off("privacy_ops", "The privacy register")
    return auth.caller_principal(request) or "local-operator"


def call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except KeyError as exc:
        raise HTTPException(404, "This collected package is unavailable.") from exc
    except privacy_ops.RecordConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except (privacy_ops.PrivacyStateError, OSError) as exc:
        raise HTTPException(503, "The package or saved receipt could not be confirmed. Recheck its history before retrying; do not send the package again.") from exc


def state(request, request_id):
    authority(request)
    value = call(native.state, request_id, authorize=lambda: authority(request))
    from .identity_format import humanize_principal
    return {**value, "receipts": [{**row, "recorded_by": str(humanize_principal(row["actor"]))}
                                 for row in value["receipts"]]}


def record(request, request_id, body):
    from .app import _require_same_origin
    _require_same_origin(request)
    actor = authority(request)
    result = call(native.record_handoff, request_id, actor=actor, **body.model_dump(),
                  authorize=lambda: authority(request))
    return {**result, "message": "Your package handoff statement is recorded. This is not proof that the requester received it."}


def confirm_saved(request, request_id, receipt_id):
    from .app import _require_same_origin
    _require_same_origin(request)
    authority(request)
    result = call(native.confirm_saved, request_id, receipt_id=receipt_id, authorize=lambda: authority(request))
    return {**result, "message": "The saved statement and its activity record are confirmed. Nothing was sent; requester receipt remains unverified."}


def private(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store", "Pragma": "no-cache"})


@router.get("/{request_id}/package-handoff")
def get_handoff(request: Request, request_id: str):
    return private(state(request, request_id))


@router.post("/{request_id}/package-handoff")
def post_handoff(request: Request, request_id: str, body: HandoffIn):
    return private(record(request, request_id, body))


@router.post("/{request_id}/package-handoff/confirm-saved")
def post_saved(request: Request, request_id: str, body: SavedStatementIn):
    return private(confirm_saved(request, request_id, body.receipt_id))
