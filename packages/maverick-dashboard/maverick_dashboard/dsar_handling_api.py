"""Review an existing privacy outcome and recover its exact native original."""
from __future__ import annotations

import json
import math
import re
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from maverick import privacy_ops as native
from maverick.authority_effects import authority_effect_fence
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from .api_schemas import DsarCloseIn
from .draft_api import context_for
from .product_operations_dsar_status import KINDS

router = APIRouter(prefix="/api/v1/privacy/dsar", tags=["privacy-request-handling"])
PURPOSE = "privacy-outcome-review-v1"
TTL = 900


class OutcomeIn(DsarCloseIn):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: OutcomeIn


class OriginalIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=2097152)


def authority(request, *, historical=False):
    from .api_flow_operator_review import _workspace_authority
    from .privacy_access import privacy_ops_or_403 as _privacy_ops_or_403
    from .request_identity import request_actor as _request_actor

    with auth.fresh_configuration():
        principal = getattr(request.state, "principal", None)
        refresh = {"session": auth._session_principal, "invite": auth._invite_session_principal,
                   "proxy": auth._proxy_principal}.get((getattr(principal, "claims", None) or {}).get("via"))
        if refresh is not None:
            fresh = refresh(request)
            if fresh is None or fresh.principal != principal.principal:
                raise HTTPException(401, "Sign in again before continuing this privacy request.")
            request.state.principal = principal = fresh
        if principal is not None:
            auth._enforce_scim_active(principal)
            auth._enforce_workspace_policies(request, principal)
        auth.require_permission(request, "operate")
        _workspace_authority(request, auth.caller_principal(request) or "", current_tenant_id_strict() or "")
        if not historical:
            _privacy_ops_or_403()
        return _request_actor(request), context_for(request)


def state(request, request_id, *, historical=False):
    actor, context = authority(request, historical=historical)
    if re.fullmatch(r"DSAR-[a-f0-9]{10}", request_id) is None:
        raise HTTPException(404, "This privacy request is unavailable.")
    record = native.get_dsar(request_id)
    if record is None:
        raise HTTPException(404, "This privacy request is unavailable.")
    if authority(request, historical=historical) != (actor, context):
        raise HTTPException(409, "Your account, workspace or access changed. Read the request again.")
    return record, actor, context


def _private(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


def _fields(record, value, actor):
    result = native._dsar_outcome(record, value, actor=actor, now=time.time())
    return {key: item for key, item in result.items() if key not in {"recorded_by", "recorded_at"}}


def _open(token, request_id):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if (set(value) != {"purpose", "request_id", "actor", "context", "revision", "operation_id", "expires_at", "outcome"}
                or value["purpose"] != PURPOSE or value["request_id"] != request_id
                or not isinstance(value["outcome"], dict) or not isinstance(value["revision"], int)
                or isinstance(value["revision"], bool) or value["revision"] < 0
                or not isinstance(value["actor"], str) or not isinstance(value["context"], str)
                or re.fullmatch(r"[a-f0-9]{64}", value["context"]) is None
                or not isinstance(value["expires_at"], (int, float)) or not math.isfinite(value["expires_at"])
                or re.fullmatch(r"[a-f0-9]{32}", value["operation_id"]) is None):
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError, crypto_at_rest.EncryptionUnavailable) as exc:
        raise HTTPException(422, "The complete reviewed outcome could not be read. Keep the original and refresh the request.") from exc


def _check(request, review, *, historical=False):
    if authority(request, historical=historical) != (review["actor"], review["context"]):
        raise HTTPException(409, "Your account or workspace changed. Read the request again.")
    if not historical and time.time() >= review["expires_at"]:
        raise HTTPException(409, "This review expired. Read its original outcome before preparing another review.")


def record_reviewed(request, request_id, body):
    review = _open(body.review_token, request_id)
    with authority_effect_fence():
        _check(request, review)
        record, actor, _context = state(request, request_id)
        if _fields(record, body.model_dump(exclude={"review_token"}), actor) != review["outcome"]:
            raise HTTPException(409, "These details differ from the complete review. Review them again before closing.")
        return native.close_dsar(request_id, closed_by=actor, outcome=review["outcome"],
            operation_id=review["operation_id"], expected_revision=review["revision"],
            effect_guard=lambda: _check(request, review))


def close(request, request_id, body):
    """The existing Close endpoint enters this same native record writer."""
    if body is not None and body.review_token:
        return record_reviewed(request, request_id, body)
    with authority_effect_fence():
        actor, context = authority(request)
        def guard():
            if authority(request) != (actor, context):
                raise HTTPException(409, "Your account or workspace changed before the request could be closed.")
        return native.close_dsar(request_id, closed_by=actor,
            outcome=None if body is None else body.model_dump(exclude={"review_token"}), effect_guard=guard)


@router.get("/{request_id}/handling")
def get_state(request: Request, request_id: str):
    record, _actor, context = state(request, request_id)
    return _private({"context": context, "revision": record.get("revision", 0),
                     "request": KINDS.get(record.get("kind"), "Privacy request"),
                     "status": record["status"], "outcome_recorded": bool(record.get("outcome"))})


@router.post("/{request_id}/handling/review")
def review_outcome(request: Request, request_id: str, body: ReviewIn):
    from .app import _require_same_origin
    _require_same_origin(request)
    record, actor, context = state(request, request_id)
    if body.outcome.review_token:
        raise HTTPException(422, "Enter the outcome fields before preparing a new review.")
    if record.get("outcome"):
        raise HTTPException(409, "An outcome is already recorded. Read its original statement.")
    try:
        outcome = _fields(record, body.outcome.model_dump(exclude={"review_token"}), actor)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    material = {"purpose": PURPOSE, "request_id": request_id, "actor": actor, "context": context,
                "revision": record.get("revision", 0), "operation_id": secrets.token_hex(32 // 2),
                "expires_at": time.time() + TTL, "outcome": outcome}
    try:
        token = crypto_at_rest.seal_to_str(json.dumps(material, sort_keys=True, allow_nan=False))
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
    except (ValueError, crypto_at_rest.EncryptionUnavailable) as exc:
        raise HTTPException(503, "The outcome review could not be protected. Your request was not closed.") from exc
    _check(request, material)
    latest, _actor, _context = state(request, request_id)
    if latest.get("revision", 0) != material["revision"]:
        raise HTTPException(409, "This request changed while the review was prepared. Read it again.")
    rows = [KINDS.get(record.get("kind"), "Privacy request") + ": " + str(record.get("subject_id") or ""),
            "Outcome: " + {"answered": "Action completed and answer sent", "refused": "Refused with a lawful reason", "withdrawn": "Withdrawn by the requester", "no_response": "Closed without an answer"}[outcome["kind"]]]
    rows.extend(label + ": " + outcome[key] for key, label in (
        ("note", "Action or explanation"), ("answered_on", "Answer sent on"), ("reference", "Proof kept at"),
        ("lawful_basis", "Lawful reason"), ("erasure", "Deletion result")) if outcome.get(key))
    rows.append("This closes the request and records your statement. It does not change another system or send a message; requester receipt remains unverified.")
    return _private({"token": token, "context": context, "expires_at": material["expires_at"],
                     "outcome": outcome, "summary": "\n\n".join(rows)})


@router.post("/{request_id}/handling/original")
def read_original(request: Request, request_id: str, body: OriginalIn):
    from .app import _require_same_origin
    _require_same_origin(request)
    review = _open(body.token, request_id)
    _check(request, review, historical=True)
    record, _actor, _context = state(request, request_id, historical=True)
    original = native.dsar_close_original(record, operation_id=review["operation_id"],
        reviewed_revision=review["revision"], actor=review["actor"], outcome=review["outcome"])
    return _private({"confirmed": original is not None, "outcome": original,
                     "audit_pending": bool(record.get("_audit_pending")) if original else False,
                     "new_review_available": original is None and not record.get("outcome") and time.time() >= review["expires_at"],
                     "message": "This exact outcome was recorded. It is an operator statement; requester receipt and changes in another system remain unverified."
                     if original else "No original outcome confirms this close. Keep the review; do not send Close again blindly."})
