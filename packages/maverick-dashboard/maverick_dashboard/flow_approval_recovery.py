"""Request a fresh bounded review for an unchanged open-ended flow pause."""
from __future__ import annotations

import hmac
import time
from contextlib import nullcontext

from fastapi import APIRouter, HTTPException, Request
from maverick import audit
from maverick.approval_cards import ApprovalCardError, digest, validate_approval_card
from maverick.flow import store
from maverick.flow.approvals import review_expired_paused_approval
from pydantic import BaseModel, ConfigDict, Field

from . import automation_queue as aq
from .approval_authority import require_approval_authority

router = APIRouter()


class RefreshIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    binding: str = Field(pattern=r"^[0-9a-f]{64}$")
    confirmed: bool


def _owned(request, run_id):
    from . import api

    api._require_flows()
    authority = require_approval_authority(request, action="flow.approval.refresh", resource=run_id)
    return api._load_owned_run(request, run_id), authority.principal


def _guard(run):
    return (nullcontext() if run.dry_run else
            store.published_flow_guard(run.flow_id, expected_release_id=run.release_id))


def _review(run, actor):
    flow = store.load_flow_snapshot(run.definition_digest)
    card = review_expired_paused_approval(run, flow, decided_by=actor)
    return card, aq.flow_approval_binding(run)


def state(request, run_id):
    run, actor = _owned(request, run_id)
    try:
        with _guard(run):
            card, binding = _review(run, actor)
        return {"binding": binding, "summary": card["summary"], "run_id": run.run_id,
                "flow_id": run.flow_id,
                "message": "Request a new seven-day review of this paused work. This does not approve, restart or repeat any step."}
    except (ApprovalCardError, store.FlowSnapshotError) as exc:
        raise HTTPException(409, "This review cannot be refreshed because the work, access or deadline changed. Reopen the run to check its current state.") from exc


def _record(run, actor, binding, new_binding, stage):
    if not audit.record("flow_approval_refreshed", agent=actor, actor=actor,
                        flow_id=run.flow_id, run_id=run.run_id, cursor=run.cursor,
                        previous_binding=binding, approval_binding=new_binding, stage=stage):
        raise HTTPException(503, "The review receipt could not be saved. Reopen the run before trying again.")


def refresh(request, run_id, payload):
    from .app import _require_same_origin

    _require_same_origin(request)
    if payload.confirmed is not True:
        raise HTTPException(422, "Confirm the fresh review request first.")
    run, actor = _owned(request, run_id)
    try:
        with store.run_lock(run.run_id), _guard(run):
            run, actor = _owned(request, run_id)
            receipt = (run.human or {}).get("approval_refresh") or {}
            if (run.status == "paused_approval" and receipt.get("previous_binding") == payload.binding
                    and receipt.get("actor") == actor):
                card = aq.current_flow_approval_card(run)
                if (receipt.get("approval_binding") != card["binding_sha256"]
                        or receipt.get("authority") != digest(aq._flow_approval_authority(run))):
                    raise ApprovalCardError("the recovered review changed")
                _record(run, actor, payload.binding, card["binding_sha256"], "completed")
                return {"status": "ready", "message": "The fresh review is ready. Review it before deciding."}
            card, binding = _review(run, actor)
            if not hmac.compare_digest(binding, payload.binding):
                raise ApprovalCardError("the reviewed pause changed")
            renewed = {key: value for key, value in card.items() if key != "binding_sha256"}
            renewed["expires_at"] = time.time() + 7 * 24 * 3600
            renewed["binding_sha256"] = digest(renewed)
            validate_approval_card(renewed)
            _record(run, actor, binding, renewed["binding_sha256"], "prepared")
            run.human = {**(run.human or {}), "approval_card": renewed,
                         "approval_refresh": {"previous_binding": binding,
                                              "approval_binding": renewed["binding_sha256"], "actor": actor,
                                              "authority": digest(aq._flow_approval_authority(run))}}
            store.save_run(run)
            _record(run, actor, binding, renewed["binding_sha256"], "completed")
    except (ApprovalCardError, store.FlowSnapshotError) as exc:
        raise HTTPException(409, "This review changed or cannot be refreshed. Reopen the run and request a current review.") from exc
    return {"status": "ready", "message": "The fresh review is ready. Review it before deciding."}


@router.get("/flows/runs/{run_id}/approval-refresh")
def preview_endpoint(request: Request, run_id: str):
    return state(request, run_id)


@router.post("/flows/runs/{run_id}/approval-refresh")
def refresh_endpoint(request: Request, run_id: str, payload: RefreshIn):
    return refresh(request, run_id, payload)
