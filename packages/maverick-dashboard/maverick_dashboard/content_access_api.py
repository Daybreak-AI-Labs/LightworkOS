"""Direct controls for reviewed employee-content access; no implicit admin read."""
from __future__ import annotations

import json
import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from maverick.authority_effects import authority_effect_fence
from maverick.privacy_ops import RecordConflict
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth, content_access

router = APIRouter(tags=["employee-content-access"])


async def _call(operation):
    try:
        return await run_in_threadpool(operation)
    except RecordConflict as exc:
        raise HTTPException(409, "This request changed. Refresh and review its current state.") from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(503, "The request could not be confirmed. Refresh its saved status before trying again.") from exc


class AccessIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    resource_kind: Literal["goal", "subject_data", "approval"]
    resource_id: str = Field(min_length=1, max_length=400)
    purpose: Literal["employee_support", "incident_investigation", "rights_request", "action_review"]
    minutes: int = Field(default=15, ge=5, le=60)


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: int = Field(ge=1)
    decision: Literal["approve", "deny", "revoke", "retry_audit"]


def _actor(request, *, write=False):
    auth.require_permission(request, "view")
    actor = auth.caller_principal(request)
    if not actor:
        raise HTTPException(403, "Use a named account for independently reviewed content access.")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
    return actor


def _public(record, actor, is_admin):
    row = {key: record.get(key) for key in ("id", "revision", "requester", "owner", "resource_kind",
           "resource_id", "label", "purpose", "minutes", "status", "reviewed_by", "expires_at")}
    row["audit_pending"] = bool(record.get("_audit_pending"))
    row["can_review"] = content_access._reviewer_current({**record, "reviewed_by": actor})
    row["can_revoke"] = actor in {record["requester"], record["owner"]} or is_admin
    row["expired"] = record.get("expires_at", 0) <= time.time() if record.get("status") == "approved" else False
    return row


def _resources(*, approvals_only=False):
    from ._shared import _world
    from .compliance_controls_api import _list_people

    world = _world()
    resources = []
    for approval in world.list_approvals(limit=500):
        if approval.status != "pending":
            continue
        try:
            resources.append(content_access.approval_resource(approval, world))
        except HTTPException:
            continue
    if approvals_only:
        return resources
    resources += [{"resource_kind": "goal", "resource_id": str(goal.id),
                  "owner": goal.owner or "", "label": f"Task {goal.id} · {goal.status}"}
                 for goal in _world().list_goals(limit=500, order="desc")]
    for person in _list_people():
        resource_id = json.dumps([person["channel"], person["user"]], separators=(",", ":"))
        resources.append({"resource_kind": "subject_data", "resource_id": resource_id,
                          "owner": "channel:" + resource_id,
                          "label": person["person"] + " · " + person["channel_label"] + " data export"})
    return resources


@router.get("/content-access", response_class=HTMLResponse)
def access_page(request: Request):
    _actor(request)
    from .app import templates
    return templates.TemplateResponse(request, "content_access.html", {})


def access_state(request: Request):
    actor = _actor(request)
    is_admin = auth.has_global_permission(request, "admin")
    can_request = is_admin or auth.has_permission(request, "operate")
    def read():
        records = [_public(row, actor, is_admin) for row in content_access.STORE.list()
                   if row.get("tenant") == content_access.tenant()
                   and (is_admin or actor in {row.get("owner"), row.get("requester")} )]
        return {"enabled": content_access.enabled(), "can_request": can_request,
                "records": records, "resources": _resources(approvals_only=not is_admin) if can_request else [],
                "resource_window": "The latest 500 approval records are considered. Installation administrators may also request the latest 500 tasks and up to 500 chat identities. Content stays private until reviewed."}
    return read()


def create_access(request: Request, body: AccessIn, *, operation_id=None):
    actor = _actor(request, write=True)
    (auth.require_permission if body.resource_kind == "approval" else auth.require_global_permission)(request, "operate" if body.resource_kind == "approval" else "admin")
    if not content_access.enabled():
        raise HTTPException(403, "Content-access requests are disabled. An installation administrator can enable them in Settings.")
    def create():
        with authority_effect_fence():
            (auth.require_permission if body.resource_kind == "approval" else auth.require_global_permission)(request, "operate" if body.resource_kind == "approval" else "admin")
            resource = next((row for row in _resources(approvals_only=body.resource_kind == "approval") if row["resource_kind"] == body.resource_kind
                             and row["resource_id"] == body.resource_id), None)
            if resource is None:
                raise HTTPException(404, "The selected resource is no longer available. Refresh the list.")
            for existing in content_access.STORE.list():
                if (existing.get("tenant") == content_access.tenant()
                        and existing.get("requester") == actor
                        and existing.get("resource_kind") == body.resource_kind
                        and existing.get("resource_id") == body.resource_id
                        and existing.get("resource_revision") == resource.get("resource_revision")
                        and existing.get("purpose") == body.purpose
                        and existing.get("minutes") == body.minutes
                        and existing.get("status") == "requested"):
                    return _public(existing, actor, True)
            row = content_access.STORE.create({"id": content_access.STORE.new_id(),
                "tenant": content_access.tenant(), "requester": actor, **resource,
                "purpose": body.purpose, "minutes": body.minutes, "status": "requested", "operation_id": operation_id},
                action="request", actor=actor, max_records=10000)
            return _public(row, actor, True)
    return create()


def decide_current_access(request: Request, request_id: str, body: DecisionIn, *, operation_id=None):
    actor = _actor(request, write=True)
    def decide():
        with authority_effect_fence():
            _actor(request, write=True)
            is_admin = auth.has_global_permission(request, "admin")
            def mutate(row):
                if row.get("tenant") != content_access.tenant():
                    raise HTTPException(404, "No such content-access request.")
                reviewer = content_access._reviewer_current({**row, "reviewed_by": actor})
                if body.decision in {"approve", "deny"}:
                    if not reviewer:
                        raise HTTPException(403, "A different administrator or the content owner must review this request.")
                    if row["status"] != "requested":
                        raise HTTPException(409, "This request has already been reviewed. Refresh its status.")
                    if body.decision == "approve" and not content_access.enabled():
                        raise HTTPException(403, "Content-access requests are disabled.")
                    row["status"] = "approved" if body.decision == "approve" else "denied"
                    row["reviewed_by"] = actor
                    row["expires_at"] = time.time() + row["minutes"] * 60
                elif body.decision == "revoke":
                    if not is_admin and actor not in {row["requester"], row["owner"]}:
                        raise HTTPException(403, "You cannot revoke this request.")
                    row["status"] = "revoked"
                elif not is_admin and actor not in {row["requester"], row["owner"]}:
                    raise HTTPException(403, "You cannot repair this request.")
                row["decision_operation_id"] = operation_id
            row = content_access.STORE.update(request_id, mutate, expected_revision=body.expected_revision,
                                              action=body.decision, actor=actor)
            if row is None:
                raise HTTPException(404, "No such content-access request.")
            return _public(row, actor, is_admin)
    return decide()


@router.get("/api/v1/content-access")
async def access_status(request: Request):
    return await _call(lambda: access_state(request))


@router.post("/api/v1/content-access")
async def request_access(request: Request, body: AccessIn):
    return await _call(lambda: create_access(request, body))


@router.post("/api/v1/content-access/{request_id}/decision")
async def decide_access(request: Request, request_id: str, body: DecisionIn):
    auth.require_api_key_scope(request, "approvals:decide")
    return await _call(lambda: decide_current_access(request, request_id, body))
