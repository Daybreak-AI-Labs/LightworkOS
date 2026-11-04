"""Authenticated, owner-scoped questions and reviewed unpublished flow drafts."""
from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Request
from fastapi import Path as ApiPath
from maverick.audit.errors import AuditRefused
from maverick.governed_operations import ServiceContext, digest
from maverick.governed_records import RecordConflict
from maverick.learning_guard import Halted
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.responses import JSONResponse

from .auth import caller_principal, require_permission, role_for_principal

router = APIRouter(prefix="/flows", tags=["flow-operator-review"])
FlowPath = Annotated[str, ApiPath(min_length=1, max_length=256)]
ReviewPath = Annotated[str, ApiPath(pattern=r"^LOQ-[0-9a-f]{32}$")]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class OperatorQuestionIn(_StrictModel):
    node_id: str = Field(min_length=1, max_length=256)
    version: int = Field(ge=1)
    revision: str = Field(min_length=1, max_length=256)
    max_probes: int = Field(default=256, ge=1, le=4096)


class OperatorAnswerIn(_StrictModel):
    expected_revision: int = Field(ge=1)
    output: Any
    reviewed: bool
    rationale: str = Field(min_length=1, max_length=2000)

    @field_validator("output")
    @classmethod
    def scalar_output(cls, value):
        if type(value) not in (str, int, bool):
            raise ValueError("output must be a strict JSON integer, string or boolean")
        if type(value) is str and len(value) > 1024:
            raise ValueError("output string exceeds limit")
        if type(value) is int and abs(value) > 10**24:
            raise ValueError("output integer exceeds limit")
        return value


def _workspace_authority(request: Request, actor: str, tenant: str) -> str:
    """Freshly bind active workspace and any selected-workspace membership."""
    from maverick.tenant.registry import TenantSuspended, assert_tenant_active

    from . import workspace_tenants

    source = getattr(request.state, "workspace_tenant_source", "") or "operator_floor"
    generation = 0
    try:
        # Existing operator floors/per-principal isolation do not require an
        # invented selection membership. The registry's existing active-state
        # hook is a no-op where no registry has been provisioned.
        assert_tenant_active(tenant)
        if source == "principal_selection":
            if not workspace_tenants.principal_can_select(actor, tenant):
                raise HTTPException(status_code=403, detail="workspace membership is no longer active")
            selected, generation = workspace_tenants.get_selection_binding(actor)
            if selected != tenant:
                raise HTTPException(status_code=409, detail="active workspace selection changed")
    except TenantSuspended as exc:
        raise HTTPException(status_code=403, detail="workspace is no longer active") from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="workspace authority is unavailable") from exc
    return "sha256:" + digest({
        "actor": actor, "tenant": tenant, "source": source, "generation": generation,
    })


def _service(request: Request, flow_id: str, *, human=False):
    from maverick.flow import store
    from maverick.flow.operator_review import OperatorReviewService

    from .flows_api import _assert_flow_access, _require_flows

    actor = caller_principal(request)
    if not actor:
        raise HTTPException(status_code=401, detail="an authenticated user identity is required")
    require_permission(request, "operate")
    _require_flows()
    try:
        tenant = current_tenant_id_strict()
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=403, detail="active tenant authority is unavailable") from exc
    if not tenant:
        raise HTTPException(status_code=409, detail="select an active tenant for operator review")
    workspace_authority = _workspace_authority(request, actor, tenant)
    current = store.load_flow(flow_id)
    if current is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, current)
    if not current.owner:
        raise HTTPException(status_code=409, detail="operator review requires an owned flow")
    role = role_for_principal(actor)
    if not role:
        raise HTTPException(status_code=403, detail="current role authority is unavailable")
    ctx = ServiceContext(
        tenant=tenant, actor=actor, resource_owner=current.owner,
        credential_authority="pure_operator_no_credentials",
        credential_ref="not_applicable", human=human,
        authorization_role=role, authorization_policy="dashboard_flow_owner_or_admin_v1",
        budget_authority="bounded_local_no_provider", workspace_authority=workspace_authority,
    )

    def authorize(context, capability, resource):
        if (context != ctx or resource != flow_id or capability not in {
            "flow.operator.request", "flow.operator.answer", "flow.operator.read",
            "flow.operator.export",
        }):
            raise HTTPException(status_code=404, detail="no such operator review")
        if (caller_principal(request) != actor or current_tenant_id_strict() != tenant
                or role_for_principal(actor) != role
                or _workspace_authority(request, actor, tenant) != workspace_authority):
            raise HTTPException(status_code=403, detail="operator review authority changed")
        require_permission(request, "operate")
        latest = store.load_flow(flow_id)
        if latest is None or latest.owner != ctx.resource_owner:
            raise HTTPException(status_code=404, detail="no such flow")
        _assert_flow_access(request, latest)
        if capability == "flow.operator.answer" and ctx.human is not True:
            raise HTTPException(status_code=403, detail="an explicit reviewed answer is required")
        return True

    return OperatorReviewService(authorize), ctx


def _call(operation: Callable):
    try:
        return operation()
    except HTTPException:
        raise
    except RecordConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except AuditRefused as exc:
        detail = {"status": "audit_unavailable", "message": str(exc)}
        if getattr(exc, "question_id", None):
            detail.update(status="audit_pending", review_id=exc.question_id)
        raise HTTPException(status_code=503, detail=detail) from exc
    except Halted as exc:
        raise HTTPException(status_code=409, detail="operator review is stopped") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="no such operator review") from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _record_response(record: dict):
    if record.get("status") == "audit_pending":
        # The transition may already be committed. Preserve its actual state;
        # never label it an uncommitted failure or return an unreceipted draft.
        return JSONResponse(record, status_code=503)
    return record


@router.post("/{flow_id}/operator-questions", response_model=None)
def request_operator_question(request: Request, flow_id: FlowPath, payload: OperatorQuestionIn):
    service, ctx = _call(lambda: _service(request, flow_id))
    result = _call(lambda: service.request(
        ctx, flow_id, payload.node_id, max_probes=payload.max_probes,
        expected_flow_version=payload.version, expected_flow_revision=payload.revision,
    ))
    return _record_response(result)


@router.get("/{flow_id}/operator-questions/{review_id}", response_model=None)
def get_operator_question(request: Request, flow_id: FlowPath, review_id: ReviewPath):
    service, ctx = _call(lambda: _service(request, flow_id))
    return _record_response(_call(lambda: service.get(ctx, review_id)))


@router.post("/{flow_id}/operator-questions/{review_id}/answer", response_model=None)
def answer_operator_question(request: Request, flow_id: FlowPath,
                             review_id: ReviewPath, payload: OperatorAnswerIn):
    if payload.reviewed is not True:
        raise HTTPException(status_code=400, detail="reviewed must be true for an explicit answer")
    service, ctx = _call(lambda: _service(request, flow_id, human=True))
    result = _call(lambda: service.answer(
        ctx, review_id, payload.output, expected_revision=payload.expected_revision,
        rationale=payload.rationale,
    ))
    return _record_response(result)


@router.get("/{flow_id}/operator-questions/{review_id}/draft", response_model=None)
def export_operator_draft(request: Request, flow_id: FlowPath, review_id: ReviewPath):
    service, ctx = _call(lambda: _service(request, flow_id))
    draft = _call(lambda: service.export_draft(ctx, review_id))
    return {"flow": draft.to_dict(), "published": False, "saved": False}
