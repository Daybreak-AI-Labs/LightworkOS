"""Authenticated enrollment and review of retained native action episodes."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Request
from fastapi import Path as ApiPath
from maverick.audit.errors import AuditRefused
from maverick.governed_operations import ServiceContext
from maverick.governed_records import RecordConflict
from maverick.learning_guard import Halted
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import JSONResponse

from .api_flow_operator_review import _workspace_authority
from .auth import caller_principal, require_permission, role_for_principal

router = APIRouter(prefix="/flows", tags=["flow-action-episodes"])
FlowPath = Annotated[str, ApiPath(min_length=1, max_length=256)]
RunPath = Annotated[str, ApiPath(min_length=1, max_length=256)]
_CAPABILITIES = frozenset({
    "flow.episode.enroll", "flow.episode.read", "flow.episode.detail",
    "flow.episode.review", "flow.episode.export",
    "flow.episode.grant", "flow.episode.export_signed", "flow.episode.withdraw", "flow.episode.current",
})
_PENDING_KEYS = frozenset({
    "schema", "id", "revision", "status", "committed_status", "audit_status",
    "binding", "retain_until", "step_count", "completed_steps", "expected_steps",
    "episode_sha256", "source_current", "planned_steps",
    "grant_sha256", "review_sha256",
})


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EpisodeEnrollmentIn(_StrictModel):
    expected_pause_binding: str = Field(pattern=r"^[0-9a-f]{64}$")
    allowed_tools: list[str] = Field(min_length=1, max_length=8)
    input_schema: dict[str, Any]
    tool_data_schemas: dict[str, dict[str, Any]]
    retain_until: float = Field(gt=0, allow_inf_nan=False)


class EpisodeReviewIn(_StrictModel):
    expected_revision: int = Field(ge=1)
    expected_episode_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewed: bool
    accepted: bool
    rationale: str = Field(min_length=1, max_length=2000)


class EpisodeGrantIn(_StrictModel):
    expected_revision: int = Field(ge=1)
    expected_episode_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    use_until: float = Field(gt=0, allow_inf_nan=False)
    retain_derived_copies: bool
    rationale: str = Field(min_length=1, max_length=2000)


class EpisodeSignedExportIn(_StrictModel):
    expected_revision: int = Field(ge=1)
    expected_episode_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_grant_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class EpisodeWithdrawIn(_StrictModel):
    expected_revision: int = Field(ge=1)
    expected_episode_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_review_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    withdraw: bool
    rationale: str = Field(min_length=1, max_length=2000)


def _service(request: Request, flow_id: str, *, human=False, maintenance=False, receipt=False):
    from maverick.flow import store
    from maverick.flow.action_episode_review import ActionEpisodeReviewService

    from .flows_api import _assert_flow_access, _require_flows

    actor = caller_principal(request)
    if not actor:
        raise HTTPException(status_code=401, detail="an authenticated user identity is required")
    require_permission(request, "operate")
    if not maintenance and not receipt:
        _require_flows()
    try:
        tenant = current_tenant_id_strict()
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=403, detail="active tenant authority is unavailable") from exc
    if not tenant:
        raise HTTPException(status_code=409, detail="select an active tenant for episode capture")
    workspace_authority = _workspace_authority(request, actor, tenant)
    current = store.load_flow(flow_id)
    if current is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, current)
    if not current.owner:
        raise HTTPException(status_code=409, detail="episode capture requires an owned flow")
    role = role_for_principal(actor)
    if not role:
        raise HTTPException(status_code=403, detail="current role authority is unavailable")
    ctx = ServiceContext(
        tenant=tenant, actor=actor, resource_owner=current.owner,
        credential_authority="native_episode_review_no_connector_credentials",
        credential_ref="not_applicable", human=human,
        authorization_role=role, authorization_policy="dashboard_flow_owner_or_admin_v1",
        budget_authority="bounded_local_no_provider", workspace_authority=workspace_authority,
    )

    def authorize(context, capability, resource):
        if context != ctx or resource != flow_id or capability not in _CAPABILITIES:
            raise HTTPException(status_code=404, detail="no such action episode")
        if (maintenance and capability != "flow.episode.withdraw") or (receipt and capability != "flow.episode.read"):
            raise HTTPException(status_code=403, detail="only evidence withdrawal is available through this control")
        if (caller_principal(request) != actor or current_tenant_id_strict() != tenant
                or role_for_principal(actor) != role
                or _workspace_authority(request, actor, tenant) != workspace_authority):
            raise HTTPException(status_code=403, detail="episode capture authority changed")
        require_permission(request, "operate")
        latest = store.load_flow(flow_id)
        if latest is None or latest.owner != ctx.resource_owner:
            raise HTTPException(status_code=404, detail="no such flow")
        _assert_flow_access(request, latest)
        if capability in {"flow.episode.enroll", "flow.episode.review", "flow.episode.grant",
                          "flow.episode.export_signed", "flow.episode.withdraw"} and ctx.human is not True:
            raise HTTPException(status_code=403, detail="an authenticated human decision is required")
        return True

    return ActionEpisodeReviewService(authorize), ctx


def _call(operation: Callable):
    try:
        return operation()
    except HTTPException:
        raise
    except RecordConflict as exc:
        raise HTTPException(status_code=409, detail="episode or source changed; refresh before retrying") from exc
    except AuditRefused as exc:
        detail = {"status": "audit_unavailable", "message": "required audit evidence is unavailable"}
        record_id = getattr(exc, "record_id", None)
        if type(record_id) is str and re.fullmatch(r"LAE-[0-9a-f]{32}", record_id):
            detail.update(status="audit_pending", record_id=record_id)
        raise HTTPException(status_code=503, detail=detail) from exc
    except Halted as exc:
        raise HTTPException(status_code=409, detail="episode capture or review is stopped") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="episode capture authority is unavailable or denied") from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="no such action episode") from exc
    except (ValueError, TypeError) as exc:
        # Raw connector values, schema contents and review rationale are not
        # echoed as exception text or copied into the public error envelope.
        raise HTTPException(status_code=400, detail="invalid action episode request or evidence") from exc


def _response(record: dict):
    pending = record.get("status") == "audit_pending"
    if pending:
        # The transition is committed; withhold usable content until delivery.
        record = {key: value for key, value in record.items() if key in _PENDING_KEYS}
    return JSONResponse(record, status_code=503 if pending else 200,
                        headers={"Cache-Control": "no-store"})


def _enrollment_info(request: Request, flow_id: str, run_id: str):
    from maverick.config import get_flows
    from maverick.flow import store
    from maverick.flow.action_episodes import TEACHING_FAMILY, capture_plan, teaching_capture_plan
    from maverick.flow.approvals import paused_operation_binding
    from maverick.learning_guard import learning_write_allowed

    # The dashboard execution-approval binding also hashes runtime authority.
    # Enrollment uses its own exact core pause commitment, exposed here under
    # the same run lock rather than inviting clients to derive it from data.
    service, ctx = _service(request, flow_id, human=True)
    with store.run_lock(run_id):
        settings = get_flows()
        if (settings.get("action_episode_capture") is not True
                or not learning_write_allowed("flow_action_episode_capture")):
            raise PermissionError("durable action episode capture is disabled or halted")
        run = store.load_run(run_id, owner=ctx.resource_owner, flow_id=flow_id)
        if run is None:
            raise LookupError("no such flow run")
        pinned = store.load_flow_snapshot(run.definition_digest)
        current = store.load_flow(flow_id)
        if (current is None or pinned.id != flow_id or pinned.owner != ctx.resource_owner
                or current.revision != run.definition_revision or pinned.revision != run.definition_revision
                or pinned.version != run.definition_version or run.dry_run):
            raise RecordConflict("capture source changed")
        allowed_tools = sorted({node.tool for node in pinned.nodes.values() if node.kind == "action"})
        teaching = pinned.recipe_teaching is not None
        if teaching:
            if settings.get("action_recipe_teaching") is not True:
                raise PermissionError("native choice teaching capture is disabled")
            alternatives = teaching_capture_plan(pinned, allowed_tools=allowed_tools)
            # Both alternatives must be declared and checked for any prior
            # action, although a completed episode contains only one of them.
            plan = [alternatives["prefix"], *alternatives["branches"].values()]
            planned_steps = 2
        else:
            plan = capture_plan(pinned, allowed_tools=allowed_tools, no_forms=True)
            planned_steps = len(plan)
        if (run.status != "paused_approval" or run.cursor != pinned.start
                or pinned.nodes[pinned.start].kind != "approval"
                or any(node_id in run.nodes for node_id, _tool in plan)):
            raise RecordConflict("capture requires the initial approval before actions")
        if service.authorize(ctx, "flow.episode.enroll", flow_id) is not True:
            raise PermissionError("capture enrollment authority changed")
        result = {
            "flow_id": flow_id, "run_id": run_id,
            "expected_pause_binding": paused_operation_binding(run),
            "definition_digest": run.definition_digest,
            "status": "initial_approval", "planned_steps": planned_steps,
            "allowed_tools": allowed_tools,
            "retention": {
                "purpose": "Retain business inputs, actual tool arguments and results as potential training evidence.",
                "maximum_seconds": 604800, "explicit_complete_schemas_required": True,
                "human_review_required_before_export": True,
                "execution_approval_is_separate": True,
            },
        }
        if teaching:
            result["capture_family"] = TEACHING_FAMILY
            result["retention"].update(human_continuation_choice_required=True,
                                       agreement_only_runs_are_training_evidence=False)
        return result


@router.get("/{flow_id}/runs/{run_id}/episode-capture/enrollment", response_model=None)
def prepare_action_episode_enrollment(request: Request, flow_id: FlowPath, run_id: RunPath):
    return _response(_call(lambda: _enrollment_info(request, flow_id, run_id)))


@router.post("/{flow_id}/runs/{run_id}/episode-capture", response_model=None)
def enroll_action_episode(request: Request, flow_id: FlowPath, run_id: RunPath,
                          payload: EpisodeEnrollmentIn):
    service, ctx = _call(lambda: _service(request, flow_id, human=True))
    return _response(_call(lambda: service.enroll(
        ctx, flow_id, run_id, expected_pause_binding=payload.expected_pause_binding,
        allowed_tools=payload.allowed_tools, input_schema=payload.input_schema,
        tool_data_schemas=payload.tool_data_schemas, retain_until=payload.retain_until,
    )))


@router.get("/{flow_id}/runs/{run_id}/episode-capture", response_model=None)
def get_action_episode_status(request: Request, flow_id: FlowPath, run_id: RunPath):
    service, ctx = _call(lambda: _service(request, flow_id))
    return _response(_call(lambda: service.get(ctx, flow_id, run_id)))


@router.get("/{flow_id}/runs/{run_id}/episode-capture/detail", response_model=None)
def get_action_episode_detail(request: Request, flow_id: FlowPath, run_id: RunPath):
    service, ctx = _call(lambda: _service(request, flow_id))
    return _response(_call(lambda: service.get(ctx, flow_id, run_id, detail=True)))


@router.post("/{flow_id}/runs/{run_id}/episode-capture/review", response_model=None)
def review_action_episode(request: Request, flow_id: FlowPath, run_id: RunPath,
                          payload: EpisodeReviewIn):
    if payload.reviewed is not True:
        raise HTTPException(status_code=400, detail="reviewed must be true for an explicit episode review")
    service, ctx = _call(lambda: _service(request, flow_id, human=True))
    return _response(_call(lambda: service.review(
        ctx, flow_id, run_id, expected_revision=payload.expected_revision,
        expected_episode_sha256=payload.expected_episode_sha256,
        accepted=payload.accepted, rationale=payload.rationale,
    )))


@router.get("/{flow_id}/runs/{run_id}/episode-capture/export", response_model=None)
def export_action_episode(request: Request, flow_id: FlowPath, run_id: RunPath):
    service, ctx = _call(lambda: _service(request, flow_id))
    return _response(_call(lambda: service.export(ctx, flow_id, run_id)))


@router.post("/{flow_id}/runs/{run_id}/episode-capture/training-grant", response_model=None)
def grant_action_episode_training(request: Request, flow_id: FlowPath, run_id: RunPath,
                                 payload: EpisodeGrantIn):
    if payload.retain_derived_copies is not True:
        raise HTTPException(status_code=400, detail="explicit consent to retain derived training copies is required")
    service, ctx = _call(lambda: _service(request, flow_id, human=True))
    return _response(_call(lambda: service.grant_training(
        ctx, flow_id, run_id, expected_revision=payload.expected_revision,
        expected_episode_sha256=payload.expected_episode_sha256, use_until=payload.use_until,
        retain_derived_copies=payload.retain_derived_copies, rationale=payload.rationale,
    )))


@router.post("/{flow_id}/runs/{run_id}/episode-capture/signed-export", response_model=None)
def export_signed_action_episode(request: Request, flow_id: FlowPath, run_id: RunPath,
                                payload: EpisodeSignedExportIn):
    service, ctx = _call(lambda: _service(request, flow_id, human=True))
    return _response(_call(lambda: service.export_signed(
        ctx, flow_id, run_id, expected_revision=payload.expected_revision,
        expected_episode_sha256=payload.expected_episode_sha256,
        expected_grant_sha256=payload.expected_grant_sha256,
    )))


@router.get("/{flow_id}/runs/{run_id}/episode-capture/withdrawal", response_model=None)
def prepare_action_episode_withdrawal(request: Request, flow_id: FlowPath, run_id: RunPath):
    service, ctx = _call(lambda: _service(request, flow_id, human=True, maintenance=True))
    return _response(_call(lambda: service.prepare_withdrawal(ctx, flow_id, run_id)))


@router.post("/{flow_id}/runs/{run_id}/episode-capture/withdraw", response_model=None)
def withdraw_action_episode(request: Request, flow_id: FlowPath, run_id: RunPath,
                            payload: EpisodeWithdrawIn):
    if payload.withdraw is not True:
        raise HTTPException(status_code=400, detail="withdraw must be true for an explicit review withdrawal")
    service, ctx = _call(lambda: _service(request, flow_id, human=True, maintenance=True))
    return _response(_call(lambda: service.withdraw(
        ctx, flow_id, run_id, expected_revision=payload.expected_revision,
        expected_episode_sha256=payload.expected_episode_sha256,
        expected_review_sha256=payload.expected_review_sha256, rationale=payload.rationale,
    )))
