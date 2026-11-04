"""Authenticated admission and draft inspection for reviewed recipe lineage."""
from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Request
from fastapi import Path as ApiPath
from maverick.audit.errors import AuditRefused
from maverick.governed_operations import ServiceContext
from maverick.governed_records import RecordConflict
from maverick.learning_guard import Halted
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from .api_flow_operator_review import _workspace_authority
from .auth import caller_principal, require_permission, role_for_principal

router = APIRouter(prefix="/flows/recipe-lineage", tags=["flow-recipe-lineage"])
RecordPath = Annotated[str, ApiPath(min_length=1, max_length=64)]
_CAPABILITIES = frozenset({"flow.recipe.admit", "flow.recipe.read", "flow.recipe.detail", "flow.recipe.draft"})
_PENDING_KEYS = frozenset({"schema", "id", "revision", "status", "committed_status", "audit_status",
                           "package_sha256", "artifact_sha256", "lineage_sha256", "use_until", "source_count"})


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RecipeLineageIn(_StrictModel):
    package: dict[str, Any]


class RecipeLineageDraftIn(_StrictModel):
    flow_id: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=256)
    teaching: bool = False


class WorkflowLearningIn(_StrictModel):
    bundles: list[dict[str, Any]] = Field(min_length=2, max_length=32)
    allowed_tools: list[str] = Field(min_length=1, max_length=8)
    domain: dict[str, Any]
    max_operations: int = Field(default=1, ge=1, le=2)
    max_steps: int = Field(default=8, ge=1, le=8)
    operators: list[str] | None = Field(default=None, max_length=16)
    constants: list[Any] | None = Field(default=None, max_length=8)


def _service(request: Request):
    from maverick.flow import store
    from maverick.flow.recipe_lineage import RecipeLineageService

    from .flows_api import _assert_flow_access, _require_flows

    actor = caller_principal(request)
    if not actor:
        raise HTTPException(status_code=401, detail="an authenticated user identity is required")
    require_permission(request, "operate")
    _require_flows()
    tenant = current_tenant_id_strict()
    if not tenant:
        raise HTTPException(status_code=409, detail="select an active tenant for recipe lineage")
    workspace = _workspace_authority(request, actor, tenant)
    role = role_for_principal(actor)
    if not role:
        raise HTTPException(status_code=403, detail="current role authority is unavailable")
    ctx = ServiceContext(
        tenant=tenant, actor=actor, resource_owner=actor, human=True,
        credential_authority="recipe_lineage_no_connector_credentials", credential_ref="not_applicable",
        authorization_role=role, authorization_policy="dashboard_recipe_same_owner_v1",
        budget_authority="bounded_local_no_provider", workspace_authority=workspace,
    )

    def authorize(context, capability, resource):
        if context != ctx:
            raise PermissionError("lineage context changed")
        if (caller_principal(request) != actor or current_tenant_id_strict() != tenant
                or role_for_principal(actor) != role
                or _workspace_authority(request, actor, tenant) != workspace):
            raise PermissionError("lineage authority changed")
        require_permission(request, "operate")
        if capability == "flow.episode.current":
            current = store.load_flow(resource)
            if current is None or current.owner != actor:
                raise PermissionError("lineage source owner changed")
            _assert_flow_access(request, current)
        elif capability not in _CAPABILITIES:
            raise PermissionError("unsupported lineage authority")
        return True

    return RecipeLineageService(authorize), ctx


def _call(operation):
    try:
        return operation()
    except HTTPException:
        raise
    except RecordConflict as exc:
        raise HTTPException(status_code=409, detail="lineage or source changed; refresh before retrying") from exc
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail={"status": "audit_pending",
                            "message": "required audit evidence is unavailable"}) from exc
    except Halted as exc:
        raise HTTPException(status_code=409, detail="recipe lineage is stopped") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="recipe lineage authority is unavailable or denied") from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="no such recipe lineage") from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="invalid recipe lineage request or evidence") from exc


def _response(value):
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    pending = value.get("status") == "audit_pending"
    if pending:
        value = {key: item for key, item in value.items() if key in _PENDING_KEYS}
    return JSONResponse(value, status_code=503 if pending else 200, headers={"Cache-Control": "no-store"})


def _workflow_gate():
    from maverick.config import get_flows
    from maverick.learning_guard import check_learning_halt

    flags = get_flows()
    if any(flags.get(key) is not True for key in (
            "action_workflow_learning", "action_recipes", "action_recipe_transforms", "action_recipe_lineage")):
        raise PermissionError("verified workflow learning is disabled")
    check_learning_halt("flow_recipe_lineage", "workflow_learning")


def _memory_gate():
    from maverick.config import get_flows
    from maverick.learning_guard import check_learning_halt

    _workflow_gate()
    if get_flows().get("action_workflow_memory_learning") is not True:
        raise PermissionError("verified workflow memory learning is disabled")
    check_learning_halt("flow_recipe_lineage", "memory_learning")


def _workflow_json_pairs(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate workflow request field")
        value[key] = child
    return value


def _learn_workflow(service, ctx, payload, *, memory=False):
    from maverick.flow.action_episode_review import ActionEpisodeReviewService
    from maverick.flow.action_provenance import local_trust
    from maverick.flow.recipe_lineage import _canonical, learn_transducer_from_verified_bundles

    gate = _memory_gate if memory else _workflow_gate
    gate()
    commitment = hashlib.sha256(_canonical(payload.model_dump()).encode("utf-8")).hexdigest()
    if service.authorize(ctx, "flow.recipe.admit", commitment) is not True:
        raise PermissionError("workflow learning authority is unavailable")
    evidence = ActionEpisodeReviewService(service.authorize, clock=service.clock)
    # Reject stale or foreign evidence before bounded, but potentially costly,
    # synthesis. Admission repeats these checks before/after its own commit.
    for bundle in payload.bundles:
        evidence.assert_bundle_current(ctx, bundle)
    learner = learn_transducer_from_verified_bundles
    if memory:
        from maverick.flow.recipe_lineage import learn_memory_from_verified_bundles

        learner = learn_memory_from_verified_bundles
    package = learner(
        payload.bundles, trust=local_trust(ctx.tenant), expected_tenant=ctx.tenant, now=service.clock(),
        allowed_tools=payload.allowed_tools, domain=payload.domain, max_operations=payload.max_operations,
        operators=payload.operators, constants=payload.constants, max_steps=payload.max_steps,
    )
    gate()
    return service.admit(ctx, package)


@router.post("/learn-workflow-verified", response_model=None)
async def learn_workflow_recipe_lineage(request: Request):
    """Learn and admit; return safe metadata, never an unaudited package."""
    return await _workflow_learning_request(request, memory=False)


@router.post("/learn-memory-verified", response_model=None)
async def learn_memory_recipe_lineage(request: Request):
    """Learn bounded integer history models and admit under current source authority."""
    return await _workflow_learning_request(request, memory=True)


async def _workflow_learning_request(request: Request, *, memory):
    from maverick.flow.recipe_lineage import MAX_PACKAGE_BYTES, _canonical

    from .app import _read_limited_request_body

    service, ctx = _call(lambda: _service(request))
    _call(_memory_gate if memory else _workflow_gate)
    raw = await _read_limited_request_body(request, max_bytes=MAX_PACKAGE_BYTES,
                                          too_large_detail="workflow learning request body too large")
    try:
        value = json.loads(raw, object_pairs_hook=_workflow_json_pairs)
        _canonical(value)
        payload = WorkflowLearningIn.model_validate(value)
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise HTTPException(status_code=422, detail="invalid bounded workflow learning request") from exc
    result = await run_in_threadpool(_call, lambda: _learn_workflow(service, ctx, payload, memory=memory))
    return _response(result)


@router.post("", response_model=None)
def admit_recipe_lineage(request: Request, payload: RecipeLineageIn):
    service, ctx = _call(lambda: _service(request))
    return _response(_call(lambda: service.admit(ctx, payload.package)))


@router.get("/{record_id}", response_model=None)
def get_recipe_lineage(request: Request, record_id: RecordPath):
    service, ctx = _call(lambda: _service(request))
    return _response(_call(lambda: service.get(ctx, record_id)))


@router.get("/{record_id}/detail", response_model=None)
def get_recipe_lineage_detail(request: Request, record_id: RecordPath):
    service, ctx = _call(lambda: _service(request))
    return _response(_call(lambda: service.get(ctx, record_id, detail=True)))


@router.post("/{record_id}/draft", response_model=None)
def draft_recipe_lineage(request: Request, record_id: RecordPath, payload: RecipeLineageDraftIn):
    from maverick.flow import store

    from .flows_api import _assert_flow_access

    service, ctx = _call(lambda: _service(request))

    def draft():
        current = store.load_flow(payload.flow_id)
        if current is not None:
            if current.owner != ctx.resource_owner:
                raise PermissionError("lineage destination belongs to another owner")
            _assert_flow_access(request, current)
        result = service.draft(ctx, record_id, flow_id=payload.flow_id, name=payload.name,
                               teaching=payload.teaching)
        # Drafting grants no persistence authority; the normal save/publish path
        # must check destination ownership again when it commits the definition.
        if service.authorize(ctx, "flow.recipe.draft", record_id) is not True:
            raise PermissionError("lineage destination authority changed")
        latest = store.load_flow(payload.flow_id)
        if latest is not None and latest.owner != ctx.resource_owner:
            raise PermissionError("lineage destination owner changed")
        return result

    return _response(_call(draft))
