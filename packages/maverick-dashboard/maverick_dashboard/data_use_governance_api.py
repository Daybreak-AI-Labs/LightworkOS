"""Tenant-pinned REST surface for provider-neutral Data Use Governance."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission

router = APIRouter(prefix="/data-use", tags=["data-use-governance"])

_TOKEN = r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$"
_IDEMPOTENCY = r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}$"
_DIGEST = r"^[0-9a-f]{64}$"
RecordType = Literal[
    "asset",
    "field",
    "lineage",
    "context",
    "label",
    "label_version",
    "label_assignment",
    "policy",
    "policy_version",
    "exception",
    "request",
    "decision",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _CasMutation(_StrictModel):
    expected_revision: int = Field(..., ge=0, le=2**31 - 1)
    idempotency_key: str = Field(..., pattern=_IDEMPOTENCY)


class AssetIn(_CasMutation):
    asset_type: Literal[
        "table",
        "view",
        "file",
        "stream",
        "api",
        "dataset",
        "model_input",
        "model_output",
    ]
    catalog_binding_sha256: str = Field(..., pattern=_DIGEST)


class FieldIn(_CasMutation):
    data_type: Literal[
        "string",
        "integer",
        "number",
        "boolean",
        "date",
        "datetime",
        "uuid",
        "binary",
        "json",
        "object",
        "array",
    ]
    nullable: bool
    catalog_binding_sha256: str = Field(..., pattern=_DIGEST)


class LineageIn(_CasMutation):
    source_asset_id: str = Field(..., pattern=_TOKEN)
    source_field_id: str = Field(..., pattern=_TOKEN)
    target_asset_id: str = Field(..., pattern=_TOKEN)
    target_field_id: str = Field(..., pattern=_TOKEN)
    transformation_sha256: str = Field(..., pattern=_DIGEST)
    observed_at: float = Field(..., gt=0)


class ContextAuthorityIn(_CasMutation):
    values: list[str] = Field(..., min_length=1, max_length=256)
    source_system: str = Field(..., pattern=_TOKEN)
    source_revision: int = Field(..., ge=1, le=2**31 - 1)
    source_authority_sha256: str = Field(..., pattern=_DIGEST)
    evidence_sha256: str = Field(..., pattern=_DIGEST)
    observed_at: float = Field(..., gt=0)
    fresh_until: float = Field(..., gt=0)


class PublishLabelIn(_CasMutation):
    version: int = Field(..., ge=1, le=2**31 - 1)
    taxonomy_id: str = Field(..., pattern=_TOKEN)
    sensitivity: int = Field(..., ge=0, le=100)
    definition_sha256: str = Field(..., pattern=_DIGEST)
    reviewed_at: float = Field(..., gt=0)
    expected_current_version: int = Field(..., ge=0, le=2**31 - 1)


class AssignLabelIn(_CasMutation):
    asset_id: str = Field(..., pattern=_TOKEN)
    field_id: str = Field(..., pattern=_TOKEN)
    label_version: int = Field(..., ge=1, le=2**31 - 1)
    assignment_evidence_sha256: str = Field(..., pattern=_DIGEST)


class PolicyVersionIn(_CasMutation):
    version: int = Field(..., ge=1, le=2**31 - 1)
    document: dict[str, Any]
    expected_current_version: int = Field(..., ge=0, le=2**31 - 1)


class ActivatePolicyIn(_CasMutation):
    version: int = Field(..., ge=1, le=2**31 - 1)
    reviewed_at: float = Field(..., gt=0)


class ExceptionRequestIn(_StrictModel):
    policy_id: str = Field(..., pattern=_TOKEN)
    scope: dict[str, Any]
    replacement_control: dict[str, Any]
    rationale_sha256: str = Field(..., pattern=_DIGEST)
    expires_at: float = Field(..., gt=0)
    idempotency_key: str = Field(..., pattern=_IDEMPOTENCY)


class ExceptionReviewIn(_CasMutation):
    approve: bool
    reviewed_at: float = Field(..., gt=0)


class DataUseRequestIn(_StrictModel):
    project_id: str = Field(..., pattern=_TOKEN)
    asset_id: str = Field(..., pattern=_TOKEN)
    field_ids: list[str] = Field(..., min_length=1, max_length=256)
    action: Literal["read", "export", "train", "analyze", "share", "write"]
    purpose_codes: list[str] = Field(..., min_length=1, max_length=256)
    request_evidence_sha256: str = Field(..., pattern=_DIGEST)
    idempotency_key: str = Field(..., pattern=_IDEMPOTENCY)


class AuthorizeRequestIn(_StrictModel):
    expected_request_revision: int = Field(..., ge=0, le=2**31 - 1)
    idempotency_key: str = Field(..., pattern=_IDEMPOTENCY)


class CompileIn(_StrictModel):
    expected_decision_sha256: str | None = Field(default=None, pattern=_DIGEST)


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using data-use governance",
        )
    return tenant


def _config() -> Mapping[str, Any]:
    from maverick import config

    try:
        if config.config_source_errors():
            return {}
        section = config.load_config().get("data_use_governance")
    except Exception:
        return {}
    return section if isinstance(section, Mapping) else {}


def _ops():
    from maverick import config, data_use_governance

    if not config.data_use_governance_enabled():
        raise HTTPException(
            status_code=403,
            detail="Data Use Governance is disabled or its configuration is unavailable.",
        )
    return data_use_governance


def _compiler_ops():
    from maverick import data_use_policy_compiler

    compiler = _config().get("compiler")
    if not isinstance(compiler, Mapping) or compiler.get("enable") is not True:
        raise HTTPException(
            status_code=403,
            detail="data-use compiler is disabled ([data_use_governance.compiler] enable)",
        )
    return data_use_policy_compiler


def _store(ops, tenant_id: str):
    from maverick.paths import data_dir

    return ops.DataUseGovernanceStore(
        data_dir(
            "data_use_governance",
            "data-use-governance.sqlite3",
            tenant=tenant_id,
        )
    )


def _actor_binding(request: Request) -> tuple[str, str]:
    """Bind review authority to the authenticated server-side actor."""

    from .request_identity import request_actor as _request_actor

    actor = _request_actor(request)
    actor_sha = hashlib.sha256(actor.encode("utf-8")).hexdigest()
    authority_sha = hashlib.sha256(
        f"lightwork-dashboard-auth:v1:{actor}".encode()
    ).hexdigest()
    return f"actor-{actor_sha[:32]}", authority_sha


def _authority():
    ops = _ops()
    tenant = _tenant_id()
    return ops, tenant, _store(ops, tenant)


async def _call(ops, function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except (ops.DataUseConflict, ops.DataUseIdempotencyConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.DataUseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ops.DataUseValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (ops.DataUseMissingAuthority, ops.DataUseStaleAuthority) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (ops.DataUseCorruptionError, ops.DataUseGovernanceError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/status")
def status(request: Request) -> dict:
    require_permission(request, "view")
    _ops_module, _tenant, store = _authority()
    result = store.status()
    result["compiler_enabled"] = (
        isinstance(_config().get("compiler"), Mapping)
        and _config()["compiler"].get("enable") is True
    )
    return result


@router.get("/background-checks")
async def background_checks(request: Request) -> dict:
    """The background data-use checks: on or off, next pass, recent results."""
    require_global_permission(request, "admin")
    from . import data_use_scheduler

    try:
        return await run_in_threadpool(data_use_scheduler.status)
    except Exception as exc:  # noqa: BLE001 - unreadable settings or job store
        raise HTTPException(status_code=503,
                            detail="The background data-use checks could not be read.") from exc


@router.get("/records/{record_type}")
async def list_records(
    request: Request,
    record_type: RecordType,
    limit: int = Query(100, ge=1, le=499),
) -> dict:
    require_permission(request, "operate")
    ops, tenant, store = _authority()
    rows = await _call(ops, store.list_records, tenant, record_type, limit=limit + 1)
    return {"items": rows[:limit], "truncated": len(rows) > limit}


@router.get("/records/{record_type}/{record_id:path}")
async def get_record(request: Request, record_type: RecordType, record_id: str) -> dict:
    require_permission(request, "operate")
    ops, tenant, store = _authority()
    record = await _call(ops, store.get_record, tenant, record_type, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="record does not exist in this tenant")
    return record


@router.put("/assets/{asset_id}")
async def put_asset(request: Request, asset_id: str, body: AssetIn) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    return await _call(ops, store.put_asset, tenant, asset_id, **body.model_dump())


@router.put("/assets/{asset_id}/fields/{field_id}")
async def put_field(
    request: Request, asset_id: str, field_id: str, body: FieldIn
) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    return await _call(
        ops, store.put_field, tenant, asset_id, field_id, **body.model_dump()
    )


@router.put("/lineage/{lineage_id}")
async def put_lineage(request: Request, lineage_id: str, body: LineageIn) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    return await _call(ops, store.put_lineage, tenant, lineage_id, **body.model_dump())


@router.put("/assets/{asset_id}/contexts/{context_kind}")
async def put_context(
    request: Request,
    asset_id: str,
    context_kind: Literal[
        "business_purpose", "regulatory", "consent", "observed_classification"
    ],
    body: ContextAuthorityIn,
) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    reviewer_id, reviewer_authority_sha256 = _actor_binding(request)
    return await _call(
        ops,
        store.put_context_authority,
        tenant,
        asset_id,
        context_kind,
        **body.model_dump(),
        reviewer_id=reviewer_id,
        reviewer_authority_sha256=reviewer_authority_sha256,
    )


@router.post("/labels/{label_id}/versions", status_code=201)
async def publish_label(request: Request, label_id: str, body: PublishLabelIn) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    reviewer_id, reviewer_authority_sha256 = _actor_binding(request)
    return await _call(
        ops,
        store.publish_machine_label,
        tenant,
        label_id,
        **body.model_dump(),
        reviewer_id=reviewer_id,
        reviewer_authority_sha256=reviewer_authority_sha256,
    )


@router.post("/labels/{label_id}/retire")
async def retire_label(request: Request, label_id: str, body: _CasMutation) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    return await _call(
        ops, store.retire_machine_label, tenant, label_id, **body.model_dump()
    )


@router.put("/labels/{label_id}/assignments")
async def assign_label(request: Request, label_id: str, body: AssignLabelIn) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    reviewer_id, reviewer_authority_sha256 = _actor_binding(request)
    payload = body.model_dump()
    asset_id = payload.pop("asset_id")
    field_id = payload.pop("field_id")
    return await _call(
        ops,
        store.assign_machine_label,
        tenant,
        asset_id,
        field_id,
        label_id,
        **payload,
        reviewer_id=reviewer_id,
        reviewer_authority_sha256=reviewer_authority_sha256,
    )


class PolicyPreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document: dict[str, Any]


@router.post("/policies/preview")
async def preview_policy(request: Request, body: PolicyPreviewIn) -> dict:
    """Which recorded requests to use data a rule would have covered in the
    last 30 days. Report only: nothing is saved or switched on."""
    require_permission(request, "operate")
    from maverick import policy_preview

    ops, tenant, store = _authority()
    requests = await _call(ops, store.list_records, tenant, "request", limit=499)
    try:
        return await run_in_threadpool(policy_preview.data_use_rule, body.document, requests)
    except ops.DataUseValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/policies/{policy_id}/versions", status_code=201)
async def put_policy_version(
    request: Request, policy_id: str, body: PolicyVersionIn
) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    author_id, author_authority_sha256 = _actor_binding(request)
    return await _call(
        ops,
        store.put_policy_version,
        tenant,
        policy_id,
        **body.model_dump(),
        author_id=author_id,
        author_authority_sha256=author_authority_sha256,
    )


@router.post("/policies/{policy_id}/activate")
async def activate_policy(
    request: Request, policy_id: str, body: ActivatePolicyIn
) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    reviewer_id, reviewer_authority_sha256 = _actor_binding(request)
    return await _call(
        ops,
        store.activate_policy,
        tenant,
        policy_id,
        **body.model_dump(),
        reviewer_id=reviewer_id,
        reviewer_authority_sha256=reviewer_authority_sha256,
    )


@router.post("/policies/{policy_id}/retire")
async def retire_policy(request: Request, policy_id: str, body: _CasMutation) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    return await _call(ops, store.retire_policy, tenant, policy_id, **body.model_dump())


@router.post("/exceptions/{exception_id}", status_code=201)
async def request_exception(
    request: Request, exception_id: str, body: ExceptionRequestIn
) -> dict:
    require_permission(request, "operate")
    ops, tenant, store = _authority()
    requester_id, requester_authority_sha256 = _actor_binding(request)
    payload = body.model_dump()
    policy_id = payload.pop("policy_id")
    return await _call(
        ops,
        store.request_policy_exception,
        tenant,
        exception_id,
        policy_id,
        **payload,
        requester_id=requester_id,
        requester_authority_sha256=requester_authority_sha256,
    )


@router.post("/exceptions/{exception_id}/review")
async def review_exception(
    request: Request, exception_id: str, body: ExceptionReviewIn
) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    reviewer_id, reviewer_authority_sha256 = _actor_binding(request)
    return await _call(
        ops,
        store.review_policy_exception,
        tenant,
        exception_id,
        **body.model_dump(),
        reviewer_id=reviewer_id,
        reviewer_authority_sha256=reviewer_authority_sha256,
    )


@router.post("/exceptions/{exception_id}/close")
async def close_exception(
    request: Request, exception_id: str, body: _CasMutation
) -> dict:
    require_permission(request, "operate")
    ops, tenant, store = _authority()
    return await _call(
        ops, store.close_policy_exception, tenant, exception_id, **body.model_dump()
    )


@router.post("/requests/{request_id}", status_code=201)
async def create_request(
    request: Request, request_id: str, body: DataUseRequestIn
) -> dict:
    require_permission(request, "operate")
    ops, tenant, store = _authority()
    requester_id, requester_authority_sha256 = _actor_binding(request)
    return await _call(
        ops,
        store.create_data_use_request,
        tenant,
        request_id,
        **body.model_dump(),
        requester_id=requester_id,
        requester_authority_sha256=requester_authority_sha256,
    )


@router.post("/requests/{request_id}/authorize")
async def authorize_request(
    request: Request, request_id: str, body: AuthorizeRequestIn
) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    authorizer_id, authorizer_authority_sha256 = _actor_binding(request)
    return await _call(
        ops,
        store.authorize_data_use_request,
        tenant,
        request_id,
        **body.model_dump(),
        authorizer_id=authorizer_id,
        authorizer_authority_sha256=authorizer_authority_sha256,
    )


@router.post("/decisions/{decision_id}/compile")
async def compile_decision(
    request: Request, decision_id: str, body: CompileIn
) -> dict:
    require_global_permission(request, "admin")
    governance_ops, tenant, store = _authority()
    compiler_ops = _compiler_ops()
    compiler = compiler_ops.DataUsePolicyCompiler(store)
    try:
        frozen = await run_in_threadpool(
            compiler.compile,
            tenant,
            decision_id,
            expected_decision_sha256=body.expected_decision_sha256,
        )
        return compiler_ops.thaw_control_ir(frozen)
    except compiler_ops.DataUseCompilationStale as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except compiler_ops.DataUseCompilationValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except compiler_ops.DataUsePolicyCompilerError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except governance_ops.DataUseGovernanceError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


__all__ = ["router"]
