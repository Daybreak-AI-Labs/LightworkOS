"""Operator API for exact identity-change AI-asset outcomes.

The active tenant comes only from request context.  Binding enrollment also
requires an independently installed deployment authorizer; dashboard admin
permission alone cannot create or replace asset authority.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from maverick.ai_identity_governance_controls import (
    IdentityGovernanceBindingError,
    IdentityGovernanceIdempotencyConflict,
    IdentityGovernanceStaleBinding,
    IdentityGovernanceStateError,
)
from maverick.ai_identity_governance_outcomes import (
    IdentityAssetOutcomeConfigError,
    IdentityAssetOutcomeCoverageError,
    make_identity_change_asset_binding,
)
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_global_permission
from .identity_governance_runtime import (
    IdentityGovernanceControlRuntime,
    IdentityGovernanceOutcomeRuntime,
)

router = APIRouter(
    prefix="/assurance/identity-governance/outcomes",
    tags=["identity-governance-outcomes"],
)

Digest = Annotated[str, Field(pattern=r"^(?:sha256:)?[0-9a-fA-F]{64}$")]
AssetId = Annotated[str, Field(pattern=r"^MAA-[0-9a-f]{32}$")]
BindingId = Annotated[str, Field(pattern=r"^IGAB-[0-9a-f]{32}$")]
OutcomeId = Annotated[str, Field(pattern=r"^IGAO-[0-9a-f]{32}$")]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AssetBindingIn(_StrictModel):
    provider: Literal["entra", "okta", "purview"]
    selector_kind: Literal[
        "provider", "identities", "grants", "data_classifications"
    ]
    selector_sha256: Digest
    asset_id: AssetId
    asset_revision: StrictInt = Field(ge=1, le=2**63 - 1)
    asset_version_digest: Digest
    binding_revision: StrictInt = Field(ge=1, le=2**63 - 1)
    asset_criticality: Literal["low", "medium", "high", "critical"]
    eu_risk_tier: Literal["minimal", "limited", "high", "unacceptable"]
    sensitive_data: Literal["none", "internal", "personal", "special_category"]
    external_exposure: Literal["internal", "restricted", "partner", "public"]
    expected_record_revision: StrictInt = Field(default=0, ge=0, le=2**63 - 1)
    authorization_sha256: Digest


class RevisionEvidenceIn(_StrictModel):
    expected_revision: StrictInt = Field(ge=1, le=2**63 - 1)
    evidence_sha256: Digest


class WorkerIn(_StrictModel):
    limit: StrictInt = Field(default=25, ge=1, le=100)


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using identity outcomes",
        )
    return tenant


def _human(request: Request) -> str:
    principal = caller_principal(request)
    if not isinstance(principal, str) or not principal.startswith("user:"):
        raise HTTPException(
            status_code=403,
            detail="an authenticated human user is required",
        )
    return principal


def _runtime(request: Request) -> IdentityGovernanceOutcomeRuntime:
    tenant = _tenant_id()
    factory = getattr(
        request.app.state,
        "identity_governance_outcome_runtime_factory",
        None,
    )
    if not callable(factory):
        raise HTTPException(
            status_code=503,
            detail="identity-governance outcome runtime is unavailable",
        )
    try:
        selected = factory(tenant)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="identity-governance outcome runtime is unavailable",
        ) from exc
    if not isinstance(selected, IdentityGovernanceOutcomeRuntime):
        raise HTTPException(
            status_code=503,
            detail="identity-governance outcome runtime is invalid",
        )
    return selected


def _control_runtime(request: Request) -> IdentityGovernanceControlRuntime:
    tenant = _tenant_id()
    factory = getattr(
        request.app.state,
        "identity_governance_control_runtime_factory",
        None,
    )
    if not callable(factory):
        raise HTTPException(
            status_code=503,
            detail="identity-governance control runtime is unavailable",
        )
    try:
        selected = factory(tenant, request)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="identity-governance control runtime is unavailable",
        ) from exc
    if not isinstance(selected, IdentityGovernanceControlRuntime):
        raise HTTPException(
            status_code=503,
            detail="identity-governance control runtime is invalid",
        )
    return selected


def _authorization_digest(body: AssetBindingIn, tenant_sha256: str) -> str:
    material = {
        "schema": "lightwork.identity_governance.ai-asset-binding-enrollment.v1",
        "tenant_sha256": tenant_sha256,
        **body.model_dump(exclude={"authorization_sha256"}),
    }
    return hashlib.sha256(
        json.dumps(
            material,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


async def _authorized_binding(
    request: Request,
    runtime: IdentityGovernanceOutcomeRuntime,
    body: AssetBindingIn,
    principal: str,
) -> None:
    authorizer = getattr(
        request.app.state,
        "identity_governance_asset_binding_authorizer",
        None,
    )
    if not callable(authorizer):
        raise HTTPException(
            status_code=503,
            detail="independent asset-binding authorization is unavailable",
        )
    enrollment_sha256 = _authorization_digest(body, runtime.tenant_sha256)
    try:
        accepted = await run_in_threadpool(
            authorizer,
            runtime.tenant_sha256,
            principal,
            enrollment_sha256,
            body.authorization_sha256.lower().removeprefix("sha256:"),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="independent asset-binding authorization failed closed",
        ) from exc
    if accepted is not True:
        raise HTTPException(
            status_code=403,
            detail="asset-binding authorization was not accepted",
        )


async def _call(function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except IdentityGovernanceStaleBinding as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (
        IdentityGovernanceBindingError,
        IdentityGovernanceIdempotencyConflict,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except IdentityAssetOutcomeCoverageError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except IdentityGovernanceStateError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except IdentityAssetOutcomeConfigError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/status")
async def identity_outcome_status(request: Request) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _human(request)
    return await _call(_runtime(request).status)


@router.get("/bindings")
async def list_identity_asset_bindings(
    request: Request,
    provider: Literal["entra", "okta", "purview"] | None = Query(default=None),
) -> list[dict[str, Any]]:
    require_global_permission(request, "admin")
    _human(request)
    return await _call(_runtime(request).asset_registry.list_bindings, provider=provider)


@router.post("/bindings", status_code=201)
async def enroll_identity_asset_binding(
    request: Request,
    body: AssetBindingIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    principal = _human(request)
    selected = _runtime(request)
    await _authorized_binding(request, selected, body, principal)
    binding = make_identity_change_asset_binding(
        tenant_sha256=selected.tenant_sha256,
        **body.model_dump(
            exclude={"expected_record_revision", "authorization_sha256"}
        )
    )
    return await _call(
        selected.asset_registry.enroll,
        binding,
        actor=principal,
        expected_record_revision=body.expected_record_revision,
    )


@router.post("/bindings/{binding_id}/revoke")
async def revoke_identity_asset_binding(
    request: Request,
    binding_id: BindingId,
    body: RevisionEvidenceIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    principal = _human(request)
    return await _call(
        _runtime(request).asset_registry.revoke,
        binding_id,
        expected_revision=body.expected_revision,
        evidence_sha256=body.evidence_sha256,
        actor=principal,
    )


@router.get("/conditional-access-decisions")
async def list_conditional_access_decisions(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1_000),
) -> list[dict[str, Any]]:
    require_global_permission(request, "admin")
    _human(request)
    ledger = _control_runtime(
        request
    ).require_conditional_access_decision_ledger()
    return await _call(ledger.list, limit=limit)


@router.get("/conditional-access-decisions/{decision_record_id}")
async def get_conditional_access_decision(
    request: Request,
    decision_record_id: Annotated[
        str, Field(pattern=r"^IGCD-[0-9a-f]{32}$")
    ],
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _human(request)
    ledger = _control_runtime(
        request
    ).require_conditional_access_decision_ledger()
    value = await _call(ledger.get, decision_record_id)
    if value is None:
        raise HTTPException(
            status_code=404,
            detail="conditional-access decision was not found",
        )
    return value


@router.post("/conditional-access-decisions/{decision_record_id}/revoke")
async def revoke_conditional_access_decision(
    request: Request,
    decision_record_id: Annotated[
        str, Field(pattern=r"^IGCD-[0-9a-f]{32}$")
    ],
    body: RevisionEvidenceIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    principal = _human(request)
    ledger = _control_runtime(
        request
    ).require_conditional_access_decision_ledger()
    return await _call(
        ledger.revoke,
        decision_record_id,
        expected_revision=body.expected_revision,
        evidence_sha256=body.evidence_sha256,
        actor=principal,
    )


@router.get("/{sink}")
async def list_identity_outcomes(
    request: Request,
    sink: Literal["dynamic_risk", "alert"],
    status: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=100, ge=1, le=1_000),
) -> list[dict[str, Any]]:
    require_global_permission(request, "admin")
    _human(request)
    return await _call(
        _runtime(request).consumer(sink).list,
        status=status,
        limit=limit,
    )


@router.get("/{sink}/{outcome_id}")
async def get_identity_outcome(
    request: Request,
    sink: Literal["dynamic_risk", "alert"],
    outcome_id: OutcomeId,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _human(request)
    value = await _call(_runtime(request).consumer(sink).get, outcome_id)
    if value is None:
        raise HTTPException(status_code=404, detail="identity outcome was not found")
    return value


@router.post("/{sink}/worker")
async def run_identity_outcome_worker(
    request: Request,
    sink: Literal["dynamic_risk", "alert"],
    body: WorkerIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _human(request)
    return await _call(
        _runtime(request).consumer(sink).run_due,
        limit=body.limit,
    )


@router.post("/{sink}/{outcome_id}/replay")
async def replay_identity_outcome(
    request: Request,
    sink: Literal["dynamic_risk", "alert"],
    outcome_id: OutcomeId,
    body: RevisionEvidenceIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    principal = _human(request)
    return await _call(
        _runtime(request).consumer(sink).replay,
        outcome_id,
        expected_revision=body.expected_revision,
        replacement_event={},
        evidence_sha256=body.evidence_sha256,
        actor=principal,
    )


@router.post("/{sink}/{outcome_id}/revoke")
async def revoke_identity_outcome(
    request: Request,
    sink: Literal["dynamic_risk", "alert"],
    outcome_id: OutcomeId,
    body: RevisionEvidenceIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    principal = _human(request)
    return await _call(
        _runtime(request).consumer(sink).revoke,
        outcome_id,
        expected_revision=body.expected_revision,
        evidence_sha256=body.evidence_sha256,
        actor=principal,
    )


__all__ = ["router"]
