"""Authenticated operator API for the closed-loop AI-governance projection.

Tenant and principal are resolved exclusively from trusted server context.
The request contract contains no tenant, principal, authority snapshot, raw
telemetry, provider selector, credential, trigger, or provider-mutation field.
Source triggers enter only through the server composition callback.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal, Protocol

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .ai_governance_loop_composition import (
    AIGovernanceLoopCompositionError,
    ai_governance_loop_capability_enabled,
)
from .auth import caller_principal, require_permission

Digest = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    ),
]
OpaqueId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}$",
    ),
]
OperationId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$",
    ),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RevisionReasonIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**63 - 1)
    reason_sha256: Digest
    operation_id: OperationId


class ControlAuthorizationIn(RevisionReasonIn):
    decision: Literal["restrict", "block"]


class RollbackAuthorizationIn(RevisionReasonIn):
    target_revision: int = Field(ge=1, le=2**63 - 1)


class RollbackApplyIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**63 - 1)
    operation_id: OperationId


class AIGovernanceLoopRuntimeLike(Protocol):
    tenant_id: str
    principal_ref: str

    def status(self) -> Mapping[str, object]: ...

    def get_case(self, asset_id: str) -> Mapping[str, object]: ...

    def history(self, asset_id: str, *, limit: int): ...

    def verify_integrity(self, asset_id: str) -> Mapping[str, object]: ...

    def authorize_control(self, asset_id: str, **kwargs): ...

    def revoke_control_authorization(self, asset_id: str, **kwargs): ...

    def replay(self, asset_id: str, **kwargs): ...

    def authorize_rollback(self, asset_id: str, **kwargs): ...

    def revoke_rollback_authorization(self, asset_id: str, **kwargs): ...

    def apply_authorized_rollback(self, asset_id: str, **kwargs): ...

    def revoke_case(self, asset_id: str, **kwargs): ...


class AIGovernanceLoopDependencies:
    """Narrow lazy seams for deployment composition and isolated tests."""

    def __init__(
        self,
        *,
        runtime_for: Callable[[str, str, Request], AIGovernanceLoopRuntimeLike] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
    ) -> None:
        for dependency in (runtime_for, enabled_probe):
            if dependency is not None and not callable(dependency):
                raise TypeError("AI-governance-loop dependency must be callable")
        self.runtime_for = runtime_for
        self.enabled_probe = enabled_probe or ai_governance_loop_capability_enabled


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using the AI governance loop",
        )
    return tenant


def _principal_ref(request: Request, tenant_id: str) -> str:
    subject = caller_principal(request)
    if subject is None:
        subject = "authorized-local-operator"
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 512:
        raise HTTPException(status_code=401, detail="an authenticated principal is required")
    digest = hashlib.sha256(
        f"lightwork.ai-governance-loop.api-principal.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"ai-governance-loop-api.{digest[:40]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def create_ai_governance_loop_router(  # noqa: C901 - explicit closed route assembly
    dependencies: AIGovernanceLoopDependencies | None = None,
) -> APIRouter:
    deps = dependencies or AIGovernanceLoopDependencies()
    router = APIRouter(
        prefix="/assurance/governance-loop",
        tags=["ai-governance-loop"],
    )

    def capability(request: Request, tenant_id: str) -> bool:
        selected = getattr(request.app.state, "ai_governance_loop_enabled_probe", None)
        probe = selected if callable(selected) else deps.enabled_probe
        try:
            available = probe(tenant_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="AI-governance-loop configuration is unavailable",
            ) from exc
        if type(available) is not bool:
            raise HTTPException(
                status_code=503,
                detail="AI-governance-loop configuration is unavailable",
            )
        return available

    def authority(request: Request) -> tuple[Any, str, str, AIGovernanceLoopRuntimeLike]:
        from maverick import ai_governance_loop as loop

        tenant = _tenant_id()
        if not capability(request, tenant):
            raise HTTPException(status_code=403, detail="ai_governance_loop_disabled")
        principal = _principal_ref(request, tenant)
        selected = getattr(request.app.state, "ai_governance_loop_runtime_factory", None)
        factory = selected if callable(selected) else deps.runtime_for
        if not callable(factory):
            raise HTTPException(
                status_code=503,
                detail="AI-governance-loop authority is unavailable",
            )
        try:
            runtime = factory(tenant, principal, request)
        except (KeyboardInterrupt, SystemExit):
            raise
        except (AIGovernanceLoopCompositionError, loop.AIGovernanceLoopError, OSError) as exc:
            raise HTTPException(
                status_code=503,
                detail="AI-governance-loop authority is unavailable",
            ) from exc
        required = (
            "status",
            "get_case",
            "history",
            "verify_integrity",
            "authorize_control",
            "revoke_control_authorization",
            "replay",
            "authorize_rollback",
            "revoke_rollback_authorization",
            "apply_authorized_rollback",
            "revoke_case",
        )
        if any(not callable(getattr(runtime, method, None)) for method in required):
            raise HTTPException(
                status_code=503,
                detail="AI-governance-loop authority is unavailable",
            )
        if runtime.tenant_id != tenant or runtime.principal_ref != principal:
            raise HTTPException(
                status_code=503,
                detail="AI-governance-loop authority is unavailable",
            )
        return loop, tenant, principal, runtime

    async def call(loop, function, *args, **kwargs):
        try:
            return _jsonable(await run_in_threadpool(function, *args, **kwargs))
        except loop.AIGovernanceLoopNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (
            loop.AIGovernanceLoopConflict,
            loop.AIGovernanceLoopLeaseLost,
            loop.AIGovernanceLoopAuthorityDrift,
        ) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except loop.AIGovernanceLoopValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except loop.AIGovernanceLoopIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="AI-governance-loop integrity verification failed",
            ) from exc
        except (AIGovernanceLoopCompositionError, loop.AIGovernanceLoopError) as exc:
            raise HTTPException(
                status_code=503,
                detail="AI-governance-loop operation failed",
            ) from exc
        except (OSError, RuntimeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="AI-governance-loop dependency is unavailable",
            ) from exc

    @router.get("/status")
    async def status(request: Request):
        require_permission(request, "view")
        tenant = _tenant_id()
        if not capability(request, tenant):
            return {
                "schema": "lightwork.ai-governance-loop-api-status.v1",
                "enabled": False,
                "complete": False,
                "live_provider_acceptance_verified": False,
                "live_customer_acceptance_verified": False,
                "limits": {
                    "status_request_opens_store": False,
                    "http_trigger_ingestion_available": False,
                    "raw_telemetry_accepted": False,
                    "authority_snapshot_accepted": False,
                    "provider_selector_accepted": False,
                },
            }
        loop, _tenant, _principal, runtime = authority(request)
        result = await call(loop, runtime.status)
        result["schema"] = "lightwork.ai-governance-loop-api-status.v1"
        return result

    @router.get("/cases/{asset_id}")
    async def get_case(request: Request, asset_id: OpaqueId):
        require_permission(request, "view")
        loop, _tenant, _principal, runtime = authority(request)
        return await call(loop, runtime.get_case, asset_id)

    @router.get("/cases/{asset_id}/history")
    async def history(
        request: Request,
        asset_id: OpaqueId,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "audit")
        loop, _tenant, _principal, runtime = authority(request)
        items = await call(loop, runtime.history, asset_id, limit=limit)
        return {"items": items, "count": len(items)}

    @router.get("/cases/{asset_id}/integrity")
    async def integrity(request: Request, asset_id: OpaqueId):
        require_permission(request, "audit")
        loop, _tenant, _principal, runtime = authority(request)
        return await call(loop, runtime.verify_integrity, asset_id)

    @router.post("/cases/{asset_id}/control/authorize")
    async def authorize_control(
        request: Request,
        asset_id: OpaqueId,
        body: ControlAuthorizationIn,
    ):
        require_permission(request, "admin")
        loop, _tenant, _principal, runtime = authority(request)
        return await call(
            loop,
            runtime.authorize_control,
            asset_id,
            **body.model_dump(),
        )

    @router.post("/cases/{asset_id}/control/revoke")
    async def revoke_control(
        request: Request,
        asset_id: OpaqueId,
        body: RevisionReasonIn,
    ):
        require_permission(request, "admin")
        loop, _tenant, _principal, runtime = authority(request)
        return await call(
            loop,
            runtime.revoke_control_authorization,
            asset_id,
            **body.model_dump(),
        )

    @router.post("/cases/{asset_id}/replay")
    async def replay(request: Request, asset_id: OpaqueId, body: RevisionReasonIn):
        require_permission(request, "admin")
        loop, _tenant, _principal, runtime = authority(request)
        return await call(loop, runtime.replay, asset_id, **body.model_dump())

    @router.post("/cases/{asset_id}/rollback/authorize")
    async def authorize_rollback(
        request: Request,
        asset_id: OpaqueId,
        body: RollbackAuthorizationIn,
    ):
        require_permission(request, "admin")
        loop, _tenant, _principal, runtime = authority(request)
        return await call(
            loop,
            runtime.authorize_rollback,
            asset_id,
            **body.model_dump(),
        )

    @router.post("/cases/{asset_id}/rollback/revoke")
    async def revoke_rollback(
        request: Request,
        asset_id: OpaqueId,
        body: RevisionReasonIn,
    ):
        require_permission(request, "admin")
        loop, _tenant, _principal, runtime = authority(request)
        return await call(
            loop,
            runtime.revoke_rollback_authorization,
            asset_id,
            **body.model_dump(),
        )

    @router.post("/cases/{asset_id}/rollback/apply")
    async def apply_rollback(
        request: Request,
        asset_id: OpaqueId,
        body: RollbackApplyIn,
    ):
        require_permission(request, "admin")
        loop, _tenant, _principal, runtime = authority(request)
        return await call(
            loop,
            runtime.apply_authorized_rollback,
            asset_id,
            **body.model_dump(),
        )

    @router.post("/cases/{asset_id}/revoke")
    async def revoke_case(
        request: Request,
        asset_id: OpaqueId,
        body: RevisionReasonIn,
    ):
        require_permission(request, "admin")
        loop, _tenant, _principal, runtime = authority(request)
        return await call(loop, runtime.revoke_case, asset_id, **body.model_dump())

    return router


router = create_ai_governance_loop_router()

__all__ = [
    "AIGovernanceLoopDependencies",
    "AIGovernanceLoopRuntimeLike",
    "ControlAuthorizationIn",
    "RevisionReasonIn",
    "RollbackApplyIn",
    "RollbackAuthorizationIn",
    "create_ai_governance_loop_router",
    "router",
]
