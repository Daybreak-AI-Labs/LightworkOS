"""Strict tenant-bound operator API for the six-suite unified audit projection.

The surface accepts no tenant selector, raw audit event, source registration,
source payload, actor, resource identifier, or credential.  Tenant and caller
authority come from authenticated server context; source adapters are installed
only by deployment composition.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal, Protocol

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_permission

SourceId = Literal[
    "ai_governance",
    "consent_preferences",
    "data_use_governance",
    "privacy_automation",
    "tech_risk_compliance",
    "third_party_management",
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReconcileIn(_StrictModel):
    source_id: SourceId | None = None


class ReplayIn(_StrictModel):
    expected_state_revision: int = Field(ge=1, le=2**63 - 1)
    reason_sha256: Digest


class RevokeIn(ReplayIn):
    pass


class AuthorizeRotationIn(_StrictModel):
    expected_state_revision: int = Field(ge=1, le=2**63 - 1)
    expected_authority_revision: int = Field(ge=1, le=2**31 - 1)
    expected_authority_sha256: Digest
    new_authority_revision: int = Field(ge=1, le=2**31 - 1)
    new_authority_sha256: Digest
    new_source_schema_version: int = Field(ge=1, le=2**31 - 1)
    new_verifier_identity_sha256: Digest
    new_trust_root_revision: int = Field(ge=1, le=2**31 - 1)
    new_source_key_id_sha256: Digest
    reason_sha256: Digest


class UnifiedAuditProjectorLike(Protocol):
    store: Any

    def status(self) -> Mapping[str, Any]: ...

    def run_all(self, *, worker_id: str): ...

    def run_source(self, source_id: str, *, worker_id: str): ...


class UnifiedAuditDependencies:
    """Narrow deployment-owned seams; absent dependencies fail closed."""

    def __init__(
        self,
        *,
        projector_for: Callable[[str, str, Request], UnifiedAuditProjectorLike] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
    ) -> None:
        for dependency in (projector_for, enabled_probe):
            if dependency is not None and not callable(dependency):
                raise TypeError("unified-audit dependency must be callable")
        self.projector_for = projector_for
        self.enabled_probe = enabled_probe


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using unified audit",
        )
    return tenant


def _principal_ref(request: Request, tenant_id: str) -> str:
    subject = caller_principal(request)
    if subject is None:
        subject = "authorized-local-operator"
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 512:
        raise HTTPException(status_code=401, detail="an authenticated principal is required")
    digest = hashlib.sha256(
        f"lightwork.unified-audit.api-principal.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"unified-audit-api.{digest[:40]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def create_unified_audit_router(  # noqa: C901 - explicit closed route assembly
    dependencies: UnifiedAuditDependencies | None = None,
) -> APIRouter:
    deps = dependencies or UnifiedAuditDependencies()
    router = APIRouter(prefix="/audit/unified", tags=["unified-audit"])

    def capability(request: Request, tenant: str) -> tuple[Any, bool]:
        from maverick import unified_audit as audit

        probe = getattr(request.app.state, "unified_audit_enabled_probe", None)
        selected = probe if callable(probe) else deps.enabled_probe
        try:
            available = selected(tenant) if callable(selected) else audit.enabled()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="unified-audit configuration is unavailable",
            ) from exc
        if type(available) is not bool:
            raise HTTPException(
                status_code=503,
                detail="unified-audit configuration is unavailable",
            )
        return audit, available

    def authority(request: Request) -> tuple[Any, str, str, UnifiedAuditProjectorLike]:
        tenant = _tenant_id()
        audit, available = capability(request, tenant)
        if not available:
            raise HTTPException(status_code=403, detail="unified_audit_disabled")
        try:
            audit.require_enabled()
        except audit.UnifiedAuditConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        principal = _principal_ref(request, tenant)
        factory = getattr(request.app.state, "unified_audit_projector_factory", None)
        selected = factory if callable(factory) else deps.projector_for
        if not callable(selected):
            raise HTTPException(status_code=503, detail="unified-audit authority is unavailable")
        try:
            projector = selected(tenant, principal, request)
        except audit.UnifiedAuditConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="unified-audit authority is unavailable",
            ) from exc
        except (audit.UnifiedAuditError, OSError, RuntimeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="unified-audit authority is unavailable",
            ) from exc
        required = ("status", "run_all", "run_source")
        if any(not callable(getattr(projector, method, None)) for method in required):
            raise HTTPException(status_code=503, detail="unified-audit authority is unavailable")
        store = getattr(projector, "store", None)
        if store is None:
            raise HTTPException(status_code=503, detail="unified-audit authority is unavailable")
        return audit, tenant, principal, projector

    async def call(audit, function, *args, **kwargs):
        try:
            return _jsonable(await run_in_threadpool(function, *args, **kwargs))
        except audit.UnifiedAuditNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (audit.UnifiedAuditConflict, audit.UnifiedAuditLeaseLost) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except audit.UnifiedAuditValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except audit.UnifiedAuditConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except audit.UnifiedAuditIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="unified-audit integrity verification failed",
            ) from exc
        except audit.UnifiedAuditError as exc:
            raise HTTPException(
                status_code=503,
                detail="unified-audit operation failed",
            ) from exc
        except (OSError, RuntimeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="unified-audit dependency is unavailable",
            ) from exc

    @router.get("/status")
    async def status(request: Request):
        require_permission(request, "audit")
        tenant = _tenant_id()
        audit, available = capability(request, tenant)
        if not available:
            return {
                "schema": "lightwork.unified-audit-api-status.v1",
                "enabled": False,
                "complete": False,
                "live_source_interoperability_verified": False,
                "live_customer_acceptance_verified": False,
                "required_sources": list(audit.REQUIRED_SUITES),
                "limits": {
                    "status_request_opens_projection_store": False,
                    "raw_event_ingestion_route": False,
                    "caller_source_registration_route": False,
                },
            }
        audit, _tenant, _principal, projector = authority(request)
        result = await call(audit, projector.status)
        result["schema"] = "lightwork.unified-audit-api-status.v1"
        return result

    @router.get("/sources")
    async def sources(request: Request):
        require_permission(request, "audit")
        audit, _tenant, _principal, projector = authority(request)
        status_result = await call(audit, projector.status)
        items = status_result.get("sources", [])
        return {
            "items": items,
            "count": len(items),
            "complete": status_result["complete"],
            "source_adapter_coverage": status_result.get(
                "source_adapter_coverage",
                {},
            ),
        }

    @router.get("/history")
    async def history(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "audit")
        audit, _tenant, _principal, projector = authority(request)
        items = await call(audit, projector.store.list_history, limit=limit)
        return {"items": items, "count": len(items)}

    @router.get("/integrity")
    async def integrity(request: Request):
        require_permission(request, "audit")
        audit, _tenant, _principal, projector = authority(request)
        return await call(audit, projector.store.verify_integrity)

    @router.post("/reconcile")
    async def reconcile(request: Request, body: ReconcileIn):
        require_permission(request, "admin")
        audit, _tenant, principal, projector = authority(request)
        if body.source_id is None:
            results = await call(audit, projector.run_all, worker_id=principal)
        else:
            results = [
                await call(
                    audit,
                    projector.run_source,
                    body.source_id,
                    worker_id=principal,
                )
            ]
        status_result = await call(audit, projector.status)
        return {"results": results, "status": status_result}

    @router.post("/sources/{source_id}/replay")
    async def replay(request: Request, source_id: SourceId, body: ReplayIn):
        require_permission(request, "admin")
        audit, _tenant, _principal, projector = authority(request)
        return await call(
            audit,
            projector.store.replay_source,
            source_id,
            **body.model_dump(),
        )

    @router.post("/sources/{source_id}/revoke")
    async def revoke(request: Request, source_id: SourceId, body: RevokeIn):
        require_permission(request, "admin")
        audit, _tenant, _principal, projector = authority(request)
        return await call(
            audit,
            projector.store.revoke_source,
            source_id,
            **body.model_dump(),
        )

    @router.post("/sources/{source_id}/rotation/authorize")
    async def authorize_rotation(
        request: Request,
        source_id: SourceId,
        body: AuthorizeRotationIn,
    ):
        require_permission(request, "admin")
        audit, _tenant, _principal, projector = authority(request)
        return await call(
            audit,
            projector.store.authorize_rotation,
            source_id,
            **body.model_dump(),
        )

    return router


router = create_unified_audit_router()

__all__ = [
    "create_unified_audit_router",
    "router",
    "UnifiedAuditDependencies",
]
