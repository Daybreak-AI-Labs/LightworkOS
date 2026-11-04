"""Strict operator API for native Data Use provider-audit evidence.

Tenant and principal authority are derived from authenticated server context.
The surface deliberately has no raw-event ingestion route and accepts neither
provider origins nor credentials. Provider-audit expectations are registered by
the trusted provider-write composition layer, not by an HTTP caller.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal, Protocol

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDEMPOTENCY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_REASON_PATTERN = r"^[a-z][a-z0-9_]{0,47}$"

OpaqueRef = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_REF_PATTERN),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_REF_PATTERN),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=192,
        pattern=_IDEMPOTENCY_PATTERN,
    ),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST_PATTERN),
]
ReasonCode = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=48, pattern=_REASON_PATTERN),
]
ProviderId = Literal["snowflake", "databricks"]
ExpectationState = Literal[
    "queued",
    "leased",
    "ambiguous",
    "cancelled",
    "converged",
    "dead_letter",
    "drift",
    "extra",
    "missing",
    "no_change",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CancelExpectationIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    reason_code: ReasonCode
    idempotency_key: IdempotencyKey


class ReplayExpectationIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class RunOnceIn(_StrictModel):
    limit: int = Field(default=10, ge=1, le=100)
    lease_seconds: int = Field(default=120, ge=30, le=86_400)
    event_limit: int = Field(default=100, ge=1, le=500)
    backoff_seconds: int = Field(default=30, ge=0, le=86_400)


class IssueReadGrantIn(_StrictModel):
    """Absolute lifecycle and CAS pins; credentials remain server-resolved."""

    expected_binding_revision: int = Field(ge=1, le=2**31 - 1)
    expected_binding_sha256: Digest
    capability_revision: int = Field(ge=1, le=2**31 - 1)
    valid_until: float = Field(gt=0, lt=100_000_000_000.0)
    retained_until: float = Field(gt=0, lt=100_000_000_000.0)
    expected_revision: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class RevokeReadGrantIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    expected_integrity_sha256: Digest
    reason_sha256: Digest
    idempotency_key: IdempotencyKey


class ProviderAuditStore(Protocol):
    def state_counts(self) -> Mapping[str, int]: ...

    def list_expectations(self, *, state: str | None, limit: int): ...

    def get_expectation(self, expectation_id: str): ...

    def list_event_evidence(self, expectation_id: str, *, limit: int): ...

    def cancel_expectation(
        self,
        expectation_id: str,
        *,
        expected_revision: int,  # noqa
        reason_code: str,  # noqa
        idempotency_key: str,  # noqa
    ): ...

    def replay_dead_letter(
        self,
        expectation_id: str,
        *,
        expected_revision: int,  # noqa
        idempotency_key: str,  # noqa
    ): ...

    def verify_integrity(self): ...


class ProviderAuditWorker(Protocol):
    def run_once(
        self,
        *,
        worker_id: str,
        limit: int,
        lease_seconds: int,  # noqa
        event_limit: int,  # noqa
        backoff_seconds: int,  # noqa
    ): ...


class ProviderAuditReadGrantAuthority(Protocol):
    """Deployment-owned independent provider-audit-read grant authority."""

    def get_current_read_grant(self, provider_id: str, binding_id: str): ...

    def issue_read_grant(
        self,
        *,
        provider_id: str,
        binding_id: str,
        expected_binding_revision: int,  # noqa
        expected_binding_sha256: str,  # noqa
        capability_revision: int,  # noqa
        valid_until: float,  # noqa
        retained_until: float,  # noqa
        expected_revision: int,  # noqa
        idempotency_key: str,  # noqa
    ): ...

    def revoke_read_grant(
        self,
        grant_id: str,
        *,
        expected_revision: int,  # noqa
        expected_integrity_sha256: str,  # noqa
        reason_sha256: str,  # noqa
        idempotency_key: str,  # noqa
    ): ...


class DataUseProviderAuditDependencies:
    """Narrow deployment composition seams; all are optional and fail closed."""

    def __init__(
        self,
        *,
        store_for: Callable[[str, str], ProviderAuditStore] | None = None,
        worker_for: Callable[[str, str, ProviderAuditStore], ProviderAuditWorker] | None = None,
        read_grants_for: Callable[[str, str, ProviderAuditStore], ProviderAuditReadGrantAuthority]
        | None = None,
    ) -> None:
        for dependency in (store_for, worker_for, read_grants_for):
            if dependency is not None and not callable(dependency):
                raise TypeError("provider-audit dependency must be callable")
        self.store_for = store_for
        self.worker_for = worker_for
        self.read_grants_for = read_grants_for


def _enabled() -> bool:
    from maverick.data_use_provider_audit import enabled

    return enabled()


def data_use_provider_audit_enabled_for_page() -> bool:
    return _enabled()


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using provider audit",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for provider audit",
    )
    digest = hashlib.sha256(
        f"lightwork.data-use.provider-audit.api-principal.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"provider-audit-api.{digest[:40]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def create_data_use_provider_audit_router(  # noqa: C901 - one closed operator surface
    dependencies: DataUseProviderAuditDependencies | None = None,
) -> APIRouter:
    deps = dependencies or DataUseProviderAuditDependencies()
    router = APIRouter(
        prefix="/data-use/providers/audit",
        tags=["data-use-provider-audit"],
    )

    def authority(request: Request):
        from maverick import data_use_provider_audit as audit

        try:
            audit.require_enabled()
        except audit.DataUseProviderAuditConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        factory = getattr(
            request.app.state,
            "data_use_provider_audit_store_factory",
            None,
        )
        try:
            if callable(factory):
                store = factory(
                    tenant_id=tenant,
                    principal_ref=principal,
                    request=request,
                )
            elif deps.store_for is not None:
                store = deps.store_for(tenant, principal)
            else:
                store = None
        except audit.DataUseProviderAuditConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (audit.DataUseProviderAuditError, OSError) as exc:
            raise HTTPException(
                status_code=503,
                detail="provider-audit store is unavailable",
            ) from exc
        if store is None:
            raise HTTPException(
                status_code=503,
                detail="provider-audit store is unavailable",
            )
        return audit, tenant, principal, store

    async def call(audit, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except audit.DataUseProviderAuditNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (
            audit.DataUseProviderAuditConflict,
            audit.DataUseProviderAuditLeaseLost,
        ) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except audit.DataUseProviderAuditValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except audit.DataUseProviderAuditConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except audit.DataUseProviderAuditIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="provider-audit integrity verification failed",
            ) from exc
        except audit.DataUseProviderAuditError as exc:
            raise HTTPException(
                status_code=503,
                detail="provider-audit operation failed",
            ) from exc
        except (OSError, RuntimeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="provider-audit dependency is unavailable",
            ) from exc

    def worker_for(
        request: Request,
        tenant: str,
        principal: str,
        store: ProviderAuditStore,
    ) -> ProviderAuditWorker:
        factory = getattr(
            request.app.state,
            "data_use_provider_audit_worker_factory",
            None,
        )
        try:
            if callable(factory):
                worker = factory(
                    tenant_id=tenant,
                    principal_ref=principal,
                    store=store,
                    request=request,
                )
            elif deps.worker_for is not None:
                worker = deps.worker_for(tenant, principal, store)
            else:
                worker = None
        except Exception as exc:  # noqa: BLE001 - dependency detail is not exposed
            raise HTTPException(
                status_code=503,
                detail="provider-audit worker is unavailable",
            ) from exc
        if worker is None or not callable(getattr(worker, "run_once", None)):
            raise HTTPException(
                status_code=503,
                detail="provider-audit worker is unavailable",
            )
        return worker

    def read_grants_for(
        request: Request,
        tenant: str,
        principal: str,
        store: ProviderAuditStore,
    ) -> ProviderAuditReadGrantAuthority:
        factory = getattr(
            request.app.state,
            "data_use_provider_audit_read_grant_factory",
            None,
        )
        try:
            if callable(factory):
                authority_manager = factory(
                    tenant_id=tenant,
                    principal_ref=principal,
                    store=store,
                    request=request,
                )
            elif deps.read_grants_for is not None:
                authority_manager = deps.read_grants_for(tenant, principal, store)
            else:
                authority_manager = None
        except Exception as exc:  # noqa: BLE001 - dependency detail is not exposed
            raise HTTPException(
                status_code=503,
                detail="provider-audit read-grant authority is unavailable",
            ) from exc
        required = (
            "get_current_read_grant",
            "issue_read_grant",
            "revoke_read_grant",
        )
        if authority_manager is None or not all(
            callable(getattr(authority_manager, name, None)) for name in required
        ):
            raise HTTPException(
                status_code=503,
                detail="provider-audit read-grant authority is unavailable",
            )
        return authority_manager

    @router.get("/status")
    async def status(request: Request):
        require_permission(request, "view")
        scheduler = getattr(
            request.app.state,
            "data_use_provider_audit_scheduler",
            None,
        )
        scheduler_status = scheduler.status() if scheduler is not None else None
        return {
            "schema": "lightwork.data-use.provider-audit-status.v1",
            "enabled": _enabled(),
            "scheduler": scheduler_status,
            "store_dependency_injected": bool(
                callable(
                    getattr(
                        request.app.state,
                        "data_use_provider_audit_store_factory",
                        None,
                    )
                )
                or deps.store_for is not None
            ),
            "worker_dependency_injected": bool(
                callable(
                    getattr(
                        request.app.state,
                        "data_use_provider_audit_worker_factory",
                        None,
                    )
                )
                or deps.worker_for is not None
            ),
            "read_grant_authority_injected": bool(
                callable(
                    getattr(
                        request.app.state,
                        "data_use_provider_audit_read_grant_factory",
                        None,
                    )
                )
                or deps.read_grants_for is not None
            ),
            "raw_provider_event_ingestion_exposed": False,
            "raw_provider_payload_persisted": False,
            "credentials_accepted_or_persisted": False,
            "provider_writes_performed": False,
            "built_in_network_transport_available": True,
            "built_in_network_transport": True,
            "network_transport_activation_verified": False,
            "audit_log_completeness_verified": False,
            "live_provider_acceptance_verified": False,
        }

    @router.get("/counts")
    async def counts(request: Request):
        require_permission(request, "operate")
        audit, _tenant, _principal_ref, store = authority(request)
        return _jsonable(await call(audit, store.state_counts))

    @router.get("/expectations")
    async def list_expectations(
        request: Request,
        state: ExpectationState | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
    ):
        require_permission(request, "operate")
        audit, _tenant, _principal_ref, store = authority(request)
        items = await call(audit, store.list_expectations, state=state, limit=limit)
        return {"items": _jsonable(items), "count": len(items)}

    @router.get("/expectations/{expectation_id}")
    async def get_expectation(request: Request, expectation_id: ObjectPath):
        require_permission(request, "operate")
        audit, _tenant, _principal_ref, store = authority(request)
        return _jsonable(await call(audit, store.get_expectation, expectation_id))

    @router.get("/expectations/{expectation_id}/evidence")
    async def list_evidence(
        request: Request,
        expectation_id: ObjectPath,
        limit: int = Query(default=100, ge=1, le=500),
    ):
        require_global_permission(request, "audit")
        audit, _tenant, _principal_ref, store = authority(request)
        items = await call(
            audit,
            store.list_event_evidence,
            expectation_id,
            limit=limit,
        )
        return {"items": _jsonable(items), "count": len(items)}

    @router.post("/expectations/{expectation_id}/cancel")
    async def cancel_expectation(
        request: Request,
        expectation_id: ObjectPath,
        body: CancelExpectationIn,
    ):
        require_global_permission(request, "admin")
        audit, _tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(
                audit,
                store.cancel_expectation,
                expectation_id,
                **body.model_dump(),
            )
        )

    @router.post("/expectations/{expectation_id}/replay")
    async def replay_expectation(
        request: Request,
        expectation_id: ObjectPath,
        body: ReplayExpectationIn,
    ):
        require_global_permission(request, "admin")
        audit, _tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(
                audit,
                store.replay_dead_letter,
                expectation_id,
                **body.model_dump(),
            )
        )

    @router.get("/integrity")
    async def integrity(request: Request):
        require_global_permission(request, "audit")
        audit, _tenant, _principal_ref, store = authority(request)
        result = _jsonable(await call(audit, store.verify_integrity))
        if isinstance(result, dict):
            result["valid"] = True
        return result

    @router.post("/admin/run-once")
    async def run_once(request: Request, body: RunOnceIn):
        require_global_permission(request, "admin")
        audit, tenant, principal, store = authority(request)
        worker = worker_for(request, tenant, principal, store)
        worker_id = (
            "provider-audit-api."
            + hashlib.sha256(
                f"lightwork.data-use.provider-audit.run.v1:{tenant}:{principal}".encode()
            ).hexdigest()[:32]
        )
        return _jsonable(
            await call(
                audit,
                worker.run_once,
                worker_id=worker_id,
                **body.model_dump(),
            )
        )

    @router.get("/read-authorities/{provider_id}/{binding_id}")
    async def get_read_grant(
        request: Request,
        provider_id: ProviderId,
        binding_id: ObjectPath,
    ):
        require_global_permission(request, "admin")
        audit, tenant, principal, store = authority(request)
        manager = read_grants_for(request, tenant, principal, store)
        return _jsonable(
            await call(
                audit,
                manager.get_current_read_grant,
                provider_id,
                binding_id,
            )
        )

    @router.post("/read-authorities/{provider_id}/{binding_id}/issue")
    async def issue_read_grant(
        request: Request,
        provider_id: ProviderId,
        binding_id: ObjectPath,
        body: IssueReadGrantIn,
    ):
        require_global_permission(request, "admin")
        audit, tenant, principal, store = authority(request)
        manager = read_grants_for(request, tenant, principal, store)
        return _jsonable(
            await call(
                audit,
                manager.issue_read_grant,
                provider_id=provider_id,
                binding_id=binding_id,
                **body.model_dump(),
            )
        )

    @router.post("/read-authorities/grants/{grant_id}/revoke")
    async def revoke_read_grant(
        request: Request,
        grant_id: ObjectPath,
        body: RevokeReadGrantIn,
    ):
        require_global_permission(request, "admin")
        audit, tenant, principal, store = authority(request)
        manager = read_grants_for(request, tenant, principal, store)
        return _jsonable(
            await call(
                audit,
                manager.revoke_read_grant,
                grant_id,
                **body.model_dump(),
            )
        )

    return router


router = create_data_use_provider_audit_router()

__all__ = [
    "DataUseProviderAuditDependencies",
    "ProviderAuditReadGrantAuthority",
    "ProviderAuditStore",
    "ProviderAuditWorker",
    "create_data_use_provider_audit_router",
    "data_use_provider_audit_enabled_for_page",
    "router",
]
