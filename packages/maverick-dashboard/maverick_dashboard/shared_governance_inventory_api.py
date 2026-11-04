"""Closed operator API for the six-suite shared governance inventory.

Tenant, principal, source providers, graph readers, integrity keys and raw
records are server-owned.  The API exposes only minimized snapshot reads and
governed maintenance operations.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from typing import Annotated, Protocol

from fastapi import APIRouter, HTTPException, Query, Request
from maverick import shared_governance_inventory as inventory
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

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
Identifier = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
    ),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReconcileIn(_StrictModel):
    expected_active_revision: int = Field(ge=0, le=10_000)
    expected_active_integrity_sha256: Digest
    operation_id: Identifier


class RetentionIn(_StrictModel):
    expected_active_revision: int = Field(ge=1, le=10_000)
    expected_active_integrity_sha256: Digest
    operation_id: Identifier
    retain_latest: int = Field(default=2, ge=1, le=100)


class InventoryRuntimeLike(Protocol):
    def status(self) -> Mapping[str, object]: ...

    def active_authority(self) -> Mapping[str, object]: ...

    def current_snapshot(self) -> Mapping[str, object]: ...

    def get_snapshot(self, snapshot_id: str) -> Mapping[str, object]: ...

    def list_snapshots(self, *, limit: int = 100) -> list[Mapping[str, object]]: ...

    def query_entities(self, **kwargs) -> Mapping[str, object]: ...

    def query_relationships(self, **kwargs) -> Mapping[str, object]: ...

    def export_snapshot(self, snapshot_id: str | None = None) -> Mapping[str, object]: ...

    def reconcile(self, **kwargs) -> Mapping[str, object]: ...

    def purge_expired(self, **kwargs) -> Mapping[str, object]: ...

    def verify_integrity(self) -> Mapping[str, object]: ...

    def write_recovery_checkpoint(self) -> Mapping[str, object]: ...

    def recover_latest(self) -> Mapping[str, object]: ...


class SharedGovernanceInventoryDependencies:
    def __init__(
        self,
        *,
        runtime_for: Callable[[str, str, Request], InventoryRuntimeLike] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[[str], bool] | None = None,
    ) -> None:
        for dependency in (runtime_for, enabled_probe, readiness_probe):
            if dependency is not None and not callable(dependency):
                raise TypeError("inventory dependency must be callable")
        self.runtime_for = runtime_for
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using governance inventory",
        )
    return tenant


def _principal_ref(request: Request, tenant_id: str) -> str:
    subject = caller_principal(request) or "authorized-local-operator"
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 512:
        raise HTTPException(status_code=401, detail="an authenticated principal is required")
    digest = hashlib.sha256(
        f"lightwork.shared-governance-inventory.identity.v1:{tenant_id}:{subject.strip()}".encode()
    ).hexdigest()
    return f"governance-inventory-principal-{digest[:40]}"


def _public_snapshot(value: Mapping[str, object]) -> dict[str, object]:
    try:
        return inventory.SharedGovernanceInventoryStore.public_snapshot(value)
    except inventory.SharedGovernanceInventoryError as exc:
        raise HTTPException(
            status_code=503,
            detail="inventory snapshot minimization failed",
        ) from exc


def _public_metadata(value: Mapping[str, object]) -> dict[str, object]:
    output = dict(value)
    output.pop("tenant_id", None)
    return output


def create_shared_governance_inventory_router(  # noqa: C901 - closed route assembly
    dependencies: SharedGovernanceInventoryDependencies | None = None,
) -> APIRouter:
    deps = dependencies or SharedGovernanceInventoryDependencies()
    router = APIRouter(
        prefix="/governance/inventory",
        tags=["shared-governance-inventory"],
    )

    def probe(request: Request, tenant_id: str) -> tuple[bool, bool]:
        enabled_probe = getattr(
            request.app.state,
            "shared_governance_inventory_enabled_probe",
            None,
        )
        readiness_probe = getattr(
            request.app.state,
            "shared_governance_inventory_readiness_probe",
            None,
        )
        selected_enabled = enabled_probe if callable(enabled_probe) else deps.enabled_probe
        selected_readiness = (
            readiness_probe if callable(readiness_probe) else deps.readiness_probe
        )
        try:
            enabled = selected_enabled(tenant_id) if callable(selected_enabled) else False
            ready = (
                selected_readiness(tenant_id)
                if callable(selected_readiness) and enabled is True
                else False
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="inventory configuration is unavailable",
            ) from exc
        if type(enabled) is not bool or type(ready) is not bool:
            raise HTTPException(
                status_code=503,
                detail="inventory configuration is unavailable",
            )
        return enabled, ready

    def authority(request: Request) -> tuple[str, InventoryRuntimeLike]:
        tenant = _tenant_id()
        enabled, ready = probe(request, tenant)
        if not enabled:
            raise HTTPException(status_code=403, detail="governance_inventory_disabled")
        if not ready:
            raise HTTPException(
                status_code=503,
                detail="inventory custody is unavailable",
            )
        factory = getattr(
            request.app.state,
            "shared_governance_inventory_runtime_factory",
            None,
        )
        selected = factory if callable(factory) else deps.runtime_for
        if not callable(selected):
            raise HTTPException(
                status_code=503,
                detail="inventory authority is unavailable",
            )
        try:
            runtime = selected(
                tenant_id=tenant,
                principal_ref=_principal_ref(request, tenant),
                request=request,
            )
        except inventory.SharedGovernanceInventoryPermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except inventory.SharedGovernanceInventoryError as exc:
            raise HTTPException(
                status_code=503,
                detail="inventory authority is unavailable",
            ) from exc
        required = (
            "status",
            "active_authority",
            "current_snapshot",
            "get_snapshot",
            "list_snapshots",
            "query_entities",
            "query_relationships",
            "export_snapshot",
            "reconcile",
            "purge_expired",
            "verify_integrity",
            "write_recovery_checkpoint",
            "recover_latest",
        )
        if any(not callable(getattr(runtime, name, None)) for name in required):
            raise HTTPException(
                status_code=503,
                detail="inventory authority is unavailable",
            )
        return tenant, runtime

    async def call(function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except inventory.SharedGovernanceInventoryNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except inventory.SharedGovernanceInventoryGone as exc:
            raise HTTPException(status_code=410, detail=str(exc)) from exc
        except inventory.SharedGovernanceInventoryConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except inventory.SharedGovernanceInventoryValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except inventory.SharedGovernanceInventoryPermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except inventory.SharedGovernanceInventoryConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except inventory.SharedGovernanceInventoryIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="inventory integrity verification failed",
            ) from exc
        except (OSError, RuntimeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="inventory dependency is unavailable",
            ) from exc

    @router.get("/status")
    async def status(request: Request):
        require_permission(request, "view")
        tenant = _tenant_id()
        enabled, ready = probe(request, tenant)
        if not enabled:
            return {
                "schema": "lightwork.shared-governance-inventory-status.v1",
                "enabled": False,
                "ready": False,
                "state": "unavailable",
                "complete": False,
                "required_sources": list(inventory.REQUIRED_SUITES),
                "raw_source_records_persisted": False,
                "raw_private_fields_persisted": False,
                "fuzzy_identity_merging_performed": False,
            }
        if not ready:
            return {
                "schema": "lightwork.shared-governance-inventory-status.v1",
                "enabled": True,
                "ready": False,
                "state": "unavailable",
                "complete": False,
                "limitations": ["inventory_custody_unavailable"],
            }
        _tenant, runtime = authority(request)
        result = dict(await call(runtime.status))
        result["ready"] = True
        return result

    @router.get("/active")
    async def active(request: Request):
        require_permission(request, "view")
        _tenant, runtime = authority(request)
        return await call(runtime.active_authority)

    @router.get("/snapshots")
    async def snapshots(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "view")
        _tenant, runtime = authority(request)
        items = await call(runtime.list_snapshots, limit=limit)
        public = [_public_metadata(item) for item in items]
        return {"items": public, "count": len(public)}

    @router.get("/snapshots/current")
    async def current(request: Request):
        require_permission(request, "view")
        _tenant, runtime = authority(request)
        return _public_snapshot(await call(runtime.current_snapshot))

    @router.get("/snapshots/{snapshot_id}")
    async def snapshot(request: Request, snapshot_id: Identifier):
        require_permission(request, "view")
        _tenant, runtime = authority(request)
        return _public_snapshot(await call(runtime.get_snapshot, snapshot_id))

    @router.get("/entities")
    async def entities(
        request: Request,
        snapshot_id: str | None = Query(default=None, min_length=1, max_length=128),
        source_id: str | None = Query(default=None, min_length=1, max_length=64),
        origin: str | None = Query(default=None, min_length=1, max_length=32),
        entity_kind: str | None = Query(default=None, min_length=1, max_length=64),
        cursor: int = Query(default=0, ge=0, le=2_147_483_647),
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "view")
        _tenant, runtime = authority(request)
        return await call(
            runtime.query_entities,
            snapshot_id=snapshot_id,
            source_id=source_id,
            origin=origin,
            entity_kind=entity_kind,
            cursor=cursor,
            limit=limit,
        )

    @router.get("/relationships")
    async def relationships(
        request: Request,
        snapshot_id: str | None = Query(default=None, min_length=1, max_length=128),
        relation_type: str | None = Query(default=None, min_length=1, max_length=64),
        entity_ref_sha256: str | None = Query(
            default=None,
            min_length=64,
            max_length=64,
            pattern=r"^[0-9a-f]{64}$",
        ),
        cursor: int = Query(default=0, ge=0, le=2_147_483_647),
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "view")
        _tenant, runtime = authority(request)
        return await call(
            runtime.query_relationships,
            snapshot_id=snapshot_id,
            relation_type=relation_type,
            entity_ref_sha256=entity_ref_sha256,
            cursor=cursor,
            limit=limit,
        )

    @router.get("/export")
    async def export(
        request: Request,
        snapshot_id: str | None = Query(default=None, min_length=1, max_length=128),
    ):
        require_permission(request, "audit")
        _tenant, runtime = authority(request)
        return await call(runtime.export_snapshot, snapshot_id)

    @router.get("/integrity")
    async def integrity_check(request: Request):
        require_permission(request, "audit")
        _tenant, runtime = authority(request)
        return await call(runtime.verify_integrity)

    @router.post("/reconcile")
    async def reconcile(request: Request, body: ReconcileIn):
        require_permission(request, "admin")
        _tenant, runtime = authority(request)
        result = await call(runtime.reconcile, **body.model_dump())
        return _public_snapshot(result)

    @router.post("/retention/purge")
    async def purge(request: Request, body: RetentionIn):
        require_permission(request, "admin")
        _tenant, runtime = authority(request)
        return await call(runtime.purge_expired, **body.model_dump())

    @router.post("/recovery/checkpoint")
    async def checkpoint(request: Request):
        require_permission(request, "admin")
        _tenant, runtime = authority(request)
        return await call(runtime.write_recovery_checkpoint)

    @router.post("/recovery/restore")
    async def restore(request: Request):
        require_permission(request, "admin")
        _tenant, runtime = authority(request)
        return await call(runtime.recover_latest)

    return router


router = create_shared_governance_inventory_router()

__all__ = [
    "SharedGovernanceInventoryDependencies",
    "create_shared_governance_inventory_router",
    "router",
]
