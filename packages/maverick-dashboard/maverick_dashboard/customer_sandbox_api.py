"""Global-admin API for governed customer sandbox tenant copies."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt, StrictStr
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_global_permission

ObjectId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]
IdempotencyKey = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$")]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RequestSandboxIn(_StrictModel):
    source_tenant_id: ObjectId
    target_sandbox_id: ObjectId
    module_allowlist: list[StrictStr] = Field(min_length=1, max_length=6)
    expires_at: StrictFloat
    retained_until: StrictFloat
    plan: ObjectId
    quota_bytes: StrictInt = Field(ge=4_096, le=50 * 1024 * 1024)
    max_attempts: StrictInt = Field(default=5, ge=1, le=20)
    idempotency_key: IdempotencyKey


class RevisionIn(_StrictModel):
    expected_revision: StrictInt = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class ProvisionIn(RevisionIn):
    retry: bool = False


class ResyncIn(RevisionIn):
    module_allowlist: list[StrictStr] | None = Field(default=None, min_length=1, max_length=6)


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _principal_ref(request: Request) -> str:
    subject = caller_principal(request) or "operator:authorized-local"
    digest = hashlib.sha256(
        f"lightwork.customer-sandbox.api-principal.v1:{subject}".encode()
    ).hexdigest()
    return f"customer-sandbox-api.{digest[:40]}"


class CustomerSandboxDependencies:
    """Injected global control-plane factory; no request tenant selects the store."""

    def __init__(
        self,
        *,
        store_factory: Callable[..., Any] | None = None,
        capability_probe: Callable[[], bool] | None = None,
    ) -> None:
        self.store_factory = store_factory
        self.capability_probe = capability_probe


def create_customer_sandbox_router(  # noqa: C901 - explicit route-local authority gates
    dependencies: CustomerSandboxDependencies | None = None,
) -> APIRouter:
    deps = dependencies or CustomerSandboxDependencies()
    router = APIRouter(prefix="/customer-sandboxes", tags=["customer-sandboxes"])

    def capability(request: Request):
        require_global_permission(request, "admin")
        from maverick import customer_sandbox_lifecycle as lifecycle

        probe = getattr(request.app.state, "customer_sandbox_capability_probe", None)
        selected_probe = probe if callable(probe) else deps.capability_probe
        if not callable(selected_probe):
            raise HTTPException(status_code=503, detail="customer sandbox authority is unavailable")
        try:
            available = selected_probe()
        except lifecycle.CustomerSandboxConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        if type(available) is not bool:
            raise HTTPException(status_code=503, detail="customer sandbox authority is unavailable")
        return lifecycle, available

    def authority(request: Request, *, admission_required: bool = True):
        lifecycle, available = capability(request)
        if admission_required and not available:
            raise HTTPException(status_code=403, detail="customer_sandbox_lifecycle_disabled")

        principal = _principal_ref(request)

        def principal_resolver() -> str:
            return principal

        factory = getattr(request.app.state, "customer_sandbox_store_factory", None)
        selected = factory if callable(factory) else deps.store_factory
        if not callable(selected):
            raise HTTPException(status_code=503, detail="customer sandbox authority is unavailable")
        try:
            store = selected(
                principal_ref=principal,
                principal_resolver=principal_resolver,
            )
        except lifecycle.CustomerSandboxConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (lifecycle.CustomerSandboxError, OSError) as exc:
            raise HTTPException(
                status_code=503,
                detail="customer sandbox authority is unavailable",
            ) from exc
        if type(store) is not lifecycle.CustomerSandboxLifecycleStore:
            raise HTTPException(status_code=503, detail="customer sandbox authority is unavailable")
        return lifecycle, store

    async def call(lifecycle, function, *args, **kwargs):
        try:
            return _jsonable(await run_in_threadpool(function, *args, **kwargs))
        except lifecycle.CustomerSandboxNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except lifecycle.CustomerSandboxPermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except lifecycle.CustomerSandboxConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except lifecycle.CustomerSandboxValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except lifecycle.CustomerSandboxConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except lifecycle.CustomerSandboxIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="customer sandbox integrity verification failed",
            ) from exc
        except lifecycle.CustomerSandboxProvisioningError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except lifecycle.CustomerSandboxError as exc:
            raise HTTPException(status_code=503, detail="customer sandbox operation failed") from exc

    @router.get("/status")
    async def status(request: Request):
        lifecycle, available = capability(request)
        if not available:
            return {
                "schema": "lightwork.customer-sandbox-api-status.v1",
                "enabled": False,
                **lifecycle.CustomerSandboxLifecycleStore.product_boundaries(),
            }
        lifecycle, store = authority(request)
        result = await call(lifecycle, store.status)
        result["schema"] = "lightwork.customer-sandbox-api-status.v1"
        return result

    @router.post("/{sandbox_id}/request")
    async def request_sandbox(request: Request, sandbox_id: ObjectId, body: RequestSandboxIn):
        lifecycle, store = authority(request)
        return await call(
            lifecycle,
            store.request_sandbox,
            sandbox_id,
            **body.model_dump(),
        )

    @router.get("")
    async def list_sandboxes(request: Request, limit: int = Query(default=100, ge=1, le=500)):
        lifecycle, store = authority(request, admission_required=False)
        items = await call(lifecycle, store.list_sandboxes, limit=limit)
        return {"items": items, "count": len(items)}

    @router.get("/{sandbox_id}")
    async def get_sandbox(request: Request, sandbox_id: ObjectId):
        lifecycle, store = authority(request, admission_required=False)
        return await call(lifecycle, store.get_sandbox, sandbox_id)

    @router.post("/{sandbox_id}/approve")
    async def approve(request: Request, sandbox_id: ObjectId, body: RevisionIn):
        lifecycle, store = authority(request)
        return await call(lifecycle, store.approve_sandbox, sandbox_id, **body.model_dump())

    @router.post("/{sandbox_id}/provision")
    async def provision(request: Request, sandbox_id: ObjectId, body: ProvisionIn):
        lifecycle, store = authority(request)
        return await call(lifecycle, store.provision_sandbox, sandbox_id, **body.model_dump())

    @router.post("/{sandbox_id}/suspend")
    async def suspend(request: Request, sandbox_id: ObjectId, body: RevisionIn):
        lifecycle, store = authority(request, admission_required=False)
        return await call(lifecycle, store.suspend_sandbox, sandbox_id, **body.model_dump())

    @router.post("/{sandbox_id}/resume")
    async def resume(request: Request, sandbox_id: ObjectId, body: RevisionIn):
        lifecycle, store = authority(request)
        return await call(lifecycle, store.resume_sandbox, sandbox_id, **body.model_dump())

    @router.post("/{sandbox_id}/expire")
    async def expire(request: Request, sandbox_id: ObjectId, body: RevisionIn):
        lifecycle, store = authority(request, admission_required=False)
        return await call(lifecycle, store.expire_sandbox, sandbox_id, **body.model_dump())

    @router.post("/{sandbox_id}/resync/request")
    async def request_resync(request: Request, sandbox_id: ObjectId, body: ResyncIn):
        lifecycle, store = authority(request)
        return await call(lifecycle, store.request_resync, sandbox_id, **body.model_dump())

    @router.post("/{sandbox_id}/destroy/request")
    async def request_destroy(request: Request, sandbox_id: ObjectId, body: RevisionIn):
        lifecycle, store = authority(request, admission_required=False)
        return await call(lifecycle, store.request_destroy, sandbox_id, **body.model_dump())

    @router.post("/{sandbox_id}/destroy/approve")
    async def approve_destroy(request: Request, sandbox_id: ObjectId, body: RevisionIn):
        lifecycle, store = authority(request, admission_required=False)
        return await call(lifecycle, store.approve_destroy, sandbox_id, **body.model_dump())

    @router.post("/{sandbox_id}/destroy")
    async def destroy(request: Request, sandbox_id: ObjectId, body: RevisionIn):
        lifecycle, store = authority(request, admission_required=False)
        return await call(lifecycle, store.destroy_sandbox, sandbox_id, **body.model_dump())

    @router.post("/{sandbox_id}/abandon/request")
    async def request_abandon(request: Request, sandbox_id: ObjectId, body: RevisionIn):
        lifecycle, store = authority(request, admission_required=False)
        return await call(lifecycle, store.request_abandon, sandbox_id, **body.model_dump())

    @router.post("/{sandbox_id}/abandon/approve")
    async def approve_abandon(request: Request, sandbox_id: ObjectId, body: RevisionIn):
        lifecycle, store = authority(request, admission_required=False)
        return await call(lifecycle, store.approve_abandon, sandbox_id, **body.model_dump())

    @router.post("/{sandbox_id}/abandon")
    async def abandon(request: Request, sandbox_id: ObjectId, body: RevisionIn):
        lifecycle, store = authority(request, admission_required=False)
        return await call(
            lifecycle,
            store.abandon_failed_sandbox,
            sandbox_id,
            **body.model_dump(),
        )

    @router.post("/{sandbox_id}/retention/purge")
    async def retention_purge(request: Request, sandbox_id: ObjectId, body: RevisionIn):
        lifecycle, store = authority(request, admission_required=False)
        return await call(
            lifecycle,
            store.purge_destroyed_sandbox,
            sandbox_id,
            **body.model_dump(),
        )

    @router.get("/{sandbox_id}/history")
    async def history(
        request: Request,
        sandbox_id: ObjectId,
        limit: int = Query(default=100, ge=1, le=500),
    ):
        lifecycle, store = authority(request, admission_required=False)
        items = await call(lifecycle, store.history, sandbox_id, limit=limit)
        return {"items": items, "count": len(items)}

    @router.get("/integrity/verify")
    async def integrity(request: Request):
        lifecycle, store = authority(request, admission_required=False)
        return await call(lifecycle, store.verify_integrity)

    return router


router = create_customer_sandbox_router()

__all__ = [
    "CustomerSandboxDependencies",
    "create_customer_sandbox_router",
    "router",
]
