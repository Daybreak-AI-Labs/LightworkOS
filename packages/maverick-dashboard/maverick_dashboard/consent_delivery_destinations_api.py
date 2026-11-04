"""Operator API for named consent-destination readiness and reconciliation."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission

router = APIRouter(
    prefix="/consent/delivery/destination-adapters",
    tags=["consent-delivery-destinations"],
)

_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_DIGEST = r"^[0-9a-f]{64}$"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReconcileIn(_StrictModel):
    message_sha256: str = Field(pattern=_DIGEST)
    request_sha256: str = Field(pattern=_DIGEST)


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using destination adapters",
        )
    return tenant


def _delivery_store(tenant_id: str):
    from maverick.paths import data_dir

    from .consent_delivery_api import _ops

    # Share the ordinary delivery API's feature/configuration refusal before
    # constructing a store; a disabled module is not an internal server error.
    return _ops().ConsentDeliveryStore(
        data_dir(
            "consent_preferences",
            "consent-delivery.sqlite3",
            tenant=tenant_id,
        )
    )


def _runtime(request: Request, tenant_id: str):
    factory = getattr(request.app.state, "consent_destination_runtime_factory", None)
    if not callable(factory):
        raise HTTPException(
            status_code=503,
            detail="named consent destination runtime is unavailable",
        )
    try:
        return factory(
            tenant_id=tenant_id,
            delivery_store=_delivery_store(tenant_id),
        )
    except Exception as exc:
        from .consent_delivery_destinations_composition import (
            ConsentDestinationCompositionError,
        )

        if isinstance(exc, ConsentDestinationCompositionError):
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        raise


def _adapter_error(exc: Exception) -> HTTPException:
    from maverick.consent_delivery import ConsentDeliveryRevoked
    from maverick.consent_delivery_destinations import (
        ConsentDestinationConfigError,
        ConsentDestinationConflict,
        ConsentDestinationReconciliationRequired,
    )

    if isinstance(exc, ConsentDestinationConfigError):
        return HTTPException(status_code=503, detail=str(exc))
    if isinstance(exc, ConsentDestinationConflict):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, ConsentDeliveryRevoked):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, ConsentDestinationReconciliationRequired):
        return HTTPException(status_code=503, detail=str(exc))
    return HTTPException(status_code=503, detail="destination adapter operation failed")


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    require_global_permission(request, "audit")
    tenant = _tenant_id()
    probe = getattr(request.app.state, "consent_destination_readiness_probe", None)
    if not callable(probe):
        raise HTTPException(
            status_code=503,
            detail="named consent destination readiness is unavailable",
        )
    return dict(await run_in_threadpool(probe, tenant))


@router.get("/{destination_id}/ambiguous")
async def ambiguous_operations(
    request: Request,
    destination_id: str = Path(pattern=_ID),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    tenant = _tenant_id()
    runtime = await run_in_threadpool(_runtime, request, tenant)
    try:
        items = await run_in_threadpool(
            runtime.operation_store.ambiguous,
            tenant,
            destination_id,
            limit=limit,
        )
    except Exception as exc:
        raise _adapter_error(exc) from exc
    return {
        "schema": "lightwork.consent-destination-ambiguities.v1",
        "tenant_id": tenant,
        "destination_id": destination_id,
        "items": items,
        "raw_provider_payloads_returned": False,
        "credential_material_returned": False,
    }


@router.get("/{destination_id}/operations/{message_sha256}")
async def operation_receipt(
    request: Request,
    destination_id: str = Path(pattern=_ID),
    message_sha256: str = Path(pattern=_DIGEST),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    tenant = _tenant_id()
    runtime = await run_in_threadpool(_runtime, request, tenant)
    try:
        return dict(
            await run_in_threadpool(
                runtime.operation_store.operation,
                tenant,
                destination_id,
                message_sha256,
            )
        )
    except Exception as exc:
        raise _adapter_error(exc) from exc


@router.post("/{destination_id}/reconcile")
async def reconcile_operation(
    request: Request,
    body: ReconcileIn,
    destination_id: str = Path(pattern=_ID),
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    tenant = _tenant_id()
    runtime = await run_in_threadpool(_runtime, request, tenant)
    try:
        return dict(
            await run_in_threadpool(
                runtime.transport.reconcile,
                destination_id=destination_id,
                message_sha256=body.message_sha256,
                request_sha256=body.request_sha256,
            )
        )
    except Exception as exc:
        raise _adapter_error(exc) from exc


@router.get("/integrity")
async def integrity(request: Request) -> dict[str, Any]:
    require_global_permission(request, "audit")
    tenant = _tenant_id()
    runtime = await run_in_threadpool(_runtime, request, tenant)
    try:
        return dict(
            await run_in_threadpool(runtime.operation_store.verify_integrity)
        )
    except Exception as exc:
        raise _adapter_error(exc) from exc


__all__ = ["router"]
