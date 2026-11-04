"""Administrative control plane for authoritative consent delivery."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission

router = APIRouter(prefix="/consent/delivery", tags=["consent-delivery"])

_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDEMPOTENCY = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class DestinationIn(_StrictModel):
    origin: str = Field(min_length=1, max_length=2048)
    signing_key_id: str = Field(pattern=_ID)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)
    # Omitted values take the installation defaults (Settings > All settings);
    # tries above the installation's most tries are lowered to it.
    max_attempts: int | None = Field(default=None, ge=1, le=20)
    base_backoff_seconds: float | None = Field(default=None, gt=0, le=3600)
    max_backoff_seconds: float | None = Field(default=None, gt=0, le=86400)
    default_retention_seconds: int = Field(default=2_592_000, ge=1, le=157_680_000)


class RotateKeyIn(_StrictModel):
    new_key_id: str = Field(pattern=_ID)
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class RevokeKeyIn(_StrictModel):
    key_id: str = Field(pattern=_ID)
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class RevokeDestinationIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class SyncIn(_StrictModel):
    destination_ids: list[str] = Field(min_length=1, max_length=64)
    limit: int = Field(default=100, ge=1, le=500)


class DispatchIn(_StrictModel):
    destination_ids: list[str] = Field(min_length=1, max_length=64)
    sync_limit: int = Field(default=100, ge=1, le=500)
    delivery_limit: int = Field(default=10, ge=1, le=100)
    lease_seconds: float = Field(default=60.0, gt=0, le=3600)


class ReplayIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)
    retention_until: float | None = Field(default=None, gt=0)


class PurgeIn(_StrictModel):
    at: float | None = Field(default=None, gt=0)
    limit: int = Field(default=500, ge=1, le=5000)


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using consent delivery",
        )
    return tenant


def _ops():
    from maverick import config, consent_delivery

    try:
        if config.config_source_errors():
            raise ValueError("configuration is invalid")
        consent = config.load_config().get("consent_preferences", {})
    except Exception:
        consent = {}
    delivery = consent.get("delivery") if isinstance(consent, Mapping) else None
    if not (
        isinstance(consent, Mapping)
        and consent.get("enable") is True
        and isinstance(delivery, Mapping)
        and delivery.get("enable") is True
    ):
        raise HTTPException(
            status_code=403,
            detail="consent delivery is disabled ([consent_preferences.delivery] enable)",
        )
    return consent_delivery


def _delivery_store(ops, tenant_id: str):
    from maverick.paths import data_dir

    return ops.ConsentDeliveryStore(
        data_dir(
            "consent_preferences",
            "consent-delivery.sqlite3",
            tenant=tenant_id,
        )
    )


def _preference_store(tenant_id: str):
    from maverick.consent_preferences import ConsentPreferenceStore
    from maverick.paths import data_dir

    return ConsentPreferenceStore(
        data_dir(
            "consent_preferences",
            "consent-preferences.sqlite3",
            tenant=tenant_id,
        )
    )


def _actor_worker_id(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    subject = getattr(principal, "sub", None) or "local-operator"
    digest = hashlib.sha256(str(subject).encode("utf-8")).hexdigest()
    return f"delivery-api-{digest[:24]}"


async def _call(ops, function, *args, **kwargs) -> Any:
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except (ops.ConsentDeliveryConflict, ops.ConsentDeliveryIdempotencyConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.ConsentDeliveryNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ops.ConsentDeliveryValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ops.ConsentDeliveryRevoked as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.ConsentDeliveryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _authority():
    ops = _ops()
    tenant = _tenant_id()
    return ops, tenant, _delivery_store(ops, tenant)


def _named_destination_adapters_enabled() -> bool:
    from maverick import config

    try:
        if config.config_source_errors():
            return False
        consent = config.load_config().get("consent_preferences", {})
    except Exception:
        return False
    delivery = consent.get("delivery") if isinstance(consent, Mapping) else None
    destinations = (
        delivery.get("destinations") if isinstance(delivery, Mapping) else None
    )
    return isinstance(destinations, Mapping) and destinations.get("enable") is True


def _named_destination_transport(
    request: Request,
    *,
    tenant_id: str,
    delivery_store: Any,
    destination_ids: list[str],
):
    """Resolve one ready runtime without allowing browser-supplied authority."""

    if not _named_destination_adapters_enabled():
        return None
    factory = getattr(request.app.state, "consent_destination_runtime_factory", None)
    if not callable(factory):
        raise HTTPException(
            status_code=503,
            detail="named consent destination runtime is unavailable",
        )
    try:
        runtime = factory(
            tenant_id=tenant_id,
            delivery_store=delivery_store,
        )
        readiness = runtime.transport.readiness()
        if not isinstance(readiness, Mapping) or readiness.get("ready") is not True:
            raise HTTPException(
                status_code=503,
                detail=(
                    "named consent destinations are not ready; verify credential "
                    "placement and install an independent reconciliation authority"
                ),
            )
        for destination_id in destination_ids:
            runtime.registry.binding(destination_id)
    except HTTPException:
        raise
    except Exception as exc:
        from maverick.consent_delivery_destinations import (
            ConsentDestinationAdapterError,
        )

        if isinstance(exc, ConsentDestinationAdapterError):
            raise HTTPException(
                status_code=422,
                detail="one or more destinations have no named provider binding",
            ) from exc
        from .consent_delivery_destinations_composition import (
            ConsentDestinationCompositionError,
        )

        if isinstance(exc, (ConsentDestinationCompositionError, ValueError)):
            raise HTTPException(
                status_code=503,
                detail="named consent destination composition is invalid",
            ) from exc
        raise
    return runtime.transport


@router.post("/destinations/{destination_id}", status_code=201)
async def enroll_destination(
    request: Request,
    destination_id: str,
    body: DestinationIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    return await _call(
        ops,
        store.enroll_destination,
        tenant,
        destination_id=destination_id,
        **body.model_dump(),
    )


@router.get("/destinations")
async def destinations(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Read-only list of the active workspace's destinations for the page."""
    require_global_permission(request, "audit")
    ops, tenant, store = _authority()
    return await _call(ops, store.list_destinations, tenant, limit=limit)


@router.get("/destinations/{destination_id}")
async def destination(request: Request, destination_id: str) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, store = _authority()
    return await _call(ops, store.destination, tenant, destination_id)


@router.post("/destinations/{destination_id}/rotate-key")
async def rotate_key(
    request: Request,
    destination_id: str,
    body: RotateKeyIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    return await _call(
        ops,
        store.rotate_signing_key,
        tenant,
        destination_id,
        **body.model_dump(),
    )


@router.post("/destinations/{destination_id}/revoke-key")
async def revoke_key(
    request: Request,
    destination_id: str,
    body: RevokeKeyIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    return await _call(
        ops,
        store.revoke_signing_key,
        tenant,
        destination_id,
        **body.model_dump(),
    )


@router.post("/destinations/{destination_id}/revoke")
async def revoke_destination(
    request: Request,
    destination_id: str,
    body: RevokeDestinationIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    return await _call(
        ops,
        store.revoke_destination,
        tenant,
        destination_id,
        **body.model_dump(),
    )


@router.post("/sync")
async def sync_authority(request: Request, body: SyncIn) -> dict[str, Any]:
    require_global_permission(request, "operate")
    ops, tenant, store = _authority()
    from maverick.consent_delivery_bridge import (
        ConsentDeliveryBridge,
        ConsentDeliveryBridgeError,
    )

    bridge = ConsentDeliveryBridge(_preference_store(tenant), store)
    try:
        return await run_in_threadpool(
            bridge.sync_once,
            tenant,
            body.destination_ids,
            limit=body.limit,
        )
    except ConsentDeliveryBridgeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.ConsentDeliveryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/dispatch")
async def dispatch(request: Request, body: DispatchIn) -> dict[str, Any]:
    """Run one explicit bridge/send batch; this may perform external HTTPS I/O."""

    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    from maverick import consent_delivery_runtime

    try:
        transport = await run_in_threadpool(
            _named_destination_transport,
            request,
            tenant_id=tenant,
            delivery_store=store,
            destination_ids=body.destination_ids,
        )
        return await run_in_threadpool(
            consent_delivery_runtime.run_delivery_once,
            tenant,
            body.destination_ids,
            worker_id=_actor_worker_id(request),
            sync_limit=body.sync_limit,
            delivery_limit=body.delivery_limit,
            lease_seconds=body.lease_seconds,
            preference_store=_preference_store(tenant),
            delivery_store=store,
            transport=transport,
        )
    except Exception as exc:
        from maverick.consent_delivery_bridge import ConsentDeliveryBridgeError

        if isinstance(exc, (ops.ConsentDeliveryError, ConsentDeliveryBridgeError)):
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        raise


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, store = _authority()
    counts = await _call(ops, store.counts, tenant)
    posture = await _call(ops, store.privacy_posture, tenant)
    chain = await _call(ops, store.verify_audit_chain, tenant)
    due = await _call(ops, store.retention_due, tenant)
    return {
        "counts": counts,
        "privacy_posture": posture,
        "audit_chain": chain,
        "retention_due": due,
        "external_acceptance": False,
    }


@router.get("/messages/{message_id}")
async def message(request: Request, message_id: str) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, store = _authority()
    return await _call(ops, store.message, tenant, message_id)


@router.get("/dead-letters")
async def dead_letters(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, store = _authority()
    return {"items": await _call(ops, store.list_dead_letters, tenant, limit=limit)}


@router.post("/dead-letters/{message_id}/replay")
async def replay_dead_letter(
    request: Request,
    message_id: str,
    body: ReplayIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    return await _call(
        ops,
        store.replay_dead_letter,
        tenant,
        message_id,
        **body.model_dump(),
    )


@router.get("/audit")
async def audit(
    request: Request,
    after_sequence: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, store = _authority()
    return {
        "events": await _call(
            ops,
            store.list_audit,
            tenant,
            after_sequence=after_sequence,
            limit=limit,
        )
    }


@router.post("/retention/purge")
async def purge(request: Request, body: PurgeIn) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    return await _call(ops, store.purge_terminal, tenant, **body.model_dump())


__all__ = ["router"]
