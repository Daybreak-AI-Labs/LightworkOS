"""Authenticated API for the stock governed document vault.

The ingestion endpoint accepts a bounded request body, never a filesystem path,
URL, bucket key, or object locator.  Delivery is an authenticated POST carrying
one opaque grant and returns a streaming response only after atomic one-time
consumption succeeds.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from starlette.concurrency import run_in_threadpool
from starlette.responses import StreamingResponse

from .auth import require_permission
from .governed_document_vault_composition import (
    document_access_principal_ref,
    governed_document_vault_enabled,
    vault_actor_ref,
)

OpaqueId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")]
DisplayName = Annotated[str, Field(min_length=1, max_length=255)]
RecordType = Annotated[
    str,
    Field(pattern=r"^[a-z][a-z0-9_.-]{0,95}$"),
]
DeliveryGrantValue = Annotated[
    str,
    Field(pattern=r"^lwdvg_v1_[A-Za-z0-9_-]{43}$"),
]
ProductArea = Literal[
    "administration",
    "ai_governance",
    "consent_preferences",
    "data_use_governance",
    "privacy_automation",
    "tech_risk_compliance",
    "third_party_management",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RevisionIn(_StrictModel):
    expected_revision: StrictInt = Field(ge=1, le=2**31 - 1)


class DeliveryIn(_StrictModel):
    delivery_grant: DeliveryGrantValue


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using the document vault",
        )
    return tenant


def _public_record(value: Any) -> dict[str, Any]:
    fields = (
        "document_ref",
        "product_area",
        "record_type",
        "safe_display_name",
        "media_type",
        "byte_size",
        "content_sha256",
        "content_revision",
        "authority_revision",
        "authority_sha256",
        "state",
        "created_at",
        "updated_at",
        "revoked_at",
        "retained_until",
    )
    if any(not hasattr(value, field) for field in fields):
        raise HTTPException(status_code=503, detail="document vault authority is unavailable")
    return {field: getattr(value, field) for field in fields}


async def _read_bounded_body(request: Request, maximum: int) -> bytes:
    raw_length = request.headers.get("content-length")
    if raw_length:
        try:
            content_length = int(raw_length)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid content length") from exc
        if content_length < 1 or content_length > maximum:
            raise HTTPException(status_code=413, detail="document exceeds the configured limit")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > maximum:
            raise HTTPException(status_code=413, detail="document exceeds the configured limit")
        chunks.append(chunk)
    if total < 1:
        raise HTTPException(status_code=422, detail="document content is required")
    return b"".join(chunks)


def create_governed_document_vault_router() -> APIRouter:  # noqa: C901
    router = APIRouter(
        prefix="/administration/document-vault",
        tags=["administration-document-vault"],
    )

    def enabled(request: Request, tenant_id: str) -> bool:
        probe = getattr(
            request.app.state, "governed_document_vault_enabled_probe", None
        )
        selected: Callable[[str], bool] = (
            probe if callable(probe) else governed_document_vault_enabled
        )
        try:
            value = selected(tenant_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail="document vault configuration is unavailable"
            ) from exc
        if type(value) is not bool:
            raise HTTPException(
                status_code=503, detail="document vault configuration is unavailable"
            )
        return value

    def authority(request: Request):
        tenant = _tenant_id()
        if not enabled(request, tenant):
            raise HTTPException(status_code=403, detail="governed_document_vault_disabled")
        factory = getattr(
            request.app.state, "governed_document_vault_store_factory", None
        )
        if not callable(factory):
            raise HTTPException(status_code=503, detail="document vault authority is unavailable")
        try:
            store = factory(tenant, request)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail="document vault authority is unavailable") from exc
        return tenant, store

    async def call(function, *args, **kwargs):
        from maverick import governed_document_vault as vault

        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except vault.VaultNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except vault.VaultPermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except vault.VaultConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except vault.VaultValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except vault.VaultIntegrityError as exc:
            raise HTTPException(status_code=503, detail="document vault integrity verification failed") from exc
        except vault.VaultConfigError as exc:
            raise HTTPException(status_code=503, detail="document vault dependency is unavailable") from exc
        except (OSError, RuntimeError) as exc:
            raise HTTPException(status_code=503, detail="document vault operation failed") from exc

    @router.get("/status")
    async def status(request: Request):
        require_permission(request, "view")
        tenant = _tenant_id()
        if not enabled(request, tenant):
            return {
                "schema": "lightwork.governed-document-vault-status.v1",
                "enabled": False,
                "configured": False,
                "ready": False,
                "external_object_store_custody_verified": False,
                "live_relying_workflow_verified": False,
            }
        _tenant, store = authority(request)
        return await call(store.status)

    @router.post("/documents", status_code=201)
    async def ingest_document(
        request: Request,
        product_area: ProductArea = Query(...),
        record_type: RecordType = Query(...),
        safe_display_name: DisplayName = Query(...),
    ):
        require_permission(request, "admin")
        tenant, store = authority(request)
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type not in store.config.allowed_media_types:
            raise HTTPException(status_code=415, detail="document media type is not approved")
        content = await _read_bounded_body(request, store.config.max_document_bytes)
        record = await call(
            store.ingest,
            content,
            principal_ref=vault_actor_ref(request, tenant),
            product_area=product_area,
            record_type=record_type,
            safe_display_name=safe_display_name,
            media_type=content_type,
        )
        return {
            "schema": "lightwork.governed-document-vault-document.v1",
            "document": _public_record(record),
        }

    @router.get("/documents")
    async def list_documents(
        request: Request,
        state: Literal["active", "revoked"] | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
    ):
        require_permission(request, "view")
        _tenant, store = authority(request)
        records = await call(store.list_documents, state=state, limit=limit)
        return {"items": [_public_record(item) for item in records], "count": len(records)}

    @router.get("/documents/{document_ref}")
    async def get_document(request: Request, document_ref: OpaqueId):
        require_permission(request, "view")
        _tenant, store = authority(request)
        return _public_record(await call(store.get, document_ref))

    @router.post("/documents/{document_ref}/revoke")
    async def revoke_document(
        request: Request,
        document_ref: OpaqueId,
        body: RevisionIn,
    ):
        require_permission(request, "admin")
        tenant, store = authority(request)
        record = await call(
            store.revoke,
            document_ref,
            principal_ref=vault_actor_ref(request, tenant),
            expected_revision=body.expected_revision,
        )
        return _public_record(record)

    @router.post("/documents/{document_ref}/retention/purge")
    async def purge_document(
        request: Request,
        document_ref: OpaqueId,
        body: RevisionIn,
    ):
        require_permission(request, "admin")
        tenant, store = authority(request)
        return await call(
            store.purge_document,
            document_ref,
            principal_ref=vault_actor_ref(request, tenant),
            expected_revision=body.expected_revision,
        )

    @router.post("/delivery")
    async def deliver(request: Request, body: DeliveryIn):
        require_permission(request, "operate")
        tenant, store = authority(request)
        payload = await call(
            store.consume_delivery_grant,
            body.delivery_grant,
            principal_ref=document_access_principal_ref(request, tenant),
        )
        filename = quote(payload.safe_display_name, safe="")
        return StreamingResponse(
            payload.chunks(store.config.stream_chunk_bytes),
            media_type=payload.media_type,
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{filename}",
                "Content-Length": str(len(payload.content)),
                "X-Content-SHA256": payload.content_sha256,
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @router.post("/maintenance/reconcile")
    async def reconcile(
        request: Request,
        limit: int = Query(default=500, ge=1, le=1_000),
    ):
        require_permission(request, "admin")
        _tenant, store = authority(request)
        return await call(store.reconcile, limit=limit)

    @router.get("/audit/events")
    async def audit_events(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "audit")
        _tenant, store = authority(request)
        events = await call(store.list_audit, limit=limit)
        return {"items": events, "count": len(events)}

    @router.get("/integrity")
    async def integrity(request: Request):
        require_permission(request, "audit")
        _tenant, store = authority(request)
        return await call(store.verify_integrity)

    return router


router = create_governed_document_vault_router()

__all__ = [
    "DeliveryIn",
    "RevisionIn",
    "create_governed_document_vault_router",
    "router",
]
