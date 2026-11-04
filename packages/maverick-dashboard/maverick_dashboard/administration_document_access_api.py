"""Strict tenant/principal-bound API for governed document delivery access.

No route accepts a tenant, principal, document path, document bytes, event-type
registration, delivery locator, or caller-selected document metadata.  The
deployment composition owns the document resolver and delivery-grant issuer.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_permission

OpaqueId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")]
IdempotencyKey = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"),
]
DownloadToken = Annotated[
    str,
    Field(pattern=r"^lwddt_v1_[A-Za-z0-9_-]{43}$"),
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
TokenState = Literal["active", "revoked", "expired", "exhausted"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class MintTokenIn(_StrictModel):
    document_ref: OpaqueId
    ttl_seconds: StrictInt | None = Field(default=None, ge=30, le=3_600)
    max_uses: StrictInt = Field(default=1, ge=1, le=10)
    idempotency_key: IdempotencyKey


class RevisionIn(_StrictModel):
    expected_revision: StrictInt = Field(ge=1, le=2**63 - 1)
    idempotency_key: IdempotencyKey


class ClaimTokenIn(_StrictModel):
    download_token: DownloadToken
    idempotency_key: IdempotencyKey


class DocumentAccessDependencies:
    """Narrow deployment-owned seams; absent or malformed seams fail closed."""

    def __init__(
        self,
        *,
        service_for: Callable[[str, str, Request], Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[[str, Request], Mapping[str, Any]] | None = None,
    ) -> None:
        for dependency in (service_for, enabled_probe, readiness_probe):
            if dependency is not None and not callable(dependency):
                raise TypeError("document-access dependency must be callable")
        self.service_for = service_for
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using document access administration",
        )
    return tenant


def _principal_ref(request: Request, tenant_id: str) -> str:
    subject = caller_principal(request) or "authorized-local-operator"
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 512:
        raise HTTPException(status_code=401, detail="an authenticated principal is required")
    digest = hashlib.sha256(
        f"lightwork.document-access.api-principal.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"document-access-api.{digest[:40]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _public_record(record: Any) -> dict[str, Any]:
    """Return bounded administration metadata, never token/principal digests."""

    fields = (
        "token_id",
        "document_ref",
        "product_area",
        "record_type",
        "media_type",
        "byte_size",
        "content_sha256",
        "authority_revision",
        "authority_sha256",
        "state",
        "revision",
        "max_uses",
        "uses_remaining",
        "claim_count",
        "issued_at",
        "expires_at",
        "retired_at",
        "retained_until",
    )
    if any(not hasattr(record, field) for field in fields):
        raise HTTPException(status_code=503, detail="document-access authority is unavailable")
    return {field: getattr(record, field) for field in fields}


def create_administration_document_access_router(  # noqa: C901
    dependencies: DocumentAccessDependencies | None = None,
) -> APIRouter:
    deps = dependencies or DocumentAccessDependencies()
    router = APIRouter(
        prefix="/administration/document-access",
        tags=["administration-document-access"],
    )

    def capability(request: Request, tenant: str) -> tuple[Any, bool]:
        from maverick import administration_document_access as access

        probe = getattr(
            request.app.state,
            "administration_document_access_enabled_probe",
            None,
        )
        selected = probe if callable(probe) else deps.enabled_probe
        try:
            available = selected(tenant) if callable(selected) else access.enabled()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="document-access configuration is unavailable",
            ) from exc
        if type(available) is not bool:
            raise HTTPException(
                status_code=503,
                detail="document-access configuration is unavailable",
            )
        return access, available

    def readiness(request: Request, tenant: str) -> Mapping[str, Any] | None:
        probe = getattr(
            request.app.state,
            "administration_document_access_readiness_probe",
            None,
        )
        selected = probe if callable(probe) else deps.readiness_probe
        if not callable(selected):
            return None
        try:
            result = selected(tenant, request)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="document-access readiness authority is unavailable",
            ) from exc
        if not isinstance(result, Mapping):
            raise HTTPException(
                status_code=503,
                detail="document-access readiness authority is unavailable",
            )
        return dict(result)

    def authority(request: Request) -> tuple[Any, str, str, Any]:
        tenant = _tenant_id()
        access, available = capability(request, tenant)
        if not available:
            raise HTTPException(
                status_code=403,
                detail="administration_document_access_disabled",
            )
        principal = _principal_ref(request, tenant)
        factory = getattr(
            request.app.state,
            "administration_document_access_service_factory",
            None,
        )
        selected = factory if callable(factory) else deps.service_for
        if not callable(selected):
            raise HTTPException(
                status_code=503,
                detail="document-access authority is unavailable",
            )
        try:
            service = selected(tenant, principal, request)
        except access.DocumentAccessConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="document-access authority is unavailable",
            ) from exc
        except (access.DocumentAccessError, OSError, RuntimeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="document-access authority is unavailable",
            ) from exc
        if type(service) is not access.DocumentAccessService:
            raise HTTPException(
                status_code=503,
                detail="document-access authority is unavailable",
            )
        return access, tenant, principal, service

    async def call(access, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except access.DocumentAccessNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except access.DocumentAccessPermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except access.DocumentAccessExpired as exc:
            raise HTTPException(status_code=410, detail=str(exc)) from exc
        except access.DocumentAccessConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except access.DocumentAccessValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except access.DocumentAccessIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="document-access integrity verification failed",
            ) from exc
        except access.DocumentAccessConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="document-access dependency is unavailable",
            ) from exc
        except access.DocumentAccessError as exc:
            raise HTTPException(
                status_code=503,
                detail="document-access operation failed",
            ) from exc
        except (OSError, RuntimeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="document-access dependency is unavailable",
            ) from exc

    @router.get("/status")
    async def status(request: Request):
        require_permission(request, "view")
        tenant = _tenant_id()
        access, available = capability(request, tenant)
        boundaries = access.DocumentAccessStore.product_boundaries()
        if not available:
            return {
                "schema": "lightwork.administration-document-access-api-status.v1",
                "enabled": False,
                "configured": False,
                "ready": False,
                "catalog_version": access.CATALOG_VERSION,
                "event_type_count": len(access.EVENT_TYPE_CATALOG),
                "live_relying_workflow_verified": False,
                "external_object_store_custody_verified": False,
                "limits": boundaries,
            }
        readiness_result = readiness(request, tenant)
        if readiness_result is not None and readiness_result.get("configured") is not True:
            return {
                "schema": "lightwork.administration-document-access-api-status.v1",
                "enabled": True,
                "configured": False,
                "ready": False,
                "catalog_version": access.CATALOG_VERSION,
                "event_type_count": len(access.EVENT_TYPE_CATALOG),
                "dependencies": dict(readiness_result),
                "live_relying_workflow_verified": False,
                "external_object_store_custody_verified": False,
                "limits": boundaries,
            }
        try:
            access, _tenant, _principal, service = authority(request)
        except HTTPException as exc:
            if exc.status_code != 503:
                raise
            return {
                "schema": "lightwork.administration-document-access-api-status.v1",
                "enabled": True,
                "configured": False,
                "ready": False,
                "catalog_version": access.CATALOG_VERSION,
                "event_type_count": len(access.EVENT_TYPE_CATALOG),
                "live_relying_workflow_verified": False,
                "external_object_store_custody_verified": False,
                "limits": boundaries,
            }
        result = _jsonable(await call(access, service.status))
        result["schema"] = "lightwork.administration-document-access-api-status.v1"
        return result

    @router.get("/event-types")
    async def event_types(
        request: Request,
        product_area: ProductArea | None = Query(default=None),
        record_type: Annotated[
            str | None,
            Query(pattern=r"^[a-z][a-z0-9_.-]{0,95}$"),
        ] = None,
    ):
        require_permission(request, "view")
        tenant = _tenant_id()
        access, available = capability(request, tenant)
        if not available:
            raise HTTPException(
                status_code=403,
                detail="administration_document_access_disabled",
            )
        items = access.list_event_types(
            product_area=product_area,
            record_type=record_type,
        )
        return {
            "schema": "lightwork.administration-event-type-catalog.v1",
            "catalog_version": access.CATALOG_VERSION,
            "items": [_jsonable(item) for item in items],
            "count": len(items),
            "caller_registration_supported": False,
        }

    @router.post("/tokens", status_code=201)
    async def mint_token(request: Request, body: MintTokenIn):
        require_permission(request, "admin")
        access, _tenant, _principal, service = authority(request)
        minted = await call(
            access,
            service.mint_token,
            body.document_ref,
            **body.model_dump(exclude={"document_ref"}),
        )
        result = {
            "schema": "lightwork.administration-document-download-token-mint.v1",
            "token": _public_record(minted.record),
            "idempotent_replay": minted.idempotent_replay,
        }
        if minted.download_token is not None:
            result["download_token"] = minted.download_token
        return result

    @router.post("/tokens/redeem")
    async def redeem_token(request: Request, body: ClaimTokenIn):
        require_permission(request, "operate")
        access, _tenant, _principal, service = authority(request)
        grant = await call(access, service.claim, **body.model_dump())
        # Deliberately return no document metadata, locator, path, bytes, token
        # record, principal, tenant, or provider detail.
        return {
            "schema": "lightwork.administration-document-delivery-grant.v1",
            "delivery_grant": grant.delivery_grant,
            "expires_at": grant.expires_at,
        }

    @router.post("/tokens/expiry/reconcile")
    async def reconcile_expiry(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
    ):
        require_permission(request, "admin")
        access, _tenant, _principal, service = authority(request)
        changed = await call(access, service.reconcile_expired, limit=limit)
        return {"expired": changed}

    @router.get("/tokens")
    async def list_tokens(
        request: Request,
        state: TokenState | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
    ):
        require_permission(request, "admin")
        access, _tenant, _principal, service = authority(request)
        records = await call(access, service.list_tokens, state=state, limit=limit)
        return {"items": [_public_record(record) for record in records], "count": len(records)}

    @router.get("/tokens/{token_id}")
    async def get_token(request: Request, token_id: OpaqueId):
        require_permission(request, "admin")
        access, _tenant, _principal, service = authority(request)
        record = await call(access, service.get_token, token_id)
        return _public_record(record)

    @router.post("/tokens/{token_id}/revoke")
    async def revoke_token(request: Request, token_id: OpaqueId, body: RevisionIn):
        require_permission(request, "admin")
        access, _tenant, _principal, service = authority(request)
        record = await call(
            access,
            service.revoke_token,
            token_id,
            **body.model_dump(),
        )
        return _public_record(record)

    @router.post("/tokens/{token_id}/retention/purge")
    async def purge_token(request: Request, token_id: OpaqueId, body: RevisionIn):
        require_permission(request, "admin")
        access, _tenant, _principal, service = authority(request)
        tombstone = await call(
            access,
            service.purge_token,
            token_id,
            **body.model_dump(),
        )
        return _jsonable(tombstone)

    @router.get("/audit/events")
    async def audit_events(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "audit")
        access, _tenant, _principal, service = authority(request)
        events = await call(access, service.store.list_audit, limit=limit)
        return {"items": _jsonable(events), "count": len(events)}

    @router.get("/integrity")
    async def integrity(request: Request):
        require_permission(request, "audit")
        access, _tenant, _principal, service = authority(request)
        return _jsonable(await call(access, service.store.verify_integrity))

    return router


router = create_administration_document_access_router()

__all__ = [
    "ClaimTokenIn",
    "DocumentAccessDependencies",
    "MintTokenIn",
    "RevisionIn",
    "create_administration_document_access_router",
    "router",
]
