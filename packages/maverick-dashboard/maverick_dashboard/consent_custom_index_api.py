"""Strict administrative API for governed consent custom indexes.

The HTTP contract intentionally excludes tenant, actor, HMAC key reference,
key version, retention, and quota fields.  Those authorities are resolved by
the deployment composition for the active tenant.  Exact-match search values
are bounded request material and are never included in URLs.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as ApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

_MAX_JSON_BYTES = 64 * 1024
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$"
OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=8, max_length=192, pattern=_OP_PATTERN),
]

_REQUIRED_RUNTIME_ATTRIBUTES = (
    "tenant_id",
    "current_key_version",
    "max_indexes",
    "max_page_size",
)
_REQUIRED_RUNTIME_METHODS = (
    "create_index",
    "get_index",
    "list_indexes_page",
    "build_index",
    "search",
    "revoke_index",
    "audit_history",
    "verify_integrity",
)
_SECURE_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


class _BoundedJSONRoute(APIRoute):
    """Reject oversized JSON before FastAPI validates a mutating body."""

    def get_route_handler(self):  # type: ignore[no-untyped-def]
        original = super().get_route_handler()

        async def bounded(request: Request):  # type: ignore[no-untyped-def]
            try:
                if request.method in {"POST", "PUT", "PATCH"}:
                    content_type = request.headers.get("content-type", "")
                    media_type = content_type.split(";", 1)[0].strip().lower()
                    if media_type != "application/json":
                        raise HTTPException(
                            status_code=415,
                            detail=(
                                "consent custom-index requests require application/json"
                            ),
                        )
                    supplied = request.headers.get("content-length")
                    if supplied is not None:
                        try:
                            declared = int(supplied)
                        except ValueError as exc:
                            raise HTTPException(
                                status_code=400,
                                detail="consent custom-index content length is invalid",
                            ) from exc
                        if declared < 0 or declared > _MAX_JSON_BYTES:
                            raise HTTPException(
                                status_code=413,
                                detail="consent custom-index request exceeds 64 KiB",
                            )
                    body = await request.body()
                    if len(body) > _MAX_JSON_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail="consent custom-index request exceeds 64 KiB",
                        )
                response = await original(request)
            except HTTPException as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"detail": exc.detail},
                    headers={**_SECURE_HEADERS, **(exc.headers or {})},
                )
            except RequestValidationError:
                return JSONResponse(
                    status_code=422,
                    content={"detail": "consent custom-index request is invalid"},
                    headers=_SECURE_HEADERS,
                )
            for name, value in _SECURE_HEADERS.items():
                response.headers[name] = value
            return response

        return bounded


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CreateIndexIn(_StrictModel):
    index_id: OpaqueId
    element_name: OpaqueId
    idempotency_key: IdempotencyKey


class RevisionIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class SearchIn(_StrictModel):
    value: bool | OpaqueId | list[OpaqueId]
    limit: int = Field(default=100, strict=True, ge=1, le=500)
    cursor: OpaqueId | None = None


class ConsentCustomIndexDependencies:
    """Deployment-owned seams for tests and alternate compositions."""

    def __init__(
        self,
        *,
        store_factory: Callable[..., Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[[str], bool] | None = None,
    ) -> None:
        for dependency in (store_factory, enabled_probe, readiness_probe):
            if dependency is not None and not callable(dependency):
                raise TypeError("consent custom-index dependency must be callable")
        self.store_factory = store_factory
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe


def _ops():
    from maverick import consent_custom_index as indexes

    return indexes


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using consent custom indexes",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for consent custom indexes",
    )
    digest = hashlib.sha256(
        f"lightwork.consent-custom-index.identity.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"consent-index-admin-{digest[:40]}"


def _dependency(request: Request, name: str, fallback: object) -> object:
    try:
        return getattr(request.app.state, name)
    except AttributeError:
        return fallback


def _secure(response: Response) -> None:
    for name, value in _SECURE_HEADERS.items():
        response.headers[name] = value


def _jsonable(value: object) -> object:
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def create_consent_custom_index_router(  # noqa: C901 - route-local trust boundaries
    dependencies: ConsentCustomIndexDependencies | None = None,
) -> APIRouter:
    deps = dependencies or ConsentCustomIndexDependencies()
    router = APIRouter(
        prefix="/consent/custom-indexes",
        tags=["consent-custom-indexes"],
        route_class=_BoundedJSONRoute,
    )

    def probes(request: Request, tenant: str) -> tuple[bool, bool, bool]:
        enabled_probe = _dependency(
            request,
            "consent_custom_index_enabled_probe",
            deps.enabled_probe,
        )
        readiness_probe = _dependency(
            request,
            "consent_custom_index_readiness_probe",
            deps.readiness_probe,
        )
        factory = _dependency(
            request,
            "consent_custom_index_store_factory",
            deps.store_factory,
        )
        if not callable(enabled_probe):
            return False, False, False
        try:
            enabled = enabled_probe(tenant)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="consent custom-index configuration is unavailable",
            ) from exc
        if type(enabled) is not bool:
            raise HTTPException(
                status_code=503,
                detail="consent custom-index configuration is unavailable",
            )
        configured = callable(factory) and callable(readiness_probe)
        ready = False
        if enabled and configured:
            try:
                ready = readiness_probe(tenant)  # type: ignore[operator]
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="consent custom-index readiness is unavailable",
                ) from exc
            if type(ready) is not bool:
                raise HTTPException(
                    status_code=503,
                    detail="consent custom-index readiness is unavailable",
                )
        return enabled, configured, ready

    async def composition(request: Request):
        tenant = _tenant_id()
        enabled, configured, ready = await run_in_threadpool(
            probes, request, tenant
        )
        if not enabled:
            raise HTTPException(
                status_code=403,
                detail="consent custom indexes are disabled",
            )
        if not configured or ready is not True:
            raise HTTPException(
                status_code=503,
                detail="consent custom-index operational readiness is not verified",
            )
        principal = _principal(request, tenant)
        factory = _dependency(
            request,
            "consent_custom_index_store_factory",
            deps.store_factory,
        )
        try:
            runtime = await run_in_threadpool(
                factory,  # type: ignore[arg-type]
                tenant_id=tenant,
                principal_ref=principal,
                request=request,
            )
            valid = all(
                hasattr(runtime, attribute)
                for attribute in _REQUIRED_RUNTIME_ATTRIBUTES
            ) and all(
                callable(getattr(runtime, method, None))
                for method in _REQUIRED_RUNTIME_METHODS
            )
            valid = valid and all(
                not isinstance(value, bool) and isinstance(value, int)
                for value in (
                    runtime.current_key_version,
                    runtime.max_indexes,
                    runtime.max_page_size,
                )
            )
            valid = valid and (
                1 <= runtime.current_key_version <= 1_000_000
                and 1 <= runtime.max_indexes <= 10_000
                and 1 <= runtime.max_page_size <= 500
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="consent custom-index authority is unavailable",
            ) from exc
        if not valid or runtime.tenant_id != tenant:
            raise HTTPException(
                status_code=503,
                detail="consent custom-index authority is unavailable",
            )
        return _ops(), tenant, runtime

    async def call(ops, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.ConsentCustomIndexNotFound as exc:
            raise HTTPException(
                status_code=404,
                detail="consent custom index was not found",
            ) from exc
        except ops.ConsentCustomIndexPermissionDenied as exc:
            raise HTTPException(
                status_code=403,
                detail="consent custom-index action is not authorized",
            ) from exc
        except ops.ConsentCustomIndexConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="consent custom-index state or revision conflicts",
            ) from exc
        except ops.ConsentCustomIndexValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail="consent custom-index request is invalid",
            ) from exc
        except ops.ConsentCustomIndexIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="consent custom-index integrity verification failed",
            ) from exc
        except ops.ConsentCustomIndexConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="consent custom-index dependency is unavailable",
            ) from exc
        except ops.ConsentCustomIndexError as exc:
            raise HTTPException(
                status_code=503,
                detail="consent custom-index operation failed",
            ) from exc

    @router.get("/status")
    async def status(request: Request, response: Response) -> dict[str, object]:
        require_permission(request, "view")
        tenant = _tenant_id()
        enabled, configured, ready = await run_in_threadpool(
            probes, request, tenant
        )
        _secure(response)
        return {
            "schema": "lightwork.consent-custom-index-api-status.v1",
            "enabled": enabled,
            "configured": configured,
            "ready": bool(enabled and configured and ready),
            "tenant_id": tenant,
            "configuration": {
                "store_opened_for_status": False,
                "raw_key_read_by_browser": False,
                "tenant_actor_key_version_retention_caller_controlled": False,
                "source_database_and_key_custody_verified_by_readiness": bool(ready),
            },
            "search": {
                "match": "exact",
                "request_body_only": True,
                "raw_values_persisted": False,
            },
            "live_customer_estate_acceptance_verified": False,
        }

    @router.get("/operations/integrity")
    async def integrity(request: Request, response: Response) -> dict[str, object]:
        require_global_permission(request, "audit")
        ops, tenant, runtime = await composition(request)
        result = await call(ops, runtime.verify_integrity, tenant)
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.get("/operations/history")
    async def history(
        request: Request,
        response: Response,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, object]:
        require_global_permission(request, "audit")
        ops, tenant, runtime = await composition(request)
        applied_limit = min(limit, runtime.max_page_size)
        events = await call(
            ops,
            runtime.audit_history,
            tenant,
            limit=applied_limit,
        )
        _secure(response)
        return {
            "schema": "lightwork.consent-custom-index-history-page.v1",
            "items": _jsonable(events),
            "count": len(events),
            "applied_limit": applied_limit,
        }

    @router.post("", status_code=201)
    async def create_index(
        request: Request,
        response: Response,
        body: CreateIndexIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, runtime = await composition(request)
        record = await call(
            ops,
            runtime.create_index,
            tenant,
            **body.model_dump(),
        )
        _secure(response)
        return _jsonable(record)  # type: ignore[return-value]

    @router.get("")
    async def list_indexes(
        request: Request,
        response: Response,
        limit: int = Query(default=100, ge=1, le=500),
        cursor: OpaqueId | None = Query(default=None),
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, runtime = await composition(request)
        applied_limit = min(limit, runtime.max_page_size)
        records, next_cursor = await call(
            ops,
            runtime.list_indexes_page,
            tenant,
            limit=applied_limit,
            cursor=cursor,
        )
        _secure(response)
        return {
            "schema": "lightwork.consent-custom-index-page.v1",
            "items": _jsonable(records),
            "count": len(records),
            "next_cursor": next_cursor,
            "applied_limit": applied_limit,
        }

    @router.get("/{index_id}")
    async def get_index(
        request: Request,
        response: Response,
        index_id: ObjectPath,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, runtime = await composition(request)
        record = await call(ops, runtime.get_index, tenant, index_id)
        _secure(response)
        return _jsonable(record)  # type: ignore[return-value]

    @router.post("/{index_id}/build")
    async def build_index(
        request: Request,
        response: Response,
        index_id: ObjectPath,
        body: RevisionIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, runtime = await composition(request)
        record = await call(
            ops,
            runtime.build_index,
            tenant,
            index_id,
            **body.model_dump(),
        )
        _secure(response)
        return _jsonable(record)  # type: ignore[return-value]

    @router.post("/{index_id}/search")
    async def search(
        request: Request,
        response: Response,
        index_id: ObjectPath,
        body: SearchIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, runtime = await composition(request)
        payload = body.model_dump()
        payload["limit"] = min(body.limit, runtime.max_page_size)
        page = await call(
            ops,
            runtime.search,
            tenant,
            index_id,
            **payload,
        )
        _secure(response)
        return _jsonable(page)  # type: ignore[return-value]

    @router.post("/{index_id}/revoke")
    async def revoke_index(
        request: Request,
        response: Response,
        index_id: ObjectPath,
        body: RevisionIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, runtime = await composition(request)
        record = await call(
            ops,
            runtime.revoke_index,
            tenant,
            index_id,
            **body.model_dump(),
        )
        _secure(response)
        return _jsonable(record)  # type: ignore[return-value]

    return router


router = create_consent_custom_index_router()

__all__ = [
    "ConsentCustomIndexDependencies",
    "CreateIndexIn",
    "RevisionIn",
    "SearchIn",
    "create_consent_custom_index_router",
    "router",
]
