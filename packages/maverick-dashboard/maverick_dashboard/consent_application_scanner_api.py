"""Strict tenant-bound API for mobile and OTT/CTV manifest analysis."""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Callable, Mapping
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as ApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_permission

_MAX_JSON_BYTES = 6 * 1_024 * 1_024
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_MEDIA_TYPE_PATTERN = r"^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}$"
_PLATFORM_PATTERN = r"^(android|fireos|ios|tvos|roku|tizen|webos)$"
_DECISION_PATTERN = r"^(accepted|needs_changes|rejected)$"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_ID_PATTERN),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=192, pattern=_ID_PATTERN),
]
Platform = Annotated[
    str,
    StringConstraints(strict=True, min_length=2, max_length=16, pattern=_PLATFORM_PATTERN),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST_PATTERN),
]
_SECURE_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


async def _read_bounded_json_body(request: Request, declared: int) -> None:
    """Buffer exactly one declared JSON body without an unbounded body read."""

    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > _MAX_JSON_BYTES:
            raise HTTPException(
                status_code=413,
                detail="consent application-scanner request exceeds 6 MiB",
            )
        if received > declared:
            raise HTTPException(
                status_code=400,
                detail="consent application-scanner request length is invalid",
            )
        if chunk:
            chunks.append(chunk)
    if received != declared:
        raise HTTPException(
            status_code=400,
            detail="consent application-scanner request length is invalid",
        )
    # Starlette's downstream JSON parser reads Request.body(). Preserve its
    # bounded cache after consuming the ASGI stream here.
    request._body = b"".join(chunks)  # noqa: SLF001 - bounded Starlette body cache


class _BoundedJSONRoute(APIRoute):
    """Require a declared, bounded JSON body before manifest decoding."""

    def get_route_handler(self):  # type: ignore[no-untyped-def]
        original = super().get_route_handler()

        async def bounded(request: Request):  # type: ignore[no-untyped-def]
            try:
                if request.method in {"POST", "PUT", "PATCH"}:
                    media_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
                    if media_type != "application/json":
                        raise HTTPException(
                            status_code=415,
                            detail="consent application-scanner requests require application/json",
                        )
                    supplied = request.headers.get("content-length")
                    if supplied is None:
                        raise HTTPException(
                            status_code=411,
                            detail="consent application-scanner content length is required",
                        )
                    try:
                        declared = int(supplied)
                    except ValueError as exc:
                        raise HTTPException(
                            status_code=400,
                            detail="consent application-scanner content length is invalid",
                        ) from exc
                    if declared < 0 or declared > _MAX_JSON_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail="consent application-scanner request exceeds 6 MiB",
                        )
                    await _read_bounded_json_body(request, declared)
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
                    content={"detail": "consent application-scanner request is invalid"},
                    headers=_SECURE_HEADERS,
                )
            for name, value in _SECURE_HEADERS.items():
                response.headers[name] = value
            return response

        return bounded


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RegisterApplicationIn(_StrictModel):
    platform: Platform
    bundle_id: str = Field(strict=True, min_length=1, max_length=255)
    display_name: str = Field(strict=True, min_length=1, max_length=255)
    idempotency_key: OpaqueId


class RevokeApplicationIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=2**31 - 1)
    reason_code: OpaqueId


class ManifestFileIn(_StrictModel):
    path: str = Field(strict=True, min_length=1, max_length=1_024)
    media_type: Annotated[
        str,
        StringConstraints(
            strict=True,
            min_length=3,
            max_length=128,
            pattern=_MEDIA_TYPE_PATTERN,
        ),
    ]
    content_base64: str = Field(strict=True, min_length=4, max_length=1_398_104)


class ScanApplicationIn(_StrictModel):
    expected_application_revision: int = Field(strict=True, ge=1, le=2**31 - 1)
    idempotency_key: OpaqueId
    files: list[ManifestFileIn] = Field(min_length=1, max_length=64)


class ReviewScanIn(_StrictModel):
    decision: Annotated[
        str,
        StringConstraints(strict=True, min_length=8, max_length=13, pattern=_DECISION_PATTERN),
    ]
    expected_revision: int = Field(strict=True, ge=1, le=2**31 - 1)
    review_note_code: OpaqueId


class MaintenanceIn(_StrictModel):
    limit: int = Field(default=100, strict=True, ge=1, le=500)


class ConsentApplicationScannerDependencies:
    """Deployment-owned request-bound seams."""

    def __init__(
        self,
        *,
        service_factory: Callable[..., Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[..., bool] | None = None,
        maintenance: Callable[..., Mapping[str, Any]] | None = None,
    ) -> None:
        for dependency in (service_factory, enabled_probe, readiness_probe, maintenance):
            if dependency is not None and not callable(dependency):
                raise TypeError("consent application-scanner dependency must be callable")
        self.service_factory = service_factory
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe
        self.maintenance = maintenance


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using consent application scanning",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request,
        error_detail="an authenticated principal is required for consent application scanning",
    )
    digest = hashlib.sha256(
        f"lightwork.consent-application-scanner.identity.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"consent-app-scanner-{digest[:40]}"


def _dependency(request: Request, name: str, fallback: object) -> object:
    return getattr(request.app.state, name, fallback)


def _decode_files(files: list[ManifestFileIn]):
    from maverick.consent_application_scanner import (
        ConsentApplicationScanValidationError,
        ManifestFile,
    )

    output: list[ManifestFile] = []
    total = 0
    for item in files:
        try:
            content = base64.b64decode(item.content_base64.encode("ascii"), validate=True)
        except (UnicodeError, binascii.Error) as exc:
            raise ConsentApplicationScanValidationError(
                "manifest content_base64 is invalid"
            ) from exc
        if not 1 <= len(content) <= 1_048_576:
            raise ConsentApplicationScanValidationError(
                "manifest file bytes must be between 1 and 1048576"
            )
        total += len(content)
        if total > 4_194_304:
            raise ConsentApplicationScanValidationError("manifest bundle exceeds 4 MiB")
        output.append(ManifestFile(path=item.path, media_type=item.media_type, content=content))
    return output


async def _call(function, *args, **kwargs):
    from maverick import consent_application_scanner as scanner

    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except (KeyboardInterrupt, SystemExit):
        raise
    except scanner.ConsentApplicationScanNotFound as exc:
        raise HTTPException(
            status_code=404, detail="consent application-scanner record was not found"
        ) from exc
    except scanner.ConsentApplicationScanConflict as exc:
        raise HTTPException(
            status_code=409,
            detail="consent application-scanner state or authority conflicts",
        ) from exc
    except scanner.ConsentApplicationScanIntegrityError as exc:
        raise HTTPException(
            status_code=503,
            detail="consent application-scanner custody failed integrity validation",
        ) from exc
    except scanner.ConsentApplicationScanValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except scanner.ConsentApplicationScanError as exc:
        raise HTTPException(
            status_code=503, detail="consent application scanning is unavailable"
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="consent application scanning is unavailable"
        ) from exc


def create_consent_application_scanner_router(  # noqa: C901 - route-local trust boundaries
    dependencies: ConsentApplicationScannerDependencies | None = None,
) -> APIRouter:
    """Build tenant-authorized routes over a strictly tenant-bound authority.

    These records never cross the active tenant, so tenant membership and an
    explicit tenant-local demotion must win over a broader dashboard role.
    Mutations require the active tenant's ``admin`` permission; integrity reads
    require its ``audit`` permission. Authentication failures remain closed.
    """

    deps = dependencies or ConsentApplicationScannerDependencies()
    router = APIRouter(
        prefix="/consent/application-scans",
        tags=["consent-application-scans"],
        route_class=_BoundedJSONRoute,
    )

    def resolve(request: Request):
        tenant = _tenant_id()
        enabled = _dependency(
            request,
            "consent_application_scanner_enabled_probe",
            deps.enabled_probe,
        )
        readiness = _dependency(
            request,
            "consent_application_scanner_readiness_probe",
            deps.readiness_probe,
        )
        factory = _dependency(
            request,
            "consent_application_scanner_service_factory",
            deps.service_factory,
        )
        if not callable(enabled) or enabled(tenant) is not True:
            raise HTTPException(status_code=403, detail="consent application scanning is disabled")
        if not callable(readiness) or readiness(request, tenant) is not True:
            raise HTTPException(status_code=503, detail="consent application scanning is not ready")
        if not callable(factory):
            raise HTTPException(
                status_code=503, detail="consent application scanning is unavailable"
            )
        try:
            service = factory(request, tenant)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="consent application scanning is unavailable",
            ) from exc
        required = (
            "register_application",
            "get_application",
            "list_applications",
            "revoke_application",
            "scan",
            "get_scan",
            "list_scans",
            "review",
            "verify_integrity",
        )
        if any(not callable(getattr(service, name, None)) for name in required):
            raise HTTPException(
                status_code=503, detail="consent application scanning is unavailable"
            )
        return tenant, service

    @router.get("/readiness")
    async def readiness(request: Request, response: Response):
        require_permission(request, "view")
        tenant = _tenant_id()
        enabled_probe = _dependency(
            request,
            "consent_application_scanner_enabled_probe",
            deps.enabled_probe,
        )
        readiness_probe = _dependency(
            request,
            "consent_application_scanner_readiness_probe",
            deps.readiness_probe,
        )
        enabled = callable(enabled_probe) and enabled_probe(tenant) is True
        ready = enabled and callable(readiness_probe) and readiness_probe(request, tenant) is True
        response.status_code = 200 if ready else 503
        return {"enabled": enabled, "ready": ready}

    @router.post("/applications", status_code=201)
    async def register(payload: RegisterApplicationIn, request: Request):
        require_permission(request, "admin")
        tenant, service = resolve(request)
        return await _call(
            service.register_application,
            platform=payload.platform,
            bundle_id=payload.bundle_id,
            display_name=payload.display_name,
            actor=_principal(request, tenant),
            idempotency_key=payload.idempotency_key,
        )

    @router.get("/applications")
    async def list_applications(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
    ):
        require_permission(request, "view")
        _, service = resolve(request)
        return {"applications": await _call(service.list_applications, limit=limit)}

    @router.get("/applications/{application_id}")
    async def get_application(application_id: ObjectPath, request: Request):
        require_permission(request, "view")
        _, service = resolve(request)
        return await _call(service.get_application, application_id)

    @router.post("/applications/{application_id}/revoke")
    async def revoke_application(
        application_id: ObjectPath,
        payload: RevokeApplicationIn,
        request: Request,
    ):
        require_permission(request, "admin")
        tenant, service = resolve(request)
        return await _call(
            service.revoke_application,
            application_id,
            actor=_principal(request, tenant),
            reason_code=payload.reason_code,
            expected_revision=payload.expected_revision,
        )

    @router.post("/applications/{application_id}/scans", status_code=201)
    async def scan_application(
        application_id: ObjectPath,
        payload: ScanApplicationIn,
        request: Request,
    ):
        require_permission(request, "admin")
        tenant, service = resolve(request)
        try:
            files = _decode_files(payload.files)
        except Exception as exc:
            from maverick import consent_application_scanner as scanner

            if isinstance(exc, scanner.ConsentApplicationScanValidationError):
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            raise
        return await _call(
            service.scan,
            application_id,
            files,
            actor=_principal(request, tenant),
            idempotency_key=payload.idempotency_key,
            expected_application_revision=payload.expected_application_revision,
        )

    @router.get("/scans")
    async def list_scans(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
    ):
        require_permission(request, "view")
        _, service = resolve(request)
        return {"scans": await _call(service.list_scans, limit=limit)}

    @router.get("/scans/{scan_id}")
    async def get_scan(scan_id: ObjectPath, request: Request):
        require_permission(request, "view")
        _, service = resolve(request)
        return await _call(service.get_scan, scan_id)

    @router.post("/scans/{scan_id}/review")
    async def review_scan(scan_id: ObjectPath, payload: ReviewScanIn, request: Request):
        require_permission(request, "admin")
        tenant, service = resolve(request)
        return await _call(
            service.review,
            scan_id,
            decision=payload.decision,
            reviewer=_principal(request, tenant),
            expected_revision=payload.expected_revision,
            review_note_code=payload.review_note_code,
        )

    @router.get("/integrity")
    async def integrity(
        request: Request,
        limit: int = Query(default=500, ge=1, le=500),
    ):
        require_permission(request, "audit")
        _, service = resolve(request)
        return await _call(service.verify_integrity, limit=limit)

    @router.post("/maintenance/purge")
    async def maintenance(payload: MaintenanceIn, request: Request):
        require_permission(request, "admin")
        tenant = _tenant_id()
        maintenance_fn = _dependency(
            request,
            "consent_application_scanner_maintenance",
            deps.maintenance,
        )
        if not callable(maintenance_fn):
            raise HTTPException(
                status_code=503, detail="consent application scanning is unavailable"
            )
        try:
            return await run_in_threadpool(
                maintenance_fn,
                request,
                tenant,
                actor=_principal(request, tenant),
                limit=payload.limit,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail="consent application scanning is unavailable"
            ) from exc

    return router


router = create_consent_application_scanner_router()
