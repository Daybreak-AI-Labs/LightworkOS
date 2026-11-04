"""Strict administrative and SDK projection APIs for website publish settings.

Administrative bodies cannot supply tenant, principal, property/publication
pins, retention policy, CSP nonce values, or executable content.  The separate
public router delegates to one server-installed projection hook and returns an
explicit disabled/not-ready document instead of guessing configuration.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_permission

_MAX_JSON_BYTES = 64 * 1024
_SECURE_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}
_PUBLIC_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Cross-Origin-Resource-Policy": "same-site",
}

OpaqueId = Annotated[
    str,
    Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"),
]
IdempotencyKey = Annotated[
    str,
    Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$"),
]
SdkVersion = Annotated[
    str,
    Field(
        strict=True,
        pattern=(
            r"^(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\."
            r"(?:0|[1-9][0-9]{0,5})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
        ),
    ),
]
Jurisdiction = Annotated[
    str, Field(strict=True, pattern=r"^[A-Z]{2}(?:-[A-Z0-9]{1,16})?$")
]


class _BoundedJSONRoute(APIRoute):
    def get_route_handler(self):  # type: ignore[no-untyped-def]
        original = super().get_route_handler()

        async def bounded(request: Request):  # type: ignore[no-untyped-def]
            try:
                if request.method in {"POST", "PUT", "PATCH"}:
                    media_type = request.headers.get("content-type", "").split(
                        ";", 1
                    )[0].strip().lower()
                    if media_type != "application/json":
                        raise HTTPException(
                            status_code=415,
                            detail="web publish-settings requests require application/json",
                        )
                    supplied = request.headers.get("content-length")
                    if supplied is not None:
                        try:
                            declared = int(supplied)
                        except ValueError as exc:
                            raise HTTPException(
                                status_code=400,
                                detail="web publish-settings content length is invalid",
                            ) from exc
                        if declared < 0 or declared > _MAX_JSON_BYTES:
                            raise HTTPException(
                                status_code=413,
                                detail="web publish-settings request exceeds 64 KiB",
                            )
                    if len(await request.body()) > _MAX_JSON_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail="web publish-settings request exceeds 64 KiB",
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
                    content={"detail": "web publish-settings request is invalid"},
                    headers=_SECURE_HEADERS,
                )
            for name, value in _SECURE_HEADERS.items():
                response.headers[name] = value
            return response

        return bounded


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class GeolocationReconsentIn(_StrictModel):
    jurisdiction: Jurisdiction
    reconsent_after_days: StrictInt = Field(ge=1, le=3_650)


class AnalyticsCategoryAssignmentIn(_StrictModel):
    tracker: Literal[
        "google_analytics",
        "google_tag_manager",
        "linkedin_insight",
        "meta_pixel",
        "microsoft_clarity",
        "tiktok_pixel",
    ]
    category: Literal["advertising", "analytics", "essential", "functional"]


CommonTracker = Literal[
    "google_analytics",
    "google_tag_manager",
    "linkedin_insight",
    "meta_pixel",
    "microsoft_clarity",
    "tiktok_pixel",
]


class WebsiteSettingsIn(_StrictModel):
    sdk_version: SdkVersion
    geolocation_reconsent: list[GeolocationReconsentIn] = Field(max_length=64)
    analytics_tracking_enabled: StrictBool
    analytics_category_assignments: list[AnalyticsCategoryAssignmentIn] = Field(
        max_length=6
    )
    common_trackers: list[CommonTracker] = Field(max_length=6)
    cookie_same_site: Literal["lax", "none", "strict"]
    cookie_domain_separation: Literal["host_only", "property_domain"]
    spa_reload_on_route_change: StrictBool
    csp_nonce_required: StrictBool
    automatic_refresh_seconds: StrictInt | None = Field(default=None, ge=30, le=86_400)


class CreateVersionIn(_StrictModel):
    expected_head_revision: StrictInt = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey
    settings: WebsiteSettingsIn


class RevisionIn(_StrictModel):
    expected_head_revision: StrictInt = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class RollbackIn(RevisionIn):
    target_version_id: OpaqueId


class WebPublishSettingsDependencies:
    """Deployment-owned seams for tests and alternate composition."""

    def __init__(
        self,
        *,
        service_for: Callable[..., Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[[str], bool] | None = None,
        public_projection: Callable[..., Mapping[str, Any]] | None = None,
    ) -> None:
        for dependency in (
            service_for,
            enabled_probe,
            readiness_probe,
            public_projection,
        ):
            if dependency is not None and not callable(dependency):
                raise TypeError("web publish-settings dependency must be callable")
        self.service_for = service_for
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe
        self.public_projection = public_projection


def _ops():
    from maverick import consent_web_publish_settings as web

    return web


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using web publish settings",
        )
    return tenant


def _principal_ref(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for web publish settings",
    )
    digest = hashlib.sha256(
        f"lightwork.web-publish-settings.identity.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"web-settings-admin-{digest[:40]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _public_version(value: Any) -> dict[str, Any]:
    result = _jsonable(value)
    if not isinstance(result, dict):
        raise HTTPException(
            status_code=503, detail="web publish-settings authority is unavailable"
        )
    # Actor digests are retained for the audit authority, not ordinary reads.
    result.pop("created_by_sha256", None)
    return result


def _selected_dependency(request: Request, name: str, fallback: object) -> object:
    selected = getattr(request.app.state, name, None)
    return selected if selected is not None else fallback


def _validated_public_projection(
    value: Mapping[str, Any], *, property_id: str
) -> dict[str, Any]:
    """Fail closed on oversized or expanded deployment projection shapes."""

    projected = dict(value)
    base_keys = {
        "schema",
        "enabled",
        "ready",
        "reason",
        "property_id",
        "browser_property_acceptance_verified",
    }
    ready_keys = base_keys | {
        "head_revision",
        "settings_version_id",
        "settings_sha256",
        "property",
        "publication",
        "settings",
    }
    if (
        projected.get("property_id") != property_id
        or type(projected.get("enabled")) is not bool
        or type(projected.get("ready")) is not bool
        or projected.get("browser_property_acceptance_verified") is not False
        or not isinstance(projected.get("schema"), str)
        or not isinstance(projected.get("reason"), str)
        or len(str(projected["reason"])) > 96
        or set(projected) != (ready_keys if projected["ready"] else base_keys)
    ):
        raise HTTPException(
            status_code=503,
            detail="web publish-settings projection is unavailable",
        )
    try:
        encoded = json.dumps(
            projected,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HTTPException(
            status_code=503,
            detail="web publish-settings projection is unavailable",
        ) from exc
    if len(encoded) > 128 * 1024:
        raise HTTPException(
            status_code=503,
            detail="web publish-settings projection is unavailable",
        )

    def inspect(item: object) -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                lowered = str(key).lower()
                if (
                    lowered in {"tenant", "tenant_id", "principal", "principal_ref"}
                    or ("nonce" in lowered and lowered != "nonce_required")
                ):
                    raise HTTPException(
                        status_code=503,
                        detail="web publish-settings projection is unavailable",
                    )
                inspect(nested)
        elif isinstance(item, list):
            for nested in item:
                inspect(nested)

    inspect(projected)
    return projected


def create_consent_web_publish_settings_router(  # noqa: C901 - route trust boundary
    dependencies: WebPublishSettingsDependencies | None = None,
) -> APIRouter:
    deps = dependencies or WebPublishSettingsDependencies()
    router = APIRouter(
        prefix="/consent/publish-settings",
        tags=["consent-web-publish-settings"],
        route_class=_BoundedJSONRoute,
    )

    def probes(request: Request, tenant: str) -> tuple[bool, bool, bool]:
        enabled_probe = _selected_dependency(
            request,
            "consent_web_publish_settings_enabled_probe",
            deps.enabled_probe,
        )
        readiness_probe = _selected_dependency(
            request,
            "consent_web_publish_settings_readiness_probe",
            deps.readiness_probe,
        )
        factory = _selected_dependency(
            request,
            "consent_web_publish_settings_service_factory",
            deps.service_for,
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
                detail="web publish-settings configuration is unavailable",
            ) from exc
        if type(enabled) is not bool:
            raise HTTPException(
                status_code=503,
                detail="web publish-settings configuration is unavailable",
            )
        configured = callable(readiness_probe) and callable(factory)
        ready = False
        if enabled and configured:
            try:
                ready = readiness_probe(tenant)  # type: ignore[operator]
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="web publish-settings readiness is unavailable",
                ) from exc
            if type(ready) is not bool:
                raise HTTPException(
                    status_code=503,
                    detail="web publish-settings readiness is unavailable",
                )
        return enabled, configured, ready

    def authority(request: Request):
        tenant = _tenant_id()
        enabled, configured, ready = probes(request, tenant)
        if not enabled:
            raise HTTPException(
                status_code=403, detail="web_publish_settings_disabled"
            )
        if not configured or not ready:
            raise HTTPException(
                status_code=503,
                detail="web publish-settings authority is not ready",
            )
        principal = _principal_ref(request, tenant)
        factory = _selected_dependency(
            request,
            "consent_web_publish_settings_service_factory",
            deps.service_for,
        )
        assert callable(factory)
        try:
            service = factory(
                tenant_id=tenant,
                principal_ref=principal,
                request=request,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="web publish-settings authority is unavailable",
            ) from exc
        required = (
            "create_version",
            "activate_version",
            "rollback",
            "withdraw",
            "get_head",
            "get_version",
            "list_versions",
            "purge_version",
            "audit_history",
            "verify_integrity",
            "recovery_status",
        )
        if any(not callable(getattr(service, name, None)) for name in required):
            raise HTTPException(
                status_code=503,
                detail="web publish-settings authority is unavailable",
            )
        return _ops(), service

    async def call(web, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except web.WebPublishSettingsNotFound as exc:
            raise HTTPException(status_code=404, detail=exc.error_code) from exc
        except web.WebPublishSettingsPermissionDenied as exc:
            raise HTTPException(status_code=403, detail=exc.error_code) from exc
        except web.WebPublishSettingsConflict as exc:
            raise HTTPException(status_code=409, detail=exc.error_code) from exc
        except web.WebPublishSettingsValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.error_code) from exc
        except web.WebPublishSettingsIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="web publish-settings integrity verification failed",
            ) from exc
        except web.WebPublishSettingsConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="web publish-settings dependency is unavailable",
            ) from exc
        except web.WebPublishSettingsError as exc:
            raise HTTPException(
                status_code=503, detail="web publish-settings operation failed"
            ) from exc

    @router.get("/status")
    async def status(request: Request):
        require_permission(request, "view")
        tenant = _tenant_id()
        enabled, configured, ready = await run_in_threadpool(probes, request, tenant)
        return {
            "schema": "lightwork.consent-web-publish-settings.status.v1",
            "enabled": enabled,
            "configured": configured,
            "ready": ready,
            "immutable_versions": True,
            "cas_heads": True,
            "publication_pins_server_resolved": True,
            "csp_nonce_values_accepted": False,
            "browser_property_acceptance_verified": False,
        }

    @router.post("/properties/{property_id}/versions", status_code=201)
    async def create_version(
        request: Request, property_id: OpaqueId, body: CreateVersionIn
    ):
        require_permission(request, "admin")
        web, service = authority(request)
        result = await call(
            web,
            service.create_version,
            property_id=property_id,
            settings=body.settings.model_dump(mode="python"),
            expected_head_revision=body.expected_head_revision,
            idempotency_key=body.idempotency_key,
        )
        return _jsonable(result)

    @router.get("/properties/{property_id}")
    async def get_head(request: Request, property_id: OpaqueId):
        require_permission(request, "view")
        web, service = authority(request)
        return _public_version(
            await call(web, service.get_head, property_id=property_id)
        )

    @router.get("/properties/{property_id}/versions")
    async def list_versions(
        request: Request,
        property_id: OpaqueId,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "view")
        web, service = authority(request)
        items = await call(
            web, service.list_versions, property_id=property_id, limit=limit
        )
        return {"items": [_public_version(item) for item in items], "count": len(items)}

    @router.get("/properties/{property_id}/versions/{version_id}")
    async def get_version(
        request: Request, property_id: OpaqueId, version_id: OpaqueId
    ):
        require_permission(request, "view")
        web, service = authority(request)
        return _public_version(
            await call(
                web,
                service.get_version,
                property_id=property_id,
                version_id=version_id,
            )
        )

    @router.post("/properties/{property_id}/versions/{version_id}/activate")
    async def activate(
        request: Request,
        property_id: OpaqueId,
        version_id: OpaqueId,
        body: RevisionIn,
    ):
        require_permission(request, "admin")
        web, service = authority(request)
        return _jsonable(
            await call(
                web,
                service.activate_version,
                property_id=property_id,
                version_id=version_id,
                **body.model_dump(),
            )
        )

    @router.post("/properties/{property_id}/rollback")
    async def rollback(request: Request, property_id: OpaqueId, body: RollbackIn):
        require_permission(request, "admin")
        web, service = authority(request)
        return _jsonable(
            await call(
                web,
                service.rollback,
                property_id=property_id,
                **body.model_dump(),
            )
        )

    @router.post("/properties/{property_id}/withdraw")
    async def withdraw(request: Request, property_id: OpaqueId, body: RevisionIn):
        require_permission(request, "admin")
        web, service = authority(request)
        return _jsonable(
            await call(
                web,
                service.withdraw,
                property_id=property_id,
                **body.model_dump(),
            )
        )

    @router.post("/properties/{property_id}/versions/{version_id}/retention-purge")
    async def retention_purge(
        request: Request,
        property_id: OpaqueId,
        version_id: OpaqueId,
        body: RevisionIn,
    ):
        require_permission(request, "admin")
        web, service = authority(request)
        return _jsonable(
            await call(
                web,
                service.purge_version,
                property_id=property_id,
                version_id=version_id,
                **body.model_dump(),
            )
        )

    @router.get("/operations/history")
    async def history(
        request: Request,
        property_id: OpaqueId | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "audit")
        web, service = authority(request)
        items = await call(
            web,
            service.audit_history,
            property_id=property_id,
            limit=limit,
        )
        return {"items": _jsonable(items), "count": len(items)}

    @router.get("/operations/integrity")
    async def integrity(request: Request):
        require_permission(request, "audit")
        web, service = authority(request)
        return _jsonable(await call(web, service.verify_integrity))

    @router.get("/operations/recovery")
    async def recovery(request: Request):
        require_permission(request, "audit")
        web, service = authority(request)
        return _jsonable(await call(web, service.recovery_status))

    return router


def create_consent_web_publish_settings_public_router(
    dependencies: WebPublishSettingsDependencies | None = None,
) -> APIRouter:
    """Create the unauthenticated, tenant-from-host SDK projection router."""

    deps = dependencies or WebPublishSettingsDependencies()
    router = APIRouter(
        prefix="/consent/publish-settings",
        tags=["public-consent-web-publish-settings"],
    )

    @router.get("/{property_id}")
    async def public_projection(
        request: Request, response: Response, property_id: OpaqueId
    ):
        tenant = _tenant_id()
        selected = _selected_dependency(
            request,
            "consent_web_publish_settings_public_projection",
            deps.public_projection,
        )
        if not callable(selected):
            result: Mapping[str, Any] = {
                "schema": _ops().PUBLIC_PROJECTION_SCHEMA,
                "enabled": False,
                "ready": False,
                "reason": "composition_unavailable",
                "property_id": property_id,
                "browser_property_acceptance_verified": False,
            }
        else:
            try:
                result = await run_in_threadpool(
                    selected, tenant, property_id, request
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                result = {
                    "schema": _ops().PUBLIC_PROJECTION_SCHEMA,
                    "enabled": True,
                    "ready": False,
                    "reason": "runtime_not_ready",
                    "property_id": property_id,
                    "browser_property_acceptance_verified": False,
                }
        if not isinstance(result, Mapping):
            raise HTTPException(
                status_code=503,
                detail="web publish-settings projection is unavailable",
            )
        projected = _validated_public_projection(result, property_id=property_id)
        for name, value in _PUBLIC_HEADERS.items():
            response.headers[name] = value
        return projected

    return router


__all__ = [
    "WebPublishSettingsDependencies",
    "create_consent_web_publish_settings_public_router",
    "create_consent_web_publish_settings_router",
]
