"""Strict authenticated administration API for Global Opt-Out configuration."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Path, Query, Request
from maverick import consent_global_opt_out as opt_out
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission

router = APIRouter(prefix="/consent/global-opt-out", tags=["consent-global-opt-out"])

_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDEMPOTENCY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class GlobalOptOutUIIn(_StrictModel):
    enabled: bool
    title: str = Field(min_length=1, max_length=2_048)
    body: str = Field(min_length=1, max_length=2_048)
    submit_label: str = Field(min_length=1, max_length=2_048)
    success_message: str = Field(min_length=1, max_length=2_048)


Device = Literal[
    "android",
    "browser",
    "connected-tv",
    "fireos",
    "ios",
    "roku",
    "tizen",
    "tvos",
    "webos",
]
Service = Literal[
    "connected-tv",
    "email",
    "mobile-app",
    "streaming-service",
    "website",
]


class GlobalOptOutConfigurationCreateIn(_StrictModel):
    application_ref: str = Field(pattern=_REF_PATTERN)
    locale: str = Field(min_length=2, max_length=64)
    mobile_ui: GlobalOptOutUIIn
    email_ui: GlobalOptOutUIIn
    supported_devices: list[Device] = Field(min_length=1, max_length=9)
    supported_services: list[Service] = Field(min_length=1, max_length=5)
    expires_at: float | None = Field(default=None, gt=0)
    expected_revision: Literal[0]
    idempotency_key: str = Field(
        min_length=8,
        max_length=192,
        pattern=_IDEMPOTENCY_PATTERN,
    )


class GlobalOptOutConfigurationUpdateIn(_StrictModel):
    locale: str = Field(min_length=2, max_length=64)
    mobile_ui: GlobalOptOutUIIn
    email_ui: GlobalOptOutUIIn
    supported_devices: list[Device] = Field(min_length=1, max_length=9)
    supported_services: list[Service] = Field(min_length=1, max_length=5)
    expires_at: float | None = Field(default=None, gt=0)
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: str = Field(
        min_length=8,
        max_length=192,
        pattern=_IDEMPOTENCY_PATTERN,
    )


class GlobalOptOutStateChangeIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: str = Field(
        min_length=8,
        max_length=192,
        pattern=_IDEMPOTENCY_PATTERN,
    )


class GlobalOptOutMaintenanceIn(_StrictModel):
    limit: int = Field(default=100, ge=1, le=1_000)


ConfigurationId = Annotated[
    str,
    Path(min_length=1, max_length=64, pattern=r"^GOO-C[0-9a-f]{48}$"),
]


def _tenant() -> str:
    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "global_opt_out_tenant_required",
                "message": "select an active tenant before managing Global Opt-Out",
            },
        )
    return tenant


def _principal_ref(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request,
        error_detail={
            "code": "global_opt_out_principal_required",
            "message": "authenticated principal authority is unavailable",
        },
    )
    digest = hashlib.sha256(
        f"lightwork.global-opt-out.identity.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"global-opt-out-admin-{digest[:32]}"


def _store(request: Request) -> opt_out.GlobalOptOutStore:
    tenant = _tenant()
    factory = getattr(request.app.state, "global_opt_out_admin_store_factory", None)
    if not callable(factory):
        raise opt_out.GlobalOptOutDisabled("Global Opt-Out composition is unavailable")
    try:
        value = factory(
            tenant_id=tenant,
            principal_ref=_principal_ref(request, tenant),
            request=request,
        )
    except opt_out.GlobalOptOutError:
        raise
    except Exception as exc:
        raise opt_out.GlobalOptOutIntegrityError(
            "Global Opt-Out composition is unavailable"
        ) from exc
    if not isinstance(value, opt_out.GlobalOptOutStore):
        raise opt_out.GlobalOptOutIntegrityError(
            "Global Opt-Out composition returned an invalid authority"
        )
    return value


def _detail(exc: opt_out.GlobalOptOutError) -> dict[str, str]:
    return {"code": exc.code, "message": str(exc)}


def _http_error(exc: opt_out.GlobalOptOutError) -> HTTPException:
    if isinstance(exc, opt_out.GlobalOptOutDisabled):
        status = 403
    elif isinstance(exc, opt_out.GlobalOptOutNotFound):
        status = 404
    elif isinstance(
        exc,
        (
            opt_out.GlobalOptOutAuthorityStale,
            opt_out.GlobalOptOutConflict,
            opt_out.GlobalOptOutNotConfigured,
        ),
    ):
        status = 409
    elif isinstance(exc, opt_out.GlobalOptOutPermissionDenied):
        status = 403
    elif isinstance(exc, opt_out.GlobalOptOutValidationError):
        status = 422
    else:
        status = 503
    return HTTPException(status_code=status, detail=_detail(exc))


async def _call(request: Request, method: str, /, *args: Any, **kwargs: Any) -> Any:
    def invoke():
        # Construct the tenant store inside both the error boundary and worker
        # thread. Disabled/missing authority can fail before a method is bound.
        return getattr(_store(request), method)(*args, **kwargs)

    try:
        return await run_in_threadpool(invoke)
    except HTTPException:
        raise
    except opt_out.GlobalOptOutError as exc:
        raise _http_error(exc) from exc
    except Exception as exc:
        error = opt_out.GlobalOptOutIntegrityError(
            "Global Opt-Out operation is unavailable"
        )
        raise _http_error(error) from exc


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    require_global_permission(request, "view")
    tenant = _tenant()
    enabled_probe = getattr(request.app.state, "global_opt_out_enabled_probe", None)
    probe = getattr(request.app.state, "global_opt_out_readiness_probe", None)
    try:
        enabled = callable(enabled_probe) and enabled_probe(tenant) is True
        readiness = probe(tenant) if callable(probe) else {"ready": False}
    except Exception:
        enabled = False
        readiness = {"ready": False}
    if not isinstance(readiness, Mapping):
        readiness = {"ready": False}
    return {
        "schema": "lightwork.consent-global-opt-out-status.v1",
        "enabled": enabled,
        "ready": readiness.get("ready") is True,
        "readiness": dict(readiness),
        "product_boundaries": opt_out.GlobalOptOutStore.product_boundaries(),
    }


@router.post("/configurations", status_code=201)
async def create_configuration(
    body: GlobalOptOutConfigurationCreateIn,
    request: Request,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    payload = body.model_dump()
    application_ref = payload.pop("application_ref")
    return await _call(request, "create_configuration", application_ref, **payload)


@router.get("/configurations")
async def list_configurations(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "view")
    return await _call(request, "list_configurations", limit=limit)


@router.get("/configurations/{configuration_id}")
async def get_configuration(
    configuration_id: ConfigurationId,
    request: Request,
) -> dict[str, Any]:
    require_global_permission(request, "view")
    return await _call(request, "get_configuration", configuration_id)


@router.put("/configurations/{configuration_id}")
async def update_configuration(
    configuration_id: ConfigurationId,
    body: GlobalOptOutConfigurationUpdateIn,
    request: Request,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    return await _call(
        request, "update_configuration",
        configuration_id,
        **body.model_dump(),
    )


@router.post("/configurations/{configuration_id}/activate")
async def activate_configuration(
    configuration_id: ConfigurationId,
    body: GlobalOptOutStateChangeIn,
    request: Request,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    return await _call(
        request, "activate_configuration",
        configuration_id,
        **body.model_dump(),
    )


@router.post("/configurations/{configuration_id}/revoke")
async def revoke_configuration(
    configuration_id: ConfigurationId,
    body: GlobalOptOutStateChangeIn,
    request: Request,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    return await _call(
        request, "revoke_configuration",
        configuration_id,
        **body.model_dump(),
    )


@router.get("/configurations/{configuration_id}/history")
async def configuration_history(
    configuration_id: ConfigurationId,
    request: Request,
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    return await _call(request, "configuration_history", configuration_id)


@router.get("/integrity")
async def verify_integrity(
    request: Request,
    limit: int = Query(default=10_000, ge=1, le=10_000),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    return await _call(request, "verify_integrity", limit=limit)


@router.post("/maintenance/purge")
async def purge_retained(
    body: GlobalOptOutMaintenanceIn,
    request: Request,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    return await _call(request, "purge_retained", limit=body.limit)


@router.post("/maintenance/retry-audit")
async def retry_audit(
    body: GlobalOptOutMaintenanceIn,
    request: Request,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    return await _call(request, "retry_pending_audit", limit=body.limit)


__all__ = [
    "GlobalOptOutConfigurationCreateIn",
    "GlobalOptOutConfigurationUpdateIn",
    "GlobalOptOutMaintenanceIn",
    "GlobalOptOutStateChangeIn",
    "GlobalOptOutUIIn",
    "router",
]
