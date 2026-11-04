"""Strict authenticated API for third-party executive PDF reports."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import _dashboard_token_authenticated, has_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_COLOR_PATTERN = r"^#[0-9A-Fa-f]{6}$"
_TOKEN_PATTERN = r"^tpr_[A-Za-z0-9_-]{32,128}$"

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
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST_PATTERN),
]
Color = Annotated[
    str,
    StringConstraints(strict=True, min_length=7, max_length=7, pattern=_COLOR_PATTERN),
]
DownloadToken = Annotated[
    str,
    StringConstraints(strict=True, min_length=36, max_length=132, pattern=_TOKEN_PATTERN),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SourceSelectorIn(_StrictModel):
    source_kind: str = Field(min_length=1, max_length=64)
    source_id: OpaqueId


class BrandTokensIn(_StrictModel):
    organization_name: str = Field(min_length=1, max_length=120)
    report_title: str = Field(min_length=1, max_length=160)
    footer_text: str = Field(min_length=1, max_length=160)
    primary_color: Color
    accent_color: Color
    text_color: Color
    brand_asset_metadata_ref: OpaqueId | None = None
    brand_asset_metadata_sha256: Digest | None = None


class CreateReportIn(_StrictModel):
    report_id: OpaqueId | None = None
    expected_absent_revision: int = Field(default=0, strict=True, ge=0, le=0)
    selectors: list[SourceSelectorIn] = Field(default_factory=list, max_length=500)
    brand: BrandTokensIn
    idempotency_key: IdempotencyKey


class ControlIn(_StrictModel):
    expected_control_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    idempotency_key: IdempotencyKey


class RevokeIn(ControlIn):
    reason_code: OpaqueId


class RedeemIn(_StrictModel):
    token: DownloadToken


class PurgeIn(_StrictModel):
    limit: int = Field(default=100, strict=True, ge=1, le=1_000)
    idempotency_key: IdempotencyKey


class ThirdPartyExecutiveReportsDependencies:
    """Deployment-owned lazy runtime and readiness seams."""

    def __init__(
        self,
        *,
        runtime_factory: Callable[..., Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[[str], bool] | None = None,
    ) -> None:
        for dependency in (runtime_factory, enabled_probe, readiness_probe):
            if dependency is not None and not callable(dependency):
                raise TypeError("executive report dependency must be callable")
        self.runtime_factory = runtime_factory
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe


def _ops():
    from maverick import third_party_executive_reports as reports

    return reports


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using executive reports",
        )
    return tenant


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _private(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"


def _report_has_permission(request: Request, permission: str) -> bool:
    if _dashboard_token_authenticated(request):
        return permission in {"operate", "view"}
    return has_permission(request, permission)


def _require_report_permission(request: Request, permission: str) -> None:
    require_permission(request, permission)
    if not _report_has_permission(request, permission):
        raise HTTPException(status_code=403, detail="insufficient role for this action")


def _report_read_context(request: Request) -> tuple:
    """Current private-page authority, repeated after a waited report read."""
    from . import auth
    from .app import require_page_visible
    from .draft_api import context_for

    with auth.fresh_configuration():
        auth.require_principal(request=request)
        _require_report_permission(request, "view")
        auth.require_page_permission(request, "/third-party/executive-reports")
        require_page_visible(request, "/third-party/executive-reports")
        return (context_for(request), _tenant_id(), auth.caller_principal(request),
                auth.caller_role(request), _dashboard_token_authenticated(request))


def create_third_party_executive_reports_router(  # noqa: C901
    dependencies: ThirdPartyExecutiveReportsDependencies | None = None,
) -> APIRouter:
    deps = dependencies or ThirdPartyExecutiveReportsDependencies()
    router = APIRouter(
        prefix="/third-party/executive-reports",
        tags=["third-party-executive-reports"],
    )

    def probe(request: Request, name: str, explicit: Callable[[str], bool] | None):
        selected = explicit or getattr(request.app.state, name, None)
        return selected if callable(selected) else None

    def runtime(request: Request):
        tenant = _tenant_id()
        factory = deps.runtime_factory or getattr(
            request.app.state,
            "third_party_executive_reports_runtime_factory",
            None,
        )
        if not callable(factory):
            raise HTTPException(
                status_code=503,
                detail="third-party executive report runtime is unavailable",
            )
        try:
            value = factory(tenant_id=tenant, request=request)
        except _ops().ThirdPartyExecutiveReportPermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except _ops().ThirdPartyExecutiveReportConfigError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (OSError, RuntimeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="third-party executive report runtime is unavailable",
            ) from exc
        if value is None or not hasattr(value, "store"):
            raise HTTPException(
                status_code=503,
                detail="third-party executive report runtime is unavailable",
            )
        return tenant, value

    async def call(function, *args, **kwargs):
        ops = _ops()
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.ThirdPartyExecutiveReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ops.ThirdPartyExecutiveReportPermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ops.ThirdPartyExecutiveReportConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ops.ThirdPartyExecutiveReportValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ops.ThirdPartyExecutiveReportConfigError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ops.ThirdPartyExecutiveReportIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="third-party executive report integrity verification failed",
            ) from exc
        except ops.ThirdPartyExecutiveReportError as exc:
            raise HTTPException(
                status_code=503,
                detail="third-party executive report operation failed",
            ) from exc

    @router.get("/status")
    async def status(request: Request, response: Response) -> dict[str, object]:
        _require_report_permission(request, "view")
        tenant = _tenant_id()
        enabled = probe(
            request,
            "third_party_executive_reports_enabled_probe",
            deps.enabled_probe,
        )
        ready = probe(
            request,
            "third_party_executive_reports_readiness_probe",
            deps.readiness_probe,
        )
        _private(response)
        return {
            "schema": "lightwork.third-party-executive-reports-status.v1",
            "enabled": bool(enabled and enabled(tenant) is True),
            "ready": bool(ready and ready(tenant) is True),
            "deterministic_pdf": True,
            "arbitrary_html_css_urls": False,
            "brand_asset_bytes_embedded": False,
            "live_portfolio_acceptance_verified": False,
        }

    @router.post("/reports", status_code=201)
    async def create_report(
        payload: CreateReportIn,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        if not (
            _report_has_permission(request, "operate")
            or _report_has_permission(request, "audit")
        ):
            raise HTTPException(status_code=403, detail="insufficient role for this action")
        ops = _ops()
        _tenant, selected = runtime(request)
        brand = ops.BrandTokens(
            schema=ops.BRAND_SCHEMA,
            **payload.brand.model_dump(),
        )
        selectors = tuple(
            ops.SourceSelector(item.source_kind, item.source_id)
            for item in payload.selectors
        )
        record = await call(
            selected.create_report,
            selectors=selectors,
            brand=brand,
            report_id=payload.report_id,
            expected_absent_revision=payload.expected_absent_revision,
            idempotency_key=payload.idempotency_key,
        )
        _private(response)
        return _jsonable(record)

    @router.get("/reports")
    async def list_reports(
        request: Request,
        response: Response,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, Any]:
        _require_report_permission(request, "view")
        _tenant, selected = runtime(request)
        values = await call(
            selected.store.list_reports,
            caller_role=selected.role_view,
            limit=limit,
        )
        _private(response)
        return {
            "schema": "lightwork.third-party-executive-report-list.v1",
            "items": _jsonable(values),
            "count": len(values),
        }

    @router.get("/reports/{report_id}")
    async def get_report(
        report_id: ObjectPath,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        before = _report_read_context(request)
        _tenant, selected = runtime(request)
        record = await call(
            selected.store.get_report,
            report_id,
            caller_role=selected.role_view,
        )
        result = _jsonable(record)
        config_gate = getattr(selected.store, "_config_gate", None)
        if config_gate is not None:
            await call(config_gate)
        if _report_read_context(request) != before:
            raise HTTPException(409, "Your account, workspace or access changed. Open the current report page again.")
        _private(response)
        response.headers["X-Lightwork-Report-Context"] = before[0]
        return result

    @router.post("/reports/{report_id}/download-grants", status_code=201)
    async def issue_download_grant(
        report_id: ObjectPath,
        payload: ControlIn,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        _require_report_permission(request, "view")
        _tenant, selected = runtime(request)
        grant = await call(
            selected.store.issue_download_grant,
            report_id,
            caller_role=selected.role_view,
            expected_control_revision=payload.expected_control_revision,
            idempotency_key=payload.idempotency_key,
        )
        _private(response)
        return _jsonable(grant)

    @router.post("/downloads/redeem")
    async def redeem_download(
        payload: RedeemIn,
        request: Request,
    ) -> Response:
        _require_report_permission(request, "view")
        _tenant, selected = runtime(request)
        artifact = await call(
            selected.store.redeem_download_token,
            payload.token,
            caller_role=selected.role_view,
        )
        response = Response(
            content=artifact.pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="third-party-report-{artifact.report_id}.pdf"'
                ),
                "X-Content-SHA256": artifact.pdf_sha256,
            },
        )
        _private(response)
        return response

    @router.post("/reports/{report_id}/revoke")
    async def revoke_report(
        report_id: ObjectPath,
        payload: RevokeIn,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        _require_report_permission(request, "admin")
        _tenant, selected = runtime(request)
        record = await call(
            selected.store.revoke_report,
            report_id,
            expected_control_revision=payload.expected_control_revision,
            reason_code=payload.reason_code,
            idempotency_key=payload.idempotency_key,
        )
        _private(response)
        return _jsonable(record)

    @router.post("/maintenance/purge")
    async def purge_reports(
        payload: PurgeIn,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        _require_report_permission(request, "admin")
        _tenant, selected = runtime(request)
        report_ids = await call(
            selected.store.purge_expired,
            limit=payload.limit,
            idempotency_key=payload.idempotency_key,
        )
        _private(response)
        return {
            "schema": "lightwork.third-party-executive-report-purge.v1",
            "report_ids": list(report_ids),
            "count": len(report_ids),
        }

    @router.get("/audit")
    async def audit_history(
        request: Request,
        response: Response,
        limit: int = Query(default=100, ge=1, le=2_000),
    ) -> dict[str, Any]:
        _require_report_permission(request, "audit")
        _tenant, selected = runtime(request)
        events = await call(selected.store.audit_history, limit=limit)
        _private(response)
        return {
            "schema": "lightwork.third-party-executive-report-audit-list.v1",
            "items": _jsonable(events),
            "count": len(events),
        }

    @router.get("/integrity")
    async def verify_integrity(request: Request, response: Response) -> dict[str, Any]:
        _require_report_permission(request, "audit")
        _tenant, selected = runtime(request)
        result = await call(selected.store.verify_integrity)
        _private(response)
        return _jsonable(result)

    return router


__all__ = [
    "BrandTokensIn",
    "ControlIn",
    "CreateReportIn",
    "PurgeIn",
    "RedeemIn",
    "RevokeIn",
    "SourceSelectorIn",
    "ThirdPartyExecutiveReportsDependencies",
    "create_third_party_executive_reports_router",
]
