"""Strict operator API for continuous technology-control evidence.

Tenant and principal authority are derived from authenticated server context.
The API accepts only closed identifiers, enumerations, revisions, and SHA-256
digests.  Provider URLs, credentials, raw artifacts, compliance conclusions,
and worker lease tokens are intentionally absent.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

_ID_PATTERN = r"^[a-z][a-z0-9_.:-]{0,127}$"
_CONTROL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]
ControlRef = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=_CONTROL_PATTERN,
    ),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST_PATTERN),
]
JobState = Literal[
    "queued",
    "leased",
    "completed",
    "incomplete",
    "dead_letter",
    "cancelled",
]
EnrollmentState = Literal["active", "paused", "revoked"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class DefinitionIn(_StrictModel):
    collector_id: OpaqueId
    collector_schema_version: int = Field(ge=1, le=2**31 - 1)
    collector_key_id: OpaqueId
    capability_revision: int = Field(ge=1, le=2**31 - 1)
    allowed_control_refs: list[ControlRef] = Field(min_length=1, max_length=250)


class IntegrityIn(_StrictModel):
    expected_integrity_sha256: Digest


class EnrollmentIn(_StrictModel):
    definition_id: OpaqueId
    definition_version: int = Field(ge=1, le=2**31 - 1)
    expected_definition_integrity_sha256: Digest
    asset_scope_sha256: Digest
    credential_profile_sha256: Digest
    control_refs: list[ControlRef] = Field(min_length=1, max_length=250)
    interval_seconds: int = Field(ge=60, le=366 * 24 * 3_600)
    operation_id: OpaqueId
    retention_seconds: int = Field(ge=60, le=10 * 366 * 24 * 3_600)


class EnrollmentStateIn(_StrictModel):
    state: EnrollmentState
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    expected_integrity_sha256: Digest


class EnqueueIn(_StrictModel):
    limit: int = Field(default=50, ge=1, le=100)
    max_attempts: int = Field(default=5, ge=1, le=20)


class RequeueIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    operation_id: OpaqueId


class PurgeIn(_StrictModel):
    cutoff: float = Field(ge=0, lt=100_000_000_000.0)
    limit: int = Field(default=500, ge=1, le=500)


def _enabled() -> bool:
    from maverick.trc_continuous_evidence import enabled

    return enabled()


def trc_continuous_evidence_enabled_for_page() -> bool:
    return _enabled()


def _collector_ids(request: Request) -> frozenset[str]:
    """Resolve the tenant's closed collector allowlist from trusted config."""

    loader = getattr(
        request.app.state,
        "trc_continuous_evidence_config_loader",
        None,
    )
    try:
        if callable(loader):
            config = loader()
        else:
            from maverick.config import config_source_errors, load_config

            if config_source_errors(include_tenant=True):
                raise RuntimeError("tenant configuration is unreadable")
            config = load_config() or {}
        from .trc_continuous_evidence_scheduler import configured_collector_ids

        configured = configured_collector_ids(config)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="continuous-evidence collector allowlist is unavailable",
        ) from exc
    if configured is None:
        raise HTTPException(
            status_code=403,
            detail="continuous evidence is not enabled for this tenant",
        )
    return frozenset(configured)


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using continuous evidence",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for continuous evidence",
    )
    digest = hashlib.sha256(
        f"lightwork.trc-evidence.api-principal.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"trc-api.{digest[:40]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items() if key != "source_manifest"}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items() if key != "source_manifest"}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _default_store_for(tenant_id: str, principal_ref: str):
    from maverick.paths import data_dir
    from maverick.trc_continuous_evidence import ContinuousEvidenceStore

    return ContinuousEvidenceStore(
        data_dir(
            "tech_risk_compliance",
            "continuous-evidence.sqlite3",
            tenant=tenant_id,
        ),
        tenant_id=tenant_id,
        principal_resolver=lambda: principal_ref,
    )


class TrcContinuousEvidenceDependencies:
    def __init__(
        self,
        *,
        store_for: Callable[[str, str], Any] = _default_store_for,
    ) -> None:
        self.store_for = store_for


def create_trc_continuous_evidence_router(  # noqa: C901
    dependencies: TrcContinuousEvidenceDependencies | None = None,
) -> APIRouter:
    deps = dependencies or TrcContinuousEvidenceDependencies()
    router = APIRouter(
        prefix="/compliance/continuous-evidence",
        tags=["trc-continuous-evidence"],
    )

    def authority(request: Request):
        from maverick import trc_continuous_evidence as evidence

        try:
            evidence.require_enabled()
        except evidence.ContinuousEvidenceConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        factory = getattr(
            request.app.state,
            "trc_continuous_evidence_store_factory",
            None,
        )
        try:
            store = (
                factory(
                    tenant_id=tenant,
                    principal_ref=principal,
                    principal_resolver=lambda: principal,
                    request=request,
                )
                if callable(factory)
                else deps.store_for(tenant, principal)
            )
        except evidence.ContinuousEvidenceConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (evidence.ContinuousEvidenceError, OSError) as exc:
            raise HTTPException(
                status_code=503,
                detail="continuous-evidence store is unavailable",
            ) from exc
        if store is None:
            raise HTTPException(
                status_code=503,
                detail="continuous-evidence store is unavailable",
            )
        return evidence, store

    async def call(evidence, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except evidence.ContinuousEvidenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except evidence.ContinuousEvidencePermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except evidence.ContinuousEvidenceConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except evidence.ContinuousEvidenceValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except evidence.ContinuousEvidenceConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except evidence.ContinuousEvidenceIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="continuous-evidence integrity verification failed",
            ) from exc
        except evidence.ContinuousEvidenceError as exc:
            raise HTTPException(
                status_code=503,
                detail="continuous-evidence operation failed",
            ) from exc

    @router.get("/status")
    async def status(request: Request):
        require_permission(request, "view")
        scheduler = getattr(
            request.app.state,
            "trc_continuous_evidence_scheduler",
            None,
        )
        scheduler_status = scheduler.status() if scheduler is not None else None
        custom_dependencies = bool(
            isinstance(scheduler_status, Mapping)
            and scheduler_status.get("custom_collector_dependencies_injected") is True
        )
        stock_probe = getattr(
            request.app.state,
            "trc_stock_evidence_readiness_probe",
            None,
        )
        stock_readiness: Mapping[str, object] | None = None
        if callable(stock_probe):
            try:
                candidate = await run_in_threadpool(stock_probe, _tenant_id())
                if isinstance(candidate, Mapping):
                    stock_readiness = candidate
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                stock_readiness = {
                    "schema": "lightwork.trc-stock-collector-production-readiness.v1",
                    "enabled": False,
                    "ready": False,
                    "error_code": "stock_collector_readiness_unavailable",
                    "status_secret_resolution": False,
                    "status_provider_network_io": False,
                    "live_provider_acceptance_verified": False,
                }
        return {
            "schema": "lightwork.trc-continuous-evidence-status.v1",
            "enabled": _enabled(),
            "scheduler": scheduler_status,
            "provider_network_io_in_core": False,
            "collector_dependency_injection_supported": True,
            "custom_collector_dependencies_injected": custom_dependencies,
            "stock_collectors": stock_readiness,
            "raw_provider_payload_persisted": False,
            "raw_credentials_persisted": False,
            "compliance_conclusions_written": False,
            "control_implementation_mutated": False,
            "certification_performed": False,
            "live_provider_acceptance_verified": False,
        }

    @router.post("/scheduler/run-once")
    async def run_scheduler_once(request: Request):
        """Run one bounded supervisor cycle using server-installed authority."""

        require_global_permission(request, "admin")
        scheduler = getattr(
            request.app.state,
            "trc_continuous_evidence_scheduler",
            None,
        )
        run_once = getattr(scheduler, "run_once", None)
        if not callable(run_once):
            raise HTTPException(
                status_code=503,
                detail="continuous-evidence scheduler is unavailable",
            )
        try:
            cycle = await run_in_threadpool(run_once)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            if "already_running" in str(exc):
                raise HTTPException(
                    status_code=409,
                    detail="continuous-evidence scheduler cycle is already running",
                ) from exc
            raise HTTPException(
                status_code=503,
                detail="continuous-evidence scheduler cycle failed",
            ) from exc
        return {
            "schema": "lightwork.trc-continuous-evidence-manual-cycle.v1",
            "executed": cycle is not None,
            "cycle": _jsonable(cycle) if cycle is not None else None,
            "provider_acceptance_claimed": False,
            "estate_completeness_claimed": False,
        }

    @router.put("/definitions/{definition_id}/versions/{version}")
    async def register_definition(
        request: Request,
        definition_id: ObjectPath,
        version: Annotated[int, ApiPath(ge=1, le=2**31 - 1)],
        body: DefinitionIn,
    ):
        require_global_permission(request, "admin")
        if body.collector_id not in _collector_ids(request):
            raise HTTPException(
                status_code=403,
                detail="collector is not enabled for this tenant",
            )
        evidence, store = authority(request)
        return _jsonable(
            await call(
                evidence,
                store.register_definition,
                definition_id=definition_id,
                version=version,
                **body.model_dump(),
            )
        )

    @router.get("/definitions")
    async def list_definitions(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "view")
        evidence, store = authority(request)
        items = await call(evidence, store.list_definitions, limit=limit)
        return {"items": _jsonable(items), "count": len(items)}

    @router.get("/definitions/{definition_id}/versions/{version}")
    async def get_definition(
        request: Request,
        definition_id: ObjectPath,
        version: Annotated[int, ApiPath(ge=1, le=2**31 - 1)],
    ):
        require_permission(request, "view")
        evidence, store = authority(request)
        return _jsonable(await call(evidence, store.get_definition, definition_id, version))

    @router.post("/definitions/{definition_id}/versions/{version}/approve")
    async def approve_definition(
        request: Request,
        definition_id: ObjectPath,
        version: Annotated[int, ApiPath(ge=1, le=2**31 - 1)],
        body: IntegrityIn,
    ):
        require_global_permission(request, "admin")
        evidence, store = authority(request)
        definition = await call(evidence, store.get_definition, definition_id, version)
        if definition.collector_id not in _collector_ids(request):
            raise HTTPException(
                status_code=403,
                detail="collector is not enabled for this tenant",
            )
        from .trc_setup_api import managed_definition_guard

        return _jsonable(
            await call(
                evidence,
                store.approve_definition,
                definition_id,
                version,
                **body.model_dump(),
                before_effect=managed_definition_guard(request, definition),
            )
        )

    @router.post("/definitions/{definition_id}/versions/{version}/retire")
    async def retire_definition(
        request: Request,
        definition_id: ObjectPath,
        version: Annotated[int, ApiPath(ge=1, le=2**31 - 1)],
        body: IntegrityIn,
    ):
        require_global_permission(request, "admin")
        evidence, store = authority(request)
        return _jsonable(
            await call(
                evidence,
                store.retire_definition,
                definition_id,
                version,
                **body.model_dump(),
            )
        )

    @router.put("/enrollments/{enrollment_id}")
    async def enroll(
        request: Request,
        enrollment_id: ObjectPath,
        body: EnrollmentIn,
    ):
        require_global_permission(request, "admin")
        evidence, store = authority(request)
        definition = await call(
            evidence,
            store.get_definition,
            body.definition_id,
            body.definition_version,
        )
        if definition.collector_id not in _collector_ids(request):
            raise HTTPException(
                status_code=403,
                detail="collector is not enabled for this tenant",
            )
        from .trc_setup_api import managed_definition_guard

        return _jsonable(
            await call(
                evidence,
                store.enroll,
                enrollment_id=enrollment_id,
                **body.model_dump(),
                before_effect=managed_definition_guard(request, definition),
            )
        )

    @router.get("/enrollments")
    async def list_enrollments(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "view")
        evidence, store = authority(request)
        items = await call(evidence, store.list_enrollments, limit=limit)
        return {"items": _jsonable(items), "count": len(items)}

    @router.get("/enrollments/{enrollment_id}")
    async def get_enrollment(request: Request, enrollment_id: ObjectPath):
        require_permission(request, "view")
        evidence, store = authority(request)
        return _jsonable(await call(evidence, store.get_enrollment, enrollment_id))

    @router.post("/enrollments/{enrollment_id}/state")
    async def update_enrollment_state(
        request: Request,
        enrollment_id: ObjectPath,
        body: EnrollmentStateIn,
    ):
        require_global_permission(request, "admin")
        evidence, store = authority(request)
        guard = None
        if body.state == "active":
            from .trc_setup_api import managed_definition_guard

            enrollment = await call(evidence, store.get_enrollment, enrollment_id)
            definition = await call(evidence, store.get_definition, enrollment.definition_id, enrollment.definition_version)
            guard = managed_definition_guard(request, definition)
        return _jsonable(
            await call(
                evidence,
                store.update_enrollment_state,
                enrollment_id,
                **body.model_dump(),
                before_effect=guard,
            )
        )

    @router.post("/jobs/enqueue-due")
    async def enqueue_due(request: Request, body: EnqueueIn):
        require_global_permission(request, "admin")
        evidence, store = authority(request)
        items = await call(evidence, store.enqueue_due, **body.model_dump())
        return {"items": _jsonable(items), "count": len(items)}

    @router.get("/jobs")
    async def list_jobs(
        request: Request,
        state: JobState | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "view")
        evidence, store = authority(request)
        items = await call(evidence, store.list_jobs, state=state, limit=limit)
        return {"items": _jsonable(items), "count": len(items)}

    @router.post("/jobs/{job_id}/requeue")
    async def requeue_job(request: Request, job_id: ObjectPath, body: RequeueIn):
        require_global_permission(request, "admin")
        evidence, store = authority(request)
        return _jsonable(
            await call(
                evidence,
                store.requeue_dead_letter,
                job_id,
                **body.model_dump(),
            )
        )

    @router.get("/runs")
    async def list_runs(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "view")
        evidence, store = authority(request)
        items = await call(evidence, store.list_runs, limit=limit)
        return {"items": _jsonable(items), "count": len(items)}

    @router.get("/observations")
    async def list_observations(
        request: Request,
        enrollment_id: OpaqueId | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "view")
        evidence, store = authority(request)
        items = await call(
            evidence,
            store.list_observations,
            enrollment_id=enrollment_id,
            limit=limit,
        )
        return {"items": _jsonable(items), "count": len(items)}

    @router.get("/alerts")
    async def list_alerts(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "view")
        evidence, store = authority(request)
        items = await call(evidence, store.list_alerts, limit=limit)
        return {"items": _jsonable(items), "count": len(items)}

    @router.get("/integrity")
    async def integrity(request: Request):
        require_global_permission(request, "audit")
        evidence, store = authority(request)
        result = _jsonable(await call(evidence, store.verify_integrity))
        result["valid"] = True
        return result

    @router.post("/retention/purge")
    async def purge_expired(request: Request, body: PurgeIn):
        require_global_permission(request, "admin")
        evidence, store = authority(request)
        return _jsonable(await call(evidence, store.purge_expired, **body.model_dump()))

    return router


router = create_trc_continuous_evidence_router()

__all__ = [
    "TrcContinuousEvidenceDependencies",
    "create_trc_continuous_evidence_router",
    "router",
    "trc_continuous_evidence_enabled_for_page",
]
