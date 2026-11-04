"""Strict tenant-bound adapter for provider-neutral privacy-rights orchestration.

Raw subject and external-request references cross this boundary only while a
case is opened.  The core immediately replaces them with tenant-keyed HMACs;
the adapter never returns those raw values.  Callback records represent worker
intent only and no endpoint performs provider I/O or response delivery.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_CREDENTIAL_REF_PATTERN = r"^(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$"
_ERROR_PATTERN = r"^[a-z][a-z0-9_]{0,47}$"
_PHASE_PATTERN = r"^(?:discover|retrieve|redact|delete|verify_delete|rectify|restrict|opt_out)$"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]
PhasePath = Annotated[
    str,
    ApiPath(min_length=1, max_length=32, pattern=_PHASE_PATTERN),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN),
]
LeaseToken = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST_PATTERN),
]
CredentialRef = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=5,
        max_length=128,
        pattern=_CREDENTIAL_REF_PATTERN,
    ),
]
ErrorCode = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=48, pattern=_ERROR_PATTERN),
]
RawReference = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=1_024),
]
Right = Literal[
    "access",
    "portability",
    "erasure",
    "rectification",
    "restriction",
    "objection",
    "opt_out",
]
TaskPhase = Literal[
    "discover",
    "retrieve",
    "redact",
    "delete",
    "verify_delete",
    "rectify",
    "restrict",
    "opt_out",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SourceEnrollmentIn(_StrictModel):
    adapter_ref: OpaqueId
    credential_ref: CredentialRef
    capabilities: list[TaskPhase] = Field(min_length=1, max_length=8)
    expected_revision: int = Field(ge=0, le=1_000_000)
    idempotency_key: IdempotencyKey


class CaseOpenIn(_StrictModel):
    request_version: int = Field(ge=1, le=1_000_000)
    external_request_ref: RawReference
    subject_reference: RawReference
    rights: list[Right] = Field(min_length=1, max_length=7)
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class RevisionIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class IdentityVerificationIn(RevisionIn):
    status: Literal["unverified", "pending", "verified", "rejected", "expired"]
    evidence_sha256: Digest | None = None
    evidence_ref: OpaqueId | None = None


class LegalHoldIn(RevisionIn):
    active: bool
    evidence_sha256: Digest
    evidence_ref: OpaqueId


class RetentionGateIn(RevisionIn):
    blocks_deletion: bool
    rule_ref: OpaqueId
    evidence_sha256: Digest


class PlanTasksIn(_StrictModel):
    phases: list[TaskPhase] | None = Field(default=None, min_length=1, max_length=8)
    max_attempts: int = Field(default=3, ge=1, le=20)
    expected_case_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class ClaimCallbacksIn(_StrictModel):
    limit: int = Field(default=10, ge=1, le=100)
    lease_seconds: int = Field(default=60, ge=1, le=3_600)
    idempotency_key: IdempotencyKey


class SourceWorkerRunIn(_StrictModel):
    run_id: IdempotencyKey
    # Omitted values are supplied by the tenant's server-owned source-adapter
    # configuration. Explicit values may only narrow those deployment caps.
    limit: int | None = Field(default=None, ge=1, le=100)
    lease_seconds: int | None = Field(default=None, ge=1, le=3_600)
    retry_delay_seconds: int | None = Field(default=None, ge=0, le=604_800)


class SourceReconciliationRunIn(_StrictModel):
    run_id: IdempotencyKey
    limit: int | None = Field(default=None, ge=1, le=100)
    retry_delay_seconds: int | None = Field(default=None, ge=0, le=604_800)


class FailCallbackIn(RevisionIn):
    lease_token: LeaseToken
    error_code: ErrorCode
    retry_delay_seconds: int = Field(ge=0, le=604_800)


class AckCallbackIn(RevisionIn):
    lease_token: LeaseToken
    acknowledgement_sha256: Digest
    acknowledgement_ref: OpaqueId


class SourceEvidenceIn(_StrictModel):
    manual_attestation: Literal[True]
    status: Literal["complete", "not_found", "partial", "failed"]
    provider_evidence_sha256: Digest
    record_count: int = Field(ge=0, le=1_000_000_000)
    opaque_ref: OpaqueId
    expected_task_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class ManifestIn(_StrictModel):
    expected_case_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class ResponsePackageIn(_StrictModel):
    object_ref: OpaqueId
    package_sha256: Digest
    encryption_key_ref: CredentialRef
    expires_at: float | int = Field(gt=0, lt=100_000_000_000.0)
    expected_case_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class ExportIn(_StrictModel):
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class PurgeIn(_StrictModel):
    cutoff: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


def _enabled() -> bool:
    from maverick import privacy_rights_orchestration as ops

    return ops.enabled()


def privacy_rights_orchestration_enabled_for_page() -> bool:
    """Read only the exact feature gate without opening tenant storage."""

    return _enabled()


def _ops():
    from maverick import privacy_rights_orchestration as ops

    try:
        ops.require_enabled()
    except ops.PrivacyRightsConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return ops


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using privacy-rights orchestration",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request,
        error_detail="an authenticated principal is required for privacy-rights orchestration",
    )
    digest = hashlib.sha256(
        (f"lightwork.privacy-rights.identity.v1:{tenant_id}:{subject}").encode()
    ).hexdigest()
    return f"pro-principal-{digest[:32]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _without_lease(value: Any) -> dict[str, Any]:
    result = _jsonable(value)
    result.pop("lease_token", None)
    return result


def _default_store_for(tenant_id: str, principal_ref: str):
    from maverick.paths import data_dir
    from maverick.privacy_rights_orchestration import (
        PrivacyRightsOrchestrationStore,
    )

    return PrivacyRightsOrchestrationStore(
        data_dir(
            "privacy_automation",
            "privacy-rights-orchestration.sqlite3",
            tenant=tenant_id,
        ),
        principal_resolver=lambda: principal_ref,
    )


class PrivacyRightsOrchestrationDependencies:
    """Explicit tenant/principal-bound store seam for runtimes and tests."""

    def __init__(
        self,
        *,
        store_for: Callable[[str, str], Any] = _default_store_for,
    ) -> None:
        self.store_for = store_for


def create_privacy_rights_orchestration_router(  # noqa: C901, PLR0915
    dependencies: PrivacyRightsOrchestrationDependencies | None = None,
) -> APIRouter:
    deps = dependencies or PrivacyRightsOrchestrationDependencies()
    router = APIRouter(
        prefix="/privacy/rights-orchestration",
        tags=["privacy-rights-orchestration"],
    )

    def authority(request: Request):
        ops = _ops()
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        factory = getattr(request.app.state, "privacy_rights_orchestration_store_factory", None)

        def resolver() -> str:
            return principal

        try:
            store = (
                factory(
                    tenant_id=tenant,
                    principal_ref=principal,
                    principal_resolver=resolver,
                    request=request,
                )
                if callable(factory)
                else deps.store_for(tenant, principal)
            )
        except ops.PrivacyRightsConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (ops.PrivacyRightsOrchestrationError, OSError) as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights orchestration store is unavailable",
            ) from exc
        if store is None:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights orchestration store is unavailable",
            )
        return ops, tenant, store

    async def call(ops, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.PrivacyRightsNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ops.PrivacyRightsPermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ops.PrivacyRightsConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ops.PrivacyRightsValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ops.PrivacyRightsConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ops.PrivacyRightsIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights integrity verification failed",
            ) from exc
        except ops.PrivacyRightsOrchestrationError as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights orchestration operation failed",
            ) from exc

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        from maverick.privacy_rights_orchestration import (
            PrivacyRightsOrchestrationStore,
        )

        probe = getattr(
            request.app.state,
            "privacy_rights_source_readiness_probe",
            None,
        )
        try:
            source_runtime = (
                await run_in_threadpool(probe, tenant)
                if callable(probe)
                else {
                    "schema": "lightwork.privacy-rights-source-readiness.v1",
                    "tenant_id": tenant,
                    "enabled": False,
                    "configured": False,
                    "ready": False,
                    "status_probe_opened_store": False,
                    "status_probe_invoked_provider": False,
                    "status_probe_resolved_secret": False,
                    "live_provider_acceptance_verified": False,
                }
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            source_runtime = {
                "schema": "lightwork.privacy-rights-source-readiness.v1",
                "tenant_id": tenant,
                "enabled": False,
                "configured": False,
                "ready": False,
                "status_probe_opened_store": False,
                "status_probe_invoked_provider": False,
                "status_probe_resolved_secret": False,
                "live_provider_acceptance_verified": False,
            }
        store_boundaries = dict(
            PrivacyRightsOrchestrationStore.product_boundaries()
        )
        return {
            "schema": "lightwork.privacy-rights-orchestration-status.v1",
            "enabled": _enabled(),
            "principal_ref": principal,
            "store_capabilities": store_boundaries,
            "network_io": bool(source_runtime.get("configured")),
            "provider_writes": bool(
                source_runtime.get("provider_writes_possible")
            ),
            "identity_verification_performed": False,
            "response_delivery_performed": False,
            "raw_subject_persisted": False,
            "raw_external_request_ref_persisted": False,
            "credential_values_persisted": False,
            "provider_origins_persisted": False,
            "estate_completeness_claimed": False,
            "live_provider_acceptance_verified": False,
            "live_customer_acceptance_verified": False,
            "callback_transport_worker_implemented": True,
            "stock_provider_contracts": [
                "google_workspace_users",
                "microsoft_graph_users",
                "salesforce_contacts",
                "servicenow_users",
            ],
            "source_runtime": source_runtime,
            "callbacks_are_worker_intent_only": False,
            "callbacks_require_source_runtime_readiness": True,
            "status_request_external_network_io": False,
            "status_request_opened_store": False,
            "status_request_resolved_secret": False,
            "case_open_raw_references_hmac_only": True,
            "claim_is_only_live_lease_token_response": True,
        }

    def source_worker(request: Request, tenant: str, principal: str):
        factory = getattr(
            request.app.state,
            "privacy_rights_source_worker_factory",
            None,
        )
        if not callable(factory):
            raise HTTPException(
                status_code=503,
                detail="privacy-rights source worker is unavailable",
            )
        try:
            selected = factory(
                tenant_id=tenant,
                principal_ref=principal,
                request=request,
            )
            from maverick.privacy_rights_source_worker import (
                PrivacyRightsSourceWorker,
            )

            if not isinstance(selected, PrivacyRightsSourceWorker):
                raise TypeError("source worker factory returned an invalid worker")
            return selected
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights source worker is unavailable",
            ) from exc

    @router.put("/sources/{source_id}")
    async def enroll_source(request: Request, source_id: ObjectPath, body: SourceEnrollmentIn):
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(ops, store.enroll_source, tenant, source_id, **body.model_dump())
        )

    @router.get("/sources/{source_id}")
    async def get_source(request: Request, source_id: ObjectPath):
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_source, tenant, source_id))

    @router.get("/sources")
    async def list_sources(request: Request, limit: int = Query(default=100, ge=1, le=1_000)):
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        items = await call(ops, store.list_sources, tenant, limit=limit)
        return {"items": _jsonable(items), "count": len(items)}

    @router.put(
        "/cases/{case_id}",
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": CaseOpenIn.model_json_schema()}},
            }
        },
    )
    async def open_case(request: Request, case_id: ObjectPath):
        require_permission(request, "operate")
        try:
            body = CaseOpenIn.model_validate(await request.json())
        except (ValidationError, ValueError, UnicodeError) as exc:
            raise HTTPException(status_code=422, detail="case-open body is invalid") from exc
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.open_case, tenant, case_id, **body.model_dump()))

    @router.get("/cases")
    async def list_cases(request: Request, limit: int = Query(default=200, ge=1, le=1_000)):
        """Rights requests in this workspace, newest first (no raw references)."""

        require_permission(request, "view")
        ops, tenant, store = authority(request)
        items = await call(ops, store.list_cases, tenant, limit=limit)
        return {"items": _jsonable(items), "count": len(items)}

    @router.get("/cases/{case_id}/work")
    async def case_work(request: Request, case_id: ObjectPath):
        """One request's source tasks, evidence, completeness checks,
        response packages and exports."""

        require_permission(request, "view")
        ops, tenant, store = authority(request)
        work = await call(ops, store.case_work, tenant, case_id)
        return {key: _jsonable(value) for key, value in work.items()}

    @router.get("/cases/{case_id}")
    async def get_case(request: Request, case_id: ObjectPath):
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_case, tenant, case_id))

    @router.post("/cases/{case_id}/identity-verification")
    async def set_identity_verification(
        request: Request, case_id: ObjectPath, body: IdentityVerificationIn
    ):
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.set_identity_verification,
                tenant,
                case_id,
                **body.model_dump(),
            )
        )

    @router.post("/cases/{case_id}/legal-hold")
    async def set_legal_hold(request: Request, case_id: ObjectPath, body: LegalHoldIn):
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(ops, store.set_legal_hold, tenant, case_id, **body.model_dump())
        )

    @router.post("/cases/{case_id}/retention-gate")
    async def set_retention_gate(request: Request, case_id: ObjectPath, body: RetentionGateIn):
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(ops, store.set_retention_gate, tenant, case_id, **body.model_dump())
        )

    @router.post("/cases/{case_id}/sources/{source_id}/plan")
    async def plan_source_tasks(
        request: Request,
        case_id: ObjectPath,
        source_id: ObjectPath,
        body: PlanTasksIn,
    ):
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        items = await call(
            ops,
            store.plan_source_tasks,
            tenant,
            case_id,
            source_id,
            **body.model_dump(),
        )
        return {"items": _jsonable(items), "count": len(items)}

    @router.post("/tasks/{task_id}/approve-destructive")
    async def approve_destructive_work(request: Request, task_id: ObjectPath, body: RevisionIn):
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.approve_destructive_work,
                tenant,
                task_id,
                **body.model_dump(),
            )
        )

    @router.post("/callbacks/claim")
    async def claim_callbacks(request: Request, body: ClaimCallbacksIn):
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        items = await call(ops, store.claim_callbacks, tenant, **body.model_dump())
        return {"items": _jsonable(items), "count": len(items)}

    @router.get("/callbacks")
    async def list_callbacks(
        request: Request,
        state: Literal[
            "pending", "leased", "acked", "ambiguous", "dead_letter"
        ]
        | None = None,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_global_permission(request, "audit")
        ops, tenant, store = authority(request)
        items = await call(
            ops,
            store.list_callbacks,
            tenant,
            state=state,
            limit=limit,
        )
        return {
            "items": [_without_lease(item) for item in items],
            "count": len(items),
        }

    @router.post("/source-runtime/run")
    async def run_source_worker(request: Request, body: SourceWorkerRunIn):
        require_global_permission(request, "admin")
        _ops()
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        selected = source_worker(request, tenant, principal)
        try:
            result = await run_in_threadpool(
                selected.run_once,
                tenant,
                worker_ref=principal,
                **body.model_dump(),
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights source worker run failed",
            ) from exc
        return _jsonable(result)

    @router.post("/source-runtime/reconcile")
    async def reconcile_source_worker(
        request: Request,
        body: SourceReconciliationRunIn,
    ):
        require_global_permission(request, "admin")
        _ops()
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        selected = source_worker(request, tenant, principal)
        try:
            result = await run_in_threadpool(
                selected.reconcile_once,
                tenant,
                worker_ref=principal,
                **body.model_dump(),
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights source reconciliation failed",
            ) from exc
        return _jsonable(result)

    @router.post("/callbacks/{callback_id}/fail")
    async def fail_callback(request: Request, callback_id: ObjectPath, body: FailCallbackIn):
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _without_lease(
            await call(ops, store.fail_callback, tenant, callback_id, **body.model_dump())
        )

    @router.post("/callbacks/{callback_id}/acknowledge")
    async def ack_callback(request: Request, callback_id: ObjectPath, body: AckCallbackIn):
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _without_lease(
            await call(ops, store.ack_callback, tenant, callback_id, **body.model_dump())
        )

    @router.post("/callbacks/{callback_id}/requeue")
    async def requeue_callback(request: Request, callback_id: ObjectPath, body: RevisionIn):
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _without_lease(
            await call(ops, store.requeue_callback, tenant, callback_id, **body.model_dump())
        )

    @router.put("/cases/{case_id}/sources/{source_id}/phases/{phase}/evidence/{evidence_id}")
    async def record_source_evidence(
        request: Request,
        case_id: ObjectPath,
        source_id: ObjectPath,
        phase: PhasePath,
        evidence_id: ObjectPath,
        body: SourceEvidenceIn,
    ):
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.record_source_evidence,
                tenant,
                case_id,
                source_id,
                phase,
                evidence_id=evidence_id,
                **body.model_dump(exclude={"manual_attestation"}),
            )
        )

    @router.put("/cases/{case_id}/manifests/{manifest_id}")
    async def build_manifest(
        request: Request,
        case_id: ObjectPath,
        manifest_id: ObjectPath,
        body: ManifestIn,
    ):
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.build_completeness_manifest,
                tenant,
                case_id,
                manifest_id,
                **body.model_dump(),
            )
        )

    @router.put("/cases/{case_id}/packages/{package_id}")
    async def create_package(
        request: Request,
        case_id: ObjectPath,
        package_id: ObjectPath,
        body: ResponsePackageIn,
    ):
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.create_response_package,
                tenant,
                case_id,
                package_id,
                **body.model_dump(),
            )
        )

    @router.get("/packages/{package_id}")
    async def get_package(request: Request, package_id: ObjectPath):
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_response_package, tenant, package_id))

    @router.post("/cases/{case_id}/closure/approve")
    async def approve_closure(request: Request, case_id: ObjectPath, body: RevisionIn):
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.approve_case_closure,
                tenant,
                case_id,
                **body.model_dump(),
            )
        )

    @router.post("/cases/{case_id}/close")
    async def close_case(request: Request, case_id: ObjectPath, body: RevisionIn):
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.close_case, tenant, case_id, **body.model_dump()))

    @router.put("/cases/{case_id}/exports/{export_id}")
    async def export_case(
        request: Request, case_id: ObjectPath, export_id: ObjectPath, body: ExportIn
    ):
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.export_case,
                tenant,
                case_id,
                export_id,
                **body.model_dump(),
            )
        )

    @router.post("/retention/purge")
    async def purge(request: Request, body: PurgeIn):
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.purge_expired, tenant, **body.model_dump()))

    @router.get("/integrity")
    async def integrity(request: Request):
        require_global_permission(request, "audit")
        ops, tenant, store = authority(request)
        result = _jsonable(await call(ops, store.verify_integrity, tenant))
        result["valid"] = True
        return result

    return router


router = create_privacy_rights_orchestration_router()

__all__ = [
    "PrivacyRightsOrchestrationDependencies",
    "create_privacy_rights_orchestration_router",
    "privacy_rights_orchestration_enabled_for_page",
    "router",
]
