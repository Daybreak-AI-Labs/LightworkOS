"""Strict administrative API for tenant-scoped consent bulk jobs.

No route accepts a tenant, actor, principal, worker identity, database path,
executor, provider, or recovery path.  Read operations require tenant access
and global audit authority; all state changes require global administration.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as ApiPath
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    StringConstraints,
    model_validator,
)
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDEMPOTENCY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
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
    StringConstraints(
        strict=True,
        min_length=8,
        max_length=192,
        pattern=_IDEMPOTENCY_PATTERN,
    ),
]
Digest = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=64,
        max_length=64,
        pattern=_DIGEST_PATTERN,
    ),
]
JobState = Literal["queued", "running", "succeeded", "failed", "cancelled"]
ActionOperation = Literal[
    "edit_preferences",
    "delete_subject",
    "change_identifier_type",
    "reactivate",
    "clear_expiration",
]

_SECURE_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}
_REQUIRED_RUNTIME_METHODS = ("operation_capabilities", "run_job", "run_next")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ConsentContextIn(_StrictModel):
    jurisdiction: OpaqueId
    country_code: str = Field(strict=True, pattern=r"^[A-Z]{2}$")
    region_code: str = Field(default="", strict=True, max_length=26)
    collection_point: OpaqueId = "web"
    asserted_source: Literal["client", "edge", "operator", "sdk", "header"] = (
        "operator"
    )


class PreferenceChoiceIn(_StrictModel):
    purpose_id: OpaqueId
    action: Literal["grant", "deny", "revoke", "withdraw"]
    channel: OpaqueId = "all"
    vendor_id: OpaqueId = "all"
    expires_at: StrictFloat | None = Field(default=None, gt=0)


class ExportItemIn(_StrictModel):
    item_id: OpaqueId
    profile_id: OpaqueId
    receipt_limit: StrictInt = Field(default=100, ge=1, le=500)


class CreateExportJobIn(_StrictModel):
    items: list[ExportItemIn] = Field(min_length=1, max_length=100_000)
    scheduled_for: StrictFloat | None = Field(default=None, gt=0)
    idempotency_key: IdempotencyKey


class CheckSubmissionIn(_StrictModel):
    idempotency_key: IdempotencyKey


class ActionItemIn(_StrictModel):
    item_id: OpaqueId
    profile_id: OpaqueId
    expected_revision: StrictInt | None = Field(
        default=None,
        ge=0,
        le=2**31 - 1,
    )
    policy_id: OpaqueId | None = None
    policy_version: StrictInt | None = Field(default=None, ge=1, le=2**31 - 1)
    context: ConsentContextIn | None = None
    choices: list[PreferenceChoiceIn] | None = Field(
        default=None,
        min_length=1,
        max_length=128,
    )
    retention_until: StrictFloat | None = Field(default=None, gt=0)
    reason_code: OpaqueId | None = None
    identity_kind: Literal["known", "anonymous"] | None = None
    subject_sha256: Digest | None = None
    reactivation_at: StrictFloat | None = Field(default=None, gt=0)
    receipt_id: OpaqueId | None = None


class CreateActionJobIn(_StrictModel):
    operation: ActionOperation
    items: list[ActionItemIn] = Field(min_length=1, max_length=100_000)
    scheduled_for: StrictFloat | None = Field(default=None, gt=0)
    idempotency_key: IdempotencyKey

    @model_validator(mode="after")
    def validate_items_for_operation(self) -> CreateActionJobIn:
        common = {"item_id", "profile_id"}
        contracts: dict[str, tuple[set[str], set[str]]] = {
            "edit_preferences": (
                common
                | {
                    "expected_revision",
                    "policy_id",
                    "policy_version",
                    "context",
                    "choices",
                },
                {"retention_until"},
            ),
            "reactivate": (
                common
                | {
                    "expected_revision",
                    "receipt_id",
                    "reactivation_at",
                },
                set(),
            ),
            "delete_subject": (
                common | {"expected_revision", "reason_code"},
                set(),
            ),
            "change_identifier_type": (
                common
                | {"expected_revision", "identity_kind", "subject_sha256"},
                set(),
            ),
            "clear_expiration": (
                common | {"expected_revision", "receipt_id"},
                set(),
            ),
        }
        required, optional = contracts[self.operation]
        for item in self.items:
            supplied = item.model_fields_set
            if required - supplied or supplied - required - optional:
                raise ValueError("action item shape does not match operation")
            if any(getattr(item, name) is None for name in required):
                raise ValueError("action item has a missing operation field")
        return self


class RevisionIn(_StrictModel):
    expected_revision: StrictInt = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class GrantCreditsIn(_StrictModel):
    amount: StrictInt = Field(ge=1, le=1_000_000_000)
    expected_revision: StrictInt = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class WorkerControlIn(_StrictModel):
    pass


class JobPartIn(_StrictModel):
    expected_revision: StrictInt | None = Field(default=None, ge=1, le=2**31 - 1)


@dataclass(frozen=True)
class ConsentJobState:
    job: dict
    part_limit: int
    now: float


@dataclass(frozen=True)
class ConsentJobControls:
    """The native authorized job controls, shared with typed Copilot actions."""

    state: Callable
    run_part: Callable
    cancel_future: Callable
    download_result: Callable
    creation_state: Callable
    submit: Callable
    check_submission: Callable
    credit_detail: Callable
    grant_allowance: Callable
    check_allowance: Callable


class RecoveryIn(_StrictModel):
    limit: StrictInt = Field(default=100, ge=1, le=500)


class RetentionPurgeIn(_StrictModel):
    before: StrictFloat | None = Field(default=None, gt=0)
    limit: StrictInt = Field(default=100, ge=1, le=500)


class ConsentBulkJobsDependencies:
    """Explicit seams used by the lazy production composition and tests."""

    def __init__(
        self,
        *,
        runtime_factory: Callable[..., Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[[str], Mapping[str, Any]] | None = None,
    ) -> None:
        for dependency in (runtime_factory, enabled_probe, readiness_probe):
            if dependency is not None and not callable(dependency):
                raise TypeError("consent bulk-job dependency must be callable")
        self.runtime_factory = runtime_factory
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe


def _ops():
    from maverick import consent_bulk_jobs

    return consent_bulk_jobs


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using consent bulk jobs",
        )
    return tenant


def _principal_ref(request: Request, tenant_id: str) -> str:
    from .consent_bulk_jobs_composition import (
        ConsentBulkJobsCompositionError,
        expected_principal_ref,
    )

    try:
        return expected_principal_ref(request, tenant_id)
    except ConsentBulkJobsCompositionError as exc:
        raise HTTPException(
            status_code=401,
            detail="an authenticated principal is required for consent bulk jobs",
        ) from exc


def _dependency(request: Request, name: str, fallback: object) -> object:
    try:
        return getattr(request.app.state, name)
    except AttributeError:
        return fallback


def _secure(response: Response) -> None:
    for name, value in _SECURE_HEADERS.items():
        response.headers[name] = value


def _public_readiness(value: Mapping[str, Any]) -> dict[str, Any]:
    operations = value.get("operations", {})
    if not isinstance(operations, Mapping):
        operations = {}
    operation_names = (
        "export_receipts",
        "edit_preferences",
        "delete_subject",
        "change_identifier_type",
        "reactivate",
        "clear_expiration",
    )
    return {
        "enabled": value.get("enabled") is True,
        "configured": value.get("configured") is True,
        "ready": value.get("ready") is True,
        "operations": {name: operations.get(name) is True for name in operation_names},
        "status_probe_opened_store": value.get("status_probe_opened_store") is True,
        "status_probe_seeded_credits": value.get("status_probe_seeded_credits") is True,
        "status_probe_invoked_provider": value.get("status_probe_invoked_provider")
        is True,
    }


def create_consent_bulk_jobs_router(  # noqa: C901, PLR0915
    dependencies: ConsentBulkJobsDependencies | None = None,
) -> APIRouter:
    deps = dependencies or ConsentBulkJobsDependencies()
    router = APIRouter(prefix="/consent/bulk-jobs", tags=["consent-bulk-jobs"])

    def probes(request: Request, tenant: str) -> dict[str, Any]:
        enabled_probe = _dependency(
            request,
            "consent_bulk_jobs_enabled_probe",
            deps.enabled_probe,
        )
        readiness_probe = _dependency(
            request,
            "consent_bulk_jobs_readiness_probe",
            deps.readiness_probe,
        )
        runtime_factory = _dependency(
            request,
            "consent_bulk_jobs_runtime_factory",
            deps.runtime_factory,
        )
        try:
            enabled = enabled_probe(tenant) if callable(enabled_probe) else False
            raw = readiness_probe(tenant) if callable(readiness_probe) else {}
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="consent bulk-job readiness is unavailable",
            ) from exc
        if type(enabled) is not bool or not isinstance(raw, Mapping):
            raise HTTPException(
                status_code=503,
                detail="consent bulk-job readiness is unavailable",
            )
        readiness = _public_readiness(raw)
        readiness["enabled"] = enabled and readiness["enabled"]
        readiness["configured"] = (
            readiness["configured"] and callable(runtime_factory)
        )
        readiness["ready"] = (
            readiness["enabled"]
            and readiness["configured"]
            and readiness["ready"]
        )
        return readiness

    def composition_state(request: Request):
        from .consent_bulk_jobs_composition import ConsentBulkJobsRuntime

        tenant = _tenant_id()
        readiness = probes(request, tenant)
        if not readiness["enabled"]:
            raise HTTPException(status_code=403, detail="consent bulk jobs are disabled")
        if not readiness["ready"]:
            raise HTTPException(
                status_code=503,
                detail="consent bulk-job operational readiness is not verified",
            )
        principal = _principal_ref(request, tenant)
        factory = _dependency(
            request,
            "consent_bulk_jobs_runtime_factory",
            deps.runtime_factory,
        )
        try:
            runtime = factory(  # type: ignore[operator]
                tenant_id=tenant,
                principal_ref=principal,
                request=request,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="consent bulk-job runtime is unavailable",
            ) from exc
        if (
            type(runtime) is not ConsentBulkJobsRuntime
            or runtime.tenant_id != tenant
            or runtime.principal_ref != principal
            or not all(
                callable(getattr(runtime, name, None))
                for name in _REQUIRED_RUNTIME_METHODS
            )
            or type(runtime.store) is not _ops().ConsentBulkJobStore
        ):
            raise HTTPException(
                status_code=503,
                detail="consent bulk-job runtime is unavailable",
            )
        return _ops(), tenant, runtime

    async def composition(request: Request):
        return await run_in_threadpool(composition_state, request)

    def call_state(ops, function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ops.ConsentBulkJobNotFound as exc:
            raise HTTPException(status_code=404, detail="consent bulk job was not found") from exc
        except ops.ConsentBulkJobConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="consent bulk-job state or revision changed",
            ) from exc
        except ops.ConsentBulkJobValidationError as exc:
            message = str(exc)
            detail = "consent bulk-job request is invalid"
            if message == "receipt_limit is outside its bound":
                detail = "Choose between 1 and 500 records per person."
            elif message == (
                "Receipt exports from a saved position are not supported. "
                "Select up to the latest 500 records per person."
            ):
                detail = "Starting from a saved position is not available. Choose up to the latest 500 records per person."
            raise HTTPException(
                status_code=422,
                detail=detail,
            ) from exc
        except ops.ConsentBulkJobError as exc:
            raise HTTPException(
                status_code=503,
                detail="consent bulk-job authority is unavailable",
            ) from exc
        except (OSError, RuntimeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="consent bulk-job operation failed",
            ) from exc

    async def call(ops, function, *args, **kwargs):
        return await run_in_threadpool(call_state, ops, function, *args, **kwargs)

    def require_audit(request: Request) -> None:
        from .consent_job_admission import context

        context(request)
        require_permission(request, "view")
        require_global_permission(request, "audit")

    def require_admin(request: Request) -> None:
        from .consent_job_admission import context

        context(request)
        require_permission(request, "operate")
        require_global_permission(request, "admin")

    def ensure_operation(runtime: Any, operation: str) -> None:
        capabilities = runtime.operation_capabilities()
        if not isinstance(capabilities, Mapping) or capabilities.get(operation) is not True:
            raise HTTPException(
                status_code=503,
                detail="the requested consent bulk-job executor is unavailable",
            )

    def job_state(request: Request, job_id: str) -> ConsentJobState:
        require_audit(request)
        ops, tenant, runtime = composition_state(request)
        job = call_state(ops, runtime.store.get_job, tenant, job_id)
        return ConsentJobState(job, runtime.worker_batch_size, runtime.clock())

    def run_part(request: Request, job_id: str, expected_revision: int | None = None) -> dict:
        require_admin(request)
        ops, _tenant, runtime = composition_state(request)
        return call_state(ops, runtime.run_job, job_id,
                          **({"expected_revision": expected_revision} if expected_revision is not None else {}))

    def cancel_future(request: Request, job_id: str, body: RevisionIn) -> dict:
        require_admin(request)
        ops, tenant, runtime = composition_state(request)
        return call_state(ops, runtime.store.cancel_job, tenant, job_id,
                          expected_revision=body.expected_revision, idempotency_key=body.idempotency_key)

    def download_result(request: Request, job_id: str) -> dict:
        require_audit(request)
        ops, tenant, runtime = composition_state(request)
        return call_state(ops, runtime.store.download_artifact, tenant, job_id)

    def creation_state(request: Request):
        require_admin(request)
        _ops, _tenant, runtime = composition_state(request)
        return {"operations": runtime.operation_capabilities(), "allowance": runtime.store.credit_detail(runtime.tenant_id)}

    def submitted(request: Request, key: str):
        require_admin(request)
        ops, tenant, runtime = composition_state(request)
        return call_state(ops, runtime.store.created_job_for_request, tenant,
                          idempotency_key=key, actor_sha256=runtime.actor_sha256)

    def submit(request: Request, body, operation: str):
        from maverick.authority_effects import authority_effect_fence

        from .consent_job_admission import reviewed_sources

        with authority_effect_fence():
            require_admin(request)
            ops, tenant, runtime = composition_state(request)
            ensure_operation(runtime, operation)
            items = [item.model_dump(mode="python", exclude_none=True) for item in body.items]
            def admit():
                require_admin(request)
                return call_state(ops, runtime.store.create_job, tenant,
                    kind="export" if operation == "export_receipts" else "mutation", operation=operation,
                    items=items, actor_sha256=runtime.actor_sha256, scheduled_for=body.scheduled_for,
                    idempotency_key=body.idempotency_key)
            # Original admission readback must not revalidate a now-changed
            # profile as a new submission, and native replay still binds payload.
            original = call_state(ops, runtime.store.created_job_for_request, tenant,
                idempotency_key=body.idempotency_key, actor_sha256=runtime.actor_sha256)
            if original is not None or request.headers.get("X-Lightwork-Profile-Context") is None:
                return admit()
            with reviewed_sources(runtime, operation, items):
                return admit()

    def credit_state(request: Request):
        require_audit(request)
        ops, tenant, runtime = composition_state(request)
        return call_state(ops, runtime.store.credit_detail, tenant)

    def grant_allowance(request: Request, body: GrantCreditsIn):
        from maverick.authority_effects import authority_effect_fence

        with authority_effect_fence():
            require_admin(request)
            ops, tenant, runtime = composition_state(request)
            return call_state(ops, runtime.store.grant_credits, tenant, body.amount,
                expected_revision=body.expected_revision, idempotency_key=body.idempotency_key,
                actor_sha256=runtime.actor_sha256)

    def check_allowance(request: Request, key: str):
        require_admin(request)
        ops, tenant, runtime = composition_state(request)
        return call_state(ops, runtime.store.granted_credit_for_request, tenant,
            idempotency_key=key, actor_sha256=runtime.actor_sha256)

    controls = ConsentJobControls(job_state, run_part, cancel_future, download_result,
        creation_state, submit, submitted, credit_state, grant_allowance, check_allowance)
    router.consent_job_controls = controls

    @router.get("/status")
    async def status(request: Request, response: Response) -> dict[str, Any]:
        require_audit(request)
        tenant = _tenant_id()
        readiness = await run_in_threadpool(probes, request, tenant)
        _secure(response)
        return {
            "schema": "lightwork.consent-bulk-jobs-api-status.v1",
            **readiness,
            "configuration": {
                "default_off": True,
                "tenant_scoped": True,
                "principal_scoped": True,
                "private_per_tenant_job_database": True,
                "credits_seeded_once": True,
                "caller_tenant_actor_worker_path_provider_fields_accepted": False,
            },
            "external_provider_invocation_supported": False,
        }

    @router.post("/exports", status_code=201)
    async def create_export(
        request: Request,
        response: Response,
        body: CreateExportJobIn,
    ) -> dict[str, Any]:
        result = await run_in_threadpool(controls.submit, request, body, "export_receipts")
        _secure(response)
        return result

    @router.post("/actions", status_code=201)
    async def create_action(
        request: Request,
        response: Response,
        body: CreateActionJobIn,
    ) -> dict[str, Any]:
        result = await run_in_threadpool(controls.submit, request, body, body.operation)
        _secure(response)
        return result

    @router.post("/requests/check")
    async def check_submission(
        request: Request, response: Response, body: CheckSubmissionIn,
    ) -> dict[str, Any]:
        job = await run_in_threadpool(controls.check_submission, request, body.idempotency_key)
        _secure(response)
        return {"found": job is not None, "job": job}

    @router.get("")
    async def list_jobs(
        request: Request,
        response: Response,
        state: JobState | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
        before_job_id: str | None = Query(default=None, min_length=1, max_length=128, pattern=_ID_PATTERN),
    ) -> dict[str, Any]:
        require_audit(request)
        ops, tenant, runtime = await composition(request)
        result = await call(
            ops,
            runtime.store.list_jobs,
            tenant,
            state=state,
            limit=limit,
            before_job_id=before_job_id,
        )
        _secure(response)
        return result

    @router.get("/{job_id}")
    async def get_job(
        request: Request,
        response: Response,
        job_id: ObjectPath,
    ) -> dict[str, Any]:
        result = (await run_in_threadpool(controls.state, request, job_id)).job
        _secure(response)
        return result

    @router.get("/{job_id}/progress")
    async def progress(
        request: Request,
        response: Response,
        job_id: ObjectPath,
    ) -> dict[str, Any]:
        require_audit(request)
        ops, tenant, runtime = await composition(request)
        job = await call(ops, runtime.store.get_job, tenant, job_id)
        _secure(response)
        return {
            "job_id": job["job_id"],
            "state": job["state"],
            "revision": job["revision"],
            "total_items": job["total_items"],
            "processed_items": job["processed_items"],
            "failed_items": job["failed_items"],
            "progress_percent": job["progress_percent"],
            "cancel_requested": job["cancel_requested"],
        }

    @router.post("/{job_id}/cancel")
    async def cancel_job(
        request: Request,
        response: Response,
        job_id: ObjectPath,
        body: RevisionIn,
    ) -> dict[str, Any]:
        result = await run_in_threadpool(controls.cancel_future, request, job_id, body)
        _secure(response)
        return result

    @router.post("/{job_id}/run")
    async def run_job(
        request: Request,
        response: Response,
        job_id: ObjectPath,
        body: JobPartIn,
    ) -> dict[str, Any]:
        result = await run_in_threadpool(controls.run_part, request, job_id, body.expected_revision)
        _secure(response)
        return result

    @router.post("/worker/run-next")
    async def run_next(
        request: Request,
        response: Response,
        body: WorkerControlIn,
    ) -> dict[str, Any]:
        del body
        require_admin(request)
        ops, _tenant, runtime = await composition(request)
        result = await call(ops, runtime.run_next)
        _secure(response)
        return result

    @router.get("/{job_id}/download")
    async def download(request: Request, job_id: ObjectPath) -> Response:
        artifact = await run_in_threadpool(controls.download_result, request, job_id)
        try:
            encoded = json.dumps(
                artifact,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="consent bulk-job artifact is unavailable",
            ) from exc
        response = Response(
            encoded,
            media_type="application/json",
            headers={
                **_SECURE_HEADERS,
                "Content-Disposition": (
                    f'attachment; filename="consent-receipts-{job_id}.json"'
                ),
            },
        )
        return response

    @router.get("/{job_id}/history")
    async def history(
        request: Request,
        response: Response,
        job_id: ObjectPath,
        limit: int = Query(default=100, ge=1, le=500),
        before_sequence: int | None = Query(default=None, ge=1, le=2**63 - 1),
    ) -> dict[str, Any]:
        require_audit(request)
        ops, tenant, runtime = await composition(request)
        result = await call(
            ops,
            runtime.store.history,
            tenant,
            job_id,
            limit=limit,
            before_sequence=before_sequence,
        )
        _secure(response)
        return result

    @router.get("/credits/detail")
    async def credit_detail(request: Request, response: Response) -> dict[str, Any]:
        result = await run_in_threadpool(controls.credit_detail, request)
        _secure(response)
        return result

    @router.post("/credits/grant")
    async def grant_credits(
        request: Request,
        response: Response,
        body: GrantCreditsIn,
    ) -> dict[str, Any]:
        result = await run_in_threadpool(controls.grant_allowance, request, body)
        _secure(response)
        return result

    @router.post("/credits/check")
    async def check_credits(request: Request, response: Response, body: CheckSubmissionIn):
        result = await run_in_threadpool(controls.check_allowance, request, body.idempotency_key)
        _secure(response)
        return {"found": result is not None, "allowance": result}

    @router.post("/operations/recover")
    async def recover(
        request: Request,
        response: Response,
        body: RecoveryIn,
    ) -> dict[str, Any]:
        require_admin(request)
        ops, tenant, runtime = await composition(request)
        result = await call(
            ops,
            runtime.store.recover_expired_leases,
            tenant,
            limit=body.limit,
        )
        _secure(response)
        return result

    @router.get("/operations/integrity")
    async def integrity(request: Request, response: Response) -> dict[str, Any]:
        require_audit(request)
        ops, tenant, runtime = await composition(request)
        result = await call(ops, runtime.store.verify_integrity, tenant)
        _secure(response)
        return result

    @router.get("/operations/retention")
    async def retention_due(
        request: Request,
        response: Response,
        before: float | None = Query(default=None, gt=0),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, Any]:
        require_audit(request)
        ops, tenant, runtime = await composition(request)
        cutoff = before if before is not None else runtime.clock()
        if not math.isfinite(cutoff):
            raise HTTPException(status_code=422, detail="retention cutoff is invalid")
        listed = await call(ops, runtime.store.list_jobs, tenant, limit=500)
        due = sorted(
            (
                job
                for job in listed["jobs"]
                if job["state"] in {"succeeded", "failed", "cancelled"}
                and float(job["retention_until"]) <= cutoff
            ),
            key=lambda job: (float(job["retention_until"]), str(job["job_id"])),
        )
        _secure(response)
        return {
            "jobs": due[:limit],
            "truncated": len(due) > limit or listed["truncated"] is True,
            "complete": listed["truncated"] is False,
            "before": cutoff,
        }

    @router.post("/operations/retention/purge")
    async def purge_retention(
        request: Request,
        response: Response,
        body: RetentionPurgeIn,
    ) -> dict[str, Any]:
        require_admin(request)
        ops, tenant, runtime = await composition(request)
        result = await call(
            ops,
            runtime.store.purge_retention,
            tenant,
            before=body.before,
            limit=body.limit,
        )
        _secure(response)
        return result

    return router


router = create_consent_bulk_jobs_router()


def job_controls() -> ConsentJobControls:
    """Return the same trusted closures used by the installed native routes."""
    return router.consent_job_controls

__all__ = [
    "ConsentBulkJobsDependencies",
    "create_consent_bulk_jobs_router",
    "router",
]
