"""Tenant-bound operator API for the durable consent scan inventory.

The router deliberately separates queue administration from the endpoint that
executes the injected browser scanner.  Claiming returns a raw lease token once;
ordinary job reads never expose the stored token digest.  Scanner observations
remain unknown until a freshness-bounded review is recorded, and the bridge is
an explicit administrator action.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Mapping
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission

router = APIRouter(prefix="/consent/scan-inventory", tags=["consent-scan-inventory"])

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDEMPOTENCY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_LEASE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._~-]{23,255}$"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=192,
        pattern=_IDEMPOTENCY_PATTERN,
    ),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST_PATTERN),
]
LeaseToken = Annotated[
    str,
    StringConstraints(strict=True, min_length=24, max_length=256, pattern=_LEASE_PATTERN),
]
ExactOrigin = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=2048)]
StartUrl = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=4096)]
ObjectPath = Annotated[str, Path(pattern=_ID_PATTERN, min_length=1, max_length=128)]
DigestPath = Annotated[str, Path(pattern=_DIGEST_PATTERN, min_length=64, max_length=64)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PropertyIn(_StrictModel):
    origins: list[ExactOrigin] = Field(min_length=1, max_length=128)
    start_urls: list[StartUrl] = Field(min_length=1, max_length=128)
    expected_revision: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class ScanLimitsIn(_StrictModel):
    # Omitted limits take the installation's scan limits (Settings > All
    # settings), and every limit is lowered to the installation's cap.
    max_pages: int | None = Field(default=None, ge=1, le=10_000)
    max_depth: int | None = Field(default=None, ge=0, le=20)
    page_timeout_seconds: int | None = Field(default=None, ge=1, le=300)
    max_network_events: int | None = Field(default=None, ge=1, le=100_000)
    settle_milliseconds: int = Field(default=1_000, ge=0, le=30_000)


class ScheduleIn(_StrictModel):
    property_id: OpaqueId
    # Required unless the installation sets a scan interval; a shorter one is
    # raised to the installation's shortest interval.
    interval_seconds: int | None = Field(default=None, ge=300, le=2_592_000)
    next_due_at: float = Field(gt=0, lt=100_000_000_000.0)
    expected_revision: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey
    limits: ScanLimitsIn = Field(default_factory=ScanLimitsIn)
    auth_secret_ref: OpaqueId | None = None
    authenticated_scan_consent: bool = False
    max_attempts: int = Field(default=3, ge=1, le=20)
    retry_base_seconds: int = Field(default=30, ge=1, le=3_600)
    retry_max_seconds: int = Field(default=3_600, ge=1, le=86_400)
    lease_seconds: int = Field(default=300, ge=30, le=86_400)
    enabled: bool = True


class EnqueueIn(_StrictModel):
    due_at: float | None = Field(default=None, gt=0, lt=100_000_000_000.0)
    limit: int = Field(default=100, ge=1, le=500)


class ClaimIn(_StrictModel):
    limit: int = Field(default=1, ge=1, le=100)


class LeaseIn(_StrictModel):
    lease_token: LeaseToken
    expected_revision: int = Field(ge=0, le=2**31 - 1)


class RunIn(_StrictModel):
    lease_token: LeaseToken


class ReplayIn(_StrictModel):
    expected_revision: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class ReviewIn(_StrictModel):
    classification: Annotated[
        str,
        StringConstraints(
            strict=True,
            pattern=r"^(essential|functional|analytics|advertising|other|not_a_tracker)$",
        ),
    ]
    registry_action: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^(observe_only|approved|blocked|retired)$"),
    ]
    report_id: OpaqueId
    valid_until: float = Field(gt=0, lt=100_000_000_000.0)
    expected_version: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey
    tracker_id: OpaqueId | None = None
    vendor_id: OpaqueId | None = None
    purpose_ids: list[OpaqueId] = Field(default_factory=list, max_length=128)
    authority_expected_revision: int = Field(default=0, ge=0, le=2**31 - 1)


class ReviewRequestIn(_StrictModel):
    """A registry-changing review waiting for a different person's approval."""

    classification: Annotated[
        str,
        StringConstraints(
            strict=True,
            pattern=r"^(essential|functional|analytics|advertising|other)$",
        ),
    ]
    registry_action: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^(approved|blocked|retired)$"),
    ]
    report_id: OpaqueId
    valid_until: float = Field(gt=0, lt=100_000_000_000.0)
    expected_version: int = Field(ge=0, le=2**31 - 1)
    tracker_id: OpaqueId
    vendor_id: OpaqueId
    purpose_ids: list[OpaqueId] = Field(default_factory=list, max_length=128)
    authority_expected_revision: int = Field(default=0, ge=0, le=2**31 - 1)


class RunDueIn(_StrictModel):
    limit: int = Field(default=5, ge=1, le=20)


class BridgeIn(_StrictModel):
    idempotency_key: IdempotencyKey
    after_tracker_key: Digest | None = None
    limit: int = Field(default=100, ge=1, le=500)


class RetentionIn(_StrictModel):
    before: float = Field(gt=0, lt=100_000_000_000.0)
    limit: int = Field(default=100, ge=1, le=500)


def _enabled() -> bool:
    """Fail closed unless both consent and its scanner are explicitly enabled."""

    try:
        from maverick import config

        if config.config_source_errors():
            return False
        loaded = config.load_config()
    except Exception:
        return False
    if not isinstance(loaded, Mapping):
        return False
    consent = loaded.get("consent_preferences")
    if not isinstance(consent, Mapping) or consent.get("enable") is not True:
        return False
    scanner = consent.get("scanner")
    return isinstance(scanner, Mapping) and scanner.get("enable") is True


def _ops():
    if not _enabled():
        raise HTTPException(
            status_code=403,
            detail=(
                "consent scan inventory is disabled; enable [consent_preferences] "
                "and [consent_preferences.scanner]"
            ),
        )
    from maverick import consent_scan_inventory

    return consent_scan_inventory


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using consent scan inventory",
        )
    return tenant


def _scanner_authority():
    """Create the production browser seam; tests inject a network-free scanner."""

    from maverick.consent_scanner import ConsentScanner, PlaywrightPageCollector

    return ConsentScanner(PlaywrightPageCollector())


def _authenticated_scan_credential_owner_configured() -> bool:
    """Deployment seam for a separately reviewed storage-state credential owner."""

    return False


def _tracker_authority(tenant_id: str):
    from maverick.consent_preferences import ConsentPreferenceStore
    from maverick.paths import data_dir

    return ConsentPreferenceStore(
        data_dir(
            "consent_preferences",
            "consent-preferences.sqlite3",
            tenant=tenant_id,
        )
    )


def _inventory(ops, tenant_id: str):
    from maverick.paths import data_dir

    return ops.ConsentScanInventory(
        data_dir(
            "consent_preferences",
            "consent-scan-inventory.sqlite3",
            tenant=tenant_id,
        ),
        _scanner_authority(),
        tracker_authority=_tracker_authority(tenant_id),
    )


def _actor_subject(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    subject = getattr(principal, "sub", None)
    return str(subject or "local-operator")


def _worker_id(request: Request, tenant_id: str) -> str:
    digest = hashlib.sha256(
        f"consent-scan-worker:{tenant_id}:{_actor_subject(request)}".encode()
    ).hexdigest()
    return f"scan-api-{digest[:24]}"


def _reviewer_sha256(request: Request, tenant_id: str) -> str:
    return hashlib.sha256(
        f"consent-scan-reviewer:{tenant_id}:{_actor_subject(request)}".encode()
    ).hexdigest()


async def _call(ops, function, *args, **kwargs) -> Any:
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except ops.ConsentScanConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.ConsentScanNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ops.ConsentScanLeaseError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.ConsentScanValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ops.ConsentScanIntegrityError as exc:
        raise HTTPException(
            status_code=503,
            detail="consent scan inventory integrity validation failed",
        ) from exc
    except ops.ConsentScanBridgeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ops.ConsentScanInventoryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _authority():
    ops = _ops()
    tenant = _tenant_id()
    return ops, tenant, _inventory(ops, tenant)


def _coverage(report: Mapping[str, Any]) -> dict[str, Any]:
    scanner_report = report.get("scanner_report")
    errors: object = []
    if isinstance(scanner_report, Mapping):
        errors = scanner_report.get("errors", [])
    elif "error_count" in report:
        errors = [None] * int(report.get("error_count") or 0)
    truncated = report.get("truncated") is True
    complete = report.get("complete") is True
    has_errors = isinstance(errors, (list, tuple)) and bool(errors)
    if complete and (truncated or has_errors):
        raise HTTPException(
            status_code=503,
            detail="scanner completeness evidence is internally inconsistent",
        )
    return {
        "coverage_complete": bool(complete and not truncated and not has_errors),
        "truncated": truncated,
        "errors_present": has_errors,
        "absence_is_proven": False,
    }


def _report_response(report: dict[str, Any]) -> dict[str, Any]:
    return {**report, "coverage": _coverage(report), "live_acceptance": False}


@router.put("/properties/{property_id}")
async def upsert_property(
    request: Request,
    property_id: ObjectPath,
    body: PropertyIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, inventory = _authority()
    return await _call(
        ops,
        inventory.upsert_property,
        tenant,
        property_id,
        body.origins,
        body.start_urls,
        expected_revision=body.expected_revision,
        idempotency_key=body.idempotency_key,
    )


@router.get("/properties")
async def properties(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    return await _call(ops, inventory.list_properties, tenant, limit=limit)


@router.get("/properties/{property_id}")
async def property_detail(request: Request, property_id: ObjectPath) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    return await _call(ops, inventory.get_property, tenant, property_id)


@router.put("/schedules/{schedule_id}")
async def put_schedule(
    request: Request,
    schedule_id: ObjectPath,
    body: ScheduleIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, inventory = _authority()
    from dataclasses import asdict

    from maverick.consent_scanner import ConsentScannerConfigError, ScanLimits, default_scan_limits

    try:
        defaults = asdict(default_scan_limits())
    except ConsentScannerConfigError as exc:
        raise HTTPException(status_code=503, detail="scanner settings are invalid") from exc
    explicit = {k: v for k, v in body.limits.model_dump().items() if v is not None}
    payload = body.model_dump(exclude={"property_id", "limits"})
    return await _call(
        ops,
        inventory.put_schedule,
        tenant,
        schedule_id,
        body.property_id,
        limits=ScanLimits(**{**defaults, **explicit}),
        **payload,
    )


@router.get("/schedules")
async def schedules(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    return await _call(ops, inventory.list_schedules, tenant, limit=limit)


@router.get("/schedules/{schedule_id}")
async def schedule_detail(request: Request, schedule_id: ObjectPath) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    return await _call(ops, inventory.get_schedule, tenant, schedule_id)


@router.post("/jobs/enqueue")
async def enqueue_jobs(request: Request, body: EnqueueIn) -> dict[str, Any]:
    require_global_permission(request, "operate")
    ops, tenant, inventory = _authority()
    return await _call(ops, inventory.enqueue_due, tenant, **body.model_dump())


@router.post("/jobs/claim")
async def claim_jobs(request: Request, body: ClaimIn) -> dict[str, Any]:
    """Return each raw lease token once; callers must keep it out of logs."""

    require_global_permission(request, "operate")
    ops, tenant, inventory = _authority()
    result = await _call(
        ops,
        inventory.claim_due,
        tenant,
        _worker_id(request, tenant),
        limit=body.limit,
    )
    return {
        **result,
        "lease_token_contract": "one_time_response_secret_not_persisted",
    }


@router.post("/jobs/{job_id}/renew")
async def renew_job_lease(
    request: Request,
    job_id: ObjectPath,
    body: LeaseIn,
) -> dict[str, Any]:
    require_global_permission(request, "operate")
    ops, tenant, inventory = _authority()
    return await _call(
        ops,
        inventory.renew_lease,
        tenant,
        job_id,
        _worker_id(request, tenant),
        body.lease_token,
        expected_revision=body.expected_revision,
    )


@router.post("/jobs/{job_id}/run")
async def run_job(
    request: Request,
    job_id: ObjectPath,
    body: RunIn,
) -> dict[str, Any]:
    """Execute one leased browser scan; this is an explicit external side effect."""

    require_global_permission(request, "admin")
    ops, tenant, inventory = _authority()
    result = await _call(
        ops,
        inventory.run_claim,
        tenant,
        job_id,
        _worker_id(request, tenant),
        body.lease_token,
    )
    response = {
        **result,
        "external_side_effect": True,
        "live_acceptance": False,
    }
    report = response.get("report")
    response["coverage"] = (
        _coverage(report)
        if isinstance(report, Mapping)
        else {
            "coverage_complete": False,
            "truncated": False,
            "errors_present": True,
            "absence_is_proven": False,
        }
    )
    return response


@router.get("/jobs")
async def jobs(
    request: Request,
    status: str | None = Query(default=None, pattern=r"^(queued|leased|succeeded|dead_letter)$"),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    return await _call(ops, inventory.list_jobs, tenant, status=status, limit=limit)


@router.get("/jobs/{job_id}")
async def job_detail(request: Request, job_id: ObjectPath) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    return await _call(ops, inventory.get_job, tenant, job_id)


@router.get("/dead-letters")
async def dead_letters(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    return await _call(
        ops,
        inventory.list_jobs,
        tenant,
        status="dead_letter",
        limit=limit,
    )


@router.post("/dead-letters/{job_id}/replay")
async def replay_dead_letter(
    request: Request,
    job_id: ObjectPath,
    body: ReplayIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, inventory = _authority()
    return await _call(
        ops,
        inventory.replay_dead_letter,
        tenant,
        job_id,
        **body.model_dump(),
    )


@router.get("/reports/diff")
async def report_diff(
    request: Request,
    older_report_id: str = Query(pattern=_ID_PATTERN, min_length=1, max_length=128),
    newer_report_id: str = Query(pattern=_ID_PATTERN, min_length=1, max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    return await _call(
        ops,
        inventory.diff_reports,
        tenant,
        older_report_id,
        newer_report_id,
        limit=limit,
    )


@router.get("/reports")
async def reports(
    request: Request,
    property_id: str | None = Query(
        default=None,
        pattern=_ID_PATTERN,
        min_length=1,
        max_length=128,
    ),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    result = await _call(
        ops,
        inventory.list_reports,
        tenant,
        property_id=property_id,
        limit=limit,
    )
    return {
        **result,
        "items": [_report_response(item) for item in result["items"]],
        "absence_is_proven": False,
    }


@router.get("/reports/{report_id}")
async def report_detail(request: Request, report_id: ObjectPath) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    result = await _call(ops, inventory.get_report, tenant, report_id)
    return _report_response(result)


@router.get("/properties/{property_id}/discoveries")
async def discoveries(
    request: Request,
    property_id: ObjectPath,
    after_tracker_key: str | None = Query(
        default=None,
        pattern=_DIGEST_PATTERN,
        min_length=64,
        max_length=64,
    ),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    result = await _call(
        ops,
        inventory.list_discoveries,
        tenant,
        property_id,
        after_tracker_key=after_tracker_key,
        limit=limit,
    )
    return {**result, "unknowns_auto_enforced": False}


async def _finding_evidence(
    ops, tenant: str, inventory, property_id: str, tracker_key: str, report_id: str
) -> str:
    """The finding's evidence fingerprint, taken from the stored report only."""

    report = await _call(ops, inventory.get_report, tenant, report_id)
    if report.get("property_id") != property_id:
        raise HTTPException(status_code=422, detail="review report property does not match")
    scanner_report = report.get("scanner_report")
    findings = scanner_report.get("findings", []) if isinstance(scanner_report, Mapping) else []
    finding = next(
        (
            item
            for item in findings
            if isinstance(item, Mapping) and item.get("tracker_key") == tracker_key
        ),
        None,
    )
    if not isinstance(finding, Mapping) or not isinstance(finding.get("evidence_sha256"), str):
        raise HTTPException(status_code=422, detail="review evidence is unavailable")
    return str(finding["evidence_sha256"])


@router.post("/properties/{property_id}/discoveries/{tracker_key}/review")
async def review_discovery(
    request: Request,
    property_id: ObjectPath,
    tracker_key: DigestPath,
    body: ReviewIn,
) -> dict[str, Any]:
    """Record a review that needs no second reviewer.

    The primary reviewer and the finding evidence are server-derived. A
    registry-changing review needs a second reviewer, and this route never
    takes one from the caller: it goes through the review-requests flow,
    where a different signed-in administrator approves.
    """

    require_global_permission(request, "admin")
    ops, tenant, inventory = _authority()
    if body.registry_action != "observe_only":
        raise HTTPException(
            status_code=409,
            detail=(
                "this review needs a second reviewer; file it with "
                "POST .../discoveries/{tracker_key}/review-requests so a "
                "different administrator can approve it"
            ),
        )
    evidence = await _finding_evidence(
        ops, tenant, inventory, property_id, tracker_key, body.report_id
    )
    payload = body.model_dump(exclude={"report_id"})
    result = await _call(
        ops,
        inventory.review_tracker,
        tenant,
        property_id,
        tracker_key,
        reviewer_sha256=_reviewer_sha256(request, tenant),
        evidence_sha256=evidence,
        report_id=body.report_id,
        **payload,
    )
    return {
        **result,
        "primary_reviewer_bound_to_request_principal": True,
        "second_reviewer_independently_authenticated_by_api": False,
    }


@router.get("/properties/{property_id}/discoveries/{tracker_key}/reviews")
async def reviews(
    request: Request,
    property_id: ObjectPath,
    tracker_key: DigestPath,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    return await _call(
        ops,
        inventory.list_reviews,
        tenant,
        property_id,
        tracker_key,
        limit=limit,
    )


@router.post("/reports/{report_id}/bridge")
async def bridge_report(
    request: Request,
    report_id: ObjectPath,
    body: BridgeIn,
) -> dict[str, Any]:
    """Apply only fresh reviewed mappings to the consent tracker authority."""

    require_global_permission(request, "admin")
    ops, tenant, inventory = _authority()
    result = await _call(
        ops,
        inventory.bridge_report,
        tenant,
        report_id,
        **body.model_dump(),
    )
    return {**result, "live_external_acceptance": False}


@router.get("/audit")
async def audit(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    result = await _call(ops, inventory.list_audit, tenant, limit=limit)
    return {
        **result,
        "chain_page_verified": False,
        "note": "records are integrity checked; this page alone does not prove full-chain export",
    }


@router.post("/retention/status")
async def retention_status(request: Request, body: RetentionIn) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    return await _call(ops, inventory.retention_due, tenant, **body.model_dump())


@router.post("/retention/purge")
async def retention_purge(request: Request, body: RetentionIn) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, inventory = _authority()
    return await _call(ops, inventory.purge_operational_data, tenant, **body.model_dump())


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops, tenant, inventory = _authority()
    properties_result = await _call(ops, inventory.list_properties, tenant, limit=500)
    schedules_result = await _call(ops, inventory.list_schedules, tenant, limit=500)
    jobs_result = await _call(ops, inventory.list_jobs, tenant, limit=500)
    reports_result = await _call(ops, inventory.list_reports, tenant, limit=500)
    from .consent_scan_scheduler import consent_scan_scheduler_status

    scheduler_status = consent_scan_scheduler_status()

    def count(result: Mapping[str, Any]) -> dict[str, Any]:
        items = result.get("items")
        return {
            "observed": len(items) if isinstance(items, list) else 0,
            "more_available": result.get("truncated") is True,
        }

    return {
        "configuration_enabled": True,
        "counts": {
            "properties": count(properties_result),
            "schedules": count(schedules_result),
            "jobs": count(jobs_result),
            "reports": count(reports_result),
        },
        "external_scan_execution": "explicit_run_endpoint_only",
        "authenticated_scan_credential_owner_configured": (
            _authenticated_scan_credential_owner_configured()
        ),
        "unknowns_auto_enforced": False,
        "absence_is_proven": False,
        "live_browser_acceptance": False,
        "customer_estate_acceptance": False,
        "scheduler": {
            "running": scheduler_status.get("running") is True,
            "configured_enabled": (scheduler_status.get("configured_enabled") is True),
            "stop_requested": scheduler_status.get("stop_requested") is True,
            "tenant_bound_metrics_exposed": False,
        },
    }


def _review_requests(tenant_id: str):
    from maverick.paths import data_dir

    from .consent_scan_review_requests import ScanReviewRequestStore

    return ScanReviewRequestStore(
        data_dir(
            "consent_preferences",
            "consent-scan-review-requests.sqlite3",
            tenant=tenant_id,
        )
    )


async def _request_call(function, *args, **kwargs) -> Any:
    from .consent_scan_review_requests import (
        ScanReviewRequestConflict,
        ScanReviewRequestError,
        ScanReviewRequestNotFound,
    )

    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except ScanReviewRequestNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ScanReviewRequestConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ScanReviewRequestError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/properties/{property_id}/discoveries/{tracker_key}/review-requests", status_code=201)
async def request_two_person_review(
    request: Request,
    property_id: ObjectPath,
    tracker_key: DigestPath,
    body: ReviewRequestIn,
) -> dict[str, Any]:
    """File a registry-changing review for a different administrator to approve.

    Replaces typing a second reviewer's fingerprint: the second reviewer is
    whoever approves, authenticated by their own session.
    """

    require_global_permission(request, "admin")
    ops, tenant, inventory = _authority()
    await _finding_evidence(ops, tenant, inventory, property_id, tracker_key, body.report_id)
    store = await run_in_threadpool(_review_requests, tenant)
    created = await _request_call(
        store.create,
        tenant,
        property_id=property_id,
        tracker_key=tracker_key,
        payload=body.model_dump(),
        proposer_sha256=_reviewer_sha256(request, tenant),
    )
    return _public_review_request(created, request, tenant)


def _public_review_request(item: Mapping[str, Any], request: Request, tenant: str) -> dict:
    public = {key: value for key, value in item.items() if key != "proposer_sha256"}
    public["requested_by_me"] = item.get("proposer_sha256") == _reviewer_sha256(request, tenant)
    return public


@router.get("/review-requests")
async def list_review_requests(
    request: Request,
    limit: int = Query(default=200, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    _ops_module, tenant, _inventory = _authority()
    store = await run_in_threadpool(_review_requests, tenant)
    items = await _request_call(store.list, tenant, limit=limit)
    return {"items": [_public_review_request(item, request, tenant) for item in items]}


@router.post("/review-requests/{request_id}/approve")
async def approve_review_request(request: Request, request_id: ObjectPath) -> dict[str, Any]:
    """Second person approves: records the review with both server-derived reviewers."""

    require_global_permission(request, "admin")
    ops, tenant, inventory = _authority()
    store = await run_in_threadpool(_review_requests, tenant)
    pending = await _request_call(store.get, tenant, request_id)
    if pending["status"] != "pending":
        raise HTTPException(status_code=409, detail="review request is no longer pending")
    approver = _reviewer_sha256(request, tenant)
    if approver == pending["proposer_sha256"]:
        raise HTTPException(
            status_code=409,
            detail="a different person must approve this review",
        )
    payload = dict(pending["payload"])
    report_id = str(payload.pop("report_id"))
    evidence = await _finding_evidence(
        ops, tenant, inventory, pending["property_id"], pending["tracker_key"], report_id
    )
    result = await _call(
        ops,
        inventory.review_tracker,
        tenant,
        pending["property_id"],
        pending["tracker_key"],
        reviewer_sha256=pending["proposer_sha256"],
        second_reviewer_sha256=approver,
        evidence_sha256=evidence,
        report_id=report_id,
        idempotency_key=f"review-request-{request_id}",
        **payload,
    )
    await _request_call(store.decide, tenant, request_id, "approved")
    return {
        **result,
        "primary_reviewer_bound_to_request_principal": True,
        "second_reviewer_independently_authenticated_by_api": True,
    }


@router.post("/review-requests/{request_id}/withdraw")
async def withdraw_review_request(request: Request, request_id: ObjectPath) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _ops_module, tenant, _inventory = _authority()
    store = await run_in_threadpool(_review_requests, tenant)
    decided = await _request_call(store.decide, tenant, request_id, "withdrawn")
    return _public_review_request(decided, request, tenant)


async def _run_claimed(request: Request, ops, tenant: str, inventory, limit: int) -> list[dict]:
    """Claim due jobs with the server-owned worker identity and run each one.

    The one-time lease token never leaves the server: this is the worker
    protocol run behind a single button.
    """

    worker = _worker_id(request, tenant)
    claimed = await _call(ops, inventory.claim_due, tenant, worker, limit=limit)
    outcomes: list[dict[str, Any]] = []
    for item in claimed.get("items", []):
        result = await _call(
            ops,
            inventory.run_claim,
            tenant,
            item["job_id"],
            worker,
            item["lease_token"],
        )
        report = result.get("report") if isinstance(result, Mapping) else None
        outcomes.append(
            {
                "job_id": item["job_id"],
                "property_id": item.get("property_id"),
                "succeeded": bool(result.get("succeeded")) if isinstance(result, Mapping) else False,
                "report_id": report.get("report_id") if isinstance(report, Mapping) else None,
                "coverage": (
                    _coverage(report)
                    if isinstance(report, Mapping)
                    else {
                        "coverage_complete": False,
                        "truncated": False,
                        "errors_present": True,
                        "absence_is_proven": False,
                    }
                ),
            }
        )
    return outcomes


@router.post("/jobs/run-due")
async def run_due_scans(request: Request, body: RunDueIn) -> dict[str, Any]:
    """Queue every due schedule, then run up to ``limit`` due scans now."""

    require_global_permission(request, "admin")
    ops, tenant, inventory = _authority()
    await _call(ops, inventory.enqueue_due, tenant, limit=100)
    outcomes = await _run_claimed(request, ops, tenant, inventory, body.limit)
    return {"outcomes": outcomes, "external_side_effect": bool(outcomes), "live_acceptance": False}


@router.post("/properties/{property_id}/scan-now")
async def scan_property_now(request: Request, property_id: ObjectPath) -> dict[str, Any]:
    """Make this website's schedule due now and run the due scans.

    The schedule keeps every setting; only its next due time moves to now,
    so later scans follow the interval from this scan.
    """

    require_global_permission(request, "admin")
    ops, tenant, inventory = _authority()
    listed = await _call(ops, inventory.list_schedules, tenant, limit=500)
    schedule = next(
        (
            item
            for item in listed.get("items", [])
            if item.get("property_id") == property_id and item.get("enabled") is True
        ),
        None,
    )
    if schedule is None:
        raise HTTPException(
            status_code=409,
            detail="this website has no active scan schedule",
        )
    from maverick.consent_scanner import ScanLimits

    clock = getattr(inventory, "_now", None)
    now = float(clock()) if callable(clock) else time.time()
    await _call(
        ops,
        inventory.put_schedule,
        tenant,
        schedule["schedule_id"],
        property_id,
        interval_seconds=schedule["interval_seconds"],
        next_due_at=now,
        expected_revision=schedule["revision"],
        idempotency_key=f"scan-now-{uuid.uuid4().hex}",
        limits=ScanLimits(**schedule["limits"]),
        auth_secret_ref=schedule.get("auth_secret_ref"),
        authenticated_scan_consent=bool(schedule.get("authenticated_scan_consent")),
        max_attempts=schedule["max_attempts"],
        retry_base_seconds=schedule["retry_base_seconds"],
        retry_max_seconds=schedule["retry_max_seconds"],
        lease_seconds=schedule["lease_seconds"],
        enabled=True,
    )
    await _call(ops, inventory.enqueue_due, tenant, limit=100)
    outcomes = await _run_claimed(request, ops, tenant, inventory, 10)
    return {
        "outcomes": outcomes,
        "property_scanned": any(item["property_id"] == property_id for item in outcomes),
        "external_side_effect": bool(outcomes),
        "live_acceptance": False,
    }


__all__ = ["router"]
