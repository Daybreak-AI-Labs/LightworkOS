"""Tenant-bound operator API for privacy-minimising data discovery.

Provider access and reviewed data-map/RoPA delivery are deliberately injected
at the application boundary.  Request bodies can identify enrolled metadata
and bounded work, but cannot provide a tenant, actor, worker, reviewer, raw
source value, provider credential, detector result, or callback payload.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import (
    caller_principal,
    has_global_permission,
    has_permission,
    require_global_permission,
    require_permission,
    require_principal,
)

router = APIRouter(
    prefix="/privacy/data-discovery",
    tags=["privacy-data-discovery"],
)

_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDEMPOTENCY = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_PROVIDER = r"^[a-z][a-z0-9_-]{0,63}$"
_ENV = r"^[A-Z][A-Z0-9_]{1,127}$"
_DIGEST = r"^[0-9a-f]{64}$"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=192,
        pattern=_IDEMPOTENCY,
    ),
]
ProviderName = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=64, pattern=_PROVIDER),
]
SavedCredentialRef = Annotated[str, StringConstraints(strict=True, min_length=2, max_length=128,
    pattern=r"^(?:[A-Z][A-Z0-9_]{1,127}|connection:[a-z0-9][a-z0-9_-]{0,63}:[0-9a-f]{32})$")]
EvidenceKeyRef = Annotated[str, StringConstraints(strict=True, min_length=2, max_length=128,
    pattern=r"^(?:[A-Z][A-Z0-9_]{1,127}|evidence-key:[a-z0-9][a-z0-9_-]{0,63}:[1-9][0-9]{0,9})$")]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST),
]
ExactOrigin = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=2_048),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID),
]

SourceKind = Literal["structured", "unstructured"]
SourceState = Literal["active", "suspended", "revoked"]
JobState = Literal["queued", "leased", "complete", "dead_letter", "cancelled"]
RemediationState = Literal[
    "queued",
    "leased",
    "applied",
    "no_change",
    "ambiguous",
    "dead_letter",
    "cancelled",
]
ReviewDecision = Literal["confirmed", "reclassified", "false_positive"]
Category = Literal[
    "authentication_secret",
    "biometric_identifier",
    "date_of_birth",
    "email_address",
    "financial_account",
    "government_identifier",
    "health_information",
    "ip_address",
    "payment_card",
    "person_name",
    "phone_number",
    "physical_address",
    "precise_location",
    "unknown_personal_data",
]
FailureCode = Literal[
    "adapter_error",
    "credential_unavailable",
    "operator_cancelled",
    "provider_contract_invalid",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ScanLimitsIn(_StrictModel):
    max_records: int = Field(default=10_000, ge=1, le=1_000_000)
    max_files: int = Field(default=1_000, ge=1, le=100_000)
    max_bytes: int = Field(default=64 * 1024 * 1024, ge=1, le=2**40)
    max_seconds: float = Field(default=300.0, ge=0.1, le=86_400.0)
    max_findings: int = Field(default=10_000, ge=1, le=100_000)
    max_fields_per_record: int = Field(default=256, ge=1, le=10_000)
    max_record_bytes: int = Field(
        default=256 * 1024,
        ge=1,
        le=64 * 1024 * 1024,
    )
    max_document_bytes: int = Field(
        default=4 * 1024 * 1024,
        ge=1,
        le=256 * 1024 * 1024,
    )


class SourceEnrollmentIn(_StrictModel):
    kind: SourceKind
    provider: ProviderName
    origin: ExactOrigin
    resource_ref: OpaqueId
    credential_env: SavedCredentialRef
    evidence_key_env: EvidenceKeyRef
    expected_revision: int = Field(default=0, ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class SourceStateIn(_StrictModel):
    state: SourceState
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class EvidenceKeyIn(_StrictModel):
    expected_revision: int = Field(default=0, ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class TestAccessIn(_StrictModel):
    confirm: Literal[True]
    expected_revision: int = Field(ge=1)


class ScheduleIn(_StrictModel):
    source_id: OpaqueId
    interval_seconds: int = Field(ge=1, le=365 * 24 * 3_600)
    limits: ScanLimitsIn = Field(default_factory=ScanLimitsIn)
    max_attempts: int = Field(default=3, ge=1, le=20)
    retention_seconds: int = Field(
        default=90 * 24 * 3_600,
        ge=1,
        le=10 * 365 * 24 * 3_600,
    )
    active: bool = True
    expected_revision: int = Field(default=0, ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey
    next_run_at: float | None = Field(
        default=None,
        gt=0,
        lt=100_000_000_000.0,
    )


class EnqueueDueIn(_StrictModel):
    limit: int = Field(default=100, ge=1, le=100)


class ManualScanIn(_StrictModel):
    limits: ScanLimitsIn = Field(default_factory=ScanLimitsIn)
    max_attempts: int = Field(default=3, ge=1, le=20)
    retention_seconds: int = Field(
        default=90 * 24 * 3_600,
        ge=1,
        le=10 * 365 * 24 * 3_600,
    )
    idempotency_key: IdempotencyKey


class ClaimIn(_StrictModel):
    limit: int = Field(default=10, ge=1, le=100)
    lease_seconds: float = Field(default=600.0, ge=1.0, le=3_600.0)


class FailJobIn(_StrictModel):
    error_code: FailureCode
    base_backoff_seconds: float = Field(default=5.0, ge=0.1, le=3_600.0)


class ReplayIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class CancelScanIn(ReplayIn):
    confirmed: Literal[True]


class RunScanIn(CancelScanIn):
    expected_source_revision: int = Field(ge=1, le=2**31 - 1)
    expected_source_integrity_sha256: Digest


class ReviewProposalIn(_StrictModel):
    decision: ReviewDecision
    effective_category: Category | None = None
    freshness_seconds: int = Field(ge=1, le=365 * 24 * 3_600)
    expected_finding_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class ReviewApprovalIn(_StrictModel):
    expected_version: int = Field(ge=1, le=2**31 - 1)
    expected_integrity_sha256: Digest
    idempotency_key: IdempotencyKey


class RetentionIn(_StrictModel):
    idempotency_key: IdempotencyKey


class RemediationWorkerIn(_StrictModel):
    limit: int = Field(default=10, ge=1, le=100)
    lease_seconds: int = Field(default=60, ge=1, le=3_600)


class RemediationReconcileIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    absent_backoff_seconds: int = Field(default=0, ge=0, le=86_400)
    idempotency_key: IdempotencyKey


class RemediationMaintenanceIn(_StrictModel):
    idempotency_key: IdempotencyKey
    target_limit: int = Field(default=500, ge=1, le=1_000)


def _ops():
    from maverick import privacy_data_discovery as ops

    try:
        ops.require_enabled()
    except ops.PrivacyDataDiscoveryConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return ops


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using privacy data discovery",
        )
    return tenant


def _principal_subject(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    subject = getattr(principal, "sub", None)
    return str(subject or "local-operator")


def _identity_ref(request: Request, tenant_id: str, purpose: str) -> str:
    digest = hashlib.sha256(
        (
            "lightwork.privacy-data-discovery.identity.v1:"
            f"{purpose}:{tenant_id}:{_principal_subject(request)}"
        ).encode()
    ).hexdigest()
    return f"pdd-{purpose}-{digest[:32]}"


def _actor_ref(request: Request, tenant_id: str) -> str:
    return _identity_ref(request, tenant_id, "actor")


def _reviewer_ref(request: Request, tenant_id: str) -> str:
    return _identity_ref(request, tenant_id, "reviewer")


def _worker_ref(request: Request, tenant_id: str) -> str:
    return _identity_ref(request, tenant_id, "worker")


def _callback_authority(request: Request, tenant_id: str) -> Callable[[Any], None] | None:
    authority = getattr(
        request.app.state,
        "privacy_data_discovery_review_callback",
        None,
    )
    if authority is None:
        return None
    callback = (
        authority
        if callable(authority)
        else getattr(authority, "apply_reviewed_classification", None)
    )
    if not callable(callback):
        raise HTTPException(
            status_code=503,
            detail="reviewed data-map/RoPA callback authority is misconfigured",
        )

    def tenant_checked(update: Any) -> None:
        if getattr(update, "tenant_id", None) != tenant_id:
            raise RuntimeError("review callback tenant binding failed")
        callback(update)

    return tenant_checked


def _store(ops, tenant_id: str, request: Request):
    from maverick.paths import data_dir

    return ops.PrivacyDataDiscoveryStore(
        data_dir(
            "privacy_automation",
            "privacy-data-discovery.sqlite3",
            tenant=tenant_id,
        ),
        review_callback=_callback_authority(request, tenant_id),
    )


def _coordinator(request: Request, ops, tenant_id: str, store):
    factory = getattr(
        request.app.state,
        "privacy_data_discovery_coordinator_factory",
        None,
    )
    if callable(factory):
        return factory(tenant_id=tenant_id, store=store)
    structured = getattr(
        request.app.state,
        "privacy_data_discovery_structured_sources",
        {},
    )
    unstructured = getattr(
        request.app.state,
        "privacy_data_discovery_unstructured_sources",
        {},
    )
    credential_check = getattr(
        request.app.state,
        "privacy_data_discovery_credential_ref_present",
        None,
    )
    if not isinstance(structured, Mapping) or not isinstance(unstructured, Mapping):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery provider adapter registry is misconfigured",
        )
    if credential_check is not None and not callable(credential_check):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery credential owner is misconfigured",
        )
    return ops.PrivacyDataDiscoveryCoordinator(
        store,
        structured_sources=structured,
        unstructured_sources=unstructured,
        credential_ref_present=credential_check,
    )


def _authority(request: Request):
    ops = _ops()
    tenant = _tenant_id()
    return ops, tenant, _store(ops, tenant, request)


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _items(values: tuple[Any, ...], limit: int) -> dict[str, Any]:
    return {
        "items": [_jsonable(value) for value in values[:limit]],
        "truncated": len(values) > limit,
    }


def _report_payload(report: Any) -> dict[str, Any]:
    result = _jsonable(report)
    return {
        **result,
        "absence_is_proven": False,
        "completeness_scope": "declared_source_and_persisted_scan_bounds_only",
        "raw_data_returned": False,
        "live_provider_acceptance_verified": False,
    }


def _provider_names(value: object) -> tuple[list[str], bool]:
    if not isinstance(value, Mapping):
        return [], False
    names = sorted(
        key
        for key in value
        if isinstance(key, str) and re.fullmatch(_PROVIDER, key) is not None
    )
    return names[:100], len(names) > 100


def _provider_list(value: object) -> tuple[list[str], bool]:
    if not isinstance(value, (list, tuple)):
        return [], False
    names = sorted(
        {
            item
            for item in value
            if isinstance(item, str) and re.fullmatch(_PROVIDER, item) is not None
        }
    )
    return names[:100], len(names) > 100


def _remediation_worker_payload(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation worker returned an invalid result",
        )
    keys = (
        "claimed",
        "applied",
        "no_change",
        "retried",
        "ambiguous",
        "dead_lettered",
        "cancelled",
    )
    if any(
        type(value.get(key)) is not int or not 0 <= value[key] <= 100
        for key in keys
    ):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation worker returned an invalid result",
        )
    result = {key: int(value[key]) for key in keys}
    if sum(result[key] for key in keys[1:]) > result["claimed"]:
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation worker returned an invalid result",
        )
    return result


def _remediation_reconciliation_payload(
    value: object,
    work_id: str,
) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or value.get("work_id") != work_id
        or value.get("state")
        not in {
            "queued",
            "applied",
            "no_change",
            "ambiguous",
            "dead_letter",
            "cancelled",
        }
        or type(value.get("revision")) is not int
        or not 1 <= value["revision"] <= 2**31 - 1
    ):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation reconciliation returned an invalid result",
        )
    result: dict[str, object] = {
        "work_id": work_id,
        "state": value["state"],
        "revision": value["revision"],
    }
    for key in ("attempts", "max_attempts"):
        item = value.get(key)
        if item is not None:
            if type(item) is not int or not 0 <= item <= 20:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "privacy discovery remediation reconciliation returned "
                        "an invalid result"
                    ),
                )
            result[key] = item
    for key in ("authority_sha256", "receipt_sha256"):
        item = value.get(key)
        if item is not None:
            if not isinstance(item, str) or re.fullmatch(_DIGEST, item) is None:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "privacy discovery remediation reconciliation returned "
                        "an invalid result"
                    ),
                )
            result[key] = item
    error = value.get("last_error_code")
    if error is not None:
        if not isinstance(error, str) or re.fullmatch(r"^[a-z][a-z0-9_]{0,63}$", error) is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "privacy discovery remediation reconciliation returned an invalid result"
                ),
            )
        result["last_error_code"] = error
    return result


def _remediation_work_payload(value: object) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or not isinstance(value.get("work_id"), str)
        or re.fullmatch(_ID, value["work_id"]) is None
        or value.get("state")
        not in {
            "queued",
            "leased",
            "applied",
            "no_change",
            "ambiguous",
            "dead_letter",
            "cancelled",
        }
        or type(value.get("revision")) is not int
        or not 1 <= value["revision"] <= 2**31 - 1
    ):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation work listing returned an invalid result",
        )
    result: dict[str, object] = {
        "work_id": value["work_id"],
        "state": value["state"],
        "revision": value["revision"],
    }
    for key in ("attempts", "max_attempts"):
        item = value.get(key)
        if type(item) is not int or not 0 <= item <= 20:
            raise HTTPException(
                status_code=503,
                detail=(
                    "privacy discovery remediation work listing returned an invalid result"
                ),
            )
        result[key] = item
    for key in (
        "next_attempt_at",
        "lease_until",
        "ambiguous_at",
        "retained_until",
        "created_at",
        "updated_at",
    ):
        item = value.get(key)
        if item is not None:
            if type(item) not in (int, float) or not 0 <= item <= 100_000_000_000.0:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "privacy discovery remediation work listing returned "
                        "an invalid result"
                    ),
                )
            result[key] = float(item)
    for key in ("authority_sha256", "receipt_sha256"):
        item = value.get(key)
        if item is not None:
            if not isinstance(item, str) or re.fullmatch(_DIGEST, item) is None:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "privacy discovery remediation work listing returned "
                        "an invalid result"
                    ),
                )
            result[key] = item
    error = value.get("last_error_code")
    if error is not None:
        if not isinstance(error, str) or re.fullmatch(r"^[a-z][a-z0-9_]{0,63}$", error) is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "privacy discovery remediation work listing returned an invalid result"
                ),
            )
        result["last_error_code"] = error
    return result


def _remediation_maintenance_payload(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation maintenance returned an invalid result",
        )
    outbox = value.get("outbox_integrity")
    data_map = value.get("data_map_integrity")
    if not isinstance(outbox, Mapping) or not isinstance(data_map, Mapping):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation maintenance returned an invalid result",
        )

    def counts(source: Mapping[str, object], keys: tuple[str, ...]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key in keys:
            if key not in source:
                continue
            item = source[key]
            if type(item) is not int or not 0 <= item <= 2**31 - 1:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "privacy discovery remediation maintenance returned "
                        "an invalid result"
                    ),
                )
            result[key] = item
        return result

    purged: dict[str, int] = {}
    for key in ("outbox_purged", "data_map_purged"):
        item = value.get(key)
        if type(item) is not int or not 0 <= item <= 1_000:
            raise HTTPException(
                status_code=503,
                detail=(
                    "privacy discovery remediation maintenance returned an invalid result"
                ),
            )
        purged[key] = item
    outbox_result = counts(
        outbox,
        (
            "current_records",
            "history_records",
            "operation_records",
            "audit_events",
        ),
    )
    terminal = outbox.get("terminal_audit_sha256")
    if terminal is not None:
        if not isinstance(terminal, str) or re.fullmatch(_DIGEST, terminal) is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "privacy discovery remediation maintenance returned an invalid result"
                ),
            )
        outbox_result["terminal_audit_sha256"] = terminal
    return {
        "schema": "lightwork.privacy-discovery-maintenance.v1",
        **purged,
        "outbox_integrity": outbox_result,
        "data_map_integrity": counts(
            data_map,
            ("observations", "tombstones"),
        ),
        "raw_data_returned": False,
        "provider_side_effect": False,
    }


async def _scheduler_runtime_status(request: Request) -> dict[str, object]:
    """Resolve only the scheduler's closed, tenant-free health projection."""

    marker = (
        getattr(
            request.app.state,
            "privacy_data_discovery_worker_scheduler_operational",
            False,
        )
        is True
    )
    resolver = getattr(
        request.app.state,
        "privacy_data_discovery_worker_scheduler_status",
        None,
    )
    if resolver is None:
        return {
            "installed": False,
            "configured_enabled": marker,
            "running": marker,
            "healthy": marker,
            "consecutive_failures": 0,
            "interrupted_cycles_recovered": 0,
            "last_error_code": None,
            "last_cycle": None,
            "process_concurrency_excluded": False,
            "cross_process_concurrency_excluded": False,
            "status_opened_tenant_store": False,
            "status_invoked_provider": False,
            "digest_only_data_map_target": False,
            "provider_network_io": False,
            "provider_writes": False,
            "estate_completeness_claimed": False,
            "live_provider_acceptance_verified": False,
        }
    if not callable(resolver):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery scheduler status authority is invalid",
        )
    try:
        raw = await run_in_threadpool(resolver)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="privacy discovery scheduler status is unavailable",
        ) from exc
    if not isinstance(raw, Mapping):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery scheduler status is invalid",
        )
    booleans = (
        "installed",
        "configured_enabled",
        "running",
        "healthy",
        "process_concurrency_excluded",
        "cross_process_concurrency_excluded",
        "status_opened_tenant_store",
        "status_invoked_provider",
        "digest_only_data_map_target",
        "provider_network_io",
        "provider_writes",
        "estate_completeness_claimed",
        "live_provider_acceptance_verified",
    )
    result: dict[str, object] = {}
    for key in booleans:
        value = raw.get(key)
        if type(value) is not bool:
            raise HTTPException(
                status_code=503,
                detail="privacy discovery scheduler status is invalid",
            )
        result[key] = value
    for key in ("consecutive_failures", "interrupted_cycles_recovered"):
        value = raw.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31 - 1:
            raise HTTPException(
                status_code=503,
                detail="privacy discovery scheduler status is invalid",
            )
        result[key] = value
    error_code = raw.get("last_error_code")
    if error_code not in {
        None,
        "scheduler_cycle_failed",
        "tenant_cycle_incomplete",
    }:
        raise HTTPException(
            status_code=503,
            detail="privacy discovery scheduler status is invalid",
        )
    result["last_error_code"] = error_code
    cycle = raw.get("last_cycle")
    if cycle is not None:
        cycle_keys = {
            "schema",
            "started_at",
            "completed_at",
            "tenants_considered",
            "tenants_enabled",
            "tenants_failed",
            "tenant_limit_reached",
            "ambiguous_considered",
            "ambiguous_applied",
            "ambiguous_no_change",
            "ambiguous_requeued",
            "ambiguous_unresolved",
            "claimed",
            "applied",
            "no_change",
            "retried",
            "ambiguous",
            "dead_lettered",
            "cancelled",
            "recovery_checked_tenants",
            "next_interval_seconds",
            "cycle_sha256",
        }
        if not isinstance(cycle, Mapping) or set(cycle) != cycle_keys:
            raise HTTPException(
                status_code=503,
                detail="privacy discovery scheduler status is invalid",
            )
        cycle = {key: cycle[key] for key in cycle_keys}
    result["last_cycle"] = cycle
    return result


async def _runtime_capabilities(request: Request, tenant_id: str) -> dict[str, Any]:
    """Resolve content-free runtime capabilities without opening a provider/store."""

    callback_configured = _callback_authority(request, tenant_id) is not None
    scheduler_status = await _scheduler_runtime_status(request)
    scheduler_running = scheduler_status["running"] is True
    probe = getattr(
        request.app.state,
        "privacy_data_discovery_readiness_probe",
        None,
    )
    if probe is None:
        structured, structured_truncated = _provider_names(
            getattr(
                request.app.state,
                "privacy_data_discovery_structured_sources",
                {},
            )
        )
        unstructured, unstructured_truncated = _provider_names(
            getattr(
                request.app.state,
                "privacy_data_discovery_unstructured_sources",
                {},
            )
        )
        durable = (
            callback_configured
            and getattr(
                request.app.state,
                "privacy_data_discovery_review_callback_durable_outbox",
                False,
            )
            is True
        )
        worker_available = callable(
            getattr(
                request.app.state,
                "privacy_data_discovery_worker_factory",
                None,
            )
        )
        return {
            "source": "legacy_global_maps",
            "configured": bool(structured or unstructured),
            "ready": bool(structured or unstructured),
            "structured": structured,
            "unstructured": unstructured,
            "truncated": structured_truncated or unstructured_truncated,
            "callback_configured": callback_configured,
            "durable_outbox": durable,
            "data_map_target": False,
            "retry_worker_available": worker_available,
            "scheduler_configured_for_tenant": False,
            "scheduler_operational": scheduler_running,
            "scheduler_status": scheduler_status,
            "automatic_retry": (
                durable and worker_available and scheduler_running
            ),
            "status_probe_opened_store": False,
            "status_probe_invoked_provider": False,
        }
    if not callable(probe):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery readiness authority is misconfigured",
        )
    try:
        raw = await run_in_threadpool(probe, tenant_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="privacy discovery readiness authority is unavailable",
        ) from exc
    if not isinstance(raw, Mapping):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery readiness authority is invalid",
        )
    structured, structured_truncated = _provider_list(
        raw.get("structured_providers")
    )
    unstructured, unstructured_truncated = _provider_list(
        raw.get("unstructured_providers")
    )
    outbox_enabled = raw.get("remediation_outbox_enabled") is True
    durable = (
        callback_configured
        and outbox_enabled
        and raw.get("approved_review_callback_durable_outbox") is True
    )
    data_map_target = (
        outbox_enabled and raw.get("data_map_target_enabled") is True
    )
    worker_available = raw.get("retry_worker_factory_installed") is True
    scheduler_configured = raw.get("remediation_scheduler_enabled") is True
    scheduler_operational = scheduler_running and scheduler_configured
    return {
        "source": "tenant_readiness_probe",
        "configured": raw.get("configured") is True,
        "ready": raw.get("ready") is True,
        "structured": structured,
        "unstructured": unstructured,
        "truncated": structured_truncated or unstructured_truncated,
        "callback_configured": callback_configured,
        "durable_outbox": durable,
        "data_map_target": data_map_target,
        "retry_worker_available": worker_available,
        "scheduler_configured_for_tenant": scheduler_configured,
        "scheduler_operational": scheduler_operational,
        "scheduler_status": scheduler_status,
        "automatic_retry": durable and worker_available and scheduler_operational,
        "status_probe_opened_store": raw.get("status_probe_opened_store") is True,
        "status_probe_invoked_provider": (
            raw.get("status_probe_invoked_provider") is True
        ),
    }


async def _remediation_runtime(
    request: Request,
    ops: Any,
    tenant_id: str,
    discovery_store: Any,
    *,
    principal_ref: str,
) -> Any:
    capabilities = await _runtime_capabilities(request, tenant_id)
    if (
        capabilities["source"] != "tenant_readiness_probe"
        or not capabilities["configured"]
        or not capabilities["ready"]
        or not capabilities["data_map_target"]
    ):
        raise HTTPException(
            status_code=403,
            detail="privacy discovery remediation data-map runtime is not ready",
        )
    factory = getattr(
        request.app.state,
        "privacy_data_discovery_remediation_runtime_factory",
        None,
    )
    if not callable(factory):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation runtime authority is unavailable",
        )
    try:
        runtime = await run_in_threadpool(
            factory,
            tenant_id=tenant_id,
            discovery_store=discovery_store,
            principal_ref=principal_ref,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except ops.PrivacyDataDiscoveryConfigError as exc:
        raise HTTPException(
            status_code=403,
            detail="privacy discovery remediation data-map runtime is disabled",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation runtime authority is unavailable",
        ) from exc
    worker = getattr(runtime, "worker", None)
    outbox = getattr(runtime, "outbox", None)
    if (
        getattr(runtime, "tenant_id", None) != tenant_id
        or not callable(getattr(worker, "run_once", None))
        or not callable(getattr(outbox, "list_work", None))
        or not callable(getattr(outbox, "reconcile_ambiguous", None))
        or not callable(getattr(runtime, "reconciler", None))
        or not callable(getattr(runtime, "maintenance", None))
        or getattr(runtime, "digest_only_target", None) is not True
        or getattr(runtime, "external_side_effect", None) is not False
        or getattr(runtime, "provider_network_io", None) is not False
        or getattr(runtime, "provider_writes", None) is not False
    ):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation runtime authority is invalid",
        )
    return runtime


async def _remediation_call(function: Callable[..., Any], *args, **kwargs) -> Any:
    from maverick import privacy_data_discovery_remediation as remediation_ops

    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except (KeyboardInterrupt, SystemExit):
        raise
    except remediation_ops.PrivacyDiscoveryRemediationConfigError as exc:
        raise HTTPException(
            status_code=403,
            detail="privacy discovery remediation is disabled or unavailable",
        ) from exc
    except remediation_ops.PrivacyDiscoveryRemediationValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail="privacy discovery remediation request is invalid",
        ) from exc
    except remediation_ops.PrivacyDiscoveryRemediationNotFound as exc:
        raise HTTPException(
            status_code=404,
            detail="privacy discovery remediation work was not found",
        ) from exc
    except (
        remediation_ops.PrivacyDiscoveryRemediationConflict,
        remediation_ops.PrivacyDiscoveryRemediationLeaseLost,
    ) as exc:
        raise HTTPException(
            status_code=409,
            detail="privacy discovery remediation state changed",
        ) from exc
    except (
        remediation_ops.PrivacyDiscoveryRemediationIntegrityError,
        remediation_ops.PrivacyDiscoveryRemediationAuthorityError,
    ) as exc:
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation authority validation failed",
        ) from exc
    except remediation_ops.PrivacyDiscoveryRemediationError as exc:
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation operation failed",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation operation failed",
        ) from exc


async def _call(ops, function, *args, **kwargs) -> Any:
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except ops.PrivacyDataDiscoveryConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ops.PrivacyDataDiscoveryNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ops.PrivacyDataDiscoveryConflict, ops.PrivacyDataDiscoveryLeaseLost) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.PrivacyDataDiscoveryValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ops.PrivacyDataDiscoveryIntegrityError as exc:
        raise HTTPException(
            status_code=503,
            detail="privacy data discovery integrity validation failed",
        ) from exc
    except ops.PrivacyDataDiscoveryAdapterError as exc:
        raise HTTPException(
            status_code=503,
            detail="privacy data discovery external adapter or callback failed",
        ) from exc
    except ops.PrivacyDataDiscoveryError as exc:
        raise HTTPException(
            status_code=503,
            detail="privacy data discovery operation failed",
        ) from exc


def _limits(ops, body: ScanLimitsIn):
    return ops.ScanLimits(**body.model_dump())


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    _ops()
    tenant = _tenant_id()
    capabilities = await _runtime_capabilities(request, tenant)
    durable = capabilities["durable_outbox"]
    return {
        "schema": "lightwork.privacy-data-discovery-runtime-status.v1",
        "enabled": True,
        "tenant_bound": True,
        "runtime_source": capabilities["source"],
        "configured": capabilities["configured"],
        "ready": capabilities["ready"],
        "structured_provider_adapters": capabilities["structured"],
        "unstructured_provider_adapters": capabilities["unstructured"],
        "provider_adapter_list_truncated": capabilities["truncated"],
        "external_scan_execution": "explicit_execute_endpoint_only",
        "raw_data_returned": False,
        "live_provider_acceptance_verified": False,
        "completeness_claim": False,
        "status_probe_opened_store": capabilities["status_probe_opened_store"],
        "status_probe_invoked_provider": capabilities[
            "status_probe_invoked_provider"
        ],
        "callback_delivery": {
            "configured": capabilities["callback_configured"],
            "approved_reviews_only": True,
            "durable_outbox": durable,
            "data_map_target": capabilities["data_map_target"],
            "bounded_retry_worker_available": capabilities[
                "retry_worker_available"
            ],
            "automatic_retry": capabilities["automatic_retry"],
            "worker_scheduler_operational": capabilities[
                "scheduler_operational"
            ],
            "worker_scheduler_configured_for_tenant": capabilities[
                "scheduler_configured_for_tenant"
            ],
            "retry_execution_requires_worker_invocation": (
                capabilities["retry_worker_available"]
                and not capabilities["scheduler_operational"]
            ),
            "enqueue_failure_recovery": (
                "manual_approved_review_redelivery_required"
            ),
            "delivery_failure_recovery": (
                "automatic_bounded_retry_and_ambiguous_reconciliation"
                if capabilities["automatic_retry"]
                else (
                    "bounded_retry_on_worker_invocation_and_ambiguous_reconciliation"
                    if durable and capabilities["retry_worker_available"]
                    else "manual_redelivery_required"
                )
            ),
        },
        "worker_scheduler": capabilities["scheduler_status"],
    }


@router.get("/posture")
async def posture(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    ops = _ops()
    tenant = _tenant_id()
    capabilities = await _runtime_capabilities(request, tenant)
    result = await _call(ops, ops.PrivacyDataDiscoveryStore.privacy_posture)
    return {
        **_jsonable(result),
        "tenant_bound": bool(tenant),
        "callback_outbox_available": capabilities["durable_outbox"],
        "data_map_target_available": capabilities["data_map_target"],
        "bounded_retry_worker_available": capabilities[
            "retry_worker_available"
        ],
        "automatic_retry_available": capabilities["automatic_retry"],
        "worker_scheduler_operational": capabilities["scheduler_operational"],
        "worker_scheduler_configured_for_tenant": capabilities[
            "scheduler_configured_for_tenant"
        ],
        "worker_scheduler": capabilities["scheduler_status"],
        "posture_opened_store": False,
        "posture_invoked_provider": False,
        "live_provider_acceptance_verified": False,
    }


@router.put("/sources/{source_id}")
async def enroll_source(
    request: Request,
    source_id: ObjectPath,
    body: SourceEnrollmentIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority(request)
    await _setup_call(request, tenant, _validate_saved_source_references, body)
    result = await _call(
        ops,
        store.enroll_source,
        tenant,
        source_id=source_id,
        actor_ref=_actor_ref(request, tenant),
        **body.model_dump(),
    )
    return {
        **_jsonable(result),
        "credential_value_persisted": False,
        "external_side_effect": False,
    }


def _validate_saved_source_references(body):
    from maverick import privacy_discovery_credentials as credentials

    if body.credential_env.startswith("connection:"):
        credentials.resolve_connection(body.credential_env, provider=body.provider, origin=body.origin)
    if body.evidence_key_env.startswith("evidence-key:"):
        credentials.resolve_key(body.evidence_key_env)


async def _setup_call(request, tenant, function, *args, **kwargs):
    from maverick import connections
    from maverick.paths import tenant_scope

    from .auth import caller_principal

    try:
        with tenant_scope(tenant=tenant), connections.bind_principal(caller_principal(request)):
            return await run_in_threadpool(function, *args, **kwargs)
    except connections.ConnectionVersionConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except (RuntimeError, OSError) as exc:
        raise HTTPException(503, "Discovery setup is unavailable; no secret values are returned") from exc


def _setup_options(app, tenant):
    from maverick import connections, privacy_discovery_credentials

    from .privacy_data_discovery_adapters_composition import snapshot_for_tenant

    snapshot = snapshot_for_tenant(app, tenant, resolve_transport=False)
    providers = snapshot.registry.status()["descriptors"]
    enabled = {item["provider"] for item in providers}
    saved = [dict(name=row["name"], provider=row["connector"], origin=row["base_url"],
                  revision=row["revision"], reference=f"connection:{row['name']}:{row['revision']}")
             for row in connections.list_connections() if row["connector"] in enabled and row["has_token"]
             and connections._may_use(row, connections.current_principal())]
    return {"providers": providers, "connections": saved, "evidence_keys": privacy_discovery_credentials.list_keys(),
            "secrets_returned": False, "provider_contacted": False}


@router.get("/setup")
async def setup_options(request: Request):
    require_global_permission(request, "admin")
    _ops()
    return await _setup_call(request, _tenant_id(), _setup_options, request.app, _tenant_id())


@router.put("/evidence-keys/{name}")
async def create_evidence_key(request: Request, name: ObjectPath, body: EvidenceKeyIn):
    from maverick.privacy_discovery_credentials import create_or_rotate

    require_global_permission(request, "admin")
    _ops()
    result = await _setup_call(request, _tenant_id(), create_or_rotate, name, **body.model_dump())
    return {**result, "secret_returned": False, "sources_updated": False,
            "next_step": "Explicitly select this key version and save each source. Old key references cannot scan."}


def _test_source_access(app, tenant, store, source_id, expected_revision):
    import time

    from .privacy_data_discovery_adapters_composition import snapshot_for_tenant

    source = store.get_source(tenant, source_id)
    if source.revision != expected_revision or source.state != "active":
        raise ValueError("source changed or is inactive; reload it before testing access")
    _validate_saved_source_references(source)
    snapshot = snapshot_for_tenant(app, tenant)
    adapters = snapshot.registry.structured if source.kind == "structured" else snapshot.registry.unstructured
    adapter = adapters.get(source.provider)
    if adapter is None:
        raise ValueError("enable this source's stock provider adapter in Settings")
    limits = _ops().ScanLimits(max_records=1, max_files=1, max_bytes=1024 * 1024, max_seconds=30,
                              max_findings=1, max_fields_per_record=256, max_record_bytes=256 * 1024,
                              max_document_bytes=1024 * 1024)
    method = adapter.iter_rows if source.kind == "structured" else adapter.iter_documents
    iterator = iter(method(source=source, credential_env=source.credential_env, limits=limits, deadline=time.time() + 30))
    try:
        observed = next(iterator, None) is not None
    finally:
        close = getattr(iterator, "close", None)
        if callable(close):
            close()
    if store.get_source(tenant, source_id).revision != expected_revision:
        raise ValueError("source changed during access test; reload and test the current version")
    return {"access": "readable", "sample_present": observed, "source_revision": expected_revision,
            "provider_contacted": True, "raw_data_returned": False, "report_created": False,
            "coverage_verified": False, "customer_acceptance_verified": False}


@router.post("/sources/{source_id}/test-access")
async def test_source_access(request: Request, source_id: ObjectPath, body: TestAccessIn):
    require_global_permission(request, "admin")
    _, tenant, store = _authority(request)
    return await _setup_call(request, tenant, _test_source_access, request.app, tenant, store,
                             source_id, body.expected_revision)


@router.post("/sources/{source_id}/state")
async def set_source_state(
    request: Request,
    source_id: ObjectPath,
    body: SourceStateIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority(request)
    result = await _call(
        ops,
        store.set_source_state,
        tenant,
        source_id,
        actor_ref=_actor_ref(request, tenant),
        **body.model_dump(),
    )
    return _jsonable(result)


@router.get("/sources")
async def list_sources(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1_999),
) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    guard = _scan_guard(request, ops, tenant, store, permission="view")
    guard()
    rows = await _call(ops, store.list_sources, tenant, limit=limit + 1)
    guard()
    return {**_items(rows, limit), "permissions": {
        "operate": has_permission(request, "operate"),
        "admin": has_global_permission(request, "admin"),
        "audit": has_permission(request, "audit"),
    }}


@router.get("/sources/{source_id}")
async def source_detail(request: Request, source_id: ObjectPath) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    return _jsonable(await _call(ops, store.get_source, tenant, source_id))


@router.put("/schedules/{schedule_id}")
async def upsert_schedule(
    request: Request,
    schedule_id: ObjectPath,
    body: ScheduleIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority(request)
    payload = body.model_dump(exclude={"limits"})
    result = await _call(
        ops,
        store.upsert_schedule,
        tenant,
        schedule_id=schedule_id,
        limits=_limits(ops, body.limits),
        actor_ref=_actor_ref(request, tenant),
        **payload,
    )
    return _jsonable(result)


@router.post("/schedules/enqueue-due")
async def enqueue_due(request: Request, body: EnqueueDueIn) -> dict[str, Any]:
    require_permission(request, "operate")
    ops, tenant, store = _authority(request)
    rows = await _call(
        ops,
        store.enqueue_due,
        tenant,
        actor_ref=_actor_ref(request, tenant),
        limit=body.limit,
    )
    return {"items": [_jsonable(row) for row in rows], "enqueued": len(rows)}


@router.get("/schedules")
async def list_schedules(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1_999),
) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    rows = await _call(ops, store.list_schedules, tenant, limit=limit + 1)
    return _items(rows, limit)


@router.get("/schedules/{schedule_id}")
async def schedule_detail(request: Request, schedule_id: ObjectPath) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    return _jsonable(await _call(ops, store.get_schedule, tenant, schedule_id))


@router.post("/sources/{source_id}/jobs")
async def enqueue_manual_scan(
    request: Request,
    source_id: ObjectPath,
    body: ManualScanIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    ops, tenant, store = _authority(request)
    payload = body.model_dump(exclude={"limits"})
    result = await _call(
        ops,
        store.enqueue_scan,
        tenant,
        source_id,
        limits=_limits(ops, body.limits),
        actor_ref=_actor_ref(request, tenant),
        **payload,
    )
    return _jsonable(result)


@router.post("/jobs/claim")
async def claim_jobs(request: Request, body: ClaimIn) -> dict[str, Any]:
    require_permission(request, "operate")
    ops, tenant, store = _authority(request)
    rows = await _call(
        ops,
        store.claim_jobs,
        tenant,
        worker_id=_worker_ref(request, tenant),
        **body.model_dump(),
    )
    return {
        "items": [_jsonable(row) for row in rows],
        "lease_owner_bound_to_request_principal": True,
    }


@router.post("/jobs/{job_id}/execute")
async def execute_job(request: Request, job_id: ObjectPath) -> dict[str, Any]:
    """Execute one leased scan; injected adapters may perform external I/O."""

    require_global_permission(request, "admin")
    ops, tenant, store = _authority(request)
    job = await _call(ops, store.get_job, tenant, job_id)
    coordinator = await _call(ops, _coordinator, request, ops, tenant, store)
    from maverick import connections
    from maverick.paths import tenant_scope

    from .auth import caller_principal

    with tenant_scope(tenant=tenant), connections.bind_principal(caller_principal(request)):
        report = await _call(ops, coordinator.execute_job, job, worker_id=_worker_ref(request, tenant))
    return {
        "report": _report_payload(report),
        "external_side_effect": True,
        "provider_network_io_possible": True,
        "raw_data_returned": False,
        "live_provider_acceptance_verified": False,
        "deadline_contract": "cooperative_adapter_deadline_checked_between_items",
    }


def _scan_original(store, tenant, job_id, guard=None):
    if guard is not None:
        guard()
    job = store.get_job(tenant, job_id)
    report = store.report_for_job(tenant, job_id) if job.state == "complete" else None
    if job.state == "complete" and report is None:
        raise HTTPException(503, "The scan is marked done, but its saved report is unavailable. No scan was repeated.")
    if guard is not None:
        guard()
    return {"job": _jsonable(job), "report": _report_payload(report) if report else None,
            "scan_repeated": False, "provider_network_io_possible": False,
            "live_provider_acceptance_verified": False}


def _scan_guard(request, ops, tenant, store, *, source_id=None, source_sha256=None, permission="operate"):
    from . import workspace_tenants

    principal = caller_principal(request)
    selected = workspace_tenants.get_selection_binding(principal) if principal else None
    if selected and selected[0] not in {None, tenant}:
        raise HTTPException(409, "Your selected workspace changed. Reload this page before continuing.")

    def guard():
        require_principal(request)
        require_permission(request, permission)
        ops.require_enabled()
        if _tenant_id() != tenant or caller_principal(request) != principal:
            raise HTTPException(409, "Your account or workspace changed. Reload this page before continuing.")
        if principal and workspace_tenants.get_selection_binding(principal) != selected:
            raise HTTPException(409, "Your selected workspace changed. Reload this page before continuing.")
        if source_id is not None:
            source = store.get_source(tenant, source_id)
            if source.state != "active" or source.integrity_sha256 != source_sha256:
                raise ops.PrivacyDataDiscoveryConflict("This source changed or was paused after review. Refresh its selection before scanning.")
            if source.credential_env.startswith("connection:"):
                from maverick import connections
                from maverick.paths import tenant_scope
                from maverick.privacy_discovery_credentials import connection_present

                with tenant_scope(tenant=tenant), connections.bind_principal(principal):
                    if not connection_present(source.credential_env):
                        raise HTTPException(403, "This saved account changed or you no longer have access. Select an available account before scanning.")
            else:
                # Deployment-managed credentials retain their existing global
                # admin floor. Saved accounts use their native current grants.
                require_global_permission(request, "admin")
    return guard


def _run_reviewed_scan(request, ops, tenant, store, job_id, body):
    from maverick import connections
    from maverick.paths import tenant_scope

    current = store.get_job(tenant, job_id)
    source = store.get_source(tenant, current.source_id)
    guard = _scan_guard(request, ops, tenant, store, source_id=current.source_id,
                        source_sha256=body.expected_source_integrity_sha256)
    result_guard = _scan_guard(request, ops, tenant, store, permission="view")
    guard()
    if source.revision != body.expected_source_revision:
        raise ops.PrivacyDataDiscoveryConflict("This source changed after review. Refresh its selection before scanning.")
    worker = _worker_ref(request, tenant)
    coordinator = _coordinator(request, ops, tenant, store)
    job, first_attempt = store.claim_job(tenant, job_id, worker_id=worker,
        expected_revision=body.expected_revision, expected_source_revision=body.expected_source_revision,
        idempotency_key=body.idempotency_key, before_write=guard)
    if not first_attempt:
        return _scan_original(store, tenant, job_id, result_guard)
    try:
        with tenant_scope(tenant=tenant), connections.bind_principal(caller_principal(request)):
            coordinator.execute_job(job, worker_id=worker,
                expected_source_sha256=body.expected_source_integrity_sha256, before_effect=guard)
    except ops.PrivacyDataDiscoveryReadInterrupted as exc:
        if isinstance(exc.__cause__, HTTPException):
            raise exc.__cause__ from None
        raise
    except (ops.PrivacyDataDiscoveryConfigError, ops.PrivacyDataDiscoveryAdapterError,
            ops.PrivacyDataDiscoveryValidationError, ops.PrivacyDataDiscoveryConflict) as exc:
        code = ("credential_unavailable" if isinstance(exc, ops.PrivacyDataDiscoveryConfigError) else
                "adapter_error" if isinstance(exc, ops.PrivacyDataDiscoveryAdapterError) else
                "provider_contract_invalid" if isinstance(exc, ops.PrivacyDataDiscoveryValidationError) else "source_changed")
        try:
            store.fail_job(tenant, job_id, worker_id=worker, error_code=code)
        except ops.PrivacyDataDiscoveryLeaseLost:
            pass
        raise
    except ops.PrivacyDataDiscoveryLeaseLost:
        return _scan_original(store, tenant, job_id, result_guard)
    return {**_scan_original(store, tenant, job_id, result_guard), "provider_network_io_possible": True,
            "raw_data_returned": False}


@router.get("/jobs/{job_id}/result")
async def scan_result(request: Request, job_id: ObjectPath) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    guard = _scan_guard(request, ops, tenant, store, permission="view")
    return await _call(ops, _scan_original, store, tenant, job_id, guard)


@router.post("/jobs/{job_id}/run")
async def run_reviewed_scan(request: Request, job_id: ObjectPath, body: RunScanIn) -> dict[str, Any]:
    require_permission(request, "operate")
    ops, tenant, store = _authority(request)
    return await _call(ops, _run_reviewed_scan, request, ops, tenant, store, job_id, body)


@router.post("/jobs/{job_id}/cancel")
async def cancel_scan(request: Request, job_id: ObjectPath, body: CancelScanIn) -> dict[str, Any]:
    require_permission(request, "operate")
    ops, tenant, store = _authority(request)
    guard = _scan_guard(request, ops, tenant, store)
    return _jsonable(await _call(ops, store.cancel_job, tenant, job_id,
        expected_revision=body.expected_revision, actor_ref=_actor_ref(request, tenant),
        idempotency_key=body.idempotency_key, before_write=guard))


@router.post("/jobs/{job_id}/fail")
async def fail_job(
    request: Request,
    job_id: ObjectPath,
    body: FailJobIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    ops, tenant, store = _authority(request)
    result = await _call(
        ops,
        store.fail_job,
        tenant,
        job_id,
        worker_id=_worker_ref(request, tenant),
        **body.model_dump(),
    )
    return _jsonable(result)


@router.post("/jobs/{job_id}/replay")
async def replay_job(
    request: Request,
    job_id: ObjectPath,
    body: ReplayIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority(request)
    result = await _call(
        ops,
        store.replay_dead_letter,
        tenant,
        job_id,
        actor_ref=_actor_ref(request, tenant),
        **body.model_dump(),
    )
    return _jsonable(result)


@router.get("/jobs")
async def list_jobs(
    request: Request,
    state: JobState | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1_999),
) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    rows = await _call(ops, store.list_jobs, tenant, state=state, limit=limit + 1)
    return _items(rows, limit)


@router.get("/jobs/{job_id}")
async def job_detail(request: Request, job_id: ObjectPath) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    return _jsonable(await _call(ops, store.get_job, tenant, job_id))


@router.get("/inventory")
async def inventory(
    request: Request,
    source_id: str | None = Query(
        default=None,
        min_length=1,
        max_length=128,
        pattern=_ID,
    ),
) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    result = _jsonable(
        await _call(ops, store.inventory, tenant, source_id=source_id)
    )
    return {
        **result,
        "absence_is_proven": False,
        "approved_findings_only_are_authoritative_updates": True,
    }


@router.get("/reports/diff")
async def diff_reports(
    request: Request,
    base_report_id: str = Query(min_length=1, max_length=128, pattern=_ID),
    target_report_id: str = Query(min_length=1, max_length=128, pattern=_ID),
    limit: int = Query(default=1_000, ge=1, le=1_999),
) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    result = _jsonable(
        await _call(
            ops,
            store.diff_reports,
            tenant,
            base_report_id,
            target_report_id,
        )
    )
    added = result.pop("added_finding_sha256")
    removed = result.pop("removed_finding_sha256")
    return {
        **result,
        "added_finding_sha256": added[:limit],
        "removed_finding_sha256": removed[:limit],
        "added_count": len(added),
        "removed_count": len(removed),
        "truncated": len(added) > limit or len(removed) > limit,
        "absence_is_proven": False,
        "digest_only": True,
    }


@router.get("/reports")
async def list_reports(
    request: Request,
    source_id: str | None = Query(
        default=None,
        min_length=1,
        max_length=128,
        pattern=_ID,
    ),
    limit: int = Query(default=100, ge=1, le=1_999),
) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    rows = await _call(
        ops,
        store.list_reports,
        tenant,
        source_id=source_id,
        limit=limit + 1,
    )
    return {
        "items": [_report_payload(row) for row in rows[:limit]],
        "truncated": len(rows) > limit,
        "absence_is_proven": False,
    }


@router.get("/reports/{report_id}")
async def report_detail(request: Request, report_id: ObjectPath) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    return _report_payload(await _call(ops, store.get_report, tenant, report_id))


@router.get("/reports/{report_id}/findings")
async def list_findings(
    request: Request,
    report_id: ObjectPath,
    limit: int = Query(default=100, ge=1, le=1_999),
) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    rows = await _call(
        ops,
        store.list_findings,
        tenant,
        report_id=report_id,
        limit=limit + 1,
    )
    return {
        **_items(rows, limit),
        "digest_only_evidence": True,
        "raw_values_returned": False,
    }


@router.get("/findings/{finding_id}")
async def finding_detail(request: Request, finding_id: ObjectPath) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    return _jsonable(await _call(ops, store.get_finding, tenant, finding_id))


@router.post("/findings/{finding_id}/reviews")
async def propose_review(
    request: Request,
    finding_id: ObjectPath,
    body: ReviewProposalIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority(request)
    finding = await _call(ops, store.get_finding, tenant, finding_id)
    result = await _call(
        ops,
        store.propose_review,
        tenant,
        finding_id,
        evidence_sha256=finding.evidence_sha256,
        prepared_by=_reviewer_ref(request, tenant),
        **body.model_dump(),
    )
    return {
        **_jsonable(result),
        "evidence_bound_from_authoritative_finding": True,
        "prepared_by_request_principal": True,
        "data_map_callback_invoked": False,
    }


@router.get("/findings/{finding_id}/reviews")
async def list_reviews(
    request: Request,
    finding_id: ObjectPath,
    limit: int = Query(default=100, ge=1, le=1_999),
) -> dict[str, Any]:
    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    rows = await _call(
        ops,
        store.list_reviews,
        tenant,
        finding_id=finding_id,
        limit=limit + 1,
    )
    return _items(rows, limit)


@router.get("/reviews")
async def list_all_reviews(
    request: Request,
    status: Literal["pending", "approved"] | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1_999),
) -> dict[str, Any]:
    """Review proposals across every finding, newest first (approval queue)."""

    require_permission(request, "view")
    ops, tenant, store = _authority(request)
    rows = await _call(ops, store.list_all_reviews, tenant, status=status, limit=limit + 1)
    return _items(rows, limit)


@router.post("/reviews/{review_id}/approve")
async def approve_review(
    request: Request,
    review_id: ObjectPath,
    body: ReviewApprovalIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority(request)
    capabilities = await _runtime_capabilities(request, tenant)
    callback_configured = _callback_authority(request, tenant) is not None
    before = await _call(ops, store.get_review, tenant, review_id)
    callback_attempted = callback_configured and before.status == "pending"
    result = await _call(
        ops,
        store.approve_review,
        tenant,
        review_id,
        approved_by=_reviewer_ref(request, tenant),
        **body.model_dump(),
    )
    return {
        **_jsonable(result),
        "four_eyes_enforced": True,
        "approved_only_callback": True,
        "callback_configured": callback_configured,
        "callback_attempted_this_request": callback_attempted,
        "callback_acknowledged": True if callback_attempted else None,
        "callback_durable_outbox": capabilities["durable_outbox"],
        "callback_enqueued_durably": (
            True
            if callback_attempted and capabilities["durable_outbox"]
            else None
        ),
        "data_map_target_configured": capabilities["data_map_target"],
        "bounded_retry_worker_available": capabilities[
            "retry_worker_available"
        ],
        "automatic_retry_available": capabilities["automatic_retry"],
        "target_applied_synchronously": False,
    }


@router.post("/remediation/worker/run-once")
async def run_remediation_worker(
    request: Request,
    body: RemediationWorkerIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority(request)
    runtime = await _remediation_runtime(
        request,
        ops,
        tenant,
        store,
        principal_ref=_worker_ref(request, tenant),
    )
    result = await _remediation_call(
        runtime.worker.run_once,
        worker_id=_worker_ref(request, tenant),
        **body.model_dump(),
    )
    payload = _remediation_worker_payload(_jsonable(result))
    return {
        **payload,
        "tenant_bound": True,
        "bounded_batch": True,
        "approved_reviews_only": True,
        "digest_only_data_map_target": True,
        "external_side_effect": False,
        "local_state_write_possible": True,
        "provider_network_io": False,
        "provider_writes": False,
        "ambiguous_outcomes_retried_optimistically": False,
        "live_provider_acceptance_verified": False,
    }


@router.get("/remediation/work")
async def list_remediation_work(
    request: Request,
    state: RemediationState | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=100),
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority(request)
    runtime = await _remediation_runtime(
        request,
        ops,
        tenant,
        store,
        principal_ref=_actor_ref(request, tenant),
    )
    values = await _remediation_call(
        runtime.outbox.list_work,
        state=state,
        limit=limit + 1,
    )
    if not isinstance(values, (list, tuple)):
        raise HTTPException(
            status_code=503,
            detail="privacy discovery remediation work listing returned an invalid result",
        )
    items = [
        _remediation_work_payload(_jsonable(value))
        for value in values[:limit]
    ]
    return {
        "items": items,
        "truncated": len(values) > limit,
        "tenant_bound": True,
        "operational_metadata_only": True,
        "raw_data_returned": False,
        "external_side_effect": False,
        "local_state_write": False,
        "provider_network_io": False,
        "provider_writes": False,
        "live_provider_acceptance_verified": False,
    }


@router.post("/remediation/work/{work_id}/reconcile")
async def reconcile_remediation_work(
    request: Request,
    work_id: ObjectPath,
    body: RemediationReconcileIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority(request)
    runtime = await _remediation_runtime(
        request,
        ops,
        tenant,
        store,
        principal_ref=_actor_ref(request, tenant),
    )
    result = await _remediation_call(
        runtime.outbox.reconcile_ambiguous,
        work_id,
        reconciler=runtime.reconciler,
        **body.model_dump(),
    )
    payload = _remediation_reconciliation_payload(_jsonable(result), work_id)
    return {
        **payload,
        "tenant_bound": True,
        "digest_only_reconciliation": True,
        "external_side_effect": False,
        "local_state_write_possible": True,
        "provider_network_io": False,
        "provider_writes": False,
        "optimistic_replay_performed": False,
        "live_provider_acceptance_verified": False,
    }


@router.post("/remediation/maintenance")
async def maintain_remediation_runtime(
    request: Request,
    body: RemediationMaintenanceIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority(request)
    runtime = await _remediation_runtime(
        request,
        ops,
        tenant,
        store,
        principal_ref=_actor_ref(request, tenant),
    )
    result = await _remediation_call(
        runtime.maintenance,
        cutoff=time.time(),
        **body.model_dump(),
    )
    payload = _remediation_maintenance_payload(_jsonable(result))
    return {
        **payload,
        "tenant_bound": True,
        "cutoff_server_derived": True,
        "retention_bounded": True,
        "integrity_verified": True,
        "external_side_effect": False,
        "local_state_write_possible": True,
        "provider_network_io": False,
        "provider_writes": False,
        "live_provider_acceptance_verified": False,
    }


@router.get("/audit")
async def audit_events(
    request: Request,
    limit: int = Query(default=500, ge=1, le=999),
) -> dict[str, Any]:
    require_permission(request, "audit")
    ops, tenant, store = _authority(request)
    rows = await _call(ops, store.audit_events, tenant, limit=limit + 1)
    return _items(rows, limit)


@router.get("/audit/verify")
async def verify_audit(request: Request) -> dict[str, Any]:
    require_permission(request, "audit")
    ops, tenant, store = _authority(request)
    verified = await _call(ops, store.verify_audit_chain, tenant)
    return {"verified": bool(verified), "tenant_bound": True}


@router.post("/retention/purge")
async def purge_retention(request: Request, body: RetentionIn) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority(request)
    count = await _call(
        ops,
        store.purge_expired,
        tenant,
        actor_ref=_actor_ref(request, tenant),
        idempotency_key=body.idempotency_key,
    )
    return {
        "purged_reports": count,
        "raw_data_purged": False,
        "digest_only_audit_tombstones_retained": True,
    }


__all__ = ["router"]
