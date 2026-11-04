"""Tenant-bound operator API for governed third-party intelligence.

The HTTP boundary exposes the provider-neutral control plane only.  It accepts
credential *environment names*, encrypted profile references, digests, and
closed evidence contracts; it never accepts a tenant selector, caller-authored
actor identity, raw provider credentials, or raw vendor profile values.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import (
    require_global_permission,
    require_page_permission,
    require_permission,
    require_principal,
)
from .draft_api import context_for

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_ENV_PATTERN = r"^[A-Z][A-Z0-9_]{1,127}$"
_TERRITORY_PATTERN = r"^[A-Z][A-Z0-9-]{1,31}$"
_HTTPS_PATTERN = r"^https://[^\s]+$"

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
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN),
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
EnvironmentName = Annotated[
    str,
    StringConstraints(strict=True, min_length=2, max_length=128, pattern=_ENV_PATTERN),
]
Territory = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=2,
        max_length=32,
        pattern=_TERRITORY_PATTERN,
    ),
]
HttpsUri = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=9,
        max_length=2_048,
        pattern=_HTTPS_PATTERN,
    ),
]

SourceKind = Literal[
    "sanctions",
    "pep",
    "watchlist",
    "adverse_media",
    "cyber_posture",
    "breach_intelligence",
    "compliance",
    "performance",
]
SourcePurpose = Literal["screening", "monitoring", "risk_scoring", "edd", "exchange"]
Severity = Literal["informational", "low", "medium", "high", "critical"]
EDDSeverity = Literal["low", "medium", "high", "critical"]
DataAccessLevel = Literal["none", "limited", "standard", "sensitive"]
FindingDisposition = Literal["false_positive", "confirmed", "not_a_match", "escalated"]
RiskStatus = Literal["approved", "rejected", "human_review"]
EDDTaskStatus = Literal["open", "complete", "waived"]
EDDDecision = Literal["approved", "rejected", "escalated"]
RiskFactor = Literal[
    "inherent_risk",
    "criticality",
    "sanctions",
    "pep",
    "watchlist",
    "adverse_media",
    "cyber_posture",
    "breach_intelligence",
    "compliance",
    "performance",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CitationIn(_StrictModel):
    citation_id: OpaqueId
    title: str = Field(min_length=1, max_length=500)
    uri: HttpsUri
    pinpoint: str = Field(min_length=1, max_length=500)


class SourceIn(_StrictModel):
    provider: OpaqueId
    kind: SourceKind
    provenance_uri: HttpsUri
    credential_env: EnvironmentName
    license_ref: str = Field(min_length=1, max_length=1_024)
    rights_basis: str = Field(min_length=1, max_length=2_000)
    purposes: list[SourcePurpose] = Field(min_length=1, max_length=5)
    territories: list[Territory] = Field(min_length=1, max_length=1_000)
    retention_seconds: int = Field(ge=86_400, le=315_360_000)
    expected_revision: int = Field(default=0, ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class ApprovalIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    approved: bool
    rationale: str = Field(min_length=1, max_length=2_000)
    idempotency_key: IdempotencyKey


class PolicyApprovalIn(_StrictModel):
    approved: bool
    rationale: str = Field(min_length=1, max_length=2_000)
    idempotency_key: IdempotencyKey


class RevisionRationaleIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    rationale: str = Field(min_length=1, max_length=2_000)
    idempotency_key: IdempotencyKey


class SnapshotIn(_StrictModel):
    dataset_revision: OpaqueId
    observed_at: float = Field(gt=0, lt=100_000_000_000.0)
    valid_until: float = Field(gt=0, lt=100_000_000_000.0)
    completeness: float = Field(ge=0.0, le=1.0)
    record_count: int = Field(ge=0, le=2**63 - 1)
    evidence_sha256: Digest
    citations: list[CitationIn] = Field(min_length=1, max_length=100)
    provenance_uri: HttpsUri
    idempotency_key: IdempotencyKey


class VendorIn(_StrictModel):
    display_label: str = Field(min_length=1, max_length=300)
    entity_identity_sha256: Digest
    encrypted_profile_ref: OpaqueId
    profile_key_ref: OpaqueId
    territories: list[Territory] = Field(min_length=1, max_length=1_000)
    service_categories: list[OpaqueId] = Field(min_length=1, max_length=1_000)
    inherent_risk_level: int = Field(ge=1, le=5)
    criticality: int = Field(ge=1, le=5)
    data_access_level: DataAccessLevel
    expected_revision: int = Field(default=0, ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey
    register_vendor_id: OpaqueId | None = None


class RelationshipIn(_StrictModel):
    vendor_id: OpaqueId
    related_vendor_id: OpaqueId | None = None
    relationship_type: OpaqueId
    scope_ref: OpaqueId
    criticality: int = Field(ge=1, le=5)
    data_access_level: DataAccessLevel
    expected_revision: int = Field(default=0, ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class ScreeningRunIn(_StrictModel):
    vendor_id: OpaqueId
    subject_identity_sha256: Digest
    snapshot_bindings: dict[SourceKind, OpaqueId] = Field(min_length=1, max_length=8)
    requested_kinds: list[SourceKind] = Field(min_length=1, max_length=8)
    idempotency_key: IdempotencyKey


class FindingIn(_StrictModel):
    source_id: OpaqueId
    kind: SourceKind
    candidate_ref: OpaqueId
    match_confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    observed_at: float = Field(gt=0, lt=100_000_000_000.0)
    valid_until: float = Field(gt=0, lt=100_000_000_000.0)
    evidence_sha256: Digest
    citations: list[CitationIn] = Field(min_length=1, max_length=100)
    idempotency_key: IdempotencyKey


class FindingReviewIn(_StrictModel):
    disposition: FindingDisposition
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    rationale: str = Field(min_length=1, max_length=2_000)
    idempotency_key: IdempotencyKey


class RevisionIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class RiskPolicyIn(_StrictModel):
    required_source_kinds: list[SourceKind] = Field(min_length=1, max_length=8)
    maximum_source_age_seconds: int = Field(ge=60, le=31_536_000)
    minimum_completeness: float = Field(ge=0.0, le=1.0)
    factor_weights: dict[RiskFactor, int] = Field(min_length=10, max_length=10)
    maximum_autoapproval_score: int = Field(ge=0, le=100_000)
    allow_low_risk_autoapproval: bool
    allowed_territories: list[Territory] = Field(min_length=1, max_length=1_000)
    maximum_vendor_criticality: int = Field(ge=1, le=5)
    maximum_data_access_level: DataAccessLevel
    expected_latest_version: int = Field(default=0, ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class RiskEvaluationIn(_StrictModel):
    vendor_id: OpaqueId
    run_id: OpaqueId
    policy_id: OpaqueId
    policy_version: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class RiskOverrideIn(_StrictModel):
    status: RiskStatus
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    rationale: str = Field(min_length=1, max_length=2_000)
    idempotency_key: IdempotencyKey


class RiskRollbackIn(_StrictModel):
    restore_decision_id: OpaqueId
    rationale: str = Field(min_length=1, max_length=2_000)
    idempotency_key: IdempotencyKey


class EDDCaseIn(_StrictModel):
    vendor_id: OpaqueId
    reason: str = Field(min_length=1, max_length=2_000)
    severity: EDDSeverity
    idempotency_key: IdempotencyKey


class EDDTaskIn(_StrictModel):
    title: str = Field(min_length=1, max_length=500)
    assignee_ref: OpaqueId
    due_at: float = Field(gt=0, lt=100_000_000_000.0)
    status: EDDTaskStatus
    evidence_sha256: Digest | None = None
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class EDDEvidenceIn(_StrictModel):
    snapshot_id: OpaqueId
    evidence_sha256: Digest
    citations: list[CitationIn] = Field(min_length=1, max_length=100)
    summary: str = Field(min_length=1, max_length=2_000)
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class EDDDecisionIn(_StrictModel):
    decision: EDDDecision
    rationale: str = Field(min_length=1, max_length=2_000)
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class MonitorIn(_StrictModel):
    vendor_id: OpaqueId
    source_bindings: dict[SourceKind, OpaqueId] = Field(min_length=1, max_length=8)
    destination_ref: OpaqueId
    cadence_seconds: int = Field(ge=60, le=31_536_000)
    idempotency_key: IdempotencyKey


class ObservationIn(_StrictModel):
    snapshot_bindings: dict[SourceKind, OpaqueId] = Field(min_length=1, max_length=8)
    observation_sha256: Digest
    evidence_sha256: Digest
    citations: list[CitationIn] = Field(min_length=1, max_length=100)
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class ClaimOutboxIn(_StrictModel):
    limit: int = Field(default=10, ge=1, le=100)
    lease_seconds: float = Field(default=60.0, ge=1.0, le=3_600.0)


class RecipientIn(_StrictModel):
    name: str = Field(min_length=1, max_length=120)
    address: str = Field(min_length=3, max_length=320)
    external_use_reviewed: bool
    context: Digest
    idempotency_key: IdempotencyKey


class RecipientWithdrawIn(RevisionIn):
    context: Digest


class ReviewedDeliveryIn(_StrictModel):
    delivery_id: OpaqueId
    pin: Digest


class RunOutboxIn(_StrictModel):
    context: Digest
    review_sha256: Digest
    items: list[ReviewedDeliveryIn] = Field(min_length=1, max_length=10)
    limit: int = Field(default=10, ge=1, le=100)
    lease_seconds: float = Field(default=120.0, ge=1.0, le=3_600.0)
    base_backoff_seconds: float = Field(default=30.0, gt=0.0, le=604_800.0)
    maximum_backoff_seconds: float = Field(
        default=86_400.0,
        gt=0.0,
        le=604_800.0,
    )


class FailOutboxIn(_StrictModel):
    lease_token: Digest
    error_code: OpaqueId
    backoff_seconds: float = Field(gt=0.0, le=604_800.0)


class AcknowledgeOutboxIn(_StrictModel):
    lease_token: Digest


class ExchangeConsentIn(_StrictModel):
    vendor_id: OpaqueId
    audience: OpaqueId
    purpose: OpaqueId
    allowed_metrics: list[OpaqueId] = Field(min_length=1, max_length=100)
    explicit_consent: bool
    expires_at: float = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class ExchangeReviewIn(_StrictModel):
    inclusion_approved: bool
    privacy_review_ref: OpaqueId | None = None
    anonymity_proof_ref: OpaqueId | None = None
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    rationale: str = Field(min_length=1, max_length=2_000)
    idempotency_key: IdempotencyKey


class ExchangeContributionIn(_StrictModel):
    metric_id: OpaqueId
    value_band: OpaqueId
    audience: OpaqueId
    purpose: OpaqueId
    evidence_sha256: Digest
    lineage_refs: list[str] = Field(min_length=1, max_length=100)
    retention_seconds: int = Field(ge=86_400, le=315_360_000)
    idempotency_key: IdempotencyKey


class ExchangeQueryIn(_StrictModel):
    audience: OpaqueId
    purpose: OpaqueId
    metric_id: OpaqueId
    limit: int = Field(default=100, ge=1, le=500)


def _enabled() -> bool:
    from maverick import third_party_intelligence as ops

    return ops.enabled()


def third_party_intelligence_enabled_for_page() -> bool:
    """Return the exact config-gate state without opening the database."""

    return _enabled()


def _ops():
    from maverick import third_party_intelligence as ops

    try:
        ops.require_enabled()
    except ops.ThirdPartyIntelligenceConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return ops


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using third-party intelligence",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    principal = getattr(request.state, "principal", None)
    subject = str(getattr(principal, "sub", None) or "local-operator")
    digest = hashlib.sha256(
        (f"lightwork.third-party-intelligence.identity.v1:{tenant_id}:{subject}").encode()
    ).hexdigest()
    return f"tpi-principal-{digest[:32]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _default_store_for(tenant_id: str):
    from maverick.paths import data_dir
    from maverick.third_party_intelligence import ThirdPartyIntelligenceStore

    return ThirdPartyIntelligenceStore(
        data_dir(
            "third_party_management",
            "third-party-intelligence.sqlite3",
            tenant=tenant_id,
        )
    )


def _mail_access(request: Request, permission: str = "operate") -> str:
    require_principal(request)
    require_permission(request, permission)
    require_page_permission(request, "/third-party/intelligence")
    from .app import require_page_visible

    require_page_visible(request, "/third-party/intelligence")
    _ops()
    return _tenant_id()


def alert_setup_overview(request: Request) -> dict[str, Any]:
    """Current native authority for the protected, read-only recipient opener."""
    tenant = _mail_access(request)
    require_global_permission(request, "admin")
    factory = getattr(request.app.state, "third_party_intelligence_store_factory", None)
    store = factory(tenant_id=tenant, request=request) if callable(factory) else _default_store_for(tenant)
    recipients = store.list_alert_recipients(tenant)
    _mail_access(request)
    require_global_permission(request, "admin")
    return {"context": context_for(request), "saved_recipients": len(recipients)}


class ThirdPartyIntelligenceDependencies:
    """Explicit store factory seam for alternate runtimes and tests."""

    def __init__(self, *, store_for: Callable[[str], Any] = _default_store_for) -> None:
        self.store_for = store_for


def create_third_party_intelligence_router(  # noqa: C901, PLR0915
    dependencies: ThirdPartyIntelligenceDependencies | None = None,
) -> APIRouter:
    deps = dependencies or ThirdPartyIntelligenceDependencies()
    router = APIRouter(
        prefix="/third-party/intelligence",
        tags=["third-party-intelligence"],
    )

    def authority(request: Request):
        ops = _ops()
        tenant = _tenant_id()
        factory = getattr(
            request.app.state,
            "third_party_intelligence_store_factory",
            None,
        )
        try:
            store = (
                factory(tenant_id=tenant, request=request)
                if callable(factory)
                else deps.store_for(tenant)
            )
        except ops.ThirdPartyIntelligenceConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (ops.ThirdPartyIntelligenceError, OSError) as exc:
            raise HTTPException(
                status_code=503,
                detail="third-party intelligence store is unavailable",
            ) from exc
        if store is None:
            raise HTTPException(
                status_code=503,
                detail="third-party intelligence store is unavailable",
            )
        return ops, tenant, store

    async def call(ops, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.ThirdPartyIntelligenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ops.ThirdPartyIntelligencePermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ops.ThirdPartyIntelligenceConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ops.ThirdPartyIntelligenceValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ops.ThirdPartyIntelligenceConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ops.ThirdPartyIntelligenceIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="third-party intelligence integrity verification failed",
            ) from exc
        except ops.ThirdPartyIntelligenceError as exc:
            raise HTTPException(
                status_code=503,
                detail="third-party intelligence operation failed",
            ) from exc

    def mail_guard(request, tenant, *, context=None, admin=False):
        expected_context = context or context_for(request)
        actor = _principal(request, tenant)

        def check():
            if _mail_access(request) != tenant or _principal(request, tenant) != actor:
                raise HTTPException(409, "Your account or workspace changed. Reload the current controls.")
            if admin:
                require_global_permission(request, "admin")
            if not hmac.compare_digest(context_for(request), expected_context):
                raise HTTPException(409, "Your account or workspace changed. Reload the current controls.")
        check()
        return check

    def mail_review(request, tenant, store, selected=None):
        from maverick import mailer
        from maverick.governed_operations import digest
        from maverick.third_party_intelligence_delivery import _message

        ops_error = _ops()
        _mail_access(request)
        if not mailer.configured():
            raise HTTPException(409, "Set up a sending account in Settings → All settings → Email, then review the alerts again.")
        now = store._clock()
        if selected is None:
            items = store.ready_outbox(tenant, limit=10)
        else:
            if len(set(selected)) != len(selected):
                raise HTTPException(422, "Choose one distinct reviewed batch.")
            items = [store.get_outbox(tenant, delivery_id) for delivery_id in selected]
        values = []
        for item in items:
            if not ((item.state == "pending" and item.next_attempt_at <= now)
                    or (item.state == "leased" and float(item.lease_until or 0) <= now)):
                raise HTTPException(409, "One of these alerts was already reserved or sent. Reload its saved outcome before sending more.")
            alert = store.get_monitoring_alert(tenant, item.alert_id)
            monitor = store.get_monitor(tenant, alert.monitor_id)
            if monitor.state != "active":
                continue
            sources = [store.get_source(tenant, source_id) for source_id in monitor.source_bindings.values()]
            if any(source.state != "active" or "monitoring" not in source.purposes for source in sources):
                continue
            try:
                recipient = store.resolve_alert_recipient(tenant, item.destination_ref)
            except ops_error.ThirdPartyIntelligenceNotFound as exc:
                raise HTTPException(409, "An older watch has no saved recipient. Stop that watch and start it again with a saved recipient.") from exc
            except ops_error.ThirdPartyIntelligencePermissionDenied:
                continue
            values.append({"delivery_id": item.delivery_id, "pin": item.integrity_sha256,
                           "recipient": recipient["name"], "address": recipient["address"],
                           "recipient_pin": recipient["integrity_sha256"],
                           "monitor_id": monitor.monitor_id, "monitor_pin": monitor.integrity_sha256,
                           "alert_pin": alert.integrity_sha256,
                           "vendor_pin": store.get_vendor(tenant, alert.vendor_id).integrity_sha256,
                           "source_pins": {source.source_id: source.integrity_sha256 for source in sources},
                           "subject": "Lightwork third-party risk change",
                           "body": _message(store, item) + f"\n\nLightwork delivery reference: {item.delivery_id}\n"})
        scope = mailer.sending_scope()
        value = {"context": context_for(request), "items": values,
                 "sender": scope["from"] or scope["user"], "provider": scope["provider"].lower(),
                 "external_use": "Email leaves Lightwork. Each named recipient receives the vendor name, a change notice and saved review references. Licensed source contents are not attached. Accepted means the mail service accepted the message; it does not prove inbox receipt. Unconfirmed sends are retained and are not sent again automatically."}
        mail_guard(request, tenant, context=value["context"])()
        return {**value, "review_sha256": digest(value)}

    def provider_runtime(request: Request):
        runtime = getattr(
            request.app.state,
            "third_party_intelligence_provider_runtime",
            None,
        )
        if (
            runtime is None
            or not callable(getattr(runtime, "readiness", None))
            or not callable(getattr(runtime, "source_readiness", None))
            or not callable(getattr(runtime, "status", None))
        ):
            raise HTTPException(
                status_code=503,
                detail="third-party provider runtime is unavailable",
            )
        return runtime

    async def provider_readiness(
        request: Request,
        *,
        source_id: str | None = None,
        verify_secret: bool = False,
    ) -> dict[str, Any]:
        runtime = provider_runtime(request)
        tenant = _tenant_id()
        try:
            if source_id is None:
                result = await run_in_threadpool(
                    runtime.readiness,
                    tenant,
                    request=request,
                )
            else:
                result = await run_in_threadpool(
                    runtime.source_readiness,
                    tenant,
                    source_id,
                    request=request,
                    verify_secret=verify_secret,
                )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            candidate = str(exc)
            safe_codes = {
                "provider_allowlist_invalid",
                "provider_composition_invalid",
                "provider_configuration_invalid",
                "provider_configuration_unavailable",
                "provider_host_invalid",
                "provider_runtime_disabled",
                "provider_source_authority_invalid",
                "provider_source_authority_unavailable",
                "provider_source_not_approved_for_monitoring",
                "provider_source_not_found",
                "provider_tenant_scope_mismatch",
                "provider_tenant_scope_missing",
                "provider_timeout_invalid",
            }
            code = (
                candidate
                if candidate in safe_codes
                else "provider_runtime_unavailable"
            )
            if code == "provider_source_not_found":
                status_code = 404
            elif code in {
                "provider_runtime_disabled",
                "provider_source_not_approved_for_monitoring",
            }:
                status_code = 403
            else:
                status_code = 503
            raise HTTPException(
                status_code=status_code,
                detail=code,
            ) from exc
        if not isinstance(result, Mapping):
            raise HTTPException(
                status_code=503,
                detail="third-party provider readiness is unavailable",
            )
        return _jsonable(result)

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        tenant = _tenant_id()
        from maverick import mailer

        runtime_readiness: dict[str, Any]
        runtime_status: dict[str, Any]
        try:
            runtime = provider_runtime(request)
            runtime_readiness = await provider_readiness(request)
            raw_status = await run_in_threadpool(runtime.status)
            runtime_status = (
                _jsonable(raw_status)
                if isinstance(raw_status, Mapping)
                else {
                    "schema": "lightwork.third-party-feed-scheduler-status.v1",
                    "running": False,
                    "error_code": "scheduler_status_unavailable",
                }
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            runtime_readiness = {
                "schema": "lightwork.third-party-provider-runtime-readiness.v1",
                "enabled": False,
                "configured": False,
                "configuration_ready": False,
                "ready": False,
                "error_code": "provider_runtime_unavailable",
                "status_secret_resolution": False,
                "status_provider_network_io": False,
                "licensed_provider_credential_verified": False,
                "live_provider_acceptance_verified": False,
            }
            runtime_status = {
                "schema": "lightwork.third-party-feed-scheduler-status.v1",
                "running": False,
                "error_code": "scheduler_status_unavailable",
            }

        return {
            "schema": "lightwork.third-party-intelligence-status.v1",
            "enabled": _enabled(),
            "principal_ref": _principal(request, tenant),
            "bundled_corpus": False,
            "live_feed_configured": False,
            "provider_acceptance_verified": False,
            "external_operations_accepted": False,
            "status_request_external_network_io": False,
            "provider_runtime": runtime_readiness,
            "provider_scheduler": runtime_status,
            "provider_composition_configured": (
                runtime_readiness.get("configured") is True
            ),
            "provider_configuration_ready": (
                runtime_readiness.get("configuration_ready") is True
            ),
            "provider_source_credential_checked": False,
            "outbound_delivery_runs_only_on_explicit_post": True,
            "delivery_destination_resolver_configured": True,
            "smtp_sender_configured": mailer.configured(),
            "raw_credentials_accepted": False,
            "raw_profile_values_accepted": False,
            "silent_pep_sanctions_adverse_dismissal_allowed": False,
            "low_risk_autoapproval_requires_approved_policy": True,
            "low_risk_autoapproval_requires_complete_fresh_evidence": True,
            "exchange_anonymity_assumed": False,
            "exchange_privacy_assumed": False,
            "limits": {
                "source_kinds": 8,
                "citations_per_evidence": 100,
                "retention_seconds_minimum": 86_400,
                "retention_seconds_maximum": 315_360_000,
                "outbox_claim_limit": 100,
                "outbox_lease_seconds_maximum": 3_600,
                "exchange_query_limit": 500,
            },
        }

    @router.get("/provider-runtime/status")
    async def provider_runtime_status(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        readiness = await provider_readiness(request)
        runtime = provider_runtime(request)
        try:
            raw_scheduler = await run_in_threadpool(runtime.status)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raw_scheduler = None
        readiness["scheduler"] = (
            _jsonable(raw_scheduler)
            if isinstance(raw_scheduler, Mapping)
            else {
                "schema": "lightwork.third-party-feed-scheduler-status.v1",
                "running": False,
                "error_code": "scheduler_status_unavailable",
            }
        )
        return readiness

    @router.post("/provider-runtime/sources/{source_id}/readiness")
    async def provider_source_readiness(
        request: Request,
        source_id: ObjectPath,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        return await provider_readiness(
            request,
            source_id=source_id,
            verify_secret=True,
        )

    # ---- read-only lists for the page (records load on open) -------------

    def _lister(name: str, method: str):
        async def listing(request: Request) -> dict[str, Any]:
            require_permission(request, "view")
            ops, tenant, store = authority(request)
            return {"items": _jsonable(await call(ops, getattr(store, method), tenant, limit=500))}

        listing.__name__ = f"list_{name}"
        return listing

    for _path, _name, _method in (
        ("/sources", "sources", "list_sources"),
        ("/snapshots", "snapshots", "list_source_snapshots"),
        ("/vendors", "vendors", "list_vendors"),
        ("/screening/runs", "screening_runs", "list_screening_runs"),
        ("/risk/policies", "risk_policies", "list_risk_policies"),
        ("/risk/decisions", "risk_decisions", "list_risk_decisions"),
        ("/edd/cases", "edd_cases", "list_edd_cases"),
        ("/monitors", "monitors", "list_monitors"),
        ("/monitoring/alerts", "monitoring_alerts", "list_monitoring_alerts"),
        ("/exchange/consents", "exchange_consents", "list_exchange_consents"),
    ):
        router.add_api_route(_path, _lister(_name, _method), methods=["GET"])

    @router.get("/me")
    async def me(request: Request) -> dict[str, Any]:
        """This person's intelligence reference, so the page can tell which
        records they created (and so cannot approve themselves)."""
        require_permission(request, "view")
        return {"principal_ref": _principal(request, _tenant_id())}

    @router.put("/sources/{source_id}")
    async def enroll_source(
        request: Request, source_id: ObjectPath, body: SourceIn
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.enroll_source,
                tenant,
                source_id=source_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.get("/sources/{source_id}")
    async def source_detail(request: Request, source_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_source, tenant, source_id))

    @router.post("/sources/{source_id}/approval")
    async def approve_source(
        request: Request, source_id: ObjectPath, body: ApprovalIn
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.approve_source,
                tenant,
                source_id,
                approver_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.post("/sources/{source_id}/revoke")
    async def revoke_source(
        request: Request, source_id: ObjectPath, body: RevisionRationaleIn
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.revoke_source,
                tenant,
                source_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.put("/sources/{source_id}/snapshots/{snapshot_id}")
    async def record_snapshot(
        request: Request,
        source_id: ObjectPath,
        snapshot_id: ObjectPath,
        body: SnapshotIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.record_source_snapshot,
                tenant,
                source_id,
                snapshot_id=snapshot_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.get("/snapshots/{snapshot_id}")
    async def snapshot_detail(request: Request, snapshot_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_source_snapshot, tenant, snapshot_id))

    @router.put("/vendors/{vendor_id}")
    async def upsert_vendor(
        request: Request, vendor_id: ObjectPath, body: VendorIn
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        actor = _principal(request, tenant)
        from .vendor_profile import effect_guard
        guard = effect_guard(request, tenant, actor, family="intelligence")
        return _jsonable(
            await call(
                ops,
                store.upsert_vendor,
                tenant,
                vendor_id=vendor_id,
                owner_ref=actor,
                actor_ref=actor,
                effect_guard=guard,
                **body.model_dump(),
            )
        )

    @router.get("/vendors/{vendor_id}")
    async def vendor_detail(request: Request, vendor_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_vendor, tenant, vendor_id))

    @router.put("/relationships/{relationship_id}")
    async def upsert_relationship(
        request: Request,
        relationship_id: ObjectPath,
        body: RelationshipIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.upsert_relationship,
                tenant,
                relationship_id=relationship_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.get("/relationships/{relationship_id}")
    async def relationship_detail(request: Request, relationship_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_relationship, tenant, relationship_id))

    @router.get("/vendors/{vendor_id}/relationships")
    async def vendor_relationships(request: Request, vendor_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        rows = await call(ops, store.list_relationships, tenant, vendor_id)
        return {"items": _jsonable(rows), "count": len(rows)}

    @router.put("/screening/runs/{run_id}")
    async def start_screening(
        request: Request, run_id: ObjectPath, body: ScreeningRunIn
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.start_screening_run,
                tenant,
                run_id=run_id,
                initiated_by=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.get("/screening/runs/{run_id}")
    async def screening_detail(request: Request, run_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_screening_run, tenant, run_id))

    @router.put("/screening/runs/{run_id}/findings/{finding_id}")
    async def record_finding(
        request: Request,
        run_id: ObjectPath,
        finding_id: ObjectPath,
        body: FindingIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.record_finding,
                tenant,
                run_id,
                finding_id=finding_id,
                detected_by=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.get("/screening/findings/{finding_id}")
    async def finding_detail(request: Request, finding_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_finding, tenant, finding_id))

    @router.get("/screening/runs/{run_id}/findings")
    async def findings_for_run(request: Request, run_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        rows = await call(ops, store.list_findings, tenant, run_id)
        return {"items": _jsonable(rows), "count": len(rows)}

    @router.post("/screening/findings/{finding_id}/review")
    async def review_finding(
        request: Request, finding_id: ObjectPath, body: FindingReviewIn
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.review_finding,
                tenant,
                finding_id,
                reviewer_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.post("/screening/runs/{run_id}/complete")
    async def complete_screening(
        request: Request, run_id: ObjectPath, body: RevisionIn
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.complete_screening_run,
                tenant,
                run_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.put("/risk/policies/{policy_id}")
    async def create_policy(
        request: Request, policy_id: ObjectPath, body: RiskPolicyIn
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.create_risk_policy,
                tenant,
                policy_id=policy_id,
                authored_by=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.get("/risk/policies/{policy_id}/versions/{version}")
    async def policy_detail(
        request: Request,
        policy_id: ObjectPath,
        version: int = ApiPath(ge=1, le=2**31 - 1),
    ) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_risk_policy, tenant, policy_id, version))

    @router.post("/risk/policies/{policy_id}/versions/{version}/approval")
    async def approve_policy(
        request: Request,
        policy_id: ObjectPath,
        body: PolicyApprovalIn,
        version: int = ApiPath(ge=1, le=2**31 - 1),
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.approve_risk_policy,
                tenant,
                policy_id,
                version,
                approver_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.put("/risk/decisions/{decision_id}/evaluate")
    async def evaluate_risk(
        request: Request, decision_id: ObjectPath, body: RiskEvaluationIn
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.evaluate_risk,
                tenant,
                decision_id=decision_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.get("/risk/decisions/{decision_id}")
    async def risk_decision_detail(request: Request, decision_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_risk_decision, tenant, decision_id))

    @router.post("/risk/decisions/{decision_id}/overrides/{override_decision_id}")
    async def override_risk(
        request: Request,
        decision_id: ObjectPath,
        override_decision_id: ObjectPath,
        body: RiskOverrideIn,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.override_risk_decision,
                tenant,
                decision_id,
                override_decision_id=override_decision_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.post("/risk/decisions/{decision_id}/rollbacks/{rollback_decision_id}")
    async def rollback_risk(
        request: Request,
        decision_id: ObjectPath,
        rollback_decision_id: ObjectPath,
        body: RiskRollbackIn,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.rollback_risk_decision,
                tenant,
                decision_id,
                rollback_decision_id=rollback_decision_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.put("/edd/cases/{case_id}")
    async def open_edd(request: Request, case_id: ObjectPath, body: EDDCaseIn) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.open_edd_case,
                tenant,
                case_id=case_id,
                opened_by=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.get("/edd/cases/{case_id}")
    async def edd_detail(request: Request, case_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_edd_case, tenant, case_id))

    @router.put("/edd/cases/{case_id}/tasks/{task_id}")
    async def set_edd_task(
        request: Request,
        case_id: ObjectPath,
        task_id: ObjectPath,
        body: EDDTaskIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.set_edd_task,
                tenant,
                case_id,
                task_id=task_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.put("/edd/cases/{case_id}/evidence/{evidence_id}")
    async def add_edd_evidence(
        request: Request,
        case_id: ObjectPath,
        evidence_id: ObjectPath,
        body: EDDEvidenceIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.add_edd_evidence,
                tenant,
                case_id,
                evidence_id=evidence_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.post("/edd/cases/{case_id}/decision")
    async def decide_edd(
        request: Request, case_id: ObjectPath, body: EDDDecisionIn
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.decide_edd_case,
                tenant,
                case_id,
                reviewer_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.put("/monitors/{monitor_id}")
    async def create_monitor(
        request: Request, monitor_id: ObjectPath, body: MonitorIn
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        await call(ops, store.resolve_alert_recipient, tenant, body.destination_ref)
        return _jsonable(
            await call(
                ops,
                store.create_monitor,
                tenant,
                monitor_id=monitor_id,
                created_by=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.get("/monitors/{monitor_id}")
    async def monitor_detail(request: Request, monitor_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_monitor, tenant, monitor_id))

    @router.get("/monitoring/due")
    async def due_monitors(
        request: Request,
        limit: int = Query(default=100, ge=1, le=100),
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        rows = await call(ops, store.due_monitors, tenant, limit=limit)
        return {"items": _jsonable(rows), "count": len(rows)}

    @router.post("/monitors/{monitor_id}/observations")
    async def record_observation(
        request: Request, monitor_id: ObjectPath, body: ObservationIn
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.record_monitor_observation,
                tenant,
                monitor_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.get("/monitoring/alerts/{alert_id}")
    async def alert_detail(request: Request, alert_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_monitoring_alert, tenant, alert_id))

    @router.get("/alert-recipients")
    async def alert_recipients(request: Request, response: Response) -> dict[str, Any]:
        _mail_access(request)
        ops, tenant, store = authority(request)
        response.headers["Cache-Control"] = "private, no-store"
        rows = await call(ops, store.list_alert_recipients, tenant)
        mail_guard(request, tenant)()
        return {"context": context_for(request), "items": rows, "count": len(rows)}

    @router.get("/alert-recipients/{recipient_id}")
    async def alert_recipient(request: Request, recipient_id: ObjectPath, response: Response) -> dict[str, Any]:
        _mail_access(request)
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        response.headers["Cache-Control"] = "private, no-store"
        result = await call(ops, store.get_alert_recipient, tenant, recipient_id)
        mail_guard(request, tenant, admin=True)()
        return _jsonable(result)

    @router.put("/alert-recipients/{recipient_id}")
    async def save_alert_recipient(request: Request, recipient_id: ObjectPath, body: RecipientIn) -> dict[str, Any]:
        _mail_access(request)
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        guard = mail_guard(request, tenant, context=body.context, admin=True)
        return await call(ops, store.save_alert_recipient, tenant, recipient_id=recipient_id,
                          actor_ref=_principal(request, tenant), effect_guard=guard,
                          **body.model_dump(exclude={"context"}))

    @router.post("/alert-recipients/{recipient_id}/withdraw")
    async def withdraw_alert_recipient(request: Request, recipient_id: ObjectPath, body: RecipientWithdrawIn) -> dict[str, Any]:
        _mail_access(request)
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        guard = mail_guard(request, tenant, context=body.context, admin=True)
        return await call(ops, store.withdraw_alert_recipient, tenant, recipient_id,
                          actor_ref=_principal(request, tenant), effect_guard=guard,
                          **body.model_dump(exclude={"context"}))

    @router.get("/outbox")
    async def outbox(request: Request, response: Response) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        response.headers["Cache-Control"] = "private, no-store"
        rows = await call(ops, store.list_outbox, tenant)
        return {"items": [{key: value for key, value in _jsonable(row).items() if key != "lease_token"}
                          for row in rows], "count": len(rows), "limit": 500}

    @router.get("/outbox/review")
    async def outbox_review(request: Request, response: Response) -> dict[str, Any]:
        _mail_access(request)
        ops, tenant, store = authority(request)
        response.headers["Cache-Control"] = "private, no-store"
        return await call(ops, mail_review, request, tenant, store)

    @router.post("/outbox/claim")
    async def claim_outbox(request: Request, body: ClaimOutboxIn) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        rows = await call(
            ops,
            store.claim_outbox,
            tenant,
            worker_id=_principal(request, tenant),
            **body.model_dump(),
        )
        return {"items": _jsonable(rows), "count": len(rows)}

    @router.post("/outbox/run")
    async def run_outbox(
        request: Request,
        body: RunOutboxIn,
    ) -> dict[str, Any]:
        """Run the explicit external alert-delivery side-effect boundary."""

        _mail_access(request)
        ops, tenant, store = authority(request)
        from maverick import mailer
        from maverick import third_party_intelligence_delivery as delivery

        ids = tuple(item.delivery_id for item in body.items)
        pins = {item.delivery_id: item.pin for item in body.items}
        access = mail_guard(request, tenant, context=body.context)
        reviewed = await call(ops, mail_review, request, tenant, store, ids)
        if (reviewed["review_sha256"] != body.review_sha256 or reviewed["context"] != body.context
                or {item["delivery_id"]: item["pin"] for item in reviewed["items"]} != pins):
            raise HTTPException(409, "The alerts, recipients or source permissions changed. Review the current alerts before sending.")
        reviewed_items = {item["delivery_id"]: item for item in reviewed["items"]}
        sender_scope = mailer.sending_scope()

        def resolver(current_tenant, reference):
            access()
            if current_tenant != tenant:
                raise HTTPException(403, "The alert belongs to a different workspace.")
            return store.resolve_alert_recipient(tenant, reference)["address"]

        def claim_guard():
            access()
            current = mail_review(request, tenant, store, ids)
            if current["review_sha256"] != body.review_sha256:
                raise HTTPException(409, "This reviewed batch changed before sending. Review the current alerts.")

        def effect_guard(item):
            access()
            saved = reviewed_items[item.delivery_id]
            recipient = store.resolve_alert_recipient(tenant, item.destination_ref)
            alert = store.get_monitoring_alert(tenant, item.alert_id)
            monitor = store.get_monitor(tenant, alert.monitor_id)
            if (recipient["integrity_sha256"] != saved["recipient_pin"]
                    or alert.integrity_sha256 != saved["alert_pin"]
                    or monitor.integrity_sha256 != saved["monitor_pin"]
                    or store.get_vendor(tenant, alert.vendor_id).integrity_sha256 != saved["vendor_pin"]
                    or mailer.sending_scope() != sender_scope
                    or any(store.get_source(tenant, source).integrity_sha256 != pin
                           for source, pin in saved["source_pins"].items())):
                raise HTTPException(409, "The reviewed recipient, sending account or source permission changed before sending.")

        transport = (
            getattr(
                request.app.state,
                "third_party_intelligence_delivery_transport",
                None,
            )
            or delivery.SmtpThirdPartyAlertTransport()
        )
        try:
            result = await run_in_threadpool(
                delivery.deliver_alert_batch,
                store,
                tenant_id=tenant,
                worker_id=_principal(request, tenant),
                resolve_destination=resolver,
                transport=transport,
                delivery_ids=ids, claim_guard=claim_guard, effect_guard=effect_guard,
                **body.model_dump(exclude={"items", "context", "review_sha256"}),
            )
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ops.ThirdPartyIntelligenceError as exc:
            raise HTTPException(
                status_code=503,
                detail="third-party-intelligence delivery batch failed",
            ) from exc
        return _jsonable(result)

    @router.post("/outbox/{delivery_id}/fail")
    async def fail_outbox(
        request: Request, delivery_id: ObjectPath, body: FailOutboxIn
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.fail_outbox,
                tenant,
                delivery_id,
                **body.model_dump(),
            )
        )

    @router.post("/outbox/{delivery_id}/acknowledge")
    async def acknowledge_outbox(
        request: Request,
        delivery_id: ObjectPath,
        body: AcknowledgeOutboxIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.acknowledge_outbox,
                tenant,
                delivery_id,
                **body.model_dump(),
            )
        )

    @router.post("/monitors/{monitor_id}/revoke")
    async def revoke_monitor(
        request: Request, monitor_id: ObjectPath, body: RevisionIn
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.revoke_monitor,
                tenant,
                monitor_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.put("/exchange/consents/{consent_id}")
    async def create_exchange_consent(
        request: Request, consent_id: ObjectPath, body: ExchangeConsentIn
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.create_exchange_consent,
                tenant,
                consent_id=consent_id,
                granted_by=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.get("/exchange/consents/{consent_id}")
    async def exchange_consent_detail(request: Request, consent_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_exchange_consent, tenant, consent_id))

    @router.post("/exchange/consents/{consent_id}/review")
    async def review_exchange_consent(
        request: Request, consent_id: ObjectPath, body: ExchangeReviewIn
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.review_exchange_consent,
                tenant,
                consent_id,
                reviewer_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.put("/exchange/consents/{consent_id}/contributions/{contribution_id}")
    async def contribute_exchange(
        request: Request,
        consent_id: ObjectPath,
        contribution_id: ObjectPath,
        body: ExchangeContributionIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.contribute_exchange,
                tenant,
                consent_id,
                contribution_id=contribution_id,
                contributed_by=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.get("/exchange/contributions/{contribution_id}")
    async def contribution_detail(request: Request, contribution_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.get_exchange_contribution,
                tenant,
                contribution_id,
            )
        )

    @router.post("/exchange/query")
    async def query_exchange(request: Request, body: ExchangeQueryIn) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        rows = await call(
            ops,
            store.query_exchange,
            tenant,
            principal_ref=_principal(request, tenant),
            **body.model_dump(),
        )
        return {
            "items": _jsonable(rows),
            "count": len(rows),
            "anonymity_independently_proven_for_every_item": bool(rows)
            and all(item.anonymous for item in rows),
            "privacy_independently_reviewed_for_every_item": bool(rows)
            and all(item.privacy_reviewed for item in rows),
        }

    @router.post("/exchange/consents/{consent_id}/withdraw")
    async def withdraw_exchange_consent(
        request: Request, consent_id: ObjectPath, body: RevisionRationaleIn
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.withdraw_exchange_consent,
                tenant,
                consent_id,
                actor_ref=_principal(request, tenant),
                **body.model_dump(),
            )
        )

    @router.post("/retention/purge")
    async def purge_retention(request: Request) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.purge_expired,
                tenant,
                actor_ref=_principal(request, tenant),
            )
        )

    @router.get("/integrity")
    async def verify_integrity(request: Request) -> dict[str, Any]:
        require_global_permission(request, "audit")
        ops, tenant, store = authority(request)
        result = _jsonable(await call(ops, store.verify_integrity, tenant))
        result["valid"] = True
        return result

    return router


router = create_third_party_intelligence_router()

__all__ = [
    "ThirdPartyIntelligenceDependencies",
    "create_third_party_intelligence_router",
    "router",
    "third_party_intelligence_enabled_for_page",
]
