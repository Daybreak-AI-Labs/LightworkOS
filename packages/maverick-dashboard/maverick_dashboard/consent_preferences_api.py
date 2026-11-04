"""Consumer Consent & Preferences REST surface.

This is deliberately separate from ``maverick.safety.consent``.  That module
authorizes risky agent actions; this router operates the consumer privacy data
plane: version-bound consent receipts, preference profiles, privacy signals,
tracker governance, enforcement decisions, and replayable downstream sync.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import asdict, is_dataclass
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission


def _limits() -> dict[str, int]:
    """``[consent_preferences.limits]`` values that are set and in bounds."""
    try:
        from maverick.config import load_config

        consent = (load_config() or {}).get("consent_preferences")
    except Exception:  # an unreadable config keeps the built-in limits
        return {}
    section = consent.get("limits") if isinstance(consent, dict) else None
    selected: dict[str, int] = {}
    for key, (lower, upper) in (("profile_page_size", (1, 500)),
                                ("receipt_page_size", (1, 500)),
                                ("request_body_bytes", (1_024, 1_048_576))):
        value = section.get(key) if isinstance(section, dict) else None
        if isinstance(value, int) and not isinstance(value, bool) and lower <= value <= upper:
            selected[key] = value
    return selected


def _page(requested: int | None, key: str, default: int) -> int:
    """A page size: the installation's size is the default and the most allowed."""
    configured = _limits().get(key)
    if requested is None:
        return configured or default
    return min(requested, configured) if configured else requested


async def _bounded_body(request: Request) -> None:
    """Refuse bodies above the installation's limit, when one is set."""
    if request.method not in {"POST", "PUT", "PATCH"}:
        return
    limit = _limits().get("request_body_bytes")
    if limit is None:
        return
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail="request body too large")
    if len(await request.body()) > limit:
        raise HTTPException(status_code=413, detail="request body too large")


router = APIRouter(prefix="/consent", tags=["consent-preferences"],
                   dependencies=[Depends(_bounded_body)])

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConsentContextIn(_StrictModel):
    jurisdiction: str = Field(..., min_length=1, max_length=80)
    country_code: str = Field(..., min_length=2, max_length=2)
    region_code: str = Field("", max_length=16)
    collection_point: str = Field("web", min_length=1, max_length=40)
    asserted_source: str = Field("client", min_length=1, max_length=80)

    @field_validator("country_code")
    @classmethod
    def _country_upper(cls, value: str) -> str:
        return value.upper()


class PreferenceChoiceIn(_StrictModel):
    purpose_id: str = Field(..., pattern=_ID_PATTERN)
    action: Literal["grant", "deny", "revoke", "withdraw"]
    channel: str = Field("all", pattern=_ID_PATTERN)
    vendor_id: str = Field("all", pattern=_ID_PATTERN)
    expires_at: float | None = Field(default=None, gt=0)


class PublishPolicyIn(_StrictModel):
    policy_id: str = Field(..., pattern=_ID_PATTERN)
    version: int = Field(..., ge=1)
    purposes: dict[str, str] = Field(..., min_length=1, max_length=128)
    notice_sha256: str = Field(..., pattern=_SHA256_PATTERN)
    effective_at: float = Field(..., gt=0)
    expires_at: float | None = Field(default=None, gt=0)
    expected_current_version: int | None = Field(default=None, ge=1)

    @field_validator("purposes")
    @classmethod
    def _purposes_are_bounded(cls, value: dict[str, str]) -> dict[str, str]:
        for purpose_id, lawful_basis in value.items():
            if not purpose_id or len(purpose_id) > 128:
                raise ValueError("purpose id is invalid")
            if not lawful_basis or len(lawful_basis) > 120:
                raise ValueError("lawful basis is invalid")
        return value


class CreateProfileIn(_StrictModel):
    profile_id: str = Field(..., pattern=_ID_PATTERN)
    identity_kind: Literal["known", "anonymous"]
    subject_sha256: str = Field(..., pattern=_SHA256_PATTERN)
    idempotency_key: str = Field(..., min_length=1, max_length=192)


class LookupProfilesIn(_StrictModel):
    profile_ids: list[str] = Field(..., min_length=1, max_length=100)


def _profile_context(request: Request, *, continuation: bool = False) -> str:
    from .draft_api import context_for

    current = context_for(request)
    expected = request.headers.get("X-Lightwork-Profile-Context")
    if ((expected is not None and (len(expected) != 64 or not expected.isascii() or not hmac.compare_digest(expected, current)))
            or (continuation and expected is None)):
        raise HTTPException(409, "Your account or workspace changed. Reload the page before choosing people.")
    return current


class LinkProfilesIn(_StrictModel):
    known_profile_id: str = Field(..., pattern=_ID_PATTERN)
    anonymous_profile_id: str = Field(..., pattern=_ID_PATTERN)
    expected_known_revision: int = Field(..., ge=0)
    expected_anonymous_revision: int = Field(..., ge=0)
    idempotency_key: str = Field(..., min_length=1, max_length=192)


class RecordPreferencesIn(_StrictModel):
    policy_id: str = Field(..., pattern=_ID_PATTERN)
    policy_version: int = Field(..., ge=1)
    context: ConsentContextIn
    choices: list[PreferenceChoiceIn] = Field(..., min_length=1, max_length=128)
    expected_revision: int = Field(..., ge=0)
    idempotency_key: str = Field(..., min_length=1, max_length=192)
    retention_until: float | None = Field(default=None, gt=0)


class PrivacySignalIn(_StrictModel):
    signal: Literal["gpc", "dnt"]
    purposes: list[str] = Field(..., min_length=1, max_length=128)
    policy_id: str = Field(..., pattern=_ID_PATTERN)
    policy_version: int = Field(..., ge=1)
    context: ConsentContextIn
    expected_revision: int = Field(..., ge=0)
    idempotency_key: str = Field(..., min_length=1, max_length=192)


class TrackerIn(_StrictModel):
    kind: Literal["web_tracker", "mobile_sdk"]
    vendor_id: str = Field(..., pattern=_ID_PATTERN)
    purpose_ids: list[str] = Field(..., min_length=1, max_length=128)
    status: Literal["approved", "blocked", "retired"]
    expected_revision: int = Field(0, ge=0)
    idempotency_key: str = Field(..., min_length=1, max_length=192)


class TrackerObservationIn(_StrictModel):
    asset_ref: str = Field(..., pattern=_ID_PATTERN)
    tracker_id: str = Field(..., pattern=_ID_PATTERN)
    location_ref: str = Field(..., min_length=1, max_length=512)
    evidence_sha256: str = Field(..., pattern=_SHA256_PATTERN)


class ScanIn(_StrictModel):
    scan_id: str = Field(..., pattern=_ID_PATTERN)
    observations: list[TrackerObservationIn] = Field(
        ..., min_length=1, max_length=512
    )
    observed_at: float = Field(..., gt=0)
    source_sha256: str = Field(..., pattern=_SHA256_PATTERN)
    idempotency_key: str = Field(..., min_length=1, max_length=192)


class EnforcementDecisionIn(_StrictModel):
    profile_id: str = Field(..., pattern=_ID_PATTERN)
    purpose_id: str = Field(..., pattern=_ID_PATTERN)
    channel: str = Field("all", pattern=_ID_PATTERN)
    vendor_id: str = Field("all", pattern=_ID_PATTERN)
    policy_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    policy_version: int | None = Field(default=None, ge=1)
    tracker_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    at: float | None = Field(default=None, gt=0)


class OutboxAckIn(_StrictModel):
    idempotency_key: str = Field(..., min_length=1, max_length=192)


class PurgeIn(_StrictModel):
    before: float = Field(..., gt=0)
    limit: int = Field(100, ge=1, le=500)


class AnalyticsSnapshotIn(_StrictModel):
    start_at: float = Field(..., gt=0)
    end_at: float = Field(..., gt=0)
    dimensions: list[
        Literal[
            "purpose_id",
            "action",
            "channel",
            "vendor_id",
            "country_code",
            "region_code",
            "privacy_signal",
            "policy_id",
            "policy_version",
            "day",
        ]
    ] = Field(..., min_length=1, max_length=4)
    # None uses the installation default; a value below the installation's
    # smallest cohort is raised to it ([consent_preferences.analytics]).
    min_cohort_size: int | None = Field(None, ge=2, le=100_000)
    max_receipts: int = Field(10_000, ge=1, le=100_000)
    max_rows: int = Field(1_000, ge=1, le=10_000)


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using consent records",
        )
    return tenant


def _store(tenant_id: str):
    from maverick.consent_preferences import ConsentPreferenceStore
    from maverick.paths import data_dir

    return ConsentPreferenceStore(
        data_dir(
            "consent_preferences",
            "consent-preferences.sqlite3",
            tenant=tenant_id,
        )
    )


def _analytics(tenant_id: str):
    from maverick import consent_analytics
    from maverick.paths import data_dir

    if not consent_analytics.enabled():
        raise HTTPException(
            status_code=403,
            detail=(
                "consent analytics is disabled "
                "([consent_preferences.analytics] enable)"
            ),
        )
    return consent_analytics, consent_analytics.ConsentAnalytics(
        data_dir(
            "consent_preferences",
            "consent-preferences.sqlite3",
            tenant=tenant_id,
        )
    )


def _ops():
    from maverick import consent_preferences

    if not consent_preferences.enabled():
        raise HTTPException(
            status_code=403,
            detail=(
                "consumer consent and preferences are disabled "
                "([consent_preferences] enable)"
            ),
        )
    return consent_preferences


def _actor_sha256(request: Request) -> str:
    from .request_identity import request_actor as _request_actor

    actor = _request_actor(request)
    return hashlib.sha256(actor.encode("utf-8")).hexdigest()


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


async def _call(ops, function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except (
        ops.ConsentConflict,
        ops.ConsentIdempotencyConflict,
        ops.ConsentStalePolicy,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.ConsentNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ops.ConsentValidationError, ops.ScanAdmissionError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (ops.ConsentPreferencesConfigError, ops.ConsentPreferencesError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


async def _analytics_call(ops, function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except ops.ConsentAnalyticsValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ops.ConsentAnalyticsConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (ops.ConsentAnalyticsUnavailable, ops.ConsentAnalyticsError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/summary")
async def summary(request: Request) -> dict:
    require_permission(request, "view")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(await _call(ops, _store(tenant_id).summary, tenant_id))


@router.get("/policies")
async def list_policies(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(ops, _store(tenant_id).list_policies, tenant_id, limit=limit)
    )


@router.post("/policies", status_code=201)
async def publish_policy(request: Request, body: PublishPolicyIn) -> dict:
    require_global_permission(request, "admin")
    ops = _ops()
    tenant_id = _tenant_id()
    payload = body.model_dump()
    return _jsonable(
        await _call(ops, _store(tenant_id).publish_policy, tenant_id, **payload)
    )


@router.get("/profiles")
async def list_profiles(
    request: Request,
    limit: int | None = Query(None, ge=1, le=500),
    after: str | None = Query(None, pattern=_ID_PATTERN),
    search: str = Query("", max_length=128),
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    limit = _page(limit, "profile_page_size", 100)
    context = _profile_context(request, continuation=after is not None)
    result = await _call(ops, _store(tenant_id).list_profiles, tenant_id, limit=limit,
                         after=after, search=search)
    return _jsonable({**result, "context": context})


@router.post("/profiles/lookup")
async def lookup_profiles(request: Request, body: LookupProfilesIn) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    context = _profile_context(request)
    result = await _call(ops, _store(tenant_id).lookup_profiles, tenant_id, body.profile_ids)
    return _jsonable({**result, "context": context})


@router.post("/profiles", status_code=201)
async def create_profile(request: Request, body: CreateProfileIn) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).create_profile,
            tenant_id,
            **body.model_dump(),
        )
    )


@router.post("/profiles/link")
async def link_profiles(request: Request, body: LinkProfilesIn) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).link_profiles,
            tenant_id,
            **body.model_dump(),
        )
    )


@router.get("/profiles/{profile_id}/identity-link")
async def profile_identity_link(request: Request, profile_id: str) -> dict:
    """Inspect current link authority without returning the subject digest."""

    require_permission(request, "view")
    ops = _ops()
    tenant_id = _tenant_id()
    authority = await _call(
        ops,
        _store(tenant_id).get_profile_authority,
        tenant_id,
        profile_id,
    )
    return {
        "profile_id": authority["profile_id"],
        "identity_kind": authority["identity_kind"],
        "profile_revision": authority["revision"],
        "status": authority["link_status"],
        "link_revision": authority["link_revision"],
        "linked_known_profile_id": authority["linked_known_profile_id"],
        "last_known_profile_id": authority["last_known_profile_id"],
        "link_id": authority["link_id"],
        "link_sha256": authority["link_sha256"],
        "record_sha256": authority["link_record_sha256"],
        "retention_until": authority["link_retention_until"],
        "receipt_histories_merged": False,
    }


@router.get("/profiles/{profile_id}/identity-link/history")
async def profile_identity_link_history(
    request: Request,
    profile_id: str,
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    require_permission(request, "view")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).get_profile_link_history,
            tenant_id,
            profile_id,
            limit=limit,
        )
    )


@router.get("/identity-links/integrity")
async def identity_link_integrity(
    request: Request,
    limit: int = Query(500, ge=1, le=500),
) -> dict:
    require_permission(request, "view")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).verify_profile_link_integrity,
            tenant_id,
            limit=limit,
        )
    )


@router.post("/profiles/{profile_id}/preferences", status_code=201)
async def record_preferences(
    request: Request,
    profile_id: str,
    body: RecordPreferencesIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    context = ops.ConsentContext(**body.context.model_dump())
    choices = [ops.PreferenceChoice(**item.model_dump()) for item in body.choices]
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).record_preferences,
            tenant_id,
            profile_id,
            body.policy_id,
            body.policy_version,
            context,
            choices,
            expected_revision=body.expected_revision,
            idempotency_key=body.idempotency_key,
            actor_sha256=_actor_sha256(request),
            retention_until=body.retention_until,
        )
    )


@router.post("/profiles/{profile_id}/privacy-signals", status_code=201)
async def ingest_privacy_signal(
    request: Request,
    profile_id: str,
    body: PrivacySignalIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    context = ops.ConsentContext(**body.context.model_dump())
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).ingest_privacy_signal,
            tenant_id,
            profile_id,
            body.signal,
            body.purposes,
            body.policy_id,
            body.policy_version,
            context,
            expected_revision=body.expected_revision,
            idempotency_key=body.idempotency_key,
            actor_sha256=_actor_sha256(request),
        )
    )


@router.get("/profiles/{profile_id}/export")
async def export_profile(
    request: Request,
    response: Response,
    profile_id: str,
    access_purpose: str = Query(..., min_length=1, max_length=160),
    receipt_limit: int | None = Query(None, ge=1, le=500),
    before_sequence: int | None = Query(None, ge=1),
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    receipt_limit = _page(receipt_limit, "receipt_page_size", 500)
    context = _profile_context(request, continuation=before_sequence is not None)
    response.headers["X-Lightwork-Profile-Context"] = context
    result = _jsonable(
        await _call(
            ops,
            _store(tenant_id).export_profile,
            tenant_id,
            profile_id,
            actor_sha256=_actor_sha256(request),
            access_purpose=access_purpose,
            receipt_limit=receipt_limit,
            before_sequence=before_sequence,
        )
    )
    return result


@router.get("/profiles/{profile_id}/access-log")
async def list_access_log(
    request: Request,
    profile_id: str,
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    require_global_permission(request, "audit")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).list_access_log,
            tenant_id,
            profile_id,
            limit=limit,
        )
    )


@router.get("/trackers")
async def list_trackers(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(ops, _store(tenant_id).list_trackers, tenant_id, limit=limit)
    )


@router.put("/trackers/{tracker_id}")
async def register_tracker(
    request: Request,
    tracker_id: str,
    body: TrackerIn,
) -> dict:
    require_global_permission(request, "admin")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).register_tracker,
            tenant_id,
            tracker_id,
            **body.model_dump(),
        )
    )


@router.post("/scans", status_code=201)
async def admit_scan(request: Request, body: ScanIn) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    observations = [
        ops.TrackerObservation(**item.model_dump()) for item in body.observations
    ]
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).admit_scan_observations,
            tenant_id,
            body.scan_id,
            observations,
            body.observed_at,
            body.source_sha256,
            body.idempotency_key,
        )
    )


@router.get("/scans/{scan_id}")
async def list_scan_observations(
    request: Request,
    scan_id: str,
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).list_scan_observations,
            tenant_id,
            scan_id,
            limit=limit,
        )
    )


@router.post("/decisions")
async def decide(request: Request, body: EnforcementDecisionIn) -> dict:
    require_permission(request, "operate", api_scope="approvals:decide")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).decide,
            tenant_id,
            **body.model_dump(),
        )
    )


@router.get("/sync/{destination_id}")
async def read_outbox(
    request: Request,
    destination_id: str,
    after_sequence: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    include_acked: bool = False,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).read_outbox,
            tenant_id,
            destination_id,
            after_sequence=after_sequence,
            limit=limit,
            include_acked=include_acked,
        )
    )


@router.post("/sync/{destination_id}/{event_id}/ack")
async def ack_outbox(
    request: Request,
    destination_id: str,
    event_id: str,
    body: OutboxAckIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).ack_outbox,
            tenant_id,
            destination_id,
            event_id,
            body.idempotency_key,
        )
    )


@router.get("/retention/due")
async def retention_due(
    request: Request,
    before: float = Query(..., gt=0),
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    require_global_permission(request, "audit")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).retention_due,
            tenant_id,
            before=before,
            limit=limit,
        )
    )


@router.post("/retention/purge")
async def purge_operational_data(request: Request, body: PurgeIn) -> dict:
    require_global_permission(request, "admin")
    ops = _ops()
    tenant_id = _tenant_id()
    return _jsonable(
        await _call(
            ops,
            _store(tenant_id).purge_operational_data,
            tenant_id,
            before=body.before,
            limit=body.limit,
        )
    )


@router.post("/analytics/snapshot")
async def analytics_snapshot(request: Request, body: AnalyticsSnapshotIn) -> dict:
    """Return a cohort-suppressed event-trend snapshot for the active tenant."""

    require_global_permission(request, "audit")
    tenant_id = _tenant_id()
    ops, analytics = _analytics(tenant_id)
    return _jsonable(
        await _analytics_call(
            ops,
            analytics.snapshot,
            tenant_id,
            body.start_at,
            body.end_at,
            body.dimensions,
            min_cohort_size=body.min_cohort_size,
            max_receipts=body.max_receipts,
            max_rows=body.max_rows,
        )
    )


__all__ = ["router"]
