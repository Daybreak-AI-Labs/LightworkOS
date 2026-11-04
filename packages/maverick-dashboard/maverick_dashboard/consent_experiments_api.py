"""Governed operator API for consent-surface experiments.

The HTTP boundary accepts only closed experiment definitions, ephemeral
assignment context, and binary outcomes.  It never accepts executable content,
raw analytics events, a tenant selector, caller-authored actor identities, or
key material.  All state-changing work is delegated to the tenant-scoped core
authority under the request's authenticated principal.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import secrets
from collections.abc import Mapping
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission

router = APIRouter(prefix="/consent/experiments", tags=["consent-experiments"])

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDEMPOTENCY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{7,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_COUNTRY_PATTERN = r"^[A-Z]{2}$"
_LOCALE_PATTERN = r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}$"
_ROOT_KEY_ENV = "MAVERICK_CONSENT_EXPERIMENT_KEY"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=8,
        max_length=256,
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
CountryCode = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=2,
        max_length=2,
        pattern=_COUNTRY_PATTERN,
    ),
]
LocaleCode = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=2,
        max_length=35,
        pattern=_LOCALE_PATTERN,
    ),
]
SubjectIdentity = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=512),
]
ExperimentPath = Annotated[
    str,
    ApiPath(pattern=_ID_PATTERN, min_length=1, max_length=128),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class VariantIn(_StrictModel):
    variant_id: OpaqueId
    allocation_bps: int = Field(ge=1, le=10_000)
    content_ref: OpaqueId
    content_sha256: Digest
    accessibility_evidence_sha256: Digest
    equal_choice_evidence_sha256: Digest
    is_control: bool = False
    is_holdout: bool = False


class AudienceIn(_StrictModel):
    country_codes: list[CountryCode] = Field(default_factory=list, max_length=100)
    region_codes: list[OpaqueId] = Field(default_factory=list, max_length=100)
    channels: list[OpaqueId] = Field(default_factory=list, max_length=100)
    locales: list[LocaleCode] = Field(default_factory=list, max_length=100)


class CreateExperimentIn(_StrictModel):
    experiment_id: OpaqueId
    metric_id: OpaqueId
    variants: list[VariantIn] = Field(min_length=2, max_length=10)
    starts_at: float = Field(gt=0, lt=32_503_680_000.0)
    ends_at: float = Field(gt=0, lt=32_503_680_000.0)
    traffic_bps: int = Field(default=10_000, ge=1, le=10_000)
    max_exposures: int = Field(default=1_000_000, ge=1, le=100_000_000)
    min_sample_per_variant: int = Field(default=100, ge=20, le=10_000_000)
    alpha: float = Field(default=0.05, ge=0.001, le=0.1)
    max_analysis_looks: int = Field(default=5, ge=1, le=20)
    minimum_effect: float = Field(default=0.0, ge=0.0, le=0.5)
    dedupe_retention_days: int = Field(default=30, ge=1, le=90)
    audience: AudienceIn | None = None
    idempotency_key: IdempotencyKey


class LifecycleIn(_StrictModel):
    expected_revision: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


PrivacySignal = Literal[
    "gpc",
    "dnt",
    "opt_out",
    "do_not_sell",
    "withdrawn",
    "revoked",
]


class AssignmentContextIn(_StrictModel):
    country_code: CountryCode | None = None
    region_code: OpaqueId | None = None
    channel: OpaqueId | None = None
    locale: LocaleCode | None = None
    privacy_signals: list[PrivacySignal] = Field(default_factory=list, max_length=6)
    required_purpose: bool = False
    accessibility_supported: bool = True
    equal_choice_prominence: bool = True


class AssignmentIn(_StrictModel):
    subject_identity: SubjectIdentity
    context: AssignmentContextIn = Field(default_factory=AssignmentContextIn)
    at: float | None = Field(default=None, gt=0, lt=32_503_680_000.0)


class ExposureIn(_StrictModel):
    subject_identity: SubjectIdentity
    context: AssignmentContextIn = Field(default_factory=AssignmentContextIn)
    idempotency_key: IdempotencyKey
    occurred_at: float | None = Field(default=None, gt=0, lt=32_503_680_000.0)


class OutcomeIn(_StrictModel):
    subject_identity: SubjectIdentity
    success: bool
    idempotency_key: IdempotencyKey
    occurred_at: float | None = Field(default=None, gt=0, lt=32_503_680_000.0)


class AnalyzeIn(_StrictModel):
    idempotency_key: IdempotencyKey


class RetentionPurgeIn(_StrictModel):
    idempotency_key: IdempotencyKey
    before: float | None = Field(default=None, gt=0, lt=32_503_680_000.0)


def _config() -> Mapping[str, Any]:
    try:
        from maverick import config

        if config.config_source_errors():
            return {}
        loaded = config.load_config()
    except Exception:
        return {}
    return loaded if isinstance(loaded, Mapping) else {}


def _enabled() -> bool:
    from maverick.consent_experiments import experiments_enabled

    return experiments_enabled(_config())


def experiments_enabled_for_page() -> bool:
    """Mount-time page context helper that has no key or database side effects."""

    return _enabled()


def _ops():
    from maverick import consent_experiments

    if not consent_experiments.experiments_enabled(_config()):
        raise HTTPException(
            status_code=403,
            detail=(
                "consent experiments are disabled; enable [consent_preferences] "
                "and [consent_preferences.experiments]"
            ),
        )
    return consent_experiments


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using consent experiments",
        )
    return tenant


def _decode_root_key(raw: str) -> bytes:
    try:
        if len(raw) == 64:
            value = bytes.fromhex(raw)
        else:
            value = base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError(
            f"{_ROOT_KEY_ENV} must be exactly 32 bytes encoded as hex or base64"
        ) from exc
    if len(value) != 32:
        raise RuntimeError(
            f"{_ROOT_KEY_ENV} must be exactly 32 bytes encoded as hex or base64"
        )
    return value


class _LocalExperimentKeyAuthority:
    """Local deployment key authority; fleets should inject a shared secret owner."""

    @staticmethod
    def _root_key() -> bytes:
        injected = os.environ.get(_ROOT_KEY_ENV, "").strip()
        if injected:
            return _decode_root_key(injected)

        from maverick.file_lock import (
            atomic_read_bytes,
            atomic_write_bytes,
            cross_process_lock,
            ensure_private_directory,
            ensure_private_file,
        )
        from maverick.paths import data_dir

        path = data_dir("keys", "consent-experiments.key", tenant=None)
        ensure_private_directory(path.parent)
        with cross_process_lock(path):
            try:
                ensure_private_file(path, 0o600)
                key = atomic_read_bytes(path)
            except FileNotFoundError:
                key = secrets.token_bytes(32)
                atomic_write_bytes(path, key)
                ensure_private_file(path, 0o600)
        if len(key) != 32:
            raise RuntimeError("stored consent experiment key authority is invalid")
        return key

    def key_for(self, tenant_id: str, capability: str) -> bytes:
        return hmac.new(
            self._root_key(),
            f"{capability}\0{tenant_id}".encode(),
            hashlib.sha256,
        ).digest()


def _authority(request: Request, ops, tenant_id: str):
    factory = getattr(
        request.app.state,
        "consent_experiment_authority_factory",
        None,
    )
    if callable(factory):
        authority = factory(tenant_id=tenant_id, request=request)
        if authority is None:
            raise HTTPException(
                status_code=503,
                detail="injected consent experiment authority is unavailable",
            )
        return authority

    from maverick.paths import data_dir

    key_authority = getattr(
        request.app.state,
        "consent_experiment_key_authority",
        None,
    ) or _LocalExperimentKeyAuthority()
    try:
        return ops.ConsentExperimentAuthority(
            data_dir(
                "consent_preferences",
                "consent-experiments.sqlite3",
                tenant=tenant_id,
            ),
            key_authority=key_authority,
            config_loader=_config,
        )
    except ops.ConsentExperimentConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ops.ConsentExperimentError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(
            status_code=503,
            detail="consent experiment secret or database authority is unavailable",
        ) from exc


def _actor_identity(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    subject = getattr(principal, "sub", None)
    return f"human:{subject or 'local-operator'}"


def _audience(body: AudienceIn | None) -> dict[str, list[str]] | None:
    if body is None:
        return None
    values = body.model_dump()
    selected = {key: value for key, value in values.items() if value}
    return selected or None


def _context(ops, body: AssignmentContextIn):
    return ops.AssignmentContext(**body.model_dump())


async def _call(ops, function, *args, **kwargs) -> Any:
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except ops.ConsentExperimentNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ops.ConsentExperimentPermissionDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (ops.ConsentExperimentConflict, ops.ConsentExperimentStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.ConsentExperimentValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ops.ConsentExperimentConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (ops.ConsentExperimentIntegrityError, ops.ConsentExperimentError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    return {
        "schema": "lightwork.consent-experiment-status.v1",
        "enabled": _enabled(),
        "external_network_io": False,
        "live_estate_acceptance_verified": False,
        "causal_certification_provided": False,
        "raw_identity_persisted": False,
        "raw_profile_or_event_payload_persisted": False,
        "assignment": "tenant-keyed deterministic sticky allocation",
        "analysis": "binary frequentist with bounded looks and familywise alpha spending",
        "limits": {
            "variants_per_experiment": 10,
            "audience_values_per_dimension": 100,
            "max_analysis_looks": 20,
            "max_dedupe_retention_days": 90,
            "max_exposures_per_experiment": 100_000_000,
        },
        "production_boundaries": [
            "Human authentication and role separation are enforced by the dashboard boundary.",
            "Certified content references must be rendered by a reviewed consent client.",
            "A statistical winner is not legal, ethical, accessibility, or customer-estate acceptance.",
            "Multi-node deployments must inject one shared managed experiment key authority.",
        ],
    }


@router.post("", status_code=201)
async def create_experiment(request: Request, body: CreateExperimentIn) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops = _ops()
    tenant = _tenant_id()
    variants = tuple(
        ops.ExperimentVariant(**variant.model_dump()) for variant in body.variants
    )
    spec = ops.ExperimentSpec(
        experiment_id=body.experiment_id,
        metric_id=body.metric_id,
        variants=variants,
        starts_at=body.starts_at,
        ends_at=body.ends_at,
        traffic_bps=body.traffic_bps,
        max_exposures=body.max_exposures,
        min_sample_per_variant=body.min_sample_per_variant,
        alpha=body.alpha,
        max_analysis_looks=body.max_analysis_looks,
        minimum_effect=body.minimum_effect,
        dedupe_retention_days=body.dedupe_retention_days,
        audience=_audience(body.audience),
    )
    authority = _authority(request, ops, tenant)
    return await _call(
        ops,
        authority.create_experiment,
        tenant,
        spec,
        created_by=_actor_identity(request),
        idempotency_key=body.idempotency_key,
    )


@router.get("")
async def list_experiments(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Read-only list of the active workspace's experiments for the page."""

    require_permission(request, "operate")
    ops = _ops()
    tenant = _tenant_id()
    lister = getattr(_authority(request, ops, tenant), "list_experiments", None)
    if not callable(lister):
        raise HTTPException(status_code=503, detail="experiment listing is unavailable")
    return await _call(ops, lister, tenant, limit=limit)


_VARIANT_LAYOUTS = ("stacked", "inline", "compact")
_VARIANT_ACTIONS = ("accept_all", "reject_all", "save_preferences")


def _variant_contents(bundle: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Certified layout variants of one exact banner, one per rule language.

    The fingerprint is computed exactly as the public experiment endpoint
    verifies it, so a person picks a layout instead of typing a digest.
    """
    from .consent_public_api import _sha256 as public_sha256

    index = {
        (item["resource_kind"], item["resource_id"], item["locale"], int(item["version"])): item
        for item in bundle.get("resources", [])
    }
    items: list[dict[str, Any]] = []
    for rule in bundle["rule_group"]["payload"]["rules"]:
        template = index.get(
            ("template", rule["template"]["id"], "", int(rule["template"]["version"]))
        )
        if template is None or not set(_VARIANT_ACTIONS) <= set(template["payload"]["actions"]):
            continue
        for locale in rule["locales"]:
            version = rule["translation_versions"].get(locale)
            translation = index.get(
                ("translation", rule["translation_catalog_id"], locale, int(version or 0))
            )
            if translation is None:
                continue
            messages = translation["payload"]["messages"]
            payload = template["payload"]
            text = {
                "title": messages[payload["title_key"]],
                "body": messages[payload["body_key"]],
                "actions": {
                    action: messages[payload["actions"][action]] for action in _VARIANT_ACTIONS
                },
            }
            for layout in _VARIANT_LAYOUTS:
                render = {"language": locale, "layout": layout, "template": text}
                items.append(
                    {
                        "rule_id": rule["rule_id"],
                        "locale": locale,
                        "layout": layout,
                        "content_ref": f"public-layout:{layout}",
                        "content_sha256": public_sha256(render),
                        "title": text["title"],
                        "body": text["body"],
                        "actions": text["actions"],
                    }
                )
    return items


@router.get("/variant-content")
async def variant_content(
    request: Request,
    property_id: Annotated[str, Query(pattern=_ID_PATTERN, max_length=128)],
    rule_group_id: Annotated[str, Query(pattern=_ID_PATTERN, max_length=128)],
    rule_group_version: Annotated[int, Query(ge=1, le=2**31 - 1)],
) -> dict[str, Any]:
    """Read-only: the banner layouts an experiment may compare, with fingerprints."""

    require_permission(request, "operate")
    _ops()
    from .consent_publishing_api import _authority as publishing_authority
    from .consent_publishing_api import _call as publishing_call

    publishing, tenant, store = publishing_authority()
    preview = await publishing_call(
        publishing,
        store.preview,
        tenant,
        property_id,
        rule_group_id,
        rule_group_version,
    )
    return {"items": _variant_contents(preview["bundle"])}


@router.post("/retention/purge")
async def purge_retention(request: Request, body: RetentionPurgeIn) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops = _ops()
    tenant = _tenant_id()
    return await _call(
        ops,
        _authority(request, ops, tenant).purge_expired_dedupe,
        tenant,
        purged_by=_actor_identity(request),
        idempotency_key=body.idempotency_key,
        before=body.before,
    )


@router.get("/{experiment_id}")
async def get_experiment(
    request: Request,
    experiment_id: ExperimentPath,
) -> dict[str, Any]:
    require_permission(request, "operate")
    ops = _ops()
    tenant = _tenant_id()
    return await _call(
        ops,
        _authority(request, ops, tenant).get_experiment,
        tenant,
        experiment_id,
    )


_ACTOR_PARAMETER = {
    "approve": "approved_by",
    "activate": "activated_by",
    "pause": "paused_by",
    "resume": "resumed_by",
    "kill": "killed_by",
    "rollback": "rolled_back_by",
}


async def _lifecycle(
    request: Request,
    experiment_id: str,
    body: LifecycleIn,
    action: Literal["approve", "activate", "pause", "resume", "kill", "rollback"],
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    ops = _ops()
    tenant = _tenant_id()
    authority = _authority(request, ops, tenant)
    return await _call(
        ops,
        getattr(authority, action),
        tenant,
        experiment_id,
        expected_revision=body.expected_revision,
        idempotency_key=body.idempotency_key,
        **{_ACTOR_PARAMETER[action]: _actor_identity(request)},
    )


@router.post("/{experiment_id}/approve")
async def approve_experiment(
    request: Request, experiment_id: ExperimentPath, body: LifecycleIn
) -> dict[str, Any]:
    return await _lifecycle(request, experiment_id, body, "approve")


@router.post("/{experiment_id}/activate")
async def activate_experiment(
    request: Request, experiment_id: ExperimentPath, body: LifecycleIn
) -> dict[str, Any]:
    return await _lifecycle(request, experiment_id, body, "activate")


@router.post("/{experiment_id}/pause")
async def pause_experiment(
    request: Request, experiment_id: ExperimentPath, body: LifecycleIn
) -> dict[str, Any]:
    return await _lifecycle(request, experiment_id, body, "pause")


@router.post("/{experiment_id}/resume")
async def resume_experiment(
    request: Request, experiment_id: ExperimentPath, body: LifecycleIn
) -> dict[str, Any]:
    return await _lifecycle(request, experiment_id, body, "resume")


@router.post("/{experiment_id}/kill")
async def kill_experiment(
    request: Request, experiment_id: ExperimentPath, body: LifecycleIn
) -> dict[str, Any]:
    return await _lifecycle(request, experiment_id, body, "kill")


@router.post("/{experiment_id}/rollback")
async def rollback_experiment(
    request: Request, experiment_id: ExperimentPath, body: LifecycleIn
) -> dict[str, Any]:
    return await _lifecycle(request, experiment_id, body, "rollback")


@router.post("/{experiment_id}/assign")
async def assign_variant(
    request: Request, experiment_id: ExperimentPath, body: AssignmentIn
) -> dict[str, Any]:
    require_permission(request, "operate")
    ops = _ops()
    tenant = _tenant_id()
    assignment = await _call(
        ops,
        _authority(request, ops, tenant).assign,
        tenant,
        experiment_id,
        body.subject_identity,
        _context(ops, body.context),
        at=body.at,
    )
    return assignment.as_dict()


@router.post("/{experiment_id}/exposures", status_code=201)
async def record_exposure(
    request: Request, experiment_id: ExperimentPath, body: ExposureIn
) -> dict[str, Any]:
    require_permission(request, "operate")
    ops = _ops()
    tenant = _tenant_id()
    return await _call(
        ops,
        _authority(request, ops, tenant).record_exposure,
        tenant,
        experiment_id,
        body.subject_identity,
        _context(ops, body.context),
        idempotency_key=body.idempotency_key,
        occurred_at=body.occurred_at,
    )


@router.post("/{experiment_id}/outcomes", status_code=201)
async def record_outcome(
    request: Request, experiment_id: ExperimentPath, body: OutcomeIn
) -> dict[str, Any]:
    require_permission(request, "operate")
    ops = _ops()
    tenant = _tenant_id()
    return await _call(
        ops,
        _authority(request, ops, tenant).record_outcome,
        tenant,
        experiment_id,
        body.subject_identity,
        success=body.success,
        idempotency_key=body.idempotency_key,
        occurred_at=body.occurred_at,
    )


@router.post("/{experiment_id}/analysis")
async def analyze_experiment(
    request: Request, experiment_id: ExperimentPath, body: AnalyzeIn
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops = _ops()
    tenant = _tenant_id()
    return await _call(
        ops,
        _authority(request, ops, tenant).analyze,
        tenant,
        experiment_id,
        analyzed_by=_actor_identity(request),
        idempotency_key=body.idempotency_key,
    )


@router.get("/{experiment_id}/audit-export")
async def audit_export(
    request: Request, experiment_id: ExperimentPath
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    ops = _ops()
    tenant = _tenant_id()
    return await _call(
        ops,
        _authority(request, ops, tenant).audit_export,
        tenant,
        experiment_id,
    )


__all__ = ["experiments_enabled_for_page", "router"]
