"""Explainable, tenant-governed dynamic risk scoring for AI assets.

The feature is deliberately default-off.  It admits only compact normalized
signals bound to an exact Model Risk asset revision and artifact digest.  Raw
prompts, outputs, provider responses, feature rows, or telemetry payloads are
outside this module's contract and are never persisted here.

Formula v1 is intentionally fixed and inspectable:

* each fresh, unresolved signal contributes
  ``severity * confidence * category_weight`` points;
* signal points are additive and capped at 100;
* validated business/regulatory context supplies independent score floors;
* the strictest result wins: ``max(signal_score, highest_context_floor)``.

Snapshots retain bounded trend and attribution metadata.  This is operational
risk decision support, not a legal classification, certification, compliance
verdict, or substitute for qualified human review.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

SIGNAL_SCHEMA = "lightwork.ai-dynamic-risk-signal.v1"
SNAPSHOT_SCHEMA = "lightwork.ai-dynamic-risk-snapshot.v1"
PROJECTION_SCHEMA = "lightwork.ai-dynamic-risk-projection.v1"
FORMULA_VERSION = "ai-dynamic-risk-formula-v1"

DRIFT_RECEIPT_SCHEMA = "lightwork.ai-dynamic-risk-normalized-drift-receipt.v1"
POLICY_RECEIPT_SCHEMA = "lightwork.ai-dynamic-risk-normalized-policy-receipt.v1"
RUNTIME_RECEIPT_SCHEMA = "lightwork.ai-dynamic-risk-normalized-runtime-receipt.v1"

# Public on purpose: reports cite the exact immutable formula inputs.
CATEGORY_WEIGHTS: dict[str, float] = {
    "quality": 0.80,
    "safety": 1.00,
    "drift": 0.75,
    "performance": 0.65,
    "policy": 1.00,
    "privacy": 1.00,
    "security": 1.00,
}
CONTEXT_FLOORS: dict[str, dict[str, float]] = {
    "asset_criticality": {
        "low": 0.0,
        "medium": 35.0,
        "high": 60.0,
        "critical": 80.0,
    },
    "eu_risk_tier": {
        "minimal": 0.0,
        "limited": 25.0,
        "high": 70.0,
        "unacceptable": 100.0,
    },
    "sensitive_data": {
        "none": 0.0,
        "internal": 15.0,
        "personal": 40.0,
        "special_category": 60.0,
    },
    "external_exposure": {
        "internal": 0.0,
        "restricted": 10.0,
        "partner": 30.0,
        "public": 50.0,
    },
}

_SIGNALS = GovernedRecordStore(
    "ai_dynamic_risk_signals",
    "DRS",
    "ai_dynamic_risk_signal",
)
_SNAPSHOTS = GovernedRecordStore(
    "ai_dynamic_risk_snapshots",
    "DRP",
    "ai_dynamic_risk_snapshot",
)

_ASSET_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z", re.IGNORECASE)
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}\Z")
_CODE_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,127}\Z")
_MAX_SIGNAL_RECORDS = 10_000
_MAX_ASSET_SIGNALS = 2_000
_MAX_SNAPSHOTS = 5_000
_MAX_HISTORY = 64
_MIN_VALIDITY_SECONDS = 60
_MAX_VALIDITY_SECONDS = 366 * 24 * 60 * 60
_MAX_FUTURE_SKEW_SECONDS = 300
_STORE_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})
_SIGNAL_FIELDS = frozenset({
    "id",
    "schema",
    "tenant_ref",
    "asset_id",
    "asset_revision",
    "asset_version_digest",
    "category",
    "signal_code",
    "severity",
    "confidence",
    "observed_at",
    "expires_at",
    "validity_seconds",
    "source_type",
    "source_id",
    "source_digest",
    "idempotency_sha256",
    "payload_sha256",
    "recorded_by_kind",
    "recorded_by",
    "status",
    "resolution",
    "supersession",
    "state_sha256",
})
_SNAPSHOT_FIELDS = frozenset({
    "id",
    "schema",
    "tenant_ref",
    "asset_id",
    "formula_version",
    "current",
    "history",
    "status",
    "snapshot_sha256",
})


class DynamicRiskError(RuntimeError):
    """Base failure for governed dynamic AI risk."""


class DynamicRiskConfigError(DynamicRiskError):
    """The default-off feature is unavailable or malformed."""


class DynamicRiskStateError(DynamicRiskError):
    """A governed risk record or registry binding is malformed."""


class DynamicRiskAssetError(DynamicRiskError):
    """An exact current Model Risk asset binding could not be established."""


class DynamicRiskIdempotencyConflict(DynamicRiskError):
    """An idempotency identity was reused for a different normalized signal."""


class RiskCategory(str, Enum):
    QUALITY = "quality"
    SAFETY = "safety"
    DRIFT = "drift"
    PERFORMANCE = "performance"
    POLICY = "policy"
    PRIVACY = "privacy"
    SECURITY = "security"


class SignalSourceType(str, Enum):
    DRIFT_RECEIPT = "drift_receipt"
    POLICY_RECEIPT = "policy_receipt"
    RUNTIME_RECEIPT = "runtime_receipt"
    TELEMETRY = "telemetry"
    EVIDENCE = "evidence"


class ActorKind(str, Enum):
    HUMAN = "human"
    SYSTEM = "system"


@dataclass(frozen=True)
class RiskActor:
    """Explicit authenticated human or named system authority."""

    kind: ActorKind | str
    principal: str


@dataclass(frozen=True)
class RiskSignal:
    """Compact normalized signal; no raw provider or model payload is allowed."""

    asset_id: str
    category: RiskCategory | str
    severity: float
    confidence: float
    observed_at: float
    expires_at: float
    source_type: SignalSourceType | str
    source_id: str
    source_digest: str
    signal_code: str
    idempotency_key: str


@dataclass(frozen=True)
class RiskContext:
    """Validated business/regulatory facts that supply strict score floors."""

    asset_criticality: str
    eu_risk_tier: str
    sensitive_data: str
    external_exposure: str


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: object, label: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if not text or len(text) > limit or any(ord(char) < 32 for char in text):
        raise ValueError(f"{label} is invalid")
    return text


def _identity(value: object, label: str, limit: int = 256) -> str:
    text = _text(value, label, limit)
    if not _ID_RE.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _code(value: object, label: str) -> str:
    text = _text(value, label, 128).lower()
    if not _CODE_RE.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _asset_id(value: object) -> str:
    text = _text(value, "asset_id", 36)
    if not _ASSET_RE.fullmatch(text):
        raise ValueError("asset_id must be an exact Model Risk asset id")
    return text


def _digest(value: object, label: str) -> str:
    text = _text(value, label, 71).lower()
    if not _DIGEST_RE.fullmatch(text):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return text.removeprefix("sha256:")


def _number(value: object, label: str, minimum: float, maximum: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{label} must be a number")
    number = float(value)
    if not math.isfinite(number) or number < minimum or number > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return number


def _timestamp(value: object, label: str) -> float:
    return _number(value, label, 0.000001, 100_000_000_000.0)


def _revision(value: object, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError(f"expected_revision must be a {qualifier} integer")
    return value


def _enum_value(value: object, enum_type: type[Enum], label: str) -> str:
    raw = value.value if isinstance(value, enum_type) else value
    try:
        return str(enum_type(raw).value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(sorted(str(item.value) for item in enum_type))
        raise ValueError(f"{label} must be one of: {allowed}") from exc


def _actor(actor: RiskActor) -> tuple[str, str]:
    if not isinstance(actor, RiskActor):
        raise TypeError("actor must be a RiskActor")
    kind = _enum_value(actor.kind, ActorKind, "actor kind")
    principal = _text(actor.principal, "actor principal", 4_096)
    expected_prefix = "user:" if kind == ActorKind.HUMAN.value else "system:"
    if not principal.startswith(expected_prefix) or len(principal) <= len(expected_prefix):
        raise ValueError(f"{kind} actor principal must start with {expected_prefix}")
    return kind, principal


def _tenant_ref() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise DynamicRiskStateError("dynamic risk operations require an explicit tenant")
    return "TEN-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:24]


def enabled() -> bool:
    """Return true only when ``[ai_dynamic_risk] enable = true`` is readable."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("ai_dynamic_risk")
    return isinstance(section, Mapping) and section.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise DynamicRiskConfigError(
            "dynamic AI risk is disabled; set [ai_dynamic_risk] enable = true"
        )


def _context(context: RiskContext) -> tuple[dict[str, str], list[dict[str, Any]]]:
    if not isinstance(context, RiskContext):
        raise TypeError("context must be a RiskContext")
    normalized: dict[str, str] = {}
    floors: list[dict[str, Any]] = []
    for dimension in (
        "asset_criticality",
        "eu_risk_tier",
        "sensitive_data",
        "external_exposure",
    ):
        value = _code(getattr(context, dimension), dimension)
        choices = CONTEXT_FLOORS[dimension]
        if value not in choices:
            raise ValueError(
                f"{dimension} must be one of: {', '.join(sorted(choices))}"
            )
        normalized[dimension] = value
        floors.append({
            "dimension": dimension,
            "value": value,
            "floor": choices[value],
            "rule": f"{FORMULA_VERSION}:{dimension}:{value}",
        })
    return normalized, floors


def _receipt_signal(
    receipt: Mapping[str, Any],
    *,
    schema: str,
    source_type: SignalSourceType,
    fixed_category: RiskCategory | None,
    allowed_categories: frozenset[str] | None = None,
) -> RiskSignal:
    """Validate one closed normalized receipt and discard its envelope.

    The exact-key requirement is the provider-JSON trust boundary.  Integrators
    must normalize arbitrary external payloads before this function is called.
    """

    if not isinstance(receipt, Mapping):
        raise TypeError("normalized receipt must be a mapping")
    expected = {
        "schema",
        "asset_id",
        "receipt_id",
        "signal_code",
        "severity",
        "confidence",
        "observed_at",
        "expires_at",
        "category",
        "receipt_sha256",
    }
    if set(receipt) != expected:
        raise ValueError("normalized receipt has unexpected or missing fields")
    payload = {key: receipt[key] for key in sorted(expected - {"receipt_sha256"})}
    if receipt.get("schema") != schema:
        raise ValueError("normalized receipt schema is unsupported")
    receipt_digest = _digest(receipt.get("receipt_sha256"), "receipt_sha256")
    if _sha256(payload) != receipt_digest:
        raise ValueError("normalized receipt digest does not match its exact payload")
    category = _enum_value(receipt.get("category"), RiskCategory, "category")
    if fixed_category is not None and category != fixed_category.value:
        raise ValueError(f"{source_type.value} category must be {fixed_category.value}")
    if allowed_categories is not None and category not in allowed_categories:
        raise ValueError("runtime receipt category is unsupported")
    receipt_id = _identity(receipt.get("receipt_id"), "receipt_id")
    return RiskSignal(
        asset_id=_asset_id(receipt.get("asset_id")),
        category=category,
        severity=_number(receipt.get("severity"), "severity", 0.0, 100.0),
        confidence=_number(receipt.get("confidence"), "confidence", 0.0, 1.0),
        observed_at=_timestamp(receipt.get("observed_at"), "observed_at"),
        expires_at=_timestamp(receipt.get("expires_at"), "expires_at"),
        source_type=source_type,
        source_id=receipt_id,
        source_digest=receipt_digest,
        signal_code=_code(receipt.get("signal_code"), "signal_code"),
        idempotency_key=f"{source_type.value}:{receipt_id}",
    )


def signal_from_drift_receipt(receipt: Mapping[str, Any]) -> RiskSignal:
    """Admit only the closed normalized drift-receipt schema."""

    return _receipt_signal(
        receipt,
        schema=DRIFT_RECEIPT_SCHEMA,
        source_type=SignalSourceType.DRIFT_RECEIPT,
        fixed_category=RiskCategory.DRIFT,
    )


def signal_from_policy_receipt(receipt: Mapping[str, Any]) -> RiskSignal:
    """Admit only the closed normalized policy-receipt schema."""

    return _receipt_signal(
        receipt,
        schema=POLICY_RECEIPT_SCHEMA,
        source_type=SignalSourceType.POLICY_RECEIPT,
        fixed_category=RiskCategory.POLICY,
    )


def signal_from_runtime_receipt(receipt: Mapping[str, Any]) -> RiskSignal:
    """Admit a closed runtime receipt for a supported runtime risk category."""

    return _receipt_signal(
        receipt,
        schema=RUNTIME_RECEIPT_SCHEMA,
        source_type=SignalSourceType.RUNTIME_RECEIPT,
        fixed_category=None,
        allowed_categories=frozenset({
            "quality", "safety", "performance", "privacy", "security",
        }),
    )


def _signal_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    keys = (
        "schema",
        "tenant_ref",
        "asset_id",
        "asset_revision",
        "asset_version_digest",
        "category",
        "signal_code",
        "severity",
        "confidence",
        "observed_at",
        "expires_at",
        "validity_seconds",
        "source_type",
        "source_id",
        "source_digest",
        "idempotency_sha256",
    )
    return {key: record.get(key) for key in keys}


def _signal_state(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": record.get("id"),
        "payload_sha256": record.get("payload_sha256"),
        "recorded_by_kind": record.get("recorded_by_kind"),
        "recorded_by": record.get("recorded_by"),
        "status": record.get("status"),
        "resolution": record.get("resolution"),
        "supersession": record.get("supersession"),
    }


def _public_signal(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "signal_id": record["id"],
        "revision": record["revision"],
        "asset_id": record["asset_id"],
        "asset_revision": record["asset_revision"],
        "asset_version_digest": record["asset_version_digest"],
        "category": record["category"],
        "signal_code": record["signal_code"],
        "severity": record["severity"],
        "confidence": record["confidence"],
        "observed_at": record["observed_at"],
        "expires_at": record["expires_at"],
        "validity_seconds": record["validity_seconds"],
        "source_type": record["source_type"],
        "source_id": record["source_id"],
        "source_digest": record["source_digest"],
        "payload_sha256": record["payload_sha256"],
        "recorded_by_kind": record["recorded_by_kind"],
        "recorded_by": record["recorded_by"],
        "status": record["status"],
        "resolution": (
            None if record["resolution"] is None else dict(record["resolution"])
        ),
        "supersession": (
            None if record["supersession"] is None else dict(record["supersession"])
        ),
    }


def _validate_lifecycle(value: object, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise DynamicRiskStateError(f"stored signal {label} is malformed")
    required = (
        {"resolved_at", "resolution_code", "evidence_digest", "actor_kind", "actor"}
        if label == "resolution"
        else {
            "superseded_at",
            "superseding_signal_id",
            "superseding_revision",
            "superseding_payload_sha256",
            "actor_kind",
            "actor",
        }
    )
    if set(value) != required:
        raise DynamicRiskStateError(f"stored signal {label} is malformed")
    try:
        if label == "resolution":
            _timestamp(value["resolved_at"], "resolved_at")
            _code(value["resolution_code"], "resolution_code")
            _digest(value["evidence_digest"], "evidence_digest")
        else:
            _timestamp(value["superseded_at"], "superseded_at")
            _identity(value["superseding_signal_id"], "superseding_signal_id", 64)
            _revision(value["superseding_revision"])
            _digest(value["superseding_payload_sha256"], "superseding_payload_sha256")
        _actor(RiskActor(kind=value["actor_kind"], principal=value["actor"]))
    except (TypeError, ValueError) as exc:
        raise DynamicRiskStateError(f"stored signal {label} is malformed") from exc
    return dict(value)


def _validate_signal_record(
    record: Mapping[str, Any],
    *,
    tenant_ref: str,
) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise DynamicRiskStateError("stored dynamic risk signal is not an object")
    unexpected = set(record) - _SIGNAL_FIELDS - _STORE_METADATA
    missing = _SIGNAL_FIELDS - set(record)
    if unexpected or missing:
        raise DynamicRiskStateError("stored dynamic risk signal shape is malformed")
    try:
        _identity(record["id"], "signal id", 64)
        if record["schema"] != SIGNAL_SCHEMA or record["tenant_ref"] != tenant_ref:
            raise ValueError("schema or tenant binding mismatch")
        _asset_id(record["asset_id"])
        _revision(record["asset_revision"])
        _digest(record["asset_version_digest"], "asset_version_digest")
        category = _enum_value(record["category"], RiskCategory, "category")
        source_type = _enum_value(
            record["source_type"], SignalSourceType, "source_type"
        )
        _code(record["signal_code"], "signal_code")
        _number(record["severity"], "severity", 0.0, 100.0)
        _number(record["confidence"], "confidence", 0.0, 1.0)
        observed_at = _timestamp(record["observed_at"], "observed_at")
        expires_at = _timestamp(record["expires_at"], "expires_at")
        validity = record["validity_seconds"]
        if (
            not isinstance(validity, int)
            or isinstance(validity, bool)
            or validity < _MIN_VALIDITY_SECONDS
            or validity > _MAX_VALIDITY_SECONDS
            or abs((expires_at - observed_at) - validity) > 1e-6
        ):
            raise ValueError("validity binding mismatch")
        _identity(record["source_id"], "source_id")
        _digest(record["source_digest"], "source_digest")
        _digest(record["idempotency_sha256"], "idempotency_sha256")
        _digest(record["payload_sha256"], "payload_sha256")
        _actor(RiskActor(record["recorded_by_kind"], record["recorded_by"]))
        status = str(record["status"])
        if status not in {"active", "resolved", "superseded"}:
            raise ValueError("invalid lifecycle status")
        resolution = _validate_lifecycle(record["resolution"], "resolution")
        supersession = _validate_lifecycle(record["supersession"], "supersession")
        if (status == "resolved") != (resolution is not None):
            raise ValueError("resolution status mismatch")
        if (status == "superseded") != (supersession is not None):
            raise ValueError("supersession status mismatch")
        if status == "active" and (resolution is not None or supersession is not None):
            raise ValueError("active signal has lifecycle terminal metadata")
        _revision(record["revision"])
        if _sha256(_signal_payload(record)) != record["payload_sha256"]:
            raise ValueError("payload digest mismatch")
        if _sha256(_signal_state(record)) != record["state_sha256"]:
            raise ValueError("state digest mismatch")
        if category not in CATEGORY_WEIGHTS or source_type not in {
            item.value for item in SignalSourceType
        }:
            raise ValueError("unsupported signal enum")
    except (KeyError, TypeError, ValueError) as exc:
        raise DynamicRiskStateError("stored dynamic risk signal is malformed") from exc
    return dict(record)


def _risk_tier(score: float) -> str:
    if score >= 75.0:
        return "critical"
    if score >= 50.0:
        return "high"
    if score >= 25.0:
        return "medium"
    return "low"


def _direction(delta: float) -> str:
    if delta > 0:
        return "worsened"
    if delta < 0:
        return "improved"
    return "unchanged"


class DynamicRiskService:
    """Admit signals, govern lifecycle, and publish explainable snapshots."""

    def __init__(
        self,
        *,
        signals: GovernedRecordStore | None = None,
        snapshots: GovernedRecordStore | None = None,
        asset_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
        clock: Callable[[], float] | None = None,
        enforce_feature: bool = True,
    ) -> None:
        if asset_lookup is not None and not callable(asset_lookup):
            raise ValueError("asset_lookup must be callable")
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        if not isinstance(enforce_feature, bool):
            raise ValueError("enforce_feature must be a boolean")
        self._signals = signals or _SIGNALS
        self._snapshots = snapshots or _SNAPSHOTS
        self._asset_lookup = asset_lookup
        self._clock = clock
        self._enforce_feature = enforce_feature

    def _require_active(self) -> str:
        if self._enforce_feature:
            require_enabled()
        if self._signals.backend_kind != self._snapshots.backend_kind:
            raise DynamicRiskStateError(
                "dynamic risk signals and snapshots use different backends"
            )
        return _tenant_ref()

    def _now(self) -> float:
        source = self._clock or self._snapshots.authoritative_time
        return _timestamp(source(), "authority time")

    def _asset_binding(self, asset_id: object) -> dict[str, Any]:
        asset = _asset_id(asset_id)
        lookup = self._asset_lookup
        if lookup is None:
            from . import model_risk_assurance

            lookup = model_risk_assurance.get_observation
        try:
            observation = lookup(asset)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise DynamicRiskAssetError("Model Risk asset lookup failed") from exc
        if not isinstance(observation, Mapping):
            raise DynamicRiskAssetError("Model Risk asset does not exist")
        try:
            observed_asset = _asset_id(observation.get("asset_id"))
            revision = _revision(observation.get("revision"))
            version_digest = _digest(
                observation.get("version_digest"), "asset version_digest"
            )
        except (TypeError, ValueError) as exc:
            raise DynamicRiskAssetError("Model Risk asset binding is malformed") from exc
        if observed_asset != asset:
            raise DynamicRiskAssetError("Model Risk asset lookup changed identity")
        return {
            "asset_id": asset,
            "revision": revision,
            "version_digest": version_digest,
        }

    def _bounded_signals(self, tenant_ref: str) -> list[dict[str, Any]]:
        rows = self._signals.list(limit=_MAX_SIGNAL_RECORDS + 1)
        if len(rows) > _MAX_SIGNAL_RECORDS:
            raise DynamicRiskStateError("dynamic risk signal namespace exceeds its bound")
        return [
            _validate_signal_record(row, tenant_ref=tenant_ref)
            for row in rows
        ]

    def ingest_signal(self, signal: RiskSignal, *, actor: RiskActor) -> dict[str, Any]:
        """Idempotently admit one exact, compact signal."""

        if not isinstance(signal, RiskSignal):
            raise TypeError("signal must be a RiskSignal")
        tenant_ref = self._require_active()
        actor_kind, actor_name = _actor(actor)
        binding = self._asset_binding(signal.asset_id)
        category = _enum_value(signal.category, RiskCategory, "category")
        source_type = _enum_value(signal.source_type, SignalSourceType, "source_type")
        severity = _number(signal.severity, "severity", 0.0, 100.0)
        confidence = _number(signal.confidence, "confidence", 0.0, 1.0)
        observed_at = _timestamp(signal.observed_at, "observed_at")
        expires_at = _timestamp(signal.expires_at, "expires_at")
        now = self._now()
        if observed_at > now + _MAX_FUTURE_SKEW_SECONDS:
            raise ValueError("observed_at is too far in the future")
        validity_float = expires_at - observed_at
        validity = int(round(validity_float))
        if (
            abs(validity_float - validity) > 1e-6
            or validity < _MIN_VALIDITY_SECONDS
            or validity > _MAX_VALIDITY_SECONDS
        ):
            raise ValueError(
                f"signal validity must be {_MIN_VALIDITY_SECONDS} through "
                f"{_MAX_VALIDITY_SECONDS} whole seconds"
            )
        source_id = _identity(signal.source_id, "source_id")
        source_digest = _digest(signal.source_digest, "source_digest")
        signal_code = _code(signal.signal_code, "signal_code")
        idempotency_key = _text(signal.idempotency_key, "idempotency_key", 256)
        idempotency_sha = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        signal_id = f"DRS-{idempotency_sha[:32]}"
        payload = {
            "schema": SIGNAL_SCHEMA,
            "tenant_ref": tenant_ref,
            "asset_id": binding["asset_id"],
            "asset_revision": binding["revision"],
            "asset_version_digest": binding["version_digest"],
            "category": category,
            "signal_code": signal_code,
            "severity": severity,
            "confidence": confidence,
            "observed_at": observed_at,
            "expires_at": expires_at,
            "validity_seconds": validity,
            "source_type": source_type,
            "source_id": source_id,
            "source_digest": source_digest,
            "idempotency_sha256": idempotency_sha,
        }
        payload_sha = _sha256(payload)
        existing = self._signals.get(signal_id)
        if existing is not None:
            current = _validate_signal_record(existing, tenant_ref=tenant_ref)
            if current["payload_sha256"] != payload_sha:
                raise DynamicRiskIdempotencyConflict(
                    "idempotency key was already used for a different dynamic risk signal"
                )
            return _public_signal(current)
        record = {
            "id": signal_id,
            **payload,
            "payload_sha256": payload_sha,
            "recorded_by_kind": actor_kind,
            "recorded_by": actor_name,
            "status": "active",
            "resolution": None,
            "supersession": None,
        }
        record["state_sha256"] = _sha256(_signal_state(record))
        try:
            saved = self._signals.create(
                record,
                action="admit_dynamic_risk_signal",
                actor=actor_name,
                max_records=_MAX_SIGNAL_RECORDS,
            )
        except RecordConflict as exc:
            concurrent = self._signals.get(signal_id)
            if concurrent is None:
                raise
            current = _validate_signal_record(concurrent, tenant_ref=tenant_ref)
            if current["payload_sha256"] != payload_sha:
                raise DynamicRiskIdempotencyConflict(
                    "idempotency key was concurrently reused for a different signal"
                ) from exc
            saved = current
        return _public_signal(_validate_signal_record(saved, tenant_ref=tenant_ref))

    def get_signal(self, signal_id: str) -> dict[str, Any] | None:
        tenant_ref = self._require_active()
        identity = _identity(signal_id, "signal_id", 64)
        row = self._signals.get(identity)
        if row is None:
            return None
        return _public_signal(_validate_signal_record(row, tenant_ref=tenant_ref))

    def list_signals(self, asset_id: str) -> list[dict[str, Any]]:
        tenant_ref = self._require_active()
        asset = _asset_id(asset_id)
        rows = self._bounded_signals(tenant_ref)
        matched = [row for row in rows if row["asset_id"] == asset]
        if len(matched) > _MAX_ASSET_SIGNALS:
            raise DynamicRiskStateError("asset exceeds its dynamic risk signal bound")
        return [
            _public_signal(row)
            for row in sorted(matched, key=lambda item: (item["observed_at"], item["id"]))
        ]

    def resolve_signal(
        self,
        signal_id: str,
        *,
        expected_revision: int,
        resolution_code: str,
        resolution_evidence_digest: str,
        actor: RiskActor,
    ) -> dict[str, Any]:
        """CAS-resolve a signal with exact evidence, never free-form payload."""

        tenant_ref = self._require_active()
        identity = _identity(signal_id, "signal_id", 64)
        expected = _revision(expected_revision)
        code = _code(resolution_code, "resolution_code")
        evidence_digest = _digest(
            resolution_evidence_digest, "resolution_evidence_digest"
        )
        actor_kind, actor_name = _actor(actor)
        now = self._now()
        current = self._signals.get(identity)
        if current is None:
            raise DynamicRiskStateError("dynamic risk signal does not exist")
        validated = _validate_signal_record(current, tenant_ref=tenant_ref)
        if validated["status"] != "active":
            raise DynamicRiskStateError("only an active signal can be resolved")

        def mutate(row: dict[str, Any]) -> None:
            row["status"] = "resolved"
            row["resolution"] = {
                "resolved_at": now,
                "resolution_code": code,
                "evidence_digest": evidence_digest,
                "actor_kind": actor_kind,
                "actor": actor_name,
            }
            row["supersession"] = None
            row["state_sha256"] = _sha256(_signal_state(row))

        saved = self._signals.update(
            identity,
            mutate,
            expected_revision=expected,
            action="resolve_dynamic_risk_signal",
            actor=actor_name,
        )
        if saved is None:
            raise DynamicRiskStateError("dynamic risk signal disappeared during resolution")
        return _public_signal(_validate_signal_record(saved, tenant_ref=tenant_ref))

    def supersede_signal(
        self,
        signal_id: str,
        *,
        superseding_signal_id: str,
        expected_revision: int,
        actor: RiskActor,
    ) -> dict[str, Any]:
        """CAS-retire an old signal after a replacement is durably admitted."""

        tenant_ref = self._require_active()
        identity = _identity(signal_id, "signal_id", 64)
        replacement_id = _identity(
            superseding_signal_id, "superseding_signal_id", 64
        )
        if replacement_id == identity:
            raise ValueError("a signal cannot supersede itself")
        expected = _revision(expected_revision)
        actor_kind, actor_name = _actor(actor)
        current = self._signals.get(identity)
        replacement = self._signals.get(replacement_id)
        if current is None or replacement is None:
            raise DynamicRiskStateError("both signals must exist before supersession")
        old = _validate_signal_record(current, tenant_ref=tenant_ref)
        new = _validate_signal_record(replacement, tenant_ref=tenant_ref)
        if old["status"] != "active" or new["status"] != "active":
            raise DynamicRiskStateError("supersession requires two active signals")
        if old["asset_id"] != new["asset_id"]:
            raise ValueError("superseding signal must bind the same asset")
        if new["observed_at"] < old["observed_at"]:
            raise ValueError("superseding signal cannot predate the original")
        now = self._now()

        def mutate(row: dict[str, Any]) -> None:
            row["status"] = "superseded"
            row["resolution"] = None
            row["supersession"] = {
                "superseded_at": now,
                "superseding_signal_id": replacement_id,
                "superseding_revision": new["revision"],
                "superseding_payload_sha256": new["payload_sha256"],
                "actor_kind": actor_kind,
                "actor": actor_name,
            }
            row["state_sha256"] = _sha256(_signal_state(row))

        saved = self._signals.update(
            identity,
            mutate,
            expected_revision=expected,
            action="supersede_dynamic_risk_signal",
            actor=actor_name,
        )
        if saved is None:
            raise DynamicRiskStateError("dynamic risk signal disappeared during supersession")
        return _public_signal(_validate_signal_record(saved, tenant_ref=tenant_ref))

    @staticmethod
    def _snapshot_id(asset_id: str) -> str:
        return f"DRP-{_sha256({'asset_id': asset_id})[:32]}"

    @staticmethod
    def _history_entry(current: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "evaluated_at": current["evaluated_at"],
            "score": current["score"],
            "risk_tier": current["risk_tier"],
            "signal_score": current["signal_score"],
            "context_floor": current["context_floor"],
            "active_signal_count": current["active_signal_count"],
            "input_sha256": current["input_sha256"],
            "change": dict(current["change"]),
        }

    @staticmethod
    def _trend(history: list[dict[str, Any]]) -> dict[str, Any]:
        points = [
            {
                "evaluated_at": row["evaluated_at"],
                "score": row["score"],
                "risk_tier": row["risk_tier"],
                "active_signal_count": row["active_signal_count"],
                "input_sha256": row["input_sha256"],
            }
            for row in history
        ]
        if len(points) < 2:
            net_change = None
            direction = "initial"
        else:
            net_change = round(points[-1]["score"] - points[0]["score"], 6)
            direction = _direction(net_change)
        return {
            "formula_version": FORMULA_VERSION,
            "bounded_to": _MAX_HISTORY,
            "points": points,
            "net_change": net_change,
            "direction": direction,
        }

    def _validate_snapshot_record(  # noqa: C901 - closed persisted-state validator
        self,
        record: Mapping[str, Any],
        *,
        tenant_ref: str,
    ) -> dict[str, Any]:
        if not isinstance(record, Mapping):
            raise DynamicRiskStateError("stored dynamic risk snapshot is not an object")
        unexpected = set(record) - _SNAPSHOT_FIELDS - _STORE_METADATA
        missing = _SNAPSHOT_FIELDS - set(record)
        if unexpected or missing:
            raise DynamicRiskStateError("stored dynamic risk snapshot shape is malformed")
        try:
            _identity(record["id"], "snapshot id", 64)
            if (
                record["schema"] != SNAPSHOT_SCHEMA
                or record["tenant_ref"] != tenant_ref
                or record["formula_version"] != FORMULA_VERSION
                or record["status"] != "current"
            ):
                raise ValueError("snapshot binding mismatch")
            _asset_id(record["asset_id"])
            _revision(record["revision"])
            if not isinstance(record["current"], Mapping):
                raise ValueError("snapshot current projection is malformed")
            history = record["history"]
            if not isinstance(history, list) or not 1 <= len(history) <= _MAX_HISTORY:
                raise ValueError("snapshot history is malformed")
            current = record["current"]
            required_current = {
                "schema", "formula_version", "evaluated_at", "evaluated_by_kind",
                "evaluated_by", "asset_id", "asset_revision", "asset_version_digest",
                "context", "context_floors", "context_floor", "signal_score", "score",
                "risk_tier", "active_signal_count", "contributions", "excluded_signals",
                "signal_state_sha256", "fresh_through", "input_sha256", "change",
            }
            if set(current) != required_current:
                raise ValueError("snapshot current projection shape is malformed")
            if current["schema"] != PROJECTION_SCHEMA:
                raise ValueError("snapshot projection schema mismatch")
            if current["formula_version"] != FORMULA_VERSION:
                raise ValueError("snapshot formula mismatch")
            if current["asset_id"] != record["asset_id"]:
                raise ValueError("snapshot asset mismatch")
            _timestamp(current["evaluated_at"], "evaluated_at")
            _actor(RiskActor(current["evaluated_by_kind"], current["evaluated_by"]))
            _revision(current["asset_revision"])
            _digest(current["asset_version_digest"], "asset_version_digest")
            score = _number(current["score"], "score", 0.0, 100.0)
            _number(current["signal_score"], "signal_score", 0.0, 100.0)
            _number(current["context_floor"], "context_floor", 0.0, 100.0)
            if current["risk_tier"] != _risk_tier(score):
                raise ValueError("snapshot risk tier is inconsistent")
            if not isinstance(current["contributions"], list):
                raise ValueError("snapshot contributions are malformed")
            if not isinstance(current["excluded_signals"], list):
                raise ValueError("snapshot excluded signals are malformed")
            if len(current["contributions"]) + len(current["excluded_signals"]) > _MAX_ASSET_SIGNALS:
                raise ValueError("snapshot signal projection exceeds its bound")
            if not isinstance(current["active_signal_count"], int):
                raise ValueError("snapshot signal count is malformed")
            if current["active_signal_count"] != len(current["contributions"]):
                raise ValueError("snapshot signal count is inconsistent")
            _digest(current["signal_state_sha256"], "signal_state_sha256")
            if current["fresh_through"] is not None:
                _timestamp(current["fresh_through"], "fresh_through")
            _digest(current["input_sha256"], "input_sha256")
            if not isinstance(current["context"], Mapping):
                raise ValueError("snapshot context is malformed")
            normalized_context, expected_floors = _context(RiskContext(**current["context"]))
            if dict(current["context"]) != normalized_context:
                raise ValueError("snapshot context is not canonical")
            if current["context_floors"] != expected_floors:
                raise ValueError("snapshot context floors are inconsistent")
            if current["context_floor"] != max(row["floor"] for row in expected_floors):
                raise ValueError("snapshot strictest context floor is inconsistent")
            if not isinstance(current["change"], Mapping):
                raise ValueError("snapshot change attribution is malformed")
            if history[-1] != self._history_entry(current):
                raise ValueError("snapshot current state is not the history head")
            if _sha256({
                "schema": record["schema"],
                "tenant_ref": record["tenant_ref"],
                "asset_id": record["asset_id"],
                "formula_version": record["formula_version"],
                "current": current,
                "history": history,
                "status": record["status"],
            }) != record["snapshot_sha256"]:
                raise ValueError("snapshot digest mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise DynamicRiskStateError("stored dynamic risk snapshot is malformed") from exc
        return dict(record)

    def _project_snapshot(self, record: Mapping[str, Any]) -> dict[str, Any]:
        current = dict(record["current"])
        history = [dict(row) for row in record["history"]]
        return {
            **current,
            "snapshot_id": record["id"],
            "snapshot_revision": record["revision"],
            "history": history,
            "trend": self._trend(history),
            "snapshot_fresh": True,
            "stale_reasons": [],
            "legal_certification": False,
        }

    def current_score(self, asset_id: str) -> dict[str, Any] | None:
        """Return the last snapshot and explicitly revalidate its freshness."""

        tenant_ref = self._require_active()
        asset = _asset_id(asset_id)
        row = self._snapshots.get(self._snapshot_id(asset))
        if row is None:
            return None
        validated = self._validate_snapshot_record(row, tenant_ref=tenant_ref)
        if validated["asset_id"] != asset:
            raise DynamicRiskStateError("dynamic risk snapshot identity collision")
        current = validated["current"]
        binding = self._asset_binding(asset)
        reasons: list[str] = []
        if (
            current["asset_revision"] != binding["revision"]
            or current["asset_version_digest"] != binding["version_digest"]
        ):
            reasons.append("asset_version_changed_since_evaluation")
        signals = [
            signal
            for signal in self._bounded_signals(tenant_ref)
            if signal["asset_id"] == asset
        ]
        if len(signals) > _MAX_ASSET_SIGNALS:
            raise DynamicRiskStateError("asset exceeds its dynamic risk signal bound")
        signal_state_bindings = [
            {
                "signal_id": signal["id"],
                "revision": signal["revision"],
                "payload_sha256": signal["payload_sha256"],
                "state_sha256": signal["state_sha256"],
            }
            for signal in sorted(signals, key=lambda item: item["id"])
        ]
        if _sha256(signal_state_bindings) != current["signal_state_sha256"]:
            reasons.append("signal_state_changed_since_evaluation")
        fresh_through = current["fresh_through"]
        if fresh_through is not None and self._now() >= fresh_through:
            reasons.append("signal_expired_since_evaluation")
        projection = self._project_snapshot(validated)
        projection["snapshot_fresh"] = not reasons
        projection["stale_reasons"] = reasons
        return projection

    def score_asset(  # noqa: C901 - explicit formula and attribution boundary
        self,
        asset_id: str,
        *,
        context: RiskContext,
        expected_revision: int,
        actor: RiskActor,
    ) -> dict[str, Any]:
        """Compute and CAS-publish the current explainable risk snapshot."""

        tenant_ref = self._require_active()
        expected = _revision(expected_revision, allow_zero=True)
        actor_kind, actor_name = _actor(actor)
        binding = self._asset_binding(asset_id)
        normalized_context, context_floors = _context(context)
        now = self._now()
        all_signals = self._bounded_signals(tenant_ref)
        asset_signals = [
            row for row in all_signals if row["asset_id"] == binding["asset_id"]
        ]
        if len(asset_signals) > _MAX_ASSET_SIGNALS:
            raise DynamicRiskStateError("asset exceeds its dynamic risk signal bound")

        contributions: list[dict[str, Any]] = []
        excluded: list[dict[str, Any]] = []
        input_bindings: list[dict[str, Any]] = []
        for row in sorted(asset_signals, key=lambda item: item["id"]):
            input_bindings.append({
                "signal_id": row["id"],
                "revision": row["revision"],
                "payload_sha256": row["payload_sha256"],
                "state_sha256": row["state_sha256"],
            })
            age = round(max(0.0, now - row["observed_at"]), 6)
            remaining = round(row["expires_at"] - now, 6)
            if row["status"] != "active":
                excluded.append({
                    "signal_id": row["id"],
                    "category": row["category"],
                    "reason": row["status"],
                    "age_seconds": age,
                    "expires_in_seconds": remaining,
                    "freshness": "inactive",
                })
                continue
            if row["expires_at"] <= now:
                excluded.append({
                    "signal_id": row["id"],
                    "category": row["category"],
                    "reason": "expired",
                    "age_seconds": age,
                    "expires_in_seconds": remaining,
                    "freshness": "expired",
                })
                continue
            if (
                row["asset_revision"] != binding["revision"]
                or row["asset_version_digest"] != binding["version_digest"]
            ):
                excluded.append({
                    "signal_id": row["id"],
                    "category": row["category"],
                    "reason": "asset_version_changed",
                    "age_seconds": age,
                    "expires_in_seconds": remaining,
                    "freshness": "stale_binding",
                })
                continue
            weight = CATEGORY_WEIGHTS[row["category"]]
            points = round(row["severity"] * row["confidence"] * weight, 6)
            contributions.append({
                "signal_id": row["id"],
                "signal_revision": row["revision"],
                "category": row["category"],
                "signal_code": row["signal_code"],
                "severity": row["severity"],
                "confidence": row["confidence"],
                "category_weight": weight,
                "points": points,
                "observed_at": row["observed_at"],
                "expires_at": row["expires_at"],
                "age_seconds": age,
                "expires_in_seconds": remaining,
                "freshness": "fresh",
                "source_type": row["source_type"],
                "source_id": row["source_id"],
                "source_digest": row["source_digest"],
            })

        contributions.sort(key=lambda row: (-row["points"], row["signal_id"]))
        excluded.sort(key=lambda row: row["signal_id"])
        signal_score = round(min(100.0, sum(row["points"] for row in contributions)), 6)
        context_floor = max(row["floor"] for row in context_floors)
        score = round(max(signal_score, context_floor), 6)
        tier = _risk_tier(score)
        input_sha = _sha256({
            "formula_version": FORMULA_VERSION,
            "asset_id": binding["asset_id"],
            "asset_revision": binding["revision"],
            "asset_version_digest": binding["version_digest"],
            "signals": input_bindings,
            "context": normalized_context,
            "evaluated_at": now,
        })

        snapshot_id = self._snapshot_id(binding["asset_id"])
        existing = self._snapshots.get(snapshot_id)
        if existing is None:
            if expected != 0:
                raise RecordConflict("dynamic risk snapshot revision is stale")
            prior = None
            history: list[dict[str, Any]] = []
        else:
            validated = self._validate_snapshot_record(existing, tenant_ref=tenant_ref)
            if validated["asset_id"] != binding["asset_id"]:
                raise DynamicRiskStateError("dynamic risk snapshot identity collision")
            if validated["revision"] != expected:
                raise RecordConflict(
                    f"dynamic risk snapshot changed (expected revision {expected}, "
                    f"found {validated['revision']})"
                )
            prior = dict(validated["current"])
            history = [dict(row) for row in validated["history"]]

        current_points = {row["signal_id"]: row["points"] for row in contributions}
        prior_points = (
            {}
            if prior is None
            else {row["signal_id"]: row["points"] for row in prior["contributions"]}
        )
        removed_reason = {row["signal_id"]: row["reason"] for row in excluded}
        added = sorted(set(current_points) - set(prior_points))
        removed = sorted(set(prior_points) - set(current_points))
        changed = [
            {
                "signal_id": identity,
                "from_points": prior_points[identity],
                "to_points": current_points[identity],
            }
            for identity in sorted(set(prior_points).intersection(current_points))
            if prior_points[identity] != current_points[identity]
        ]
        if prior is None:
            change = {
                "from_score": None,
                "delta": None,
                "direction": "initial",
                "added_signal_ids": added,
                "removed_signals": [],
                "changed_signals": changed,
                "context_floor_change": None,
            }
        else:
            delta = round(score - prior["score"], 6)
            change = {
                "from_score": prior["score"],
                "delta": delta,
                "direction": _direction(delta),
                "added_signal_ids": added,
                "removed_signals": [
                    {
                        "signal_id": identity,
                        "reason": removed_reason.get(identity, "not_current"),
                    }
                    for identity in removed
                ],
                "changed_signals": changed,
                "context_floor_change": round(
                    context_floor - prior["context_floor"], 6
                ),
            }

        current = {
            "schema": PROJECTION_SCHEMA,
            "formula_version": FORMULA_VERSION,
            "evaluated_at": now,
            "evaluated_by_kind": actor_kind,
            "evaluated_by": actor_name,
            "asset_id": binding["asset_id"],
            "asset_revision": binding["revision"],
            "asset_version_digest": binding["version_digest"],
            "context": normalized_context,
            "context_floors": context_floors,
            "context_floor": context_floor,
            "signal_score": signal_score,
            "score": score,
            "risk_tier": tier,
            "active_signal_count": len(contributions),
            "contributions": contributions,
            "excluded_signals": excluded,
            "signal_state_sha256": _sha256(input_bindings),
            "fresh_through": (
                min(row["expires_at"] for row in contributions)
                if contributions
                else None
            ),
            "input_sha256": input_sha,
            "change": change,
        }
        history.append(self._history_entry(current))
        history = history[-_MAX_HISTORY:]
        base = {
            "schema": SNAPSHOT_SCHEMA,
            "tenant_ref": tenant_ref,
            "asset_id": binding["asset_id"],
            "formula_version": FORMULA_VERSION,
            "current": current,
            "history": history,
            "status": "current",
        }
        snapshot_sha = _sha256(base)
        if existing is None:
            saved = self._snapshots.create(
                {
                    "id": snapshot_id,
                    **base,
                    "snapshot_sha256": snapshot_sha,
                },
                action="publish_dynamic_risk_snapshot",
                actor=actor_name,
                max_records=_MAX_SNAPSHOTS,
            )
        else:
            def mutate(row: dict[str, Any]) -> None:
                for key, value in base.items():
                    row[key] = value
                row["snapshot_sha256"] = snapshot_sha

            saved = self._snapshots.update(
                snapshot_id,
                mutate,
                expected_revision=expected,
                action="publish_dynamic_risk_snapshot",
                actor=actor_name,
            )
            if saved is None:
                raise DynamicRiskStateError("dynamic risk snapshot disappeared during update")
        validated_saved = self._validate_snapshot_record(saved, tenant_ref=tenant_ref)
        return self._project_snapshot(validated_saved)


default_service = DynamicRiskService()


__all__ = [
    "ActorKind",
    "CATEGORY_WEIGHTS",
    "CONTEXT_FLOORS",
    "DRIFT_RECEIPT_SCHEMA",
    "DynamicRiskAssetError",
    "DynamicRiskConfigError",
    "DynamicRiskError",
    "DynamicRiskIdempotencyConflict",
    "DynamicRiskService",
    "DynamicRiskStateError",
    "FORMULA_VERSION",
    "POLICY_RECEIPT_SCHEMA",
    "PROJECTION_SCHEMA",
    "RUNTIME_RECEIPT_SCHEMA",
    "RiskActor",
    "RiskCategory",
    "RiskContext",
    "RiskSignal",
    "SIGNAL_SCHEMA",
    "SNAPSHOT_SCHEMA",
    "SignalSourceType",
    "default_service",
    "enabled",
    "require_enabled",
    "signal_from_drift_receipt",
    "signal_from_policy_receipt",
    "signal_from_runtime_receipt",
]
