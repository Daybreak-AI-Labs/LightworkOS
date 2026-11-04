"""Tenant-governed, digest-only AI explanation receipts.

This capability is deliberately default-off.  Provider-specific explainers
must be reduced to one of the closed normalized receipt schemas in this module
before admission.  Raw feature values, prompts, model outputs, subject labels,
and provider payloads are outside the persistence contract.

The resulting reason and adverse-reason codes are deterministic decision
support.  They are not legal notices, compliance findings, certifications, or
a substitute for a qualified human reviewer.
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

EXPLANATION_SCHEMA = "lightwork.ai-explanation.v1"
PROJECTION_VERSION = "ai-explanation-reason-projection-v1"
DECISION_SUPPORT_NOTICE = (
    "Decision-support explanation only; not a legal adverse-action notice, "
    "compliance determination, certification, or substitute for qualified "
    "human review."
)

NATIVE_ADDITIVE_RECEIPT_SCHEMA = (
    "lightwork.ai-explainability-normalized-native-additive-receipt.v1"
)
SHAP_RECEIPT_SCHEMA = "lightwork.ai-explainability-normalized-shap-receipt.v1"
LIME_RECEIPT_SCHEMA = "lightwork.ai-explainability-normalized-lime-receipt.v1"
CAPTUM_RECEIPT_SCHEMA = "lightwork.ai-explainability-normalized-captum-receipt.v1"
ALIBI_RECEIPT_SCHEMA = "lightwork.ai-explainability-normalized-alibi-receipt.v1"
COUNTERFACTUAL_RECEIPT_SCHEMA = (
    "lightwork.ai-explainability-normalized-counterfactual-receipt.v1"
)

METHOD_RECEIPT_SCHEMAS: dict[str, str] = {
    "native_additive": NATIVE_ADDITIVE_RECEIPT_SCHEMA,
    "shap": SHAP_RECEIPT_SCHEMA,
    "lime": LIME_RECEIPT_SCHEMA,
    "captum": CAPTUM_RECEIPT_SCHEMA,
    "alibi": ALIBI_RECEIPT_SCHEMA,
    "counterfactual": COUNTERFACTUAL_RECEIPT_SCHEMA,
}

_EXPLANATIONS = GovernedRecordStore(
    "ai_explanations",
    "AIX",
    "ai_explanation",
)

_ASSET_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,127}\Z")
_IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}\Z")
_EXPLANATION_ID_RE = re.compile(r"AIX-[0-9a-f]{32}\Z")
_TENANT_REF_RE = re.compile(r"TEN-[0-9a-f]{24}\Z")

_RECEIPT_FIELDS = frozenset({
    "schema",
    "method",
    "asset_id",
    "asset_revision",
    "asset_version_digest",
    "receipt_id",
    "observed_at",
    "input_sha256",
    "output_sha256",
    "explainer_sha256",
    "source_sha256",
    "contributions",
    "counterfactuals",
    "receipt_sha256",
})
_CONTRIBUTION_FIELDS = frozenset({"factor_code", "direction", "magnitude"})
_COUNTERFACTUAL_FIELDS = frozenset({
    "change_code",
    "outcome_code",
    "distance",
    "feasible",
})
_REVIEW_FIELDS = frozenset({
    "reviewed_at",
    "outcome",
    "evidence_sha256",
    "reviewer",
})
_RECORD_FIELDS = frozenset({
    "id",
    "schema",
    "tenant_ref",
    "asset_id",
    "asset_revision",
    "asset_version_digest",
    "method",
    "observed_at",
    "input_sha256",
    "output_sha256",
    "explainer_sha256",
    "source_sha256",
    "receipt_id_sha256",
    "receipt_sha256",
    "contributions",
    "counterfactuals",
    "projection",
    "payload_sha256",
    "recorded_by_kind",
    "recorded_by",
    "status",
    "review",
    "state_sha256",
})
_STORE_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})
_IMMUTABLE_PAYLOAD_FIELDS = (
    "schema",
    "tenant_ref",
    "asset_id",
    "asset_revision",
    "asset_version_digest",
    "method",
    "observed_at",
    "input_sha256",
    "output_sha256",
    "explainer_sha256",
    "source_sha256",
    "receipt_id_sha256",
    "receipt_sha256",
    "contributions",
    "counterfactuals",
    "projection",
)

_MAX_RECORDS = 10_000
_MAX_CONTRIBUTIONS = 64
_MAX_COUNTERFACTUALS = 16
_MAX_REASON_CODES = 8
_MAX_ADVERSE_REASONS = 4
_MAX_PUBLIC_COUNTERFACTUALS = 8
_MAX_FUTURE_SKEW_SECONDS = 300.0


class ExplainabilityError(RuntimeError):
    """Base failure for governed AI explanations."""


class ExplainabilityConfigError(ExplainabilityError):
    """The default-off capability is unavailable or disabled."""


class ExplainabilityStateError(ExplainabilityError):
    """Persisted explanation state is missing, stale, or malformed."""


class ExplainabilityAssetError(ExplainabilityError):
    """An exact current Model Risk asset binding cannot be established."""


class ExplainabilityIdempotencyConflict(ExplainabilityError):
    """A receipt identity was reused for a different normalized payload."""


class ExplanationMethod(str, Enum):
    NATIVE_ADDITIVE = "native_additive"
    SHAP = "shap"
    LIME = "lime"
    CAPTUM = "captum"
    ALIBI = "alibi"
    COUNTERFACTUAL = "counterfactual"


class ContributionDirection(str, Enum):
    NEGATIVE = "negative"
    NEUTRAL = "neutral"
    POSITIVE = "positive"


class ActorKind(str, Enum):
    HUMAN = "human"
    SYSTEM = "system"


class ReviewOutcome(str, Enum):
    ACCEPTED = "accepted"
    NEEDS_REMEDIATION = "needs_remediation"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ExplanationActor:
    """Explicit authenticated human or named system authority."""

    kind: ActorKind | str
    principal: str


@dataclass(frozen=True)
class NormalizedExplanation:
    """Transient, closed explanation receipt after provider-boundary checks."""

    method: str
    asset_id: str
    asset_revision: int
    asset_version_digest: str
    receipt_id: str
    observed_at: float
    input_sha256: str
    output_sha256: str
    explainer_sha256: str
    source_sha256: str
    contributions: tuple[dict[str, Any], ...]
    counterfactuals: tuple[dict[str, Any], ...]
    receipt_sha256: str


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


def _identity(value: object, label: str) -> str:
    text = _text(value, label, 256)
    if not _IDENTITY_RE.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _token(value: object, label: str) -> str:
    text = _text(value, label, 128).lower()
    if not _TOKEN_RE.fullmatch(text):
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


def _revision(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("revision must be a positive integer")
    return value


def _number(value: object, label: str, minimum: float, maximum: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{label} must be a number")
    number = float(value)
    if not math.isfinite(number) or number < minimum or number > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return number


def _timestamp(value: object, label: str) -> float:
    return _number(value, label, 0.000001, 100_000_000_000.0)


def _enum_value(value: object, enum_type: type[Enum], label: str) -> str:
    raw = value.value if isinstance(value, enum_type) else value
    try:
        return str(enum_type(raw).value)
    except (TypeError, ValueError) as exc:
        choices = ", ".join(sorted(str(member.value) for member in enum_type))
        raise ValueError(f"{label} must be one of: {choices}") from exc


def _principal(kind: object, principal: object) -> tuple[str, str]:
    normalized_kind = _enum_value(kind, ActorKind, "actor kind")
    normalized_principal = _text(principal, "actor principal", 4_096)
    prefix = "user:" if normalized_kind == ActorKind.HUMAN.value else "system:"
    if not normalized_principal.startswith(prefix) or len(normalized_principal) <= len(prefix):
        raise ValueError(f"{normalized_kind} actor principal must start with {prefix}")
    return normalized_kind, normalized_principal


def _actor(actor: ExplanationActor) -> tuple[str, str]:
    if not isinstance(actor, ExplanationActor):
        raise TypeError("actor must be an ExplanationActor")
    return _principal(actor.kind, actor.principal)


def _actor_ref(principal: str, tenant_ref: str) -> str:
    material = f"{tenant_ref}\x00{principal}".encode()
    return "ACT-" + hashlib.sha256(material).hexdigest()[:24]


def _tenant_ref() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise ExplainabilityStateError("AI explanation operations require an explicit tenant")
    return "TEN-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:24]


def enabled() -> bool:
    """Return true only for an explicit ``[ai_explainability] enable = true``."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("ai_explainability")
    return isinstance(section, Mapping) and section.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise ExplainabilityConfigError(
            "AI explainability is disabled; set [ai_explainability] enable = true"
        )


def _normalize_contributions(value: object) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list):
        raise ValueError("contributions must be a list")
    if len(value) > _MAX_CONTRIBUTIONS:
        raise ValueError(f"contributions cannot exceed {_MAX_CONTRIBUTIONS} items")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != _CONTRIBUTION_FIELDS:
            raise ValueError("each contribution must use the closed normalized shape")
        factor = _token(item.get("factor_code"), "factor_code")
        if factor in seen:
            raise ValueError("contribution factor_code values must be unique")
        seen.add(factor)
        direction = _enum_value(
            item.get("direction"), ContributionDirection, "contribution direction"
        )
        magnitude = _number(item.get("magnitude"), "magnitude", 0.0, 1.0)
        if direction == ContributionDirection.NEUTRAL.value and magnitude != 0.0:
            raise ValueError("neutral contributions must have zero magnitude")
        normalized.append({
            "factor_code": factor,
            "direction": direction,
            "magnitude": magnitude,
        })
    return tuple(sorted(normalized, key=lambda row: row["factor_code"]))


def _normalize_counterfactuals(value: object) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list):
        raise ValueError("counterfactuals must be a list")
    if len(value) > _MAX_COUNTERFACTUALS:
        raise ValueError(f"counterfactuals cannot exceed {_MAX_COUNTERFACTUALS} items")
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != _COUNTERFACTUAL_FIELDS:
            raise ValueError("each counterfactual must use the closed normalized shape")
        change = _token(item.get("change_code"), "change_code")
        outcome = _token(item.get("outcome_code"), "outcome_code")
        identity = (change, outcome)
        if identity in seen:
            raise ValueError("counterfactual change/outcome pairs must be unique")
        seen.add(identity)
        feasible = item.get("feasible")
        if not isinstance(feasible, bool):
            raise ValueError("counterfactual feasible must be a boolean")
        normalized.append({
            "change_code": change,
            "outcome_code": outcome,
            "distance": _number(item.get("distance"), "distance", 0.0, 1.0),
            "feasible": feasible,
        })
    return tuple(sorted(normalized, key=lambda row: (row["change_code"], row["outcome_code"])))


def _normalized_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_method: ExplanationMethod,
) -> NormalizedExplanation:
    if not isinstance(receipt, Mapping):
        raise TypeError("normalized explanation receipt must be a mapping")
    if set(receipt) != _RECEIPT_FIELDS:
        raise ValueError("normalized explanation receipt has unexpected or missing fields")
    method = _enum_value(receipt.get("method"), ExplanationMethod, "method")
    if method != expected_method.value:
        raise ValueError(f"normalized explanation method must be {expected_method.value}")
    if receipt.get("schema") != METHOD_RECEIPT_SCHEMAS[method]:
        raise ValueError("normalized explanation receipt schema is unsupported")
    payload = {key: receipt[key] for key in sorted(_RECEIPT_FIELDS - {"receipt_sha256"})}
    receipt_sha = _digest(receipt.get("receipt_sha256"), "receipt_sha256")
    if _sha256(payload) != receipt_sha:
        raise ValueError("normalized explanation receipt digest does not match its payload")
    contributions = _normalize_contributions(receipt.get("contributions"))
    counterfactuals = _normalize_counterfactuals(receipt.get("counterfactuals"))
    if method == ExplanationMethod.COUNTERFACTUAL.value:
        if not counterfactuals:
            raise ValueError("counterfactual receipts require at least one counterfactual")
    elif not contributions:
        raise ValueError(f"{method} receipts require at least one contribution")
    return NormalizedExplanation(
        method=method,
        asset_id=_asset_id(receipt.get("asset_id")),
        asset_revision=_revision(receipt.get("asset_revision")),
        asset_version_digest=_digest(
            receipt.get("asset_version_digest"), "asset_version_digest"
        ),
        receipt_id=_identity(receipt.get("receipt_id"), "receipt_id"),
        observed_at=_timestamp(receipt.get("observed_at"), "observed_at"),
        input_sha256=_digest(receipt.get("input_sha256"), "input_sha256"),
        output_sha256=_digest(receipt.get("output_sha256"), "output_sha256"),
        explainer_sha256=_digest(receipt.get("explainer_sha256"), "explainer_sha256"),
        source_sha256=_digest(receipt.get("source_sha256"), "source_sha256"),
        contributions=contributions,
        counterfactuals=counterfactuals,
        receipt_sha256=receipt_sha,
    )


def explanation_from_native_additive_receipt(
    receipt: Mapping[str, Any],
) -> NormalizedExplanation:
    return _normalized_receipt(receipt, expected_method=ExplanationMethod.NATIVE_ADDITIVE)


def explanation_from_shap_receipt(receipt: Mapping[str, Any]) -> NormalizedExplanation:
    return _normalized_receipt(receipt, expected_method=ExplanationMethod.SHAP)


def explanation_from_lime_receipt(receipt: Mapping[str, Any]) -> NormalizedExplanation:
    return _normalized_receipt(receipt, expected_method=ExplanationMethod.LIME)


def explanation_from_captum_receipt(receipt: Mapping[str, Any]) -> NormalizedExplanation:
    return _normalized_receipt(receipt, expected_method=ExplanationMethod.CAPTUM)


def explanation_from_alibi_receipt(receipt: Mapping[str, Any]) -> NormalizedExplanation:
    return _normalized_receipt(receipt, expected_method=ExplanationMethod.ALIBI)


def explanation_from_counterfactual_receipt(
    receipt: Mapping[str, Any],
) -> NormalizedExplanation:
    return _normalized_receipt(receipt, expected_method=ExplanationMethod.COUNTERFACTUAL)


_RECEIPT_ADAPTERS: dict[str, Callable[[Mapping[str, Any]], NormalizedExplanation]] = {
    "native_additive": explanation_from_native_additive_receipt,
    "shap": explanation_from_shap_receipt,
    "lime": explanation_from_lime_receipt,
    "captum": explanation_from_captum_receipt,
    "alibi": explanation_from_alibi_receipt,
    "counterfactual": explanation_from_counterfactual_receipt,
}


def explanation_from_receipt(receipt: Mapping[str, Any]) -> NormalizedExplanation:
    """Dispatch one closed normalized provider receipt by its exact method."""

    if not isinstance(receipt, Mapping):
        raise TypeError("normalized explanation receipt must be a mapping")
    method = _enum_value(receipt.get("method"), ExplanationMethod, "method")
    return _RECEIPT_ADAPTERS[method](receipt)


def _reason_projection(
    contributions: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    counterfactuals: tuple[dict[str, Any], ...] | list[dict[str, Any]],
) -> dict[str, Any]:
    ranked = sorted(
        contributions,
        key=lambda row: (-row["magnitude"], row["factor_code"], row["direction"]),
    )
    reason_codes = [
        f"explain.{row['factor_code']}.{row['direction']}"
        for row in ranked[:_MAX_REASON_CODES]
    ]
    adverse_reasons = [
        f"adverse.{row['factor_code']}"
        for row in ranked
        if row["direction"] == ContributionDirection.NEGATIVE.value
    ][:_MAX_ADVERSE_REASONS]
    ranked_counterfactuals = sorted(
        counterfactuals,
        key=lambda row: (
            not row["feasible"],
            row["distance"],
            row["change_code"],
            row["outcome_code"],
        ),
    )[:_MAX_PUBLIC_COUNTERFACTUALS]
    return {
        "projection_version": PROJECTION_VERSION,
        "reason_codes": reason_codes,
        "adverse_reasons": adverse_reasons,
        "counterfactuals": [
            {
                "code": f"counterfactual.{row['change_code']}.to.{row['outcome_code']}",
                "distance": row["distance"],
                "feasible": row["feasible"],
            }
            for row in ranked_counterfactuals
        ],
        "disclaimer": DECISION_SUPPORT_NOTICE,
    }


def _payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record.get(key) for key in _IMMUTABLE_PAYLOAD_FIELDS}


def _state(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": record.get("id"),
        "payload_sha256": record.get("payload_sha256"),
        "recorded_by_kind": record.get("recorded_by_kind"),
        "recorded_by": record.get("recorded_by"),
        "status": record.get("status"),
        "review": record.get("review"),
    }


def _validate_review(value: object, recorded_by: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != _REVIEW_FIELDS:
        raise ExplainabilityStateError("stored explanation review is malformed")
    try:
        reviewed_at = _timestamp(value.get("reviewed_at"), "reviewed_at")
        outcome = _enum_value(value.get("outcome"), ReviewOutcome, "review outcome")
        evidence = _digest(value.get("evidence_sha256"), "evidence_sha256")
        _, reviewer = _principal(ActorKind.HUMAN, value.get("reviewer"))
    except (TypeError, ValueError) as exc:
        raise ExplainabilityStateError("stored explanation review is malformed") from exc
    if reviewer == recorded_by:
        raise ExplainabilityStateError("stored explanation violates four-eyes review")
    return {
        "reviewed_at": reviewed_at,
        "outcome": outcome,
        "evidence_sha256": evidence,
        "reviewer": reviewer,
    }


def _validate_record(record: Mapping[str, Any], *, tenant_ref: str) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise ExplainabilityStateError("stored explanation is not an object")
    if (set(record) - _RECORD_FIELDS - _STORE_METADATA) or (_RECORD_FIELDS - set(record)):
        raise ExplainabilityStateError("stored explanation shape is malformed")
    try:
        explanation_id = _text(record.get("id"), "explanation id", 36)
        if not _EXPLANATION_ID_RE.fullmatch(explanation_id):
            raise ValueError("explanation id is invalid")
        stored_tenant = _text(record.get("tenant_ref"), "tenant_ref", 28)
        if not _TENANT_REF_RE.fullmatch(stored_tenant) or stored_tenant != tenant_ref:
            raise ValueError("explanation tenant binding is invalid")
        if record.get("schema") != EXPLANATION_SCHEMA:
            raise ValueError("explanation schema is unsupported")
        _revision(record.get("revision"))
        _timestamp(record.get("created_at"), "created_at")
        _timestamp(record.get("updated_at"), "updated_at")
        _asset_id(record.get("asset_id"))
        _revision(record.get("asset_revision"))
        _digest(record.get("asset_version_digest"), "asset_version_digest")
        method = _enum_value(record.get("method"), ExplanationMethod, "method")
        _timestamp(record.get("observed_at"), "observed_at")
        for field in (
            "input_sha256",
            "output_sha256",
            "explainer_sha256",
            "source_sha256",
            "receipt_id_sha256",
            "receipt_sha256",
            "payload_sha256",
            "state_sha256",
        ):
            _digest(record.get(field), field)
        contributions = _normalize_contributions(record.get("contributions"))
        counterfactuals = _normalize_counterfactuals(record.get("counterfactuals"))
        if method == ExplanationMethod.COUNTERFACTUAL.value:
            if not counterfactuals:
                raise ValueError("counterfactual explanation has no counterfactuals")
        elif not contributions:
            raise ValueError("attribution explanation has no contributions")
        kind, principal = _principal(
            record.get("recorded_by_kind"), record.get("recorded_by")
        )
        status = _token(record.get("status"), "status")
        if status not in {"pending_review", "reviewed"}:
            raise ValueError("explanation status is unsupported")
        review = _validate_review(record.get("review"), principal)
        if (status == "pending_review") != (review is None):
            raise ValueError("explanation review lifecycle is inconsistent")
    except ExplainabilityStateError:
        raise
    except (TypeError, ValueError) as exc:
        raise ExplainabilityStateError("stored explanation is malformed") from exc
    expected_projection = _reason_projection(contributions, counterfactuals)
    if record.get("projection") != expected_projection:
        raise ExplainabilityStateError("stored explanation projection is malformed")
    if _sha256(_payload(record)) != record.get("payload_sha256"):
        raise ExplainabilityStateError("stored explanation payload digest is malformed")
    if _sha256(_state(record)) != record.get("state_sha256"):
        raise ExplainabilityStateError("stored explanation state digest is malformed")
    normalized = dict(record)
    normalized["contributions"] = [dict(row) for row in contributions]
    normalized["counterfactuals"] = [dict(row) for row in counterfactuals]
    normalized["recorded_by_kind"] = kind
    normalized["recorded_by"] = principal
    normalized["review"] = review
    return normalized


class ExplainabilityService:
    """Admit normalized explanations and govern independent human review."""

    def __init__(
        self,
        *,
        records: GovernedRecordStore | None = None,
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
        self._records = records or _EXPLANATIONS
        self._asset_lookup = asset_lookup
        self._clock = clock
        self._enforce_feature = enforce_feature

    def _require_active(self) -> str:
        if self._enforce_feature:
            require_enabled()
        _ = self._records.backend_kind
        return _tenant_ref()

    def _now(self) -> float:
        source = self._clock or self._records.authoritative_time
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
            raise ExplainabilityAssetError("Model Risk asset lookup failed") from exc
        if not isinstance(observation, Mapping):
            raise ExplainabilityAssetError("Model Risk asset does not exist")
        try:
            observed_asset = _asset_id(observation.get("asset_id"))
            revision = _revision(observation.get("revision"))
            version_digest = _digest(
                observation.get("version_digest"), "asset version_digest"
            )
        except (TypeError, ValueError) as exc:
            raise ExplainabilityAssetError("Model Risk asset binding is malformed") from exc
        if observed_asset != asset:
            raise ExplainabilityAssetError("Model Risk asset lookup changed identity")
        return {
            "asset_id": asset,
            "revision": revision,
            "version_digest": version_digest,
        }

    @staticmethod
    def _binding_state(
        record: Mapping[str, Any], current: Mapping[str, Any]
    ) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        if record["asset_revision"] != current["revision"]:
            reasons.append("asset_revision_changed")
        if record["asset_version_digest"] != current["version_digest"]:
            reasons.append("asset_version_digest_changed")
        return not reasons, reasons

    def _public(
        self,
        record: Mapping[str, Any],
        *,
        current_binding: Mapping[str, Any],
    ) -> dict[str, Any]:
        fresh, reasons = self._binding_state(record, current_binding)
        review = record["review"]
        return {
            "explanation_id": record["id"],
            "revision": record["revision"],
            "asset_id": record["asset_id"],
            "asset_revision": record["asset_revision"],
            "asset_version_digest": record["asset_version_digest"],
            "method": record["method"],
            "observed_at": record["observed_at"],
            "input_sha256": record["input_sha256"],
            "output_sha256": record["output_sha256"],
            "explainer_sha256": record["explainer_sha256"],
            "source_sha256": record["source_sha256"],
            "receipt_id_sha256": record["receipt_id_sha256"],
            "receipt_sha256": record["receipt_sha256"],
            "payload_sha256": record["payload_sha256"],
            "contributions": [dict(row) for row in record["contributions"]],
            "counterfactuals": [dict(row) for row in record["counterfactuals"]],
            "reason_codes": list(record["projection"]["reason_codes"]),
            "adverse_reasons": list(record["projection"]["adverse_reasons"]),
            "counterfactual_projection": [
                dict(row) for row in record["projection"]["counterfactuals"]
            ],
            "projection_version": record["projection"]["projection_version"],
            "disclaimer": record["projection"]["disclaimer"],
            "recorded_by_kind": record["recorded_by_kind"],
            "recorded_by_ref": _actor_ref(record["recorded_by"], record["tenant_ref"]),
            "status": record["status"],
            "review": (
                None
                if review is None
                else {
                    "reviewed_at": review["reviewed_at"],
                    "outcome": review["outcome"],
                    "evidence_sha256": review["evidence_sha256"],
                    "reviewer_ref": _actor_ref(review["reviewer"], record["tenant_ref"]),
                }
            ),
            "binding_current": fresh,
            "stale_reasons": reasons,
            "current_asset_revision": current_binding["revision"],
            "current_asset_version_digest": current_binding["version_digest"],
        }

    def _bounded_records(self, tenant_ref: str) -> list[dict[str, Any]]:
        rows = self._records.list(limit=_MAX_RECORDS + 1)
        if len(rows) > _MAX_RECORDS:
            raise ExplainabilityStateError("AI explanation namespace exceeds its bound")
        return [_validate_record(row, tenant_ref=tenant_ref) for row in rows]

    def ingest_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        actor: ExplanationActor,
    ) -> dict[str, Any]:
        """Idempotently admit one digest-closed, exact-artifact explanation."""

        explanation = explanation_from_receipt(receipt)
        tenant_ref = self._require_active()
        actor_kind, actor_name = _actor(actor)
        binding = self._asset_binding(explanation.asset_id)
        if (
            explanation.asset_revision != binding["revision"]
            or explanation.asset_version_digest != binding["version_digest"]
        ):
            raise ExplainabilityAssetError(
                "normalized explanation receipt is not bound to the current Model Risk asset"
            )
        now = self._now()
        if explanation.observed_at > now + _MAX_FUTURE_SKEW_SECONDS:
            raise ValueError("observed_at is too far in the future")
        receipt_identity = (
            f"{tenant_ref}\x00{explanation.method}:{explanation.receipt_id}"
        )
        identity_sha = hashlib.sha256(receipt_identity.encode("utf-8")).hexdigest()
        record_id = f"AIX-{identity_sha[:32]}"
        contributions = [dict(row) for row in explanation.contributions]
        counterfactuals = [dict(row) for row in explanation.counterfactuals]
        projection = _reason_projection(contributions, counterfactuals)
        payload = {
            "schema": EXPLANATION_SCHEMA,
            "tenant_ref": tenant_ref,
            "asset_id": binding["asset_id"],
            "asset_revision": binding["revision"],
            "asset_version_digest": binding["version_digest"],
            "method": explanation.method,
            "observed_at": explanation.observed_at,
            "input_sha256": explanation.input_sha256,
            "output_sha256": explanation.output_sha256,
            "explainer_sha256": explanation.explainer_sha256,
            "source_sha256": explanation.source_sha256,
            "receipt_id_sha256": hashlib.sha256(
                f"{tenant_ref}\x00{explanation.receipt_id}".encode()
            ).hexdigest(),
            "receipt_sha256": explanation.receipt_sha256,
            "contributions": contributions,
            "counterfactuals": counterfactuals,
            "projection": projection,
        }
        payload_sha = _sha256(payload)
        current = self._records.get(record_id)
        if current is not None:
            validated = _validate_record(current, tenant_ref=tenant_ref)
            if validated["payload_sha256"] != payload_sha:
                raise ExplainabilityIdempotencyConflict(
                    "receipt identity was already used for a different explanation"
                )
            return self._public(validated, current_binding=binding)
        record = {
            "id": record_id,
            **payload,
            "payload_sha256": payload_sha,
            "recorded_by_kind": actor_kind,
            "recorded_by": actor_name,
            "status": "pending_review",
            "review": None,
        }
        record["state_sha256"] = _sha256(_state(record))
        try:
            saved = self._records.create(
                record,
                action="admit_ai_explanation",
                actor=actor_name,
                max_records=_MAX_RECORDS,
            )
        except RecordConflict as exc:
            concurrent = self._records.get(record_id)
            if concurrent is None:
                raise
            validated = _validate_record(concurrent, tenant_ref=tenant_ref)
            if validated["payload_sha256"] != payload_sha:
                raise ExplainabilityIdempotencyConflict(
                    "receipt identity was concurrently reused for a different explanation"
                ) from exc
            saved = validated
        validated_saved = _validate_record(saved, tenant_ref=tenant_ref)
        return self._public(validated_saved, current_binding=binding)

    def get_explanation(self, explanation_id: str) -> dict[str, Any] | None:
        tenant_ref = self._require_active()
        identity = _text(explanation_id, "explanation_id", 36)
        if not _EXPLANATION_ID_RE.fullmatch(identity):
            raise ValueError("explanation_id is invalid")
        row = self._records.get(identity)
        if row is None:
            return None
        validated = _validate_record(row, tenant_ref=tenant_ref)
        binding = self._asset_binding(validated["asset_id"])
        return self._public(validated, current_binding=binding)

    def list_explanations(self, asset_id: str | None = None) -> list[dict[str, Any]]:
        tenant_ref = self._require_active()
        asset = None if asset_id is None else _asset_id(asset_id)
        rows = self._bounded_records(tenant_ref)
        if asset is not None:
            rows = [row for row in rows if row["asset_id"] == asset]
        bindings: dict[str, dict[str, Any]] = {}
        projected: list[dict[str, Any]] = []
        for row in sorted(rows, key=lambda item: (item["observed_at"], item["id"])):
            binding = bindings.get(row["asset_id"])
            if binding is None:
                binding = self._asset_binding(row["asset_id"])
                bindings[row["asset_id"]] = binding
            projected.append(self._public(row, current_binding=binding))
        return projected

    def review_explanation(
        self,
        explanation_id: str,
        *,
        expected_revision: int,
        outcome: ReviewOutcome | str,
        evidence_sha256: str,
        actor: ExplanationActor,
    ) -> dict[str, Any]:
        """CAS-review an explanation with an independent authenticated human."""

        tenant_ref = self._require_active()
        identity = _text(explanation_id, "explanation_id", 36)
        if not _EXPLANATION_ID_RE.fullmatch(identity):
            raise ValueError("explanation_id is invalid")
        expected = _revision(expected_revision)
        actor_kind, reviewer = _actor(actor)
        if actor_kind != ActorKind.HUMAN.value:
            raise ValueError("AI explanation review requires a human actor")
        review_outcome = _enum_value(outcome, ReviewOutcome, "review outcome")
        evidence = _digest(evidence_sha256, "evidence_sha256")
        raw = self._records.get(identity)
        if raw is None:
            raise ExplainabilityStateError("AI explanation does not exist")
        current = _validate_record(raw, tenant_ref=tenant_ref)
        if current["recorded_by"] == reviewer:
            raise ExplainabilityStateError(
                "AI explanation review requires a different principal"
            )
        if current["status"] != "pending_review":
            raise ExplainabilityStateError("AI explanation has already been reviewed")
        binding = self._asset_binding(current["asset_id"])
        fresh, _ = self._binding_state(current, binding)
        if not fresh:
            raise ExplainabilityStateError(
                "stale AI explanation cannot be reviewed against a changed model artifact"
            )
        reviewed_at = self._now()

        def mutate(row: dict[str, Any]) -> None:
            validated = _validate_record(row, tenant_ref=tenant_ref)
            if validated["recorded_by"] == reviewer:
                raise ExplainabilityStateError(
                    "AI explanation review requires a different principal"
                )
            if validated["status"] != "pending_review":
                raise ExplainabilityStateError("AI explanation has already been reviewed")
            row["status"] = "reviewed"
            row["review"] = {
                "reviewed_at": reviewed_at,
                "outcome": review_outcome,
                "evidence_sha256": evidence,
                "reviewer": reviewer,
            }
            row["state_sha256"] = _sha256(_state(row))

        saved = self._records.update(
            identity,
            mutate,
            expected_revision=expected,
            action="review_ai_explanation",
            actor=reviewer,
        )
        if saved is None:
            raise ExplainabilityStateError("AI explanation disappeared during review")
        validated_saved = _validate_record(saved, tenant_ref=tenant_ref)
        return self._public(validated_saved, current_binding=binding)


default_service = ExplainabilityService()


def configured_explainability() -> ExplainabilityService:
    """Return the default authority only when explicitly enabled."""

    require_enabled()
    return default_service


__all__ = [
    "ActorKind",
    "ALIBI_RECEIPT_SCHEMA",
    "CAPTUM_RECEIPT_SCHEMA",
    "COUNTERFACTUAL_RECEIPT_SCHEMA",
    "ContributionDirection",
    "DECISION_SUPPORT_NOTICE",
    "EXPLANATION_SCHEMA",
    "ExplainabilityAssetError",
    "ExplainabilityConfigError",
    "ExplainabilityError",
    "ExplainabilityIdempotencyConflict",
    "ExplainabilityService",
    "ExplainabilityStateError",
    "ExplanationActor",
    "ExplanationMethod",
    "LIME_RECEIPT_SCHEMA",
    "METHOD_RECEIPT_SCHEMAS",
    "NATIVE_ADDITIVE_RECEIPT_SCHEMA",
    "NormalizedExplanation",
    "PROJECTION_VERSION",
    "ReviewOutcome",
    "SHAP_RECEIPT_SCHEMA",
    "configured_explainability",
    "default_service",
    "enabled",
    "explanation_from_alibi_receipt",
    "explanation_from_captum_receipt",
    "explanation_from_counterfactual_receipt",
    "explanation_from_lime_receipt",
    "explanation_from_native_additive_receipt",
    "explanation_from_receipt",
    "explanation_from_shap_receipt",
    "require_enabled",
]
