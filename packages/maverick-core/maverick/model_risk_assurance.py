"""Governed model-risk inventory, assurance evidence, and promotion interlock.

This module is the policy-neutral core of the Model Risk & AI Assurance
Officer.  It keeps discovered facts, human declarations, evidence, decisions,
and deployment lineage in separate CAS-governed collections.  That separation
is deliberate: telemetry cannot approve itself, a generated screening result
cannot become a legal classification, and a promotion approval cannot float
from one artifact or evaluator revision to another.

Framework information is explanatory metadata only.  NIST AI RMF 1.0 mappings
use GOVERN/MAP/MEASURE/MANAGE, ISO/IEC 42001:2023 is identified as an AI
management-system requirements standard, and EU AI Act applicability is always
a dated human assertion.  Nothing returned by this module is a certification,
conformity assessment, or legal determination.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from datetime import date
from itertools import islice
from pathlib import Path
from typing import Any

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

_OBSERVATIONS = GovernedRecordStore(
    "model_risk_observations", "MRO", "model_risk_observation",
)
_DECLARATIONS = GovernedRecordStore(
    "model_risk_declarations", "MRD", "model_risk_declaration",
)
_EVIDENCE = GovernedRecordStore(
    "model_risk_evidence", "MRE", "model_risk_evidence",
)
_INCIDENTS = GovernedRecordStore(
    "model_risk_incidents", "MRI", "model_risk_incident",
)
_DECISIONS = GovernedRecordStore(
    "model_risk_decisions", "MRX", "model_risk_human_decision",
)
_DEPLOYMENTS = GovernedRecordStore(
    "model_risk_deployments", "MRL", "model_risk_deployment_lineage",
)

OBSERVATION_SCHEMA = "lightwork.model-risk-observation.v1"
DECLARATION_SCHEMA = "lightwork.model-risk-declaration.v1"
EVIDENCE_SCHEMA = "lightwork.model-risk-evidence.v1"
INCIDENT_SCHEMA = "lightwork.model-risk-incident.v1"
DECISION_SCHEMA = "lightwork.model-risk-human-decision.v1"
DEPLOYMENT_SCHEMA = "lightwork.model-risk-deployment-lineage.v1"
PACK_SCHEMA = "lightwork.model-risk-assurance-pack.v1"
PACK_EVENT = "model_risk_assurance_pack"
_MAX_NAMESPACE_RECORDS = 5_000

_ASSET_TYPES = frozenset({
    "system",
    "component",
    "model",
    "agent",
    "tool",
    "dataset",
    "provider",
})
_ALLOWED_PARENT_TYPES = {
    "system": frozenset(),
    "component": frozenset({"system", "component"}),
    "agent": frozenset({"system", "component"}),
    "model": frozenset({"system", "component", "agent"}),
    "tool": frozenset({"system", "component", "agent"}),
    "dataset": frozenset({"system", "component", "agent"}),
    "provider": frozenset({"system", "component", "agent"}),
}
_MAX_HIERARCHY_DEPTH = 16
_LIFECYCLES = frozenset({"proposed", "approved", "rejected", "production", "suspended", "retired"})
_ACTIVE_LIFECYCLES = frozenset({"approved", "production"})
_RISK_TIERS = frozenset({"low", "medium", "high", "critical"})
_EVIDENCE_KINDS = frozenset({
    "evaluation",
    "red_team",
    "training_run",
    "drift_monitoring",
    "model_card",
    "data_assessment",
    "vendor_assessment",
    "incident_analysis",
    "human_oversight_test",
    "explainability",
    "fairness",
})
_EVIDENCE_RESULTS = frozenset({"passed", "failed", "inconclusive"})
_REVIEW_DECISIONS = frozenset({"approved", "rejected", "revoked"})
_INCIDENT_STATES = frozenset({"open", "contained", "resolved", "dismissed"})
_INCIDENT_TRANSITIONS = {
    "open": frozenset({"contained", "resolved", "dismissed"}),
    "contained": frozenset({"resolved", "dismissed"}),
    "resolved": frozenset(),
    "dismissed": frozenset(),
}
_EU_ASSERTED_CATEGORIES = frozenset({
    "undetermined",
    "not_applicable",
    "minimal",
    "limited",
    "high_risk",
    "prohibited",
    "gpai",
    "gpai_systemic_risk",
})
_HIGH_RISK_DOMAINS = frozenset({
    "biometrics",
    "critical_infrastructure",
    "education",
    "employment",
    "essential_services",
    "law_enforcement",
    "migration_border",
    "justice_democracy",
})
_PROHIBITED_SIGNALS = frozenset({
    "harmful_manipulation",
    "vulnerability_exploitation",
    "social_scoring",
    "profiling_only_crime_prediction",
    "untargeted_facial_scraping",
    "workplace_education_emotion_inference",
    "sensitive_biometric_categorisation",
    "restricted_realtime_remote_biometric_id",
})
_TRANSPARENCY_SIGNALS = frozenset({
    "human_interaction",
    "synthetic_content",
    "emotion_or_biometric_categorisation",
    "deepfake",
})
_SENSITIVE_KEY = re.compile(
    r"(?:secret|token|password|passwd|credential|authorization|api[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SOURCE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,63}\Z")
_ASSET_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_TOKEN_RE = re.compile(r"[a-z][a-z0-9_:-]{0,63}\Z")
_TRAINING_KEY_ID_RE = re.compile(r"[0-9a-f]{16}\Z")
_TRAINING_LICENSE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}\Z")

_TRAINING_COMMITMENT_SCHEMA = "lightwork.training-transparency-commitment.v1"
_TRAINING_COMMITMENT_FIELDS = frozenset({
    "schema",
    "dataset_sha256",
    "environment_sha256",
    "base_model_artifact_sha256",
    "adapter_sha256",
    "approval_subject_sha256",
    "receipt_payload_sha256",
    "event_hash",
    "key_id",
})
_TRAINING_ASSURANCE_SCHEMA = "lightwork.training-assurance-commitment.v1"
_TRAINING_ASSURANCE_FIELDS = frozenset({
    "schema",
    "dataset_sha256",
    "base_model_license_id",
    "base_model_license_evidence_sha256",
    "evaluation_run_sha256",
    "sealed_holdout_sha256",
    "qualification_evidence_sha256",
    "qualification_policy_sha256",
    "adapter_sha256",
    "receipt_payload_sha256",
})

_MAX_JSON_BYTES = 64 * 1024
_MAX_COLLECTION = 256
_MAX_EVIDENCE_BINDINGS = 64
_MAX_FUTURE_SKEW = 300.0
_MAX_VALIDITY_SECONDS = 5 * 366 * 24 * 60 * 60
_MISSING = object()

NIST_AI_RMF_METADATA = {
    "framework": "NIST AI Risk Management Framework",
    "version": "1.0",
    "version_status": "under_revision",
    "functions": ["GOVERN", "MAP", "MEASURE", "MANAGE"],
    "source": "https://www.nist.gov/itl/ai-risk-management-framework",
    "mapping_only": True,
}
ISO_42001_METADATA = {
    "standard": "ISO/IEC 42001:2023",
    "kind": "AI management system requirements",
    "source": "https://www.iso.org/standard/81230.html",
    "mapping_only": True,
}
EU_AI_ACT_METADATA = {
    "instrument": "Regulation (EU) 2024/1689",
    "source": "https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai",
    "applicability": "human_review_required",
    "mapping_only": True,
}
NON_CERTIFICATION_NOTICE = (
    "Decision-support and evidence metadata only; not a certification, legal "
    "classification, conformity assessment, or legal advice."
)


class ModelRiskAssuranceError(RuntimeError):
    """Base failure for governed model-risk assurance."""


class ModelRiskStateError(ModelRiskAssuranceError):
    """Persisted authority is missing, malformed, or internally inconsistent."""


class ModelRiskConfigError(ModelRiskAssuranceError):
    """Deployment-global assurance policy is malformed or unreadable."""


class PromotionGateDenied(ModelRiskAssuranceError):
    """Raised by the enforcing promotion interlock when assurance is incomplete."""

    def __init__(self, decision: dict[str, Any]) -> None:
        self.decision = decision
        reasons = "; ".join(decision.get("reasons") or ["promotion denied"])
        super().__init__(reasons)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _required_text(value: object, label: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if not text:
        raise ValueError(f"{label} is required")
    if len(text) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    if _CONTROL_RE.search(text):
        raise ValueError(f"{label} contains control characters")
    _reject_secret(text, label)
    return text


def _optional_text(value: object, label: str, limit: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if len(text) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    if _CONTROL_RE.search(text):
        raise ValueError(f"{label} contains control characters")
    _reject_secret(text, label)
    return text


def _reject_secret(value: str, label: str) -> None:
    try:
        from .safety.secret_detector import scan

        matches = scan(value)
    except Exception as exc:
        raise ValueError("secret detection is unavailable") from exc
    if matches:
        kinds = ", ".join(sorted({match.name for match in matches}))
        raise ValueError(f"{label} contains secret material ({kinds})")


def _token(value: object, label: str, allowed: frozenset[str] | None = None) -> str:
    text = _required_text(value, label, 64).lower().replace("-", "_")
    if not _TOKEN_RE.fullmatch(text):
        raise ValueError(f"{label} must be a stable token")
    if allowed is not None and text not in allowed:
        raise ValueError(f"{label} must be one of {sorted(allowed)}")
    return text


def _source(value: object) -> str:
    text = _required_text(value, "source", 64)
    if not _SOURCE_RE.fullmatch(text):
        raise ValueError("source must be a stable namespace token")
    return text


def _asset_id(value: object) -> str:
    text = _required_text(value, "asset_id", 36)
    if not _ASSET_RE.fullmatch(text):
        raise ValueError("asset_id is not a model-risk inventory identity")
    return text


def _digest(value: object, label: str) -> str:
    text = _required_text(value, label, 71).lower()
    if not _DIGEST_RE.fullmatch(text):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return text.removeprefix("sha256:")


def _revision(value: object, label: str = "expected_revision") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _timestamp(value: object | None, label: str, *, now: float | None = None) -> float:
    stamp = time.time() if value is None else float(value)
    if not math.isfinite(stamp) or stamp <= 0:
        raise ValueError(f"{label} must be a positive finite timestamp")
    reference = time.time() if now is None else float(now)
    if stamp > reference + _MAX_FUTURE_SKEW:
        raise ValueError(f"{label} exceeds the clock-skew allowance")
    return stamp


def _expiry(value: object, observed_at: float, label: str = "valid_until") -> float:
    stamp = float(value)
    if not math.isfinite(stamp) or stamp <= observed_at:
        raise ValueError(f"{label} must be after observed_at")
    if stamp - observed_at > _MAX_VALIDITY_SECONDS:
        raise ValueError(f"{label} exceeds the maximum validity window")
    return stamp


def _bounded_tokens(
    values: object,
    label: str,
    *,
    allowed: frozenset[str] | None = None,
    limit: int = _MAX_COLLECTION,
) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes, Mapping)) or not isinstance(values, Iterable):
        raise ValueError(f"{label} must be a list")
    raw = list(islice(iter(values), limit + 1))
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds {limit} items")
    return sorted({_token(item, label, allowed) for item in raw})


def _bounded_json(value: object, label: str, *, max_fields: int = 64) -> object:
    """Validate bounded JSON-like metadata without persisting credentials."""

    seen = 0

    def visit(item: object, depth: int) -> object:
        nonlocal seen
        if depth > 5:
            raise ValueError(f"{label} exceeds the nesting limit")
        if item is None or isinstance(item, bool):
            return item
        if isinstance(item, int):
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError(f"{label} contains a non-finite number")
            return item
        if isinstance(item, str):
            return _optional_text(item, label, 2000)
        if isinstance(item, Mapping):
            if len(item) > max_fields:
                raise ValueError(f"{label} exceeds {max_fields} fields")
            out: dict[str, object] = {}
            for raw_key in sorted(item, key=str):
                key = _required_text(raw_key, f"{label} key", 128)
                if _SENSITIVE_KEY.search(key):
                    raise ValueError(f"{label} contains sensitive key {key!r}")
                seen += 1
                if seen > max_fields * 4:
                    raise ValueError(f"{label} is too complex")
                out[key] = visit(item[raw_key], depth + 1)
            return out
        if isinstance(item, (list, tuple)):
            if len(item) > _MAX_COLLECTION:
                raise ValueError(f"{label} exceeds {_MAX_COLLECTION} items")
            return [visit(child, depth + 1) for child in item]
        raise ValueError(f"{label} contains an unsupported value")

    out = visit(value, 0)
    if len(_canonical(out)) > _MAX_JSON_BYTES:
        raise ValueError(f"{label} exceeds {_MAX_JSON_BYTES} bytes")
    return out


def _training_commitment(value: object) -> dict[str, str]:
    """Return the strict, content-free commitment emitted by receipt verification."""

    if not isinstance(value, Mapping) or set(value) != _TRAINING_COMMITMENT_FIELDS:
        raise ValueError("training receipt commitment has missing or unexpected fields")
    if value.get("schema") != _TRAINING_COMMITMENT_SCHEMA:
        raise ValueError("training receipt commitment schema is invalid")
    key_id = value.get("key_id")
    if not isinstance(key_id, str) or not _TRAINING_KEY_ID_RE.fullmatch(key_id):
        raise ValueError("training receipt commitment key id is invalid")
    return {
        "schema": _TRAINING_COMMITMENT_SCHEMA,
        "dataset_sha256": _digest(value.get("dataset_sha256"), "dataset digest"),
        "environment_sha256": _digest(
            value.get("environment_sha256"),
            "environment digest",
        ),
        "base_model_artifact_sha256": _digest(
            value.get("base_model_artifact_sha256"),
            "base-model artifact digest",
        ),
        "adapter_sha256": _digest(value.get("adapter_sha256"), "adapter digest"),
        "approval_subject_sha256": _digest(
            value.get("approval_subject_sha256"),
            "approval-subject digest",
        ),
        "receipt_payload_sha256": _digest(
            value.get("receipt_payload_sha256"),
            "receipt-payload digest",
        ),
        "event_hash": _digest(value.get("event_hash"), "receipt event hash"),
        "key_id": key_id,
    }


def _training_assurance_commitment(value: object) -> dict[str, str]:
    """Return strict qualification commitments derived from a private receipt."""

    if not isinstance(value, Mapping) or set(value) != _TRAINING_ASSURANCE_FIELDS:
        raise ValueError("training assurance commitment has missing or unexpected fields")
    if value.get("schema") != _TRAINING_ASSURANCE_SCHEMA:
        raise ValueError("training assurance commitment schema is invalid")
    license_id = _required_text(
        value.get("base_model_license_id"),
        "base-model license id",
        128,
    )
    if not _TRAINING_LICENSE_ID_RE.fullmatch(license_id):
        raise ValueError("base-model license id must be a bounded opaque identifier")
    return {
        "schema": _TRAINING_ASSURANCE_SCHEMA,
        "dataset_sha256": _digest(value.get("dataset_sha256"), "dataset digest"),
        "base_model_license_id": license_id,
        "base_model_license_evidence_sha256": _digest(
            value.get("base_model_license_evidence_sha256"),
            "base-model license-evidence digest",
        ),
        "evaluation_run_sha256": _digest(
            value.get("evaluation_run_sha256"),
            "evaluation-run digest",
        ),
        "sealed_holdout_sha256": _digest(
            value.get("sealed_holdout_sha256"),
            "sealed-holdout digest",
        ),
        "qualification_evidence_sha256": _digest(
            value.get("qualification_evidence_sha256"),
            "qualification-evidence digest",
        ),
        "qualification_policy_sha256": _digest(
            value.get("qualification_policy_sha256"),
            "qualification-policy digest",
        ),
        "adapter_sha256": _digest(value.get("adapter_sha256"), "adapter digest"),
        "receipt_payload_sha256": _digest(
            value.get("receipt_payload_sha256"),
            "receipt-payload digest",
        ),
    }


def _training_evidence_scope(
    receipt: Mapping[str, Any],
    assurance: Mapping[str, Any],
) -> str:
    return _sha256({
        "training_receipt_commitment": receipt,
        "training_assurance_commitment": assurance,
    })


def stable_asset_id(asset_type: str, source: str, source_id: str) -> str:
    """Return a deterministic inventory identity for an external source tuple."""

    kind = _token(asset_type, "asset_type", _ASSET_TYPES)
    namespace = _source(source)
    external_id = _required_text(source_id, "source_id", 256)
    digest = _sha256({"asset_type": kind, "source": namespace, "source_id": external_id})
    return f"MAA-{digest[:32]}"


def _record_id(prefix: str, *parts: object) -> str:
    return f"{prefix}-{_sha256([str(part) for part in parts])[:24]}"


def _hierarchy_transaction_target() -> Path:
    """Return the active tenant's strict hierarchy-mutation lock target."""

    from .paths import data_dir

    return data_dir(
        "model_risk_assurance",
        "declaration-hierarchy-mutations.transaction",
    )


def _graph_node_id(source_id: str) -> str:
    identity = {"source": "model_risk_assurance", "source_id": source_id}
    return f"EGN-{_sha256(identity)[:24]}"


def _approved_graph_source_id(evidence: Mapping[str, Any]) -> str:
    return (
        f"{evidence.get('id')}:{evidence.get('payload_sha256')}:"
        f"review:{evidence.get('revision')}"
    )


def _require_evidence_graph_dependency() -> None:
    """Fail before authority mutation unless the evidence graph is usable."""

    try:
        from . import evidence_graph

        available = evidence_graph.enabled()
    except Exception as exc:
        raise ModelRiskConfigError("evidence graph dependency is unreadable") from exc
    if not available:
        raise ModelRiskConfigError(
            "model-risk assurance requires [evidence_graph] enable = true"
        )


def _public(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "_audit_pending"}


def _record_sha(record: Mapping[str, Any]) -> str:
    return _sha256(_public(record))


def _red_team_review_is_independent(record: Mapping[str, Any]) -> bool:
    producer = str(record.get("producer_actor") or "").strip()
    review = record.get("review")
    reviewer = (
        str(review.get("reviewer") or "").strip()
        if isinstance(review, Mapping)
        else ""
    )
    return bool(
        producer
        and reviewer
        and producer.casefold() != reviewer.casefold()
    )


def _citation(record: Mapping[str, Any], relation: str) -> dict[str, Any]:
    return {
        "record_id": _required_text(record.get("id"), "record id", 64),
        "revision": _revision(record.get("revision"), "record revision"),
        "record_sha256": _record_sha(record),
        "relation": _token(relation, "citation relation"),
    }


def citation_is_current(
    citation: Mapping[str, Any],
    record: Mapping[str, Any] | None,
) -> bool:
    """Validate an exact governed citation against a freshly loaded record."""

    return bool(
        record
        and citation.get("record_id") == record.get("id")
        and citation.get("revision") == record.get("revision")
        and citation.get("record_sha256") == _record_sha(record)
    )


def _iso_date(value: object, label: str) -> str:
    text = _required_text(value, label, 64)
    try:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            raise ValueError(text)
        date.fromisoformat(text)
    except ValueError:
        raise ValueError(f"{label} must be a calendar date (YYYY-MM-DD)") from None
    return text


def _eu_assertion(value: object, *, actor: str, now: float) -> dict[str, Any]:
    raw = {} if value is None else value
    if not isinstance(raw, Mapping):
        raise ValueError("eu_ai_act must be an object")
    category = _token(
        raw.get("category", "undetermined"),
        "EU AI Act asserted category",
        _EU_ASSERTED_CATEGORIES,
    )
    if category == "undetermined":
        return {
            "category": category,
            "asserted_by": "",
            "asserted_at": None,
            "as_of": "",
            "source_ref": EU_AI_ACT_METADATA["source"],
            "rationale": "",
            "human_reviewed": False,
        }
    asserted_by = _required_text(raw.get("asserted_by") or actor, "asserted_by", 256)
    asserted_at = _timestamp(raw.get("asserted_at"), "asserted_at", now=now)
    return {
        "category": category,
        "asserted_by": asserted_by,
        "asserted_at": asserted_at,
        "as_of": _iso_date(raw.get("as_of"), "EU AI Act assertion as_of"),
        "source_ref": _required_text(raw.get("source_ref"), "EU AI Act source_ref", 1000),
        "rationale": _required_text(raw.get("rationale"), "EU AI Act rationale", 4000),
        "human_reviewed": True,
    }


def assurance_profile(context: Mapping[str, Any] | None, eu_ai_act: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return deterministic screening and versioned framework mappings.

    ``screening_level`` is an operational triage signal.  It is intentionally
    distinct from the dated, human-reviewed ``asserted_category`` and cannot be
    interpreted as an automatic EU AI Act classification.
    """

    raw = {} if context is None else context
    if not isinstance(raw, Mapping):
        raise ValueError("risk_context must be an object")
    prohibited = _bounded_tokens(
        raw.get("prohibited_signals"),
        "prohibited signal",
        allowed=_PROHIBITED_SIGNALS,
    )
    high_risk = _bounded_tokens(
        raw.get("high_risk_domains"),
        "high-risk domain",
        allowed=_HIGH_RISK_DOMAINS,
    )
    transparency = _bounded_tokens(
        raw.get("transparency_signals"),
        "transparency signal",
        allowed=_TRANSPARENCY_SIGNALS,
    )
    safety_critical = raw.get("safety_critical", False)
    human_oversight = raw.get("human_oversight", False)
    third_party = raw.get("third_party", False)
    for value, label in (
        (safety_critical, "safety_critical"),
        (human_oversight, "human_oversight"),
        (third_party, "third_party"),
    ):
        if not isinstance(value, bool):
            raise ValueError(f"{label} must be a boolean")

    eu = dict(eu_ai_act or {"category": "undetermined", "human_reviewed": False})
    asserted_category = str(eu.get("category") or "undetermined")
    if prohibited or asserted_category == "prohibited":
        screening = "critical"
    elif high_risk or safety_critical or asserted_category in {
        "high_risk", "gpai_systemic_risk",
    }:
        screening = "high"
    elif transparency or third_party or asserted_category in {"limited", "gpai"}:
        screening = "medium"
    else:
        screening = "low"
    mappings = {
        "nist_ai_rmf": {
            **NIST_AI_RMF_METADATA,
            "asset_mappings": {
                "GOVERN": ["accountability", "risk_acceptance", "human_oversight"],
                "MAP": ["inventory", "intended_use", "third_party_context"],
                "MEASURE": ["evaluation", "red_team", "drift_monitoring"],
                "MANAGE": ["incident_response", "promotion_gate", "rollback_lineage"],
            },
        },
        "iso_iec_42001": {
            **ISO_42001_METADATA,
            "asset_mappings": [
                "context_and_scope",
                "leadership_and_accountability",
                "risk_and_impact_assessment",
                "operational_controls",
                "performance_evaluation",
                "continual_improvement",
            ],
        },
        "eu_ai_act": {
            **EU_AI_ACT_METADATA,
            "asserted_category": asserted_category,
            "assertion_human_reviewed": bool(eu.get("human_reviewed")),
            "screening_signals": {
                "article_5_review": prohibited,
                "article_6_annex_iii_review": high_risk,
                "transparency_review": transparency,
                "gpai_role_review": asserted_category.startswith("gpai"),
            },
            "assertion": eu,
        },
    }
    profile = {
        "screening_level": screening,
        "screening_reasons": {
            "prohibited_signals": prohibited,
            "high_risk_domains": high_risk,
            "transparency_signals": transparency,
            "safety_critical": safety_critical,
            "third_party": third_party,
            "human_oversight": human_oversight,
            "human_asserted_eu_category": asserted_category,
        },
        "framework_mappings": mappings,
        "legal_certification": False,
        "compliance_verdict": "not_provided",
        "notice": NON_CERTIFICATION_NOTICE,
    }
    return {**profile, "profile_sha256": _sha256(profile)}


class ModelRiskAssuranceOfficer:
    """Tenant-scoped governed authority with injectable record backends."""

    def __init__(
        self,
        *,
        observations: GovernedRecordStore | None = None,
        declarations: GovernedRecordStore | None = None,
        evidence: GovernedRecordStore | None = None,
        incidents: GovernedRecordStore | None = None,
        decisions: GovernedRecordStore | None = None,
        deployments: GovernedRecordStore | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        self._observations = observations or _OBSERVATIONS
        self._declarations = declarations or _DECLARATIONS
        self._evidence = evidence or _EVIDENCE
        self._incidents = incidents or _INCIDENTS
        self._decisions = decisions or _DECISIONS
        self._deployments = deployments or _DEPLOYMENTS
        self._clock = clock

    @property
    def backend_kind(self) -> str:
        kinds = {
            store.backend_kind
            for store in (
                self._observations,
                self._declarations,
                self._evidence,
                self._incidents,
                self._decisions,
                self._deployments,
            )
        }
        if len(kinds) != 1:
            raise ModelRiskStateError("model-risk authorities use different backends")
        return next(iter(kinds))

    def _now(self) -> float:
        source = self._clock or self._decisions.authoritative_time
        sampled = float(source())
        return _timestamp(sampled, "authority clock", now=sampled)

    @staticmethod
    def _bounded_records(
        store: GovernedRecordStore,
        label: str,
    ) -> list[dict[str, Any]]:
        rows = store.list(limit=_MAX_NAMESPACE_RECORDS + 1)
        if len(rows) > _MAX_NAMESPACE_RECORDS:
            raise ModelRiskStateError(
                f"{label} exceeds the {_MAX_NAMESPACE_RECORDS}-record operational limit"
            )
        return rows

    def observe_asset(
        self,
        *,
        asset_type: str,
        source: str,
        source_id: str,
        display_name: str,
        version_digest: str,
        actor: str,
        expected_revision: int = 0,
        observed_at: float | None = None,
        metadata: Mapping[str, Any] | None = None,
        dependencies: object = None,
    ) -> dict[str, Any]:
        """CAS-create or replace the current observed snapshot for one asset."""

        _require_evidence_graph_dependency()
        kind = _token(asset_type, "asset_type", _ASSET_TYPES)
        namespace = _source(source)
        external_id = _required_text(source_id, "source_id", 256)
        asset = stable_asset_id(kind, namespace, external_id)
        name = _required_text(display_name, "display_name", 256)
        digest = _digest(version_digest, "version_digest")
        operator = _required_text(actor, "actor", 256)
        expected = _revision(expected_revision)
        now = self._now()
        observed = _timestamp(observed_at, "observed_at", now=now)
        meta = _bounded_json(dict(metadata or {}), "metadata")
        deps = _bounded_tokens(dependencies, "dependency", limit=128)
        identity = {
            "asset_type": kind,
            "source": namespace,
            "source_id": external_id,
        }
        snapshot = {
            "asset_id": asset,
            "identity": identity,
            "display_name": name,
            "version_digest": digest,
            "metadata": meta,
            "dependencies": deps,
        }
        snapshot_sha = _sha256(snapshot)
        graph_source_id = f"observation:{asset}:{snapshot_sha}"
        graph_node_id = _graph_node_id(graph_source_id)
        record_id = _record_id("MRO", asset)
        record = {
            "id": record_id,
            "schema": OBSERVATION_SCHEMA,
            **snapshot,
            "snapshot_sha256": snapshot_sha,
            "observed_at": observed,
            "evidence_node_id": graph_node_id,
            "status": "observed",
        }
        current = self._observations.get(record_id)
        current_revision = int((current or {}).get("revision") or 0)
        if current_revision != expected:
            raise RecordConflict(
                f"asset observation changed (expected revision {expected}, found {current_revision})"
            )
        if current is not None and current.get("snapshot_sha256") == snapshot_sha:
            saved = current
        elif current is None:
            saved = self._observations.create(
                record, action="observe_asset", actor=operator,
            )
        else:
            if current.get("asset_id") != asset or current.get("identity") != identity:
                raise ModelRiskStateError("asset observation identity binding changed")

            def mutate(row: dict[str, Any]) -> None:
                for key, value in record.items():
                    if key != "id":
                        row[key] = value

            saved = self._observations.update(
                record_id,
                mutate,
                expected_revision=expected,
                action="observe_asset",
                actor=operator,
            )
            if saved is None:
                raise ModelRiskStateError("asset observation disappeared during update")

        # Projection follows CAS admission. A stale/concurrent loser therefore
        # cannot create an orphan graph node. The deterministic graph identity
        # lets a retry reconcile a commit-then-crash without duplicating proof.
        from . import evidence_graph

        node = evidence_graph.ingest(
            source="model_risk_assurance",
            source_id=graph_source_id,
            evidence_type="ai_asset_observation",
            title=f"Observed {kind}: {name}",
            summary=(
                "Bounded inventory metadata and an exact version digest observed "
                "by the Model Risk & AI Assurance Officer."
            ),
            controls=["AI-RMF:MAP", "ISO42001:inventory"],
            attributes={
                "asset_id": asset,
                "asset_type": kind,
                "snapshot_sha256": snapshot_sha,
                "version_digest": digest,
            },
            links=[{
                "relation": "observes",
                "target_type": "ai_asset",
                "target_id": asset,
            }],
            actor=operator,
            observed_at=observed,
        )
        if node.get("id") != graph_node_id:
            raise ModelRiskStateError("evidence graph returned an unexpected identity")
        return saved

    def get_observation(self, asset_id: str) -> dict[str, Any] | None:
        asset = _asset_id(asset_id)
        row = self._observations.get(_record_id("MRO", asset))
        if row is not None and row.get("asset_id") != asset:
            raise ModelRiskStateError("asset observation identity collision")
        return row

    def list_inventory(self) -> list[dict[str, Any]]:
        return sorted(
            self._bounded_records(self._observations, "model-risk inventory"),
            key=lambda row: str(row.get("asset_id") or ""),
        )

    def declare_asset(
        self,
        asset_id: str,
        *,
        owner: str,
        purpose: str,
        intended_use: str,
        actor: str,
        risk_tier: str = "medium",
        lifecycle: str = "proposed",
        risk_context: Mapping[str, Any] | None = None,
        eu_ai_act: Mapping[str, Any] | None = None,
        parent_asset_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a human declaration bound to the current observed revision."""

        from .file_lock import cross_process_lock

        with cross_process_lock(_hierarchy_transaction_target(), strict=True):
            return self._declare_asset_locked(
                asset_id,
                owner=owner,
                purpose=purpose,
                intended_use=intended_use,
                actor=actor,
                risk_tier=risk_tier,
                lifecycle=lifecycle,
                risk_context=risk_context,
                eu_ai_act=eu_ai_act,
                parent_asset_id=parent_asset_id,
            )

    def _declare_asset_locked(
        self,
        asset_id: str,
        *,
        owner: str,
        purpose: str,
        intended_use: str,
        actor: str,
        risk_tier: str,
        lifecycle: str,
        risk_context: Mapping[str, Any] | None,
        eu_ai_act: Mapping[str, Any] | None,
        parent_asset_id: str | None,
    ) -> dict[str, Any]:
        """Create a declaration while hierarchy mutation is serialized."""

        asset = _asset_id(asset_id)
        observation = self.get_observation(asset)
        if observation is None:
            raise ModelRiskStateError("an observed asset is required before declaration")
        parent = self._validated_parent_asset_id(asset, parent_asset_id)
        now = self._now()
        context = _bounded_json(dict(risk_context or {}), "risk_context")
        assert isinstance(context, dict)
        eu = _eu_assertion(eu_ai_act, actor=actor, now=now)
        profile = assurance_profile(context, eu)
        state = _token(lifecycle, "lifecycle", _LIFECYCLES)
        if state not in {"proposed", "rejected"}:
            raise ValueError("new declarations must start proposed or rejected")
        record = {
            "id": _record_id("MRD", asset),
            "schema": DECLARATION_SCHEMA,
            "asset_id": asset,
            "parent_asset_id": parent,
            "owner": _required_text(owner, "owner", 256),
            "purpose": _required_text(purpose, "purpose", 4000),
            "intended_use": _required_text(intended_use, "intended_use", 4000),
            "risk_tier": _token(risk_tier, "risk_tier", _RISK_TIERS),
            "risk_context": context,
            "eu_ai_act": eu,
            "assurance_profile": profile,
            "observation_binding": _citation(observation, "declares"),
            "observed_version_digest": observation["version_digest"],
            "review": None,
            "lifecycle": state,
            "status": state,
            "legal_certification": False,
            "notice": NON_CERTIFICATION_NOTICE,
        }
        return self._declarations.create(record, action="declare_asset", actor=actor)

    def get_declaration(self, asset_id: str) -> dict[str, Any] | None:
        asset = _asset_id(asset_id)
        row = self._declarations.get(_record_id("MRD", asset))
        if row is not None and row.get("asset_id") != asset:
            raise ModelRiskStateError("asset declaration identity collision")
        return row

    def list_declarations(self) -> list[dict[str, Any]]:
        return sorted(
            self._bounded_records(self._declarations, "model-risk declarations"),
            key=lambda row: str(row.get("asset_id") or ""),
        )

    def _validated_parent_asset_id(
        self,
        asset_id: str,
        parent_asset_id: object,
    ) -> str | None:
        """Validate one tenant-local hierarchy edge and its bounded ancestry."""

        asset = _asset_id(asset_id)
        observation = self.get_observation(asset)
        if observation is None:
            raise ModelRiskStateError("asset observation is missing")
        child_type = _token(
            (observation.get("identity") or {}).get("asset_type"),
            "asset_type",
            _ASSET_TYPES,
        )
        if parent_asset_id is None or parent_asset_id == "":
            return None
        parent = _asset_id(parent_asset_id)
        if parent == asset:
            raise ValueError("an asset cannot be its own parent")
        if child_type == "system":
            raise ValueError("system assets cannot have a parent")

        seen = {asset}
        current = parent
        depth = 0
        previous_type = child_type
        while current is not None:
            if current in seen:
                raise ValueError("asset hierarchy contains a cycle")
            seen.add(current)
            depth += 1
            if depth > _MAX_HIERARCHY_DEPTH:
                raise ValueError(
                    f"asset hierarchy exceeds the {_MAX_HIERARCHY_DEPTH}-level limit"
                )
            parent_observation = self.get_observation(current)
            parent_declaration = self.get_declaration(current)
            if parent_observation is None or parent_declaration is None:
                raise ModelRiskStateError(
                    "parent asset must be observed and declared in the active tenant"
                )
            parent_type = _token(
                (parent_observation.get("identity") or {}).get("asset_type"),
                "parent asset_type",
                _ASSET_TYPES,
            )
            allowed = _ALLOWED_PARENT_TYPES[previous_type]
            if parent_type not in allowed:
                raise ValueError(
                    f"{previous_type} assets cannot be governed by a {parent_type} parent"
                )
            next_parent = parent_declaration.get("parent_asset_id")
            current = None if next_parent in (None, "") else _asset_id(next_parent)
            previous_type = parent_type
        return parent

    def _hierarchy_binding(
        self,
        asset_id: str,
        parent_asset_id: object,
    ) -> dict[str, Any]:
        """Bind an exact, tenant-local ancestor chain for human review."""

        parent = self._validated_parent_asset_id(asset_id, parent_asset_id)
        ancestors: list[dict[str, Any]] = []
        current = parent
        while current is not None:
            observation = self.get_observation(current)
            declaration = self.get_declaration(current)
            if observation is None or declaration is None:
                raise ModelRiskStateError("hierarchy authority disappeared")
            ancestors.append({
                "asset_id": current,
                "asset_type": (observation.get("identity") or {}).get("asset_type"),
                "observation": _citation(observation, "hierarchy_observation"),
                "declaration": _citation(declaration, "hierarchy_declaration"),
            })
            next_parent = declaration.get("parent_asset_id")
            current = None if next_parent in (None, "") else _asset_id(next_parent)
        body = {"parent_asset_id": parent, "ancestors": ancestors}
        return {**body, "hierarchy_sha256": _sha256(body)}

    def hierarchy_binding(self, asset_id: str) -> dict[str, Any]:
        """Return the exact validated ancestor binding for one declared asset."""

        asset = _asset_id(asset_id)
        declaration = self.get_declaration(asset)
        if declaration is None:
            raise ModelRiskStateError("asset declaration does not exist")
        return self._hierarchy_binding(asset, declaration.get("parent_asset_id"))

    def update_declaration(
        self,
        asset_id: str,
        *,
        expected_revision: int,
        actor: str,
        owner: object = _MISSING,
        purpose: object = _MISSING,
        intended_use: object = _MISSING,
        risk_tier: object = _MISSING,
        risk_context: object = _MISSING,
        eu_ai_act: object = _MISSING,
        parent_asset_id: object = _MISSING,
    ) -> dict[str, Any]:
        """CAS-update human metadata and invalidate any earlier approval."""

        from .file_lock import cross_process_lock

        with cross_process_lock(_hierarchy_transaction_target(), strict=True):
            return self._update_declaration_locked(
                asset_id,
                expected_revision=expected_revision,
                actor=actor,
                owner=owner,
                purpose=purpose,
                intended_use=intended_use,
                risk_tier=risk_tier,
                risk_context=risk_context,
                eu_ai_act=eu_ai_act,
                parent_asset_id=parent_asset_id,
            )

    def _update_declaration_locked(
        self,
        asset_id: str,
        *,
        expected_revision: int,
        actor: str,
        owner: object,
        purpose: object,
        intended_use: object,
        risk_tier: object,
        risk_context: object,
        eu_ai_act: object,
        parent_asset_id: object,
    ) -> dict[str, Any]:
        """Update a declaration while hierarchy mutation is serialized."""

        asset = _asset_id(asset_id)
        expected = _revision(expected_revision)
        if all(
            item is _MISSING
            for item in (
                owner,
                purpose,
                intended_use,
                risk_tier,
                risk_context,
                eu_ai_act,
                parent_asset_id,
            )
        ):
            raise ValueError("at least one declaration field must be updated")
        observation = self.get_observation(asset)
        if observation is None:
            raise ModelRiskStateError("asset observation is missing")
        now = self._now()
        parent = (
            _MISSING
            if parent_asset_id is _MISSING
            else self._validated_parent_asset_id(asset, parent_asset_id)
        )

        def mutate(row: dict[str, Any]) -> None:
            if row.get("asset_id") != asset:
                raise ModelRiskStateError("asset declaration identity changed")
            if row.get("lifecycle") == "retired":
                raise ValueError("retired declarations cannot be changed")
            if owner is not _MISSING:
                row["owner"] = _required_text(owner, "owner", 256)
            if purpose is not _MISSING:
                row["purpose"] = _required_text(purpose, "purpose", 4000)
            if intended_use is not _MISSING:
                row["intended_use"] = _required_text(intended_use, "intended_use", 4000)
            if risk_tier is not _MISSING:
                row["risk_tier"] = _token(risk_tier, "risk_tier", _RISK_TIERS)
            if risk_context is not _MISSING:
                value = _bounded_json(risk_context, "risk_context")
                if not isinstance(value, dict):
                    raise ValueError("risk_context must be an object")
                row["risk_context"] = value
            if eu_ai_act is not _MISSING:
                row["eu_ai_act"] = _eu_assertion(eu_ai_act, actor=actor, now=now)
            if parent is not _MISSING:
                row["parent_asset_id"] = parent
            row["assurance_profile"] = assurance_profile(
                row.get("risk_context") or {},
                row.get("eu_ai_act") or {},
            )
            row["observation_binding"] = _citation(observation, "declares")
            row["observed_version_digest"] = observation["version_digest"]
            row["review"] = None
            row["lifecycle"] = "proposed"
            row["status"] = "proposed"
            row["legal_certification"] = False

        saved = self._declarations.update(
            _record_id("MRD", asset),
            mutate,
            expected_revision=expected,
            action="update_declaration",
            actor=actor,
        )
        if saved is None:
            raise ModelRiskStateError("asset declaration does not exist")
        return saved

    def review_declaration(
        self,
        asset_id: str,
        *,
        decision: str,
        rationale: str,
        reviewer: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """Record an explicit human approval or rejection over current facts."""

        from .file_lock import cross_process_lock

        with cross_process_lock(_hierarchy_transaction_target(), strict=True):
            return self._review_declaration_locked(
                asset_id,
                decision=decision,
                rationale=rationale,
                reviewer=reviewer,
                expected_revision=expected_revision,
            )

    def _review_declaration_locked(
        self,
        asset_id: str,
        *,
        decision: str,
        rationale: str,
        reviewer: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """Review a declaration against one serialized hierarchy snapshot."""

        asset = _asset_id(asset_id)
        choice = _token(decision, "decision", frozenset({"approved", "rejected"}))
        expected = _revision(expected_revision)
        human = _required_text(reviewer, "reviewer", 256)
        why = _required_text(rationale, "rationale", 4000)
        observation = self.get_observation(asset)
        if observation is None:
            raise ModelRiskStateError("asset observation is missing")
        now = self._now()

        def mutate(row: dict[str, Any]) -> None:
            if row.get("asset_id") != asset:
                raise ModelRiskStateError("asset declaration identity changed")
            if row.get("lifecycle") == "retired":
                raise ValueError("retired declarations cannot be reviewed")
            eu = row.get("eu_ai_act") or {}
            if choice == "approved":
                if eu.get("category") == "undetermined" or eu.get("human_reviewed") is not True:
                    raise ValueError("approval requires a dated human EU AI Act assertion")
                if eu.get("category") == "prohibited":
                    raise ValueError("a prohibited-use assertion cannot be approved")
            binding = {
                "observation": _citation(observation, "reviewed"),
                "version_digest": observation["version_digest"],
                "profile_sha256": (row.get("assurance_profile") or {}).get("profile_sha256"),
                "hierarchy": self._hierarchy_binding(
                    asset,
                    row.get("parent_asset_id"),
                ),
            }
            row["review"] = {
                "decision": choice,
                "reviewer": human,
                "rationale": why,
                "reviewed_at": now,
                "binding": binding,
                "binding_sha256": _sha256(binding),
                "legal_certification": False,
            }
            row["lifecycle"] = choice
            row["status"] = choice
            row["observation_binding"] = _citation(observation, "declares")
            row["observed_version_digest"] = observation["version_digest"]
            row["legal_certification"] = False

        saved = self._declarations.update(
            _record_id("MRD", asset),
            mutate,
            expected_revision=expected,
            action=f"review_declaration_{choice}",
            actor=human,
        )
        if saved is None:
            raise ModelRiskStateError("asset declaration does not exist")
        return saved

    def record_evidence(
        self,
        asset_id: str,
        *,
        source_id: str,
        evidence_kind: str,
        result: str,
        scope_digest: str,
        artifact_digest: str,
        actor: str,
        observed_at: float,
        valid_until: float,
        evaluator_digest: str | None = None,
        evaluator_asset_id: str | None = None,
        summary: str = "",
        metrics: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist immutable, expiring evidence; human review is separate."""

        return self._record_evidence(
            asset_id,
            source_id=source_id,
            evidence_kind=evidence_kind,
            result=result,
            scope_digest=scope_digest,
            artifact_digest=artifact_digest,
            actor=actor,
            observed_at=observed_at,
            valid_until=valid_until,
            evaluator_digest=evaluator_digest,
            evaluator_asset_id=evaluator_asset_id,
            summary=summary,
            metrics=metrics,
            verified_training_commitment=None,
            verified_training_assurance=None,
        )

    def _record_evidence(
        self,
        asset_id: str,
        *,
        source_id: str,
        evidence_kind: str,
        result: str,
        scope_digest: str,
        artifact_digest: str,
        actor: str,
        observed_at: float,
        valid_until: float,
        evaluator_digest: str | None = None,
        evaluator_asset_id: str | None = None,
        summary: str = "",
        metrics: Mapping[str, Any] | None = None,
        verified_training_commitment: Mapping[str, Any] | None,
        verified_training_assurance: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Internal persistence seam for ordinary or receipt-verified evidence."""

        _require_evidence_graph_dependency()
        asset = _asset_id(asset_id)
        observation = self.get_observation(asset)
        if observation is None:
            raise ModelRiskStateError("evidence requires an observed asset")
        source = _required_text(source_id, "source_id", 256)
        kind = _token(evidence_kind, "evidence_kind", _EVIDENCE_KINDS)
        if kind == "training_run":
            if (
                verified_training_commitment is None
                or verified_training_assurance is None
            ):
                raise ValueError(
                    "training_run evidence requires a verified tenant-private receipt"
                )
            training_commitment = _training_commitment(
                verified_training_commitment,
            )
            training_assurance = _training_assurance_commitment(
                verified_training_assurance,
            )
            if (
                training_commitment["dataset_sha256"]
                != training_assurance["dataset_sha256"]
                or training_commitment["adapter_sha256"]
                != training_assurance["adapter_sha256"]
                or training_commitment["receipt_payload_sha256"]
                != training_assurance["receipt_payload_sha256"]
            ):
                raise ModelRiskStateError(
                    "training receipt and assurance commitments do not match"
                )
        else:
            if (
                verified_training_commitment is not None
                or verified_training_assurance is not None
            ):
                raise ModelRiskStateError(
                    "a training receipt commitment cannot authorize another evidence kind"
                )
            training_commitment = None
            training_assurance = None
        outcome = _token(result, "result", _EVIDENCE_RESULTS)
        scope = _digest(scope_digest, "scope_digest")
        artifact = _digest(artifact_digest, "artifact_digest")
        evaluator = (
            None if evaluator_digest is None else _digest(evaluator_digest, "evaluator_digest")
        )
        evaluator_asset = (
            None if evaluator_asset_id is None else _asset_id(evaluator_asset_id)
        )
        if evaluator_asset is not None and evaluator is None:
            raise ValueError("evaluator_asset_id requires evaluator_digest")
        if kind in {"evaluation", "red_team"} and evaluator_asset is None:
            raise ValueError(
                f"{kind} evidence requires a governed evaluator_asset_id",
            )
        evaluator_binding = None
        if evaluator_asset is not None:
            evaluator_observation = self.get_observation(evaluator_asset)
            if evaluator_observation is None:
                raise ModelRiskStateError("evaluator asset is not observed")
            if evaluator_observation.get("version_digest") != evaluator:
                raise RecordConflict(
                    "evaluator digest does not match its current observation",
                )
            evaluator_binding = _citation(
                evaluator_observation,
                "produced_evidence",
            )
        operator = _required_text(actor, "actor", 256)
        now = self._now()
        observed = _timestamp(observed_at, "observed_at", now=now)
        expiry = _expiry(valid_until, observed)
        note = _optional_text(summary, "summary", 4000)
        measurements = _bounded_json(dict(metrics or {}), "metrics", max_fields=128)
        # Producer identity is authority metadata, never caller-owned metrics.
        # Removing a similarly named measurement prevents a spoofed value from
        # being mistaken for the authenticated actor bound below.
        measurements.pop("producer_actor", None)
        if training_commitment is not None and measurements != {
            "training_receipt_commitment": training_commitment,
            "training_assurance_commitment": training_assurance,
        }:
            raise ModelRiskStateError(
                "training_run evidence may persist only verified receipt commitments"
            )
        immutable = {
            "asset_id": asset,
            "source_id": source,
            "evidence_kind": kind,
            "result": outcome,
            "scope_digest": scope,
            "artifact_digest": artifact,
            "evaluator_digest": evaluator,
            "evaluator_asset_id": evaluator_asset,
            "evaluator_binding": evaluator_binding,
            "summary": note,
            "metrics": measurements,
            "observed_at": observed,
            "valid_until": expiry,
        }
        if kind == "red_team":
            immutable["producer_actor"] = operator
        payload_sha = _sha256(immutable)
        record_id = _record_id("MRE", asset, source)
        graph_source_id = f"evidence:{asset}:{source}"
        graph_node_id = _graph_node_id(graph_source_id)
        record = {
            "id": record_id,
            "schema": EVIDENCE_SCHEMA,
            **immutable,
            "payload_sha256": payload_sha,
            "evidence_node_id": graph_node_id,
            "review": None,
            "status": "pending_review",
            "legal_certification": False,
        }
        try:
            saved = self._evidence.create(record, action="record_evidence", actor=operator)
        except RecordConflict as exc:
            current = self._evidence.get(record_id)
            if current is not None and current.get("payload_sha256") == payload_sha:
                saved = current
            else:
                raise RecordConflict(
                    "evidence source id is already bound to different content"
                ) from exc

        from . import evidence_graph

        graph_attributes = {
            "asset_id": asset,
            "artifact_digest": artifact,
            "evidence_kind": kind,
            "evidence_payload_sha256": payload_sha,
            "result": outcome,
            "scope_digest": scope,
        }
        if evaluator is not None:
            graph_attributes["evaluator_digest"] = evaluator
        if evaluator_asset is not None:
            graph_attributes["evaluator_asset_id"] = evaluator_asset
        node = evidence_graph.ingest(
            source="model_risk_assurance",
            source_id=graph_source_id,
            evidence_type=f"ai_assurance_{kind}",
            title=f"{kind.replace('_', ' ').title()} for {observation['display_name']}",
            summary=note or f"Governed {kind.replace('_', ' ')} result: {outcome}.",
            controls=["AI-RMF:MEASURE", "ISO42001:performance_evaluation"],
            attributes=graph_attributes,
            links=[{
                "relation": "supports",
                "target_type": "ai_asset",
                "target_id": asset,
            }],
            actor=operator,
            observed_at=observed,
            valid_until=expiry,
        )
        if node.get("id") != graph_node_id:
            raise ModelRiskStateError("evidence graph returned an unexpected identity")
        return saved

    def record_verified_training_receipt_evidence(
        self,
        asset_id: str,
        *,
        receipt_id: str,
        actor: str,
        valid_until: float,
    ) -> dict[str, Any]:
        """Verify one private receipt and persist only its public commitment.

        The receipt is resolved from the active tenant's private store. Trust
        anchors come only from protected server-side audit and approver
        registries; neither receipt keys nor arbitrary caller-provided receipt
        bodies are accepted here. Human Model Risk review remains a separate
        required transition.
        """

        asset = _asset_id(asset_id)
        observation = self.get_observation(asset)
        if observation is None:
            raise ModelRiskStateError("training evidence requires an observed asset")
        reference = _required_text(receipt_id, "receipt_id", 128)
        operator = _required_text(actor, "actor", 256)
        observed = self._now()
        expiry = _expiry(valid_until, observed)
        from .paths import current_tenant_id_strict

        tenant_id = current_tenant_id_strict()
        if not tenant_id:
            raise ModelRiskStateError(
                "training receipt evidence requires an explicit tenant scope"
            )
        try:
            from .training import receipts as training_receipts

            (
                trusted_receipt_pubkeys,
                trusted_approver_pubkeys,
            ) = training_receipts.server_training_trust_registries()
            receipt = training_receipts.read_verified_training_receipt(
                reference,
                trusted_receipt_pubkeys=trusted_receipt_pubkeys,
                trusted_approver_pubkeys=trusted_approver_pubkeys,
                expected_tenant_id=tenant_id,
            )
            commitment = training_receipts.public_transparency_commitment(
                receipt,
                trusted_receipt_pubkeys=trusted_receipt_pubkeys,
                trusted_approver_pubkeys=trusted_approver_pubkeys,
                expected_tenant_id=tenant_id,
            )
            normalized = _training_commitment(commitment)
            assurance_commitment = (
                training_receipts.model_risk_assurance_commitment(
                    receipt,
                    trusted_receipt_pubkeys=trusted_receipt_pubkeys,
                    trusted_approver_pubkeys=trusted_approver_pubkeys,
                    expected_tenant_id=tenant_id,
                )
            )
            assurance = _training_assurance_commitment(
                assurance_commitment,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise ModelRiskStateError(
                "tenant-private training receipt could not be verified"
            ) from None
        if normalized["adapter_sha256"] != observation.get("version_digest"):
            raise ModelRiskStateError(
                "verified training receipt covers different artifact bytes"
            )
        if (
            normalized["dataset_sha256"] != assurance["dataset_sha256"]
            or normalized["adapter_sha256"] != assurance["adapter_sha256"]
            or normalized["receipt_payload_sha256"]
            != assurance["receipt_payload_sha256"]
        ):
            raise ModelRiskStateError(
                "verified training receipt commitments do not match"
            )
        scope_digest = _training_evidence_scope(normalized, assurance)
        return self._record_evidence(
            asset,
            source_id=(
                "training_receipt:"
                f"{normalized['receipt_payload_sha256']}"
            ),
            evidence_kind="training_run",
            result="passed",
            scope_digest=scope_digest,
            artifact_digest=normalized["adapter_sha256"],
            actor=operator,
            observed_at=observed,
            valid_until=expiry,
            evaluator_digest=None,
            summary="Verified tenant-private training receipt commitment.",
            metrics={
                "training_receipt_commitment": normalized,
                "training_assurance_commitment": assurance,
            },
            verified_training_commitment=normalized,
            verified_training_assurance=assurance,
        )

    def get_evidence(self, evidence_id: str, *, now: float | None = None) -> dict[str, Any] | None:
        record_id = _required_text(evidence_id, "evidence_id", 64)
        row = self._evidence.get(record_id)
        if row is None:
            return None
        current = self._now() if now is None else _timestamp(now, "now", now=float(now))
        out = dict(row)
        out["freshness"] = (
            "current" if float(out.get("valid_until") or 0) > current else "stale"
        )
        return out

    def list_evidence(
        self,
        *,
        asset_id: str | None = None,
        now: float | None = None,
    ) -> list[dict[str, Any]]:
        asset = None if asset_id is None else _asset_id(asset_id)
        current = self._now() if now is None else _timestamp(now, "now", now=float(now))
        rows = []
        for stored in self._bounded_records(self._evidence, "model-risk evidence"):
            if asset is not None and stored.get("asset_id") != asset:
                continue
            row = dict(stored)
            row["freshness"] = (
                "current" if float(row.get("valid_until") or 0) > current else "stale"
            )
            rows.append(row)
        return sorted(
            rows,
            key=lambda row: (str(row.get("asset_id") or ""), str(row.get("id") or "")),
        )

    def review_evidence(
        self,
        evidence_id: str,
        *,
        decision: str,
        rationale: str,
        reviewer: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        _require_evidence_graph_dependency()
        record_id = _required_text(evidence_id, "evidence_id", 64)
        choice = _token(decision, "decision", _REVIEW_DECISIONS)
        why = _required_text(rationale, "rationale", 4000)
        human = _required_text(reviewer, "reviewer", 256)
        expected = _revision(expected_revision)
        now = self._now()

        def mutate(row: dict[str, Any]) -> None:
            if row.get("status") == "revoked":
                raise ValueError("revoked evidence cannot be reviewed again")
            if row.get("evidence_kind") == "red_team" and choice == "approved":
                producer = str(row.get("producer_actor") or "").strip()
                if not producer:
                    raise ValueError(
                        "red-team evidence requires a bound producer actor",
                    )
                if producer.casefold() == human.casefold():
                    raise ValueError(
                        "red-team evidence requires an independent reviewer",
                    )
            row["review"] = {
                "decision": choice,
                "reviewer": human,
                "rationale": why,
                "reviewed_at": now,
                "payload_sha256": row.get("payload_sha256"),
                "legal_certification": False,
            }
            row["status"] = choice

        saved = self._evidence.update(
            record_id,
            mutate,
            expected_revision=expected,
            action=f"review_evidence_{choice}",
            actor=human,
        )
        if saved is None:
            raise ModelRiskStateError("evidence does not exist")
        if choice == "approved":
            # Approval projection follows source CAS. The graph binds the exact
            # governed review revision and lazily revalidates it on every read.
            # A post-CAS projection failure is deliberately surfaced; promotion
            # remains closed until an idempotent review/reconciliation succeeds.
            from . import evidence_graph

            projected = evidence_graph.project_model_risk_evidence(
                saved["id"], actor=human,
            )
            expected_node_id = _graph_node_id(_approved_graph_source_id(saved))
            if projected.get("id") != expected_node_id:
                raise ModelRiskStateError(
                    "evidence graph returned an unexpected approval identity"
                )
        return saved

    def record_incident(
        self,
        asset_id: str,
        *,
        source_id: str,
        severity: str,
        summary: str,
        actor: str,
        occurred_at: float,
        evidence_ids: object,
    ) -> dict[str, Any]:
        asset = _asset_id(asset_id)
        if self.get_observation(asset) is None:
            raise ModelRiskStateError("incident requires an observed asset")
        source = _required_text(source_id, "source_id", 256)
        level = _token(severity, "severity", _RISK_TIERS)
        note = _required_text(summary, "summary", 4000)
        operator = _required_text(actor, "actor", 256)
        happened = _timestamp(occurred_at, "occurred_at", now=self._now())
        citations = self._evidence_citations(evidence_ids, relation="supports_incident")
        record = {
            "id": _record_id("MRI", asset, source),
            "schema": INCIDENT_SCHEMA,
            "asset_id": asset,
            "source_id": source,
            "severity": level,
            "summary": note,
            "occurred_at": happened,
            "evidence_citations": citations,
            "resolution": "",
            "status": "open",
        }
        return self._incidents.create(record, action="record_incident", actor=operator)

    def update_incident(
        self,
        incident_id: str,
        *,
        status: str,
        resolution: str,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        record_id = _required_text(incident_id, "incident_id", 64)
        target = _token(status, "status", _INCIDENT_STATES)
        detail = _required_text(resolution, "resolution", 4000)
        expected = _revision(expected_revision)

        def mutate(row: dict[str, Any]) -> None:
            current = _token(row.get("status"), "incident status", _INCIDENT_STATES)
            if target != current and target not in _INCIDENT_TRANSITIONS[current]:
                raise ValueError(f"incident transition {current} -> {target} is invalid")
            row["status"] = target
            row["resolution"] = detail

        saved = self._incidents.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="update_incident",
            actor=actor,
        )
        if saved is None:
            raise ModelRiskStateError("incident does not exist")
        return saved

    def list_incidents(self, *, asset_id: str | None = None) -> list[dict[str, Any]]:
        asset = None if asset_id is None else _asset_id(asset_id)
        return sorted(
            [
                row
                for row in self._bounded_records(
                    self._incidents,
                    "model-risk incidents",
                )
                if asset is None or row.get("asset_id") == asset
            ],
            key=lambda row: (str(row.get("asset_id") or ""), str(row.get("id") or "")),
        )

    def _evidence_citations(self, evidence_ids: object, *, relation: str) -> list[dict[str, Any]]:
        if isinstance(evidence_ids, (str, bytes, Mapping)) or not isinstance(evidence_ids, Iterable):
            raise ValueError("evidence_ids must be a list")
        raw = list(islice(iter(evidence_ids), _MAX_EVIDENCE_BINDINGS + 1))
        if len(raw) > _MAX_EVIDENCE_BINDINGS:
            raise ValueError("evidence_ids exceeds the 64-item limit")
        citations: list[dict[str, Any]] = []
        for item in sorted({_required_text(value, "evidence id", 64) for value in raw}):
            evidence = self._evidence.get(item)
            if evidence is None:
                raise ModelRiskStateError(f"evidence {item!r} does not exist")
            citations.append(_citation(evidence, relation))
        return citations

    def _finding(
        self,
        kind: str,
        asset_id: str,
        *,
        severity: str,
        summary: str,
        details: Mapping[str, Any],
        citations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if not citations:
            raise ModelRiskStateError("a finding requires at least one evidence citation")
        identity = {"finding_type": kind, "asset_id": asset_id}
        body = {
            "id": f"MRF-{_sha256(identity)[:24]}",
            "finding_type": _token(kind, "finding_type"),
            "asset_id": _asset_id(asset_id),
            "severity": _token(severity, "severity", _RISK_TIERS),
            "summary": _required_text(summary, "summary", 1000),
            "details": _bounded_json(dict(details), "finding details"),
            "citations": sorted(citations, key=lambda row: (row["record_id"], row["relation"])),
        }
        body["finding_sha256"] = _sha256(body)
        return body

    def _declaration_is_current(
        self,
        declaration: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> bool:
        review = declaration.get("review") or {}
        binding = review.get("binding") or {}
        citation = binding.get("observation") or {}
        try:
            hierarchy = self._hierarchy_binding(
                str(declaration.get("asset_id") or ""),
                declaration.get("parent_asset_id"),
            )
        except (ModelRiskAssuranceError, ValueError, TypeError):
            return False
        return bool(
            declaration.get("lifecycle") in _ACTIVE_LIFECYCLES
            and review.get("decision") == "approved"
            and citation.get("record_id") == observation.get("id")
            and citation.get("revision") == observation.get("revision")
            and citation.get("record_sha256") == _record_sha(observation)
            and binding.get("version_digest") == observation.get("version_digest")
            and binding.get("profile_sha256")
            == (declaration.get("assurance_profile") or {}).get("profile_sha256")
            and (binding.get("hierarchy") or {}).get("hierarchy_sha256")
            == hierarchy.get("hierarchy_sha256")
        )

    def _evidence_evaluator_is_current(
        self,
        evidence: Mapping[str, Any],
    ) -> bool:
        if evidence.get("evidence_kind") not in {"evaluation", "red_team"}:
            return True
        evaluator_asset = evidence.get("evaluator_asset_id")
        binding = evidence.get("evaluator_binding")
        if not isinstance(evaluator_asset, str) or not isinstance(binding, Mapping):
            return False
        try:
            observation = self.get_observation(evaluator_asset)
        except (ModelRiskAssuranceError, ValueError):
            return False
        return bool(
            self._citation_is_current(binding, observation)
            and observation is not None
            and observation.get("version_digest")
            == evidence.get("evaluator_digest")
        )

    def findings(self, *, now: float | None = None) -> list[dict[str, Any]]:
        current = self._now() if now is None else _timestamp(now, "now", now=float(now))
        declarations = {row["asset_id"]: row for row in self.list_declarations()}
        evidence_by_asset: dict[str, list[dict[str, Any]]] = {}
        for row in self.list_evidence(now=current):
            evidence_by_asset.setdefault(str(row.get("asset_id") or ""), []).append(row)
        incidents_by_asset: dict[str, list[dict[str, Any]]] = {}
        for row in self.list_incidents():
            incidents_by_asset.setdefault(str(row.get("asset_id") or ""), []).append(row)
        deployments_by_asset: dict[str, list[dict[str, Any]]] = {}
        for row in self.list_deployments():
            deployments_by_asset.setdefault(str(row.get("asset_id") or ""), []).append(row)
        out: list[dict[str, Any]] = []

        for observation in self.list_inventory():
            asset = observation["asset_id"]
            declaration = declarations.get(asset)
            observation_citation = [_citation(observation, "supports")]
            if declaration is None:
                out.append(self._finding(
                    "undeclared_asset",
                    asset,
                    severity="high",
                    summary="The observed AI asset has no accountable human declaration.",
                    details={"asset_type": observation["identity"]["asset_type"]},
                    citations=observation_citation,
                ))
                continue
            citations = [*observation_citation, _citation(declaration, "governs")]
            eu = declaration.get("eu_ai_act") or {}
            if eu.get("category") == "undetermined" or eu.get("human_reviewed") is not True:
                out.append(self._finding(
                    "eu_applicability_undetermined",
                    asset,
                    severity="high",
                    summary="EU AI Act role and category have not been asserted by a human reviewer.",
                    details={"asserted_category": eu.get("category") or "undetermined"},
                    citations=citations,
                ))
            if eu.get("category") == "prohibited":
                out.append(self._finding(
                    "prohibited_use_asserted",
                    asset,
                    severity="critical",
                    summary="A human reviewer asserted a prohibited-use category.",
                    details={"as_of": eu.get("as_of") or "", "source_ref": eu.get("source_ref") or ""},
                    citations=citations,
                ))
            if not self._declaration_is_current(declaration, observation):
                out.append(self._finding(
                    "stale_declaration_authority",
                    asset,
                    severity="high",
                    summary="The approved declaration is not bound to the current observed asset revision.",
                    details={
                        "declaration_revision": declaration.get("revision"),
                        "observation_revision": observation.get("revision"),
                    },
                    citations=citations,
                ))
            profile = declaration.get("assurance_profile") or {}
            reasons = profile.get("screening_reasons") or {}
            prohibited_signals = list(reasons.get("prohibited_signals") or [])
            if prohibited_signals:
                out.append(self._finding(
                    "prohibited_practice_screening_signal",
                    asset,
                    severity="critical",
                    summary=(
                        "Operational screening found a possible prohibited-practice "
                        "signal requiring resolution by qualified human review."
                    ),
                    details={
                        "signals": prohibited_signals,
                        "legal_classification": "not_determined_by_screening",
                    },
                    citations=citations,
                ))
            if profile.get("screening_level") in {"high", "critical"} and reasons.get("human_oversight") is not True:
                out.append(self._finding(
                    "human_oversight_missing",
                    asset,
                    severity="high",
                    summary="A high-impact screening profile lacks declared human oversight.",
                    details={"screening_level": profile.get("screening_level")},
                    citations=citations,
                ))

            asset_evidence = evidence_by_asset.get(asset, [])
            usable = [
                row
                for row in asset_evidence
                if row.get("status") == "approved"
                and row.get("freshness") == "current"
                and row.get("result") == "passed"
                and row.get("artifact_digest") == observation.get("version_digest")
                and self._evidence_evaluator_is_current(row)
                and (
                    row.get("evidence_kind") != "red_team"
                    or _red_team_review_is_independent(row)
                )
            ]
            usable_kinds = {row.get("evidence_kind") for row in usable}
            for required_kind in ("evaluation", "red_team"):
                if required_kind not in usable_kinds:
                    out.append(self._finding(
                        f"{required_kind}_evidence_missing",
                        asset,
                        severity="high",
                        summary=f"No approved, current {required_kind.replace('_', ' ')} evidence covers the observed artifact.",
                        details={"required_kind": required_kind},
                        citations=citations + [
                            _citation(row, "historical") for row in asset_evidence[:8]
                        ],
                    ))
            if reasons.get("third_party") is True and "vendor_assessment" not in usable_kinds:
                out.append(self._finding(
                    "third_party_assessment_missing",
                    asset,
                    severity="high",
                    summary="The third-party asset lacks a current approved vendor assessment.",
                    details={"third_party": True},
                    citations=citations + [_citation(row, "historical") for row in asset_evidence[:8]],
                ))
            for row in asset_evidence:
                if row.get("evidence_kind") == "drift_monitoring" and row.get("result") in {"failed", "inconclusive"}:
                    out.append(self._finding(
                        "drift_detected",
                        asset,
                        severity="high",
                        summary="Drift monitoring did not produce a passing result.",
                        details={"result": row.get("result"), "evidence_id": row.get("id")},
                        citations=citations + [_citation(row, "detects")],
                    ))
            for deployment in deployments_by_asset.get(asset, []):
                if deployment.get("artifact_digest") != observation.get("version_digest"):
                    out.append(self._finding(
                        "deployment_observation_drift",
                        asset,
                        severity="critical",
                        summary="Observed artifact bytes differ from the governed deployment lineage.",
                        details={
                            "deployment_id": deployment.get("deployment_id"),
                            "deployed_digest": deployment.get("artifact_digest"),
                            "observed_digest": observation.get("version_digest"),
                        },
                        citations=citations + [_citation(deployment, "conflicts")],
                    ))
            for incident in incidents_by_asset.get(asset, []):
                if incident.get("status") in {"open", "contained"}:
                    out.append(self._finding(
                        "active_incident",
                        asset,
                        severity=str(incident.get("severity") or "high"),
                        summary="An unresolved AI assurance incident remains active.",
                        details={"incident_id": incident.get("id"), "status": incident.get("status")},
                        citations=citations + [_citation(incident, "reports")],
                    ))

        return sorted(out, key=lambda row: (row["asset_id"], row["finding_type"], row["id"]))

    def accept_risk(
        self,
        finding_id: str,
        *,
        finding_sha256: str,
        rationale: str,
        reviewer: str,
        expires_at: float,
        expected_revision: int = 0,
    ) -> dict[str, Any]:
        """Human-accept one exact finding revision for a bounded time.

        Critical findings are never suppressible by risk acceptance.  A changed
        finding digest or expired decision automatically loses authority.
        """

        identifier = _required_text(finding_id, "finding_id", 64)
        digest = _digest(finding_sha256, "finding_sha256")
        current = next((row for row in self.findings() if row["id"] == identifier), None)
        if current is None:
            raise ModelRiskStateError("finding does not exist in current assurance state")
        if current["finding_sha256"] != digest:
            raise RecordConflict("finding changed before risk acceptance")
        if current["severity"] == "critical":
            raise ValueError("critical findings cannot be risk-accepted for promotion")
        now = self._now()
        expiry = _expiry(expires_at, now, "expires_at")
        human = _required_text(reviewer, "reviewer", 256)
        why = _required_text(rationale, "rationale", 4000)
        expected = _revision(expected_revision)
        record_id = _record_id("MRX", "risk_acceptance", identifier)
        record = {
            "id": record_id,
            "schema": DECISION_SCHEMA,
            "record_kind": "risk_acceptance",
            "finding_id": identifier,
            "finding_sha256": digest,
            "asset_id": current["asset_id"],
            "severity": current["severity"],
            "rationale": why,
            "reviewer": human,
            "decided_at": now,
            "expires_at": expiry,
            "finding_citations": current["citations"],
            "legal_certification": False,
            "status": "accepted",
        }
        existing = self._decisions.get(record_id)
        found_revision = int((existing or {}).get("revision") or 0)
        if found_revision != expected:
            raise RecordConflict(
                f"risk acceptance changed (expected revision {expected}, found {found_revision})"
            )
        if existing is None:
            return self._decisions.create(record, action="accept_risk", actor=human)

        def mutate(row: dict[str, Any]) -> None:
            for key, value in record.items():
                if key != "id":
                    row[key] = value

        saved = self._decisions.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="accept_risk",
            actor=human,
        )
        if saved is None:
            raise ModelRiskStateError("risk acceptance disappeared")
        return saved

    def current_risk_acceptance(
        self,
        finding: Mapping[str, Any],
        *,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        """Return authority for one exact, current, non-critical finding digest."""

        if finding.get("severity") == "critical":
            return None
        current = self._now() if now is None else _timestamp(now, "now", now=float(now))
        record = self._decisions.get(
            _record_id("MRX", "risk_acceptance", finding.get("id")),
        )
        if not (
            record
            and record.get("record_kind") == "risk_acceptance"
            and record.get("status") == "accepted"
            and record.get("finding_id") == finding.get("id")
            and record.get("finding_sha256") == finding.get("finding_sha256")
            and record.get("asset_id") == finding.get("asset_id")
            and record.get("severity") == finding.get("severity")
            and float(record.get("expires_at") or 0) > current
        ):
            return None
        return record

    def _risk_is_accepted(self, finding: Mapping[str, Any], *, now: float) -> bool:
        return self.current_risk_acceptance(finding, now=now) is not None

    def _authority_binding(
        self,
        *,
        asset_id: str,
        artifact_revision: int,
        artifact_digest: str,
        declaration_revision: int,
        evaluator_asset_id: str,
        evaluator_revision: int,
        evaluator_digest: str,
        evidence_ids: object,
    ) -> dict[str, Any]:
        asset = _asset_id(asset_id)
        evaluator_asset = _asset_id(evaluator_asset_id)
        artifact = self.get_observation(asset)
        evaluator = self.get_observation(evaluator_asset)
        declaration = self.get_declaration(asset)
        if artifact is None or evaluator is None or declaration is None:
            raise ModelRiskStateError("artifact, evaluator, and declaration authority are required")
        if int(artifact.get("revision") or 0) != _revision(artifact_revision, "artifact_revision"):
            raise RecordConflict("artifact observation revision is stale")
        if artifact.get("version_digest") != _digest(artifact_digest, "artifact_digest"):
            raise RecordConflict("artifact digest does not match current observation")
        if int(evaluator.get("revision") or 0) != _revision(evaluator_revision, "evaluator_revision"):
            raise RecordConflict("evaluator observation revision is stale")
        if evaluator.get("version_digest") != _digest(evaluator_digest, "evaluator_digest"):
            raise RecordConflict("evaluator digest does not match current observation")
        if int(declaration.get("revision") or 0) != _revision(
            declaration_revision, "declaration_revision",
        ):
            raise RecordConflict("declaration revision is stale")
        citations = self._evidence_citations(evidence_ids, relation="supports_promotion")
        return {
            "asset_id": asset,
            "artifact": _citation(artifact, "promotion_artifact"),
            "artifact_digest": artifact["version_digest"],
            "declaration": _citation(declaration, "promotion_declaration"),
            "evaluator_asset_id": evaluator_asset,
            "evaluator": _citation(evaluator, "promotion_evaluator"),
            "evaluator_digest": evaluator["version_digest"],
            "evidence": citations,
        }

    def authorize_promotion_candidate(
        self,
        *,
        candidate_id: str,
        rung: str,
        payload_sha256: str,
        asset_id: str,
        artifact_revision: int,
        artifact_digest: str,
        declaration_revision: int,
        evaluator_asset_id: str,
        evaluator_revision: int,
        evaluator_digest: str,
        evidence_ids: object,
        reviewer: str,
        rationale: str,
        expires_at: float,
        expected_revision: int = 0,
    ) -> dict[str, Any]:
        """Human-authorize one exact DGM candidate and its assurance authority."""

        candidate = _required_text(candidate_id, "candidate_id", 256)
        risk_rung = _token(rung, "rung")
        payload = _digest(payload_sha256, "payload_sha256")
        human = _required_text(reviewer, "reviewer", 256)
        why = _required_text(rationale, "rationale", 4000)
        now = self._now()
        expiry = _expiry(expires_at, now, "expires_at")
        expected = _revision(expected_revision)
        authority = self._authority_binding(
            asset_id=asset_id,
            artifact_revision=artifact_revision,
            artifact_digest=artifact_digest,
            declaration_revision=declaration_revision,
            evaluator_asset_id=evaluator_asset_id,
            evaluator_revision=evaluator_revision,
            evaluator_digest=evaluator_digest,
            evidence_ids=evidence_ids,
        )
        request = {
            "candidate_id": candidate,
            "rung": risk_rung,
            "payload_sha256": payload,
            "authority": authority,
        }
        binding_sha = _sha256(request)
        record_id = _record_id("MRX", "promotion", candidate, risk_rung)
        record = {
            "id": record_id,
            "schema": DECISION_SCHEMA,
            "record_kind": "promotion_authorization",
            "candidate_id": candidate,
            "rung": risk_rung,
            "payload_sha256": payload,
            "asset_id": authority["asset_id"],
            "request": request,
            "binding_sha256": binding_sha,
            "reviewer": human,
            "rationale": why,
            "decided_at": now,
            "expires_at": expiry,
            "legal_certification": False,
            "status": "approved",
        }
        existing = self._decisions.get(record_id)
        found_revision = int((existing or {}).get("revision") or 0)
        if found_revision != expected:
            raise RecordConflict(
                f"promotion authorization changed (expected revision {expected}, found {found_revision})"
            )
        if existing is None:
            return self._decisions.create(
                record,
                action="authorize_promotion_candidate",
                actor=human,
            )

        def mutate(row: dict[str, Any]) -> None:
            for key, value in record.items():
                if key != "id":
                    row[key] = value

        saved = self._decisions.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="authorize_promotion_candidate",
            actor=human,
        )
        if saved is None:
            raise ModelRiskStateError("promotion authorization disappeared")
        return saved

    def revoke_promotion_candidate(
        self,
        *,
        candidate_id: str,
        rung: str,
        rationale: str,
        reviewer: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        candidate = _required_text(candidate_id, "candidate_id", 256)
        risk_rung = _token(rung, "rung")
        human = _required_text(reviewer, "reviewer", 256)
        why = _required_text(rationale, "rationale", 4000)

        def mutate(row: dict[str, Any]) -> None:
            if row.get("record_kind") != "promotion_authorization":
                raise ModelRiskStateError("decision is not a promotion authorization")
            row["status"] = "revoked"
            row["revoked_by"] = human
            row["revocation_rationale"] = why
            row["revoked_at"] = self._now()

        saved = self._decisions.update(
            _record_id("MRX", "promotion", candidate, risk_rung),
            mutate,
            expected_revision=_revision(expected_revision),
            action="revoke_promotion_candidate",
            actor=human,
        )
        if saved is None:
            raise ModelRiskStateError("promotion authorization does not exist")
        return saved

    @staticmethod
    def _citation_is_current(
        citation: Mapping[str, Any], record: Mapping[str, Any] | None,
    ) -> bool:
        return citation_is_current(citation, record)

    def _verify_promotion_authorization(  # noqa: C901 - one fail-closed authority walk
        self,
        *,
        candidate_id: str,
        rung: str,
        payload_sha256: str,
        now: float,
    ) -> tuple[bool, str, dict[str, Any] | None]:
        candidate = _required_text(candidate_id, "candidate_id", 256)
        risk_rung = _token(rung, "rung")
        payload = _digest(payload_sha256, "payload_sha256")
        authorization = self._decisions.get(
            _record_id("MRX", "promotion", candidate, risk_rung),
        )
        if authorization is None:
            return False, "no governed model-risk promotion authorization exists", None
        if authorization.get("record_kind") != "promotion_authorization":
            return False, "governed decision has the wrong authority kind", authorization
        if authorization.get("status") != "approved":
            return False, "model-risk promotion authorization is not approved", authorization
        if float(authorization.get("expires_at") or 0) <= now:
            return False, "model-risk promotion authorization expired", authorization
        request = authorization.get("request")
        if not isinstance(request, dict) or _sha256(request) != authorization.get("binding_sha256"):
            return False, "model-risk promotion binding is malformed", authorization
        if (
            request.get("candidate_id") != candidate
            or request.get("rung") != risk_rung
            or request.get("payload_sha256") != payload
        ):
            return False, "candidate, rung, or payload digest differs from human approval", authorization
        authority = request.get("authority")
        if not isinstance(authority, dict):
            return False, "promotion authority binding is missing", authorization
        asset = str(authority.get("asset_id") or "")
        evaluator_asset = str(authority.get("evaluator_asset_id") or "")
        try:
            artifact = self.get_observation(asset)
            evaluator = self.get_observation(evaluator_asset)
            declaration = self.get_declaration(asset)
        except (ModelRiskAssuranceError, ValueError):
            return False, "bound artifact, evaluator, or declaration identity is invalid", authorization
        if not self._citation_is_current(authority.get("artifact") or {}, artifact):
            return False, "artifact observation authority is stale", authorization
        if artifact is None or artifact.get("version_digest") != authority.get("artifact_digest"):
            return False, "artifact digest authority is stale", authorization
        if not self._citation_is_current(authority.get("evaluator") or {}, evaluator):
            return False, "evaluator observation authority is stale", authorization
        if evaluator is None or evaluator.get("version_digest") != authority.get("evaluator_digest"):
            return False, "evaluator digest authority is stale", authorization
        if not self._citation_is_current(authority.get("declaration") or {}, declaration):
            return False, "human declaration authority is stale", authorization
        if declaration is None or not self._declaration_is_current(declaration, artifact):
            return False, "human declaration is unapproved or stale", authorization
        eu = declaration.get("eu_ai_act") or {}
        if eu.get("category") in {None, "", "undetermined", "prohibited"}:
            return False, "EU AI Act applicability is undetermined or prohibits promotion", authorization

        bound_evidence = authority.get("evidence")
        if not isinstance(bound_evidence, list) or not bound_evidence:
            return False, "promotion has no bound assurance evidence", authorization
        kinds: set[str] = set()
        training_dataset_digests: set[str] = set()
        data_assessment_scopes: set[str] = set()
        for citation in bound_evidence:
            if not isinstance(citation, dict):
                return False, "promotion evidence binding is malformed", authorization
            evidence = self._evidence.get(str(citation.get("record_id") or ""))
            if not self._citation_is_current(citation, evidence):
                return False, "promotion evidence authority is stale", authorization
            if evidence is None:
                return False, "promotion evidence is missing", authorization
            if evidence.get("asset_id") != asset:
                return False, "promotion evidence belongs to a different asset", authorization
            if evidence.get("status") != "approved" or evidence.get("result") != "passed":
                return False, "promotion evidence is not approved and passing", authorization
            if float(evidence.get("valid_until") or 0) <= now:
                return False, "promotion evidence expired", authorization
            if evidence.get("artifact_digest") != authority.get("artifact_digest"):
                return False, "promotion evidence covers different artifact bytes", authorization
            evidence_kind = str(evidence.get("evidence_kind") or "")
            if (
                evidence_kind == "red_team"
                and not _red_team_review_is_independent(evidence)
            ):
                return (
                    False,
                    "red-team evidence lacks independent producer review",
                    authorization,
                )
            if evidence_kind == "data_assessment":
                data_assessment_scopes.add(str(evidence.get("scope_digest") or ""))
            if evidence_kind in {"evaluation", "red_team"}:
                evidence_evaluator_asset = evidence.get("evaluator_asset_id")
                evidence_evaluator_binding = evidence.get("evaluator_binding")
                if evidence_evaluator_asset is not None:
                    try:
                        evidence_evaluator = self.get_observation(
                            str(evidence_evaluator_asset),
                        )
                    except (ModelRiskAssuranceError, ValueError):
                        return (
                            False,
                            "promotion evidence evaluator identity is invalid",
                            authorization,
                        )
                    if (
                        not isinstance(evidence_evaluator_binding, Mapping)
                        or not self._citation_is_current(
                            evidence_evaluator_binding,
                            evidence_evaluator,
                        )
                    ) or (
                        evidence_evaluator is None
                        or evidence_evaluator.get("version_digest")
                        != evidence.get("evaluator_digest")
                    ):
                        return (
                            False,
                            "promotion evidence evaluator authority is stale",
                            authorization,
                        )
                elif evidence.get("evaluator_digest") != authority.get(
                    "evaluator_digest",
                ):
                    return (
                        False,
                        "promotion evidence covers a different evaluator",
                        authorization,
                    )
            if evidence_kind == "training_run":
                measurements = evidence.get("metrics")
                exact_training_fields = {
                    "training_receipt_commitment",
                    "training_assurance_commitment",
                }
                raw_commitment = None
                raw_assurance = None
                if (
                    isinstance(measurements, Mapping)
                    and set(measurements) == exact_training_fields
                ):
                    raw_commitment = measurements.get(
                        "training_receipt_commitment"
                    )
                    raw_assurance = measurements.get(
                        "training_assurance_commitment"
                    )
                try:
                    commitment = _training_commitment(raw_commitment)
                    assurance = _training_assurance_commitment(raw_assurance)
                except ValueError:
                    return (
                        False,
                        "training-run evidence commitment is missing or malformed",
                        authorization,
                    )
                if (
                    commitment["dataset_sha256"]
                    != assurance["dataset_sha256"]
                    or commitment["adapter_sha256"]
                    != assurance["adapter_sha256"]
                    or commitment["receipt_payload_sha256"]
                    != assurance["receipt_payload_sha256"]
                    or evidence.get("scope_digest")
                    != _training_evidence_scope(commitment, assurance)
                    or evidence.get("artifact_digest") != commitment["adapter_sha256"]
                    or evidence.get("source_id")
                    != f"training_receipt:{commitment['receipt_payload_sha256']}"
                ):
                    return (
                        False,
                        "training-run evidence commitment is stale or mismatched",
                        authorization,
                    )
                training_dataset_digests.add(commitment["dataset_sha256"])
            node_id = str(evidence.get("evidence_node_id") or "")
            from . import evidence_graph

            raw_node = evidence_graph.get(node_id)
            if (
                raw_node is None
                or raw_node.get("attributes", {}).get("evidence_payload_sha256")
                != evidence.get("payload_sha256")
            ):
                return False, "promotion evidence graph citation is missing or drifted", authorization
            approved_node = evidence_graph.get(
                _graph_node_id(_approved_graph_source_id(evidence)),
            )
            review = (approved_node or {}).get("review") or {}
            authority_validation = (approved_node or {}).get("authority_validation") or {}
            attributes = (approved_node or {}).get("attributes") or {}
            if (
                approved_node is None
                or approved_node.get("status") != "approved"
                or approved_node.get("freshness") != "current"
                or authority_validation.get("status") != "current"
                or review.get("inherited_from") != evidence.get("id")
                or review.get("authority_revision") != evidence.get("revision")
                or review.get("authority_schema") != EVIDENCE_SCHEMA
                or attributes.get("evidence_payload_sha256")
                != evidence.get("payload_sha256")
                or attributes.get("asset_id") != asset
                or attributes.get("artifact_digest") != authority.get("artifact_digest")
                or (
                    evidence_kind in {"evaluation", "red_team"}
                    and attributes.get("evaluator_digest")
                    != evidence.get("evaluator_digest")
                )
                or (
                    evidence.get("evaluator_asset_id") is not None
                    and attributes.get("evaluator_asset_id")
                    != evidence.get("evaluator_asset_id")
                )
            ):
                return (
                    False,
                    "approved evidence graph authority is missing, stale, revoked, or drifted",
                    authorization,
                )
            kinds.add(evidence_kind)
        required_kinds = {"evaluation", "red_team"}
        if risk_rung == "weights":
            required_kinds.update({"training_run", "data_assessment"})
        missing = required_kinds - kinds
        if missing:
            return False, f"required promotion evidence is missing: {', '.join(sorted(missing))}", authorization
        if (
            risk_rung == "weights"
            and not training_dataset_digests.issubset(data_assessment_scopes)
        ):
            return (
                False,
                "data-assessment evidence covers different training data",
                authorization,
            )

        blocking = []
        for finding in self.findings(now=now):
            if finding.get("asset_id") != asset or finding.get("severity") not in {"high", "critical"}:
                continue
            if self._risk_is_accepted(finding, now=now):
                continue
            blocking.append(str(finding.get("finding_type") or "unknown"))
        if blocking:
            return False, f"blocking assurance findings: {', '.join(sorted(blocking))}", authorization
        return True, "exact model-risk authority is current and approved", authorization

    def verify_promotion_candidate(
        self,
        *,
        candidate_id: str,
        rung: str,
        payload_sha256: str,
        now: float | None = None,
    ) -> tuple[bool, str]:
        """Re-read and verify exact current CAS authority for a DGM candidate."""

        authority_now = self._now()
        if now is not None:
            claimed_now = _timestamp(now, "now", now=authority_now)
            if abs(claimed_now - authority_now) > _MAX_FUTURE_SKEW:
                raise ValueError("now exceeds the authority clock-skew allowance")
        # A caller-supplied replica timestamp is diagnostic only.  Promotion
        # expiry and freshness are always evaluated against record authority.
        current = authority_now
        allowed, reason, _ = self._verify_promotion_authorization(
            candidate_id=candidate_id,
            rung=rung,
            payload_sha256=payload_sha256,
            now=current,
        )
        return allowed, reason

    def require_promotion_candidate(
        self,
        *,
        candidate_id: str,
        rung: str,
        payload_sha256: str,
        now: float | None = None,
    ) -> None:
        allowed, reason = self.verify_promotion_candidate(
            candidate_id=candidate_id,
            rung=rung,
            payload_sha256=payload_sha256,
            now=now,
        )
        if not allowed:
            raise PromotionGateDenied({"allowed": False, "reasons": [reason]})

    def record_deployment(
        self,
        *,
        deployment_id: str,
        candidate_id: str,
        rung: str,
        payload_sha256: str,
        predecessor_digest: str | None,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        """CAS-publish deployment lineage only after re-running the exact gate."""

        identifier = _required_text(deployment_id, "deployment_id", 256)
        candidate = _required_text(candidate_id, "candidate_id", 256)
        risk_rung = _token(rung, "rung")
        payload = _digest(payload_sha256, "payload_sha256")
        expected = _revision(expected_revision)
        now = self._now()
        allowed, reason, authorization = self._verify_promotion_authorization(
            candidate_id=candidate,
            rung=risk_rung,
            payload_sha256=payload,
            now=now,
        )
        if not allowed or authorization is None:
            raise PromotionGateDenied({"allowed": False, "reasons": [reason]})
        authority = authorization["request"]["authority"]
        artifact_digest = authority["artifact_digest"]
        record_id = _record_id("MRL", identifier)
        current = self._deployments.get(record_id)
        found_revision = int((current or {}).get("revision") or 0)
        if found_revision != expected:
            raise RecordConflict(
                f"deployment lineage changed (expected revision {expected}, found {found_revision})"
            )
        predecessor = None if predecessor_digest is None else _digest(
            predecessor_digest, "predecessor_digest",
        )
        if current is None:
            if predecessor is not None:
                raise ValueError("the first deployment cannot claim a predecessor")
            history: list[dict[str, Any]] = []
        else:
            if predecessor != current.get("artifact_digest"):
                raise RecordConflict("deployment predecessor is not the current artifact")
            history = list(current.get("history") or [])
            history.append({
                "artifact_digest": current.get("artifact_digest"),
                "candidate_id": current.get("candidate_id"),
                "deployed_at": current.get("deployed_at"),
                "lineage_revision": current.get("revision"),
            })
            history = history[-128:]
        record = {
            "id": record_id,
            "schema": DEPLOYMENT_SCHEMA,
            "deployment_id": identifier,
            "asset_id": authority["asset_id"],
            "artifact_digest": artifact_digest,
            "predecessor_digest": predecessor,
            "evaluator_asset_id": authority["evaluator_asset_id"],
            "evaluator_digest": authority["evaluator_digest"],
            "candidate_id": candidate,
            "rung": risk_rung,
            "payload_sha256": payload,
            "promotion_authorization": _citation(authorization, "authorizes"),
            "promotion_binding_sha256": authorization["binding_sha256"],
            "evidence_citations": authority["evidence"],
            "history": history,
            "deployed_at": now,
            "status": "deployed",
        }
        operator = _required_text(actor, "actor", 256)
        if current is None:
            return self._deployments.create(record, action="record_deployment", actor=operator)

        def mutate(row: dict[str, Any]) -> None:
            for key, value in record.items():
                if key != "id":
                    row[key] = value

        saved = self._deployments.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="record_deployment",
            actor=operator,
        )
        if saved is None:
            raise ModelRiskStateError("deployment lineage disappeared")
        return saved

    def list_deployments(self, *, asset_id: str | None = None) -> list[dict[str, Any]]:
        asset = None if asset_id is None else _asset_id(asset_id)
        return sorted(
            [
                row
                for row in self._bounded_records(
                    self._deployments,
                    "model-risk deployments",
                )
                if asset is None or row.get("asset_id") == asset
            ],
            key=lambda row: str(row.get("deployment_id") or ""),
        )

    def render_assurance_pack(
        self,
        *,
        actor: str,
        asset_id: str | None = None,
        generated_at: float | None = None,
    ) -> dict[str, Any]:
        """Render and Ed25519-sign a tenant-scoped, citation-complete pack."""

        operator = _required_text(actor, "actor", 256)
        now = self._now()
        stamp = _timestamp(generated_at, "generated_at", now=now)
        if abs(stamp - now) > _MAX_FUTURE_SKEW:
            raise ValueError("generated_at exceeds the authority clock-skew allowance")
        asset = None if asset_id is None else _asset_id(asset_id)
        inventory = [
            _public(row)
            for row in self.list_inventory()
            if asset is None or row.get("asset_id") == asset
        ]
        declarations = [
            _public(row)
            for row in self.list_declarations()
            if asset is None or row.get("asset_id") == asset
        ]
        evidence = []
        for row in self.list_evidence(asset_id=asset, now=stamp):
            projected = _public(row)
            if projected.get("evidence_kind") == "red_team":
                projected["independent_review_authority"] = (
                    "current"
                    if _red_team_review_is_independent(projected)
                    else "invalid_or_legacy"
                )
            evidence.append(projected)
        incidents = [_public(row) for row in self.list_incidents(asset_id=asset)]
        deployments = [_public(row) for row in self.list_deployments(asset_id=asset)]
        decisions = [
            _public(row)
            for row in self._bounded_records(
                self._decisions,
                "model-risk decisions",
            )
            if asset is None or row.get("asset_id") == asset
        ]
        findings = [
            row
            for row in self.findings(now=stamp)
            if asset is None or row.get("asset_id") == asset
        ]
        node_ids = {
            str(row.get("evidence_node_id") or "")
            for row in [*inventory, *evidence]
            if row.get("evidence_node_id")
        }
        node_ids.update(
            _graph_node_id(_approved_graph_source_id(row))
            for row in evidence
            if row.get("status") == "approved"
        )
        sorted_node_ids = sorted(node_ids)
        from . import evidence_graph
        from .paths import current_tenant_id

        nodes: list[dict[str, Any]] = []
        for node_id in sorted_node_ids:
            node = evidence_graph.get(node_id)
            if node is None:
                raise ModelRiskStateError(f"evidence graph node {node_id!r} is missing")
            nodes.append(_public(node))
        graph = {
            "node_ids": sorted_node_ids,
            "nodes": sorted(nodes, key=lambda row: str(row.get("id") or "")),
        }
        graph["graph_sha256"] = _sha256(graph)
        body = {
            "schema": PACK_SCHEMA,
            "generated_at": stamp,
            "generated_by": operator,
            "tenant": current_tenant_id() or "",
            "asset_filter": asset or "",
            "inventory": inventory,
            "declarations": declarations,
            "evidence": evidence,
            "incidents": incidents,
            "deployments": deployments,
            "human_decisions": sorted(decisions, key=lambda row: str(row.get("id") or "")),
            "findings": findings,
            "evidence_graph": graph,
            "framework_metadata": {
                "nist_ai_rmf": NIST_AI_RMF_METADATA,
                "iso_iec_42001": ISO_42001_METADATA,
                "eu_ai_act": EU_AI_ACT_METADATA,
            },
            "legal_certification": False,
            "compliance_verdict": "not_provided",
            "notice": NON_CERTIFICATION_NOTICE,
        }
        digest = _sha256(body)
        return {
            **body,
            "pack_sha256": digest,
            "attestation": _sign_pack(digest, actor=operator, generated_at=stamp),
        }


def _attestation_path() -> Path:
    from .paths import data_dir

    return data_dir("model_risk_assurance", "pack_attestations.ndjson")


def _find_attestation(path: Path, attestation_id: str) -> dict[str, Any]:
    with path.open("rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        handle.seek(max(0, size - 1024 * 1024))
        tail = handle.read()
    for raw_line in reversed(tail.splitlines()):
        try:
            row = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if row.get("attestation_id") == attestation_id:
            return row
    raise ModelRiskStateError("signed assurance-pack attestation could not be recovered")


def _sign_pack(digest: str, *, actor: str, generated_at: float) -> dict[str, Any]:
    from .audit import signing

    path = _attestation_path()
    signer = signing.AuditSigner(path)
    attestation_id = uuid.uuid4().hex
    event = {
        "v": 1,
        "event": PACK_EVENT,
        "attestation_id": attestation_id,
        "actor": actor,
        "generated_at": generated_at,
        "pack_sha256": digest,
    }
    if not signer.write(event):
        raise ModelRiskStateError("audit signer refused the assurance pack")
    receipt = _find_attestation(path, attestation_id)
    return {
        "algorithm": "Ed25519",
        "key_id": receipt["key_id"],
        "public_key": signer.public_key_hex,
        "signature": receipt["sig"],
        "event_hash": receipt["hash"],
        "signed_message": "hex-decoded event_hash",
        "receipt": receipt,
    }


def verify_assurance_pack(
    pack: Mapping[str, Any],
    *,
    trusted_pubkeys: Mapping[str, str] | None,
) -> bool:
    """Verify a pack against an external key-id registry, never its own key."""

    try:
        from .audit.signing import verify_ed25519

        if not isinstance(pack, Mapping) or not isinstance(trusted_pubkeys, Mapping):
            return False
        body = dict(pack)
        digest = body.pop("pack_sha256")
        attestation = body.pop("attestation")
        if not isinstance(digest, str) or _sha256(body) != digest:
            return False
        if not isinstance(attestation, Mapping):
            return False
        if (
            attestation.get("algorithm") != "Ed25519"
            or attestation.get("signed_message") != "hex-decoded event_hash"
        ):
            return False
        receipt = attestation.get("receipt")
        if not isinstance(receipt, Mapping):
            return False
        if (
            receipt.get("event") != PACK_EVENT
            or receipt.get("pack_sha256") != digest
            or receipt.get("sig") != attestation.get("signature")
            or receipt.get("hash") != attestation.get("event_hash")
        ):
            return False
        key_id = receipt.get("key_id")
        if not isinstance(key_id, str):
            return False
        trusted = trusted_pubkeys.get(key_id)
        disclosed = attestation.get("public_key")
        if not isinstance(trusted, str) or not isinstance(disclosed, str):
            return False
        trusted = trusted.strip().lower()
        key_bytes = bytes.fromhex(trusted)
        if len(key_bytes) != 32:
            return False
        if hashlib.sha256(key_bytes).hexdigest()[:16] != key_id:
            return False
        if not hmac.compare_digest(disclosed.strip().lower(), trusted):
            return False
        if attestation.get("key_id") != key_id:
            return False
        unsigned = {key: value for key, value in receipt.items() if key not in {"hash", "sig"}}
        row_hash = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, default=str).encode("utf-8"),
        ).hexdigest()
        if row_hash != receipt.get("hash"):
            return False
        return verify_ed25519(trusted, str(receipt["sig"]), bytes.fromhex(row_hash))
    except (KeyError, TypeError, ValueError):
        return False


def promotion_gate_enabled() -> bool:
    """Return the explicit deployment-global DGM assurance-gate switch.

    Compatibility posture is off: both ``enable`` and ``gate_promotions`` must
    be the literal boolean ``true``.  An unreadable or malformed *enabled*
    policy raises :class:`ModelRiskConfigError`; callers at an enforcement
    boundary must treat that as denial rather than silently bypassing the gate.
    """

    try:
        from .config import config_source_errors, load_global_config

        cfg = load_global_config()
        errors = config_source_errors(include_tenant=False)
    except Exception as exc:
        raise ModelRiskConfigError("model-risk assurance policy is unavailable") from exc
    if errors:
        raise ModelRiskConfigError("model-risk assurance policy is unreadable")
    if not isinstance(cfg, dict):
        raise ModelRiskConfigError("configuration root must be a table")
    section = cfg.get("model_risk_assurance")
    if section is None:
        return False
    if not isinstance(section, dict):
        raise ModelRiskConfigError("model_risk_assurance must be a table")
    enabled = section.get("enable", False)
    gate = section.get("gate_promotions", False)
    if not isinstance(enabled, bool):
        raise ModelRiskConfigError("model_risk_assurance.enable must be a boolean")
    if enabled and not isinstance(gate, bool):
        raise ModelRiskConfigError("model_risk_assurance.gate_promotions must be a boolean")
    active = enabled is True and gate is True
    if not active:
        return False
    _require_evidence_graph_dependency()
    return True


_DEFAULT = ModelRiskAssuranceOfficer()


def enabled() -> bool:
    """Fail-closed deployment-global feature and dependency posture."""

    try:
        from .config import config_source_errors, load_global_config

        cfg = load_global_config()
        if config_source_errors(include_tenant=False) or not isinstance(cfg, dict):
            return False
        section = cfg.get("model_risk_assurance")
        if not isinstance(section, dict) or section.get("enable") is not True:
            return False
        if not isinstance(section.get("gate_promotions", False), bool):
            return False
        from . import evidence_graph

        return evidence_graph.enabled()
    except Exception:
        return False


# Stable module façade for REST, CLI, and dashboard consumers.  Keep authority
# in the single tenant-aware instance rather than letting each surface create a
# divergent in-process store selection.
def observe_asset(**kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.observe_asset(**kwargs)


def get_observation(asset_id: str) -> dict[str, Any] | None:
    return _DEFAULT.get_observation(asset_id)


def list_inventory() -> list[dict[str, Any]]:
    return _DEFAULT.list_inventory()


def dependency_graph(*, asset_id: str | None = None) -> dict[str, Any]:
    """Nodes and dependency edges over the governed inventory.

    With ``asset_id``, the projection keeps that asset plus its direct
    dependencies and direct dependents; otherwise the whole estate.
    """

    return dependency_graph_from_rows(
        _DEFAULT.list_inventory(), asset_id=asset_id
    )


def dependency_graph_from_rows(
    rows: list[dict[str, Any]], *, asset_id: str | None = None
) -> dict[str, Any]:
    """The same projection over an inventory scan the caller already holds,
    so consumers that also need the rows (the AI-BOM export) scan once."""

    wanted = None if asset_id is None else str(asset_id).strip()
    edges = [
        {"asset_id": str(row.get("asset_id")), "depends_on": str(dependency)}
        for row in rows
        for dependency in (row.get("dependencies") or [])
    ]

    # Dependencies are stored as normalized tokens (lowercase, "-" -> "_"),
    # while asset ids are "MAA-<hex>": compare in token space or the
    # neighbourhood filter never matches anything.
    def _norm(value: str) -> str:
        return value.lower().replace("-", "_")

    if wanted is not None:
        neighbours = {_norm(wanted)}
        for edge in edges:
            if _norm(edge["asset_id"]) == _norm(wanted):
                neighbours.add(_norm(edge["depends_on"]))
            if _norm(edge["depends_on"]) == _norm(wanted):
                neighbours.add(_norm(edge["asset_id"]))
        rows = [
            row for row in rows
            if _norm(str(row.get("asset_id"))) in neighbours
        ]
        edges = [
            edge
            for edge in edges
            if _norm(edge["asset_id"]) in neighbours
            and _norm(edge["depends_on"]) in neighbours
        ]
    nodes = [
        {
            "asset_id": row.get("asset_id"),
            "display_name": row.get("display_name"),
            # Type and source live under the observation's identity
            # sub-dict, not at the top level of the row.
            "asset_type": (row.get("identity") or {}).get("asset_type"),
            "source": (row.get("identity") or {}).get("source"),
        }
        for row in rows
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


def declare_asset(asset_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.declare_asset(asset_id, **kwargs)


def get_declaration(asset_id: str) -> dict[str, Any] | None:
    return _DEFAULT.get_declaration(asset_id)


def list_declarations() -> list[dict[str, Any]]:
    return _DEFAULT.list_declarations()


def hierarchy_binding(asset_id: str) -> dict[str, Any]:
    return _DEFAULT.hierarchy_binding(asset_id)


def update_declaration(asset_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.update_declaration(asset_id, **kwargs)


def review_declaration(asset_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.review_declaration(asset_id, **kwargs)


def record_evidence(asset_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.record_evidence(asset_id, **kwargs)


def record_verified_training_receipt_evidence(
    asset_id: str,
    **kwargs: Any,
) -> dict[str, Any]:
    return _DEFAULT.record_verified_training_receipt_evidence(asset_id, **kwargs)


def get_evidence(
    evidence_id: str, *, now: float | None = None,
) -> dict[str, Any] | None:
    return _DEFAULT.get_evidence(evidence_id, now=now)


def list_evidence(
    *, asset_id: str | None = None, now: float | None = None,
) -> list[dict[str, Any]]:
    return _DEFAULT.list_evidence(asset_id=asset_id, now=now)


def review_evidence(evidence_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.review_evidence(evidence_id, **kwargs)


def record_incident(asset_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.record_incident(asset_id, **kwargs)


def update_incident(incident_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.update_incident(incident_id, **kwargs)


def list_incidents(*, asset_id: str | None = None) -> list[dict[str, Any]]:
    return _DEFAULT.list_incidents(asset_id=asset_id)


def findings(*, now: float | None = None) -> list[dict[str, Any]]:
    return _DEFAULT.findings(now=now)


def accept_risk(finding_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.accept_risk(finding_id, **kwargs)


def current_risk_acceptance(
    finding: Mapping[str, Any],
    *,
    now: float | None = None,
) -> dict[str, Any] | None:
    return _DEFAULT.current_risk_acceptance(finding, now=now)


def authorize_promotion_candidate(**kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.authorize_promotion_candidate(**kwargs)


def revoke_promotion_candidate(**kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.revoke_promotion_candidate(**kwargs)


def record_deployment(**kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.record_deployment(**kwargs)


def list_deployments(*, asset_id: str | None = None) -> list[dict[str, Any]]:
    return _DEFAULT.list_deployments(asset_id=asset_id)


def render_assurance_pack(**kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.render_assurance_pack(**kwargs)


def verify_promotion_candidate(
    *,
    candidate_id: str,
    rung: str,
    payload_sha256: str,
    now: float | None = None,
) -> tuple[bool, str]:
    """Stable SelfImprovementController seam with fail-closed policy reads."""

    try:
        if not promotion_gate_enabled():
            return True, "model-risk assurance promotion gate is disabled"
    except ModelRiskConfigError as exc:
        return False, f"model-risk assurance policy unavailable: {exc}"
    try:
        return _DEFAULT.verify_promotion_candidate(
            candidate_id=candidate_id,
            rung=rung,
            payload_sha256=payload_sha256,
            now=now,
        )
    except (ModelRiskAssuranceError, RecordConflict, ValueError) as exc:
        return False, f"model-risk assurance verification failed: {exc}"


__all__ = [
    "DECLARATION_SCHEMA",
    "DECISION_SCHEMA",
    "DEPLOYMENT_SCHEMA",
    "EVIDENCE_SCHEMA",
    "EU_AI_ACT_METADATA",
    "INCIDENT_SCHEMA",
    "ISO_42001_METADATA",
    "ModelRiskAssuranceError",
    "ModelRiskAssuranceOfficer",
    "ModelRiskConfigError",
    "ModelRiskStateError",
    "NIST_AI_RMF_METADATA",
    "NON_CERTIFICATION_NOTICE",
    "OBSERVATION_SCHEMA",
    "PACK_SCHEMA",
    "PromotionGateDenied",
    "accept_risk",
    "assurance_profile",
    "authorize_promotion_candidate",
    "citation_is_current",
    "declare_asset",
    "enabled",
    "findings",
    "get_declaration",
    "get_evidence",
    "get_observation",
    "list_declarations",
    "list_deployments",
    "list_evidence",
    "list_incidents",
    "list_inventory",
    "observe_asset",
    "promotion_gate_enabled",
    "record_deployment",
    "record_evidence",
    "record_incident",
    "record_verified_training_receipt_evidence",
    "render_assurance_pack",
    "review_declaration",
    "review_evidence",
    "revoke_promotion_candidate",
    "stable_asset_id",
    "update_declaration",
    "update_incident",
    "verify_assurance_pack",
    "verify_promotion_candidate",
]
