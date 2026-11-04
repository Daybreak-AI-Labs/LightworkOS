"""Pydantic inputs for the governed Model Risk assurance API."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EvidenceReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str = Field(..., pattern="^(approved|rejected|revoked)$")
    rationale: str = Field(..., min_length=1, max_length=4000)
    expected_revision: int = Field(..., ge=1)

def _validate_string_items(
    values: list[str],
    *,
    label: str,
    max_length: int,
) -> None:
    """Apply the core's per-item text boundary at the HTTP schema edge."""
    for index, value in enumerate(values):
        if not value.strip():
            raise ValueError(f"{label} {index} must not be empty")
        if len(value) > max_length:
            raise ValueError(
                f"{label} {index} exceeds the {max_length}-character limit"
            )


def _validate_assurance_json(
    value: object,
    *,
    label: str,
    max_bytes: int,
    max_depth: int,
    max_nodes: int,
    max_object_items: int | None = None,
    max_array_items: int | None = None,
    max_string_chars: int | None = None,
    max_key_chars: int | None = None,
) -> None:
    """Bound nested assurance values before they reach synchronous stores."""
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} must contain finite JSON values") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{label} exceeds the {max_bytes}-byte limit")

    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise ValueError(f"{label} exceeds the structure limit")
        if depth > max_depth:
            raise ValueError(f"{label} exceeds the nesting limit")
        if isinstance(current, str):
            if max_string_chars is not None and len(current) > max_string_chars:
                raise ValueError(
                    f"{label} contains a string longer than "
                    f"{max_string_chars} characters"
                )
        elif isinstance(current, dict):
            if max_object_items is not None and len(current) > max_object_items:
                raise ValueError(f"{label} contains an oversized object")
            for key, item in current.items():
                if not isinstance(key, str):
                    raise ValueError(f"{label} object keys must be strings")
                if max_key_chars is not None and len(key) > max_key_chars:
                    raise ValueError(f"{label} contains an oversized object key")
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            if max_array_items is not None and len(current) > max_array_items:
                raise ValueError(f"{label} contains an oversized array")
            stack.extend((item, depth + 1) for item in current)


# Model Risk & AI Assurance Officer ----------------------------------------

_MODEL_RISK_DIGEST = "^(?:sha256:)?[0-9a-fA-F]{64}$"
_MODEL_RISK_ASSET_ID = "^MAA-[0-9a-f]{32}$"
_TRAINING_RECEIPT_ID = r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$"


class ModelRiskObservationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_type: str = Field(
        ...,
        pattern="^(system|component|model|agent|tool|dataset|provider)$",
    )
    source: str = Field(..., min_length=1, max_length=64)
    source_id: str = Field(..., min_length=1, max_length=256)
    display_name: str = Field(..., min_length=1, max_length=256)
    version_digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    expected_revision: int = Field(0, ge=0)
    observed_at: float | None = Field(None, gt=0)
    metadata: dict = Field(default_factory=dict, max_length=128)
    dependencies: list[str] = Field(default_factory=list, max_length=128)

    @model_validator(mode="after")
    def bound_observation(self):
        _validate_string_items(
            self.dependencies, label="model-risk dependency", max_length=256
        )
        _validate_assurance_json(
            self.metadata,
            label="model-risk metadata",
            max_bytes=64 * 1024,
            max_depth=8,
            max_nodes=2048,
            max_object_items=128,
            max_array_items=256,
            max_string_chars=4000,
            max_key_chars=128,
        )
        return self


class ModelRiskDeclarationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    owner: str = Field(..., min_length=1, max_length=256)
    purpose: str = Field(..., min_length=1, max_length=4000)
    intended_use: str = Field(..., min_length=1, max_length=4000)
    risk_tier: str = Field("medium", pattern="^(low|medium|high|critical)$")
    lifecycle: str = Field("proposed", pattern="^(proposed|rejected)$")
    risk_context: dict = Field(default_factory=dict, max_length=128)
    eu_ai_act: dict = Field(default_factory=dict, max_length=32)
    parent_asset_id: str | None = Field(None, pattern=_MODEL_RISK_ASSET_ID)

    @model_validator(mode="after")
    def bound_declaration(self):
        for value, label, fields in (
            (self.risk_context, "model-risk context", 128),
            (self.eu_ai_act, "EU AI Act assertion", 32),
        ):
            _validate_assurance_json(
                value,
                label=label,
                max_bytes=64 * 1024,
                max_depth=8,
                max_nodes=2048,
                max_object_items=fields,
                max_array_items=128,
                max_string_chars=4000,
                max_key_chars=128,
            )
        return self


class ModelRiskDeclarationUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(..., ge=1)
    owner: str | None = Field(None, min_length=1, max_length=256)
    purpose: str | None = Field(None, min_length=1, max_length=4000)
    intended_use: str | None = Field(None, min_length=1, max_length=4000)
    risk_tier: str | None = Field(None, pattern="^(low|medium|high|critical)$")
    risk_context: dict | None = Field(None, max_length=128)
    eu_ai_act: dict | None = Field(None, max_length=32)
    parent_asset_id: str | None = Field(None, pattern=_MODEL_RISK_ASSET_ID)

    @model_validator(mode="after")
    def require_bounded_change(self):
        if not self.model_fields_set.difference({"expected_revision"}):
            raise ValueError("at least one declaration field must be updated")
        for value, label, fields in (
            (self.risk_context, "model-risk context", 128),
            (self.eu_ai_act, "EU AI Act assertion", 32),
        ):
            if value is not None:
                _validate_assurance_json(
                    value,
                    label=label,
                    max_bytes=64 * 1024,
                    max_depth=8,
                    max_nodes=2048,
                    max_object_items=fields,
                    max_array_items=128,
                    max_string_chars=4000,
                    max_key_chars=128,
                )
        return self


class RedTeamCampaignIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    external_agent_id: str = Field(..., min_length=1, max_length=128)
    idempotency_key: str = Field(..., min_length=1, max_length=128)
    safe_target_environment: bool
    case_keys: list[str] | None = Field(None, min_length=1, max_length=32)
    ttl_seconds: int | None = Field(None, ge=300, le=2_592_000)

    @model_validator(mode="after")
    def bound_case_keys(self):
        if self.case_keys is not None:
            _validate_string_items(
                self.case_keys,
                label="red-team case key",
                max_length=64,
            )
            if len(set(self.case_keys)) != len(self.case_keys):
                raise ValueError("red-team case keys must be unique")
        return self


class RedTeamCancelIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)
    rationale: str = Field(..., min_length=1, max_length=2000)


class RedTeamFinalizeIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    force_incomplete: bool = False


class RedTeamScheduleIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    external_agent_id: str = Field(..., min_length=1, max_length=128)
    idempotency_key: str = Field(..., min_length=1, max_length=128)
    safe_target_environment: bool
    cadence_seconds: int = Field(..., ge=300, le=31_536_000)
    first_run_at: float | None = Field(None, gt=0)
    case_keys: list[str] | None = Field(None, min_length=1, max_length=32)
    campaign_ttl_seconds: int | None = Field(None, ge=300, le=2_592_000)

    @model_validator(mode="after")
    def bound_schedule_case_keys(self):
        if self.case_keys is not None:
            _validate_string_items(
                self.case_keys,
                label="red-team schedule case key",
                max_length=64,
            )
            if len(set(self.case_keys)) != len(self.case_keys):
                raise ValueError("red-team schedule case keys must be unique")
        return self


class RedTeamRunDueIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    limit: int = Field(20, ge=1, le=100)


class PortfolioSnapshotRefreshIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(0, ge=0)
    period_id: str | None = Field(None, pattern=r"^20[0-9]{2}-Q[1-4]$")


class PolicyPackActivateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(0, ge=0)


class PolicyPackRefreshIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)


class PolicyPackEvidenceBindingIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    requirement_id: str = Field(
        ...,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$",
    )
    evidence_id: str = Field(
        ...,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    )
    evidence_revision: int = Field(..., ge=1, le=2_147_483_647)
    evidence_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class PolicyPackAttestIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)
    idempotency_key: str = Field(
        ...,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    )
    evidence_bindings: list[PolicyPackEvidenceBindingIn] = Field(
        ...,
        min_length=1,
        max_length=512,
    )


class PolicyPackLegacyAttestIn(PolicyPackAttestIn):
    """Compatibility payload for the original body-selected control route."""

    control_id: str = Field(
        ...,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$",
    )


class ModelRiskDeclarationReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str = Field(..., pattern="^(approved|rejected)$")
    rationale: str = Field(..., min_length=1, max_length=4000)
    expected_revision: int = Field(..., ge=1)


class ModelRiskEvidenceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    source_id: str = Field(..., min_length=1, max_length=256)
    evidence_kind: str = Field(
        ...,
        pattern=(
            "^(evaluation|red_team|drift_monitoring|model_card|data_assessment|"
            "vendor_assessment|incident_analysis|human_oversight_test)$"
        ),
    )
    result: str = Field(..., pattern="^(passed|failed|inconclusive)$")
    scope_digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    artifact_digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    evaluator_digest: str | None = Field(None, pattern=_MODEL_RISK_DIGEST)
    evaluator_asset_id: str | None = Field(None, pattern=_MODEL_RISK_ASSET_ID)
    summary: str = Field("", max_length=4000)
    metrics: dict = Field(default_factory=dict, max_length=128)
    observed_at: float = Field(..., gt=0)
    valid_until: float = Field(..., gt=0)

    @model_validator(mode="after")
    def bound_evidence(self):
        if self.valid_until <= self.observed_at:
            raise ValueError("valid_until must be later than observed_at")
        if self.evaluator_asset_id is not None and self.evaluator_digest is None:
            raise ValueError("evaluator_asset_id requires evaluator_digest")
        if (
            self.evidence_kind in {"evaluation", "red_team"}
            and self.evaluator_asset_id is None
        ):
            raise ValueError(
                f"{self.evidence_kind} evidence requires evaluator_asset_id",
            )
        _validate_assurance_json(
            self.metrics,
            label="model-risk evidence metrics",
            max_bytes=64 * 1024,
            max_depth=8,
            max_nodes=2048,
            max_object_items=128,
            max_array_items=256,
            max_string_chars=4000,
            max_key_chars=128,
        )
        return self


class ModelRiskTrainingReceiptEvidenceIn(BaseModel):
    """Register one tenant-private receipt using server-side trust policy."""

    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    receipt_id: str = Field(..., pattern=_TRAINING_RECEIPT_ID)
    actor: str = Field(..., min_length=1, max_length=256)
    valid_until: float = Field(..., gt=0)

    @model_validator(mode="after")
    def validate_training_receipt_boundary(self):
        if self.actor != self.actor.strip():
            raise ValueError("actor must not have leading or trailing whitespace")
        return self


class ModelRiskIncidentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    source_id: str = Field(..., min_length=1, max_length=256)
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    summary: str = Field(..., min_length=1, max_length=4000)
    occurred_at: float = Field(..., gt=0)
    evidence_ids: list[str] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def bound_evidence_ids(self):
        _validate_string_items(
            self.evidence_ids, label="model-risk evidence id", max_length=64
        )
        return self


class ModelRiskIncidentUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., pattern="^(open|contained|resolved|dismissed)$")
    resolution: str = Field(..., min_length=1, max_length=4000)
    expected_revision: int = Field(..., ge=1)


class ModelRiskAcceptanceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    rationale: str = Field(..., min_length=1, max_length=4000)
    expires_at: float = Field(..., gt=0)
    expected_revision: int = Field(0, ge=0)


class ModelRiskPromotionAuthorizationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(..., min_length=1, max_length=256)
    rung: str = Field(
        ..., pattern="^(config|prompt|tool|policy|evaluator|code|weights)$"
    )
    payload_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    artifact_revision: int = Field(..., ge=1)
    artifact_digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    declaration_revision: int = Field(..., ge=1)
    evaluator_asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    evaluator_revision: int = Field(..., ge=1)
    evaluator_digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    evidence_ids: list[str] = Field(..., min_length=1, max_length=64)
    rationale: str = Field(..., min_length=1, max_length=4000)
    expires_at: float = Field(..., gt=0)
    expected_revision: int = Field(0, ge=0)

    @model_validator(mode="after")
    def bound_promotion_evidence(self):
        _validate_string_items(
            self.evidence_ids, label="promotion evidence id", max_length=64
        )
        return self


class ModelRiskPromotionRevocationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(..., min_length=1, max_length=256)
    rung: str = Field(
        ..., pattern="^(config|prompt|tool|policy|evaluator|code|weights)$"
    )
    rationale: str = Field(..., min_length=1, max_length=4000)
    expected_revision: int = Field(..., ge=1)


class ModelRiskDeploymentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deployment_id: str = Field(..., min_length=1, max_length=256)
    candidate_id: str = Field(..., min_length=1, max_length=256)
    rung: str = Field(
        ..., pattern="^(config|prompt|tool|policy|evaluator|code|weights)$"
    )
    payload_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    predecessor_digest: str | None = Field(None, pattern=_MODEL_RISK_DIGEST)
    expected_revision: int = Field(0, ge=0)


# AI vendor risk, drift monitoring, and agent topology ----------------------

_SAFE_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$"


class VendorDocumentReferenceIn(BaseModel):
    """A connector-bound document reference; the browser never supplies bytes."""

    model_config = ConfigDict(extra="forbid", strict=True)

    source: str = Field(..., pattern=_SAFE_IDENTIFIER)
    document_id: str = Field(..., min_length=1, max_length=512)
    document_name: str = Field("", max_length=512)
    ref: dict = Field(default_factory=dict, max_length=32)

    @model_validator(mode="after")
    def bound_reference(self):
        _validate_assurance_json(
            self.ref,
            label="vendor document reference",
            max_bytes=16 * 1024,
            max_depth=4,
            max_nodes=128,
            max_object_items=32,
            max_array_items=64,
            max_string_chars=1024,
            max_key_chars=128,
        )
        return self


class VendorAssessmentDraftIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    vendor: str = Field(..., min_length=1, max_length=300)
    answers: dict = Field(default_factory=dict, max_length=32)
    documents: list[VendorDocumentReferenceIn] = Field(default_factory=list, max_length=8)
    use_prior: bool = True

    @model_validator(mode="after")
    def bound_draft(self):
        _validate_assurance_json(
            self.answers,
            label="vendor assessment answers",
            max_bytes=128 * 1024,
            max_depth=6,
            max_nodes=1024,
            max_object_items=32,
            max_array_items=64,
            max_string_chars=4000,
            max_key_chars=128,
        )
        return self


class VendorAssessmentReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    decision: str = Field(..., pattern="^(approved|rejected)$")
    rationale: str = Field(..., min_length=1, max_length=4000)
    expected_revision: int = Field(..., ge=1)


class VendorAssessmentProjectionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    valid_until: float = Field(..., gt=0)


class VendorPortalInvitationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    vendor: str = Field(..., min_length=1, max_length=300)
    expires_in_seconds: int = Field(
        default=14 * 24 * 60 * 60,
        ge=60 * 60,
        le=90 * 24 * 60 * 60,
    )


class VendorPortalRevocationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    reason: str = Field(..., min_length=1, max_length=500)
    expected_revision: int = Field(..., ge=1)


class VendorPortalImportIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)


class DriftBaselineIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    source_id: str = Field(..., pattern=_SAFE_IDENTIFIER)
    feature_samples: dict | None = Field(None, max_length=64)
    predictions: list | None = Field(None, max_length=10_000)
    embeddings: list | None = Field(None, max_length=10_000)
    ground_truth: list | None = Field(None, max_length=10_000)
    expected_revision: int = Field(0, ge=0)

    @model_validator(mode="after")
    def bound_samples(self):
        _validate_assurance_json(
            {
                "feature_samples": self.feature_samples,
                "predictions": self.predictions,
                "embeddings": self.embeddings,
                "ground_truth": self.ground_truth,
            },
            label="aggregate drift samples",
            max_bytes=2 * 1024 * 1024,
            max_depth=5,
            max_nodes=100_000,
            max_object_items=64,
            max_array_items=10_000,
            max_string_chars=256,
            max_key_chars=128,
        )
        return self


class DriftEvaluationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    run_id: str = Field(..., pattern=_SAFE_IDENTIFIER)
    feature_samples: dict | None = Field(None, max_length=64)
    predictions: list | None = Field(None, max_length=10_000)
    embeddings: list | None = Field(None, max_length=10_000)
    ground_truth: list | None = Field(None, max_length=10_000)
    observed_at: float | None = Field(None, gt=0)

    @model_validator(mode="after")
    def bound_samples(self):
        _validate_assurance_json(
            {
                "feature_samples": self.feature_samples,
                "predictions": self.predictions,
                "embeddings": self.embeddings,
                "ground_truth": self.ground_truth,
            },
            label="aggregate drift samples",
            max_bytes=2 * 1024 * 1024,
            max_depth=5,
            max_nodes=100_000,
            max_object_items=64,
            max_array_items=10_000,
            max_string_chars=256,
            max_key_chars=128,
        )
        return self


# AI Evidence-Ready Gateway -------------------------------------------------

_GATEWAY_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_GATEWAY_DIGEST = r"^(?:sha256:)?[0-9a-fA-F]{64}$"
_GATEWAY_OPTIONAL_DIGEST = (
    r"^(?:$|(?:sha256:)?[0-9a-fA-F]{64})$"
)


def _require_https(value: str, *, label: str) -> None:
    if not value.startswith("https://"):
        raise ValueError(f"{label} must use HTTPS")


class EvidenceGatewayCitationIn(BaseModel):
    """One immutable source reference attached to a regulatory impact."""

    model_config = ConfigDict(extra="forbid", strict=True)

    source_name: str = Field(..., min_length=1, max_length=256)
    retrieval_url: str = Field(..., min_length=9, max_length=2048)
    record_url: str = Field(..., min_length=9, max_length=2048)
    retrieved_at: str = Field(..., min_length=1, max_length=64)
    content_sha256: str = Field(..., pattern=_GATEWAY_DIGEST)
    feed_url: str | None = Field(None, min_length=9, max_length=2048)
    payload_sha256: str | None = Field(None, pattern=_GATEWAY_DIGEST)
    source_record_sha256: str | None = Field(
        None,
        pattern=_GATEWAY_DIGEST,
    )
    source_format: str | None = Field(None, min_length=1, max_length=32)
    parser_version: str | None = Field(None, min_length=1, max_length=64)
    acquisition: str | None = Field(None, min_length=1, max_length=64)
    acquired_by: str | None = Field(None, min_length=1, max_length=128)
    official_citation: str | None = Field(None, max_length=1024)

    @model_validator(mode="after")
    def require_https_sources(self):
        _require_https(self.retrieval_url, label="retrieval_url")
        _require_https(self.record_url, label="record_url")
        if self.feed_url is not None:
            _require_https(self.feed_url, label="feed_url")
        try:
            retrieved = datetime.fromisoformat(
                self.retrieved_at.replace("Z", "+00:00")
            )
            retrieved_timestamp = retrieved.timestamp()
        except (OverflowError, ValueError) as exc:
            raise ValueError(
                "retrieved_at must be an ISO-8601 timestamp"
            ) from exc
        if (
            retrieved.tzinfo is None
            or retrieved_timestamp > time.time() + 300
        ):
            raise ValueError(
                "retrieved_at must be timezone-aware and not in the future"
            )
        return self


class EvidenceGatewayPolicyUpsertIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int | None = Field(None, ge=0)
    disclosure_text: str = Field(
        "AI disclosure: You are interacting with an AI system. Review important "
        "outputs before relying on them.",
        min_length=1,
        max_length=2000,
    )
    require_interaction_disclosure: bool = True
    require_machine_readable_marking: bool = True
    require_visible_marking: bool = False
    supported_modalities: list[str] = Field(
        default_factory=lambda: ["text"],
        min_length=1,
        max_length=16,
    )
    machine_marker: str = Field(
        "[lightwork-ai-generated; evidence-receipt={receipt_id}]",
        min_length=1,
        max_length=1000,
    )
    visible_marker: str = Field(
        "Disclosure: This text was generated by an AI system.",
        min_length=1,
        max_length=1000,
    )
    model_sha256: str = Field("", pattern=_GATEWAY_OPTIONAL_DIGEST)
    context_sha256: str = Field("", pattern=_GATEWAY_OPTIONAL_DIGEST)
    metadata: dict = Field(default_factory=dict, max_length=128)

    @model_validator(mode="after")
    def bound_policy(self):
        if any(value != "text" for value in self.supported_modalities):
            raise ValueError("v1 supports only the text modality")
        if len(set(self.supported_modalities)) != len(self.supported_modalities):
            raise ValueError("supported_modalities must not contain duplicates")
        if self.machine_marker.count("{receipt_id}") != 1:
            raise ValueError(
                "machine_marker must contain one {receipt_id} placeholder"
            )
        marker_remainder = self.machine_marker.replace("{receipt_id}", "")
        if "{" in marker_remainder or "}" in marker_remainder:
            raise ValueError(
                "machine_marker contains an unsupported placeholder"
            )
        _validate_assurance_json(
            self.metadata,
            label="gateway policy metadata",
            max_bytes=64 * 1024,
            max_depth=8,
            max_nodes=2048,
            max_object_items=128,
            max_array_items=256,
            max_string_chars=4000,
            max_key_chars=128,
        )
        return self


class EvidenceGatewayDeliveryIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    generated_text: str = Field(..., min_length=1, max_length=16 * 1024 * 1024)
    input_text: str = Field("", max_length=16 * 1024 * 1024)
    conversation_id: str = Field(..., min_length=1, max_length=1024)
    idempotency_key: str = Field(..., min_length=1, max_length=1024)
    policy_id: str = Field("default", pattern=_GATEWAY_ID)
    model_sha256: str = Field("", pattern=_GATEWAY_OPTIONAL_DIGEST)
    context_sha256: str = Field("", pattern=_GATEWAY_OPTIONAL_DIGEST)
    modality: str = Field("text", pattern="^text$")
    human_interaction: Literal[True] = True
    synthetic_content: Literal[True] = True
    deepfake: bool = False
    public_interest_text: bool = False


class EvidenceGatewayRegulatoryImpactIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    alert_id: str = Field(..., min_length=1, max_length=256)
    alert_revision: int = Field(..., ge=0)
    content_sha256: str = Field(..., pattern=_GATEWAY_DIGEST)
    citations: list[EvidenceGatewayCitationIn] = Field(
        ...,
        min_length=1,
        max_length=64,
    )
    affected_policy_ids: list[str] = Field(
        default_factory=lambda: ["default"],
        min_length=1,
        max_length=64,
    )
    affected_asset_ids: list[str] = Field(default_factory=list, max_length=128)
    control_ids: list[str] = Field(default_factory=list, max_length=128)
    match_reasons: list[str] = Field(default_factory=list, max_length=128)
    impact_id: str | None = Field(None, pattern=_GATEWAY_ID)

    @model_validator(mode="after")
    def bound_regulatory_impact(self):
        for values, label, maximum in (
            (self.affected_policy_ids, "affected policy id", 128),
            (self.affected_asset_ids, "affected asset id", 256),
            (self.control_ids, "control id", 256),
            (self.match_reasons, "match reason", 1000),
        ):
            _validate_string_items(values, label=label, max_length=maximum)
            if len(set(values)) != len(values):
                raise ValueError(f"{label}s must not contain duplicates")
        return self


class EvidenceGatewayImpactReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    decision: str = Field(..., pattern="^(accepted|dismissed)$")
    rationale: str = Field(..., min_length=1, max_length=4000)
    expected_revision: int = Field(..., ge=0)


_AI_REGULATORY_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$"


class AIRegulatoryImpactRuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    rule_id: str = Field(..., pattern=_AI_REGULATORY_ID)
    regimes: list[str] = Field(default_factory=list, max_length=256)
    domains: list[str] = Field(default_factory=list, max_length=256)
    policy_ids: list[str] = Field(
        default_factory=lambda: ["default"],
        min_length=1,
        max_length=256,
    )
    control_ids: list[str] = Field(default_factory=list, max_length=256)
    asset_ids: list[str] = Field(default_factory=list, max_length=256)
    evidence_kinds: list[str] = Field(default_factory=list, max_length=256)
    evidence_ids: list[str] = Field(default_factory=list, max_length=256)

    @model_validator(mode="after")
    def validate_rule_scope(self):
        if not self.regimes and not self.domains:
            raise ValueError("an impact rule requires a regime or domain")
        for field_name in (
            "regimes",
            "domains",
            "policy_ids",
            "control_ids",
            "asset_ids",
            "evidence_kinds",
            "evidence_ids",
        ):
            values = getattr(self, field_name)
            _validate_string_items(values, label=field_name, max_length=128)
            if len(set(values)) != len(values):
                raise ValueError(f"{field_name} must not contain duplicates")
        return self


class AIRegulatorySyncIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    rules: list[AIRegulatoryImpactRuleIn] = Field(
        ...,
        min_length=1,
        max_length=256,
    )
    deliver: bool = False

    @model_validator(mode="after")
    def unique_rule_ids(self):
        identifiers = [rule.rule_id for rule in self.rules]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("impact rule ids must be unique")
        return self


class AIRegulatoryNoticeDeliveryIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=0)


class AIRegulatoryStalenessResolveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=0)
    resolution: str = Field(..., min_length=1, max_length=4000)


_GOVERNANCE_TOKEN = r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$"
_SHA256 = r"^(?:sha256:)?[0-9a-f]{64}$"


class AILiteracyRequirementIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    title: str = Field(..., min_length=1, max_length=300)
    role_ids: list[str] = Field(default_factory=list, max_length=256)
    system_ids: list[str] = Field(default_factory=list, max_length=256)
    provider_id: str = Field(..., pattern=_GOVERNANCE_TOKEN)
    content_id: str = Field(..., pattern=_GOVERNANCE_TOKEN)
    content_version: str = Field(..., pattern=_GOVERNANCE_TOKEN)
    validity_days: int = Field(..., ge=1, le=1830)
    due_within_days: int = Field(..., ge=0, le=366)
    status: Literal["active", "retired"] = "active"
    expected_revision: int = Field(..., ge=0)
    idempotency_key: str = Field(..., min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_scopes(self):
        if not self.role_ids and not self.system_ids:
            raise ValueError("a literacy requirement needs a role or system scope")
        for values, label in (
            (self.role_ids, "role id"),
            (self.system_ids, "system id"),
        ):
            _validate_string_items(values, label=label, max_length=128)
            if len(set(values)) != len(values):
                raise ValueError(f"{label}s must not contain duplicates")
        return self


class AILiteracyAssignmentIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    role_ids: list[str] = Field(default_factory=list, max_length=256)
    system_ids: list[str] = Field(default_factory=list, max_length=256)
    expected_revision: int = Field(..., ge=0)
    idempotency_key: str = Field(..., min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_scopes(self):
        for values, label in (
            (self.role_ids, "role id"),
            (self.system_ids, "system id"),
        ):
            _validate_string_items(values, label=label, max_length=128)
            if len(set(values)) != len(values):
                raise ValueError(f"{label}s must not contain duplicates")
        return self


class AILiteracyCompletionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    provider_id: str = Field(..., pattern=_GOVERNANCE_TOKEN)
    content_id: str = Field(..., pattern=_GOVERNANCE_TOKEN)
    content_version: str = Field(..., pattern=_GOVERNANCE_TOKEN)
    completed_at: float = Field(..., gt=0)
    expires_at: float = Field(..., gt=0)
    provider_evidence_sha256: str = Field(..., pattern=_SHA256)
    provider_record_id: str = Field(..., min_length=1, max_length=512)
    idempotency_key: str = Field(..., min_length=1, max_length=256)


class AILiteracyWaiverGrantIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    kind: Literal["exemption", "waiver"]
    reviewer_id: str = Field(..., pattern=_GOVERNANCE_TOKEN)
    reason_code: Literal[
        "accessibility_accommodation",
        "equivalent_training",
        "leave_or_absence",
        "contractual_exception",
        "role_transition",
        "other_reviewed_basis",
    ]
    decision_basis_sha256: str = Field(..., pattern=_SHA256)
    starts_at: float = Field(..., gt=0)
    expires_at: float = Field(..., gt=0)
    idempotency_key: str = Field(..., min_length=1, max_length=256)


class AILiteracyWaiverRevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    reviewer_id: str = Field(..., pattern=_GOVERNANCE_TOKEN)
    expected_revision: int = Field(..., ge=1)
    idempotency_key: str = Field(..., min_length=1, max_length=256)


class AILiteracyEvidenceExportIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    person_ids: list[str] | None = Field(None, max_length=1000)
    as_of: float | None = Field(None, gt=0)

    @model_validator(mode="after")
    def validate_people(self):
        if self.person_ids is not None:
            _validate_string_items(
                self.person_ids,
                label="person id",
                max_length=128,
            )
            if len(set(self.person_ids)) != len(self.person_ids):
                raise ValueError("person ids must not contain duplicates")
        return self


class Article73EvidenceRefIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(..., pattern=_GOVERNANCE_TOKEN)
    sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class Article73IncidentOpenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    title: str = Field(..., min_length=1, max_length=300)
    asset_id: str = Field(..., pattern=_GOVERNANCE_TOKEN)
    asset_version: str = Field(..., pattern=_GOVERNANCE_TOKEN)
    awareness_at: float = Field(..., gt=0)
    summary: str = Field(..., min_length=1, max_length=8000)
    occurred_at: float | None = Field(None, gt=0)
    operator_role: Literal["provider", "deployer", "unknown"] = "unknown"
    asserted_high_risk: Literal["yes", "no", "unknown"] = "unknown"
    asserted_union_market: Literal["yes", "no", "unknown"] = "unknown"
    incident_member_states: list[str] = Field(default_factory=list, max_length=27)
    outcomes: list[
        Literal[
            "death",
            "serious_harm_to_health",
            "critical_infrastructure_irreversible_disruption",
            "fundamental_rights_obligations_infringement",
            "serious_property_or_environment_harm",
        ]
    ] = Field(default_factory=list, max_length=5)
    widespread_infringement: bool = False
    causality: Literal[
        "not_assessed",
        "suspected",
        "reasonable_likelihood",
        "established",
        "not_supported",
    ] = "not_assessed"
    evidence_refs: list[Article73EvidenceRefIn] = Field(
        default_factory=list,
        max_length=128,
    )
    calendar_timezone: str = Field(default="UTC", min_length=1, max_length=128)


class Article73RoutingIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    decision: Literal[
        "report_to_authority",
        "do_not_report",
        "legal_review_required",
    ]
    threshold_determination: Literal["met", "not_met", "uncertain"]
    applicability_determination: Literal["applies", "does_not_apply", "uncertain"]
    rationale: str = Field(..., min_length=1, max_length=8000)
    expected_revision: int = Field(..., ge=1)


class Article73ReportDraftIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    kind: Literal["initial", "update", "final"]
    details: dict
    expected_revision: int = Field(..., ge=1)

    @model_validator(mode="after")
    def bound_details(self):
        _validate_assurance_json(
            self.details,
            label="Article 73 report details",
            max_bytes=256 * 1024,
            max_depth=8,
            max_nodes=2000,
            max_object_items=64,
            max_array_items=128,
            max_string_chars=8000,
            max_key_chars=128,
        )
        return self


class Article73AuthorityIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)


class Article73SubmissionIn(Article73AuthorityIn):
    # The authority's filing reference, bounded exactly as the incident
    # register accepts it (letters and numbers first, no spaces, 128 max).
    submission_reference: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$",
    )
    receipt_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    submitted_at: float | None = Field(None, gt=0)


class AIBusinessIntakeFieldOut(BaseModel):
    path: str
    label: str
    kind: Literal["text", "boolean", "choice", "multiple"]
    group: str
    required: bool
    choices: list[str] | None = None
    max_length: int | None = None


class AIBusinessIntakeFormOut(BaseModel):
    schema_version: str = Field(alias="schema")
    fields: list[AIBusinessIntakeFieldOut]
    max_submission_bytes: int
    notice: str
    context: str
    can_edit: bool


class AIBusinessIntakeStartIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    idempotency_key: str = Field(..., min_length=1, max_length=128)
    initial: dict | None = None

    @model_validator(mode="after")
    def bound_initial(self):
        if self.initial is not None:
            _validate_assurance_json(
                self.initial,
                label="AI business intake initial answers",
                max_bytes=16 * 1024,
                max_depth=8,
                max_nodes=512,
                max_object_items=64,
                max_array_items=64,
                max_string_chars=4000,
                max_key_chars=128,
            )
        return self


class AIBusinessIntakeSaveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    patch: dict
    operation_id: str = Field(..., min_length=1, max_length=128)
    expected_revision: int = Field(..., ge=1)

    @model_validator(mode="after")
    def bound_patch(self):
        _validate_assurance_json(
            self.patch,
            label="AI business intake answer patch",
            max_bytes=16 * 1024,
            max_depth=8,
            max_nodes=512,
            max_object_items=64,
            max_array_items=64,
            max_string_chars=4000,
            max_key_chars=128,
        )
        return self


class AIBusinessIntakeSubmitIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    operation_id: str = Field(..., min_length=1, max_length=128)
    expected_revision: int = Field(..., ge=1)


class AICostCitationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    uri: str = Field(..., min_length=1, max_length=2048)
    sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    row_ref: str = Field(default="", max_length=256)


class AICostUsageIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    metric: str = Field(..., min_length=1, max_length=256)
    quantity: str = Field(..., min_length=1, max_length=128)
    unit: str = Field(..., min_length=1, max_length=128)


class AICostObservationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    source_record_id: str = Field(..., min_length=1, max_length=512)
    period_start: str = Field(..., min_length=1, max_length=64)
    period_end: str = Field(..., min_length=1, max_length=64)
    currency: str = Field(..., pattern=r"^[A-Za-z]{3}$")
    cost: str = Field(..., min_length=1, max_length=128)
    usage: list[AICostUsageIn] = Field(..., min_length=1, max_length=32)
    service: str = Field(..., min_length=1, max_length=512)
    resource_id: str = Field(..., min_length=1, max_length=1024)
    citation: AICostCitationIn
    region: str = Field(default="", max_length=256)
    registry_asset_id: str = Field(
        default="",
        pattern=r"^(?:|MAA-[0-9a-f]{32})$",
    )
    correction_of_source_record_id: str = Field(default="", max_length=512)
    correction_reason: str = Field(default="", max_length=2000)


class AICostBatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    provider: Literal["aws", "azure", "gcp", "openai"]
    collector_id: str = Field(..., pattern=_GOVERNANCE_TOKEN)
    source_account_id: str = Field(..., min_length=1, max_length=256)
    batch_id: str = Field(..., min_length=1, max_length=512)
    period_start: str = Field(..., min_length=1, max_length=64)
    period_end: str = Field(..., min_length=1, max_length=64)
    collected_at: float = Field(..., gt=0)
    complete: Literal[True]
    manifest_citation: AICostCitationIn
    records: list[AICostObservationIn] = Field(..., min_length=1, max_length=1000)


class AICostCollectIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    period_start: str = Field(..., min_length=1, max_length=64)
    period_end: str = Field(..., min_length=1, max_length=64)
    max_records: int = Field(default=1000, ge=1, le=1000)


class AICostROIAssumptionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    scope_kind: Literal["portfolio", "department", "asset"]
    scope_id: str = Field(default="", max_length=256)
    period_start: str = Field(..., min_length=1, max_length=64)
    period_end: str = Field(..., min_length=1, max_length=64)
    currency: str = Field(..., pattern=r"^[A-Za-z]{3}$")
    assumed_benefit: str = Field(..., min_length=1, max_length=128)
    methodology: str = Field(..., min_length=1, max_length=2000)
    rationale: str = Field(..., min_length=1, max_length=4000)
    citations: list[AICostCitationIn] = Field(..., min_length=1, max_length=16)
    idempotency_key: str = Field(..., min_length=1, max_length=256)
    expected_revision: int = Field(..., ge=0)


# Explainable dynamic AI risk ----------------------------------------------


class AIDynamicRiskSignalIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    category: str = Field(
        ...,
        pattern="^(quality|safety|drift|performance|policy|privacy|security)$",
    )
    severity: float = Field(..., ge=0, le=100)
    confidence: float = Field(..., ge=0, le=1)
    observed_at: float = Field(..., gt=0)
    expires_at: float = Field(..., gt=0)
    source_type: str = Field(
        ...,
        pattern="^(drift_receipt|policy_receipt|runtime_receipt|telemetry|evidence)$",
    )
    source_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$",
    )
    source_digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    signal_code: str = Field(
        ...,
        pattern=r"^[a-z0-9][a-z0-9_.:-]{0,127}$",
    )
    idempotency_key: str = Field(..., min_length=1, max_length=256)

    @model_validator(mode="after")
    def valid_window(self):
        if self.expires_at <= self.observed_at:
            raise ValueError("expires_at must be later than observed_at")
        return self


class AIDynamicRiskResolveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)
    resolution_code: str = Field(
        ...,
        pattern=r"^[a-z0-9][a-z0-9_.:-]{0,127}$",
    )
    resolution_evidence_digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)


class AIDynamicRiskSupersedeIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)
    superseding_signal_id: str = Field(
        ...,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,63}$",
    )


class AIDynamicRiskScoreIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(0, ge=0)
    asset_criticality: str = Field(
        ...,
        pattern="^(low|medium|high|critical)$",
    )
    eu_risk_tier: str = Field(
        ...,
        pattern="^(minimal|limited|high|unacceptable)$",
    )
    sensitive_data: str = Field(
        ...,
        pattern="^(none|internal|personal|special_category)$",
    )
    external_exposure: str = Field(
        ...,
        pattern="^(internal|restricted|partner|public)$",
    )


# Operational AI policy management ----------------------------------------


_AI_POLICY_TOKEN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"


class AIPolicyApplicabilityIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    risk_tiers: list[str] = Field(default_factory=list, max_length=64)
    jurisdictions: list[str] = Field(default_factory=list, max_length=64)
    data_classes: list[str] = Field(default_factory=list, max_length=64)
    deployment_types: list[str] = Field(default_factory=list, max_length=64)
    asset_types: list[str] = Field(default_factory=list, max_length=64)
    tags: list[str] = Field(default_factory=list, max_length=64)
    use_case_tags: list[str] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def bound_tokens(self):
        for name in (
            "risk_tiers",
            "jurisdictions",
            "data_classes",
            "deployment_types",
            "asset_types",
            "tags",
            "use_case_tags",
        ):
            values = getattr(self, name)
            _validate_string_items(
                values,
                label=f"AI policy {name}",
                max_length=128,
            )
        return self


class AIPolicyStatementIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    statement_id: str = Field(..., pattern=_AI_POLICY_TOKEN)
    text: str = Field(..., min_length=1, max_length=4000)
    effect: Literal["allow", "review", "restrict", "prohibit"]
    applicability: AIPolicyApplicabilityIn = Field(
        default_factory=AIPolicyApplicabilityIn
    )
    required_control_ids: list[str] = Field(default_factory=list, max_length=128)

    @model_validator(mode="after")
    def bound_controls(self):
        _validate_string_items(
            self.required_control_ids,
            label="AI policy required control",
            max_length=128,
        )
        return self


class AIPolicyCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    policy_id: str = Field(..., pattern=_AI_POLICY_TOKEN)
    title: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=4000)
    statements: list[AIPolicyStatementIn] = Field(
        ...,
        min_length=1,
        max_length=128,
    )


class AIPolicyVersionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    title: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=4000)
    statements: list[AIPolicyStatementIn] = Field(
        ...,
        min_length=1,
        max_length=128,
    )
    expected_revision: int = Field(..., ge=1)


class AIPolicyActivateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: int = Field(..., ge=1, le=100)
    expected_revision: int = Field(..., ge=1)


class AIPolicyScopeIn(AIPolicyApplicabilityIn):
    asset_ids: list[str] = Field(default_factory=list, max_length=64)
    statement_ids: list[str] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def bound_scope_tokens(self):
        for name in ("asset_ids", "statement_ids"):
            _validate_string_items(
                getattr(self, name),
                label=f"AI policy exception {name}",
                max_length=128,
            )
        return self


class AIPolicyExceptionRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    exception_key: str = Field(..., pattern=_AI_POLICY_TOKEN)
    policy_id: str = Field(..., pattern=_AI_POLICY_TOKEN)
    policy_version: int = Field(..., ge=1, le=100)
    scope: AIPolicyScopeIn
    reason: str = Field(..., min_length=1, max_length=2000)
    compensating_control_ids: list[str] = Field(
        ...,
        min_length=1,
        max_length=128,
    )
    expires_at: float = Field(..., gt=0)

    @model_validator(mode="after")
    def bound_compensating_controls(self):
        _validate_string_items(
            self.compensating_control_ids,
            label="AI policy compensating control",
            max_length=128,
        )
        return self


class AIPolicyExceptionApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)


class AIPolicyExceptionCloseIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)
    reason: str = Field(..., min_length=1, max_length=1000)


class AIPolicyContextIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_AI_POLICY_TOKEN)
    risk_tier: Literal["unclassified", "low", "medium", "high", "critical"] = (
        "unclassified"
    )
    jurisdictions: list[str] = Field(default_factory=list, max_length=64)
    data_classes: list[str] = Field(default_factory=list, max_length=64)
    deployment_types: list[str] = Field(default_factory=list, max_length=64)
    asset_types: list[str] = Field(default_factory=list, max_length=64)
    tags: list[str] = Field(default_factory=list, max_length=64)
    use_case_tags: list[str] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def bound_context_tokens(self):
        for name in (
            "jurisdictions",
            "data_classes",
            "deployment_types",
            "asset_types",
            "tags",
            "use_case_tags",
        ):
            _validate_string_items(
                getattr(self, name),
                label=f"AI policy context {name}",
                max_length=128,
            )
        return self


class AIRuntimeGuardrailIn(BaseModel):
    """One transient runtime evaluation; content is never a stored record."""

    model_config = ConfigDict(extra="forbid", strict=True)

    stage: Literal["prompt", "output", "action"]
    content: str = Field(default="", max_length=65_536)
    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    asset_revision: int = Field(..., ge=1)
    asset_version_digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    action_name: str | None = Field(
        None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$",
    )
    action_arguments: dict | None = None
    known_prompt: str | None = Field(None, max_length=65_536)

    @model_validator(mode="after")
    def validate_stage_and_transient_body(self):
        if self.stage == "action":
            if self.action_name is None:
                raise ValueError("action_name is required for the action stage")
        elif self.action_name is not None or self.action_arguments is not None:
            raise ValueError("action metadata is valid only for the action stage")
        if self.known_prompt is not None and self.stage != "output":
            raise ValueError("known_prompt is valid only for the output stage")
        if self.action_arguments is not None:
            _validate_assurance_json(
                self.action_arguments,
                label="runtime action arguments",
                max_bytes=64 * 1024,
                max_depth=8,
                max_nodes=2000,
                max_object_items=128,
                max_array_items=256,
                max_string_chars=16_384,
                max_key_chars=256,
            )
        return self


# Governed digest-only AI explainability ----------------------------------


_AI_EXPLANATION_METHODS = (
    "native_additive",
    "shap",
    "lime",
    "captum",
    "alibi",
    "counterfactual",
)
_AI_EXPLANATION_SCHEMAS = {
    "native_additive": (
        "lightwork.ai-explainability-normalized-native-additive-receipt.v1"
    ),
    "shap": "lightwork.ai-explainability-normalized-shap-receipt.v1",
    "lime": "lightwork.ai-explainability-normalized-lime-receipt.v1",
    "captum": "lightwork.ai-explainability-normalized-captum-receipt.v1",
    "alibi": "lightwork.ai-explainability-normalized-alibi-receipt.v1",
    "counterfactual": (
        "lightwork.ai-explainability-normalized-counterfactual-receipt.v1"
    ),
}


class AIExplanationContributionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    factor_code: str = Field(..., pattern=r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
    direction: Literal["negative", "neutral", "positive"]
    magnitude: float = Field(..., ge=0, le=1)


class AIExplanationCounterfactualIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    change_code: str = Field(..., pattern=r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
    outcome_code: str = Field(..., pattern=r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
    distance: float = Field(..., ge=0, le=1)
    feasible: bool


class AIExplanationReceiptIn(BaseModel):
    """Closed normalized receipt; provider payloads and raw values are forbidden."""

    model_config = ConfigDict(extra="forbid", strict=True)

    receipt_schema: Literal[
        "lightwork.ai-explainability-normalized-native-additive-receipt.v1",
        "lightwork.ai-explainability-normalized-shap-receipt.v1",
        "lightwork.ai-explainability-normalized-lime-receipt.v1",
        "lightwork.ai-explainability-normalized-captum-receipt.v1",
        "lightwork.ai-explainability-normalized-alibi-receipt.v1",
        "lightwork.ai-explainability-normalized-counterfactual-receipt.v1",
    ] = Field(..., alias="schema")
    method: Literal[
        "native_additive",
        "shap",
        "lime",
        "captum",
        "alibi",
        "counterfactual",
    ]
    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    asset_revision: int = Field(..., ge=1)
    asset_version_digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    receipt_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$",
    )
    observed_at: float = Field(..., gt=0)
    input_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    output_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    explainer_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    source_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    contributions: list[AIExplanationContributionIn] = Field(
        default_factory=list,
        max_length=64,
    )
    counterfactuals: list[AIExplanationCounterfactualIn] = Field(
        default_factory=list,
        max_length=16,
    )
    receipt_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)

    @model_validator(mode="after")
    def exact_method_schema_pair(self):
        if self.method not in _AI_EXPLANATION_METHODS:
            raise ValueError("unsupported AI explanation method")
        if self.receipt_schema != _AI_EXPLANATION_SCHEMAS[self.method]:
            raise ValueError("AI explanation schema does not match its method")
        if self.method == "counterfactual":
            if not self.counterfactuals:
                raise ValueError(
                    "counterfactual explanations require a counterfactual"
                )
        elif not self.contributions:
            raise ValueError("attribution explanations require a contribution")
        return self


class AIExplanationReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)
    outcome: Literal["accepted", "needs_remediation", "rejected"]
    evidence_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)


# Independent insurance-assurance evidence profiles -----------------------


class AIInsurabilityEvidenceBindingIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    evidence_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$",
    )
    digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)


class AIInsurabilityCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    profile_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$",
    )
    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    content: dict
    evidence_bindings: list[AIInsurabilityEvidenceBindingIn] = Field(
        default_factory=list,
        max_length=128,
    )
    idempotency_key: str = Field(..., min_length=1, max_length=256)

    @model_validator(mode="after")
    def bound_profile_content(self):
        _validate_assurance_json(
            self.content,
            label="AI assurance profile content",
            max_bytes=256 * 1024,
            max_depth=12,
            max_nodes=10_000,
            max_object_items=256,
            max_array_items=1000,
            max_string_chars=4000,
            max_key_chars=128,
        )
        return self


class AIInsurabilityVersionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    content: dict
    evidence_bindings: list[AIInsurabilityEvidenceBindingIn] = Field(
        default_factory=list,
        max_length=128,
    )
    expected_revision: int = Field(..., ge=1)
    idempotency_key: str = Field(..., min_length=1, max_length=256)

    @model_validator(mode="after")
    def bound_profile_content(self):
        _validate_assurance_json(
            self.content,
            label="AI assurance profile content",
            max_bytes=256 * 1024,
            max_depth=12,
            max_nodes=10_000,
            max_object_items=256,
            max_array_items=1000,
            max_string_chars=4000,
            max_key_chars=128,
        )
        return self


class AIInsurabilityApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: int = Field(..., ge=1, le=50)
    expected_revision: int = Field(..., ge=1)


# EU AI Act conformity-readiness workflow ---------------------------------


class AIConformityCitationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    provision: str = Field(..., min_length=1, max_length=128)
    official_url: str = Field(..., min_length=1, max_length=2048)


class AIConformityCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    economic_operator_role: Literal[
        "provider",
        "deployer",
        "importer",
        "distributor",
        "product_manufacturer",
        "authorised_representative",
        "other",
    ]
    risk_tier: Literal[
        "prohibited",
        "high_risk",
        "limited",
        "minimal",
        "general_purpose",
        "undetermined",
    ]
    act_applicability: Literal["applicable", "not_applicable", "undetermined"]
    legal_basis: list[AIConformityCitationIn] = Field(
        ...,
        min_length=1,
        max_length=16,
    )
    operation_id: str = Field(..., min_length=1, max_length=256)


class AIConformityEvidenceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    evidence_type: Literal[
        "fria",
        "annex_iv",
        "article_43",
        "post_market",
        "declaration_draft",
        "ce_marking",
    ]
    source_ref: str = Field(..., min_length=1, max_length=256)
    sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    operation_id: str = Field(..., min_length=1, max_length=256)


class AIConformityDeterminationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    outcome: Literal["required", "not_required", "undetermined"]
    rationale_sha256: str | None = Field(None, pattern=_MODEL_RISK_DIGEST)
    citations: list[AIConformityCitationIn] = Field(
        default_factory=list,
        max_length=16,
    )
    expected_revision: int = Field(..., ge=1)
    operation_id: str = Field(..., min_length=1, max_length=256)


class AIConformityArticle43RouteIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    route: Literal[
        "internal_control_annex_vi",
        "notified_body_annex_vii",
        "union_harmonisation_law",
        "not_applicable",
        "undetermined",
    ]
    rationale_sha256: str | None = Field(None, pattern=_MODEL_RISK_DIGEST)
    citations: list[AIConformityCitationIn] = Field(
        default_factory=list,
        max_length=16,
    )
    expected_revision: int = Field(..., ge=1)
    operation_id: str = Field(..., min_length=1, max_length=256)


class AIConformityChecklistEntryIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    domain: Literal[
        "fria",
        "annex_iv",
        "article_43",
        "post_market",
        "declaration_draft",
        "ce_marking",
    ]
    section: str = Field(..., min_length=1, max_length=128)
    status: Literal["pending", "complete", "not_applicable"]
    evidence_binding_ids: list[str] = Field(default_factory=list, max_length=16)
    rationale_sha256: str | None = Field(None, pattern=_MODEL_RISK_DIGEST)
    citations: list[AIConformityCitationIn] = Field(
        default_factory=list,
        max_length=16,
    )
    expected_revision: int = Field(..., ge=1)
    operation_id: str = Field(..., min_length=1, max_length=256)

    @model_validator(mode="after")
    def bound_binding_ids(self):
        _validate_string_items(
            self.evidence_binding_ids,
            label="conformity evidence binding",
            max_length=36,
        )
        return self


class AIConformityActionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)
    operation_id: str = Field(..., min_length=1, max_length=256)


# Regulated-vertical evidence packages ------------------------------------


class AIRegulatedVerticalCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    package_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$",
    )
    package_type: Literal[
        "credit_adverse_action",
        "fair_lending_aggregate",
        "nyc_ll144",
        "naic_insurance",
    ]
    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    content: dict
    evidence_bindings: list[AIInsurabilityEvidenceBindingIn] = Field(
        default_factory=list,
        max_length=128,
    )
    idempotency_key: str = Field(..., min_length=1, max_length=256)

    @model_validator(mode="after")
    def bound_package_content(self):
        _validate_assurance_json(
            self.content,
            label="regulated-vertical package content",
            max_bytes=256 * 1024,
            max_depth=12,
            max_nodes=10_000,
            max_object_items=256,
            max_array_items=1000,
            max_string_chars=4000,
            max_key_chars=128,
        )
        return self


class AIRegulatedVerticalVersionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    content: dict
    evidence_bindings: list[AIInsurabilityEvidenceBindingIn] = Field(
        default_factory=list,
        max_length=128,
    )
    expected_revision: int = Field(..., ge=1)
    idempotency_key: str = Field(..., min_length=1, max_length=256)

    @model_validator(mode="after")
    def bound_package_content(self):
        _validate_assurance_json(
            self.content,
            label="regulated-vertical package content",
            max_bytes=256 * 1024,
            max_depth=12,
            max_nodes=10_000,
            max_object_items=256,
            max_array_items=1000,
            max_string_chars=4000,
            max_key_chars=128,
        )
        return self


class AIRegulatedVerticalApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: int = Field(..., ge=1, le=50)
    expected_revision: int = Field(..., ge=1)


# Bank model-risk-management evidence packages ----------------------------


class AIBankMRMCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    package_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$",
    )
    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    content: dict
    evidence_bindings: list[AIInsurabilityEvidenceBindingIn] = Field(
        default_factory=list,
        max_length=128,
    )
    idempotency_key: str = Field(..., min_length=1, max_length=256)

    @model_validator(mode="after")
    def bound_package_content(self):
        _validate_assurance_json(
            self.content,
            label="bank MRM package content",
            max_bytes=256 * 1024,
            max_depth=12,
            max_nodes=10_000,
            max_object_items=256,
            max_array_items=1000,
            max_string_chars=4000,
            max_key_chars=128,
        )
        return self


class AIBankMRMVersionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    content: dict
    evidence_bindings: list[AIInsurabilityEvidenceBindingIn] = Field(
        default_factory=list,
        max_length=128,
    )
    expected_revision: int = Field(..., ge=1)
    idempotency_key: str = Field(..., min_length=1, max_length=256)

    @model_validator(mode="after")
    def bound_package_content(self):
        _validate_assurance_json(
            self.content,
            label="bank MRM package content",
            max_bytes=256 * 1024,
            max_depth=12,
            max_nodes=10_000,
            max_object_items=256,
            max_array_items=1000,
            max_string_chars=4000,
            max_key_chars=128,
        )
        return self


class AIBankMRMApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: int = Field(..., ge=1, le=50)
    expected_revision: int = Field(..., ge=1)


# Privacy-bounded benchmark exchange --------------------------------------


_AI_BENCHMARK_METRIC = (
    "control_coverage_rate|eval_pass_rate|human_review_rate|incident_free_rate|"
    "model_drift_free_rate|policy_exception_free_rate|red_team_pass_rate|"
    "runtime_allow_rate"
)


class AIBenchmarkPeriodIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    start: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    end: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")


class AIBenchmarkCohortIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    industry_code: Literal[
        "financial_services",
        "healthcare",
        "manufacturing",
        "public_sector",
        "retail",
        "technology",
        "other",
        "undisclosed",
    ]
    geography_code: Literal[
        "asia_pacific",
        "europe",
        "global",
        "latin_america",
        "middle_east_africa",
        "north_america",
        "undisclosed",
    ]
    organization_size_code: Literal[
        "small",
        "midsize",
        "enterprise",
        "undisclosed",
    ]
    model_modality_code: Literal[
        "audio",
        "image",
        "multimodal",
        "tabular",
        "text",
        "video",
        "other",
    ]


class AIBenchmarkContributionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    contribution_id: str = Field(..., pattern=r"^BCI-[0-9a-f]{32}$")
    metric_code: str = Field(..., pattern=f"^({_AI_BENCHMARK_METRIC})$")
    numerator: int = Field(..., ge=0, le=1_000_000_000_000)
    denominator: int = Field(..., ge=1, le=1_000_000_000_000)
    period: AIBenchmarkPeriodIn
    cohort: AIBenchmarkCohortIn
    evidence_bindings: list[AIInsurabilityEvidenceBindingIn] = Field(
        ...,
        min_length=1,
        max_length=32,
    )
    voluntary_opt_in: Literal[True]
    idempotency_key: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$",
    )

    @model_validator(mode="after")
    def bounded_ratio(self):
        if self.numerator > self.denominator:
            raise ValueError("benchmark numerator cannot exceed denominator")
        return self


class AIBenchmarkContributionVersionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    metric_code: str = Field(..., pattern=f"^({_AI_BENCHMARK_METRIC})$")
    numerator: int = Field(..., ge=0, le=1_000_000_000_000)
    denominator: int = Field(..., ge=1, le=1_000_000_000_000)
    period: AIBenchmarkPeriodIn
    cohort: AIBenchmarkCohortIn
    evidence_bindings: list[AIInsurabilityEvidenceBindingIn] = Field(
        ...,
        min_length=1,
        max_length=32,
    )
    voluntary_opt_in: Literal[True]
    idempotency_key: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$",
    )
    expected_revision: int = Field(..., ge=1)

    @model_validator(mode="after")
    def bounded_ratio(self):
        if self.numerator > self.denominator:
            raise ValueError("benchmark numerator cannot exceed denominator")
        return self


class AIBenchmarkContributionApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: int = Field(..., ge=1, le=50)
    expected_revision: int = Field(..., ge=1)


class AIBenchmarkCoordinatorSubmitIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    explicit_consent: Literal[True]
    idempotency_key: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$",
    )
    version: int | None = Field(default=None, ge=1, le=50)


class AIBenchmarkPrivacyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    state: Literal["not_dp", "differential_privacy"]
    epsilon: float | None = Field(None, gt=0)
    delta: float | None = Field(None, ge=0, lt=1)
    noise_mechanism: Literal["discrete_gaussian", "gaussian", "laplace"] | None = None

    @model_validator(mode="after")
    def complete_or_explicitly_not_dp(self):
        values = (self.epsilon, self.delta, self.noise_mechanism)
        if self.state == "not_dp" and any(value is not None for value in values):
            raise ValueError("not_dp reports cannot carry DP parameters")
        if self.state == "differential_privacy" and any(
            value is None for value in values
        ):
            raise ValueError("differential_privacy reports require complete parameters")
        return self


class AIBenchmarkSignatureIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    algorithm: Literal["ECDSA-P256-SHA256", "Ed25519", "RSA-PSS-SHA256"]
    key_id: str = Field(..., pattern=r"^KEY-[0-9a-f]{32}$")
    value: str = Field(..., min_length=32, max_length=2048)


class AIBenchmarkCohortReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    report_schema: Literal["lightwork.ai-benchmark-cohort-report.v1"] = Field(
        ...,
        alias="schema",
    )
    report_id: str = Field(..., pattern=r"^BXR-[0-9a-f]{32}$")
    issued_at: float = Field(..., gt=0)
    metric_code: str = Field(..., pattern=f"^({_AI_BENCHMARK_METRIC})$")
    numerator: int = Field(..., ge=0, le=1_000_000_000_000)
    denominator: int = Field(..., ge=1, le=1_000_000_000_000)
    period: AIBenchmarkPeriodIn
    cohort: AIBenchmarkCohortIn
    contributor_count: int = Field(..., ge=5, le=1_000_000_000_000)
    k_anonymity_min: int = Field(..., ge=5, le=1_000_000_000_000)
    aggregation_method: Literal[
        "pooled_ratio",
        "weighted_mean_ratio",
        "unweighted_mean_ratio",
    ]
    privacy: AIBenchmarkPrivacyIn
    methodology_version: Literal["benchmark-aggregate-v1"]
    report_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    signature: AIBenchmarkSignatureIn

    @model_validator(mode="after")
    def bounded_report(self):
        if self.numerator > self.denominator:
            raise ValueError("benchmark numerator cannot exceed denominator")
        if self.contributor_count < self.k_anonymity_min:
            raise ValueError("contributor_count must satisfy k_anonymity_min")
        return self


# Privacy-safe discovery sensor control plane ------------------------------


class AIDiscoverySensorRegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    sensor_name: str = Field(..., pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")
    sensor_type: Literal[
        "browser_extension",
        "network_egress",
        "oauth_grant",
        "saas_posture",
        "identity_directory",
        "data_catalog",
    ]
    config_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)


class AIDiscoverySensorApprovalIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)


class AIDiscoverySensorConfigurationIn(AIDiscoverySensorApprovalIn):
    config_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)


class AIDiscoverySensorRevocationIn(AIDiscoverySensorApprovalIn):
    reason_code: str = Field(
        ...,
        pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$",
    )


class AIDiscoveryObservationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    sensor_revision: int = Field(..., ge=1)
    config_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    event_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    observed_at: float = Field(..., ge=0)
    ai_service_code: str = Field(..., pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")
    ai_product_code: str = Field(..., pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")
    provider_code: str = Field(..., pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")
    domain_category: str = Field(..., pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")
    deployment_type: Literal[
        "embedded",
        "hosted_api",
        "managed_cloud",
        "saas",
        "self_hosted",
        "unknown",
    ]
    environment_code: str = Field(..., pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")
    context_codes: list[str] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def bounded_context_codes(self):
        for index, value in enumerate(self.context_codes):
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?", value):
                raise ValueError(f"context code {index} is invalid")
        return self


# Tenant-bound identity control plane ------------------------------------


_AI_IDENTITY_PRINCIPAL_REF = r"^prn_[0-9a-f]{32}$"
_AI_IDENTITY_PROVIDER_SUBJECT = r"^(?:sub|idn)_[0-9a-f]{32}$"
_AI_IDENTITY_CODE = r"^[a-z][a-z0-9_.:-]{0,127}$"
_AI_IDENTITY_ASSET_ID = r"^ast_[0-9a-f]{32}$"
_AI_IDENTITY_IDEMPOTENCY = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,255}$"


class AIIdentityFederationBindingIn(BaseModel):
    """Pseudonymous exact-match assertions; raw identities are inadmissible.

    ``provider_subject_id`` selects no authority by itself. The runtime must
    independently resolve an enrolled principal/provider binding and require
    this value to match it exactly.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    principal_ref: str = Field(..., pattern=_AI_IDENTITY_PRINCIPAL_REF)
    provider_subject_id: str = Field(..., pattern=_AI_IDENTITY_PROVIDER_SUBJECT)
    expected_binding_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    expected_revision: int = Field(..., ge=1)


class AIIdentityCapabilityDecisionIn(AIIdentityFederationBindingIn):
    required_capability: str = Field(..., pattern=_AI_IDENTITY_CODE)
    idempotency_key: str = Field(..., pattern=_AI_IDENTITY_IDEMPOTENCY)


class AIIdentityPurviewContextIn(AIIdentityFederationBindingIn):
    provider: Literal["entra", "okta"]


class AIIdentityPurviewPrepareIn(AIIdentityPurviewContextIn):
    asset_id: str = Field(..., pattern=_AI_IDENTITY_ASSET_ID)
    classification_codes: list[str] = Field(..., max_length=128)
    expected_asset_binding_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    expected_source_revision: int = Field(..., ge=1)
    idempotency_key: str = Field(..., pattern=_AI_IDENTITY_IDEMPOTENCY)

    @model_validator(mode="after")
    def exact_classification_codes(self):
        if self.classification_codes != sorted(set(self.classification_codes)):
            raise ValueError("classification_codes must be sorted and unique")
        for index, value in enumerate(self.classification_codes):
            if not re.fullmatch(_AI_IDENTITY_CODE.removeprefix("^").removesuffix("$"), value):
                raise ValueError(f"classification code {index} is invalid")
        return self


class AIIdentityPurviewRecordIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    principal_ref: str = Field(..., pattern=_AI_IDENTITY_PRINCIPAL_REF)
    mapping_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)


class AIIdentityPurviewRevisionIn(AIIdentityPurviewRecordIn):
    expected_record_revision: int = Field(..., ge=1)


# Digest-only C2PA media provenance ---------------------------------------


_AI_MEDIA_IDENTITY = r"^[A-Za-z0-9][A-Za-z0-9_.:@/+\-=]{0,255}$"
_AI_MEDIA_TOKEN = r"^[a-z0-9][a-z0-9_.:/-]{0,127}$"


class AIMediaProvenanceReceiptIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    receipt_schema: Literal["lightwork.c2pa-adapter-receipt.v1"] = Field(
        ...,
        alias="schema",
    )
    operation: Literal["verification", "signing"]
    adapter_id: str = Field(..., pattern=_AI_MEDIA_TOKEN)
    adapter_version: str = Field(..., pattern=_AI_MEDIA_IDENTITY)
    standard: str = Field(..., pattern=r"^c2pa(?:/[0-9]+(?:\.[0-9]+)*)?$")
    receipt_id: str = Field(..., pattern=_AI_MEDIA_IDENTITY)
    observed_at: float = Field(..., gt=0, le=100_000_000_000.0)
    media_kind: Literal["image", "audio", "video"]
    source_content_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    content_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    asset_id: str = Field(..., pattern=_MODEL_RISK_ASSET_ID)
    asset_revision: int = Field(..., ge=1)
    asset_version_digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    deployment_id: str = Field(..., pattern=_AI_MEDIA_IDENTITY)
    deployment_revision: int = Field(..., ge=1)
    deployment_artifact_digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    context_id: str = Field(..., pattern=_AI_MEDIA_IDENTITY)
    context_revision: int = Field(..., ge=1)
    context_digest: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    manifest_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)
    claim_generator: str = Field(..., min_length=1, max_length=256)
    signing_time: float = Field(..., gt=0, le=100_000_000_000.0)
    validation_state: Literal[
        "valid",
        "invalid",
        "indeterminate",
        "unsupported",
        "error",
    ]
    assertion_codes: list[str] = Field(..., min_length=1, max_length=64)
    trust_chain_state: Literal[
        "trusted",
        "untrusted",
        "unknown",
        "not_applicable",
        "error",
    ]
    receipt_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)

    @model_validator(mode="after")
    def closed_receipt_contract(self):
        if self.operation == "verification" and (
            self.source_content_sha256.lower().removeprefix("sha256:")
            != self.content_sha256.lower().removeprefix("sha256:")
        ):
            raise ValueError("verification receipt content digests must match")
        if len(set(self.assertion_codes)) != len(self.assertion_codes):
            raise ValueError("assertion_codes must be unique")
        for index, value in enumerate(self.assertion_codes):
            if not re.fullmatch(_AI_MEDIA_TOKEN.removeprefix("^").removesuffix("$"), value):
                raise ValueError(f"assertion code {index} is invalid")
        return self


class AIMediaProvenanceReleasePrepareIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)
    purpose_code: str = Field(..., pattern=_AI_MEDIA_TOKEN)
    evidence_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)


class AIMediaProvenanceReleaseReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)
    outcome: Literal["approved", "rejected", "needs_remediation"]
    evidence_sha256: str = Field(..., pattern=_MODEL_RISK_DIGEST)


class AIPolicyPreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    context: AIPolicyContextIn


class AIPolicyEvaluateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    evaluation_key: str = Field(..., pattern=_AI_POLICY_TOKEN)
    context: AIPolicyContextIn
    expected_revision: int = Field(0, ge=0)


class AIPolicyAttestIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_revision: int = Field(..., ge=1)


class EvidenceGatewayPacketVerifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    packet: dict

    @model_validator(mode="after")
    def bound_packet(self):
        _validate_assurance_json(
            self.packet,
            label="assurance packet",
            max_bytes=2 * 1024 * 1024,
            max_depth=16,
            max_nodes=50_000,
            max_object_items=4096,
            max_array_items=10_000,
            max_string_chars=262_144,
            max_key_chars=256,
        )
        return self
