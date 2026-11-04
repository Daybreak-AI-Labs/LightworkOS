"""Tenant-bound, digest-only multimodal evidence analysis authority.

The authority accepts raw artifacts only as ephemeral adapter input. Durable
records contain media metadata, SHA-256 pins, closed evidence codes, revisioned
criteria, deterministic adapter receipts, transparent score components, and a
provenance chain. They never contain artifact bytes, extracted text, prompts,
credentials, or a legal/compliance conclusion.

Extraction and analysis adapters are untrusted computation seams. Deployment
must independently attest exact deterministic, offline, data-only adapter
authorities. Core validates every returned pin and digest, limits outputs to
criteria-defined codes, computes summaries/scores/remediation itself, and
requires a distinct authorized human before a record can be released.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import math
import re
import secrets
import sqlite3
import threading
import time
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, fields, replace
from importlib import metadata as importlib_metadata
from io import BytesIO
from pathlib import Path
from typing import Any

from .constant_time import text_equals
from .file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

ARTIFACT_AUTHORITY_SCHEMA = "lightwork.ai-evidence.artifact-authority.v1"
CRITERION_SCHEMA = "lightwork.ai-evidence.criterion.v1"
CRITERIA_AUTHORITY_SCHEMA = "lightwork.ai-evidence.criteria-authority.v1"
ADAPTER_AUTHORITY_SCHEMA = "lightwork.ai-evidence.adapter-authority.v1"
EXTRACTION_REQUEST_SCHEMA = "lightwork.ai-evidence.extraction-request.v1"
EXTRACTION_OUTPUT_SCHEMA = "lightwork.ai-evidence.extraction-output.v1"
FACT_SCHEMA = "lightwork.ai-evidence.fact.v1"
ANALYSIS_REQUEST_SCHEMA = "lightwork.ai-evidence.analysis-request.v1"
ASSESSMENT_SCHEMA = "lightwork.ai-evidence.assessment.v1"
ANALYSIS_OUTPUT_SCHEMA = "lightwork.ai-evidence.analysis-output.v1"
REVIEW_AUTHORITY_SCHEMA = "lightwork.ai-evidence.review-authority.v1"
ARTIFACT_RECORD_SCHEMA = "lightwork.ai-evidence.artifact-record.v1"
SUMMARY_SCHEMA = "lightwork.ai-evidence.summary.v1"
JUSTIFICATION_SCHEMA = "lightwork.ai-evidence.justification.v1"
GAP_SCHEMA = "lightwork.ai-evidence.gap-suggestion.v1"
PROVENANCE_SCHEMA = "lightwork.ai-evidence.provenance-link.v1"
RECORD_SCHEMA = "lightwork.ai-evidence.analysis-record.v1"
INTEGRITY_SCHEMA = "lightwork.ai-evidence.integrity-report.v1"

NON_CONCLUSION_NOTICE = (
    "This is a technical evidence aid requiring human review. It is not legal "
    "advice, a compliance determination, certification, or conformity assessment."
)

RAW_ARTIFACT_CONTENT_PERSISTED = False
EXTRACTED_TEXT_PERSISTED = False
LEGAL_OR_COMPLIANCE_CONCLUSION = False

MEDIA_PDF = "application/pdf"
MEDIA_JPEG = "image/jpeg"
MEDIA_PNG = "image/png"
MEDIA_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
MEDIA_XLS = "application/vnd.ms-excel"
MEDIA_TEXT = "text/plain"
SUPPORTED_MEDIA_TYPES = frozenset(
    {MEDIA_PDF, MEDIA_JPEG, MEDIA_PNG, MEDIA_XLSX, MEDIA_XLS, MEDIA_TEXT}
)

__all__ = [
    "ADAPTER_AUTHORITY_SCHEMA",
    "ANALYSIS_OUTPUT_SCHEMA",
    "ANALYSIS_REQUEST_SCHEMA",
    "ARTIFACT_AUTHORITY_SCHEMA",
    "BoundedLocalExtractionAdapter",
    "CriterionEvidenceAssessment",
    "DeterministicCriteriaAnalysisAdapter",
    "EvidenceAdapterAuthority",
    "EvidenceAnalysisAdapterOutput",
    "EvidenceAnalysisConfigError",
    "EvidenceAnalysisConflict",
    "EvidenceAnalysisError",
    "EvidenceAnalysisIntegrityError",
    "EvidenceAnalysisIntegrityReport",
    "EvidenceAnalysisNotFound",
    "EvidenceAnalysisPermissionError",
    "EvidenceAnalysisRecord",
    "EvidenceAnalysisRequest",
    "EvidenceAnalysisStore",
    "EvidenceAnalysisValidationError",
    "EvidenceArtifact",
    "EvidenceArtifactAuthority",
    "EvidenceArtifactRecord",
    "EvidenceCriteriaAuthority",
    "EvidenceCriterion",
    "EvidenceExtractionOutput",
    "EvidenceExtractionRequest",
    "EvidenceGapSuggestion",
    "EvidenceProvenanceLink",
    "EvidenceRetentionResult",
    "EvidenceSummary",
    "EXTRACTED_TEXT_PERSISTED",
    "EXTRACTION_OUTPUT_SCHEMA",
    "EXTRACTION_REQUEST_SCHEMA",
    "ExtractedEvidenceFact",
    "HumanReviewAuthority",
    "JustificationComponent",
    "JustificationScore",
    "LEGAL_OR_COMPLIANCE_CONCLUSION",
    "MEDIA_JPEG",
    "MEDIA_PDF",
    "MEDIA_PNG",
    "MEDIA_TEXT",
    "MEDIA_XLS",
    "MEDIA_XLSX",
    "NON_CONCLUSION_NOTICE",
    "RAW_ARTIFACT_CONTENT_PERSISTED",
    "SUPPORTED_MEDIA_TYPES",
    "adapter_authority_sha256",
    "analysis_output_sha256",
    "artifact_byte_limit",
    "artifact_authority_sha256",
    "assessment_sha256",
    "criteria_authority_sha256",
    "criterion_sha256",
    "extraction_output_sha256",
    "fact_sha256",
    "review_authority_sha256",
]

_MEDIA_LIMITS = {
    MEDIA_PDF: 16 * 1024 * 1024,
    MEDIA_JPEG: 12 * 1024 * 1024,
    MEDIA_PNG: 12 * 1024 * 1024,
    MEDIA_XLSX: 20 * 1024 * 1024,
    MEDIA_XLS: 20 * 1024 * 1024,
    MEDIA_TEXT: 2 * 1024 * 1024,
}
_SCHEMA_VERSION = 1
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_CRITERIA = 128
_MAX_FACTS = 512
_MAX_ANALYSES = 10_000
_MAX_VALID_SECONDS = 366 * 24 * 60 * 60
_MAX_RETENTION_SECONDS = 10 * 366 * 24 * 60 * 60
_MIN_RETENTION_SECONDS = 60
_MAX_PURGE = 500
_ZERO_DIGEST = "0" * 64
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CONCLUSION_TERMS = frozenset(
    {"certified", "compliant", "conformant", "lawful", "noncompliant", "unlawful"}
)
_DISPOSITIONS = frozenset(
    {"evidence_supported", "evidence_partial", "evidence_missing", "indeterminate"}
)
_RATIONALE_BY_DISPOSITION = {
    "evidence_supported": "direct_evidence",
    "evidence_partial": "partial_evidence",
    "evidence_missing": "no_matching_evidence",
    "indeterminate": "adapter_indeterminate",
}
_COVERAGE_BPS = {
    "evidence_supported": 10_000,
    "evidence_partial": 5_000,
    "evidence_missing": 0,
    "indeterminate": 0,
}
_REVIEW_CAPABILITIES = frozenset({"approve", "reject", "revoke"})
_STATUSES = frozenset({"pending_review", "review_approved", "review_rejected", "revoked"})
_LOCAL_ADAPTER_ID = "lightwork-local-multimodal"
_LOCAL_ADAPTER_REVISION = 1


def artifact_byte_limit(media_type: str) -> int:
    """Return the core ingestion limit for one exact supported media type."""

    if type(media_type) is not str or media_type not in SUPPORTED_MEDIA_TYPES:
        raise EvidenceAnalysisValidationError("artifact media type is unsupported")
    return _MEDIA_LIMITS[media_type]


class EvidenceAnalysisError(RuntimeError):
    """Base evidence-analysis error."""


class EvidenceAnalysisConfigError(EvidenceAnalysisError):
    """A gate, adapter, or independent authority is unavailable."""


class EvidenceAnalysisValidationError(EvidenceAnalysisError, ValueError):
    """Caller material is outside the closed evidence contract."""


class EvidenceAnalysisConflict(EvidenceAnalysisError):
    """An idempotency pin, revision, or independently resolved pin changed."""


class EvidenceAnalysisNotFound(EvidenceAnalysisError):
    """A tenant-local evidence analysis does not exist."""


class EvidenceAnalysisPermissionError(EvidenceAnalysisError):
    """Human review or release authority is missing or insufficient."""


class EvidenceAnalysisIntegrityError(EvidenceAnalysisError):
    """Adapter or persisted evidence failed integrity validation."""


def _disabled_gate() -> None:
    raise EvidenceAnalysisConfigError("AI evidence analysis is not enabled")


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    artifact_id: str
    media_type: str
    content: bytes
    source_ref: str
    source_revision: int
    acquired_at: float


@dataclass(frozen=True, slots=True)
class EvidenceArtifactAuthority:
    tenant_sha256: str
    artifact_id: str
    media_type: str
    content_sha256: str
    byte_length: int
    source_ref: str
    source_revision: int
    acquired_at: float
    valid_until: float
    revoked: bool
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceCriterion:
    criterion_id: str
    revision: int
    control_ref: str
    control_revision: int
    control_sha256: str
    legal_basis_ref: str
    legal_basis_revision: int
    legal_basis_sha256: str
    stakeholder_requirement_ref: str
    stakeholder_requirement_revision: int
    stakeholder_requirement_sha256: str
    expected_fact_code: str
    gap_code: str
    remediation_code: str
    weight_bps: int
    criterion_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceCriteriaAuthority:
    tenant_sha256: str
    criteria_set_id: str
    revision: int
    criteria: tuple[EvidenceCriterion, ...]
    valid_until: float
    revoked: bool
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceAdapterAuthority:
    stage: str
    adapter_id: str
    revision: int
    implementation_sha256: str
    configuration_sha256: str
    deterministic: bool
    network_access: bool
    untrusted_content_mode: str
    legal_conclusion_enabled: bool
    valid_until: float
    revoked: bool
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceArtifactRecord:
    artifact_id: str
    media_type: str
    content_sha256: str
    byte_length: int
    source_ref: str
    source_revision: int
    acquired_at: float
    artifact_authority_sha256: str
    descriptor_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceExtractionRequest:
    schema: str
    artifact: EvidenceArtifact
    artifact_record: EvidenceArtifactRecord
    criteria_authority: EvidenceCriteriaAuthority
    adapter_authority_sha256: str
    untrusted_content: bool
    instruction_mode: str
    request_sha256: str


@dataclass(frozen=True, slots=True)
class ExtractedEvidenceFact:
    fact_id: str
    fact_code: str
    locator_sha256: str
    value_sha256: str
    confidence_bps: int
    fact_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceExtractionOutput:
    schema: str
    request_sha256: str
    artifact_descriptor_sha256: str
    criteria_authority_sha256: str
    adapter_authority_sha256: str
    deterministic: bool
    facts: tuple[ExtractedEvidenceFact, ...]
    output_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceAnalysisRequest:
    schema: str
    artifact_record: EvidenceArtifactRecord
    criteria_authority: EvidenceCriteriaAuthority
    extraction: EvidenceExtractionOutput
    adapter_authority_sha256: str
    request_sha256: str


@dataclass(frozen=True, slots=True)
class CriterionEvidenceAssessment:
    criterion_id: str
    criterion_sha256: str
    disposition: str
    fact_ids: tuple[str, ...]
    confidence_bps: int
    rationale_code: str
    assessment_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceAnalysisAdapterOutput:
    schema: str
    request_sha256: str
    artifact_descriptor_sha256: str
    criteria_authority_sha256: str
    extraction_output_sha256: str
    adapter_authority_sha256: str
    deterministic: bool
    assessments: tuple[CriterionEvidenceAssessment, ...]
    output_sha256: str


@dataclass(frozen=True, slots=True)
class HumanReviewAuthority:
    tenant_sha256: str
    reviewer_sha256: str
    capabilities: tuple[str, ...]
    revision: int
    valid_until: float
    revoked: bool
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceSummary:
    total_criteria: int
    evidence_supported: int
    evidence_partial: int
    evidence_missing: int
    indeterminate: int
    extracted_fact_count: int
    summary_sha256: str


@dataclass(frozen=True, slots=True)
class JustificationComponent:
    criterion_id: str
    weight_bps: int
    coverage_bps: int
    confidence_bps: int
    provenance_bps: int
    component_score_bps: int
    component_sha256: str


@dataclass(frozen=True, slots=True)
class JustificationScore:
    methodology: str
    components: tuple[JustificationComponent, ...]
    score_bps: int
    maximum_bps: int
    score_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceGapSuggestion:
    criterion_id: str
    disposition: str
    gap_code: str
    remediation_code: str
    suggestion_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceProvenanceLink:
    sequence: int
    stage: str
    input_sha256: str
    output_sha256: str
    previous_link_sha256: str
    link_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceAnalysisRecord:
    analysis_id: str
    tenant_sha256: str
    artifact_authority: EvidenceArtifactAuthority
    artifact: EvidenceArtifactRecord
    criteria_authority: EvidenceCriteriaAuthority
    extraction_adapter_authority: EvidenceAdapterAuthority
    analysis_adapter_authority: EvidenceAdapterAuthority
    extraction: EvidenceExtractionOutput
    adapter_analysis: EvidenceAnalysisAdapterOutput
    summary: EvidenceSummary
    justification: JustificationScore
    gaps: tuple[EvidenceGapSuggestion, ...]
    provenance: tuple[EvidenceProvenanceLink, ...]
    provenance_sha256: str
    submitter_sha256: str
    status: str
    human_review_required: bool
    review_decision: str | None
    review_authority: HumanReviewAuthority | None
    reviewed_at: float | None
    revocation_authority: HumanReviewAuthority | None
    revocation_reason_code: str | None
    revoked_at: float | None
    legal_or_compliance_conclusion: bool
    notice: str
    valid_until: float
    retained_until: float
    created_at: float
    updated_at: float
    revision: int
    previous_integrity_sha256: str | None
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceAnalysisIntegrityReport:
    schema: str
    analyses: int
    history_records: int
    operations: int
    terminal_sha256: str
    verification_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceRetentionResult:
    analysis_ids: tuple[str, ...]
    history_records: int
    operations: int


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise EvidenceAnalysisValidationError("evidence material is not canonical JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise EvidenceAnalysisValidationError("evidence material exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _implementation_sha256(value: type) -> str:
    try:
        source = inspect.getsource(value)
    except (OSError, TypeError) as exc:
        raise EvidenceAnalysisConfigError("adapter implementation source is unavailable") from exc
    return _text_sha256(source)


def _distribution_version(name: str) -> str:
    try:
        return importlib_metadata.version(name)
    except importlib_metadata.PackageNotFoundError:
        return "unavailable"


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and text_equals(left, right)


def _without_digest(value: object, field: str, schema: str) -> dict[str, Any]:
    payload = asdict(value)
    payload.pop(field)
    payload["schema"] = schema
    return payload


def artifact_authority_sha256(value: EvidenceArtifactAuthority) -> str:
    return _sha256(_without_digest(value, "authority_sha256", ARTIFACT_AUTHORITY_SCHEMA))


def criterion_sha256(value: EvidenceCriterion) -> str:
    return _sha256(_without_digest(value, "criterion_sha256", CRITERION_SCHEMA))


def criteria_authority_sha256(value: EvidenceCriteriaAuthority) -> str:
    return _sha256(_without_digest(value, "authority_sha256", CRITERIA_AUTHORITY_SCHEMA))


def adapter_authority_sha256(value: EvidenceAdapterAuthority) -> str:
    return _sha256(_without_digest(value, "authority_sha256", ADAPTER_AUTHORITY_SCHEMA))


def fact_sha256(value: ExtractedEvidenceFact) -> str:
    return _sha256(_without_digest(value, "fact_sha256", FACT_SCHEMA))


def extraction_output_sha256(value: EvidenceExtractionOutput) -> str:
    return _sha256(_without_digest(value, "output_sha256", EXTRACTION_OUTPUT_SCHEMA))


def assessment_sha256(value: CriterionEvidenceAssessment) -> str:
    return _sha256(_without_digest(value, "assessment_sha256", ASSESSMENT_SCHEMA))


def analysis_output_sha256(value: EvidenceAnalysisAdapterOutput) -> str:
    return _sha256(_without_digest(value, "output_sha256", ANALYSIS_OUTPUT_SCHEMA))


def review_authority_sha256(value: HumanReviewAuthority) -> str:
    return _sha256(_without_digest(value, "authority_sha256", REVIEW_AUTHORITY_SCHEMA))


def _ref(value: object, label: str, pattern: re.Pattern[str] = _REF_RE) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise EvidenceAnalysisValidationError(f"{label} must be a bounded opaque reference")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise EvidenceAnalysisValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _evidence_code(value: object, label: str) -> str:
    selected = _ref(value, label)
    words = {word for word in re.split(r"[_.:-]+", selected.lower()) if word}
    if words & _CONCLUSION_TERMS:
        raise EvidenceAnalysisValidationError(
            f"{label} cannot encode a legal or compliance conclusion"
        )
    return selected


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EvidenceAnalysisValidationError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceAnalysisValidationError(f"{label} must be a timestamp")
    selected = float(value)
    if not math.isfinite(selected) or selected <= 0:
        raise EvidenceAnalysisValidationError(f"{label} must be a positive finite timestamp")
    return selected


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise EvidenceAnalysisValidationError("tenant_id is invalid") from exc


def _actor_sha256(tenant_id: str, actor_ref: object) -> str:
    actor = _ref(actor_ref, "actor_ref")
    return _text_sha256(f"lightwork.ai-evidence.actor.v1:{tenant_id}:{actor}")


def _idempotency_sha256(tenant_sha256: str, key: object) -> str:
    selected = _ref(key, "idempotency_key", _IDEMPOTENCY_RE)
    return _sha256(
        {
            "schema": "lightwork.ai-evidence.idempotency.v1",
            "tenant_sha256": tenant_sha256,
            "idempotency_key": selected,
        }
    )


def _now(clock: Callable[[], float]) -> float:
    try:
        return _timestamp(clock(), "clock")
    except (KeyboardInterrupt, SystemExit):
        raise
    except EvidenceAnalysisValidationError:
        raise
    except Exception as exc:
        raise EvidenceAnalysisConfigError("evidence-analysis clock is unavailable") from exc


def _lifetime(now: float, valid_until: object, retained_until: object) -> tuple[float, float]:
    valid = _timestamp(valid_until, "valid_until")
    retained = _timestamp(retained_until, "retained_until")
    if not now < valid <= now + _MAX_VALID_SECONDS:
        raise EvidenceAnalysisValidationError("analysis validity is outside its bound")
    if not max(valid, now + _MIN_RETENTION_SECONDS) <= retained <= now + _MAX_RETENTION_SECONDS:
        raise EvidenceAnalysisValidationError("analysis retention is outside its bound")
    return valid, retained


def _exact_mapping(value: object, model: type, label: str) -> dict[str, Any]:
    expected = {field.name for field in fields(model)}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise EvidenceAnalysisIntegrityError(f"stored {label} has an invalid shape")
    return dict(value)


def _validate_artifact(value: EvidenceArtifact) -> tuple[str, int]:
    if type(value) is not EvidenceArtifact:
        raise EvidenceAnalysisValidationError("artifact contract is invalid")
    _ref(value.artifact_id, "artifact_id")
    _ref(value.source_ref, "source_ref")
    _integer(value.source_revision, "source_revision", 1, 2_147_483_647)
    _timestamp(value.acquired_at, "acquired_at")
    if value.media_type not in SUPPORTED_MEDIA_TYPES:
        raise EvidenceAnalysisValidationError("artifact media type is unsupported")
    if type(value.content) is not bytes or not value.content:
        raise EvidenceAnalysisValidationError("artifact content must be non-empty bytes")
    size = len(value.content)
    if size > _MEDIA_LIMITS[value.media_type]:
        raise EvidenceAnalysisValidationError("artifact exceeds its media byte bound")
    content = value.content
    if value.media_type == MEDIA_PDF and not content.startswith(b"%PDF-"):
        raise EvidenceAnalysisValidationError("PDF signature is invalid")
    if value.media_type == MEDIA_JPEG and not (
        content.startswith(b"\xff\xd8\xff") and content.endswith(b"\xff\xd9")
    ):
        raise EvidenceAnalysisValidationError("JPEG signature is invalid")
    if value.media_type == MEDIA_PNG and not content.startswith(b"\x89PNG\r\n\x1a\n"):
        raise EvidenceAnalysisValidationError("PNG signature is invalid")
    if value.media_type == MEDIA_XLSX and not content.startswith(b"PK\x03\x04"):
        raise EvidenceAnalysisValidationError("XLSX signature is invalid")
    if value.media_type == MEDIA_XLS and not content.startswith(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    ):
        raise EvidenceAnalysisValidationError("XLS signature is invalid")
    if value.media_type == MEDIA_TEXT:
        try:
            decoded = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise EvidenceAnalysisValidationError("text artifact is not UTF-8") from exc
        if "\x00" in decoded:
            raise EvidenceAnalysisValidationError("text artifact contains a NUL character")
    return _bytes_sha256(content), size


def _validate_artifact_authority(
    value: object,
    *,
    tenant_sha256: str,
    artifact: EvidenceArtifact,
    content_sha256: str,
    byte_length: int,
    expected_authority_sha256: str,
    now: float,
) -> EvidenceArtifactAuthority:
    if type(value) is not EvidenceArtifactAuthority:
        raise EvidenceAnalysisConfigError("artifact source authority is unavailable")
    authority = value
    for field_value, label in (
        (authority.tenant_sha256, "artifact tenant_sha256"),
        (authority.content_sha256, "artifact content_sha256"),
        (authority.authority_sha256, "artifact authority_sha256"),
    ):
        _digest(field_value, label)
    if (
        not _same(authority.tenant_sha256, tenant_sha256)
        or authority.artifact_id != artifact.artifact_id
        or authority.media_type != artifact.media_type
        or not _same(authority.content_sha256, content_sha256)
        or authority.byte_length != byte_length
        or authority.source_ref != artifact.source_ref
        or authority.source_revision != artifact.source_revision
        or authority.acquired_at != float(artifact.acquired_at)
        or authority.revoked is not False
        or _timestamp(authority.valid_until, "artifact authority valid_until") <= now
        or not _same(authority.authority_sha256, artifact_authority_sha256(authority))
        or not _same(authority.authority_sha256, expected_authority_sha256)
    ):
        raise EvidenceAnalysisConflict("artifact source authority is stale, revoked, or misbound")
    return authority


def _validate_criterion(value: object) -> EvidenceCriterion:
    if type(value) is not EvidenceCriterion:
        raise EvidenceAnalysisValidationError("criterion contract is invalid")
    criterion = value
    for item, label in (
        (criterion.criterion_id, "criterion_id"),
        (criterion.control_ref, "control_ref"),
        (criterion.legal_basis_ref, "legal_basis_ref"),
        (criterion.stakeholder_requirement_ref, "stakeholder_requirement_ref"),
    ):
        _ref(item, label)
    for item, label in (
        (criterion.expected_fact_code, "expected_fact_code"),
        (criterion.gap_code, "gap_code"),
        (criterion.remediation_code, "remediation_code"),
    ):
        _evidence_code(item, label)
    for item, label in (
        (criterion.revision, "criterion revision"),
        (criterion.control_revision, "control revision"),
        (criterion.legal_basis_revision, "legal-basis revision"),
        (criterion.stakeholder_requirement_revision, "stakeholder requirement revision"),
    ):
        _integer(item, label, 1, 2_147_483_647)
    _integer(criterion.weight_bps, "criterion weight_bps", 1, 10_000)
    for item, label in (
        (criterion.control_sha256, "control_sha256"),
        (criterion.legal_basis_sha256, "legal_basis_sha256"),
        (criterion.stakeholder_requirement_sha256, "stakeholder_requirement_sha256"),
        (criterion.criterion_sha256, "criterion_sha256"),
    ):
        _digest(item, label)
    if not _same(criterion.criterion_sha256, criterion_sha256(criterion)):
        raise EvidenceAnalysisValidationError("criterion digest is invalid")
    return criterion


def _validate_criteria_authority(
    value: object,
    *,
    tenant_sha256: str,
    criteria_set_id: str,
    expected_revision: int,
    expected_authority_sha256: str,
    now: float,
    require_active: bool = True,
) -> EvidenceCriteriaAuthority:
    if type(value) is not EvidenceCriteriaAuthority:
        raise EvidenceAnalysisConfigError("criteria authority is unavailable")
    authority = value
    _digest(authority.tenant_sha256, "criteria tenant_sha256")
    _ref(authority.criteria_set_id, "criteria_set_id")
    _integer(authority.revision, "criteria revision", 1, 2_147_483_647)
    _digest(authority.authority_sha256, "criteria authority_sha256")
    if type(authority.criteria) is not tuple or not 1 <= len(authority.criteria) <= _MAX_CRITERIA:
        raise EvidenceAnalysisValidationError("criteria count is outside its bound")
    criteria = tuple(_validate_criterion(item) for item in authority.criteria)
    identifiers = tuple(item.criterion_id for item in criteria)
    if identifiers != tuple(sorted(identifiers)) or len(identifiers) != len(set(identifiers)):
        raise EvidenceAnalysisValidationError("criteria must be unique and sorted")
    if sum(item.weight_bps for item in criteria) != 10_000:
        raise EvidenceAnalysisValidationError("criteria weights must total 10000 basis points")
    authority_valid_until = _timestamp(authority.valid_until, "criteria valid_until")
    active_invalid = require_active and authority_valid_until <= now
    if (
        not _same(authority.tenant_sha256, tenant_sha256)
        or authority.criteria_set_id != _ref(criteria_set_id, "criteria_set_id")
        or authority.revision != expected_revision
        or not _same(authority.authority_sha256, expected_authority_sha256)
        or not _same(authority.authority_sha256, criteria_authority_sha256(authority))
        or authority.revoked is not False
        or active_invalid
    ):
        raise EvidenceAnalysisConflict("criteria authority is stale, revoked, or misbound")
    return authority


def _validate_adapter_authority(
    value: object,
    *,
    stage: str,
    now: float,
    require_active: bool = True,
) -> EvidenceAdapterAuthority:
    if type(value) is not EvidenceAdapterAuthority:
        raise EvidenceAnalysisConfigError(f"{stage} adapter authority is unavailable")
    authority = value
    _ref(authority.adapter_id, "adapter_id")
    _integer(authority.revision, "adapter revision", 1, 2_147_483_647)
    for item, label in (
        (authority.implementation_sha256, "adapter implementation_sha256"),
        (authority.configuration_sha256, "adapter configuration_sha256"),
        (authority.authority_sha256, "adapter authority_sha256"),
    ):
        _digest(item, label)
    authority_valid_until = _timestamp(authority.valid_until, "adapter valid_until")
    active_invalid = require_active and authority_valid_until <= now
    if (
        authority.stage != stage
        or authority.deterministic is not True
        or authority.network_access is not False
        or authority.untrusted_content_mode != "data_only"
        or authority.legal_conclusion_enabled is not False
        or authority.revoked is not False
        or active_invalid
        or not _same(authority.authority_sha256, adapter_authority_sha256(authority))
    ):
        raise EvidenceAnalysisConfigError(f"{stage} adapter authority is not trusted")
    return authority


def _artifact_record(
    artifact: EvidenceArtifact,
    authority: EvidenceArtifactAuthority,
) -> EvidenceArtifactRecord:
    body = {
        "schema": ARTIFACT_RECORD_SCHEMA,
        "artifact_id": artifact.artifact_id,
        "media_type": artifact.media_type,
        "content_sha256": authority.content_sha256,
        "byte_length": authority.byte_length,
        "source_ref": artifact.source_ref,
        "source_revision": artifact.source_revision,
        "acquired_at": float(artifact.acquired_at),
        "artifact_authority_sha256": authority.authority_sha256,
    }
    return EvidenceArtifactRecord(
        artifact_id=artifact.artifact_id,
        media_type=artifact.media_type,
        content_sha256=authority.content_sha256,
        byte_length=authority.byte_length,
        source_ref=artifact.source_ref,
        source_revision=artifact.source_revision,
        acquired_at=float(artifact.acquired_at),
        artifact_authority_sha256=authority.authority_sha256,
        descriptor_sha256=_sha256(body),
    )


def _extraction_request_sha256(
    artifact: EvidenceArtifactRecord,
    criteria: EvidenceCriteriaAuthority,
    adapter: EvidenceAdapterAuthority,
) -> str:
    return _sha256(
        {
            "schema": EXTRACTION_REQUEST_SCHEMA,
            "artifact_descriptor_sha256": artifact.descriptor_sha256,
            "criteria_authority_sha256": criteria.authority_sha256,
            "adapter_authority_sha256": adapter.authority_sha256,
            "untrusted_content": True,
            "instruction_mode": "data_only",
        }
    )


_EVIDENCE_PDF_SLOTS = threading.BoundedSemaphore(2)


def _isolated_evidence_pdf_text(content: bytes, *, maximum_characters: int) -> str:
    """Child-process entry point for bounded evidence PDF extraction."""
    return BoundedLocalExtractionAdapter(
        maximum_characters=maximum_characters,
    )._pdf_text_in_process(content)


class BoundedLocalExtractionAdapter:
    """Offline bounded parser with exact-code matching and no raw-text output.

    ``pypdf``, ``openpyxl``, Pillow, and optional ``pytesseract`` are imported
    lazily. Missing dependencies fail closed. XLSX formulas, macros, external
    links, encrypted ZIP members, excessive expansion, and legacy XLS parsing
    are refused rather than guessed. Facts are emitted only for whole-line
    ``LIGHTWORK_EVIDENCE_FACT:<criteria-code>`` markers; arbitrary prose,
    prompts, negations, and incidental mentions do not become findings.
    """

    def __init__(self, *, enable_ocr: bool = False, maximum_characters: int = 250_000) -> None:
        if type(enable_ocr) is not bool:
            raise EvidenceAnalysisValidationError("enable_ocr must be boolean")
        self.enable_ocr = enable_ocr
        self.maximum_characters = _integer(
            maximum_characters,
            "maximum_characters",
            1_000,
            1_000_000,
        )

    def authority(self, *, valid_until: float) -> EvidenceAdapterAuthority:
        raw = EvidenceAdapterAuthority(
            stage="extraction",
            adapter_id=_LOCAL_ADAPTER_ID,
            revision=_LOCAL_ADAPTER_REVISION,
            implementation_sha256=_implementation_sha256(type(self)),
            configuration_sha256=_sha256(
                {
                    "schema": "lightwork.ai-evidence.local-extraction-config.v1",
                    "enable_ocr": self.enable_ocr,
                    "maximum_characters": self.maximum_characters,
                    "parser_versions": {
                        "openpyxl": _distribution_version("openpyxl"),
                        "pillow": _distribution_version("Pillow"),
                        "pypdf": _distribution_version("pypdf"),
                        "pytesseract": _distribution_version("pytesseract"),
                    },
                }
            ),
            deterministic=True,
            network_access=False,
            untrusted_content_mode="data_only",
            legal_conclusion_enabled=False,
            valid_until=_timestamp(valid_until, "adapter valid_until"),
            revoked=False,
            authority_sha256=_ZERO_DIGEST,
        )
        return replace(raw, authority_sha256=adapter_authority_sha256(raw))

    def _bounded(self, text: str) -> str:
        if len(text) > self.maximum_characters:
            raise EvidenceAnalysisValidationError("extracted text exceeds its character bound")
        return text

    def _pdf_text(self, content: bytes) -> str:
        from .parser_isolation import parse_isolated

        if not _EVIDENCE_PDF_SLOTS.acquire(timeout=0.25):
            raise EvidenceAnalysisConfigError("PDF extraction is busy; retry later")
        try:
            try:
                result = parse_isolated(
                    "evidence_pdf_text", content, timeout=30.0,
                    maximum_characters=self.maximum_characters,
                )
            except (RuntimeError, ValueError, OSError) as exc:
                raise EvidenceAnalysisValidationError("PDF extraction failed closed") from exc
        finally:
            _EVIDENCE_PDF_SLOTS.release()
        if not isinstance(result, str):
            raise EvidenceAnalysisValidationError("PDF extraction returned an invalid result")
        return self._bounded(result)

    def _pdf_text_in_process(self, content: bytes) -> str:
        if any(token in content for token in (b"/JavaScript", b"/EmbeddedFiles", b"/Launch")):
            raise EvidenceAnalysisValidationError("active or embedded PDF content is unsupported")
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise EvidenceAnalysisConfigError("pypdf is required for local PDF extraction") from exc
        try:
            reader = PdfReader(BytesIO(content), strict=True)
            if reader.is_encrypted or len(reader.pages) > 200:
                raise EvidenceAnalysisValidationError("encrypted or oversized PDF is unsupported")
            fragments: list[str] = []
            extracted_characters = 0
            for page in reader.pages:
                rendered = page.extract_text() or ""
                extracted_characters += len(rendered)
                if extracted_characters > self.maximum_characters:
                    raise EvidenceAnalysisValidationError(
                        "extracted text exceeds its character bound"
                    )
                fragments.append(rendered)
            output = "\n".join(fragments)
        except EvidenceAnalysisError:
            raise
        except Exception as exc:
            raise EvidenceAnalysisValidationError("PDF extraction failed closed") from exc
        return self._bounded(output)

    def _xlsx_text(self, content: bytes) -> str:
        try:
            with zipfile.ZipFile(BytesIO(content)) as archive:
                infos = archive.infolist()
                if len(infos) > 10_000 or sum(item.file_size for item in infos) > 64 * 1024 * 1024:
                    raise EvidenceAnalysisValidationError("XLSX expansion exceeds its bound")
                names = {item.filename.lower() for item in infos}
                if any(item.flag_bits & 0x1 for item in infos):
                    raise EvidenceAnalysisValidationError("encrypted XLSX members are unsupported")
                if any("vbaproject.bin" in name or "externallinks/" in name for name in names):
                    raise EvidenceAnalysisValidationError(
                        "XLSX macros and external links are unsupported"
                    )
        except EvidenceAnalysisError:
            raise
        except (OSError, zipfile.BadZipFile) as exc:
            raise EvidenceAnalysisValidationError("XLSX container is invalid") from exc
        try:
            from openpyxl import load_workbook
        except ImportError as exc:
            raise EvidenceAnalysisConfigError(
                "openpyxl is required for local XLSX extraction"
            ) from exc
        try:
            workbook = load_workbook(
                BytesIO(content),
                read_only=True,
                data_only=False,
                keep_links=False,
            )
            fragments: list[str] = []
            cells = 0
            extracted_characters = 0
            try:
                if len(workbook.worksheets) > 200 or getattr(workbook, "_external_links", []):
                    raise EvidenceAnalysisValidationError("XLSX workbook exceeds safe bounds")
                for sheet in workbook.worksheets:
                    for row in sheet.iter_rows():
                        for cell in row:
                            if cell.value is None:
                                continue
                            cells += 1
                            if cells > 200_000:
                                raise EvidenceAnalysisValidationError(
                                    "XLSX cell count exceeds its bound"
                                )
                            if cell.data_type == "f" or (
                                isinstance(cell.value, str) and cell.value.startswith("=")
                            ):
                                raise EvidenceAnalysisValidationError(
                                    "XLSX formulas are unsupported"
                                )
                            rendered = str(cell.value)
                            extracted_characters += len(rendered)
                            if extracted_characters > self.maximum_characters:
                                raise EvidenceAnalysisValidationError(
                                    "extracted text exceeds its character bound"
                                )
                            fragments.append(rendered)
            finally:
                workbook.close()
        except EvidenceAnalysisError:
            raise
        except Exception as exc:
            raise EvidenceAnalysisValidationError("XLSX extraction failed closed") from exc
        return self._bounded("\n".join(fragments))

    def _image_text(self, content: bytes) -> str:
        try:
            from PIL import Image
        except ImportError as exc:
            raise EvidenceAnalysisConfigError(
                "Pillow is required for local image extraction"
            ) from exc
        try:
            with Image.open(BytesIO(content)) as image:
                width, height = image.size
                if width <= 0 or height <= 0 or width * height > 40_000_000:
                    raise EvidenceAnalysisValidationError("image dimensions exceed their bound")
                fragments = [str(image.format or ""), str(width), str(height)]
                fragments.extend(
                    str(value)
                    for value in image.info.values()
                    if isinstance(value, (str, int, float, bool))
                )
                try:
                    fragments.extend(str(value) for value in image.getexif().values())
                except (AttributeError, TypeError, ValueError):
                    pass
                if self.enable_ocr:
                    try:
                        import pytesseract
                    except ImportError as exc:
                        raise EvidenceAnalysisConfigError(
                            "pytesseract is required when local OCR is enabled"
                        ) from exc
                    try:
                        fragments.append(pytesseract.image_to_string(image))
                    except Exception as exc:
                        raise EvidenceAnalysisConfigError("local OCR is unavailable") from exc
        except EvidenceAnalysisError:
            raise
        except Exception as exc:
            raise EvidenceAnalysisValidationError("image extraction failed closed") from exc
        return self._bounded("\n".join(fragments))

    def _extract_text(self, artifact: EvidenceArtifact) -> str:
        if artifact.media_type == MEDIA_TEXT:
            return self._bounded(artifact.content.decode("utf-8", errors="strict"))
        if artifact.media_type == MEDIA_PDF:
            return self._pdf_text(artifact.content)
        if artifact.media_type == MEDIA_XLSX:
            return self._xlsx_text(artifact.content)
        if artifact.media_type == MEDIA_XLS:
            raise EvidenceAnalysisConfigError("legacy XLS needs an injected safe parser")
        if artifact.media_type in {MEDIA_JPEG, MEDIA_PNG}:
            return self._image_text(artifact.content)
        raise EvidenceAnalysisValidationError("artifact media type is unsupported")

    def __call__(self, request: EvidenceExtractionRequest) -> EvidenceExtractionOutput:
        if (
            type(request) is not EvidenceExtractionRequest
            or request.schema != EXTRACTION_REQUEST_SCHEMA
            or request.untrusted_content is not True
            or request.instruction_mode != "data_only"
        ):
            raise EvidenceAnalysisValidationError("extraction request contract is invalid")
        _validate_artifact(request.artifact)
        text = self._extract_text(request.artifact)
        facts: list[ExtractedEvidenceFact] = []
        for criterion in request.criteria_authority.criteria:
            code = criterion.expected_fact_code
            marker = f"LIGHTWORK_EVIDENCE_FACT:{code}"
            match = re.search(
                rf"(?m)^{re.escape(marker)}[ \t]*$",
                text,
            )
            if match is None:
                continue
            raw = ExtractedEvidenceFact(
                fact_id=f"fact-{criterion.criterion_id}",
                fact_code=code,
                locator_sha256=_sha256(
                    {
                        "artifact_descriptor_sha256": request.artifact_record.descriptor_sha256,
                        "media_type": request.artifact.media_type,
                        "offset": match.start(),
                    }
                ),
                value_sha256=_sha256(
                    {
                        "artifact_sha256": request.artifact_record.content_sha256,
                        "fact_code": code,
                        "offset": match.start(),
                    }
                ),
                confidence_bps=10_000,
                fact_sha256=_ZERO_DIGEST,
            )
            facts.append(replace(raw, fact_sha256=fact_sha256(raw)))
        output = EvidenceExtractionOutput(
            schema=EXTRACTION_OUTPUT_SCHEMA,
            request_sha256=request.request_sha256,
            artifact_descriptor_sha256=request.artifact_record.descriptor_sha256,
            criteria_authority_sha256=request.criteria_authority.authority_sha256,
            adapter_authority_sha256=request.adapter_authority_sha256,
            deterministic=True,
            facts=tuple(facts),
            output_sha256=_ZERO_DIGEST,
        )
        return replace(output, output_sha256=extraction_output_sha256(output))


def _validate_artifact_record(value: EvidenceArtifactRecord) -> None:
    if type(value) is not EvidenceArtifactRecord:
        raise EvidenceAnalysisIntegrityError("artifact descriptor contract is invalid")
    _ref(value.artifact_id, "artifact_id")
    _ref(value.source_ref, "source_ref")
    if value.media_type not in SUPPORTED_MEDIA_TYPES:
        raise EvidenceAnalysisIntegrityError("stored artifact media type is unsupported")
    for item, label in (
        (value.content_sha256, "content_sha256"),
        (value.artifact_authority_sha256, "artifact_authority_sha256"),
        (value.descriptor_sha256, "descriptor_sha256"),
    ):
        _digest(item, label)
    _integer(value.byte_length, "artifact byte_length", 1, _MEDIA_LIMITS[value.media_type])
    _integer(value.source_revision, "source_revision", 1, 2_147_483_647)
    _timestamp(value.acquired_at, "acquired_at")
    body = asdict(value)
    supplied = body.pop("descriptor_sha256")
    body["schema"] = ARTIFACT_RECORD_SCHEMA
    if not _same(supplied, _sha256(body)):
        raise EvidenceAnalysisIntegrityError("artifact descriptor digest is invalid")


def _validate_extraction_output(
    value: object,
    *,
    request: EvidenceExtractionRequest,
) -> EvidenceExtractionOutput:
    if type(value) is not EvidenceExtractionOutput:
        raise EvidenceAnalysisIntegrityError("extraction adapter returned an invalid contract")
    output = value
    if (
        output.schema != EXTRACTION_OUTPUT_SCHEMA
        or output.request_sha256 != request.request_sha256
        or output.artifact_descriptor_sha256 != request.artifact_record.descriptor_sha256
        or output.criteria_authority_sha256 != request.criteria_authority.authority_sha256
        or output.adapter_authority_sha256 != request.adapter_authority_sha256
        or output.deterministic is not True
        or type(output.facts) is not tuple
        or len(output.facts) > _MAX_FACTS
    ):
        raise EvidenceAnalysisIntegrityError("extraction adapter output is misbound")
    expected_codes = {item.expected_fact_code for item in request.criteria_authority.criteria}
    identifiers: set[str] = set()
    for fact in output.facts:
        if type(fact) is not ExtractedEvidenceFact:
            raise EvidenceAnalysisIntegrityError("extracted fact contract is invalid")
        _ref(fact.fact_id, "fact_id")
        _ref(fact.fact_code, "fact_code")
        _digest(fact.locator_sha256, "fact locator_sha256")
        _digest(fact.value_sha256, "fact value_sha256")
        _digest(fact.fact_sha256, "fact_sha256")
        _integer(fact.confidence_bps, "fact confidence_bps", 0, 10_000)
        if (
            fact.fact_id in identifiers
            or fact.fact_code not in expected_codes
            or not _same(fact.fact_sha256, fact_sha256(fact))
        ):
            raise EvidenceAnalysisIntegrityError("extracted fact is forged or outside criteria")
        identifiers.add(fact.fact_id)
    _digest(output.output_sha256, "extraction output_sha256")
    if not _same(output.output_sha256, extraction_output_sha256(output)):
        raise EvidenceAnalysisIntegrityError("extraction output digest is invalid")
    return output


def _analysis_request_sha256(
    artifact: EvidenceArtifactRecord,
    criteria: EvidenceCriteriaAuthority,
    extraction: EvidenceExtractionOutput,
    adapter: EvidenceAdapterAuthority,
) -> str:
    return _sha256(
        {
            "schema": ANALYSIS_REQUEST_SCHEMA,
            "artifact_descriptor_sha256": artifact.descriptor_sha256,
            "criteria_authority_sha256": criteria.authority_sha256,
            "extraction_output_sha256": extraction.output_sha256,
            "adapter_authority_sha256": adapter.authority_sha256,
        }
    )


class DeterministicCriteriaAnalysisAdapter:
    """Closed baseline analyzer: direct matching facts support, absence gaps.

    It deliberately performs no semantic inference and cannot issue partial or
    legal/compliance conclusions. Richer deterministic analyzers remain an
    injected extension seam under the same output contract and human gate.
    """

    def authority(self, *, valid_until: float) -> EvidenceAdapterAuthority:
        raw = EvidenceAdapterAuthority(
            stage="analysis",
            adapter_id="lightwork-criteria-match",
            revision=1,
            implementation_sha256=_implementation_sha256(type(self)),
            configuration_sha256=_sha256(
                {"schema": "lightwork.ai-evidence.criteria-analysis-config.v1"}
            ),
            deterministic=True,
            network_access=False,
            untrusted_content_mode="data_only",
            legal_conclusion_enabled=False,
            valid_until=_timestamp(valid_until, "adapter valid_until"),
            revoked=False,
            authority_sha256=_ZERO_DIGEST,
        )
        return replace(raw, authority_sha256=adapter_authority_sha256(raw))

    def __call__(self, request: EvidenceAnalysisRequest) -> EvidenceAnalysisAdapterOutput:
        if (
            type(request) is not EvidenceAnalysisRequest
            or request.schema != ANALYSIS_REQUEST_SCHEMA
        ):
            raise EvidenceAnalysisValidationError("analysis request contract is invalid")
        facts_by_code: dict[str, list[ExtractedEvidenceFact]] = {}
        for fact in request.extraction.facts:
            facts_by_code.setdefault(fact.fact_code, []).append(fact)
        assessments: list[CriterionEvidenceAssessment] = []
        for criterion in request.criteria_authority.criteria:
            facts = facts_by_code.get(criterion.expected_fact_code, [])
            disposition = "evidence_supported" if facts else "evidence_missing"
            confidence = min((item.confidence_bps for item in facts), default=0)
            raw = CriterionEvidenceAssessment(
                criterion_id=criterion.criterion_id,
                criterion_sha256=criterion.criterion_sha256,
                disposition=disposition,
                fact_ids=tuple(sorted(item.fact_id for item in facts)),
                confidence_bps=confidence,
                rationale_code=_RATIONALE_BY_DISPOSITION[disposition],
                assessment_sha256=_ZERO_DIGEST,
            )
            assessments.append(replace(raw, assessment_sha256=assessment_sha256(raw)))
        output = EvidenceAnalysisAdapterOutput(
            schema=ANALYSIS_OUTPUT_SCHEMA,
            request_sha256=request.request_sha256,
            artifact_descriptor_sha256=request.artifact_record.descriptor_sha256,
            criteria_authority_sha256=request.criteria_authority.authority_sha256,
            extraction_output_sha256=request.extraction.output_sha256,
            adapter_authority_sha256=request.adapter_authority_sha256,
            deterministic=True,
            assessments=tuple(assessments),
            output_sha256=_ZERO_DIGEST,
        )
        return replace(output, output_sha256=analysis_output_sha256(output))


def _validate_analysis_output(
    value: object,
    *,
    request: EvidenceAnalysisRequest,
) -> EvidenceAnalysisAdapterOutput:
    if type(value) is not EvidenceAnalysisAdapterOutput:
        raise EvidenceAnalysisIntegrityError("analysis adapter returned an invalid contract")
    output = value
    if (
        output.schema != ANALYSIS_OUTPUT_SCHEMA
        or output.request_sha256 != request.request_sha256
        or output.artifact_descriptor_sha256 != request.artifact_record.descriptor_sha256
        or output.criteria_authority_sha256 != request.criteria_authority.authority_sha256
        or output.extraction_output_sha256 != request.extraction.output_sha256
        or output.adapter_authority_sha256 != request.adapter_authority_sha256
        or output.deterministic is not True
        or type(output.assessments) is not tuple
        or len(output.assessments) != len(request.criteria_authority.criteria)
    ):
        raise EvidenceAnalysisIntegrityError("analysis adapter output is misbound")
    criteria_by_id = {
        criterion.criterion_id: criterion for criterion in request.criteria_authority.criteria
    }
    facts_by_id = {fact.fact_id: fact for fact in request.extraction.facts}
    seen: set[str] = set()
    for assessment in output.assessments:
        if type(assessment) is not CriterionEvidenceAssessment:
            raise EvidenceAnalysisIntegrityError("criterion assessment contract is invalid")
        criterion = criteria_by_id.get(assessment.criterion_id)
        if criterion is None or assessment.criterion_id in seen:
            raise EvidenceAnalysisIntegrityError("criterion assessment coverage is invalid")
        seen.add(assessment.criterion_id)
        if (
            not _same(assessment.criterion_sha256, criterion.criterion_sha256)
            or assessment.disposition not in _DISPOSITIONS
            or assessment.rationale_code != _RATIONALE_BY_DISPOSITION[assessment.disposition]
            or type(assessment.fact_ids) is not tuple
            or tuple(sorted(assessment.fact_ids)) != assessment.fact_ids
            or len(assessment.fact_ids) != len(set(assessment.fact_ids))
        ):
            raise EvidenceAnalysisIntegrityError("criterion assessment is invalid")
        _integer(assessment.confidence_bps, "assessment confidence_bps", 0, 10_000)
        if assessment.disposition in {"evidence_supported", "evidence_partial"}:
            if not assessment.fact_ids or assessment.confidence_bps <= 0:
                raise EvidenceAnalysisIntegrityError("positive assessment lacks evidence")
            if any(
                fact_id not in facts_by_id
                or facts_by_id[fact_id].fact_code != criterion.expected_fact_code
                for fact_id in assessment.fact_ids
            ):
                raise EvidenceAnalysisIntegrityError("assessment cites misbound facts")
        elif assessment.fact_ids or assessment.confidence_bps != 0:
            raise EvidenceAnalysisIntegrityError("negative assessment cannot cite facts")
        _digest(assessment.assessment_sha256, "assessment_sha256")
        if not _same(assessment.assessment_sha256, assessment_sha256(assessment)):
            raise EvidenceAnalysisIntegrityError("assessment digest is invalid")
    if set(criteria_by_id) != seen:
        raise EvidenceAnalysisIntegrityError("analysis omitted required criteria")
    _digest(output.output_sha256, "analysis output_sha256")
    if not _same(output.output_sha256, analysis_output_sha256(output)):
        raise EvidenceAnalysisIntegrityError("analysis output digest is invalid")
    return output


def _summary(
    criteria: EvidenceCriteriaAuthority,
    extraction: EvidenceExtractionOutput,
    analysis: EvidenceAnalysisAdapterOutput,
) -> EvidenceSummary:
    counts = dict.fromkeys(_DISPOSITIONS, 0)
    for assessment in analysis.assessments:
        counts[assessment.disposition] += 1
    body = {
        "schema": SUMMARY_SCHEMA,
        "total_criteria": len(criteria.criteria),
        "evidence_supported": counts["evidence_supported"],
        "evidence_partial": counts["evidence_partial"],
        "evidence_missing": counts["evidence_missing"],
        "indeterminate": counts["indeterminate"],
        "extracted_fact_count": len(extraction.facts),
    }
    return EvidenceSummary(
        **{key: value for key, value in body.items() if key != "schema"},
        summary_sha256=_sha256(body),
    )


def _justification(
    criteria: EvidenceCriteriaAuthority,
    analysis: EvidenceAnalysisAdapterOutput,
) -> JustificationScore:
    by_id = {item.criterion_id: item for item in analysis.assessments}
    components: list[JustificationComponent] = []
    for criterion in criteria.criteria:
        assessment = by_id[criterion.criterion_id]
        coverage = _COVERAGE_BPS[assessment.disposition]
        provenance = 10_000 if assessment.fact_ids else 0
        component_score = coverage * assessment.confidence_bps * provenance // 100_000_000
        raw = JustificationComponent(
            criterion_id=criterion.criterion_id,
            weight_bps=criterion.weight_bps,
            coverage_bps=coverage,
            confidence_bps=assessment.confidence_bps,
            provenance_bps=provenance,
            component_score_bps=component_score,
            component_sha256=_ZERO_DIGEST,
        )
        body = _without_digest(raw, "component_sha256", JUSTIFICATION_SCHEMA)
        components.append(replace(raw, component_sha256=_sha256(body)))
    score = sum(item.weight_bps * item.component_score_bps for item in components) // 10_000
    body = {
        "schema": JUSTIFICATION_SCHEMA,
        "methodology": "weighted_coverage_x_confidence_x_provenance_bps_v1",
        "components": [asdict(item) for item in components],
        "score_bps": score,
        "maximum_bps": 10_000,
    }
    return JustificationScore(
        methodology=body["methodology"],
        components=tuple(components),
        score_bps=score,
        maximum_bps=10_000,
        score_sha256=_sha256(body),
    )


def _gaps(
    criteria: EvidenceCriteriaAuthority,
    analysis: EvidenceAnalysisAdapterOutput,
) -> tuple[EvidenceGapSuggestion, ...]:
    criteria_by_id = {item.criterion_id: item for item in criteria.criteria}
    output: list[EvidenceGapSuggestion] = []
    for assessment in analysis.assessments:
        if assessment.disposition == "evidence_supported":
            continue
        criterion = criteria_by_id[assessment.criterion_id]
        body = {
            "schema": GAP_SCHEMA,
            "criterion_id": criterion.criterion_id,
            "disposition": assessment.disposition,
            "gap_code": criterion.gap_code,
            "remediation_code": criterion.remediation_code,
        }
        output.append(
            EvidenceGapSuggestion(
                criterion_id=criterion.criterion_id,
                disposition=assessment.disposition,
                gap_code=criterion.gap_code,
                remediation_code=criterion.remediation_code,
                suggestion_sha256=_sha256(body),
            )
        )
    return tuple(output)


def _provenance_link(
    sequence: int,
    stage: str,
    input_sha256: str,
    output_sha256: str,
    previous_link_sha256: str,
) -> EvidenceProvenanceLink:
    body = {
        "schema": PROVENANCE_SCHEMA,
        "sequence": sequence,
        "stage": stage,
        "input_sha256": input_sha256,
        "output_sha256": output_sha256,
        "previous_link_sha256": previous_link_sha256,
    }
    return EvidenceProvenanceLink(
        **{key: value for key, value in body.items() if key != "schema"}, link_sha256=_sha256(body)
    )


def _provenance(
    artifact_authority: EvidenceArtifactAuthority,
    artifact: EvidenceArtifactRecord,
    extraction_request: EvidenceExtractionRequest,
    extraction: EvidenceExtractionOutput,
    analysis_request: EvidenceAnalysisRequest,
    analysis: EvidenceAnalysisAdapterOutput,
    summary: EvidenceSummary,
    score: JustificationScore,
    gaps: tuple[EvidenceGapSuggestion, ...],
) -> tuple[EvidenceProvenanceLink, ...]:
    scoring_output = _sha256(
        {
            "summary_sha256": summary.summary_sha256,
            "score_sha256": score.score_sha256,
            "gap_sha256": [item.suggestion_sha256 for item in gaps],
        }
    )
    links = [
        _provenance_link(
            1,
            "source_authority",
            artifact_authority.authority_sha256,
            artifact.descriptor_sha256,
            _ZERO_DIGEST,
        )
    ]
    links.append(
        _provenance_link(
            2,
            "deterministic_extraction",
            extraction_request.request_sha256,
            extraction.output_sha256,
            links[-1].link_sha256,
        )
    )
    links.append(
        _provenance_link(
            3,
            "deterministic_analysis",
            analysis_request.request_sha256,
            analysis.output_sha256,
            links[-1].link_sha256,
        )
    )
    links.append(
        _provenance_link(
            4,
            "core_scoring",
            analysis.output_sha256,
            scoring_output,
            links[-1].link_sha256,
        )
    )
    return tuple(links)


def _record_payload(value: EvidenceAnalysisRecord) -> dict[str, Any]:
    payload = asdict(value)
    payload.pop("integrity_sha256")
    payload["schema"] = RECORD_SCHEMA
    return payload


def _record_integrity_sha256(value: EvidenceAnalysisRecord) -> str:
    return _sha256(_record_payload(value))


def _record_json(value: EvidenceAnalysisRecord) -> str:
    payload = asdict(value)
    payload["schema"] = RECORD_SCHEMA
    return _canonical(payload).decode("ascii")


def _construct(model: type, value: object, label: str):
    try:
        return model(**_exact_mapping(value, model, label))
    except EvidenceAnalysisIntegrityError:
        raise
    except (TypeError, ValueError) as exc:
        raise EvidenceAnalysisIntegrityError(f"stored {label} is invalid") from exc


def _record_from_payload(payload: object) -> EvidenceAnalysisRecord:
    if not isinstance(payload, Mapping) or payload.get("schema") != RECORD_SCHEMA:
        raise EvidenceAnalysisIntegrityError("stored evidence analysis schema is invalid")
    body = dict(payload)
    body.pop("schema")
    expected = {field.name for field in fields(EvidenceAnalysisRecord)}
    if set(body) != expected:
        raise EvidenceAnalysisIntegrityError("stored evidence analysis shape is invalid")
    artifact_authority = _construct(
        EvidenceArtifactAuthority,
        body["artifact_authority"],
        "artifact authority",
    )
    artifact = _construct(EvidenceArtifactRecord, body["artifact"], "artifact descriptor")
    criteria_data = _exact_mapping(
        body["criteria_authority"],
        EvidenceCriteriaAuthority,
        "criteria authority",
    )
    if not isinstance(criteria_data["criteria"], list):
        raise EvidenceAnalysisIntegrityError("stored criteria are invalid")
    criteria_data["criteria"] = tuple(
        _construct(EvidenceCriterion, item, "criterion") for item in criteria_data["criteria"]
    )
    criteria = EvidenceCriteriaAuthority(**criteria_data)
    extraction_adapter = _construct(
        EvidenceAdapterAuthority,
        body["extraction_adapter_authority"],
        "extraction adapter authority",
    )
    analysis_adapter = _construct(
        EvidenceAdapterAuthority,
        body["analysis_adapter_authority"],
        "analysis adapter authority",
    )
    extraction_data = _exact_mapping(
        body["extraction"],
        EvidenceExtractionOutput,
        "extraction output",
    )
    if not isinstance(extraction_data["facts"], list):
        raise EvidenceAnalysisIntegrityError("stored extracted facts are invalid")
    extraction_data["facts"] = tuple(
        _construct(ExtractedEvidenceFact, item, "extracted fact")
        for item in extraction_data["facts"]
    )
    extraction = EvidenceExtractionOutput(**extraction_data)
    analysis_data = _exact_mapping(
        body["adapter_analysis"],
        EvidenceAnalysisAdapterOutput,
        "analysis adapter output",
    )
    if not isinstance(analysis_data["assessments"], list):
        raise EvidenceAnalysisIntegrityError("stored assessments are invalid")
    assessments: list[CriterionEvidenceAssessment] = []
    for item in analysis_data["assessments"]:
        item_data = _exact_mapping(item, CriterionEvidenceAssessment, "assessment")
        if not isinstance(item_data["fact_ids"], list):
            raise EvidenceAnalysisIntegrityError("stored assessment fact IDs are invalid")
        item_data["fact_ids"] = tuple(item_data["fact_ids"])
        assessments.append(CriterionEvidenceAssessment(**item_data))
    analysis_data["assessments"] = tuple(assessments)
    adapter_analysis = EvidenceAnalysisAdapterOutput(**analysis_data)
    summary = _construct(EvidenceSummary, body["summary"], "summary")
    justification_data = _exact_mapping(
        body["justification"],
        JustificationScore,
        "justification score",
    )
    if not isinstance(justification_data["components"], list):
        raise EvidenceAnalysisIntegrityError("stored justification components are invalid")
    justification_data["components"] = tuple(
        _construct(JustificationComponent, item, "justification component")
        for item in justification_data["components"]
    )
    justification = JustificationScore(**justification_data)
    if not isinstance(body["gaps"], list) or not isinstance(body["provenance"], list):
        raise EvidenceAnalysisIntegrityError("stored gaps or provenance are invalid")
    gaps = tuple(_construct(EvidenceGapSuggestion, item, "gap") for item in body["gaps"])
    provenance = tuple(
        _construct(EvidenceProvenanceLink, item, "provenance link") for item in body["provenance"]
    )
    review_authority = body["review_authority"]
    if review_authority is not None:
        review_data = _exact_mapping(
            review_authority,
            HumanReviewAuthority,
            "review authority",
        )
        if not isinstance(review_data["capabilities"], list):
            raise EvidenceAnalysisIntegrityError("stored review capabilities are invalid")
        review_data["capabilities"] = tuple(review_data["capabilities"])
        review_authority = HumanReviewAuthority(**review_data)
    revocation_authority = body["revocation_authority"]
    if revocation_authority is not None:
        revocation_data = _exact_mapping(
            revocation_authority,
            HumanReviewAuthority,
            "revocation authority",
        )
        if not isinstance(revocation_data["capabilities"], list):
            raise EvidenceAnalysisIntegrityError("stored revocation capabilities are invalid")
        revocation_data["capabilities"] = tuple(revocation_data["capabilities"])
        revocation_authority = HumanReviewAuthority(**revocation_data)
    body.update(
        {
            "artifact_authority": artifact_authority,
            "artifact": artifact,
            "criteria_authority": criteria,
            "extraction_adapter_authority": extraction_adapter,
            "analysis_adapter_authority": analysis_adapter,
            "extraction": extraction,
            "adapter_analysis": adapter_analysis,
            "summary": summary,
            "justification": justification,
            "gaps": gaps,
            "provenance": provenance,
            "review_authority": review_authority,
            "revocation_authority": revocation_authority,
        }
    )
    try:
        return EvidenceAnalysisRecord(**body)
    except (TypeError, ValueError) as exc:
        raise EvidenceAnalysisIntegrityError("stored evidence analysis is invalid") from exc


def _review_authority_structural(value: HumanReviewAuthority) -> None:
    if type(value) is not HumanReviewAuthority:
        raise EvidenceAnalysisIntegrityError("review authority contract is invalid")
    _digest(value.tenant_sha256, "review tenant_sha256")
    _digest(value.reviewer_sha256, "reviewer_sha256")
    _integer(value.revision, "review authority revision", 1, 2_147_483_647)
    _timestamp(value.valid_until, "review authority valid_until")
    _digest(value.authority_sha256, "review authority_sha256")
    if (
        type(value.capabilities) is not tuple
        or not value.capabilities
        or tuple(sorted(value.capabilities)) != value.capabilities
        or len(value.capabilities) != len(set(value.capabilities))
        or not set(value.capabilities).issubset(_REVIEW_CAPABILITIES)
        or value.revoked is not False
        or not _same(value.authority_sha256, review_authority_sha256(value))
    ):
        raise EvidenceAnalysisIntegrityError("review authority contract is invalid")


def _validate_review_state(record: EvidenceAnalysisRecord) -> None:
    if (
        record.status not in _STATUSES
        or record.human_review_required is not True
        or record.legal_or_compliance_conclusion is not False
        or record.notice != NON_CONCLUSION_NOTICE
    ):
        raise EvidenceAnalysisIntegrityError("stored review or conclusion boundary is invalid")
    if record.status == "pending_review" and any(
        value is not None
        for value in (
            record.review_decision,
            record.review_authority,
            record.reviewed_at,
            record.revocation_authority,
        )
    ):
        raise EvidenceAnalysisIntegrityError("pending evidence has unexpected review material")
    if record.status in {"review_approved", "review_rejected"}:
        if (
            record.review_decision
            != ("approve" if record.status == "review_approved" else "reject")
            or record.review_authority is None
            or record.reviewed_at is None
        ):
            raise EvidenceAnalysisIntegrityError("reviewed evidence lacks review authority")
        _review_authority_structural(record.review_authority)
    if record.status == "revoked":
        if record.review_authority is None:
            if record.review_decision is not None or record.reviewed_at is not None:
                raise EvidenceAnalysisIntegrityError("revoked evidence review state is invalid")
        else:
            _review_authority_structural(record.review_authority)
            if record.review_decision not in {"approve", "reject"} or record.reviewed_at is None:
                raise EvidenceAnalysisIntegrityError("revoked evidence review state is invalid")
    if record.status == "revoked" and (
        record.revocation_authority is None
        or record.revocation_reason_code is None
        or record.revoked_at is None
    ):
        raise EvidenceAnalysisIntegrityError("revoked evidence lacks revocation material")
    if record.revocation_authority is not None:
        _review_authority_structural(record.revocation_authority)
    if record.status != "revoked" and any(
        value is not None
        for value in (
            record.revocation_authority,
            record.revocation_reason_code,
            record.revoked_at,
        )
    ):
        raise EvidenceAnalysisIntegrityError("active evidence has revocation material")


def _validate_stored_record(record: EvidenceAnalysisRecord) -> None:
    _ref(record.analysis_id, "analysis_id")
    _digest(record.tenant_sha256, "tenant_sha256")
    if type(record.artifact_authority) is not EvidenceArtifactAuthority:
        raise EvidenceAnalysisIntegrityError("artifact authority snapshot is invalid")
    authority = record.artifact_authority
    _ref(authority.artifact_id, "artifact authority artifact_id")
    _ref(authority.source_ref, "artifact authority source_ref")
    if authority.media_type not in SUPPORTED_MEDIA_TYPES:
        raise EvidenceAnalysisIntegrityError("artifact authority media type is unsupported")
    _integer(
        authority.byte_length,
        "artifact authority byte_length",
        1,
        _MEDIA_LIMITS[authority.media_type],
    )
    _integer(
        authority.source_revision,
        "artifact authority source_revision",
        1,
        2_147_483_647,
    )
    for item, label in (
        (authority.tenant_sha256, "artifact tenant_sha256"),
        (authority.content_sha256, "artifact content_sha256"),
        (authority.authority_sha256, "artifact authority_sha256"),
    ):
        _digest(item, label)
    _timestamp(authority.acquired_at, "artifact acquired_at")
    _timestamp(authority.valid_until, "artifact authority valid_until")
    if authority.revoked is not False or not _same(
        authority.authority_sha256,
        artifact_authority_sha256(authority),
    ):
        raise EvidenceAnalysisIntegrityError("artifact authority snapshot is invalid")
    _validate_artifact_record(record.artifact)
    if (
        not _same(authority.tenant_sha256, record.tenant_sha256)
        or authority.artifact_id != record.artifact.artifact_id
        or authority.media_type != record.artifact.media_type
        or not _same(authority.content_sha256, record.artifact.content_sha256)
        or authority.byte_length != record.artifact.byte_length
        or authority.source_ref != record.artifact.source_ref
        or authority.source_revision != record.artifact.source_revision
        or authority.acquired_at != record.artifact.acquired_at
        or not _same(authority.authority_sha256, record.artifact.artifact_authority_sha256)
    ):
        raise EvidenceAnalysisIntegrityError("artifact snapshot is misbound")
    criteria = _validate_criteria_authority(
        record.criteria_authority,
        tenant_sha256=record.tenant_sha256,
        criteria_set_id=record.criteria_authority.criteria_set_id,
        expected_revision=record.criteria_authority.revision,
        expected_authority_sha256=record.criteria_authority.authority_sha256,
        now=1.0,
        require_active=False,
    )
    extraction_adapter = _validate_adapter_authority(
        record.extraction_adapter_authority,
        stage="extraction",
        now=1.0,
        require_active=False,
    )
    analysis_adapter = _validate_adapter_authority(
        record.analysis_adapter_authority,
        stage="analysis",
        now=1.0,
        require_active=False,
    )
    dummy_artifact = EvidenceArtifact(
        artifact_id=record.artifact.artifact_id,
        media_type=record.artifact.media_type,
        content=b"x",
        source_ref=record.artifact.source_ref,
        source_revision=record.artifact.source_revision,
        acquired_at=record.artifact.acquired_at,
    )
    extraction_request = EvidenceExtractionRequest(
        schema=EXTRACTION_REQUEST_SCHEMA,
        artifact=dummy_artifact,
        artifact_record=record.artifact,
        criteria_authority=criteria,
        adapter_authority_sha256=extraction_adapter.authority_sha256,
        untrusted_content=True,
        instruction_mode="data_only",
        request_sha256=_extraction_request_sha256(
            record.artifact,
            criteria,
            extraction_adapter,
        ),
    )
    extraction = _validate_extraction_output(record.extraction, request=extraction_request)
    analysis_request = EvidenceAnalysisRequest(
        schema=ANALYSIS_REQUEST_SCHEMA,
        artifact_record=record.artifact,
        criteria_authority=criteria,
        extraction=extraction,
        adapter_authority_sha256=analysis_adapter.authority_sha256,
        request_sha256=_analysis_request_sha256(
            record.artifact,
            criteria,
            extraction,
            analysis_adapter,
        ),
    )
    analysis = _validate_analysis_output(record.adapter_analysis, request=analysis_request)
    expected_summary = _summary(criteria, extraction, analysis)
    expected_justification = _justification(criteria, analysis)
    expected_gaps = _gaps(criteria, analysis)
    expected_provenance = _provenance(
        authority,
        record.artifact,
        extraction_request,
        extraction,
        analysis_request,
        analysis,
        expected_summary,
        expected_justification,
        expected_gaps,
    )
    if (
        not _same(_sha256(asdict(record.summary)), _sha256(asdict(expected_summary)))
        or not _same(
            _sha256(asdict(record.justification)),
            _sha256(asdict(expected_justification)),
        )
        or not _same(
            _sha256([asdict(item) for item in record.gaps]),
            _sha256([asdict(item) for item in expected_gaps]),
        )
        or not _same(
            _sha256([asdict(item) for item in record.provenance]),
            _sha256([asdict(item) for item in expected_provenance]),
        )
        or not _same(record.provenance_sha256, expected_provenance[-1].link_sha256)
    ):
        raise EvidenceAnalysisIntegrityError("derived evidence analysis material is invalid")
    _digest(record.submitter_sha256, "submitter_sha256")
    _validate_review_state(record)
    valid = _timestamp(record.valid_until, "valid_until")
    retained = _timestamp(record.retained_until, "retained_until")
    created = _timestamp(record.created_at, "created_at")
    updated = _timestamp(record.updated_at, "updated_at")
    if not created <= updated < retained or not created < valid <= retained:
        raise EvidenceAnalysisIntegrityError("stored evidence lifetime is invalid")
    _integer(record.revision, "record revision", 1, 2_147_483_647)
    if record.revision == 1:
        if record.previous_integrity_sha256 is not None:
            raise EvidenceAnalysisIntegrityError("initial evidence has a previous digest")
    else:
        _digest(record.previous_integrity_sha256, "previous_integrity_sha256")
    _digest(record.integrity_sha256, "integrity_sha256")
    if not _same(record.integrity_sha256, _record_integrity_sha256(record)):
        raise EvidenceAnalysisIntegrityError("stored evidence analysis failed integrity")


class EvidenceAnalysisStore:
    """Durable single-tenant authority for evidence analysis and human release."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        artifact_authority_resolver: Callable[[str, str], EvidenceArtifactAuthority],
        criteria_authority_resolver: Callable[[str, str], EvidenceCriteriaAuthority],
        review_authority_resolver: Callable[[str, str], HumanReviewAuthority],
        adapter_authority_resolver: Callable[
            [str, str, str, int],
            EvidenceAdapterAuthority,
        ],
        extraction_adapter: Callable[[EvidenceExtractionRequest], EvidenceExtractionOutput],
        analysis_adapter: Callable[
            [EvidenceAnalysisRequest],
            EvidenceAnalysisAdapterOutput,
        ],
        extraction_adapter_authority: EvidenceAdapterAuthority,
        analysis_adapter_authority: EvidenceAdapterAuthority,
        config_gate: Callable[[], None] = _disabled_gate,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        if not all(
            callable(item)
            for item in (
                artifact_authority_resolver,
                criteria_authority_resolver,
                review_authority_resolver,
                adapter_authority_resolver,
                extraction_adapter,
                analysis_adapter,
                config_gate,
                clock,
            )
        ):
            raise EvidenceAnalysisConfigError("evidence-analysis dependencies are unavailable")
        config_gate()
        now = _now(clock)
        self.path = Path(path)
        self._tenant_id = _tenant(tenant_id)
        self._tenant_sha256 = _text_sha256(self._tenant_id)
        self._artifact_resolver = artifact_authority_resolver
        self._criteria_resolver = criteria_authority_resolver
        self._review_resolver = review_authority_resolver
        self._adapter_authority_resolver = adapter_authority_resolver
        self._extraction_adapter = extraction_adapter
        self._analysis_adapter = analysis_adapter
        self._extraction_adapter_authority = _validate_adapter_authority(
            extraction_adapter_authority,
            stage="extraction",
            now=now,
        )
        self._analysis_adapter_authority = _validate_adapter_authority(
            analysis_adapter_authority,
            stage="analysis",
            now=now,
        )
        self._gate = config_gate
        self._clock = clock
        self._id_factory = id_factory or (lambda: f"EVA-{secrets.token_hex(16)}")
        self._retention = threading.local()
        ensure_private_directory(self.path.parent)
        with cross_process_lock(self.path, strict=True):
            self._initialize()

    @property
    def tenant_id(self) -> str:
        """Canonical tenant binding exposed for deployment composition checks."""

        return self._tenant_id

    def _check_gate(self) -> None:
        try:
            self._gate()
        except EvidenceAnalysisError:
            raise
        except Exception as exc:
            raise EvidenceAnalysisConfigError("evidence-analysis gate rejected access") from exc

    def _require_tenant(self, tenant_id: object) -> str:
        tenant = _tenant(tenant_id)
        if not text_equals(tenant, self._tenant_id):
            raise EvidenceAnalysisNotFound("tenant-bound evidence analysis is unavailable")
        return tenant

    def _connect(self) -> sqlite3.Connection:
        ensure_private_directory(self.path.parent)
        connection = sqlite3.connect(
            self.path,
            timeout=30.0,
            isolation_level=None,
            factory=ClosingConnection,
        )
        try:
            ensure_private_file(self.path, 0o600)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.create_function(
                "ai_evidence_retention_authorized",
                0,
                lambda: 1 if bool(getattr(self._retention, "authorized", False)) else 0,
            )
        except BaseException:
            connection.close()
            raise
        return connection

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ai_evidence_analysis_meta(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ai_evidence_analyses(
                    analysis_id TEXT PRIMARY KEY,tenant_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,revision INTEGER NOT NULL,
                    valid_until REAL NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ai_evidence_analysis_retention_idx
                    ON ai_evidence_analyses(
                        tenant_sha256,retained_until,status,analysis_id
                    );
                CREATE TABLE IF NOT EXISTS ai_evidence_analysis_history(
                    tenant_sha256 TEXT NOT NULL,analysis_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,analysis_id,revision)
                );
                CREATE TABLE IF NOT EXISTS ai_evidence_analysis_operations(
                    tenant_sha256 TEXT NOT NULL,key_sha256 TEXT NOT NULL,
                    action TEXT NOT NULL,request_sha256 TEXT NOT NULL,
                    analysis_id TEXT NOT NULL,result_integrity_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,operation_integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,key_sha256)
                );
                CREATE TRIGGER IF NOT EXISTS ai_evidence_analysis_history_no_update
                    BEFORE UPDATE ON ai_evidence_analysis_history
                    BEGIN SELECT RAISE(ABORT,'immutable AI evidence history'); END;
                CREATE TRIGGER IF NOT EXISTS ai_evidence_analysis_operation_no_update
                    BEFORE UPDATE ON ai_evidence_analysis_operations
                    BEGIN SELECT RAISE(ABORT,'immutable AI evidence idempotency'); END;
                CREATE TRIGGER IF NOT EXISTS ai_evidence_analysis_record_no_delete
                    BEFORE DELETE ON ai_evidence_analyses
                    WHEN ai_evidence_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'AI evidence retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS ai_evidence_analysis_history_no_delete
                    BEFORE DELETE ON ai_evidence_analysis_history
                    WHEN ai_evidence_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'AI evidence retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS ai_evidence_analysis_operation_no_delete
                    BEFORE DELETE ON ai_evidence_analysis_operations
                    WHEN ai_evidence_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'AI evidence retention authority required'); END;
                """
            )
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, _SCHEMA_VERSION}:
                raise EvidenceAnalysisConfigError(
                    f"unsupported AI evidence-analysis schema version {version}"
                )
            connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            connection.execute(
                "INSERT OR IGNORE INTO ai_evidence_analysis_meta(key,value) "
                "VALUES('tenant_sha256',?)",
                (self._tenant_sha256,),
            )
            row = connection.execute(
                "SELECT value FROM ai_evidence_analysis_meta WHERE key='tenant_sha256'"
            ).fetchone()
            if row is None or not _same(row["value"], self._tenant_sha256):
                raise EvidenceAnalysisIntegrityError(
                    "evidence-analysis database belongs to another tenant"
                )

    @staticmethod
    def _row_record(row: sqlite3.Row, label: str) -> EvidenceAnalysisRecord:
        try:
            raw = str(row["payload_json"])
            if not 1 <= len(raw.encode("utf-8")) <= _MAX_JSON_BYTES:
                raise ValueError("stored payload exceeds its bound")
            payload = json.loads(raw)
        except (TypeError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise EvidenceAnalysisIntegrityError(f"stored {label} is invalid") from exc
        record = _record_from_payload(payload)
        if (
            record.analysis_id != row["analysis_id"]
            or record.tenant_sha256 != row["tenant_sha256"]
            or record.revision != row["revision"]
            or not _same(record.integrity_sha256, row["integrity_sha256"])
        ):
            raise EvidenceAnalysisIntegrityError(f"stored {label} index is inconsistent")
        for field_name in ("status", "valid_until", "retained_until"):
            if field_name in row.keys() and getattr(record, field_name) != row[field_name]:
                raise EvidenceAnalysisIntegrityError(f"stored {label} index is inconsistent")
        try:
            _validate_stored_record(record)
        except EvidenceAnalysisIntegrityError:
            raise
        except EvidenceAnalysisError as exc:
            raise EvidenceAnalysisIntegrityError(
                f"stored {label} violates the evidence contract"
            ) from exc
        return record

    def _current(
        self,
        connection: sqlite3.Connection,
        analysis_id: str,
    ) -> EvidenceAnalysisRecord:
        row = connection.execute(
            "SELECT * FROM ai_evidence_analyses WHERE tenant_sha256=? AND analysis_id=?",
            (self._tenant_sha256, analysis_id),
        ).fetchone()
        if row is None:
            raise EvidenceAnalysisNotFound("evidence analysis was not found")
        return self._row_record(row, "evidence analysis")

    def _by_integrity(
        self,
        connection: sqlite3.Connection,
        analysis_id: str,
        integrity_sha256: str,
    ) -> EvidenceAnalysisRecord:
        row = connection.execute(
            "SELECT * FROM ai_evidence_analyses WHERE tenant_sha256=? AND analysis_id=? "
            "AND integrity_sha256=?",
            (self._tenant_sha256, analysis_id, integrity_sha256),
        ).fetchone()
        if row is not None:
            return self._row_record(row, "evidence analysis")
        row = connection.execute(
            "SELECT analysis_id,tenant_sha256,revision,payload_json,integrity_sha256 "
            "FROM ai_evidence_analysis_history WHERE tenant_sha256=? AND analysis_id=? "
            "AND integrity_sha256=?",
            (self._tenant_sha256, analysis_id, integrity_sha256),
        ).fetchone()
        if row is None:
            raise EvidenceAnalysisIntegrityError("idempotency result record is unavailable")
        return self._row_record(row, "evidence analysis history")

    @staticmethod
    def _operation_body(row: Mapping[str, object]) -> dict[str, object]:
        return {
            "schema": "lightwork.ai-evidence.operation.v1",
            "tenant_sha256": row["tenant_sha256"],
            "key_sha256": row["key_sha256"],
            "action": row["action"],
            "request_sha256": row["request_sha256"],
            "analysis_id": row["analysis_id"],
            "result_integrity_sha256": row["result_integrity_sha256"],
            "created_at": row["created_at"],
        }

    def _replay(
        self,
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        action: str,
        request_sha256: str,
    ) -> EvidenceAnalysisRecord | None:
        row = connection.execute(
            "SELECT * FROM ai_evidence_analysis_operations WHERE tenant_sha256=? AND key_sha256=?",
            (self._tenant_sha256, key_sha256),
        ).fetchone()
        if row is None:
            return None
        body = self._operation_body(row)
        if not _same(row["operation_integrity_sha256"], _sha256(body)):
            raise EvidenceAnalysisIntegrityError("stored idempotency operation failed integrity")
        if row["action"] != action or not _same(row["request_sha256"], request_sha256):
            raise EvidenceAnalysisConflict("idempotency key is bound to another request")
        return self._by_integrity(
            connection,
            str(row["analysis_id"]),
            str(row["result_integrity_sha256"]),
        )

    def _insert_operation(
        self,
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        action: str,
        request_sha256: str,
        record: EvidenceAnalysisRecord,
        now: float,
    ) -> None:
        body: dict[str, object] = {
            "schema": "lightwork.ai-evidence.operation.v1",
            "tenant_sha256": self._tenant_sha256,
            "key_sha256": key_sha256,
            "action": action,
            "request_sha256": request_sha256,
            "analysis_id": record.analysis_id,
            "result_integrity_sha256": record.integrity_sha256,
            "created_at": now,
        }
        connection.execute(
            "INSERT INTO ai_evidence_analysis_operations VALUES(?,?,?,?,?,?,?,?)",
            (
                self._tenant_sha256,
                key_sha256,
                action,
                request_sha256,
                record.analysis_id,
                record.integrity_sha256,
                now,
                _sha256(body),
            ),
        )

    @staticmethod
    def _insert_record(
        connection: sqlite3.Connection,
        record: EvidenceAnalysisRecord,
    ) -> None:
        connection.execute(
            "INSERT INTO ai_evidence_analyses VALUES(?,?,?,?,?,?,?,?)",
            (
                record.analysis_id,
                record.tenant_sha256,
                record.status,
                record.revision,
                record.valid_until,
                record.retained_until,
                _record_json(record),
                record.integrity_sha256,
            ),
        )

    @staticmethod
    def _archive(
        connection: sqlite3.Connection,
        record: EvidenceAnalysisRecord,
    ) -> None:
        connection.execute(
            "INSERT INTO ai_evidence_analysis_history VALUES(?,?,?,?,?)",
            (
                record.tenant_sha256,
                record.analysis_id,
                record.revision,
                _record_json(record),
                record.integrity_sha256,
            ),
        )

    @staticmethod
    def _update_record(
        connection: sqlite3.Connection,
        record: EvidenceAnalysisRecord,
    ) -> None:
        connection.execute(
            "UPDATE ai_evidence_analyses SET status=?,revision=?,valid_until=?,"
            "retained_until=?,payload_json=?,integrity_sha256=? WHERE tenant_sha256=? "
            "AND analysis_id=?",
            (
                record.status,
                record.revision,
                record.valid_until,
                record.retained_until,
                _record_json(record),
                record.integrity_sha256,
                record.tenant_sha256,
                record.analysis_id,
            ),
        )

    def _resolve_artifact_authority(
        self,
        artifact: EvidenceArtifact,
        *,
        content_sha256: str,
        byte_length: int,
        expected_authority_sha256: str,
        now: float,
    ) -> EvidenceArtifactAuthority:
        try:
            value = self._artifact_resolver(self._tenant_id, artifact.artifact_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except EvidenceAnalysisError:
            raise
        except Exception as exc:
            raise EvidenceAnalysisConfigError("artifact authority resolution failed") from exc
        return _validate_artifact_authority(
            value,
            tenant_sha256=self._tenant_sha256,
            artifact=artifact,
            content_sha256=content_sha256,
            byte_length=byte_length,
            expected_authority_sha256=expected_authority_sha256,
            now=now,
        )

    def _resolve_criteria_authority(
        self,
        criteria_set_id: str,
        *,
        expected_revision: int,
        expected_authority_sha256: str,
        now: float,
    ) -> EvidenceCriteriaAuthority:
        try:
            value = self._criteria_resolver(self._tenant_id, criteria_set_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except EvidenceAnalysisError:
            raise
        except Exception as exc:
            raise EvidenceAnalysisConfigError("criteria authority resolution failed") from exc
        return _validate_criteria_authority(
            value,
            tenant_sha256=self._tenant_sha256,
            criteria_set_id=criteria_set_id,
            expected_revision=expected_revision,
            expected_authority_sha256=expected_authority_sha256,
            now=now,
        )

    def _resolve_review_authority(
        self,
        reviewer_ref: str,
        *,
        capability: str,
        now: float,
    ) -> HumanReviewAuthority:
        if capability not in _REVIEW_CAPABILITIES:
            raise EvidenceAnalysisConfigError("review capability is unsupported")
        reviewer_sha256 = _actor_sha256(self._tenant_id, reviewer_ref)
        try:
            value = self._review_resolver(self._tenant_id, reviewer_ref)
        except (KeyboardInterrupt, SystemExit):
            raise
        except EvidenceAnalysisError:
            raise
        except Exception as exc:
            raise EvidenceAnalysisPermissionError("human review authority is unavailable") from exc
        if type(value) is not HumanReviewAuthority:
            raise EvidenceAnalysisPermissionError("human review authority is unavailable")
        try:
            _review_authority_structural(value)
        except EvidenceAnalysisError as exc:
            raise EvidenceAnalysisPermissionError("human review authority is invalid") from exc
        if (
            not _same(value.tenant_sha256, self._tenant_sha256)
            or not _same(value.reviewer_sha256, reviewer_sha256)
            or capability not in value.capabilities
            or value.revoked is not False
            or value.valid_until <= now
        ):
            raise EvidenceAnalysisPermissionError(
                "human review authority is expired, revoked, misbound, or insufficient"
            )
        return value

    def _resolve_adapter_authority(
        self,
        snapshot: EvidenceAdapterAuthority,
        *,
        now: float,
    ) -> EvidenceAdapterAuthority:
        """Re-resolve one exact adapter authority instead of trusting a cached grant."""

        try:
            value = self._adapter_authority_resolver(
                self._tenant_id,
                snapshot.stage,
                snapshot.adapter_id,
                snapshot.revision,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except EvidenceAnalysisError:
            raise
        except Exception as exc:
            raise EvidenceAnalysisConfigError(
                "current evidence adapter authority is unavailable"
            ) from exc
        current = _validate_adapter_authority(
            value,
            stage=snapshot.stage,
            now=now,
        )
        if current != snapshot:
            raise EvidenceAnalysisConflict("evidence adapter authority changed")
        return current

    def _refresh_authorities(self, record: EvidenceAnalysisRecord, now: float) -> None:
        try:
            artifact = self._artifact_resolver(self._tenant_id, record.artifact.artifact_id)
            criteria = self._criteria_resolver(
                self._tenant_id,
                record.criteria_authority.criteria_set_id,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except EvidenceAnalysisError:
            raise
        except Exception as exc:
            raise EvidenceAnalysisPermissionError(
                "current evidence authority is unavailable"
            ) from exc
        if (
            type(artifact) is not EvidenceArtifactAuthority
            or type(criteria) is not EvidenceCriteriaAuthority
        ):
            raise EvidenceAnalysisPermissionError("current evidence authority is unavailable")
        if (
            artifact != record.artifact_authority
            or artifact.revoked is not False
            or artifact.valid_until <= now
            or not _same(artifact.authority_sha256, artifact_authority_sha256(artifact))
            or criteria != record.criteria_authority
            or criteria.revoked is not False
            or criteria.valid_until <= now
            or not _same(criteria.authority_sha256, criteria_authority_sha256(criteria))
        ):
            raise EvidenceAnalysisConflict("evidence source or criteria authority changed")
        extraction_adapter = self._resolve_adapter_authority(
            record.extraction_adapter_authority,
            now=now,
        )
        analysis_adapter = self._resolve_adapter_authority(
            record.analysis_adapter_authority,
            now=now,
        )
        if (
            extraction_adapter != self._extraction_adapter_authority
            or analysis_adapter != self._analysis_adapter_authority
        ):
            raise EvidenceAnalysisConflict("evidence adapter authority changed")

    def analyze(
        self,
        tenant_id: str,
        *,
        artifact: EvidenceArtifact,
        expected_artifact_authority_sha256: str,
        criteria_set_id: str,
        expected_criteria_revision: int,
        expected_criteria_authority_sha256: str,
        submitter_ref: str,
        valid_until: float,
        retained_until: float,
        idempotency_key: str,
    ) -> EvidenceAnalysisRecord:
        """Analyze one source-attested artifact; raw bytes remain ephemeral."""

        self._check_gate()
        tenant = self._require_tenant(tenant_id)
        now = _now(self._clock)
        content_sha256, byte_length = _validate_artifact(artifact)
        if artifact.acquired_at > now:
            raise EvidenceAnalysisValidationError("artifact acquisition time is in the future")
        expected_artifact_sha = _digest(
            expected_artifact_authority_sha256,
            "expected_artifact_authority_sha256",
        )
        criteria_id = _ref(criteria_set_id, "criteria_set_id")
        criteria_revision = _integer(
            expected_criteria_revision,
            "expected_criteria_revision",
            1,
            2_147_483_647,
        )
        expected_criteria_sha = _digest(
            expected_criteria_authority_sha256,
            "expected_criteria_authority_sha256",
        )
        valid, retained = _lifetime(now, valid_until, retained_until)
        submitter_sha256 = _actor_sha256(tenant, submitter_ref)
        key_sha256 = _idempotency_sha256(self._tenant_sha256, idempotency_key)
        request_sha256 = _sha256(
            {
                "schema": "lightwork.ai-evidence.analyze-request.v1",
                "tenant_sha256": self._tenant_sha256,
                "artifact_id": artifact.artifact_id,
                "media_type": artifact.media_type,
                "content_sha256": content_sha256,
                "byte_length": byte_length,
                "source_ref": artifact.source_ref,
                "source_revision": artifact.source_revision,
                "acquired_at": float(artifact.acquired_at),
                "expected_artifact_authority_sha256": expected_artifact_sha,
                "criteria_set_id": criteria_id,
                "expected_criteria_revision": criteria_revision,
                "expected_criteria_authority_sha256": expected_criteria_sha,
                "extraction_adapter_authority_sha256": (
                    self._extraction_adapter_authority.authority_sha256
                ),
                "analysis_adapter_authority_sha256": (
                    self._analysis_adapter_authority.authority_sha256
                ),
                "submitter_sha256": submitter_sha256,
                "valid_until": valid,
                "retained_until": retained,
            }
        )
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            replay = self._replay(
                connection,
                key_sha256=key_sha256,
                action="analyze",
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay

        artifact_authority = self._resolve_artifact_authority(
            artifact,
            content_sha256=content_sha256,
            byte_length=byte_length,
            expected_authority_sha256=expected_artifact_sha,
            now=now,
        )
        criteria = self._resolve_criteria_authority(
            criteria_id,
            expected_revision=criteria_revision,
            expected_authority_sha256=expected_criteria_sha,
            now=now,
        )
        extraction_adapter_authority = self._resolve_adapter_authority(
            self._extraction_adapter_authority,
            now=now,
        )
        analysis_adapter_authority = self._resolve_adapter_authority(
            self._analysis_adapter_authority,
            now=now,
        )
        if valid > min(
            artifact_authority.valid_until,
            criteria.valid_until,
            extraction_adapter_authority.valid_until,
            analysis_adapter_authority.valid_until,
        ):
            raise EvidenceAnalysisValidationError(
                "analysis validity exceeds a bound authority lifetime"
            )
        descriptor = _artifact_record(artifact, artifact_authority)
        extraction_request = EvidenceExtractionRequest(
            schema=EXTRACTION_REQUEST_SCHEMA,
            artifact=artifact,
            artifact_record=descriptor,
            criteria_authority=criteria,
            adapter_authority_sha256=extraction_adapter_authority.authority_sha256,
            untrusted_content=True,
            instruction_mode="data_only",
            request_sha256=_extraction_request_sha256(
                descriptor,
                criteria,
                extraction_adapter_authority,
            ),
        )
        try:
            extracted_raw = self._extraction_adapter(extraction_request)
        except (KeyboardInterrupt, SystemExit):
            raise
        except EvidenceAnalysisError:
            raise
        except Exception as exc:
            raise EvidenceAnalysisConfigError("evidence extraction adapter failed") from exc
        extraction = _validate_extraction_output(extracted_raw, request=extraction_request)
        analysis_request = EvidenceAnalysisRequest(
            schema=ANALYSIS_REQUEST_SCHEMA,
            artifact_record=descriptor,
            criteria_authority=criteria,
            extraction=extraction,
            adapter_authority_sha256=analysis_adapter_authority.authority_sha256,
            request_sha256=_analysis_request_sha256(
                descriptor,
                criteria,
                extraction,
                analysis_adapter_authority,
            ),
        )
        try:
            analyzed_raw = self._analysis_adapter(analysis_request)
        except (KeyboardInterrupt, SystemExit):
            raise
        except EvidenceAnalysisError:
            raise
        except Exception as exc:
            raise EvidenceAnalysisConfigError("evidence analysis adapter failed") from exc
        adapter_analysis = _validate_analysis_output(analyzed_raw, request=analysis_request)
        summary = _summary(criteria, extraction, adapter_analysis)
        justification = _justification(criteria, adapter_analysis)
        gaps = _gaps(criteria, adapter_analysis)
        provenance = _provenance(
            artifact_authority,
            descriptor,
            extraction_request,
            extraction,
            analysis_request,
            adapter_analysis,
            summary,
            justification,
            gaps,
        )
        try:
            analysis_id = _ref(self._id_factory(), "analysis_id")
        except EvidenceAnalysisError:
            raise
        except Exception as exc:
            raise EvidenceAnalysisConfigError("analysis identifier factory failed") from exc
        record = EvidenceAnalysisRecord(
            analysis_id=analysis_id,
            tenant_sha256=self._tenant_sha256,
            artifact_authority=artifact_authority,
            artifact=descriptor,
            criteria_authority=criteria,
            extraction_adapter_authority=extraction_adapter_authority,
            analysis_adapter_authority=analysis_adapter_authority,
            extraction=extraction,
            adapter_analysis=adapter_analysis,
            summary=summary,
            justification=justification,
            gaps=gaps,
            provenance=provenance,
            provenance_sha256=provenance[-1].link_sha256,
            submitter_sha256=submitter_sha256,
            status="pending_review",
            human_review_required=True,
            review_decision=None,
            review_authority=None,
            reviewed_at=None,
            revocation_authority=None,
            revocation_reason_code=None,
            revoked_at=None,
            legal_or_compliance_conclusion=False,
            notice=NON_CONCLUSION_NOTICE,
            valid_until=valid,
            retained_until=retained,
            created_at=now,
            updated_at=now,
            revision=1,
            previous_integrity_sha256=None,
            integrity_sha256=_ZERO_DIGEST,
        )
        record = replace(record, integrity_sha256=_record_integrity_sha256(record))
        _validate_stored_record(record)
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            self._begin(connection)
            replay = self._replay(
                connection,
                key_sha256=key_sha256,
                action="analyze",
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_evidence_analyses WHERE tenant_sha256=?",
                    (self._tenant_sha256,),
                ).fetchone()[0]
            )
            if count >= _MAX_ANALYSES:
                raise EvidenceAnalysisConflict("evidence-analysis capacity is reached")
            if (
                connection.execute(
                    "SELECT 1 FROM ai_evidence_analyses WHERE analysis_id=?",
                    (record.analysis_id,),
                ).fetchone()
                is not None
            ):
                raise EvidenceAnalysisConflict("analysis identifier collision")
            self._insert_record(connection, record)
            self._insert_operation(
                connection,
                key_sha256=key_sha256,
                action="analyze",
                request_sha256=request_sha256,
                record=record,
                now=now,
            )
        return record

    def get(self, tenant_id: str, analysis_id: str) -> EvidenceAnalysisRecord:
        self._check_gate()
        self._require_tenant(tenant_id)
        selected = _ref(analysis_id, "analysis_id")
        with self._connect() as connection:
            return self._current(connection, selected)

    def list_analyses(
        self,
        tenant_id: str,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> tuple[EvidenceAnalysisRecord, ...]:
        """Return bounded current heads after full stored-record validation."""

        self._check_gate()
        self._require_tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 1_000)
        clauses = ["tenant_sha256=?"]
        values: list[object] = [self._tenant_sha256]
        if status is not None:
            if status not in _STATUSES:
                raise EvidenceAnalysisValidationError(
                    "evidence-analysis status is unsupported"
                )
            clauses.append("status=?")
            values.append(status)
        values.append(bounded)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM ai_evidence_analyses WHERE "
                + " AND ".join(clauses)
                + " ORDER BY analysis_id LIMIT ?",
                tuple(values),
            ).fetchall()
        return tuple(self._row_record(row, "evidence analysis") for row in rows)

    def context_record_count(self, tenant_id: str) -> int:
        """Return the exact tenant current-head count for bounded projections."""

        self._check_gate()
        self._require_tenant(tenant_id)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM ai_evidence_analyses WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchone()
        if row is None or not isinstance(row[0], int) or row[0] < 0:
            raise EvidenceAnalysisIntegrityError(
                "evidence-analysis record count is invalid"
            )
        return int(row[0])

    def get_released(self, tenant_id: str, analysis_id: str) -> EvidenceAnalysisRecord:
        """Return only current, unexpired evidence released by a human reviewer."""

        record = self.get(tenant_id, analysis_id)
        now = _now(self._clock)
        if record.status != "review_approved" or record.valid_until <= now:
            raise EvidenceAnalysisPermissionError("evidence analysis is not released")
        self._refresh_authorities(record, now)
        return record

    def review(
        self,
        tenant_id: str,
        analysis_id: str,
        *,
        reviewer_ref: str,
        decision: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> EvidenceAnalysisRecord:
        self._check_gate()
        tenant = self._require_tenant(tenant_id)
        selected = _ref(analysis_id, "analysis_id")
        if decision not in {"approve", "reject"}:
            raise EvidenceAnalysisValidationError("review decision is unsupported")
        revision = _integer(
            expected_revision,
            "expected_revision",
            1,
            2_147_483_647,
        )
        now = _now(self._clock)
        reviewer_sha256 = _actor_sha256(tenant, reviewer_ref)
        key_sha256 = _idempotency_sha256(self._tenant_sha256, idempotency_key)
        request_sha256 = _sha256(
            {
                "schema": "lightwork.ai-evidence.review-request.v1",
                "tenant_sha256": self._tenant_sha256,
                "analysis_id": selected,
                "reviewer_sha256": reviewer_sha256,
                "decision": decision,
                "expected_revision": revision,
            }
        )
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            replay = self._replay(
                connection,
                key_sha256=key_sha256,
                action="review",
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            current = self._current(connection, selected)
        if current.revision != revision or current.status != "pending_review":
            raise EvidenceAnalysisConflict("evidence review revision or state changed")
        if current.valid_until <= now:
            raise EvidenceAnalysisConflict("evidence analysis expired before review")
        if _same(current.submitter_sha256, reviewer_sha256):
            raise EvidenceAnalysisPermissionError("submitter cannot review their own analysis")
        review_authority = self._resolve_review_authority(
            reviewer_ref,
            capability=decision,
            now=now,
        )
        self._refresh_authorities(current, now)
        updated = replace(
            current,
            status="review_approved" if decision == "approve" else "review_rejected",
            review_decision=decision,
            review_authority=review_authority,
            reviewed_at=now,
            updated_at=now,
            revision=current.revision + 1,
            previous_integrity_sha256=current.integrity_sha256,
            integrity_sha256=_ZERO_DIGEST,
        )
        updated = replace(updated, integrity_sha256=_record_integrity_sha256(updated))
        _validate_stored_record(updated)
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            self._begin(connection)
            replay = self._replay(
                connection,
                key_sha256=key_sha256,
                action="review",
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            observed = self._current(connection, selected)
            if (
                observed.revision != current.revision
                or not _same(observed.integrity_sha256, current.integrity_sha256)
                or observed.status != "pending_review"
            ):
                raise EvidenceAnalysisConflict("evidence review revision or state changed")
            self._archive(connection, observed)
            self._update_record(connection, updated)
            self._insert_operation(
                connection,
                key_sha256=key_sha256,
                action="review",
                request_sha256=request_sha256,
                record=updated,
                now=now,
            )
        return updated

    def revoke(
        self,
        tenant_id: str,
        analysis_id: str,
        *,
        reviewer_ref: str,
        reason_code: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> EvidenceAnalysisRecord:
        self._check_gate()
        tenant = self._require_tenant(tenant_id)
        selected = _ref(analysis_id, "analysis_id")
        reason = _ref(reason_code, "reason_code")
        revision = _integer(
            expected_revision,
            "expected_revision",
            1,
            2_147_483_647,
        )
        now = _now(self._clock)
        reviewer_sha256 = _actor_sha256(tenant, reviewer_ref)
        key_sha256 = _idempotency_sha256(self._tenant_sha256, idempotency_key)
        request_sha256 = _sha256(
            {
                "schema": "lightwork.ai-evidence.revoke-request.v1",
                "tenant_sha256": self._tenant_sha256,
                "analysis_id": selected,
                "reviewer_sha256": reviewer_sha256,
                "reason_code": reason,
                "expected_revision": revision,
            }
        )
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            replay = self._replay(
                connection,
                key_sha256=key_sha256,
                action="revoke",
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            current = self._current(connection, selected)
        if current.revision != revision or current.status == "revoked":
            raise EvidenceAnalysisConflict("evidence revocation revision or state changed")
        if _same(current.submitter_sha256, reviewer_sha256):
            raise EvidenceAnalysisPermissionError("submitter cannot revoke their own analysis")
        revoke_authority = self._resolve_review_authority(
            reviewer_ref,
            capability="revoke",
            now=now,
        )
        updated = replace(
            current,
            status="revoked",
            revocation_authority=revoke_authority,
            revocation_reason_code=reason,
            revoked_at=now,
            updated_at=now,
            revision=current.revision + 1,
            previous_integrity_sha256=current.integrity_sha256,
            integrity_sha256=_ZERO_DIGEST,
        )
        updated = replace(updated, integrity_sha256=_record_integrity_sha256(updated))
        _validate_stored_record(updated)
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            self._begin(connection)
            replay = self._replay(
                connection,
                key_sha256=key_sha256,
                action="revoke",
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            observed = self._current(connection, selected)
            if (
                observed.revision != current.revision
                or not _same(observed.integrity_sha256, current.integrity_sha256)
                or observed.status == "revoked"
            ):
                raise EvidenceAnalysisConflict("evidence revocation revision or state changed")
            self._archive(connection, observed)
            self._update_record(connection, updated)
            self._insert_operation(
                connection,
                key_sha256=key_sha256,
                action="revoke",
                request_sha256=request_sha256,
                record=updated,
                now=now,
            )
        return updated

    def history(
        self,
        tenant_id: str,
        analysis_id: str,
    ) -> tuple[EvidenceAnalysisRecord, ...]:
        self._check_gate()
        self._require_tenant(tenant_id)
        selected = _ref(analysis_id, "analysis_id")
        with self._connect() as connection:
            current = self._current(connection, selected)
            rows = connection.execute(
                "SELECT analysis_id,tenant_sha256,revision,payload_json,integrity_sha256 "
                "FROM ai_evidence_analysis_history WHERE tenant_sha256=? AND analysis_id=? "
                "ORDER BY revision",
                (self._tenant_sha256, selected),
            ).fetchall()
            records = [self._row_record(row, "evidence analysis history") for row in rows]
        records.append(current)
        return tuple(records)

    def retention_due(
        self,
        tenant_id: str,
        *,
        as_of: float | None = None,
        limit: int = 100,
    ) -> tuple[str, ...]:
        self._check_gate()
        self._require_tenant(tenant_id)
        now = _now(self._clock)
        selected = now if as_of is None else _timestamp(as_of, "as_of")
        if selected > now:
            raise EvidenceAnalysisValidationError("retention as_of cannot be in the future")
        bounded_limit = _integer(limit, "limit", 1, _MAX_PURGE)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT analysis_id FROM ai_evidence_analyses WHERE tenant_sha256=? "
                "AND retained_until<=? ORDER BY retained_until,analysis_id LIMIT ?",
                (self._tenant_sha256, selected, bounded_limit),
            ).fetchall()
        return tuple(str(row["analysis_id"]) for row in rows)

    def purge_expired(
        self,
        tenant_id: str,
        *,
        as_of: float | None = None,
        limit: int = 100,
    ) -> EvidenceRetentionResult:
        self._check_gate()
        self._require_tenant(tenant_id)
        now = _now(self._clock)
        selected = now if as_of is None else _timestamp(as_of, "as_of")
        if selected > now:
            raise EvidenceAnalysisValidationError("retention as_of cannot be in the future")
        bounded_limit = _integer(limit, "limit", 1, _MAX_PURGE)
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            self._begin(connection)
            rows = connection.execute(
                "SELECT * FROM ai_evidence_analyses WHERE tenant_sha256=? "
                "AND retained_until<=? ORDER BY retained_until,analysis_id LIMIT ?",
                (self._tenant_sha256, selected, bounded_limit),
            ).fetchall()
            due_records = [self._row_record(row, "evidence analysis") for row in rows]
            identifiers = tuple(record.analysis_id for record in due_records)
            history_count = 0
            operation_count = 0
            for current in due_records:
                identifier = current.analysis_id
                history_rows = connection.execute(
                    "SELECT analysis_id,tenant_sha256,revision,payload_json,integrity_sha256 "
                    "FROM ai_evidence_analysis_history WHERE tenant_sha256=? AND analysis_id=? "
                    "ORDER BY revision",
                    (self._tenant_sha256, identifier),
                ).fetchall()
                history = [
                    self._row_record(row, "evidence analysis history") for row in history_rows
                ]
                records = [*history, current]
                if tuple(item.revision for item in records) != tuple(range(1, len(records) + 1)):
                    raise EvidenceAnalysisIntegrityError(
                        "retained evidence revision history is incomplete"
                    )
                for previous, item in zip(records, records[1:], strict=False):
                    if not _same(item.previous_integrity_sha256, previous.integrity_sha256):
                        raise EvidenceAnalysisIntegrityError(
                            "retained evidence integrity chain is broken"
                        )
                operation_rows = connection.execute(
                    "SELECT * FROM ai_evidence_analysis_operations WHERE tenant_sha256=? "
                    "AND analysis_id=?",
                    (self._tenant_sha256, identifier),
                ).fetchall()
                result_hashes = {item.integrity_sha256 for item in records}
                for operation in operation_rows:
                    if (
                        not _same(
                            operation["operation_integrity_sha256"],
                            _sha256(self._operation_body(operation)),
                        )
                        or str(operation["result_integrity_sha256"]) not in result_hashes
                    ):
                        raise EvidenceAnalysisIntegrityError(
                            "retained evidence operation failed integrity"
                        )
                history_count += len(history)
                operation_count += len(operation_rows)
            self._retention.authorized = True
            try:
                for identifier in identifiers:
                    connection.execute(
                        "DELETE FROM ai_evidence_analysis_operations WHERE tenant_sha256=? "
                        "AND analysis_id=?",
                        (self._tenant_sha256, identifier),
                    )
                    connection.execute(
                        "DELETE FROM ai_evidence_analysis_history WHERE tenant_sha256=? "
                        "AND analysis_id=?",
                        (self._tenant_sha256, identifier),
                    )
                    connection.execute(
                        "DELETE FROM ai_evidence_analyses WHERE tenant_sha256=? AND analysis_id=?",
                        (self._tenant_sha256, identifier),
                    )
            finally:
                self._retention.authorized = False
        return EvidenceRetentionResult(
            analysis_ids=identifiers,
            history_records=history_count,
            operations=operation_count,
        )

    def verify_integrity(self, tenant_id: str) -> EvidenceAnalysisIntegrityReport:
        self._check_gate()
        self._require_tenant(tenant_id)
        with self._connect() as connection:
            current_rows = connection.execute(
                "SELECT * FROM ai_evidence_analyses WHERE tenant_sha256=? ORDER BY analysis_id",
                (self._tenant_sha256,),
            ).fetchall()
            history_rows = connection.execute(
                "SELECT analysis_id,tenant_sha256,revision,payload_json,integrity_sha256 "
                "FROM ai_evidence_analysis_history WHERE tenant_sha256=? "
                "ORDER BY analysis_id,revision",
                (self._tenant_sha256,),
            ).fetchall()
            operation_rows = connection.execute(
                "SELECT * FROM ai_evidence_analysis_operations WHERE tenant_sha256=? "
                "ORDER BY key_sha256",
                (self._tenant_sha256,),
            ).fetchall()
            current = [self._row_record(row, "evidence analysis") for row in current_rows]
            history = [self._row_record(row, "evidence analysis history") for row in history_rows]
            by_id: dict[str, list[EvidenceAnalysisRecord]] = {}
            for record in history + current:
                by_id.setdefault(record.analysis_id, []).append(record)
            for identifier, records in by_id.items():
                records.sort(key=lambda item: item.revision)
                if tuple(item.revision for item in records) != tuple(range(1, len(records) + 1)):
                    raise EvidenceAnalysisIntegrityError(
                        f"evidence analysis {identifier} revision history is incomplete"
                    )
                for previous, item in zip(records, records[1:], strict=False):
                    if not _same(item.previous_integrity_sha256, previous.integrity_sha256):
                        raise EvidenceAnalysisIntegrityError(
                            "evidence analysis integrity chain is broken"
                        )
            result_hashes = {
                (record.analysis_id, record.integrity_sha256) for record in history + current
            }
            operation_hashes: list[str] = []
            for row in operation_rows:
                body = self._operation_body(row)
                supplied = str(row["operation_integrity_sha256"])
                if (
                    not _same(supplied, _sha256(body))
                    or (
                        str(row["analysis_id"]),
                        str(row["result_integrity_sha256"]),
                    )
                    not in result_hashes
                ):
                    raise EvidenceAnalysisIntegrityError(
                        "evidence-analysis operation failed integrity"
                    )
                operation_hashes.append(supplied)
        terminal = _sha256(
            {
                "current": [item.integrity_sha256 for item in current],
                "history": [item.integrity_sha256 for item in history],
                "operations": operation_hashes,
            }
        )
        body = {
            "schema": INTEGRITY_SCHEMA,
            "analyses": len(current),
            "history_records": len(history),
            "operations": len(operation_hashes),
            "terminal_sha256": terminal,
        }
        return EvidenceAnalysisIntegrityReport(
            **{key: value for key, value in body.items() if key != "schema"},
            schema=INTEGRITY_SCHEMA,
            verification_sha256=_sha256(body),
        )
