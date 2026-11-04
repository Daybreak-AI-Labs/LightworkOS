"""Governed evidence-assisted assessment answer proposals.

This module bridges the general multimodal evidence-analysis authority into the
general assessment engine without treating a model or a document as a human
attestation.  It deliberately separates four steps:

* evidence is extracted and independently released by ``ai_evidence_analysis``;
* a deterministic, questionnaire-bound mapping creates answer *proposals*;
* a different human principal approves or rejects an explicit subset; and
* a separately invoked CAS operation fills only questions that are still empty.

No raw artifact bytes, extracted text, prompts, or free-form model output are
stored here.  Citations contain only opaque identifiers and verified digests.
The local proposal digest and governed-record audit outbox are integrity and
delivery controls; they are not an external WORM/notarization claim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any, Literal

from .governed_records import GovernedRecordStore

PROPOSAL_SCHEMA = "lightwork.assessment-evidence-proposal.v1"
MAPPING_SCHEMA = "lightwork.assessment-evidence-mapping-authority.v1"
INTEGRITY_SCHEMA = "lightwork.assessment-evidence-integrity.v1"
APPLICATION_RECEIPT_SCHEMA = "lightwork.assessment-evidence-application-receipt.v1"
NOTICE = (
    "Evidence-assisted draft requiring human review. It is not a vendor "
    "attestation, certification, conformity assessment, or legal conclusion."
)

_PROPOSALS = GovernedRecordStore(
    "assessment_evidence_proposals",
    "AEP",
    "assessment_evidence_proposal",
)
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_QUESTION_RE = re.compile(r"[a-z0-9][a-z0-9_]{0,59}\Z")
_ANSWERS = frozenset({"yes", "no", "na", "unknown"})
_DISPOSITIONS = frozenset(
    {"evidence_supported", "evidence_partial", "evidence_missing", "indeterminate"}
)
_STATUSES = frozenset({"pending_review", "approved", "rejected", "applied", "expired"})
_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_PROPOSALS = 10_000
_MAX_ANALYSES = 32
_MAX_CANDIDATES = 500
_MAX_CITATIONS = 32
_MAX_OPERATIONS = 64


class AssessmentEvidenceError(RuntimeError):
    """Base governed assessment-evidence error."""


class AssessmentEvidenceConfigError(AssessmentEvidenceError):
    """A required feature gate or production authority is unavailable."""


class AssessmentEvidenceValidationError(AssessmentEvidenceError, ValueError):
    """Input or resolved material violates the closed contract."""


class AssessmentEvidenceConflict(AssessmentEvidenceError):
    """An idempotency, revision, or independently resolved authority changed."""


class AssessmentEvidenceNotFound(AssessmentEvidenceError):
    """A proposal, assessment, or evidence record is unavailable."""


class AssessmentEvidenceTransitionError(AssessmentEvidenceError):
    """A requested proposal or assessment transition is not allowed."""


class AssessmentEvidenceIntegrityError(AssessmentEvidenceError):
    """Persisted or resolved material failed structural/digest validation."""


@dataclass(frozen=True, slots=True)
class AssessmentEvidenceSettings:
    retention_seconds: int = 365 * 24 * 60 * 60
    max_records: int = 5_000
    max_evidence_records_per_proposal: int = 16
    max_citations_per_answer: int = 8
    min_confidence_bps: int = 7_000
    apply_enabled: bool = False

    def __post_init__(self) -> None:
        _integer(self.retention_seconds, "retention_seconds", 60, 10 * 366 * 86400)
        _integer(self.max_records, "max_records", 1, _MAX_PROPOSALS)
        _integer(
            self.max_evidence_records_per_proposal,
            "max_evidence_records_per_proposal",
            1,
            _MAX_ANALYSES,
        )
        _integer(
            self.max_citations_per_answer,
            "max_citations_per_answer",
            1,
            _MAX_CITATIONS,
        )
        _integer(self.min_confidence_bps, "min_confidence_bps", 1, 10_000)
        if type(self.apply_enabled) is not bool:
            raise AssessmentEvidenceValidationError("apply_enabled must be boolean")


@dataclass(frozen=True, slots=True)
class AssessmentEvidenceMapping:
    question_id: str
    criteria_set_id: str
    criteria_revision: int
    criteria_authority_sha256: str
    criterion_id: str
    criterion_sha256: str
    supported_answer: Literal["yes", "no", "na"]


@dataclass(frozen=True, slots=True)
class AssessmentEvidenceMappingAuthority:
    schema: str
    tenant_sha256: str
    assessment_type: str
    template_digest: str
    revision: int
    mappings: tuple[AssessmentEvidenceMapping, ...]
    valid_until: float
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class AssessmentApplyResult:
    assessment_id: str
    assessment_revision: int
    applied_question_ids: tuple[str, ...]
    assessment_result_sha256: str


@dataclass(frozen=True, slots=True)
class AssessmentEvidenceIntegrityReport:
    schema: str
    tenant_sha256: str
    records: int
    pending_review: int
    approved: int
    applied: int
    rejected: int
    expired: int
    pending_audit_receipts: int
    terminal_sha256: str
    verified: bool


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
        raise AssessmentEvidenceValidationError(
            "assessment evidence material is not canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise AssessmentEvidenceValidationError(
            "assessment evidence material exceeds its JSON bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


def _answer_application_receipt(
    *, proposal_id: str, proposal_sha256: str, candidate: Mapping[str, Any]
) -> dict[str, str]:
    """Build the non-user-authorable fence written by the governed applier."""

    receipt = {
        "schema": APPLICATION_RECEIPT_SCHEMA,
        "proposal_id": _ref(proposal_id, "proposal_id"),
        "proposal_sha256": _digest(proposal_sha256, "proposal_sha256"),
        "question_id": _question(candidate.get("question_id")),
        "answer": str(candidate.get("answer") or ""),
        "candidate_sha256": _digest(
            candidate.get("candidate_sha256"), "candidate_sha256"
        ),
    }
    if receipt["answer"] not in _ANSWERS - {"unknown"}:
        raise AssessmentEvidenceValidationError("application receipt answer is invalid")
    return {**receipt, "receipt_sha256": _sha256(receipt)}


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise AssessmentEvidenceValidationError(f"{label} is not a lowercase SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise AssessmentEvidenceValidationError(
            f"{label} must be an integer between {minimum} and {maximum}"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AssessmentEvidenceValidationError(f"{label} is not a timestamp")
    selected = float(value)
    if not math.isfinite(selected) or selected <= 0 or selected >= 100_000_000_000:
        raise AssessmentEvidenceValidationError(f"{label} is not a timestamp")
    return selected


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise AssessmentEvidenceValidationError(f"{label} is invalid")
    return value


def _question(value: object) -> str:
    if not isinstance(value, str) or not _QUESTION_RE.fullmatch(value):
        raise AssessmentEvidenceValidationError("question_id is invalid")
    return value


def _operation(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or not _OP_RE.fullmatch(value):
        raise AssessmentEvidenceValidationError("idempotency_key is invalid")
    return value, hashlib.sha256(value.encode("utf-8")).hexdigest()


def _actor(value: object) -> str:
    if not isinstance(value, str):
        raise AssessmentEvidenceValidationError("actor is invalid")
    selected = value.strip()
    if not 1 <= len(selected) <= 512 or any(ord(char) < 32 for char in selected):
        raise AssessmentEvidenceValidationError("actor is invalid")
    return selected


def _rationale(value: object) -> str:
    if not isinstance(value, str):
        raise AssessmentEvidenceValidationError("review rationale is invalid")
    selected = value.strip()
    if not 1 <= len(selected) <= 4_000 or any(ord(char) < 32 for char in selected):
        raise AssessmentEvidenceValidationError("review rationale is invalid")
    try:
        from .safety.secret_detector import scan

        if scan(selected):
            raise AssessmentEvidenceValidationError("review rationale contains secret material")
    except AssessmentEvidenceValidationError:
        raise
    except Exception as exc:
        raise AssessmentEvidenceConfigError("secret detection is unavailable") from exc
    return selected


def _tenant_digest(tenant_id: str) -> str:
    from .paths import canonical_tenant_id

    tenant = canonical_tenant_id(tenant_id)
    return hashlib.sha256(
        f"lightwork.assessment-evidence.tenant.v1:{tenant}".encode()
    ).hexdigest()


def _mapping_payload(value: AssessmentEvidenceMappingAuthority) -> dict[str, Any]:
    return {
        "schema": MAPPING_SCHEMA,
        "tenant_sha256": value.tenant_sha256,
        "assessment_type": value.assessment_type,
        "template_digest": value.template_digest,
        "revision": value.revision,
        "mappings": [asdict(item) for item in value.mappings],
        "valid_until": value.valid_until,
    }


def mapping_authority_sha256(value: AssessmentEvidenceMappingAuthority) -> str:
    return _sha256(_mapping_payload(value))


def _mapping_authority_from_payload(value: object) -> AssessmentEvidenceMappingAuthority:
    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "tenant_sha256",
        "assessment_type",
        "template_digest",
        "revision",
        "mappings",
        "valid_until",
        "authority_sha256",
    }:
        raise AssessmentEvidenceIntegrityError("stored mapping authority is invalid")
    raw_mappings = value.get("mappings")
    if not isinstance(raw_mappings, list) or not 1 <= len(raw_mappings) <= _MAX_CANDIDATES:
        raise AssessmentEvidenceIntegrityError("stored mappings are invalid")
    mappings: list[AssessmentEvidenceMapping] = []
    mapping_fields = {
        "question_id",
        "criteria_set_id",
        "criteria_revision",
        "criteria_authority_sha256",
        "criterion_id",
        "criterion_sha256",
        "supported_answer",
    }
    for item in raw_mappings:
        if not isinstance(item, Mapping) or set(item) != mapping_fields:
            raise AssessmentEvidenceIntegrityError("stored mapping is invalid")
        try:
            mappings.append(AssessmentEvidenceMapping(**dict(item)))
        except (TypeError, ValueError) as exc:
            raise AssessmentEvidenceIntegrityError("stored mapping is invalid") from exc
    try:
        authority = AssessmentEvidenceMappingAuthority(
            schema=str(value["schema"]),
            tenant_sha256=str(value["tenant_sha256"]),
            assessment_type=str(value["assessment_type"]),
            template_digest=str(value["template_digest"]),
            revision=value["revision"],
            mappings=tuple(mappings),
            valid_until=value["valid_until"],
            authority_sha256=str(value["authority_sha256"]),
        )
    except (TypeError, ValueError) as exc:
        raise AssessmentEvidenceIntegrityError("stored mapping authority is invalid") from exc
    _digest(authority.tenant_sha256, "mapping tenant_sha256")
    _digest(authority.template_digest, "mapping template_digest")
    _digest(authority.authority_sha256, "mapping authority_sha256")
    _integer(authority.revision, "mapping revision", 1, 2_147_483_647)
    _timestamp(authority.valid_until, "mapping valid_until")
    if authority.schema != MAPPING_SCHEMA or not _same(
        authority.authority_sha256,
        mapping_authority_sha256(authority),
    ):
        raise AssessmentEvidenceIntegrityError("stored mapping authority digest is invalid")
    return authority


def _validate_mapping_authority(
    value: object,
    *,
    tenant_sha256: str,
    assessment: Mapping[str, Any],
    evidence_records: Sequence[Any],
    now: float,
) -> AssessmentEvidenceMappingAuthority:
    if type(value) is not AssessmentEvidenceMappingAuthority:
        raise AssessmentEvidenceIntegrityError("assessment evidence mapping authority is invalid")
    if value.schema != MAPPING_SCHEMA:
        raise AssessmentEvidenceIntegrityError("assessment evidence mapping schema is invalid")
    _digest(value.tenant_sha256, "mapping tenant_sha256")
    _digest(value.template_digest, "mapping template_digest")
    _digest(value.authority_sha256, "mapping authority_sha256")
    _integer(value.revision, "mapping revision", 1, 2_147_483_647)
    _timestamp(value.valid_until, "mapping valid_until")
    if (
        not _same(value.tenant_sha256, tenant_sha256)
        or value.assessment_type != assessment.get("type")
        or not _same(value.template_digest, assessment.get("template_digest"))
        or value.valid_until <= now
        or not _same(value.authority_sha256, mapping_authority_sha256(value))
    ):
        raise AssessmentEvidenceConflict("assessment evidence mapping authority changed or expired")
    if not 1 <= len(value.mappings) <= _MAX_CANDIDATES:
        raise AssessmentEvidenceIntegrityError("assessment evidence mappings are invalid")
    questions = _assessment_questions(assessment)
    criteria: dict[tuple[str, int, str, str], Any] = {}
    for record in evidence_records:
        authority = record.criteria_authority
        for criterion in authority.criteria:
            criteria[
                (
                    authority.criteria_set_id,
                    authority.revision,
                    authority.authority_sha256,
                    criterion.criterion_id,
                )
            ] = criterion
    seen: set[tuple[str, str, str]] = set()
    for item in value.mappings:
        if type(item) is not AssessmentEvidenceMapping:
            raise AssessmentEvidenceIntegrityError("assessment evidence mapping is invalid")
        _question(item.question_id)
        _ref(item.criteria_set_id, "criteria_set_id")
        _integer(item.criteria_revision, "criteria_revision", 1, 2_147_483_647)
        _digest(item.criteria_authority_sha256, "criteria_authority_sha256")
        _ref(item.criterion_id, "criterion_id")
        _digest(item.criterion_sha256, "criterion_sha256")
        if item.supported_answer not in {"yes", "no", "na"}:
            raise AssessmentEvidenceIntegrityError("supported assessment answer is invalid")
        question = questions.get(item.question_id)
        criterion = criteria.get(
            (
                item.criteria_set_id,
                item.criteria_revision,
                item.criteria_authority_sha256,
                item.criterion_id,
            )
        )
        if question is None or criterion is None or not _same(
            item.criterion_sha256, criterion.criterion_sha256
        ):
            raise AssessmentEvidenceConflict(
                "assessment evidence mapping no longer resolves to exact authorities"
            )
        identity = (item.question_id, item.criteria_authority_sha256, item.criterion_id)
        if identity in seen:
            raise AssessmentEvidenceIntegrityError("assessment evidence mapping is duplicated")
        seen.add(identity)
    return value


def _assessment_questions(record: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    snapshot = record.get("template_snapshot")
    if not isinstance(snapshot, Mapping) or not isinstance(snapshot.get("questions"), list):
        raise AssessmentEvidenceIntegrityError(
            "assessment requires an immutable questionnaire snapshot"
        )
    digest = record.get("template_digest")
    _digest(digest, "assessment template_digest")
    try:
        from .assessment import template_for_saved_record

        resolved = template_for_saved_record(dict(record))
    except Exception as exc:
        raise AssessmentEvidenceIntegrityError(
            "assessment questionnaire snapshot does not verify"
        ) from exc
    if resolved is None or not _same(resolved.digest, digest):
        raise AssessmentEvidenceIntegrityError(
            "assessment questionnaire snapshot does not verify"
        )
    return {
        item.id: {
            "id": item.id,
            "section": item.section,
            "risk_answer": item.risk_answer,
            "severity": item.severity,
        }
        for item in resolved.questions
    }


def derive_exact_mapping_authority(
    tenant_id: str,
    assessment: Mapping[str, Any],
    evidence_records: Sequence[Any],
    *,
    now: float | None = None,
) -> AssessmentEvidenceMappingAuthority:
    """Build the safe stock mapping for exact criterion/question identities.

    A matching criterion means "evidence for this question's safe control";
    evidence support therefore proposes the opposite of the question's
    ``risk_answer``.  Absence/partial evidence never becomes a negative answer.
    Deployments with different criteria semantics must inject an independently
    governed mapping resolver instead of relying on this convention.
    """

    _timestamp(time.time() if now is None else now, "clock")
    tenant_sha = _tenant_digest(tenant_id)
    questions = _assessment_questions(assessment)
    mappings_by_identity: dict[tuple[str, int, str, str], AssessmentEvidenceMapping] = {}
    valid_until = 100_000_000_000.0 - 1
    for record in evidence_records:
        valid_until = min(valid_until, float(record.valid_until))
        authority = record.criteria_authority
        for criterion in authority.criteria:
            question = questions.get(criterion.criterion_id)
            if question is None:
                continue
            risk_answer = question["risk_answer"]
            supported_answer = "no" if risk_answer == "yes" else "yes"
            mapping = AssessmentEvidenceMapping(
                question_id=criterion.criterion_id,
                criteria_set_id=authority.criteria_set_id,
                criteria_revision=authority.revision,
                criteria_authority_sha256=authority.authority_sha256,
                criterion_id=criterion.criterion_id,
                criterion_sha256=criterion.criterion_sha256,
                supported_answer=supported_answer,
            )
            mappings_by_identity[
                (
                    mapping.criteria_set_id,
                    mapping.criteria_revision,
                    mapping.criteria_authority_sha256,
                    mapping.criterion_id,
                )
            ] = mapping
    mappings = list(mappings_by_identity.values())
    mappings.sort(
        key=lambda item: (
            item.question_id,
            item.criteria_set_id,
            item.criteria_revision,
            item.criterion_id,
        )
    )
    if not mappings:
        raise AssessmentEvidenceValidationError(
            "no evidence criteria map exactly to the pinned questionnaire"
        )
    raw = AssessmentEvidenceMappingAuthority(
        schema=MAPPING_SCHEMA,
        tenant_sha256=tenant_sha,
        assessment_type=str(assessment.get("type") or ""),
        template_digest=str(assessment.get("template_digest") or ""),
        revision=1,
        mappings=tuple(mappings),
        valid_until=valid_until,
        authority_sha256="0" * 64,
    )
    return AssessmentEvidenceMappingAuthority(
        **{
            **asdict(raw),
            "mappings": raw.mappings,
            "authority_sha256": mapping_authority_sha256(raw),
        }
    )


def _validate_assessment(record: object, assessment_id: str) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise AssessmentEvidenceNotFound("assessment is unavailable")
    value = dict(record)
    if value.get("id") != assessment_id:
        raise AssessmentEvidenceIntegrityError("assessment identity is invalid")
    _ref(assessment_id, "assessment_id")
    _integer(value.get("revision"), "assessment revision", 1, 2**63 - 1)
    _integer(value.get("template_revision"), "template revision", 0, 2**63 - 1)
    _digest(value.get("template_digest"), "assessment template_digest")
    if value.get("status") not in {"pending_review", "needs_more"}:
        raise AssessmentEvidenceTransitionError(
            "only an open assessment can receive evidence-assisted proposals"
        )
    answers = value.get("answers")
    if not isinstance(answers, Mapping):
        raise AssessmentEvidenceIntegrityError("assessment answers are invalid")
    _assessment_questions(value)
    return value


def _validate_evidence_record(record: object, tenant_sha256: str, now: float) -> Any:
    from . import ai_evidence_analysis as evidence

    if type(record) is not evidence.EvidenceAnalysisRecord:
        raise AssessmentEvidenceIntegrityError("evidence analysis contract is invalid")
    if (
        not _same(record.tenant_sha256, tenant_sha256)
        or record.status != "review_approved"
        or record.review_decision != "approve"
        or record.human_review_required is not True
        or record.legal_or_compliance_conclusion is not False
        or record.valid_until <= now
        or record.retained_until <= now
    ):
        raise AssessmentEvidenceConflict(
            "evidence analysis is not a current human-approved tenant authority"
        )
    _ref(record.analysis_id, "analysis_id")
    _digest(record.integrity_sha256, "evidence integrity_sha256")
    _digest(record.provenance_sha256, "evidence provenance_sha256")
    return record


def _candidate_citation(record: Any, assessment: Any) -> dict[str, Any]:
    facts = {item.fact_id: item for item in record.extraction.facts}
    fact_refs = []
    for fact_id in assessment.fact_ids:
        fact = facts.get(fact_id)
        if fact is None:
            raise AssessmentEvidenceIntegrityError(
                "evidence assessment references a missing extracted fact"
            )
        fact_refs.append(
            {
                "fact_id": fact.fact_id,
                "fact_sha256": fact.fact_sha256,
                "locator_sha256": fact.locator_sha256,
                "value_sha256": fact.value_sha256,
            }
        )
    return {
        "schema": "lightwork.assessment-evidence-citation.v1",
        "analysis_id": record.analysis_id,
        "analysis_revision": record.revision,
        "analysis_integrity_sha256": record.integrity_sha256,
        "provenance_sha256": record.provenance_sha256,
        "artifact_id": record.artifact.artifact_id,
        "source_ref": record.artifact.source_ref,
        "source_revision": record.artifact.source_revision,
        "content_sha256": record.artifact.content_sha256,
        "criteria_set_id": record.criteria_authority.criteria_set_id,
        "criteria_revision": record.criteria_authority.revision,
        "criteria_authority_sha256": record.criteria_authority.authority_sha256,
        "criterion_id": assessment.criterion_id,
        "criterion_sha256": assessment.criterion_sha256,
        "disposition": assessment.disposition,
        "confidence_bps": assessment.confidence_bps,
        "facts": fact_refs,
    }


def _proposal_candidates(
    assessment: Mapping[str, Any],
    evidence_records: Sequence[Any],
    mapping: AssessmentEvidenceMappingAuthority,
    *,
    max_citations: int,
    min_confidence_bps: int,
) -> list[dict[str, Any]]:
    answers = assessment["answers"]
    by_mapping: dict[
        tuple[str, int, str, str], AssessmentEvidenceMapping
    ] = {
        (
            item.criteria_set_id,
            item.criteria_revision,
            item.criteria_authority_sha256,
            item.criterion_id,
        ): item
        for item in mapping.mappings
    }
    grouped: dict[str, list[tuple[AssessmentEvidenceMapping, Any, Any]]] = {}
    for record in evidence_records:
        authority = record.criteria_authority
        for evidence_assessment in record.adapter_analysis.assessments:
            key = (
                authority.criteria_set_id,
                authority.revision,
                authority.authority_sha256,
                evidence_assessment.criterion_id,
            )
            item = by_mapping.get(key)
            if item is not None:
                grouped.setdefault(item.question_id, []).append(
                    (item, record, evidence_assessment)
                )
    candidates: list[dict[str, Any]] = []
    for question_id in sorted(grouped):
        if question_id in answers:
            continue
        rows = grouped[question_id]
        if len(rows) > max_citations:
            raise AssessmentEvidenceValidationError(
                "evidence citations exceed the per-answer bound"
            )
        supported_answers = {
            item.supported_answer
            for item, _record, result in rows
            if result.disposition == "evidence_supported"
        }
        all_supported = all(
            result.disposition == "evidence_supported" for _item, _record, result in rows
        )
        flags: list[str] = ["human_review_required"]
        if all_supported and len(supported_answers) == 1:
            answer = next(iter(supported_answers))
            confidence_bps = min(result.confidence_bps for _item, _record, result in rows)
        else:
            answer = "unknown"
            confidence_bps = min(result.confidence_bps for _item, _record, result in rows)
            dispositions = {result.disposition for _item, _record, result in rows}
            if len(supported_answers) > 1 or (
                "evidence_supported" in dispositions and len(dispositions) > 1
            ):
                flags.append("source_conflict")
            if "evidence_partial" in dispositions:
                flags.append("source_incomplete")
            if dispositions.intersection({"evidence_missing", "indeterminate"}):
                flags.append("source_incomplete")
        if confidence_bps < min_confidence_bps:
            flags.append("low_confidence")
        citations = [
            _candidate_citation(record, result) for _item, record, result in rows
        ]
        candidate = {
            "schema": "lightwork.assessment-evidence-answer-proposal.v1",
            "question_id": question_id,
            "answer": answer,
            "confidence_bps": confidence_bps,
            "flags": sorted(set(flags)),
            "eligible_for_apply": (
                answer != "unknown"
                and confidence_bps >= min_confidence_bps
                and not set(flags).intersection(
                    {"source_conflict", "source_incomplete", "low_confidence"}
                )
            ),
            "citations": citations,
        }
        candidate["candidate_sha256"] = _sha256(candidate)
        candidates.append(candidate)
    if not candidates:
        raise AssessmentEvidenceValidationError(
            "no unanswered assessment question has mapped evidence"
        )
    return candidates


def _proposal_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": PROPOSAL_SCHEMA,
        "tenant_sha256": record["tenant_sha256"],
        "assessment": record["assessment"],
        "evidence": record["evidence"],
        "mapping_authority": record["mapping_authority"],
        "candidates": record["candidates"],
        "notice": record["notice"],
    }


def _validate_operation_receipts(value: object) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > _MAX_OPERATIONS:
        raise AssessmentEvidenceIntegrityError("proposal operation receipts are invalid")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise AssessmentEvidenceIntegrityError("proposal operation receipt is invalid")
        row = dict(item)
        if set(row) != {"action", "idempotency_sha256", "request_sha256", "actor_sha256"}:
            raise AssessmentEvidenceIntegrityError("proposal operation receipt is invalid")
        if row["action"] not in {"approve", "reject", "apply", "expire"}:
            raise AssessmentEvidenceIntegrityError("proposal operation receipt is invalid")
        for key in ("idempotency_sha256", "request_sha256", "actor_sha256"):
            _digest(row[key], key)
        if row["idempotency_sha256"] in seen:
            raise AssessmentEvidenceIntegrityError("proposal idempotency receipt is duplicated")
        seen.add(row["idempotency_sha256"])
        output.append(row)
    return output


def _lifecycle_sha256(value: Mapping[str, Any], digest_field: str) -> str:
    payload = dict(value)
    payload.pop(digest_field, None)
    return _sha256(payload)


def _validated_record(record: object, tenant_sha256: str) -> dict[str, Any]:  # noqa: C901
    if not isinstance(record, Mapping):
        raise AssessmentEvidenceIntegrityError("assessment evidence proposal is invalid")
    value = dict(record)
    required = {
        "id",
        "schema",
        "tenant_sha256",
        "assessment",
        "evidence",
        "mapping_authority",
        "candidates",
        "proposal_sha256",
        "request_sha256",
        "created_by_sha256",
        "status",
        "review",
        "application",
        "operations",
        "retained_until",
        "notice",
        "created_at",
        "updated_at",
        "revision",
    }
    optional = {"_audit_pending", "expired_payload_sha256", "expired_at"}
    if not required.issubset(value) or set(value).difference(required | optional):
        raise AssessmentEvidenceIntegrityError("assessment evidence proposal shape is invalid")
    _ref(value["id"], "proposal_id")
    _digest(value["tenant_sha256"], "proposal tenant_sha256")
    _digest(value["proposal_sha256"], "proposal_sha256")
    _digest(value["request_sha256"], "request_sha256")
    _digest(value["created_by_sha256"], "created_by_sha256")
    _integer(value["revision"], "proposal revision", 1, 2**63 - 1)
    _timestamp(value["created_at"], "proposal created_at")
    _timestamp(value["updated_at"], "proposal updated_at")
    _timestamp(value["retained_until"], "proposal retained_until")
    if (
        value["schema"] != PROPOSAL_SCHEMA
        or value["notice"] != NOTICE
        or not _same(value["tenant_sha256"], tenant_sha256)
        or value["status"] not in _STATUSES
    ):
        raise AssessmentEvidenceIntegrityError("assessment evidence proposal boundary is invalid")
    _validate_operation_receipts(value["operations"])
    assessment = value["assessment"]
    if not isinstance(assessment, Mapping) or set(assessment) != {
        "id",
        "revision",
        "type",
        "template_revision",
        "template_digest",
        "answers_sha256",
    }:
        raise AssessmentEvidenceIntegrityError("proposal assessment authority is invalid")
    _ref(assessment["id"], "assessment_id")
    _integer(assessment["revision"], "assessment revision", 1, 2**63 - 1)
    _integer(assessment["template_revision"], "template revision", 0, 2**63 - 1)
    _digest(assessment["template_digest"], "template_digest")
    _digest(assessment["answers_sha256"], "answers_sha256")
    mapping = _mapping_authority_from_payload(value["mapping_authority"])
    if (
        not _same(mapping.tenant_sha256, tenant_sha256)
        or mapping.assessment_type != assessment["type"]
        or not _same(mapping.template_digest, assessment["template_digest"])
    ):
        raise AssessmentEvidenceIntegrityError("proposal mapping authority is misbound")
    evidence_refs = value["evidence"]
    if not isinstance(evidence_refs, list) or not 1 <= len(evidence_refs) <= _MAX_ANALYSES:
        raise AssessmentEvidenceIntegrityError("proposal evidence authorities are invalid")
    for item in evidence_refs:
        if not isinstance(item, Mapping) or set(item) != {
            "analysis_id",
            "revision",
            "integrity_sha256",
            "provenance_sha256",
            "valid_until",
        }:
            raise AssessmentEvidenceIntegrityError("proposal evidence authority is invalid")
        _ref(item["analysis_id"], "analysis_id")
        _integer(item["revision"], "analysis revision", 1, 2**63 - 1)
        _digest(item["integrity_sha256"], "analysis integrity_sha256")
        _digest(item["provenance_sha256"], "analysis provenance_sha256")
        _timestamp(item["valid_until"], "analysis valid_until")
    if value["status"] == "expired":
        if value["candidates"] != [] or value["review"] is not None or value["application"] is not None:
            raise AssessmentEvidenceIntegrityError("expired proposal retained sensitive material")
        _digest(value.get("expired_payload_sha256"), "expired_payload_sha256")
    else:
        candidates = value["candidates"]
        if not isinstance(candidates, list) or not 1 <= len(candidates) <= _MAX_CANDIDATES:
            raise AssessmentEvidenceIntegrityError("proposal candidates are invalid")
        question_ids: set[str] = set()
        for item in candidates:
            if not isinstance(item, Mapping):
                raise AssessmentEvidenceIntegrityError("proposal candidate is invalid")
            candidate = dict(item)
            claimed = candidate.pop("candidate_sha256", None)
            _digest(claimed, "candidate_sha256")
            if not _same(claimed, _sha256(candidate)):
                raise AssessmentEvidenceIntegrityError("proposal candidate digest is invalid")
            question_id = _question(candidate.get("question_id"))
            if question_id in question_ids:
                raise AssessmentEvidenceIntegrityError("proposal question is duplicated")
            question_ids.add(question_id)
            if candidate.get("answer") not in _ANSWERS:
                raise AssessmentEvidenceIntegrityError("proposal answer is invalid")
            _integer(candidate.get("confidence_bps"), "candidate confidence", 0, 10_000)
            if type(candidate.get("eligible_for_apply")) is not bool:
                raise AssessmentEvidenceIntegrityError("proposal eligibility is invalid")
            citations = candidate.get("citations")
            if not isinstance(citations, list) or not 1 <= len(citations) <= _MAX_CITATIONS:
                raise AssessmentEvidenceIntegrityError("proposal citations are invalid")
        if not _same(value["proposal_sha256"], _sha256(_proposal_payload(value))):
            raise AssessmentEvidenceIntegrityError("proposal digest is invalid")
    review = value["review"]
    application = value["application"]
    if value["status"] == "pending_review" and (review is not None or application is not None):
        raise AssessmentEvidenceIntegrityError("pending proposal has terminal material")
    if value["status"] in {"approved", "applied", "rejected"}:
        if not isinstance(review, Mapping) or set(review) != {
            "decision",
            "selected_question_ids",
            "rationale",
            "rationale_sha256",
            "reviewer_sha256",
            "reviewed_at",
            "review_sha256",
        } or review.get("decision") not in {"approve", "reject"}:
            raise AssessmentEvidenceIntegrityError("reviewed proposal lacks review material")
        _digest(review.get("reviewer_sha256"), "reviewer_sha256")
        _digest(review.get("rationale_sha256"), "rationale_sha256")
        _digest(review.get("review_sha256"), "review_sha256")
        _timestamp(review.get("reviewed_at"), "reviewed_at")
        rationale = review.get("rationale")
        if not isinstance(rationale, str) or not _same(
            review["rationale_sha256"],
            hashlib.sha256(rationale.encode()).hexdigest(),
        ) or not _same(
            review["review_sha256"],
            _lifecycle_sha256(review, "review_sha256"),
        ):
            raise AssessmentEvidenceIntegrityError("proposal review digest is invalid")
        selected = review.get("selected_question_ids")
        if not isinstance(selected, list) or len(selected) > _MAX_CANDIDATES:
            raise AssessmentEvidenceIntegrityError("review selection is invalid")
        if review["decision"] == "approve" and not selected:
            raise AssessmentEvidenceIntegrityError("approved proposal has no selected questions")
        if review["decision"] == "reject" and selected:
            raise AssessmentEvidenceIntegrityError("rejected proposal selected questions")
        candidates_by_id = {
            item["question_id"]: item
            for item in value["candidates"]
            if isinstance(item, Mapping) and isinstance(item.get("question_id"), str)
        }
        if any(
            question_id not in candidates_by_id
            or candidates_by_id[question_id].get("eligible_for_apply") is not True
            for question_id in selected
        ):
            raise AssessmentEvidenceIntegrityError("review selection is not eligible")
    if value["status"] == "applied":
        if not isinstance(application, Mapping) or set(application) != {
            "assessment_revision",
            "applied_question_ids",
            "assessment_result_sha256",
            "applied_by_sha256",
            "applied_at",
            "application_sha256",
        }:
            raise AssessmentEvidenceIntegrityError("applied proposal lacks application result")
        _integer(application.get("assessment_revision"), "applied assessment revision", 1, 2**63 - 1)
        _digest(application.get("assessment_result_sha256"), "assessment_result_sha256")
        _digest(application.get("applied_by_sha256"), "applied_by_sha256")
        _digest(application.get("application_sha256"), "application_sha256")
        _timestamp(application.get("applied_at"), "applied_at")
        applied_questions = application.get("applied_question_ids")
        if (
            not isinstance(applied_questions, list)
            or applied_questions != review["selected_question_ids"]
            or not _same(
                application["application_sha256"],
                _lifecycle_sha256(application, "application_sha256"),
            )
        ):
            raise AssessmentEvidenceIntegrityError("proposal application digest is invalid")
    elif application is not None:
        raise AssessmentEvidenceIntegrityError("non-applied proposal has application material")
    return value


def _proposal_id(tenant_sha256: str, assessment_id: str, idempotency_sha256: str) -> str:
    identity = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"lightwork:assessment-evidence:{tenant_sha256}:{assessment_id}:{idempotency_sha256}",
    )
    return f"AEP-{identity.hex}"


def _receipt(
    *, action: str, idempotency_sha256: str, request_sha256: str, actor: str
) -> dict[str, str]:
    return {
        "action": action,
        "idempotency_sha256": idempotency_sha256,
        "request_sha256": request_sha256,
        "actor_sha256": hashlib.sha256(actor.encode("utf-8")).hexdigest(),
    }


def _replay(record: Mapping[str, Any], idem_sha: str, request_sha: str, action: str) -> bool:
    for item in _validate_operation_receipts(record.get("operations")):
        if item["idempotency_sha256"] != idem_sha:
            continue
        if item["action"] != action or not _same(item["request_sha256"], request_sha):
            raise AssessmentEvidenceConflict(
                "idempotency_key was already used for a different operation"
            )
        return True
    return False


def apply_answers_to_assessment(  # noqa: C901
    assessment_id: str,
    candidates: Sequence[Mapping[str, Any]],
    *,
    proposal_id: str,
    proposal_sha256: str,
    actor: str,
    expected_revision: int,
) -> AssessmentApplyResult:
    """CAS-fill unanswered assessment questions from one approved proposal."""

    from . import assessment as assessment_ops

    selected_actor = _actor(actor)
    selected_id = _ref(assessment_id, "assessment_id")
    expected = _integer(expected_revision, "expected assessment revision", 1, 2**63 - 1)
    _ref(proposal_id, "proposal_id")
    _digest(proposal_sha256, "proposal_sha256")
    if not 1 <= len(candidates) <= _MAX_CANDIDATES:
        raise AssessmentEvidenceValidationError("approved answer selection is invalid")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in candidates:
        if not isinstance(raw, Mapping):
            raise AssessmentEvidenceValidationError("approved answer selection is invalid")
        question_id = _question(raw.get("question_id"))
        if question_id in seen or raw.get("answer") not in _ANSWERS - {"unknown"}:
            raise AssessmentEvidenceValidationError("approved answer selection is invalid")
        if raw.get("eligible_for_apply") is not True:
            raise AssessmentEvidenceValidationError("ineligible answer cannot be applied")
        _integer(raw.get("confidence_bps"), "candidate confidence", 1, 10_000)
        _digest(raw.get("candidate_sha256"), "candidate_sha256")
        seen.add(question_id)
        normalized.append(dict(raw))

    applied_ids = tuple(sorted(seen))

    # Crash recovery for the only cross-store window: the assessment write may
    # commit before the proposal's application receipt.  An exact retry is a
    # no-change success only when every answer carries the applier-only receipt
    # written in the same assessment CAS. The public AI-metadata endpoint can
    # author source labels, so source metadata alone is never recovery proof.
    current = assessment_ops.load_saved(selected_id)
    if current is None:
        raise AssessmentEvidenceNotFound("assessment is unavailable")
    current_revision = current.get("revision")
    if isinstance(current_revision, int) and not isinstance(current_revision, bool):
        if current_revision > expected:
            existing_answers = current.get("answers")
            if isinstance(existing_answers, Mapping) and all(
                isinstance(existing_answers.get(candidate["question_id"]), Mapping)
                and existing_answers[candidate["question_id"]].get("answer")
                == candidate["answer"]
                and isinstance(
                    existing_answers[candidate["question_id"]].get("ai_metadata"),
                    Mapping,
                )
                and existing_answers[candidate["question_id"]]["ai_metadata"].get(
                    "source"
                )
                == {
                    "kind": "document_evidence",
                    "ref": proposal_id,
                    "sha256": proposal_sha256,
                }
                and existing_answers[candidate["question_id"]]["ai_metadata"].get(
                    "application_receipt"
                )
                == _answer_application_receipt(
                    proposal_id=proposal_id,
                    proposal_sha256=proposal_sha256,
                    candidate=candidate,
                )
                for candidate in normalized
            ):
                return AssessmentApplyResult(
                    assessment_id=selected_id,
                    assessment_revision=current_revision,
                    applied_question_ids=applied_ids,
                    assessment_result_sha256=_sha256(current.get("result")),
                )
            raise AssessmentEvidenceConflict(
                "assessment changed after the proposal was generated"
            )
        if current_revision < expected:
            raise AssessmentEvidenceConflict("assessment revision regressed")

    def mutate(record: dict[str, Any]) -> None:
        if record.get("status") not in {"pending_review", "needs_more"}:
            raise AssessmentEvidenceTransitionError(
                "only an open assessment can receive approved proposed answers"
            )
        template = assessment_ops.template_for_saved_record(record)
        if template is None:
            raise AssessmentEvidenceIntegrityError("assessment questionnaire is unavailable")
        answers = record.get("answers")
        if not isinstance(answers, dict):
            raise AssessmentEvidenceIntegrityError("assessment answers are invalid")
        for candidate in normalized:
            question_id = candidate["question_id"]
            if template.question(question_id) is None:
                raise AssessmentEvidenceConflict("proposal question no longer exists")
            if question_id in answers:
                raise AssessmentEvidenceConflict(
                    "proposal application refuses to overwrite an existing answer"
                )
            citation_digests = [
                _sha256(citation) for citation in candidate.get("citations") or []
            ]
            answers[question_id] = {
                "answer": candidate["answer"],
                "note": (
                    "Applied after independent review from governed evidence proposal "
                    f"{proposal_id}; verify cited source authorities before final assessment approval."
                ),
                "ai_metadata": {
                    "schema": "lightwork.assessment-answer-ai-metadata.v1",
                    "confidence": round(candidate["confidence_bps"] / 10_000, 6),
                    "flags": ["human_review_required"],
                    "source": {
                        "kind": "document_evidence",
                        "ref": proposal_id,
                        "sha256": proposal_sha256,
                    },
                    "citation_sha256": citation_digests,
                    "application_receipt": _answer_application_receipt(
                        proposal_id=proposal_id,
                        proposal_sha256=proposal_sha256,
                        candidate=candidate,
                    ),
                    "recorded_by": selected_actor,
                    "recorded_at": time.time(),
                    "answer_at_recording": candidate["answer"],
                },
            }
        session = assessment_ops.AssessmentSession(
            type=str(record.get("type") or ""),
            subject=str(record.get("subject") or ""),
            id=selected_id,
            created_at=float(record.get("created_at") or time.time()),
            template_revision=int(record.get("template_revision")),
            template_digest=str(record.get("template_digest")),
            template_snapshot=dict(record.get("template_snapshot") or {}),
            answers=json.loads(json.dumps(answers)),
        )
        record["result"] = asdict(session.evaluate())
        record["status"] = "pending_review"

    receipt = assessment_ops._audit_receipt(  # noqa: SLF001 - same-package authority bridge
        "ASSESSMENT_EVIDENCE_PROPOSAL_APPLIED",
        selected_actor,
        assessment=selected_id,
        proposal_id=proposal_id,
        proposal_sha256=proposal_sha256,
        question_ids=list(applied_ids),
    )
    try:
        saved = assessment_ops._rewrite_saved(  # noqa: SLF001 - atomic assessment CAS primitive
            selected_id,
            mutate,
            expected_revision=expected,
            audit_receipt=receipt,
        )
    except assessment_ops.AssessmentConflict as exc:
        raise AssessmentEvidenceConflict(str(exc)) from exc
    except assessment_ops.AssessmentStateError as exc:
        raise AssessmentEvidenceIntegrityError(str(exc)) from exc
    if saved is None:
        raise AssessmentEvidenceNotFound("assessment is unavailable")
    result_sha = _sha256(saved.get("result"))
    return AssessmentApplyResult(
        assessment_id=selected_id,
        assessment_revision=int(saved["revision"]),
        applied_question_ids=applied_ids,
        assessment_result_sha256=result_sha,
    )


class AssessmentEvidenceService:
    """Tenant-bound production service over independently resolved authorities."""

    def __init__(
        self,
        *,
        tenant_id: str,
        settings: AssessmentEvidenceSettings,
        assessment_resolver: Callable[[str], Mapping[str, Any] | None],
        evidence_resolver: Callable[[str], Any],
        mapping_resolver: Callable[
            [str, Mapping[str, Any], Sequence[Any], float],
            AssessmentEvidenceMappingAuthority,
        ] | None = None,
        assessment_applier: Callable[..., AssessmentApplyResult] = apply_answers_to_assessment,
        store: GovernedRecordStore | None = None,
        clock: Callable[[], float] = time.time,
        config_gate: Callable[[], None] | None = None,
    ) -> None:
        from .paths import canonical_tenant_id

        self.tenant_id = canonical_tenant_id(tenant_id)
        self.tenant_sha256 = _tenant_digest(self.tenant_id)
        if type(settings) is not AssessmentEvidenceSettings:
            raise TypeError("settings must be AssessmentEvidenceSettings")
        for dependency in (assessment_resolver, evidence_resolver, assessment_applier, clock):
            if not callable(dependency):
                raise TypeError("assessment evidence dependency must be callable")
        if mapping_resolver is not None and not callable(mapping_resolver):
            raise TypeError("mapping_resolver must be callable")
        if config_gate is not None and not callable(config_gate):
            raise TypeError("config_gate must be callable")
        self.settings = settings
        self._assessment_resolver = assessment_resolver
        self._evidence_resolver = evidence_resolver
        self._mapping_resolver = mapping_resolver
        self._assessment_applier = assessment_applier
        self._store = store or _PROPOSALS
        self._clock = clock
        self._config_gate = config_gate

    def _gate(self) -> float:
        if self._config_gate is not None:
            self._config_gate()
        return _timestamp(self._clock(), "clock")

    def _evidence(self, analysis_ids: Sequence[str], now: float) -> tuple[Any, ...]:
        if (
            isinstance(analysis_ids, (str, bytes))
            or not isinstance(analysis_ids, Sequence)
            or not 1 <= len(analysis_ids) <= self.settings.max_evidence_records_per_proposal
        ):
            raise AssessmentEvidenceValidationError("analysis_ids are invalid")
        selected = tuple(_ref(value, "analysis_id") for value in analysis_ids)
        if len(set(selected)) != len(selected):
            raise AssessmentEvidenceValidationError("analysis_ids must be unique")
        records: list[Any] = []
        for analysis_id in selected:
            try:
                record = self._evidence_resolver(analysis_id)
            except AssessmentEvidenceError:
                raise
            except Exception as exc:
                raise AssessmentEvidenceConfigError(
                    "evidence analysis authority is unavailable"
                ) from exc
            records.append(_validate_evidence_record(record, self.tenant_sha256, now))
        return tuple(records)

    def create_proposal(
        self,
        assessment_id: str,
        analysis_ids: Sequence[str],
        *,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        now = self._gate()
        selected_actor = _actor(actor)
        selected_assessment_id = _ref(assessment_id, "assessment_id")
        _key, idem_sha = _operation(idempotency_key)
        request_sha = _sha256(
            {
                "assessment_id": selected_assessment_id,
                "analysis_ids": list(analysis_ids),
            }
        )
        proposal_id = _proposal_id(
            self.tenant_sha256, selected_assessment_id, idem_sha
        )
        existing = self._store.get(proposal_id)
        if existing is not None:
            validated = _validated_record(existing, self.tenant_sha256)
            if not _same(validated["request_sha256"], request_sha):
                raise AssessmentEvidenceConflict(
                    "idempotency_key was already used for a different proposal"
                )
            return validated
        try:
            resolved = self._assessment_resolver(selected_assessment_id)
        except AssessmentEvidenceError:
            raise
        except Exception as exc:
            raise AssessmentEvidenceConfigError("assessment authority is unavailable") from exc
        assessment = _validate_assessment(resolved, selected_assessment_id)
        records = self._evidence(analysis_ids, now)
        if self._mapping_resolver is None:
            mapping = derive_exact_mapping_authority(
                self.tenant_id,
                assessment,
                records,
                now=now,
            )
        else:
            try:
                mapping = self._mapping_resolver(
                    self.tenant_id,
                    assessment,
                    records,
                    now,
                )
            except AssessmentEvidenceError:
                raise
            except Exception as exc:
                raise AssessmentEvidenceConfigError(
                    "assessment evidence mapping authority is unavailable"
                ) from exc
        mapping = _validate_mapping_authority(
            mapping,
            tenant_sha256=self.tenant_sha256,
            assessment=assessment,
            evidence_records=records,
            now=now,
        )
        candidates = _proposal_candidates(
            assessment,
            records,
            mapping,
            max_citations=self.settings.max_citations_per_answer,
            min_confidence_bps=self.settings.min_confidence_bps,
        )
        evidence_refs = [
            {
                "analysis_id": record.analysis_id,
                "revision": record.revision,
                "integrity_sha256": record.integrity_sha256,
                "provenance_sha256": record.provenance_sha256,
                "valid_until": record.valid_until,
            }
            for record in records
        ]
        evidence_refs.sort(key=lambda item: item["analysis_id"])
        record: dict[str, Any] = {
            "id": proposal_id,
            "schema": PROPOSAL_SCHEMA,
            "tenant_sha256": self.tenant_sha256,
            "assessment": {
                "id": selected_assessment_id,
                "revision": assessment["revision"],
                "type": assessment["type"],
                "template_revision": assessment["template_revision"],
                "template_digest": assessment["template_digest"],
                "answers_sha256": _sha256(assessment["answers"]),
            },
            "evidence": evidence_refs,
            "mapping_authority": asdict(mapping),
            "candidates": candidates,
            "proposal_sha256": "0" * 64,
            "request_sha256": request_sha,
            "created_by_sha256": hashlib.sha256(selected_actor.encode("utf-8")).hexdigest(),
            "status": "pending_review",
            "review": None,
            "application": None,
            "operations": [],
            "retained_until": now + self.settings.retention_seconds,
            "notice": NOTICE,
        }
        record["proposal_sha256"] = _sha256(_proposal_payload(record))
        try:
            saved = self._store.create(
                record,
                action="create_assessment_evidence_proposal",
                actor=selected_actor,
                max_records=self.settings.max_records,
            )
        except Exception as exc:
            # A same-key concurrent create is an exact replay only when its
            # independently committed request digest matches.
            current = self._store.get(proposal_id)
            if current is not None:
                validated = _validated_record(current, self.tenant_sha256)
                if _same(validated["request_sha256"], request_sha):
                    return validated
            raise AssessmentEvidenceConflict("proposal create conflicted") from exc
        return _validated_record(saved, self.tenant_sha256)

    def get_proposal(self, proposal_id: str) -> dict[str, Any]:
        self._gate()
        selected = _ref(proposal_id, "proposal_id")
        record = self._store.get(selected)
        if record is None:
            raise AssessmentEvidenceNotFound("assessment evidence proposal is unavailable")
        return _validated_record(record, self.tenant_sha256)

    def list_proposals(self, *, limit: int = 100) -> list[dict[str, Any]]:
        self._gate()
        bounded = _integer(limit, "list limit", 1, 500)
        rows = [
            _validated_record(row, self.tenant_sha256)
            for row in self._store.list(limit=bounded)
        ]
        rows.sort(key=lambda row: (float(row["created_at"]), row["id"]), reverse=True)
        return rows[:bounded]

    def review_proposal(
        self,
        proposal_id: str,
        *,
        decision: Literal["approve", "reject"],
        selected_question_ids: Sequence[str],
        rationale: str,
        actor: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        now = self._gate()
        selected_id = _ref(proposal_id, "proposal_id")
        reviewer = _actor(actor)
        expected = _integer(expected_revision, "expected proposal revision", 1, 2**63 - 1)
        if decision not in {"approve", "reject"}:
            raise AssessmentEvidenceValidationError("review decision is invalid")
        if isinstance(selected_question_ids, (str, bytes)) or not isinstance(
            selected_question_ids, Sequence
        ):
            raise AssessmentEvidenceValidationError("review question selection is invalid")
        questions = tuple(sorted(_question(value) for value in selected_question_ids))
        if len(questions) != len(set(questions)) or len(questions) > _MAX_CANDIDATES:
            raise AssessmentEvidenceValidationError("review question selection is invalid")
        why = _rationale(rationale)
        _key, idem_sha = _operation(idempotency_key)
        request_sha = _sha256(
            {
                "decision": decision,
                "selected_question_ids": list(questions),
                "rationale": why,
            }
        )
        current = self.get_proposal(selected_id)
        if _replay(current, idem_sha, request_sha, decision):
            return current
        if current["status"] != "pending_review":
            raise AssessmentEvidenceTransitionError("only a pending proposal can be reviewed")
        creator_sha = current["created_by_sha256"]
        reviewer_sha = hashlib.sha256(reviewer.encode("utf-8")).hexdigest()
        if _same(creator_sha, reviewer_sha):
            raise AssessmentEvidenceTransitionError(
                "proposal creator cannot approve or reject the same proposal"
            )
        candidates = {item["question_id"]: item for item in current["candidates"]}
        if decision == "approve":
            if not questions or any(
                question not in candidates
                or candidates[question]["eligible_for_apply"] is not True
                for question in questions
            ):
                raise AssessmentEvidenceValidationError(
                    "approval must select one or more eligible proposal questions"
                )
        elif questions:
            raise AssessmentEvidenceValidationError(
                "rejected proposal cannot select answer questions"
            )
        receipt = _receipt(
            action=decision,
            idempotency_sha256=idem_sha,
            request_sha256=request_sha,
            actor=reviewer,
        )

        def mutate(record: dict[str, Any]) -> None:
            validated = _validated_record(record, self.tenant_sha256)
            if validated["status"] != "pending_review":
                raise AssessmentEvidenceTransitionError(
                    "only a pending proposal can be reviewed"
                )
            record["status"] = "approved" if decision == "approve" else "rejected"
            review_record = {
                "decision": decision,
                "selected_question_ids": list(questions),
                "rationale": why,
                "rationale_sha256": hashlib.sha256(why.encode("utf-8")).hexdigest(),
                "reviewer_sha256": reviewer_sha,
                "reviewed_at": now,
            }
            review_record["review_sha256"] = _lifecycle_sha256(
                review_record,
                "review_sha256",
            )
            record["review"] = review_record
            record["operations"] = [*validated["operations"], receipt]

        try:
            saved = self._store.update(
                selected_id,
                mutate,
                expected_revision=expected,
                action=f"{decision}_assessment_evidence_proposal",
                actor=reviewer,
            )
        except AssessmentEvidenceError:
            raise
        except Exception as exc:
            raise AssessmentEvidenceConflict("proposal changed during review") from exc
        if saved is None:
            raise AssessmentEvidenceNotFound("assessment evidence proposal is unavailable")
        return _validated_record(saved, self.tenant_sha256)

    def apply_proposal(
        self,
        proposal_id: str,
        *,
        actor: str,
        expected_revision: int,
        expected_assessment_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        now = self._gate()
        if not self.settings.apply_enabled:
            raise AssessmentEvidenceConfigError("assessment evidence application is disabled")
        selected_id = _ref(proposal_id, "proposal_id")
        operator = _actor(actor)
        expected = _integer(expected_revision, "expected proposal revision", 1, 2**63 - 1)
        expected_assessment = _integer(
            expected_assessment_revision,
            "expected assessment revision",
            1,
            2**63 - 1,
        )
        _key, idem_sha = _operation(idempotency_key)
        request_sha = _sha256(
            {
                "proposal_id": selected_id,
                "expected_assessment_revision": expected_assessment,
            }
        )
        current = self.get_proposal(selected_id)
        if _replay(current, idem_sha, request_sha, "apply"):
            return current
        if current["status"] != "approved":
            raise AssessmentEvidenceTransitionError("only an approved proposal can be applied")
        if expected_assessment != current["assessment"]["revision"]:
            raise AssessmentEvidenceConflict(
                "proposal is not pinned to the expected assessment revision"
            )
        # Re-resolve every evidence authority immediately before mutation so a
        # review cannot race revocation, expiry, or replacement.
        resolved = self._evidence(
            [item["analysis_id"] for item in current["evidence"]], now
        )
        exact = {record.analysis_id: record for record in resolved}
        for pinned in current["evidence"]:
            record = exact.get(pinned["analysis_id"])
            if (
                record is None
                or record.revision != pinned["revision"]
                or not _same(record.integrity_sha256, pinned["integrity_sha256"])
                or not _same(record.provenance_sha256, pinned["provenance_sha256"])
            ):
                raise AssessmentEvidenceConflict(
                    "evidence analysis changed after proposal review"
                )
        review = current["review"]
        chosen = set(review["selected_question_ids"])
        candidates = [
            item for item in current["candidates"] if item["question_id"] in chosen
        ]
        try:
            result = self._assessment_applier(
                current["assessment"]["id"],
                candidates,
                proposal_id=selected_id,
                proposal_sha256=current["proposal_sha256"],
                actor=operator,
                expected_revision=expected_assessment,
            )
        except AssessmentEvidenceError:
            raise
        except Exception as exc:
            raise AssessmentEvidenceConfigError(
                "assessment proposal application authority is unavailable"
            ) from exc
        if type(result) is not AssessmentApplyResult:
            raise AssessmentEvidenceIntegrityError(
                "assessment application result contract is invalid"
            )
        if (
            result.assessment_id != current["assessment"]["id"]
            or tuple(sorted(chosen)) != result.applied_question_ids
            or result.assessment_revision <= expected_assessment
        ):
            raise AssessmentEvidenceIntegrityError(
                "assessment application result is misbound"
            )
        receipt = _receipt(
            action="apply",
            idempotency_sha256=idem_sha,
            request_sha256=request_sha,
            actor=operator,
        )

        def mutate(record: dict[str, Any]) -> None:
            validated = _validated_record(record, self.tenant_sha256)
            if validated["status"] != "approved":
                raise AssessmentEvidenceTransitionError(
                    "only an approved proposal can be applied"
                )
            record["status"] = "applied"
            application_record = {
                "assessment_revision": result.assessment_revision,
                "applied_question_ids": list(result.applied_question_ids),
                "assessment_result_sha256": result.assessment_result_sha256,
                "applied_by_sha256": hashlib.sha256(operator.encode("utf-8")).hexdigest(),
                "applied_at": now,
            }
            application_record["application_sha256"] = _lifecycle_sha256(
                application_record,
                "application_sha256",
            )
            record["application"] = application_record
            record["operations"] = [*validated["operations"], receipt]

        try:
            saved = self._store.update(
                selected_id,
                mutate,
                expected_revision=expected,
                action="apply_assessment_evidence_proposal",
                actor=operator,
            )
        except AssessmentEvidenceError:
            raise
        except Exception as exc:
            # The assessment CAS already committed. Surface an explicit
            # recoverable conflict; idempotent reconciliation can compare the
            # assessment's proposal source metadata before retrying the record.
            raise AssessmentEvidenceConflict(
                "assessment answers committed but proposal receipt needs reconciliation"
            ) from exc
        if saved is None:
            raise AssessmentEvidenceNotFound("assessment evidence proposal is unavailable")
        return _validated_record(saved, self.tenant_sha256)

    def purge_expired(self, *, actor: str = "system", limit: int = 100) -> tuple[str, ...]:
        now = self._gate()
        operator = _actor(actor)
        bounded = _integer(limit, "purge limit", 1, 500)
        # A previously expired row may have retained its tombstone because the
        # audit sink was unavailable. Retry delivery before deciding whether it
        # is safe to remove the only durable copy of that receipt.
        self._store.retry_pending(limit=bounded)
        candidates = [
            _validated_record(row, self.tenant_sha256)
            for row in self._store.list(limit=self.settings.max_records + 1)
        ]
        candidates.sort(key=lambda row: (row["retained_until"], row["id"]))
        purged: list[str] = []
        for current in candidates:
            if len(purged) >= bounded or current["retained_until"] > now:
                continue
            if current["status"] == "expired":
                if current.get("_audit_pending"):
                    continue
                if self._store.delete(
                    current["id"], expected_revision=current["revision"]
                ):
                    purged.append(current["id"])
                continue
            request_sha = _sha256(
                {"proposal_id": current["id"], "retained_until": current["retained_until"]}
            )
            idem_sha = hashlib.sha256(
                f"expire:{current['id']}:{current['retained_until']}".encode()
            ).hexdigest()
            receipt = _receipt(
                action="expire",
                idempotency_sha256=idem_sha,
                request_sha256=request_sha,
                actor=operator,
            )

            def mutate(
                record: dict[str, Any],
                operation_receipt: dict[str, str] = receipt,
                expired_at: float = now,
            ) -> None:
                validated = _validated_record(record, self.tenant_sha256)
                record["status"] = "expired"
                record["expired_payload_sha256"] = validated["proposal_sha256"]
                record["expired_at"] = expired_at
                record["candidates"] = []
                record["review"] = None
                record["application"] = None
                record["operations"] = [
                    *validated["operations"],
                    operation_receipt,
                ]

            saved = self._store.update(
                current["id"],
                mutate,
                expected_revision=current["revision"],
                action="expire_assessment_evidence_proposal",
                actor=operator,
            )
            if saved is not None:
                expired = _validated_record(saved, self.tenant_sha256)
                if not expired.get("_audit_pending") and self._store.delete(
                    current["id"], expected_revision=expired["revision"]
                ):
                    purged.append(current["id"])
        return tuple(purged)

    def verify_integrity(self) -> AssessmentEvidenceIntegrityReport:
        self._gate()
        rows = self._store.list(limit=self.settings.max_records + 1)
        if len(rows) > self.settings.max_records:
            raise AssessmentEvidenceIntegrityError("proposal namespace exceeds its configured bound")
        counts = dict.fromkeys(_STATUSES, 0)
        pending_audit = 0
        tips: list[str] = []
        for row in rows:
            validated = _validated_record(row, self.tenant_sha256)
            counts[validated["status"]] += 1
            pending = validated.get("_audit_pending") or []
            if not isinstance(pending, list):
                raise AssessmentEvidenceIntegrityError("proposal audit outbox is invalid")
            pending_audit += len(pending)
            tips.append(
                _sha256(
                    {
                        "id": validated["id"],
                        "revision": validated["revision"],
                        "proposal_sha256": validated["proposal_sha256"],
                        "status": validated["status"],
                    }
                )
            )
        return AssessmentEvidenceIntegrityReport(
            schema=INTEGRITY_SCHEMA,
            tenant_sha256=self.tenant_sha256,
            records=len(rows),
            pending_review=counts["pending_review"],
            approved=counts["approved"],
            applied=counts["applied"],
            rejected=counts["rejected"],
            expired=counts["expired"],
            pending_audit_receipts=pending_audit,
            terminal_sha256=_sha256(tips),
            verified=True,
        )

    def status(self) -> dict[str, Any]:
        report = self.verify_integrity()
        return {
            "schema": "lightwork.assessment-evidence-status.v1",
            "tenant_sha256": self.tenant_sha256,
            "enabled": True,
            "ready": report.verified and report.pending_audit_receipts == 0,
            "integrity": asdict(report),
            "limits": {
                "max_records": self.settings.max_records,
                "max_evidence_records_per_proposal": (
                    self.settings.max_evidence_records_per_proposal
                ),
                "max_citations_per_answer": self.settings.max_citations_per_answer,
                "min_confidence_bps": self.settings.min_confidence_bps,
                "retention_seconds": self.settings.retention_seconds,
                "apply_enabled": self.settings.apply_enabled,
                "raw_artifact_content_persisted": False,
                "extracted_text_persisted": False,
                "silent_answer_commit_possible": False,
                "existing_answers_overwritten": False,
                "external_worm_anchor_verified": False,
                "live_provider_or_customer_acceptance_verified": False,
            },
        }


__all__ = [
    "AssessmentApplyResult",
    "AssessmentEvidenceConfigError",
    "AssessmentEvidenceConflict",
    "AssessmentEvidenceError",
    "AssessmentEvidenceIntegrityError",
    "AssessmentEvidenceIntegrityReport",
    "AssessmentEvidenceMapping",
    "AssessmentEvidenceMappingAuthority",
    "AssessmentEvidenceNotFound",
    "AssessmentEvidenceService",
    "AssessmentEvidenceSettings",
    "AssessmentEvidenceTransitionError",
    "AssessmentEvidenceValidationError",
    "APPLICATION_RECEIPT_SCHEMA",
    "INTEGRITY_SCHEMA",
    "MAPPING_SCHEMA",
    "NOTICE",
    "PROPOSAL_SCHEMA",
    "apply_answers_to_assessment",
    "derive_exact_mapping_authority",
    "mapping_authority_sha256",
]
