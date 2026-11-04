"""Governed third-party AI vendor-risk assessments.

This module adds the AI-specific diligence layer that the generic vendor-risk
questionnaire intentionally does not attempt to cover.  It reuses three
existing Lightwork authorities instead of creating parallel substitutes:

* :mod:`maverick.assessment` supplies the deterministic question scoring;
* :mod:`maverick.privacy_ops` supplies bounded document extraction and its
  digest-bound provenance envelope; and
* :class:`maverick.governed_records.GovernedRecordStore` supplies tenant-scoped
  CAS persistence plus the durable audit outbox.

Document answers are lexical draft suggestions, never autonomous vendor
attestations.  Only short, secret-redacted citations are retained; source
locators, document bytes, and full extracted text are not persisted.  A
separate human review is required before an assessment may be projected as
``vendor_assessment`` evidence into the model-risk register.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from . import assessment as _assessment
from .assessment import AssessmentSession, AssessmentTemplate, Question
from .governed_records import GovernedRecordStore
from .privacy_ops import (
    _build_document_evidence,
    _document_text,
    _validate_document_evidence_record,
)

AI_VENDOR_SCHEMA = "lightwork.ai-vendor-risk.v1"
AI_VENDOR_DOCUMENT_SCHEMA = "lightwork.ai-vendor-document-answers.v1"
NON_CERTIFICATION_NOTICE = (
    "Decision-support draft requiring human review; not a certification, "
    "conformity assessment, legal classification, or legal advice."
)

_VENDORS = GovernedRecordStore(
    "ai_vendor_risk", "AIV", "ai_vendor",
)

_MAX_VENDOR_RECORDS = 5_000
_MAX_LIST_LIMIT = 100
_MAX_DOCUMENTS = 8
_MAX_CITATIONS_PER_ANSWER = 3
_MAX_DOCUMENT_INPUT_BYTES = 16 * 1024 * 1024
_MAX_EXTRACTED_CHARS = 1_000_000
_MAX_QUOTE_CHARS = 320
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ANSWERS = frozenset({"yes", "no", "na", "unknown"})
_DECISIONS = frozenset({"approved", "needs_work", "rejected"})


class AIVendorRiskError(RuntimeError):
    """Base failure for the governed AI vendor-risk authority."""


class AIVendorRiskConfigError(AIVendorRiskError):
    """The explicit AI vendor-risk product gate is unavailable."""


class AIVendorRiskStateError(AIVendorRiskError):
    """Persisted or supplied AI vendor-risk evidence cannot be trusted."""


def enabled() -> bool:
    """Return the explicit default-off feature and model-risk dependency state."""

    try:
        from . import model_risk_assurance as mra
        from .config import config_source_errors, load_global_config

        config = load_global_config()
        if config_source_errors(include_tenant=False) or not isinstance(config, dict):
            return False
        section = config.get("ai_vendor_risk")
        if not isinstance(section, dict) or section.get("enable") is not True:
            return False
        return mra.enabled()
    except Exception:
        return False


@dataclass(frozen=True)
class _Rule:
    answer: str
    patterns: tuple[re.Pattern[str], ...]


def _compiled(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


AI_VENDOR_QUESTIONS: tuple[Question, ...] = (
    Question(
        "aiv_provenance",
        "Model provenance",
        "Has the vendor documented the AI system's model/provider origin and version provenance?",
        "no",
        "high",
        "Obtain a versioned model/provider provenance statement and change-notification terms.",
    ),
    Question(
        "aiv_training_data",
        "Training data",
        "Has the vendor documented lawful training-data sources and whether customer data is used for training?",
        "no",
        "high",
        "Require training-data provenance, rights, customer-data-use, and opt-out disclosures.",
    ),
    Question(
        "aiv_subprocessors",
        "AI supply chain",
        "Does the vendor disclose AI subprocessors and provide notice of material changes?",
        "no",
        "medium",
        "Require a current AI subprocessor list and advance change notification.",
    ),
    Question(
        "aiv_evaluation",
        "Evaluation evidence",
        "Does the vendor provide current, scoped AI evaluation and red-team evidence?",
        "no",
        "high",
        "Obtain artifact-scoped evaluation methods, limitations, results, and remediation evidence.",
    ),
    Question(
        "aiv_incidents",
        "Incident history",
        "Has the vendor disclosed a material or unresolved AI incident in the review period?",
        "yes",
        "high",
        "Investigate incident scope, affected versions, root cause, remediation, and recurrence risk.",
    ),
    Question(
        "aiv_eu_role",
        "EU AI Act roles",
        "Are the vendor and customer roles under the EU AI Act explicitly documented?",
        "no",
        "high",
        "Obtain a dated human determination of provider, deployer, importer, and distributor roles.",
    ),
    Question(
        "aiv_retention",
        "Data retention",
        "Is retention and deletion for prompts, outputs, and customer data explicitly bounded?",
        "no",
        "medium",
        "Set enforceable retention, deletion, backup, and offboarding requirements.",
    ),
    Question(
        "aiv_human_oversight",
        "Human oversight",
        "Does the service support effective human review, override, and escalation?",
        "no",
        "high",
        "Define trained human review, override authority, escalation, and tested fallback procedures.",
    ),
)

AI_VENDOR_TEMPLATE = AssessmentTemplate(
    type="ai_vendor_risk",
    title="Third-Party AI Vendor Risk Assessment",
    framework="NIST AI RMF / EU AI Act / TPRM",
    description=(
        "Bounded due-diligence screen for third-party AI providers; all "
        "document-derived answers require human confirmation."
    ),
    questions=AI_VENDOR_QUESTIONS,
)

_QUESTION_BY_ID = {question.id: question for question in AI_VENDOR_QUESTIONS}

# Deliberately narrow, explainable lexical signals.  Absence of a signal is
# ``unknown`` rather than a guessed answer.  Patterns are static and bounded;
# no document-provided expression is ever compiled or evaluated.
_DOCUMENT_RULES: dict[str, tuple[_Rule, _Rule]] = {
    "aiv_provenance": (
        _Rule("yes", _compiled(
            r"\b(?:model|system)\s+provenance\b.{0,100}\b(?:documented|disclosed|provider|origin|versioned?)\b",
            r"\b(?:foundation|base)\s+model\s+(?:provider|origin|version)\b.{0,100}\b(?:documented|disclosed|identified|listed)\b",
        )),
        _Rule("no", _compiled(
            r"\b(?:model|system)\s+provenance\b.{0,80}\b(?:undisclosed|unknown|not\s+disclosed|unavailable)\b",
            r"\b(?:cannot|will\s+not|does\s+not)\s+disclose\b.{0,80}\b(?:model|provider|provenance|version)\b",
        )),
    ),
    "aiv_training_data": (
        _Rule("yes", _compiled(
            r"\btraining[- ]data\s+(?:sources?|provenance)\b.{0,120}\b(?:documented|disclosed|licensed|lawful|authorized)\b",
            r"\bcustomer\s+(?:data|prompts?|inputs?)\b.{0,100}\b(?:not|never)\s+(?:used|use)\b.{0,50}\btrain(?:ing)?\b",
        )),
        _Rule("no", _compiled(
            r"\bcustomer\s+(?:data|prompts?|inputs?)\b.{0,100}\b(?:is|are|may\s+be)\s+used\b.{0,50}\btrain(?:ing)?\b",
            r"\btraining[- ]data\s+(?:sources?|provenance)\b.{0,80}\b(?:unknown|undisclosed|unavailable)\b",
        )),
    ),
    "aiv_subprocessors": (
        _Rule("yes", _compiled(
            r"\bsubprocessor\s+list\b.{0,100}\b(?:published|disclosed|available|maintained|updated)\b",
            r"\bsubprocessors?\b.{0,100}\b(?:advance\s+notice|change\s+notification|notification\s+of\s+changes)\b",
        )),
        _Rule("no", _compiled(
            r"\b(?:does\s+not|will\s+not|refuses?\s+to)\b.{0,50}\bdisclos\w*\b.{0,50}\bsubprocessors?\b",
            r"\bsubprocessors?\b.{0,80}\b(?:not\s+disclosed|undisclosed|unavailable)\b",
        )),
    ),
    "aiv_evaluation": (
        _Rule("yes", _compiled(
            r"\b(?:publishes?|provides?|documents?)\b.{0,100}\b(?:evaluation|benchmark|red[- ]team(?:ing)?)\s+(?:results?|reports?|evidence)\b",
            r"\b(?:evaluation|benchmark|red[- ]team(?:ing)?)\s+(?:results?|reports?|evidence)\b.{0,100}\b(?:published|provided|available|documented)\b",
        )),
        _Rule("no", _compiled(
            r"\b(?:no|without)\s+(?:independent\s+)?(?:evaluation|benchmarking|red[- ]team(?:ing)?)\b",
            r"\b(?:evaluation|benchmark|red[- ]team(?:ing)?)\s+(?:results?|evidence)\b.{0,80}\b(?:unavailable|not\s+provided|not\s+disclosed)\b",
        )),
    ),
    "aiv_incidents": (
        _Rule("yes", _compiled(
            r"\b(?:experienced|suffered|disclosed)\b.{0,60}\b(?:material\s+|unresolved\s+)?(?:ai\s+)?incident\b",
            r"\b(?:material|unresolved)\s+(?:ai\s+)?incident\b.{0,80}\b(?:occurred|reported|open|investigat)\w*\b",
        )),
        _Rule("no", _compiled(
            r"\bno\b.{0,50}\b(?:material\s+|reported\s+|unresolved\s+)?(?:ai\s+)?incidents?\b",
            r"\b(?:ai\s+)?incident\s+history\b.{0,80}\b(?:none|no\s+incidents?|clear)\b",
        )),
    ),
    "aiv_eu_role": (
        _Rule("yes", _compiled(
            r"\beu\s+ai\s+act\b.{0,120}\b(?:provider|deployer|importer|distributor)\b.{0,80}\b(?:role|classified|identified|acts?)\b",
            r"\b(?:acts?|identified|classified)\b.{0,80}\b(?:provider|deployer|importer|distributor)\b.{0,100}\beu\s+ai\s+act\b",
        )),
        _Rule("no", _compiled(
            r"\beu\s+ai\s+act\b.{0,100}\brole\b.{0,60}\b(?:not\s+determined|undetermined|unknown|not\s+assessed)\b",
            r"\b(?:provider|deployer)\s+role\b.{0,60}\b(?:unknown|undetermined|not\s+documented)\b",
        )),
    ),
    "aiv_retention": (
        _Rule("yes", _compiled(
            r"\b(?:prompts?|inputs?|outputs?|customer\s+data)\b.{0,100}\bretain\w*\b.{0,60}\b\d{1,4}\s+(?:days?|months?|years?)\b",
            r"\bretention\s+(?:period|schedule|policy)\b.{0,100}\b(?:delet\w*|\d{1,4}\s+(?:days?|months?|years?))\b",
        )),
        _Rule("no", _compiled(
            r"\b(?:prompts?|inputs?|outputs?|customer\s+data)\b.{0,100}\bretained?\s+indefinitely\b",
            r"\b(?:no|without)\s+(?:defined\s+)?retention\s+(?:period|schedule|limit|policy)\b",
        )),
    ),
    "aiv_human_oversight": (
        _Rule("yes", _compiled(
            r"\bhuman\s+(?:reviewers?|operators?)\b.{0,100}\b(?:can|may|must)\s+(?:review|override|approve|escalate|stop)\b",
            r"\brequires?\s+human\s+(?:review|approval|oversight)\b",
            r"\bhuman\s+oversight\b.{0,80}\b(?:implemented|required|documented|tested)\b",
        )),
        _Rule("no", _compiled(
            r"\b(?:without|no)\s+(?:meaningful\s+|effective\s+)?human\s+(?:review|oversight|approval|override)\b",
            r"\bfully\s+automated\b.{0,100}\b(?:no|without)\s+human\b",
        )),
    ),
}


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


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_tenant() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if not tenant:
        raise AIVendorRiskStateError(
            "AI vendor-risk records require an explicit tenant authority"
        )
    return tenant


def _tenant_sha256(tenant: str | None = None) -> str:
    return hashlib.sha256((tenant or _require_tenant()).encode("utf-8")).hexdigest()


def _text(value: object, label: str, limit: int, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if required and not text:
        raise ValueError(f"{label} is required")
    if len(text) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    if _CONTROL_RE.search(text):
        raise ValueError(f"{label} contains control characters")
    try:
        from .safety.secret_detector import scan

        matches = scan(text)
    except Exception as exc:
        raise ValueError("secret detection is unavailable") from exc
    if matches:
        kinds = ", ".join(sorted({match.name for match in matches}))
        raise ValueError(f"{label} contains secret material ({kinds})")
    return text


def _redacted(value: str) -> tuple[str, bool]:
    try:
        from .safety.secret_detector import redact

        safe, matches = redact(value)
    except Exception as exc:
        raise AIVendorRiskStateError("secret redaction is unavailable") from exc
    return safe, bool(matches)


def _bounded_ref(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Bound a connector locator before hashing it into provenance.

    Locator values are never persisted, but an attacker-controlled, deeply
    nested object can still exhaust memory during canonical serialization.
    Keep only JSON-like values and enforce a small structural ceiling.
    """

    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > 32:
        raise ValueError("document ref must be an object with at most 32 fields")
    seen = 0

    def visit(item: object, depth: int) -> object:
        nonlocal seen
        if depth > 4:
            raise ValueError("document ref exceeds the nesting limit")
        if item is None or isinstance(item, (bool, int)):
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("document ref contains a non-finite number")
            return item
        if isinstance(item, str):
            if len(item) > 2_000 or _CONTROL_RE.search(item):
                raise ValueError("document ref contains an invalid string")
            return item
        if isinstance(item, Mapping):
            if len(item) > 32:
                raise ValueError("document ref object exceeds 32 fields")
            out: dict[str, object] = {}
            for raw_key in sorted(item, key=str):
                key = str(raw_key)
                if not key or len(key) > 128 or _CONTROL_RE.search(key):
                    raise ValueError("document ref contains an invalid key")
                seen += 1
                if seen > 128:
                    raise ValueError("document ref is too complex")
                out[key] = visit(item[raw_key], depth + 1)
            return out
        if isinstance(item, (list, tuple)):
            if len(item) > 32:
                raise ValueError("document ref list exceeds 32 items")
            return [visit(child, depth + 1) for child in item]
        raise ValueError("document ref contains an unsupported value")

    return visit(value, 0)  # type: ignore[return-value]


def _revision(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("expected_revision must be a non-negative integer")
    return value


def _bounded_records() -> list[dict[str, Any]]:
    rows = _VENDORS.list(limit=_MAX_VENDOR_RECORDS + 1)
    if len(rows) > _MAX_VENDOR_RECORDS:
        raise AIVendorRiskStateError(
            f"AI vendor-risk records exceed the {_MAX_VENDOR_RECORDS}-record limit"
        )
    return rows


def _vendor_key(name: str) -> str:
    normalized = " ".join(name.casefold().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _template_snapshot() -> tuple[dict[str, Any], str]:
    # These package-private helpers are the assessment engine's canonical
    # policy serializer and digest.  Using them ensures this draft has exactly
    # the same pinned-questionnaire semantics as every other assessment.
    policy = _assessment._template_record(AI_VENDOR_TEMPLATE, department="privacy")
    digest = _assessment._template_digest(policy)
    return {**policy, "custom": False}, digest


def questionnaire() -> dict[str, Any]:
    """Return the exact public questionnaire bound to new assessments."""

    _require_tenant()
    _, digest = _template_snapshot()
    return {
        "schema": "lightwork.ai-vendor-questionnaire.v1",
        "template_revision": 1,
        "template_digest": digest,
        "title": AI_VENDOR_TEMPLATE.title,
        "description": AI_VENDOR_TEMPLATE.description,
        "questions": [asdict(question) for question in AI_VENDOR_QUESTIONS],
        "notice": NON_CERTIFICATION_NOTICE,
    }


def _assessment_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": record.get("schema"),
        "tenant_sha256": record.get("tenant_sha256"),
        "vendor_key": record.get("vendor_key"),
        "vendor": record.get("vendor"),
        "template_revision": record.get("template_revision"),
        "template_digest": record.get("template_digest"),
        "template_snapshot": record.get("template_snapshot"),
        "answers": record.get("answers"),
        "answer_sources": record.get("answer_sources"),
        "documents": record.get("documents"),
        "prior_citations": record.get("prior_citations"),
        "skipped_prior_questions": record.get("skipped_prior_questions"),
        "result": record.get("result"),
    }


def _public(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "_audit_pending"}


def _validated_record(  # noqa: C901 - one complete persisted-record trust boundary
    record: Mapping[str, Any],
) -> dict[str, Any]:
    row = dict(record)
    if row.get("schema") != AI_VENDOR_SCHEMA:
        raise AIVendorRiskStateError("AI vendor-risk record schema is invalid")
    if row.get("tenant_sha256") != _tenant_sha256():
        raise AIVendorRiskStateError("AI vendor-risk tenant binding is invalid")
    try:
        vendor = _text(row.get("vendor"), "persisted vendor", 300)
        _text(row.get("assessed_by"), "persisted assessed_by", 256)
    except ValueError as exc:
        raise AIVendorRiskStateError("AI vendor-risk identity metadata is invalid") from exc
    if _vendor_key(vendor) != row.get("vendor_key"):
        raise AIVendorRiskStateError("AI vendor-risk vendor identity is invalid")
    expected_snapshot, expected_template_digest = _template_snapshot()
    if (
        row.get("template_revision") != 1
        or row.get("template_digest") != expected_template_digest
        or row.get("template_snapshot") != expected_snapshot
    ):
        raise AIVendorRiskStateError("AI vendor-risk questionnaire binding is invalid")
    claimed = row.get("assessment_sha256")
    if not isinstance(claimed, str) or not _DIGEST_RE.fullmatch(claimed):
        raise AIVendorRiskStateError("AI vendor-risk assessment digest is invalid")
    if _sha256(_assessment_payload(row)) != claimed:
        raise AIVendorRiskStateError("AI vendor-risk assessment binding does not verify")
    if row.get("status") not in {"pending_review", *_DECISIONS}:
        raise AIVendorRiskStateError("AI vendor-risk lifecycle is invalid")
    answers = row.get("answers")
    if not isinstance(answers, dict) or set(answers) != set(_QUESTION_BY_ID):
        raise AIVendorRiskStateError("AI vendor-risk answers are invalid")
    for qid, answer in answers.items():
        if not isinstance(answer, dict) or answer.get("answer") not in _ANSWERS:
            raise AIVendorRiskStateError(f"AI vendor-risk answer {qid!r} is invalid")
        try:
            _text(
                answer.get("note") or "",
                f"persisted answer {qid} note",
                1000,
                required=False,
            )
        except ValueError as exc:
            raise AIVendorRiskStateError(
                f"AI vendor-risk answer {qid!r} note is invalid"
            ) from exc
    documents = row.get("documents")
    if not isinstance(documents, list) or len(documents) > _MAX_DOCUMENTS:
        raise AIVendorRiskStateError("AI vendor-risk document evidence is invalid")
    for document in documents:
        if (
            not isinstance(document, dict)
            or set(document) != {"evidence", "truncated_for_assessment"}
            or not isinstance(document["truncated_for_assessment"], bool)
            or not isinstance(document["evidence"], dict)
        ):
            raise AIVendorRiskStateError("AI vendor-risk document evidence is invalid")
        evidence = document["evidence"]
        _validate_document_evidence_record({
            "document_evidence": evidence,
            "extraction_confidence": evidence.get("confidence"),
            "review_required": evidence.get("review_required"),
        })
    evidence_by_binding = {
        (
            item["evidence"]["source_binding_sha256"],
            item["evidence"]["document_sha256"],
            item["evidence"]["extracted_text_sha256"],
        ): item["evidence"]
        for item in documents
    }
    sources = row.get("answer_sources")
    if not isinstance(sources, dict) or set(sources) != set(_QUESTION_BY_ID):
        raise AIVendorRiskStateError("AI vendor-risk answer provenance is invalid")
    for qid, source in sources.items():
        if not isinstance(source, dict):
            raise AIVendorRiskStateError("AI vendor-risk answer provenance is invalid")
        kind = source.get("kind")
        confidence = source.get("confidence")
        if (
            kind
            not in {
                "manual",
                "vendor_attested",
                "document",
                "prior_approved",
                "missing",
            }
            or isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(float(confidence))
            or not 0 <= float(confidence) <= 1
        ):
            raise AIVendorRiskStateError("AI vendor-risk answer provenance is invalid")
        answer = answers[qid]
        citations = answer.get("citations")
        if kind == "document":
            if (
                source.get("review_required") is not True
                or not isinstance(citations, list)
                or not 1 <= len(citations) <= _MAX_CITATIONS_PER_ANSWER
                or not 0 <= float(confidence) <= 0.88
            ):
                raise AIVendorRiskStateError("AI vendor document provenance is invalid")
            for citation in citations:
                if not isinstance(citation, Mapping):
                    raise AIVendorRiskStateError("AI vendor document citation is invalid")
                binding = (
                    citation.get("source_binding_sha256"),
                    citation.get("document_sha256"),
                    citation.get("extracted_text_sha256"),
                )
                evidence = evidence_by_binding.get(binding)
                if evidence is None:
                    raise AIVendorRiskStateError(
                        "AI vendor document citation has no bound document"
                    )
                _validate_citation(citation, evidence=evidence)
        elif citations is not None:
            raise AIVendorRiskStateError(
                "non-document AI vendor answer contains document citations"
            )
        if kind == "manual" and float(confidence) != 1.0:
            raise AIVendorRiskStateError("manual AI vendor answer confidence is invalid")
        if kind == "vendor_attested" and (
            source.get("review_required") is not True
            or float(confidence) != 0.75
            or not isinstance(source.get("submission_sha256"), str)
            or not _DIGEST_RE.fullmatch(source["submission_sha256"])
        ):
            raise AIVendorRiskStateError(
                "vendor-attested AI vendor answer provenance is invalid"
            )
        if kind == "missing" and (
            float(confidence) != 0.0 or answer.get("answer") != "unknown"
        ):
            raise AIVendorRiskStateError("missing AI vendor answer provenance is invalid")
        if kind == "prior_approved" and (
            float(confidence) != 1.0
            or source.get("requires_revalidation") is not True
            or answer.get("answer") not in {"yes", "no", "na"}
            or not isinstance(source.get("citation"), Mapping)
        ):
            raise AIVendorRiskStateError("prior AI vendor answer provenance is invalid")
    prior_citations = row.get("prior_citations")
    skipped = row.get("skipped_prior_questions")
    if (
        not isinstance(prior_citations, list)
        or len(prior_citations) > len(_QUESTION_BY_ID)
        or not isinstance(skipped, list)
        or skipped != sorted(set(skipped))
        or any(qid not in _QUESTION_BY_ID for qid in skipped)
    ):
        raise AIVendorRiskStateError("AI vendor prior-answer binding is invalid")
    citation_questions: set[str] = set()
    for citation in prior_citations:
        if not isinstance(citation, dict):
            raise AIVendorRiskStateError("AI vendor prior-answer citation is invalid")
        qid = citation.get("question_id")
        if qid in citation_questions or qid not in _QUESTION_BY_ID:
            raise AIVendorRiskStateError("AI vendor prior-answer citation is invalid")
        citation_questions.add(qid)
        if (
            not isinstance(citation.get("record_id"), str)
            or not citation["record_id"]
            or isinstance(citation.get("revision"), bool)
            or not isinstance(citation.get("revision"), int)
            or citation["revision"] < 1
            or not isinstance(citation.get("assessment_sha256"), str)
            or not _DIGEST_RE.fullmatch(citation["assessment_sha256"])
            or citation.get("source_kind")
            not in {"ai_vendor_risk", "security_vendor_memory"}
            or sources[qid].get("citation") != citation
        ):
            raise AIVendorRiskStateError("AI vendor prior-answer citation is invalid")
    if citation_questions != set(skipped):
        raise AIVendorRiskStateError("AI vendor prior-answer binding is invalid")

    session = AssessmentSession(
        type=AI_VENDOR_TEMPLATE.type,
        subject=vendor,
        template_revision=1,
        template_digest=expected_template_digest,
        template_snapshot=expected_snapshot,
    )
    for qid, answer in answers.items():
        session.record(qid, answer["answer"], answer.get("note") or "")
    if row.get("result") != asdict(session.evaluate()):
        raise AIVendorRiskStateError("AI vendor-risk deterministic result is invalid")
    review = row.get("review")
    if row.get("status") == "pending_review":
        if review is not None:
            raise AIVendorRiskStateError("pending AI vendor-risk review is invalid")
    elif (
        not isinstance(review, dict)
        or review.get("decision") != row.get("status")
        or review.get("assessment_sha256") != claimed
        or review.get("legal_certification") is not False
        or not isinstance(review.get("reviewed_at"), (int, float))
        or isinstance(review.get("reviewed_at"), bool)
        or not math.isfinite(float(review["reviewed_at"]))
        or float(review["reviewed_at"]) <= 0
    ):
        raise AIVendorRiskStateError("AI vendor-risk human review is invalid")
    if isinstance(review, dict):
        try:
            _text(review.get("reviewer"), "persisted reviewer", 256)
            _text(review.get("rationale"), "persisted rationale", 4000)
        except ValueError as exc:
            raise AIVendorRiskStateError("AI vendor-risk human review is invalid") from exc
    return _public(row)


def _quote_span(text: str, start: int, end: int) -> tuple[int, int, str]:
    left_floor = max(0, start - _MAX_QUOTE_CHARS // 2)
    right_ceiling = min(len(text), end + _MAX_QUOTE_CHARS // 2)
    left = max(
        text.rfind("\n", left_floor, start),
        text.rfind(".", left_floor, start),
        text.rfind("!", left_floor, start),
        text.rfind("?", left_floor, start),
    )
    left = start if left < 0 else left + 1
    candidates = [
        pos
        for pos in (
            text.find("\n", end, right_ceiling),
            text.find(".", end, right_ceiling),
            text.find("!", end, right_ceiling),
            text.find("?", end, right_ceiling),
        )
        if pos >= 0
    ]
    right = min(candidates) + 1 if candidates else right_ceiling
    if right - left > _MAX_QUOTE_CHARS:
        half = _MAX_QUOTE_CHARS // 2
        left = max(0, start - half)
        right = min(len(text), left + _MAX_QUOTE_CHARS)
    quote = " ".join(text[left:right].split())
    return left, right, quote[:_MAX_QUOTE_CHARS]


def _answer_confidence(extraction_confidence: str, signals: int) -> float:
    ceiling = {
        "source_bytes": 0.88,
        "best_effort": 0.72,
        "untrusted": 0.65,
    }.get(extraction_confidence, 0.60)
    return round(min(ceiling, 0.80 + max(0, signals - 1) * 0.04), 2)


def _citation(
    *,
    text: str,
    match: re.Match[str],
    evidence: Mapping[str, Any],
    confidence: float,
) -> dict[str, Any]:
    start, end, raw_quote = _quote_span(text, match.start(), match.end())
    display, was_redacted = _redacted(raw_quote)
    return {
        "source_binding_sha256": evidence["source_binding_sha256"],
        "document_sha256": evidence["document_sha256"],
        "extracted_text_sha256": evidence["extracted_text_sha256"],
        "quote_sha256": hashlib.sha256(raw_quote.encode("utf-8")).hexdigest(),
        "display_quote_sha256": hashlib.sha256(display.encode("utf-8")).hexdigest(),
        "start": start,
        "end": end,
        "quote": display,
        "redacted": was_redacted,
        "confidence": confidence,
    }


_CLAUSE_RE = re.compile(r"[^.!?;\n]+")
_HEDGE_RE = re.compile(r"\b(?:might|could|should|would|planned|planning|plans?|intend\w*|proposed|pending|unless|aim\w*|expect\w*)\b|\bmay\s+be\b", re.IGNORECASE)
_NEGATION_RE = re.compile(r"\b(?:not|never|no|without|cannot|can't|isn't|aren't|doesn't|don't|won't)\b", re.IGNORECASE)


def _uncertain_signal(clause: str, *, qid: str, rule: _Rule, pattern: re.Pattern[str]) -> bool:
    """Keep explicit negative rules; abstain on surrounding negation/hedges.

    This is a conservative lexical screen, not a semantic assertion. Only a
    negation explicitly required by the matched static rule is consumed. An
    additional negation (including a double negative) needs human resolution.
    """
    if _HEDGE_RE.search(clause):
        return True
    remainder = clause
    if qid == "aiv_training_data" and rule.answer == "yes" and "(?:not|never)" in pattern.pattern:
        remainder = re.sub(r"\b(?:not|never)\s+(?:used|use)\b", "used", remainder, count=1, flags=re.IGNORECASE)
    elif rule.answer == "no":
        # Match only expressions present in this particular negative rule;
        # e.g. 'incident history is not clear' must not turn 'clear' into no.
        spelling = pattern.pattern.replace(r"\s+", " ")
        for expression in ("does not", "will not", "not disclosed", "not provided",
                           "not determined", "not assessed", "not documented",
                           "cannot", "without", "no"):
            if expression in spelling:
                remainder = re.sub(r"\b" + re.escape(expression).replace(r"\ ", r"\s+") + r"\b",
                                   " ", remainder, count=1, flags=re.IGNORECASE)
    return _NEGATION_RE.search(remainder) is not None


def _extract_document_answers(
    text: str,
    evidence: Mapping[str, Any],
    *,
    truncated: bool,
) -> dict[str, Any]:
    answers: dict[str, dict[str, Any]] = {}
    for qid, rules in _DOCUMENT_RULES.items():
        matches: dict[str, list[re.Match[str]]] = {"yes": [], "no": []}
        uncertain: list[re.Match[str]] = []
        for rule in rules:
            for pattern in rule.patterns:
                for clause in _CLAUSE_RE.finditer(text):
                    hit = pattern.search(text, clause.start(), clause.end())
                    if hit is not None:
                        destination = (uncertain if _uncertain_signal(clause.group(), qid=qid,
                                       rule=rule, pattern=pattern) else matches[rule.answer])
                        if len(destination) < _MAX_CITATIONS_PER_ANSWER:
                            destination.append(hit)
        present = [answer for answer, hits in matches.items() if hits]
        if not present and not uncertain:
            continue
        if len(present) > 1 or uncertain:
            answer = "unknown"
            confidence = 0.0
            selected = (uncertain + matches["yes"] + matches["no"])[:_MAX_CITATIONS_PER_ANSWER]
            note = "Conflicting, negated or uncertain document signals require human resolution."
        else:
            answer = present[0]
            selected = matches[answer][:_MAX_CITATIONS_PER_ANSWER]
            confidence = _answer_confidence(
                str(evidence.get("confidence") or ""), len(matches[answer])
            )
            note = "Deterministic lexical document signal; human confirmation required."
        answers[qid] = {
            "answer": answer,
            "note": note,
            "confidence": confidence,
            "citations": [
                _citation(
                    text=text,
                    match=hit,
                    evidence=evidence,
                    confidence=confidence,
                )
                for hit in selected
            ],
        }
    return {
        "schema": AI_VENDOR_DOCUMENT_SCHEMA,
        "tenant_sha256": _tenant_sha256(),
        "document_evidence": dict(evidence),
        "answers": answers,
        "unanswered": sorted(set(_QUESTION_BY_ID) - set(answers)),
        "truncated": bool(truncated),
        "review_required": True,
    }


def extract_answers_from_document(
    data: bytes,
    mime: str,
    *,
    source: str = "upload",
    document_id: str = "document",
    ref: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract bounded, cited draft answers from supplied document bytes.

    The locator is digest-bound by the shared document-evidence helper and is
    never returned or stored in plaintext.  The returned answer suggestions
    remain review-required even for UTF-8 source bytes.
    """

    _require_tenant()
    if not isinstance(data, bytes):
        raise ValueError("document data must be bytes")
    if len(data) > _MAX_DOCUMENT_INPUT_BYTES:
        raise ValueError("document exceeds the 16 MiB input limit")
    source_name = _text(source, "document source", 64)
    doc = _text(document_id, "document_id", 512)
    locator_ref = _bounded_ref(ref)
    extraction: dict[str, Any] = {}
    extracted = _document_text(data, mime, _metadata=extraction)
    if not extracted.strip():
        raise ValueError("document yielded no supported text")
    truncated = len(extracted) > _MAX_EXTRACTED_CHARS
    text = extracted[:_MAX_EXTRACTED_CHARS]
    # Bind to the exact bounded text that the rules actually inspected.  This
    # prevents a digest for an uninspected suffix being misread as full review.
    evidence = _build_document_evidence(
        data=data,
        text=text,
        mime=str(mime or "")[:255],
        source=source_name,
        doc_id=doc,
        ref=locator_ref,
        extraction=extraction,
    )
    _validate_document_evidence_record({
        "document_evidence": evidence,
        "extraction_confidence": evidence["confidence"],
        "review_required": evidence["review_required"],
    })
    return _extract_document_answers(text, evidence, truncated=truncated)


def extract_answers_from_connected_document(
    source: str,
    document_id: str,
    *,
    ref: Mapping[str, Any] | None = None,
    document_name: str = "",
    principal: str | None = None,
    allow_ambient_credentials: bool = False,
) -> dict[str, Any]:
    """Fetch through a configured connector, then run the same bounded path."""

    _require_tenant()
    from . import doc_discovery

    data, mime = doc_discovery.fetch(
        source,
        document_id,
        _bounded_ref(ref),
        max_bytes=_MAX_DOCUMENT_INPUT_BYTES,
        principal=principal,
        allow_ambient_credentials=allow_ambient_credentials,
    )
    resolved = doc_discovery.resolve_mime(document_name or document_id, mime)
    return extract_answers_from_document(
        data,
        resolved,
        source=source,
        document_id=document_id,
        ref=ref,
    )


def _validate_citation(
    citation: object,
    *,
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(citation, Mapping):
        raise AIVendorRiskStateError("document citation is invalid")
    row = dict(citation)
    for key in (
        "source_binding_sha256",
        "document_sha256",
        "extracted_text_sha256",
        "quote_sha256",
        "display_quote_sha256",
    ):
        value = row.get(key)
        if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
            raise AIVendorRiskStateError("document citation digest is invalid")
    for key in ("source_binding_sha256", "document_sha256", "extracted_text_sha256"):
        if row[key] != evidence[key]:
            raise AIVendorRiskStateError("document citation binding is invalid")
    quote = row.get("quote")
    if not isinstance(quote, str) or len(quote) > _MAX_QUOTE_CHARS:
        raise AIVendorRiskStateError("document citation quote is invalid")
    if hashlib.sha256(quote.encode("utf-8")).hexdigest() != row["display_quote_sha256"]:
        raise AIVendorRiskStateError("document citation display digest is invalid")
    if _CONTROL_RE.search(quote):
        raise AIVendorRiskStateError("document citation contains control characters")
    _, leaked = _redacted(quote)
    if leaked:
        raise AIVendorRiskStateError("document citation contains secret material")
    start, end = row.get("start"), row.get("end")
    if (
        isinstance(start, bool)
        or not isinstance(start, int)
        or isinstance(end, bool)
        or not isinstance(end, int)
        or start < 0
        or end < start
        or end > _MAX_EXTRACTED_CHARS
    ):
        raise AIVendorRiskStateError("document citation span is invalid")
    confidence = row.get("confidence")
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not math.isfinite(float(confidence))
        or not 0 <= float(confidence) <= 1
    ):
        raise AIVendorRiskStateError("document citation confidence is invalid")
    if not isinstance(row.get("redacted"), bool):
        raise AIVendorRiskStateError("document citation redaction marker is invalid")
    return row


def _validate_document_result(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("schema") != AI_VENDOR_DOCUMENT_SCHEMA:
        raise AIVendorRiskStateError("AI vendor document result schema is invalid")
    if value.get("tenant_sha256") != _tenant_sha256():
        raise AIVendorRiskStateError("AI vendor document tenant binding is invalid")
    evidence = value.get("document_evidence")
    if not isinstance(evidence, Mapping):
        raise AIVendorRiskStateError("AI vendor document evidence is invalid")
    evidence = dict(evidence)
    _validate_document_evidence_record({
        "document_evidence": evidence,
        "extraction_confidence": evidence.get("confidence"),
        "review_required": evidence.get("review_required"),
    })
    if evidence.get("review_required") is not True or value.get("review_required") is not True:
        raise AIVendorRiskStateError("AI vendor document answers must require review")
    raw_answers = value.get("answers")
    if not isinstance(raw_answers, Mapping) or len(raw_answers) > len(_QUESTION_BY_ID):
        raise AIVendorRiskStateError("AI vendor document answers are invalid")
    answers: dict[str, dict[str, Any]] = {}
    for qid, raw in raw_answers.items():
        if qid not in _QUESTION_BY_ID or not isinstance(raw, Mapping):
            raise AIVendorRiskStateError("AI vendor document answer identity is invalid")
        answer = str(raw.get("answer") or "").lower()
        if answer not in {"yes", "no", "unknown"}:
            raise AIVendorRiskStateError("AI vendor document answer is invalid")
        confidence = raw.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(float(confidence))
            or not 0 <= float(confidence) <= 0.88
        ):
            raise AIVendorRiskStateError("AI vendor document confidence is invalid")
        if (answer == "unknown") != (float(confidence) == 0.0):
            raise AIVendorRiskStateError("AI vendor document confidence is invalid")
        citations = raw.get("citations")
        if not isinstance(citations, list) or not 1 <= len(citations) <= _MAX_CITATIONS_PER_ANSWER:
            raise AIVendorRiskStateError("AI vendor document citations are invalid")
        answers[qid] = {
            "answer": answer,
            "note": _text(raw.get("note") or "", "document answer note", 500),
            "confidence": round(float(confidence), 2),
            "citations": [
                _validate_citation(citation, evidence=evidence)
                for citation in citations
            ],
        }
    return {
        "schema": AI_VENDOR_DOCUMENT_SCHEMA,
        "tenant_sha256": value["tenant_sha256"],
        "document_evidence": evidence,
        "answers": answers,
        "truncated": bool(value.get("truncated", False)),
        "review_required": True,
    }


def _manual_answers(values: Mapping[str, object] | None) -> dict[str, dict[str, Any]]:
    if values is None:
        return {}
    if not isinstance(values, Mapping) or len(values) > len(_QUESTION_BY_ID):
        raise ValueError("answers must be a bounded object")
    out: dict[str, dict[str, Any]] = {}
    for qid, raw in values.items():
        if qid not in _QUESTION_BY_ID:
            raise ValueError(f"unknown AI vendor question {qid!r}")
        if isinstance(raw, str):
            answer, note = raw, ""
        elif isinstance(raw, Mapping):
            answer, note = raw.get("answer"), raw.get("note") or ""
        else:
            raise ValueError(f"answer {qid!r} must be a string or object")
        answer = str(answer or "").strip().lower()
        if answer not in _ANSWERS:
            raise ValueError(f"answer {qid!r} must be one of {sorted(_ANSWERS)}")
        out[qid] = {
            "answer": answer,
            "note": _text(note, f"answer {qid} note", 1000, required=False),
        }
    return out


def _document_candidates(
    results: Iterable[Mapping[str, Any]] | None,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    if results is None:
        return {}, []
    if isinstance(results, (str, bytes, Mapping)):
        raise ValueError("document_results must be a list")
    raw = list(results)
    if len(raw) > _MAX_DOCUMENTS:
        raise ValueError(f"document_results exceeds {_MAX_DOCUMENTS} documents")
    validated = [_validate_document_result(item) for item in raw]
    candidates: dict[str, list[dict[str, Any]]] = {}
    for result in validated:
        for qid, answer in result["answers"].items():
            candidates.setdefault(qid, []).append(answer)
    merged: dict[str, dict[str, Any]] = {}
    for qid, options in candidates.items():
        substantive = {item["answer"] for item in options if item["answer"] != "unknown"}
        citations = [
            citation
            for item in options
            for citation in item["citations"]
        ][:_MAX_CITATIONS_PER_ANSWER]
        if len(substantive) > 1 or any(item["answer"] == "unknown" for item in options):
            merged[qid] = {
                "answer": "unknown",
                "note": "Conflicting current document answers require human resolution.",
                "confidence": 0.0,
                "citations": citations,
            }
            continue
        chosen_answer = next(iter(substantive), "unknown")
        same = [item for item in options if item["answer"] == chosen_answer]
        chosen = max(same or options, key=lambda item: float(item["confidence"]))
        merged[qid] = {
            **chosen,
            "citations": citations,
        }
    evidence = [
        {
            "evidence": item["document_evidence"],
            "truncated_for_assessment": item["truncated"],
        }
        for item in validated
    ]
    return merged, evidence


def _latest_approved(vendor_key: str) -> dict[str, Any] | None:
    validated = [_validated_record(row) for row in _bounded_records()]
    rows = [
        row
        for row in validated
        if row.get("vendor_key") == vendor_key and row.get("status") == "approved"
    ]
    if not rows:
        return None
    latest = max(rows, key=lambda row: (float(row.get("created_at") or 0), str(row.get("id") or "")))
    return _validated_record(latest)


def prior_answer_plan(vendor: str) -> dict[str, Any]:
    """Return safe prior-answer skips from the latest approved same-tenant review."""

    _require_tenant()
    name = _text(vendor, "vendor", 300)
    prior = _latest_approved(_vendor_key(name))
    reusable: dict[str, dict[str, Any]] = {}
    if prior is not None:
        for qid, answer in prior["answers"].items():
            if answer.get("answer") in {"yes", "no", "na"}:
                reusable[qid] = {
                    "answer": answer["answer"],
                    "note": "Carried from the latest approved AI vendor assessment; revalidate on change.",
                    "source_record_id": prior["id"],
                    "source_revision": prior["revision"],
                    "source_assessment_sha256": prior["assessment_sha256"],
                    "source_kind": "ai_vendor_risk",
                }
    # Reuse the established security vendor memory only where its semantics
    # actually match this questionnaire.  "Disclosed and governed
    # subprocessors" is safe to carry as an advisory skip; SOC reports,
    # offboarding deletion, and generic assurance are not silently promoted to
    # AI evaluation/training/retention answers.
    if "aiv_subprocessors" not in reusable:
        try:
            from .security_ops import latest_vendor_assessment

            legacy = latest_vendor_assessment(name)
        except Exception:
            legacy = None
        if isinstance(legacy, Mapping) and legacy.get("status") == "approved":
            checks = {
                str(item.get("key") or ""): item.get("answer")
                for item in (legacy.get("checks") or [])
                if isinstance(item, Mapping)
            }
            legacy_answer = checks.get("subprocessors")
            if legacy_answer in {True, False}:
                legacy_id = str(legacy.get("id") or "")
                legacy_revision = legacy.get("revision")
                if (
                    legacy_id
                    and isinstance(legacy_revision, int)
                    and not isinstance(legacy_revision, bool)
                ):
                    source_digest = _sha256({
                        "id": legacy_id,
                        "revision": legacy_revision,
                        "subprocessors": legacy_answer,
                    })
                    reusable["aiv_subprocessors"] = {
                        "answer": "yes" if legacy_answer else "no",
                        "note": (
                            "Carried from the latest approved security vendor "
                            "assessment; confirm that the disclosure covers AI subprocessors."
                        ),
                        "source_record_id": legacy_id,
                        "source_revision": legacy_revision,
                        "source_assessment_sha256": source_digest,
                        "source_kind": "security_vendor_memory",
                    }
    return {
        "vendor_key": _vendor_key(name),
        "prior_record_id": prior.get("id") if prior else None,
        "skipped": reusable,
        "ask": [qid for qid in _QUESTION_BY_ID if qid not in reusable],
    }


def draft_vendor_assessment(
    vendor: str,
    *,
    answers: Mapping[str, object] | None = None,
    attested_answers: Mapping[str, object] | None = None,
    attestation_sha256: str | None = None,
    document_results: Iterable[Mapping[str, Any]] | None = None,
    actor: str,
    use_prior: bool = True,
) -> dict[str, Any]:
    """Create a governed, deterministic AI vendor-risk draft.

    Precedence is explicit: current internal manual answer, current
    vendor-attested answer, current document answer, latest approved prior
    answer, then ``unknown``. Only approved prior
    answers can be skipped, so a machine draft never becomes authority merely
    by being the newest record.
    """

    tenant = _require_tenant()
    name = _text(vendor, "vendor", 300)
    operator = _text(actor, "actor", 256)
    manual = _manual_answers(answers)
    attested = _manual_answers(attested_answers)
    attestation_digest: str | None = None
    if attested:
        attestation_digest = _digest(
            attestation_sha256,
            "attestation_sha256",
        )
    elif attestation_sha256 is not None:
        raise ValueError(
            "attestation_sha256 requires at least one vendor-attested answer"
        )
    document, document_evidence = _document_candidates(document_results)
    plan = prior_answer_plan(name) if use_prior else {
        "prior_record_id": None,
        "skipped": {},
    }
    prior = plan["skipped"]
    merged: dict[str, dict[str, Any]] = {}
    sources: dict[str, dict[str, Any]] = {}
    prior_citations: list[dict[str, Any]] = []
    skipped: list[str] = []
    for qid in _QUESTION_BY_ID:
        if qid in manual:
            merged[qid] = dict(manual[qid])
            sources[qid] = {"kind": "manual", "confidence": 1.0}
        elif qid in attested:
            merged[qid] = dict(attested[qid])
            sources[qid] = {
                "kind": "vendor_attested",
                "confidence": 0.75,
                "review_required": True,
                "submission_sha256": attestation_digest,
            }
        elif qid in document:
            value = dict(document[qid])
            merged[qid] = {
                "answer": value["answer"],
                "note": value["note"],
                "citations": value["citations"],
            }
            sources[qid] = {
                "kind": "document",
                "confidence": value["confidence"],
                "review_required": True,
            }
        elif qid in prior:
            value = prior[qid]
            merged[qid] = {
                "answer": value["answer"],
                "note": value["note"],
            }
            citation = {
                "question_id": qid,
                "record_id": value["source_record_id"],
                "revision": value["source_revision"],
                "assessment_sha256": value["source_assessment_sha256"],
                "source_kind": value.get("source_kind", "ai_vendor_risk"),
            }
            prior_citations.append(citation)
            skipped.append(qid)
            sources[qid] = {
                "kind": "prior_approved",
                "confidence": 1.0,
                "citation": citation,
                "requires_revalidation": True,
            }
        else:
            merged[qid] = {
                "answer": "unknown",
                "note": "No current evidence supplied; human diligence required.",
            }
            sources[qid] = {"kind": "missing", "confidence": 0.0}

    snapshot, template_digest = _template_snapshot()
    session = AssessmentSession(
        type=AI_VENDOR_TEMPLATE.type,
        subject=name,
        template_revision=1,
        template_digest=template_digest,
        template_snapshot=snapshot,
    )
    for qid, answer in merged.items():
        session.record(qid, answer["answer"], answer.get("note") or "")
    result = asdict(session.evaluate())
    record: dict[str, Any] = {
        "id": _VENDORS.new_id(),
        "schema": AI_VENDOR_SCHEMA,
        "tenant_sha256": _tenant_sha256(tenant),
        "vendor_key": _vendor_key(name),
        "vendor": name,
        "template_revision": 1,
        "template_digest": template_digest,
        "template_snapshot": snapshot,
        "answers": merged,
        "answer_sources": sources,
        "documents": document_evidence,
        "prior_citations": prior_citations,
        "skipped_prior_questions": sorted(skipped),
        "result": result,
        "status": "pending_review",
        "review_required": True,
        "review": None,
        "assessed_by": operator,
        "notice": NON_CERTIFICATION_NOTICE,
    }
    record["assessment_sha256"] = _sha256(_assessment_payload(record))
    saved = _VENDORS.create(
        record,
        action="draft_ai_vendor_assessment",
        actor=operator,
        max_records=_MAX_VENDOR_RECORDS,
    )
    return _validated_record(saved)


def get_vendor_assessment(record_id: str) -> dict[str, Any] | None:
    _require_tenant()
    identifier = _text(record_id, "record_id", 64)
    row = _VENDORS.get(identifier)
    return None if row is None else _validated_record(row)


def list_vendor_assessments(*, limit: int = 50) -> dict[str, Any]:
    _require_tenant()
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST_LIMIT:
        raise ValueError(f"limit must be between 1 and {_MAX_LIST_LIMIT}")
    rows = [_validated_record(row) for row in _bounded_records()]
    rows.sort(key=lambda row: (float(row.get("created_at") or 0), row["id"]), reverse=True)
    page = rows[:limit]
    items = [
        {
            "id": row["id"],
            "vendor": row["vendor"],
            "status": row["status"],
            "risk_rating": row["result"]["risk_rating"],
            "answered": row["result"]["answered"],
            "total": row["result"]["total"],
            "findings": len(row["result"]["findings"]),
            "created_at": row.get("created_at"),
            "revision": row.get("revision"),
        }
        for row in page
    ]
    return {
        "items": items,
        "count": len(items),
        "truncated": len(rows) > len(items),
        "limit": limit,
    }


def find_vendor_assessment_by_attestation(
    attestation_sha256: str,
) -> dict[str, Any] | None:
    """Resolve one portal attestation digest for crash-safe import recovery."""

    _require_tenant()
    digest = _digest(attestation_sha256, "attestation_sha256")
    matches: list[dict[str, Any]] = []
    for row in _bounded_records():
        validated = _validated_record(row)
        if any(
            source.get("kind") == "vendor_attested"
            and source.get("submission_sha256") == digest
            for source in validated["answer_sources"].values()
        ):
            matches.append(validated)
    if len(matches) > 1:
        raise AIVendorRiskStateError(
            "multiple AI vendor assessments claim one attestation digest"
        )
    return None if not matches else _public(matches[0])


def review_vendor_assessment(
    record_id: str,
    *,
    decision: str,
    rationale: str,
    reviewer: str,
    expected_revision: int,
) -> dict[str, Any]:
    _require_tenant()
    identifier = _text(record_id, "record_id", 64)
    choice = _text(decision, "decision", 32).lower()
    if choice not in _DECISIONS:
        raise ValueError(f"decision must be one of {sorted(_DECISIONS)}")
    why = _text(rationale, "rationale", 4000)
    human = _text(reviewer, "reviewer", 256)
    expected = _revision(expected_revision)

    def mutate(row: dict[str, Any]) -> None:
        _validated_record(row)
        if row.get("status") != "pending_review":
            raise ValueError("only a pending AI vendor-risk draft can be reviewed")
        row["status"] = choice
        row["review"] = {
            "decision": choice,
            "rationale": why,
            "reviewer": human,
            "reviewed_at": time.time(),
            "assessment_sha256": row["assessment_sha256"],
            "legal_certification": False,
        }

    saved = _VENDORS.update(
        identifier,
        mutate,
        expected_revision=expected,
        action=f"review_ai_vendor_{choice}",
        actor=human,
    )
    if saved is None:
        raise AIVendorRiskStateError("AI vendor-risk record does not exist")
    return _validated_record(saved)


def model_risk_evidence_payload(record_id: str) -> dict[str, Any]:
    """Return the bounded evidence fields for an approved vendor assessment."""

    record = get_vendor_assessment(record_id)
    if record is None:
        raise AIVendorRiskStateError("AI vendor-risk record does not exist")
    if record.get("status") != "approved":
        raise AIVendorRiskStateError(
            "model-risk projection requires an approved AI vendor assessment"
        )
    result = record["result"]
    if result["answered"] < result["total"]:
        outcome = "inconclusive"
    elif result["findings"]:
        outcome = "failed"
    else:
        outcome = "passed"
    return {
        "source_id": f"ai_vendor:{record['id']}:r{record['revision']}",
        "evidence_kind": "vendor_assessment",
        "result": outcome,
        "scope_digest": record["assessment_sha256"],
        "summary": (
            f"Approved governed AI vendor assessment {record['id']}; "
            f"residual risk {result['residual_risk']}."
        ),
        "metrics": {
            "ai_vendor_record_id": record["id"],
            "ai_vendor_record_revision": record["revision"],
            "assessment_sha256": record["assessment_sha256"],
            "answered": result["answered"],
            "total": result["total"],
            "findings": len(result["findings"]),
            "residual_risk": result["residual_risk"],
            "questionnaire_digest": record["template_digest"],
        },
    }


def project_to_model_risk(
    record_id: str,
    asset_id: str,
    *,
    actor: str,
    valid_until: float,
    officer: Any | None = None,
) -> dict[str, Any]:
    """Project an approved draft into the existing model-risk evidence plane.

    The artifact digest is resolved from the tenant's current model-risk
    observation rather than accepted from the caller.  Model-risk human review
    remains a second, independent gate after this projection.
    """

    _require_tenant()
    operator = _text(actor, "actor", 256)
    payload = model_risk_evidence_payload(record_id)
    if officer is None:
        from .model_risk_assurance import ModelRiskAssuranceOfficer

        officer = ModelRiskAssuranceOfficer()
    observation = officer.get_observation(asset_id)
    if observation is None:
        raise AIVendorRiskStateError(
            "model-risk projection requires a current observed AI asset"
        )
    observed_at = float(officer._now())
    if not math.isfinite(observed_at) or observed_at <= 0:
        raise AIVendorRiskStateError("model-risk authority clock is invalid")
    return officer.record_evidence(
        asset_id,
        source_id=payload["source_id"],
        evidence_kind=payload["evidence_kind"],
        result=payload["result"],
        scope_digest=payload["scope_digest"],
        artifact_digest=observation["version_digest"],
        actor=operator,
        observed_at=observed_at,
        valid_until=valid_until,
        summary=payload["summary"],
        metrics=payload["metrics"],
    )


__all__ = [
    "AI_VENDOR_DOCUMENT_SCHEMA",
    "AI_VENDOR_QUESTIONS",
    "AI_VENDOR_SCHEMA",
    "AI_VENDOR_TEMPLATE",
    "AIVendorRiskError",
    "AIVendorRiskConfigError",
    "AIVendorRiskStateError",
    "NON_CERTIFICATION_NOTICE",
    "draft_vendor_assessment",
    "extract_answers_from_connected_document",
    "extract_answers_from_document",
    "enabled",
    "find_vendor_assessment_by_attestation",
    "get_vendor_assessment",
    "list_vendor_assessments",
    "model_risk_evidence_payload",
    "prior_answer_plan",
    "project_to_model_risk",
    "questionnaire",
    "review_vendor_assessment",
]
