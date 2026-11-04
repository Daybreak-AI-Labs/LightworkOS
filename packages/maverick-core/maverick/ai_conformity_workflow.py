"""Governed EU AI Act conformity-readiness workflow.

This default-off module is an internal evidence-readiness aid.  It binds every
case to the exact current Model Risk observation revision and version digest,
keeps only compact SHA-256 evidence references, and requires two distinct human
principals to submit and approve a complete package.

It deliberately does not classify a system as a matter of law, perform a
conformity assessment, create or sign an EU declaration of conformity, affix or
authorise a CE mark, certify a system, or represent acceptance by a regulator
or notified body.  The legal checklist is an original, compact index derived
from the official consolidated Regulation (EU) 2024/1689; it does not reproduce
standards text.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

CASE_SCHEMA = "lightwork.eu-ai-conformity-readiness-case.v1"
EVIDENCE_SCHEMA = "lightwork.eu-ai-conformity-evidence-binding.v1"
SUBMISSION_SCHEMA = "lightwork.eu-ai-conformity-readiness-submission.v1"
APPROVAL_SCHEMA = "lightwork.eu-ai-conformity-readiness-approval.v1"
MANIFEST_SCHEMA = "lightwork.eu-ai-conformity-readiness-manifest.v1"
PROJECTION_SCHEMA = "lightwork.eu-ai-conformity-readiness-projection.v1"
PACKAGE_SCHEMA = "lightwork.eu-ai-conformity-readiness-package.v1"

CONSOLIDATED_REGULATION_URL = (
    "https://eur-lex.europa.eu/legal-content/EN/TXT/"
    "?uri=CELEX:02024R1689-20260727"
)
CONSOLIDATED_REGULATION_ELI = (
    "https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng"
)
LEGAL_TEXT_VERSION = "02024R1689-20260727"

NON_CERTIFICATION_NOTICE = (
    "Internal readiness evidence only. This workflow does not provide a legal "
    "classification, conformity determination, certification, CE marking, "
    "regulator acceptance, notified-body acceptance, or a final or signed EU "
    "declaration of conformity. Qualified humans remain responsible for every "
    "legal determination and external act."
)
DRAFT_DECLARATION_LABEL = (
    "DRAFT READINESS DATA ONLY - NOT AN EU DECLARATION OF CONFORMITY"
)
CE_READINESS_LABEL = "CE-MARKING READINESS ONLY - NO CE MARK IS CREATED OR AUTHORISED"
PACKAGE_LABEL = "INTERNAL READINESS PACKAGE - NO LEGAL OR EXTERNAL APPROVAL EFFECT"

FRIA_SECTIONS = (
    "1a_deployer_process",
    "1b_use_period_and_frequency",
    "1c_affected_person_categories",
    "1d_specific_harm_risks",
    "1e_human_oversight_implementation",
    "1f_risk_response_governance_and_complaints",
)
ANNEX_IV_SECTIONS = (
    "1_general_system_description",
    "2_development_elements_and_process",
    "3_monitoring_functioning_and_control",
    "4_performance_metric_appropriateness",
    "5_risk_management_system",
    "6_lifecycle_changes",
    "7_standards_or_other_technical_solutions",
    "8_declaration_copy_readiness",
    "9_post_market_monitoring_system_and_plan",
)
ARTICLE_43_SECTIONS = (
    "route_legal_basis_review",
    "quality_management_review",
    "technical_documentation_review",
    "design_development_consistency_review",
    "post_market_consistency_review",
    "notified_body_application_readiness",
    "notified_body_surveillance_readiness",
    "union_product_law_route_review",
    "substantial_modification_review",
)
POST_MARKET_SECTIONS = (
    "1_proportionate_monitoring_system",
    "2_active_systematic_data_collection",
    "2_lifetime_performance_analysis",
    "2_other_ai_system_interaction_analysis",
    "3_documented_monitoring_plan",
)
DECLARATION_DRAFT_SECTIONS = (
    "1_system_identification_data",
    "2_provider_identity_data",
    "3_provider_responsibility_authority_data",
    "4_conformity_statement_human_drafting_gate",
    "5_personal_data_law_statement_applicability",
    "6_standards_or_common_specification_references",
    "7_notified_body_and_certificate_applicability",
    "8_issue_and_authorised_signatory_data",
)
CE_MARKING_SECTIONS = (
    "1_general_principles_plan",
    "2_digital_accessibility_or_non_digital_basis",
    "3_visible_legible_indelible_affixing_plan",
    "4_notified_body_identifier_applicability",
    "5_other_union_law_marking_applicability",
)

CHECKLIST_SECTIONS: dict[str, tuple[str, ...]] = {
    "fria": FRIA_SECTIONS,
    "annex_iv": ANNEX_IV_SECTIONS,
    "article_43": ARTICLE_43_SECTIONS,
    "post_market": POST_MARKET_SECTIONS,
    "declaration_draft": DECLARATION_DRAFT_SECTIONS,
    "ce_marking": CE_MARKING_SECTIONS,
}

ARTICLE_43_ROUTE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "internal_control_annex_vi": (
        "route_legal_basis_review",
        "quality_management_review",
        "technical_documentation_review",
        "design_development_consistency_review",
        "post_market_consistency_review",
        "substantial_modification_review",
    ),
    "notified_body_annex_vii": (
        "route_legal_basis_review",
        "quality_management_review",
        "technical_documentation_review",
        "notified_body_application_readiness",
        "notified_body_surveillance_readiness",
        "substantial_modification_review",
    ),
    "union_harmonisation_law": (
        "route_legal_basis_review",
        "quality_management_review",
        "technical_documentation_review",
        "union_product_law_route_review",
        "substantial_modification_review",
    ),
}

_CASES = GovernedRecordStore(
    "eu_ai_conformity_readiness_cases",
    "EUC",
    "eu_ai_conformity_readiness_case",
)
_EVIDENCE = GovernedRecordStore(
    "eu_ai_conformity_evidence_bindings",
    "EUE",
    "eu_ai_conformity_evidence_binding",
)

_ASSET_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z", re.IGNORECASE)
_OPAQUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_PROVISION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .()/-]{0,127}\Z")
_HUMAN_RE = re.compile(r"user:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")

_ECONOMIC_OPERATOR_ROLES = frozenset({
    "provider",
    "deployer",
    "importer",
    "distributor",
    "product_manufacturer",
    "authorised_representative",
    "other",
})
_RISK_TIERS = frozenset({
    "prohibited",
    "high_risk",
    "limited",
    "minimal",
    "general_purpose",
    "undetermined",
})
_ACT_APPLICABILITY = frozenset({"applicable", "not_applicable", "undetermined"})
_FRIA_OUTCOMES = frozenset({"required", "not_required", "undetermined"})
_ARTICLE_43_ROUTES = frozenset({
    *ARTICLE_43_ROUTE_REQUIREMENTS,
    "not_applicable",
    "undetermined",
})
_ITEM_STATUSES = frozenset({"pending", "complete", "not_applicable"})
_EVIDENCE_TYPES = frozenset(CHECKLIST_SECTIONS)

_MAX_CASES = 5_000
_MAX_EVIDENCE_RECORDS = 10_000
_MAX_EVIDENCE_PER_CASE = 512
_MAX_BINDINGS_PER_ITEM = 16
_MAX_CITATIONS = 16
_MAX_SUBMISSIONS = 32
_MAX_APPROVALS = 32
_MAX_LIST_LIMIT = 500
_STORE_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})

_CASE_FIELDS = frozenset({
    "id",
    "schema",
    "tenant_ref",
    "request_sha256",
    "asset_binding",
    "declaration",
    "fria",
    "annex_iv",
    "article_43",
    "post_market",
    "declaration_draft",
    "ce_marking",
    "content_generation",
    "content_sha256",
    "submissions",
    "approvals",
    "workflow_status",
    "created_by",
    "last_operation_sha256",
    "last_operation_request_sha256",
    "state_sha256",
})
_EVIDENCE_FIELDS = frozenset({
    "id",
    "schema",
    "tenant_ref",
    "case_id",
    "asset_binding",
    "operation_sha256",
    "evidence_type",
    "source_ref",
    "evidence_sha256",
    "binding_sha256",
    "recorded_by",
    "recorded_at",
    "state_sha256",
})


class AIConformityWorkflowError(RuntimeError):
    """Base error for the governed readiness workflow."""


class AIConformityWorkflowConfigError(AIConformityWorkflowError):
    """The default-off feature or one of its authorities is unavailable."""


class AIConformityWorkflowStateError(AIConformityWorkflowError):
    """Persisted state or a governed dependency is malformed."""


class AIConformityWorkflowAssetError(AIConformityWorkflowError):
    """The exact current Model Risk asset binding cannot be established."""


class AIConformityWorkflowIncomplete(AIConformityWorkflowError):
    """A strict internal readiness package still has one or more gaps."""


class AIConformityWorkflowIdempotencyConflict(AIConformityWorkflowError):
    """An operation identity was reused for different content."""


@dataclass(frozen=True)
class HumanActor:
    """Opaque, non-PII human principal reference used for accountability."""

    principal_ref: str


@dataclass(frozen=True)
class LegalCitation:
    """Short provision locator pointing only to an official EUR-Lex source."""

    provision: str
    official_url: str = CONSOLIDATED_REGULATION_URL


@dataclass(frozen=True)
class EvidenceReference:
    """Compact evidence identity; source bytes and raw documents are forbidden."""

    evidence_type: str
    source_ref: str
    sha256: str


@dataclass(frozen=True)
class ChecklistEntry:
    """One governed checklist state containing only immutable bindings/digests."""

    status: str
    evidence_binding_ids: tuple[str, ...] = ()
    rationale_sha256: str | None = None
    citations: tuple[LegalCitation, ...] = ()


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


def _opaque(value: object, label: str, limit: int = 256) -> str:
    text = _text(value, label, limit)
    if not _OPAQUE_RE.fullmatch(text):
        raise ValueError(f"{label} must be an opaque non-PII reference")
    return text


def _human(actor: HumanActor) -> str:
    if not isinstance(actor, HumanActor):
        raise TypeError("actor must be a HumanActor")
    principal = _text(actor.principal_ref, "human principal_ref", 133)
    if not _HUMAN_RE.fullmatch(principal):
        raise ValueError(
            "human principal_ref must be an opaque non-PII user: reference"
        )
    return principal


def _digest(value: object, label: str) -> str:
    text = _text(value, label, 71).lower()
    if not _DIGEST_RE.fullmatch(text):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return text.removeprefix("sha256:")


def _asset_id(value: object) -> str:
    text = _text(value, "asset_id", 36)
    if not _ASSET_RE.fullmatch(text):
        raise ValueError("asset_id must be an exact Model Risk asset id")
    return text


def _positive_revision(value: object, label: str = "expected_revision") -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _timestamp(value: object, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{label} must be a positive finite timestamp")
    number = float(value)
    if number <= 0 or number >= 100_000_000_000 or number != number:
        raise ValueError(f"{label} must be a positive finite timestamp")
    return number


def _choice(value: object, label: str, allowed: frozenset[str]) -> str:
    text = _text(value, label, 64).lower()
    if text not in allowed:
        raise ValueError(f"{label} must be one of: {', '.join(sorted(allowed))}")
    return text


def _operation(value: object) -> str:
    key = _text(value, "operation_id", 256)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:32]}"


def _tenant_ref() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise AIConformityWorkflowStateError(
            "EU AI conformity readiness operations require an explicit tenant"
        )
    return "TEN-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:24]


def _citation(value: LegalCitation) -> dict[str, str]:
    if not isinstance(value, LegalCitation):
        raise TypeError("citations must contain LegalCitation values")
    provision = _text(value.provision, "legal provision", 128)
    if not _PROVISION_RE.fullmatch(provision):
        raise ValueError("legal provision is invalid")
    url = _text(value.official_url, "official legal URL", 1_000)
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "eur-lex.europa.eu"
        or not (parsed.path.startswith("/legal-content/") or parsed.path.startswith("/eli/"))
    ):
        raise ValueError("legal citations must point to an official EUR-Lex primary source")
    return {"provision": provision, "official_url": url}


def _citations(
    values: Sequence[LegalCitation] | None,
    *,
    required: bool,
) -> list[dict[str, str]]:
    if values is None:
        values = ()
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise TypeError("citations must be a sequence")
    if len(values) > _MAX_CITATIONS:
        raise ValueError(f"citations cannot exceed {_MAX_CITATIONS}")
    normalized = [_citation(value) for value in values]
    unique = {(item["provision"], item["official_url"]) for item in normalized}
    if len(unique) != len(normalized):
        raise ValueError("citations must be unique")
    if required and not normalized:
        raise ValueError("at least one official legal citation is required")
    return sorted(normalized, key=lambda item: (item["official_url"], item["provision"]))


def _blank_item() -> dict[str, Any]:
    return {
        "status": "pending",
        "evidence_bindings": [],
        "rationale_sha256": None,
        "citations": [],
    }


def _blank_items(domain: str) -> dict[str, dict[str, Any]]:
    return {section: _blank_item() for section in CHECKLIST_SECTIONS[domain]}


def _item_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": value.get("status"),
        "evidence_bindings": value.get("evidence_bindings"),
        "rationale_sha256": value.get("rationale_sha256"),
        "citations": value.get("citations"),
    }


def _validate_citation_rows(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > _MAX_CITATIONS:
        raise ValueError("stored citations are malformed")
    result: list[dict[str, str]] = []
    for row in value:
        if not isinstance(row, Mapping) or set(row) != {"provision", "official_url"}:
            raise ValueError("stored citation is malformed")
        result.append(
            _citation(LegalCitation(str(row["provision"]), str(row["official_url"])))
        )
    if result != sorted(result, key=lambda item: (item["official_url"], item["provision"])):
        raise ValueError("stored citations are not canonical")
    if len({(item["provision"], item["official_url"]) for item in result}) != len(result):
        raise ValueError("stored citations are duplicated")
    return result


def _validate_binding_pointer(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {
        "binding_id",
        "evidence_sha256",
        "binding_sha256",
    }:
        raise ValueError("evidence binding pointer is malformed")
    binding_id = _opaque(value["binding_id"], "binding_id", 36)
    if not binding_id.startswith("EUE-"):
        raise ValueError("evidence binding id is malformed")
    return {
        "binding_id": binding_id,
        "evidence_sha256": _digest(value["evidence_sha256"], "evidence_sha256"),
        "binding_sha256": _digest(value["binding_sha256"], "binding_sha256"),
    }


def _validate_item(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "status",
        "evidence_bindings",
        "rationale_sha256",
        "citations",
    }:
        raise ValueError("checklist item shape is malformed")
    status = _choice(value["status"], "checklist status", _ITEM_STATUSES)
    raw_bindings = value["evidence_bindings"]
    if not isinstance(raw_bindings, list) or len(raw_bindings) > _MAX_BINDINGS_PER_ITEM:
        raise ValueError("checklist evidence bindings are malformed")
    bindings = [_validate_binding_pointer(item) for item in raw_bindings]
    if len({item["binding_id"] for item in bindings}) != len(bindings):
        raise ValueError("checklist evidence bindings are duplicated")
    rationale = value["rationale_sha256"]
    rationale_digest = None if rationale is None else _digest(rationale, "rationale_sha256")
    citations = _validate_citation_rows(value["citations"])
    if status == "pending" and (bindings or rationale_digest or citations):
        raise ValueError("pending checklist items cannot carry completion evidence")
    if status == "complete" and not bindings:
        raise ValueError("complete checklist items require evidence bindings")
    if status == "not_applicable" and (not rationale_digest or not citations):
        raise ValueError(
            "not-applicable checklist items require a rationale digest and citation"
        )
    return {
        "status": status,
        "evidence_bindings": bindings,
        "rationale_sha256": rationale_digest,
        "citations": citations,
    }


def _asset_binding(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "asset_id",
        "asset_revision",
        "asset_version_digest",
    }:
        raise ValueError("asset binding shape is malformed")
    return {
        "asset_id": _asset_id(value["asset_id"]),
        "asset_revision": _positive_revision(value["asset_revision"], "asset_revision"),
        "asset_version_digest": _digest(
            value["asset_version_digest"], "asset_version_digest"
        ),
    }


def _validate_declaration(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "economic_operator_role",
        "risk_tier",
        "act_applicability",
        "legal_basis",
        "asserted_by",
        "asserted_at",
        "classification_source",
    }:
        raise ValueError("human declaration shape is malformed")
    legal_basis = _validate_citation_rows(value["legal_basis"])
    if not legal_basis:
        raise ValueError("human declaration legal basis is missing")
    if value["classification_source"] != "human_declaration_unverified":
        raise ValueError("human declaration source is malformed")
    return {
        "economic_operator_role": _choice(
            value["economic_operator_role"],
            "economic_operator_role",
            _ECONOMIC_OPERATOR_ROLES,
        ),
        "risk_tier": _choice(value["risk_tier"], "risk_tier", _RISK_TIERS),
        "act_applicability": _choice(
            value["act_applicability"],
            "act_applicability",
            _ACT_APPLICABILITY,
        ),
        "legal_basis": legal_basis,
        "asserted_by": _human(HumanActor(str(value["asserted_by"]))),
        "asserted_at": _timestamp(value["asserted_at"], "asserted_at"),
        "classification_source": "human_declaration_unverified",
    }


def _validate_determination(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "outcome",
        "rationale_sha256",
        "citations",
        "decided_by",
        "decided_at",
    }:
        raise ValueError("FRIA determination shape is malformed")
    outcome = _choice(value["outcome"], "FRIA outcome", _FRIA_OUTCOMES)
    rationale = value["rationale_sha256"]
    citations = _validate_citation_rows(value["citations"])
    decided_by = value["decided_by"]
    decided_at = value["decided_at"]
    if outcome == "undetermined":
        if rationale is not None or citations or decided_by is not None or decided_at is not None:
            raise ValueError("undetermined FRIA determination carries decision material")
        return {
            "outcome": outcome,
            "rationale_sha256": None,
            "citations": [],
            "decided_by": None,
            "decided_at": None,
        }
    if rationale is None or not citations or decided_by is None or decided_at is None:
        raise ValueError("FRIA determination is incomplete")
    return {
        "outcome": outcome,
        "rationale_sha256": _digest(rationale, "FRIA rationale_sha256"),
        "citations": citations,
        "decided_by": _human(HumanActor(str(decided_by))),
        "decided_at": _timestamp(decided_at, "FRIA decided_at"),
    }


def _validate_route(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "route",
        "rationale_sha256",
        "citations",
        "selected_by",
        "selected_at",
        "selection_source",
    }:
        raise ValueError("Article 43 route shape is malformed")
    route = _choice(value["route"], "Article 43 route", _ARTICLE_43_ROUTES)
    rationale = value["rationale_sha256"]
    citations = _validate_citation_rows(value["citations"])
    selected_by = value["selected_by"]
    selected_at = value["selected_at"]
    if value["selection_source"] != "human_declaration_unverified":
        raise ValueError("Article 43 route source is malformed")
    if route == "undetermined":
        if rationale is not None or citations or selected_by is not None or selected_at is not None:
            raise ValueError("undetermined Article 43 route carries decision material")
        return {
            "route": route,
            "rationale_sha256": None,
            "citations": [],
            "selected_by": None,
            "selected_at": None,
            "selection_source": "human_declaration_unverified",
        }
    if rationale is None or not citations or selected_by is None or selected_at is None:
        raise ValueError("Article 43 route declaration is incomplete")
    return {
        "route": route,
        "rationale_sha256": _digest(rationale, "Article 43 rationale_sha256"),
        "citations": citations,
        "selected_by": _human(HumanActor(str(selected_by))),
        "selected_at": _timestamp(selected_at, "Article 43 selected_at"),
        "selection_source": "human_declaration_unverified",
    }


def _validate_items(value: object, domain: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != set(CHECKLIST_SECTIONS[domain]):
        raise ValueError(f"{domain} checklist shape is malformed")
    return {section: _validate_item(value[section]) for section in CHECKLIST_SECTIONS[domain]}


def _evidence_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": record.get("schema"),
        "tenant_ref": record.get("tenant_ref"),
        "case_id": record.get("case_id"),
        "asset_binding": record.get("asset_binding"),
        "evidence_type": record.get("evidence_type"),
        "source_ref": record.get("source_ref"),
        "evidence_sha256": record.get("evidence_sha256"),
    }


def _evidence_state(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": record.get("id"),
        "operation_sha256": record.get("operation_sha256"),
        "binding_sha256": record.get("binding_sha256"),
        "recorded_by": record.get("recorded_by"),
        "recorded_at": record.get("recorded_at"),
    }


def _validate_evidence_record(
    record: object,
    *,
    tenant_ref: str,
    case_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise AIConformityWorkflowStateError("stored evidence binding is not an object")
    if set(record) - _EVIDENCE_FIELDS - _STORE_METADATA or _EVIDENCE_FIELDS - set(record):
        raise AIConformityWorkflowStateError("stored evidence binding shape is malformed")
    try:
        binding_id = _opaque(record["id"], "binding id", 36)
        if not binding_id.startswith("EUE-"):
            raise ValueError("binding identity is malformed")
        if record["schema"] != EVIDENCE_SCHEMA or record["tenant_ref"] != tenant_ref:
            raise ValueError("evidence schema or tenant binding mismatch")
        bound_case = _opaque(record["case_id"], "case_id", 36)
        if case_id is not None and bound_case != case_id:
            raise ValueError("evidence case binding mismatch")
        _asset_binding(record["asset_binding"])
        _digest(record["operation_sha256"], "operation_sha256")
        _choice(record["evidence_type"], "evidence_type", _EVIDENCE_TYPES)
        _opaque(record["source_ref"], "source_ref")
        _digest(record["evidence_sha256"], "evidence_sha256")
        _human(HumanActor(str(record["recorded_by"])))
        _timestamp(record["recorded_at"], "recorded_at")
        if _sha256(_evidence_payload(record)) != record["binding_sha256"]:
            raise ValueError("evidence binding digest mismatch")
        if _sha256(_evidence_state(record)) != record["state_sha256"]:
            raise ValueError("evidence state digest mismatch")
        _digest(record["state_sha256"], "state_sha256")
        if "revision" in record:
            _positive_revision(record["revision"], "evidence revision")
    except (KeyError, TypeError, ValueError) as exc:
        raise AIConformityWorkflowStateError("stored evidence binding is malformed") from exc
    return dict(record)


def _public_evidence(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "binding_id": record["id"],
        "evidence_type": record["evidence_type"],
        "source_ref": record["source_ref"],
        "asset_binding": dict(record["asset_binding"]),
        "evidence_sha256": record["evidence_sha256"],
        "binding_sha256": record["binding_sha256"],
    }


def _manifest_payload(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {key: manifest.get(key) for key in (
        "schema",
        "legal_text_version",
        "official_source_urls",
        "case_id",
        "tenant_ref",
        "case_content_generation",
        "case_content_sha256",
        "asset_binding",
        "section_digests",
        "evidence_bindings_sha256",
        "evidence_binding_count",
        "gaps",
        "complete",
        "legal_effects",
        "notice",
    )}


def _validate_manifest(value: object, *, tenant_ref: str, case_id: str) -> dict[str, Any]:
    fields = set(_manifest_payload({})) | {"manifest_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("submission manifest shape is malformed")
    if value["schema"] != MANIFEST_SCHEMA or value["legal_text_version"] != LEGAL_TEXT_VERSION:
        raise ValueError("submission manifest schema is unsupported")
    if value["tenant_ref"] != tenant_ref or value["case_id"] != case_id:
        raise ValueError("submission manifest authority binding mismatch")
    if value["official_source_urls"] != [
        CONSOLIDATED_REGULATION_URL,
        CONSOLIDATED_REGULATION_ELI,
    ]:
        raise ValueError("submission manifest legal source binding mismatch")
    _positive_revision(value["case_content_generation"], "case_content_generation")
    _digest(value["case_content_sha256"], "case_content_sha256")
    _asset_binding(value["asset_binding"])
    section_digests = value["section_digests"]
    expected_sections = {
        "human_declaration",
        "fria",
        "annex_iv",
        "article_43",
        "post_market",
        "declaration_draft",
        "ce_marking",
    }
    if not isinstance(section_digests, Mapping) or set(section_digests) != expected_sections:
        raise ValueError("submission manifest section digests are malformed")
    for digest in section_digests.values():
        _digest(digest, "section digest")
    _digest(value["evidence_bindings_sha256"], "evidence_bindings_sha256")
    count = value["evidence_binding_count"]
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= _MAX_EVIDENCE_PER_CASE:
        raise ValueError("submission manifest evidence count is malformed")
    gaps = value["gaps"]
    if (
        not isinstance(gaps, list)
        or len(gaps) > 128
        or any(not isinstance(gap, str) or not _OPAQUE_RE.fullmatch(gap) for gap in gaps)
        or gaps != sorted(set(gaps))
    ):
        raise ValueError("submission manifest gaps are malformed")
    if not isinstance(value["complete"], bool) or value["complete"] != (not gaps):
        raise ValueError("submission manifest completeness is inconsistent")
    if value["legal_effects"] != _no_legal_effects():
        raise ValueError("submission manifest legal-effect boundary changed")
    if value["notice"] != NON_CERTIFICATION_NOTICE:
        raise ValueError("submission manifest notice changed")
    if _sha256(_manifest_payload(value)) != value["manifest_sha256"]:
        raise ValueError("submission manifest digest mismatch")
    return dict(value)


def _submission_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record.get(key) for key in (
        "id",
        "schema",
        "operation_sha256",
        "case_id",
        "case_content_generation",
        "case_content_sha256",
        "asset_binding",
        "manifest",
        "manifest_sha256",
        "submitted_by",
        "submitted_at",
        "scope",
        "legal_effect",
    )}


def _validate_submission(value: object, *, tenant_ref: str, case_id: str) -> dict[str, Any]:
    fields = set(_submission_payload({})) | {"submission_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("submission record shape is malformed")
    submission_id = _opaque(value["id"], "submission id", 36)
    if not submission_id.startswith("EUS-") or value["schema"] != SUBMISSION_SCHEMA:
        raise ValueError("submission identity is malformed")
    if value["case_id"] != case_id:
        raise ValueError("submission case binding mismatch")
    _digest(value["operation_sha256"], "operation_sha256")
    generation = _positive_revision(
        value["case_content_generation"], "case_content_generation"
    )
    content_sha = _digest(value["case_content_sha256"], "case_content_sha256")
    binding = _asset_binding(value["asset_binding"])
    manifest = _validate_manifest(value["manifest"], tenant_ref=tenant_ref, case_id=case_id)
    if (
        manifest["case_content_generation"] != generation
        or manifest["case_content_sha256"] != content_sha
        or manifest["asset_binding"] != binding
        or manifest["manifest_sha256"] != value["manifest_sha256"]
    ):
        raise ValueError("submission manifest binding mismatch")
    _human(HumanActor(str(value["submitted_by"])))
    _timestamp(value["submitted_at"], "submitted_at")
    if value["scope"] != "internal_readiness_package_only" or value["legal_effect"] is not False:
        raise ValueError("submission scope changed")
    if _sha256(_submission_payload(value)) != value["submission_sha256"]:
        raise ValueError("submission digest mismatch")
    return dict(value)


def _approval_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record.get(key) for key in (
        "id",
        "schema",
        "operation_sha256",
        "submission_id",
        "submission_sha256",
        "approved_by",
        "approved_at",
        "four_eyes_verified",
        "scope",
        "legal_effect",
    )}


def _validate_approval(value: object) -> dict[str, Any]:
    fields = set(_approval_payload({})) | {"approval_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("approval record shape is malformed")
    approval_id = _opaque(value["id"], "approval id", 36)
    submission_id = _opaque(value["submission_id"], "submission id", 36)
    if not approval_id.startswith("EUA-") or not submission_id.startswith("EUS-"):
        raise ValueError("approval identity is malformed")
    if value["schema"] != APPROVAL_SCHEMA:
        raise ValueError("approval schema is unsupported")
    _digest(value["operation_sha256"], "operation_sha256")
    _digest(value["submission_sha256"], "submission_sha256")
    _human(HumanActor(str(value["approved_by"])))
    _timestamp(value["approved_at"], "approved_at")
    if value["four_eyes_verified"] is not True:
        raise ValueError("approval four-eyes boundary changed")
    if value["scope"] != "internal_readiness_package_only" or value["legal_effect"] is not False:
        raise ValueError("approval scope changed")
    if _sha256(_approval_payload(value)) != value["approval_sha256"]:
        raise ValueError("approval digest mismatch")
    return dict(value)


def _case_content(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record.get(key) for key in (
        "asset_binding",
        "declaration",
        "fria",
        "annex_iv",
        "article_43",
        "post_market",
        "declaration_draft",
        "ce_marking",
    )}


def _case_state(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record.get(key) for key in (
        "id",
        "schema",
        "tenant_ref",
        "request_sha256",
        "content_generation",
        "content_sha256",
        "submissions",
        "approvals",
        "workflow_status",
        "created_by",
        "last_operation_sha256",
        "last_operation_request_sha256",
    )} | {"content": _case_content(record)}


def _validate_case_record(record: object, *, tenant_ref: str) -> dict[str, Any]:  # noqa: C901
    if not isinstance(record, Mapping):
        raise AIConformityWorkflowStateError("stored conformity case is not an object")
    if set(record) - _CASE_FIELDS - _STORE_METADATA or _CASE_FIELDS - set(record):
        raise AIConformityWorkflowStateError("stored conformity case shape is malformed")
    try:
        case_id = _opaque(record["id"], "case id", 36)
        if not case_id.startswith("EUC-"):
            raise ValueError("case identity is malformed")
        if record["schema"] != CASE_SCHEMA or record["tenant_ref"] != tenant_ref:
            raise ValueError("case schema or tenant binding mismatch")
        _digest(record["request_sha256"], "request_sha256")
        _asset_binding(record["asset_binding"])
        _validate_declaration(record["declaration"])
        fria = record["fria"]
        if not isinstance(fria, Mapping) or set(fria) != {"determination", "items"}:
            raise ValueError("FRIA record shape is malformed")
        _validate_determination(fria["determination"])
        _validate_items(fria["items"], "fria")
        annex = record["annex_iv"]
        if not isinstance(annex, Mapping) or set(annex) != {"items"}:
            raise ValueError("Annex IV record shape is malformed")
        _validate_items(annex["items"], "annex_iv")
        article = record["article_43"]
        if not isinstance(article, Mapping) or set(article) != {"route", "items"}:
            raise ValueError("Article 43 record shape is malformed")
        _validate_route(article["route"])
        _validate_items(article["items"], "article_43")
        post_market = record["post_market"]
        if not isinstance(post_market, Mapping) or set(post_market) != {"items"}:
            raise ValueError("post-market record shape is malformed")
        _validate_items(post_market["items"], "post_market")
        declaration = record["declaration_draft"]
        if not isinstance(declaration, Mapping) or set(declaration) != {
            "label", "signed", "final_declaration_generated", "items"
        }:
            raise ValueError("declaration draft shape is malformed")
        if (
            declaration["label"] != DRAFT_DECLARATION_LABEL
            or declaration["signed"] is not False
            or declaration["final_declaration_generated"] is not False
        ):
            raise ValueError("declaration draft legal boundary changed")
        _validate_items(declaration["items"], "declaration_draft")
        ce = record["ce_marking"]
        if not isinstance(ce, Mapping) or set(ce) != {
            "label", "mark_created", "mark_affixed", "items"
        }:
            raise ValueError("CE readiness shape is malformed")
        if (
            ce["label"] != CE_READINESS_LABEL
            or ce["mark_created"] is not False
            or ce["mark_affixed"] is not False
        ):
            raise ValueError("CE-marking legal boundary changed")
        _validate_items(ce["items"], "ce_marking")
        _positive_revision(record["content_generation"], "content_generation")
        if _sha256(_case_content(record)) != record["content_sha256"]:
            raise ValueError("case content digest mismatch")
        submissions = record["submissions"]
        approvals = record["approvals"]
        if not isinstance(submissions, list) or len(submissions) > _MAX_SUBMISSIONS:
            raise ValueError("case submission history is malformed")
        if not isinstance(approvals, list) or len(approvals) > _MAX_APPROVALS:
            raise ValueError("case approval history is malformed")
        validated_submissions = [
            _validate_submission(item, tenant_ref=tenant_ref, case_id=case_id)
            for item in submissions
        ]
        validated_approvals = [_validate_approval(item) for item in approvals]
        if len({item["id"] for item in validated_submissions}) != len(validated_submissions):
            raise ValueError("case submissions are duplicated")
        if len({item["id"] for item in validated_approvals}) != len(validated_approvals):
            raise ValueError("case approvals are duplicated")
        submissions_by_id = {item["id"]: item for item in validated_submissions}
        for approval in validated_approvals:
            submission = submissions_by_id.get(approval["submission_id"])
            if (
                submission is None
                or approval["submission_sha256"] != submission["submission_sha256"]
                or approval["approved_by"] == submission["submitted_by"]
            ):
                raise ValueError("approval submission or four-eyes binding mismatch")
        workflow = _choice(
            record["workflow_status"],
            "workflow_status",
            frozenset({"draft", "submitted", "approved"}),
        )
        if workflow == "submitted" and not submissions:
            raise ValueError("submitted case has no submission")
        if workflow == "approved" and (not submissions or not approvals):
            raise ValueError("approved case has no approval")
        _human(HumanActor(str(record["created_by"])))
        last_operation = record["last_operation_sha256"]
        last_request = record["last_operation_request_sha256"]
        if (last_operation is None) != (last_request is None):
            raise ValueError("last operation binding is incomplete")
        if last_operation is not None and last_request is not None:
            _digest(last_operation, "last_operation_sha256")
            _digest(last_request, "last_operation_request_sha256")
        if _sha256(_case_state(record)) != record["state_sha256"]:
            raise ValueError("case state digest mismatch")
        _digest(record["state_sha256"], "state_sha256")
        if "revision" in record:
            _positive_revision(record["revision"], "case revision")
    except (KeyError, TypeError, ValueError) as exc:
        raise AIConformityWorkflowStateError("stored conformity case is malformed") from exc
    return dict(record)


def _no_legal_effects() -> dict[str, bool]:
    return {
        "legal_classification": False,
        "conformity_determination": False,
        "certification": False,
        "ce_marking": False,
        "regulator_acceptance": False,
        "notified_body_acceptance": False,
        "final_signed_declaration": False,
    }


class EUAIConformityWorkflow:
    """Tenant-scoped CAS authority for internal conformity-readiness cases."""

    def __init__(
        self,
        *,
        cases: GovernedRecordStore | None = None,
        evidence: GovernedRecordStore | None = None,
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
        self._cases = cases or _CASES
        self._evidence = evidence or _EVIDENCE
        self._asset_lookup = asset_lookup
        self._clock = clock
        self._enforce_feature = enforce_feature

    @property
    def backend_kind(self) -> str:
        kinds = {self._cases.backend_kind, self._evidence.backend_kind}
        if len(kinds) != 1:
            raise AIConformityWorkflowStateError(
                "conformity cases and evidence bindings use different backends"
            )
        return next(iter(kinds))

    def _require_active(self) -> str:
        if self._enforce_feature:
            require_enabled()
        _ = self.backend_kind
        return _tenant_ref()

    def _now(self) -> float:
        source = self._clock or self._cases.authoritative_time
        try:
            return _timestamp(source(), "authority time")
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise AIConformityWorkflowStateError(
                "conformity workflow authority time is unavailable"
            ) from exc

    def _current_asset(self, asset_id: object) -> dict[str, Any]:
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
            raise AIConformityWorkflowAssetError("Model Risk asset lookup failed") from exc
        if not isinstance(observation, Mapping):
            raise AIConformityWorkflowAssetError("Model Risk asset does not exist")
        try:
            binding = _asset_binding({
                "asset_id": observation.get("asset_id"),
                "asset_revision": observation.get("revision"),
                "asset_version_digest": observation.get("version_digest"),
            })
        except (TypeError, ValueError) as exc:
            raise AIConformityWorkflowAssetError(
                "Model Risk asset binding is malformed"
            ) from exc
        if binding["asset_id"] != asset:
            raise AIConformityWorkflowAssetError("Model Risk asset lookup changed identity")
        return binding

    def _get_case_record(self, case_id: object, *, tenant_ref: str) -> dict[str, Any]:
        identity = _opaque(case_id, "case_id", 36)
        if not identity.startswith("EUC-"):
            raise ValueError("case_id is malformed")
        raw = self._cases.get(identity)
        if raw is None:
            raise AIConformityWorkflowStateError("conformity case does not exist")
        return _validate_case_record(raw, tenant_ref=tenant_ref)

    def _get_evidence_record(
        self,
        binding_id: object,
        *,
        tenant_ref: str,
        case_id: str,
    ) -> dict[str, Any]:
        identity = _opaque(binding_id, "binding_id", 36)
        raw = self._evidence.get(identity)
        if raw is None:
            raise AIConformityWorkflowStateError("referenced evidence binding is missing")
        return _validate_evidence_record(raw, tenant_ref=tenant_ref, case_id=case_id)

    @staticmethod
    def _binding_pointers(record: Mapping[str, Any]) -> list[tuple[str, dict[str, str]]]:
        pointers: list[tuple[str, dict[str, str]]] = []
        for domain in CHECKLIST_SECTIONS:
            container = record[domain]
            items = container["items"]
            for section in CHECKLIST_SECTIONS[domain]:
                for pointer in items[section]["evidence_bindings"]:
                    pointers.append((domain, dict(pointer)))
        return pointers

    def _validated_references(
        self,
        record: Mapping[str, Any],
        *,
        tenant_ref: str,
    ) -> dict[str, dict[str, Any]]:
        references: dict[str, dict[str, Any]] = {}
        for domain, pointer in self._binding_pointers(record):
            binding_id = pointer["binding_id"]
            evidence = self._get_evidence_record(
                binding_id,
                tenant_ref=tenant_ref,
                case_id=record["id"],
            )
            if evidence["evidence_type"] != domain:
                raise AIConformityWorkflowStateError(
                    "evidence binding type does not match checklist domain"
                )
            if evidence["asset_binding"] != record["asset_binding"]:
                raise AIConformityWorkflowStateError(
                    "evidence binding does not match the case asset version"
                )
            if (
                evidence["evidence_sha256"] != pointer["evidence_sha256"]
                or evidence["binding_sha256"] != pointer["binding_sha256"]
            ):
                raise AIConformityWorkflowStateError(
                    "evidence binding pointer digest does not match immutable evidence"
                )
            prior = references.get(binding_id)
            if prior is not None and prior["binding_sha256"] != evidence["binding_sha256"]:
                raise AIConformityWorkflowStateError("evidence binding identity collision")
            references[binding_id] = evidence
        if len(references) > _MAX_EVIDENCE_PER_CASE:
            raise AIConformityWorkflowStateError("case evidence bindings exceed their bound")
        return references

    @staticmethod
    def _item_gap(
        gaps: list[str],
        *,
        domain: str,
        section: str,
        item: Mapping[str, Any],
        allow_not_applicable: bool,
    ) -> None:
        status = item["status"]
        if status == "complete":
            return
        if status == "not_applicable" and allow_not_applicable:
            return
        gaps.append(f"{domain}.{section}")

    def _manifest(
        self,
        record: Mapping[str, Any],
        *,
        tenant_ref: str,
        current_asset: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:  # noqa: C901
        references = self._validated_references(record, tenant_ref=tenant_ref)
        gaps: list[str] = []
        declaration = record["declaration"]
        if declaration["act_applicability"] != "applicable":
            gaps.append("human_declaration.act_applicability_not_applicable_or_undetermined")
        if declaration["risk_tier"] != "high_risk":
            gaps.append("human_declaration.risk_tier_not_high_risk")
        if record["asset_binding"] != current_asset:
            gaps.append("asset_binding.stale_model_risk_revision_or_version")

        determination = record["fria"]["determination"]
        if determination["outcome"] == "undetermined":
            gaps.append("fria.determination")
        elif determination["outcome"] == "required":
            for section in FRIA_SECTIONS:
                self._item_gap(
                    gaps,
                    domain="fria",
                    section=section,
                    item=record["fria"]["items"][section],
                    allow_not_applicable=False,
                )

        for section in ANNEX_IV_SECTIONS:
            self._item_gap(
                gaps,
                domain="annex_iv",
                section=section,
                item=record["annex_iv"]["items"][section],
                allow_not_applicable=False,
            )

        route = record["article_43"]["route"]["route"]
        route_requirements = ARTICLE_43_ROUTE_REQUIREMENTS.get(route)
        if route_requirements is None:
            gaps.append("article_43.route")
        else:
            for section in route_requirements:
                self._item_gap(
                    gaps,
                    domain="article_43",
                    section=section,
                    item=record["article_43"]["items"][section],
                    allow_not_applicable=False,
                )

        post_market_na = {"2_other_ai_system_interaction_analysis"}
        for section in POST_MARKET_SECTIONS:
            self._item_gap(
                gaps,
                domain="post_market",
                section=section,
                item=record["post_market"]["items"][section],
                allow_not_applicable=section in post_market_na,
            )

        declaration_na = {
            "5_personal_data_law_statement_applicability",
            "6_standards_or_common_specification_references",
            "7_notified_body_and_certificate_applicability",
        }
        for section in DECLARATION_DRAFT_SECTIONS:
            self._item_gap(
                gaps,
                domain="declaration_draft",
                section=section,
                item=record["declaration_draft"]["items"][section],
                allow_not_applicable=section in declaration_na,
            )

        ce_na = {
            "2_digital_accessibility_or_non_digital_basis",
            "4_notified_body_identifier_applicability",
            "5_other_union_law_marking_applicability",
        }
        for section in CE_MARKING_SECTIONS:
            self._item_gap(
                gaps,
                domain="ce_marking",
                section=section,
                item=record["ce_marking"]["items"][section],
                allow_not_applicable=section in ce_na,
            )

        section_digests = {
            "human_declaration": _sha256(record["declaration"]),
            "fria": _sha256(record["fria"]),
            "annex_iv": _sha256(record["annex_iv"]),
            "article_43": _sha256(record["article_43"]),
            "post_market": _sha256(record["post_market"]),
            "declaration_draft": _sha256(record["declaration_draft"]),
            "ce_marking": _sha256(record["ce_marking"]),
        }
        exact_bindings = [
            {
                "binding_id": item["id"],
                "evidence_sha256": item["evidence_sha256"],
                "binding_sha256": item["binding_sha256"],
            }
            for item in sorted(references.values(), key=lambda row: row["id"])
        ]
        manifest: dict[str, Any] = {
            "schema": MANIFEST_SCHEMA,
            "legal_text_version": LEGAL_TEXT_VERSION,
            "official_source_urls": [
                CONSOLIDATED_REGULATION_URL,
                CONSOLIDATED_REGULATION_ELI,
            ],
            "case_id": record["id"],
            "tenant_ref": tenant_ref,
            "case_content_generation": record["content_generation"],
            "case_content_sha256": record["content_sha256"],
            "asset_binding": dict(record["asset_binding"]),
            "section_digests": section_digests,
            "evidence_bindings_sha256": _sha256(exact_bindings),
            "evidence_binding_count": len(exact_bindings),
            "gaps": sorted(set(gaps)),
            "complete": not gaps,
            "legal_effects": _no_legal_effects(),
            "notice": NON_CERTIFICATION_NOTICE,
        }
        manifest["manifest_sha256"] = _sha256(_manifest_payload(manifest))
        _validate_manifest(manifest, tenant_ref=tenant_ref, case_id=record["id"])
        return manifest, references

    @staticmethod
    def _current_submission(
        record: Mapping[str, Any], manifest: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        for submission in reversed(record["submissions"]):
            if (
                submission["case_content_generation"] == record["content_generation"]
                and submission["case_content_sha256"] == record["content_sha256"]
                and submission["asset_binding"] == manifest["asset_binding"]
                and submission["manifest_sha256"] == manifest["manifest_sha256"]
            ):
                return dict(submission)
        return None

    @staticmethod
    def _current_approval(
        record: Mapping[str, Any], submission: Mapping[str, Any] | None
    ) -> dict[str, Any] | None:
        if submission is None:
            return None
        for approval in reversed(record["approvals"]):
            if (
                approval["submission_id"] == submission["id"]
                and approval["submission_sha256"] == submission["submission_sha256"]
            ):
                return dict(approval)
        return None

    @staticmethod
    def _project_items(record: Mapping[str, Any], domain: str) -> dict[str, Any]:
        return {
            section: {
                "status": record[domain]["items"][section]["status"],
                "evidence_bindings": [
                    dict(pointer)
                    for pointer in record[domain]["items"][section]["evidence_bindings"]
                ],
                "rationale_sha256": record[domain]["items"][section][
                    "rationale_sha256"
                ],
                "citations": [
                    dict(citation)
                    for citation in record[domain]["items"][section]["citations"]
                ],
            }
            for section in CHECKLIST_SECTIONS[domain]
        }

    def _projection_from_record(
        self,
        record: Mapping[str, Any],
        *,
        tenant_ref: str,
    ) -> dict[str, Any]:
        current_asset = self._current_asset(record["asset_binding"]["asset_id"])
        manifest, _ = self._manifest(
            record,
            tenant_ref=tenant_ref,
            current_asset=current_asset,
        )
        submission = self._current_submission(record, manifest)
        approval = self._current_approval(record, submission)
        stale_reasons: list[str] = []
        if record["asset_binding"] != current_asset:
            stale_reasons.append("model_risk_asset_revision_or_version_changed")
        if record["submissions"] and submission is None:
            stale_reasons.append("submitted_manifest_or_case_content_changed")
        if record["approvals"] and approval is None:
            stale_reasons.append("approved_submission_is_not_current")

        if stale_reasons:
            readiness_status = "stale_internal_readiness_evidence"
        elif approval is not None:
            readiness_status = "approved_internal_readiness_package_current"
        elif submission is not None:
            readiness_status = "submitted_for_distinct_human_readiness_approval"
        elif manifest["complete"]:
            readiness_status = "complete_internal_draft_not_submitted"
        else:
            readiness_status = "incomplete_internal_draft"

        ce_gaps = [gap for gap in manifest["gaps"] if gap.startswith("ce_marking.")]
        if stale_reasons:
            ce_status = "stale_readiness_data"
        elif ce_gaps:
            ce_status = "incomplete_readiness_data"
        elif approval is not None:
            ce_status = "current_for_qualified_human_review_only"
        else:
            ce_status = "draft_readiness_data_not_approved"

        return {
            "schema": PROJECTION_SCHEMA,
            "case_id": record["id"],
            "revision": record["revision"],
            "content_generation": record["content_generation"],
            "content_sha256": record["content_sha256"],
            "asset_binding": dict(record["asset_binding"]),
            "current_model_risk_binding": dict(current_asset),
            "asset_binding_current": record["asset_binding"] == current_asset,
            "human_declaration": {
                "economic_operator_role": record["declaration"]["economic_operator_role"],
                "risk_tier": record["declaration"]["risk_tier"],
                "act_applicability": record["declaration"]["act_applicability"],
                "legal_basis": [
                    dict(citation) for citation in record["declaration"]["legal_basis"]
                ],
                "classification_source": "human_declaration_unverified",
            },
            "fria": {
                "determination": dict(record["fria"]["determination"]),
                "items": self._project_items(record, "fria"),
            },
            "annex_iv": {"items": self._project_items(record, "annex_iv")},
            "article_43": {
                "route": dict(record["article_43"]["route"]),
                "items": self._project_items(record, "article_43"),
            },
            "post_market": {"items": self._project_items(record, "post_market")},
            "declaration_draft": {
                "label": DRAFT_DECLARATION_LABEL,
                "signed": False,
                "final_declaration_generated": False,
                "items": self._project_items(record, "declaration_draft"),
            },
            "ce_marking_readiness": {
                "label": CE_READINESS_LABEL,
                "status": ce_status,
                "mark_created": False,
                "mark_affixed": False,
                "items": self._project_items(record, "ce_marking"),
            },
            "workflow_status": readiness_status,
            "stored_workflow_status": record["workflow_status"],
            "stale": bool(stale_reasons),
            "stale_reasons": stale_reasons,
            "strict_manifest": dict(manifest),
            "current_submission": (
                None
                if submission is None
                else {
                    "submission_id": submission["id"],
                    "submission_sha256": submission["submission_sha256"],
                    "manifest_sha256": submission["manifest_sha256"],
                    "scope": submission["scope"],
                    "legal_effect": False,
                }
            ),
            "current_approval": (
                None
                if approval is None
                else {
                    "approval_id": approval["id"],
                    "approval_sha256": approval["approval_sha256"],
                    "submission_id": approval["submission_id"],
                    "four_eyes_verified": True,
                    "scope": approval["scope"],
                    "legal_effect": False,
                }
            ),
            "legal_classification_status": "human_declared_unverified",
            "legal_effects": _no_legal_effects(),
            "notice": NON_CERTIFICATION_NOTICE,
        }

    def create_case(
        self,
        *,
        asset_id: str,
        economic_operator_role: str,
        risk_tier: str,
        act_applicability: str,
        legal_basis: Sequence[LegalCitation],
        operation_id: str,
        actor: HumanActor,
    ) -> dict[str, Any]:
        """Idempotently create a human-declared case bound to current Model Risk."""

        tenant_ref = self._require_active()
        principal = _human(actor)
        binding = self._current_asset(asset_id)
        role = _choice(
            economic_operator_role,
            "economic_operator_role",
            _ECONOMIC_OPERATOR_ROLES,
        )
        tier = _choice(risk_tier, "risk_tier", _RISK_TIERS)
        applicability = _choice(
            act_applicability,
            "act_applicability",
            _ACT_APPLICABILITY,
        )
        citations = _citations(legal_basis, required=True)
        operation_sha = _operation(operation_id)
        case_id = _stable_id("EUC", tenant_ref, operation_sha)
        now = self._now()
        request = {
            "asset_binding": binding,
            "economic_operator_role": role,
            "risk_tier": tier,
            "act_applicability": applicability,
            "legal_basis": citations,
            "asserted_by": principal,
        }
        request_sha = _sha256(request)
        existing = self._cases.get(case_id)
        if existing is not None:
            current = _validate_case_record(existing, tenant_ref=tenant_ref)
            if current["request_sha256"] != request_sha:
                raise AIConformityWorkflowIdempotencyConflict(
                    "case operation_id was reused for different declarations"
                )
            return self._projection_from_record(current, tenant_ref=tenant_ref)

        record: dict[str, Any] = {
            "id": case_id,
            "schema": CASE_SCHEMA,
            "tenant_ref": tenant_ref,
            "request_sha256": request_sha,
            "asset_binding": binding,
            "declaration": {
                "economic_operator_role": role,
                "risk_tier": tier,
                "act_applicability": applicability,
                "legal_basis": citations,
                "asserted_by": principal,
                "asserted_at": now,
                "classification_source": "human_declaration_unverified",
            },
            "fria": {
                "determination": {
                    "outcome": "undetermined",
                    "rationale_sha256": None,
                    "citations": [],
                    "decided_by": None,
                    "decided_at": None,
                },
                "items": _blank_items("fria"),
            },
            "annex_iv": {"items": _blank_items("annex_iv")},
            "article_43": {
                "route": {
                    "route": "undetermined",
                    "rationale_sha256": None,
                    "citations": [],
                    "selected_by": None,
                    "selected_at": None,
                    "selection_source": "human_declaration_unverified",
                },
                "items": _blank_items("article_43"),
            },
            "post_market": {"items": _blank_items("post_market")},
            "declaration_draft": {
                "label": DRAFT_DECLARATION_LABEL,
                "signed": False,
                "final_declaration_generated": False,
                "items": _blank_items("declaration_draft"),
            },
            "ce_marking": {
                "label": CE_READINESS_LABEL,
                "mark_created": False,
                "mark_affixed": False,
                "items": _blank_items("ce_marking"),
            },
            "content_generation": 1,
            "content_sha256": "",
            "submissions": [],
            "approvals": [],
            "workflow_status": "draft",
            "created_by": principal,
            "last_operation_sha256": operation_sha,
            "last_operation_request_sha256": request_sha,
            "state_sha256": "",
        }
        record["content_sha256"] = _sha256(_case_content(record))
        record["state_sha256"] = _sha256(_case_state(record))
        try:
            saved = self._cases.create(
                record,
                action="create_eu_ai_conformity_readiness_case",
                actor=principal,
                max_records=_MAX_CASES,
            )
        except RecordConflict:
            raced = self._cases.get(case_id)
            if raced is None:
                raise
            saved = raced
        validated = _validate_case_record(saved, tenant_ref=tenant_ref)
        if validated["request_sha256"] != request_sha:
            raise AIConformityWorkflowIdempotencyConflict(
                "case operation_id was reused for different declarations"
            )
        return self._projection_from_record(validated, tenant_ref=tenant_ref)

    def bind_evidence(
        self,
        case_id: str,
        *,
        evidence: EvidenceReference,
        operation_id: str,
        actor: HumanActor,
    ) -> dict[str, Any]:
        """Append one immutable digest-only evidence binding to a case."""

        tenant_ref = self._require_active()
        principal = _human(actor)
        case = self._get_case_record(case_id, tenant_ref=tenant_ref)
        if not isinstance(evidence, EvidenceReference):
            raise TypeError("evidence must be an EvidenceReference")
        evidence_type = _choice(
            evidence.evidence_type,
            "evidence_type",
            _EVIDENCE_TYPES,
        )
        source_ref = _opaque(evidence.source_ref, "source_ref")
        evidence_sha = _digest(evidence.sha256, "evidence sha256")
        operation_sha = _operation(operation_id)
        binding_id = _stable_id("EUE", tenant_ref, case["id"], operation_sha)
        payload = {
            "schema": EVIDENCE_SCHEMA,
            "tenant_ref": tenant_ref,
            "case_id": case["id"],
            "asset_binding": dict(case["asset_binding"]),
            "evidence_type": evidence_type,
            "source_ref": source_ref,
            "evidence_sha256": evidence_sha,
        }
        binding_sha = _sha256(payload)
        existing = self._evidence.get(binding_id)
        if existing is not None:
            current = _validate_evidence_record(
                existing,
                tenant_ref=tenant_ref,
                case_id=case["id"],
            )
            if current["binding_sha256"] != binding_sha:
                raise AIConformityWorkflowIdempotencyConflict(
                    "evidence operation_id was reused for different evidence"
                )
            if current["recorded_by"] != principal:
                raise AIConformityWorkflowIdempotencyConflict(
                    "evidence operation_id was reused by a different human"
                )
            return _public_evidence(current)

        rows = self._evidence.list(limit=_MAX_EVIDENCE_RECORDS + 1)
        if len(rows) > _MAX_EVIDENCE_RECORDS:
            raise AIConformityWorkflowStateError("evidence namespace exceeds its bound")
        case_count = 0
        for row in rows:
            checked = _validate_evidence_record(row, tenant_ref=tenant_ref)
            if checked["case_id"] == case["id"]:
                case_count += 1
        if case_count >= _MAX_EVIDENCE_PER_CASE:
            raise AIConformityWorkflowStateError("case evidence binding limit reached")

        now = self._now()
        record = {
            "id": binding_id,
            **payload,
            "operation_sha256": operation_sha,
            "binding_sha256": binding_sha,
            "recorded_by": principal,
            "recorded_at": now,
            "state_sha256": "",
        }
        record["state_sha256"] = _sha256(_evidence_state(record))
        try:
            saved = self._evidence.create(
                record,
                action="bind_eu_ai_conformity_evidence",
                actor=principal,
                max_records=_MAX_EVIDENCE_RECORDS,
            )
        except RecordConflict:
            raced = self._evidence.get(binding_id)
            if raced is None:
                raise
            saved = raced
        validated = _validate_evidence_record(
            saved,
            tenant_ref=tenant_ref,
            case_id=case["id"],
        )
        if validated["binding_sha256"] != binding_sha:
            raise AIConformityWorkflowIdempotencyConflict(
                "evidence operation_id was reused for different evidence"
            )
        if validated["recorded_by"] != principal:
            raise AIConformityWorkflowIdempotencyConflict(
                "evidence operation_id was reused by a different human"
            )
        return _public_evidence(validated)

    def _content_update(
        self,
        record: Mapping[str, Any],
        *,
        tenant_ref: str,
        expected_revision: int,
        operation_sha: str,
        request_sha: str,
        principal: str,
        action: str,
        mutate_content: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        expected = _positive_revision(expected_revision)
        if record["last_operation_sha256"] == operation_sha:
            if record["last_operation_request_sha256"] != request_sha:
                raise AIConformityWorkflowIdempotencyConflict(
                    "operation_id was reused for a different case mutation"
                )
            return self._projection_from_record(record, tenant_ref=tenant_ref)
        if record["revision"] != expected:
            raise RecordConflict(
                f"conformity case changed (expected revision {expected}, "
                f"found {record['revision']})"
            )

        def mutate(row: dict[str, Any]) -> None:
            current = _validate_case_record(row, tenant_ref=tenant_ref)
            if current["content_sha256"] != record["content_sha256"]:
                raise RecordConflict("conformity case content changed during CAS")
            mutate_content(row)
            row["content_generation"] = int(row["content_generation"]) + 1
            row["content_sha256"] = _sha256(_case_content(row))
            row["workflow_status"] = "draft"
            row["last_operation_sha256"] = operation_sha
            row["last_operation_request_sha256"] = request_sha
            row["state_sha256"] = _sha256(_case_state(row))

        saved = self._cases.update(
            record["id"],
            mutate,
            expected_revision=expected,
            action=action,
            actor=principal,
        )
        if saved is None:
            raise AIConformityWorkflowStateError("conformity case disappeared during CAS")
        validated = _validate_case_record(saved, tenant_ref=tenant_ref)
        return self._projection_from_record(validated, tenant_ref=tenant_ref)

    def set_fria_determination(
        self,
        case_id: str,
        *,
        outcome: str,
        rationale_sha256: str | None,
        citations: Sequence[LegalCitation],
        expected_revision: int,
        operation_id: str,
        actor: HumanActor,
    ) -> dict[str, Any]:
        """CAS-record a human Article 27 applicability determination."""

        tenant_ref = self._require_active()
        principal = _human(actor)
        record = self._get_case_record(case_id, tenant_ref=tenant_ref)
        normalized_outcome = _choice(outcome, "FRIA outcome", _FRIA_OUTCOMES)
        if normalized_outcome == "undetermined":
            if rationale_sha256 is not None or citations:
                raise ValueError("undetermined FRIA outcome cannot carry decision material")
            rationale = None
            legal_basis: list[dict[str, str]] = []
            decided_by: str | None = None
            decided_at: float | None = None
        else:
            rationale = _digest(rationale_sha256, "FRIA rationale_sha256")
            legal_basis = _citations(citations, required=True)
            decided_by = principal
            decided_at = self._now()
        decision = {
            "outcome": normalized_outcome,
            "rationale_sha256": rationale,
            "citations": legal_basis,
            "decided_by": decided_by,
            "decided_at": decided_at,
        }
        request_sha = _sha256({
            "case_id": record["id"],
            "outcome": normalized_outcome,
            "rationale_sha256": rationale,
            "citations": legal_basis,
            "actor": principal,
        })
        operation_sha = _operation(operation_id)

        def mutate(row: dict[str, Any]) -> None:
            row["fria"]["determination"] = decision

        return self._content_update(
            record,
            tenant_ref=tenant_ref,
            expected_revision=expected_revision,
            operation_sha=operation_sha,
            request_sha=request_sha,
            principal=principal,
            action="set_eu_ai_fria_determination",
            mutate_content=mutate,
        )

    def set_article_43_route(
        self,
        case_id: str,
        *,
        route: str,
        rationale_sha256: str | None,
        citations: Sequence[LegalCitation],
        expected_revision: int,
        operation_id: str,
        actor: HumanActor,
    ) -> dict[str, Any]:
        """CAS-record a human-selected Article 43 assessment route."""

        tenant_ref = self._require_active()
        principal = _human(actor)
        record = self._get_case_record(case_id, tenant_ref=tenant_ref)
        normalized_route = _choice(route, "Article 43 route", _ARTICLE_43_ROUTES)
        if normalized_route == "undetermined":
            if rationale_sha256 is not None or citations:
                raise ValueError("undetermined Article 43 route cannot carry decision material")
            rationale = None
            legal_basis: list[dict[str, str]] = []
            selected_by: str | None = None
            selected_at: float | None = None
        else:
            rationale = _digest(rationale_sha256, "Article 43 rationale_sha256")
            legal_basis = _citations(citations, required=True)
            selected_by = principal
            selected_at = self._now()
        selection = {
            "route": normalized_route,
            "rationale_sha256": rationale,
            "citations": legal_basis,
            "selected_by": selected_by,
            "selected_at": selected_at,
            "selection_source": "human_declaration_unverified",
        }
        request_sha = _sha256({
            "case_id": record["id"],
            "route": normalized_route,
            "rationale_sha256": rationale,
            "citations": legal_basis,
            "actor": principal,
        })
        operation_sha = _operation(operation_id)

        def mutate(row: dict[str, Any]) -> None:
            row["article_43"]["route"] = selection

        return self._content_update(
            record,
            tenant_ref=tenant_ref,
            expected_revision=expected_revision,
            operation_sha=operation_sha,
            request_sha=request_sha,
            principal=principal,
            action="set_eu_ai_article_43_route",
            mutate_content=mutate,
        )

    def set_checklist_entry(
        self,
        case_id: str,
        *,
        domain: str,
        section: str,
        entry: ChecklistEntry,
        expected_revision: int,
        operation_id: str,
        actor: HumanActor,
    ) -> dict[str, Any]:
        """CAS-replace one checklist entry with exact immutable evidence pointers."""

        tenant_ref = self._require_active()
        principal = _human(actor)
        record = self._get_case_record(case_id, tenant_ref=tenant_ref)
        normalized_domain = _choice(domain, "checklist domain", _EVIDENCE_TYPES)
        normalized_section = _text(section, "checklist section", 128)
        if normalized_section not in CHECKLIST_SECTIONS[normalized_domain]:
            raise ValueError("checklist section is not valid for its domain")
        if not isinstance(entry, ChecklistEntry):
            raise TypeError("entry must be a ChecklistEntry")
        status = _choice(entry.status, "checklist status", _ITEM_STATUSES)
        binding_ids = entry.evidence_binding_ids
        if isinstance(binding_ids, (str, bytes)) or not isinstance(binding_ids, tuple):
            raise TypeError("evidence_binding_ids must be a tuple")
        if len(binding_ids) > _MAX_BINDINGS_PER_ITEM:
            raise ValueError(
                f"checklist entries cannot exceed {_MAX_BINDINGS_PER_ITEM} bindings"
            )
        normalized_ids = [
            _opaque(binding_id, "binding_id", 36) for binding_id in binding_ids
        ]
        if len(set(normalized_ids)) != len(normalized_ids):
            raise ValueError("evidence_binding_ids must be unique")
        pointers: list[dict[str, str]] = []
        for binding_id in sorted(normalized_ids):
            evidence_record = self._get_evidence_record(
                binding_id,
                tenant_ref=tenant_ref,
                case_id=record["id"],
            )
            if evidence_record["evidence_type"] != normalized_domain:
                raise ValueError("evidence binding type does not match checklist domain")
            if evidence_record["asset_binding"] != record["asset_binding"]:
                raise AIConformityWorkflowStateError(
                    "evidence binding targets a different Model Risk asset version"
                )
            pointers.append({
                "binding_id": binding_id,
                "evidence_sha256": evidence_record["evidence_sha256"],
                "binding_sha256": evidence_record["binding_sha256"],
            })
        rationale = (
            None
            if entry.rationale_sha256 is None
            else _digest(entry.rationale_sha256, "rationale_sha256")
        )
        legal_basis = _citations(entry.citations, required=False)
        normalized_entry = _validate_item({
            "status": status,
            "evidence_bindings": pointers,
            "rationale_sha256": rationale,
            "citations": legal_basis,
        })
        request_sha = _sha256({
            "case_id": record["id"],
            "domain": normalized_domain,
            "section": normalized_section,
            "entry": normalized_entry,
            "actor": principal,
        })
        operation_sha = _operation(operation_id)

        def mutate(row: dict[str, Any]) -> None:
            row[normalized_domain]["items"][normalized_section] = normalized_entry

        return self._content_update(
            record,
            tenant_ref=tenant_ref,
            expected_revision=expected_revision,
            operation_sha=operation_sha,
            request_sha=request_sha,
            principal=principal,
            action="set_eu_ai_conformity_checklist_entry",
            mutate_content=mutate,
        )

    def set_fria_section(self, case_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.set_checklist_entry(case_id, domain="fria", **kwargs)

    def set_annex_iv_section(self, case_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.set_checklist_entry(case_id, domain="annex_iv", **kwargs)

    def set_article_43_check(self, case_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.set_checklist_entry(case_id, domain="article_43", **kwargs)

    def set_post_market_section(self, case_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.set_checklist_entry(case_id, domain="post_market", **kwargs)

    def set_declaration_draft_section(
        self, case_id: str, **kwargs: Any
    ) -> dict[str, Any]:
        return self.set_checklist_entry(case_id, domain="declaration_draft", **kwargs)

    def set_ce_marking_section(self, case_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.set_checklist_entry(case_id, domain="ce_marking", **kwargs)

    def submit_case(
        self,
        case_id: str,
        *,
        expected_revision: int,
        operation_id: str,
        actor: HumanActor,
    ) -> dict[str, Any]:
        """Human-submit an exact complete internal manifest under revision CAS."""

        tenant_ref = self._require_active()
        principal = _human(actor)
        record = self._get_case_record(case_id, tenant_ref=tenant_ref)
        operation_sha = _operation(operation_id)
        request_sha = _sha256({
            "case_id": record["id"],
            "content_generation": record["content_generation"],
            "content_sha256": record["content_sha256"],
            "actor": principal,
        })
        for prior in record["submissions"]:
            if prior["operation_sha256"] != operation_sha:
                continue
            if (
                prior["case_content_generation"] != record["content_generation"]
                or prior["case_content_sha256"] != record["content_sha256"]
                or prior["submitted_by"] != principal
            ):
                raise AIConformityWorkflowIdempotencyConflict(
                    "submission operation_id was reused for different content"
                )
            return self._projection_from_record(record, tenant_ref=tenant_ref)
        expected = _positive_revision(expected_revision)
        if record["revision"] != expected:
            raise RecordConflict(
                f"conformity case changed (expected revision {expected}, "
                f"found {record['revision']})"
            )
        if len(record["submissions"]) >= _MAX_SUBMISSIONS:
            raise AIConformityWorkflowStateError("case submission history limit reached")
        current_asset = self._current_asset(record["asset_binding"]["asset_id"])
        manifest, _ = self._manifest(
            record,
            tenant_ref=tenant_ref,
            current_asset=current_asset,
        )
        if not manifest["complete"]:
            raise AIConformityWorkflowIncomplete(
                "strict readiness manifest is incomplete: " + ", ".join(manifest["gaps"])
            )
        submission: dict[str, Any] = {
            "id": _stable_id("EUS", tenant_ref, record["id"], operation_sha),
            "schema": SUBMISSION_SCHEMA,
            "operation_sha256": operation_sha,
            "case_id": record["id"],
            "case_content_generation": record["content_generation"],
            "case_content_sha256": record["content_sha256"],
            "asset_binding": dict(record["asset_binding"]),
            "manifest": manifest,
            "manifest_sha256": manifest["manifest_sha256"],
            "submitted_by": principal,
            "submitted_at": self._now(),
            "scope": "internal_readiness_package_only",
            "legal_effect": False,
            "submission_sha256": "",
        }
        submission["submission_sha256"] = _sha256(_submission_payload(submission))
        _validate_submission(submission, tenant_ref=tenant_ref, case_id=record["id"])

        def mutate(row: dict[str, Any]) -> None:
            current = _validate_case_record(row, tenant_ref=tenant_ref)
            if (
                current["content_generation"] != record["content_generation"]
                or current["content_sha256"] != record["content_sha256"]
            ):
                raise RecordConflict("conformity case content changed during submission")
            row["submissions"].append(submission)
            row["workflow_status"] = "submitted"
            row["last_operation_sha256"] = operation_sha
            row["last_operation_request_sha256"] = request_sha
            row["state_sha256"] = _sha256(_case_state(row))

        saved = self._cases.update(
            record["id"],
            mutate,
            expected_revision=expected,
            action="submit_eu_ai_conformity_readiness",
            actor=principal,
        )
        if saved is None:
            raise AIConformityWorkflowStateError("conformity case disappeared during submit")
        validated = _validate_case_record(saved, tenant_ref=tenant_ref)
        return self._projection_from_record(validated, tenant_ref=tenant_ref)

    def approve_case(
        self,
        case_id: str,
        *,
        expected_revision: int,
        operation_id: str,
        actor: HumanActor,
    ) -> dict[str, Any]:
        """Distinct human-approve only the exact current internal submission."""

        tenant_ref = self._require_active()
        principal = _human(actor)
        record = self._get_case_record(case_id, tenant_ref=tenant_ref)
        operation_sha = _operation(operation_id)
        for prior in record["approvals"]:
            if prior["operation_sha256"] != operation_sha:
                continue
            if prior["approved_by"] != principal:
                raise AIConformityWorkflowIdempotencyConflict(
                    "approval operation_id was reused by a different human"
                )
            return self._projection_from_record(record, tenant_ref=tenant_ref)
        expected = _positive_revision(expected_revision)
        if record["revision"] != expected:
            raise RecordConflict(
                f"conformity case changed (expected revision {expected}, "
                f"found {record['revision']})"
            )
        if len(record["approvals"]) >= _MAX_APPROVALS:
            raise AIConformityWorkflowStateError("case approval history limit reached")
        current_asset = self._current_asset(record["asset_binding"]["asset_id"])
        manifest, _ = self._manifest(
            record,
            tenant_ref=tenant_ref,
            current_asset=current_asset,
        )
        submission = self._current_submission(record, manifest)
        if submission is None or not manifest["complete"]:
            raise AIConformityWorkflowIncomplete(
                "approval requires an exact current complete human submission"
            )
        if submission["submitted_by"] == principal:
            raise ValueError("approval requires a distinct human from the submitter")
        request_sha = _sha256({
            "case_id": record["id"],
            "submission_id": submission["id"],
            "submission_sha256": submission["submission_sha256"],
            "actor": principal,
        })
        approval: dict[str, Any] = {
            "id": _stable_id("EUA", tenant_ref, record["id"], operation_sha),
            "schema": APPROVAL_SCHEMA,
            "operation_sha256": operation_sha,
            "submission_id": submission["id"],
            "submission_sha256": submission["submission_sha256"],
            "approved_by": principal,
            "approved_at": self._now(),
            "four_eyes_verified": True,
            "scope": "internal_readiness_package_only",
            "legal_effect": False,
            "approval_sha256": "",
        }
        approval["approval_sha256"] = _sha256(_approval_payload(approval))
        _validate_approval(approval)

        def mutate(row: dict[str, Any]) -> None:
            current = _validate_case_record(row, tenant_ref=tenant_ref)
            if (
                current["content_generation"] != record["content_generation"]
                or current["content_sha256"] != record["content_sha256"]
                or not current["submissions"]
                or current["submissions"][-1]["submission_sha256"]
                != submission["submission_sha256"]
            ):
                raise RecordConflict("conformity submission changed during approval")
            row["approvals"].append(approval)
            row["workflow_status"] = "approved"
            row["last_operation_sha256"] = operation_sha
            row["last_operation_request_sha256"] = request_sha
            row["state_sha256"] = _sha256(_case_state(row))

        saved = self._cases.update(
            record["id"],
            mutate,
            expected_revision=expected,
            action="approve_eu_ai_conformity_readiness",
            actor=principal,
        )
        if saved is None:
            raise AIConformityWorkflowStateError("conformity case disappeared during approve")
        validated = _validate_case_record(saved, tenant_ref=tenant_ref)
        return self._projection_from_record(validated, tenant_ref=tenant_ref)

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        """Return an integrity-checked, dynamically revalidated safe projection."""

        tenant_ref = self._require_active()
        identity = _opaque(case_id, "case_id", 36)
        raw = self._cases.get(identity)
        if raw is None:
            return None
        record = _validate_case_record(raw, tenant_ref=tenant_ref)
        return self._projection_from_record(record, tenant_ref=tenant_ref)

    def project_case(self, case_id: str) -> dict[str, Any] | None:
        """Explicit alias emphasizing that no raw governed record is returned."""

        return self.get_case(case_id)

    def list_cases(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Return a bounded set of integrity-checked tenant projections."""

        tenant_ref = self._require_active()
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= _MAX_LIST_LIMIT:
            raise ValueError(f"limit must be between 1 and {_MAX_LIST_LIMIT}")
        rows = self._cases.list(limit=limit)
        records = [_validate_case_record(row, tenant_ref=tenant_ref) for row in rows]
        return [
            self._projection_from_record(record, tenant_ref=tenant_ref)
            for record in sorted(records, key=lambda item: item["id"])
        ]

    def list_case_projections(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Explicit safe-projection alias for dashboard and API consumers."""

        return self.list_cases(limit=limit)

    def get_evidence_binding(self, binding_id: str) -> dict[str, Any] | None:
        """Return a digest-only immutable binding projection."""

        tenant_ref = self._require_active()
        identity = _opaque(binding_id, "binding_id", 36)
        raw = self._evidence.get(identity)
        if raw is None:
            return None
        record = _validate_evidence_record(raw, tenant_ref=tenant_ref)
        return _public_evidence(record)

    def list_case_evidence(self, case_id: str) -> list[dict[str, Any]]:
        """Return one case's fingerprint-only evidence bindings, read-only."""

        tenant_ref = self._require_active()
        case = self._get_case_record(case_id, tenant_ref=tenant_ref)
        rows = self._evidence.list(limit=_MAX_EVIDENCE_RECORDS + 1)
        if len(rows) > _MAX_EVIDENCE_RECORDS:
            raise AIConformityWorkflowStateError("evidence namespace exceeds its bound")
        result = []
        for row in rows:
            checked = _validate_evidence_record(row, tenant_ref=tenant_ref)
            if checked["case_id"] == case["id"]:
                result.append(_public_evidence(checked))
        return sorted(result, key=lambda item: item["binding_id"])

    def export_package(self, case_id: str) -> dict[str, Any]:
        """Export only an exact current four-eyes-approved readiness package."""

        tenant_ref = self._require_active()
        record = self._get_case_record(case_id, tenant_ref=tenant_ref)
        current_asset = self._current_asset(record["asset_binding"]["asset_id"])
        manifest, references = self._manifest(
            record,
            tenant_ref=tenant_ref,
            current_asset=current_asset,
        )
        submission = self._current_submission(record, manifest)
        approval = self._current_approval(record, submission)
        if not manifest["complete"] or submission is None or approval is None:
            raise AIConformityWorkflowIncomplete(
                "package export requires a current complete four-eyes-approved submission"
            )
        projection = self._projection_from_record(record, tenant_ref=tenant_ref)
        payload: dict[str, Any] = {
            "schema": PACKAGE_SCHEMA,
            "label": PACKAGE_LABEL,
            "case_id": record["id"],
            "asset_binding": dict(record["asset_binding"]),
            "strict_manifest": manifest,
            "case_projection": projection,
            "evidence_bindings": [
                _public_evidence(item)
                for item in sorted(references.values(), key=lambda row: row["id"])
            ],
            "submission_receipt": {
                "submission_id": submission["id"],
                "submission_sha256": submission["submission_sha256"],
                "manifest_sha256": submission["manifest_sha256"],
                "submitted_by": submission["submitted_by"],
                "submitted_at": submission["submitted_at"],
                "scope": submission["scope"],
                "legal_effect": False,
            },
            "approval_receipt": {
                "approval_id": approval["id"],
                "approval_sha256": approval["approval_sha256"],
                "submission_id": approval["submission_id"],
                "approved_by": approval["approved_by"],
                "approved_at": approval["approved_at"],
                "four_eyes_verified": True,
                "scope": approval["scope"],
                "legal_effect": False,
            },
            "declaration_artifact": {
                "label": DRAFT_DECLARATION_LABEL,
                "signed": False,
                "final_declaration_generated": False,
            },
            "ce_marking_artifact": {
                "label": CE_READINESS_LABEL,
                "mark_created": False,
                "mark_affixed": False,
            },
            "legal_effects": _no_legal_effects(),
            "notice": NON_CERTIFICATION_NOTICE,
        }
        payload["package_sha256"] = _sha256(payload)
        return payload


def enabled() -> bool:
    """Fail closed unless G18 and its Model Risk authority are enabled."""

    try:
        from . import model_risk_assurance
        from .config import config_source_errors, load_global_config

        config = load_global_config()
        if config_source_errors(include_tenant=False) or not isinstance(config, dict):
            return False
        section = config.get("ai_conformity_workflow")
        return bool(
            isinstance(section, dict)
            and section.get("enable") is True
            and model_risk_assurance.enabled()
        )
    except Exception:
        return False


def require_enabled() -> None:
    if not enabled():
        raise AIConformityWorkflowConfigError(
            "EU AI conformity readiness is disabled or its Model Risk authority "
            "is unavailable; set [ai_conformity_workflow].enable = true"
        )


def configured_ai_conformity_workflow() -> EUAIConformityWorkflow:
    """Return a configured service only after fail-closed dependency checks."""

    require_enabled()
    return EUAIConformityWorkflow()


def configured_service() -> EUAIConformityWorkflow:
    """Concise alias for configured_ai_conformity_workflow."""

    return configured_ai_conformity_workflow()


AIConformityWorkflowService = EUAIConformityWorkflow


_DEFAULT = EUAIConformityWorkflow()


def create_case(**kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.create_case(**kwargs)


def bind_evidence(case_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.bind_evidence(case_id, **kwargs)


def set_fria_determination(case_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.set_fria_determination(case_id, **kwargs)


def set_article_43_route(case_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.set_article_43_route(case_id, **kwargs)


def set_checklist_entry(case_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.set_checklist_entry(case_id, **kwargs)


def set_fria_section(case_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.set_fria_section(case_id, **kwargs)


def set_annex_iv_section(case_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.set_annex_iv_section(case_id, **kwargs)


def set_article_43_check(case_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.set_article_43_check(case_id, **kwargs)


def set_post_market_section(case_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.set_post_market_section(case_id, **kwargs)


def set_declaration_draft_section(case_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.set_declaration_draft_section(case_id, **kwargs)


def set_ce_marking_section(case_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.set_ce_marking_section(case_id, **kwargs)


def submit_case(case_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.submit_case(case_id, **kwargs)


def approve_case(case_id: str, **kwargs: Any) -> dict[str, Any]:
    return _DEFAULT.approve_case(case_id, **kwargs)


def get_case(case_id: str) -> dict[str, Any] | None:
    return _DEFAULT.get_case(case_id)


def project_case(case_id: str) -> dict[str, Any] | None:
    return _DEFAULT.project_case(case_id)


def list_cases(*, limit: int = 100) -> list[dict[str, Any]]:
    return _DEFAULT.list_cases(limit=limit)


def list_case_projections(*, limit: int = 100) -> list[dict[str, Any]]:
    return _DEFAULT.list_case_projections(limit=limit)


def get_evidence_binding(binding_id: str) -> dict[str, Any] | None:
    return _DEFAULT.get_evidence_binding(binding_id)


def export_package(case_id: str) -> dict[str, Any]:
    return _DEFAULT.export_package(case_id)


__all__ = [
    "AIConformityWorkflowAssetError",
    "AIConformityWorkflowConfigError",
    "AIConformityWorkflowError",
    "AIConformityWorkflowIdempotencyConflict",
    "AIConformityWorkflowIncomplete",
    "AIConformityWorkflowStateError",
    "AIConformityWorkflowService",
    "ANNEX_IV_SECTIONS",
    "APPROVAL_SCHEMA",
    "ARTICLE_43_ROUTE_REQUIREMENTS",
    "ARTICLE_43_SECTIONS",
    "CASE_SCHEMA",
    "CE_MARKING_SECTIONS",
    "CE_READINESS_LABEL",
    "CHECKLIST_SECTIONS",
    "CONSOLIDATED_REGULATION_ELI",
    "CONSOLIDATED_REGULATION_URL",
    "ChecklistEntry",
    "DECLARATION_DRAFT_SECTIONS",
    "DRAFT_DECLARATION_LABEL",
    "EUAIConformityWorkflow",
    "EVIDENCE_SCHEMA",
    "EvidenceReference",
    "FRIA_SECTIONS",
    "HumanActor",
    "LEGAL_TEXT_VERSION",
    "LegalCitation",
    "MANIFEST_SCHEMA",
    "NON_CERTIFICATION_NOTICE",
    "PACKAGE_LABEL",
    "PACKAGE_SCHEMA",
    "POST_MARKET_SECTIONS",
    "PROJECTION_SCHEMA",
    "SUBMISSION_SCHEMA",
    "approve_case",
    "bind_evidence",
    "configured_ai_conformity_workflow",
    "configured_service",
    "create_case",
    "enabled",
    "export_package",
    "get_case",
    "get_evidence_binding",
    "list_cases",
    "list_case_projections",
    "project_case",
    "require_enabled",
    "set_annex_iv_section",
    "set_article_43_check",
    "set_article_43_route",
    "set_ce_marking_section",
    "set_checklist_entry",
    "set_declaration_draft_section",
    "set_fria_determination",
    "set_fria_section",
    "set_post_market_section",
    "submit_case",
]
