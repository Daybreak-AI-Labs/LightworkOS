"""Governed, non-legal decision-support packages for regulated AI uses.

This default-off module prepares four tightly bounded evidence packages:

* credit adverse-action reason-code support;
* aggregate fair-lending/disparate-impact measurement;
* New York City Local Law 144 AEDT audit/notice readiness; and
* NAIC insurance-AI governance evidence mapping.

Every version is bound to the exact current Model Risk asset revision and
version digest, an immutable package-template authority, and the exact digests
of approved current evidence.  A second authenticated human must approve the
latest complete version using compare-and-swap.  Any authority change makes an
approval stale and prevents export.

The closed schemas admit only opaque codes, counts, timestamps, and SHA-256
digests.  There is no field for applicant, employee, candidate, policyholder,
prompt, feature, outcome, or other individual-level data.  The module does not
make credit, employment, or insurance decisions; determine legal compliance;
perform an independent audit; create a regulator filing; or certify anything.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from statistics import NormalDist
from typing import Any

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

PACKAGE_SCHEMA = "lightwork.ai-regulated-vertical-package.v1"
EXPORT_SCHEMA = "lightwork.ai-regulated-vertical-package-export.v1"
AGGREGATE_REPORT_SCHEMA = "lightwork.fair-lending-aggregate-report.v1"
DECISION_SUPPORT_NOTICE = (
    "Human-reviewed evidence support only. This package does not make a credit, "
    "employment, or insurance decision; determine compliance; perform or claim "
    "an independent audit; create a regulator filing; or certify a system."
)

CREDIT_ADVERSE_ACTION = "credit_adverse_action"
FAIR_LENDING_AGGREGATE = "fair_lending_aggregate"
NYC_LL144 = "nyc_ll144"
NAIC_INSURANCE = "naic_insurance"
PACKAGE_TYPES = frozenset(
    {CREDIT_ADVERSE_ACTION, FAIR_LENDING_AGGREGATE, NYC_LL144, NAIC_INSURANCE}
)

NYC_LL144_CHECKS = (
    "independent_bias_audit",
    "selection_or_scoring_rates",
    "impact_ratios_by_category",
    "public_summary",
    "candidate_notice",
    "data_retention",
)
NAIC_CHECKS = (
    "governance_accountability",
    "ai_system_inventory_and_risk_classification",
    "lifecycle_controls",
    "data_controls",
    "validation_testing",
    "third_party_controls",
    "consumer_outcome_monitoring",
    "documentation_and_recordkeeping",
)

_TEMPLATE_SPECIFICATIONS: dict[str, dict[str, Any]] = {
    CREDIT_ADVERSE_ACTION: {
        "template_id": "lightwork.credit-adverse-action-reason-support",
        "version": 1,
        "required": (
            "model_receipt_sha256",
            "input_receipt_sha256",
            "explanation_receipt_sha256",
            "reason_codes",
        ),
    },
    FAIR_LENDING_AGGREGATE: {
        "template_id": "lightwork.fair-lending-aggregate-measurement",
        "version": 1,
        "required": (
            "analysis_scope_code",
            "window_start",
            "window_end",
            "reference_cohort",
            "comparison_cohorts",
            "methodology_sha256",
        ),
    },
    NYC_LL144: {
        "template_id": "lightwork.nyc-local-law-144-readiness",
        "version": 1,
        "required_checks": NYC_LL144_CHECKS,
    },
    NAIC_INSURANCE: {
        "template_id": "lightwork.naic-insurance-ai-governance-mapping",
        "version": 1,
        "required_checks": NAIC_CHECKS,
    },
}

_PACKAGES = GovernedRecordStore(
    "ai_regulated_vertical_packages", "RVP", "ai_regulated_vertical_package"
)

_ASSET_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_HUMAN_RE = re.compile(r"user:[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")

_MAX_PACKAGES = 5_000
_MAX_LIST = 250
_MAX_VERSIONS = 50
_MAX_EVIDENCE = 128
_MAX_REASON_CODES = 16
_MAX_COHORTS = 64
_MAX_JURISDICTIONS = 32
_MAX_SAMPLE_COUNT = 1_000_000_000
_MAX_JSON_BYTES = 256 * 1024
_MAX_FUTURE_SKEW_SECONDS = 300

_STORE_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})
_RECORD_FIELDS = frozenset(
    {
        "id",
        "schema",
        "tenant_ref",
        "package_id",
        "package_type",
        "asset_id",
        "versions",
        "status",
        "create_operation_sha256",
        "state_sha256",
    }
)
_VERSION_FIELDS = frozenset(
    {
        "version",
        "prepared_at",
        "prepared_by_ref",
        "operation_sha256",
        "asset_binding",
        "template_binding",
        "evidence_bindings",
        "content",
        "content_sha256",
        "authority_sha256",
        "approval",
    }
)


class AIRegulatedVerticalsError(RuntimeError):
    """Base error for regulated-vertical decision-support packages."""


class AIRegulatedVerticalsConfigError(AIRegulatedVerticalsError):
    """The default-off feature is unavailable."""


class AIRegulatedVerticalsStateError(AIRegulatedVerticalsError):
    """Persisted package authority is malformed or inconsistent."""


class AIRegulatedVerticalsAssetError(AIRegulatedVerticalsError):
    """An exact current Model Risk asset binding cannot be established."""


class AIRegulatedVerticalsEvidenceError(AIRegulatedVerticalsError):
    """Cited evidence is absent, unapproved, stale, or digest-mismatched."""


class AIRegulatedVerticalsTemplateError(AIRegulatedVerticalsError):
    """A package template authority is absent or changed."""


class AIRegulatedVerticalsApprovalError(AIRegulatedVerticalsError):
    """A package is incomplete or lacks valid four-eyes approval."""


class AIRegulatedVerticalsStaleError(AIRegulatedVerticalsError):
    """An approved package no longer matches current authority."""


class AIRegulatedVerticalsIdempotencyConflict(AIRegulatedVerticalsError):
    """An operation identity was reused with different content."""


def enabled() -> bool:
    """Return true only for explicit ``[ai_regulated_verticals] enable = true``."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("ai_regulated_verticals")
    return isinstance(section, Mapping) and section.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise AIRegulatedVerticalsConfigError(
            "regulated-vertical packages are disabled; set "
            "[ai_regulated_verticals] enable = true"
        )


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("regulated-vertical data must be finite JSON") from exc
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValueError("regulated-vertical data exceeds the 256 KiB bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _closed(value: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    if set(value) != fields:
        raise ValueError(f"{label} must use the closed schema")
    return value


def _text(value: object, label: str, limit: int = 128) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if not text or len(text) > limit or any(ord(character) < 32 for character in text):
        raise ValueError(f"{label} is invalid")
    return text


def _token(value: object, label: str) -> str:
    text = _text(value, label)
    if not _TOKEN_RE.fullmatch(text):
        raise ValueError(f"{label} must be an opaque code")
    return text


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


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a timestamp")
    number = float(value)
    if not math.isfinite(number) or number <= 0 or number >= 100_000_000_000:
        raise ValueError(f"{label} must be a positive finite timestamp")
    return number


def _number(value: object, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number")
    number = float(value)
    if not math.isfinite(number) or number < minimum or number > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return number


def _package_type(value: object) -> str:
    kind = _token(value, "package_type")
    if kind not in PACKAGE_TYPES:
        raise ValueError("package_type is unsupported")
    return kind


def _actor(actor: object) -> tuple[str, str]:
    principal = _text(actor, "actor", 133)
    if not _HUMAN_RE.fullmatch(principal):
        raise ValueError("actor must be an opaque user: human principal")
    return principal, hashlib.sha256(principal.encode("utf-8")).hexdigest()


def _tenant_ref() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise AIRegulatedVerticalsStateError(
            "regulated-vertical operations require an explicit tenant"
        )
    return "TEN-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:24]


def _evidence_ids(
    value: object, label: str, *, allow_empty: bool = False
) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{label} must be an array")
    if len(value) > _MAX_EVIDENCE:
        raise ValueError(f"{label} exceeds {_MAX_EVIDENCE} entries")
    result = sorted({_token(item, label) for item in value})
    if len(result) != len(value):
        raise ValueError(f"{label} entries must be unique")
    if not allow_empty and not result:
        raise ValueError(f"{label} must cite evidence")
    return result


def _evidence_bindings(value: object) -> list[dict[str, str]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError("evidence_bindings must be an array")
    if not 1 <= len(value) <= _MAX_EVIDENCE:
        raise ValueError(f"evidence_bindings must contain 1 through {_MAX_EVIDENCE} entries")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value:
        row = _closed(
            item, frozenset({"evidence_id", "digest"}), "evidence binding"
        )
        evidence_id = _token(row["evidence_id"], "evidence_id")
        if evidence_id in seen:
            raise ValueError("evidence_id entries must be unique")
        seen.add(evidence_id)
        result.append(
            {"evidence_id": evidence_id, "digest": _digest(row["digest"], "evidence digest")}
        )
    return sorted(result, key=lambda item: item["evidence_id"])


def _check_item(value: object, label: str, *, naic: bool = False) -> dict[str, Any]:
    row = _closed(
        value,
        frozenset({"state", "evidence_ids", "rationale_sha256"}),
        label,
    )
    allowed = (
        {"implemented", "partial", "missing", "not_applicable"}
        if naic
        else {"complete", "missing", "not_applicable"}
    )
    state = _token(row["state"], f"{label} state")
    if state not in allowed:
        raise ValueError(f"{label} state is unsupported")
    evidence = _evidence_ids(
        row["evidence_ids"], f"{label} evidence_ids", allow_empty=True
    )
    rationale = row["rationale_sha256"]
    rationale_sha = None if rationale is None else _digest(rationale, f"{label} rationale")
    complete_state = "implemented" if naic else "complete"
    if state == complete_state and not evidence:
        raise ValueError(f"{label} {complete_state} state must cite evidence")
    if state == "not_applicable" and (not rationale_sha or evidence):
        raise ValueError(
            f"{label} not_applicable state requires only a rationale digest"
        )
    if state in {"missing", "partial"} and (evidence or rationale_sha):
        raise ValueError(f"{label} {state} state cannot imply completed evidence")
    return {
        "state": state,
        "evidence_ids": evidence,
        "rationale_sha256": rationale_sha,
    }


def _normalize_credit(value: object) -> dict[str, Any]:
    row = _closed(
        value,
        frozenset(
            {
                "model_receipt_sha256",
                "input_receipt_sha256",
                "explanation_receipt_sha256",
                "reason_codes",
            }
        ),
        "credit adverse-action content",
    )
    reasons_raw = row["reason_codes"]
    if isinstance(reasons_raw, (str, bytes)) or not isinstance(reasons_raw, Sequence):
        raise ValueError("reason_codes must be an array")
    if not 1 <= len(reasons_raw) <= _MAX_REASON_CODES:
        raise ValueError("reason_codes must contain 1 through 16 entries")
    reasons: list[dict[str, Any]] = []
    codes: set[str] = set()
    ranks: set[int] = set()
    for item in reasons_raw:
        reason = _closed(
            item,
            frozenset({"code", "rank", "source_factor_code", "evidence_ids"}),
            "reason code",
        )
        code = _token(reason["code"], "reason code")
        rank = _integer(reason["rank"], "reason rank", 1, _MAX_REASON_CODES)
        if code in codes or rank in ranks:
            raise ValueError("reason code values and ranks must be unique")
        codes.add(code)
        ranks.add(rank)
        reasons.append(
            {
                "code": code,
                "rank": rank,
                "source_factor_code": _token(
                    reason["source_factor_code"], "source_factor_code"
                ),
                "evidence_ids": _evidence_ids(
                    reason["evidence_ids"], "reason evidence_ids"
                ),
            }
        )
    reasons.sort(key=lambda item: item["rank"])
    if [item["rank"] for item in reasons] != list(range(1, len(reasons) + 1)):
        raise ValueError("reason ranks must be contiguous starting at 1")
    return {
        "model_receipt_sha256": _digest(
            row["model_receipt_sha256"], "model receipt digest"
        ),
        "input_receipt_sha256": _digest(
            row["input_receipt_sha256"], "input receipt digest"
        ),
        "explanation_receipt_sha256": _digest(
            row["explanation_receipt_sha256"], "explanation receipt digest"
        ),
        "reason_codes": reasons,
    }


def _wilson(successes: int, samples: int) -> tuple[float, float] | None:
    if samples == 0:
        return None
    z = NormalDist().inv_cdf(0.975)
    rate = successes / samples
    denominator = 1.0 + z * z / samples
    center = (rate + z * z / (2.0 * samples)) / denominator
    radius = z * math.sqrt(
        (rate * (1.0 - rate) + z * z / (4.0 * samples)) / samples
    ) / denominator
    return max(0.0, center - radius), min(1.0, center + radius)


def _cohort(value: object, label: str) -> dict[str, Any]:
    raw_fields = frozenset(
        {
            "cohort_code",
            "definition_sha256",
            "sample_count",
            "favorable_count",
            "missing_count",
            "evidence_ids",
        }
    )
    canonical_fields = raw_fields | {"selection_rate", "confidence"}
    comparison_fields = canonical_fields | {"impact_ratio", "impact_ratio_state"}
    if not isinstance(value, Mapping) or set(value) not in {
        raw_fields,
        canonical_fields,
        comparison_fields,
    }:
        raise ValueError(f"{label} must use the closed schema")
    row = {key: value[key] for key in raw_fields}
    samples = _integer(row["sample_count"], f"{label} sample_count", 0, _MAX_SAMPLE_COUNT)
    favorable = _integer(row["favorable_count"], f"{label} favorable_count", 0, samples)
    missing = _integer(row["missing_count"], f"{label} missing_count", 0, _MAX_SAMPLE_COUNT)
    interval = _wilson(favorable, samples)
    rate = None if samples == 0 else favorable / samples
    return {
        "cohort_code": _token(row["cohort_code"], f"{label} cohort_code"),
        "definition_sha256": _digest(
            row["definition_sha256"], f"{label} definition digest"
        ),
        "sample_count": samples,
        "favorable_count": favorable,
        "missing_count": missing,
        "selection_rate": rate,
        "confidence": {
            "method": "wilson_score_95",
            "level": 0.95,
            "lower": None if interval is None else interval[0],
            "upper": None if interval is None else interval[1],
            "state": "unavailable_zero_denominator" if interval is None else "measured",
        },
        "evidence_ids": _evidence_ids(row["evidence_ids"], f"{label} evidence_ids"),
    }


def _normalize_fair_lending(value: object) -> dict[str, Any]:
    raw_fields = frozenset(
        {
            "analysis_scope_code",
            "window_start",
            "window_end",
            "reference_cohort",
            "comparison_cohorts",
            "methodology_sha256",
            "limitations_codes",
        }
    )
    canonical_fields = raw_fields | {"schema", "interpretation_state"}
    if not isinstance(value, Mapping) or set(value) not in {
        raw_fields,
        canonical_fields,
    }:
        raise ValueError("fair-lending aggregate content must use the closed schema")
    row = {key: value[key] for key in raw_fields}
    start = _timestamp(row["window_start"], "window_start")
    end = _timestamp(row["window_end"], "window_end")
    if end < start:
        raise ValueError("analysis window is reversed")
    reference = _cohort(row["reference_cohort"], "reference cohort")
    comparisons_raw = row["comparison_cohorts"]
    if isinstance(comparisons_raw, (str, bytes)) or not isinstance(
        comparisons_raw, Sequence
    ):
        raise ValueError("comparison_cohorts must be an array")
    if not 1 <= len(comparisons_raw) <= _MAX_COHORTS:
        raise ValueError("comparison_cohorts must contain 1 through 64 entries")
    comparisons: list[dict[str, Any]] = []
    seen = {reference["cohort_code"]}
    for value_item in comparisons_raw:
        cohort = _cohort(value_item, "comparison cohort")
        if cohort["cohort_code"] in seen:
            raise ValueError("cohort_code values must be unique")
        seen.add(cohort["cohort_code"])
        ref_rate = reference["selection_rate"]
        rate = cohort["selection_rate"]
        if ref_rate is None or ref_rate == 0.0 or rate is None:
            ratio = None
            ratio_state = "unavailable_zero_denominator"
        else:
            ratio = rate / ref_rate
            ratio_state = "measured"
        comparisons.append(
            {
                **cohort,
                "impact_ratio": ratio,
                "impact_ratio_state": ratio_state,
            }
        )
    comparisons.sort(key=lambda item: item["cohort_code"])
    limitations = _evidence_ids(
        row["limitations_codes"], "limitations_codes", allow_empty=True
    )
    return {
        "schema": AGGREGATE_REPORT_SCHEMA,
        "analysis_scope_code": _token(row["analysis_scope_code"], "analysis_scope_code"),
        "window_start": start,
        "window_end": end,
        "reference_cohort": reference,
        "comparison_cohorts": comparisons,
        "methodology_sha256": _digest(
            row["methodology_sha256"], "methodology digest"
        ),
        "limitations_codes": limitations,
        "interpretation_state": "human_review_required_no_automated_conclusion",
    }


def _normalize_auditor(value: object) -> dict[str, Any]:
    row = _closed(
        value,
        frozenset(
            {
                "state",
                "assertion_sha256",
                "asserted_at",
                "coverage_start",
                "coverage_end",
                "evidence_ids",
            }
        ),
        "independent auditor assertion",
    )
    state = _token(row["state"], "independent auditor state")
    if state not in {"asserted", "missing"}:
        raise ValueError("independent auditor state is unsupported")
    if state == "missing":
        if any(
            row[key] is not None
            for key in ("assertion_sha256", "asserted_at", "coverage_start", "coverage_end")
        ) or row["evidence_ids"] != []:
            raise ValueError("missing auditor assertion cannot imply assertion data")
        return {
            "state": "missing",
            "assertion_sha256": None,
            "asserted_at": None,
            "coverage_start": None,
            "coverage_end": None,
            "evidence_ids": [],
        }
    asserted_at = _timestamp(row["asserted_at"], "auditor asserted_at")
    coverage_start = _timestamp(row["coverage_start"], "auditor coverage_start")
    coverage_end = _timestamp(row["coverage_end"], "auditor coverage_end")
    if coverage_end < coverage_start:
        raise ValueError("auditor coverage window is reversed")
    return {
        "state": "asserted",
        "assertion_sha256": _digest(
            row["assertion_sha256"], "independent auditor assertion digest"
        ),
        "asserted_at": asserted_at,
        "coverage_start": coverage_start,
        "coverage_end": coverage_end,
        "evidence_ids": _evidence_ids(
            row["evidence_ids"], "independent auditor evidence_ids"
        ),
    }


def _checklist(
    value: object, required: Sequence[str], label: str, *, naic: bool = False
) -> dict[str, dict[str, Any]]:
    expected = frozenset(required)
    row = _closed(value, expected, label)
    return {
        item: _check_item(row[item], f"{label} {item}", naic=naic)
        for item in required
    }


def _normalize_nyc(value: object) -> dict[str, Any]:
    raw_fields = frozenset(
        {
            "assessment_window_start",
            "assessment_window_end",
            "independent_auditor",
            "checklist",
        }
    )
    canonical_fields = raw_fields | {"legal_determination_state"}
    if not isinstance(value, Mapping) or set(value) not in {
        raw_fields,
        canonical_fields,
    }:
        raise ValueError("NYC Local Law 144 content must use the closed schema")
    row = {key: value[key] for key in raw_fields}
    start = _timestamp(row["assessment_window_start"], "assessment_window_start")
    end = _timestamp(row["assessment_window_end"], "assessment_window_end")
    if end < start:
        raise ValueError("assessment window is reversed")
    return {
        "assessment_window_start": start,
        "assessment_window_end": end,
        "independent_auditor": _normalize_auditor(row["independent_auditor"]),
        "checklist": _checklist(
            row["checklist"], NYC_LL144_CHECKS, "NYC Local Law 144 checklist"
        ),
        "legal_determination_state": "human_review_required",
    }


def _normalize_naic(value: object) -> dict[str, Any]:
    raw_fields = frozenset(
        {
            "bulletin_version_code",
            "jurisdiction_scope_codes",
            "applicability_assertion_sha256",
            "checklist",
        }
    )
    canonical_fields = raw_fields | {"legal_determination_state"}
    if not isinstance(value, Mapping) or set(value) not in {
        raw_fields,
        canonical_fields,
    }:
        raise ValueError("NAIC insurance AI content must use the closed schema")
    row = {key: value[key] for key in raw_fields}
    jurisdictions = _evidence_ids(
        row["jurisdiction_scope_codes"],
        "jurisdiction_scope_codes",
    )
    if len(jurisdictions) > _MAX_JURISDICTIONS:
        raise ValueError("jurisdiction_scope_codes exceeds 32 entries")
    return {
        "bulletin_version_code": _token(
            row["bulletin_version_code"], "bulletin_version_code"
        ),
        "jurisdiction_scope_codes": jurisdictions,
        "applicability_assertion_sha256": _digest(
            row["applicability_assertion_sha256"], "applicability assertion digest"
        ),
        "checklist": _checklist(
            row["checklist"], NAIC_CHECKS, "NAIC checklist", naic=True
        ),
        "legal_determination_state": "human_review_required",
    }


def _normalize_content(package_type: str, value: object) -> dict[str, Any]:
    if package_type == CREDIT_ADVERSE_ACTION:
        result = _normalize_credit(value)
    elif package_type == FAIR_LENDING_AGGREGATE:
        result = _normalize_fair_lending(value)
    elif package_type == NYC_LL144:
        result = _normalize_nyc(value)
    else:
        result = _normalize_naic(value)
    _canonical(result)
    return result


def _content_evidence_ids(package_type: str, content: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    if package_type == CREDIT_ADVERSE_ACTION:
        for reason in content["reason_codes"]:
            result.update(reason["evidence_ids"])
    elif package_type == FAIR_LENDING_AGGREGATE:
        result.update(content["reference_cohort"]["evidence_ids"])
        for cohort in content["comparison_cohorts"]:
            result.update(cohort["evidence_ids"])
    elif package_type == NYC_LL144:
        result.update(content["independent_auditor"]["evidence_ids"])
        for item in content["checklist"].values():
            result.update(item["evidence_ids"])
    else:
        for item in content["checklist"].values():
            result.update(item["evidence_ids"])
    return result


def _completeness_gaps(package_type: str, content: Mapping[str, Any]) -> list[str]:
    gaps: list[str] = []
    if package_type == FAIR_LENDING_AGGREGATE:
        if content["reference_cohort"]["sample_count"] == 0:
            gaps.append("reference_cohort.zero_denominator")
        gaps.extend(
            f"comparison_cohort.{row['cohort_code']}.zero_denominator"
            for row in content["comparison_cohorts"]
            if row["sample_count"] == 0
        )
    elif package_type == NYC_LL144:
        if content["independent_auditor"]["state"] != "asserted":
            gaps.append("independent_auditor")
        gaps.extend(
            f"checklist.{name}"
            for name, item in content["checklist"].items()
            if item["state"] == "missing"
        )
    elif package_type == NAIC_INSURANCE:
        gaps.extend(
            f"checklist.{name}"
            for name, item in content["checklist"].items()
            if item["state"] in {"missing", "partial"}
        )
    return sorted(gaps)


def _builtin_template(package_type: str) -> dict[str, Any]:
    specification = _TEMPLATE_SPECIFICATIONS[package_type]
    return {
        "package_type": package_type,
        "template_id": specification["template_id"],
        "version": specification["version"],
        "digest": _sha256(specification),
    }


def _record_state(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in sorted(_RECORD_FIELDS - {"state_sha256"})}


class RegulatedVerticalsService:
    """Prepare, approve, revalidate, and export closed regulated-use packages."""

    def __init__(
        self,
        *,
        records: GovernedRecordStore | None = None,
        asset_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
        evidence_resolver: Callable[[str], Mapping[str, Any] | None] | None = None,
        template_resolver: Callable[[str], Mapping[str, Any] | None] | None = None,
        clock: Callable[[], float] | None = None,
        enforce_feature: bool = True,
    ) -> None:
        for value, label in (
            (asset_lookup, "asset_lookup"),
            (evidence_resolver, "evidence_resolver"),
            (template_resolver, "template_resolver"),
            (clock, "clock"),
        ):
            if value is not None and not callable(value):
                raise ValueError(f"{label} must be callable")
        if not isinstance(enforce_feature, bool):
            raise ValueError("enforce_feature must be a boolean")
        self._records = records or _PACKAGES
        self._asset_lookup = asset_lookup
        self._evidence_resolver = evidence_resolver
        self._template_resolver = template_resolver
        self._clock = clock
        self._enforce_feature = enforce_feature

    def _require_active(self) -> str:
        if self._enforce_feature:
            require_enabled()
        return _tenant_ref()

    def _now(self) -> float:
        source = self._clock or self._records.authoritative_time
        return _timestamp(source(), "authority time")

    def _asset_binding(self, value: object) -> dict[str, Any]:
        asset = _asset_id(value)
        lookup = self._asset_lookup
        if lookup is None:
            from . import model_risk_assurance

            lookup = model_risk_assurance.get_observation
        try:
            observation = lookup(asset)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise AIRegulatedVerticalsAssetError("Model Risk asset lookup failed") from exc
        if not isinstance(observation, Mapping):
            raise AIRegulatedVerticalsAssetError("Model Risk asset does not exist")
        try:
            observed = _asset_id(observation.get("asset_id"))
            revision = _integer(
                observation.get("revision"), "asset revision", 1, 2**63 - 1
            )
            digest = _digest(
                observation.get("version_digest"), "asset version_digest"
            )
        except (TypeError, ValueError) as exc:
            raise AIRegulatedVerticalsAssetError(
                "Model Risk asset binding is malformed"
            ) from exc
        if observed != asset:
            raise AIRegulatedVerticalsAssetError("Model Risk asset lookup changed identity")
        return {"asset_id": asset, "revision": revision, "version_digest": digest}

    def _template_binding(self, value: object) -> dict[str, Any]:
        package_type = _package_type(value)
        resolver = self._template_resolver or _builtin_template
        try:
            raw = resolver(package_type)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise AIRegulatedVerticalsTemplateError("template authority lookup failed") from exc
        try:
            row = _closed(
                raw,
                frozenset({"package_type", "template_id", "version", "digest"}),
                "template binding",
            )
            bound_type = _package_type(row["package_type"])
            binding = {
                "package_type": bound_type,
                "template_id": _token(row["template_id"], "template_id"),
                "version": _integer(row["version"], "template version", 1, 2**31 - 1),
                "digest": _digest(row["digest"], "template digest"),
            }
        except (TypeError, ValueError) as exc:
            raise AIRegulatedVerticalsTemplateError(
                "template authority is malformed"
            ) from exc
        if bound_type != package_type:
            raise AIRegulatedVerticalsTemplateError("template authority changed package type")
        return binding

    def _evidence_lookup(self, evidence_id: str) -> Mapping[str, Any]:
        resolver = self._evidence_resolver
        if resolver is None:
            from . import model_risk_assurance

            resolver = model_risk_assurance.get_evidence
        try:
            row = resolver(evidence_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise AIRegulatedVerticalsEvidenceError("approved evidence lookup failed") from exc
        if not isinstance(row, Mapping):
            raise AIRegulatedVerticalsEvidenceError("cited approved evidence does not exist")
        return row

    def _verify_evidence(
        self, binding: Mapping[str, str], *, asset_id: str
    ) -> dict[str, str]:
        evidence_id = _token(binding.get("evidence_id"), "evidence_id")
        expected = _digest(binding.get("digest"), "evidence digest")
        row = self._evidence_lookup(evidence_id)
        try:
            observed_id = _token(
                row.get("evidence_id", row.get("id")), "resolved evidence_id"
            )
            observed_digest = _digest(
                row.get("digest", row.get("evidence_digest", row.get("payload_sha256"))),
                "resolved evidence digest",
            )
        except (TypeError, ValueError) as exc:
            raise AIRegulatedVerticalsEvidenceError(
                "resolved evidence binding is malformed"
            ) from exc
        if observed_id != evidence_id or observed_digest != expected:
            raise AIRegulatedVerticalsEvidenceError("cited evidence digest changed")
        if row.get("status") != "approved":
            raise AIRegulatedVerticalsEvidenceError("cited evidence is not approved")
        if "result" in row and row.get("result") != "passed":
            raise AIRegulatedVerticalsEvidenceError("cited evidence is not a passing result")
        if not (row.get("current") is True or row.get("freshness") == "current"):
            raise AIRegulatedVerticalsEvidenceError("cited evidence is not current")
        if "asset_id" in row and row.get("asset_id") != asset_id:
            raise AIRegulatedVerticalsEvidenceError(
                "cited evidence belongs to a different asset"
            )
        return {"evidence_id": evidence_id, "digest": observed_digest}

    def _verify_evidence_set(
        self, bindings: Sequence[Mapping[str, str]], *, asset_id: str
    ) -> list[dict[str, str]]:
        return [self._verify_evidence(row, asset_id=asset_id) for row in bindings]

    @staticmethod
    def _record_id(tenant_ref: str, package_id: str) -> str:
        return f"RVP-{_sha256({'tenant_ref': tenant_ref, 'package_id': package_id})[:32]}"

    def _version(
        self,
        *,
        number: int,
        asset_binding: Mapping[str, Any],
        template_binding: Mapping[str, Any],
        evidence_bindings: Sequence[Mapping[str, str]],
        content: Mapping[str, Any],
        operation_sha256: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        now = self._now()
        timestamp_fields: list[float] = []
        if template_binding["package_type"] == FAIR_LENDING_AGGREGATE:
            timestamp_fields.append(content["window_end"])
        elif template_binding["package_type"] == NYC_LL144:
            timestamp_fields.append(content["assessment_window_end"])
            auditor = content["independent_auditor"]
            if auditor["state"] == "asserted":
                timestamp_fields.extend([auditor["asserted_at"], auditor["coverage_end"]])
        if any(value > now + _MAX_FUTURE_SKEW_SECONDS for value in timestamp_fields):
            raise ValueError("package authority timestamp is too far in the future")
        content_sha = _sha256(content)
        authority = {
            "version": number,
            "asset_binding": dict(asset_binding),
            "template_binding": dict(template_binding),
            "evidence_bindings": [dict(row) for row in evidence_bindings],
            "content_sha256": content_sha,
        }
        return {
            "version": number,
            "prepared_at": now,
            "prepared_by_ref": actor_ref,
            "operation_sha256": operation_sha256,
            "asset_binding": dict(asset_binding),
            "template_binding": dict(template_binding),
            "evidence_bindings": [dict(row) for row in evidence_bindings],
            "content": copy.deepcopy(dict(content)),
            "content_sha256": content_sha,
            "authority_sha256": _sha256(authority),
            "approval": None,
        }

    def _validate_record(  # noqa: C901
        self, value: object, *, tenant_ref: str
    ) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise AIRegulatedVerticalsStateError("stored package is not an object")
        if set(value) - _RECORD_FIELDS - _STORE_METADATA or _RECORD_FIELDS - set(value):
            raise AIRegulatedVerticalsStateError("stored package shape is malformed")
        try:
            record = dict(value)
            if record["schema"] != PACKAGE_SCHEMA:
                raise ValueError("package schema changed")
            if record["tenant_ref"] != tenant_ref:
                raise ValueError("package tenant authority changed")
            package_id = _token(record["package_id"], "package_id")
            package_type = _package_type(record["package_type"])
            asset_id = _asset_id(record["asset_id"])
            if record["id"] != self._record_id(tenant_ref, package_id):
                raise ValueError("package identity digest changed")
            _digest(record["create_operation_sha256"], "create operation digest")
            revision = _integer(record["revision"], "revision", 1, 2**63 - 1)
            versions = record["versions"]
            if not isinstance(versions, list) or not 1 <= len(versions) <= _MAX_VERSIONS:
                raise ValueError("package versions are malformed")
            for index, raw_version in enumerate(versions, start=1):
                version = _closed(raw_version, _VERSION_FIELDS, "stored package version")
                if version["version"] != index:
                    raise ValueError("package versions are not contiguous")
                _timestamp(version["prepared_at"], "prepared_at")
                prepared_ref = _digest(version["prepared_by_ref"], "prepared_by_ref")
                _digest(version["operation_sha256"], "operation_sha256")
                asset = _closed(
                    version["asset_binding"],
                    frozenset({"asset_id", "revision", "version_digest"}),
                    "asset binding",
                )
                if _asset_id(asset["asset_id"]) != asset_id:
                    raise ValueError("package asset changed")
                _integer(asset["revision"], "asset revision", 1, 2**63 - 1)
                _digest(asset["version_digest"], "asset version digest")
                template = _closed(
                    version["template_binding"],
                    frozenset({"package_type", "template_id", "version", "digest"}),
                    "template binding",
                )
                if _package_type(template["package_type"]) != package_type:
                    raise ValueError("package template type changed")
                _token(template["template_id"], "template_id")
                _integer(template["version"], "template version", 1, 2**31 - 1)
                _digest(template["digest"], "template digest")
                evidence = _evidence_bindings(version["evidence_bindings"])
                if evidence != version["evidence_bindings"]:
                    raise ValueError("evidence bindings are not canonical")
                content = _normalize_content(package_type, version["content"])
                if content != version["content"]:
                    raise ValueError("package content is not canonical")
                if {row["evidence_id"] for row in evidence} != _content_evidence_ids(
                    package_type, content
                ):
                    raise ValueError("package evidence bindings are not exact")
                content_sha = _digest(version["content_sha256"], "content_sha256")
                if content_sha != _sha256(content):
                    raise ValueError("package content digest mismatch")
                authority = {
                    "version": index,
                    "asset_binding": dict(asset),
                    "template_binding": dict(template),
                    "evidence_bindings": evidence,
                    "content_sha256": content_sha,
                }
                authority_sha = _digest(
                    version["authority_sha256"], "authority_sha256"
                )
                if authority_sha != _sha256(authority):
                    raise ValueError("package authority digest mismatch")
                approval = version["approval"]
                if approval is not None:
                    approved = _closed(
                        approval,
                        frozenset(
                            {
                                "approved_at",
                                "approved_by_ref",
                                "authority_sha256",
                                "four_eyes",
                            }
                        ),
                        "package approval",
                    )
                    _timestamp(approved["approved_at"], "approved_at")
                    approved_ref = _digest(
                        approved["approved_by_ref"], "approved_by_ref"
                    )
                    if approved_ref == prepared_ref or approved["four_eyes"] is not True:
                        raise ValueError("package approval violates four-eyes")
                    if _digest(
                        approved["authority_sha256"], "approval authority"
                    ) != authority_sha:
                        raise ValueError("package approval authority mismatch")
            expected_status = "approved" if versions[-1]["approval"] is not None else "draft"
            if record["status"] != expected_status:
                raise ValueError("package status is inconsistent")
            if _digest(record["state_sha256"], "state_sha256") != _sha256(
                _record_state(record)
            ):
                raise ValueError("package state digest mismatch")
            record["revision"] = revision
        except AIRegulatedVerticalsStateError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise AIRegulatedVerticalsStateError("stored package is malformed") from exc
        return record

    def _currentness(self, version: Mapping[str, Any]) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        try:
            current_asset = self._asset_binding(version["asset_binding"]["asset_id"])
            if current_asset != version["asset_binding"]:
                reasons.append("asset_authority_changed")
        except AIRegulatedVerticalsError:
            reasons.append("asset_authority_unavailable")
        try:
            current_template = self._template_binding(
                version["template_binding"]["package_type"]
            )
            if current_template != version["template_binding"]:
                reasons.append("template_authority_changed")
        except AIRegulatedVerticalsError:
            reasons.append("template_authority_unavailable")
        for binding in version["evidence_bindings"]:
            try:
                self._verify_evidence(
                    binding, asset_id=version["asset_binding"]["asset_id"]
                )
            except AIRegulatedVerticalsEvidenceError:
                reasons.append(f"evidence_authority_changed:{binding['evidence_id']}")
        return not reasons, reasons

    def _version_projection(
        self, package_type: str, version: Mapping[str, Any]
    ) -> dict[str, Any]:
        fresh, reasons = self._currentness(version)
        gaps = _completeness_gaps(package_type, version["content"])
        approved = version["approval"] is not None
        status = "stale" if approved and not fresh else ("approved" if approved else "draft")
        return {
            "version": version["version"],
            "prepared_at": version["prepared_at"],
            "asset_binding": copy.deepcopy(version["asset_binding"]),
            "template_binding": copy.deepcopy(version["template_binding"]),
            "evidence_bindings": copy.deepcopy(version["evidence_bindings"]),
            "content": copy.deepcopy(version["content"]),
            "content_sha256": version["content_sha256"],
            "authority_sha256": version["authority_sha256"],
            "approved_at": None if not approved else version["approval"]["approved_at"],
            "four_eyes_approved": approved,
            "authority_fresh": fresh,
            "stale_reasons": reasons,
            "completeness_gaps": gaps,
            "exportable": approved and fresh and not gaps,
            "status": status,
        }

    def _public_record(self, record: Mapping[str, Any]) -> dict[str, Any]:
        package_type = record["package_type"]
        versions = [
            self._version_projection(package_type, row) for row in record["versions"]
        ]
        return {
            "schema": PACKAGE_SCHEMA,
            "package_id": record["package_id"],
            "package_type": package_type,
            "asset_id": record["asset_id"],
            "revision": record["revision"],
            "status": versions[-1]["status"],
            "versions": versions,
            "notice": DECISION_SUPPORT_NOTICE,
        }

    def create_package(
        self,
        package_id: str,
        *,
        package_type: str,
        asset_id: str,
        content: Mapping[str, Any],
        evidence_bindings: Sequence[Mapping[str, str]],
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = _token(package_id, "package_id")
        kind = _package_type(package_type)
        actor_name, actor_ref = _actor(actor)
        operation = _text(idempotency_key, "idempotency_key", 256)
        operation_sha = _sha256({"tenant_ref": tenant_ref, "operation": operation})
        normalized = _normalize_content(kind, content)
        bindings = _evidence_bindings(evidence_bindings)
        if {row["evidence_id"] for row in bindings} != _content_evidence_ids(
            kind, normalized
        ):
            raise ValueError(
                "evidence_bindings must exactly match all package evidence citations"
            )
        asset = self._asset_binding(asset_id)
        template = self._template_binding(kind)
        bindings = self._verify_evidence_set(bindings, asset_id=asset["asset_id"])
        record_id = self._record_id(tenant_ref, semantic_id)
        existing = self._records.get(record_id)
        if existing is not None:
            current = self._validate_record(existing, tenant_ref=tenant_ref)
            first = current["versions"][0]
            if (
                current["create_operation_sha256"] != operation_sha
                or current["package_type"] != kind
                or first["asset_binding"] != asset
                or first["template_binding"] != template
                or first["evidence_bindings"] != bindings
                or first["content"] != normalized
            ):
                raise AIRegulatedVerticalsIdempotencyConflict(
                    "package identity or idempotency key is bound to different content"
                )
            return self._public_record(current)
        version = self._version(
            number=1,
            asset_binding=asset,
            template_binding=template,
            evidence_bindings=bindings,
            content=normalized,
            operation_sha256=operation_sha,
            actor_ref=actor_ref,
        )
        record = {
            "id": record_id,
            "schema": PACKAGE_SCHEMA,
            "tenant_ref": tenant_ref,
            "package_id": semantic_id,
            "package_type": kind,
            "asset_id": asset["asset_id"],
            "versions": [version],
            "status": "draft",
            "create_operation_sha256": operation_sha,
        }
        record["state_sha256"] = _sha256(_record_state(record))
        try:
            saved = self._records.create(
                record,
                action="prepare_regulated_vertical_package",
                actor=actor_name,
                max_records=_MAX_PACKAGES,
            )
        except RecordConflict as exc:
            concurrent = self._records.get(record_id)
            if concurrent is None:
                raise
            current = self._validate_record(concurrent, tenant_ref=tenant_ref)
            first = current["versions"][0]
            if (
                current["create_operation_sha256"] != operation_sha
                or current["package_type"] != kind
                or first["asset_binding"] != asset
                or first["template_binding"] != template
                or first["evidence_bindings"] != bindings
                or first["content"] != normalized
            ):
                raise AIRegulatedVerticalsIdempotencyConflict(
                    "package was concurrently created with different content"
                ) from exc
            saved = current
        return self._public_record(self._validate_record(saved, tenant_ref=tenant_ref))

    def add_version(
        self,
        package_id: str,
        *,
        content: Mapping[str, Any],
        evidence_bindings: Sequence[Mapping[str, str]],
        expected_revision: int,
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = _token(package_id, "package_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**63 - 1)
        actor_name, actor_ref = _actor(actor)
        operation = _text(idempotency_key, "idempotency_key", 256)
        operation_sha = _sha256({"tenant_ref": tenant_ref, "operation": operation})
        record_id = self._record_id(tenant_ref, semantic_id)
        raw = self._records.get(record_id)
        if raw is None:
            raise AIRegulatedVerticalsStateError("package does not exist")
        current = self._validate_record(raw, tenant_ref=tenant_ref)
        kind = current["package_type"]
        normalized = _normalize_content(kind, content)
        bindings = _evidence_bindings(evidence_bindings)
        if {row["evidence_id"] for row in bindings} != _content_evidence_ids(
            kind, normalized
        ):
            raise ValueError(
                "evidence_bindings must exactly match all package evidence citations"
            )
        asset = self._asset_binding(current["asset_id"])
        template = self._template_binding(kind)
        bindings = self._verify_evidence_set(bindings, asset_id=asset["asset_id"])
        latest = current["versions"][-1]
        if latest["operation_sha256"] == operation_sha:
            if (
                latest["asset_binding"] != asset
                or latest["template_binding"] != template
                or latest["evidence_bindings"] != bindings
                or latest["content"] != normalized
            ):
                raise AIRegulatedVerticalsIdempotencyConflict(
                    "idempotency key is bound to a different package version"
                )
            return self._public_record(current)
        if current["revision"] != expected:
            raise RecordConflict(
                f"package changed (expected revision {expected}, found {current['revision']})"
            )
        if len(current["versions"]) >= _MAX_VERSIONS:
            raise AIRegulatedVerticalsStateError("package exceeds its version bound")
        next_version = self._version(
            number=len(current["versions"]) + 1,
            asset_binding=asset,
            template_binding=template,
            evidence_bindings=bindings,
            content=normalized,
            operation_sha256=operation_sha,
            actor_ref=actor_ref,
        )

        def mutate(row: dict[str, Any]) -> None:
            validated = self._validate_record(row, tenant_ref=tenant_ref)
            if validated["revision"] != expected:
                raise RecordConflict("package revision changed")
            row["versions"].append(next_version)
            row["status"] = "draft"
            row["state_sha256"] = _sha256(_record_state(row))

        saved = self._records.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="prepare_regulated_vertical_package_version",
            actor=actor_name,
        )
        if saved is None:
            raise AIRegulatedVerticalsStateError("package disappeared")
        return self._public_record(self._validate_record(saved, tenant_ref=tenant_ref))

    def approve_package(
        self,
        package_id: str,
        version: int,
        *,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = _token(package_id, "package_id")
        selected = _integer(version, "version", 1, _MAX_VERSIONS)
        expected = _integer(expected_revision, "expected_revision", 1, 2**63 - 1)
        actor_name, actor_ref = _actor(actor)
        record_id = self._record_id(tenant_ref, semantic_id)
        raw = self._records.get(record_id)
        if raw is None:
            raise AIRegulatedVerticalsStateError("package does not exist")
        current = self._validate_record(raw, tenant_ref=tenant_ref)
        if current["revision"] != expected:
            raise RecordConflict(
                f"package changed (expected revision {expected}, found {current['revision']})"
            )
        if selected != len(current["versions"]):
            raise AIRegulatedVerticalsApprovalError(
                "only the latest package version can be approved"
            )
        candidate = current["versions"][selected - 1]
        if candidate["approval"] is not None:
            return self._public_record(current)
        if actor_ref == candidate["prepared_by_ref"]:
            raise AIRegulatedVerticalsApprovalError(
                "four-eyes approval requires a different human than the preparer"
            )
        gaps = _completeness_gaps(current["package_type"], candidate["content"])
        if gaps:
            raise AIRegulatedVerticalsApprovalError(
                "package has missing required data: " + ", ".join(gaps)
            )
        fresh, reasons = self._currentness(candidate)
        if not fresh:
            raise AIRegulatedVerticalsStaleError(
                "package authority is stale: " + ", ".join(reasons)
            )
        approved_at = self._now()

        def mutate(row: dict[str, Any]) -> None:
            validated = self._validate_record(row, tenant_ref=tenant_ref)
            live = validated["versions"][selected - 1]
            if live["approval"] is not None:
                return
            if live["prepared_by_ref"] == actor_ref:
                raise AIRegulatedVerticalsApprovalError(
                    "package violates four-eyes approval"
                )
            live["approval"] = {
                "approved_at": approved_at,
                "approved_by_ref": actor_ref,
                "authority_sha256": live["authority_sha256"],
                "four_eyes": True,
            }
            row["status"] = "approved"
            row["state_sha256"] = _sha256(_record_state(row))

        saved = self._records.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="approve_regulated_vertical_package",
            actor=actor_name,
        )
        if saved is None:
            raise AIRegulatedVerticalsStateError("package disappeared")
        return self._public_record(self._validate_record(saved, tenant_ref=tenant_ref))

    def get_package(self, package_id: str) -> dict[str, Any] | None:
        tenant_ref = self._require_active()
        semantic_id = _token(package_id, "package_id")
        row = self._records.get(self._record_id(tenant_ref, semantic_id))
        if row is None:
            return None
        return self._public_record(self._validate_record(row, tenant_ref=tenant_ref))

    def list_packages(self, *, limit: int = _MAX_LIST) -> list[dict[str, Any]]:
        tenant_ref = self._require_active()
        maximum = _integer(limit, "limit", 1, _MAX_LIST)
        result: list[dict[str, Any]] = []
        for raw in self._records.list(limit=maximum):
            record = self._validate_record(raw, tenant_ref=tenant_ref)
            latest = self._version_projection(
                record["package_type"], record["versions"][-1]
            )
            result.append(
                {
                    "package_id": record["package_id"],
                    "package_type": record["package_type"],
                    "asset_id": record["asset_id"],
                    "revision": record["revision"],
                    "latest_version": latest["version"],
                    "status": latest["status"],
                    "exportable": latest["exportable"],
                }
            )
        return sorted(result, key=lambda item: item["package_id"])

    def export_package(
        self, package_id: str, *, version: int | None = None
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = _token(package_id, "package_id")
        row = self._records.get(self._record_id(tenant_ref, semantic_id))
        if row is None:
            raise AIRegulatedVerticalsStateError("package does not exist")
        record = self._validate_record(row, tenant_ref=tenant_ref)
        selected = (
            len(record["versions"])
            if version is None
            else _integer(version, "version", 1, len(record["versions"]))
        )
        candidate = record["versions"][selected - 1]
        if candidate["approval"] is None:
            raise AIRegulatedVerticalsApprovalError("package version is not human approved")
        gaps = _completeness_gaps(record["package_type"], candidate["content"])
        if gaps:
            raise AIRegulatedVerticalsApprovalError("package version is incomplete")
        fresh, reasons = self._currentness(candidate)
        if not fresh:
            raise AIRegulatedVerticalsStaleError(
                "package authority is stale: " + ", ".join(reasons)
            )
        packet = {
            "schema": EXPORT_SCHEMA,
            "package_id": record["package_id"],
            "package_type": record["package_type"],
            "version": selected,
            "prepared_at": candidate["prepared_at"],
            "approved_at": candidate["approval"]["approved_at"],
            "asset_binding": copy.deepcopy(candidate["asset_binding"]),
            "template_binding": copy.deepcopy(candidate["template_binding"]),
            "evidence_bindings": copy.deepcopy(candidate["evidence_bindings"]),
            "content": copy.deepcopy(candidate["content"]),
            "content_sha256": candidate["content_sha256"],
            "authority_sha256": candidate["authority_sha256"],
            "approval": {
                "human_approved": True,
                "four_eyes": True,
                "authority_fresh": True,
            },
            "privacy": {
                "aggregate_or_digest_only": True,
                "individual_records_included": False,
                "raw_inputs_included": False,
                "raw_outputs_included": False,
            },
            "claims": {
                "credit_decision": False,
                "employment_decision": False,
                "insurance_decision": False,
                "compliance_determination": False,
                "independent_audit_claim": False,
                "regulator_filing_claim": False,
                "certification_claim": False,
                "automated_adverse_impact_conclusion": False,
            },
            "notice": DECISION_SUPPORT_NOTICE,
        }
        return {**packet, "packet_sha256": _sha256(packet)}


_DEFAULT = RegulatedVerticalsService()


def configured_regulated_verticals() -> RegulatedVerticalsService:
    require_enabled()
    return _DEFAULT


__all__ = [
    "AGGREGATE_REPORT_SCHEMA",
    "AIRegulatedVerticalsApprovalError",
    "AIRegulatedVerticalsAssetError",
    "AIRegulatedVerticalsConfigError",
    "AIRegulatedVerticalsError",
    "AIRegulatedVerticalsEvidenceError",
    "AIRegulatedVerticalsIdempotencyConflict",
    "AIRegulatedVerticalsStaleError",
    "AIRegulatedVerticalsStateError",
    "AIRegulatedVerticalsTemplateError",
    "CREDIT_ADVERSE_ACTION",
    "DECISION_SUPPORT_NOTICE",
    "EXPORT_SCHEMA",
    "FAIR_LENDING_AGGREGATE",
    "NAIC_CHECKS",
    "NAIC_INSURANCE",
    "NYC_LL144",
    "NYC_LL144_CHECKS",
    "PACKAGE_SCHEMA",
    "PACKAGE_TYPES",
    "RegulatedVerticalsService",
    "configured_regulated_verticals",
    "enabled",
    "require_enabled",
]
