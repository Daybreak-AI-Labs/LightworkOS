"""Short, governed business intake for proposed AI use cases.

The intake is deliberately smaller than a full AI risk assessment.  A business
operator supplies seven bounded question groups: identity, accountability,
purpose, data context, deployment context, structured regulatory signals, and
an optional link to an already observed system.  Drafts are tenant-scoped and
CAS-governed, so a conversational surface can save one answer group at a time
and resume safely.

Submission performs deterministic *triage*, not a legal classification.  It
uses :func:`maverick.model_risk_assurance.assurance_profile` as the existing
signal authority, creates or links a governed ``system`` observation, creates
a proposed model-risk declaration when one does not exist, and saves a pinned
``aira`` assessment in ``pending_review``.  The EU AI Act category remains
``undetermined`` until a human reviewer asserts it.

The persisted burden metrics distinguish machine runtime and system-observed
session elapsed time.  They never claim that a person completed the intake in
under three minutes; that claim requires a separate observed usability study.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
import unicodedata
from collections.abc import Callable, Mapping
from typing import Any

from .assessment import (
    AssessmentConflict,
    AssessmentSession,
    load_saved,
    save_session,
    template_for_saved_record,
)
from .governed_records import GovernedRecordStore
from .model_risk_assurance import (
    EU_AI_ACT_METADATA,
    ModelRiskAssuranceOfficer,
    assurance_profile,
    stable_asset_id,
)
from .privacy_ops import RecordConflict

INTAKE_SCHEMA = "lightwork.ai-business-intake.v1"
CLASSIFICATION_SCHEMA = "lightwork.ai-business-intake-triage.v1"
METRICS_SCHEMA = "lightwork.ai-business-intake-burden.v1"
NON_DETERMINATION_NOTICE = (
    "Automated structured triage only. Human review is required; this record is "
    "not a legal classification, approval, conformity assessment, or certification."
)

_INTAKES = GovernedRecordStore(
    "ai_business_intakes",
    "ABI",
    "ai_business_intake",
)

_MAX_RECORDS = 5_000
_MAX_OPERATION_RECEIPTS = 64
_MAX_SUBMISSION_BYTES = 16 * 1024
_STATUS = frozenset({"draft", "submitting", "pending_review"})
_STAGES = frozenset({"proposed", "pilot", "production"})
_AUDIENCES = frozenset({"internal", "external", "both"})
_DECISION_ROLES = frozenset({"assistive", "recommending", "automated"})
_NOTICE_STATES = frozenset({"yes", "no", "not_applicable", "unknown"})
_DATA_CATEGORIES = frozenset({
    "none",
    "public",
    "internal",
    "confidential_business",
    "personal",
    "sensitive_personal",
    "financial",
    "health",
    "biometric",
    "employment",
    "education",
    "location",
    "criminal_justice",
})
_TOP_LEVEL_FIELDS = frozenset({
    "use_case_name",
    "accountable_owner",
    "business_unit",
    "purpose",
    "data_context",
    "deployment_context",
    "regulatory_context",
    "existing_asset_id",
})
_REQUIRED_GROUPS = (
    "use_case_name",
    "accountable_owner",
    "business_unit",
    "purpose",
    "data_context",
    "deployment_context",
    "regulatory_context",
)
_REQUIRED_LEAVES = (
    "use_case_name",
    "accountable_owner",
    "business_unit",
    "purpose",
    "data_context.categories",
    "data_context.personal_data",
    "data_context.sensitive_data",
    "deployment_context.stage",
    "deployment_context.audience",
    "deployment_context.decision_role",
    "deployment_context.human_oversight",
    "deployment_context.third_party",
    "deployment_context.safety_critical",
    "deployment_context.transparency_notice",
    "regulatory_context.prohibited_signals",
    "regulatory_context.high_risk_domains",
    "regulatory_context.transparency_signals",
)
_DATA_KEYS = frozenset({
    "categories",
    "personal_data",
    "sensitive_data",
    "source_summary",
})
_DEPLOYMENT_KEYS = frozenset({
    "stage",
    "audience",
    "decision_role",
    "human_oversight",
    "third_party",
    "safety_critical",
    "transparency_notice",
})
_REGULATORY_KEYS = frozenset({
    "prohibited_signals",
    "high_risk_domains",
    "transparency_signals",
})
_ASSET_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_INTAKE_RE = re.compile(r"ABI-[0-9a-f]{24}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SECRET_VALUE_RE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}|"
    r"\bsk-[A-Za-z0-9_-]{16,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})",
    re.IGNORECASE,
)
_RISK_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def form_contract() -> dict[str, Any]:
    """Describe the current bounded questionnaire; submission remains authoritative."""
    from . import model_risk_assurance as authority

    fields = []

    def field(path, label, kind, group, choices=None, limit=None):
        row = {"path": path, "label": label, "kind": kind, "group": group,
               "required": path in _REQUIRED_LEAVES}
        if choices is not None:
            row["choices"] = sorted(choices)
        if limit is not None:
            row["max_length"] = limit
        fields.append(row)

    for path, label, limit in (("use_case_name", "Use-case name", 256),
                               ("accountable_owner", "Accountable owner", 256),
                               ("business_unit", "Business unit", 256),
                               ("purpose", "What will this AI help people do?", 4000)):
        field(path, label, "text", "About the use case", limit=limit)
    field("data_context.categories", "Types of data used", "multiple", "Data", _DATA_CATEGORIES)
    field("data_context.personal_data", "Does it use personal data?", "boolean", "Data")
    field("data_context.sensitive_data", "Does it use sensitive personal data?", "boolean", "Data")
    field("data_context.source_summary", "Where does the data come from?", "text", "Data", limit=500)
    for path, label, choices in (("stage", "Deployment stage", _STAGES),
                                 ("audience", "Who will use or be affected by it?", _AUDIENCES),
                                 ("decision_role", "Role in decisions", _DECISION_ROLES),
                                 ("transparency_notice", "Are people told AI is involved?", _NOTICE_STATES)):
        field("deployment_context." + path, label, "choice", "Deployment", choices)
    for path, label in (("human_oversight", "Can a person review or intervene?"),
                        ("third_party", "Does a third party supply or operate the AI?"),
                        ("safety_critical", "Could its failure affect people's safety?")):
        field("deployment_context." + path, label, "boolean", "Deployment")
    for path, label, choices in (
        ("prohibited_signals", "Potential prohibited-practice signals", authority._PROHIBITED_SIGNALS),
        ("high_risk_domains", "Potential high-risk use areas", authority._HIGH_RISK_DOMAINS),
        ("transparency_signals", "Transparency signals", authority._TRANSPARENCY_SIGNALS),
    ):
        field("regulatory_context." + path, label, "multiple", "Expert review signals", choices)
    field("existing_asset_id", "Existing governed asset reference (optional)", "text", "Advanced", limit=64)
    return {"schema": INTAKE_SCHEMA, "fields": fields, "max_submission_bytes": _MAX_SUBMISSION_BYTES,
            "notice": NON_DETERMINATION_NOTICE}


class AIBusinessIntakeError(RuntimeError):
    """Base failure for the governed AI business-intake core."""


class AIBusinessIntakeStateError(AIBusinessIntakeError):
    """Persisted intake authority is malformed or internally inconsistent."""


class AIBusinessIntakeConfigError(AIBusinessIntakeError):
    """The feature or one of its required authorities is unavailable."""


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("AI business intake must be bounded JSON") from exc
    if len(encoded) > _MAX_SUBMISSION_BYTES:
        raise ValueError("AI business intake exceeds the 16 KiB submission limit")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: object, label: str, limit: int, *, required: bool) -> str:
    if not isinstance(value, str):
        if value is None and not required:
            return ""
        raise ValueError(f"{label} must be text")
    text_value = unicodedata.normalize("NFKC", value).strip()
    if required and not text_value:
        raise ValueError(f"{label} is required")
    if len(text_value) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    if _CONTROL_RE.search(text_value):
        raise ValueError(f"{label} contains control characters")
    if _SECRET_VALUE_RE.search(text_value):
        raise ValueError(f"{label} appears to contain a credential or private key")
    return text_value


def _required_text(value: object, label: str, limit: int) -> str:
    return _text(value, label, limit, required=True)


def _optional_text(value: object, label: str, limit: int) -> str:
    return _text(value, label, limit, required=False)


def _strict_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _choice(value: object, label: str, allowed: frozenset[str]) -> str:
    text_value = _required_text(value, label, 64).lower()
    if text_value not in allowed:
        raise ValueError(f"{label} must be one of {', '.join(sorted(allowed))}")
    return text_value


def _string_list(
    value: object,
    label: str,
    *,
    allowed: frozenset[str] | None = None,
    limit: int = 16,
) -> list[str]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{label} must be an array")
    if len(value) > limit:
        raise ValueError(f"{label} exceeds {limit} entries")
    output: list[str] = []
    for item in value:
        token = _required_text(item, label, 64).lower()
        if allowed is not None and token not in allowed:
            raise ValueError(f"{label} contains an unsupported value: {token}")
        if token not in output:
            output.append(token)
    return sorted(output)


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _known_keys(value: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{label} contains unknown fields: {', '.join(unknown)}")


def _normalize_data_context(value: object, *, complete: bool) -> dict[str, Any]:
    raw = _mapping(value, "data_context")
    _known_keys(raw, _DATA_KEYS, "data_context")
    if complete:
        missing = sorted({"categories", "personal_data", "sensitive_data"} - set(raw))
        if missing:
            raise ValueError(f"data_context is incomplete: {', '.join(missing)}")
    out: dict[str, Any] = {}
    if "categories" in raw:
        categories = _string_list(
            raw["categories"],
            "data categories",
            allowed=_DATA_CATEGORIES,
            limit=12,
        )
        if not categories:
            raise ValueError("data_context.categories must not be empty")
        if "none" in categories and len(categories) != 1:
            raise ValueError("data category 'none' cannot be combined with another category")
        out["categories"] = categories
    if "personal_data" in raw:
        out["personal_data"] = _strict_bool(raw["personal_data"], "personal_data")
    if "sensitive_data" in raw:
        out["sensitive_data"] = _strict_bool(raw["sensitive_data"], "sensitive_data")
    if "source_summary" in raw:
        summary = _optional_text(raw["source_summary"], "source_summary", 500)
        if summary:
            out["source_summary"] = summary
    if out.get("sensitive_data") is True and out.get("personal_data") is False:
        raise ValueError("sensitive_data cannot be true when personal_data is false")
    return out


def _normalize_deployment_context(value: object, *, complete: bool) -> dict[str, Any]:
    raw = _mapping(value, "deployment_context")
    _known_keys(raw, _DEPLOYMENT_KEYS, "deployment_context")
    if complete:
        missing = sorted(_DEPLOYMENT_KEYS - set(raw))
        if missing:
            raise ValueError(f"deployment_context is incomplete: {', '.join(missing)}")
    out: dict[str, Any] = {}
    if "stage" in raw:
        out["stage"] = _choice(raw["stage"], "deployment stage", _STAGES)
    if "audience" in raw:
        out["audience"] = _choice(raw["audience"], "audience", _AUDIENCES)
    if "decision_role" in raw:
        out["decision_role"] = _choice(
            raw["decision_role"], "decision role", _DECISION_ROLES,
        )
    for field in ("human_oversight", "third_party", "safety_critical"):
        if field in raw:
            out[field] = _strict_bool(raw[field], field)
    if "transparency_notice" in raw:
        out["transparency_notice"] = _choice(
            raw["transparency_notice"],
            "transparency notice",
            _NOTICE_STATES,
        )
    if (
        out.get("decision_role") == "automated"
        and out.get("human_oversight") is True
    ):
        # This is possible (a person can review automated output), so keep it.
        # The explicit fields avoid inferring that oversight eliminates the risk.
        pass
    return out


def _normalize_regulatory_context(value: object, *, complete: bool) -> dict[str, Any]:
    raw = _mapping(value, "regulatory_context")
    _known_keys(raw, _REGULATORY_KEYS, "regulatory_context")
    if complete:
        missing = sorted(_REGULATORY_KEYS - set(raw))
        if missing:
            raise ValueError(f"regulatory_context is incomplete: {', '.join(missing)}")
    out: dict[str, Any] = {}
    for field in (
        "prohibited_signals",
        "high_risk_domains",
        "transparency_signals",
    ):
        if field in raw:
            # The existing model-risk authority owns the legal-signal vocabulary.
            # Feed the value through it below instead of copying that vocabulary.
            out[field] = _string_list(raw[field], field, limit=16)
    if out:
        probe = assurance_profile({
            "prohibited_signals": out.get("prohibited_signals", []),
            "high_risk_domains": out.get("high_risk_domains", []),
            "transparency_signals": out.get("transparency_signals", []),
            "safety_critical": False,
            "human_oversight": False,
            "third_party": False,
        })
        reasons = probe["screening_reasons"]
        for field in (
            "prohibited_signals",
            "high_risk_domains",
            "transparency_signals",
        ):
            if field in out:
                out[field] = list(reasons[field])
    return out


def _normalize_patch(value: Mapping[str, Any]) -> dict[str, Any]:
    raw = _mapping(value, "submission patch")
    _known_keys(raw, _TOP_LEVEL_FIELDS, "submission patch")
    if not raw:
        raise ValueError("submission patch must not be empty")
    out: dict[str, Any] = {}
    for field, limit in (
        ("use_case_name", 256),
        ("accountable_owner", 256),
        ("business_unit", 256),
        ("purpose", 4000),
    ):
        if field in raw:
            text_value = _optional_text(raw[field], field, limit)
            out[field] = text_value
    if "data_context" in raw:
        out["data_context"] = _normalize_data_context(raw["data_context"], complete=False)
    if "deployment_context" in raw:
        out["deployment_context"] = _normalize_deployment_context(
            raw["deployment_context"], complete=False,
        )
    if "regulatory_context" in raw:
        out["regulatory_context"] = _normalize_regulatory_context(
            raw["regulatory_context"], complete=False,
        )
    if "existing_asset_id" in raw:
        asset = _optional_text(raw["existing_asset_id"], "existing_asset_id", 64)
        if asset and not _ASSET_RE.fullmatch(asset):
            raise ValueError("existing_asset_id is invalid")
        out["existing_asset_id"] = asset
    _canonical(out)
    return out


def _deep_merge(current: Mapping[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
    merged = json.loads(json.dumps(dict(current), ensure_ascii=False))
    for key, value in patch.items():
        if key in {"data_context", "deployment_context", "regulatory_context"}:
            nested = dict(merged.get(key) or {})
            nested.update(value)
            merged[key] = nested
        elif value == "":
            merged.pop(key, None)
        else:
            merged[key] = value
    _canonical(merged)
    return merged


def _path_present(submission: Mapping[str, Any], path: str) -> bool:
    current: object = submission
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False
        current = current[part]
    if isinstance(current, str):
        return bool(current.strip())
    return current is not None


def _missing_fields(submission: Mapping[str, Any]) -> list[str]:
    return [path for path in _REQUIRED_LEAVES if not _path_present(submission, path)]


def _complete_submission(value: Mapping[str, Any]) -> dict[str, Any]:
    missing = _missing_fields(value)
    if missing:
        raise ValueError("AI business intake is incomplete: " + ", ".join(missing))
    out = {
        "use_case_name": _required_text(value.get("use_case_name"), "use_case_name", 256),
        "accountable_owner": _required_text(
            value.get("accountable_owner"), "accountable_owner", 256,
        ),
        "business_unit": _required_text(value.get("business_unit"), "business_unit", 256),
        "purpose": _required_text(value.get("purpose"), "purpose", 4000),
        "data_context": _normalize_data_context(value.get("data_context"), complete=True),
        "deployment_context": _normalize_deployment_context(
            value.get("deployment_context"), complete=True,
        ),
        "regulatory_context": _normalize_regulatory_context(
            value.get("regulatory_context"), complete=True,
        ),
    }
    asset = _optional_text(value.get("existing_asset_id"), "existing_asset_id", 64)
    if asset:
        if not _ASSET_RE.fullmatch(asset):
            raise ValueError("existing_asset_id is invalid")
        out["existing_asset_id"] = asset
    _canonical(out)
    return out


def _active_tenant() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if not tenant:
        raise AIBusinessIntakeConfigError(
            "AI business intake requires an explicit tenant scope"
        )
    return _required_text(tenant, "tenant", 256)


def _revision(value: object, label: str = "expected_revision") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _public_record(record: Mapping[str, Any]) -> dict[str, Any]:
    hidden = {
        "_audit_pending",
        "idempotency_key_sha256",
        "start_request_sha256",
        "operation_receipts",
        "submission_operation",
    }
    return {key: value for key, value in record.items() if key not in hidden}


def _record_digest(record: Mapping[str, Any]) -> str:
    return _sha256(_public_record(record))


def _validate_record(value: Mapping[str, Any] | None, intake_id: str) -> dict[str, Any] | None:
    if value is None:
        return None
    row = dict(value)
    if row.get("schema") != INTAKE_SCHEMA or row.get("id") != intake_id:
        raise AIBusinessIntakeStateError("AI business intake identity is invalid")
    if not _INTAKE_RE.fullmatch(intake_id):
        raise AIBusinessIntakeStateError("AI business intake id is invalid")
    if row.get("status") not in _STATUS:
        raise AIBusinessIntakeStateError("AI business intake status is invalid")
    _revision(row.get("revision"), "persisted revision")
    if not isinstance(row.get("submission"), Mapping):
        raise AIBusinessIntakeStateError("AI business intake submission is invalid")
    receipts = row.get("operation_receipts")
    if not isinstance(receipts, list) or len(receipts) > _MAX_OPERATION_RECEIPTS:
        raise AIBusinessIntakeStateError("AI business intake operation history is invalid")
    expected_missing = _missing_fields(row["submission"])
    if row.get("missing_fields") != expected_missing:
        raise AIBusinessIntakeStateError("AI business intake progress projection is invalid")
    return row


def _receipt_fingerprint(kind: str, operation_id: str, payload: object, actor: str) -> tuple[str, str]:
    operation = _required_text(operation_id, "operation_id", 128)
    operator = _required_text(actor, "actor", 256)
    op_sha = _sha256(operation)
    request_sha = _sha256({"kind": kind, "operation_id_sha256": op_sha, "payload": payload, "actor": operator})
    return op_sha, request_sha


def _find_receipt(record: Mapping[str, Any], operation_sha: str) -> Mapping[str, Any] | None:
    for receipt in record.get("operation_receipts") or []:
        if isinstance(receipt, Mapping) and receipt.get("operation_id_sha256") == operation_sha:
            return receipt
    return None


def _classification(submission: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    deployment = submission["deployment_context"]
    regulatory = submission["regulatory_context"]
    risk_context = {
        "prohibited_signals": list(regulatory["prohibited_signals"]),
        "high_risk_domains": list(regulatory["high_risk_domains"]),
        "transparency_signals": list(regulatory["transparency_signals"]),
        "safety_critical": bool(deployment["safety_critical"]),
        "human_oversight": bool(deployment["human_oversight"]),
        "third_party": bool(deployment["third_party"]),
    }
    authority = assurance_profile(risk_context)
    risk = str(authority["screening_level"])
    reasons: list[str] = ["model_risk_assurance.assurance_profile"]
    if submission["data_context"]["sensitive_data"] and _RISK_RANK[risk] < 2:
        risk = "medium"
        reasons.append("sensitive_data_floor")
    if (
        deployment["decision_role"] == "automated"
        and not deployment["human_oversight"]
        and _RISK_RANK[risk] < 3
    ):
        risk = "high"
        reasons.append("unreviewed_automated_decision_floor")
    triage = {
        "schema": CLASSIFICATION_SCHEMA,
        "method": "structured_deterministic_triage",
        "authority_profile": authority,
        "operational_risk_tier": risk,
        "operational_reasons": reasons,
        "eu_ai_act_category": "undetermined",
        "eu_ai_act_source_ref": EU_AI_ACT_METADATA["source"],
        "human_review_required": True,
        "legal_determination": False,
        "notice": NON_DETERMINATION_NOTICE,
    }
    return triage, risk_context


def _intended_use(submission: Mapping[str, Any]) -> str:
    deployment = submission["deployment_context"]
    return (
        f"{deployment['decision_role']} use in {deployment['stage']} stage for "
        f"{deployment['audience']} audiences; accountable business unit: "
        f"{submission['business_unit']}. Human oversight declared: "
        f"{str(deployment['human_oversight']).lower()}."
    )


def _assessment_answers(
    intake_id: str,
    submission: Mapping[str, Any],
) -> dict[str, dict[str, str]]:
    deployment = submission["deployment_context"]
    regulatory = submission["regulatory_context"]
    notice = deployment["transparency_notice"]
    transparency_relevant = bool(regulatory["transparency_signals"])
    if not transparency_relevant:
        transparency_answer = "na"
    elif notice == "yes":
        transparency_answer = "yes"
    elif notice == "no":
        transparency_answer = "no"
    else:
        transparency_answer = "unknown"
    note = (
        f"Generated from governed business intake {intake_id}; automated triage "
        "only and pending independent human review."
    )
    return {
        "aira_purpose": {"answer": "yes", "note": note},
        "aira_prohibited": {
            "answer": "yes" if regulatory["prohibited_signals"] else "no",
            "note": note,
        },
        "aira_high_risk": {
            "answer": (
                "yes"
                if regulatory["high_risk_domains"] or deployment["safety_critical"]
                else "no"
            ),
            "note": note,
        },
        "aira_transparency": {"answer": transparency_answer, "note": note},
        "aira_oversight": {
            "answer": "yes" if deployment["human_oversight"] else "no",
            "note": note,
        },
        "aira_bias": {"answer": "unknown", "note": note},
        "aira_accuracy": {"answer": "unknown", "note": note},
        "aira_data_governance": {"answer": "unknown", "note": note},
        "aira_security": {"answer": "unknown", "note": note},
        "aira_logging": {"answer": "unknown", "note": note},
    }


def _assessment_id(intake_id: str) -> str:
    return f"g14-{_sha256({'intake_id': intake_id})[:24]}"


def _binding(record: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "id": str(record.get("id") or record.get("asset_id") or ""),
        "revision": _revision(record.get("revision"), f"{kind} revision"),
        "status": str(record.get("status") or record.get("lifecycle") or ""),
        "record_sha256": _record_digest(record),
    }


def _leaf_count(value: object) -> int:
    if isinstance(value, Mapping):
        return sum(_leaf_count(item) for item in value.values())
    if isinstance(value, list):
        return max(1, len(value))
    return 1


def _text_character_count(value: object) -> int:
    if isinstance(value, Mapping):
        return sum(_text_character_count(item) for item in value.values())
    if isinstance(value, list):
        return sum(_text_character_count(item) for item in value)
    return len(value) if isinstance(value, str) else 0


class AIBusinessIntakeService:
    """Tenant-scoped intake authority with injectable persistence seams."""

    def __init__(
        self,
        *,
        store: GovernedRecordStore | None = None,
        model_risk: ModelRiskAssuranceOfficer | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        if monotonic is not None and not callable(monotonic):
            raise ValueError("monotonic must be callable")
        self._store = store or _INTAKES
        self._model_risk = model_risk or ModelRiskAssuranceOfficer()
        self._monotonic = monotonic or time.perf_counter

    @property
    def backend_kind(self) -> str:
        if self._store.backend_kind != self._model_risk.backend_kind:
            raise AIBusinessIntakeStateError(
                "business intake and model-risk authorities use different backends"
            )
        return self._store.backend_kind

    def _now(self) -> float:
        value = float(self._store.authoritative_time())
        if not math.isfinite(value) or value <= 0:
            raise AIBusinessIntakeStateError("business intake authority clock is invalid")
        return value

    def start(
        self,
        *,
        idempotency_key: str,
        actor: str,
        initial: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create an idempotent draft and return its safe resume projection."""

        tenant = _active_tenant()
        key = _required_text(idempotency_key, "idempotency_key", 128)
        operator = _required_text(actor, "actor", 256)
        initial_patch = {} if initial is None else _normalize_patch(initial)
        submission = _deep_merge({}, initial_patch) if initial_patch else {}
        key_sha = _sha256(key)
        intake_id = f"ABI-{key_sha[:24]}"
        request_sha = _sha256({
            "tenant": tenant,
            "idempotency_key_sha256": key_sha,
            "actor": operator,
            "initial": submission,
        })
        existing = _validate_record(self._store.get(intake_id), intake_id)
        if existing is not None:
            if existing.get("start_request_sha256") != request_sha:
                raise RecordConflict(
                    "idempotency key is already bound to a different intake request"
                )
            return self._resume_projection(existing)
        now = self._now()
        record = {
            "id": intake_id,
            "schema": INTAKE_SCHEMA,
            "status": "draft",
            "idempotency_key_sha256": key_sha,
            "start_request_sha256": request_sha,
            "submission": submission,
            "missing_fields": _missing_fields(submission),
            "started_at": now,
            "started_by": operator,
            "last_saved_at": now,
            "save_count": 0,
            "operation_receipts": [],
            "classification": None,
            "asset_binding": None,
            "declaration_binding": None,
            "assessment_binding": None,
            "burden_metrics": None,
            "human_review": {
                "required": True,
                "completed_by_intake": False,
                "legal_classification_asserted": False,
            },
            "notice": NON_DETERMINATION_NOTICE,
        }
        try:
            saved = self._store.create(
                record,
                action="start_ai_business_intake",
                actor=operator,
                max_records=_MAX_RECORDS,
            )
        except RecordConflict:
            raced = _validate_record(self._store.get(intake_id), intake_id)
            if raced is None or raced.get("start_request_sha256") != request_sha:
                raise
            saved = raced
        return self._resume_projection(saved)

    def save(
        self,
        intake_id: str,
        *,
        patch: Mapping[str, Any],
        actor: str,
        operation_id: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """Merge one conversational answer group under revision CAS."""

        _active_tenant()
        record_id = _required_text(intake_id, "intake_id", 64)
        if not _INTAKE_RE.fullmatch(record_id):
            raise ValueError("intake_id is invalid")
        operator = _required_text(actor, "actor", 256)
        expected = _revision(expected_revision)
        normalized = _normalize_patch(patch)
        operation_sha, request_sha = _receipt_fingerprint(
            "save", operation_id, normalized, operator,
        )
        current = _validate_record(self._store.get(record_id), record_id)
        if current is None:
            raise AIBusinessIntakeStateError("AI business intake does not exist")
        replay = _find_receipt(current, operation_sha)
        if replay is not None:
            if replay.get("request_sha256") != request_sha:
                raise RecordConflict("operation_id is already bound to different answers")
            return self._resume_projection(current)
        if current["status"] != "draft":
            raise AIBusinessIntakeStateError(
                "submitted AI business intake answers cannot be changed"
            )
        if current["revision"] != expected:
            raise RecordConflict(
                f"AI business intake changed (expected revision {expected}, "
                f"found {current['revision']})"
            )
        if len(current["operation_receipts"]) >= _MAX_OPERATION_RECEIPTS:
            raise AIBusinessIntakeStateError(
                "AI business intake operation history has reached its bound"
            )
        now = self._now()

        def mutate(row: dict[str, Any]) -> None:
            row["submission"] = _deep_merge(row["submission"], normalized)
            row["missing_fields"] = _missing_fields(row["submission"])
            row["last_saved_at"] = now
            row["save_count"] = int(row.get("save_count") or 0) + 1
            row["operation_receipts"].append({
                "kind": "save",
                "operation_id_sha256": operation_sha,
                "request_sha256": request_sha,
                "applied_at": now,
            })

        try:
            saved = self._store.update(
                record_id,
                mutate,
                expected_revision=expected,
                action="save_ai_business_intake",
                actor=operator,
            )
        except RecordConflict:
            raced = _validate_record(self._store.get(record_id), record_id)
            replay = _find_receipt(raced or {}, operation_sha)
            if replay is None or replay.get("request_sha256") != request_sha:
                raise
            saved = raced
        if saved is None:
            raise AIBusinessIntakeStateError("AI business intake disappeared")
        return self._resume_projection(saved)

    def _ensure_observation(
        self,
        intake_id: str,
        submission: Mapping[str, Any],
        submission_sha: str,
        actor: str,
    ) -> tuple[dict[str, Any], bool]:
        existing_asset = str(submission.get("existing_asset_id") or "")
        if existing_asset:
            observation = self._model_risk.get_observation(existing_asset)
            if observation is None:
                raise AIBusinessIntakeStateError(
                    "linked inventory asset does not exist in the active tenant"
                )
            identity = observation.get("identity") or {}
            if identity.get("asset_type") != "system":
                raise ValueError("existing_asset_id must reference a system asset")
            return observation, True

        asset_id = stable_asset_id("system", "business_intake", intake_id)
        current = self._model_risk.get_observation(asset_id)
        expected_identity = {
            "asset_type": "system",
            "source": "business_intake",
            "source_id": intake_id,
        }
        expected_metadata = {
            "intake_id": intake_id,
            "business_unit": submission["business_unit"],
            "deployment_stage": submission["deployment_context"]["stage"],
            "authority": "operator_submission",
        }
        if current is not None:
            if (
                current.get("identity") != expected_identity
                or current.get("display_name") != submission["use_case_name"]
                or current.get("version_digest") != submission_sha
                or current.get("metadata") != expected_metadata
            ):
                raise AIBusinessIntakeStateError(
                    "business-intake inventory identity is bound to different content"
                )
            return current, False
        created = self._model_risk.observe_asset(
            asset_type="system",
            source="business_intake",
            source_id=intake_id,
            display_name=submission["use_case_name"],
            version_digest=submission_sha,
            actor=actor,
            expected_revision=0,
            metadata=expected_metadata,
            dependencies=[],
        )
        return created, False

    def _ensure_declaration(
        self,
        observation: Mapping[str, Any],
        submission: Mapping[str, Any],
        classification: Mapping[str, Any],
        risk_context: Mapping[str, Any],
        actor: str,
        *,
        linked_existing_asset: bool,
    ) -> dict[str, Any]:
        asset_id = str(observation["asset_id"])
        current = self._model_risk.get_declaration(asset_id)
        if current is not None:
            if not linked_existing_asset and (
                current.get("owner") != submission["accountable_owner"]
                or current.get("purpose") != submission["purpose"]
                or current.get("risk_context") != risk_context
            ):
                raise AIBusinessIntakeStateError(
                    "business-intake declaration is bound to different content"
                )
            return current
        return self._model_risk.declare_asset(
            asset_id,
            owner=submission["accountable_owner"],
            purpose=submission["purpose"],
            intended_use=_intended_use(submission),
            actor=actor,
            risk_tier=str(classification["operational_risk_tier"]),
            lifecycle="proposed",
            risk_context=risk_context,
            # Automated triage must never fill the human assertion fields.
            eu_ai_act={"category": "undetermined"},
        )

    @staticmethod
    def _ensure_assessment(
        intake_id: str,
        submission: Mapping[str, Any],
    ) -> dict[str, Any]:
        assessment_id = _assessment_id(intake_id)
        expected_answers = _assessment_answers(intake_id, submission)
        existing = load_saved(assessment_id)
        if existing is not None:
            if (
                existing.get("type") != "aira"
                or existing.get("subject") != submission["use_case_name"]
            ):
                raise AIBusinessIntakeStateError(
                    "business-intake assessment identity is bound to different content"
                )
            answers = existing.get("answers")
            if not isinstance(answers, Mapping):
                raise AIBusinessIntakeStateError(
                    "business-intake assessment answers are malformed"
                )
            pinned_template = template_for_saved_record(existing)
            if pinned_template is None:
                raise AIBusinessIntakeStateError(
                    "business-intake assessment questionnaire is unavailable"
                )
            available = {question.id for question in pinned_template.questions}
            bound_questions = available.intersection(expected_answers)
            if not bound_questions:
                raise AIBusinessIntakeStateError(
                    "business-intake assessment lacks a governed intake binding"
                )
            for question_id in bound_questions:
                if answers.get(question_id) != expected_answers[question_id]:
                    raise AIBusinessIntakeStateError(
                        "business-intake assessment is bound to different triage"
                    )
            return existing

        session = AssessmentSession(
            type="aira",
            subject=submission["use_case_name"],
            id=assessment_id,
        )
        template = session.template()
        available = {question.id for question in template.questions}
        for question_id, answer in expected_answers.items():
            if question_id in available:
                session.record(question_id, answer["answer"], answer["note"])
        if not session.answers:
            raise AIBusinessIntakeStateError(
                "active AIRA questionnaire has no compatible intake questions"
            )
        try:
            save_session(session)
        except AssessmentConflict:
            existing = load_saved(assessment_id)
            if existing is None:
                raise
            return AIBusinessIntakeService._ensure_assessment(intake_id, submission)
        saved = load_saved(assessment_id)
        if saved is None or saved.get("status") != "pending_review":
            raise AIBusinessIntakeStateError(
                "AI risk assessment was not queued for human review"
            )
        return saved

    def submit(
        self,
        intake_id: str,
        *,
        actor: str,
        operation_id: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """Route a complete intake into inventory and independent review.

        ``submitting`` is a durable recovery state.  If the process stops after
        creating an observation, declaration, or assessment, replaying the same
        operation reconciles those deterministic artifacts and completes the
        intake without duplicating them.
        """

        _active_tenant()
        record_id = _required_text(intake_id, "intake_id", 64)
        if not _INTAKE_RE.fullmatch(record_id):
            raise ValueError("intake_id is invalid")
        operator = _required_text(actor, "actor", 256)
        expected = _revision(expected_revision)
        current = _validate_record(self._store.get(record_id), record_id)
        if current is None:
            raise AIBusinessIntakeStateError("AI business intake does not exist")
        submission = _complete_submission(current["submission"])
        submission_sha = _sha256(submission)
        operation_sha, request_sha = _receipt_fingerprint(
            "submit",
            operation_id,
            {"intake_id": record_id, "submission_sha256": submission_sha},
            operator,
        )
        operation = current.get("submission_operation")
        if current["status"] == "pending_review":
            if (
                isinstance(operation, Mapping)
                and operation.get("operation_id_sha256") == operation_sha
                and operation.get("request_sha256") == request_sha
                and operation.get("state") == "completed"
            ):
                return self._summary_projection(current)
            raise AIBusinessIntakeStateError("AI business intake is already submitted")
        if current["status"] == "submitting":
            if (
                not isinstance(operation, Mapping)
                or operation.get("operation_id_sha256") != operation_sha
                or operation.get("request_sha256") != request_sha
            ):
                raise RecordConflict(
                    "AI business intake is being submitted by a different operation"
                )
            staged = current
        else:
            if current["revision"] != expected:
                raise RecordConflict(
                    f"AI business intake changed (expected revision {expected}, "
                    f"found {current['revision']})"
                )
            classification, _ = _classification(submission)
            started_at = self._now()

            def stage(row: dict[str, Any]) -> None:
                row["status"] = "submitting"
                row["submission"] = submission
                row["missing_fields"] = []
                row["submission_sha256"] = submission_sha
                row["classification"] = classification
                row["submission_operation"] = {
                    "operation_id_sha256": operation_sha,
                    "request_sha256": request_sha,
                    "state": "in_progress",
                    "started_at": started_at,
                    "actor": operator,
                }

            staged = self._store.update(
                record_id,
                stage,
                expected_revision=expected,
                action="stage_ai_business_intake_submission",
                actor=operator,
            )
            if staged is None:
                raise AIBusinessIntakeStateError("AI business intake disappeared")

        machine_start = float(self._monotonic())
        classification, risk_context = _classification(submission)
        observation, linked_existing = self._ensure_observation(
            record_id,
            submission,
            submission_sha,
            operator,
        )
        declaration = self._ensure_declaration(
            observation,
            submission,
            classification,
            risk_context,
            operator,
            linked_existing_asset=linked_existing,
        )
        assessment = self._ensure_assessment(record_id, submission)
        machine_end = float(self._monotonic())
        if not all(math.isfinite(value) for value in (machine_start, machine_end)):
            raise AIBusinessIntakeStateError("machine processing clock is invalid")
        machine_ms = max(0, int(round((machine_end - machine_start) * 1000)))
        completed_at = self._now()
        elapsed = max(0.0, completed_at - float(staged["started_at"]))
        metrics = {
            "schema": METRICS_SCHEMA,
            "question_group_count": len(_REQUIRED_GROUPS),
            "required_leaf_field_count": len(_REQUIRED_LEAVES),
            "provided_leaf_value_count": _leaf_count(submission),
            "submitted_text_character_count": _text_character_count(submission),
            "draft_save_count": int(staged.get("save_count") or 0),
            "machine_processing_ms": machine_ms,
            "system_observed_session_elapsed_seconds": round(elapsed, 3),
            "measurement_scope": "machine_processing_and_field_burden_only",
            "human_completion_verified": False,
            "under_three_minutes_claimed": False,
            "usability_benchmark_status": "not_evaluated",
        }
        staged_revision = _revision(staged.get("revision"), "staged revision")

        def finalize(row: dict[str, Any]) -> None:
            active = row.get("submission_operation")
            if (
                not isinstance(active, dict)
                or active.get("operation_id_sha256") != operation_sha
                or active.get("request_sha256") != request_sha
            ):
                raise RecordConflict("AI business intake submission authority changed")
            active["state"] = "completed"
            active["completed_at"] = completed_at
            row["status"] = "pending_review"
            row["classification"] = classification
            row["asset_binding"] = {
                **_binding(observation, kind="model_risk_observation"),
                "asset_id": observation["asset_id"],
                "linked_existing": linked_existing,
                "version_digest": observation["version_digest"],
            }
            row["declaration_binding"] = {
                **_binding(declaration, kind="model_risk_declaration"),
                "asset_id": declaration["asset_id"],
                "review_required": declaration.get("review") is None,
            }
            row["assessment_binding"] = {
                **_binding(assessment, kind="aira_assessment"),
                "assessment_id": assessment["id"],
                "human_decision_required": assessment.get("status") == "pending_review",
            }
            row["burden_metrics"] = metrics
            row["submitted_at"] = completed_at
            row["submitted_by"] = operator
            row["human_review"] = {
                "required": True,
                "completed_by_intake": False,
                "legal_classification_asserted": False,
                "declaration_status_at_routing": declaration.get("status"),
                "assessment_status_at_routing": assessment.get("status"),
            }

        try:
            saved = self._store.update(
                record_id,
                finalize,
                expected_revision=staged_revision,
                action="route_ai_business_intake_for_review",
                actor=operator,
            )
        except RecordConflict:
            raced = _validate_record(self._store.get(record_id), record_id)
            active = (raced or {}).get("submission_operation")
            if not (
                raced
                and raced.get("status") == "pending_review"
                and isinstance(active, Mapping)
                and active.get("operation_id_sha256") == operation_sha
                and active.get("request_sha256") == request_sha
                and active.get("state") == "completed"
            ):
                raise
            saved = raced
        if saved is None:
            raise AIBusinessIntakeStateError("AI business intake disappeared")
        return self._summary_projection(saved)

    def get(self, intake_id: str, *, include_submission: bool = False) -> dict[str, Any] | None:
        """Return a safe tenant-local summary or resume projection."""

        _active_tenant()
        record_id = _required_text(intake_id, "intake_id", 64)
        if not _INTAKE_RE.fullmatch(record_id):
            raise ValueError("intake_id is invalid")
        record = _validate_record(self._store.get(record_id), record_id)
        if record is None:
            return None
        return (
            self._resume_projection(record)
            if include_submission
            else self._summary_projection(record)
        )

    def list(self) -> list[dict[str, Any]]:
        """Return bounded safe summaries for the active tenant only."""

        _active_tenant()
        rows = self._store.list(limit=_MAX_RECORDS + 1)
        if len(rows) > _MAX_RECORDS:
            raise AIBusinessIntakeStateError(
                f"AI business intake exceeds the {_MAX_RECORDS}-record operational limit"
            )
        validated = [_validate_record(row, str(row.get("id") or "")) for row in rows]
        return sorted(
            [self._summary_projection(row) for row in validated if row is not None],
            key=lambda row: (float(row.get("started_at") or 0), str(row.get("id"))),
            reverse=True,
        )

    @staticmethod
    def _summary_projection(record: Mapping[str, Any]) -> dict[str, Any]:
        submission = record.get("submission") or {}
        classification = record.get("classification")
        triage = None
        if isinstance(classification, Mapping):
            authority = classification.get("authority_profile") or {}
            triage = {
                "schema": classification.get("schema"),
                "operational_risk_tier": classification.get("operational_risk_tier"),
                "screening_level": authority.get("screening_level"),
                "screening_reasons": authority.get("screening_reasons"),
                "eu_ai_act_category": classification.get("eu_ai_act_category"),
                "human_review_required": True,
                "legal_determination": False,
                "notice": NON_DETERMINATION_NOTICE,
            }
        return {
            "id": record.get("id"),
            "schema": record.get("schema"),
            "status": record.get("status"),
            "revision": record.get("revision"),
            "use_case_name": submission.get("use_case_name", ""),
            "accountable_owner": submission.get("accountable_owner", ""),
            "business_unit": submission.get("business_unit", ""),
            "progress": {
                "question_group_count": len(_REQUIRED_GROUPS),
                "required_leaf_field_count": len(_REQUIRED_LEAVES),
                "missing_fields": list(record.get("missing_fields") or []),
            },
            "classification": triage,
            "asset_binding": record.get("asset_binding"),
            "declaration_binding": record.get("declaration_binding"),
            "assessment_binding": record.get("assessment_binding"),
            "burden_metrics": record.get("burden_metrics"),
            "human_review": record.get("human_review"),
            "started_at": record.get("started_at"),
            "submitted_at": record.get("submitted_at"),
            "notice": NON_DETERMINATION_NOTICE,
        }

    @staticmethod
    def _resume_projection(record: Mapping[str, Any]) -> dict[str, Any]:
        return {
            **AIBusinessIntakeService._summary_projection(record),
            "submission": json.loads(
                json.dumps(record.get("submission") or {}, ensure_ascii=False)
            ),
            "save_count": int(record.get("save_count") or 0),
            "last_saved_at": record.get("last_saved_at"),
        }


def enabled() -> bool:
    """True only when the deployment opts into G14 and its authorities."""

    try:
        from . import model_risk_assurance
        from .config import config_source_errors, load_global_config

        config = load_global_config()
        if config_source_errors(include_tenant=False) or not isinstance(config, dict):
            return False
        section = config.get("ai_business_intake")
        return bool(
            isinstance(section, dict)
            and section.get("enable") is True
            and model_risk_assurance.enabled()
        )
    except Exception:
        return False


def require_enabled() -> None:
    if not enabled():
        raise AIBusinessIntakeConfigError(
            "AI business intake is disabled or its model-risk dependency is unavailable"
        )


_DEFAULT = AIBusinessIntakeService()


def start_intake(**kwargs: Any) -> dict[str, Any]:
    require_enabled()
    return _DEFAULT.start(**kwargs)


def save_intake(intake_id: str, **kwargs: Any) -> dict[str, Any]:
    require_enabled()
    return _DEFAULT.save(intake_id, **kwargs)


def submit_intake(intake_id: str, **kwargs: Any) -> dict[str, Any]:
    require_enabled()
    return _DEFAULT.submit(intake_id, **kwargs)


def get_intake(intake_id: str, *, include_submission: bool = False) -> dict[str, Any] | None:
    require_enabled()
    return _DEFAULT.get(intake_id, include_submission=include_submission)


def list_intakes() -> list[dict[str, Any]]:
    require_enabled()
    return _DEFAULT.list()


__all__ = [
    "AIBusinessIntakeConfigError",
    "AIBusinessIntakeError",
    "AIBusinessIntakeService",
    "AIBusinessIntakeStateError",
    "CLASSIFICATION_SCHEMA",
    "INTAKE_SCHEMA",
    "METRICS_SCHEMA",
    "NON_DETERMINATION_NOTICE",
    "enabled",
    "form_contract",
    "get_intake",
    "list_intakes",
    "require_enabled",
    "save_intake",
    "start_intake",
    "submit_intake",
]
