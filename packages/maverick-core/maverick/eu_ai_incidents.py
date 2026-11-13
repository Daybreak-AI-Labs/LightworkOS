"""Governed EU AI Act Article 73 serious-incident reporting records.

This module turns the reporting clock and filing lifecycle into deterministic,
tenant-scoped records.  It does *not* decide whether the AI Act applies, make a
legal conclusion, identify a competent authority, or transmit a report.  Those
are authenticated-human decisions recorded through :class:`HumanAuthority`.

The clock rules are drawn from the official consolidated Regulation (EU)
2024/1689, Article 73 and the Article 3(49) definition as available on
2026-08-28:

* https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng
* https://eur-lex.europa.eu/eli/reg/2024/1689/art_73/oj

Article 73 sets an outer limit of 15 days from awareness, shortened to two days
for a widespread infringement or Article 3(49)(b) critical-infrastructure
incident, and to 10 days for death.  The Act also says reporting is immediate
in the circumstances specified there.  This module preserves that qualitative
requirement rather than replacing it with the outer-limit timestamp.  When
categories overlap it selects the earliest outer limit.  It intentionally does
not reuse the GDPR Article 33 72-hour clock.

Because Article 73 expresses the limits in days, the timestamp uses a recorded
IANA timezone and the base calendar-period rules in Regulation 1182/71 rather
than aliasing two days to 48 hours.  The clock deliberately does not guess a
Member State's public-holiday calendar or authority procedure; every projection
therefore retains ``authority_calendar_confirmation_required=True``.

The European Commission published a draft high-risk-system reporting template
for consultation on 2025-09-26.  ``report_template`` and the bounded payload
below are an internal operational shape informed by that material, not a claim
that Lightwork reproduces a final regulator form:

* https://digital-strategy.ec.europa.eu/en/consultations/ai-act-commission-issues-draft-guidance-and-reporting-template-serious-ai-incidents-and-seeks

This is compliance decision support, not legal advice.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import time as datetime_time
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

INCIDENT_SCHEMA = "lightwork.eu-ai-act-article-73-incident.v1"
REPORT_SCHEMA = "lightwork.eu-ai-act-article-73-report.v1"
SAFE_PROJECTION_SCHEMA = "lightwork.eu-ai-act-article-73-safe-projection.v1"
ARTICLE_73_SOURCE_URL = (
    "https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng"
)
COMMISSION_TEMPLATE_SOURCE_URL = (
    "https://digital-strategy.ec.europa.eu/en/consultations/"
    "ai-act-commission-issues-draft-guidance-and-reporting-template-"
    "serious-ai-incidents-and-seeks"
)
PERIOD_CALCULATION_SOURCE_URL = "https://eur-lex.europa.eu/eli/reg/1971/1182/oj/eng"
NON_LEGAL_NOTICE = (
    "Human-reviewed compliance decision support; not legal advice, an "
    "applicability determination, a regulator filing, or proof of compliance."
)


def enabled() -> bool:
    """Return whether the tenant's explicit Article 73 workflow gate is on."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("eu_ai_incidents")
    return isinstance(section, Mapping) and section.get("enable") is True

_INCIDENTS = GovernedRecordStore(
    "eu_ai_article_73_incidents",
    "A73",
    "eu_ai_article_73_incident",
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_DISALLOWED_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_INCIDENT_ID_RE = re.compile(r"A73-[A-Za-z0-9_-]{1,59}\Z")
_REPORT_ID_RE = re.compile(r"A73R-[0-9a-f]{24}\Z")
_TENANT_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")

_MAX_INCIDENTS = 5_000
_MAX_LIST_LIMIT = 500
_MAX_REPORTS = 64
_MAX_ROUTING_DECISIONS = 16
_MAX_EVIDENCE_REFS = 128
_MAX_AUTHORITIES = 64
_MAX_MEMBER_STATES = 27
_MAX_RELATED_REPORTS = 64
_MAX_MISSING_FIELDS = 32

_EU_MEMBER_STATES = frozenset({
    "AT", "BE", "BG", "HR", "CY", "CZ", "DE", "DK", "EE", "EL", "ES",
    "FI", "FR", "HU", "IE", "IT", "LT", "LU", "LV", "MT", "NL", "PL",
    "PT", "RO", "SE", "SI", "SK",
})
_OUTCOMES = frozenset({
    "death",
    "serious_harm_to_health",
    "critical_infrastructure_irreversible_disruption",
    "fundamental_rights_obligations_infringement",
    "serious_property_or_environment_harm",
})
_CAUSALITY = frozenset({
    "not_assessed",
    "suspected",
    "reasonable_likelihood",
    "established",
    "not_supported",
})
_TRISTATE = frozenset({"yes", "no", "unknown"})
_OPERATOR_ROLES = frozenset({"provider", "deployer", "unknown"})
_AUTHORITY_ROLES = frozenset({
    "authorized_provider_representative",
    "incident_commander",
    "legal_counsel",
    "regulatory_compliance_officer",
    "safety_officer",
})
_EXTERNAL_DECISION_ROLES = frozenset({
    "authorized_provider_representative",
    "legal_counsel",
    "regulatory_compliance_officer",
})
_ROUTING_DECISIONS = frozenset({
    "report_to_authority",
    "do_not_report",
    "legal_review_required",
})
_THRESHOLD_DETERMINATIONS = frozenset({"met", "not_met", "uncertain"})
_APPLICABILITY_DETERMINATIONS = frozenset({
    "applies", "does_not_apply", "uncertain",
})
_REPORT_KINDS = frozenset({"initial", "update", "final"})
_REPORT_STATUSES = frozenset({"draft", "approved", "submitted"})
_INVESTIGATION_STATUSES = frozenset({
    "not_started", "ongoing", "completed", "unknown",
})
_SYSTEM_OPERATOR_TYPES = frozenset({"professional_user", "other", "unknown"})
_FINAL_REPORTABILITY = frozenset({"reportable", "non_reportable", "undetermined"})
_REVIEW_STATES = frozenset({"yes", "no", "unknown"})
_ADEQUACY_STATES = frozenset({"yes", "no", "not_applicable", "unknown"})
_MISSING_FIELD_NAMES = frozenset({
    "affected_member_states",
    "causal_assessment_summary",
    "consequences",
    "contact_reference",
    "corrective_actions",
    "detected_at",
    "expected_next_report_at",
    "incident_occurred_at",
    "initial_reporter_contact_reference",
    "investigation_summary",
    "provider_organization_reference",
    "risk_assessment_results",
    "root_cause_conclusion",
    "submitter_contact_reference",
    "system_name",
    "system_purpose",
})
_REPORT_DETAIL_FIELDS = frozenset({
    "attestation_accepted",
    "authorized_representative_reference",
    "causal_assessment_summary",
    "catalogue_reference",
    "consequences",
    "contact_reference",
    "corrective_actions",
    "detected_at",
    "estimated_users_affected",
    "eu_database_registration_id",
    "expected_next_report_at",
    "final_reportability_conclusion",
    "firmware_version",
    "incident_occurred_at",
    "initial_reporter_contact_reference",
    "investigation_status",
    "investigation_summary",
    "known_missing_fields",
    "lot_batch_number",
    "other_regulatory_report_references",
    "planned_investigations",
    "preservation_actions",
    "provider_organization_reference",
    "related_report_references",
    "risk_assessment_results",
    "risk_assessment_reviewed",
    "risk_assessment_still_adequate",
    "root_cause_conclusion",
    "serial_number",
    "software_version",
    "submitter_contact_reference",
    "system_model",
    "system_name",
    "system_operator_type",
    "system_purpose",
})
_FINAL_REQUIRED_TEXT = (
    "causal_assessment_summary",
    "consequences",
    "contact_reference",
    "corrective_actions",
    "investigation_summary",
    "provider_organization_reference",
    "risk_assessment_results",
    "root_cause_conclusion",
    "submitter_contact_reference",
    "system_name",
    "system_purpose",
)
_RECORD_FIELDS = frozenset({
    "_audit_pending",
    "asserted_high_risk",
    "asserted_union_market",
    "asset_id",
    "asset_version",
    "awareness_at",
    "causality",
    "clock",
    "created_at",
    "evidence_refs",
    "id",
    "incident_member_states",
    "legal_source_url",
    "notice",
    "occurred_at",
    "operator_role",
    "outcomes",
    "reports",
    "revision",
    "routing_history",
    "schema",
    "status",
    "summary",
    "tenant_sha256",
    "title",
    "updated_at",
    "widespread_infringement",
})
_REPORT_FIELDS = frozenset({
    "actor_type",
    "approval",
    "id",
    "kind",
    "payload",
    "payload_sha256",
    "prepared_at",
    "prepared_by",
    "sequence",
    "status",
    "submission",
})
_APPROVAL_FIELDS = frozenset({
    "actor_type",
    "approved_at",
    "approved_by",
    "authority_role",
    "payload_sha256",
})
_SUBMISSION_FIELDS = frozenset({
    "actor_type",
    "authority_refs",
    "authority_role",
    "receipt_sha256",
    "submission_reference",
    "submitted_at",
    "submitted_by",
})


class Article73Error(RuntimeError):
    """Base failure for the Article 73 incident register."""


class Article73StateError(Article73Error):
    """A persisted record or requested lifecycle transition is invalid."""


class Article73ConfigurationError(Article73Error):
    """The explicit Article 73 feature gate is unavailable or disabled."""


def _require_enabled() -> None:
    if not enabled():
        raise Article73ConfigurationError(
            "EU AI Act incident reporting is disabled; set "
            "[eu_ai_incidents].enable = true"
        )


@dataclass(frozen=True)
class HumanAuthority:
    """Authenticated human principal and the authority used for a decision.

    API adapters must construct this only after authenticating the user and
    authorizing the recorded role.  Requiring Lightwork's ``user:`` principal
    form prevents a scheduler, agent, or service label from crossing the core
    filing boundary by accident.
    """

    principal: str
    role: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "principal", _human_principal(self.principal))
        role = _identity(self.role, "authority role").lower()
        if role not in _AUTHORITY_ROLES:
            raise ValueError("authority role is not approved for Article 73 records")
        object.__setattr__(self, "role", role)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("value is not bounded canonical JSON") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _identity(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not _ID_RE.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _text(
    value: object,
    label: str,
    limit: int,
    *,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if (
        (not text and not allow_empty)
        or len(text) > limit
        or _DISALLOWED_CONTROL_RE.search(text)
    ):
        raise ValueError(f"{label} is invalid")
    return text


def _enum(value: object, label: str, allowed: frozenset[str]) -> str:
    text = _text(value, label, 80).lower()
    if text not in allowed:
        raise ValueError(f"{label} is unsupported")
    return text


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a Unix timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"{label} must be a positive Unix timestamp")
    return result


def _optional_timestamp(value: object, label: str) -> float | None:
    if value is None:
        return None
    return _timestamp(value, label)


def _optional_nonnegative_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 1_000_000_000_000
    ):
        raise ValueError(f"{label} must be a bounded non-negative integer")
    return value


def _calendar_timezone(value: object) -> str:
    name = _text(value, "calendar_timezone", 128)
    try:
        zone = ZoneInfo(name)
    except (ValueError, ZoneInfoNotFoundError) as exc:
        raise ValueError("calendar_timezone must be an installed IANA zone") from exc
    return str(zone.key)


def _base_calendar_limit_at(
    awareness_at: float,
    days: int,
    calendar_timezone: str,
) -> tuple[float, str]:
    """Return the last second of the unextended Nth local calendar day.

    Regulation 1182/71 excludes the event day and generally measures a period
    in days through the last hour of its final day.  Weekend/public-holiday
    extensions and authority-specific procedure still require human legal
    confirmation, so this is deliberately the earlier *base* calendar limit.
    """

    zone = ZoneInfo(calendar_timezone)
    awareness_local = datetime.fromtimestamp(awareness_at, tz=zone)
    limit_date = awareness_local.date() + timedelta(days=days)
    next_midnight = datetime.combine(
        limit_date + timedelta(days=1),
        datetime_time.min,
        tzinfo=zone,
    )
    return next_midnight.timestamp() - 1.0, limit_date.isoformat()


def _expected_revision(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("expected_revision must be a positive integer")
    return value


def _human_principal(value: object) -> str:
    principal = _text(value, "human principal", 4_096)
    if not principal.startswith("user:"):
        raise ValueError("human principal must be an authenticated user: identity")
    subject = principal.removeprefix("user:")
    try:
        from .oidc import validate_subject

        validate_subject(subject)
    except (TypeError, ValueError) as exc:
        raise ValueError("human principal has an invalid authenticated subject") from exc
    return principal


def _require_exact_fields(
    value: Mapping[str, Any],
    allowed: frozenset[str],
    label: str,
) -> None:
    extras = set(value) - allowed
    missing = allowed - {"_audit_pending"} - set(value)
    if extras or missing:
        raise Article73StateError(f"{label} fields are malformed")


def _principal_sha256(principal: str) -> str:
    return hashlib.sha256(principal.encode("utf-8")).hexdigest()


def _require_tenant() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if not tenant:
        raise Article73StateError(
            "Article 73 incident records require an explicit tenant authority"
        )
    return tenant


def _tenant_sha256() -> str:
    return hashlib.sha256(_require_tenant().encode("utf-8")).hexdigest()


def _outcomes(values: object) -> list[str]:
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise ValueError("outcomes must be a bounded list")
    if len(values) > len(_OUTCOMES):
        raise ValueError("outcomes contains too many values")
    normalized = sorted({_enum(item, "outcome", _OUTCOMES) for item in values})
    return normalized


def _member_states(values: object, *, allow_empty: bool = True) -> list[str]:
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise ValueError("member states must be a bounded list")
    if len(values) > _MAX_MEMBER_STATES:
        raise ValueError("member states exceeds the EU Member State limit")
    normalized = sorted({str(value or "").strip().upper() for value in values})
    if any(value not in _EU_MEMBER_STATES for value in normalized):
        raise ValueError("member states must use current EU two-letter codes")
    if not allow_empty and not normalized:
        raise ValueError("at least one incident Member State is required")
    return normalized


def _identities(
    values: object,
    label: str,
    *,
    limit: int,
    allow_empty: bool = True,
) -> list[str]:
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise ValueError(f"{label} must be a bounded list")
    if len(values) > limit:
        raise ValueError(f"{label} exceeds {limit} values")
    normalized = sorted({_identity(value, label) for value in values})
    if not allow_empty and not normalized:
        raise ValueError(f"{label} requires at least one value")
    return normalized


def _evidence_refs(values: object) -> list[dict[str, str]]:
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise ValueError("evidence_refs must be a bounded list")
    if len(values) > _MAX_EVIDENCE_REFS:
        raise ValueError("evidence_refs exceeds its record limit")
    normalized: dict[str, dict[str, str]] = {}
    for value in values:
        if not isinstance(value, Mapping):
            raise ValueError("each evidence reference must be an object")
        unknown = set(value) - {"id", "sha256"}
        if unknown:
            raise ValueError("evidence reference contains unsupported fields")
        reference_id = _identity(value.get("id"), "evidence id")
        digest = str(value.get("sha256") or "").strip().lower().removeprefix("sha256:")
        if not _DIGEST_RE.fullmatch(digest):
            raise ValueError("evidence sha256 must be a SHA-256 digest")
        candidate = {"id": reference_id, "sha256": digest}
        previous = normalized.get(reference_id)
        if previous is not None and previous != candidate:
            raise ValueError("an evidence id cannot bind two digests")
        normalized[reference_id] = candidate
    return [normalized[key] for key in sorted(normalized)]


def _clock(
    awareness_at: float,
    outcomes: Sequence[str],
    widespread_infringement: bool,
    causality: str,
    calendar_timezone: str,
) -> dict[str, Any]:
    """Return the earliest Article 73 awareness-anchored outer limit."""

    candidates: list[tuple[int, str]] = [(15, "article_73_paragraph_2")]
    reasons = ["general_outer_limit"]
    if (
        widespread_infringement
        or "critical_infrastructure_irreversible_disruption" in outcomes
    ):
        candidates.append((2, "article_73_paragraph_3"))
        if widespread_infringement:
            reasons.append("widespread_infringement")
        if "critical_infrastructure_irreversible_disruption" in outcomes:
            reasons.append("article_3_49_b_critical_infrastructure")
    if "death" in outcomes:
        candidates.append((10, "article_73_paragraph_4"))
        reasons.append("death")
    days, rule = min(candidates, key=lambda item: item[0])
    if rule == "article_73_paragraph_3":
        immediate_trigger = "awareness"
        immediate_ready = bool(widespread_infringement or outcomes)
    elif rule == "article_73_paragraph_4":
        immediate_trigger = "causal_link_suspected_or_established"
        immediate_ready = causality in {"suspected", "established"}
    else:
        immediate_trigger = "causal_link_established_or_reasonably_likely"
        immediate_ready = causality in {"reasonable_likelihood", "established"}
    outer_limit_at, outer_limit_local_date = _base_calendar_limit_at(
        awareness_at,
        days,
        calendar_timezone,
    )
    return {
        "anchor": "awareness",
        "awareness_at": awareness_at,
        "outer_limit_days": days,
        "outer_limit_at": outer_limit_at,
        "outer_limit_local_date": outer_limit_local_date,
        "calendar_timezone": calendar_timezone,
        "period_calculation_source_url": PERIOD_CALCULATION_SOURCE_URL,
        "authority_calendar_confirmation_required": True,
        "rule": rule,
        "priority_reasons": sorted(set(reasons)),
        "timing": "immediately_when_article_73_trigger_is_met_with_outer_limit",
        "immediate_trigger": immediate_trigger,
        "immediate_trigger_ready": immediate_ready,
        "source_url": ARTICLE_73_SOURCE_URL,
        "not_gdpr_72_hours": True,
    }


def calculate_article_73_clock(
    awareness_at: float,
    *,
    outcomes: Sequence[str] = (),
    widespread_infringement: bool = False,
    causality: str = "not_assessed",
    calendar_timezone: str = "UTC",
) -> dict[str, Any]:
    """Calculate an operational outer-limit projection from official rules.

    This is arithmetic, not an applicability or causation determination.  The
    caller must have a human confirm the incident facts and competent route.
    """

    awareness = _timestamp(awareness_at, "awareness_at")
    normalized_outcomes = _outcomes(outcomes)
    if not isinstance(widespread_infringement, bool):
        raise ValueError("widespread_infringement must be a boolean")
    causal_state = _enum(causality, "causality", _CAUSALITY)
    zone_name = _calendar_timezone(calendar_timezone)
    # A record carries the notice beside its embedded clock; a bare clock
    # returned to a caller has to carry it itself.
    return {
        **_clock(
            awareness,
            normalized_outcomes,
            widespread_infringement,
            causal_state,
            zone_name,
        ),
        "notice": NON_LEGAL_NOTICE,
    }


def report_template(kind: str = "initial") -> dict[str, Any]:
    """Return a blank, bounded internal template for a human-prepared report."""

    report_kind = _enum(kind, "report kind", _REPORT_KINDS)
    return {
        "schema": REPORT_SCHEMA,
        "kind": report_kind,
        "template_status": "lightwork_internal_informed_by_commission_draft",
        "legal_source_url": ARTICLE_73_SOURCE_URL,
        "commission_draft_template_url": COMMISSION_TEMPLATE_SOURCE_URL,
        "fields": {
            "eu_database_registration_id": "",
            "system_name": "",
            "system_model": "",
            "catalogue_reference": "",
            "serial_number": "",
            "lot_batch_number": "",
            "software_version": "",
            "firmware_version": "",
            "system_purpose": "",
            "incident_occurred_at": None,
            "detected_at": None,
            "expected_next_report_at": None,
            "estimated_users_affected": None,
            "system_operator_type": "unknown",
            "causal_assessment_summary": "",
            "consequences": "",
            "investigation_status": "unknown",
            "investigation_summary": "",
            "planned_investigations": "",
            "root_cause_conclusion": "",
            "corrective_actions": "",
            "preservation_actions": "",
            "risk_assessment_reviewed": "unknown",
            "risk_assessment_still_adequate": "unknown",
            "risk_assessment_results": "",
            "final_reportability_conclusion": "undetermined",
            "provider_organization_reference": "",
            "authorized_representative_reference": "",
            "submitter_contact_reference": "",
            "initial_reporter_contact_reference": "",
            "contact_reference": "",
            "related_report_references": [],
            "other_regulatory_report_references": [],
            "known_missing_fields": [],
            "attestation_accepted": False,
        },
        "final_required_text_fields": list(_FINAL_REQUIRED_TEXT),
        "notice": NON_LEGAL_NOTICE,
    }


def _report_id(incident_id: str, sequence: int, tenant_sha256: str) -> str:
    material = [incident_id, sequence, tenant_sha256]
    return f"A73R-{_sha256(material)[:24]}"


def _normalize_report_payload(
    incident: Mapping[str, Any],
    kind: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(details, Mapping):
        raise ValueError("report details must be an object")
    unknown = set(details) - _REPORT_DETAIL_FIELDS
    if unknown:
        raise ValueError(
            "report details contains unsupported fields: "
            + ", ".join(sorted(unknown))
        )
    report_kind = _enum(kind, "report kind", _REPORT_KINDS)
    occurred = _optional_timestamp(
        details.get("incident_occurred_at", incident.get("occurred_at")),
        "incident_occurred_at",
    )
    if occurred is not None and occurred > float(incident["awareness_at"]):
        raise ValueError("incident_occurred_at cannot be after awareness_at")
    detected = _optional_timestamp(details.get("detected_at"), "detected_at")
    if detected is not None and detected > float(incident["awareness_at"]):
        raise ValueError("detected_at cannot be after awareness_at")
    expected_next = _optional_timestamp(
        details.get("expected_next_report_at"),
        "expected_next_report_at",
    )
    if expected_next is not None and expected_next <= float(incident["awareness_at"]):
        raise ValueError("expected_next_report_at must be after awareness_at")
    if report_kind == "final" and expected_next is not None:
        raise ValueError("a final report cannot schedule another report")
    investigation_status = _enum(
        details.get("investigation_status", "unknown"),
        "investigation_status",
        _INVESTIGATION_STATUSES,
    )
    missing = _identities(
        details.get("known_missing_fields") or (),
        "known_missing_fields",
        limit=_MAX_MISSING_FIELDS,
    )
    if any(item not in _MISSING_FIELD_NAMES for item in missing):
        raise ValueError("known_missing_fields contains an unsupported field")
    related = _identities(
        details.get("related_report_references") or (),
        "related_report_references",
        limit=_MAX_RELATED_REPORTS,
    )
    other_regulatory = _identities(
        details.get("other_regulatory_report_references") or (),
        "other_regulatory_report_references",
        limit=_MAX_RELATED_REPORTS,
    )
    attestation = details.get("attestation_accepted", False)
    if not isinstance(attestation, bool):
        raise ValueError("attestation_accepted must be a boolean")
    payload = {
        "schema": REPORT_SCHEMA,
        "kind": report_kind,
        "incident_id": incident["id"],
        "asset_id": incident["asset_id"],
        "asset_version": incident["asset_version"],
        "operator_role": incident["operator_role"],
        "asserted_high_risk": incident["asserted_high_risk"],
        "asserted_union_market": incident["asserted_union_market"],
        "incident_member_states": list(incident["incident_member_states"]),
        "authority_refs": list(incident["routing_history"][-1]["authority_refs"]),
        "awareness_at": incident["awareness_at"],
        "incident_occurred_at": occurred,
        "detected_at": detected,
        "expected_next_report_at": expected_next,
        "outcomes": list(incident["outcomes"]),
        "widespread_infringement": incident["widespread_infringement"],
        "causality": incident["causality"],
        "incident_summary": incident["summary"],
        "eu_database_registration_id": _text(
            details.get("eu_database_registration_id", ""),
            "eu_database_registration_id",
            256,
            allow_empty=True,
        ),
        "system_name": _text(
            details.get("system_name", ""),
            "system_name",
            1_000,
            allow_empty=True,
        ),
        "system_model": _text(
            details.get("system_model", ""),
            "system_model",
            1_000,
            allow_empty=True,
        ),
        "catalogue_reference": _text(
            details.get("catalogue_reference", ""),
            "catalogue_reference",
            256,
            allow_empty=True,
        ),
        "serial_number": _text(
            details.get("serial_number", ""),
            "serial_number",
            256,
            allow_empty=True,
        ),
        "lot_batch_number": _text(
            details.get("lot_batch_number", ""),
            "lot_batch_number",
            256,
            allow_empty=True,
        ),
        "software_version": _text(
            details.get("software_version", incident["asset_version"]),
            "software_version",
            256,
            allow_empty=True,
        ),
        "firmware_version": _text(
            details.get("firmware_version", ""),
            "firmware_version",
            256,
            allow_empty=True,
        ),
        "system_purpose": _text(
            details.get("system_purpose", ""),
            "system_purpose",
            4_000,
            allow_empty=True,
        ),
        "causal_assessment_summary": _text(
            details.get("causal_assessment_summary", ""),
            "causal_assessment_summary",
            8_000,
            allow_empty=True,
        ),
        "consequences": _text(
            details.get("consequences", ""),
            "consequences",
            8_000,
            allow_empty=True,
        ),
        "estimated_users_affected": _optional_nonnegative_integer(
            details.get("estimated_users_affected"),
            "estimated_users_affected",
        ),
        "system_operator_type": _enum(
            details.get("system_operator_type", "unknown"),
            "system_operator_type",
            _SYSTEM_OPERATOR_TYPES,
        ),
        "investigation_status": investigation_status,
        "investigation_summary": _text(
            details.get("investigation_summary", ""),
            "investigation_summary",
            12_000,
            allow_empty=True,
        ),
        "planned_investigations": _text(
            details.get("planned_investigations", ""),
            "planned_investigations",
            12_000,
            allow_empty=True,
        ),
        "root_cause_conclusion": _text(
            details.get("root_cause_conclusion", ""),
            "root_cause_conclusion",
            12_000,
            allow_empty=True,
        ),
        "corrective_actions": _text(
            details.get("corrective_actions", ""),
            "corrective_actions",
            12_000,
            allow_empty=True,
        ),
        "preservation_actions": _text(
            details.get("preservation_actions", ""),
            "preservation_actions",
            8_000,
            allow_empty=True,
        ),
        "risk_assessment_reviewed": _enum(
            details.get("risk_assessment_reviewed", "unknown"),
            "risk_assessment_reviewed",
            _REVIEW_STATES,
        ),
        "risk_assessment_still_adequate": _enum(
            details.get("risk_assessment_still_adequate", "unknown"),
            "risk_assessment_still_adequate",
            _ADEQUACY_STATES,
        ),
        "risk_assessment_results": _text(
            details.get("risk_assessment_results", ""),
            "risk_assessment_results",
            12_000,
            allow_empty=True,
        ),
        "final_reportability_conclusion": _enum(
            details.get("final_reportability_conclusion", "undetermined"),
            "final_reportability_conclusion",
            _FINAL_REPORTABILITY,
        ),
        "provider_organization_reference": _text(
            details.get("provider_organization_reference", ""),
            "provider_organization_reference",
            256,
            allow_empty=True,
        ),
        "authorized_representative_reference": _text(
            details.get("authorized_representative_reference", ""),
            "authorized_representative_reference",
            256,
            allow_empty=True,
        ),
        "submitter_contact_reference": _text(
            details.get("submitter_contact_reference", ""),
            "submitter_contact_reference",
            256,
            allow_empty=True,
        ),
        "initial_reporter_contact_reference": _text(
            details.get("initial_reporter_contact_reference", ""),
            "initial_reporter_contact_reference",
            256,
            allow_empty=True,
        ),
        "contact_reference": _text(
            details.get("contact_reference", ""),
            "contact_reference",
            256,
            allow_empty=True,
        ),
        "related_report_references": related,
        "other_regulatory_report_references": other_regulatory,
        "known_missing_fields": missing,
        "attestation_accepted": attestation,
        "legal_source_url": ARTICLE_73_SOURCE_URL,
        "template_source_url": COMMISSION_TEMPLATE_SOURCE_URL,
        "template_status": "lightwork_internal_informed_by_commission_draft",
        "notice": NON_LEGAL_NOTICE,
    }
    if report_kind == "final":
        if missing:
            raise Article73StateError("a final report cannot declare missing fields")
        absent = [field for field in _FINAL_REQUIRED_TEXT if not payload[field]]
        if absent:
            raise Article73StateError(
                "a final report is incomplete: " + ", ".join(absent)
            )
        if payload["attestation_accepted"] is not True:
            raise Article73StateError(
                "a final report requires the human accuracy attestation"
            )
        if payload["final_reportability_conclusion"] == "undetermined":
            raise Article73StateError(
                "a final report requires a reportability conclusion"
            )
        if payload["risk_assessment_reviewed"] == "unknown":
            raise Article73StateError(
                "a final report must record whether the risk assessment was reviewed"
            )
    return payload


def _validate_report_payload(
    payload: object,
    incident: Mapping[str, Any],
    kind: str,
) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise Article73StateError("Article 73 report payload is malformed")
    details = {
        key: payload.get(key)
        for key in _REPORT_DETAIL_FIELDS
        if key in payload
    }
    try:
        expected = _normalize_report_payload(incident, kind, details)
    except (TypeError, ValueError, Article73StateError) as exc:
        raise Article73StateError("Article 73 report payload is malformed") from exc
    if dict(payload) != expected:
        raise Article73StateError("Article 73 report payload binding is invalid")
    return expected


def _validate_clock(record: Mapping[str, Any]) -> dict[str, Any]:
    try:
        expected = _clock(
            float(record["awareness_at"]),
            list(record["outcomes"]),
            bool(record["widespread_infringement"]),
            str(record["causality"]),
            _calendar_timezone(record["clock"]["calendar_timezone"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise Article73StateError("Article 73 clock inputs are malformed") from exc
    if record.get("clock") != expected:
        raise Article73StateError("Article 73 clock binding is invalid")
    return expected


def _validate_routing_history(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > _MAX_ROUTING_DECISIONS:
        raise Article73StateError("Article 73 routing history is malformed")
    normalized: list[dict[str, Any]] = []
    terminal_seen = False
    for index, item in enumerate(value, start=1):
        if not isinstance(item, Mapping) or terminal_seen:
            raise Article73StateError("Article 73 routing history is malformed")
        try:
            decision = _enum(item.get("decision"), "decision", _ROUTING_DECISIONS)
            threshold = _enum(
                item.get("threshold_determination"),
                "threshold_determination",
                _THRESHOLD_DETERMINATIONS,
            )
            applicability = _enum(
                item.get("applicability_determination"),
                "applicability_determination",
                _APPLICABILITY_DETERMINATIONS,
            )
            principal = _human_principal(item.get("decided_by"))
            role = _enum(item.get("authority_role"), "authority_role", _AUTHORITY_ROLES)
            decided_at = _timestamp(item.get("decided_at"), "decided_at")
            rationale = _text(item.get("rationale"), "rationale", 8_000)
            authority_refs = _identities(
                item.get("authority_refs") or (),
                "authority_refs",
                limit=_MAX_AUTHORITIES,
            )
        except (TypeError, ValueError) as exc:
            raise Article73StateError("Article 73 routing history is malformed") from exc
        if item.get("sequence") != index or item.get("actor_type") != "human":
            raise Article73StateError("Article 73 routing history ordering is invalid")
        if role not in _EXTERNAL_DECISION_ROLES:
            raise Article73StateError("Article 73 routing role lacks authority")
        if decision == "report_to_authority":
            if threshold not in {"met", "uncertain"}:
                raise Article73StateError("report routing has an invalid threshold decision")
            if applicability not in {"applies", "uncertain"} or not authority_refs:
                raise Article73StateError("report routing has an invalid applicability route")
            terminal_seen = True
        elif decision == "do_not_report":
            if threshold != "not_met" and applicability != "does_not_apply":
                raise Article73StateError("do-not-report routing lacks a negative basis")
            if authority_refs:
                raise Article73StateError("do-not-report routing cannot name destinations")
            terminal_seen = True
        else:
            if threshold != "uncertain" and applicability != "uncertain":
                raise Article73StateError("legal-review routing must preserve uncertainty")
            if authority_refs:
                raise Article73StateError("legal-review routing cannot name destinations")
        normalized.append({
            "sequence": index,
            "decision": decision,
            "threshold_determination": threshold,
            "applicability_determination": applicability,
            "rationale": rationale,
            "authority_refs": authority_refs,
            "decided_by": principal,
            "actor_type": "human",
            "authority_role": role,
            "decided_at": decided_at,
        })
    if normalized != value:
        raise Article73StateError("Article 73 routing history is not canonical")
    return normalized


def _validate_report_approval(
    approval: object,
    *,
    prepared_by: str,
    prepared_at: float,
    payload_sha256: object,
) -> float:
    if not isinstance(approval, Mapping):
        raise Article73StateError("an approved report lacks human approval")
    _require_exact_fields(approval, _APPROVAL_FIELDS, "Article 73 report approval")
    try:
        approved_by = _human_principal(approval.get("approved_by"))
        authority_role = _enum(
            approval.get("authority_role"),
            "authority_role",
            _AUTHORITY_ROLES,
        )
        approved_at = _timestamp(approval.get("approved_at"), "approved_at")
    except (TypeError, ValueError) as exc:
        raise Article73StateError("Article 73 report approval is malformed") from exc
    if (
        approval.get("actor_type") != "human"
        or authority_role not in _EXTERNAL_DECISION_ROLES
        or approved_by.casefold() == prepared_by.casefold()
        or approval.get("payload_sha256") != payload_sha256
        or approved_at < prepared_at
    ):
        raise Article73StateError("Article 73 report approval is invalid")
    return approved_at


def _validate_report_submission(
    submission: object,
    *,
    approved_at: float,
    awareness_at: float,
    authority_refs: Sequence[str],
) -> None:
    if not isinstance(submission, Mapping):
        raise Article73StateError("a submitted report lacks a receipt")
    _require_exact_fields(
        submission,
        _SUBMISSION_FIELDS,
        "Article 73 report submission",
    )
    try:
        _human_principal(submission.get("submitted_by"))
        submitted_role = _enum(
            submission.get("authority_role"),
            "authority_role",
            _AUTHORITY_ROLES,
        )
        submitted_at = _timestamp(submission.get("submitted_at"), "submitted_at")
        submission_ref = _identity(
            submission.get("submission_reference"),
            "submission_reference",
        )
        submitted_authority_refs = _identities(
            submission.get("authority_refs") or (),
            "submission authority_refs",
            limit=_MAX_AUTHORITIES,
            allow_empty=False,
        )
        receipt_sha = str(submission.get("receipt_sha256") or "").lower()
    except (TypeError, ValueError) as exc:
        raise Article73StateError("Article 73 submission is malformed") from exc
    if (
        submission.get("actor_type") != "human"
        or submitted_role not in _EXTERNAL_DECISION_ROLES
        or submitted_at < approved_at
        or submitted_at < awareness_at
        or submitted_authority_refs != list(authority_refs)
        or not _DIGEST_RE.fullmatch(receipt_sha)
        or not submission_ref
    ):
        raise Article73StateError("Article 73 submission is invalid")


def _validate_reports(
    value: object,
    incident: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > _MAX_REPORTS:
        raise Article73StateError("Article 73 reports are malformed")
    normalized: list[dict[str, Any]] = []
    final_seen = False
    submitted_seen = False
    tenant_digest = str(incident["tenant_sha256"])
    for index, item in enumerate(value, start=1):
        if not isinstance(item, Mapping) or final_seen:
            raise Article73StateError("Article 73 report sequence is malformed")
        _require_exact_fields(item, _REPORT_FIELDS, "Article 73 report")
        try:
            report_id = _text(item.get("id"), "report id", 64)
            kind = _enum(item.get("kind"), "report kind", _REPORT_KINDS)
            status = _enum(item.get("status"), "report status", _REPORT_STATUSES)
            prepared_by = _human_principal(item.get("prepared_by"))
            prepared_at = _timestamp(item.get("prepared_at"), "prepared_at")
            payload = _validate_report_payload(item.get("payload"), incident, kind)
        except (TypeError, ValueError, Article73StateError) as exc:
            raise Article73StateError("Article 73 report is malformed") from exc
        if (
            item.get("sequence") != index
            or report_id != _report_id(str(incident["id"]), index, tenant_digest)
            or _REPORT_ID_RE.fullmatch(report_id) is None
            or item.get("actor_type") != "human"
            or item.get("payload_sha256") != _sha256(payload)
        ):
            raise Article73StateError("Article 73 report binding is invalid")
        if index == 1 and kind not in {"initial", "final"}:
            raise Article73StateError("the first Article 73 report must be initial or final")
        if index > 1 and kind == "initial":
            raise Article73StateError("an initial Article 73 report must be first")
        if kind == "update" and not submitted_seen:
            raise Article73StateError("an update requires a submitted earlier report")
        if index < len(value) and status != "submitted":
            raise Article73StateError("only the final report entry may remain unsubmitted")

        approval = item.get("approval")
        submission = item.get("submission")
        if status == "draft":
            if approval is not None or submission is not None:
                raise Article73StateError("a draft report cannot have approval or submission")
        else:
            approved_at = _validate_report_approval(
                approval,
                prepared_by=prepared_by,
                prepared_at=prepared_at,
                payload_sha256=item.get("payload_sha256"),
            )
            if status == "approved":
                if submission is not None:
                    raise Article73StateError("an approved report cannot have a submission")
            else:
                _validate_report_submission(
                    submission,
                    approved_at=approved_at,
                    awareness_at=float(incident["awareness_at"]),
                    authority_refs=incident["routing_history"][-1]["authority_refs"],
                )
                submitted_seen = True
        if kind == "final":
            final_seen = True
        normalized.append(dict(item))
    return normalized


def _derived_status(
    routing_history: Sequence[Mapping[str, Any]],
    reports: Sequence[Mapping[str, Any]],
) -> str:
    if not routing_history:
        return "triage"
    route = routing_history[-1]["decision"]
    if route == "legal_review_required":
        return "awaiting_legal_review"
    if route == "do_not_report":
        return "not_reportable"
    if not reports:
        return "reporting_required"
    current = reports[-1]
    if current["status"] != "submitted":
        return "drafting"
    if current["kind"] == "initial":
        return "initial_submitted"
    if current["kind"] == "update":
        return "follow_up"
    return "final_submitted"


def _validate_record(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise Article73StateError("Article 73 incident record is malformed")
    record = dict(value)
    _require_exact_fields(record, _RECORD_FIELDS, "Article 73 incident record")
    try:
        if record.get("schema") != INCIDENT_SCHEMA:
            raise ValueError("schema")
        incident_id = _text(record.get("id"), "incident id", 64)
        if _INCIDENT_ID_RE.fullmatch(incident_id) is None:
            raise ValueError("incident id")
        tenant_digest = str(record.get("tenant_sha256") or "").lower()
        if (
            _TENANT_DIGEST_RE.fullmatch(tenant_digest) is None
            or tenant_digest != _tenant_sha256()
        ):
            raise ValueError("tenant")
        revision = record.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise ValueError("revision")
        _text(record.get("title"), "title", 300)
        _text(record.get("summary"), "summary", 8_000)
        _identity(record.get("asset_id"), "asset_id")
        _identity(record.get("asset_version"), "asset_version")
        _enum(record.get("operator_role"), "operator_role", _OPERATOR_ROLES)
        _enum(record.get("asserted_high_risk"), "asserted_high_risk", _TRISTATE)
        _enum(record.get("asserted_union_market"), "asserted_union_market", _TRISTATE)
        member_states = _member_states(record.get("incident_member_states") or ())
        if record.get("incident_member_states") != member_states:
            raise ValueError("member states")
        awareness = _timestamp(record.get("awareness_at"), "awareness_at")
        occurred = _optional_timestamp(record.get("occurred_at"), "occurred_at")
        if occurred is not None and occurred > awareness:
            raise ValueError("occurred_at")
        outcomes = _outcomes(record.get("outcomes") or ())
        if record.get("outcomes") != outcomes:
            raise ValueError("outcomes")
        if not isinstance(record.get("widespread_infringement"), bool):
            raise ValueError("widespread")
        _enum(record.get("causality"), "causality", _CAUSALITY)
        if record.get("legal_source_url") != ARTICLE_73_SOURCE_URL:
            raise ValueError("legal source")
        if record.get("notice") != NON_LEGAL_NOTICE:
            raise ValueError("notice")
        evidence = _evidence_refs(record.get("evidence_refs") or ())
        if record.get("evidence_refs") != evidence:
            raise ValueError("evidence")
        created_at = _timestamp(record.get("created_at"), "created_at")
        updated_at = _timestamp(record.get("updated_at"), "updated_at")
        if created_at > updated_at:
            raise ValueError("record chronology")
    except (TypeError, ValueError) as exc:
        raise Article73StateError("Article 73 incident record is malformed") from exc
    _validate_clock(record)
    routing = _validate_routing_history(record.get("routing_history"))
    reports = _validate_reports(record.get("reports"), record)
    if reports and (
        not routing or routing[-1]["decision"] != "report_to_authority"
    ):
        raise Article73StateError("Article 73 reports lack a human filing route")
    if routing and routing[-1]["decision"] == "report_to_authority" and not member_states:
        raise Article73StateError("a report route requires an incident Member State")
    if record.get("status") != _derived_status(routing, reports):
        raise Article73StateError("Article 73 incident status is inconsistent")
    return record


class Article73IncidentRegister:
    """Tenant-scoped Article 73 register with CAS lifecycle transitions."""

    def __init__(self, store: GovernedRecordStore | None = None) -> None:
        self._store = _INCIDENTS if store is None else store

    def open_incident(
        self,
        title: str,
        *,
        asset_id: str,
        asset_version: str,
        awareness_at: float,
        summary: str,
        occurred_at: float | None = None,
        operator_role: str = "unknown",
        asserted_high_risk: str = "unknown",
        asserted_union_market: str = "unknown",
        incident_member_states: Sequence[str] = (),
        outcomes: Sequence[str] = (),
        widespread_infringement: bool = False,
        causality: str = "not_assessed",
        evidence_refs: Sequence[Mapping[str, str]] = (),
        calendar_timezone: str = "UTC",
        opened_by: str,
    ) -> dict[str, Any]:
        """Open triage without making an Article 3 or Article 73 conclusion.

        ``outcomes`` and ``widespread_infringement`` are bounded asserted facts,
        not automated legal classifications.  In particular, the latter must
        mean the Article 3(61) term of art rather than merely "many users".
        Only :meth:`record_routing_decision` records a human threshold and
        applicability decision.
        """

        _require_enabled()
        tenant_digest = _tenant_sha256()
        actor = _text(opened_by, "opened_by", 4_096)
        awareness = _timestamp(awareness_at, "awareness_at")
        observed_at = float(self._store.authoritative_time())
        if awareness > observed_at:
            raise ValueError("awareness_at cannot be in the future")
        occurrence = _optional_timestamp(occurred_at, "occurred_at")
        if occurrence is not None and occurrence > awareness:
            raise ValueError("occurred_at cannot be after awareness_at")
        normalized_outcomes = _outcomes(outcomes)
        if not isinstance(widespread_infringement, bool):
            raise ValueError("widespread_infringement must be a boolean")
        causal_state = _enum(causality, "causality", _CAUSALITY)
        zone_name = _calendar_timezone(calendar_timezone)
        record = {
            "schema": INCIDENT_SCHEMA,
            "id": self._store.new_id(),
            "tenant_sha256": tenant_digest,
            "status": "triage",
            "title": _text(title, "title", 300),
            "summary": _text(summary, "summary", 8_000),
            "asset_id": _identity(asset_id, "asset_id"),
            "asset_version": _identity(asset_version, "asset_version"),
            "operator_role": _enum(operator_role, "operator_role", _OPERATOR_ROLES),
            "asserted_high_risk": _enum(
                asserted_high_risk, "asserted_high_risk", _TRISTATE
            ),
            "asserted_union_market": _enum(
                asserted_union_market, "asserted_union_market", _TRISTATE
            ),
            "incident_member_states": _member_states(incident_member_states),
            "awareness_at": awareness,
            "occurred_at": occurrence,
            "outcomes": normalized_outcomes,
            "widespread_infringement": widespread_infringement,
            "causality": causal_state,
            "clock": _clock(
                awareness,
                normalized_outcomes,
                widespread_infringement,
                causal_state,
                zone_name,
            ),
            "evidence_refs": _evidence_refs(evidence_refs),
            "routing_history": [],
            "reports": [],
            "legal_source_url": ARTICLE_73_SOURCE_URL,
            "notice": NON_LEGAL_NOTICE,
        }
        saved = self._store.create(
            record,
            action="open_article_73_triage",
            actor=actor,
            max_records=_MAX_INCIDENTS,
        )
        return _validate_record(saved)

    def record_routing_decision(
        self,
        incident_id: str,
        *,
        decision: str,
        threshold_determination: str,
        applicability_determination: str,
        rationale: str,
        authority_refs: Sequence[str] = (),
        authority: HumanAuthority,
        expected_revision: int,
    ) -> dict[str, Any]:
        _require_enabled()
        if not isinstance(authority, HumanAuthority):
            raise TypeError("authority must be an authenticated HumanAuthority")
        if authority.role not in _EXTERNAL_DECISION_ROLES:
            raise ValueError("authority role cannot decide external Article 73 routing")
        route = _enum(decision, "decision", _ROUTING_DECISIONS)
        threshold = _enum(
            threshold_determination,
            "threshold_determination",
            _THRESHOLD_DETERMINATIONS,
        )
        applicability = _enum(
            applicability_determination,
            "applicability_determination",
            _APPLICABILITY_DETERMINATIONS,
        )
        refs = _identities(
            authority_refs,
            "authority_refs",
            limit=_MAX_AUTHORITIES,
        )
        why = _text(rationale, "rationale", 8_000)
        expected = _expected_revision(expected_revision)
        now = float(self._store.authoritative_time())

        if route == "report_to_authority":
            if threshold not in {"met", "uncertain"}:
                raise Article73StateError(
                    "report routing requires a met or precautionary uncertain threshold"
                )
            if applicability not in {"applies", "uncertain"}:
                raise Article73StateError(
                    "report routing requires applicable or precautionary uncertain scope"
                )
            if not refs:
                raise Article73StateError(
                    "report routing requires a human-selected authority reference"
                )
        elif route == "do_not_report":
            if threshold != "not_met" and applicability != "does_not_apply":
                raise Article73StateError(
                    "do-not-report needs a human negative threshold or applicability basis"
                )
            if refs:
                raise Article73StateError(
                    "do-not-report routing cannot include an authority destination"
                )
        else:
            if threshold != "uncertain" and applicability != "uncertain":
                raise Article73StateError(
                    "legal review must preserve threshold or applicability uncertainty"
                )
            if refs:
                raise Article73StateError(
                    "legal-review routing cannot include an authority destination"
                )

        def _mutate(current: dict[str, Any]) -> None:
            _validate_record(current)
            if current["status"] not in {"triage", "awaiting_legal_review"}:
                raise Article73StateError("Article 73 routing is already final")
            if route == "report_to_authority" and not current["incident_member_states"]:
                raise Article73StateError(
                    "report routing requires the incident Member State"
                )
            history = list(current["routing_history"])
            if len(history) >= _MAX_ROUTING_DECISIONS:
                raise Article73StateError("Article 73 routing history is full")
            history.append({
                "sequence": len(history) + 1,
                "decision": route,
                "threshold_determination": threshold,
                "applicability_determination": applicability,
                "rationale": why,
                "authority_refs": refs,
                "decided_by": authority.principal,
                "actor_type": "human",
                "authority_role": authority.role,
                "decided_at": now,
            })
            current["routing_history"] = history
            current["status"] = _derived_status(history, current["reports"])

        saved = self._store.update(
            _text(incident_id, "incident_id", 64),
            _mutate,
            expected_revision=expected,
            action="human_article_73_routing_decision",
            actor=authority.principal,
        )
        if saved is None:
            raise Article73StateError("Article 73 incident does not exist")
        return _validate_record(saved)

    def draft_report(
        self,
        incident_id: str,
        *,
        kind: str,
        details: Mapping[str, Any],
        prepared_by: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        _require_enabled()
        principal = _human_principal(prepared_by)
        report_kind = _enum(kind, "report kind", _REPORT_KINDS)
        expected = _expected_revision(expected_revision)
        now = float(self._store.authoritative_time())

        def _mutate(current: dict[str, Any]) -> None:
            _validate_record(current)
            if current["status"] in {"not_reportable", "final_submitted"}:
                raise Article73StateError("Article 73 incident cannot receive another report")
            if (
                not current["routing_history"]
                or current["routing_history"][-1]["decision"]
                != "report_to_authority"
            ):
                raise Article73StateError(
                    "a human report-to-authority decision is required first"
                )
            reports = list(current["reports"])
            if reports and reports[-1]["status"] != "submitted":
                raise Article73StateError("an Article 73 report is already awaiting submission")
            if not reports and report_kind not in {"initial", "final"}:
                raise Article73StateError("the first report must be initial or final")
            if reports and report_kind == "initial":
                raise Article73StateError("an initial report can only be first")
            if len(reports) >= _MAX_REPORTS:
                raise Article73StateError("Article 73 report history is full")
            payload = _normalize_report_payload(current, report_kind, details)
            sequence = len(reports) + 1
            reports.append({
                "id": _report_id(current["id"], sequence, current["tenant_sha256"]),
                "sequence": sequence,
                "kind": report_kind,
                "status": "draft",
                "payload": payload,
                "payload_sha256": _sha256(payload),
                "prepared_by": principal,
                "actor_type": "human",
                "prepared_at": now,
                "approval": None,
                "submission": None,
            })
            current["reports"] = reports
            current["status"] = _derived_status(current["routing_history"], reports)

        saved = self._store.update(
            _text(incident_id, "incident_id", 64),
            _mutate,
            expected_revision=expected,
            action=f"draft_article_73_{report_kind}_report",
            actor=principal,
        )
        if saved is None:
            raise Article73StateError("Article 73 incident does not exist")
        return _validate_record(saved)

    def approve_report(
        self,
        incident_id: str,
        report_id: str,
        *,
        authority: HumanAuthority,
        expected_revision: int,
    ) -> dict[str, Any]:
        _require_enabled()
        if not isinstance(authority, HumanAuthority):
            raise TypeError("authority must be an authenticated HumanAuthority")
        if authority.role not in _EXTERNAL_DECISION_ROLES:
            raise ValueError("authority role cannot approve an external Article 73 report")
        target = _text(report_id, "report_id", 64)
        if _REPORT_ID_RE.fullmatch(target) is None:
            raise ValueError("report_id is invalid")
        expected = _expected_revision(expected_revision)
        now = float(self._store.authoritative_time())

        def _mutate(current: dict[str, Any]) -> None:
            _validate_record(current)
            report = next((item for item in current["reports"] if item["id"] == target), None)
            if report is None:
                raise Article73StateError("Article 73 report does not exist")
            if report is not current["reports"][-1] or report["status"] != "draft":
                raise Article73StateError("only the current draft report can be approved")
            if authority.principal.casefold() == str(report["prepared_by"]).casefold():
                raise Article73StateError(
                    "Article 73 external reports require four-eyes approval"
                )
            report["status"] = "approved"
            report["approval"] = {
                "approved_by": authority.principal,
                "actor_type": "human",
                "authority_role": authority.role,
                "approved_at": now,
                "payload_sha256": report["payload_sha256"],
            }
            current["status"] = _derived_status(
                current["routing_history"], current["reports"]
            )

        saved = self._store.update(
            _text(incident_id, "incident_id", 64),
            _mutate,
            expected_revision=expected,
            action="approve_article_73_report",
            actor=authority.principal,
        )
        if saved is None:
            raise Article73StateError("Article 73 incident does not exist")
        return _validate_record(saved)

    def record_submission(
        self,
        incident_id: str,
        report_id: str,
        *,
        submission_reference: str,
        receipt_sha256: str,
        authority: HumanAuthority,
        expected_revision: int,
        submitted_at: float | None = None,
    ) -> dict[str, Any]:
        """Record a human-performed filing; this method sends nothing externally.

        ``submission_reference`` must identify an immutable receipt bundle that
        covers every human-selected authority reference on the route.  The
        supplied digest binds that bundle without persisting its contents here.
        """

        _require_enabled()
        if not isinstance(authority, HumanAuthority):
            raise TypeError("authority must be an authenticated HumanAuthority")
        if authority.role not in _EXTERNAL_DECISION_ROLES:
            raise ValueError("authority role cannot record an external Article 73 filing")
        target = _text(report_id, "report_id", 64)
        if _REPORT_ID_RE.fullmatch(target) is None:
            raise ValueError("report_id is invalid")
        reference = _identity(submission_reference, "submission_reference")
        digest = str(receipt_sha256 or "").strip().lower().removeprefix("sha256:")
        if not _DIGEST_RE.fullmatch(digest):
            raise ValueError("receipt_sha256 must be a SHA-256 digest")
        expected = _expected_revision(expected_revision)
        observed_at = float(self._store.authoritative_time())
        now = (
            observed_at
            if submitted_at is None
            else _timestamp(submitted_at, "submitted_at")
        )
        if now > observed_at:
            raise ValueError("submitted_at cannot be in the future")

        def _mutate(current: dict[str, Any]) -> None:
            _validate_record(current)
            report = next((item for item in current["reports"] if item["id"] == target), None)
            if report is None:
                raise Article73StateError("Article 73 report does not exist")
            if report is not current["reports"][-1] or report["status"] != "approved":
                raise Article73StateError("only the current approved report can be submitted")
            approved_at = float(report["approval"]["approved_at"])
            if now < approved_at:
                raise Article73StateError("submitted_at cannot precede approval")
            if now < float(current["awareness_at"]):
                raise Article73StateError("submitted_at cannot precede awareness")
            route_authority_refs = list(
                current["routing_history"][-1]["authority_refs"]
            )
            report["status"] = "submitted"
            report["submission"] = {
                "submission_reference": reference,
                "receipt_sha256": digest,
                "authority_refs": route_authority_refs,
                "submitted_by": authority.principal,
                "actor_type": "human",
                "authority_role": authority.role,
                "submitted_at": now,
            }
            current["status"] = _derived_status(
                current["routing_history"], current["reports"]
            )

        saved = self._store.update(
            _text(incident_id, "incident_id", 64),
            _mutate,
            expected_revision=expected,
            action="record_article_73_external_submission",
            actor=authority.principal,
        )
        if saved is None:
            raise Article73StateError("Article 73 incident does not exist")
        return _validate_record(saved)

    def get(self, incident_id: str) -> dict[str, Any] | None:
        _require_enabled()
        _require_tenant()
        value = self._store.get(_text(incident_id, "incident_id", 64))
        return None if value is None else _validate_record(value)

    def get_report_payload(
        self,
        incident_id: str,
        report_id: str,
    ) -> dict[str, Any] | None:
        """Return the tenant-bound full payload for an authorized filing adapter."""

        record = self.get(incident_id)
        if record is None:
            return None
        target = _text(report_id, "report_id", 64)
        report = next((item for item in record["reports"] if item["id"] == target), None)
        if report is None:
            return None
        if report["status"] not in {"approved", "submitted"}:
            raise Article73StateError(
                "an Article 73 report payload is not available for filing before approval"
            )
        return dict(report["payload"])

    def safe_projection(
        self,
        incident_id: str,
        *,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        record = self.get(incident_id)
        if record is None:
            return None
        observed_at = (
            float(self._store.authoritative_time())
            if now is None
            else _timestamp(now, "now")
        )
        submitted = [
            report for report in record["reports"] if report["status"] == "submitted"
        ]
        first_submission_at = (
            float(submitted[0]["submission"]["submitted_at"]) if submitted else None
        )
        due_at = float(record["clock"]["outer_limit_at"])
        if first_submission_at is not None:
            clock_status = "submission_recorded"
        elif observed_at > due_at:
            clock_status = "overdue"
        else:
            clock_status = "running"
        route = record["routing_history"][-1] if record["routing_history"] else None
        report_rows: list[dict[str, Any]] = []
        for report in record["reports"]:
            approval = report.get("approval") or {}
            submission = report.get("submission") or {}
            report_rows.append({
                "id": report["id"],
                "sequence": report["sequence"],
                "kind": report["kind"],
                "status": report["status"],
                "payload_sha256": report["payload_sha256"],
                "prepared_by_sha256": _principal_sha256(report["prepared_by"]),
                "prepared_at": report["prepared_at"],
                "approved_by_sha256": (
                    _principal_sha256(approval["approved_by"]) if approval else None
                ),
                "approved_at": approval.get("approved_at"),
                "submitted_by_sha256": (
                    _principal_sha256(submission["submitted_by"]) if submission else None
                ),
                "submitted_at": submission.get("submitted_at"),
                "receipt_sha256": submission.get("receipt_sha256"),
                "authority_refs": list(submission.get("authority_refs") or ()),
            })
        return {
            "schema": SAFE_PROJECTION_SCHEMA,
            "incident_id": record["id"],
            "revision": record["revision"],
            "tenant_sha256": record["tenant_sha256"],
            "status": record["status"],
            "asset_id": record["asset_id"],
            "asset_version": record["asset_version"],
            "outcomes": list(record["outcomes"]),
            "widespread_infringement": record["widespread_infringement"],
            "clock": {
                **dict(record["clock"]),
                "status": clock_status,
                "first_submission_at": first_submission_at,
                "first_submission_within_base_limit": (
                    None
                    if first_submission_at is None
                    else first_submission_at <= due_at
                ),
            },
            "routing": (
                None
                if route is None
                else {
                    "sequence": route["sequence"],
                    "decision": route["decision"],
                    "threshold_determination": route["threshold_determination"],
                    "applicability_determination": route[
                        "applicability_determination"
                    ],
                    "authority_refs": list(route["authority_refs"]),
                    "decided_by_sha256": _principal_sha256(route["decided_by"]),
                    "authority_role": route["authority_role"],
                    "decided_at": route["decided_at"],
                }
            ),
            "evidence_refs": [dict(item) for item in record["evidence_refs"]],
            "reports": report_rows,
            "legal_source_url": ARTICLE_73_SOURCE_URL,
            "notice": NON_LEGAL_NOTICE,
        }

    def list_safe(
        self,
        *,
        limit: int = 100,
        now: float | None = None,
    ) -> list[dict[str, Any]]:
        _require_enabled()
        _require_tenant()
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST_LIMIT:
            raise ValueError(f"limit must be between 1 and {_MAX_LIST_LIMIT}")
        observed_at = (
            float(self._store.authoritative_time())
            if now is None
            else _timestamp(now, "now")
        )
        records = self._store.list(limit=limit + 1)
        if len(records) > limit:
            records = records[:limit]
        projections = []
        for record in records:
            validated = _validate_record(record)
            projection = self.safe_projection(validated["id"], now=observed_at)
            if projection is not None:
                projections.append(projection)
        return sorted(
            projections,
            key=lambda item: (float(item["clock"]["outer_limit_at"]), item["incident_id"]),
        )

    def reporting_inventory(self, *, now: float | None = None) -> list[dict[str, Any]]:
        """Complete retained reporting projections, refusing an over-capacity store."""
        _require_enabled()
        _require_tenant()
        observed_at = (float(self._store.authoritative_time()) if now is None
                       else _timestamp(now, "now"))
        records = self._store.list(limit=_MAX_INCIDENTS + 1)
        if len(records) > _MAX_INCIDENTS:
            raise Article73StateError("Article 73 incident inventory exceeds its supported capacity")
        projections = []
        for record in records:
            validated = _validate_record(record)
            projection = self.safe_projection(validated["id"], now=observed_at)
            if projection is None:
                raise Article73StateError("Article 73 incident inventory changed while reading")
            projections.append(projection)
        return sorted(projections, key=lambda item: (
            float(item["clock"]["outer_limit_at"]), item["incident_id"]))


_DEFAULT = Article73IncidentRegister()


def open_incident(title: str, **kwargs: Any) -> dict[str, Any]:
    """Open tenant-scoped triage through the default-off global adapter."""

    _require_enabled()
    return _DEFAULT.open_incident(title, **kwargs)


def record_routing_decision(incident_id: str, **kwargs: Any) -> dict[str, Any]:
    """Record a human routing decision through the global adapter."""

    _require_enabled()
    return _DEFAULT.record_routing_decision(incident_id, **kwargs)


def draft_report(incident_id: str, **kwargs: Any) -> dict[str, Any]:
    """Draft a report through the global adapter."""

    _require_enabled()
    return _DEFAULT.draft_report(incident_id, **kwargs)


def approve_report(
    incident_id: str,
    report_id: str,
    **kwargs: Any,
) -> dict[str, Any]:
    """Approve the current draft through the global adapter."""

    _require_enabled()
    return _DEFAULT.approve_report(incident_id, report_id, **kwargs)


def record_submission(
    incident_id: str,
    report_id: str,
    **kwargs: Any,
) -> dict[str, Any]:
    """Record (but never perform) a filing through the global adapter."""

    _require_enabled()
    return _DEFAULT.record_submission(incident_id, report_id, **kwargs)


def get_incident(incident_id: str) -> dict[str, Any] | None:
    """Return the full tenant-bound record through the global adapter."""

    _require_enabled()
    return _DEFAULT.get(incident_id)


def get_report_payload(
    incident_id: str,
    report_id: str,
) -> dict[str, Any] | None:
    """Return a full tenant-bound report payload through the global adapter."""

    _require_enabled()
    return _DEFAULT.get_report_payload(incident_id, report_id)


def get_safe_projection(
    incident_id: str,
    *,
    now: float | None = None,
) -> dict[str, Any] | None:
    """Return an audit-friendly redacted projection through the global adapter."""

    _require_enabled()
    return _DEFAULT.safe_projection(incident_id, now=now)


def list_incidents(
    *,
    limit: int = 100,
    now: float | None = None,
) -> list[dict[str, Any]]:
    """List audit-friendly projections through the global adapter."""

    _require_enabled()
    return _DEFAULT.list_safe(limit=limit, now=now)


def reporting_inventory(*, now: float | None = None) -> list[dict[str, Any]]:
    """Read all supported retained incident clocks for reporting summaries."""
    return _DEFAULT.reporting_inventory(now=now)


__all__ = [
    "ARTICLE_73_SOURCE_URL",
    "Article73ConfigurationError",
    "Article73Error",
    "Article73IncidentRegister",
    "Article73StateError",
    "COMMISSION_TEMPLATE_SOURCE_URL",
    "HumanAuthority",
    "INCIDENT_SCHEMA",
    "NON_LEGAL_NOTICE",
    "PERIOD_CALCULATION_SOURCE_URL",
    "REPORT_SCHEMA",
    "SAFE_PROJECTION_SCHEMA",
    "RecordConflict",
    "approve_report",
    "calculate_article_73_clock",
    "draft_report",
    "enabled",
    "get_incident",
    "get_report_payload",
    "get_safe_projection",
    "list_incidents",
    "open_incident",
    "record_routing_decision",
    "record_submission",
    "reporting_inventory",
    "report_template",
]
