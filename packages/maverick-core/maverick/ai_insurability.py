"""Governed, underwriter-safe AI assurance profile projections.

This default-off module assembles bounded assurance facts for independent
verification.  It does **not** make an underwriting decision and never claims
insurability, coverage, pricing impact, certification, or insurer acceptance.

Every profile version is pinned to one exact current Model Risk asset revision
and version digest plus the exact digests of approved, current evidence.  A
different authenticated human must approve the prepared version with CAS before
it can be exported.  Asset or evidence authority changes make that approval
stale and export fails closed.

Only the closed v1 summary schema below is persisted.  Raw prompts, model
outputs, provider payloads, personal data, and secrets have no admission path.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

PROFILE_SCHEMA = "lightwork.ai-assurance-profile.v1"
EXPORT_SCHEMA = "lightwork.ai-assurance-profile-export.v1"
MEASUREMENT_SCHEMA = "lightwork.ai-assurance-measurement.v1"
NON_UNDERWRITING_NOTICE = (
    "Independent assurance evidence only. This profile is not an underwriting "
    "decision and does not establish insurability, coverage, premium impact, "
    "certification, or acceptance by any insurer."
)

_PROFILES = GovernedRecordStore(
    "ai_insurability_profiles", "IAP", "ai_insurability_profile"
)

_ASSET_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}|"
    r"\bsk-[A-Za-z0-9_-]{16,}|"
    r"\bAKIA[0-9A-Z]{16}\b)",
    re.IGNORECASE,
)
_PROHIBITED_CLAIM_RE = re.compile(
    r"\b(?:insurable|insured|coverage|premium|certif(?:y|ied|ication)|"
    r"insurer[- ]accept(?:ed|ance))\b",
    re.IGNORECASE,
)

_MAX_PROFILES = 2_000
_MAX_LIST = 100
_MAX_VERSIONS = 50
_MAX_EVIDENCE = 128
_MAX_FRAMEWORKS = 32
_MAX_SAFEGUARDS = 64
_MAX_TEXT_ITEMS = 32
_MAX_STEPS = 16
_MAX_JSON_BYTES = 256 * 1024
_MAX_SAMPLE_COUNT = 1_000_000_000
_MAX_FUTURE_SKEW_SECONDS = 300

_MEASUREMENT_NAMES = (
    "evaluation",
    "red_team",
    "drift",
    "runtime",
    "uptime",
    "refusal",
)
_MEASUREMENT_STATES = frozenset({"measured", "missing", "not_applicable"})
_MEASUREMENT_UNITS = frozenset({"percent", "score", "rate"})
_FRAMEWORK_POSTURES = frozenset(
    {"implemented", "partial", "not_assessed", "not_applicable"}
)
_SAFEGUARD_STATES = frozenset({"verified", "partial", "planned", "not_applicable"})
_SEVERITIES = frozenset({"none", "low", "medium", "high", "critical"})
_DATA_STATES = frozenset({"measured", "missing"})
_STORE_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})
_RECORD_FIELDS = frozenset(
    {
        "id",
        "schema",
        "tenant_ref",
        "profile_id",
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
        "evidence_bindings",
        "content",
        "content_sha256",
        "authority_sha256",
        "approval",
    }
)
_CONTENT_FIELDS = frozenset(
    {
        "governance_posture",
        "measurements",
        "incident_summary",
        "open_findings_summary",
        "safeguards",
        "exclusions",
        "limitations",
        "verifier_instructions",
    }
)


class AIInsurabilityError(RuntimeError):
    """Base error for assurance-profile governance."""


class AIInsurabilityConfigError(AIInsurabilityError):
    """The default-off feature is unavailable."""


class AIInsurabilityStateError(AIInsurabilityError):
    """Persisted profile authority is malformed or inconsistent."""


class AIInsurabilityAssetError(AIInsurabilityError):
    """An exact current Model Risk asset binding cannot be established."""


class AIInsurabilityEvidenceError(AIInsurabilityError):
    """Cited evidence is absent, unapproved, stale, or digest-mismatched."""


class AIInsurabilityApprovalError(AIInsurabilityError):
    """A profile is incomplete or lacks valid four-eyes approval."""


class AIInsurabilityStaleError(AIInsurabilityError):
    """An approved profile no longer matches current asset/evidence authority."""


class AIInsurabilityIdempotencyConflict(AIInsurabilityError):
    """An operation identity was reused with different content."""


def enabled() -> bool:
    """Return true only for explicit ``[ai_insurability] enable = true``."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("ai_insurability")
    return isinstance(section, Mapping) and section.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise AIInsurabilityConfigError(
            "AI assurance profiles are disabled; set [ai_insurability] enable = true"
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
        raise ValueError("assurance profile data must be finite JSON") from exc
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValueError("assurance profile data exceeds the 256 KiB bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _closed(value: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    if set(value) != fields:
        raise ValueError(f"{label} has unexpected or missing fields")
    return value


def _safe_text(value: object, label: str, limit: int = 512) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    result = unicodedata.normalize("NFKC", value).strip()
    if not result or len(result) > limit or _CONTROL_RE.search(result):
        raise ValueError(f"{label} is invalid")
    if _SECRET_RE.search(result):
        raise ValueError(f"{label} appears to contain secret material")
    if _EMAIL_RE.search(result):
        raise ValueError(f"{label} must not contain personal contact data")
    if _PROHIBITED_CLAIM_RE.search(result):
        raise ValueError(f"{label} contains a prohibited underwriting claim")
    return result


def _token(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    result = value.strip()
    if not _TOKEN_RE.fullmatch(result):
        raise ValueError(f"{label} must be a bounded identifier")
    return result


def _asset_id(value: object) -> str:
    if not isinstance(value, str) or not _ASSET_RE.fullmatch(value):
        raise ValueError("asset_id must be an exact Model Risk asset id")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return value.lower().removeprefix("sha256:")


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0 or result > 100_000_000_000.0:
        raise ValueError(f"{label} must be a positive finite timestamp")
    return result


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _number(value: object, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number")
    result = float(value)
    if not math.isfinite(result) or result < minimum or result > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return result


def _human_ref(actor: object, label: str = "actor") -> tuple[str, str]:
    if not isinstance(actor, str):
        raise ValueError(f"{label} must be an authenticated user principal")
    principal = actor.strip()
    if not principal.startswith("user:") or len(principal) <= 5 or len(principal) > 256:
        raise ValueError(f"{label} must be an authenticated user: principal")
    if _CONTROL_RE.search(principal) or _SECRET_RE.search(principal):
        raise ValueError(f"{label} is invalid")
    return principal, _sha256({"human_principal": principal})


def _audit_actor(actor_ref: str) -> str:
    """Use only a pseudonymous principal reference in persisted audit outboxes."""

    return f"user-ref:{actor_ref[:32]}"


def _tenant_ref() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if not tenant:
        raise AIInsurabilityStateError(
            "AI assurance profiles require an explicit tenant authority"
        )
    return "TEN-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:24]


def _string_list(
    value: object,
    label: str,
    *,
    maximum: int = _MAX_TEXT_ITEMS,
    allow_empty: bool = True,
) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{label} must be an array")
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds {maximum} entries")
    result = [_safe_text(item, label) for item in value]
    if not allow_empty and not result:
        raise ValueError(f"{label} must not be empty")
    return result


def _evidence_ids(value: object, label: str, *, allow_empty: bool = True) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{label} must be an array")
    if len(value) > _MAX_EVIDENCE:
        raise ValueError(f"{label} exceeds {_MAX_EVIDENCE} entries")
    result = sorted({_token(item, label) for item in value})
    if not allow_empty and not result:
        raise ValueError(f"{label} must cite evidence")
    return result


def _normalize_measurement(value: object, name: str) -> dict[str, Any]:
    fields = frozenset(
        {
            "schema",
            "state",
            "value",
            "unit",
            "window_start",
            "window_end",
            "sample_count",
            "confidence",
            "evidence_ids",
        }
    )
    row = _closed(value, fields, f"{name} measurement")
    if row["schema"] != MEASUREMENT_SCHEMA:
        raise ValueError(f"{name} measurement schema is unsupported")
    state = _token(row["state"], f"{name} state")
    if state not in _MEASUREMENT_STATES:
        raise ValueError(f"{name} measurement state is unsupported")
    unit = _token(row["unit"], f"{name} unit")
    if unit not in _MEASUREMENT_UNITS:
        raise ValueError(f"{name} measurement unit is unsupported")
    evidence = _evidence_ids(row["evidence_ids"], f"{name} evidence_ids")
    if state == "measured":
        measured = {
            "schema": MEASUREMENT_SCHEMA,
            "state": state,
            "value": _number(row["value"], f"{name} value", 0.0, 100.0),
            "unit": unit,
            "window_start": _timestamp(row["window_start"], f"{name} window_start"),
            "window_end": _timestamp(row["window_end"], f"{name} window_end"),
            "sample_count": _integer(
                row["sample_count"], f"{name} sample_count", 1, _MAX_SAMPLE_COUNT
            ),
            "confidence": _number(
                row["confidence"], f"{name} confidence", 0.0, 1.0
            ),
            "evidence_ids": evidence,
        }
        if measured["window_end"] < measured["window_start"]:
            raise ValueError(f"{name} measurement window is reversed")
        if not evidence:
            raise ValueError(f"{name} measured state must cite evidence")
        return measured
    if any(
        row[key] is not None for key in ("value", "window_start", "window_end", "confidence")
    ) or row["sample_count"] != 0 or evidence:
        raise ValueError(f"{name} {state} state must not imply measured data")
    return {
        "schema": MEASUREMENT_SCHEMA,
        "state": state,
        "value": None,
        "unit": unit,
        "window_start": None,
        "window_end": None,
        "sample_count": 0,
        "confidence": None,
        "evidence_ids": [],
    }


def _normalize_summary(value: object, label: str, *, findings: bool) -> dict[str, Any]:
    fields = (
        frozenset({"data_state", "as_of", "total_open", "critical_open", "overdue_open", "evidence_ids"})
        if findings
        else frozenset({"data_state", "as_of", "open_count", "closed_count", "highest_open_severity", "evidence_ids"})
    )
    row = _closed(value, fields, label)
    state = _token(row["data_state"], f"{label} data_state")
    if state not in _DATA_STATES:
        raise ValueError(f"{label} data_state is unsupported")
    if state == "missing":
        expected_null = {key: None for key in fields if key not in {"data_state", "evidence_ids"}}
        if any(row[key] is not None for key in expected_null) or row["evidence_ids"] != []:
            raise ValueError(f"{label} missing state must not imply measured data")
        return {"data_state": "missing", **expected_null, "evidence_ids": []}
    evidence = _evidence_ids(row["evidence_ids"], f"{label} evidence_ids", allow_empty=False)
    result: dict[str, Any] = {
        "data_state": "measured",
        "as_of": _timestamp(row["as_of"], f"{label} as_of"),
        "evidence_ids": evidence,
    }
    if findings:
        total = _integer(row["total_open"], "total_open", 0, _MAX_SAMPLE_COUNT)
        critical = _integer(row["critical_open"], "critical_open", 0, total)
        overdue = _integer(row["overdue_open"], "overdue_open", 0, total)
        result.update(total_open=total, critical_open=critical, overdue_open=overdue)
    else:
        result.update(
            open_count=_integer(row["open_count"], "open_count", 0, _MAX_SAMPLE_COUNT),
            closed_count=_integer(row["closed_count"], "closed_count", 0, _MAX_SAMPLE_COUNT),
        )
        severity = _token(row["highest_open_severity"], "highest_open_severity")
        if severity not in _SEVERITIES:
            raise ValueError("highest_open_severity is unsupported")
        if result["open_count"] == 0 and severity != "none":
            raise ValueError("highest_open_severity must be none when no incidents are open")
        if result["open_count"] > 0 and severity == "none":
            raise ValueError("highest_open_severity is required for open incidents")
        result["highest_open_severity"] = severity
    return result


def _normalize_content(value: object) -> dict[str, Any]:  # noqa: C901
    content = _closed(value, _CONTENT_FIELDS, "profile content")

    governance = _closed(
        content["governance_posture"],
        frozenset({"frameworks", "accountable_role", "review_cadence_days"}),
        "governance_posture",
    )
    frameworks_raw = governance["frameworks"]
    if isinstance(frameworks_raw, (str, bytes)) or not isinstance(frameworks_raw, Sequence):
        raise ValueError("frameworks must be an array")
    if not 1 <= len(frameworks_raw) <= _MAX_FRAMEWORKS:
        raise ValueError("frameworks must contain 1 through 32 entries")
    frameworks: list[dict[str, Any]] = []
    framework_ids: set[str] = set()
    for item in frameworks_raw:
        row = _closed(
            item,
            frozenset({"framework_id", "posture", "evidence_ids"}),
            "framework posture",
        )
        framework_id = _token(row["framework_id"], "framework_id")
        if framework_id in framework_ids:
            raise ValueError("framework_id entries must be unique")
        framework_ids.add(framework_id)
        posture = _token(row["posture"], "framework posture")
        if posture not in _FRAMEWORK_POSTURES:
            raise ValueError("framework posture is unsupported")
        frameworks.append(
            {
                "framework_id": framework_id,
                "posture": posture,
                "evidence_ids": _evidence_ids(row["evidence_ids"], "framework evidence_ids"),
            }
        )
    frameworks.sort(key=lambda row: row["framework_id"])

    measurements = _closed(
        content["measurements"], frozenset(_MEASUREMENT_NAMES), "measurements"
    )
    normalized_measurements = {
        name: _normalize_measurement(measurements[name], name)
        for name in _MEASUREMENT_NAMES
    }

    safeguards_raw = content["safeguards"]
    if isinstance(safeguards_raw, (str, bytes)) or not isinstance(safeguards_raw, Sequence):
        raise ValueError("safeguards must be an array")
    if not 1 <= len(safeguards_raw) <= _MAX_SAFEGUARDS:
        raise ValueError("safeguards must contain 1 through 64 entries")
    safeguards: list[dict[str, Any]] = []
    control_ids: set[str] = set()
    for item in safeguards_raw:
        row = _closed(
            item,
            frozenset({"control_id", "status", "evidence_ids"}),
            "safeguard",
        )
        control_id = _token(row["control_id"], "control_id")
        if control_id in control_ids:
            raise ValueError("control_id entries must be unique")
        control_ids.add(control_id)
        status = _token(row["status"], "safeguard status")
        if status not in _SAFEGUARD_STATES:
            raise ValueError("safeguard status is unsupported")
        safeguards.append(
            {
                "control_id": control_id,
                "status": status,
                "evidence_ids": _evidence_ids(row["evidence_ids"], "safeguard evidence_ids"),
            }
        )
    safeguards.sort(key=lambda row: row["control_id"])

    verifier = _closed(
        content["verifier_instructions"],
        frozenset({"schema_version", "steps"}),
        "verifier_instructions",
    )
    if verifier["schema_version"] != "v1":
        raise ValueError("verifier instruction schema is unsupported")
    steps = _string_list(
        verifier["steps"], "verifier step", maximum=_MAX_STEPS, allow_empty=False
    )

    result = {
        "governance_posture": {
            "frameworks": frameworks,
            "accountable_role": _token(governance["accountable_role"], "accountable_role"),
            "review_cadence_days": _integer(
                governance["review_cadence_days"], "review_cadence_days", 1, 3660
            ),
        },
        "measurements": normalized_measurements,
        "incident_summary": _normalize_summary(
            content["incident_summary"], "incident_summary", findings=False
        ),
        "open_findings_summary": _normalize_summary(
            content["open_findings_summary"], "open_findings_summary", findings=True
        ),
        "safeguards": safeguards,
        "exclusions": _string_list(
            content["exclusions"], "exclusion", allow_empty=False
        ),
        "limitations": _string_list(
            content["limitations"], "limitation", allow_empty=False
        ),
        "verifier_instructions": {"schema_version": "v1", "steps": steps},
    }
    _canonical(result)
    return result


def _content_evidence_ids(content: Mapping[str, Any]) -> set[str]:
    identities: set[str] = set()
    for framework in content["governance_posture"]["frameworks"]:
        identities.update(framework["evidence_ids"])
    for measurement in content["measurements"].values():
        identities.update(measurement["evidence_ids"])
    identities.update(content["incident_summary"]["evidence_ids"])
    identities.update(content["open_findings_summary"]["evidence_ids"])
    for safeguard in content["safeguards"]:
        identities.update(safeguard["evidence_ids"])
    return identities


def _completeness_gaps(content: Mapping[str, Any]) -> list[str]:
    gaps = [
        f"measurement:{name}"
        for name in _MEASUREMENT_NAMES
        if content["measurements"][name]["state"] == "missing"
    ]
    gaps.extend(
        f"framework:{row['framework_id']}"
        for row in content["governance_posture"]["frameworks"]
        if row["posture"] == "not_assessed"
    )
    if content["incident_summary"]["data_state"] == "missing":
        gaps.append("incident_summary")
    if content["open_findings_summary"]["data_state"] == "missing":
        gaps.append("open_findings_summary")
    return sorted(gaps)


def _normalize_citations(value: object) -> list[dict[str, str]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError("evidence_bindings must be an array")
    if len(value) > _MAX_EVIDENCE:
        raise ValueError(f"evidence_bindings exceeds {_MAX_EVIDENCE} entries")
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
    return sorted(result, key=lambda row: row["evidence_id"])


def _record_state(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in sorted(_RECORD_FIELDS - {"state_sha256"})}


class AIInsurabilityService:
    """Prepare, approve, revalidate, and export bounded assurance profiles."""

    def __init__(
        self,
        *,
        profiles: GovernedRecordStore | None = None,
        asset_lookup: Callable[[str], Mapping[str, Any] | None] | None = None,
        evidence_resolver: Callable[[str], Mapping[str, Any] | None] | None = None,
        clock: Callable[[], float] | None = None,
        enforce_feature: bool = True,
    ) -> None:
        if asset_lookup is not None and not callable(asset_lookup):
            raise ValueError("asset_lookup must be callable")
        if evidence_resolver is not None and not callable(evidence_resolver):
            raise ValueError("evidence_resolver must be callable")
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        if not isinstance(enforce_feature, bool):
            raise ValueError("enforce_feature must be a boolean")
        self._profiles = profiles or _PROFILES
        self._asset_lookup = asset_lookup
        self._evidence_resolver = evidence_resolver
        self._clock = clock
        self._enforce_feature = enforce_feature

    def _require_active(self) -> str:
        if self._enforce_feature:
            require_enabled()
        return _tenant_ref()

    def _now(self) -> float:
        source = self._clock or self._profiles.authoritative_time
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
            raise AIInsurabilityAssetError("Model Risk asset lookup failed") from exc
        if not isinstance(observation, Mapping):
            raise AIInsurabilityAssetError("Model Risk asset does not exist")
        try:
            observed = _asset_id(observation.get("asset_id"))
            revision = _integer(observation.get("revision"), "asset revision", 1, 2**63 - 1)
            digest = _digest(observation.get("version_digest"), "asset version_digest")
        except (TypeError, ValueError) as exc:
            raise AIInsurabilityAssetError("Model Risk asset binding is malformed") from exc
        if observed != asset:
            raise AIInsurabilityAssetError("Model Risk asset lookup changed identity")
        return {"asset_id": asset, "revision": revision, "version_digest": digest}

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
            raise AIInsurabilityEvidenceError("approved evidence lookup failed") from exc
        if not isinstance(row, Mapping):
            raise AIInsurabilityEvidenceError("cited approved evidence does not exist")
        return row

    def _verify_evidence(
        self, binding: Mapping[str, str], *, asset_id: str
    ) -> dict[str, str]:
        evidence_id = _token(binding.get("evidence_id"), "evidence_id")
        expected_digest = _digest(binding.get("digest"), "evidence digest")
        row = self._evidence_lookup(evidence_id)
        observed_id = row.get("evidence_id", row.get("id"))
        digest_value = row.get(
            "digest", row.get("evidence_digest", row.get("payload_sha256"))
        )
        try:
            observed = _token(observed_id, "resolved evidence_id")
            digest = _digest(digest_value, "resolved evidence digest")
        except (TypeError, ValueError) as exc:
            raise AIInsurabilityEvidenceError("resolved evidence binding is malformed") from exc
        if observed != evidence_id or digest != expected_digest:
            raise AIInsurabilityEvidenceError("cited evidence digest changed")
        if row.get("status") != "approved":
            raise AIInsurabilityEvidenceError("cited evidence is not approved")
        if "result" in row and row.get("result") != "passed":
            raise AIInsurabilityEvidenceError("cited evidence is not a passing result")
        current = row.get("current") is True or row.get("freshness") == "current"
        if not current:
            raise AIInsurabilityEvidenceError("cited evidence is not current")
        if "asset_id" in row and row.get("asset_id") != asset_id:
            raise AIInsurabilityEvidenceError("cited evidence belongs to a different asset")
        return {"evidence_id": evidence_id, "digest": digest}

    def _verify_evidence_set(
        self, bindings: Sequence[Mapping[str, str]], *, asset_id: str
    ) -> list[dict[str, str]]:
        return [self._verify_evidence(row, asset_id=asset_id) for row in bindings]

    @staticmethod
    def _record_id(tenant_ref: str, profile_id: str) -> str:
        return f"IAP-{_sha256({'tenant_ref': tenant_ref, 'profile_id': profile_id})[:32]}"

    def _version(
        self,
        *,
        number: int,
        asset_binding: Mapping[str, Any],
        content: Mapping[str, Any],
        evidence_bindings: Sequence[Mapping[str, str]],
        operation_sha256: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        now = self._now()
        if any(
            measurement["state"] == "measured"
            and measurement["window_end"] > now + _MAX_FUTURE_SKEW_SECONDS
            for measurement in content["measurements"].values()
        ):
            raise ValueError("measurement window ends too far in the future")
        for label in ("incident_summary", "open_findings_summary"):
            summary = content[label]
            if summary["data_state"] == "measured" and summary["as_of"] > now + _MAX_FUTURE_SKEW_SECONDS:
                raise ValueError(f"{label} is too far in the future")
        content_sha = _sha256(content)
        authority = {
            "version": number,
            "asset_binding": dict(asset_binding),
            "evidence_bindings": [dict(row) for row in evidence_bindings],
            "content_sha256": content_sha,
        }
        return {
            "version": number,
            "prepared_at": now,
            "prepared_by_ref": actor_ref,
            "operation_sha256": operation_sha256,
            "asset_binding": dict(asset_binding),
            "evidence_bindings": [dict(row) for row in evidence_bindings],
            "content": copy.deepcopy(dict(content)),
            "content_sha256": content_sha,
            "authority_sha256": _sha256(authority),
            "approval": None,
        }

    def _validate_record(self, value: object, *, tenant_ref: str) -> dict[str, Any]:  # noqa: C901
        if not isinstance(value, Mapping):
            raise AIInsurabilityStateError("stored assurance profile is not an object")
        if set(value) - _RECORD_FIELDS - _STORE_METADATA or _RECORD_FIELDS - set(value):
            raise AIInsurabilityStateError("stored assurance profile shape is malformed")
        try:
            record = dict(value)
            if record["schema"] != PROFILE_SCHEMA or record["tenant_ref"] != tenant_ref:
                raise ValueError("profile schema or tenant binding mismatch")
            profile_id = _token(record["profile_id"], "profile_id")
            asset = _asset_id(record["asset_id"])
            if record["id"] != self._record_id(tenant_ref, profile_id):
                raise ValueError("profile identity mismatch")
            _integer(record["revision"], "record revision", 1, 2**63 - 1)
            _timestamp(record["created_at"], "created_at")
            _timestamp(record["updated_at"], "updated_at")
            _digest(record["create_operation_sha256"], "create operation digest")
            versions = record["versions"]
            if not isinstance(versions, list) or not 1 <= len(versions) <= _MAX_VERSIONS:
                raise ValueError("profile versions are malformed")
            for index, candidate in enumerate(versions, start=1):
                version = _closed(candidate, _VERSION_FIELDS, "stored profile version")
                if version["version"] != index:
                    raise ValueError("profile versions are not contiguous")
                _timestamp(version["prepared_at"], "prepared_at")
                prepared_ref = _digest(version["prepared_by_ref"], "prepared_by_ref")
                _digest(version["operation_sha256"], "operation digest")
                binding = _closed(
                    version["asset_binding"],
                    frozenset({"asset_id", "revision", "version_digest"}),
                    "asset binding",
                )
                if _asset_id(binding["asset_id"]) != asset:
                    raise ValueError("profile version asset changed")
                _integer(binding["revision"], "asset revision", 1, 2**63 - 1)
                _digest(binding["version_digest"], "asset version digest")
                citations = _normalize_citations(version["evidence_bindings"])
                if citations != version["evidence_bindings"]:
                    raise ValueError("evidence bindings are not canonical")
                content = _normalize_content(version["content"])
                if content != version["content"]:
                    raise ValueError("profile content is not canonical")
                if set(row["evidence_id"] for row in citations) != _content_evidence_ids(content):
                    raise ValueError("profile citations do not exactly match referenced evidence")
                content_sha = _digest(version["content_sha256"], "content_sha256")
                if content_sha != _sha256(content):
                    raise ValueError("profile content digest mismatch")
                authority = {
                    "version": index,
                    "asset_binding": dict(binding),
                    "evidence_bindings": citations,
                    "content_sha256": content_sha,
                }
                authority_sha = _digest(version["authority_sha256"], "authority_sha256")
                if authority_sha != _sha256(authority):
                    raise ValueError("profile authority digest mismatch")
                approval = version["approval"]
                if approval is not None:
                    approved = _closed(
                        approval,
                        frozenset({"approved_at", "approved_by_ref", "authority_sha256", "four_eyes"}),
                        "profile approval",
                    )
                    approved_at = _timestamp(approved["approved_at"], "approved_at")
                    if approved_at < version["prepared_at"]:
                        raise ValueError("profile approval predates preparation")
                    approved_ref = _digest(approved["approved_by_ref"], "approved_by_ref")
                    if approved_ref == prepared_ref or approved["four_eyes"] is not True:
                        raise ValueError("profile approval violates four-eyes")
                    if _digest(approved["authority_sha256"], "approval authority") != authority_sha:
                        raise ValueError("profile approval authority mismatch")
            expected_status = "approved" if versions[-1]["approval"] is not None else "draft"
            if record["status"] != expected_status:
                raise ValueError("profile status is inconsistent")
            if _digest(record["state_sha256"], "state_sha256") != _sha256(_record_state(record)):
                raise ValueError("profile state digest mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise AIInsurabilityStateError("stored assurance profile is malformed") from exc
        return record

    def _currentness(self, version: Mapping[str, Any]) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        try:
            current_asset = self._asset_binding(version["asset_binding"]["asset_id"])
            if current_asset != version["asset_binding"]:
                reasons.append("asset_authority_changed")
        except AIInsurabilityError:
            reasons.append("asset_authority_unavailable")
        for binding in version["evidence_bindings"]:
            try:
                self._verify_evidence(binding, asset_id=version["asset_binding"]["asset_id"])
            except AIInsurabilityEvidenceError:
                reasons.append(f"evidence_authority_changed:{binding['evidence_id']}")
        return not reasons, reasons

    def _version_projection(self, version: Mapping[str, Any]) -> dict[str, Any]:
        fresh, reasons = self._currentness(version)
        gaps = _completeness_gaps(version["content"])
        approved = version["approval"] is not None
        status = "stale" if approved and not fresh else ("approved" if approved else "draft")
        return {
            "version": version["version"],
            "prepared_at": version["prepared_at"],
            "asset_binding": copy.deepcopy(version["asset_binding"]),
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
        versions = [self._version_projection(row) for row in record["versions"]]
        return {
            "schema": PROFILE_SCHEMA,
            "profile_id": record["profile_id"],
            "asset_id": record["asset_id"],
            "revision": record["revision"],
            "status": versions[-1]["status"],
            "versions": versions,
            "notice": NON_UNDERWRITING_NOTICE,
        }

    def create_profile(
        self,
        profile_id: str,
        *,
        asset_id: str,
        content: Mapping[str, Any],
        evidence_bindings: Sequence[Mapping[str, str]],
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = _token(profile_id, "profile_id")
        _actor_name, actor_ref = _human_ref(actor, "preparer")
        operation = _safe_text(idempotency_key, "idempotency_key", 256)
        operation_sha = _sha256({"tenant_ref": tenant_ref, "operation": operation})
        normalized_content = _normalize_content(content)
        citations = _normalize_citations(evidence_bindings)
        if set(row["evidence_id"] for row in citations) != _content_evidence_ids(normalized_content):
            raise ValueError("evidence_bindings must exactly match all content citations")
        record_id = self._record_id(tenant_ref, semantic_id)
        existing = self._profiles.get(record_id)
        if existing is not None:
            current = self._validate_record(existing, tenant_ref=tenant_ref)
            first = current["versions"][0]
            if (
                current["create_operation_sha256"] != operation_sha
                or first["asset_binding"]["asset_id"] != _asset_id(asset_id)
                or first["evidence_bindings"] != citations
                or first["content"] != normalized_content
            ):
                raise AIInsurabilityIdempotencyConflict(
                    "profile identity or idempotency key is already bound to different content"
                )
            return self._public_record(current)
        asset = self._asset_binding(asset_id)
        citations = self._verify_evidence_set(citations, asset_id=asset["asset_id"])
        version = self._version(
            number=1,
            asset_binding=asset,
            content=normalized_content,
            evidence_bindings=citations,
            operation_sha256=operation_sha,
            actor_ref=actor_ref,
        )
        record = {
            "id": record_id,
            "schema": PROFILE_SCHEMA,
            "tenant_ref": tenant_ref,
            "profile_id": semantic_id,
            "asset_id": asset["asset_id"],
            "versions": [version],
            "status": "draft",
            "create_operation_sha256": operation_sha,
        }
        record["state_sha256"] = _sha256(_record_state(record))
        try:
            saved = self._profiles.create(
                record,
                action="prepare_ai_assurance_profile",
                actor=_audit_actor(actor_ref),
                max_records=_MAX_PROFILES,
            )
        except RecordConflict as exc:
            concurrent = self._profiles.get(record_id)
            if concurrent is None:
                raise
            current = self._validate_record(concurrent, tenant_ref=tenant_ref)
            first = current["versions"][0]
            if (
                current["create_operation_sha256"] != operation_sha
                or first["asset_binding"] != asset
                or first["evidence_bindings"] != citations
                or first["content"] != normalized_content
            ):
                raise AIInsurabilityIdempotencyConflict(
                    "profile was concurrently created with different content"
                ) from exc
            saved = current
        return self._public_record(self._validate_record(saved, tenant_ref=tenant_ref))

    def add_version(
        self,
        profile_id: str,
        *,
        content: Mapping[str, Any],
        evidence_bindings: Sequence[Mapping[str, str]],
        expected_revision: int,
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = _token(profile_id, "profile_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**63 - 1)
        _actor_name, actor_ref = _human_ref(actor, "preparer")
        operation = _safe_text(idempotency_key, "idempotency_key", 256)
        operation_sha = _sha256({"tenant_ref": tenant_ref, "operation": operation})
        normalized_content = _normalize_content(content)
        citations = _normalize_citations(evidence_bindings)
        if set(row["evidence_id"] for row in citations) != _content_evidence_ids(normalized_content):
            raise ValueError("evidence_bindings must exactly match all content citations")
        record_id = self._record_id(tenant_ref, semantic_id)
        raw = self._profiles.get(record_id)
        if raw is None:
            raise AIInsurabilityStateError("assurance profile does not exist")
        current = self._validate_record(raw, tenant_ref=tenant_ref)
        latest = current["versions"][-1]
        if latest["operation_sha256"] == operation_sha:
            if (
                latest["evidence_bindings"] != citations
                or latest["content"] != normalized_content
            ):
                raise AIInsurabilityIdempotencyConflict(
                    "idempotency key is already bound to a different profile version"
                )
            return self._public_record(current)
        asset = self._asset_binding(current["asset_id"])
        citations = self._verify_evidence_set(citations, asset_id=asset["asset_id"])
        if current["revision"] != expected:
            raise RecordConflict(
                f"assurance profile changed (expected revision {expected}, found {current['revision']})"
            )
        if len(current["versions"]) >= _MAX_VERSIONS:
            raise AIInsurabilityStateError("assurance profile exceeds its version bound")
        next_version = self._version(
            number=len(current["versions"]) + 1,
            asset_binding=asset,
            content=normalized_content,
            evidence_bindings=citations,
            operation_sha256=operation_sha,
            actor_ref=actor_ref,
        )

        def mutate(row: dict[str, Any]) -> None:
            validated = self._validate_record(row, tenant_ref=tenant_ref)
            if validated["revision"] != expected:
                raise RecordConflict("assurance profile revision changed")
            row["versions"].append(next_version)
            row["status"] = "draft"
            row["state_sha256"] = _sha256(_record_state(row))

        saved = self._profiles.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="prepare_ai_assurance_profile_version",
            actor=_audit_actor(actor_ref),
        )
        if saved is None:
            raise AIInsurabilityStateError("assurance profile disappeared")
        return self._public_record(self._validate_record(saved, tenant_ref=tenant_ref))

    def approve_profile(
        self,
        profile_id: str,
        version: int,
        *,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = _token(profile_id, "profile_id")
        selected = _integer(version, "version", 1, _MAX_VERSIONS)
        expected = _integer(expected_revision, "expected_revision", 1, 2**63 - 1)
        _actor_name, actor_ref = _human_ref(actor, "approver")
        record_id = self._record_id(tenant_ref, semantic_id)
        raw = self._profiles.get(record_id)
        if raw is None:
            raise AIInsurabilityStateError("assurance profile does not exist")
        current = self._validate_record(raw, tenant_ref=tenant_ref)
        if current["revision"] != expected:
            raise RecordConflict(
                f"assurance profile changed (expected revision {expected}, found {current['revision']})"
            )
        if selected != len(current["versions"]):
            raise AIInsurabilityApprovalError("only the latest profile version can be approved")
        candidate = current["versions"][selected - 1]
        if candidate["approval"] is not None:
            return self._public_record(current)
        if actor_ref == candidate["prepared_by_ref"]:
            raise AIInsurabilityApprovalError(
                "four-eyes approval requires a different human than the preparer"
            )
        gaps = _completeness_gaps(candidate["content"])
        if gaps:
            raise AIInsurabilityApprovalError(
                "profile has missing required assurance data: " + ", ".join(gaps)
            )
        fresh, reasons = self._currentness(candidate)
        if not fresh:
            raise AIInsurabilityStaleError(
                "profile authority is stale: " + ", ".join(reasons)
            )
        approved_at = self._now()
        if approved_at < candidate["prepared_at"]:
            raise AIInsurabilityStateError(
                "approval authority time predates profile preparation"
            )

        def mutate(row: dict[str, Any]) -> None:
            validated = self._validate_record(row, tenant_ref=tenant_ref)
            live = validated["versions"][selected - 1]
            if live["approval"] is not None:
                return
            if live["prepared_by_ref"] == actor_ref:
                raise AIInsurabilityApprovalError("profile violates four-eyes approval")
            live["approval"] = {
                "approved_at": approved_at,
                "approved_by_ref": actor_ref,
                "authority_sha256": live["authority_sha256"],
                "four_eyes": True,
            }
            row["status"] = "approved"
            row["state_sha256"] = _sha256(_record_state(row))

        saved = self._profiles.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="approve_ai_assurance_profile",
            actor=_audit_actor(actor_ref),
        )
        if saved is None:
            raise AIInsurabilityStateError("assurance profile disappeared")
        return self._public_record(self._validate_record(saved, tenant_ref=tenant_ref))

    def get_profile(self, profile_id: str) -> dict[str, Any] | None:
        tenant_ref = self._require_active()
        semantic_id = _token(profile_id, "profile_id")
        row = self._profiles.get(self._record_id(tenant_ref, semantic_id))
        if row is None:
            return None
        return self._public_record(self._validate_record(row, tenant_ref=tenant_ref))

    def list_profiles(self, *, limit: int = _MAX_LIST) -> list[dict[str, Any]]:
        tenant_ref = self._require_active()
        maximum = _integer(limit, "limit", 1, _MAX_LIST)
        rows = self._profiles.list(limit=maximum)
        result: list[dict[str, Any]] = []
        for raw in rows:
            record = self._validate_record(raw, tenant_ref=tenant_ref)
            latest = self._version_projection(record["versions"][-1])
            result.append(
                {
                    "profile_id": record["profile_id"],
                    "asset_id": record["asset_id"],
                    "revision": record["revision"],
                    "latest_version": latest["version"],
                    "status": latest["status"],
                    "exportable": latest["exportable"],
                }
            )
        return sorted(result, key=lambda row: row["profile_id"])

    def export_profile(self, profile_id: str, *, version: int | None = None) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = _token(profile_id, "profile_id")
        row = self._profiles.get(self._record_id(tenant_ref, semantic_id))
        if row is None:
            raise AIInsurabilityStateError("assurance profile does not exist")
        record = self._validate_record(row, tenant_ref=tenant_ref)
        selected = len(record["versions"]) if version is None else _integer(
            version, "version", 1, len(record["versions"])
        )
        candidate = record["versions"][selected - 1]
        if candidate["approval"] is None:
            raise AIInsurabilityApprovalError("profile version is not human approved")
        gaps = _completeness_gaps(candidate["content"])
        if gaps:
            raise AIInsurabilityApprovalError("profile version is incomplete")
        fresh, reasons = self._currentness(candidate)
        if not fresh:
            raise AIInsurabilityStaleError(
                "profile authority is stale: " + ", ".join(reasons)
            )
        packet = {
            "schema": EXPORT_SCHEMA,
            "profile_id": record["profile_id"],
            "version": selected,
            "prepared_at": candidate["prepared_at"],
            "approved_at": candidate["approval"]["approved_at"],
            "asset_binding": copy.deepcopy(candidate["asset_binding"]),
            "evidence_bindings": copy.deepcopy(candidate["evidence_bindings"]),
            "content": copy.deepcopy(candidate["content"]),
            "content_sha256": candidate["content_sha256"],
            "authority_sha256": candidate["authority_sha256"],
            "approval": {"human_approved": True, "four_eyes": True, "authority_fresh": True},
            "claims": {
                "underwriting_decision": False,
                "insurability_determination": False,
                "coverage_determination": False,
                "premium_reduction_claim": False,
                "certification_claim": False,
                "insurer_acceptance_claim": False,
            },
            "notice": NON_UNDERWRITING_NOTICE,
        }
        return {**packet, "packet_sha256": _sha256(packet)}


_DEFAULT = AIInsurabilityService()


def configured_insurability() -> AIInsurabilityService:
    require_enabled()
    return _DEFAULT


__all__ = [
    "AIInsurabilityApprovalError",
    "AIInsurabilityAssetError",
    "AIInsurabilityConfigError",
    "AIInsurabilityError",
    "AIInsurabilityEvidenceError",
    "AIInsurabilityIdempotencyConflict",
    "AIInsurabilityService",
    "AIInsurabilityStaleError",
    "AIInsurabilityStateError",
    "EXPORT_SCHEMA",
    "MEASUREMENT_SCHEMA",
    "NON_UNDERWRITING_NOTICE",
    "PROFILE_SCHEMA",
    "configured_insurability",
    "enabled",
    "require_enabled",
]
