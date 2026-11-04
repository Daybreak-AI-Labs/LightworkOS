"""Governed bank model-risk-management evidence packages.

This default-off module prepares bounded, deterministic evidence packages for
independent model-risk review.  It does not decide whether a model is approved,
valid, compliant, certified, or acceptable to any supervisor or regulator.

Each immutable package version is pinned to one exact current Model Risk asset
revision/version digest and to the exact digests of approved, current evidence.
A second authenticated human can approve only the integrity of that package
version.  Asset or evidence authority changes make the approval stale and make
export fail closed.

Only the closed summary schema below is admitted.  Raw prompts, model outputs,
provider payloads, secrets, personal contact data, and unbounded extensions have
no persistence path.
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

PACKAGE_SCHEMA = "lightwork.ai-bank-mrm-package.v1"
EXPORT_SCHEMA = "lightwork.ai-bank-mrm-package-export.v1"
SECTION_SCHEMA = "lightwork.ai-bank-mrm-section.v1"
NOTICE = (
    "Model-risk evidence package only. Approval attests to package integrity, "
    "not model approval, validation, compliance, certification, regulatory "
    "acceptance, or supervisory acceptance. Independent review remains required."
)

_PACKAGES = GovernedRecordStore(
    "ai_bank_mrm_packages", "BMP", "ai_bank_mrm_package"
)

_ASSET_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)")
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}|"
    r"\bsk-[A-Za-z0-9_-]{16,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\b(?:password|secret|api[_ -]?key)\s*[:=]\s*\S+)",
    re.IGNORECASE,
)
_RAW_PAYLOAD_RE = re.compile(
    r"\b(?:raw[_ -]?(?:prompt|output|response)|prompt[_ -]?text|"
    r"model[_ -]?output|provider[_ -]?payload)\b",
    re.IGNORECASE,
)
_PROHIBITED_CLAIM_RE = re.compile(
    r"\b(?:compliant|certified|certification|regulator[- ]approved|"
    r"regulator[- ]accepted|supervisor[- ]approved|supervisor[- ]accepted)\b",
    re.IGNORECASE,
)

_MAX_PACKAGES = 2_000
_MAX_VERSIONS = 50
_MAX_LIST = 100
_MAX_EVIDENCE = 128
_MAX_JSON_BYTES = 256 * 1024
_STORE_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})
_RECORD_FIELDS = frozenset(
    {
        "id",
        "schema",
        "tenant_ref",
        "package_id",
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
        "inventory_classification",
        "validation_scope",
        "validation_results",
        "conceptual_soundness",
        "outcomes_monitoring",
        "limitations",
        "change_controls",
        "issues_remediation",
        "independent_review",
    }
)
_STATES = frozenset({"verified", "unverified", "missing"})

# Every section has an exact field set.  The value kind is intentionally small:
# text, opaque identifier, controlled choice, bounded integer, or timestamp.
_FIELD_SPECS: dict[str, dict[str, tuple[str, frozenset[str] | None]]] = {
    "inventory_classification": {
        "model_name": ("text", None),
        "model_purpose": ("text", None),
        "business_use": ("text", None),
        "owner_role": ("token", None),
        "model_tier": (
            "choice",
            frozenset({"tier-1", "tier-2", "tier-3", "tier-4", "unrated"}),
        ),
        "materiality": (
            "choice",
            frozenset({"low", "moderate", "high", "critical", "unrated"}),
        ),
        "deployment_state": (
            "choice",
            frozenset({"proposed", "development", "validation", "production", "retired"}),
        ),
    },
    "validation_scope": {
        "validation_type": (
            "choice",
            frozenset({"initial", "periodic", "change-triggered", "targeted"}),
        ),
        "scope_summary": ("text", None),
        "population_code": ("token", None),
        "exclusions_summary": ("text", None),
    },
    "validation_results": {
        "outcome": (
            "choice",
            frozenset(
                {"satisfactory", "satisfactory-with-conditions", "unsatisfactory"}
            ),
        ),
        "results_summary": ("text", None),
        "open_findings": ("integer", None),
        "high_findings": ("integer", None),
        "observed_at": ("timestamp", None),
    },
    "conceptual_soundness": {
        "methodology_code": ("token", None),
        "assumptions_summary": ("text", None),
        "soundness_summary": ("text", None),
    },
    "outcomes_monitoring": {
        "monitoring_summary": ("text", None),
        "metric_set_code": ("token", None),
        "cadence_days": ("integer", None),
        "last_observed_at": ("timestamp", None),
    },
    "limitations": {
        "limitations_summary": ("text", None),
        "limitation_count": ("integer", None),
        "residual_risk": (
            "choice",
            frozenset({"low", "moderate", "high", "critical", "unrated"}),
        ),
    },
    "change_controls": {
        "change_policy_code": ("token", None),
        "change_summary": ("text", None),
        "last_change_at": ("timestamp", None),
    },
    "issues_remediation": {
        "issues_summary": ("text", None),
        "open_issues": ("integer", None),
        "overdue_issues": ("integer", None),
        "highest_severity": (
            "choice",
            frozenset({"none", "low", "moderate", "high", "critical"}),
        ),
    },
    "independent_review": {
        "review_type": (
            "choice",
            frozenset({"independent-validation", "independent-challenge", "audit"}),
        ),
        "reviewer_role": ("token", None),
        "conclusion": (
            "choice",
            frozenset(
                {"satisfactory", "satisfactory-with-conditions", "unsatisfactory"}
            ),
        ),
        "reviewed_at": ("timestamp", None),
    },
}


class AIBankMRMError(RuntimeError):
    """Base error for bank MRM evidence-package governance."""


class AIBankMRMConfigError(AIBankMRMError):
    """The default-off capability is unavailable."""


class AIBankMRMStateError(AIBankMRMError):
    """Persisted package authority is malformed or inconsistent."""


class AIBankMRMAssetError(AIBankMRMError):
    """An exact current Model Risk asset binding cannot be established."""


class AIBankMRMEvidenceError(AIBankMRMError):
    """Cited evidence is absent, unapproved, stale, or digest-mismatched."""


class AIBankMRMApprovalError(AIBankMRMError):
    """Package-integrity approval is absent or violates four-eyes."""


class AIBankMRMStaleError(AIBankMRMError):
    """Approved package authority no longer matches current authority."""


class AIBankMRMIdempotencyConflict(AIBankMRMError):
    """An operation identity was reused for different content."""


def enabled() -> bool:
    """Return true only for explicit ``[ai_bank_mrm] enable = true``."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("ai_bank_mrm")
    return isinstance(section, Mapping) and section.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise AIBankMRMConfigError(
            "bank MRM evidence packages are disabled; set [ai_bank_mrm] enable = true"
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
        raise ValueError("bank MRM package data must be finite JSON") from exc
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValueError("bank MRM package data exceeds the 256 KiB bound")
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
    if _EMAIL_RE.search(result) or _PHONE_RE.search(result) or _SSN_RE.search(result):
        raise ValueError(f"{label} must not contain personal contact data")
    if _RAW_PAYLOAD_RE.search(result):
        raise ValueError(f"{label} must not contain raw prompt or output material")
    if _PROHIBITED_CLAIM_RE.search(result):
        raise ValueError(f"{label} contains a prohibited assurance claim")
    return result


def _token(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    result = value.strip()
    if not _TOKEN_RE.fullmatch(result):
        raise ValueError(f"{label} must be a bounded identifier")
    if _SECRET_RE.search(result) or _RAW_PAYLOAD_RE.search(result):
        raise ValueError(f"{label} is invalid")
    return result


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return value.lower().removeprefix("sha256:")


def _asset_id(value: object) -> str:
    if not isinstance(value, str) or not _ASSET_RE.fullmatch(value):
        raise ValueError("asset_id must be an exact Model Risk asset id")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0 or result > 100_000_000_000.0:
        raise ValueError(f"{label} must be a positive finite timestamp")
    return result


def _human_ref(actor: object, label: str) -> str:
    if not isinstance(actor, str):
        raise ValueError(f"{label} must be an authenticated user principal")
    principal = actor.strip()
    if not principal.startswith("user:") or len(principal) <= 5 or len(principal) > 256:
        raise ValueError(f"{label} must be an authenticated user: principal")
    if _CONTROL_RE.search(principal) or _SECRET_RE.search(principal):
        raise ValueError(f"{label} is invalid")
    return _sha256({"human_principal": principal})


def _audit_actor(actor_ref: str) -> str:
    return f"user-ref:{actor_ref[:32]}"


def _tenant_ref() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if not tenant:
        raise AIBankMRMStateError(
            "bank MRM evidence packages require an explicit tenant authority"
        )
    return "TEN-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:24]


def _normalize_value(
    value: object,
    *,
    kind: str,
    allowed: frozenset[str] | None,
    label: str,
) -> str | int | float:
    if kind == "text":
        return _safe_text(value, label)
    if kind == "token":
        return _token(value, label)
    if kind == "choice":
        result = _token(value, label)
        if allowed is None or result not in allowed:
            raise ValueError(f"{label} is unsupported")
        return result
    if kind == "integer":
        return _integer(value, label, 0, 1_000_000_000)
    if kind == "timestamp":
        return _timestamp(value, label)
    raise ValueError(f"{label} has an unsupported field type")


def _derive_section_state(assertions: Sequence[Mapping[str, Any]]) -> str:
    states = {row["state"] for row in assertions}
    if states == {"verified"}:
        return "verified"
    if "missing" in states:
        return "missing"
    return "unverified"


def _normalize_evidence_ids(value: object, label: str) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{label} must be an array")
    if len(value) > _MAX_EVIDENCE:
        raise ValueError(f"{label} exceeds {_MAX_EVIDENCE} entries")
    result = sorted({_token(item, label) for item in value})
    if len(result) != len(value):
        raise ValueError(f"{label} must not contain duplicates")
    return result


def _normalize_section(value: object, name: str) -> dict[str, Any]:
    section = _closed(
        value,
        frozenset({"schema", "state", "assertions", "evidence_ids"}),
        name,
    )
    if section["schema"] != SECTION_SCHEMA:
        raise ValueError(f"{name} schema is unsupported")
    declared_state = _token(section["state"], f"{name} state")
    if declared_state not in _STATES:
        raise ValueError(f"{name} state is unsupported")
    assertions = section["assertions"]
    if isinstance(assertions, (str, bytes)) or not isinstance(assertions, Sequence):
        raise ValueError(f"{name} assertions must be an array")
    specs = _FIELD_SPECS[name]
    if len(assertions) != len(specs):
        raise ValueError(f"{name} must contain every required assertion exactly once")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in assertions:
        row = _closed(
            item,
            frozenset({"field", "state", "value"}),
            f"{name} assertion",
        )
        field = _token(row["field"], f"{name} field")
        if field not in specs or field in seen:
            raise ValueError(f"{name} assertion field is unknown or duplicated")
        seen.add(field)
        state = _token(row["state"], f"{name}.{field} state")
        if state not in _STATES:
            raise ValueError(f"{name}.{field} state is unsupported")
        if state == "verified":
            kind, allowed = specs[field]
            normalized_value: object = _normalize_value(
                row["value"], kind=kind, allowed=allowed, label=f"{name}.{field}"
            )
        else:
            if row["value"] is not None:
                raise ValueError(
                    f"{name}.{field} {state} state must not imply verified data"
                )
            normalized_value = None
        normalized.append({"field": field, "state": state, "value": normalized_value})
    if seen != set(specs):
        raise ValueError(f"{name} assertion fields are incomplete")
    normalized.sort(key=lambda row: row["field"])
    derived_state = _derive_section_state(normalized)
    if declared_state != derived_state:
        raise ValueError(f"{name} state does not match its assertion states")
    evidence_ids = _normalize_evidence_ids(
        section["evidence_ids"], f"{name} evidence_ids"
    )
    has_verified = any(row["state"] == "verified" for row in normalized)
    if has_verified and not evidence_ids:
        raise ValueError(f"{name} verified assertions must cite approved evidence")
    if not has_verified and evidence_ids:
        raise ValueError(f"{name} without verified assertions must not cite evidence")
    return {
        "schema": SECTION_SCHEMA,
        "state": derived_state,
        "assertions": normalized,
        "evidence_ids": evidence_ids,
    }


def _normalize_content(value: object) -> dict[str, Any]:
    content = _closed(value, _CONTENT_FIELDS, "package content")
    return {name: _normalize_section(content[name], name) for name in sorted(content)}


def _content_evidence_ids(content: Mapping[str, Any]) -> set[str]:
    return {
        evidence_id
        for section in content.values()
        for evidence_id in section["evidence_ids"]
    }


def _completeness_gaps(content: Mapping[str, Any]) -> list[str]:
    return [
        f"{section_name}.{assertion['field']}:{assertion['state']}"
        for section_name in sorted(content)
        for assertion in content[section_name]["assertions"]
        if assertion["state"] != "verified"
    ]


def _normalize_bindings(value: object) -> list[dict[str, str]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError("evidence_bindings must be an array")
    if len(value) > _MAX_EVIDENCE:
        raise ValueError(f"evidence_bindings exceeds {_MAX_EVIDENCE} entries")
    result: list[dict[str, str]] = []
    ids: set[str] = set()
    for item in value:
        row = _closed(
            item, frozenset({"evidence_id", "digest"}), "evidence binding"
        )
        evidence_id = _token(row["evidence_id"], "evidence_id")
        if evidence_id in ids:
            raise ValueError("evidence_bindings must not contain duplicates")
        ids.add(evidence_id)
        result.append(
            {"evidence_id": evidence_id, "digest": _digest(row["digest"], "digest")}
        )
    return sorted(result, key=lambda row: row["evidence_id"])


def _record_state(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in sorted(_RECORD_FIELDS - {"state_sha256"})}


class AIBankMRMService:
    """Prepare, version, approve, and export bounded MRM evidence packages."""

    def __init__(
        self,
        *,
        packages: GovernedRecordStore | None = None,
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
        self._packages = packages or _PACKAGES
        self._asset_lookup = asset_lookup
        self._evidence_resolver = evidence_resolver
        self._clock = clock
        self._enforce_feature = enforce_feature

    def _require_active(self) -> str:
        if self._enforce_feature:
            require_enabled()
        return _tenant_ref()

    def _now(self) -> float:
        source = self._clock or self._packages.authoritative_time
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
            raise AIBankMRMAssetError("Model Risk asset lookup failed") from exc
        if not isinstance(observation, Mapping):
            raise AIBankMRMAssetError("Model Risk asset does not exist")
        try:
            observed = _asset_id(observation.get("asset_id"))
            revision = _integer(
                observation.get("revision"), "asset revision", 1, 2**63 - 1
            )
            digest = _digest(
                observation.get("version_digest"), "asset version_digest"
            )
        except (TypeError, ValueError) as exc:
            raise AIBankMRMAssetError("Model Risk asset binding is malformed") from exc
        if observed != asset:
            raise AIBankMRMAssetError("Model Risk asset lookup changed identity")
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
            raise AIBankMRMEvidenceError("approved evidence lookup failed") from exc
        if not isinstance(row, Mapping):
            raise AIBankMRMEvidenceError("cited approved evidence does not exist")
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
            raise AIBankMRMEvidenceError(
                "resolved evidence binding is malformed"
            ) from exc
        if observed != evidence_id or digest != expected_digest:
            raise AIBankMRMEvidenceError("cited evidence digest changed")
        if row.get("status") != "approved":
            raise AIBankMRMEvidenceError("cited evidence is not approved")
        if "result" in row and row.get("result") != "passed":
            raise AIBankMRMEvidenceError("cited evidence is not a passing result")
        current = row.get("current") is True or row.get("freshness") == "current"
        if not current:
            raise AIBankMRMEvidenceError("cited evidence is not current")
        if "asset_id" in row and row.get("asset_id") != asset_id:
            raise AIBankMRMEvidenceError(
                "cited evidence belongs to a different Model Risk asset"
            )
        return {"evidence_id": evidence_id, "digest": digest}

    def _verify_evidence_set(
        self, bindings: Sequence[Mapping[str, str]], *, asset_id: str
    ) -> list[dict[str, str]]:
        return [self._verify_evidence(row, asset_id=asset_id) for row in bindings]

    @staticmethod
    def _record_id(tenant_ref: str, package_id: str) -> str:
        return f"BMP-{_sha256({'tenant_ref': tenant_ref, 'package_id': package_id})[:32]}"

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
        content_sha = _sha256(content)
        authority = {
            "version": number,
            "asset_binding": dict(asset_binding),
            "evidence_bindings": [dict(row) for row in evidence_bindings],
            "content_sha256": content_sha,
        }
        return {
            "version": number,
            "prepared_at": self._now(),
            "prepared_by_ref": actor_ref,
            "operation_sha256": operation_sha256,
            "asset_binding": dict(asset_binding),
            "evidence_bindings": [dict(row) for row in evidence_bindings],
            "content": copy.deepcopy(dict(content)),
            "content_sha256": content_sha,
            "authority_sha256": _sha256(authority),
            "approval": None,
        }

    def _validate_record(  # noqa: C901 - one fail-closed authority walk
        self, value: object, *, tenant_ref: str
    ) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise AIBankMRMStateError("stored bank MRM package is not an object")
        if set(value) - _RECORD_FIELDS - _STORE_METADATA or _RECORD_FIELDS - set(value):
            raise AIBankMRMStateError("stored bank MRM package shape is malformed")
        try:
            record = dict(value)
            if record["schema"] != PACKAGE_SCHEMA or record["tenant_ref"] != tenant_ref:
                raise ValueError("package schema or tenant binding mismatch")
            package_id = _token(record["package_id"], "package_id")
            asset = _asset_id(record["asset_id"])
            if record["id"] != self._record_id(tenant_ref, package_id):
                raise ValueError("package record identity mismatch")
            _digest(record["create_operation_sha256"], "create operation digest")
            versions = record["versions"]
            if (
                isinstance(versions, (str, bytes))
                or not isinstance(versions, list)
                or not 1 <= len(versions) <= _MAX_VERSIONS
            ):
                raise ValueError("package versions are malformed")
            for index, version in enumerate(versions, start=1):
                row = _closed(version, _VERSION_FIELDS, "package version")
                if _integer(row["version"], "version", 1, _MAX_VERSIONS) != index:
                    raise ValueError("package version sequence is malformed")
                prepared_at = _timestamp(row["prepared_at"], "prepared_at")
                prepared_ref = _digest(row["prepared_by_ref"], "prepared_by_ref")
                _digest(row["operation_sha256"], "operation_sha256")
                binding = _closed(
                    row["asset_binding"],
                    frozenset({"asset_id", "revision", "version_digest"}),
                    "asset binding",
                )
                if _asset_id(binding["asset_id"]) != asset:
                    raise ValueError("package version asset changed")
                _integer(binding["revision"], "asset revision", 1, 2**63 - 1)
                _digest(binding["version_digest"], "asset version digest")
                citations = _normalize_bindings(row["evidence_bindings"])
                if citations != row["evidence_bindings"]:
                    raise ValueError("evidence bindings are not canonical")
                content = _normalize_content(row["content"])
                if content != row["content"]:
                    raise ValueError("package content is not canonical")
                if {item["evidence_id"] for item in citations} != _content_evidence_ids(
                    content
                ):
                    raise ValueError("package evidence bindings do not match citations")
                content_sha = _digest(row["content_sha256"], "content_sha256")
                if content_sha != _sha256(content):
                    raise ValueError("package content digest mismatch")
                authority = {
                    "version": index,
                    "asset_binding": dict(binding),
                    "evidence_bindings": citations,
                    "content_sha256": content_sha,
                }
                authority_sha = _digest(row["authority_sha256"], "authority_sha256")
                if authority_sha != _sha256(authority):
                    raise ValueError("package authority digest mismatch")
                approval = row["approval"]
                if approval is not None:
                    approved = _closed(
                        approval,
                        frozenset(
                            {
                                "approved_at",
                                "approved_by_ref",
                                "authority_sha256",
                                "four_eyes",
                                "scope",
                            }
                        ),
                        "package approval",
                    )
                    if _timestamp(approved["approved_at"], "approved_at") < prepared_at:
                        raise ValueError("package approval predates preparation")
                    approved_ref = _digest(
                        approved["approved_by_ref"], "approved_by_ref"
                    )
                    if approved_ref == prepared_ref or approved["four_eyes"] is not True:
                        raise ValueError("package approval violates four-eyes")
                    if approved["scope"] != "package-integrity-only":
                        raise ValueError("package approval scope is unsafe")
                    if (
                        _digest(approved["authority_sha256"], "approval authority")
                        != authority_sha
                    ):
                        raise ValueError("package approval authority mismatch")
            expected_status = "approved" if versions[-1]["approval"] is not None else "draft"
            if record["status"] != expected_status:
                raise ValueError("package status is inconsistent")
            if _digest(record["state_sha256"], "state_sha256") != _sha256(
                _record_state(record)
            ):
                raise ValueError("package state digest mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise AIBankMRMStateError("stored bank MRM package is malformed") from exc
        return record

    def _currentness(self, version: Mapping[str, Any]) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        try:
            current_asset = self._asset_binding(version["asset_binding"]["asset_id"])
            if current_asset != version["asset_binding"]:
                reasons.append("asset_authority_changed")
        except AIBankMRMError:
            reasons.append("asset_authority_unavailable")
        for binding in version["evidence_bindings"]:
            try:
                self._verify_evidence(
                    binding, asset_id=version["asset_binding"]["asset_id"]
                )
            except AIBankMRMEvidenceError:
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
            "approval_scope": (
                None if not approved else version["approval"]["scope"]
            ),
            "four_eyes_approved": approved,
            "authority_fresh": fresh,
            "stale_reasons": reasons,
            "completeness_gaps": gaps,
            "complete": not gaps,
            "exportable": approved and fresh,
            "status": status,
        }

    def _public_record(self, record: Mapping[str, Any]) -> dict[str, Any]:
        versions = [self._version_projection(row) for row in record["versions"]]
        return {
            "schema": PACKAGE_SCHEMA,
            "package_id": record["package_id"],
            "asset_id": record["asset_id"],
            "revision": record["revision"],
            "status": versions[-1]["status"],
            "versions": versions,
            "notice": NOTICE,
        }

    def create_package(
        self,
        package_id: str,
        *,
        asset_id: str,
        content: Mapping[str, Any],
        evidence_bindings: Sequence[Mapping[str, str]],
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = _token(package_id, "package_id")
        actor_ref = _human_ref(actor, "preparer")
        operation = _safe_text(idempotency_key, "idempotency_key", 256)
        operation_sha = _sha256({"tenant_ref": tenant_ref, "operation": operation})
        normalized_content = _normalize_content(content)
        citations = _normalize_bindings(evidence_bindings)
        if {row["evidence_id"] for row in citations} != _content_evidence_ids(
            normalized_content
        ):
            raise ValueError(
                "evidence_bindings must exactly match all package content citations"
            )
        record_id = self._record_id(tenant_ref, semantic_id)
        existing = self._packages.get(record_id)
        if existing is not None:
            current = self._validate_record(existing, tenant_ref=tenant_ref)
            first = current["versions"][0]
            if (
                current["create_operation_sha256"] != operation_sha
                or first["asset_binding"]["asset_id"] != _asset_id(asset_id)
                or first["evidence_bindings"] != citations
                or first["content"] != normalized_content
            ):
                raise AIBankMRMIdempotencyConflict(
                    "package identity or idempotency key is bound to different content"
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
            "schema": PACKAGE_SCHEMA,
            "tenant_ref": tenant_ref,
            "package_id": semantic_id,
            "asset_id": asset["asset_id"],
            "versions": [version],
            "status": "draft",
            "create_operation_sha256": operation_sha,
        }
        record["state_sha256"] = _sha256(_record_state(record))
        try:
            saved = self._packages.create(
                record,
                action="prepare_ai_bank_mrm_package",
                actor=_audit_actor(actor_ref),
                max_records=_MAX_PACKAGES,
            )
        except RecordConflict as exc:
            concurrent = self._packages.get(record_id)
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
                raise AIBankMRMIdempotencyConflict(
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
        actor_ref = _human_ref(actor, "preparer")
        operation = _safe_text(idempotency_key, "idempotency_key", 256)
        operation_sha = _sha256({"tenant_ref": tenant_ref, "operation": operation})
        normalized_content = _normalize_content(content)
        citations = _normalize_bindings(evidence_bindings)
        if {row["evidence_id"] for row in citations} != _content_evidence_ids(
            normalized_content
        ):
            raise ValueError(
                "evidence_bindings must exactly match all package content citations"
            )
        record_id = self._record_id(tenant_ref, semantic_id)
        raw = self._packages.get(record_id)
        if raw is None:
            raise AIBankMRMStateError("bank MRM package does not exist")
        current = self._validate_record(raw, tenant_ref=tenant_ref)
        prior = [row for row in current["versions"] if row["operation_sha256"] == operation_sha]
        if prior:
            version = prior[0]
            if (
                version["evidence_bindings"] != citations
                or version["content"] != normalized_content
            ):
                raise AIBankMRMIdempotencyConflict(
                    "idempotency key is bound to a different package version"
                )
            return self._public_record(current)
        if current["revision"] != expected:
            raise RecordConflict(
                f"bank MRM package changed (expected revision {expected}, "
                f"found {current['revision']})"
            )
        if len(current["versions"]) >= _MAX_VERSIONS:
            raise AIBankMRMStateError("bank MRM package exceeds its version bound")
        asset = self._asset_binding(current["asset_id"])
        citations = self._verify_evidence_set(citations, asset_id=asset["asset_id"])
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
                raise RecordConflict("bank MRM package revision changed")
            row["versions"].append(next_version)
            row["status"] = "draft"
            row["state_sha256"] = _sha256(_record_state(row))

        saved = self._packages.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="prepare_ai_bank_mrm_package_version",
            actor=_audit_actor(actor_ref),
        )
        if saved is None:
            raise AIBankMRMStateError("bank MRM package disappeared")
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
        actor_ref = _human_ref(actor, "approver")
        record_id = self._record_id(tenant_ref, semantic_id)
        raw = self._packages.get(record_id)
        if raw is None:
            raise AIBankMRMStateError("bank MRM package does not exist")
        current = self._validate_record(raw, tenant_ref=tenant_ref)
        if current["revision"] != expected:
            raise RecordConflict(
                f"bank MRM package changed (expected revision {expected}, "
                f"found {current['revision']})"
            )
        if selected != len(current["versions"]):
            raise AIBankMRMApprovalError(
                "only the latest bank MRM package version can be approved"
            )
        candidate = current["versions"][selected - 1]
        if candidate["approval"] is not None:
            return self._public_record(current)
        if actor_ref == candidate["prepared_by_ref"]:
            raise AIBankMRMApprovalError(
                "four-eyes approval requires a different human than the preparer"
            )
        fresh, reasons = self._currentness(candidate)
        if not fresh:
            raise AIBankMRMStaleError(
                "bank MRM package authority is stale: " + ", ".join(reasons)
            )
        approved_at = self._now()
        if approved_at < candidate["prepared_at"]:
            raise AIBankMRMStateError(
                "approval authority time predates package preparation"
            )

        def mutate(row: dict[str, Any]) -> None:
            validated = self._validate_record(row, tenant_ref=tenant_ref)
            live = validated["versions"][selected - 1]
            if live["approval"] is not None:
                return
            if live["prepared_by_ref"] == actor_ref:
                raise AIBankMRMApprovalError("package violates four-eyes approval")
            live["approval"] = {
                "approved_at": approved_at,
                "approved_by_ref": actor_ref,
                "authority_sha256": live["authority_sha256"],
                "four_eyes": True,
                "scope": "package-integrity-only",
            }
            row["status"] = "approved"
            row["state_sha256"] = _sha256(_record_state(row))

        saved = self._packages.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="approve_ai_bank_mrm_package_integrity",
            actor=_audit_actor(actor_ref),
        )
        if saved is None:
            raise AIBankMRMStateError("bank MRM package disappeared")
        return self._public_record(self._validate_record(saved, tenant_ref=tenant_ref))

    def get_package(self, package_id: str) -> dict[str, Any] | None:
        tenant_ref = self._require_active()
        semantic_id = _token(package_id, "package_id")
        row = self._packages.get(self._record_id(tenant_ref, semantic_id))
        if row is None:
            return None
        return self._public_record(self._validate_record(row, tenant_ref=tenant_ref))

    def list_packages(self, *, limit: int = _MAX_LIST) -> list[dict[str, Any]]:
        tenant_ref = self._require_active()
        maximum = _integer(limit, "limit", 1, _MAX_LIST)
        result: list[dict[str, Any]] = []
        for raw in self._packages.list(limit=maximum):
            record = self._validate_record(raw, tenant_ref=tenant_ref)
            latest = self._version_projection(record["versions"][-1])
            result.append(
                {
                    "package_id": record["package_id"],
                    "asset_id": record["asset_id"],
                    "revision": record["revision"],
                    "latest_version": latest["version"],
                    "status": latest["status"],
                    "complete": latest["complete"],
                    "exportable": latest["exportable"],
                }
            )
        return sorted(result, key=lambda row: row["package_id"])

    def export_package(
        self, package_id: str, *, version: int | None = None
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = _token(package_id, "package_id")
        row = self._packages.get(self._record_id(tenant_ref, semantic_id))
        if row is None:
            raise AIBankMRMStateError("bank MRM package does not exist")
        record = self._validate_record(row, tenant_ref=tenant_ref)
        selected = (
            len(record["versions"])
            if version is None
            else _integer(version, "version", 1, len(record["versions"]))
        )
        candidate = record["versions"][selected - 1]
        if candidate["approval"] is None:
            raise AIBankMRMApprovalError(
                "bank MRM package version lacks four-eyes integrity approval"
            )
        fresh, reasons = self._currentness(candidate)
        if not fresh:
            raise AIBankMRMStaleError(
                "bank MRM package authority is stale: " + ", ".join(reasons)
            )
        gaps = _completeness_gaps(candidate["content"])
        packet = {
            "schema": EXPORT_SCHEMA,
            "package_id": record["package_id"],
            "version": selected,
            "prepared_at": candidate["prepared_at"],
            "approved_at": candidate["approval"]["approved_at"],
            "asset_binding": copy.deepcopy(candidate["asset_binding"]),
            "evidence_bindings": copy.deepcopy(candidate["evidence_bindings"]),
            "content": copy.deepcopy(candidate["content"]),
            "content_sha256": candidate["content_sha256"],
            "authority_sha256": candidate["authority_sha256"],
            "completeness": {"complete": not gaps, "gaps": gaps},
            "approval": {
                "package_integrity_reviewed": True,
                "four_eyes": True,
                "authority_fresh": True,
                "scope": "package-integrity-only",
            },
            "claims": {
                "model_approved": False,
                "validation_conclusion": False,
                "compliance_determination": False,
                "certification": False,
                "regulatory_acceptance": False,
                "supervisory_acceptance": False,
            },
            "notice": NOTICE,
        }
        return {**packet, "packet_sha256": _sha256(packet)}


_DEFAULT = AIBankMRMService()


def configured_bank_mrm() -> AIBankMRMService:
    require_enabled()
    return _DEFAULT


def configured_service() -> AIBankMRMService:
    return configured_bank_mrm()


__all__ = [
    "AIBankMRMApprovalError",
    "AIBankMRMAssetError",
    "AIBankMRMConfigError",
    "AIBankMRMError",
    "AIBankMRMEvidenceError",
    "AIBankMRMIdempotencyConflict",
    "AIBankMRMService",
    "AIBankMRMStaleError",
    "AIBankMRMStateError",
    "EXPORT_SCHEMA",
    "NOTICE",
    "PACKAGE_SCHEMA",
    "SECTION_SCHEMA",
    "configured_bank_mrm",
    "configured_service",
    "enabled",
    "require_enabled",
]
