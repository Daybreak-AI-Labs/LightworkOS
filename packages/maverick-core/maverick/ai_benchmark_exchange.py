"""Privacy-bounded benchmark contribution and cohort-report governance.

This module is an intentionally small, default-off control plane.  It creates
human-approved aggregate contribution packets and admits externally produced
cohort reports after an injected signature verifier accepts them.  Its default
service has no network transport.  An operator may configure, or a caller may
explicitly inject, a trust-root verifier and an opt-in coordinator, but
transmission remains a separate, consent-bearing operation and no operation
pools records across tenants.

Only closed, bounded aggregate schemas are admitted.  Raw examples, prompts,
outputs, feature values, personal data, secrets, free-form customer labels,
and customer identifiers have no persistence or export path.  Export is
voluntary, requires two different authenticated humans, strips tenant identity,
and fails closed when any cited evidence is no longer current.

The cohort-report verifier proves only schema integrity, digest integrity, and
the configured external signature boundary.  A report is never described as
anonymous.  Differential-privacy parameters are reported only when complete;
this module does not implement privacy-budget accounting and therefore never
claims that differential privacy was independently verified.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import date, datetime, timezone
from typing import Any, Protocol

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

CONTRIBUTION_SCHEMA = "lightwork.ai-benchmark-contribution.v1"
CONTRIBUTION_EXPORT_SCHEMA = "lightwork.ai-benchmark-contribution-export.v1"
COHORT_REPORT_SCHEMA = "lightwork.ai-benchmark-cohort-report.v1"
COHORT_REPORT_PROJECTION_SCHEMA = "lightwork.ai-benchmark-cohort-report-projection.v1"

METHODOLOGY_NOTICE = (
    "Voluntary organization-level aggregates only. Results may have selection, "
    "measurement, survivorship, and cohort-composition bias and are not a "
    "population estimate or compliance determination."
)
PRIVACY_NOTICE = (
    "No raw records are included. Pseudonymity is not anonymity. Schema and "
    "signature verification do not prove re-identification resistance. "
    "Differential privacy is not independently verified by Lightwork."
)


class _CoordinatorSubmitter(Protocol):
    def submit(
        self,
        export_package: Mapping[str, Any],
        *,
        explicit_consent: bool,
        idempotency_key: str,
    ) -> Mapping[str, Any]: ...

SUPPORTED_METRICS = frozenset(
    {
        "control_coverage_rate",
        "eval_pass_rate",
        "human_review_rate",
        "incident_free_rate",
        "model_drift_free_rate",
        "policy_exception_free_rate",
        "red_team_pass_rate",
        "runtime_allow_rate",
    }
)
SUPPORTED_INDUSTRIES = frozenset(
    {
        "financial_services",
        "healthcare",
        "manufacturing",
        "public_sector",
        "retail",
        "technology",
        "other",
        "undisclosed",
    }
)
SUPPORTED_GEOGRAPHIES = frozenset(
    {
        "asia_pacific",
        "europe",
        "global",
        "latin_america",
        "middle_east_africa",
        "north_america",
        "undisclosed",
    }
)
SUPPORTED_ORG_SIZES = frozenset({"small", "midsize", "enterprise", "undisclosed"})
SUPPORTED_MODALITIES = frozenset(
    {"audio", "image", "multimodal", "tabular", "text", "video", "other"}
)
SUPPORTED_AGGREGATION_METHODS = frozenset(
    {"pooled_ratio", "weighted_mean_ratio", "unweighted_mean_ratio"}
)
SUPPORTED_NOISE_MECHANISMS = frozenset(
    {"discrete_gaussian", "gaussian", "laplace"}
)
SUPPORTED_SIGNATURE_ALGORITHMS = frozenset(
    {"ECDSA-P256-SHA256", "Ed25519", "RSA-PSS-SHA256"}
)
METHODOLOGY_VERSION = "benchmark-aggregate-v1"

_CONTRIBUTIONS = GovernedRecordStore(
    "ai_benchmark_contributions", "BXC", "ai_benchmark_contribution"
)
_REPORTS = GovernedRecordStore(
    "ai_benchmark_cohort_reports", "BXR", "ai_benchmark_cohort_report"
)

_CONTRIBUTION_ID_RE = re.compile(r"BCI-[0-9a-f]{32}\Z")
_EXPORTED_CONTRIBUTION_ID_RE = re.compile(r"BXC-[0-9a-f]{32}\Z")
_REPORT_ID_RE = re.compile(r"BXR-[0-9a-f]{32}\Z")
_EVIDENCE_ID_RE = re.compile(r"MRE-[0-9a-f]{32}\Z")
_KEY_ID_RE = re.compile(r"KEY-[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_SIGNATURE_RE = re.compile(r"[A-Za-z0-9+/=_-]{32,2048}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}|"
    r"\bsk-[A-Za-z0-9_-]{16,}|"
    r"\bAKIA[0-9A-Z]{16}\b)",
    re.IGNORECASE,
)

_MAX_CONTRIBUTIONS = 10_000
_MAX_REPORTS = 2_000
_MAX_LIST = 100
_MAX_VERSIONS = 50
_MAX_EVIDENCE = 32
_MAX_COUNT = 1_000_000_000_000
_MAX_JSON_BYTES = 256 * 1024
_MAX_FUTURE_SKEW_SECONDS = 300.0

_PERIOD_FIELDS = frozenset({"start", "end"})
_COHORT_FIELDS = frozenset(
    {"industry_code", "geography_code", "organization_size_code", "model_modality_code"}
)
_EVIDENCE_FIELDS = frozenset({"evidence_id", "digest"})
_CONTENT_FIELDS = frozenset(
    {"metric_code", "numerator", "denominator", "period", "cohort", "evidence_bindings"}
)
_CONSENT_FIELDS = frozenset({"voluntary_opt_in", "consented_at", "consented_by_ref"})
_APPROVAL_FIELDS = frozenset(
    {"approved_at", "approved_by_ref", "authority_sha256", "four_eyes"}
)
_VERSION_FIELDS = frozenset(
    {
        "version",
        "prepared_at",
        "prepared_by_ref",
        "operation_sha256",
        "consent",
        "content",
        "content_sha256",
        "authority_sha256",
        "approval",
    }
)
_CONTRIBUTION_RECORD_FIELDS = frozenset(
    {
        "id",
        "schema",
        "tenant_ref",
        "contribution_id",
        "versions",
        "status",
        "create_operation_sha256",
        "state_sha256",
    }
)
_REPORT_BODY_FIELDS = frozenset(
    {
        "schema",
        "report_id",
        "issued_at",
        "metric_code",
        "numerator",
        "denominator",
        "period",
        "cohort",
        "contributor_count",
        "k_anonymity_min",
        "aggregation_method",
        "privacy",
        "methodology_version",
    }
)
_PRIVACY_FIELDS = frozenset(
    {"state", "epsilon", "delta", "noise_mechanism"}
)
_SIGNATURE_FIELDS = frozenset({"algorithm", "key_id", "value"})
_INTEGRATION_CONFIG_FIELDS = frozenset({"enable", "trust_roots", "coordinator"})
_COORDINATOR_CONFIG_FIELDS = frozenset(
    {
        "enable",
        "origin",
        "timeout_seconds",
        "max_request_bytes",
        "max_response_bytes",
    }
)
_REPORT_INPUT_FIELDS = _REPORT_BODY_FIELDS | frozenset({"report_sha256", "signature"})
_REPORT_RECORD_FIELDS = frozenset(
    {
        "id",
        "schema",
        "tenant_ref",
        "report_id",
        "body",
        "report_sha256",
        "signature",
        "ingested_at",
        "ingested_by_ref",
        "verification",
        "state_sha256",
    }
)
_VERIFICATION_FIELDS = frozenset(
    {"signature_verified", "verified_at", "algorithm", "key_id_sha256"}
)
_STORE_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})


class AIBenchmarkExchangeError(RuntimeError):
    """Base error for the bounded benchmark exchange."""


class AIBenchmarkExchangeConfigError(AIBenchmarkExchangeError):
    """The explicitly default-off capability is unavailable."""


class AIBenchmarkExchangeStateError(AIBenchmarkExchangeError):
    """Persisted contribution or report state is malformed."""


class AIBenchmarkExchangeEvidenceError(AIBenchmarkExchangeError):
    """Bound evidence is absent, stale, unapproved, or digest-mismatched."""


class AIBenchmarkExchangeConsentError(AIBenchmarkExchangeError):
    """Voluntary opt-in or four-eyes export approval is missing."""


class AIBenchmarkExchangeStaleError(AIBenchmarkExchangeError):
    """Approved contribution evidence is no longer current."""


class AIBenchmarkExchangeVerificationError(AIBenchmarkExchangeError):
    """An external cohort report failed digest or signature verification."""


class AIBenchmarkExchangeIdempotencyConflict(AIBenchmarkExchangeError):
    """An identity or operation was reused with different content."""


def enabled() -> bool:
    """Return true only for explicit ``[ai_benchmark_exchange] enable = true``."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("ai_benchmark_exchange")
    return isinstance(section, Mapping) and section.get("enable") is True


def require_enabled() -> None:
    if not enabled():
        raise AIBenchmarkExchangeConfigError(
            "AI benchmark exchange is disabled; set "
            "[ai_benchmark_exchange] enable = true"
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
        raise ValueError("benchmark data must be finite JSON") from exc
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValueError("benchmark data exceeds the 256 KiB bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _closed(value: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    if set(value) != fields:
        raise ValueError(f"{label} has unexpected or missing fields")
    return value


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


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0 or result > 100_000_000_000.0:
        raise ValueError(f"{label} must be a positive finite timestamp")
    return result


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return value.lower().removeprefix("sha256:")


def _token(value: object, label: str) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise ValueError(f"{label} must be a bounded identifier")
    if _CONTROL_RE.search(value) or _SECRET_RE.search(value):
        raise ValueError(f"{label} is invalid")
    return value


def _choice(value: object, choices: frozenset[str], label: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"{label} is not in the closed taxonomy")
    return value


def _date(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 10:
        raise ValueError(f"{label} must be an ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO date") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"{label} must be a canonical ISO date")
    return value


def _human_ref(actor: object, label: str) -> tuple[str, str]:
    if not isinstance(actor, str):
        raise ValueError(f"{label} must be an authenticated user principal")
    principal = actor.strip()
    if not principal.startswith("user:") or len(principal) <= 5 or len(principal) > 256:
        raise ValueError(f"{label} must be an authenticated user: principal")
    if _CONTROL_RE.search(principal) or _SECRET_RE.search(principal):
        raise ValueError(f"{label} is invalid")
    return principal, _sha256({"human_principal": principal})


def _audit_actor(actor_ref: str) -> str:
    return f"user-ref:{actor_ref[:32]}"


def _tenant_ref() -> str:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if not tenant:
        raise AIBenchmarkExchangeStateError(
            "AI benchmark exchange requires an explicit tenant authority"
        )
    return "TEN-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:24]


def _normalize_period(value: object) -> dict[str, str]:
    row = _closed(value, _PERIOD_FIELDS, "period")
    start = _date(row["start"], "period.start")
    end = _date(row["end"], "period.end")
    if start > end:
        raise ValueError("period.start must not follow period.end")
    return {"start": start, "end": end}


def _normalize_cohort(value: object) -> dict[str, str]:
    row = _closed(value, _COHORT_FIELDS, "cohort")
    return {
        "industry_code": _choice(
            row["industry_code"], SUPPORTED_INDUSTRIES, "cohort.industry_code"
        ),
        "geography_code": _choice(
            row["geography_code"], SUPPORTED_GEOGRAPHIES, "cohort.geography_code"
        ),
        "organization_size_code": _choice(
            row["organization_size_code"],
            SUPPORTED_ORG_SIZES,
            "cohort.organization_size_code",
        ),
        "model_modality_code": _choice(
            row["model_modality_code"],
            SUPPORTED_MODALITIES,
            "cohort.model_modality_code",
        ),
    }


def _normalize_evidence(value: object) -> list[dict[str, str]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError("evidence_bindings must be an array")
    if not 1 <= len(value) <= _MAX_EVIDENCE:
        raise ValueError(f"evidence_bindings must contain 1 to {_MAX_EVIDENCE} entries")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value:
        row = _closed(item, _EVIDENCE_FIELDS, "evidence binding")
        evidence_id = row["evidence_id"]
        if not isinstance(evidence_id, str) or not _EVIDENCE_ID_RE.fullmatch(evidence_id):
            raise ValueError("evidence_id must be an exact Model Risk evidence id")
        if evidence_id in seen:
            raise ValueError("evidence_id entries must be unique")
        seen.add(evidence_id)
        result.append(
            {"evidence_id": evidence_id, "digest": _digest(row["digest"], "evidence digest")}
        )
    return sorted(result, key=lambda row: row["evidence_id"])


def _normalize_content(
    *,
    metric_code: object,
    numerator: object,
    denominator: object,
    period: object,
    cohort: object,
    evidence_bindings: object,
) -> dict[str, Any]:
    metric = _choice(metric_code, SUPPORTED_METRICS, "metric_code")
    num = _integer(numerator, "numerator", 0, _MAX_COUNT)
    den = _integer(denominator, "denominator", 1, _MAX_COUNT)
    if num > den:
        raise ValueError("numerator must not exceed denominator")
    return {
        "metric_code": metric,
        "numerator": num,
        "denominator": den,
        "period": _normalize_period(period),
        "cohort": _normalize_cohort(cohort),
        "evidence_bindings": _normalize_evidence(evidence_bindings),
    }


def _normalize_stored_content(value: object) -> dict[str, Any]:
    row = _closed(value, _CONTENT_FIELDS, "stored contribution content")
    return _normalize_content(
        metric_code=row["metric_code"],
        numerator=row["numerator"],
        denominator=row["denominator"],
        period=row["period"],
        cohort=row["cohort"],
        evidence_bindings=row["evidence_bindings"],
    )


def _record_state(record: Mapping[str, Any], fields: frozenset[str]) -> dict[str, Any]:
    return {key: record[key] for key in sorted(fields - {"state_sha256"})}


def _normalize_privacy(value: object) -> dict[str, Any]:
    row = _closed(value, _PRIVACY_FIELDS, "privacy")
    state = row["state"]
    if state == "not_dp":
        if any(row[key] is not None for key in ("epsilon", "delta", "noise_mechanism")):
            raise ValueError("not_dp reports must not provide differential-privacy parameters")
        return {
            "state": "not_dp",
            "epsilon": None,
            "delta": None,
            "noise_mechanism": None,
        }
    if state != "differential_privacy":
        raise ValueError("privacy.state must be not_dp or differential_privacy")
    epsilon = _number(row["epsilon"], "privacy.epsilon", 1e-12, 1_000_000.0)
    delta = _number(row["delta"], "privacy.delta", 0.0, 0.999999999999)
    mechanism = _choice(
        row["noise_mechanism"], SUPPORTED_NOISE_MECHANISMS, "privacy.noise_mechanism"
    )
    return {
        "state": "differential_privacy",
        "epsilon": epsilon,
        "delta": delta,
        "noise_mechanism": mechanism,
    }


def _normalize_signature(value: object) -> dict[str, str]:
    row = _closed(value, _SIGNATURE_FIELDS, "signature")
    algorithm = _choice(
        row["algorithm"], SUPPORTED_SIGNATURE_ALGORITHMS, "signature.algorithm"
    )
    key_id = row["key_id"]
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        raise ValueError("signature.key_id must be an opaque key id")
    signature = row["value"]
    if not isinstance(signature, str) or not _SIGNATURE_RE.fullmatch(signature):
        raise ValueError("signature.value must be bounded base64url, base64, or hex text")
    return {"algorithm": algorithm, "key_id": key_id, "value": signature}


def _normalize_report(value: object) -> tuple[dict[str, Any], str, dict[str, str]]:
    row = _closed(value, _REPORT_INPUT_FIELDS, "cohort report")
    if row["schema"] != COHORT_REPORT_SCHEMA:
        raise ValueError("cohort report schema is unsupported")
    report_id = row["report_id"]
    if not isinstance(report_id, str) or not _REPORT_ID_RE.fullmatch(report_id):
        raise ValueError("report_id must be a bounded pseudonymous report id")
    num = _integer(row["numerator"], "numerator", 0, _MAX_COUNT)
    den = _integer(row["denominator"], "denominator", 1, _MAX_COUNT)
    if num > den:
        raise ValueError("numerator must not exceed denominator")
    contributor_count = _integer(
        row["contributor_count"], "contributor_count", 5, _MAX_COUNT
    )
    k_min = _integer(row["k_anonymity_min"], "k_anonymity_min", 5, _MAX_COUNT)
    if contributor_count < k_min:
        raise ValueError("contributor_count must satisfy k_anonymity_min")
    body = {
        "schema": COHORT_REPORT_SCHEMA,
        "report_id": report_id,
        "issued_at": _timestamp(row["issued_at"], "issued_at"),
        "metric_code": _choice(row["metric_code"], SUPPORTED_METRICS, "metric_code"),
        "numerator": num,
        "denominator": den,
        "period": _normalize_period(row["period"]),
        "cohort": _normalize_cohort(row["cohort"]),
        "contributor_count": contributor_count,
        "k_anonymity_min": k_min,
        "aggregation_method": _choice(
            row["aggregation_method"],
            SUPPORTED_AGGREGATION_METHODS,
            "aggregation_method",
        ),
        "privacy": _normalize_privacy(row["privacy"]),
        "methodology_version": row["methodology_version"],
    }
    if body["methodology_version"] != METHODOLOGY_VERSION:
        raise ValueError("cohort report methodology_version is unsupported")
    expected = _digest(row["report_sha256"], "report_sha256")
    if not hmac.compare_digest(expected, _sha256(body)):
        raise AIBenchmarkExchangeVerificationError("cohort report digest is invalid")
    return body, expected, _normalize_signature(row["signature"])


def _default_pseudonym(tenant_ref: str, contribution_id: str) -> str:
    # The existing privacy salt is a persistent deployment secret, not exported.
    # Tenant binding in the MAC prevents cross-tenant correlation.
    from .privacy import _anon_salt

    material = f"ai-benchmark-exchange-v1\0{tenant_ref}\0{contribution_id}".encode()
    digest = hmac.new(_anon_salt(), material, hashlib.sha256).hexdigest()[:32]
    return f"BXC-{digest}"


class AIBenchmarkExchangeService:
    """Govern voluntary aggregate exports and verified external reports."""

    def __init__(
        self,
        *,
        contributions: GovernedRecordStore | None = None,
        reports: GovernedRecordStore | None = None,
        evidence_resolver: Callable[[str], Mapping[str, Any] | None] | None = None,
        signature_verifier: Callable[[bytes, Mapping[str, str]], bool] | None = None,
        trust_roots: Callable[[bytes, Mapping[str, str]], bool] | None = None,
        coordinator: _CoordinatorSubmitter | None = None,
        pseudonymizer: Callable[[str, str], str] | None = None,
        clock: Callable[[], float] | None = None,
        enforce_feature: bool = True,
    ) -> None:
        if signature_verifier is not None and trust_roots is not None:
            raise ValueError(
                "signature_verifier and trust_roots are mutually exclusive"
            )
        for callback, label in (
            (evidence_resolver, "evidence_resolver"),
            (signature_verifier, "signature_verifier"),
            (trust_roots, "trust_roots"),
            (pseudonymizer, "pseudonymizer"),
            (clock, "clock"),
        ):
            if callback is not None and not callable(callback):
                raise ValueError(f"{label} must be callable")
        if not isinstance(enforce_feature, bool):
            raise ValueError("enforce_feature must be a boolean")
        if coordinator is not None and (
            not hasattr(coordinator, "submit") or not callable(coordinator.submit)
        ):
            raise ValueError("coordinator must provide a callable submit method")
        self._contributions = contributions or _CONTRIBUTIONS
        self._reports = reports or _REPORTS
        self._evidence_resolver = evidence_resolver
        self._signature_verifier = (
            trust_roots if trust_roots is not None else signature_verifier
        )
        self._coordinator = coordinator
        self._pseudonymizer = pseudonymizer or _default_pseudonym
        self._clock = clock
        self._enforce_feature = enforce_feature

    def _require_active(self) -> str:
        if self._enforce_feature:
            require_enabled()
        return _tenant_ref()

    def _now(self) -> float:
        source = self._clock or self._contributions.authoritative_time
        return _timestamp(source(), "authority time")

    @staticmethod
    def _contribution_record_id(tenant_ref: str, contribution_id: str) -> str:
        return "BXC-" + _sha256(
            {"tenant_ref": tenant_ref, "contribution_id": contribution_id}
        )[:32]

    @staticmethod
    def _report_record_id(tenant_ref: str, report_id: str) -> str:
        return "BXR-" + _sha256({"tenant_ref": tenant_ref, "report_id": report_id})[:32]

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
            raise AIBenchmarkExchangeEvidenceError("approved evidence lookup failed") from exc
        if not isinstance(row, Mapping):
            raise AIBenchmarkExchangeEvidenceError("bound evidence does not exist")
        return row

    def _verify_evidence(self, binding: Mapping[str, str]) -> dict[str, str]:
        evidence_id = binding["evidence_id"]
        expected = binding["digest"]
        row = self._evidence_lookup(evidence_id)
        observed_id = row.get("evidence_id", row.get("id"))
        digest_value = row.get("digest", row.get("evidence_digest", row.get("payload_sha256")))
        try:
            observed_digest = _digest(digest_value, "resolved evidence digest")
        except (TypeError, ValueError) as exc:
            raise AIBenchmarkExchangeEvidenceError(
                "resolved evidence binding is malformed"
            ) from exc
        if observed_id != evidence_id or not hmac.compare_digest(observed_digest, expected):
            raise AIBenchmarkExchangeEvidenceError("bound evidence identity or digest changed")
        if row.get("status") != "approved":
            raise AIBenchmarkExchangeEvidenceError("bound evidence is not approved")
        if "result" in row and row.get("result") != "passed":
            raise AIBenchmarkExchangeEvidenceError("bound evidence is not passing")
        if not (row.get("current") is True or row.get("freshness") == "current"):
            raise AIBenchmarkExchangeEvidenceError("bound evidence is not current")
        return {"evidence_id": evidence_id, "digest": observed_digest}

    def _verify_evidence_set(
        self, bindings: Sequence[Mapping[str, str]]
    ) -> list[dict[str, str]]:
        return [self._verify_evidence(row) for row in bindings]

    def _version(
        self,
        *,
        number: int,
        content: Mapping[str, Any],
        operation_sha256: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        now = self._now()
        end_date = date.fromisoformat(content["period"]["end"])
        now_date = datetime.fromtimestamp(now, timezone.utc).date()
        if end_date > now_date:
            raise ValueError("contribution period must be complete before preparation")
        content_sha = _sha256(content)
        authority = {
            "version": number,
            "content_sha256": content_sha,
            "evidence_bindings": content["evidence_bindings"],
            "voluntary_opt_in": True,
        }
        return {
            "version": number,
            "prepared_at": now,
            "prepared_by_ref": actor_ref,
            "operation_sha256": operation_sha256,
            "consent": {
                "voluntary_opt_in": True,
                "consented_at": now,
                "consented_by_ref": actor_ref,
            },
            "content": copy.deepcopy(dict(content)),
            "content_sha256": content_sha,
            "authority_sha256": _sha256(authority),
            "approval": None,
        }

    def _validate_contribution(  # noqa: C901
        self, value: object, *, tenant_ref: str
    ) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise AIBenchmarkExchangeStateError("stored contribution is not an object")
        if (
            set(value) - _CONTRIBUTION_RECORD_FIELDS - _STORE_METADATA
            or _CONTRIBUTION_RECORD_FIELDS - set(value)
        ):
            raise AIBenchmarkExchangeStateError("stored contribution shape is malformed")
        try:
            record = dict(value)
            if record["schema"] != CONTRIBUTION_SCHEMA or record["tenant_ref"] != tenant_ref:
                raise ValueError("contribution schema or tenant mismatch")
            contribution_id = record["contribution_id"]
            if not isinstance(contribution_id, str) or not _CONTRIBUTION_ID_RE.fullmatch(
                contribution_id
            ):
                raise ValueError("contribution_id is malformed")
            if record["id"] != self._contribution_record_id(tenant_ref, contribution_id):
                raise ValueError("contribution identity mismatch")
            _integer(record["revision"], "revision", 1, 2**63 - 1)
            _timestamp(record["created_at"], "created_at")
            _timestamp(record["updated_at"], "updated_at")
            _digest(record["create_operation_sha256"], "create operation digest")
            versions = record["versions"]
            if not isinstance(versions, list) or not 1 <= len(versions) <= _MAX_VERSIONS:
                raise ValueError("contribution versions are malformed")
            for index, candidate in enumerate(versions, start=1):
                version = _closed(candidate, _VERSION_FIELDS, "stored contribution version")
                if version["version"] != index:
                    raise ValueError("contribution versions are not contiguous")
                prepared_at = _timestamp(version["prepared_at"], "prepared_at")
                prepared_ref = _digest(version["prepared_by_ref"], "prepared_by_ref")
                _digest(version["operation_sha256"], "operation_sha256")
                consent = _closed(version["consent"], _CONSENT_FIELDS, "stored consent")
                if consent["voluntary_opt_in"] is not True:
                    raise ValueError("stored contribution lacks voluntary opt-in")
                consented_at = _timestamp(consent["consented_at"], "consented_at")
                if consented_at != prepared_at:
                    raise ValueError("consent time differs from preparation time")
                if _digest(consent["consented_by_ref"], "consented_by_ref") != prepared_ref:
                    raise ValueError("consent authority differs from preparer")
                content = _normalize_stored_content(version["content"])
                if content != version["content"]:
                    raise ValueError("contribution content is not canonical")
                content_sha = _digest(version["content_sha256"], "content_sha256")
                if content_sha != _sha256(content):
                    raise ValueError("contribution content digest mismatch")
                authority = {
                    "version": index,
                    "content_sha256": content_sha,
                    "evidence_bindings": content["evidence_bindings"],
                    "voluntary_opt_in": True,
                }
                authority_sha = _digest(version["authority_sha256"], "authority_sha256")
                if authority_sha != _sha256(authority):
                    raise ValueError("contribution authority digest mismatch")
                approval = version["approval"]
                if approval is not None:
                    approved = _closed(approval, _APPROVAL_FIELDS, "stored approval")
                    if _timestamp(approved["approved_at"], "approved_at") < prepared_at:
                        raise ValueError("approval predates preparation")
                    approved_ref = _digest(approved["approved_by_ref"], "approved_by_ref")
                    if approved_ref == prepared_ref or approved["four_eyes"] is not True:
                        raise ValueError("approval violates four-eyes")
                    if _digest(approved["authority_sha256"], "approval authority") != authority_sha:
                        raise ValueError("approval authority mismatch")
            expected_status = "approved" if versions[-1]["approval"] is not None else "draft"
            if record["status"] != expected_status:
                raise ValueError("contribution status is inconsistent")
            expected_state = _sha256(_record_state(record, _CONTRIBUTION_RECORD_FIELDS))
            if _digest(record["state_sha256"], "state_sha256") != expected_state:
                raise ValueError("contribution state digest mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise AIBenchmarkExchangeStateError("stored contribution is malformed") from exc
        return record

    def _evidence_currentness(self, version: Mapping[str, Any]) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        for binding in version["content"]["evidence_bindings"]:
            try:
                self._verify_evidence(binding)
            except AIBenchmarkExchangeEvidenceError:
                reasons.append(f"evidence_authority_changed:{binding['evidence_id']}")
        return not reasons, reasons

    def _contribution_projection(self, record: Mapping[str, Any]) -> dict[str, Any]:
        versions: list[dict[str, Any]] = []
        for version in record["versions"]:
            fresh, reasons = self._evidence_currentness(version)
            approved = version["approval"] is not None
            status = "stale" if approved and not fresh else ("approved" if approved else "draft")
            versions.append(
                {
                    "version": version["version"],
                    "prepared_at": version["prepared_at"],
                    "content": copy.deepcopy(version["content"]),
                    "content_sha256": version["content_sha256"],
                    "authority_sha256": version["authority_sha256"],
                    "voluntary_opt_in": True,
                    "four_eyes_approved": approved,
                    "authority_fresh": fresh,
                    "stale_reasons": reasons,
                    "exportable": approved and fresh,
                    "status": status,
                }
            )
        return {
            "schema": CONTRIBUTION_SCHEMA,
            "contribution_id": record["contribution_id"],
            "revision": record["revision"],
            "status": versions[-1]["status"],
            "versions": versions,
        }

    @staticmethod
    def _normalize_contribution_id(value: object) -> str:
        if not isinstance(value, str) or not _CONTRIBUTION_ID_RE.fullmatch(value):
            raise ValueError("contribution_id must be a bounded internal identifier")
        return value

    def create_contribution(
        self,
        contribution_id: str,
        *,
        metric_code: str,
        numerator: int,
        denominator: int,
        period: Mapping[str, str],
        cohort: Mapping[str, str],
        evidence_bindings: Sequence[Mapping[str, str]],
        voluntary_opt_in: bool,
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = self._normalize_contribution_id(contribution_id)
        if voluntary_opt_in is not True:
            raise AIBenchmarkExchangeConsentError(
                "contribution requires explicit voluntary_opt_in = true"
            )
        _, actor_ref = _human_ref(actor, "consenting preparer")
        operation = _token(idempotency_key, "idempotency_key")
        operation_sha = _sha256({"tenant_ref": tenant_ref, "operation": operation})
        content = _normalize_content(
            metric_code=metric_code,
            numerator=numerator,
            denominator=denominator,
            period=period,
            cohort=cohort,
            evidence_bindings=evidence_bindings,
        )
        record_id = self._contribution_record_id(tenant_ref, semantic_id)
        existing = self._contributions.get(record_id)
        if existing is not None:
            current = self._validate_contribution(existing, tenant_ref=tenant_ref)
            first = current["versions"][0]
            if (
                current["create_operation_sha256"] != operation_sha
                or first["content"] != content
            ):
                raise AIBenchmarkExchangeIdempotencyConflict(
                    "contribution identity or idempotency key is already bound"
                )
            return self._contribution_projection(current)
        content["evidence_bindings"] = self._verify_evidence_set(
            content["evidence_bindings"]
        )
        version = self._version(
            number=1,
            content=content,
            operation_sha256=operation_sha,
            actor_ref=actor_ref,
        )
        record = {
            "id": record_id,
            "schema": CONTRIBUTION_SCHEMA,
            "tenant_ref": tenant_ref,
            "contribution_id": semantic_id,
            "versions": [version],
            "status": "draft",
            "create_operation_sha256": operation_sha,
        }
        record["state_sha256"] = _sha256(
            _record_state(record, _CONTRIBUTION_RECORD_FIELDS)
        )
        try:
            saved = self._contributions.create(
                record,
                action="prepare_ai_benchmark_contribution",
                actor=_audit_actor(actor_ref),
                max_records=_MAX_CONTRIBUTIONS,
            )
        except RecordConflict as exc:
            concurrent = self._contributions.get(record_id)
            if concurrent is None:
                raise
            current = self._validate_contribution(concurrent, tenant_ref=tenant_ref)
            if (
                current["create_operation_sha256"] != operation_sha
                or current["versions"][0]["content"] != content
            ):
                raise AIBenchmarkExchangeIdempotencyConflict(
                    "contribution was concurrently created with different content"
                ) from exc
            saved = current
        return self._contribution_projection(
            self._validate_contribution(saved, tenant_ref=tenant_ref)
        )

    def add_version(
        self,
        contribution_id: str,
        *,
        metric_code: str,
        numerator: int,
        denominator: int,
        period: Mapping[str, str],
        cohort: Mapping[str, str],
        evidence_bindings: Sequence[Mapping[str, str]],
        voluntary_opt_in: bool,
        expected_revision: int,
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = self._normalize_contribution_id(contribution_id)
        if voluntary_opt_in is not True:
            raise AIBenchmarkExchangeConsentError(
                "each contribution version requires explicit voluntary opt-in"
            )
        expected = _integer(expected_revision, "expected_revision", 1, 2**63 - 1)
        _, actor_ref = _human_ref(actor, "consenting preparer")
        operation = _token(idempotency_key, "idempotency_key")
        operation_sha = _sha256({"tenant_ref": tenant_ref, "operation": operation})
        content = _normalize_content(
            metric_code=metric_code,
            numerator=numerator,
            denominator=denominator,
            period=period,
            cohort=cohort,
            evidence_bindings=evidence_bindings,
        )
        record_id = self._contribution_record_id(tenant_ref, semantic_id)
        raw = self._contributions.get(record_id)
        if raw is None:
            raise AIBenchmarkExchangeStateError("benchmark contribution does not exist")
        current = self._validate_contribution(raw, tenant_ref=tenant_ref)
        latest = current["versions"][-1]
        if latest["operation_sha256"] == operation_sha:
            if latest["content"] != content:
                raise AIBenchmarkExchangeIdempotencyConflict(
                    "idempotency key is already bound to another version"
                )
            return self._contribution_projection(current)
        if current["revision"] != expected:
            raise RecordConflict(
                f"benchmark contribution changed (expected revision {expected}, "
                f"found {current['revision']})"
            )
        if len(current["versions"]) >= _MAX_VERSIONS:
            raise AIBenchmarkExchangeStateError("contribution version bound reached")
        content["evidence_bindings"] = self._verify_evidence_set(
            content["evidence_bindings"]
        )
        version = self._version(
            number=len(current["versions"]) + 1,
            content=content,
            operation_sha256=operation_sha,
            actor_ref=actor_ref,
        )

        def mutate(row: dict[str, Any]) -> None:
            validated = self._validate_contribution(row, tenant_ref=tenant_ref)
            if validated["revision"] != expected:
                raise RecordConflict("benchmark contribution revision changed")
            row["versions"].append(version)
            row["status"] = "draft"
            row["state_sha256"] = _sha256(
                _record_state(row, _CONTRIBUTION_RECORD_FIELDS)
            )

        saved = self._contributions.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="prepare_ai_benchmark_contribution_version",
            actor=_audit_actor(actor_ref),
        )
        if saved is None:
            raise AIBenchmarkExchangeStateError("benchmark contribution disappeared")
        return self._contribution_projection(
            self._validate_contribution(saved, tenant_ref=tenant_ref)
        )

    def approve_contribution(
        self,
        contribution_id: str,
        version: int,
        *,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = self._normalize_contribution_id(contribution_id)
        selected = _integer(version, "version", 1, _MAX_VERSIONS)
        expected = _integer(expected_revision, "expected_revision", 1, 2**63 - 1)
        _, actor_ref = _human_ref(actor, "approver")
        record_id = self._contribution_record_id(tenant_ref, semantic_id)
        raw = self._contributions.get(record_id)
        if raw is None:
            raise AIBenchmarkExchangeStateError("benchmark contribution does not exist")
        current = self._validate_contribution(raw, tenant_ref=tenant_ref)
        if current["revision"] != expected:
            raise RecordConflict("benchmark contribution revision changed")
        if selected != len(current["versions"]):
            raise AIBenchmarkExchangeConsentError("only the latest version can be approved")
        candidate = current["versions"][selected - 1]
        if candidate["approval"] is not None:
            return self._contribution_projection(current)
        if actor_ref == candidate["prepared_by_ref"]:
            raise AIBenchmarkExchangeConsentError(
                "four-eyes approval requires a different authenticated human"
            )
        fresh, reasons = self._evidence_currentness(candidate)
        if not fresh:
            raise AIBenchmarkExchangeStaleError(
                "contribution evidence is stale: " + ", ".join(reasons)
            )
        approved_at = self._now()
        if approved_at < candidate["prepared_at"]:
            raise AIBenchmarkExchangeStateError("approval predates preparation")

        def mutate(row: dict[str, Any]) -> None:
            validated = self._validate_contribution(row, tenant_ref=tenant_ref)
            live = validated["versions"][selected - 1]
            if live["approval"] is not None:
                return
            if live["prepared_by_ref"] == actor_ref:
                raise AIBenchmarkExchangeConsentError("approval violates four-eyes")
            live["approval"] = {
                "approved_at": approved_at,
                "approved_by_ref": actor_ref,
                "authority_sha256": live["authority_sha256"],
                "four_eyes": True,
            }
            row["status"] = "approved"
            row["state_sha256"] = _sha256(
                _record_state(row, _CONTRIBUTION_RECORD_FIELDS)
            )

        saved = self._contributions.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="approve_ai_benchmark_contribution",
            actor=_audit_actor(actor_ref),
        )
        if saved is None:
            raise AIBenchmarkExchangeStateError("benchmark contribution disappeared")
        return self._contribution_projection(
            self._validate_contribution(saved, tenant_ref=tenant_ref)
        )

    def get_contribution(self, contribution_id: str) -> dict[str, Any] | None:
        tenant_ref = self._require_active()
        semantic_id = self._normalize_contribution_id(contribution_id)
        row = self._contributions.get(
            self._contribution_record_id(tenant_ref, semantic_id)
        )
        if row is None:
            return None
        return self._contribution_projection(
            self._validate_contribution(row, tenant_ref=tenant_ref)
        )

    def list_contributions(self, *, limit: int = _MAX_LIST) -> list[dict[str, Any]]:
        tenant_ref = self._require_active()
        maximum = _integer(limit, "limit", 1, _MAX_LIST)
        result: list[dict[str, Any]] = []
        for raw in self._contributions.list(limit=maximum):
            record = self._validate_contribution(raw, tenant_ref=tenant_ref)
            projection = self._contribution_projection(record)
            result.append(
                {
                    "contribution_id": record["contribution_id"],
                    "revision": record["revision"],
                    "latest_version": len(record["versions"]),
                    "status": projection["status"],
                    "exportable": projection["versions"][-1]["exportable"],
                }
            )
        return sorted(result, key=lambda row: row["contribution_id"])

    def export_contribution(
        self, contribution_id: str, *, version: int | None = None
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        semantic_id = self._normalize_contribution_id(contribution_id)
        row = self._contributions.get(
            self._contribution_record_id(tenant_ref, semantic_id)
        )
        if row is None:
            raise AIBenchmarkExchangeStateError("benchmark contribution does not exist")
        record = self._validate_contribution(row, tenant_ref=tenant_ref)
        selected = len(record["versions"]) if version is None else _integer(
            version, "version", 1, len(record["versions"])
        )
        candidate = record["versions"][selected - 1]
        if candidate["approval"] is None:
            raise AIBenchmarkExchangeConsentError(
                "contribution version lacks four-eyes human approval"
            )
        fresh, reasons = self._evidence_currentness(candidate)
        if not fresh:
            raise AIBenchmarkExchangeStaleError(
                "contribution evidence is stale: " + ", ".join(reasons)
            )
        pseudonym = self._pseudonymizer(tenant_ref, semantic_id)
        if not isinstance(pseudonym, str) or not _EXPORTED_CONTRIBUTION_ID_RE.fullmatch(
            pseudonym
        ):
            raise AIBenchmarkExchangeStateError(
                "pseudonymizer did not return a bounded pseudonymous id"
            )
        content = candidate["content"]
        packet = {
            "schema": CONTRIBUTION_EXPORT_SCHEMA,
            "pseudonymous_contribution_id": pseudonym,
            "version": selected,
            "metric_code": content["metric_code"],
            "numerator": content["numerator"],
            "denominator": content["denominator"],
            "period": copy.deepcopy(content["period"]),
            "cohort": copy.deepcopy(content["cohort"]),
            "evidence_bindings": copy.deepcopy(content["evidence_bindings"]),
            "content_sha256": candidate["content_sha256"],
            "authority_sha256": candidate["authority_sha256"],
            "approval": {
                "voluntary_opt_in": True,
                "human_approved": True,
                "four_eyes": True,
                "evidence_current": True,
            },
            "methodology": {
                "aggregation_level": "organization",
                "calculation": "bounded_numerator_divided_by_denominator",
                "sampling_basis": "voluntary_opt_in",
            },
            "privacy": {
                "raw_records_included": False,
                "tenant_identity_included": False,
                "customer_identifiers_included": False,
                "anonymity_claim": False,
                "differential_privacy_claim": False,
                "privacy_budget_accounting": "unsupported",
            },
            "limitations": [METHODOLOGY_NOTICE, PRIVACY_NOTICE],
        }
        return {**packet, "packet_sha256": _sha256(packet)}

    def submit_contribution_to_coordinator(
        self,
        contribution_id: str,
        *,
        explicit_consent: bool,
        idempotency_key: str,
        version: int | None = None,
    ) -> dict[str, Any]:
        """Explicitly submit one already-approved aggregate export.

        This method never discovers or constructs a coordinator.  The injected
        coordinator remains responsible for HTTPS policy, response validation,
        and ambiguous-delivery handling.
        """

        self._require_active()
        if explicit_consent is not True:
            raise AIBenchmarkExchangeConsentError(
                "literal consent is required for coordinator submission"
            )
        coordinator = self._coordinator
        if coordinator is None:
            raise AIBenchmarkExchangeConfigError(
                "AI benchmark coordinator is not configured"
            )
        operation = _token(idempotency_key, "idempotency_key")
        package = self.export_contribution(contribution_id, version=version)
        receipt = coordinator.submit(
            copy.deepcopy(package),
            explicit_consent=True,
            idempotency_key=operation,
        )
        if not isinstance(receipt, Mapping):
            raise AIBenchmarkExchangeStateError(
                "benchmark coordinator returned a malformed receipt"
            )
        try:
            _canonical(receipt)
        except ValueError as exc:
            raise AIBenchmarkExchangeStateError(
                "benchmark coordinator returned a malformed receipt"
            ) from exc
        return copy.deepcopy(dict(receipt))

    def _validate_report_record(
        self, value: object, *, tenant_ref: str
    ) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise AIBenchmarkExchangeStateError("stored cohort report is not an object")
        if (
            set(value) - _REPORT_RECORD_FIELDS - _STORE_METADATA
            or _REPORT_RECORD_FIELDS - set(value)
        ):
            raise AIBenchmarkExchangeStateError("stored cohort report shape is malformed")
        try:
            record = dict(value)
            if record["schema"] != COHORT_REPORT_SCHEMA or record["tenant_ref"] != tenant_ref:
                raise ValueError("cohort report schema or tenant mismatch")
            report_id = record["report_id"]
            if not isinstance(report_id, str) or not _REPORT_ID_RE.fullmatch(report_id):
                raise ValueError("report_id is malformed")
            if record["id"] != self._report_record_id(tenant_ref, report_id):
                raise ValueError("cohort report identity mismatch")
            _integer(record["revision"], "revision", 1, 2**63 - 1)
            _timestamp(record["created_at"], "created_at")
            _timestamp(record["updated_at"], "updated_at")
            _timestamp(record["ingested_at"], "ingested_at")
            _digest(record["ingested_by_ref"], "ingested_by_ref")
            body_input = {
                **dict(_closed(record["body"], _REPORT_BODY_FIELDS, "stored report body")),
                "report_sha256": record["report_sha256"],
                "signature": record["signature"],
            }
            body, report_sha, signature = _normalize_report(body_input)
            if body != record["body"] or report_sha != record["report_sha256"]:
                raise ValueError("cohort report body is not canonical")
            if signature != record["signature"]:
                raise ValueError("cohort report signature is not canonical")
            verification = _closed(
                record["verification"], _VERIFICATION_FIELDS, "stored verification"
            )
            if verification["signature_verified"] is not True:
                raise ValueError("stored report was not signature verified")
            _timestamp(verification["verified_at"], "verified_at")
            if verification["algorithm"] != signature["algorithm"]:
                raise ValueError("verification algorithm changed")
            if _digest(verification["key_id_sha256"], "key_id_sha256") != _sha256(
                {"key_id": signature["key_id"]}
            ):
                raise ValueError("verification key identity changed")
            expected_state = _sha256(_record_state(record, _REPORT_RECORD_FIELDS))
            if _digest(record["state_sha256"], "state_sha256") != expected_state:
                raise ValueError("cohort report state digest mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise AIBenchmarkExchangeStateError("stored cohort report is malformed") from exc
        return record

    @staticmethod
    def _report_projection(record: Mapping[str, Any]) -> dict[str, Any]:
        body = record["body"]
        privacy = body["privacy"]
        dp_complete = privacy["state"] == "differential_privacy"
        return {
            "schema": COHORT_REPORT_PROJECTION_SCHEMA,
            **copy.deepcopy(body),
            "report_sha256": record["report_sha256"],
            "verification": {
                "signature_verified": True,
                "algorithm": record["verification"]["algorithm"],
                "key_id_sha256": record["verification"]["key_id_sha256"],
            },
            "privacy_assessment": {
                "k_threshold_structurally_satisfied": (
                    body["contributor_count"] >= body["k_anonymity_min"] >= 5
                ),
                "anonymity_verified": False,
                "differential_privacy_parameters_complete": dp_complete,
                "differential_privacy_verified": False,
                "privacy_budget_accounting": "unsupported",
            },
            "limitations": [METHODOLOGY_NOTICE, PRIVACY_NOTICE],
        }

    def ingest_cohort_report(
        self, report: Mapping[str, Any], *, actor: str
    ) -> dict[str, Any]:
        tenant_ref = self._require_active()
        _, actor_ref = _human_ref(actor, "report ingester")
        body, report_sha, signature = _normalize_report(report)
        now = self._now()
        if body["issued_at"] > now + _MAX_FUTURE_SKEW_SECONDS:
            raise AIBenchmarkExchangeVerificationError(
                "cohort report issuance time is too far in the future"
            )
        verifier = self._signature_verifier
        if verifier is None:
            raise AIBenchmarkExchangeVerificationError(
                "cohort report signature verifier is not configured"
            )
        try:
            verified = verifier(_canonical(body), copy.deepcopy(signature))
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise AIBenchmarkExchangeVerificationError(
                "cohort report signature verification failed"
            ) from exc
        if verified is not True:
            raise AIBenchmarkExchangeVerificationError(
                "cohort report signature is not valid"
            )
        report_id = body["report_id"]
        record_id = self._report_record_id(tenant_ref, report_id)
        existing = self._reports.get(record_id)
        if existing is not None:
            current = self._validate_report_record(existing, tenant_ref=tenant_ref)
            if (
                current["report_sha256"] != report_sha
                or current["signature"] != signature
            ):
                raise AIBenchmarkExchangeIdempotencyConflict(
                    "report identity is already bound to different signed content"
                )
            return self._report_projection(current)
        record = {
            "id": record_id,
            "schema": COHORT_REPORT_SCHEMA,
            "tenant_ref": tenant_ref,
            "report_id": report_id,
            "body": body,
            "report_sha256": report_sha,
            "signature": signature,
            "ingested_at": now,
            "ingested_by_ref": actor_ref,
            "verification": {
                "signature_verified": True,
                "verified_at": now,
                "algorithm": signature["algorithm"],
                "key_id_sha256": _sha256({"key_id": signature["key_id"]}),
            },
        }
        record["state_sha256"] = _sha256(_record_state(record, _REPORT_RECORD_FIELDS))
        try:
            saved = self._reports.create(
                record,
                action="ingest_ai_benchmark_cohort_report",
                actor=_audit_actor(actor_ref),
                max_records=_MAX_REPORTS,
            )
        except RecordConflict as exc:
            concurrent = self._reports.get(record_id)
            if concurrent is None:
                raise
            current = self._validate_report_record(concurrent, tenant_ref=tenant_ref)
            if (
                current["report_sha256"] != report_sha
                or current["signature"] != signature
            ):
                raise AIBenchmarkExchangeIdempotencyConflict(
                    "report was concurrently created with different signed content"
                ) from exc
            saved = current
        return self._report_projection(
            self._validate_report_record(saved, tenant_ref=tenant_ref)
        )

    def get_cohort_report(self, report_id: str) -> dict[str, Any] | None:
        tenant_ref = self._require_active()
        if not isinstance(report_id, str) or not _REPORT_ID_RE.fullmatch(report_id):
            raise ValueError("report_id must be a bounded pseudonymous report id")
        row = self._reports.get(self._report_record_id(tenant_ref, report_id))
        if row is None:
            return None
        return self._report_projection(
            self._validate_report_record(row, tenant_ref=tenant_ref)
        )

    def list_cohort_reports(self, *, limit: int = _MAX_LIST) -> list[dict[str, Any]]:
        tenant_ref = self._require_active()
        maximum = _integer(limit, "limit", 1, _MAX_LIST)
        result = [
            self._report_projection(
                self._validate_report_record(row, tenant_ref=tenant_ref)
            )
            for row in self._reports.list(limit=maximum)
        ]
        return sorted(result, key=lambda row: row["report_id"])


_DEFAULT = AIBenchmarkExchangeService()


def _operator_configured_integrations() -> tuple[
    Callable[[bytes, Mapping[str, str]], bool] | None,
    _CoordinatorSubmitter | None,
]:
    """Parse the closed deployment-global benchmark integration section."""

    try:
        from .config import config_source_errors, load_global_config

        config = load_global_config()
        source_errors = config_source_errors(include_tenant=False)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise AIBenchmarkExchangeConfigError(
            "AI benchmark exchange operator configuration is unavailable"
        ) from exc
    if source_errors:
        raise AIBenchmarkExchangeConfigError(
            "AI benchmark exchange operator configuration is unreadable"
        )
    if not isinstance(config, Mapping):
        raise AIBenchmarkExchangeConfigError(
            "AI benchmark exchange operator configuration is malformed"
        )
    section = config.get("ai_benchmark_exchange")
    if not isinstance(section, Mapping):
        raise AIBenchmarkExchangeConfigError(
            "AI benchmark exchange is disabled; set "
            "[ai_benchmark_exchange] enable = true"
        )
    if set(section) - _INTEGRATION_CONFIG_FIELDS:
        raise AIBenchmarkExchangeConfigError(
            "AI benchmark exchange configuration contains unknown fields"
        )
    feature_enabled = section.get("enable")
    if feature_enabled is not True and feature_enabled is not False:
        raise AIBenchmarkExchangeConfigError(
            "ai_benchmark_exchange.enable must be a boolean"
        )
    if feature_enabled is not True:
        raise AIBenchmarkExchangeConfigError(
            "AI benchmark exchange is disabled; set "
            "[ai_benchmark_exchange] enable = true"
        )

    has_trust_roots = "trust_roots" in section
    has_coordinator = "coordinator" in section
    if not has_trust_roots and not has_coordinator:
        return None, None

    from .ai_benchmark_exchange_transport import (
        BenchmarkCoordinatorClient,
        BenchmarkExchangeTransportError,
        CoordinatorTransportLimits,
        VersionedEd25519TrustRoots,
        validated_coordinator_origin,
    )

    trust_roots = None
    coordinator = None
    try:
        if has_trust_roots:
            trust_roots = VersionedEd25519TrustRoots.from_document(
                section["trust_roots"]
            )
        if has_coordinator:
            table = section["coordinator"]
            if not isinstance(table, Mapping):
                raise AIBenchmarkExchangeConfigError(
                    "ai_benchmark_exchange.coordinator must be a table"
                )
            if set(table) - _COORDINATOR_CONFIG_FIELDS:
                raise AIBenchmarkExchangeConfigError(
                    "AI benchmark coordinator configuration contains unknown fields"
                )
            if "enable" not in table or not isinstance(table["enable"], bool):
                raise AIBenchmarkExchangeConfigError(
                    "ai_benchmark_exchange.coordinator.enable must be a boolean"
                )
            limits = CoordinatorTransportLimits(
                timeout_seconds=table.get("timeout_seconds", 15.0),
                max_request_bytes=table.get("max_request_bytes", 128 * 1024),
                max_response_bytes=table.get("max_response_bytes", 128 * 1024),
            )
            origin = None
            if "origin" in table:
                origin = validated_coordinator_origin(table["origin"])
            if table["enable"] is True:
                if origin is None:
                    raise AIBenchmarkExchangeConfigError(
                        "enabled AI benchmark coordinator requires origin"
                    )
                coordinator = BenchmarkCoordinatorClient(
                    coordinator_origin=origin,
                    enabled=True,
                    limits=limits,
                )
    except AIBenchmarkExchangeConfigError:
        raise
    except BenchmarkExchangeTransportError as exc:
        raise AIBenchmarkExchangeConfigError(
            "AI benchmark exchange integration configuration is invalid"
        ) from exc
    return trust_roots, coordinator


def configured_benchmark_exchange(
    *,
    trust_roots: Callable[[bytes, Mapping[str, str]], bool] | None = None,
    coordinator: _CoordinatorSubmitter | None = None,
) -> AIBenchmarkExchangeService:
    """Return the local default or a bounded configured/injected integration."""

    if trust_roots is not None or coordinator is not None:
        require_enabled()
        return AIBenchmarkExchangeService(
            trust_roots=trust_roots,
            coordinator=coordinator,
        )
    configured_roots, configured_coordinator = _operator_configured_integrations()
    if configured_roots is None and configured_coordinator is None:
        return _DEFAULT
    return AIBenchmarkExchangeService(
        trust_roots=configured_roots,
        coordinator=configured_coordinator,
    )


__all__ = [
    "AIBenchmarkExchangeConfigError",
    "AIBenchmarkExchangeConsentError",
    "AIBenchmarkExchangeError",
    "AIBenchmarkExchangeEvidenceError",
    "AIBenchmarkExchangeIdempotencyConflict",
    "AIBenchmarkExchangeService",
    "AIBenchmarkExchangeStaleError",
    "AIBenchmarkExchangeStateError",
    "AIBenchmarkExchangeVerificationError",
    "COHORT_REPORT_PROJECTION_SCHEMA",
    "COHORT_REPORT_SCHEMA",
    "CONTRIBUTION_EXPORT_SCHEMA",
    "CONTRIBUTION_SCHEMA",
    "METHODOLOGY_NOTICE",
    "PRIVACY_NOTICE",
    "SUPPORTED_AGGREGATION_METHODS",
    "SUPPORTED_GEOGRAPHIES",
    "SUPPORTED_INDUSTRIES",
    "SUPPORTED_METRICS",
    "SUPPORTED_MODALITIES",
    "SUPPORTED_NOISE_MECHANISMS",
    "SUPPORTED_ORG_SIZES",
    "SUPPORTED_SIGNATURE_ALGORITHMS",
    "METHODOLOGY_VERSION",
    "configured_benchmark_exchange",
    "enabled",
    "require_enabled",
]
