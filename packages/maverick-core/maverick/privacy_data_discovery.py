"""Privacy-minimising personal-data discovery and inventory authority.

This module provides a production-shaped, provider-neutral control plane for
structured and unstructured personal-data discovery.  It deliberately does
not make a live-provider, legal-compliance, or completeness claim.  Provider
adapters are injected and receive an exact enrolled HTTPS origin plus the
*name* of an environment variable that owns their credential; credential
values never enter this authority.

The default gate is closed.  Deployments must explicitly configure both::

    [privacy_automation]
    enable = true
    [privacy_automation.data_discovery]
    enable = true

Raw rows and document content exist only in adapter-to-detector memory.  The
SQLite authority retains opaque identifiers, bounded counters, classifications
and keyed evidence/location digests -- never samples, values, document text,
email/IP/payment values, or credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import sqlite3
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from .authority_effects import authority_effect_fence
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 2
_JOB_TABLE_SQL = """CREATE TABLE IF NOT EXISTS {name}(
    tenant_id TEXT NOT NULL, job_id TEXT NOT NULL, source_id TEXT NOT NULL,
    schedule_id TEXT,
    state TEXT NOT NULL CHECK(state IN ('queued','leased','complete','dead_letter','cancelled')),
    next_attempt_at REAL NOT NULL, lease_until REAL, payload_json TEXT NOT NULL,
    integrity_sha256 TEXT NOT NULL, PRIMARY KEY(tenant_id, job_id),
    FOREIGN KEY(tenant_id, source_id) REFERENCES sources(tenant_id, source_id)
);"""
REPORT_SCHEMA = "lightwork.privacy-data-discovery-report.v1"
FINDING_SCHEMA = "lightwork.privacy-data-discovery-finding.v1"
REVIEW_SCHEMA = "lightwork.privacy-data-discovery-review.v1"
AUDIT_SCHEMA = "lightwork.privacy-data-discovery-audit.v1"

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_ENV_RE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z")
_PROVIDER_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ERROR_RE = re.compile(r"[a-z][a-z0-9_]{0,47}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_FINDINGS_PER_REPORT = 100_000
_MAX_ERRORS = 100
_MAX_CLAIM = 100
_MAX_LIST = 2_000
_MAX_AUDIT_LIST = 1_000
_MAX_RETRIES = 20
_MAX_LEASE_SECONDS = 3_600.0
_MAX_BACKOFF_SECONDS = 86_400.0
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600
_SOURCE_KINDS = frozenset({"structured", "unstructured"})
_SOURCE_STATES = frozenset({"active", "suspended", "revoked"})
_JOB_STATES = frozenset({"queued", "leased", "complete", "dead_letter", "cancelled"})
_REVIEW_DECISIONS = frozenset({"confirmed", "reclassified", "false_positive"})
_CATEGORIES = frozenset(
    {
        "authentication_secret",
        "biometric_identifier",
        "date_of_birth",
        "email_address",
        "financial_account",
        "government_identifier",
        "health_information",
        "ip_address",
        "payment_card",
        "person_name",
        "phone_number",
        "physical_address",
        "precise_location",
        "unknown_personal_data",
    }
)


class PrivacyDataDiscoveryError(RuntimeError):
    """Base discovery error."""


class PrivacyDataDiscoveryConfigError(PrivacyDataDiscoveryError):
    """The capability has not been explicitly enabled."""


class PrivacyDataDiscoveryReadInterrupted(PrivacyDataDiscoveryError):
    """Current authority could not be verified at a provider read boundary."""


class PrivacyDataDiscoveryValidationError(PrivacyDataDiscoveryError, ValueError):
    """Input is outside the closed discovery contract."""


class PrivacyDataDiscoveryConflict(PrivacyDataDiscoveryError):
    """CAS, state, or idempotency preconditions failed."""


class PrivacyDataDiscoveryNotFound(PrivacyDataDiscoveryError):
    """A tenant-scoped resource does not exist."""


class PrivacyDataDiscoveryLeaseLost(PrivacyDataDiscoveryError):
    """A worker no longer owns the job lease."""


class PrivacyDataDiscoveryIntegrityError(PrivacyDataDiscoveryError):
    """Persisted content does not match its integrity digest."""


class PrivacyDataDiscoveryAdapterError(PrivacyDataDiscoveryError):
    """An injected provider adapter failed without exposing source content."""


def enabled() -> bool:
    """Return true only when privacy automation and discovery are enabled."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    privacy = config.get("privacy_automation")
    discovery = privacy.get("data_discovery") if isinstance(privacy, Mapping) else None
    return (
        isinstance(privacy, Mapping)
        and privacy.get("enable") is True
        and isinstance(discovery, Mapping)
        and discovery.get("enable") is True
    )


def require_enabled() -> None:
    """Fail closed unless both configuration gates are explicitly true."""

    if not enabled():
        raise PrivacyDataDiscoveryConfigError(
            "privacy data discovery is disabled; explicitly enable "
            "privacy_automation and privacy_automation.data_discovery"
        )


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PrivacyDataDiscoveryValidationError(
            "discovery data must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise PrivacyDataDiscoveryValidationError(
            "discovery data exceeds its canonical byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _opaque(
    value: object,
    label: str,
    pattern: re.Pattern[str] = _REF_RE,
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PrivacyDataDiscoveryValidationError(
            f"{label} must be a bounded opaque identifier"
        )
    if _CONTROL_RE.search(value):
        raise PrivacyDataDiscoveryValidationError(f"{label} contains control characters")
    return value


def _tenant_id(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except ValueError as exc:
        raise PrivacyDataDiscoveryValidationError("tenant_id is invalid") from exc


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise PrivacyDataDiscoveryValidationError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _positive_int(value: object, label: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise PrivacyDataDiscoveryValidationError(
            f"{label} must be an integer between 1 and {maximum}"
        )
    return value


def _nonnegative_int(value: object, label: str, maximum: int = 2**31 - 1) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= maximum
    ):
        raise PrivacyDataDiscoveryValidationError(
            f"{label} must be an integer between 0 and {maximum}"
        )
    return value


def _finite_time(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise PrivacyDataDiscoveryValidationError(
            f"{label} must be a positive finite timestamp"
        )
    return float(value)


def _bounded_float(value: object, label: str, lower: float, upper: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not lower <= float(value) <= upper
    ):
        raise PrivacyDataDiscoveryValidationError(
            f"{label} must be finite between {lower:g} and {upper:g}"
        )
    return float(value)


def _exact_https_origin(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2_048:
        raise PrivacyDataDiscoveryValidationError("origin must be an exact HTTPS origin")
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise PrivacyDataDiscoveryValidationError(
            "origin must be an exact HTTPS origin"
        ) from exc
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme != "https"
        or not _HOST_RE.fullmatch(host)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
        or (port is not None and port != 443)
    ):
        raise PrivacyDataDiscoveryValidationError(
            "origin must be exact HTTPS without credentials, path, query, or fragment"
        )
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        address = None
    if host == "localhost" or host.endswith(".localhost") or (
        address is not None
        and (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )
    ):
        raise PrivacyDataDiscoveryValidationError(
            "origin cannot identify a local or non-public authority"
        )
    return f"https://{host}" if port is None else f"https://{host}:{port}"


def _category(value: object) -> str:
    if not isinstance(value, str) or value not in _CATEGORIES:
        raise PrivacyDataDiscoveryValidationError("classification category is closed")
    return value


@dataclass(frozen=True)
class ScanLimits:
    """Closed, persisted limits for one bounded provider scan."""

    max_records: int = 10_000
    max_files: int = 1_000
    max_bytes: int = 64 * 1024 * 1024
    max_seconds: float = 300.0
    max_findings: int = 10_000
    max_fields_per_record: int = 256
    max_record_bytes: int = 256 * 1024
    max_document_bytes: int = 4 * 1024 * 1024

    def validated(self) -> ScanLimits:
        return ScanLimits(
            max_records=_positive_int(self.max_records, "max_records", 1_000_000),
            max_files=_positive_int(self.max_files, "max_files", 100_000),
            max_bytes=_positive_int(self.max_bytes, "max_bytes", 2**40),
            max_seconds=_bounded_float(
                self.max_seconds, "max_seconds", 0.1, 86_400.0
            ),
            max_findings=_positive_int(
                self.max_findings, "max_findings", _MAX_FINDINGS_PER_REPORT
            ),
            max_fields_per_record=_positive_int(
                self.max_fields_per_record, "max_fields_per_record", 10_000
            ),
            max_record_bytes=_positive_int(
                self.max_record_bytes, "max_record_bytes", 64 * 1024 * 1024
            ),
            max_document_bytes=_positive_int(
                self.max_document_bytes, "max_document_bytes", 256 * 1024 * 1024
            ),
        )


@dataclass(frozen=True)
class EnrolledSource:
    tenant_id: str
    source_id: str
    kind: str
    provider: str
    origin: str
    resource_ref: str
    credential_env: str
    evidence_key_env: str
    state: str
    revision: int
    enrolled_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class StructuredRecord:
    """Ephemeral row returned by a structured provider adapter."""

    record_ref: str
    fields: Mapping[str, object]


@dataclass(frozen=True)
class UnstructuredDocument:
    """Ephemeral document returned by an unstructured provider adapter."""

    document_ref: str
    media_type: str
    content: bytes | str


class StructuredRowSource(Protocol):
    """Injected adapter; it owns credential resolution and any network I/O."""

    def iter_rows(
        self,
        *,
        source: EnrolledSource,
        credential_env: str,
        limits: ScanLimits,
        deadline: float,
    ) -> Iterable[StructuredRecord]: ...


class UnstructuredDocumentSource(Protocol):
    """Injected adapter; it owns credential resolution and any network I/O."""

    def iter_documents(
        self,
        *,
        source: EnrolledSource,
        credential_env: str,
        limits: ScanLimits,
        deadline: float,
    ) -> Iterable[UnstructuredDocument]: ...


@dataclass(frozen=True)
class Detection:
    category: str
    confidence: float
    ambiguous: bool
    location_sha256: str
    evidence_sha256: str
    detector: str


@dataclass(frozen=True)
class ScanReport:
    report_id: str
    tenant_id: str
    source_id: str
    job_id: str
    started_at: float
    finished_at: float
    records_seen: int
    files_seen: int
    bytes_seen: int
    findings_count: int
    ambiguous_count: int
    completeness: str
    truncation_reasons: tuple[str, ...]
    error_codes: tuple[str, ...]
    limitations: tuple[str, ...]
    retention_until: float
    integrity_sha256: str
    evidence_key_fingerprint: str | None = None
    source_scope_sha256: str | None = None


@dataclass(frozen=True)
class Finding:
    finding_id: str
    tenant_id: str
    report_id: str
    source_id: str
    category: str
    confidence: float
    ambiguous: bool
    location_sha256: str
    evidence_sha256: str
    detector: str
    revision: int
    integrity_sha256: str


@dataclass(frozen=True)
class DiscoverySchedule:
    schedule_id: str
    tenant_id: str
    source_id: str
    interval_seconds: int
    limits: ScanLimits
    max_attempts: int
    retention_seconds: int
    active: bool
    next_run_at: float
    revision: int
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class ScanJob:
    job_id: str
    tenant_id: str
    source_id: str
    schedule_id: str | None
    state: str
    limits: ScanLimits
    attempts: int
    max_attempts: int
    next_attempt_at: float
    lease_owner: str | None
    lease_until: float | None
    retention_seconds: int
    revision: int
    last_error_code: str | None


@dataclass(frozen=True)
class ReviewProposal:
    review_id: str
    tenant_id: str
    finding_id: str
    decision: str
    effective_category: str | None
    prepared_by: str
    prepared_at: float
    evidence_sha256: str
    freshness_seconds: int
    status: str
    approved_by: str | None
    approved_at: float | None
    version: int
    integrity_sha256: str


@dataclass(frozen=True)
class ReviewedClassification:
    tenant_id: str
    source_id: str
    report_id: str
    finding_id: str
    review_id: str
    decision: str
    category: str | None
    evidence_sha256: str
    reviewed_at: float
    review_version: int


class ReviewedDataMapCallback(Protocol):
    """Called only after a fresh four-eyes review becomes effective."""

    def __call__(self, _update: ReviewedClassification) -> None: ...


@dataclass(frozen=True)
class InventorySnapshot:
    tenant_id: str
    source_id: str | None
    report_ids: tuple[str, ...]
    counts_by_category: Mapping[str, int]
    unreviewed_count: int
    false_positive_count: int
    ambiguous_count: int
    completeness: str
    truncated: bool
    limitations: tuple[str, ...]
    generated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class InventoryDiff:
    tenant_id: str
    base_report_id: str
    target_report_id: str
    added_finding_sha256: tuple[str, ...]
    removed_finding_sha256: tuple[str, ...]
    unchanged_count: int
    base_completeness: str
    target_completeness: str
    integrity_sha256: str


@dataclass(frozen=True)
class DiscoveryRunResult:
    tenant_id: str
    worker_id: str
    completed_reports: tuple[ScanReport, ...]
    failed_jobs: tuple[ScanJob, ...]
    interrupted_jobs: tuple[ScanJob, ...] = ()


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    tenant_id: str
    action: str
    subject_sha256: str
    actor_ref: str
    occurred_at: float
    details: Mapping[str, object]
    previous_sha256: str
    integrity_sha256: str


def _default_evidence_key_resolver(env_name: str) -> bytes:
    if isinstance(env_name, str) and env_name.startswith("evidence-key:"):
        from .privacy_discovery_credentials import resolve_key

        try:
            return resolve_key(env_name)
        except Exception as exc:
            raise PrivacyDataDiscoveryConfigError("saved evidence key is unavailable or rotated; update the source key selection") from exc
    name = _opaque(env_name, "evidence_key_env", _ENV_RE)
    value = os.environ.get(name)
    if value is None or len(value.encode("utf-8")) < 32:
        raise PrivacyDataDiscoveryConfigError(
            "evidence HMAC key environment variable is absent or shorter than 32 bytes"
        )
    return value.encode("utf-8")


class PersonalDataDetector:
    """Deterministic bounded detector that emits digests, never samples."""

    _EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}(?![\w.-])")
    _PHONE = re.compile(r"(?<!\d)(?:\+?1[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}(?!\d)")
    _SSN = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}(?!\d)")
    _CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
    _IP = re.compile(r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f:.]{3,45})(?![0-9A-Fa-f:.])")
    _DATE = re.compile(r"(?<!\d)(?:19|20)\d{2}[-/]?(?:0[1-9]|1[0-2])[-/]?(?:0[1-9]|[12]\d|3[01])(?!\d)")
    _PERSONAL_LABELS = re.compile(
        r"(?:name|email|mail|phone|mobile|address|birth|dob|ssn|passport|tax|"
        r"health|medical|patient|card|account|routing|latitude|longitude|"
        r"biometric|fingerprint|face|password|secret|token)",
        re.IGNORECASE,
    )
    _LABEL_CATEGORIES: tuple[tuple[re.Pattern[str], str, float], ...] = (
        (re.compile(r"(?:password|passcode|secret|auth[_ -]?token|api[_ -]?key)", re.IGNORECASE), "authentication_secret", 0.72),
        (re.compile(r"(?:fingerprint|faceprint|iris|voiceprint|biometric)", re.IGNORECASE), "biometric_identifier", 0.70),
        (re.compile(r"(?:date[_ -]?of[_ -]?birth|birth[_ -]?date|\bdob\b)", re.IGNORECASE), "date_of_birth", 0.68),
        (re.compile(r"(?:medical|health|diagnos|patient|prescription)", re.IGNORECASE), "health_information", 0.62),
        (re.compile(r"(?:latitude|longitude|precise[_ -]?location|gps)", re.IGNORECASE), "precise_location", 0.65),
        (re.compile(r"(?:street|postal|physical[_ -]?address|home[_ -]?address)", re.IGNORECASE), "physical_address", 0.55),
        (re.compile(r"(?:first[_ -]?name|last[_ -]?name|full[_ -]?name)", re.IGNORECASE), "person_name", 0.55),
        (re.compile(r"(?:bank|routing|financial[_ -]?account)", re.IGNORECASE), "financial_account", 0.58),
        (re.compile(r"(?:passport|driver.?s[_ -]?license|tax[_ -]?id)", re.IGNORECASE), "government_identifier", 0.62),
    )

    def __init__(self, evidence_key: bytes) -> None:
        if not isinstance(evidence_key, bytes) or len(evidence_key) < 32:
            raise PrivacyDataDiscoveryValidationError(
                "evidence key must contain at least 32 bytes"
            )
        self._key = bytes(evidence_key)

    def _hmac(self, purpose: str, value: bytes) -> str:
        return hmac.new(
            self._key,
            purpose.encode("ascii") + b"\x00" + value,
            hashlib.sha256,
        ).hexdigest()

    def _detection(
        self,
        *,
        category: str,
        confidence: float,
        ambiguous: bool,
        location: bytes,
        evidence: bytes,
        detector: str,
    ) -> Detection:
        return Detection(
            category=_category(category),
            confidence=_bounded_float(confidence, "confidence", 0.0, 1.0),
            ambiguous=bool(ambiguous),
            location_sha256=self._hmac("location", location),
            evidence_sha256=self._hmac("evidence", evidence),
            detector=_opaque(detector, "detector"),
        )

    @staticmethod
    def _luhn(candidate: str) -> bool:
        digits = "".join(character for character in candidate if character.isdigit())
        if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
            return False
        total = 0
        parity = len(digits) % 2
        for index, character in enumerate(digits):
            number = int(character)
            if index % 2 == parity:
                number *= 2
                if number > 9:
                    number -= 9
            total += number
        return total % 10 == 0

    def detect_text(self, text: str, *, location: bytes) -> tuple[Detection, ...]:
        if not isinstance(text, str):
            raise PrivacyDataDiscoveryValidationError("detector text must be a string")
        found: list[Detection] = []
        seen: set[tuple[str, str]] = set()

        def add(category: str, confidence: float, match: str, detector: str) -> None:
            evidence = match.strip().lower().encode("utf-8", errors="replace")
            digest = self._hmac("deduplicate", evidence)
            key = (category, digest)
            if key in seen:
                return
            seen.add(key)
            found.append(
                self._detection(
                    category=category,
                    confidence=confidence,
                    ambiguous=False,
                    location=location + b"\x00" + str(len(found)).encode("ascii"),
                    evidence=evidence,
                    detector=detector,
                )
            )

        for match in self._EMAIL.finditer(text):
            add("email_address", 0.99, match.group(0), "regex_email_v1")
        for match in self._PHONE.finditer(text):
            add("phone_number", 0.86, match.group(0), "regex_phone_v1")
        for match in self._SSN.finditer(text):
            add("government_identifier", 0.97, match.group(0), "regex_ssn_v1")
        for match in self._CARD.finditer(text):
            if self._luhn(match.group(0)):
                add("payment_card", 0.98, match.group(0), "luhn_card_v1")
        for match in self._DATE.finditer(text):
            add("date_of_birth", 0.44, match.group(0), "ambiguous_date_v1")
            found[-1] = Detection(**{**asdict(found[-1]), "ambiguous": True})
        for match in self._IP.finditer(text):
            candidate = match.group(0)
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            add("ip_address", 0.96, candidate, "ipaddress_v1")
        return tuple(found)

    def detect_field(
        self,
        field_name: str,
        value: object,
        *,
        location: bytes,
    ) -> tuple[Detection, ...]:
        if not isinstance(field_name, str) or not field_name:
            raise PrivacyDataDiscoveryValidationError("field name is invalid")
        try:
            value_text = value if isinstance(value, str) else json.dumps(value)
        except (TypeError, ValueError):
            value_text = ""
        encoded_value = value_text.encode("utf-8", errors="replace")
        field_location = location + b"\x00" + field_name.encode("utf-8", errors="replace")
        detections = list(self.detect_text(value_text, location=field_location))
        categories = {item.category for item in detections}
        for pattern, category, confidence in self._LABEL_CATEGORIES:
            if pattern.search(field_name) and category not in categories:
                detections.append(
                    self._detection(
                        category=category,
                        confidence=confidence,
                        ambiguous=True,
                        location=field_location,
                        evidence=field_name.lower().encode("utf-8") + b"\x00" + encoded_value,
                        detector="semantic_label_v1",
                    )
                )
                categories.add(category)
        if self._PERSONAL_LABELS.search(field_name) and not detections:
            detections.append(
                self._detection(
                    category="unknown_personal_data",
                    confidence=0.35,
                    ambiguous=True,
                    location=field_location,
                    evidence=field_name.lower().encode("utf-8") + b"\x00" + encoded_value,
                    detector="unknown_label_v1",
                )
            )
        return tuple(detections)

    def detect_document(
        self, text: str, *, location: bytes
    ) -> tuple[Detection, ...]:
        detections = list(self.detect_text(text, location=location))
        if not detections and re.search(
            r"\b(?:personal data|personally identifiable|pii|patient|passport|biometric)\b",
            text,
            re.IGNORECASE,
        ):
            detections.append(
                self._detection(
                    category="unknown_personal_data",
                    confidence=0.31,
                    ambiguous=True,
                    location=location,
                    evidence=text.encode("utf-8", errors="replace"),
                    detector="unknown_document_context_v1",
                )
            )
        return tuple(detections)


def _limits_payload(limits: ScanLimits) -> dict[str, object]:
    return asdict(limits.validated())


def _limits_from_json(value: str) -> ScanLimits:
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PrivacyDataDiscoveryIntegrityError("persisted limits are invalid") from exc
    if not isinstance(decoded, dict) or set(decoded) != set(asdict(ScanLimits())):
        raise PrivacyDataDiscoveryIntegrityError("persisted limits changed schema")
    try:
        return ScanLimits(**decoded).validated()
    except PrivacyDataDiscoveryValidationError as exc:
        raise PrivacyDataDiscoveryIntegrityError("persisted limits are invalid") from exc


class PrivacyDataDiscoveryStore:
    """Private SQLite authority for sources, schedules, jobs, reports and reviews."""

    def __init__(
        self,
        path: str | Path,
        *,
        config_gate: Callable[[], None] = require_enabled,
        clock: Callable[[], float] = time.time,
        evidence_key_resolver: Callable[[str], bytes] = _default_evidence_key_resolver,
        review_callback: ReviewedDataMapCallback | None = None,
    ) -> None:
        config_gate()
        self.path = Path(path)
        ensure_private_directory(self.path.parent)
        self._clock = clock
        self._evidence_key_resolver = evidence_key_resolver
        self._review_callback = review_callback
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30.0, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA secure_delete=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                f"""
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS metadata(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sources(
                    tenant_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, source_id)
                );
                CREATE TABLE IF NOT EXISTS schedules(
                    tenant_id TEXT NOT NULL,
                    schedule_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    active INTEGER NOT NULL CHECK(active IN (0,1)),
                    next_run_at REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, schedule_id),
                    FOREIGN KEY(tenant_id, source_id)
                        REFERENCES sources(tenant_id, source_id)
                );
                {_JOB_TABLE_SQL.format(name='jobs')}
                CREATE INDEX IF NOT EXISTS jobs_claim
                    ON jobs(tenant_id, state, next_attempt_at, lease_until);
                CREATE TABLE IF NOT EXISTS reports(
                    tenant_id TEXT NOT NULL,
                    report_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, report_id),
                    UNIQUE(tenant_id, job_id),
                    FOREIGN KEY(tenant_id, source_id)
                        REFERENCES sources(tenant_id, source_id)
                );
                CREATE TABLE IF NOT EXISTS findings(
                    tenant_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    report_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, finding_id),
                    FOREIGN KEY(tenant_id, report_id)
                        REFERENCES reports(tenant_id, report_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS findings_report
                    ON findings(tenant_id, report_id);
                CREATE TABLE IF NOT EXISTS reviews(
                    tenant_id TEXT NOT NULL,
                    review_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, review_id),
                    FOREIGN KEY(tenant_id, finding_id)
                        REFERENCES findings(tenant_id, finding_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS reviews_finding
                    ON reviews(tenant_id, finding_id);
                CREATE TABLE IF NOT EXISTS operations(
                    tenant_id TEXT NOT NULL,
                    operation_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    result_kind TEXT NOT NULL,
                    result_id TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, operation_sha256)
                );
                CREATE TABLE IF NOT EXISTS audit_events(
                    tenant_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, sequence)
                );
                INSERT OR IGNORE INTO metadata(key,value)
                    VALUES('schema_version','2');
                COMMIT;
                """
            )
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if version is not None and version["value"] == "1":
                # No native table references jobs. Rebuild only its closed state
                # constraint atomically; retained payloads, receipts and digests
                # remain byte-for-byte intact on installed V1 databases.
                self._begin(connection)
                connection.execute(_JOB_TABLE_SQL.format(name="jobs_v2"))
                connection.execute("INSERT INTO jobs_v2 SELECT * FROM jobs")
                connection.execute("DROP TABLE jobs")
                connection.execute("ALTER TABLE jobs_v2 RENAME TO jobs")
                connection.execute("CREATE INDEX jobs_claim ON jobs(tenant_id,state,next_attempt_at,lease_until)")
                connection.execute("UPDATE metadata SET value='2' WHERE key='schema_version'")
                connection.commit()
                version = connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
            if version is None or version["value"] != str(SCHEMA_VERSION):
                raise PrivacyDataDiscoveryIntegrityError(
                    "privacy discovery database schema is unsupported"
                )
        ensure_private_file(self.path)

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _row_payload(row: sqlite3.Row, kind: str) -> dict[str, Any]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise PrivacyDataDiscoveryIntegrityError(
                f"persisted {kind} is not canonical JSON"
            ) from exc
        if not isinstance(payload, dict) or _sha256(payload) != row["integrity_sha256"]:
            raise PrivacyDataDiscoveryIntegrityError(
                f"persisted {kind} failed integrity verification"
            )
        return payload

    @staticmethod
    def _operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request: Mapping[str, object],
    ) -> tuple[str, sqlite3.Row | None]:
        operation = _opaque(idempotency_key, "idempotency_key", _IDEMPOTENCY_RE)
        operation_sha = hashlib.sha256(operation.encode("utf-8")).hexdigest()
        request_sha = _sha256(dict(request))
        row = connection.execute(
            "SELECT * FROM operations WHERE tenant_id=? AND operation_sha256=?",
            (tenant_id, operation_sha),
        ).fetchone()
        if row is not None and row["request_sha256"] != request_sha:
            raise PrivacyDataDiscoveryConflict(
                "idempotency key is bound to different canonical content"
            )
        return request_sha, row

    @staticmethod
    def _record_operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request_sha: str,
        result_kind: str,
        result_id: str,
    ) -> None:
        operation_sha = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        connection.execute(
            "INSERT INTO operations VALUES(?,?,?,?,?)",
            (tenant_id, operation_sha, request_sha, result_kind, result_id),
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        action: str,
        subject: str,
        actor_ref: str,
        details: Mapping[str, object],
        now: float,
    ) -> None:
        action = _opaque(action, "audit action")
        actor = _opaque(actor_ref, "actor_ref")
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM audit_events "
            "WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = "0" * 64 if previous is None else previous["integrity_sha256"]
        payload = {
            "schema": AUDIT_SCHEMA,
            "sequence": sequence,
            "tenant_id": tenant_id,
            "action": action,
            "subject_sha256": hashlib.sha256(subject.encode("utf-8")).hexdigest(),
            "actor_ref": actor,
            "occurred_at": now,
            "details": dict(details),
            "previous_sha256": previous_sha,
        }
        digest = _sha256(payload)
        connection.execute(
            "INSERT INTO audit_events VALUES(?,?,?,?)",
            (tenant_id, sequence, _canonical(payload).decode("ascii"), digest),
        )

    def enroll_source(
        self,
        tenant_id: str,
        *,
        source_id: str,
        kind: str,
        provider: str,
        origin: str,
        resource_ref: str,
        credential_env: str,
        evidence_key_env: str,
        actor_ref: str,
        idempotency_key: str,
        expected_revision: int = 0,
        now: float | None = None,
    ) -> EnrolledSource:
        """Create or CAS-update one exact source without storing credentials."""

        tenant = _tenant_id(tenant_id)
        source = _opaque(source_id, "source_id")
        if kind not in _SOURCE_KINDS:
            raise PrivacyDataDiscoveryValidationError("source kind is closed")
        provider_name = _opaque(provider, "provider", _PROVIDER_RE)
        exact_origin = _exact_https_origin(origin)
        resource = _opaque(resource_ref, "resource_ref")
        from .privacy_discovery_credentials import validate_reference

        try:
            credential = validate_reference(credential_env)
            evidence_env = validate_reference(evidence_key_env, evidence=True)
        except ValueError as exc:
            raise PrivacyDataDiscoveryValidationError(str(exc)) from exc
        if credential == evidence_env:
            raise PrivacyDataDiscoveryValidationError(
                "source credential and evidence HMAC key require separate environment refs"
            )
        actor = _opaque(actor_ref, "actor_ref")
        expected = _nonnegative_int(expected_revision, "expected_revision")
        moment = _finite_time(self._clock() if now is None else now, "now")
        request = {
            "action": "enroll_source",
            "source_id": source,
            "kind": kind,
            "provider": provider_name,
            "origin": exact_origin,
            "resource_ref": resource,
            "credential_env": credential,
            "evidence_key_env": evidence_env,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_source(tenant, operation["result_id"])
            existing = connection.execute(
                "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                (tenant, source),
            ).fetchone()
            if existing is None:
                if expected != 0:
                    raise PrivacyDataDiscoveryConflict(
                        "source expected revision does not match absence"
                    )
                enrolled_at = moment
                revision = 1
            else:
                old = self._row_payload(existing, "source")
                if int(old["revision"]) != expected:
                    raise PrivacyDataDiscoveryConflict(
                        "source expected revision does not match"
                    )
                enrolled_at = float(old["enrolled_at"])
                revision = expected + 1
            payload = {
                "tenant_id": tenant,
                "source_id": source,
                "kind": kind,
                "provider": provider_name,
                "origin": exact_origin,
                "resource_ref": resource,
                "credential_env": credential,
                "evidence_key_env": evidence_env,
                "state": "active",
                "revision": revision,
                "enrolled_at": enrolled_at,
                "updated_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO sources VALUES(?,?,?,?) "
                "ON CONFLICT(tenant_id,source_id) DO UPDATE SET "
                "payload_json=excluded.payload_json,integrity_sha256=excluded.integrity_sha256",
                (tenant, source, _canonical(payload).decode("ascii"), digest),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "source", source
            )
            self._audit(
                connection,
                tenant,
                "source_enrolled",
                source,
                actor,
                {"kind": kind, "provider": provider_name, "revision": revision},
                moment,
            )
            connection.commit()
        return self.get_source(tenant, source)

    @staticmethod
    def _source_from(payload: Mapping[str, object], digest: str) -> EnrolledSource:
        return EnrolledSource(**payload, integrity_sha256=digest)  # type: ignore[arg-type]

    def get_source(self, tenant_id: str, source_id: str) -> EnrolledSource:
        tenant = _tenant_id(tenant_id)
        source = _opaque(source_id, "source_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                (tenant, source),
            ).fetchone()
        if row is None:
            raise PrivacyDataDiscoveryNotFound("source does not exist for tenant")
        return self._source_from(self._row_payload(row, "source"), row["integrity_sha256"])

    def list_sources(self, tenant_id: str, *, limit: int = 500) -> tuple[EnrolledSource, ...]:
        tenant = _tenant_id(tenant_id)
        count = _positive_int(limit, "limit", _MAX_LIST)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM sources WHERE tenant_id=? ORDER BY source_id LIMIT ?",
                (tenant, count),
            ).fetchall()
        return tuple(
            self._source_from(self._row_payload(row, "source"), row["integrity_sha256"])
            for row in rows
        )

    def set_source_state(
        self,
        tenant_id: str,
        source_id: str,
        *,
        state: str,
        expected_revision: int,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> EnrolledSource:
        tenant = _tenant_id(tenant_id)
        source = _opaque(source_id, "source_id")
        if state not in _SOURCE_STATES:
            raise PrivacyDataDiscoveryValidationError("source state is closed")
        expected = _nonnegative_int(expected_revision, "expected_revision")
        actor = _opaque(actor_ref, "actor_ref")
        moment = _finite_time(self._clock() if now is None else now, "now")
        request = {
            "action": "set_source_state",
            "source_id": source,
            "state": state,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_source(tenant, source)
            row = connection.execute(
                "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                (tenant, source),
            ).fetchone()
            if row is None:
                raise PrivacyDataDiscoveryNotFound("source does not exist for tenant")
            payload = self._row_payload(row, "source")
            if int(payload["revision"]) != expected:
                raise PrivacyDataDiscoveryConflict(
                    "source expected revision does not match"
                )
            payload["state"] = state
            payload["revision"] = expected + 1
            payload["updated_at"] = moment
            digest = _sha256(payload)
            connection.execute(
                "UPDATE sources SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND source_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, source),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "source", source
            )
            self._audit(
                connection,
                tenant,
                "source_state_changed",
                source,
                actor,
                {"state": state, "revision": expected + 1},
                moment,
            )
            connection.commit()
        return self.get_source(tenant, source)

    @staticmethod
    def _schedule_from(
        payload: Mapping[str, object], digest: str
    ) -> DiscoverySchedule:
        values = dict(payload)
        limits_value = values.pop("limits")
        limits = _limits_from_json(_canonical(limits_value).decode("ascii"))
        return DiscoverySchedule(  # type: ignore[arg-type]
            **values, limits=limits, integrity_sha256=digest
        )

    def upsert_schedule(
        self,
        tenant_id: str,
        *,
        schedule_id: str,
        source_id: str,
        interval_seconds: int,
        limits: ScanLimits,
        max_attempts: int,
        retention_seconds: int,
        active: bool,
        expected_revision: int,
        actor_ref: str,
        idempotency_key: str,
        next_run_at: float | None = None,
        now: float | None = None,
    ) -> DiscoverySchedule:
        """Create or CAS-update a bounded periodic schedule."""

        tenant = _tenant_id(tenant_id)
        schedule = _opaque(schedule_id, "schedule_id")
        source = _opaque(source_id, "source_id")
        interval = _positive_int(
            interval_seconds, "interval_seconds", 365 * 24 * 3_600
        )
        checked_limits = limits.validated()
        attempts = _positive_int(max_attempts, "max_attempts", _MAX_RETRIES)
        retention = _positive_int(
            retention_seconds, "retention_seconds", _MAX_RETENTION_SECONDS
        )
        if not isinstance(active, bool):
            raise PrivacyDataDiscoveryValidationError("active must be a boolean")
        expected = _nonnegative_int(expected_revision, "expected_revision")
        actor = _opaque(actor_ref, "actor_ref")
        moment = _finite_time(self._clock() if now is None else now, "now")
        due = _finite_time(
            moment if next_run_at is None else next_run_at, "next_run_at"
        )
        request = {
            "action": "upsert_schedule",
            "schedule_id": schedule,
            "source_id": source,
            "interval_seconds": interval,
            "limits": _limits_payload(checked_limits),
            "max_attempts": attempts,
            "retention_seconds": retention,
            "active": active,
            "expected_revision": expected,
            "next_run_at": due,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_schedule(tenant, schedule)
            source_row = connection.execute(
                "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                (tenant, source),
            ).fetchone()
            if source_row is None:
                raise PrivacyDataDiscoveryNotFound("source does not exist for tenant")
            source_payload = self._row_payload(source_row, "source")
            if source_payload["state"] == "revoked":
                raise PrivacyDataDiscoveryConflict("revoked source cannot be scheduled")
            existing = connection.execute(
                "SELECT * FROM schedules WHERE tenant_id=? AND schedule_id=?",
                (tenant, schedule),
            ).fetchone()
            if existing is None:
                if expected != 0:
                    raise PrivacyDataDiscoveryConflict(
                        "schedule expected revision does not match absence"
                    )
                created_at = moment
                revision = 1
            else:
                old = self._row_payload(existing, "schedule")
                if int(old["revision"]) != expected:
                    raise PrivacyDataDiscoveryConflict(
                        "schedule expected revision does not match"
                    )
                created_at = float(old["created_at"])
                revision = expected + 1
            payload = {
                "schedule_id": schedule,
                "tenant_id": tenant,
                "source_id": source,
                "interval_seconds": interval,
                "limits": _limits_payload(checked_limits),
                "max_attempts": attempts,
                "retention_seconds": retention,
                "active": active,
                "next_run_at": due,
                "revision": revision,
                "created_at": created_at,
                "updated_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO schedules VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(tenant_id,schedule_id) DO UPDATE SET "
                "source_id=excluded.source_id,active=excluded.active,"
                "next_run_at=excluded.next_run_at,payload_json=excluded.payload_json,"
                "integrity_sha256=excluded.integrity_sha256",
                (
                    tenant,
                    schedule,
                    source,
                    int(active),
                    due,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "schedule", schedule
            )
            self._audit(
                connection,
                tenant,
                "schedule_upserted",
                schedule,
                actor,
                {"active": active, "revision": revision},
                moment,
            )
            connection.commit()
        return self.get_schedule(tenant, schedule)

    def get_schedule(self, tenant_id: str, schedule_id: str) -> DiscoverySchedule:
        tenant = _tenant_id(tenant_id)
        schedule = _opaque(schedule_id, "schedule_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM schedules WHERE tenant_id=? AND schedule_id=?",
                (tenant, schedule),
            ).fetchone()
        if row is None:
            raise PrivacyDataDiscoveryNotFound("schedule does not exist for tenant")
        payload = self._row_payload(row, "schedule")
        if bool(row["active"]) is not bool(payload["active"]) or float(
            row["next_run_at"]
        ) != float(payload["next_run_at"]):
            raise PrivacyDataDiscoveryIntegrityError("schedule index fields diverged")
        return self._schedule_from(payload, row["integrity_sha256"])

    def list_schedules(
        self, tenant_id: str, *, limit: int = 500
    ) -> tuple[DiscoverySchedule, ...]:
        tenant = _tenant_id(tenant_id)
        count = _positive_int(limit, "limit", _MAX_LIST)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM schedules WHERE tenant_id=? ORDER BY schedule_id LIMIT ?",
                (tenant, count),
            ).fetchall()
        result: list[DiscoverySchedule] = []
        for row in rows:
            payload = self._row_payload(row, "schedule")
            if bool(row["active"]) is not bool(payload["active"]) or float(
                row["next_run_at"]
            ) != float(payload["next_run_at"]):
                raise PrivacyDataDiscoveryIntegrityError("schedule index fields diverged")
            result.append(self._schedule_from(payload, row["integrity_sha256"]))
        return tuple(result)

    @staticmethod
    def _job_from(payload: Mapping[str, object], digest: str) -> ScanJob:
        values = dict(payload)
        limits_value = values.pop("limits")
        limits = _limits_from_json(_canonical(limits_value).decode("ascii"))
        return ScanJob(**values, limits=limits)  # type: ignore[arg-type]

    def _insert_job(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        source: str,
        schedule: str | None,
        limits: ScanLimits,
        max_attempts: int,
        retention_seconds: int,
        idempotency_key: str,
        actor: str,
        moment: float,
    ) -> ScanJob:
        request = {
            "action": "enqueue_scan",
            "source_id": source,
            "schedule_id": schedule,
            "limits": _limits_payload(limits),
            "max_attempts": max_attempts,
            "retention_seconds": retention_seconds,
            "actor_ref": actor,
        }
        request_sha, operation = self._operation(
            connection, tenant, idempotency_key, request
        )
        if operation is not None:
            row = connection.execute(
                "SELECT * FROM jobs WHERE tenant_id=? AND job_id=?",
                (tenant, operation["result_id"]),
            ).fetchone()
            if row is None:
                raise PrivacyDataDiscoveryIntegrityError(
                    "idempotent job result is missing"
                )
            return self._job_from(
                self._row_payload(row, "job"), row["integrity_sha256"]
            )
        operation_sha = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        job_id = f"PDJ-{operation_sha[:32]}"
        payload = {
            "job_id": job_id,
            "tenant_id": tenant,
            "source_id": source,
            "schedule_id": schedule,
            "state": "queued",
            "limits": _limits_payload(limits),
            "attempts": 0,
            "max_attempts": max_attempts,
            "next_attempt_at": moment,
            "lease_owner": None,
            "lease_until": None,
            "retention_seconds": retention_seconds,
            "revision": 1,
            "last_error_code": None,
        }
        digest = _sha256(payload)
        connection.execute(
            "INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)",
            (
                tenant,
                job_id,
                source,
                schedule,
                "queued",
                moment,
                None,
                _canonical(payload).decode("ascii"),
                digest,
            ),
        )
        self._record_operation(
            connection, tenant, idempotency_key, request_sha, "job", job_id
        )
        self._audit(
            connection,
            tenant,
            "scan_enqueued",
            job_id,
            actor,
            {"source_id": source, "scheduled": schedule is not None},
            moment,
        )
        return self._job_from(payload, digest)

    def enqueue_scan(
        self,
        tenant_id: str,
        source_id: str,
        *,
        limits: ScanLimits,
        max_attempts: int,
        retention_seconds: int,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ScanJob:
        """Idempotently enqueue an explicitly bounded manual scan."""

        tenant = _tenant_id(tenant_id)
        source = _opaque(source_id, "source_id")
        checked_limits = limits.validated()
        attempts = _positive_int(max_attempts, "max_attempts", _MAX_RETRIES)
        retention = _positive_int(
            retention_seconds, "retention_seconds", _MAX_RETENTION_SECONDS
        )
        actor = _opaque(actor_ref, "actor_ref")
        moment = _finite_time(self._clock() if now is None else now, "now")
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                (tenant, source),
            ).fetchone()
            if row is None:
                raise PrivacyDataDiscoveryNotFound("source does not exist for tenant")
            source_payload = self._row_payload(row, "source")
            if source_payload["state"] != "active":
                raise PrivacyDataDiscoveryConflict("source is not active")
            job = self._insert_job(
                connection,
                tenant=tenant,
                source=source,
                schedule=None,
                limits=checked_limits,
                max_attempts=attempts,
                retention_seconds=retention,
                idempotency_key=idempotency_key,
                actor=actor,
                moment=moment,
            )
            connection.commit()
        return job

    def enqueue_due(
        self,
        tenant_id: str,
        *,
        actor_ref: str = "privacy_scheduler",
        limit: int = 100,
        now: float | None = None,
    ) -> tuple[ScanJob, ...]:
        """Enqueue at most one catch-up job per due active schedule."""

        tenant = _tenant_id(tenant_id)
        actor = _opaque(actor_ref, "actor_ref")
        count = _positive_int(limit, "limit", _MAX_CLAIM)
        moment = _finite_time(self._clock() if now is None else now, "now")
        enqueued: list[ScanJob] = []
        with self._connect() as connection:
            self._begin(connection)
            rows = connection.execute(
                "SELECT * FROM schedules WHERE tenant_id=? AND active=1 "
                "AND next_run_at<=? ORDER BY next_run_at,schedule_id LIMIT ?",
                (tenant, moment, count),
            ).fetchall()
            for row in rows:
                payload = self._row_payload(row, "schedule")
                schedule = self._schedule_from(payload, row["integrity_sha256"])
                source_row = connection.execute(
                    "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                    (tenant, schedule.source_id),
                ).fetchone()
                if source_row is None:
                    raise PrivacyDataDiscoveryIntegrityError(
                        "schedule references a missing source"
                    )
                source_payload = self._row_payload(source_row, "source")
                if source_payload["state"] != "active":
                    continue
                run_token = f"schedule:{schedule.schedule_id}:{int(schedule.next_run_at * 1000)}"
                job = self._insert_job(
                    connection,
                    tenant=tenant,
                    source=schedule.source_id,
                    schedule=schedule.schedule_id,
                    limits=schedule.limits,
                    max_attempts=schedule.max_attempts,
                    retention_seconds=schedule.retention_seconds,
                    idempotency_key=run_token,
                    actor=actor,
                    moment=moment,
                )
                enqueued.append(job)
                next_run = schedule.next_run_at
                while next_run <= moment:
                    next_run += schedule.interval_seconds
                payload["next_run_at"] = next_run
                payload["updated_at"] = moment
                payload["revision"] = int(payload["revision"]) + 1
                digest = _sha256(payload)
                connection.execute(
                    "UPDATE schedules SET next_run_at=?,payload_json=?,integrity_sha256=? "
                    "WHERE tenant_id=? AND schedule_id=?",
                    (
                        next_run,
                        _canonical(payload).decode("ascii"),
                        digest,
                        tenant,
                        schedule.schedule_id,
                    ),
                )
            connection.commit()
        return tuple(enqueued)

    def get_job(self, tenant_id: str, job_id: str) -> ScanJob:
        tenant = _tenant_id(tenant_id)
        job = _opaque(job_id, "job_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE tenant_id=? AND job_id=?",
                (tenant, job),
            ).fetchone()
        if row is None:
            raise PrivacyDataDiscoveryNotFound("scan job does not exist for tenant")
        payload = self._row_payload(row, "job")
        self._verify_job_indexes(row, payload)
        return self._job_from(payload, row["integrity_sha256"])

    def list_jobs(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        limit: int = 500,
    ) -> tuple[ScanJob, ...]:
        """List tenant jobs, optionally restricted to a closed lifecycle state."""

        tenant = _tenant_id(tenant_id)
        if state is not None and state not in _JOB_STATES:
            raise PrivacyDataDiscoveryValidationError("job state is closed")
        count = _positive_int(limit, "limit", _MAX_LIST)
        query = "SELECT * FROM jobs WHERE tenant_id=?"
        params: list[object] = [tenant]
        if state is not None:
            query += " AND state=?"
            params.append(state)
        query += " ORDER BY rowid DESC LIMIT ?"
        params.append(count)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        result: list[ScanJob] = []
        for row in rows:
            payload = self._row_payload(row, "job")
            self._verify_job_indexes(row, payload)
            result.append(self._job_from(payload, row["integrity_sha256"]))
        return tuple(result)

    @staticmethod
    def _verify_job_indexes(row: sqlite3.Row, payload: Mapping[str, object]) -> None:
        if (
            row["state"] != payload["state"]
            or float(row["next_attempt_at"]) != float(payload["next_attempt_at"])
            or (
                row["lease_until"] is None
                and payload["lease_until"] is not None
            )
            or (
                row["lease_until"] is not None
                and float(row["lease_until"]) != float(payload["lease_until"])
            )
        ):
            raise PrivacyDataDiscoveryIntegrityError("job index fields diverged")

    @staticmethod
    def _update_job_row(
        connection: sqlite3.Connection,
        tenant: str,
        payload: Mapping[str, object],
    ) -> str:
        digest = _sha256(dict(payload))
        connection.execute(
            "UPDATE jobs SET state=?,next_attempt_at=?,lease_until=?,"
            "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND job_id=?",
            (
                payload["state"],
                payload["next_attempt_at"],
                payload["lease_until"],
                _canonical(dict(payload)).decode("ascii"),
                digest,
                tenant,
                payload["job_id"],
            ),
        )
        return digest

    def claim_jobs(
        self,
        tenant_id: str,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: float = 60.0,
        now: float | None = None,
    ) -> tuple[ScanJob, ...]:
        """Recover stale leases and CAS-claim due jobs for one worker."""

        tenant = _tenant_id(tenant_id)
        worker = _opaque(worker_id, "worker_id")
        count = _positive_int(limit, "limit", _MAX_CLAIM)
        lease_for = _bounded_float(
            lease_seconds, "lease_seconds", 1.0, _MAX_LEASE_SECONDS
        )
        moment = _finite_time(self._clock() if now is None else now, "now")
        claimed: list[ScanJob] = []
        with self._connect() as connection:
            self._begin(connection)
            stale = connection.execute(
                "SELECT * FROM jobs WHERE tenant_id=? AND state='leased' "
                "AND lease_until<=? ORDER BY lease_until LIMIT ?",
                (tenant, moment, count),
            ).fetchall()
            for row in stale:
                payload = self._row_payload(row, "job")
                self._verify_job_indexes(row, payload)
                if int(payload["attempts"]) >= int(payload["max_attempts"]):
                    payload["state"] = "dead_letter"
                    payload["last_error_code"] = "stale_lease_exhausted"
                else:
                    payload["state"] = "queued"
                    payload["next_attempt_at"] = moment
                    payload["last_error_code"] = "stale_lease_recovered"
                payload["lease_owner"] = None
                payload["lease_until"] = None
                payload["revision"] = int(payload["revision"]) + 1
                self._update_job_row(connection, tenant, payload)
                self._audit(
                    connection,
                    tenant,
                    "stale_lease_recovered",
                    str(payload["job_id"]),
                    worker,
                    {"result_state": payload["state"]},
                    moment,
                )
            rows = connection.execute(
                "SELECT * FROM jobs WHERE tenant_id=? AND state='queued' "
                "AND next_attempt_at<=? ORDER BY next_attempt_at,job_id LIMIT ?",
                (tenant, moment, count),
            ).fetchall()
            for row in rows:
                payload = self._row_payload(row, "job")
                self._verify_job_indexes(row, payload)
                source_row = connection.execute(
                    "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                    (tenant, payload["source_id"]),
                ).fetchone()
                if source_row is None:
                    raise PrivacyDataDiscoveryIntegrityError("job source is missing")
                source_payload = self._row_payload(source_row, "source")
                if source_payload["state"] != "active":
                    payload["state"] = "dead_letter"
                    payload["last_error_code"] = "source_inactive"
                    payload["revision"] = int(payload["revision"]) + 1
                    self._update_job_row(connection, tenant, payload)
                    continue
                digest = self._lease_job(connection, tenant, payload, worker, moment, lease_for)
                claimed.append(self._job_from(payload, digest))
            connection.commit()
        return tuple(claimed)

    def _lease_job(self, connection, tenant, payload, worker, moment, lease_for):
        """The shared physical lease writer for a batch and a reviewed single scan."""
        payload.update(state="leased", attempts=int(payload["attempts"]) + 1,
                       lease_owner=worker, lease_until=moment + lease_for,
                       revision=int(payload["revision"]) + 1)
        digest = self._update_job_row(connection, tenant, payload)
        self._audit(connection, tenant, "scan_leased", str(payload["job_id"]), worker,
                    {"attempt": payload["attempts"]}, moment)
        return digest

    def claim_job(self, tenant_id: str, job_id: str, *, expected_revision: int,
                  expected_source_revision: int, worker_id: str, idempotency_key: str,
                  before_write=None) -> tuple[ScanJob, bool]:
        """Claim exactly one reviewed queued job once; repeats only read its original."""
        tenant, job, worker = _tenant_id(tenant_id), _opaque(job_id, "job_id"), _opaque(worker_id, "worker_id")
        expected = _positive_int(expected_revision, "expected_revision", 2**31 - 1)
        source_expected = _positive_int(expected_source_revision, "expected_source_revision", 2**31 - 1)
        request = {"action": "claim_scan", "job_id": job, "worker_id": worker,
                   "expected_revision": expected, "expected_source_revision": source_expected}
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                connection.commit()
                return self.get_job(tenant, job), False
            row = connection.execute("SELECT * FROM jobs WHERE tenant_id=? AND job_id=?", (tenant, job)).fetchone()
            if row is None:
                raise PrivacyDataDiscoveryNotFound("scan job does not exist for tenant")
            payload = self._row_payload(row, "job")
            self._verify_job_indexes(row, payload)
            moment = _finite_time(self._clock(), "now")
            if payload["state"] != "queued" or int(payload["revision"]) != expected:
                raise PrivacyDataDiscoveryConflict("This scan changed or already started. Read its original before another decision.")
            if float(payload["next_attempt_at"]) > moment or int(payload["attempts"]) >= int(payload["max_attempts"]):
                raise PrivacyDataDiscoveryConflict("This scan is waiting for its retry time or has used its attempts. Refresh the scan before continuing.")
            source_row = connection.execute("SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                (tenant, payload["source_id"])).fetchone()
            if source_row is None:
                raise PrivacyDataDiscoveryIntegrityError("job source is missing")
            source = self._row_payload(source_row, "source")
            if source["state"] != "active" or int(source["revision"]) != source_expected:
                raise PrivacyDataDiscoveryConflict("This source changed or was paused. Review its current selection before scanning.")
            if before_write is not None:
                before_write()
            lease_for = min(_MAX_LEASE_SECONDS, float(payload["limits"]["max_seconds"]) + 60)
            digest = self._lease_job(connection, tenant, payload, worker, moment, lease_for)
            self._record_operation(connection, tenant, idempotency_key, request_sha, "job", job)
            connection.commit()
        return self._job_from(payload, digest), True

    def cancel_job(self, tenant_id: str, job_id: str, *, expected_revision: int,
                   actor_ref: str, idempotency_key: str, before_write=None) -> ScanJob:
        """Cancel only an exact queued scan; never relabel running work as cancelled."""
        tenant, job, actor = _tenant_id(tenant_id), _opaque(job_id, "job_id"), _opaque(actor_ref, "actor_ref")
        expected = _positive_int(expected_revision, "expected_revision", 2**31 - 1)
        request = {"action": "cancel_scan", "job_id": job, "actor_ref": actor, "expected_revision": expected}
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                connection.commit()
                return self.get_job(tenant, job)
            row = connection.execute("SELECT * FROM jobs WHERE tenant_id=? AND job_id=?", (tenant, job)).fetchone()
            if row is None:
                raise PrivacyDataDiscoveryNotFound("scan job does not exist for tenant")
            payload = self._row_payload(row, "job")
            self._verify_job_indexes(row, payload)
            if payload["state"] != "queued" or int(payload["revision"]) != expected:
                raise PrivacyDataDiscoveryConflict("This scan changed or already started. Refresh its current state before cancelling.")
            if before_write is not None:
                before_write()
            moment = _finite_time(self._clock(), "now")
            payload.update(state="cancelled", lease_owner=None, lease_until=None,
                           last_error_code="operator_cancelled", revision=expected + 1)
            digest = self._update_job_row(connection, tenant, payload)
            self._record_operation(connection, tenant, idempotency_key, request_sha, "job", job)
            self._audit(connection, tenant, "scan_cancelled", job, actor, {"revision": expected + 1}, moment)
            connection.commit()
        return self._job_from(payload, digest)

    def report_for_job(self, tenant_id: str, job_id: str) -> ScanReport | None:
        tenant, job = _tenant_id(tenant_id), _opaque(job_id, "job_id")
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM reports WHERE tenant_id=? AND job_id=?", (tenant, job)).fetchone()
        return self._report_from(self._row_payload(row, "report"), row["integrity_sha256"]) if row else None

    def fail_job(
        self,
        tenant_id: str,
        job_id: str,
        *,
        worker_id: str,
        error_code: str,
        base_backoff_seconds: float = 5.0,
        now: float | None = None,
    ) -> ScanJob:
        """Retry or dead-letter a leased job using only a closed error code."""

        tenant = _tenant_id(tenant_id)
        job = _opaque(job_id, "job_id")
        worker = _opaque(worker_id, "worker_id")
        code = _opaque(error_code, "error_code", _ERROR_RE)
        base = _bounded_float(
            base_backoff_seconds, "base_backoff_seconds", 0.1, 3_600.0
        )
        moment = _finite_time(self._clock() if now is None else now, "now")
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM jobs WHERE tenant_id=? AND job_id=?",
                (tenant, job),
            ).fetchone()
            if row is None:
                raise PrivacyDataDiscoveryNotFound("scan job does not exist for tenant")
            payload = self._row_payload(row, "job")
            self._verify_job_indexes(row, payload)
            if (
                payload["state"] != "leased"
                or payload["lease_owner"] != worker
                or float(payload["lease_until"] or 0) <= moment
            ):
                raise PrivacyDataDiscoveryLeaseLost("scan job lease is no longer owned")
            if int(payload["attempts"]) >= int(payload["max_attempts"]):
                payload["state"] = "dead_letter"
                action = "scan_dead_lettered"
            else:
                payload["state"] = "queued"
                delay = min(
                    _MAX_BACKOFF_SECONDS,
                    base * (2 ** max(0, int(payload["attempts"]) - 1)),
                )
                payload["next_attempt_at"] = moment + delay
                action = "scan_retry_scheduled"
            payload["lease_owner"] = None
            payload["lease_until"] = None
            payload["last_error_code"] = code
            payload["revision"] = int(payload["revision"]) + 1
            digest = self._update_job_row(connection, tenant, payload)
            self._audit(
                connection,
                tenant,
                action,
                job,
                worker,
                {"attempt": payload["attempts"], "error_code": code},
                moment,
            )
            connection.commit()
        return self._job_from(payload, digest)

    def replay_dead_letter(
        self,
        tenant_id: str,
        job_id: str,
        *,
        expected_revision: int,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ScanJob:
        tenant = _tenant_id(tenant_id)
        job = _opaque(job_id, "job_id")
        expected = _nonnegative_int(expected_revision, "expected_revision")
        actor = _opaque(actor_ref, "actor_ref")
        moment = _finite_time(self._clock() if now is None else now, "now")
        request = {
            "action": "replay_dead_letter",
            "job_id": job,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_job(tenant, job)
            row = connection.execute(
                "SELECT * FROM jobs WHERE tenant_id=? AND job_id=?",
                (tenant, job),
            ).fetchone()
            if row is None:
                raise PrivacyDataDiscoveryNotFound("scan job does not exist for tenant")
            payload = self._row_payload(row, "job")
            if payload["state"] != "dead_letter" or int(payload["revision"]) != expected:
                raise PrivacyDataDiscoveryConflict(
                    "dead-letter state or expected revision does not match"
                )
            payload["state"] = "queued"
            payload["attempts"] = 0
            payload["next_attempt_at"] = moment
            payload["lease_owner"] = None
            payload["lease_until"] = None
            payload["last_error_code"] = None
            payload["revision"] = expected + 1
            digest = self._update_job_row(connection, tenant, payload)
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "job", job
            )
            self._audit(
                connection,
                tenant,
                "dead_letter_replayed",
                job,
                actor,
                {"revision": expected + 1},
                moment,
            )
            connection.commit()
        return self._job_from(payload, digest)

    @staticmethod
    def _report_from(payload: Mapping[str, object], digest: str) -> ScanReport:
        values = dict(payload)
        values.pop("schema", None)
        values["truncation_reasons"] = tuple(values["truncation_reasons"])
        values["error_codes"] = tuple(values["error_codes"])
        values["limitations"] = tuple(values["limitations"])
        return ScanReport(**values, integrity_sha256=digest)  # type: ignore[arg-type]

    @staticmethod
    def _finding_from(payload: Mapping[str, object], digest: str) -> Finding:
        values = dict(payload)
        values.pop("schema", None)
        return Finding(**values, integrity_sha256=digest)  # type: ignore[arg-type]

    def _complete_job(
        self,
        tenant_id: str,
        job_id: str,
        *,
        worker_id: str,
        started_at: float,
        finished_at: float,
        records_seen: int,
        files_seen: int,
        bytes_seen: int,
        detections: Sequence[Detection],
        truncation_reasons: Sequence[str],
        error_codes: Sequence[str],
        evidence_key_fingerprint: str | None = None,
        source_scope_sha256: str | None = None,
        expected_source_sha256: str | None = None,
        before_write=None,
    ) -> ScanReport:
        tenant = _tenant_id(tenant_id)
        job = _opaque(job_id, "job_id")
        worker = _opaque(worker_id, "worker_id")
        started = _finite_time(started_at, "started_at")
        finished = _finite_time(finished_at, "finished_at")
        if finished < started:
            raise PrivacyDataDiscoveryValidationError(
                "finished_at cannot precede started_at"
            )
        records = _nonnegative_int(records_seen, "records_seen", 1_000_000)
        files = _nonnegative_int(files_seen, "files_seen", 100_000)
        byte_count = _nonnegative_int(bytes_seen, "bytes_seen", 2**40)
        if not isinstance(detections, Sequence) or len(detections) > _MAX_FINDINGS_PER_REPORT:
            raise PrivacyDataDiscoveryValidationError("finding count exceeds report bound")
        truncations = tuple(
            sorted({_opaque(item, "truncation reason") for item in truncation_reasons})
        )
        errors = tuple(sorted({_opaque(item, "error code", _ERROR_RE) for item in error_codes}))
        if len(errors) > _MAX_ERRORS:
            raise PrivacyDataDiscoveryValidationError("report error count exceeds bound")
        moment = finished
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM jobs WHERE tenant_id=? AND job_id=?",
                (tenant, job),
            ).fetchone()
            if row is None:
                raise PrivacyDataDiscoveryNotFound("scan job does not exist for tenant")
            job_payload = self._row_payload(row, "job")
            self._verify_job_indexes(row, job_payload)
            if expected_source_sha256 is not None:
                source_row = connection.execute("SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                    (tenant, job_payload["source_id"])).fetchone()
                if source_row is None or source_row["integrity_sha256"] != expected_source_sha256:
                    raise PrivacyDataDiscoveryConflict("source changed during scan; no report was committed")
            if (
                job_payload["state"] != "leased"
                or job_payload["lease_owner"] != worker
                or float(job_payload["lease_until"] or 0) < finished
            ):
                raise PrivacyDataDiscoveryLeaseLost("scan job lease is no longer owned")
            existing = connection.execute(
                "SELECT * FROM reports WHERE tenant_id=? AND job_id=?",
                (tenant, job),
            ).fetchone()
            if existing is not None:
                raise PrivacyDataDiscoveryConflict("scan job already has an immutable report")
            report_id = f"PDR-{hashlib.sha256((tenant + ':' + job).encode()).hexdigest()[:32]}"
            ambiguity = sum(1 for item in detections if item.ambiguous)
            completeness = (
                "bounded_partial" if truncations or errors else "complete_within_declared_bounds"
            )
            limitations = (
                "adapter_defined_source_scope",
                "cooperative_provider_deadline",
                "provider_adapter_must_enforce_dns_pinning_and_transport_security",
                "deterministic_patterns_are_not_exhaustive",
                "encrypted_or_unsupported_content_may_be_unobserved",
                "no_legal_or_regulatory_completeness_claim",
            )
            report_payload = {
                "schema": REPORT_SCHEMA,
                "report_id": report_id,
                "tenant_id": tenant,
                "source_id": job_payload["source_id"],
                "job_id": job,
                "started_at": started,
                "finished_at": finished,
                "records_seen": records,
                "files_seen": files,
                "bytes_seen": byte_count,
                "findings_count": len(detections),
                "ambiguous_count": ambiguity,
                "completeness": completeness,
                "truncation_reasons": list(truncations),
                "error_codes": list(errors),
                "limitations": list(limitations),
                "retention_until": finished + int(job_payload["retention_seconds"]),
                "evidence_key_fingerprint": evidence_key_fingerprint,
                "source_scope_sha256": source_scope_sha256,
            }
            report_digest = _sha256(report_payload)
            if before_write is not None:
                before_write()
            connection.execute(
                "INSERT INTO reports VALUES(?,?,?,?,?,?)",
                (
                    tenant,
                    report_id,
                    job_payload["source_id"],
                    job,
                    _canonical(report_payload).decode("ascii"),
                    report_digest,
                ),
            )
            for index, detection in enumerate(detections):
                _category(detection.category)
                _digest(detection.location_sha256, "location_sha256")
                _digest(detection.evidence_sha256, "evidence_sha256")
                detector = _opaque(detection.detector, "detector")
                confidence = _bounded_float(
                    detection.confidence, "confidence", 0.0, 1.0
                )
                finding_identity = _sha256(
                    {
                        "report_id": report_id,
                        "index": index,
                        "category": detection.category,
                        "location_sha256": detection.location_sha256,
                        "evidence_sha256": detection.evidence_sha256,
                    }
                )
                finding_id = f"PDF-{finding_identity[:32]}"
                finding_payload = {
                    "schema": FINDING_SCHEMA,
                    "finding_id": finding_id,
                    "tenant_id": tenant,
                    "report_id": report_id,
                    "source_id": job_payload["source_id"],
                    "category": detection.category,
                    "confidence": confidence,
                    "ambiguous": bool(detection.ambiguous),
                    "location_sha256": detection.location_sha256,
                    "evidence_sha256": detection.evidence_sha256,
                    "detector": detector,
                    "revision": 1,
                }
                finding_digest = _sha256(finding_payload)
                connection.execute(
                    "INSERT INTO findings VALUES(?,?,?,?,?,?)",
                    (
                        tenant,
                        finding_id,
                        report_id,
                        job_payload["source_id"],
                        _canonical(finding_payload).decode("ascii"),
                        finding_digest,
                    ),
                )
            job_payload["state"] = "complete"
            job_payload["lease_owner"] = None
            job_payload["lease_until"] = None
            job_payload["revision"] = int(job_payload["revision"]) + 1
            self._update_job_row(connection, tenant, job_payload)
            self._audit(
                connection,
                tenant,
                "scan_completed",
                report_id,
                worker,
                {
                    "completeness": completeness,
                    "findings_count": len(detections),
                    "ambiguous_count": ambiguity,
                },
                moment,
            )
            connection.commit()
        return self.get_report(tenant, report_id)

    def get_report(self, tenant_id: str, report_id: str) -> ScanReport:
        tenant = _tenant_id(tenant_id)
        report = _opaque(report_id, "report_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM reports WHERE tenant_id=? AND report_id=?",
                (tenant, report),
            ).fetchone()
        if row is None:
            raise PrivacyDataDiscoveryNotFound("scan report does not exist for tenant")
        return self._report_from(
            self._row_payload(row, "report"), row["integrity_sha256"]
        )

    def list_reports(
        self,
        tenant_id: str,
        *,
        source_id: str | None = None,
        limit: int = 500,
    ) -> tuple[ScanReport, ...]:
        tenant = _tenant_id(tenant_id)
        source = None if source_id is None else _opaque(source_id, "source_id")
        count = _positive_int(limit, "limit", _MAX_LIST)
        query = "SELECT * FROM reports WHERE tenant_id=?"
        params: list[object] = [tenant]
        if source is not None:
            query += " AND source_id=?"
            params.append(source)
        query += " ORDER BY rowid DESC LIMIT ?"
        params.append(count)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return tuple(
            self._report_from(self._row_payload(row, "report"), row["integrity_sha256"])
            for row in rows
        )

    def get_finding(self, tenant_id: str, finding_id: str) -> Finding:
        tenant = _tenant_id(tenant_id)
        finding = _opaque(finding_id, "finding_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM findings WHERE tenant_id=? AND finding_id=?",
                (tenant, finding),
            ).fetchone()
        if row is None:
            raise PrivacyDataDiscoveryNotFound("finding does not exist for tenant")
        return self._finding_from(
            self._row_payload(row, "finding"), row["integrity_sha256"]
        )

    def list_findings(
        self,
        tenant_id: str,
        *,
        report_id: str,
        limit: int = 2_000,
    ) -> tuple[Finding, ...]:
        tenant = _tenant_id(tenant_id)
        report = _opaque(report_id, "report_id")
        count = _positive_int(limit, "limit", _MAX_LIST)
        self.get_report(tenant, report)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM findings WHERE tenant_id=? AND report_id=? "
                "ORDER BY finding_id LIMIT ?",
                (tenant, report, count),
            ).fetchall()
        return tuple(
            self._finding_from(self._row_payload(row, "finding"), row["integrity_sha256"])
            for row in rows
        )

    @staticmethod
    def _review_from(payload: Mapping[str, object], digest: str) -> ReviewProposal:
        values = dict(payload)
        values.pop("schema", None)
        return ReviewProposal(**values, integrity_sha256=digest)  # type: ignore[arg-type]

    def propose_review(
        self,
        tenant_id: str,
        finding_id: str,
        *,
        decision: str,
        effective_category: str | None,
        evidence_sha256: str,
        freshness_seconds: int,
        expected_finding_revision: int,
        prepared_by: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ReviewProposal:
        """Prepare, but do not apply, a versioned human classification review."""

        tenant = _tenant_id(tenant_id)
        finding = _opaque(finding_id, "finding_id")
        if decision not in _REVIEW_DECISIONS:
            raise PrivacyDataDiscoveryValidationError("review decision is closed")
        if decision == "false_positive":
            if effective_category is not None:
                raise PrivacyDataDiscoveryValidationError(
                    "false-positive review cannot retain a category"
                )
            effective = None
        else:
            effective = _category(effective_category)
        evidence = _digest(evidence_sha256, "evidence_sha256")
        freshness = _positive_int(
            freshness_seconds, "freshness_seconds", 365 * 24 * 3_600
        )
        expected = _positive_int(
            expected_finding_revision, "expected_finding_revision", 2**31 - 1
        )
        preparer = _opaque(prepared_by, "prepared_by")
        moment = _finite_time(self._clock() if now is None else now, "now")
        request = {
            "action": "propose_review",
            "finding_id": finding,
            "decision": decision,
            "effective_category": effective,
            "evidence_sha256": evidence,
            "freshness_seconds": freshness,
            "expected_finding_revision": expected,
            "prepared_by": preparer,
        }
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_review(tenant, operation["result_id"])
            finding_row = connection.execute(
                "SELECT * FROM findings WHERE tenant_id=? AND finding_id=?",
                (tenant, finding),
            ).fetchone()
            if finding_row is None:
                raise PrivacyDataDiscoveryNotFound("finding does not exist for tenant")
            finding_payload = self._row_payload(finding_row, "finding")
            if int(finding_payload["revision"]) != expected:
                raise PrivacyDataDiscoveryConflict(
                    "finding expected revision does not match"
                )
            latest = connection.execute(
                "SELECT * FROM reviews WHERE tenant_id=? AND finding_id=? "
                "ORDER BY rowid DESC LIMIT 1",
                (tenant, finding),
            ).fetchone()
            version = 1
            if latest is not None:
                previous = self._row_payload(latest, "review")
                if previous["status"] == "pending":
                    if moment <= float(previous["prepared_at"]) + int(
                        previous["freshness_seconds"]
                    ):
                        raise PrivacyDataDiscoveryConflict(
                            "finding already has a pending review"
                        )
                    previous["status"] = "expired"
                    expired_digest = _sha256(previous)
                    connection.execute(
                        "UPDATE reviews SET payload_json=?,integrity_sha256=? "
                        "WHERE tenant_id=? AND review_id=?",
                        (
                            _canonical(previous).decode("ascii"),
                            expired_digest,
                            tenant,
                            previous["review_id"],
                        ),
                    )
                    self._audit(
                        connection,
                        tenant,
                        "review_expired",
                        str(previous["review_id"]),
                        preparer,
                        {"version": previous["version"]},
                        moment,
                    )
                version = int(previous["version"]) + 1
            operation_sha = hashlib.sha256(idempotency_key.encode()).hexdigest()
            review_id = f"PDRW-{operation_sha[:32]}"
            payload = {
                "schema": REVIEW_SCHEMA,
                "review_id": review_id,
                "tenant_id": tenant,
                "finding_id": finding,
                "decision": decision,
                "effective_category": effective,
                "prepared_by": preparer,
                "prepared_at": moment,
                "evidence_sha256": evidence,
                "freshness_seconds": freshness,
                "status": "pending",
                "approved_by": None,
                "approved_at": None,
                "version": version,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO reviews VALUES(?,?,?,?,?)",
                (
                    tenant,
                    review_id,
                    finding,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "review", review_id
            )
            self._audit(
                connection,
                tenant,
                "review_proposed",
                review_id,
                preparer,
                {"decision": decision, "version": version},
                moment,
            )
            connection.commit()
        return self.get_review(tenant, review_id)

    def get_review(self, tenant_id: str, review_id: str) -> ReviewProposal:
        tenant = _tenant_id(tenant_id)
        review = _opaque(review_id, "review_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM reviews WHERE tenant_id=? AND review_id=?",
                (tenant, review),
            ).fetchone()
        if row is None:
            raise PrivacyDataDiscoveryNotFound("review does not exist for tenant")
        return self._review_from(
            self._row_payload(row, "review"), row["integrity_sha256"]
        )

    def list_reviews(
        self,
        tenant_id: str,
        *,
        finding_id: str,
        limit: int = 100,
    ) -> tuple[ReviewProposal, ...]:
        tenant = _tenant_id(tenant_id)
        finding = _opaque(finding_id, "finding_id")
        count = _positive_int(limit, "limit", _MAX_LIST)
        self.get_finding(tenant, finding)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM reviews WHERE tenant_id=? AND finding_id=? "
                "ORDER BY rowid DESC LIMIT ?",
                (tenant, finding, count),
            ).fetchall()
        return tuple(
            self._review_from(self._row_payload(row, "review"), row["integrity_sha256"])
            for row in rows
        )

    def list_all_reviews(
        self,
        tenant_id: str,
        *,
        status: str | None = None,
        limit: int = 200,
    ) -> tuple[ReviewProposal, ...]:
        """Read-only, newest-first review proposals across every finding,
        optionally only one status (for the approval queue)."""

        tenant = _tenant_id(tenant_id)
        count = _positive_int(limit, "limit", _MAX_LIST)
        # The status filter runs in SQL, before the newest-first limit, so an
        # older review still waiting for approval never drops out of the
        # queue behind newer decided ones. The payload is integrity-checked
        # below and the status re-checked on the verified value.
        if status is None:
            query = "SELECT * FROM reviews WHERE tenant_id=? ORDER BY rowid DESC LIMIT ?"
            params: tuple[object, ...] = (tenant, count)
        else:
            query = (
                "SELECT * FROM reviews WHERE tenant_id=? "
                "AND json_extract(payload_json, '$.status')=? ORDER BY rowid DESC LIMIT ?"
            )
            params = (tenant, str(status), count)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        reviews = [
            self._review_from(self._row_payload(row, "review"), row["integrity_sha256"])
            for row in rows
        ]
        if status is not None:
            reviews = [review for review in reviews if review.status == status]
        return tuple(reviews[:count])

    def approve_review(
        self,
        tenant_id: str,
        review_id: str,
        *,
        approved_by: str,
        expected_version: int,
        expected_integrity_sha256: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ReviewedClassification:
        """Apply a fresh, digest-bound review with human four-eyes separation."""

        tenant = _tenant_id(tenant_id)
        review = _opaque(review_id, "review_id")
        approver = _opaque(approved_by, "approved_by")
        version = _positive_int(expected_version, "expected_version", 2**31 - 1)
        expected_digest = _digest(
            expected_integrity_sha256, "expected_integrity_sha256"
        )
        moment = _finite_time(self._clock() if now is None else now, "now")
        request = {
            "action": "approve_review",
            "review_id": review,
            "expected_version": version,
            "expected_integrity_sha256": expected_digest,
            "approved_by": approver,
        }
        callback_update: ReviewedClassification | None = None
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                row = connection.execute(
                    "SELECT * FROM reviews WHERE tenant_id=? AND review_id=?",
                    (tenant, review),
                ).fetchone()
                if row is None:
                    raise PrivacyDataDiscoveryIntegrityError(
                        "idempotent review result is missing"
                    )
                payload = self._row_payload(row, "review")
                if payload["status"] != "approved":
                    raise PrivacyDataDiscoveryIntegrityError(
                        "idempotent review approval is not effective"
                    )
                callback_update = self._review_update(connection, payload)
                connection.commit()
            else:
                row = connection.execute(
                    "SELECT * FROM reviews WHERE tenant_id=? AND review_id=?",
                    (tenant, review),
                ).fetchone()
                if row is None:
                    raise PrivacyDataDiscoveryNotFound(
                        "review does not exist for tenant"
                    )
                payload = self._row_payload(row, "review")
                if row["integrity_sha256"] != expected_digest:
                    raise PrivacyDataDiscoveryConflict(
                        "review integrity CAS does not match"
                    )
                if payload["status"] != "pending" or int(payload["version"]) != version:
                    raise PrivacyDataDiscoveryConflict(
                        "review state or expected version does not match"
                    )
                if payload["prepared_by"] == approver:
                    raise PrivacyDataDiscoveryConflict(
                        "four-eyes approval requires a different human"
                    )
                if moment > float(payload["prepared_at"]) + int(
                    payload["freshness_seconds"]
                ):
                    raise PrivacyDataDiscoveryConflict("review evidence is stale")
                payload["status"] = "approved"
                payload["approved_by"] = approver
                payload["approved_at"] = moment
                digest = _sha256(payload)
                connection.execute(
                    "UPDATE reviews SET payload_json=?,integrity_sha256=? "
                    "WHERE tenant_id=? AND review_id=?",
                    (_canonical(payload).decode("ascii"), digest, tenant, review),
                )
                finding_row = connection.execute(
                    "SELECT * FROM findings WHERE tenant_id=? AND finding_id=?",
                    (tenant, payload["finding_id"]),
                ).fetchone()
                if finding_row is None:
                    raise PrivacyDataDiscoveryIntegrityError(
                        "review finding is missing"
                    )
                finding_payload = self._row_payload(finding_row, "finding")
                finding_payload["revision"] = int(finding_payload["revision"]) + 1
                finding_digest = _sha256(finding_payload)
                connection.execute(
                    "UPDATE findings SET payload_json=?,integrity_sha256=? "
                    "WHERE tenant_id=? AND finding_id=?",
                    (
                        _canonical(finding_payload).decode("ascii"),
                        finding_digest,
                        tenant,
                        payload["finding_id"],
                    ),
                )
                self._record_operation(
                    connection,
                    tenant,
                    idempotency_key,
                    request_sha,
                    "review_approval",
                    review,
                )
                self._audit(
                    connection,
                    tenant,
                    "review_approved",
                    review,
                    approver,
                    {
                        "decision": payload["decision"],
                        "version": payload["version"],
                        "four_eyes": True,
                    },
                    moment,
                )
                callback_update = self._review_update(connection, payload)
                connection.commit()
        if callback_update is None:
            raise PrivacyDataDiscoveryIntegrityError("review update was not constructed")
        if self._review_callback is not None and operation is None:
            try:
                self._review_callback(callback_update)
            except Exception as exc:
                # Do not roll back an effective human review or expose callback text.
                self._record_callback_failure(
                    tenant, review, approver, moment, "review_callback_failed"
                )
                raise PrivacyDataDiscoveryAdapterError(
                    "review callback failed after durable approval"
                ) from exc
        return callback_update

    def _review_update(
        self, connection: sqlite3.Connection, review_payload: Mapping[str, object]
    ) -> ReviewedClassification:
        finding_row = connection.execute(
            "SELECT * FROM findings WHERE tenant_id=? AND finding_id=?",
            (review_payload["tenant_id"], review_payload["finding_id"]),
        ).fetchone()
        if finding_row is None:
            raise PrivacyDataDiscoveryIntegrityError("review finding is missing")
        finding = self._row_payload(finding_row, "finding")
        return ReviewedClassification(
            tenant_id=str(review_payload["tenant_id"]),
            source_id=str(finding["source_id"]),
            report_id=str(finding["report_id"]),
            finding_id=str(finding["finding_id"]),
            review_id=str(review_payload["review_id"]),
            decision=str(review_payload["decision"]),
            category=(
                None
                if review_payload["effective_category"] is None
                else str(review_payload["effective_category"])
            ),
            evidence_sha256=str(review_payload["evidence_sha256"]),
            reviewed_at=float(review_payload["approved_at"]),
            review_version=int(review_payload["version"]),
        )

    def _record_callback_failure(
        self,
        tenant: str,
        review: str,
        actor: str,
        moment: float,
        code: str,
    ) -> None:
        with self._connect() as connection:
            self._begin(connection)
            self._audit(
                connection,
                tenant,
                "review_callback_failed",
                review,
                actor,
                {"error_code": code},
                moment,
            )
            connection.commit()

    def inventory(
        self,
        tenant_id: str,
        *,
        source_id: str | None = None,
        now: float | None = None,
    ) -> InventorySnapshot:
        """Build a digest-only inventory from the latest report per source."""

        tenant = _tenant_id(tenant_id)
        source = None if source_id is None else _opaque(source_id, "source_id")
        moment = _finite_time(self._clock() if now is None else now, "now")
        reports = self.list_reports(tenant, source_id=source, limit=_MAX_LIST)
        with self._connect() as connection:
            if source is None:
                report_total = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM reports WHERE tenant_id=?", (tenant,)
                    ).fetchone()[0]
                )
            else:
                report_total = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM reports WHERE tenant_id=? AND source_id=?",
                        (tenant, source),
                    ).fetchone()[0]
                )
        truncated = report_total > len(reports)
        selected: dict[str, ScanReport] = {}
        for report in reports:
            selected.setdefault(report.source_id, report)
        counts: dict[str, int] = {}
        unreviewed = 0
        false_positives = 0
        ambiguous = 0
        with self._connect() as connection:
            for report in selected.values():
                rows = connection.execute(
                    "SELECT * FROM findings WHERE tenant_id=? AND report_id=?",
                    (tenant, report.report_id),
                ).fetchall()
                for row in rows:
                    finding = self._finding_from(
                        self._row_payload(row, "finding"), row["integrity_sha256"]
                    )
                    review_row = connection.execute(
                        "SELECT * FROM reviews WHERE tenant_id=? AND finding_id=? "
                        "ORDER BY rowid DESC LIMIT 1",
                        (tenant, finding.finding_id),
                    ).fetchone()
                    if review_row is None:
                        category = finding.category
                        unreviewed += 1
                    else:
                        review = self._review_from(
                            self._row_payload(review_row, "review"),
                            review_row["integrity_sha256"],
                        )
                        if review.status != "approved":
                            category = finding.category
                            unreviewed += 1
                        elif review.decision == "false_positive":
                            false_positives += 1
                            continue
                        else:
                            if review.effective_category is None:
                                raise PrivacyDataDiscoveryIntegrityError(
                                    "approved review lacks an effective category"
                                )
                            category = review.effective_category
                    counts[category] = counts.get(category, 0) + 1
                    if finding.ambiguous:
                        ambiguous += 1
        completeness_values = {report.completeness for report in selected.values()}
        if truncated:
            completeness = "inventory_report_limit_reached"
        elif not selected:
            completeness = "no_reports"
        elif completeness_values == {"complete_within_declared_bounds"}:
            completeness = "latest_reports_complete_within_declared_bounds"
        else:
            completeness = "latest_reports_include_bounded_partial_results"
        payload = {
            "tenant_id": tenant,
            "source_id": source,
            "report_ids": sorted(report.report_id for report in selected.values()),
            "counts_by_category": dict(sorted(counts.items())),
            "unreviewed_count": unreviewed,
            "false_positive_count": false_positives,
            "ambiguous_count": ambiguous,
            "completeness": completeness,
            "truncated": truncated,
            "limitations": [
                "latest_immutable_report_per_included_source",
                "unreviewed_findings_are_not_authoritative_data_map_updates",
                "scan_report_limit_may_bound_inventory" if truncated else "none",
            ],
            "generated_at": moment,
        }
        return InventorySnapshot(
            tenant_id=tenant,
            source_id=source,
            report_ids=tuple(payload["report_ids"]),
            counts_by_category=payload["counts_by_category"],
            unreviewed_count=unreviewed,
            false_positive_count=false_positives,
            ambiguous_count=ambiguous,
            completeness=completeness,
            truncated=truncated,
            limitations=tuple(payload["limitations"]),
            generated_at=moment,
            integrity_sha256=_sha256(payload),
        )

    def diff_reports(
        self,
        tenant_id: str,
        base_report_id: str,
        target_report_id: str,
    ) -> InventoryDiff:
        """Compare two immutable reports using non-reversible finding fingerprints."""

        tenant = _tenant_id(tenant_id)
        base = self.get_report(tenant, base_report_id)
        target = self.get_report(tenant, target_report_id)
        if base.source_id != target.source_id:
            raise PrivacyDataDiscoveryValidationError(
                "inventory diff requires reports from the same source"
            )
        if (not base.evidence_key_fingerprint or not target.evidence_key_fingerprint
                or base.evidence_key_fingerprint != target.evidence_key_fingerprint
                or not base.source_scope_sha256 or base.source_scope_sha256 != target.source_scope_sha256):
            raise PrivacyDataDiscoveryValidationError(
                "reports use different or unverified evidence key generations/source scopes; establish a new comparison baseline"
            )

        def fingerprints(report_id: str) -> set[str]:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM findings WHERE tenant_id=? AND report_id=?",
                    (tenant, report_id),
                ).fetchall()
            result: set[str] = set()
            for row in rows:
                item = self._finding_from(
                    self._row_payload(row, "finding"), row["integrity_sha256"]
                )
                result.add(
                    _sha256(
                        {
                            "category": item.category,
                            "location_sha256": item.location_sha256,
                            "evidence_sha256": item.evidence_sha256,
                        }
                    )
                )
            return result

        base_set = fingerprints(base.report_id)
        target_set = fingerprints(target.report_id)
        payload = {
            "tenant_id": tenant,
            "base_report_id": base.report_id,
            "target_report_id": target.report_id,
            "added_finding_sha256": sorted(target_set - base_set),
            "removed_finding_sha256": sorted(base_set - target_set),
            "unchanged_count": len(base_set & target_set),
            "base_completeness": base.completeness,
            "target_completeness": target.completeness,
        }
        return InventoryDiff(
            tenant_id=tenant,
            base_report_id=base.report_id,
            target_report_id=target.report_id,
            added_finding_sha256=tuple(payload["added_finding_sha256"]),
            removed_finding_sha256=tuple(payload["removed_finding_sha256"]),
            unchanged_count=int(payload["unchanged_count"]),
            base_completeness=base.completeness,
            target_completeness=target.completeness,
            integrity_sha256=_sha256(payload),
        )

    def audit_events(
        self, tenant_id: str, *, limit: int = 500
    ) -> tuple[AuditEvent, ...]:
        tenant = _tenant_id(tenant_id)
        count = _positive_int(limit, "limit", _MAX_AUDIT_LIST)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events WHERE tenant_id=? "
                "ORDER BY sequence LIMIT ?",
                (tenant, count),
            ).fetchall()
        events: list[AuditEvent] = []
        for row in rows:
            payload = self._row_payload(row, "audit event")
            payload.pop("schema", None)
            events.append(
                AuditEvent(  # type: ignore[arg-type]
                    **payload, integrity_sha256=row["integrity_sha256"]
                )
            )
        return tuple(events)

    def verify_audit_chain(self, tenant_id: str) -> bool:
        tenant = _tenant_id(tenant_id)
        previous = "0" * 64
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
        expected_sequence = 1
        for row in rows:
            payload = self._row_payload(row, "audit event")
            if (
                int(payload["sequence"]) != expected_sequence
                or payload["previous_sha256"] != previous
            ):
                raise PrivacyDataDiscoveryIntegrityError("audit chain is discontinuous")
            previous = row["integrity_sha256"]
            expected_sequence += 1
        return True

    def purge_expired(
        self,
        tenant_id: str,
        *,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> int:
        """Apply configured report retention and leave digest-only audit tombstones."""

        tenant = _tenant_id(tenant_id)
        actor = _opaque(actor_ref, "actor_ref")
        moment = _finite_time(self._clock() if now is None else now, "now")
        request = {"action": "purge_expired", "cutoff": moment, "actor_ref": actor}
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return int(operation["result_id"])
            rows = connection.execute(
                "SELECT * FROM reports WHERE tenant_id=?", (tenant,)
            ).fetchall()
            expired: list[str] = []
            for row in rows:
                payload = self._row_payload(row, "report")
                if float(payload["retention_until"]) <= moment:
                    expired.append(str(payload["report_id"]))
            for report_id in expired:
                connection.execute(
                    "DELETE FROM operations WHERE tenant_id=? AND result_id IN "
                    "(SELECT review_id FROM reviews WHERE tenant_id=? AND finding_id IN "
                    "(SELECT finding_id FROM findings WHERE tenant_id=? AND report_id=?))",
                    (tenant, tenant, tenant, report_id),
                )
                connection.execute(
                    "DELETE FROM reports WHERE tenant_id=? AND report_id=?",
                    (tenant, report_id),
                )
                self._audit(
                    connection,
                    tenant,
                    "report_retention_purged",
                    report_id,
                    actor,
                    {},
                    moment,
                )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "purge_count",
                str(len(expired)),
            )
            connection.commit()
        return len(expired)

    @staticmethod
    def privacy_posture() -> Mapping[str, object]:
        """Return explicit product boundaries, not an assurance claim."""

        return {
            "raw_values_persisted": False,
            "document_text_persisted": False,
            "samples_persisted": False,
            "credential_values_persisted": False,
            "evidence_digest": "tenant_keyed_hmac_sha256",
            "source_scope": "exact_enrolled_https_authority_and_resource_ref",
            "network_boundary": "injected_adapter_must_enforce_dns_pinning",
            "completeness_claim": False,
            "live_provider_acceptance": False,
            "limitations_are_reported": True,
        }


class PrivacyDataDiscoveryCoordinator:
    """Runs leased jobs through injected offline-testable provider adapters."""

    _TEXT_MEDIA_TYPES = frozenset(
        {
            "application/json",
            "application/ld+json",
            "application/xml",
            "text/csv",
            "text/html",
            "text/plain",
            "text/xml",
        }
    )

    def __init__(
        self,
        store: PrivacyDataDiscoveryStore,
        *,
        structured_sources: Mapping[str, StructuredRowSource] | None = None,
        unstructured_sources: Mapping[str, UnstructuredDocumentSource] | None = None,
        clock: Callable[[], float] = time.time,
        credential_ref_present: Callable[[str], bool] | None = None,
    ) -> None:
        self.store = store
        self._structured = dict(structured_sources or {})
        self._unstructured = dict(unstructured_sources or {})
        self._clock = clock
        from .privacy_data_discovery_adapters import credential_reference_present

        self._credential_ref_present = (
            credential_ref_present
            if credential_ref_present is not None
            else credential_reference_present
        )

    @staticmethod
    def _ephemeral_json(value: object, maximum: int) -> bytes:
        try:
            encoded = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise PrivacyDataDiscoveryValidationError(
                "provider record is not bounded JSON"
            ) from exc
        if len(encoded) > maximum:
            raise PrivacyDataDiscoveryValidationError(
                "provider record exceeds its ephemeral byte bound"
            )
        return encoded

    @staticmethod
    def _append_detections(
        target: list[Detection],
        additions: Iterable[Detection],
        seen: set[tuple[str, str, str]],
        maximum: int,
    ) -> bool:
        for item in additions:
            key = (item.category, item.location_sha256, item.evidence_sha256)
            if key in seen:
                continue
            if len(target) >= maximum:
                return False
            seen.add(key)
            target.append(item)
        return True

    def _scan_structured(
        self,
        source: EnrolledSource,
        job: ScanJob,
        detector: PersonalDataDetector,
        deadline: float,
    ) -> tuple[int, int, int, list[Detection], list[str], list[str]]:
        adapter = self._structured.get(source.provider)
        if adapter is None:
            raise PrivacyDataDiscoveryAdapterError(
                "no structured adapter is registered for the enrolled provider"
            )
        detections: list[Detection] = []
        seen: set[tuple[str, str, str]] = set()
        truncations: list[str] = []
        errors: list[str] = []
        records = 0
        byte_count = 0
        try:
            rows = adapter.iter_rows(
                source=source,
                credential_env=source.credential_env,
                limits=job.limits,
                deadline=deadline,
            )
            for row in rows:
                if self._clock() > deadline:
                    truncations.append("time_limit")
                    break
                if records >= job.limits.max_records:
                    truncations.append("record_limit")
                    break
                if not isinstance(row, StructuredRecord):
                    errors.append("invalid_record")
                    if len(errors) >= _MAX_ERRORS:
                        truncations.append("error_limit")
                        break
                    continue
                record_ref = _opaque(row.record_ref, "record_ref")
                if not isinstance(row.fields, Mapping):
                    errors.append("invalid_record")
                    continue
                try:
                    encoded = self._ephemeral_json(
                        dict(row.fields), job.limits.max_record_bytes
                    )
                except PrivacyDataDiscoveryValidationError:
                    errors.append("record_too_large_or_invalid")
                    continue
                if byte_count + len(encoded) > job.limits.max_bytes:
                    truncations.append("byte_limit")
                    break
                byte_count += len(encoded)
                records += 1
                items = list(row.fields.items())
                if len(items) > job.limits.max_fields_per_record:
                    items = items[: job.limits.max_fields_per_record]
                    truncations.append("field_limit")
                base_location = (
                    source.source_id + "\x00" + record_ref
                ).encode("utf-8")
                for name, value in items:
                    if not isinstance(name, str) or not 1 <= len(name) <= 512:
                        errors.append("invalid_field_name")
                        continue
                    additions = detector.detect_field(
                        name, value, location=base_location
                    )
                    if not self._append_detections(
                        detections,
                        additions,
                        seen,
                        job.limits.max_findings,
                    ):
                        truncations.append("finding_limit")
                        return records, 0, byte_count, detections, truncations, errors
        except PrivacyDataDiscoveryError:
            raise
        except Exception as exc:
            raise PrivacyDataDiscoveryAdapterError(
                "structured provider adapter failed"
            ) from exc
        return records, 0, byte_count, detections, truncations, errors[:_MAX_ERRORS]

    def _scan_unstructured(
        self,
        source: EnrolledSource,
        job: ScanJob,
        detector: PersonalDataDetector,
        deadline: float,
    ) -> tuple[int, int, int, list[Detection], list[str], list[str]]:
        adapter = self._unstructured.get(source.provider)
        if adapter is None:
            raise PrivacyDataDiscoveryAdapterError(
                "no unstructured adapter is registered for the enrolled provider"
            )
        detections: list[Detection] = []
        seen: set[tuple[str, str, str]] = set()
        truncations: list[str] = []
        errors: list[str] = []
        files = 0
        byte_count = 0
        try:
            documents = adapter.iter_documents(
                source=source,
                credential_env=source.credential_env,
                limits=job.limits,
                deadline=deadline,
            )
            for document in documents:
                if self._clock() > deadline:
                    truncations.append("time_limit")
                    break
                if files >= job.limits.max_files:
                    truncations.append("file_limit")
                    break
                if not isinstance(document, UnstructuredDocument):
                    errors.append("invalid_document")
                    continue
                document_ref = _opaque(document.document_ref, "document_ref")
                media_type = (
                    document.media_type.split(";", 1)[0].strip().lower()
                    if isinstance(document.media_type, str)
                    else ""
                )
                if media_type not in self._TEXT_MEDIA_TYPES:
                    errors.append("unsupported_media_type")
                    files += 1
                    continue
                if isinstance(document.content, str):
                    encoded = document.content.encode("utf-8", errors="replace")
                    text = document.content
                elif isinstance(document.content, bytes):
                    encoded = document.content
                    text = encoded.decode("utf-8", errors="replace")
                else:
                    errors.append("invalid_document")
                    continue
                if len(encoded) > job.limits.max_document_bytes:
                    errors.append("document_too_large")
                    truncations.append("document_byte_limit")
                    files += 1
                    continue
                if byte_count + len(encoded) > job.limits.max_bytes:
                    truncations.append("byte_limit")
                    break
                byte_count += len(encoded)
                files += 1
                location = (source.source_id + "\x00" + document_ref).encode("utf-8")
                additions = detector.detect_document(text, location=location)
                if not self._append_detections(
                    detections, additions, seen, job.limits.max_findings
                ):
                    truncations.append("finding_limit")
                    break
        except PrivacyDataDiscoveryError:
            raise
        except Exception as exc:
            raise PrivacyDataDiscoveryAdapterError(
                "unstructured provider adapter failed"
            ) from exc
        return 0, files, byte_count, detections, truncations, errors[:_MAX_ERRORS]

    def execute_job(self, job: ScanJob, *, worker_id: str, expected_source_sha256: str | None = None,
                    before_effect=None) -> ScanReport:
        """Execute one already-leased job; raw provider content is never returned."""

        worker = _opaque(worker_id, "worker_id")
        current = self.store.get_job(job.tenant_id, job.job_id)
        if (
            current.state != "leased"
            or current.lease_owner != worker
            or current.revision != job.revision
        ):
            raise PrivacyDataDiscoveryLeaseLost("scan job lease is no longer owned")
        source = self.store.get_source(job.tenant_id, job.source_id)
        if source.state != "active":
            raise PrivacyDataDiscoveryConflict("source is not active")
        if expected_source_sha256 is not None and source.integrity_sha256 != expected_source_sha256:
            raise PrivacyDataDiscoveryConflict("This source changed after review. No report was committed.")
        if source.credential_env.startswith("connection:") or source.evidence_key_env.startswith("evidence-key:"):
            from .paths import current_tenant_id_strict

            if current_tenant_id_strict() != job.tenant_id:
                raise PrivacyDataDiscoveryConfigError("saved discovery references require the exact job tenant context")
        if not self._credential_ref_present(source.credential_env):
            raise PrivacyDataDiscoveryConfigError(
                "enrolled credential reference is unavailable or changed; update the saved source selection"
            )
        root_evidence_key = self.store._evidence_key_resolver(source.evidence_key_env)
        if not isinstance(root_evidence_key, bytes) or len(root_evidence_key) < 32:
            raise PrivacyDataDiscoveryConfigError(
                "evidence HMAC key resolver returned insufficient key material"
            )
        evidence_key = hmac.new(
            root_evidence_key,
            b"lightwork-privacy-discovery-tenant\x00" + job.tenant_id.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        detector = PersonalDataDetector(evidence_key)
        started = _finite_time(self._clock(), "started_at")
        deadline = started + job.limits.max_seconds
        if before_effect is not None:
            before_effect()
        if source.kind == "structured":
            result = self._scan_structured(source, job, detector, deadline)
        elif source.kind == "unstructured":
            result = self._scan_unstructured(source, job, detector, deadline)
        else:
            raise PrivacyDataDiscoveryIntegrityError("source kind is unsupported")
        records, files, byte_count, detections, truncations, errors = result
        if source.evidence_key_env.startswith("evidence-key:"):
            # Rotation during a scan must not publish fresh evidence under the
            # retired reference. A later scan requires explicit source update.
            if self.store._evidence_key_resolver(source.evidence_key_env) != root_evidence_key:
                raise PrivacyDataDiscoveryConfigError("evidence key changed during scan")
        finished = _finite_time(self._clock(), "finished_at")
        if finished > deadline and "time_limit" not in truncations:
            truncations.append("time_limit")
        if before_effect is not None:
            before_effect()
        return self.store._complete_job(
            job.tenant_id,
            job.job_id,
            worker_id=worker,
            started_at=started,
            finished_at=finished,
            records_seen=records,
            files_seen=files,
            bytes_seen=byte_count,
            detections=detections,
            truncation_reasons=truncations,
            error_codes=errors,
            evidence_key_fingerprint=hmac.new(evidence_key, b"lightwork-discovery-comparison-key-v1", hashlib.sha256).hexdigest(),
            source_scope_sha256=_sha256({"provider": source.provider, "origin": source.origin, "resource_ref": source.resource_ref}),
            expected_source_sha256=source.integrity_sha256,
            before_write=before_effect,
        )

    def run_once(
        self,
        tenant_id: str,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: float = 600.0,
        now: float | None = None,
    ) -> DiscoveryRunResult:
        """Claim a bounded batch; interrupted jobs never prevent independent work.

        A changed source is retried only while this worker still owns the lease.
        Lost leases are reported from current retained state without mutating
        another worker's job or claiming that its scan completed.
        """

        tenant = _tenant_id(tenant_id)
        worker = _opaque(worker_id, "worker_id")
        jobs = self.store.claim_jobs(
            tenant,
            worker_id=worker,
            limit=limit,
            lease_seconds=lease_seconds,
            now=now,
        )
        completed: list[ScanReport] = []
        failed: list[ScanJob] = []
        interrupted: list[ScanJob] = []
        for job in jobs:
            try:
                completed.append(self.execute_job(job, worker_id=worker))
            except PrivacyDataDiscoveryLeaseLost:
                interrupted.append(self.store.get_job(tenant, job.job_id))
            except (PrivacyDataDiscoveryConfigError, PrivacyDataDiscoveryAdapterError,
                    PrivacyDataDiscoveryValidationError, PrivacyDataDiscoveryConflict) as exc:
                if isinstance(exc, PrivacyDataDiscoveryConfigError):
                    error_code = "credential_unavailable"
                elif isinstance(exc, PrivacyDataDiscoveryAdapterError):
                    error_code = "adapter_error"
                elif isinstance(exc, PrivacyDataDiscoveryValidationError):
                    error_code = "provider_contract_invalid"
                else:
                    error_code = "source_changed"
                try:
                    failed.append(
                        self.store.fail_job(tenant, job.job_id, worker_id=worker,
                                            error_code=error_code)
                    )
                except PrivacyDataDiscoveryLeaseLost:
                    interrupted.append(self.store.get_job(tenant, job.job_id))
        return DiscoveryRunResult(
            tenant_id=tenant,
            worker_id=worker,
            completed_reports=tuple(completed),
            failed_jobs=tuple(failed),
            interrupted_jobs=tuple(interrupted),
        )


__all__ = [
    "AUDIT_SCHEMA",
    "FINDING_SCHEMA",
    "REPORT_SCHEMA",
    "REVIEW_SCHEMA",
    "AuditEvent",
    "Detection",
    "DiscoveryRunResult",
    "DiscoverySchedule",
    "EnrolledSource",
    "Finding",
    "InventoryDiff",
    "InventorySnapshot",
    "PersonalDataDetector",
    "PrivacyDataDiscoveryAdapterError",
    "PrivacyDataDiscoveryConfigError",
    "PrivacyDataDiscoveryConflict",
    "PrivacyDataDiscoveryCoordinator",
    "PrivacyDataDiscoveryError",
    "PrivacyDataDiscoveryIntegrityError",
    "PrivacyDataDiscoveryLeaseLost",
    "PrivacyDataDiscoveryNotFound",
    "PrivacyDataDiscoveryStore",
    "PrivacyDataDiscoveryValidationError",
    "ReviewProposal",
    "ReviewedClassification",
    "ReviewedDataMapCallback",
    "ScanJob",
    "ScanLimits",
    "ScanReport",
    "StructuredRecord",
    "StructuredRowSource",
    "UnstructuredDocument",
    "UnstructuredDocumentSource",
    "enabled",
    "require_enabled",
]
