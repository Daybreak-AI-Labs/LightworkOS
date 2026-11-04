"""Governed, provider-neutral third-party intelligence authority.

This module stores control-plane evidence only.  It performs no network calls,
ships no sanctions or vendor-intelligence corpus, and makes no claim that a
provider, customer, regulator, or production estate accepted the result.
Credentials remain external: only environment-variable names and encrypted
profile/vault references are retained. Identity attributes are represented by
caller-computed SHA-256 digests; ``display_label`` is therefore a bounded
operator label and must not be used for plaintext sensitive profile data.

The capability fails closed unless both exact gates are true::

    [third_party_management]
    enable = true
    [third_party_management.intelligence]
    enable = true

Sanctions, politically exposed person (PEP), and adverse-media candidates can
never be silently dismissed.  They block low-risk autoapproval until an
independent human records a reviewed disposition; confirmed matches continue
to block.  Autoapproval is otherwise possible only under an independently
approved, explicit policy whose complete and fresh evidence gates all pass.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .authority_effects import authority_effect_fence
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
AUDIT_SCHEMA = "lightwork.third-party-intelligence-audit.v1"

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_ENV_RE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_TERRITORY_RE = re.compile(r"[A-Z][A-Z0-9-]{1,31}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_LIST = 1_000
_MIN_RETENTION_SECONDS = 24 * 60 * 60
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 60 * 60
_MAX_LEASE_SECONDS = 60 * 60
_MAX_BACKOFF_SECONDS = 7 * 24 * 60 * 60

SOURCE_KINDS = frozenset(
    {
        "sanctions",
        "pep",
        "watchlist",
        "adverse_media",
        "cyber_posture",
        "breach_intelligence",
        "compliance",
        "performance",
    }
)
MANDATORY_REVIEW_KINDS = frozenset({"sanctions", "pep", "adverse_media"})
MANDATORY_AUTOAPPROVAL_KINDS = frozenset(
    {
        "sanctions",
        "pep",
        "watchlist",
        "adverse_media",
        "cyber_posture",
        "breach_intelligence",
    }
)
SOURCE_PURPOSES = frozenset(
    {"screening", "monitoring", "risk_scoring", "edd", "exchange"}
)
SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})
SEVERITY_POINTS = {
    "informational": 0,
    "low": 5,
    "medium": 15,
    "high": 35,
    "critical": 60,
}
FINDING_DISPOSITIONS = frozenset(
    {"pending_review", "false_positive", "confirmed", "not_a_match", "escalated"}
)
DATA_ACCESS_LEVELS = {"none": 0, "limited": 1, "standard": 2, "sensitive": 3}
RISK_FACTOR_KEYS = frozenset(
    {"inherent_risk", "criticality", *SOURCE_KINDS}
)
EDD_DECISIONS = frozenset({"approved", "rejected", "escalated"})
OUTBOX_STATES = frozenset(
    {"pending", "leased", "dispatching", "ambiguous", "delivered", "cancelled", "dead_letter"}
)


class ThirdPartyIntelligenceError(RuntimeError):
    """Base error for the third-party intelligence authority."""


class ThirdPartyIntelligenceConfigError(ThirdPartyIntelligenceError):
    """The authority is not explicitly enabled."""


class ThirdPartyIntelligenceValidationError(ThirdPartyIntelligenceError, ValueError):
    """Input is outside a closed schema or safety bound."""


class ThirdPartyIntelligenceConflict(ThirdPartyIntelligenceError):
    """A CAS, idempotency, lease, or state precondition failed."""


class ThirdPartyIntelligenceNotFound(ThirdPartyIntelligenceError):
    """A tenant-scoped object is absent or deliberately undisclosed."""


class ThirdPartyIntelligencePermissionDenied(ThirdPartyIntelligenceError):
    """The approved data rights, policy, or human authority is insufficient."""


class ThirdPartyIntelligenceIntegrityError(ThirdPartyIntelligenceError):
    """Persisted state or its audit chain failed integrity verification."""


def enabled() -> bool:
    """Return true only for the exact parent and intelligence gates."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    third_party = config.get("third_party_management")
    intelligence = (
        third_party.get("intelligence") if isinstance(third_party, Mapping) else None
    )
    return (
        isinstance(third_party, Mapping)
        and third_party.get("enable") is True
        and isinstance(intelligence, Mapping)
        and intelligence.get("enable") is True
    )


def require_enabled() -> None:
    if not enabled():
        raise ThirdPartyIntelligenceConfigError(
            "third-party intelligence is disabled; explicitly enable "
            "third_party_management and third_party_management.intelligence"
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
        raise ThirdPartyIntelligenceValidationError(
            "third-party intelligence state must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise ThirdPartyIntelligenceValidationError(
            "third-party intelligence state exceeds its canonical byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ThirdPartyIntelligenceValidationError("tenant_id is invalid") from exc


def _id(
    value: object,
    label: str,
    pattern: re.Pattern[str] = _ID_RE,
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ThirdPartyIntelligenceValidationError(
            f"{label} must be a bounded opaque identifier"
        )
    return value


def _text(value: object, label: str, maximum: int, *, minimum: int = 1) -> str:
    if not isinstance(value, str):
        raise ThirdPartyIntelligenceValidationError(f"{label} must be text")
    normalized = value.strip()
    if _CONTROL_RE.search(normalized):
        raise ThirdPartyIntelligenceValidationError(
            f"{label} contains control characters"
        )
    length = len(normalized.encode("utf-8"))
    if not minimum <= length <= maximum:
        raise ThirdPartyIntelligenceValidationError(
            f"{label} must contain between {minimum} and {maximum} UTF-8 bytes"
        )
    return normalized


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ThirdPartyIntelligenceValidationError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise ThirdPartyIntelligenceValidationError(
            f"{label} must be a positive finite timestamp"
        )
    return float(value)


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ThirdPartyIntelligenceValidationError(
            f"{label} must be an integer between {minimum} and {maximum}"
        )
    return value


def _fraction(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 1.0
    ):
        raise ThirdPartyIntelligenceValidationError(
            f"{label} must be finite between zero and one"
        )
    return float(value)


def _retention(value: object) -> int:
    return _integer(
        value,
        "retention_seconds",
        _MIN_RETENTION_SECONDS,
        _MAX_RETENTION_SECONDS,
    )


def _closed_list(
    values: Sequence[str],
    label: str,
    allowed: frozenset[str] | None = None,
    *,
    maximum: int = 100,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ThirdPartyIntelligenceValidationError(f"{label} must be a list")
    if not 1 <= len(values) <= maximum:
        raise ThirdPartyIntelligenceValidationError(
            f"{label} must contain between 1 and {maximum} values"
        )
    result = tuple(sorted(_id(item, label) for item in values))
    if len(result) != len(set(result)):
        raise ThirdPartyIntelligenceValidationError(f"{label} contains duplicates")
    if allowed is not None and not set(result).issubset(allowed):
        raise ThirdPartyIntelligenceValidationError(
            f"{label} contains an unsupported value"
        )
    return result


def _territories(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ThirdPartyIntelligenceValidationError("territories must be a list")
    if not 1 <= len(values) <= 100:
        raise ThirdPartyIntelligenceValidationError(
            "territories must contain between 1 and 100 values"
        )
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or not _TERRITORY_RE.fullmatch(value):
            raise ThirdPartyIntelligenceValidationError(
                "territory must be an uppercase bounded identifier"
            )
        result.append(value)
    if len(result) != len(set(result)):
        raise ThirdPartyIntelligenceValidationError("territories contain duplicates")
    return tuple(sorted(result))


def _https_uri(value: object, label: str) -> str:
    uri = _text(value, label, 2_048)
    parsed = urlparse(uri)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ThirdPartyIntelligenceValidationError(
            f"{label} must be a credential-free HTTPS URI"
        )
    return uri


@dataclass(frozen=True)
class Citation:
    citation_id: str
    title: str
    uri: str
    pinpoint: str


def _citation(value: Mapping[str, object]) -> Citation:
    if not isinstance(value, Mapping) or set(value) != {
        "citation_id",
        "title",
        "uri",
        "pinpoint",
    }:
        raise ThirdPartyIntelligenceValidationError("citation schema is closed")
    return Citation(
        citation_id=_id(value["citation_id"], "citation_id"),
        title=_text(value["title"], "citation title", 500),
        uri=_https_uri(value["uri"], "citation uri"),
        pinpoint=_text(value["pinpoint"], "citation pinpoint", 500),
    )


def _citations(values: Sequence[Mapping[str, object]]) -> tuple[Citation, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ThirdPartyIntelligenceValidationError("citations must be a list")
    if not 1 <= len(values) <= 100:
        raise ThirdPartyIntelligenceValidationError(
            "citations must contain between 1 and 100 values"
        )
    result = tuple(_citation(item) for item in values)
    if len({item.citation_id for item in result}) != len(result):
        raise ThirdPartyIntelligenceValidationError("citation IDs must be unique")
    return result


def _citation_json(values: Sequence[Citation]) -> list[dict[str, str]]:
    return [
        {
            "citation_id": item.citation_id,
            "title": item.title,
            "uri": item.uri,
            "pinpoint": item.pinpoint,
        }
        for item in values
    ]


@dataclass(frozen=True)
class IntelligenceSource:
    tenant_id: str
    source_id: str
    provider: str
    kind: str
    provenance_uri: str
    credential_env: str
    license_ref: str
    rights_basis: str
    purposes: tuple[str, ...]
    territories: tuple[str, ...]
    retention_seconds: int
    state: str
    revision: int
    enrolled_by: str
    approved_by: str | None
    enrolled_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class SourceSnapshot:
    tenant_id: str
    snapshot_id: str
    source_id: str
    source_revision: int
    dataset_revision: str
    observed_at: float
    valid_until: float
    completeness: float
    record_count: int
    evidence_sha256: str
    citations: tuple[Citation, ...]
    provenance_uri: str
    retained_until: float
    created_by: str
    created_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class VendorProfile:
    tenant_id: str
    vendor_id: str
    display_label: str
    entity_identity_sha256: str
    encrypted_profile_ref: str
    profile_key_ref: str
    territories: tuple[str, ...]
    service_categories: tuple[str, ...]
    inherent_risk_level: int
    criticality: int
    data_access_level: str
    owner_ref: str
    state: str
    revision: int
    created_at: float
    updated_at: float
    integrity_sha256: str
    register_vendor_id: str | None = None


@dataclass(frozen=True)
class VendorRelationship:
    tenant_id: str
    relationship_id: str
    vendor_id: str
    related_vendor_id: str | None
    relationship_type: str
    scope_ref: str
    criticality: int
    data_access_level: str
    revision: int
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class ScreeningRun:
    tenant_id: str
    run_id: str
    vendor_id: str
    subject_identity_sha256: str
    snapshot_bindings: Mapping[str, str]
    requested_kinds: tuple[str, ...]
    state: str
    revision: int
    initiated_by: str
    initiated_at: float
    completed_at: float | None
    integrity_sha256: str


@dataclass(frozen=True)
class ScreeningFinding:
    tenant_id: str
    finding_id: str
    run_id: str
    vendor_id: str
    source_id: str
    kind: str
    candidate_ref: str
    match_confidence: float
    severity: str
    observed_at: float
    valid_until: float
    evidence_sha256: str
    citations: tuple[Citation, ...]
    disposition: str
    detected_by: str
    reviewed_by: str | None
    review_rationale: str | None
    revision: int
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class RiskPolicy:
    tenant_id: str
    policy_id: str
    version: int
    required_source_kinds: tuple[str, ...]
    maximum_source_age_seconds: int
    minimum_completeness: float
    factor_weights: Mapping[str, int]
    maximum_autoapproval_score: int
    allow_low_risk_autoapproval: bool
    allowed_territories: tuple[str, ...]
    maximum_vendor_criticality: int
    maximum_data_access_level: str
    state: str
    authored_by: str
    approved_by: str | None
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class RiskDecision:
    tenant_id: str
    decision_id: str
    vendor_id: str
    run_id: str
    policy_id: str
    policy_version: int
    status: str
    score: int
    factors: Mapping[str, int]
    reason_codes: tuple[str, ...]
    evidence_sha256: str
    autoapproved: bool
    revision: int
    decided_by: str
    decided_at: float
    supersedes_decision_id: str | None
    rolled_back_from: str | None
    integrity_sha256: str


@dataclass(frozen=True)
class EDDCase:
    tenant_id: str
    case_id: str
    vendor_id: str
    reason: str
    severity: str
    state: str
    tasks: tuple[Mapping[str, object], ...]
    evidence: tuple[Mapping[str, object], ...]
    decision: str | None
    decision_rationale: str | None
    opened_by: str
    decided_by: str | None
    revision: int
    opened_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class Monitor:
    tenant_id: str
    monitor_id: str
    vendor_id: str
    source_bindings: Mapping[str, str]
    destination_ref: str
    cadence_seconds: int
    next_run_at: float
    state: str
    last_observation_sha256: str | None
    revision: int
    created_by: str
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class MonitoringAlert:
    tenant_id: str
    alert_id: str
    monitor_id: str
    vendor_id: str
    previous_observation_sha256: str
    observation_sha256: str
    evidence_sha256: str
    snapshot_bindings: Mapping[str, str]
    citations: tuple[Citation, ...]
    created_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class MonitoringResult:
    monitor: Monitor
    changed: bool
    alert: MonitoringAlert | None


@dataclass(frozen=True)
class OutboxItem:
    tenant_id: str
    delivery_id: str
    alert_id: str
    destination_ref: str
    state: str
    attempt: int
    maximum_attempts: int
    next_attempt_at: float
    lease_token: str | None
    lease_until: float | None
    revision: int
    last_error_code: str | None
    integrity_sha256: str


@dataclass(frozen=True)
class ExchangeConsent:
    tenant_id: str
    consent_id: str
    vendor_id: str
    audience: str
    purpose: str
    allowed_metrics: tuple[str, ...]
    explicit_consent: bool
    inclusion_reviewed: bool
    privacy_reviewed: bool
    anonymity_proven: bool
    privacy_review_ref: str | None
    anonymity_proof_ref: str | None
    state: str
    revision: int
    granted_by: str
    reviewed_by: str | None
    expires_at: float
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class ExchangeContribution:
    tenant_id: str
    contribution_id: str
    consent_id: str
    metric_id: str
    value_band: str
    audience: str
    purpose: str
    anonymous: bool
    privacy_reviewed: bool
    evidence_sha256: str
    lineage_refs: tuple[str, ...]
    state: str
    retained_until: float
    contributed_by: str
    created_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class IntegrityVerification:
    tenant_id: str
    verified_records: int
    audit_events: int
    terminal_audit_sha256: str


class ThirdPartyIntelligenceStore:
    """Tenant-isolated SQLite control plane for third-party intelligence."""

    def __init__(
        self,
        path: str | Path,
        *,
        config_gate: Callable[[], None] = require_enabled,
        clock: Callable[[], float] = time.time,
        token_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
    ) -> None:
        config_gate()
        self.path = Path(path)
        self._clock = clock
        self._token_factory = token_factory
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30.0, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS metadata(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sources(
                    tenant_id TEXT NOT NULL,source_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,source_id)
                );
                CREATE TABLE IF NOT EXISTS source_snapshots(
                    tenant_id TEXT NOT NULL,snapshot_id TEXT NOT NULL,source_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,snapshot_id),
                    FOREIGN KEY(tenant_id,source_id) REFERENCES sources(tenant_id,source_id)
                );
                CREATE TABLE IF NOT EXISTS vendors(
                    tenant_id TEXT NOT NULL,vendor_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,vendor_id)
                );
                CREATE TABLE IF NOT EXISTS relationships(
                    tenant_id TEXT NOT NULL,relationship_id TEXT NOT NULL,vendor_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,relationship_id),
                    FOREIGN KEY(tenant_id,vendor_id) REFERENCES vendors(tenant_id,vendor_id)
                );
                CREATE TABLE IF NOT EXISTS screening_runs(
                    tenant_id TEXT NOT NULL,run_id TEXT NOT NULL,vendor_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,run_id),
                    FOREIGN KEY(tenant_id,vendor_id) REFERENCES vendors(tenant_id,vendor_id)
                );
                CREATE TABLE IF NOT EXISTS findings(
                    tenant_id TEXT NOT NULL,finding_id TEXT NOT NULL,run_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,finding_id),
                    FOREIGN KEY(tenant_id,run_id) REFERENCES screening_runs(tenant_id,run_id)
                );
                CREATE TABLE IF NOT EXISTS risk_policies(
                    tenant_id TEXT NOT NULL,policy_id TEXT NOT NULL,version INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,policy_id,version)
                );
                CREATE TABLE IF NOT EXISTS risk_decisions(
                    tenant_id TEXT NOT NULL,decision_id TEXT NOT NULL,vendor_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,decision_id),
                    FOREIGN KEY(tenant_id,vendor_id) REFERENCES vendors(tenant_id,vendor_id)
                );
                CREATE TABLE IF NOT EXISTS edd_cases(
                    tenant_id TEXT NOT NULL,case_id TEXT NOT NULL,vendor_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,case_id),
                    FOREIGN KEY(tenant_id,vendor_id) REFERENCES vendors(tenant_id,vendor_id)
                );
                CREATE TABLE IF NOT EXISTS monitors(
                    tenant_id TEXT NOT NULL,monitor_id TEXT NOT NULL,vendor_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,monitor_id),
                    FOREIGN KEY(tenant_id,vendor_id) REFERENCES vendors(tenant_id,vendor_id)
                );
                CREATE TABLE IF NOT EXISTS monitoring_alerts(
                    tenant_id TEXT NOT NULL,alert_id TEXT NOT NULL,monitor_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,alert_id),
                    FOREIGN KEY(tenant_id,monitor_id) REFERENCES monitors(tenant_id,monitor_id)
                );
                CREATE TABLE IF NOT EXISTS outbox(
                    tenant_id TEXT NOT NULL,delivery_id TEXT NOT NULL,alert_id TEXT NOT NULL,
                    state TEXT NOT NULL,next_attempt_at REAL NOT NULL,lease_until REAL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,delivery_id),
                    FOREIGN KEY(tenant_id,alert_id) REFERENCES monitoring_alerts(tenant_id,alert_id)
                );
                CREATE INDEX IF NOT EXISTS outbox_claim
                    ON outbox(tenant_id,state,next_attempt_at,lease_until);
                CREATE TABLE IF NOT EXISTS alert_recipients(
                    tenant_id TEXT NOT NULL,recipient_id TEXT NOT NULL,destination_ref TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,recipient_id),UNIQUE(tenant_id,destination_ref)
                );
                CREATE TABLE IF NOT EXISTS exchange_consents(
                    tenant_id TEXT NOT NULL,consent_id TEXT NOT NULL,vendor_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,consent_id),
                    FOREIGN KEY(tenant_id,vendor_id) REFERENCES vendors(tenant_id,vendor_id)
                );
                CREATE TABLE IF NOT EXISTS exchange_contributions(
                    tenant_id TEXT NOT NULL,contribution_id TEXT NOT NULL,consent_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,contribution_id),
                    FOREIGN KEY(tenant_id,consent_id)
                        REFERENCES exchange_consents(tenant_id,consent_id)
                );
                CREATE TABLE IF NOT EXISTS operations(
                    tenant_id TEXT NOT NULL,operation_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_kind TEXT NOT NULL,result_id TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,operation_sha256)
                );
                CREATE TABLE IF NOT EXISTS audit_events(
                    tenant_id TEXT NOT NULL,sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,sequence)
                );
                INSERT OR IGNORE INTO metadata(key,value) VALUES('schema_version','1');
                COMMIT;
                """
            )
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if version is None or version["value"] != str(SCHEMA_VERSION):
                raise ThirdPartyIntelligenceIntegrityError(
                    "third-party intelligence database schema is unsupported"
                )
        ensure_private_file(self.path)

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _row(row: sqlite3.Row, label: str) -> dict[str, Any]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ThirdPartyIntelligenceIntegrityError(
                f"persisted {label} is not canonical JSON"
            ) from exc
        if not isinstance(payload, dict) or _sha256(payload) != row["integrity_sha256"]:
            raise ThirdPartyIntelligenceIntegrityError(
                f"persisted {label} failed integrity verification"
            )
        return payload

    @staticmethod
    def _operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request: Mapping[str, object],
    ) -> tuple[str, sqlite3.Row | None]:
        key = _id(idempotency_key, "idempotency_key", _OP_RE)
        operation_sha = hashlib.sha256(key.encode()).hexdigest()
        request_sha = _sha256(dict(request))
        row = connection.execute(
            "SELECT * FROM operations WHERE tenant_id=? AND operation_sha256=?",
            (tenant_id, operation_sha),
        ).fetchone()
        if row is not None:
            operation_payload = {
                "tenant_id": row["tenant_id"],
                "operation_sha256": row["operation_sha256"],
                "request_sha256": row["request_sha256"],
                "result_kind": row["result_kind"],
                "result_id": row["result_id"],
            }
            if _sha256(operation_payload) != row["integrity_sha256"]:
                raise ThirdPartyIntelligenceIntegrityError(
                    "persisted idempotency binding failed integrity verification"
                )
            if row["request_sha256"] != request_sha:
                raise ThirdPartyIntelligenceConflict(
                    "idempotency key is bound to different canonical content"
                )
        return request_sha, row

    @staticmethod
    def _record_operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request_sha256: str,
        result_kind: str,
        result_id: str,
    ) -> None:
        operation_payload = {
            "tenant_id": tenant_id,
            "operation_sha256": hashlib.sha256(idempotency_key.encode()).hexdigest(),
            "request_sha256": request_sha256,
            "result_kind": result_kind,
            "result_id": result_id,
        }
        connection.execute(
            "INSERT INTO operations VALUES(?,?,?,?,?,?)",
            (
                tenant_id,
                operation_payload["operation_sha256"],
                request_sha256,
                result_kind,
                result_id,
                _sha256(operation_payload),
            ),
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
        actor = _id(actor_ref, "actor_ref")
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM audit_events WHERE tenant_id=? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = "0" * 64 if previous is None else previous["integrity_sha256"]
        payload = {
            "schema": AUDIT_SCHEMA,
            "tenant_id": tenant_id,
            "sequence": sequence,
            "action": _id(action, "audit action"),
            "subject_sha256": hashlib.sha256(subject.encode()).hexdigest(),
            "actor_ref": actor,
            "details": dict(details),
            "occurred_at": now,
            "previous_sha256": previous_sha,
        }
        digest = _sha256(payload)
        connection.execute(
            "INSERT INTO audit_events VALUES(?,?,?,?)",
            (tenant_id, sequence, _canonical(payload).decode("ascii"), digest),
        )

    @staticmethod
    def _source_from(payload: Mapping[str, Any], digest: str) -> IntelligenceSource:
        values = dict(payload)
        values["purposes"] = tuple(values["purposes"])
        values["territories"] = tuple(values["territories"])
        return IntelligenceSource(**values, integrity_sha256=digest)

    @staticmethod
    def _snapshot_from(payload: Mapping[str, Any], digest: str) -> SourceSnapshot:
        values = dict(payload)
        values["citations"] = tuple(Citation(**item) for item in values["citations"])
        return SourceSnapshot(**values, integrity_sha256=digest)

    @staticmethod
    def _vendor_from(payload: Mapping[str, Any], digest: str) -> VendorProfile:
        values = dict(payload)
        values["territories"] = tuple(values["territories"])
        values["service_categories"] = tuple(values["service_categories"])
        return VendorProfile(**values, integrity_sha256=digest)

    @staticmethod
    def _relationship_from(
        payload: Mapping[str, Any], digest: str
    ) -> VendorRelationship:
        return VendorRelationship(**dict(payload), integrity_sha256=digest)

    @staticmethod
    def _run_from(payload: Mapping[str, Any], digest: str) -> ScreeningRun:
        values = dict(payload)
        values["snapshot_bindings"] = dict(values["snapshot_bindings"])
        values["requested_kinds"] = tuple(values["requested_kinds"])
        return ScreeningRun(**values, integrity_sha256=digest)

    @staticmethod
    def _finding_from(payload: Mapping[str, Any], digest: str) -> ScreeningFinding:
        values = dict(payload)
        values["citations"] = tuple(Citation(**item) for item in values["citations"])
        return ScreeningFinding(**values, integrity_sha256=digest)

    @staticmethod
    def _policy_from(payload: Mapping[str, Any], digest: str) -> RiskPolicy:
        values = dict(payload)
        values["required_source_kinds"] = tuple(values["required_source_kinds"])
        values["allowed_territories"] = tuple(values["allowed_territories"])
        values["factor_weights"] = dict(values["factor_weights"])
        return RiskPolicy(**values, integrity_sha256=digest)

    @staticmethod
    def _decision_from(payload: Mapping[str, Any], digest: str) -> RiskDecision:
        values = dict(payload)
        values["factors"] = dict(values["factors"])
        values["reason_codes"] = tuple(values["reason_codes"])
        return RiskDecision(**values, integrity_sha256=digest)

    @staticmethod
    def _edd_from(payload: Mapping[str, Any], digest: str) -> EDDCase:
        values = dict(payload)
        values["tasks"] = tuple(dict(item) for item in values["tasks"])
        values["evidence"] = tuple(dict(item) for item in values["evidence"])
        return EDDCase(**values, integrity_sha256=digest)

    @staticmethod
    def _monitor_from(payload: Mapping[str, Any], digest: str) -> Monitor:
        values = dict(payload)
        values["source_bindings"] = dict(values["source_bindings"])
        return Monitor(**values, integrity_sha256=digest)

    @staticmethod
    def _alert_from(payload: Mapping[str, Any], digest: str) -> MonitoringAlert:
        values = dict(payload)
        values["snapshot_bindings"] = dict(values["snapshot_bindings"])
        values["citations"] = tuple(Citation(**item) for item in values["citations"])
        return MonitoringAlert(**values, integrity_sha256=digest)

    @staticmethod
    def _outbox_from(payload: Mapping[str, Any], digest: str) -> OutboxItem:
        return OutboxItem(**dict(payload), integrity_sha256=digest)

    @staticmethod
    def _consent_from(payload: Mapping[str, Any], digest: str) -> ExchangeConsent:
        values = dict(payload)
        values["allowed_metrics"] = tuple(values["allowed_metrics"])
        return ExchangeConsent(**values, integrity_sha256=digest)

    @staticmethod
    def _contribution_from(
        payload: Mapping[str, Any], digest: str
    ) -> ExchangeContribution:
        values = dict(payload)
        values["lineage_refs"] = tuple(values["lineage_refs"])
        return ExchangeContribution(**values, integrity_sha256=digest)

    def _get_payload(
        self,
        table: str,
        tenant_id: str,
        id_column: str,
        object_id: str,
        label: str,
    ) -> tuple[dict[str, Any], str]:
        allowed = {
            ("sources", "source_id"),
            ("source_snapshots", "snapshot_id"),
            ("vendors", "vendor_id"),
            ("relationships", "relationship_id"),
            ("screening_runs", "run_id"),
            ("findings", "finding_id"),
            ("risk_decisions", "decision_id"),
            ("edd_cases", "case_id"),
            ("monitors", "monitor_id"),
            ("monitoring_alerts", "alert_id"),
            ("outbox", "delivery_id"),
            ("alert_recipients", "recipient_id"),
            ("exchange_consents", "consent_id"),
            ("exchange_contributions", "contribution_id"),
        }
        if (table, id_column) not in allowed:
            raise ThirdPartyIntelligenceIntegrityError("internal table selection is invalid")
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT * FROM {table} WHERE tenant_id=? AND {id_column}=?",  # noqa: S608
                (tenant_id, object_id),
            ).fetchone()
        if row is None:
            raise ThirdPartyIntelligenceNotFound(f"{label} not found")
        return self._row(row, label), row["integrity_sha256"]

    def _list_payloads(
        self,
        table: str,
        tenant_id: str,
        id_column: str,
        label: str,
        *,
        limit: int,
    ) -> tuple[tuple[dict[str, Any], str], ...]:
        allowed = {
            ("sources", "source_id"),
            ("source_snapshots", "snapshot_id"),
            ("vendors", "vendor_id"),
            ("screening_runs", "run_id"),
            ("risk_decisions", "decision_id"),
            ("edd_cases", "case_id"),
            ("monitors", "monitor_id"),
            ("monitoring_alerts", "alert_id"),
            ("outbox", "delivery_id"),
            ("alert_recipients", "recipient_id"),
        }
        if (table, id_column) not in allowed:
            raise ThirdPartyIntelligenceIntegrityError(
                "internal table selection is invalid"
            )
        bounded = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM {table} WHERE tenant_id=? "  # noqa: S608
                f"ORDER BY {id_column} LIMIT ?",  # noqa: S608
                (tenant_id, bounded),
            ).fetchall()
        return tuple(
            (self._row(row, label), row["integrity_sha256"])
            for row in rows
        )

    def list_sources(
        self, tenant_id: str, *, limit: int = 100
    ) -> tuple[IntelligenceSource, ...]:
        tenant = _tenant(tenant_id)
        return tuple(
            self._source_from(payload, digest)
            for payload, digest in self._list_payloads(
                "sources", tenant, "source_id", "source", limit=limit
            )
        )

    def list_source_snapshots(
        self, tenant_id: str, *, limit: int = 100
    ) -> tuple[SourceSnapshot, ...]:
        tenant = _tenant(tenant_id)
        return tuple(
            self._snapshot_from(payload, digest)
            for payload, digest in self._list_payloads(
                "source_snapshots",
                tenant,
                "snapshot_id",
                "source snapshot",
                limit=limit,
            )
        )

    def list_vendors(
        self, tenant_id: str, *, limit: int = 100
    ) -> tuple[VendorProfile, ...]:
        tenant = _tenant(tenant_id)
        return tuple(
            self._vendor_from(payload, digest)
            for payload, digest in self._list_payloads(
                "vendors", tenant, "vendor_id", "vendor", limit=limit
            )
        )

    def list_screening_runs(
        self, tenant_id: str, *, limit: int = 100
    ) -> tuple[ScreeningRun, ...]:
        tenant = _tenant(tenant_id)
        return tuple(
            self._run_from(payload, digest)
            for payload, digest in self._list_payloads(
                "screening_runs", tenant, "run_id", "screening run", limit=limit
            )
        )

    def list_risk_decisions(
        self, tenant_id: str, *, limit: int = 100
    ) -> tuple[RiskDecision, ...]:
        tenant = _tenant(tenant_id)
        return tuple(
            self._decision_from(payload, digest)
            for payload, digest in self._list_payloads(
                "risk_decisions",
                tenant,
                "decision_id",
                "risk decision",
                limit=limit,
            )
        )

    def list_edd_cases(
        self, tenant_id: str, *, limit: int = 100
    ) -> tuple[EDDCase, ...]:
        tenant = _tenant(tenant_id)
        return tuple(
            self._edd_from(payload, digest)
            for payload, digest in self._list_payloads(
                "edd_cases", tenant, "case_id", "EDD case", limit=limit
            )
        )

    def list_monitors(
        self, tenant_id: str, *, limit: int = 100
    ) -> tuple[Monitor, ...]:
        tenant = _tenant(tenant_id)
        return tuple(
            self._monitor_from(payload, digest)
            for payload, digest in self._list_payloads(
                "monitors", tenant, "monitor_id", "monitor", limit=limit
            )
        )

    def list_monitoring_alerts(
        self, tenant_id: str, *, limit: int = 100
    ) -> tuple[MonitoringAlert, ...]:
        tenant = _tenant(tenant_id)
        return tuple(
            self._alert_from(payload, digest)
            for payload, digest in self._list_payloads(
                "monitoring_alerts",
                tenant,
                "alert_id",
                "monitoring alert",
                limit=limit,
            )
        )

    def list_risk_policies(
        self, tenant_id: str, *, limit: int = 100
    ) -> tuple[RiskPolicy, ...]:
        """Every stored policy version, integrity-checked; read-only."""
        tenant = _tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM risk_policies WHERE tenant_id=? "
                "ORDER BY policy_id, version DESC LIMIT ?",
                (tenant, bounded),
            ).fetchall()
        return tuple(
            self._policy_from(self._row(row, "risk policy"), row["integrity_sha256"])
            for row in rows
        )

    def list_exchange_consents(
        self, tenant_id: str, *, limit: int = 100
    ) -> tuple[ExchangeConsent, ...]:
        """This workspace's own sharing consents, integrity-checked; read-only."""
        tenant = _tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM exchange_consents WHERE tenant_id=? "
                "ORDER BY consent_id LIMIT ?",
                (tenant, bounded),
            ).fetchall()
        return tuple(
            self._consent_from(self._row(row, "exchange consent"), row["integrity_sha256"])
            for row in rows
        )

    def context_record_counts(self, tenant_id: str) -> Mapping[str, int]:
        """Return exact current-head counts for context truncation disclosure."""

        tenant = _tenant(tenant_id)
        tables = (
            "sources",
            "source_snapshots",
            "vendors",
            "screening_runs",
            "risk_decisions",
            "edd_cases",
            "monitors",
            "monitoring_alerts",
        )
        with self._connect() as connection:
            return {
                table: int(
                    connection.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE tenant_id=?",  # noqa: S608
                        (tenant,),
                    ).fetchone()[0]
                )
                for table in tables
            }

    # -- independently governed sources ---------------------------------

    def enroll_source(
        self,
        tenant_id: str,
        *,
        source_id: str,
        provider: str,
        kind: str,
        provenance_uri: str,
        credential_env: str,
        license_ref: str,
        rights_basis: str,
        purposes: Sequence[str],
        territories: Sequence[str],
        retention_seconds: int,
        actor_ref: str,
        idempotency_key: str,
        expected_revision: int = 0,
        now: float | None = None,
    ) -> IntelligenceSource:
        tenant = _tenant(tenant_id)
        source = _id(source_id, "source_id")
        provider_value = _id(provider, "provider")
        if kind not in SOURCE_KINDS:
            raise ThirdPartyIntelligenceValidationError("source kind is closed")
        provenance = _https_uri(provenance_uri, "provenance_uri")
        if urlparse(provenance).query:
            raise ThirdPartyIntelligenceValidationError(
                "provenance_uri must not contain query parameters"
            )
        credential = _id(credential_env, "credential_env", _ENV_RE)
        license_value = _text(license_ref, "license_ref", 1_024)
        basis = _text(rights_basis, "rights_basis", 2_000)
        purpose_values = _closed_list(purposes, "purposes", SOURCE_PURPOSES)
        territory_values = _territories(territories)
        retention = _retention(retention_seconds)
        actor = _id(actor_ref, "actor_ref")
        expected = _integer(expected_revision, "expected_revision", 0, 2**31 - 1)
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "enroll_source",
            "source_id": source,
            "provider": provider_value,
            "kind": kind,
            "provenance_uri": provenance,
            "credential_env": credential,
            "license_ref": license_value,
            "rights_basis": basis,
            "purposes": list(purpose_values),
            "territories": list(territory_values),
            "retention_seconds": retention,
            "actor_ref": actor,
            "expected_revision": expected,
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
                if expected:
                    raise ThirdPartyIntelligenceConflict(
                        "source expected revision does not match absence"
                    )
                revision = 1
                enrolled_at = moment
            else:
                previous = self._row(row, "source")
                if int(previous["revision"]) != expected:
                    raise ThirdPartyIntelligenceConflict(
                        "source expected revision does not match"
                    )
                revision = expected + 1
                enrolled_at = float(previous["enrolled_at"])
            payload = {
                "tenant_id": tenant,
                "source_id": source,
                "provider": provider_value,
                "kind": kind,
                "provenance_uri": provenance,
                "credential_env": credential,
                "license_ref": license_value,
                "rights_basis": basis,
                "purposes": list(purpose_values),
                "territories": list(territory_values),
                "retention_seconds": retention,
                "state": "pending",
                "revision": revision,
                "enrolled_by": actor,
                "approved_by": None,
                "enrolled_at": enrolled_at,
                "updated_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO sources VALUES(?,?,?,?) ON CONFLICT(tenant_id,source_id) "
                "DO UPDATE SET payload_json=excluded.payload_json,"
                "integrity_sha256=excluded.integrity_sha256",
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
                {"kind": kind, "revision": revision, "state": "pending"},
                moment,
            )
            connection.commit()
        return self.get_source(tenant, source)

    def approve_source(
        self,
        tenant_id: str,
        source_id: str,
        *,
        expected_revision: int,
        approver_ref: str,
        approved: bool,
        rationale: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> IntelligenceSource:
        tenant = _tenant(tenant_id)
        source = _id(source_id, "source_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        approver = _id(approver_ref, "approver_ref")
        if not isinstance(approved, bool):
            raise ThirdPartyIntelligenceValidationError("approved must be boolean")
        reason = _text(rationale, "rationale", 2_000)
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "approve_source",
            "source_id": source,
            "expected_revision": expected,
            "approver_ref": approver,
            "approved": approved,
            "rationale": reason,
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
                raise ThirdPartyIntelligenceNotFound("source not found")
            payload = self._row(row, "source")
            if payload["state"] != "pending" or int(payload["revision"]) != expected:
                raise ThirdPartyIntelligenceConflict(
                    "source approval state or revision does not match"
                )
            if payload["enrolled_by"] == approver:
                raise ThirdPartyIntelligencePermissionDenied(
                    "source enrollment and approval require different humans"
                )
            payload.update(
                {
                    "state": "active" if approved else "rejected",
                    "approved_by": approver,
                    "revision": expected + 1,
                    "updated_at": moment,
                }
            )
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
                "source_approved" if approved else "source_rejected",
                source,
                approver,
                {"revision": expected + 1, "rationale_sha256": _sha256(reason)},
                moment,
            )
            connection.commit()
        return self.get_source(tenant, source)

    def revoke_source(
        self,
        tenant_id: str,
        source_id: str,
        *,
        expected_revision: int,
        actor_ref: str,
        rationale: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> IntelligenceSource:
        tenant = _tenant(tenant_id)
        source = _id(source_id, "source_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        actor = _id(actor_ref, "actor_ref")
        reason = _text(rationale, "rationale", 2_000)
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "revoke_source",
            "source_id": source,
            "expected_revision": expected,
            "actor_ref": actor,
            "rationale": reason,
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
                raise ThirdPartyIntelligenceNotFound("source not found")
            payload = self._row(row, "source")
            if int(payload["revision"]) != expected:
                raise ThirdPartyIntelligenceConflict(
                    "source expected revision does not match"
                )
            payload.update(
                {"state": "revoked", "revision": expected + 1, "updated_at": moment}
            )
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
                "source_revoked",
                source,
                actor,
                {"rationale_sha256": _sha256(reason)},
                moment,
            )
            connection.commit()
        return self.get_source(tenant, source)

    def get_source(self, tenant_id: str, source_id: str) -> IntelligenceSource:
        tenant = _tenant(tenant_id)
        source = _id(source_id, "source_id")
        payload, digest = self._get_payload(
            "sources", tenant, "source_id", source, "source"
        )
        return self._source_from(payload, digest)

    def record_source_snapshot(
        self,
        tenant_id: str,
        source_id: str,
        *,
        snapshot_id: str,
        dataset_revision: str,
        observed_at: float,
        valid_until: float,
        completeness: float,
        record_count: int,
        evidence_sha256: str,
        citations: Sequence[Mapping[str, object]],
        provenance_uri: str,
        actor_ref: str,
        idempotency_key: str,
        expected_source_revision: int | None = None,
        expected_source_integrity_sha256: str | None = None,
        now: float | None = None,
    ) -> SourceSnapshot:
        tenant = _tenant(tenant_id)
        source = self.get_source(tenant, source_id)
        snapshot = _id(snapshot_id, "snapshot_id")
        revision = _id(dataset_revision, "dataset_revision")
        observed = _timestamp(observed_at, "observed_at")
        valid = _timestamp(valid_until, "valid_until")
        if valid <= observed:
            raise ThirdPartyIntelligenceValidationError(
                "valid_until must follow observed_at"
            )
        completeness_value = _fraction(completeness, "completeness")
        count = _integer(record_count, "record_count", 0, 2**63 - 1)
        evidence = _digest(evidence_sha256, "evidence_sha256")
        citation_values = _citations(citations)
        provenance = _https_uri(provenance_uri, "provenance_uri")
        actor = _id(actor_ref, "actor_ref")
        expected_source = (
            None
            if expected_source_revision is None
            else _integer(
                expected_source_revision,
                "expected_source_revision",
                1,
                2**31 - 1,
            )
        )
        expected_source_integrity = (
            None
            if expected_source_integrity_sha256 is None
            else _digest(
                expected_source_integrity_sha256,
                "expected_source_integrity_sha256",
            )
        )
        moment = _timestamp(self._clock() if now is None else now, "now")
        if source.state != "active" or source.approved_by is None:
            raise ThirdPartyIntelligencePermissionDenied(
                "source must be independently approved and active"
            )
        if expected_source is not None and source.revision != expected_source:
            raise ThirdPartyIntelligenceConflict(
                "source revision changed before snapshot recording"
            )
        if expected_source_integrity is not None and not hmac.compare_digest(
            source.integrity_sha256,
            expected_source_integrity,
        ):
            raise ThirdPartyIntelligenceConflict(
                "source integrity changed before snapshot recording"
            )
        if provenance != source.provenance_uri:
            raise ThirdPartyIntelligencePermissionDenied(
                "snapshot provenance does not match approved source"
            )
        request = {
            "action": "record_source_snapshot",
            "source_id": source.source_id,
            "snapshot_id": snapshot,
            "dataset_revision": revision,
            "observed_at": observed,
            "valid_until": valid,
            "completeness": completeness_value,
            "record_count": count,
            "evidence_sha256": evidence,
            "citations": _citation_json(citation_values),
            "provenance_uri": provenance,
            "actor_ref": actor,
        }
        if expected_source is not None:
            request["expected_source_revision"] = expected_source
        if expected_source_integrity is not None:
            request["expected_source_integrity_sha256"] = expected_source_integrity
        with self._connect() as connection:
            self._begin(connection)
            source_row = connection.execute(
                "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                (tenant, source.source_id),
            ).fetchone()
            if source_row is None:
                raise ThirdPartyIntelligenceNotFound("source not found")
            source = self._source_from(
                self._row(source_row, "source"),
                str(source_row["integrity_sha256"]),
            )
            if source.state != "active" or source.approved_by is None:
                raise ThirdPartyIntelligencePermissionDenied(
                    "source must remain independently approved and active"
                )
            if expected_source is not None and source.revision != expected_source:
                raise ThirdPartyIntelligenceConflict(
                    "source revision changed before snapshot commit"
                )
            if expected_source_integrity is not None and not hmac.compare_digest(
                source.integrity_sha256,
                expected_source_integrity,
            ):
                raise ThirdPartyIntelligenceConflict(
                    "source integrity changed before snapshot commit"
                )
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_source_snapshot(tenant, snapshot)
            if connection.execute(
                "SELECT 1 FROM source_snapshots WHERE tenant_id=? AND snapshot_id=?",
                (tenant, snapshot),
            ).fetchone():
                raise ThirdPartyIntelligenceConflict("snapshot already exists")
            payload = {
                "tenant_id": tenant,
                "snapshot_id": snapshot,
                "source_id": source.source_id,
                "source_revision": source.revision,
                "dataset_revision": revision,
                "observed_at": observed,
                "valid_until": valid,
                "completeness": completeness_value,
                "record_count": count,
                "evidence_sha256": evidence,
                "citations": _citation_json(citation_values),
                "provenance_uri": provenance,
                "retained_until": moment + source.retention_seconds,
                "created_by": actor,
                "created_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO source_snapshots VALUES(?,?,?,?,?)",
                (
                    tenant,
                    snapshot,
                    source.source_id,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "snapshot", snapshot
            )
            self._audit(
                connection,
                tenant,
                "source_snapshot_recorded",
                snapshot,
                actor,
                {
                    "source_id": source.source_id,
                    "source_revision": source.revision,
                    "evidence_sha256": evidence,
                },
                moment,
            )
            connection.commit()
        return self.get_source_snapshot(tenant, snapshot)

    def get_source_snapshot(
        self, tenant_id: str, snapshot_id: str
    ) -> SourceSnapshot:
        tenant = _tenant(tenant_id)
        snapshot = _id(snapshot_id, "snapshot_id")
        payload, digest = self._get_payload(
            "source_snapshots", tenant, "snapshot_id", snapshot, "source snapshot"
        )
        return self._snapshot_from(payload, digest)

    # -- secret-safe vendor and relationship authority ------------------

    def upsert_vendor(
        self,
        tenant_id: str,
        *,
        vendor_id: str,
        display_label: str,
        entity_identity_sha256: str,
        encrypted_profile_ref: str,
        profile_key_ref: str,
        territories: Sequence[str],
        service_categories: Sequence[str],
        inherent_risk_level: int,
        criticality: int,
        data_access_level: str,
        owner_ref: str,
        actor_ref: str,
        idempotency_key: str,
        expected_revision: int = 0,
        now: float | None = None,
        register_vendor_id: str | None = None,
        effect_guard: Callable[[], None] | None = None,
    ) -> VendorProfile:
        tenant = _tenant(tenant_id)
        vendor = _id(vendor_id, "vendor_id")
        label = _text(display_label, "display_label", 300)
        identity_digest = _digest(entity_identity_sha256, "entity_identity_sha256")
        encrypted_ref = _id(encrypted_profile_ref, "encrypted_profile_ref")
        key_ref = _id(profile_key_ref, "profile_key_ref")
        if encrypted_ref == key_ref:
            raise ThirdPartyIntelligenceValidationError(
                "encrypted profile and key references must be separated"
            )
        territory_values = _territories(territories)
        service_values = _closed_list(service_categories, "service_categories")
        inherent = _integer(inherent_risk_level, "inherent_risk_level", 1, 5)
        criticality_value = _integer(criticality, "criticality", 1, 5)
        if data_access_level not in DATA_ACCESS_LEVELS:
            raise ThirdPartyIntelligenceValidationError("data_access_level is closed")
        owner = _id(owner_ref, "owner_ref")
        actor = _id(actor_ref, "actor_ref")
        expected = _integer(expected_revision, "expected_revision", 0, 2**31 - 1)
        registered = _id(register_vendor_id, "register_vendor_id") if register_vendor_id is not None else None
        if registered is not None and expected == 0:
            identity_digest = hashlib.sha256(f"lightwork.registered-vendor.identity.v1:{tenant}:{registered}".encode()).hexdigest()
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "upsert_vendor",
            "vendor_id": vendor,
            "display_label": label,
            "entity_identity_sha256": identity_digest,
            "encrypted_profile_ref": encrypted_ref,
            "profile_key_ref": key_ref,
            "territories": list(territory_values),
            "service_categories": list(service_values),
            "inherent_risk_level": inherent,
            "criticality": criticality_value,
            "data_access_level": data_access_level,
            "owner_ref": owner,
            "actor_ref": actor,
            "expected_revision": expected,
        }
        if registered is not None:
            request["register_vendor_id"] = registered
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_vendor(tenant, vendor)
            if effect_guard is not None:
                effect_guard()
            row = connection.execute(
                "SELECT * FROM vendors WHERE tenant_id=? AND vendor_id=?",
                (tenant, vendor),
            ).fetchone()
            if row is None:
                if expected:
                    raise ThirdPartyIntelligenceConflict(
                        "vendor expected revision does not match absence"
                    )
                revision = 1
                created_at = moment
            else:
                previous = self._row(row, "vendor")
                if int(previous["revision"]) != expected:
                    raise ThirdPartyIntelligenceConflict(
                        "vendor expected revision does not match"
                    )
                prior_register = previous.get("register_vendor_id")
                if prior_register is not None and registered not in {None, prior_register}:
                    raise ThirdPartyIntelligenceConflict("This intelligence profile is already bound to another registered vendor.")
                registered = prior_register or registered
                if prior_register is not None and previous["entity_identity_sha256"] != identity_digest:
                    raise ThirdPartyIntelligenceConflict("A bound vendor's canonical entity identity cannot be replaced by caller-authored text.")
                revision = expected + 1
                created_at = float(previous["created_at"])
            if registered is not None:
                from . import vendor_management
                from .paths import current_tenant_id_strict
                if current_tenant_id_strict() != tenant or vendor_management.get_vendor(registered) is None:
                    raise ThirdPartyIntelligenceConflict("Choose a current vendor from this workspace's register.")
                for other in connection.execute("SELECT * FROM vendors WHERE tenant_id=? AND vendor_id<>?", (tenant, vendor)).fetchall():
                    if self._row(other, "vendor").get("register_vendor_id") == registered:
                        raise ThirdPartyIntelligenceConflict("This registered vendor already has an intelligence profile. Open that existing profile.")
            payload = {
                "tenant_id": tenant,
                "vendor_id": vendor,
                "display_label": label,
                "entity_identity_sha256": identity_digest,
                "encrypted_profile_ref": encrypted_ref,
                "profile_key_ref": key_ref,
                "territories": list(territory_values),
                "service_categories": list(service_values),
                "inherent_risk_level": inherent,
                "criticality": criticality_value,
                "data_access_level": data_access_level,
                "owner_ref": owner,
                "state": "active",
                "revision": revision,
                "created_at": created_at,
                "updated_at": moment,
                "register_vendor_id": registered,
            }
            digest = _sha256(payload)
            if effect_guard is not None:
                effect_guard()
            connection.execute(
                "INSERT INTO vendors VALUES(?,?,?,?) ON CONFLICT(tenant_id,vendor_id) "
                "DO UPDATE SET payload_json=excluded.payload_json,"
                "integrity_sha256=excluded.integrity_sha256",
                (tenant, vendor, _canonical(payload).decode("ascii"), digest),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "vendor", vendor
            )
            self._audit(
                connection,
                tenant,
                "vendor_profile_upserted",
                vendor,
                actor,
                {"revision": revision, "identity_sha256": identity_digest},
                moment,
            )
            connection.commit()
        return self.get_vendor(tenant, vendor)

    def get_vendor(self, tenant_id: str, vendor_id: str) -> VendorProfile:
        tenant = _tenant(tenant_id)
        vendor = _id(vendor_id, "vendor_id")
        payload, digest = self._get_payload(
            "vendors", tenant, "vendor_id", vendor, "vendor"
        )
        return self._vendor_from(payload, digest)

    def upsert_relationship(
        self,
        tenant_id: str,
        *,
        relationship_id: str,
        vendor_id: str,
        related_vendor_id: str | None,
        relationship_type: str,
        scope_ref: str,
        criticality: int,
        data_access_level: str,
        actor_ref: str,
        idempotency_key: str,
        expected_revision: int = 0,
        now: float | None = None,
    ) -> VendorRelationship:
        tenant = _tenant(tenant_id)
        relationship = _id(relationship_id, "relationship_id")
        vendor = self.get_vendor(tenant, vendor_id)
        related = (
            self.get_vendor(tenant, related_vendor_id).vendor_id
            if related_vendor_id is not None
            else None
        )
        relation_type = _id(relationship_type, "relationship_type")
        scope = _id(scope_ref, "scope_ref")
        criticality_value = _integer(criticality, "criticality", 1, 5)
        if data_access_level not in DATA_ACCESS_LEVELS:
            raise ThirdPartyIntelligenceValidationError("data_access_level is closed")
        actor = _id(actor_ref, "actor_ref")
        expected = _integer(expected_revision, "expected_revision", 0, 2**31 - 1)
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "upsert_relationship",
            "relationship_id": relationship,
            "vendor_id": vendor.vendor_id,
            "related_vendor_id": related,
            "relationship_type": relation_type,
            "scope_ref": scope,
            "criticality": criticality_value,
            "data_access_level": data_access_level,
            "actor_ref": actor,
            "expected_revision": expected,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_relationship(tenant, relationship)
            row = connection.execute(
                "SELECT * FROM relationships WHERE tenant_id=? AND relationship_id=?",
                (tenant, relationship),
            ).fetchone()
            if row is None:
                if expected:
                    raise ThirdPartyIntelligenceConflict(
                        "relationship expected revision does not match absence"
                    )
                revision = 1
                created_at = moment
            else:
                previous = self._row(row, "relationship")
                if int(previous["revision"]) != expected:
                    raise ThirdPartyIntelligenceConflict(
                        "relationship expected revision does not match"
                    )
                revision = expected + 1
                created_at = float(previous["created_at"])
            payload = {
                "tenant_id": tenant,
                "relationship_id": relationship,
                "vendor_id": vendor.vendor_id,
                "related_vendor_id": related,
                "relationship_type": relation_type,
                "scope_ref": scope,
                "criticality": criticality_value,
                "data_access_level": data_access_level,
                "revision": revision,
                "created_at": created_at,
                "updated_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO relationships VALUES(?,?,?,?,?) "
                "ON CONFLICT(tenant_id,relationship_id) DO UPDATE SET "
                "vendor_id=excluded.vendor_id,payload_json=excluded.payload_json,"
                "integrity_sha256=excluded.integrity_sha256",
                (
                    tenant,
                    relationship,
                    vendor.vendor_id,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "relationship",
                relationship,
            )
            self._audit(
                connection,
                tenant,
                "vendor_relationship_upserted",
                relationship,
                actor,
                {"vendor_id": vendor.vendor_id, "revision": revision},
                moment,
            )
            connection.commit()
        return self.get_relationship(tenant, relationship)

    def get_relationship(
        self, tenant_id: str, relationship_id: str
    ) -> VendorRelationship:
        tenant = _tenant(tenant_id)
        relationship = _id(relationship_id, "relationship_id")
        payload, digest = self._get_payload(
            "relationships",
            tenant,
            "relationship_id",
            relationship,
            "relationship",
        )
        return self._relationship_from(payload, digest)

    def list_relationships(
        self, tenant_id: str, vendor_id: str
    ) -> tuple[VendorRelationship, ...]:
        tenant = _tenant(tenant_id)
        vendor = _id(vendor_id, "vendor_id")
        self.get_vendor(tenant, vendor)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM relationships WHERE tenant_id=? AND vendor_id=? "
                "ORDER BY relationship_id LIMIT ?",
                (tenant, vendor, _MAX_LIST),
            ).fetchall()
        return tuple(
            self._relationship_from(self._row(row, "relationship"), row["integrity_sha256"])
            for row in rows
        )

    # -- governed screening and match review ----------------------------

    def _validated_snapshot_binding(
        self,
        tenant: str,
        snapshot_id: str,
        *,
        expected_kind: str,
        purpose: str,
        vendor: VendorProfile,
        now: float,
        maximum_age_seconds: int | None = None,
        minimum_completeness: float | None = None,
    ) -> tuple[SourceSnapshot, IntelligenceSource]:
        snapshot = self.get_source_snapshot(tenant, snapshot_id)
        source = self.get_source(tenant, snapshot.source_id)
        if source.kind != expected_kind:
            raise ThirdPartyIntelligencePermissionDenied(
                "snapshot source kind does not match its binding"
            )
        if source.state != "active" or source.approved_by is None:
            raise ThirdPartyIntelligencePermissionDenied(
                "snapshot source is no longer active and approved"
            )
        if snapshot.source_revision != source.revision:
            raise ThirdPartyIntelligencePermissionDenied(
                "snapshot is bound to an obsolete source-rights revision"
            )
        if purpose not in source.purposes:
            raise ThirdPartyIntelligencePermissionDenied(
                "source rights do not permit the requested purpose"
            )
        if not set(vendor.territories).issubset(source.territories):
            raise ThirdPartyIntelligencePermissionDenied(
                "source territorial rights do not cover the vendor profile"
            )
        if snapshot.observed_at > now or snapshot.valid_until <= now:
            raise ThirdPartyIntelligencePermissionDenied(
                "source snapshot is not currently fresh"
            )
        if (
            maximum_age_seconds is not None
            and now - snapshot.observed_at > maximum_age_seconds
        ):
            raise ThirdPartyIntelligencePermissionDenied(
                "source snapshot exceeds policy freshness"
            )
        if (
            minimum_completeness is not None
            and snapshot.completeness < minimum_completeness
        ):
            raise ThirdPartyIntelligencePermissionDenied(
                "source snapshot is below policy completeness"
            )
        return snapshot, source

    def start_screening_run(
        self,
        tenant_id: str,
        *,
        run_id: str,
        vendor_id: str,
        subject_identity_sha256: str,
        snapshot_bindings: Mapping[str, str],
        requested_kinds: Sequence[str],
        initiated_by: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ScreeningRun:
        tenant = _tenant(tenant_id)
        run = _id(run_id, "run_id")
        vendor = self.get_vendor(tenant, vendor_id)
        subject_digest = _digest(subject_identity_sha256, "subject_identity_sha256")
        if not hmac.compare_digest(subject_digest, vendor.entity_identity_sha256):
            raise ThirdPartyIntelligencePermissionDenied(
                "screening subject does not match the governed vendor identity"
            )
        kind_values = _closed_list(
            requested_kinds, "requested_kinds", SOURCE_KINDS, maximum=len(SOURCE_KINDS)
        )
        if not isinstance(snapshot_bindings, Mapping):
            raise ThirdPartyIntelligenceValidationError(
                "snapshot_bindings must be an object"
            )
        bindings = {
            _id(kind, "source kind"): _id(snapshot, "snapshot_id")
            for kind, snapshot in snapshot_bindings.items()
        }
        if set(bindings) != set(kind_values):
            raise ThirdPartyIntelligenceValidationError(
                "snapshot_bindings must exactly cover requested_kinds"
            )
        if len(set(bindings.values())) != len(bindings):
            raise ThirdPartyIntelligenceValidationError(
                "each source kind requires an independently bound snapshot"
            )
        initiator = _id(initiated_by, "initiated_by")
        moment = _timestamp(self._clock() if now is None else now, "now")
        for kind, snapshot_id in bindings.items():
            self._validated_snapshot_binding(
                tenant,
                snapshot_id,
                expected_kind=kind,
                purpose="screening",
                vendor=vendor,
                now=moment,
            )
        request = {
            "action": "start_screening_run",
            "run_id": run,
            "vendor_id": vendor.vendor_id,
            "subject_identity_sha256": subject_digest,
            "snapshot_bindings": dict(sorted(bindings.items())),
            "requested_kinds": list(kind_values),
            "initiated_by": initiator,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_screening_run(tenant, run)
            if connection.execute(
                "SELECT 1 FROM screening_runs WHERE tenant_id=? AND run_id=?",
                (tenant, run),
            ).fetchone():
                raise ThirdPartyIntelligenceConflict("screening run already exists")
            payload = {
                "tenant_id": tenant,
                "run_id": run,
                "vendor_id": vendor.vendor_id,
                "subject_identity_sha256": subject_digest,
                "snapshot_bindings": dict(sorted(bindings.items())),
                "requested_kinds": list(kind_values),
                "state": "open",
                "revision": 1,
                "initiated_by": initiator,
                "initiated_at": moment,
                "completed_at": None,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO screening_runs VALUES(?,?,?,?,?)",
                (
                    tenant,
                    run,
                    vendor.vendor_id,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "screening_run", run
            )
            self._audit(
                connection,
                tenant,
                "screening_run_started",
                run,
                initiator,
                {"vendor_id": vendor.vendor_id, "requested_kinds": list(kind_values)},
                moment,
            )
            connection.commit()
        return self.get_screening_run(tenant, run)

    def get_screening_run(self, tenant_id: str, run_id: str) -> ScreeningRun:
        tenant = _tenant(tenant_id)
        run = _id(run_id, "run_id")
        payload, digest = self._get_payload(
            "screening_runs", tenant, "run_id", run, "screening run"
        )
        return self._run_from(payload, digest)

    def record_finding(
        self,
        tenant_id: str,
        run_id: str,
        *,
        finding_id: str,
        source_id: str,
        kind: str,
        candidate_ref: str,
        match_confidence: float,
        severity: str,
        observed_at: float,
        valid_until: float,
        evidence_sha256: str,
        citations: Sequence[Mapping[str, object]],
        detected_by: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ScreeningFinding:
        tenant = _tenant(tenant_id)
        run = self.get_screening_run(tenant, run_id)
        finding = _id(finding_id, "finding_id")
        source = self.get_source(tenant, source_id)
        if kind not in SOURCE_KINDS:
            raise ThirdPartyIntelligenceValidationError("finding kind is closed")
        candidate = _id(candidate_ref, "candidate_ref")
        confidence = _fraction(match_confidence, "match_confidence")
        if severity not in SEVERITIES:
            raise ThirdPartyIntelligenceValidationError("severity is closed")
        observed = _timestamp(observed_at, "observed_at")
        valid = _timestamp(valid_until, "valid_until")
        if valid <= observed:
            raise ThirdPartyIntelligenceValidationError(
                "finding valid_until must follow observed_at"
            )
        evidence = _digest(evidence_sha256, "evidence_sha256")
        citation_values = _citations(citations)
        detector = _id(detected_by, "detected_by")
        moment = _timestamp(self._clock() if now is None else now, "now")
        if run.state != "open":
            raise ThirdPartyIntelligenceConflict("screening run is not open")
        if kind not in run.requested_kinds:
            raise ThirdPartyIntelligencePermissionDenied(
                "finding kind was not requested by the governed run"
            )
        snapshot_id = run.snapshot_bindings.get(kind)
        if snapshot_id is None:
            raise ThirdPartyIntelligenceIntegrityError(
                "screening run lacks its source binding"
            )
        snapshot, bound_source = self._validated_snapshot_binding(
            tenant,
            snapshot_id,
            expected_kind=kind,
            purpose="screening",
            vendor=self.get_vendor(tenant, run.vendor_id),
            now=moment,
        )
        if source.source_id != bound_source.source_id:
            raise ThirdPartyIntelligencePermissionDenied(
                "finding source does not match governed snapshot binding"
            )
        if not (snapshot.observed_at <= observed <= snapshot.valid_until):
            raise ThirdPartyIntelligencePermissionDenied(
                "finding observation is outside its snapshot evidence window"
            )
        request = {
            "action": "record_finding",
            "run_id": run.run_id,
            "finding_id": finding,
            "source_id": source.source_id,
            "kind": kind,
            "candidate_ref": candidate,
            "match_confidence": confidence,
            "severity": severity,
            "observed_at": observed,
            "valid_until": valid,
            "evidence_sha256": evidence,
            "citations": _citation_json(citation_values),
            "detected_by": detector,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_finding(tenant, finding)
            if connection.execute(
                "SELECT 1 FROM findings WHERE tenant_id=? AND finding_id=?",
                (tenant, finding),
            ).fetchone():
                raise ThirdPartyIntelligenceConflict("finding already exists")
            payload = {
                "tenant_id": tenant,
                "finding_id": finding,
                "run_id": run.run_id,
                "vendor_id": run.vendor_id,
                "source_id": source.source_id,
                "kind": kind,
                "candidate_ref": candidate,
                "match_confidence": confidence,
                "severity": severity,
                "observed_at": observed,
                "valid_until": valid,
                "evidence_sha256": evidence,
                "citations": _citation_json(citation_values),
                "disposition": "pending_review",
                "detected_by": detector,
                "reviewed_by": None,
                "review_rationale": None,
                "revision": 1,
                "created_at": moment,
                "updated_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO findings VALUES(?,?,?,?,?)",
                (tenant, finding, run.run_id, _canonical(payload).decode("ascii"), digest),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "finding", finding
            )
            self._audit(
                connection,
                tenant,
                "screening_finding_recorded",
                finding,
                detector,
                {
                    "run_id": run.run_id,
                    "kind": kind,
                    "mandatory_review": kind in MANDATORY_REVIEW_KINDS,
                    "evidence_sha256": evidence,
                },
                moment,
            )
            connection.commit()
        return self.get_finding(tenant, finding)

    def get_finding(self, tenant_id: str, finding_id: str) -> ScreeningFinding:
        tenant = _tenant(tenant_id)
        finding = _id(finding_id, "finding_id")
        payload, digest = self._get_payload(
            "findings", tenant, "finding_id", finding, "screening finding"
        )
        return self._finding_from(payload, digest)

    def list_findings(
        self, tenant_id: str, run_id: str
    ) -> tuple[ScreeningFinding, ...]:
        tenant = _tenant(tenant_id)
        run = _id(run_id, "run_id")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM findings WHERE tenant_id=? AND run_id=? "
                "ORDER BY finding_id LIMIT ?",
                (tenant, run, _MAX_LIST),
            ).fetchall()
        return tuple(
            self._finding_from(self._row(row, "screening finding"), row["integrity_sha256"])
            for row in rows
        )

    def review_finding(
        self,
        tenant_id: str,
        finding_id: str,
        *,
        disposition: str,
        expected_revision: int,
        reviewer_ref: str,
        rationale: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ScreeningFinding:
        tenant = _tenant(tenant_id)
        finding = _id(finding_id, "finding_id")
        if disposition not in FINDING_DISPOSITIONS - {"pending_review"}:
            raise ThirdPartyIntelligenceValidationError(
                "finding disposition is closed"
            )
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        reviewer = _id(reviewer_ref, "reviewer_ref")
        reason = _text(rationale, "rationale", 2_000)
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "review_finding",
            "finding_id": finding,
            "disposition": disposition,
            "expected_revision": expected,
            "reviewer_ref": reviewer,
            "rationale": reason,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_finding(tenant, finding)
            row = connection.execute(
                "SELECT * FROM findings WHERE tenant_id=? AND finding_id=?",
                (tenant, finding),
            ).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("screening finding not found")
            payload = self._row(row, "screening finding")
            if (
                payload["disposition"] != "pending_review"
                or int(payload["revision"]) != expected
            ):
                raise ThirdPartyIntelligenceConflict(
                    "finding review state or revision does not match"
                )
            if payload["detected_by"] == reviewer:
                raise ThirdPartyIntelligencePermissionDenied(
                    "finding detection and disposition require different humans"
                )
            payload.update(
                {
                    "disposition": disposition,
                    "reviewed_by": reviewer,
                    "review_rationale": reason,
                    "revision": expected + 1,
                    "updated_at": moment,
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE findings SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND finding_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, finding),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "finding", finding
            )
            self._audit(
                connection,
                tenant,
                "screening_finding_reviewed",
                finding,
                reviewer,
                {"disposition": disposition, "revision": expected + 1},
                moment,
            )
            connection.commit()
        return self.get_finding(tenant, finding)

    @staticmethod
    def _hard_stop(finding: ScreeningFinding) -> bool:
        if finding.disposition in {"false_positive", "not_a_match"}:
            return False
        return (
            finding.kind in MANDATORY_REVIEW_KINDS
            or finding.severity == "critical"
            or finding.disposition == "escalated"
        )

    def complete_screening_run(
        self,
        tenant_id: str,
        run_id: str,
        *,
        expected_revision: int,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ScreeningRun:
        tenant = _tenant(tenant_id)
        run = _id(run_id, "run_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        actor = _id(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "complete_screening_run",
            "run_id": run,
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
                return self.get_screening_run(tenant, run)
            row = connection.execute(
                "SELECT * FROM screening_runs WHERE tenant_id=? AND run_id=?",
                (tenant, run),
            ).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("screening run not found")
            payload = self._row(row, "screening run")
            if payload["state"] != "open" or int(payload["revision"]) != expected:
                raise ThirdPartyIntelligenceConflict(
                    "screening run state or revision does not match"
                )
            vendor = self.get_vendor(tenant, payload["vendor_id"])
            for kind, snapshot_id in payload["snapshot_bindings"].items():
                self._validated_snapshot_binding(
                    tenant,
                    snapshot_id,
                    expected_kind=kind,
                    purpose="screening",
                    vendor=vendor,
                    now=moment,
                )
            findings = self.list_findings(tenant, run)
            if any(item.disposition == "pending_review" for item in findings):
                raise ThirdPartyIntelligenceConflict(
                    "every finding requires human disposition before completion"
                )
            state = "blocked" if any(self._hard_stop(item) for item in findings) else "complete"
            payload.update(
                {
                    "state": state,
                    "revision": expected + 1,
                    "completed_at": moment,
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE screening_runs SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND run_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, run),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "screening_run",
                run,
            )
            self._audit(
                connection,
                tenant,
                "screening_run_completed",
                run,
                actor,
                {"state": state, "finding_count": len(findings)},
                moment,
            )
            connection.commit()
        return self.get_screening_run(tenant, run)

    # -- versioned risk policy and fail-closed decisioning ---------------

    def create_risk_policy(
        self,
        tenant_id: str,
        *,
        policy_id: str,
        required_source_kinds: Sequence[str],
        maximum_source_age_seconds: int,
        minimum_completeness: float,
        factor_weights: Mapping[str, int],
        maximum_autoapproval_score: int,
        allow_low_risk_autoapproval: bool,
        allowed_territories: Sequence[str],
        maximum_vendor_criticality: int,
        maximum_data_access_level: str,
        authored_by: str,
        idempotency_key: str,
        expected_latest_version: int = 0,
        now: float | None = None,
    ) -> RiskPolicy:
        tenant = _tenant(tenant_id)
        policy = _id(policy_id, "policy_id")
        kinds = _closed_list(
            required_source_kinds,
            "required_source_kinds",
            SOURCE_KINDS,
            maximum=len(SOURCE_KINDS),
        )
        max_age = _integer(
            maximum_source_age_seconds,
            "maximum_source_age_seconds",
            60,
            365 * 24 * 60 * 60,
        )
        completeness = _fraction(minimum_completeness, "minimum_completeness")
        if not isinstance(factor_weights, Mapping) or set(factor_weights) != set(
            RISK_FACTOR_KEYS
        ):
            raise ThirdPartyIntelligenceValidationError(
                "factor_weights must exactly cover the closed factor catalog"
            )
        weights = {
            key: _integer(value, f"factor_weights.{key}", 0, 100)
            for key, value in sorted(factor_weights.items())
        }
        max_score = _integer(
            maximum_autoapproval_score,
            "maximum_autoapproval_score",
            0,
            100_000,
        )
        if not isinstance(allow_low_risk_autoapproval, bool):
            raise ThirdPartyIntelligenceValidationError(
                "allow_low_risk_autoapproval must be boolean"
            )
        if allow_low_risk_autoapproval and not MANDATORY_AUTOAPPROVAL_KINDS.issubset(
            kinds
        ):
            raise ThirdPartyIntelligenceValidationError(
                "autoapproval policy omits mandatory sanctions, PEP, watchlist, "
                "adverse-media, cyber-posture, or breach-intelligence evidence"
            )
        territories = _territories(allowed_territories)
        max_criticality = _integer(
            maximum_vendor_criticality, "maximum_vendor_criticality", 1, 5
        )
        if maximum_data_access_level not in DATA_ACCESS_LEVELS:
            raise ThirdPartyIntelligenceValidationError(
                "maximum_data_access_level is closed"
            )
        author = _id(authored_by, "authored_by")
        expected = _integer(
            expected_latest_version, "expected_latest_version", 0, 2**31 - 1
        )
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "create_risk_policy",
            "policy_id": policy,
            "required_source_kinds": list(kinds),
            "maximum_source_age_seconds": max_age,
            "minimum_completeness": completeness,
            "factor_weights": weights,
            "maximum_autoapproval_score": max_score,
            "allow_low_risk_autoapproval": allow_low_risk_autoapproval,
            "allowed_territories": list(territories),
            "maximum_vendor_criticality": max_criticality,
            "maximum_data_access_level": maximum_data_access_level,
            "authored_by": author,
            "expected_latest_version": expected,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_risk_policy(tenant, policy, expected + 1)
            latest = connection.execute(
                "SELECT MAX(version) AS version FROM risk_policies "
                "WHERE tenant_id=? AND policy_id=?",
                (tenant, policy),
            ).fetchone()
            latest_version = int(latest["version"] or 0)
            if latest_version != expected:
                raise ThirdPartyIntelligenceConflict(
                    "policy latest-version CAS does not match"
                )
            version = latest_version + 1
            payload = {
                "tenant_id": tenant,
                "policy_id": policy,
                "version": version,
                "required_source_kinds": list(kinds),
                "maximum_source_age_seconds": max_age,
                "minimum_completeness": completeness,
                "factor_weights": weights,
                "maximum_autoapproval_score": max_score,
                "allow_low_risk_autoapproval": allow_low_risk_autoapproval,
                "allowed_territories": list(territories),
                "maximum_vendor_criticality": max_criticality,
                "maximum_data_access_level": maximum_data_access_level,
                "state": "pending",
                "authored_by": author,
                "approved_by": None,
                "created_at": moment,
                "updated_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO risk_policies VALUES(?,?,?,?,?)",
                (tenant, policy, version, _canonical(payload).decode("ascii"), digest),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "risk_policy",
                f"{policy}:{version}",
            )
            self._audit(
                connection,
                tenant,
                "risk_policy_authored",
                f"{policy}:{version}",
                author,
                {"autoapproval_enabled": allow_low_risk_autoapproval},
                moment,
            )
            connection.commit()
        return self.get_risk_policy(tenant, policy, version)

    def get_risk_policy(
        self, tenant_id: str, policy_id: str, version: int
    ) -> RiskPolicy:
        tenant = _tenant(tenant_id)
        policy = _id(policy_id, "policy_id")
        policy_version = _integer(version, "version", 1, 2**31 - 1)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM risk_policies WHERE tenant_id=? AND policy_id=? "
                "AND version=?",
                (tenant, policy, policy_version),
            ).fetchone()
        if row is None:
            raise ThirdPartyIntelligenceNotFound("risk policy not found")
        return self._policy_from(self._row(row, "risk policy"), row["integrity_sha256"])

    def approve_risk_policy(
        self,
        tenant_id: str,
        policy_id: str,
        version: int,
        *,
        approver_ref: str,
        approved: bool,
        rationale: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> RiskPolicy:
        tenant = _tenant(tenant_id)
        policy = _id(policy_id, "policy_id")
        policy_version = _integer(version, "version", 1, 2**31 - 1)
        approver = _id(approver_ref, "approver_ref")
        if not isinstance(approved, bool):
            raise ThirdPartyIntelligenceValidationError("approved must be boolean")
        reason = _text(rationale, "rationale", 2_000)
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "approve_risk_policy",
            "policy_id": policy,
            "version": policy_version,
            "approver_ref": approver,
            "approved": approved,
            "rationale": reason,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_risk_policy(tenant, policy, policy_version)
            row = connection.execute(
                "SELECT * FROM risk_policies WHERE tenant_id=? AND policy_id=? "
                "AND version=?",
                (tenant, policy, policy_version),
            ).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("risk policy not found")
            payload = self._row(row, "risk policy")
            if payload["state"] != "pending":
                raise ThirdPartyIntelligenceConflict("risk policy is not pending")
            if payload["authored_by"] == approver:
                raise ThirdPartyIntelligencePermissionDenied(
                    "policy author and approver require different humans"
                )
            payload.update(
                {
                    "state": "approved" if approved else "rejected",
                    "approved_by": approver,
                    "updated_at": moment,
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE risk_policies SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND policy_id=? AND version=?",
                (
                    _canonical(payload).decode("ascii"),
                    digest,
                    tenant,
                    policy,
                    policy_version,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "risk_policy",
                f"{policy}:{policy_version}",
            )
            self._audit(
                connection,
                tenant,
                "risk_policy_approved" if approved else "risk_policy_rejected",
                f"{policy}:{policy_version}",
                approver,
                {"rationale_sha256": _sha256(reason)},
                moment,
            )
            connection.commit()
        return self.get_risk_policy(tenant, policy, policy_version)

    @staticmethod
    def _policy_scope_reasons(
        vendor: VendorProfile,
        relationships: Sequence[VendorRelationship],
        policy: RiskPolicy,
    ) -> list[str]:
        reasons: list[str] = []
        if not set(vendor.territories).issubset(policy.allowed_territories):
            reasons.append("vendor_outside_policy_territory")
        if vendor.criticality > policy.maximum_vendor_criticality:
            reasons.append("vendor_criticality_exceeds_scope")
        if (
            DATA_ACCESS_LEVELS[vendor.data_access_level]
            > DATA_ACCESS_LEVELS[policy.maximum_data_access_level]
        ):
            reasons.append("vendor_data_access_exceeds_scope")
        if any(
            item.criticality > policy.maximum_vendor_criticality
            for item in relationships
        ):
            reasons.append("relationship_criticality_exceeds_scope")
        if any(
            DATA_ACCESS_LEVELS[item.data_access_level]
            > DATA_ACCESS_LEVELS[policy.maximum_data_access_level]
            for item in relationships
        ):
            reasons.append("relationship_data_access_exceeds_scope")
        return reasons

    def evaluate_risk(
        self,
        tenant_id: str,
        *,
        decision_id: str,
        vendor_id: str,
        run_id: str,
        policy_id: str,
        policy_version: int,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> RiskDecision:
        """Evaluate a bounded policy; any uncertainty routes to human review."""

        tenant = _tenant(tenant_id)
        decision = _id(decision_id, "decision_id")
        vendor = self.get_vendor(tenant, vendor_id)
        run = self.get_screening_run(tenant, run_id)
        policy = self.get_risk_policy(tenant, policy_id, policy_version)
        actor = _id(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        if run.vendor_id != vendor.vendor_id:
            raise ThirdPartyIntelligencePermissionDenied(
                "screening run belongs to another vendor"
            )
        request = {
            "action": "evaluate_risk",
            "decision_id": decision,
            "vendor_id": vendor.vendor_id,
            "run_id": run.run_id,
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "actor_ref": actor,
        }
        reasons: list[str] = []
        factors: dict[str, int] = {}
        factors["inherent_risk"] = (
            vendor.inherent_risk_level * policy.factor_weights["inherent_risk"]
        )
        relationships = self.list_relationships(tenant, vendor.vendor_id)
        effective_criticality = max(
            [vendor.criticality, *(item.criticality for item in relationships)]
        )
        factors["criticality"] = (
            effective_criticality * policy.factor_weights["criticality"]
        )
        if policy.state != "approved" or policy.approved_by is None:
            reasons.append("policy_not_approved")
        if not policy.allow_low_risk_autoapproval:
            reasons.append("autoapproval_not_explicitly_enabled")
        if run.state != "complete":
            reasons.append("screening_not_clear_and_complete")
        reasons.extend(self._policy_scope_reasons(vendor, relationships, policy))
        if not set(policy.required_source_kinds).issubset(run.snapshot_bindings):
            reasons.append("required_source_kind_missing")
        snapshot_integrities: dict[str, str] = {}
        for kind in policy.required_source_kinds:
            snapshot_id = run.snapshot_bindings.get(kind)
            if snapshot_id is None:
                continue
            try:
                snapshot, _source = self._validated_snapshot_binding(
                    tenant,
                    snapshot_id,
                    expected_kind=kind,
                    purpose="risk_scoring",
                    vendor=vendor,
                    now=moment,
                    maximum_age_seconds=policy.maximum_source_age_seconds,
                    minimum_completeness=policy.minimum_completeness,
                )
                snapshot_integrities[kind] = snapshot.integrity_sha256
            except (
                ThirdPartyIntelligenceNotFound,
                ThirdPartyIntelligencePermissionDenied,
            ):
                reasons.append(f"source_{kind}_stale_incomplete_or_unlicensed")
        findings = self.list_findings(tenant, run.run_id)
        for finding in findings:
            if finding.disposition in {"false_positive", "not_a_match"}:
                continue
            factor = SEVERITY_POINTS[finding.severity] * policy.factor_weights[finding.kind]
            factors[finding.kind] = factors.get(finding.kind, 0) + factor
            if self._hard_stop(finding):
                reasons.append(f"hard_stop_{finding.kind}")
            elif finding.disposition != "confirmed":
                reasons.append(f"unresolved_{finding.kind}")
        score = sum(factors.values())
        if score > policy.maximum_autoapproval_score:
            reasons.append("risk_score_exceeds_threshold")
        reason_values = tuple(sorted(set(reasons)))
        autoapproved = not reason_values
        status = "auto_approved" if autoapproved else "human_review"
        evidence_sha = _sha256(
            {
                "vendor_revision": vendor.revision,
                "run_integrity_sha256": run.integrity_sha256,
                "policy_integrity_sha256": policy.integrity_sha256,
                "finding_integrity_sha256": [
                    item.integrity_sha256 for item in findings
                ],
                "relationship_integrity_sha256": [
                    item.integrity_sha256 for item in relationships
                ],
                "snapshot_integrity_sha256": dict(sorted(snapshot_integrities.items())),
                "factors": factors,
                "reasons": list(reason_values),
            }
        )
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_risk_decision(tenant, decision)
            if connection.execute(
                "SELECT 1 FROM risk_decisions WHERE tenant_id=? AND decision_id=?",
                (tenant, decision),
            ).fetchone():
                raise ThirdPartyIntelligenceConflict("risk decision already exists")
            payload = {
                "tenant_id": tenant,
                "decision_id": decision,
                "vendor_id": vendor.vendor_id,
                "run_id": run.run_id,
                "policy_id": policy.policy_id,
                "policy_version": policy.version,
                "status": status,
                "score": score,
                "factors": dict(sorted(factors.items())),
                "reason_codes": list(reason_values),
                "evidence_sha256": evidence_sha,
                "autoapproved": autoapproved,
                "revision": 1,
                "decided_by": actor,
                "decided_at": moment,
                "supersedes_decision_id": None,
                "rolled_back_from": None,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO risk_decisions VALUES(?,?,?,?,?)",
                (
                    tenant,
                    decision,
                    vendor.vendor_id,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "risk_decision",
                decision,
            )
            self._audit(
                connection,
                tenant,
                "risk_decision_recorded",
                decision,
                actor,
                {
                    "status": status,
                    "score": score,
                    "evidence_sha256": evidence_sha,
                },
                moment,
            )
            connection.commit()
        return self.get_risk_decision(tenant, decision)

    def get_risk_decision(self, tenant_id: str, decision_id: str) -> RiskDecision:
        tenant = _tenant(tenant_id)
        decision = _id(decision_id, "decision_id")
        payload, digest = self._get_payload(
            "risk_decisions", tenant, "decision_id", decision, "risk decision"
        )
        return self._decision_from(payload, digest)

    def override_risk_decision(
        self,
        tenant_id: str,
        decision_id: str,
        *,
        override_decision_id: str,
        status: str,
        expected_revision: int,
        actor_ref: str,
        rationale: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> RiskDecision:
        tenant = _tenant(tenant_id)
        prior = self.get_risk_decision(tenant, decision_id)
        override = _id(override_decision_id, "override_decision_id")
        if status not in {"approved", "rejected", "human_review"}:
            raise ThirdPartyIntelligenceValidationError("override status is closed")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        actor = _id(actor_ref, "actor_ref")
        reason = _text(rationale, "rationale", 2_000)
        moment = _timestamp(self._clock() if now is None else now, "now")
        if prior.revision != expected:
            raise ThirdPartyIntelligenceConflict(
                "risk decision expected revision does not match"
            )
        request = {
            "action": "override_risk_decision",
            "decision_id": prior.decision_id,
            "override_decision_id": override,
            "status": status,
            "expected_revision": expected,
            "actor_ref": actor,
            "rationale": reason,
        }
        evidence_sha = _sha256(
            {
                "prior_integrity_sha256": prior.integrity_sha256,
                "override_status": status,
                "rationale_sha256": _sha256(reason),
            }
        )
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_risk_decision(tenant, override)
            if connection.execute(
                "SELECT 1 FROM risk_decisions WHERE tenant_id=? AND decision_id=?",
                (tenant, override),
            ).fetchone():
                raise ThirdPartyIntelligenceConflict("override decision already exists")
            payload = {
                "tenant_id": tenant,
                "decision_id": override,
                "vendor_id": prior.vendor_id,
                "run_id": prior.run_id,
                "policy_id": prior.policy_id,
                "policy_version": prior.policy_version,
                "status": status,
                "score": prior.score,
                "factors": dict(prior.factors),
                "reason_codes": ["human_override"],
                "evidence_sha256": evidence_sha,
                "autoapproved": False,
                "revision": 1,
                "decided_by": actor,
                "decided_at": moment,
                "supersedes_decision_id": prior.decision_id,
                "rolled_back_from": None,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO risk_decisions VALUES(?,?,?,?,?)",
                (
                    tenant,
                    override,
                    prior.vendor_id,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "risk_decision",
                override,
            )
            self._audit(
                connection,
                tenant,
                "risk_decision_overridden",
                override,
                actor,
                {"prior_decision_id": prior.decision_id, "status": status},
                moment,
            )
            connection.commit()
        return self.get_risk_decision(tenant, override)

    def rollback_risk_decision(
        self,
        tenant_id: str,
        decision_id: str,
        *,
        restore_decision_id: str,
        rollback_decision_id: str,
        actor_ref: str,
        rationale: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> RiskDecision:
        tenant = _tenant(tenant_id)
        current = self.get_risk_decision(tenant, decision_id)
        restore = self.get_risk_decision(tenant, restore_decision_id)
        rollback = _id(rollback_decision_id, "rollback_decision_id")
        actor = _id(actor_ref, "actor_ref")
        reason = _text(rationale, "rationale", 2_000)
        moment = _timestamp(self._clock() if now is None else now, "now")
        if current.vendor_id != restore.vendor_id:
            raise ThirdPartyIntelligencePermissionDenied(
                "rollback decisions belong to different vendors"
            )
        request = {
            "action": "rollback_risk_decision",
            "decision_id": current.decision_id,
            "restore_decision_id": restore.decision_id,
            "rollback_decision_id": rollback,
            "actor_ref": actor,
            "rationale": reason,
        }
        evidence_sha = _sha256(
            {
                "current_integrity_sha256": current.integrity_sha256,
                "restore_integrity_sha256": restore.integrity_sha256,
                "rationale_sha256": _sha256(reason),
            }
        )
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_risk_decision(tenant, rollback)
            payload = {
                "tenant_id": tenant,
                "decision_id": rollback,
                "vendor_id": restore.vendor_id,
                "run_id": restore.run_id,
                "policy_id": restore.policy_id,
                "policy_version": restore.policy_version,
                "status": restore.status,
                "score": restore.score,
                "factors": dict(restore.factors),
                "reason_codes": ["human_rollback"],
                "evidence_sha256": evidence_sha,
                "autoapproved": False,
                "revision": 1,
                "decided_by": actor,
                "decided_at": moment,
                "supersedes_decision_id": current.decision_id,
                "rolled_back_from": current.decision_id,
            }
            digest = _sha256(payload)
            try:
                connection.execute(
                    "INSERT INTO risk_decisions VALUES(?,?,?,?,?)",
                    (
                        tenant,
                        rollback,
                        restore.vendor_id,
                        _canonical(payload).decode("ascii"),
                        digest,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ThirdPartyIntelligenceConflict(
                    "rollback decision already exists"
                ) from exc
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "risk_decision",
                rollback,
            )
            self._audit(
                connection,
                tenant,
                "risk_decision_rolled_back",
                rollback,
                actor,
                {
                    "rolled_back_from": current.decision_id,
                    "restored_decision_id": restore.decision_id,
                },
                moment,
            )
            connection.commit()
        return self.get_risk_decision(tenant, rollback)

    # -- enhanced due diligence -----------------------------------------

    def open_edd_case(
        self,
        tenant_id: str,
        *,
        case_id: str,
        vendor_id: str,
        reason: str,
        severity: str,
        opened_by: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> EDDCase:
        tenant = _tenant(tenant_id)
        case = _id(case_id, "case_id")
        vendor = self.get_vendor(tenant, vendor_id)
        reason_value = _text(reason, "reason", 2_000)
        if severity not in SEVERITIES - {"informational"}:
            raise ThirdPartyIntelligenceValidationError("EDD severity is closed")
        opener = _id(opened_by, "opened_by")
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "open_edd_case",
            "case_id": case,
            "vendor_id": vendor.vendor_id,
            "reason": reason_value,
            "severity": severity,
            "opened_by": opener,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_edd_case(tenant, case)
            if connection.execute(
                "SELECT 1 FROM edd_cases WHERE tenant_id=? AND case_id=?",
                (tenant, case),
            ).fetchone():
                raise ThirdPartyIntelligenceConflict("EDD case already exists")
            payload = {
                "tenant_id": tenant,
                "case_id": case,
                "vendor_id": vendor.vendor_id,
                "reason": reason_value,
                "severity": severity,
                "state": "open",
                "tasks": [],
                "evidence": [],
                "decision": None,
                "decision_rationale": None,
                "opened_by": opener,
                "decided_by": None,
                "revision": 1,
                "opened_at": moment,
                "updated_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO edd_cases VALUES(?,?,?,?,?)",
                (tenant, case, vendor.vendor_id, _canonical(payload).decode("ascii"), digest),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "edd_case", case
            )
            self._audit(
                connection,
                tenant,
                "edd_case_opened",
                case,
                opener,
                {"vendor_id": vendor.vendor_id, "severity": severity},
                moment,
            )
            connection.commit()
        return self.get_edd_case(tenant, case)

    def get_edd_case(self, tenant_id: str, case_id: str) -> EDDCase:
        tenant = _tenant(tenant_id)
        case = _id(case_id, "case_id")
        payload, digest = self._get_payload(
            "edd_cases", tenant, "case_id", case, "EDD case"
        )
        return self._edd_from(payload, digest)

    def set_edd_task(
        self,
        tenant_id: str,
        case_id: str,
        *,
        task_id: str,
        title: str,
        assignee_ref: str,
        due_at: float,
        status: str,
        evidence_sha256: str | None,
        expected_revision: int,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> EDDCase:
        tenant = _tenant(tenant_id)
        case = _id(case_id, "case_id")
        task = _id(task_id, "task_id")
        title_value = _text(title, "task title", 500)
        assignee = _id(assignee_ref, "assignee_ref")
        due = _timestamp(due_at, "due_at")
        if status not in {"open", "complete", "waived"}:
            raise ThirdPartyIntelligenceValidationError("EDD task status is closed")
        evidence = (
            _digest(evidence_sha256, "evidence_sha256")
            if evidence_sha256 is not None
            else None
        )
        if status in {"complete", "waived"} and evidence is None:
            raise ThirdPartyIntelligenceValidationError(
                "completed or waived EDD tasks require evidence"
            )
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        actor = _id(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "set_edd_task",
            "case_id": case,
            "task_id": task,
            "title": title_value,
            "assignee_ref": assignee,
            "due_at": due,
            "status": status,
            "evidence_sha256": evidence,
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
                return self.get_edd_case(tenant, case)
            row = connection.execute(
                "SELECT * FROM edd_cases WHERE tenant_id=? AND case_id=?",
                (tenant, case),
            ).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("EDD case not found")
            payload = self._row(row, "EDD case")
            if payload["state"] != "open" or int(payload["revision"]) != expected:
                raise ThirdPartyIntelligenceConflict(
                    "EDD case state or revision does not match"
                )
            tasks = [item for item in payload["tasks"] if item["task_id"] != task]
            if len(tasks) >= 500:
                raise ThirdPartyIntelligenceValidationError("EDD task limit reached")
            tasks.append(
                {
                    "task_id": task,
                    "title": title_value,
                    "assignee_ref": assignee,
                    "due_at": due,
                    "status": status,
                    "evidence_sha256": evidence,
                    "updated_by": actor,
                    "updated_at": moment,
                }
            )
            tasks.sort(key=lambda item: item["task_id"])
            payload.update(
                {"tasks": tasks, "revision": expected + 1, "updated_at": moment}
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE edd_cases SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND case_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, case),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "edd_case", case
            )
            self._audit(
                connection,
                tenant,
                "edd_task_recorded",
                f"{case}:{task}",
                actor,
                {"status": status, "revision": expected + 1},
                moment,
            )
            connection.commit()
        return self.get_edd_case(tenant, case)

    def add_edd_evidence(
        self,
        tenant_id: str,
        case_id: str,
        *,
        evidence_id: str,
        snapshot_id: str,
        evidence_sha256: str,
        citations: Sequence[Mapping[str, object]],
        summary: str,
        expected_revision: int,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> EDDCase:
        tenant = _tenant(tenant_id)
        case = _id(case_id, "case_id")
        evidence_id_value = _id(evidence_id, "evidence_id")
        snapshot = self.get_source_snapshot(tenant, snapshot_id)
        evidence = _digest(evidence_sha256, "evidence_sha256")
        citation_values = _citations(citations)
        summary_value = _text(summary, "summary", 2_000)
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        actor = _id(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        case_current = self.get_edd_case(tenant, case)
        vendor = self.get_vendor(tenant, case_current.vendor_id)
        self._validated_snapshot_binding(
            tenant,
            snapshot.snapshot_id,
            expected_kind=self.get_source(tenant, snapshot.source_id).kind,
            purpose="edd",
            vendor=vendor,
            now=moment,
        )
        request = {
            "action": "add_edd_evidence",
            "case_id": case,
            "evidence_id": evidence_id_value,
            "snapshot_id": snapshot.snapshot_id,
            "evidence_sha256": evidence,
            "citations": _citation_json(citation_values),
            "summary": summary_value,
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
                return self.get_edd_case(tenant, case)
            row = connection.execute(
                "SELECT * FROM edd_cases WHERE tenant_id=? AND case_id=?",
                (tenant, case),
            ).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("EDD case not found")
            payload = self._row(row, "EDD case")
            if payload["state"] != "open" or int(payload["revision"]) != expected:
                raise ThirdPartyIntelligenceConflict(
                    "EDD case state or revision does not match"
                )
            if any(item["evidence_id"] == evidence_id_value for item in payload["evidence"]):
                raise ThirdPartyIntelligenceConflict("EDD evidence already exists")
            if len(payload["evidence"]) >= 500:
                raise ThirdPartyIntelligenceValidationError("EDD evidence limit reached")
            payload["evidence"].append(
                {
                    "evidence_id": evidence_id_value,
                    "snapshot_id": snapshot.snapshot_id,
                    "source_id": snapshot.source_id,
                    "evidence_sha256": evidence,
                    "citations": _citation_json(citation_values),
                    "summary": summary_value,
                    "added_by": actor,
                    "added_at": moment,
                }
            )
            payload["evidence"].sort(key=lambda item: item["evidence_id"])
            payload.update(
                {"revision": expected + 1, "updated_at": moment}
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE edd_cases SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND case_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, case),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "edd_case", case
            )
            self._audit(
                connection,
                tenant,
                "edd_evidence_added",
                f"{case}:{evidence_id_value}",
                actor,
                {"source_id": snapshot.source_id, "evidence_sha256": evidence},
                moment,
            )
            connection.commit()
        return self.get_edd_case(tenant, case)

    def decide_edd_case(
        self,
        tenant_id: str,
        case_id: str,
        *,
        decision: str,
        rationale: str,
        expected_revision: int,
        reviewer_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> EDDCase:
        tenant = _tenant(tenant_id)
        case = _id(case_id, "case_id")
        if decision not in EDD_DECISIONS:
            raise ThirdPartyIntelligenceValidationError("EDD decision is closed")
        rationale_value = _text(rationale, "rationale", 4_000)
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        reviewer = _id(reviewer_ref, "reviewer_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "decide_edd_case",
            "case_id": case,
            "decision": decision,
            "rationale": rationale_value,
            "expected_revision": expected,
            "reviewer_ref": reviewer,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_edd_case(tenant, case)
            row = connection.execute(
                "SELECT * FROM edd_cases WHERE tenant_id=? AND case_id=?",
                (tenant, case),
            ).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("EDD case not found")
            payload = self._row(row, "EDD case")
            if payload["state"] != "open" or int(payload["revision"]) != expected:
                raise ThirdPartyIntelligenceConflict(
                    "EDD case state or revision does not match"
                )
            if payload["opened_by"] == reviewer:
                raise ThirdPartyIntelligencePermissionDenied(
                    "EDD case opener and decision reviewer require different humans"
                )
            if decision != "escalated":
                if not payload["tasks"] or any(
                    item["status"] not in {"complete", "waived"}
                    for item in payload["tasks"]
                ):
                    raise ThirdPartyIntelligenceConflict(
                        "EDD decision requires all governed tasks complete"
                    )
                if not payload["evidence"]:
                    raise ThirdPartyIntelligenceConflict(
                        "EDD decision requires retained evidence"
                    )
                vendor = self.get_vendor(tenant, payload["vendor_id"])
                for item in payload["evidence"]:
                    snapshot = self.get_source_snapshot(tenant, item["snapshot_id"])
                    source = self.get_source(tenant, snapshot.source_id)
                    self._validated_snapshot_binding(
                        tenant,
                        snapshot.snapshot_id,
                        expected_kind=source.kind,
                        purpose="edd",
                        vendor=vendor,
                        now=moment,
                    )
            payload.update(
                {
                    "state": "escalated" if decision == "escalated" else "decided",
                    "decision": decision,
                    "decision_rationale": rationale_value,
                    "decided_by": reviewer,
                    "revision": expected + 1,
                    "updated_at": moment,
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE edd_cases SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND case_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, case),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "edd_case", case
            )
            self._audit(
                connection,
                tenant,
                "edd_case_decided",
                case,
                reviewer,
                {"decision": decision, "rationale_sha256": _sha256(rationale_value)},
                moment,
            )
            connection.commit()
        return self.get_edd_case(tenant, case)

    # -- continuous monitoring and reliable delivery --------------------

    def create_monitor(
        self,
        tenant_id: str,
        *,
        monitor_id: str,
        vendor_id: str,
        source_bindings: Mapping[str, str],
        destination_ref: str,
        cadence_seconds: int,
        created_by: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> Monitor:
        tenant = _tenant(tenant_id)
        monitor = _id(monitor_id, "monitor_id")
        vendor = self.get_vendor(tenant, vendor_id)
        if not isinstance(source_bindings, Mapping) or not source_bindings:
            raise ThirdPartyIntelligenceValidationError(
                "source_bindings must be a non-empty object"
            )
        bindings: dict[str, str] = {}
        for kind, source_id in source_bindings.items():
            if kind not in SOURCE_KINDS:
                raise ThirdPartyIntelligenceValidationError("source kind is closed")
            source = self.get_source(tenant, source_id)
            if source.kind != kind or source.state != "active":
                raise ThirdPartyIntelligencePermissionDenied(
                    "monitor source does not match an active kind binding"
                )
            if "monitoring" not in source.purposes:
                raise ThirdPartyIntelligencePermissionDenied(
                    "source rights do not permit monitoring"
                )
            if not set(vendor.territories).issubset(source.territories):
                raise ThirdPartyIntelligencePermissionDenied(
                    "source territories do not cover the vendor"
                )
            bindings[kind] = source.source_id
        destination = _id(destination_ref, "destination_ref")
        cadence = _integer(cadence_seconds, "cadence_seconds", 60, 365 * 24 * 60 * 60)
        creator = _id(created_by, "created_by")
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "create_monitor",
            "monitor_id": monitor,
            "vendor_id": vendor.vendor_id,
            "source_bindings": dict(sorted(bindings.items())),
            "destination_ref": destination,
            "cadence_seconds": cadence,
            "created_by": creator,
        }
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_monitor(tenant, monitor)
            if connection.execute(
                "SELECT 1 FROM monitors WHERE tenant_id=? AND monitor_id=?",
                (tenant, monitor),
            ).fetchone():
                raise ThirdPartyIntelligenceConflict("monitor already exists")
            payload = {
                "tenant_id": tenant,
                "monitor_id": monitor,
                "vendor_id": vendor.vendor_id,
                "source_bindings": dict(sorted(bindings.items())),
                "destination_ref": destination,
                "cadence_seconds": cadence,
                "next_run_at": moment,
                "state": "active",
                "last_observation_sha256": None,
                "revision": 1,
                "created_by": creator,
                "created_at": moment,
                "updated_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO monitors VALUES(?,?,?,?,?)",
                (tenant, monitor, vendor.vendor_id, _canonical(payload).decode("ascii"), digest),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "monitor", monitor
            )
            self._audit(
                connection,
                tenant,
                "vendor_monitor_created",
                monitor,
                creator,
                {"vendor_id": vendor.vendor_id, "source_kinds": sorted(bindings)},
                moment,
            )
            connection.commit()
        return self.get_monitor(tenant, monitor)

    def get_monitor(self, tenant_id: str, monitor_id: str) -> Monitor:
        tenant = _tenant(tenant_id)
        monitor = _id(monitor_id, "monitor_id")
        payload, digest = self._get_payload(
            "monitors", tenant, "monitor_id", monitor, "monitor"
        )
        return self._monitor_from(payload, digest)

    def due_monitors(
        self, tenant_id: str, *, limit: int = 100, now: float | None = None,
        after_id: str | None = None,
    ) -> tuple[Monitor, ...]:
        tenant = _tenant(tenant_id)
        limit_value = _integer(limit, "limit", 1, 500)
        moment = _timestamp(self._clock() if now is None else now, "now")
        position = "" if after_id is None else _id(after_id, "after_id")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM monitors WHERE tenant_id=? "
                "AND json_extract(payload_json,'$.state')='active' "
                "AND json_extract(payload_json,'$.next_run_at')<=? "
                "AND monitor_id>? "
                "ORDER BY monitor_id LIMIT ?",
                (tenant, moment, position, limit_value),
            ).fetchall()
        return tuple(
            self._monitor_from(self._row(row, "monitor"), row["integrity_sha256"])
            for row in rows
        )

    def record_monitor_observation(
        self,
        tenant_id: str,
        monitor_id: str,
        *,
        snapshot_bindings: Mapping[str, str],
        observation_sha256: str,
        evidence_sha256: str,
        citations: Sequence[Mapping[str, object]],
        expected_revision: int,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> MonitoringResult:
        tenant = _tenant(tenant_id)
        monitor_id_value = _id(monitor_id, "monitor_id")
        current = self.get_monitor(tenant, monitor_id_value)
        if not isinstance(snapshot_bindings, Mapping):
            raise ThirdPartyIntelligenceValidationError(
                "snapshot_bindings must be an object"
            )
        bindings = {
            _id(kind, "source kind"): _id(snapshot, "snapshot_id")
            for kind, snapshot in snapshot_bindings.items()
        }
        if set(bindings) != set(current.source_bindings):
            raise ThirdPartyIntelligenceValidationError(
                "snapshot bindings must exactly cover monitor sources"
            )
        observation = _digest(observation_sha256, "observation_sha256")
        evidence = _digest(evidence_sha256, "evidence_sha256")
        citation_values = _citations(citations)
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        actor = _id(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        vendor = self.get_vendor(tenant, current.vendor_id)
        for kind, snapshot_id in bindings.items():
            _snapshot, source = self._validated_snapshot_binding(
                tenant,
                snapshot_id,
                expected_kind=kind,
                purpose="monitoring",
                vendor=vendor,
                now=moment,
            )
            if source.source_id != current.source_bindings[kind]:
                raise ThirdPartyIntelligencePermissionDenied(
                    "snapshot source does not match monitor enrollment"
                )
        request = {
            "action": "record_monitor_observation",
            "monitor_id": monitor_id_value,
            "snapshot_bindings": dict(sorted(bindings.items())),
            "observation_sha256": observation,
            "evidence_sha256": evidence,
            "citations": _citation_json(citation_values),
            "expected_revision": expected,
            "actor_ref": actor,
        }
        alert: MonitoringAlert | None = None
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                result_monitor = self.get_monitor(tenant, monitor_id_value)
                result_id = str(operation["result_id"])
                if result_id != "baseline" and result_id != "unchanged":
                    alert = self.get_monitoring_alert(tenant, result_id)
                return MonitoringResult(
                    monitor=result_monitor,
                    changed=result_id not in {"baseline", "unchanged"},
                    alert=alert,
                )
            row = connection.execute(
                "SELECT * FROM monitors WHERE tenant_id=? AND monitor_id=?",
                (tenant, monitor_id_value),
            ).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("monitor not found")
            payload = self._row(row, "monitor")
            if payload["state"] != "active" or int(payload["revision"]) != expected:
                raise ThirdPartyIntelligenceConflict(
                    "monitor state or revision does not match"
                )
            previous = payload["last_observation_sha256"]
            changed = previous is not None and not hmac.compare_digest(previous, observation)
            result_id = "baseline" if previous is None else "unchanged"
            if changed:
                stable = _sha256(
                    {
                        "tenant_id": tenant,
                        "monitor_id": monitor_id_value,
                        "previous": previous,
                        "current": observation,
                        "snapshot_bindings": dict(sorted(bindings.items())),
                    }
                )
                alert_id = f"ALT-{stable[:24]}"
                delivery_id = f"DLV-{stable[24:48]}"
                alert_payload = {
                    "tenant_id": tenant,
                    "alert_id": alert_id,
                    "monitor_id": monitor_id_value,
                    "vendor_id": current.vendor_id,
                    "previous_observation_sha256": previous,
                    "observation_sha256": observation,
                    "evidence_sha256": evidence,
                    "snapshot_bindings": dict(sorted(bindings.items())),
                    "citations": _citation_json(citation_values),
                    "created_at": moment,
                }
                alert_digest = _sha256(alert_payload)
                inserted = connection.execute(
                    "INSERT OR IGNORE INTO monitoring_alerts VALUES(?,?,?,?,?)",
                    (
                        tenant,
                        alert_id,
                        monitor_id_value,
                        _canonical(alert_payload).decode("ascii"),
                        alert_digest,
                    ),
                ).rowcount
                if inserted:
                    outbox_payload = {
                        "tenant_id": tenant,
                        "delivery_id": delivery_id,
                        "alert_id": alert_id,
                        "destination_ref": current.destination_ref,
                        "state": "pending",
                        "attempt": 0,
                        "maximum_attempts": 5,
                        "next_attempt_at": moment,
                        "lease_token": None,
                        "lease_until": None,
                        "revision": 1,
                        "last_error_code": None,
                    }
                    outbox_digest = _sha256(outbox_payload)
                    connection.execute(
                        "INSERT INTO outbox VALUES(?,?,?,?,?,?,?,?)",
                        (
                            tenant,
                            delivery_id,
                            alert_id,
                            "pending",
                            moment,
                            None,
                            _canonical(outbox_payload).decode("ascii"),
                            outbox_digest,
                        ),
                    )
                alert = self._alert_from(alert_payload, alert_digest)
                result_id = alert_id
            payload.update(
                {
                    "last_observation_sha256": observation,
                    "next_run_at": moment + int(payload["cadence_seconds"]),
                    "revision": expected + 1,
                    "updated_at": moment,
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE monitors SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND monitor_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, monitor_id_value),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "monitor_observation",
                result_id,
            )
            self._audit(
                connection,
                tenant,
                "monitor_observation_recorded",
                monitor_id_value,
                actor,
                {"changed": changed, "evidence_sha256": evidence},
                moment,
            )
            connection.commit()
        return MonitoringResult(
            monitor=self.get_monitor(tenant, monitor_id_value),
            changed=changed,
            alert=alert,
        )

    def get_monitoring_alert(
        self, tenant_id: str, alert_id: str
    ) -> MonitoringAlert:
        tenant = _tenant(tenant_id)
        alert = _id(alert_id, "alert_id")
        payload, digest = self._get_payload(
            "monitoring_alerts", tenant, "alert_id", alert, "monitoring alert"
        )
        return self._alert_from(payload, digest)

    def _recipient_record(self, row: sqlite3.Row) -> dict[str, Any]:
        from .tenant.kms import unseal_text_for_tenant

        payload = self._row(row, "alert recipient")
        try:
            private = json.loads(unseal_text_for_tenant(
                row["tenant_id"], bytes.fromhex(payload["sealed_address"])))
            if (private["tenant_id"] != row["tenant_id"]
                    or private["recipient_id"] != row["recipient_id"]
                    or private["destination_ref"] != payload["destination_ref"]
                    or private["destination_ref"] != row["destination_ref"]
                    or private["revision"] != payload["revision"]
                    or private["state"] != payload["state"]):
                raise ValueError("recipient binding changed")
        except Exception as exc:
            raise ThirdPartyIntelligenceIntegrityError(
                "The saved alert recipient could not be opened.") from exc
        return {**private, "integrity_sha256": row["integrity_sha256"]}

    def get_alert_recipient(self, tenant_id: str, recipient_id: str) -> dict[str, Any]:
        tenant, recipient = _tenant(tenant_id), _id(recipient_id, "recipient_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM alert_recipients WHERE tenant_id=? AND recipient_id=?",
                (tenant, recipient)).fetchone()
        if row is None:
            raise ThirdPartyIntelligenceNotFound("Alert recipient not found.")
        return self._recipient_record(row)

    def list_alert_recipients(self, tenant_id: str, *, limit: int = 500) -> tuple[dict[str, Any], ...]:
        tenant, bounded = _tenant(tenant_id), _integer(limit, "limit", 1, 1000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM alert_recipients WHERE tenant_id=? ORDER BY recipient_id LIMIT ?",
                (tenant, bounded)).fetchall()
        return tuple(self._recipient_record(row) for row in rows)

    def resolve_alert_recipient(self, tenant_id: str, destination_ref: str) -> dict[str, Any]:
        tenant, reference = _tenant(tenant_id), _id(destination_ref, "destination_ref")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM alert_recipients WHERE tenant_id=? AND destination_ref=?", (tenant, reference)).fetchall()
        for row in rows:
            payload = self._row(row, "alert recipient")
            if payload["destination_ref"] == reference:
                recipient = self._recipient_record(row)
                if recipient["state"] != "active":
                    raise ThirdPartyIntelligencePermissionDenied("This alert recipient was withdrawn. Choose a current recipient.")
                return recipient
        raise ThirdPartyIntelligenceNotFound("Choose a saved alert recipient.")

    def save_alert_recipient(self, tenant_id: str, *, recipient_id: str, name: str,
                             address: str, actor_ref: str, idempotency_key: str,
                             external_use_reviewed: bool,
                             effect_guard: Callable[[], None] | None = None) -> dict[str, Any]:
        """An address is immutable under its opaque reference; changes require a new choice."""
        from .tenant.kms import seal_text_for_tenant
        from .third_party_intelligence_delivery import DestinationResolutionError, _recipient

        tenant, recipient = _tenant(tenant_id), _id(recipient_id, "recipient_id")
        label, actor = _text(name, "name", 120), _id(actor_ref, "actor_ref")
        try:
            email = _recipient(address)
        except DestinationResolutionError as exc:
            raise ThirdPartyIntelligenceValidationError("Enter one complete email address, such as team@example.com.") from exc
        if external_use_reviewed is not True:
            raise ThirdPartyIntelligencePermissionDenied("Review who will receive vendor change alerts before saving.")
        request = {"action": "save_alert_recipient", "recipient_id": recipient,
                   "name": label, "address": email, "actor_ref": actor, "external_use_reviewed": True}
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            if effect_guard:
                effect_guard()
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                connection.commit()
                return self.get_alert_recipient(tenant, recipient)
            if connection.execute("SELECT 1 FROM alert_recipients WHERE tenant_id=? AND recipient_id=?",
                                  (tenant, recipient)).fetchone():
                raise ThirdPartyIntelligenceConflict("This recipient already exists. Withdraw it and add a new recipient to change its address.")
            private = {"tenant_id": tenant, "recipient_id": recipient, "name": label,
                       "address": email, "destination_ref": "recipient-" + secrets.token_hex(24),
                       "revision": 1, "state": "active", "created_by": actor, "created_at": self._clock()}
            payload = {key: private[key] for key in ("tenant_id", "recipient_id", "destination_ref", "revision", "state")}
            payload["sealed_address"] = seal_text_for_tenant(tenant, _canonical(private).decode("ascii")).hex()
            connection.execute("INSERT INTO alert_recipients VALUES(?,?,?,?,?)",
                               (tenant, recipient, private["destination_ref"], _canonical(payload).decode("ascii"), _sha256(payload)))
            self._record_operation(connection, tenant, idempotency_key, request_sha, "alert_recipient", recipient)
            self._audit(connection, tenant, "alert_recipient_saved", recipient, actor, {"revision": 1}, self._clock())
            if effect_guard:
                effect_guard()
            connection.commit()
        return self.get_alert_recipient(tenant, recipient)

    def withdraw_alert_recipient(self, tenant_id: str, recipient_id: str, *, expected_revision: int,
                                 actor_ref: str, idempotency_key: str,
                                 effect_guard: Callable[[], None] | None = None) -> dict[str, Any]:
        from .tenant.kms import seal_text_for_tenant

        tenant, recipient = _tenant(tenant_id), _id(recipient_id, "recipient_id")
        expected, actor = _integer(expected_revision, "expected_revision", 1, 2**31 - 1), _id(actor_ref, "actor_ref")
        request = {"action": "withdraw_alert_recipient", "recipient_id": recipient,
                   "expected_revision": expected, "actor_ref": actor}
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            if effect_guard:
                effect_guard()
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                connection.commit()
                return self.get_alert_recipient(tenant, recipient)
            row = connection.execute("SELECT * FROM alert_recipients WHERE tenant_id=? AND recipient_id=?",
                                     (tenant, recipient)).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("Alert recipient not found.")
            private = self._recipient_record(row)
            if private["state"] != "active" or private["revision"] != expected:
                raise ThirdPartyIntelligenceConflict("This recipient changed. Reload the current recipients.")
            private.pop("integrity_sha256")
            private.update(state="withdrawn", revision=expected + 1)
            payload = {key: private[key] for key in ("tenant_id", "recipient_id", "destination_ref", "revision", "state")}
            payload["sealed_address"] = seal_text_for_tenant(tenant, _canonical(private).decode("ascii")).hex()
            connection.execute("UPDATE alert_recipients SET payload_json=?,integrity_sha256=? WHERE tenant_id=? AND recipient_id=?",
                               (_canonical(payload).decode("ascii"), _sha256(payload), tenant, recipient))
            for delivery_row in connection.execute("SELECT * FROM outbox WHERE tenant_id=? AND state IN ('pending','leased')", (tenant,)).fetchall():
                delivery = self._row(delivery_row, "outbox item")
                if delivery["destination_ref"] == private["destination_ref"]:
                    delivery.update(state="cancelled", lease_token=None, lease_until=None, revision=delivery["revision"] + 1)
                    connection.execute("UPDATE outbox SET state='cancelled',lease_until=NULL,payload_json=?,integrity_sha256=? WHERE tenant_id=? AND delivery_id=?",
                                       (_canonical(delivery).decode("ascii"), _sha256(delivery), tenant, delivery["delivery_id"]))
            self._record_operation(connection, tenant, idempotency_key, request_sha, "alert_recipient", recipient)
            self._audit(connection, tenant, "alert_recipient_withdrawn", recipient, actor, {"revision": expected + 1}, self._clock())
            if effect_guard:
                effect_guard()
            connection.commit()
        return self.get_alert_recipient(tenant, recipient)

    def list_outbox(self, tenant_id: str, *, limit: int = 500) -> tuple[OutboxItem, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM outbox WHERE tenant_id=? ORDER BY "
                "CASE WHEN state IN ('dispatching','ambiguous') THEN 0 WHEN state IN ('pending','leased') THEN 1 ELSE 2 END,"
                "next_attempt_at DESC,delivery_id LIMIT ?",
                (_tenant(tenant_id), _integer(limit, "limit", 1, 1000))).fetchall()
        return tuple(self._outbox_from(self._row(row, "outbox item"), row["integrity_sha256"]) for row in rows)

    def ready_outbox(self, tenant_id: str, *, limit: int = 10) -> tuple[OutboxItem, ...]:
        """Bound matching waiting work, so retained history cannot starve new alerts."""
        moment = self._clock()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT o.* FROM outbox o JOIN monitoring_alerts a ON a.tenant_id=o.tenant_id AND a.alert_id=o.alert_id "
                "JOIN monitors m ON m.tenant_id=a.tenant_id AND m.monitor_id=a.monitor_id WHERE o.tenant_id=? "
                "AND ((o.state='pending' AND o.next_attempt_at<=?) OR (o.state='leased' AND o.lease_until<=?)) "
                "AND json_extract(m.payload_json,'$.state')='active' AND NOT EXISTS ("
                "SELECT 1 FROM json_each(m.payload_json,'$.source_bindings') b LEFT JOIN sources s "
                "ON s.tenant_id=m.tenant_id AND s.source_id=b.value WHERE s.source_id IS NULL "
                "OR json_extract(s.payload_json,'$.state')!='active' OR NOT EXISTS "
                "(SELECT 1 FROM json_each(s.payload_json,'$.purposes') p WHERE p.value='monitoring')) "
                "AND (json_extract(o.payload_json,'$.destination_ref') NOT LIKE 'recipient-%' OR EXISTS "
                "(SELECT 1 FROM alert_recipients r WHERE r.tenant_id=o.tenant_id "
                "AND r.destination_ref=json_extract(o.payload_json,'$.destination_ref') AND json_extract(r.payload_json,'$.state')='active')) "
                "ORDER BY o.next_attempt_at,o.delivery_id LIMIT ?",
                (_tenant(tenant_id), moment, moment, _integer(limit, "limit", 1, 100))).fetchall()
        return tuple(self._outbox_from(self._row(row, "outbox item"), row["integrity_sha256"]) for row in rows)

    def get_outbox(self, tenant_id: str, delivery_id: str) -> OutboxItem:
        payload, digest = self._get_payload("outbox", _tenant(tenant_id), "delivery_id",
                                           _id(delivery_id, "delivery_id"), "outbox item")
        return self._outbox_from(payload, digest)

    def assert_delivery_authority(self, item: OutboxItem) -> None:
        current = self.get_outbox(item.tenant_id, item.delivery_id)
        if (current.state not in {"leased", "dispatching"} or current.lease_token != item.lease_token
                or float(current.lease_until or 0) < self._clock()):
            raise ThirdPartyIntelligenceConflict("The alert's send reservation expired or changed.")
        alert = self.get_monitoring_alert(item.tenant_id, item.alert_id)
        monitor = self.get_monitor(item.tenant_id, alert.monitor_id)
        if monitor.state != "active" or monitor.destination_ref != item.destination_ref:
            raise ThirdPartyIntelligencePermissionDenied("This vendor watch was stopped or changed.")
        vendor = self.get_vendor(item.tenant_id, alert.vendor_id)
        for kind, source_id in monitor.source_bindings.items():
            source = self.get_source(item.tenant_id, source_id)
            if (source.state != "active" or source.kind != kind or "monitoring" not in source.purposes
                    or not set(vendor.territories).issubset(source.territories)):
                raise ThirdPartyIntelligencePermissionDenied("A source's permission to watch for changes was withdrawn.")

    def mark_outbox_dispatch(self, item: OutboxItem, *, ambiguous: bool = False) -> OutboxItem:
        """Retain admission before network effect; never automatically reclaim an uncertain send."""
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            row = connection.execute("SELECT * FROM outbox WHERE tenant_id=? AND delivery_id=?",
                                     (item.tenant_id, item.delivery_id)).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("Alert delivery not found.")
            payload = self._row(row, "outbox item")
            if payload["state"] != ("dispatching" if ambiguous else "leased") or payload["lease_token"] != item.lease_token:
                raise ThirdPartyIntelligenceConflict("The alert's send reservation changed.")
            if not ambiguous:
                self.assert_delivery_authority(item)
            payload.update(state="ambiguous" if ambiguous else "dispatching", revision=payload["revision"] + 1)
            digest = _sha256(payload)
            connection.execute("UPDATE outbox SET state=?,payload_json=?,integrity_sha256=? WHERE tenant_id=? AND delivery_id=?",
                               (payload["state"], _canonical(payload).decode("ascii"), digest, item.tenant_id, item.delivery_id))
            connection.commit()
        return self._outbox_from(payload, digest)

    def claim_outbox(
        self,
        tenant_id: str,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: float = 60.0,
        now: float | None = None,
        delivery_ids: Sequence[str] | None = None,
        effect_guard: Callable[[], None] | None = None,
    ) -> tuple[OutboxItem, ...]:
        tenant = _tenant(tenant_id)
        worker = _id(worker_id, "worker_id")
        limit_value = _integer(limit, "limit", 1, 100)
        lease = _timestamp(lease_seconds, "lease_seconds")
        if lease > _MAX_LEASE_SECONDS:
            raise ThirdPartyIntelligenceValidationError("lease_seconds is too large")
        moment = _timestamp(self._clock() if now is None else now, "now")
        selected = tuple(_id(value, "delivery_id") for value in delivery_ids) if delivery_ids is not None else None
        if selected is not None and (not selected or len(set(selected)) != len(selected) or len(selected) > limit_value):
            raise ThirdPartyIntelligenceValidationError("Choose one bounded, distinct reviewed batch.")
        selection_sql = " AND delivery_id IN (" + ",".join("?" for _ in selected) + ")" if selected else ""
        claimed: list[OutboxItem] = []
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            if effect_guard:
                effect_guard()
            moment = _timestamp(self._clock() if now is None else now, "now")
            rows = connection.execute(
                "SELECT * FROM outbox WHERE tenant_id=? AND "
                "((state='pending' AND next_attempt_at<=?) OR "
                "(state='leased' AND lease_until<=?)) "
                + selection_sql + " ORDER BY next_attempt_at,delivery_id LIMIT ?",
                (tenant, moment, moment, *(selected or ()), limit_value),
            ).fetchall()
            for row in rows:
                payload = self._row(row, "outbox item")
                alert_row = connection.execute(
                    "SELECT * FROM monitoring_alerts WHERE tenant_id=? AND alert_id=?",
                    (tenant, payload["alert_id"]),
                ).fetchone()
                if alert_row is None:
                    raise ThirdPartyIntelligenceIntegrityError(
                        "outbox item references a missing alert"
                    )
                alert_payload = self._row(alert_row, "monitoring alert")
                monitor_row = connection.execute(
                    "SELECT * FROM monitors WHERE tenant_id=? AND monitor_id=?",
                    (tenant, alert_payload["monitor_id"]),
                ).fetchone()
                if monitor_row is None:
                    raise ThirdPartyIntelligenceIntegrityError(
                        "monitoring alert references a missing monitor"
                    )
                monitor_payload = self._row(monitor_row, "monitor")
                source_rights_current = monitor_payload["state"] == "active"
                vendor = self.get_vendor(tenant, monitor_payload["vendor_id"])
                for kind, source_id in monitor_payload["source_bindings"].items():
                    source_row = connection.execute(
                        "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                        (tenant, source_id),
                    ).fetchone()
                    if source_row is None:
                        source_rights_current = False
                        break
                    source_payload = self._row(source_row, "source")
                    if (
                        source_payload["state"] != "active"
                        or source_payload["kind"] != kind
                        or not set(vendor.territories).issubset(source_payload["territories"])
                        or "monitoring" not in source_payload["purposes"]
                    ):
                        source_rights_current = False
                        break
                if source_rights_current and payload["destination_ref"].startswith("recipient-"):
                    try:
                        self.resolve_alert_recipient(tenant, payload["destination_ref"])
                    except (ThirdPartyIntelligenceNotFound, ThirdPartyIntelligencePermissionDenied):
                        source_rights_current = False
                if not source_rights_current:
                    payload.update(
                        {
                            "state": "cancelled",
                            "lease_token": None,
                            "lease_until": None,
                            "revision": int(payload["revision"]) + 1,
                        }
                    )
                    digest = _sha256(payload)
                    connection.execute(
                        "UPDATE outbox SET state='cancelled',lease_until=NULL,"
                        "payload_json=?,integrity_sha256=? "
                        "WHERE tenant_id=? AND delivery_id=?",
                        (
                            _canonical(payload).decode("ascii"),
                            digest,
                            tenant,
                            payload["delivery_id"],
                        ),
                    )
                    continue
                lease_token = hashlib.sha256(
                    f"{tenant}:{payload['delivery_id']}:{worker}:{moment}".encode()
                ).hexdigest()
                payload.update(
                    {
                        "state": "leased",
                        "lease_token": lease_token,
                        "lease_until": moment + lease,
                        "revision": int(payload["revision"]) + 1,
                    }
                )
                digest = _sha256(payload)
                connection.execute(
                    "UPDATE outbox SET state='leased',lease_until=?,payload_json=?,"
                    "integrity_sha256=? WHERE tenant_id=? AND delivery_id=?",
                    (
                        payload["lease_until"],
                        _canonical(payload).decode("ascii"),
                        digest,
                        tenant,
                        payload["delivery_id"],
                    ),
                )
                claimed.append(self._outbox_from(payload, digest))
            connection.commit()
        return tuple(claimed)

    def fail_outbox(
        self,
        tenant_id: str,
        delivery_id: str,
        *,
        lease_token: str,
        error_code: str,
        backoff_seconds: float,
        now: float | None = None,
    ) -> OutboxItem:
        tenant = _tenant(tenant_id)
        delivery = _id(delivery_id, "delivery_id")
        token = _digest(lease_token, "lease_token")
        error = _id(error_code, "error_code")
        backoff = _timestamp(backoff_seconds, "backoff_seconds")
        if backoff > _MAX_BACKOFF_SECONDS:
            raise ThirdPartyIntelligenceValidationError("backoff_seconds is too large")
        moment = _timestamp(self._clock() if now is None else now, "now")
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM outbox WHERE tenant_id=? AND delivery_id=?",
                (tenant, delivery),
            ).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("outbox item not found")
            payload = self._row(row, "outbox item")
            if (
                payload["state"] not in {"leased", "dispatching"}
                or not hmac.compare_digest(payload["lease_token"] or "", token)
                or float(payload["lease_until"] or 0) < moment
            ):
                raise ThirdPartyIntelligenceConflict("outbox lease was lost")
            attempt = int(payload["attempt"]) + 1
            retry_state = "dead_letter" if attempt >= int(payload["maximum_attempts"]) else "pending"
            try:
                self.assert_delivery_authority(self._outbox_from(payload, row["integrity_sha256"]))
                if payload["destination_ref"].startswith("recipient-"):
                    self.resolve_alert_recipient(tenant, payload["destination_ref"])
            except (ThirdPartyIntelligencePermissionDenied, ThirdPartyIntelligenceNotFound):
                retry_state = "cancelled"
            payload.update(
                {
                    "state": retry_state,
                    "attempt": attempt,
                    "next_attempt_at": moment + backoff,
                    "lease_token": None,
                    "lease_until": None,
                    "revision": int(payload["revision"]) + 1,
                    "last_error_code": error,
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE outbox SET state=?,next_attempt_at=?,lease_until=NULL,"
                "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND delivery_id=?",
                (
                    payload["state"],
                    payload["next_attempt_at"],
                    _canonical(payload).decode("ascii"),
                    digest,
                    tenant,
                    delivery,
                ),
            )
            connection.commit()
        return self._outbox_from(payload, digest)

    def acknowledge_outbox(
        self,
        tenant_id: str,
        delivery_id: str,
        *,
        lease_token: str,
        now: float | None = None,
    ) -> OutboxItem:
        tenant = _tenant(tenant_id)
        delivery = _id(delivery_id, "delivery_id")
        token = _digest(lease_token, "lease_token")
        moment = _timestamp(self._clock() if now is None else now, "now")
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM outbox WHERE tenant_id=? AND delivery_id=?",
                (tenant, delivery),
            ).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("outbox item not found")
            payload = self._row(row, "outbox item")
            if (
                payload["state"] not in {"leased", "dispatching"}
                or not hmac.compare_digest(payload["lease_token"] or "", token)
                or float(payload["lease_until"] or 0) < moment
            ):
                raise ThirdPartyIntelligenceConflict("outbox lease was lost")
            payload.update(
                {
                    "state": "delivered",
                    "lease_token": None,
                    "lease_until": None,
                    "revision": int(payload["revision"]) + 1,
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE outbox SET state='delivered',lease_until=NULL,payload_json=?,"
                "integrity_sha256=? WHERE tenant_id=? AND delivery_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, delivery),
            )
            connection.commit()
        return self._outbox_from(payload, digest)

    def revoke_monitor(
        self,
        tenant_id: str,
        monitor_id: str,
        *,
        expected_revision: int,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> Monitor:
        tenant = _tenant(tenant_id)
        monitor = _id(monitor_id, "monitor_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        actor = _id(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "revoke_monitor",
            "monitor_id": monitor,
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
                return self.get_monitor(tenant, monitor)
            row = connection.execute(
                "SELECT * FROM monitors WHERE tenant_id=? AND monitor_id=?",
                (tenant, monitor),
            ).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("monitor not found")
            payload = self._row(row, "monitor")
            if int(payload["revision"]) != expected:
                raise ThirdPartyIntelligenceConflict(
                    "monitor expected revision does not match"
                )
            payload.update(
                {"state": "revoked", "revision": expected + 1, "updated_at": moment}
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE monitors SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND monitor_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, monitor),
            )
            alert_rows = connection.execute(
                "SELECT alert_id FROM monitoring_alerts WHERE tenant_id=? AND monitor_id=?",
                (tenant, monitor),
            ).fetchall()
            for alert_row in alert_rows:
                delivery_rows = connection.execute(
                    "SELECT * FROM outbox WHERE tenant_id=? AND alert_id=? "
                    "AND state IN ('pending','leased')",
                    (tenant, alert_row["alert_id"]),
                ).fetchall()
                for delivery_row in delivery_rows:
                    delivery_payload = self._row(delivery_row, "outbox item")
                    delivery_payload.update(
                        {
                            "state": "cancelled",
                            "lease_token": None,
                            "lease_until": None,
                            "revision": int(delivery_payload["revision"]) + 1,
                        }
                    )
                    delivery_digest = _sha256(delivery_payload)
                    connection.execute(
                        "UPDATE outbox SET state='cancelled',lease_until=NULL,"
                        "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND delivery_id=?",
                        (
                            _canonical(delivery_payload).decode("ascii"),
                            delivery_digest,
                            tenant,
                            delivery_payload["delivery_id"],
                        ),
                    )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "monitor", monitor
            )
            self._audit(
                connection, tenant, "vendor_monitor_revoked", monitor, actor, {}, moment
            )
            connection.commit()
        return self.get_monitor(tenant, monitor)

    # -- consent-gated, claim-honest risk exchange ----------------------

    def create_exchange_consent(
        self,
        tenant_id: str,
        *,
        consent_id: str,
        vendor_id: str,
        audience: str,
        purpose: str,
        allowed_metrics: Sequence[str],
        explicit_consent: bool,
        expires_at: float,
        granted_by: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ExchangeConsent:
        tenant = _tenant(tenant_id)
        consent = _id(consent_id, "consent_id")
        vendor = self.get_vendor(tenant, vendor_id)
        audience_value = _id(audience, "audience")
        purpose_value = _id(purpose, "purpose")
        metrics = _closed_list(allowed_metrics, "allowed_metrics", maximum=100)
        if explicit_consent is not True:
            raise ThirdPartyIntelligencePermissionDenied(
                "risk exchange requires explicit affirmative contribution consent"
            )
        expiry = _timestamp(expires_at, "expires_at")
        grantor = _id(granted_by, "granted_by")
        if grantor != vendor.owner_ref:
            raise ThirdPartyIntelligencePermissionDenied(
                "only the governed vendor owner may grant exchange consent"
            )
        moment = _timestamp(self._clock() if now is None else now, "now")
        if not moment < expiry <= moment + 365 * 24 * 60 * 60:
            raise ThirdPartyIntelligenceValidationError(
                "exchange consent expiry must be within one year"
            )
        request = {
            "action": "create_exchange_consent",
            "consent_id": consent,
            "vendor_id": vendor.vendor_id,
            "audience": audience_value,
            "purpose": purpose_value,
            "allowed_metrics": list(metrics),
            "explicit_consent": True,
            "expires_at": expiry,
            "granted_by": grantor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_exchange_consent(tenant, consent)
            if connection.execute(
                "SELECT 1 FROM exchange_consents WHERE tenant_id=? AND consent_id=?",
                (tenant, consent),
            ).fetchone():
                raise ThirdPartyIntelligenceConflict("exchange consent already exists")
            payload = {
                "tenant_id": tenant,
                "consent_id": consent,
                "vendor_id": vendor.vendor_id,
                "audience": audience_value,
                "purpose": purpose_value,
                "allowed_metrics": list(metrics),
                "explicit_consent": True,
                "inclusion_reviewed": False,
                "privacy_reviewed": False,
                "anonymity_proven": False,
                "privacy_review_ref": None,
                "anonymity_proof_ref": None,
                "state": "pending_review",
                "revision": 1,
                "granted_by": grantor,
                "reviewed_by": None,
                "expires_at": expiry,
                "created_at": moment,
                "updated_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO exchange_consents VALUES(?,?,?,?,?)",
                (
                    tenant,
                    consent,
                    vendor.vendor_id,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "exchange_consent",
                consent,
            )
            self._audit(
                connection,
                tenant,
                "exchange_consent_recorded",
                consent,
                grantor,
                {
                    "audience": audience_value,
                    "purpose": purpose_value,
                    "anonymity_proven": False,
                    "privacy_reviewed": False,
                },
                moment,
            )
            connection.commit()
        return self.get_exchange_consent(tenant, consent)

    def get_exchange_consent(
        self, tenant_id: str, consent_id: str
    ) -> ExchangeConsent:
        tenant = _tenant(tenant_id)
        consent = _id(consent_id, "consent_id")
        payload, digest = self._get_payload(
            "exchange_consents", tenant, "consent_id", consent, "exchange consent"
        )
        return self._consent_from(payload, digest)

    def review_exchange_consent(
        self,
        tenant_id: str,
        consent_id: str,
        *,
        inclusion_approved: bool,
        privacy_review_ref: str | None,
        anonymity_proof_ref: str | None,
        expected_revision: int,
        reviewer_ref: str,
        rationale: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ExchangeConsent:
        tenant = _tenant(tenant_id)
        consent = _id(consent_id, "consent_id")
        if not isinstance(inclusion_approved, bool):
            raise ThirdPartyIntelligenceValidationError(
                "inclusion_approved must be boolean"
            )
        privacy_ref = (
            _id(privacy_review_ref, "privacy_review_ref")
            if privacy_review_ref is not None
            else None
        )
        anonymity_ref = (
            _id(anonymity_proof_ref, "anonymity_proof_ref")
            if anonymity_proof_ref is not None
            else None
        )
        if inclusion_approved and privacy_ref is None:
            raise ThirdPartyIntelligencePermissionDenied(
                "approved exchange inclusion requires a privacy review artifact"
            )
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        reviewer = _id(reviewer_ref, "reviewer_ref")
        reason = _text(rationale, "rationale", 2_000)
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "review_exchange_consent",
            "consent_id": consent,
            "inclusion_approved": inclusion_approved,
            "privacy_review_ref": privacy_ref,
            "anonymity_proof_ref": anonymity_ref,
            "expected_revision": expected,
            "reviewer_ref": reviewer,
            "rationale": reason,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_exchange_consent(tenant, consent)
            row = connection.execute(
                "SELECT * FROM exchange_consents WHERE tenant_id=? AND consent_id=?",
                (tenant, consent),
            ).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("exchange consent not found")
            payload = self._row(row, "exchange consent")
            if (
                payload["state"] != "pending_review"
                or int(payload["revision"]) != expected
            ):
                raise ThirdPartyIntelligenceConflict(
                    "exchange consent state or revision does not match"
                )
            if payload["granted_by"] == reviewer:
                raise ThirdPartyIntelligencePermissionDenied(
                    "exchange grantor and inclusion reviewer require different humans"
                )
            payload.update(
                {
                    "inclusion_reviewed": inclusion_approved,
                    "privacy_reviewed": inclusion_approved and privacy_ref is not None,
                    "anonymity_proven": inclusion_approved and anonymity_ref is not None,
                    "privacy_review_ref": privacy_ref if inclusion_approved else None,
                    "anonymity_proof_ref": anonymity_ref if inclusion_approved else None,
                    "state": "active" if inclusion_approved else "rejected",
                    "revision": expected + 1,
                    "reviewed_by": reviewer,
                    "updated_at": moment,
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE exchange_consents SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND consent_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, consent),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "exchange_consent",
                consent,
            )
            self._audit(
                connection,
                tenant,
                "exchange_consent_reviewed",
                consent,
                reviewer,
                {
                    "inclusion_reviewed": payload["inclusion_reviewed"],
                    "privacy_reviewed": payload["privacy_reviewed"],
                    "anonymity_proven": payload["anonymity_proven"],
                    "rationale_sha256": _sha256(reason),
                },
                moment,
            )
            connection.commit()
        return self.get_exchange_consent(tenant, consent)

    def _validate_exchange_lineage(
        self,
        tenant: str,
        vendor: VendorProfile,
        lineage_refs: Sequence[str],
        now: float,
    ) -> tuple[str, ...]:
        refs = _closed_list(lineage_refs, "lineage_refs", maximum=100)
        for ref in refs:
            if ":" not in ref:
                raise ThirdPartyIntelligenceValidationError(
                    "lineage refs require an exact object-kind prefix"
                )
            kind, object_id = ref.split(":", 1)
            if kind == "snapshot":
                snapshot = self.get_source_snapshot(tenant, object_id)
                source = self.get_source(tenant, snapshot.source_id)
                self._validated_snapshot_binding(
                    tenant,
                    snapshot.snapshot_id,
                    expected_kind=source.kind,
                    purpose="exchange",
                    vendor=vendor,
                    now=now,
                )
            elif kind == "finding":
                finding = self.get_finding(tenant, object_id)
                if finding.vendor_id != vendor.vendor_id:
                    raise ThirdPartyIntelligencePermissionDenied(
                        "exchange lineage belongs to another vendor"
                    )
                source = self.get_source(tenant, finding.source_id)
                if source.state != "active" or "exchange" not in source.purposes:
                    raise ThirdPartyIntelligencePermissionDenied(
                        "finding source rights do not permit exchange"
                    )
            elif kind == "decision":
                decision = self.get_risk_decision(tenant, object_id)
                if decision.vendor_id != vendor.vendor_id:
                    raise ThirdPartyIntelligencePermissionDenied(
                        "exchange lineage belongs to another vendor"
                    )
            elif kind == "alert":
                alert = self.get_monitoring_alert(tenant, object_id)
                if alert.vendor_id != vendor.vendor_id:
                    raise ThirdPartyIntelligencePermissionDenied(
                        "exchange lineage belongs to another vendor"
                    )
            else:
                raise ThirdPartyIntelligenceValidationError(
                    "exchange lineage object kind is closed"
                )
        return refs

    def contribute_exchange(
        self,
        tenant_id: str,
        consent_id: str,
        *,
        contribution_id: str,
        metric_id: str,
        value_band: str,
        audience: str,
        purpose: str,
        evidence_sha256: str,
        lineage_refs: Sequence[str],
        retention_seconds: int,
        contributed_by: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ExchangeContribution:
        tenant = _tenant(tenant_id)
        consent = self.get_exchange_consent(tenant, consent_id)
        contribution = _id(contribution_id, "contribution_id")
        metric = _id(metric_id, "metric_id")
        band = _id(value_band, "value_band")
        audience_value = _id(audience, "audience")
        purpose_value = _id(purpose, "purpose")
        evidence = _digest(evidence_sha256, "evidence_sha256")
        retention = _retention(retention_seconds)
        actor = _id(contributed_by, "contributed_by")
        moment = _timestamp(self._clock() if now is None else now, "now")
        if (
            consent.state != "active"
            or not consent.explicit_consent
            or not consent.inclusion_reviewed
            or not consent.privacy_reviewed
            or consent.expires_at <= moment
        ):
            raise ThirdPartyIntelligencePermissionDenied(
                "exchange consent is not active, reviewed, and unexpired"
            )
        if audience_value != consent.audience or purpose_value != consent.purpose:
            raise ThirdPartyIntelligencePermissionDenied(
                "exchange audience or purpose exceeds consent"
            )
        if metric not in consent.allowed_metrics:
            raise ThirdPartyIntelligencePermissionDenied(
                "exchange metric exceeds consent"
            )
        vendor = self.get_vendor(tenant, consent.vendor_id)
        lineage = self._validate_exchange_lineage(
            tenant, vendor, lineage_refs, moment
        )
        request = {
            "action": "contribute_exchange",
            "consent_id": consent.consent_id,
            "contribution_id": contribution,
            "metric_id": metric,
            "value_band": band,
            "audience": audience_value,
            "purpose": purpose_value,
            "evidence_sha256": evidence,
            "lineage_refs": list(lineage),
            "retention_seconds": retention,
            "contributed_by": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_exchange_contribution(tenant, contribution)
            if connection.execute(
                "SELECT 1 FROM exchange_contributions WHERE tenant_id=? "
                "AND contribution_id=?",
                (tenant, contribution),
            ).fetchone():
                raise ThirdPartyIntelligenceConflict(
                    "exchange contribution already exists"
                )
            payload = {
                "tenant_id": tenant,
                "contribution_id": contribution,
                "consent_id": consent.consent_id,
                "metric_id": metric,
                "value_band": band,
                "audience": audience_value,
                "purpose": purpose_value,
                "anonymous": consent.anonymity_proven,
                "privacy_reviewed": consent.privacy_reviewed,
                "evidence_sha256": evidence,
                "lineage_refs": list(lineage),
                "state": "active",
                "retained_until": min(moment + retention, consent.expires_at),
                "contributed_by": actor,
                "created_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO exchange_contributions VALUES(?,?,?,?,?)",
                (
                    tenant,
                    contribution,
                    consent.consent_id,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "exchange_contribution",
                contribution,
            )
            self._audit(
                connection,
                tenant,
                "exchange_contribution_recorded",
                contribution,
                actor,
                {
                    "audience": audience_value,
                    "purpose": purpose_value,
                    "anonymous": consent.anonymity_proven,
                    "privacy_reviewed": consent.privacy_reviewed,
                    "evidence_sha256": evidence,
                },
                moment,
            )
            connection.commit()
        return self.get_exchange_contribution(tenant, contribution)

    def get_exchange_contribution(
        self, tenant_id: str, contribution_id: str
    ) -> ExchangeContribution:
        tenant = _tenant(tenant_id)
        contribution = _id(contribution_id, "contribution_id")
        payload, digest = self._get_payload(
            "exchange_contributions",
            tenant,
            "contribution_id",
            contribution,
            "exchange contribution",
        )
        return self._contribution_from(payload, digest)

    def query_exchange(
        self,
        tenant_id: str,
        *,
        audience: str,
        purpose: str,
        metric_id: str,
        principal_ref: str,
        limit: int = 100,
        now: float | None = None,
    ) -> tuple[ExchangeContribution, ...]:
        """Return only active, purpose-bound records; vendor identities are absent."""

        tenant = _tenant(tenant_id)
        audience_value = _id(audience, "audience")
        purpose_value = _id(purpose, "purpose")
        metric = _id(metric_id, "metric_id")
        principal = _id(principal_ref, "principal_ref")
        if principal != audience_value:
            raise ThirdPartyIntelligencePermissionDenied(
                "query principal does not match the consent-bound audience"
            )
        limit_value = _integer(limit, "limit", 1, 500)
        moment = _timestamp(self._clock() if now is None else now, "now")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM exchange_contributions WHERE tenant_id=? "
                "ORDER BY contribution_id LIMIT ?",
                (tenant, _MAX_LIST),
            ).fetchall()
        result: list[ExchangeContribution] = []
        for row in rows:
            contribution = self._contribution_from(
                self._row(row, "exchange contribution"), row["integrity_sha256"]
            )
            if (
                contribution.state != "active"
                or contribution.audience != audience_value
                or contribution.purpose != purpose_value
                or contribution.metric_id != metric
                or contribution.retained_until <= moment
            ):
                continue
            consent = self.get_exchange_consent(tenant, contribution.consent_id)
            if consent.state != "active" or consent.expires_at <= moment:
                continue
            vendor = self.get_vendor(tenant, consent.vendor_id)
            try:
                self._validate_exchange_lineage(
                    tenant, vendor, contribution.lineage_refs, moment
                )
            except (
                ThirdPartyIntelligenceNotFound,
                ThirdPartyIntelligencePermissionDenied,
            ):
                continue
            result.append(contribution)
        return tuple(result[:limit_value])

    def withdraw_exchange_consent(
        self,
        tenant_id: str,
        consent_id: str,
        *,
        expected_revision: int,
        actor_ref: str,
        rationale: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ExchangeConsent:
        tenant = _tenant(tenant_id)
        consent = _id(consent_id, "consent_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        actor = _id(actor_ref, "actor_ref")
        reason = _text(rationale, "rationale", 2_000)
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "withdraw_exchange_consent",
            "consent_id": consent,
            "expected_revision": expected,
            "actor_ref": actor,
            "rationale": reason,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_exchange_consent(tenant, consent)
            row = connection.execute(
                "SELECT * FROM exchange_consents WHERE tenant_id=? AND consent_id=?",
                (tenant, consent),
            ).fetchone()
            if row is None:
                raise ThirdPartyIntelligenceNotFound("exchange consent not found")
            payload = self._row(row, "exchange consent")
            if int(payload["revision"]) != expected:
                raise ThirdPartyIntelligenceConflict(
                    "exchange consent expected revision does not match"
                )
            payload.update(
                {"state": "withdrawn", "revision": expected + 1, "updated_at": moment}
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE exchange_consents SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND consent_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, consent),
            )
            rows = connection.execute(
                "SELECT * FROM exchange_contributions WHERE tenant_id=? AND consent_id=?",
                (tenant, consent),
            ).fetchall()
            for contribution_row in rows:
                contribution_payload = self._row(
                    contribution_row, "exchange contribution"
                )
                contribution_payload["state"] = "withdrawn"
                contribution_digest = _sha256(contribution_payload)
                connection.execute(
                    "UPDATE exchange_contributions SET payload_json=?,"
                    "integrity_sha256=? WHERE tenant_id=? AND contribution_id=?",
                    (
                        _canonical(contribution_payload).decode("ascii"),
                        contribution_digest,
                        tenant,
                        contribution_payload["contribution_id"],
                    ),
                )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "exchange_consent",
                consent,
            )
            self._audit(
                connection,
                tenant,
                "exchange_consent_withdrawn",
                consent,
                actor,
                {
                    "withdrawn_contributions": len(rows),
                    "rationale_sha256": _sha256(reason),
                },
                moment,
            )
            connection.commit()
        return self.get_exchange_consent(tenant, consent)

    # -- retention and integrity ----------------------------------------

    def purge_expired(
        self,
        tenant_id: str,
        *,
        actor_ref: str,
        now: float | None = None,
    ) -> Mapping[str, int]:
        tenant = _tenant(tenant_id)
        actor = _id(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        counts = {"source_snapshots": 0, "exchange_contributions": 0}
        with authority_effect_fence(), self._connect() as connection:
            self._begin(connection)
            snapshot_rows = connection.execute(
                "SELECT * FROM source_snapshots WHERE tenant_id=?", (tenant,)
            ).fetchall()
            for row in snapshot_rows:
                payload = self._row(row, "source snapshot")
                if float(payload["retained_until"]) <= moment:
                    counts["source_snapshots"] += connection.execute(
                        "DELETE FROM source_snapshots WHERE tenant_id=? AND snapshot_id=?",
                        (tenant, payload["snapshot_id"]),
                    ).rowcount
            contribution_rows = connection.execute(
                "SELECT * FROM exchange_contributions WHERE tenant_id=?", (tenant,)
            ).fetchall()
            for row in contribution_rows:
                payload = self._row(row, "exchange contribution")
                if float(payload["retained_until"]) <= moment:
                    counts["exchange_contributions"] += connection.execute(
                        "DELETE FROM exchange_contributions WHERE tenant_id=? "
                        "AND contribution_id=?",
                        (tenant, payload["contribution_id"]),
                    ).rowcount
            self._audit(
                connection,
                tenant,
                "intelligence_retention_purged",
                "retention",
                actor,
                counts,
                moment,
            )
            connection.commit()
        return counts

    def verify_integrity(self, tenant_id: str) -> IntegrityVerification:
        tenant = _tenant(tenant_id)
        tables = (
            ("sources", "source"),
            ("source_snapshots", "source snapshot"),
            ("vendors", "vendor"),
            ("relationships", "relationship"),
            ("screening_runs", "screening run"),
            ("findings", "screening finding"),
            ("risk_policies", "risk policy"),
            ("risk_decisions", "risk decision"),
            ("edd_cases", "EDD case"),
            ("monitors", "monitor"),
            ("monitoring_alerts", "monitoring alert"),
            ("outbox", "outbox item"),
            ("alert_recipients", "alert recipient"),
            ("exchange_consents", "exchange consent"),
            ("exchange_contributions", "exchange contribution"),
        )
        verified = 0
        with self._connect() as connection:
            for table, label in tables:
                rows = connection.execute(
                    f"SELECT * FROM {table} WHERE tenant_id=?",  # noqa: S608
                    (tenant,),
                ).fetchall()
                for row in rows:
                    self._row(row, label)
                    if table == "alert_recipients":
                        self._recipient_record(row)
                    verified += 1
            operation_rows = connection.execute(
                "SELECT * FROM operations WHERE tenant_id=?", (tenant,)
            ).fetchall()
            for row in operation_rows:
                operation_payload = {
                    "tenant_id": row["tenant_id"],
                    "operation_sha256": row["operation_sha256"],
                    "request_sha256": row["request_sha256"],
                    "result_kind": row["result_kind"],
                    "result_id": row["result_id"],
                }
                if _sha256(operation_payload) != row["integrity_sha256"]:
                    raise ThirdPartyIntelligenceIntegrityError(
                        "persisted idempotency binding failed integrity verification"
                    )
                verified += 1
            audit_rows = connection.execute(
                "SELECT * FROM audit_events WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
        previous = "0" * 64
        expected_sequence = 1
        for row in audit_rows:
            payload = self._row(row, "audit event")
            if (
                int(payload["sequence"]) != expected_sequence
                or payload["previous_sha256"] != previous
            ):
                raise ThirdPartyIntelligenceIntegrityError(
                    "audit chain continuity failed"
                )
            previous = row["integrity_sha256"]
            expected_sequence += 1
        return IntegrityVerification(
            tenant_id=tenant,
            verified_records=verified,
            audit_events=len(audit_rows),
            terminal_audit_sha256=previous,
        )


__all__ = [
    "Citation",
    "EDDCase",
    "ExchangeConsent",
    "ExchangeContribution",
    "IntegrityVerification",
    "IntelligenceSource",
    "MANDATORY_AUTOAPPROVAL_KINDS",
    "MANDATORY_REVIEW_KINDS",
    "Monitor",
    "MonitoringAlert",
    "MonitoringResult",
    "OutboxItem",
    "RiskDecision",
    "RiskPolicy",
    "SOURCE_KINDS",
    "ScreeningFinding",
    "ScreeningRun",
    "SourceSnapshot",
    "ThirdPartyIntelligenceConfigError",
    "ThirdPartyIntelligenceConflict",
    "ThirdPartyIntelligenceError",
    "ThirdPartyIntelligenceIntegrityError",
    "ThirdPartyIntelligenceNotFound",
    "ThirdPartyIntelligencePermissionDenied",
    "ThirdPartyIntelligenceStore",
    "ThirdPartyIntelligenceValidationError",
    "VendorProfile",
    "VendorRelationship",
    "enabled",
    "require_enabled",
]
