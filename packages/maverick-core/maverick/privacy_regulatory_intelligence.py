"""Licensed, evidence-grounded privacy regulatory intelligence authority.

The module is a provider-neutral control plane.  It does not bundle a legal
corpus, scrape publishers, or claim equivalence to any proprietary research
service.  Deployments enroll content only after recording its provenance,
license and permitted uses, and a second human approves the source.

The capability is closed unless both exact configuration gates are true::

    [privacy_automation]
    enable = true
    [privacy_automation.regulatory_intelligence]
    enable = true

Research is deliberately extractive and evidence-bound.  It returns short
excerpts and citations from approved material or explicitly abstains; it never
invents legal conclusions and every answer carries a legal-advice disclaimer.
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
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
SOURCE_SCHEMA = "lightwork.privacy-regulatory-source.v1"
DOCUMENT_SCHEMA = "lightwork.privacy-regulatory-document.v1"
COLLECTION_SCHEMA = "lightwork.privacy-regulatory-collection.v1"
SHARE_SCHEMA = "lightwork.privacy-regulatory-share.v1"
SUBSCRIPTION_SCHEMA = "lightwork.privacy-regulatory-subscription.v1"
ALERT_SCHEMA = "lightwork.privacy-regulatory-alert.v1"
OUTBOX_SCHEMA = "lightwork.privacy-regulatory-outbox.v1"
REPORT_SCHEMA = "lightwork.privacy-regulatory-report.v1"
AUDIT_SCHEMA = "lightwork.privacy-regulatory-audit.v1"

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_LANGUAGE_RE = re.compile(r"[a-z]{2,3}(?:-[A-Z]{2})?\Z")
_JURISDICTION_RE = re.compile(r"[A-Z][A-Z0-9-]{1,31}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_TOKEN_RE = re.compile(r"[^\W_]{2,}", re.UNICODE)

_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_CONTENT_BYTES = 512 * 1024
_MAX_QUERY_BYTES = 2_048
_MAX_REPORT_BYTES = 2 * 1024 * 1024
_MAX_LIST = 1_000
_MAX_SEARCH_RESULTS = 100
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 60 * 60
_MIN_RETENTION_SECONDS = 24 * 60 * 60
_MAX_LEASE_SECONDS = 60 * 60
_MAX_BACKOFF_SECONDS = 7 * 24 * 60 * 60

_ALLOWED_USES = frozenset(
    {"search", "research", "compare", "alerts", "reports", "share"}
)
_SOURCE_STATES = frozenset({"pending", "active", "rejected", "revoked"})
_DOCUMENT_TYPES = frozenset(
    {
        "authority_guidance",
        "case_law",
        "enforcement_action",
        "law",
        "regulation",
        "regulatory_update",
        "standard",
    }
)
_COLLECTION_ROLES = frozenset({"viewer", "editor", "owner"})
_SHARE_SCOPES = frozenset({"view", "export"})
_OUTBOX_STATES = frozenset({"pending", "leased", "delivered", "cancelled", "dead_letter"})


class PrivacyRegulatoryIntelligenceError(RuntimeError):
    """Base error for the regulatory-intelligence authority."""


class PrivacyRegulatoryIntelligenceConfigError(PrivacyRegulatoryIntelligenceError):
    """The capability is not explicitly enabled."""


class PrivacyRegulatoryIntelligenceValidationError(
    PrivacyRegulatoryIntelligenceError, ValueError
):
    """Input is outside the closed authority contract."""


class PrivacyRegulatoryIntelligenceConflict(PrivacyRegulatoryIntelligenceError):
    """A CAS, idempotency, lease, or state precondition failed."""


class PrivacyRegulatoryIntelligenceNotFound(PrivacyRegulatoryIntelligenceError):
    """A tenant-scoped object is absent or unavailable to the caller."""


class PrivacyRegulatoryIntelligencePermissionDenied(
    PrivacyRegulatoryIntelligenceError
):
    """The source rights or collection ACL does not permit an operation."""


class PrivacyRegulatoryIntelligenceIntegrityError(
    PrivacyRegulatoryIntelligenceError
):
    """Persisted content or its audit chain failed verification."""


def enabled() -> bool:
    """Return true only for the exact parent and child configuration gates."""

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
    intelligence = (
        privacy.get("regulatory_intelligence") if isinstance(privacy, Mapping) else None
    )
    return (
        isinstance(privacy, Mapping)
        and privacy.get("enable") is True
        and isinstance(intelligence, Mapping)
        and intelligence.get("enable") is True
    )


def require_enabled() -> None:
    """Fail closed unless the regulatory-intelligence gate is explicit."""

    if not enabled():
        raise PrivacyRegulatoryIntelligenceConfigError(
            "privacy regulatory intelligence is disabled; explicitly enable "
            "privacy_automation and privacy_automation.regulatory_intelligence"
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
        raise PrivacyRegulatoryIntelligenceValidationError(
            "regulatory intelligence data must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise PrivacyRegulatoryIntelligenceValidationError(
            "regulatory intelligence data exceeds its canonical byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise PrivacyRegulatoryIntelligenceValidationError(
            "tenant_id is invalid"
        ) from exc


def _identifier(
    value: object,
    label: str,
    pattern: re.Pattern[str] = _ID_RE,
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PrivacyRegulatoryIntelligenceValidationError(
            f"{label} must be a bounded opaque identifier"
        )
    return value


def _text(value: object, label: str, maximum: int, *, minimum: int = 1) -> str:
    if not isinstance(value, str):
        raise PrivacyRegulatoryIntelligenceValidationError(f"{label} must be text")
    normalized = value.strip()
    if _CONTROL_RE.search(normalized):
        raise PrivacyRegulatoryIntelligenceValidationError(
            f"{label} contains unsupported control characters"
        )
    length = len(normalized.encode("utf-8"))
    if not minimum <= length <= maximum:
        raise PrivacyRegulatoryIntelligenceValidationError(
            f"{label} must contain between {minimum} and {maximum} UTF-8 bytes"
        )
    return normalized


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise PrivacyRegulatoryIntelligenceValidationError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _positive_int(value: object, label: str, maximum: int = 2**31 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise PrivacyRegulatoryIntelligenceValidationError(
            f"{label} must be an integer between 1 and {maximum}"
        )
    return value


def _nonnegative_int(value: object, label: str, maximum: int = 2**31 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise PrivacyRegulatoryIntelligenceValidationError(
            f"{label} must be an integer between 0 and {maximum}"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise PrivacyRegulatoryIntelligenceValidationError(
            f"{label} must be a positive finite timestamp"
        )
    return float(value)


def _retention(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not _MIN_RETENTION_SECONDS <= value <= _MAX_RETENTION_SECONDS
    ):
        raise PrivacyRegulatoryIntelligenceValidationError(
            "retention_seconds is outside the bounded retention window"
        )
    return value


def _iso_date(value: object, label: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise PrivacyRegulatoryIntelligenceValidationError(
            f"{label} must be an ISO date"
        )
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise PrivacyRegulatoryIntelligenceValidationError(
            f"{label} must be an ISO date"
        ) from exc
    return parsed.isoformat()


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
        raise PrivacyRegulatoryIntelligenceValidationError(
            f"{label} must be a credential-free HTTPS URI"
        )
    return uri


def _closed_ids(
    values: Sequence[str],
    label: str,
    *,
    maximum: int = 100,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise PrivacyRegulatoryIntelligenceValidationError(f"{label} must be a list")
    if not 1 <= len(values) <= maximum:
        raise PrivacyRegulatoryIntelligenceValidationError(
            f"{label} must contain between 1 and {maximum} values"
        )
    normalized = tuple(_identifier(item, label) for item in values)
    if len(set(normalized)) != len(normalized):
        raise PrivacyRegulatoryIntelligenceValidationError(
            f"{label} contains duplicates"
        )
    return tuple(sorted(normalized))


def _jurisdictions(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise PrivacyRegulatoryIntelligenceValidationError(
            "jurisdictions must be a list"
        )
    if not 1 <= len(values) <= 100:
        raise PrivacyRegulatoryIntelligenceValidationError(
            "jurisdictions must contain between 1 and 100 values"
        )
    output: list[str] = []
    for value in values:
        if not isinstance(value, str) or not _JURISDICTION_RE.fullmatch(value):
            raise PrivacyRegulatoryIntelligenceValidationError(
                "jurisdiction must be an uppercase bounded identifier"
            )
        output.append(value)
    if len(set(output)) != len(output):
        raise PrivacyRegulatoryIntelligenceValidationError(
            "jurisdictions contain duplicates"
        )
    return tuple(sorted(output))


def _language(value: object) -> str:
    if not isinstance(value, str) or not _LANGUAGE_RE.fullmatch(value):
        raise PrivacyRegulatoryIntelligenceValidationError(
            "language must be a bounded BCP-47 language tag"
        )
    return value


def _query(value: object) -> str:
    query = _text(value, "query", _MAX_QUERY_BYTES)
    if not _query_tokens(query):
        raise PrivacyRegulatoryIntelligenceValidationError(
            "query must contain at least one searchable token"
        )
    return query


def _query_tokens(value: str) -> tuple[str, ...]:
    return tuple(sorted(set(token.casefold() for token in _TOKEN_RE.findall(value))))


def _content(value: object) -> str:
    if not isinstance(value, str):
        raise PrivacyRegulatoryIntelligenceValidationError("content must be text")
    if _CONTROL_RE.search(value):
        raise PrivacyRegulatoryIntelligenceValidationError(
            "content contains unsupported control characters"
        )
    length = len(value.encode("utf-8"))
    if not 1 <= length <= _MAX_CONTENT_BYTES:
        raise PrivacyRegulatoryIntelligenceValidationError(
            "content exceeds the licensed document byte bound"
        )
    return value


def _content_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Citation:
    citation_id: str
    title: str
    uri: str
    pinpoint: str

    @classmethod
    def validated(cls, value: Mapping[str, object]) -> Citation:
        if not isinstance(value, Mapping) or set(value) != {
            "citation_id",
            "title",
            "uri",
            "pinpoint",
        }:
            raise PrivacyRegulatoryIntelligenceValidationError(
                "citation has an unsupported schema"
            )
        return cls(
            citation_id=_identifier(value["citation_id"], "citation_id"),
            title=_text(value["title"], "citation title", 500),
            uri=_https_uri(value["uri"], "citation uri"),
            pinpoint=_text(value["pinpoint"], "citation pinpoint", 500),
        )


def _citations(values: Sequence[Mapping[str, object]]) -> tuple[Citation, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise PrivacyRegulatoryIntelligenceValidationError("citations must be a list")
    if not 1 <= len(values) <= 100:
        raise PrivacyRegulatoryIntelligenceValidationError(
            "citations must contain between 1 and 100 values"
        )
    result = tuple(Citation.validated(value) for value in values)
    ids = [citation.citation_id for citation in result]
    if len(ids) != len(set(ids)):
        raise PrivacyRegulatoryIntelligenceValidationError(
            "citation identifiers must be unique"
        )
    return result


@dataclass(frozen=True)
class RegulatorySource:
    tenant_id: str
    source_id: str
    name: str
    license_ref: str
    rights_basis: str
    allowed_uses: tuple[str, ...]
    provenance_uri: str
    jurisdictions: tuple[str, ...]
    authorities: tuple[str, ...]
    document_types: tuple[str, ...]
    languages: tuple[str, ...]
    retention_seconds: int
    state: str
    revision: int
    enrolled_by: str
    approved_by: str | None
    approval_rationale: str | None
    enrolled_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class RegulatoryDocument:
    tenant_id: str
    document_id: str
    version: int
    source_id: str
    title: str
    jurisdiction: str
    authority: str
    document_type: str
    language: str
    publication_date: str
    effective_date: str | None
    superseded_date: str | None
    citations: tuple[Citation, ...]
    content_sha256: str
    supersedes_version: int | None
    retain_until: float
    ingested_by: str
    ingested_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class SearchHit:
    document_id: str
    version: int
    source_id: str
    title: str
    jurisdiction: str
    authority: str
    document_type: str
    publication_date: str
    effective_date: str | None
    score: int
    excerpt: str
    content_sha256: str
    evidence_sha256: str
    citations: tuple[Citation, ...]
    # True when ``effective_date`` is later than the date searched. ``None``
    # only on a hit read back from a report stored before the flag existed.
    not_yet_effective: bool | None = None


def _hit_payload(hit: SearchHit) -> dict[str, Any]:
    values = asdict(hit)
    values["citations"] = [asdict(citation) for citation in hit.citations]
    if values["not_yet_effective"] is None:
        # Keep a report stored before the flag existed byte-identical.
        del values["not_yet_effective"]
    return values


@dataclass(frozen=True)
class ResearchAnswer:
    query: str
    status: str
    answer: str
    evidence: tuple[SearchHit, ...]
    citations: tuple[Citation, ...]
    disclaimer: str
    evidence_sha256: str
    # True when the answer is grounded only in law that is not yet in effect.
    not_yet_effective: bool = False

    @property
    def abstained(self) -> bool:
        return self.status == "abstained"


@dataclass(frozen=True)
class JurisdictionComparison:
    query: str
    jurisdictions: tuple[str, ...]
    answers: Mapping[str, ResearchAnswer]
    evidence_sha256: str


@dataclass(frozen=True)
class ResearchCollection:
    tenant_id: str
    collection_id: str
    title: str
    description: str
    owner_ref: str
    acl: Mapping[str, str]
    items: tuple[tuple[str, int], ...]
    jurisdictions: tuple[str, ...]
    revision: int
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class CapabilityShare:
    tenant_id: str
    share_id: str
    collection_id: str
    scopes: tuple[str, ...]
    expires_at: float
    state: str
    created_by: str
    created_at: float
    token: str | None
    integrity_sha256: str


@dataclass(frozen=True)
class SavedQuery:
    tenant_id: str
    subscription_id: str
    query: str
    jurisdictions: tuple[str, ...]
    principal_ref: str
    destination_ref: str
    cadence_seconds: int
    next_run_at: float
    state: str
    revision: int
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class RegulatoryAlert:
    tenant_id: str
    alert_id: str
    subscription_id: str
    document_id: str
    document_version: int
    jurisdiction: str
    evidence_sha256: str
    created_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class DeliveryItem:
    tenant_id: str
    delivery_id: str
    alert_id: str
    subscription_id: str
    destination_ref: str
    state: str
    attempt: int
    max_attempts: int
    next_attempt_at: float
    lease_token: str | None
    lease_until: float | None
    revision: int
    last_error_code: str | None
    integrity_sha256: str


@dataclass(frozen=True)
class EvidenceReport:
    tenant_id: str
    report_id: str
    query: str
    jurisdictions: tuple[str, ...]
    status: str
    evidence: tuple[SearchHit, ...]
    citations: tuple[Citation, ...]
    disclaimer: str
    created_by: str
    created_at: float
    retain_until: float
    integrity_sha256: str

    def export(self) -> dict[str, object]:
        """Return a canonical, evidence-backed and content-minimised report."""

        return {
            "schema": REPORT_SCHEMA,
            "tenant_id": self.tenant_id,
            "report_id": self.report_id,
            "query": self.query,
            "jurisdictions": list(self.jurisdictions),
            "status": self.status,
            "evidence": [_hit_payload(hit) for hit in self.evidence],
            "citations": [asdict(citation) for citation in self.citations],
            "disclaimer": self.disclaimer,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "retain_until": self.retain_until,
            "integrity_sha256": self.integrity_sha256,
        }


@dataclass(frozen=True)
class IntegrityVerification:
    tenant_id: str
    verified_records: int
    audit_events: int
    terminal_audit_sha256: str


_DISCLAIMER = (
    "This is corpus-grounded research evidence, not legal advice. A qualified "
    "human must verify the cited primary materials before relying on it."
)


class PrivacyRegulatoryIntelligenceStore:
    """Private durable authority for a tenant's licensed research corpus."""

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
                CREATE TABLE IF NOT EXISTS documents(
                    tenant_id TEXT NOT NULL,
                    document_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    source_id TEXT NOT NULL,
                    content_text TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, document_id, version),
                    FOREIGN KEY(tenant_id, source_id)
                        REFERENCES sources(tenant_id, source_id)
                );
                CREATE INDEX IF NOT EXISTS documents_current
                    ON documents(tenant_id, document_id, version DESC);
                CREATE TABLE IF NOT EXISTS collections(
                    tenant_id TEXT NOT NULL,
                    collection_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, collection_id)
                );
                CREATE TABLE IF NOT EXISTS shares(
                    share_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    collection_id TEXT NOT NULL,
                    token_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    UNIQUE(token_sha256),
                    FOREIGN KEY(tenant_id, collection_id)
                        REFERENCES collections(tenant_id, collection_id)
                );
                CREATE TABLE IF NOT EXISTS subscriptions(
                    tenant_id TEXT NOT NULL,
                    subscription_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, subscription_id)
                );
                CREATE TABLE IF NOT EXISTS alerts(
                    tenant_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    subscription_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, alert_id),
                    FOREIGN KEY(tenant_id, subscription_id)
                        REFERENCES subscriptions(tenant_id, subscription_id)
                );
                CREATE TABLE IF NOT EXISTS outbox(
                    tenant_id TEXT NOT NULL,
                    delivery_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    subscription_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(
                        state IN ('pending','leased','delivered','cancelled','dead_letter')
                    ),
                    next_attempt_at REAL NOT NULL,
                    lease_until REAL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, delivery_id),
                    FOREIGN KEY(tenant_id, alert_id)
                        REFERENCES alerts(tenant_id, alert_id)
                );
                CREATE INDEX IF NOT EXISTS outbox_claim
                    ON outbox(tenant_id, state, next_attempt_at, lease_until);
                CREATE TABLE IF NOT EXISTS reports(
                    tenant_id TEXT NOT NULL,
                    report_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, report_id)
                );
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
                    VALUES('schema_version','1');
                COMMIT;
                """
            )
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if version is None or version["value"] != str(SCHEMA_VERSION):
                raise PrivacyRegulatoryIntelligenceIntegrityError(
                    "regulatory intelligence database schema is unsupported"
                )
        ensure_private_file(self.path)

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _row_payload(row: sqlite3.Row, label: str) -> dict[str, Any]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise PrivacyRegulatoryIntelligenceIntegrityError(
                f"persisted {label} is not canonical JSON"
            ) from exc
        if not isinstance(payload, dict) or _sha256(payload) != row["integrity_sha256"]:
            raise PrivacyRegulatoryIntelligenceIntegrityError(
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
        key = _identifier(idempotency_key, "idempotency_key", _IDEMPOTENCY_RE)
        operation_sha = hashlib.sha256(key.encode("utf-8")).hexdigest()
        request_sha = _sha256(dict(request))
        row = connection.execute(
            "SELECT * FROM operations WHERE tenant_id=? AND operation_sha256=?",
            (tenant_id, operation_sha),
        ).fetchone()
        if row is not None and row["request_sha256"] != request_sha:
            raise PrivacyRegulatoryIntelligenceConflict(
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
        connection.execute(
            "INSERT INTO operations VALUES(?,?,?,?,?)",
            (
                tenant_id,
                hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest(),
                request_sha256,
                result_kind,
                result_id,
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
        action_id = _identifier(action, "audit action")
        actor = _identifier(actor_ref, "actor_ref")
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM audit_events "
            "WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = "0" * 64 if previous is None else previous["integrity_sha256"]
        payload = {
            "schema": AUDIT_SCHEMA,
            "tenant_id": tenant_id,
            "sequence": sequence,
            "action": action_id,
            "subject_sha256": hashlib.sha256(subject.encode("utf-8")).hexdigest(),
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
    def _source_from(payload: Mapping[str, Any], digest: str) -> RegulatorySource:
        values = dict(payload)
        values.pop("schema", None)
        for label in (
            "allowed_uses",
            "jurisdictions",
            "authorities",
            "document_types",
            "languages",
        ):
            values[label] = tuple(values[label])
        return RegulatorySource(**values, integrity_sha256=digest)

    @staticmethod
    def _document_from(
        payload: Mapping[str, Any], digest: str
    ) -> RegulatoryDocument:
        values = dict(payload)
        values.pop("schema", None)
        values["citations"] = tuple(Citation(**item) for item in values["citations"])
        return RegulatoryDocument(**values, integrity_sha256=digest)

    @staticmethod
    def _collection_from(
        payload: Mapping[str, Any], digest: str
    ) -> ResearchCollection:
        values = dict(payload)
        values.pop("schema", None)
        values["acl"] = dict(values["acl"])
        values["items"] = tuple((item[0], int(item[1])) for item in values["items"])
        values["jurisdictions"] = tuple(values["jurisdictions"])
        return ResearchCollection(**values, integrity_sha256=digest)

    @staticmethod
    def _share_from(
        payload: Mapping[str, Any], digest: str, *, token: str | None = None
    ) -> CapabilityShare:
        values = dict(payload)
        values.pop("schema", None)
        values.pop("token_sha256", None)
        values["scopes"] = tuple(values["scopes"])
        return CapabilityShare(**values, token=token, integrity_sha256=digest)

    @staticmethod
    def _subscription_from(payload: Mapping[str, Any], digest: str) -> SavedQuery:
        values = dict(payload)
        values.pop("schema", None)
        values["jurisdictions"] = tuple(values["jurisdictions"])
        return SavedQuery(**values, integrity_sha256=digest)

    @staticmethod
    def _alert_from(payload: Mapping[str, Any], digest: str) -> RegulatoryAlert:
        values = dict(payload)
        values.pop("schema", None)
        return RegulatoryAlert(**values, integrity_sha256=digest)

    @staticmethod
    def _delivery_from(payload: Mapping[str, Any], digest: str) -> DeliveryItem:
        values = dict(payload)
        values.pop("schema", None)
        return DeliveryItem(**values, integrity_sha256=digest)

    @staticmethod
    def _hit_from(value: Mapping[str, Any]) -> SearchHit:
        values = dict(value)
        values["citations"] = tuple(Citation(**item) for item in values["citations"])
        return SearchHit(**values)

    @classmethod
    def _report_from(cls, payload: Mapping[str, Any], digest: str) -> EvidenceReport:
        values = dict(payload)
        values.pop("schema", None)
        values["jurisdictions"] = tuple(values["jurisdictions"])
        values["evidence"] = tuple(cls._hit_from(item) for item in values["evidence"])
        values["citations"] = tuple(Citation(**item) for item in values["citations"])
        return EvidenceReport(**values, integrity_sha256=digest)

    def enroll_source(
        self,
        tenant_id: str,
        *,
        source_id: str,
        name: str,
        license_ref: str,
        rights_basis: str,
        allowed_uses: Sequence[str],
        provenance_uri: str,
        jurisdictions: Sequence[str],
        authorities: Sequence[str],
        document_types: Sequence[str],
        languages: Sequence[str],
        retention_seconds: int,
        actor_ref: str,
        idempotency_key: str,
        expected_revision: int = 0,
        now: float | None = None,
    ) -> RegulatorySource:
        """Enroll or CAS-replace source rights; every change resets approval."""

        tenant = _tenant(tenant_id)
        source = _identifier(source_id, "source_id")
        source_name = _text(name, "source name", 500)
        license_id = _text(license_ref, "license_ref", 1_024)
        basis = _text(rights_basis, "rights_basis", 1_000)
        uses = _closed_ids(allowed_uses, "allowed_uses", maximum=len(_ALLOWED_USES))
        if not set(uses).issubset(_ALLOWED_USES):
            raise PrivacyRegulatoryIntelligenceValidationError(
                "allowed_uses contains an unsupported purpose"
            )
        provenance = _https_uri(provenance_uri, "provenance_uri")
        jurisdiction_values = _jurisdictions(jurisdictions)
        authority_values = _closed_ids(authorities, "authorities")
        type_values = _closed_ids(document_types, "document_types")
        if not set(type_values).issubset(_DOCUMENT_TYPES):
            raise PrivacyRegulatoryIntelligenceValidationError(
                "document_types contains an unsupported type"
            )
        if isinstance(languages, (str, bytes)) or not 1 <= len(languages) <= 50:
            raise PrivacyRegulatoryIntelligenceValidationError(
                "languages must contain between 1 and 50 values"
            )
        language_values = tuple(sorted({_language(value) for value in languages}))
        if len(language_values) != len(languages):
            raise PrivacyRegulatoryIntelligenceValidationError(
                "languages contains duplicates"
            )
        retention = _retention(retention_seconds)
        actor = _identifier(actor_ref, "actor_ref")
        expected = _nonnegative_int(expected_revision, "expected_revision")
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "enroll_source",
            "source_id": source,
            "name": source_name,
            "license_ref": license_id,
            "rights_basis": basis,
            "allowed_uses": list(uses),
            "provenance_uri": provenance,
            "jurisdictions": list(jurisdiction_values),
            "authorities": list(authority_values),
            "document_types": list(type_values),
            "languages": list(language_values),
            "retention_seconds": retention,
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
                return self.get_source(tenant, operation["result_id"])
            row = connection.execute(
                "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                (tenant, source),
            ).fetchone()
            if row is None:
                if expected != 0:
                    raise PrivacyRegulatoryIntelligenceConflict(
                        "source expected revision does not match absence"
                    )
                revision = 1
                enrolled_at = moment
            else:
                previous = self._row_payload(row, "source")
                if int(previous["revision"]) != expected:
                    raise PrivacyRegulatoryIntelligenceConflict(
                        "source expected revision does not match"
                    )
                revision = expected + 1
                enrolled_at = float(previous["enrolled_at"])
            payload = {
                "schema": SOURCE_SCHEMA,
                "tenant_id": tenant,
                "source_id": source,
                "name": source_name,
                "license_ref": license_id,
                "rights_basis": basis,
                "allowed_uses": list(uses),
                "provenance_uri": provenance,
                "jurisdictions": list(jurisdiction_values),
                "authorities": list(authority_values),
                "document_types": list(type_values),
                "languages": list(language_values),
                "retention_seconds": retention,
                "state": "pending",
                "revision": revision,
                "enrolled_by": actor,
                "approved_by": None,
                "approval_rationale": None,
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
                {"revision": revision, "state": "pending"},
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
        rationale: str,
        approved: bool,
        idempotency_key: str,
        now: float | None = None,
    ) -> RegulatorySource:
        """Record independent human approval or rejection of exact source rights."""

        tenant = _tenant(tenant_id)
        source = _identifier(source_id, "source_id")
        expected = _positive_int(expected_revision, "expected_revision")
        approver = _identifier(approver_ref, "approver_ref")
        reason = _text(rationale, "approval rationale", 2_000)
        if not isinstance(approved, bool):
            raise PrivacyRegulatoryIntelligenceValidationError("approved must be boolean")
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "approve_source",
            "source_id": source,
            "expected_revision": expected,
            "approver_ref": approver,
            "rationale": reason,
            "approved": approved,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_source(tenant, operation["result_id"])
            row = connection.execute(
                "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                (tenant, source),
            ).fetchone()
            if row is None:
                raise PrivacyRegulatoryIntelligenceNotFound("source not found")
            payload = self._row_payload(row, "source")
            if int(payload["revision"]) != expected or payload["state"] != "pending":
                raise PrivacyRegulatoryIntelligenceConflict(
                    "source approval state or revision does not match"
                )
            if payload["enrolled_by"] == approver:
                raise PrivacyRegulatoryIntelligencePermissionDenied(
                    "source enrollment and approval require different humans"
                )
            payload.update(
                {
                    "state": "active" if approved else "rejected",
                    "revision": expected + 1,
                    "approved_by": approver,
                    "approval_rationale": reason,
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
                {"revision": expected + 1},
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
        reason: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> RegulatorySource:
        tenant = _tenant(tenant_id)
        source = _identifier(source_id, "source_id")
        expected = _positive_int(expected_revision, "expected_revision")
        actor = _identifier(actor_ref, "actor_ref")
        rationale = _text(reason, "revocation reason", 2_000)
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "revoke_source",
            "source_id": source,
            "expected_revision": expected,
            "actor_ref": actor,
            "reason": rationale,
        }
        with self._connect() as connection:
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
                raise PrivacyRegulatoryIntelligenceNotFound("source not found")
            payload = self._row_payload(row, "source")
            if int(payload["revision"]) != expected:
                raise PrivacyRegulatoryIntelligenceConflict(
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
                {"reason_sha256": hashlib.sha256(rationale.encode()).hexdigest()},
                moment,
            )
            connection.commit()
        return self.get_source(tenant, source)

    def get_source(self, tenant_id: str, source_id: str) -> RegulatorySource:
        tenant = _tenant(tenant_id)
        source = _identifier(source_id, "source_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                (tenant, source),
            ).fetchone()
        if row is None:
            raise PrivacyRegulatoryIntelligenceNotFound("source not found")
        return self._source_from(self._row_payload(row, "source"), row["integrity_sha256"])

    def list_sources(self, tenant_id: str) -> tuple[RegulatorySource, ...]:
        tenant = _tenant(tenant_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM sources WHERE tenant_id=? ORDER BY source_id LIMIT ?",
                (tenant, _MAX_LIST),
            ).fetchall()
        return tuple(
            self._source_from(self._row_payload(row, "source"), row["integrity_sha256"])
            for row in rows
        )

    def list_records(self, tenant_id: str) -> dict[str, tuple]:
        """Read-only listing of the latest version of each document, saved
        trackers and evidence reports for one tenant (integrity-checked)."""

        tenant = _tenant(tenant_id)
        with self._connect() as connection:
            document_ids = [
                row[0]
                for row in connection.execute(
                    "SELECT DISTINCT document_id FROM documents WHERE tenant_id=? "
                    "ORDER BY document_id LIMIT ?",
                    (tenant, _MAX_LIST),
                ).fetchall()
            ]
            subscriptions = tuple(
                self._subscription_from(self._row_payload(row, "subscription"), row["integrity_sha256"])
                for row in connection.execute(
                    "SELECT * FROM subscriptions WHERE tenant_id=? ORDER BY subscription_id LIMIT ?",
                    (tenant, _MAX_LIST),
                ).fetchall()
            )
            reports = tuple(
                self._report_from(self._row_payload(row, "report"), row["integrity_sha256"])
                for row in connection.execute(
                    "SELECT * FROM reports WHERE tenant_id=? ORDER BY rowid DESC LIMIT ?",
                    (tenant, _MAX_LIST),
                ).fetchall()
            )
        documents = tuple(self.get_document(tenant, document_id) for document_id in document_ids)
        return {"documents": documents, "subscriptions": subscriptions, "reports": reports}

    def ingest_document(
        self,
        tenant_id: str,
        *,
        document_id: str,
        source_id: str,
        title: str,
        jurisdiction: str,
        authority: str,
        document_type: str,
        language: str,
        publication_date: str,
        effective_date: str | None,
        superseded_date: str | None,
        citations: Sequence[Mapping[str, object]],
        content: str,
        content_sha256: str,
        expected_latest_version: int,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> RegulatoryDocument:
        """Append one immutable licensed document version."""

        tenant = _tenant(tenant_id)
        document = _identifier(document_id, "document_id")
        source = _identifier(source_id, "source_id")
        document_title = _text(title, "title", 1_000)
        jurisdiction_value = _jurisdictions([jurisdiction])[0]
        authority_value = _identifier(authority, "authority")
        type_value = _identifier(document_type, "document_type")
        if type_value not in _DOCUMENT_TYPES:
            raise PrivacyRegulatoryIntelligenceValidationError(
                "document_type is unsupported"
            )
        language_value = _language(language)
        published = _iso_date(publication_date, "publication_date")
        effective = _iso_date(effective_date, "effective_date", optional=True)
        superseded = _iso_date(superseded_date, "superseded_date", optional=True)
        if effective and superseded and effective > superseded:
            raise PrivacyRegulatoryIntelligenceValidationError(
                "effective_date cannot follow superseded_date"
            )
        citation_values = _citations(citations)
        body = _content(content)
        supplied_digest = _digest(content_sha256, "content_sha256")
        if not hmac.compare_digest(supplied_digest, _content_digest(body)):
            raise PrivacyRegulatoryIntelligenceValidationError(
                "content_sha256 does not match content"
            )
        expected = _nonnegative_int(expected_latest_version, "expected_latest_version")
        actor = _identifier(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "ingest_document",
            "document_id": document,
            "source_id": source,
            "title": document_title,
            "jurisdiction": jurisdiction_value,
            "authority": authority_value,
            "document_type": type_value,
            "language": language_value,
            "publication_date": published,
            "effective_date": effective,
            "superseded_date": superseded,
            "citations": [asdict(citation) for citation in citation_values],
            "content_sha256": supplied_digest,
            "expected_latest_version": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                result_id = str(operation["result_id"])
                result_document, result_version = result_id.rsplit(":", 1)
                return self.get_document(tenant, result_document, int(result_version))
            source_row = connection.execute(
                "SELECT * FROM sources WHERE tenant_id=? AND source_id=?",
                (tenant, source),
            ).fetchone()
            if source_row is None:
                raise PrivacyRegulatoryIntelligenceNotFound("source not found")
            source_payload = self._row_payload(source_row, "source")
            if source_payload["state"] != "active" or not source_payload["approved_by"]:
                raise PrivacyRegulatoryIntelligencePermissionDenied(
                    "source requires independent approval before ingestion"
                )
            if not set(_ALLOWED_USES).intersection(source_payload["allowed_uses"]):
                raise PrivacyRegulatoryIntelligencePermissionDenied(
                    "source rights do not permit intelligence use"
                )
            for value, label, enrolled in (
                (jurisdiction_value, "jurisdiction", source_payload["jurisdictions"]),
                (authority_value, "authority", source_payload["authorities"]),
                (type_value, "document_type", source_payload["document_types"]),
                (language_value, "language", source_payload["languages"]),
            ):
                if value not in enrolled:
                    raise PrivacyRegulatoryIntelligencePermissionDenied(
                        f"{label} is outside the approved source scope"
                    )
            latest = connection.execute(
                "SELECT MAX(version) AS version FROM documents "
                "WHERE tenant_id=? AND document_id=?",
                (tenant, document),
            ).fetchone()
            latest_version = int(latest["version"] or 0)
            if latest_version != expected:
                raise PrivacyRegulatoryIntelligenceConflict(
                    "document latest-version CAS does not match"
                )
            version = latest_version + 1
            payload = {
                "schema": DOCUMENT_SCHEMA,
                "tenant_id": tenant,
                "document_id": document,
                "version": version,
                "source_id": source,
                "title": document_title,
                "jurisdiction": jurisdiction_value,
                "authority": authority_value,
                "document_type": type_value,
                "language": language_value,
                "publication_date": published,
                "effective_date": effective,
                "superseded_date": superseded,
                "citations": [asdict(citation) for citation in citation_values],
                "content_sha256": supplied_digest,
                "supersedes_version": latest_version or None,
                "retain_until": moment + int(source_payload["retention_seconds"]),
                "ingested_by": actor,
                "ingested_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO documents VALUES(?,?,?,?,?,?,?)",
                (
                    tenant,
                    document,
                    version,
                    source,
                    body,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            result_id = f"{document}:{version}"
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "document", result_id
            )
            self._audit(
                connection,
                tenant,
                "document_ingested",
                result_id,
                actor,
                {"content_sha256": supplied_digest, "source_id": source},
                moment,
            )
            connection.commit()
        return self.get_document(tenant, document, version)

    def get_document(
        self, tenant_id: str, document_id: str, version: int | None = None
    ) -> RegulatoryDocument:
        tenant = _tenant(tenant_id)
        document = _identifier(document_id, "document_id")
        with self._connect() as connection:
            if version is None:
                row = connection.execute(
                    "SELECT * FROM documents WHERE tenant_id=? AND document_id=? "
                    "ORDER BY version DESC LIMIT 1",
                    (tenant, document),
                ).fetchone()
            else:
                exact_version = _positive_int(version, "version")
                row = connection.execute(
                    "SELECT * FROM documents WHERE tenant_id=? AND document_id=? "
                    "AND version=?",
                    (tenant, document, exact_version),
                ).fetchone()
        if row is None:
            raise PrivacyRegulatoryIntelligenceNotFound("document not found")
        payload = self._row_payload(row, "document")
        if not hmac.compare_digest(payload["content_sha256"], _content_digest(row["content_text"])):
            raise PrivacyRegulatoryIntelligenceIntegrityError(
                "persisted document content failed digest verification"
            )
        return self._document_from(payload, row["integrity_sha256"])

    def list_document_versions(
        self, tenant_id: str, document_id: str
    ) -> tuple[RegulatoryDocument, ...]:
        tenant = _tenant(tenant_id)
        document = _identifier(document_id, "document_id")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM documents WHERE tenant_id=? AND document_id=? "
                "ORDER BY version",
                (tenant, document),
            ).fetchall()
        return tuple(
            self.get_document(tenant, document, int(row["version"])) for row in rows
        )

    @staticmethod
    def _excerpt(content: str, tokens: Sequence[str]) -> str:
        collapsed = " ".join(content.split())
        folded = collapsed.casefold()
        positions = [folded.find(token) for token in tokens if token in folded]
        start = max(0, min(positions) - 80) if positions else 0
        excerpt = collapsed[start : start + 320]
        if start:
            excerpt = "…" + excerpt
        if start + 320 < len(collapsed):
            excerpt += "…"
        return excerpt

    def search(
        self,
        tenant_id: str,
        query: str,
        *,
        jurisdictions: Sequence[str] | None = None,
        use: str = "search",
        limit: int = 20,
        as_of: str | None = None,
    ) -> tuple[SearchHit, ...]:
        """Search latest approved versions and return digest-bound evidence.

        A published text that takes effect after ``as_of`` is still returned,
        with ``not_yet_effective`` set on its hit.
        """

        tenant = _tenant(tenant_id)
        query_value = _query(query)
        tokens = _query_tokens(query_value)
        if use not in _ALLOWED_USES:
            raise PrivacyRegulatoryIntelligenceValidationError("research use is closed")
        jurisdiction_filter = (
            frozenset(_jurisdictions(jurisdictions)) if jurisdictions is not None else None
        )
        result_limit = _positive_int(limit, "limit", _MAX_SEARCH_RESULTS)
        as_of_value = _iso_date(as_of or date.today().isoformat(), "as_of")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT d.*,s.payload_json AS source_payload_json,"
                "s.integrity_sha256 AS source_integrity_sha256 "
                "FROM documents d JOIN sources s ON "
                "s.tenant_id=d.tenant_id AND s.source_id=d.source_id "
                "WHERE d.tenant_id=? ORDER BY d.document_id, d.version DESC",
                (tenant,),
            ).fetchall()
        hits: list[SearchHit] = []
        selected_documents: set[str] = set()
        for row in rows:
            document_payload = self._row_payload(row, "document")
            # Choose the newest publication known at the historical boundary,
            # after authenticating its metadata. A later publication must not
            # erase the previously available version from historical research.
            document_id = document_payload["document_id"]
            if document_id in selected_documents:
                continue
            if document_payload["publication_date"] > as_of_value:
                continue
            selected_documents.add(document_id)
            try:
                source_payload = json.loads(row["source_payload_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise PrivacyRegulatoryIntelligenceIntegrityError(
                    "persisted source is not canonical JSON"
                ) from exc
            if (
                not isinstance(source_payload, dict)
                or _sha256(source_payload) != row["source_integrity_sha256"]
            ):
                raise PrivacyRegulatoryIntelligenceIntegrityError(
                    "persisted source failed integrity verification"
                )
            if source_payload["state"] != "active" or use not in source_payload["allowed_uses"]:
                continue
            if jurisdiction_filter is not None and document_payload["jurisdiction"] not in jurisdiction_filter:
                continue
            if document_payload["publication_date"] > as_of_value:
                continue
            superseded_date = document_payload["superseded_date"]
            if superseded_date is not None and superseded_date <= as_of_value:
                continue
            content = row["content_text"]
            if not hmac.compare_digest(
                document_payload["content_sha256"], _content_digest(content)
            ):
                raise PrivacyRegulatoryIntelligenceIntegrityError(
                    "persisted document content failed digest verification"
                )
            haystack = f"{document_payload['title']} {content}".casefold()
            matched = [token for token in tokens if token in haystack]
            if not matched:
                continue
            citations = tuple(Citation(**item) for item in document_payload["citations"])
            evidence = {
                "document_id": document_payload["document_id"],
                "version": document_payload["version"],
                "content_sha256": document_payload["content_sha256"],
                "query_tokens": list(tokens),
                "matched_tokens": matched,
                "citation_ids": [item.citation_id for item in citations],
            }
            effective_date = document_payload["effective_date"]
            hits.append(
                SearchHit(
                    document_id=document_payload["document_id"],
                    version=int(document_payload["version"]),
                    source_id=document_payload["source_id"],
                    title=document_payload["title"],
                    jurisdiction=document_payload["jurisdiction"],
                    authority=document_payload["authority"],
                    document_type=document_payload["document_type"],
                    publication_date=document_payload["publication_date"],
                    effective_date=effective_date,
                    score=len(matched),
                    excerpt=self._excerpt(content, matched),
                    content_sha256=document_payload["content_sha256"],
                    evidence_sha256=_sha256(evidence),
                    citations=citations,
                    not_yet_effective=(
                        effective_date is not None and effective_date > as_of_value
                    ),
                )
            )
        hits.sort(key=lambda hit: (-hit.score, hit.publication_date, hit.document_id))
        return tuple(hits[:result_limit])

    def research(
        self,
        tenant_id: str,
        query: str,
        *,
        jurisdictions: Sequence[str] | None = None,
        minimum_evidence: int = 1,
        limit: int = 10,
        as_of: str | None = None,
    ) -> ResearchAnswer:
        """Return grounded excerpts and citations, or an explicit abstention."""

        query_value = _query(query)
        minimum = _positive_int(minimum_evidence, "minimum_evidence", 20)
        hits = self.search(
            tenant_id,
            query_value,
            jurisdictions=jurisdictions,
            use="research",
            limit=limit,
            as_of=as_of,
        )
        return self._answer_from_hits(query_value, hits, minimum)

    @staticmethod
    def _answer_from_hits(
        query_value: str,
        hits: Sequence[SearchHit],
        minimum_evidence: int,
    ) -> ResearchAnswer:
        citations: list[Citation] = []
        seen: set[str] = set()
        for hit in hits:
            for citation in hit.citations:
                if citation.citation_id not in seen:
                    citations.append(citation)
                    seen.add(citation.citation_id)
        not_yet_effective = False
        if len(hits) < minimum_evidence:
            status = "abstained"
            answer = (
                "Insufficient approved, in-scope evidence to answer this question. "
                "No legal conclusion was generated."
            )
        else:
            status = "grounded"
            parts = [
                f"[{hit.citations[0].citation_id}] "
                + (
                    f"(not yet in effect; takes effect {hit.effective_date}) "
                    if hit.not_yet_effective
                    else ""
                )
                + hit.excerpt
                for hit in hits[:10]
            ]
            answer = "Grounded evidence excerpts: " + " ".join(parts)
            not_yet_effective = all(hit.not_yet_effective for hit in hits)
            if not_yet_effective:
                answer = (
                    "None of this evidence is in effect yet on the date searched. "
                    + answer
                )
        evidence_payload = {
            "query": query_value,
            "status": status,
            "hits": [
                {
                    "document_id": hit.document_id,
                    "version": hit.version,
                    "evidence_sha256": hit.evidence_sha256,
                }
                for hit in hits
            ],
            "citation_ids": [citation.citation_id for citation in citations],
        }
        return ResearchAnswer(
            query=query_value,
            status=status,
            answer=answer,
            evidence=tuple(hits),
            citations=tuple(citations),
            disclaimer=_DISCLAIMER,
            evidence_sha256=_sha256(evidence_payload),
            not_yet_effective=not_yet_effective,
        )

    def compare_jurisdictions(
        self,
        tenant_id: str,
        query: str,
        jurisdictions: Sequence[str],
        *,
        minimum_evidence_per_jurisdiction: int = 1,
        as_of: str | None = None,
    ) -> JurisdictionComparison:
        query_value = _query(query)
        jurisdiction_values = _jurisdictions(jurisdictions)
        if len(jurisdiction_values) < 2:
            raise PrivacyRegulatoryIntelligenceValidationError(
                "comparison requires at least two jurisdictions"
            )
        minimum = _positive_int(
            minimum_evidence_per_jurisdiction,
            "minimum_evidence_per_jurisdiction",
            20,
        )
        answers = {}
        for jurisdiction in jurisdiction_values:
            hits = self.search(
                tenant_id,
                query_value,
                jurisdictions=[jurisdiction],
                use="compare",
                limit=20,
                as_of=as_of,
            )
            answers[jurisdiction] = self._answer_from_hits(query_value, hits, minimum)
        digest = _sha256(
            {
                "query": query_value,
                "jurisdictions": list(jurisdiction_values),
                "answers": {
                    key: value.evidence_sha256 for key, value in answers.items()
                },
            }
        )
        return JurisdictionComparison(
            query=query_value,
            jurisdictions=jurisdiction_values,
            answers=answers,
            evidence_sha256=digest,
        )

    def create_collection(
        self,
        tenant_id: str,
        *,
        collection_id: str,
        title: str,
        description: str,
        owner_ref: str,
        jurisdictions: Sequence[str],
        idempotency_key: str,
        now: float | None = None,
    ) -> ResearchCollection:
        tenant = _tenant(tenant_id)
        collection = _identifier(collection_id, "collection_id")
        title_value = _text(title, "title", 500)
        description_value = _text(description, "description", 2_000, minimum=0)
        owner = _identifier(owner_ref, "owner_ref")
        jurisdiction_values = _jurisdictions(jurisdictions)
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "create_collection",
            "collection_id": collection,
            "title": title_value,
            "description": description_value,
            "owner_ref": owner,
            "jurisdictions": list(jurisdiction_values),
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_collection(tenant, collection, principal_ref=owner)
            if connection.execute(
                "SELECT 1 FROM collections WHERE tenant_id=? AND collection_id=?",
                (tenant, collection),
            ).fetchone():
                raise PrivacyRegulatoryIntelligenceConflict("collection already exists")
            payload = {
                "schema": COLLECTION_SCHEMA,
                "tenant_id": tenant,
                "collection_id": collection,
                "title": title_value,
                "description": description_value,
                "owner_ref": owner,
                "acl": {owner: "owner"},
                "items": [],
                "jurisdictions": list(jurisdiction_values),
                "revision": 1,
                "created_at": moment,
                "updated_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO collections VALUES(?,?,?,?)",
                (tenant, collection, _canonical(payload).decode("ascii"), digest),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "collection", collection
            )
            self._audit(
                connection, tenant, "collection_created", collection, owner, {}, moment
            )
            connection.commit()
        return self.get_collection(tenant, collection, principal_ref=owner)

    def _collection_row(
        self, connection: sqlite3.Connection, tenant: str, collection: str
    ) -> tuple[sqlite3.Row, dict[str, Any]]:
        row = connection.execute(
            "SELECT * FROM collections WHERE tenant_id=? AND collection_id=?",
            (tenant, collection),
        ).fetchone()
        if row is None:
            raise PrivacyRegulatoryIntelligenceNotFound("collection not found")
        return row, self._row_payload(row, "collection")

    @staticmethod
    def _require_collection_role(
        payload: Mapping[str, Any], principal: str, allowed: frozenset[str]
    ) -> None:
        if payload["acl"].get(principal) not in allowed:
            raise PrivacyRegulatoryIntelligenceNotFound("collection not found")

    def get_collection(
        self, tenant_id: str, collection_id: str, *, principal_ref: str
    ) -> ResearchCollection:
        tenant = _tenant(tenant_id)
        collection = _identifier(collection_id, "collection_id")
        principal = _identifier(principal_ref, "principal_ref")
        with self._connect() as connection:
            row, payload = self._collection_row(connection, tenant, collection)
        self._require_collection_role(payload, principal, _COLLECTION_ROLES)
        return self._collection_from(payload, row["integrity_sha256"])

    def grant_collection_access(
        self,
        tenant_id: str,
        collection_id: str,
        *,
        principal_ref: str,
        role: str,
        expected_revision: int,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ResearchCollection:
        tenant = _tenant(tenant_id)
        collection = _identifier(collection_id, "collection_id")
        principal = _identifier(principal_ref, "principal_ref")
        if role not in {"viewer", "editor"}:
            raise PrivacyRegulatoryIntelligenceValidationError(
                "collection grant role must be viewer or editor"
            )
        expected = _positive_int(expected_revision, "expected_revision")
        actor = _identifier(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "grant_collection_access",
            "collection_id": collection,
            "principal_ref": principal,
            "role": role,
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
                return self.get_collection(tenant, collection, principal_ref=actor)
            row, payload = self._collection_row(connection, tenant, collection)
            self._require_collection_role(payload, actor, frozenset({"owner"}))
            if int(payload["revision"]) != expected:
                raise PrivacyRegulatoryIntelligenceConflict(
                    "collection expected revision does not match"
                )
            # The owner is the only principal who can manage the collection;
            # replacing that role would leave it with nobody who can.
            if payload["acl"].get(principal) == "owner":
                raise PrivacyRegulatoryIntelligenceConflict(
                    "the collection owner's role cannot be changed"
                )
            payload["acl"][principal] = role
            payload["revision"] = expected + 1
            payload["updated_at"] = moment
            digest = _sha256(payload)
            connection.execute(
                "UPDATE collections SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND collection_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, collection),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "collection", collection
            )
            self._audit(
                connection,
                tenant,
                "collection_acl_granted",
                collection,
                actor,
                {"principal_sha256": hashlib.sha256(principal.encode()).hexdigest(), "role": role},
                moment,
            )
            connection.commit()
        return self.get_collection(tenant, collection, principal_ref=actor)

    def add_collection_document(
        self,
        tenant_id: str,
        collection_id: str,
        *,
        document_id: str,
        version: int,
        expected_revision: int,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> ResearchCollection:
        tenant = _tenant(tenant_id)
        collection = _identifier(collection_id, "collection_id")
        document = _identifier(document_id, "document_id")
        document_version = _positive_int(version, "version")
        expected = _positive_int(expected_revision, "expected_revision")
        actor = _identifier(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "add_collection_document",
            "collection_id": collection,
            "document_id": document,
            "version": document_version,
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
                return self.get_collection(tenant, collection, principal_ref=actor)
            row, payload = self._collection_row(connection, tenant, collection)
            self._require_collection_role(payload, actor, frozenset({"owner", "editor"}))
            if int(payload["revision"]) != expected:
                raise PrivacyRegulatoryIntelligenceConflict(
                    "collection expected revision does not match"
                )
            document_row = connection.execute(
                "SELECT d.*,s.payload_json AS source_payload_json,"
                "s.integrity_sha256 AS source_integrity_sha256 FROM documents d "
                "JOIN sources s ON s.tenant_id=d.tenant_id AND s.source_id=d.source_id "
                "WHERE d.tenant_id=? AND d.document_id=? AND d.version=?",
                (tenant, document, document_version),
            ).fetchone()
            if document_row is None:
                raise PrivacyRegulatoryIntelligenceNotFound("document not found")
            document_payload = self._row_payload(document_row, "document")
            source_payload = json.loads(document_row["source_payload_json"])
            if (
                not isinstance(source_payload, dict)
                or _sha256(source_payload) != document_row["source_integrity_sha256"]
                or source_payload["state"] != "active"
                or "share" not in source_payload["allowed_uses"]
            ):
                raise PrivacyRegulatoryIntelligencePermissionDenied(
                    "source rights do not permit collection sharing"
                )
            if document_payload["jurisdiction"] not in payload["jurisdictions"]:
                raise PrivacyRegulatoryIntelligencePermissionDenied(
                    "document jurisdiction is outside collection scope"
                )
            item = [document, document_version]
            if item not in payload["items"]:
                if len(payload["items"]) >= _MAX_LIST:
                    raise PrivacyRegulatoryIntelligenceValidationError(
                        "collection item limit reached"
                    )
                payload["items"].append(item)
                payload["items"].sort()
            payload["revision"] = expected + 1
            payload["updated_at"] = moment
            digest = _sha256(payload)
            connection.execute(
                "UPDATE collections SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND collection_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, collection),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "collection", collection
            )
            self._audit(
                connection,
                tenant,
                "collection_document_added",
                collection,
                actor,
                {"document_id": document, "version": document_version},
                moment,
            )
            connection.commit()
        return self.get_collection(tenant, collection, principal_ref=actor)

    def create_share(
        self,
        tenant_id: str,
        collection_id: str,
        *,
        share_id: str,
        scopes: Sequence[str],
        expires_at: float,
        actor_ref: str,
        idempotency_key: str,
        now: float | None = None,
    ) -> CapabilityShare:
        tenant = _tenant(tenant_id)
        collection = _identifier(collection_id, "collection_id")
        share = _identifier(share_id, "share_id")
        scope_values = _closed_ids(scopes, "share scopes", maximum=len(_SHARE_SCOPES))
        if not set(scope_values).issubset(_SHARE_SCOPES):
            raise PrivacyRegulatoryIntelligenceValidationError("share scope is closed")
        actor = _identifier(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        expiry = _timestamp(expires_at, "expires_at")
        if not moment < expiry <= moment + 30 * 24 * 60 * 60:
            raise PrivacyRegulatoryIntelligenceValidationError(
                "share expiry must be within 30 days"
            )
        request = {
            "action": "create_share",
            "collection_id": collection,
            "share_id": share,
            "scopes": list(scope_values),
            "expires_at": expiry,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            _row, collection_payload = self._collection_row(connection, tenant, collection)
            self._require_collection_role(
                collection_payload, actor, frozenset({"owner", "editor"})
            )
            for document_id, version in collection_payload["items"]:
                document_row = connection.execute(
                    "SELECT d.source_id,s.payload_json,s.integrity_sha256 FROM documents d "
                    "JOIN sources s ON s.tenant_id=d.tenant_id AND s.source_id=d.source_id "
                    "WHERE d.tenant_id=? AND d.document_id=? AND d.version=?",
                    (tenant, document_id, version),
                ).fetchone()
                if document_row is None:
                    raise PrivacyRegulatoryIntelligenceIntegrityError(
                        "collection references a missing document"
                    )
                source_payload = self._row_payload(document_row, "source")
                if source_payload["state"] != "active" or "share" not in source_payload["allowed_uses"]:
                    raise PrivacyRegulatoryIntelligencePermissionDenied(
                        "collection contains content without current sharing rights"
                    )
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                raise PrivacyRegulatoryIntelligenceConflict(
                    "share tokens are returned once; create a new share identity"
                )
            secret = self._token_factory()
            if not isinstance(secret, str) or len(secret.encode("utf-8")) < 32:
                raise PrivacyRegulatoryIntelligenceIntegrityError(
                    "token factory returned insufficient entropy"
                )
            token = f"{share}.{secret}"
            token_sha = hashlib.sha256(token.encode("utf-8")).hexdigest()
            payload = {
                "schema": SHARE_SCHEMA,
                "tenant_id": tenant,
                "share_id": share,
                "collection_id": collection,
                "scopes": list(scope_values),
                "expires_at": expiry,
                "state": "active",
                "created_by": actor,
                "created_at": moment,
                "token_sha256": token_sha,
            }
            digest = _sha256(payload)
            try:
                connection.execute(
                    "INSERT INTO shares VALUES(?,?,?,?,?,?)",
                    (
                        share,
                        tenant,
                        collection,
                        token_sha,
                        _canonical(payload).decode("ascii"),
                        digest,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise PrivacyRegulatoryIntelligenceConflict(
                    "share identity already exists"
                ) from exc
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "share", share
            )
            self._audit(
                connection,
                tenant,
                "collection_share_created",
                share,
                actor,
                {"collection_id": collection, "expires_at": expiry},
                moment,
            )
            connection.commit()
        return self._share_from(payload, digest, token=token)

    def redeem_share(
        self, token: str, *, scope: str = "view", now: float | None = None
    ) -> ResearchCollection:
        token_value = _text(token, "share token", 512)
        if "." not in token_value:
            raise PrivacyRegulatoryIntelligenceNotFound("share not found")
        share_id, _secret = token_value.split(".", 1)
        try:
            share = _identifier(share_id, "share_id")
        except PrivacyRegulatoryIntelligenceValidationError as exc:
            raise PrivacyRegulatoryIntelligenceNotFound("share not found") from exc
        if scope not in _SHARE_SCOPES:
            raise PrivacyRegulatoryIntelligenceValidationError("share scope is closed")
        moment = _timestamp(self._clock() if now is None else now, "now")
        token_sha = hashlib.sha256(token_value.encode("utf-8")).hexdigest()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM shares WHERE share_id=?", (share,)
            ).fetchone()
            if row is None:
                raise PrivacyRegulatoryIntelligenceNotFound("share not found")
            payload = self._row_payload(row, "share")
            if (
                not hmac.compare_digest(row["token_sha256"], token_sha)
                or not hmac.compare_digest(payload["token_sha256"], token_sha)
                or payload["state"] != "active"
                or float(payload["expires_at"]) <= moment
                or scope not in payload["scopes"]
            ):
                raise PrivacyRegulatoryIntelligenceNotFound("share not found")
            _collection_row, collection_payload = self._collection_row(
                connection, row["tenant_id"], payload["collection_id"]
            )
            for document_id, version in collection_payload["items"]:
                document_row = connection.execute(
                    "SELECT s.payload_json,s.integrity_sha256 FROM documents d "
                    "JOIN sources s ON s.tenant_id=d.tenant_id AND s.source_id=d.source_id "
                    "WHERE d.tenant_id=? AND d.document_id=? AND d.version=?",
                    (row["tenant_id"], document_id, version),
                ).fetchone()
                if document_row is None:
                    raise PrivacyRegulatoryIntelligenceNotFound("share not found")
                source_payload = self._row_payload(document_row, "source")
                if source_payload["state"] != "active" or "share" not in source_payload["allowed_uses"]:
                    raise PrivacyRegulatoryIntelligenceNotFound("share not found")
        return self._collection_from(collection_payload, _collection_row["integrity_sha256"])

    def revoke_share(
        self,
        tenant_id: str,
        share_id: str,
        *,
        actor_ref: str,
        now: float | None = None,
    ) -> CapabilityShare:
        tenant = _tenant(tenant_id)
        share = _identifier(share_id, "share_id")
        actor = _identifier(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM shares WHERE tenant_id=? AND share_id=?",
                (tenant, share),
            ).fetchone()
            if row is None:
                raise PrivacyRegulatoryIntelligenceNotFound("share not found")
            payload = self._row_payload(row, "share")
            _collection_row, collection_payload = self._collection_row(
                connection, tenant, payload["collection_id"]
            )
            self._require_collection_role(
                collection_payload, actor, frozenset({"owner", "editor"})
            )
            payload["state"] = "revoked"
            digest = _sha256(payload)
            connection.execute(
                "UPDATE shares SET payload_json=?,integrity_sha256=? WHERE share_id=?",
                (_canonical(payload).decode("ascii"), digest, share),
            )
            self._audit(
                connection, tenant, "collection_share_revoked", share, actor, {}, moment
            )
            connection.commit()
        return self._share_from(payload, digest)

    def save_query(
        self,
        tenant_id: str,
        *,
        subscription_id: str,
        query: str,
        jurisdictions: Sequence[str],
        principal_ref: str,
        destination_ref: str,
        cadence_seconds: int,
        idempotency_key: str,
        expected_revision: int = 0,
        now: float | None = None,
    ) -> SavedQuery:
        """Create or CAS-replace a saved query and jurisdiction tracker."""

        tenant = _tenant(tenant_id)
        subscription = _identifier(subscription_id, "subscription_id")
        query_value = _query(query)
        jurisdiction_values = _jurisdictions(jurisdictions)
        principal = _identifier(principal_ref, "principal_ref")
        destination = _identifier(destination_ref, "destination_ref")
        cadence = _positive_int(cadence_seconds, "cadence_seconds", 365 * 24 * 60 * 60)
        if cadence < 60:
            raise PrivacyRegulatoryIntelligenceValidationError(
                "cadence_seconds must be at least 60"
            )
        expected = _nonnegative_int(expected_revision, "expected_revision")
        moment = _timestamp(self._clock() if now is None else now, "now")
        request = {
            "action": "save_query",
            "subscription_id": subscription,
            "query": query_value,
            "jurisdictions": list(jurisdiction_values),
            "principal_ref": principal,
            "destination_ref": destination,
            "cadence_seconds": cadence,
            "expected_revision": expected,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_saved_query(tenant, subscription)
            row = connection.execute(
                "SELECT * FROM subscriptions WHERE tenant_id=? AND subscription_id=?",
                (tenant, subscription),
            ).fetchone()
            if row is None:
                if expected != 0:
                    raise PrivacyRegulatoryIntelligenceConflict(
                        "subscription expected revision does not match absence"
                    )
                revision = 1
                created_at = moment
            else:
                previous = self._row_payload(row, "subscription")
                if int(previous["revision"]) != expected:
                    raise PrivacyRegulatoryIntelligenceConflict(
                        "subscription expected revision does not match"
                    )
                revision = expected + 1
                created_at = float(previous["created_at"])
            payload = {
                "schema": SUBSCRIPTION_SCHEMA,
                "tenant_id": tenant,
                "subscription_id": subscription,
                "query": query_value,
                "jurisdictions": list(jurisdiction_values),
                "principal_ref": principal,
                "destination_ref": destination,
                "cadence_seconds": cadence,
                "next_run_at": moment,
                "state": "active",
                "revision": revision,
                "created_at": created_at,
                "updated_at": moment,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO subscriptions VALUES(?,?,?,?) "
                "ON CONFLICT(tenant_id,subscription_id) DO UPDATE SET "
                "payload_json=excluded.payload_json,integrity_sha256=excluded.integrity_sha256",
                (tenant, subscription, _canonical(payload).decode("ascii"), digest),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "subscription",
                subscription,
            )
            self._audit(
                connection,
                tenant,
                "subscription_saved",
                subscription,
                principal,
                {"revision": revision},
                moment,
            )
            connection.commit()
        return self.get_saved_query(tenant, subscription)

    create_jurisdiction_tracker = save_query

    def get_saved_query(self, tenant_id: str, subscription_id: str) -> SavedQuery:
        tenant = _tenant(tenant_id)
        subscription = _identifier(subscription_id, "subscription_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM subscriptions WHERE tenant_id=? AND subscription_id=?",
                (tenant, subscription),
            ).fetchone()
        if row is None:
            raise PrivacyRegulatoryIntelligenceNotFound("subscription not found")
        return self._subscription_from(
            self._row_payload(row, "subscription"), row["integrity_sha256"]
        )

    def due_subscriptions(
        self, tenant_id: str, *, limit: int = 100, now: float | None = None
    ) -> tuple[SavedQuery, ...]:
        tenant = _tenant(tenant_id)
        result_limit = _positive_int(limit, "limit", 500)
        moment = _timestamp(self._clock() if now is None else now, "now")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM subscriptions WHERE tenant_id=? ORDER BY subscription_id",
                (tenant,),
            ).fetchall()
        result: list[SavedQuery] = []
        for row in rows:
            item = self._subscription_from(
                self._row_payload(row, "subscription"), row["integrity_sha256"]
            )
            if item.state == "active" and item.next_run_at <= moment:
                result.append(item)
        return tuple(result[:result_limit])

    def advance_subscription(
        self,
        tenant_id: str,
        subscription_id: str,
        *,
        expected_revision: int,
        actor_ref: str,
        now: float | None = None,
    ) -> SavedQuery:
        tenant = _tenant(tenant_id)
        subscription = _identifier(subscription_id, "subscription_id")
        expected = _positive_int(expected_revision, "expected_revision")
        actor = _identifier(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM subscriptions WHERE tenant_id=? AND subscription_id=?",
                (tenant, subscription),
            ).fetchone()
            if row is None:
                raise PrivacyRegulatoryIntelligenceNotFound("subscription not found")
            payload = self._row_payload(row, "subscription")
            if int(payload["revision"]) != expected or payload["state"] != "active":
                raise PrivacyRegulatoryIntelligenceConflict(
                    "subscription state or revision does not match"
                )
            payload["next_run_at"] = moment + int(payload["cadence_seconds"])
            payload["revision"] = expected + 1
            payload["updated_at"] = moment
            digest = _sha256(payload)
            connection.execute(
                "UPDATE subscriptions SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND subscription_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, subscription),
            )
            self._audit(
                connection,
                tenant,
                "subscription_advanced",
                subscription,
                actor,
                {"next_run_at": payload["next_run_at"]},
                moment,
            )
            connection.commit()
        return self.get_saved_query(tenant, subscription)

    def generate_alerts(
        self,
        tenant_id: str,
        document_id: str,
        version: int,
        *,
        actor_ref: str,
        now: float | None = None,
    ) -> tuple[RegulatoryAlert, ...]:
        """Generate deterministic alert/outbox rows for matching subscriptions."""

        tenant = _tenant(tenant_id)
        document = self.get_document(tenant, document_id, version)
        source = self.get_source(tenant, document.source_id)
        if source.state != "active" or "alerts" not in source.allowed_uses:
            raise PrivacyRegulatoryIntelligencePermissionDenied(
                "source rights do not permit regulatory alerts"
            )
        actor = _identifier(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        hits_by_query: dict[str, bool] = {}
        created: list[RegulatoryAlert] = []
        with self._connect() as connection:
            self._begin(connection)
            rows = connection.execute(
                "SELECT * FROM subscriptions WHERE tenant_id=? ORDER BY subscription_id",
                (tenant,),
            ).fetchall()
            document_row = connection.execute(
                "SELECT content_text FROM documents WHERE tenant_id=? AND document_id=? "
                "AND version=?",
                (tenant, document.document_id, document.version),
            ).fetchone()
            if document_row is None:
                raise PrivacyRegulatoryIntelligenceNotFound("document not found")
            haystack = f"{document.title} {document_row['content_text']}".casefold()
            for row in rows:
                subscription_payload = self._row_payload(row, "subscription")
                if (
                    subscription_payload["state"] != "active"
                    or document.jurisdiction not in subscription_payload["jurisdictions"]
                ):
                    continue
                query_value = subscription_payload["query"]
                matched = hits_by_query.setdefault(
                    query_value,
                    any(token in haystack for token in _query_tokens(query_value)),
                )
                if not matched:
                    continue
                stable = _sha256(
                    {
                        "tenant_id": tenant,
                        "subscription_id": subscription_payload["subscription_id"],
                        "document_id": document.document_id,
                        "version": document.version,
                    }
                )
                alert_id = f"ALT-{stable[:24]}"
                delivery_id = f"DLV-{stable[24:48]}"
                evidence_sha = _sha256(
                    {
                        "document_id": document.document_id,
                        "version": document.version,
                        "content_sha256": document.content_sha256,
                        "query": query_value,
                    }
                )
                alert_payload = {
                    "schema": ALERT_SCHEMA,
                    "tenant_id": tenant,
                    "alert_id": alert_id,
                    "subscription_id": subscription_payload["subscription_id"],
                    "document_id": document.document_id,
                    "document_version": document.version,
                    "jurisdiction": document.jurisdiction,
                    "evidence_sha256": evidence_sha,
                    "created_at": moment,
                }
                alert_digest = _sha256(alert_payload)
                inserted = connection.execute(
                    "INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?)",
                    (
                        tenant,
                        alert_id,
                        subscription_payload["subscription_id"],
                        _canonical(alert_payload).decode("ascii"),
                        alert_digest,
                    ),
                ).rowcount
                if not inserted:
                    existing = connection.execute(
                        "SELECT * FROM alerts WHERE tenant_id=? AND alert_id=?",
                        (tenant, alert_id),
                    ).fetchone()
                    if existing is None:
                        raise PrivacyRegulatoryIntelligenceIntegrityError(
                            "deterministic alert disappeared"
                        )
                    existing_payload = self._row_payload(existing, "alert")
                    created.append(
                        self._alert_from(existing_payload, existing["integrity_sha256"])
                    )
                    continue
                delivery_payload = {
                    "schema": OUTBOX_SCHEMA,
                    "tenant_id": tenant,
                    "delivery_id": delivery_id,
                    "alert_id": alert_id,
                    "subscription_id": subscription_payload["subscription_id"],
                    "destination_ref": subscription_payload["destination_ref"],
                    "state": "pending",
                    "attempt": 0,
                    "max_attempts": 5,
                    "next_attempt_at": moment,
                    "lease_token": None,
                    "lease_until": None,
                    "revision": 1,
                    "last_error_code": None,
                }
                delivery_digest = _sha256(delivery_payload)
                connection.execute(
                    "INSERT INTO outbox VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        tenant,
                        delivery_id,
                        alert_id,
                        subscription_payload["subscription_id"],
                        "pending",
                        moment,
                        None,
                        _canonical(delivery_payload).decode("ascii"),
                        delivery_digest,
                    ),
                )
                self._audit(
                    connection,
                    tenant,
                    "regulatory_alert_generated",
                    alert_id,
                    actor,
                    {"delivery_id": delivery_id, "evidence_sha256": evidence_sha},
                    moment,
                )
                created.append(
                    self._alert_from(alert_payload, alert_digest)
                )
            connection.commit()
        return tuple(created)

    def claim_deliveries(
        self,
        tenant_id: str,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: float = 60.0,
        now: float | None = None,
    ) -> tuple[DeliveryItem, ...]:
        tenant = _tenant(tenant_id)
        worker = _identifier(worker_id, "worker_id")
        result_limit = _positive_int(limit, "limit", 100)
        lease = _timestamp(lease_seconds, "lease_seconds")
        if lease > _MAX_LEASE_SECONDS:
            raise PrivacyRegulatoryIntelligenceValidationError("lease_seconds is too large")
        moment = _timestamp(self._clock() if now is None else now, "now")
        claimed: list[DeliveryItem] = []
        with self._connect() as connection:
            self._begin(connection)
            rows = connection.execute(
                "SELECT * FROM outbox WHERE tenant_id=? AND "
                "((state='pending' AND next_attempt_at<=?) OR "
                "(state='leased' AND lease_until<=?)) "
                "ORDER BY next_attempt_at,delivery_id LIMIT ?",
                (tenant, moment, moment, result_limit),
            ).fetchall()
            for row in rows:
                payload = self._row_payload(row, "outbox delivery")
                subscription_row = connection.execute(
                    "SELECT * FROM subscriptions WHERE tenant_id=? AND subscription_id=?",
                    (tenant, payload["subscription_id"]),
                ).fetchone()
                if subscription_row is None:
                    raise PrivacyRegulatoryIntelligenceIntegrityError(
                        "delivery references missing subscription"
                    )
                subscription_payload = self._row_payload(
                    subscription_row, "subscription"
                )
                if subscription_payload["state"] != "active":
                    payload.update(
                        {
                            "state": "cancelled",
                            "lease_token": None,
                            "lease_until": None,
                            "revision": int(payload["revision"]) + 1,
                        }
                    )
                else:
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
                    "UPDATE outbox SET state=?,next_attempt_at=?,lease_until=?,"
                    "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND delivery_id=?",
                    (
                        payload["state"],
                        payload["next_attempt_at"],
                        payload["lease_until"],
                        _canonical(payload).decode("ascii"),
                        digest,
                        tenant,
                        payload["delivery_id"],
                    ),
                )
                if payload["state"] == "leased":
                    claimed.append(self._delivery_from(payload, digest))
            connection.commit()
        return tuple(claimed)

    def fail_delivery(
        self,
        tenant_id: str,
        delivery_id: str,
        *,
        lease_token: str,
        error_code: str,
        backoff_seconds: float,
        now: float | None = None,
    ) -> DeliveryItem:
        tenant = _tenant(tenant_id)
        delivery = _identifier(delivery_id, "delivery_id")
        token = _digest(lease_token, "lease_token")
        error = _identifier(error_code, "error_code")
        backoff = _timestamp(backoff_seconds, "backoff_seconds")
        if backoff > _MAX_BACKOFF_SECONDS:
            raise PrivacyRegulatoryIntelligenceValidationError(
                "backoff_seconds is too large"
            )
        moment = _timestamp(self._clock() if now is None else now, "now")
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM outbox WHERE tenant_id=? AND delivery_id=?",
                (tenant, delivery),
            ).fetchone()
            if row is None:
                raise PrivacyRegulatoryIntelligenceNotFound("delivery not found")
            payload = self._row_payload(row, "outbox delivery")
            if (
                payload["state"] != "leased"
                or not hmac.compare_digest(payload["lease_token"] or "", token)
                or float(payload["lease_until"] or 0) < moment
            ):
                raise PrivacyRegulatoryIntelligenceConflict("delivery lease was lost")
            attempt = int(payload["attempt"]) + 1
            payload.update(
                {
                    "state": "dead_letter"
                    if attempt >= int(payload["max_attempts"])
                    else "pending",
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
        return self._delivery_from(payload, digest)

    def acknowledge_delivery(
        self,
        tenant_id: str,
        delivery_id: str,
        *,
        lease_token: str,
        now: float | None = None,
    ) -> DeliveryItem:
        tenant = _tenant(tenant_id)
        delivery = _identifier(delivery_id, "delivery_id")
        token = _digest(lease_token, "lease_token")
        moment = _timestamp(self._clock() if now is None else now, "now")
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM outbox WHERE tenant_id=? AND delivery_id=?",
                (tenant, delivery),
            ).fetchone()
            if row is None:
                raise PrivacyRegulatoryIntelligenceNotFound("delivery not found")
            payload = self._row_payload(row, "outbox delivery")
            if (
                payload["state"] != "leased"
                or not hmac.compare_digest(payload["lease_token"] or "", token)
                or float(payload["lease_until"] or 0) < moment
            ):
                raise PrivacyRegulatoryIntelligenceConflict("delivery lease was lost")
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
                "UPDATE outbox SET state='delivered',lease_until=NULL,"
                "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND delivery_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, delivery),
            )
            connection.commit()
        return self._delivery_from(payload, digest)

    def revoke_subscription(
        self,
        tenant_id: str,
        subscription_id: str,
        *,
        expected_revision: int,
        actor_ref: str,
        now: float | None = None,
    ) -> SavedQuery:
        tenant = _tenant(tenant_id)
        subscription = _identifier(subscription_id, "subscription_id")
        expected = _positive_int(expected_revision, "expected_revision")
        actor = _identifier(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM subscriptions WHERE tenant_id=? AND subscription_id=?",
                (tenant, subscription),
            ).fetchone()
            if row is None:
                raise PrivacyRegulatoryIntelligenceNotFound("subscription not found")
            payload = self._row_payload(row, "subscription")
            if int(payload["revision"]) != expected:
                raise PrivacyRegulatoryIntelligenceConflict(
                    "subscription expected revision does not match"
                )
            payload.update(
                {"state": "revoked", "revision": expected + 1, "updated_at": moment}
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE subscriptions SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND subscription_id=?",
                (_canonical(payload).decode("ascii"), digest, tenant, subscription),
            )
            delivery_rows = connection.execute(
                "SELECT * FROM outbox WHERE tenant_id=? AND subscription_id=? "
                "AND state IN ('pending','leased')",
                (tenant, subscription),
            ).fetchall()
            for delivery_row in delivery_rows:
                delivery_payload = self._row_payload(delivery_row, "outbox delivery")
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
                    "payload_json=?,integrity_sha256=? "
                    "WHERE tenant_id=? AND delivery_id=?",
                    (
                        _canonical(delivery_payload).decode("ascii"),
                        delivery_digest,
                        tenant,
                        delivery_payload["delivery_id"],
                    ),
                )
            self._audit(
                connection,
                tenant,
                "subscription_revoked",
                subscription,
                actor,
                {"cancelled_deliveries": len(delivery_rows)},
                moment,
            )
            connection.commit()
        return self.get_saved_query(tenant, subscription)

    def export_report(
        self,
        tenant_id: str,
        *,
        report_id: str,
        query: str,
        jurisdictions: Sequence[str],
        actor_ref: str,
        idempotency_key: str,
        retention_seconds: int,
        now: float | None = None,
    ) -> EvidenceReport:
        """Persist a bounded report containing evidence, citations and abstentions."""

        tenant = _tenant(tenant_id)
        report = _identifier(report_id, "report_id")
        query_value = _query(query)
        jurisdiction_values = _jurisdictions(jurisdictions)
        actor = _identifier(actor_ref, "actor_ref")
        retention = _retention(retention_seconds)
        moment = _timestamp(self._clock() if now is None else now, "now")
        report_hits = self.search(
            tenant,
            query_value,
            jurisdictions=jurisdiction_values,
            use="reports",
            limit=_MAX_SEARCH_RESULTS,
        )
        answer = self._answer_from_hits(query_value, report_hits, 1)
        request = {
            "action": "export_report",
            "report_id": report,
            "query": query_value,
            "jurisdictions": list(jurisdiction_values),
            "actor_ref": actor,
            "retention_seconds": retention,
            "evidence_sha256": answer.evidence_sha256,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                connection.commit()
                return self.get_report(tenant, report)
            if connection.execute(
                "SELECT 1 FROM reports WHERE tenant_id=? AND report_id=?",
                (tenant, report),
            ).fetchone():
                raise PrivacyRegulatoryIntelligenceConflict("report already exists")
            payload = {
                "schema": REPORT_SCHEMA,
                "tenant_id": tenant,
                "report_id": report,
                "query": query_value,
                "jurisdictions": list(jurisdiction_values),
                "status": answer.status,
                "evidence": [_hit_payload(hit) for hit in answer.evidence],
                "citations": [asdict(citation) for citation in answer.citations],
                "disclaimer": answer.disclaimer,
                "created_by": actor,
                "created_at": moment,
                "retain_until": moment + retention,
            }
            if len(_canonical(payload, maximum=_MAX_REPORT_BYTES)) > _MAX_REPORT_BYTES:
                raise PrivacyRegulatoryIntelligenceValidationError(
                    "report exceeds its export byte bound"
                )
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO reports VALUES(?,?,?,?)",
                (tenant, report, _canonical(payload).decode("ascii"), digest),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "report", report
            )
            self._audit(
                connection,
                tenant,
                "evidence_report_exported",
                report,
                actor,
                {"status": answer.status, "evidence_sha256": answer.evidence_sha256},
                moment,
            )
            connection.commit()
        return self.get_report(tenant, report)

    def get_report(self, tenant_id: str, report_id: str) -> EvidenceReport:
        tenant = _tenant(tenant_id)
        report = _identifier(report_id, "report_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM reports WHERE tenant_id=? AND report_id=?",
                (tenant, report),
            ).fetchone()
        if row is None:
            raise PrivacyRegulatoryIntelligenceNotFound("report not found")
        return self._report_from(
            self._row_payload(row, "report"), row["integrity_sha256"]
        )

    def purge_expired(
        self,
        tenant_id: str,
        *,
        actor_ref: str,
        now: float | None = None,
    ) -> Mapping[str, int]:
        """Apply bounded retention without deleting the tamper-evident audit chain."""

        tenant = _tenant(tenant_id)
        actor = _identifier(actor_ref, "actor_ref")
        moment = _timestamp(self._clock() if now is None else now, "now")
        counts = {"documents": 0, "reports": 0, "shares": 0}
        with self._connect() as connection:
            self._begin(connection)
            document_rows = connection.execute(
                "SELECT * FROM documents WHERE tenant_id=?", (tenant,)
            ).fetchall()
            for row in document_rows:
                payload = self._row_payload(row, "document")
                if float(payload["retain_until"]) <= moment:
                    counts["documents"] += connection.execute(
                        "DELETE FROM documents WHERE tenant_id=? AND document_id=? AND version=?",
                        (tenant, payload["document_id"], payload["version"]),
                    ).rowcount
            report_rows = connection.execute(
                "SELECT * FROM reports WHERE tenant_id=?", (tenant,)
            ).fetchall()
            for row in report_rows:
                payload = self._row_payload(row, "report")
                if float(payload["retain_until"]) <= moment:
                    counts["reports"] += connection.execute(
                        "DELETE FROM reports WHERE tenant_id=? AND report_id=?",
                        (tenant, payload["report_id"]),
                    ).rowcount
            share_rows = connection.execute(
                "SELECT * FROM shares WHERE tenant_id=?", (tenant,)
            ).fetchall()
            for row in share_rows:
                payload = self._row_payload(row, "share")
                if float(payload["expires_at"]) <= moment:
                    counts["shares"] += connection.execute(
                        "DELETE FROM shares WHERE tenant_id=? AND share_id=?",
                        (tenant, payload["share_id"]),
                    ).rowcount
            self._audit(
                connection,
                tenant,
                "retention_purge_completed",
                "retention",
                actor,
                counts,
                moment,
            )
            connection.commit()
        return counts

    def verify_integrity(self, tenant_id: str) -> IntegrityVerification:
        """Verify every retained object and the tenant's complete audit chain."""

        tenant = _tenant(tenant_id)
        verified = 0
        with self._connect() as connection:
            for table, label in (
                ("sources", "source"),
                ("documents", "document"),
                ("collections", "collection"),
                ("shares", "share"),
                ("subscriptions", "subscription"),
                ("alerts", "alert"),
                ("outbox", "outbox delivery"),
                ("reports", "report"),
            ):
                rows = connection.execute(
                    f"SELECT * FROM {table} WHERE tenant_id=?",  # noqa: S608
                    (tenant,),
                ).fetchall()
                for row in rows:
                    payload = self._row_payload(row, label)
                    if table == "documents" and not hmac.compare_digest(
                        payload["content_sha256"], _content_digest(row["content_text"])
                    ):
                        raise PrivacyRegulatoryIntelligenceIntegrityError(
                            "persisted document content failed digest verification"
                        )
                    verified += 1
            audit_rows = connection.execute(
                "SELECT * FROM audit_events WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
        previous = "0" * 64
        expected_sequence = 1
        for row in audit_rows:
            payload = self._row_payload(row, "audit event")
            if (
                int(payload["sequence"]) != expected_sequence
                or payload["previous_sha256"] != previous
            ):
                raise PrivacyRegulatoryIntelligenceIntegrityError(
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
    "CapabilityShare",
    "Citation",
    "DeliveryItem",
    "EvidenceReport",
    "IntegrityVerification",
    "JurisdictionComparison",
    "PrivacyRegulatoryIntelligenceConfigError",
    "PrivacyRegulatoryIntelligenceConflict",
    "PrivacyRegulatoryIntelligenceError",
    "PrivacyRegulatoryIntelligenceIntegrityError",
    "PrivacyRegulatoryIntelligenceNotFound",
    "PrivacyRegulatoryIntelligencePermissionDenied",
    "PrivacyRegulatoryIntelligenceStore",
    "PrivacyRegulatoryIntelligenceValidationError",
    "RegulatoryAlert",
    "RegulatoryDocument",
    "RegulatorySource",
    "ResearchAnswer",
    "ResearchCollection",
    "SavedQuery",
    "SearchHit",
    "enabled",
    "require_enabled",
]
