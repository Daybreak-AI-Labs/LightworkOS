"""Durable downstream remediation for approved privacy-discovery reviews.

The existing privacy-discovery authority calls an injected callback only after
an independently approved review becomes effective.  This module is the
durable, provider-neutral callback target for that seam.  It re-reads only the
public discovery APIs, pins the exact tenant/source/report/finding/review
authority, and persists a bounded digest-only work envelope.

No network client, provider credential, raw location, source value, document
content, or executable remediation expression exists here.  A deployment may
attach an idempotent callback and a read-only reconciliation probe.  Unknown
callback outcomes stop in ``ambiguous`` until that probe proves applied,
no-change, or absent; they are never retried optimistically.
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
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .privacy_data_discovery import (
    EnrolledSource,
    Finding,
    PrivacyDataDiscoveryError,
    ReviewedClassification,
    ReviewProposal,
    ScanReport,
    require_enabled,
)
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
WORK_SCHEMA = "lightwork.privacy-data-discovery-remediation-work.v1"
CLAIM_SCHEMA = "lightwork.privacy-data-discovery-remediation-claim.v1"
AUDIT_SCHEMA = "lightwork.privacy-data-discovery-remediation-audit.v1"

NETWORK_IO = False
PROVIDER_WRITES = False
RAW_LOCATIONS_PERSISTED = False
RAW_VALUES_PERSISTED = False
CREDENTIAL_VALUES_PERSISTED = False
COMPLETENESS_INFERRED = False

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ERROR_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_TOKEN_RE = re.compile(r"lwdrm1\.[A-Za-z0-9_-]{43,96}\Z")
_MAX_JSON_BYTES = 1024 * 1024
_MAX_LIST = 500
_MAX_CLAIM = 100
_MAX_LEASE_SECONDS = 3_600
_MAX_RETRIES = 20
_MAX_BACKOFF_SECONDS = 86_400
_MIN_RETENTION_SECONDS = 60
_MAX_RETENTION_SECONDS = 10 * 366 * 24 * 60 * 60
_MAX_PURGE = 500
_STATES = frozenset(
    {
        "queued",
        "leased",
        "applied",
        "no_change",
        "ambiguous",
        "dead_letter",
        "cancelled",
    }
)
_TERMINAL_STATES = frozenset({"applied", "no_change", "cancelled"})
_CALLBACK_OUTCOMES = frozenset({"applied", "no_change"})
_RECONCILIATION_OUTCOMES = frozenset({"applied", "no_change", "absent", "unknown"})
_FORBIDDEN_KEYS = frozenset(
    {
        "content",
        "credential",
        "credential_env",
        "document_text",
        "location",
        "origin",
        "raw_location",
        "raw_value",
        "resource_ref",
        "sample",
        "secret",
        "source_value",
        "tenant_id",
        "value",
    }
)


class PrivacyDiscoveryRemediationError(RuntimeError):
    """Base durable-remediation error."""


class PrivacyDiscoveryRemediationConfigError(PrivacyDiscoveryRemediationError):
    """The feature gate or a constructor-bound authority is unavailable."""


class PrivacyDiscoveryRemediationValidationError(PrivacyDiscoveryRemediationError, ValueError):
    """Input is outside the closed remediation contract."""


class PrivacyDiscoveryRemediationConflict(PrivacyDiscoveryRemediationError):
    """An idempotency, state, or revision precondition changed."""


class PrivacyDiscoveryRemediationNotFound(PrivacyDiscoveryRemediationError):
    """A tenant-bound remediation record is absent."""


class PrivacyDiscoveryRemediationLeaseLost(PrivacyDiscoveryRemediationError):
    """A worker no longer owns the exact remediation lease."""


class PrivacyDiscoveryRemediationIntegrityError(PrivacyDiscoveryRemediationError):
    """Persisted or resolved authority failed exact integrity validation."""


class PrivacyDiscoveryRemediationAuthorityError(PrivacyDiscoveryRemediationError):
    """The approved discovery authority is unavailable, stale, or revoked."""


class RemediationCallbackError(PrivacyDiscoveryRemediationError):
    """Closed callback failure with no raw provider text."""

    def __init__(self, error_code: str) -> None:
        self.error_code = _error_code(error_code)
        super().__init__(self.error_code)


class RemediationRetryableError(RemediationCallbackError):
    """The callback proved no effect and may be retried with backoff."""


class RemediationPermanentError(RemediationCallbackError):
    """The callback proved a permanent no-effect failure."""


class RemediationAmbiguousError(RemediationCallbackError):
    """The callback outcome may have taken effect and must be reconciled."""


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
        raise PrivacyDiscoveryRemediationValidationError(
            "remediation metadata must be finite canonical JSON"
        ) from exc
    if len(encoded) > maximum:
        raise PrivacyDiscoveryRemediationValidationError(
            "remediation metadata exceeds its byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _same(left: object, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return hmac.compare_digest(left, right)
    except (TypeError, ValueError):
        return False


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(str(value))
    except (TypeError, ValueError) as exc:
        raise PrivacyDiscoveryRemediationValidationError("tenant binding is invalid") from exc


def _ref(value: object, label: str, *, operation: bool = False) -> str:
    pattern = _OP_RE if operation else _REF_RE
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PrivacyDiscoveryRemediationValidationError(
            f"{label} must be a bounded opaque identifier"
        )
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise PrivacyDiscoveryRemediationValidationError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PrivacyDiscoveryRemediationValidationError(f"{label} must be finite")
    result = float(value)
    if not math.isfinite(result):
        raise PrivacyDiscoveryRemediationValidationError(f"{label} must be finite")
    return result


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PrivacyDiscoveryRemediationValidationError(f"{label} is outside its bound")
    return value


def _error_code(value: object) -> str:
    if not isinstance(value, str) or not _ERROR_RE.fullmatch(value):
        raise PrivacyDiscoveryRemediationValidationError("error_code is invalid")
    return value


def _privacy_safe(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str) or key.lower() in _FORBIDDEN_KEYS:
                raise PrivacyDiscoveryRemediationIntegrityError(
                    "remediation metadata contains a forbidden field"
                )
            _privacy_safe(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _privacy_safe(child)
    elif isinstance(value, str):
        if len(value) > 512 or any(ord(character) < 32 for character in value):
            raise PrivacyDiscoveryRemediationIntegrityError(
                "remediation metadata contains unsafe text"
            )
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise PrivacyDiscoveryRemediationIntegrityError(
            "remediation metadata contains an unsupported value"
        )


@dataclass(frozen=True, slots=True)
class ResolvedRemediationAuthority:
    tenant_sha256: str
    source_id: str
    source_revision: int
    source_integrity_sha256: str
    report_id: str
    report_integrity_sha256: str
    report_retention_until: float
    report_completeness_sha256: str
    finding_id: str
    finding_revision: int
    finding_integrity_sha256: str
    review_id: str
    review_version: int
    review_integrity_sha256: str
    decision: str
    category: str | None
    evidence_sha256: str
    reviewed_at: float
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class RemediationWork:
    work_id: str
    tenant_sha256: str
    source_id: str
    source_revision: int
    source_integrity_sha256: str
    report_id: str
    report_integrity_sha256: str
    report_retention_until: float
    report_completeness_sha256: str
    finding_id: str
    finding_revision: int
    finding_integrity_sha256: str
    review_id: str
    review_version: int
    review_integrity_sha256: str
    decision: str
    category: str | None
    evidence_sha256: str
    reviewed_at: float
    authority_sha256: str
    callback_idempotency_sha256: str
    state: str
    attempts: int
    max_attempts: int
    next_attempt_at: float
    lease_owner_sha256: str | None
    lease_token_sha256: str | None
    lease_until: float | None
    last_error_code: str | None
    receipt_sha256: str | None
    ambiguous_at: float | None
    retained_until: float
    created_at: float
    updated_at: float
    revision: int
    previous_integrity_sha256: str
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class RemediationEnqueueResult:
    work: RemediationWork
    created: bool
    no_change: bool


@dataclass(frozen=True, slots=True)
class RemediationClaim:
    schema: str
    work_id: str
    tenant_sha256: str
    source_id: str
    report_id: str
    finding_id: str
    review_id: str
    review_version: int
    decision: str
    category: str | None
    evidence_sha256: str
    authority_sha256: str
    callback_idempotency_sha256: str
    report_completeness_sha256: str
    completeness_claimed: bool
    attempt: int
    lease_owner_sha256: str
    lease_token: str
    lease_until: float
    work_revision: int


@dataclass(frozen=True, slots=True)
class RemediationCallbackResult:
    outcome: str
    receipt_sha256: str
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class RemediationReconciliationResult:
    outcome: str
    authority_sha256: str
    receipt_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class RemediationReconciliationProbe:
    schema: str
    work_id: str
    tenant_sha256: str
    source_id: str
    report_id: str
    finding_id: str
    review_id: str
    review_version: int
    decision: str
    category: str | None
    evidence_sha256: str
    authority_sha256: str
    callback_idempotency_sha256: str
    report_completeness_sha256: str
    completeness_claimed: bool
    attempt: int


@dataclass(frozen=True, slots=True)
class RemediationWorkerResult:
    claimed: int
    applied: int
    no_change: int
    retried: int
    ambiguous: int
    dead_lettered: int
    cancelled: int


@dataclass(frozen=True, slots=True)
class RemediationIntegrityVerification:
    current_records: int
    history_records: int
    operation_records: int
    audit_events: int
    terminal_audit_sha256: str


class RemediationCallback(Protocol):
    def __call__(self, claim: RemediationClaim) -> RemediationCallbackResult: ...


class RemediationReconciler(Protocol):
    def __call__(
        self, _probe: RemediationReconciliationProbe
    ) -> RemediationReconciliationResult: ...


def _authority_payload(authority: ResolvedRemediationAuthority) -> dict[str, object]:
    payload = asdict(authority)
    payload.pop("authority_sha256", None)
    return payload


def _work_payload(work: RemediationWork) -> dict[str, object]:
    payload = asdict(work)
    payload.pop("integrity_sha256", None)
    payload["schema"] = WORK_SCHEMA
    return payload


class PrivacyDataDiscoveryRemediationStore:
    """Private per-tenant SQLite outbox for approved discovery classifications."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        discovery_store: object,
        principal_resolver: Callable[[], str | None],
        config_gate: Callable[[], None] = require_enabled,
        clock: Callable[[], float] = time.time,
        lease_token_factory: Callable[[], str] = lambda: "lwdrm1." + secrets.token_urlsafe(32),
        default_max_attempts: int = 5,
        default_retention_seconds: int = 30 * 24 * 60 * 60,
    ) -> None:
        if not all(
            callable(item) for item in (principal_resolver, config_gate, clock, lease_token_factory)
        ):
            raise PrivacyDiscoveryRemediationConfigError(
                "remediation dependencies must be callable"
            )
        required = (
            "get_source",
            "get_report",
            "get_finding",
            "get_review",
            "list_reviews",
        )
        if any(not callable(getattr(discovery_store, name, None)) for name in required):
            raise PrivacyDiscoveryRemediationConfigError(
                "discovery authority does not expose the required public reads"
            )
        config_gate()
        self.path = Path(path)
        self._tenant_id = _tenant(tenant_id)
        self._tenant_sha256 = _sha256(
            {
                "schema": "lightwork.privacy-data-discovery-remediation-tenant.v1",
                "tenant": self._tenant_id,
            }
        )
        self._discovery = discovery_store
        self._principal_resolver = principal_resolver
        self._gate = config_gate
        self._clock = clock
        self._token_factory = lease_token_factory
        self._default_max_attempts = _integer(
            default_max_attempts,
            "default_max_attempts",
            1,
            _MAX_RETRIES,
        )
        self._default_retention_seconds = _integer(
            default_retention_seconds,
            "default_retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        )
        ensure_private_directory(self.path.parent)
        self._initialize()
        ensure_private_file(self.path)

    def _check_gate(self) -> None:
        try:
            self._gate()
        except PrivacyDataDiscoveryError as exc:
            raise PrivacyDiscoveryRemediationConfigError(
                "privacy discovery remediation is disabled"
            ) from exc
        except Exception as exc:
            raise PrivacyDiscoveryRemediationConfigError(
                "privacy discovery remediation gate is unavailable"
            ) from exc

    def _now(self) -> float:
        return _timestamp(self._clock(), "current time")

    def _actor_sha256(self) -> str:
        try:
            principal = self._principal_resolver()
        except Exception as exc:
            raise PrivacyDiscoveryRemediationConfigError(
                "remediation principal authority is unavailable"
            ) from exc
        if not isinstance(principal, str) or not principal or len(principal) > 512:
            raise PrivacyDiscoveryRemediationConfigError(
                "remediation principal authority is unavailable"
            )
        return _sha256(
            {
                "schema": "lightwork.privacy-data-discovery-remediation-principal.v1",
                "tenant_sha256": self._tenant_sha256,
                "principal": principal,
            }
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, SCHEMA_VERSION):
                raise PrivacyDiscoveryRemediationConfigError(
                    "unsupported remediation schema version"
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS remediation_work(
                    tenant_sha256 TEXT NOT NULL,
                    work_id TEXT NOT NULL,
                    review_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    next_attempt_at REAL NOT NULL,
                    lease_until REAL,
                    retained_until REAL NOT NULL,
                    revision INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,work_id),
                    UNIQUE(tenant_sha256,review_id)
                );
                CREATE INDEX IF NOT EXISTS remediation_ready
                    ON remediation_work(tenant_sha256,state,next_attempt_at,work_id);
                CREATE TABLE IF NOT EXISTS remediation_history(
                    tenant_sha256 TEXT NOT NULL,
                    work_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,work_id,revision)
                );
                CREATE TABLE IF NOT EXISTS remediation_operations(
                    tenant_sha256 TEXT NOT NULL,
                    operation_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    result_kind TEXT NOT NULL,
                    result_id TEXT NOT NULL,
                    result_revision INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(tenant_sha256,operation_sha256)
                );
                CREATE TABLE IF NOT EXISTS remediation_audit(
                    tenant_sha256 TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS remediation_history_no_update
                BEFORE UPDATE ON remediation_history
                BEGIN SELECT RAISE(ABORT,'remediation history is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS remediation_operations_no_update
                BEFORE UPDATE ON remediation_operations
                BEGIN SELECT RAISE(ABORT,'remediation operations are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS remediation_audit_no_update
                BEFORE UPDATE ON remediation_audit
                BEGIN SELECT RAISE(ABORT,'remediation audit is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS remediation_audit_no_delete
                BEFORE DELETE ON remediation_audit
                BEGIN SELECT RAISE(ABORT,'remediation audit is immutable'); END;
                """
            )
            connection.execute("DROP TRIGGER IF EXISTS remediation_history_no_delete")
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            connection.commit()

    @staticmethod
    def _row_payload(row: sqlite3.Row, label: str) -> tuple[dict[str, Any], str]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PrivacyDiscoveryRemediationIntegrityError(f"stored {label} is invalid") from exc
        if not isinstance(payload, dict):
            raise PrivacyDiscoveryRemediationIntegrityError(f"stored {label} is invalid")
        digest_value = str(row["integrity_sha256"])
        if not _same(_sha256(payload), digest_value):
            raise PrivacyDiscoveryRemediationIntegrityError(f"stored {label} failed integrity")
        _privacy_safe(payload)
        return payload, digest_value

    def _validated_work(
        self,
        payload: Mapping[str, object],
        integrity_sha256: str,
    ) -> RemediationWork:
        expected = set(RemediationWork.__dataclass_fields__) - {"integrity_sha256"}
        body = dict(payload)
        if body.pop("schema", None) != WORK_SCHEMA or set(body) != expected:
            raise PrivacyDiscoveryRemediationIntegrityError("remediation work fields are invalid")
        try:
            work_id = _ref(body["work_id"], "work_id")
            tenant_sha = _digest(body["tenant_sha256"], "tenant_sha256")
            if not _same(tenant_sha, self._tenant_sha256):
                raise PrivacyDiscoveryRemediationIntegrityError(
                    "remediation tenant binding is invalid"
                )
            source_id = _ref(body["source_id"], "source_id")
            report_id = _ref(body["report_id"], "report_id")
            finding_id = _ref(body["finding_id"], "finding_id")
            review_id = _ref(body["review_id"], "review_id")
            source_revision = _integer(body["source_revision"], "source_revision", 1, 2**31 - 1)
            finding_revision = _integer(body["finding_revision"], "finding_revision", 1, 2**31 - 1)
            review_version = _integer(body["review_version"], "review_version", 1, 2**31 - 1)
            source_sha = _digest(body["source_integrity_sha256"], "source_integrity_sha256")
            report_sha = _digest(body["report_integrity_sha256"], "report_integrity_sha256")
            completeness_sha = _digest(
                body["report_completeness_sha256"],
                "report_completeness_sha256",
            )
            finding_sha = _digest(body["finding_integrity_sha256"], "finding_integrity_sha256")
            review_sha = _digest(body["review_integrity_sha256"], "review_integrity_sha256")
            evidence_sha = _digest(body["evidence_sha256"], "evidence_sha256")
            authority_sha = _digest(body["authority_sha256"], "authority_sha256")
            callback_sha = _digest(
                body["callback_idempotency_sha256"],
                "callback_idempotency_sha256",
            )
            decision = _ref(body["decision"], "decision")
            if decision not in {"confirmed", "reclassified", "false_positive"}:
                raise PrivacyDiscoveryRemediationIntegrityError("remediation decision is invalid")
            category_value = body["category"]
            category = None if category_value is None else _ref(category_value, "category")
            if (decision == "false_positive") != (category is None):
                raise PrivacyDiscoveryRemediationIntegrityError(
                    "remediation category does not match its decision"
                )
            reviewed_at = _timestamp(body["reviewed_at"], "reviewed_at")
            report_retention = _timestamp(body["report_retention_until"], "report_retention_until")
            state = _ref(body["state"], "state")
            if state not in _STATES:
                raise PrivacyDiscoveryRemediationIntegrityError("remediation state is invalid")
            attempts = _integer(body["attempts"], "attempts", 0, _MAX_RETRIES)
            max_attempts = _integer(body["max_attempts"], "max_attempts", 1, _MAX_RETRIES)
            if attempts > max_attempts:
                raise PrivacyDiscoveryRemediationIntegrityError(
                    "remediation attempts exceed their bound"
                )
            next_attempt = _timestamp(body["next_attempt_at"], "next_attempt_at")
            owner_value = body["lease_owner_sha256"]
            owner = None if owner_value is None else _digest(owner_value, "lease_owner_sha256")
            token_value = body["lease_token_sha256"]
            token = None if token_value is None else _digest(token_value, "lease_token_sha256")
            lease_value = body["lease_until"]
            lease_until = None if lease_value is None else _timestamp(lease_value, "lease_until")
            error_value = body["last_error_code"]
            error = None if error_value is None else _error_code(error_value)
            receipt_value = body["receipt_sha256"]
            receipt = None if receipt_value is None else _digest(receipt_value, "receipt_sha256")
            ambiguous_value = body["ambiguous_at"]
            ambiguous_at = (
                None if ambiguous_value is None else _timestamp(ambiguous_value, "ambiguous_at")
            )
            retained_until = _timestamp(body["retained_until"], "retained_until")
            created_at = _timestamp(body["created_at"], "created_at")
            updated_at = _timestamp(body["updated_at"], "updated_at")
            revision = _integer(body["revision"], "revision", 1, 2**31 - 1)
            previous_sha = _digest(
                body["previous_integrity_sha256"],
                "previous_integrity_sha256",
            )
            if not created_at <= updated_at <= retained_until <= report_retention:
                raise PrivacyDiscoveryRemediationIntegrityError(
                    "remediation retention binding is invalid"
                )
            if state == "queued" and any(
                value is not None for value in (owner, token, lease_until, ambiguous_at, receipt)
            ):
                raise PrivacyDiscoveryRemediationIntegrityError(
                    "queued remediation contains terminal or lease evidence"
                )
            if state == "leased" and (
                any(value is None for value in (owner, token, lease_until))
                or ambiguous_at is not None
                or receipt is not None
            ):
                raise PrivacyDiscoveryRemediationIntegrityError(
                    "leased remediation evidence is invalid"
                )
            if state == "ambiguous" and (
                owner is None
                or token is None
                or lease_until is not None
                or ambiguous_at is None
                or receipt is not None
            ):
                raise PrivacyDiscoveryRemediationIntegrityError(
                    "ambiguous remediation evidence is invalid"
                )
            if state in {"applied", "no_change"} and (
                owner is None
                or token is None
                or lease_until is not None
                or receipt is None
                or ambiguous_at is not None
            ):
                raise PrivacyDiscoveryRemediationIntegrityError(
                    "completed remediation evidence is invalid"
                )
            if state in {"dead_letter", "cancelled"} and any(
                value is not None for value in (owner, token, lease_until, ambiguous_at, receipt)
            ):
                raise PrivacyDiscoveryRemediationIntegrityError(
                    "stopped remediation retains unsafe lease evidence"
                )
            if state not in {"ambiguous", "applied", "no_change"} and receipt is not None:
                raise PrivacyDiscoveryRemediationIntegrityError(
                    "remediation receipt state is invalid"
                )
        except PrivacyDiscoveryRemediationIntegrityError:
            raise
        except PrivacyDiscoveryRemediationError as exc:
            raise PrivacyDiscoveryRemediationIntegrityError(
                "remediation work validation failed"
            ) from exc
        return RemediationWork(
            work_id=work_id,
            tenant_sha256=tenant_sha,
            source_id=source_id,
            source_revision=source_revision,
            source_integrity_sha256=source_sha,
            report_id=report_id,
            report_integrity_sha256=report_sha,
            report_retention_until=report_retention,
            report_completeness_sha256=completeness_sha,
            finding_id=finding_id,
            finding_revision=finding_revision,
            finding_integrity_sha256=finding_sha,
            review_id=review_id,
            review_version=review_version,
            review_integrity_sha256=review_sha,
            decision=decision,
            category=category,
            evidence_sha256=evidence_sha,
            reviewed_at=reviewed_at,
            authority_sha256=authority_sha,
            callback_idempotency_sha256=callback_sha,
            state=state,
            attempts=attempts,
            max_attempts=max_attempts,
            next_attempt_at=next_attempt,
            lease_owner_sha256=owner,
            lease_token_sha256=token,
            lease_until=lease_until,
            last_error_code=error,
            receipt_sha256=receipt,
            ambiguous_at=ambiguous_at,
            retained_until=retained_until,
            created_at=created_at,
            updated_at=updated_at,
            revision=revision,
            previous_integrity_sha256=previous_sha,
            integrity_sha256=_digest(integrity_sha256, "integrity_sha256"),
        )

    def _work_from_row(self, row: sqlite3.Row) -> RemediationWork:
        payload, digest_value = self._row_payload(row, "remediation work")
        work = self._validated_work(payload, digest_value)
        if (
            row["tenant_sha256"] != work.tenant_sha256
            or row["work_id"] != work.work_id
            or row["review_id"] != work.review_id
            or row["state"] != work.state
            or float(row["next_attempt_at"]) != work.next_attempt_at
            or (None if row["lease_until"] is None else float(row["lease_until"]))
            != work.lease_until
            or float(row["retained_until"]) != work.retained_until
            or int(row["revision"]) != work.revision
        ):
            raise PrivacyDiscoveryRemediationIntegrityError(
                "remediation work indexes are inconsistent"
            )
        return work

    def _insert_work(self, connection: sqlite3.Connection, work: RemediationWork) -> None:
        payload = _work_payload(work)
        digest_value = _sha256(payload)
        stored = replace(work, integrity_sha256=digest_value)
        self._validated_work(payload, digest_value)
        values = (
            stored.tenant_sha256,
            stored.work_id,
            stored.review_id,
            stored.state,
            stored.next_attempt_at,
            stored.lease_until,
            stored.retained_until,
            stored.revision,
            _canonical(payload).decode("ascii"),
            digest_value,
        )
        connection.execute(
            "INSERT INTO remediation_work VALUES(?,?,?,?,?,?,?,?,?,?)",
            values,
        )
        connection.execute(
            "INSERT INTO remediation_history VALUES(?,?,?,?,?,?)",
            (
                stored.tenant_sha256,
                stored.work_id,
                stored.revision,
                stored.state,
                _canonical(payload).decode("ascii"),
                digest_value,
            ),
        )

    def _replace_work(
        self,
        connection: sqlite3.Connection,
        previous: RemediationWork,
        **changes: object,
    ) -> RemediationWork:
        candidate = replace(
            previous,
            **changes,
            revision=previous.revision + 1,
            previous_integrity_sha256=previous.integrity_sha256,
            integrity_sha256="0" * 64,
        )
        payload = _work_payload(candidate)
        digest_value = _sha256(payload)
        candidate = replace(candidate, integrity_sha256=digest_value)
        self._validated_work(payload, digest_value)
        changed = connection.execute(
            "UPDATE remediation_work SET state=?,next_attempt_at=?,lease_until=?,"
            "retained_until=?,revision=?,payload_json=?,integrity_sha256=? "
            "WHERE tenant_sha256=? AND work_id=? AND revision=?",
            (
                candidate.state,
                candidate.next_attempt_at,
                candidate.lease_until,
                candidate.retained_until,
                candidate.revision,
                _canonical(payload).decode("ascii"),
                digest_value,
                candidate.tenant_sha256,
                candidate.work_id,
                previous.revision,
            ),
        ).rowcount
        if changed != 1:
            raise PrivacyDiscoveryRemediationConflict("remediation revision CAS failed")
        connection.execute(
            "INSERT INTO remediation_history VALUES(?,?,?,?,?,?)",
            (
                candidate.tenant_sha256,
                candidate.work_id,
                candidate.revision,
                candidate.state,
                _canonical(payload).decode("ascii"),
                digest_value,
            ),
        )
        return candidate

    def _audit(
        self,
        connection: sqlite3.Connection,
        event_type: str,
        subject: str,
        actor_sha256: str,
        details: Mapping[str, object],
        occurred_at: float,
    ) -> None:
        event = _error_code(event_type)
        subject_sha = _text_sha256(_ref(subject, "audit subject"))
        actor_sha = _digest(actor_sha256, "actor_sha256")
        safe_details = dict(details)
        _privacy_safe(safe_details)
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM remediation_audit "
            "WHERE tenant_sha256=? ORDER BY sequence DESC LIMIT 1",
            (self._tenant_sha256,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = "0" * 64 if previous is None else str(previous["integrity_sha256"])
        payload = {
            "schema": AUDIT_SCHEMA,
            "sequence": sequence,
            "event_type": event,
            "subject_sha256": subject_sha,
            "actor_sha256": actor_sha,
            "details": safe_details,
            "occurred_at": occurred_at,
            "previous_integrity_sha256": previous_sha,
        }
        digest_value = _sha256(payload)
        connection.execute(
            "INSERT INTO remediation_audit VALUES(?,?,?,?)",
            (
                self._tenant_sha256,
                sequence,
                _canonical(payload).decode("ascii"),
                digest_value,
            ),
        )

    def _operation(
        self,
        connection: sqlite3.Connection,
        idempotency_key: str,
        request: Mapping[str, object],
    ) -> sqlite3.Row | None:
        key = _ref(idempotency_key, "idempotency_key", operation=True)
        operation_sha = _text_sha256(key)
        request_sha = _sha256(dict(request))
        row = connection.execute(
            "SELECT * FROM remediation_operations WHERE tenant_sha256=? AND operation_sha256=?",
            (self._tenant_sha256, operation_sha),
        ).fetchone()
        if row is not None and not _same(row["request_sha256"], request_sha):
            raise PrivacyDiscoveryRemediationConflict(
                "idempotency key is bound to another exact request"
            )
        return row

    def _record_operation(
        self,
        connection: sqlite3.Connection,
        idempotency_key: str,
        request: Mapping[str, object],
        result_kind: str,
        result_id: str,
        result_revision: int,
        created_at: float,
    ) -> None:
        key = _ref(idempotency_key, "idempotency_key", operation=True)
        connection.execute(
            "INSERT INTO remediation_operations VALUES(?,?,?,?,?,?,?)",
            (
                self._tenant_sha256,
                _text_sha256(key),
                _sha256(dict(request)),
                _ref(result_kind, "result_kind"),
                _ref(result_id, "result_id"),
                _integer(result_revision, "result_revision", 0, 2**31 - 1),
                created_at,
            ),
        )

    def _safe_discovery_call(self, method: str, *args: object, **kwargs: object) -> Any:
        try:
            return getattr(self._discovery, method)(*args, **kwargs)
        except (PrivacyDataDiscoveryError, OSError) as exc:
            raise PrivacyDiscoveryRemediationAuthorityError(
                "approved discovery authority is unavailable"
            ) from exc
        except Exception as exc:
            raise PrivacyDiscoveryRemediationAuthorityError(
                "approved discovery authority is unavailable"
            ) from exc

    def _resolve_once(
        self,
        update: ReviewedClassification,
        now: float,
    ) -> ResolvedRemediationAuthority:
        if type(update) is not ReviewedClassification:
            raise PrivacyDiscoveryRemediationValidationError(
                "review callback uses an invalid exact type"
            )
        if _tenant(update.tenant_id) != self._tenant_id:
            raise PrivacyDiscoveryRemediationAuthorityError(
                "review callback tenant binding is invalid"
            )
        source_id = _ref(update.source_id, "source_id")
        report_id = _ref(update.report_id, "report_id")
        finding_id = _ref(update.finding_id, "finding_id")
        review_id = _ref(update.review_id, "review_id")
        source = self._safe_discovery_call("get_source", self._tenant_id, source_id)
        report = self._safe_discovery_call("get_report", self._tenant_id, report_id)
        finding = self._safe_discovery_call("get_finding", self._tenant_id, finding_id)
        review = self._safe_discovery_call("get_review", self._tenant_id, review_id)
        latest = self._safe_discovery_call(
            "list_reviews",
            self._tenant_id,
            finding_id=finding_id,
            limit=1,
        )
        if (
            type(source) is not EnrolledSource
            or type(report) is not ScanReport
            or type(finding) is not Finding
            or type(review) is not ReviewProposal
            or not isinstance(latest, tuple)
            or len(latest) != 1
            or type(latest[0]) is not ReviewProposal
        ):
            raise PrivacyDiscoveryRemediationAuthorityError(
                "approved discovery authority returned an invalid contract"
            )
        latest_review = latest[0]
        category = review.effective_category
        if (
            source.tenant_id != self._tenant_id
            or source.source_id != source_id
            or source.state != "active"
            or report.tenant_id != self._tenant_id
            or report.report_id != report_id
            or report.source_id != source_id
            or report.retention_until <= now
            or finding.tenant_id != self._tenant_id
            or finding.finding_id != finding_id
            or finding.report_id != report_id
            or finding.source_id != source_id
            or review.tenant_id != self._tenant_id
            or review.review_id != review_id
            or review.finding_id != finding_id
            or review.status != "approved"
            or latest_review != review
            or update.review_version != review.version
            or update.decision != review.decision
            or update.category != category
            or update.evidence_sha256 != review.evidence_sha256
            or update.reviewed_at != review.approved_at
        ):
            raise PrivacyDiscoveryRemediationAuthorityError(
                "approved discovery authority is stale or revoked"
            )
        if (review.decision == "false_positive") != (category is None):
            raise PrivacyDiscoveryRemediationAuthorityError(
                "approved classification category is invalid"
            )
        completeness_sha = _sha256(
            {
                "schema": "lightwork.privacy-data-discovery-remediation-completeness.v1",
                "completeness": report.completeness,
                "truncation_reasons": list(report.truncation_reasons),
                "error_codes": list(report.error_codes),
                "limitations": list(report.limitations),
                "completeness_claimed": False,
            }
        )
        provisional = ResolvedRemediationAuthority(
            tenant_sha256=self._tenant_sha256,
            source_id=source_id,
            source_revision=source.revision,
            source_integrity_sha256=_digest(source.integrity_sha256, "source.integrity_sha256"),
            report_id=report_id,
            report_integrity_sha256=_digest(report.integrity_sha256, "report.integrity_sha256"),
            report_retention_until=report.retention_until,
            report_completeness_sha256=completeness_sha,
            finding_id=finding_id,
            finding_revision=finding.revision,
            finding_integrity_sha256=_digest(finding.integrity_sha256, "finding.integrity_sha256"),
            review_id=review_id,
            review_version=review.version,
            review_integrity_sha256=_digest(review.integrity_sha256, "review.integrity_sha256"),
            decision=review.decision,
            category=category,
            evidence_sha256=_digest(review.evidence_sha256, "review.evidence_sha256"),
            reviewed_at=_timestamp(review.approved_at, "review.approved_at"),
            authority_sha256="0" * 64,
        )
        return replace(
            provisional,
            authority_sha256=_sha256(_authority_payload(provisional)),
        )

    def _resolve_update(
        self,
        update: ReviewedClassification,
        now: float,
    ) -> ResolvedRemediationAuthority:
        first = self._resolve_once(update, now)
        second = self._resolve_once(update, now)
        if first != second:
            raise PrivacyDiscoveryRemediationAuthorityError(
                "approved discovery authority drifted during resolution"
            )
        return second

    @staticmethod
    def _update_from_work(work: RemediationWork) -> ReviewedClassification:
        return ReviewedClassification(
            tenant_id="invalid-placeholder",
            source_id=work.source_id,
            report_id=work.report_id,
            finding_id=work.finding_id,
            review_id=work.review_id,
            decision=work.decision,
            category=work.category,
            evidence_sha256=work.evidence_sha256,
            reviewed_at=work.reviewed_at,
            review_version=work.review_version,
        )

    def _resolve_work(
        self,
        work: RemediationWork,
        now: float,
    ) -> ResolvedRemediationAuthority:
        update = replace(self._update_from_work(work), tenant_id=self._tenant_id)
        authority = self._resolve_update(update, now)
        expected = ResolvedRemediationAuthority(
            tenant_sha256=work.tenant_sha256,
            source_id=work.source_id,
            source_revision=work.source_revision,
            source_integrity_sha256=work.source_integrity_sha256,
            report_id=work.report_id,
            report_integrity_sha256=work.report_integrity_sha256,
            report_retention_until=work.report_retention_until,
            report_completeness_sha256=work.report_completeness_sha256,
            finding_id=work.finding_id,
            finding_revision=work.finding_revision,
            finding_integrity_sha256=work.finding_integrity_sha256,
            review_id=work.review_id,
            review_version=work.review_version,
            review_integrity_sha256=work.review_integrity_sha256,
            decision=work.decision,
            category=work.category,
            evidence_sha256=work.evidence_sha256,
            reviewed_at=work.reviewed_at,
            authority_sha256=work.authority_sha256,
        )
        if authority != expected:
            raise PrivacyDiscoveryRemediationAuthorityError(
                "approved discovery authority changed after enqueue"
            )
        return authority

    def _get_work_row(
        self,
        connection: sqlite3.Connection,
        work_id: str,
    ) -> RemediationWork:
        work = _ref(work_id, "work_id")
        row = connection.execute(
            "SELECT * FROM remediation_work WHERE tenant_sha256=? AND work_id=?",
            (self._tenant_sha256, work),
        ).fetchone()
        if row is None:
            raise PrivacyDiscoveryRemediationNotFound("remediation work was not found")
        return self._work_from_row(row)

    def enqueue_review(
        self,
        update: ReviewedClassification,
        *,
        max_attempts: int | None = None,
        retention_seconds: int | None = None,
    ) -> RemediationEnqueueResult:
        """Durably enqueue one exact, currently approved classification."""

        self._check_gate()
        now = self._now()
        actor_sha = self._actor_sha256()
        authority = self._resolve_update(update, now)
        attempts_bound = (
            self._default_max_attempts
            if max_attempts is None
            else _integer(
                max_attempts,
                "max_attempts",
                1,
                _MAX_RETRIES,
            )
        )
        retention_bound = (
            self._default_retention_seconds
            if retention_seconds is None
            else _integer(
                retention_seconds,
                "retention_seconds",
                _MIN_RETENTION_SECONDS,
                _MAX_RETENTION_SECONDS,
            )
        )
        retained_until = min(now + retention_bound, authority.report_retention_until)
        if retained_until < now + _MIN_RETENTION_SECONDS:
            raise PrivacyDiscoveryRemediationAuthorityError(
                "approved report retention is too short for remediation"
            )
        work_identity = _sha256(
            {
                "schema": "lightwork.privacy-data-discovery-remediation-identity.v1",
                "tenant_sha256": self._tenant_sha256,
                "review_id": authority.review_id,
                "review_version": authority.review_version,
            }
        )
        work_id = f"PDRM-{work_identity[:32]}"
        callback_sha = _sha256(
            {
                "schema": "lightwork.privacy-data-discovery-remediation-callback-key.v1",
                "work_id": work_id,
                "authority_sha256": authority.authority_sha256,
            }
        )
        initial = RemediationWork(
            work_id=work_id,
            tenant_sha256=self._tenant_sha256,
            source_id=authority.source_id,
            source_revision=authority.source_revision,
            source_integrity_sha256=authority.source_integrity_sha256,
            report_id=authority.report_id,
            report_integrity_sha256=authority.report_integrity_sha256,
            report_retention_until=authority.report_retention_until,
            report_completeness_sha256=authority.report_completeness_sha256,
            finding_id=authority.finding_id,
            finding_revision=authority.finding_revision,
            finding_integrity_sha256=authority.finding_integrity_sha256,
            review_id=authority.review_id,
            review_version=authority.review_version,
            review_integrity_sha256=authority.review_integrity_sha256,
            decision=authority.decision,
            category=authority.category,
            evidence_sha256=authority.evidence_sha256,
            reviewed_at=authority.reviewed_at,
            authority_sha256=authority.authority_sha256,
            callback_idempotency_sha256=callback_sha,
            state="queued",
            attempts=0,
            max_attempts=attempts_bound,
            next_attempt_at=now,
            lease_owner_sha256=None,
            lease_token_sha256=None,
            lease_until=None,
            last_error_code=None,
            receipt_sha256=None,
            ambiguous_at=None,
            retained_until=retained_until,
            created_at=now,
            updated_at=now,
            revision=1,
            previous_integrity_sha256="0" * 64,
            integrity_sha256="0" * 64,
        )
        created = False
        with self._connect() as connection:
            self._begin(connection)
            existing_row = connection.execute(
                "SELECT * FROM remediation_work WHERE tenant_sha256=? AND review_id=?",
                (self._tenant_sha256, authority.review_id),
            ).fetchone()
            if existing_row is None:
                try:
                    self._insert_work(connection, initial)
                except sqlite3.IntegrityError as exc:
                    raise PrivacyDiscoveryRemediationConflict(
                        "remediation work identity collided"
                    ) from exc
                self._audit(
                    connection,
                    "review_enqueued",
                    work_id,
                    actor_sha,
                    {
                        "authority_sha256": authority.authority_sha256,
                        "review_version": authority.review_version,
                        "callback_idempotency_sha256": callback_sha,
                    },
                    now,
                )
                created = True
            else:
                existing = self._work_from_row(existing_row)
                if (
                    existing.work_id != work_id
                    or existing.authority_sha256 != authority.authority_sha256
                    or existing.callback_idempotency_sha256 != callback_sha
                ):
                    raise PrivacyDiscoveryRemediationConflict(
                        "review is already bound to different remediation authority"
                    )
            connection.commit()
        work = self.get_work(work_id)
        return RemediationEnqueueResult(
            work=work,
            created=created,
            no_change=not created,
        )

    def make_review_callback(
        self,
        *,
        max_attempts: int | None = None,
        retention_seconds: int | None = None,
    ) -> Callable[[ReviewedClassification], None]:
        """Return the approved-review callback expected by the discovery store."""

        def callback(update: ReviewedClassification) -> None:
            self.enqueue_review(
                update,
                max_attempts=max_attempts,
                retention_seconds=retention_seconds,
            )

        return callback

    def get_work(self, work_id: str) -> RemediationWork:
        self._check_gate()
        with self._connect() as connection:
            return self._get_work_row(connection, work_id)

    def list_work(
        self,
        *,
        state: str | None = None,
        limit: int = 100,
    ) -> tuple[RemediationWork, ...]:
        self._check_gate()
        count = _integer(limit, "limit", 1, _MAX_LIST)
        params: list[object] = [self._tenant_sha256]
        query = "SELECT * FROM remediation_work WHERE tenant_sha256=?"
        if state is not None:
            selected = _ref(state, "state")
            if selected not in _STATES:
                raise PrivacyDiscoveryRemediationValidationError("remediation state is invalid")
            query += " AND state=?"
            params.append(selected)
        query += " ORDER BY work_id LIMIT ?"
        params.append(count)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return tuple(self._work_from_row(row) for row in rows)

    @staticmethod
    def _claim_from(work: RemediationWork, raw_token: str) -> RemediationClaim:
        if work.state != "leased" or work.lease_owner_sha256 is None or work.lease_until is None:
            raise PrivacyDiscoveryRemediationIntegrityError("remediation work is not leased")
        return RemediationClaim(
            schema=CLAIM_SCHEMA,
            work_id=work.work_id,
            tenant_sha256=work.tenant_sha256,
            source_id=work.source_id,
            report_id=work.report_id,
            finding_id=work.finding_id,
            review_id=work.review_id,
            review_version=work.review_version,
            decision=work.decision,
            category=work.category,
            evidence_sha256=work.evidence_sha256,
            authority_sha256=work.authority_sha256,
            callback_idempotency_sha256=work.callback_idempotency_sha256,
            report_completeness_sha256=work.report_completeness_sha256,
            completeness_claimed=False,
            attempt=work.attempts,
            lease_owner_sha256=work.lease_owner_sha256,
            lease_token=raw_token,
            lease_until=work.lease_until,
            work_revision=work.revision,
        )

    def _recover_expired_leases(
        self,
        connection: sqlite3.Connection,
        now: float,
        actor_sha256: str,
    ) -> int:
        rows = connection.execute(
            "SELECT * FROM remediation_work WHERE tenant_sha256=? AND state='leased' "
            "AND lease_until<=? ORDER BY lease_until,work_id LIMIT ?",
            (self._tenant_sha256, now, _MAX_CLAIM),
        ).fetchall()
        recovered = 0
        for row in rows:
            current = self._work_from_row(row)
            changed = self._replace_work(
                connection,
                current,
                state="ambiguous",
                lease_until=None,
                last_error_code="lease_expired_outcome_unknown",
                ambiguous_at=now,
                updated_at=now,
            )
            self._audit(
                connection,
                "lease_recovered_ambiguous",
                current.work_id,
                actor_sha256,
                {
                    "attempts": changed.attempts,
                    "authority_sha256": changed.authority_sha256,
                },
                now,
            )
            recovered += 1
        return recovered

    def _cancel_stale_queued(
        self,
        work: RemediationWork,
        now: float,
        actor_sha256: str,
    ) -> None:
        with self._connect() as connection:
            self._begin(connection)
            current = self._get_work_row(connection, work.work_id)
            if current.state == "queued" and current.revision == work.revision:
                changed = self._replace_work(
                    connection,
                    current,
                    state="cancelled",
                    lease_owner_sha256=None,
                    lease_token_sha256=None,
                    lease_until=None,
                    last_error_code="authority_stale_or_revoked",
                    ambiguous_at=None,
                    receipt_sha256=None,
                    updated_at=now,
                )
                self._audit(
                    connection,
                    "authority_cancelled",
                    changed.work_id,
                    actor_sha256,
                    {"authority_sha256": changed.authority_sha256},
                    now,
                )
            connection.commit()

    def claim_ready(
        self,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: int = 60,
    ) -> tuple[RemediationClaim, ...]:
        """Recover expired leases and claim fresh, exact approved work."""

        self._check_gate()
        worker = _ref(worker_id, "worker_id")
        worker_sha = _sha256(
            {
                "schema": "lightwork.privacy-data-discovery-remediation-worker.v1",
                "tenant_sha256": self._tenant_sha256,
                "worker": worker,
            }
        )
        count = _integer(limit, "limit", 1, _MAX_CLAIM)
        lease = _integer(
            lease_seconds,
            "lease_seconds",
            1,
            _MAX_LEASE_SECONDS,
        )
        now = self._now()
        actor_sha = self._actor_sha256()
        with self._connect() as connection:
            self._begin(connection)
            self._recover_expired_leases(connection, now, actor_sha)
            rows = connection.execute(
                "SELECT * FROM remediation_work WHERE tenant_sha256=? "
                "AND state='queued' AND next_attempt_at<=? AND retained_until>? "
                "ORDER BY next_attempt_at,work_id LIMIT ?",
                (self._tenant_sha256, now, now, count),
            ).fetchall()
            candidates = tuple(self._work_from_row(row) for row in rows)
            connection.commit()
        claims: list[RemediationClaim] = []
        for candidate in candidates:
            try:
                self._resolve_work(candidate, now)
            except PrivacyDiscoveryRemediationAuthorityError:
                self._cancel_stale_queued(candidate, now, actor_sha)
                continue
            try:
                raw_token = self._token_factory()
            except Exception as exc:
                raise PrivacyDiscoveryRemediationConfigError(
                    "lease token authority is unavailable"
                ) from exc
            if not isinstance(raw_token, str) or not _TOKEN_RE.fullmatch(raw_token):
                raise PrivacyDiscoveryRemediationConfigError(
                    "lease token authority returned an invalid token"
                )
            with self._connect() as connection:
                self._begin(connection)
                current = self._get_work_row(connection, candidate.work_id)
                if (
                    current.state != "queued"
                    or current.revision != candidate.revision
                    or current.next_attempt_at > now
                    or current.retained_until <= now
                ):
                    connection.commit()
                    continue
                changed = self._replace_work(
                    connection,
                    current,
                    state="leased",
                    attempts=current.attempts + 1,
                    lease_owner_sha256=worker_sha,
                    lease_token_sha256=_text_sha256(raw_token),
                    lease_until=now + lease,
                    last_error_code=None,
                    ambiguous_at=None,
                    receipt_sha256=None,
                    updated_at=now,
                )
                self._audit(
                    connection,
                    "work_leased",
                    changed.work_id,
                    actor_sha,
                    {
                        "attempt": changed.attempts,
                        "lease_until": changed.lease_until,
                        "authority_sha256": changed.authority_sha256,
                    },
                    now,
                )
                connection.commit()
            claims.append(self._claim_from(changed, raw_token))
        return tuple(claims)

    def _work_for_claim(
        self,
        connection: sqlite3.Connection,
        claim: RemediationClaim,
        now: float,
        *,
        allow_ambiguous: bool = False,
    ) -> RemediationWork:
        if type(claim) is not RemediationClaim or claim.schema != CLAIM_SCHEMA:
            raise PrivacyDiscoveryRemediationLeaseLost("remediation claim is invalid")
        current = self._get_work_row(connection, claim.work_id)
        state_ok = current.state == "leased" or (allow_ambiguous and current.state == "ambiguous")
        if (
            not state_ok
            or current.revision != claim.work_revision
            or current.lease_owner_sha256 != claim.lease_owner_sha256
            or current.lease_token_sha256 is None
            or not _same(current.lease_token_sha256, _text_sha256(claim.lease_token))
            or current.authority_sha256 != claim.authority_sha256
            or current.callback_idempotency_sha256 != claim.callback_idempotency_sha256
            or (
                current.state == "leased"
                and (current.lease_until is None or current.lease_until <= now)
            )
        ):
            raise PrivacyDiscoveryRemediationLeaseLost(
                "remediation lease no longer authorizes work"
            )
        if claim != self._claim_from(current, claim.lease_token):
            raise PrivacyDiscoveryRemediationLeaseLost("remediation claim projection is invalid")
        return current

    def validate_claim_authority(self, claim: RemediationClaim) -> RemediationWork:
        """Re-read exact public authority immediately before callback execution."""

        self._check_gate()
        now = self._now()
        with self._connect() as connection:
            current = self._work_for_claim(connection, claim, now)
        self._resolve_work(current, now)
        return current

    @staticmethod
    def _validated_callback_result(
        result: RemediationCallbackResult,
        authority_sha256: str,
    ) -> RemediationCallbackResult:
        if type(result) is not RemediationCallbackResult:
            raise PrivacyDiscoveryRemediationValidationError(
                "remediation callback returned an invalid exact type"
            )
        if result.outcome not in _CALLBACK_OUTCOMES:
            raise PrivacyDiscoveryRemediationValidationError(
                "remediation callback outcome is invalid"
            )
        receipt = _digest(result.receipt_sha256, "receipt_sha256")
        authority = _digest(result.authority_sha256, "authority_sha256")
        if not _same(authority, authority_sha256):
            raise PrivacyDiscoveryRemediationAuthorityError(
                "remediation callback acknowledged different authority"
            )
        return replace(result, receipt_sha256=receipt, authority_sha256=authority)

    def acknowledge(
        self,
        claim: RemediationClaim,
        result: RemediationCallbackResult,
    ) -> RemediationWork:
        """Idempotently acknowledge one exact callback result."""

        self._check_gate()
        validated = self._validated_callback_result(result, claim.authority_sha256)
        now = self._now()
        actor_sha = self._actor_sha256()
        with self._connect() as connection:
            self._begin(connection)
            current = self._get_work_row(connection, claim.work_id)
            token_sha = _text_sha256(claim.lease_token)
            if current.state in _CALLBACK_OUTCOMES:
                if (
                    current.revision == claim.work_revision + 1
                    and current.lease_token_sha256 == token_sha
                    and current.lease_owner_sha256 == claim.lease_owner_sha256
                    and current.state == validated.outcome
                    and current.receipt_sha256 == validated.receipt_sha256
                ):
                    connection.commit()
                    return current
                raise PrivacyDiscoveryRemediationConflict(
                    "remediation was acknowledged by another exact result"
                )
            current = self._work_for_claim(connection, claim, now)
            changed = self._replace_work(
                connection,
                current,
                state=validated.outcome,
                lease_until=None,
                last_error_code=None,
                receipt_sha256=validated.receipt_sha256,
                ambiguous_at=None,
                updated_at=now,
            )
            self._audit(
                connection,
                f"work_{validated.outcome}",
                changed.work_id,
                actor_sha,
                {
                    "attempt": changed.attempts,
                    "authority_sha256": changed.authority_sha256,
                    "receipt_sha256": validated.receipt_sha256,
                },
                now,
            )
            connection.commit()
            return changed

    def fail_claim(
        self,
        claim: RemediationClaim,
        *,
        error_code: str,
        disposition: str,
        backoff_seconds: int = 1,
    ) -> RemediationWork:
        """Record a proved retryable/permanent failure or an unknown outcome."""

        self._check_gate()
        code = _error_code(error_code)
        if disposition not in {"retry", "dead_letter", "ambiguous"}:
            raise PrivacyDiscoveryRemediationValidationError("failure disposition is invalid")
        backoff = _integer(
            backoff_seconds,
            "backoff_seconds",
            0,
            _MAX_BACKOFF_SECONDS,
        )
        now = self._now()
        actor_sha = self._actor_sha256()
        with self._connect() as connection:
            self._begin(connection)
            current = self._work_for_claim(connection, claim, now)
            if disposition == "ambiguous":
                state = "ambiguous"
            elif disposition == "dead_letter" or current.attempts >= current.max_attempts:
                state = "dead_letter"
            else:
                state = "queued"
            keep_claim_digest = state == "ambiguous"
            changed = self._replace_work(
                connection,
                current,
                state=state,
                next_attempt_at=now + backoff if state == "queued" else current.next_attempt_at,
                lease_owner_sha256=(current.lease_owner_sha256 if keep_claim_digest else None),
                lease_token_sha256=(current.lease_token_sha256 if keep_claim_digest else None),
                lease_until=None,
                last_error_code=code,
                receipt_sha256=None,
                ambiguous_at=now if state == "ambiguous" else None,
                updated_at=now,
            )
            self._audit(
                connection,
                {
                    "queued": "work_retry_scheduled",
                    "dead_letter": "work_dead_lettered",
                    "ambiguous": "work_outcome_ambiguous",
                }[state],
                changed.work_id,
                actor_sha,
                {
                    "attempt": changed.attempts,
                    "error_code": code,
                    "authority_sha256": changed.authority_sha256,
                },
                now,
            )
            connection.commit()
            return changed

    def cancel_claim(
        self,
        claim: RemediationClaim,
        *,
        reason_code: str,
    ) -> RemediationWork:
        """Cancel an exact lease before any callback is attempted."""

        self._check_gate()
        reason = _error_code(reason_code)
        now = self._now()
        actor_sha = self._actor_sha256()
        with self._connect() as connection:
            self._begin(connection)
            current = self._work_for_claim(connection, claim, now)
            changed = self._replace_work(
                connection,
                current,
                state="cancelled",
                lease_owner_sha256=None,
                lease_token_sha256=None,
                lease_until=None,
                last_error_code=reason,
                receipt_sha256=None,
                ambiguous_at=None,
                updated_at=now,
            )
            self._audit(
                connection,
                "work_cancelled",
                changed.work_id,
                actor_sha,
                {
                    "reason_code": reason,
                    "authority_sha256": changed.authority_sha256,
                },
                now,
            )
            connection.commit()
            return changed

    def cancel_work(
        self,
        work_id: str,
        *,
        reason_code: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> RemediationWork:
        """Cancel queued or dead-letter work; ambiguous work requires reconciliation."""

        self._check_gate()
        work_ref = _ref(work_id, "work_id")
        reason = _error_code(reason_code)
        revision = _integer(
            expected_revision,
            "expected_revision",
            1,
            2**31 - 1,
        )
        now = self._now()
        actor_sha = self._actor_sha256()
        request = {
            "action": "cancel_work",
            "work_id": work_ref,
            "reason_code": reason,
            "expected_revision": revision,
        }
        with self._connect() as connection:
            self._begin(connection)
            operation = self._operation(connection, idempotency_key, request)
            if operation is not None:
                result = self._get_work_row(connection, str(operation["result_id"]))
                connection.commit()
                return result
            current = self._get_work_row(connection, work_ref)
            if current.revision != revision or current.state not in {
                "queued",
                "dead_letter",
            }:
                raise PrivacyDiscoveryRemediationConflict(
                    "only exact queued or dead-letter work can be cancelled"
                )
            changed = self._replace_work(
                connection,
                current,
                state="cancelled",
                lease_owner_sha256=None,
                lease_token_sha256=None,
                lease_until=None,
                last_error_code=reason,
                receipt_sha256=None,
                ambiguous_at=None,
                updated_at=now,
            )
            self._record_operation(
                connection,
                idempotency_key,
                request,
                "work",
                changed.work_id,
                changed.revision,
                now,
            )
            self._audit(
                connection,
                "work_cancelled",
                changed.work_id,
                actor_sha,
                {
                    "reason_code": reason,
                    "authority_sha256": changed.authority_sha256,
                },
                now,
            )
            connection.commit()
            return changed

    def replay_dead_letter(
        self,
        work_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
        backoff_seconds: int = 0,
    ) -> RemediationWork:
        """Explicitly replay a dead letter after current authority is re-certified."""

        self._check_gate()
        work_ref = _ref(work_id, "work_id")
        revision = _integer(
            expected_revision,
            "expected_revision",
            1,
            2**31 - 1,
        )
        backoff = _integer(
            backoff_seconds,
            "backoff_seconds",
            0,
            _MAX_BACKOFF_SECONDS,
        )
        now = self._now()
        actor_sha = self._actor_sha256()
        request = {
            "action": "replay_dead_letter",
            "work_id": work_ref,
            "expected_revision": revision,
            "backoff_seconds": backoff,
        }
        with self._connect() as connection:
            self._begin(connection)
            operation = self._operation(connection, idempotency_key, request)
            if operation is not None:
                result = self._get_work_row(connection, str(operation["result_id"]))
                connection.commit()
                return result
            connection.commit()
        current = self.get_work(work_ref)
        if current.state != "dead_letter" or current.revision != revision:
            raise PrivacyDiscoveryRemediationConflict("dead-letter replay state changed")
        self._resolve_work(current, now)
        with self._connect() as connection:
            self._begin(connection)
            operation = self._operation(connection, idempotency_key, request)
            if operation is not None:
                result = self._get_work_row(connection, str(operation["result_id"]))
                connection.commit()
                return result
            current = self._get_work_row(connection, work_ref)
            if current.state != "dead_letter" or current.revision != revision:
                raise PrivacyDiscoveryRemediationConflict("dead-letter replay state changed")
            changed = self._replace_work(
                connection,
                current,
                state="queued",
                attempts=0,
                next_attempt_at=now + backoff,
                lease_owner_sha256=None,
                lease_token_sha256=None,
                lease_until=None,
                last_error_code=None,
                receipt_sha256=None,
                ambiguous_at=None,
                updated_at=now,
            )
            self._record_operation(
                connection,
                idempotency_key,
                request,
                "work",
                changed.work_id,
                changed.revision,
                now,
            )
            self._audit(
                connection,
                "dead_letter_replayed",
                changed.work_id,
                actor_sha,
                {"authority_sha256": changed.authority_sha256},
                now,
            )
            connection.commit()
            return changed

    @staticmethod
    def _probe_from(work: RemediationWork) -> RemediationReconciliationProbe:
        return RemediationReconciliationProbe(
            schema=CLAIM_SCHEMA,
            work_id=work.work_id,
            tenant_sha256=work.tenant_sha256,
            source_id=work.source_id,
            report_id=work.report_id,
            finding_id=work.finding_id,
            review_id=work.review_id,
            review_version=work.review_version,
            decision=work.decision,
            category=work.category,
            evidence_sha256=work.evidence_sha256,
            authority_sha256=work.authority_sha256,
            callback_idempotency_sha256=work.callback_idempotency_sha256,
            report_completeness_sha256=work.report_completeness_sha256,
            completeness_claimed=False,
            attempt=work.attempts,
        )

    def reconcile_ambiguous(
        self,
        work_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
        reconciler: RemediationReconciler,
        absent_backoff_seconds: int = 0,
    ) -> RemediationWork:
        """Resolve an unknown callback outcome without optimistic replay."""

        self._check_gate()
        if not callable(reconciler):
            raise PrivacyDiscoveryRemediationConfigError("remediation reconciler is unavailable")
        work_ref = _ref(work_id, "work_id")
        revision = _integer(
            expected_revision,
            "expected_revision",
            1,
            2**31 - 1,
        )
        backoff = _integer(
            absent_backoff_seconds,
            "absent_backoff_seconds",
            0,
            _MAX_BACKOFF_SECONDS,
        )
        now = self._now()
        actor_sha = self._actor_sha256()
        request = {
            "action": "reconcile_ambiguous",
            "work_id": work_ref,
            "expected_revision": revision,
            "absent_backoff_seconds": backoff,
        }
        with self._connect() as connection:
            self._begin(connection)
            operation = self._operation(connection, idempotency_key, request)
            if operation is not None:
                result = self._get_work_row(connection, str(operation["result_id"]))
                connection.commit()
                return result
            connection.commit()
        current = self.get_work(work_ref)
        if current.state != "ambiguous" or current.revision != revision:
            raise PrivacyDiscoveryRemediationConflict("ambiguous remediation state changed")
        try:
            raw_result = reconciler(self._probe_from(current))
        except Exception as exc:
            raise RemediationAmbiguousError("reconciliation_unavailable") from exc
        if type(raw_result) is not RemediationReconciliationResult:
            raise PrivacyDiscoveryRemediationValidationError(
                "remediation reconciler returned an invalid exact type"
            )
        outcome = raw_result.outcome
        if outcome not in _RECONCILIATION_OUTCOMES:
            raise PrivacyDiscoveryRemediationValidationError(
                "remediation reconciliation outcome is invalid"
            )
        authority_sha = _digest(raw_result.authority_sha256, "authority_sha256")
        if not _same(authority_sha, current.authority_sha256):
            raise PrivacyDiscoveryRemediationAuthorityError(
                "remediation reconciliation authority mismatched"
            )
        receipt = raw_result.receipt_sha256
        if outcome in _CALLBACK_OUTCOMES:
            receipt = _digest(receipt, "receipt_sha256")
        elif receipt is not None:
            raise PrivacyDiscoveryRemediationValidationError(
                "non-terminal reconciliation cannot contain a receipt"
            )
        if outcome == "absent":
            try:
                self._resolve_work(current, now)
                absent_state = "queued"
                absent_error = "reconciled_absent"
            except PrivacyDiscoveryRemediationAuthorityError:
                absent_state = "cancelled"
                absent_error = "authority_stale_or_revoked"
        else:
            absent_state = "ambiguous"
            absent_error = current.last_error_code
        with self._connect() as connection:
            self._begin(connection)
            operation = self._operation(connection, idempotency_key, request)
            if operation is not None:
                result = self._get_work_row(connection, str(operation["result_id"]))
                connection.commit()
                return result
            current = self._get_work_row(connection, work_ref)
            if current.state != "ambiguous" or current.revision != revision:
                raise PrivacyDiscoveryRemediationConflict("ambiguous remediation state changed")
            if outcome in _CALLBACK_OUTCOMES:
                state = outcome
                owner = current.lease_owner_sha256
                token = current.lease_token_sha256
                error = None
                ambiguous_at = None
                next_attempt = current.next_attempt_at
            elif outcome == "absent":
                state = absent_state
                owner = None
                token = None
                error = absent_error
                ambiguous_at = None
                next_attempt = now + backoff
            else:
                state = "ambiguous"
                owner = current.lease_owner_sha256
                token = current.lease_token_sha256
                error = absent_error
                ambiguous_at = current.ambiguous_at
                next_attempt = current.next_attempt_at
            changed = self._replace_work(
                connection,
                current,
                state=state,
                next_attempt_at=next_attempt,
                lease_owner_sha256=owner,
                lease_token_sha256=token,
                lease_until=None,
                last_error_code=error,
                receipt_sha256=receipt if outcome in _CALLBACK_OUTCOMES else None,
                ambiguous_at=ambiguous_at,
                updated_at=now,
            )
            self._record_operation(
                connection,
                idempotency_key,
                request,
                "work",
                changed.work_id,
                changed.revision,
                now,
            )
            self._audit(
                connection,
                f"reconciliation_{outcome}",
                changed.work_id,
                actor_sha,
                {
                    "authority_sha256": changed.authority_sha256,
                    "receipt_sha256": receipt,
                    "state": changed.state,
                },
                now,
            )
            connection.commit()
            return changed

    def purge_expired(
        self,
        *,
        cutoff: float,
        idempotency_key: str,
    ) -> int:
        """Purge bounded expired work/history and retain audit tombstones."""

        self._check_gate()
        now = self._now()
        selected_cutoff = _timestamp(cutoff, "cutoff")
        if selected_cutoff > now:
            raise PrivacyDiscoveryRemediationValidationError(
                "retention cutoff cannot be in the future"
            )
        actor_sha = self._actor_sha256()
        request = {"action": "purge_expired", "cutoff": selected_cutoff}
        with self._connect() as connection:
            self._begin(connection)
            operation = self._operation(connection, idempotency_key, request)
            if operation is not None:
                connection.commit()
                return int(operation["result_id"])
            rows = connection.execute(
                "SELECT * FROM remediation_work WHERE tenant_sha256=? "
                "AND retained_until<=? ORDER BY retained_until,work_id LIMIT ?",
                (self._tenant_sha256, selected_cutoff, _MAX_PURGE),
            ).fetchall()
            works = tuple(self._work_from_row(row) for row in rows)
            for work in works:
                self._audit(
                    connection,
                    "retention_purged",
                    work.work_id,
                    actor_sha,
                    {
                        "terminal_state_sha256": _text_sha256(work.state),
                        "terminal_integrity_sha256": work.integrity_sha256,
                    },
                    now,
                )
                connection.execute(
                    "DELETE FROM remediation_operations WHERE tenant_sha256=? AND result_id=?",
                    (self._tenant_sha256, work.work_id),
                )
                connection.execute(
                    "DELETE FROM remediation_history WHERE tenant_sha256=? AND work_id=?",
                    (self._tenant_sha256, work.work_id),
                )
                connection.execute(
                    "DELETE FROM remediation_work WHERE tenant_sha256=? AND work_id=?",
                    (self._tenant_sha256, work.work_id),
                )
            self._record_operation(
                connection,
                idempotency_key,
                request,
                "purge_count",
                str(len(works)),
                0,
                now,
            )
            connection.commit()
            return len(works)

    def state_counts(self) -> Mapping[str, int]:
        """Return bounded aggregate state only; no work identities."""

        self._check_gate()
        counts = dict.fromkeys(sorted(_STATES), 0)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT state,COUNT(*) AS count FROM remediation_work "
                "WHERE tenant_sha256=? GROUP BY state",
                (self._tenant_sha256,),
            ).fetchall()
        for row in rows:
            state = str(row["state"])
            if state not in counts:
                raise PrivacyDiscoveryRemediationIntegrityError(
                    "remediation state index is invalid"
                )
            counts[state] = int(row["count"])
        counts["total"] = sum(counts.values())
        return counts

    def audit_events(self, *, limit: int = 100) -> tuple[Mapping[str, object], ...]:
        self._check_gate()
        count = _integer(limit, "limit", 1, _MAX_LIST)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM remediation_audit WHERE tenant_sha256=? "
                "ORDER BY sequence DESC LIMIT ?",
                (self._tenant_sha256, count),
            ).fetchall()
        events: list[Mapping[str, object]] = []
        for row in reversed(rows):
            payload, digest_value = self._row_payload(row, "remediation audit")
            events.append({**payload, "integrity_sha256": digest_value})
        return tuple(events)

    def verify_integrity(self) -> RemediationIntegrityVerification:
        """Verify current rows, immutable history, operations and audit chain."""

        self._check_gate()
        with self._connect() as connection:
            current_rows = connection.execute(
                "SELECT * FROM remediation_work WHERE tenant_sha256=? ORDER BY work_id",
                (self._tenant_sha256,),
            ).fetchall()
            current = {work.work_id: work for work in map(self._work_from_row, current_rows)}
            history_rows = connection.execute(
                "SELECT * FROM remediation_history WHERE tenant_sha256=? ORDER BY work_id,revision",
                (self._tenant_sha256,),
            ).fetchall()
            history_count = 0
            latest_history: dict[str, tuple[int, str]] = {}
            previous_by_work: dict[str, str] = {}
            revision_by_work: dict[str, int] = {}
            for row in history_rows:
                payload, digest_value = self._row_payload(row, "remediation history")
                work = self._validated_work(payload, digest_value)
                if (
                    row["tenant_sha256"] != work.tenant_sha256
                    or row["work_id"] != work.work_id
                    or int(row["revision"]) != work.revision
                    or row["state"] != work.state
                ):
                    raise PrivacyDiscoveryRemediationIntegrityError(
                        "remediation history indexes are inconsistent"
                    )
                previous = previous_by_work.get(work.work_id, "0" * 64)
                expected_revision = revision_by_work.get(work.work_id, 0) + 1
                if work.revision != expected_revision or work.previous_integrity_sha256 != previous:
                    raise PrivacyDiscoveryRemediationIntegrityError(
                        "remediation history chain is invalid"
                    )
                previous_by_work[work.work_id] = digest_value
                revision_by_work[work.work_id] = work.revision
                latest_history[work.work_id] = (work.revision, digest_value)
                history_count += 1
            for work_id, work in current.items():
                if latest_history.get(work_id) != (work.revision, work.integrity_sha256):
                    raise PrivacyDiscoveryRemediationIntegrityError(
                        "current remediation is not bound to its history"
                    )
            operation_rows = connection.execute(
                "SELECT * FROM remediation_operations WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchall()
            for row in operation_rows:
                _digest(row["operation_sha256"], "operation_sha256")
                _digest(row["request_sha256"], "request_sha256")
                _ref(row["result_kind"], "result_kind")
                _ref(row["result_id"], "result_id")
                _integer(row["result_revision"], "result_revision", 0, 2**31 - 1)
                _timestamp(row["created_at"], "created_at")
            audit_rows = connection.execute(
                "SELECT * FROM remediation_audit WHERE tenant_sha256=? ORDER BY sequence",
                (self._tenant_sha256,),
            ).fetchall()
            previous_audit = "0" * 64
            expected_sequence = 1
            for row in audit_rows:
                payload, digest_value = self._row_payload(row, "remediation audit")
                required = {
                    "schema",
                    "sequence",
                    "event_type",
                    "subject_sha256",
                    "actor_sha256",
                    "details",
                    "occurred_at",
                    "previous_integrity_sha256",
                }
                if (
                    set(payload) != required
                    or payload["schema"] != AUDIT_SCHEMA
                    or int(row["sequence"]) != expected_sequence
                    or payload["sequence"] != expected_sequence
                    or payload["previous_integrity_sha256"] != previous_audit
                ):
                    raise PrivacyDiscoveryRemediationIntegrityError(
                        "remediation audit chain is invalid"
                    )
                _error_code(payload["event_type"])
                _digest(payload["subject_sha256"], "subject_sha256")
                _digest(payload["actor_sha256"], "actor_sha256")
                _timestamp(payload["occurred_at"], "occurred_at")
                _privacy_safe(payload["details"])
                previous_audit = digest_value
                expected_sequence += 1
        return RemediationIntegrityVerification(
            current_records=len(current_rows),
            history_records=history_count,
            operation_records=len(operation_rows),
            audit_events=len(audit_rows),
            terminal_audit_sha256=previous_audit,
        )

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "authority": "constructor_bound_public_discovery_reads",
            "tenant_binding": "constructor_bound",
            "approved_reviews_only": True,
            "latest_review_required": True,
            "source_must_be_active": True,
            "authority_double_read": True,
            "work_payload": "opaque_ids_and_sha256_only",
            "raw_locations_persisted": False,
            "raw_values_persisted": False,
            "document_content_persisted": False,
            "credentials_persisted": False,
            "network_io": False,
            "provider_writes": False,
            "callback": "constructor_injected_idempotent_adapter",
            "ambiguous_outcomes_optimistically_retried": False,
            "completeness_inferred": False,
            "live_provider_acceptance_verified": False,
        }


class PrivacyDataDiscoveryRemediationWorker:
    """Bounded worker around an injected idempotent remediation callback."""

    def __init__(
        self,
        store: PrivacyDataDiscoveryRemediationStore,
        *,
        callback: RemediationCallback,
        retry_backoff: Callable[[int], int] | None = None,
    ) -> None:
        if not isinstance(store, PrivacyDataDiscoveryRemediationStore):
            raise PrivacyDiscoveryRemediationConfigError("remediation worker store is invalid")
        if not callable(callback):
            raise PrivacyDiscoveryRemediationConfigError("remediation callback is unavailable")
        if retry_backoff is not None and not callable(retry_backoff):
            raise PrivacyDiscoveryRemediationConfigError("remediation retry backoff is invalid")
        self._store = store
        self._callback = callback
        self._retry_backoff = retry_backoff or (
            lambda attempt: min(2 ** min(attempt, 16), _MAX_BACKOFF_SECONDS)
        )

    def _backoff(self, attempt: int) -> int:
        try:
            value = self._retry_backoff(attempt)
        except Exception as exc:
            raise PrivacyDiscoveryRemediationConfigError(
                "remediation retry backoff failed"
            ) from exc
        return _integer(value, "retry backoff", 0, _MAX_BACKOFF_SECONDS)

    def run_once(
        self,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: int = 60,
    ) -> RemediationWorkerResult:
        claims = self._store.claim_ready(
            worker_id=worker_id,
            limit=limit,
            lease_seconds=lease_seconds,
        )
        result = {
            "claimed": len(claims),
            "applied": 0,
            "no_change": 0,
            "retried": 0,
            "ambiguous": 0,
            "dead_lettered": 0,
            "cancelled": 0,
        }
        for claim in claims:
            try:
                self._store.validate_claim_authority(claim)
            except PrivacyDiscoveryRemediationAuthorityError:
                try:
                    self._store.cancel_claim(
                        claim,
                        reason_code="authority_stale_or_revoked",
                    )
                    result["cancelled"] += 1
                except PrivacyDiscoveryRemediationLeaseLost:
                    pass
                continue
            try:
                callback_result = self._callback(claim)
                completed = self._store.acknowledge(claim, callback_result)
                result[completed.state] += 1
            except RemediationRetryableError as exc:
                failed = self._store.fail_claim(
                    claim,
                    error_code=exc.error_code,
                    disposition="retry",
                    backoff_seconds=self._backoff(claim.attempt),
                )
                if failed.state == "dead_letter":
                    result["dead_lettered"] += 1
                else:
                    result["retried"] += 1
            except RemediationPermanentError as exc:
                self._store.fail_claim(
                    claim,
                    error_code=exc.error_code,
                    disposition="dead_letter",
                )
                result["dead_lettered"] += 1
            except RemediationAmbiguousError as exc:
                self._store.fail_claim(
                    claim,
                    error_code=exc.error_code,
                    disposition="ambiguous",
                )
                result["ambiguous"] += 1
            except PrivacyDiscoveryRemediationLeaseLost:
                continue
            except Exception:
                self._store.fail_claim(
                    claim,
                    error_code="callback_outcome_unknown",
                    disposition="ambiguous",
                )
                result["ambiguous"] += 1
        return RemediationWorkerResult(**result)


__all__ = [
    "AUDIT_SCHEMA",
    "CLAIM_SCHEMA",
    "RemediationAmbiguousError",
    "RemediationCallback",
    "RemediationCallbackResult",
    "RemediationClaim",
    "RemediationEnqueueResult",
    "RemediationIntegrityVerification",
    "RemediationPermanentError",
    "RemediationReconciler",
    "RemediationReconciliationProbe",
    "RemediationReconciliationResult",
    "RemediationRetryableError",
    "RemediationWork",
    "RemediationWorkerResult",
    "ResolvedRemediationAuthority",
    "PrivacyDataDiscoveryRemediationStore",
    "PrivacyDataDiscoveryRemediationWorker",
    "PrivacyDiscoveryRemediationAuthorityError",
    "PrivacyDiscoveryRemediationConfigError",
    "PrivacyDiscoveryRemediationConflict",
    "PrivacyDiscoveryRemediationError",
    "PrivacyDiscoveryRemediationIntegrityError",
    "PrivacyDiscoveryRemediationLeaseLost",
    "PrivacyDiscoveryRemediationNotFound",
    "PrivacyDiscoveryRemediationValidationError",
    "WORK_SCHEMA",
]
