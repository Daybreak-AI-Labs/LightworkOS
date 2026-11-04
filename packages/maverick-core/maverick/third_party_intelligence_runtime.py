"""Durable provider-feed worker for the third-party intelligence authority.

This module owns only feed jobs, minimized receipts, and their audit history.
The existing :mod:`maverick.third_party_intelligence` store remains the sole
authority for sources, snapshots, vendors, monitors, alerts, and risk
decisions.  Raw credentials and provider pages stay inside injected resolvers
and adapters; no provider result can approve a vendor or infer a legal,
regulatory, sanctions, or business conclusion.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection
from .third_party_intelligence_providers import (
    CredentialBinding,
    ProviderFeedResult,
    ProviderRequest,
    ThirdPartyProviderConfigError,
    ThirdPartyProviderCredentialError,
    ThirdPartyProviderError,
    ThirdPartyProviderFactory,
    ThirdPartyProviderIncompleteError,
    ThirdPartyProviderProtocolError,
    ThirdPartyProviderTransportError,
)

SCHEMA_VERSION = 1
AUDIT_SCHEMA = "lightwork.third-party-intelligence-feed-audit.v1"
RECEIPT_SCHEMA = "lightwork.third-party-intelligence-feed-receipt.v1"
JOB_SCHEMA = "lightwork.third-party-intelligence-feed-job.v1"

NETWORK_IO = True
PROVIDER_WRITES = False
RAW_CREDENTIALS_PERSISTED = False
RAW_PROVIDER_PAYLOADS_PERSISTED = False
AUTOMATIC_VENDOR_APPROVAL = False
LIVE_PROVIDER_ACCEPTANCE_VERIFIED = False
CROSS_STORE_ATOMICITY = False

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_ENV_RE = re.compile(r"[A-Z][A-Z0-9_]{1,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_TERMINAL_STATES = frozenset({"completed", "dead_letter", "revoked", "cancelled"})
_ACTIVE_STATES = frozenset({"pending", "retry", "leased"})
_MAX_LEASE_SECONDS = 3_600.0
_MAX_BACKOFF_SECONDS = 7 * 24 * 60 * 60.0
_MIN_RETENTION_SECONDS = 60
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 60 * 60
_MAX_JSON_BYTES = 4 * 1024 * 1024


class ThirdPartyFeedRuntimeError(RuntimeError):
    """Base feed-runtime error."""


class ThirdPartyFeedRuntimeConfigError(ThirdPartyFeedRuntimeError):
    """Required feature gates or trusted dependencies are unavailable."""


class ThirdPartyFeedRuntimeValidationError(ThirdPartyFeedRuntimeError, ValueError):
    """Input is outside the closed feed-runtime contract."""


class ThirdPartyFeedRuntimeConflict(ThirdPartyFeedRuntimeError):
    """A lease, idempotency, state, revision, or authority pin drifted."""


class ThirdPartyFeedRuntimeNotFound(ThirdPartyFeedRuntimeError):
    """A tenant-scoped feed job or receipt is absent."""


class ThirdPartyFeedRuntimeIntegrityError(ThirdPartyFeedRuntimeError):
    """Persisted job, receipt, history, operation, or audit evidence is invalid."""


class ThirdPartyFeedAuthorityDrift(ThirdPartyFeedRuntimeConflict):
    """The approved source or monitor authority changed around provider I/O."""


def enabled() -> bool:
    """Return true only for root, intelligence, and provider-runtime gates."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    root = config.get("third_party_management")
    intelligence = root.get("intelligence") if isinstance(root, Mapping) else None
    providers = intelligence.get("providers") if isinstance(intelligence, Mapping) else None
    return (
        isinstance(root, Mapping)
        and root.get("enable") is True
        and isinstance(intelligence, Mapping)
        and intelligence.get("enable") is True
        and isinstance(providers, Mapping)
        and providers.get("enable") is True
    )


def require_enabled() -> None:
    if not enabled():
        raise ThirdPartyFeedRuntimeConfigError(
            "third-party feed runtime is disabled; explicitly enable "
            "third_party_management, intelligence, and intelligence.providers"
        )


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        result = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ThirdPartyFeedRuntimeValidationError(
            "feed-runtime state must be finite canonical JSON"
        ) from exc
    if not 1 <= len(result) <= maximum:
        raise ThirdPartyFeedRuntimeValidationError("feed-runtime state exceeds its byte bound")
    return result


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ThirdPartyFeedRuntimeValidationError("tenant_id is invalid") from exc


def _identifier(value: object, label: str, pattern: re.Pattern[str] = _ID_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ThirdPartyFeedRuntimeValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ThirdPartyFeedRuntimeValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ThirdPartyFeedRuntimeValidationError(
            f"{label} must be an integer from {minimum} through {maximum}"
        )
    return value


def _number(value: object, label: str, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise ThirdPartyFeedRuntimeValidationError(f"{label} is outside its bound")
    return float(value)


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


@dataclass(frozen=True, slots=True)
class SourceAuthorityPin:
    kind: str
    source_id: str
    provider: str
    provenance_uri: str
    credential_env: str
    source_revision: int
    source_integrity_sha256: str


@dataclass(frozen=True, slots=True)
class FeedJob:
    tenant_id: str
    job_id: str
    monitor_id: str
    monitor_revision: int
    monitor_integrity_sha256: str
    vendor_id: str
    source_pins: tuple[SourceAuthorityPin, ...]
    state: str
    attempt: int
    maximum_attempts: int
    next_attempt_at: float
    lease_token: str | None
    lease_until: float | None
    revision: int
    receipt_id: str | None
    last_error_code: str | None
    retained_until: float
    created_by: str
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class FeedReceipt:
    tenant_id: str
    receipt_id: str
    job_id: str
    monitor_id: str
    monitor_revision_before: int
    monitor_revision_after: int
    changed: bool
    alert_id: str | None
    observation_sha256: str
    evidence_sha256: str
    source_receipts: tuple[Mapping[str, object], ...]
    retained_until: float
    completed_at: float
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class FeedBatchOutcome:
    job_id: str
    state: str
    receipt_id: str | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class FeedBatchResult:
    tenant_id: str
    claimed: int
    completed: int
    retry_pending: int
    dead_lettered: int
    revoked: int
    outcomes: tuple[FeedBatchOutcome, ...]


CredentialResolver = Callable[[str, str, str, str], CredentialBinding]


class ThirdPartyFeedRuntimeStore:
    """Tenant-bound durable feed-job and minimized-receipt ledger."""

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

    def _now(self) -> float:
        return _number(self._clock(), "runtime clock", 0.001, 100_000_000_000.0)

    def _connect(self) -> sqlite3.Connection:
        ensure_private_directory(self.path.parent)
        if not self.path.exists():
            try:
                descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        ensure_private_file(self.path, 0o600)
        connection = sqlite3.connect(
            self.path, timeout=30.0, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS feed_meta(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS feed_jobs(
                    tenant_id TEXT NOT NULL,job_id TEXT NOT NULL,monitor_id TEXT NOT NULL,
                    state TEXT NOT NULL,next_attempt_at REAL NOT NULL,
                    lease_until REAL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,job_id)
                );
                CREATE INDEX IF NOT EXISTS feed_jobs_due
                    ON feed_jobs(tenant_id,state,next_attempt_at,lease_until);
                CREATE TABLE IF NOT EXISTS feed_receipts(
                    tenant_id TEXT NOT NULL,receipt_id TEXT NOT NULL,job_id TEXT NOT NULL,
                    retained_until REAL NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,receipt_id),UNIQUE(tenant_id,job_id)
                );
                CREATE TABLE IF NOT EXISTS feed_history(
                    tenant_id TEXT NOT NULL,job_id TEXT NOT NULL,revision INTEGER NOT NULL,
                    state TEXT NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,job_id,revision)
                );
                CREATE TABLE IF NOT EXISTS feed_operations(
                    tenant_id TEXT NOT NULL,namespace TEXT NOT NULL,key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_kind TEXT NOT NULL,result_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,namespace,key_sha256)
                );
                CREATE TABLE IF NOT EXISTS feed_audit(
                    tenant_id TEXT NOT NULL,sequence INTEGER NOT NULL,event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS feed_receipts_no_update BEFORE UPDATE ON feed_receipts
                    BEGIN SELECT RAISE(ABORT,'immutable feed receipt'); END;
                CREATE TRIGGER IF NOT EXISTS feed_history_no_update BEFORE UPDATE ON feed_history
                    BEGIN SELECT RAISE(ABORT,'immutable feed history'); END;
                CREATE TRIGGER IF NOT EXISTS feed_operations_no_update BEFORE UPDATE ON feed_operations
                    BEGIN SELECT RAISE(ABORT,'immutable feed operation'); END;
                CREATE TRIGGER IF NOT EXISTS feed_operations_no_delete BEFORE DELETE ON feed_operations
                    BEGIN SELECT RAISE(ABORT,'immutable feed operation'); END;
                CREATE TRIGGER IF NOT EXISTS feed_audit_no_update BEFORE UPDATE ON feed_audit
                    BEGIN SELECT RAISE(ABORT,'immutable feed audit'); END;
                CREATE TRIGGER IF NOT EXISTS feed_audit_no_delete BEFORE DELETE ON feed_audit
                    BEGIN SELECT RAISE(ABORT,'immutable feed audit'); END;
                COMMIT;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO feed_meta(key,value) VALUES('schema_version',?)",
                (str(SCHEMA_VERSION),),
            )
            row = connection.execute(
                "SELECT value FROM feed_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None or row["value"] != str(SCHEMA_VERSION):
                raise ThirdPartyFeedRuntimeConfigError("unsupported feed-runtime schema")

    @staticmethod
    def _payload(row: sqlite3.Row, label: str) -> dict[str, Any]:
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ThirdPartyFeedRuntimeIntegrityError(f"{label} JSON is invalid") from exc
        if not isinstance(payload, dict):
            raise ThirdPartyFeedRuntimeIntegrityError(f"{label} must be an object")
        digest = _sha256(payload)
        if not _same(digest, row["integrity_sha256"]):
            raise ThirdPartyFeedRuntimeIntegrityError(f"{label} integrity check failed")
        ThirdPartyFeedRuntimeStore._assert_row_binding(row, payload, label)
        return {**payload, "integrity_sha256": digest}

    @staticmethod
    def _assert_row_binding(
        row: sqlite3.Row,
        payload: Mapping[str, Any],
        label: str,
    ) -> None:
        specifications: dict[str, tuple[str | None, tuple[tuple[str, str], ...]]] = {
            "feed job": (
                JOB_SCHEMA,
                (
                    ("tenant_id", "text"),
                    ("job_id", "text"),
                    ("monitor_id", "text"),
                    ("state", "text"),
                    ("next_attempt_at", "real"),
                    ("lease_until", "optional_real"),
                    ("retained_until", "real"),
                ),
            ),
            "feed receipt": (
                RECEIPT_SCHEMA,
                (
                    ("tenant_id", "text"),
                    ("receipt_id", "text"),
                    ("job_id", "text"),
                    ("retained_until", "real"),
                ),
            ),
            "feed history": (
                JOB_SCHEMA,
                (
                    ("tenant_id", "text"),
                    ("job_id", "text"),
                    ("revision", "integer"),
                    ("state", "text"),
                    ("retained_until", "real"),
                ),
            ),
            "feed operation": (
                None,
                (
                    ("tenant_id", "text"),
                    ("namespace", "text"),
                    ("key_sha256", "text"),
                    ("request_sha256", "text"),
                    ("result_kind", "text"),
                    ("result_id", "text"),
                ),
            ),
            "feed audit": (
                AUDIT_SCHEMA,
                (
                    ("tenant_id", "text"),
                    ("sequence", "integer"),
                    ("event_type", "text"),
                ),
            ),
        }
        specification = specifications.get(label)
        if specification is None:
            raise ThirdPartyFeedRuntimeConfigError("unknown feed persistence label")
        schema, fields = specification
        if schema is not None and payload.get("schema") != schema:
            raise ThirdPartyFeedRuntimeIntegrityError(f"{label} schema is invalid")
        for field, kind in fields:
            signed = payload.get(field)
            stored = row[field]
            if kind == "text":
                valid = type(signed) is str and type(stored) is str and signed == stored
            elif kind == "integer":
                valid = type(signed) is int and type(stored) is int and signed == stored
            elif kind == "optional_real" and signed is None and stored is None:
                valid = True
            else:
                valid = (
                    type(signed) in {int, float}
                    and type(stored) in {int, float}
                    and math.isfinite(float(signed))
                    and math.isfinite(float(stored))
                    and float(signed) == float(stored)
                )
            if not valid:
                raise ThirdPartyFeedRuntimeIntegrityError(
                    f"{label} {field} index binding is invalid"
                )

    @staticmethod
    def _insert(
        connection: sqlite3.Connection,
        table: str,
        columns: Sequence[str],
        values: Sequence[object],
        payload: Mapping[str, object],
    ) -> str:
        digest = _sha256(payload)
        names = ",".join((*columns, "payload_json", "integrity_sha256"))
        placeholders = ",".join("?" for _ in range(len(columns) + 2))
        connection.execute(
            f"INSERT INTO {table}({names}) VALUES({placeholders})",  # noqa: S608
            (*values, _canonical(payload).decode("ascii"), digest),
        )
        return digest

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        event_type: str,
        object_id: str,
        actor_ref: str,
        details: Mapping[str, object],
        occurred_at: float,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM feed_audit WHERE tenant_id=? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = "0" * 64 if previous is None else str(previous["integrity_sha256"])
        payload = {
            "schema": AUDIT_SCHEMA,
            "tenant_id": tenant,
            "sequence": sequence,
            "event_type": _identifier(event_type, "event_type"),
            "object_sha256": _sha256({"object_id": object_id}),
            "actor_sha256": _sha256({"actor_ref": actor_ref}),
            "details": dict(details),
            "occurred_at": occurred_at,
            "previous_integrity_sha256": previous_sha,
        }
        self._insert(
            connection,
            "feed_audit",
            ("tenant_id", "sequence", "event_type"),
            (tenant, sequence, event_type),
            payload,
        )

    def _history(self, connection: sqlite3.Connection, payload: Mapping[str, object]) -> None:
        self._insert(
            connection,
            "feed_history",
            ("tenant_id", "job_id", "revision", "state", "retained_until"),
            (
                payload["tenant_id"],
                payload["job_id"],
                payload["revision"],
                payload["state"],
                payload["retained_until"],
            ),
            payload,
        )

    @staticmethod
    def _operation_key(value: object) -> str:
        key = _identifier(value, "idempotency_key")
        return hashlib.sha256(key.encode("ascii")).hexdigest()

    def _operation(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
    ) -> tuple[str, str] | None:
        row = connection.execute(
            "SELECT * FROM feed_operations WHERE tenant_id=? AND namespace=? AND key_sha256=?",
            (tenant, namespace, key_sha256),
        ).fetchone()
        if row is None:
            return None
        payload = self._payload(row, "feed operation")
        if payload.get("request_sha256") != request_sha256:
            raise ThirdPartyFeedRuntimeConflict(
                "idempotency key was already used for different content"
            )
        return str(payload["result_kind"]), str(payload["result_id"])

    def _record_operation(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
        result_kind: str,
        result_id: str,
    ) -> None:
        payload = {
            "tenant_id": tenant,
            "namespace": namespace,
            "key_sha256": key_sha256,
            "request_sha256": request_sha256,
            "result_kind": result_kind,
            "result_id": result_id,
        }
        self._insert(
            connection,
            "feed_operations",
            (
                "tenant_id",
                "namespace",
                "key_sha256",
                "request_sha256",
                "result_kind",
                "result_id",
            ),
            (
                tenant,
                namespace,
                key_sha256,
                request_sha256,
                result_kind,
                result_id,
            ),
            payload,
        )

    @staticmethod
    def _job_from(payload: Mapping[str, Any]) -> FeedJob:
        return FeedJob(
            tenant_id=str(payload["tenant_id"]),
            job_id=str(payload["job_id"]),
            monitor_id=str(payload["monitor_id"]),
            monitor_revision=int(payload["monitor_revision"]),
            monitor_integrity_sha256=str(payload["monitor_integrity_sha256"]),
            vendor_id=str(payload["vendor_id"]),
            source_pins=tuple(SourceAuthorityPin(**item) for item in payload["source_pins"]),
            state=str(payload["state"]),
            attempt=int(payload["attempt"]),
            maximum_attempts=int(payload["maximum_attempts"]),
            next_attempt_at=float(payload["next_attempt_at"]),
            lease_token=payload["lease_token"],
            lease_until=(None if payload["lease_until"] is None else float(payload["lease_until"])),
            revision=int(payload["revision"]),
            receipt_id=payload["receipt_id"],
            last_error_code=payload["last_error_code"],
            retained_until=float(payload["retained_until"]),
            created_by=str(payload["created_by"]),
            created_at=float(payload["created_at"]),
            updated_at=float(payload["updated_at"]),
            integrity_sha256=str(payload["integrity_sha256"]),
        )

    @staticmethod
    def _receipt_from(payload: Mapping[str, Any]) -> FeedReceipt:
        return FeedReceipt(
            tenant_id=str(payload["tenant_id"]),
            receipt_id=str(payload["receipt_id"]),
            job_id=str(payload["job_id"]),
            monitor_id=str(payload["monitor_id"]),
            monitor_revision_before=int(payload["monitor_revision_before"]),
            monitor_revision_after=int(payload["monitor_revision_after"]),
            changed=bool(payload["changed"]),
            alert_id=payload["alert_id"],
            observation_sha256=str(payload["observation_sha256"]),
            evidence_sha256=str(payload["evidence_sha256"]),
            source_receipts=tuple(payload["source_receipts"]),
            retained_until=float(payload["retained_until"]),
            completed_at=float(payload["completed_at"]),
            integrity_sha256=str(payload["integrity_sha256"]),
        )

    def get_job(self, tenant_id: str, job_id: str) -> FeedJob:
        tenant = _tenant(tenant_id)
        job = _identifier(job_id, "job_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM feed_jobs WHERE tenant_id=? AND job_id=?",
                (tenant, job),
            ).fetchone()
        if row is None:
            raise ThirdPartyFeedRuntimeNotFound("feed job was not found")
        return self._job_from(self._payload(row, "feed job"))

    def get_receipt(self, tenant_id: str, receipt_id: str) -> FeedReceipt:
        tenant = _tenant(tenant_id)
        receipt = _identifier(receipt_id, "receipt_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM feed_receipts WHERE tenant_id=? AND receipt_id=?",
                (tenant, receipt),
            ).fetchone()
        if row is None:
            raise ThirdPartyFeedRuntimeNotFound("feed receipt was not found")
        return self._receipt_from(self._payload(row, "feed receipt"))

    def list_jobs(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        limit: int = 100,
    ) -> tuple[FeedJob, ...]:
        tenant = _tenant(tenant_id)
        count = _integer(limit, "limit", 1, 500)
        if state is not None and state not in {*_ACTIVE_STATES, *_TERMINAL_STATES}:
            raise ThirdPartyFeedRuntimeValidationError("job state is closed")
        with self._connect() as connection:
            if state is None:
                rows = connection.execute(
                    "SELECT * FROM feed_jobs WHERE tenant_id=? ORDER BY job_id DESC LIMIT ?",
                    (tenant, count),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM feed_jobs WHERE tenant_id=? AND state=? "
                    "ORDER BY job_id DESC LIMIT ?",
                    (tenant, state, count),
                ).fetchall()
        return tuple(self._job_from(self._payload(row, "feed job")) for row in rows)

    def select_due_monitors(
        self, tenant_id: str, intelligence_store: Any, *, limit: int = 100,
    ) -> tuple:
        """Rotate a bounded native selection even while earlier jobs remain due.

        The cursor is tenant-bound scheduling metadata, never evidence of a
        scan or permission to run it. Save it before enqueueing: a crash may
        delay a selection until the next rotation, but cannot replay an effect.
        The ordinary enqueue path still rechecks current source authority and
        retains the exact existing job for a previously submitted revision.
        """
        tenant = _tenant(tenant_id)
        count = _integer(limit, "limit", 1, 500)
        key = "monitor-selection:" + tenant
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute("SELECT value FROM feed_meta WHERE key=?", (key,)).fetchone()
            position = _identifier(row["value"], "monitor selection") if row else None
            monitors = intelligence_store.due_monitors(tenant, limit=count, after_id=position)
            if not monitors and position is not None:
                monitors = intelligence_store.due_monitors(tenant, limit=count)
            if monitors:
                last = _identifier(monitors[-1].monitor_id, "monitor selection")
                connection.execute(
                    "INSERT INTO feed_meta(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, last),
                )
            connection.commit()
        return tuple(monitors)

    def enqueue_monitor(
        self,
        tenant_id: str,
        monitor_id: str,
        intelligence_store: Any,
        *,
        actor_ref: str,
        idempotency_key: str,
        maximum_attempts: int = 5,
        retention_seconds: int = 30 * 24 * 60 * 60,
        require_due: bool = True,
    ) -> FeedJob:
        tenant = _tenant(tenant_id)
        monitor_key = _identifier(monitor_id, "monitor_id")
        actor = _identifier(actor_ref, "actor_ref")
        attempts = _integer(maximum_attempts, "maximum_attempts", 1, 20)
        retention = _integer(
            retention_seconds,
            "retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        )
        if not isinstance(require_due, bool):
            raise ThirdPartyFeedRuntimeValidationError("require_due must be boolean")
        now = self._now()
        monitor = intelligence_store.get_monitor(tenant, monitor_key)
        if monitor.tenant_id != tenant or monitor.state != "active":
            raise ThirdPartyFeedAuthorityDrift("monitor is not active for this tenant")
        if require_due and monitor.next_run_at > now:
            raise ThirdPartyFeedRuntimeConflict("monitor is not due")
        source_pins: list[dict[str, object]] = []
        for kind, source_id in sorted(monitor.source_bindings.items()):
            source = intelligence_store.get_source(tenant, source_id)
            if (
                source.tenant_id != tenant
                or source.source_id != source_id
                or source.kind != kind
                or source.state != "active"
                or source.approved_by is None
                or "monitoring" not in source.purposes
            ):
                raise ThirdPartyFeedAuthorityDrift(
                    "monitor source is not independently approved for monitoring"
                )
            source_pins.append(
                {
                    "kind": source.kind,
                    "source_id": source.source_id,
                    "provider": source.provider,
                    "provenance_uri": source.provenance_uri,
                    "credential_env": _identifier(
                        source.credential_env,
                        "credential_env",
                        _ENV_RE,
                    ),
                    "source_revision": source.revision,
                    "source_integrity_sha256": _digest(
                        source.integrity_sha256,
                        "source_integrity_sha256",
                    ),
                }
            )
        binding = {
            "tenant_id": tenant,
            "monitor_id": monitor.monitor_id,
            "monitor_revision": monitor.revision,
            "monitor_integrity_sha256": monitor.integrity_sha256,
            "vendor_id": monitor.vendor_id,
            "source_pins": source_pins,
        }
        binding_sha = _sha256(binding)
        job_id = f"TPJ-{binding_sha[:32]}"
        key_sha = self._operation_key(idempotency_key)
        request_sha = _sha256(
            {
                "action": "enqueue_monitor",
                "binding_sha256": binding_sha,
                "maximum_attempts": attempts,
                "retention_seconds": retention,
                "actor_ref": actor,
            }
        )
        payload = {
            "schema": JOB_SCHEMA,
            **binding,
            "job_id": job_id,
            "binding_sha256": binding_sha,
            "state": "pending",
            "attempt": 0,
            "maximum_attempts": attempts,
            "next_attempt_at": now,
            "lease_token": None,
            "lease_until": None,
            "revision": 1,
            "receipt_id": None,
            "last_error_code": None,
            "retained_until": now + retention,
            "created_by": actor,
            "created_at": now,
            "updated_at": now,
        }
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation(
                connection,
                tenant,
                "monitor.enqueue",
                key_sha,
                request_sha,
            )
            if replay is not None:
                connection.rollback()
                kind, result_id = replay
                if kind != "job":
                    raise ThirdPartyFeedRuntimeIntegrityError(
                        "enqueue idempotency result kind is invalid"
                    )
                return self.get_job(tenant, result_id)
            existing = connection.execute(
                "SELECT * FROM feed_jobs WHERE tenant_id=? AND job_id=?",
                (tenant, job_id),
            ).fetchone()
            if existing is None:
                self._insert(
                    connection,
                    "feed_jobs",
                    (
                        "tenant_id",
                        "job_id",
                        "monitor_id",
                        "state",
                        "next_attempt_at",
                        "lease_until",
                        "retained_until",
                    ),
                    (
                        tenant,
                        job_id,
                        monitor.monitor_id,
                        "pending",
                        now,
                        None,
                        now + retention,
                    ),
                    payload,
                )
                self._history(connection, payload)
                self._audit(
                    connection,
                    tenant,
                    "feed_job_enqueued",
                    job_id,
                    actor,
                    {"binding_sha256": binding_sha},
                    now,
                )
            self._record_operation(
                connection,
                tenant,
                "monitor.enqueue",
                key_sha,
                request_sha,
                "job",
                job_id,
            )
            connection.commit()
        return self.get_job(tenant, job_id)

    def claim_jobs(
        self,
        tenant_id: str,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: float = 60.0,
    ) -> tuple[FeedJob, ...]:
        tenant = _tenant(tenant_id)
        worker = _identifier(worker_id, "worker_id")
        count = _integer(limit, "limit", 1, 100)
        lease = _number(lease_seconds, "lease_seconds", 1.0, _MAX_LEASE_SECONDS)
        now = self._now()
        claimed: list[FeedJob] = []
        with self._connect() as connection:
            self._begin(connection)
            rows = connection.execute(
                "SELECT * FROM feed_jobs WHERE tenant_id=? AND "
                "((state IN ('pending','retry') AND next_attempt_at<=?) OR "
                "(state='leased' AND lease_until<=?)) ORDER BY next_attempt_at,job_id LIMIT ?",
                (tenant, now, now, count),
            ).fetchall()
            for row in rows:
                payload = self._payload(row, "feed job")
                payload.pop("integrity_sha256", None)
                if payload["retained_until"] <= now:
                    payload.update(
                        {
                            "state": "dead_letter",
                            "lease_token": None,
                            "lease_until": None,
                            "last_error_code": "retention_expired",
                            "revision": int(payload["revision"]) + 1,
                            "updated_at": now,
                        }
                    )
                else:
                    token = hashlib.sha256(
                        f"{tenant}:{payload['job_id']}:{worker}:{self._token_factory()}".encode()
                    ).hexdigest()
                    payload.update(
                        {
                            "state": "leased",
                            "attempt": int(payload["attempt"]) + 1,
                            "lease_token": token,
                            "lease_until": now + lease,
                            "revision": int(payload["revision"]) + 1,
                            "updated_at": now,
                        }
                    )
                digest = _sha256(payload)
                connection.execute(
                    "UPDATE feed_jobs SET state=?,next_attempt_at=?,lease_until=?,"
                    "retained_until=?,payload_json=?,integrity_sha256=? "
                    "WHERE tenant_id=? AND job_id=?",
                    (
                        payload["state"],
                        payload["next_attempt_at"],
                        payload["lease_until"],
                        payload["retained_until"],
                        _canonical(payload).decode("ascii"),
                        digest,
                        tenant,
                        payload["job_id"],
                    ),
                )
                self._history(connection, payload)
                self._audit(
                    connection,
                    tenant,
                    "feed_job_claimed" if payload["state"] == "leased" else "feed_job_expired",
                    str(payload["job_id"]),
                    worker,
                    {"attempt": payload["attempt"], "state": payload["state"]},
                    now,
                )
                if payload["state"] == "leased":
                    claimed.append(self._job_from({**payload, "integrity_sha256": digest}))
            connection.commit()
        return tuple(claimed)

    def fail_job(
        self,
        tenant_id: str,
        job_id: str,
        *,
        lease_token: str,
        error_code: str,
        backoff_seconds: float,
        actor_ref: str,
    ) -> FeedJob:
        return self._finish_failed(
            tenant_id,
            job_id,
            lease_token=lease_token,
            error_code=error_code,
            backoff_seconds=backoff_seconds,
            actor_ref=actor_ref,
            revoke=False,
            force_dead_letter=False,
        )

    def dead_letter_job(
        self,
        tenant_id: str,
        job_id: str,
        *,
        lease_token: str,
        error_code: str,
        actor_ref: str,
    ) -> FeedJob:
        """Finish one leased job immediately after a definitive failure."""

        return self._finish_failed(
            tenant_id,
            job_id,
            lease_token=lease_token,
            error_code=error_code,
            backoff_seconds=0.0,
            actor_ref=actor_ref,
            revoke=False,
            force_dead_letter=True,
        )

    def revoke_job(
        self,
        tenant_id: str,
        job_id: str,
        *,
        lease_token: str,
        error_code: str,
        actor_ref: str,
    ) -> FeedJob:
        return self._finish_failed(
            tenant_id,
            job_id,
            lease_token=lease_token,
            error_code=error_code,
            backoff_seconds=0.0,
            actor_ref=actor_ref,
            revoke=True,
            force_dead_letter=False,
        )

    def _finish_failed(
        self,
        tenant_id: str,
        job_id: str,
        *,
        lease_token: str,
        error_code: str,
        backoff_seconds: float,
        actor_ref: str,
        revoke: bool,
        force_dead_letter: bool,
    ) -> FeedJob:
        tenant = _tenant(tenant_id)
        job = _identifier(job_id, "job_id")
        token = _digest(lease_token, "lease_token")
        code = _identifier(error_code, "error_code")
        actor = _identifier(actor_ref, "actor_ref")
        backoff = _number(
            backoff_seconds,
            "backoff_seconds",
            0.0 if revoke or force_dead_letter else 1.0,
            _MAX_BACKOFF_SECONDS,
        )
        now = self._now()
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM feed_jobs WHERE tenant_id=? AND job_id=?",
                (tenant, job),
            ).fetchone()
            if row is None:
                raise ThirdPartyFeedRuntimeNotFound("feed job was not found")
            payload = self._payload(row, "feed job")
            payload.pop("integrity_sha256", None)
            if (
                payload["state"] != "leased"
                or not _same(payload["lease_token"], token)
                or float(payload["lease_until"] or 0) < now
            ):
                raise ThirdPartyFeedRuntimeConflict("feed job lease was lost")
            if revoke:
                state = "revoked"
                next_attempt = now
            elif force_dead_letter:
                state = "dead_letter"
                next_attempt = now
            elif int(payload["attempt"]) >= int(payload["maximum_attempts"]):
                state = "dead_letter"
                next_attempt = now
            else:
                state = "retry"
                next_attempt = now + backoff
            payload.update(
                {
                    "state": state,
                    "next_attempt_at": next_attempt,
                    "lease_token": None,
                    "lease_until": None,
                    "last_error_code": code,
                    "revision": int(payload["revision"]) + 1,
                    "updated_at": now,
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE feed_jobs SET state=?,next_attempt_at=?,lease_until=NULL,"
                "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND job_id=?",
                (
                    state,
                    next_attempt,
                    _canonical(payload).decode("ascii"),
                    digest,
                    tenant,
                    job,
                ),
            )
            self._history(connection, payload)
            self._audit(
                connection,
                tenant,
                "feed_job_revoked" if revoke else "feed_job_failed",
                job,
                actor,
                {"state": state, "error_code": code},
                now,
            )
            connection.commit()
        return self.get_job(tenant, job)

    def complete_job(
        self,
        tenant_id: str,
        job_id: str,
        *,
        lease_token: str,
        receipt: Mapping[str, object],
        actor_ref: str,
    ) -> FeedReceipt:
        tenant = _tenant(tenant_id)
        job = _identifier(job_id, "job_id")
        token = _digest(lease_token, "lease_token")
        actor = _identifier(actor_ref, "actor_ref")
        now = self._now()
        expected_receipt_id = f"TPR-{_sha256(receipt)[:32]}"
        expected_fields = {
            "tenant_id",
            "job_id",
            "monitor_id",
            "monitor_revision_before",
            "monitor_revision_after",
            "changed",
            "alert_id",
            "observation_sha256",
            "evidence_sha256",
            "source_receipts",
            "retained_until",
        }
        if set(receipt) != expected_fields:
            raise ThirdPartyFeedRuntimeValidationError("feed receipt schema is closed")
        payload = {
            "schema": RECEIPT_SCHEMA,
            "tenant_id": tenant,
            "receipt_id": expected_receipt_id,
            **dict(receipt),
            "completed_at": now,
        }
        if payload.get("job_id") != job or payload.get("tenant_id") != tenant:
            raise ThirdPartyFeedRuntimeValidationError("feed receipt binding is invalid")
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM feed_jobs WHERE tenant_id=? AND job_id=?",
                (tenant, job),
            ).fetchone()
            if row is None:
                raise ThirdPartyFeedRuntimeNotFound("feed job was not found")
            job_payload = self._payload(row, "feed job")
            if job_payload["state"] == "completed":
                connection.rollback()
                return self.get_receipt(tenant, str(job_payload["receipt_id"]))
            job_payload.pop("integrity_sha256", None)
            if (
                job_payload["state"] != "leased"
                or not _same(job_payload["lease_token"], token)
                or float(job_payload["lease_until"] or 0) < now
            ):
                raise ThirdPartyFeedRuntimeConflict("feed job lease was lost")
            self._validate_receipt_payload(job_payload, payload)
            self._insert(
                connection,
                "feed_receipts",
                ("tenant_id", "receipt_id", "job_id", "retained_until"),
                (
                    tenant,
                    expected_receipt_id,
                    job,
                    payload["retained_until"],
                ),
                payload,
            )
            job_payload.update(
                {
                    "state": "completed",
                    "next_attempt_at": now,
                    "lease_token": None,
                    "lease_until": None,
                    "receipt_id": expected_receipt_id,
                    "last_error_code": None,
                    "revision": int(job_payload["revision"]) + 1,
                    "updated_at": now,
                }
            )
            digest = _sha256(job_payload)
            connection.execute(
                "UPDATE feed_jobs SET state='completed',next_attempt_at=?,lease_until=NULL,"
                "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND job_id=?",
                (
                    now,
                    _canonical(job_payload).decode("ascii"),
                    digest,
                    tenant,
                    job,
                ),
            )
            self._history(connection, job_payload)
            self._audit(
                connection,
                tenant,
                "feed_job_completed",
                expected_receipt_id,
                actor,
                {
                    "job_id_sha256": _sha256({"job_id": job}),
                    "observation_sha256": payload["observation_sha256"],
                    "evidence_sha256": payload["evidence_sha256"],
                },
                now,
            )
            connection.commit()
        return self.get_receipt(tenant, expected_receipt_id)

    @staticmethod
    def _validate_receipt_payload(
        job: Mapping[str, Any],
        receipt: Mapping[str, Any],
    ) -> None:
        changed = receipt.get("changed")
        alert_id = receipt.get("alert_id")
        if (
            receipt.get("monitor_id") != job.get("monitor_id")
            or receipt.get("monitor_revision_before") != job.get("monitor_revision")
            or receipt.get("monitor_revision_after") != int(job["monitor_revision"]) + 1
            or type(changed) is not bool
            or (changed and not isinstance(alert_id, str))
            or (not changed and alert_id is not None)
            or receipt.get("retained_until") != job.get("retained_until")
        ):
            raise ThirdPartyFeedRuntimeValidationError("feed receipt monitor binding is invalid")
        _digest(receipt.get("observation_sha256"), "observation_sha256")
        _digest(receipt.get("evidence_sha256"), "evidence_sha256")
        source_receipts = receipt.get("source_receipts")
        if isinstance(source_receipts, (str, bytes)) or not isinstance(
            source_receipts,
            Sequence,
        ):
            raise ThirdPartyFeedRuntimeValidationError("feed source receipts must be a list")
        pins = {(item["kind"], item["source_id"]): item for item in job["source_pins"]}
        if len(source_receipts) != len(pins):
            raise ThirdPartyFeedRuntimeValidationError(
                "feed source receipts do not exactly cover source pins"
            )
        required = {
            "kind",
            "provider",
            "source_id",
            "source_revision",
            "source_integrity_sha256",
            "credential_key_id_sha256",
            "dataset_revision",
            "snapshot_id",
            "snapshot_integrity_sha256",
            "provider_receipt_sha256",
            "coverage_complete",
            "cursor_count",
            "record_count",
        }
        seen: set[tuple[str, str]] = set()
        for item in source_receipts:
            if not isinstance(item, Mapping) or set(item) != required:
                raise ThirdPartyFeedRuntimeValidationError("feed source receipt schema is closed")
            key = (str(item["kind"]), str(item["source_id"]))
            pin = pins.get(key)
            if (
                pin is None
                or key in seen
                or item["provider"] != pin["provider"]
                or item["source_revision"] != pin["source_revision"]
                or item["source_integrity_sha256"] != pin["source_integrity_sha256"]
                or item["coverage_complete"] is not True
            ):
                raise ThirdPartyFeedRuntimeValidationError(
                    "feed source receipt authority binding is invalid"
                )
            seen.add(key)
            for field in (
                "source_integrity_sha256",
                "credential_key_id_sha256",
                "snapshot_integrity_sha256",
                "provider_receipt_sha256",
            ):
                _digest(item[field], field)
            _identifier(item["dataset_revision"], "dataset_revision")
            _identifier(item["snapshot_id"], "snapshot_id")
            _integer(item["cursor_count"], "cursor_count", 1, 32)
            _integer(item["record_count"], "record_count", 1, 5_000)

    def replay_dead_letter(
        self,
        tenant_id: str,
        job_id: str,
        *,
        expected_revision: int,
        actor_ref: str,
        idempotency_key: str,
    ) -> FeedJob:
        tenant = _tenant(tenant_id)
        job = _identifier(job_id, "job_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        actor = _identifier(actor_ref, "actor_ref")
        key_sha = self._operation_key(idempotency_key)
        request_sha = _sha256(
            {
                "action": "replay_dead_letter",
                "job_id": job,
                "expected_revision": expected,
                "actor_ref": actor,
            }
        )
        now = self._now()
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation(
                connection,
                tenant,
                "job.replay",
                key_sha,
                request_sha,
            )
            if replay is not None:
                connection.rollback()
                return self.get_job(tenant, replay[1])
            row = connection.execute(
                "SELECT * FROM feed_jobs WHERE tenant_id=? AND job_id=?",
                (tenant, job),
            ).fetchone()
            if row is None:
                raise ThirdPartyFeedRuntimeNotFound("feed job was not found")
            payload = self._payload(row, "feed job")
            payload.pop("integrity_sha256", None)
            if payload["state"] != "dead_letter" or int(payload["revision"]) != expected:
                raise ThirdPartyFeedRuntimeConflict(
                    "only the exact dead-letter revision can be replayed"
                )
            payload.update(
                {
                    "state": "pending",
                    "attempt": 0,
                    "next_attempt_at": now,
                    "lease_token": None,
                    "lease_until": None,
                    "last_error_code": None,
                    "revision": expected + 1,
                    "updated_at": now,
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE feed_jobs SET state='pending',next_attempt_at=?,lease_until=NULL,"
                "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND job_id=?",
                (now, _canonical(payload).decode("ascii"), digest, tenant, job),
            )
            self._history(connection, payload)
            self._record_operation(
                connection,
                tenant,
                "job.replay",
                key_sha,
                request_sha,
                "job",
                job,
            )
            self._audit(
                connection,
                tenant,
                "feed_job_replayed",
                job,
                actor,
                {"revision": expected + 1},
                now,
            )
            connection.commit()
        return self.get_job(tenant, job)

    def cancel_job(
        self,
        tenant_id: str,
        job_id: str,
        *,
        expected_revision: int,
        actor_ref: str,
        idempotency_key: str,
    ) -> FeedJob:
        tenant = _tenant(tenant_id)
        job = _identifier(job_id, "job_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        actor = _identifier(actor_ref, "actor_ref")
        key_sha = self._operation_key(idempotency_key)
        request_sha = _sha256(
            {
                "action": "cancel_job",
                "job_id": job,
                "expected_revision": expected,
                "actor_ref": actor,
            }
        )
        now = self._now()
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation(
                connection,
                tenant,
                "job.cancel",
                key_sha,
                request_sha,
            )
            if replay is not None:
                connection.rollback()
                return self.get_job(tenant, replay[1])
            row = connection.execute(
                "SELECT * FROM feed_jobs WHERE tenant_id=? AND job_id=?",
                (tenant, job),
            ).fetchone()
            if row is None:
                raise ThirdPartyFeedRuntimeNotFound("feed job was not found")
            payload = self._payload(row, "feed job")
            payload.pop("integrity_sha256", None)
            if payload["state"] not in _ACTIVE_STATES or int(payload["revision"]) != expected:
                raise ThirdPartyFeedRuntimeConflict("job is not cancellable at this revision")
            payload.update(
                {
                    "state": "cancelled",
                    "next_attempt_at": now,
                    "lease_token": None,
                    "lease_until": None,
                    "revision": expected + 1,
                    "updated_at": now,
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE feed_jobs SET state='cancelled',next_attempt_at=?,lease_until=NULL,"
                "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND job_id=?",
                (now, _canonical(payload).decode("ascii"), digest, tenant, job),
            )
            self._history(connection, payload)
            self._record_operation(
                connection,
                tenant,
                "job.cancel",
                key_sha,
                request_sha,
                "job",
                job,
            )
            self._audit(
                connection,
                tenant,
                "feed_job_cancelled",
                job,
                actor,
                {"revision": expected + 1},
                now,
            )
            connection.commit()
        return self.get_job(tenant, job)

    def purge_expired(self, tenant_id: str, *, cutoff: float) -> Mapping[str, int]:
        tenant = _tenant(tenant_id)
        moment = _number(cutoff, "cutoff", 0.001, self._now())
        with self._connect() as connection:
            self._begin(connection)
            terminal = tuple(sorted(_TERMINAL_STATES))
            placeholders = ",".join("?" for _ in terminal)
            jobs = connection.execute(
                f"SELECT job_id FROM feed_jobs WHERE tenant_id=? AND state IN "  # noqa: S608
                f"({placeholders}) AND retained_until<=?",
                (tenant, *terminal, moment),
            ).fetchall()
            job_ids = [str(row["job_id"]) for row in jobs]
            receipts = history = removed_jobs = 0
            for job_id in job_ids:
                receipts += connection.execute(
                    "DELETE FROM feed_receipts WHERE tenant_id=? AND job_id=?",
                    (tenant, job_id),
                ).rowcount
                history += connection.execute(
                    "DELETE FROM feed_history WHERE tenant_id=? AND job_id=?",
                    (tenant, job_id),
                ).rowcount
                removed_jobs += connection.execute(
                    "DELETE FROM feed_jobs WHERE tenant_id=? AND job_id=?",
                    (tenant, job_id),
                ).rowcount
            self._audit(
                connection,
                tenant,
                "feed_retention_purged",
                f"purge-{int(moment)}",
                "system-retention",
                {"jobs": removed_jobs, "receipts": receipts, "history": history},
                self._now(),
            )
            connection.commit()
        return {"jobs": removed_jobs, "receipts": receipts, "history": history}

    def verify_integrity(self, tenant_id: str) -> Mapping[str, int | str]:
        tenant = _tenant(tenant_id)
        counts: dict[str, int] = {
            "jobs": 0,
            "receipts": 0,
            "history": 0,
            "operations": 0,
            "audit_events": 0,
        }
        with self._connect() as connection:
            for table, key, label in (
                ("feed_jobs", "jobs", "feed job"),
                ("feed_receipts", "receipts", "feed receipt"),
                ("feed_history", "history", "feed history"),
                ("feed_operations", "operations", "feed operation"),
            ):
                rows = connection.execute(
                    f"SELECT * FROM {table} WHERE tenant_id=?",  # noqa: S608
                    (tenant,),
                ).fetchall()
                for row in rows:
                    payload = self._payload(row, label)
                    if payload.get("tenant_id") != tenant:
                        raise ThirdPartyFeedRuntimeIntegrityError(
                            f"{label} tenant binding is invalid"
                        )
                    counts[key] += 1
            heads = connection.execute(
                "SELECT * FROM feed_jobs WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            for row in heads:
                job = self._payload(row, "feed job")
                history_row = connection.execute(
                    "SELECT * FROM feed_history WHERE tenant_id=? AND job_id=? "
                    "ORDER BY revision DESC LIMIT 1",
                    (tenant, job["job_id"]),
                ).fetchone()
                if history_row is None:
                    raise ThirdPartyFeedRuntimeIntegrityError("feed job has no immutable history")
                history_payload = self._payload(history_row, "feed history")
                if (
                    history_payload["revision"] != job["revision"]
                    or history_payload["state"] != job["state"]
                    or history_payload.get("receipt_id") != job.get("receipt_id")
                ):
                    raise ThirdPartyFeedRuntimeIntegrityError(
                        "feed job differs from latest history"
                    )
                if job["state"] == "completed":
                    receipt = connection.execute(
                        "SELECT * FROM feed_receipts WHERE tenant_id=? AND receipt_id=?",
                        (tenant, job["receipt_id"]),
                    ).fetchone()
                    if receipt is None:
                        raise ThirdPartyFeedRuntimeIntegrityError(
                            "completed feed job lacks its receipt"
                        )
            rows = connection.execute(
                "SELECT * FROM feed_audit WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
            previous = "0" * 64
            expected_sequence = 1
            terminal = previous
            for row in rows:
                payload = self._payload(row, "feed audit")
                if (
                    payload.get("schema") != AUDIT_SCHEMA
                    or payload.get("tenant_id") != tenant
                    or payload.get("sequence") != expected_sequence
                    or payload.get("previous_integrity_sha256") != previous
                ):
                    raise ThirdPartyFeedRuntimeIntegrityError("feed audit chain is invalid")
                terminal = str(row["integrity_sha256"])
                previous = terminal
                expected_sequence += 1
                counts["audit_events"] += 1
        return {**counts, "terminal_audit_sha256": terminal}


def _authority(
    intelligence_store: Any,
    tenant: str,
    job: FeedJob,
    *,
    allow_recovery_revision: bool,
) -> tuple[Any, tuple[Any, ...]]:
    try:
        monitor = intelligence_store.get_monitor(tenant, job.monitor_id)
        sources = tuple(
            intelligence_store.get_source(tenant, pin.source_id) for pin in job.source_pins
        )
    except Exception as exc:
        raise ThirdPartyFeedAuthorityDrift("feed authority is unavailable") from exc
    allowed_revision = {job.monitor_revision}
    if allow_recovery_revision:
        allowed_revision.add(job.monitor_revision + 1)
    if (
        monitor.tenant_id != tenant
        or monitor.monitor_id != job.monitor_id
        or monitor.vendor_id != job.vendor_id
        or monitor.state != "active"
        or monitor.revision not in allowed_revision
        or (
            monitor.revision == job.monitor_revision
            and not _same(
                monitor.integrity_sha256,
                job.monitor_integrity_sha256,
            )
        )
        or dict(monitor.source_bindings) != {pin.kind: pin.source_id for pin in job.source_pins}
    ):
        raise ThirdPartyFeedAuthorityDrift("monitor authority drifted")
    for pin, source in zip(job.source_pins, sources, strict=True):
        if (
            source.tenant_id != tenant
            or source.source_id != pin.source_id
            or source.kind != pin.kind
            or source.provider != pin.provider
            or source.provenance_uri != pin.provenance_uri
            or source.credential_env != pin.credential_env
            or source.revision != pin.source_revision
            or not _same(source.integrity_sha256, pin.source_integrity_sha256)
            or source.state != "active"
            or source.approved_by is None
            or "monitoring" not in source.purposes
        ):
            raise ThirdPartyFeedAuthorityDrift("approved source authority drifted")
    return monitor, sources


def _safe_error_code(error: Exception) -> str:
    if isinstance(error, ThirdPartyFeedAuthorityDrift):
        return "authority_drift"
    if isinstance(error, ThirdPartyProviderCredentialError):
        return "credential_revoked" if error.revoked else "credential_unavailable"
    if isinstance(error, ThirdPartyProviderTransportError):
        if error.ambiguous:
            return "provider_ambiguous"
        return "provider_unavailable" if error.retryable else "provider_definitive"
    if isinstance(error, ThirdPartyProviderIncompleteError):
        return "provider_incomplete"
    if isinstance(error, ThirdPartyProviderProtocolError):
        return "provider_protocol"
    if isinstance(error, ThirdPartyProviderConfigError):
        return "provider_config"
    if isinstance(error, ThirdPartyProviderError):
        return "provider_unavailable"
    name = type(error).__name__.lower()
    if "credential" in name or "secret" in name or "key" in name:
        return "credential_unavailable"
    if "conflict" in name or "permission" in name or "notfound" in name:
        return "authority_drift"
    return "feed_runtime_error"


def _retryable_failure(error: Exception) -> bool:
    if isinstance(error, ThirdPartyProviderTransportError):
        return error.retryable
    if isinstance(error, ThirdPartyProviderCredentialError):
        return error.retryable
    if isinstance(error, ThirdPartyProviderIncompleteError):
        return True
    if isinstance(
        error,
        (
            ThirdPartyProviderProtocolError,
            ThirdPartyProviderConfigError,
        ),
    ):
        return False
    # Generic provider failures and cross-store acknowledgement failures retain
    # the bounded retry/dead-letter recovery behavior that predates the bundled
    # transport.  Only errors carrying a definitive classification bypass it.
    return True


def _provider_citations(result: ProviderFeedResult) -> list[dict[str, str]]:
    return [asdict(item) for item in result.citations]


def _execute_job(
    runtime_store: ThirdPartyFeedRuntimeStore,
    intelligence_store: Any,
    provider_factory: ThirdPartyProviderFactory,
    credential_resolver: CredentialResolver,
    job: FeedJob,
    *,
    worker_id: str,
) -> FeedReceipt:
    monitor, sources = _authority(
        intelligence_store,
        job.tenant_id,
        job,
        allow_recovery_revision=True,
    )
    results: list[ProviderFeedResult] = []
    for pin, _source in zip(job.source_pins, sources, strict=True):
        try:
            credential = credential_resolver(
                job.tenant_id,
                pin.credential_env,
                pin.provider,
                pin.source_id,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except ThirdPartyProviderError:
            raise
        except Exception:
            raise ThirdPartyFeedRuntimeConfigError("feed credential resolver failed") from None
        if not isinstance(credential, CredentialBinding):
            raise ThirdPartyFeedRuntimeConfigError(
                "credential resolver returned an invalid binding"
            )
        adapter = provider_factory.create(pin.provider, pin.provenance_uri)
        result = adapter.collect(
            ProviderRequest(
                tenant_id=job.tenant_id,
                provider=pin.provider,
                source_id=pin.source_id,
                source_revision=pin.source_revision,
                source_integrity_sha256=pin.source_integrity_sha256,
                kind=pin.kind,
                capability="monitoring",
                key_id=credential.key_id,
            ),
            credential,
        )
        if not result.coverage_complete:
            raise ThirdPartyProviderError("provider feed is not complete")
        now = runtime_store._now()
        if result.observed_at > now or result.valid_until <= now:
            raise ThirdPartyProviderError("provider observation is not currently fresh")
        results.append(result)
    monitor_after_io, _sources_after_io = _authority(
        intelligence_store,
        job.tenant_id,
        job,
        allow_recovery_revision=True,
    )
    observation = _sha256(
        [
            {
                "kind": result.kind,
                "source_id": result.source_id,
                "observation_sha256": result.observation_sha256,
            }
            for result in sorted(results, key=lambda item: item.kind)
        ]
    )
    evidence = _sha256(
        [
            {
                "kind": result.kind,
                "source_id": result.source_id,
                "evidence_sha256": result.evidence_sha256,
                "provider_receipt_sha256": result.provider_receipt_sha256,
            }
            for result in sorted(results, key=lambda item: item.kind)
        ]
    )
    if monitor_after_io.revision == job.monitor_revision + 1 and not _same(
        monitor_after_io.last_observation_sha256,
        observation,
    ):
        raise ThirdPartyFeedAuthorityDrift("monitor changed to a different observation")
    actor = f"feed-worker-{hashlib.sha256(worker_id.encode()).hexdigest()[:32]}"
    bindings: dict[str, str] = {}
    citations_by_id: dict[str, dict[str, str]] = {}
    source_receipts: list[dict[str, object]] = []
    for pin, result in zip(job.source_pins, results, strict=True):
        snapshot_stable = _sha256(
            {
                "job_id": job.job_id,
                "source_id": pin.source_id,
                "source_revision": pin.source_revision,
                "provider_receipt_sha256": result.provider_receipt_sha256,
            }
        )
        snapshot_id = f"TPS-{snapshot_stable[:32]}"
        citations = _provider_citations(result)
        snapshot = intelligence_store.record_source_snapshot(
            job.tenant_id,
            pin.source_id,
            snapshot_id=snapshot_id,
            dataset_revision=result.dataset_revision,
            observed_at=result.observed_at,
            valid_until=result.valid_until,
            completeness=1.0,
            record_count=result.record_count,
            evidence_sha256=result.evidence_sha256,
            citations=citations,
            provenance_uri=pin.provenance_uri,
            actor_ref=actor,
            idempotency_key=f"feed-snapshot-{snapshot_stable[:48]}",
            expected_source_revision=pin.source_revision,
            expected_source_integrity_sha256=pin.source_integrity_sha256,
        )
        if (
            snapshot.tenant_id != job.tenant_id
            or snapshot.source_id != pin.source_id
            or snapshot.source_revision != pin.source_revision
            or not _same(snapshot.evidence_sha256, result.evidence_sha256)
        ):
            raise ThirdPartyFeedRuntimeIntegrityError(
                "recorded source snapshot does not match the provider receipt"
            )
        bindings[pin.kind] = snapshot.snapshot_id
        for citation in citations:
            prior = citations_by_id.get(citation["citation_id"])
            if prior is not None and prior != citation:
                raise ThirdPartyFeedRuntimeIntegrityError(
                    "provider citation identity drifted across sources"
                )
            citations_by_id[citation["citation_id"]] = citation
        source_receipts.append(
            {
                "kind": pin.kind,
                "provider": pin.provider,
                "source_id": pin.source_id,
                "source_revision": pin.source_revision,
                "source_integrity_sha256": pin.source_integrity_sha256,
                "credential_key_id_sha256": result.key_id_sha256,
                "dataset_revision": result.dataset_revision,
                "snapshot_id": snapshot.snapshot_id,
                "snapshot_integrity_sha256": snapshot.integrity_sha256,
                "provider_receipt_sha256": result.provider_receipt_sha256,
                "coverage_complete": True,
                "cursor_count": result.cursor_count,
                "record_count": result.record_count,
            }
        )
    if len(citations_by_id) > 100:
        raise ThirdPartyFeedRuntimeValidationError(
            "combined provider citations exceed the monitor bound"
        )
    monitor_result = intelligence_store.record_monitor_observation(
        job.tenant_id,
        job.monitor_id,
        snapshot_bindings=bindings,
        observation_sha256=observation,
        evidence_sha256=evidence,
        citations=[citations_by_id[key] for key in sorted(citations_by_id)],
        expected_revision=job.monitor_revision,
        actor_ref=actor,
        idempotency_key=f"feed-observation-{job.job_id}",
    )
    if (
        monitor_result.monitor.tenant_id != job.tenant_id
        or monitor_result.monitor.monitor_id != job.monitor_id
        or monitor_result.monitor.revision != job.monitor_revision + 1
        or not _same(monitor_result.monitor.last_observation_sha256, observation)
    ):
        raise ThirdPartyFeedRuntimeIntegrityError(
            "monitor observation acknowledgement is inconsistent"
        )
    alert_id = None if monitor_result.alert is None else monitor_result.alert.alert_id
    receipt_payload = {
        "tenant_id": job.tenant_id,
        "job_id": job.job_id,
        "monitor_id": job.monitor_id,
        "monitor_revision_before": job.monitor_revision,
        "monitor_revision_after": monitor_result.monitor.revision,
        "changed": monitor_result.changed,
        "alert_id": alert_id,
        "observation_sha256": observation,
        "evidence_sha256": evidence,
        "source_receipts": source_receipts,
        "retained_until": job.retained_until,
    }
    if job.lease_token is None:
        raise ThirdPartyFeedRuntimeIntegrityError("claimed job lacks a lease token")
    return runtime_store.complete_job(
        job.tenant_id,
        job.job_id,
        lease_token=job.lease_token,
        receipt=receipt_payload,
        actor_ref=actor,
    )


def run_feed_batch(
    runtime_store: ThirdPartyFeedRuntimeStore,
    intelligence_store: Any,
    provider_factory: ThirdPartyProviderFactory,
    credential_resolver: CredentialResolver,
    *,
    tenant_id: str,
    worker_id: str,
    limit: int = 10,
    lease_seconds: float = 60.0,
    base_backoff_seconds: float = 30.0,
    maximum_backoff_seconds: float = 86_400.0,
) -> FeedBatchResult:
    """Run one tenant-bound batch; provider failures never cross tenants."""

    tenant = _tenant(tenant_id)
    worker = _identifier(worker_id, "worker_id")
    base = _number(base_backoff_seconds, "base_backoff_seconds", 1.0, _MAX_BACKOFF_SECONDS)
    maximum = _number(
        maximum_backoff_seconds,
        "maximum_backoff_seconds",
        base,
        _MAX_BACKOFF_SECONDS,
    )
    if not callable(credential_resolver):
        raise ThirdPartyFeedRuntimeConfigError("credential resolver is unavailable")
    jobs = runtime_store.claim_jobs(
        tenant,
        worker_id=worker,
        limit=limit,
        lease_seconds=lease_seconds,
    )
    outcomes: list[FeedBatchOutcome] = []
    completed = retry_pending = dead_lettered = revoked = 0
    for job in jobs:
        try:
            receipt = _execute_job(
                runtime_store,
                intelligence_store,
                provider_factory,
                credential_resolver,
                job,
                worker_id=worker,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:  # noqa: BLE001 - boundary errors are sanitized
            if job.lease_token is None:  # pragma: no cover - claim invariant
                raise ThirdPartyFeedRuntimeIntegrityError("claimed feed job lacks a lease") from exc
            code = _safe_error_code(exc)
            if code in {"authority_drift", "credential_revoked"}:
                failed = runtime_store.revoke_job(
                    tenant,
                    job.job_id,
                    lease_token=job.lease_token,
                    error_code=code,
                    actor_ref=worker,
                )
                revoked += 1
            elif not _retryable_failure(exc):
                failed = runtime_store.dead_letter_job(
                    tenant,
                    job.job_id,
                    lease_token=job.lease_token,
                    error_code=code,
                    actor_ref=worker,
                )
                dead_lettered += 1
            else:
                backoff = min(maximum, base * (2 ** max(0, job.attempt - 1)))
                failed = runtime_store.fail_job(
                    tenant,
                    job.job_id,
                    lease_token=job.lease_token,
                    error_code=code,
                    backoff_seconds=backoff,
                    actor_ref=worker,
                )
                if failed.state == "dead_letter":
                    dead_lettered += 1
                else:
                    retry_pending += 1
            outcomes.append(
                FeedBatchOutcome(
                    job_id=job.job_id,
                    state=failed.state,
                    error_code=code,
                )
            )
        else:
            completed += 1
            outcomes.append(
                FeedBatchOutcome(
                    job_id=job.job_id,
                    state="completed",
                    receipt_id=receipt.receipt_id,
                )
            )
    return FeedBatchResult(
        tenant_id=tenant,
        claimed=len(jobs),
        completed=completed,
        retry_pending=retry_pending,
        dead_lettered=dead_lettered,
        revoked=revoked,
        outcomes=tuple(outcomes),
    )


def enqueue_due_monitors(
    runtime_store: ThirdPartyFeedRuntimeStore,
    intelligence_store: Any,
    *,
    tenant_id: str,
    actor_ref: str,
    limit: int = 100,
) -> tuple[FeedJob, ...]:
    """Rotate due monitors without duplicating revisions or blocking peers."""

    from .third_party_intelligence import ThirdPartyIntelligenceNotFound

    tenant = _tenant(tenant_id)
    actor = _identifier(actor_ref, "actor_ref")
    count = _integer(limit, "limit", 1, 500)
    monitors = runtime_store.select_due_monitors(tenant, intelligence_store, limit=count)
    jobs: list[FeedJob] = []
    for monitor in monitors:
        stable = _sha256(
            {
                "tenant_id": tenant,
                "monitor_id": monitor.monitor_id,
                "monitor_revision": monitor.revision,
                "monitor_integrity_sha256": monitor.integrity_sha256,
            }
        )
        try:
            job = runtime_store.enqueue_monitor(
                tenant,
                monitor.monitor_id,
                intelligence_store,
                actor_ref=actor,
                idempotency_key=f"due-monitor-{stable[:48]}",
                require_due=True,
            )
        except (ThirdPartyFeedRuntimeConflict, ThirdPartyIntelligenceNotFound):
            # Current source/monitor authority can change after selection. No
            # job or permission is invented; eligible peers still get queued.
            # Configuration, integrity and unexpected failures still surface.
            logging.getLogger(__name__).warning(
                "Due monitor refused by current authority: tenant=%s monitor=%s",
                tenant, monitor.monitor_id,
            )
            continue
        jobs.append(job)
    return tuple(jobs)


__all__ = [
    "AUTOMATIC_VENDOR_APPROVAL",
    "CROSS_STORE_ATOMICITY",
    "CredentialResolver",
    "FeedBatchOutcome",
    "FeedBatchResult",
    "FeedJob",
    "FeedReceipt",
    "LIVE_PROVIDER_ACCEPTANCE_VERIFIED",
    "NETWORK_IO",
    "PROVIDER_WRITES",
    "RAW_CREDENTIALS_PERSISTED",
    "RAW_PROVIDER_PAYLOADS_PERSISTED",
    "SourceAuthorityPin",
    "ThirdPartyFeedAuthorityDrift",
    "ThirdPartyFeedRuntimeConfigError",
    "ThirdPartyFeedRuntimeConflict",
    "ThirdPartyFeedRuntimeError",
    "ThirdPartyFeedRuntimeIntegrityError",
    "ThirdPartyFeedRuntimeNotFound",
    "ThirdPartyFeedRuntimeStore",
    "ThirdPartyFeedRuntimeValidationError",
    "enabled",
    "enqueue_due_monitors",
    "require_enabled",
    "run_feed_batch",
]
