"""Durable, tenant-scoped consent bulk-job authority.

The authority implements the control plane shared by large receipt exports and
governed data-subject mutations.  It deliberately does not invent provider or
identity authority: callers supply already-authorized, opaque job items and a
deployment-owned executor.  Jobs are idempotent, credit-reserved, lease based,
recoverable after worker loss, cancellable, retention bounded, and recorded in
an append-only hash chain.

Raw identity values, credentials, filesystem paths, exception messages, and
unbounded documents are outside this contract.  Export artifacts are bounded
canonical JSON held in the private SQLite authority and are released only by
the administrative API after the job reaches ``succeeded``.
"""

from __future__ import annotations

import contextlib
import hashlib
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

from . import consent_storage
from .constant_time import text_equals
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

SCHEMA_VERSION = 1
JOB_SCHEMA = "lightwork.consent-bulk-job.v1"
ARTIFACT_SCHEMA = "lightwork.consent-bulk-export.v1"
EVENT_SCHEMA = "lightwork.consent-bulk-job-event.v1"

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_JOB_KINDS = frozenset({"export", "mutation"})
_OPERATIONS = frozenset(
    {
        "export_receipts",
        "edit_preferences",
        "delete_subject",
        "change_identifier_type",
        "reactivate",
        "clear_expiration",
    }
)
_EXPORT_OPERATIONS = frozenset({"export_receipts"})
_MUTATION_OPERATIONS = _OPERATIONS - _EXPORT_OPERATIONS
_STATES = frozenset(
    {"queued", "running", "succeeded", "failed", "cancelled"}
)
_TERMINAL_STATES = frozenset({"succeeded", "failed", "cancelled"})
_ITEM_STATES = frozenset({"pending", "succeeded", "failed"})
_ERROR_CODES = frozenset(
    {
        "authority_unavailable",
        "conflict",
        "invalid_item",
        "not_found",
        "quota_exceeded",
        "worker_failure",
    }
)
_MAX_JSON_BYTES = 256 * 1024
_MAX_ITEM_BYTES = 64 * 1024
_MAX_RESULT_BYTES = 512 * 1024
_MAX_READ_LIMIT = 500


class ConsentBulkJobError(RuntimeError):
    """Base error for the consent bulk-job authority."""


class ConsentBulkJobValidationError(ConsentBulkJobError, ValueError):
    """Input is outside the closed bulk-job contract."""


class ConsentBulkJobConflict(ConsentBulkJobError):
    """A concurrency, idempotency, credit, or state precondition failed."""


class ConsentBulkJobNotFound(ConsentBulkJobError):
    """A tenant-scoped job or artifact does not exist."""


class ConsentBulkJobLeaseLost(ConsentBulkJobConflict):
    """A worker no longer owns the job lease."""


@dataclass(frozen=True, slots=True)
class ConsentBulkJobLimits:
    max_jobs: int = 10_000
    max_items_per_job: int = 10_000
    max_artifact_bytes: int = 16 * 1024 * 1024
    lease_seconds: int = 60
    retention_seconds: int = 31_536_000

    def __post_init__(self) -> None:
        _integer(self.max_jobs, "max_jobs", 1, 1_000_000)
        _integer(self.max_items_per_job, "max_items_per_job", 1, 100_000)
        _integer(
            self.max_artifact_bytes,
            "max_artifact_bytes",
            1_024,
            256 * 1024 * 1024,
        )
        _integer(self.lease_seconds, "lease_seconds", 5, 3_600)
        _integer(
            self.retention_seconds,
            "retention_seconds",
            86_400,
            315_360_000,
        )


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise ConsentBulkJobValidationError("bulk-job data must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise ConsentBulkJobValidationError("bulk-job data exceeds its byte bound")
    return encoded


def _sha256(value: object, *, maximum: int = _MAX_JSON_BYTES) -> str:
    return hashlib.sha256(_canonical(value, maximum=maximum)).hexdigest()


def _loads(value: object, label: str, *, maximum: int = _MAX_JSON_BYTES) -> Any:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= maximum:
        raise ConsentBulkJobError(f"stored {label} is invalid")
    try:
        return json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ConsentBulkJobError(f"stored {label} is invalid") from exc


def _text(value: object, label: str, pattern: re.Pattern[str] = _REF_RE) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ConsentBulkJobValidationError(f"{label} is not a bounded identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ConsentBulkJobValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise ConsentBulkJobValidationError("tenant_id is invalid") from exc


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ConsentBulkJobValidationError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str, *, allow_none: bool = False) -> float | None:
    if value is None and allow_none:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise ConsentBulkJobValidationError(f"{label} must be a positive timestamp")
    return float(value)


def _validate_item(  # noqa: C901 - operation-specific closed contracts
    operation: str, value: object
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ConsentBulkJobValidationError("bulk-job item must be an object")
    item = {str(key): item for key, item in value.items()}
    _canonical(item, maximum=_MAX_ITEM_BYTES)
    common = {"item_id", "profile_id"}
    required: set[str]
    allowed: set[str]
    if operation == "export_receipts":
        if "after_sequence" in item:
            raise ConsentBulkJobValidationError(
                "Receipt exports from a saved position are not supported. "
                "Select up to the latest 500 records per person."
            )
        required = common
        allowed = common | {"receipt_limit"}
    elif operation == "edit_preferences":
        required = common | {
            "expected_revision",
            "policy_id",
            "policy_version",
            "context",
            "choices",
        }
        allowed = required | {"retention_until", "reactivation_at"}
    elif operation == "reactivate":
        required = common | {
            "expected_revision",
            "receipt_id",
            "reactivation_at",
        }
        allowed = required
    elif operation == "delete_subject":
        required = common | {"expected_revision", "reason_code"}
        allowed = required
    elif operation == "change_identifier_type":
        required = common | {
            "expected_revision",
            "identity_kind",
            "subject_sha256",
        }
        allowed = required
    elif operation == "clear_expiration":
        required = common | {"expected_revision", "receipt_id"}
        allowed = required
    else:  # pragma: no cover - caller validates the closed operation enum
        raise ConsentBulkJobValidationError("bulk-job operation is invalid")
    if set(item) - allowed or required - set(item):
        raise ConsentBulkJobValidationError("bulk-job item shape is invalid")
    _text(item["item_id"], "item_id")
    _text(item["profile_id"], "profile_id")
    if "expected_revision" in item:
        _integer(item["expected_revision"], "expected_revision", 0, 2**31 - 1)
    if "policy_id" in item:
        _text(item["policy_id"], "policy_id")
        _integer(item["policy_version"], "policy_version", 1, 2**31 - 1)
        if not isinstance(item["context"], Mapping):
            raise ConsentBulkJobValidationError("context must be an object")
        if not isinstance(item["choices"], list) or not 1 <= len(item["choices"]) <= 128:
            raise ConsentBulkJobValidationError("choices must be a bounded list")
        if item.get("retention_until") is not None:
            _timestamp(item["retention_until"], "retention_until")
        if item.get("reactivation_at") is not None:
            _timestamp(item["reactivation_at"], "reactivation_at")
    if operation == "delete_subject":
        _text(item["reason_code"], "reason_code")
    if operation == "change_identifier_type":
        if item["identity_kind"] not in {"known", "anonymous"}:
            raise ConsentBulkJobValidationError("identity_kind is invalid")
        _digest(item["subject_sha256"], "subject_sha256")
    if operation in {"reactivate", "clear_expiration"}:
        _text(item["receipt_id"], "receipt_id")
    if operation == "reactivate":
        _timestamp(item["reactivation_at"], "reactivation_at")
    if operation == "export_receipts":
        if "receipt_limit" in item:
            _integer(item["receipt_limit"], "receipt_limit", 1, 500)
    return item


class ConsentBulkJobStore:
    """Private SQLite authority for exports, mutations, credits, and leases."""

    def __init__(
        self,
        path: Path,
        *,
        limits: ConsentBulkJobLimits | None = None,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
    ) -> None:
        self.path = Path(path).expanduser()
        self.limits = limits or ConsentBulkJobLimits()
        self._clock = clock
        self._id_factory = id_factory or (
            lambda prefix: f"{prefix}-{secrets.token_urlsafe(18)}"
        )
        if not callable(clock) or not callable(self._id_factory):
            raise TypeError("bulk-job clock and id factory must be callable")
        self._initialize()

    @contextlib.contextmanager
    def _connect(self):
        with consent_storage.authority_connection(
            self.path, ensure_directory=ensure_private_directory,
            ensure_file=ensure_private_file,
        ) as connection:
            yield connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS consent_bulk_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS consent_bulk_credits (
                    tenant TEXT PRIMARY KEY,
                    available INTEGER NOT NULL,
                    reserved INTEGER NOT NULL,
                    consumed INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS consent_bulk_jobs (
                    tenant TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (kind IN ('export', 'mutation')),
                    operation TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (
                        state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')
                    ),
                    actor_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    scheduled_for REAL NOT NULL,
                    total_items INTEGER NOT NULL,
                    processed_items INTEGER NOT NULL,
                    failed_items INTEGER NOT NULL,
                    credits_reserved INTEGER NOT NULL,
                    credits_consumed INTEGER NOT NULL,
                    credits_refunded INTEGER NOT NULL,
                    cancel_requested INTEGER NOT NULL CHECK (cancel_requested IN (0, 1)),
                    lease_owner_sha256 TEXT,
                    lease_expires_at REAL,
                    revision INTEGER NOT NULL,
                    artifact_json TEXT,
                    artifact_sha256 TEXT,
                    result_sha256 TEXT,
                    created_at REAL NOT NULL,
                    started_at REAL,
                    completed_at REAL,
                    retention_until REAL NOT NULL,
                    PRIMARY KEY (tenant, job_id)
                );
                CREATE INDEX IF NOT EXISTS consent_bulk_jobs_due
                    ON consent_bulk_jobs(tenant, state, scheduled_for, created_at);
                CREATE INDEX IF NOT EXISTS consent_bulk_jobs_browse
                    ON consent_bulk_jobs(tenant, created_at DESC, job_id DESC);
                CREATE TABLE IF NOT EXISTS consent_bulk_items (
                    tenant TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    item_id TEXT NOT NULL,
                    input_json TEXT NOT NULL,
                    input_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('pending', 'succeeded', 'failed')),
                    attempts INTEGER NOT NULL,
                    result_json TEXT,
                    result_sha256 TEXT,
                    error_code TEXT,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (tenant, job_id, ordinal),
                    UNIQUE (tenant, job_id, item_id),
                    FOREIGN KEY (tenant, job_id)
                        REFERENCES consent_bulk_jobs(tenant, job_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS consent_bulk_idempotency (
                    tenant TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant, namespace, key_sha256)
                );
                CREATE TABLE IF NOT EXISTS consent_bulk_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    previous_event_sha256 TEXT,
                    event_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE (tenant, event_id)
                );
                CREATE INDEX IF NOT EXISTS consent_bulk_events_job
                    ON consent_bulk_events(tenant, job_id, sequence);

                CREATE TRIGGER IF NOT EXISTS consent_bulk_events_no_update
                    BEFORE UPDATE ON consent_bulk_events
                    BEGIN SELECT RAISE(ABORT, 'bulk events are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_bulk_events_no_delete
                    BEFORE DELETE ON consent_bulk_events
                    BEGIN SELECT RAISE(ABORT, 'bulk events are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_bulk_idempotency_no_update
                    BEFORE UPDATE ON consent_bulk_idempotency
                    BEGIN SELECT RAISE(ABORT, 'bulk idempotency is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS consent_bulk_idempotency_no_delete
                    BEFORE DELETE ON consent_bulk_idempotency
                    BEGIN SELECT RAISE(ABORT, 'bulk idempotency is immutable'); END;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO consent_bulk_meta(key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )
            row = connection.execute(
                "SELECT value FROM consent_bulk_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None or row["value"] != str(SCHEMA_VERSION):
                raise ConsentBulkJobError("unsupported consent bulk-job schema")

    def _now(self) -> float:
        value = _timestamp(self._clock(), "clock")
        assert value is not None
        return value

    def _new_id(self, prefix: str) -> str:
        return _text(self._id_factory(prefix), f"{prefix} identifier")

    @staticmethod
    def _idempotency(value: object) -> str:
        raw = _text(value, "idempotency_key", _IDEMPOTENCY_RE)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _replay(
        connection: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT request_sha256, result_json FROM consent_bulk_idempotency "
            "WHERE tenant = ? AND namespace = ? AND key_sha256 = ?",
            (tenant, namespace, key_sha256),
        ).fetchone()
        if row is None:
            return None
        if not text_equals(str(row["request_sha256"]), request_sha256):
            raise ConsentBulkJobConflict(
                "idempotency key was already used for different content"
            )
        result = _loads(row["result_json"], "idempotency result")
        if not isinstance(result, dict):
            raise ConsentBulkJobError("stored idempotency result is invalid")
        return result

    @staticmethod
    def _save_replay(
        connection: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
        result: Mapping[str, Any],
        now: float,
    ) -> None:
        connection.execute(
            "INSERT INTO consent_bulk_idempotency(tenant, namespace, key_sha256, "
            "request_sha256, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                tenant,
                namespace,
                key_sha256,
                request_sha256,
                _canonical(result).decode("ascii"),
                now,
            ),
        )

    def _event(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        job_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        now: float,
    ) -> None:
        event = _text(event_type, "event_type")
        prior = connection.execute(
            "SELECT event_sha256 FROM consent_bulk_events WHERE tenant = ? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant,),
        ).fetchone()
        previous = str(prior["event_sha256"]) if prior is not None else None
        event_id = self._new_id("CP-BEV")
        body = {
            "schema": EVENT_SCHEMA,
            "event_id": event_id,
            "job_id": job_id,
            "event_type": event,
            "payload": dict(payload),
            "previous_event_sha256": previous,
            "created_at": now,
        }
        payload_sha = _sha256(payload)
        event_sha = _sha256(body)
        connection.execute(
            "INSERT INTO consent_bulk_events(tenant, event_id, job_id, event_type, "
            "payload_json, payload_sha256, previous_event_sha256, event_sha256, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tenant,
                event_id,
                job_id,
                event,
                _canonical(payload).decode("ascii"),
                payload_sha,
                previous,
                event_sha,
                now,
            ),
        )

    def ensure_credit_account(
        self,
        tenant_id: str,
        *,
        initial_credits: int,
    ) -> dict[str, Any]:
        """Create the tenant credit account once; never silently replenish it."""

        tenant = _tenant(tenant_id)
        initial = _integer(initial_credits, "initial_credits", 0, 1_000_000_000)
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT OR IGNORE INTO consent_bulk_credits(tenant, available, "
                    "reserved, consumed, revision, updated_at) VALUES (?, ?, 0, 0, 1, ?)",
                    (tenant, initial, now),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return self.credit_detail(tenant)

    def grant_credits(
        self,
        tenant_id: str,
        amount: int,
        *,
        expected_revision: int,
        idempotency_key: str,
        actor_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Explicitly grant credits with CAS and idempotency."""

        tenant = _tenant(tenant_id)
        granted = _integer(amount, "amount", 1, 1_000_000_000)
        revision = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        key_sha = self._idempotency(idempotency_key)
        actor = _digest(actor_sha256, "actor_sha256") if actor_sha256 is not None else None
        request = {"amount": granted, "expected_revision": revision}
        if actor is not None:
            request["actor_sha256"] = actor
        request_sha = _sha256(request)
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay(
                    connection,
                    tenant=tenant,
                    namespace="credits.grant",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return {key: value for key, value in replay.items() if key != "actor_sha256"}
                updated = connection.execute(
                    "UPDATE consent_bulk_credits SET available = available + ?, "
                    "revision = revision + 1, updated_at = ? WHERE tenant = ? "
                    "AND revision = ?",
                    (granted, now, tenant, revision),
                )
                if updated.rowcount != 1:
                    raise ConsentBulkJobConflict("credit account revision changed")
                result = self._credit_row(connection, tenant)
                if actor is not None:
                    result["added"] = granted
                self._save_replay(
                    connection,
                    tenant=tenant,
                    namespace="credits.grant",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result={**result, **({"actor_sha256": actor} if actor is not None else {})},
                    now=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def granted_credit_for_request(
        self, tenant_id: str, *, idempotency_key: str, actor_sha256: str,
    ) -> dict[str, Any] | None:
        """Read the original actor's accepted allowance, never grant it again."""
        tenant = _tenant(tenant_id)
        key, actor = self._idempotency(idempotency_key), _digest(actor_sha256, "actor_sha256")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM consent_bulk_idempotency WHERE tenant = ? "
                "AND namespace = 'credits.grant' AND key_sha256 = ?", (tenant, key),
            ).fetchone()
            if row is None:
                return None
            result = _loads(row["result_json"], "idempotency result")
            if not isinstance(result, dict):
                raise ConsentBulkJobError("stored allowance result is invalid")
            if not text_equals(str(result.get("actor_sha256", "")), actor):
                return None
            return {key: value for key, value in result.items() if key != "actor_sha256"}

    @staticmethod
    def _credit_row(connection: sqlite3.Connection, tenant: str) -> dict[str, Any]:
        row = connection.execute(
            "SELECT available, reserved, consumed, revision, updated_at "
            "FROM consent_bulk_credits WHERE tenant = ?",
            (tenant,),
        ).fetchone()
        if row is None:
            raise ConsentBulkJobConflict("bulk-job credit account is not configured")
        return {
            "available": int(row["available"]),
            "reserved": int(row["reserved"]),
            "consumed": int(row["consumed"]),
            "revision": int(row["revision"]),
            "updated_at": float(row["updated_at"]),
        }

    def credit_detail(self, tenant_id: str) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        with self._connect() as connection:
            return self._credit_row(connection, tenant)

    def create_job(  # noqa: PLR0913 - explicit authority inputs
        self,
        tenant_id: str,
        *,
        kind: str,
        operation: str,
        items: Sequence[Mapping[str, Any]],
        actor_sha256: str,
        scheduled_for: float | None,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        if kind not in _JOB_KINDS or operation not in _OPERATIONS:
            raise ConsentBulkJobValidationError("bulk-job kind or operation is invalid")
        if (kind == "export") != (operation in _EXPORT_OPERATIONS):
            raise ConsentBulkJobValidationError("bulk-job kind does not match operation")
        if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
            raise ConsentBulkJobValidationError("items must be a bounded sequence")
        if not 1 <= len(items) <= self.limits.max_items_per_job:
            raise ConsentBulkJobValidationError("bulk-job item count is outside its bound")
        normalized = [_validate_item(operation, item) for item in items]
        item_ids = [str(item["item_id"]) for item in normalized]
        if len(set(item_ids)) != len(item_ids):
            raise ConsentBulkJobValidationError("bulk-job item identifiers must be unique")
        actor = _digest(actor_sha256, "actor_sha256")
        now = self._now()
        requested_schedule = _timestamp(scheduled_for, "scheduled_for", allow_none=True)
        scheduled = requested_schedule or now
        key_sha = self._idempotency(idempotency_key)
        request = {
            "kind": kind,
            "operation": operation,
            "items": normalized,
            "actor_sha256": actor,
            # Hash the submitted choice, not the clock used to start immediate
            # work. Otherwise an identical retry always conflicts a moment later.
            "scheduled_for": requested_schedule,
        }
        request_sha = _sha256(request, maximum=max(_MAX_JSON_BYTES, len(normalized) * _MAX_ITEM_BYTES))
        credits = len(normalized)
        retention_until = now + self.limits.retention_seconds
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay(
                    connection,
                    tenant=tenant,
                    namespace="jobs.create",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                count = connection.execute(
                    "SELECT COUNT(*) AS count FROM consent_bulk_jobs WHERE tenant = ? "
                    "AND retention_until > ?",
                    (tenant, now),
                ).fetchone()
                if count is None or int(count["count"]) >= self.limits.max_jobs:
                    raise ConsentBulkJobConflict("bulk-job quota is exhausted")
                credit = self._credit_row(connection, tenant)
                if credit["available"] < credits:
                    raise ConsentBulkJobConflict("bulk-job credits are exhausted")
                connection.execute(
                    "UPDATE consent_bulk_credits SET available = available - ?, "
                    "reserved = reserved + ?, revision = revision + 1, updated_at = ? "
                    "WHERE tenant = ?",
                    (credits, credits, now, tenant),
                )
                job_id = self._new_id("CP-BJOB")
                connection.execute(
                    "INSERT INTO consent_bulk_jobs(tenant, job_id, kind, operation, "
                    "state, actor_sha256, request_sha256, scheduled_for, total_items, "
                    "processed_items, failed_items, credits_reserved, credits_consumed, "
                    "credits_refunded, cancel_requested, revision, created_at, "
                    "retention_until) VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?, 0, 0, "
                    "?, 0, 0, 0, 1, ?, ?)",
                    (
                        tenant,
                        job_id,
                        kind,
                        operation,
                        actor,
                        request_sha,
                        scheduled,
                        len(normalized),
                        credits,
                        now,
                        retention_until,
                    ),
                )
                for ordinal, item in enumerate(normalized):
                    connection.execute(
                        "INSERT INTO consent_bulk_items(tenant, job_id, ordinal, item_id, "
                        "input_json, input_sha256, state, attempts, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, ?)",
                        (
                            tenant,
                            job_id,
                            ordinal,
                            item["item_id"],
                            _canonical(item, maximum=_MAX_ITEM_BYTES).decode("ascii"),
                            _sha256(item, maximum=_MAX_ITEM_BYTES),
                            now,
                        ),
                    )
                result = self._job_row(connection, tenant, job_id)
                self._event(
                    connection,
                    tenant=tenant,
                    job_id=job_id,
                    event_type="job.created",
                    payload={
                        "kind": kind,
                        "operation": operation,
                        "executor_scope": "job",
                        "receipt_revision_chain": True,
                        "total_items": len(normalized),
                        "scheduled_for": scheduled,
                        "request_sha256": request_sha,
                    },
                    now=now,
                )
                self._save_replay(
                    connection,
                    tenant=tenant,
                    namespace="jobs.create",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _job_row(
        connection: sqlite3.Connection, tenant: str, job_id: str
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT job_id, kind, operation, state, actor_sha256, request_sha256, "
            "scheduled_for, total_items, processed_items, failed_items, "
            "credits_reserved, credits_consumed, credits_refunded, cancel_requested, "
            "revision, artifact_sha256, result_sha256, created_at, started_at, "
            "completed_at, retention_until FROM consent_bulk_jobs "
            "WHERE tenant = ? AND job_id = ?",
            (tenant, job_id),
        ).fetchone()
        if row is None:
            raise ConsentBulkJobNotFound("bulk job does not exist in this tenant")
        result = dict(row)
        result["cancel_requested"] = bool(result["cancel_requested"])
        result["progress_percent"] = round(
            100.0 * int(result["processed_items"]) / int(result["total_items"]), 2
        )
        result["schema"] = JOB_SCHEMA
        return result

    def get_job(self, tenant_id: str, job_id: str) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job = _text(job_id, "job_id")
        with self._connect() as connection:
            return self._job_row(connection, tenant, job)

    def job_executor_scope(self, tenant_id: str, job_id: str) -> str:
        """Preserve earlier jobs' effect keys while isolating new jobs' keys."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM consent_bulk_events WHERE tenant = ? AND job_id = ? "
                "AND event_type = 'job.created' ORDER BY sequence LIMIT 1",
                (_tenant(tenant_id), _text(job_id, "job_id")),
            ).fetchone()
            if row is None:
                raise ConsentBulkJobNotFound("bulk job admission is unavailable")
            event = _loads(row["payload_json"], "job admission")
            scope = event.get("executor_scope", "legacy") if isinstance(event, dict) else None
            if scope not in {"legacy", "job"}:
                raise ConsentBulkJobError("bulk job execution scope is invalid")
            return scope

    def receipt_execution_item(
        self, tenant_id: str, job_id: str, item: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Advance a reviewed profile version only through verified job results.

        Two receipts selected for one person share the version reviewed in the
        UI. Each native change advances it. A failed predecessor or an unrelated
        edit must never authorize later changes by blindly incrementing it.
        """
        tenant, job = _tenant(tenant_id), _text(job_id, "job_id")
        selected = dict(item)
        with self._connect() as connection:
            admission = connection.execute(
                "SELECT payload_json FROM consent_bulk_events WHERE tenant = ? AND job_id = ? "
                "AND event_type = 'job.created' ORDER BY sequence LIMIT 1", (tenant, job),
            ).fetchone()
            if admission is None:
                raise ConsentBulkJobNotFound("bulk job admission is unavailable")
            if _loads(admission["payload_json"], "job admission").get("receipt_revision_chain") is not True:
                return selected  # Keep pre-existing jobs' native replay inputs.
            current = connection.execute(
                "SELECT ordinal, input_sha256 FROM consent_bulk_items "
                "WHERE tenant = ? AND job_id = ? AND item_id = ?",
                (tenant, job, _text(selected.get("item_id"), "item_id")),
            ).fetchone()
            if current is None or not text_equals(
                _sha256(selected, maximum=_MAX_ITEM_BYTES), str(current["input_sha256"]),
            ):
                raise ConsentBulkJobError("stored bulk-job item integrity failed")
            rows = connection.execute(
                "SELECT input_json, input_sha256, state, result_json, result_sha256 "
                "FROM consent_bulk_items WHERE tenant = ? AND job_id = ? AND ordinal < ? "
                "ORDER BY ordinal", (tenant, job, current["ordinal"]),
            ).fetchall()
        revision = selected["expected_revision"]
        for row in rows:
            previous = _loads(row["input_json"], "bulk-job item", maximum=_MAX_ITEM_BYTES)
            if not isinstance(previous, dict) or not text_equals(
                _sha256(previous, maximum=_MAX_ITEM_BYTES), str(row["input_sha256"]),
            ):
                raise ConsentBulkJobError("stored predecessor integrity failed")
            if (previous.get("profile_id") != selected["profile_id"] or
                    previous.get("expected_revision") != selected["expected_revision"]):
                continue
            if row["state"] != "succeeded":
                raise ConsentBulkJobConflict("an earlier selected record was not confirmed")
            result = _loads(row["result_json"], "bulk-job result", maximum=_MAX_RESULT_BYTES)
            if (not isinstance(result, dict) or not text_equals(
                    _sha256(result, maximum=_MAX_RESULT_BYTES), str(row["result_sha256"])) or
                    result.get("profile_id") != selected["profile_id"] or
                    result.get("receipt_id") != previous.get("receipt_id") or
                    type(result.get("profile_revision")) is not int or
                    result["profile_revision"] != revision + 1):
                raise ConsentBulkJobError("predecessor result could not be confirmed")
            revision = result["profile_revision"]
        selected["expected_revision"] = revision
        return selected

    def created_job_for_request(
        self, tenant_id: str, *, idempotency_key: str, actor_sha256: str,
    ) -> dict[str, Any] | None:
        """Read an actor's original submission without creating or running work."""
        tenant = _tenant(tenant_id)
        key = self._idempotency(idempotency_key)
        actor = _digest(actor_sha256, "actor_sha256")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM consent_bulk_idempotency "
                "WHERE tenant = ? AND namespace = 'jobs.create' AND key_sha256 = ?",
                (tenant, key),
            ).fetchone()
            if row is None:
                return None
            original = _loads(row["result_json"], "idempotency result")
            if not isinstance(original, dict):
                raise ConsentBulkJobError("stored idempotency result is invalid")
            if not text_equals(str(original.get("actor_sha256", "")), actor):
                return None
            try:
                return self._job_row(connection, tenant, _text(original.get("job_id"), "job_id"))
            except ConsentBulkJobNotFound:
                # The immutable admission remains after a retained job is purged.
                return {**original, "retained": False}

    def list_jobs(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        limit: int = 100,
        before_job_id: str | None = None,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        page_size = _integer(limit, "limit", 1, _MAX_READ_LIMIT)
        if state is not None and state not in _STATES:
            raise ConsentBulkJobValidationError("state is invalid")
        with self._connect() as connection:
            predicates, arguments = ["tenant = ?"], [tenant]
            if state is not None:
                predicates.append("state = ?")
                arguments.append(state)
            if before_job_id is not None:
                anchor = self._job_row(connection, tenant, _text(before_job_id, "before_job_id"))
                predicates.append("(created_at < ? OR (created_at = ? AND job_id < ?))")
                arguments.extend((anchor["created_at"], anchor["created_at"], anchor["job_id"]))
            rows = connection.execute(
                "SELECT job_id FROM consent_bulk_jobs WHERE " + " AND ".join(predicates)
                + " ORDER BY created_at DESC, job_id DESC LIMIT ?",
                (*arguments, page_size + 1),
            ).fetchall()
            jobs = [
                self._job_row(connection, tenant, str(row["job_id"]))
                for row in rows[:page_size]
            ]
        more = len(rows) > page_size
        return {"jobs": jobs, "truncated": more,
                "next_before_job_id": jobs[-1]["job_id"] if more and jobs else None}

    def cancel_job(
        self,
        tenant_id: str,
        job_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job = _text(job_id, "job_id")
        revision = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        key_sha = self._idempotency(idempotency_key)
        request = {"job_id": job, "expected_revision": revision}
        request_sha = _sha256(request)
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._replay(
                    connection,
                    tenant=tenant,
                    namespace=f"jobs.cancel:{job}",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                row = connection.execute(
                    "SELECT state, revision, total_items, processed_items, "
                    "credits_reserved, credits_consumed, credits_refunded "
                    "FROM consent_bulk_jobs WHERE tenant = ? AND job_id = ?",
                    (tenant, job),
                ).fetchone()
                if row is None:
                    raise ConsentBulkJobNotFound("bulk job does not exist in this tenant")
                if int(row["revision"]) != revision:
                    raise ConsentBulkJobConflict("bulk-job revision changed")
                if row["state"] in _TERMINAL_STATES:
                    raise ConsentBulkJobConflict("terminal bulk job cannot be cancelled")
                unprocessed = int(row["total_items"]) - int(row["processed_items"])
                if row["state"] == "queued":
                    state = "cancelled"
                    completed_at: float | None = now
                    refund = unprocessed
                    connection.execute(
                        "UPDATE consent_bulk_credits SET available = available + ?, "
                        "reserved = reserved - ?, revision = revision + 1, updated_at = ? "
                        "WHERE tenant = ?",
                        (refund, refund, now, tenant),
                    )
                else:
                    state = "running"
                    completed_at = None
                    refund = 0
                updated = connection.execute(
                    "UPDATE consent_bulk_jobs SET state = ?, cancel_requested = 1, "
                    "credits_refunded = credits_refunded + ?, completed_at = ?, "
                    "revision = revision + 1 WHERE tenant = ? AND job_id = ? "
                    "AND revision = ?",
                    (state, refund, completed_at, tenant, job, revision),
                )
                if updated.rowcount != 1:
                    raise ConsentBulkJobConflict("bulk-job revision changed")
                result = self._job_row(connection, tenant, job)
                self._event(
                    connection,
                    tenant=tenant,
                    job_id=job,
                    event_type="job.cancel_requested",
                    payload={"state": state, "credits_refunded": refund},
                    now=now,
                )
                self._save_replay(
                    connection,
                    tenant=tenant,
                    namespace=f"jobs.cancel:{job}",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                    result=result,
                    now=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _claim(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        job_id: str,
        worker_sha256: str,
        now: float,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT state, scheduled_for, cancel_requested, lease_owner_sha256, "
            "lease_expires_at, started_at FROM consent_bulk_jobs "
            "WHERE tenant = ? AND job_id = ?",
            (tenant, job_id),
        ).fetchone()
        if row is None:
            raise ConsentBulkJobNotFound("bulk job does not exist in this tenant")
        if row["state"] in _TERMINAL_STATES:
            return self._job_row(connection, tenant, job_id)
        if float(row["scheduled_for"]) > now:
            raise ConsentBulkJobConflict("bulk job is not scheduled to run yet")
        lease_expires = (
            float(row["lease_expires_at"])
            if row["lease_expires_at"] is not None
            else None
        )
        owner = str(row["lease_owner_sha256"]) if row["lease_owner_sha256"] else None
        if owner is not None and lease_expires is not None and lease_expires > now:
            if not text_equals(owner, worker_sha256):
                raise ConsentBulkJobConflict("bulk job is leased by another worker")
        started = float(row["started_at"]) if row["started_at"] is not None else now
        connection.execute(
            "UPDATE consent_bulk_jobs SET state = 'running', lease_owner_sha256 = ?, "
            "lease_expires_at = ?, started_at = ?, revision = revision + 1 "
            "WHERE tenant = ? AND job_id = ?",
            (worker_sha256, now + self.limits.lease_seconds, started, tenant, job_id),
        )
        self._event(
            connection,
            tenant=tenant,
            job_id=job_id,
            event_type="job.leased",
            payload={"lease_expires_at": now + self.limits.lease_seconds},
            now=now,
        )
        return self._job_row(connection, tenant, job_id)

    @staticmethod
    def _closed_error(exc: BaseException) -> str:
        name = type(exc).__name__.lower()
        if "notfound" in name or "not_found" in name:
            return "not_found"
        if "conflict" in name or "stale" in name:
            return "conflict"
        if "validation" in name or isinstance(exc, (TypeError, ValueError)):
            return "invalid_item"
        if isinstance(exc, ConsentBulkJobError):
            return "authority_unavailable"
        return "worker_failure"

    def run_job(  # noqa: C901 - transaction and worker trust boundaries
        self,
        tenant_id: str,
        job_id: str,
        *,
        worker_sha256: str,
        executor: Callable[[str, Mapping[str, Any]], Mapping[str, Any]],
        batch_size: int = 100,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        """Claim a due job and execute one bounded batch.

        The caller may invoke this repeatedly.  A stale lease is recoverable,
        successful items are never repeated, and cancellation is observed
        between items.  Executor exceptions are reduced to a closed error code;
        their message is never persisted.
        """

        tenant = _tenant(tenant_id)
        job = _text(job_id, "job_id")
        worker = _digest(worker_sha256, "worker_sha256")
        batch = _integer(batch_size, "batch_size", 1, 500)
        revision = (_integer(expected_revision, "expected_revision", 1, 2**31 - 1)
                    if expected_revision is not None else None)
        if not callable(executor):
            raise TypeError("bulk-job executor must be callable")
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if revision is not None and self._job_row(connection, tenant, job)["revision"] != revision:
                    raise ConsentBulkJobConflict("bulk-job revision changed before this part started")
                claimed = self._claim(
                    connection,
                    tenant=tenant,
                    job_id=job,
                    worker_sha256=worker,
                    now=now,
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        if claimed["state"] in _TERMINAL_STATES:
            return claimed

        completed = 0
        while completed < batch:
            current = self._now()
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    job_row = connection.execute(
                        "SELECT operation, state, cancel_requested, lease_owner_sha256, "
                        "lease_expires_at FROM consent_bulk_jobs "
                        "WHERE tenant = ? AND job_id = ?",
                        (tenant, job),
                    ).fetchone()
                    if job_row is None:
                        raise ConsentBulkJobNotFound(
                            "bulk job does not exist in this tenant"
                        )
                    owner = str(job_row["lease_owner_sha256"] or "")
                    expires = float(job_row["lease_expires_at"] or 0)
                    if not text_equals(owner, worker) or expires <= current:
                        raise ConsentBulkJobLeaseLost("bulk-job lease was lost")
                    if bool(job_row["cancel_requested"]):
                        self._finish_cancelled(connection, tenant, job, current)
                        connection.execute("COMMIT")
                        return self.get_job(tenant, job)
                    item_row = connection.execute(
                        "SELECT ordinal, input_json, input_sha256 FROM consent_bulk_items "
                        "WHERE tenant = ? AND job_id = ? AND state = 'pending' "
                        "ORDER BY ordinal LIMIT 1",
                        (tenant, job),
                    ).fetchone()
                    if item_row is None:
                        self._finish(connection, tenant, job, current)
                        connection.execute("COMMIT")
                        return self.get_job(tenant, job)
                    operation = str(job_row["operation"])
                    item = _loads(
                        item_row["input_json"], "bulk-job item", maximum=_MAX_ITEM_BYTES
                    )
                    if not isinstance(item, dict) or not text_equals(
                        _sha256(item, maximum=_MAX_ITEM_BYTES),
                        str(item_row["input_sha256"]),
                    ):
                        raise ConsentBulkJobError("stored bulk-job item integrity failed")
                    ordinal = int(item_row["ordinal"])
                    connection.execute("COMMIT")
                except BaseException:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise

            result: Mapping[str, Any] | None = None
            error_code: str | None = None
            try:
                candidate = executor(operation, item)
                if not isinstance(candidate, Mapping):
                    raise ConsentBulkJobValidationError(
                        "bulk-job executor returned an invalid result"
                    )
                result = {str(key): value for key, value in candidate.items()}
                _canonical(result, maximum=_MAX_RESULT_BYTES)
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as exc:  # executor is a deployment-owned boundary
                error_code = self._closed_error(exc)

            current = self._now()
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    lease = connection.execute(
                        "SELECT lease_owner_sha256, lease_expires_at FROM consent_bulk_jobs "
                        "WHERE tenant = ? AND job_id = ? AND state = 'running'",
                        (tenant, job),
                    ).fetchone()
                    if lease is None or not text_equals(
                        str(lease["lease_owner_sha256"] or ""), worker
                    ):
                        raise ConsentBulkJobLeaseLost("bulk-job lease was lost")
                    state = "succeeded" if error_code is None else "failed"
                    result_json = (
                        _canonical(result, maximum=_MAX_RESULT_BYTES).decode("ascii")
                        if result is not None
                        else None
                    )
                    result_sha = (
                        _sha256(result, maximum=_MAX_RESULT_BYTES)
                        if result is not None
                        else None
                    )
                    updated = connection.execute(
                        "UPDATE consent_bulk_items SET state = ?, attempts = attempts + 1, "
                        "result_json = ?, result_sha256 = ?, error_code = ?, updated_at = ? "
                        "WHERE tenant = ? AND job_id = ? AND ordinal = ? AND state = 'pending'",
                        (
                            state,
                            result_json,
                            result_sha,
                            error_code,
                            current,
                            tenant,
                            job,
                            ordinal,
                        ),
                    )
                    if updated.rowcount != 1:
                        raise ConsentBulkJobConflict("bulk-job item changed concurrently")
                    connection.execute(
                        "UPDATE consent_bulk_jobs SET processed_items = processed_items + 1, "
                        "failed_items = failed_items + ?, credits_consumed = "
                        "credits_consumed + 1, lease_expires_at = ?, revision = revision + 1 "
                        "WHERE tenant = ? AND job_id = ?",
                        (
                            int(error_code is not None),
                            current + self.limits.lease_seconds,
                            tenant,
                            job,
                        ),
                    )
                    connection.execute(
                        "UPDATE consent_bulk_credits SET reserved = reserved - 1, "
                        "consumed = consumed + 1, revision = revision + 1, updated_at = ? "
                        "WHERE tenant = ? AND reserved >= 1",
                        (current, tenant),
                    )
                    self._event(
                        connection,
                        tenant=tenant,
                        job_id=job,
                        event_type=f"item.{state}",
                        payload={
                            "ordinal": ordinal,
                            "item_id": item["item_id"],
                            "result_sha256": result_sha,
                            "error_code": error_code,
                        },
                        now=current,
                    )
                    connection.execute("COMMIT")
                except BaseException:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise
            completed += 1

        # A batch that consumes exactly the final pending item must still move
        # the job to a terminal state.  Requiring a second worker invocation
        # would otherwise leave a 100%-complete job leased and "running".
        current = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                remaining = connection.execute(
                    "SELECT 1 FROM consent_bulk_items WHERE tenant = ? AND job_id = ? "
                    "AND state = 'pending' LIMIT 1",
                    (tenant, job),
                ).fetchone()
                if remaining is None:
                    self._finish(connection, tenant, job, current)
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return self.get_job(tenant, job)

    def _finish_cancelled(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        job_id: str,
        now: float,
    ) -> None:
        row = connection.execute(
            "SELECT total_items, processed_items FROM consent_bulk_jobs "
            "WHERE tenant = ? AND job_id = ? AND state = 'running'",
            (tenant, job_id),
        ).fetchone()
        if row is None:
            raise ConsentBulkJobConflict("bulk job is not running")
        refund = int(row["total_items"]) - int(row["processed_items"])
        connection.execute(
            "UPDATE consent_bulk_credits SET available = available + ?, "
            "reserved = reserved - ?, revision = revision + 1, updated_at = ? "
            "WHERE tenant = ? AND reserved >= ?",
            (refund, refund, now, tenant, refund),
        )
        connection.execute(
            "UPDATE consent_bulk_jobs SET state = 'cancelled', credits_refunded = "
            "credits_refunded + ?, lease_owner_sha256 = NULL, lease_expires_at = NULL, "
            "completed_at = ?, revision = revision + 1 WHERE tenant = ? AND job_id = ?",
            (refund, now, tenant, job_id),
        )
        self._event(
            connection,
            tenant=tenant,
            job_id=job_id,
            event_type="job.cancelled",
            payload={"credits_refunded": refund},
            now=now,
        )

    def _finish(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        job_id: str,
        now: float,
    ) -> None:
        row = connection.execute(
            "SELECT kind, total_items, processed_items, failed_items "
            "FROM consent_bulk_jobs WHERE tenant = ? AND job_id = ? AND state = 'running'",
            (tenant, job_id),
        ).fetchone()
        if row is None or int(row["processed_items"]) != int(row["total_items"]):
            raise ConsentBulkJobConflict("bulk job is not ready to finish")
        state = "failed" if int(row["failed_items"]) else "succeeded"
        artifact_json: str | None = None
        artifact_sha: str | None = None
        terminal_error_code: str | None = None
        if row["kind"] == "export" and state == "succeeded":
            items = connection.execute(
                "SELECT item_id, result_json, result_sha256 FROM consent_bulk_items "
                "WHERE tenant = ? AND job_id = ? ORDER BY ordinal",
                (tenant, job_id),
            ).fetchall()
            results: list[dict[str, Any]] = []
            for item in items:
                result = _loads(
                    item["result_json"], "bulk export result", maximum=_MAX_RESULT_BYTES
                )
                if not isinstance(result, dict) or not text_equals(
                    _sha256(result, maximum=_MAX_RESULT_BYTES),
                    str(item["result_sha256"]),
                ):
                    raise ConsentBulkJobError("stored bulk export result integrity failed")
                results.append({"item_id": str(item["item_id"]), "result": result})
            artifact = {
                "schema": ARTIFACT_SCHEMA,
                "job_id": job_id,
                "item_count": len(results),
                "items": results,
                "generated_at": now,
            }
            try:
                encoded = _canonical(artifact, maximum=self.limits.max_artifact_bytes)
            except ConsentBulkJobValidationError:
                # Every item may be valid while their combined download still
                # exceeds the tenant artifact limit.  This is a terminal,
                # operator-visible capacity outcome, not a retryable lease
                # failure that should strand the job in ``running`` forever.
                state = "failed"
                terminal_error_code = "artifact_too_large"
            else:
                artifact_json = encoded.decode("ascii")
                artifact_sha = hashlib.sha256(encoded).hexdigest()
        result_body = {
            "job_id": job_id,
            "state": state,
            "processed_items": int(row["processed_items"]),
            "failed_items": int(row["failed_items"]),
            "artifact_sha256": artifact_sha,
            "completed_at": now,
        }
        if terminal_error_code is not None:
            result_body["error_code"] = terminal_error_code
        result_sha = _sha256(result_body)
        connection.execute(
            "UPDATE consent_bulk_jobs SET state = ?, artifact_json = ?, "
            "artifact_sha256 = ?, result_sha256 = ?, lease_owner_sha256 = NULL, "
            "lease_expires_at = NULL, completed_at = ?, revision = revision + 1 "
            "WHERE tenant = ? AND job_id = ?",
            (state, artifact_json, artifact_sha, result_sha, now, tenant, job_id),
        )
        self._event(
            connection,
            tenant=tenant,
            job_id=job_id,
            event_type=f"job.{state}",
            payload={**result_body, "result_sha256": result_sha},
            now=now,
        )

    def download_artifact(self, tenant_id: str, job_id: str) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job = _text(job_id, "job_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state, artifact_json, artifact_sha256 FROM consent_bulk_jobs "
                "WHERE tenant = ? AND job_id = ?",
                (tenant, job),
            ).fetchone()
        if row is None:
            raise ConsentBulkJobNotFound("bulk job does not exist in this tenant")
        if row["state"] != "succeeded" or row["artifact_json"] is None:
            raise ConsentBulkJobConflict("bulk export artifact is not ready")
        artifact = _loads(
            row["artifact_json"],
            "bulk export artifact",
            maximum=self.limits.max_artifact_bytes,
        )
        encoded = _canonical(artifact, maximum=self.limits.max_artifact_bytes)
        if not text_equals(
            hashlib.sha256(encoded).hexdigest(), str(row["artifact_sha256"])
        ):
            raise ConsentBulkJobError("bulk export artifact integrity failed")
        if not isinstance(artifact, dict):
            raise ConsentBulkJobError("stored bulk export artifact is invalid")
        return {**artifact, "artifact_sha256": str(row["artifact_sha256"])}

    def recover_expired_leases(self, tenant_id: str, *, limit: int = 100) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        page_size = _integer(limit, "limit", 1, _MAX_READ_LIMIT)
        now = self._now()
        recovered: list[str] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    "SELECT job_id FROM consent_bulk_jobs WHERE tenant = ? "
                    "AND state = 'running' AND lease_expires_at <= ? "
                    "ORDER BY lease_expires_at LIMIT ?",
                    (tenant, now, page_size),
                ).fetchall()
                for row in rows:
                    job = str(row["job_id"])
                    connection.execute(
                        "UPDATE consent_bulk_jobs SET state = 'queued', "
                        "lease_owner_sha256 = NULL, lease_expires_at = NULL, "
                        "revision = revision + 1 WHERE tenant = ? AND job_id = ?",
                        (tenant, job),
                    )
                    self._event(
                        connection,
                        tenant=tenant,
                        job_id=job,
                        event_type="job.recovered",
                        payload={"recovered_at": now},
                        now=now,
                    )
                    recovered.append(job)
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return {"recovered_job_ids": recovered, "recovered_count": len(recovered)}

    def history(
        self, tenant_id: str, job_id: str, *, limit: int = 100,
        before_sequence: int | None = None,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        job = _text(job_id, "job_id")
        page_size = _integer(limit, "limit", 1, _MAX_READ_LIMIT)
        before = 2**63 - 1 if before_sequence is None else _integer(before_sequence, "before_sequence", 1, 2**63 - 1)
        with self._connect() as connection:
            self._job_row(connection, tenant, job)
            rows = connection.execute(
                "SELECT sequence, event_id, event_type, payload_json, payload_sha256, "
                "previous_event_sha256, event_sha256, created_at "
                "FROM consent_bulk_events WHERE tenant = ? AND job_id = ? AND sequence < ? "
                "ORDER BY sequence DESC LIMIT ?",
                (tenant, job, before, page_size + 1),
            ).fetchall()
        events: list[dict[str, Any]] = []
        for row in rows[:page_size]:
            payload = _loads(row["payload_json"], "bulk-job event payload")
            if not isinstance(payload, dict) or not text_equals(
                _sha256(payload), str(row["payload_sha256"])
            ):
                raise ConsentBulkJobError("stored bulk-job event integrity failed")
            events.append(
                {
                    "sequence": int(row["sequence"]),
                    "event_id": str(row["event_id"]),
                    "event_type": str(row["event_type"]),
                    "payload": payload,
                    "payload_sha256": str(row["payload_sha256"]),
                    "previous_event_sha256": row["previous_event_sha256"],
                    "event_sha256": str(row["event_sha256"]),
                    "created_at": float(row["created_at"]),
                }
            )
        return {"job_id": job, "events": events, "truncated": len(rows) > page_size,
                "next_before_sequence": events[-1]["sequence"] if len(rows) > page_size else None}

    def verify_integrity(self, tenant_id: str) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        previous: str | None = None
        checked = 0
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_id, job_id, event_type, payload_json, payload_sha256, "
                "previous_event_sha256, event_sha256, created_at "
                "FROM consent_bulk_events WHERE tenant = ? ORDER BY sequence",
                (tenant,),
            ).fetchall()
        for row in rows:
            payload = _loads(row["payload_json"], "bulk-job event payload")
            if not isinstance(payload, dict):
                raise ConsentBulkJobError("stored bulk-job event integrity failed")
            body = {
                "schema": EVENT_SCHEMA,
                "event_id": str(row["event_id"]),
                "job_id": str(row["job_id"]),
                "event_type": str(row["event_type"]),
                "payload": payload,
                "previous_event_sha256": previous,
                "created_at": float(row["created_at"]),
            }
            valid = (
                text_equals(_sha256(payload), str(row["payload_sha256"]))
                and row["previous_event_sha256"] == previous
                and text_equals(_sha256(body), str(row["event_sha256"]))
            )
            if not valid:
                raise ConsentBulkJobError("stored bulk-job event integrity failed")
            previous = str(row["event_sha256"])
            checked += 1
        return {
            "integrity_valid": True,
            "events_checked": checked,
            "head_sha256": previous,
        }

    def purge_retention(
        self, tenant_id: str, *, before: float | None = None, limit: int = 100
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        cutoff = _timestamp(before, "before", allow_none=True) or self._now()
        page_size = _integer(limit, "limit", 1, _MAX_READ_LIMIT)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    "SELECT job_id FROM consent_bulk_jobs WHERE tenant = ? "
                    "AND state IN ('succeeded', 'failed', 'cancelled') "
                    "AND retention_until <= ? ORDER BY retention_until LIMIT ?",
                    (tenant, cutoff, page_size),
                ).fetchall()
                job_ids = [str(row["job_id"]) for row in rows]
                for job in job_ids:
                    connection.execute(
                        "DELETE FROM consent_bulk_items WHERE tenant = ? AND job_id = ?",
                        (tenant, job),
                    )
                    connection.execute(
                        "DELETE FROM consent_bulk_jobs WHERE tenant = ? AND job_id = ?",
                        (tenant, job),
                    )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return {"jobs_purged": len(job_ids), "events_retained": True}


__all__ = [
    "ARTIFACT_SCHEMA",
    "ConsentBulkJobConflict",
    "ConsentBulkJobError",
    "ConsentBulkJobLeaseLost",
    "ConsentBulkJobLimits",
    "ConsentBulkJobNotFound",
    "ConsentBulkJobStore",
    "ConsentBulkJobValidationError",
    "EVENT_SCHEMA",
    "JOB_SCHEMA",
]
