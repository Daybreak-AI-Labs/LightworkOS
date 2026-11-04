"""Durable scheduling and reviewed inventory for consent tracker scans.

This authority coordinates an injected :class:`ConsentScanner`; it never
performs network access itself.  Scanner findings remain ``unknown`` until a
versioned human review is recorded.  Only fresh, reviewed decisions may cross
the injected consent-tracker bridge.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse, urlunparse

from . import consent_storage
from .consent_scanner import (
    SCAN_REPORT_SCHEMA,
    ConsentScannerConfigError,
    ScanFinding,
    ScanLimits,
    ScanReport,
    capped_scan_limits,
    default_scan_limits,
    require_enabled,
    scan_limit_settings,
)
from .constant_time import text_equals
from .file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

SCAN_INVENTORY_SCHEMA = "lightwork.consent-scan-inventory.v1"
_SCHEMA_VERSION = 1
_MAX_JSON_BYTES = 2 * 1_024 * 1_024
_MAX_LIST_LIMIT = 500
_MAX_PROPERTIES = 10_000
_MAX_SCHEDULES = 10_000
_MAX_ORIGINS = 128
_MAX_START_URLS = 128
_MAX_PURPOSES = 128
_MAX_REPLAYS = 10
_MAX_STALE_RECOVERY = 500
_MIN_INTERVAL_SECONDS = 300
_MAX_INTERVAL_SECONDS = 2_592_000
_MAX_REVIEW_LIFETIME = 366 * 86_400

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{23,255}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)
_JOB_STATES = frozenset({"queued", "leased", "succeeded", "dead_letter"})
_REVIEW_CLASSES = frozenset(
    {"essential", "functional", "analytics", "advertising", "other", "not_a_tracker"}
)
_REVIEW_ACTIONS = frozenset({"observe_only", "approved", "blocked", "retired"})
_FINDING_KINDS = frozenset({"network", "cookie", "storage"})
_RESOURCE_TYPES = frozenset(
    {"script", "image", "xhr", "fetch", "media", "font", "websocket", "other"}
)


class ConsentScanInventoryError(RuntimeError):
    """Base failure for the scan inventory authority."""


class ConsentScanValidationError(ConsentScanInventoryError, ValueError):
    """Caller input is invalid or exceeds a closed bound."""


class ConsentScanConflict(ConsentScanInventoryError):
    """A CAS, idempotency, or authority precondition changed."""


class ConsentScanNotFound(ConsentScanInventoryError):
    """The requested tenant-scoped object is unavailable."""


class ConsentScanLeaseError(ConsentScanInventoryError):
    """A worker does not own a current job lease."""


class ConsentScanIntegrityError(ConsentScanInventoryError):
    """Stored or injected evidence failed exact integrity validation."""


class ConsentScanBridgeError(ConsentScanInventoryError):
    """The reviewed-observation bridge did not complete."""


class ScannerAuthority(Protocol):
    def scan(
        self,
        tenant_id: str,
        property_id: str,
        start_urls: Sequence[str],
        _allowed_origins: Sequence[str],
        *,
        limits: ScanLimits | None = None,
        auth_secret_ref: str | None = None,
        authenticated_scan_consent: bool = False,
    ) -> ScanReport: ...


class TrackerAuthority(Protocol):
    def register_tracker(
        self,
        tenant_id: str,
        tracker_id: str,
        kind: str,
        vendor_id: str,
        purpose_ids: Sequence[str],
        status: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> Mapping[str, Any]: ...

    def admit_scan_observations(
        self,
        tenant_id: str,
        _scan_id: str,
        observations: Sequence[Any],
        _observed_at: float,
        _source_sha256: str,
        idempotency_key: str,
    ) -> Mapping[str, Any]: ...


def _authenticated_scans_enabled() -> bool:
    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        loaded = load_config()
    except Exception:
        return False
    if not isinstance(loaded, Mapping):
        return False
    consent = loaded.get("consent_preferences")
    if not isinstance(consent, Mapping) or consent.get("enable") is not True:
        return False
    scanner = consent.get("scanner")
    return (
        isinstance(scanner, Mapping)
        and scanner.get("enable") is True
        and scanner.get("allow_authenticated_scans") is True
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
        raise ConsentScanValidationError("scan inventory data must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise ConsentScanValidationError("scan inventory data exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _loads(value: object, label: str) -> Any:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= _MAX_JSON_BYTES:
        raise ConsentScanIntegrityError(f"stored {label} is invalid")
    try:
        return json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ConsentScanIntegrityError(f"stored {label} is invalid") from exc


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise ConsentScanValidationError(f"{label} must be an opaque identifier")
    return value


def _tenant_id(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except ValueError as exc:
        raise ConsentScanValidationError("tenant_id is invalid") from exc


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ConsentScanValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _idempotency(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or not _IDEMPOTENCY_RE.fullmatch(value):
        raise ConsentScanValidationError("idempotency_key is invalid")
    return value, _text_digest(value)


def _revision(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31 - 1:
        raise ConsentScanValidationError(f"{label} must be a non-negative integer")
    return value


def _positive_int(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ConsentScanValidationError(f"{label} must be an integer between {lower} and {upper}")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConsentScanValidationError(f"{label} must be a finite timestamp")
    normalized = float(value)
    if not math.isfinite(normalized) or not 0 < normalized < 100_000_000_000.0:
        raise ConsentScanValidationError(f"{label} must be a finite timestamp")
    return normalized


def _limit(value: object) -> int:
    return _positive_int(value, "limit", 1, _MAX_LIST_LIMIT)


def _error_code(error: Exception) -> str:
    candidate = type(error).__name__
    return candidate if _REF_RE.fullmatch(candidate) else "scanner_error"


def _origin(value: object) -> str:
    if not isinstance(value, str) or value != value.strip() or "*" in value or len(value) > 2048:
        raise ConsentScanValidationError("origin must be one exact HTTPS origin")
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise ConsentScanValidationError("origin must be one exact HTTPS origin") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
        or port not in {None, 443}
    ):
        raise ConsentScanValidationError("origin must be one exact HTTPS origin")
    host = parsed.hostname.lower().rstrip(".")
    if not _HOST_RE.fullmatch(host):
        raise ConsentScanValidationError("origin must use a valid exact hostname")
    return f"https://{host}" if port is None else f"https://{host}:443"


def _navigation_url(value: object, origins: frozenset[str]) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        raise ConsentScanValidationError("start URL is invalid")
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise ConsentScanValidationError("start URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in {None, 443}
    ):
        raise ConsentScanValidationError("start URL must be HTTPS without credentials")
    host = parsed.hostname.lower().rstrip(".")
    origin = f"https://{host}" if port is None else f"https://{host}:443"
    if origin not in origins:
        raise ConsentScanValidationError("start URL is outside enrolled origins")
    return urlunparse(("https", parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))


def _sequence(
    values: object,
    label: str,
    *,
    maximum: int,
    normalizer: Callable[[object], str],
) -> list[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ConsentScanValidationError(f"{label} must be a bounded sequence")
    if not 1 <= len(values) <= maximum:
        raise ConsentScanValidationError(f"{label} must be a bounded sequence")
    normalized = [normalizer(value) for value in values]
    if len(set(normalized)) != len(normalized):
        raise ConsentScanValidationError(f"{label} cannot contain duplicates")
    return sorted(normalized)


class ConsentScanInventory:
    """Tenant-keyed SQLite authority for scheduled consent scans."""

    def __init__(
        self,
        path: Path,
        scanner: ScannerAuthority,
        *,
        tracker_authority: TrackerAuthority | None = None,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
        token_factory: Callable[[], str] | None = None,
        gate: Callable[[], None] = require_enabled,
        authenticated_scan_gate: Callable[[], bool] = _authenticated_scans_enabled,
    ) -> None:
        if not callable(getattr(scanner, "scan", None)):
            raise TypeError("scanner must expose scan()")
        self.path = Path(path).expanduser()
        self._scanner = scanner
        self._tracker_authority = tracker_authority
        self._clock = clock
        self._id_factory = id_factory or (lambda prefix: f"{prefix}-{secrets.token_urlsafe(18)}")
        self._token_factory = token_factory or (lambda: f"lease-{secrets.token_urlsafe(24)}")
        self._gate = gate
        self._authenticated_scan_gate = authenticated_scan_gate
        ensure_private_directory(self.path.parent)
        with cross_process_lock(self.path, strict=True):
            self._initialize()

    def _require(self) -> None:
        self._gate()

    def _now(self) -> float:
        return _timestamp(self._clock(), "clock")

    def _new_id(self, prefix: str) -> str:
        return _ref(self._id_factory(prefix), f"{prefix} identifier")

    @contextlib.contextmanager
    def _connect(self):
        with consent_storage.authority_connection(
            self.path, ensure_directory=ensure_private_directory,
            ensure_file=ensure_private_file,
        ) as connection:
            yield connection

    def _initialize(self) -> None:
        statements = (
            """
            CREATE TABLE IF NOT EXISTS consent_scan_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_scan_properties (
                tenant TEXT NOT NULL,
                property_id TEXT NOT NULL,
                origins_json TEXT NOT NULL,
                start_urls_json TEXT NOT NULL,
                revision INTEGER NOT NULL,
                record_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (tenant, property_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_scan_schedules (
                tenant TEXT NOT NULL,
                schedule_id TEXT NOT NULL,
                property_id TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                limits_json TEXT NOT NULL,
                auth_secret_ref TEXT,
                authenticated_scan_consent INTEGER NOT NULL,
                max_attempts INTEGER NOT NULL,
                retry_base_seconds INTEGER NOT NULL,
                retry_max_seconds INTEGER NOT NULL,
                lease_seconds INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                next_due_at REAL NOT NULL,
                revision INTEGER NOT NULL,
                configuration_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (tenant, schedule_id)
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS consent_scan_schedules_due
                ON consent_scan_schedules(tenant, enabled, next_due_at)
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_scan_jobs (
                tenant TEXT NOT NULL,
                job_id TEXT NOT NULL,
                schedule_id TEXT NOT NULL,
                property_id TEXT NOT NULL,
                scheduled_for REAL NOT NULL,
                missed_intervals INTEGER NOT NULL,
                property_revision INTEGER NOT NULL,
                property_sha256 TEXT NOT NULL,
                schedule_revision INTEGER NOT NULL,
                schedule_sha256 TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN ('queued', 'leased', 'succeeded', 'dead_letter')
                ),
                attempts INTEGER NOT NULL,
                max_attempts INTEGER NOT NULL,
                retry_base_seconds INTEGER NOT NULL,
                retry_max_seconds INTEGER NOT NULL,
                lease_seconds INTEGER NOT NULL,
                available_at REAL NOT NULL,
                lease_owner TEXT,
                lease_token_sha256 TEXT,
                lease_expires_at REAL,
                last_error_code TEXT,
                report_id TEXT,
                replay_count INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                record_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (tenant, job_id),
                UNIQUE (tenant, schedule_id, scheduled_for)
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS consent_scan_jobs_due
                ON consent_scan_jobs(tenant, status, available_at, scheduled_for)
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_scan_reports (
                tenant TEXT NOT NULL,
                report_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                schedule_id TEXT NOT NULL,
                property_id TEXT NOT NULL,
                scanner_run_id TEXT NOT NULL,
                scanner_report_json TEXT NOT NULL,
                scanner_report_sha256 TEXT NOT NULL,
                record_sha256 TEXT NOT NULL,
                started_at REAL NOT NULL,
                completed_at REAL NOT NULL,
                complete INTEGER NOT NULL,
                truncated INTEGER NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (tenant, report_id),
                UNIQUE (tenant, job_id),
                UNIQUE (tenant, scanner_run_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_scan_discoveries (
                tenant TEXT NOT NULL,
                property_id TEXT NOT NULL,
                tracker_key TEXT NOT NULL,
                first_report_id TEXT NOT NULL,
                first_seen_at REAL NOT NULL,
                last_report_id TEXT NOT NULL,
                last_seen_at REAL NOT NULL,
                initial_classification TEXT NOT NULL CHECK (
                    initial_classification = 'unknown'
                ),
                revision INTEGER NOT NULL,
                record_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant, property_id, tracker_key)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_scan_classifications (
                tenant TEXT NOT NULL,
                property_id TEXT NOT NULL,
                tracker_key TEXT NOT NULL,
                version INTEGER NOT NULL,
                classification TEXT NOT NULL,
                registry_action TEXT NOT NULL,
                tracker_id TEXT,
                vendor_id TEXT,
                purpose_ids_json TEXT NOT NULL,
                reviewer_sha256 TEXT NOT NULL,
                second_reviewer_sha256 TEXT,
                evidence_sha256 TEXT NOT NULL,
                report_id TEXT NOT NULL,
                reviewed_at REAL NOT NULL,
                valid_until REAL NOT NULL,
                authority_expected_revision INTEGER NOT NULL,
                record_sha256 TEXT NOT NULL,
                PRIMARY KEY (tenant, property_id, tracker_key, version)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_scan_classification_heads (
                tenant TEXT NOT NULL,
                property_id TEXT NOT NULL,
                tracker_key TEXT NOT NULL,
                current_version INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                PRIMARY KEY (tenant, property_id, tracker_key)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_scan_idempotency (
                tenant TEXT NOT NULL,
                namespace TEXT NOT NULL,
                key_sha256 TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (tenant, namespace, key_sha256)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_scan_bridges (
                tenant TEXT NOT NULL,
                report_id TEXT NOT NULL,
                page_sha256 TEXT NOT NULL,
                result_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (tenant, report_id, page_sha256)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS consent_scan_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant TEXT NOT NULL,
                event_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                object_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                previous_event_sha256 TEXT,
                event_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE (tenant, event_id),
                UNIQUE (tenant, event_sha256)
            )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS consent_scan_reports_no_update
            BEFORE UPDATE ON consent_scan_reports
            BEGIN SELECT RAISE(ABORT, 'scan reports are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS consent_scan_classifications_no_update
            BEFORE UPDATE ON consent_scan_classifications
            BEGIN SELECT RAISE(ABORT, 'scan classifications are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS consent_scan_classifications_no_delete
            BEFORE DELETE ON consent_scan_classifications
            BEGIN SELECT RAISE(ABORT, 'scan classifications are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS consent_scan_idempotency_no_update
            BEFORE UPDATE ON consent_scan_idempotency
            BEGIN SELECT RAISE(ABORT, 'scan idempotency records are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS consent_scan_audit_no_update
            BEFORE UPDATE ON consent_scan_audit
            BEGIN SELECT RAISE(ABORT, 'scan audit is immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS consent_scan_audit_no_delete
            BEFORE DELETE ON consent_scan_audit
            BEGIN SELECT RAISE(ABORT, 'scan audit is immutable'); END
            """,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in statements:
                    connection.execute(statement)
                connection.execute(
                    "INSERT OR IGNORE INTO consent_scan_meta(key, value) "
                    "VALUES ('schema_version', ?)",
                    (str(_SCHEMA_VERSION),),
                )
                row = connection.execute(
                    "SELECT value FROM consent_scan_meta WHERE key = 'schema_version'"
                ).fetchone()
                if row is None or row["value"] != str(_SCHEMA_VERSION):
                    raise ConsentScanIntegrityError("unsupported scan inventory schema")
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _property_result(row: sqlite3.Row) -> dict[str, Any]:
        body = {
            "property_id": str(row["property_id"]),
            "origins": _loads(row["origins_json"], "property origins"),
            "start_urls": _loads(row["start_urls_json"], "property start URLs"),
            "revision": int(row["revision"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }
        expected = _sha256(body)
        if not text_equals(expected, str(row["record_sha256"])):
            raise ConsentScanIntegrityError("stored scan property failed integrity")
        return {**body, "record_sha256": expected}

    def _property_row(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        property_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM consent_scan_properties WHERE tenant = ? AND property_id = ?",
            (tenant, property_id),
        ).fetchone()
        if row is None:
            raise ConsentScanNotFound("scan property is unavailable")
        self._property_result(row)
        return row

    @staticmethod
    def _schedule_result(row: sqlite3.Row) -> dict[str, Any]:
        config = {
            "schedule_id": str(row["schedule_id"]),
            "property_id": str(row["property_id"]),
            "interval_seconds": int(row["interval_seconds"]),
            "limits": _loads(row["limits_json"], "scan limits"),
            "auth_secret_ref": row["auth_secret_ref"],
            "authenticated_scan_consent": bool(row["authenticated_scan_consent"]),
            "max_attempts": int(row["max_attempts"]),
            "retry_base_seconds": int(row["retry_base_seconds"]),
            "retry_max_seconds": int(row["retry_max_seconds"]),
            "lease_seconds": int(row["lease_seconds"]),
            "enabled": bool(row["enabled"]),
            "revision": int(row["revision"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }
        expected = _sha256(config)
        if not text_equals(expected, str(row["configuration_sha256"])):
            raise ConsentScanIntegrityError("stored scan schedule failed integrity")
        return {
            **config,
            "next_due_at": float(row["next_due_at"]),
            "configuration_sha256": expected,
        }

    def _schedule_row(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        schedule_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM consent_scan_schedules WHERE tenant = ? AND schedule_id = ?",
            (tenant, schedule_id),
        ).fetchone()
        if row is None:
            raise ConsentScanNotFound("scan schedule is unavailable")
        self._schedule_result(row)
        return row

    def _idempotent_result(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT request_sha256, result_json FROM consent_scan_idempotency "
            "WHERE tenant = ? AND namespace = ? AND key_sha256 = ?",
            (tenant, namespace, key_sha256),
        ).fetchone()
        if row is None:
            return None
        if not text_equals(str(row["request_sha256"]), request_sha256):
            raise ConsentScanConflict("idempotency key was rebound to different content")
        result = _loads(row["result_json"], "idempotency result")
        if not isinstance(result, dict):
            raise ConsentScanIntegrityError("stored idempotency result is invalid")
        return result

    @staticmethod
    def _save_idempotency(
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
            "INSERT INTO consent_scan_idempotency(tenant, namespace, key_sha256, "
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

    def _audit(
        self,
        connection: sqlite3.Connection,
        *,
        tenant: str,
        event_type: str,
        object_type: str,
        object_id: str,
        payload: Mapping[str, Any],
        now: float,
    ) -> None:
        previous = connection.execute(
            "SELECT event_sha256 FROM consent_scan_audit WHERE tenant = ? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant,),
        ).fetchone()
        previous_sha = str(previous["event_sha256"]) if previous is not None else None
        event_id = self._new_id("CSI-AUD")
        body = {
            "event_id": event_id,
            "event_type": _ref(event_type, "event_type"),
            "object_type": _ref(object_type, "object_type"),
            "object_id": _ref(object_id, "object_id"),
            "payload_sha256": _sha256(payload),
            "previous_event_sha256": previous_sha,
            "created_at": now,
        }
        event_sha = _sha256(body)
        connection.execute(
            "INSERT INTO consent_scan_audit(tenant, event_id, event_type, "
            "object_type, object_id, payload_sha256, previous_event_sha256, "
            "event_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tenant,
                event_id,
                body["event_type"],
                body["object_type"],
                body["object_id"],
                body["payload_sha256"],
                previous_sha,
                event_sha,
                now,
            ),
        )

    def upsert_property(
        self,
        tenant_id: str,
        property_id: str,
        origins: Sequence[str],
        start_urls: Sequence[str],
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create or CAS-revise exact origins and bounded scan entry points."""

        self._require()
        tenant = _tenant_id(tenant_id)
        property_ref = _ref(property_id, "property_id")
        normalized_origins = _sequence(
            origins,
            "origins",
            maximum=_MAX_ORIGINS,
            normalizer=_origin,
        )
        origin_set = frozenset(normalized_origins)
        normalized_urls = _sequence(
            start_urls,
            "start_urls",
            maximum=_MAX_START_URLS,
            normalizer=lambda value: _navigation_url(value, origin_set),
        )
        expected = _revision(expected_revision, "expected_revision")
        _raw_key, key_sha = _idempotency(idempotency_key)
        request = {
            "property_id": property_ref,
            "origins": normalized_origins,
            "start_urls": normalized_urls,
            "expected_revision": expected,
        }
        request_sha = _sha256(request)
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace="property.upsert",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                row = connection.execute(
                    "SELECT * FROM consent_scan_properties WHERE tenant = ? AND property_id = ?",
                    (tenant, property_ref),
                ).fetchone()
                current = int(row["revision"]) if row is not None else 0
                if current != expected:
                    raise ConsentScanConflict(
                        f"property revision is {current}, expected {expected}"
                    )
                if row is None:
                    count = int(
                        connection.execute(
                            "SELECT COUNT(*) FROM consent_scan_properties WHERE tenant = ?",
                            (tenant,),
                        ).fetchone()[0]
                    )
                    if count >= _MAX_PROPERTIES:
                        raise ConsentScanConflict("tenant property capacity reached")
                created_at = float(row["created_at"]) if row is not None else now
                body = {
                    "property_id": property_ref,
                    "origins": normalized_origins,
                    "start_urls": normalized_urls,
                    "revision": current + 1,
                    "created_at": created_at,
                    "updated_at": now,
                }
                record_sha = _sha256(body)
                if row is None:
                    connection.execute(
                        "INSERT INTO consent_scan_properties(tenant, property_id, "
                        "origins_json, start_urls_json, revision, record_sha256, "
                        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            tenant,
                            property_ref,
                            _canonical(normalized_origins).decode("ascii"),
                            _canonical(normalized_urls).decode("ascii"),
                            current + 1,
                            record_sha,
                            created_at,
                            now,
                        ),
                    )
                else:
                    updated = connection.execute(
                        "UPDATE consent_scan_properties SET origins_json = ?, "
                        "start_urls_json = ?, revision = ?, record_sha256 = ?, "
                        "updated_at = ? WHERE tenant = ? AND property_id = ? "
                        "AND revision = ?",
                        (
                            _canonical(normalized_origins).decode("ascii"),
                            _canonical(normalized_urls).decode("ascii"),
                            current + 1,
                            record_sha,
                            now,
                            tenant,
                            property_ref,
                            current,
                        ),
                    )
                    if updated.rowcount != 1:
                        raise ConsentScanConflict("property changed concurrently")
                result = {**body, "record_sha256": record_sha}
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="property.changed",
                    object_type="property",
                    object_id=property_ref,
                    payload={"record_sha256": record_sha, "revision": current + 1},
                    now=now,
                )
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace="property.upsert",
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

    def get_property(self, tenant_id: str, property_id: str) -> dict[str, Any]:
        self._require()
        tenant = _tenant_id(tenant_id)
        property_ref = _ref(property_id, "property_id")
        with self._connect() as connection:
            return self._property_result(self._property_row(connection, tenant, property_ref))

    def list_properties(self, tenant_id: str, *, limit: int = 100) -> dict[str, Any]:
        self._require()
        tenant = _tenant_id(tenant_id)
        page_size = _limit(limit)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM consent_scan_properties WHERE tenant = ? "
                "ORDER BY property_id LIMIT ?",
                (tenant, page_size + 1),
            ).fetchall()
        return {
            "items": [self._property_result(row) for row in rows[:page_size]],
            "truncated": len(rows) > page_size,
        }

    def put_schedule(
        self,
        tenant_id: str,
        schedule_id: str,
        property_id: str,
        *,
        interval_seconds: int | None,
        next_due_at: float,
        expected_revision: int,
        idempotency_key: str,
        limits: ScanLimits | None = None,
        auth_secret_ref: str | None = None,
        authenticated_scan_consent: bool = False,
        max_attempts: int = 3,
        retry_base_seconds: int = 30,
        retry_max_seconds: int = 3_600,
        lease_seconds: int = 300,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Create or CAS-revise one interval schedule.

        The installation's scanner settings supply the interval when none is
        given, raise a shorter interval to the installation's shortest, and
        lower each scan limit to the installation's cap.
        """

        self._require()
        tenant = _tenant_id(tenant_id)
        schedule_ref = _ref(schedule_id, "schedule_id")
        property_ref = _ref(property_id, "property_id")
        try:
            installation = scan_limit_settings()
        except ConsentScannerConfigError as exc:
            raise ConsentScanValidationError("scanner configuration is invalid") from exc
        if interval_seconds is None:
            if "interval_seconds" not in installation:
                raise ConsentScanValidationError("interval_seconds is required")
            interval_seconds = installation["interval_seconds"]
        interval = max(
            _positive_int(
                interval_seconds,
                "interval_seconds",
                _MIN_INTERVAL_SECONDS,
                _MAX_INTERVAL_SECONDS,
            ),
            installation.get("interval_seconds", _MIN_INTERVAL_SECONDS),
        )
        due = _timestamp(next_due_at, "next_due_at")
        expected = _revision(expected_revision, "expected_revision")
        attempts = _positive_int(max_attempts, "max_attempts", 1, 20)
        retry_base = _positive_int(retry_base_seconds, "retry_base_seconds", 1, 3_600)
        retry_max = _positive_int(retry_max_seconds, "retry_max_seconds", 1, 86_400)
        if retry_max < retry_base:
            raise ConsentScanValidationError("retry_max_seconds cannot be below retry_base_seconds")
        lease = _positive_int(lease_seconds, "lease_seconds", 30, 86_400)
        if not isinstance(enabled, bool) or not isinstance(authenticated_scan_consent, bool):
            raise ConsentScanValidationError("schedule booleans must be explicit")
        secret_ref = _ref(auth_secret_ref, "auth_secret_ref") if auth_secret_ref else None
        if (secret_ref is None and authenticated_scan_consent) or (
            secret_ref is not None and not authenticated_scan_consent
        ):
            raise ConsentScanValidationError(
                "authenticated scans require both a secret reference and explicit consent"
            )
        if secret_ref is not None and not self._authenticated_scan_gate():
            raise ConsentScanValidationError(
                "authenticated scans are not enabled by scanner configuration"
            )
        scan_limits = capped_scan_limits(
            limits or default_scan_limits(installation), installation
        )
        limits_body = asdict(scan_limits)
        _raw_key, key_sha = _idempotency(idempotency_key)
        request = {
            "schedule_id": schedule_ref,
            "property_id": property_ref,
            "interval_seconds": interval,
            "next_due_at": due,
            "limits": limits_body,
            "auth_secret_ref": secret_ref,
            "authenticated_scan_consent": authenticated_scan_consent,
            "max_attempts": attempts,
            "retry_base_seconds": retry_base,
            "retry_max_seconds": retry_max,
            "lease_seconds": lease,
            "enabled": enabled,
            "expected_revision": expected,
        }
        request_sha = _sha256(request)
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace="schedule.put",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                self._property_row(connection, tenant, property_ref)
                row = connection.execute(
                    "SELECT * FROM consent_scan_schedules WHERE tenant = ? AND schedule_id = ?",
                    (tenant, schedule_ref),
                ).fetchone()
                current = int(row["revision"]) if row is not None else 0
                if current != expected:
                    raise ConsentScanConflict(
                        f"schedule revision is {current}, expected {expected}"
                    )
                if row is None:
                    count = int(
                        connection.execute(
                            "SELECT COUNT(*) FROM consent_scan_schedules WHERE tenant = ?",
                            (tenant,),
                        ).fetchone()[0]
                    )
                    if count >= _MAX_SCHEDULES:
                        raise ConsentScanConflict("tenant schedule capacity reached")
                created_at = float(row["created_at"]) if row is not None else now
                config = {
                    "schedule_id": schedule_ref,
                    "property_id": property_ref,
                    "interval_seconds": interval,
                    "limits": limits_body,
                    "auth_secret_ref": secret_ref,
                    "authenticated_scan_consent": authenticated_scan_consent,
                    "max_attempts": attempts,
                    "retry_base_seconds": retry_base,
                    "retry_max_seconds": retry_max,
                    "lease_seconds": lease,
                    "enabled": enabled,
                    "revision": current + 1,
                    "created_at": created_at,
                    "updated_at": now,
                }
                config_sha = _sha256(config)
                values = (
                    property_ref,
                    interval,
                    _canonical(limits_body).decode("ascii"),
                    secret_ref,
                    int(authenticated_scan_consent),
                    attempts,
                    retry_base,
                    retry_max,
                    lease,
                    int(enabled),
                    due,
                    current + 1,
                    config_sha,
                    now,
                )
                if row is None:
                    connection.execute(
                        "INSERT INTO consent_scan_schedules(tenant, schedule_id, "
                        "property_id, interval_seconds, limits_json, auth_secret_ref, "
                        "authenticated_scan_consent, max_attempts, retry_base_seconds, "
                        "retry_max_seconds, lease_seconds, enabled, next_due_at, revision, "
                        "configuration_sha256, created_at, updated_at) VALUES "
                        "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (tenant, schedule_ref, *values[:-1], created_at, now),
                    )
                else:
                    updated = connection.execute(
                        "UPDATE consent_scan_schedules SET property_id = ?, "
                        "interval_seconds = ?, limits_json = ?, auth_secret_ref = ?, "
                        "authenticated_scan_consent = ?, max_attempts = ?, "
                        "retry_base_seconds = ?, retry_max_seconds = ?, lease_seconds = ?, "
                        "enabled = ?, next_due_at = ?, revision = ?, "
                        "configuration_sha256 = ?, updated_at = ? WHERE tenant = ? "
                        "AND schedule_id = ? AND revision = ?",
                        (*values, tenant, schedule_ref, current),
                    )
                    if updated.rowcount != 1:
                        raise ConsentScanConflict("schedule changed concurrently")
                result = {
                    **config,
                    "next_due_at": due,
                    "configuration_sha256": config_sha,
                }
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="schedule.changed",
                    object_type="schedule",
                    object_id=schedule_ref,
                    payload={"configuration_sha256": config_sha, "revision": current + 1},
                    now=now,
                )
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace="schedule.put",
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

    def get_schedule(self, tenant_id: str, schedule_id: str) -> dict[str, Any]:
        self._require()
        tenant = _tenant_id(tenant_id)
        schedule_ref = _ref(schedule_id, "schedule_id")
        with self._connect() as connection:
            return self._schedule_result(self._schedule_row(connection, tenant, schedule_ref))

    def list_schedules(self, tenant_id: str, *, limit: int = 100) -> dict[str, Any]:
        self._require()
        tenant = _tenant_id(tenant_id)
        page_size = _limit(limit)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM consent_scan_schedules WHERE tenant = ? "
                "ORDER BY schedule_id LIMIT ?",
                (tenant, page_size + 1),
            ).fetchall()
        return {
            "items": [self._schedule_result(row) for row in rows[:page_size]],
            "truncated": len(rows) > page_size,
        }

    @staticmethod
    def _job_body(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "job_id": str(row["job_id"]),
            "schedule_id": str(row["schedule_id"]),
            "property_id": str(row["property_id"]),
            "scheduled_for": float(row["scheduled_for"]),
            "missed_intervals": int(row["missed_intervals"]),
            "property_revision": int(row["property_revision"]),
            "property_sha256": str(row["property_sha256"]),
            "schedule_revision": int(row["schedule_revision"]),
            "schedule_sha256": str(row["schedule_sha256"]),
            "status": str(row["status"]),
            "attempts": int(row["attempts"]),
            "max_attempts": int(row["max_attempts"]),
            "retry_base_seconds": int(row["retry_base_seconds"]),
            "retry_max_seconds": int(row["retry_max_seconds"]),
            "lease_seconds": int(row["lease_seconds"]),
            "available_at": float(row["available_at"]),
            "lease_owner": row["lease_owner"],
            "lease_token_sha256": row["lease_token_sha256"],
            "lease_expires_at": (
                float(row["lease_expires_at"]) if row["lease_expires_at"] is not None else None
            ),
            "last_error_code": row["last_error_code"],
            "report_id": row["report_id"],
            "replay_count": int(row["replay_count"]),
            "revision": int(row["revision"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    @classmethod
    def _job_result(cls, row: sqlite3.Row) -> dict[str, Any]:
        body = cls._job_body(row)
        expected = _sha256(body)
        if not text_equals(expected, str(row["record_sha256"])):
            raise ConsentScanIntegrityError("stored scan job failed integrity")
        return {**body, "record_sha256": expected}

    @staticmethod
    def _public_job(result: Mapping[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in result.items() if key != "lease_token_sha256"}

    def _job_row(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        job_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM consent_scan_jobs WHERE tenant = ? AND job_id = ?",
            (tenant, job_id),
        ).fetchone()
        if row is None:
            raise ConsentScanNotFound("scan job is unavailable")
        self._job_result(row)
        return row

    @staticmethod
    def _insert_job(
        connection: sqlite3.Connection,
        tenant: str,
        body: Mapping[str, Any],
        record_sha256: str,
    ) -> None:
        connection.execute(
            "INSERT INTO consent_scan_jobs(tenant, job_id, schedule_id, property_id, "
            "scheduled_for, missed_intervals, property_revision, property_sha256, "
            "schedule_revision, schedule_sha256, status, attempts, max_attempts, "
            "retry_base_seconds, retry_max_seconds, lease_seconds, available_at, "
            "lease_owner, lease_token_sha256, lease_expires_at, last_error_code, "
            "report_id, replay_count, revision, record_sha256, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "?, ?, ?, ?, ?, ?, ?)",
            (
                tenant,
                body["job_id"],
                body["schedule_id"],
                body["property_id"],
                body["scheduled_for"],
                body["missed_intervals"],
                body["property_revision"],
                body["property_sha256"],
                body["schedule_revision"],
                body["schedule_sha256"],
                body["status"],
                body["attempts"],
                body["max_attempts"],
                body["retry_base_seconds"],
                body["retry_max_seconds"],
                body["lease_seconds"],
                body["available_at"],
                body["lease_owner"],
                body["lease_token_sha256"],
                body["lease_expires_at"],
                body["last_error_code"],
                body["report_id"],
                body["replay_count"],
                body["revision"],
                record_sha256,
                body["created_at"],
                body["updated_at"],
            ),
        )

    @staticmethod
    def _update_job(
        connection: sqlite3.Connection,
        tenant: str,
        body: Mapping[str, Any],
        record_sha256: str,
        expected_revision: int,
    ) -> None:
        updated = connection.execute(
            "UPDATE consent_scan_jobs SET status = ?, attempts = ?, "
            "max_attempts = ?, retry_base_seconds = ?, retry_max_seconds = ?, "
            "lease_seconds = ?, available_at = ?, lease_owner = ?, "
            "lease_token_sha256 = ?, lease_expires_at = ?, last_error_code = ?, "
            "report_id = ?, replay_count = ?, property_revision = ?, "
            "property_sha256 = ?, schedule_revision = ?, schedule_sha256 = ?, "
            "revision = ?, record_sha256 = ?, updated_at = ? WHERE tenant = ? "
            "AND job_id = ? AND revision = ?",
            (
                body["status"],
                body["attempts"],
                body["max_attempts"],
                body["retry_base_seconds"],
                body["retry_max_seconds"],
                body["lease_seconds"],
                body["available_at"],
                body["lease_owner"],
                body["lease_token_sha256"],
                body["lease_expires_at"],
                body["last_error_code"],
                body["report_id"],
                body["replay_count"],
                body["property_revision"],
                body["property_sha256"],
                body["schedule_revision"],
                body["schedule_sha256"],
                body["revision"],
                record_sha256,
                body["updated_at"],
                tenant,
                body["job_id"],
                expected_revision,
            ),
        )
        if updated.rowcount != 1:
            raise ConsentScanConflict("scan job changed concurrently")

    def enqueue_due(
        self,
        tenant_id: str,
        *,
        due_at: float | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Materialize a bounded batch of due interval jobs exactly once."""

        self._require()
        tenant = _tenant_id(tenant_id)
        now = self._now() if due_at is None else _timestamp(due_at, "due_at")
        page_size = _limit(limit)
        try:
            shortest_interval = scan_limit_settings().get(
                "interval_seconds", _MIN_INTERVAL_SECONDS
            )
        except ConsentScannerConfigError as exc:
            raise ConsentScanValidationError("scanner configuration is invalid") from exc
        jobs: list[dict[str, Any]] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    "SELECT * FROM consent_scan_schedules WHERE tenant = ? "
                    "AND enabled = 1 AND next_due_at <= ? "
                    "ORDER BY next_due_at, schedule_id LIMIT ?",
                    (tenant, now, page_size + 1),
                ).fetchall()
                for row in rows[:page_size]:
                    schedule = self._schedule_result(row)
                    property_row = self._property_row(
                        connection,
                        tenant,
                        schedule["property_id"],
                    )
                    property_result = self._property_result(property_row)
                    scheduled_for = float(row["next_due_at"])
                    # The installation's shortest interval also holds schedules
                    # saved before it was set.
                    interval = max(int(schedule["interval_seconds"]), shortest_interval)
                    intervals_elapsed = int((now - scheduled_for) // interval)
                    missed = max(0, intervals_elapsed)
                    next_due = scheduled_for + (missed + 1) * interval
                    body = {
                        "job_id": self._new_id("CSI-JOB"),
                        "schedule_id": schedule["schedule_id"],
                        "property_id": schedule["property_id"],
                        "scheduled_for": scheduled_for,
                        "missed_intervals": missed,
                        "property_revision": property_result["revision"],
                        "property_sha256": property_result["record_sha256"],
                        "schedule_revision": schedule["revision"],
                        "schedule_sha256": schedule["configuration_sha256"],
                        "status": "queued",
                        "attempts": 0,
                        "max_attempts": schedule["max_attempts"],
                        "retry_base_seconds": schedule["retry_base_seconds"],
                        "retry_max_seconds": schedule["retry_max_seconds"],
                        "lease_seconds": schedule["lease_seconds"],
                        "available_at": now,
                        "lease_owner": None,
                        "lease_token_sha256": None,
                        "lease_expires_at": None,
                        "last_error_code": None,
                        "report_id": None,
                        "replay_count": 0,
                        "revision": 1,
                        "created_at": now,
                        "updated_at": now,
                    }
                    record_sha = _sha256(body)
                    self._insert_job(connection, tenant, body, record_sha)
                    connection.execute(
                        "UPDATE consent_scan_schedules SET next_due_at = ? "
                        "WHERE tenant = ? AND schedule_id = ? AND next_due_at = ?",
                        (next_due, tenant, schedule["schedule_id"], scheduled_for),
                    )
                    result = {**body, "record_sha256": record_sha}
                    jobs.append(self._public_job(result))
                    self._audit(
                        connection,
                        tenant=tenant,
                        event_type="job.enqueued",
                        object_type="job",
                        object_id=body["job_id"],
                        payload={
                            "record_sha256": record_sha,
                            "scheduled_for": scheduled_for,
                            "missed_intervals": missed,
                        },
                        now=now,
                    )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return {"items": jobs, "truncated": len(rows) > page_size}

    def _recover_stale_leases(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        now: float,
    ) -> tuple[int, bool]:
        rows = connection.execute(
            "SELECT * FROM consent_scan_jobs WHERE tenant = ? AND status = 'leased' "
            "AND lease_expires_at <= ? ORDER BY lease_expires_at, job_id LIMIT ?",
            (tenant, now, _MAX_STALE_RECOVERY + 1),
        ).fetchall()
        for row in rows[:_MAX_STALE_RECOVERY]:
            current = self._job_result(row)
            dead = current["attempts"] >= current["max_attempts"]
            body = {
                **self._job_body(row),
                "status": "dead_letter" if dead else "queued",
                "available_at": now,
                "lease_owner": None,
                "lease_token_sha256": None,
                "lease_expires_at": None,
                "last_error_code": "lease_expired",
                "revision": current["revision"] + 1,
                "updated_at": now,
            }
            record_sha = _sha256(body)
            self._update_job(connection, tenant, body, record_sha, current["revision"])
            self._audit(
                connection,
                tenant=tenant,
                event_type="job.lease_recovered",
                object_type="job",
                object_id=current["job_id"],
                payload={
                    "status": body["status"],
                    "attempts": body["attempts"],
                    "record_sha256": record_sha,
                },
                now=now,
            )
        return min(len(rows), _MAX_STALE_RECOVERY), len(rows) > _MAX_STALE_RECOVERY

    def claim_due(
        self,
        tenant_id: str,
        worker_id: str,
        *,
        limit: int = 1,
    ) -> dict[str, Any]:
        """Recover stale leases and atomically claim queued work."""

        self._require()
        tenant = _tenant_id(tenant_id)
        worker = _ref(worker_id, "worker_id")
        page_size = _positive_int(limit, "limit", 1, 100)
        now = self._now()
        claimed: list[dict[str, Any]] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                recovered, recovery_truncated = self._recover_stale_leases(
                    connection,
                    tenant,
                    now,
                )
                rows = connection.execute(
                    "SELECT * FROM consent_scan_jobs WHERE tenant = ? "
                    "AND status = 'queued' AND available_at <= ? "
                    "ORDER BY available_at, scheduled_for, job_id LIMIT ?",
                    (tenant, now, page_size + 1),
                ).fetchall()
                for row in rows[:page_size]:
                    current = self._job_result(row)
                    raw_token = self._token_factory()
                    if not isinstance(raw_token, str) or not _TOKEN_RE.fullmatch(raw_token):
                        raise ConsentScanIntegrityError(
                            "lease token factory returned an invalid token"
                        )
                    token_sha = _text_digest(raw_token)
                    body = {
                        **self._job_body(row),
                        "status": "leased",
                        "attempts": current["attempts"] + 1,
                        "lease_owner": worker,
                        "lease_token_sha256": token_sha,
                        "lease_expires_at": now + current["lease_seconds"],
                        "last_error_code": None,
                        "revision": current["revision"] + 1,
                        "updated_at": now,
                    }
                    record_sha = _sha256(body)
                    self._update_job(connection, tenant, body, record_sha, current["revision"])
                    claimed.append(
                        {
                            **self._public_job({**body, "record_sha256": record_sha}),
                            "lease_token": raw_token,
                        }
                    )
                    self._audit(
                        connection,
                        tenant=tenant,
                        event_type="job.claimed",
                        object_type="job",
                        object_id=current["job_id"],
                        payload={
                            "worker_sha256": _text_digest(worker),
                            "attempt": body["attempts"],
                            "lease_expires_at": body["lease_expires_at"],
                        },
                        now=now,
                    )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return {
            "items": claimed,
            "truncated": len(rows) > page_size,
            "recovered_leases": recovered,
            "recovery_truncated": recovery_truncated,
        }

    @staticmethod
    def _assert_lease(
        row: sqlite3.Row,
        *,
        worker: str,
        token_sha256: str,
        now: float,
    ) -> None:
        if (
            row["status"] != "leased"
            or row["lease_owner"] != worker
            or row["lease_token_sha256"] is None
            or not text_equals(str(row["lease_token_sha256"]), token_sha256)
            or row["lease_expires_at"] is None
            or float(row["lease_expires_at"]) <= now
        ):
            raise ConsentScanLeaseError("scan job lease is unavailable")

    def renew_lease(
        self,
        tenant_id: str,
        job_id: str,
        worker_id: str,
        lease_token: str,
        *,
        expected_revision: int,
    ) -> dict[str, Any]:
        """CAS-renew a current lease by its schedule-bound duration."""

        self._require()
        tenant = _tenant_id(tenant_id)
        job_ref = _ref(job_id, "job_id")
        worker = _ref(worker_id, "worker_id")
        if not isinstance(lease_token, str) or not _TOKEN_RE.fullmatch(lease_token):
            raise ConsentScanLeaseError("scan job lease is unavailable")
        token_sha = _text_digest(lease_token)
        expected = _revision(expected_revision, "expected_revision")
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._job_row(connection, tenant, job_ref)
                current = self._job_result(row)
                if current["revision"] != expected:
                    raise ConsentScanConflict(
                        f"job revision is {current['revision']}, expected {expected}"
                    )
                self._assert_lease(
                    row,
                    worker=worker,
                    token_sha256=token_sha,
                    now=now,
                )
                body = {
                    **self._job_body(row),
                    "lease_expires_at": now + current["lease_seconds"],
                    "revision": current["revision"] + 1,
                    "updated_at": now,
                }
                record_sha = _sha256(body)
                self._update_job(connection, tenant, body, record_sha, current["revision"])
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="job.lease_renewed",
                    object_type="job",
                    object_id=job_ref,
                    payload={
                        "worker_sha256": _text_digest(worker),
                        "lease_expires_at": body["lease_expires_at"],
                    },
                    now=now,
                )
                connection.execute("COMMIT")
                return self._public_job({**body, "record_sha256": record_sha})
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _validate_scanner_report(
        report: object,
        *,
        tenant: str,
        property_id: str,
    ) -> tuple[ScanReport, dict[str, Any]]:
        if not isinstance(report, ScanReport):
            raise ConsentScanIntegrityError("scanner returned an invalid report type")
        body = asdict(report)
        supplied_sha = body.pop("report_sha256", None)
        try:
            expected_sha = _sha256(body)
        except ConsentScanValidationError as exc:
            raise ConsentScanIntegrityError("scanner report exceeded inventory bounds") from exc
        if (
            not isinstance(supplied_sha, str)
            or not hmac.compare_digest(expected_sha, supplied_sha)
            or report.schema != SCAN_REPORT_SCHEMA
            or report.tenant_sha256 != _text_digest(tenant)
            or report.property_id != property_id
            or not 0 < report.started_at <= report.completed_at < 100_000_000_000.0
            or isinstance(report.pages_attempted, bool)
            or not 0 <= report.pages_attempted <= 10_000
            or isinstance(report.pages_captured, bool)
            or not 0 <= report.pages_captured <= report.pages_attempted
            or len(report.page_sha256) > 10_000
            or len(set(report.page_sha256)) != len(report.page_sha256)
            or any(
                not isinstance(item, str) or not _DIGEST_RE.fullmatch(item)
                for item in report.page_sha256
            )
            or len(report.errors) > 100
            or report.complete != (not report.truncated and not report.errors)
            or any(finding.classification != "unknown" for finding in report.findings)
            or len({finding.tracker_key for finding in report.findings}) != len(report.findings)
        ):
            raise ConsentScanIntegrityError("scanner report failed exact integrity validation")
        for finding in report.findings:
            if (
                not isinstance(finding, ScanFinding)
                or finding.kind not in _FINDING_KINDS
                or not isinstance(finding.host, str)
                or not _HOST_RE.fullmatch(finding.host)
                or not isinstance(finding.first_party, bool)
                or (
                    finding.path_sha256 is not None
                    and (
                        not isinstance(finding.path_sha256, str)
                        or not _DIGEST_RE.fullmatch(finding.path_sha256)
                    )
                )
                or (
                    finding.name_sha256 is not None
                    and (
                        not isinstance(finding.name_sha256, str)
                        or not _DIGEST_RE.fullmatch(finding.name_sha256)
                    )
                )
                or (
                    finding.resource_type is not None
                    and finding.resource_type not in _RESOURCE_TYPES
                )
            ):
                raise ConsentScanIntegrityError("scanner finding is invalid")
            _ref(finding.finding_id, "finding_id")
            _digest(finding.tracker_key, "tracker_key")
            _digest(finding.source_page_sha256, "source_page_sha256")
            _digest(finding.evidence_sha256, "evidence_sha256")
        for error in report.errors:
            if (
                not isinstance(error, Mapping)
                or set(error) != {"page_sha256", "error_code"}
                or not isinstance(error["page_sha256"], str)
                or not _DIGEST_RE.fullmatch(error["page_sha256"])
                or not isinstance(error["error_code"], str)
                or not _REF_RE.fullmatch(error["error_code"])
            ):
                raise ConsentScanIntegrityError("scanner error summary is invalid")
        return report, {**body, "report_sha256": expected_sha}

    def _finish_failure(
        self,
        tenant: str,
        job_id: str,
        worker: str,
        token_sha: str,
        *,
        error_code: str,
        permanent: bool,
    ) -> dict[str, Any]:
        now = self._now()
        normalized_error = _ref(error_code, "error_code")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._job_row(connection, tenant, job_id)
                current = self._job_result(row)
                self._assert_lease(
                    row,
                    worker=worker,
                    token_sha256=token_sha,
                    now=now,
                )
                dead = permanent or current["attempts"] >= current["max_attempts"]
                delay = min(
                    current["retry_base_seconds"] * (2 ** max(0, current["attempts"] - 1)),
                    current["retry_max_seconds"],
                )
                body = {
                    **self._job_body(row),
                    "status": "dead_letter" if dead else "queued",
                    "available_at": now if dead else now + delay,
                    "lease_owner": None,
                    "lease_token_sha256": None,
                    "lease_expires_at": None,
                    "last_error_code": normalized_error,
                    "revision": current["revision"] + 1,
                    "updated_at": now,
                }
                record_sha = _sha256(body)
                self._update_job(connection, tenant, body, record_sha, current["revision"])
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type=("job.dead_lettered" if dead else "job.retry_scheduled"),
                    object_type="job",
                    object_id=job_id,
                    payload={
                        "error_code": normalized_error,
                        "attempts": current["attempts"],
                        "available_at": body["available_at"],
                    },
                    now=now,
                )
                connection.execute("COMMIT")
                return self._public_job({**body, "record_sha256": record_sha})
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _discovery_result(row: sqlite3.Row) -> dict[str, Any]:
        body = {
            "property_id": str(row["property_id"]),
            "tracker_key": str(row["tracker_key"]),
            "first_report_id": str(row["first_report_id"]),
            "first_seen_at": float(row["first_seen_at"]),
            "last_report_id": str(row["last_report_id"]),
            "last_seen_at": float(row["last_seen_at"]),
            "initial_classification": str(row["initial_classification"]),
            "revision": int(row["revision"]),
        }
        expected = _sha256(body)
        if body["initial_classification"] != "unknown" or not text_equals(
            expected, str(row["record_sha256"])
        ):
            raise ConsentScanIntegrityError("stored discovery failed integrity")
        return {**body, "record_sha256": expected}

    @staticmethod
    def _report_result(row: sqlite3.Row) -> dict[str, Any]:
        scanner_report = _loads(row["scanner_report_json"], "scanner report")
        if not isinstance(scanner_report, dict):
            raise ConsentScanIntegrityError("stored scanner report is invalid")
        scanner_body = dict(scanner_report)
        supplied_scanner_sha = scanner_body.pop("report_sha256", None)
        expected_scanner_sha = _sha256(scanner_body)
        if (
            not isinstance(supplied_scanner_sha, str)
            or not text_equals(supplied_scanner_sha, expected_scanner_sha)
            or not text_equals(
                expected_scanner_sha,
                str(row["scanner_report_sha256"]),
            )
        ):
            raise ConsentScanIntegrityError("stored scanner report failed integrity")
        body = {
            "report_id": str(row["report_id"]),
            "job_id": str(row["job_id"]),
            "schedule_id": str(row["schedule_id"]),
            "property_id": str(row["property_id"]),
            "scanner_run_id": str(row["scanner_run_id"]),
            "scanner_report_sha256": expected_scanner_sha,
            "started_at": float(row["started_at"]),
            "completed_at": float(row["completed_at"]),
            "complete": bool(row["complete"]),
            "truncated": bool(row["truncated"]),
            "created_at": float(row["created_at"]),
        }
        expected_record_sha = _sha256(body)
        if (
            scanner_report.get("run_id") != body["scanner_run_id"]
            or scanner_report.get("property_id") != body["property_id"]
            or scanner_report.get("started_at") != body["started_at"]
            or scanner_report.get("completed_at") != body["completed_at"]
            or scanner_report.get("complete") is not body["complete"]
            or scanner_report.get("truncated") is not body["truncated"]
            or not text_equals(expected_record_sha, str(row["record_sha256"]))
        ):
            raise ConsentScanIntegrityError("stored inventory report failed integrity")
        return {
            **body,
            "record_sha256": expected_record_sha,
            "scanner_report": scanner_report,
        }

    def _report_row(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        report_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM consent_scan_reports WHERE tenant = ? AND report_id = ?",
            (tenant, report_id),
        ).fetchone()
        if row is None:
            raise ConsentScanNotFound("scan report is unavailable")
        self._report_result(row)
        return row

    def _persist_success(
        self,
        tenant: str,
        job_id: str,
        worker: str,
        token_sha: str,
        report: ScanReport,
        report_body: Mapping[str, Any],
    ) -> dict[str, Any]:
        now = self._now()
        report_id = self._new_id("CSI-RPT")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._job_row(connection, tenant, job_id)
                current = self._job_result(row)
                self._assert_lease(
                    row,
                    worker=worker,
                    token_sha256=token_sha,
                    now=now,
                )
                if current["property_id"] != report.property_id:
                    raise ConsentScanIntegrityError("report property does not match job")
                inventory_body = {
                    "report_id": report_id,
                    "job_id": job_id,
                    "schedule_id": current["schedule_id"],
                    "property_id": current["property_id"],
                    "scanner_run_id": report.run_id,
                    "scanner_report_sha256": report.report_sha256,
                    "started_at": report.started_at,
                    "completed_at": report.completed_at,
                    "complete": report.complete,
                    "truncated": report.truncated,
                    "created_at": now,
                }
                record_sha = _sha256(inventory_body)
                connection.execute(
                    "INSERT INTO consent_scan_reports(tenant, report_id, job_id, "
                    "schedule_id, property_id, scanner_run_id, scanner_report_json, "
                    "scanner_report_sha256, record_sha256, started_at, completed_at, "
                    "complete, truncated, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, "
                    "?, ?, ?, ?, ?, ?)",
                    (
                        tenant,
                        report_id,
                        job_id,
                        current["schedule_id"],
                        current["property_id"],
                        report.run_id,
                        _canonical(report_body).decode("ascii"),
                        report.report_sha256,
                        record_sha,
                        report.started_at,
                        report.completed_at,
                        int(report.complete),
                        int(report.truncated),
                        now,
                    ),
                )
                for finding in report.findings:
                    existing = connection.execute(
                        "SELECT * FROM consent_scan_discoveries WHERE tenant = ? "
                        "AND property_id = ? AND tracker_key = ?",
                        (tenant, current["property_id"], finding.tracker_key),
                    ).fetchone()
                    if existing is None:
                        discovery = {
                            "property_id": current["property_id"],
                            "tracker_key": finding.tracker_key,
                            "first_report_id": report_id,
                            "first_seen_at": report.completed_at,
                            "last_report_id": report_id,
                            "last_seen_at": report.completed_at,
                            "initial_classification": "unknown",
                            "revision": 1,
                        }
                        discovery_sha = _sha256(discovery)
                        connection.execute(
                            "INSERT INTO consent_scan_discoveries(tenant, property_id, "
                            "tracker_key, first_report_id, first_seen_at, last_report_id, "
                            "last_seen_at, initial_classification, revision, record_sha256) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, 'unknown', ?, ?)",
                            (
                                tenant,
                                discovery["property_id"],
                                discovery["tracker_key"],
                                discovery["first_report_id"],
                                discovery["first_seen_at"],
                                discovery["last_report_id"],
                                discovery["last_seen_at"],
                                discovery["revision"],
                                discovery_sha,
                            ),
                        )
                    else:
                        previous = self._discovery_result(existing)
                        discovery = {
                            **{
                                key: value
                                for key, value in previous.items()
                                if key != "record_sha256"
                            },
                            "last_report_id": report_id,
                            "last_seen_at": report.completed_at,
                            "revision": previous["revision"] + 1,
                        }
                        discovery_sha = _sha256(discovery)
                        updated = connection.execute(
                            "UPDATE consent_scan_discoveries SET last_report_id = ?, "
                            "last_seen_at = ?, revision = ?, record_sha256 = ? WHERE "
                            "tenant = ? AND property_id = ? AND tracker_key = ? "
                            "AND revision = ?",
                            (
                                report_id,
                                report.completed_at,
                                discovery["revision"],
                                discovery_sha,
                                tenant,
                                current["property_id"],
                                finding.tracker_key,
                                previous["revision"],
                            ),
                        )
                        if updated.rowcount != 1:
                            raise ConsentScanConflict("discovery changed concurrently")
                job_body = {
                    **self._job_body(row),
                    "status": "succeeded",
                    "lease_owner": None,
                    "lease_token_sha256": None,
                    "lease_expires_at": None,
                    "last_error_code": None,
                    "report_id": report_id,
                    "revision": current["revision"] + 1,
                    "updated_at": now,
                }
                job_sha = _sha256(job_body)
                self._update_job(connection, tenant, job_body, job_sha, current["revision"])
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="report.recorded",
                    object_type="report",
                    object_id=report_id,
                    payload={
                        "scanner_report_sha256": report.report_sha256,
                        "complete": report.complete,
                        "truncated": report.truncated,
                        "findings": len(report.findings),
                    },
                    now=now,
                )
                connection.execute("COMMIT")
                return {
                    "succeeded": True,
                    "job": self._public_job({**job_body, "record_sha256": job_sha}),
                    "report": {
                        **inventory_body,
                        "record_sha256": record_sha,
                        "scanner_report": dict(report_body),
                    },
                }
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def run_claim(
        self,
        tenant_id: str,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> dict[str, Any]:
        """Run the injected scanner for exactly one current lease."""

        self._require()
        tenant = _tenant_id(tenant_id)
        job_ref = _ref(job_id, "job_id")
        worker = _ref(worker_id, "worker_id")
        if not isinstance(lease_token, str) or not _TOKEN_RE.fullmatch(lease_token):
            raise ConsentScanLeaseError("scan job lease is unavailable")
        token_sha = _text_digest(lease_token)
        now = self._now()
        with self._connect() as connection:
            row = self._job_row(connection, tenant, job_ref)
            current = self._job_result(row)
            self._assert_lease(
                row,
                worker=worker,
                token_sha256=token_sha,
                now=now,
            )
            property_row = self._property_row(
                connection,
                tenant,
                current["property_id"],
            )
            property_result = self._property_result(property_row)
            schedule_row = self._schedule_row(
                connection,
                tenant,
                current["schedule_id"],
            )
            schedule = self._schedule_result(schedule_row)
        authority_current = (
            property_result["revision"] == current["property_revision"]
            and text_equals(
                property_result["record_sha256"],
                current["property_sha256"],
            )
            and schedule["revision"] == current["schedule_revision"]
            and text_equals(
                schedule["configuration_sha256"],
                current["schedule_sha256"],
            )
            and schedule["enabled"] is True
            and (schedule["auth_secret_ref"] is None or self._authenticated_scan_gate())
        )
        if not authority_current:
            failed = self._finish_failure(
                tenant,
                job_ref,
                worker,
                token_sha,
                error_code="authority_changed",
                permanent=True,
            )
            return {"succeeded": False, "job": failed}
        try:
            scan_limits = ScanLimits(**schedule["limits"]).validated()
            raw_report = self._scanner.scan(
                tenant,
                current["property_id"],
                property_result["start_urls"],
                property_result["origins"],
                limits=scan_limits,
                auth_secret_ref=schedule["auth_secret_ref"],
                authenticated_scan_consent=schedule["authenticated_scan_consent"],
            )
            report, report_body = self._validate_scanner_report(
                raw_report,
                tenant=tenant,
                property_id=current["property_id"],
            )
        except Exception as exc:
            failed = self._finish_failure(
                tenant,
                job_ref,
                worker,
                token_sha,
                error_code=_error_code(exc),
                permanent=False,
            )
            return {"succeeded": False, "job": failed}
        return self._persist_success(
            tenant,
            job_ref,
            worker,
            token_sha,
            report,
            report_body,
        )

    def replay_dead_letter(
        self,
        tenant_id: str,
        job_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """CAS-replay one dead letter against fresh property/schedule authority."""

        self._require()
        tenant = _tenant_id(tenant_id)
        job_ref = _ref(job_id, "job_id")
        expected = _revision(expected_revision, "expected_revision")
        _raw_key, key_sha = _idempotency(idempotency_key)
        request = {"job_id": job_ref, "expected_revision": expected}
        request_sha = _sha256(request)
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace="job.replay",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                row = self._job_row(connection, tenant, job_ref)
                current = self._job_result(row)
                if current["revision"] != expected:
                    raise ConsentScanConflict(
                        f"job revision is {current['revision']}, expected {expected}"
                    )
                if current["status"] != "dead_letter":
                    raise ConsentScanConflict("only dead-letter jobs can be replayed")
                if current["replay_count"] >= _MAX_REPLAYS:
                    raise ConsentScanConflict("dead-letter replay bound reached")
                property_result = self._property_result(
                    self._property_row(connection, tenant, current["property_id"])
                )
                schedule = self._schedule_result(
                    self._schedule_row(connection, tenant, current["schedule_id"])
                )
                if schedule["enabled"] is not True:
                    raise ConsentScanConflict("disabled schedules cannot be replayed")
                body = {
                    **self._job_body(row),
                    "status": "queued",
                    "attempts": 0,
                    "max_attempts": schedule["max_attempts"],
                    "retry_base_seconds": schedule["retry_base_seconds"],
                    "retry_max_seconds": schedule["retry_max_seconds"],
                    "lease_seconds": schedule["lease_seconds"],
                    "available_at": now,
                    "lease_owner": None,
                    "lease_token_sha256": None,
                    "lease_expires_at": None,
                    "last_error_code": None,
                    "property_revision": property_result["revision"],
                    "property_sha256": property_result["record_sha256"],
                    "schedule_revision": schedule["revision"],
                    "schedule_sha256": schedule["configuration_sha256"],
                    "replay_count": current["replay_count"] + 1,
                    "revision": current["revision"] + 1,
                    "updated_at": now,
                }
                record_sha = _sha256(body)
                self._update_job(connection, tenant, body, record_sha, current["revision"])
                result = self._public_job({**body, "record_sha256": record_sha})
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="job.replayed",
                    object_type="job",
                    object_id=job_ref,
                    payload={
                        "replay_count": body["replay_count"],
                        "record_sha256": record_sha,
                    },
                    now=now,
                )
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace="job.replay",
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

    def get_job(self, tenant_id: str, job_id: str) -> dict[str, Any]:
        self._require()
        tenant = _tenant_id(tenant_id)
        job_ref = _ref(job_id, "job_id")
        with self._connect() as connection:
            result = self._job_result(self._job_row(connection, tenant, job_ref))
        return self._public_job(result)

    def list_jobs(
        self,
        tenant_id: str,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._require()
        tenant = _tenant_id(tenant_id)
        page_size = _limit(limit)
        if status is not None and status not in _JOB_STATES:
            raise ConsentScanValidationError("job status is invalid")
        with self._connect() as connection:
            if status is None:
                rows = connection.execute(
                    "SELECT * FROM consent_scan_jobs WHERE tenant = ? "
                    "ORDER BY created_at DESC, job_id LIMIT ?",
                    (tenant, page_size + 1),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM consent_scan_jobs WHERE tenant = ? AND status = ? "
                    "ORDER BY created_at DESC, job_id LIMIT ?",
                    (tenant, status, page_size + 1),
                ).fetchall()
        return {
            "items": [self._public_job(self._job_result(row)) for row in rows[:page_size]],
            "truncated": len(rows) > page_size,
        }

    def get_report(self, tenant_id: str, report_id: str) -> dict[str, Any]:
        self._require()
        tenant = _tenant_id(tenant_id)
        report_ref = _ref(report_id, "report_id")
        with self._connect() as connection:
            return self._report_result(self._report_row(connection, tenant, report_ref))

    def list_reports(
        self,
        tenant_id: str,
        *,
        property_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._require()
        tenant = _tenant_id(tenant_id)
        property_ref = _ref(property_id, "property_id") if property_id else None
        page_size = _limit(limit)
        with self._connect() as connection:
            if property_ref is None:
                rows = connection.execute(
                    "SELECT * FROM consent_scan_reports WHERE tenant = ? "
                    "ORDER BY completed_at DESC, report_id LIMIT ?",
                    (tenant, page_size + 1),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM consent_scan_reports WHERE tenant = ? "
                    "AND property_id = ? ORDER BY completed_at DESC, report_id LIMIT ?",
                    (tenant, property_ref, page_size + 1),
                ).fetchall()
        items = []
        for row in rows[:page_size]:
            result = self._report_result(row)
            report = result.pop("scanner_report")
            items.append(
                {
                    **result,
                    "pages_attempted": report["pages_attempted"],
                    "pages_captured": report["pages_captured"],
                    "finding_count": len(report["findings"]),
                    "error_count": len(report["errors"]),
                }
            )
        return {"items": items, "truncated": len(rows) > page_size}

    def diff_reports(
        self,
        tenant_id: str,
        older_report_id: str,
        newer_report_id: str,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Compare finding keys without turning non-observation into proof of absence."""

        self._require()
        tenant = _tenant_id(tenant_id)
        older_ref = _ref(older_report_id, "older_report_id")
        newer_ref = _ref(newer_report_id, "newer_report_id")
        page_size = _limit(limit)
        with self._connect() as connection:
            older = self._report_result(self._report_row(connection, tenant, older_ref))
            newer = self._report_result(self._report_row(connection, tenant, newer_ref))
        if older["property_id"] != newer["property_id"]:
            raise ConsentScanValidationError("report properties do not match")
        older_keys = {
            str(item["tracker_key"])
            for item in older["scanner_report"]["findings"]
            if isinstance(item, dict) and isinstance(item.get("tracker_key"), str)
        }
        newer_keys = {
            str(item["tracker_key"])
            for item in newer["scanner_report"]["findings"]
            if isinstance(item, dict) and isinstance(item.get("tracker_key"), str)
        }
        added_all = sorted(newer_keys - older_keys)
        removed_all = sorted(older_keys - newer_keys)
        unchanged_count = len(older_keys & newer_keys)
        combined = [("added", key) for key in added_all] + [("removed", key) for key in removed_all]
        selected = combined[:page_size]
        result = {
            "property_id": older["property_id"],
            "older_report_id": older_ref,
            "newer_report_id": newer_ref,
            "older_report_sha256": older["scanner_report_sha256"],
            "newer_report_sha256": newer["scanner_report_sha256"],
            "added": [key for kind, key in selected if kind == "added"],
            "removed": [key for kind, key in selected if kind == "removed"],
            "added_count": len(added_all),
            "removed_count": len(removed_all),
            "unchanged_count": unchanged_count,
            "diff_truncated": len(combined) > page_size,
            "older_complete": older["complete"],
            "newer_complete": newer["complete"],
            "coverage_complete": older["complete"] and newer["complete"],
            "absence_is_proven": False,
        }
        return {**result, "diff_sha256": _sha256(result)}

    def list_discoveries(
        self,
        tenant_id: str,
        property_id: str,
        *,
        after_tracker_key: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._require()
        tenant = _tenant_id(tenant_id)
        property_ref = _ref(property_id, "property_id")
        after = (
            _digest(after_tracker_key, "after_tracker_key")
            if after_tracker_key is not None
            else None
        )
        page_size = _limit(limit)
        now = self._now()
        with self._connect() as connection:
            self._property_row(connection, tenant, property_ref)
            if after is None:
                rows = connection.execute(
                    "SELECT * FROM consent_scan_discoveries WHERE tenant = ? "
                    "AND property_id = ? ORDER BY tracker_key LIMIT ?",
                    (tenant, property_ref, page_size + 1),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM consent_scan_discoveries WHERE tenant = ? "
                    "AND property_id = ? AND tracker_key > ? "
                    "ORDER BY tracker_key LIMIT ?",
                    (tenant, property_ref, after, page_size + 1),
                ).fetchall()
            items = []
            for row in rows[:page_size]:
                discovery = self._discovery_result(row)
                review = self._current_classification(
                    connection,
                    tenant,
                    property_ref,
                    discovery["tracker_key"],
                )
                items.append(
                    {
                        **discovery,
                        "review": review,
                        "review_fresh": bool(review is not None and review["valid_until"] > now),
                    }
                )
        truncated = len(rows) > page_size
        return {
            "items": items,
            "after_tracker_key": after,
            "truncated": truncated,
            "next_after_tracker_key": items[-1]["tracker_key"] if truncated and items else None,
        }

    @staticmethod
    def _classification_result(row: sqlite3.Row) -> dict[str, Any]:
        body = {
            "property_id": str(row["property_id"]),
            "tracker_key": str(row["tracker_key"]),
            "version": int(row["version"]),
            "classification": str(row["classification"]),
            "registry_action": str(row["registry_action"]),
            "tracker_id": row["tracker_id"],
            "vendor_id": row["vendor_id"],
            "purpose_ids": _loads(row["purpose_ids_json"], "review purposes"),
            "reviewer_sha256": str(row["reviewer_sha256"]),
            "second_reviewer_sha256": row["second_reviewer_sha256"],
            "evidence_sha256": str(row["evidence_sha256"]),
            "report_id": str(row["report_id"]),
            "reviewed_at": float(row["reviewed_at"]),
            "valid_until": float(row["valid_until"]),
            "authority_expected_revision": int(row["authority_expected_revision"]),
        }
        expected = _sha256(body)
        if (
            body["classification"] not in _REVIEW_CLASSES
            or body["registry_action"] not in _REVIEW_ACTIONS
            or not text_equals(expected, str(row["record_sha256"]))
        ):
            raise ConsentScanIntegrityError("stored tracker review failed integrity")
        return {**body, "record_sha256": expected}

    def _current_classification(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        property_id: str,
        tracker_key: str,
    ) -> dict[str, Any] | None:
        head = connection.execute(
            "SELECT current_version, revision FROM consent_scan_classification_heads "
            "WHERE tenant = ? AND property_id = ? AND tracker_key = ?",
            (tenant, property_id, tracker_key),
        ).fetchone()
        if head is None:
            orphan = connection.execute(
                "SELECT 1 FROM consent_scan_classifications WHERE tenant = ? "
                "AND property_id = ? AND tracker_key = ? LIMIT 1",
                (tenant, property_id, tracker_key),
            ).fetchone()
            if orphan is not None:
                raise ConsentScanIntegrityError("tracker review head is missing")
            return None
        maximum = connection.execute(
            "SELECT MAX(version) FROM consent_scan_classifications WHERE tenant = ? "
            "AND property_id = ? AND tracker_key = ?",
            (tenant, property_id, tracker_key),
        ).fetchone()[0]
        if (
            maximum is None
            or int(head["current_version"]) != int(maximum)
            or int(head["revision"]) != int(maximum)
        ):
            raise ConsentScanIntegrityError("tracker review head failed integrity")
        row = connection.execute(
            "SELECT c.* FROM consent_scan_classifications c WHERE c.tenant = ? "
            "AND c.property_id = ? AND c.tracker_key = ? AND c.version = ?",
            (tenant, property_id, tracker_key, int(head["current_version"])),
        ).fetchone()
        if row is None:
            raise ConsentScanIntegrityError("tracker review head is invalid")
        return self._classification_result(row)

    def review_tracker(
        self,
        tenant_id: str,
        property_id: str,
        tracker_key: str,
        *,
        classification: str,
        registry_action: str,
        reviewer_sha256: str,
        evidence_sha256: str,
        report_id: str,
        valid_until: float,
        expected_version: int,
        idempotency_key: str,
        second_reviewer_sha256: str | None = None,
        tracker_id: str | None = None,
        vendor_id: str | None = None,
        purpose_ids: Sequence[str] = (),
        authority_expected_revision: int = 0,
    ) -> dict[str, Any]:
        """Record one immutable, freshness-bounded classification version."""

        self._require()
        tenant = _tenant_id(tenant_id)
        property_ref = _ref(property_id, "property_id")
        tracker_digest = _digest(tracker_key, "tracker_key")
        if classification not in _REVIEW_CLASSES:
            raise ConsentScanValidationError("classification is invalid")
        if registry_action not in _REVIEW_ACTIONS:
            raise ConsentScanValidationError("registry_action is invalid")
        if classification == "not_a_tracker" and registry_action != "observe_only":
            raise ConsentScanValidationError(
                "not-a-tracker classifications cannot carry registry authority"
            )
        reviewer = _digest(reviewer_sha256, "reviewer_sha256")
        second = (
            _digest(second_reviewer_sha256, "second_reviewer_sha256")
            if second_reviewer_sha256 is not None
            else None
        )
        evidence = _digest(evidence_sha256, "evidence_sha256")
        report_ref = _ref(report_id, "report_id")
        expected = _revision(expected_version, "expected_version")
        authority_revision = _revision(
            authority_expected_revision,
            "authority_expected_revision",
        )
        now = self._now()
        freshness = _timestamp(valid_until, "valid_until")
        if not now < freshness <= now + _MAX_REVIEW_LIFETIME:
            raise ConsentScanValidationError("review freshness is outside its bound")
        if registry_action == "observe_only":
            if (
                any(value is not None for value in (tracker_id, vendor_id, second_reviewer_sha256))
                or purpose_ids
            ):
                raise ConsentScanValidationError(
                    "observe-only reviews cannot carry registry authority"
                )
            tracker_ref = None
            vendor_ref = None
            purposes: list[str] = []
        else:
            if second is None or hmac.compare_digest(reviewer, second):
                raise ConsentScanValidationError("registry actions require two distinct reviewers")
            tracker_ref = _ref(tracker_id, "tracker_id")
            vendor_ref = _ref(vendor_id, "vendor_id")
            purposes = _sequence(
                purpose_ids,
                "purpose_ids",
                maximum=_MAX_PURPOSES,
                normalizer=lambda value: _ref(value, "purpose_id"),
            )
        _raw_key, key_sha = _idempotency(idempotency_key)
        request = {
            "property_id": property_ref,
            "tracker_key": tracker_digest,
            "classification": classification,
            "registry_action": registry_action,
            "tracker_id": tracker_ref,
            "vendor_id": vendor_ref,
            "purpose_ids": purposes,
            "reviewer_sha256": reviewer,
            "second_reviewer_sha256": second,
            "evidence_sha256": evidence,
            "report_id": report_ref,
            "valid_until": freshness,
            "authority_expected_revision": authority_revision,
            "expected_version": expected,
        }
        request_sha = _sha256(request)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace="tracker.review",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if replay is not None:
                    connection.execute("COMMIT")
                    return replay
                discovery = connection.execute(
                    "SELECT * FROM consent_scan_discoveries WHERE tenant = ? "
                    "AND property_id = ? AND tracker_key = ?",
                    (tenant, property_ref, tracker_digest),
                ).fetchone()
                if discovery is None:
                    raise ConsentScanNotFound("tracker discovery is unavailable")
                self._discovery_result(discovery)
                report = self._report_result(self._report_row(connection, tenant, report_ref))
                if report["property_id"] != property_ref or tracker_digest not in {
                    item.get("tracker_key")
                    for item in report["scanner_report"]["findings"]
                    if isinstance(item, dict)
                }:
                    raise ConsentScanValidationError(
                        "review evidence report does not contain this tracker"
                    )
                head = connection.execute(
                    "SELECT current_version, revision FROM "
                    "consent_scan_classification_heads WHERE tenant = ? "
                    "AND property_id = ? AND tracker_key = ?",
                    (tenant, property_ref, tracker_digest),
                ).fetchone()
                current_version = int(head["current_version"]) if head is not None else 0
                if current_version != expected:
                    raise ConsentScanConflict(
                        f"classification version is {current_version}, expected {expected}"
                    )
                body = {
                    "property_id": property_ref,
                    "tracker_key": tracker_digest,
                    "version": current_version + 1,
                    "classification": classification,
                    "registry_action": registry_action,
                    "tracker_id": tracker_ref,
                    "vendor_id": vendor_ref,
                    "purpose_ids": purposes,
                    "reviewer_sha256": reviewer,
                    "second_reviewer_sha256": second,
                    "evidence_sha256": evidence,
                    "report_id": report_ref,
                    "reviewed_at": now,
                    "valid_until": freshness,
                    "authority_expected_revision": authority_revision,
                }
                record_sha = _sha256(body)
                connection.execute(
                    "INSERT INTO consent_scan_classifications(tenant, property_id, "
                    "tracker_key, version, classification, registry_action, tracker_id, "
                    "vendor_id, purpose_ids_json, reviewer_sha256, "
                    "second_reviewer_sha256, evidence_sha256, report_id, reviewed_at, "
                    "valid_until, authority_expected_revision, record_sha256) VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        tenant,
                        property_ref,
                        tracker_digest,
                        body["version"],
                        classification,
                        registry_action,
                        tracker_ref,
                        vendor_ref,
                        _canonical(purposes).decode("ascii"),
                        reviewer,
                        second,
                        evidence,
                        report_ref,
                        now,
                        freshness,
                        authority_revision,
                        record_sha,
                    ),
                )
                if head is None:
                    connection.execute(
                        "INSERT INTO consent_scan_classification_heads(tenant, "
                        "property_id, tracker_key, current_version, revision) "
                        "VALUES (?, ?, ?, ?, 1)",
                        (tenant, property_ref, tracker_digest, body["version"]),
                    )
                else:
                    updated = connection.execute(
                        "UPDATE consent_scan_classification_heads SET current_version = ?, "
                        "revision = revision + 1 WHERE tenant = ? AND property_id = ? "
                        "AND tracker_key = ? AND current_version = ? AND revision = ?",
                        (
                            body["version"],
                            tenant,
                            property_ref,
                            tracker_digest,
                            current_version,
                            int(head["revision"]),
                        ),
                    )
                    if updated.rowcount != 1:
                        raise ConsentScanConflict("classification changed concurrently")
                result = {**body, "record_sha256": record_sha}
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="tracker.reviewed",
                    object_type="tracker",
                    object_id=tracker_digest,
                    payload={
                        "record_sha256": record_sha,
                        "version": body["version"],
                        "registry_action": registry_action,
                    },
                    now=now,
                )
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace="tracker.review",
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

    def list_reviews(
        self,
        tenant_id: str,
        property_id: str,
        tracker_key: str,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._require()
        tenant = _tenant_id(tenant_id)
        property_ref = _ref(property_id, "property_id")
        tracker_digest = _digest(tracker_key, "tracker_key")
        page_size = _limit(limit)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM consent_scan_classifications WHERE tenant = ? "
                "AND property_id = ? AND tracker_key = ? "
                "ORDER BY version DESC LIMIT ?",
                (tenant, property_ref, tracker_digest, page_size + 1),
            ).fetchall()
        return {
            "items": [self._classification_result(row) for row in rows[:page_size]],
            "truncated": len(rows) > page_size,
        }

    @staticmethod
    def _tracker_registration(review: Mapping[str, Any]) -> dict[str, Any]:
        """The native registration request, independent of finding/reviewer identity."""
        return {
            "tracker_id": review["tracker_id"],
            "kind": "web_tracker",
            "vendor_id": review["vendor_id"],
            "purpose_ids": sorted(review["purpose_ids"]),
            "status": review["registry_action"],
            "expected_revision": review["authority_expected_revision"],
        }

    def _bridge_reviews(self, connection, tenant, report, findings, now):
        """Refuse contradictory mappings across the complete report before effects."""
        reviews, registrations, review_groups = {}, {}, {}
        for finding in findings:
            tracker_key = finding["tracker_key"]
            if tracker_key not in reviews:
                reviews[tracker_key] = self._current_classification(
                    connection, tenant, report["property_id"], tracker_key
                )
            review = reviews[tracker_key]
            if (review is None or review["valid_until"] <= now
                    or review["registry_action"] == "observe_only"):
                continue
            registration = self._tracker_registration(review)
            previous = registrations.setdefault(review["tracker_id"], registration)
            if previous != registration:
                raise ConsentScanConflict(
                    "These reviewed findings assign different settings to the same tracker. "
                    "Review them consistently before applying. This attempt changed no trackers."
                )
            review_groups.setdefault(review["tracker_id"], set()).add(review["record_sha256"])
        return reviews, review_groups

    def bridge_report(
        self,
        tenant_id: str,
        report_id: str,
        *,
        idempotency_key: str,
        after_tracker_key: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Bridge only fresh reviewed mappings in one bounded report page."""

        self._require()
        if self._tracker_authority is None:
            raise ConsentScanBridgeError("consent tracker authority is unavailable")
        tenant = _tenant_id(tenant_id)
        report_ref = _ref(report_id, "report_id")
        after = (
            _digest(after_tracker_key, "after_tracker_key")
            if after_tracker_key is not None
            else None
        )
        page_size = _limit(limit)
        _raw_key, key_sha = _idempotency(idempotency_key)
        now = self._now()
        with self._connect() as connection:
            report = self._report_result(self._report_row(connection, tenant, report_ref))
            findings = sorted(
                (
                    item
                    for item in report["scanner_report"]["findings"]
                    if isinstance(item, dict)
                    and isinstance(item.get("tracker_key"), str)
                ),
                key=lambda item: item["tracker_key"],
            )
            reviews, review_groups = self._bridge_reviews(connection, tenant, report, findings, now)
            findings = [item for item in findings if after is None or item["tracker_key"] > after]
            page = findings[:page_size]
            reviewed: list[tuple[dict[str, Any], dict[str, Any]]] = []
            skipped_unknown = 0
            skipped_stale = 0
            skipped_observe_only = 0
            for finding in page:
                review = reviews[finding["tracker_key"]]
                if review is None:
                    skipped_unknown += 1
                elif review["valid_until"] <= now:
                    skipped_stale += 1
                elif review["registry_action"] == "observe_only":
                    skipped_observe_only += 1
                else:
                    reviewed.append((finding, review))
        request = {
            "report_id": report_ref,
            "report_sha256": report["scanner_report_sha256"],
            "after_tracker_key": after,
            "limit": page_size,
            "page_tracker_keys": [item["tracker_key"] for item in page],
            "review_sha256": [review["record_sha256"] for _finding, review in reviewed],
        }
        request_sha = _sha256(request)
        with self._connect() as connection:
            existing = self._idempotent_result(
                connection,
                tenant=tenant,
                namespace="report.bridge",
                key_sha256=key_sha,
                request_sha256=request_sha,
            )
            if existing is not None:
                return existing
        observations = []
        registered = 0
        registered_ids: set[str] = set()
        try:
            from .consent_preferences import TrackerObservation

            for finding, review in reviewed:
                registration = self._tracker_registration(review)
                if review["tracker_id"] not in registered_ids:
                    # Equivalent script/cookie findings share the native accepted
                    # request even across pages or a lost return; current equality
                    # is never substituted for that original idempotency receipt.
                    registry_idempotency = "scan-reviewed-registry-" + _sha256(
                        {"tenant": tenant, "report_id": report_ref,
                         "report_sha256": report["scanner_report_sha256"],
                         "review_sha256": sorted(review_groups[review["tracker_id"]]),
                         **registration}
                    )
                    self._tracker_authority.register_tracker(
                        tenant,
                        registration["tracker_id"],
                        registration["kind"],
                        registration["vendor_id"],
                        registration["purpose_ids"],
                        registration["status"],
                        expected_revision=registration["expected_revision"],
                        idempotency_key=registry_idempotency,
                    )
                    registered_ids.add(review["tracker_id"])
                    registered += 1
                if review["registry_action"] == "approved":
                    observations.append(
                        TrackerObservation(
                            report["property_id"],
                            review["tracker_id"],
                            _ref(finding["finding_id"], "finding_id"),
                            _digest(finding["evidence_sha256"], "evidence_sha256"),
                        )
                    )
            admission_result: Mapping[str, Any] | None = None
            if observations:
                admission_key = "scan-reviewed-admission-" + _sha256(request)
                admission_result = self._tracker_authority.admit_scan_observations(
                    tenant,
                    report_ref,
                    observations,
                    float(report["scanner_report"]["completed_at"]),
                    report["scanner_report_sha256"],
                    admission_key,
                )
        except Exception as exc:
            failure_time = self._now()
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    self._audit(
                        connection,
                        tenant=tenant,
                        event_type="report.bridge_failed",
                        object_type="report",
                        object_id=report_ref,
                        payload={
                            "error_code": _error_code(exc),
                            "page_sha256": _sha256(request),
                        },
                        now=failure_time,
                    )
                    connection.execute("COMMIT")
                except BaseException:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise
            raise ConsentScanBridgeError("reviewed tracker authority bridge failed") from exc
        page_truncated = len(findings) > page_size
        next_after = page[-1]["tracker_key"] if page_truncated and page else None
        result = {
            "schema": SCAN_INVENTORY_SCHEMA,
            "report_id": report_ref,
            "report_sha256": report["scanner_report_sha256"],
            "page_count": len(page),
            "reviewed_count": len(reviewed),
            "registered_count": registered,
            "admitted_count": len(observations),
            "skipped_unknown": skipped_unknown,
            "skipped_stale": skipped_stale,
            "skipped_observe_only": skipped_observe_only,
            "page_truncated": page_truncated,
            "next_after_tracker_key": next_after,
            "report_complete": report["complete"],
            "report_truncated": report["truncated"],
            "bridge_complete": not page_truncated,
            "review_coverage_complete": (
                not page_truncated and skipped_unknown == 0 and skipped_stale == 0
            ),
            "unknowns_auto_enforced": False,
            "admission_sha256": (
                _sha256(dict(admission_result)) if admission_result is not None else None
            ),
        }
        result_sha = _sha256(result)
        page_sha = _sha256(request)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._idempotent_result(
                    connection,
                    tenant=tenant,
                    namespace="report.bridge",
                    key_sha256=key_sha,
                    request_sha256=request_sha,
                )
                if existing is not None:
                    connection.execute("COMMIT")
                    return existing
                bridge = connection.execute(
                    "SELECT result_sha256 FROM consent_scan_bridges WHERE tenant = ? "
                    "AND report_id = ? AND page_sha256 = ?",
                    (tenant, report_ref, page_sha),
                ).fetchone()
                if bridge is not None and not text_equals(
                    str(bridge["result_sha256"]),
                    result_sha,
                ):
                    raise ConsentScanConflict("bridge page result changed")
                if bridge is None:
                    connection.execute(
                        "INSERT INTO consent_scan_bridges(tenant, report_id, "
                        "page_sha256, result_sha256, created_at) VALUES (?, ?, ?, ?, ?)",
                        (tenant, report_ref, page_sha, result_sha, now),
                    )
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="report.bridged",
                    object_type="report",
                    object_id=report_ref,
                    payload={"result_sha256": result_sha, **result},
                    now=now,
                )
                self._save_idempotency(
                    connection,
                    tenant=tenant,
                    namespace="report.bridge",
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
    def _audit_result(row: sqlite3.Row) -> dict[str, Any]:
        body = {
            "event_id": str(row["event_id"]),
            "event_type": str(row["event_type"]),
            "object_type": str(row["object_type"]),
            "object_id": str(row["object_id"]),
            "payload_sha256": str(row["payload_sha256"]),
            "previous_event_sha256": row["previous_event_sha256"],
            "created_at": float(row["created_at"]),
        }
        expected = _sha256(body)
        if not text_equals(expected, str(row["event_sha256"])):
            raise ConsentScanIntegrityError("stored scan audit event failed integrity")
        return {**body, "event_sha256": expected}

    def list_audit(self, tenant_id: str, *, limit: int = 100) -> dict[str, Any]:
        self._require()
        tenant = _tenant_id(tenant_id)
        page_size = _limit(limit)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM consent_scan_audit WHERE tenant = ? ORDER BY sequence DESC LIMIT ?",
                (tenant, page_size + 1),
            ).fetchall()
        return {
            "events": [self._audit_result(row) for row in rows[:page_size]],
            "truncated": len(rows) > page_size,
        }

    def retention_due(
        self,
        tenant_id: str,
        *,
        before: float,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List bounded operational evidence eligible for retention handling."""

        self._require()
        tenant = _tenant_id(tenant_id)
        cutoff = _timestamp(before, "before")
        page_size = _limit(limit)
        with self._connect() as connection:
            reports = connection.execute(
                "SELECT report_id, scanner_report_sha256, completed_at FROM "
                "consent_scan_reports WHERE tenant = ? AND completed_at < ? "
                "ORDER BY completed_at, report_id LIMIT ?",
                (tenant, cutoff, page_size + 1),
            ).fetchall()
            jobs = connection.execute(
                "SELECT job_id, status, updated_at FROM consent_scan_jobs WHERE "
                "tenant = ? AND status IN ('succeeded', 'dead_letter') AND updated_at < ? "
                "ORDER BY updated_at, job_id LIMIT ?",
                (tenant, cutoff, page_size + 1),
            ).fetchall()
        return {
            "reports": [dict(row) for row in reports[:page_size]],
            "reports_truncated": len(reports) > page_size,
            "jobs": [dict(row) for row in jobs[:page_size]],
            "jobs_truncated": len(jobs) > page_size,
            "reports_deleted": False,
            "action_required": "explicit_retention_purge_or_hold_review",
        }

    def purge_operational_data(
        self,
        tenant_id: str,
        *,
        before: float,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Delete bounded unreferenced reports/jobs and expired idempotency rows.

        First/last discovery evidence, reviewed reports, and bridged reports are
        retained.  Immutable reviews and audit events are never deleted here.
        """

        self._require()
        tenant = _tenant_id(tenant_id)
        cutoff = _timestamp(before, "before")
        page_size = _limit(limit)
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                report_rows = connection.execute(
                    "SELECT r.report_id, r.job_id FROM consent_scan_reports r WHERE "
                    "r.tenant = ? AND r.completed_at < ? AND NOT EXISTS (SELECT 1 "
                    "FROM consent_scan_classifications c WHERE c.tenant = r.tenant "
                    "AND c.report_id = r.report_id) AND NOT EXISTS (SELECT 1 FROM "
                    "consent_scan_bridges b WHERE b.tenant = r.tenant AND "
                    "b.report_id = r.report_id) AND NOT EXISTS (SELECT 1 FROM "
                    "consent_scan_discoveries d WHERE d.tenant = r.tenant AND "
                    "(d.first_report_id = r.report_id OR d.last_report_id = r.report_id)) "
                    "ORDER BY r.completed_at, r.report_id LIMIT ?",
                    (tenant, cutoff, page_size + 1),
                ).fetchall()
                selected_reports = report_rows[:page_size]
                for row in selected_reports:
                    connection.execute(
                        "DELETE FROM consent_scan_reports WHERE tenant = ? AND report_id = ?",
                        (tenant, row["report_id"]),
                    )
                    connection.execute(
                        "DELETE FROM consent_scan_jobs WHERE tenant = ? AND job_id = ? "
                        "AND status = 'succeeded'",
                        (tenant, row["job_id"]),
                    )
                dead_rows = connection.execute(
                    "SELECT job_id FROM consent_scan_jobs WHERE tenant = ? "
                    "AND status = 'dead_letter' AND updated_at < ? "
                    "ORDER BY updated_at, job_id LIMIT ?",
                    (tenant, cutoff, page_size + 1),
                ).fetchall()
                for row in dead_rows[:page_size]:
                    connection.execute(
                        "DELETE FROM consent_scan_jobs WHERE tenant = ? AND job_id = ?",
                        (tenant, row["job_id"]),
                    )
                idem_rows = connection.execute(
                    "SELECT namespace, key_sha256 FROM consent_scan_idempotency "
                    "WHERE tenant = ? AND created_at < ? ORDER BY created_at LIMIT ?",
                    (tenant, cutoff, page_size + 1),
                ).fetchall()
                for row in idem_rows[:page_size]:
                    connection.execute(
                        "DELETE FROM consent_scan_idempotency WHERE tenant = ? "
                        "AND namespace = ? AND key_sha256 = ?",
                        (tenant, row["namespace"], row["key_sha256"]),
                    )
                result = {
                    "reports_deleted": len(selected_reports),
                    "dead_letter_jobs_deleted": min(len(dead_rows), page_size),
                    "idempotency_deleted": min(len(idem_rows), page_size),
                    "reports_truncated": len(report_rows) > page_size,
                    "dead_letters_truncated": len(dead_rows) > page_size,
                    "idempotency_truncated": len(idem_rows) > page_size,
                    "classifications_deleted": 0,
                    "audit_events_deleted": 0,
                }
                self._audit(
                    connection,
                    tenant=tenant,
                    event_type="retention.purged",
                    object_type="retention",
                    object_id=self._new_id("CSI-RET"),
                    payload=result,
                    now=now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise


__all__ = [
    "ConsentScanBridgeError",
    "ConsentScanConflict",
    "ConsentScanIntegrityError",
    "ConsentScanInventory",
    "ConsentScanInventoryError",
    "ConsentScanLeaseError",
    "ConsentScanNotFound",
    "ConsentScanValidationError",
    "SCAN_INVENTORY_SCHEMA",
    "ScannerAuthority",
    "TrackerAuthority",
]
