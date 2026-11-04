"""Deployable, consent-gated agents for AI discovery sensor observations.

The agents consume bounded JSON events supplied by an approved network log
forwarder, browser extension, or OAuth audit-log adapter.  Raw source events
are normalized in memory and are never written to the durable spool.  Only the
closed :class:`~maverick.ai_discovery_sensor_clients.NormalizedSensorEvent`
shape is retained and sent to Lightwork's signed external ingress.

This is deliberately an *event consumer*, not packet capture, browser-history
collection, or an OAuth tenant crawler.  Deployments must provide and review a
source adapter, document consent, and state coverage limitations.  The module
does not claim that supplied events are complete for an enterprise estate.

Run ``python -m maverick.ai_discovery_sensor_agents --help`` for the standalone
JSONL runner.  It is disabled unless its own configuration contains both
``enable: true`` and ``consent_acknowledged: true``.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import sqlite3
import stat
import sys
import threading
import time
import urllib.parse
import uuid
import weakref
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Protocol

from .ai_discovery_sensor_clients import (
    DEFAULT_AI_HOSTS,
    DiscoverySensorClientError,
    NormalizedSensorEvent,
    SensorBinding,
    SignedDiscoverySensorClient,
    SignedObservationRequest,
    normalize_browser_oauth,
    normalize_identity_audit,
    normalize_network_egress,
    safe_request_digest,
)
from .file_lock import ensure_private_directory, ensure_private_file

_SPOOL_LOCKS_GUARD = threading.Lock()
_SPOOL_LOCKS: weakref.WeakValueDictionary[str, Any] = weakref.WeakValueDictionary()


def _shared_spool_lock(path: Path) -> Any:
    """Return one process lock for every handle to the same spool path."""

    key = os.path.normcase(str(path.resolve(strict=False)))
    with _SPOOL_LOCKS_GUARD:
        lock = _SPOOL_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _SPOOL_LOCKS[key] = lock
        return lock

AGENT_CONFIG_SCHEMA = "lightwork.ai-discovery-agent.v1"
_SOURCE_KINDS = frozenset(
    {"network_egress", "browser_extension", "oauth_grant", "identity_directory"}
)
_RAW_NETWORK_FIELDS = frozenset(
    {"hostname", "source_event_sha256", "observed_at", "context_codes"}
)
_RAW_BROWSER_FIELDS = frozenset(
    {
        "source_event_sha256",
        "observed_at",
        "provider_code",
        "ai_product_code",
        "context_codes",
    }
)
_NORMALIZED_FIELDS = frozenset(field.name for field in fields(NormalizedSensorEvent))
_PROHIBITED_PERSISTED_FIELDS = frozenset(
    {
        "access_token",
        "account_id",
        "body",
        "browser_history",
        "content",
        "cookie",
        "credential",
        "email",
        "hostname",
        "ip",
        "ip_address",
        "password",
        "prompt",
        "raw_event",
        "raw_url",
        "refresh_token",
        "secret",
        "token",
        "uri",
        "url",
        "user_id",
        "username",
    }
)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN_RE = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?\Z")
_MAX_CONFIG_BYTES = 128 * 1024
_MAX_SOURCE_LINE_BYTES = 64 * 1024
_MAX_GATEWAY_RESPONSE_BYTES = 64 * 1024
_MAX_LIMITATIONS = 32
_MAX_COMPLETED_DIGESTS = 100_000
_SAFE_CONTEXT_CODES = frozenset(
    {
        "admin_consent",
        "application",
        "approved_source",
        "corporate_network",
        "delegated",
        "interactive",
        "managed_device",
        "non_interactive",
        "remote_network",
        "service_principal",
        "test_fixture",
        "unmanaged_device",
        "user_consent",
    }
)
_SAFE_BROWSER_PRODUCTS = frozenset(
    {
        ("anthropic", "claude"),
        ("google", "gemini"),
        ("hugging_face", "hugging_face_hub"),
        ("microsoft", "copilot"),
        ("openai", "chatgpt"),
        ("openai", "openai_api"),
    }
)
_SAFE_ENVIRONMENT_CODES = frozenset(
    {"consenting_test", "development", "production", "sandbox", "staging", "test", "workforce"}
)
_DEPLOYMENT_TYPES = frozenset(
    {"embedded", "hosted_api", "managed_cloud", "saas", "self_hosted", "unknown"}
)


class DiscoverySensorAgentError(RuntimeError):
    """Base error for the standalone discovery sensor agent."""


class SensorAgentConfigError(DiscoverySensorAgentError, ValueError):
    """The standalone agent configuration is unsafe or malformed."""


class SensorAgentStateError(DiscoverySensorAgentError):
    """The private normalized-event spool is unavailable or corrupt."""


class SensorAgentTransportError(DiscoverySensorAgentError):
    """An observation could not be delivered to the configured gateway."""


class ObservationTransport(Protocol):
    """Transport boundary used by the HTTPS sender and local test estate."""

    def send(self, request: SignedObservationRequest) -> TransportResponse: ...


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    retry_after_seconds: float | None = None


@dataclass(frozen=True)
class AgentRunReport:
    source_kind: str
    source_scope_code: str
    consent_reference_sha256: str
    input_events: int
    normalized_events: int
    unmatched_events: int
    invalid_events: int
    duplicate_events: int
    delivered_events: int
    retry_scheduled_events: int
    auth_blocked_events: int
    permanent_failed_events: int
    pending_events: int
    blocked_events: int
    coverage_complete: bool
    coverage_limitations: tuple[str, ...]
    raw_source_persisted: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _closed_mapping(value: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SensorAgentConfigError(f"{label} must use the closed schema")
    return value


def _token(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _TOKEN_RE.fullmatch(text) or text in _PROHIBITED_PERSISTED_FIELDS:
        raise SensorAgentConfigError(f"{label} is invalid")
    return text


def _context_code(value: object) -> str:
    code = _token(value, "context code")
    if code not in _SAFE_CONTEXT_CODES:
        raise SensorAgentConfigError("context code is not in the reviewed safe taxonomy")
    return code


def _positive_int(value: object, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise SensorAgentConfigError(f"{label} must be between 1 and {maximum}")
    return value


def _positive_float(value: object, label: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SensorAgentConfigError(f"{label} must be a finite positive number")
    parsed = float(value)
    if not math.isfinite(parsed) or not 0 < parsed <= maximum:
        raise SensorAgentConfigError(f"{label} must be a finite positive number")
    return parsed


def _string(value: object, label: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str):
        raise SensorAgentConfigError(f"{label} must be a string")
    text = value.strip()
    if not text or len(text.encode("utf-8", "replace")) > maximum:
        raise SensorAgentConfigError(f"{label} is invalid")
    return text


@dataclass(frozen=True)
class SensorAgentConfig:
    """Closed configuration for one deployable sensor event consumer."""

    schema: str
    enable: bool
    consent_acknowledged: bool
    consent_reference: str
    source_kind: str
    source_scope_code: str
    coverage_limitations: tuple[str, ...]
    endpoint_url: str
    allow_loopback_http: bool
    key_file: Path
    spool_file: Path
    binding: SensorBinding
    environment_code: str
    deployment_type: str
    context_codes: tuple[str, ...]
    batch_size: int
    max_pending: int
    request_timeout_seconds: float
    lease_seconds: float
    base_backoff_seconds: float

    @classmethod
    def from_mapping(cls, value: object) -> SensorAgentConfig:
        fields = frozenset(
            {
                "schema",
                "enable",
                "consent_acknowledged",
                "consent_reference",
                "source_kind",
                "source_scope_code",
                "coverage_limitations",
                "endpoint_url",
                "allow_loopback_http",
                "key_file",
                "spool_file",
                "binding",
                "environment_code",
                "deployment_type",
                "context_codes",
                "batch_size",
                "max_pending",
                "request_timeout_seconds",
                "lease_seconds",
                "base_backoff_seconds",
            }
        )
        row = _closed_mapping(value, fields, "sensor agent configuration")
        if row["schema"] != AGENT_CONFIG_SCHEMA:
            raise SensorAgentConfigError("sensor agent schema is unsupported")
        if not isinstance(row["enable"], bool) or not isinstance(
            row["consent_acknowledged"], bool
        ):
            raise SensorAgentConfigError("enable and consent_acknowledged must be booleans")
        if not isinstance(row["allow_loopback_http"], bool):
            raise SensorAgentConfigError("allow_loopback_http must be a boolean")
        source_kind = _token(row["source_kind"], "source_kind")
        if source_kind not in _SOURCE_KINDS:
            raise SensorAgentConfigError("source_kind is unsupported")
        limitations = row["coverage_limitations"]
        if (
            not isinstance(limitations, list)
            or not 1 <= len(limitations) <= _MAX_LIMITATIONS
            or any(not isinstance(item, str) for item in limitations)
        ):
            raise SensorAgentConfigError("coverage_limitations must be a non-empty bounded list")
        normalized_limitations = tuple(
            _token(item, "coverage limitation") for item in limitations
        )
        if len(set(normalized_limitations)) != len(normalized_limitations):
            raise SensorAgentConfigError("coverage_limitations must not contain duplicates")
        contexts = row["context_codes"]
        if not isinstance(contexts, list) or len(contexts) > 16:
            raise SensorAgentConfigError("context_codes must be a bounded list")
        normalized_contexts = tuple(_context_code(item) for item in contexts)
        if len(set(normalized_contexts)) != len(normalized_contexts):
            raise SensorAgentConfigError("context_codes must not contain duplicates")
        binding_row = _closed_mapping(
            row["binding"],
            frozenset(
                {"tenant_ref", "agent_id", "sensor_id", "sensor_revision", "config_sha256"}
            ),
            "sensor binding",
        )
        binding = SensorBinding(
            tenant_ref=_string(binding_row["tenant_ref"], "tenant_ref", maximum=256),
            agent_id=_string(binding_row["agent_id"], "agent_id", maximum=128),
            sensor_id=_string(binding_row["sensor_id"], "sensor_id", maximum=64),
            sensor_revision=_positive_int(
                binding_row["sensor_revision"], "sensor_revision", 2**31 - 1
            ),
            config_sha256=_string(
                binding_row["config_sha256"], "config_sha256", maximum=71
            ),
        )
        # Reuse the exact client validator before the config is admitted.
        SignedDiscoverySensorClient(binding, signer=lambda _message: b"0" * 64)
        result = cls(
            schema=AGENT_CONFIG_SCHEMA,
            enable=row["enable"],
            consent_acknowledged=row["consent_acknowledged"],
            consent_reference=_string(
                row["consent_reference"], "consent_reference", maximum=512
            ),
            source_kind=source_kind,
            source_scope_code=_token(row["source_scope_code"], "source_scope_code"),
            coverage_limitations=normalized_limitations,
            endpoint_url=_string(row["endpoint_url"], "endpoint_url", maximum=2048),
            allow_loopback_http=row["allow_loopback_http"],
            key_file=Path(_string(row["key_file"], "key_file", maximum=4096)).expanduser(),
            spool_file=Path(_string(row["spool_file"], "spool_file", maximum=4096)).expanduser(),
            binding=binding,
            environment_code=_token(row["environment_code"], "environment_code"),
            deployment_type=_token(row["deployment_type"], "deployment_type"),
            context_codes=tuple(sorted(normalized_contexts)),
            batch_size=_positive_int(row["batch_size"], "batch_size", 500),
            max_pending=_positive_int(row["max_pending"], "max_pending", 1_000_000),
            request_timeout_seconds=_positive_float(
                row["request_timeout_seconds"], "request_timeout_seconds", 60.0
            ),
            lease_seconds=_positive_float(row["lease_seconds"], "lease_seconds", 900.0),
            base_backoff_seconds=_positive_float(
                row["base_backoff_seconds"], "base_backoff_seconds", 3600.0
            ),
        )
        # Endpoint validation is centralized in the concrete transport.
        HTTPSObservationTransport.validate_endpoint(
            result.endpoint_url, allow_loopback_http=result.allow_loopback_http
        )
        if result.environment_code not in _SAFE_ENVIRONMENT_CODES:
            raise SensorAgentConfigError(
                "environment_code is not in the reviewed safe taxonomy"
            )
        if result.deployment_type not in _DEPLOYMENT_TYPES:
            raise SensorAgentConfigError("deployment_type is unsupported")
        return result

    def require_authorized(self) -> None:
        if not self.enable:
            raise SensorAgentConfigError("sensor agent is disabled; set enable to true")
        if not self.consent_acknowledged:
            raise SensorAgentConfigError(
                "sensor agent requires explicit consenting-estate acknowledgement"
            )

    @property
    def consent_reference_sha256(self) -> str:
        return hashlib.sha256(self.consent_reference.encode("utf-8")).hexdigest()


def load_agent_config(path: str | Path) -> SensorAgentConfig:
    config_path = Path(path).expanduser()
    try:
        if config_path.stat().st_size > _MAX_CONFIG_BYTES:
            raise SensorAgentConfigError("sensor agent configuration exceeds the size limit")
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except SensorAgentConfigError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise SensorAgentConfigError("sensor agent configuration is unreadable") from exc
    return SensorAgentConfig.from_mapping(payload)


class ReloadingEd25519KeyFileSigner:
    """Read an owner-restricted PKCS8 PEM key on every signature.

    Atomic key-file replacement therefore performs rotation without restarting
    the process.  Key generation and production custody remain operator-owned;
    this class never creates, exports, or logs private material.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()

    def __call__(self, message: bytes) -> bytes:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        try:
            ensure_private_file(self.path, 0o600)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            descriptor = os.open(str(self.path), flags)
            try:
                opened = os.fstat(descriptor)
                visible = self.path.lstat()
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or not stat.S_ISREG(visible.st_mode)
                    or opened.st_nlink != 1
                    or visible.st_nlink != 1
                    or (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino)
                ):
                    raise PermissionError("key file identity changed")
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    pem = stream.read(64 * 1024 + 1)
                if len(pem) > 64 * 1024:
                    raise ValueError("key file exceeds the size limit")
            finally:
                os.close(descriptor)
            key = serialization.load_pem_private_key(pem, password=None)
        except (OSError, PermissionError, TypeError, ValueError) as exc:
            raise DiscoverySensorClientError("Ed25519 key file is unavailable") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise DiscoverySensorClientError("key file is not an Ed25519 private key")
        return key.sign(message)


def _canonical_event(event: NormalizedSensorEvent) -> str:
    row = asdict(event)
    row["context_codes"] = list(event.context_codes)
    if set(row) != _NORMALIZED_FIELDS or _PROHIBITED_PERSISTED_FIELDS.intersection(row):
        raise SensorAgentStateError("normalized event violates the private spool schema")
    try:
        encoded = json.dumps(
            row, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise SensorAgentStateError("normalized event is not finite JSON") from exc
    if len(encoded.encode("utf-8")) > _MAX_SOURCE_LINE_BYTES:
        raise SensorAgentStateError("normalized event exceeds the spool item limit")
    return encoded


def _decode_event(payload: str) -> NormalizedSensorEvent:
    try:
        row = json.loads(payload)
        if not isinstance(row, dict) or set(row) != _NORMALIZED_FIELDS:
            raise ValueError("closed schema mismatch")
        contexts = row.pop("context_codes")
        if not isinstance(contexts, list):
            raise ValueError("context_codes is not a list")
        event = NormalizedSensorEvent(context_codes=tuple(contexts), **row)
        # Validate the whole shape through the existing signed client helpers
        # later.  This digest check detects obvious spool corruption now.
        if not _DIGEST_RE.fullmatch(str(event.event_sha256)):
            raise ValueError("event digest is invalid")
        return event
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SensorAgentStateError("normalized event spool is corrupt") from exc


@dataclass(frozen=True)
class _LeasedEvent:
    event: NormalizedSensorEvent
    attempts: int


class DiscoverySensorSpool:
    """Private SQLite spool with expiring leases and digest idempotency."""

    def __init__(self, path: str | Path, *, max_pending: int = 100_000) -> None:
        # Bind a relative configuration path to the startup directory once.
        # Re-resolving it implicitly on every SQLite open after ``chdir`` can
        # select a different database while still holding the original path's
        # process lock.
        expanded = Path(path).expanduser()
        # Make the configured location independent of later ``chdir`` calls,
        # but preserve every on-disk path component for the private-directory
        # checks below. ``Path.resolve`` would erase a symlink/junction parent
        # before ``ensure_private_directory`` could reject that alias.
        self.path = Path(os.path.abspath(os.fspath(expanded)))
        self.max_pending = _positive_int(max_pending, "max_pending", 1_000_000)
        self._lock = _shared_spool_lock(self.path)
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.path), timeout=30.0, isolation_level=None, check_same_thread=False
        )
        try:
            connection.row_factory = sqlite3.Row
            # Arm the busy handler before any connection-local pragma. Journal
            # mode is a database-wide setting and must not be rewritten by
            # every hot-path connection: concurrent workers would race that
            # pragma and then starve at BEGIN IMMEDIATE.
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
        except BaseException:
            connection.close()
            raise
        return connection

    @contextmanager
    def _serialized_connection(self):
        """Serialize same-process handles while SQLite coordinates processes."""

        with self._lock:
            connection = None
            try:
                connection = self._connect()
                yield connection
            except SensorAgentStateError:
                raise
            except sqlite3.Error as exc:
                # SQLite's busy handler is the bounded inter-process wait. If
                # another process outlives it, preserve the spool API contract
                # so the CLI reports an operational failure without leaking a
                # raw driver traceback.
                raise SensorAgentStateError(
                    "normalized event spool operation failed"
                ) from exc
            finally:
                if connection is not None:
                    connection.close()

    def _initialize(self) -> None:
        try:
            with self._serialized_connection() as connection:
                # DELETE is intentional for the privacy-minimized spool: unlike
                # WAL, acknowledged payload pages are not retained in a sidecar.
                # Set it once during serialized initialization, never on each
                # concurrent enqueue/lease/ack connection.
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS pending_events (
                        event_sha256 TEXT PRIMARY KEY,
                        payload_json TEXT NOT NULL,
                        state TEXT NOT NULL CHECK(state IN ('queued','leased','auth_blocked')),
                        attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                        next_attempt_at REAL NOT NULL DEFAULT 0,
                        lease_owner TEXT,
                        lease_until REAL,
                        last_status INTEGER,
                        created_at REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS completed_events (
                        event_sha256 TEXT PRIMARY KEY,
                        completed_at REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS pending_ready_idx
                    ON pending_events(state, next_attempt_at, lease_until, created_at);
                    """
                )
            ensure_private_file(self.path, 0o600)
        except (OSError, PermissionError, sqlite3.Error) as exc:
            raise SensorAgentStateError("normalized event spool is unavailable") from exc

    def enqueue(self, event: NormalizedSensorEvent, *, now: float | None = None) -> bool:
        payload = _canonical_event(event)
        event_digest = str(event.event_sha256).lower()
        if not _DIGEST_RE.fullmatch(event_digest):
            raise SensorAgentStateError("event_sha256 is invalid")
        moment = time.time() if now is None else float(now)
        with self._serialized_connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM completed_events WHERE event_sha256 = ?", (event_digest,)
                ).fetchone():
                    connection.execute("COMMIT")
                    return False
                existing = connection.execute(
                    "SELECT payload_json FROM pending_events WHERE event_sha256 = ?",
                    (event_digest,),
                ).fetchone()
                if existing is not None:
                    if existing["payload_json"] != payload:
                        raise SensorAgentStateError(
                            "event digest conflicts with queued payload"
                        )
                    connection.execute("COMMIT")
                    return False
                count = connection.execute("SELECT COUNT(*) FROM pending_events").fetchone()[0]
                if count >= self.max_pending:
                    raise SensorAgentStateError("normalized event spool is full")
                connection.execute(
                    """INSERT INTO pending_events(
                           event_sha256,payload_json,state,attempts,next_attempt_at,created_at
                       ) VALUES(?,?,'queued',0,0,?)""",
                    (event_digest, payload, moment),
                )
                connection.execute("COMMIT")
                return True
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def lease(
        self,
        worker_id: str,
        *,
        limit: int,
        lease_seconds: float,
        now: float | None = None,
    ) -> tuple[_LeasedEvent, ...]:
        worker = _token(worker_id, "worker_id")
        batch = _positive_int(limit, "lease limit", 500)
        lease_for = _positive_float(lease_seconds, "lease_seconds", 900.0)
        moment = time.time() if now is None else float(now)
        with self._serialized_connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    """SELECT event_sha256,payload_json,attempts
                       FROM pending_events
                       WHERE (state = 'queued' AND next_attempt_at <= ?)
                          OR (state = 'leased' AND lease_until <= ?)
                       ORDER BY created_at,event_sha256 LIMIT ?""",
                    (moment, moment, batch),
                ).fetchall()
                # Validate every selected payload before publishing leases. A
                # corrupt row must roll back the whole selection, not become a
                # durable poison lease that blocks healthy rows until expiry.
                decoded: list[tuple[str, _LeasedEvent]] = []
                for row in rows:
                    digest = str(row["event_sha256"])
                    event = _decode_event(row["payload_json"])
                    if digest != event.event_sha256:
                        raise SensorAgentStateError(
                            "normalized event spool is corrupt: payload digest mismatch"
                        )
                    decoded.append((digest, _LeasedEvent(event, int(row["attempts"]))))
                digests = [digest for digest, _item in decoded]
                leased_events = tuple(item for _digest, item in decoded)
                for digest in digests:
                    connection.execute(
                        """UPDATE pending_events
                           SET state='leased',lease_owner=?,lease_until=?
                           WHERE event_sha256=?""",
                        (worker, moment + lease_for, digest),
                    )
                connection.execute("COMMIT")
                return leased_events
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def acknowledge(self, event_sha256: str, worker_id: str, *, now: float | None = None) -> None:
        self._finish_lease(event_sha256, worker_id, outcome="complete", now=now)

    def retry(
        self,
        event_sha256: str,
        worker_id: str,
        *,
        status_code: int | None,
        retry_at: float,
    ) -> None:
        self._finish_lease(
            event_sha256,
            worker_id,
            outcome="retry",
            status_code=status_code,
            retry_at=retry_at,
        )

    def block_auth(
        self, event_sha256: str, worker_id: str, *, status_code: int
    ) -> None:
        self._finish_lease(
            event_sha256,
            worker_id,
            outcome="auth_blocked",
            status_code=status_code,
        )

    def discard_permanent(
        self, event_sha256: str, worker_id: str, *, status_code: int
    ) -> None:
        self._finish_lease(
            event_sha256,
            worker_id,
            outcome="complete",
            status_code=status_code,
        )

    def _finish_lease(
        self,
        event_sha256: str,
        worker_id: str,
        *,
        outcome: str,
        status_code: int | None = None,
        retry_at: float | None = None,
        now: float | None = None,
    ) -> None:
        digest = str(event_sha256).lower()
        worker = _token(worker_id, "worker_id")
        moment = time.time() if now is None else float(now)
        with self._serialized_connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT state,lease_owner FROM pending_events WHERE event_sha256=?",
                    (digest,),
                ).fetchone()
                if row is None or row["state"] != "leased" or row["lease_owner"] != worker:
                    raise SensorAgentStateError(
                        "event lease is no longer owned by this worker"
                    )
                if outcome == "complete":
                    connection.execute(
                        "INSERT OR REPLACE INTO completed_events(event_sha256,completed_at) "
                        "VALUES(?,?)",
                        (digest, moment),
                    )
                    connection.execute(
                        "DELETE FROM pending_events WHERE event_sha256=?", (digest,)
                    )
                    overflow = connection.execute(
                        "SELECT COUNT(*) FROM completed_events"
                    ).fetchone()[0] - _MAX_COMPLETED_DIGESTS
                    if overflow > 0:
                        connection.execute(
                            """DELETE FROM completed_events WHERE event_sha256 IN (
                                   SELECT event_sha256 FROM completed_events
                                   ORDER BY completed_at,event_sha256 LIMIT ?
                               )""",
                            (overflow,),
                        )
                elif outcome == "retry":
                    if retry_at is None or not math.isfinite(float(retry_at)):
                        raise SensorAgentStateError("retry time is invalid")
                    connection.execute(
                        """UPDATE pending_events SET state='queued',attempts=attempts+1,
                           next_attempt_at=?,lease_owner=NULL,lease_until=NULL,last_status=?
                           WHERE event_sha256=?""",
                        (float(retry_at), status_code, digest),
                    )
                elif outcome == "auth_blocked":
                    connection.execute(
                        """UPDATE pending_events SET state='auth_blocked',attempts=attempts+1,
                           lease_owner=NULL,lease_until=NULL,last_status=?
                           WHERE event_sha256=?""",
                        (status_code, digest),
                    )
                else:  # pragma: no cover - private contract
                    raise AssertionError("unsupported lease outcome")
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def unblock_auth(self) -> int:
        with self._serialized_connection() as connection:
            cursor = connection.execute(
                """UPDATE pending_events SET state='queued',next_attempt_at=0,
                   lease_owner=NULL,lease_until=NULL WHERE state='auth_blocked'"""
            )
            return int(cursor.rowcount)

    def counts(self) -> dict[str, int]:
        with self._serialized_connection() as connection:
            rows = connection.execute(
                "SELECT state,COUNT(*) AS count FROM pending_events GROUP BY state"
            ).fetchall()
            counts = {"queued": 0, "leased": 0, "auth_blocked": 0}
            counts.update({str(row["state"]): int(row["count"]) for row in rows})
            counts["pending"] = counts["queued"] + counts["leased"]
            counts["completed"] = int(
                connection.execute("SELECT COUNT(*) FROM completed_events").fetchone()[0]
            )
            return counts

    def privacy_posture(self) -> dict[str, Any]:
        """Inspect every retained payload and report, never return, its values."""

        with self._serialized_connection() as connection:
            rows = connection.execute("SELECT payload_json FROM pending_events").fetchall()
        retained_fields: set[str] = set()
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, ValueError) as exc:
                raise SensorAgentStateError("normalized event spool is corrupt") from exc
            if not isinstance(payload, dict):
                raise SensorAgentStateError("normalized event spool is corrupt")
            retained_fields.update(str(key).lower() for key in payload)
        prohibited = tuple(sorted(retained_fields.intersection(_PROHIBITED_PERSISTED_FIELDS)))
        return {
            "raw_source_persisted": False,
            "pending_payloads_inspected": len(rows),
            "retained_fields": tuple(sorted(retained_fields)),
            "prohibited_fields_found": prohibited,
            "privacy_check_passed": not prohibited,
        }


class HTTPSObservationTransport:
    """Fixed-origin, redirect-free HTTPS transport for signed observations."""

    def __init__(
        self,
        endpoint_url: str,
        *,
        timeout_seconds: float = 10.0,
        allow_loopback_http: bool = False,
        sender: Callable[..., Any] | None = None,
    ) -> None:
        self._origin = self.validate_endpoint(
            endpoint_url, allow_loopback_http=allow_loopback_http
        )
        self._timeout = _positive_float(timeout_seconds, "timeout_seconds", 60.0)
        self._sender = sender

    @staticmethod
    def validate_endpoint(endpoint_url: str, *, allow_loopback_http: bool) -> str:
        try:
            parsed = urllib.parse.urlsplit(endpoint_url)
            port = parsed.port
        except (TypeError, ValueError) as exc:
            raise SensorAgentConfigError("endpoint_url is invalid") from exc
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or not parsed.hostname
        ):
            raise SensorAgentConfigError("endpoint_url must be a credential-free origin")
        hostname = parsed.hostname.rstrip(".").lower()
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise SensorAgentConfigError("endpoint_url hostname is invalid") from exc
        loopback = hostname == "localhost"
        try:
            loopback = loopback or ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            pass
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and allow_loopback_http and loopback
        ):
            raise SensorAgentConfigError(
                "endpoint_url must use HTTPS; HTTP is limited to explicit loopback tests"
            )
        if port is not None and not 1 <= port <= 65535:
            raise SensorAgentConfigError("endpoint_url port is invalid")
        netloc = f"[{hostname}]" if ":" in hostname else hostname
        if port is not None:
            netloc += f":{port}"
        return f"{parsed.scheme}://{netloc}"

    @staticmethod
    def _header(headers: object, name: str) -> object | None:
        if not isinstance(headers, Mapping):
            return None
        wanted = name.lower()
        for key, value in headers.items():
            if str(key).lower() == wanted:
                return value
        return None

    @classmethod
    def _consume_response(cls, response: object) -> TransportResponse:
        status = getattr(response, "status_code", None)
        if isinstance(status, bool) or not isinstance(status, int):
            raise SensorAgentTransportError(
                "sensor gateway returned an invalid response"
            )
        headers = getattr(response, "headers", {})
        raw_length = cls._header(headers, "Content-Length")
        declared_length: int | None = None
        if raw_length is not None:
            text_length = str(raw_length).strip()
            if re.fullmatch(r"[0-9]+", text_length) is None:
                raise SensorAgentTransportError(
                    "sensor gateway returned an invalid Content-Length"
                )
            declared_length = int(text_length)
            if declared_length > _MAX_GATEWAY_RESPONSE_BYTES:
                raise SensorAgentTransportError(
                    "sensor gateway response exceeds its byte bound"
                )

        iterator = getattr(response, "iter_bytes", None)
        if callable(iterator):
            received = 0
            for chunk in iterator():
                if not isinstance(chunk, bytes):
                    raise SensorAgentTransportError(
                        "sensor gateway returned an invalid response body"
                    )
                received += len(chunk)
                if received > _MAX_GATEWAY_RESPONSE_BYTES:
                    raise SensorAgentTransportError(
                        "sensor gateway response exceeds its byte bound"
                    )
        elif declared_length not in {None, 0}:
            # A production httpx streaming response always exposes iter_bytes.
            # A custom sender that declares a body but cannot stream it cannot
            # prove the response remained inside the bound, so fail closed.
            raise SensorAgentTransportError(
                "sensor gateway response body is not streamable"
            )

        retry_after: float | None = None
        raw_retry = cls._header(headers, "Retry-After")
        if raw_retry is not None:
            try:
                parsed_retry = float(raw_retry)
                if math.isfinite(parsed_retry) and 0 <= parsed_retry <= 3600:
                    retry_after = parsed_retry
            except (TypeError, ValueError):
                pass
        return TransportResponse(
            status_code=status,
            retry_after_seconds=retry_after,
        )

    def send(self, request: SignedObservationRequest) -> TransportResponse:
        try:
            if self._sender is None:
                import httpx

                with httpx.stream(
                    "POST",
                    self._origin + request.path,
                    content=request.body,
                    headers=dict(request.headers),
                    timeout=self._timeout,
                    follow_redirects=False,
                ) as response:
                    return self._consume_response(response)
            response = self._sender(
                self._origin + request.path,
                content=request.body,
                headers=dict(request.headers),
                timeout=self._timeout,
                follow_redirects=False,
            )
            try:
                return self._consume_response(response)
            finally:
                close = getattr(response, "close", None)
                if callable(close):
                    close()
        except SensorAgentTransportError:
            raise
        except Exception as exc:
            raise SensorAgentTransportError("sensor gateway transport failed") from exc


class DiscoverySensorAgent:
    """Normalize source events, durably queue closed data, and deliver it."""

    def __init__(
        self,
        config: SensorAgentConfig,
        *,
        signer: Callable[[bytes], bytes] | None = None,
        transport: ObservationTransport | None = None,
        clock: Callable[[], float] | None = None,
        nonce_factory: Callable[[], str] | None = None,
        worker_id: str | None = None,
        ai_hosts: Mapping[str, tuple[str, str, str]] = DEFAULT_AI_HOSTS,
    ) -> None:
        if not isinstance(config, SensorAgentConfig):
            raise TypeError("config must be a SensorAgentConfig")
        config.require_authorized()
        self.config = config
        self._clock = clock or time.time
        self._spool = DiscoverySensorSpool(config.spool_file, max_pending=config.max_pending)
        self._signer = signer or ReloadingEd25519KeyFileSigner(config.key_file)
        self._client = SignedDiscoverySensorClient(
            config.binding,
            signer=self._signer,
            clock=self._clock,
            nonce_factory=nonce_factory,
        )
        self._transport = transport or HTTPSObservationTransport(
            config.endpoint_url,
            timeout_seconds=config.request_timeout_seconds,
            allow_loopback_http=config.allow_loopback_http,
        )
        worker = worker_id or "agent-" + uuid.uuid4().hex[:16]
        self._worker_id = _token(worker, "worker_id")
        self._ai_hosts = ai_hosts

    @property
    def spool(self) -> DiscoverySensorSpool:
        return self._spool

    def normalize(self, raw_event: object) -> NormalizedSensorEvent | None:
        if self.config.source_kind == "identity_directory":
            # Identity-provider records often carry users, client IDs, and
            # provider payloads. They may only enter through the reviewed
            # adapters' closed NormalizedSensorEvent shape below, never the
            # generic JSONL/raw-event path.
            raise SensorAgentConfigError(
                "identity-directory records require a reviewed identity audit adapter"
            )
        fields = (
            _RAW_NETWORK_FIELDS
            if self.config.source_kind == "network_egress"
            else _RAW_BROWSER_FIELDS
        )
        try:
            row = _closed_mapping(raw_event, fields, "raw source event")
            contexts = row["context_codes"]
            if not isinstance(contexts, list):
                raise SensorAgentConfigError("context_codes must be a list")
            raw_contexts = tuple(_context_code(item) for item in contexts)
            combined_contexts = tuple(self.config.context_codes) + raw_contexts
            if self.config.source_kind == "network_egress":
                return normalize_network_egress(
                    hostname=row["hostname"],
                    source_event_sha256=row["source_event_sha256"],
                    observed_at=row["observed_at"],
                    environment_code=self.config.environment_code,
                    deployment_type=self.config.deployment_type,
                    context_codes=combined_contexts,
                    ai_hosts=self._ai_hosts,
                )
            provider_code = _token(row["provider_code"], "provider_code")
            product_code = _token(row["ai_product_code"], "ai_product_code")
            if (provider_code, product_code) not in _SAFE_BROWSER_PRODUCTS:
                raise SensorAgentConfigError(
                    "browser/OAuth product is not in the reviewed safe taxonomy"
                )
            return normalize_browser_oauth(
                source_event_sha256=row["source_event_sha256"],
                observed_at=row["observed_at"],
                provider_code=provider_code,
                ai_product_code=product_code,
                environment_code=self.config.environment_code,
                oauth_grant=self.config.source_kind == "oauth_grant",
                deployment_type=self.config.deployment_type,
                context_codes=combined_contexts,
            )
        except DiscoverySensorClientError as exc:
            raise SensorAgentConfigError("raw source event failed privacy normalization") from exc

    def ingest_normalized(self, events: Iterable[NormalizedSensorEvent | None]) -> dict[str, int]:
        """Queue reviewed identity-audit events without ever retaining raw input.

        Provider adapters normalize their source logs in memory and call this
        method. The existing private spool, key-rotation signer, and delivery
        transport are reused unchanged; only the closed event shape can cross
        this boundary.
        """

        if self.config.source_kind != "identity_directory":
            raise SensorAgentConfigError(
                "normalized identity-audit events require source_kind identity_directory"
            )
        counters = {
            "input": 0,
            "normalized": 0,
            "unmatched": 0,
            "invalid": 0,
            "duplicate": 0,
        }
        for event in events:
            counters["input"] += 1
            if event is None:
                counters["unmatched"] += 1
                continue
            try:
                if not isinstance(event, NormalizedSensorEvent):
                    raise SensorAgentConfigError("identity adapter did not return a normalized event")
                if event.domain_category != "identity_directory":
                    raise SensorAgentConfigError("identity event has an invalid domain category")
                if event.environment_code != self.config.environment_code:
                    raise SensorAgentConfigError("identity event environment does not match sensor configuration")
                if event.deployment_type != self.config.deployment_type:
                    raise SensorAgentConfigError("identity event deployment does not match sensor configuration")
                if event.ai_service_code != event.provider_code or (
                    event.provider_code,
                    event.ai_product_code,
                ) not in _SAFE_BROWSER_PRODUCTS:
                    raise SensorAgentConfigError(
                        "identity event product is not in the reviewed safe taxonomy"
                    )
                contexts = tuple(_context_code(item) for item in event.context_codes)
                if len(set(contexts)) != len(contexts):
                    raise SensorAgentConfigError("identity event contexts contain duplicates")
                if not set(self.config.context_codes).issubset(contexts):
                    raise SensorAgentConfigError(
                        "identity event omits required sensor context codes"
                    )
                checked = normalize_identity_audit(
                    source_event_sha256=event.event_sha256,
                    observed_at=event.observed_at,
                    ai_service_code=event.ai_service_code,
                    ai_product_code=event.ai_product_code,
                    provider_code=event.provider_code,
                    environment_code=event.environment_code,
                    deployment_type=event.deployment_type,
                    context_codes=contexts,
                )
                if checked != event:
                    raise SensorAgentConfigError("identity event failed closed normalization")
                inserted = self._spool.enqueue(checked, now=self._clock())
            except (DiscoverySensorClientError, SensorAgentConfigError, TypeError, ValueError):
                counters["invalid"] += 1
                continue
            counters["normalized"] += int(inserted)
            counters["duplicate"] += int(not inserted)
        return counters

    def ingest(self, raw_events: Iterable[object]) -> dict[str, int]:
        counters = {"input": 0, "normalized": 0, "unmatched": 0, "invalid": 0, "duplicate": 0}
        for raw_event in raw_events:
            counters["input"] += 1
            try:
                event = self.normalize(raw_event)
            except (SensorAgentConfigError, TypeError, ValueError):
                counters["invalid"] += 1
                continue
            if event is None:
                counters["unmatched"] += 1
                continue
            try:
                inserted = self._spool.enqueue(event, now=self._clock())
            except SensorAgentStateError:
                raise
            counters["normalized"] += int(inserted)
            counters["duplicate"] += int(not inserted)
        return counters

    def deliver_once(self) -> dict[str, int]:
        counters = {"delivered": 0, "retry_scheduled": 0, "auth_blocked": 0, "permanent_failed": 0}
        now = float(self._clock())
        leased = self._spool.lease(
            self._worker_id,
            limit=self.config.batch_size,
            lease_seconds=self.config.lease_seconds,
            now=now,
        )
        for item in leased:
            event_digest = item.event.event_sha256
            try:
                request = self._client.build(item.event)
                # Calculate the safe digest before I/O so callers can instrument
                # delivery without body or signature logging.
                safe_request_digest(request)
                response = self._transport.send(request)
            except (DiscoverySensorClientError, SensorAgentTransportError):
                retry_at = now + self._backoff(item.attempts)
                self._spool.retry(
                    event_digest,
                    self._worker_id,
                    status_code=None,
                    retry_at=retry_at,
                )
                counters["retry_scheduled"] += 1
                continue
            status = response.status_code
            if 200 <= status < 300:
                self._spool.acknowledge(event_digest, self._worker_id, now=now)
                counters["delivered"] += 1
            elif status in {401, 403, 409}:
                # Authentication, revocation, or sensor binding/configuration
                # authority needs operator action.  Preserve the normalized
                # observation for explicit unblock after rotation/re-approval.
                self._spool.block_auth(event_digest, self._worker_id, status_code=status)
                counters["auth_blocked"] += 1
            elif status in {408, 425, 429} or 500 <= status < 600:
                delay = response.retry_after_seconds
                retry_at = now + (delay if delay is not None else self._backoff(item.attempts))
                self._spool.retry(
                    event_digest,
                    self._worker_id,
                    status_code=status,
                    retry_at=retry_at,
                )
                counters["retry_scheduled"] += 1
            else:
                # A schema/binding refusal will not heal by retry.  Retain only
                # its digest in completed_events to prevent an infinite poison
                # loop; the raw or normalized body is never copied to logs.
                self._spool.discard_permanent(
                    event_digest, self._worker_id, status_code=status
                )
                counters["permanent_failed"] += 1
        return counters

    def _backoff(self, attempts: int) -> float:
        exponent = min(max(int(attempts), 0), 10)
        return min(self.config.base_backoff_seconds * (2**exponent), 3600.0)

    def run_once(self, raw_events: Iterable[object]) -> AgentRunReport:
        ingested = self.ingest(raw_events)
        delivered = self.deliver_once()
        counts = self._spool.counts()
        return AgentRunReport(
            source_kind=self.config.source_kind,
            source_scope_code=self.config.source_scope_code,
            consent_reference_sha256=self.config.consent_reference_sha256,
            input_events=ingested["input"],
            normalized_events=ingested["normalized"],
            unmatched_events=ingested["unmatched"],
            invalid_events=ingested["invalid"],
            duplicate_events=ingested["duplicate"],
            delivered_events=delivered["delivered"],
            retry_scheduled_events=delivered["retry_scheduled"],
            auth_blocked_events=delivered["auth_blocked"],
            permanent_failed_events=delivered["permanent_failed"],
            pending_events=counts["pending"],
            blocked_events=counts["auth_blocked"],
            coverage_complete=False,
            coverage_limitations=self.config.coverage_limitations,
        )


def _read_jsonl(path: str) -> Iterable[object]:
    if path == "-":
        stream = sys.stdin.buffer
    else:
        try:
            stream = Path(path).expanduser().open("rb")
        except OSError as exc:
            raise SensorAgentConfigError("source JSONL is unavailable") from exc
    close = path != "-"
    try:
        for line_number, raw_line in enumerate(stream, start=1):
            if len(raw_line) > _MAX_SOURCE_LINE_BYTES:
                yield {"invalid_line": line_number}
                continue
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                yield json.loads(stripped)
            except (UnicodeError, ValueError):
                yield {"invalid_line": line_number}
    finally:
        if close:
            stream.close()


def _build_agent(config_path: str | Path) -> DiscoverySensorAgent:
    return DiscoverySensorAgent(load_agent_config(config_path))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m maverick.ai_discovery_sensor_agents",
        description="Consent-gated JSONL AI discovery sensor event consumer",
    )
    parser.add_argument("--config", required=True, help="closed JSON agent configuration")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run-once", help="normalize JSONL and attempt one batch")
    run_parser.add_argument("--source-jsonl", required=True, help="source path or - for stdin")
    subparsers.add_parser("deliver-once", help="retry one due batch from the durable spool")
    subparsers.add_parser(
        "unblock-auth",
        help="requeue blocked events after operator key/trust/binding approval",
    )
    subparsers.add_parser("privacy-report", help="inspect retained field names only")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        agent = _build_agent(args.config)
        if args.command == "run-once":
            output: object = agent.run_once(_read_jsonl(args.source_jsonl)).as_dict()
        elif args.command == "deliver-once":
            output = agent.deliver_once()
        elif args.command == "unblock-auth":
            output = {"unblocked": agent.spool.unblock_auth()}
        else:
            output = agent.spool.privacy_posture()
    except DiscoverySensorAgentError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, "result": output}, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main tests
    raise SystemExit(main())


__all__ = [
    "AGENT_CONFIG_SCHEMA",
    "AgentRunReport",
    "DiscoverySensorAgent",
    "DiscoverySensorAgentError",
    "DiscoverySensorSpool",
    "HTTPSObservationTransport",
    "ObservationTransport",
    "ReloadingEd25519KeyFileSigner",
    "SensorAgentConfig",
    "SensorAgentConfigError",
    "SensorAgentStateError",
    "SensorAgentTransportError",
    "TransportResponse",
    "load_agent_config",
    "main",
]
