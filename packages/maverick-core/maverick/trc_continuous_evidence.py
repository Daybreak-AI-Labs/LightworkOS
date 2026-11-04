"""Durable continuous-evidence authority for technology controls.

This runtime governs *technical observations*, not compliance conclusions.  It
stores approved collector definitions, exact-scope enrollments, leased jobs,
digest-only observations, change alerts, and an immutable audit chain.  Provider
adapters and credential resolution are injected and remain outside the store.

Nothing in this module certifies a control, marks a framework requirement as
implemented, or changes Security Ops state.  Complete collection means only
that an installed collector explicitly reached its terminal cursor for the
enrolled technical scope.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection
from .trc_evidence_collectors import (
    CollectionRequest,
    CollectorRegistry,
    ControlEvidence,
    EvidenceCollectorError,
    EvidencePage,
    validate_page,
    validate_request,
)

SCHEMA_VERSION = 2
DEFINITION_SCHEMA = "lightwork.trc-evidence-definition.v1"
ENROLLMENT_SCHEMA = "lightwork.trc-evidence-enrollment.v1"
JOB_SCHEMA = "lightwork.trc-evidence-job.v1"
RUN_SCHEMA = "lightwork.trc-evidence-run.v1"
OBSERVATION_SCHEMA = "lightwork.trc-evidence-observation.v1"
ALERT_SCHEMA = "lightwork.trc-evidence-alert.v1"
AUDIT_SCHEMA = "lightwork.trc-evidence-audit.v1"

LIVE_PROVIDER_ACCEPTANCE = False
COMPLIANCE_CONCLUSIONS_WRITTEN = False
CONTROL_IMPLEMENTATION_MUTATED = False
RAW_PROVIDER_PAYLOAD_PERSISTED = False
RAW_CREDENTIALS_PERSISTED = False

_ID_RE = re.compile(r"[a-z][a-z0-9_.:-]{0,127}\Z")
_CONTROL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ERROR_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_TOKEN_RE = re.compile(r"lwtrc1\.[A-Za-z0-9_-]{32,128}\Z")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_CONTROLS = 250
_MAX_PAGES = 50
_MAX_ITEMS = 2_000
_MAX_TOTAL_BYTES = 16 * 1024 * 1024
_MAX_CLAIM = 100
_MAX_ATTEMPTS = 20
_MAX_LEASE_SECONDS = 3_600
_MAX_INTERVAL_SECONDS = 366 * 24 * 3_600
_MIN_RETENTION_SECONDS = 60
_MAX_RETENTION_SECONDS = 10 * 366 * 24 * 3_600
_JOB_STATES = frozenset({"queued", "leased", "completed", "incomplete", "dead_letter", "cancelled"})
_TERMINAL_JOB_STATES = frozenset({"completed", "incomplete", "dead_letter", "cancelled"})
_ENROLLMENT_STATES = frozenset({"active", "paused", "revoked"})
_DEFINITION_STATES = frozenset({"pending", "approved", "retired"})
_OBSERVATION_STATUSES = frozenset({"observed", "failed", "unknown"})


class ContinuousEvidenceError(RuntimeError):
    """Base continuous-evidence error."""


class ContinuousEvidenceConfigError(ContinuousEvidenceError):
    """The feature gate or a server-side dependency is unavailable."""


class ContinuousEvidenceValidationError(ContinuousEvidenceError, ValueError):
    """Input is outside the closed evidence contract."""


class ContinuousEvidenceConflict(ContinuousEvidenceError):
    """An idempotency, CAS, or exact-authority precondition failed."""


class ContinuousEvidenceNotFound(ContinuousEvidenceError):
    """A tenant-bound record is absent or deliberately undisclosed."""


class ContinuousEvidencePermissionDenied(ContinuousEvidenceError):
    """Independent approval or an authenticated principal is required."""


class ContinuousEvidenceIntegrityError(ContinuousEvidenceError):
    """Persisted state or its immutable chain failed verification."""


class ContinuousEvidenceLeaseLost(ContinuousEvidenceError):
    """A worker no longer owns the exact job lease."""


def enabled() -> bool:
    """Return true only for the exact default-off product and feature gates."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    root = config.get("tech_risk_compliance")
    feature = root.get("continuous_evidence") if isinstance(root, Mapping) else None
    return (
        isinstance(root, Mapping)
        and root.get("enable") is True
        and isinstance(feature, Mapping)
        and feature.get("enable") is True
    )


def require_enabled() -> None:
    if not enabled():
        raise ContinuousEvidenceConfigError(
            "continuous evidence is disabled; explicitly enable "
            "tech_risk_compliance and tech_risk_compliance.continuous_evidence"
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
        raise ContinuousEvidenceValidationError(
            "evidence metadata must be finite canonical JSON"
        ) from exc
    if len(encoded) > maximum:
        raise ContinuousEvidenceValidationError("evidence metadata exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _same(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ContinuousEvidenceValidationError(f"{label} is invalid")
    return value


def _collector_allowlist(value: Sequence[str] | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ContinuousEvidenceConfigError("collector allowlist is invalid")
    allowed = tuple(_id(item, "allowed collector_id") for item in value)
    if not allowed or len(allowed) > 32 or len(set(allowed)) != len(allowed):
        raise ContinuousEvidenceConfigError("collector allowlist is invalid")
    return allowed


def _control(value: object) -> str:
    if not isinstance(value, str) or not _CONTROL_RE.fullmatch(value):
        raise ContinuousEvidenceValidationError("control_ref is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ContinuousEvidenceValidationError(f"{label} is invalid")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ContinuousEvidenceValidationError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise ContinuousEvidenceValidationError(f"{label} is invalid")
    return float(value)


def _error_code(value: object) -> str:
    if not isinstance(value, str) or not _ERROR_RE.fullmatch(value):
        raise ContinuousEvidenceValidationError("error_code is invalid")
    return value


def _token(value: object) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise ContinuousEvidenceValidationError("lease token is invalid")
    return value


def _controls(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ContinuousEvidenceValidationError("control_refs must be a sequence")
    normalized = tuple(_control(item) for item in values)
    if not 1 <= len(normalized) <= _MAX_CONTROLS:
        raise ContinuousEvidenceValidationError("control_refs is outside its bound")
    if len(set(normalized)) != len(normalized):
        raise ContinuousEvidenceValidationError("control_refs contains duplicates")
    return tuple(sorted(normalized))


def _runtime_principal() -> str | None:
    try:
        from .connections import current_principal

        return current_principal()
    except Exception:
        return None


@dataclass(frozen=True, slots=True)
class CollectorDefinition:
    definition_id: str
    version: int
    collector_id: str
    collector_schema_version: int
    collector_key_id: str
    capability_revision: int
    allowed_control_refs: tuple[str, ...]
    state: str
    created_by_sha256: str
    approved_by_sha256: str | None
    created_at: float
    approved_at: float | None
    retired_at: float | None
    integrity_sha256: str
    source_manifest: dict[str, Any] | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class CollectorEnrollment:
    enrollment_id: str
    definition_id: str
    definition_version: int
    definition_integrity_sha256: str
    collector_id: str
    asset_scope_sha256: str
    credential_profile_sha256: str
    control_refs: tuple[str, ...]
    interval_seconds: int
    state: str
    next_due_at: float
    revision: int
    created_at: float
    updated_at: float
    retained_until: float
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceJob:
    job_id: str
    enrollment_id: str
    enrollment_revision: int
    enrollment_integrity_sha256: str
    state: str
    attempt: int
    max_attempts: int
    not_before: float
    lease_token_sha256: str | None
    lease_until: float | None
    error_code: str | None
    requested_window_started_at: float
    requested_window_ended_at: float
    created_at: float
    updated_at: float
    retained_until: float
    revision: int
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class ClaimedEvidenceJob:
    job: EvidenceJob
    lease_token: str


@dataclass(frozen=True, slots=True)
class EvidenceRun:
    run_id: str
    job_id: str
    enrollment_id: str
    enrollment_revision: int
    definition_id: str
    definition_version: int
    collector_id: str
    state: str
    complete: bool
    incomplete_reason: str | None
    page_count: int
    item_count: int
    byte_count: int
    terminal_cursor_sha256: str
    coverage_manifest_sha256: str
    artifact_manifest_sha256: str
    started_at: float
    completed_at: float
    retained_until: float
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceObservation:
    observation_id: str
    run_id: str
    enrollment_id: str
    control_ref: str
    status: str
    reason_code: str
    evidence_sha256: str
    source_revision_sha256: str
    observed_at: float
    retained_until: float
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceChangeAlert:
    alert_id: str
    enrollment_id: str
    control_ref: str
    previous_observation_sha256: str
    current_observation_sha256: str
    previous_status: str
    current_status: str
    created_at: float
    retained_until: float
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class CollectionOutcome:
    job: EvidenceJob
    run: EvidenceRun | None
    observations: tuple[EvidenceObservation, ...]
    alerts: tuple[EvidenceChangeAlert, ...]


@dataclass(frozen=True, slots=True)
class IntegrityVerification:
    definitions: int
    enrollments: int
    jobs: int
    runs: int
    observations: int
    alerts: int
    audit_events: int
    terminal_audit_sha256: str


@dataclass(frozen=True, slots=True)
class RetentionPurgeResult:
    alerts: int
    observations: int
    runs: int
    jobs: int
    enrollments: int
    cutoff: float


def _record_payload(
    record: object,
    schema: str,
    tenant_sha256: str,
) -> dict[str, object]:
    payload = asdict(record)
    payload.pop("integrity_sha256", None)
    if payload.get("source_manifest") is None:
        payload.pop("source_manifest", None)
    payload["schema"] = schema
    payload["tenant_sha256"] = tenant_sha256
    return payload


class ContinuousEvidenceStore:
    """Private per-tenant SQLite authority for continuous evidence."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        principal_resolver: Callable[[], str | None] = _runtime_principal,
        config_gate: Callable[[], None] = require_enabled,
        clock: Callable[[], float] = time.time,
        lease_token_factory: Callable[[], str] = lambda: "lwtrc1." + secrets.token_urlsafe(32),
        default_retention_seconds: int = 90 * 24 * 3_600,
    ) -> None:
        if not all(
            callable(item) for item in (principal_resolver, config_gate, clock, lease_token_factory)
        ):
            raise ContinuousEvidenceConfigError("continuous-evidence dependencies must be callable")
        config_gate()
        self.path = Path(path)
        self._tenant_id = canonical_tenant_id(tenant_id)
        self._tenant_sha256 = _sha256(
            {
                "schema": "lightwork.trc-evidence-tenant.v1",
                "tenant_id": self._tenant_id,
            }
        )
        self._principal_resolver = principal_resolver
        self._gate = config_gate
        self._clock = clock
        self._lease_token_factory = lease_token_factory
        self._retention = threading.local()
        self._default_retention_seconds = _integer(
            default_retention_seconds,
            "default_retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        )
        ensure_private_directory(self.path.parent)
        self._initialize()
        ensure_private_file(self.path)

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def tenant_sha256(self) -> str:
        return self._tenant_sha256

    def _check_gate(self) -> None:
        try:
            self._gate()
        except ContinuousEvidenceError:
            raise
        except Exception as exc:
            raise ContinuousEvidenceConfigError("continuous-evidence gate is unavailable") from exc

    def _now(self) -> float:
        return _timestamp(self._clock(), "current time")

    def _actor_sha256(self) -> str:
        try:
            principal = self._principal_resolver()
        except Exception as exc:
            raise ContinuousEvidenceConfigError(
                "continuous-evidence principal authority is unavailable"
            ) from exc
        if not isinstance(principal, str) or not principal or len(principal) > 512:
            raise ContinuousEvidencePermissionDenied(
                "an authenticated continuous-evidence principal is required"
            )
        return _sha256(
            {
                "schema": "lightwork.trc-evidence-principal.v1",
                "tenant_sha256": self._tenant_sha256,
                "principal": principal,
            }
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.create_function(
            "trc_evidence_retention_authorized",
            0,
            lambda: 1 if bool(getattr(self._retention, "authorized", False)) else 0,
        )
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def _authorized_retention(self):
        if bool(getattr(self._retention, "authorized", False)):
            raise ContinuousEvidencePermissionDenied(
                "nested continuous-evidence retention authority is invalid"
            )
        self._retention.authorized = True
        try:
            yield
        finally:
            self._retention.authorized = False

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, SCHEMA_VERSION):
                raise ContinuousEvidenceConfigError(
                    "unsupported continuous-evidence schema version"
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS trc_definitions(
                    tenant_sha256 TEXT NOT NULL,
                    definition_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,definition_id,version)
                );
                CREATE TABLE IF NOT EXISTS trc_definition_history(
                    tenant_sha256 TEXT NOT NULL,
                    definition_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,definition_id,version,state)
                );
                CREATE TABLE IF NOT EXISTS trc_enrollments(
                    tenant_sha256 TEXT NOT NULL,
                    enrollment_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    next_due_at REAL NOT NULL,
                    revision INTEGER NOT NULL,
                    retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,enrollment_id)
                );
                CREATE TABLE IF NOT EXISTS trc_enrollment_history(
                    tenant_sha256 TEXT NOT NULL,
                    enrollment_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,enrollment_id,revision)
                );
                CREATE TABLE IF NOT EXISTS trc_jobs(
                    tenant_sha256 TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    enrollment_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    not_before REAL NOT NULL,
                    lease_until REAL,
                    revision INTEGER NOT NULL,
                    retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,job_id)
                );
                CREATE INDEX IF NOT EXISTS trc_jobs_ready
                    ON trc_jobs(tenant_sha256,state,not_before,job_id);
                CREATE TABLE IF NOT EXISTS trc_job_history(
                    tenant_sha256 TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,job_id,revision)
                );
                CREATE TABLE IF NOT EXISTS trc_runs(
                    tenant_sha256 TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    enrollment_id TEXT NOT NULL,
                    completed_at REAL NOT NULL,
                    retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,run_id),
                    UNIQUE(tenant_sha256,job_id)
                );
                CREATE TABLE IF NOT EXISTS trc_observations(
                    tenant_sha256 TEXT NOT NULL,
                    observation_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    enrollment_id TEXT NOT NULL,
                    control_ref TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,observation_id),
                    UNIQUE(tenant_sha256,run_id,control_ref)
                );
                CREATE INDEX IF NOT EXISTS trc_observation_latest
                    ON trc_observations(
                        tenant_sha256,enrollment_id,control_ref,observed_at
                    );
                CREATE TABLE IF NOT EXISTS trc_alerts(
                    tenant_sha256 TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    enrollment_id TEXT NOT NULL,
                    control_ref TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,alert_id)
                );
                CREATE TABLE IF NOT EXISTS trc_operations(
                    tenant_sha256 TEXT NOT NULL,
                    operation_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    result_kind TEXT NOT NULL,
                    result_id TEXT NOT NULL,
                    result_revision INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(tenant_sha256,operation_sha256)
                );
                CREATE TABLE IF NOT EXISTS trc_audit(
                    tenant_sha256 TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS trc_definition_history_no_update
                    BEFORE UPDATE ON trc_definition_history
                    BEGIN SELECT RAISE(ABORT,'definition history is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trc_definitions_no_delete
                    BEFORE DELETE ON trc_definitions
                    BEGIN SELECT RAISE(ABORT,'collector definitions are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trc_definition_history_no_delete
                    BEFORE DELETE ON trc_definition_history
                    BEGIN SELECT RAISE(ABORT,'definition history is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trc_enrollment_history_no_update
                    BEFORE UPDATE ON trc_enrollment_history
                    BEGIN SELECT RAISE(ABORT,'enrollment history is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trc_enrollments_guard_delete
                    BEFORE DELETE ON trc_enrollments
                    WHEN trc_evidence_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS trc_enrollment_history_guard_delete
                    BEFORE DELETE ON trc_enrollment_history
                    WHEN trc_evidence_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS trc_job_history_no_update
                    BEFORE UPDATE ON trc_job_history
                    BEGIN SELECT RAISE(ABORT,'job history is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trc_jobs_guard_delete
                    BEFORE DELETE ON trc_jobs
                    WHEN trc_evidence_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS trc_job_history_guard_delete
                    BEFORE DELETE ON trc_job_history
                    WHEN trc_evidence_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS trc_runs_no_update
                    BEFORE UPDATE ON trc_runs
                    BEGIN SELECT RAISE(ABORT,'evidence runs are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trc_runs_guard_delete
                    BEFORE DELETE ON trc_runs
                    WHEN trc_evidence_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS trc_observations_no_update
                    BEFORE UPDATE ON trc_observations
                    BEGIN SELECT RAISE(ABORT,'evidence observations are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trc_observations_guard_delete
                    BEFORE DELETE ON trc_observations
                    WHEN trc_evidence_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS trc_alerts_no_update
                    BEFORE UPDATE ON trc_alerts
                    BEGIN SELECT RAISE(ABORT,'evidence alerts are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trc_alerts_guard_delete
                    BEFORE DELETE ON trc_alerts
                    WHEN trc_evidence_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS trc_operations_no_update
                    BEFORE UPDATE ON trc_operations
                    BEGIN SELECT RAISE(ABORT,'evidence operations are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trc_operations_guard_delete
                    BEFORE DELETE ON trc_operations
                    WHEN trc_evidence_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS trc_audit_no_update
                    BEFORE UPDATE ON trc_audit
                    BEGIN SELECT RAISE(ABORT,'evidence audit is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trc_audit_no_delete
                    BEFORE DELETE ON trc_audit
                    BEGIN SELECT RAISE(ABORT,'evidence audit is immutable'); END;
                """
            )
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            connection.commit()

    def _decode(self, row: sqlite3.Row, label: str) -> tuple[dict[str, Any], str]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ContinuousEvidenceIntegrityError(f"stored {label} is invalid") from exc
        if not isinstance(payload, dict):
            raise ContinuousEvidenceIntegrityError(f"stored {label} is invalid")
        integrity = str(row["integrity_sha256"])
        if not _same(_sha256(payload), integrity):
            raise ContinuousEvidenceIntegrityError(f"stored {label} failed integrity")
        if (
            str(row["tenant_sha256"]) != self._tenant_sha256
            or payload.get("tenant_sha256") != self._tenant_sha256
        ):
            raise ContinuousEvidenceIntegrityError(f"stored {label} has an invalid tenant binding")
        return payload, integrity

    def _definition(self, row: sqlite3.Row) -> CollectorDefinition:
        payload, integrity = self._decode(row, "collector definition")
        if payload.pop("schema", None) != DEFINITION_SCHEMA:
            raise ContinuousEvidenceIntegrityError("collector definition schema is invalid")
        payload.pop("tenant_sha256", None)
        try:
            allowed_control_refs = tuple(payload.pop("allowed_control_refs"))
            definition = CollectorDefinition(
                **payload,
                allowed_control_refs=allowed_control_refs,
                integrity_sha256=integrity,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ContinuousEvidenceIntegrityError(
                "collector definition fields are invalid"
            ) from exc
        self._validate_definition(definition)
        if (
            str(row["definition_id"]) != definition.definition_id
            or int(row["version"]) != definition.version
            or str(row["state"]) != definition.state
        ):
            raise ContinuousEvidenceIntegrityError("collector definition index is inconsistent")
        return definition

    @staticmethod
    def _validate_definition(definition: CollectorDefinition) -> None:
        _id(definition.definition_id, "definition_id")
        _integer(definition.version, "definition version", 1, 2**31 - 1)
        _id(definition.collector_id, "collector_id")
        if definition.source_manifest is not None:
            from .trc_stock_evidence_collectors import managed_source_from_definition

            source = managed_source_from_definition("default", definition)
            if (source.collector_id != definition.collector_id or
                    tuple(item.control_ref for item in source.bindings) != definition.allowed_control_refs):
                raise ContinuousEvidenceValidationError("source and definition controls disagree")
        _integer(
            definition.collector_schema_version,
            "collector_schema_version",
            1,
            2**31 - 1,
        )
        _id(definition.collector_key_id, "collector_key_id")
        _integer(definition.capability_revision, "capability_revision", 1, 2**31 - 1)
        if tuple(sorted(definition.allowed_control_refs)) != _controls(
            definition.allowed_control_refs
        ):
            raise ContinuousEvidenceIntegrityError("collector definition controls are invalid")
        if definition.state not in _DEFINITION_STATES:
            raise ContinuousEvidenceIntegrityError("collector definition state is invalid")
        _digest(definition.created_by_sha256, "created_by_sha256")
        _timestamp(definition.created_at, "created_at")
        if definition.state == "pending":
            if any(
                value is not None
                for value in (
                    definition.approved_by_sha256,
                    definition.approved_at,
                    definition.retired_at,
                )
            ):
                raise ContinuousEvidenceIntegrityError(
                    "pending collector definition carries approval state"
                )
        elif definition.approved_by_sha256 is None or definition.approved_at is None:
            raise ContinuousEvidenceIntegrityError(
                "approved collector definition lacks approval authority"
            )
        if definition.approved_by_sha256 is not None:
            _digest(definition.approved_by_sha256, "approved_by_sha256")
            if _same(definition.created_by_sha256, definition.approved_by_sha256):
                raise ContinuousEvidenceIntegrityError(
                    "collector definition violates independent approval"
                )
        if definition.approved_at is not None:
            _timestamp(definition.approved_at, "approved_at")
        if definition.state == "retired":
            _timestamp(definition.retired_at, "retired_at")
        elif definition.retired_at is not None:
            raise ContinuousEvidenceIntegrityError("active collector definition has retired_at")

    def _enrollment(
        self,
        row: sqlite3.Row,
        *,
        indexed: bool = True,
    ) -> CollectorEnrollment:
        payload, integrity = self._decode(row, "collector enrollment")
        if payload.pop("schema", None) != ENROLLMENT_SCHEMA:
            raise ContinuousEvidenceIntegrityError("collector enrollment schema is invalid")
        payload.pop("tenant_sha256", None)
        try:
            control_refs = tuple(payload.pop("control_refs"))
            enrollment = CollectorEnrollment(
                **payload,
                control_refs=control_refs,
                integrity_sha256=integrity,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ContinuousEvidenceIntegrityError(
                "collector enrollment fields are invalid"
            ) from exc
        _id(enrollment.enrollment_id, "enrollment_id")
        _id(enrollment.definition_id, "definition_id")
        _integer(enrollment.definition_version, "definition_version", 1, 2**31 - 1)
        _digest(enrollment.definition_integrity_sha256, "definition_integrity_sha256")
        _id(enrollment.collector_id, "collector_id")
        _digest(enrollment.asset_scope_sha256, "asset_scope_sha256")
        _digest(enrollment.credential_profile_sha256, "credential_profile_sha256")
        if enrollment.control_refs != _controls(enrollment.control_refs):
            raise ContinuousEvidenceIntegrityError("enrollment controls are invalid")
        _integer(enrollment.interval_seconds, "interval_seconds", 60, _MAX_INTERVAL_SECONDS)
        if enrollment.state not in _ENROLLMENT_STATES:
            raise ContinuousEvidenceIntegrityError("enrollment state is invalid")
        _integer(enrollment.revision, "revision", 1, 2**31 - 1)
        created = _timestamp(enrollment.created_at, "created_at")
        updated = _timestamp(enrollment.updated_at, "updated_at")
        due = _timestamp(enrollment.next_due_at, "next_due_at")
        retained = _timestamp(enrollment.retained_until, "retained_until")
        if not (created <= updated <= retained and created <= due <= retained):
            raise ContinuousEvidenceIntegrityError("enrollment time binding is invalid")
        if indexed and (
            str(row["enrollment_id"]) != enrollment.enrollment_id
            or str(row["state"]) != enrollment.state
            or float(row["next_due_at"]) != enrollment.next_due_at
            or int(row["revision"]) != enrollment.revision
            or float(row["retained_until"]) != enrollment.retained_until
        ):
            raise ContinuousEvidenceIntegrityError("enrollment index is inconsistent")
        return enrollment

    def _job(
        self,
        row: sqlite3.Row,
        *,
        indexed: bool = True,
    ) -> EvidenceJob:
        payload, integrity = self._decode(row, "evidence job")
        if payload.pop("schema", None) != JOB_SCHEMA:
            raise ContinuousEvidenceIntegrityError("evidence job schema is invalid")
        payload.pop("tenant_sha256", None)
        try:
            job = EvidenceJob(**payload, integrity_sha256=integrity)
        except (TypeError, ValueError) as exc:
            raise ContinuousEvidenceIntegrityError("evidence job fields are invalid") from exc
        _id(job.job_id, "job_id")
        _id(job.enrollment_id, "enrollment_id")
        _integer(job.enrollment_revision, "enrollment_revision", 1, 2**31 - 1)
        _digest(job.enrollment_integrity_sha256, "enrollment_integrity_sha256")
        if job.state not in _JOB_STATES:
            raise ContinuousEvidenceIntegrityError("evidence job state is invalid")
        _integer(job.attempt, "attempt", 0, _MAX_ATTEMPTS)
        _integer(job.max_attempts, "max_attempts", 1, _MAX_ATTEMPTS)
        if job.attempt > job.max_attempts:
            raise ContinuousEvidenceIntegrityError("evidence job attempt is invalid")
        for value, label in (
            (job.not_before, "not_before"),
            (job.requested_window_started_at, "requested_window_started_at"),
            (job.requested_window_ended_at, "requested_window_ended_at"),
            (job.created_at, "created_at"),
            (job.updated_at, "updated_at"),
            (job.retained_until, "retained_until"),
        ):
            _timestamp(value, label)
        if job.requested_window_started_at > job.requested_window_ended_at:
            raise ContinuousEvidenceIntegrityError("evidence job window is reversed")
        if job.state == "leased":
            if job.lease_token_sha256 is None or job.lease_until is None:
                raise ContinuousEvidenceIntegrityError("leased job lacks a lease")
            _digest(job.lease_token_sha256, "lease_token_sha256")
            _timestamp(job.lease_until, "lease_until")
        elif job.lease_token_sha256 is not None or job.lease_until is not None:
            raise ContinuousEvidenceIntegrityError("unleased job carries lease authority")
        if job.error_code is not None:
            _error_code(job.error_code)
        _integer(job.revision, "revision", 1, 2**31 - 1)
        if not (
            job.created_at <= job.updated_at <= job.retained_until
            and job.requested_window_ended_at <= job.updated_at
        ):
            raise ContinuousEvidenceIntegrityError("evidence job time binding is invalid")
        if indexed:
            indexed_lease = None if row["lease_until"] is None else float(row["lease_until"])
            if (
                str(row["job_id"]) != job.job_id
                or str(row["enrollment_id"]) != job.enrollment_id
                or str(row["state"]) != job.state
                or float(row["not_before"]) != job.not_before
                or indexed_lease != job.lease_until
                or int(row["revision"]) != job.revision
                or float(row["retained_until"]) != job.retained_until
            ):
                raise ContinuousEvidenceIntegrityError("evidence job index is inconsistent")
        return job

    def _run(self, row: sqlite3.Row) -> EvidenceRun:
        payload, integrity = self._decode(row, "evidence run")
        if payload.pop("schema", None) != RUN_SCHEMA:
            raise ContinuousEvidenceIntegrityError("evidence run schema is invalid")
        payload.pop("tenant_sha256", None)
        try:
            run = EvidenceRun(**payload, integrity_sha256=integrity)
        except (TypeError, ValueError) as exc:
            raise ContinuousEvidenceIntegrityError("evidence run fields are invalid") from exc
        if run.state not in {"complete", "incomplete"} or run.complete != (run.state == "complete"):
            raise ContinuousEvidenceIntegrityError("evidence run state is invalid")
        if run.complete != (run.incomplete_reason is None):
            raise ContinuousEvidenceIntegrityError("evidence run completeness is invalid")
        for value, label in (
            (run.run_id, "run_id"),
            (run.job_id, "job_id"),
            (run.enrollment_id, "enrollment_id"),
            (run.definition_id, "definition_id"),
            (run.collector_id, "collector_id"),
        ):
            _id(value, label)
        for value, label in (
            (run.terminal_cursor_sha256, "terminal_cursor_sha256"),
            (run.coverage_manifest_sha256, "coverage_manifest_sha256"),
            (run.artifact_manifest_sha256, "artifact_manifest_sha256"),
        ):
            _digest(value, label)
        _integer(run.enrollment_revision, "enrollment_revision", 1, 2**31 - 1)
        _integer(run.definition_version, "definition_version", 1, 2**31 - 1)
        _integer(run.page_count, "page_count", 1, _MAX_PAGES)
        _integer(run.item_count, "item_count", 0, _MAX_ITEMS)
        _integer(run.byte_count, "byte_count", 0, _MAX_TOTAL_BYTES)
        if run.incomplete_reason is not None:
            _error_code(run.incomplete_reason)
        started = _timestamp(run.started_at, "started_at")
        completed = _timestamp(run.completed_at, "completed_at")
        retained = _timestamp(run.retained_until, "retained_until")
        if not started <= completed <= retained:
            raise ContinuousEvidenceIntegrityError("evidence run time binding is invalid")
        if (
            str(row["run_id"]) != run.run_id
            or str(row["job_id"]) != run.job_id
            or str(row["enrollment_id"]) != run.enrollment_id
            or float(row["completed_at"]) != run.completed_at
            or float(row["retained_until"]) != run.retained_until
        ):
            raise ContinuousEvidenceIntegrityError("evidence run index is inconsistent")
        return run

    def _observation(self, row: sqlite3.Row) -> EvidenceObservation:
        payload, integrity = self._decode(row, "evidence observation")
        if payload.pop("schema", None) != OBSERVATION_SCHEMA:
            raise ContinuousEvidenceIntegrityError("observation schema is invalid")
        payload.pop("tenant_sha256", None)
        try:
            item = EvidenceObservation(**payload, integrity_sha256=integrity)
        except (TypeError, ValueError) as exc:
            raise ContinuousEvidenceIntegrityError("observation fields are invalid") from exc
        for value, label in (
            (item.observation_id, "observation_id"),
            (item.run_id, "run_id"),
            (item.enrollment_id, "enrollment_id"),
        ):
            _id(value, label)
        if item.status not in _OBSERVATION_STATUSES:
            raise ContinuousEvidenceIntegrityError("observation status is invalid")
        _control(item.control_ref)
        _error_code(item.reason_code)
        _digest(item.evidence_sha256, "evidence_sha256")
        _digest(item.source_revision_sha256, "source_revision_sha256")
        observed = _timestamp(item.observed_at, "observed_at")
        retained = _timestamp(item.retained_until, "retained_until")
        if observed > retained:
            raise ContinuousEvidenceIntegrityError("observation time binding is invalid")
        if (
            str(row["observation_id"]) != item.observation_id
            or str(row["run_id"]) != item.run_id
            or str(row["enrollment_id"]) != item.enrollment_id
            or str(row["control_ref"]) != item.control_ref
            or float(row["observed_at"]) != item.observed_at
            or float(row["retained_until"]) != item.retained_until
        ):
            raise ContinuousEvidenceIntegrityError("observation index is inconsistent")
        return item

    def _alert(self, row: sqlite3.Row) -> EvidenceChangeAlert:
        payload, integrity = self._decode(row, "evidence alert")
        if payload.pop("schema", None) != ALERT_SCHEMA:
            raise ContinuousEvidenceIntegrityError("alert schema is invalid")
        payload.pop("tenant_sha256", None)
        try:
            alert = EvidenceChangeAlert(**payload, integrity_sha256=integrity)
        except (TypeError, ValueError) as exc:
            raise ContinuousEvidenceIntegrityError("alert fields are invalid") from exc
        for value, label in (
            (alert.alert_id, "alert_id"),
            (alert.enrollment_id, "enrollment_id"),
        ):
            _id(value, label)
        _control(alert.control_ref)
        for value, label in (
            (alert.previous_observation_sha256, "previous_observation_sha256"),
            (alert.current_observation_sha256, "current_observation_sha256"),
        ):
            _digest(value, label)
        if (
            alert.previous_status not in _OBSERVATION_STATUSES
            or alert.current_status not in _OBSERVATION_STATUSES
        ):
            raise ContinuousEvidenceIntegrityError("alert status is invalid")
        created = _timestamp(alert.created_at, "created_at")
        retained = _timestamp(alert.retained_until, "retained_until")
        if created > retained:
            raise ContinuousEvidenceIntegrityError("alert time binding is invalid")
        if (
            str(row["alert_id"]) != alert.alert_id
            or str(row["enrollment_id"]) != alert.enrollment_id
            or str(row["control_ref"]) != alert.control_ref
            or float(row["created_at"]) != alert.created_at
            or float(row["retained_until"]) != alert.retained_until
        ):
            raise ContinuousEvidenceIntegrityError("alert index is inconsistent")
        return alert

    @staticmethod
    def _insert_record(
        connection: sqlite3.Connection,
        table: str,
        columns: tuple[object, ...],
        record: object,
        schema: str,
    ) -> str:
        payload = _record_payload(record, schema, str(columns[0]))
        encoded = _canonical(payload).decode("ascii")
        integrity = _sha256(payload)
        placeholders = ",".join("?" for _ in range(len(columns) + 2))
        connection.execute(
            f"INSERT INTO {table} VALUES({placeholders})",  # noqa: S608
            (*columns, encoded, integrity),
        )
        return integrity

    def _audit(
        self,
        connection: sqlite3.Connection,
        action: str,
        subject_sha256: str,
        actor_sha256: str,
        now: float,
    ) -> None:
        _id(action, "audit action")
        _digest(subject_sha256, "audit subject_sha256")
        _digest(actor_sha256, "audit actor_sha256")
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM trc_audit "
            "WHERE tenant_sha256=? ORDER BY sequence DESC LIMIT 1",
            (self._tenant_sha256,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = "0" * 64 if previous is None else str(previous["integrity_sha256"])
        payload = {
            "schema": AUDIT_SCHEMA,
            "tenant_sha256": self._tenant_sha256,
            "sequence": sequence,
            "action": action,
            "subject_sha256": subject_sha256,
            "actor_sha256": actor_sha256,
            "created_at": now,
            "previous_integrity_sha256": previous_sha,
        }
        encoded = _canonical(payload).decode("ascii")
        integrity = _sha256(payload)
        connection.execute(
            "INSERT INTO trc_audit VALUES(?,?,?,?)",
            (self._tenant_sha256, sequence, encoded, integrity),
        )

    def _operation(
        self,
        connection: sqlite3.Connection,
        operation_id: str,
        request: object,
    ) -> tuple[str, sqlite3.Row | None]:
        operation = _id(operation_id, "operation_id")
        operation_sha = _sha256(
            {
                "schema": "lightwork.trc-evidence-operation-id.v1",
                "tenant_sha256": self._tenant_sha256,
                "operation_id": operation,
            }
        )
        request_sha = _sha256(request)
        row = connection.execute(
            "SELECT * FROM trc_operations WHERE tenant_sha256=? AND operation_sha256=?",
            (self._tenant_sha256, operation_sha),
        ).fetchone()
        if row is not None and not _same(str(row["request_sha256"]), request_sha):
            raise ContinuousEvidenceConflict("operation_id is bound to another request")
        return operation_sha, row

    @staticmethod
    def _save_operation(
        connection: sqlite3.Connection,
        tenant_sha256: str,
        operation_sha256: str,
        request_sha256: str,
        result_kind: str,
        result_id: str,
        result_revision: int,
        now: float,
    ) -> None:
        connection.execute(
            "INSERT INTO trc_operations VALUES(?,?,?,?,?,?,?)",
            (
                tenant_sha256,
                operation_sha256,
                request_sha256,
                result_kind,
                result_id,
                result_revision,
                now,
            ),
        )

    def register_definition(
        self,
        *,
        definition_id: str,
        version: int,
        collector_id: str,
        collector_schema_version: int,
        collector_key_id: str,
        capability_revision: int,
        allowed_control_refs: Sequence[str],
        source_manifest: Mapping[str, Any] | None = None,
        expected_previous_integrity_sha256: str | None = None,
        operation_id: str | None = None,
        before_effect: Callable[[], None] | None = None,
    ) -> CollectorDefinition:
        self._check_gate()
        actor = self._actor_sha256()
        now = self._now()
        definition = CollectorDefinition(
            definition_id=_id(definition_id, "definition_id"),
            version=_integer(version, "version", 1, 2**31 - 1),
            collector_id=_id(collector_id, "collector_id"),
            collector_schema_version=_integer(
                collector_schema_version,
                "collector_schema_version",
                1,
                2**31 - 1,
            ),
            collector_key_id=_id(collector_key_id, "collector_key_id"),
            capability_revision=_integer(
                capability_revision,
                "capability_revision",
                1,
                2**31 - 1,
            ),
            allowed_control_refs=_controls(allowed_control_refs),
            state="pending",
            created_by_sha256=actor,
            approved_by_sha256=None,
            created_at=now,
            approved_at=None,
            retired_at=None,
            integrity_sha256="0" * 64,
            source_manifest=(json.loads(_canonical(source_manifest)) if source_manifest is not None else None),
        )
        self._validate_definition(definition)
        with self._connect() as connection:
            self._begin(connection)
            source_request = {
                "schema": "lightwork.trc-source-save.v1", "actor_sha256": actor,
                "definition_id": definition.definition_id, "version": definition.version,
                "source_manifest": definition.source_manifest,
                "expected_previous_integrity_sha256": expected_previous_integrity_sha256,
            }
            operation_sha = None
            if operation_id is not None:
                if source_manifest is None:
                    raise ContinuousEvidenceValidationError("source operation requires a source manifest")
                operation_sha, prior = self._operation(connection, operation_id, source_request)
                if prior is not None:
                    original = connection.execute(
                        "SELECT * FROM trc_definition_history WHERE tenant_sha256=? "
                        "AND definition_id=? AND version=? AND state='pending'",
                        (self._tenant_sha256, prior["result_id"], prior["result_revision"]),
                    ).fetchone()
                    if original is None or prior["result_kind"] != "source_definition":
                        raise ContinuousEvidenceIntegrityError("source operation result disappeared")
                    return self._definition(original)
            existing = connection.execute(
                "SELECT * FROM trc_definitions WHERE tenant_sha256=? "
                "AND definition_id=? AND version=?",
                (self._tenant_sha256, definition.definition_id, definition.version),
            ).fetchone()
            if existing is not None:
                if source_manifest is not None and operation_id is not None:
                    raise ContinuousEvidenceConflict("another source operation already saved this version")
                stored = self._definition(existing)
                request_fields = (
                    stored.collector_id,
                    stored.collector_schema_version,
                    stored.collector_key_id,
                    stored.capability_revision,
                    stored.allowed_control_refs,
                    stored.source_manifest,
                )
                new_fields = (
                    definition.collector_id,
                    definition.collector_schema_version,
                    definition.collector_key_id,
                    definition.capability_revision,
                    definition.allowed_control_refs,
                    definition.source_manifest,
                )
                if request_fields != new_fields:
                    raise ContinuousEvidenceConflict(
                        "collector definition version already has different content"
                    )
                return stored
            previous_row = connection.execute(
                "SELECT * FROM trc_definitions WHERE tenant_sha256=? AND definition_id=? "
                "ORDER BY version DESC LIMIT 1", (self._tenant_sha256, definition.definition_id),
            ).fetchone()
            previous = self._definition(previous_row) if previous_row is not None else None
            if previous is not None and (previous.source_manifest is not None or source_manifest is not None):
                if (previous.source_manifest is None or source_manifest is None or
                        definition.version != previous.version + 1 or
                        expected_previous_integrity_sha256 != previous.integrity_sha256):
                    raise ContinuousEvidenceConflict("source changed; review its current version")
            elif source_manifest is not None and (definition.version != 1 or expected_previous_integrity_sha256 is not None):
                raise ContinuousEvidenceConflict("new source must start with its first version")
            if source_manifest is not None and previous is None:
                count = connection.execute(
                    "SELECT COUNT(DISTINCT definition_id) FROM trc_definitions WHERE tenant_sha256=? "
                    "AND json_type(payload_json,'$.source_manifest')='object'", (self._tenant_sha256,),
                ).fetchone()[0]
                if count >= 64:
                    raise ContinuousEvidenceValidationError("workspace source limit reached")
            if before_effect is not None:
                before_effect()
            integrity = self._insert_record(
                connection,
                "trc_definitions",
                (
                    self._tenant_sha256,
                    definition.definition_id,
                    definition.version,
                    definition.state,
                ),
                definition,
                DEFINITION_SCHEMA,
            )
            stored = replace(definition, integrity_sha256=integrity)
            self._insert_record(
                connection,
                "trc_definition_history",
                (
                    self._tenant_sha256,
                    stored.definition_id,
                    stored.version,
                    stored.state,
                ),
                stored,
                DEFINITION_SCHEMA,
            )
            self._audit(connection, "definition_registered", integrity, actor, now)
            if previous is not None and source_manifest is not None:
                rows = connection.execute(
                    "SELECT * FROM trc_enrollments WHERE tenant_sha256=? "
                    "AND json_extract(payload_json,'$.definition_id')=? AND state='active'",
                    (self._tenant_sha256, definition.definition_id),
                ).fetchall()
                for row in rows:
                    enrollment = self._enrollment(row)
                    paused = self._replace_enrollment(connection, enrollment, replace(
                        enrollment, state="paused", revision=enrollment.revision + 1, updated_at=now,
                    ))
                    self._cancel_enrollment_jobs(connection, enrollment.enrollment_id, "source_changed", now)
                    self._audit(connection, "source_enrollment_paused", paused.integrity_sha256, actor, now)
            if operation_sha is not None:
                self._save_operation(connection, self._tenant_sha256, operation_sha,
                                     _sha256(source_request), "source_definition", stored.definition_id,
                                     stored.version, now)
            if before_effect is not None:
                before_effect()
            connection.commit()
            return stored

    def source_original(self, *, operation_id: str, definition_id: str, version: int,
                        source_manifest: Mapping[str, Any],
                        expected_previous_integrity_sha256: str | None = None) -> CollectorDefinition | None:
        """Recover the exact original pending record; never repeat a source write."""
        actor = self._actor_sha256()
        request = {"schema": "lightwork.trc-source-save.v1", "actor_sha256": actor,
                   "definition_id": _id(definition_id, "definition_id"), "version": version,
                   "source_manifest": json.loads(_canonical(source_manifest)),
                   "expected_previous_integrity_sha256": expected_previous_integrity_sha256}
        with self._connect() as connection:
            _operation_sha, prior = self._operation(connection, operation_id, request)
            if prior is None:
                return None
            row = connection.execute(
                "SELECT * FROM trc_definition_history WHERE tenant_sha256=? AND definition_id=? "
                "AND version=? AND state='pending'",
                (self._tenant_sha256, prior["result_id"], prior["result_revision"]),
            ).fetchone()
        if row is None or prior["result_kind"] != "source_definition":
            raise ContinuousEvidenceIntegrityError("source operation result disappeared")
        return self._definition(row)

    def list_source_definitions(self, *, limit: int = 65) -> tuple[CollectorDefinition, ...]:
        self._check_gate()
        limit = _integer(limit, "limit", 1, 65)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT d.* FROM trc_definitions d JOIN (SELECT definition_id,MAX(version) AS version "
                "FROM trc_definitions WHERE tenant_sha256=? GROUP BY definition_id) latest "
                "ON d.definition_id=latest.definition_id AND d.version=latest.version "
                "WHERE d.tenant_sha256=? AND json_type(d.payload_json,'$.source_manifest')='object' "
                "ORDER BY d.definition_id LIMIT ?", (self._tenant_sha256, self._tenant_sha256, limit),
            ).fetchall()
        return tuple(self._definition(row) for row in rows)

    def source_pause_count(self, definition: CollectorDefinition) -> int:
        self._check_gate()
        with self._connect() as connection:
            return int(connection.execute(
                "SELECT COUNT(*) FROM trc_enrollment_history WHERE tenant_sha256=? "
                "AND json_extract(payload_json,'$.definition_id')=? "
                "AND json_extract(payload_json,'$.definition_version')<? "
                "AND json_extract(payload_json,'$.state')='paused' "
                "AND json_extract(payload_json,'$.updated_at')=?",
                (self._tenant_sha256, definition.definition_id, definition.version, definition.created_at),
            ).fetchone()[0])

    def _require_latest_source(self, connection: sqlite3.Connection, definition: CollectorDefinition) -> None:
        if definition.source_manifest is None:
            return
        latest = connection.execute(
            "SELECT MAX(version) FROM trc_definitions WHERE tenant_sha256=? AND definition_id=?",
            (self._tenant_sha256, definition.definition_id),
        ).fetchone()[0]
        if latest != definition.version:
            raise ContinuousEvidenceConflict("source has a newer version awaiting review")

    def _cancel_enrollment_jobs(self, connection: sqlite3.Connection, enrollment_id: str,
                                code: str, now: float) -> None:
        rows = connection.execute(
            "SELECT * FROM trc_jobs WHERE tenant_sha256=? AND enrollment_id=? AND state IN ('queued','leased')",
            (self._tenant_sha256, enrollment_id),
        ).fetchall()
        for row in rows:
            job = self._job(row)
            self._replace_job(connection, job, replace(
                job, state="cancelled", lease_token_sha256=None, lease_until=None,
                error_code=code, updated_at=now, revision=job.revision + 1,
            ))

    def get_definition(self, definition_id: str, version: int) -> CollectorDefinition:
        self._check_gate()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM trc_definitions WHERE tenant_sha256=? "
                "AND definition_id=? AND version=?",
                (
                    self._tenant_sha256,
                    _id(definition_id, "definition_id"),
                    _integer(version, "version", 1, 2**31 - 1),
                ),
            ).fetchone()
        if row is None:
            raise ContinuousEvidenceNotFound("collector definition not found")
        return self._definition(row)

    def list_definitions(self, *, limit: int = 500) -> tuple[CollectorDefinition, ...]:
        self._check_gate()
        limit = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM trc_definitions WHERE tenant_sha256=? "
                "ORDER BY definition_id,version DESC LIMIT ?",
                (self._tenant_sha256, limit),
            ).fetchall()
        return tuple(self._definition(row) for row in rows)

    def approve_definition(
        self,
        definition_id: str,
        version: int,
        *,
        expected_integrity_sha256: str,
        before_effect: Callable[[], None] | None = None,
    ) -> CollectorDefinition:
        self._check_gate()
        actor = self._actor_sha256()
        now = self._now()
        expected = _digest(expected_integrity_sha256, "expected_integrity_sha256")
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM trc_definitions WHERE tenant_sha256=? "
                "AND definition_id=? AND version=?",
                (
                    self._tenant_sha256,
                    _id(definition_id, "definition_id"),
                    _integer(version, "version", 1, 2**31 - 1),
                ),
            ).fetchone()
            if row is None:
                raise ContinuousEvidenceNotFound("collector definition not found")
            current = self._definition(row)
            self._require_latest_source(connection, current)
            if not _same(current.integrity_sha256, expected):
                raise ContinuousEvidenceConflict("collector definition changed")
            if current.state == "approved":
                return current
            if current.state != "pending":
                raise ContinuousEvidenceConflict("collector definition is not approvable")
            if _same(current.created_by_sha256, actor):
                raise ContinuousEvidencePermissionDenied(
                    "collector definition requires an independent approver"
                )
            if before_effect is not None:
                before_effect()
            candidate = replace(
                current,
                state="approved",
                approved_by_sha256=actor,
                approved_at=now,
            )
            payload = _record_payload(candidate, DEFINITION_SCHEMA, self._tenant_sha256)
            integrity = _sha256(payload)
            connection.execute(
                "UPDATE trc_definitions SET state=?,payload_json=?,integrity_sha256=? "
                "WHERE tenant_sha256=? AND definition_id=? AND version=? "
                "AND integrity_sha256=?",
                (
                    candidate.state,
                    _canonical(payload).decode("ascii"),
                    integrity,
                    self._tenant_sha256,
                    candidate.definition_id,
                    candidate.version,
                    current.integrity_sha256,
                ),
            )
            if connection.total_changes != 1:
                raise ContinuousEvidenceConflict("collector definition changed")
            stored = replace(candidate, integrity_sha256=integrity)
            self._insert_record(
                connection,
                "trc_definition_history",
                (
                    self._tenant_sha256,
                    stored.definition_id,
                    stored.version,
                    stored.state,
                ),
                stored,
                DEFINITION_SCHEMA,
            )
            self._audit(connection, "definition_approved", integrity, actor, now)
            if before_effect is not None:
                before_effect()
            connection.commit()
            return stored

    def retire_definition(
        self,
        definition_id: str,
        version: int,
        *,
        expected_integrity_sha256: str,
    ) -> CollectorDefinition:
        self._check_gate()
        actor = self._actor_sha256()
        now = self._now()
        expected = _digest(expected_integrity_sha256, "expected_integrity_sha256")
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM trc_definitions WHERE tenant_sha256=? "
                "AND definition_id=? AND version=?",
                (
                    self._tenant_sha256,
                    _id(definition_id, "definition_id"),
                    _integer(version, "version", 1, 2**31 - 1),
                ),
            ).fetchone()
            if row is None:
                raise ContinuousEvidenceNotFound("collector definition not found")
            current = self._definition(row)
            if not _same(current.integrity_sha256, expected):
                raise ContinuousEvidenceConflict("collector definition changed")
            if current.state == "retired":
                return current
            if current.state != "approved":
                raise ContinuousEvidenceConflict("collector definition is not active")
            candidate = replace(current, state="retired", retired_at=now)
            payload = _record_payload(candidate, DEFINITION_SCHEMA, self._tenant_sha256)
            integrity = _sha256(payload)
            connection.execute(
                "UPDATE trc_definitions SET state=?,payload_json=?,integrity_sha256=? "
                "WHERE tenant_sha256=? AND definition_id=? AND version=? "
                "AND integrity_sha256=?",
                (
                    candidate.state,
                    _canonical(payload).decode("ascii"),
                    integrity,
                    self._tenant_sha256,
                    candidate.definition_id,
                    candidate.version,
                    current.integrity_sha256,
                ),
            )
            if connection.total_changes != 1:
                raise ContinuousEvidenceConflict("collector definition changed")
            stored = replace(candidate, integrity_sha256=integrity)
            self._insert_record(
                connection,
                "trc_definition_history",
                (
                    self._tenant_sha256,
                    stored.definition_id,
                    stored.version,
                    stored.state,
                ),
                stored,
                DEFINITION_SCHEMA,
            )
            self._audit(connection, "definition_retired", integrity, actor, now)
            connection.commit()
            return stored

    def enroll(
        self,
        *,
        enrollment_id: str,
        definition_id: str,
        definition_version: int,
        expected_definition_integrity_sha256: str,
        asset_scope_sha256: str,
        credential_profile_sha256: str,
        control_refs: Sequence[str],
        interval_seconds: int,
        operation_id: str,
        retention_seconds: int | None = None,
        before_effect: Callable[[], None] | None = None,
    ) -> CollectorEnrollment:
        self._check_gate()
        actor = self._actor_sha256()
        now = self._now()
        controls = _controls(control_refs)
        retained_for = (
            self._default_retention_seconds
            if retention_seconds is None
            else _integer(
                retention_seconds,
                "retention_seconds",
                _MIN_RETENTION_SECONDS,
                _MAX_RETENTION_SECONDS,
            )
        )
        request = {
            "schema": "lightwork.trc-evidence-enrollment-request.v1",
            "enrollment_id": _id(enrollment_id, "enrollment_id"),
            "definition_id": _id(definition_id, "definition_id"),
            "definition_version": _integer(definition_version, "definition_version", 1, 2**31 - 1),
            "expected_definition_integrity_sha256": _digest(
                expected_definition_integrity_sha256,
                "expected_definition_integrity_sha256",
            ),
            "asset_scope_sha256": _digest(asset_scope_sha256, "asset_scope_sha256"),
            "credential_profile_sha256": _digest(
                credential_profile_sha256, "credential_profile_sha256"
            ),
            "control_refs": controls,
            "interval_seconds": _integer(
                interval_seconds, "interval_seconds", 60, _MAX_INTERVAL_SECONDS
            ),
            "retention_seconds": retained_for,
        }
        with self._connect() as connection:
            self._begin(connection)
            operation_sha, prior = self._operation(connection, operation_id, request)
            request_sha = _sha256(request)
            if prior is not None:
                row = connection.execute(
                    "SELECT * FROM trc_enrollment_history WHERE tenant_sha256=? "
                    "AND enrollment_id=? AND revision=?",
                    (
                        self._tenant_sha256,
                        str(prior["result_id"]),
                        int(prior["result_revision"]),
                    ),
                ).fetchone()
                if row is None:
                    raise ContinuousEvidenceIntegrityError(
                        "enrollment operation result disappeared"
                    )
                return self._enrollment(row, indexed=False)
            definition_row = connection.execute(
                "SELECT * FROM trc_definitions WHERE tenant_sha256=? "
                "AND definition_id=? AND version=?",
                (
                    self._tenant_sha256,
                    request["definition_id"],
                    request["definition_version"],
                ),
            ).fetchone()
            if definition_row is None:
                raise ContinuousEvidenceNotFound("collector definition not found")
            definition = self._definition(definition_row)
            self._require_latest_source(connection, definition)
            if definition.state != "approved" or not _same(
                definition.integrity_sha256,
                request["expected_definition_integrity_sha256"],
            ):
                raise ContinuousEvidenceConflict(
                    "collector definition is not the exact approved authority"
                )
            if not set(controls).issubset(definition.allowed_control_refs):
                raise ContinuousEvidenceValidationError(
                    "enrollment controls exceed the approved collector definition"
                )
            if definition.source_manifest is not None:
                from .trc_stock_evidence_collectors import managed_source_from_definition

                source = managed_source_from_definition(self._tenant_id, definition)
                if (request["enrollment_id"] != source.enrollment_id or
                        request["asset_scope_sha256"] != source.asset_scope_sha256 or
                        request["credential_profile_sha256"] != source.credential_profile_sha256):
                    raise ContinuousEvidenceConflict("source enrollment does not match its approved scope and account")
            if before_effect is not None:
                before_effect()
            enrollment = CollectorEnrollment(
                enrollment_id=request["enrollment_id"],
                definition_id=definition.definition_id,
                definition_version=definition.version,
                definition_integrity_sha256=definition.integrity_sha256,
                collector_id=definition.collector_id,
                asset_scope_sha256=request["asset_scope_sha256"],
                credential_profile_sha256=request["credential_profile_sha256"],
                control_refs=controls,
                interval_seconds=request["interval_seconds"],
                state="active",
                next_due_at=now,
                revision=1,
                created_at=now,
                updated_at=now,
                retained_until=now + retained_for,
                integrity_sha256="0" * 64,
            )
            integrity = self._insert_record(
                connection,
                "trc_enrollments",
                (
                    self._tenant_sha256,
                    enrollment.enrollment_id,
                    enrollment.state,
                    enrollment.next_due_at,
                    enrollment.revision,
                    enrollment.retained_until,
                ),
                enrollment,
                ENROLLMENT_SCHEMA,
            )
            stored = replace(enrollment, integrity_sha256=integrity)
            self._insert_record(
                connection,
                "trc_enrollment_history",
                (self._tenant_sha256, stored.enrollment_id, stored.revision),
                stored,
                ENROLLMENT_SCHEMA,
            )
            self._save_operation(
                connection,
                self._tenant_sha256,
                operation_sha,
                request_sha,
                "enrollment",
                stored.enrollment_id,
                stored.revision,
                now,
            )
            self._audit(connection, "enrollment_created", integrity, actor, now)
            if before_effect is not None:
                before_effect()
            connection.commit()
            return stored

    def get_enrollment(self, enrollment_id: str) -> CollectorEnrollment:
        self._check_gate()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM trc_enrollments WHERE tenant_sha256=? AND enrollment_id=?",
                (self._tenant_sha256, _id(enrollment_id, "enrollment_id")),
            ).fetchone()
        if row is None:
            raise ContinuousEvidenceNotFound("collector enrollment not found")
        return self._enrollment(row)

    def list_enrollments(self, *, limit: int = 500) -> tuple[CollectorEnrollment, ...]:
        self._check_gate()
        limit = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM trc_enrollments WHERE tenant_sha256=? "
                "ORDER BY enrollment_id LIMIT ?",
                (self._tenant_sha256, limit),
            ).fetchall()
        return tuple(self._enrollment(row) for row in rows)

    def update_enrollment_state(
        self,
        enrollment_id: str,
        *,
        state: str,
        expected_revision: int,
        expected_integrity_sha256: str,
        before_effect: Callable[[], None] | None = None,
    ) -> CollectorEnrollment:
        self._check_gate()
        if state not in _ENROLLMENT_STATES:
            raise ContinuousEvidenceValidationError("enrollment state is invalid")
        actor = self._actor_sha256()
        now = self._now()
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM trc_enrollments WHERE tenant_sha256=? AND enrollment_id=?",
                (self._tenant_sha256, _id(enrollment_id, "enrollment_id")),
            ).fetchone()
            if row is None:
                raise ContinuousEvidenceNotFound("collector enrollment not found")
            current = self._enrollment(row)
            if current.revision != expected_revision or not _same(
                current.integrity_sha256,
                _digest(expected_integrity_sha256, "expected_integrity_sha256"),
            ):
                raise ContinuousEvidenceConflict("collector enrollment changed")
            if current.state == "revoked" and state != "revoked":
                raise ContinuousEvidenceConflict("revoked enrollment cannot be restored")
            if current.state == state:
                return current
            if state == "active":
                definition_row = connection.execute(
                    "SELECT * FROM trc_definitions WHERE tenant_sha256=? "
                    "AND definition_id=? AND version=?",
                    (
                        self._tenant_sha256,
                        current.definition_id,
                        current.definition_version,
                    ),
                ).fetchone()
                definition = None if definition_row is None else self._definition(definition_row)
                if (
                    definition is None
                    or definition.state != "approved"
                    or not _same(
                        definition.integrity_sha256,
                        current.definition_integrity_sha256,
                    )
                ):
                    raise ContinuousEvidenceConflict(
                        "collector definition is not the exact approved authority"
                    )
                self._require_latest_source(connection, definition)
            if before_effect is not None:
                before_effect()
            candidate = replace(
                current,
                state=state,
                revision=current.revision + 1,
                updated_at=now,
            )
            payload = _record_payload(candidate, ENROLLMENT_SCHEMA, self._tenant_sha256)
            integrity = _sha256(payload)
            cursor = connection.execute(
                "UPDATE trc_enrollments SET state=?,next_due_at=?,revision=?,"
                "retained_until=?,payload_json=?,integrity_sha256=? "
                "WHERE tenant_sha256=? AND enrollment_id=? AND revision=? "
                "AND integrity_sha256=?",
                (
                    candidate.state,
                    candidate.next_due_at,
                    candidate.revision,
                    candidate.retained_until,
                    _canonical(payload).decode("ascii"),
                    integrity,
                    self._tenant_sha256,
                    candidate.enrollment_id,
                    current.revision,
                    current.integrity_sha256,
                ),
            )
            if cursor.rowcount != 1:
                raise ContinuousEvidenceConflict("collector enrollment changed")
            stored = replace(candidate, integrity_sha256=integrity)
            self._insert_record(
                connection,
                "trc_enrollment_history",
                (self._tenant_sha256, stored.enrollment_id, stored.revision),
                stored,
                ENROLLMENT_SCHEMA,
            )
            if state in {"paused", "revoked"}:
                queued = connection.execute(
                    "SELECT * FROM trc_jobs WHERE tenant_sha256=? AND enrollment_id=? "
                    "AND state IN ('queued','leased')",
                    (self._tenant_sha256, stored.enrollment_id),
                ).fetchall()
                for job_row in queued:
                    job = self._job(job_row)
                    self._replace_job(
                        connection,
                        job,
                        replace(
                            job,
                            state="cancelled",
                            lease_token_sha256=None,
                            lease_until=None,
                            error_code=(
                                "enrollment_revoked" if state == "revoked" else "enrollment_paused"
                            ),
                            updated_at=now,
                            revision=job.revision + 1,
                        ),
                    )
            self._audit(connection, f"enrollment_{state}", integrity, actor, now)
            if before_effect is not None:
                before_effect()
            connection.commit()
            return stored

    def _replace_enrollment(
        self,
        connection: sqlite3.Connection,
        current: CollectorEnrollment,
        candidate: CollectorEnrollment,
    ) -> CollectorEnrollment:
        payload = _record_payload(candidate, ENROLLMENT_SCHEMA, self._tenant_sha256)
        integrity = _sha256(payload)
        cursor = connection.execute(
            "UPDATE trc_enrollments SET state=?,next_due_at=?,revision=?,retained_until=?,"
            "payload_json=?,integrity_sha256=? WHERE tenant_sha256=? "
            "AND enrollment_id=? AND revision=? AND integrity_sha256=?",
            (
                candidate.state,
                candidate.next_due_at,
                candidate.revision,
                candidate.retained_until,
                _canonical(payload).decode("ascii"),
                integrity,
                self._tenant_sha256,
                current.enrollment_id,
                current.revision,
                current.integrity_sha256,
            ),
        )
        if cursor.rowcount != 1:
            raise ContinuousEvidenceConflict("collector enrollment changed")
        stored = replace(candidate, integrity_sha256=integrity)
        self._insert_record(
            connection,
            "trc_enrollment_history",
            (self._tenant_sha256, stored.enrollment_id, stored.revision),
            stored,
            ENROLLMENT_SCHEMA,
        )
        return stored

    def _replace_job(
        self,
        connection: sqlite3.Connection,
        current: EvidenceJob,
        candidate: EvidenceJob,
    ) -> EvidenceJob:
        payload = _record_payload(candidate, JOB_SCHEMA, self._tenant_sha256)
        integrity = _sha256(payload)
        cursor = connection.execute(
            "UPDATE trc_jobs SET state=?,not_before=?,lease_until=?,revision=?,"
            "retained_until=?,payload_json=?,integrity_sha256=? "
            "WHERE tenant_sha256=? AND job_id=? AND revision=? AND integrity_sha256=?",
            (
                candidate.state,
                candidate.not_before,
                candidate.lease_until,
                candidate.revision,
                candidate.retained_until,
                _canonical(payload).decode("ascii"),
                integrity,
                self._tenant_sha256,
                current.job_id,
                current.revision,
                current.integrity_sha256,
            ),
        )
        if cursor.rowcount != 1:
            raise ContinuousEvidenceConflict("evidence job changed")
        stored = replace(candidate, integrity_sha256=integrity)
        self._insert_record(
            connection,
            "trc_job_history",
            (self._tenant_sha256, stored.job_id, stored.revision),
            stored,
            JOB_SCHEMA,
        )
        return stored

    def enqueue_due(
        self,
        *,
        limit: int = 50,
        max_attempts: int = 5,
        allowed_collector_ids: Sequence[str] | None = None,
    ) -> tuple[EvidenceJob, ...]:
        self._check_gate()
        limit = _integer(limit, "limit", 1, _MAX_CLAIM)
        max_attempts = _integer(max_attempts, "max_attempts", 1, _MAX_ATTEMPTS)
        allowed_collectors = _collector_allowlist(allowed_collector_ids)
        actor = self._actor_sha256()
        created: list[EvidenceJob] = []
        with self._connect() as connection:
            self._begin(connection)
            now = self._now()
            rows = connection.execute(
                "SELECT * FROM trc_enrollments WHERE tenant_sha256=? "
                "AND state='active' AND next_due_at<=? ORDER BY next_due_at,enrollment_id "
                "LIMIT ?",
                (self._tenant_sha256, now, limit),
            ).fetchall()
            for row in rows:
                enrollment = self._enrollment(row)
                live_job = connection.execute(
                    "SELECT 1 FROM trc_jobs WHERE tenant_sha256=? AND enrollment_id=? "
                    "AND state IN ('queued','leased') LIMIT 1",
                    (self._tenant_sha256, enrollment.enrollment_id),
                ).fetchone()
                if live_job is not None:
                    # Scheduling bookkeeping must never invalidate work that is
                    # already queued or leased for this exact enrollment.
                    continue
                definition_row = connection.execute(
                    "SELECT * FROM trc_definitions WHERE tenant_sha256=? "
                    "AND definition_id=? AND version=?",
                    (
                        self._tenant_sha256,
                        enrollment.definition_id,
                        enrollment.definition_version,
                    ),
                ).fetchone()
                definition = None if definition_row is None else self._definition(definition_row)
                if (
                    definition is None
                    or definition.state != "approved"
                    or (
                        allowed_collectors is not None
                        and definition.collector_id not in allowed_collectors
                    )
                    or not _same(
                        definition.integrity_sha256,
                        enrollment.definition_integrity_sha256,
                    )
                ):
                    paused = self._replace_enrollment(
                        connection,
                        enrollment,
                        replace(
                            enrollment,
                            state="paused",
                            updated_at=now,
                            revision=enrollment.revision + 1,
                        ),
                    )
                    self._audit(
                        connection,
                        "enrollment_authority_stale",
                        paused.integrity_sha256,
                        actor,
                        now,
                    )
                    continue
                due_at = enrollment.next_due_at
                job_id = (
                    "job."
                    + _sha256(
                        {
                            "schema": "lightwork.trc-evidence-due-job.v1",
                            "tenant_sha256": self._tenant_sha256,
                            "enrollment_id": enrollment.enrollment_id,
                            "enrollment_revision": enrollment.revision,
                            "due_at": enrollment.next_due_at,
                        }
                    )[:48]
                )
                exists = connection.execute(
                    "SELECT * FROM trc_jobs WHERE tenant_sha256=? AND job_id=?",
                    (self._tenant_sha256, job_id),
                ).fetchone()
                if exists is not None:
                    continue
                retention_window = max(
                    _MIN_RETENTION_SECONDS,
                    enrollment.retained_until - enrollment.updated_at,
                )
                # One collection requests the elapsed window. Continue the
                # original cadence after now instead of replaying each missed
                # interval as another collection of overlapping current data.
                intervals = math.floor((now - due_at) / enrollment.interval_seconds) + 1
                next_due_at = _timestamp(
                    due_at + intervals * enrollment.interval_seconds, "next_due_at",
                )
                if next_due_at <= now:
                    raise ContinuousEvidenceValidationError(
                        "the next collection time cannot advance at this clock value"
                    )
                scheduled_enrollment = self._replace_enrollment(
                    connection,
                    enrollment,
                    replace(
                        enrollment,
                        next_due_at=next_due_at,
                        updated_at=now,
                        retained_until=max(next_due_at, now + retention_window),
                        revision=enrollment.revision + 1,
                    ),
                )
                job = EvidenceJob(
                    job_id=job_id,
                    enrollment_id=scheduled_enrollment.enrollment_id,
                    enrollment_revision=scheduled_enrollment.revision,
                    enrollment_integrity_sha256=scheduled_enrollment.integrity_sha256,
                    state="queued",
                    attempt=0,
                    max_attempts=max_attempts,
                    not_before=now,
                    lease_token_sha256=None,
                    lease_until=None,
                    error_code=None,
                    requested_window_started_at=max(
                        scheduled_enrollment.created_at,
                        due_at - scheduled_enrollment.interval_seconds,
                    ),
                    requested_window_ended_at=now,
                    created_at=now,
                    updated_at=now,
                    retained_until=min(
                        scheduled_enrollment.retained_until,
                        now + retention_window,
                    ),
                    revision=1,
                    integrity_sha256="0" * 64,
                )
                integrity = self._insert_record(
                    connection,
                    "trc_jobs",
                    (
                        self._tenant_sha256,
                        job.job_id,
                        job.enrollment_id,
                        job.state,
                        job.not_before,
                        job.lease_until,
                        job.revision,
                        job.retained_until,
                    ),
                    job,
                    JOB_SCHEMA,
                )
                stored = replace(job, integrity_sha256=integrity)
                self._insert_record(
                    connection,
                    "trc_job_history",
                    (self._tenant_sha256, stored.job_id, stored.revision),
                    stored,
                    JOB_SCHEMA,
                )
                self._audit(connection, "job_enqueued", integrity, actor, now)
                created.append(stored)
            connection.commit()
        return tuple(created)

    def claim_jobs(
        self,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: int = 60,
    ) -> tuple[ClaimedEvidenceJob, ...]:
        self._check_gate()
        worker = _id(worker_id, "worker_id")
        limit = _integer(limit, "limit", 1, _MAX_CLAIM)
        lease_seconds = _integer(lease_seconds, "lease_seconds", 1, _MAX_LEASE_SECONDS)
        actor = self._actor_sha256()
        now = self._now()
        results: list[ClaimedEvidenceJob] = []
        with self._connect() as connection:
            self._begin(connection)
            expired = connection.execute(
                "SELECT * FROM trc_jobs WHERE tenant_sha256=? AND state='leased' "
                "AND lease_until<=? ORDER BY lease_until LIMIT ?",
                (self._tenant_sha256, now, _MAX_CLAIM),
            ).fetchall()
            for row in expired:
                job = self._job(row)
                next_state = "dead_letter" if job.attempt >= job.max_attempts else "queued"
                recovered = self._replace_job(
                    connection,
                    job,
                    replace(
                        job,
                        state=next_state,
                        not_before=now,
                        lease_token_sha256=None,
                        lease_until=None,
                        error_code="lease_expired",
                        updated_at=now,
                        revision=job.revision + 1,
                    ),
                )
                self._audit(
                    connection,
                    "job_dead_lettered" if next_state == "dead_letter" else "job_lease_recovered",
                    recovered.integrity_sha256,
                    actor,
                    now,
                )
            rows = connection.execute(
                "SELECT * FROM trc_jobs WHERE tenant_sha256=? AND state='queued' "
                "AND not_before<=? ORDER BY not_before,job_id LIMIT ?",
                (self._tenant_sha256, now, limit),
            ).fetchall()
            for row in rows:
                job = self._job(row)
                enrollment_row = connection.execute(
                    "SELECT * FROM trc_enrollments WHERE tenant_sha256=? AND enrollment_id=?",
                    (self._tenant_sha256, job.enrollment_id),
                ).fetchone()
                if enrollment_row is None:
                    cancelled = self._replace_job(
                        connection,
                        job,
                        replace(
                            job,
                            state="cancelled",
                            error_code="enrollment_missing",
                            updated_at=now,
                            revision=job.revision + 1,
                        ),
                    )
                    self._audit(
                        connection,
                        "job_cancelled",
                        cancelled.integrity_sha256,
                        actor,
                        now,
                    )
                    continue
                enrollment = self._enrollment(enrollment_row)
                if (
                    enrollment.state != "active"
                    or enrollment.revision != job.enrollment_revision
                    or not _same(
                        enrollment.integrity_sha256,
                        job.enrollment_integrity_sha256,
                    )
                ):
                    cancelled = self._replace_job(
                        connection,
                        job,
                        replace(
                            job,
                            state="cancelled",
                            error_code="enrollment_drift",
                            updated_at=now,
                            revision=job.revision + 1,
                        ),
                    )
                    self._audit(
                        connection,
                        "job_cancelled",
                        cancelled.integrity_sha256,
                        actor,
                        now,
                    )
                    continue
                definition_row = connection.execute(
                    "SELECT * FROM trc_definitions WHERE tenant_sha256=? "
                    "AND definition_id=? AND version=?",
                    (
                        self._tenant_sha256,
                        enrollment.definition_id,
                        enrollment.definition_version,
                    ),
                ).fetchone()
                definition = None if definition_row is None else self._definition(definition_row)
                if (
                    definition is None
                    or definition.state != "approved"
                    or not _same(
                        definition.integrity_sha256,
                        enrollment.definition_integrity_sha256,
                    )
                ):
                    cancelled = self._replace_job(
                        connection,
                        job,
                        replace(
                            job,
                            state="cancelled",
                            error_code="definition_drift",
                            updated_at=now,
                            revision=job.revision + 1,
                        ),
                    )
                    self._audit(
                        connection,
                        "job_cancelled",
                        cancelled.integrity_sha256,
                        actor,
                        now,
                    )
                    continue
                token = _token(self._lease_token_factory())
                leased = self._replace_job(
                    connection,
                    job,
                    replace(
                        job,
                        state="leased",
                        attempt=job.attempt + 1,
                        lease_token_sha256=hashlib.sha256(token.encode("ascii")).hexdigest(),
                        lease_until=now + lease_seconds,
                        error_code=None,
                        updated_at=now,
                        revision=job.revision + 1,
                    ),
                )
                self._audit(
                    connection,
                    "job_claimed",
                    leased.integrity_sha256,
                    _sha256(
                        {
                            "schema": "lightwork.trc-evidence-worker.v1",
                            "actor_sha256": actor,
                            "worker_id": worker,
                        }
                    ),
                    now,
                )
                results.append(ClaimedEvidenceJob(leased, token))
            connection.commit()
        return tuple(results)

    def get_job(self, job_id: str) -> EvidenceJob:
        self._check_gate()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM trc_jobs WHERE tenant_sha256=? AND job_id=?",
                (self._tenant_sha256, _id(job_id, "job_id")),
            ).fetchone()
        if row is None:
            raise ContinuousEvidenceNotFound("evidence job not found")
        return self._job(row)

    def list_jobs(
        self,
        *,
        state: str | None = None,
        limit: int = 500,
    ) -> tuple[EvidenceJob, ...]:
        self._check_gate()
        limit = _integer(limit, "limit", 1, 1_000)
        query = "SELECT * FROM trc_jobs WHERE tenant_sha256=?"
        values: list[object] = [self._tenant_sha256]
        if state is not None:
            if state not in _JOB_STATES:
                raise ContinuousEvidenceValidationError("evidence job state is invalid")
            query += " AND state=?"
            values.append(state)
        query += " ORDER BY not_before DESC,job_id DESC LIMIT ?"
        values.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, values).fetchall()
        return tuple(self._job(row) for row in rows)

    def fail_job(
        self,
        job_id: str,
        *,
        lease_token: str,
        error_code: str,
        backoff_seconds: int,
    ) -> EvidenceJob:
        self._check_gate()
        token = _token(lease_token)
        error = _error_code(error_code)
        backoff = _integer(backoff_seconds, "backoff_seconds", 1, 86_400)
        actor = self._actor_sha256()
        now = self._now()
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM trc_jobs WHERE tenant_sha256=? AND job_id=?",
                (self._tenant_sha256, _id(job_id, "job_id")),
            ).fetchone()
            if row is None:
                raise ContinuousEvidenceNotFound("evidence job not found")
            current = self._job(row)
            if (
                current.state != "leased"
                or current.lease_until is None
                or current.lease_until <= now
            ):
                raise ContinuousEvidenceLeaseLost("evidence job lease is not active")
            token_sha = hashlib.sha256(token.encode("ascii")).hexdigest()
            if current.lease_token_sha256 is None or not _same(
                current.lease_token_sha256, token_sha
            ):
                raise ContinuousEvidenceLeaseLost("evidence job lease is not owned")
            state = "dead_letter" if current.attempt >= current.max_attempts else "queued"
            stored = self._replace_job(
                connection,
                current,
                replace(
                    current,
                    state=state,
                    not_before=now + backoff if state == "queued" else now,
                    lease_token_sha256=None,
                    lease_until=None,
                    error_code=error,
                    updated_at=now,
                    revision=current.revision + 1,
                ),
            )
            self._audit(connection, "job_failed", stored.integrity_sha256, actor, now)
            connection.commit()
            return stored

    def requeue_dead_letter(
        self,
        job_id: str,
        *,
        expected_revision: int,
        operation_id: str,
    ) -> EvidenceJob:
        self._check_gate()
        actor = self._actor_sha256()
        now = self._now()
        request = {
            "schema": "lightwork.trc-evidence-requeue-request.v1",
            "job_id": _id(job_id, "job_id"),
            "expected_revision": _integer(expected_revision, "expected_revision", 1, 2**31 - 1),
        }
        with self._connect() as connection:
            self._begin(connection)
            operation_sha, prior = self._operation(connection, operation_id, request)
            if prior is not None:
                row = connection.execute(
                    "SELECT * FROM trc_job_history WHERE tenant_sha256=? "
                    "AND job_id=? AND revision=?",
                    (
                        self._tenant_sha256,
                        str(prior["result_id"]),
                        int(prior["result_revision"]),
                    ),
                ).fetchone()
                if row is None:
                    raise ContinuousEvidenceIntegrityError("requeue operation result disappeared")
                return self._job(row, indexed=False)
            row = connection.execute(
                "SELECT * FROM trc_jobs WHERE tenant_sha256=? AND job_id=?",
                (self._tenant_sha256, request["job_id"]),
            ).fetchone()
            if row is None:
                raise ContinuousEvidenceNotFound("evidence job not found")
            current = self._job(row)
            if current.state != "dead_letter" or current.revision != expected_revision:
                raise ContinuousEvidenceConflict("evidence job is not replayable")
            stored = self._replace_job(
                connection,
                current,
                replace(
                    current,
                    state="queued",
                    attempt=0,
                    not_before=now,
                    error_code=None,
                    updated_at=now,
                    revision=current.revision + 1,
                ),
            )
            self._save_operation(
                connection,
                self._tenant_sha256,
                operation_sha,
                _sha256(request),
                "job",
                stored.job_id,
                stored.revision,
                now,
            )
            self._audit(connection, "job_requeued", stored.integrity_sha256, actor, now)
            connection.commit()
            return stored

    def cancel_claim(
        self,
        job_id: str,
        *,
        lease_token: str,
        error_code: str = "collector_authority_changed",
    ) -> EvidenceJob:
        """Fail closed an exact live claim without leaving a stale lease behind."""

        self._check_gate()
        token = _token(lease_token)
        error = _error_code(error_code)
        actor = self._actor_sha256()
        now = self._now()
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM trc_jobs WHERE tenant_sha256=? AND job_id=?",
                (self._tenant_sha256, _id(job_id, "job_id")),
            ).fetchone()
            if row is None:
                raise ContinuousEvidenceNotFound("evidence job not found")
            current = self._job(row)
            token_sha = hashlib.sha256(token.encode("ascii")).hexdigest()
            if (
                current.state != "leased"
                or current.lease_until is None
                or current.lease_until <= now
                or current.lease_token_sha256 is None
                or not _same(current.lease_token_sha256, token_sha)
            ):
                raise ContinuousEvidenceLeaseLost("evidence job lease is not active")
            stored = self._replace_job(
                connection,
                current,
                replace(
                    current,
                    state="cancelled",
                    lease_token_sha256=None,
                    lease_until=None,
                    error_code=error,
                    updated_at=now,
                    revision=current.revision + 1,
                ),
            )
            self._audit(connection, "job_cancelled", stored.integrity_sha256, actor, now)
            connection.commit()
            return stored

    def complete_collection(
        self,
        *,
        claimed: ClaimedEvidenceJob,
        definition: CollectorDefinition,
        enrollment: CollectorEnrollment,
        pages: Sequence[EvidencePage],
        observations: Sequence[ControlEvidence],
        complete: bool,
        incomplete_reason: str | None,
        started_at: float,
    ) -> CollectionOutcome:
        """Atomically persist a double-read-pinned, normalized collection."""

        self._check_gate()
        if not pages or len(pages) > _MAX_PAGES:
            raise ContinuousEvidenceValidationError("page count is outside its bound")
        if len(observations) > _MAX_ITEMS:
            raise ContinuousEvidenceValidationError("item count exceeds its bound")
        validated_pages = tuple(
            validate_page(page, expected_controls=enrollment.control_refs) for page in pages
        )
        if any(page.terminal for page in validated_pages[:-1]):
            raise ContinuousEvidenceValidationError(
                "collection contains a page after a terminal provider page"
            )
        terminal = validated_pages[-1].terminal
        if not terminal and len(validated_pages) != _MAX_PAGES:
            raise ContinuousEvidenceValidationError(
                "non-terminal collection did not exhaust its page bound"
            )
        page_items: dict[str, ControlEvidence] = {}
        total_page_items = 0
        for page in validated_pages:
            total_page_items += len(page.items)
            for item in page.items:
                prior = page_items.get(item.control_ref)
                if prior is not None and prior != item:
                    raise ContinuousEvidenceValidationError(
                        "collector pages contain conflicting observations"
                    )
                page_items[item.control_ref] = item
        if total_page_items > _MAX_ITEMS:
            raise ContinuousEvidenceValidationError("collection page items exceed their bound")
        supplied_items: dict[str, ControlEvidence] = {}
        for item in observations:
            if not isinstance(item, ControlEvidence) or item.control_ref in supplied_items:
                raise ContinuousEvidenceValidationError(
                    "collection observations are invalid or duplicated"
                )
            supplied_items[item.control_ref] = item
        if supplied_items != page_items:
            raise ContinuousEvidenceValidationError(
                "collection observations do not exactly match provider pages"
            )
        actual_complete = (
            terminal
            and validated_pages[-1].complete
            and set(page_items) == set(enrollment.control_refs)
        )
        expected_incomplete_reason = (
            None
            if actual_complete
            else (
                validated_pages[-1].incomplete_reason or "coverage_unknown"
                if terminal
                else "provider_truncated"
            )
        )
        if complete != actual_complete or incomplete_reason != expected_incomplete_reason:
            raise ContinuousEvidenceValidationError(
                "collection completeness is not supported by its provider pages"
            )
        actor = self._actor_sha256()
        now = self._now()
        token = _token(claimed.lease_token)
        token_sha = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._connect() as connection:
            self._begin(connection)
            job_row = connection.execute(
                "SELECT * FROM trc_jobs WHERE tenant_sha256=? AND job_id=?",
                (self._tenant_sha256, claimed.job.job_id),
            ).fetchone()
            enrollment_row = connection.execute(
                "SELECT * FROM trc_enrollments WHERE tenant_sha256=? AND enrollment_id=?",
                (self._tenant_sha256, enrollment.enrollment_id),
            ).fetchone()
            definition_row = connection.execute(
                "SELECT * FROM trc_definitions WHERE tenant_sha256=? "
                "AND definition_id=? AND version=?",
                (
                    self._tenant_sha256,
                    definition.definition_id,
                    definition.version,
                ),
            ).fetchone()
            if job_row is None or enrollment_row is None or definition_row is None:
                raise ContinuousEvidenceConflict("collection authority disappeared")
            current_job = self._job(job_row)
            current_enrollment = self._enrollment(enrollment_row)
            current_definition = self._definition(definition_row)
            if (
                current_job.state != "leased"
                or current_job.lease_until is None
                or current_job.lease_until <= now
                or current_job.lease_token_sha256 is None
                or not _same(current_job.lease_token_sha256, token_sha)
            ):
                raise ContinuousEvidenceLeaseLost("evidence job lease is not active")
            if (
                current_enrollment.state != "active"
                or current_definition.state != "approved"
                or not _same(
                    current_enrollment.integrity_sha256,
                    enrollment.integrity_sha256,
                )
                or not _same(
                    current_definition.integrity_sha256,
                    definition.integrity_sha256,
                )
                or not _same(
                    current_job.enrollment_integrity_sha256,
                    enrollment.integrity_sha256,
                )
            ):
                raise ContinuousEvidenceConflict("collector authority changed during collection")
            page_values = list(validated_pages)
            byte_count = sum(int(page.bytes_read) for page in page_values)
            if byte_count > _MAX_TOTAL_BYTES:
                raise ContinuousEvidenceValidationError("collection bytes exceed their bound")
            coverage = {
                "schema": "lightwork.trc-evidence-coverage-manifest.v1",
                "enrollment_integrity_sha256": enrollment.integrity_sha256,
                "definition_integrity_sha256": definition.integrity_sha256,
                "control_refs": enrollment.control_refs,
                "observed_control_refs": tuple(sorted(item.control_ref for item in observations)),
                "complete": complete,
                "incomplete_reason": incomplete_reason,
                "page_count": len(page_values),
                "item_count": len(observations),
                "byte_count": byte_count,
            }
            artifact_manifest = {
                "schema": "lightwork.trc-evidence-artifact-manifest.v1",
                "page_artifact_sha256": tuple(str(page.artifact_sha256) for page in page_values),
                "source_revision_sha256": tuple(
                    str(page.source_revision_sha256) for page in page_values
                ),
                "provider_request_sha256": tuple(
                    str(page.provider_request_sha256) for page in page_values
                ),
            }
            run_id = "run." + current_job.job_id.removeprefix("job.")
            run = EvidenceRun(
                run_id=run_id,
                job_id=current_job.job_id,
                enrollment_id=enrollment.enrollment_id,
                enrollment_revision=enrollment.revision,
                definition_id=definition.definition_id,
                definition_version=definition.version,
                collector_id=definition.collector_id,
                state="complete" if complete else "incomplete",
                complete=complete,
                incomplete_reason=incomplete_reason,
                page_count=len(page_values),
                item_count=len(observations),
                byte_count=byte_count,
                terminal_cursor_sha256=_sha256(
                    {
                        "schema": "lightwork.trc-evidence-terminal-cursor.v1",
                        "terminal": bool(page_values[-1].terminal),
                        "cursor": page_values[-1].next_cursor,
                    }
                ),
                coverage_manifest_sha256=_sha256(coverage),
                artifact_manifest_sha256=_sha256(artifact_manifest),
                started_at=_timestamp(started_at, "started_at"),
                completed_at=now,
                retained_until=min(
                    enrollment.retained_until,
                    now + self._default_retention_seconds,
                ),
                integrity_sha256="0" * 64,
            )
            run_integrity = self._insert_record(
                connection,
                "trc_runs",
                (
                    self._tenant_sha256,
                    run.run_id,
                    run.job_id,
                    run.enrollment_id,
                    run.completed_at,
                    run.retained_until,
                ),
                run,
                RUN_SCHEMA,
            )
            stored_run = replace(run, integrity_sha256=run_integrity)
            stored_observations: list[EvidenceObservation] = []
            stored_alerts: list[EvidenceChangeAlert] = []
            for item in observations:
                prior_row = connection.execute(
                    "SELECT * FROM trc_observations WHERE tenant_sha256=? "
                    "AND enrollment_id=? AND control_ref=? "
                    "ORDER BY observed_at DESC,observation_id DESC LIMIT 1",
                    (self._tenant_sha256, enrollment.enrollment_id, item.control_ref),
                ).fetchone()
                observation_id = (
                    "obs."
                    + _sha256(
                        {
                            "schema": "lightwork.trc-evidence-observation-id.v1",
                            "run_id": run.run_id,
                            "control_ref": item.control_ref,
                        }
                    )[:48]
                )
                observation = EvidenceObservation(
                    observation_id=observation_id,
                    run_id=run.run_id,
                    enrollment_id=enrollment.enrollment_id,
                    control_ref=item.control_ref,
                    status=item.status,
                    reason_code=item.reason_code,
                    evidence_sha256=item.evidence_sha256,
                    source_revision_sha256=item.source_revision_sha256,
                    observed_at=now,
                    retained_until=run.retained_until,
                    integrity_sha256="0" * 64,
                )
                obs_integrity = self._insert_record(
                    connection,
                    "trc_observations",
                    (
                        self._tenant_sha256,
                        observation.observation_id,
                        observation.run_id,
                        observation.enrollment_id,
                        observation.control_ref,
                        observation.observed_at,
                        observation.retained_until,
                    ),
                    observation,
                    OBSERVATION_SCHEMA,
                )
                stored_observation = replace(observation, integrity_sha256=obs_integrity)
                stored_observations.append(stored_observation)
                if prior_row is not None:
                    prior = self._observation(prior_row)
                    if prior.status != stored_observation.status or not _same(
                        prior.evidence_sha256,
                        stored_observation.evidence_sha256,
                    ):
                        alert_id = (
                            "alert."
                            + _sha256(
                                {
                                    "schema": "lightwork.trc-evidence-alert-id.v1",
                                    "previous": prior.integrity_sha256,
                                    "current": stored_observation.integrity_sha256,
                                }
                            )[:48]
                        )
                        alert = EvidenceChangeAlert(
                            alert_id=alert_id,
                            enrollment_id=enrollment.enrollment_id,
                            control_ref=item.control_ref,
                            previous_observation_sha256=prior.integrity_sha256,
                            current_observation_sha256=stored_observation.integrity_sha256,
                            previous_status=prior.status,
                            current_status=stored_observation.status,
                            created_at=now,
                            retained_until=run.retained_until,
                            integrity_sha256="0" * 64,
                        )
                        alert_integrity = self._insert_record(
                            connection,
                            "trc_alerts",
                            (
                                self._tenant_sha256,
                                alert.alert_id,
                                alert.enrollment_id,
                                alert.control_ref,
                                alert.created_at,
                                alert.retained_until,
                            ),
                            alert,
                            ALERT_SCHEMA,
                        )
                        stored_alerts.append(replace(alert, integrity_sha256=alert_integrity))
            stored_job = self._replace_job(
                connection,
                current_job,
                replace(
                    current_job,
                    state="completed" if complete else "incomplete",
                    lease_token_sha256=None,
                    lease_until=None,
                    error_code=None if complete else "collection_incomplete",
                    updated_at=now,
                    revision=current_job.revision + 1,
                ),
            )
            self._audit(
                connection,
                "collection_completed" if complete else "collection_incomplete",
                stored_run.integrity_sha256,
                actor,
                now,
            )
            connection.commit()
            return CollectionOutcome(
                job=stored_job,
                run=stored_run,
                observations=tuple(stored_observations),
                alerts=tuple(stored_alerts),
            )

    def list_runs(self, *, limit: int = 100) -> tuple[EvidenceRun, ...]:
        self._check_gate()
        limit = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM trc_runs WHERE tenant_sha256=? "
                "ORDER BY completed_at DESC,run_id DESC LIMIT ?",
                (self._tenant_sha256, limit),
            ).fetchall()
        return tuple(self._run(row) for row in rows)

    def list_observations(
        self,
        *,
        enrollment_id: str | None = None,
        limit: int = 500,
    ) -> tuple[EvidenceObservation, ...]:
        self._check_gate()
        limit = _integer(limit, "limit", 1, 1_000)
        query = "SELECT * FROM trc_observations WHERE tenant_sha256=?"
        values: list[object] = [self._tenant_sha256]
        if enrollment_id is not None:
            query += " AND enrollment_id=?"
            values.append(_id(enrollment_id, "enrollment_id"))
        query += " ORDER BY observed_at DESC,observation_id DESC LIMIT ?"
        values.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, values).fetchall()
        return tuple(self._observation(row) for row in rows)

    def list_alerts(self, *, limit: int = 500) -> tuple[EvidenceChangeAlert, ...]:
        self._check_gate()
        limit = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM trc_alerts WHERE tenant_sha256=? "
                "ORDER BY created_at DESC,alert_id DESC LIMIT ?",
                (self._tenant_sha256, limit),
            ).fetchall()
        return tuple(self._alert(row) for row in rows)

    def purge_expired(
        self,
        *,
        cutoff: float,
        limit: int = 500,
    ) -> RetentionPurgeResult:
        """Purge bounded expired evidence while preserving the audit chain."""

        self._check_gate()
        actor = self._actor_sha256()
        now = self._now()
        selected_cutoff = _timestamp(cutoff, "cutoff")
        if selected_cutoff > now:
            raise ContinuousEvidenceValidationError("retention cutoff is in the future")
        limit = _integer(limit, "limit", 1, 500)
        counts = {
            "alerts": 0,
            "observations": 0,
            "runs": 0,
            "jobs": 0,
            "enrollments": 0,
        }
        with self._authorized_retention(), self._connect() as connection:
            self._begin(connection)

            def identifiers(table: str, column: str, condition: str = "") -> list[str]:
                rows = connection.execute(
                    f"SELECT {column} FROM {table} WHERE tenant_sha256=? "  # noqa: S608
                    f"AND retained_until<=? {condition} ORDER BY retained_until LIMIT ?",
                    (self._tenant_sha256, selected_cutoff, limit),
                ).fetchall()
                return [str(row[column]) for row in rows]

            for table, column, count_key in (
                ("trc_alerts", "alert_id", "alerts"),
                ("trc_observations", "observation_id", "observations"),
            ):
                values = identifiers(table, column)
                for value in values:
                    connection.execute(
                        f"DELETE FROM {table} WHERE tenant_sha256=? AND {column}=?",  # noqa: S608
                        (self._tenant_sha256, value),
                    )
                counts[count_key] = len(values)

            run_ids = identifiers(
                "trc_runs",
                "run_id",
                "AND NOT EXISTS(SELECT 1 FROM trc_observations o WHERE "
                "o.tenant_sha256=trc_runs.tenant_sha256 AND "
                "o.run_id=trc_runs.run_id)",
            )
            for run_id in run_ids:
                connection.execute(
                    "DELETE FROM trc_runs WHERE tenant_sha256=? AND run_id=?",
                    (self._tenant_sha256, run_id),
                )
            counts["runs"] = len(run_ids)

            job_ids = identifiers(
                "trc_jobs",
                "job_id",
                "AND state IN ('completed','incomplete','dead_letter','cancelled') "
                "AND NOT EXISTS(SELECT 1 FROM trc_runs r WHERE "
                "r.tenant_sha256=trc_jobs.tenant_sha256 AND r.job_id=trc_jobs.job_id)",
            )
            for job_id in job_ids:
                connection.execute(
                    "DELETE FROM trc_operations WHERE tenant_sha256=? "
                    "AND result_kind='job' AND result_id=?",
                    (self._tenant_sha256, job_id),
                )
                connection.execute(
                    "DELETE FROM trc_job_history WHERE tenant_sha256=? AND job_id=?",
                    (self._tenant_sha256, job_id),
                )
                connection.execute(
                    "DELETE FROM trc_jobs WHERE tenant_sha256=? AND job_id=?",
                    (self._tenant_sha256, job_id),
                )
            counts["jobs"] = len(job_ids)

            enrollment_rows = connection.execute(
                "SELECT enrollment_id FROM trc_enrollments WHERE tenant_sha256=? "
                "AND state='revoked' AND retained_until<=? "
                "AND NOT EXISTS(SELECT 1 FROM trc_jobs j WHERE "
                "j.tenant_sha256=trc_enrollments.tenant_sha256 AND "
                "j.enrollment_id=trc_enrollments.enrollment_id) "
                "ORDER BY retained_until LIMIT ?",
                (self._tenant_sha256, selected_cutoff, limit),
            ).fetchall()
            enrollment_ids = [str(row["enrollment_id"]) for row in enrollment_rows]
            for enrollment_id in enrollment_ids:
                connection.execute(
                    "DELETE FROM trc_operations WHERE tenant_sha256=? "
                    "AND result_kind='enrollment' AND result_id=?",
                    (self._tenant_sha256, enrollment_id),
                )
                connection.execute(
                    "DELETE FROM trc_enrollment_history WHERE tenant_sha256=? AND enrollment_id=?",
                    (self._tenant_sha256, enrollment_id),
                )
                connection.execute(
                    "DELETE FROM trc_enrollments WHERE tenant_sha256=? AND enrollment_id=?",
                    (self._tenant_sha256, enrollment_id),
                )
            counts["enrollments"] = len(enrollment_ids)
            result = RetentionPurgeResult(cutoff=selected_cutoff, **counts)
            self._audit(
                connection,
                "retention_purged",
                _sha256(
                    {
                        "schema": "lightwork.trc-evidence-retention-purge.v1",
                        **asdict(result),
                    }
                ),
                actor,
                now,
            )
            connection.commit()
        return result

    def unified_audit_records(self):
        """Return the canonical continuous-evidence audit as digest-only records."""

        from .unified_audit import GENESIS_SHA256, build_source_record

        # Verify the complete persisted graph first; the page reader performs a
        # second capture and rejects drift before accepting any projection.
        self.verify_integrity()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM trc_audit WHERE tenant_sha256=? ORDER BY sequence",
                (self._tenant_sha256,),
            ).fetchall()
        previous_integrity = GENESIS_SHA256
        previous_record = GENESIS_SHA256
        records = []
        for expected_sequence, row in enumerate(rows, start=1):
            payload, integrity = self._decode(row, "evidence audit")
            action_name = str(payload.get("action") or "")
            if (
                payload.get("schema") != AUDIT_SCHEMA
                or payload.get("tenant_sha256") != self._tenant_sha256
                or payload.get("sequence") != expected_sequence
                or int(row["sequence"]) != expected_sequence
                or payload.get("previous_integrity_sha256")
                != previous_integrity
            ):
                raise ContinuousEvidenceIntegrityError(
                    "continuous-evidence audit chain is discontinuous"
                )
            actor_sha256 = _digest(
                payload.get("actor_sha256"),
                "audit actor_sha256",
            )
            subject_sha256 = _digest(
                payload.get("subject_sha256"),
                "audit subject_sha256",
            )
            source_action = (
                "approval_granted"
                if "approved" in action_name
                else "evidence_recorded"
                if any(
                    token in action_name
                    for token in ("collection", "observation", "run_completed")
                )
                else "control_evaluated"
                if "definition" in action_name
                else "status_changed"
            )
            record = build_source_record(
                sequence=expected_sequence,
                occurred_at=float(payload["created_at"]),
                action=source_action,
                actor_sha256=actor_sha256,
                resource_sha256=subject_sha256,
                payload_sha256=integrity,
                previous_sha256=previous_record,
            )
            records.append(record)
            previous_integrity = integrity
            previous_record = record.record_sha256
        return tuple(records)

    def verify_integrity(self) -> IntegrityVerification:
        self._check_gate()
        try:
            return self._verify_integrity()
        except ContinuousEvidenceIntegrityError:
            raise
        except (
            ContinuousEvidenceValidationError,
            KeyError,
            TypeError,
            ValueError,
            UnicodeError,
            sqlite3.DatabaseError,
        ) as exc:
            raise ContinuousEvidenceIntegrityError(
                "continuous-evidence persisted state is invalid"
            ) from exc

    def _verify_integrity(  # noqa: C901 - one complete persisted-graph verifier
        self,
    ) -> IntegrityVerification:
        with self._connect() as connection:
            definition_rows = connection.execute(
                "SELECT * FROM trc_definitions WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchall()
            enrollment_rows = connection.execute(
                "SELECT * FROM trc_enrollments WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchall()
            job_rows = connection.execute(
                "SELECT * FROM trc_jobs WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchall()
            run_rows = connection.execute(
                "SELECT * FROM trc_runs WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchall()
            observation_rows = connection.execute(
                "SELECT * FROM trc_observations WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchall()
            alert_rows = connection.execute(
                "SELECT * FROM trc_alerts WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchall()
            definitions = {
                (item.definition_id, item.version): item
                for item in (self._definition(row) for row in definition_rows)
            }
            enrollments = {
                item.enrollment_id: item
                for item in (self._enrollment(row) for row in enrollment_rows)
            }
            jobs = {item.job_id: item for item in (self._job(row) for row in job_rows)}
            runs = {item.run_id: item for item in (self._run(row) for row in run_rows)}
            observations = {
                item.observation_id: item
                for item in (self._observation(row) for row in observation_rows)
            }
            for row in alert_rows:
                self._alert(row)

            definition_history_rows = connection.execute(
                "SELECT * FROM trc_definition_history WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchall()
            definition_histories: dict[tuple[str, int], dict[str, CollectorDefinition]] = {}
            for row in definition_history_rows:
                item = self._definition(row)
                definition_histories.setdefault((item.definition_id, item.version), {})[
                    item.state
                ] = item
            expected_definition_states = {
                "pending": {"pending"},
                "approved": {"pending", "approved"},
                "retired": {"pending", "approved", "retired"},
            }
            for key, current in definitions.items():
                history = definition_histories.get(key)
                if (
                    history is None
                    or set(history) != expected_definition_states[current.state]
                    or history[current.state] != current
                ):
                    raise ContinuousEvidenceIntegrityError(
                        "collector definition history is incomplete"
                    )
            if set(definition_histories) != set(definitions):
                raise ContinuousEvidenceIntegrityError("collector definition history is orphaned")

            enrollment_history_rows = connection.execute(
                "SELECT * FROM trc_enrollment_history WHERE tenant_sha256=? "
                "ORDER BY enrollment_id,revision",
                (self._tenant_sha256,),
            ).fetchall()
            enrollment_histories: dict[str, list[CollectorEnrollment]] = {}
            for row in enrollment_history_rows:
                item = self._enrollment(row, indexed=False)
                enrollment_histories.setdefault(item.enrollment_id, []).append(item)
            for enrollment_id, current in enrollments.items():
                history = enrollment_histories.get(enrollment_id, [])
                if (
                    not history
                    or history[-1] != current
                    or tuple(item.revision for item in history)
                    != tuple(range(1, current.revision + 1))
                ):
                    raise ContinuousEvidenceIntegrityError(
                        "collector enrollment history is discontinuous"
                    )
            if set(enrollment_histories) != set(enrollments):
                raise ContinuousEvidenceIntegrityError("collector enrollment history is orphaned")

            job_history_rows = connection.execute(
                "SELECT * FROM trc_job_history WHERE tenant_sha256=? ORDER BY job_id,revision",
                (self._tenant_sha256,),
            ).fetchall()
            job_histories: dict[str, list[EvidenceJob]] = {}
            for row in job_history_rows:
                item = self._job(row, indexed=False)
                job_histories.setdefault(item.job_id, []).append(item)
            for job_id, current in jobs.items():
                history = job_histories.get(job_id, [])
                if (
                    not history
                    or history[-1] != current
                    or tuple(item.revision for item in history)
                    != tuple(range(1, current.revision + 1))
                ):
                    raise ContinuousEvidenceIntegrityError("evidence job history is discontinuous")
            if set(job_histories) != set(jobs):
                raise ContinuousEvidenceIntegrityError("evidence job history is orphaned")

            definition_integrities = {
                (definition_id, version): {item.integrity_sha256 for item in history.values()}
                for (definition_id, version), history in definition_histories.items()
            }
            enrollment_by_revision = {
                (enrollment_id, item.revision): item
                for enrollment_id, history in enrollment_histories.items()
                for item in history
            }
            job_by_revision = {
                (job_id, item.revision): item
                for job_id, history in job_histories.items()
                for item in history
            }
            for enrollment in enrollments.values():
                if enrollment.definition_integrity_sha256 not in definition_integrities.get(
                    (enrollment.definition_id, enrollment.definition_version),
                    set(),
                ):
                    raise ContinuousEvidenceIntegrityError(
                        "collector enrollment definition binding is invalid"
                    )
            for job in jobs.values():
                enrollment = enrollment_by_revision.get(
                    (job.enrollment_id, job.enrollment_revision)
                )
                if enrollment is None or not _same(
                    enrollment.integrity_sha256,
                    job.enrollment_integrity_sha256,
                ):
                    raise ContinuousEvidenceIntegrityError(
                        "evidence job enrollment binding is invalid"
                    )
            for run in runs.values():
                job = jobs.get(run.job_id)
                enrollment = enrollment_by_revision.get(
                    (run.enrollment_id, run.enrollment_revision)
                )
                if (
                    job is None
                    or enrollment is None
                    or job.enrollment_id != run.enrollment_id
                    or enrollment.definition_id != run.definition_id
                    or enrollment.definition_version != run.definition_version
                    or enrollment.collector_id != run.collector_id
                ):
                    raise ContinuousEvidenceIntegrityError(
                        "evidence run authority binding is invalid"
                    )
            for observation in observations.values():
                run = runs.get(observation.run_id)
                if (
                    run is None
                    or run.enrollment_id != observation.enrollment_id
                    or observation.control_ref
                    not in enrollment_by_revision[
                        (run.enrollment_id, run.enrollment_revision)
                    ].control_refs
                ):
                    raise ContinuousEvidenceIntegrityError(
                        "evidence observation run binding is invalid"
                    )

            operation_rows = connection.execute(
                "SELECT * FROM trc_operations WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchall()
            for row in operation_rows:
                operation_sha = _digest(row["operation_sha256"], "operation_sha256")
                _digest(row["request_sha256"], "request_sha256")
                result_kind = str(row["result_kind"])
                result_id = _id(row["result_id"], "result_id")
                result_revision = _integer(
                    row["result_revision"],
                    "result_revision",
                    1,
                    2**31 - 1,
                )
                _timestamp(row["created_at"], "operation created_at")
                target_exists = (
                    (result_id, result_revision) in enrollment_by_revision
                    if result_kind == "enrollment"
                    else (result_id, result_revision) in job_by_revision
                    if result_kind == "job"
                    else False
                )
                if not target_exists or not operation_sha:
                    raise ContinuousEvidenceIntegrityError(
                        "evidence operation result binding is invalid"
                    )
            audit_rows = connection.execute(
                "SELECT * FROM trc_audit WHERE tenant_sha256=? ORDER BY sequence",
                (self._tenant_sha256,),
            ).fetchall()
            previous = "0" * 64
            for expected_sequence, row in enumerate(audit_rows, start=1):
                payload, integrity = self._decode(row, "evidence audit")
                if (
                    payload.get("schema") != AUDIT_SCHEMA
                    or payload.get("tenant_sha256") != self._tenant_sha256
                    or payload.get("sequence") != expected_sequence
                    or int(row["sequence"]) != expected_sequence
                    or payload.get("previous_integrity_sha256") != previous
                ):
                    raise ContinuousEvidenceIntegrityError(
                        "continuous-evidence audit chain is discontinuous"
                    )
                _id(payload.get("action"), "audit action")
                _digest(payload.get("subject_sha256"), "audit subject_sha256")
                _digest(payload.get("actor_sha256"), "audit actor_sha256")
                _timestamp(payload.get("created_at"), "audit created_at")
                previous = integrity
        return IntegrityVerification(
            definitions=len(definition_rows),
            enrollments=len(enrollment_rows),
            jobs=len(job_rows),
            runs=len(run_rows),
            observations=len(observation_rows),
            alerts=len(alert_rows),
            audit_events=len(audit_rows),
            terminal_audit_sha256=previous,
        )


CredentialResolver = Callable[[str, str, int, str], object | None]


def _safe_collector_error(error: Exception) -> str:
    if isinstance(error, EvidenceCollectorError):
        return "collector_contract_error"
    name = type(error).__name__.lower()
    if "timeout" in name:
        return "collector_timeout"
    if "permission" in name or "auth" in name or "credential" in name:
        return "collector_access_denied"
    if "connection" in name or "transport" in name:
        return "collector_unavailable"
    return "collector_error"


def run_claimed_collection(
    store: ContinuousEvidenceStore,
    claimed: ClaimedEvidenceJob,
    *,
    registry: CollectorRegistry,
    resolve_credential: CredentialResolver,
    allowed_collector_ids: Sequence[str] | None = None,
    retry_backoff_seconds: int = 30,
) -> CollectionOutcome:
    """Run one exact claimed job with pre/post authority reads and safe failure."""

    if not callable(resolve_credential):
        raise ContinuousEvidenceConfigError("credential resolver must be callable")
    started = store._now()
    try:
        job = store.get_job(claimed.job.job_id)
        if not _same(job.integrity_sha256, claimed.job.integrity_sha256):
            raise ContinuousEvidenceConflict("claimed evidence job changed")
        enrollment = store.get_enrollment(job.enrollment_id)
        if (
            enrollment.state != "active"
            or enrollment.revision != job.enrollment_revision
            or not _same(
                enrollment.integrity_sha256,
                job.enrollment_integrity_sha256,
            )
        ):
            raise ContinuousEvidenceConflict("collector enrollment is stale or inactive")
        definition = store.get_definition(
            enrollment.definition_id,
            enrollment.definition_version,
        )
        if definition.state != "approved" or not _same(
            definition.integrity_sha256,
            enrollment.definition_integrity_sha256,
        ):
            raise ContinuousEvidenceConflict("collector definition is stale or inactive")
        allowed = _collector_allowlist(allowed_collector_ids)
        if allowed is not None:
            if definition.collector_id not in allowed:
                raise ContinuousEvidenceConflict("collector is not enabled for this tenant")
        credential_handle = resolve_credential(
            store.tenant_id,
            enrollment.enrollment_id,
            enrollment.revision,
            enrollment.credential_profile_sha256,
        )
        request = validate_request(
            CollectionRequest(
                tenant_sha256=store.tenant_sha256,
                definition_id=definition.definition_id,
                definition_version=definition.version,
                definition_integrity_sha256=definition.integrity_sha256,
                collector_id=definition.collector_id,
                collector_schema_version=definition.collector_schema_version,
                collector_key_id=definition.collector_key_id,
                capability_revision=definition.capability_revision,
                enrollment_id=enrollment.enrollment_id,
                enrollment_revision=enrollment.revision,
                enrollment_integrity_sha256=enrollment.integrity_sha256,
                asset_scope_sha256=enrollment.asset_scope_sha256,
                control_refs=enrollment.control_refs,
                window_started_at=job.requested_window_started_at,
                window_ended_at=job.requested_window_ended_at,
                credential_handle=credential_handle,
            )
        )
        collector = registry.resolve(definition.collector_id)
        pages: list[EvidencePage] = []
        observations: dict[str, ControlEvidence] = {}
        cursor: str | None = None
        seen_cursors: set[str] = set()
        complete = False
        incomplete_reason: str | None = "coverage_unknown"
        byte_count = 0
        for _ in range(_MAX_PAGES):
            page = validate_page(
                collector.fetch(request, cursor),
                expected_controls=enrollment.control_refs,
            )
            pages.append(page)
            byte_count += page.bytes_read
            if byte_count > _MAX_TOTAL_BYTES:
                raise ContinuousEvidenceValidationError("collection bytes exceed their bound")
            for item in page.items:
                prior = observations.get(item.control_ref)
                if prior is not None and prior != item:
                    raise ContinuousEvidenceValidationError(
                        "collector returned conflicting observations"
                    )
                observations[item.control_ref] = item
            if len(observations) > _MAX_ITEMS:
                raise ContinuousEvidenceValidationError(
                    "collection observations exceed their bound"
                )
            if page.terminal:
                complete = page.complete and set(observations) == set(enrollment.control_refs)
                incomplete_reason = (
                    None if complete else (page.incomplete_reason or "coverage_unknown")
                )
                break
            assert page.next_cursor is not None
            if page.next_cursor in seen_cursors:
                raise ContinuousEvidenceValidationError("collector pagination cursor repeated")
            seen_cursors.add(page.next_cursor)
            cursor = page.next_cursor
        else:
            complete = False
            incomplete_reason = "provider_truncated"
        if not pages:
            raise ContinuousEvidenceValidationError("collector returned no page")
        return store.complete_collection(
            claimed=claimed,
            definition=definition,
            enrollment=enrollment,
            pages=pages,
            observations=tuple(observations[key] for key in sorted(observations)),
            complete=complete,
            incomplete_reason=incomplete_reason,
            started_at=started,
        )
    except ContinuousEvidenceConflict as conflict:
        try:
            cancelled = store.cancel_claim(
                claimed.job.job_id,
                lease_token=claimed.lease_token,
                error_code="collector_authority_changed",
            )
        except (ContinuousEvidenceLeaseLost, ContinuousEvidenceNotFound):
            raise conflict from None
        return CollectionOutcome(
            job=cancelled,
            run=None,
            observations=(),
            alerts=(),
        )
    except ContinuousEvidenceLeaseLost:
        raise
    except Exception as error:  # noqa: BLE001 - provider detail is deliberately sanitized
        failed = store.fail_job(
            claimed.job.job_id,
            lease_token=claimed.lease_token,
            error_code=_safe_collector_error(error),
            backoff_seconds=_integer(retry_backoff_seconds, "retry_backoff_seconds", 1, 86_400),
        )
        return CollectionOutcome(
            job=failed,
            run=None,
            observations=(),
            alerts=(),
        )


__all__ = [
    "ALERT_SCHEMA",
    "AUDIT_SCHEMA",
    "CONTROL_IMPLEMENTATION_MUTATED",
    "COMPLIANCE_CONCLUSIONS_WRITTEN",
    "ClaimedEvidenceJob",
    "CollectionOutcome",
    "CollectorDefinition",
    "CollectorEnrollment",
    "ContinuousEvidenceConfigError",
    "ContinuousEvidenceConflict",
    "ContinuousEvidenceError",
    "ContinuousEvidenceIntegrityError",
    "ContinuousEvidenceLeaseLost",
    "ContinuousEvidenceNotFound",
    "ContinuousEvidencePermissionDenied",
    "ContinuousEvidenceStore",
    "ContinuousEvidenceValidationError",
    "CredentialResolver",
    "DEFINITION_SCHEMA",
    "ENROLLMENT_SCHEMA",
    "EvidenceChangeAlert",
    "EvidenceJob",
    "EvidenceObservation",
    "EvidenceRun",
    "IntegrityVerification",
    "JOB_SCHEMA",
    "LIVE_PROVIDER_ACCEPTANCE",
    "OBSERVATION_SCHEMA",
    "RAW_CREDENTIALS_PERSISTED",
    "RAW_PROVIDER_PAYLOAD_PERSISTED",
    "RetentionPurgeResult",
    "RUN_SCHEMA",
    "enabled",
    "require_enabled",
    "run_claimed_collection",
]
