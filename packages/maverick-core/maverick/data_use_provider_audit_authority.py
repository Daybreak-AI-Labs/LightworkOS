"""Durable digest-only authority outbox for native provider audit.

The native provider adapter owns the mutation operation and
``data_use_provider_audit`` owns reconciliation evidence.  This module is the
small trust bridge between them.  A server stages a compiler-produced control
IR before provider I/O, then finalizes the staged projection only from the
credential-free operation record owned by :class:`ProviderBindingStore`.

Only closed codes, opaque references, timestamps, counters, and SHA-256 pins
are persisted.  Tenant names, provider origins, catalogs, tables, principals,
credentials, SQL, HTTP bodies, and audit-log records are never written here.
Provider audit read authority is separate: an operator must issue an exact,
expiring, revisioned capability grant.  Enabling the feature does not infer a
grant.

This module performs no network I/O and no provider writes.  It does not claim
that a provider audit source is complete or interoperable with a live tenant.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .data_use_policy_compiler import COMPILER_VERSION, CONTROL_IR_SCHEMA
from .data_use_provider_adapters import (
    COMPILER_AUTHORITY_SHA256,
    PROVIDER_RESULT_SCHEMA,
)
from .data_use_provider_audit import (
    DataUseProviderAuditConfigError,
    DataUseProviderAuditConflict,
    DataUseProviderAuditError,
    DataUseProviderAuditIntegrityError,
    DataUseProviderAuditNotFound,
    DataUseProviderAuditValidationError,
    ProviderAuditControlAuthority,
    ProviderAuditExpectedChange,
    ProviderAuditReadAuthority,
    control_authority_sha256,
    expected_change_sha256,
    operation_correlation_sha256,
    read_authority_sha256,
    require_enabled,
)
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

PROJECTION_SCHEMA = "lightwork.data-use.provider-audit-projection.v1"
AUTHORITY_RECORD_SCHEMA = "lightwork.data-use.provider-audit-authority-record.v1"
READ_GRANT_SCHEMA = "lightwork.data-use.provider-audit-read-grant.v1"
INTEGRITY_SCHEMA = "lightwork.data-use.provider-audit-authority-integrity.v1"
AUDIT_EVENT_SCHEMA = "lightwork.data-use.provider-audit-authority-event.v1"

NETWORK_IO = False
PROVIDER_WRITES = False
RAW_CONTROL_MATERIAL_PERSISTED = False
RAW_PROVIDER_MATERIAL_PERSISTED = False

_SCHEMA_VERSION = "1"
_PROVIDERS = frozenset({"snowflake", "databricks"})
_EFFECTS = frozenset({"allow", "deny", "mask", "row_filter", "review"})
_OPERATIONS = frozenset({"apply", "rollback"})
_CHANGE_KINDS = frozenset({"grant", "masking_policy", "revoke", "row_filter", "state_anchor"})
_MASK_METHODS = frozenset(
    {
        "redact",
        "null",
        "hash_sha256",
        "tokenize",
        "preserve_last4",
        "bucket",
        "generalize_date",
    }
)
_AUTHORITY_STATES = frozenset({"staged", "finalized", "registered", "revoked"})
_ACTIVE_CONTROL_STATES = frozenset({"finalized", "registered"})
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_JSON_BYTES = 1024 * 1024
_MAX_CONTROLS = 520
_MAX_EXPECTED_CHANGES = 520
_MAX_AUTHORITY_SECONDS = 366 * 24 * 60 * 60
_MAX_RETENTION_SECONDS = 10 * 366 * 24 * 60 * 60
_MIN_RETENTION_SECONDS = 60
_MAX_PURGE = 500
_MAX_CONTROL_AUTHORITIES = 10_000
_MAX_READ_GRANTS = 10_000


class DataUseProviderAuditAuthorityError(DataUseProviderAuditError):
    """Base authority-outbox error."""


class DataUseProviderAuditAuthorityConfigError(DataUseProviderAuditConfigError):
    """The authority store or an injected server dependency is unavailable."""


class DataUseProviderAuditAuthorityValidationError(DataUseProviderAuditValidationError):
    """Server material is outside the closed authority contract."""


class DataUseProviderAuditAuthorityConflict(DataUseProviderAuditConflict):
    """An authority, CAS revision, or idempotency pin changed."""


class DataUseProviderAuditAuthorityNotFound(DataUseProviderAuditNotFound):
    """A tenant-local authority record does not exist."""


class DataUseProviderAuditAuthorityIntegrityError(DataUseProviderAuditIntegrityError):
    """Persisted authority evidence failed integrity validation."""


@dataclass(frozen=True, slots=True)
class ProviderAuditAuthorityProjection:
    provider_id: str
    binding_id: str
    binding_revision: int
    binding_sha256: str
    operation_idempotency_sha256: str
    compilation_id: str
    ir_sha256: str
    operation: str
    control_state_sha256: str
    target_state_sha256: str
    expected_changes: tuple[ProviderAuditExpectedChange, ...]
    projection_sha256: str


@dataclass(frozen=True, slots=True)
class ProviderAuditAuthorityRecord:
    authority_id: str
    tenant_sha256: str
    provider_id: str
    binding_id: str
    binding_revision: int
    binding_sha256: str
    operation_idempotency_sha256: str
    compilation_id: str
    ir_sha256: str
    operation: str
    control_state_sha256: str
    target_state_sha256: str
    expected_changes: tuple[ProviderAuditExpectedChange, ...]
    projection_sha256: str
    operation_request_sha256: str | None
    operation_result_sha256: str | None
    correlation_sha256: str | None
    no_change: bool | None
    authority_revision: int
    control_authority_sha256: str | None
    state: str
    valid_until: float
    retained_until: float
    created_at: float
    updated_at: float
    finalized_at: float | None
    revoked_at: float | None
    revision: int
    previous_integrity_sha256: str | None
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class ProviderAuditReadGrant:
    grant_id: str
    tenant_sha256: str
    provider_id: str
    binding_id: str
    binding_revision: int
    binding_sha256: str
    credential_key_id_sha256: str
    credential_revision: int
    credential_authority_sha256: str
    capability: str
    capability_revision: int
    authority_sha256: str
    valid_until: float
    retained_until: float
    revoked: bool
    created_at: float
    updated_at: float
    revoked_at: float | None
    revocation_reason_sha256: str | None
    revision: int
    previous_integrity_sha256: str | None
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class ProviderAuditAuthorityIntegrityVerification:
    schema: str
    control_authorities: int
    read_grants: int
    history_records: int
    operation_records: int
    audit_events: int
    terminal_audit_sha256: str
    verification_sha256: str


@dataclass(frozen=True, slots=True)
class ProviderAuditAuthorityPurgeResult:
    control_authorities: int
    read_grants: int


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise DataUseProviderAuditAuthorityValidationError(
            "provider audit authority must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise DataUseProviderAuditAuthorityValidationError(
            "provider audit authority exceeds its byte bound"
        )
    return encoded


def _plain_json(value: object, label: str) -> Any:
    try:
        return json.loads(_canonical(value).decode("ascii"))
    except DataUseProviderAuditAuthorityValidationError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DataUseProviderAuditAuthorityValidationError(f"{label} is invalid") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise DataUseProviderAuditAuthorityValidationError("tenant_id is invalid") from exc


def _provider(value: object) -> str:
    selected = str(value or "").strip().lower()
    if selected not in _PROVIDERS:
        raise DataUseProviderAuditAuthorityValidationError("provider_id is unsupported")
    return selected


def _ref(
    value: object,
    label: str,
    *,
    pattern: re.Pattern[str] = _REF_RE,
) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DataUseProviderAuditAuthorityValidationError(
            f"{label} must be a bounded opaque reference"
        )
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise DataUseProviderAuditAuthorityValidationError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DataUseProviderAuditAuthorityValidationError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DataUseProviderAuditAuthorityValidationError(f"{label} must be a timestamp")
    selected = float(value)
    if not math.isfinite(selected) or selected <= 0:
        raise DataUseProviderAuditAuthorityValidationError(
            f"{label} must be a positive finite timestamp"
        )
    return selected


def _now(clock: Callable[[], float]) -> float:
    try:
        return _timestamp(clock(), "clock")
    except (KeyboardInterrupt, SystemExit):
        raise
    except DataUseProviderAuditAuthorityValidationError:
        raise
    except Exception as exc:
        raise DataUseProviderAuditAuthorityConfigError("authority clock is unavailable") from exc


def _bounded_lifetime(
    *,
    now: float,
    valid_until: object,
    retained_until: object,
) -> tuple[float, float]:
    valid = _timestamp(valid_until, "valid_until")
    retained = _timestamp(retained_until, "retained_until")
    if not now < valid <= now + _MAX_AUTHORITY_SECONDS:
        raise DataUseProviderAuditAuthorityValidationError(
            "authority validity is outside its bound"
        )
    if not max(valid, now + _MIN_RETENTION_SECONDS) <= retained <= (now + _MAX_RETENTION_SECONDS):
        raise DataUseProviderAuditAuthorityValidationError(
            "authority retention is outside its bound"
        )
    return valid, retained


def _privacy_safe(value: object) -> None:
    forbidden = {
        "authorization",
        "catalog",
        "client_ip",
        "credential",
        "email",
        "origin",
        "principal",
        "query_text",
        "raw_event",
        "schema_name",
        "sql",
        "statement",
        "table",
        "tenant_id",
        "token",
        "username",
    }

    def visit(item: object, depth: int) -> None:
        if depth > 16:
            raise DataUseProviderAuditAuthorityValidationError(
                "authority evidence nesting exceeds its bound"
            )
        if isinstance(item, Mapping):
            for raw_key, child in item.items():
                if not isinstance(raw_key, str):
                    raise DataUseProviderAuditAuthorityValidationError(
                        "authority evidence keys must be text"
                    )
                key = raw_key.casefold()
                if key in forbidden and not key.endswith("_sha256"):
                    raise DataUseProviderAuditAuthorityValidationError(
                        "raw provider, tenant, or identity material cannot be persisted"
                    )
                visit(child, depth + 1)
        elif isinstance(item, (list, tuple)):
            if len(item) > _MAX_CONTROLS:
                raise DataUseProviderAuditAuthorityValidationError(
                    "authority evidence collection exceeds its bound"
                )
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str) and len(item) > 512:
            raise DataUseProviderAuditAuthorityValidationError(
                "authority evidence text exceeds its bound"
            )

    visit(value, 0)


def _expected_changes(value: object) -> tuple[ProviderAuditExpectedChange, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > _MAX_EXPECTED_CHANGES:
        raise DataUseProviderAuditAuthorityValidationError(
            "expected provider changes exceed their bound"
        )
    output: list[ProviderAuditExpectedChange] = []
    seen: set[str] = set()
    for item in value:
        if isinstance(item, ProviderAuditExpectedChange):
            change = item
        elif isinstance(item, Mapping) and set(item) == {
            "change_kind",
            "control_sha256",
            "change_sha256",
        }:
            change = ProviderAuditExpectedChange(**item)
        else:
            raise DataUseProviderAuditAuthorityValidationError(
                "expected provider change is invalid"
            )
        if change.change_kind not in _CHANGE_KINDS:
            raise DataUseProviderAuditAuthorityValidationError(
                "expected provider change kind is unsupported"
            )
        control = _digest(change.control_sha256, "expected control_sha256")
        expected = expected_change_sha256(change.change_kind, control)
        if not _same(change.change_sha256, expected) or expected in seen:
            raise DataUseProviderAuditAuthorityValidationError(
                "expected provider changes are duplicated or failed integrity"
            )
        seen.add(expected)
        output.append(ProviderAuditExpectedChange(change.change_kind, control, expected))
    return tuple(sorted(output, key=lambda item: item.change_sha256))


def _change(kind: str, material: Mapping[str, Any]) -> ProviderAuditExpectedChange:
    if kind not in _CHANGE_KINDS:
        raise DataUseProviderAuditAuthorityValidationError(
            "projected provider change kind is unsupported"
        )
    control_sha = _sha256(material)
    return ProviderAuditExpectedChange(
        change_kind=kind,
        control_sha256=control_sha,
        change_sha256=expected_change_sha256(kind, control_sha),
    )


def _authority_payload(value: ProviderAuditAuthorityRecord) -> dict[str, Any]:
    payload = asdict(value)
    payload.pop("integrity_sha256")
    payload["schema"] = AUTHORITY_RECORD_SCHEMA
    _privacy_safe(payload)
    return payload


def _read_grant_payload(value: ProviderAuditReadGrant) -> dict[str, Any]:
    payload = asdict(value)
    payload.pop("integrity_sha256")
    payload["schema"] = READ_GRANT_SCHEMA
    _privacy_safe(payload)
    return payload


def _projection_payload(value: ProviderAuditAuthorityProjection) -> dict[str, Any]:
    payload = asdict(value)
    payload.pop("projection_sha256")
    payload["schema"] = PROJECTION_SCHEMA
    _privacy_safe(payload)
    return payload


class DataUseProviderAuditAuthorityStore:
    """Tenant-bound durable provider-audit authority and recovery outbox."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        binding_store: object,
        config_gate: Callable[[], None] = require_enabled,
        clock: Callable[[], float] = time.time,
    ) -> None:
        config_gate()
        if not callable(getattr(binding_store, "get_binding", None)) or not callable(
            getattr(binding_store, "get_operation", None)
        ):
            raise DataUseProviderAuditAuthorityConfigError(
                "provider binding/operation authority is unavailable"
            )
        if not callable(config_gate) or not callable(clock):
            raise DataUseProviderAuditAuthorityConfigError(
                "provider audit authority dependencies are unavailable"
            )
        self.path = Path(path)
        self._tenant_id = _tenant(tenant_id)
        self._tenant_sha256 = _text_sha256(self._tenant_id)
        self._binding_store = binding_store
        self._config_gate = config_gate
        self._clock = clock
        self._retention = threading.local()
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _check_gate(self) -> None:
        try:
            self._config_gate()
        except DataUseProviderAuditError:
            raise
        except Exception as exc:
            raise DataUseProviderAuditAuthorityConfigError(
                "provider audit authority gate rejected access"
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        ensure_private_directory(self.path.parent)
        connection = sqlite3.connect(
            self.path, timeout=30, isolation_level=None, factory=ClosingConnection
        )
        ensure_private_file(self.path, 0o600)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.create_function(
            "provider_audit_authority_retention_authorized",
            0,
            lambda: 1 if bool(getattr(self._retention, "authorized", False)) else 0,
        )
        return connection

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS provider_audit_authority_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS provider_audit_recovery_cursors(
                    tenant_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL,
                    valid_until REAL NOT NULL,
                    authority_id TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(tenant_sha256,state)
                );
                CREATE TABLE IF NOT EXISTS provider_audit_control_authorities(
                    authority_id TEXT PRIMARY KEY,
                    tenant_sha256 TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    operation_idempotency_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    valid_until REAL NOT NULL,
                    retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    UNIQUE(
                        tenant_sha256,
                        provider_id,
                        binding_id,
                        operation_idempotency_sha256
                    )
                );
                CREATE INDEX IF NOT EXISTS provider_audit_control_state_idx
                    ON provider_audit_control_authorities(
                        tenant_sha256,state,valid_until,authority_id
                    );
                CREATE TABLE IF NOT EXISTS provider_audit_read_grants(
                    grant_id TEXT PRIMARY KEY,
                    tenant_sha256 TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    capability_revision INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    valid_until REAL NOT NULL,
                    retained_until REAL NOT NULL,
                    revoked INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    UNIQUE(tenant_sha256,provider_id,binding_id,capability_revision)
                );
                CREATE INDEX IF NOT EXISTS provider_audit_read_binding_idx
                    ON provider_audit_read_grants(
                        tenant_sha256,provider_id,binding_id,revoked,valid_until
                    );
                CREATE TABLE IF NOT EXISTS provider_audit_authority_history(
                    object_type TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    tenant_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(object_type,object_id,revision)
                );
                CREATE TABLE IF NOT EXISTS provider_audit_authority_operations(
                    tenant_sha256 TEXT NOT NULL,
                    key_sha256 TEXT NOT NULL,
                    action TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    object_type TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    result_integrity_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(tenant_sha256,key_sha256)
                );
                CREATE TABLE IF NOT EXISTS provider_audit_authority_chain(
                    sequence INTEGER PRIMARY KEY,
                    tenant_sha256 TEXT NOT NULL,
                    action TEXT NOT NULL,
                    object_ref TEXT NOT NULL,
                    detail_sha256 TEXT NOT NULL,
                    occurred_at REAL NOT NULL,
                    previous_event_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL UNIQUE
                );
                CREATE TRIGGER IF NOT EXISTS provider_audit_authority_history_no_update
                    BEFORE UPDATE ON provider_audit_authority_history
                    BEGIN SELECT RAISE(ABORT, 'immutable provider audit authority history'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_authority_operations_no_update
                    BEFORE UPDATE ON provider_audit_authority_operations
                    BEGIN SELECT RAISE(ABORT, 'immutable provider audit authority operation'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_authority_chain_no_update
                    BEFORE UPDATE ON provider_audit_authority_chain
                    BEGIN SELECT RAISE(ABORT, 'immutable provider audit authority chain'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_authority_chain_no_delete
                    BEFORE DELETE ON provider_audit_authority_chain
                    BEGIN SELECT RAISE(ABORT, 'immutable provider audit authority chain'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_control_guard_delete
                    BEFORE DELETE ON provider_audit_control_authorities
                    WHEN provider_audit_authority_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT, 'provider audit authority retention required'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_read_guard_delete
                    BEFORE DELETE ON provider_audit_read_grants
                    WHEN provider_audit_authority_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT, 'provider audit authority retention required'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_authority_history_guard_delete
                    BEFORE DELETE ON provider_audit_authority_history
                    WHEN provider_audit_authority_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT, 'provider audit authority retention required'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_authority_operations_guard_delete
                    BEFORE DELETE ON provider_audit_authority_operations
                    WHEN provider_audit_authority_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT, 'provider audit authority retention required'); END;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO provider_audit_authority_meta(key,value) "
                "VALUES('schema_version',?)",
                (_SCHEMA_VERSION,),
            )
            row = connection.execute(
                "SELECT value FROM provider_audit_authority_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None or row["value"] != _SCHEMA_VERSION:
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "unsupported provider audit authority schema version"
                )
            connection.execute(
                "INSERT OR IGNORE INTO provider_audit_authority_meta(key,value) "
                "VALUES('tenant_sha256',?)",
                (self._tenant_sha256,),
            )
            tenant_row = connection.execute(
                "SELECT value FROM provider_audit_authority_meta WHERE key='tenant_sha256'"
            ).fetchone()
            if tenant_row is None or not _same(str(tenant_row["value"]), self._tenant_sha256):
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "provider audit authority database belongs to another tenant"
                )

    @staticmethod
    def _row_payload(row: sqlite3.Row, label: str) -> tuple[dict[str, Any], str]:
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DataUseProviderAuditAuthorityIntegrityError(f"stored {label} is invalid") from exc
        if not isinstance(payload, dict):
            raise DataUseProviderAuditAuthorityIntegrityError(f"stored {label} is invalid")
        integrity = str(row["integrity_sha256"])
        if not _DIGEST_RE.fullmatch(integrity) or not _same(integrity, _sha256(payload)):
            raise DataUseProviderAuditAuthorityIntegrityError(f"stored {label} failed integrity")
        try:
            _privacy_safe(payload)
        except DataUseProviderAuditAuthorityValidationError as exc:
            raise DataUseProviderAuditAuthorityIntegrityError(
                f"stored {label} contains prohibited material"
            ) from exc
        return payload, integrity

    def _validated_control(  # noqa: C901 - validates the complete persisted contract
        self,
        payload: Mapping[str, Any],
        integrity_sha256: str,
    ) -> ProviderAuditAuthorityRecord:
        body = dict(payload)
        if body.pop("schema", None) != AUTHORITY_RECORD_SCHEMA:
            raise DataUseProviderAuditAuthorityIntegrityError("control authority schema is invalid")
        expected = set(ProviderAuditAuthorityRecord.__dataclass_fields__) - {"integrity_sha256"}
        if set(body) != expected:
            raise DataUseProviderAuditAuthorityIntegrityError(
                "control authority fields are invalid"
            )
        try:
            body["expected_changes"] = _expected_changes(body["expected_changes"])
            value = ProviderAuditAuthorityRecord(
                **body,
                integrity_sha256=integrity_sha256,
            )
            _ref(value.authority_id, "authority_id")
            if not _same(_digest(value.tenant_sha256, "tenant_sha256"), self._tenant_sha256):
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "control authority crossed a tenant boundary"
                )
            _provider(value.provider_id)
            _ref(value.binding_id, "binding_id")
            _integer(value.binding_revision, "binding_revision", 1, 2**31 - 1)
            _digest(value.binding_sha256, "binding_sha256")
            _digest(
                value.operation_idempotency_sha256,
                "operation_idempotency_sha256",
            )
            _ref(value.compilation_id, "compilation_id")
            _digest(value.ir_sha256, "ir_sha256")
            if value.operation not in _OPERATIONS:
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "control authority operation is invalid"
                )
            _digest(value.control_state_sha256, "control_state_sha256")
            _digest(value.target_state_sha256, "target_state_sha256")
            _digest(value.projection_sha256, "projection_sha256")
            _integer(value.authority_revision, "authority_revision", 1, 2**31 - 1)
            if value.state not in _AUTHORITY_STATES:
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "control authority state is invalid"
                )
            valid = _timestamp(value.valid_until, "valid_until")
            retained = _timestamp(value.retained_until, "retained_until")
            created = _timestamp(value.created_at, "created_at")
            updated = _timestamp(value.updated_at, "updated_at")
            finalized = (
                None
                if value.finalized_at is None
                else _timestamp(value.finalized_at, "finalized_at")
            )
            revoked = (
                None if value.revoked_at is None else _timestamp(value.revoked_at, "revoked_at")
            )
            if not created <= updated <= retained or valid > retained:
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "control authority timestamps are inconsistent"
                )
            _integer(value.revision, "revision", 1, 2**31 - 1)
            previous = value.previous_integrity_sha256
            if value.revision == 1 and previous is not None:
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "initial control authority contains a history link"
                )
            if value.revision > 1 and previous is None:
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "control authority history link is absent"
                )
            if previous is not None:
                _digest(previous, "previous_integrity_sha256")
            finalized_fields = (
                value.operation_request_sha256,
                value.operation_result_sha256,
                value.correlation_sha256,
                value.no_change,
                value.control_authority_sha256,
                finalized,
            )
            if value.state == "staged":
                if any(item is not None for item in finalized_fields) or revoked is not None:
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "staged control authority contains finalized material"
                    )
                if not value.expected_changes:
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "staged control authority has no expected changes"
                    )
            else:
                if any(item is None for item in finalized_fields):
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "finalized control authority is incomplete"
                    )
                _digest(value.operation_request_sha256, "operation_request_sha256")
                _digest(value.operation_result_sha256, "operation_result_sha256")
                _digest(value.correlation_sha256, "correlation_sha256")
                _digest(value.control_authority_sha256, "control_authority_sha256")
                if not isinstance(value.no_change, bool):
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "control authority no-change state is invalid"
                    )
                if value.no_change == bool(value.expected_changes):
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "control authority expected changes are inconsistent"
                    )
                if value.state in _ACTIVE_CONTROL_STATES and revoked is not None:
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "active control authority contains revocation evidence"
                    )
                if value.state == "revoked" and revoked is None:
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "revoked control authority lacks revocation evidence"
                    )
                authority = self._control_authority(value, revoked=value.state == "revoked")
                if not _same(authority.authority_sha256, value.control_authority_sha256):
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "control authority digest is inconsistent"
                    )
            projection = ProviderAuditAuthorityProjection(
                provider_id=value.provider_id,
                binding_id=value.binding_id,
                binding_revision=value.binding_revision,
                binding_sha256=value.binding_sha256,
                operation_idempotency_sha256=value.operation_idempotency_sha256,
                compilation_id=value.compilation_id,
                ir_sha256=value.ir_sha256,
                operation=value.operation,
                control_state_sha256=value.control_state_sha256,
                target_state_sha256=value.target_state_sha256,
                expected_changes=(
                    value.expected_changes
                    if value.state == "staged" or value.no_change is False
                    else ()
                ),
                projection_sha256=value.projection_sha256,
            )
            # A no-change finalization intentionally empties expected changes;
            # its original staged projection remains immutable in revision 1.
            if value.state == "staged" and not _same(
                _sha256(_projection_payload(projection)),
                value.projection_sha256,
            ):
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "control projection digest is inconsistent"
                )
            if not _same(_sha256(_authority_payload(value)), integrity_sha256):
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "control authority integrity is invalid"
                )
            return value
        except DataUseProviderAuditAuthorityIntegrityError:
            raise
        except DataUseProviderAuditError as exc:
            raise DataUseProviderAuditAuthorityIntegrityError(
                "stored control authority is malformed"
            ) from exc
        except (TypeError, ValueError) as exc:
            raise DataUseProviderAuditAuthorityIntegrityError(
                "stored control authority is malformed"
            ) from exc

    def _validated_read_grant(
        self,
        payload: Mapping[str, Any],
        integrity_sha256: str,
    ) -> ProviderAuditReadGrant:
        body = dict(payload)
        if body.pop("schema", None) != READ_GRANT_SCHEMA:
            raise DataUseProviderAuditAuthorityIntegrityError(
                "provider audit read-grant schema is invalid"
            )
        expected = set(ProviderAuditReadGrant.__dataclass_fields__) - {"integrity_sha256"}
        if set(body) != expected:
            raise DataUseProviderAuditAuthorityIntegrityError(
                "provider audit read-grant fields are invalid"
            )
        try:
            value = ProviderAuditReadGrant(**body, integrity_sha256=integrity_sha256)
            _ref(value.grant_id, "grant_id")
            if not _same(_digest(value.tenant_sha256, "tenant_sha256"), self._tenant_sha256):
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "provider audit read grant crossed a tenant boundary"
                )
            _provider(value.provider_id)
            _ref(value.binding_id, "binding_id")
            _integer(value.binding_revision, "binding_revision", 1, 2**31 - 1)
            _digest(value.binding_sha256, "binding_sha256")
            _digest(value.credential_key_id_sha256, "credential_key_id_sha256")
            _integer(value.credential_revision, "credential_revision", 1, 2**31 - 1)
            _digest(value.credential_authority_sha256, "credential_authority_sha256")
            if value.capability != "provider_audit_read":
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "provider audit read capability is invalid"
                )
            _integer(value.capability_revision, "capability_revision", 1, 2**31 - 1)
            _digest(value.authority_sha256, "authority_sha256")
            valid = _timestamp(value.valid_until, "valid_until")
            retained = _timestamp(value.retained_until, "retained_until")
            created = _timestamp(value.created_at, "created_at")
            updated = _timestamp(value.updated_at, "updated_at")
            revoked_at = (
                None if value.revoked_at is None else _timestamp(value.revoked_at, "revoked_at")
            )
            if not created <= updated <= retained or valid > retained:
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "provider audit read-grant timestamps are inconsistent"
                )
            if not isinstance(value.revoked, bool) or value.revoked != (revoked_at is not None):
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "provider audit read-grant revocation is inconsistent"
                )
            if value.revoked != (value.revocation_reason_sha256 is not None):
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "provider audit read-grant reason is inconsistent"
                )
            if value.revocation_reason_sha256 is not None:
                _digest(value.revocation_reason_sha256, "revocation_reason_sha256")
            _integer(value.revision, "revision", 1, 2**31 - 1)
            if value.revision == 1 and value.previous_integrity_sha256 is not None:
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "initial provider audit read grant contains a history link"
                )
            if value.revision > 1 and value.previous_integrity_sha256 is None:
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "provider audit read-grant history link is absent"
                )
            if value.previous_integrity_sha256 is not None:
                _digest(value.previous_integrity_sha256, "previous_integrity_sha256")
            authority = self._read_authority(value)
            if not _same(authority.authority_sha256, value.authority_sha256):
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "provider audit read authority digest is inconsistent"
                )
            if not _same(_sha256(_read_grant_payload(value)), integrity_sha256):
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "provider audit read-grant integrity is invalid"
                )
            return value
        except DataUseProviderAuditAuthorityIntegrityError:
            raise
        except DataUseProviderAuditError as exc:
            raise DataUseProviderAuditAuthorityIntegrityError(
                "stored provider audit read grant is malformed"
            ) from exc
        except (TypeError, ValueError) as exc:
            raise DataUseProviderAuditAuthorityIntegrityError(
                "stored provider audit read grant is malformed"
            ) from exc

    def _current_binding(self, provider_id: str, binding_id: str) -> dict[str, Any]:
        provider = _provider(provider_id)
        binding_ref = _ref(binding_id, "binding_id")
        raw = self._binding_store.get_binding(self._tenant_id, binding_ref)
        if not isinstance(raw, Mapping):
            raise DataUseProviderAuditAuthorityNotFound("provider binding does not exist")
        binding = dict(raw)
        if (
            _tenant(binding.get("tenant_id")) != self._tenant_id
            or _provider(binding.get("provider_id")) != provider
            or _ref(binding.get("binding_id"), "binding_id") != binding_ref
            or binding.get("revoked") is not False
        ):
            raise DataUseProviderAuditAuthorityConflict("provider binding is stale or revoked")
        _integer(binding.get("revision"), "binding revision", 1, 2**31 - 1)
        for field in (
            "binding_sha256",
            "credential_key_id_sha256",
            "credential_authority_sha256",
        ):
            _digest(binding.get(field), field)
        _integer(
            binding.get("credential_revision"),
            "credential_revision",
            1,
            2**31 - 1,
        )
        if not isinstance(binding.get("asset_id"), str) or not isinstance(
            binding.get("field_map"), Mapping
        ):
            raise DataUseProviderAuditAuthorityConflict(
                "provider binding control inventory is incomplete"
            )
        return binding

    @staticmethod
    def _control_source(value: object, *, rollback: bool, control_id: str) -> None:
        if not isinstance(value, Mapping) or set(value) != {
            "policy_id",
            "policy_version",
            "policy_sha256",
            "exception_id",
        }:
            raise DataUseProviderAuditAuthorityValidationError(
                "control source is outside the compiler contract"
            )
        if rollback:
            if any(item is not None for item in value.values()):
                raise DataUseProviderAuditAuthorityValidationError(
                    "rollback control source is not safe deny"
                )
            return
        policy_id = value.get("policy_id")
        if policy_id is None:
            if any(item is not None for item in value.values()):
                raise DataUseProviderAuditAuthorityValidationError(
                    "default-deny source is malformed"
                )
            return
        _ref(policy_id, "control policy_id")
        _integer(value.get("policy_version"), "control policy_version", 1, 2**31 - 1)
        _digest(value.get("policy_sha256"), "control policy_sha256")
        if value.get("exception_id") is not None:
            _ref(value.get("exception_id"), "control exception_id")

    def _project_control_ir(  # noqa: C901 - validates the complete compiler contract
        self,
        *,
        provider_id: str,
        binding: Mapping[str, Any],
        operation_idempotency_sha256: str,
        control_ir: Mapping[str, Any],
        operation: str,
    ) -> ProviderAuditAuthorityProjection:
        provider = _provider(provider_id)
        idem = _digest(operation_idempotency_sha256, "operation_idempotency_sha256")
        if operation not in _OPERATIONS:
            raise DataUseProviderAuditAuthorityValidationError(
                "provider audit operation is unsupported"
            )
        value = _plain_json(control_ir, "control_ir")
        required = {
            "schema",
            "tenant_id",
            "compiler",
            "bindings",
            "bindings_sha256",
            "desired_state",
            "desired_state_sha256",
            "rollback_state",
            "rollback_state_sha256",
            "native_adapter",
            "provider_writes_possible",
            "live_provider_acceptance_verified",
            "compilation_id",
            "ir_sha256",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise DataUseProviderAuditAuthorityValidationError(
                "control_ir schema or shape is unsupported"
            )
        if value.get("schema") != CONTROL_IR_SCHEMA or value.get("tenant_id") != self._tenant_id:
            raise DataUseProviderAuditAuthorityConflict(
                "control_ir tenant or schema binding changed"
            )
        expected_ir = _sha256(
            {key: item for key, item in value.items() if key not in {"compilation_id", "ir_sha256"}}
        )
        if (
            not _same(_digest(value.get("ir_sha256"), "ir_sha256"), expected_ir)
            or value.get("compilation_id") != f"duc-{expected_ir[:40]}"
        ):
            raise DataUseProviderAuditAuthorityValidationError("control_ir digest does not match")
        if value.get("compiler") != {
            "version": COMPILER_VERSION,
            "compiler_sha256": COMPILER_AUTHORITY_SHA256,
        }:
            raise DataUseProviderAuditAuthorityConflict("control_ir compiler authority changed")
        if (
            value.get("provider_writes_possible") is not True
            or value.get("live_provider_acceptance_verified") is not False
        ):
            raise DataUseProviderAuditAuthorityValidationError(
                "control_ir contains unsupported provider claims"
            )
        adapter = value.get("native_adapter")
        if not isinstance(adapter, dict) or adapter != {
            "adapter_id": f"{provider}-native",
            "adapter_authority_sha256": adapter.get("adapter_authority_sha256"),
            "control_schema": CONTROL_IR_SCHEMA,
            "supported_effects": sorted(_EFFECTS),
            "controlled_operations": ["apply_control_ir", "rollback_control_ir"],
        }:
            raise DataUseProviderAuditAuthorityConflict("control_ir native adapter binding changed")
        _digest(adapter["adapter_authority_sha256"], "adapter_authority_sha256")
        bindings = value.get("bindings")
        if not isinstance(bindings, dict) or not _same(
            _digest(value.get("bindings_sha256"), "bindings_sha256"),
            _sha256(bindings),
        ):
            raise DataUseProviderAuditAuthorityValidationError(
                "control_ir binding digest does not match"
            )
        asset = bindings.get("asset")
        fields = bindings.get("fields")
        if not isinstance(asset, Mapping) or asset.get("asset_id") != binding["asset_id"]:
            raise DataUseProviderAuditAuthorityConflict("control_ir asset binding changed")
        if not isinstance(fields, list) or not 1 <= len(fields) <= _MAX_CONTROLS:
            raise DataUseProviderAuditAuthorityValidationError(
                "control_ir field bindings are invalid"
            )
        field_ids: set[str] = set()
        for field in fields:
            if not isinstance(field, Mapping) or set(field) != {
                "field_id",
                "revision",
                "record_sha256",
            }:
                raise DataUseProviderAuditAuthorityValidationError(
                    "control_ir field binding is invalid"
                )
            field_id = _ref(field.get("field_id"), "field_id")
            _integer(field.get("revision"), "field revision", 1, 2**31 - 1)
            _digest(field.get("record_sha256"), "field record_sha256")
            if field_id in field_ids:
                raise DataUseProviderAuditAuthorityValidationError(
                    "control_ir field bindings contain duplicates"
                )
            field_ids.add(field_id)
        if field_ids != set(binding["field_map"]):
            raise DataUseProviderAuditAuthorityConflict(
                "control_ir fields do not match the enrolled provider binding"
            )
        state_key = "rollback_state" if operation == "rollback" else "desired_state"
        digest_key = f"{state_key}_sha256"
        controls = value.get(state_key)
        if not isinstance(controls, list) or not 1 <= len(controls) <= _MAX_CONTROLS:
            raise DataUseProviderAuditAuthorityValidationError(
                "selected control state is outside its bound"
            )
        state_sha = _digest(value.get(digest_key), digest_key)
        expected_state = _sha256(
            {
                "kind": "rollback" if operation == "rollback" else "desired",
                "bindings_sha256": value["bindings_sha256"],
                "controls": controls,
            }
        )
        if not _same(state_sha, expected_state):
            raise DataUseProviderAuditAuthorityValidationError(
                "selected control-state digest does not match"
            )
        normalized: list[dict[str, Any]] = []
        controlled_fields: set[str] = set()
        row_digests: set[str] = set()
        projected: list[ProviderAuditExpectedChange] = []
        base = {
            "schema": PROJECTION_SCHEMA,
            "provider_id": provider,
            "binding_sha256": binding["binding_sha256"],
            "operation_idempotency_sha256": idem,
            "ir_sha256": expected_ir,
            "operation": operation,
            "target_state_sha256": state_sha,
        }
        for raw in controls:
            if not isinstance(raw, dict) or set(raw) != {
                "operation",
                "control_id",
                "asset_id",
                "field_id",
                "parameters",
                "source",
            }:
                raise DataUseProviderAuditAuthorityValidationError(
                    "compiled control is outside its closed shape"
                )
            effect = str(raw.get("operation") or "")
            if effect not in _EFFECTS:
                raise DataUseProviderAuditAuthorityValidationError(
                    "compiled control effect is unsupported"
                )
            control_id = _ref(raw.get("control_id"), "control_id")
            field_id = _ref(raw.get("field_id"), "field_id")
            if raw.get("asset_id") != binding["asset_id"] or field_id not in field_ids:
                raise DataUseProviderAuditAuthorityConflict(
                    "compiled control resource binding changed"
                )
            parameters = raw.get("parameters")
            if not isinstance(parameters, dict):
                raise DataUseProviderAuditAuthorityValidationError(
                    "compiled control parameters are invalid"
                )
            if effect == "mask":
                if set(parameters) != {"method"} or parameters.get("method") not in _MASK_METHODS:
                    raise DataUseProviderAuditAuthorityValidationError(
                        "compiled mask parameters are unsupported"
                    )
                if parameters["method"] not in binding.get("mask_bindings", {}):
                    raise DataUseProviderAuditAuthorityConflict(
                        "compiled mask has no enrolled provider binding"
                    )
            elif effect == "row_filter":
                if set(parameters) != {"ast"}:
                    raise DataUseProviderAuditAuthorityValidationError(
                        "compiled row-filter parameters are unsupported"
                    )
                row_digest = _sha256(parameters["ast"])
                row_digests.add(row_digest)
                if row_digest not in binding.get("row_filter_bindings", {}):
                    raise DataUseProviderAuditAuthorityConflict(
                        "compiled row filter has no enrolled provider binding"
                    )
            elif parameters:
                raise DataUseProviderAuditAuthorityValidationError(
                    "compiled control contains arbitrary parameters"
                )
            self._control_source(
                raw.get("source"),
                rollback=operation == "rollback",
                control_id=control_id,
            )
            if operation == "rollback" and (
                effect != "deny" or control_id != f"rollback-deny-{field_id}"
            ):
                raise DataUseProviderAuditAuthorityValidationError(
                    "rollback control is not compiler-generated safe deny"
                )
            normalized.append(raw)
            controlled_fields.add(field_id)
            semantic = _sha256(raw)
            field_sha = _text_sha256(field_id)
            if effect == "mask":
                projected.append(
                    _change(
                        "masking_policy",
                        {**base, "action": "set", "field_sha256": field_sha, "control": semantic},
                    )
                )
            elif effect in {"allow", "row_filter"}:
                projected.append(
                    _change(
                        "masking_policy",
                        {
                            **base,
                            "action": "unset",
                            "field_sha256": field_sha,
                            "control": semantic,
                        },
                    )
                )
        if controlled_fields != field_ids:
            raise DataUseProviderAuditAuthorityValidationError(
                "selected control state does not govern every enrolled field"
            )
        expected_order = sorted(
            normalized,
            key=lambda item: (
                item["asset_id"],
                item["field_id"],
                item["operation"],
                item["control_id"],
                _sha256(item),
            ),
        )
        if normalized != expected_order:
            raise DataUseProviderAuditAuthorityValidationError(
                "selected control state is not in deterministic compiler order"
            )
        if operation == "rollback" and len(normalized) != len(field_ids):
            raise DataUseProviderAuditAuthorityValidationError(
                "rollback state is not one safe deny per field"
            )
        if len(row_digests) > 1:
            raise DataUseProviderAuditAuthorityValidationError(
                "selected controls contain multiple native row filters"
            )
        if row_digests:
            projected.append(
                _change(
                    "row_filter",
                    {**base, "action": "set", "row_filter_sha256": next(iter(row_digests))},
                )
            )
        effects = {item["operation"] for item in normalized}
        access_kind = "revoke" if effects & {"deny", "review"} else "grant"
        projected.append(
            _change(
                access_kind,
                {**base, "action": access_kind, "control_state_sha256": state_sha},
            )
        )
        projected.append(
            _change(
                "state_anchor",
                {**base, "action": "set", "state_sha256": state_sha},
            )
        )
        changes = _expected_changes(projected)
        projection = ProviderAuditAuthorityProjection(
            provider_id=provider,
            binding_id=str(binding["binding_id"]),
            binding_revision=int(binding["revision"]),
            binding_sha256=str(binding["binding_sha256"]),
            operation_idempotency_sha256=idem,
            compilation_id=str(value["compilation_id"]),
            ir_sha256=expected_ir,
            operation=operation,
            control_state_sha256=state_sha,
            target_state_sha256=state_sha,
            expected_changes=changes,
            projection_sha256="0" * 64,
        )
        return replace(
            projection,
            projection_sha256=_sha256(_projection_payload(projection)),
        )

    def _control_authority(
        self,
        value: ProviderAuditAuthorityRecord,
        *,
        revoked: bool,
    ) -> ProviderAuditControlAuthority:
        if (
            value.operation_request_sha256 is None
            or value.operation_result_sha256 is None
            or value.correlation_sha256 is None
        ):
            raise DataUseProviderAuditAuthorityIntegrityError(
                "control authority has not been finalized"
            )
        authority = ProviderAuditControlAuthority(
            tenant_id=self._tenant_id,
            provider_id=value.provider_id,
            binding_id=value.binding_id,
            binding_revision=value.binding_revision,
            binding_sha256=value.binding_sha256,
            operation_idempotency_sha256=value.operation_idempotency_sha256,
            operation_request_sha256=value.operation_request_sha256,
            operation_result_sha256=value.operation_result_sha256,
            compilation_id=value.compilation_id,
            ir_sha256=value.ir_sha256,
            operation=value.operation,
            target_state_sha256=value.target_state_sha256,
            correlation_sha256=value.correlation_sha256,
            expected_changes=value.expected_changes,
            revision=value.authority_revision,
            valid_until=value.valid_until,
            revoked=revoked,
            authority_sha256="0" * 64,
        )
        return replace(
            authority,
            authority_sha256=control_authority_sha256(authority),
        )

    def _read_authority(self, value: ProviderAuditReadGrant) -> ProviderAuditReadAuthority:
        authority = ProviderAuditReadAuthority(
            tenant_id=self._tenant_id,
            provider_id=value.provider_id,
            binding_id=value.binding_id,
            binding_revision=value.binding_revision,
            binding_sha256=value.binding_sha256,
            credential_key_id_sha256=value.credential_key_id_sha256,
            credential_revision=value.credential_revision,
            credential_authority_sha256=value.credential_authority_sha256,
            capability=value.capability,
            capability_revision=value.capability_revision,
            valid_until=value.valid_until,
            revoked=value.revoked,
            authority_sha256="0" * 64,
        )
        return replace(authority, authority_sha256=read_authority_sha256(authority))

    def _validate_provider_operation(
        self,
        value: ProviderAuditAuthorityRecord,
        binding: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if int(binding["revision"]) != value.binding_revision or not _same(
            binding["binding_sha256"], value.binding_sha256
        ):
            raise DataUseProviderAuditAuthorityConflict(
                "provider binding drifted after authority staging"
            )
        try:
            raw = self._binding_store.get_operation(
                tenant_id=self._tenant_id,
                provider_id=value.provider_id,
                binding_id=value.binding_id,
                idempotency_sha256=value.operation_idempotency_sha256,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise DataUseProviderAuditAuthorityConfigError(
                "provider operation authority is unavailable"
            ) from exc
        if not isinstance(raw, Mapping):
            raise DataUseProviderAuditAuthorityNotFound("provider operation does not exist")
        operation = _plain_json(raw, "provider operation")
        required = {
            "tenant_id",
            "provider_id",
            "binding_id",
            "idempotency_sha256",
            "request_sha256",
            "status",
            "evidence",
            "created_at",
            "updated_at",
        }
        if not isinstance(operation, dict) or set(operation) != required:
            raise DataUseProviderAuditAuthorityConflict(
                "provider operation projection changed schema"
            )
        if (
            _tenant(operation["tenant_id"]) != self._tenant_id
            or _provider(operation["provider_id"]) != value.provider_id
            or _ref(operation["binding_id"], "operation binding_id") != value.binding_id
            or not _same(
                _digest(operation["idempotency_sha256"], "operation idempotency_sha256"),
                value.operation_idempotency_sha256,
            )
            or operation["status"] != "complete"
        ):
            raise DataUseProviderAuditAuthorityConflict(
                "provider operation is not exact and complete"
            )
        request_sha = _digest(operation["request_sha256"], "operation request_sha256")
        created_at = _timestamp(operation["created_at"], "operation created_at")
        updated_at = _timestamp(operation["updated_at"], "operation updated_at")
        if created_at > updated_at:
            raise DataUseProviderAuditAuthorityConflict(
                "provider operation timestamps are inconsistent"
            )
        result = operation["evidence"]
        required_result = {
            "schema",
            "tenant_id",
            "provider_id",
            "adapter_id",
            "binding_id",
            "binding_revision",
            "binding_sha256",
            "compilation_id",
            "ir_sha256",
            "operation",
            "idempotency_sha256",
            "request_sha256",
            "target_state_sha256",
            "observed_before_sha256",
            "observed_after_sha256",
            "reconciliation",
            "no_change",
            "provider_writes_possible",
            "credential_material_recorded",
            "http_receipts",
            "http_receipts_sha256",
            "rollback_mode",
            "restored_prior_native_state",
            "live_provider_acceptance_verified",
            "result_sha256",
        }
        if not isinstance(result, dict) or set(result) != required_result:
            raise DataUseProviderAuditAuthorityConflict(
                "provider reconciliation result changed schema"
            )
        result_without_digest = {
            key: item for key, item in result.items() if key != "result_sha256"
        }
        expected_rollback = "compiled_safe_deny" if value.operation == "rollback" else None
        if (
            result["schema"] != PROVIDER_RESULT_SCHEMA
            or _tenant(result["tenant_id"]) != self._tenant_id
            or _provider(result["provider_id"]) != value.provider_id
            or result["adapter_id"] != f"{value.provider_id}-native"
            or _ref(result["binding_id"], "result binding_id") != value.binding_id
            or result["binding_revision"] != value.binding_revision
            or not _same(result["binding_sha256"], value.binding_sha256)
            or result["compilation_id"] != value.compilation_id
            or not _same(result["ir_sha256"], value.ir_sha256)
            or result["operation"] != value.operation
            or not _same(result["idempotency_sha256"], value.operation_idempotency_sha256)
            or not _same(result["request_sha256"], request_sha)
            or not _same(result["target_state_sha256"], value.target_state_sha256)
            or result["reconciliation"] not in {"converged", "no_change"}
            or not isinstance(result["no_change"], bool)
            or (result["reconciliation"] == "no_change") is not result["no_change"]
            or result["provider_writes_possible"] is not True
            or result["credential_material_recorded"] is not False
            or result["live_provider_acceptance_verified"] is not False
            or result["restored_prior_native_state"] is not False
            or result["rollback_mode"] != expected_rollback
            or not isinstance(result["http_receipts"], list)
            or len(result["http_receipts"]) > _MAX_CONTROLS
            or not _same(
                _digest(result["result_sha256"], "provider result_sha256"),
                _sha256(result_without_digest),
            )
            or not _same(
                _digest(result["http_receipts_sha256"], "http_receipts_sha256"),
                _sha256(result["http_receipts"]),
            )
            or not _same(
                _digest(result["target_state_sha256"], "target_state_sha256"),
                _digest(result["observed_after_sha256"], "observed_after_sha256"),
            )
            or (
                result["no_change"] is True
                and not _same(
                    result["observed_before_sha256"],
                    result["target_state_sha256"],
                )
            )
        ):
            raise DataUseProviderAuditAuthorityConflict(
                "provider reconciliation result failed exact authority validation"
            )
        _digest(result["ir_sha256"], "result ir_sha256")
        _ref(result["compilation_id"], "result compilation_id")
        if result["observed_before_sha256"] is not None:
            _digest(result["observed_before_sha256"], "observed_before_sha256")
        return operation, result

    def _recovery_operation_status(
        self,
        value: ProviderAuditAuthorityRecord,
        binding: Mapping[str, Any],
    ) -> str | None:
        """Distinguish normal pending outcomes from authority/schema drift."""

        if int(binding["revision"]) != value.binding_revision or not _same(
            binding["binding_sha256"], value.binding_sha256
        ):
            raise DataUseProviderAuditAuthorityConflict(
                "provider binding drifted after authority staging"
            )
        try:
            raw = self._binding_store.get_operation(
                tenant_id=self._tenant_id,
                provider_id=value.provider_id,
                binding_id=value.binding_id,
                idempotency_sha256=value.operation_idempotency_sha256,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise DataUseProviderAuditAuthorityConfigError(
                "provider operation authority is unavailable"
            ) from exc
        if raw is None:
            return None
        operation = _plain_json(raw, "provider operation")
        required = {
            "tenant_id",
            "provider_id",
            "binding_id",
            "idempotency_sha256",
            "request_sha256",
            "status",
            "evidence",
            "created_at",
            "updated_at",
        }
        if not isinstance(operation, dict) or set(operation) != required:
            raise DataUseProviderAuditAuthorityConflict(
                "provider operation projection changed schema"
            )
        status = operation["status"]
        if (
            _tenant(operation["tenant_id"]) != self._tenant_id
            or _provider(operation["provider_id"]) != value.provider_id
            or _ref(operation["binding_id"], "operation binding_id") != value.binding_id
            or not _same(
                _digest(operation["idempotency_sha256"], "operation idempotency_sha256"),
                value.operation_idempotency_sha256,
            )
            or status not in {"in_progress", "complete", "ambiguous", "failed_no_effect"}
            or _timestamp(operation["created_at"], "operation created_at")
            > _timestamp(operation["updated_at"], "operation updated_at")
        ):
            raise DataUseProviderAuditAuthorityConflict(
                "provider operation recovery projection is invalid"
            )
        _digest(operation["request_sha256"], "operation request_sha256")
        if status == "complete" and not isinstance(operation["evidence"], dict):
            raise DataUseProviderAuditAuthorityConflict(
                "completed provider operation lacks result evidence"
            )
        if status == "in_progress" and operation["evidence"] is not None:
            raise DataUseProviderAuditAuthorityConflict(
                "in-progress provider operation contains terminal evidence"
            )
        if (
            status in {"ambiguous", "failed_no_effect"}
            and operation["evidence"] is not None
            and not isinstance(operation["evidence"], dict)
        ):
            raise DataUseProviderAuditAuthorityConflict(
                "terminal provider operation evidence is malformed"
            )
        return str(status)

    def _get_control(
        self,
        connection: sqlite3.Connection,
        authority_id: str,
    ) -> ProviderAuditAuthorityRecord:
        authority_ref = _ref(authority_id, "authority_id")
        row = connection.execute(
            "SELECT * FROM provider_audit_control_authorities "
            "WHERE tenant_sha256=? AND authority_id=?",
            (self._tenant_sha256, authority_ref),
        ).fetchone()
        if row is None:
            raise DataUseProviderAuditAuthorityNotFound(
                "provider audit control authority does not exist"
            )
        payload, integrity = self._row_payload(row, "control authority")
        value = self._validated_control(payload, integrity)
        if (
            str(row["tenant_sha256"]) != self._tenant_sha256
            or str(row["state"]) != value.state
            or int(row["revision"]) != value.revision
            or float(row["valid_until"]) != value.valid_until
            or float(row["retained_until"]) != value.retained_until
        ):
            raise DataUseProviderAuditAuthorityIntegrityError(
                "control authority index fields failed integrity"
            )
        return value

    def _get_read_grant(
        self,
        connection: sqlite3.Connection,
        grant_id: str,
    ) -> ProviderAuditReadGrant:
        grant_ref = _ref(grant_id, "grant_id")
        row = connection.execute(
            "SELECT * FROM provider_audit_read_grants WHERE tenant_sha256=? AND grant_id=?",
            (self._tenant_sha256, grant_ref),
        ).fetchone()
        if row is None:
            raise DataUseProviderAuditAuthorityNotFound("provider audit read grant does not exist")
        payload, integrity = self._row_payload(row, "provider audit read grant")
        value = self._validated_read_grant(payload, integrity)
        if (
            str(row["tenant_sha256"]) != self._tenant_sha256
            or int(row["capability_revision"]) != value.capability_revision
            or int(row["revision"]) != value.revision
            or float(row["valid_until"]) != value.valid_until
            or float(row["retained_until"]) != value.retained_until
            or bool(row["revoked"]) != value.revoked
        ):
            raise DataUseProviderAuditAuthorityIntegrityError(
                "provider audit read-grant index fields failed integrity"
            )
        return value

    @staticmethod
    def _payload_json(payload: Mapping[str, Any]) -> str:
        return _canonical(payload).decode("ascii")

    def _insert_history(
        self,
        connection: sqlite3.Connection,
        *,
        object_type: str,
        object_id: str,
        revision: int,
        payload: Mapping[str, Any],
        integrity_sha256: str,
    ) -> None:
        if object_type not in {"control", "read"}:
            raise DataUseProviderAuditAuthorityIntegrityError(
                "provider audit authority history type is invalid"
            )
        connection.execute(
            "INSERT INTO provider_audit_authority_history("
            "object_type,object_id,revision,tenant_sha256,payload_json,integrity_sha256"
            ") VALUES(?,?,?,?,?,?)",
            (
                object_type,
                object_id,
                revision,
                self._tenant_sha256,
                self._payload_json(payload),
                integrity_sha256,
            ),
        )

    def _insert_control(
        self,
        connection: sqlite3.Connection,
        value: ProviderAuditAuthorityRecord,
    ) -> None:
        payload = _authority_payload(value)
        connection.execute(
            "INSERT INTO provider_audit_control_authorities("
            "authority_id,tenant_sha256,provider_id,binding_id,"
            "operation_idempotency_sha256,state,revision,valid_until,retained_until,"
            "payload_json,integrity_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                value.authority_id,
                self._tenant_sha256,
                value.provider_id,
                value.binding_id,
                value.operation_idempotency_sha256,
                value.state,
                value.revision,
                value.valid_until,
                value.retained_until,
                self._payload_json(payload),
                value.integrity_sha256,
            ),
        )
        self._insert_history(
            connection,
            object_type="control",
            object_id=value.authority_id,
            revision=value.revision,
            payload=payload,
            integrity_sha256=value.integrity_sha256,
        )

    def _insert_read_grant(
        self,
        connection: sqlite3.Connection,
        value: ProviderAuditReadGrant,
    ) -> None:
        payload = _read_grant_payload(value)
        connection.execute(
            "INSERT INTO provider_audit_read_grants("
            "grant_id,tenant_sha256,provider_id,binding_id,capability_revision,"
            "revision,valid_until,retained_until,revoked,payload_json,integrity_sha256"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                value.grant_id,
                self._tenant_sha256,
                value.provider_id,
                value.binding_id,
                value.capability_revision,
                value.revision,
                value.valid_until,
                value.retained_until,
                int(value.revoked),
                self._payload_json(payload),
                value.integrity_sha256,
            ),
        )
        self._insert_history(
            connection,
            object_type="read",
            object_id=value.grant_id,
            revision=value.revision,
            payload=payload,
            integrity_sha256=value.integrity_sha256,
        )

    def _replace_control(
        self,
        connection: sqlite3.Connection,
        current: ProviderAuditAuthorityRecord,
        value: ProviderAuditAuthorityRecord,
    ) -> ProviderAuditAuthorityRecord:
        if value.revision != current.revision + 1 or not _same(
            value.previous_integrity_sha256, current.integrity_sha256
        ):
            raise DataUseProviderAuditAuthorityIntegrityError(
                "control authority revision link is invalid"
            )
        value = replace(value, integrity_sha256=_sha256(_authority_payload(value)))
        self._validated_control(_authority_payload(value), value.integrity_sha256)
        cursor = connection.execute(
            "UPDATE provider_audit_control_authorities SET state=?,revision=?,"
            "valid_until=?,retained_until=?,payload_json=?,integrity_sha256=? "
            "WHERE tenant_sha256=? AND authority_id=? AND revision=? "
            "AND integrity_sha256=?",
            (
                value.state,
                value.revision,
                value.valid_until,
                value.retained_until,
                self._payload_json(_authority_payload(value)),
                value.integrity_sha256,
                self._tenant_sha256,
                current.authority_id,
                current.revision,
                current.integrity_sha256,
            ),
        )
        if cursor.rowcount != 1:
            raise DataUseProviderAuditAuthorityConflict("control authority revision changed")
        self._insert_history(
            connection,
            object_type="control",
            object_id=value.authority_id,
            revision=value.revision,
            payload=_authority_payload(value),
            integrity_sha256=value.integrity_sha256,
        )
        return value

    def _replace_read_grant(
        self,
        connection: sqlite3.Connection,
        current: ProviderAuditReadGrant,
        value: ProviderAuditReadGrant,
    ) -> ProviderAuditReadGrant:
        if value.revision != current.revision + 1 or not _same(
            value.previous_integrity_sha256, current.integrity_sha256
        ):
            raise DataUseProviderAuditAuthorityIntegrityError(
                "provider audit read-grant revision link is invalid"
            )
        value = replace(value, integrity_sha256=_sha256(_read_grant_payload(value)))
        self._validated_read_grant(_read_grant_payload(value), value.integrity_sha256)
        cursor = connection.execute(
            "UPDATE provider_audit_read_grants SET capability_revision=?,revision=?,"
            "valid_until=?,retained_until=?,revoked=?,payload_json=?,integrity_sha256=? "
            "WHERE tenant_sha256=? AND grant_id=? AND revision=? AND integrity_sha256=?",
            (
                value.capability_revision,
                value.revision,
                value.valid_until,
                value.retained_until,
                int(value.revoked),
                self._payload_json(_read_grant_payload(value)),
                value.integrity_sha256,
                self._tenant_sha256,
                current.grant_id,
                current.revision,
                current.integrity_sha256,
            ),
        )
        if cursor.rowcount != 1:
            raise DataUseProviderAuditAuthorityConflict(
                "provider audit read-grant revision changed"
            )
        self._insert_history(
            connection,
            object_type="read",
            object_id=value.grant_id,
            revision=value.revision,
            payload=_read_grant_payload(value),
            integrity_sha256=value.integrity_sha256,
        )
        return value

    def _audit(
        self,
        connection: sqlite3.Connection,
        *,
        action: str,
        object_ref: str,
        detail_sha256: str,
        now: float,
    ) -> None:
        selected_action = _ref(action, "audit action")
        selected_ref = _ref(object_ref, "audit object_ref")
        detail = _digest(detail_sha256, "audit detail_sha256")
        prior = connection.execute(
            "SELECT event_sha256 FROM provider_audit_authority_chain "
            "WHERE tenant_sha256=? ORDER BY sequence DESC LIMIT 1",
            (self._tenant_sha256,),
        ).fetchone()
        previous = "0" * 64 if prior is None else str(prior["event_sha256"])
        sequence_row = connection.execute(
            "SELECT COALESCE(MAX(sequence),0)+1 AS value FROM provider_audit_authority_chain"
        ).fetchone()
        sequence = int(sequence_row["value"])
        material = {
            "schema": AUDIT_EVENT_SCHEMA,
            "sequence": sequence,
            "tenant_sha256": self._tenant_sha256,
            "action": selected_action,
            "object_ref": selected_ref,
            "detail_sha256": detail,
            "occurred_at": now,
            "previous_event_sha256": previous,
        }
        connection.execute(
            "INSERT INTO provider_audit_authority_chain("
            "sequence,tenant_sha256,action,object_ref,detail_sha256,occurred_at,"
            "previous_event_sha256,event_sha256) VALUES(?,?,?,?,?,?,?,?)",
            (
                sequence,
                self._tenant_sha256,
                selected_action,
                selected_ref,
                detail,
                now,
                previous,
                _sha256(material),
            ),
        )

    @staticmethod
    def _operation_key(idempotency_key: str) -> str:
        key = _ref(
            idempotency_key,
            "idempotency_key",
            pattern=_IDEMPOTENCY_RE,
        )
        return _text_sha256(key)

    def _operation_replay(
        self,
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        action: str,
        request_sha256: str,
    ) -> ProviderAuditAuthorityRecord | ProviderAuditReadGrant | None:
        row = connection.execute(
            "SELECT * FROM provider_audit_authority_operations "
            "WHERE tenant_sha256=? AND key_sha256=?",
            (self._tenant_sha256, key_sha256),
        ).fetchone()
        if row is None:
            return None
        if str(row["action"]) != action or not _same(str(row["request_sha256"]), request_sha256):
            raise DataUseProviderAuditAuthorityConflict(
                "provider audit authority idempotency key was rebound"
            )
        object_type = str(row["object_type"])
        object_id = str(row["object_id"])
        historical = connection.execute(
            "SELECT 1 FROM provider_audit_authority_history "
            "WHERE tenant_sha256=? AND object_type=? AND object_id=? "
            "AND integrity_sha256=?",
            (
                self._tenant_sha256,
                object_type,
                object_id,
                str(row["result_integrity_sha256"]),
            ),
        ).fetchone()
        if historical is None:
            raise DataUseProviderAuditAuthorityIntegrityError(
                "provider audit authority idempotency result lost its evidence"
            )
        if object_type == "control":
            return self._get_control(connection, object_id)
        if object_type == "read":
            return self._get_read_grant(connection, object_id)
        raise DataUseProviderAuditAuthorityIntegrityError(
            "provider audit authority idempotency type is invalid"
        )

    def _save_operation(
        self,
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        action: str,
        request_sha256: str,
        object_type: str,
        value: ProviderAuditAuthorityRecord | ProviderAuditReadGrant,
        now: float,
    ) -> None:
        object_id = (
            value.authority_id
            if isinstance(value, ProviderAuditAuthorityRecord)
            else value.grant_id
        )
        connection.execute(
            "INSERT INTO provider_audit_authority_operations("
            "tenant_sha256,key_sha256,action,request_sha256,object_type,object_id,"
            "result_integrity_sha256,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                self._tenant_sha256,
                key_sha256,
                action,
                request_sha256,
                object_type,
                object_id,
                value.integrity_sha256,
                now,
            ),
        )

    def stage_operation(
        self,
        *,
        provider_id: str,
        binding_id: str,
        operation_idempotency_sha256: str,
        control_ir: Mapping[str, Any],
        operation: str,
        authority_revision: int,
        valid_until: float,
        retained_until: float,
        idempotency_key: str,
    ) -> ProviderAuditAuthorityRecord:
        """Stage a server-derived, digest-only expected-change projection."""

        self._check_gate()
        provider = _provider(provider_id)
        binding_ref = _ref(binding_id, "binding_id")
        idem = _digest(
            operation_idempotency_sha256,
            "operation_idempotency_sha256",
        )
        authority_rev = _integer(
            authority_revision,
            "authority_revision",
            1,
            2**31 - 1,
        )
        now = _now(self._clock)
        valid, retained = _bounded_lifetime(
            now=now,
            valid_until=valid_until,
            retained_until=retained_until,
        )
        binding = self._current_binding(provider, binding_ref)
        projection = self._project_control_ir(
            provider_id=provider,
            binding=binding,
            operation_idempotency_sha256=idem,
            control_ir=control_ir,
            operation=operation,
        )
        request = {
            "action": "stage_operation",
            "provider_id": provider,
            "binding_id": binding_ref,
            "binding_revision": projection.binding_revision,
            "binding_sha256": projection.binding_sha256,
            "operation_idempotency_sha256": idem,
            "projection_sha256": projection.projection_sha256,
            "authority_revision": authority_rev,
            "valid_until": valid,
            "retained_until": retained,
        }
        request_sha = _sha256(request)
        key_sha = self._operation_key(idempotency_key)
        authority_id = f"DUAO-{_sha256(request)[:32]}"
        value = ProviderAuditAuthorityRecord(
            authority_id=authority_id,
            tenant_sha256=self._tenant_sha256,
            provider_id=provider,
            binding_id=binding_ref,
            binding_revision=projection.binding_revision,
            binding_sha256=projection.binding_sha256,
            operation_idempotency_sha256=idem,
            compilation_id=projection.compilation_id,
            ir_sha256=projection.ir_sha256,
            operation=projection.operation,
            control_state_sha256=projection.control_state_sha256,
            target_state_sha256=projection.target_state_sha256,
            expected_changes=projection.expected_changes,
            projection_sha256=projection.projection_sha256,
            operation_request_sha256=None,
            operation_result_sha256=None,
            correlation_sha256=None,
            no_change=None,
            authority_revision=authority_rev,
            control_authority_sha256=None,
            state="staged",
            valid_until=valid,
            retained_until=retained,
            created_at=now,
            updated_at=now,
            finalized_at=None,
            revoked_at=None,
            revision=1,
            previous_integrity_sha256=None,
            integrity_sha256="0" * 64,
        )
        value = replace(value, integrity_sha256=_sha256(_authority_payload(value)))
        self._validated_control(_authority_payload(value), value.integrity_sha256)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation_replay(
                connection,
                key_sha256=key_sha,
                action="stage_operation",
                request_sha256=request_sha,
            )
            if replay is not None:
                if not isinstance(replay, ProviderAuditAuthorityRecord):
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "stage-operation replay has the wrong authority type"
                    )
                connection.commit()
                return replay
            latest = self._current_binding(provider, binding_ref)
            if int(latest["revision"]) != projection.binding_revision or not _same(
                latest["binding_sha256"], projection.binding_sha256
            ):
                raise DataUseProviderAuditAuthorityConflict(
                    "provider binding drifted during authority staging"
                )
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM provider_audit_control_authorities WHERE tenant_sha256=?",
                    (self._tenant_sha256,),
                ).fetchone()[0]
            )
            if count >= _MAX_CONTROL_AUTHORITIES:
                raise DataUseProviderAuditAuthorityConflict(
                    "provider audit control-authority capacity exhausted"
                )
            if (
                connection.execute(
                    "SELECT 1 FROM provider_audit_authority_chain "
                    "WHERE tenant_sha256=? AND object_ref=? LIMIT 1",
                    (self._tenant_sha256, authority_id),
                ).fetchone()
                is not None
            ):
                raise DataUseProviderAuditAuthorityConflict(
                    "retired provider audit control-authority id cannot be reused"
                )
            self._insert_control(connection, value)
            self._audit(
                connection,
                action="control_staged",
                object_ref=authority_id,
                detail_sha256=value.integrity_sha256,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha,
                action="stage_operation",
                request_sha256=request_sha,
                object_type="control",
                value=value,
                now=now,
            )
            connection.commit()
            return value

    def get_control_authority_record(
        self,
        authority_id: str,
    ) -> ProviderAuditAuthorityRecord:
        self._check_gate()
        with self._connect() as connection:
            return self._get_control(connection, authority_id)

    def get_control_authority_for_operation(
        self,
        provider_id: str,
        binding_id: str,
        operation_idempotency_sha256: str,
    ) -> ProviderAuditAuthorityRecord:
        """Look up the unique durable outbox record for an exact operation."""

        self._check_gate()
        provider = _provider(provider_id)
        binding_ref = _ref(binding_id, "binding_id")
        operation_idem = _digest(
            operation_idempotency_sha256,
            "operation_idempotency_sha256",
        )
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT authority_id FROM provider_audit_control_authorities "
                "WHERE tenant_sha256=? AND provider_id=? AND binding_id=? "
                "AND operation_idempotency_sha256=?",
                (self._tenant_sha256, provider, binding_ref, operation_idem),
            ).fetchall()
            if not rows:
                raise DataUseProviderAuditAuthorityNotFound(
                    "provider audit control authority does not exist for operation"
                )
            if len(rows) != 1:
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "provider audit operation has ambiguous control authority"
                )
            return self._get_control(connection, str(rows[0]["authority_id"]))

    def list_control_authorities(
        self,
        *,
        state: str | None = None,
        limit: int = 100,
    ) -> tuple[ProviderAuditAuthorityRecord, ...]:
        self._check_gate()
        bounded = _integer(limit, "limit", 1, 500)
        if state is not None and state not in _AUTHORITY_STATES:
            raise DataUseProviderAuditAuthorityValidationError("control authority state is invalid")
        with self._connect() as connection:
            if state is None:
                rows = connection.execute(
                    "SELECT authority_id FROM provider_audit_control_authorities "
                    "WHERE tenant_sha256=? ORDER BY valid_until,authority_id LIMIT ?",
                    (self._tenant_sha256, bounded),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT authority_id FROM provider_audit_control_authorities "
                    "WHERE tenant_sha256=? AND state=? "
                    "ORDER BY valid_until,authority_id LIMIT ?",
                    (self._tenant_sha256, state, bounded),
                ).fetchall()
            return tuple(self._get_control(connection, str(row["authority_id"])) for row in rows)

    def next_control_authorities(
        self,
        *,
        state: str,
        limit: int = 100,
    ) -> tuple[ProviderAuditAuthorityRecord, ...]:
        """Return a fair, durable recovery page and advance its state cursor.

        A fixed first page lets a persistent pending/failing prefix starve all
        later recoverable records.  This operational cursor advances even when
        callers cannot finalize the returned rows, then wraps after the tail.
        It contains only a closed state, timestamp, and opaque authority ID.
        """

        self._check_gate()
        bounded = _integer(limit, "limit", 1, 500)
        if state not in {"staged", "finalized"}:
            raise DataUseProviderAuditAuthorityValidationError(
                "recovery cursor state is invalid"
            )
        with self._connect() as connection:
            self._begin(connection)
            cursor = connection.execute(
                "SELECT valid_until,authority_id FROM provider_audit_recovery_cursors "
                "WHERE tenant_sha256=? AND state=?",
                (self._tenant_sha256, state),
            ).fetchone()
            rows: list[sqlite3.Row]
            if cursor is None:
                rows = connection.execute(
                    "SELECT authority_id,valid_until FROM provider_audit_control_authorities "
                    "WHERE tenant_sha256=? AND state=? "
                    "ORDER BY valid_until,authority_id LIMIT ?",
                    (self._tenant_sha256, state, bounded),
                ).fetchall()
            else:
                cursor_time = _timestamp(cursor["valid_until"], "recovery cursor valid_until")
                cursor_id = _ref(cursor["authority_id"], "recovery cursor authority_id")
                rows = connection.execute(
                    "SELECT authority_id,valid_until FROM provider_audit_control_authorities "
                    "WHERE tenant_sha256=? AND state=? "
                    "AND (valid_until>? OR (valid_until=? AND authority_id>?)) "
                    "ORDER BY valid_until,authority_id LIMIT ?",
                    (
                        self._tenant_sha256,
                        state,
                        cursor_time,
                        cursor_time,
                        cursor_id,
                        bounded,
                    ),
                ).fetchall()
                if not rows:
                    rows = connection.execute(
                        "SELECT authority_id,valid_until "
                        "FROM provider_audit_control_authorities "
                        "WHERE tenant_sha256=? AND state=? "
                        "ORDER BY valid_until,authority_id LIMIT ?",
                        (self._tenant_sha256, state, bounded),
                    ).fetchall()
            if rows:
                last = rows[-1]
                now = _now(self._clock)
                connection.execute(
                    "INSERT INTO provider_audit_recovery_cursors("
                    "tenant_sha256,state,valid_until,authority_id,updated_at) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(tenant_sha256,state) DO UPDATE SET "
                    "valid_until=excluded.valid_until,authority_id=excluded.authority_id,"
                    "updated_at=excluded.updated_at",
                    (
                        self._tenant_sha256,
                        state,
                        float(last["valid_until"]),
                        str(last["authority_id"]),
                        now,
                    ),
                )
            else:
                connection.execute(
                    "DELETE FROM provider_audit_recovery_cursors "
                    "WHERE tenant_sha256=? AND state=?",
                    (self._tenant_sha256, state),
                )
            values = tuple(
                self._get_control(connection, str(row["authority_id"])) for row in rows
            )
            connection.commit()
            return values

    def finalize_operation(
        self,
        authority_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ProviderAuditAuthorityRecord:
        """Finalize one staged projection from exact immutable operation evidence."""

        self._check_gate()
        authority_ref = _ref(authority_id, "authority_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        request = {
            "action": "finalize_operation",
            "authority_id": authority_ref,
            "expected_revision": expected,
        }
        request_sha = _sha256(request)
        key_sha = self._operation_key(idempotency_key)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation_replay(
                connection,
                key_sha256=key_sha,
                action="finalize_operation",
                request_sha256=request_sha,
            )
            if replay is not None:
                if not isinstance(replay, ProviderAuditAuthorityRecord):
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "finalize-operation replay has the wrong authority type"
                    )
                connection.commit()
                return replay
            current = self._get_control(connection, authority_ref)
            now = _now(self._clock)
            if current.revision != expected or current.state != "staged":
                raise DataUseProviderAuditAuthorityConflict(
                    "control authority is not the expected staged revision"
                )
            if current.valid_until <= now:
                raise DataUseProviderAuditAuthorityConflict(
                    "control authority expired before finalization"
                )
            first_binding = self._current_binding(
                current.provider_id,
                current.binding_id,
            )
            first_operation, first_result = self._validate_provider_operation(
                current,
                first_binding,
            )
            second_binding = self._current_binding(
                current.provider_id,
                current.binding_id,
            )
            second_operation, second_result = self._validate_provider_operation(
                current,
                second_binding,
            )
            first_fingerprint = _sha256(
                {
                    "binding_revision": first_binding["revision"],
                    "binding_sha256": first_binding["binding_sha256"],
                    "operation_request_sha256": first_operation["request_sha256"],
                    "result_sha256": _sha256(first_result),
                }
            )
            second_fingerprint = _sha256(
                {
                    "binding_revision": second_binding["revision"],
                    "binding_sha256": second_binding["binding_sha256"],
                    "operation_request_sha256": second_operation["request_sha256"],
                    "result_sha256": _sha256(second_result),
                }
            )
            if not _same(first_fingerprint, second_fingerprint):
                raise DataUseProviderAuditAuthorityConflict(
                    "provider operation authority drifted during finalization"
                )
            no_change = bool(second_result["no_change"])
            correlation = operation_correlation_sha256(
                provider_id=current.provider_id,
                binding_sha256=current.binding_sha256,
                operation_idempotency_sha256=current.operation_idempotency_sha256,
                operation_request_sha256=str(second_operation["request_sha256"]),
            )
            value = replace(
                current,
                expected_changes=() if no_change else current.expected_changes,
                operation_request_sha256=str(second_operation["request_sha256"]),
                operation_result_sha256=_sha256(second_result),
                correlation_sha256=correlation,
                no_change=no_change,
                control_authority_sha256="0" * 64,
                state="finalized",
                updated_at=now,
                finalized_at=now,
                revision=current.revision + 1,
                previous_integrity_sha256=current.integrity_sha256,
                integrity_sha256="0" * 64,
            )
            authority = self._control_authority(value, revoked=False)
            value = replace(
                value,
                control_authority_sha256=authority.authority_sha256,
            )
            value = self._replace_control(connection, current, value)
            self._audit(
                connection,
                action="control_finalized",
                object_ref=value.authority_id,
                detail_sha256=value.integrity_sha256,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha,
                action="finalize_operation",
                request_sha256=request_sha,
                object_type="control",
                value=value,
                now=now,
            )
            connection.commit()
            return value

    def mark_registered(
        self,
        authority_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ProviderAuditAuthorityRecord:
        """Durably acknowledge that the audit store accepted this authority."""

        self._check_gate()
        authority_ref = _ref(authority_id, "authority_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        request = {
            "action": "mark_registered",
            "authority_id": authority_ref,
            "expected_revision": expected,
        }
        request_sha = _sha256(request)
        key_sha = self._operation_key(idempotency_key)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation_replay(
                connection,
                key_sha256=key_sha,
                action="mark_registered",
                request_sha256=request_sha,
            )
            if replay is not None:
                if not isinstance(replay, ProviderAuditAuthorityRecord):
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "registration replay has the wrong authority type"
                    )
                connection.commit()
                return replay
            current = self._get_control(connection, authority_ref)
            if current.revision != expected or current.state != "finalized":
                raise DataUseProviderAuditAuthorityConflict(
                    "control authority is not the expected finalized revision"
                )
            now = _now(self._clock)
            value = replace(
                current,
                state="registered",
                updated_at=now,
                revision=current.revision + 1,
                previous_integrity_sha256=current.integrity_sha256,
                integrity_sha256="0" * 64,
            )
            value = self._replace_control(connection, current, value)
            self._audit(
                connection,
                action="control_registered",
                object_ref=value.authority_id,
                detail_sha256=value.integrity_sha256,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha,
                action="mark_registered",
                request_sha256=request_sha,
                object_type="control",
                value=value,
                now=now,
            )
            connection.commit()
            return value

    def recover_finalizable(
        self,
        *,
        limit: int = 100,
    ) -> tuple[ProviderAuditAuthorityRecord, ...]:
        """Finalize bounded staged records whose provider operation completed."""

        self._check_gate()
        bounded = _integer(limit, "limit", 1, 500)
        staged = self.next_control_authorities(state="staged", limit=bounded)
        recovered: list[ProviderAuditAuthorityRecord] = []
        for value in staged:
            binding = self._current_binding(value.provider_id, value.binding_id)
            if self._recovery_operation_status(value, binding) != "complete":
                continue
            self._validate_provider_operation(value, binding)
            recovered.append(
                self.finalize_operation(
                    value.authority_id,
                    expected_revision=value.revision,
                    idempotency_key=(f"recover:{value.authority_id}:{value.revision}"),
                )
            )
        return tuple(recovered)

    def revoke_control_authority(
        self,
        authority_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ProviderAuditAuthorityRecord:
        """Revoke a finalized control authority without deleting its evidence."""

        self._check_gate()
        authority_ref = _ref(authority_id, "authority_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        request = {
            "action": "revoke_control_authority",
            "authority_id": authority_ref,
            "expected_revision": expected,
        }
        request_sha = _sha256(request)
        key_sha = self._operation_key(idempotency_key)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation_replay(
                connection,
                key_sha256=key_sha,
                action="revoke_control_authority",
                request_sha256=request_sha,
            )
            if replay is not None:
                if not isinstance(replay, ProviderAuditAuthorityRecord):
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "control revocation replay has the wrong authority type"
                    )
                connection.commit()
                return replay
            current = self._get_control(connection, authority_ref)
            if current.revision != expected or current.state not in _ACTIVE_CONTROL_STATES:
                raise DataUseProviderAuditAuthorityConflict(
                    "control authority is not the expected active revision"
                )
            now = _now(self._clock)
            value = replace(
                current,
                authority_revision=current.authority_revision + 1,
                control_authority_sha256="0" * 64,
                state="revoked",
                updated_at=now,
                revoked_at=now,
                revision=current.revision + 1,
                previous_integrity_sha256=current.integrity_sha256,
                integrity_sha256="0" * 64,
            )
            authority = self._control_authority(value, revoked=True)
            value = replace(
                value,
                control_authority_sha256=authority.authority_sha256,
            )
            value = self._replace_control(connection, current, value)
            self._audit(
                connection,
                action="control_revoked",
                object_ref=value.authority_id,
                detail_sha256=value.integrity_sha256,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha,
                action="revoke_control_authority",
                request_sha256=request_sha,
                object_type="control",
                value=value,
                now=now,
            )
            connection.commit()
            return value

    def resolve_control_authority(
        self,
        provider_id: str,
        binding_id: str,
        operation_idempotency_sha256: str,
        result: Mapping[str, Any],
    ) -> ProviderAuditControlAuthority:
        """Resolve exactly one current finalized authority for the audit store."""

        self._check_gate()
        provider = _provider(provider_id)
        binding_ref = _ref(binding_id, "binding_id")
        operation_idem = _digest(
            operation_idempotency_sha256,
            "operation_idempotency_sha256",
        )
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT authority_id FROM provider_audit_control_authorities "
                "WHERE tenant_sha256=? AND provider_id=? AND binding_id=? "
                "AND operation_idempotency_sha256=? "
                "AND state IN ('finalized','registered')",
                (self._tenant_sha256, provider, binding_ref, operation_idem),
            ).fetchall()
            if len(rows) != 1:
                raise DataUseProviderAuditAuthorityConflict(
                    "exact finalized control authority is unavailable"
                )
            value = self._get_control(connection, str(rows[0]["authority_id"]))
        now = _now(self._clock)
        if value.valid_until <= now or value.state not in _ACTIVE_CONTROL_STATES:
            raise DataUseProviderAuditAuthorityConflict(
                "provider audit control authority is expired or revoked"
            )
        binding = self._current_binding(provider, binding_ref)
        _operation, current_result = self._validate_provider_operation(value, binding)
        supplied = _plain_json(result, "provider result")
        if not isinstance(supplied, dict) or not _same(_sha256(supplied), _sha256(current_result)):
            raise DataUseProviderAuditAuthorityConflict(
                "provider result is not bound to the finalized authority"
            )
        authority = self._control_authority(value, revoked=False)
        if not _same(authority.authority_sha256, value.control_authority_sha256):
            raise DataUseProviderAuditAuthorityIntegrityError(
                "finalized control authority digest failed integrity"
            )
        return authority

    def issue_read_grant(
        self,
        *,
        provider_id: str,
        binding_id: str,
        expected_binding_revision: int,
        expected_binding_sha256: str,
        capability_revision: int,
        valid_until: float,
        retained_until: float,
        expected_revision: int,
        idempotency_key: str,
    ) -> ProviderAuditReadGrant:
        """Issue an exact read grant; the enable flag never implies this grant."""

        self._check_gate()
        provider = _provider(provider_id)
        binding_ref = _ref(binding_id, "binding_id")
        expected_binding_rev = _integer(
            expected_binding_revision,
            "expected_binding_revision",
            1,
            2**31 - 1,
        )
        expected_binding_sha = _digest(
            expected_binding_sha256,
            "expected_binding_sha256",
        )
        capability_rev = _integer(
            capability_revision,
            "capability_revision",
            1,
            2**31 - 1,
        )
        expected = _integer(expected_revision, "expected_revision", 0, 2**31 - 1)
        if expected != 0:
            raise DataUseProviderAuditAuthorityValidationError(
                "new read-grant issuance requires expected_revision zero"
            )
        now = _now(self._clock)
        valid, retained = _bounded_lifetime(
            now=now,
            valid_until=valid_until,
            retained_until=retained_until,
        )
        binding = self._current_binding(provider, binding_ref)
        if binding["revision"] != expected_binding_rev or not _same(
            binding["binding_sha256"], expected_binding_sha
        ):
            raise DataUseProviderAuditAuthorityConflict(
                "provider binding does not match read-grant issuance pins"
            )
        request = {
            "action": "issue_read_grant",
            "provider_id": provider,
            "binding_id": binding_ref,
            "binding_revision": binding["revision"],
            "binding_sha256": binding["binding_sha256"],
            "expected_binding_revision": expected_binding_rev,
            "expected_binding_sha256": expected_binding_sha,
            "credential_key_id_sha256": binding["credential_key_id_sha256"],
            "credential_revision": binding["credential_revision"],
            "credential_authority_sha256": binding["credential_authority_sha256"],
            "capability": "provider_audit_read",
            "capability_revision": capability_rev,
            "valid_until": valid,
            "retained_until": retained,
            "expected_revision": expected,
        }
        request_sha = _sha256(request)
        key_sha = self._operation_key(idempotency_key)
        grant_id = f"DUAR-{_sha256(request)[:32]}"
        value = ProviderAuditReadGrant(
            grant_id=grant_id,
            tenant_sha256=self._tenant_sha256,
            provider_id=provider,
            binding_id=binding_ref,
            binding_revision=int(binding["revision"]),
            binding_sha256=str(binding["binding_sha256"]),
            credential_key_id_sha256=str(binding["credential_key_id_sha256"]),
            credential_revision=int(binding["credential_revision"]),
            credential_authority_sha256=str(binding["credential_authority_sha256"]),
            capability="provider_audit_read",
            capability_revision=capability_rev,
            authority_sha256="0" * 64,
            valid_until=valid,
            retained_until=retained,
            revoked=False,
            created_at=now,
            updated_at=now,
            revoked_at=None,
            revocation_reason_sha256=None,
            revision=1,
            previous_integrity_sha256=None,
            integrity_sha256="0" * 64,
        )
        authority = self._read_authority(value)
        value = replace(value, authority_sha256=authority.authority_sha256)
        value = replace(value, integrity_sha256=_sha256(_read_grant_payload(value)))
        self._validated_read_grant(_read_grant_payload(value), value.integrity_sha256)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation_replay(
                connection,
                key_sha256=key_sha,
                action="issue_read_grant",
                request_sha256=request_sha,
            )
            if replay is not None:
                if not isinstance(replay, ProviderAuditReadGrant):
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "read-grant issuance replay has the wrong authority type"
                    )
                connection.commit()
                return replay
            latest = self._current_binding(provider, binding_ref)
            binding_fingerprint = _sha256(
                {
                    "revision": binding["revision"],
                    "binding_sha256": binding["binding_sha256"],
                    "credential_key_id_sha256": binding["credential_key_id_sha256"],
                    "credential_revision": binding["credential_revision"],
                    "credential_authority_sha256": binding["credential_authority_sha256"],
                }
            )
            latest_fingerprint = _sha256(
                {
                    "revision": latest["revision"],
                    "binding_sha256": latest["binding_sha256"],
                    "credential_key_id_sha256": latest["credential_key_id_sha256"],
                    "credential_revision": latest["credential_revision"],
                    "credential_authority_sha256": latest["credential_authority_sha256"],
                }
            )
            if not _same(binding_fingerprint, latest_fingerprint):
                raise DataUseProviderAuditAuthorityConflict(
                    "provider binding drifted during read-grant issuance"
                )
            active = connection.execute(
                "SELECT grant_id FROM provider_audit_read_grants "
                "WHERE tenant_sha256=? AND provider_id=? AND binding_id=? "
                "AND revoked=0 AND valid_until>? LIMIT 1",
                (self._tenant_sha256, provider, binding_ref, now),
            ).fetchone()
            if active is not None:
                raise DataUseProviderAuditAuthorityConflict(
                    "an active provider audit read grant must be revoked before rotation"
                )
            maximum = connection.execute(
                "SELECT MAX(capability_revision) AS value "
                "FROM provider_audit_read_grants WHERE tenant_sha256=? "
                "AND provider_id=? AND binding_id=?",
                (self._tenant_sha256, provider, binding_ref),
            ).fetchone()["value"]
            if maximum is not None and capability_rev <= int(maximum):
                raise DataUseProviderAuditAuthorityConflict(
                    "provider audit capability revision is not monotonic"
                )
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM provider_audit_read_grants WHERE tenant_sha256=?",
                    (self._tenant_sha256,),
                ).fetchone()[0]
            )
            if count >= _MAX_READ_GRANTS:
                raise DataUseProviderAuditAuthorityConflict(
                    "provider audit read-grant capacity exhausted"
                )
            if (
                connection.execute(
                    "SELECT 1 FROM provider_audit_authority_chain "
                    "WHERE tenant_sha256=? AND object_ref=? LIMIT 1",
                    (self._tenant_sha256, grant_id),
                ).fetchone()
                is not None
            ):
                raise DataUseProviderAuditAuthorityConflict(
                    "retired provider audit read-grant id cannot be reused"
                )
            self._insert_read_grant(connection, value)
            self._audit(
                connection,
                action="read_grant_issued",
                object_ref=grant_id,
                detail_sha256=value.integrity_sha256,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha,
                action="issue_read_grant",
                request_sha256=request_sha,
                object_type="read",
                value=value,
                now=now,
            )
            connection.commit()
            return value

    def get_read_grant(self, grant_id: str) -> ProviderAuditReadGrant:
        self._check_gate()
        with self._connect() as connection:
            return self._get_read_grant(connection, grant_id)

    def get_current_read_grant(
        self,
        provider_id: str,
        binding_id: str,
    ) -> ProviderAuditReadGrant:
        """Return the single active, unexpired read-grant record for operator CAS."""

        self._check_gate()
        provider = _provider(provider_id)
        binding_ref = _ref(binding_id, "binding_id")
        now = _now(self._clock)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT grant_id FROM provider_audit_read_grants "
                "WHERE tenant_sha256=? AND provider_id=? AND binding_id=? "
                "AND revoked=0 AND valid_until>? ORDER BY capability_revision DESC",
                (self._tenant_sha256, provider, binding_ref, now),
            ).fetchall()
            if not rows:
                raise DataUseProviderAuditAuthorityNotFound(
                    "active provider audit read grant does not exist"
                )
            if len(rows) != 1:
                raise DataUseProviderAuditAuthorityConflict(
                    "active provider audit read grant is ambiguous"
                )
            return self._get_read_grant(connection, str(rows[0]["grant_id"]))

    def list_read_grants(
        self,
        *,
        provider_id: str | None = None,
        limit: int = 100,
    ) -> tuple[ProviderAuditReadGrant, ...]:
        self._check_gate()
        bounded = _integer(limit, "limit", 1, 500)
        provider = None if provider_id is None else _provider(provider_id)
        with self._connect() as connection:
            if provider is None:
                rows = connection.execute(
                    "SELECT grant_id FROM provider_audit_read_grants "
                    "WHERE tenant_sha256=? "
                    "ORDER BY capability_revision DESC,grant_id LIMIT ?",
                    (self._tenant_sha256, bounded),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT grant_id FROM provider_audit_read_grants "
                    "WHERE tenant_sha256=? AND provider_id=? "
                    "ORDER BY capability_revision DESC,grant_id LIMIT ?",
                    (self._tenant_sha256, provider, bounded),
                ).fetchall()
            return tuple(self._get_read_grant(connection, str(row["grant_id"])) for row in rows)

    def revoke_read_grant(
        self,
        grant_id: str,
        *,
        expected_revision: int,
        expected_integrity_sha256: str,
        reason_sha256: str,
        idempotency_key: str,
    ) -> ProviderAuditReadGrant:
        """Revoke one exact read grant with CAS and immutable evidence."""

        self._check_gate()
        grant_ref = _ref(grant_id, "grant_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        expected_integrity = _digest(
            expected_integrity_sha256,
            "expected_integrity_sha256",
        )
        reason = _digest(reason_sha256, "reason_sha256")
        request = {
            "action": "revoke_read_grant",
            "grant_id": grant_ref,
            "expected_revision": expected,
            "expected_integrity_sha256": expected_integrity,
            "reason_sha256": reason,
        }
        request_sha = _sha256(request)
        key_sha = self._operation_key(idempotency_key)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation_replay(
                connection,
                key_sha256=key_sha,
                action="revoke_read_grant",
                request_sha256=request_sha,
            )
            if replay is not None:
                if not isinstance(replay, ProviderAuditReadGrant):
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "read-grant revocation replay has the wrong authority type"
                    )
                connection.commit()
                return replay
            current = self._get_read_grant(connection, grant_ref)
            if (
                current.revision != expected
                or not _same(current.integrity_sha256, expected_integrity)
                or current.revoked
            ):
                raise DataUseProviderAuditAuthorityConflict(
                    "provider audit read grant is not the expected active revision"
                )
            now = _now(self._clock)
            value = replace(
                current,
                authority_sha256="0" * 64,
                revoked=True,
                updated_at=now,
                revoked_at=now,
                revocation_reason_sha256=reason,
                revision=current.revision + 1,
                previous_integrity_sha256=current.integrity_sha256,
                integrity_sha256="0" * 64,
            )
            authority = self._read_authority(value)
            value = replace(value, authority_sha256=authority.authority_sha256)
            value = self._replace_read_grant(connection, current, value)
            self._audit(
                connection,
                action="read_grant_revoked",
                object_ref=value.grant_id,
                detail_sha256=value.integrity_sha256,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha,
                action="revoke_read_grant",
                request_sha256=request_sha,
                object_type="read",
                value=value,
                now=now,
            )
            connection.commit()
            return value

    def resolve_read_authority(
        self,
        provider_id: str,
        binding_id: str,
    ) -> ProviderAuditReadAuthority:
        """Resolve one explicit current read grant for the audit runtime."""

        self._check_gate()
        provider = _provider(provider_id)
        binding_ref = _ref(binding_id, "binding_id")
        now = _now(self._clock)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT grant_id FROM provider_audit_read_grants "
                "WHERE tenant_sha256=? AND provider_id=? AND binding_id=? "
                "AND revoked=0 AND valid_until>? ORDER BY capability_revision DESC",
                (self._tenant_sha256, provider, binding_ref, now),
            ).fetchall()
            if len(rows) != 1:
                raise DataUseProviderAuditAuthorityConflict(
                    "exact active provider audit read grant is unavailable"
                )
            value = self._get_read_grant(connection, str(rows[0]["grant_id"]))
        binding = self._current_binding(provider, binding_ref)
        expected = (
            int(binding["revision"]),
            str(binding["binding_sha256"]),
            str(binding["credential_key_id_sha256"]),
            int(binding["credential_revision"]),
            str(binding["credential_authority_sha256"]),
        )
        actual = (
            value.binding_revision,
            value.binding_sha256,
            value.credential_key_id_sha256,
            value.credential_revision,
            value.credential_authority_sha256,
        )
        if actual != expected or value.revoked or value.valid_until <= now:
            raise DataUseProviderAuditAuthorityConflict(
                "provider audit read authority is stale, expired, or revoked"
            )
        authority = self._read_authority(value)
        if not _same(authority.authority_sha256, value.authority_sha256):
            raise DataUseProviderAuditAuthorityIntegrityError(
                "provider audit read-authority digest failed integrity"
            )
        return authority

    def verify_integrity(  # noqa: C901 - verifies every persisted authority chain
        self,
    ) -> ProviderAuditAuthorityIntegrityVerification:
        """Verify current records, revision chains, idempotency, and audit chain."""

        self._check_gate()
        with self._connect() as connection:
            metadata = dict(
                connection.execute("SELECT key,value FROM provider_audit_authority_meta").fetchall()
            )
            if metadata != {
                "schema_version": _SCHEMA_VERSION,
                "tenant_sha256": self._tenant_sha256,
            }:
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "provider audit authority metadata failed integrity"
                )
            for table in (
                "provider_audit_recovery_cursors",
                "provider_audit_control_authorities",
                "provider_audit_read_grants",
                "provider_audit_authority_history",
                "provider_audit_authority_operations",
                "provider_audit_authority_chain",
            ):
                wrong = int(
                    connection.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE tenant_sha256<>?",  # noqa: S608
                        (self._tenant_sha256,),
                    ).fetchone()[0]
                )
                if wrong:
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "provider audit authority database contains another tenant"
                    )

            cursor_rows = connection.execute(
                "SELECT * FROM provider_audit_recovery_cursors "
                "WHERE tenant_sha256=? ORDER BY state",
                (self._tenant_sha256,),
            ).fetchall()
            if len(cursor_rows) > 2:
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "provider audit recovery cursor count is invalid"
                )
            for row in cursor_rows:
                if row["state"] not in {"staged", "finalized"}:
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "provider audit recovery cursor state is invalid"
                    )
                _timestamp(row["valid_until"], "recovery cursor valid_until")
                _ref(row["authority_id"], "recovery cursor authority_id")
                _timestamp(row["updated_at"], "recovery cursor updated_at")

            history_rows = connection.execute(
                "SELECT * FROM provider_audit_authority_history "
                "WHERE tenant_sha256=? ORDER BY object_type,object_id,revision",
                (self._tenant_sha256,),
            ).fetchall()
            history: dict[tuple[str, str], list[tuple[int, str]]] = {}
            for row in history_rows:
                object_type = str(row["object_type"])
                object_id = str(row["object_id"])
                revision = int(row["revision"])
                payload, integrity = self._row_payload(
                    row,
                    "provider audit authority history",
                )
                if object_type == "control":
                    value = self._validated_control(payload, integrity)
                    if value.authority_id != object_id or value.revision != revision:
                        raise DataUseProviderAuditAuthorityIntegrityError(
                            "control authority history index failed integrity"
                        )
                    previous = value.previous_integrity_sha256
                elif object_type == "read":
                    grant = self._validated_read_grant(payload, integrity)
                    if grant.grant_id != object_id or grant.revision != revision:
                        raise DataUseProviderAuditAuthorityIntegrityError(
                            "provider audit read history index failed integrity"
                        )
                    previous = grant.previous_integrity_sha256
                else:
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "provider audit authority history type is invalid"
                    )
                entries = history.setdefault((object_type, object_id), [])
                if revision != len(entries) + 1:
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "provider audit authority history revisions are not contiguous"
                    )
                expected_previous = None if not entries else entries[-1][1]
                if previous != expected_previous:
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "provider audit authority history link failed integrity"
                    )
                entries.append((revision, integrity))

            current: dict[tuple[str, str], tuple[int, str]] = {}
            control_rows = connection.execute(
                "SELECT authority_id FROM provider_audit_control_authorities "
                "WHERE tenant_sha256=? ORDER BY authority_id",
                (self._tenant_sha256,),
            ).fetchall()
            for row in control_rows:
                value = self._get_control(connection, str(row["authority_id"]))
                current[("control", value.authority_id)] = (
                    value.revision,
                    value.integrity_sha256,
                )
            read_rows = connection.execute(
                "SELECT grant_id FROM provider_audit_read_grants "
                "WHERE tenant_sha256=? ORDER BY grant_id",
                (self._tenant_sha256,),
            ).fetchall()
            for row in read_rows:
                value = self._get_read_grant(connection, str(row["grant_id"]))
                current[("read", value.grant_id)] = (
                    value.revision,
                    value.integrity_sha256,
                )
            if set(current) != set(history):
                raise DataUseProviderAuditAuthorityIntegrityError(
                    "current provider audit authorities and history diverged"
                )
            for key, current_pin in current.items():
                if history[key][-1] != current_pin:
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "current provider audit authority is not its latest revision"
                    )

            operation_rows = connection.execute(
                "SELECT * FROM provider_audit_authority_operations "
                "WHERE tenant_sha256=? ORDER BY key_sha256",
                (self._tenant_sha256,),
            ).fetchall()
            for row in operation_rows:
                _digest(row["key_sha256"], "idempotency key_sha256")
                _ref(row["action"], "idempotency action")
                _digest(row["request_sha256"], "idempotency request_sha256")
                object_type = str(row["object_type"])
                object_id = _ref(row["object_id"], "idempotency object_id")
                result_integrity = _digest(
                    row["result_integrity_sha256"],
                    "idempotency result_integrity_sha256",
                )
                _timestamp(row["created_at"], "idempotency created_at")
                if object_type not in {"control", "read"} or not any(
                    _same(result_integrity, item[1])
                    for item in history.get((object_type, object_id), [])
                ):
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "provider audit authority idempotency evidence failed integrity"
                    )

            audit_rows = connection.execute(
                "SELECT * FROM provider_audit_authority_chain "
                "WHERE tenant_sha256=? ORDER BY sequence",
                (self._tenant_sha256,),
            ).fetchall()
            previous = "0" * 64
            previous_sequence = 0
            for row in audit_rows:
                sequence = int(row["sequence"])
                if sequence != previous_sequence + 1:
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "provider audit authority event sequence has a gap"
                    )
                material = {
                    "schema": AUDIT_EVENT_SCHEMA,
                    "sequence": sequence,
                    "tenant_sha256": self._tenant_sha256,
                    "action": _ref(row["action"], "audit action"),
                    "object_ref": _ref(row["object_ref"], "audit object_ref"),
                    "detail_sha256": _digest(
                        row["detail_sha256"],
                        "audit detail_sha256",
                    ),
                    "occurred_at": _timestamp(row["occurred_at"], "audit occurred_at"),
                    "previous_event_sha256": _digest(
                        row["previous_event_sha256"],
                        "audit previous_event_sha256",
                    ),
                }
                actual = _digest(row["event_sha256"], "audit event_sha256")
                if not _same(material["previous_event_sha256"], previous) or not _same(
                    actual, _sha256(material)
                ):
                    raise DataUseProviderAuditAuthorityIntegrityError(
                        "provider audit authority event chain failed integrity"
                    )
                previous = actual
                previous_sequence = sequence

            verification = {
                "schema": INTEGRITY_SCHEMA,
                "tenant_sha256": self._tenant_sha256,
                "control_authorities": len(control_rows),
                "read_grants": len(read_rows),
                "history_records": len(history_rows),
                "operation_records": len(operation_rows),
                "audit_events": len(audit_rows),
                "terminal_audit_sha256": previous,
            }
            return ProviderAuditAuthorityIntegrityVerification(
                schema=INTEGRITY_SCHEMA,
                control_authorities=len(control_rows),
                read_grants=len(read_rows),
                history_records=len(history_rows),
                operation_records=len(operation_rows),
                audit_events=len(audit_rows),
                terminal_audit_sha256=previous,
                verification_sha256=_sha256(verification),
            )

    def purge_expired(
        self,
        *,
        cutoff: float,
        limit: int = 100,
    ) -> ProviderAuditAuthorityPurgeResult:
        """Delete only records past bounded retention, leaving chained tombstones."""

        self._check_gate()
        selected_cutoff = _timestamp(cutoff, "cutoff")
        now = _now(self._clock)
        if selected_cutoff > now:
            raise DataUseProviderAuditAuthorityValidationError(
                "retention cutoff cannot be in the future"
            )
        bounded = _integer(limit, "limit", 1, _MAX_PURGE)
        control_count = 0
        read_count = 0
        self._retention.authorized = True
        try:
            with self._connect() as connection:
                self._begin(connection)
                control_rows = connection.execute(
                    "SELECT authority_id FROM provider_audit_control_authorities "
                    "WHERE tenant_sha256=? AND retained_until<=? "
                    "ORDER BY retained_until,authority_id LIMIT ?",
                    (self._tenant_sha256, selected_cutoff, bounded),
                ).fetchall()
                remaining = bounded - len(control_rows)
                read_rows = (
                    []
                    if remaining == 0
                    else connection.execute(
                        "SELECT grant_id FROM provider_audit_read_grants "
                        "WHERE tenant_sha256=? AND retained_until<=? "
                        "ORDER BY retained_until,grant_id LIMIT ?",
                        (self._tenant_sha256, selected_cutoff, remaining),
                    ).fetchall()
                )
                for row in control_rows:
                    value = self._get_control(connection, str(row["authority_id"]))
                    self._audit(
                        connection,
                        action="control_purged",
                        object_ref=value.authority_id,
                        detail_sha256=value.integrity_sha256,
                        now=now,
                    )
                    connection.execute(
                        "DELETE FROM provider_audit_authority_operations "
                        "WHERE tenant_sha256=? AND object_type='control' AND object_id=?",
                        (self._tenant_sha256, value.authority_id),
                    )
                    connection.execute(
                        "DELETE FROM provider_audit_authority_history "
                        "WHERE tenant_sha256=? AND object_type='control' AND object_id=?",
                        (self._tenant_sha256, value.authority_id),
                    )
                    connection.execute(
                        "DELETE FROM provider_audit_control_authorities "
                        "WHERE tenant_sha256=? AND authority_id=?",
                        (self._tenant_sha256, value.authority_id),
                    )
                    control_count += 1
                for row in read_rows:
                    value = self._get_read_grant(connection, str(row["grant_id"]))
                    self._audit(
                        connection,
                        action="read_grant_purged",
                        object_ref=value.grant_id,
                        detail_sha256=value.integrity_sha256,
                        now=now,
                    )
                    connection.execute(
                        "DELETE FROM provider_audit_authority_operations "
                        "WHERE tenant_sha256=? AND object_type='read' AND object_id=?",
                        (self._tenant_sha256, value.grant_id),
                    )
                    connection.execute(
                        "DELETE FROM provider_audit_authority_history "
                        "WHERE tenant_sha256=? AND object_type='read' AND object_id=?",
                        (self._tenant_sha256, value.grant_id),
                    )
                    connection.execute(
                        "DELETE FROM provider_audit_read_grants "
                        "WHERE tenant_sha256=? AND grant_id=?",
                        (self._tenant_sha256, value.grant_id),
                    )
                    read_count += 1
                connection.commit()
        finally:
            self._retention.authorized = False
        return ProviderAuditAuthorityPurgeResult(
            control_authorities=control_count,
            read_grants=read_count,
        )

    @staticmethod
    def product_boundaries() -> dict[str, bool]:
        return {
            "network_io": NETWORK_IO,
            "provider_writes": PROVIDER_WRITES,
            "raw_control_material_persisted": RAW_CONTROL_MATERIAL_PERSISTED,
            "raw_provider_material_persisted": RAW_PROVIDER_MATERIAL_PERSISTED,
            "live_provider_acceptance_verified": False,
            "provider_audit_source_completeness_verified": False,
        }


__all__ = [
    "AUDIT_EVENT_SCHEMA",
    "AUTHORITY_RECORD_SCHEMA",
    "DataUseProviderAuditAuthorityConfigError",
    "DataUseProviderAuditAuthorityConflict",
    "DataUseProviderAuditAuthorityError",
    "DataUseProviderAuditAuthorityIntegrityError",
    "DataUseProviderAuditAuthorityNotFound",
    "DataUseProviderAuditAuthorityStore",
    "DataUseProviderAuditAuthorityValidationError",
    "INTEGRITY_SCHEMA",
    "NETWORK_IO",
    "PROJECTION_SCHEMA",
    "PROVIDER_WRITES",
    "ProviderAuditAuthorityIntegrityVerification",
    "ProviderAuditAuthorityProjection",
    "ProviderAuditAuthorityPurgeResult",
    "ProviderAuditAuthorityRecord",
    "ProviderAuditReadGrant",
    "RAW_CONTROL_MATERIAL_PERSISTED",
    "RAW_PROVIDER_MATERIAL_PERSISTED",
    "READ_GRANT_SCHEMA",
]
