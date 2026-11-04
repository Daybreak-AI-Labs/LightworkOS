"""Durable deployment authority for the California DROP control plane.

The external California DROP service remains authoritative.  This registry
stores only independently approved, digest-bound imports needed by the local
control plane.  It does not call California, validate a broker registration,
match a natural person, decide an exemption, or claim legal acceptance.

Broker enrollments, DROP-record imports, revocations and terminal outcome
approvals are append-only versions.  Every write requires two distinct,
deployment-resolved principal bindings and an idempotency key.  Subject data,
provider credentials, attachments and raw evidence are never accepted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from maverick.file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from maverick.paths import canonical_tenant_id
from maverick.privacy_drop_management import (
    TERMINAL_STATUSES,
    DROPDSARReceipt,
    DROPManagementConfigError,
    DROPManagementConflict,
    DROPManagementError,
    DROPManagementIntegrityError,
    DROPManagementNotFound,
    DROPManagementValidationError,
    DROPPrincipalBinding,
    DROPRecordAuthority,
    DROPStatusEvidence,
)
from maverick.sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
NETWORK_IO = False
LIVE_DROP_AUTHORITY_VERIFIED = False
LEGAL_ACCEPTANCE_VERIFIED = False

_DIGEST_RE = __import__("re").compile(r"[0-9a-f]{64}\Z")
_REF_RE = __import__("re").compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_MAX_JSON_BYTES = 256 * 1024
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600
_KINDS = frozenset({"broker", "record", "outcome"})
_STATES = frozenset({"active", "revoked"})
_REQUIRED_TRIGGERS = frozenset(
    {
        "drop_registry_versions_no_update",
        "drop_registry_operations_no_update",
        "drop_registry_audit_no_update",
        "drop_registry_versions_no_delete",
        "drop_registry_operations_no_delete",
        "drop_registry_audit_no_delete",
    }
)


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise DROPManagementValidationError("DROP registry metadata must be finite JSON") from exc
    if not 1 <= len(encoded) <= _MAX_JSON_BYTES:
        raise DROPManagementValidationError("DROP registry metadata exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise DROPManagementValidationError("tenant authority is invalid") from exc


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise DROPManagementValidationError(f"{label} is not a closed reference")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise DROPManagementValidationError(f"{label} is not a SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DROPManagementValidationError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DROPManagementValidationError(f"{label} is not a finite timestamp")
    result = float(value)
    if not math.isfinite(result) or not 0 < result < 100_000_000_000.0:
        raise DROPManagementValidationError(f"{label} is not a finite timestamp")
    return result


@dataclass(frozen=True, slots=True)
class DROPBrokerEnrollment:
    tenant_id: str
    broker_ref: str
    registration_sha256: str
    version: int
    state: str
    valid_until: float
    retained_until: float
    approved_by_binding_sha256: str
    reviewed_by_binding_sha256: str
    approved_by_key_revision: int
    reviewed_by_key_revision: int
    evidence_sha256: str
    created_at: float
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class DROPRegistryReconciliation:
    tenant_id: str
    integrity_valid: bool
    active_brokers: int
    active_records: int
    approved_outcomes: int
    expired_active_brokers: int
    expired_active_records: int
    checked_at: float


class DROPAuthorityRegistry:
    """Tenant-bound append-only broker, record and outcome authority."""

    def __init__(  # noqa: PLR0913 - explicit trust seams are intentional
        self,
        path: str | Path,
        *,
        tenant_id: str,
        principal_binding_resolver: Callable[[str, str], str | DROPPrincipalBinding],
        principal_binding_verifier: Callable[[str, str, int, str], bool] | None = None,
        retention_seconds: int = 365 * 24 * 3_600,
        maintenance_authorizer: Callable[[], bool] = lambda: False,
        config_gate: Callable[[], None] = lambda: None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not all(
            callable(value)
            for value in (
                principal_binding_resolver,
                maintenance_authorizer,
                config_gate,
                clock,
            )
        ):
            raise DROPManagementConfigError("DROP registry dependencies are incomplete")
        try:
            config_gate()
        except Exception as exc:
            raise DROPManagementConfigError("DROP registry configuration is unavailable") from exc
        self.path = Path(path)
        self.tenant_id = _tenant(tenant_id)
        self._principal_binding_resolver = principal_binding_resolver
        if principal_binding_verifier is not None and not callable(principal_binding_verifier):
            raise DROPManagementConfigError("DROP principal verifier is unavailable")
        self._principal_binding_verifier = principal_binding_verifier
        self._retention_seconds = _integer(
            retention_seconds,
            "retention_seconds",
            3_600,
            _MAX_RETENTION_SECONDS,
        )
        self._maintenance_authorizer = maintenance_authorizer
        self._gate = config_gate
        self._clock = clock
        self._maintenance = threading.local()
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.create_function(
            "drop_registry_maintenance_authorized",
            0,
            lambda: 1 if bool(getattr(self._maintenance, "authorized", False)) else 0,
        )
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS drop_registry_meta(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS drop_registry_versions(
                    tenant_id TEXT NOT NULL,kind TEXT NOT NULL,object_key TEXT NOT NULL,
                    version INTEGER NOT NULL,state TEXT NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,kind,object_key,version)
                );
                CREATE TABLE IF NOT EXISTS drop_registry_operations(
                    tenant_id TEXT NOT NULL,action TEXT NOT NULL,key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,kind TEXT NOT NULL,object_key TEXT NOT NULL,
                    version INTEGER NOT NULL,result_json TEXT NOT NULL,created_at REAL NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,action,key_sha256)
                );
                CREATE TABLE IF NOT EXISTS drop_registry_audit(
                    tenant_id TEXT NOT NULL,kind TEXT NOT NULL,object_key TEXT NOT NULL,
                    sequence INTEGER NOT NULL,event_type TEXT NOT NULL,
                    event_payload_sha256 TEXT NOT NULL,previous_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL,created_at REAL NOT NULL,
                    PRIMARY KEY(tenant_id,kind,object_key,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS drop_registry_versions_no_update
                    BEFORE UPDATE ON drop_registry_versions
                    BEGIN SELECT RAISE(ABORT,'immutable DROP registry version'); END;
                CREATE TRIGGER IF NOT EXISTS drop_registry_operations_no_update
                    BEFORE UPDATE ON drop_registry_operations
                    BEGIN SELECT RAISE(ABORT,'immutable DROP registry operation'); END;
                CREATE TRIGGER IF NOT EXISTS drop_registry_audit_no_update
                    BEFORE UPDATE ON drop_registry_audit
                    BEGIN SELECT RAISE(ABORT,'immutable DROP registry audit'); END;
                CREATE TRIGGER IF NOT EXISTS drop_registry_versions_no_delete
                    BEFORE DELETE ON drop_registry_versions
                    WHEN drop_registry_maintenance_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'DROP registry maintenance authority required'); END;
                CREATE TRIGGER IF NOT EXISTS drop_registry_operations_no_delete
                    BEFORE DELETE ON drop_registry_operations
                    WHEN drop_registry_maintenance_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'DROP registry maintenance authority required'); END;
                CREATE TRIGGER IF NOT EXISTS drop_registry_audit_no_delete
                    BEFORE DELETE ON drop_registry_audit
                    WHEN drop_registry_maintenance_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'DROP registry maintenance authority required'); END;
                """
            )
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, SCHEMA_VERSION):
                raise DROPManagementConfigError(
                    f"unsupported DROP registry schema version {version}"
                )
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            tenant_sha256 = _text_sha256(self.tenant_id)
            connection.execute(
                "INSERT OR IGNORE INTO drop_registry_meta(key,value) "
                "VALUES('tenant_sha256',?)",
                (tenant_sha256,),
            )
            binding = connection.execute(
                "SELECT value FROM drop_registry_meta WHERE key='tenant_sha256'"
            ).fetchone()
            if binding is None or not _same(binding[0], tenant_sha256):
                raise DROPManagementIntegrityError("DROP registry belongs to another tenant")
            foreign = connection.execute(
                "SELECT EXISTS(SELECT 1 FROM drop_registry_versions WHERE tenant_id<>?) "
                "OR EXISTS(SELECT 1 FROM drop_registry_operations WHERE tenant_id<>?) "
                "OR EXISTS(SELECT 1 FROM drop_registry_audit WHERE tenant_id<>?)",
                (self.tenant_id, self.tenant_id, self.tenant_id),
            ).fetchone()
            if foreign is None or int(foreign[0]) != 0:
                raise DROPManagementIntegrityError("DROP registry contains another tenant")
        ensure_private_file(self.path)

    def _now(self) -> float:
        return _timestamp(self._clock(), "current time")

    @staticmethod
    def _binding(value: object) -> DROPPrincipalBinding:
        if isinstance(value, str):
            return DROPPrincipalBinding(
                binding_sha256=_digest(value, "principal_binding_sha256"),
                key_revision=1,
            )
        if type(value) is DROPPrincipalBinding:
            return value.normalized()
        raise DROPManagementValidationError("principal binding authority is invalid")

    def principal_binding_authority(
        self,
        tenant_id: str,
        principal_ref: str,
    ) -> DROPPrincipalBinding:
        tenant = _tenant(tenant_id)
        principal = _ref(principal_ref, "principal_ref")
        if tenant != self.tenant_id:
            raise DROPManagementNotFound("DROP authority was not found")
        try:
            first = self._principal_binding_resolver(tenant, principal)
            second = self._principal_binding_resolver(tenant, principal)
        except Exception as exc:
            raise DROPManagementConfigError("DROP principal authority is unavailable") from exc
        try:
            first_binding = self._binding(first)
            second_binding = self._binding(second)
        except DROPManagementValidationError as exc:
            raise DROPManagementConfigError("DROP principal authority is unavailable") from exc
        if (
            first_binding.key_revision != second_binding.key_revision
            or not _same(first_binding.binding_sha256, second_binding.binding_sha256)
        ):
            raise DROPManagementConflict("DROP principal authority changed")
        return second_binding

    def principal_binding(self, tenant_id: str, principal_ref: str) -> str:
        return self.principal_binding_authority(tenant_id, principal_ref).binding_sha256

    def _verify_binding(
        self,
        principal_ref: str,
        binding_sha256: object,
        key_revision: object,
    ) -> bool:
        try:
            digest = _digest(binding_sha256, "principal_binding_sha256")
            revision = _integer(key_revision, "principal_key_revision", 1, 2**31 - 1)
            if callable(self._principal_binding_verifier):
                return self._principal_binding_verifier(
                    self.tenant_id,
                    _ref(principal_ref, "principal_ref"),
                    revision,
                    digest,
                ) is True
            current = self.principal_binding_authority(self.tenant_id, principal_ref)
            return current.key_revision == revision and _same(current.binding_sha256, digest)
        except DROPManagementError:
            return False

    def _independent_bindings(
        self,
        actor_ref: str,
        reviewer_ref: str,
    ) -> tuple[DROPPrincipalBinding, DROPPrincipalBinding]:
        actor = self.principal_binding_authority(self.tenant_id, actor_ref)
        reviewer = self.principal_binding_authority(self.tenant_id, reviewer_ref)
        if _same(actor.binding_sha256, reviewer.binding_sha256):
            raise DROPManagementConflict("independent DROP approval is required")
        return actor, reviewer

    @staticmethod
    def _row_payload(row: sqlite3.Row) -> dict[str, Any]:
        try:
            raw = str(row["payload_json"])
            if not 1 <= len(raw.encode("utf-8")) <= _MAX_JSON_BYTES:
                raise ValueError("stored payload exceeds its byte bound")
            payload = json.loads(raw)
        except (TypeError, UnicodeError, ValueError) as exc:
            raise DROPManagementIntegrityError("stored DROP registry payload is invalid") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("tenant_id") != row["tenant_id"]
            or payload.get("kind") != row["kind"]
            or payload.get("object_key") != row["object_key"]
            or payload.get("version") != row["version"]
            or payload.get("state") != row["state"]
            or payload.get("retained_until") != row["retained_until"]
            or not _same(_sha256(payload), row["integrity_sha256"])
        ):
            raise DROPManagementIntegrityError("stored DROP registry payload changed")
        return payload

    def _current(
        self,
        connection: sqlite3.Connection,
        kind: str,
        object_key: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT * FROM drop_registry_versions WHERE tenant_id=? AND kind=? "
            "AND object_key=? ORDER BY version DESC LIMIT 1",
            (self.tenant_id, kind, object_key),
        ).fetchone()
        return None if row is None else self._row_payload(row)

    @staticmethod
    def _operation_body(row: sqlite3.Row) -> dict[str, object]:
        return {
            "tenant_id": str(row["tenant_id"]),
            "action": str(row["action"]),
            "key_sha256": str(row["key_sha256"]),
            "request_sha256": str(row["request_sha256"]),
            "kind": str(row["kind"]),
            "object_key": str(row["object_key"]),
            "version": int(row["version"]),
            "result_json": str(row["result_json"]),
            "created_at": float(row["created_at"]),
        }

    def _replay(
        self,
        connection: sqlite3.Connection,
        action: str,
        idempotency_key: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        key_sha256 = _text_sha256(_ref(idempotency_key, "idempotency_key"))
        row = connection.execute(
            "SELECT * FROM drop_registry_operations WHERE tenant_id=? AND action=? "
            "AND key_sha256=?",
            (self.tenant_id, action, key_sha256),
        ).fetchone()
        if row is None:
            return None
        body = self._operation_body(row)
        if not _same(_sha256(body), row["integrity_sha256"]):
            raise DROPManagementIntegrityError("stored DROP registry operation changed")
        if not _same(body["request_sha256"], request_sha256):
            raise DROPManagementConflict("idempotency key is bound to another DROP operation")
        try:
            result = json.loads(str(body["result_json"]))
        except (TypeError, ValueError) as exc:
            raise DROPManagementIntegrityError("stored DROP registry result is invalid") from exc
        if not isinstance(result, dict):
            raise DROPManagementIntegrityError("stored DROP registry result is invalid")
        return result

    @staticmethod
    def _append_audit(
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        kind: str,
        object_key: str,
        event_type: str,
        event_payload_sha256: str,
        created_at: float,
    ) -> None:
        row = connection.execute(
            "SELECT sequence,event_sha256 FROM drop_registry_audit WHERE tenant_id=? "
            "AND kind=? AND object_key=? ORDER BY sequence DESC LIMIT 1",
            (tenant_id, kind, object_key),
        ).fetchone()
        sequence = 1 if row is None else int(row["sequence"]) + 1
        previous = "0" * 64 if row is None else str(row["event_sha256"])
        body = {
            "tenant_id": tenant_id,
            "kind": kind,
            "object_key": object_key,
            "sequence": sequence,
            "event_type": event_type,
            "event_payload_sha256": event_payload_sha256,
            "previous_sha256": previous,
            "created_at": created_at,
        }
        connection.execute(
            "INSERT INTO drop_registry_audit VALUES(?,?,?,?,?,?,?,?,?)",
            (
                tenant_id,
                kind,
                object_key,
                sequence,
                event_type,
                event_payload_sha256,
                previous,
                _sha256(body),
                created_at,
            ),
        )

    def _append(  # noqa: PLR0913 - atomic append contract is explicit
        self,
        *,
        action: str,
        idempotency_key: str,
        request: Mapping[str, object],
        payload: Mapping[str, object],
        event_type: str,
    ) -> dict[str, Any]:
        request_sha256 = _sha256(dict(request))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._replay(
                connection,
                action,
                idempotency_key,
                request_sha256,
            )
            if replay is not None:
                connection.rollback()
                return replay
            kind = str(payload["kind"])
            object_key = str(payload["object_key"])
            version = int(payload["version"])
            created_at = float(payload["created_at"])
            result_json = _canonical(dict(payload)).decode("ascii")
            connection.execute(
                "INSERT INTO drop_registry_versions VALUES(?,?,?,?,?,?,?,?)",
                (
                    self.tenant_id,
                    kind,
                    object_key,
                    version,
                    payload["state"],
                    payload["retained_until"],
                    result_json,
                    _sha256(dict(payload)),
                ),
            )
            key_sha256 = _text_sha256(_ref(idempotency_key, "idempotency_key"))
            operation = {
                "tenant_id": self.tenant_id,
                "action": action,
                "key_sha256": key_sha256,
                "request_sha256": request_sha256,
                "kind": kind,
                "object_key": object_key,
                "version": version,
                "result_json": result_json,
                "created_at": created_at,
            }
            connection.execute(
                "INSERT INTO drop_registry_operations VALUES(?,?,?,?,?,?,?,?,?,?)",
                (*operation.values(), _sha256(operation)),
            )
            self._append_audit(
                connection,
                tenant_id=self.tenant_id,
                kind=kind,
                object_key=object_key,
                event_type=event_type,
                event_payload_sha256=_sha256(dict(payload)),
                created_at=created_at,
            )
            connection.commit()
        return dict(payload)

    def _validate_approval_payload(self, payload: Mapping[str, object]) -> None:
        try:
            actor_ref = _ref(payload["approved_by_ref"], "approved_by_ref")
            reviewer_ref = _ref(payload["reviewed_by_ref"], "reviewed_by_ref")
            actor_digest = _digest(
                payload["approved_by_binding_sha256"],
                "approved_by_binding_sha256",
            )
            reviewer_digest = _digest(
                payload["reviewed_by_binding_sha256"],
                "reviewed_by_binding_sha256",
            )
            actor_revision = _integer(
                payload["approved_by_key_revision"],
                "approved_by_key_revision",
                1,
                2**31 - 1,
            )
            reviewer_revision = _integer(
                payload["reviewed_by_key_revision"],
                "reviewed_by_key_revision",
                1,
                2**31 - 1,
            )
        except (KeyError, DROPManagementValidationError) as exc:
            raise DROPManagementIntegrityError("stored DROP approval binding is invalid") from exc
        if (
            _same(actor_digest, reviewer_digest)
            or not self._verify_binding(actor_ref, actor_digest, actor_revision)
            or not self._verify_binding(reviewer_ref, reviewer_digest, reviewer_revision)
        ):
            raise DROPManagementIntegrityError("stored DROP approval binding is invalid")

    def _broker(self, payload: Mapping[str, object]) -> DROPBrokerEnrollment:
        try:
            result = DROPBrokerEnrollment(
                tenant_id=_tenant(payload["tenant_id"]),
                broker_ref=_ref(payload["broker_ref"], "broker_ref"),
                registration_sha256=_digest(
                    payload["registration_sha256"],
                    "registration_sha256",
                ),
                version=_integer(payload["version"], "version", 1, 2**31 - 1),
                state=str(payload["state"]),
                valid_until=_timestamp(payload["valid_until"], "valid_until"),
                retained_until=_timestamp(payload["retained_until"], "retained_until"),
                approved_by_binding_sha256=_digest(
                    payload["approved_by_binding_sha256"],
                    "approved_by_binding_sha256",
                ),
                reviewed_by_binding_sha256=_digest(
                    payload["reviewed_by_binding_sha256"],
                    "reviewed_by_binding_sha256",
                ),
                approved_by_key_revision=_integer(
                    payload["approved_by_key_revision"],
                    "approved_by_key_revision",
                    1,
                    2**31 - 1,
                ),
                reviewed_by_key_revision=_integer(
                    payload["reviewed_by_key_revision"],
                    "reviewed_by_key_revision",
                    1,
                    2**31 - 1,
                ),
                evidence_sha256=_digest(payload["evidence_sha256"], "evidence_sha256"),
                created_at=_timestamp(payload["created_at"], "created_at"),
                integrity_sha256=_sha256(dict(payload)),
            )
        except KeyError as exc:
            raise DROPManagementIntegrityError("stored DROP broker enrollment is invalid") from exc
        self._validate_approval_payload(payload)
        return result

    def enroll_broker(  # noqa: PLR0913 - explicit authority input
        self,
        *,
        broker_ref: str,
        registration_sha256: str,
        evidence_sha256: str,
        valid_until: float,
        expected_version: int,
        actor_ref: str,
        reviewer_ref: str,
        idempotency_key: str,
    ) -> DROPBrokerEnrollment:
        """Enroll or rotate one independently reviewed broker registration digest."""

        self._gate()
        broker = _ref(broker_ref, "broker_ref")
        registration = _digest(registration_sha256, "registration_sha256")
        evidence = _digest(evidence_sha256, "evidence_sha256")
        expected = _integer(expected_version, "expected_version", 0, 2**31 - 2)
        now = self._now()
        valid = _timestamp(valid_until, "valid_until")
        if valid <= now:
            raise DROPManagementValidationError("broker authority is already expired")
        actor, reviewer = self._independent_bindings(actor_ref, reviewer_ref)
        object_key = f"broker:{broker}"
        request = {
            "action": "enroll_broker",
            "broker_ref": broker,
            "registration_sha256": registration,
            "evidence_sha256": evidence,
            "valid_until": valid,
            "expected_version": expected,
            "actor_binding_sha256": actor.binding_sha256,
            "reviewer_binding_sha256": reviewer.binding_sha256,
            "actor_key_revision": actor.key_revision,
            "reviewer_key_revision": reviewer.key_revision,
        }
        request_sha256 = _sha256(request)
        with self._connect() as connection:
            replay = self._replay(connection, "enroll_broker", idempotency_key, request_sha256)
            if replay is not None:
                return self._broker(replay)
            current = self._current(connection, "broker", object_key)
        current_version = 0 if current is None else int(current["version"])
        if current_version != expected:
            raise DROPManagementConflict("broker enrollment revision changed")
        retained_until = now + self._retention_seconds
        if valid >= retained_until:
            raise DROPManagementValidationError("broker validity exceeds configured retention")
        payload: dict[str, object] = {
            "schema": "lightwork.privacy-drop-broker-authority.v1",
            "tenant_id": self.tenant_id,
            "kind": "broker",
            "object_key": object_key,
            "broker_ref": broker,
            "registration_sha256": registration,
            "version": expected + 1,
            "state": "active",
            "valid_until": valid,
            "retained_until": retained_until,
            "approved_by_binding_sha256": actor.binding_sha256,
            "reviewed_by_binding_sha256": reviewer.binding_sha256,
            "approved_by_key_revision": actor.key_revision,
            "reviewed_by_key_revision": reviewer.key_revision,
            "approved_by_ref": _ref(actor_ref, "actor_ref"),
            "reviewed_by_ref": _ref(reviewer_ref, "reviewer_ref"),
            "evidence_sha256": evidence,
            "created_at": now,
        }
        try:
            result = self._append(
                action="enroll_broker",
                idempotency_key=idempotency_key,
                request=request,
                payload=payload,
                event_type="DROP_BROKER_ENROLLED",
            )
        except sqlite3.IntegrityError as exc:
            raise DROPManagementConflict("broker enrollment changed concurrently") from exc
        return self._broker(result)

    def _active_broker(self, broker_ref: str, now: float) -> DROPBrokerEnrollment:
        broker = _ref(broker_ref, "broker_ref")
        with self._connect() as connection:
            payload = self._current(connection, "broker", f"broker:{broker}")
        if payload is None:
            raise DROPManagementNotFound("DROP broker authority was not found")
        result = self._broker(payload)
        if (
            result.tenant_id != self.tenant_id
            or result.state != "active"
            or result.valid_until <= now
            or result.retained_until <= now
            or _same(result.approved_by_binding_sha256, result.reviewed_by_binding_sha256)
        ):
            raise DROPManagementNotFound("DROP broker authority was not found")
        return result

    def revoke_broker(
        self,
        broker_ref: str,
        *,
        expected_version: int,
        evidence_sha256: str,
        actor_ref: str,
        reviewer_ref: str,
        idempotency_key: str,
    ) -> DROPBrokerEnrollment:
        self._gate()
        broker = _ref(broker_ref, "broker_ref")
        expected = _integer(expected_version, "expected_version", 1, 2**31 - 2)
        evidence = _digest(evidence_sha256, "evidence_sha256")
        actor, reviewer = self._independent_bindings(actor_ref, reviewer_ref)
        object_key = f"broker:{broker}"
        now = self._now()
        request = {
            "action": "revoke_broker",
            "broker_ref": broker,
            "expected_version": expected,
            "evidence_sha256": evidence,
            "actor_binding_sha256": actor.binding_sha256,
            "reviewer_binding_sha256": reviewer.binding_sha256,
            "actor_key_revision": actor.key_revision,
            "reviewer_key_revision": reviewer.key_revision,
        }
        request_sha256 = _sha256(request)
        with self._connect() as connection:
            replay = self._replay(connection, "revoke_broker", idempotency_key, request_sha256)
            if replay is not None:
                return self._broker(replay)
            current = self._current(connection, "broker", object_key)
        if current is None or current.get("state") != "active" or current.get("version") != expected:
            raise DROPManagementConflict("broker enrollment revision changed")
        payload = dict(current)
        payload.update(
            {
                "version": expected + 1,
                "state": "revoked",
                "approved_by_binding_sha256": actor.binding_sha256,
                "reviewed_by_binding_sha256": reviewer.binding_sha256,
                "approved_by_key_revision": actor.key_revision,
                "reviewed_by_key_revision": reviewer.key_revision,
                "approved_by_ref": _ref(actor_ref, "actor_ref"),
                "reviewed_by_ref": _ref(reviewer_ref, "reviewer_ref"),
                "evidence_sha256": evidence,
                "created_at": now,
            }
        )
        try:
            result = self._append(
                action="revoke_broker",
                idempotency_key=idempotency_key,
                request=request,
                payload=payload,
                event_type="DROP_BROKER_REVOKED",
            )
        except sqlite3.IntegrityError as exc:
            raise DROPManagementConflict("broker revocation changed concurrently") from exc
        return self._broker(result)

    def _record(self, payload: Mapping[str, object]) -> DROPRecordAuthority:
        raw = payload.get("authority")
        if not isinstance(raw, Mapping):
            raise DROPManagementIntegrityError("stored DROP record authority is invalid")
        try:
            authority = DROPRecordAuthority(**dict(raw)).normalized()
        except (TypeError, DROPManagementValidationError) as exc:
            raise DROPManagementIntegrityError("stored DROP record authority is invalid") from exc
        if not _same(payload.get("authority_sha256"), authority.authority_sha256):
            raise DROPManagementIntegrityError("stored DROP record authority changed")
        self._validate_approval_payload(payload)
        return authority

    def import_record(  # noqa: PLR0913 - exact external import authority
        self,
        authority: DROPRecordAuthority,
        *,
        broker_ref: str,
        import_evidence_sha256: str,
        expected_version: int,
        actor_ref: str,
        reviewer_ref: str,
        idempotency_key: str,
    ) -> DROPRecordAuthority:
        """Import one digest-only external record after independent review."""

        self._gate()
        if type(authority) is not DROPRecordAuthority:
            raise DROPManagementValidationError("DROP record authority is unavailable")
        authority = authority.normalized()
        if authority.tenant_id != self.tenant_id:
            raise DROPManagementNotFound("DROP record authority was not found")
        broker = self._active_broker(broker_ref, self._now())
        if not _same(broker.registration_sha256, authority.broker_registration_sha256):
            raise DROPManagementConflict("DROP broker registration binding changed")
        import_evidence = _digest(import_evidence_sha256, "import_evidence_sha256")
        expected = _integer(expected_version, "expected_version", 0, 2**31 - 2)
        actor, reviewer = self._independent_bindings(actor_ref, reviewer_ref)
        now = self._now()
        if authority.valid_until <= now:
            raise DROPManagementValidationError("DROP record authority is already expired")
        object_key = f"record:{authority.drop_id}"
        request = {
            "action": "import_record",
            "authority_sha256": authority.authority_sha256,
            "broker_ref": broker.broker_ref,
            "broker_version": broker.version,
            "import_evidence_sha256": import_evidence,
            "expected_version": expected,
            "actor_binding_sha256": actor.binding_sha256,
            "reviewer_binding_sha256": reviewer.binding_sha256,
            "actor_key_revision": actor.key_revision,
            "reviewer_key_revision": reviewer.key_revision,
        }
        request_sha256 = _sha256(request)
        with self._connect() as connection:
            replay = self._replay(connection, "import_record", idempotency_key, request_sha256)
            if replay is not None:
                return self._record(replay)
            current = self._current(connection, "record", object_key)
        current_version = 0 if current is None else int(current["version"])
        if current_version != expected:
            raise DROPManagementConflict("DROP record import revision changed")
        if current is not None:
            current_authority = self._record(current)
            if authority.record_revision <= current_authority.record_revision:
                raise DROPManagementConflict("DROP external record revision did not advance")
        retained_until = now + self._retention_seconds
        if authority.valid_until >= retained_until:
            raise DROPManagementValidationError("DROP record validity exceeds configured retention")
        payload: dict[str, object] = {
            "schema": "lightwork.privacy-drop-record-import.v1",
            "tenant_id": self.tenant_id,
            "kind": "record",
            "object_key": object_key,
            "drop_id": authority.drop_id,
            "version": expected + 1,
            "state": "active",
            "broker_ref": broker.broker_ref,
            "broker_version": broker.version,
            "authority": asdict(authority),
            "authority_sha256": authority.authority_sha256,
            "import_evidence_sha256": import_evidence,
            "approved_by_binding_sha256": actor.binding_sha256,
            "reviewed_by_binding_sha256": reviewer.binding_sha256,
            "approved_by_key_revision": actor.key_revision,
            "reviewed_by_key_revision": reviewer.key_revision,
            "approved_by_ref": _ref(actor_ref, "actor_ref"),
            "reviewed_by_ref": _ref(reviewer_ref, "reviewer_ref"),
            "created_at": now,
            "retained_until": retained_until,
        }
        try:
            result = self._append(
                action="import_record",
                idempotency_key=idempotency_key,
                request=request,
                payload=payload,
                event_type="DROP_RECORD_IMPORTED",
            )
        except sqlite3.IntegrityError as exc:
            raise DROPManagementConflict("DROP record import changed concurrently") from exc
        return self._record(result)

    def resolve_record(
        self,
        *,
        drop_id: int,
        request_type: str | None = None,
        template_id: str | None = None,
        language: str | None = None,
    ) -> DROPRecordAuthority:
        self._gate()
        drop = _integer(drop_id, "drop_id", 1, 2**31 - 1)
        with self._connect() as connection:
            payload = self._current(connection, "record", f"record:{drop}")
        if payload is None or payload.get("state") != "active":
            raise DROPManagementNotFound("DROP record authority was not found")
        authority = self._record(payload)
        now = self._now()
        if authority.valid_until <= now or float(payload["retained_until"]) <= now:
            raise DROPManagementNotFound("DROP record authority was not found")
        broker = self._active_broker(str(payload["broker_ref"]), now)
        if (
            broker.version != payload.get("broker_version")
            or not _same(broker.registration_sha256, authority.broker_registration_sha256)
            or (request_type is not None and authority.request_type != request_type)
            or (template_id is not None and authority.template_id != template_id)
            or (language is not None and authority.language != str(language).lower())
        ):
            raise DROPManagementConflict("DROP record authority changed")
        return authority

    def revoke_record(  # noqa: PLR0913 - independent revocation authority
        self,
        drop_id: int,
        *,
        expected_version: int,
        evidence_sha256: str,
        actor_ref: str,
        reviewer_ref: str,
        idempotency_key: str,
    ) -> DROPRecordAuthority:
        self._gate()
        drop = _integer(drop_id, "drop_id", 1, 2**31 - 1)
        expected = _integer(expected_version, "expected_version", 1, 2**31 - 2)
        evidence = _digest(evidence_sha256, "evidence_sha256")
        actor, reviewer = self._independent_bindings(actor_ref, reviewer_ref)
        object_key = f"record:{drop}"
        now = self._now()
        request = {
            "action": "revoke_record",
            "drop_id": drop,
            "expected_version": expected,
            "evidence_sha256": evidence,
            "actor_binding_sha256": actor.binding_sha256,
            "reviewer_binding_sha256": reviewer.binding_sha256,
            "actor_key_revision": actor.key_revision,
            "reviewer_key_revision": reviewer.key_revision,
        }
        request_sha256 = _sha256(request)
        with self._connect() as connection:
            replay = self._replay(connection, "revoke_record", idempotency_key, request_sha256)
            if replay is not None:
                return self._record(replay)
            current = self._current(connection, "record", object_key)
        if current is None or current.get("state") != "active" or current.get("version") != expected:
            raise DROPManagementConflict("DROP record import revision changed")
        payload = dict(current)
        payload.update(
            {
                "version": expected + 1,
                "state": "revoked",
                "revocation_evidence_sha256": evidence,
                "approved_by_binding_sha256": actor.binding_sha256,
                "reviewed_by_binding_sha256": reviewer.binding_sha256,
                "approved_by_key_revision": actor.key_revision,
                "reviewed_by_key_revision": reviewer.key_revision,
                "approved_by_ref": _ref(actor_ref, "actor_ref"),
                "reviewed_by_ref": _ref(reviewer_ref, "reviewer_ref"),
                "created_at": now,
            }
        )
        try:
            result = self._append(
                action="revoke_record",
                idempotency_key=idempotency_key,
                request=request,
                payload=payload,
                event_type="DROP_RECORD_REVOKED",
            )
        except sqlite3.IntegrityError as exc:
            raise DROPManagementConflict("DROP record revocation changed concurrently") from exc
        return self._record(result)

    def _outcome(self, payload: Mapping[str, object]) -> DROPStatusEvidence:
        raw = payload.get("evidence")
        if not isinstance(raw, Mapping):
            raise DROPManagementIntegrityError("stored DROP outcome authority is invalid")
        try:
            evidence = DROPStatusEvidence(**dict(raw)).normalized()
        except (TypeError, DROPManagementValidationError) as exc:
            raise DROPManagementIntegrityError("stored DROP outcome authority is invalid") from exc
        if not _same(payload.get("evidence_binding_sha256"), evidence.evidence_binding_sha256):
            raise DROPManagementIntegrityError("stored DROP outcome authority changed")
        self._validate_approval_payload(payload)
        return evidence

    def approve_outcome(  # noqa: PLR0913 - explicit evidence contract
        self,
        authority: DROPRecordAuthority,
        receipt: DROPDSARReceipt,
        *,
        status: str,
        reviewer_ref: str,
        evidence_sha256: str,
        evidence_revision: int,
        observed_at: float,
        valid_until: float,
        deletion_verified: bool = False,
        opt_out_verified: bool = False,
        search_complete: bool = False,
        exemption_approved: bool = False,
        provider_operations_complete: bool = False,
        expected_version: int,
        actor_ref: str,
        idempotency_key: str,
    ) -> DROPStatusEvidence:
        """Store one independently reviewed terminal outcome evidence snapshot."""

        self._gate()
        authority = self.resolve_record(drop_id=authority.drop_id)
        if type(receipt) is not DROPDSARReceipt:
            raise DROPManagementValidationError("DROP DSAR receipt is unavailable")
        receipt = receipt.normalized()
        if (
            receipt.tenant_id != self.tenant_id
            or receipt.drop_id != authority.drop_id
            or not _same(receipt.authority_sha256, authority.authority_sha256)
        ):
            raise DROPManagementConflict("DROP DSAR receipt binding changed")
        if status not in TERMINAL_STATUSES:
            raise DROPManagementValidationError("DROP outcome status is not terminal")
        expected = _integer(expected_version, "expected_version", 0, 2**31 - 2)
        actor, reviewer = self._independent_bindings(actor_ref, reviewer_ref)
        now = self._now()
        evidence = DROPStatusEvidence(
            tenant_id=self.tenant_id,
            drop_id=authority.drop_id,
            authority_sha256=authority.authority_sha256,
            request_queue_id=receipt.request_queue_id,
            internal_case_id=receipt.internal_case_id,
            status=status,
            reviewer_ref=_ref(reviewer_ref, "reviewer_ref"),
            evidence_sha256=_digest(evidence_sha256, "evidence_sha256"),
            evidence_revision=_integer(
                evidence_revision,
                "evidence_revision",
                1,
                2**31 - 1,
            ),
            observed_at=_timestamp(observed_at, "observed_at"),
            valid_until=_timestamp(valid_until, "valid_until"),
            deletion_verified=deletion_verified,
            opt_out_verified=opt_out_verified,
            search_complete=search_complete,
            exemption_approved=exemption_approved,
            provider_operations_complete=provider_operations_complete,
        ).normalized()
        if not receipt.created_at <= evidence.observed_at <= now < evidence.valid_until:
            raise DROPManagementValidationError("DROP outcome evidence time is invalid")
        object_key = f"outcome:{authority.drop_id}:{status}"
        request = {
            "action": "approve_outcome",
            "authority_sha256": authority.authority_sha256,
            "receipt_sha256": receipt.receipt_sha256,
            "evidence_binding_sha256": evidence.evidence_binding_sha256,
            "expected_version": expected,
            "actor_binding_sha256": actor.binding_sha256,
            "reviewer_binding_sha256": reviewer.binding_sha256,
            "actor_key_revision": actor.key_revision,
            "reviewer_key_revision": reviewer.key_revision,
        }
        request_sha256 = _sha256(request)
        with self._connect() as connection:
            replay = self._replay(connection, "approve_outcome", idempotency_key, request_sha256)
            if replay is not None:
                return self._outcome(replay)
            current = self._current(connection, "outcome", object_key)
        current_version = 0 if current is None else int(current["version"])
        if current_version != expected:
            raise DROPManagementConflict("DROP outcome approval revision changed")
        retained_until = now + self._retention_seconds
        if evidence.valid_until >= retained_until:
            raise DROPManagementValidationError("DROP outcome validity exceeds retention")
        payload: dict[str, object] = {
            "schema": "lightwork.privacy-drop-outcome-authority.v1",
            "tenant_id": self.tenant_id,
            "kind": "outcome",
            "object_key": object_key,
            "drop_id": authority.drop_id,
            "status": status,
            "version": expected + 1,
            "state": "active",
            "authority_sha256": authority.authority_sha256,
            "receipt_sha256": receipt.receipt_sha256,
            "evidence": asdict(evidence),
            "evidence_binding_sha256": evidence.evidence_binding_sha256,
            "approved_by_binding_sha256": actor.binding_sha256,
            "reviewed_by_binding_sha256": reviewer.binding_sha256,
            "approved_by_key_revision": actor.key_revision,
            "reviewed_by_key_revision": reviewer.key_revision,
            "approved_by_ref": _ref(actor_ref, "actor_ref"),
            "reviewed_by_ref": _ref(reviewer_ref, "reviewer_ref"),
            "created_at": now,
            "retained_until": retained_until,
        }
        try:
            result = self._append(
                action="approve_outcome",
                idempotency_key=idempotency_key,
                request=request,
                payload=payload,
                event_type="DROP_OUTCOME_APPROVED",
            )
        except sqlite3.IntegrityError as exc:
            raise DROPManagementConflict("DROP outcome approval changed concurrently") from exc
        return self._outcome(result)

    def resolve_outcome(
        self,
        authority: DROPRecordAuthority,
        receipt: DROPDSARReceipt,
        status: str,
    ) -> DROPStatusEvidence:
        current_authority = self.resolve_record(drop_id=authority.drop_id)
        if not _same(current_authority.authority_sha256, authority.authority_sha256):
            raise DROPManagementConflict("DROP record authority changed")
        receipt = receipt.normalized()
        with self._connect() as connection:
            payload = self._current(
                connection,
                "outcome",
                f"outcome:{authority.drop_id}:{status}",
            )
        if payload is None or payload.get("state") != "active":
            raise DROPManagementNotFound("DROP outcome evidence was not found")
        evidence = self._outcome(payload)
        now = self._now()
        if (
            evidence.valid_until <= now
            or float(payload["retained_until"]) <= now
            or not _same(payload.get("authority_sha256"), authority.authority_sha256)
            or not _same(payload.get("receipt_sha256"), receipt.receipt_sha256)
            or _same(
                payload.get("approved_by_binding_sha256"),
                payload.get("reviewed_by_binding_sha256"),
            )
            or not self._verify_binding(
                evidence.reviewer_ref,
                payload.get("reviewed_by_binding_sha256"),
                payload.get("reviewed_by_key_revision"),
            )
        ):
            raise DROPManagementConflict("DROP outcome evidence changed")
        return evidence

    def verify_integrity(self) -> bool:  # noqa: C901 - closed registry audit
        try:
            self._gate()
            with self._connect() as connection:
                meta = connection.execute(
                    "SELECT key,value FROM drop_registry_meta ORDER BY key"
                ).fetchall()
                triggers = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                versions = connection.execute(
                    "SELECT * FROM drop_registry_versions WHERE tenant_id=? "
                    "ORDER BY kind,object_key,version",
                    (self.tenant_id,),
                ).fetchall()
                operations = connection.execute(
                    "SELECT * FROM drop_registry_operations WHERE tenant_id=? "
                    "ORDER BY action,key_sha256",
                    (self.tenant_id,),
                ).fetchall()
                audits = connection.execute(
                    "SELECT * FROM drop_registry_audit WHERE tenant_id=? "
                    "ORDER BY kind,object_key,sequence",
                    (self.tenant_id,),
                ).fetchall()
            if (
                len(meta) != 1
                or meta[0]["key"] != "tenant_sha256"
                or not _same(meta[0]["value"], _text_sha256(self.tenant_id))
                or not _REQUIRED_TRIGGERS.issubset(triggers)
            ):
                return False
            seen_versions: dict[tuple[str, str], int] = {}
            payload_digests: set[tuple[str, str, int, str]] = set()
            for row in versions:
                payload = self._row_payload(row)
                kind = str(payload["kind"])
                state = str(payload["state"])
                if kind not in _KINDS or state not in _STATES:
                    return False
                key = (kind, str(payload["object_key"]))
                if int(payload["version"]) != seen_versions.get(key, 0) + 1:
                    return False
                seen_versions[key] = int(payload["version"])
                if kind == "broker":
                    broker = self._broker(payload)
                    if _same(
                        broker.approved_by_binding_sha256,
                        broker.reviewed_by_binding_sha256,
                    ):
                        return False
                elif kind == "record":
                    authority = self._record(payload)
                    if authority.tenant_id != self.tenant_id:
                        return False
                else:
                    self._outcome(payload)
                payload_digests.add((kind, key[1], int(payload["version"]), _sha256(payload)))
            for row in operations:
                body = self._operation_body(row)
                if (
                    body["tenant_id"] != self.tenant_id
                    or not _same(_sha256(body), row["integrity_sha256"])
                    or (
                        str(body["kind"]),
                        str(body["object_key"]),
                        int(body["version"]),
                        _sha256(json.loads(str(body["result_json"]))),
                    )
                    not in payload_digests
                ):
                    return False
            previous: dict[tuple[str, str], str] = {}
            sequence: dict[tuple[str, str], int] = {}
            for row in audits:
                key = (str(row["kind"]), str(row["object_key"]))
                body = {
                    "tenant_id": str(row["tenant_id"]),
                    "kind": key[0],
                    "object_key": key[1],
                    "sequence": int(row["sequence"]),
                    "event_type": str(row["event_type"]),
                    "event_payload_sha256": str(row["event_payload_sha256"]),
                    "previous_sha256": str(row["previous_sha256"]),
                    "created_at": float(row["created_at"]),
                }
                if (
                    body["sequence"] != sequence.get(key, 0) + 1
                    or body["previous_sha256"] != previous.get(key, "0" * 64)
                    or not _same(_sha256(body), row["event_sha256"])
                ):
                    return False
                _digest(body["event_payload_sha256"], "event_payload_sha256")
                sequence[key] = int(body["sequence"])
                previous[key] = str(row["event_sha256"])
            return len(audits) == len(versions)
        except (
            DROPManagementConfigError,
            DROPManagementIntegrityError,
            DROPManagementValidationError,
            KeyError,
            TypeError,
            ValueError,
            sqlite3.Error,
        ):
            return False

    def reconcile(self) -> DROPRegistryReconciliation:
        """Return an exact local snapshot without inferring external completeness."""

        self._gate()
        checked_at = self._now()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM drop_registry_versions current WHERE tenant_id=? "
                "AND version=(SELECT MAX(version) FROM drop_registry_versions latest "
                "WHERE latest.tenant_id=current.tenant_id AND latest.kind=current.kind "
                "AND latest.object_key=current.object_key)",
                (self.tenant_id,),
            ).fetchall()
        payloads = tuple(self._row_payload(row) for row in rows)
        active_brokers = tuple(
            payload
            for payload in payloads
            if payload["kind"] == "broker" and payload["state"] == "active"
        )
        active_records = tuple(
            payload
            for payload in payloads
            if payload["kind"] == "record" and payload["state"] == "active"
        )
        active_outcomes = tuple(
            payload
            for payload in payloads
            if payload["kind"] == "outcome" and payload["state"] == "active"
        )
        return DROPRegistryReconciliation(
            tenant_id=self.tenant_id,
            integrity_valid=self.verify_integrity(),
            active_brokers=len(active_brokers),
            active_records=len(active_records),
            approved_outcomes=len(active_outcomes),
            expired_active_brokers=sum(
                float(payload["valid_until"]) <= checked_at for payload in active_brokers
            ),
            expired_active_records=sum(
                float(payload["authority"]["valid_until"]) <= checked_at
                for payload in active_records
            ),
            checked_at=checked_at,
        )

    def retained_key_revision_counts(self) -> Mapping[int, int]:
        """Count retained approval bindings by key revision without exposing principals."""

        self._gate()
        now = self._now()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM drop_registry_versions WHERE tenant_id=? "
                "AND retained_until>? ORDER BY kind,object_key,version",
                (self.tenant_id, now),
            ).fetchall()
        counts: dict[int, int] = {}
        for row in rows:
            payload = self._row_payload(row)
            self._validate_approval_payload(payload)
            for field in ("approved_by_key_revision", "reviewed_by_key_revision"):
                revision = _integer(payload[field], field, 1, 2**31 - 1)
                counts[revision] = counts.get(revision, 0) + 1
        return counts

    def list_authorities(
        self,
        *,
        kind: str | None = None,
        limit: int = 100,
    ) -> tuple[Mapping[str, object], ...]:
        """Return bounded current authority projections with digest-only fields."""

        self._gate()
        if kind is not None and kind not in _KINDS:
            raise DROPManagementValidationError("DROP authority kind is invalid")
        bounded = _integer(limit, "limit", 1, 250)
        query = (
            "SELECT * FROM drop_registry_versions current WHERE tenant_id=? "
            "AND version=(SELECT MAX(version) FROM drop_registry_versions latest "
            "WHERE latest.tenant_id=current.tenant_id AND latest.kind=current.kind "
            "AND latest.object_key=current.object_key) "
        )
        parameters: list[object] = [self.tenant_id]
        if kind is not None:
            query += "AND kind=? "
            parameters.append(kind)
        query += "ORDER BY kind,object_key LIMIT ?"
        parameters.append(bounded)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(parameters)).fetchall()
        projections: list[Mapping[str, object]] = []
        for row in rows:
            payload = self._row_payload(row)
            self._validate_approval_payload(payload)
            projection: dict[str, object] = {
                "kind": payload["kind"],
                "object_key": payload["object_key"],
                "version": payload["version"],
                "state": payload["state"],
                "created_at": payload["created_at"],
                "retained_until": payload["retained_until"],
                "approved_by_key_revision": payload["approved_by_key_revision"],
                "reviewed_by_key_revision": payload["reviewed_by_key_revision"],
                "integrity_sha256": _sha256(payload),
            }
            for field in (
                "broker_ref",
                "registration_sha256",
                "evidence_sha256",
                "valid_until",
                "drop_id",
                "authority_sha256",
                "import_evidence_sha256",
                "status",
                "evidence_binding_sha256",
            ):
                if field in payload:
                    projection[field] = payload[field]
            projections.append(projection)
        return tuple(projections)

    def list_record_details(self, *, limit: int = 250) -> tuple[Mapping[str, object], ...]:
        """Current imported DROP records with the closed request details a
        person needs to start or follow a request. No subject or broker
        digests are returned."""

        self._gate()
        bounded = _integer(limit, "limit", 1, 250)
        now = self._now()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM drop_registry_versions current WHERE tenant_id=? AND kind='record' "
                "AND version=(SELECT MAX(version) FROM drop_registry_versions latest "
                "WHERE latest.tenant_id=current.tenant_id AND latest.kind=current.kind "
                "AND latest.object_key=current.object_key) ORDER BY object_key LIMIT ?",
                (self.tenant_id, bounded),
            ).fetchall()
        details: list[Mapping[str, object]] = []
        for row in rows:
            payload = self._row_payload(row)
            authority = self._record(payload)
            details.append(
                {
                    "drop_id": authority.drop_id,
                    "request_type": authority.request_type,
                    "template_id": authority.template_id,
                    "language": authority.language,
                    "valid_until": authority.valid_until,
                    "version": payload["version"],
                    "state": payload["state"],
                    "usable": payload["state"] == "active"
                    and authority.valid_until > now
                    and float(payload["retained_until"]) > now,
                }
            )
        return tuple(details)

    def revision_history(
        self,
        *,
        kind: str,
        object_key: str,
        limit: int = 100,
    ) -> tuple[Mapping[str, object], ...]:
        selected_kind = str(kind)
        if selected_kind not in _KINDS:
            raise DROPManagementValidationError("DROP authority kind is invalid")
        selected_key = _ref(object_key, "object_key")
        bounded = _integer(limit, "limit", 1, 250)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM drop_registry_versions WHERE tenant_id=? AND kind=? "
                "AND object_key=? ORDER BY version DESC LIMIT ?",
                (self.tenant_id, selected_kind, selected_key, bounded),
            ).fetchall()
        result: list[Mapping[str, object]] = []
        for row in rows:
            payload = self._row_payload(row)
            self._validate_approval_payload(payload)
            result.append(
                {
                    "kind": selected_kind,
                    "object_key": selected_key,
                    "version": payload["version"],
                    "state": payload["state"],
                    "created_at": payload["created_at"],
                    "retained_until": payload["retained_until"],
                    "approved_by_key_revision": payload["approved_by_key_revision"],
                    "reviewed_by_key_revision": payload["reviewed_by_key_revision"],
                    "integrity_sha256": _sha256(payload),
                }
            )
        return tuple(result)

    def purge_expired(self, *, before: float | None = None, limit: int = 100) -> int:
        """Purge complete expired object histories under explicit maintenance authority."""

        self._gate()
        try:
            authorized = self._maintenance_authorizer()
        except Exception as exc:
            raise DROPManagementConfigError("DROP registry maintenance is unavailable") from exc
        if authorized is not True:
            raise DROPManagementConfigError("DROP registry maintenance is unavailable")
        if not self.verify_integrity():
            raise DROPManagementIntegrityError("DROP registry integrity must pass before purge")
        now = self._now()
        cutoff = now if before is None else min(now, _timestamp(before, "before"))
        bounded = _integer(limit, "limit", 1, 1_000)
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            candidates = connection.execute(
                "SELECT kind,object_key,MAX(version) AS version FROM drop_registry_versions "
                "WHERE tenant_id=? GROUP BY kind,object_key ORDER BY kind,object_key",
                (self.tenant_id,),
            ).fetchall()
            selected: list[tuple[str, str]] = []
            for candidate in candidates:
                if len(selected) >= bounded:
                    break
                row = connection.execute(
                    "SELECT * FROM drop_registry_versions WHERE tenant_id=? AND kind=? "
                    "AND object_key=? AND version=?",
                    (
                        self.tenant_id,
                        candidate["kind"],
                        candidate["object_key"],
                        candidate["version"],
                    ),
                ).fetchone()
                if row is None:
                    raise DROPManagementIntegrityError("DROP registry current row disappeared")
                payload = self._row_payload(row)
                if float(payload["retained_until"]) > cutoff:
                    continue
                if payload["kind"] == "broker":
                    linked = connection.execute(
                        "SELECT payload_json FROM drop_registry_versions WHERE tenant_id=? "
                        "AND kind='record'",
                        (self.tenant_id,),
                    ).fetchall()
                    if any(
                        json.loads(str(item["payload_json"])).get("broker_ref")
                        == payload["broker_ref"]
                        for item in linked
                    ):
                        continue
                selected.append((str(payload["kind"]), str(payload["object_key"])))
            self._maintenance.authorized = True
            try:
                for kind, object_key in selected:
                    connection.execute(
                        "DELETE FROM drop_registry_audit WHERE tenant_id=? AND kind=? "
                        "AND object_key=?",
                        (self.tenant_id, kind, object_key),
                    )
                    connection.execute(
                        "DELETE FROM drop_registry_operations WHERE tenant_id=? AND kind=? "
                        "AND object_key=?",
                        (self.tenant_id, kind, object_key),
                    )
                    connection.execute(
                        "DELETE FROM drop_registry_versions WHERE tenant_id=? AND kind=? "
                        "AND object_key=?",
                        (self.tenant_id, kind, object_key),
                    )
                connection.commit()
            finally:
                self._maintenance.authorized = False
        return len(selected)

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "durable_local_authority_registry": True,
            "network_io": NETWORK_IO,
            "live_drop_authority_verified": LIVE_DROP_AUTHORITY_VERIFIED,
            "legal_acceptance_verified": LEGAL_ACCEPTANCE_VERIFIED,
            "raw_subject_identity_accepted": False,
            "provider_credentials_accepted": False,
            "raw_evidence_accepted": False,
            "independent_broker_enrollment_required": True,
            "independent_record_import_required": True,
            "independent_terminal_outcome_approval_required": True,
            "external_subject_match_claimed": False,
        }


__all__ = [
    "LEGAL_ACCEPTANCE_VERIFIED",
    "LIVE_DROP_AUTHORITY_VERIFIED",
    "NETWORK_IO",
    "DROPAuthorityRegistry",
    "DROPBrokerEnrollment",
    "DROPRegistryReconciliation",
]
