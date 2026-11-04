"""Privacy-preserving California DROP request and status control plane.

The Delete Request and Opt-out Platform (DROP) is an external California
authority.  This module does not scrape that authority or accept a caller's
claim that a DROP record belongs to a tenant.  A server-installed resolver
must independently bind the record, registered broker, subject, request type,
template and language.  Creation composes an idempotent existing privacy-rights
intake callback; status changes require separately resolved outcome evidence.

Only opaque references and SHA-256 bindings are durable.  Names, email
addresses, attachments, provider credentials and retrieved subject data are
outside this store.  Local tests prove control-plane behavior only; they are
not California DROP interoperability or legal acceptance.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .constant_time import text_equals
from .file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
REQUEST_TYPES = frozenset({"DataDeletion", "OptOut"})
DROP_STATUSES = frozenset({"PENDING", "EXEMPTED", "DELETED", "OPTED_OUT", "NOT_FOUND"})
TERMINAL_STATUSES = DROP_STATUSES - {"PENDING"}
NETWORK_IO = False
LIVE_DROP_INTEROPERABILITY_VERIFIED = False
LEGAL_ACCEPTANCE_VERIFIED = False

_DIGEST_RE = __import__("re").compile(r"[0-9a-f]{64}\Z")
_REF_RE = __import__("re").compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_LANGUAGE_RE = __import__("re").compile(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?\Z")
_MAX_JSON_BYTES = 256 * 1024
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600
_PAYLOAD_FIELDS = frozenset(
    {
        "schema",
        "tenant_id",
        "drop_id",
        "request_type",
        "authority",
        "authority_sha256",
        "operation_key_sha256",
        "request_sha256",
        "state",
        "status",
        "revision",
        "receipt",
        "outcome_evidence",
        "outcome_evidence_sha256",
        "status_actor_binding_sha256",
        "status_reviewer_binding_sha256",
        "status_actor_ref",
        "principal_key_revision",
        "status_actor_key_revision",
        "status_reviewer_key_revision",
        "created_at",
        "updated_at",
        "retained_until",
    }
)
_REQUIRED_TRIGGERS = frozenset(
    {
        "drop_operations_no_update",
        "drop_audit_no_update",
        "drop_requests_no_delete",
        "drop_operations_no_delete",
        "drop_audit_no_delete",
    }
)


class DROPManagementError(RuntimeError):
    """Base error for DROP management."""


class DROPManagementConfigError(DROPManagementError):
    """Required deployment authority is disabled or unavailable."""


class DROPManagementValidationError(DROPManagementError, ValueError):
    """A value is outside the closed DROP contract."""


class DROPManagementConflict(DROPManagementError):
    """CAS, idempotency, authority, or lifecycle state changed."""


class DROPManagementNotFound(DROPManagementError):
    """A tenant-bound DROP record is absent or deliberately undisclosed."""


class DROPManagementIntegrityError(DROPManagementError):
    """Persisted DROP evidence failed integrity validation."""


def enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Return true only when DROP and its privacy-rights parent are enabled."""

    if config is None:
        try:
            from .config import config_source_errors, load_config

            if config_source_errors():
                return False
            config = load_config()
        except Exception:
            return False
    privacy = config.get("privacy_automation") if isinstance(config, Mapping) else None
    if not isinstance(privacy, Mapping):
        return False
    rights = privacy.get("rights_orchestration")
    drop = privacy.get("drop_management")
    return (
        privacy.get("enable") is True
        and isinstance(rights, Mapping)
        and rights.get("enable") is True
        and isinstance(drop, Mapping)
        and drop.get("enable") is True
    )


def require_enabled() -> None:
    if not enabled():
        raise DROPManagementConfigError(
            "DROP management requires privacy_automation, rights_orchestration, "
            "and privacy_automation.drop_management"
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
        raise DROPManagementValidationError("DROP metadata must be finite JSON") from exc
    if not 1 <= len(encoded) <= _MAX_JSON_BYTES:
        raise DROPManagementValidationError("DROP metadata exceeds its byte bound")
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


def _uuid(value: object, label: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (AttributeError, TypeError, ValueError) as exc:
        raise DROPManagementValidationError(f"{label} is not a UUID") from exc


@dataclass(frozen=True)
class DROPPrincipalBinding:
    """One principal digest pinned to a versioned server-owned key revision."""

    binding_sha256: str
    key_revision: int

    def normalized(self) -> DROPPrincipalBinding:
        return DROPPrincipalBinding(
            binding_sha256=_digest(self.binding_sha256, "principal_binding_sha256"),
            key_revision=_integer(self.key_revision, "principal_key_revision", 1, 2**31 - 1),
        )


@dataclass(frozen=True)
class DROPRecordAuthority:
    """Independent, time-bounded authority for one external DROP record."""

    tenant_id: str
    drop_id: int
    broker_registration_sha256: str
    subject_binding_sha256: str
    request_type: str
    template_id: str
    language: str
    record_revision: int
    valid_until: float
    authority_sha256: str = ""

    def normalized(self) -> DROPRecordAuthority:
        tenant = _tenant(self.tenant_id)
        drop_id = _integer(self.drop_id, "drop_id", 1, 2**31 - 1)
        broker = _digest(self.broker_registration_sha256, "broker_registration_sha256")
        subject = _digest(self.subject_binding_sha256, "subject_binding_sha256")
        if self.request_type not in REQUEST_TYPES:
            raise DROPManagementValidationError("request_type must be DataDeletion or OptOut")
        template = _uuid(self.template_id, "template_id")
        language = str(self.language or "").lower()
        if not _LANGUAGE_RE.fullmatch(language):
            raise DROPManagementValidationError("language is not a supported closed code")
        revision = _integer(self.record_revision, "record_revision", 1, 2**31 - 1)
        valid_until = _timestamp(self.valid_until, "valid_until")
        body = {
            "tenant_id": tenant,
            "drop_id": drop_id,
            "broker_registration_sha256": broker,
            "subject_binding_sha256": subject,
            "request_type": self.request_type,
            "template_id": template,
            "language": language,
            "record_revision": revision,
            "valid_until": valid_until,
        }
        calculated = _sha256(body)
        if self.authority_sha256 and not _same(self.authority_sha256, calculated):
            raise DROPManagementValidationError("DROP record authority digest changed")
        return DROPRecordAuthority(**body, authority_sha256=calculated)


@dataclass(frozen=True)
class DROPDSARReceipt:
    """Minimized receipt returned by the existing privacy-rights intake."""

    tenant_id: str
    drop_id: int
    authority_sha256: str
    subject_binding_sha256: str
    request_type: str
    request_queue_id: str
    request_queue_ref_id: str
    internal_case_id: str
    created_at: float
    receipt_sha256: str = ""

    def normalized(self) -> DROPDSARReceipt:
        body = {
            "tenant_id": _tenant(self.tenant_id),
            "drop_id": _integer(self.drop_id, "drop_id", 1, 2**31 - 1),
            "authority_sha256": _digest(self.authority_sha256, "authority_sha256"),
            "subject_binding_sha256": _digest(
                self.subject_binding_sha256, "subject_binding_sha256"
            ),
            "request_type": self.request_type,
            "request_queue_id": _uuid(self.request_queue_id, "request_queue_id"),
            "request_queue_ref_id": _ref(self.request_queue_ref_id, "request_queue_ref_id"),
            "internal_case_id": _ref(self.internal_case_id, "internal_case_id"),
            "created_at": _timestamp(self.created_at, "created_at"),
        }
        if body["request_type"] not in REQUEST_TYPES:
            raise DROPManagementValidationError("receipt request_type is invalid")
        calculated = _sha256(body)
        if self.receipt_sha256 and not _same(self.receipt_sha256, calculated):
            raise DROPManagementValidationError("DSAR receipt digest changed")
        return DROPDSARReceipt(**body, receipt_sha256=calculated)


@dataclass(frozen=True)
class DROPStatusEvidence:
    """Independent outcome evidence authorizing one terminal DROP status."""

    tenant_id: str
    drop_id: int
    authority_sha256: str
    request_queue_id: str
    internal_case_id: str
    status: str
    reviewer_ref: str
    evidence_sha256: str
    evidence_revision: int
    observed_at: float
    valid_until: float
    deletion_verified: bool = False
    opt_out_verified: bool = False
    search_complete: bool = False
    exemption_approved: bool = False
    provider_operations_complete: bool = False
    evidence_binding_sha256: str = ""

    def normalized(self) -> DROPStatusEvidence:
        if self.status not in TERMINAL_STATUSES:
            raise DROPManagementValidationError("status evidence must authorize a terminal status")
        flags = (
            self.deletion_verified,
            self.opt_out_verified,
            self.search_complete,
            self.exemption_approved,
            self.provider_operations_complete,
        )
        if any(not isinstance(value, bool) for value in flags):
            raise DROPManagementValidationError("status evidence flags must be boolean")
        body = {
            "tenant_id": _tenant(self.tenant_id),
            "drop_id": _integer(self.drop_id, "drop_id", 1, 2**31 - 1),
            "authority_sha256": _digest(self.authority_sha256, "authority_sha256"),
            "request_queue_id": _uuid(self.request_queue_id, "request_queue_id"),
            "internal_case_id": _ref(self.internal_case_id, "internal_case_id"),
            "status": self.status,
            "reviewer_ref": _ref(self.reviewer_ref, "reviewer_ref"),
            "evidence_sha256": _digest(self.evidence_sha256, "evidence_sha256"),
            "evidence_revision": _integer(
                self.evidence_revision, "evidence_revision", 1, 2**31 - 1
            ),
            "observed_at": _timestamp(self.observed_at, "observed_at"),
            "valid_until": _timestamp(self.valid_until, "valid_until"),
            "deletion_verified": self.deletion_verified,
            "opt_out_verified": self.opt_out_verified,
            "search_complete": self.search_complete,
            "exemption_approved": self.exemption_approved,
            "provider_operations_complete": self.provider_operations_complete,
        }
        calculated = _sha256(body)
        if self.evidence_binding_sha256 and not _same(self.evidence_binding_sha256, calculated):
            raise DROPManagementValidationError("status evidence binding changed")
        return DROPStatusEvidence(**body, evidence_binding_sha256=calculated)


@dataclass(frozen=True)
class DROPRequestRecord:
    tenant_id: str
    drop_id: int
    request_type: str
    status: str
    revision: int
    request_queue_id: str
    request_queue_ref_id: str
    internal_case_id: str
    authority_sha256: str
    outcome_evidence_sha256: str
    created_at: float
    updated_at: float
    retained_until: float
    integrity_sha256: str
    principal_key_revision: int = 1
    status_actor_key_revision: int = 0
    status_reviewer_key_revision: int = 0


class DROPManagementStore:
    """Recoverable DROP-to-privacy-rights bridge with terminal evidence gates."""

    def __init__(  # noqa: PLR0913 - explicit trust seams are intentional
        self,
        path: str | Path,
        *,
        tenant_id: str,
        authority_resolver: Callable[[DROPRecordAuthority], DROPRecordAuthority],
        dsar_submitter: Callable[[DROPRecordAuthority, str], DROPDSARReceipt],
        status_evidence_resolver: Callable[
            [DROPRecordAuthority, DROPDSARReceipt, str], DROPStatusEvidence
        ],
        principal_binding_resolver: Callable[[str, str], str | DROPPrincipalBinding],
        principal_binding_verifier: Callable[[str, str, int, str], bool] | None = None,
        principal_key_revision_checker: Callable[[int], bool] | None = None,
        retention_seconds: int = 365 * 24 * 3_600,
        maintenance_authorizer: Callable[[], bool] = lambda: False,
        config_gate: Callable[[], None] = require_enabled,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not all(
            callable(value)
            for value in (
                authority_resolver,
                dsar_submitter,
                status_evidence_resolver,
                principal_binding_resolver,
                maintenance_authorizer,
                config_gate,
                clock,
            )
        ):
            raise DROPManagementConfigError("DROP authority dependencies are incomplete")
        try:
            config_gate()
        except DROPManagementError:
            raise
        except Exception as exc:
            raise DROPManagementConfigError("DROP configuration gate is unavailable") from exc
        self.path = Path(path)
        self.tenant_id = _tenant(tenant_id)
        self._authority_resolver = authority_resolver
        self._dsar_submitter = dsar_submitter
        self._status_evidence_resolver = status_evidence_resolver
        self._principal_binding_resolver = principal_binding_resolver
        for dependency in (principal_binding_verifier, principal_key_revision_checker):
            if dependency is not None and not callable(dependency):
                raise DROPManagementConfigError("DROP principal key authority is unavailable")
        self._principal_binding_verifier = principal_binding_verifier
        self._principal_key_revision_checker = principal_key_revision_checker
        self._retention_seconds = _integer(
            retention_seconds, "retention_seconds", 3_600, _MAX_RETENTION_SECONDS
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
            "drop_maintenance_authorized",
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
                CREATE TABLE IF NOT EXISTS drop_meta(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS drop_requests(
                    tenant_id TEXT NOT NULL,drop_id INTEGER NOT NULL,state TEXT NOT NULL,
                    status TEXT,revision INTEGER NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,drop_id)
                );
                CREATE TABLE IF NOT EXISTS drop_operations(
                    tenant_id TEXT NOT NULL,action TEXT NOT NULL,key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,drop_id INTEGER NOT NULL,created_at REAL NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,action,key_sha256)
                );
                CREATE TABLE IF NOT EXISTS drop_audit(
                    tenant_id TEXT NOT NULL,drop_id INTEGER NOT NULL,sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,event_payload_sha256 TEXT NOT NULL,
                    previous_sha256 TEXT NOT NULL,event_sha256 TEXT NOT NULL,created_at REAL NOT NULL,
                    PRIMARY KEY(tenant_id,drop_id,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS drop_operations_no_update
                    BEFORE UPDATE ON drop_operations
                    BEGIN SELECT RAISE(ABORT,'immutable DROP operation'); END;
                CREATE TRIGGER IF NOT EXISTS drop_audit_no_update
                    BEFORE UPDATE ON drop_audit
                    BEGIN SELECT RAISE(ABORT,'immutable DROP audit'); END;
                CREATE TRIGGER IF NOT EXISTS drop_requests_no_delete
                    BEFORE DELETE ON drop_requests
                    WHEN drop_maintenance_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'DROP maintenance authority required'); END;
                CREATE TRIGGER IF NOT EXISTS drop_operations_no_delete
                    BEFORE DELETE ON drop_operations
                    WHEN drop_maintenance_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'DROP maintenance authority required'); END;
                CREATE TRIGGER IF NOT EXISTS drop_audit_no_delete
                    BEFORE DELETE ON drop_audit
                    WHEN drop_maintenance_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'DROP maintenance authority required'); END;
                """
            )
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, SCHEMA_VERSION):
                raise DROPManagementConfigError(
                    f"unsupported DROP management schema version {version}"
                )
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            tenants = {
                str(row[0])
                for row in connection.execute(
                    "SELECT tenant_id FROM drop_requests "
                    "UNION SELECT tenant_id FROM drop_operations "
                    "UNION SELECT tenant_id FROM drop_audit"
                )
            }
            if tenants and tenants != {self.tenant_id}:
                raise DROPManagementIntegrityError(
                    "DROP database contains a different tenant binding"
                )
            tenant_sha256 = _text_sha256(self.tenant_id)
            connection.execute(
                "INSERT OR IGNORE INTO drop_meta(key,value) VALUES('tenant_sha256',?)",
                (tenant_sha256,),
            )
            binding = connection.execute(
                "SELECT value FROM drop_meta WHERE key='tenant_sha256'"
            ).fetchone()
            if binding is None or not _same(binding[0], tenant_sha256):
                raise DROPManagementIntegrityError("DROP database belongs to another tenant")
        ensure_private_file(self.path)

    def _now(self) -> float:
        return _timestamp(self._clock(), "current time")

    def _resolve(self, expected: DROPRecordAuthority, now: float) -> DROPRecordAuthority:
        if type(expected) is not DROPRecordAuthority:
            raise DROPManagementConflict("DROP record authority is unavailable")
        expected = expected.normalized()
        if not text_equals(expected.tenant_id, self.tenant_id):
            raise DROPManagementNotFound("DROP request was not found")
        if expected.valid_until <= now:
            raise DROPManagementConflict("DROP record authority expired")
        try:
            first = self._authority_resolver(expected)
            second = self._authority_resolver(expected)
        except DROPManagementError:
            raise
        except Exception as exc:
            raise DROPManagementConflict("DROP record authority is unavailable") from exc
        if type(first) is not DROPRecordAuthority or type(second) is not DROPRecordAuthority:
            raise DROPManagementConflict("DROP record authority is unavailable")
        first = first.normalized()
        second = second.normalized()
        if (
            first.valid_until <= now
            or second.valid_until <= now
            or not _same(first.authority_sha256, expected.authority_sha256)
            or not _same(second.authority_sha256, expected.authority_sha256)
        ):
            raise DROPManagementConflict("DROP record authority changed")
        return second

    @staticmethod
    def _binding(value: object) -> DROPPrincipalBinding:
        if isinstance(value, str):
            return DROPPrincipalBinding(value, 1).normalized()
        if type(value) is DROPPrincipalBinding:
            return value.normalized()
        raise DROPManagementValidationError("principal binding authority is invalid")

    def _principal_binding(
        self,
        tenant_id: str,
        principal_ref: str,
    ) -> DROPPrincipalBinding:
        if not text_equals(_tenant(tenant_id), self.tenant_id):
            raise DROPManagementNotFound("DROP request was not found")
        principal = _ref(principal_ref, "principal_ref")
        try:
            first = self._principal_binding_resolver(self.tenant_id, principal)
            second = self._principal_binding_resolver(self.tenant_id, principal)
        except DROPManagementError:
            raise
        except Exception as exc:
            raise DROPManagementConflict("principal binding is unavailable") from exc
        try:
            first_binding = self._binding(first)
            second_binding = self._binding(second)
        except DROPManagementValidationError as exc:
            raise DROPManagementConflict("principal binding is unavailable") from exc
        if (
            first_binding.key_revision != second_binding.key_revision
            or not _same(first_binding.binding_sha256, second_binding.binding_sha256)
        ):
            raise DROPManagementConflict("principal binding changed")
        return second_binding

    def _verify_principal_binding(
        self,
        principal_ref: str,
        key_revision: object,
        binding_sha256: object,
    ) -> bool:
        try:
            revision = _integer(key_revision, "principal_key_revision", 1, 2**31 - 1)
            digest = _digest(binding_sha256, "principal_binding_sha256")
            if callable(self._principal_binding_verifier):
                return self._principal_binding_verifier(
                    self.tenant_id,
                    _ref(principal_ref, "principal_ref"),
                    revision,
                    digest,
                ) is True
            current = self._principal_binding(self.tenant_id, principal_ref)
            return current.key_revision == revision and _same(current.binding_sha256, digest)
        except DROPManagementError:
            return False

    def _require_key_revision(self, value: object) -> int:
        revision = _integer(value, "principal_key_revision", 1, 2**31 - 1)
        if callable(self._principal_key_revision_checker):
            try:
                active = self._principal_key_revision_checker(revision)
            except Exception as exc:
                raise DROPManagementConflict("principal key revision is unavailable") from exc
            if active is not True:
                raise DROPManagementConflict("principal key revision is unavailable")
        return revision

    @staticmethod
    def _payload(row: sqlite3.Row) -> dict[str, Any]:
        try:
            raw = str(row["payload_json"])
            if not 1 <= len(raw.encode("utf-8")) <= _MAX_JSON_BYTES:
                raise ValueError("stored payload exceeds its bound")
            payload = json.loads(raw)
        except (TypeError, UnicodeError, ValueError) as exc:
            raise DROPManagementIntegrityError("stored DROP request is invalid") from exc
        if (
            not isinstance(payload, dict)
            or set(payload) != _PAYLOAD_FIELDS
            or payload.get("schema") != "lightwork.privacy-drop-request.v1"
            or payload.get("tenant_id") != row["tenant_id"]
            or payload.get("drop_id") != row["drop_id"]
            or payload.get("state") != row["state"]
            or payload.get("status") != row["status"]
            or payload.get("revision") != row["revision"]
            or payload.get("retained_until") != row["retained_until"]
            or not _same(_sha256(payload), row["integrity_sha256"])
        ):
            raise DROPManagementIntegrityError("stored DROP request changed")
        return payload

    @staticmethod
    def _authority(payload: Mapping[str, Any]) -> DROPRecordAuthority:
        raw = payload.get("authority")
        if not isinstance(raw, Mapping):
            raise DROPManagementIntegrityError("stored DROP authority is invalid")
        try:
            authority = DROPRecordAuthority(**dict(raw)).normalized()
        except (TypeError, DROPManagementError) as exc:
            raise DROPManagementIntegrityError("stored DROP authority is invalid") from exc
        if not _same(payload.get("authority_sha256"), authority.authority_sha256):
            raise DROPManagementIntegrityError("stored DROP authority changed")
        return authority

    @staticmethod
    def _receipt(payload: Mapping[str, Any]) -> DROPDSARReceipt:
        raw = payload.get("receipt")
        if not isinstance(raw, Mapping):
            raise DROPManagementIntegrityError("stored DSAR receipt is invalid")
        try:
            return DROPDSARReceipt(**dict(raw)).normalized()
        except (TypeError, DROPManagementError) as exc:
            raise DROPManagementIntegrityError("stored DSAR receipt is invalid") from exc

    @staticmethod
    def _outcome(payload: Mapping[str, Any]) -> DROPStatusEvidence:
        raw = payload.get("outcome_evidence")
        if not isinstance(raw, Mapping):
            raise DROPManagementIntegrityError("stored DROP outcome evidence is invalid")
        try:
            evidence = DROPStatusEvidence(**dict(raw)).normalized()
        except (TypeError, DROPManagementError) as exc:
            raise DROPManagementIntegrityError("stored DROP outcome evidence is invalid") from exc
        if not _same(payload.get("outcome_evidence_sha256"), evidence.evidence_binding_sha256):
            raise DROPManagementIntegrityError("stored DROP outcome evidence changed")
        return evidence

    def _public(self, payload: Mapping[str, Any]) -> DROPRequestRecord:
        self._validate_persisted_state(payload)
        receipt = self._receipt(payload)
        return DROPRequestRecord(
            tenant_id=str(payload["tenant_id"]),
            drop_id=int(payload["drop_id"]),
            request_type=str(payload["request_type"]),
            status=str(payload["status"]),
            revision=int(payload["revision"]),
            request_queue_id=receipt.request_queue_id,
            request_queue_ref_id=receipt.request_queue_ref_id,
            internal_case_id=receipt.internal_case_id,
            authority_sha256=str(payload["authority_sha256"]),
            outcome_evidence_sha256=str(payload.get("outcome_evidence_sha256") or ""),
            principal_key_revision=int(payload["principal_key_revision"]),
            status_actor_key_revision=int(payload["status_actor_key_revision"]),
            status_reviewer_key_revision=int(payload["status_reviewer_key_revision"]),
            created_at=float(payload["created_at"]),
            updated_at=float(payload["updated_at"]),
            retained_until=float(payload["retained_until"]),
            integrity_sha256=_sha256(dict(payload)),
        )

    @staticmethod
    def _operation_body(row: sqlite3.Row) -> dict[str, object]:
        return {
            "tenant_id": str(row["tenant_id"]),
            "action": str(row["action"]),
            "key_sha256": str(row["key_sha256"]),
            "request_sha256": str(row["request_sha256"]),
            "drop_id": int(row["drop_id"]),
            "created_at": float(row["created_at"]),
        }

    def _operation(
        self,
        tenant_id: str,
        action: str,
        key_sha256: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM drop_operations WHERE tenant_id=? AND action=? AND key_sha256=?",
                (tenant_id, action, key_sha256),
            ).fetchone()
            if row is None:
                return None
            body = self._operation_body(row)
            if not _same(_sha256(body), row["integrity_sha256"]):
                raise DROPManagementIntegrityError("stored DROP operation changed")
            if not _same(body["request_sha256"], request_sha256):
                raise DROPManagementConflict("idempotency key is bound to another request")
            request_row = connection.execute(
                "SELECT * FROM drop_requests WHERE tenant_id=? AND drop_id=?",
                (tenant_id, body["drop_id"]),
            ).fetchone()
        if request_row is None:
            raise DROPManagementIntegrityError("idempotent DROP request is missing")
        return self._payload(request_row)

    @staticmethod
    def _append_audit(
        connection: sqlite3.Connection,
        payload: Mapping[str, Any],
        event_type: str,
        event_payload_sha256: str,
        created_at: float,
    ) -> None:
        tenant_id = str(payload["tenant_id"])
        drop_id = int(payload["drop_id"])
        row = connection.execute(
            "SELECT sequence,event_sha256 FROM drop_audit WHERE tenant_id=? AND drop_id=? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant_id, drop_id),
        ).fetchone()
        sequence = 1 if row is None else int(row["sequence"]) + 1
        previous = "0" * 64 if row is None else str(row["event_sha256"])
        body = {
            "tenant_id": tenant_id,
            "drop_id": drop_id,
            "sequence": sequence,
            "event_type": event_type,
            "event_payload_sha256": event_payload_sha256,
            "previous_sha256": previous,
            "created_at": created_at,
        }
        connection.execute(
            "INSERT INTO drop_audit VALUES(?,?,?,?,?,?,?,?)",
            (
                body["tenant_id"],
                body["drop_id"],
                body["sequence"],
                body["event_type"],
                body["event_payload_sha256"],
                body["previous_sha256"],
                _sha256(body),
                body["created_at"],
            ),
        )

    @staticmethod
    def _validate_receipt(
        receipt: DROPDSARReceipt,
        authority: DROPRecordAuthority,
    ) -> DROPDSARReceipt:
        if type(receipt) is not DROPDSARReceipt:
            raise DROPManagementConflict("DSAR receipt is unavailable")
        receipt = receipt.normalized()
        if (
            receipt.tenant_id != authority.tenant_id
            or receipt.drop_id != authority.drop_id
            or receipt.request_type != authority.request_type
            or not _same(receipt.authority_sha256, authority.authority_sha256)
            or not _same(receipt.subject_binding_sha256, authority.subject_binding_sha256)
        ):
            raise DROPManagementConflict("DSAR receipt binding changed")
        return receipt

    def create_request(
        self,
        authority: DROPRecordAuthority,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> DROPRequestRecord:
        """Create/recover one deletion or permanent opt-out privacy request."""

        self._gate()
        if _integer(expected_revision, "expected_revision", 0, 0) != 0:
            raise DROPManagementConflict("new DROP request requires revision zero")
        key_sha = _text_sha256(_ref(idempotency_key, "idempotency_key"))
        now = self._now()
        authority = self._resolve(authority, now)
        record_key_revision = self._principal_binding(
            authority.tenant_id,
            f"drop-management-record:{authority.drop_id}",
        ).key_revision
        request_sha = _sha256(
            {
                "action": "create_drop_request",
                "authority_sha256": authority.authority_sha256,
                "expected_revision": 0,
            }
        )
        payload = self._operation(authority.tenant_id, "create", key_sha, request_sha)
        if payload is None:
            retained_until = now + self._retention_seconds
            payload = {
                "schema": "lightwork.privacy-drop-request.v1",
                "tenant_id": authority.tenant_id,
                "drop_id": authority.drop_id,
                "request_type": authority.request_type,
                "authority": asdict(authority),
                "authority_sha256": authority.authority_sha256,
                "operation_key_sha256": key_sha,
                "request_sha256": request_sha,
                "state": "creating",
                "status": None,
                "revision": 0,
                "receipt": None,
                "outcome_evidence": None,
                "outcome_evidence_sha256": "",
                "status_actor_binding_sha256": "",
                "status_reviewer_binding_sha256": "",
                "status_actor_ref": "",
                "principal_key_revision": record_key_revision,
                "status_actor_key_revision": 0,
                "status_reviewer_key_revision": 0,
                "created_at": now,
                "updated_at": now,
                "retained_until": retained_until,
            }
            operation = {
                "tenant_id": authority.tenant_id,
                "action": "create",
                "key_sha256": key_sha,
                "request_sha256": request_sha,
                "drop_id": authority.drop_id,
                "created_at": now,
            }
            try:
                with self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        "INSERT INTO drop_requests VALUES(?,?,?,?,?,?,?,?)",
                        (
                            authority.tenant_id,
                            authority.drop_id,
                            "creating",
                            None,
                            0,
                            retained_until,
                            _canonical(payload).decode("ascii"),
                            _sha256(payload),
                        ),
                    )
                    connection.execute(
                        "INSERT INTO drop_operations VALUES(?,?,?,?,?,?,?)",
                        (*operation.values(), _sha256(operation)),
                    )
                    connection.commit()
            except sqlite3.IntegrityError:
                payload = self._operation(authority.tenant_id, "create", key_sha, request_sha)
                if payload is None:
                    raise DROPManagementConflict("DROP request changed concurrently") from None

        stored = self._authority(payload)
        if not _same(stored.authority_sha256, authority.authority_sha256):
            raise DROPManagementConflict("DROP request authority changed")
        if payload.get("state") == "active":
            return self._public(payload)
        if payload.get("state") != "creating" or payload.get("revision") != 0:
            raise DROPManagementIntegrityError("DROP request state is invalid")
        bridge_key = f"drop-dsar-{key_sha}"
        try:
            receipt = self._dsar_submitter(authority, bridge_key)
        except DROPManagementError:
            raise
        except Exception as exc:
            raise DROPManagementConflict("privacy-rights intake is unavailable") from exc
        receipt = self._validate_receipt(receipt, authority)
        self._resolve(authority, self._now())
        finalized_at = self._now()
        if not (
            float(payload["created_at"])
            <= receipt.created_at
            <= finalized_at
            < min(authority.valid_until, float(payload["retained_until"]))
        ):
            raise DROPManagementConflict("DSAR receipt time is invalid")
        final = dict(payload)
        final.update(
            {
                "state": "active",
                "status": "PENDING",
                "revision": 1,
                "receipt": asdict(receipt),
                "updated_at": finalized_at,
            }
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE drop_requests SET state='active',status='PENDING',revision=1,"
                "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND drop_id=? "
                "AND state='creating' AND revision=0 AND integrity_sha256=?",
                (
                    _canonical(final).decode("ascii"),
                    _sha256(final),
                    authority.tenant_id,
                    authority.drop_id,
                    _sha256(payload),
                ),
            )
            if updated.rowcount == 1:
                self._append_audit(
                    connection,
                    final,
                    "DROP_REQUEST_CREATED",
                    receipt.receipt_sha256,
                    float(final["updated_at"]),
                )
            else:
                row = connection.execute(
                    "SELECT * FROM drop_requests WHERE tenant_id=? AND drop_id=?",
                    (authority.tenant_id, authority.drop_id),
                ).fetchone()
                if row is None:
                    raise DROPManagementConflict("DROP finalization CAS failed")
                current = self._payload(row)
                if current != final:
                    raise DROPManagementConflict("DROP finalization CAS failed")
                final = current
            connection.commit()
        return self._public(final)

    def _validate_outcome(
        self,
        evidence: DROPStatusEvidence,
        authority: DROPRecordAuthority,
        receipt: DROPDSARReceipt,
        status: str,
        actor_binding: DROPPrincipalBinding,
        now: float,
    ) -> tuple[DROPStatusEvidence, DROPPrincipalBinding]:
        if type(evidence) is not DROPStatusEvidence:
            raise DROPManagementConflict("DROP status evidence is unavailable")
        evidence = evidence.normalized()
        reviewer_binding = self._principal_binding(
            authority.tenant_id,
            evidence.reviewer_ref,
        )
        if (
            evidence.tenant_id != authority.tenant_id
            or evidence.drop_id != authority.drop_id
            or evidence.status != status
            or evidence.request_queue_id != receipt.request_queue_id
            or evidence.internal_case_id != receipt.internal_case_id
            or not _same(evidence.authority_sha256, authority.authority_sha256)
            or not receipt.created_at <= evidence.observed_at <= now < evidence.valid_until
            or _same(reviewer_binding.binding_sha256, actor_binding.binding_sha256)
        ):
            raise DROPManagementConflict("DROP status evidence binding changed")
        if status == "DELETED" and not (
            authority.request_type == "DataDeletion"
            and evidence.deletion_verified
            and evidence.search_complete
            and evidence.provider_operations_complete
        ):
            raise DROPManagementConflict("deletion outcome is not independently verified")
        if status == "OPTED_OUT" and not (
            authority.request_type == "OptOut"
            and evidence.opt_out_verified
            and evidence.provider_operations_complete
        ):
            raise DROPManagementConflict("opt-out outcome is not independently verified")
        if status == "NOT_FOUND" and not evidence.search_complete:
            raise DROPManagementConflict("not-found outcome requires a complete search")
        if status == "EXEMPTED" and not evidence.exemption_approved:
            raise DROPManagementConflict("exemption outcome is not independently approved")
        return evidence, reviewer_binding

    def update_status(
        self,
        authority: DROPRecordAuthority,
        *,
        status: str,
        expected_revision: int,
        idempotency_key: str,
        actor_ref: str,
    ) -> DROPRequestRecord:
        """Apply one independently evidenced terminal status with CAS."""

        self._gate()
        if status not in TERMINAL_STATUSES:
            raise DROPManagementValidationError("status must be a terminal DROP status")
        actor = _ref(actor_ref, "actor_ref")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        key_sha = _text_sha256(_ref(idempotency_key, "idempotency_key"))
        now = self._now()
        authority = self._resolve(authority, now)
        actor_binding = self._principal_binding(authority.tenant_id, actor)
        request_sha = _sha256(
            {
                "action": "update_drop_status",
                "authority_sha256": authority.authority_sha256,
                "status": status,
                "expected_revision": expected,
                "actor_binding_sha256": actor_binding.binding_sha256,
                "actor_key_revision": actor_binding.key_revision,
            }
        )
        replay = self._operation(authority.tenant_id, "update_status", key_sha, request_sha)
        if replay is not None:
            return self._public(replay)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM drop_requests WHERE tenant_id=? AND drop_id=?",
                (authority.tenant_id, authority.drop_id),
            ).fetchone()
        if row is None:
            raise DROPManagementNotFound("DROP request was not found")
        payload = self._payload(row)
        if float(payload["retained_until"]) <= now:
            raise DROPManagementNotFound("DROP request was not found")
        if payload.get("state") != "active" or payload.get("status") != "PENDING":
            raise DROPManagementConflict("DROP status must differ from its terminal state")
        if payload.get("revision") != expected:
            raise DROPManagementConflict("DROP request revision changed")
        stored = self._authority(payload)
        if not _same(stored.authority_sha256, authority.authority_sha256):
            raise DROPManagementNotFound("DROP request was not found")
        receipt = self._receipt(payload)
        try:
            evidence = self._status_evidence_resolver(authority, receipt, status)
        except DROPManagementError:
            raise
        except Exception as exc:
            raise DROPManagementConflict("DROP status evidence is unavailable") from exc
        evidence, reviewer_binding = self._validate_outcome(
            evidence,
            authority,
            receipt,
            status,
            actor_binding,
            self._now(),
        )
        self._resolve(authority, self._now())
        updated_at = self._now()
        if updated_at >= min(
            evidence.valid_until,
            authority.valid_until,
            float(payload["retained_until"]),
        ):
            raise DROPManagementConflict("DROP status evidence expired before commit")
        final = dict(payload)
        final.update(
            {
                "status": status,
                "revision": expected + 1,
                "outcome_evidence": asdict(evidence),
                "outcome_evidence_sha256": evidence.evidence_binding_sha256,
                "status_actor_binding_sha256": actor_binding.binding_sha256,
                "status_reviewer_binding_sha256": reviewer_binding.binding_sha256,
                "status_actor_ref": actor,
                "status_actor_key_revision": actor_binding.key_revision,
                "status_reviewer_key_revision": reviewer_binding.key_revision,
                "updated_at": updated_at,
            }
        )
        operation = {
            "tenant_id": authority.tenant_id,
            "action": "update_status",
            "key_sha256": key_sha,
            "request_sha256": request_sha,
            "drop_id": authority.drop_id,
            "created_at": float(final["updated_at"]),
        }
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                updated = connection.execute(
                    "UPDATE drop_requests SET status=?,revision=?,payload_json=?,"
                    "integrity_sha256=? WHERE tenant_id=? AND drop_id=? AND state='active' "
                    "AND status='PENDING' AND revision=? AND integrity_sha256=?",
                    (
                        status,
                        expected + 1,
                        _canonical(final).decode("ascii"),
                        _sha256(final),
                        authority.tenant_id,
                        authority.drop_id,
                        expected,
                        _sha256(payload),
                    ),
                )
                if updated.rowcount != 1:
                    raise DROPManagementConflict("DROP status update CAS failed")
                connection.execute(
                    "INSERT INTO drop_operations VALUES(?,?,?,?,?,?,?)",
                    (*operation.values(), _sha256(operation)),
                )
                self._append_audit(
                    connection,
                    final,
                    "DROP_STATUS_UPDATED",
                    evidence.evidence_binding_sha256,
                    float(final["updated_at"]),
                )
                connection.commit()
        except sqlite3.IntegrityError:
            replay = self._operation(authority.tenant_id, "update_status", key_sha, request_sha)
            if replay is None:
                raise DROPManagementConflict("DROP status changed concurrently") from None
            final = replay
        return self._public(final)

    def get_request(self, authority: DROPRecordAuthority) -> DROPRequestRecord:
        self._gate()
        now = self._now()
        authority = self._resolve(authority, now)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM drop_requests WHERE tenant_id=? AND drop_id=?",
                (authority.tenant_id, authority.drop_id),
            ).fetchone()
        if row is None:
            raise DROPManagementNotFound("DROP request was not found")
        payload = self._payload(row)
        if (
            payload.get("state") != "active"
            or float(payload["retained_until"]) <= now
            or not _same(payload.get("authority_sha256"), authority.authority_sha256)
        ):
            raise DROPManagementNotFound("DROP request was not found")
        return self._public(payload)

    def _validate_persisted_state(
        self,
        payload: Mapping[str, Any],
    ) -> tuple[DROPRecordAuthority, DROPDSARReceipt | None, DROPStatusEvidence | None]:
        authority = self._authority(payload)
        if (
            not text_equals(authority.tenant_id, self.tenant_id)
            or payload.get("request_type") != authority.request_type
            or payload.get("drop_id") != authority.drop_id
        ):
            raise DROPManagementIntegrityError("stored DROP authority is misbound")
        try:
            _digest(payload.get("operation_key_sha256"), "operation_key_sha256")
            _digest(payload.get("request_sha256"), "request_sha256")
            principal_key_revision = self._require_key_revision(
                payload.get("principal_key_revision")
            )
            created_at = _timestamp(payload.get("created_at"), "created_at")
            updated_at = _timestamp(payload.get("updated_at"), "updated_at")
            retained_until = _timestamp(payload.get("retained_until"), "retained_until")
        except DROPManagementValidationError as exc:
            raise DROPManagementIntegrityError("stored DROP metadata is invalid") from exc
        if not (
            created_at <= updated_at < retained_until
            and 3_600 <= retained_until - created_at <= _MAX_RETENTION_SECONDS
            and updated_at < authority.valid_until
        ):
            raise DROPManagementIntegrityError("stored DROP retention state is invalid")
        state = payload.get("state")
        status = payload.get("status")
        revision = payload.get("revision")
        outcome = payload.get("outcome_evidence")
        outcome_sha = payload.get("outcome_evidence_sha256")
        actor_binding = payload.get("status_actor_binding_sha256")
        reviewer_binding = payload.get("status_reviewer_binding_sha256")
        actor_ref = payload.get("status_actor_ref")
        actor_key_revision = payload.get("status_actor_key_revision")
        reviewer_key_revision = payload.get("status_reviewer_key_revision")
        if principal_key_revision < 1:
            raise DROPManagementIntegrityError("stored DROP principal key is invalid")
        if state == "creating":
            if (
                status is not None
                or revision != 0
                or payload.get("receipt") is not None
                or outcome is not None
                or outcome_sha != ""
                or actor_binding != ""
                or reviewer_binding != ""
                or actor_ref != ""
                or actor_key_revision != 0
                or reviewer_key_revision != 0
            ):
                raise DROPManagementIntegrityError("stored DROP creating state is invalid")
            return authority, None, None
        if state != "active":
            raise DROPManagementIntegrityError("stored DROP lifecycle state is invalid")
        try:
            receipt = self._validate_receipt(self._receipt(payload), authority)
        except DROPManagementConflict as exc:
            raise DROPManagementIntegrityError("stored DSAR receipt is misbound") from exc
        if not created_at <= receipt.created_at <= updated_at:
            raise DROPManagementIntegrityError("stored DSAR receipt time is invalid")
        if status == "PENDING":
            if (
                revision != 1
                or outcome is not None
                or outcome_sha != ""
                or actor_binding != ""
                or reviewer_binding != ""
                or actor_ref != ""
                or actor_key_revision != 0
                or reviewer_key_revision != 0
            ):
                raise DROPManagementIntegrityError("stored pending DROP state is invalid")
            return authority, receipt, None
        if status not in TERMINAL_STATUSES or revision != 2:
            raise DROPManagementIntegrityError("stored terminal DROP state is invalid")
        evidence = self._outcome(payload)
        try:
            actor_sha256 = _digest(actor_binding, "status_actor_binding_sha256")
            reviewer_sha256 = _digest(reviewer_binding, "status_reviewer_binding_sha256")
            stored_actor_ref = _ref(actor_ref, "status_actor_ref")
            actor_revision = self._require_key_revision(actor_key_revision)
            reviewer_revision = self._require_key_revision(reviewer_key_revision)
        except DROPManagementError as exc:
            raise DROPManagementIntegrityError("stored DROP principal binding is invalid") from exc
        if (
            _same(actor_sha256, reviewer_sha256)
            or evidence.tenant_id != authority.tenant_id
            or evidence.drop_id != authority.drop_id
            or evidence.status != status
            or evidence.request_queue_id != receipt.request_queue_id
            or evidence.internal_case_id != receipt.internal_case_id
            or not _same(evidence.authority_sha256, authority.authority_sha256)
            or not receipt.created_at <= evidence.observed_at <= updated_at < evidence.valid_until
            or actor_revision < 1
            or not self._verify_principal_binding(
                stored_actor_ref,
                actor_revision,
                actor_sha256,
            )
            or not self._verify_principal_binding(
                evidence.reviewer_ref,
                reviewer_revision,
                reviewer_sha256,
            )
        ):
            raise DROPManagementIntegrityError("stored DROP outcome binding is invalid")
        if status == "DELETED" and not (
            authority.request_type == "DataDeletion"
            and evidence.deletion_verified
            and evidence.search_complete
            and evidence.provider_operations_complete
        ):
            raise DROPManagementIntegrityError("stored deletion outcome is invalid")
        if status == "OPTED_OUT" and not (
            authority.request_type == "OptOut"
            and evidence.opt_out_verified
            and evidence.provider_operations_complete
        ):
            raise DROPManagementIntegrityError("stored opt-out outcome is invalid")
        if status == "NOT_FOUND" and not evidence.search_complete:
            raise DROPManagementIntegrityError("stored not-found outcome is invalid")
        if status == "EXEMPTED" and not evidence.exemption_approved:
            raise DROPManagementIntegrityError("stored exemption outcome is invalid")
        return authority, receipt, evidence

    def verify_integrity(self) -> bool:  # noqa: C901 - complete closed-schema audit
        """Verify every mirror, payload, idempotency binding and audit link."""

        try:
            self._gate()
            with self._connect() as connection:
                meta = connection.execute("SELECT key,value FROM drop_meta ORDER BY key").fetchall()
                if (
                    len(meta) != 1
                    or meta[0]["key"] != "tenant_sha256"
                    or not _same(
                        meta[0]["value"],
                        _text_sha256(self.tenant_id),
                    )
                ):
                    return False
                triggers = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }
                if not _REQUIRED_TRIGGERS.issubset(triggers):
                    return False
                foreign = connection.execute(
                    "SELECT EXISTS(SELECT 1 FROM drop_requests WHERE tenant_id<>?) "
                    "OR EXISTS(SELECT 1 FROM drop_operations WHERE tenant_id<>?) "
                    "OR EXISTS(SELECT 1 FROM drop_audit WHERE tenant_id<>?)",
                    (self.tenant_id, self.tenant_id, self.tenant_id),
                ).fetchone()
                if foreign is None or int(foreign[0]) != 0:
                    return False
                requests = connection.execute(
                    "SELECT * FROM drop_requests WHERE tenant_id=? ORDER BY drop_id",
                    (self.tenant_id,),
                ).fetchall()
                operations = connection.execute(
                    "SELECT * FROM drop_operations WHERE tenant_id=? ORDER BY action,key_sha256",
                    (self.tenant_id,),
                ).fetchall()
                audits = connection.execute(
                    "SELECT * FROM drop_audit WHERE tenant_id=? ORDER BY drop_id,sequence",
                    (self.tenant_id,),
                ).fetchall()
            payloads: dict[tuple[str, int], dict[str, Any]] = {}
            for row in requests:
                payload = self._payload(row)
                self._validate_persisted_state(payload)
                key = (str(row["tenant_id"]), int(row["drop_id"]))
                if key in payloads:
                    return False
                payloads[key] = payload
            operations_by_request: dict[tuple[str, int], list[dict[str, object]]] = {}
            for row in operations:
                body = self._operation_body(row)
                key = (str(body["tenant_id"]), int(body["drop_id"]))
                _digest(body["key_sha256"], "operation key_sha256")
                _digest(body["request_sha256"], "operation request_sha256")
                _digest(row["integrity_sha256"], "operation integrity_sha256")
                if (
                    not _same(_sha256(body), row["integrity_sha256"])
                    or key not in payloads
                    or body["action"] not in {"create", "update_status"}
                    or _timestamp(body["created_at"], "operation created_at") <= 0
                ):
                    return False
                operations_by_request.setdefault(key, []).append(body)
            previous: dict[tuple[str, int], str] = {}
            sequence: dict[tuple[str, int], int] = {}
            audits_by_request: dict[tuple[str, int], list[dict[str, object]]] = {}
            for row in audits:
                key = (str(row["tenant_id"]), int(row["drop_id"]))
                expected_sequence = sequence.get(key, 0) + 1
                body = {
                    "tenant_id": key[0],
                    "drop_id": key[1],
                    "sequence": int(row["sequence"]),
                    "event_type": str(row["event_type"]),
                    "event_payload_sha256": str(row["event_payload_sha256"]),
                    "previous_sha256": str(row["previous_sha256"]),
                    "created_at": float(row["created_at"]),
                }
                if (
                    key not in payloads
                    or body["sequence"] != expected_sequence
                    or body["previous_sha256"] != previous.get(key, "0" * 64)
                    or not _same(_sha256(body), row["event_sha256"])
                ):
                    return False
                _digest(body["event_payload_sha256"], "event_payload_sha256")
                _digest(row["event_sha256"], "event_sha256")
                _timestamp(body["created_at"], "audit created_at")
                sequence[key] = expected_sequence
                previous[key] = str(row["event_sha256"])
                audits_by_request.setdefault(key, []).append(body)
            for key, payload in payloads.items():
                request_operations = operations_by_request.get(key, [])
                create_operations = [
                    item for item in request_operations if item["action"] == "create"
                ]
                update_operations = [
                    item for item in request_operations if item["action"] == "update_status"
                ]
                if len(create_operations) != 1:
                    return False
                create_operation = create_operations[0]
                if (
                    not _same(
                        create_operation["key_sha256"],
                        payload["operation_key_sha256"],
                    )
                    or not _same(create_operation["request_sha256"], payload["request_sha256"])
                    or create_operation["created_at"] != payload["created_at"]
                ):
                    return False
                request_audits = audits_by_request.get(key, [])
                if payload["state"] == "creating":
                    if update_operations or request_audits:
                        return False
                    continue
                receipt = self._receipt(payload)
                if (
                    not request_audits
                    or request_audits[0]["event_type"] != "DROP_REQUEST_CREATED"
                    or not _same(
                        request_audits[0]["event_payload_sha256"],
                        receipt.receipt_sha256,
                    )
                    or not receipt.created_at
                    <= request_audits[0]["created_at"]
                    <= payload["updated_at"]
                ):
                    return False
                if payload["status"] == "PENDING":
                    if update_operations or len(request_audits) != 1:
                        return False
                    continue
                if len(update_operations) != 1 or len(request_audits) != 2:
                    return False
                expected_update_sha256 = _sha256(
                    {
                        "action": "update_drop_status",
                        "authority_sha256": payload["authority_sha256"],
                        "status": payload["status"],
                        "expected_revision": int(payload["revision"]) - 1,
                        "actor_binding_sha256": payload["status_actor_binding_sha256"],
                        "actor_key_revision": payload["status_actor_key_revision"],
                    }
                )
                if (
                    not _same(update_operations[0]["request_sha256"], expected_update_sha256)
                    or update_operations[0]["created_at"] != payload["updated_at"]
                    or request_audits[1]["event_type"] != "DROP_STATUS_UPDATED"
                    or request_audits[1]["created_at"] != payload["updated_at"]
                    or not _same(
                        request_audits[1]["event_payload_sha256"],
                        payload["outcome_evidence_sha256"],
                    )
                ):
                    return False
            return True
        except (DROPManagementError, KeyError, TypeError, ValueError, sqlite3.Error):
            return False

    def purge_expired(self, *, before: float | None = None, limit: int = 100) -> int:
        """Delete an expired request and all of its minimized local bindings."""

        self._gate()
        try:
            maintenance_authorized = self._maintenance_authorizer()
        except Exception as exc:
            raise DROPManagementConfigError("DROP maintenance authority is unavailable") from exc
        if maintenance_authorized is not True:
            raise DROPManagementConfigError("DROP maintenance authority is unavailable")
        if not self.verify_integrity():
            raise DROPManagementIntegrityError("DROP integrity must pass before retention purge")
        now = self._now()
        cutoff = now if before is None else min(now, _timestamp(before, "before"))
        bounded = _integer(limit, "limit", 1, 1_000)
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM drop_requests WHERE tenant_id=? AND retained_until<=? "
                "ORDER BY retained_until,drop_id LIMIT ?",
                (self.tenant_id, cutoff, bounded),
            ).fetchall()
            for row in rows:
                payload = self._payload(row)
                self._validate_persisted_state(payload)
            self._maintenance.authorized = True
            try:
                for row in rows:
                    key = (self.tenant_id, int(row["drop_id"]))
                    connection.execute(
                        "DELETE FROM drop_audit WHERE tenant_id=? AND drop_id=?", key
                    )
                    connection.execute(
                        "DELETE FROM drop_operations WHERE tenant_id=? AND drop_id=?", key
                    )
                    connection.execute(
                        "DELETE FROM drop_requests WHERE tenant_id=? AND drop_id=?", key
                    )
                connection.commit()
            finally:
                self._maintenance.authorized = False
        return len(rows)

    def retained_key_revision_counts(self) -> Mapping[int, int]:
        """Count retained management records by principal-key revision."""

        self._gate()
        now = self._now()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM drop_requests WHERE tenant_id=? AND retained_until>? "
                "ORDER BY drop_id",
                (self.tenant_id, now),
            ).fetchall()
        counts: dict[int, int] = {}
        for row in rows:
            payload = self._payload(row)
            self._validate_persisted_state(payload)
            revisions = [int(payload["principal_key_revision"])]
            if int(payload["status_actor_key_revision"]):
                revisions.extend(
                    (
                        int(payload["status_actor_key_revision"]),
                        int(payload["status_reviewer_key_revision"]),
                    )
                )
            for revision in revisions:
                counts[revision] = counts.get(revision, 0) + 1
        return counts

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "local_control_plane": True,
            "network_io": NETWORK_IO,
            "live_drop_interoperability_verified": LIVE_DROP_INTEROPERABILITY_VERIFIED,
            "legal_acceptance_verified": LEGAL_ACCEPTANCE_VERIFIED,
            "raw_names_or_email_persisted": False,
            "attachments_persisted": False,
            "retrieved_subject_data_persisted": False,
            "provider_credentials_persisted": False,
            "independent_record_authority_required": True,
            "independent_terminal_outcome_evidence_required": True,
            "permanent_external_effect_claimed": False,
        }


__all__ = [
    "DROP_STATUSES",
    "LEGAL_ACCEPTANCE_VERIFIED",
    "LIVE_DROP_INTEROPERABILITY_VERIFIED",
    "NETWORK_IO",
    "REQUEST_TYPES",
    "TERMINAL_STATUSES",
    "DROPDSARReceipt",
    "DROPManagementConfigError",
    "DROPManagementConflict",
    "DROPManagementError",
    "DROPManagementIntegrityError",
    "DROPManagementNotFound",
    "DROPManagementStore",
    "DROPManagementValidationError",
    "DROPPrincipalBinding",
    "DROPRecordAuthority",
    "DROPRequestRecord",
    "DROPStatusEvidence",
    "enabled",
    "require_enabled",
]
