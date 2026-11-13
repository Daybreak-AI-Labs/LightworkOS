"""Local governance authority for privacy-notice releases and updates.

Notice content and consent-delivery implementation stay outside this module.
Releases bind only SHA-256 digests and an opaque reference to an existing
consent publication.  Publication, rollback, and withdrawal are durable local
intent records; this module performs no network I/O, SDK deployment, or site
mutation.

The capability is closed unless both exact gates are explicitly enabled::

    [privacy_automation]
    enable = true
    [privacy_automation.notice_governance]
    enable = true
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
AUDIT_SCHEMA = "lightwork.privacy-notice-governance-audit.v1"
EXPORT_SCHEMA = "lightwork.privacy-notice-governance-export.v1"
LIVE_PROVIDER_WRITES = False
LIVE_ACCEPTANCE_VERIFIED = False

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_KEY_REF_RE = re.compile(
    r"(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}\Z"
)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_LOCALE_RE = re.compile(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}\Z")
_JURISDICTION_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_ERROR_RE = re.compile(r"[a-z][a-z0-9_]{0,47}\Z")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_SELECTIONS = 64
_MAX_CITATIONS = 64
_MAX_REASON_CODES = 64
_MAX_LIST = 1_000
_MAX_LEASE_SECONDS = 3_600
_MAX_BACKOFF_SECONDS = 7 * 24 * 3_600
_MIN_RETENTION_SECONDS = 60
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600

APPROVAL_ROLES = frozenset({"privacy", "legal", "brand", "accessibility"})
RELEASE_STATES = frozenset(
    {
        "draft",
        "review",
        "approved",
        "scheduled",
        "published",
        "rolled_back",
        "withdrawn",
    }
)
INTENT_ACTIONS = frozenset({"publish", "rollback", "withdraw"})
INTENT_STATES = frozenset({"pending", "leased", "acked", "dead_letter", "cancelled"})
PROPOSAL_DECISIONS = frozenset({"approved", "rejected"})


class PrivacyNoticeGovernanceError(RuntimeError):
    """Base privacy-notice governance error."""


class PrivacyNoticeConfigError(PrivacyNoticeGovernanceError):
    """The exact two-level feature gate is not enabled."""


class PrivacyNoticeValidationError(PrivacyNoticeGovernanceError, ValueError):
    """Input is outside the closed and bounded notice contract."""


class PrivacyNoticeConflict(PrivacyNoticeGovernanceError):
    """A CAS, state, lease, or idempotency precondition failed."""


class PrivacyNoticeNotFound(PrivacyNoticeGovernanceError):
    """A tenant-scoped record is absent or deliberately undisclosed."""


class PrivacyNoticePermissionDenied(PrivacyNoticeGovernanceError):
    """Authentication or independent-authorization separation is insufficient."""


class PrivacyNoticeIntegrityError(PrivacyNoticeGovernanceError):
    """Persisted content, signature, or audit chain failed verification."""


def enabled() -> bool:
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
    notice = (
        privacy.get("notice_governance") if isinstance(privacy, Mapping) else None
    )
    return (
        isinstance(privacy, Mapping)
        and privacy.get("enable") is True
        and isinstance(notice, Mapping)
        and notice.get("enable") is True
    )


def require_enabled() -> None:
    if not enabled():
        raise PrivacyNoticeConfigError(
            "privacy notice governance is disabled; explicitly enable "
            "privacy_automation and privacy_automation.notice_governance"
        )


def _runtime_principal() -> str | None:
    try:
        from .connections import current_principal

        return current_principal()
    except Exception:
        return None


def _default_lease_token() -> str:
    return f"lease:{secrets.token_urlsafe(32)}"


def _default_signing_key_resolver(tenant_id: str, key_ref: str) -> bytes:
    del tenant_id
    if not key_ref.startswith("env:"):
        raise PrivacyNoticeConfigError(
            "the default signing resolver accepts only env: references"
        )
    value = os.environ.get(key_ref.removeprefix("env:"))
    if value is None or len(value.encode()) < 32:
        raise PrivacyNoticeConfigError(
            "privacy-notice signing key is absent or shorter than 32 bytes"
        )
    return value.encode()


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
        raise PrivacyNoticeValidationError(
            "notice governance state must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise PrivacyNoticeValidationError(
            "notice governance state exceeds its canonical byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise PrivacyNoticeValidationError("tenant_id is invalid") from exc


def _id(
    value: object,
    label: str,
    pattern: re.Pattern[str] = _ID_RE,
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PrivacyNoticeValidationError(
            f"{label} must be a bounded opaque identifier"
        )
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise PrivacyNoticeValidationError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise PrivacyNoticeValidationError(
            f"{label} must be an integer between {minimum} and {maximum}"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise PrivacyNoticeValidationError(
            f"{label} must be a positive finite timestamp"
        )
    return float(value)


def _retained_until(value: object, now: float) -> float:
    retained = _timestamp(value, "retained_until")
    if not _MIN_RETENTION_SECONDS <= retained - now <= _MAX_RETENTION_SECONDS:
        raise PrivacyNoticeValidationError(
            "retained_until must be between 60 seconds and 10 years from now"
        )
    return retained


def _selection(
    value: object,
    label: str,
    pattern: re.Pattern[str],
) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise PrivacyNoticeValidationError(f"{label} must be a sequence")
    items = tuple(value)
    if not 1 <= len(items) <= _MAX_SELECTIONS:
        raise PrivacyNoticeValidationError(f"{label} has an invalid item count")
    if any(not isinstance(item, str) or not pattern.fullmatch(item) for item in items):
        raise PrivacyNoticeValidationError(f"{label} contains an unsupported value")
    if len(set(items)) != len(items):
        raise PrivacyNoticeValidationError(f"{label} must not contain duplicates")
    return tuple(sorted(items))


def _id_sequence(
    value: object,
    label: str,
    *,
    maximum: int,
    minimum: int = 0,
) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise PrivacyNoticeValidationError(f"{label} must be a sequence")
    items = tuple(_id(item, f"{label} item") for item in value)
    if not minimum <= len(items) <= maximum or len(set(items)) != len(items):
        raise PrivacyNoticeValidationError(f"{label} has invalid or duplicate items")
    return tuple(sorted(items))


@dataclass(frozen=True)
class ApprovalPolicy:
    tenant_id: str
    policy_id: str
    required_roles: tuple[str, ...]
    quorum: int
    approval_ttl_seconds: int
    revision: int
    created_by: str
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class NoticeRelease:
    tenant_id: str
    notice_id: str
    version: int
    property_id: str
    jurisdictions: tuple[str, ...]
    locales: tuple[str, ...]
    policy_sha256: str
    content_sha256: str
    configuration_sha256: str
    consent_publication_ref: str
    approval_policy_id: str
    approval_policy_sha256: str
    required_roles: tuple[str, ...]
    quorum: int
    approval_ttl_seconds: int
    effective_from: float
    effective_until: float
    retained_until: float
    update_proposal_ref: str | None
    definition_sha256: str
    state: str
    activate_at: float | None
    created_by: str
    approved_digest_sha256: str | None
    rollback_target_version: int | None
    state_revision: int
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class NoticeApproval:
    tenant_id: str
    notice_id: str
    release_version: int
    role: str
    actor_ref: str
    release_sha256: str
    approved_at: float
    expires_at: float
    revoked_at: float | None
    revision: int
    integrity_sha256: str


@dataclass(frozen=True)
class PublicationIntent:
    tenant_id: str
    intent_id: str
    notice_id: str
    release_version: int
    action: str
    target_version: int | None
    release_sha256: str
    consent_publication_ref: str
    state: str
    attempts: int
    max_attempts: int
    recovery_count: int
    next_attempt_at: float
    lease_owner: str | None
    lease_token: str | None
    lease_until: float | None
    last_error_code: str | None
    acknowledgement_sha256: str | None
    acknowledgement_ref: str | None
    revision: int
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class NoticeUpdateProposal:
    tenant_id: str
    proposal_id: str
    notice_id: str
    base_version: int
    policy_sha256: str
    content_sha256: str
    configuration_sha256: str
    consent_publication_ref: str
    regulatory_citations: tuple[Mapping[str, str], ...]
    reason_codes: tuple[str, ...]
    status: str
    retained_until: float
    created_by: str
    reviewed_by: str | None
    revision: int
    created_at: float
    reviewed_at: float | None
    integrity_sha256: str


@dataclass(frozen=True)
class SignedNoticeExport:
    tenant_id: str
    export_id: str
    notice_id: str
    schema: str
    body: Mapping[str, object]
    body_sha256: str
    signing_key_ref: str
    signature_hmac_sha256: str
    retained_until: float
    created_by: str
    created_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class IntegrityVerification:
    tenant_id: str
    verified_records: int
    audit_events: int
    terminal_audit_sha256: str


class PrivacyNoticeGovernanceStore:
    """Private SQLite authority for notice versioning and publication intent."""

    def __init__(
        self,
        path: str | Path,
        *,
        config_gate: Callable[[], None] = require_enabled,
        principal_resolver: Callable[[], str | None] = _runtime_principal,
        signing_key_resolver: Callable[[str, str], bytes] = _default_signing_key_resolver,
        regulatory_reference_resolver: Callable[[str, str, str, str], bool]
        | None = None,
        clock: Callable[[], float] = time.time,
        token_factory: Callable[[], str] = _default_lease_token,
    ) -> None:
        config_gate()
        self.path = Path(path)
        self._principal_resolver = principal_resolver
        self._signing_key_resolver = signing_key_resolver
        self._regulatory_reference_resolver = regulatory_reference_resolver
        self._clock = clock
        self._token_factory = token_factory
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _actor(self) -> str:
        actor = self._principal_resolver()
        if actor is None or actor == "":
            raise PrivacyNoticePermissionDenied(
                "an authenticated runtime principal is required"
            )
        return _id(actor, "authenticated principal")

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
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS notice_approval_policies(
                    tenant_id TEXT NOT NULL,policy_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,policy_id)
                );
                CREATE TABLE IF NOT EXISTS notice_release_definitions(
                    tenant_id TEXT NOT NULL,notice_id TEXT NOT NULL,version INTEGER NOT NULL,
                    property_id TEXT NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,notice_id,version)
                );
                CREATE TABLE IF NOT EXISTS notice_release_states(
                    tenant_id TEXT NOT NULL,notice_id TEXT NOT NULL,version INTEGER NOT NULL,
                    state TEXT NOT NULL,activate_at REAL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,notice_id,version),
                    FOREIGN KEY(tenant_id,notice_id,version)
                        REFERENCES notice_release_definitions(tenant_id,notice_id,version)
                            ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS notice_effective_release
                    ON notice_release_states(tenant_id,state,activate_at);
                CREATE TABLE IF NOT EXISTS notice_approvals(
                    tenant_id TEXT NOT NULL,notice_id TEXT NOT NULL,
                    release_version INTEGER NOT NULL,role TEXT NOT NULL,
                    actor_ref TEXT NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,notice_id,release_version,role),
                    UNIQUE(tenant_id,notice_id,release_version,actor_ref),
                    FOREIGN KEY(tenant_id,notice_id,release_version)
                        REFERENCES notice_release_definitions(tenant_id,notice_id,version)
                            ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS notice_publication_intents(
                    tenant_id TEXT NOT NULL,intent_id TEXT NOT NULL,notice_id TEXT NOT NULL,
                    release_version INTEGER NOT NULL,action TEXT NOT NULL,state TEXT NOT NULL,
                    next_attempt_at REAL NOT NULL,lease_until REAL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,intent_id),
                    FOREIGN KEY(tenant_id,notice_id,release_version)
                        REFERENCES notice_release_definitions(tenant_id,notice_id,version)
                            ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS notice_intent_claim
                    ON notice_publication_intents(
                        tenant_id,state,next_attempt_at,lease_until
                    );
                CREATE TABLE IF NOT EXISTS notice_update_proposals(
                    tenant_id TEXT NOT NULL,proposal_id TEXT NOT NULL,notice_id TEXT NOT NULL,
                    status TEXT NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,proposal_id)
                );
                CREATE INDEX IF NOT EXISTS notice_proposal_retention
                    ON notice_update_proposals(tenant_id,retained_until);
                CREATE TABLE IF NOT EXISTS notice_exports(
                    tenant_id TEXT NOT NULL,export_id TEXT NOT NULL,notice_id TEXT NOT NULL,
                    retained_until REAL NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,export_id)
                );
                CREATE INDEX IF NOT EXISTS notice_export_retention
                    ON notice_exports(tenant_id,retained_until);
                CREATE TABLE IF NOT EXISTS notice_operations(
                    tenant_id TEXT NOT NULL,operation_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_kind TEXT NOT NULL,
                    result_id TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,operation_sha256)
                );
                CREATE TABLE IF NOT EXISTS notice_audit_events(
                    tenant_id TEXT NOT NULL,sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS notice_release_no_update
                    BEFORE UPDATE ON notice_release_definitions
                    BEGIN SELECT RAISE(ABORT, 'immutable notice release definition'); END;
                CREATE TRIGGER IF NOT EXISTS notice_release_guarded_delete
                    BEFORE DELETE ON notice_release_definitions
                    WHEN EXISTS(
                        SELECT 1 FROM notice_release_states
                        WHERE tenant_id=OLD.tenant_id AND notice_id=OLD.notice_id
                            AND version=OLD.version
                    )
                    BEGIN SELECT RAISE(ABORT, 'notice release state must purge first'); END;
                CREATE TRIGGER IF NOT EXISTS notice_audit_no_update
                    BEFORE UPDATE ON notice_audit_events
                    BEGIN SELECT RAISE(ABORT, 'immutable notice audit'); END;
                CREATE TRIGGER IF NOT EXISTS notice_audit_no_delete
                    BEFORE DELETE ON notice_audit_events
                    BEGIN SELECT RAISE(ABORT, 'immutable notice audit'); END;
                INSERT OR IGNORE INTO metadata(key,value) VALUES('schema_version','1');
                COMMIT;
                """
            )
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if version is None or version["value"] != str(SCHEMA_VERSION):
                raise PrivacyNoticeIntegrityError(
                    "privacy notice governance database schema is unsupported"
                )
        ensure_private_file(self.path)

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _payload(row: sqlite3.Row, label: str, tenant: str) -> dict[str, Any]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise PrivacyNoticeIntegrityError(
                f"persisted {label} is not canonical JSON"
            ) from exc
        if (
            not isinstance(payload, dict)
            or _sha256(payload) != row["integrity_sha256"]
            or row["tenant_id"] != tenant
            or payload.get("tenant_id") != tenant
        ):
            raise PrivacyNoticeIntegrityError(
                f"persisted {label} failed tenant or content integrity"
            )
        return payload

    @staticmethod
    def _insert(
        connection: sqlite3.Connection,
        table: str,
        columns: tuple[str, ...],
        indexes: tuple[object, ...],
        payload: Mapping[str, object],
    ) -> str:
        digest = _sha256(dict(payload))
        names = ",".join(columns + ("payload_json", "integrity_sha256"))
        placeholders = ",".join("?" for _ in range(len(columns) + 2))
        connection.execute(
            f"INSERT INTO {table}({names}) VALUES({placeholders})",  # noqa: S608
            indexes + (_canonical(dict(payload)).decode("ascii"), digest),
        )
        return digest

    @staticmethod
    def _write(
        connection: sqlite3.Connection,
        table: str,
        tenant: str,
        id_column: str,
        object_id: str,
        payload: Mapping[str, object],
        *,
        version: int | None = None,
        index_updates: Mapping[str, object] | None = None,
    ) -> str:
        digest = _sha256(dict(payload))
        assignments = ["payload_json=?", "integrity_sha256=?"]
        values: list[object] = [_canonical(dict(payload)).decode("ascii"), digest]
        for column, value in (index_updates or {}).items():
            assignments.append(f"{column}=?")
            values.append(value)
        where = f"tenant_id=? AND {id_column}=?"
        values.extend((tenant, object_id))
        if version is not None:
            where += " AND version=?" if table == "notice_release_states" else " AND release_version=?"
            values.append(version)
        result = connection.execute(
            f"UPDATE {table} SET {','.join(assignments)} WHERE {where}",  # noqa: S608
            tuple(values),
        )
        if result.rowcount != 1:
            raise PrivacyNoticeNotFound(f"{table} record was not found")
        return digest

    @staticmethod
    def _get(
        connection: sqlite3.Connection,
        table: str,
        tenant: str,
        id_column: str,
        object_id: str,
        label: str,
        *,
        version: int | None = None,
    ) -> tuple[dict[str, Any], str]:
        where = f"tenant_id=? AND {id_column}=?"
        values: list[object] = [tenant, object_id]
        if version is not None:
            version_column = "version" if table in {
                "notice_release_definitions",
                "notice_release_states",
            } else "release_version"
            where += f" AND {version_column}=?"
            values.append(version)
        row = connection.execute(
            f"SELECT * FROM {table} WHERE {where}",  # noqa: S608
            tuple(values),
        ).fetchone()
        if row is None:
            raise PrivacyNoticeNotFound(f"{label} was not found")
        return PrivacyNoticeGovernanceStore._payload(row, label, tenant), row[
            "integrity_sha256"
        ]

    @staticmethod
    def _operation(
        connection: sqlite3.Connection,
        tenant: str,
        idempotency_key: str,
        request: Mapping[str, object],
    ) -> tuple[str, sqlite3.Row | None]:
        key = _id(idempotency_key, "idempotency_key", _OP_RE)
        operation_sha = hashlib.sha256(key.encode()).hexdigest()
        request_sha = _sha256(dict(request))
        row = connection.execute(
            "SELECT * FROM notice_operations WHERE tenant_id=? AND operation_sha256=?",
            (tenant, operation_sha),
        ).fetchone()
        if row is not None:
            binding = {
                "tenant_id": row["tenant_id"],
                "operation_sha256": row["operation_sha256"],
                "request_sha256": row["request_sha256"],
                "result_kind": row["result_kind"],
                "result_id": row["result_id"],
            }
            if _sha256(binding) != row["integrity_sha256"]:
                raise PrivacyNoticeIntegrityError(
                    "persisted idempotency binding failed integrity verification"
                )
            if row["request_sha256"] != request_sha:
                raise PrivacyNoticeConflict(
                    "idempotency key is bound to different canonical content"
                )
        return request_sha, row

    @staticmethod
    def _record_operation(
        connection: sqlite3.Connection,
        tenant: str,
        idempotency_key: str,
        request_sha: str,
        result_kind: str,
        result_id: str,
    ) -> None:
        binding = {
            "tenant_id": tenant,
            "operation_sha256": hashlib.sha256(idempotency_key.encode()).hexdigest(),
            "request_sha256": request_sha,
            "result_kind": _id(result_kind, "result_kind"),
            "result_id": _id(result_id, "result_id"),
        }
        connection.execute(
            "INSERT INTO notice_operations VALUES(?,?,?,?,?,?)",
            (
                tenant,
                binding["operation_sha256"],
                request_sha,
                binding["result_kind"],
                binding["result_id"],
                _sha256(binding),
            ),
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        action: str,
        subject: str,
        actor: str,
        details: Mapping[str, object],
        now: float,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM notice_audit_events "
            "WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
            (tenant,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = "0" * 64 if previous is None else previous["integrity_sha256"]
        payload = {
            "schema": AUDIT_SCHEMA,
            "tenant_id": tenant,
            "sequence": sequence,
            "action": _id(action, "audit action"),
            "subject_sha256": hashlib.sha256(subject.encode()).hexdigest(),
            "actor_ref": actor,
            "details": dict(details),
            "occurred_at": now,
            "previous_sha256": previous_sha,
        }
        digest = _sha256(payload)
        connection.execute(
            "INSERT INTO notice_audit_events VALUES(?,?,?,?)",
            (tenant, sequence, _canonical(payload).decode("ascii"), digest),
        )

    @staticmethod
    def _policy(payload: Mapping[str, Any], digest: str) -> ApprovalPolicy:
        values = dict(payload)
        values["required_roles"] = tuple(values["required_roles"])
        return ApprovalPolicy(**values, integrity_sha256=digest)

    @staticmethod
    def _approval(payload: Mapping[str, Any], digest: str) -> NoticeApproval:
        return NoticeApproval(**dict(payload), integrity_sha256=digest)

    @staticmethod
    def _intent(payload: Mapping[str, Any], digest: str) -> PublicationIntent:
        return PublicationIntent(**dict(payload), integrity_sha256=digest)

    @staticmethod
    def _proposal(
        payload: Mapping[str, Any], digest: str
    ) -> NoticeUpdateProposal:
        values = dict(payload)
        values["regulatory_citations"] = tuple(
            dict(item) for item in values["regulatory_citations"]
        )
        values["reason_codes"] = tuple(values["reason_codes"])
        return NoticeUpdateProposal(**values, integrity_sha256=digest)

    @staticmethod
    def _export(payload: Mapping[str, Any], digest: str) -> SignedNoticeExport:
        values = dict(payload)
        values["body"] = dict(values["body"])
        return SignedNoticeExport(**values, integrity_sha256=digest)

    def _release(
        self,
        definition: Mapping[str, Any],
        state: Mapping[str, Any],
        definition_digest: str,
        state_digest: str,
    ) -> NoticeRelease:
        return NoticeRelease(
            tenant_id=definition["tenant_id"],
            notice_id=definition["notice_id"],
            version=definition["version"],
            property_id=definition["property_id"],
            jurisdictions=tuple(definition["jurisdictions"]),
            locales=tuple(definition["locales"]),
            policy_sha256=definition["policy_sha256"],
            content_sha256=definition["content_sha256"],
            configuration_sha256=definition["configuration_sha256"],
            consent_publication_ref=definition["consent_publication_ref"],
            approval_policy_id=definition["approval_policy_id"],
            approval_policy_sha256=definition["approval_policy_sha256"],
            required_roles=tuple(definition["required_roles"]),
            quorum=definition["quorum"],
            approval_ttl_seconds=definition["approval_ttl_seconds"],
            effective_from=definition["effective_from"],
            effective_until=definition["effective_until"],
            retained_until=definition["retained_until"],
            update_proposal_ref=definition["update_proposal_ref"],
            definition_sha256=definition_digest,
            state=state["state"],
            activate_at=state["activate_at"],
            created_by=definition["created_by"],
            approved_digest_sha256=state["approved_digest_sha256"],
            rollback_target_version=state["rollback_target_version"],
            state_revision=state["revision"],
            created_at=definition["created_at"],
            updated_at=state["updated_at"],
            integrity_sha256=_sha256(
                {
                    "definition_sha256": definition_digest,
                    "state_sha256": state_digest,
                }
            ),
        )

    def _get_release(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        notice_id: str,
        version: int,
    ) -> NoticeRelease:
        definition, definition_digest = self._get(
            connection,
            "notice_release_definitions",
            tenant,
            "notice_id",
            notice_id,
            "notice release definition",
            version=version,
        )
        state, state_digest = self._get(
            connection,
            "notice_release_states",
            tenant,
            "notice_id",
            notice_id,
            "notice release state",
            version=version,
        )
        if state["definition_sha256"] != definition_digest:
            raise PrivacyNoticeIntegrityError(
                "notice release state is not bound to its immutable definition"
            )
        return self._release(definition, state, definition_digest, state_digest)

    def list_records(self, tenant_id: str, *, limit: int = 200) -> dict[str, tuple]:
        """Read-only listing of approval policies, releases (newest version
        first), approvals, update proposals, exports and publication-queue
        items for one tenant, each loaded through the integrity-checked
        readers. Lease tokens are never part of the listing."""

        tenant = _tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, _MAX_LIST)
        self._actor()
        with self._connect() as connection:
            def rows(sql: str) -> list[sqlite3.Row]:
                return connection.execute(sql, (tenant, bounded)).fetchall()

            policies = tuple(
                self._policy(self._payload(row, "approval policy", tenant), row["integrity_sha256"])
                for row in rows(
                    "SELECT * FROM notice_approval_policies WHERE tenant_id=? "
                    "ORDER BY policy_id LIMIT ?"
                )
            )
            releases = tuple(
                self._get_release(connection, tenant, row["notice_id"], int(row["version"]))
                for row in rows(
                    "SELECT notice_id, version FROM notice_release_definitions "
                    "WHERE tenant_id=? ORDER BY notice_id, version DESC LIMIT ?"
                )
            )
            approvals = tuple(
                self._approval(self._payload(row, "notice approval", tenant), row["integrity_sha256"])
                for row in rows(
                    "SELECT * FROM notice_approvals WHERE tenant_id=? "
                    "ORDER BY notice_id, release_version, role LIMIT ?"
                )
            )
            proposals = tuple(
                self._proposal(self._payload(row, "update proposal", tenant), row["integrity_sha256"])
                for row in rows(
                    "SELECT * FROM notice_update_proposals WHERE tenant_id=? "
                    "ORDER BY rowid DESC LIMIT ?"
                )
            )
            exports = tuple(
                self._export(self._payload(row, "notice export", tenant), row["integrity_sha256"])
                for row in rows(
                    "SELECT * FROM notice_exports WHERE tenant_id=? ORDER BY rowid DESC LIMIT ?"
                )
            )
            queue = {
                str(state): int(count)
                for state, count in connection.execute(
                    "SELECT state, COUNT(*) FROM notice_publication_intents "
                    "WHERE tenant_id=? GROUP BY state",
                    (tenant,),
                ).fetchall()
            }
        return {
            "policies": policies,
            "releases": releases,
            "approvals": approvals,
            "proposals": proposals,
            "exports": exports,
            "queue": queue,
        }

    def set_approval_policy(
        self,
        tenant_id: str,
        policy_id: str,
        *,
        required_roles: Sequence[str],
        quorum: int,
        approval_ttl_seconds: int,
        expected_revision: int,
        idempotency_key: str,
    ) -> ApprovalPolicy:
        tenant = _tenant(tenant_id)
        policy_key = _id(policy_id, "policy_id")
        roles = _id_sequence(
            required_roles,
            "required_roles",
            minimum=1,
            maximum=len(APPROVAL_ROLES),
        )
        if not set(roles).issubset(APPROVAL_ROLES):
            raise PrivacyNoticeValidationError("required_roles contains an unknown role")
        quorum_value = _integer(quorum, "quorum", 1, len(APPROVAL_ROLES))
        if quorum_value < len(roles):
            raise PrivacyNoticeValidationError(
                "quorum cannot be smaller than the required role count"
            )
        ttl = _integer(approval_ttl_seconds, "approval_ttl_seconds", 60, 365 * 24 * 3_600)
        expected = _integer(expected_revision, "expected_revision", 0, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "set_approval_policy",
            "policy_id": policy_key,
            "required_roles": list(roles),
            "quorum": quorum_value,
            "approval_ttl_seconds": ttl,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            row = connection.execute(
                "SELECT * FROM notice_approval_policies WHERE tenant_id=? AND policy_id=?",
                (tenant, policy_key),
            ).fetchone()
            if operation is not None:
                if row is None:
                    raise PrivacyNoticeIntegrityError("approval policy result is missing")
                return self._policy(
                    self._payload(row, "approval policy", tenant), row["integrity_sha256"]
                )
            current_revision = 0
            current: dict[str, Any] | None = None
            if row is not None:
                current = self._payload(row, "approval policy", tenant)
                current_revision = int(current["revision"])
            if current_revision != expected:
                raise PrivacyNoticeConflict(
                    f"approval policy CAS failed: expected {expected}, found {current_revision}"
                )
            payload = {
                "tenant_id": tenant,
                "policy_id": policy_key,
                "required_roles": list(roles),
                "quorum": quorum_value,
                "approval_ttl_seconds": ttl,
                "revision": expected + 1,
                "created_by": actor if current is None else current["created_by"],
                "created_at": now if current is None else current["created_at"],
                "updated_at": now,
            }
            if row is None:
                digest_value = self._insert(
                    connection,
                    "notice_approval_policies",
                    ("tenant_id", "policy_id"),
                    (tenant, policy_key),
                    payload,
                )
            else:
                digest_value = self._write(
                    connection,
                    "notice_approval_policies",
                    tenant,
                    "policy_id",
                    policy_key,
                    payload,
                )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "policy", policy_key
            )
            self._audit(
                connection,
                tenant,
                "approval_policy_set",
                policy_key,
                actor,
                {"revision": expected + 1, "quorum": quorum_value},
                now,
            )
            return self._policy(payload, digest_value)

    def get_approval_policy(self, tenant_id: str, policy_id: str) -> ApprovalPolicy:
        tenant = _tenant(tenant_id)
        policy_key = _id(policy_id, "policy_id")
        self._actor()
        with self._connect() as connection:
            payload, digest_value = self._get(
                connection,
                "notice_approval_policies",
                tenant,
                "policy_id",
                policy_key,
                "approval policy",
            )
            return self._policy(payload, digest_value)

    def create_release(
        self,
        tenant_id: str,
        notice_id: str,
        *,
        property_id: str,
        jurisdictions: Sequence[str],
        locales: Sequence[str],
        policy_sha256: str,
        content_sha256: str,
        configuration_sha256: str,
        consent_publication_ref: str,
        approval_policy_id: str,
        effective_from: float,
        effective_until: float,
        retained_until: float,
        update_proposal_ref: str | None = None,
        expected_latest_version: int,
        idempotency_key: str,
        before_write: Callable[[sqlite3.Connection, NoticeUpdateProposal | None], None] | None = None,
    ) -> NoticeRelease:
        """Append an immutable content-free notice release definition."""

        tenant = _tenant(tenant_id)
        notice = _id(notice_id, "notice_id")
        property_key = _id(property_id, "property_id")
        jurisdiction_values = _selection(
            jurisdictions, "jurisdictions", _JURISDICTION_RE
        )
        locale_values = _selection(locales, "locales", _LOCALE_RE)
        policy_digest = _digest(policy_sha256, "policy_sha256")
        content_digest = _digest(content_sha256, "content_sha256")
        configuration_digest = _digest(
            configuration_sha256, "configuration_sha256"
        )
        consent_ref = _id(consent_publication_ref, "consent_publication_ref")
        policy_key = _id(approval_policy_id, "approval_policy_id")
        proposal_ref = (
            None
            if update_proposal_ref is None
            else _id(update_proposal_ref, "update_proposal_ref")
        )
        expected = _integer(
            expected_latest_version, "expected_latest_version", 0, 1_000_000
        )
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        start = _timestamp(effective_from, "effective_from")
        end = _timestamp(effective_until, "effective_until")
        if end <= start:
            raise PrivacyNoticeValidationError(
                "effective_until must be later than effective_from"
            )
        retained = _retained_until(retained_until, now)
        if retained < end:
            raise PrivacyNoticeValidationError(
                "release retention cannot end before its effective window"
            )
        version = expected + 1
        with self._connect() as connection:
            self._begin(connection)
            policy_raw, policy_integrity = self._get(
                connection,
                "notice_approval_policies",
                tenant,
                "policy_id",
                policy_key,
                "approval policy",
            )
            policy = self._policy(policy_raw, policy_integrity)
            proposal = None
            if proposal_ref is not None:
                proposal_raw, proposal_digest = self._get(
                    connection,
                    "notice_update_proposals",
                    tenant,
                    "proposal_id",
                    proposal_ref,
                    "notice update proposal",
                )
                proposal = self._proposal(proposal_raw, proposal_digest)
                if (
                    proposal.status != "approved"
                    or proposal.notice_id != notice
                    or proposal.policy_sha256 != policy_digest
                    or proposal.content_sha256 != content_digest
                    or proposal.configuration_sha256 != configuration_digest
                    or proposal.consent_publication_ref != consent_ref
                ):
                    raise PrivacyNoticeConflict(
                        "approved update proposal does not match the release digests"
                    )
            if before_write is not None:
                before_write(connection, proposal)
            request = {
                "action": "create_release",
                "notice_id": notice,
                "property_id": property_key,
                "jurisdictions": list(jurisdiction_values),
                "locales": list(locale_values),
                "policy_sha256": policy_digest,
                "content_sha256": content_digest,
                "configuration_sha256": configuration_digest,
                "consent_publication_ref": consent_ref,
                "approval_policy_id": policy_key,
                "effective_from": start,
                "effective_until": end,
                "retained_until": retained,
                "update_proposal_ref": proposal_ref,
                "expected_latest_version": expected,
                "actor_ref": actor,
            }
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                return self._get_release(connection, tenant, notice, version)
            latest_row = connection.execute(
                "SELECT MAX(version) AS latest FROM notice_release_definitions "
                "WHERE tenant_id=? AND notice_id=?",
                (tenant, notice),
            ).fetchone()
            latest = 0 if latest_row["latest"] is None else int(latest_row["latest"])
            if latest != expected:
                raise PrivacyNoticeConflict(
                    f"latest release CAS failed: expected {expected}, found {latest}"
                )
            definition = {
                "tenant_id": tenant,
                "notice_id": notice,
                "version": version,
                "property_id": property_key,
                "jurisdictions": list(jurisdiction_values),
                "locales": list(locale_values),
                "policy_sha256": policy_digest,
                "content_sha256": content_digest,
                "configuration_sha256": configuration_digest,
                "consent_publication_ref": consent_ref,
                "approval_policy_id": policy_key,
                "approval_policy_sha256": policy_integrity,
                "required_roles": list(policy.required_roles),
                "quorum": policy.quorum,
                "approval_ttl_seconds": policy.approval_ttl_seconds,
                "effective_from": start,
                "effective_until": end,
                "retained_until": retained,
                "update_proposal_ref": proposal_ref,
                "created_by": actor,
                "created_at": now,
            }
            definition_digest = self._insert(
                connection,
                "notice_release_definitions",
                ("tenant_id", "notice_id", "version", "property_id", "retained_until"),
                (tenant, notice, version, property_key, retained),
                definition,
            )
            state = {
                "tenant_id": tenant,
                "notice_id": notice,
                "version": version,
                "definition_sha256": definition_digest,
                "state": "draft",
                "activate_at": None,
                "approved_digest_sha256": None,
                "rollback_target_version": None,
                "revision": 1,
                "updated_at": now,
            }
            state_digest = self._insert(
                connection,
                "notice_release_states",
                ("tenant_id", "notice_id", "version", "state", "activate_at"),
                (tenant, notice, version, "draft", None),
                state,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "release",
                f"{notice}:{version}",
            )
            self._audit(
                connection,
                tenant,
                "notice_release_created",
                f"{notice}:{version}",
                actor,
                {"property_id": property_key, "version": version},
                now,
            )
            return self._release(definition, state, definition_digest, state_digest)

    def get_release(
        self, tenant_id: str, notice_id: str, version: int
    ) -> NoticeRelease:
        tenant = _tenant(tenant_id)
        notice = _id(notice_id, "notice_id")
        release_version = _integer(version, "version", 1, 1_000_000)
        self._actor()
        with self._connect() as connection:
            return self._get_release(connection, tenant, notice, release_version)

    def submit_for_review(
        self,
        tenant_id: str,
        notice_id: str,
        version: int,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> NoticeRelease:
        tenant = _tenant(tenant_id)
        notice = _id(notice_id, "notice_id")
        release_version = _integer(version, "version", 1, 1_000_000)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "submit_for_review",
            "notice_id": notice,
            "version": release_version,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            current = self._get_release(connection, tenant, notice, release_version)
            if operation is not None:
                return current
            if current.state_revision != expected:
                raise PrivacyNoticeConflict(
                    f"release state CAS failed: expected {expected}, "
                    f"found {current.state_revision}"
                )
            if current.state != "draft":
                raise PrivacyNoticeConflict("only draft releases can enter review")
            state_raw, _state_digest = self._get(
                connection,
                "notice_release_states",
                tenant,
                "notice_id",
                notice,
                "notice release state",
                version=release_version,
            )
            payload = dict(state_raw)
            payload.update(
                {"state": "review", "revision": expected + 1, "updated_at": now}
            )
            self._write(
                connection,
                "notice_release_states",
                tenant,
                "notice_id",
                notice,
                payload,
                version=release_version,
                index_updates={"state": "review"},
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "release",
                f"{notice}:{release_version}",
            )
            self._audit(
                connection,
                tenant,
                "notice_review_started",
                f"{notice}:{release_version}",
                actor,
                {},
                now,
            )
            return self._get_release(connection, tenant, notice, release_version)

    def _active_approvals(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        release: NoticeRelease,
        now: float,
    ) -> tuple[NoticeApproval, ...]:
        rows = connection.execute(
            "SELECT * FROM notice_approvals WHERE tenant_id=? AND notice_id=? "
            "AND release_version=? ORDER BY role",
            (tenant, release.notice_id, release.version),
        ).fetchall()
        approvals = tuple(
            self._approval(
                self._payload(row, "notice approval", tenant), row["integrity_sha256"]
            )
            for row in rows
        )
        return tuple(
            item
            for item in approvals
            if item.revoked_at is None
            and item.expires_at > now
            and item.release_sha256 == release.definition_sha256
        )

    @staticmethod
    def _ready(release: NoticeRelease, approvals: Sequence[NoticeApproval]) -> bool:
        roles = {item.role for item in approvals}
        actors = {item.actor_ref for item in approvals}
        return (
            set(release.required_roles).issubset(roles)
            and len(approvals) >= release.quorum
            and len(actors) == len(approvals)
        )

    def approve_release(
        self,
        tenant_id: str,
        notice_id: str,
        version: int,
        *,
        role: str,
        expected_release_sha256: str,
        expected_revision: int,
        idempotency_key: str,
        effect_guard: Callable[[], None] | None = None,
    ) -> NoticeRelease:
        """Approve one exact release digest under one role and one human identity."""

        tenant = _tenant(tenant_id)
        notice = _id(notice_id, "notice_id")
        release_version = _integer(version, "version", 1, 1_000_000)
        if role not in APPROVAL_ROLES:
            raise PrivacyNoticeValidationError("approval role is unsupported")
        release_digest = _digest(expected_release_sha256, "expected_release_sha256")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "approve_release",
            "notice_id": notice,
            "version": release_version,
            "role": role,
            "release_sha256": release_digest,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            if effect_guard is not None:
                effect_guard()
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            current = self._get_release(connection, tenant, notice, release_version)
            if operation is not None:
                return current
            if current.state_revision != expected:
                raise PrivacyNoticeConflict(
                    f"release state CAS failed: expected {expected}, "
                    f"found {current.state_revision}"
                )
            if current.state not in {"review", "approved"}:
                raise PrivacyNoticeConflict("release is not in an approvable state")
            if current.definition_sha256 != release_digest:
                raise PrivacyNoticeConflict("approval digest does not match the release")
            if actor == current.created_by:
                raise PrivacyNoticePermissionDenied(
                    "the release author cannot approve their own release"
                )
            if role not in current.required_roles and current.quorum <= len(
                current.required_roles
            ):
                raise PrivacyNoticeConflict("approval role is outside this release policy")
            if connection.execute(
                "SELECT 1 FROM notice_approvals WHERE tenant_id=? AND notice_id=? "
                "AND release_version=? AND (role=? OR actor_ref=?)",
                (tenant, notice, release_version, role, actor),
            ).fetchone():
                raise PrivacyNoticePermissionDenied(
                    "a role or authenticated human already approved this release"
                )
            approval_payload = {
                "tenant_id": tenant,
                "notice_id": notice,
                "release_version": release_version,
                "role": role,
                "actor_ref": actor,
                "release_sha256": release_digest,
                "approved_at": now,
                "expires_at": now + current.approval_ttl_seconds,
                "revoked_at": None,
                "revision": 1,
            }
            if effect_guard is not None:
                effect_guard()
            self._insert(
                connection,
                "notice_approvals",
                ("tenant_id", "notice_id", "release_version", "role", "actor_ref"),
                (tenant, notice, release_version, role, actor),
                approval_payload,
            )
            approvals = self._active_approvals(connection, tenant, current, now)
            state_raw, _state_digest = self._get(
                connection,
                "notice_release_states",
                tenant,
                "notice_id",
                notice,
                "notice release state",
                version=release_version,
            )
            state_payload = dict(state_raw)
            if self._ready(current, approvals):
                state_payload.update(
                    {
                        "state": "approved",
                        "approved_digest_sha256": release_digest,
                    }
                )
            state_payload.update({"revision": expected + 1, "updated_at": now})
            self._write(
                connection,
                "notice_release_states",
                tenant,
                "notice_id",
                notice,
                state_payload,
                version=release_version,
                index_updates={"state": state_payload["state"]},
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "release",
                f"{notice}:{release_version}",
            )
            self._audit(
                connection,
                tenant,
                "notice_release_approved",
                f"{notice}:{release_version}",
                actor,
                {"role": role, "ready": self._ready(current, approvals)},
                now,
            )
            result = self._get_release(connection, tenant, notice, release_version)
            if effect_guard is not None:
                effect_guard()
            return result

    def revoke_approval(
        self,
        tenant_id: str,
        notice_id: str,
        version: int,
        *,
        role: str,
        expected_approval_revision: int,
        idempotency_key: str,
        effect_guard: Callable[[], None] | None = None,
    ) -> NoticeRelease:
        tenant = _tenant(tenant_id)
        notice = _id(notice_id, "notice_id")
        release_version = _integer(version, "version", 1, 1_000_000)
        if role not in APPROVAL_ROLES:
            raise PrivacyNoticeValidationError("approval role is unsupported")
        expected = _integer(
            expected_approval_revision, "expected_approval_revision", 1, 1_000_000
        )
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "revoke_approval",
            "notice_id": notice,
            "version": release_version,
            "role": role,
            "expected_approval_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            if effect_guard is not None:
                effect_guard()
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            role_row = connection.execute(
                "SELECT * FROM notice_approvals WHERE tenant_id=? AND notice_id=? "
                "AND release_version=? AND role=?",
                (tenant, notice, release_version, role),
            ).fetchone()
            if role_row is None:
                raise PrivacyNoticeNotFound("notice approval was not found")
            approval_raw = self._payload(role_row, "notice approval", tenant)
            approval = self._approval(approval_raw, role_row["integrity_sha256"])
            if operation is not None:
                return self._get_release(connection, tenant, notice, release_version)
            if approval.actor_ref != actor:
                raise PrivacyNoticePermissionDenied(
                    "only the authenticated approver can revoke this approval"
                )
            if approval.revision != expected or approval.revoked_at is not None:
                raise PrivacyNoticeConflict("approval revision or state is invalid")
            approval_payload = dict(approval_raw)
            approval_payload.update({"revoked_at": now, "revision": expected + 1})
            if effect_guard is not None:
                effect_guard()
            approval_update = connection.execute(
                "UPDATE notice_approvals SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND notice_id=? AND release_version=? AND role=?",
                (
                    _canonical(approval_payload),
                    _sha256(approval_payload),
                    tenant,
                    notice,
                    release_version,
                    role,
                ),
            )
            if approval_update.rowcount != 1:
                raise PrivacyNoticeIntegrityError("notice approval update was not exact")
            release = self._get_release(connection, tenant, notice, release_version)
            if release.state in {"approved", "scheduled"}:
                state_raw, _state_digest = self._get(
                    connection,
                    "notice_release_states",
                    tenant,
                    "notice_id",
                    notice,
                    "notice release state",
                    version=release_version,
                )
                state_payload = dict(state_raw)
                state_payload.update(
                    {
                        "state": "review",
                        "activate_at": None,
                        "approved_digest_sha256": None,
                        "revision": release.state_revision + 1,
                        "updated_at": now,
                    }
                )
                self._write(
                    connection,
                    "notice_release_states",
                    tenant,
                    "notice_id",
                    notice,
                    state_payload,
                    version=release_version,
                    index_updates={"state": "review", "activate_at": None},
                )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "release",
                f"{notice}:{release_version}",
            )
            self._audit(
                connection,
                tenant,
                "notice_approval_revoked",
                f"{notice}:{release_version}",
                actor,
                {"role": role},
                now,
            )
            result = self._get_release(connection, tenant, notice, release_version)
            if effect_guard is not None:
                effect_guard()
            return result

    def _insert_intent(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        release: NoticeRelease,
        *,
        action: str,
        target_version: int | None,
        next_attempt_at: float,
        max_attempts: int,
        now: float,
    ) -> PublicationIntent:
        intent_id = "intent:" + hashlib.sha256(
            _canonical(
                {
                    "notice_id": release.notice_id,
                    "version": release.version,
                    "action": action,
                    "target_version": target_version,
                    "revision": release.state_revision,
                }
            )
        ).hexdigest()[:40]
        payload = {
            "tenant_id": tenant,
            "intent_id": intent_id,
            "notice_id": release.notice_id,
            "release_version": release.version,
            "action": action,
            "target_version": target_version,
            "release_sha256": release.definition_sha256,
            "consent_publication_ref": release.consent_publication_ref,
            "state": "pending",
            "attempts": 0,
            "max_attempts": max_attempts,
            "recovery_count": 0,
            "next_attempt_at": next_attempt_at,
            "lease_owner": None,
            "lease_token": None,
            "lease_until": None,
            "last_error_code": None,
            "acknowledgement_sha256": None,
            "acknowledgement_ref": None,
            "revision": 1,
            "created_at": now,
            "updated_at": now,
        }
        digest_value = self._insert(
            connection,
            "notice_publication_intents",
            (
                "tenant_id",
                "intent_id",
                "notice_id",
                "release_version",
                "action",
                "state",
                "next_attempt_at",
                "lease_until",
            ),
            (
                tenant,
                intent_id,
                release.notice_id,
                release.version,
                action,
                "pending",
                next_attempt_at,
                None,
            ),
            payload,
        )
        return self._intent(payload, digest_value)

    def schedule_release(
        self,
        tenant_id: str,
        notice_id: str,
        version: int,
        *,
        activate_at: float,
        expected_release_sha256: str,
        max_attempts: int,
        expected_revision: int,
        idempotency_key: str,
    ) -> NoticeRelease:
        tenant = _tenant(tenant_id)
        notice = _id(notice_id, "notice_id")
        release_version = _integer(version, "version", 1, 1_000_000)
        activation = _timestamp(activate_at, "activate_at")
        release_digest = _digest(expected_release_sha256, "expected_release_sha256")
        attempts = _integer(max_attempts, "max_attempts", 1, 20)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "schedule_release",
            "notice_id": notice,
            "version": release_version,
            "activate_at": activation,
            "release_sha256": release_digest,
            "max_attempts": attempts,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            release = self._get_release(connection, tenant, notice, release_version)
            if operation is not None:
                return release
            if release.state_revision != expected:
                raise PrivacyNoticeConflict(
                    f"release state CAS failed: expected {expected}, "
                    f"found {release.state_revision}"
                )
            approvals = self._active_approvals(connection, tenant, release, now)
            if release.state != "approved" or not self._ready(release, approvals):
                raise PrivacyNoticeConflict("release approval readiness is invalid")
            if (
                release.definition_sha256 != release_digest
                or release.approved_digest_sha256 != release_digest
            ):
                raise PrivacyNoticeConflict("scheduled digest is not the approved digest")
            if not max(now, release.effective_from) <= activation < release.effective_until:
                raise PrivacyNoticeConflict("activation is outside the effective window")
            state_raw, _state_digest = self._get(
                connection,
                "notice_release_states",
                tenant,
                "notice_id",
                notice,
                "notice release state",
                version=release_version,
            )
            state_payload = dict(state_raw)
            state_payload.update(
                {
                    "state": "scheduled",
                    "activate_at": activation,
                    "revision": expected + 1,
                    "updated_at": now,
                }
            )
            self._write(
                connection,
                "notice_release_states",
                tenant,
                "notice_id",
                notice,
                state_payload,
                version=release_version,
                index_updates={"state": "scheduled", "activate_at": activation},
            )
            scheduled = self._get_release(connection, tenant, notice, release_version)
            self._insert_intent(
                connection,
                tenant,
                scheduled,
                action="publish",
                target_version=None,
                next_attempt_at=activation,
                max_attempts=attempts,
                now=now,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "release",
                f"{notice}:{release_version}",
            )
            self._audit(
                connection,
                tenant,
                "notice_release_scheduled",
                f"{notice}:{release_version}",
                actor,
                {"activate_at": activation},
                now,
            )
            return scheduled

    def claim_publication_intents(
        self,
        tenant_id: str,
        *,
        limit: int,
        lease_seconds: int,
    ) -> tuple[PublicationIntent, ...]:
        """Lease ready local publication intents; this performs no external write."""

        tenant = _tenant(tenant_id)
        bounded_limit = _integer(limit, "limit", 1, 100)
        lease = _integer(lease_seconds, "lease_seconds", 1, _MAX_LEASE_SECONDS)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        with self._connect() as connection:
            self._begin(connection)
            rows = connection.execute(
                "SELECT * FROM notice_publication_intents WHERE tenant_id=? AND "
                "((state='pending' AND next_attempt_at<=?) OR "
                "(state='leased' AND lease_until<=?)) "
                "ORDER BY next_attempt_at,intent_id LIMIT ?",
                (tenant, now, now, min(1_000, bounded_limit * 10)),
            ).fetchall()
            claimed: list[PublicationIntent] = []
            for row in rows:
                if len(claimed) >= bounded_limit:
                    break
                raw = self._payload(row, "publication intent", tenant)
                current = self._intent(raw, row["integrity_sha256"])
                release = self._get_release(
                    connection, tenant, current.notice_id, current.release_version
                )
                if current.action == "publish":
                    approvals = self._active_approvals(connection, tenant, release, now)
                    if (
                        release.state != "scheduled"
                        or not self._ready(release, approvals)
                        or not release.effective_from <= now < release.effective_until
                    ):
                        # Persist progress through rejected candidates. Otherwise
                        # the same bounded prefix can hide due work forever.
                        expired = now >= release.effective_until
                        deferred = dict(raw)
                        state = "dead_letter" if expired else "pending"
                        next_attempt = max(now + 60, release.effective_from)
                        error_code = "release_expired" if expired else "release_not_ready"
                        deferred.update(state=state, next_attempt_at=next_attempt,
                                        lease_owner=None, lease_token=None, lease_until=None,
                                        last_error_code=error_code, revision=current.revision + 1,
                                        updated_at=now)
                        self._write(connection, "notice_publication_intents", tenant,
                                    "intent_id", current.intent_id, deferred,
                                    index_updates={"state": state, "next_attempt_at": next_attempt,
                                                   "lease_until": None})
                        self._audit(connection, tenant, "publication_intent_failed",
                                    current.intent_id, actor,
                                    {"state": state, "error_code": error_code, "attempts": current.attempts}, now)
                        continue
                token = _id(self._token_factory(), "lease_token", _OP_RE)
                payload = dict(raw)
                payload.update(
                    {
                        "state": "leased",
                        "lease_owner": actor,
                        "lease_token": token,
                        "lease_until": now + lease,
                        "recovery_count": current.recovery_count
                        + int(current.state == "leased"),
                        "revision": current.revision + 1,
                        "updated_at": now,
                    }
                )
                digest_value = self._write(
                    connection,
                    "notice_publication_intents",
                    tenant,
                    "intent_id",
                    current.intent_id,
                    payload,
                    index_updates={"state": "leased", "lease_until": now + lease},
                )
                claimed.append(self._intent(payload, digest_value))
                self._audit(
                    connection,
                    tenant,
                    "publication_intent_claimed",
                    current.intent_id,
                    actor,
                    {"recovered": current.state == "leased"},
                    now,
                )
            return tuple(claimed)

    @staticmethod
    def _assert_lease(
        intent: PublicationIntent,
        actor: str,
        token: str,
        expected_revision: int,
        now: float,
    ) -> None:
        if intent.revision != expected_revision:
            raise PrivacyNoticeConflict(
                f"intent revision CAS failed: expected {expected_revision}, "
                f"found {intent.revision}"
            )
        if (
            intent.state != "leased"
            or intent.lease_owner != actor
            or intent.lease_token != token
            or intent.lease_until is None
            or intent.lease_until <= now
        ):
            raise PrivacyNoticeConflict("publication intent lease is invalid")

    def fail_publication_intent(
        self,
        tenant_id: str,
        intent_id: str,
        *,
        lease_token: str,
        error_code: str,
        retry_delay_seconds: int,
        expected_revision: int,
        idempotency_key: str,
    ) -> PublicationIntent:
        tenant = _tenant(tenant_id)
        intent_key = _id(intent_id, "intent_id")
        token = _id(lease_token, "lease_token", _OP_RE)
        if not isinstance(error_code, str) or not _ERROR_RE.fullmatch(error_code):
            raise PrivacyNoticeValidationError("error_code is unsupported")
        delay = _integer(
            retry_delay_seconds, "retry_delay_seconds", 0, _MAX_BACKOFF_SECONDS
        )
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "fail_publication_intent",
            "intent_id": intent_key,
            "lease_token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "error_code": error_code,
            "retry_delay_seconds": delay,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            raw, stored_digest = self._get(
                connection,
                "notice_publication_intents",
                tenant,
                "intent_id",
                intent_key,
                "publication intent",
            )
            if operation is not None:
                return self._intent(raw, stored_digest)
            current = self._intent(raw, stored_digest)
            self._assert_lease(current, actor, token, expected, now)
            attempts = current.attempts + 1
            state = "dead_letter" if attempts >= current.max_attempts else "pending"
            payload = dict(raw)
            payload.update(
                {
                    "state": state,
                    "attempts": attempts,
                    "next_attempt_at": now + delay,
                    "lease_owner": None,
                    "lease_token": None,
                    "lease_until": None,
                    "last_error_code": error_code,
                    "revision": current.revision + 1,
                    "updated_at": now,
                }
            )
            digest_value = self._write(
                connection,
                "notice_publication_intents",
                tenant,
                "intent_id",
                intent_key,
                payload,
                index_updates={
                    "state": state,
                    "next_attempt_at": now + delay,
                    "lease_until": None,
                },
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "intent", intent_key
            )
            self._audit(
                connection,
                tenant,
                "publication_intent_failed",
                intent_key,
                actor,
                {"state": state, "attempts": attempts, "error_code": error_code},
                now,
            )
            return self._intent(payload, digest_value)

    def requeue_publication_intent(
        self,
        tenant_id: str,
        intent_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> PublicationIntent:
        tenant = _tenant(tenant_id)
        intent_key = _id(intent_id, "intent_id")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "requeue_publication_intent",
            "intent_id": intent_key,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            raw, stored_digest = self._get(
                connection,
                "notice_publication_intents",
                tenant,
                "intent_id",
                intent_key,
                "publication intent",
            )
            if operation is not None:
                return self._intent(raw, stored_digest)
            current = self._intent(raw, stored_digest)
            if current.revision != expected or current.state != "dead_letter":
                raise PrivacyNoticeConflict(
                    "only the expected dead-letter intent can be requeued"
                )
            payload = dict(raw)
            payload.update(
                {
                    "state": "pending",
                    "attempts": 0,
                    "next_attempt_at": now,
                    "last_error_code": None,
                    "revision": current.revision + 1,
                    "updated_at": now,
                }
            )
            digest_value = self._write(
                connection,
                "notice_publication_intents",
                tenant,
                "intent_id",
                intent_key,
                payload,
                index_updates={"state": "pending", "next_attempt_at": now},
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "intent", intent_key
            )
            self._audit(
                connection,
                tenant,
                "publication_intent_requeued",
                intent_key,
                actor,
                {},
                now,
            )
            return self._intent(payload, digest_value)

    def ack_publication_intent(
        self,
        tenant_id: str,
        intent_id: str,
        *,
        lease_token: str,
        acknowledgement_sha256: str,
        acknowledgement_ref: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> PublicationIntent:
        tenant = _tenant(tenant_id)
        intent_key = _id(intent_id, "intent_id")
        token = _id(lease_token, "lease_token", _OP_RE)
        acknowledgement = _digest(
            acknowledgement_sha256, "acknowledgement_sha256"
        )
        reference = _id(acknowledgement_ref, "acknowledgement_ref")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "ack_publication_intent",
            "intent_id": intent_key,
            "lease_token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "acknowledgement_sha256": acknowledgement,
            "acknowledgement_ref": reference,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            raw, stored_digest = self._get(
                connection,
                "notice_publication_intents",
                tenant,
                "intent_id",
                intent_key,
                "publication intent",
            )
            if operation is not None:
                return self._intent(raw, stored_digest)
            current = self._intent(raw, stored_digest)
            self._assert_lease(current, actor, token, expected, now)
            release = self._get_release(
                connection, tenant, current.notice_id, current.release_version
            )
            if current.action == "publish":
                approvals = self._active_approvals(connection, tenant, release, now)
                if (
                    release.state != "scheduled"
                    or release.definition_sha256 != current.release_sha256
                    or not self._ready(release, approvals)
                    or not release.effective_from <= now < release.effective_until
                ):
                    raise PrivacyNoticeConflict(
                        "publication readiness, digest, or effective window is invalid"
                    )
                state_raw, _state_digest = self._get(
                    connection,
                    "notice_release_states",
                    tenant,
                    "notice_id",
                    release.notice_id,
                    "notice release state",
                    version=release.version,
                )
                state_payload = dict(state_raw)
                state_payload.update(
                    {
                        "state": "published",
                        "revision": release.state_revision + 1,
                        "updated_at": now,
                    }
                )
                self._write(
                    connection,
                    "notice_release_states",
                    tenant,
                    "notice_id",
                    release.notice_id,
                    state_payload,
                    version=release.version,
                    index_updates={"state": "published"},
                )
            payload = dict(raw)
            payload.update(
                {
                    "state": "acked",
                    "lease_owner": None,
                    "lease_token": None,
                    "lease_until": None,
                    "acknowledgement_sha256": acknowledgement,
                    "acknowledgement_ref": reference,
                    "revision": current.revision + 1,
                    "updated_at": now,
                }
            )
            digest_value = self._write(
                connection,
                "notice_publication_intents",
                tenant,
                "intent_id",
                intent_key,
                payload,
                index_updates={"state": "acked", "lease_until": None},
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "intent", intent_key
            )
            self._audit(
                connection,
                tenant,
                "publication_intent_acknowledged",
                intent_key,
                actor,
                {"action": current.action, "acknowledgement_sha256": acknowledgement},
                now,
            )
            return self._intent(payload, digest_value)

    def _independent_terminal_action(
        self,
        tenant: str,
        notice: str,
        version: int,
        *,
        action: str,
        target_version: int | None,
        reason_code: str,
        max_attempts: int,
        expected_revision: int,
        idempotency_key: str,
        actor: str,
        now: float,
    ) -> NoticeRelease:
        request = {
            "action": action,
            "notice_id": notice,
            "version": version,
            "target_version": target_version,
            "reason_code": reason_code,
            "max_attempts": max_attempts,
            "expected_revision": expected_revision,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            release = self._get_release(connection, tenant, notice, version)
            if operation is not None:
                return release
            if release.state_revision != expected_revision:
                raise PrivacyNoticeConflict(
                    f"release state CAS failed: expected {expected_revision}, "
                    f"found {release.state_revision}"
                )
            if release.state != "published":
                raise PrivacyNoticeConflict(
                    f"only a published release can be {action}"
                )
            approval_actors = {
                row["actor_ref"]
                for row in connection.execute(
                    "SELECT actor_ref FROM notice_approvals WHERE tenant_id=? "
                    "AND notice_id=? AND release_version=?",
                    (tenant, notice, version),
                ).fetchall()
            }
            if actor == release.created_by or actor in approval_actors:
                raise PrivacyNoticePermissionDenied(
                    f"{action} requires an independently authorized principal"
                )
            if action == "rollback":
                if target_version is None or target_version >= version:
                    raise PrivacyNoticeValidationError(
                        "rollback target must be an earlier release version"
                    )
                target = self._get_release(
                    connection, tenant, notice, target_version
                )
                if target.state != "published":
                    raise PrivacyNoticeConflict(
                        "rollback target must be a published release"
                    )
            state_raw, _state_digest = self._get(
                connection,
                "notice_release_states",
                tenant,
                "notice_id",
                notice,
                "notice release state",
                version=version,
            )
            state_payload = dict(state_raw)
            state_payload.update(
                {
                    "state": "rolled_back" if action == "rollback" else "withdrawn",
                    "rollback_target_version": target_version,
                    "revision": expected_revision + 1,
                    "updated_at": now,
                }
            )
            self._write(
                connection,
                "notice_release_states",
                tenant,
                "notice_id",
                notice,
                state_payload,
                version=version,
                index_updates={"state": state_payload["state"]},
            )
            terminal = self._get_release(connection, tenant, notice, version)
            self._insert_intent(
                connection,
                tenant,
                terminal,
                action=action,
                target_version=target_version,
                next_attempt_at=now,
                max_attempts=max_attempts,
                now=now,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "release",
                f"{notice}:{version}",
            )
            self._audit(
                connection,
                tenant,
                f"notice_release_{action}",
                f"{notice}:{version}",
                actor,
                {"target_version": target_version, "reason_code": reason_code},
                now,
            )
            return terminal

    def rollback_release(
        self,
        tenant_id: str,
        notice_id: str,
        version: int,
        *,
        target_version: int,
        reason_code: str,
        max_attempts: int,
        expected_revision: int,
        idempotency_key: str,
    ) -> NoticeRelease:
        tenant = _tenant(tenant_id)
        notice = _id(notice_id, "notice_id")
        release_version = _integer(version, "version", 2, 1_000_000)
        target = _integer(target_version, "target_version", 1, 1_000_000)
        reason = _id(reason_code, "reason_code")
        attempts = _integer(max_attempts, "max_attempts", 1, 20)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        return self._independent_terminal_action(
            tenant,
            notice,
            release_version,
            action="rollback",
            target_version=target,
            reason_code=reason,
            max_attempts=attempts,
            expected_revision=expected,
            idempotency_key=idempotency_key,
            actor=self._actor(),
            now=_timestamp(self._clock(), "current time"),
        )

    def withdraw_release(
        self,
        tenant_id: str,
        notice_id: str,
        version: int,
        *,
        reason_code: str,
        max_attempts: int,
        expected_revision: int,
        idempotency_key: str,
    ) -> NoticeRelease:
        tenant = _tenant(tenant_id)
        notice = _id(notice_id, "notice_id")
        release_version = _integer(version, "version", 1, 1_000_000)
        reason = _id(reason_code, "reason_code")
        attempts = _integer(max_attempts, "max_attempts", 1, 20)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        return self._independent_terminal_action(
            tenant,
            notice,
            release_version,
            action="withdraw",
            target_version=None,
            reason_code=reason,
            max_attempts=attempts,
            expected_revision=expected,
            idempotency_key=idempotency_key,
            actor=self._actor(),
            now=_timestamp(self._clock(), "current time"),
        )

    def current_effective_release(
        self,
        tenant_id: str,
        property_id: str,
        jurisdiction: str,
        locale: str,
        *,
        at: float | None = None,
    ) -> NoticeRelease:
        tenant = _tenant(tenant_id)
        property_key = _id(property_id, "property_id")
        if not isinstance(jurisdiction, str) or not _JURISDICTION_RE.fullmatch(
            jurisdiction
        ):
            raise PrivacyNoticeValidationError("jurisdiction is unsupported")
        if not isinstance(locale, str) or not _LOCALE_RE.fullmatch(locale):
            raise PrivacyNoticeValidationError("locale is unsupported")
        moment = _timestamp(self._clock() if at is None else at, "at")
        self._actor()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT d.*,s.payload_json AS state_payload,s.integrity_sha256 AS state_sha "
                "FROM notice_release_definitions d JOIN notice_release_states s "
                "ON d.tenant_id=s.tenant_id AND d.notice_id=s.notice_id "
                "AND d.version=s.version WHERE d.tenant_id=? AND d.property_id=? "
                "AND s.state='published' ORDER BY d.version DESC",
                (tenant, property_key),
            ).fetchall()
            for row in rows:
                definition = self._payload(row, "notice release definition", tenant)
                state_row = {
                    "tenant_id": row["tenant_id"],
                    "payload_json": row["state_payload"],
                    "integrity_sha256": row["state_sha"],
                }
                state = self._payload(state_row, "notice release state", tenant)  # type: ignore[arg-type]
                if (
                    jurisdiction in definition["jurisdictions"]
                    and locale in definition["locales"]
                    and definition["effective_from"] <= moment
                    < definition["effective_until"]
                ):
                    release = self._release(
                        definition,
                        state,
                        row["integrity_sha256"],
                        row["state_sha"],
                    )
                    approvals = self._active_approvals(
                        connection, tenant, release, moment
                    )
                    if self._ready(release, approvals):
                        return release
        raise PrivacyNoticeNotFound("no exact effective notice release was found")

    def create_update_proposal(
        self,
        tenant_id: str,
        proposal_id: str,
        *,
        notice_id: str,
        base_version: int,
        policy_sha256: str,
        content_sha256: str,
        configuration_sha256: str,
        consent_publication_ref: str,
        regulatory_citations: Sequence[Mapping[str, str]],
        reason_codes: Sequence[str],
        retained_until: float,
        idempotency_key: str,
        before_write: Callable[[sqlite3.Connection, NoticeRelease], None] | None = None,
    ) -> NoticeUpdateProposal:
        """Create a human-review proposal; never infer applicability or publish."""

        tenant = _tenant(tenant_id)
        proposal_key = _id(proposal_id, "proposal_id")
        notice = _id(notice_id, "notice_id")
        base = _integer(base_version, "base_version", 1, 1_000_000)
        policy_digest = _digest(policy_sha256, "policy_sha256")
        content_digest = _digest(content_sha256, "content_sha256")
        configuration_digest = _digest(
            configuration_sha256, "configuration_sha256"
        )
        consent_ref = _id(consent_publication_ref, "consent_publication_ref")
        if (
            isinstance(regulatory_citations, (str, bytes))
            or not isinstance(regulatory_citations, Sequence)
            or not 1 <= len(regulatory_citations) <= _MAX_CITATIONS
        ):
            raise PrivacyNoticeValidationError("regulatory_citations is invalid")
        resolver = self._regulatory_reference_resolver
        if not callable(resolver):
            raise PrivacyNoticeConfigError(
                "an independent regulatory reference resolver is required"
            )
        citations: list[dict[str, str]] = []
        for item in regulatory_citations:
            if not isinstance(item, Mapping) or set(item) != {
                "document_ref",
                "source_ref",
                "evidence_sha256",
            }:
                raise PrivacyNoticeValidationError(
                    "regulatory citation schema is closed"
                )
            document_ref = _id(item["document_ref"], "document_ref")
            source_ref = _id(item["source_ref"], "source_ref")
            evidence = _digest(item["evidence_sha256"], "evidence_sha256")
            if resolver(tenant, document_ref, source_ref, evidence) is not True:
                raise PrivacyNoticeConflict(
                    "regulatory citation is not independently approved"
                )
            citations.append(
                {
                    "document_ref": document_ref,
                    "source_ref": source_ref,
                    "evidence_sha256": evidence,
                }
            )
        reasons = _id_sequence(
            reason_codes,
            "reason_codes",
            minimum=1,
            maximum=_MAX_REASON_CODES,
        )
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        retained = _retained_until(retained_until, now)
        request = {
            "action": "create_update_proposal",
            "proposal_id": proposal_key,
            "notice_id": notice,
            "base_version": base,
            "policy_sha256": policy_digest,
            "content_sha256": content_digest,
            "configuration_sha256": configuration_digest,
            "consent_publication_ref": consent_ref,
            "regulatory_citations": citations,
            "reason_codes": list(reasons),
            "retained_until": retained,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            base_release = self._get_release(connection, tenant, notice, base)
            if before_write is not None:
                before_write(connection, base_release)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                raw, digest_value = self._get(
                    connection,
                    "notice_update_proposals",
                    tenant,
                    "proposal_id",
                    proposal_key,
                    "notice update proposal",
                )
                return self._proposal(raw, digest_value)
            payload = {
                "tenant_id": tenant,
                "proposal_id": proposal_key,
                "notice_id": notice,
                "base_version": base,
                "policy_sha256": policy_digest,
                "content_sha256": content_digest,
                "configuration_sha256": configuration_digest,
                "consent_publication_ref": consent_ref,
                "regulatory_citations": citations,
                "reason_codes": list(reasons),
                "status": "pending_review",
                "retained_until": retained,
                "created_by": actor,
                "reviewed_by": None,
                "revision": 1,
                "created_at": now,
                "reviewed_at": None,
            }
            digest_value = self._insert(
                connection,
                "notice_update_proposals",
                ("tenant_id", "proposal_id", "notice_id", "status", "retained_until"),
                (tenant, proposal_key, notice, "pending_review", retained),
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "proposal",
                proposal_key,
            )
            self._audit(
                connection,
                tenant,
                "notice_update_proposed",
                proposal_key,
                actor,
                {"citation_count": len(citations), "auto_published": False},
                now,
            )
            return self._proposal(payload, digest_value)

    def review_update_proposal(
        self,
        tenant_id: str,
        proposal_id: str,
        *,
        decision: str,
        expected_revision: int,
        idempotency_key: str,
        effect_guard: Callable[[], None] | None = None,
    ) -> NoticeUpdateProposal:
        tenant = _tenant(tenant_id)
        proposal_key = _id(proposal_id, "proposal_id")
        if decision not in PROPOSAL_DECISIONS:
            raise PrivacyNoticeValidationError("proposal decision is unsupported")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "review_update_proposal",
            "proposal_id": proposal_key,
            "decision": decision,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            if effect_guard is not None:
                effect_guard()
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            raw, stored_digest = self._get(
                connection,
                "notice_update_proposals",
                tenant,
                "proposal_id",
                proposal_key,
                "notice update proposal",
            )
            if operation is not None:
                return self._proposal(raw, stored_digest)
            current = self._proposal(raw, stored_digest)
            if current.revision != expected or current.status != "pending_review":
                raise PrivacyNoticeConflict("proposal revision or state is invalid")
            if current.created_by == actor:
                raise PrivacyNoticePermissionDenied(
                    "update proposal requires a reviewer distinct from its creator"
                )
            payload = dict(raw)
            payload.update(
                {
                    "status": decision,
                    "reviewed_by": actor,
                    "revision": expected + 1,
                    "reviewed_at": now,
                }
            )
            if effect_guard is not None:
                effect_guard()
            digest_value = self._write(
                connection,
                "notice_update_proposals",
                tenant,
                "proposal_id",
                proposal_key,
                payload,
                index_updates={"status": decision},
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "proposal",
                proposal_key,
            )
            self._audit(
                connection,
                tenant,
                "notice_update_reviewed",
                proposal_key,
                actor,
                {"decision": decision, "auto_published": False},
                now,
            )
            result = self._proposal(payload, digest_value)
            if effect_guard is not None:
                effect_guard()
            return result

    def get_update_proposal(
        self, tenant_id: str, proposal_id: str
    ) -> NoticeUpdateProposal:
        tenant = _tenant(tenant_id)
        proposal_key = _id(proposal_id, "proposal_id")
        self._actor()
        with self._connect() as connection:
            raw, digest_value = self._get(
                connection,
                "notice_update_proposals",
                tenant,
                "proposal_id",
                proposal_key,
                "notice update proposal",
            )
            return self._proposal(raw, digest_value)

    def export_notice(
        self,
        tenant_id: str,
        notice_id: str,
        export_id: str,
        *,
        signing_key_ref: str,
        retained_until: float,
        idempotency_key: str,
    ) -> SignedNoticeExport:
        """Create a signed metadata export with no content, secrets, or lease tokens."""

        tenant = _tenant(tenant_id)
        notice = _id(notice_id, "notice_id")
        export_key = _id(export_id, "export_id")
        key_ref = _id(signing_key_ref, "signing_key_ref", _KEY_REF_RE)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        retained = _retained_until(retained_until, now)
        request = {
            "action": "export_notice",
            "notice_id": notice,
            "export_id": export_key,
            "signing_key_ref": key_ref,
            "retained_until": retained,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                raw, digest_value = self._get(
                    connection,
                    "notice_exports",
                    tenant,
                    "export_id",
                    export_key,
                    "notice export",
                )
                return self._export(raw, digest_value)
            definitions = connection.execute(
                "SELECT * FROM notice_release_definitions WHERE tenant_id=? "
                "AND notice_id=? ORDER BY version",
                (tenant, notice),
            ).fetchall()
            if not definitions:
                raise PrivacyNoticeNotFound("notice was not found")
            releases: list[dict[str, object]] = []
            terminal_retention = retained
            for row in definitions:
                release = self._get_release(
                    connection, tenant, notice, int(row["version"])
                )
                releases.append(
                    {
                        "notice_id": release.notice_id,
                        "version": release.version,
                        "property_id": release.property_id,
                        "jurisdictions": list(release.jurisdictions),
                        "locales": list(release.locales),
                        "policy_sha256": release.policy_sha256,
                        "content_sha256": release.content_sha256,
                        "configuration_sha256": release.configuration_sha256,
                        "consent_publication_ref": release.consent_publication_ref,
                        "definition_sha256": release.definition_sha256,
                        "state": release.state,
                        "effective_from": release.effective_from,
                        "effective_until": release.effective_until,
                    }
                )
                terminal_retention = min(terminal_retention, release.retained_until)
            approval_rows = connection.execute(
                "SELECT * FROM notice_approvals WHERE tenant_id=? AND notice_id=? "
                "ORDER BY release_version,role",
                (tenant, notice),
            ).fetchall()
            approval_summaries = [
                {
                    "release_version": row["release_version"],
                    "role": approval["role"],
                    "actor_sha256": hashlib.sha256(
                        approval["actor_ref"].encode()
                    ).hexdigest(),
                    "release_sha256": approval["release_sha256"],
                    "expires_at": approval["expires_at"],
                    "revoked": approval["revoked_at"] is not None,
                }
                for row in approval_rows
                for approval in [self._payload(row, "notice approval", tenant)]
            ]
            intent_rows = connection.execute(
                "SELECT action,state,COUNT(*) AS total "
                "FROM notice_publication_intents WHERE tenant_id=? AND notice_id=? "
                "GROUP BY action,state ORDER BY action,state",
                (tenant, notice),
            ).fetchall()
            body = {
                "releases": releases,
                "approval_summaries": approval_summaries,
                "publication_intent_counts": [dict(row) for row in intent_rows],
                "limitations": self.product_boundaries(),
            }
            body_sha = _sha256(body)
            key = self._signing_key_resolver(tenant, key_ref)
            if not isinstance(key, bytes) or len(key) < 32:
                raise PrivacyNoticeConfigError("signing key must contain at least 32 bytes")
            signature = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
            payload = {
                "tenant_id": tenant,
                "export_id": export_key,
                "notice_id": notice,
                "schema": EXPORT_SCHEMA,
                "body": body,
                "body_sha256": body_sha,
                "signing_key_ref": key_ref,
                "signature_hmac_sha256": signature,
                "retained_until": terminal_retention,
                "created_by": actor,
                "created_at": now,
            }
            digest_value = self._insert(
                connection,
                "notice_exports",
                ("tenant_id", "export_id", "notice_id", "retained_until"),
                (tenant, export_key, notice, terminal_retention),
                payload,
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, "export", export_key
            )
            self._audit(
                connection,
                tenant,
                "notice_export_signed",
                export_key,
                actor,
                {"notice_id": notice, "body_sha256": body_sha},
                now,
            )
            return self._export(payload, digest_value)

    def _verify_export(self, export: SignedNoticeExport) -> None:
        if _sha256(export.body) != export.body_sha256:
            raise PrivacyNoticeIntegrityError("notice export body digest is invalid")
        key = self._signing_key_resolver(export.tenant_id, export.signing_key_ref)
        expected = hmac.new(key, _canonical(export.body), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, export.signature_hmac_sha256):
            raise PrivacyNoticeIntegrityError("notice export signature is invalid")

    def get_export(self, tenant_id: str, export_id: str) -> SignedNoticeExport:
        tenant = _tenant(tenant_id)
        export_key = _id(export_id, "export_id")
        self._actor()
        with self._connect() as connection:
            raw, digest_value = self._get(
                connection,
                "notice_exports",
                tenant,
                "export_id",
                export_key,
                "notice export",
            )
            export = self._export(raw, digest_value)
            self._verify_export(export)
            return export

    def purge_expired(
        self,
        tenant_id: str,
        *,
        cutoff: float,
        idempotency_key: str,
    ) -> Mapping[str, int]:
        tenant = _tenant(tenant_id)
        requested = _timestamp(cutoff, "cutoff")
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        # A cutoff in the future must not delete records before their
        # retention ends: nothing later than the current time is purged.
        moment = min(now, requested)
        request = {"action": "purge_expired", "cutoff": requested, "actor_ref": actor}
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                parts = operation["result_id"].split(":")
                if len(parts) != 3 or any(not part.isdigit() for part in parts):
                    raise PrivacyNoticeIntegrityError("purge result is invalid")
                return {
                    "exports": int(parts[0]),
                    "proposals": int(parts[1]),
                    "releases": int(parts[2]),
                }
            exports = connection.execute(
                "DELETE FROM notice_exports WHERE tenant_id=? AND retained_until<=?",
                (tenant, moment),
            ).rowcount
            proposals = connection.execute(
                "DELETE FROM notice_update_proposals WHERE tenant_id=? "
                "AND retained_until<=? AND status IN ('approved','rejected')",
                (tenant, moment),
            ).rowcount
            candidates = connection.execute(
                "SELECT d.notice_id,d.version FROM notice_release_definitions d "
                "JOIN notice_release_states s ON d.tenant_id=s.tenant_id "
                "AND d.notice_id=s.notice_id AND d.version=s.version "
                "WHERE d.tenant_id=? AND d.retained_until<=? "
                "AND s.state IN ('published','rolled_back','withdrawn')",
                (tenant, moment),
            ).fetchall()
            for row in candidates:
                connection.execute(
                    "DELETE FROM notice_release_states WHERE tenant_id=? "
                    "AND notice_id=? AND version=?",
                    (tenant, row["notice_id"], row["version"]),
                )
                connection.execute(
                    "DELETE FROM notice_release_definitions WHERE tenant_id=? "
                    "AND notice_id=? AND version=?",
                    (tenant, row["notice_id"], row["version"]),
                )
            result_id = f"{exports}:{proposals}:{len(candidates)}"
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "purge_result",
                result_id,
            )
            self._audit(
                connection,
                tenant,
                "notice_retention_purged",
                idempotency_key,
                actor,
                {
                    "exports": exports,
                    "proposals": proposals,
                    "releases": len(candidates),
                },
                now,
            )
            return {
                "exports": exports,
                "proposals": proposals,
                "releases": len(candidates),
            }

    def verify_integrity(self, tenant_id: str) -> IntegrityVerification:
        tenant = _tenant(tenant_id)
        self._actor()
        verified = 0
        tables = (
            ("notice_approval_policies", "approval policy"),
            ("notice_release_definitions", "notice release definition"),
            ("notice_release_states", "notice release state"),
            ("notice_approvals", "notice approval"),
            ("notice_publication_intents", "publication intent"),
            ("notice_update_proposals", "notice update proposal"),
            ("notice_exports", "notice export"),
        )
        with self._connect() as connection:
            for table, label in tables:
                rows = connection.execute(
                    f"SELECT * FROM {table} WHERE tenant_id=?",  # noqa: S608
                    (tenant,),
                ).fetchall()
                for row in rows:
                    payload = self._payload(row, label, tenant)
                    for column in (
                        "policy_id",
                        "notice_id",
                        "version",
                        "release_version",
                        "property_id",
                        "role",
                        "actor_ref",
                        "intent_id",
                        "action",
                        "proposal_id",
                        "export_id",
                        "state",
                        "status",
                        "activate_at",
                        "next_attempt_at",
                        "lease_until",
                        "retained_until",
                    ):
                        if column in row.keys() and payload.get(column) != row[column]:
                            raise PrivacyNoticeIntegrityError(
                                f"persisted {label} index binding is invalid"
                            )
                    if table == "notice_exports":
                        self._verify_export(
                            self._export(payload, row["integrity_sha256"])
                        )
                    verified += 1
            state_rows = connection.execute(
                "SELECT * FROM notice_release_states WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            for row in state_rows:
                state = self._payload(row, "notice release state", tenant)
                definition = connection.execute(
                    "SELECT integrity_sha256 FROM notice_release_definitions "
                    "WHERE tenant_id=? AND notice_id=? AND version=?",
                    (tenant, row["notice_id"], row["version"]),
                ).fetchone()
                if (
                    definition is None
                    or state["definition_sha256"] != definition["integrity_sha256"]
                ):
                    raise PrivacyNoticeIntegrityError(
                        "notice release definition binding is invalid"
                    )
            operation_rows = connection.execute(
                "SELECT * FROM notice_operations WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            for row in operation_rows:
                binding = {
                    "tenant_id": row["tenant_id"],
                    "operation_sha256": row["operation_sha256"],
                    "request_sha256": row["request_sha256"],
                    "result_kind": row["result_kind"],
                    "result_id": row["result_id"],
                }
                if row["tenant_id"] != tenant or _sha256(binding) != row["integrity_sha256"]:
                    raise PrivacyNoticeIntegrityError(
                        "notice idempotency binding is invalid"
                    )
                verified += 1
            audit_rows = connection.execute(
                "SELECT * FROM notice_audit_events WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
            previous = "0" * 64
            terminal = previous
            for sequence, row in enumerate(audit_rows, start=1):
                payload = self._payload(row, "notice audit event", tenant)
                if (
                    row["sequence"] != sequence
                    or payload["sequence"] != sequence
                    or payload["previous_sha256"] != previous
                ):
                    raise PrivacyNoticeIntegrityError(
                        "privacy notice audit chain is discontinuous"
                    )
                previous = row["integrity_sha256"]
                terminal = previous
                verified += 1
            return IntegrityVerification(
                tenant_id=tenant,
                verified_records=verified,
                audit_events=len(audit_rows),
                terminal_audit_sha256=terminal,
            )

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "provider_neutral": True,
            "network_io": False,
            "provider_writes": False,
            "legal_advice": False,
            "maintained_notice_content": False,
            "sdk_deployment": False,
            "site_mutation": False,
            "accessibility_acceptance": False,
            "legal_acceptance": False,
            "customer_acceptance": False,
            "automatic_legal_applicability_inference": False,
            "automatic_publication": False,
            "raw_html_persisted": False,
            "pii_persisted": False,
            "secret_values_persisted": False,
            "live_acceptance_verified": False,
        }


__all__ = [
    "APPROVAL_ROLES",
    "INTENT_ACTIONS",
    "INTENT_STATES",
    "LIVE_ACCEPTANCE_VERIFIED",
    "LIVE_PROVIDER_WRITES",
    "RELEASE_STATES",
    "ApprovalPolicy",
    "IntegrityVerification",
    "NoticeApproval",
    "NoticeRelease",
    "NoticeUpdateProposal",
    "PrivacyNoticeConfigError",
    "PrivacyNoticeConflict",
    "PrivacyNoticeGovernanceError",
    "PrivacyNoticeGovernanceStore",
    "PrivacyNoticeIntegrityError",
    "PrivacyNoticeNotFound",
    "PrivacyNoticePermissionDenied",
    "PrivacyNoticeValidationError",
    "PublicationIntent",
    "SignedNoticeExport",
    "enabled",
    "require_enabled",
]
