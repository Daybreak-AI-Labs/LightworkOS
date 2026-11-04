"""One-time consumer delivery authority for privacy-rights response packages.

This module is a local, provider-neutral authorization layer.  It mints a
short-lived consumer capability only after an injected trusted resolver proves
that an exact privacy-rights case and response package are ready.  The raw
consumer capability and the raw server grant are each returned once; only
their SHA-256 digests are persisted.

The bundled resolver uses only the public ``get_case`` and
``get_response_package`` methods of ``PrivacyRightsOrchestrationStore``.  A
closed orchestration case is the public proof that identity evidence, planned
work, callbacks, redaction, a completeness manifest, and four-eyes closure all
passed.  This module never reads the orchestration database directly.

The capability is closed unless all exact gates are explicitly enabled::

    [privacy_automation]
    enable = true
    [privacy_automation.rights_orchestration]
    enable = true
    [privacy_automation.rights_consumer_delivery]
    enable = true

There is no network client, object-store client, provider write, identity
verification, source-system acceptance, object payload, encryption key value,
or raw subject identifier in this module.  Redeeming a consumer capability
returns only a short-lived opaque grant for a separately governed server-side
delivery adapter.
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
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
AUDIT_SCHEMA = "lightwork.privacy-rights-consumer-delivery-audit.v1"
EXPORT_SCHEMA = "lightwork.privacy-rights-consumer-delivery-export.v1"
AUTHORITY_SCHEMA = "lightwork.privacy-rights-consumer-delivery-authority.v1"

NETWORK_IO = False
PROVIDER_WRITES = False
OBJECT_BYTES_RETURNED = False
OBJECT_STORE_CREDENTIALS_RETURNED = False
IDENTITY_VERIFICATION_PERFORMED = False
LIVE_SOURCE_ACCEPTANCE_VERIFIED = False
LIVE_IDENTITY_ACCEPTANCE_VERIFIED = False

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_KEY_REF_RE = re.compile(r"(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CAPABILITY_RE = re.compile(r"lwrcd1\.[A-Za-z0-9_-]{43,96}\Z")
_SERVER_GRANT_RE = re.compile(r"lwrcg1\.[A-Za-z0-9_-]{43,96}\Z")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MIN_TTL_SECONDS = 30
_MAX_TTL_SECONDS = 15 * 60
_MIN_SERVER_GRANT_SECONDS = 5
_MAX_SERVER_GRANT_SECONDS = 120
_MIN_RETENTION_SECONDS = 60
_MAX_RETENTION_SECONDS = 365 * 24 * 60 * 60
_MAX_ATTEMPTS = 5
_MAX_ATTEMPT_INTERVAL_SECONDS = 60
_UNAVAILABLE = "delivery capability is unavailable"

_DELIVERY_STATES = frozenset({"active", "redeemed", "claimed", "revoked", "expired", "exhausted"})


class RightsConsumerDeliveryError(RuntimeError):
    """Base consumer delivery error."""


class RightsConsumerDeliveryConfigError(RightsConsumerDeliveryError):
    """The feature gate, trusted resolver, or key boundary is unavailable."""


class RightsConsumerDeliveryValidationError(RightsConsumerDeliveryError, ValueError):
    """Input is outside the closed and bounded contract."""


class RightsConsumerDeliveryConflict(RightsConsumerDeliveryError):
    """A lifecycle, CAS, or idempotency precondition failed."""


class RightsConsumerDeliveryNotFound(RightsConsumerDeliveryError):
    """A tenant-scoped operator record is absent."""


class RightsConsumerDeliveryPermissionDenied(RightsConsumerDeliveryError):
    """An authenticated server-side principal is required."""


class RightsConsumerDeliveryDenied(RightsConsumerDeliveryError):
    """A deliberately non-enumerating consumer authorization failure."""

    def __init__(self) -> None:
        super().__init__(_UNAVAILABLE)


class RightsConsumerDeliveryIntegrityError(RightsConsumerDeliveryError):
    """Persisted state, history, audit, or signed export failed validation."""


def enabled() -> bool:
    """Return true only when the three exact privacy delivery gates are true."""

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
    orchestration = privacy.get("rights_orchestration") if isinstance(privacy, Mapping) else None
    delivery = privacy.get("rights_consumer_delivery") if isinstance(privacy, Mapping) else None
    return (
        isinstance(privacy, Mapping)
        and privacy.get("enable") is True
        and isinstance(orchestration, Mapping)
        and orchestration.get("enable") is True
        and isinstance(delivery, Mapping)
        and delivery.get("enable") is True
    )


def require_enabled() -> None:
    """Fail closed unless every dependent gate is explicitly enabled."""

    if not enabled():
        raise RightsConsumerDeliveryConfigError(
            "rights consumer delivery is disabled; explicitly enable "
            "privacy_automation, privacy_automation.rights_orchestration, "
            "and privacy_automation.rights_consumer_delivery"
        )


def _runtime_principal() -> str | None:
    try:
        from .connections import current_principal

        return current_principal()
    except Exception:
        return None


def _default_digest_key_resolver(tenant_id: str) -> bytes:
    del tenant_id
    value = os.environ.get("MAVERICK_PRIVACY_RIGHTS_DELIVERY_DIGEST_KEY")
    if value is None or len(value.encode("utf-8")) < 32:
        raise RightsConsumerDeliveryConfigError(
            "MAVERICK_PRIVACY_RIGHTS_DELIVERY_DIGEST_KEY is absent or shorter than 32 bytes"
        )
    return value.encode("utf-8")


def _default_signing_key_resolver(tenant_id: str, key_ref: str) -> bytes:
    del tenant_id
    if not key_ref.startswith("env:"):
        raise RightsConsumerDeliveryConfigError(
            "the default export signer accepts only env: references"
        )
    value = os.environ.get(key_ref.removeprefix("env:"))
    if value is None or len(value.encode("utf-8")) < 32:
        raise RightsConsumerDeliveryConfigError(
            "the rights delivery export key is absent or shorter than 32 bytes"
        )
    return value.encode("utf-8")


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
        raise RightsConsumerDeliveryValidationError(
            "delivery state must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise RightsConsumerDeliveryValidationError(
            "delivery state exceeds its canonical byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise RightsConsumerDeliveryValidationError("tenant_id is invalid") from exc


def _id(
    value: object,
    label: str,
    pattern: re.Pattern[str] = _ID_RE,
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise RightsConsumerDeliveryValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise RightsConsumerDeliveryValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _optional_digest(value: object, label: str) -> str | None:
    return None if value is None else _digest(value, label)


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RightsConsumerDeliveryValidationError(
            f"{label} must be an integer from {minimum} to {maximum}"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RightsConsumerDeliveryValidationError(f"{label} must be a timestamp")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise RightsConsumerDeliveryValidationError(f"{label} must be finite")
    return result


def _optional_timestamp(value: object, label: str) -> float | None:
    return None if value is None else _timestamp(value, label)


def _retained_until(value: object, now: float) -> float:
    retained = _timestamp(value, "retained_until")
    if not now + _MIN_RETENTION_SECONDS <= retained <= now + _MAX_RETENTION_SECONDS:
        raise RightsConsumerDeliveryValidationError(
            "retained_until must be between 60 seconds and one year from now"
        )
    return retained


def _raw_token(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise RightsConsumerDeliveryValidationError(f"{label} is not a valid opaque capability")
    return value


def _token_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise RightsConsumerDeliveryValidationError(f"{label} must be boolean")
    return value


@dataclass(frozen=True)
class ResolvedRightsDeliveryAuthority:
    """Privacy-rights state safe to bind into a consumer capability."""

    tenant_id: str
    case_id: str
    package_id: str
    consumer_subject_binding_sha256: str
    case_revision: int
    case_record_sha256: str
    package_revision: int
    package_record_sha256: str
    identity_status: str
    identity_evidence_sha256: str | None
    completeness_ready: bool
    redaction_ready: bool
    closure_ready: bool
    delivery_object_ref_sha256: str
    package_sha256: str
    package_expires_at: float
    case_retained_until: float
    orchestration_delivery_performed: bool


@dataclass(frozen=True)
class RightsConsumerDelivery:
    tenant_id: str
    delivery_id: str
    case_id: str
    package_id: str
    consumer_subject_binding_sha256: str
    case_revision: int
    case_record_sha256: str
    package_revision: int
    package_record_sha256: str
    identity_evidence_sha256: str
    completeness_ready: bool
    redaction_ready: bool
    closure_ready: bool
    delivery_object_ref_sha256: str
    package_sha256: str
    package_expires_at: float
    case_retained_until: float
    authority_sha256: str
    status: str
    issued_at: float
    expires_at: float
    retained_until: float
    max_attempts: int
    min_attempt_interval_seconds: int
    attempts: int
    last_attempt_at: float | None
    last_request_context_sha256: str | None
    redeemed_at: float | None
    revoked_at: float | None
    revocation_reason_code: str | None
    server_grant_expires_at: float | None
    server_grant_claimed_at: float | None
    created_by_sha256: str
    revision: int
    integrity_sha256: str


@dataclass(frozen=True)
class MintedRightsConsumerDelivery:
    delivery: RightsConsumerDelivery
    capability: str | None
    capability_returned: bool
    idempotent_replay: bool


@dataclass(frozen=True)
class ClaimedServerDeliveryGrant:
    """Server-only authorization metadata; never object credentials or bytes."""

    tenant_id: str
    delivery_id: str
    case_id: str
    package_id: str
    case_revision: int
    case_record_sha256: str
    package_revision: int
    package_record_sha256: str
    delivery_object_ref_sha256: str
    package_sha256: str
    authority_sha256: str
    claimed_at: float


@dataclass(frozen=True)
class SignedRightsConsumerDeliveryExport:
    tenant_id: str
    export_id: str
    delivery_id: str
    schema: str
    body: Mapping[str, object]
    body_sha256: str
    signing_key_ref: str
    signature_hmac_sha256: str
    retained_until: float
    created_by_sha256: str
    created_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class IntegrityVerification:
    tenant_id: str
    verified_records: int
    audit_events: int
    terminal_audit_sha256: str


def _authority_payload(
    authority: ResolvedRightsDeliveryAuthority,
) -> dict[str, object]:
    return {
        "schema": AUTHORITY_SCHEMA,
        "tenant_id": authority.tenant_id,
        "case_id": authority.case_id,
        "package_id": authority.package_id,
        "consumer_subject_binding_sha256": (authority.consumer_subject_binding_sha256),
        "case_revision": authority.case_revision,
        "case_record_sha256": authority.case_record_sha256,
        "package_revision": authority.package_revision,
        "package_record_sha256": authority.package_record_sha256,
        "identity_status": authority.identity_status,
        "identity_evidence_sha256": authority.identity_evidence_sha256,
        "completeness_ready": authority.completeness_ready,
        "redaction_ready": authority.redaction_ready,
        "closure_ready": authority.closure_ready,
        "delivery_object_ref_sha256": authority.delivery_object_ref_sha256,
        "package_sha256": authority.package_sha256,
        "package_expires_at": authority.package_expires_at,
        "case_retained_until": authority.case_retained_until,
        "orchestration_delivery_performed": (authority.orchestration_delivery_performed),
    }


def _normalized_authority(
    value: object,
) -> ResolvedRightsDeliveryAuthority:
    if not isinstance(value, ResolvedRightsDeliveryAuthority):
        raise RightsConsumerDeliveryConfigError(
            "the trusted authorization resolver returned an invalid contract"
        )
    tenant = _tenant(value.tenant_id)
    case = _id(value.case_id, "case_id")
    package = _id(value.package_id, "package_id")
    subject = _digest(
        value.consumer_subject_binding_sha256,
        "consumer_subject_binding_sha256",
    )
    case_revision = _integer(value.case_revision, "case_revision", 1, 1_000_000)
    package_revision = _integer(value.package_revision, "package_revision", 1, 1_000_000)
    identity_status = _id(value.identity_status, "identity_status")
    result = ResolvedRightsDeliveryAuthority(
        tenant_id=tenant,
        case_id=case,
        package_id=package,
        consumer_subject_binding_sha256=subject,
        case_revision=case_revision,
        case_record_sha256=_digest(value.case_record_sha256, "case_record_sha256"),
        package_revision=package_revision,
        package_record_sha256=_digest(value.package_record_sha256, "package_record_sha256"),
        identity_status=identity_status,
        identity_evidence_sha256=_optional_digest(
            value.identity_evidence_sha256, "identity_evidence_sha256"
        ),
        completeness_ready=_bool(value.completeness_ready, "completeness_ready"),
        redaction_ready=_bool(value.redaction_ready, "redaction_ready"),
        closure_ready=_bool(value.closure_ready, "closure_ready"),
        delivery_object_ref_sha256=_digest(
            value.delivery_object_ref_sha256,
            "delivery_object_ref_sha256",
        ),
        package_sha256=_digest(value.package_sha256, "package_sha256"),
        package_expires_at=_timestamp(value.package_expires_at, "package_expires_at"),
        case_retained_until=_timestamp(value.case_retained_until, "case_retained_until"),
        orchestration_delivery_performed=_bool(
            value.orchestration_delivery_performed,
            "orchestration_delivery_performed",
        ),
    )
    if result.package_expires_at > result.case_retained_until:
        raise RightsConsumerDeliveryConfigError(
            "the trusted authorization resolver returned inconsistent retention"
        )
    return result


def resolver_from_orchestration_store(
    store: object,
) -> Callable[[str, str, str], ResolvedRightsDeliveryAuthority]:
    """Bind public orchestration reads into the exact delivery authority.

    The returned callable deliberately invokes only ``get_case`` and
    ``get_response_package``.  It treats an immutable package as revision 1
    because the current public package record has no mutable revision field.
    """

    get_case = getattr(store, "get_case", None)
    get_package = getattr(store, "get_response_package", None)
    if not callable(get_case) or not callable(get_package):
        raise RightsConsumerDeliveryConfigError(
            "the orchestration authority must expose public case and package reads"
        )

    def resolve(
        tenant_id: str,
        case_id: str,
        package_id: str,
    ) -> ResolvedRightsDeliveryAuthority:
        tenant = _tenant(tenant_id)
        case_key = _id(case_id, "case_id")
        package_key = _id(package_id, "package_id")
        rights_case = get_case(tenant, case_key)
        package = get_package(tenant, package_key)
        if (
            getattr(rights_case, "tenant_id", None) != tenant
            or getattr(rights_case, "case_id", None) != case_key
            or getattr(package, "tenant_id", None) != tenant
            or getattr(package, "package_id", None) != package_key
            or getattr(package, "case_id", None) != case_key
        ):
            raise RightsConsumerDeliveryDenied
        closed = (
            getattr(rights_case, "status", None) == "closed"
            and isinstance(getattr(rights_case, "closure_approved_by", None), str)
            and bool(getattr(rights_case, "closure_approved_by", None))
            and isinstance(getattr(rights_case, "closed_by", None), str)
            and bool(getattr(rights_case, "closed_by", None))
        )
        rights = tuple(getattr(rights_case, "rights", ()))
        package_right = bool(set(rights).intersection({"access", "portability"}))
        object_ref = getattr(package, "object_ref", None)
        if not isinstance(object_ref, str) or not object_ref:
            raise RightsConsumerDeliveryDenied
        object_ref_sha256 = _sha256(
            {
                "schema": "lightwork.privacy-rights-delivery-object-ref.v1",
                "tenant_id": tenant,
                "object_ref": object_ref,
            }
        )
        package_revision = getattr(package, "revision", 1)
        return _normalized_authority(
            ResolvedRightsDeliveryAuthority(
                tenant_id=tenant,
                case_id=case_key,
                package_id=package_key,
                consumer_subject_binding_sha256=getattr(rights_case, "subject_sha256", None),
                case_revision=getattr(rights_case, "revision", None),
                case_record_sha256=getattr(rights_case, "integrity_sha256", None),
                package_revision=package_revision,
                package_record_sha256=getattr(package, "integrity_sha256", None),
                identity_status=getattr(rights_case, "identity_status", ""),
                identity_evidence_sha256=getattr(rights_case, "identity_evidence_sha256", None),
                completeness_ready=closed,
                redaction_ready=closed and package_right,
                closure_ready=closed,
                delivery_object_ref_sha256=object_ref_sha256,
                package_sha256=getattr(package, "package_sha256", None),
                package_expires_at=getattr(package, "expires_at", None),
                case_retained_until=getattr(rights_case, "retained_until", None),
                orchestration_delivery_performed=getattr(package, "delivery_performed", None),
            )
        )

    return resolve


_INTERNAL_DELIVERY_FIELDS = frozenset(
    {
        "tenant_id",
        "delivery_id",
        "case_id",
        "package_id",
        "consumer_subject_binding_sha256",
        "case_revision",
        "case_record_sha256",
        "package_revision",
        "package_record_sha256",
        "identity_evidence_sha256",
        "completeness_ready",
        "redaction_ready",
        "closure_ready",
        "delivery_object_ref_sha256",
        "package_sha256",
        "package_expires_at",
        "case_retained_until",
        "orchestration_delivery_performed",
        "authority_sha256",
        "reauthentication_receipt_sha256",
        "capability_sha256",
        "server_grant_sha256",
        "status",
        "issued_at",
        "expires_at",
        "retained_until",
        "max_attempts",
        "min_attempt_interval_seconds",
        "attempts",
        "last_attempt_at",
        "last_request_context_sha256",
        "redeemed_at",
        "revoked_at",
        "revocation_reason_code",
        "server_grant_expires_at",
        "server_grant_claimed_at",
        "created_by_sha256",
        "revision",
    }
)


class RightsConsumerDeliveryStore:
    """Private SQLite authority for short-lived one-time package delivery."""

    def __init__(
        self,
        path: str | Path,
        *,
        authorization_resolver: Callable[[str, str, str], ResolvedRightsDeliveryAuthority],
        current_consumer_binding_resolver: Callable[[], str | None],
        config_gate: Callable[[], None] = require_enabled,
        principal_resolver: Callable[[], str | None] = _runtime_principal,
        digest_key_resolver: Callable[[str], bytes] = _default_digest_key_resolver,
        signing_key_resolver: Callable[[str, str], bytes] = _default_signing_key_resolver,
        clock: Callable[[], float] = time.time,
        capability_factory: Callable[[], str] = lambda: "lwrcd1." + secrets.token_urlsafe(32),
        server_grant_factory: Callable[[], str] = lambda: "lwrcg1." + secrets.token_urlsafe(32),
        server_grant_ttl_seconds: int = 30,
    ) -> None:
        config_gate()
        if not callable(authorization_resolver):
            raise RightsConsumerDeliveryConfigError(
                "a constructor-bound trusted authorization_resolver is required"
            )
        if not callable(current_consumer_binding_resolver):
            raise RightsConsumerDeliveryConfigError(
                "a constructor-bound consumer binding resolver is required"
            )
        if not callable(principal_resolver):
            raise RightsConsumerDeliveryConfigError("principal_resolver must be callable")
        if not callable(digest_key_resolver) or not callable(signing_key_resolver):
            raise RightsConsumerDeliveryConfigError("key resolvers must be callable")
        self._server_grant_ttl_seconds = _integer(
            server_grant_ttl_seconds,
            "server_grant_ttl_seconds",
            _MIN_SERVER_GRANT_SECONDS,
            _MAX_SERVER_GRANT_SECONDS,
        )
        self.path = Path(path)
        self._authorization_resolver = authorization_resolver
        self._current_consumer_binding_resolver = current_consumer_binding_resolver
        self._principal_resolver = principal_resolver
        self._digest_key_resolver = digest_key_resolver
        self._signing_key_resolver = signing_key_resolver
        self._clock = clock
        self._capability_factory = capability_factory
        self._server_grant_factory = server_grant_factory
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, factory=ClosingConnection)
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
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS rights_consumer_deliveries(
                    tenant_id TEXT NOT NULL,delivery_id TEXT NOT NULL,
                    status TEXT NOT NULL,capability_sha256 TEXT NOT NULL UNIQUE,
                    server_grant_sha256 TEXT UNIQUE,expires_at REAL NOT NULL,
                    retained_until REAL NOT NULL,revision INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,delivery_id)
                );
                CREATE INDEX IF NOT EXISTS rights_consumer_delivery_retention
                    ON rights_consumer_deliveries(
                        tenant_id,retained_until,expires_at,status
                    );
                CREATE TABLE IF NOT EXISTS rights_consumer_delivery_history(
                    tenant_id TEXT NOT NULL,delivery_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,delivery_id,revision),
                    FOREIGN KEY(tenant_id,delivery_id)
                        REFERENCES rights_consumer_deliveries(
                            tenant_id,delivery_id
                        ) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS rights_consumer_delivery_exports(
                    tenant_id TEXT NOT NULL,export_id TEXT NOT NULL,
                    delivery_id TEXT NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,export_id),
                    FOREIGN KEY(tenant_id,delivery_id)
                        REFERENCES rights_consumer_deliveries(
                            tenant_id,delivery_id
                        ) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS rights_consumer_delivery_operations(
                    tenant_id TEXT NOT NULL,idempotency_key TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_kind TEXT NOT NULL,
                    result_id TEXT NOT NULL,result_revision INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS rights_consumer_delivery_audit_events(
                    tenant_id TEXT NOT NULL,sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS rights_delivery_history_no_update
                    BEFORE UPDATE ON rights_consumer_delivery_history
                    BEGIN SELECT RAISE(ABORT,'immutable delivery history'); END;
                CREATE TRIGGER IF NOT EXISTS rights_delivery_export_no_update
                    BEFORE UPDATE ON rights_consumer_delivery_exports
                    BEGIN SELECT RAISE(ABORT,'immutable signed export'); END;
                CREATE TRIGGER IF NOT EXISTS rights_delivery_operation_no_update
                    BEFORE UPDATE ON rights_consumer_delivery_operations
                    BEGIN SELECT RAISE(ABORT,'immutable idempotency binding'); END;
                CREATE TRIGGER IF NOT EXISTS rights_delivery_operation_no_delete
                    BEFORE DELETE ON rights_consumer_delivery_operations
                    BEGIN SELECT RAISE(ABORT,'immutable idempotency binding'); END;
                CREATE TRIGGER IF NOT EXISTS rights_delivery_audit_no_update
                    BEFORE UPDATE ON rights_consumer_delivery_audit_events
                    BEGIN SELECT RAISE(ABORT,'immutable audit event'); END;
                CREATE TRIGGER IF NOT EXISTS rights_delivery_audit_no_delete
                    BEFORE DELETE ON rights_consumer_delivery_audit_events
                    BEGIN SELECT RAISE(ABORT,'immutable audit event'); END;
                """
            )
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, SCHEMA_VERSION):
                raise RightsConsumerDeliveryConfigError(
                    f"unsupported rights delivery schema version {version}"
                )
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        ensure_private_file(self.path)

    def _key(self, tenant: str) -> bytes:
        key = self._digest_key_resolver(tenant)
        if not isinstance(key, bytes) or len(key) < 32:
            raise RightsConsumerDeliveryConfigError(
                "the tenant digest key must contain at least 32 bytes"
            )
        return key

    def _actor_sha256(self, tenant: str) -> str:
        actor = self._principal_resolver()
        if not isinstance(actor, str) or not actor or len(actor) > 1_024:
            raise RightsConsumerDeliveryPermissionDenied(
                "an authenticated runtime principal is required"
            )
        return hmac.new(
            self._key(tenant),
            _canonical(
                {
                    "schema": "lightwork.rights-delivery-principal.v1",
                    "tenant_id": tenant,
                    "principal": actor,
                }
            ),
            hashlib.sha256,
        ).hexdigest()

    def _consumer_binding(self) -> str:
        value = self._current_consumer_binding_resolver()
        return _digest(value, "current consumer binding")

    @staticmethod
    def _payload(
        row: sqlite3.Row,
        label: str,
        tenant: str,
    ) -> tuple[dict[str, Any], str]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise RightsConsumerDeliveryIntegrityError(f"{label} contains invalid JSON") from exc
        if not isinstance(payload, dict) or payload.get("tenant_id") != tenant:
            raise RightsConsumerDeliveryIntegrityError(f"{label} tenant binding is invalid")
        digest_value = _sha256(payload)
        if not hmac.compare_digest(digest_value, str(row["integrity_sha256"])):
            raise RightsConsumerDeliveryIntegrityError(f"{label} integrity check failed")
        return payload, digest_value

    @staticmethod
    def _insert(
        connection: sqlite3.Connection,
        table: str,
        columns: tuple[str, ...],
        values: tuple[object, ...],
        payload: Mapping[str, object],
    ) -> str:
        digest_value = _sha256(payload)
        names = ",".join((*columns, "payload_json", "integrity_sha256"))
        placeholders = ",".join("?" for _ in range(len(columns) + 2))
        connection.execute(
            f"INSERT INTO {table}({names}) VALUES({placeholders})",  # noqa: S608
            (*values, _canonical(payload).decode("ascii"), digest_value),
        )
        return digest_value

    def _operation(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        idempotency_key: str,
        request: Mapping[str, object],
    ) -> tuple[str, sqlite3.Row | None]:
        operation = _id(idempotency_key, "idempotency_key", _OP_RE)
        request_sha = _sha256(request)
        row = connection.execute(
            "SELECT * FROM rights_consumer_delivery_operations "
            "WHERE tenant_id=? AND idempotency_key=?",
            (tenant, operation),
        ).fetchone()
        if row is not None:
            payload, _ = self._payload(row, "delivery operation", tenant)
            if (
                payload.get("idempotency_key") != operation
                or payload.get("request_sha256") != request_sha
                or not hmac.compare_digest(request_sha, str(row["request_sha256"]))
            ):
                raise RightsConsumerDeliveryConflict(
                    "idempotency key was already used for a different request"
                )
        return request_sha, row

    def _record_operation(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        idempotency_key: str,
        request_sha256: str,
        result_kind: str,
        result_id: str,
        result_revision: int,
    ) -> None:
        payload = {
            "tenant_id": tenant,
            "idempotency_key": idempotency_key,
            "request_sha256": request_sha256,
            "result_kind": _id(result_kind, "result_kind"),
            "result_id": _id(result_id, "result_id", _OP_RE),
            "result_revision": _integer(result_revision, "result_revision", 0, 1_000_000),
        }
        self._insert(
            connection,
            "rights_consumer_delivery_operations",
            (
                "tenant_id",
                "idempotency_key",
                "request_sha256",
                "result_kind",
                "result_id",
                "result_revision",
            ),
            (
                tenant,
                idempotency_key,
                request_sha256,
                result_kind,
                result_id,
                result_revision,
            ),
            payload,
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        event_type: str,
        object_ref: str,
        actor_sha256: str,
        details: Mapping[str, object],
        occurred_at: float,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 "
            "FROM rights_consumer_delivery_audit_events "
            "WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
            (tenant,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = "0" * 64 if previous is None else str(previous["integrity_sha256"])
        payload = {
            "tenant_id": tenant,
            "schema": AUDIT_SCHEMA,
            "sequence": sequence,
            "event_type": _id(event_type, "event_type"),
            "object_ref": _id(object_ref, "object_ref", _OP_RE),
            "actor_sha256": _digest(actor_sha256, "actor_sha256"),
            "details": dict(details),
            "occurred_at": occurred_at,
            "previous_integrity_sha256": previous_sha,
        }
        digest_value = _sha256(payload)
        connection.execute(
            "INSERT INTO rights_consumer_delivery_audit_events VALUES(?,?,?,?)",
            (
                tenant,
                sequence,
                _canonical(payload).decode("ascii"),
                digest_value,
            ),
        )

    def _resolve(
        self,
        tenant: str,
        case_id: str,
        package_id: str,
    ) -> ResolvedRightsDeliveryAuthority:
        authority = _normalized_authority(self._authorization_resolver(tenant, case_id, package_id))
        if (
            authority.tenant_id != tenant
            or authority.case_id != case_id
            or authority.package_id != package_id
        ):
            raise RightsConsumerDeliveryDenied
        return authority

    @staticmethod
    def _ready(authority: ResolvedRightsDeliveryAuthority, now: float) -> bool:
        return (
            authority.identity_status == "verified"
            and authority.identity_evidence_sha256 is not None
            and authority.completeness_ready
            and authority.redaction_ready
            and authority.closure_ready
            and not authority.orchestration_delivery_performed
            and authority.package_expires_at > now
            and authority.case_retained_until > now
        )

    @staticmethod
    def _authority_from_payload(
        payload: Mapping[str, object],
    ) -> ResolvedRightsDeliveryAuthority:
        return _normalized_authority(
            ResolvedRightsDeliveryAuthority(
                tenant_id=payload["tenant_id"],  # type: ignore[arg-type]
                case_id=payload["case_id"],  # type: ignore[arg-type]
                package_id=payload["package_id"],  # type: ignore[arg-type]
                consumer_subject_binding_sha256=payload["consumer_subject_binding_sha256"],  # type: ignore[arg-type]
                case_revision=payload["case_revision"],  # type: ignore[arg-type]
                case_record_sha256=payload["case_record_sha256"],  # type: ignore[arg-type]
                package_revision=payload["package_revision"],  # type: ignore[arg-type]
                package_record_sha256=payload["package_record_sha256"],  # type: ignore[arg-type]
                identity_status="verified",
                identity_evidence_sha256=payload["identity_evidence_sha256"],  # type: ignore[arg-type]
                completeness_ready=payload["completeness_ready"],  # type: ignore[arg-type]
                redaction_ready=payload["redaction_ready"],  # type: ignore[arg-type]
                closure_ready=payload["closure_ready"],  # type: ignore[arg-type]
                delivery_object_ref_sha256=payload["delivery_object_ref_sha256"],  # type: ignore[arg-type]
                package_sha256=payload["package_sha256"],  # type: ignore[arg-type]
                package_expires_at=payload["package_expires_at"],  # type: ignore[arg-type]
                case_retained_until=payload["case_retained_until"],  # type: ignore[arg-type]
                orchestration_delivery_performed=payload["orchestration_delivery_performed"],  # type: ignore[arg-type]
            )
        )

    def _validated_internal_delivery(
        self,
        payload: Mapping[str, object],
    ) -> dict[str, Any]:
        if set(payload) != _INTERNAL_DELIVERY_FIELDS:
            raise RightsConsumerDeliveryIntegrityError("delivery record fields are invalid")
        try:
            tenant = _tenant(payload["tenant_id"])
            delivery_id = _id(payload["delivery_id"], "delivery_id")
            case_id = _id(payload["case_id"], "case_id")
            package_id = _id(payload["package_id"], "package_id")
            subject = _digest(
                payload["consumer_subject_binding_sha256"],
                "consumer_subject_binding_sha256",
            )
            case_revision = _integer(payload["case_revision"], "case_revision", 1, 1_000_000)
            package_revision = _integer(
                payload["package_revision"], "package_revision", 1, 1_000_000
            )
            identity_evidence = _digest(
                payload["identity_evidence_sha256"],
                "identity_evidence_sha256",
            )
            authority = self._authority_from_payload(payload)
            authority_sha = _digest(payload["authority_sha256"], "authority_sha256")
            if not hmac.compare_digest(authority_sha, _sha256(_authority_payload(authority))):
                raise RightsConsumerDeliveryIntegrityError("delivery authority digest is invalid")
            reauth = _digest(
                payload["reauthentication_receipt_sha256"],
                "reauthentication_receipt_sha256",
            )
            capability = _digest(payload["capability_sha256"], "capability_sha256")
            server_grant = _optional_digest(payload["server_grant_sha256"], "server_grant_sha256")
            status = _id(payload["status"], "status")
            if status not in _DELIVERY_STATES:
                raise RightsConsumerDeliveryIntegrityError("delivery status is invalid")
            issued_at = _timestamp(payload["issued_at"], "issued_at")
            expires_at = _timestamp(payload["expires_at"], "expires_at")
            retained_until = _timestamp(payload["retained_until"], "retained_until")
            max_attempts = _integer(payload["max_attempts"], "max_attempts", 1, _MAX_ATTEMPTS)
            interval = _integer(
                payload["min_attempt_interval_seconds"],
                "min_attempt_interval_seconds",
                0,
                _MAX_ATTEMPT_INTERVAL_SECONDS,
            )
            attempts = _integer(payload["attempts"], "attempts", 0, max_attempts)
            last_attempt = _optional_timestamp(payload["last_attempt_at"], "last_attempt_at")
            last_context = _optional_digest(
                payload["last_request_context_sha256"],
                "last_request_context_sha256",
            )
            redeemed_at = _optional_timestamp(payload["redeemed_at"], "redeemed_at")
            revoked_at = _optional_timestamp(payload["revoked_at"], "revoked_at")
            reason = payload["revocation_reason_code"]
            if reason is not None:
                reason = _id(reason, "revocation_reason_code")
            grant_expires = _optional_timestamp(
                payload["server_grant_expires_at"],
                "server_grant_expires_at",
            )
            grant_claimed = _optional_timestamp(
                payload["server_grant_claimed_at"],
                "server_grant_claimed_at",
            )
            created_by = _digest(payload["created_by_sha256"], "created_by_sha256")
            revision = _integer(payload["revision"], "revision", 1, 1_000_000)
            if not issued_at < expires_at <= authority.package_expires_at:
                raise RightsConsumerDeliveryIntegrityError("delivery expiry binding is invalid")
            if not expires_at <= retained_until <= authority.case_retained_until:
                raise RightsConsumerDeliveryIntegrityError("delivery retention binding is invalid")
            if attempts == 0 and (last_attempt is not None or last_context is not None):
                raise RightsConsumerDeliveryIntegrityError(
                    "delivery attempt evidence is inconsistent"
                )
            if attempts > 0 and (last_attempt is None or last_context is None):
                raise RightsConsumerDeliveryIntegrityError(
                    "delivery attempt evidence is incomplete"
                )
            if status == "active" and any(
                value is not None
                for value in (server_grant, redeemed_at, grant_expires, grant_claimed)
            ):
                raise RightsConsumerDeliveryIntegrityError(
                    "active delivery contains a server grant"
                )
            if status in {"redeemed", "claimed"} and any(
                value is None for value in (server_grant, redeemed_at, grant_expires)
            ):
                raise RightsConsumerDeliveryIntegrityError(
                    "redeemed delivery grant evidence is incomplete"
                )
            if status == "redeemed" and grant_claimed is not None:
                raise RightsConsumerDeliveryIntegrityError(
                    "unclaimed server grant contains a claim timestamp"
                )
            if status == "claimed" and grant_claimed is None:
                raise RightsConsumerDeliveryIntegrityError(
                    "claimed server grant has no claim timestamp"
                )
            if status == "revoked" and (revoked_at is None or reason is None):
                raise RightsConsumerDeliveryIntegrityError(
                    "revoked delivery evidence is incomplete"
                )
            if status != "revoked" and (revoked_at is not None or reason is not None):
                raise RightsConsumerDeliveryIntegrityError(
                    "non-revoked delivery contains revocation evidence"
                )
        except RightsConsumerDeliveryIntegrityError:
            raise
        except RightsConsumerDeliveryError as exc:
            raise RightsConsumerDeliveryIntegrityError("delivery record validation failed") from exc
        return {
            "tenant_id": tenant,
            "delivery_id": delivery_id,
            "case_id": case_id,
            "package_id": package_id,
            "consumer_subject_binding_sha256": subject,
            "case_revision": case_revision,
            "case_record_sha256": authority.case_record_sha256,
            "package_revision": package_revision,
            "package_record_sha256": authority.package_record_sha256,
            "identity_evidence_sha256": identity_evidence,
            "completeness_ready": authority.completeness_ready,
            "redaction_ready": authority.redaction_ready,
            "closure_ready": authority.closure_ready,
            "delivery_object_ref_sha256": authority.delivery_object_ref_sha256,
            "package_sha256": authority.package_sha256,
            "package_expires_at": authority.package_expires_at,
            "case_retained_until": authority.case_retained_until,
            "orchestration_delivery_performed": (authority.orchestration_delivery_performed),
            "authority_sha256": authority_sha,
            "reauthentication_receipt_sha256": reauth,
            "capability_sha256": capability,
            "server_grant_sha256": server_grant,
            "status": status,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "retained_until": retained_until,
            "max_attempts": max_attempts,
            "min_attempt_interval_seconds": interval,
            "attempts": attempts,
            "last_attempt_at": last_attempt,
            "last_request_context_sha256": last_context,
            "redeemed_at": redeemed_at,
            "revoked_at": revoked_at,
            "revocation_reason_code": reason,
            "server_grant_expires_at": grant_expires,
            "server_grant_claimed_at": grant_claimed,
            "created_by_sha256": created_by,
            "revision": revision,
        }

    def _delivery(
        self,
        payload: Mapping[str, object],
        integrity_sha256: str,
    ) -> RightsConsumerDelivery:
        row = self._validated_internal_delivery(payload)
        return RightsConsumerDelivery(
            **{
                key: value
                for key, value in row.items()
                if key
                not in {
                    "reauthentication_receipt_sha256",
                    "capability_sha256",
                    "server_grant_sha256",
                    "orchestration_delivery_performed",
                }
            },
            integrity_sha256=integrity_sha256,
        )

    def _get_delivery_payload(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        delivery_id: str,
        *,
        revision: int | None = None,
    ) -> tuple[dict[str, Any], str]:
        if revision is None:
            row = connection.execute(
                "SELECT * FROM rights_consumer_deliveries WHERE tenant_id=? AND delivery_id=?",
                (tenant, delivery_id),
            ).fetchone()
            label = "consumer delivery"
        else:
            row = connection.execute(
                "SELECT * FROM rights_consumer_delivery_history "
                "WHERE tenant_id=? AND delivery_id=? AND revision=?",
                (tenant, delivery_id, revision),
            ).fetchone()
            label = "consumer delivery history"
        if row is None:
            raise RightsConsumerDeliveryNotFound("consumer delivery was not found")
        payload, digest_value = self._payload(row, label, tenant)
        validated = self._validated_internal_delivery(payload)
        return validated, digest_value

    def _insert_delivery(
        self,
        connection: sqlite3.Connection,
        payload: Mapping[str, object],
    ) -> str:
        digest_value = self._insert(
            connection,
            "rights_consumer_deliveries",
            (
                "tenant_id",
                "delivery_id",
                "status",
                "capability_sha256",
                "server_grant_sha256",
                "expires_at",
                "retained_until",
                "revision",
            ),
            (
                payload["tenant_id"],
                payload["delivery_id"],
                payload["status"],
                payload["capability_sha256"],
                payload["server_grant_sha256"],
                payload["expires_at"],
                payload["retained_until"],
                payload["revision"],
            ),
            payload,
        )
        self._insert(
            connection,
            "rights_consumer_delivery_history",
            ("tenant_id", "delivery_id", "revision", "status"),
            (
                payload["tenant_id"],
                payload["delivery_id"],
                payload["revision"],
                payload["status"],
            ),
            payload,
        )
        return digest_value

    def _write_delivery(
        self,
        connection: sqlite3.Connection,
        payload: Mapping[str, object],
        *,
        expected_revision: int,
    ) -> str:
        digest_value = _sha256(payload)
        changed = connection.execute(
            "UPDATE rights_consumer_deliveries SET status=?,"
            "server_grant_sha256=?,expires_at=?,retained_until=?,revision=?,"
            "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND delivery_id=? "
            "AND revision=?",
            (
                payload["status"],
                payload["server_grant_sha256"],
                payload["expires_at"],
                payload["retained_until"],
                payload["revision"],
                _canonical(payload).decode("ascii"),
                digest_value,
                payload["tenant_id"],
                payload["delivery_id"],
                expected_revision,
            ),
        ).rowcount
        if changed != 1:
            raise RightsConsumerDeliveryConflict("delivery revision CAS failed")
        self._insert(
            connection,
            "rights_consumer_delivery_history",
            ("tenant_id", "delivery_id", "revision", "status"),
            (
                payload["tenant_id"],
                payload["delivery_id"],
                payload["revision"],
                payload["status"],
            ),
            payload,
        )
        return digest_value

    def mint_delivery(
        self,
        tenant_id: str,
        case_id: str,
        package_id: str,
        delivery_id: str,
        *,
        reauthentication_receipt_sha256: str,
        ttl_seconds: int,
        retained_until: float,
        max_attempts: int = 3,
        min_attempt_interval_seconds: int = 1,
        idempotency_key: str,
    ) -> MintedRightsConsumerDelivery:
        """Mint one raw consumer capability and disclose it exactly once."""

        tenant = _tenant(tenant_id)
        case = _id(case_id, "case_id")
        package = _id(package_id, "package_id")
        delivery = _id(delivery_id, "delivery_id")
        reauth = _digest(
            reauthentication_receipt_sha256,
            "reauthentication_receipt_sha256",
        )
        ttl = _integer(
            ttl_seconds,
            "ttl_seconds",
            _MIN_TTL_SECONDS,
            _MAX_TTL_SECONDS,
        )
        attempts_bound = _integer(max_attempts, "max_attempts", 1, _MAX_ATTEMPTS)
        interval = _integer(
            min_attempt_interval_seconds,
            "min_attempt_interval_seconds",
            0,
            _MAX_ATTEMPT_INTERVAL_SECONDS,
        )
        now = _timestamp(self._clock(), "current time")
        retained = _retained_until(retained_until, now)
        expires = now + ttl
        try:
            current_subject = self._consumer_binding()
            authority = self._resolve(tenant, case, package)
        except Exception:
            raise RightsConsumerDeliveryDenied from None
        if (
            not self._ready(authority, now)
            or not hmac.compare_digest(current_subject, authority.consumer_subject_binding_sha256)
            or expires > authority.package_expires_at
            or retained > authority.case_retained_until
        ):
            raise RightsConsumerDeliveryDenied
        actor_sha = self._actor_sha256(tenant)
        authority_sha = _sha256(_authority_payload(authority))
        request = {
            "action": "mint_delivery",
            "delivery_id": delivery,
            "case_id": case,
            "package_id": package,
            "authority_sha256": authority_sha,
            "consumer_subject_binding_sha256": current_subject,
            "reauthentication_receipt_sha256": reauth,
            "ttl_seconds": ttl,
            "retained_until": retained,
            "max_attempts": attempts_bound,
            "min_attempt_interval_seconds": interval,
            "actor_sha256": actor_sha,
        }
        raw_capability: str | None = None
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                if operation["result_kind"] != "delivery":
                    raise RightsConsumerDeliveryIntegrityError("mint replay result kind is invalid")
                payload, digest_value = self._get_delivery_payload(
                    connection,
                    tenant,
                    str(operation["result_id"]),
                    revision=int(operation["result_revision"]),
                )
                return MintedRightsConsumerDelivery(
                    delivery=self._delivery(payload, digest_value),
                    capability=None,
                    capability_returned=False,
                    idempotent_replay=True,
                )
            try:
                raw_capability = _raw_token(
                    self._capability_factory(),
                    "generated capability",
                    _CAPABILITY_RE,
                )
            except RightsConsumerDeliveryValidationError as exc:
                raise RightsConsumerDeliveryConfigError(
                    "capability_factory returned an invalid token"
                ) from exc
            payload = {
                "tenant_id": tenant,
                "delivery_id": delivery,
                "case_id": case,
                "package_id": package,
                "consumer_subject_binding_sha256": current_subject,
                "case_revision": authority.case_revision,
                "case_record_sha256": authority.case_record_sha256,
                "package_revision": authority.package_revision,
                "package_record_sha256": authority.package_record_sha256,
                "identity_evidence_sha256": authority.identity_evidence_sha256,
                "completeness_ready": authority.completeness_ready,
                "redaction_ready": authority.redaction_ready,
                "closure_ready": authority.closure_ready,
                "delivery_object_ref_sha256": (authority.delivery_object_ref_sha256),
                "package_sha256": authority.package_sha256,
                "package_expires_at": authority.package_expires_at,
                "case_retained_until": authority.case_retained_until,
                "orchestration_delivery_performed": (authority.orchestration_delivery_performed),
                "authority_sha256": authority_sha,
                "reauthentication_receipt_sha256": reauth,
                "capability_sha256": _token_sha256(raw_capability),
                "server_grant_sha256": None,
                "status": "active",
                "issued_at": now,
                "expires_at": expires,
                "retained_until": retained,
                "max_attempts": attempts_bound,
                "min_attempt_interval_seconds": interval,
                "attempts": 0,
                "last_attempt_at": None,
                "last_request_context_sha256": None,
                "redeemed_at": None,
                "revoked_at": None,
                "revocation_reason_code": None,
                "server_grant_expires_at": None,
                "server_grant_claimed_at": None,
                "created_by_sha256": actor_sha,
                "revision": 1,
            }
            self._validated_internal_delivery(payload)
            try:
                digest_value = self._insert_delivery(connection, payload)
            except sqlite3.IntegrityError as exc:
                raise RightsConsumerDeliveryConflict(
                    "delivery identifier or generated capability already exists"
                ) from exc
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "delivery",
                delivery,
                1,
            )
            self._audit(
                connection,
                tenant,
                "delivery_capability_minted",
                delivery,
                actor_sha,
                {
                    "case_revision": authority.case_revision,
                    "package_revision": authority.package_revision,
                    "authority_sha256": authority_sha,
                    "expires_at": expires,
                    "max_attempts": attempts_bound,
                },
                now,
            )
            result = self._delivery(payload, digest_value)
        return MintedRightsConsumerDelivery(
            delivery=result,
            capability=raw_capability,
            capability_returned=True,
            idempotent_replay=False,
        )

    def get_delivery(
        self,
        tenant_id: str,
        delivery_id: str,
    ) -> RightsConsumerDelivery:
        tenant = _tenant(tenant_id)
        delivery = _id(delivery_id, "delivery_id")
        self._actor_sha256(tenant)
        with self._connect() as connection:
            payload, digest_value = self._get_delivery_payload(connection, tenant, delivery)
            return self._delivery(payload, digest_value)

    def revoke_delivery(
        self,
        tenant_id: str,
        delivery_id: str,
        *,
        reason_code: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> RightsConsumerDelivery:
        tenant = _tenant(tenant_id)
        delivery = _id(delivery_id, "delivery_id")
        reason = _id(reason_code, "reason_code")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor_sha = self._actor_sha256(tenant)
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "revoke_delivery",
            "delivery_id": delivery,
            "reason_code": reason,
            "expected_revision": expected,
            "actor_sha256": actor_sha,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                payload, digest_value = self._get_delivery_payload(
                    connection,
                    tenant,
                    str(operation["result_id"]),
                    revision=int(operation["result_revision"]),
                )
                return self._delivery(payload, digest_value)
            current, _ = self._get_delivery_payload(connection, tenant, delivery)
            if current["revision"] != expected:
                raise RightsConsumerDeliveryConflict("delivery revision CAS failed")
            if current["status"] not in {"active", "redeemed"}:
                raise RightsConsumerDeliveryConflict(
                    "delivery cannot be revoked in its current state"
                )
            payload = dict(current)
            payload.update(
                {
                    "status": "revoked",
                    "revoked_at": now,
                    "revocation_reason_code": reason,
                    "revision": expected + 1,
                }
            )
            digest_value = self._write_delivery(connection, payload, expected_revision=expected)
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "delivery",
                delivery,
                expected + 1,
            )
            self._audit(
                connection,
                tenant,
                "delivery_capability_revoked",
                delivery,
                actor_sha,
                {"reason_code": reason, "revision": expected + 1},
                now,
            )
            return self._delivery(payload, digest_value)

    @staticmethod
    def _authority_matches(
        current: ResolvedRightsDeliveryAuthority,
        stored: Mapping[str, object],
    ) -> bool:
        stored_authority = RightsConsumerDeliveryStore._authority_from_payload(stored)
        return hmac.compare_digest(
            _sha256(_authority_payload(current)),
            _sha256(_authority_payload(stored_authority)),
        )

    def _failed_attempt(
        self,
        connection: sqlite3.Connection,
        payload: Mapping[str, object],
        *,
        request_context_sha256: str,
        actor_sha256: str,
        reason_code: str,
        now: float,
    ) -> None:
        if payload["status"] != "active":
            return
        current_revision = int(payload["revision"])
        attempt_count = min(int(payload["max_attempts"]), int(payload["attempts"]) + 1)
        status = str(payload["status"])
        if now >= float(payload["expires_at"]):
            status = "expired"
        elif attempt_count >= int(payload["max_attempts"]):
            status = "exhausted"
        changed = dict(payload)
        changed.update(
            {
                "status": status,
                "attempts": attempt_count,
                "last_attempt_at": now,
                "last_request_context_sha256": request_context_sha256,
                "revision": current_revision + 1,
            }
        )
        self._write_delivery(connection, changed, expected_revision=current_revision)
        self._audit(
            connection,
            str(payload["tenant_id"]),
            "delivery_redeem_denied",
            str(payload["delivery_id"]),
            actor_sha256,
            {
                "reason_code": _id(reason_code, "reason_code"),
                "attempts": attempt_count,
                "max_attempts": int(payload["max_attempts"]),
                "status": status,
                "request_context_sha256": request_context_sha256,
            },
            now,
        )

    def redeem(
        self,
        capability: str,
        *,
        reauthentication_receipt_sha256: str,
        request_context_sha256: str,
    ) -> str:
        """Atomically redeem once and return only an opaque server grant.

        Deliberately no tenant, case, package, profile, or subject selector is
        accepted.  Every denial has the same public exception and message.
        """

        try:
            raw = _raw_token(capability, "capability", _CAPABILITY_RE)
            reauth = _digest(
                reauthentication_receipt_sha256,
                "reauthentication_receipt_sha256",
            )
            context = _digest(request_context_sha256, "request_context_sha256")
        except RightsConsumerDeliveryError:
            raise RightsConsumerDeliveryDenied from None
        token_sha = _token_sha256(raw)
        now = _timestamp(self._clock(), "current time")
        denied = False
        raw_server_grant: str | None = None
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM rights_consumer_deliveries WHERE capability_sha256=?",
                (token_sha,),
            ).fetchone()
            if row is None:
                denied = True
            else:
                tenant = _tenant(row["tenant_id"])
                payload, _ = self._payload(row, "consumer delivery", tenant)
                current = self._validated_internal_delivery(payload)
                try:
                    subject = self._consumer_binding()
                except Exception:
                    subject = None
                actor_sha = (
                    subject
                    if subject is not None
                    else _sha256(
                        {
                            "schema": "lightwork.rights-delivery-unknown-consumer.v1",
                            "request_context_sha256": context,
                        }
                    )
                )
                reason: str | None = None
                current_authority: ResolvedRightsDeliveryAuthority | None = None
                if current["status"] != "active":
                    denied = True
                elif now >= float(current["expires_at"]):
                    reason = "expired"
                elif int(current["attempts"]) >= int(current["max_attempts"]):
                    reason = "attempts_exhausted"
                elif current["last_attempt_at"] is not None and now < float(
                    current["last_attempt_at"]
                ) + int(current["min_attempt_interval_seconds"]):
                    reason = "rate_limited"
                elif subject is None or not hmac.compare_digest(
                    subject, str(current["consumer_subject_binding_sha256"])
                ):
                    reason = "consumer_binding_mismatch"
                elif not hmac.compare_digest(
                    reauth, str(current["reauthentication_receipt_sha256"])
                ):
                    reason = "reauthentication_mismatch"
                else:
                    try:
                        current_authority = self._resolve(
                            tenant,
                            str(current["case_id"]),
                            str(current["package_id"]),
                        )
                    except Exception:
                        reason = "authority_unavailable"
                    if current_authority is not None and (
                        not self._ready(current_authority, now)
                        or not self._authority_matches(current_authority, current)
                    ):
                        reason = "authority_drift"
                if reason is not None:
                    self._failed_attempt(
                        connection,
                        current,
                        request_context_sha256=context,
                        actor_sha256=actor_sha,
                        reason_code=reason,
                        now=now,
                    )
                    denied = True
                elif not denied:
                    try:
                        raw_server_grant = _raw_token(
                            self._server_grant_factory(),
                            "generated server grant",
                            _SERVER_GRANT_RE,
                        )
                    except RightsConsumerDeliveryValidationError as exc:
                        raise RightsConsumerDeliveryConfigError(
                            "server_grant_factory returned an invalid token"
                        ) from exc
                    current_revision = int(current["revision"])
                    changed = dict(current)
                    changed.update(
                        {
                            "status": "redeemed",
                            "attempts": int(current["attempts"]) + 1,
                            "last_attempt_at": now,
                            "last_request_context_sha256": context,
                            "redeemed_at": now,
                            "server_grant_sha256": _token_sha256(raw_server_grant),
                            "server_grant_expires_at": min(
                                float(current["expires_at"]),
                                now + self._server_grant_ttl_seconds,
                            ),
                            "revision": current_revision + 1,
                        }
                    )
                    try:
                        self._write_delivery(
                            connection,
                            changed,
                            expected_revision=current_revision,
                        )
                    except sqlite3.IntegrityError as exc:
                        raise RightsConsumerDeliveryConflict(
                            "generated server grant collided"
                        ) from exc
                    self._audit(
                        connection,
                        tenant,
                        "delivery_capability_redeemed",
                        str(current["delivery_id"]),
                        actor_sha,
                        {
                            "authority_sha256": current["authority_sha256"],
                            "request_context_sha256": context,
                            "attempts": changed["attempts"],
                            "server_grant_expires_at": changed["server_grant_expires_at"],
                        },
                        now,
                    )
        if denied or raw_server_grant is None:
            raise RightsConsumerDeliveryDenied
        return raw_server_grant

    def claim_server_grant(self, server_grant: str) -> ClaimedServerDeliveryGrant:
        """Atomically claim an opaque grant for a server-owned delivery adapter."""

        try:
            raw = _raw_token(server_grant, "server_grant", _SERVER_GRANT_RE)
        except RightsConsumerDeliveryError:
            raise RightsConsumerDeliveryDenied from None
        grant_sha = _token_sha256(raw)
        now = _timestamp(self._clock(), "current time")
        result: ClaimedServerDeliveryGrant | None = None
        with self._connect() as connection:
            self._begin(connection)
            row = connection.execute(
                "SELECT * FROM rights_consumer_deliveries WHERE server_grant_sha256=?",
                (grant_sha,),
            ).fetchone()
            if row is not None:
                tenant = _tenant(row["tenant_id"])
                payload, _ = self._payload(row, "consumer delivery", tenant)
                current = self._validated_internal_delivery(payload)
                valid = (
                    current["status"] == "redeemed"
                    and current["server_grant_expires_at"] is not None
                    and now < float(current["server_grant_expires_at"])
                    and current["server_grant_claimed_at"] is None
                )
                current_authority: ResolvedRightsDeliveryAuthority | None = None
                if valid:
                    try:
                        current_authority = self._resolve(
                            tenant,
                            str(current["case_id"]),
                            str(current["package_id"]),
                        )
                    except Exception:
                        valid = False
                if current_authority is not None and (
                    not self._ready(current_authority, now)
                    or not self._authority_matches(current_authority, current)
                ):
                    valid = False
                if valid:
                    actor_sha = self._actor_sha256(tenant)
                    revision = int(current["revision"])
                    changed = dict(current)
                    changed.update(
                        {
                            "status": "claimed",
                            "server_grant_claimed_at": now,
                            "revision": revision + 1,
                        }
                    )
                    self._write_delivery(connection, changed, expected_revision=revision)
                    self._audit(
                        connection,
                        tenant,
                        "server_delivery_grant_claimed",
                        str(current["delivery_id"]),
                        actor_sha,
                        {
                            "authority_sha256": current["authority_sha256"],
                            "package_record_sha256": current["package_record_sha256"],
                        },
                        now,
                    )
                    result = ClaimedServerDeliveryGrant(
                        tenant_id=tenant,
                        delivery_id=str(current["delivery_id"]),
                        case_id=str(current["case_id"]),
                        package_id=str(current["package_id"]),
                        case_revision=int(current["case_revision"]),
                        case_record_sha256=str(current["case_record_sha256"]),
                        package_revision=int(current["package_revision"]),
                        package_record_sha256=str(current["package_record_sha256"]),
                        delivery_object_ref_sha256=str(current["delivery_object_ref_sha256"]),
                        package_sha256=str(current["package_sha256"]),
                        authority_sha256=str(current["authority_sha256"]),
                        claimed_at=now,
                    )
        if result is None:
            raise RightsConsumerDeliveryDenied
        return result

    def export_signed_metadata(
        self,
        tenant_id: str,
        delivery_id: str,
        export_id: str,
        *,
        expected_delivery_revision: int,
        signing_key_ref: str,
        retained_until: float,
        idempotency_key: str,
    ) -> SignedRightsConsumerDeliveryExport:
        """Export signed delivery metadata without any bearer or object secret."""

        tenant = _tenant(tenant_id)
        delivery = _id(delivery_id, "delivery_id")
        export = _id(export_id, "export_id")
        expected = _integer(
            expected_delivery_revision,
            "expected_delivery_revision",
            1,
            1_000_000,
        )
        key_ref = _id(signing_key_ref, "signing_key_ref", _KEY_REF_RE)
        actor_sha = self._actor_sha256(tenant)
        now = _timestamp(self._clock(), "current time")
        retained = _retained_until(retained_until, now)
        request = {
            "action": "export_signed_metadata",
            "delivery_id": delivery,
            "export_id": export,
            "expected_delivery_revision": expected,
            "signing_key_ref": key_ref,
            "retained_until": retained,
            "actor_sha256": actor_sha,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                row = connection.execute(
                    "SELECT * FROM rights_consumer_delivery_exports "
                    "WHERE tenant_id=? AND export_id=?",
                    (tenant, str(operation["result_id"])),
                ).fetchone()
                if row is None:
                    raise RightsConsumerDeliveryIntegrityError(
                        "signed export replay target is unavailable"
                    )
                payload, digest_value = self._payload(row, "signed delivery export", tenant)
                result = self._export(payload, digest_value)
                self._verify_export_signature(result)
                return result
            current, current_digest = self._get_delivery_payload(connection, tenant, delivery)
            if int(current["revision"]) != expected:
                raise RightsConsumerDeliveryConflict("delivery revision CAS failed")
            public = self._delivery(current, current_digest)
            history_rows = connection.execute(
                "SELECT * FROM rights_consumer_delivery_history "
                "WHERE tenant_id=? AND delivery_id=? ORDER BY revision",
                (tenant, delivery),
            ).fetchall()
            history = []
            for row in history_rows:
                history_payload, history_digest = self._payload(
                    row, "consumer delivery history", tenant
                )
                validated = self._validated_internal_delivery(history_payload)
                history.append(
                    {
                        "revision": validated["revision"],
                        "status": validated["status"],
                        "authority_sha256": validated["authority_sha256"],
                        "integrity_sha256": history_digest,
                    }
                )
            audit_tip = connection.execute(
                "SELECT integrity_sha256 "
                "FROM rights_consumer_delivery_audit_events "
                "WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
                (tenant,),
            ).fetchone()
            body = {
                "delivery": asdict(public),
                "history": history,
                "audit_terminal_sha256": (
                    "0" * 64 if audit_tip is None else str(audit_tip["integrity_sha256"])
                ),
                "limitations": dict(self.product_boundaries()),
            }
            body_sha = _sha256(body)
            key = self._signing_key_resolver(tenant, key_ref)
            if not isinstance(key, bytes) or len(key) < 32:
                raise RightsConsumerDeliveryConfigError(
                    "export signing key must contain at least 32 bytes"
                )
            signature = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
            payload = {
                "tenant_id": tenant,
                "export_id": export,
                "delivery_id": delivery,
                "schema": EXPORT_SCHEMA,
                "body": body,
                "body_sha256": body_sha,
                "signing_key_ref": key_ref,
                "signature_hmac_sha256": signature,
                "retained_until": min(retained, float(current["retained_until"])),
                "created_by_sha256": actor_sha,
                "created_at": now,
            }
            digest_value = self._insert(
                connection,
                "rights_consumer_delivery_exports",
                ("tenant_id", "export_id", "delivery_id", "retained_until"),
                (
                    tenant,
                    export,
                    delivery,
                    payload["retained_until"],
                ),
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "export",
                export,
                expected,
            )
            self._audit(
                connection,
                tenant,
                "delivery_metadata_export_signed",
                export,
                actor_sha,
                {
                    "delivery_id": delivery,
                    "delivery_revision": expected,
                    "body_sha256": body_sha,
                },
                now,
            )
            return self._export(payload, digest_value)

    @staticmethod
    def _export(
        payload: Mapping[str, object],
        integrity_sha256: str,
    ) -> SignedRightsConsumerDeliveryExport:
        required = {
            "tenant_id",
            "export_id",
            "delivery_id",
            "schema",
            "body",
            "body_sha256",
            "signing_key_ref",
            "signature_hmac_sha256",
            "retained_until",
            "created_by_sha256",
            "created_at",
        }
        if set(payload) != required or not isinstance(payload["body"], Mapping):
            raise RightsConsumerDeliveryIntegrityError("signed delivery export fields are invalid")
        try:
            return SignedRightsConsumerDeliveryExport(
                tenant_id=_tenant(payload["tenant_id"]),
                export_id=_id(payload["export_id"], "export_id"),
                delivery_id=_id(payload["delivery_id"], "delivery_id"),
                schema=(
                    EXPORT_SCHEMA
                    if payload["schema"] == EXPORT_SCHEMA
                    else (_ for _ in ()).throw(
                        RightsConsumerDeliveryIntegrityError(
                            "signed delivery export schema is invalid"
                        )
                    )
                ),
                body=dict(payload["body"]),
                body_sha256=_digest(payload["body_sha256"], "body_sha256"),
                signing_key_ref=_id(
                    payload["signing_key_ref"],
                    "signing_key_ref",
                    _KEY_REF_RE,
                ),
                signature_hmac_sha256=_digest(
                    payload["signature_hmac_sha256"],
                    "signature_hmac_sha256",
                ),
                retained_until=_timestamp(payload["retained_until"], "retained_until"),
                created_by_sha256=_digest(payload["created_by_sha256"], "created_by_sha256"),
                created_at=_timestamp(payload["created_at"], "created_at"),
                integrity_sha256=integrity_sha256,
            )
        except RightsConsumerDeliveryIntegrityError:
            raise
        except RightsConsumerDeliveryError as exc:
            raise RightsConsumerDeliveryIntegrityError(
                "signed delivery export validation failed"
            ) from exc

    def _verify_export_signature(self, export: SignedRightsConsumerDeliveryExport) -> None:
        if not hmac.compare_digest(_sha256(export.body), export.body_sha256):
            raise RightsConsumerDeliveryIntegrityError(
                "signed delivery export body digest is invalid"
            )
        key = self._signing_key_resolver(export.tenant_id, export.signing_key_ref)
        if not isinstance(key, bytes) or len(key) < 32:
            raise RightsConsumerDeliveryConfigError(
                "export signing key must contain at least 32 bytes"
            )
        expected = hmac.new(key, _canonical(export.body), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, export.signature_hmac_sha256):
            raise RightsConsumerDeliveryIntegrityError(
                "signed delivery export signature is invalid"
            )

    def get_export(
        self,
        tenant_id: str,
        export_id: str,
    ) -> SignedRightsConsumerDeliveryExport:
        tenant = _tenant(tenant_id)
        export = _id(export_id, "export_id")
        self._actor_sha256(tenant)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM rights_consumer_delivery_exports WHERE tenant_id=? AND export_id=?",
                (tenant, export),
            ).fetchone()
            if row is None:
                raise RightsConsumerDeliveryNotFound("signed delivery export was not found")
            payload, digest_value = self._payload(row, "signed delivery export", tenant)
            result = self._export(payload, digest_value)
            self._verify_export_signature(result)
            return result

    def purge_expired(
        self,
        tenant_id: str,
        *,
        cutoff: float,
        idempotency_key: str,
    ) -> Mapping[str, int]:
        """Purge retained delivery state; immutable minimized audit remains."""

        tenant = _tenant(tenant_id)
        moment = _timestamp(cutoff, "cutoff")
        actor_sha = self._actor_sha256(tenant)
        request = {
            "action": "purge_expired",
            "cutoff": moment,
            "actor_sha256": actor_sha,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                parts = str(operation["result_id"]).split(":")
                if len(parts) != 3 or any(not item.isdigit() for item in parts):
                    raise RightsConsumerDeliveryIntegrityError("purge replay result is invalid")
                return {
                    "deliveries": int(parts[0]),
                    "history": int(parts[1]),
                    "exports": int(parts[2]),
                }
            export_count = connection.execute(
                "DELETE FROM rights_consumer_delivery_exports "
                "WHERE tenant_id=? AND retained_until<=?",
                (tenant, moment),
            ).rowcount
            rows = connection.execute(
                "SELECT delivery_id FROM rights_consumer_deliveries "
                "WHERE tenant_id=? AND retained_until<=? AND expires_at<=?",
                (tenant, moment, moment),
            ).fetchall()
            delivery_ids = [str(row["delivery_id"]) for row in rows]
            history_count = 0
            delivery_count = 0
            for delivery in delivery_ids:
                history_count += connection.execute(
                    "DELETE FROM rights_consumer_delivery_history "
                    "WHERE tenant_id=? AND delivery_id=?",
                    (tenant, delivery),
                ).rowcount
                delivery_count += connection.execute(
                    "DELETE FROM rights_consumer_deliveries WHERE tenant_id=? AND delivery_id=?",
                    (tenant, delivery),
                ).rowcount
            result_id = f"{delivery_count}:{history_count}:{export_count}"
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "purge_result",
                result_id,
                0,
            )
            self._audit(
                connection,
                tenant,
                "delivery_retention_purged",
                "retention",
                actor_sha,
                {
                    "cutoff": moment,
                    "deliveries": delivery_count,
                    "history": history_count,
                    "exports": export_count,
                },
                moment,
            )
            return {
                "deliveries": delivery_count,
                "history": history_count,
                "exports": export_count,
            }

    def verify_integrity(self, tenant_id: str) -> IntegrityVerification:
        tenant = _tenant(tenant_id)
        self._actor_sha256(tenant)
        verified = 0
        with self._connect() as connection:
            delivery_rows = connection.execute(
                "SELECT * FROM rights_consumer_deliveries WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            for row in delivery_rows:
                payload, digest_value = self._payload(row, "consumer delivery", tenant)
                current = self._validated_internal_delivery(payload)
                for column in (
                    "delivery_id",
                    "status",
                    "capability_sha256",
                    "server_grant_sha256",
                    "expires_at",
                    "retained_until",
                    "revision",
                ):
                    if str(row[column]) != str(current[column]):
                        raise RightsConsumerDeliveryIntegrityError(
                            f"consumer delivery indexed {column} is inconsistent"
                        )
                latest = connection.execute(
                    "SELECT * FROM rights_consumer_delivery_history "
                    "WHERE tenant_id=? AND delivery_id=? "
                    "ORDER BY revision DESC LIMIT 1",
                    (tenant, current["delivery_id"]),
                ).fetchone()
                if latest is None:
                    raise RightsConsumerDeliveryIntegrityError(
                        "consumer delivery has no immutable history"
                    )
                latest_payload, latest_digest = self._payload(
                    latest, "consumer delivery history", tenant
                )
                self._validated_internal_delivery(latest_payload)
                if latest_payload != current or not hmac.compare_digest(
                    latest_digest, digest_value
                ):
                    raise RightsConsumerDeliveryIntegrityError(
                        "consumer delivery differs from latest history"
                    )
                history_rows = connection.execute(
                    "SELECT * FROM rights_consumer_delivery_history "
                    "WHERE tenant_id=? AND delivery_id=? ORDER BY revision",
                    (tenant, current["delivery_id"]),
                ).fetchall()
                expected_revision = 1
                for history_row in history_rows:
                    history_payload, _ = self._payload(
                        history_row, "consumer delivery history", tenant
                    )
                    history = self._validated_internal_delivery(history_payload)
                    if int(history["revision"]) != expected_revision:
                        raise RightsConsumerDeliveryIntegrityError(
                            "consumer delivery history revision chain is invalid"
                        )
                    expected_revision += 1
                    verified += 1
                verified += 1
            orphan = connection.execute(
                "SELECT 1 FROM rights_consumer_delivery_history h "
                "LEFT JOIN rights_consumer_deliveries d ON "
                "d.tenant_id=h.tenant_id AND d.delivery_id=h.delivery_id "
                "WHERE h.tenant_id=? AND d.delivery_id IS NULL LIMIT 1",
                (tenant,),
            ).fetchone()
            if orphan is not None:
                raise RightsConsumerDeliveryIntegrityError("consumer delivery history is orphaned")
            export_rows = connection.execute(
                "SELECT * FROM rights_consumer_delivery_exports WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            for row in export_rows:
                payload, digest_value = self._payload(row, "signed delivery export", tenant)
                export = self._export(payload, digest_value)
                self._verify_export_signature(export)
                if (
                    row["export_id"] != export.export_id
                    or row["delivery_id"] != export.delivery_id
                    or float(row["retained_until"]) != export.retained_until
                ):
                    raise RightsConsumerDeliveryIntegrityError(
                        "signed delivery export index is inconsistent"
                    )
                verified += 1
            operation_rows = connection.execute(
                "SELECT * FROM rights_consumer_delivery_operations WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            for row in operation_rows:
                payload, _ = self._payload(row, "delivery operation", tenant)
                if (
                    payload.get("idempotency_key") != row["idempotency_key"]
                    or payload.get("request_sha256") != row["request_sha256"]
                    or payload.get("result_kind") != row["result_kind"]
                    or payload.get("result_id") != row["result_id"]
                    or payload.get("result_revision") != row["result_revision"]
                ):
                    raise RightsConsumerDeliveryIntegrityError(
                        "delivery operation index is inconsistent"
                    )
                verified += 1
            audit_rows = connection.execute(
                "SELECT * FROM rights_consumer_delivery_audit_events "
                "WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
            previous_sha = "0" * 64
            expected_sequence = 1
            for row in audit_rows:
                payload, digest_value = self._payload(row, "delivery audit event", tenant)
                if (
                    int(payload.get("sequence", 0)) != expected_sequence
                    or int(row["sequence"]) != expected_sequence
                    or payload.get("previous_integrity_sha256") != previous_sha
                ):
                    raise RightsConsumerDeliveryIntegrityError("delivery audit chain is invalid")
                previous_sha = digest_value
                expected_sequence += 1
                verified += 1
            return IntegrityVerification(
                tenant_id=tenant,
                verified_records=verified,
                audit_events=len(audit_rows),
                terminal_audit_sha256=previous_sha,
            )

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "authority": "local_provider_neutral",
            "authorization_source": "constructor_bound_public_orchestration_resolver",
            "network_io": False,
            "provider_writes": False,
            "object_bytes_returned": False,
            "object_store_credentials_returned": False,
            "encryption_key_values_persisted": False,
            "raw_subject_identifiers_persisted": False,
            "raw_identity_evidence_persisted": False,
            "raw_object_references_persisted": False,
            "raw_capabilities_persisted": False,
            "identity_verification_performed": False,
            "source_system_fulfillment_performed": False,
            "live_source_acceptance_verified": False,
            "live_identity_acceptance_verified": False,
            "estate_completeness_inferred": False,
            "consumer_redeem_returns": "opaque_server_grant_only",
        }


__all__ = [
    "AUDIT_SCHEMA",
    "AUTHORITY_SCHEMA",
    "ClaimedServerDeliveryGrant",
    "EXPORT_SCHEMA",
    "IntegrityVerification",
    "MintedRightsConsumerDelivery",
    "ResolvedRightsDeliveryAuthority",
    "RightsConsumerDelivery",
    "RightsConsumerDeliveryConfigError",
    "RightsConsumerDeliveryConflict",
    "RightsConsumerDeliveryDenied",
    "RightsConsumerDeliveryError",
    "RightsConsumerDeliveryIntegrityError",
    "RightsConsumerDeliveryNotFound",
    "RightsConsumerDeliveryPermissionDenied",
    "RightsConsumerDeliveryStore",
    "RightsConsumerDeliveryValidationError",
    "SignedRightsConsumerDeliveryExport",
    "enabled",
    "require_enabled",
    "resolver_from_orchestration_store",
]
