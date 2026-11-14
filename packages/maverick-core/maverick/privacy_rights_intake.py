"""Authenticated consumer intake for the existing privacy-rights authority.

This module is deliberately a coordinator, not a second rights system.  It
accepts only a server-constructed, digest-only public authority, independently
re-resolves that authority and fresh identity evidence, and drives
``PrivacyRightsOrchestrationStore`` through a recoverable idempotent saga.

No email address, identity token, OIDC subject, reauthentication receipt,
provider credential, or retrieved subject data is accepted or persisted here.
Source selection, legal/retention gates, and destructive approval remain owned
by the existing orchestration authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .privacy_rights_orchestration import CALLBACK_PHASES, RIGHTS
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 2
AUTHORITY_SCHEMA = "lightwork.privacy-rights-intake-authority.v1"
IDENTITY_EVIDENCE_SCHEMA = "lightwork.privacy-rights-identity-evidence.v1"
REQUEST_BINDING_SCHEMA = "lightwork.privacy-rights-intake-binding.v1"
STATUS_SCHEMA = "lightwork.privacy-rights-intake-status.v1"

NETWORK_IO = False
PROVIDER_WRITES = False
IDENTITY_VERIFICATION_PERFORMED = False
RESPONSE_DELIVERY_PERFORMED = False
ESTATE_COMPLETENESS_CLAIMED = False
LIVE_PROVIDER_ACCEPTANCE_VERIFIED = False

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_KEY_REF_RE = re.compile(r"(?:env|vault|secret|kms):[A-Za-z0-9][A-Za-z0-9_.:/-]{0,159}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_JSON_BYTES = 512 * 1024
_MAX_SOURCES = 1_000
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600
_MIN_REQUEST_TTL_SECONDS = 60
_MAX_REQUEST_TTL_SECONDS = 30 * 24 * 3_600
_MAX_ACTIVE_REQUESTS = 10_000
_MAX_IDENTITY_EVIDENCE_TTL_SECONDS = 15 * 60
_CLOCK_SKEW_SECONDS = 60
_CHANNELS = frozenset({"browser-origin", "mobile-app", "service-client", "ott-ctv"})
_IDENTITY_METHODS = frozenset({"account-session", "email-link", "oidc", "passkey", "provider-idv"})
_ASSURANCE_LEVELS = {"low": 1, "substantial": 2, "high": 3}
_RIGHT_PHASES = {
    "access": ("discover", "retrieve", "redact"),
    "portability": ("discover", "retrieve", "redact"),
    "erasure": ("discover", "delete", "verify_delete"),
    "rectification": ("discover", "rectify"),
    "restriction": ("discover", "restrict"),
    "objection": ("discover", "opt_out"),
    "opt_out": ("discover", "opt_out"),
}


class PrivacyRightsIntakeError(RuntimeError):
    """Base error for authenticated consumer rights intake."""


class PrivacyRightsIntakeConfigError(PrivacyRightsIntakeError):
    """Configuration or an injected authority is unavailable."""


class PrivacyRightsIntakeValidationError(PrivacyRightsIntakeError, ValueError):
    """Input is outside the closed intake contract."""


class PrivacyRightsIntakeConflict(PrivacyRightsIntakeError):
    """Authority, idempotency, source, or orchestration state drifted."""


class PrivacyRightsIntakeNotFound(PrivacyRightsIntakeError):
    """A subject-bound request is absent or deliberately undisclosed."""


class PrivacyRightsIntakeIntegrityError(PrivacyRightsIntakeError):
    """Persisted or signed evidence failed exact integrity verification."""


def enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Require every parent plus the exact default-off intake gate."""

    if config is None:
        try:
            from .config import config_source_errors, load_config

            if config_source_errors():
                return False
            config = load_config()
        except Exception:
            return False
    if not isinstance(config, Mapping):
        return False
    consent = config.get("consent_preferences")
    privacy = config.get("privacy_automation")
    if not isinstance(consent, Mapping) or not isinstance(privacy, Mapping):
        return False
    required_consent = ("publishing", "public_api", "trust_center")
    required_privacy = ("rights_orchestration", "rights_consumer_intake")
    return (
        consent.get("enable") is True
        and privacy.get("enable") is True
        and all(
            isinstance(consent.get(name), Mapping) and consent[name].get("enable") is True
            for name in required_consent
        )
        and all(
            isinstance(privacy.get(name), Mapping) and privacy[name].get("enable") is True
            for name in required_privacy
        )
    )


def require_enabled() -> None:
    if not enabled():
        raise PrivacyRightsIntakeConfigError(
            "consumer rights intake requires consent publishing, public API, "
            "Trust Center, privacy automation, rights orchestration, and "
            "rights_consumer_intake"
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
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise PrivacyRightsIntakeValidationError("intake metadata must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise PrivacyRightsIntakeValidationError("intake metadata exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _same(left: object, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))
    except UnicodeEncodeError:
        return False


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise PrivacyRightsIntakeValidationError("tenant authority is invalid") from exc


def _ref(
    value: object,
    label: str,
    pattern: re.Pattern[str] = _REF_RE,
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PrivacyRightsIntakeValidationError(f"{label} is not a closed reference")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise PrivacyRightsIntakeValidationError(f"{label} is not a SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PrivacyRightsIntakeValidationError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PrivacyRightsIntakeValidationError(f"{label} is not a finite timestamp")
    normalized = float(value)
    if not math.isfinite(normalized) or not 0 < normalized < 100_000_000_000.0:
        raise PrivacyRightsIntakeValidationError(f"{label} is not a finite timestamp")
    return normalized


def _rights(value: object) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise PrivacyRightsIntakeValidationError("rights must be a closed sequence")
    items = tuple(value)
    if not 1 <= len(items) <= len(RIGHTS):
        raise PrivacyRightsIntakeValidationError("rights count is outside its bound")
    if any(not isinstance(item, str) or item not in RIGHTS for item in items):
        raise PrivacyRightsIntakeValidationError("rights contain an unsupported code")
    if len(set(items)) != len(items):
        raise PrivacyRightsIntakeValidationError("rights contain duplicates")
    return tuple(sorted(items))


def _required_phases(rights: Sequence[str]) -> tuple[str, ...]:
    phases: list[str] = []
    # Keep retrieval ahead of deletion, matching the orchestration authority.
    for right in _RIGHT_PHASES:
        if right not in rights:
            continue
        for phase in _RIGHT_PHASES[right]:
            if phase not in phases:
                phases.append(phase)
    return tuple(phases)


@dataclass(frozen=True)
class ConsumerRightsIntakeAuthority:
    """Digest-only snapshot of an admitted public client/profile context."""

    tenant_id: str
    property_sha256: str
    property_revision: int
    profile_sha256: str
    profile_credential_sha256: str
    profile_binding_sha256: str
    profile_revision: int
    subject_binding_sha256: str
    client_credential_sha256: str
    client_record_sha256: str
    client_revision: int
    publication_sha256: str
    publication_bundle_sha256: str
    configuration_sha256: str
    policy_sha256: str
    policy_version: int
    trust_context_sha256: str
    trust_context_revision: int
    capability_grant_sha256: str
    channel: str
    channel_binding_sha256: str
    identity_authority_sha256: str
    minimum_identity_assurance: str
    valid_until: float
    revoked: bool = False

    def normalized(self) -> ConsumerRightsIntakeAuthority:
        tenant = _tenant(self.tenant_id)
        for name in (
            "property_sha256",
            "profile_sha256",
            "profile_credential_sha256",
            "profile_binding_sha256",
            "subject_binding_sha256",
            "client_credential_sha256",
            "client_record_sha256",
            "publication_sha256",
            "publication_bundle_sha256",
            "configuration_sha256",
            "policy_sha256",
            "trust_context_sha256",
            "capability_grant_sha256",
            "channel_binding_sha256",
            "identity_authority_sha256",
        ):
            _digest(getattr(self, name), name)
        for name in (
            "property_revision",
            "profile_revision",
            "client_revision",
            "policy_version",
            "trust_context_revision",
        ):
            _integer(getattr(self, name), name, 1, 2**31 - 1)
        if self.channel not in _CHANNELS:
            raise PrivacyRightsIntakeValidationError("channel is unsupported")
        if self.minimum_identity_assurance not in _ASSURANCE_LEVELS:
            raise PrivacyRightsIntakeValidationError("minimum identity assurance is unsupported")
        if not isinstance(self.revoked, bool):
            raise PrivacyRightsIntakeValidationError("authority revocation state is invalid")
        _timestamp(self.valid_until, "authority valid_until")
        if tenant != self.tenant_id:
            raise PrivacyRightsIntakeValidationError("tenant authority is not canonical")
        if self.identity_authority_sha256 in {
            self.subject_binding_sha256,
            self.profile_binding_sha256,
            self.client_record_sha256,
        }:
            raise PrivacyRightsIntakeValidationError(
                "identity authority must be independent from subject/client authority"
            )
        return self

    @property
    def authority_sha256(self) -> str:
        return _sha256({"schema": AUTHORITY_SCHEMA, **asdict(self.normalized())})


@dataclass(frozen=True)
class ConsumerRightsIdentityEvidence:
    """Ephemeral result returned only by the injected identity authority."""

    schema: str
    tenant_id: str
    property_sha256: str
    profile_sha256: str
    profile_binding_sha256: str
    subject_binding_sha256: str
    channel: str
    channel_binding_sha256: str
    verification_authority_sha256: str
    verification_method: str
    assurance_level: str
    evidence_ref: str
    evidence_revision: int
    verified_at: float
    valid_until: float
    revoked: bool
    evidence_sha256: str

    def normalized(self) -> ConsumerRightsIdentityEvidence:
        tenant = _tenant(self.tenant_id)
        if self.schema != IDENTITY_EVIDENCE_SCHEMA:
            raise PrivacyRightsIntakeValidationError("identity evidence schema is unsupported")
        for name in (
            "property_sha256",
            "profile_sha256",
            "profile_binding_sha256",
            "subject_binding_sha256",
            "channel_binding_sha256",
            "verification_authority_sha256",
        ):
            _digest(getattr(self, name), name)
        if self.channel not in _CHANNELS:
            raise PrivacyRightsIntakeValidationError("identity evidence channel is unsupported")
        if self.verification_method not in _IDENTITY_METHODS:
            raise PrivacyRightsIntakeValidationError("identity verification method is unsupported")
        if self.assurance_level not in _ASSURANCE_LEVELS:
            raise PrivacyRightsIntakeValidationError("identity assurance level is unsupported")
        _ref(self.evidence_ref, "identity evidence_ref")
        _integer(self.evidence_revision, "evidence_revision", 1, 2**31 - 1)
        verified = _timestamp(self.verified_at, "identity verified_at")
        valid = _timestamp(self.valid_until, "identity valid_until")
        if valid <= verified or valid - verified > _MAX_IDENTITY_EVIDENCE_TTL_SECONDS:
            raise PrivacyRightsIntakeValidationError(
                "identity evidence freshness window is invalid"
            )
        if not isinstance(self.revoked, bool):
            raise PrivacyRightsIntakeValidationError(
                "identity evidence revocation state is invalid"
            )
        supplied = _digest(self.evidence_sha256, "identity evidence_sha256")
        body = asdict(self)
        body.pop("evidence_sha256")
        if not _same(supplied, _sha256(body)):
            raise PrivacyRightsIntakeValidationError("identity evidence digest does not verify")
        if tenant != self.tenant_id:
            raise PrivacyRightsIntakeValidationError("identity evidence tenant is not canonical")
        return self


@dataclass(frozen=True)
class ConsumerRightsSigningKey:
    """Ephemeral key material; only its authority metadata enters status."""

    tenant_id: str
    key_ref: str
    revision: int
    key: bytes
    valid_from: float
    valid_until: float
    revoked: bool = False

    def normalized(self) -> ConsumerRightsSigningKey:
        tenant = _tenant(self.tenant_id)
        _ref(self.key_ref, "signing key_ref", _KEY_REF_RE)
        _integer(self.revision, "signing key revision", 1, 2**31 - 1)
        start = _timestamp(self.valid_from, "signing key valid_from")
        end = _timestamp(self.valid_until, "signing key valid_until")
        if end <= start:
            raise PrivacyRightsIntakeValidationError("signing key validity window is invalid")
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            raise PrivacyRightsIntakeValidationError("signing key material is unavailable")
        if not isinstance(self.revoked, bool):
            raise PrivacyRightsIntakeValidationError("signing key revocation state is invalid")
        if tenant != self.tenant_id:
            raise PrivacyRightsIntakeValidationError("signing key tenant is not canonical")
        return self

    @property
    def authority_sha256(self) -> str:
        value = self.normalized()
        return _sha256(
            {
                "tenant_id": value.tenant_id,
                "key_ref": value.key_ref,
                "revision": value.revision,
                "valid_from": value.valid_from,
                "valid_until": value.valid_until,
                "revoked": value.revoked,
            }
        )


@dataclass(frozen=True)
class SignedConsumerRightsStatus:
    payload: Mapping[str, object]
    signing_key_ref: str
    signing_key_revision: int
    signing_key_authority_sha256: str
    signature: str
    evidence_sha256: str


def _default_signing_key_resolver(
    tenant_id: str,
    key_ref: str | None,
    revision: int | None,
) -> ConsumerRightsSigningKey:
    expected_ref = "env:MAVERICK_PRIVACY_RIGHTS_INTAKE_SIGNING_KEY"
    if key_ref not in {None, expected_ref} or revision not in {None, 1}:
        raise PrivacyRightsIntakeConfigError("consumer rights intake signing key is unavailable")
    value = os.environ.get("MAVERICK_PRIVACY_RIGHTS_INTAKE_SIGNING_KEY")
    if value is None or len(value.encode("utf-8")) < 32:
        raise PrivacyRightsIntakeConfigError(
            "MAVERICK_PRIVACY_RIGHTS_INTAKE_SIGNING_KEY is absent or too short"
        )
    return ConsumerRightsSigningKey(
        tenant_id=tenant_id,
        key_ref=expected_ref,
        revision=1,
        key=value.encode("utf-8"),
        valid_from=1.0,
        valid_until=99_999_999_999.0,
    )


class PrivacyRightsIntakeStore:
    """Recoverable subject-bound coordinator over one rights store."""

    def __init__(  # noqa: PLR0913 - every callable is an authority seam
        self,
        path: str | Path,
        *,
        rights_store: object,
        authority_resolver: Callable[[], ConsumerRightsIntakeAuthority],
        identity_evidence_resolver: Callable[[], ConsumerRightsIdentityEvidence],
        signing_key_resolver: Callable[
            [str, str | None, int | None], ConsumerRightsSigningKey
        ] = _default_signing_key_resolver,
        request_ttl_seconds: int = 86_400,
        retention_seconds: int = 365 * 24 * 3_600,
        max_active_requests: int = 1_000,
        max_active_requests_per_subject: int | None = None,
        maintenance_authorizer: Callable[[], bool] = lambda: False,
        config_gate: Callable[[], None] = require_enabled,
        clock: Callable[[], float] = time.time,
    ) -> None:
        config_gate()
        required = (
            "open_case",
            "get_case",
            "set_identity_verification",
            "get_source",
            "list_sources",
            "plan_source_tasks",
        )
        if any(not callable(getattr(rights_store, name, None)) for name in required):
            raise PrivacyRightsIntakeConfigError(
                "privacy-rights orchestration authority is incomplete"
            )
        if not all(
            callable(item)
            for item in (
                authority_resolver,
                identity_evidence_resolver,
                signing_key_resolver,
                maintenance_authorizer,
                config_gate,
                clock,
            )
        ):
            raise PrivacyRightsIntakeConfigError(
                "consumer intake authority dependencies are incomplete"
            )
        self.path = Path(path)
        self._rights = rights_store
        self._authority_resolver = authority_resolver
        self._identity_evidence_resolver = identity_evidence_resolver
        self._signing_key_resolver = signing_key_resolver
        self._request_ttl_seconds = _integer(
            request_ttl_seconds,
            "request_ttl_seconds",
            _MIN_REQUEST_TTL_SECONDS,
            _MAX_REQUEST_TTL_SECONDS,
        )
        self._retention_seconds = _integer(
            retention_seconds,
            "retention_seconds",
            60,
            _MAX_RETENTION_SECONDS,
        )
        self._max_active_requests = _integer(
            max_active_requests,
            "max_active_requests",
            1,
            _MAX_ACTIVE_REQUESTS,
        )
        subject_limit = (
            min(25, self._max_active_requests)
            if max_active_requests_per_subject is None
            else max_active_requests_per_subject
        )
        self._max_active_requests_per_subject = _integer(
            subject_limit,
            "max_active_requests_per_subject",
            1,
            self._max_active_requests,
        )
        self._maintenance_authorizer = maintenance_authorizer
        self._gate = config_gate
        self._clock = clock
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS consumer_rights_intake_requests(
                    tenant_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('creating','active')),
                    revision INTEGER NOT NULL,
                    retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,case_id)
                );
                CREATE TABLE IF NOT EXISTS consumer_rights_intake_operations(
                    tenant_id TEXT NOT NULL,
                    key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,key_sha256),
                    FOREIGN KEY(tenant_id,case_id)
                        REFERENCES consumer_rights_intake_requests(tenant_id,case_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS consumer_rights_intake_active(
                    tenant_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    subject_binding_sha256 TEXT NOT NULL,
                    active_until REAL NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,case_id),
                    FOREIGN KEY(tenant_id,case_id)
                        REFERENCES consumer_rights_intake_requests(tenant_id,case_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS consumer_rights_intake_active_tenant_idx
                    ON consumer_rights_intake_active(tenant_id,active_until);
                CREATE INDEX IF NOT EXISTS consumer_rights_intake_active_subject_idx
                    ON consumer_rights_intake_active(
                        tenant_id,subject_binding_sha256,active_until
                    );
                CREATE TABLE IF NOT EXISTS consumer_rights_intake_audit(
                    tenant_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    request_integrity_sha256 TEXT NOT NULL,
                    previous_sha256 TEXT,
                    event_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(tenant_id,case_id,sequence),
                    FOREIGN KEY(tenant_id,case_id)
                        REFERENCES consumer_rights_intake_requests(tenant_id,case_id)
                        ON DELETE CASCADE
                );
                CREATE TRIGGER IF NOT EXISTS consumer_rights_intake_operations_no_update
                    BEFORE UPDATE ON consumer_rights_intake_operations
                    BEGIN SELECT RAISE(ABORT,'immutable consumer intake idempotency'); END;
                CREATE TRIGGER IF NOT EXISTS consumer_rights_intake_audit_no_update
                    BEFORE UPDATE ON consumer_rights_intake_audit
                    BEGIN SELECT RAISE(ABORT,'immutable consumer intake audit'); END;
                CREATE TRIGGER IF NOT EXISTS consumer_rights_intake_active_no_update
                    BEFORE UPDATE ON consumer_rights_intake_active
                    BEGIN SELECT RAISE(ABORT,'immutable consumer intake quota binding'); END;
                """
            )
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, 1, SCHEMA_VERSION):
                raise PrivacyRightsIntakeConfigError(
                    f"unsupported consumer rights intake schema version {version}"
                )
            missing_active = connection.execute(
                "SELECT requests.* FROM consumer_rights_intake_requests AS requests "
                "LEFT JOIN consumer_rights_intake_active AS active "
                "ON active.tenant_id=requests.tenant_id AND active.case_id=requests.case_id "
                "WHERE active.case_id IS NULL ORDER BY requests.tenant_id,requests.case_id"
            ).fetchall()
            for row in missing_active:
                payload = self._payload(row)
                authority = self._authority(payload["authority"])
                connection.execute(
                    "INSERT INTO consumer_rights_intake_active VALUES(?,?,?,?,?)",
                    (
                        row["tenant_id"],
                        row["case_id"],
                        authority.subject_binding_sha256,
                        payload["active_until"],
                        _sha256(
                            {
                                "tenant_id": row["tenant_id"],
                                "case_id": row["case_id"],
                                "subject_binding_sha256": (
                                    authority.subject_binding_sha256
                                ),
                                "active_until": payload["active_until"],
                            }
                        ),
                    ),
                )
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        ensure_private_file(self.path)

    def _now(self) -> float:
        return _timestamp(self._clock(), "current time")

    @staticmethod
    def _authority_payload(authority: ConsumerRightsIntakeAuthority) -> dict[str, Any]:
        normalized = authority.normalized()
        return {
            "schema": AUTHORITY_SCHEMA,
            **asdict(normalized),
            "authority_sha256": normalized.authority_sha256,
        }

    @staticmethod
    def _authority(value: object) -> ConsumerRightsIntakeAuthority:
        if not isinstance(value, Mapping):
            raise PrivacyRightsIntakeIntegrityError("stored consumer authority is invalid")
        body = dict(value)
        if body.pop("schema", None) != AUTHORITY_SCHEMA:
            raise PrivacyRightsIntakeIntegrityError("stored consumer authority schema is invalid")
        supplied = body.pop("authority_sha256", None)
        try:
            authority = ConsumerRightsIntakeAuthority(**body).normalized()
        except (TypeError, PrivacyRightsIntakeError) as exc:
            raise PrivacyRightsIntakeIntegrityError("stored consumer authority is invalid") from exc
        if not _same(supplied, authority.authority_sha256):
            raise PrivacyRightsIntakeIntegrityError("stored consumer authority changed")
        return authority

    @staticmethod
    def _identity_payload(evidence: ConsumerRightsIdentityEvidence) -> dict[str, Any]:
        normalized = evidence.normalized()
        return {
            "evidence_sha256": normalized.evidence_sha256,
            "evidence_ref_sha256": _text_sha256(normalized.evidence_ref),
            "evidence_revision": normalized.evidence_revision,
            "verified_at": normalized.verified_at,
            "valid_until": normalized.valid_until,
            "verification_authority_sha256": (normalized.verification_authority_sha256),
            "verification_method": normalized.verification_method,
            "assurance_level": normalized.assurance_level,
            "channel": normalized.channel,
            "channel_binding_sha256": normalized.channel_binding_sha256,
            "subject_binding_sha256": normalized.subject_binding_sha256,
        }

    @staticmethod
    def _validate_identity_payload(value: object) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) != {
            "evidence_sha256",
            "evidence_ref_sha256",
            "evidence_revision",
            "verified_at",
            "valid_until",
            "verification_authority_sha256",
            "verification_method",
            "assurance_level",
            "channel",
            "channel_binding_sha256",
            "subject_binding_sha256",
        }:
            raise PrivacyRightsIntakeIntegrityError("stored identity evidence pins are invalid")
        result = dict(value)
        for name in (
            "evidence_sha256",
            "evidence_ref_sha256",
            "verification_authority_sha256",
            "channel_binding_sha256",
            "subject_binding_sha256",
        ):
            _digest(result[name], name)
        _integer(result["evidence_revision"], "evidence_revision", 1, 2**31 - 1)
        verified = _timestamp(result["verified_at"], "identity verified_at")
        valid = _timestamp(result["valid_until"], "identity valid_until")
        if valid <= verified or valid - verified > _MAX_IDENTITY_EVIDENCE_TTL_SECONDS:
            raise PrivacyRightsIntakeIntegrityError("stored identity evidence freshness is invalid")
        if result["verification_method"] not in _IDENTITY_METHODS:
            raise PrivacyRightsIntakeIntegrityError(
                "stored identity verification method is invalid"
            )
        if result["assurance_level"] not in _ASSURANCE_LEVELS:
            raise PrivacyRightsIntakeIntegrityError("stored identity assurance is invalid")
        if result["channel"] not in _CHANNELS:
            raise PrivacyRightsIntakeIntegrityError("stored identity channel is invalid")
        return result

    @staticmethod
    def _source_plan(value: object, tenant: str) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) != {
            "source_id",
            "source_revision",
            "source_integrity_sha256",
            "capabilities",
            "phases",
        }:
            raise PrivacyRightsIntakeIntegrityError("stored source plan is invalid")
        source_id = _ref(value["source_id"], "source_id")
        revision = _integer(value["source_revision"], "source_revision", 1, 2**31 - 1)
        integrity = _digest(value["source_integrity_sha256"], "source_integrity_sha256")
        capabilities = value["capabilities"]
        phases = value["phases"]
        if (
            not isinstance(capabilities, list)
            or not isinstance(phases, list)
            or not phases
            or any(not isinstance(item, str) for item in capabilities + phases)
            or len(capabilities) != len(set(capabilities))
            or len(phases) != len(set(phases))
        ):
            raise PrivacyRightsIntakeIntegrityError("stored source plan is invalid")
        del tenant
        return {
            "source_id": source_id,
            "source_revision": revision,
            "source_integrity_sha256": integrity,
            "capabilities": capabilities,
            "phases": phases,
        }

    @classmethod
    def _payload(cls, row: sqlite3.Row) -> dict[str, Any]:
        raw = row["payload_json"]
        if not isinstance(raw, str) or not 1 <= len(raw.encode("utf-8")) <= _MAX_JSON_BYTES:
            raise PrivacyRightsIntakeIntegrityError("stored consumer intake request is invalid")
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise PrivacyRightsIntakeIntegrityError(
                "stored consumer intake request is invalid"
            ) from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != REQUEST_BINDING_SCHEMA
            or payload.get("tenant_id") != row["tenant_id"]
            or payload.get("case_id") != row["case_id"]
            or payload.get("state") != row["state"]
            or payload.get("revision") != row["revision"]
            or payload.get("retained_until") != row["retained_until"]
            or not _same(_sha256(payload), row["integrity_sha256"])
        ):
            raise PrivacyRightsIntakeIntegrityError("stored consumer intake request changed")
        authority = cls._authority(payload.get("authority"))
        created_at = _timestamp(payload.get("created_at"), "request created_at")
        active_until = _timestamp(payload.get("active_until"), "request active_until")
        if not created_at < active_until <= float(row["retained_until"]):
            raise PrivacyRightsIntakeIntegrityError(
                "stored consumer intake active window is invalid"
            )
        if authority.tenant_id != row["tenant_id"]:
            raise PrivacyRightsIntakeIntegrityError(
                "stored consumer intake authority tenant changed"
            )
        cls._validate_identity_payload(payload.get("initial_identity_evidence"))
        normalized_rights = _rights(payload.get("rights"))
        if list(normalized_rights) != payload.get("rights"):
            raise PrivacyRightsIntakeIntegrityError("stored request rights changed")
        plans = payload.get("source_plans")
        if not isinstance(plans, list) or len(plans) > _MAX_SOURCES:
            raise PrivacyRightsIntakeIntegrityError("stored source plans are invalid")
        normalized_plans = [cls._source_plan(item, str(row["tenant_id"])) for item in plans]
        if normalized_plans != plans:
            raise PrivacyRightsIntakeIntegrityError("stored source plan order changed")
        if len({item["source_id"] for item in plans}) != len(plans):
            raise PrivacyRightsIntakeIntegrityError("stored source plans are duplicated")
        return payload

    @staticmethod
    def _operation_body(row: sqlite3.Row) -> dict[str, Any]:
        body = {
            "tenant_id": str(row["tenant_id"]),
            "key_sha256": str(row["key_sha256"]),
            "request_sha256": str(row["request_sha256"]),
            "case_id": str(row["case_id"]),
            "created_at": float(row["created_at"]),
        }
        for name in ("key_sha256", "request_sha256"):
            _digest(body[name], name)
        if not _same(_sha256(body), row["integrity_sha256"]):
            raise PrivacyRightsIntakeIntegrityError("stored intake idempotency binding changed")
        return body

    @staticmethod
    def _active_body(row: sqlite3.Row) -> dict[str, Any]:
        body = {
            "tenant_id": _tenant(row["tenant_id"]),
            "case_id": _ref(row["case_id"], "case_id"),
            "subject_binding_sha256": _digest(
                row["subject_binding_sha256"],
                "subject_binding_sha256",
            ),
            "active_until": _timestamp(row["active_until"], "active_until"),
        }
        if not _same(_sha256(body), row["integrity_sha256"]):
            raise PrivacyRightsIntakeIntegrityError(
                "stored consumer intake quota binding changed"
            )
        return body

    @staticmethod
    def _audit_event(
        *,
        tenant_id: str,
        case_id: str,
        sequence: int,
        event_type: str,
        request_integrity_sha256: str,
        previous_sha256: str | None,
        created_at: float,
    ) -> dict[str, Any]:
        return {
            "tenant_id": tenant_id,
            "case_id": case_id,
            "sequence": sequence,
            "event_type": event_type,
            "request_integrity_sha256": request_integrity_sha256,
            "previous_sha256": previous_sha256,
            "created_at": created_at,
        }

    def _insert_audit(
        self,
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        case_id: str,
        event_type: str,
        request_integrity_sha256: str,
        created_at: float,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence,event_sha256 FROM consumer_rights_intake_audit "
            "WHERE tenant_id=? AND case_id=? ORDER BY sequence DESC LIMIT 1",
            (tenant_id, case_id),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = None if previous is None else str(previous["event_sha256"])
        event = self._audit_event(
            tenant_id=tenant_id,
            case_id=case_id,
            sequence=sequence,
            event_type=event_type,
            request_integrity_sha256=request_integrity_sha256,
            previous_sha256=previous_sha,
            created_at=created_at,
        )
        connection.execute(
            "INSERT INTO consumer_rights_intake_audit VALUES(?,?,?,?,?,?,?,?)",
            (
                tenant_id,
                case_id,
                sequence,
                event_type,
                request_integrity_sha256,
                previous_sha,
                _sha256(event),
                created_at,
            ),
        )

    def _resolve_authority(
        self,
        expected: ConsumerRightsIntakeAuthority,
        now: float,
    ) -> ConsumerRightsIntakeAuthority:
        if not isinstance(expected, ConsumerRightsIntakeAuthority):
            raise PrivacyRightsIntakeValidationError(
                "consumer authority must be server constructed"
            )
        expected = expected.normalized()
        if expected.revoked or expected.valid_until <= now:
            raise PrivacyRightsIntakeConflict("consumer authority is expired or revoked")
        try:
            first = self._authority_resolver()
            second = self._authority_resolver()
        except PrivacyRightsIntakeError:
            raise
        except Exception as exc:
            raise PrivacyRightsIntakeConflict("consumer authority is unavailable") from exc
        if not isinstance(first, ConsumerRightsIntakeAuthority) or not isinstance(
            second, ConsumerRightsIntakeAuthority
        ):
            raise PrivacyRightsIntakeConflict("consumer authority is unavailable")
        first = first.normalized()
        second = second.normalized()
        if (
            first.revoked
            or second.revoked
            or first.valid_until <= now
            or second.valid_until <= now
            or not _same(first.authority_sha256, expected.authority_sha256)
            or not _same(second.authority_sha256, expected.authority_sha256)
        ):
            raise PrivacyRightsIntakeConflict("consumer authority changed")
        return second

    def _resolve_identity(
        self,
        authority: ConsumerRightsIntakeAuthority,
        now: float,
    ) -> ConsumerRightsIdentityEvidence:
        try:
            first = self._identity_evidence_resolver()
            second = self._identity_evidence_resolver()
        except PrivacyRightsIntakeError:
            raise
        except Exception as exc:
            raise PrivacyRightsIntakeConflict(
                "independent identity evidence is unavailable"
            ) from exc
        if not isinstance(first, ConsumerRightsIdentityEvidence) or not isinstance(
            second, ConsumerRightsIdentityEvidence
        ):
            raise PrivacyRightsIntakeConflict("independent identity evidence is unavailable")
        first = first.normalized()
        second = second.normalized()
        if not _same(first.evidence_sha256, second.evidence_sha256):
            raise PrivacyRightsIntakeConflict("identity evidence changed during resolution")
        for evidence in (first, second):
            if (
                evidence.revoked
                or evidence.verified_at > now + _CLOCK_SKEW_SECONDS
                or evidence.valid_until <= now
                or evidence.tenant_id != authority.tenant_id
                or not _same(evidence.property_sha256, authority.property_sha256)
                or not _same(evidence.profile_sha256, authority.profile_sha256)
                or not _same(
                    evidence.profile_binding_sha256,
                    authority.profile_binding_sha256,
                )
                or not _same(
                    evidence.subject_binding_sha256,
                    authority.subject_binding_sha256,
                )
                or evidence.channel != authority.channel
                or not _same(
                    evidence.channel_binding_sha256,
                    authority.channel_binding_sha256,
                )
                or not _same(
                    evidence.verification_authority_sha256,
                    authority.identity_authority_sha256,
                )
                or _ASSURANCE_LEVELS[evidence.assurance_level]
                < _ASSURANCE_LEVELS[authority.minimum_identity_assurance]
            ):
                raise PrivacyRightsIntakeConflict(
                    "identity evidence is stale, revoked, self-asserted, or misbound"
                )
        return second

    def _resolve_for_mutation(
        self,
        expected: ConsumerRightsIntakeAuthority,
        initial_identity: Mapping[str, Any],
    ) -> tuple[ConsumerRightsIntakeAuthority, ConsumerRightsIdentityEvidence]:
        now = self._now()
        authority = self._resolve_authority(expected, now)
        evidence = self._resolve_identity(authority, now)
        if self._identity_payload(evidence) != dict(initial_identity):
            raise PrivacyRightsIntakeConflict(
                "identity evidence changed while request creation was incomplete"
            )
        return authority, evidence

    def _source_plans(
        self,
        tenant_id: str,
        requested_rights: Sequence[str],
    ) -> list[dict[str, Any]]:
        required = _required_phases(requested_rights)
        try:
            sources = self._rights.list_sources(tenant_id, limit=_MAX_SOURCES)
        except Exception as exc:
            raise PrivacyRightsIntakeConflict("rights source authority is unavailable") from exc
        if not isinstance(sources, tuple) or len(sources) > _MAX_SOURCES:
            raise PrivacyRightsIntakeConflict("rights source authority is invalid")
        plans: list[dict[str, Any]] = []
        seen: set[str] = set()
        for source in sorted(sources, key=lambda item: str(getattr(item, "source_id", ""))):
            source_id = _ref(getattr(source, "source_id", None), "source_id")
            if source_id in seen:
                raise PrivacyRightsIntakeConflict("rights sources are duplicated")
            seen.add(source_id)
            capabilities = getattr(source, "capabilities", None)
            if (
                getattr(source, "tenant_id", None) != tenant_id
                or getattr(source, "state", None) != "active"
                or not isinstance(capabilities, tuple)
            ):
                continue
            phases = [phase for phase in required if phase in capabilities]
            if phases:
                plans.append(
                    {
                        "source_id": source_id,
                        "source_revision": _integer(
                            getattr(source, "revision", None),
                            "source_revision",
                            1,
                            2**31 - 1,
                        ),
                        "source_integrity_sha256": _digest(
                            getattr(source, "integrity_sha256", None),
                            "source_integrity_sha256",
                        ),
                        "capabilities": list(capabilities),
                        "phases": phases,
                    }
                )
        return plans

    def _validate_source_plan(self, tenant_id: str, plan: Mapping[str, Any]) -> None:
        normalized = self._source_plan(plan, tenant_id)
        try:
            source = self._rights.get_source(tenant_id, normalized["source_id"])
        except Exception as exc:
            raise PrivacyRightsIntakeConflict("pinned rights source is unavailable") from exc
        if (
            getattr(source, "tenant_id", None) != tenant_id
            or getattr(source, "source_id", None) != normalized["source_id"]
            or getattr(source, "state", None) != "active"
            or getattr(source, "revision", None) != normalized["source_revision"]
            or tuple(getattr(source, "capabilities", ())) != tuple(normalized["capabilities"])
            or not _same(
                getattr(source, "integrity_sha256", None),
                normalized["source_integrity_sha256"],
            )
        ):
            raise PrivacyRightsIntakeConflict("pinned rights source changed")

    def _operation(
        self,
        tenant_id: str,
        key_sha256: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM consumer_rights_intake_operations "
                "WHERE tenant_id=? AND key_sha256=?",
                (tenant_id, key_sha256),
            ).fetchone()
            if row is None:
                return None
            operation = self._operation_body(row)
            if not _same(operation["request_sha256"], request_sha256):
                raise PrivacyRightsIntakeConflict(
                    "idempotency key is bound to another rights request"
                )
            request_row = connection.execute(
                "SELECT * FROM consumer_rights_intake_requests WHERE tenant_id=? AND case_id=?",
                (tenant_id, operation["case_id"]),
            ).fetchone()
            if request_row is None:
                raise PrivacyRightsIntakeIntegrityError("idempotent intake request is missing")
            return self._payload(request_row)

    def _reserve(
        self,
        authority: ConsumerRightsIntakeAuthority,
        evidence: ConsumerRightsIdentityEvidence,
        requested_rights: tuple[str, ...],
        source_plans: Sequence[Mapping[str, Any]],
        *,
        key_sha256: str,
        request_sha256: str,
        now: float,
    ) -> dict[str, Any]:
        tenant = authority.tenant_id
        case_digest = _sha256(
            {
                "schema": "lightwork.privacy-rights-intake-case-id.v1",
                "tenant_sha256": _text_sha256(tenant),
                "key_sha256": key_sha256,
                "authority_sha256": authority.authority_sha256,
                "rights": list(requested_rights),
            }
        )
        case_id = f"PRI-{case_digest[:40]}"
        retained_until = now + self._retention_seconds
        active_until = min(now + self._request_ttl_seconds, retained_until)
        identity = self._identity_payload(evidence)
        plans = [dict(plan) for plan in source_plans]
        payload: dict[str, Any] = {
            "schema": REQUEST_BINDING_SCHEMA,
            "tenant_id": tenant,
            "case_id": case_id,
            "rights": list(requested_rights),
            "authority": self._authority_payload(authority),
            "initial_identity_evidence": identity,
            "request_sha256": request_sha256,
            "operation_key_sha256": key_sha256,
            "source_plans": plans,
            "source_snapshot_sha256": _sha256(plans),
            "state": "creating",
            "revision": 0,
            "created_case_revision": None,
            "created_case_sha256": None,
            "case_subject_sha256": None,
            "case_external_request_sha256": None,
            "planned_source_count": 0,
            "planned_callback_count": 0,
            "created_at": now,
            "updated_at": now,
            "active_until": active_until,
            "retained_until": retained_until,
        }
        operation = {
            "tenant_id": tenant,
            "key_sha256": key_sha256,
            "request_sha256": request_sha256,
            "case_id": case_id,
            "created_at": now,
        }
        request_integrity = _sha256(payload)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing_operation = connection.execute(
                    "SELECT * FROM consumer_rights_intake_operations "
                    "WHERE tenant_id=? AND key_sha256=?",
                    (tenant, key_sha256),
                ).fetchone()
                if existing_operation is not None:
                    existing_body = self._operation_body(existing_operation)
                    if not _same(existing_body["request_sha256"], request_sha256):
                        raise PrivacyRightsIntakeConflict(
                            "idempotency key is bound to another rights request"
                        )
                    existing_request = connection.execute(
                        "SELECT * FROM consumer_rights_intake_requests "
                        "WHERE tenant_id=? AND case_id=?",
                        (tenant, existing_body["case_id"]),
                    ).fetchone()
                    if existing_request is None:
                        raise PrivacyRightsIntakeIntegrityError(
                            "idempotent intake request is missing"
                        )
                    connection.commit()
                    return self._payload(existing_request)

                tenant_active_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM consumer_rights_intake_active "
                        "WHERE tenant_id=? AND active_until>?",
                        (tenant, now),
                    ).fetchone()[0]
                )
                if tenant_active_count >= self._max_active_requests:
                    raise PrivacyRightsIntakeConflict(
                        "maximum active tenant consumer rights requests reached"
                    )
                subject_active_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM consumer_rights_intake_active "
                        "WHERE tenant_id=? AND subject_binding_sha256=? AND active_until>?",
                        (tenant, authority.subject_binding_sha256, now),
                    ).fetchone()[0]
                )
                if subject_active_count >= self._max_active_requests_per_subject:
                    raise PrivacyRightsIntakeConflict(
                        "maximum active subject consumer rights requests reached"
                    )
                connection.execute(
                    "INSERT INTO consumer_rights_intake_requests VALUES(?,?,?,?,?,?,?)",
                    (
                        tenant,
                        case_id,
                        "creating",
                        0,
                        retained_until,
                        _canonical(payload).decode("ascii"),
                        request_integrity,
                    ),
                )
                connection.execute(
                    "INSERT INTO consumer_rights_intake_active VALUES(?,?,?,?,?)",
                    (
                        tenant,
                        case_id,
                        authority.subject_binding_sha256,
                        active_until,
                        _sha256(
                            {
                                "tenant_id": tenant,
                                "case_id": case_id,
                                "subject_binding_sha256": (
                                    authority.subject_binding_sha256
                                ),
                                "active_until": active_until,
                            }
                        ),
                    ),
                )
                connection.execute(
                    "INSERT INTO consumer_rights_intake_operations VALUES(?,?,?,?,?,?)",
                    (
                        tenant,
                        key_sha256,
                        request_sha256,
                        case_id,
                        now,
                        _sha256(operation),
                    ),
                )
                self._insert_audit(
                    connection,
                    tenant_id=tenant,
                    case_id=case_id,
                    event_type="request_reserved",
                    request_integrity_sha256=request_integrity,
                    created_at=now,
                )
                connection.commit()
            return payload
        except sqlite3.IntegrityError:
            existing = self._operation(tenant, key_sha256, request_sha256)
            if existing is None:
                raise PrivacyRightsIntakeConflict(
                    "consumer intake request changed concurrently"
                ) from None
            return existing

    @staticmethod
    def _case_matches(
        rights_case: object,
        payload: Mapping[str, Any],
        evidence: Mapping[str, Any],
    ) -> bool:
        return (
            getattr(rights_case, "tenant_id", None) == payload["tenant_id"]
            and getattr(rights_case, "case_id", None) == payload["case_id"]
            and tuple(getattr(rights_case, "rights", ())) == tuple(payload["rights"])
            and getattr(rights_case, "identity_status", None) == "verified"
            and _same(
                getattr(rights_case, "identity_evidence_sha256", None),
                evidence["evidence_sha256"],
            )
            and getattr(rights_case, "identity_evidence_ref", None)
            == f"PRI-IDV-{str(evidence['evidence_ref_sha256'])[:40]}"
        )

    def _finalize(
        self,
        payload: Mapping[str, Any],
        rights_case: object,
        callback_count: int,
    ) -> dict[str, Any]:
        tenant = str(payload["tenant_id"])
        case_id = str(payload["case_id"])
        final = dict(payload)
        final.update(
            {
                "state": "active",
                "revision": 1,
                "created_case_revision": getattr(rights_case, "revision", None),
                "created_case_sha256": getattr(rights_case, "integrity_sha256", None),
                "case_subject_sha256": getattr(rights_case, "subject_sha256", None),
                "case_external_request_sha256": getattr(
                    rights_case, "external_request_sha256", None
                ),
                "planned_source_count": len(payload["source_plans"]),
                "planned_callback_count": callback_count,
                "updated_at": self._now(),
            }
        )
        for name in (
            "created_case_sha256",
            "case_subject_sha256",
            "case_external_request_sha256",
        ):
            _digest(final[name], name)
        original_integrity = _sha256(dict(payload))
        final_integrity = _sha256(final)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE consumer_rights_intake_requests SET state='active',revision=1,"
                "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND case_id=? "
                "AND state='creating' AND revision=0 AND integrity_sha256=?",
                (
                    _canonical(final).decode("ascii"),
                    final_integrity,
                    tenant,
                    case_id,
                    original_integrity,
                ),
            )
            if updated.rowcount == 1:
                self._insert_audit(
                    connection,
                    tenant_id=tenant,
                    case_id=case_id,
                    event_type="request_activated",
                    request_integrity_sha256=final_integrity,
                    created_at=float(final["updated_at"]),
                )
                connection.commit()
                return final
            current_row = connection.execute(
                "SELECT * FROM consumer_rights_intake_requests WHERE tenant_id=? AND case_id=?",
                (tenant, case_id),
            ).fetchone()
            if current_row is None:
                raise PrivacyRightsIntakeIntegrityError(
                    "consumer intake request disappeared during finalization"
                )
            current = self._payload(current_row)
            comparable = dict(final)
            comparable["updated_at"] = current.get("updated_at")
            if current != comparable:
                raise PrivacyRightsIntakeConflict(
                    "consumer intake finalization changed concurrently"
                )
            connection.commit()
            return current

    def _resume(
        self,
        payload: Mapping[str, Any],
        authority: ConsumerRightsIntakeAuthority,
    ) -> dict[str, Any]:
        stored = self._authority(payload.get("authority"))
        if not _same(stored.authority_sha256, authority.authority_sha256):
            raise PrivacyRightsIntakeConflict("stored consumer authority changed")
        if payload.get("state") == "active":
            return dict(payload)
        if payload.get("state") != "creating" or payload.get("revision") != 0:
            raise PrivacyRightsIntakeIntegrityError("consumer intake request state is invalid")
        tenant = authority.tenant_id
        case_id = _ref(payload.get("case_id"), "case_id")
        requested_rights = _rights(payload.get("rights"))
        initial_identity = self._validate_identity_payload(payload.get("initial_identity_evidence"))

        _, evidence = self._resolve_for_mutation(authority, initial_identity)
        rights_case = self._rights.open_case(
            tenant,
            case_id,
            request_version=1,
            external_request_ref=f"{case_id}:{payload['request_sha256']}",
            subject_reference=authority.subject_binding_sha256,
            rights=requested_rights,
            retained_until=float(payload["retained_until"]),
            idempotency_key=f"pri-open-{case_id}",
        )
        if (
            getattr(rights_case, "tenant_id", None) != tenant
            or getattr(rights_case, "case_id", None) != case_id
            or tuple(getattr(rights_case, "rights", ())) != requested_rights
        ):
            raise PrivacyRightsIntakeConflict(
                "privacy-rights case authority changed during opening"
            )

        _, evidence = self._resolve_for_mutation(authority, initial_identity)
        evidence_ref = f"PRI-IDV-{_text_sha256(evidence.evidence_ref)[:40]}"
        if getattr(rights_case, "identity_status", None) == "unverified":
            rights_case = self._rights.set_identity_verification(
                tenant,
                case_id,
                status="verified",
                evidence_sha256=evidence.evidence_sha256,
                evidence_ref=evidence_ref,
                expected_revision=1,
                idempotency_key=f"pri-identity-{case_id}",
            )
        elif not self._case_matches(rights_case, payload, initial_identity):
            raise PrivacyRightsIntakeConflict("privacy-rights case identity authority changed")

        raw_plans = payload.get("source_plans")
        if not isinstance(raw_plans, list):
            raise PrivacyRightsIntakeIntegrityError("stored source plans are invalid")
        callback_count = 0
        for index, raw_plan in enumerate(raw_plans):
            plan = self._source_plan(raw_plan, tenant)
            self._resolve_for_mutation(authority, initial_identity)
            self._validate_source_plan(tenant, plan)
            tasks = self._rights.plan_source_tasks(
                tenant,
                case_id,
                plan["source_id"],
                phases=tuple(plan["phases"]),
                expected_case_revision=2 + index,
                idempotency_key=f"pri-plan-{case_id}-{index}",
            )
            task_phases = tuple(getattr(item, "phase", None) for item in tasks)
            if (
                any(getattr(item, "tenant_id", None) != tenant for item in tasks)
                or any(getattr(item, "case_id", None) != case_id for item in tasks)
                or any(getattr(item, "source_id", None) != plan["source_id"] for item in tasks)
                or set(task_phases) != set(plan["phases"])
            ):
                raise PrivacyRightsIntakeConflict("privacy-rights source plan result changed")
            callback_count += sum(phase in CALLBACK_PHASES for phase in plan["phases"])

        self._resolve_for_mutation(authority, initial_identity)
        for raw_plan in raw_plans:
            self._validate_source_plan(tenant, raw_plan)
        rights_case = self._rights.get_case(tenant, case_id)
        if not self._case_matches(rights_case, payload, initial_identity) or getattr(
            rights_case, "revision", None
        ) != 2 + len(raw_plans):
            raise PrivacyRightsIntakeConflict("privacy-rights case changed during request creation")
        return self._finalize(payload, rights_case, callback_count)

    def create_request(
        self,
        authority: ConsumerRightsIntakeAuthority,
        *,
        rights: Sequence[str],
        expected_revision: int,
        idempotency_key: str,
    ) -> SignedConsumerRightsStatus:
        """Open and plan a recoverable request using server-owned authority."""

        self._gate()
        expected = _integer(expected_revision, "expected_revision", 0, 2**31 - 1)
        if expected != 0:
            raise PrivacyRightsIntakeConflict("new consumer rights request requires revision zero")
        requested_rights = _rights(rights)
        raw_key = _ref(idempotency_key, "idempotency_key")
        key_sha = _text_sha256(raw_key)
        now = self._now()
        authority = self._resolve_authority(authority, now)
        evidence = self._resolve_identity(authority, now)
        request_sha = _sha256(
            {
                "action": "create_consumer_rights_request",
                "authority_sha256": authority.authority_sha256,
                "rights": list(requested_rights),
                "expected_revision": 0,
            }
        )
        payload = self._operation(authority.tenant_id, key_sha, request_sha)
        if payload is None:
            source_plans = self._source_plans(authority.tenant_id, requested_rights)
            payload = self._reserve(
                authority,
                evidence,
                requested_rights,
                source_plans,
                key_sha256=key_sha,
                request_sha256=request_sha,
                now=now,
            )
        payload = self._resume(payload, authority)
        return self.get_status(authority, str(payload["case_id"]))

    def _request_payload(
        self,
        tenant_id: str,
        case_id: str,
        now: float,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        case = _ref(case_id, "case_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM consumer_rights_intake_requests WHERE tenant_id=? AND case_id=?",
                (tenant, case),
            ).fetchone()
        if row is None:
            raise PrivacyRightsIntakeNotFound("consumer rights request was not found")
        payload = self._payload(row)
        if float(payload["retained_until"]) <= now:
            raise PrivacyRightsIntakeNotFound("consumer rights request was not found")
        if payload.get("state") != "active" or payload.get("revision") != 1:
            raise PrivacyRightsIntakeConflict("consumer rights request is not ready")
        return payload

    def _signing_key(
        self,
        tenant_id: str,
        *,
        key_ref: str | None,
        revision: int | None,
        at: float,
        for_signing: bool,
    ) -> ConsumerRightsSigningKey:
        try:
            value = self._signing_key_resolver(tenant_id, key_ref, revision)
        except PrivacyRightsIntakeError:
            raise
        except Exception as exc:
            raise PrivacyRightsIntakeConfigError(
                "consumer rights signing key is unavailable"
            ) from exc
        if not isinstance(value, ConsumerRightsSigningKey):
            raise PrivacyRightsIntakeConfigError("consumer rights signing key is unavailable")
        value = value.normalized()
        if (
            value.tenant_id != tenant_id
            or value.revoked
            or not value.valid_from <= at < value.valid_until
            or (key_ref is not None and value.key_ref != key_ref)
            or (revision is not None and value.revision != revision)
        ):
            action = "signing" if for_signing else "verification"
            raise PrivacyRightsIntakeConfigError(
                f"consumer rights {action} key authority is unavailable"
            )
        return value

    def _signed_status(
        self,
        payload: Mapping[str, Any],
        authority: ConsumerRightsIntakeAuthority,
        evidence: ConsumerRightsIdentityEvidence,
        rights_case: object,
        now: float,
    ) -> SignedConsumerRightsStatus:
        subject_proof = _sha256(
            {
                "case_id": payload["case_id"],
                "subject_binding_sha256": authority.subject_binding_sha256,
                "profile_binding_sha256": authority.profile_binding_sha256,
            }
        )
        body: dict[str, object] = {
            "schema": STATUS_SCHEMA,
            "tenant_sha256": _text_sha256(authority.tenant_id),
            "case_id": payload["case_id"],
            "rights": list(payload["rights"]),
            "status": getattr(rights_case, "status", None),
            "identity_status": getattr(rights_case, "identity_status", None),
            "legal_hold": getattr(rights_case, "legal_hold", None),
            "retention_blocks_deletion": getattr(rights_case, "retention_blocks_deletion", None),
            "bridge_revision": payload["revision"],
            "bridge_sha256": _sha256(dict(payload)),
            "authority_sha256": authority.authority_sha256,
            "subject_binding_proof_sha256": subject_proof,
            "property_sha256": authority.property_sha256,
            "profile_sha256": authority.profile_sha256,
            "profile_binding_sha256": authority.profile_binding_sha256,
            "client_record_sha256": authority.client_record_sha256,
            "publication_sha256": authority.publication_sha256,
            "publication_bundle_sha256": authority.publication_bundle_sha256,
            "configuration_sha256": authority.configuration_sha256,
            "policy_sha256": authority.policy_sha256,
            "policy_version": authority.policy_version,
            "trust_context_sha256": authority.trust_context_sha256,
            "trust_context_revision": authority.trust_context_revision,
            "capability_grant_sha256": authority.capability_grant_sha256,
            "channel": authority.channel,
            "channel_binding_sha256": authority.channel_binding_sha256,
            "identity_evidence_sha256": evidence.evidence_sha256,
            "identity_evidence_revision": evidence.evidence_revision,
            "identity_evidence_valid_until": evidence.valid_until,
            "identity_verification_method": evidence.verification_method,
            "identity_assurance_level": evidence.assurance_level,
            "source_snapshot_sha256": payload["source_snapshot_sha256"],
            "planned_source_count": payload["planned_source_count"],
            "planned_callback_count": payload["planned_callback_count"],
            "intake_active_until": payload["active_until"],
            "orchestration_revision": getattr(rights_case, "revision", None),
            "orchestration_sha256": getattr(rights_case, "integrity_sha256", None),
            "destructive_approval_required": "erasure" in payload["rights"],
            "retrieved_payload_included": False,
            "response_delivery_performed": False,
            "provider_operations_verified": False,
            "estate_completeness_claimed": False,
            "generated_at": now,
        }
        key = self._signing_key(
            authority.tenant_id,
            key_ref=None,
            revision=None,
            at=now,
            for_signing=True,
        )
        signature = hmac.new(key.key, _canonical(body), hashlib.sha256).hexdigest()
        artifact_sha = _sha256(
            {
                "payload": body,
                "signing_key_ref": key.key_ref,
                "signing_key_revision": key.revision,
                "signing_key_authority_sha256": key.authority_sha256,
                "signature": signature,
            }
        )
        return SignedConsumerRightsStatus(
            payload=body,
            signing_key_ref=key.key_ref,
            signing_key_revision=key.revision,
            signing_key_authority_sha256=key.authority_sha256,
            signature=signature,
            evidence_sha256=artifact_sha,
        )

    def get_status(
        self,
        authority: ConsumerRightsIntakeAuthority,
        case_id: str,
    ) -> SignedConsumerRightsStatus:
        """Return signed status only after fresh exact authority re-resolution."""

        self._gate()
        now = self._now()
        try:
            authority = self._resolve_authority(authority, now)
            evidence = self._resolve_identity(authority, now)
        except (PrivacyRightsIntakeConflict, PrivacyRightsIntakeValidationError) as exc:
            raise PrivacyRightsIntakeNotFound("consumer rights request was not found") from exc
        payload = self._request_payload(authority.tenant_id, case_id, now)
        stored = self._authority(payload.get("authority"))
        if not _same(stored.authority_sha256, authority.authority_sha256):
            raise PrivacyRightsIntakeNotFound("consumer rights request was not found")
        for plan in payload["source_plans"]:
            self._validate_source_plan(authority.tenant_id, plan)
        try:
            rights_case = self._rights.get_case(authority.tenant_id, case_id)
        except Exception as exc:
            raise PrivacyRightsIntakeConflict(
                "privacy-rights case authority is unavailable"
            ) from exc
        if (
            getattr(rights_case, "tenant_id", None) != authority.tenant_id
            or getattr(rights_case, "case_id", None) != case_id
            or tuple(getattr(rights_case, "rights", ())) != tuple(payload["rights"])
            or not _same(
                getattr(rights_case, "subject_sha256", None),
                payload["case_subject_sha256"],
            )
            or not _same(
                getattr(rights_case, "external_request_sha256", None),
                payload["case_external_request_sha256"],
            )
        ):
            raise PrivacyRightsIntakeIntegrityError("privacy-rights case binding changed")
        return self._signed_status(payload, authority, evidence, rights_case, now)

    def verify_signed_status(self, status: SignedConsumerRightsStatus) -> bool:
        """Verify current or historical key revisions without persisting keys."""

        if not isinstance(status, SignedConsumerRightsStatus):
            return False
        case_id = status.payload.get("case_id")
        generated_at = status.payload.get("generated_at")
        if not isinstance(case_id, str):
            return False
        try:
            moment = _timestamp(generated_at, "status generated_at")
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM consumer_rights_intake_requests WHERE case_id=? LIMIT 2",
                    (case_id,),
                ).fetchall()
            if len(rows) != 1:
                return False
            payload = self._payload(rows[0])
            authority = self._authority(payload["authority"])
            if (
                status.payload.get("schema") != STATUS_SCHEMA
                or status.payload.get("tenant_sha256") != _text_sha256(authority.tenant_id)
                or not _same(
                    status.payload.get("authority_sha256"),
                    authority.authority_sha256,
                )
                or not _same(status.payload.get("bridge_sha256"), _sha256(payload))
            ):
                return False
            key = self._signing_key(
                authority.tenant_id,
                key_ref=status.signing_key_ref,
                revision=status.signing_key_revision,
                at=moment,
                for_signing=False,
            )
            expected_signature = hmac.new(
                key.key, _canonical(status.payload), hashlib.sha256
            ).hexdigest()
            expected_artifact = _sha256(
                {
                    "payload": status.payload,
                    "signing_key_ref": status.signing_key_ref,
                    "signing_key_revision": status.signing_key_revision,
                    "signing_key_authority_sha256": (status.signing_key_authority_sha256),
                    "signature": status.signature,
                }
            )
            return (
                _same(key.authority_sha256, status.signing_key_authority_sha256)
                and _same(expected_signature, status.signature)
                and _same(expected_artifact, status.evidence_sha256)
            )
        except (PrivacyRightsIntakeError, sqlite3.Error):
            return False

    def purge_expired(
        self,
        *,
        before: float | None = None,
        limit: int = 100,
    ) -> Mapping[str, int]:
        """Atomically purge request, operation, and request-local audit state."""

        self._gate()
        if self._maintenance_authorizer() is not True:
            raise PrivacyRightsIntakeConfigError(
                "consumer intake maintenance authority is unavailable"
            )
        now = self._now()
        cutoff = now if before is None else min(now, _timestamp(before, "before"))
        bounded = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT tenant_id,case_id FROM consumer_rights_intake_requests "
                "WHERE retained_until<=? ORDER BY retained_until,tenant_id,case_id "
                "LIMIT ?",
                (cutoff, bounded),
            ).fetchall()
            keys = [(str(row["tenant_id"]), str(row["case_id"])) for row in rows]
            deleted_operations = 0
            deleted_audit = 0
            for tenant_id, case_id in keys:
                deleted_audit += connection.execute(
                    "DELETE FROM consumer_rights_intake_audit WHERE tenant_id=? AND case_id=?",
                    (tenant_id, case_id),
                ).rowcount
                deleted_operations += connection.execute(
                    "DELETE FROM consumer_rights_intake_operations WHERE tenant_id=? AND case_id=?",
                    (tenant_id, case_id),
                ).rowcount
                deleted = connection.execute(
                    "DELETE FROM consumer_rights_intake_requests WHERE tenant_id=? AND case_id=?",
                    (tenant_id, case_id),
                )
                if deleted.rowcount != 1:
                    raise PrivacyRightsIntakeIntegrityError(
                        "expired consumer intake binding is incomplete"
                    )
            if deleted_operations != len(keys):
                raise PrivacyRightsIntakeIntegrityError(
                    "expired consumer intake operation is incomplete"
                )
            connection.commit()
        return {
            "requests_deleted": len(keys),
            "operations_deleted": deleted_operations,
            "audit_events_deleted": deleted_audit,
        }

    def verify_integrity(self, tenant_id: str) -> Mapping[str, object]:
        """Verify local records, request-local audit chains, and case pins."""

        self._gate()
        tenant = _tenant(tenant_id)
        try:
            with self._connect() as connection:
                sqlite_check = tuple(
                    str(row[0]) for row in connection.execute("PRAGMA integrity_check").fetchall()
                )
        except sqlite3.Error as exc:
            raise PrivacyRightsIntakeIntegrityError(
                "consumer intake SQLite integrity verification failed"
            ) from exc
        if sqlite_check != ("ok",):
            raise PrivacyRightsIntakeIntegrityError(
                "consumer intake SQLite integrity verification failed"
            )
        requests: list[dict[str, Any]] = []
        with self._connect() as connection:
            request_rows = connection.execute(
                "SELECT * FROM consumer_rights_intake_requests WHERE tenant_id=? ORDER BY case_id",
                (tenant,),
            ).fetchall()
            operation_rows = connection.execute(
                "SELECT * FROM consumer_rights_intake_operations "
                "WHERE tenant_id=? ORDER BY case_id",
                (tenant,),
            ).fetchall()
            active_rows = connection.execute(
                "SELECT * FROM consumer_rights_intake_active "
                "WHERE tenant_id=? ORDER BY case_id",
                (tenant,),
            ).fetchall()
            if len(request_rows) != len(operation_rows) or len(request_rows) != len(active_rows):
                raise PrivacyRightsIntakeIntegrityError(
                    "consumer intake request/idempotency/quota cardinality changed"
                )
            operations = {
                body["case_id"]: body
                for body in (self._operation_body(row) for row in operation_rows)
            }
            if len(operations) != len(operation_rows):
                raise PrivacyRightsIntakeIntegrityError("consumer intake operations are duplicated")
            active_bindings = {
                body["case_id"]: body
                for body in (self._active_body(row) for row in active_rows)
            }
            if len(active_bindings) != len(active_rows):
                raise PrivacyRightsIntakeIntegrityError(
                    "consumer intake quota bindings are duplicated"
                )
            terminal = "0" * 64
            audit_count = 0
            for row in request_rows:
                payload = self._payload(row)
                requests.append(payload)
                operation = operations.get(payload["case_id"])
                active = active_bindings.get(payload["case_id"])
                authority = self._authority(payload["authority"])
                if (
                    operation is None
                    or operation["tenant_id"] != tenant
                    or not _same(operation["request_sha256"], payload["request_sha256"])
                    or active is None
                    or active["tenant_id"] != tenant
                    or not _same(
                        active["subject_binding_sha256"],
                        authority.subject_binding_sha256,
                    )
                    or active["active_until"] != payload["active_until"]
                ):
                    raise PrivacyRightsIntakeIntegrityError(
                        "consumer intake operation or quota does not bind its request"
                    )
                audit_rows = connection.execute(
                    "SELECT * FROM consumer_rights_intake_audit "
                    "WHERE tenant_id=? AND case_id=? ORDER BY sequence",
                    (tenant, payload["case_id"]),
                ).fetchall()
                expected_events = 2 if payload["state"] == "active" else 1
                if len(audit_rows) != expected_events:
                    raise PrivacyRightsIntakeIntegrityError(
                        "consumer intake audit event count changed"
                    )
                previous: str | None = None
                for expected_sequence, audit_row in enumerate(audit_rows, 1):
                    event = self._audit_event(
                        tenant_id=str(audit_row["tenant_id"]),
                        case_id=str(audit_row["case_id"]),
                        sequence=int(audit_row["sequence"]),
                        event_type=str(audit_row["event_type"]),
                        request_integrity_sha256=str(audit_row["request_integrity_sha256"]),
                        previous_sha256=audit_row["previous_sha256"],
                        created_at=float(audit_row["created_at"]),
                    )
                    if (
                        event["sequence"] != expected_sequence
                        or event["previous_sha256"] != previous
                        or not _same(_sha256(event), audit_row["event_sha256"])
                    ):
                        raise PrivacyRightsIntakeIntegrityError(
                            "consumer intake audit chain changed"
                        )
                    previous = str(audit_row["event_sha256"])
                    terminal = previous
                    audit_count += 1
                if payload["state"] == "active" and not _same(
                    audit_rows[-1]["request_integrity_sha256"], _sha256(payload)
                ):
                    raise PrivacyRightsIntakeIntegrityError(
                        "consumer intake terminal audit does not bind current state"
                    )

        for payload in requests:
            for plan in payload["source_plans"]:
                self._validate_source_plan(tenant, plan)
            try:
                rights_case = self._rights.get_case(tenant, payload["case_id"])
            except Exception as exc:
                raise PrivacyRightsIntakeIntegrityError(
                    "consumer intake orchestration case is unavailable"
                ) from exc
            if (
                getattr(rights_case, "tenant_id", None) != tenant
                or tuple(getattr(rights_case, "rights", ())) != tuple(payload["rights"])
                or (
                    payload["state"] == "active"
                    and (
                        not _same(
                            getattr(rights_case, "subject_sha256", None),
                            payload["case_subject_sha256"],
                        )
                        or not _same(
                            getattr(rights_case, "external_request_sha256", None),
                            payload["case_external_request_sha256"],
                        )
                    )
                )
            ):
                raise PrivacyRightsIntakeIntegrityError(
                    "consumer intake orchestration case binding changed"
                )
        return {
            "tenant_sha256": _text_sha256(tenant),
            "requests": len(requests),
            "operations": len(requests),
            "quota_bindings": len(requests),
            "audit_events": audit_count,
            "terminal_audit_sha256": terminal,
        }

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "channel_neutral": True,
            "local_control_plane": True,
            "network_io": NETWORK_IO,
            "provider_writes": PROVIDER_WRITES,
            "orchestration_is_sole_case_task_authority": True,
            "independent_identity_resolver_required": True,
            "identity_verification_performed": IDENTITY_VERIFICATION_PERFORMED,
            "raw_email_persisted": False,
            "raw_identity_token_or_oidc_subject_persisted": False,
            "raw_reauthentication_receipt_persisted": False,
            "raw_profile_or_property_id_persisted": False,
            "provider_credentials_persisted": False,
            "retrieved_payload_persisted": False,
            "consumer_selects_source_or_tenant": False,
            "consumer_controls_legal_or_retention_gates": False,
            "destructive_work_auto_approved": False,
            "response_delivery_performed": RESPONSE_DELIVERY_PERFORMED,
            "estate_completeness_claimed": ESTATE_COMPLETENESS_CLAIMED,
            "live_provider_acceptance_verified": (LIVE_PROVIDER_ACCEPTANCE_VERIFIED),
        }


__all__ = [
    "AUTHORITY_SCHEMA",
    "ESTATE_COMPLETENESS_CLAIMED",
    "IDENTITY_EVIDENCE_SCHEMA",
    "IDENTITY_VERIFICATION_PERFORMED",
    "LIVE_PROVIDER_ACCEPTANCE_VERIFIED",
    "NETWORK_IO",
    "PROVIDER_WRITES",
    "PrivacyRightsIntakeConfigError",
    "PrivacyRightsIntakeConflict",
    "PrivacyRightsIntakeError",
    "PrivacyRightsIntakeIntegrityError",
    "PrivacyRightsIntakeNotFound",
    "PrivacyRightsIntakeStore",
    "PrivacyRightsIntakeValidationError",
    "RESPONSE_DELIVERY_PERFORMED",
    "STATUS_SCHEMA",
    "ConsumerRightsIdentityEvidence",
    "ConsumerRightsIntakeAuthority",
    "ConsumerRightsSigningKey",
    "SignedConsumerRightsStatus",
    "enabled",
    "require_enabled",
]
