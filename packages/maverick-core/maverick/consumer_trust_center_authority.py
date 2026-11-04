"""Persisted authority for the unified consumer trust-center read model.

The public trust-center read model deliberately accepts a zero-argument
``TrustCenterContext`` resolver.  This module is the server-side authority that
backs that seam.  It persists only closed metadata and exact SHA-256 bindings;
tenant, property, profile, consumer identity, credentials, legal prose, and
signing-key values are resolved at runtime and are never written to SQLite.

Four-eyes grants and per-case rights authorizations are proposed by one
principal and approved by two other, distinct principals.  The public consumer
actor is separated from all three.  Every mutation is CAS-bound, idempotent,
audited, and appended to immutable history.  Resolution fails closed on
expiry, revocation, authority drift, or missing active capability grants.

This module performs no network or provider writes and does not infer rights
case completeness, identity verification, legal sufficiency, or publication
acceptance.  Those properties remain the responsibility of the existing
public source authorities read by :mod:`maverick.consumer_trust_center`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from . import consent_storage
from .consent_profile_data import PublicProfileAuthority
from .consumer_trust_center import (
    ConsumerTrustCenterError,
    ConsumerTrustCenterSourceAdapter,
    TrustCenterCapabilityGrant,
    TrustCenterConflict,
    TrustCenterContext,
    TrustCenterIntegrityError,
    TrustCenterRightsAuthorization,
    TrustCenterValidationError,
    require_trust_center_enabled,
)
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

AUTHORITY_SCHEMA = "lightwork.consumer-trust-center-authority.v1"
AUTHORITY_EXPORT_SCHEMA = "lightwork.consumer-trust-center-authority-export.v1"
PRINCIPAL_AUTHORITY_SCHEMA = "lightwork.consumer-trust-center-principal-authority.v1"

NETWORK_IO = False
PROVIDER_WRITES = False
RAW_IDENTIFIERS_PERSISTED = False
SIGNING_KEYS_PERSISTED = False
COMPLETENESS_INFERRED = False

_SCHEMA_VERSION = 1
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_RETENTION_SECONDS = 10 * 366 * 24 * 60 * 60
_MIN_RETENTION_SECONDS = 60
_MAX_AUTHORITY_SECONDS = 366 * 24 * 60 * 60
_MAX_HISTORY_LIMIT = 100
_MAX_RIGHTS_CASES = 50
_MAX_PURGE = 500
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_KEY_REF_RE = re.compile(r"(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_LOCALE_RE = re.compile(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,2}\Z")

CAPABILITIES = frozenset({"active_publication", "consent_history", "profile_data", "rights_cases"})
PRINCIPAL_PERMISSIONS = frozenset(
    {
        "authority_read",
        "capability_approve",
        "capability_request",
        "context_admin",
        "metadata_export",
        "retention_purge",
        "rights_approve",
        "rights_request",
    }
)
_ACTIVE_STATES = frozenset({"proposed", "first_approved", "active"})


class TrustCenterAuthorityError(ConsumerTrustCenterError):
    """Base persisted-authority failure."""


class TrustCenterAuthorityConfigError(TrustCenterAuthorityError):
    """A constructor-bound server authority is absent or invalid."""


class TrustCenterAuthorityPermissionDenied(TrustCenterAuthorityError):
    """The current server principal lacks exact tenant-local authority."""


class TrustCenterAuthorityNotFound(TrustCenterAuthorityError):
    """A tenant-scoped authority record is absent."""


@dataclass(frozen=True, slots=True)
class TrustCenterPrincipalAuthority:
    """Closed server result authorizing one operator principal."""

    tenant_sha256: str
    principal_sha256: str
    permissions: tuple[str, ...]
    valid_until: float
    authority_sha256: str
    revoked: bool = False


@dataclass(frozen=True, slots=True)
class ResolvedTrustCenterBinding:
    """Ephemeral public binding material; none of its raw fields are stored."""

    tenant_id: str
    property_id: str
    profile_id: str
    actor_sha256: str
    requested_locale: str
    server_origin: str | None
    server_bundle_id: str | None
    server_platform: str | None
    jurisdiction: str
    country_code: str
    region_code: str
    profile_authority: PublicProfileAuthority | None


@dataclass(frozen=True, slots=True)
class TrustCenterContextAuthority:
    context_ref: str
    tenant_sha256: str
    property_sha256: str
    profile_sha256: str
    actor_sha256: str
    binding_sha256: str
    profile_authority_sha256: str | None
    publication_history_limit: int
    receipt_limit: int
    valid_until: float
    retained_until: float
    status: str
    created_by_sha256: str
    updated_by_sha256: str
    created_at: float
    updated_at: float
    revision: int
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class CapabilityGrantAuthority:
    grant_ref: str
    context_ref: str
    tenant_sha256: str
    property_sha256: str
    profile_sha256: str
    capability: str
    requested_by_sha256: str
    approved_by_sha256: str | None
    second_approved_by_sha256: str | None
    valid_until: float
    retained_until: float
    status: str
    created_at: float
    updated_at: float
    revision: int
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class RightsCaseAuthorizationAuthority:
    authorization_ref: str
    context_ref: str
    tenant_sha256: str
    case_id: str
    expected_case_sha256: str
    requested_by_sha256: str
    approved_by_sha256: str | None
    second_approved_by_sha256: str | None
    valid_until: float
    retained_until: float
    status: str
    created_at: float
    updated_at: float
    revision: int
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class SignedTrustCenterAuthorityExport:
    schema: str
    export_id: str
    tenant_sha256: str
    context_ref: str
    signing_key_ref: str
    payload: Mapping[str, object]
    payload_sha256: str
    signature_sha256: str
    retained_until: float
    created_at: float


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
        raise TrustCenterValidationError("trust-center authority must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise TrustCenterValidationError("trust-center authority exceeds its byte bound")
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
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise TrustCenterValidationError("tenant_id is invalid") from exc


def _ref(value: object, label: str, pattern: re.Pattern[str] = _REF_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise TrustCenterValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise TrustCenterValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TrustCenterValidationError(f"{label} must be a finite timestamp")
    normalized = float(value)
    if not math.isfinite(normalized) or not 0 < normalized < 100_000_000_000.0:
        raise TrustCenterValidationError(f"{label} must be a finite timestamp")
    return normalized


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise TrustCenterValidationError(f"{label} is outside its bound")
    return value


def _now(clock: Callable[[], float]) -> float:
    return _timestamp(clock(), "clock")


def _retention(value: object, now: float) -> float:
    retained = _timestamp(value, "retained_until")
    if not now + _MIN_RETENTION_SECONDS <= retained <= now + _MAX_RETENTION_SECONDS:
        raise TrustCenterValidationError("retained_until is outside its strict bound")
    return retained


def _validity(value: object, now: float, retained_until: float) -> float:
    valid = _timestamp(value, "valid_until")
    if not now < valid <= min(now + _MAX_AUTHORITY_SECONDS, retained_until):
        raise TrustCenterValidationError("valid_until is outside its strict bound")
    return valid


def _loads(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= _MAX_JSON_BYTES:
        raise TrustCenterIntegrityError(f"stored {label} is invalid")
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise TrustCenterIntegrityError(f"stored {label} is invalid") from exc
    if not isinstance(decoded, dict):
        raise TrustCenterIntegrityError(f"stored {label} is invalid")
    return decoded


def _record_payload(value: object) -> dict[str, Any]:
    body = asdict(value) if hasattr(value, "__dataclass_fields__") else dict(value)  # type: ignore[arg-type]
    body.pop("integrity_sha256", None)
    return body


def _record_integrity(value: object) -> str:
    return _sha256(_record_payload(value))


def principal_authority_sha256(authority: TrustCenterPrincipalAuthority) -> str:
    if not isinstance(authority, TrustCenterPrincipalAuthority):
        raise TrustCenterValidationError("principal authority uses an invalid type")
    return _sha256(
        {
            "schema": PRINCIPAL_AUTHORITY_SCHEMA,
            "tenant_sha256": authority.tenant_sha256,
            "principal_sha256": authority.principal_sha256,
            "permissions": list(authority.permissions),
            "valid_until": authority.valid_until,
        }
    )


def _public_authority_sha256(authority: PublicProfileAuthority | None) -> str | None:
    if authority is None:
        return None
    if type(authority) is not PublicProfileAuthority:
        raise TrustCenterIntegrityError("profile authority uses an invalid exact type")
    return _sha256({"schema": "lightwork.public-profile-authority-pin.v1", **asdict(authority)})


def _binding_body(binding: ResolvedTrustCenterBinding) -> dict[str, object]:
    if not isinstance(binding, ResolvedTrustCenterBinding):
        raise TrustCenterIntegrityError("binding resolver returned an invalid type")
    tenant = _tenant(binding.tenant_id)
    property_id = _ref(binding.property_id, "resolved property_id")
    profile_id = _ref(binding.profile_id, "resolved profile_id")
    actor = _digest(binding.actor_sha256, "resolved actor_sha256")
    if not isinstance(binding.requested_locale, str) or not _LOCALE_RE.fullmatch(
        binding.requested_locale
    ):
        raise TrustCenterValidationError("resolved requested_locale is invalid")
    optional: dict[str, str | None] = {}
    for label in ("server_origin", "server_bundle_id", "server_platform"):
        item = getattr(binding, label)
        if item is not None and (
            not isinstance(item, str) or not 1 <= len(item.encode("utf-8")) <= 2_048
        ):
            raise TrustCenterValidationError(f"resolved {label} is invalid")
        optional[label] = None if item is None else _text_sha256(item)
    for label in ("jurisdiction", "country_code", "region_code"):
        item = getattr(binding, label)
        if not isinstance(item, str) or not _REF_RE.fullmatch(item):
            raise TrustCenterValidationError(f"resolved {label} is invalid")
    profile_authority_sha = _public_authority_sha256(binding.profile_authority)
    if binding.profile_authority is not None and (
        binding.profile_authority.tenant_id != tenant
        or binding.profile_authority.property_id != property_id
        or binding.profile_authority.profile_id != profile_id
    ):
        raise TrustCenterConflict("profile authority does not match the resolved binding")
    return {
        "schema": "lightwork.consumer-trust-center-binding.v1",
        "tenant_sha256": _text_sha256(tenant),
        "property_sha256": _text_sha256(property_id),
        "profile_sha256": _text_sha256(profile_id),
        "actor_sha256": actor,
        "requested_locale_sha256": _text_sha256(binding.requested_locale),
        "server_origin_sha256": optional["server_origin"],
        "server_bundle_id_sha256": optional["server_bundle_id"],
        "server_platform_sha256": optional["server_platform"],
        "jurisdiction_sha256": _text_sha256(binding.jurisdiction),
        "country_code_sha256": _text_sha256(binding.country_code),
        "region_code_sha256": _text_sha256(binding.region_code),
        "profile_authority_sha256": profile_authority_sha,
    }


def _context_from_payload(payload: Mapping[str, Any]) -> TrustCenterContextAuthority:
    return TrustCenterContextAuthority(**dict(payload))


def _grant_from_payload(payload: Mapping[str, Any]) -> CapabilityGrantAuthority:
    return CapabilityGrantAuthority(**dict(payload))


def _rights_from_payload(payload: Mapping[str, Any]) -> RightsCaseAuthorizationAuthority:
    return RightsCaseAuthorizationAuthority(**dict(payload))


def _export_from_payload(payload: Mapping[str, Any]) -> SignedTrustCenterAuthorityExport:
    return SignedTrustCenterAuthorityExport(**dict(payload))


class ConsumerTrustCenterAuthorityStore:
    """Private, digest-only SQLite authority for public Trust Center contexts."""

    def __init__(
        self,
        path: str | Path,
        *,
        binding_resolver: Callable[[str], ResolvedTrustCenterBinding],
        principal_authority_resolver: Callable[[str], TrustCenterPrincipalAuthority],
        signing_key_resolver: Callable[[str, str], bytes],
        signing_key_ref: str = "env:MAVERICK_TRUST_CENTER_AUTHORITY_SIGNING_KEY",
        config_gate: Callable[[], None] = require_trust_center_enabled,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
    ) -> None:
        config_gate()
        if not all(
            callable(item)
            for item in (
                binding_resolver,
                principal_authority_resolver,
                signing_key_resolver,
                config_gate,
                clock,
            )
        ):
            raise TrustCenterAuthorityConfigError(
                "trust-center authority dependencies must be callable"
            )
        self.path = Path(path)
        self._binding_resolver = binding_resolver
        self._principal_resolver = principal_authority_resolver
        self._signing_key_resolver = signing_key_resolver
        self._signing_key_ref = _ref(signing_key_ref, "signing_key_ref", _KEY_REF_RE)
        self._gate = config_gate
        self._clock = clock
        self._id_factory = id_factory or (lambda prefix: f"{prefix}-{secrets.token_hex(12)}")
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if consent_storage.shared():
            connection = consent_storage.connect(self.path, timeout=30.0, implicit_transactions=True)
        else:
            connection = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
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
                CREATE TABLE IF NOT EXISTS trust_center_authority_contexts(
                    context_ref TEXT PRIMARY KEY,tenant_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,revision INTEGER NOT NULL,
                    valid_until REAL NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS trust_center_authority_context_tenant
                    ON trust_center_authority_contexts(
                        tenant_sha256,retained_until,status,context_ref
                    );
                CREATE TABLE IF NOT EXISTS trust_center_authority_grants(
                    grant_ref TEXT PRIMARY KEY,context_ref TEXT NOT NULL,
                    tenant_sha256 TEXT NOT NULL,capability TEXT NOT NULL,
                    status TEXT NOT NULL,revision INTEGER NOT NULL,
                    valid_until REAL NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    FOREIGN KEY(context_ref) REFERENCES
                        trust_center_authority_contexts(context_ref) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS trust_center_authority_grant_context
                    ON trust_center_authority_grants(
                        tenant_sha256,context_ref,capability,status,valid_until
                    );
                CREATE TABLE IF NOT EXISTS trust_center_authority_rights(
                    authorization_ref TEXT PRIMARY KEY,context_ref TEXT NOT NULL,
                    tenant_sha256 TEXT NOT NULL,case_id TEXT NOT NULL,
                    status TEXT NOT NULL,revision INTEGER NOT NULL,
                    valid_until REAL NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    FOREIGN KEY(context_ref) REFERENCES
                        trust_center_authority_contexts(context_ref) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS trust_center_authority_right_context
                    ON trust_center_authority_rights(
                        tenant_sha256,context_ref,case_id,status,valid_until
                    );
                CREATE TABLE IF NOT EXISTS trust_center_authority_history(
                    tenant_sha256 TEXT NOT NULL,object_kind TEXT NOT NULL,
                    object_ref TEXT NOT NULL,revision INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,object_kind,object_ref,revision)
                );
                CREATE TABLE IF NOT EXISTS trust_center_authority_operations(
                    tenant_sha256 TEXT NOT NULL,key_sha256 TEXT NOT NULL,
                    action TEXT NOT NULL,context_ref TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_kind TEXT NOT NULL,
                    result_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    retained_until REAL NOT NULL,created_at REAL NOT NULL,
                    PRIMARY KEY(tenant_sha256,key_sha256)
                );
                CREATE TABLE IF NOT EXISTS trust_center_authority_exports(
                    export_id TEXT PRIMARY KEY,context_ref TEXT NOT NULL,
                    tenant_sha256 TEXT NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    FOREIGN KEY(context_ref) REFERENCES
                        trust_center_authority_contexts(context_ref) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS trust_center_authority_audit(
                    tenant_sha256 TEXT NOT NULL,sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS trust_center_authority_history_no_update
                    BEFORE UPDATE ON trust_center_authority_history
                    BEGIN SELECT RAISE(ABORT,'immutable trust-center authority history'); END;
                CREATE TRIGGER IF NOT EXISTS trust_center_authority_operation_no_update
                    BEFORE UPDATE ON trust_center_authority_operations
                    BEGIN SELECT RAISE(ABORT,'immutable trust-center idempotency'); END;
                CREATE TRIGGER IF NOT EXISTS trust_center_authority_export_no_update
                    BEFORE UPDATE ON trust_center_authority_exports
                    BEGIN SELECT RAISE(ABORT,'immutable trust-center authority export'); END;
                CREATE TRIGGER IF NOT EXISTS trust_center_authority_audit_no_update
                    BEFORE UPDATE ON trust_center_authority_audit
                    BEGIN SELECT RAISE(ABORT,'immutable trust-center authority audit'); END;
                CREATE TRIGGER IF NOT EXISTS trust_center_authority_audit_no_delete
                    BEFORE DELETE ON trust_center_authority_audit
                    BEGIN SELECT RAISE(ABORT,'immutable trust-center authority audit'); END;
                """
            )
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, _SCHEMA_VERSION):
                raise TrustCenterAuthorityConfigError(
                    f"unsupported trust-center authority schema version {version}"
                )
            connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
        if not consent_storage.shared():
            ensure_private_file(self.path)

    def _check_gate(self) -> None:
        self._gate()

    def _new_ref(self, prefix: str) -> str:
        return _ref(self._id_factory(prefix), f"{prefix} identifier")

    def _principal(self, tenant: str, permission: str, now: float) -> str:
        if permission not in PRINCIPAL_PERMISSIONS:
            raise TrustCenterAuthorityConfigError("unknown principal permission")
        try:
            authority = self._principal_resolver(tenant)
        except ConsumerTrustCenterError:
            raise
        except Exception as exc:
            raise TrustCenterAuthorityPermissionDenied(
                "principal authority resolution failed"
            ) from exc
        if not isinstance(authority, TrustCenterPrincipalAuthority):
            raise TrustCenterAuthorityPermissionDenied("principal authority is unavailable")
        tenant_sha = _text_sha256(tenant)
        permissions = authority.permissions
        if (
            not _same(authority.tenant_sha256, tenant_sha)
            or not _DIGEST_RE.fullmatch(str(authority.principal_sha256))
            or type(permissions) is not tuple
            or not permissions
            or len(permissions) != len(set(permissions))
            or tuple(sorted(permissions)) != permissions
            or not set(permissions).issubset(PRINCIPAL_PERMISSIONS)
            or permission not in permissions
            or authority.revoked is not False
            or _timestamp(authority.valid_until, "principal valid_until") <= now
            or not _same(authority.authority_sha256, principal_authority_sha256(authority))
        ):
            raise TrustCenterAuthorityPermissionDenied(
                "principal authority is expired, revoked, mismatched, or insufficient"
            )
        return authority.principal_sha256

    def _binding(self, context_ref: str) -> tuple[ResolvedTrustCenterBinding, dict[str, object]]:
        try:
            binding = self._binding_resolver(context_ref)
        except ConsumerTrustCenterError:
            raise
        except Exception as exc:
            raise TrustCenterIntegrityError("trust-center binding resolution failed") from exc
        body = _binding_body(binding)
        return binding, body

    @staticmethod
    def _row_payload(row: sqlite3.Row, label: str) -> dict[str, Any]:
        payload = _loads(row["payload_json"], label)
        supplied = payload.get("integrity_sha256")
        if not _same(supplied, row["integrity_sha256"]):
            raise TrustCenterIntegrityError(f"stored {label} index is inconsistent")
        body = dict(payload)
        body.pop("integrity_sha256", None)
        if not _same(_sha256(body), supplied):
            raise TrustCenterIntegrityError(f"stored {label} failed integrity")
        for field in (
            "authorization_ref",
            "capability",
            "case_id",
            "context_ref",
            "grant_ref",
            "retained_until",
            "revision",
            "status",
            "tenant_sha256",
            "valid_until",
        ):
            if field in row.keys() and payload.get(field) != row[field]:
                raise TrustCenterIntegrityError(f"stored {label} index is inconsistent")
        return payload

    @staticmethod
    def _context_row(
        connection: sqlite3.Connection, tenant_sha: str, context_ref: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM trust_center_authority_contexts WHERE tenant_sha256=? AND context_ref=?",
            (tenant_sha, context_ref),
        ).fetchone()
        if row is None:
            raise TrustCenterAuthorityNotFound("trust-center context was not found")
        return row

    @staticmethod
    def _child_row(
        connection: sqlite3.Connection,
        table: str,
        id_column: str,
        tenant_sha: str,
        object_ref: str,
    ) -> sqlite3.Row:
        if (table, id_column) not in {
            ("trust_center_authority_grants", "grant_ref"),
            ("trust_center_authority_rights", "authorization_ref"),
        }:
            raise TrustCenterAuthorityConfigError("invalid internal authority table")
        row = connection.execute(
            f"SELECT * FROM {table} WHERE tenant_sha256=? AND {id_column}=?",  # noqa: S608
            (tenant_sha, object_ref),
        ).fetchone()
        if row is None:
            raise TrustCenterAuthorityNotFound("trust-center authority was not found")
        return row

    @staticmethod
    def _insert_history(
        connection: sqlite3.Connection,
        tenant_sha: str,
        kind: str,
        object_ref: str,
        record: object,
    ) -> None:
        revision = int(record.revision)  # type: ignore[attr-defined]
        previous = connection.execute(
            "SELECT integrity_sha256 FROM trust_center_authority_history "
            "WHERE tenant_sha256=? AND object_kind=? AND object_ref=? "
            "ORDER BY revision DESC LIMIT 1",
            (tenant_sha, kind, object_ref),
        ).fetchone()
        payload = {
            "schema": "lightwork.consumer-trust-center-authority-history.v1",
            "tenant_sha256": tenant_sha,
            "object_kind": kind,
            "object_ref": object_ref,
            "revision": revision,
            "record": asdict(record),
            "previous_integrity_sha256": (
                None if previous is None else str(previous["integrity_sha256"])
            ),
        }
        integrity = _sha256(payload)
        connection.execute(
            "INSERT INTO trust_center_authority_history VALUES(?,?,?,?,?,?)",
            (
                tenant_sha,
                kind,
                object_ref,
                revision,
                _canonical(payload).decode("ascii"),
                integrity,
            ),
        )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        tenant_sha: str,
        event_type: str,
        object_kind: str,
        object_ref: str,
        actor_sha: str,
        record_sha: str,
        now: float,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM trust_center_authority_audit "
            "WHERE tenant_sha256=? ORDER BY sequence DESC LIMIT 1",
            (tenant_sha,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        payload = {
            "schema": "lightwork.consumer-trust-center-authority-audit.v1",
            "tenant_sha256": tenant_sha,
            "sequence": sequence,
            "event_type": _ref(event_type, "audit event_type"),
            "object_kind": _ref(object_kind, "audit object_kind"),
            "object_ref": _ref(object_ref, "audit object_ref"),
            "actor_sha256": _digest(actor_sha, "audit actor_sha256"),
            "record_sha256": _digest(record_sha, "audit record_sha256"),
            "previous_integrity_sha256": (
                None if previous is None else str(previous["integrity_sha256"])
            ),
            "created_at": now,
        }
        connection.execute(
            "INSERT INTO trust_center_authority_audit VALUES(?,?,?,?)",
            (tenant_sha, sequence, _canonical(payload).decode("ascii"), _sha256(payload)),
        )

    @staticmethod
    def _operation_key(value: object) -> str:
        key = _ref(value, "idempotency_key", _IDEMPOTENCY_RE)
        return _text_sha256(key)

    @classmethod
    def _replay(
        cls,
        connection: sqlite3.Connection,
        tenant_sha: str,
        idempotency_key: str,
        action: str,
        request_sha: str,
    ) -> tuple[str, dict[str, Any]] | None:
        key_sha = cls._operation_key(idempotency_key)
        row = connection.execute(
            "SELECT * FROM trust_center_authority_operations "
            "WHERE tenant_sha256=? AND key_sha256=?",
            (tenant_sha, key_sha),
        ).fetchone()
        if row is None:
            return None
        result = _loads(row["result_json"], "idempotency result")
        integrity = _sha256(
            {
                "tenant_sha256": tenant_sha,
                "key_sha256": key_sha,
                "action": row["action"],
                "context_ref": row["context_ref"],
                "request_sha256": row["request_sha256"],
                "result_kind": row["result_kind"],
                "result": result,
                "retained_until": row["retained_until"],
                "created_at": row["created_at"],
            }
        )
        if (
            row["action"] != action
            or not _same(row["request_sha256"], request_sha)
            or not _same(row["integrity_sha256"], integrity)
        ):
            raise TrustCenterConflict("idempotency key is bound to another exact request")
        return str(row["result_kind"]), result

    @classmethod
    def _save_operation(
        cls,
        connection: sqlite3.Connection,
        *,
        tenant_sha: str,
        idempotency_key: str,
        action: str,
        context_ref: str,
        request_sha: str,
        result_kind: str,
        result: Mapping[str, Any],
        retained_until: float,
        created_at: float,
    ) -> None:
        key_sha = cls._operation_key(idempotency_key)
        body = {
            "tenant_sha256": tenant_sha,
            "key_sha256": key_sha,
            "action": action,
            "context_ref": context_ref,
            "request_sha256": request_sha,
            "result_kind": result_kind,
            "result": dict(result),
            "retained_until": retained_until,
            "created_at": created_at,
        }
        connection.execute(
            "INSERT INTO trust_center_authority_operations VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                tenant_sha,
                key_sha,
                action,
                context_ref,
                request_sha,
                result_kind,
                _canonical(result).decode("ascii"),
                _sha256(body),
                retained_until,
                created_at,
            ),
        )

    def create_context(
        self,
        *,
        context_ref: str,
        valid_until: float,
        retained_until: float,
        publication_history_limit: int = 25,
        receipt_limit: int = 25,
        idempotency_key: str,
    ) -> TrustCenterContextAuthority:
        """Enroll one server-resolved consumer binding without storing raw values."""

        self._check_gate()
        ref = _ref(context_ref, "context_ref")
        now = _now(self._clock)
        binding, body = self._binding(ref)
        tenant = _tenant(binding.tenant_id)
        tenant_sha = str(body["tenant_sha256"])
        actor = self._principal(tenant, "context_admin", now)
        if _same(actor, body["actor_sha256"]):
            raise TrustCenterAuthorityPermissionDenied(
                "the consumer actor cannot administer its own trust-center context"
            )
        retained = _retention(retained_until, now)
        valid = _validity(valid_until, now, retained)
        history_limit = _integer(
            publication_history_limit,
            "publication_history_limit",
            1,
            _MAX_HISTORY_LIMIT,
        )
        receipts = _integer(receipt_limit, "receipt_limit", 1, _MAX_HISTORY_LIMIT)
        request = {
            "action": "create_context",
            "context_ref": ref,
            "binding_sha256": _sha256(body),
            "valid_until": valid,
            "retained_until": retained,
            "publication_history_limit": history_limit,
            "receipt_limit": receipts,
        }
        request_sha = _sha256(request)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._replay(
                connection, tenant_sha, idempotency_key, "create_context", request_sha
            )
            if replay is not None:
                kind, result = replay
                if kind != "context":
                    raise TrustCenterIntegrityError("context replay kind is invalid")
                return _context_from_payload(result)
            if connection.execute(
                "SELECT 1 FROM trust_center_authority_contexts WHERE context_ref=?",
                (ref,),
            ).fetchone():
                raise TrustCenterConflict("context_ref is already enrolled")
            record = TrustCenterContextAuthority(
                context_ref=ref,
                tenant_sha256=tenant_sha,
                property_sha256=str(body["property_sha256"]),
                profile_sha256=str(body["profile_sha256"]),
                actor_sha256=str(body["actor_sha256"]),
                binding_sha256=_sha256(body),
                profile_authority_sha256=(
                    None
                    if body["profile_authority_sha256"] is None
                    else str(body["profile_authority_sha256"])
                ),
                publication_history_limit=history_limit,
                receipt_limit=receipts,
                valid_until=valid,
                retained_until=retained,
                status="active",
                created_by_sha256=actor,
                updated_by_sha256=actor,
                created_at=now,
                updated_at=now,
                revision=1,
                integrity_sha256="0" * 64,
            )
            record = replace(record, integrity_sha256=_record_integrity(record))
            payload = asdict(record)
            connection.execute(
                "INSERT INTO trust_center_authority_contexts VALUES(?,?,?,?,?,?,?,?)",
                (
                    ref,
                    tenant_sha,
                    record.status,
                    record.revision,
                    valid,
                    retained,
                    _canonical(payload).decode("ascii"),
                    record.integrity_sha256,
                ),
            )
            self._insert_history(connection, tenant_sha, "context", ref, record)
            self._audit(
                connection,
                tenant_sha,
                "context_created",
                "context",
                ref,
                actor,
                record.integrity_sha256,
                now,
            )
            self._save_operation(
                connection,
                tenant_sha=tenant_sha,
                idempotency_key=idempotency_key,
                action="create_context",
                context_ref=ref,
                request_sha=request_sha,
                result_kind="context",
                result=payload,
                retained_until=retained,
                created_at=now,
            )
            connection.commit()
            return record

    @staticmethod
    def _updated_context(
        current: TrustCenterContextAuthority,
        *,
        actor_sha: str,
        now: float,
        **changes: object,
    ) -> TrustCenterContextAuthority:
        record = replace(
            current,
            **changes,
            updated_by_sha256=actor_sha,
            updated_at=now,
            revision=current.revision + 1,
            integrity_sha256="0" * 64,
        )
        return replace(record, integrity_sha256=_record_integrity(record))

    @staticmethod
    def _write_context(
        connection: sqlite3.Connection,
        previous: TrustCenterContextAuthority,
        current: TrustCenterContextAuthority,
    ) -> None:
        result = connection.execute(
            "UPDATE trust_center_authority_contexts SET status=?,revision=?,valid_until=?,"
            "retained_until=?,payload_json=?,integrity_sha256=? "
            "WHERE tenant_sha256=? AND context_ref=? AND revision=?",
            (
                current.status,
                current.revision,
                current.valid_until,
                current.retained_until,
                _canonical(asdict(current)).decode("ascii"),
                current.integrity_sha256,
                current.tenant_sha256,
                current.context_ref,
                previous.revision,
            ),
        )
        if result.rowcount != 1:
            raise TrustCenterConflict("trust-center context CAS failed")

    def revise_context(
        self,
        tenant_id: str,
        context_ref: str,
        *,
        expected_revision: int,
        valid_until: float,
        retained_until: float,
        publication_history_limit: int,
        receipt_limit: int,
        idempotency_key: str,
    ) -> TrustCenterContextAuthority:
        """CAS-revise expiry, limits, and the exact live server binding pin."""

        self._check_gate()
        tenant = _tenant(tenant_id)
        tenant_sha = _text_sha256(tenant)
        ref = _ref(context_ref, "context_ref")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        now = _now(self._clock)
        actor = self._principal(tenant, "context_admin", now)
        binding, binding_body = self._binding(ref)
        if binding.tenant_id != tenant or _same(actor, binding.actor_sha256):
            raise TrustCenterAuthorityPermissionDenied("context binding or actor is mismatched")
        retained = _retention(retained_until, now)
        valid = _validity(valid_until, now, retained)
        history_limit = _integer(
            publication_history_limit,
            "publication_history_limit",
            1,
            _MAX_HISTORY_LIMIT,
        )
        receipts = _integer(receipt_limit, "receipt_limit", 1, _MAX_HISTORY_LIMIT)
        request = {
            "action": "revise_context",
            "context_ref": ref,
            "expected_revision": expected,
            "binding_sha256": _sha256(binding_body),
            "valid_until": valid,
            "retained_until": retained,
            "publication_history_limit": history_limit,
            "receipt_limit": receipts,
        }
        request_sha = _sha256(request)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._replay(
                connection, tenant_sha, idempotency_key, "revise_context", request_sha
            )
            if replay is not None:
                return _context_from_payload(replay[1])
            row = self._context_row(connection, tenant_sha, ref)
            current = _context_from_payload(self._row_payload(row, "context"))
            if current.status != "active" or current.revision != expected:
                raise TrustCenterConflict("context revision or state changed")
            child = connection.execute(
                "SELECT 1 FROM trust_center_authority_grants WHERE tenant_sha256=? "
                "AND context_ref=? AND status='active' AND valid_until>? LIMIT 1",
                (tenant_sha, ref, valid),
            ).fetchone()
            right = connection.execute(
                "SELECT 1 FROM trust_center_authority_rights WHERE tenant_sha256=? "
                "AND context_ref=? AND status='active' AND valid_until>? LIMIT 1",
                (tenant_sha, ref, valid),
            ).fetchone()
            if child is not None or right is not None:
                raise TrustCenterConflict("context validity cannot truncate active authority")
            if current.binding_sha256 != _sha256(binding_body):
                live_child = connection.execute(
                    "SELECT 1 FROM trust_center_authority_grants WHERE tenant_sha256=? "
                    "AND context_ref=? AND status IN ('proposed','first_approved','active') "
                    "UNION ALL SELECT 1 FROM trust_center_authority_rights "
                    "WHERE tenant_sha256=? AND context_ref=? "
                    "AND status IN ('proposed','first_approved','active') LIMIT 1",
                    (tenant_sha, ref, tenant_sha, ref),
                ).fetchone()
                if live_child is not None:
                    raise TrustCenterConflict(
                        "binding changes require revoking child authorities first"
                    )
            updated = self._updated_context(
                current,
                actor_sha=actor,
                now=now,
                property_sha256=str(binding_body["property_sha256"]),
                profile_sha256=str(binding_body["profile_sha256"]),
                actor_sha256=str(binding_body["actor_sha256"]),
                binding_sha256=_sha256(binding_body),
                profile_authority_sha256=binding_body["profile_authority_sha256"],
                publication_history_limit=history_limit,
                receipt_limit=receipts,
                valid_until=valid,
                retained_until=retained,
            )
            self._write_context(connection, current, updated)
            self._insert_history(connection, tenant_sha, "context", ref, updated)
            self._audit(
                connection,
                tenant_sha,
                "context_revised",
                "context",
                ref,
                actor,
                updated.integrity_sha256,
                now,
            )
            result = asdict(updated)
            self._save_operation(
                connection,
                tenant_sha=tenant_sha,
                idempotency_key=idempotency_key,
                action="revise_context",
                context_ref=ref,
                request_sha=request_sha,
                result_kind="context",
                result=result,
                retained_until=retained,
                created_at=now,
            )
            connection.commit()
            return updated

    def revoke_context(
        self,
        tenant_id: str,
        context_ref: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> TrustCenterContextAuthority:
        """Revoke the context and every live child authority atomically."""

        self._check_gate()
        tenant = _tenant(tenant_id)
        tenant_sha = _text_sha256(tenant)
        ref = _ref(context_ref, "context_ref")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        now = _now(self._clock)
        actor = self._principal(tenant, "context_admin", now)
        request_sha = _sha256(
            {"action": "revoke_context", "context_ref": ref, "expected_revision": expected}
        )
        with self._connect() as connection:
            self._begin(connection)
            replay = self._replay(
                connection, tenant_sha, idempotency_key, "revoke_context", request_sha
            )
            if replay is not None:
                return _context_from_payload(replay[1])
            row = self._context_row(connection, tenant_sha, ref)
            current = _context_from_payload(self._row_payload(row, "context"))
            if current.status != "active" or current.revision != expected:
                raise TrustCenterConflict("context revision or state changed")
            updated = self._updated_context(current, actor_sha=actor, now=now, status="revoked")
            self._write_context(connection, current, updated)
            self._insert_history(connection, tenant_sha, "context", ref, updated)
            for table, kind, id_column, loader in (
                (
                    "trust_center_authority_grants",
                    "grant",
                    "grant_ref",
                    _grant_from_payload,
                ),
                (
                    "trust_center_authority_rights",
                    "rights_authorization",
                    "authorization_ref",
                    _rights_from_payload,
                ),
            ):
                rows = connection.execute(
                    f"SELECT * FROM {table} WHERE tenant_sha256=? AND context_ref=? "  # noqa: S608
                    "AND status IN ('proposed','first_approved','active')",
                    (tenant_sha, ref),
                ).fetchall()
                for child_row in rows:
                    child = loader(self._row_payload(child_row, kind))
                    revoked = replace(
                        child,
                        status="revoked",
                        updated_at=now,
                        revision=child.revision + 1,
                        integrity_sha256="0" * 64,
                    )
                    revoked = replace(revoked, integrity_sha256=_record_integrity(revoked))
                    connection.execute(
                        f"UPDATE {table} SET status=?,revision=?,payload_json=?,"  # noqa: S608
                        f"integrity_sha256=? WHERE tenant_sha256=? AND {id_column}=? "
                        "AND revision=?",
                        (
                            "revoked",
                            revoked.revision,
                            _canonical(asdict(revoked)).decode("ascii"),
                            revoked.integrity_sha256,
                            tenant_sha,
                            getattr(revoked, id_column),
                            child.revision,
                        ),
                    )
                    self._insert_history(
                        connection,
                        tenant_sha,
                        kind,
                        str(getattr(revoked, id_column)),
                        revoked,
                    )
            self._audit(
                connection,
                tenant_sha,
                "context_revoked",
                "context",
                ref,
                actor,
                updated.integrity_sha256,
                now,
            )
            result = asdict(updated)
            self._save_operation(
                connection,
                tenant_sha=tenant_sha,
                idempotency_key=idempotency_key,
                action="revoke_context",
                context_ref=ref,
                request_sha=request_sha,
                result_kind="context",
                result=result,
                retained_until=current.retained_until,
                created_at=now,
            )
            connection.commit()
            return updated

    def _mutated_context_generation(
        self,
        connection: sqlite3.Connection,
        current: TrustCenterContextAuthority,
        actor_sha: str,
        now: float,
    ) -> TrustCenterContextAuthority:
        updated = self._updated_context(current, actor_sha=actor_sha, now=now)
        self._write_context(connection, current, updated)
        self._insert_history(
            connection, current.tenant_sha256, "context", current.context_ref, updated
        )
        return updated

    def propose_capability_grant(
        self,
        tenant_id: str,
        context_ref: str,
        capability: str,
        *,
        expected_context_revision: int,
        valid_until: float,
        idempotency_key: str,
    ) -> CapabilityGrantAuthority:
        self._check_gate()
        tenant = _tenant(tenant_id)
        tenant_sha = _text_sha256(tenant)
        ref = _ref(context_ref, "context_ref")
        if capability not in CAPABILITIES:
            raise TrustCenterValidationError("capability is unsupported")
        expected = _integer(expected_context_revision, "expected_context_revision", 1, 2**31 - 1)
        now = _now(self._clock)
        actor = self._principal(tenant, "capability_request", now)
        request_sha = _sha256(
            {
                "action": "propose_capability_grant",
                "context_ref": ref,
                "capability": capability,
                "expected_context_revision": expected,
                "valid_until": valid_until,
            }
        )
        with self._connect() as connection:
            self._begin(connection)
            replay = self._replay(
                connection,
                tenant_sha,
                idempotency_key,
                "propose_capability_grant",
                request_sha,
            )
            if replay is not None:
                return _grant_from_payload(replay[1])
            context = _context_from_payload(
                self._row_payload(self._context_row(connection, tenant_sha, ref), "context")
            )
            if (
                context.status != "active"
                or context.revision != expected
                or context.valid_until <= now
                or _same(actor, context.actor_sha256)
            ):
                raise TrustCenterConflict("context authority is stale or actor-separated")
            valid = _validity(valid_until, now, context.retained_until)
            if valid > context.valid_until:
                raise TrustCenterValidationError("grant cannot outlive its context")
            if capability == "profile_data" and context.profile_authority_sha256 is None:
                raise TrustCenterConflict("profile-data public authority is not pinned")
            duplicate = connection.execute(
                "SELECT 1 FROM trust_center_authority_grants WHERE tenant_sha256=? "
                "AND context_ref=? AND capability=? AND status IN "
                "('proposed','first_approved','active') LIMIT 1",
                (tenant_sha, ref, capability),
            ).fetchone()
            if duplicate is not None:
                raise TrustCenterConflict("capability already has a live authority")
            grant_ref = self._new_ref("TCG")
            record = CapabilityGrantAuthority(
                grant_ref=grant_ref,
                context_ref=ref,
                tenant_sha256=tenant_sha,
                property_sha256=context.property_sha256,
                profile_sha256=context.profile_sha256,
                capability=capability,
                requested_by_sha256=actor,
                approved_by_sha256=None,
                second_approved_by_sha256=None,
                valid_until=valid,
                retained_until=context.retained_until,
                status="proposed",
                created_at=now,
                updated_at=now,
                revision=1,
                integrity_sha256="0" * 64,
            )
            record = replace(record, integrity_sha256=_record_integrity(record))
            connection.execute(
                "INSERT INTO trust_center_authority_grants VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    grant_ref,
                    ref,
                    tenant_sha,
                    capability,
                    record.status,
                    record.revision,
                    valid,
                    record.retained_until,
                    _canonical(asdict(record)).decode("ascii"),
                    record.integrity_sha256,
                ),
            )
            self._insert_history(connection, tenant_sha, "grant", grant_ref, record)
            context = self._mutated_context_generation(connection, context, actor, now)
            self._audit(
                connection,
                tenant_sha,
                "capability_grant_proposed",
                "grant",
                grant_ref,
                actor,
                record.integrity_sha256,
                now,
            )
            result = asdict(record)
            self._save_operation(
                connection,
                tenant_sha=tenant_sha,
                idempotency_key=idempotency_key,
                action="propose_capability_grant",
                context_ref=ref,
                request_sha=request_sha,
                result_kind="grant",
                result=result,
                retained_until=context.retained_until,
                created_at=now,
            )
            connection.commit()
            return record

    def approve_capability_grant(
        self,
        tenant_id: str,
        grant_ref: str,
        *,
        expected_revision: int,
        expected_context_revision: int,
        idempotency_key: str,
    ) -> CapabilityGrantAuthority:
        self._check_gate()
        tenant = _tenant(tenant_id)
        tenant_sha = _text_sha256(tenant)
        ref = _ref(grant_ref, "grant_ref")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        context_expected = _integer(
            expected_context_revision, "expected_context_revision", 1, 2**31 - 1
        )
        now = _now(self._clock)
        actor = self._principal(tenant, "capability_approve", now)
        request_sha = _sha256(
            {
                "action": "approve_capability_grant",
                "grant_ref": ref,
                "expected_revision": expected,
                "expected_context_revision": context_expected,
            }
        )
        with self._connect() as connection:
            self._begin(connection)
            replay = self._replay(
                connection,
                tenant_sha,
                idempotency_key,
                "approve_capability_grant",
                request_sha,
            )
            if replay is not None:
                return _grant_from_payload(replay[1])
            row = self._child_row(
                connection,
                "trust_center_authority_grants",
                "grant_ref",
                tenant_sha,
                ref,
            )
            current = _grant_from_payload(self._row_payload(row, "grant"))
            context = _context_from_payload(
                self._row_payload(
                    self._context_row(connection, tenant_sha, current.context_ref), "context"
                )
            )
            if (
                current.revision != expected
                or current.status not in {"proposed", "first_approved"}
                or current.valid_until <= now
                or context.status != "active"
                or context.revision != context_expected
                or context.valid_until <= now
                or _same(actor, context.actor_sha256)
                or _same(actor, current.requested_by_sha256)
                or _same(actor, current.approved_by_sha256)
            ):
                raise TrustCenterConflict("grant approval authority or separation changed")
            if current.status == "proposed":
                changes: dict[str, object] = {
                    "approved_by_sha256": actor,
                    "status": "first_approved",
                }
            else:
                changes = {"second_approved_by_sha256": actor, "status": "active"}
            updated = replace(
                current,
                **changes,
                updated_at=now,
                revision=current.revision + 1,
                integrity_sha256="0" * 64,
            )
            updated = replace(updated, integrity_sha256=_record_integrity(updated))
            result = connection.execute(
                "UPDATE trust_center_authority_grants SET status=?,revision=?,payload_json=?,"
                "integrity_sha256=? WHERE tenant_sha256=? AND grant_ref=? AND revision=?",
                (
                    updated.status,
                    updated.revision,
                    _canonical(asdict(updated)).decode("ascii"),
                    updated.integrity_sha256,
                    tenant_sha,
                    ref,
                    current.revision,
                ),
            )
            if result.rowcount != 1:
                raise TrustCenterConflict("grant approval CAS failed")
            self._insert_history(connection, tenant_sha, "grant", ref, updated)
            context = self._mutated_context_generation(connection, context, actor, now)
            event = (
                "capability_grant_first_approved"
                if updated.status == "first_approved"
                else "capability_grant_activated"
            )
            self._audit(
                connection,
                tenant_sha,
                event,
                "grant",
                ref,
                actor,
                updated.integrity_sha256,
                now,
            )
            payload = asdict(updated)
            self._save_operation(
                connection,
                tenant_sha=tenant_sha,
                idempotency_key=idempotency_key,
                action="approve_capability_grant",
                context_ref=current.context_ref,
                request_sha=request_sha,
                result_kind="grant",
                result=payload,
                retained_until=context.retained_until,
                created_at=now,
            )
            connection.commit()
            return updated

    def revoke_capability_grant(
        self,
        tenant_id: str,
        grant_ref: str,
        *,
        expected_revision: int,
        expected_context_revision: int,
        idempotency_key: str,
    ) -> CapabilityGrantAuthority:
        return self._revoke_child(
            tenant_id,
            grant_ref,
            expected_revision=expected_revision,
            expected_context_revision=expected_context_revision,
            idempotency_key=idempotency_key,
            table="trust_center_authority_grants",
            id_column="grant_ref",
            kind="grant",
            permission="context_admin",
            action="revoke_capability_grant",
            loader=_grant_from_payload,
        )

    def propose_rights_authorization(
        self,
        tenant_id: str,
        context_ref: str,
        case_id: str,
        expected_case_sha256: str,
        *,
        expected_context_revision: int,
        valid_until: float,
        idempotency_key: str,
    ) -> RightsCaseAuthorizationAuthority:
        self._check_gate()
        tenant = _tenant(tenant_id)
        tenant_sha = _text_sha256(tenant)
        ref = _ref(context_ref, "context_ref")
        case = _ref(case_id, "case_id")
        case_sha = _digest(expected_case_sha256, "expected_case_sha256")
        expected = _integer(expected_context_revision, "expected_context_revision", 1, 2**31 - 1)
        now = _now(self._clock)
        actor = self._principal(tenant, "rights_request", now)
        request_sha = _sha256(
            {
                "action": "propose_rights_authorization",
                "context_ref": ref,
                "case_id": case,
                "expected_case_sha256": case_sha,
                "expected_context_revision": expected,
                "valid_until": valid_until,
            }
        )
        with self._connect() as connection:
            self._begin(connection)
            replay = self._replay(
                connection,
                tenant_sha,
                idempotency_key,
                "propose_rights_authorization",
                request_sha,
            )
            if replay is not None:
                return _rights_from_payload(replay[1])
            context = _context_from_payload(
                self._row_payload(self._context_row(connection, tenant_sha, ref), "context")
            )
            if (
                context.status != "active"
                or context.revision != expected
                or context.valid_until <= now
                or _same(actor, context.actor_sha256)
            ):
                raise TrustCenterConflict("context authority is stale or actor-separated")
            active_rights_grant = connection.execute(
                "SELECT valid_until FROM trust_center_authority_grants WHERE tenant_sha256=? "
                "AND context_ref=? AND capability='rights_cases' AND status='active' "
                "AND valid_until>? LIMIT 1",
                (tenant_sha, ref, now),
            ).fetchone()
            if active_rights_grant is None:
                raise TrustCenterConflict("rights_cases capability is not active")
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM trust_center_authority_rights "
                    "WHERE tenant_sha256=? AND context_ref=? AND status IN "
                    "('proposed','first_approved','active')",
                    (tenant_sha, ref),
                ).fetchone()[0]
            )
            if count >= _MAX_RIGHTS_CASES:
                raise TrustCenterConflict("rights authorization count reached its bound")
            if connection.execute(
                "SELECT 1 FROM trust_center_authority_rights WHERE tenant_sha256=? "
                "AND context_ref=? AND case_id=? AND status IN "
                "('proposed','first_approved','active') LIMIT 1",
                (tenant_sha, ref, case),
            ).fetchone():
                raise TrustCenterConflict("case already has a live authorization")
            valid = _validity(valid_until, now, context.retained_until)
            if valid > context.valid_until:
                raise TrustCenterValidationError("rights authorization cannot outlive context")
            if valid > float(active_rights_grant["valid_until"]):
                raise TrustCenterValidationError(
                    "rights authorization cannot outlive its capability grant"
                )
            authorization_ref = self._new_ref("TCR")
            record = RightsCaseAuthorizationAuthority(
                authorization_ref=authorization_ref,
                context_ref=ref,
                tenant_sha256=tenant_sha,
                case_id=case,
                expected_case_sha256=case_sha,
                requested_by_sha256=actor,
                approved_by_sha256=None,
                second_approved_by_sha256=None,
                valid_until=valid,
                retained_until=context.retained_until,
                status="proposed",
                created_at=now,
                updated_at=now,
                revision=1,
                integrity_sha256="0" * 64,
            )
            record = replace(record, integrity_sha256=_record_integrity(record))
            connection.execute(
                "INSERT INTO trust_center_authority_rights VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    authorization_ref,
                    ref,
                    tenant_sha,
                    case,
                    record.status,
                    record.revision,
                    valid,
                    record.retained_until,
                    _canonical(asdict(record)).decode("ascii"),
                    record.integrity_sha256,
                ),
            )
            self._insert_history(
                connection, tenant_sha, "rights_authorization", authorization_ref, record
            )
            context = self._mutated_context_generation(connection, context, actor, now)
            self._audit(
                connection,
                tenant_sha,
                "rights_authorization_proposed",
                "rights_authorization",
                authorization_ref,
                actor,
                record.integrity_sha256,
                now,
            )
            payload = asdict(record)
            self._save_operation(
                connection,
                tenant_sha=tenant_sha,
                idempotency_key=idempotency_key,
                action="propose_rights_authorization",
                context_ref=ref,
                request_sha=request_sha,
                result_kind="rights_authorization",
                result=payload,
                retained_until=context.retained_until,
                created_at=now,
            )
            connection.commit()
            return record

    def approve_rights_authorization(
        self,
        tenant_id: str,
        authorization_ref: str,
        *,
        expected_revision: int,
        expected_context_revision: int,
        idempotency_key: str,
    ) -> RightsCaseAuthorizationAuthority:
        return self._approve_rights(
            tenant_id,
            authorization_ref,
            expected_revision=expected_revision,
            expected_context_revision=expected_context_revision,
            idempotency_key=idempotency_key,
        )

    def _approve_rights(
        self,
        tenant_id: str,
        authorization_ref: str,
        *,
        expected_revision: int,
        expected_context_revision: int,
        idempotency_key: str,
    ) -> RightsCaseAuthorizationAuthority:
        self._check_gate()
        tenant = _tenant(tenant_id)
        tenant_sha = _text_sha256(tenant)
        ref = _ref(authorization_ref, "authorization_ref")
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        context_expected = _integer(
            expected_context_revision, "expected_context_revision", 1, 2**31 - 1
        )
        now = _now(self._clock)
        actor = self._principal(tenant, "rights_approve", now)
        request_sha = _sha256(
            {
                "action": "approve_rights_authorization",
                "authorization_ref": ref,
                "expected_revision": expected,
                "expected_context_revision": context_expected,
            }
        )
        with self._connect() as connection:
            self._begin(connection)
            replay = self._replay(
                connection,
                tenant_sha,
                idempotency_key,
                "approve_rights_authorization",
                request_sha,
            )
            if replay is not None:
                return _rights_from_payload(replay[1])
            row = self._child_row(
                connection,
                "trust_center_authority_rights",
                "authorization_ref",
                tenant_sha,
                ref,
            )
            current = _rights_from_payload(self._row_payload(row, "rights authorization"))
            context = _context_from_payload(
                self._row_payload(
                    self._context_row(connection, tenant_sha, current.context_ref), "context"
                )
            )
            if (
                current.revision != expected
                or current.status not in {"proposed", "first_approved"}
                or current.valid_until <= now
                or context.status != "active"
                or context.revision != context_expected
                or context.valid_until <= now
                or _same(actor, context.actor_sha256)
                or _same(actor, current.requested_by_sha256)
                or _same(actor, current.approved_by_sha256)
            ):
                raise TrustCenterConflict("rights approval authority or separation changed")
            if current.status == "proposed":
                changes: dict[str, object] = {
                    "approved_by_sha256": actor,
                    "status": "first_approved",
                }
            else:
                changes = {"second_approved_by_sha256": actor, "status": "active"}
            updated = replace(
                current,
                **changes,
                updated_at=now,
                revision=current.revision + 1,
                integrity_sha256="0" * 64,
            )
            updated = replace(updated, integrity_sha256=_record_integrity(updated))
            result = connection.execute(
                "UPDATE trust_center_authority_rights SET status=?,revision=?,payload_json=?,"
                "integrity_sha256=? WHERE tenant_sha256=? AND authorization_ref=? AND revision=?",
                (
                    updated.status,
                    updated.revision,
                    _canonical(asdict(updated)).decode("ascii"),
                    updated.integrity_sha256,
                    tenant_sha,
                    ref,
                    current.revision,
                ),
            )
            if result.rowcount != 1:
                raise TrustCenterConflict("rights approval CAS failed")
            self._insert_history(connection, tenant_sha, "rights_authorization", ref, updated)
            context = self._mutated_context_generation(connection, context, actor, now)
            event = (
                "rights_authorization_first_approved"
                if updated.status == "first_approved"
                else "rights_authorization_activated"
            )
            self._audit(
                connection,
                tenant_sha,
                event,
                "rights_authorization",
                ref,
                actor,
                updated.integrity_sha256,
                now,
            )
            payload = asdict(updated)
            self._save_operation(
                connection,
                tenant_sha=tenant_sha,
                idempotency_key=idempotency_key,
                action="approve_rights_authorization",
                context_ref=current.context_ref,
                request_sha=request_sha,
                result_kind="rights_authorization",
                result=payload,
                retained_until=context.retained_until,
                created_at=now,
            )
            connection.commit()
            return updated

    def revoke_rights_authorization(
        self,
        tenant_id: str,
        authorization_ref: str,
        *,
        expected_revision: int,
        expected_context_revision: int,
        idempotency_key: str,
    ) -> RightsCaseAuthorizationAuthority:
        return self._revoke_child(
            tenant_id,
            authorization_ref,
            expected_revision=expected_revision,
            expected_context_revision=expected_context_revision,
            idempotency_key=idempotency_key,
            table="trust_center_authority_rights",
            id_column="authorization_ref",
            kind="rights_authorization",
            permission="context_admin",
            action="revoke_rights_authorization",
            loader=_rights_from_payload,
        )

    def _revoke_child(
        self,
        tenant_id: str,
        object_ref: str,
        *,
        expected_revision: int,
        expected_context_revision: int,
        idempotency_key: str,
        table: str,
        id_column: str,
        kind: str,
        permission: str,
        action: str,
        loader: Callable[[Mapping[str, Any]], Any],
    ) -> Any:
        self._check_gate()
        tenant = _tenant(tenant_id)
        tenant_sha = _text_sha256(tenant)
        ref = _ref(object_ref, id_column)
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        context_expected = _integer(
            expected_context_revision, "expected_context_revision", 1, 2**31 - 1
        )
        now = _now(self._clock)
        actor = self._principal(tenant, permission, now)
        request_sha = _sha256(
            {
                "action": action,
                id_column: ref,
                "expected_revision": expected,
                "expected_context_revision": context_expected,
            }
        )
        with self._connect() as connection:
            self._begin(connection)
            replay = self._replay(connection, tenant_sha, idempotency_key, action, request_sha)
            if replay is not None:
                return loader(replay[1])
            row = self._child_row(connection, table, id_column, tenant_sha, ref)
            current = loader(self._row_payload(row, kind))
            context = _context_from_payload(
                self._row_payload(
                    self._context_row(connection, tenant_sha, current.context_ref), "context"
                )
            )
            if (
                current.revision != expected
                or current.status not in _ACTIVE_STATES
                or context.status != "active"
                or context.revision != context_expected
                or _same(actor, context.actor_sha256)
            ):
                raise TrustCenterConflict("revocation authority or CAS changed")
            updated = replace(
                current,
                status="revoked",
                updated_at=now,
                revision=current.revision + 1,
                integrity_sha256="0" * 64,
            )
            updated = replace(updated, integrity_sha256=_record_integrity(updated))
            result = connection.execute(
                f"UPDATE {table} SET status=?,revision=?,payload_json=?,integrity_sha256=? "  # noqa: S608
                f"WHERE tenant_sha256=? AND {id_column}=? AND revision=?",
                (
                    "revoked",
                    updated.revision,
                    _canonical(asdict(updated)).decode("ascii"),
                    updated.integrity_sha256,
                    tenant_sha,
                    ref,
                    current.revision,
                ),
            )
            if result.rowcount != 1:
                raise TrustCenterConflict("revocation CAS failed")
            self._insert_history(connection, tenant_sha, kind, ref, updated)
            if kind == "grant" and getattr(current, "capability", None) == "rights_cases":
                rows = connection.execute(
                    "SELECT * FROM trust_center_authority_rights WHERE tenant_sha256=? "
                    "AND context_ref=? AND status IN ('proposed','first_approved','active')",
                    (tenant_sha, current.context_ref),
                ).fetchall()
                for rights_row in rows:
                    right = _rights_from_payload(
                        self._row_payload(rights_row, "rights authorization")
                    )
                    right_revoked = replace(
                        right,
                        status="revoked",
                        updated_at=now,
                        revision=right.revision + 1,
                        integrity_sha256="0" * 64,
                    )
                    right_revoked = replace(
                        right_revoked,
                        integrity_sha256=_record_integrity(right_revoked),
                    )
                    connection.execute(
                        "UPDATE trust_center_authority_rights SET status='revoked',"
                        "revision=?,payload_json=?,integrity_sha256=? WHERE tenant_sha256=? "
                        "AND authorization_ref=? AND revision=?",
                        (
                            right_revoked.revision,
                            _canonical(asdict(right_revoked)).decode("ascii"),
                            right_revoked.integrity_sha256,
                            tenant_sha,
                            right.authorization_ref,
                            right.revision,
                        ),
                    )
                    self._insert_history(
                        connection,
                        tenant_sha,
                        "rights_authorization",
                        right.authorization_ref,
                        right_revoked,
                    )
                    self._audit(
                        connection,
                        tenant_sha,
                        "rights_authorization_revoked_with_capability",
                        "rights_authorization",
                        right.authorization_ref,
                        actor,
                        right_revoked.integrity_sha256,
                        now,
                    )
            context = self._mutated_context_generation(connection, context, actor, now)
            self._audit(
                connection,
                tenant_sha,
                f"{kind}_revoked",
                kind,
                ref,
                actor,
                updated.integrity_sha256,
                now,
            )
            payload = asdict(updated)
            self._save_operation(
                connection,
                tenant_sha=tenant_sha,
                idempotency_key=idempotency_key,
                action=action,
                context_ref=current.context_ref,
                request_sha=request_sha,
                result_kind=kind,
                result=payload,
                retained_until=context.retained_until,
                created_at=now,
            )
            connection.commit()
            return updated

    def get_context_authority(
        self, tenant_id: str, context_ref: str
    ) -> TrustCenterContextAuthority:
        self._check_gate()
        tenant = _tenant(tenant_id)
        now = _now(self._clock)
        self._principal(tenant, "authority_read", now)
        tenant_sha = _text_sha256(tenant)
        ref = _ref(context_ref, "context_ref")
        with self._connect() as connection:
            return _context_from_payload(
                self._row_payload(self._context_row(connection, tenant_sha, ref), "context")
            )

    def _resolved_context_once(self, context_ref: str, now: float) -> TrustCenterContext:
        ref = _ref(context_ref, "context_ref")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM trust_center_authority_contexts WHERE context_ref=?",
                (ref,),
            ).fetchone()
            if row is None:
                raise TrustCenterAuthorityNotFound("trust-center context was not found")
            authority = _context_from_payload(self._row_payload(row, "context"))
            grant_rows = connection.execute(
                "SELECT * FROM trust_center_authority_grants WHERE tenant_sha256=? "
                "AND context_ref=? AND status='active' AND valid_until>? "
                "ORDER BY capability,grant_ref",
                (authority.tenant_sha256, ref, now),
            ).fetchall()
            right_rows = connection.execute(
                "SELECT * FROM trust_center_authority_rights WHERE tenant_sha256=? "
                "AND context_ref=? AND status='active' AND valid_until>? "
                "ORDER BY case_id,authorization_ref",
                (authority.tenant_sha256, ref, now),
            ).fetchall()
            grants = tuple(
                _grant_from_payload(self._row_payload(item, "grant")) for item in grant_rows
            )
            rights = tuple(
                _rights_from_payload(self._row_payload(item, "rights authorization"))
                for item in right_rows
            )
        if (
            authority.status != "active"
            or authority.valid_until <= now
            or authority.retained_until <= now
            or not grants
        ):
            raise TrustCenterConflict("trust-center context is unavailable")
        if len(grants) > len(CAPABILITIES) or len(rights) > _MAX_RIGHTS_CASES:
            raise TrustCenterIntegrityError("trust-center authority exceeds its strict bound")
        binding, binding_body = self._binding(ref)
        if (
            not _same(authority.tenant_sha256, binding_body["tenant_sha256"])
            or not _same(authority.property_sha256, binding_body["property_sha256"])
            or not _same(authority.profile_sha256, binding_body["profile_sha256"])
            or not _same(authority.actor_sha256, binding_body["actor_sha256"])
            or not _same(authority.binding_sha256, _sha256(binding_body))
            or authority.profile_authority_sha256 != binding_body["profile_authority_sha256"]
        ):
            raise TrustCenterConflict("trust-center public binding drifted")
        capabilities: set[str] = set()
        public_grants: list[TrustCenterCapabilityGrant] = []
        for grant in grants:
            if (
                grant.capability in capabilities
                or grant.approved_by_sha256 is None
                or grant.second_approved_by_sha256 is None
                or _same(grant.requested_by_sha256, grant.approved_by_sha256)
                or _same(grant.requested_by_sha256, grant.second_approved_by_sha256)
                or _same(grant.approved_by_sha256, grant.second_approved_by_sha256)
                or _same(authority.actor_sha256, grant.requested_by_sha256)
                or _same(authority.actor_sha256, grant.approved_by_sha256)
                or _same(authority.actor_sha256, grant.second_approved_by_sha256)
                or not _same(grant.property_sha256, authority.property_sha256)
                or not _same(grant.profile_sha256, authority.profile_sha256)
            ):
                raise TrustCenterConflict("capability grant is duplicated or mismatched")
            capabilities.add(grant.capability)
            public = TrustCenterCapabilityGrant(
                capability=grant.capability,
                grant_ref=grant.grant_ref,
                tenant_sha256=authority.tenant_sha256,
                property_id=binding.property_id,
                profile_sha256=authority.profile_sha256,
                approved_by_sha256=grant.approved_by_sha256,
                second_approved_by_sha256=grant.second_approved_by_sha256,
                valid_until=grant.valid_until,
                grant_sha256="0" * 64,
                revoked=False,
            )
            public_grants.append(
                replace(
                    public,
                    grant_sha256=ConsumerTrustCenterSourceAdapter.capability_grant_sha256(public),
                )
            )
        public_rights: list[TrustCenterRightsAuthorization] = []
        cases: set[str] = set()
        for item in rights:
            if "rights_cases" not in capabilities:
                raise TrustCenterConflict(
                    "rights authorization exists without an active capability grant"
                )
            if (
                item.case_id in cases
                or item.approved_by_sha256 is None
                or item.second_approved_by_sha256 is None
                or _same(item.requested_by_sha256, item.approved_by_sha256)
                or _same(item.requested_by_sha256, item.second_approved_by_sha256)
                or _same(item.approved_by_sha256, item.second_approved_by_sha256)
                or _same(authority.actor_sha256, item.requested_by_sha256)
                or _same(authority.actor_sha256, item.approved_by_sha256)
                or _same(authority.actor_sha256, item.second_approved_by_sha256)
            ):
                raise TrustCenterConflict("rights authorization is duplicated or mismatched")
            cases.add(item.case_id)
            public = TrustCenterRightsAuthorization(
                case_id=item.case_id,
                expected_case_sha256=item.expected_case_sha256,
                approved_by_sha256=item.approved_by_sha256,
                second_approved_by_sha256=item.second_approved_by_sha256,
                valid_until=item.valid_until,
                authorization_sha256="0" * 64,
                revoked=False,
            )
            public_rights.append(
                replace(
                    public,
                    authorization_sha256=(
                        ConsumerTrustCenterSourceAdapter.rights_authorization_sha256(public)
                    ),
                )
            )
        if "profile_data" in capabilities and binding.profile_authority is None:
            raise TrustCenterConflict("profile-data authority is unavailable")
        context = TrustCenterContext(
            tenant_id=binding.tenant_id,
            property_id=binding.property_id,
            profile_id=binding.profile_id,
            actor_sha256=binding.actor_sha256,
            requested_locale=binding.requested_locale,
            server_origin=binding.server_origin,
            server_bundle_id=binding.server_bundle_id,
            server_platform=binding.server_platform,
            jurisdiction=binding.jurisdiction,
            country_code=binding.country_code,
            region_code=binding.region_code,
            profile_authority=binding.profile_authority,
            capability_grants=tuple(public_grants),
            rights_authorizations=tuple(public_rights),
            publication_history_limit=authority.publication_history_limit,
            receipt_limit=authority.receipt_limit,
            retained_until=authority.retained_until,
            revision=authority.revision,
            valid_until=authority.valid_until,
            context_sha256="0" * 64,
            revoked=False,
        )
        return replace(
            context,
            context_sha256=ConsumerTrustCenterSourceAdapter.context_sha256(context),
        )

    def make_context_resolver(self, context_ref: str) -> Callable[[], TrustCenterContext]:
        """Bind an opaque server reference and return the public zero-argument seam."""

        ref = _ref(context_ref, "context_ref")

        def resolve() -> TrustCenterContext:
            self._check_gate()
            now = _now(self._clock)
            first = self._resolved_context_once(ref, now)
            second = self._resolved_context_once(ref, now)
            if first != second:
                raise TrustCenterConflict("trust-center authority drifted during resolution")
            return second

        return resolve

    def export_signed_metadata(
        self,
        tenant_id: str,
        context_ref: str,
        *,
        idempotency_key: str,
    ) -> SignedTrustCenterAuthorityExport:
        """Sign digest-only authority metadata; never consumer data or key values."""

        self._check_gate()
        tenant = _tenant(tenant_id)
        tenant_sha = _text_sha256(tenant)
        ref = _ref(context_ref, "context_ref")
        now = _now(self._clock)
        actor = self._principal(tenant, "metadata_export", now)
        with self._connect() as connection:
            self._begin(connection)
            context = _context_from_payload(
                self._row_payload(self._context_row(connection, tenant_sha, ref), "context")
            )
            grants = [
                self._row_payload(row, "grant")
                for row in connection.execute(
                    "SELECT * FROM trust_center_authority_grants WHERE tenant_sha256=? "
                    "AND context_ref=? ORDER BY grant_ref",
                    (tenant_sha, ref),
                )
            ]
            rights = [
                self._row_payload(row, "rights authorization")
                for row in connection.execute(
                    "SELECT * FROM trust_center_authority_rights WHERE tenant_sha256=? "
                    "AND context_ref=? ORDER BY authorization_ref",
                    (tenant_sha, ref),
                )
            ]
            payload = {
                "schema": AUTHORITY_SCHEMA,
                "tenant_sha256": tenant_sha,
                "context": asdict(context),
                "capability_grants": grants,
                "rights_authorizations": rights,
                "boundaries": self.product_boundaries(),
            }
            request_sha = _sha256(
                {
                    "action": "export_signed_metadata",
                    "context_ref": ref,
                    "payload_sha256": _sha256(payload),
                    "signing_key_ref": self._signing_key_ref,
                }
            )
            replay = self._replay(
                connection,
                tenant_sha,
                idempotency_key,
                "export_signed_metadata",
                request_sha,
            )
            if replay is not None:
                return _export_from_payload(replay[1])
            try:
                key = self._signing_key_resolver(tenant, self._signing_key_ref)
            except ConsumerTrustCenterError:
                raise
            except Exception as exc:
                raise TrustCenterAuthorityConfigError(
                    "trust-center signing key resolution failed"
                ) from exc
            if not isinstance(key, bytes) or len(key) < 32:
                raise TrustCenterAuthorityConfigError(
                    "trust-center signing key must contain at least 32 bytes"
                )
            payload_sha = _sha256(payload)
            signature = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
            export = SignedTrustCenterAuthorityExport(
                schema=AUTHORITY_EXPORT_SCHEMA,
                export_id=self._new_ref("TCX"),
                tenant_sha256=tenant_sha,
                context_ref=ref,
                signing_key_ref=self._signing_key_ref,
                payload=payload,
                payload_sha256=payload_sha,
                signature_sha256=signature,
                retained_until=context.retained_until,
                created_at=now,
            )
            export_payload = asdict(export)
            export_integrity = _sha256(export_payload)
            connection.execute(
                "INSERT INTO trust_center_authority_exports VALUES(?,?,?,?,?,?)",
                (
                    export.export_id,
                    ref,
                    tenant_sha,
                    export.retained_until,
                    _canonical(export_payload).decode("ascii"),
                    export_integrity,
                ),
            )
            self._audit(
                connection,
                tenant_sha,
                "authority_metadata_exported",
                "authority_export",
                export.export_id,
                actor,
                export_integrity,
                now,
            )
            self._save_operation(
                connection,
                tenant_sha=tenant_sha,
                idempotency_key=idempotency_key,
                action="export_signed_metadata",
                context_ref=ref,
                request_sha=request_sha,
                result_kind="authority_export",
                result=export_payload,
                retained_until=context.retained_until,
                created_at=now,
            )
            connection.commit()
            return export

    def get_signed_metadata(
        self,
        tenant_id: str,
        export_id: str,
    ) -> SignedTrustCenterAuthorityExport:
        """Read one tenant-local export after row and signature verification."""

        self._check_gate()
        tenant = _tenant(tenant_id)
        tenant_sha = _text_sha256(tenant)
        export_ref = _ref(export_id, "export_id")
        now = _now(self._clock)
        self._principal(tenant, "authority_read", now)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM trust_center_authority_exports "
                "WHERE tenant_sha256=? AND export_id=?",
                (tenant_sha, export_ref),
            ).fetchone()
        if row is None:
            raise TrustCenterAuthorityNotFound("trust-center authority export was not found")
        payload = _loads(row["payload_json"], "authority export")
        if (
            payload.get("export_id") != row["export_id"]
            or payload.get("context_ref") != row["context_ref"]
            or payload.get("tenant_sha256") != row["tenant_sha256"]
            or payload.get("retained_until") != row["retained_until"]
            or not _same(_sha256(payload), row["integrity_sha256"])
        ):
            raise TrustCenterIntegrityError("authority export failed integrity")
        exported = _export_from_payload(payload)
        if not self.verify_signed_metadata(exported):
            raise TrustCenterIntegrityError("authority export signature failed verification")
        return exported

    def verify_signed_metadata(self, export: SignedTrustCenterAuthorityExport) -> bool:
        self._check_gate()
        if not isinstance(export, SignedTrustCenterAuthorityExport):
            return False
        try:
            tenant_sha = _digest(export.tenant_sha256, "export tenant_sha256")
            if (
                export.schema != AUTHORITY_EXPORT_SCHEMA
                or export.signing_key_ref != self._signing_key_ref
            ):
                return False
            if export.payload.get("tenant_sha256") != tenant_sha:
                return False
            if not _same(export.payload_sha256, _sha256(export.payload)):
                return False
            tenant_id = None
            # No raw tenant is present in the export. Verification therefore
            # resolves the current binding for the server-bound context.
            binding, binding_body = self._binding(export.context_ref)
            if not _same(binding_body["tenant_sha256"], tenant_sha):
                return False
            tenant_id = binding.tenant_id
            key = self._signing_key_resolver(tenant_id, self._signing_key_ref)
            if not isinstance(key, bytes) or len(key) < 32:
                return False
            expected = hmac.new(key, _canonical(export.payload), hashlib.sha256).hexdigest()
            return _same(expected, export.signature_sha256)
        except (ConsumerTrustCenterError, TypeError, ValueError):
            return False

    def retention_due(self, tenant_id: str, *, before: float, limit: int = 100) -> tuple[str, ...]:
        self._check_gate()
        tenant = _tenant(tenant_id)
        now = _now(self._clock)
        self._principal(tenant, "authority_read", now)
        cutoff = _timestamp(before, "before")
        bounded = _integer(limit, "limit", 1, _MAX_PURGE)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT context_ref FROM trust_center_authority_contexts "
                "WHERE tenant_sha256=? AND retained_until<=? "
                "ORDER BY retained_until,context_ref LIMIT ?",
                (_text_sha256(tenant), cutoff, bounded),
            ).fetchall()
        return tuple(str(row["context_ref"]) for row in rows)

    def purge_expired(
        self,
        tenant_id: str,
        *,
        before: float,
        limit: int = 100,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        """Purge expired payload/history while retaining chained audit tombstones."""

        self._check_gate()
        tenant = _tenant(tenant_id)
        tenant_sha = _text_sha256(tenant)
        now = _now(self._clock)
        actor = self._principal(tenant, "retention_purge", now)
        cutoff = _timestamp(before, "before")
        if cutoff > now:
            raise TrustCenterValidationError("purge cutoff cannot be in the future")
        bounded = _integer(limit, "limit", 1, _MAX_PURGE)
        request_sha = _sha256({"action": "purge_expired", "before": cutoff, "limit": bounded})
        with self._connect() as connection:
            self._begin(connection)
            replay = self._replay(
                connection, tenant_sha, idempotency_key, "purge_expired", request_sha
            )
            if replay is not None:
                return replay[1]
            rows = connection.execute(
                "SELECT context_ref,integrity_sha256 FROM trust_center_authority_contexts "
                "WHERE tenant_sha256=? AND retained_until<=? "
                "ORDER BY retained_until,context_ref LIMIT ?",
                (tenant_sha, cutoff, bounded),
            ).fetchall()
            purged: list[str] = []
            for row in rows:
                ref = str(row["context_ref"])
                connection.execute(
                    "DELETE FROM trust_center_authority_history WHERE tenant_sha256=? "
                    "AND (object_ref=? OR object_ref IN "
                    "(SELECT grant_ref FROM trust_center_authority_grants "
                    "WHERE tenant_sha256=? AND context_ref=?) OR object_ref IN "
                    "(SELECT authorization_ref FROM trust_center_authority_rights "
                    "WHERE tenant_sha256=? AND context_ref=?))",
                    (tenant_sha, ref, tenant_sha, ref, tenant_sha, ref),
                )
                connection.execute(
                    "DELETE FROM trust_center_authority_operations WHERE tenant_sha256=? "
                    "AND context_ref=?",
                    (tenant_sha, ref),
                )
                connection.execute(
                    "DELETE FROM trust_center_authority_contexts WHERE tenant_sha256=? "
                    "AND context_ref=? AND retained_until<=?",
                    (tenant_sha, ref, cutoff),
                )
                self._audit(
                    connection,
                    tenant_sha,
                    "context_payload_purged",
                    "context",
                    ref,
                    actor,
                    str(row["integrity_sha256"]),
                    now,
                )
                purged.append(ref)
            result: dict[str, object] = {
                "schema": "lightwork.consumer-trust-center-authority-purge.v1",
                "tenant_sha256": tenant_sha,
                "cutoff": cutoff,
                "contexts_purged": tuple(purged),
                "count": len(purged),
            }
            # Purge idempotency is retained for one bounded year and contains
            # only closed digests/opaque references.
            operation_retention = min(now + _MAX_AUTHORITY_SECONDS, now + _MAX_RETENTION_SECONDS)
            self._save_operation(
                connection,
                tenant_sha=tenant_sha,
                idempotency_key=idempotency_key,
                action="purge_expired",
                context_ref="retention-purge",
                request_sha=request_sha,
                result_kind="purge_result",
                result=result,
                retained_until=operation_retention,
                created_at=now,
            )
            connection.commit()
            return result

    def history(
        self,
        tenant_id: str,
        object_kind: str,
        object_ref: str,
        *,
        limit: int = 100,
    ) -> tuple[Mapping[str, object], ...]:
        self._check_gate()
        tenant = _tenant(tenant_id)
        now = _now(self._clock)
        self._principal(tenant, "authority_read", now)
        if object_kind not in {"context", "grant", "rights_authorization"}:
            raise TrustCenterValidationError("object_kind is invalid")
        ref = _ref(object_ref, "object_ref")
        bounded = _integer(limit, "limit", 1, _MAX_HISTORY_LIMIT)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM trust_center_authority_history "
                "WHERE tenant_sha256=? AND object_kind=? AND object_ref=? "
                "ORDER BY revision DESC LIMIT ?",
                (_text_sha256(tenant), object_kind, ref, bounded),
            ).fetchall()
        return tuple(_loads(row["payload_json"], "authority history") for row in rows)

    def list_authority(self, tenant_id: str, *, limit: int = 100) -> dict[str, tuple[object, ...]]:
        """Newest-first contexts, capability grants and rights authorizations.

        Read-only and integrity-checked like the single-object reads, so an
        operator page can show every record with its own buttons.
        """

        self._check_gate()
        tenant = _tenant(tenant_id)
        now = _now(self._clock)
        self._principal(tenant, "authority_read", now)
        bounded = _integer(limit, "limit", 1, _MAX_HISTORY_LIMIT)
        tenant_sha = _text_sha256(tenant)
        with self._connect() as connection:
            contexts = connection.execute(
                "SELECT * FROM trust_center_authority_contexts WHERE tenant_sha256=? "
                "ORDER BY valid_until DESC,context_ref LIMIT ?",
                (tenant_sha, bounded),
            ).fetchall()
            grants = connection.execute(
                "SELECT * FROM trust_center_authority_grants WHERE tenant_sha256=? "
                "ORDER BY valid_until DESC,grant_ref LIMIT ?",
                (tenant_sha, bounded),
            ).fetchall()
            rights = connection.execute(
                "SELECT * FROM trust_center_authority_rights WHERE tenant_sha256=? "
                "ORDER BY valid_until DESC,authorization_ref LIMIT ?",
                (tenant_sha, bounded),
            ).fetchall()
            return {
                "contexts": tuple(
                    _context_from_payload(self._row_payload(row, "context")) for row in contexts
                ),
                "grants": tuple(
                    _grant_from_payload(self._row_payload(row, "grant")) for row in grants
                ),
                "rights_authorizations": tuple(
                    _rights_from_payload(self._row_payload(row, "rights authorization"))
                    for row in rights
                ),
            }

    def verify_integrity(self, tenant_id: str) -> Mapping[str, int]:
        self._check_gate()
        tenant = _tenant(tenant_id)
        now = _now(self._clock)
        self._principal(tenant, "authority_read", now)
        tenant_sha = _text_sha256(tenant)
        counts = {
            "contexts": 0,
            "grants": 0,
            "rights_authorizations": 0,
            "history": 0,
            "operations": 0,
            "exports": 0,
            "audit_events": 0,
        }
        with self._connect() as connection:
            for table, label, key in (
                ("trust_center_authority_contexts", "context", "contexts"),
                ("trust_center_authority_grants", "grant", "grants"),
                (
                    "trust_center_authority_rights",
                    "rights authorization",
                    "rights_authorizations",
                ),
            ):
                for row in connection.execute(
                    f"SELECT * FROM {table} WHERE tenant_sha256=?",  # noqa: S608
                    (tenant_sha,),
                ):
                    self._row_payload(row, label)
                    counts[key] += 1
            histories: dict[tuple[str, str], str | None] = {}
            for row in connection.execute(
                "SELECT * FROM trust_center_authority_history WHERE tenant_sha256=? "
                "ORDER BY object_kind,object_ref,revision",
                (tenant_sha,),
            ):
                payload = _loads(row["payload_json"], "authority history")
                chain_key = (str(row["object_kind"]), str(row["object_ref"]))
                record = payload.get("record")
                if not isinstance(record, Mapping):
                    raise TrustCenterIntegrityError("authority history record is invalid")
                record_body = dict(record)
                record_integrity = record_body.pop("integrity_sha256", None)
                if (
                    payload.get("tenant_sha256") != tenant_sha
                    or payload.get("object_kind") != chain_key[0]
                    or payload.get("object_ref") != chain_key[1]
                    or payload.get("revision") != row["revision"]
                    or record.get("revision") != row["revision"]
                    or not _same(_sha256(record_body), record_integrity)
                    or payload.get("previous_integrity_sha256") != histories.get(chain_key)
                    or not _same(_sha256(payload), row["integrity_sha256"])
                ):
                    raise TrustCenterIntegrityError("authority history chain failed integrity")
                histories[chain_key] = str(row["integrity_sha256"])
                counts["history"] += 1
            for row in connection.execute(
                "SELECT * FROM trust_center_authority_operations WHERE tenant_sha256=?",
                (tenant_sha,),
            ):
                result = _loads(row["result_json"], "idempotency result")
                body = {
                    "tenant_sha256": tenant_sha,
                    "key_sha256": row["key_sha256"],
                    "action": row["action"],
                    "context_ref": row["context_ref"],
                    "request_sha256": row["request_sha256"],
                    "result_kind": row["result_kind"],
                    "result": result,
                    "retained_until": row["retained_until"],
                    "created_at": row["created_at"],
                }
                if not _same(_sha256(body), row["integrity_sha256"]):
                    raise TrustCenterIntegrityError("idempotency binding failed integrity")
                counts["operations"] += 1
            for row in connection.execute(
                "SELECT * FROM trust_center_authority_exports WHERE tenant_sha256=?",
                (tenant_sha,),
            ):
                payload = _loads(row["payload_json"], "authority export")
                if (
                    payload.get("export_id") != row["export_id"]
                    or payload.get("context_ref") != row["context_ref"]
                    or payload.get("tenant_sha256") != row["tenant_sha256"]
                    or payload.get("retained_until") != row["retained_until"]
                    or not _same(_sha256(payload), row["integrity_sha256"])
                ):
                    raise TrustCenterIntegrityError("authority export failed integrity")
                counts["exports"] += 1
            previous: str | None = None
            expected_sequence = 1
            for row in connection.execute(
                "SELECT * FROM trust_center_authority_audit WHERE tenant_sha256=? "
                "ORDER BY sequence",
                (tenant_sha,),
            ):
                payload = _loads(row["payload_json"], "authority audit")
                if (
                    row["sequence"] != expected_sequence
                    or payload.get("sequence") != expected_sequence
                    or payload.get("tenant_sha256") != tenant_sha
                    or payload.get("previous_integrity_sha256") != previous
                    or not _same(_sha256(payload), row["integrity_sha256"])
                ):
                    raise TrustCenterIntegrityError("authority audit chain failed integrity")
                previous = str(row["integrity_sha256"])
                expected_sequence += 1
                counts["audit_events"] += 1
        return counts

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "tenant_local": True,
            "default_off": True,
            "principal_authority": "constructor_bound",
            "binding_authority": "constructor_bound",
            "signing_key_authority": "constructor_bound",
            "persisted_bindings": "sha256_only",
            "four_eyes_capability_grants": True,
            "four_eyes_case_authorizations": True,
            "zero_argument_context_resolver": True,
            "raw_client_credentials_persisted": False,
            "raw_profile_credentials_persisted": False,
            "raw_identity_persisted": False,
            "raw_subject_references_persisted": False,
            "legal_or_free_text_persisted": False,
            "signing_keys_persisted": False,
            "completeness_inferred": False,
            "network_io": False,
            "provider_writes": False,
            "live_acceptance_verified": False,
        }


__all__ = [
    "AUTHORITY_EXPORT_SCHEMA",
    "AUTHORITY_SCHEMA",
    "CAPABILITIES",
    "PRINCIPAL_AUTHORITY_SCHEMA",
    "PRINCIPAL_PERMISSIONS",
    "CapabilityGrantAuthority",
    "ConsumerTrustCenterAuthorityStore",
    "ResolvedTrustCenterBinding",
    "RightsCaseAuthorizationAuthority",
    "SignedTrustCenterAuthorityExport",
    "TrustCenterAuthorityConfigError",
    "TrustCenterAuthorityError",
    "TrustCenterAuthorityNotFound",
    "TrustCenterAuthorityPermissionDenied",
    "TrustCenterContextAuthority",
    "TrustCenterPrincipalAuthority",
    "principal_authority_sha256",
]
