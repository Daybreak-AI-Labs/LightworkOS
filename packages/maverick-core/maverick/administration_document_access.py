"""Governed administration for document-download tokens and event discovery.

The control plane in this module never reads or stores document bytes, paths,
object-store locators, caller-selected metadata, raw download tokens, or raw
delivery grants.  A deployment-owned resolver authoritatively binds one opaque
document reference to the active tenant and authenticated principal.  A
separate deployment-owned issuer turns an atomic claim into a short-lived,
opaque delivery grant.

The SQLite store is a tenant-bound control-plane ledger.  It keeps token and
grant digests, bounded metadata, CAS revisions, idempotency receipts, retention
tombstones, and a locally hash-linked audit history.  That local linkage is not
an external WORM anchor and this module does not claim object-store custody or
acceptance by a live relying workflow.
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
from collections.abc import Callable, Mapping
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .constant_time import text_equals
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

SCHEMA_VERSION = 1
CATALOG_VERSION = 1
GENESIS_SHA256 = "0" * 64

TOKEN_SCHEMA = "lightwork.administration-document-download-token.v1"
OPERATION_SCHEMA = "lightwork.administration-document-access-operation.v1"
CLAIM_SCHEMA = "lightwork.administration-document-access-claim.v1"
AUDIT_SCHEMA = "lightwork.administration-document-access-audit.v1"
TOMBSTONE_SCHEMA = "lightwork.administration-document-access-tombstone.v1"
META_SCHEMA = "lightwork.administration-document-access-store.v1"

_OPAQUE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_PRINCIPAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}\Z")
_RECORD_TYPE_RE = re.compile(r"[a-z][a-z0-9_.-]{0,95}\Z")
_EVENT_TYPE_RE = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MEDIA_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,127}\Z")
_DOWNLOAD_TOKEN_RE = re.compile(r"lwddt_v1_[A-Za-z0-9_-]{43}\Z")
_DELIVERY_GRANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{31,1023}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_MAX_DOCUMENT_BYTES = 10 * 1024 * 1024 * 1024
_MAX_AUDIT_LIMIT = 1_000
_MAX_LIST_LIMIT = 500
_TOKEN_STATES = frozenset({"active", "revoked", "expired", "exhausted"})
_TERMINAL_STATES = frozenset({"revoked", "expired", "exhausted"})

PRODUCT_AREAS = frozenset(
    {
        "administration",
        "ai_governance",
        "consent_preferences",
        "data_use_governance",
        "privacy_automation",
        "tech_risk_compliance",
        "third_party_management",
    }
)


class DocumentAccessError(RuntimeError):
    """Base error with a closed, non-sensitive error code."""

    def __init__(self, error_code: str) -> None:
        if not isinstance(error_code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", error_code):
            raise ValueError("document access error code is invalid")
        self.error_code = error_code
        super().__init__(error_code)


class DocumentAccessConfigError(DocumentAccessError):
    """The exact feature gate or a server-owned dependency is unavailable."""


class DocumentAccessValidationError(DocumentAccessError, ValueError):
    """A caller value or injected value violates the bounded contract."""


class DocumentAccessPermissionDenied(DocumentAccessError):
    """The document or token is not bound to the current principal."""


class DocumentAccessConflict(DocumentAccessError):
    """A CAS, idempotency, authority, state, or replay precondition changed."""


class DocumentAccessNotFound(DocumentAccessError):
    """A token is absent from the active retained control plane."""


class DocumentAccessExpired(DocumentAccessConflict):
    """The token expired before it could be claimed."""


class DocumentAccessIntegrityError(DocumentAccessError):
    """Persisted state or its local audit linkage cannot be trusted."""


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise DocumentAccessValidationError("document_access_material_invalid") from exc
    if not 1 <= len(encoded) <= 128 * 1024:
        raise DocumentAccessValidationError("document_access_material_oversized")
    return encoded


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest(value: object, *, label: str = "digest") -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise DocumentAccessValidationError(f"document_access_{label}_invalid")
    return value


def _opaque_id(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _OPAQUE_ID_RE.fullmatch(value) is None:
        raise DocumentAccessValidationError(f"document_access_{label}_invalid")
    if value in {".", ".."}:
        raise DocumentAccessValidationError(f"document_access_{label}_invalid")
    return value


def _principal(value: object) -> str:
    if not isinstance(value, str) or _PRINCIPAL_RE.fullmatch(value) is None:
        raise DocumentAccessPermissionDenied("document_access_principal_invalid")
    return value


def _idempotency_digest(value: object) -> str:
    if not isinstance(value, str) or _IDEMPOTENCY_RE.fullmatch(value) is None:
        raise DocumentAccessValidationError("document_access_idempotency_key_invalid")
    return _text_sha256("lightwork.document-access.idempotency.v1:" + value)


def _record_type(value: object) -> str:
    if not isinstance(value, str) or _RECORD_TYPE_RE.fullmatch(value) is None:
        raise DocumentAccessValidationError("document_access_record_type_invalid")
    return value


def _product_area(value: object) -> str:
    if not isinstance(value, str) or value not in PRODUCT_AREAS:
        raise DocumentAccessValidationError("document_access_product_area_invalid")
    return value


def _integer(value: object, *, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DocumentAccessValidationError(f"document_access_{label}_invalid")
    return value


def _timestamp(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DocumentAccessValidationError(f"document_access_{label}_invalid")
    selected = float(value)
    if not math.isfinite(selected) or selected <= 0 or selected >= 100_000_000_000.0:
        raise DocumentAccessValidationError(f"document_access_{label}_invalid")
    return selected


def _clock_value(clock: Callable[[], float]) -> float:
    try:
        return _timestamp(clock(), label="clock")
    except (KeyboardInterrupt, SystemExit):
        raise
    except DocumentAccessError:
        raise
    except Exception as exc:
        raise DocumentAccessConfigError("document_access_clock_unavailable") from exc


def _display_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 255
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or _CONTROL_RE.search(value) is not None
    ):
        raise DocumentAccessValidationError("document_access_display_name_invalid")
    return value


def _media_type(value: object) -> str:
    if not isinstance(value, str) or _MEDIA_TYPE_RE.fullmatch(value) is None:
        raise DocumentAccessValidationError("document_access_media_type_invalid")
    return value


def _download_token(value: object) -> str:
    if not isinstance(value, str) or _DOWNLOAD_TOKEN_RE.fullmatch(value) is None:
        raise DocumentAccessValidationError("document_access_download_token_invalid")
    return value


def _delivery_grant(value: object) -> str:
    if not isinstance(value, str) or _DELIVERY_GRANT_RE.fullmatch(value) is None:
        raise DocumentAccessConfigError("document_access_delivery_grant_invalid")
    return value


def _tenant(value: object) -> str:
    if not isinstance(value, str):
        raise DocumentAccessValidationError("document_access_tenant_invalid")
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise DocumentAccessValidationError("document_access_tenant_invalid") from exc


def _tenant_sha256(tenant_id: str) -> str:
    return _text_sha256(f"lightwork.document-access.tenant.v1:{tenant_id}")


def _principal_sha256(tenant_sha256: str, principal_ref: str) -> str:
    return _text_sha256(f"lightwork.document-access.principal.v1:{tenant_sha256}:{principal_ref}")


def _token_sha256(raw_token: str) -> str:
    return _text_sha256("lightwork.document-access.token.v1:" + raw_token)


@dataclass(frozen=True, slots=True)
class DocumentAccessConfig:
    """Exact default-off policy for the administration capability."""

    enable: bool = False
    default_ttl_seconds: int = 300
    max_ttl_seconds: int = 900
    max_uses: int = 1
    delivery_grant_ttl_seconds: int = 60
    retention_seconds: int = 7 * 24 * 60 * 60

    def __post_init__(self) -> None:
        if type(self.enable) is not bool:
            raise DocumentAccessConfigError("document_access_enable_invalid")
        try:
            default_ttl = _integer(
                self.default_ttl_seconds,
                minimum=30,
                maximum=3_600,
                label="default_ttl_seconds",
            )
            maximum_ttl = _integer(
                self.max_ttl_seconds,
                minimum=30,
                maximum=3_600,
                label="max_ttl_seconds",
            )
            grant_ttl = _integer(
                self.delivery_grant_ttl_seconds,
                minimum=5,
                maximum=300,
                label="delivery_grant_ttl_seconds",
            )
            _integer(self.max_uses, minimum=1, maximum=10, label="max_uses")
            _integer(
                self.retention_seconds,
                minimum=60,
                maximum=366 * 24 * 60 * 60,
                label="retention_seconds",
            )
        except DocumentAccessValidationError as exc:
            raise DocumentAccessConfigError(exc.error_code) from exc
        if default_ttl > maximum_ttl:
            raise DocumentAccessConfigError("document_access_default_ttl_exceeds_maximum")
        if grant_ttl > maximum_ttl:
            raise DocumentAccessConfigError("document_access_grant_ttl_exceeds_maximum")

    @classmethod
    def from_mapping(cls, config: Mapping[str, Any]) -> DocumentAccessConfig:
        if not isinstance(config, Mapping):
            raise DocumentAccessConfigError("document_access_configuration_unavailable")
        section = config.get("administration_document_access") or {}
        if not isinstance(section, Mapping):
            raise DocumentAccessConfigError("document_access_configuration_invalid")
        allowed = {
            "enable",
            "default_ttl_seconds",
            "max_ttl_seconds",
            "max_uses",
            "delivery_grant_ttl_seconds",
            "retention_seconds",
        }
        unknown = sorted(str(key) for key in section if key not in allowed)
        if unknown:
            raise DocumentAccessConfigError("document_access_configuration_unknown_key")
        values = {key: section[key] for key in allowed if key in section}
        try:
            return cls(**values)
        except TypeError as exc:
            raise DocumentAccessConfigError("document_access_configuration_invalid") from exc


def _load_config() -> Mapping[str, Any]:
    try:
        from .config import config_source_errors, load_config

        config = load_config()
        if config_source_errors(include_tenant=True):
            raise DocumentAccessConfigError("document_access_configuration_source_invalid")
    except (KeyboardInterrupt, SystemExit):
        raise
    except DocumentAccessError:
        raise
    except Exception as exc:
        raise DocumentAccessConfigError("document_access_configuration_unavailable") from exc
    if not isinstance(config, Mapping):
        raise DocumentAccessConfigError("document_access_configuration_unavailable")
    return config


def config_from(config: Mapping[str, Any] | None = None) -> DocumentAccessConfig:
    return DocumentAccessConfig.from_mapping(_load_config() if config is None else config)


def enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Return true only for the exact boolean opt-in; invalid policy is off."""

    try:
        selected = _load_config() if config is None else config
        settings = DocumentAccessConfig.from_mapping(selected)
        section = selected.get("administration_document_access")
        return bool(
            settings.enable and isinstance(section, Mapping) and section.get("enable") is True
        )
    except (DocumentAccessError, TypeError, ValueError):
        return False


def require_enabled(config: Mapping[str, Any] | None = None) -> DocumentAccessConfig:
    settings = config_from(config)
    if not settings.enable:
        raise DocumentAccessConfigError("administration_document_access_disabled")
    return settings


@dataclass(frozen=True, slots=True)
class EventTypeDefinition:
    event_type: str
    product_area: str
    record_type: str
    description: str
    catalog_version: int = CATALOG_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.event_type, str)
            or _EVENT_TYPE_RE.fullmatch(self.event_type) is None
        ):
            raise DocumentAccessValidationError("document_access_event_type_invalid")
        _product_area(self.product_area)
        _record_type(self.record_type)
        if (
            not isinstance(self.description, str)
            or not self.description
            or len(self.description) > 256
            or _CONTROL_RE.search(self.description) is not None
        ):
            raise DocumentAccessValidationError("document_access_event_description_invalid")
        _integer(
            self.catalog_version,
            minimum=1,
            maximum=2**31 - 1,
            label="catalog_version",
        )


# Closed, versioned, code-owned registry.  There is deliberately no registration
# API and no configuration merge path.
EVENT_TYPE_CATALOG = (
    EventTypeDefinition(
        "administration.document_download_token.minted",
        "administration",
        "document_download_token",
        "A governed short-lived document token was minted.",
    ),
    EventTypeDefinition(
        "administration.document_download_token.claimed",
        "administration",
        "document_download_token",
        "A token use was atomically reserved for delivery.",
    ),
    EventTypeDefinition(
        "administration.document_download_token.exhausted",
        "administration",
        "document_download_token",
        "The bounded token use count reached zero.",
    ),
    EventTypeDefinition(
        "administration.document_download_token.revoked",
        "administration",
        "document_download_token",
        "An administrator revoked an active token.",
    ),
    EventTypeDefinition(
        "administration.document_download_token.expired",
        "administration",
        "document_download_token",
        "The token passed its fixed expiry without a valid claim.",
    ),
    EventTypeDefinition(
        "administration.document_download_token.authority_invalidated",
        "administration",
        "document_download_token",
        "The authoritative document binding changed or was withdrawn.",
    ),
    EventTypeDefinition(
        "administration.document_download_token.retention_purged",
        "administration",
        "document_download_token",
        "Retained token metadata was replaced by a digest-only tombstone.",
    ),
    EventTypeDefinition(
        "administration.document_attachment.delivery_grant_issued",
        "administration",
        "document_attachment",
        "A server-owned issuer returned an opaque short-lived delivery grant.",
    ),
    EventTypeDefinition(
        "administration.document_attachment.delivery_grant_failed",
        "administration",
        "document_attachment",
        "A reserved token use ended without a grant being returned.",
    ),
    # The remaining entries expose the fixed normalized action vocabulary used
    # by the six-suite unified-audit contract.  Discovery does not assert that
    # a live authoritative reader is installed for any suite; readiness and
    # source coverage remain separate runtime facts.
    EventTypeDefinition(
        "ai_governance.normalized_audit.record_changed",
        "ai_governance",
        "normalized_audit_record",
        "An AI-governance source projected a normalized record change.",
    ),
    EventTypeDefinition(
        "ai_governance.normalized_audit.risk_changed",
        "ai_governance",
        "normalized_audit_record",
        "An AI-governance source projected a normalized risk change.",
    ),
    EventTypeDefinition(
        "consent_preferences.normalized_audit.consent_recorded",
        "consent_preferences",
        "normalized_audit_record",
        "A consent source projected a normalized consent record.",
    ),
    EventTypeDefinition(
        "consent_preferences.normalized_audit.consent_revoked",
        "consent_preferences",
        "normalized_audit_record",
        "A consent source projected a normalized consent revocation.",
    ),
    EventTypeDefinition(
        "data_use_governance.normalized_audit.policy_changed",
        "data_use_governance",
        "normalized_audit_record",
        "A data-use source projected a normalized policy change.",
    ),
    EventTypeDefinition(
        "privacy_automation.normalized_audit.request_submitted",
        "privacy_automation",
        "normalized_audit_record",
        "A privacy source projected a normalized request submission.",
    ),
    EventTypeDefinition(
        "privacy_automation.normalized_audit.status_changed",
        "privacy_automation",
        "normalized_audit_record",
        "A privacy source projected a normalized status change.",
    ),
    EventTypeDefinition(
        "tech_risk_compliance.normalized_audit.control_evaluated",
        "tech_risk_compliance",
        "normalized_audit_record",
        "A technology-risk source projected a normalized control evaluation.",
    ),
    EventTypeDefinition(
        "tech_risk_compliance.normalized_audit.evidence_recorded",
        "tech_risk_compliance",
        "normalized_audit_record",
        "A technology-risk source projected normalized evidence.",
    ),
    EventTypeDefinition(
        "third_party_management.normalized_audit.relationship_changed",
        "third_party_management",
        "normalized_audit_record",
        "A third-party source projected a normalized relationship change.",
    ),
    EventTypeDefinition(
        "third_party_management.normalized_audit.risk_changed",
        "third_party_management",
        "normalized_audit_record",
        "A third-party source projected a normalized risk change.",
    ),
)
_EVENT_TYPES = frozenset(item.event_type for item in EVENT_TYPE_CATALOG)


def list_event_types(
    *,
    product_area: str | None = None,
    record_type: str | None = None,
) -> tuple[EventTypeDefinition, ...]:
    """Filter the immutable server registry without accepting registrations."""

    if product_area is not None:
        _product_area(product_area)
    if record_type is not None:
        _record_type(record_type)
    return tuple(
        item
        for item in EVENT_TYPE_CATALOG
        if (product_area is None or item.product_area == product_area)
        and (record_type is None or item.record_type == record_type)
    )


@dataclass(frozen=True, slots=True)
class DocumentAuthority:
    """Ephemeral, resolver-owned document and authorization snapshot."""

    tenant_id: str
    principal_ref: str
    document_ref: str
    product_area: str
    record_type: str
    safe_display_name: str
    media_type: str
    byte_size: int
    content_sha256: str
    authority_revision: int
    authority_sha256: str
    download_allowed: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _tenant(self.tenant_id))
        _principal(self.principal_ref)
        _opaque_id(self.document_ref, label="document_ref")
        _product_area(self.product_area)
        _record_type(self.record_type)
        _display_name(self.safe_display_name)
        _media_type(self.media_type)
        _integer(self.byte_size, minimum=0, maximum=_MAX_DOCUMENT_BYTES, label="byte_size")
        _digest(self.content_sha256, label="content_sha256")
        _integer(
            self.authority_revision,
            minimum=1,
            maximum=2**31 - 1,
            label="authority_revision",
        )
        if _digest(self.authority_sha256, label="authority_sha256") == GENESIS_SHA256:
            raise DocumentAccessValidationError("document_access_authority_sha256_invalid")
        if type(self.download_allowed) is not bool:
            raise DocumentAccessValidationError("document_access_download_allowed_invalid")


@dataclass(frozen=True, slots=True)
class DocumentDownloadTokenRecord:
    token_id: str
    tenant_sha256: str
    principal_sha256: str
    document_ref: str
    document_sha256: str
    product_area: str
    record_type: str
    media_type: str
    byte_size: int
    content_sha256: str
    authority_revision: int
    authority_sha256: str
    token_sha256: str
    state: str
    revision: int
    max_uses: int
    uses_remaining: int
    claim_count: int
    issued_at: float
    expires_at: float
    retired_at: float | None
    retained_until: float | None
    created_idempotency_sha256: str
    request_sha256: str
    record_sha256: str


@dataclass(frozen=True, slots=True)
class MintedDocumentToken:
    record: DocumentDownloadTokenRecord
    download_token: str | None
    idempotent_replay: bool


@dataclass(frozen=True, slots=True)
class DeliveryClaim:
    tenant_id: str
    principal_ref: str
    token_id: str
    claim_id: str
    document_ref: str
    product_area: str
    record_type: str
    safe_display_name: str
    media_type: str
    byte_size: int
    content_sha256: str
    authority_revision: int
    authority_sha256: str
    grant_expires_at: float


@dataclass(frozen=True, slots=True)
class DeliveryGrant:
    """Opaque delivery capability returned by a deployment-owned issuer."""

    grant: str
    expires_at: float


@dataclass(frozen=True, slots=True)
class ClaimedDeliveryGrant:
    delivery_grant: str
    expires_at: float


@dataclass(frozen=True, slots=True)
class RetentionTombstone:
    token_id: str
    tenant_sha256: str
    principal_sha256: str
    document_sha256: str
    final_record_sha256: str
    retired_at: float
    purged_at: float
    tombstone_sha256: str


@runtime_checkable
class DocumentAuthorityResolver(Protocol):
    def __call__(
        self,
        tenant_id: str,
        principal_ref: str,
        document_ref: str,
    ) -> DocumentAuthority: ...


@runtime_checkable
class DeliveryGrantIssuer(Protocol):
    def __call__(self, claim: DeliveryClaim) -> DeliveryGrant: ...


PrincipalResolver = Callable[[], str]


def _record_material(record: DocumentDownloadTokenRecord) -> dict[str, object]:
    result = asdict(record)
    result.pop("record_sha256", None)
    return {"schema": TOKEN_SCHEMA, **result}


def _record_with_digest(record: DocumentDownloadTokenRecord) -> DocumentDownloadTokenRecord:
    return replace(record, record_sha256=canonical_sha256(_record_material(record)))


def _tombstone_material(tombstone: RetentionTombstone) -> dict[str, object]:
    result = asdict(tombstone)
    result.pop("tombstone_sha256", None)
    return {"schema": TOMBSTONE_SCHEMA, **result}


class DocumentAccessStore:
    """Tenant-bound SQLite authority for token state and digest-only history."""

    _schema_lock = threading.RLock()

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path).expanduser().resolve()
        self.tenant_id = _tenant(tenant_id)
        self.tenant_sha256 = _tenant_sha256(self.tenant_id)
        if not callable(clock):
            raise DocumentAccessConfigError("document_access_clock_unavailable")
        self._clock = clock
        try:
            ensure_private_directory(self.path.parent)
            with self._schema_lock:
                with closing(self._connect(initializing=True)) as connection, connection:
                    self._create_schema(connection)
            ensure_private_file(self.path)
        except DocumentAccessError:
            raise
        except (OSError, PermissionError, sqlite3.DatabaseError) as exc:
            raise DocumentAccessConfigError("document_access_store_unavailable") from exc

    def _connect(self, *, initializing: bool = False) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA busy_timeout=30000")
                if initializing:
                    connection.execute("PRAGMA journal_mode=WAL")
                    connection.execute("PRAGMA synchronous=FULL")
            except BaseException:
                connection.close()
                raise
            return connection
        except sqlite3.DatabaseError as exc:
            raise DocumentAccessIntegrityError("document_access_store_invalid") from exc

    @contextmanager
    def _transaction(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_meta_on(connection)
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _create_schema(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS document_access_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                schema_version INTEGER NOT NULL,
                tenant_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                integrity_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS document_download_tokens (
                token_id TEXT PRIMARY KEY,
                tenant_sha256 TEXT NOT NULL,
                principal_sha256 TEXT NOT NULL,
                document_ref TEXT NOT NULL,
                document_sha256 TEXT NOT NULL,
                product_area TEXT NOT NULL,
                record_type TEXT NOT NULL,
                media_type TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                content_sha256 TEXT NOT NULL,
                authority_revision INTEGER NOT NULL,
                authority_sha256 TEXT NOT NULL,
                token_sha256 TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL,
                revision INTEGER NOT NULL,
                max_uses INTEGER NOT NULL,
                uses_remaining INTEGER NOT NULL,
                claim_count INTEGER NOT NULL,
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                retired_at REAL,
                retained_until REAL,
                created_idempotency_sha256 TEXT NOT NULL UNIQUE,
                request_sha256 TEXT NOT NULL,
                record_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS document_access_operations (
                idempotency_sha256 TEXT PRIMARY KEY,
                operation_type TEXT NOT NULL,
                token_id TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                result_revision INTEGER NOT NULL,
                completed_at REAL NOT NULL,
                integrity_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS document_access_claims (
                idempotency_sha256 TEXT PRIMARY KEY,
                claim_id TEXT NOT NULL UNIQUE,
                token_id TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at REAL NOT NULL,
                completed_at REAL,
                grant_sha256 TEXT UNIQUE,
                integrity_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS document_access_audit (
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                token_id TEXT NOT NULL,
                actor_sha256 TEXT NOT NULL,
                resource_sha256 TEXT NOT NULL,
                detail_sha256 TEXT NOT NULL,
                occurred_at REAL NOT NULL,
                previous_sha256 TEXT NOT NULL,
                event_sha256 TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS document_access_tombstones (
                token_id TEXT PRIMARY KEY,
                tenant_sha256 TEXT NOT NULL,
                principal_sha256 TEXT NOT NULL,
                document_sha256 TEXT NOT NULL,
                final_record_sha256 TEXT NOT NULL,
                retired_at REAL NOT NULL,
                purged_at REAL NOT NULL,
                tombstone_sha256 TEXT NOT NULL
            );
            """
        )
        row = connection.execute("SELECT 1 FROM document_access_meta WHERE singleton=1").fetchone()
        if row is None:
            created_at = _clock_value(self._clock)
            material = {
                "schema": META_SCHEMA,
                "schema_version": SCHEMA_VERSION,
                "tenant_sha256": self.tenant_sha256,
                "created_at": created_at,
            }
            connection.execute(
                "INSERT INTO document_access_meta VALUES (1,?,?,?,?)",
                (
                    SCHEMA_VERSION,
                    self.tenant_sha256,
                    created_at,
                    canonical_sha256(material),
                ),
            )
        self._verify_meta_on(connection)

    def _verify_meta_on(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT schema_version,tenant_sha256,created_at,integrity_sha256 "
            "FROM document_access_meta WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise DocumentAccessIntegrityError("document_access_metadata_missing")
        material = {
            "schema": META_SCHEMA,
            "schema_version": int(row["schema_version"]),
            "tenant_sha256": str(row["tenant_sha256"]),
            "created_at": float(row["created_at"]),
        }
        expected = canonical_sha256(material)
        if (
            material["schema_version"] != SCHEMA_VERSION
            or not text_equals(str(material["tenant_sha256"]), self.tenant_sha256)
            or not text_equals(expected, str(row["integrity_sha256"]))
        ):
            raise DocumentAccessIntegrityError("document_access_metadata_invalid")

    def _record_from_row(self, row: sqlite3.Row) -> DocumentDownloadTokenRecord:
        record = DocumentDownloadTokenRecord(
            token_id=str(row["token_id"]),
            tenant_sha256=str(row["tenant_sha256"]),
            principal_sha256=str(row["principal_sha256"]),
            document_ref=str(row["document_ref"]),
            document_sha256=str(row["document_sha256"]),
            product_area=str(row["product_area"]),
            record_type=str(row["record_type"]),
            media_type=str(row["media_type"]),
            byte_size=int(row["byte_size"]),
            content_sha256=str(row["content_sha256"]),
            authority_revision=int(row["authority_revision"]),
            authority_sha256=str(row["authority_sha256"]),
            token_sha256=str(row["token_sha256"]),
            state=str(row["state"]),
            revision=int(row["revision"]),
            max_uses=int(row["max_uses"]),
            uses_remaining=int(row["uses_remaining"]),
            claim_count=int(row["claim_count"]),
            issued_at=float(row["issued_at"]),
            expires_at=float(row["expires_at"]),
            retired_at=None if row["retired_at"] is None else float(row["retired_at"]),
            retained_until=(
                None if row["retained_until"] is None else float(row["retained_until"])
            ),
            created_idempotency_sha256=str(row["created_idempotency_sha256"]),
            request_sha256=str(row["request_sha256"]),
            record_sha256=str(row["record_sha256"]),
        )
        DocumentAccessStore._validate_record(record)
        if not hmac.compare_digest(record.tenant_sha256, self.tenant_sha256):
            raise DocumentAccessIntegrityError("document_access_token_tenant_invalid")
        return record

    @staticmethod
    def _validate_record(record: DocumentDownloadTokenRecord) -> None:
        _opaque_id(record.token_id, label="token_id")
        for label in (
            "tenant_sha256",
            "principal_sha256",
            "document_sha256",
            "content_sha256",
            "authority_sha256",
            "token_sha256",
            "created_idempotency_sha256",
            "request_sha256",
            "record_sha256",
        ):
            _digest(getattr(record, label), label=label)
        _opaque_id(record.document_ref, label="document_ref")
        _product_area(record.product_area)
        _record_type(record.record_type)
        _media_type(record.media_type)
        _integer(record.byte_size, minimum=0, maximum=_MAX_DOCUMENT_BYTES, label="byte_size")
        _integer(
            record.authority_revision,
            minimum=1,
            maximum=2**31 - 1,
            label="authority_revision",
        )
        if record.state not in _TOKEN_STATES:
            raise DocumentAccessIntegrityError("document_access_token_state_invalid")
        _integer(record.revision, minimum=1, maximum=2**63 - 1, label="revision")
        _integer(record.max_uses, minimum=1, maximum=10, label="max_uses")
        _integer(
            record.uses_remaining,
            minimum=0,
            maximum=record.max_uses,
            label="uses_remaining",
        )
        _integer(record.claim_count, minimum=0, maximum=record.max_uses, label="claim_count")
        _timestamp(record.issued_at, label="issued_at")
        _timestamp(record.expires_at, label="expires_at")
        if record.expires_at <= record.issued_at:
            raise DocumentAccessIntegrityError("document_access_token_lifetime_invalid")
        if record.state == "active":
            if record.uses_remaining <= 0 or record.retired_at is not None:
                raise DocumentAccessIntegrityError("document_access_active_token_invalid")
        else:
            if record.retired_at is None or record.retained_until is None:
                raise DocumentAccessIntegrityError("document_access_retired_token_invalid")
            _timestamp(record.retired_at, label="retired_at")
            _timestamp(record.retained_until, label="retained_until")
            if record.retained_until < record.retired_at:
                raise DocumentAccessIntegrityError("document_access_retention_invalid")
        expected = canonical_sha256(_record_material(record))
        if not hmac.compare_digest(expected, record.record_sha256):
            raise DocumentAccessIntegrityError("document_access_token_integrity_invalid")

    @staticmethod
    def _write_record_on(
        connection: sqlite3.Connection,
        record: DocumentDownloadTokenRecord,
        *,
        expected_revision: int,
    ) -> None:
        result = connection.execute(
            """
            UPDATE document_download_tokens SET
                state=?,revision=?,uses_remaining=?,claim_count=?,retired_at=?,
                retained_until=?,record_sha256=?
            WHERE token_id=? AND revision=?
            """,
            (
                record.state,
                record.revision,
                record.uses_remaining,
                record.claim_count,
                record.retired_at,
                record.retained_until,
                record.record_sha256,
                record.token_id,
                expected_revision,
            ),
        )
        if result.rowcount != 1:
            raise DocumentAccessConflict("document_access_revision_conflict")

    @staticmethod
    def _operation_integrity(
        *,
        idempotency_sha256: str,
        operation_type: str,
        token_id: str,
        request_sha256: str,
        result_revision: int,
        completed_at: float,
    ) -> str:
        return canonical_sha256(
            {
                "schema": OPERATION_SCHEMA,
                "idempotency_sha256": idempotency_sha256,
                "operation_type": operation_type,
                "token_id": token_id,
                "request_sha256": request_sha256,
                "result_revision": result_revision,
                "completed_at": completed_at,
            }
        )

    @staticmethod
    def _claim_integrity(
        *,
        idempotency_sha256: str,
        claim_id: str,
        token_id: str,
        request_sha256: str,
        state: str,
        created_at: float,
        completed_at: float | None,
        grant_sha256: str | None,
    ) -> str:
        return canonical_sha256(
            {
                "schema": CLAIM_SCHEMA,
                "idempotency_sha256": idempotency_sha256,
                "claim_id": claim_id,
                "token_id": token_id,
                "request_sha256": request_sha256,
                "state": state,
                "created_at": created_at,
                "completed_at": completed_at,
                "grant_sha256": grant_sha256,
            }
        )

    def _append_audit_on(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        token_id: str,
        actor_sha256: str,
        resource_sha256: str,
        detail: Mapping[str, object],
        occurred_at: float,
    ) -> None:
        if event_type not in _EVENT_TYPES:
            raise DocumentAccessIntegrityError("document_access_event_type_invalid")
        row = connection.execute(
            "SELECT sequence,event_sha256 FROM document_access_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if row is None else int(row["sequence"]) + 1
        previous = GENESIS_SHA256 if row is None else str(row["event_sha256"])
        detail_sha256 = canonical_sha256(dict(detail))
        material = {
            "schema": AUDIT_SCHEMA,
            "sequence": sequence,
            "event_type": event_type,
            "token_id": token_id,
            "actor_sha256": actor_sha256,
            "resource_sha256": resource_sha256,
            "detail_sha256": detail_sha256,
            "occurred_at": occurred_at,
            "previous_sha256": previous,
        }
        event_sha256 = canonical_sha256(material)
        connection.execute(
            "INSERT INTO document_access_audit VALUES (?,?,?,?,?,?,?,?,?)",
            (
                sequence,
                event_type,
                token_id,
                actor_sha256,
                resource_sha256,
                detail_sha256,
                occurred_at,
                previous,
                event_sha256,
            ),
        )

    def find_mint_replay(
        self,
        *,
        idempotency_sha256: str,
        request_sha256: str,
    ) -> MintedDocumentToken | None:
        with closing(self._connect()) as connection, connection:
            self._verify_meta_on(connection)
            operation = connection.execute(
                "SELECT * FROM document_access_operations WHERE idempotency_sha256=?",
                (idempotency_sha256,),
            ).fetchone()
            if operation is None:
                return None
            self._validate_operation_row(operation)
            if str(operation["operation_type"]) != "mint" or not text_equals(
                str(operation["request_sha256"]), request_sha256
            ):
                raise DocumentAccessConflict("document_access_idempotency_conflict")
            row = connection.execute(
                "SELECT * FROM document_download_tokens WHERE token_id=?",
                (str(operation["token_id"]),),
            ).fetchone()
            if row is None:
                if connection.execute(
                    "SELECT 1 FROM document_access_tombstones WHERE token_id=?",
                    (str(operation["token_id"]),),
                ).fetchone():
                    raise DocumentAccessConflict("document_access_token_retention_purged")
                raise DocumentAccessIntegrityError("document_access_operation_target_missing")
            return MintedDocumentToken(self._record_from_row(row), None, True)

    def _validate_operation_row(self, row: sqlite3.Row) -> None:
        values = {
            "idempotency_sha256": str(row["idempotency_sha256"]),
            "operation_type": str(row["operation_type"]),
            "token_id": str(row["token_id"]),
            "request_sha256": str(row["request_sha256"]),
            "result_revision": int(row["result_revision"]),
            "completed_at": float(row["completed_at"]),
        }
        expected = self._operation_integrity(**values)
        if not text_equals(expected, str(row["integrity_sha256"])):
            raise DocumentAccessIntegrityError("document_access_operation_integrity_invalid")

    def create_token(
        self,
        *,
        principal_sha256: str,
        authority: DocumentAuthority,
        ttl_seconds: int,
        max_uses: int,
        idempotency_sha256: str,
        request_sha256: str,
        retention_seconds: int,
    ) -> MintedDocumentToken:
        now = _clock_value(self._clock)
        raw_token = "lwddt_v1_" + secrets.token_urlsafe(32)
        token_digest = _token_sha256(raw_token)
        token_id = "ddt-" + secrets.token_hex(16)
        document_sha256 = _text_sha256(
            f"lightwork.document-access.document.v1:{self.tenant_sha256}:{authority.document_ref}"
        )
        record = _record_with_digest(
            DocumentDownloadTokenRecord(
                token_id=token_id,
                tenant_sha256=self.tenant_sha256,
                principal_sha256=principal_sha256,
                document_ref=authority.document_ref,
                document_sha256=document_sha256,
                product_area=authority.product_area,
                record_type=authority.record_type,
                media_type=authority.media_type,
                byte_size=authority.byte_size,
                content_sha256=authority.content_sha256,
                authority_revision=authority.authority_revision,
                authority_sha256=authority.authority_sha256,
                token_sha256=token_digest,
                state="active",
                revision=1,
                max_uses=max_uses,
                uses_remaining=max_uses,
                claim_count=0,
                issued_at=now,
                expires_at=now + ttl_seconds,
                retired_at=None,
                retained_until=None,
                created_idempotency_sha256=idempotency_sha256,
                request_sha256=request_sha256,
                record_sha256=GENESIS_SHA256,
            )
        )
        self._validate_record(record)
        with self._transaction() as connection:
            operation = connection.execute(
                "SELECT * FROM document_access_operations WHERE idempotency_sha256=?",
                (idempotency_sha256,),
            ).fetchone()
            if operation is not None:
                self._validate_operation_row(operation)
                if str(operation["operation_type"]) != "mint" or not text_equals(
                    str(operation["request_sha256"]), request_sha256
                ):
                    raise DocumentAccessConflict("document_access_idempotency_conflict")
                row = connection.execute(
                    "SELECT * FROM document_download_tokens WHERE token_id=?",
                    (str(operation["token_id"]),),
                ).fetchone()
                if row is None:
                    raise DocumentAccessConflict("document_access_token_retention_purged")
                return MintedDocumentToken(self._record_from_row(row), None, True)
            connection.execute(
                """
                INSERT INTO document_download_tokens (
                    token_id,tenant_sha256,principal_sha256,document_ref,
                    document_sha256,product_area,record_type,media_type,byte_size,
                    content_sha256,authority_revision,authority_sha256,token_sha256,
                    state,revision,max_uses,uses_remaining,claim_count,issued_at,
                    expires_at,retired_at,retained_until,created_idempotency_sha256,
                    request_sha256,record_sha256
                ) VALUES (
                    ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
                )
                """,
                tuple(asdict(record).values()),
            )
            operation_integrity = self._operation_integrity(
                idempotency_sha256=idempotency_sha256,
                operation_type="mint",
                token_id=token_id,
                request_sha256=request_sha256,
                result_revision=record.revision,
                completed_at=now,
            )
            connection.execute(
                "INSERT INTO document_access_operations VALUES (?,?,?,?,?,?,?)",
                (
                    idempotency_sha256,
                    "mint",
                    token_id,
                    request_sha256,
                    record.revision,
                    now,
                    operation_integrity,
                ),
            )
            self._append_audit_on(
                connection,
                event_type="administration.document_download_token.minted",
                token_id=token_id,
                actor_sha256=principal_sha256,
                resource_sha256=document_sha256,
                detail={
                    "authority_sha256": authority.authority_sha256,
                    "expires_at": record.expires_at,
                    "max_uses": max_uses,
                    "retention_seconds": retention_seconds,
                },
                occurred_at=now,
            )
        return MintedDocumentToken(record, raw_token, False)

    def _get_record_on(
        self,
        connection: sqlite3.Connection,
        *,
        token_id: str | None = None,
        token_sha256: str | None = None,
    ) -> DocumentDownloadTokenRecord:
        if (token_id is None) == (token_sha256 is None):
            raise DocumentAccessIntegrityError("document_access_lookup_invalid")
        if token_id is not None:
            row = connection.execute(
                "SELECT * FROM document_download_tokens WHERE token_id=?",
                (token_id,),
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT * FROM document_download_tokens WHERE token_sha256=?",
                (token_sha256,),
            ).fetchone()
        if row is None:
            raise DocumentAccessNotFound("document_access_token_not_found")
        return self._record_from_row(row)

    def get_token(self, token_id: str, *, principal_sha256: str) -> DocumentDownloadTokenRecord:
        selected = _opaque_id(token_id, label="token_id")
        with closing(self._connect()) as connection, connection:
            self._verify_meta_on(connection)
            record = self._get_record_on(connection, token_id=selected)
        if not hmac.compare_digest(record.principal_sha256, principal_sha256):
            raise DocumentAccessPermissionDenied("document_access_token_principal_mismatch")
        return record

    def list_tokens(
        self,
        *,
        principal_sha256: str,
        state: str | None = None,
        limit: int = 100,
    ) -> list[DocumentDownloadTokenRecord]:
        _integer(limit, minimum=1, maximum=_MAX_LIST_LIMIT, label="limit")
        if state is not None and state not in _TOKEN_STATES:
            raise DocumentAccessValidationError("document_access_token_state_invalid")
        query = "SELECT * FROM document_download_tokens WHERE principal_sha256=?"
        values: list[object] = [principal_sha256]
        if state is not None:
            query += " AND state=?"
            values.append(state)
        query += " ORDER BY issued_at DESC,token_id DESC LIMIT ?"
        values.append(limit)
        with closing(self._connect()) as connection, connection:
            self._verify_meta_on(connection)
            rows = connection.execute(query, values).fetchall()
        return [self._record_from_row(row) for row in rows]

    def revoke_token(
        self,
        token_id: str,
        *,
        principal_sha256: str,
        expected_revision: int,
        idempotency_key: str,
        retention_seconds: int,
    ) -> DocumentDownloadTokenRecord:
        selected = _opaque_id(token_id, label="token_id")
        expected = _integer(
            expected_revision,
            minimum=1,
            maximum=2**63 - 1,
            label="expected_revision",
        )
        idem = _idempotency_digest(idempotency_key)
        request_sha = canonical_sha256(
            {
                "operation": "revoke",
                "token_id": selected,
                "principal_sha256": principal_sha256,
                "expected_revision": expected,
            }
        )
        now = _clock_value(self._clock)
        with self._transaction() as connection:
            prior = connection.execute(
                "SELECT * FROM document_access_operations WHERE idempotency_sha256=?",
                (idem,),
            ).fetchone()
            if prior is not None:
                self._validate_operation_row(prior)
                if (
                    str(prior["operation_type"]) != "revoke"
                    or not text_equals(str(prior["request_sha256"]), request_sha)
                    or str(prior["token_id"]) != selected
                ):
                    raise DocumentAccessConflict("document_access_idempotency_conflict")
                return self._get_record_on(connection, token_id=selected)
            record = self._get_record_on(connection, token_id=selected)
            if not hmac.compare_digest(record.principal_sha256, principal_sha256):
                raise DocumentAccessPermissionDenied("document_access_token_principal_mismatch")
            if record.revision != expected:
                raise DocumentAccessConflict("document_access_revision_conflict")
            if record.state != "active":
                raise DocumentAccessConflict("document_access_token_not_active")
            updated = _record_with_digest(
                replace(
                    record,
                    state="revoked",
                    revision=record.revision + 1,
                    retired_at=now,
                    retained_until=now + retention_seconds,
                )
            )
            self._write_record_on(connection, updated, expected_revision=record.revision)
            integrity = self._operation_integrity(
                idempotency_sha256=idem,
                operation_type="revoke",
                token_id=selected,
                request_sha256=request_sha,
                result_revision=updated.revision,
                completed_at=now,
            )
            connection.execute(
                "INSERT INTO document_access_operations VALUES (?,?,?,?,?,?,?)",
                (idem, "revoke", selected, request_sha, updated.revision, now, integrity),
            )
            self._append_audit_on(
                connection,
                event_type="administration.document_download_token.revoked",
                token_id=selected,
                actor_sha256=principal_sha256,
                resource_sha256=record.document_sha256,
                detail={"expected_revision": expected, "new_revision": updated.revision},
                occurred_at=now,
            )
            return updated

    def reconcile_expired(self, *, retention_seconds: int, limit: int = 100) -> int:
        maximum = _integer(limit, minimum=1, maximum=_MAX_LIST_LIMIT, label="limit")
        now = _clock_value(self._clock)
        changed = 0
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM document_download_tokens "
                "WHERE state='active' AND expires_at<=? ORDER BY expires_at,token_id LIMIT ?",
                (now, maximum),
            ).fetchall()
            for row in rows:
                record = self._record_from_row(row)
                updated = _record_with_digest(
                    replace(
                        record,
                        state="expired",
                        revision=record.revision + 1,
                        retired_at=now,
                        retained_until=now + retention_seconds,
                    )
                )
                self._write_record_on(connection, updated, expected_revision=record.revision)
                self._append_audit_on(
                    connection,
                    event_type="administration.document_download_token.expired",
                    token_id=record.token_id,
                    actor_sha256=record.principal_sha256,
                    resource_sha256=record.document_sha256,
                    detail={"expires_at": record.expires_at, "new_revision": updated.revision},
                    occurred_at=now,
                )
                changed += 1
        return changed

    def invalidate_authority(
        self,
        *,
        token_sha256: str,
        principal_sha256: str,
        retention_seconds: int,
    ) -> None:
        now = _clock_value(self._clock)
        with self._transaction() as connection:
            record = self._get_record_on(connection, token_sha256=token_sha256)
            if not hmac.compare_digest(record.principal_sha256, principal_sha256):
                raise DocumentAccessPermissionDenied("document_access_token_principal_mismatch")
            if record.state != "active":
                return
            updated = _record_with_digest(
                replace(
                    record,
                    state="revoked",
                    revision=record.revision + 1,
                    retired_at=now,
                    retained_until=now + retention_seconds,
                )
            )
            self._write_record_on(connection, updated, expected_revision=record.revision)
            self._append_audit_on(
                connection,
                event_type="administration.document_download_token.authority_invalidated",
                token_id=record.token_id,
                actor_sha256=principal_sha256,
                resource_sha256=record.document_sha256,
                detail={"authority_sha256": record.authority_sha256},
                occurred_at=now,
            )

    def reserve_claim(
        self,
        *,
        token_sha256: str,
        principal_sha256: str,
        authority: DocumentAuthority,
        idempotency_key: str,
        retention_seconds: int,
    ) -> tuple[DocumentDownloadTokenRecord, str, str, float]:
        idem = _idempotency_digest(idempotency_key)
        now = _clock_value(self._clock)
        request_sha = canonical_sha256(
            {
                "operation": "claim",
                "token_sha256": token_sha256,
                "principal_sha256": principal_sha256,
                "authority_revision": authority.authority_revision,
                "authority_sha256": authority.authority_sha256,
            }
        )
        terminal_error: DocumentAccessError | None = None
        result: tuple[DocumentDownloadTokenRecord, str, str, float] | None = None
        with self._transaction() as connection:
            prior = connection.execute(
                "SELECT * FROM document_access_claims WHERE idempotency_sha256=?",
                (idem,),
            ).fetchone()
            if prior is not None:
                self._validate_claim_row(prior)
                if not text_equals(str(prior["request_sha256"]), request_sha):
                    raise DocumentAccessConflict("document_access_idempotency_conflict")
                raise DocumentAccessConflict("document_access_claim_replay")
            record = self._get_record_on(connection, token_sha256=token_sha256)
            if not hmac.compare_digest(record.principal_sha256, principal_sha256):
                raise DocumentAccessPermissionDenied("document_access_token_principal_mismatch")
            if record.state != "active":
                terminal_error = DocumentAccessConflict("document_access_token_not_active")
            elif now >= record.expires_at:
                updated = _record_with_digest(
                    replace(
                        record,
                        state="expired",
                        revision=record.revision + 1,
                        retired_at=now,
                        retained_until=now + retention_seconds,
                    )
                )
                self._write_record_on(connection, updated, expected_revision=record.revision)
                self._append_audit_on(
                    connection,
                    event_type="administration.document_download_token.expired",
                    token_id=record.token_id,
                    actor_sha256=principal_sha256,
                    resource_sha256=record.document_sha256,
                    detail={"expires_at": record.expires_at, "new_revision": updated.revision},
                    occurred_at=now,
                )
                terminal_error = DocumentAccessExpired("document_access_token_expired")
            else:
                remaining = record.uses_remaining - 1
                state = "exhausted" if remaining == 0 else "active"
                retired_at = now if state == "exhausted" else None
                retained_until = now + retention_seconds if state == "exhausted" else None
                updated = _record_with_digest(
                    replace(
                        record,
                        state=state,
                        revision=record.revision + 1,
                        uses_remaining=remaining,
                        claim_count=record.claim_count + 1,
                        retired_at=retired_at,
                        retained_until=retained_until,
                    )
                )
                self._write_record_on(connection, updated, expected_revision=record.revision)
                claim_id = "dcl-" + secrets.token_hex(16)
                integrity = self._claim_integrity(
                    idempotency_sha256=idem,
                    claim_id=claim_id,
                    token_id=record.token_id,
                    request_sha256=request_sha,
                    state="pending",
                    created_at=now,
                    completed_at=None,
                    grant_sha256=None,
                )
                connection.execute(
                    "INSERT INTO document_access_claims VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        idem,
                        claim_id,
                        record.token_id,
                        request_sha,
                        "pending",
                        now,
                        None,
                        None,
                        integrity,
                    ),
                )
                self._append_audit_on(
                    connection,
                    event_type="administration.document_download_token.claimed",
                    token_id=record.token_id,
                    actor_sha256=principal_sha256,
                    resource_sha256=record.document_sha256,
                    detail={
                        "claim_id_sha256": _text_sha256(claim_id),
                        "new_revision": updated.revision,
                        "uses_remaining": updated.uses_remaining,
                    },
                    occurred_at=now,
                )
                if state == "exhausted":
                    self._append_audit_on(
                        connection,
                        event_type="administration.document_download_token.exhausted",
                        token_id=record.token_id,
                        actor_sha256=principal_sha256,
                        resource_sha256=record.document_sha256,
                        detail={"claim_count": updated.claim_count},
                        occurred_at=now,
                    )
                result = (updated, claim_id, idem, now)
        if terminal_error is not None:
            raise terminal_error
        if result is None:
            raise DocumentAccessIntegrityError("document_access_claim_reservation_missing")
        return result

    def _validate_claim_row(self, row: sqlite3.Row) -> None:
        values = {
            "idempotency_sha256": str(row["idempotency_sha256"]),
            "claim_id": str(row["claim_id"]),
            "token_id": str(row["token_id"]),
            "request_sha256": str(row["request_sha256"]),
            "state": str(row["state"]),
            "created_at": float(row["created_at"]),
            "completed_at": (None if row["completed_at"] is None else float(row["completed_at"])),
            "grant_sha256": (None if row["grant_sha256"] is None else str(row["grant_sha256"])),
        }
        if values["state"] not in {"pending", "issued", "failed"}:
            raise DocumentAccessIntegrityError("document_access_claim_state_invalid")
        expected = self._claim_integrity(**values)
        if not text_equals(expected, str(row["integrity_sha256"])):
            raise DocumentAccessIntegrityError("document_access_claim_integrity_invalid")

    def finalize_claim(
        self,
        *,
        claim_id: str,
        issued: bool,
        grant_sha256: str | None,
        restore_use: bool = False,
    ) -> None:
        """Close a pending claim as issued or failed.

        ``restore_use`` gives the reserved use back on a failed claim. It is
        for an issuer that failed before issuing anything; a token that was
        revoked, invalidated or has expired meanwhile stays as it is.
        """

        now = _clock_value(self._clock)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM document_access_claims WHERE claim_id=?",
                (claim_id,),
            ).fetchone()
            if row is None:
                raise DocumentAccessIntegrityError("document_access_claim_missing")
            self._validate_claim_row(row)
            if str(row["state"]) != "pending":
                raise DocumentAccessConflict("document_access_claim_already_finalized")
            selected_digest = _digest(grant_sha256, label="grant_sha256") if issued else None
            state = "issued" if issued else "failed"
            integrity = self._claim_integrity(
                idempotency_sha256=str(row["idempotency_sha256"]),
                claim_id=str(row["claim_id"]),
                token_id=str(row["token_id"]),
                request_sha256=str(row["request_sha256"]),
                state=state,
                created_at=float(row["created_at"]),
                completed_at=now,
                grant_sha256=selected_digest,
            )
            try:
                result = connection.execute(
                    "UPDATE document_access_claims SET state=?,completed_at=?,grant_sha256=?,"
                    "integrity_sha256=? WHERE claim_id=? AND state='pending'",
                    (state, now, selected_digest, integrity, claim_id),
                )
            except sqlite3.IntegrityError as exc:
                raise DocumentAccessConflict("document_access_delivery_grant_reused") from exc
            if result.rowcount != 1:
                raise DocumentAccessConflict("document_access_claim_already_finalized")
            token = self._get_record_on(connection, token_id=str(row["token_id"]))
            detail: dict[str, object] = {
                "claim_id_sha256": _text_sha256(claim_id),
                "grant_sha256": selected_digest or GENESIS_SHA256,
            }
            if (
                restore_use
                and not issued
                and token.state in {"active", "exhausted"}
                and token.claim_count > 0
                and now < token.expires_at
            ):
                restored = _record_with_digest(
                    replace(
                        token,
                        state="active",
                        revision=token.revision + 1,
                        uses_remaining=token.uses_remaining + 1,
                        claim_count=token.claim_count - 1,
                        retired_at=None,
                        retained_until=None,
                    )
                )
                self._write_record_on(connection, restored, expected_revision=token.revision)
                detail["use_restored"] = True
                detail["new_revision"] = restored.revision
                detail["uses_remaining"] = restored.uses_remaining
            self._append_audit_on(
                connection,
                event_type=(
                    "administration.document_attachment.delivery_grant_issued"
                    if issued
                    else "administration.document_attachment.delivery_grant_failed"
                ),
                token_id=token.token_id,
                actor_sha256=token.principal_sha256,
                resource_sha256=token.document_sha256,
                detail=detail,
                occurred_at=now,
            )

    def purge_token(
        self,
        token_id: str,
        *,
        principal_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> RetentionTombstone:
        selected = _opaque_id(token_id, label="token_id")
        expected = _integer(
            expected_revision,
            minimum=1,
            maximum=2**63 - 1,
            label="expected_revision",
        )
        idem = _idempotency_digest(idempotency_key)
        request_sha = canonical_sha256(
            {
                "operation": "purge",
                "token_id": selected,
                "principal_sha256": principal_sha256,
                "expected_revision": expected,
            }
        )
        now = _clock_value(self._clock)
        with self._transaction() as connection:
            prior = connection.execute(
                "SELECT * FROM document_access_operations WHERE idempotency_sha256=?",
                (idem,),
            ).fetchone()
            if prior is not None:
                self._validate_operation_row(prior)
                if (
                    str(prior["operation_type"]) != "purge"
                    or str(prior["token_id"]) != selected
                    or not text_equals(str(prior["request_sha256"]), request_sha)
                ):
                    raise DocumentAccessConflict("document_access_idempotency_conflict")
                tombstone_row = connection.execute(
                    "SELECT * FROM document_access_tombstones WHERE token_id=?",
                    (selected,),
                ).fetchone()
                if tombstone_row is None:
                    raise DocumentAccessIntegrityError("document_access_tombstone_missing")
                return self._tombstone_from_row(tombstone_row)
            record = self._get_record_on(connection, token_id=selected)
            if not hmac.compare_digest(record.principal_sha256, principal_sha256):
                raise DocumentAccessPermissionDenied("document_access_token_principal_mismatch")
            if record.revision != expected:
                raise DocumentAccessConflict("document_access_revision_conflict")
            if record.state not in _TERMINAL_STATES:
                raise DocumentAccessConflict("document_access_retention_requires_terminal_token")
            if record.retained_until is None or now < record.retained_until:
                raise DocumentAccessConflict("document_access_retention_not_elapsed")
            tombstone = RetentionTombstone(
                token_id=record.token_id,
                tenant_sha256=record.tenant_sha256,
                principal_sha256=record.principal_sha256,
                document_sha256=record.document_sha256,
                final_record_sha256=record.record_sha256,
                retired_at=record.retired_at or now,
                purged_at=now,
                tombstone_sha256=GENESIS_SHA256,
            )
            tombstone = replace(
                tombstone,
                tombstone_sha256=canonical_sha256(_tombstone_material(tombstone)),
            )
            connection.execute(
                "INSERT INTO document_access_tombstones VALUES (?,?,?,?,?,?,?,?)",
                tuple(asdict(tombstone).values()),
            )
            connection.execute(
                "DELETE FROM document_download_tokens WHERE token_id=? AND revision=?",
                (selected, expected),
            )
            operation_integrity = self._operation_integrity(
                idempotency_sha256=idem,
                operation_type="purge",
                token_id=selected,
                request_sha256=request_sha,
                result_revision=expected,
                completed_at=now,
            )
            connection.execute(
                "INSERT INTO document_access_operations VALUES (?,?,?,?,?,?,?)",
                (idem, "purge", selected, request_sha, expected, now, operation_integrity),
            )
            self._append_audit_on(
                connection,
                event_type="administration.document_download_token.retention_purged",
                token_id=selected,
                actor_sha256=principal_sha256,
                resource_sha256=record.document_sha256,
                detail={"final_record_sha256": record.record_sha256},
                occurred_at=now,
            )
            return tombstone

    @staticmethod
    def _tombstone_from_row(row: sqlite3.Row) -> RetentionTombstone:
        tombstone = RetentionTombstone(
            token_id=str(row["token_id"]),
            tenant_sha256=str(row["tenant_sha256"]),
            principal_sha256=str(row["principal_sha256"]),
            document_sha256=str(row["document_sha256"]),
            final_record_sha256=str(row["final_record_sha256"]),
            retired_at=float(row["retired_at"]),
            purged_at=float(row["purged_at"]),
            tombstone_sha256=str(row["tombstone_sha256"]),
        )
        expected = canonical_sha256(_tombstone_material(tombstone))
        if not text_equals(expected, tombstone.tombstone_sha256):
            raise DocumentAccessIntegrityError("document_access_tombstone_integrity_invalid")
        return tombstone

    def list_audit(self, *, limit: int = 100) -> list[dict[str, object]]:
        _integer(limit, minimum=1, maximum=_MAX_AUDIT_LIMIT, label="limit")
        with closing(self._connect()) as connection, connection:
            self._verify_meta_on(connection)
            rows = connection.execute(
                "SELECT * FROM document_access_audit ORDER BY sequence DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def status(self) -> dict[str, object]:
        integrity = self.verify_integrity()
        now = _clock_value(self._clock)
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                "SELECT state,COUNT(*) AS count FROM document_download_tokens GROUP BY state"
            ).fetchall()
            tombstones = int(
                connection.execute("SELECT COUNT(*) FROM document_access_tombstones").fetchone()[0]
            )
        counts = dict.fromkeys(sorted(_TOKEN_STATES), 0)
        counts.update({str(row["state"]): int(row["count"]) for row in rows})
        return {
            "schema": "lightwork.administration-document-access-status.v1",
            "enabled": True,
            "configured": True,
            "ready": integrity["ok"] is True,
            "catalog_version": CATALOG_VERSION,
            "event_type_count": len(EVENT_TYPE_CATALOG),
            "token_counts": counts,
            "tombstone_count": tombstones,
            "observed_at": now,
            "integrity": integrity,
            "live_relying_workflow_verified": False,
            "external_object_store_custody_verified": False,
            "limits": self.product_boundaries(),
        }

    @staticmethod
    def product_boundaries() -> dict[str, bool]:
        return {
            "raw_download_tokens_persisted": False,
            "raw_delivery_grants_persisted": False,
            "raw_document_bytes_persisted": False,
            "document_paths_or_urls_persisted": False,
            "caller_event_type_registration_supported": False,
            "local_integrity_is_external_worm_anchor": False,
            "live_relying_workflow_verified": False,
            "external_object_store_custody_verified": False,
        }

    def verify_integrity(self) -> dict[str, object]:
        try:
            with closing(self._connect()) as connection, connection:
                self._verify_meta_on(connection)
                token_rows = connection.execute(
                    "SELECT * FROM document_download_tokens ORDER BY token_id"
                ).fetchall()
                for row in token_rows:
                    record = self._record_from_row(row)
                    if not hmac.compare_digest(record.tenant_sha256, self.tenant_sha256):
                        raise DocumentAccessIntegrityError("document_access_token_tenant_invalid")

                operation_rows = connection.execute(
                    "SELECT * FROM document_access_operations ORDER BY completed_at,"
                    "idempotency_sha256"
                ).fetchall()
                for row in operation_rows:
                    self._validate_operation_row(row)
                    token_exists = connection.execute(
                        "SELECT 1 FROM document_download_tokens WHERE token_id=?",
                        (str(row["token_id"]),),
                    ).fetchone()
                    tombstone_exists = connection.execute(
                        "SELECT 1 FROM document_access_tombstones WHERE token_id=?",
                        (str(row["token_id"]),),
                    ).fetchone()
                    if token_exists is None and tombstone_exists is None:
                        raise DocumentAccessIntegrityError(
                            "document_access_operation_target_missing"
                        )

                claim_rows = connection.execute(
                    "SELECT * FROM document_access_claims ORDER BY created_at,claim_id"
                ).fetchall()
                for row in claim_rows:
                    self._validate_claim_row(row)

                tombstone_rows = connection.execute(
                    "SELECT * FROM document_access_tombstones ORDER BY token_id"
                ).fetchall()
                for row in tombstone_rows:
                    tombstone = self._tombstone_from_row(row)
                    if not hmac.compare_digest(tombstone.tenant_sha256, self.tenant_sha256):
                        raise DocumentAccessIntegrityError(
                            "document_access_tombstone_tenant_invalid"
                        )

                audit_rows = connection.execute(
                    "SELECT * FROM document_access_audit ORDER BY sequence"
                ).fetchall()
                previous = GENESIS_SHA256
                expected_sequence = 1
                for row in audit_rows:
                    event_type = str(row["event_type"])
                    if event_type not in _EVENT_TYPES:
                        raise DocumentAccessIntegrityError(
                            "document_access_audit_event_type_invalid"
                        )
                    material = {
                        "schema": AUDIT_SCHEMA,
                        "sequence": int(row["sequence"]),
                        "event_type": event_type,
                        "token_id": str(row["token_id"]),
                        "actor_sha256": str(row["actor_sha256"]),
                        "resource_sha256": str(row["resource_sha256"]),
                        "detail_sha256": str(row["detail_sha256"]),
                        "occurred_at": float(row["occurred_at"]),
                        "previous_sha256": str(row["previous_sha256"]),
                    }
                    expected = canonical_sha256(material)
                    if (
                        material["sequence"] != expected_sequence
                        or not hmac.compare_digest(str(material["previous_sha256"]), previous)
                        or not hmac.compare_digest(expected, str(row["event_sha256"]))
                    ):
                        raise DocumentAccessIntegrityError(
                            "document_access_audit_integrity_invalid"
                        )
                    previous = str(row["event_sha256"])
                    expected_sequence += 1
                return {
                    "schema": "lightwork.administration-document-access-integrity.v1",
                    "ok": True,
                    "schema_version": SCHEMA_VERSION,
                    "token_count": len(token_rows),
                    "operation_count": len(operation_rows),
                    "claim_count": len(claim_rows),
                    "tombstone_count": len(tombstone_rows),
                    "audit_event_count": len(audit_rows),
                    "audit_tip_sha256": previous,
                    "external_worm_anchor_verified": False,
                }
        except DocumentAccessError:
            raise
        except (OSError, sqlite3.DatabaseError, TypeError, ValueError) as exc:
            raise DocumentAccessIntegrityError(
                "document_access_integrity_verification_failed"
            ) from exc


class DocumentAccessService:
    """Principal-bound service joining the store to server-owned authorities."""

    def __init__(
        self,
        *,
        store: DocumentAccessStore,
        config: DocumentAccessConfig,
        principal_resolver: PrincipalResolver,
        document_resolver: DocumentAuthorityResolver,
        delivery_grant_issuer: DeliveryGrantIssuer,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if type(store) is not DocumentAccessStore:
            raise DocumentAccessConfigError("document_access_store_unavailable")
        if type(config) is not DocumentAccessConfig or not config.enable:
            raise DocumentAccessConfigError("administration_document_access_disabled")
        for dependency in (principal_resolver, document_resolver, delivery_grant_issuer, clock):
            if not callable(dependency):
                raise DocumentAccessConfigError("document_access_dependency_unavailable")
        self.store = store
        self.config = config
        self._principal_resolver = principal_resolver
        self._document_resolver = document_resolver
        self._delivery_grant_issuer = delivery_grant_issuer
        self._clock = clock

    def _principal(self) -> tuple[str, str]:
        try:
            principal = _principal(self._principal_resolver())
        except (KeyboardInterrupt, SystemExit):
            raise
        except DocumentAccessError:
            raise
        except Exception as exc:
            raise DocumentAccessConfigError("document_access_principal_unavailable") from exc
        return principal, _principal_sha256(self.store.tenant_sha256, principal)

    def _resolve(self, *, principal_ref: str, document_ref: str) -> DocumentAuthority:
        try:
            authority = self._document_resolver(
                self.store.tenant_id,
                principal_ref,
                _opaque_id(document_ref, label="document_ref"),
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except DocumentAccessError:
            raise
        except Exception as exc:
            raise DocumentAccessConfigError(
                "document_access_document_resolver_unavailable"
            ) from exc
        if type(authority) is not DocumentAuthority:
            raise DocumentAccessConfigError("document_access_document_authority_invalid")
        if authority.tenant_id != self.store.tenant_id or not hmac.compare_digest(
            authority.principal_ref, principal_ref
        ):
            raise DocumentAccessPermissionDenied("document_access_authority_binding_mismatch")
        if not authority.download_allowed:
            raise DocumentAccessPermissionDenied("document_access_download_not_authorized")
        return authority

    @staticmethod
    def _authority_matches(
        record: DocumentDownloadTokenRecord,
        authority: DocumentAuthority,
    ) -> bool:
        return bool(
            record.document_ref == authority.document_ref
            and record.product_area == authority.product_area
            and record.record_type == authority.record_type
            and record.media_type == authority.media_type
            and record.byte_size == authority.byte_size
            and hmac.compare_digest(record.content_sha256, authority.content_sha256)
            and record.authority_revision == authority.authority_revision
            and hmac.compare_digest(record.authority_sha256, authority.authority_sha256)
        )

    def mint_token(
        self,
        document_ref: str,
        *,
        ttl_seconds: int | None = None,
        max_uses: int = 1,
        idempotency_key: str,
    ) -> MintedDocumentToken:
        requested_ref = _opaque_id(document_ref, label="document_ref")
        ttl = (
            self.config.default_ttl_seconds
            if ttl_seconds is None
            else _integer(
                ttl_seconds,
                minimum=30,
                maximum=self.config.max_ttl_seconds,
                label="ttl_seconds",
            )
        )
        uses = _integer(
            max_uses,
            minimum=1,
            maximum=self.config.max_uses,
            label="max_uses",
        )
        principal_ref, principal_sha = self._principal()
        idem = _idempotency_digest(idempotency_key)
        request_sha = canonical_sha256(
            {
                "operation": "mint",
                "tenant_sha256": self.store.tenant_sha256,
                "principal_sha256": principal_sha,
                "requested_document_sha256": _text_sha256(requested_ref),
                "ttl_seconds": ttl,
                "max_uses": uses,
            }
        )
        replay = self.store.find_mint_replay(
            idempotency_sha256=idem,
            request_sha256=request_sha,
        )
        if replay is not None:
            return replay
        authority = self._resolve(principal_ref=principal_ref, document_ref=requested_ref)
        return self.store.create_token(
            principal_sha256=principal_sha,
            authority=authority,
            ttl_seconds=ttl,
            max_uses=uses,
            idempotency_sha256=idem,
            request_sha256=request_sha,
            retention_seconds=self.config.retention_seconds,
        )

    def get_token(self, token_id: str) -> DocumentDownloadTokenRecord:
        _principal_ref, principal_sha = self._principal()
        return self.store.get_token(token_id, principal_sha256=principal_sha)

    def list_tokens(
        self,
        *,
        state: str | None = None,
        limit: int = 100,
    ) -> list[DocumentDownloadTokenRecord]:
        _principal_ref, principal_sha = self._principal()
        return self.store.list_tokens(
            principal_sha256=principal_sha,
            state=state,
            limit=limit,
        )

    def revoke_token(
        self,
        token_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> DocumentDownloadTokenRecord:
        _principal_ref, principal_sha = self._principal()
        return self.store.revoke_token(
            token_id,
            principal_sha256=principal_sha,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            retention_seconds=self.config.retention_seconds,
        )

    def claim(
        self,
        download_token: str,
        *,
        idempotency_key: str,
    ) -> ClaimedDeliveryGrant:
        raw_token = _download_token(download_token)
        token_digest = _token_sha256(raw_token)
        principal_ref, principal_sha = self._principal()

        # Read only the digest-selected retained record, then independently
        # re-resolve its server-owned opaque reference before consuming a use.
        with closing(self.store._connect()) as connection, connection:
            self.store._verify_meta_on(connection)
            record = self.store._get_record_on(connection, token_sha256=token_digest)
        if not hmac.compare_digest(record.principal_sha256, principal_sha):
            raise DocumentAccessPermissionDenied("document_access_token_principal_mismatch")
        try:
            authority = self._resolve(
                principal_ref=principal_ref,
                document_ref=record.document_ref,
            )
        except DocumentAccessPermissionDenied:
            # The token and caller were already matched locally.  A current
            # authoritative denial/binding mismatch permanently fails this
            # retained token closed instead of leaving an apparently-active
            # capability that can be retried against stale authority.
            self.store.invalidate_authority(
                token_sha256=token_digest,
                principal_sha256=principal_sha,
                retention_seconds=self.config.retention_seconds,
            )
            raise
        if not self._authority_matches(record, authority):
            self.store.invalidate_authority(
                token_sha256=token_digest,
                principal_sha256=principal_sha,
                retention_seconds=self.config.retention_seconds,
            )
            raise DocumentAccessConflict("document_access_document_authority_changed")

        updated, claim_id, _idem, reserved_at = self.store.reserve_claim(
            token_sha256=token_digest,
            principal_sha256=principal_sha,
            authority=authority,
            idempotency_key=idempotency_key,
            retention_seconds=self.config.retention_seconds,
        )
        grant_deadline = min(
            updated.expires_at,
            reserved_at + self.config.delivery_grant_ttl_seconds,
        )
        claim = DeliveryClaim(
            tenant_id=self.store.tenant_id,
            principal_ref=principal_ref,
            token_id=updated.token_id,
            claim_id=claim_id,
            document_ref=authority.document_ref,
            product_area=authority.product_area,
            record_type=authority.record_type,
            safe_display_name=authority.safe_display_name,
            media_type=authority.media_type,
            byte_size=authority.byte_size,
            content_sha256=authority.content_sha256,
            authority_revision=authority.authority_revision,
            authority_sha256=authority.authority_sha256,
            grant_expires_at=grant_deadline,
        )
        grant_returned = False
        try:
            issued = self._delivery_grant_issuer(claim)
            grant_returned = True
            if type(issued) is not DeliveryGrant:
                raise DocumentAccessConfigError("document_access_delivery_grant_invalid")
            opaque = _delivery_grant(issued.grant)
            expires_at = _timestamp(issued.expires_at, label="delivery_grant_expires_at")
            if expires_at <= reserved_at or expires_at > grant_deadline:
                raise DocumentAccessConfigError("document_access_delivery_grant_lifetime_invalid")
            grant_sha = _text_sha256("lightwork.document-access.delivery-grant.v1:" + opaque)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            # The use is given back only when the issuer itself raised, so
            # nothing was issued and a transient outage does not exhaust the
            # token. A returned grant that fails validation may be live, so
            # that use stays consumed.
            self.store.finalize_claim(
                claim_id=claim_id,
                issued=False,
                grant_sha256=None,
                restore_use=not grant_returned,
            )
            if isinstance(exc, DocumentAccessError):
                raise
            raise DocumentAccessConfigError("document_access_delivery_issuer_unavailable") from exc
        self.store.finalize_claim(
            claim_id=claim_id,
            issued=True,
            grant_sha256=grant_sha,
        )
        return ClaimedDeliveryGrant(opaque, expires_at)

    def reconcile_expired(self, *, limit: int = 100) -> int:
        return self.store.reconcile_expired(
            retention_seconds=self.config.retention_seconds,
            limit=limit,
        )

    def purge_token(
        self,
        token_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> RetentionTombstone:
        _principal_ref, principal_sha = self._principal()
        return self.store.purge_token(
            token_id,
            principal_sha256=principal_sha,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def status(self) -> dict[str, object]:
        return self.store.status()


__all__ = [
    "CATALOG_VERSION",
    "EVENT_TYPE_CATALOG",
    "PRODUCT_AREAS",
    "ClaimedDeliveryGrant",
    "DeliveryClaim",
    "DeliveryGrant",
    "DeliveryGrantIssuer",
    "DocumentAccessConfig",
    "DocumentAccessConfigError",
    "DocumentAccessConflict",
    "DocumentAccessError",
    "DocumentAccessExpired",
    "DocumentAccessIntegrityError",
    "DocumentAccessNotFound",
    "DocumentAccessPermissionDenied",
    "DocumentAccessService",
    "DocumentAccessStore",
    "DocumentAccessValidationError",
    "DocumentAuthority",
    "DocumentAuthorityResolver",
    "DocumentDownloadTokenRecord",
    "EventTypeDefinition",
    "MintedDocumentToken",
    "RetentionTombstone",
    "canonical_sha256",
    "config_from",
    "enabled",
    "list_event_types",
    "require_enabled",
]
