"""Tenant-private encrypted document authority and one-time delivery grants.

This is the stock, local custody plane used by the administration document-
access and incident-attachment control planes.  It accepts document bytes only
through a server-owned call, stores an authenticated ciphertext produced by
``maverick.crypto_at_rest``, and exposes opaque document references.  Paths,
object locators, raw principals, raw grants, and encryption keys are never part
of its public or persisted metadata contracts.

The local vault is production-deployable for a single Lightwork persistence
plane.  It deliberately does not claim external object-store custody, backup
acceptance, malware scanning, or acceptance by a live relying workflow.
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
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import administration_document_access as document_access
from .constant_time import text_equals
from .file_lock import (
    ensure_private_directory,
    ensure_private_file,
    private_path_is_restricted,
)
from .paths import canonical_tenant_id, tenant_scope

SCHEMA_VERSION = 2
GENESIS_SHA256 = "0" * 64
GRANT_PREFIX = "lwdvg_v1_"

_INGEST_EVENT = "administration.governed_document.ingested"
_REVOKE_EVENT = "administration.governed_document.revoked"
_PURGE_EVENT = "administration.governed_document.retention_purged"

DEFAULT_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "image/jpeg",
        "image/png",
        "image/webp",
        "text/csv",
        "text/plain",
    }
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_RECORD_TYPE_RE = re.compile(r"[a-z][a-z0-9_.-]{0,95}\Z")
_MEDIA_TYPE_RE = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,127}\Z"
)
_GRANT_RE = re.compile(r"lwdvg_v1_[A-Za-z0-9_-]{43}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class GovernedDocumentVaultError(RuntimeError):
    """Closed-code base error for the vault."""

    def __init__(self, error_code: str) -> None:
        if not isinstance(error_code, str) or not re.fullmatch(
            r"[a-z][a-z0-9_]{0,95}", error_code
        ):
            raise ValueError("governed document vault error code is invalid")
        self.error_code = error_code
        super().__init__(error_code)


class VaultConfigError(GovernedDocumentVaultError):
    pass


class VaultValidationError(GovernedDocumentVaultError, ValueError):
    pass


class VaultNotFound(GovernedDocumentVaultError):
    pass


class VaultPermissionDenied(GovernedDocumentVaultError):
    pass


class VaultConflict(GovernedDocumentVaultError):
    pass


class VaultIntegrityError(GovernedDocumentVaultError):
    pass


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise VaultValidationError("document_vault_material_invalid") from exc
    if not 1 <= len(encoded) <= 256 * 1024:
        raise VaultValidationError("document_vault_material_oversized")
    return encoded


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _tenant(value: object) -> str:
    if not isinstance(value, str):
        raise VaultValidationError("document_vault_tenant_invalid")
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise VaultValidationError("document_vault_tenant_invalid") from exc


def _identifier(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or _ID_RE.fullmatch(value) is None
        or value in {".", ".."}
    ):
        raise VaultValidationError(f"document_vault_{label}_invalid")
    return value


def _principal(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or _CONTROL_RE.search(value):
        raise VaultPermissionDenied("document_vault_principal_invalid")
    return value


def _display_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 255
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or _CONTROL_RE.search(value)
    ):
        raise VaultValidationError("document_vault_display_name_invalid")
    return value


def _media_type(value: object) -> str:
    if not isinstance(value, str):
        raise VaultValidationError("document_vault_media_type_invalid")
    selected = value.strip().lower()
    if _MEDIA_TYPE_RE.fullmatch(selected) is None:
        raise VaultValidationError("document_vault_media_type_invalid")
    return selected


def _record_type(value: object) -> str:
    if not isinstance(value, str) or _RECORD_TYPE_RE.fullmatch(value) is None:
        raise VaultValidationError("document_vault_record_type_invalid")
    return value


def _product_area(value: object) -> str:
    if not isinstance(value, str) or value not in document_access.PRODUCT_AREAS:
        raise VaultValidationError("document_vault_product_area_invalid")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise VaultValidationError(f"document_vault_{label}_invalid")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise VaultValidationError(f"document_vault_{label}_invalid")
    selected = float(value)
    if not math.isfinite(selected) or not 0 < selected < 100_000_000_000:
        raise VaultValidationError(f"document_vault_{label}_invalid")
    return selected


def _clock_value(clock: Callable[[], float]) -> float:
    try:
        return _timestamp(clock(), "clock")
    except (KeyboardInterrupt, SystemExit):
        raise
    except GovernedDocumentVaultError:
        raise
    except Exception as exc:
        raise VaultConfigError("document_vault_clock_unavailable") from exc


def _grant(value: object) -> str:
    if not isinstance(value, str) or _GRANT_RE.fullmatch(value) is None:
        raise VaultValidationError("document_vault_delivery_grant_invalid")
    return value


def _grant_sha256(value: str) -> str:
    return _text_sha256("lightwork.governed-document-vault.grant.v1:" + value)


def _principal_sha256(tenant_sha256: str, value: str) -> str:
    return _text_sha256(
        f"lightwork.governed-document-vault.principal.v1:{tenant_sha256}:{value}"
    )


@dataclass(frozen=True, slots=True)
class GovernedDocumentVaultConfig:
    enable: bool = False
    max_document_bytes: int = 25 * 1024 * 1024
    max_documents: int = 100_000
    retention_seconds: int = 365 * 24 * 60 * 60
    grant_ttl_seconds: int = 60
    claim_lease_seconds: int = 30
    stream_chunk_bytes: int = 64 * 1024
    allowed_media_types: tuple[str, ...] = tuple(sorted(DEFAULT_MEDIA_TYPES))

    def __post_init__(self) -> None:
        if type(self.enable) is not bool:
            raise VaultConfigError("document_vault_enable_invalid")
        for value, label, low, high in (
            (self.max_document_bytes, "max_document_bytes", 1_024, 100 * 1024 * 1024),
            (self.max_documents, "max_documents", 1, 1_000_000),
            (self.retention_seconds, "retention_seconds", 60, 10 * 365 * 24 * 60 * 60),
            (self.grant_ttl_seconds, "grant_ttl_seconds", 5, 300),
            (self.claim_lease_seconds, "claim_lease_seconds", 5, 300),
            (self.stream_chunk_bytes, "stream_chunk_bytes", 4 * 1024, 1024 * 1024),
        ):
            try:
                _integer(value, label, low, high)
            except VaultValidationError as exc:
                raise VaultConfigError(exc.error_code) from exc
        values = self.allowed_media_types
        if not isinstance(values, tuple) or not values or len(values) > len(DEFAULT_MEDIA_TYPES):
            raise VaultConfigError("document_vault_allowed_media_types_invalid")
        normalized: list[str] = []
        for value in values:
            try:
                selected = _media_type(value)
            except VaultValidationError as exc:
                raise VaultConfigError(exc.error_code) from exc
            if selected not in DEFAULT_MEDIA_TYPES:
                raise VaultConfigError("document_vault_media_type_not_approved")
            normalized.append(selected)
        if len(set(normalized)) != len(normalized) or tuple(sorted(normalized)) != values:
            raise VaultConfigError("document_vault_allowed_media_types_invalid")

    @classmethod
    def from_mapping(cls, config: Mapping[str, Any]) -> GovernedDocumentVaultConfig:
        if not isinstance(config, Mapping):
            raise VaultConfigError("document_vault_configuration_unavailable")
        section = config.get("governed_document_vault") or {}
        if not isinstance(section, Mapping):
            raise VaultConfigError("document_vault_configuration_invalid")
        allowed = {
            "enable",
            "max_document_bytes",
            "max_documents",
            "retention_seconds",
            "grant_ttl_seconds",
            "claim_lease_seconds",
            "stream_chunk_bytes",
            "allowed_media_types",
        }
        if any(key not in allowed for key in section):
            raise VaultConfigError("document_vault_configuration_unknown_key")
        values = dict(section)
        if "allowed_media_types" in values:
            raw = values["allowed_media_types"]
            if not isinstance(raw, list):
                raise VaultConfigError("document_vault_allowed_media_types_invalid")
            values["allowed_media_types"] = tuple(sorted(raw))
        try:
            return cls(**values)
        except TypeError as exc:
            raise VaultConfigError("document_vault_configuration_invalid") from exc


@dataclass(frozen=True, slots=True)
class GovernedDocumentRecord:
    document_ref: str
    product_area: str
    record_type: str
    safe_display_name: str
    media_type: str
    byte_size: int
    content_sha256: str
    content_revision: int
    authority_revision: int
    authority_sha256: str
    state: str
    created_at: float
    updated_at: float
    revoked_at: float | None
    retained_until: float | None


@dataclass(frozen=True, slots=True)
class DeliveryPayload:
    document_ref: str
    safe_display_name: str
    media_type: str
    content_sha256: str
    content: bytes

    def chunks(self, chunk_bytes: int) -> Iterator[bytes]:
        size = _integer(chunk_bytes, "stream_chunk_bytes", 4 * 1024, 1024 * 1024)
        for offset in range(0, len(self.content), size):
            yield self.content[offset : offset + size]


def _authority_material(
    *,
    tenant_sha256: str,
    document_ref: str,
    product_area: str,
    record_type: str,
    safe_display_name: str,
    media_type: str,
    byte_size: int,
    content_sha256: str,
    content_revision: int,
    authority_revision: int,
    state: str,
) -> dict[str, object]:
    return {
        "schema": "lightwork.governed-document-authority.v1",
        "tenant_sha256": tenant_sha256,
        "document_sha256": _text_sha256(document_ref),
        "product_area": product_area,
        "record_type": record_type,
        "safe_display_name": safe_display_name,
        "media_type": media_type,
        "byte_size": byte_size,
        "content_sha256": content_sha256,
        "content_revision": content_revision,
        "authority_revision": authority_revision,
        "state": state,
    }


class GovernedDocumentVault:
    """SQLite metadata authority plus AES-GCM sealed document blobs."""

    _schema_lock = threading.RLock()

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        config: GovernedDocumentVaultConfig,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path).expanduser().resolve()
        self.tenant_id = _tenant(tenant_id)
        self.tenant_sha256 = _text_sha256(
            "lightwork.governed-document-vault.tenant.v1:" + self.tenant_id
        )
        if type(config) is not GovernedDocumentVaultConfig or not config.enable:
            raise VaultConfigError("governed_document_vault_disabled")
        if not callable(clock):
            raise VaultConfigError("document_vault_clock_unavailable")
        self.config = config
        self._clock = clock
        self._read_only = False
        try:
            ensure_private_directory(self.path.parent)
            with self._schema_lock:
                with closing(self._connect(initializing=True)) as connection, connection:
                    self._create_schema(connection)
            ensure_private_file(self.path)
        except GovernedDocumentVaultError:
            raise
        except (OSError, PermissionError, sqlite3.DatabaseError) as exc:
            raise VaultConfigError("document_vault_store_unavailable") from exc

    @classmethod
    def operational_probe(
        cls,
        path: str | Path,
        *,
        tenant_id: str,
        config: GovernedDocumentVaultConfig,
    ) -> dict[str, object]:
        """Open and verify an already-provisioned vault without changing records.

        Integrity is evaluated through a SQLite read-only handle.  A separate
        rolled-back no-change transaction then verifies that the exact main
        database authority remains writable.  The probe never creates a vault,
        migrates its schema, or commits a domain mutation.
        """

        selected = Path(path).expanduser().resolve()
        tenant = _tenant(tenant_id)
        if type(config) is not GovernedDocumentVaultConfig or not config.enable:
            raise VaultConfigError("governed_document_vault_disabled")
        if (
            not selected.is_file()
            or not private_path_is_restricted(selected)
            or not private_path_is_restricted(selected.parent, 0o700)
        ):
            raise VaultConfigError("document_vault_store_unavailable")
        instance = cls.__new__(cls)
        instance.path = selected
        instance.tenant_id = tenant
        instance.tenant_sha256 = _text_sha256(
            "lightwork.governed-document-vault.tenant.v1:" + tenant
        )
        instance.config = config
        instance._clock = time.time
        instance._read_only = True
        integrity = instance.verify_integrity(verify_content=False)
        connection = instance._connect(read_only=False)
        try:
            connection.execute("BEGIN IMMEDIATE")
            instance._verify_meta(connection)
            instance._verify_integrity_state(connection)
            connection.execute(
                "UPDATE governed_document_integrity_state "
                "SET terminal_sha256=terminal_sha256 WHERE singleton=1"
            )
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.rollback()
        finally:
            connection.close()
        return integrity

    def _connect(
        self,
        *,
        initializing: bool = False,
        read_only: bool | None = None,
    ) -> sqlite3.Connection:
        try:
            selected_read_only = (
                self._read_only if read_only is None else read_only
            )
            target: str | Path = self.path
            uri = False
            if selected_read_only:
                target = self.path.as_uri() + "?mode=ro"
                uri = True
            connection = sqlite3.connect(
                target,
                timeout=30,
                isolation_level=None,
                uri=uri,
            )
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
            raise VaultIntegrityError("document_vault_store_invalid") from exc

    @contextmanager
    def _transaction(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_meta(connection)
            self._verify_integrity_state(connection)
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
            CREATE TABLE IF NOT EXISTS governed_document_vault_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                schema_version INTEGER NOT NULL,
                tenant_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                integrity_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS governed_documents (
                document_ref TEXT PRIMARY KEY,
                product_area TEXT NOT NULL,
                record_type TEXT NOT NULL,
                safe_display_name TEXT NOT NULL,
                media_type TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                content_sha256 TEXT NOT NULL,
                content_revision INTEGER NOT NULL,
                authority_revision INTEGER NOT NULL,
                authority_sha256 TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                revoked_at REAL,
                retained_until REAL,
                row_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS governed_document_revisions (
                document_ref TEXT NOT NULL,
                content_revision INTEGER NOT NULL,
                encrypted_content BLOB NOT NULL,
                ciphertext_sha256 TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                created_at REAL NOT NULL,
                row_sha256 TEXT NOT NULL,
                PRIMARY KEY(document_ref, content_revision),
                FOREIGN KEY(document_ref) REFERENCES governed_documents(document_ref)
            );
            CREATE TABLE IF NOT EXISTS governed_document_authorities (
                document_ref TEXT NOT NULL,
                authority_revision INTEGER NOT NULL,
                content_revision INTEGER NOT NULL,
                state TEXT NOT NULL,
                authority_sha256 TEXT NOT NULL,
                occurred_at REAL NOT NULL,
                row_sha256 TEXT NOT NULL,
                PRIMARY KEY(document_ref, authority_revision),
                FOREIGN KEY(document_ref) REFERENCES governed_documents(document_ref)
            );
            CREATE TABLE IF NOT EXISTS governed_document_grants (
                grant_sha256 TEXT PRIMARY KEY,
                claim_id TEXT NOT NULL UNIQUE,
                document_ref TEXT NOT NULL,
                authority_revision INTEGER NOT NULL,
                authority_sha256 TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                principal_sha256 TEXT NOT NULL,
                state TEXT NOT NULL,
                revision INTEGER NOT NULL,
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                claimed_at REAL,
                lease_sha256 TEXT,
                lease_until REAL,
                consumed_at REAL,
                retained_until REAL,
                row_sha256 TEXT NOT NULL,
                FOREIGN KEY(document_ref) REFERENCES governed_documents(document_ref)
            );
            CREATE TABLE IF NOT EXISTS governed_document_audit (
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                subject_sha256 TEXT NOT NULL,
                actor_sha256 TEXT NOT NULL,
                detail_sha256 TEXT NOT NULL,
                occurred_at REAL NOT NULL,
                previous_sha256 TEXT NOT NULL,
                event_sha256 TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS governed_document_tombstones (
                document_sha256 TEXT PRIMARY KEY,
                final_authority_sha256 TEXT NOT NULL,
                final_content_sha256 TEXT NOT NULL,
                purged_at REAL NOT NULL,
                tombstone_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS governed_document_integrity_anchors (
                sequence INTEGER PRIMARY KEY,
                record_kind TEXT NOT NULL,
                event_type TEXT NOT NULL,
                document_sha256 TEXT NOT NULL,
                authority_revision INTEGER NOT NULL,
                authority_sha256 TEXT NOT NULL,
                record_sha256 TEXT NOT NULL,
                audit_detail_sha256 TEXT NOT NULL,
                occurred_at REAL NOT NULL,
                previous_sha256 TEXT NOT NULL,
                anchor_sha256 TEXT NOT NULL UNIQUE,
                UNIQUE(record_kind, document_sha256, authority_revision)
            );
            CREATE TABLE IF NOT EXISTS governed_document_integrity_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                anchor_count INTEGER NOT NULL,
                terminal_sha256 TEXT NOT NULL,
                integrity_sha256 TEXT NOT NULL
            );
            """
        )
        connection.execute("BEGIN IMMEDIATE")
        try:
            meta = connection.execute(
                "SELECT * FROM governed_document_vault_meta WHERE singleton=1"
            ).fetchone()
            if meta is None:
                created = _clock_value(self._clock)
                material = {
                    "schema": "lightwork.governed-document-vault-meta.v1",
                    "schema_version": SCHEMA_VERSION,
                    "tenant_sha256": self.tenant_sha256,
                    "created_at": created,
                }
                connection.execute(
                    "INSERT INTO governed_document_vault_meta VALUES(1,?,?,?,?)",
                    (
                        SCHEMA_VERSION,
                        self.tenant_sha256,
                        created,
                        canonical_sha256(material),
                    ),
                )
                self._initialize_integrity_state(connection)
            elif meta["schema_version"] == 1:
                self._verify_meta_row(meta, expected_version=1)
                self._initialize_integrity_state(connection)
                self._backfill_integrity_anchors(connection)
                upgraded = {
                    "schema": "lightwork.governed-document-vault-meta.v1",
                    "schema_version": SCHEMA_VERSION,
                    "tenant_sha256": self.tenant_sha256,
                    "created_at": meta["created_at"],
                }
                connection.execute(
                    "UPDATE governed_document_vault_meta "
                    "SET schema_version=?,integrity_sha256=? WHERE singleton=1",
                    (SCHEMA_VERSION, canonical_sha256(upgraded)),
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        connection.executescript(
            """
            CREATE TRIGGER IF NOT EXISTS governed_document_anchor_no_update
            BEFORE UPDATE ON governed_document_integrity_anchors
            BEGIN
                SELECT RAISE(ABORT, 'governed document integrity anchors are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS governed_document_anchor_no_delete
            BEFORE DELETE ON governed_document_integrity_anchors
            BEGIN
                SELECT RAISE(ABORT, 'governed document integrity anchors are immutable');
            END;
            """
        )
        self._verify_meta(connection)
        self._verify_integrity_state(connection)

    @staticmethod
    def _integrity_state_material(
        anchor_count: int,
        terminal_sha256: str,
    ) -> dict[str, object]:
        return {
            "schema": "lightwork.governed-document-integrity-state.v1",
            "anchor_count": anchor_count,
            "terminal_sha256": terminal_sha256,
        }

    def _initialize_integrity_state(self, connection: sqlite3.Connection) -> None:
        if connection.execute(
            "SELECT 1 FROM governed_document_integrity_state WHERE singleton=1"
        ).fetchone() is not None:
            return
        material = self._integrity_state_material(0, GENESIS_SHA256)
        connection.execute(
            "INSERT INTO governed_document_integrity_state VALUES(1,0,?,?)",
            (GENESIS_SHA256, canonical_sha256(material)),
        )

    def _verify_integrity_state(self, connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM governed_document_integrity_state WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise VaultIntegrityError("document_vault_completeness_state_missing")
        count = row["anchor_count"]
        terminal = row["terminal_sha256"]
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            or not isinstance(terminal, str)
            or _DIGEST_RE.fullmatch(terminal) is None
            or not hmac.compare_digest(
                row["integrity_sha256"],
                canonical_sha256(self._integrity_state_material(count, terminal)),
            )
        ):
            raise VaultIntegrityError("document_vault_completeness_state_invalid")
        observed = connection.execute(
            "SELECT COUNT(*),MAX(sequence) FROM governed_document_integrity_anchors"
        ).fetchone()
        last = connection.execute(
            "SELECT anchor_sha256 FROM governed_document_integrity_anchors "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        observed_terminal = GENESIS_SHA256 if last is None else last[0]
        if (
            observed is None
            or observed[0] != count
            or (count == 0 and observed[1] is not None)
            or (count > 0 and observed[1] != count)
            or not hmac.compare_digest(observed_terminal, terminal)
        ):
            raise VaultIntegrityError("document_vault_completeness_state_invalid")
        return row

    @staticmethod
    def _integrity_anchor_material(row: Mapping[str, Any]) -> dict[str, object]:
        return {
            "schema": "lightwork.governed-document-integrity-anchor.v1",
            **{
                key: row[key]
                for key in (
                    "sequence",
                    "record_kind",
                    "event_type",
                    "document_sha256",
                    "authority_revision",
                    "authority_sha256",
                    "record_sha256",
                    "audit_detail_sha256",
                    "occurred_at",
                    "previous_sha256",
                )
            },
        }

    def _append_integrity_anchor(
        self,
        connection: sqlite3.Connection,
        *,
        record_kind: str,
        event_type: str,
        document_sha256: str,
        authority_revision: int,
        authority_sha256: str,
        record_sha256: str,
        audit_detail_sha256: str,
        occurred_at: float,
    ) -> None:
        state = self._verify_integrity_state(connection)
        sequence = int(state["anchor_count"]) + 1
        prior = str(state["terminal_sha256"])
        row = {
            "sequence": sequence,
            "record_kind": record_kind,
            "event_type": event_type,
            "document_sha256": document_sha256,
            "authority_revision": authority_revision,
            "authority_sha256": authority_sha256,
            "record_sha256": record_sha256,
            "audit_detail_sha256": audit_detail_sha256,
            "occurred_at": occurred_at,
            "previous_sha256": prior,
        }
        anchor_sha256 = canonical_sha256(self._integrity_anchor_material(row))
        connection.execute(
            "INSERT INTO governed_document_integrity_anchors "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                sequence,
                record_kind,
                event_type,
                document_sha256,
                authority_revision,
                authority_sha256,
                record_sha256,
                audit_detail_sha256,
                occurred_at,
                prior,
                anchor_sha256,
            ),
        )
        state_material = self._integrity_state_material(sequence, anchor_sha256)
        connection.execute(
            "UPDATE governed_document_integrity_state "
            "SET anchor_count=?,terminal_sha256=?,integrity_sha256=? "
            "WHERE singleton=1",
            (sequence, anchor_sha256, canonical_sha256(state_material)),
        )

    def _backfill_integrity_anchors(self, connection: sqlite3.Connection) -> None:
        if connection.execute(
            "SELECT 1 FROM governed_document_integrity_anchors LIMIT 1"
        ).fetchone() is not None:
            raise VaultIntegrityError("document_vault_completeness_migration_invalid")
        documents = {
            row["document_ref"]: row
            for row in connection.execute("SELECT * FROM governed_documents")
        }
        tombstones = {
            row["document_sha256"]: row
            for row in connection.execute("SELECT * FROM governed_document_tombstones")
        }
        for row in connection.execute(
            "SELECT * FROM governed_document_authorities "
            "ORDER BY document_ref,authority_revision"
        ):
            head = documents.get(row["document_ref"])
            if head is None:
                raise VaultIntegrityError("document_vault_completeness_migration_invalid")
            event_type = _INGEST_EVENT if row["authority_revision"] == 1 else _REVOKE_EVENT
            detail = (
                {
                    "authority_sha256": row["authority_sha256"],
                    "content_sha256": head["content_sha256"],
                }
                if row["authority_revision"] == 1
                else {
                    "authority_revision": row["authority_revision"],
                    "authority_sha256": row["authority_sha256"],
                }
            )
            self._append_integrity_anchor(
                connection,
                record_kind="authority",
                event_type=event_type,
                document_sha256=_text_sha256(row["document_ref"]),
                authority_revision=row["authority_revision"],
                authority_sha256=row["authority_sha256"],
                record_sha256=row["row_sha256"],
                audit_detail_sha256=canonical_sha256(detail),
                occurred_at=row["occurred_at"],
            )
        for row in sorted(tombstones.values(), key=lambda item: item["document_sha256"]):
            self._append_integrity_anchor(
                connection,
                record_kind="legacy_tombstone",
                event_type=_PURGE_EVENT,
                document_sha256=row["document_sha256"],
                authority_revision=0,
                authority_sha256=row["final_authority_sha256"],
                record_sha256=row["tombstone_sha256"],
                audit_detail_sha256=canonical_sha256(
                    {"tombstone_sha256": row["tombstone_sha256"]}
                ),
                occurred_at=row["purged_at"],
            )

    def _verify_meta_row(self, row: Mapping[str, Any], *, expected_version: int) -> None:
        material = {
            "schema": "lightwork.governed-document-vault-meta.v1",
            "schema_version": row["schema_version"],
            "tenant_sha256": row["tenant_sha256"],
            "created_at": row["created_at"],
        }
        if (
            row["schema_version"] != expected_version
            or not hmac.compare_digest(row["tenant_sha256"], self.tenant_sha256)
            or not hmac.compare_digest(
                row["integrity_sha256"], canonical_sha256(material)
            )
        ):
            raise VaultIntegrityError("document_vault_meta_invalid")

    def _verify_meta(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT * FROM governed_document_vault_meta WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise VaultIntegrityError("document_vault_meta_missing")
        self._verify_meta_row(row, expected_version=SCHEMA_VERSION)

    @staticmethod
    def _document_material(row: Mapping[str, Any]) -> dict[str, object]:
        return {
            "schema": "lightwork.governed-document-head.v1",
            **{key: row[key] for key in (
                "document_ref", "product_area", "record_type", "safe_display_name",
                "media_type", "byte_size", "content_sha256", "content_revision",
                "authority_revision", "authority_sha256", "state", "created_at",
                "updated_at", "revoked_at", "retained_until",
            )},
        }

    @staticmethod
    def _grant_material(row: Mapping[str, Any]) -> dict[str, object]:
        return {
            "schema": "lightwork.governed-document-delivery-grant-record.v1",
            **{key: row[key] for key in (
                "grant_sha256", "claim_id", "document_ref", "authority_revision",
                "authority_sha256", "content_sha256", "principal_sha256", "state",
                "revision", "issued_at", "expires_at", "claimed_at", "lease_sha256",
                "lease_until", "consumed_at", "retained_until",
            )},
        }

    @staticmethod
    def _authority_material(row: Mapping[str, Any]) -> dict[str, object]:
        return {
            "schema": "lightwork.governed-document-authority-record.v1",
            **{
                key: row[key]
                for key in (
                    "document_ref",
                    "authority_revision",
                    "content_revision",
                    "state",
                    "authority_sha256",
                    "occurred_at",
                )
            },
        }

    @staticmethod
    def _tombstone_material(row: Mapping[str, Any]) -> dict[str, object]:
        return {
            "schema": "lightwork.governed-document-tombstone.v1",
            **{
                key: row[key]
                for key in (
                    "document_sha256",
                    "final_authority_sha256",
                    "final_content_sha256",
                    "purged_at",
                )
            },
        }

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        subject_sha256: str,
        actor_sha256: str,
        detail: object,
        occurred_at: float,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence,event_sha256 FROM governed_document_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        prior = GENESIS_SHA256 if previous is None else str(previous["event_sha256"])
        material = {
            "schema": "lightwork.governed-document-vault-audit.v1",
            "sequence": sequence,
            "event_type": event_type,
            "subject_sha256": subject_sha256,
            "actor_sha256": actor_sha256,
            "detail_sha256": canonical_sha256(detail),
            "occurred_at": occurred_at,
            "previous_sha256": prior,
        }
        connection.execute(
            "INSERT INTO governed_document_audit VALUES(?,?,?,?,?,?,?,?)",
            (
                sequence,
                event_type,
                subject_sha256,
                actor_sha256,
                material["detail_sha256"],
                occurred_at,
                prior,
                canonical_sha256(material),
            ),
        )

    def _count_documents(self, connection: sqlite3.Connection) -> int:
        return int(connection.execute("SELECT COUNT(*) FROM governed_documents").fetchone()[0])

    def ingest(
        self,
        content: bytes,
        *,
        principal_ref: str,
        product_area: str,
        record_type: str,
        safe_display_name: str,
        media_type: str,
    ) -> GovernedDocumentRecord:
        if not isinstance(content, bytes) or not 1 <= len(content) <= self.config.max_document_bytes:
            raise VaultValidationError("document_vault_content_size_invalid")
        principal = _principal(principal_ref)
        area = _product_area(product_area)
        kind = _record_type(record_type)
        display = _display_name(safe_display_name)
        selected_media = _media_type(media_type)
        if selected_media not in self.config.allowed_media_types:
            raise VaultValidationError("document_vault_media_type_not_approved")
        now = _clock_value(self._clock)
        document_ref = "doc_" + secrets.token_urlsafe(24)
        content_sha = hashlib.sha256(content).hexdigest()
        authority = _authority_material(
            tenant_sha256=self.tenant_sha256,
            document_ref=document_ref,
            product_area=area,
            record_type=kind,
            safe_display_name=display,
            media_type=selected_media,
            byte_size=len(content),
            content_sha256=content_sha,
            content_revision=1,
            authority_revision=1,
            state="active",
        )
        authority_sha = canonical_sha256(authority)
        try:
            from .crypto_at_rest import seal

            with tenant_scope(tenant=self.tenant_id):
                encrypted = seal(content)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise VaultConfigError("document_vault_encryption_unavailable") from exc
        ciphertext_sha = hashlib.sha256(encrypted).hexdigest()
        head = {
            "document_ref": document_ref,
            "product_area": area,
            "record_type": kind,
            "safe_display_name": display,
            "media_type": selected_media,
            "byte_size": len(content),
            "content_sha256": content_sha,
            "content_revision": 1,
            "authority_revision": 1,
            "authority_sha256": authority_sha,
            "state": "active",
            "created_at": now,
            "updated_at": now,
            "revoked_at": None,
            "retained_until": None,
        }
        revision_material = {
            "schema": "lightwork.governed-document-content-revision.v1",
            "document_ref": document_ref,
            "content_revision": 1,
            "ciphertext_sha256": ciphertext_sha,
            "content_sha256": content_sha,
            "byte_size": len(content),
            "created_at": now,
        }
        authority_record = {
            "document_ref": document_ref,
            "authority_revision": 1,
            "content_revision": 1,
            "state": "active",
            "authority_sha256": authority_sha,
            "occurred_at": now,
        }
        authority_record_sha = canonical_sha256(
            self._authority_material(authority_record)
        )
        audit_detail = {
            "authority_sha256": authority_sha,
            "content_sha256": content_sha,
        }
        actor_sha = _principal_sha256(self.tenant_sha256, principal)
        with self._transaction() as connection:
            if self._count_documents(connection) >= self.config.max_documents:
                raise VaultConflict("document_vault_capacity_exceeded")
            connection.execute(
                "INSERT INTO governed_documents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (*head.values(), canonical_sha256(self._document_material(head))),
            )
            connection.execute(
                "INSERT INTO governed_document_revisions VALUES(?,?,?,?,?,?,?,?)",
                (
                    document_ref,
                    1,
                    encrypted,
                    ciphertext_sha,
                    content_sha,
                    len(content),
                    now,
                    canonical_sha256(revision_material),
                ),
            )
            connection.execute(
                "INSERT INTO governed_document_authorities VALUES(?,?,?,?,?,?,?)",
                (
                    document_ref,
                    1,
                    1,
                    "active",
                    authority_sha,
                    now,
                    authority_record_sha,
                ),
            )
            self._append_integrity_anchor(
                connection,
                record_kind="authority",
                event_type=_INGEST_EVENT,
                document_sha256=_text_sha256(document_ref),
                authority_revision=1,
                authority_sha256=authority_sha,
                record_sha256=authority_record_sha,
                audit_detail_sha256=canonical_sha256(audit_detail),
                occurred_at=now,
            )
            self._append_audit(
                connection,
                event_type=_INGEST_EVENT,
                subject_sha256=_text_sha256(document_ref),
                actor_sha256=actor_sha,
                detail=audit_detail,
                occurred_at=now,
            )
        return GovernedDocumentRecord(**head)

    def _head_on(self, connection: sqlite3.Connection, document_ref: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM governed_documents WHERE document_ref=?", (document_ref,)
        ).fetchone()
        if row is None:
            raise VaultNotFound("document_vault_document_not_found")
        self._validate_document_row(row)
        return row

    def _validate_document_row(self, row: Mapping[str, Any]) -> None:
        """Validate the selected head without reading a different revision."""
        if not hmac.compare_digest(
            row["row_sha256"], canonical_sha256(self._document_material(row))
        ):
            raise VaultIntegrityError("document_vault_document_integrity_invalid")

    @staticmethod
    def _record(row: Mapping[str, Any]) -> GovernedDocumentRecord:
        return GovernedDocumentRecord(
            **{key: row[key] for key in GovernedDocumentRecord.__dataclass_fields__}
        )

    def get(self, document_ref: str) -> GovernedDocumentRecord:
        identifier = _identifier(document_ref, "document_ref")
        with closing(self._connect()) as connection, connection:
            self._verify_meta(connection)
            return self._record(self._head_on(connection, identifier))

    def list_documents(self, *, state: str | None = None, limit: int = 100) -> list[GovernedDocumentRecord]:
        """List integrity-checked heads from one read snapshot, not grants.

        A subsequent authority resolution or grant consumption still reads the
        current authoritative record; a listing never authorizes delivery.
        """
        selected_limit = _integer(limit, "limit", 1, 500)
        if state not in {None, "active", "revoked"}:
            raise VaultValidationError("document_vault_state_invalid")
        sql = "SELECT * FROM governed_documents"
        params: list[object] = []
        if state is not None:
            sql += " WHERE state=?"
            params.append(state)
        sql += " ORDER BY updated_at DESC, document_ref LIMIT ?"
        params.append(selected_limit)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN")
            self._verify_meta(connection)
            rows = connection.execute(sql, params).fetchall()
            for row in rows:
                self._validate_document_row(row)
            return [self._record(row) for row in rows]

    def history_window(self, *, offset=0, after=None, before=None, oldest=False):
        """Metadata heads beyond the ordinary listing cap, never delivery grants."""
        from .metadata_history import sql_window
        where, params = ["1=1"], []
        for value, operator in ((after, ">="), (before, "<")):
            if value is not None:
                where.append("created_at" + operator + "?")
                params.append(value)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN")
            self._verify_meta(connection)
            result = sql_window(connection.execute, table="governed_documents", columns="*",
                                stamp="document_ref,row_sha256", where=" AND ".join(where), params=tuple(params),
                                order="created_at " + ("ASC" if oldest else "DESC") + ",document_ref", offset=offset)
            for row in result.rows:
                self._validate_document_row(row)
            result.rows = [self._record(row) for row in result.rows]
            return result

    def context_record_count(self) -> int:
        """Return the exact current-head count without scanning document bodies."""

        with closing(self._connect()) as connection, connection:
            self._verify_meta(connection)
            row = connection.execute(
                "SELECT COUNT(*) FROM governed_documents"
            ).fetchone()
        if row is None or not isinstance(row[0], int) or row[0] < 0:
            raise VaultIntegrityError("document_vault_record_count_invalid")
        return int(row[0])

    def resolve_authority(
        self,
        tenant_id: str,
        principal_ref: str,
        document_ref: str,
    ) -> document_access.DocumentAuthority:
        if not text_equals(_tenant(tenant_id), self.tenant_id):
            raise VaultNotFound("document_vault_document_not_found")
        principal = _principal(principal_ref)
        record = self.get(document_ref)
        return document_access.DocumentAuthority(
            tenant_id=self.tenant_id,
            principal_ref=principal,
            document_ref=record.document_ref,
            product_area=record.product_area,
            record_type=record.record_type,
            safe_display_name=record.safe_display_name,
            media_type=record.media_type,
            byte_size=record.byte_size,
            content_sha256=record.content_sha256,
            authority_revision=record.authority_revision,
            authority_sha256=record.authority_sha256,
            download_allowed=record.state == "active",
        )

    def revoke(
        self,
        document_ref: str,
        *,
        principal_ref: str,
        expected_revision: int,
    ) -> GovernedDocumentRecord:
        identifier = _identifier(document_ref, "document_ref")
        principal = _principal(principal_ref)
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        now = _clock_value(self._clock)
        actor_sha = _principal_sha256(self.tenant_sha256, principal)
        with self._transaction() as connection:
            current = self._head_on(connection, identifier)
            if current["authority_revision"] != expected:
                raise VaultConflict("document_vault_revision_changed")
            if current["state"] != "active":
                raise VaultConflict("document_vault_document_not_active")
            authority_revision = expected + 1
            authority = _authority_material(
                tenant_sha256=self.tenant_sha256,
                document_ref=identifier,
                product_area=current["product_area"],
                record_type=current["record_type"],
                safe_display_name=current["safe_display_name"],
                media_type=current["media_type"],
                byte_size=current["byte_size"],
                content_sha256=current["content_sha256"],
                content_revision=current["content_revision"],
                authority_revision=authority_revision,
                state="revoked",
            )
            authority_sha = canonical_sha256(authority)
            head = dict(current)
            head.update(
                authority_revision=authority_revision,
                authority_sha256=authority_sha,
                state="revoked",
                updated_at=now,
                revoked_at=now,
                retained_until=now + self.config.retention_seconds,
            )
            head.pop("row_sha256", None)
            result = connection.execute(
                """UPDATE governed_documents SET authority_revision=?,authority_sha256=?,
                   state='revoked',updated_at=?,revoked_at=?,retained_until=?,row_sha256=?
                   WHERE document_ref=? AND authority_revision=? AND state='active'""",
                (
                    authority_revision,
                    authority_sha,
                    now,
                    now,
                    head["retained_until"],
                    canonical_sha256(self._document_material(head)),
                    identifier,
                    expected,
                ),
            )
            if result.rowcount != 1:
                raise VaultConflict("document_vault_revision_changed")
            authority_record = {
                "document_ref": identifier,
                "authority_revision": authority_revision,
                "content_revision": current["content_revision"],
                "state": "revoked",
                "authority_sha256": authority_sha,
                "occurred_at": now,
            }
            authority_record_sha = canonical_sha256(
                self._authority_material(authority_record)
            )
            audit_detail = {
                "authority_revision": authority_revision,
                "authority_sha256": authority_sha,
            }
            connection.execute(
                "INSERT INTO governed_document_authorities VALUES(?,?,?,?,?,?,?)",
                (
                    identifier,
                    authority_revision,
                    current["content_revision"],
                    "revoked",
                    authority_sha,
                    now,
                    authority_record_sha,
                ),
            )
            self._append_integrity_anchor(
                connection,
                record_kind="authority",
                event_type=_REVOKE_EVENT,
                document_sha256=_text_sha256(identifier),
                authority_revision=authority_revision,
                authority_sha256=authority_sha,
                record_sha256=authority_record_sha,
                audit_detail_sha256=canonical_sha256(audit_detail),
                occurred_at=now,
            )
            rows = connection.execute(
                "SELECT * FROM governed_document_grants WHERE document_ref=? AND state IN ('issued','claimed')",
                (identifier,),
            ).fetchall()
            for grant in rows:
                updated = dict(grant)
                updated.update(
                    state="revoked",
                    revision=grant["revision"] + 1,
                    retained_until=now + self.config.retention_seconds,
                    lease_sha256=None,
                    lease_until=None,
                )
                updated.pop("row_sha256", None)
                connection.execute(
                    """UPDATE governed_document_grants SET state='revoked',revision=?,
                    lease_sha256=NULL,lease_until=NULL,retained_until=?,row_sha256=?
                    WHERE grant_sha256=? AND revision=?""",
                    (
                        updated["revision"],
                        updated["retained_until"],
                        canonical_sha256(self._grant_material(updated)),
                        grant["grant_sha256"],
                        grant["revision"],
                    ),
                )
            self._append_audit(
                connection,
                event_type=_REVOKE_EVENT,
                subject_sha256=_text_sha256(identifier),
                actor_sha256=actor_sha,
                detail=audit_detail,
                occurred_at=now,
            )
            return GovernedDocumentRecord(**head)

    def issue_delivery_grant(
        self, claim: document_access.DeliveryClaim
    ) -> document_access.DeliveryGrant:
        if type(claim) is not document_access.DeliveryClaim:
            raise VaultValidationError("document_vault_delivery_claim_invalid")
        if claim.tenant_id != self.tenant_id:
            raise VaultPermissionDenied("document_vault_delivery_claim_binding_invalid")
        principal = _principal(claim.principal_ref)
        now = _clock_value(self._clock)
        expires_at = min(now + self.config.grant_ttl_seconds, claim.grant_expires_at)
        if expires_at <= now:
            raise VaultConflict("document_vault_delivery_claim_expired")
        raw = GRANT_PREFIX + secrets.token_urlsafe(32)
        grant_sha = _grant_sha256(raw)
        principal_sha = _principal_sha256(self.tenant_sha256, principal)
        with self._transaction() as connection:
            document = self._head_on(connection, claim.document_ref)
            if (
                document["state"] != "active"
                or document["authority_revision"] != claim.authority_revision
                or not hmac.compare_digest(document["authority_sha256"], claim.authority_sha256)
                or not hmac.compare_digest(document["content_sha256"], claim.content_sha256)
                or document["byte_size"] != claim.byte_size
                or document["media_type"] != claim.media_type
                or document["safe_display_name"] != claim.safe_display_name
            ):
                raise VaultConflict("document_vault_delivery_claim_authority_changed")
            if connection.execute(
                "SELECT 1 FROM governed_document_grants WHERE claim_id=?", (claim.claim_id,)
            ).fetchone() is not None:
                raise VaultConflict("document_vault_delivery_claim_replayed")
            row = {
                "grant_sha256": grant_sha,
                "claim_id": claim.claim_id,
                "document_ref": claim.document_ref,
                "authority_revision": claim.authority_revision,
                "authority_sha256": claim.authority_sha256,
                "content_sha256": claim.content_sha256,
                "principal_sha256": principal_sha,
                "state": "issued",
                "revision": 1,
                "issued_at": now,
                "expires_at": expires_at,
                "claimed_at": None,
                "lease_sha256": None,
                "lease_until": None,
                "consumed_at": None,
                "retained_until": None,
            }
            connection.execute(
                "INSERT INTO governed_document_grants VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (*row.values(), canonical_sha256(self._grant_material(row))),
            )
            self._append_audit(
                connection,
                event_type="administration.governed_document.delivery_grant_issued",
                subject_sha256=grant_sha,
                actor_sha256=principal_sha,
                detail={
                    "document_sha256": _text_sha256(claim.document_ref),
                    "authority_sha256": claim.authority_sha256,
                    "expires_at": expires_at,
                },
                occurred_at=now,
            )
        return document_access.DeliveryGrant(grant=raw, expires_at=expires_at)

    def _grant_on(self, connection: sqlite3.Connection, grant_sha: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM governed_document_grants WHERE grant_sha256=?", (grant_sha,)
        ).fetchone()
        if row is None:
            raise VaultNotFound("document_vault_delivery_grant_not_found")
        if not hmac.compare_digest(row["row_sha256"], canonical_sha256(self._grant_material(row))):
            raise VaultIntegrityError("document_vault_delivery_grant_integrity_invalid")
        return row

    def consume_delivery_grant(
        self,
        raw_grant: str,
        *,
        principal_ref: str,
    ) -> DeliveryPayload:
        selected_grant = _grant(raw_grant)
        principal = _principal(principal_ref)
        principal_sha = _principal_sha256(self.tenant_sha256, principal)
        grant_sha = _grant_sha256(selected_grant)
        now = _clock_value(self._clock)
        lease = secrets.token_urlsafe(32)
        lease_sha = _text_sha256("lightwork.governed-document-vault.lease.v1:" + lease)
        with self._transaction() as connection:
            row = self._grant_on(connection, grant_sha)
            if not hmac.compare_digest(row["principal_sha256"], principal_sha):
                raise VaultPermissionDenied("document_vault_delivery_grant_binding_invalid")
            if row["state"] != "issued":
                raise VaultConflict("document_vault_delivery_grant_replayed")
            if row["expires_at"] <= now:
                raise VaultConflict("document_vault_delivery_grant_expired")
            document = self._head_on(connection, row["document_ref"])
            if (
                document["state"] != "active"
                or document["authority_revision"] != row["authority_revision"]
                or not hmac.compare_digest(document["authority_sha256"], row["authority_sha256"])
                or not hmac.compare_digest(document["content_sha256"], row["content_sha256"])
            ):
                raise VaultConflict("document_vault_delivery_authority_changed")
            claimed = dict(row)
            claimed.update(
                state="claimed",
                revision=row["revision"] + 1,
                claimed_at=now,
                lease_sha256=lease_sha,
                lease_until=min(row["expires_at"], now + self.config.claim_lease_seconds),
            )
            claimed.pop("row_sha256", None)
            result = connection.execute(
                """UPDATE governed_document_grants SET state='claimed',revision=?,claimed_at=?,
                lease_sha256=?,lease_until=?,row_sha256=? WHERE grant_sha256=?
                AND revision=? AND state='issued'""",
                (
                    claimed["revision"],
                    now,
                    lease_sha,
                    claimed["lease_until"],
                    canonical_sha256(self._grant_material(claimed)),
                    grant_sha,
                    row["revision"],
                ),
            )
            if result.rowcount != 1:
                raise VaultConflict("document_vault_delivery_grant_replayed")
            revision = connection.execute(
                """SELECT * FROM governed_document_revisions
                   WHERE document_ref=? AND content_revision=?""",
                (document["document_ref"], document["content_revision"]),
            ).fetchone()
            if revision is None:
                raise VaultIntegrityError("document_vault_content_revision_missing")
            revision_material = {
                "schema": "lightwork.governed-document-content-revision.v1",
                "document_ref": revision["document_ref"],
                "content_revision": revision["content_revision"],
                "ciphertext_sha256": revision["ciphertext_sha256"],
                "content_sha256": revision["content_sha256"],
                "byte_size": revision["byte_size"],
                "created_at": revision["created_at"],
            }
            ciphertext = bytes(revision["encrypted_content"])
            if (
                not hmac.compare_digest(revision["row_sha256"], canonical_sha256(revision_material))
                or not hmac.compare_digest(
                    revision["ciphertext_sha256"], hashlib.sha256(ciphertext).hexdigest()
                )
            ):
                raise VaultIntegrityError("document_vault_content_integrity_invalid")
        try:
            from .crypto_at_rest import unseal

            with tenant_scope(tenant=self.tenant_id):
                content = unseal(ciphertext)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise VaultIntegrityError("document_vault_content_decryption_failed") from exc
        if (
            len(content) != document["byte_size"]
            or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), document["content_sha256"])
        ):
            raise VaultIntegrityError("document_vault_content_integrity_invalid")
        completed = _clock_value(self._clock)
        with self._transaction() as connection:
            current = self._grant_on(connection, grant_sha)
            if (
                current["state"] != "claimed"
                or current["revision"] != claimed["revision"]
                or not isinstance(current["lease_sha256"], str)
                or not hmac.compare_digest(current["lease_sha256"], lease_sha)
                or current["expires_at"] <= completed
            ):
                raise VaultConflict("document_vault_delivery_claim_changed")
            consumed = dict(current)
            consumed.update(
                state="consumed",
                revision=current["revision"] + 1,
                consumed_at=completed,
                lease_sha256=None,
                lease_until=None,
                retained_until=completed + self.config.retention_seconds,
            )
            consumed.pop("row_sha256", None)
            result = connection.execute(
                """UPDATE governed_document_grants SET state='consumed',revision=?,consumed_at=?,
                lease_sha256=NULL,lease_until=NULL,retained_until=?,row_sha256=?
                WHERE grant_sha256=? AND revision=? AND state='claimed' AND lease_sha256=?""",
                (
                    consumed["revision"],
                    completed,
                    consumed["retained_until"],
                    canonical_sha256(self._grant_material(consumed)),
                    grant_sha,
                    current["revision"],
                    lease_sha,
                ),
            )
            if result.rowcount != 1:
                raise VaultConflict("document_vault_delivery_claim_changed")
            self._append_audit(
                connection,
                event_type="administration.governed_document.delivery_grant_consumed",
                subject_sha256=grant_sha,
                actor_sha256=principal_sha,
                detail={
                    "document_sha256": _text_sha256(document["document_ref"]),
                    "content_sha256": document["content_sha256"],
                },
                occurred_at=completed,
            )
        return DeliveryPayload(
            document_ref=document["document_ref"],
            safe_display_name=document["safe_display_name"],
            media_type=document["media_type"],
            content_sha256=document["content_sha256"],
            content=content,
        )

    def reconcile(self, *, limit: int = 500) -> dict[str, int]:
        selected_limit = _integer(limit, "limit", 1, 1_000)
        now = _clock_value(self._clock)
        expired = recovered = purged = 0
        with self._transaction() as connection:
            rows = connection.execute(
                """SELECT * FROM governed_document_grants
                WHERE (state='claimed' AND lease_until IS NOT NULL AND lease_until<=?)
                   OR (state IN ('issued','claimed') AND expires_at<=?)
                   OR (state IN ('consumed','revoked','expired')
                       AND retained_until IS NOT NULL AND retained_until<=?)
                ORDER BY issued_at LIMIT ?""",
                (now, now, now, selected_limit),
            ).fetchall()
            for row in rows:
                updated = dict(row)
                event = None
                if row["state"] == "claimed" and row["lease_until"] <= now < row["expires_at"]:
                    updated.update(
                        state="issued",
                        revision=row["revision"] + 1,
                        claimed_at=None,
                        lease_sha256=None,
                        lease_until=None,
                    )
                    recovered += 1
                    event = "administration.governed_document.delivery_claim_recovered"
                elif row["state"] in {"issued", "claimed"} and row["expires_at"] <= now:
                    updated.update(
                        state="expired",
                        revision=row["revision"] + 1,
                        lease_sha256=None,
                        lease_until=None,
                        retained_until=now + self.config.retention_seconds,
                    )
                    expired += 1
                    event = "administration.governed_document.delivery_grant_expired"
                elif (
                    row["state"] in {"consumed", "revoked", "expired"}
                    and row["retained_until"] is not None
                    and row["retained_until"] <= now
                ):
                    connection.execute(
                        "DELETE FROM governed_document_grants WHERE grant_sha256=? AND revision=?",
                        (row["grant_sha256"], row["revision"]),
                    )
                    purged += 1
                    continue
                if event is None:
                    continue
                updated.pop("row_sha256", None)
                connection.execute(
                    """UPDATE governed_document_grants SET state=?,revision=?,claimed_at=?,
                    lease_sha256=?,lease_until=?,retained_until=?,row_sha256=?
                    WHERE grant_sha256=? AND revision=?""",
                    (
                        updated["state"],
                        updated["revision"],
                        updated["claimed_at"],
                        updated["lease_sha256"],
                        updated["lease_until"],
                        updated["retained_until"],
                        canonical_sha256(self._grant_material(updated)),
                        row["grant_sha256"],
                        row["revision"],
                    ),
                )
                self._append_audit(
                    connection,
                    event_type=event,
                    subject_sha256=row["grant_sha256"],
                    actor_sha256=self.tenant_sha256,
                    detail={"prior_state": row["state"], "new_state": updated["state"]},
                    occurred_at=now,
                )
        return {"expired": expired, "recovered": recovered, "purged": purged}

    def purge_document(
        self,
        document_ref: str,
        *,
        principal_ref: str,
        expected_revision: int,
    ) -> dict[str, object]:
        identifier = _identifier(document_ref, "document_ref")
        principal = _principal(principal_ref)
        expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        now = _clock_value(self._clock)
        with self._transaction() as connection:
            row = self._head_on(connection, identifier)
            if row["authority_revision"] != expected:
                raise VaultConflict("document_vault_revision_changed")
            if row["state"] != "revoked" or row["retained_until"] is None or row["retained_until"] > now:
                raise VaultConflict("document_vault_retention_active")
            active_grants = connection.execute(
                "SELECT 1 FROM governed_document_grants WHERE document_ref=? AND state IN ('issued','claimed')",
                (identifier,),
            ).fetchone()
            if active_grants is not None:
                raise VaultConflict("document_vault_delivery_grant_active")
            tombstone = {
                "document_sha256": _text_sha256(identifier),
                "final_authority_sha256": row["authority_sha256"],
                "final_content_sha256": row["content_sha256"],
                "purged_at": now,
            }
            tombstone_sha = canonical_sha256(self._tombstone_material(tombstone))
            connection.execute("DELETE FROM governed_document_grants WHERE document_ref=?", (identifier,))
            connection.execute("DELETE FROM governed_document_authorities WHERE document_ref=?", (identifier,))
            connection.execute("DELETE FROM governed_document_revisions WHERE document_ref=?", (identifier,))
            connection.execute("DELETE FROM governed_documents WHERE document_ref=?", (identifier,))
            connection.execute(
                "INSERT INTO governed_document_tombstones VALUES(?,?,?,?,?)",
                (
                    tombstone["document_sha256"],
                    tombstone["final_authority_sha256"],
                    tombstone["final_content_sha256"],
                    now,
                    tombstone_sha,
                ),
            )
            audit_detail = {"tombstone_sha256": tombstone_sha}
            self._append_integrity_anchor(
                connection,
                record_kind="tombstone",
                event_type=_PURGE_EVENT,
                document_sha256=tombstone["document_sha256"],
                authority_revision=expected,
                authority_sha256=tombstone["final_authority_sha256"],
                record_sha256=tombstone_sha,
                audit_detail_sha256=canonical_sha256(audit_detail),
                occurred_at=now,
            )
            self._append_audit(
                connection,
                event_type=_PURGE_EVENT,
                subject_sha256=tombstone["document_sha256"],
                actor_sha256=_principal_sha256(self.tenant_sha256, principal),
                detail=audit_detail,
                occurred_at=now,
            )
        return {
            "schema": "lightwork.governed-document-tombstone.v1",
            **tombstone,
            "tombstone_sha256": tombstone_sha,
        }

    def list_audit(self, *, limit: int = 100) -> list[dict[str, object]]:
        selected = _integer(limit, "limit", 1, 1_000)
        with closing(self._connect()) as connection, connection:
            self._verify_meta(connection)
            return [dict(row) for row in connection.execute(
                "SELECT * FROM governed_document_audit ORDER BY sequence DESC LIMIT ?",
                (selected,),
            ).fetchall()]

    def verify_integrity(  # noqa: C901 - complete closed-schema forensic walk
        self,
        *,
        verify_content: bool = True,
    ) -> dict[str, object]:
        if type(verify_content) is not bool:
            raise VaultValidationError("document_vault_verify_content_invalid")
        documents = revisions = authorities = grants = tombstones = events = 0
        anchor_count = 0
        with closing(self._connect()) as connection, connection:
            self._verify_meta(connection)
            integrity_state = self._verify_integrity_state(connection)
            document_rows: dict[str, sqlite3.Row] = {}
            documents_by_sha: dict[str, sqlite3.Row] = {}
            for row in connection.execute(
                "SELECT * FROM governed_documents ORDER BY document_ref"
            ):
                self._head_on(connection, row["document_ref"])
                document_sha = _text_sha256(row["document_ref"])
                if document_sha in documents_by_sha:
                    raise VaultIntegrityError(
                        "document_vault_document_integrity_invalid"
                    )
                document_rows[row["document_ref"]] = row
                documents_by_sha[document_sha] = row
                documents += 1
            revision_rows: dict[tuple[str, int], sqlite3.Row] = {}
            for row in connection.execute(
                "SELECT * FROM governed_document_revisions ORDER BY document_ref,content_revision"
            ):
                ciphertext = bytes(row["encrypted_content"])
                material = {
                    "schema": "lightwork.governed-document-content-revision.v1",
                    "document_ref": row["document_ref"],
                    "content_revision": row["content_revision"],
                    "ciphertext_sha256": row["ciphertext_sha256"],
                    "content_sha256": row["content_sha256"],
                    "byte_size": row["byte_size"],
                    "created_at": row["created_at"],
                }
                if (
                    not hmac.compare_digest(row["row_sha256"], canonical_sha256(material))
                    or not hmac.compare_digest(
                        row["ciphertext_sha256"], hashlib.sha256(ciphertext).hexdigest()
                    )
                ):
                    raise VaultIntegrityError("document_vault_content_integrity_invalid")
                if verify_content:
                    try:
                        from .crypto_at_rest import unseal

                        with tenant_scope(tenant=self.tenant_id):
                            plaintext = unseal(ciphertext)
                    except Exception as exc:
                        raise VaultIntegrityError("document_vault_content_decryption_failed") from exc
                    if (
                        len(plaintext) != row["byte_size"]
                        or not hmac.compare_digest(
                            hashlib.sha256(plaintext).hexdigest(), row["content_sha256"]
                        )
                    ):
                        raise VaultIntegrityError("document_vault_content_integrity_invalid")
                key = (row["document_ref"], row["content_revision"])
                if key in revision_rows:
                    raise VaultIntegrityError("document_vault_content_integrity_invalid")
                revision_rows[key] = row
                revisions += 1
            authority_rows: dict[str, list[sqlite3.Row]] = {}
            for row in connection.execute(
                "SELECT * FROM governed_document_authorities "
                "ORDER BY document_ref,authority_revision"
            ):
                if not hmac.compare_digest(
                    row["row_sha256"],
                    canonical_sha256(self._authority_material(row)),
                ):
                    raise VaultIntegrityError(
                        "document_vault_authority_integrity_invalid"
                    )
                authority_rows.setdefault(row["document_ref"], []).append(row)
                authorities += 1
            for row in connection.execute("SELECT * FROM governed_document_grants"):
                self._grant_on(connection, row["grant_sha256"])
                grants += 1
            tombstone_rows: dict[str, sqlite3.Row] = {}
            for row in connection.execute(
                "SELECT * FROM governed_document_tombstones ORDER BY document_sha256"
            ):
                if not hmac.compare_digest(
                    row["tombstone_sha256"],
                    canonical_sha256(self._tombstone_material(row)),
                ):
                    raise VaultIntegrityError(
                        "document_vault_tombstone_integrity_invalid"
                    )
                tombstone_rows[row["document_sha256"]] = row
                tombstones += 1
            prior = GENESIS_SHA256
            expected = 1
            audit_correlations: dict[tuple[object, ...], int] = {}
            for row in connection.execute("SELECT * FROM governed_document_audit ORDER BY sequence"):
                material = {
                    "schema": "lightwork.governed-document-vault-audit.v1",
                    "sequence": row["sequence"],
                    "event_type": row["event_type"],
                    "subject_sha256": row["subject_sha256"],
                    "actor_sha256": row["actor_sha256"],
                    "detail_sha256": row["detail_sha256"],
                    "occurred_at": row["occurred_at"],
                    "previous_sha256": row["previous_sha256"],
                }
                if (
                    row["sequence"] != expected
                    or not hmac.compare_digest(row["previous_sha256"], prior)
                    or not hmac.compare_digest(row["event_sha256"], canonical_sha256(material))
                ):
                    raise VaultIntegrityError("document_vault_audit_integrity_invalid")
                prior = row["event_sha256"]
                expected += 1
                events += 1
                if row["event_type"] in {_INGEST_EVENT, _REVOKE_EVENT, _PURGE_EVENT}:
                    key = (
                        row["event_type"],
                        row["subject_sha256"],
                        row["detail_sha256"],
                        row["occurred_at"],
                    )
                    audit_correlations[key] = audit_correlations.get(key, 0) + 1

            authority_anchors: dict[str, list[sqlite3.Row]] = {}
            tombstone_anchors: dict[str, list[sqlite3.Row]] = {}
            anchor_correlations: dict[tuple[object, ...], int] = {}
            anchor_prior = GENESIS_SHA256
            anchor_expected = 1
            for row in connection.execute(
                "SELECT * FROM governed_document_integrity_anchors ORDER BY sequence"
            ):
                kind = row["record_kind"]
                revision = row["authority_revision"]
                event_type = row["event_type"]
                strings = (
                    row["document_sha256"],
                    row["authority_sha256"],
                    row["record_sha256"],
                    row["audit_detail_sha256"],
                    row["previous_sha256"],
                    row["anchor_sha256"],
                )
                kind_valid = (
                    kind == "authority"
                    and isinstance(revision, int)
                    and not isinstance(revision, bool)
                    and revision >= 1
                    and event_type
                    == (_INGEST_EVENT if revision == 1 else _REVOKE_EVENT)
                ) or (
                    kind == "tombstone"
                    and isinstance(revision, int)
                    and not isinstance(revision, bool)
                    and revision >= 1
                    and event_type == _PURGE_EVENT
                ) or (
                    kind == "legacy_tombstone"
                    and revision == 0
                    and event_type == _PURGE_EVENT
                )
                if (
                    row["sequence"] != anchor_expected
                    or not kind_valid
                    or any(
                        not isinstance(value, str)
                        or _DIGEST_RE.fullmatch(value) is None
                        for value in strings
                    )
                    or not isinstance(row["occurred_at"], (int, float))
                    or isinstance(row["occurred_at"], bool)
                    or not hmac.compare_digest(row["previous_sha256"], anchor_prior)
                    or not hmac.compare_digest(
                        row["anchor_sha256"],
                        canonical_sha256(self._integrity_anchor_material(row)),
                    )
                ):
                    raise VaultIntegrityError(
                        "document_vault_completeness_anchor_invalid"
                    )
                correlation = (
                    event_type,
                    row["document_sha256"],
                    row["audit_detail_sha256"],
                    row["occurred_at"],
                )
                anchor_correlations[correlation] = (
                    anchor_correlations.get(correlation, 0) + 1
                )
                if kind == "authority":
                    authority_anchors.setdefault(row["document_sha256"], []).append(row)
                else:
                    tombstone_anchors.setdefault(row["document_sha256"], []).append(row)
                anchor_prior = row["anchor_sha256"]
                anchor_expected += 1
                anchor_count += 1
            if (
                anchor_count != integrity_state["anchor_count"]
                or not hmac.compare_digest(
                    anchor_prior, integrity_state["terminal_sha256"]
                )
            ):
                raise VaultIntegrityError("document_vault_completeness_state_invalid")

            legacy_document_shas = {
                document_sha
                for document_sha, rows in tombstone_anchors.items()
                if any(row["record_kind"] == "legacy_tombstone" for row in rows)
            }
            for key, count in anchor_correlations.items():
                if audit_correlations.get(key) != count:
                    raise VaultIntegrityError(
                        "document_vault_completeness_audit_invalid"
                    )
            for key, count in audit_correlations.items():
                if (
                    anchor_correlations.get(key) != count
                    and not (
                        key[0] in {_INGEST_EVENT, _REVOKE_EVENT}
                        and key[1] in legacy_document_shas
                    )
                ):
                    raise VaultIntegrityError(
                        "document_vault_completeness_audit_invalid"
                    )

            for document_ref, head in document_rows.items():
                document_sha = _text_sha256(document_ref)
                if document_sha in tombstone_rows or document_sha in tombstone_anchors:
                    raise VaultIntegrityError(
                        "document_vault_tombstone_completeness_invalid"
                    )
                expected_content_revisions = set(
                    range(1, int(head["content_revision"]) + 1)
                )
                actual_content_revisions = {
                    revision
                    for ref, revision in revision_rows
                    if ref == document_ref
                }
                current_content = revision_rows.get(
                    (document_ref, head["content_revision"])
                )
                if (
                    actual_content_revisions != expected_content_revisions
                    or current_content is None
                    or current_content["content_sha256"] != head["content_sha256"]
                    or current_content["byte_size"] != head["byte_size"]
                ):
                    raise VaultIntegrityError(
                        "document_vault_content_integrity_invalid"
                    )
                history = authority_rows.get(document_ref, [])
                anchors = authority_anchors.get(document_sha, [])
                expected_authority_revisions = list(
                    range(1, int(head["authority_revision"]) + 1)
                )
                if (
                    [row["authority_revision"] for row in history]
                    != expected_authority_revisions
                    or [row["authority_revision"] for row in anchors]
                    != expected_authority_revisions
                ):
                    raise VaultIntegrityError(
                        "document_vault_authority_completeness_invalid"
                    )
                for authority_row, anchor in zip(history, anchors, strict=True):
                    revision = authority_row["authority_revision"]
                    expected_state = "active" if revision == 1 else "revoked"
                    expected_event = _INGEST_EVENT if revision == 1 else _REVOKE_EVENT
                    expected_authority_sha = canonical_sha256(
                        _authority_material(
                            tenant_sha256=self.tenant_sha256,
                            document_ref=document_ref,
                            product_area=head["product_area"],
                            record_type=head["record_type"],
                            safe_display_name=head["safe_display_name"],
                            media_type=head["media_type"],
                            byte_size=head["byte_size"],
                            content_sha256=head["content_sha256"],
                            content_revision=authority_row["content_revision"],
                            authority_revision=revision,
                            state=expected_state,
                        )
                    )
                    detail = (
                        {
                            "authority_sha256": expected_authority_sha,
                            "content_sha256": head["content_sha256"],
                        }
                        if revision == 1
                        else {
                            "authority_revision": revision,
                            "authority_sha256": expected_authority_sha,
                        }
                    )
                    if (
                        authority_row["state"] != expected_state
                        or authority_row["authority_sha256"] != expected_authority_sha
                        or anchor["event_type"] != expected_event
                        or anchor["authority_sha256"] != expected_authority_sha
                        or anchor["record_sha256"] != authority_row["row_sha256"]
                        or anchor["audit_detail_sha256"]
                        != canonical_sha256(detail)
                        or anchor["occurred_at"] != authority_row["occurred_at"]
                    ):
                        raise VaultIntegrityError(
                            "document_vault_authority_completeness_invalid"
                        )
                latest = history[-1]
                if (
                    latest["content_revision"] != head["content_revision"]
                    or latest["state"] != head["state"]
                    or latest["authority_sha256"] != head["authority_sha256"]
                ):
                    raise VaultIntegrityError(
                        "document_vault_authority_completeness_invalid"
                    )

            for document_ref in authority_rows:
                if document_ref not in document_rows:
                    raise VaultIntegrityError(
                        "document_vault_authority_completeness_invalid"
                    )
            for document_sha, tombstone_row in tombstone_rows.items():
                if document_sha in documents_by_sha:
                    raise VaultIntegrityError(
                        "document_vault_tombstone_completeness_invalid"
                    )
                anchors = tombstone_anchors.get(document_sha, [])
                if len(anchors) != 1:
                    raise VaultIntegrityError(
                        "document_vault_tombstone_completeness_invalid"
                    )
                anchor = anchors[0]
                if (
                    anchor["record_sha256"] != tombstone_row["tombstone_sha256"]
                    or anchor["authority_sha256"]
                    != tombstone_row["final_authority_sha256"]
                    or anchor["occurred_at"] != tombstone_row["purged_at"]
                    or anchor["audit_detail_sha256"]
                    != canonical_sha256(
                        {"tombstone_sha256": tombstone_row["tombstone_sha256"]}
                    )
                ):
                    raise VaultIntegrityError(
                        "document_vault_tombstone_completeness_invalid"
                    )
                historical = authority_anchors.get(document_sha, [])
                if anchor["record_kind"] == "legacy_tombstone":
                    if historical:
                        raise VaultIntegrityError(
                            "document_vault_authority_completeness_invalid"
                        )
                    continue
                expected_revisions = list(
                    range(1, int(anchor["authority_revision"]) + 1)
                )
                if (
                    [row["authority_revision"] for row in historical]
                    != expected_revisions
                    or not historical
                    or historical[-1]["authority_sha256"]
                    != tombstone_row["final_authority_sha256"]
                ):
                    raise VaultIntegrityError(
                        "document_vault_authority_completeness_invalid"
                    )
                for history_anchor in historical:
                    revision = history_anchor["authority_revision"]
                    detail = (
                        {
                            "authority_sha256": history_anchor["authority_sha256"],
                            "content_sha256": tombstone_row["final_content_sha256"],
                        }
                        if revision == 1
                        else {
                            "authority_revision": revision,
                            "authority_sha256": history_anchor["authority_sha256"],
                        }
                    )
                    if history_anchor["audit_detail_sha256"] != canonical_sha256(detail):
                        raise VaultIntegrityError(
                            "document_vault_authority_completeness_invalid"
                        )
            if set(tombstone_anchors) != set(tombstone_rows):
                raise VaultIntegrityError(
                    "document_vault_tombstone_completeness_invalid"
                )
            if set(authority_anchors) - (set(documents_by_sha) | set(tombstone_rows)):
                raise VaultIntegrityError(
                    "document_vault_authority_completeness_invalid"
                )
        return {
            "schema": "lightwork.governed-document-vault-integrity.v1",
            "ok": True,
            "documents": documents,
            "content_revisions": revisions,
            "authority_revisions": authorities,
            "delivery_grants": grants,
            "tombstones": tombstones,
            "integrity_anchors": anchor_count,
            "integrity_anchor_head_sha256": anchor_prior,
            "audit_events": events,
            "audit_head_sha256": prior,
            "content_verified": verify_content,
        }

    def status(self) -> dict[str, object]:
        integrity = self.verify_integrity(verify_content=False)
        return {
            "schema": "lightwork.governed-document-vault-status.v1",
            "enabled": True,
            "configured": True,
            "ready": integrity["ok"] is True,
            "tenant_private_persistence": True,
            "at_rest_encryption": "maverick.crypto_at_rest",
            "raw_grants_persisted": False,
            "raw_principals_persisted": False,
            "object_locators_persisted": False,
            "external_object_store_custody_verified": False,
            "live_relying_workflow_verified": False,
            "limits": {
                "max_document_bytes": self.config.max_document_bytes,
                "max_documents": self.config.max_documents,
                "grant_ttl_seconds": self.config.grant_ttl_seconds,
                "stream_chunk_bytes": self.config.stream_chunk_bytes,
                "allowed_media_types": list(self.config.allowed_media_types),
            },
            "integrity": integrity,
        }


__all__ = [
    "DEFAULT_MEDIA_TYPES",
    "DeliveryPayload",
    "GovernedDocumentRecord",
    "GovernedDocumentVault",
    "GovernedDocumentVaultConfig",
    "GovernedDocumentVaultError",
    "VaultConfigError",
    "VaultConflict",
    "VaultIntegrityError",
    "VaultNotFound",
    "VaultPermissionDenied",
    "VaultValidationError",
    "canonical_sha256",
]
