"""Governed custom data-element indexes for consent profiles.

The index is an administrative projection over ``consent_profile_data``.  It
stores only HMAC search tokens and tenant-local profile identifiers; queried
values and raw key material are never persisted.  SQLite triggers invalidate a
ready index whenever its source element changes, so searches fail closed until
an operator rebuilds the projection.

The capability is default-off behind all three exact gates::

    [consent_preferences]
    enable = true
    [consent_preferences.profile_data]
    enable = true
    [consent_preferences.profile_data.custom_index]
    enable = true
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from . import consent_storage
from .constant_time import text_equals
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
INDEX_STATES = frozenset({"pending", "ready", "stale", "revoked"})

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}\Z")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_PAGE_SIZE = 500
_MAX_QUERY_CATALOGS = 10_000
_MAX_QUERY_CATALOG_BYTES = 16 * 1024 * 1024
_MAX_QUERY_ORDERS = 128
_MIN_RETENTION_SECONDS = 24 * 60 * 60
_MAX_RETENTION_SECONDS = 5 * 365 * 24 * 60 * 60


class ConsentCustomIndexError(RuntimeError):
    """Base custom-index error."""


class ConsentCustomIndexConfigError(ConsentCustomIndexError):
    """The exact capability gates or deployment custody are unavailable."""


class ConsentCustomIndexValidationError(ConsentCustomIndexError, ValueError):
    """A caller supplied an input outside the closed contract."""


class ConsentCustomIndexConflict(ConsentCustomIndexError):
    """A revision, idempotency, source-freshness, or state precondition failed."""


class ConsentCustomIndexNotFound(ConsentCustomIndexError):
    """A tenant-local index or published data element was not found."""


class ConsentCustomIndexPermissionDenied(ConsentCustomIndexError):
    """An authenticated administrative principal is unavailable."""


class ConsentCustomIndexIntegrityError(ConsentCustomIndexError):
    """Persisted projection material failed integrity verification."""


def custom_index_enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Return true only for the exact parent, profile, and custom-index gates."""

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
    profile = consent.get("profile_data") if isinstance(consent, Mapping) else None
    index = profile.get("custom_index") if isinstance(profile, Mapping) else None
    return (
        isinstance(consent, Mapping)
        and consent.get("enable") is True
        and isinstance(profile, Mapping)
        and profile.get("enable") is True
        and isinstance(index, Mapping)
        and index.get("enable") is True
    )


def require_custom_index_enabled(config: Mapping[str, Any] | None = None) -> None:
    if not custom_index_enabled(config):
        raise ConsentCustomIndexConfigError(
            "consent custom indexes are disabled; explicitly enable consent_preferences, "
            "consent_preferences.profile_data, and profile_data.custom_index"
        )


def _runtime_principal() -> str | None:
    try:
        from .connections import current_principal

        return current_principal()
    except Exception:
        return None


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ConsentCustomIndexValidationError(
            "custom-index material must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= _MAX_JSON_BYTES:
        raise ConsentCustomIndexValidationError("custom-index material exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _id(value: object, label: str, pattern: re.Pattern[str] = _ID_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ConsentCustomIndexValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConsentCustomIndexValidationError(
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
        raise ConsentCustomIndexValidationError(f"{label} must be a positive finite timestamp")
    return float(value)


def _key(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) < 32:
        raise ConsentCustomIndexConfigError(
            "custom-index key custody must return at least 32 bytes"
        )
    return value


def _value_token(key: bytes, tenant_id: str, element_name: str, value: object) -> str:
    material = {
        "schema": "lightwork.consent-custom-index-query.v1",
        "tenant_id": tenant_id,
        "element_name": element_name,
        "value": value,
    }
    return hmac.new(key, _canonical(material), hashlib.sha256).hexdigest()


def _query_value(value: object) -> bool | str | list[str]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _id(value, "query value")
    if isinstance(value, list) and 1 <= len(value) <= 64:
        selected = [_id(item, "query value") for item in value]
        if len(set(selected)) != len(selected):
            raise ConsentCustomIndexValidationError("query values must be unique")
        return selected
    raise ConsentCustomIndexValidationError(
        "query value must be a boolean, opaque value ID, or unique value-ID list"
    )


@dataclass(frozen=True, slots=True)
class CustomDataElementIndex:
    tenant_id: str
    index_id: str
    element_name: str
    state: str
    revision: int
    key_version: int
    source_change_revision: int
    source_records_sha256: str | None
    entry_count: int
    created_by: str
    retained_until: float
    built_at: float | None
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class CustomDataElementSearchPage:
    tenant_id: str
    index_id: str
    element_name: str
    index_revision: int
    profile_ids: tuple[str, ...]
    next_cursor: str | None
    source_fresh: bool


class ConsentCustomIndexStore:
    """Tenant-isolated lifecycle and indexed exact-match search authority."""

    def __init__(
        self,
        path: str | Path,
        *,
        key_resolver: Callable[[str, int], bytes],
        config_gate: Callable[[], None] = require_custom_index_enabled,
        principal_resolver: Callable[[], str | None] = _runtime_principal,
        clock: Callable[[], float] = time.time,
    ) -> None:
        config_gate()
        if not callable(key_resolver):
            raise ConsentCustomIndexConfigError("custom-index key resolver is required")
        self.path = Path(path)
        self._key_resolver = key_resolver
        self._principal_resolver = principal_resolver
        self._clock = clock
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if consent_storage.shared():
            connection = consent_storage.connect(self.path, timeout=30.0)
        else:
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
            source = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='profile_values'"
            ).fetchone()
            if source is None:
                raise ConsentCustomIndexConfigError(
                    "consent profile-data storage must be initialized before custom indexes"
                )
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS consent_custom_index_metadata(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS consent_custom_indexes(
                    tenant_id TEXT NOT NULL,index_id TEXT NOT NULL,element_name TEXT NOT NULL,
                    state TEXT NOT NULL,revision INTEGER NOT NULL,key_version INTEGER NOT NULL,
                    source_change_revision INTEGER NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,index_id),UNIQUE(tenant_id,element_name)
                );
                CREATE TABLE IF NOT EXISTS consent_custom_index_entries(
                    tenant_id TEXT NOT NULL,index_id TEXT NOT NULL,value_token TEXT NOT NULL,
                    profile_id TEXT NOT NULL,source_integrity_sha256 TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,index_id,value_token,profile_id)
                );
                CREATE INDEX IF NOT EXISTS consent_custom_index_lookup
                    ON consent_custom_index_entries(tenant_id,index_id,value_token,profile_id);
                CREATE TABLE IF NOT EXISTS consent_custom_index_source_changes(
                    tenant_id TEXT NOT NULL,element_name TEXT NOT NULL,
                    change_revision INTEGER NOT NULL,
                    PRIMARY KEY(tenant_id,element_name)
                );
                CREATE TABLE IF NOT EXISTS consent_custom_index_operations(
                    tenant_id TEXT NOT NULL,operation_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_id TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,operation_sha256)
                );
                CREATE TABLE IF NOT EXISTS consent_custom_index_audit(
                    tenant_id TEXT NOT NULL,sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS consent_custom_index_source_insert
                AFTER INSERT ON profile_values BEGIN
                    INSERT INTO consent_custom_index_source_changes(
                        tenant_id,element_name,change_revision
                    ) VALUES(NEW.tenant_id,NEW.preference_id,1)
                    ON CONFLICT(tenant_id,element_name) DO UPDATE SET
                        change_revision=change_revision+1;
                END;
                CREATE TRIGGER IF NOT EXISTS consent_custom_index_source_update
                AFTER UPDATE ON profile_values BEGIN
                    INSERT INTO consent_custom_index_source_changes(
                        tenant_id,element_name,change_revision
                    ) VALUES(NEW.tenant_id,NEW.preference_id,1)
                    ON CONFLICT(tenant_id,element_name) DO UPDATE SET
                        change_revision=change_revision+1;
                END;
                CREATE TRIGGER IF NOT EXISTS consent_custom_index_source_delete
                AFTER DELETE ON profile_values BEGIN
                    INSERT INTO consent_custom_index_source_changes(
                        tenant_id,element_name,change_revision
                    ) VALUES(OLD.tenant_id,OLD.preference_id,1)
                    ON CONFLICT(tenant_id,element_name) DO UPDATE SET
                        change_revision=change_revision+1;
                END;
                INSERT OR IGNORE INTO consent_custom_index_metadata(key,value)
                    VALUES('schema_version','1');
                COMMIT;
                """
            )
            row = connection.execute(
                "SELECT value FROM consent_custom_index_metadata WHERE key='schema_version'"
            ).fetchone()
            if row is None or row["value"] != str(SCHEMA_VERSION):
                raise ConsentCustomIndexIntegrityError(
                    "consent custom-index database schema is unsupported"
                )
        if not consent_storage.shared():
            ensure_private_file(self.path)

    def _actor(self) -> str:
        actor = self._principal_resolver()
        if actor is None or actor == "":
            raise ConsentCustomIndexPermissionDenied(
                "an authenticated administrative principal is required"
            )
        return _id(actor, "authenticated principal")

    @staticmethod
    def _tenant(value: object) -> str:
        try:
            tenant = canonical_tenant_id(value)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ConsentCustomIndexValidationError("tenant_id is invalid") from exc
        if tenant != value:
            raise ConsentCustomIndexValidationError("tenant_id must already be canonical")
        return tenant

    @staticmethod
    def _payload(row: sqlite3.Row, label: str) -> dict[str, Any]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ConsentCustomIndexIntegrityError(
                f"persisted {label} is not canonical JSON"
            ) from exc
        if not isinstance(payload, dict) or not text_equals(
            _sha256(payload), str(row["integrity_sha256"])
        ):
            raise ConsentCustomIndexIntegrityError(
                f"persisted {label} failed integrity verification"
            )
        return payload

    @staticmethod
    def _from(payload: Mapping[str, Any], digest: str) -> CustomDataElementIndex:
        if payload.get("state") not in INDEX_STATES:
            raise ConsentCustomIndexIntegrityError("custom-index state is invalid")
        return CustomDataElementIndex(
            tenant_id=str(payload["tenant_id"]),
            index_id=str(payload["index_id"]),
            element_name=str(payload["element_name"]),
            state=str(payload["state"]),
            revision=int(payload["revision"]),
            key_version=int(payload["key_version"]),
            source_change_revision=int(payload["source_change_revision"]),
            source_records_sha256=(
                None
                if payload["source_records_sha256"] is None
                else str(payload["source_records_sha256"])
            ),
            entry_count=int(payload["entry_count"]),
            created_by=str(payload["created_by"]),
            retained_until=float(payload["retained_until"]),
            built_at=None if payload["built_at"] is None else float(payload["built_at"]),
            created_at=float(payload["created_at"]),
            updated_at=float(payload["updated_at"]),
            integrity_sha256=digest,
        )

    @staticmethod
    def _source_revision(
        connection: sqlite3.Connection, tenant_id: str, element_name: str
    ) -> int:
        row = connection.execute(
            "SELECT change_revision FROM consent_custom_index_source_changes "
            "WHERE tenant_id=? AND element_name=?",
            (tenant_id, element_name),
        ).fetchone()
        return 0 if row is None else int(row["change_revision"])

    @staticmethod
    def _definition_exists(
        connection: sqlite3.Connection, tenant_id: str, element_name: str
    ) -> bool:
        rows = connection.execute(
            "SELECT * FROM catalogs WHERE tenant_id=?", (tenant_id,)
        ).fetchall()
        for row in rows:
            try:
                payload = ConsentCustomIndexStore._payload(row, "preference catalog")
            except ConsentCustomIndexIntegrityError:
                raise
            if payload.get("state") != "published":
                continue
            definitions = payload.get("definitions")
            if isinstance(definitions, list) and any(
                isinstance(item, Mapping) and item.get("preference_id") == element_name
                for item in definitions
            ):
                return True
        return False

    @staticmethod
    def _operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request: Mapping[str, object],
    ) -> tuple[str, sqlite3.Row | None]:
        operation = _id(idempotency_key, "idempotency_key", _OP_RE)
        operation_sha = hashlib.sha256(f"{tenant_id}\0{operation}".encode()).hexdigest()
        request_sha = _sha256(request)
        row = connection.execute(
            "SELECT * FROM consent_custom_index_operations "
            "WHERE tenant_id=? AND operation_sha256=?",
            (tenant_id, operation_sha),
        ).fetchone()
        if row is not None:
            body = {
                "tenant_id": row["tenant_id"],
                "operation_sha256": row["operation_sha256"],
                "request_sha256": row["request_sha256"],
                "result_id": row["result_id"],
            }
            if _sha256(body) != row["integrity_sha256"]:
                raise ConsentCustomIndexIntegrityError("custom-index operation is corrupt")
            if not text_equals(request_sha, str(row["request_sha256"])):
                raise ConsentCustomIndexConflict(
                    "idempotency key was reused with a different request"
                )
        return request_sha, row

    @staticmethod
    def _record_operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request_sha: str,
        result_id: str,
    ) -> None:
        operation_sha = hashlib.sha256(f"{tenant_id}\0{idempotency_key}".encode()).hexdigest()
        body = {
            "tenant_id": tenant_id,
            "operation_sha256": operation_sha,
            "request_sha256": request_sha,
            "result_id": result_id,
        }
        connection.execute(
            "INSERT INTO consent_custom_index_operations VALUES(?,?,?,?,?)",
            (tenant_id, operation_sha, request_sha, result_id, _sha256(body)),
        )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        tenant_id: str,
        action: str,
        index_id: str,
        actor: str,
        occurred_at: float,
        details: Mapping[str, object],
    ) -> None:
        head = connection.execute(
            "SELECT sequence,integrity_sha256 FROM consent_custom_index_audit "
            "WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        sequence = 1 if head is None else int(head["sequence"]) + 1
        previous = "0" * 64 if head is None else str(head["integrity_sha256"])
        payload = {
            "tenant_id": tenant_id,
            "sequence": sequence,
            "action": action,
            "index_id": index_id,
            "actor": actor,
            "occurred_at": occurred_at,
            "details": dict(details),
            "previous_sha256": previous,
        }
        digest = _sha256(payload)
        connection.execute(
            "INSERT INTO consent_custom_index_audit VALUES(?,?,?,?)",
            (tenant_id, sequence, _canonical(payload).decode("ascii"), digest),
        )

    @staticmethod
    def _get_row(
        connection: sqlite3.Connection, tenant_id: str, index_id: str
    ) -> tuple[sqlite3.Row, CustomDataElementIndex]:
        row = connection.execute(
            "SELECT * FROM consent_custom_indexes WHERE tenant_id=? AND index_id=?",
            (tenant_id, index_id),
        ).fetchone()
        if row is None:
            raise ConsentCustomIndexNotFound("custom data-element index was not found")
        payload = ConsentCustomIndexStore._payload(row, "custom data-element index")
        index = ConsentCustomIndexStore._from(payload, str(row["integrity_sha256"]))
        if (
            index.tenant_id != row["tenant_id"]
            or index.index_id != row["index_id"]
            or index.element_name != row["element_name"]
            or index.state != row["state"]
            or index.revision != row["revision"]
            or index.key_version != row["key_version"]
            or index.source_change_revision != row["source_change_revision"]
            or index.retained_until != row["retained_until"]
        ):
            raise ConsentCustomIndexIntegrityError("custom-index columns are inconsistent")
        return row, index

    def create_index(
        self,
        tenant_id: str,
        *,
        index_id: str,
        element_name: str,
        key_version: int,
        retention_seconds: int,
        idempotency_key: str,
    ) -> CustomDataElementIndex:
        tenant = self._tenant(tenant_id)
        index_key = _id(index_id, "index_id")
        element = _id(element_name, "element_name")
        version = _integer(key_version, "key_version", 1, 1_000_000)
        retention = _integer(
            retention_seconds,
            "retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        )
        actor = self._actor()
        _key(self._key_resolver(tenant, version))
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "create_index",
            "index_id": index_key,
            "element_name": element,
            "key_version": version,
            "retention_seconds": retention,
        }
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            request_sha, prior = self._operation(
                connection, tenant, idempotency_key, request
            )
            if prior is not None:
                return self._get_row(connection, tenant, str(prior["result_id"]))[1]
            if not self._definition_exists(connection, tenant, element):
                raise ConsentCustomIndexNotFound(
                    "published custom data element was not found"
                )
            source_revision = self._source_revision(connection, tenant, element)
            payload = {
                "tenant_id": tenant,
                "index_id": index_key,
                "element_name": element,
                "state": "pending",
                "revision": 1,
                "key_version": version,
                "source_change_revision": source_revision,
                "source_records_sha256": None,
                "entry_count": 0,
                "created_by": actor,
                "retained_until": now + retention,
                "built_at": None,
                "created_at": now,
                "updated_at": now,
            }
            digest = _sha256(payload)
            try:
                connection.execute(
                    "INSERT INTO consent_custom_indexes VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        tenant,
                        index_key,
                        element,
                        "pending",
                        1,
                        version,
                        source_revision,
                        now + retention,
                        _canonical(payload).decode("ascii"),
                        digest,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConsentCustomIndexConflict(
                    "index ID or data element is already governed"
                ) from exc
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, index_key
            )
            self._audit(connection, tenant, "index_created", index_key, actor, now, {})
            return self._from(payload, digest)

    def get_index(self, tenant_id: str, index_id: str) -> CustomDataElementIndex:
        tenant = self._tenant(tenant_id)
        index_key = _id(index_id, "index_id")
        with self._connect() as connection:
            _, index = self._get_row(connection, tenant, index_key)
            current = self._source_revision(connection, tenant, index.element_name)
            if index.state == "ready" and current != index.source_change_revision:
                return replace(index, state="stale")
            return index

    def list_indexes(self, tenant_id: str) -> tuple[CustomDataElementIndex, ...]:
        tenant = self._tenant(tenant_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT index_id FROM consent_custom_indexes WHERE tenant_id=? "
                "ORDER BY index_id",
                (tenant,),
            ).fetchall()
            indexes: list[CustomDataElementIndex] = []
            for row in rows:
                _, index = self._get_row(connection, tenant, str(row["index_id"]))
                current = self._source_revision(connection, tenant, index.element_name)
                if index.state == "ready" and current != index.source_change_revision:
                    indexes.append(replace(index, state="stale"))
                else:
                    indexes.append(index)
            return tuple(indexes)

    def build_index(
        self,
        tenant_id: str,
        index_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CustomDataElementIndex:
        tenant = self._tenant(tenant_id)
        index_key = _id(index_id, "index_id")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "build_index",
            "index_id": index_key,
            "expected_revision": expected,
        }
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            request_sha, prior = self._operation(
                connection, tenant, idempotency_key, request
            )
            if prior is not None:
                return self._get_row(connection, tenant, str(prior["result_id"]))[1]
            _, current = self._get_row(connection, tenant, index_key)
            if current.revision != expected:
                raise ConsentCustomIndexConflict(
                    f"custom-index revision CAS failed: expected {expected}, "
                    f"found {current.revision}"
                )
            if current.state == "revoked":
                raise ConsentCustomIndexConflict("revoked custom index cannot be rebuilt")
            key = _key(self._key_resolver(tenant, current.key_version))
            source_rows = connection.execute(
                "SELECT * FROM profile_values WHERE tenant_id=? AND preference_id=? "
                "ORDER BY profile_id",
                (tenant, current.element_name),
            ).fetchall()
            entries: list[tuple[str, str, str]] = []
            source_material: list[dict[str, str]] = []
            for source_row in source_rows:
                payload = self._payload(source_row, "profile value")
                if (
                    payload.get("tenant_id") != tenant
                    or payload.get("profile_id") != source_row["profile_id"]
                    or payload.get("preference_id") != current.element_name
                ):
                    raise ConsentCustomIndexIntegrityError(
                        "profile value source columns are inconsistent"
                    )
                source_integrity = str(source_row["integrity_sha256"])
                source_material.append(
                    {
                        "profile_id": str(source_row["profile_id"]),
                        "integrity_sha256": source_integrity,
                    }
                )
                expires_at = payload.get("expires_at")
                if payload.get("status") != "active" or (
                    isinstance(expires_at, (int, float)) and float(expires_at) <= now
                ):
                    continue
                token = _value_token(
                    key,
                    tenant,
                    current.element_name,
                    payload.get("value"),
                )
                entries.append((token, str(source_row["profile_id"]), source_integrity))
            connection.execute(
                "DELETE FROM consent_custom_index_entries WHERE tenant_id=? AND index_id=?",
                (tenant, index_key),
            )
            for token, profile_id, source_integrity in entries:
                entry_body = {
                    "tenant_id": tenant,
                    "index_id": index_key,
                    "value_token": token,
                    "profile_id": profile_id,
                    "source_integrity_sha256": source_integrity,
                }
                connection.execute(
                    "INSERT INTO consent_custom_index_entries VALUES(?,?,?,?,?,?)",
                    (
                        tenant,
                        index_key,
                        token,
                        profile_id,
                        source_integrity,
                        _sha256(entry_body),
                    ),
                )
            source_revision = self._source_revision(
                connection, tenant, current.element_name
            )
            payload = {
                "tenant_id": tenant,
                "index_id": index_key,
                "element_name": current.element_name,
                "state": "ready",
                "revision": current.revision + 1,
                "key_version": current.key_version,
                "source_change_revision": source_revision,
                "source_records_sha256": _sha256(source_material),
                "entry_count": len(entries),
                "created_by": current.created_by,
                "retained_until": current.retained_until,
                "built_at": now,
                "created_at": current.created_at,
                "updated_at": now,
            }
            digest = _sha256(payload)
            connection.execute(
                "UPDATE consent_custom_indexes SET state=?,revision=?,key_version=?,"
                "source_change_revision=?,retained_until=?,payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND index_id=?",
                (
                    "ready",
                    current.revision + 1,
                    current.key_version,
                    source_revision,
                    current.retained_until,
                    _canonical(payload).decode("ascii"),
                    digest,
                    tenant,
                    index_key,
                ),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, index_key
            )
            self._audit(
                connection,
                tenant,
                "index_built",
                index_key,
                actor,
                now,
                {"entry_count": len(entries), "source_change_revision": source_revision},
            )
            return self._from(payload, digest)

    def search(
        self,
        tenant_id: str,
        index_id: str,
        *,
        value: object,
        limit: int = 100,
        cursor: str | None = None,
    ) -> CustomDataElementSearchPage:
        tenant = self._tenant(tenant_id)
        index_key = _id(index_id, "index_id")
        page_size = _integer(limit, "limit", 1, _MAX_PAGE_SIZE)
        after = "" if cursor is None else _id(cursor, "cursor")
        query_value = _query_value(value)
        now = _timestamp(self._clock(), "current time")
        with self._connect() as connection:
            connection.execute("BEGIN")  # One consistent index/source/history read.
            _, index = self._get_row(connection, tenant, index_key)
            if index.state != "ready":
                raise ConsentCustomIndexConflict("custom index is not ready")
            current_revision = self._source_revision(
                connection, tenant, index.element_name
            )
            if current_revision != index.source_change_revision:
                raise ConsentCustomIndexConflict(
                    "custom index is stale and must be rebuilt before search"
                )
            key = _key(self._key_resolver(tenant, index.key_version))
            tokens = self._query_tokens(connection, key, tenant, index.element_name, query_value)
            placeholders = ",".join("?" for _ in tokens)
            # Entries are built once, so a value that has expired since then is
            # dropped here; keep reading until the page holds live profiles.
            profile_ids: list[str] = []
            scan_after = after
            while len(profile_ids) <= page_size:
                rows = connection.execute(
                    "SELECT * FROM consent_custom_index_entries "
                    f"WHERE tenant_id=? AND index_id=? AND value_token IN ({placeholders}) AND profile_id>? "
                    "ORDER BY profile_id LIMIT ?",
                    (tenant, index_key, *tokens, scan_after, page_size + 1),
                ).fetchall()
                for row in rows:
                    body = {
                        "tenant_id": row["tenant_id"],
                        "index_id": row["index_id"],
                        "value_token": row["value_token"],
                        "profile_id": row["profile_id"],
                        "source_integrity_sha256": row["source_integrity_sha256"],
                    }
                    if _sha256(body) != row["integrity_sha256"]:
                        raise ConsentCustomIndexIntegrityError(
                            "custom-index entry failed integrity verification"
                        )
                scanned = [str(row["profile_id"]) for row in rows]
                live = self._live_profiles(
                    connection, tenant, index.element_name, scanned, now
                )
                profile_ids.extend(item for item in scanned if item in live)
                if len(rows) <= page_size:
                    break
                scan_after = scanned[-1]
            visible = profile_ids[:page_size]
            return CustomDataElementSearchPage(
                tenant_id=tenant,
                index_id=index.index_id,
                element_name=index.element_name,
                index_revision=index.revision,
                profile_ids=tuple(visible),
                next_cursor=(
                    visible[-1] if len(profile_ids) > page_size and visible else None
                ),
                source_fresh=True,
            )

    def _live_profiles(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        element_name: str,
        profile_ids: list[str],
        now: float,
    ) -> set[str]:
        """Profiles whose source value is still active and unexpired at ``now``."""
        if not profile_ids:
            return set()
        placeholders = ",".join("?" for _ in profile_ids)
        rows = connection.execute(
            "SELECT * FROM profile_values WHERE tenant_id=? AND preference_id=? "
            f"AND profile_id IN ({placeholders})",
            (tenant, element_name, *profile_ids),
        ).fetchall()
        live: set[str] = set()
        for row in rows:
            payload = self._payload(row, "profile value")
            expires_at = payload.get("expires_at")
            if payload.get("status") == "active" and not (
                isinstance(expires_at, (int, float)) and float(expires_at) <= now
            ):
                live.add(str(row["profile_id"]))
        return live

    @staticmethod
    def _query_tokens(connection, key, tenant: str, element: str, value) -> tuple[str, ...]:
        """Search every retained published ordering without rewriting old tokens."""
        tokens = {_value_token(key, tenant, element, value)}
        if not isinstance(value, list):
            return tuple(tokens)
        from .consent_profile_data import (
            ConsentProfileDataValidationError,
            _definitions,
            _normalize_value,
        )
        count = size = 0
        after, version = "", 0
        while True:
            rows = connection.execute(
                "SELECT * FROM catalogs WHERE tenant_id=? "
                "AND (catalog_id>? OR (catalog_id=? AND version>?)) "
                "ORDER BY catalog_id,version LIMIT 32",
                (tenant, after, after, version),
            ).fetchall()
            if not rows:
                return tuple(sorted(tokens))
            for row in rows:
                count += 1
                size += len(str(row["payload_json"]).encode("utf-8"))
                if count > _MAX_QUERY_CATALOGS or size > _MAX_QUERY_CATALOG_BYTES:
                    raise ConsentCustomIndexConflict(
                        "The published question history exceeds this search's supported size. No incomplete results were returned."
                    )
                payload = ConsentCustomIndexStore._payload(row, "preference catalog")
                after, version = str(row["catalog_id"]), row["version"]
                if (payload.get("tenant_id") != tenant or payload.get("catalog_id") != after
                        or not _ID_RE.fullmatch(after) or type(version) is not int
                        or not 1 <= version <= 1_000_000 or type(payload.get("version")) is not int
                        or payload.get("version") != version):
                    raise ConsentCustomIndexIntegrityError("published question history could not be verified")
                if payload.get("state") != "published":
                    continue
                try:
                    definitions = _definitions(payload.get("definitions"))
                except ConsentProfileDataValidationError as exc:
                    raise ConsentCustomIndexIntegrityError("published question choices could not be verified") from exc
                for definition in definitions:
                    if definition["preference_id"] != element or definition["value_type"] != "multi_select":
                        continue
                    try:
                        normalized = _normalize_value(definition, value)
                    except ConsentProfileDataValidationError:
                        continue  # These choices were not present in this published version.
                    tokens.add(_value_token(key, tenant, element, normalized))
                    if len(tokens) > _MAX_QUERY_ORDERS:
                        raise ConsentCustomIndexConflict(
                            "The published answer history exceeds this search's supported size. No incomplete results were returned."
                        )

    def revoke_index(
        self,
        tenant_id: str,
        index_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> CustomDataElementIndex:
        tenant = self._tenant(tenant_id)
        index_key = _id(index_id, "index_id")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "revoke_index",
            "index_id": index_key,
            "expected_revision": expected,
        }
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            request_sha, prior = self._operation(
                connection, tenant, idempotency_key, request
            )
            if prior is not None:
                return self._get_row(connection, tenant, str(prior["result_id"]))[1]
            _, current = self._get_row(connection, tenant, index_key)
            if current.revision != expected:
                raise ConsentCustomIndexConflict(
                    f"custom-index revision CAS failed: expected {expected}, "
                    f"found {current.revision}"
                )
            if current.state == "revoked":
                raise ConsentCustomIndexConflict("custom index is already revoked")
            payload = {
                **{
                    key: getattr(current, key)
                    for key in (
                        "tenant_id",
                        "index_id",
                        "element_name",
                        "key_version",
                        "source_change_revision",
                        "source_records_sha256",
                        "entry_count",
                        "created_by",
                        "retained_until",
                        "built_at",
                        "created_at",
                    )
                },
                "state": "revoked",
                "revision": current.revision + 1,
                "updated_at": now,
            }
            digest = _sha256(payload)
            connection.execute(
                "UPDATE consent_custom_indexes SET state=?,revision=?,payload_json=?,"
                "integrity_sha256=? WHERE tenant_id=? AND index_id=?",
                (
                    "revoked",
                    current.revision + 1,
                    _canonical(payload).decode("ascii"),
                    digest,
                    tenant,
                    index_key,
                ),
            )
            connection.execute(
                "DELETE FROM consent_custom_index_entries WHERE tenant_id=? AND index_id=?",
                (tenant, index_key),
            )
            self._record_operation(
                connection, tenant, idempotency_key, request_sha, index_key
            )
            self._audit(connection, tenant, "index_revoked", index_key, actor, now, {})
            return self._from(payload, digest)

    def audit_history(
        self, tenant_id: str, *, limit: int = 200
    ) -> tuple[Mapping[str, object], ...]:
        tenant = self._tenant(tenant_id)
        page_size = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM consent_custom_index_audit WHERE tenant_id=? "
                "ORDER BY sequence DESC LIMIT ?",
                (tenant, page_size),
            ).fetchall()
            events = [self._payload(row, "custom-index audit event") for row in rows]
            return tuple(events)

    def verify_integrity(self, tenant_id: str) -> Mapping[str, object]:
        tenant = self._tenant(tenant_id)
        with self._connect() as connection:
            index_rows = connection.execute(
                "SELECT * FROM consent_custom_indexes WHERE tenant_id=? ORDER BY index_id",
                (tenant,),
            ).fetchall()
            for row in index_rows:
                self._get_row(connection, tenant, str(row["index_id"]))
            entry_rows = connection.execute(
                "SELECT * FROM consent_custom_index_entries WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            for row in entry_rows:
                body = {
                    "tenant_id": row["tenant_id"],
                    "index_id": row["index_id"],
                    "value_token": row["value_token"],
                    "profile_id": row["profile_id"],
                    "source_integrity_sha256": row["source_integrity_sha256"],
                }
                if _sha256(body) != row["integrity_sha256"]:
                    raise ConsentCustomIndexIntegrityError(
                        "custom-index entry failed integrity verification"
                    )
            audit_rows = connection.execute(
                "SELECT * FROM consent_custom_index_audit WHERE tenant_id=? "
                "ORDER BY sequence",
                (tenant,),
            ).fetchall()
            previous = "0" * 64
            for expected_sequence, row in enumerate(audit_rows, start=1):
                payload = self._payload(row, "custom-index audit event")
                if (
                    payload.get("sequence") != expected_sequence
                    or payload.get("previous_sha256") != previous
                ):
                    raise ConsentCustomIndexIntegrityError(
                        "custom-index audit chain is inconsistent"
                    )
                previous = str(row["integrity_sha256"])
            return {
                "tenant_id": tenant,
                "ok": True,
                "index_count": len(index_rows),
                "entry_count": len(entry_rows),
                "audit_event_count": len(audit_rows),
                "checked_at": _timestamp(self._clock(), "current time"),
            }


__all__ = [
    "ConsentCustomIndexConfigError",
    "ConsentCustomIndexConflict",
    "ConsentCustomIndexError",
    "ConsentCustomIndexIntegrityError",
    "ConsentCustomIndexNotFound",
    "ConsentCustomIndexPermissionDenied",
    "ConsentCustomIndexStore",
    "ConsentCustomIndexValidationError",
    "CustomDataElementIndex",
    "CustomDataElementSearchPage",
    "custom_index_enabled",
    "require_custom_index_enabled",
]
