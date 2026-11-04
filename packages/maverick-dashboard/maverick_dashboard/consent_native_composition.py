"""Stock, fail-closed production composition for native consent SDKs.

The public native router has one dependency object, while tenant registries
must remain physically separate.  This module bridges those constraints with
an operator-owned directory: an application reference is globally bound to
one canonical tenant before any client-supplied tenant value can select a
registry.  Each resolved registry still lives under that tenant's private data
directory.

Attestation, profile linking, rights intake, and certified TCF/GPP wire
verification are deployment seams.  None receives a permissive default.
Receipt signing may be injected, or it is derived from a named environment
root with a tenant/key/revision-separated Ed25519 seed.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import threading
import time
import weakref
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from maverick import consent_storage
from maverick.consent_native_sdk import (
    NativeApplicationAuthority,
    NativeConsentCapacityError,
    NativeConsentConflict,
    NativeConsentDenied,
    NativeConsentDeviceRegistry,
    NativeConsentGateway,
    NativeConsentIntegrityError,
    NativeConsentValidationError,
    NativeDeviceAuthority,
    NativeEnrollmentEvidence,
    NativeRequestEnvelope,
    NativeResponseReceipt,
)
from maverick.file_lock import (
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from maverick.paths import canonical_tenant_id, current_tenant_id_strict, data_dir, tenant_scope

from ._shared import authenticated_subject
from .consent_native_backend import LightworkNativeConsentBackend
from .consent_native_sdk_api import NativeConsentSDKAPIDependencies
from .consent_public_api import PublicClientBinding, PublicConsentDependencies

_CONFIG_KEYS = frozenset(
    {
        "enable",
        "receipt_key_id",
        "receipt_key_revision",
        "receipt_key_secret_ref",
        "max_applications",
        "max_devices",
        "max_requests",
        "requests_per_minute",
        "require_profile_linking",
        "require_rights_requests",
    }
)
_SECRET_REF_RE = re.compile(r"[A-Z][A-Z0-9_]{2,127}\Z")
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_PUBLIC_KEY_RE = _DIGEST_RE
_DIRECTORY_SCHEMA_VERSION = 1
_MAX_DIRECTORY_APPLICATIONS = 1_000_000
_MAX_KEYS_PER_APPLICATION = 64
_MAX_RATE_BUCKETS = 10_000
_RATE_WINDOW_SECONDS = 60.0
_DEFAULT_MAX_APPLICATIONS = 1_000
_DEFAULT_MAX_DEVICES = 100_000
_DEFAULT_MAX_REQUESTS = 1_000_000
_DEFAULT_REQUESTS_PER_MINUTE = 120
# How long the public gate trusts one replay of the directory audit chain. A
# failed replay is retried sooner so a transient error does not hold the
# endpoints shut. The admin readiness and integrity checks never use this.
_GATE_INTEGRITY_PASS_SECONDS = 30.0
_GATE_INTEGRITY_FAIL_SECONDS = 5.0


class NativeConsentCompositionError(NativeConsentIntegrityError):
    """A deployment-owned native-consent dependency is unavailable."""


@dataclass(frozen=True, slots=True)
class NativeConsentSettings:
    receipt_key_id: str
    receipt_key_revision: int
    receipt_key_secret_ref: str
    max_applications: int
    max_devices: int
    max_requests: int
    requests_per_minute: int
    require_profile_linking: bool
    require_rights_requests: bool
    standards_wire_required: bool


@dataclass(frozen=True, slots=True)
class NativeApplicationDirectoryRecord:
    application_ref: str
    tenant_id: str
    tenant_sha256: str
    authority_sha256: str
    registry_revision: int
    directory_revision: int
    current_key_id: str
    current_key_revision: int
    current_public_key_hex: str


def _canonical(value: object, *, maximum: int = 256 * 1_024) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise NativeConsentCompositionError("native consent authority is invalid") from exc
    if not 1 <= len(encoded) <= maximum:
        raise NativeConsentCompositionError("native consent authority is outside its bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
        raise NativeConsentValidationError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise NativeConsentValidationError(f"{label} is invalid")
    return value


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise NativeConsentCompositionError(f"{label} is outside its bound")
    return value


def native_consent_settings(config: Mapping[str, Any]) -> NativeConsentSettings | None:
    """Validate the closed native SDK contract, returning ``None`` only when off."""

    if not isinstance(config, Mapping):
        raise NativeConsentCompositionError("native consent configuration is unavailable")
    consent = config.get("consent_preferences")
    if not isinstance(consent, Mapping):
        return None
    section = consent.get("native_sdk")
    if section is None:
        return None
    if not isinstance(section, Mapping):
        raise NativeConsentCompositionError(
            "consent_preferences.native_sdk must be a table"
        )
    if any(key not in _CONFIG_KEYS for key in section):
        raise NativeConsentCompositionError(
            "native consent configuration contains an unknown key"
        )
    enabled = section.get("enable", False)
    if type(enabled) is not bool:
        raise NativeConsentCompositionError("native consent enable gate must be true or false")
    if enabled is not True:
        return None
    publishing = consent.get("publishing")
    public_api = consent.get("public_api")
    if (
        consent.get("enable") is not True
        or not isinstance(publishing, Mapping)
        or publishing.get("enable") is not True
        or not isinstance(public_api, Mapping)
        or public_api.get("enable") is not True
    ):
        raise NativeConsentCompositionError(
            "native consent requires consent, publishing, and public API gates"
        )
    key_id = section.get("receipt_key_id")
    secret_ref = section.get("receipt_key_secret_ref")
    if not isinstance(key_id, str) or _REF_RE.fullmatch(key_id) is None:
        raise NativeConsentCompositionError("native consent receipt key id is invalid")
    if not isinstance(secret_ref, str) or _SECRET_REF_RE.fullmatch(secret_ref) is None:
        raise NativeConsentCompositionError("native consent receipt key reference is invalid")
    profile_required = section.get("require_profile_linking", False)
    rights_required = section.get("require_rights_requests", False)
    if type(profile_required) is not bool or type(rights_required) is not bool:
        raise NativeConsentCompositionError("native consent callback requirements are invalid")
    standards = consent.get("standards")
    wire_required = isinstance(standards, Mapping) and (
        standards.get("gpp") is True or standards.get("tcf") is True
    )
    return NativeConsentSettings(
        receipt_key_id=key_id,
        receipt_key_revision=_integer(
            section.get("receipt_key_revision", 1),
            "native consent receipt_key_revision",
            1,
            1_000_000,
        ),
        receipt_key_secret_ref=secret_ref,
        max_applications=_integer(
            section.get("max_applications", _DEFAULT_MAX_APPLICATIONS),
            "native consent max_applications",
            1,
            100_000,
        ),
        max_devices=_integer(
            section.get("max_devices", _DEFAULT_MAX_DEVICES),
            "native consent max_devices",
            1,
            10_000_000,
        ),
        max_requests=_integer(
            section.get("max_requests", _DEFAULT_MAX_REQUESTS),
            "native consent max_requests",
            1,
            100_000_000,
        ),
        requests_per_minute=_integer(
            section.get("requests_per_minute", _DEFAULT_REQUESTS_PER_MINUTE),
            "native consent requests_per_minute",
            1,
            10_000,
        ),
        require_profile_linking=profile_required,
        require_rights_requests=rights_required,
        standards_wire_required=wire_required,
    )


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise NativeConsentCompositionError(
            "native consent tenant configuration is unavailable"
        ) from exc
    if errors or not isinstance(config, Mapping):
        raise NativeConsentCompositionError(
            "native consent tenant configuration is unavailable"
        )
    return config


def settings_for_tenant(tenant_id: str) -> NativeConsentSettings:
    selected = native_consent_settings(_load_tenant_config(tenant_id))
    if selected is None:
        raise NativeConsentDenied("native consent is disabled")
    return selected


def native_consent_enabled(tenant_id: str) -> bool:
    try:
        return native_consent_settings(_load_tenant_config(tenant_id)) is not None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _standards_contract_sha256(config: Mapping[str, Any]) -> str:
    consent = config.get("consent_preferences")
    standards = consent.get("standards") if isinstance(consent, Mapping) else None
    selected = standards if isinstance(standards, Mapping) else {}
    body = {
        "schema": "lightwork.native-consent-standards-configuration.v1",
        "gpc": selected.get("gpc") is True,
        "dnt": selected.get("dnt") is True,
        "gpp": selected.get("gpp") is True,
        "tcf": selected.get("tcf") is True,
        "google_consent_mode": selected.get("google_consent_mode") is True,
    }
    return _sha256(body)


class _RevisionObserver:
    """The read-only connection whose PRAGMA data_version reports in-place commits."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.connection: sqlite3.Connection | None = None
        self.file_identity: tuple[int, int] | None = None

    def close(self) -> None:
        with self.lock:
            connection, self.connection, self.file_identity = self.connection, None, None
        if connection is not None:
            connection.close()


class NativeApplicationDirectory:
    """Global application selector directory containing no device state."""

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path).expanduser()
        self._clock = clock
        # PRAGMA data_version is comparable only on the SAME connection. Keep a
        # read-only observer open so rapid in-place updates are noticed even on
        # filesystems whose timestamp/size do not move between requests. The
        # finalizer closes the observer when this directory is released or the
        # process exits; the observer is kept apart so it does not keep self alive.
        self._revision = _RevisionObserver()
        self._revision_finalizer = weakref.finalize(self, self._revision.close)
        ensure_private_directory(self.path.parent)
        with cross_process_lock(self.path, strict=True):
            self._initialize()

    def close(self) -> None:
        """Release the revision observer's file handle. Safe to call more than once."""
        self._revision.close()

    @contextlib.contextmanager
    def _connect(self):
        if consent_storage.shared():
            connection = consent_storage.connect(self.path, timeout=10.0)
        else:
            ensure_private_directory(self.path.parent)
            if not self.path.exists():
                try:
                    descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                except FileExistsError:
                    pass
                else:
                    os.close(descriptor)
            ensure_private_file(self.path, 0o600)
            connection = sqlite3.connect(str(self.path), isolation_level=None, timeout=10.0)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA secure_delete=ON")
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS native_consent_directory_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS native_consent_application_directory(
                    application_ref TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    tenant_sha256 TEXT NOT NULL,
                    authority_sha256 TEXT NOT NULL,
                    registry_revision INTEGER NOT NULL,
                    directory_revision INTEGER NOT NULL,
                    current_key_id TEXT NOT NULL,
                    current_key_revision INTEGER NOT NULL,
                    current_public_key_hex TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending','active')),
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS native_consent_directory_tenant_idx
                ON native_consent_application_directory(tenant_sha256,application_ref);
                CREATE TABLE IF NOT EXISTS native_consent_directory_receipt_keys(
                    application_ref TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    key_revision INTEGER NOT NULL,
                    public_key_hex TEXT NOT NULL,
                    binding_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(application_ref,key_id,key_revision),
                    FOREIGN KEY(application_ref)
                        REFERENCES native_consent_application_directory(application_ref)
                );
                CREATE TABLE IF NOT EXISTS native_consent_directory_audit(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_json TEXT NOT NULL,
                    previous_sha256 TEXT,
                    event_sha256 TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS native_consent_directory_audit_no_update
                BEFORE UPDATE ON native_consent_directory_audit
                BEGIN SELECT RAISE(ABORT, 'native consent directory audit is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS native_consent_directory_audit_no_delete
                BEFORE DELETE ON native_consent_directory_audit
                BEGIN SELECT RAISE(ABORT, 'native consent directory audit is immutable'); END;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO native_consent_directory_meta(key,value) "
                "VALUES('schema_version',?)",
                (str(_DIRECTORY_SCHEMA_VERSION),),
            )
            row = connection.execute(
                "SELECT value FROM native_consent_directory_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None or row["value"] != str(_DIRECTORY_SCHEMA_VERSION):
                raise NativeConsentCompositionError(
                    "unsupported native consent application directory schema"
                )

    @staticmethod
    def _record(row: sqlite3.Row) -> NativeApplicationDirectoryRecord:
        return NativeApplicationDirectoryRecord(
            application_ref=_ref(row["application_ref"], "application_ref"),
            tenant_id=canonical_tenant_id(str(row["tenant_id"])),
            tenant_sha256=_digest(row["tenant_sha256"], "tenant_sha256"),
            authority_sha256=_digest(row["authority_sha256"], "authority_sha256"),
            registry_revision=_integer(
                row["registry_revision"], "registry_revision", 1, 2**31 - 1
            ),
            directory_revision=_integer(
                row["directory_revision"], "directory_revision", 1, 2**31 - 1
            ),
            current_key_id=_ref(row["current_key_id"], "receipt key id"),
            current_key_revision=_integer(
                row["current_key_revision"], "receipt key revision", 1, 1_000_000
            ),
            current_public_key_hex=_digest(
                row["current_public_key_hex"], "receipt public key"
            ),
        )

    @staticmethod
    def _key_binding(
        application_ref: str,
        key_id: str,
        key_revision: int,
        public_key_hex: str,
    ) -> str:
        return _sha256(
            {
                "schema": "lightwork.native-consent-receipt-key-binding.v1",
                "application_ref": application_ref,
                "key_id": key_id,
                "key_revision": key_revision,
                "public_key_hex": public_key_hex,
            }
        )

    @staticmethod
    def _append_audit(
        connection: sqlite3.Connection,
        *,
        event_type: str,
        application_ref: str,
        tenant_sha256: str,
        authority_sha256: str,
        directory_revision: int,
        key_binding_sha256: str,
        occurred_at: float,
    ) -> None:
        previous = connection.execute(
            "SELECT event_sha256 FROM native_consent_directory_audit "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        prior = str(previous["event_sha256"]) if previous is not None else None
        body = {
            "schema": "lightwork.native-consent-directory-event.v1",
            "event_type": event_type,
            "application_ref": application_ref,
            "tenant_sha256": tenant_sha256,
            "authority_sha256": authority_sha256,
            "directory_revision": directory_revision,
            "key_binding_sha256": key_binding_sha256,
            "occurred_at": occurred_at,
            "previous_sha256": prior,
        }
        connection.execute(
            "INSERT INTO native_consent_directory_audit("
            "event_json,previous_sha256,event_sha256) VALUES(?,?,?)",
            (_canonical(body).decode("ascii"), prior, _sha256(body)),
        )

    def register_new(
        self,
        authority: NativeApplicationAuthority,
        *,
        registry: NativeConsentDeviceRegistry,
        settings: NativeConsentSettings,
        public_key_hex: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """Reserve globally, create tenant-locally, then activate with exact CAS."""

        if expected_revision != 0:
            raise NativeConsentConflict(
                "native application authority updates require a new application reference"
            )
        authority.normalized()
        app_ref = authority.application_ref
        tenant = canonical_tenant_id(authority.tenant_id)
        tenant_sha = _text_sha256(tenant)
        public_key = _digest(public_key_hex, "receipt public key")
        now = float(self._clock())
        if not math.isfinite(now) or now <= 0:
            raise NativeConsentCompositionError("native consent clock is invalid")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM native_consent_application_directory "
                    "WHERE application_ref=?",
                    (app_ref,),
                ).fetchone()
                if row is not None and row["status"] == "active":
                    raise NativeConsentConflict(
                        "native application reference is already registered"
                    )
                if row is not None:
                    exact_pending = (
                        row["tenant_id"] == tenant
                        and _same(row["tenant_sha256"], tenant_sha)
                        and _same(row["authority_sha256"], authority.authority_sha256)
                        and row["current_key_id"] == settings.receipt_key_id
                        and int(row["current_key_revision"])
                        == settings.receipt_key_revision
                        and _same(row["current_public_key_hex"], public_key)
                    )
                    if not exact_pending:
                        raise NativeConsentConflict(
                            "native application reference is reserved by another authority"
                        )
                else:
                    global_count = connection.execute(
                        "SELECT COUNT(*) AS count FROM native_consent_application_directory"
                    ).fetchone()
                    tenant_count = connection.execute(
                        "SELECT COUNT(*) AS count FROM native_consent_application_directory "
                        "WHERE tenant_sha256=?",
                        (tenant_sha,),
                    ).fetchone()
                    if (
                        global_count is None
                        or int(global_count["count"]) >= _MAX_DIRECTORY_APPLICATIONS
                        or tenant_count is None
                        or int(tenant_count["count"]) >= settings.max_applications
                    ):
                        raise NativeConsentCapacityError(
                            "native application directory reached its bound"
                        )
                    connection.execute(
                        "INSERT INTO native_consent_application_directory("
                        "application_ref,tenant_id,tenant_sha256,authority_sha256,"
                        "registry_revision,directory_revision,current_key_id,"
                        "current_key_revision,current_public_key_hex,status,created_at,"
                        "updated_at) VALUES(?,?,?,?,?,?,?,?,?,'pending',?,?)",
                        (
                            app_ref,
                            tenant,
                            tenant_sha,
                            authority.authority_sha256,
                            0,
                            0,
                            settings.receipt_key_id,
                            settings.receipt_key_revision,
                            public_key,
                            now,
                            now,
                        ),
                    )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        try:
            result = registry.register_application(authority, expected_revision=0)
        except NativeConsentConflict:
            existing, revision = registry.get_application(app_ref)
            if revision != 1 or not _same(
                existing.authority_sha256, authority.authority_sha256
            ):
                raise
            result = {
                "application_ref": app_ref,
                "revision": revision,
                "authority_sha256": existing.authority_sha256,
                "status": "active",
            }
        key_binding = self._key_binding(
            app_ref,
            settings.receipt_key_id,
            settings.receipt_key_revision,
            public_key,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                updated = connection.execute(
                    "UPDATE native_consent_application_directory SET status='active',"
                    "registry_revision=1,directory_revision=1,updated_at=? "
                    "WHERE application_ref=? AND status='pending' AND tenant_sha256=? "
                    "AND authority_sha256=?",
                    (now, app_ref, tenant_sha, authority.authority_sha256),
                )
                if updated.rowcount != 1:
                    raise NativeConsentConflict(
                        "native application directory activation changed"
                    )
                connection.execute(
                    "INSERT INTO native_consent_directory_receipt_keys("
                    "application_ref,key_id,key_revision,public_key_hex,"
                    "binding_sha256,created_at) VALUES(?,?,?,?,?,?)",
                    (
                        app_ref,
                        settings.receipt_key_id,
                        settings.receipt_key_revision,
                        public_key,
                        key_binding,
                        now,
                    ),
                )
                self._append_audit(
                    connection,
                    event_type="application.registered",
                    application_ref=app_ref,
                    tenant_sha256=tenant_sha,
                    authority_sha256=authority.authority_sha256,
                    directory_revision=1,
                    key_binding_sha256=key_binding,
                    occurred_at=now,
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return {**result, "directory_revision": 1}

    def resolve(
        self,
        application_ref: str,
        *,
        claimed_tenant_id: str | None = None,
    ) -> NativeApplicationDirectoryRecord:
        app_ref = _ref(application_ref, "application_ref")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM native_consent_application_directory "
                "WHERE application_ref=? AND status='active'",
                (app_ref,),
            ).fetchone()
        if row is None:
            raise NativeConsentDenied("native application authority is unavailable")
        record = self._record(row)
        if not _same(record.tenant_sha256, _text_sha256(record.tenant_id)):
            raise NativeConsentCompositionError("native application tenant binding changed")
        if claimed_tenant_id is not None:
            claimed = canonical_tenant_id(claimed_tenant_id)
            if not _same(record.tenant_sha256, _text_sha256(claimed)):
                raise NativeConsentDenied("native application tenant authority changed")
        return record

    def records_for_tenant(
        self,
        tenant_id: str,
        *,
        limit: int,
    ) -> tuple[NativeApplicationDirectoryRecord, ...]:
        tenant = canonical_tenant_id(tenant_id)
        bound = _integer(limit, "native application list limit", 1, 100_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM native_consent_application_directory "
                "WHERE tenant_sha256=? AND status='active' ORDER BY application_ref LIMIT ?",
                (_text_sha256(tenant), bound + 1),
            ).fetchall()
        if len(rows) > bound:
            raise NativeConsentCapacityError("native application directory read is incomplete")
        records = tuple(self._record(row) for row in rows)
        if any(item.tenant_id != tenant for item in records):
            raise NativeConsentCompositionError("native application tenant directory changed")
        return records

    def rotate_receipt_key(
        self,
        application_ref: str,
        *,
        tenant_id: str,
        expected_directory_revision: int,
        key_id: str,
        key_revision: int,
        public_key_hex: str,
    ) -> dict[str, Any]:
        app_ref = _ref(application_ref, "application_ref")
        tenant = canonical_tenant_id(tenant_id)
        expected = _integer(
            expected_directory_revision,
            "expected_directory_revision",
            1,
            2**31 - 1,
        )
        selected_key_id = _ref(key_id, "receipt key id")
        selected_revision = _integer(
            key_revision, "receipt key revision", 1, 1_000_000
        )
        public_key = _digest(public_key_hex, "receipt public key")
        now = float(self._clock())
        binding = self._key_binding(
            app_ref, selected_key_id, selected_revision, public_key
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM native_consent_application_directory "
                    "WHERE application_ref=? AND status='active'",
                    (app_ref,),
                ).fetchone()
                if row is None:
                    raise NativeConsentDenied("native application authority is unavailable")
                if (
                    not _same(row["tenant_sha256"], _text_sha256(tenant))
                    or int(row["directory_revision"]) != expected
                ):
                    raise NativeConsentConflict(
                        "native application directory revision changed"
                    )
                if (
                    row["current_key_id"] == selected_key_id
                    and int(row["current_key_revision"]) == selected_revision
                ):
                    raise NativeConsentConflict("receipt key rotation requires a new key")
                count = connection.execute(
                    "SELECT COUNT(*) AS count FROM native_consent_directory_receipt_keys "
                    "WHERE application_ref=?",
                    (app_ref,),
                ).fetchone()
                if count is None or int(count["count"]) >= _MAX_KEYS_PER_APPLICATION:
                    raise NativeConsentCapacityError(
                        "native receipt key history reached its bound"
                    )
                existing = connection.execute(
                    "SELECT public_key_hex,binding_sha256 "
                    "FROM native_consent_directory_receipt_keys "
                    "WHERE application_ref=? AND key_id=? AND key_revision=?",
                    (app_ref, selected_key_id, selected_revision),
                ).fetchone()
                if existing is not None:
                    raise NativeConsentConflict("native receipt key revision already exists")
                connection.execute(
                    "INSERT INTO native_consent_directory_receipt_keys("
                    "application_ref,key_id,key_revision,public_key_hex,"
                    "binding_sha256,created_at) VALUES(?,?,?,?,?,?)",
                    (
                        app_ref,
                        selected_key_id,
                        selected_revision,
                        public_key,
                        binding,
                        now,
                    ),
                )
                updated = connection.execute(
                    "UPDATE native_consent_application_directory SET "
                    "current_key_id=?,current_key_revision=?,current_public_key_hex=?,"
                    "directory_revision=directory_revision+1,updated_at=? "
                    "WHERE application_ref=? AND directory_revision=?",
                    (
                        selected_key_id,
                        selected_revision,
                        public_key,
                        now,
                        app_ref,
                        expected,
                    ),
                )
                if updated.rowcount != 1:
                    raise NativeConsentConflict(
                        "native application directory revision changed"
                    )
                self._append_audit(
                    connection,
                    event_type="receipt-key.rotated",
                    application_ref=app_ref,
                    tenant_sha256=_text_sha256(tenant),
                    authority_sha256=str(row["authority_sha256"]),
                    directory_revision=expected + 1,
                    key_binding_sha256=binding,
                    occurred_at=now,
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return {
            "application_ref": app_ref,
            "directory_revision": expected + 1,
            "key_id": selected_key_id,
            "key_revision": selected_revision,
            "public_key_hex": public_key,
        }

    def receipt_keys(self, application_ref: str) -> dict[str, Any]:
        record = self.resolve(application_ref)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM native_consent_directory_receipt_keys "
                "WHERE application_ref=? ORDER BY created_at,key_id,key_revision LIMIT ?",
                (record.application_ref, _MAX_KEYS_PER_APPLICATION + 1),
            ).fetchall()
        if not rows or len(rows) > _MAX_KEYS_PER_APPLICATION:
            raise NativeConsentCompositionError("native receipt key history is unavailable")
        keys: list[dict[str, Any]] = []
        for row in rows:
            key_id = _ref(row["key_id"], "receipt key id")
            revision = _integer(
                row["key_revision"], "receipt key revision", 1, 1_000_000
            )
            public_key = _digest(row["public_key_hex"], "receipt public key")
            expected = self._key_binding(
                record.application_ref, key_id, revision, public_key
            )
            if not _same(row["binding_sha256"], expected):
                raise NativeConsentCompositionError("native receipt key binding changed")
            keys.append(
                {
                    "key_id": key_id,
                    "key_revision": revision,
                    "public_key_hex": public_key,
                    "current": (
                        key_id == record.current_key_id
                        and revision == record.current_key_revision
                        and _same(public_key, record.current_public_key_hex)
                    ),
                }
            )
        if sum(item["current"] is True for item in keys) != 1:
            raise NativeConsentCompositionError("current native receipt key is unavailable")
        return {
            "schema": "lightwork.native-consent-receipt-keys.v1",
            "application_ref": record.application_ref,
            "application_authority_sha256": record.authority_sha256,
            "directory_revision": record.directory_revision,
            "keys": keys,
        }

    def has_active_application(self) -> bool:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT 1 FROM native_consent_application_directory "
                    "WHERE status='active' LIMIT 1"
                ).fetchone()
            return row is not None
        except Exception:
            return False

    def integrity_revision(self) -> object:
        """A cheap change signal for the directory, not an integrity verdict.

        Local storage is a DELETE-journal SQLite file. A persistent read-only
        observer's data_version catches committed SQL edits; file identity,
        timestamps and journal/WAL also catch normal replacements and direct
        file changes. Shared Postgres storage has no local file;
        its WAL insertion position changes as writes are recorded. Failure to observe
        either store closes the public gate rather than reusing an old pass.
        """
        if consent_storage.shared():
            with self._connect() as connection:
                row = connection.execute("SELECT pg_current_wal_insert_lsn()").fetchone()
            if row is None or row[0] is None:
                raise NativeConsentCompositionError("native directory revision is unavailable")
            return ("postgres", str(row[0]))

        def stamp(path: Path) -> tuple[int, int, int, int, int] | None:
            try:
                state = path.stat()
            except FileNotFoundError:
                return None
            return (state.st_dev, state.st_ino, state.st_size,
                    state.st_mtime_ns, state.st_ctime_ns)

        base = str(self.path)
        main = stamp(self.path)
        if main is None:
            raise NativeConsentCompositionError("native directory file is unavailable")
        identity = main[:2]
        observer = self._revision
        with observer.lock:
            if observer.connection is None or observer.file_identity != identity:
                if observer.connection is not None:
                    observer.connection.close()
                observer.connection = None
                observer.file_identity = None
                connection = sqlite3.connect(
                    f"{self.path.resolve().as_uri()}?mode=ro", uri=True,
                    check_same_thread=False, timeout=5.0,
                )
                try:
                    connection.execute("PRAGMA query_only=ON")
                except BaseException:
                    connection.close()
                    raise
                observer.connection = connection
                observer.file_identity = identity
            row = observer.connection.execute("PRAGMA data_version").fetchone()
        if row is None:
            raise NativeConsentCompositionError("native directory revision is unavailable")
        return (main, stamp(Path(base + "-journal")),
                stamp(Path(base + "-wal")), int(row[0]))

    def verify_integrity(self) -> bool:  # noqa: C901 - explicit cross-table audit checks
        def checked_ref(value: object, label: str) -> str:
            try:
                return _ref(value, label)
            except NativeConsentValidationError as exc:
                raise NativeConsentCompositionError(
                    "native application directory changed"
                ) from exc

        def checked_digest(value: object, label: str) -> str:
            try:
                return _digest(value, label)
            except NativeConsentValidationError as exc:
                raise NativeConsentCompositionError(
                    "native application directory changed"
                ) from exc

        previous: str | None = None
        audit_bindings: set[tuple[str, str]] = set()
        latest: dict[str, dict[str, Any]] = {}
        event_keys = {
            "schema",
            "event_type",
            "application_ref",
            "tenant_sha256",
            "authority_sha256",
            "directory_revision",
            "key_binding_sha256",
            "occurred_at",
            "previous_sha256",
        }
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT sequence,event_json,previous_sha256,event_sha256 "
                "FROM native_consent_directory_audit ORDER BY sequence"
            )
            count = 0
            for row in cursor:
                count += 1
                if count > _MAX_DIRECTORY_APPLICATIONS * _MAX_KEYS_PER_APPLICATION:
                    raise NativeConsentCapacityError(
                        "native consent directory audit exceeds its bound"
                    )
                try:
                    body = json.loads(row["event_json"])
                except (TypeError, ValueError) as exc:
                    raise NativeConsentCompositionError(
                        "native consent directory audit changed"
                    ) from exc
                if (
                    not isinstance(body, Mapping)
                    or body.get("previous_sha256") != previous
                    or row["previous_sha256"] != previous
                    or not _same(row["event_sha256"], _sha256(body))
                ):
                    raise NativeConsentCompositionError(
                        "native consent directory audit changed"
                    )
                if set(body) != event_keys or body.get("schema") != (
                    "lightwork.native-consent-directory-event.v1"
                ):
                    raise NativeConsentCompositionError(
                        "native consent directory audit changed"
                    )
                application_ref = checked_ref(
                    body.get("application_ref"), "application_ref"
                )
                tenant_sha = checked_digest(
                    body.get("tenant_sha256"), "tenant_sha256"
                )
                authority_sha = checked_digest(
                    body.get("authority_sha256"), "authority_sha256"
                )
                revision = _integer(
                    body.get("directory_revision"),
                    "directory_revision",
                    1,
                    2**31 - 1,
                )
                binding = checked_digest(
                    body.get("key_binding_sha256"), "key_binding_sha256"
                )
                occurred_at = body.get("occurred_at")
                if (
                    isinstance(occurred_at, bool)
                    or not isinstance(occurred_at, (int, float))
                    or not math.isfinite(float(occurred_at))
                    or float(occurred_at) <= 0
                ):
                    raise NativeConsentCompositionError(
                        "native consent directory audit changed"
                    )
                prior = latest.get(application_ref)
                event_type = body.get("event_type")
                if prior is None:
                    if event_type != "application.registered" or revision != 1:
                        raise NativeConsentCompositionError(
                            "native consent directory audit changed"
                        )
                elif (
                    event_type != "receipt-key.rotated"
                    or revision != int(prior["directory_revision"]) + 1
                    or not _same(prior["tenant_sha256"], tenant_sha)
                    or not _same(prior["authority_sha256"], authority_sha)
                ):
                    raise NativeConsentCompositionError(
                        "native consent directory audit changed"
                    )
                selector = (application_ref, binding)
                if selector in audit_bindings:
                    raise NativeConsentCompositionError(
                        "native consent directory audit changed"
                    )
                audit_bindings.add(selector)
                latest[application_ref] = {
                    "tenant_sha256": tenant_sha,
                    "authority_sha256": authority_sha,
                    "directory_revision": revision,
                    "key_binding_sha256": binding,
                }
                previous = str(row["event_sha256"])

            applications = connection.execute(
                "SELECT * FROM native_consent_application_directory "
                "ORDER BY application_ref LIMIT ?",
                (_MAX_DIRECTORY_APPLICATIONS + 1,),
            ).fetchall()
            if len(applications) > _MAX_DIRECTORY_APPLICATIONS:
                raise NativeConsentCapacityError(
                    "native application directory exceeds its bound"
                )
            stored_bindings: set[tuple[str, str]] = set()
            active_refs: set[str] = set()
            for application in applications:
                application_ref = checked_ref(
                    application["application_ref"], "application_ref"
                )
                try:
                    tenant_id = canonical_tenant_id(str(application["tenant_id"]))
                except (TypeError, ValueError) as exc:
                    raise NativeConsentCompositionError(
                        "native application tenant binding changed"
                    ) from exc
                tenant_sha = checked_digest(
                    application["tenant_sha256"], "tenant_sha256"
                )
                authority_sha = checked_digest(
                    application["authority_sha256"], "authority_sha256"
                )
                if not _same(tenant_sha, _text_sha256(tenant_id)):
                    raise NativeConsentCompositionError(
                        "native application tenant binding changed"
                    )
                key_rows = connection.execute(
                    "SELECT * FROM native_consent_directory_receipt_keys "
                    "WHERE application_ref=? ORDER BY key_id,key_revision LIMIT ?",
                    (application_ref, _MAX_KEYS_PER_APPLICATION + 1),
                ).fetchall()
                status = application["status"]
                if status == "pending":
                    if (
                        int(application["registry_revision"]) != 0
                        or int(application["directory_revision"]) != 0
                        or key_rows
                        or application_ref in latest
                    ):
                        raise NativeConsentCompositionError(
                            "pending native application authority changed"
                        )
                    checked_ref(application["current_key_id"], "receipt key id")
                    _integer(
                        application["current_key_revision"],
                        "receipt key revision",
                        1,
                        1_000_000,
                    )
                    checked_digest(
                        application["current_public_key_hex"], "receipt public key"
                    )
                    continue
                if status != "active" or not 1 <= len(key_rows) <= _MAX_KEYS_PER_APPLICATION:
                    raise NativeConsentCompositionError(
                        "native application directory changed"
                    )
                try:
                    record = self._record(application)
                except NativeConsentValidationError as exc:
                    raise NativeConsentCompositionError(
                        "native application directory changed"
                    ) from exc
                active_refs.add(application_ref)
                current_bindings: list[str] = []
                for key_row in key_rows:
                    key_id = checked_ref(key_row["key_id"], "receipt key id")
                    key_revision = _integer(
                        key_row["key_revision"],
                        "receipt key revision",
                        1,
                        1_000_000,
                    )
                    public_key = checked_digest(
                        key_row["public_key_hex"], "receipt public key"
                    )
                    binding = self._key_binding(
                        application_ref,
                        key_id,
                        key_revision,
                        public_key,
                    )
                    if not _same(key_row["binding_sha256"], binding):
                        raise NativeConsentCompositionError(
                            "native receipt key binding changed"
                        )
                    selector = (application_ref, binding)
                    if selector in stored_bindings:
                        raise NativeConsentCompositionError(
                            "native receipt key binding changed"
                        )
                    stored_bindings.add(selector)
                    if (
                        key_id == record.current_key_id
                        and key_revision == record.current_key_revision
                        and _same(public_key, record.current_public_key_hex)
                    ):
                        current_bindings.append(binding)
                audit_state = latest.get(application_ref)
                if (
                    len(current_bindings) != 1
                    or audit_state is None
                    or not _same(audit_state["tenant_sha256"], tenant_sha)
                    or not _same(audit_state["authority_sha256"], authority_sha)
                    or audit_state["directory_revision"] != record.directory_revision
                    or not _same(
                        audit_state["key_binding_sha256"], current_bindings[0]
                    )
                ):
                    raise NativeConsentCompositionError(
                        "native application directory changed"
                    )
            if active_refs != set(latest) or stored_bindings != audit_bindings:
                raise NativeConsentCompositionError(
                    "native application directory audit binding changed"
                )
        return True


class _BoundedRateLimiter:
    def __init__(self, *, default_limit: int = _DEFAULT_REQUESTS_PER_MINUTE) -> None:
        self.default_limit = default_limit
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str], deque[float]] = {}

    def __call__(self, subject: str, operation: str, limit: int | None = None) -> None:
        selected = _integer(
            self.default_limit if limit is None else limit,
            "native consent rate limit",
            1,
            10_000,
        )
        key = (_text_sha256(str(subject)), _ref(operation, "native operation"))
        now = time.monotonic()
        with self._lock:
            if key not in self._buckets and len(self._buckets) >= _MAX_RATE_BUCKETS:
                for candidate, values in tuple(self._buckets.items()):
                    while values and now - values[0] >= _RATE_WINDOW_SECONDS:
                        values.popleft()
                    if not values:
                        self._buckets.pop(candidate, None)
                if len(self._buckets) >= _MAX_RATE_BUCKETS:
                    raise NativeConsentCapacityError(
                        "native consent rate-limit capacity reached"
                    )
            values = self._buckets.setdefault(key, deque())
            while values and now - values[0] >= _RATE_WINDOW_SECONDS:
                values.popleft()
            if len(values) >= selected:
                raise NativeConsentDenied("native consent rate limit reached")
            values.append(now)


class _TimedVerdict:
    """Share one run of a slow yes/no check between requests that arrive together.

    A yes is reused for ``pass_seconds`` only while ``revision`` stays the same.
    A no, or a check that raised, is reused for only ``fail_seconds``: a transient fault clears quickly, while a
    store that really is broken is still re-checked at most that often rather
    than on every request. Anything but ``True`` counts as a no, so a fault can
    close a gate but never open it. Callers that arrive while the check runs
    wait for it and take its answer instead of starting their own.
    """

    def __init__(
        self,
        check: Callable[[], bool],
        *,
        pass_seconds: float,
        fail_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        revision: Callable[[], object] | None = None,
    ) -> None:
        self._check = check
        self._pass_seconds = pass_seconds
        self._fail_seconds = fail_seconds
        self._clock = clock
        self._revision = revision
        self._lock = threading.Lock()
        self._verdict = False
        self._expires = float("-inf")
        self._observed_revision: object = object()

    def __call__(self) -> bool:
        with self._lock:
            try:
                before = self._revision() if self._revision is not None else None
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                self._expires = float("-inf")
                self._verdict = False
                return False
            if self._clock() < self._expires and before == self._observed_revision:
                return self._verdict
            try:
                verdict = self._check() is True
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                verdict = False
            try:
                after = self._revision() if self._revision is not None else None
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                self._expires = float("-inf")
                self._verdict = False
                return False
            self._verdict = verdict
            self._observed_revision = after
            if before != after:
                # A write raced the replay. Recheck on the next request; no
                # snapshot spanning two revisions may admit a public action.
                self._verdict = False
                self._expires = float("-inf")
                return False
            self._expires = self._clock() + (self._pass_seconds if verdict
                                             else self._fail_seconds)
            return verdict


class _DerivedEd25519ReceiptSigner:
    def __init__(self, seed: bytes, *, key_id: str, key_revision: int) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self.key_id = key_id
        self.key_revision = key_revision

    @property
    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization

        return self._private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()

    def sign(self, body: bytes) -> bytes:
        return self._private.sign(body)


def _secret_material(value: object) -> bytes:
    if not isinstance(value, str):
        raise NativeConsentCompositionError("native receipt key custody is unavailable")
    if value.startswith("base64:"):
        try:
            material = base64.b64decode(value[7:].encode("ascii"), validate=True)
        except (UnicodeError, binascii.Error) as exc:
            raise NativeConsentCompositionError(
                "native receipt key custody is unavailable"
            ) from exc
    elif value.startswith("hex:"):
        try:
            material = bytes.fromhex(value[4:])
        except ValueError as exc:
            raise NativeConsentCompositionError(
                "native receipt key custody is unavailable"
            ) from exc
    else:
        material = value.encode("utf-8")
    if not 32 <= len(material) <= 4_096:
        raise NativeConsentCompositionError("native receipt key custody is unavailable")
    return material


def _environment_receipt_signer(
    *, tenant_id: str, settings: NativeConsentSettings
) -> _DerivedEd25519ReceiptSigner:
    tenant = canonical_tenant_id(tenant_id)
    raw = os.environ.get(settings.receipt_key_secret_ref)
    if raw is None:
        raise NativeConsentCompositionError("native receipt key custody is unavailable")
    root = _secret_material(raw)
    context = (
        "lightwork.native-consent.receipt-ed25519.v1\0"
        f"{tenant}\0{settings.receipt_key_id}\0{settings.receipt_key_revision}"
    ).encode()
    seed = hmac.new(root, context, hashlib.sha256).digest()
    return _DerivedEd25519ReceiptSigner(
        seed,
        key_id=settings.receipt_key_id,
        key_revision=settings.receipt_key_revision,
    )


def _receipt_signer(
    app: FastAPI,
    *,
    tenant_id: str,
    settings: NativeConsentSettings,
) -> tuple[object, str]:
    factory = getattr(app.state, "consent_native_receipt_signer_factory", None)
    if factory is None:
        signer: object = _environment_receipt_signer(
            tenant_id=tenant_id,
            settings=settings,
        )
    elif callable(factory):
        try:
            signer = factory(
                tenant_id=canonical_tenant_id(tenant_id),
                key_id=settings.receipt_key_id,
                key_revision=settings.receipt_key_revision,
                secret_ref=settings.receipt_key_secret_ref,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise NativeConsentCompositionError(
                "native receipt signer is unavailable"
            ) from exc
    else:
        raise NativeConsentCompositionError("native receipt signer is unavailable")
    if (
        getattr(signer, "key_id", None) != settings.receipt_key_id
        or getattr(signer, "key_revision", None) != settings.receipt_key_revision
        or not callable(getattr(signer, "sign", None))
    ):
        raise NativeConsentCompositionError("native receipt signer authority is invalid")
    public_key = getattr(signer, "public_key_hex", None)
    if not isinstance(public_key, str):
        resolver = getattr(app.state, "consent_native_receipt_public_key_resolver", None)
        if not callable(resolver):
            raise NativeConsentCompositionError(
                "native receipt public-key authority is unavailable"
            )
        try:
            public_key = resolver(
                tenant_id=canonical_tenant_id(tenant_id),
                key_id=settings.receipt_key_id,
                key_revision=settings.receipt_key_revision,
                signer=signer,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise NativeConsentCompositionError(
                "native receipt public-key authority is unavailable"
            ) from exc
    public_hex = _digest(public_key, "native receipt public key")
    challenge = b"lightwork.native-consent.receipt-signer-readiness.v1"
    try:
        signature = signer.sign(challenge)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ValueError("invalid Ed25519 signature")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            signature, challenge
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise NativeConsentCompositionError(
            "native receipt signer and public key do not match"
        ) from exc
    return signer, public_hex


class _InjectedAttestationVerifier:
    def __init__(self, app: FastAPI) -> None:
        self._app = app

    def available(self) -> bool:
        verifier = getattr(self._app.state, "consent_native_attestation_verifier", None)
        return callable(getattr(verifier, "verify", None))

    def verify(
        self,
        evidence: NativeEnrollmentEvidence,
        attestation_material: bytes,
    ) -> object:
        verifier = getattr(self._app.state, "consent_native_attestation_verifier", None)
        method = getattr(verifier, "verify", None)
        if not callable(method):
            raise NativeConsentDenied("native platform attestation authority is unavailable")
        try:
            return method(evidence, attestation_material)
        except (KeyboardInterrupt, SystemExit):
            raise
        except (NativeConsentDenied, NativeConsentValidationError):
            raise
        except Exception as exc:
            raise NativeConsentDenied("native platform attestation failed") from exc


def _registry_for(tenant_id: str, settings: NativeConsentSettings) -> NativeConsentDeviceRegistry:
    tenant = canonical_tenant_id(tenant_id)
    return NativeConsentDeviceRegistry(
        data_dir(
            "consent_preferences",
            "consent-native-sdk.sqlite3",
            tenant=tenant,
        ),
        max_devices=settings.max_devices,
        max_requests=settings.max_requests,
    )


def _validate_directory_registry(
    record: NativeApplicationDirectoryRecord,
    registry: NativeConsentDeviceRegistry,
) -> NativeApplicationAuthority:
    authority, revision = registry.get_application(record.application_ref)
    if (
        revision != record.registry_revision
        or authority.tenant_id != record.tenant_id
        or not _same(authority.authority_sha256, record.authority_sha256)
    ):
        raise NativeConsentConflict("native application directory authority changed")
    return authority


class _RegistryMultiplexer:
    def __init__(
        self,
        directory: NativeApplicationDirectory,
        verifier: _InjectedAttestationVerifier,
        limiter: _BoundedRateLimiter,
    ) -> None:
        self._directory = directory
        self._verifier = verifier
        self._limiter = limiter

    def enroll_device(
        self,
        evidence: NativeEnrollmentEvidence,
        *,
        verifier: object,
        attestation_material: bytes,
        sdk_version: int,
    ) -> NativeDeviceAuthority:
        if verifier is not self._verifier:
            raise NativeConsentDenied("native platform attestation authority changed")
        record = self._directory.resolve(
            evidence.application_ref,
            claimed_tenant_id=evidence.tenant_id,
        )
        settings = settings_for_tenant(record.tenant_id)
        self._limiter(record.application_ref, "enroll", settings.requests_per_minute)
        registry = _registry_for(record.tenant_id, settings)
        _validate_directory_registry(record, registry)
        return registry.enroll_device(
            evidence,
            verifier=self._verifier,
            attestation_material=attestation_material,
            sdk_version=sdk_version,
        )

    def get_application(
        self, application_ref: str
    ) -> tuple[NativeApplicationAuthority, int]:
        record = self._directory.resolve(application_ref)
        settings = settings_for_tenant(record.tenant_id)
        registry = _registry_for(record.tenant_id, settings)
        authority = _validate_directory_registry(record, registry)
        return authority, record.registry_revision

    def refresh_device_authority(
        self,
        device_id: str,
        evidence: NativeEnrollmentEvidence,
        *,
        verifier: object,
        attestation_material: bytes,
        expected_revision: int,
        admitted_sdk_version: int | None = None,
    ) -> NativeDeviceAuthority:
        """Route re-attestation only after resolving the server-owned app binding."""

        if verifier is not self._verifier:
            raise NativeConsentDenied("native platform attestation authority changed")
        record = self._directory.resolve(
            evidence.application_ref,
            claimed_tenant_id=evidence.tenant_id,
        )
        settings = settings_for_tenant(record.tenant_id)
        self._limiter(record.application_ref, "refresh", settings.requests_per_minute)
        registry = _registry_for(record.tenant_id, settings)
        _validate_directory_registry(record, registry)
        return registry.refresh_device_authority(
            device_id,
            evidence,
            verifier=self._verifier,
            attestation_material=attestation_material,
            expected_revision=expected_revision,
            admitted_sdk_version=admitted_sdk_version,
        )


def _optional_callback(app: FastAPI, name: str) -> Callable[..., Mapping[str, Any]] | None:
    selected = getattr(app.state, name, None)
    if selected is None:
        return None
    if not callable(selected):
        raise NativeConsentCompositionError(f"{name} must be callable")
    return selected


class _GatewayMultiplexer:
    def __init__(
        self,
        app: FastAPI,
        directory: NativeApplicationDirectory,
        public: PublicConsentDependencies,
        limiter: _BoundedRateLimiter,
    ) -> None:
        self._app = app
        self._directory = directory
        self._public = public
        self._limiter = limiter

    def dispatch(self, envelope: NativeRequestEnvelope) -> NativeResponseReceipt:
        record = self._directory.resolve(
            envelope.application_ref,
            claimed_tenant_id=envelope.tenant_id,
        )
        settings = settings_for_tenant(record.tenant_id)
        self._limiter(record.application_ref, "dispatch", settings.requests_per_minute)
        signer, public_key = _receipt_signer(
            self._app,
            tenant_id=record.tenant_id,
            settings=settings,
        )
        if (
            record.current_key_id != settings.receipt_key_id
            or record.current_key_revision != settings.receipt_key_revision
            or not _same(record.current_public_key_hex, public_key)
        ):
            raise NativeConsentConflict("native receipt key rotation is incomplete")
        profile_linker = _optional_callback(
            self._app, "consent_native_profile_linker"
        )
        rights_requester = _optional_callback(
            self._app, "consent_native_rights_requester"
        )
        standards_verifier = _optional_callback(
            self._app, "consent_native_standards_wire_verifier"
        )
        if settings.require_profile_linking and profile_linker is None:
            raise NativeConsentDenied("native profile linking authority is unavailable")
        if settings.require_rights_requests and rights_requester is None:
            raise NativeConsentDenied("native rights-request authority is unavailable")
        if settings.standards_wire_required and standards_verifier is None:
            raise NativeConsentDenied("native consent-string verifier is unavailable")
        registry = _registry_for(record.tenant_id, settings)
        _validate_directory_registry(record, registry)
        backend = LightworkNativeConsentBackend(
            self._public,
            profile_linker=profile_linker,
            rights_requester=rights_requester,
            standards_wire_verifier=standards_verifier,
        )
        gateway = NativeConsentGateway(
            registry,
            client_authority_resolver=(
                self._public.credential_store.resolve_client_authority
            ),
            handler=backend,
            receipt_signer=signer,
        )
        return gateway.dispatch(envelope)


def _request_for(app: FastAPI, request: object, tenant_id: str, principal_ref: str) -> Request:
    if not isinstance(request, Request) or request.app is not app:
        raise NativeConsentDenied("native consent request authority is unavailable")
    tenant = canonical_tenant_id(tenant_id)
    current = current_tenant_id_strict()
    if current is None or canonical_tenant_id(current) != tenant:
        raise NativeConsentDenied("native consent tenant authority is unavailable")
    try:
        subject = authenticated_subject(
            request, error_detail="native consent principal authority is unavailable",
        )
    except HTTPException as exc:
        raise NativeConsentDenied(str(exc.detail)) from exc
    expected = "native-consent-admin-" + _text_sha256(
        f"lightwork.native-consent.identity.v1:{tenant}:{subject}"
    )[:40]
    if not _same(principal_ref, expected):
        raise NativeConsentDenied("native consent principal authority changed")
    return request


def native_consent_principal_ref(request: Request, tenant_id: str) -> str:
    tenant = canonical_tenant_id(tenant_id)
    subject = authenticated_subject(
        request,
        error_detail={
            "code": "native_consent_principal_required",
            "message": "authenticated principal authority is unavailable",
        },
    )
    return "native-consent-admin-" + _text_sha256(
        f"lightwork.native-consent.identity.v1:{tenant}:{subject}"
    )[:40]


def _resolve_admin_client(
    public: PublicConsentDependencies,
    *,
    tenant_id: str,
    credential_id: str,
) -> PublicClientBinding:
    tenant = canonical_tenant_id(tenant_id)
    selector = _ref(credential_id, "public client reference")
    path = getattr(public.credential_store, "path", None)
    if not isinstance(path, Path):
        raise NativeConsentCompositionError("public client registry path is unavailable")
    try:
        with consent_storage.reading(path) as connection:
            rows = connection.execute(
                "SELECT credential_sha256 FROM public_consent_clients "
                "WHERE tenant_id=? AND credential_id=? AND status='active' LIMIT 2",
                (tenant, selector),
            ).fetchall()
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise NativeConsentCompositionError("public client authority is unavailable") from exc
    if len(rows) != 1 or not isinstance(rows[0][0], str):
        raise NativeConsentDenied("public service client authority is unavailable")
    try:
        client = public.credential_store.resolve_client_authority(str(rows[0][0]))
    except Exception as exc:
        raise NativeConsentDenied("public service client authority is unavailable") from exc
    if (
        not isinstance(client, PublicClientBinding)
        or client.tenant_id != tenant
        or client.credential_id != selector
        or client.client_kind != "service"
        or not isinstance(client.service_client_id, str)
        or not isinstance(client.target_bundle_id, str)
        or not isinstance(client.target_platform, str)
    ):
        raise NativeConsentDenied("public service client authority is unavailable")
    return client


def _active_policy(
    public: PublicConsentDependencies,
    client: PublicClientBinding,
    *,
    evaluated_at: float,
) -> Mapping[str, Any]:
    policy = public.preference_store_for(client.tenant_id).get_active_policy(
        client.tenant_id, client.policy_id, version=client.policy_version, at=evaluated_at,
    )
    if not isinstance(policy, Mapping) or not _same(
        policy.get("policy_sha256"), client.policy_sha256
    ):
        raise NativeConsentConflict("native consent policy authority changed")
    return policy


def _derive_application_authority(
    public: PublicConsentDependencies,
    *,
    tenant_id: str,
    public_client_ref: str,
    minimum_sdk_version: int,
) -> NativeApplicationAuthority:
    tenant = canonical_tenant_id(tenant_id)
    client = _resolve_admin_client(
        public,
        tenant_id=tenant,
        credential_id=public_client_ref,
    )
    publishing = public.publishing_store_for(tenant)
    configuration = publishing.resolve_public_configuration(
        tenant,
        client.property_id,
        server_origin=client.target_origin,
        server_bundle_id=client.target_bundle_id,
        server_platform=client.target_platform,
        jurisdiction=client.jurisdiction,
        country_code=client.country_code,
        region_code=client.region_code,
        requested_locale=client.default_locale,
    )
    property_binding = configuration.get("property") if isinstance(configuration, Mapping) else None
    publication = configuration.get("publication") if isinstance(configuration, Mapping) else None
    rule = configuration.get("rule") if isinstance(configuration, Mapping) else None
    if (
        not isinstance(configuration, Mapping)
        or configuration.get("allowed") is not True
        or not isinstance(property_binding, Mapping)
        or not isinstance(publication, Mapping)
        or not isinstance(rule, Mapping)
        or property_binding.get("property_id") != client.property_id
        or property_binding.get("revision") != client.property_revision
        or not _same(publication.get("publication_sha256"), client.publication_sha256)
        or not _same(publication.get("bundle_sha256"), client.bundle_sha256)
    ):
        raise NativeConsentConflict("published native consent authority changed")
    evaluated_at = float(configuration.get("evaluated_at", math.nan))
    if not math.isfinite(evaluated_at) or evaluated_at <= 0:
        raise NativeConsentCompositionError("published native consent time is invalid")
    policy = _active_policy(public, client, evaluated_at=evaluated_at)
    content = configuration.get("configuration")
    purposes = content.get("purposes") if isinstance(content, Mapping) else None
    notice = content.get("notice") if isinstance(content, Mapping) else None
    if not isinstance(purposes, list) or not isinstance(notice, Mapping):
        raise NativeConsentCompositionError("published native consent content is unavailable")
    published: dict[str, str] = {}
    for item in purposes:
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("id"), str)
            or item["id"] in published
        ):
            raise NativeConsentCompositionError(
                "published native consent purposes are invalid"
            )
        published[str(item["id"])] = str(item.get("lawful_basis", ""))
    if published != policy.get("purposes") or not _same(
        notice.get("document_sha256"), policy.get("notice_sha256")
    ):
        raise NativeConsentConflict("published native consent policy changed")
    preview = publishing.preview(
        tenant,
        client.property_id,
        client.rule_group_id,
        client.rule_group_version,
    )
    bundle = preview.get("bundle") if isinstance(preview, Mapping) else None
    preview_property = bundle.get("property") if isinstance(bundle, Mapping) else None
    group = bundle.get("rule_group") if isinstance(bundle, Mapping) else None
    group_payload = group.get("payload") if isinstance(group, Mapping) else None
    rules = group_payload.get("rules") if isinstance(group_payload, Mapping) else None
    if (
        not isinstance(bundle, Mapping)
        or not _same(preview.get("bundle_sha256"), client.bundle_sha256)
        or not isinstance(preview_property, Mapping)
        or preview_property.get("revision") != client.property_revision
        or not _same(preview_property.get("record_sha256"), client.property_sha256)
        or not isinstance(rules, list)
        or len(rules) > 1_000
    ):
        raise NativeConsentConflict("native publication preview authority changed")
    selected = [
        item
        for item in rules
        if isinstance(item, Mapping)
        and item.get("rule_id") == rule.get("rule_id")
        and _same(item.get("rule_sha256"), rule.get("rule_sha256"))
    ]
    if len(selected) != 1:
        raise NativeConsentConflict("native publication rule authority changed")
    locales = selected[0].get("locales")
    default_locale = selected[0].get("default_locale")
    if (
        not isinstance(locales, list)
        or not all(isinstance(item, str) for item in locales)
        or not isinstance(default_locale, str)
    ):
        raise NativeConsentCompositionError("native publication locales are unavailable")
    config = _load_tenant_config(tenant)
    return NativeApplicationAuthority(
        application_ref=str(client.service_client_id),
        tenant_id=tenant,
        property_id=client.property_id,
        application_id=str(client.target_bundle_id),
        platform=str(client.target_platform),
        public_client_credential_sha256=client.credential_sha256,
        public_client_revision=client.revision,
        public_client_record_sha256=client.record_sha256,
        property_revision=client.property_revision,
        property_sha256=client.property_sha256,
        publication_sha256=client.publication_sha256,
        publication_bundle_sha256=client.bundle_sha256,
        configuration_sha256=str(configuration["configuration_sha256"]),
        policy_id=client.policy_id,
        policy_version=client.policy_version,
        policy_sha256=client.policy_sha256,
        standards_contract_sha256=_standards_contract_sha256(config),
        minimum_sdk_version=_integer(
            minimum_sdk_version, "minimum_sdk_version", 1, 1_000_000
        ),
        default_locale=default_locale,
        locales=tuple(locales),
    )


def _device_authority(
    registry: NativeConsentDeviceRegistry,
    *,
    application_ref: str,
    device_id: str,
    expected_revision: int,
) -> NativeDeviceAuthority:
    app_ref = _ref(application_ref, "application_ref")
    device_ref = _ref(device_id, "device_id")
    expected = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
    path = registry.path
    try:
        with consent_storage.reading(path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM native_consent_devices WHERE device_id=? "
                "AND application_ref=? AND status='active'",
                (device_ref, app_ref),
            ).fetchone()
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise NativeConsentCompositionError("native device authority is unavailable") from exc
    if row is None or int(row["revision"]) != expected:
        raise NativeConsentConflict("native device authority revision changed")
    return NativeDeviceAuthority(
        device_id=str(row["device_id"]),
        application_ref=str(row["application_ref"]),
        application_authority_sha256=str(row["application_authority_sha256"]),
        tenant_id=str(row["tenant_id"]),
        application_id=str(row["application_id"]),
        platform=str(row["platform"]),
        install_subject_sha256=str(row["install_subject_sha256"]),
        public_key_hex=str(row["public_key_hex"]),
        key_revision=int(row["key_revision"]),
        sdk_version=int(row["sdk_version"]),
        revision=int(row["revision"]),
        attestation_authority=str(row["attestation_authority"]),
        attestation_evidence_sha256=str(row["attestation_evidence_sha256"]),
        attestation_valid_until=float(row["attestation_valid_until"]),
        created_at=float(row["created_at"]),
    )


_MAX_LISTED_DEVICES = 500


def list_native_applications(
    directory: NativeApplicationDirectory,
    registry: NativeConsentDeviceRegistry,
    *,
    tenant_id: str,
    limit: int,
) -> dict[str, Any]:
    """Safe, read-only rows for the tenant's registered native applications.

    Every row is re-validated against the tenant-private registry, so a row
    that no longer matches its directory binding fails closed rather than
    being listed. No key material other than the public key identity is shown.
    """

    items: list[dict[str, Any]] = []
    for record in directory.records_for_tenant(tenant_id, limit=limit):
        authority = _validate_directory_registry(record, registry)
        items.append(
            {
                "application_ref": record.application_ref,
                "application_id": authority.application_id,
                "platform": authority.platform,
                "property_id": authority.property_id,
                "minimum_sdk_version": authority.minimum_sdk_version,
                "default_locale": authority.default_locale,
                "directory_revision": record.directory_revision,
                "current_key_id": record.current_key_id,
                "current_key_revision": record.current_key_revision,
            }
        )
    return {"items": items}


def list_native_devices(
    registry: NativeConsentDeviceRegistry,
    *,
    application_ref: str,
    limit: int = _MAX_LISTED_DEVICES,
) -> dict[str, Any]:
    """Read-only device rows for one application; no key or install subject."""

    app_ref = _ref(application_ref, "application_ref")
    bound = _integer(limit, "native device list limit", 1, _MAX_LISTED_DEVICES)
    path = registry.path
    try:
        with consent_storage.reading(path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT device_id,platform,sdk_version,revision,status,created_at,"
                "updated_at,attestation_valid_until FROM native_consent_devices "
                "WHERE application_ref=? ORDER BY status, created_at DESC, device_id LIMIT ?",
                (app_ref, bound + 1),
            ).fetchall()
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise NativeConsentCompositionError("native device registry is unavailable") from exc
    items = [
        {
            "device_id": _ref(row["device_id"], "device_id"),
            "platform": str(row["platform"]),
            "sdk_version": int(row["sdk_version"]),
            "revision": int(row["revision"]),
            "status": "revoked" if row["status"] == "revoked" else "active",
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
            "attestation_valid_until": float(row["attestation_valid_until"]),
        }
        for row in rows[:bound]
    ]
    return {"items": items, "truncated": len(rows) > bound}


def attach_consent_native_composition(  # noqa: C901 - explicit deployment seam checks
    app: FastAPI,
    *,
    public_dependencies: PublicConsentDependencies,
) -> NativeConsentSDKAPIDependencies:
    """Install production seams and return dependencies for the public router."""

    if not isinstance(app, FastAPI):
        raise TypeError("native consent composition requires a FastAPI app")
    if not isinstance(public_dependencies, PublicConsentDependencies):
        raise TypeError("native consent composition requires public consent dependencies")
    marker = "_consent_native_composition_attached"
    if getattr(app.state, marker, False) is True:
        dependencies = getattr(app.state, "consent_native_public_dependencies", None)
        if not isinstance(dependencies, NativeConsentSDKAPIDependencies):
            raise NativeConsentCompositionError("native consent composition state changed")
        return dependencies
    directory = NativeApplicationDirectory(
        data_dir(
            "consent_public_api",
            "native-consent-application-directory.sqlite3",
            tenant=None,
        )
    )
    limiter = _BoundedRateLimiter()
    verifier = _InjectedAttestationVerifier(app)
    registry = _RegistryMultiplexer(directory, verifier, limiter)
    gateway = _GatewayMultiplexer(app, directory, public_dependencies, limiter)

    # Replaying the audit chain grows with the fleet, so rather than run it for
    # every anonymous request, share one replay across a short window.
    directory_intact = _TimedVerdict(
        directory.verify_integrity,
        pass_seconds=_GATE_INTEGRITY_PASS_SECONDS,
        fail_seconds=_GATE_INTEGRITY_FAIL_SECONDS,
        revision=directory.integrity_revision,
    )

    def public_gate() -> bool:
        try:
            return (
                verifier.available()
                and directory.has_active_application()
                and directory_intact()
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False

    dependencies = NativeConsentSDKAPIDependencies(
        gate=public_gate,
        registry=registry,  # type: ignore[arg-type]
        attestation_verifier=verifier,  # type: ignore[arg-type]
        gateway=gateway,  # type: ignore[arg-type]
        rate_limit=limiter,
    )

    def register_application(
        *,
        request: object,
        tenant_id: str,
        principal_ref: str,
        public_client_ref: str,
        minimum_sdk_version: int,
        expected_revision: int,
    ) -> dict[str, Any]:
        _request_for(app, request, tenant_id, principal_ref)
        settings = settings_for_tenant(tenant_id)
        _signer, public_key = _receipt_signer(
            app, tenant_id=tenant_id, settings=settings
        )
        authority = _derive_application_authority(
            public_dependencies,
            tenant_id=tenant_id,
            public_client_ref=public_client_ref,
            minimum_sdk_version=minimum_sdk_version,
        )
        tenant_registry = _registry_for(tenant_id, settings)
        result = directory.register_new(
            authority,
            registry=tenant_registry,
            settings=settings,
            public_key_hex=public_key,
            expected_revision=expected_revision,
        )
        return {
            **result,
            "authority": {
                **authority.normalized(),
                "authority_sha256": authority.authority_sha256,
            },
            "authority_updates_require_new_application_ref": True,
        }

    def rotate_receipt_key(
        *,
        request: object,
        tenant_id: str,
        principal_ref: str,
        application_ref: str,
        expected_directory_revision: int,
    ) -> dict[str, Any]:
        _request_for(app, request, tenant_id, principal_ref)
        settings = settings_for_tenant(tenant_id)
        record = directory.resolve(application_ref, claimed_tenant_id=tenant_id)
        registry_for_tenant = _registry_for(tenant_id, settings)
        _validate_directory_registry(record, registry_for_tenant)
        _signer, public_key = _receipt_signer(
            app, tenant_id=tenant_id, settings=settings
        )
        return directory.rotate_receipt_key(
            application_ref,
            tenant_id=tenant_id,
            expected_directory_revision=expected_directory_revision,
            key_id=settings.receipt_key_id,
            key_revision=settings.receipt_key_revision,
            public_key_hex=public_key,
        )

    def rotate_device(
        *,
        request: object,
        tenant_id: str,
        principal_ref: str,
        application_ref: str,
        device_id: str,
        expected_revision: int,
        public_key_hex: str,
        attestation_nonce: str,
        attestation_evidence_sha256: str,
        attestation_material: bytes,
        issued_at: float,
        expires_at: float,
    ) -> dict[str, Any]:
        _request_for(app, request, tenant_id, principal_ref)
        settings = settings_for_tenant(tenant_id)
        record = directory.resolve(application_ref, claimed_tenant_id=tenant_id)
        tenant_registry = _registry_for(tenant_id, settings)
        authority = _validate_directory_registry(record, tenant_registry)
        device = _device_authority(
            tenant_registry,
            application_ref=record.application_ref,
            device_id=device_id,
            expected_revision=expected_revision,
        )
        if not _same(device.application_authority_sha256, authority.authority_sha256):
            raise NativeConsentConflict("native device application authority changed")
        evidence = NativeEnrollmentEvidence(
            application_ref=record.application_ref,
            tenant_id=record.tenant_id,
            application_id=authority.application_id,
            platform=authority.platform,
            install_subject_sha256=device.install_subject_sha256,
            public_key_hex=public_key_hex,
            attestation_nonce=attestation_nonce,
            attestation_evidence_sha256=attestation_evidence_sha256,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        rotated = tenant_registry.rotate_device_key(
            device.device_id,
            evidence,
            verifier=verifier,
            attestation_material=attestation_material,
            expected_revision=expected_revision,
        )
        return asdict(rotated)

    def revoke_device(
        *,
        request: object,
        tenant_id: str,
        principal_ref: str,
        application_ref: str,
        device_id: str,
        expected_revision: int,
        evidence_sha256: str,
    ) -> dict[str, Any]:
        _request_for(app, request, tenant_id, principal_ref)
        settings = settings_for_tenant(tenant_id)
        record = directory.resolve(application_ref, claimed_tenant_id=tenant_id)
        tenant_registry = _registry_for(tenant_id, settings)
        _validate_directory_registry(record, tenant_registry)
        _device_authority(
            tenant_registry,
            application_ref=record.application_ref,
            device_id=device_id,
            expected_revision=expected_revision,
        )
        return tenant_registry.revoke_device(
            device_id,
            expected_revision=expected_revision,
            evidence_sha256=evidence_sha256,
        )

    def readiness(*, request: object, tenant_id: str, principal_ref: str) -> dict[str, Any]:
        _request_for(app, request, tenant_id, principal_ref)
        reasons: list[str] = []
        try:
            settings = settings_for_tenant(tenant_id)
        except Exception:
            return {
                "schema": "lightwork.native-consent-readiness.v1",
                "enabled": False,
                "ready": False,
                "reasons": ["configuration_unavailable"],
            }
        if not verifier.available():
            reasons.append("attestation_verifier_unavailable")
        try:
            _signer, public_key = _receipt_signer(
                app, tenant_id=tenant_id, settings=settings
            )
        except Exception:
            public_key = None
            reasons.append("receipt_signer_unavailable")
        profile = getattr(app.state, "consent_native_profile_linker", None)
        rights = getattr(app.state, "consent_native_rights_requester", None)
        standards = getattr(app.state, "consent_native_standards_wire_verifier", None)
        if settings.require_profile_linking and not callable(profile):
            reasons.append("profile_linker_unavailable")
        if settings.require_rights_requests and not callable(rights):
            reasons.append("rights_requester_unavailable")
        if settings.standards_wire_required and not callable(standards):
            reasons.append("standards_wire_verifier_unavailable")
        try:
            with tenant_scope(tenant=canonical_tenant_id(tenant_id)):
                if public_dependencies.gate() is not True:
                    reasons.append("public_consent_authority_unavailable")
        except Exception:
            reasons.append("public_consent_authority_unavailable")
        try:
            if directory.verify_integrity() is not True:
                reasons.append("application_directory_integrity_failed")
            records = directory.records_for_tenant(
                tenant_id, limit=settings.max_applications
            )
        except Exception:
            records = ()
            reasons.append("application_directory_unavailable")
        if not records:
            reasons.append("application_registration_required")
        try:
            tenant_registry = _registry_for(tenant_id, settings)
            if tenant_registry.verify_integrity().get("valid") is not True:
                reasons.append("device_registry_integrity_failed")
            for record in records:
                authority = _validate_directory_registry(record, tenant_registry)
                client = public_dependencies.credential_store.resolve_client_authority(
                    authority.public_client_credential_sha256
                )
                if not isinstance(client, PublicClientBinding):
                    raise NativeConsentCompositionError(
                        "public client authority is invalid"
                    )
                if (
                    record.current_key_id != settings.receipt_key_id
                    or record.current_key_revision != settings.receipt_key_revision
                    or public_key is None
                    or not _same(record.current_public_key_hex, public_key)
                ):
                    reasons.append("receipt_key_rotation_incomplete")
                    break
        except Exception:
            reasons.append("registered_application_authority_unavailable")
        return {
            "schema": "lightwork.native-consent-readiness.v1",
            "enabled": True,
            "ready": not reasons,
            "applications": len(records),
            "reasons": list(dict.fromkeys(reasons)),
            "profile_linking_required": settings.require_profile_linking,
            "rights_requests_required": settings.require_rights_requests,
            "standards_wire_verification_required": settings.standards_wire_required,
        }

    def integrity(*, request: object, tenant_id: str, principal_ref: str) -> dict[str, Any]:
        _request_for(app, request, tenant_id, principal_ref)
        settings = settings_for_tenant(tenant_id)
        directory.verify_integrity()
        records = directory.records_for_tenant(
            tenant_id, limit=settings.max_applications
        )
        tenant_registry = _registry_for(tenant_id, settings)
        registry_result = tenant_registry.verify_integrity()
        for record in records:
            _validate_directory_registry(record, tenant_registry)
            directory.receipt_keys(record.application_ref)
        return {
            "schema": "lightwork.native-consent-production-integrity.v1",
            "valid": registry_result.get("valid") is True,
            "applications": len(records),
            "registry": registry_result,
            "directory_valid": True,
        }

    def applications(*, request: object, tenant_id: str, principal_ref: str) -> dict[str, Any]:
        _request_for(app, request, tenant_id, principal_ref)
        settings = settings_for_tenant(tenant_id)
        return list_native_applications(
            directory,
            _registry_for(tenant_id, settings),
            tenant_id=tenant_id,
            limit=settings.max_applications,
        )

    def devices(
        *,
        request: object,
        tenant_id: str,
        principal_ref: str,
        application_ref: str,
    ) -> dict[str, Any]:
        _request_for(app, request, tenant_id, principal_ref)
        settings = settings_for_tenant(tenant_id)
        record = directory.resolve(application_ref, claimed_tenant_id=tenant_id)
        tenant_registry = _registry_for(tenant_id, settings)
        _validate_directory_registry(record, tenant_registry)
        return list_native_devices(tenant_registry, application_ref=record.application_ref)

    def public_receipt_keys(application_ref: str) -> dict[str, Any]:
        record = directory.resolve(application_ref)
        settings = settings_for_tenant(record.tenant_id)
        tenant_registry = _registry_for(record.tenant_id, settings)
        _validate_directory_registry(record, tenant_registry)
        return directory.receipt_keys(record.application_ref)

    app.state.consent_native_public_dependencies = dependencies
    app.state.consent_native_public_rate_limit = limiter
    app.state.consent_native_admin_register = register_application
    app.state.consent_native_admin_rotate_receipt_key = rotate_receipt_key
    app.state.consent_native_admin_rotate_device = rotate_device
    app.state.consent_native_admin_revoke_device = revoke_device
    app.state.consent_native_admin_readiness = readiness
    app.state.consent_native_admin_integrity = integrity
    app.state.consent_native_admin_applications = applications
    app.state.consent_native_admin_devices = devices
    app.state.consent_native_public_receipt_keys = public_receipt_keys
    app.state.consent_native_enabled_probe = native_consent_enabled
    setattr(app.state, marker, True)
    return dependencies


__all__ = [
    "NativeApplicationDirectory",
    "NativeApplicationDirectoryRecord",
    "NativeConsentCompositionError",
    "NativeConsentSettings",
    "attach_consent_native_composition",
    "list_native_applications",
    "list_native_devices",
    "native_consent_enabled",
    "native_consent_principal_ref",
    "native_consent_settings",
    "settings_for_tenant",
]
