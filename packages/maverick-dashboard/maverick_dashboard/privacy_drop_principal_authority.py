"""Versioned principal-binding key authority for California DROP.

Only secret-provider references and SHA-256 bindings are durable.  Key bytes
are fetched for the shortest possible operation and are never returned or
written to SQLite.  Current and previous revisions can verify retained
evidence; retired, revoked and unknown revisions fail closed.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maverick.file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from maverick.paths import canonical_tenant_id
from maverick.privacy_drop_management import (
    DROPManagementConfigError,
    DROPManagementConflict,
    DROPManagementIntegrityError,
    DROPManagementNotFound,
    DROPManagementValidationError,
    DROPPrincipalBinding,
)
from maverick.sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
_ACTIVE_STATES = frozenset({"current", "previous"})
_ALL_STATES = _ACTIVE_STATES | {"retired", "revoked"}
_DIGEST_RE = __import__("re").compile(r"[0-9a-f]{64}\Z")
_REF_RE = __import__("re").compile(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,255}\Z")
_KEY_REF_RE = __import__("re").compile(
    r"(?:env:[A-Z][A-Z0-9_]{0,127}|"
    r"(?:kms|secret|vault|aws-kms|azure-keyvault|gcp-kms)://"
    r"[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,239})\Z"
)
_MAX_JSON_BYTES = 64 * 1024


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
        raise DROPManagementValidationError("DROP key metadata must be finite JSON") from exc
    if not 1 <= len(encoded) <= _MAX_JSON_BYTES:
        raise DROPManagementValidationError("DROP key metadata exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise DROPManagementValidationError(f"{label} is not a closed reference")
    return value


def _key_ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not _KEY_REF_RE.fullmatch(value):
        raise DROPManagementValidationError(f"{label} is not a secret-provider reference")
    return value


def _revision(value: object, label: str = "key_revision") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**31 - 1:
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
class DROPPrincipalKeyRevision:
    revision: int
    state: str
    key_ref_sha256: str
    created_at: float
    changed_at: float
    integrity_sha256: str


class DROPPrincipalKeyAuthority:
    """Tenant-bound, durable current/previous keyring with explicit lifecycle."""

    def __init__(  # noqa: PLR0913 - trust seams are intentionally explicit
        self,
        path: str | Path,
        *,
        tenant_id: str,
        initial_key_ref: str,
        secret_resolver: Callable[[str, str], bytes],
        dependency_counter: Callable[[int], int] = lambda _revision: 0,
        config_gate: Callable[[], None] = lambda: None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not all(callable(value) for value in (secret_resolver, dependency_counter, config_gate, clock)):
            raise DROPManagementConfigError("DROP key authority dependencies are incomplete")
        try:
            config_gate()
        except Exception as exc:
            raise DROPManagementConfigError("DROP key authority configuration is unavailable") from exc
        self.path = Path(path)
        self.tenant_id = canonical_tenant_id(tenant_id)
        self._initial_key_ref = _key_ref(initial_key_ref, "initial_key_ref")
        self._secret_resolver = secret_resolver
        self._dependency_counter = dependency_counter
        self._gate = config_gate
        self._clock = clock
        self._maintenance = threading.local()
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self) -> None:
        now = _timestamp(self._clock(), "current time")
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS drop_principal_key_meta(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS drop_principal_key_revisions(
                    tenant_id TEXT NOT NULL,revision INTEGER NOT NULL,state TEXT NOT NULL,
                    key_ref TEXT NOT NULL,key_ref_sha256 TEXT NOT NULL,created_at REAL NOT NULL,
                    changed_at REAL NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,PRIMARY KEY(tenant_id,revision)
                );
                CREATE TABLE IF NOT EXISTS drop_principal_key_operations(
                    tenant_id TEXT NOT NULL,action TEXT NOT NULL,key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_json TEXT NOT NULL,created_at REAL NOT NULL,
                    integrity_sha256 TEXT NOT NULL,PRIMARY KEY(tenant_id,action,key_sha256)
                );
                CREATE TABLE IF NOT EXISTS drop_principal_key_migrations(
                    tenant_id TEXT NOT NULL,migration_id TEXT NOT NULL,from_revision INTEGER NOT NULL,
                    to_revision INTEGER NOT NULL,objects_migrated INTEGER NOT NULL,
                    remaining_dependencies INTEGER NOT NULL,actor_binding_sha256 TEXT NOT NULL,
                    reviewer_binding_sha256 TEXT NOT NULL,actor_key_revision INTEGER NOT NULL,
                    reviewer_key_revision INTEGER NOT NULL,created_at REAL NOT NULL,
                    integrity_sha256 TEXT NOT NULL,PRIMARY KEY(tenant_id,migration_id)
                );
                CREATE TRIGGER IF NOT EXISTS drop_principal_key_revisions_no_delete
                    BEFORE DELETE ON drop_principal_key_revisions
                    BEGIN SELECT RAISE(ABORT,'immutable DROP key revision'); END;
                CREATE TRIGGER IF NOT EXISTS drop_principal_key_operations_no_update
                    BEFORE UPDATE ON drop_principal_key_operations
                    BEGIN SELECT RAISE(ABORT,'immutable DROP key operation'); END;
                CREATE TRIGGER IF NOT EXISTS drop_principal_key_operations_no_delete
                    BEFORE DELETE ON drop_principal_key_operations
                    BEGIN SELECT RAISE(ABORT,'immutable DROP key operation'); END;
                CREATE TRIGGER IF NOT EXISTS drop_principal_key_migrations_no_update
                    BEFORE UPDATE ON drop_principal_key_migrations
                    BEGIN SELECT RAISE(ABORT,'immutable DROP key migration'); END;
                CREATE TRIGGER IF NOT EXISTS drop_principal_key_migrations_no_delete
                    BEFORE DELETE ON drop_principal_key_migrations
                    BEGIN SELECT RAISE(ABORT,'immutable DROP key migration'); END;
                """
            )
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, SCHEMA_VERSION):
                raise DROPManagementConfigError(
                    f"unsupported DROP principal key schema version {version}"
                )
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            tenant_sha256 = _text_sha256(self.tenant_id)
            connection.execute(
                "INSERT OR IGNORE INTO drop_principal_key_meta(key,value) VALUES('tenant_sha256',?)",
                (tenant_sha256,),
            )
            binding = connection.execute(
                "SELECT value FROM drop_principal_key_meta WHERE key='tenant_sha256'"
            ).fetchone()
            if binding is None or not _same(binding[0], tenant_sha256):
                raise DROPManagementIntegrityError("DROP keyring belongs to another tenant")
            foreign = connection.execute(
                "SELECT EXISTS(SELECT 1 FROM drop_principal_key_revisions WHERE tenant_id<>?) "
                "OR EXISTS(SELECT 1 FROM drop_principal_key_operations WHERE tenant_id<>?) "
                "OR EXISTS(SELECT 1 FROM drop_principal_key_migrations WHERE tenant_id<>?)",
                (self.tenant_id, self.tenant_id, self.tenant_id),
            ).fetchone()
            if foreign is None or int(foreign[0]) != 0:
                raise DROPManagementIntegrityError("DROP keyring contains another tenant")
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM drop_principal_key_revisions WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchone()[0]
            )
            if count == 0:
                self._resolve_secret(self._initial_key_ref)
                payload = {
                    "tenant_id": self.tenant_id,
                    "revision": 1,
                    "state": "current",
                    "key_ref_sha256": _text_sha256(self._initial_key_ref),
                    "created_at": now,
                    "changed_at": now,
                }
                connection.execute(
                    "INSERT INTO drop_principal_key_revisions VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        self.tenant_id,
                        1,
                        "current",
                        self._initial_key_ref,
                        payload["key_ref_sha256"],
                        now,
                        now,
                        _canonical(payload).decode("ascii"),
                        _sha256(payload),
                    ),
                )
            connection.commit()
        ensure_private_file(self.path)

    def _resolve_secret(self, key_ref: str) -> bytes:
        try:
            value = self._secret_resolver(self.tenant_id, key_ref)
        except Exception as exc:
            raise DROPManagementConfigError("DROP principal key secret is unavailable") from exc
        if not isinstance(value, bytes) or len(value) < 32:
            raise DROPManagementConfigError("DROP principal key secret is unavailable")
        return value

    @staticmethod
    def _row_payload(row: sqlite3.Row) -> dict[str, Any]:
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, ValueError) as exc:
            raise DROPManagementIntegrityError("stored DROP key revision is invalid") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("tenant_id") != row["tenant_id"]
            or payload.get("revision") != row["revision"]
            or payload.get("state") != row["state"]
            or payload.get("key_ref_sha256") != row["key_ref_sha256"]
            or payload.get("created_at") != row["created_at"]
            or payload.get("changed_at") != row["changed_at"]
            or not _same(_sha256(payload), row["integrity_sha256"])
            or not _same(_text_sha256(str(row["key_ref"])), row["key_ref_sha256"])
        ):
            raise DROPManagementIntegrityError("stored DROP key revision changed")
        return payload

    def _row(self, revision: int) -> sqlite3.Row:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM drop_principal_key_revisions WHERE tenant_id=? AND revision=?",
                (self.tenant_id, _revision(revision)),
            ).fetchone()
        if row is None:
            raise DROPManagementNotFound("DROP principal key revision was not found")
        self._row_payload(row)
        return row

    def current_revision(self) -> int:
        self._gate()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT revision FROM drop_principal_key_revisions "
                "WHERE tenant_id=? AND state='current' ORDER BY revision",
                (self.tenant_id,),
            ).fetchall()
        if len(rows) != 1:
            raise DROPManagementIntegrityError("DROP keyring current authority is invalid")
        return int(rows[0][0])

    def require_active_revision(self, revision: int) -> None:
        row = self._row(revision)
        if str(row["state"]) not in _ACTIVE_STATES:
            raise DROPManagementConflict("DROP principal key revision is not active")
        self._resolve_secret(str(row["key_ref"]))

    def bind(self, tenant_id: str, principal_ref: str, revision: int | None = None) -> DROPPrincipalBinding:
        self._gate()
        if canonical_tenant_id(tenant_id) != self.tenant_id:
            raise DROPManagementNotFound("DROP principal authority was not found")
        principal = _ref(principal_ref, "principal_ref")
        selected = self.current_revision() if revision is None else _revision(revision)
        row = self._row(selected)
        if str(row["state"]) not in _ACTIVE_STATES:
            raise DROPManagementConflict("DROP principal key revision is not active")
        secret = self._resolve_secret(str(row["key_ref"]))
        digest = hmac.new(
            secret,
            (
                "lightwork.privacy-drop.principal-binding.v2:"
                f"{self.tenant_id}:{selected}:{principal}"
            ).encode(),
            hashlib.sha256,
        ).hexdigest()
        return DROPPrincipalBinding(digest, selected)

    def verify(
        self,
        tenant_id: str,
        principal_ref: str,
        revision: int,
        binding_sha256: str,
    ) -> bool:
        try:
            expected = self.bind(tenant_id, principal_ref, revision)
            return _same(expected.binding_sha256, binding_sha256)
        except (DROPManagementConfigError, DROPManagementConflict, DROPManagementNotFound):
            return False

    def _independent(self, actor_ref: str, reviewer_ref: str) -> tuple[DROPPrincipalBinding, DROPPrincipalBinding]:
        actor = self.bind(self.tenant_id, actor_ref)
        reviewer = self.bind(self.tenant_id, reviewer_ref)
        if _same(actor.binding_sha256, reviewer.binding_sha256):
            raise DROPManagementConflict("independent DROP key approval is required")
        return actor, reviewer

    def _operation_replay(
        self,
        connection: sqlite3.Connection,
        action: str,
        idempotency_key: str,
        request_sha256: str,
    ) -> Mapping[str, object] | None:
        key_sha256 = _text_sha256(_ref(idempotency_key, "idempotency_key"))
        row = connection.execute(
            "SELECT * FROM drop_principal_key_operations WHERE tenant_id=? AND action=? "
            "AND key_sha256=?",
            (self.tenant_id, action, key_sha256),
        ).fetchone()
        if row is None:
            return None
        body = {
            "tenant_id": str(row["tenant_id"]),
            "action": str(row["action"]),
            "key_sha256": str(row["key_sha256"]),
            "request_sha256": str(row["request_sha256"]),
            "result_json": str(row["result_json"]),
            "created_at": float(row["created_at"]),
        }
        if not _same(_sha256(body), row["integrity_sha256"]):
            raise DROPManagementIntegrityError("stored DROP key operation changed")
        if not _same(request_sha256, row["request_sha256"]):
            raise DROPManagementConflict("idempotency key is bound to another key operation")
        result = json.loads(str(row["result_json"]))
        if not isinstance(result, Mapping):
            raise DROPManagementIntegrityError("stored DROP key result is invalid")
        return result

    def _append_operation(
        self,
        connection: sqlite3.Connection,
        *,
        action: str,
        idempotency_key: str,
        request_sha256: str,
        result: Mapping[str, object],
        created_at: float,
    ) -> None:
        body = {
            "tenant_id": self.tenant_id,
            "action": action,
            "key_sha256": _text_sha256(_ref(idempotency_key, "idempotency_key")),
            "request_sha256": request_sha256,
            "result_json": _canonical(dict(result)).decode("ascii"),
            "created_at": created_at,
        }
        connection.execute(
            "INSERT INTO drop_principal_key_operations VALUES(?,?,?,?,?,?,?)",
            (*body.values(), _sha256(body)),
        )

    def rotate(  # noqa: PLR0913 - explicit key ceremony inputs
        self,
        *,
        new_key_ref: str,
        expected_current_revision: int,
        actor_ref: str,
        reviewer_ref: str,
        idempotency_key: str,
    ) -> DROPPrincipalKeyRevision:
        self._gate()
        key_ref = _key_ref(new_key_ref, "new_key_ref")
        expected = _revision(expected_current_revision, "expected_current_revision")
        self._resolve_secret(key_ref)
        actor, reviewer = self._independent(actor_ref, reviewer_ref)
        now = _timestamp(self._clock(), "current time")
        request = {
            "new_key_ref_sha256": _text_sha256(key_ref),
            "expected_current_revision": expected,
            "actor_binding_sha256": actor.binding_sha256,
            "reviewer_binding_sha256": reviewer.binding_sha256,
            "actor_key_revision": actor.key_revision,
            "reviewer_key_revision": reviewer.key_revision,
        }
        request_sha256 = _sha256(request)
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._operation_replay(
                connection, "rotate", idempotency_key, request_sha256
            )
            if replay is not None:
                connection.rollback()
                return self._public(replay)
            current = connection.execute(
                "SELECT * FROM drop_principal_key_revisions WHERE tenant_id=? "
                "AND state='current'",
                (self.tenant_id,),
            ).fetchall()
            if len(current) != 1 or int(current[0]["revision"]) != expected:
                raise DROPManagementConflict("DROP key current revision changed")
            if _same(current[0]["key_ref_sha256"], _text_sha256(key_ref)):
                raise DROPManagementConflict("DROP key reference did not rotate")
            current_payload = self._row_payload(current[0])
            current_payload.update({"state": "previous", "changed_at": now})
            connection.execute(
                "UPDATE drop_principal_key_revisions SET state='previous',changed_at=?,"
                "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND revision=? "
                "AND state='current'",
                (
                    now,
                    _canonical(current_payload).decode("ascii"),
                    _sha256(current_payload),
                    self.tenant_id,
                    expected,
                ),
            )
            revision = expected + 1
            payload = {
                "tenant_id": self.tenant_id,
                "revision": revision,
                "state": "current",
                "key_ref_sha256": _text_sha256(key_ref),
                "created_at": now,
                "changed_at": now,
            }
            connection.execute(
                "INSERT INTO drop_principal_key_revisions VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    self.tenant_id,
                    revision,
                    "current",
                    key_ref,
                    payload["key_ref_sha256"],
                    now,
                    now,
                    _canonical(payload).decode("ascii"),
                    _sha256(payload),
                ),
            )
            self._append_operation(
                connection,
                action="rotate",
                idempotency_key=idempotency_key,
                request_sha256=request_sha256,
                result=payload,
                created_at=now,
            )
            connection.commit()
        return self._public(payload)

    def retire(  # noqa: PLR0913 - explicit lifecycle authority
        self,
        revision: int,
        *,
        expected_state: str,
        actor_ref: str,
        reviewer_ref: str,
        idempotency_key: str,
        revoke: bool = False,
    ) -> DROPPrincipalKeyRevision:
        self._gate()
        selected = _revision(revision)
        if expected_state != "previous":
            raise DROPManagementValidationError("only a previous DROP key can retire")
        actor, reviewer = self._independent(actor_ref, reviewer_ref)
        dependencies = self._dependency_counter(selected)
        if isinstance(dependencies, bool) or not isinstance(dependencies, int) or dependencies < 0:
            raise DROPManagementConfigError("DROP key dependency count is unavailable")
        if dependencies:
            raise DROPManagementConflict("retained DROP records still depend on this key revision")
        now = _timestamp(self._clock(), "current time")
        action = "revoke" if revoke else "retire"
        result_state = "revoked" if revoke else "retired"
        request = {
            "revision": selected,
            "expected_state": expected_state,
            "result_state": result_state,
            "actor_binding_sha256": actor.binding_sha256,
            "reviewer_binding_sha256": reviewer.binding_sha256,
            "actor_key_revision": actor.key_revision,
            "reviewer_key_revision": reviewer.key_revision,
        }
        request_sha256 = _sha256(request)
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._operation_replay(connection, action, idempotency_key, request_sha256)
            if replay is not None:
                connection.rollback()
                return self._public(replay)
            row = connection.execute(
                "SELECT * FROM drop_principal_key_revisions WHERE tenant_id=? AND revision=?",
                (self.tenant_id, selected),
            ).fetchone()
            if row is None or str(row["state"]) != expected_state:
                raise DROPManagementConflict("DROP key revision state changed")
            payload = self._row_payload(row)
            payload.update({"state": result_state, "changed_at": now})
            updated = connection.execute(
                "UPDATE drop_principal_key_revisions SET state=?,changed_at=?,payload_json=?,"
                "integrity_sha256=? WHERE tenant_id=? AND revision=? AND state=?",
                (
                    result_state,
                    now,
                    _canonical(payload).decode("ascii"),
                    _sha256(payload),
                    self.tenant_id,
                    selected,
                    expected_state,
                ),
            )
            if updated.rowcount != 1:
                raise DROPManagementConflict("DROP key revision changed concurrently")
            self._append_operation(
                connection,
                action=action,
                idempotency_key=idempotency_key,
                request_sha256=request_sha256,
                result=payload,
                created_at=now,
            )
            connection.commit()
        return self._public(payload)

    def record_migration(  # noqa: PLR0913 - explicit migration ceremony evidence
        self,
        *,
        migration_id: str,
        from_revision: int,
        to_revision: int,
        objects_migrated: int,
        remaining_dependencies: int,
        actor_ref: str,
        reviewer_ref: str,
    ) -> Mapping[str, object]:
        self._gate()
        migration = _ref(migration_id, "migration_id")
        source = _revision(from_revision, "from_revision")
        target = _revision(to_revision, "to_revision")
        if source == target or target != self.current_revision():
            raise DROPManagementConflict("DROP key migration target is not current")
        self.require_active_revision(source)
        for value, label in (
            (objects_migrated, "objects_migrated"),
            (remaining_dependencies, "remaining_dependencies"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000:
                raise DROPManagementValidationError(f"{label} is outside its bound")
        actual_remaining = self._dependency_counter(source)
        if actual_remaining != remaining_dependencies:
            raise DROPManagementConflict("DROP key migration dependency count changed")
        actor, reviewer = self._independent(actor_ref, reviewer_ref)
        now = _timestamp(self._clock(), "current time")
        payload = {
            "tenant_id": self.tenant_id,
            "migration_id": migration,
            "from_revision": source,
            "to_revision": target,
            "objects_migrated": objects_migrated,
            "remaining_dependencies": remaining_dependencies,
            "actor_binding_sha256": actor.binding_sha256,
            "reviewer_binding_sha256": reviewer.binding_sha256,
            "actor_key_revision": actor.key_revision,
            "reviewer_key_revision": reviewer.key_revision,
            "created_at": now,
        }
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            try:
                connection.execute(
                    "INSERT INTO drop_principal_key_migrations VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (*payload.values(), _sha256(payload)),
                )
                connection.commit()
            except sqlite3.IntegrityError:
                row = connection.execute(
                    "SELECT * FROM drop_principal_key_migrations WHERE tenant_id=? "
                    "AND migration_id=?",
                    (self.tenant_id, migration),
                ).fetchone()
                if row is None:
                    raise DROPManagementConflict("DROP key migration changed concurrently") from None
                stored = {key: row[key] for key in payload}
                if stored != payload or not _same(_sha256(stored), row["integrity_sha256"]):
                    raise DROPManagementConflict("DROP key migration id was replayed differently") from None
        return dict(payload)

    @staticmethod
    def _public(payload: Mapping[str, object]) -> DROPPrincipalKeyRevision:
        return DROPPrincipalKeyRevision(
            revision=_revision(payload["revision"]),
            state=str(payload["state"]),
            key_ref_sha256=str(payload["key_ref_sha256"]),
            created_at=_timestamp(payload["created_at"], "created_at"),
            changed_at=_timestamp(payload["changed_at"], "changed_at"),
            integrity_sha256=_sha256(dict(payload)),
        )

    def list_revisions(self) -> tuple[DROPPrincipalKeyRevision, ...]:
        self._gate()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM drop_principal_key_revisions WHERE tenant_id=? "
                "ORDER BY revision DESC",
                (self.tenant_id,),
            ).fetchall()
        return tuple(self._public(self._row_payload(row)) for row in rows)

    def verify_integrity(self) -> bool:
        try:
            self._gate()
            with self._connect() as connection:
                meta = connection.execute(
                    "SELECT key,value FROM drop_principal_key_meta ORDER BY key"
                ).fetchall()
                rows = connection.execute(
                    "SELECT * FROM drop_principal_key_revisions WHERE tenant_id=? "
                    "ORDER BY revision",
                    (self.tenant_id,),
                ).fetchall()
                operations = connection.execute(
                    "SELECT * FROM drop_principal_key_operations WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchall()
                migrations = connection.execute(
                    "SELECT * FROM drop_principal_key_migrations WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchall()
            if (
                len(meta) != 1
                or meta[0]["key"] != "tenant_sha256"
                or not _same(meta[0]["value"], _text_sha256(self.tenant_id))
                or not rows
                or sum(str(row["state"]) == "current" for row in rows) != 1
            ):
                return False
            for expected, row in enumerate(rows, 1):
                payload = self._row_payload(row)
                if int(row["revision"]) != expected or payload["state"] not in _ALL_STATES:
                    return False
                if payload["state"] in _ACTIVE_STATES:
                    self._resolve_secret(str(row["key_ref"]))
            for row in operations:
                body = {
                    "tenant_id": str(row["tenant_id"]),
                    "action": str(row["action"]),
                    "key_sha256": str(row["key_sha256"]),
                    "request_sha256": str(row["request_sha256"]),
                    "result_json": str(row["result_json"]),
                    "created_at": float(row["created_at"]),
                }
                if (
                    body["action"] not in {"rotate", "retire", "revoke"}
                    or not _DIGEST_RE.fullmatch(str(body["key_sha256"]))
                    or not _DIGEST_RE.fullmatch(str(body["request_sha256"]))
                    or not _same(_sha256(body), row["integrity_sha256"])
                    or not isinstance(json.loads(str(body["result_json"])), Mapping)
                ):
                    return False
            revision_ids = {int(row["revision"]) for row in rows}
            for row in migrations:
                body = {
                    "tenant_id": str(row["tenant_id"]),
                    "migration_id": str(row["migration_id"]),
                    "from_revision": int(row["from_revision"]),
                    "to_revision": int(row["to_revision"]),
                    "objects_migrated": int(row["objects_migrated"]),
                    "remaining_dependencies": int(row["remaining_dependencies"]),
                    "actor_binding_sha256": str(row["actor_binding_sha256"]),
                    "reviewer_binding_sha256": str(row["reviewer_binding_sha256"]),
                    "actor_key_revision": int(row["actor_key_revision"]),
                    "reviewer_key_revision": int(row["reviewer_key_revision"]),
                    "created_at": float(row["created_at"]),
                }
                if (
                    body["from_revision"] not in revision_ids
                    or body["to_revision"] not in revision_ids
                    or body["actor_key_revision"] not in revision_ids
                    or body["reviewer_key_revision"] not in revision_ids
                    or not _DIGEST_RE.fullmatch(str(body["actor_binding_sha256"]))
                    or not _DIGEST_RE.fullmatch(str(body["reviewer_binding_sha256"]))
                    or not _same(_sha256(body), row["integrity_sha256"])
                ):
                    return False
            return True
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

    def dependency_counts(self) -> Mapping[int, int]:
        return {
            item.revision: self._dependency_counter(item.revision)
            for item in self.list_revisions()
        }

    @staticmethod
    def public_payload(value: DROPPrincipalKeyRevision) -> Mapping[str, object]:
        return {
            "revision": value.revision,
            "state": value.state,
            "key_ref_sha256": value.key_ref_sha256,
            "created_at": value.created_at,
            "changed_at": value.changed_at,
            "integrity_sha256": value.integrity_sha256,
        }


__all__ = [
    "DROPPrincipalKeyAuthority",
    "DROPPrincipalKeyRevision",
]
