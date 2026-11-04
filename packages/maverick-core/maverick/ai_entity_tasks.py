"""Tenant-bound review and remediation tasks for governed AI entities.

The public AI-governance task outcome is more than a generic work item.  Every
task in this authority is pinned to an independently resolved AI entity and
entity revision, has a closed review/remediation kind, records status,
assignee, priority and collaborators, and retains an immutable revision
history.  Callers cannot provide tenant, actor or entity authority.

The feature is default-off and deliberately performs no provider network I/O.
It provides a durable local product core; live provider/customer acceptance is
a separate deployment stage.
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
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from .constant_time import text_equals
from .file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
AUTHORITY_SCHEMA = "lightwork.ai-entity-task.entity-authority.v1"
TASK_SCHEMA = "lightwork.ai-entity-task.v1"
HISTORY_SCHEMA = "lightwork.ai-entity-task-history.v1"
INTEGRITY_SCHEMA = "lightwork.ai-entity-task-integrity.v1"

TASK_KINDS = frozenset({"review", "remediation"})
TASK_STATUSES = frozenset({"open", "in_progress", "blocked", "resolved", "dismissed"})
TERMINAL_STATUSES = frozenset({"resolved", "dismissed"})
TASK_PRIORITIES = frozenset({"low", "medium", "high", "critical"})

_TRANSITIONS: Mapping[str, frozenset[str]] = {
    "open": frozenset({"in_progress", "blocked", "resolved", "dismissed"}),
    "in_progress": frozenset({"open", "blocked", "resolved", "dismissed"}),
    "blocked": frozenset({"open", "in_progress", "resolved", "dismissed"}),
    "resolved": frozenset({"open"}),
    "dismissed": frozenset({"open"}),
}
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_TITLE = 500
_MAX_DESCRIPTION = 16_000
_MAX_COLLABORATORS = 64
_MIN_RETENTION_SECONDS = 3_600
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600
_MAX_TASKS = 1_000_000


class AIEntityTaskError(RuntimeError):
    """Base error for the AI-entity task authority."""


class AIEntityTaskConfigError(AIEntityTaskError):
    """The feature or one of its server-owned dependencies is unavailable."""


class AIEntityTaskValidationError(AIEntityTaskError, ValueError):
    """An input falls outside the closed task contract."""


class AIEntityTaskConflict(AIEntityTaskError):
    """A CAS, idempotency, entity-authority, or lifecycle precondition failed."""


class AIEntityTaskNotFound(AIEntityTaskError):
    """A tenant-bound task is absent or deliberately undisclosed."""


class AIEntityTaskPermissionDenied(AIEntityTaskError):
    """The authenticated or maintenance authority is insufficient."""


class AIEntityTaskIntegrityError(AIEntityTaskError):
    """Persisted task state or history failed integrity validation."""


def enabled() -> bool:
    """Return true only when inventory and AI-entity tasks are explicitly enabled."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    inventory = config.get("ai_inventory")
    tasks = config.get("ai_entity_tasks")
    return (
        isinstance(inventory, Mapping)
        and inventory.get("enable") is True
        and isinstance(tasks, Mapping)
        and tasks.get("enable") is True
    )


def require_enabled() -> None:
    """Fail closed unless both the AI inventory and task gates are literal true."""

    if not enabled():
        raise AIEntityTaskConfigError(
            "AI-entity tasks are disabled; explicitly enable ai_inventory and "
            "ai_entity_tasks"
        )


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise AIEntityTaskValidationError("value must be finite JSON") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise AIEntityTaskValidationError(f"{label} is not a SHA-256 digest")
    return value


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value if isinstance(value, str) else "")
    except (TypeError, ValueError) as exc:
        raise AIEntityTaskValidationError("tenant authority is invalid") from exc


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise AIEntityTaskValidationError(f"{label} is not a closed identifier")
    return value


def _operation_key(value: object) -> str:
    if not isinstance(value, str) or _OP_RE.fullmatch(value) is None:
        raise AIEntityTaskValidationError("idempotency_key is not a closed identifier")
    return value


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise AIEntityTaskValidationError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str, *, optional: bool = False) -> float | None:
    if optional and value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AIEntityTaskValidationError(f"{label} is not a finite timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise AIEntityTaskValidationError(f"{label} is not a finite timestamp")
    return result


def _text(value: object, label: str, maximum: int, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise AIEntityTaskValidationError(f"{label} must be text")
    normalized = value.strip()
    if (not empty and not normalized) or len(normalized) > maximum:
        raise AIEntityTaskValidationError(f"{label} is outside its bound")
    if any(ord(character) < 32 and character not in "\n\r\t" for character in normalized):
        raise AIEntityTaskValidationError(f"{label} contains a control character")
    return normalized


def _principal(value: object, label: str = "principal") -> str:
    return _identifier(value, label)


def _collaborators(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > _MAX_COLLABORATORS:
        raise AIEntityTaskValidationError("collaborators are outside their bound")
    normalized = tuple(_principal(item, "collaborator") for item in value)
    if len(set(normalized)) != len(normalized):
        raise AIEntityTaskValidationError("collaborators must be unique")
    return tuple(sorted(normalized))


@dataclass(frozen=True)
class AIEntityAuthority:
    """Independent, time-bounded authority for one exact AI-entity revision."""

    schema: str
    tenant_id: str
    entity_id: str
    entity_revision: int
    entity_type: str
    issuer_ref: str
    issued_at: float
    valid_until: float
    revoked: bool
    authority_sha256: str

    def normalized(self) -> AIEntityAuthority:
        if self.schema != AUTHORITY_SCHEMA:
            raise AIEntityTaskValidationError("entity authority schema is invalid")
        body = {
            "schema": AUTHORITY_SCHEMA,
            "tenant_id": _tenant(self.tenant_id),
            "entity_id": _identifier(self.entity_id, "entity_id"),
            "entity_revision": _integer(
                self.entity_revision, "entity_revision", 1, 2_147_483_647
            ),
            "entity_type": _identifier(self.entity_type, "entity_type"),
            "issuer_ref": _principal(self.issuer_ref, "issuer_ref"),
            "issued_at": _timestamp(self.issued_at, "issued_at"),
            "valid_until": _timestamp(self.valid_until, "valid_until"),
            "revoked": self.revoked,
        }
        if type(self.revoked) is not bool:
            raise AIEntityTaskValidationError("entity authority revoked flag is invalid")
        if body["valid_until"] <= body["issued_at"]:
            raise AIEntityTaskValidationError("entity authority lifetime is invalid")
        expected = _sha256(body)
        if not hmac.compare_digest(_digest(self.authority_sha256, "authority_sha256"), expected):
            raise AIEntityTaskValidationError("entity authority digest changed")
        return AIEntityAuthority(**body, authority_sha256=expected)


def issue_entity_authority(
    *,
    tenant_id: str,
    entity_id: str,
    entity_revision: int,
    entity_type: str,
    issuer_ref: str,
    issued_at: float,
    valid_until: float,
    revoked: bool = False,
) -> AIEntityAuthority:
    """Create a self-consistent authority for an independently enrolled entity."""

    body = {
        "schema": AUTHORITY_SCHEMA,
        "tenant_id": _tenant(tenant_id),
        "entity_id": _identifier(entity_id, "entity_id"),
        "entity_revision": _integer(entity_revision, "entity_revision", 1, 2_147_483_647),
        "entity_type": _identifier(entity_type, "entity_type"),
        "issuer_ref": _principal(issuer_ref, "issuer_ref"),
        "issued_at": _timestamp(issued_at, "issued_at"),
        "valid_until": _timestamp(valid_until, "valid_until"),
        "revoked": revoked,
    }
    if type(revoked) is not bool or body["valid_until"] <= body["issued_at"]:
        raise AIEntityTaskValidationError("entity authority lifetime or revocation is invalid")
    return AIEntityAuthority(**body, authority_sha256=_sha256(body)).normalized()


@dataclass(frozen=True)
class AIEntityTask:
    schema: str
    tenant_id: str
    task_id: str
    entity_id: str
    entity_revision: int
    entity_type: str
    entity_authority_sha256: str
    kind: str
    title: str
    description: str
    status: str
    assignee_ref: str | None
    collaborator_refs: tuple[str, ...]
    priority: str
    due_at: float | None
    created_by_ref: str
    created_at: float
    updated_at: float
    closed_at: float | None
    retained_until: float
    revision: int
    previous_integrity_sha256: str | None
    integrity_sha256: str


@dataclass(frozen=True)
class AIEntityTaskHistory:
    schema: str
    task_id: str
    revision: int
    event_type: str
    actor_ref: str
    changes: Mapping[str, object]
    record: AIEntityTask
    created_at: float
    previous_event_sha256: str | None
    event_sha256: str


def _task_body(record: AIEntityTask) -> dict[str, object]:
    body = asdict(record)
    body.pop("integrity_sha256", None)
    return body


def _task_integrity(record: AIEntityTask) -> str:
    return _sha256(_task_body(record))


def _normalize_task(record: AIEntityTask) -> AIEntityTask:
    if not isinstance(record, AIEntityTask) or record.schema != TASK_SCHEMA:
        raise AIEntityTaskIntegrityError("stored AI-entity task shape is invalid")
    try:
        normalized = replace(
            record,
            tenant_id=_tenant(record.tenant_id),
            task_id=_identifier(record.task_id, "task_id"),
            entity_id=_identifier(record.entity_id, "entity_id"),
            entity_revision=_integer(
                record.entity_revision, "entity_revision", 1, 2_147_483_647
            ),
            entity_type=_identifier(record.entity_type, "entity_type"),
            entity_authority_sha256=_digest(
                record.entity_authority_sha256, "entity_authority_sha256"
            ),
            kind=_identifier(record.kind, "kind"),
            title=_text(record.title, "title", _MAX_TITLE),
            description=_text(
                record.description, "description", _MAX_DESCRIPTION, empty=True
            ),
            assignee_ref=(
                _principal(record.assignee_ref, "assignee_ref")
                if record.assignee_ref is not None
                else None
            ),
            collaborator_refs=_collaborators(record.collaborator_refs),
            created_by_ref=_principal(record.created_by_ref, "created_by_ref"),
            due_at=_timestamp(record.due_at, "due_at", optional=True),
            created_at=float(_timestamp(record.created_at, "created_at")),
            updated_at=float(_timestamp(record.updated_at, "updated_at")),
            closed_at=_timestamp(record.closed_at, "closed_at", optional=True),
            retained_until=float(_timestamp(record.retained_until, "retained_until")),
            revision=_integer(record.revision, "revision", 1, 2_147_483_647),
            previous_integrity_sha256=(
                _digest(record.previous_integrity_sha256, "previous_integrity_sha256")
                if record.previous_integrity_sha256 is not None
                else None
            ),
            integrity_sha256=_digest(record.integrity_sha256, "integrity_sha256"),
        )
    except AIEntityTaskValidationError as exc:
        raise AIEntityTaskIntegrityError("stored AI-entity task is invalid") from exc
    if normalized.kind not in TASK_KINDS:
        raise AIEntityTaskIntegrityError("stored task kind is invalid")
    if normalized.status not in TASK_STATUSES or normalized.priority not in TASK_PRIORITIES:
        raise AIEntityTaskIntegrityError("stored task status or priority is invalid")
    if normalized.revision == 1 and normalized.previous_integrity_sha256 is not None:
        raise AIEntityTaskIntegrityError("initial task has a previous digest")
    if normalized.revision > 1 and normalized.previous_integrity_sha256 is None:
        raise AIEntityTaskIntegrityError("revised task is missing its previous digest")
    if normalized.updated_at < normalized.created_at:
        raise AIEntityTaskIntegrityError("stored task time order is invalid")
    if normalized.retained_until <= normalized.updated_at:
        raise AIEntityTaskIntegrityError("stored task retention is invalid")
    if normalized.status in TERMINAL_STATUSES:
        if normalized.closed_at is None or normalized.closed_at != normalized.updated_at:
            raise AIEntityTaskIntegrityError("terminal task close time is invalid")
    elif normalized.closed_at is not None:
        raise AIEntityTaskIntegrityError("active task has a close time")
    if not hmac.compare_digest(normalized.integrity_sha256, _task_integrity(normalized)):
        raise AIEntityTaskIntegrityError("stored task integrity changed")
    return normalized


class AIEntityTaskStore:
    """Durable, tenant-bound AI-entity task and immutable-history authority."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        entity_authority_resolver: Callable[[str, str, int], AIEntityAuthority],
        principal_resolver: Callable[[], str | None],
        maintenance_authorizer: Callable[[], bool] = lambda: False,
        config_gate: Callable[[], None] = require_enabled,
        retention_seconds: int = 365 * 24 * 3_600,
        max_tasks: int = 100_000,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        if not all(
            callable(value)
            for value in (
                entity_authority_resolver,
                principal_resolver,
                maintenance_authorizer,
                config_gate,
                clock,
            )
        ):
            raise AIEntityTaskConfigError("AI-entity task dependencies are incomplete")
        try:
            config_gate()
        except AIEntityTaskError:
            raise
        except Exception as exc:
            raise AIEntityTaskConfigError("AI-entity task configuration is unavailable") from exc
        self.path = Path(path)
        self.tenant_id = _tenant(tenant_id)
        self._tenant_sha256 = hashlib.sha256(self.tenant_id.encode()).hexdigest()
        self._authority_resolver = entity_authority_resolver
        self._principal_resolver = principal_resolver
        self._maintenance_authorizer = maintenance_authorizer
        self._retention_seconds = _integer(
            retention_seconds,
            "retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        )
        self._max_tasks = _integer(max_tasks, "max_tasks", 1, _MAX_TASKS)
        self._clock = clock
        self._id_factory = id_factory or (lambda: f"AIT-{secrets.token_hex(16)}")
        self._maintenance = threading.local()
        ensure_private_directory(self.path.parent)
        with cross_process_lock(self.path, strict=True):
            self._initialize()

    def _now(self) -> float:
        return float(_timestamp(self._clock(), "clock"))

    def _actor(self) -> str:
        try:
            actor = self._principal_resolver()
        except Exception as exc:
            raise AIEntityTaskPermissionDenied("authenticated principal is unavailable") from exc
        if actor is None:
            raise AIEntityTaskPermissionDenied("authenticated principal is required")
        return _principal(actor, "authenticated principal")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.create_function(
            "ai_entity_task_maintenance_authorized",
            0,
            lambda: 1 if bool(getattr(self._maintenance, "authorized", False)) else 0,
        )
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ai_entity_task_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ai_entity_tasks(
                    tenant_sha256 TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assignee_ref TEXT,
                    priority TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    retained_until REAL NOT NULL,
                    revision INTEGER NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256, task_id)
                );
                CREATE INDEX IF NOT EXISTS ai_entity_tasks_entity_idx
                    ON ai_entity_tasks(tenant_sha256, entity_id, updated_at, task_id);
                CREATE INDEX IF NOT EXISTS ai_entity_tasks_queue_idx
                    ON ai_entity_tasks(tenant_sha256, status, priority, updated_at, task_id);
                CREATE INDEX IF NOT EXISTS ai_entity_tasks_retention_idx
                    ON ai_entity_tasks(tenant_sha256, retained_until, task_id);
                CREATE TABLE IF NOT EXISTS ai_entity_task_history(
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_sha256 TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    actor_ref TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    previous_event_sha256 TEXT,
                    event_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE(tenant_sha256, task_id, revision),
                    FOREIGN KEY(tenant_sha256, task_id)
                        REFERENCES ai_entity_tasks(tenant_sha256, task_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS ai_entity_task_operations(
                    tenant_sha256 TEXT NOT NULL,
                    idempotency_sha256 TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(tenant_sha256, idempotency_sha256)
                );
                CREATE TABLE IF NOT EXISTS ai_entity_task_tombstones(
                    tenant_sha256 TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    last_integrity_sha256 TEXT NOT NULL,
                    purged_at REAL NOT NULL,
                    PRIMARY KEY(tenant_sha256, task_id)
                );
                CREATE TRIGGER IF NOT EXISTS ai_entity_task_history_no_update
                    BEFORE UPDATE ON ai_entity_task_history
                    BEGIN SELECT RAISE(ABORT,'immutable AI-entity task history'); END;
                CREATE TRIGGER IF NOT EXISTS ai_entity_task_operation_no_update
                    BEFORE UPDATE ON ai_entity_task_operations
                    BEGIN SELECT RAISE(ABORT,'immutable AI-entity task operation'); END;
                CREATE TRIGGER IF NOT EXISTS ai_entity_task_tombstone_no_update
                    BEFORE UPDATE ON ai_entity_task_tombstones
                    BEGIN SELECT RAISE(ABORT,'immutable AI-entity task tombstone'); END;
                CREATE TRIGGER IF NOT EXISTS ai_entity_task_no_delete
                    BEFORE DELETE ON ai_entity_tasks
                    WHEN ai_entity_task_maintenance_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'AI-entity task maintenance required'); END;
                CREATE TRIGGER IF NOT EXISTS ai_entity_task_history_no_delete
                    BEFORE DELETE ON ai_entity_task_history
                    WHEN ai_entity_task_maintenance_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'AI-entity task maintenance required'); END;
                """
            )
            version = connection.execute(
                "SELECT value FROM ai_entity_task_meta WHERE key='schema_version'"
            ).fetchone()
            if version is None:
                connection.execute(
                    "INSERT INTO ai_entity_task_meta(key,value) VALUES('schema_version',?)",
                    (str(SCHEMA_VERSION),),
                )
            elif version["value"] != str(SCHEMA_VERSION):
                raise AIEntityTaskConfigError(
                    f"unsupported AI-entity task schema version {version['value']}"
                )
            tenant = connection.execute(
                "SELECT value FROM ai_entity_task_meta WHERE key='tenant_sha256'"
            ).fetchone()
            if tenant is None:
                connection.execute(
                    "INSERT INTO ai_entity_task_meta(key,value) VALUES('tenant_sha256',?)",
                    (self._tenant_sha256,),
                )
            elif not hmac.compare_digest(tenant["value"], self._tenant_sha256):
                raise AIEntityTaskIntegrityError("AI-entity task database belongs to another tenant")
        ensure_private_file(self.path)

    def _require_tenant(self, tenant_id: object) -> None:
        if not text_equals(_tenant(tenant_id), self.tenant_id):
            raise AIEntityTaskNotFound("AI-entity task was not found")

    def _resolve_entity(self, entity_id: str, entity_revision: int) -> AIEntityAuthority:
        entity = _identifier(entity_id, "entity_id")
        revision = _integer(entity_revision, "entity_revision", 1, 2_147_483_647)
        try:
            first = self._authority_resolver(self.tenant_id, entity, revision)
            second = self._authority_resolver(self.tenant_id, entity, revision)
            if not isinstance(first, AIEntityAuthority) or not isinstance(
                second, AIEntityAuthority
            ):
                raise TypeError("entity authority type is invalid")
            left = first.normalized()
            right = second.normalized()
        except AIEntityTaskError:
            raise
        except Exception as exc:
            raise AIEntityTaskConflict("AI-entity authority is unavailable") from exc
        if left != right:
            raise AIEntityTaskConflict("AI-entity authority changed")
        now = self._now()
        if (
            left.tenant_id != self.tenant_id
            or left.entity_id != entity
            or left.entity_revision != revision
            or left.revoked
            or not left.issued_at <= now < left.valid_until
        ):
            raise AIEntityTaskConflict("AI-entity authority is not current")
        return left

    @staticmethod
    def _row_task(row: sqlite3.Row | None) -> AIEntityTask:
        if row is None:
            raise AIEntityTaskNotFound("AI-entity task was not found")
        try:
            payload = json.loads(row["record_json"])
            if not isinstance(payload, dict):
                raise TypeError("record is not an object")
            payload["collaborator_refs"] = tuple(payload["collaborator_refs"])
            return _normalize_task(AIEntityTask(**payload))
        except AIEntityTaskError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIEntityTaskIntegrityError("stored AI-entity task is invalid") from exc

    def _existing_operation(
        self,
        connection: sqlite3.Connection,
        *,
        idempotency_key: str,
        operation_type: str,
        request_sha256: str,
    ) -> AIEntityTask | None:
        key_sha256 = _sha256(
            {"schema": "lightwork.ai-entity-task-idempotency.v1", "key": idempotency_key}
        )
        row = connection.execute(
            "SELECT operation_type,request_sha256,task_id FROM ai_entity_task_operations "
            "WHERE tenant_sha256=? AND idempotency_sha256=?",
            (self._tenant_sha256, key_sha256),
        ).fetchone()
        if row is None:
            return None
        if row["operation_type"] != operation_type or not text_equals(
            str(row["request_sha256"]), request_sha256
        ):
            raise AIEntityTaskConflict("idempotency key is bound to another operation")
        task_row = connection.execute(
            "SELECT record_json FROM ai_entity_tasks WHERE tenant_sha256=? AND task_id=?",
            (self._tenant_sha256, row["task_id"]),
        ).fetchone()
        if task_row is None:
            raise AIEntityTaskConflict("idempotent task result has expired")
        return self._row_task(task_row)

    def _record_operation(
        self,
        connection: sqlite3.Connection,
        *,
        idempotency_key: str,
        operation_type: str,
        request_sha256: str,
        task_id: str,
        created_at: float,
    ) -> None:
        key_sha256 = _sha256(
            {"schema": "lightwork.ai-entity-task-idempotency.v1", "key": idempotency_key}
        )
        connection.execute(
            "INSERT INTO ai_entity_task_operations VALUES(?,?,?,?,?,?)",
            (
                self._tenant_sha256,
                key_sha256,
                operation_type,
                request_sha256,
                task_id,
                created_at,
            ),
        )

    def _append_history(
        self,
        connection: sqlite3.Connection,
        *,
        task: AIEntityTask,
        event_type: str,
        actor_ref: str,
        changes: Mapping[str, object],
    ) -> None:
        previous = connection.execute(
            "SELECT event_sha256 FROM ai_entity_task_history WHERE tenant_sha256=? "
            "AND task_id=? ORDER BY revision DESC LIMIT 1",
            (self._tenant_sha256, task.task_id),
        ).fetchone()
        previous_sha256 = previous["event_sha256"] if previous is not None else None
        event_body = {
            "schema": HISTORY_SCHEMA,
            "task_id": task.task_id,
            "revision": task.revision,
            "event_type": event_type,
            "actor_ref": actor_ref,
            "changes": dict(changes),
            "record": asdict(task),
            "created_at": task.updated_at,
            "previous_event_sha256": previous_sha256,
        }
        event_sha256 = _sha256(event_body)
        connection.execute(
            "INSERT INTO ai_entity_task_history(tenant_sha256,task_id,revision,event_type,"
            "actor_ref,event_json,previous_event_sha256,event_sha256,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                self._tenant_sha256,
                task.task_id,
                task.revision,
                event_type,
                actor_ref,
                _canonical_json(event_body),
                previous_sha256,
                event_sha256,
                task.updated_at,
            ),
        )

    def create_task(
        self,
        tenant_id: str,
        *,
        entity_id: str,
        entity_revision: int,
        kind: str,
        title: str,
        description: str = "",
        status: str = "open",
        assignee_ref: str | None = None,
        collaborator_refs: Sequence[str] = (),
        priority: str = "medium",
        due_at: float | None = None,
        idempotency_key: str,
    ) -> AIEntityTask:
        self._require_tenant(tenant_id)
        actor = self._actor()
        authority = self._resolve_entity(entity_id, entity_revision)
        task_kind = _identifier(kind, "kind")
        if task_kind not in TASK_KINDS:
            raise AIEntityTaskValidationError("task kind is invalid")
        task_status = _identifier(status, "status")
        if task_status != "open":
            raise AIEntityTaskValidationError("new tasks must start open")
        task_priority = _identifier(priority, "priority")
        if task_priority not in TASK_PRIORITIES:
            raise AIEntityTaskValidationError("task priority is invalid")
        normalized_title = _text(title, "title", _MAX_TITLE)
        normalized_description = _text(
            description, "description", _MAX_DESCRIPTION, empty=True
        )
        normalized_assignee = (
            _principal(assignee_ref, "assignee_ref") if assignee_ref is not None else None
        )
        normalized_collaborators = _collaborators(tuple(collaborator_refs))
        normalized_due = _timestamp(due_at, "due_at", optional=True)
        key = _operation_key(idempotency_key)
        request_body = {
            "schema": "lightwork.ai-entity-task-create.v1",
            "entity_authority_sha256": authority.authority_sha256,
            "kind": task_kind,
            "title": normalized_title,
            "description": normalized_description,
            "status": task_status,
            "assignee_ref": normalized_assignee,
            "collaborator_refs": normalized_collaborators,
            "priority": task_priority,
            "due_at": normalized_due,
        }
        request_sha256 = _sha256(request_body)
        now = self._now()
        if normalized_due is not None and normalized_due <= now:
            raise AIEntityTaskValidationError("due_at must be in the future")
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._existing_operation(
                connection,
                idempotency_key=key,
                operation_type="create",
                request_sha256=request_sha256,
            )
            if existing is not None:
                return existing
            count = connection.execute(
                "SELECT COUNT(*) AS total FROM ai_entity_tasks WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchone()["total"]
            if count >= self._max_tasks:
                raise AIEntityTaskConflict("AI-entity task quota is exhausted")
            task_id = _identifier(self._id_factory(), "generated task_id")
            if connection.execute(
                "SELECT 1 FROM ai_entity_task_tombstones WHERE tenant_sha256=? AND task_id=?",
                (self._tenant_sha256, task_id),
            ).fetchone() is not None:
                raise AIEntityTaskConflict("generated task identifier was already used")
            retained_until = now + self._retention_seconds
            draft = AIEntityTask(
                schema=TASK_SCHEMA,
                tenant_id=self.tenant_id,
                task_id=task_id,
                entity_id=authority.entity_id,
                entity_revision=authority.entity_revision,
                entity_type=authority.entity_type,
                entity_authority_sha256=authority.authority_sha256,
                kind=task_kind,
                title=normalized_title,
                description=normalized_description,
                status="open",
                assignee_ref=normalized_assignee,
                collaborator_refs=normalized_collaborators,
                priority=task_priority,
                due_at=normalized_due,
                created_by_ref=actor,
                created_at=now,
                updated_at=now,
                closed_at=None,
                retained_until=retained_until,
                revision=1,
                previous_integrity_sha256=None,
                integrity_sha256="0" * 64,
            )
            task = _normalize_task(replace(draft, integrity_sha256=_task_integrity(draft)))
            connection.execute(
                "INSERT INTO ai_entity_tasks VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    self._tenant_sha256,
                    task.task_id,
                    task.entity_id,
                    task.status,
                    task.assignee_ref,
                    task.priority,
                    task.updated_at,
                    task.retained_until,
                    task.revision,
                    _canonical_json(asdict(task)),
                ),
            )
            self._append_history(
                connection,
                task=task,
                event_type="created",
                actor_ref=actor,
                changes=request_body,
            )
            self._record_operation(
                connection,
                idempotency_key=key,
                operation_type="create",
                request_sha256=request_sha256,
                task_id=task.task_id,
                created_at=now,
            )
            return task

    def update_task(
        self,
        tenant_id: str,
        task_id: str,
        *,
        expected_revision: int,
        changes: Mapping[str, object],
        idempotency_key: str,
    ) -> AIEntityTask:
        self._require_tenant(tenant_id)
        actor = self._actor()
        task_key = _identifier(task_id, "task_id")
        revision = _integer(expected_revision, "expected_revision", 1, 2_147_483_647)
        if not isinstance(changes, Mapping) or not changes:
            raise AIEntityTaskValidationError("task update must contain changes")
        allowed = {
            "status",
            "assignee_ref",
            "priority",
            "collaborator_refs",
            "due_at",
        }
        if not set(changes).issubset(allowed):
            raise AIEntityTaskValidationError("task update contains an unsupported field")
        normalized: dict[str, object] = {}
        if "status" in changes:
            status = _identifier(changes["status"], "status")
            if status not in TASK_STATUSES:
                raise AIEntityTaskValidationError("task status is invalid")
            normalized["status"] = status
        if "assignee_ref" in changes:
            raw_assignee = changes["assignee_ref"]
            normalized["assignee_ref"] = (
                None if raw_assignee is None else _principal(raw_assignee, "assignee_ref")
            )
        if "priority" in changes:
            priority = _identifier(changes["priority"], "priority")
            if priority not in TASK_PRIORITIES:
                raise AIEntityTaskValidationError("task priority is invalid")
            normalized["priority"] = priority
        if "collaborator_refs" in changes:
            normalized["collaborator_refs"] = _collaborators(changes["collaborator_refs"])
        if "due_at" in changes:
            normalized["due_at"] = _timestamp(
                changes["due_at"],
                "due_at",
                optional=True,
            )
        key = _operation_key(idempotency_key)
        request_body = {
            "schema": "lightwork.ai-entity-task-update.v1",
            "task_id": task_key,
            "expected_revision": revision,
            "changes": normalized,
        }
        request_sha256 = _sha256(request_body)
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._existing_operation(
                connection,
                idempotency_key=key,
                operation_type="update",
                request_sha256=request_sha256,
            )
            if existing is not None:
                return existing
            row = connection.execute(
                "SELECT record_json FROM ai_entity_tasks WHERE tenant_sha256=? AND task_id=?",
                (self._tenant_sha256, task_key),
            ).fetchone()
            current = self._row_task(row)
            if current.revision != revision:
                raise AIEntityTaskConflict("AI-entity task revision changed")
            authority = self._resolve_entity(current.entity_id, current.entity_revision)
            if not hmac.compare_digest(
                authority.authority_sha256, current.entity_authority_sha256
            ):
                raise AIEntityTaskConflict("AI-entity task authority changed")
            new_status = str(normalized.get("status", current.status))
            if new_status != current.status and new_status not in _TRANSITIONS[current.status]:
                raise AIEntityTaskConflict("AI-entity task status transition is invalid")
            now = self._now()
            normalized_due = normalized.get("due_at", current.due_at)
            if normalized_due is not None and float(normalized_due) <= now:
                raise AIEntityTaskValidationError("due_at must be in the future")
            material = {
                key_name: value
                for key_name, value in normalized.items()
                if value != getattr(current, key_name)
            }
            if not material:
                raise AIEntityTaskConflict("AI-entity task update has no change")
            closed_at = (
                current.closed_at
                if new_status == current.status
                else (now if new_status in TERMINAL_STATUSES else None)
            )
            draft = replace(
                current,
                **material,
                updated_at=now,
                closed_at=closed_at,
                retained_until=now + self._retention_seconds,
                revision=current.revision + 1,
                previous_integrity_sha256=current.integrity_sha256,
                integrity_sha256="0" * 64,
            )
            updated = _normalize_task(replace(draft, integrity_sha256=_task_integrity(draft)))
            changed = connection.execute(
                "UPDATE ai_entity_tasks SET status=?,assignee_ref=?,priority=?,updated_at=?,"
                "retained_until=?,revision=?,record_json=? WHERE tenant_sha256=? AND task_id=? "
                "AND revision=?",
                (
                    updated.status,
                    updated.assignee_ref,
                    updated.priority,
                    updated.updated_at,
                    updated.retained_until,
                    updated.revision,
                    _canonical_json(asdict(updated)),
                    self._tenant_sha256,
                    task_key,
                    current.revision,
                ),
            ).rowcount
            if changed != 1:
                raise AIEntityTaskConflict("AI-entity task changed concurrently")
            self._append_history(
                connection,
                task=updated,
                event_type="updated",
                actor_ref=actor,
                changes=material,
            )
            self._record_operation(
                connection,
                idempotency_key=key,
                operation_type="update",
                request_sha256=request_sha256,
                task_id=task_key,
                created_at=now,
            )
            return updated

    def get_task(self, tenant_id: str, task_id: str) -> AIEntityTask:
        self._require_tenant(tenant_id)
        task_key = _identifier(task_id, "task_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json FROM ai_entity_tasks WHERE tenant_sha256=? AND task_id=?",
                (self._tenant_sha256, task_key),
            ).fetchone()
        return self._row_task(row)

    def list_tasks(
        self,
        tenant_id: str,
        *,
        entity_id: str | None = None,
        status: str | None = None,
        assignee_ref: str | None = None,
        priority: str | None = None,
        limit: int = 100,
    ) -> tuple[AIEntityTask, ...]:
        self._require_tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 500)
        clauses = ["tenant_sha256=?"]
        parameters: list[object] = [self._tenant_sha256]
        if entity_id is not None:
            clauses.append("entity_id=?")
            parameters.append(_identifier(entity_id, "entity_id"))
        if status is not None:
            selected_status = _identifier(status, "status")
            if selected_status not in TASK_STATUSES:
                raise AIEntityTaskValidationError("task status is invalid")
            clauses.append("status=?")
            parameters.append(selected_status)
        if assignee_ref is not None:
            clauses.append("assignee_ref=?")
            parameters.append(_principal(assignee_ref, "assignee_ref"))
        if priority is not None:
            selected_priority = _identifier(priority, "priority")
            if selected_priority not in TASK_PRIORITIES:
                raise AIEntityTaskValidationError("task priority is invalid")
            clauses.append("priority=?")
            parameters.append(selected_priority)
        parameters.append(bounded)
        query = (
            "SELECT record_json FROM ai_entity_tasks WHERE "
            + " AND ".join(clauses)
            + " ORDER BY updated_at DESC,task_id DESC LIMIT ?"
        )
        with self._connect() as connection:
            rows = connection.execute(query, tuple(parameters)).fetchall()
        return tuple(self._row_task(row) for row in rows)

    def history(self, tenant_id: str, task_id: str) -> tuple[AIEntityTaskHistory, ...]:
        self._require_tenant(tenant_id)
        task_key = _identifier(task_id, "task_id")
        # Deliberately require the current record so purged tasks remain undisclosed.
        self.get_task(tenant_id, task_key)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM ai_entity_task_history WHERE tenant_sha256=? AND task_id=? "
                "ORDER BY revision",
                (self._tenant_sha256, task_key),
            ).fetchall()
        events: list[AIEntityTaskHistory] = []
        previous_sha256: str | None = None
        for row in rows:
            try:
                body = json.loads(row["event_json"])
                record_payload = dict(body["record"])
                record_payload["collaborator_refs"] = tuple(
                    record_payload["collaborator_refs"]
                )
                record = _normalize_task(AIEntityTask(**record_payload))
                event = AIEntityTaskHistory(
                    schema=body["schema"],
                    task_id=body["task_id"],
                    revision=body["revision"],
                    event_type=body["event_type"],
                    actor_ref=body["actor_ref"],
                    changes=body["changes"],
                    record=record,
                    created_at=body["created_at"],
                    previous_event_sha256=body["previous_event_sha256"],
                    event_sha256=row["event_sha256"],
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise AIEntityTaskIntegrityError("stored task history is invalid") from exc
            expected_body = {
                "schema": event.schema,
                "task_id": event.task_id,
                "revision": event.revision,
                "event_type": event.event_type,
                "actor_ref": event.actor_ref,
                "changes": dict(event.changes),
                "record": asdict(event.record),
                "created_at": event.created_at,
                "previous_event_sha256": event.previous_event_sha256,
            }
            if (
                event.schema != HISTORY_SCHEMA
                or event.task_id != task_key
                or event.revision != len(events) + 1
                or event.record.revision != event.revision
                or event.previous_event_sha256 != previous_sha256
                or row["previous_event_sha256"] != previous_sha256
                or not text_equals(str(event.event_sha256), _sha256(expected_body))
            ):
                raise AIEntityTaskIntegrityError("AI-entity task history chain changed")
            previous_sha256 = event.event_sha256
            events.append(event)
        if not events:
            raise AIEntityTaskIntegrityError("AI-entity task history is missing")
        return tuple(events)

    def verify_integrity(self, tenant_id: str) -> dict[str, object]:
        self._require_tenant(tenant_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT task_id,record_json FROM ai_entity_tasks WHERE tenant_sha256=? "
                "ORDER BY task_id",
                (self._tenant_sha256,),
            ).fetchall()
            tombstones = connection.execute(
                "SELECT task_id,last_integrity_sha256,purged_at FROM ai_entity_task_tombstones "
                "WHERE tenant_sha256=? ORDER BY task_id",
                (self._tenant_sha256,),
            ).fetchall()
        tasks = tuple(self._row_task(row) for row in rows)
        history_count = 0
        for task in tasks:
            events = self.history(tenant_id, task.task_id)
            if events[-1].record != task:
                raise AIEntityTaskIntegrityError("latest task history does not match task")
            history_count += len(events)
        for row in tombstones:
            _identifier(row["task_id"], "tombstone task_id")
            _digest(row["last_integrity_sha256"], "tombstone integrity")
            _timestamp(row["purged_at"], "tombstone purge time")
        digest = _sha256(
            {
                "schema": INTEGRITY_SCHEMA,
                "tenant_sha256": self._tenant_sha256,
                "tasks": [task.integrity_sha256 for task in tasks],
                "tombstones": [
                    [row["task_id"], row["last_integrity_sha256"], row["purged_at"]]
                    for row in tombstones
                ],
            }
        )
        return {
            "schema": INTEGRITY_SCHEMA,
            "ok": True,
            "task_count": len(tasks),
            "history_count": history_count,
            "tombstone_count": len(tombstones),
            "integrity_sha256": digest,
        }

    def retention_due(self, tenant_id: str, *, limit: int = 100) -> tuple[AIEntityTask, ...]:
        self._require_tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 1_000)
        now = self._now()
        placeholders = ",".join("?" for _ in TERMINAL_STATUSES)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json FROM ai_entity_tasks WHERE tenant_sha256=? "
                f"AND status IN ({placeholders}) AND retained_until<=? "
                "ORDER BY retained_until,task_id LIMIT ?",
                (self._tenant_sha256, *sorted(TERMINAL_STATUSES), now, bounded),
            ).fetchall()
        return tuple(self._row_task(row) for row in rows)

    def purge_expired(self, tenant_id: str, *, limit: int = 100) -> int:
        self._require_tenant(tenant_id)
        try:
            authorized = self._maintenance_authorizer()
        except Exception as exc:
            raise AIEntityTaskPermissionDenied("maintenance authority is unavailable") from exc
        if authorized is not True:
            raise AIEntityTaskPermissionDenied("maintenance authority is required")
        due = self.retention_due(tenant_id, limit=limit)
        if not due:
            return 0
        # Verify before destruction; callers receive no partial success claim.
        self.verify_integrity(tenant_id)
        now = self._now()
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._maintenance.authorized = True
            try:
                removed = 0
                for task in due:
                    row = connection.execute(
                        "SELECT record_json FROM ai_entity_tasks WHERE tenant_sha256=? "
                        "AND task_id=? AND revision=? AND retained_until<=?",
                        (self._tenant_sha256, task.task_id, task.revision, now),
                    ).fetchone()
                    if row is None:
                        continue
                    current = self._row_task(row)
                    if current.status not in TERMINAL_STATUSES:
                        continue
                    connection.execute(
                        "INSERT INTO ai_entity_task_tombstones VALUES(?,?,?,?)",
                        (
                            self._tenant_sha256,
                            current.task_id,
                            current.integrity_sha256,
                            now,
                        ),
                    )
                    removed += connection.execute(
                        "DELETE FROM ai_entity_tasks WHERE tenant_sha256=? AND task_id=?",
                        (self._tenant_sha256, current.task_id),
                    ).rowcount
                return removed
            finally:
                self._maintenance.authorized = False


__all__ = [
    "AUTHORITY_SCHEMA",
    "HISTORY_SCHEMA",
    "INTEGRITY_SCHEMA",
    "SCHEMA_VERSION",
    "TASK_KINDS",
    "TASK_PRIORITIES",
    "TASK_SCHEMA",
    "TASK_STATUSES",
    "TERMINAL_STATUSES",
    "AIEntityAuthority",
    "AIEntityTask",
    "AIEntityTaskConfigError",
    "AIEntityTaskConflict",
    "AIEntityTaskError",
    "AIEntityTaskHistory",
    "AIEntityTaskIntegrityError",
    "AIEntityTaskNotFound",
    "AIEntityTaskPermissionDenied",
    "AIEntityTaskStore",
    "AIEntityTaskValidationError",
    "enabled",
    "issue_entity_authority",
    "require_enabled",
]
