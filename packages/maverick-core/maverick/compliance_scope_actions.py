"""Deterministic local plans from finalized compliance scope decisions.

This module is a provider-neutral authority between :mod:`compliance_scoping`
and local control/evidence-task adapters.  It resolves a finalized scope through
an injected trusted resolver; callers provide only opaque scope/catalog/plan
identifiers and CAS values.  Versioned mapping catalogs translate exact
framework/control references into closed control and evidence-task intents.

The module deliberately contains no licensed framework text, raw evidence,
free-text task descriptions, arbitrary expressions/code, network client, or
provider write implementation.  Applying a plan is unavailable unless the host
injects a local, idempotent callback and accepts its closed receipt contract.
That callback must use the deterministic ``operation_ref`` as its idempotency
authority: the callback and this SQLite store cannot share a transaction, so an
exception after a callback-side write is an ambiguous outcome whose safe
recovery is an exact retry/reconciliation, not an assumption that no write ran.

The capability is closed unless both exact gates are explicitly enabled::

    [tech_risk_compliance]
    enable = true
    [tech_risk_compliance.scope_actions]
    enable = true
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .constant_time import text_equals
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
AUDIT_SCHEMA = "lightwork.compliance-scope-actions-audit.v1"
EXPORT_SCHEMA = "lightwork.compliance-scope-actions-export.v1"
APPLY_SCHEMA = "lightwork.compliance-scope-actions-apply.v1"

LIVE_PROVIDER_WRITES = False
LICENSED_FRAMEWORK_CONTENT_INCLUDED = False
RAW_EVIDENCE_PERSISTED = False
LIVE_ACCEPTANCE_VERIFIED = False

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_REF_RE = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}\Z")
_KEY_REF_RE = re.compile(r"(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_CATALOG_ENTRIES = 2_000
_MAX_EVIDENCE_TASKS_PER_ENTRY = 64
_MAX_SCOPE_CONTROLS = 5_000
_MAX_REASON_CODES = 64
_MAX_INTENTS = 5_000
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600
_MIN_RETENTION_SECONDS = 60

RESPONSIBILITY_ROLES = frozenset({"first_line", "second_line", "control_owner", "evidence_owner"})
DESIRED_CONTROL_STATES = frozenset({"not_started", "not_implemented", "planned"})
EVIDENCE_TASK_KINDS = frozenset({"collect", "refresh", "review"})
EVIDENCE_CADENCES = frozenset({"one_time", "monthly", "quarterly", "annual", "continuous"})
PLAN_STATES = frozenset({"draft", "approved", "applied", "no_change", "rolled_back"})


class ComplianceScopeActionError(RuntimeError):
    """Base scope-action authority error."""


class ComplianceScopeActionConfigError(ComplianceScopeActionError):
    """The feature gate, signer, or local apply seam is unavailable."""


class ComplianceScopeActionValidationError(ComplianceScopeActionError, ValueError):
    """Data is outside the closed scope-action contract."""


class ComplianceScopeActionConflict(ComplianceScopeActionError):
    """A CAS, idempotency, lifecycle, or authoritative-scope check failed."""


class ComplianceScopeActionNotFound(ComplianceScopeActionError):
    """A tenant-scoped object is absent or deliberately undisclosed."""


class ComplianceScopeActionPermissionDenied(ComplianceScopeActionError):
    """Authentication or four-eyes separation is insufficient."""


class ComplianceScopeActionIntegrityError(ComplianceScopeActionError):
    """Persisted content, audit chain, or signed export failed verification."""


def enabled() -> bool:
    """Return true only for the exact two-level scope-action gate."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    root = config.get("tech_risk_compliance")
    actions = root.get("scope_actions") if isinstance(root, Mapping) else None
    return (
        isinstance(root, Mapping)
        and root.get("enable") is True
        and isinstance(actions, Mapping)
        and actions.get("enable") is True
    )


def require_enabled() -> None:
    if not enabled():
        raise ComplianceScopeActionConfigError(
            "scope actions are disabled; explicitly enable tech_risk_compliance "
            "and tech_risk_compliance.scope_actions"
        )


def _runtime_principal() -> str | None:
    try:
        from .connections import current_principal

        return current_principal()
    except Exception:
        return None


def _default_signing_key_resolver(tenant_id: str, key_ref: str) -> bytes:
    del tenant_id
    if not key_ref.startswith("env:"):
        raise ComplianceScopeActionConfigError(
            "the default signing resolver accepts only env: references"
        )
    value = os.environ.get(key_ref.removeprefix("env:"))
    if value is None or len(value.encode("utf-8")) < 32:
        raise ComplianceScopeActionConfigError(
            "the scope-action signing key is absent or shorter than 32 bytes"
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
        raise ComplianceScopeActionValidationError(
            "scope-action state must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise ComplianceScopeActionValidationError(
            "scope-action state exceeds its canonical byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ComplianceScopeActionValidationError("tenant_id is invalid") from exc


def _id(
    value: object,
    label: str,
    pattern: re.Pattern[str] = _ID_RE,
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ComplianceScopeActionValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ComplianceScopeActionValidationError(
            f"{label} must be an integer from {minimum} to {maximum}"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ComplianceScopeActionValidationError(f"{label} must be a timestamp")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ComplianceScopeActionValidationError(f"{label} must be finite")
    return result


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ComplianceScopeActionValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _closed_mapping(
    value: object,
    label: str,
    keys: frozenset[str],
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComplianceScopeActionValidationError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        raise ComplianceScopeActionValidationError(f"{label} fields must be exactly {sorted(keys)}")
    return value


def _sequence(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int,
) -> list[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ComplianceScopeActionValidationError(f"{label} must be an array")
    result = list(value)
    if not minimum <= len(result) <= maximum:
        raise ComplianceScopeActionValidationError(
            f"{label} must contain {minimum} to {maximum} items"
        )
    return result


def _id_list(value: object, label: str, *, maximum: int) -> tuple[str, ...]:
    values = tuple(_id(item, f"{label} item") for item in _sequence(value, label, maximum=maximum))
    if len(set(values)) != len(values):
        raise ComplianceScopeActionValidationError(f"{label} must be unique")
    return values


def _retained_until(value: object, now: float) -> float:
    retained = _timestamp(value, "retained_until")
    if not now + _MIN_RETENTION_SECONDS <= retained <= now + _MAX_RETENTION_SECONDS:
        raise ComplianceScopeActionValidationError(
            "retained_until is outside the supported retention window"
        )
    return retained


def _responsibilities(value: object) -> dict[str, str]:
    mapping = _closed_mapping(value, "responsibility assignments", RESPONSIBILITY_ROLES)
    result = {
        role: _id(mapping[role], f"{role} assignment", _REF_RE)
        for role in sorted(RESPONSIBILITY_ROLES)
    }
    if result["first_line"] == result["second_line"]:
        raise ComplianceScopeActionValidationError(
            "first_line and second_line assignments must be distinct"
        )
    return result


def _catalog_entry(value: object) -> dict[str, object]:
    item = _closed_mapping(
        value,
        "catalog entry",
        frozenset(
            {
                "entry_id",
                "framework_ref",
                "scope_control_ref",
                "desired_control_ref",
                "desired_control_state",
                "control_owner_role",
                "evidence_tasks",
            }
        ),
    )
    state = _id(item["desired_control_state"], "desired_control_state")
    if state not in DESIRED_CONTROL_STATES:
        raise ComplianceScopeActionValidationError(
            "desired_control_state is outside the closed pre-evidence states"
        )
    owner_role = _id(item["control_owner_role"], "control_owner_role")
    if owner_role not in {"second_line", "control_owner"}:
        raise ComplianceScopeActionValidationError(
            "control_owner_role must be second_line or control_owner"
        )
    tasks: list[dict[str, str]] = []
    for raw in _sequence(
        item["evidence_tasks"],
        "evidence_tasks",
        maximum=_MAX_EVIDENCE_TASKS_PER_ENTRY,
    ):
        task = _closed_mapping(
            raw,
            "evidence task",
            frozenset({"evidence_mapping_ref", "task_kind", "owner_role", "cadence"}),
        )
        kind = _id(task["task_kind"], "task_kind")
        cadence = _id(task["cadence"], "cadence")
        task_owner = _id(task["owner_role"], "owner_role")
        if kind not in EVIDENCE_TASK_KINDS:
            raise ComplianceScopeActionValidationError("task_kind is unsupported")
        if cadence not in EVIDENCE_CADENCES:
            raise ComplianceScopeActionValidationError("cadence is unsupported")
        if task_owner not in {"second_line", "control_owner", "evidence_owner"}:
            raise ComplianceScopeActionValidationError("evidence task owner_role is unsupported")
        tasks.append(
            {
                "evidence_mapping_ref": _id(task["evidence_mapping_ref"], "evidence_mapping_ref"),
                "task_kind": kind,
                "owner_role": task_owner,
                "cadence": cadence,
            }
        )
    if len({task["evidence_mapping_ref"] for task in tasks}) != len(tasks):
        raise ComplianceScopeActionValidationError(
            "evidence_mapping_ref must be unique within a catalog entry"
        )
    return {
        "entry_id": _id(item["entry_id"], "entry_id"),
        "framework_ref": _id(item["framework_ref"], "framework_ref"),
        "scope_control_ref": _id(item["scope_control_ref"], "scope_control_ref"),
        "desired_control_ref": _id(item["desired_control_ref"], "desired_control_ref"),
        "desired_control_state": state,
        "control_owner_role": owner_role,
        "evidence_tasks": sorted(tasks, key=lambda task: str(task["evidence_mapping_ref"])),
    }


@dataclass(frozen=True)
class ResolvedFinalScope:
    """The minimal authoritative finalized-scope projection used by this module."""

    tenant_id: str
    scope_id: str
    scope_revision: int
    scope_integrity_sha256: str
    assessment_id: str
    assessment_revision: int
    assessment_integrity_sha256: str
    status: str
    applicable_frameworks: tuple[str, ...]
    control_applicability: tuple[Mapping[str, object], ...]
    responsibility_assignments: Mapping[str, str]
    retained_until: float


@dataclass(frozen=True)
class ActionCatalogVersion:
    tenant_id: str
    catalog_id: str
    version: int
    entries: tuple[Mapping[str, object], ...]
    definition_sha256: str
    status: str
    created_by: str
    reviewed_by: str | None
    revision: int
    created_at: float
    reviewed_at: float | None
    integrity_sha256: str


@dataclass(frozen=True)
class ScopeActionPlan:
    tenant_id: str
    plan_id: str
    scope_id: str
    scope_revision: int
    scope_integrity_sha256: str
    assessment_id: str
    assessment_revision: int
    assessment_integrity_sha256: str
    catalog_id: str
    catalog_version: int
    catalog_sha256: str
    responsibility_assignments: Mapping[str, str]
    control_intents: tuple[Mapping[str, object], ...]
    evidence_task_intents: tuple[Mapping[str, object], ...]
    desired_sha256: str
    status: str
    planned_by: str
    approved_by: str | None
    last_operation: str | None
    last_outcome: str | None
    last_receipt: Mapping[str, object] | None
    reconciliation_count: int
    rollback_of_revision: int | None
    retained_until: float
    revision: int
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class SignedScopeActionExport:
    tenant_id: str
    export_id: str
    plan_id: str
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


def resolver_from_scoping_store(store: object) -> Callable[[str, str], Mapping[str, object]]:
    """Adapt a ``ComplianceScopingStore`` without exposing caller-supplied results."""

    get_scope = getattr(store, "get_scope", None)
    get_assessment = getattr(store, "get_assessment", None)
    if not callable(get_scope) or not callable(get_assessment):
        raise ComplianceScopeActionConfigError(
            "scope store must expose get_scope and get_assessment"
        )

    def resolve(tenant_id: str, scope_id: str) -> Mapping[str, object]:
        scope = get_scope(tenant_id, scope_id)
        assessment = get_assessment(tenant_id, scope.assessment_id)
        return {
            "tenant_id": scope.tenant_id,
            "scope_id": scope.scope_id,
            "scope_revision": scope.revision,
            "scope_integrity_sha256": scope.integrity_sha256,
            "assessment_id": assessment.assessment_id,
            "assessment_revision": assessment.revision,
            "assessment_integrity_sha256": assessment.integrity_sha256,
            "status": scope.status,
            "applicable_frameworks": list(scope.applicable_frameworks),
            "control_applicability": [dict(item) for item in scope.control_applicability],
            "responsibility_assignments": dict(scope.responsibility_assignments),
            "retained_until": scope.retained_until,
        }

    return resolve


class ComplianceScopeActionStore:
    """Private SQLite authority for scope-derived desired action plans."""

    def __init__(
        self,
        path: str | Path,
        *,
        scope_resolver: Callable[[str, str], Mapping[str, object]],
        config_gate: Callable[[], None] = require_enabled,
        principal_resolver: Callable[[], str | None] = _runtime_principal,
        apply_callback: Callable[[Mapping[str, object]], Mapping[str, object]] | None = None,
        signing_key_resolver: Callable[[str, str], bytes] = _default_signing_key_resolver,
        clock: Callable[[], float] = time.time,
    ) -> None:
        config_gate()
        if not callable(scope_resolver):
            raise ComplianceScopeActionConfigError("a trusted scope_resolver is required")
        if apply_callback is not None and not callable(apply_callback):
            raise ComplianceScopeActionConfigError("apply_callback must be callable")
        self.path = Path(path)
        self._scope_resolver = scope_resolver
        self._principal_resolver = principal_resolver
        self._apply_callback = apply_callback
        self._signing_key_resolver = signing_key_resolver
        self._clock = clock
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _actor(self) -> str:
        actor = self._principal_resolver()
        if actor is None or actor == "":
            raise ComplianceScopeActionPermissionDenied(
                "an authenticated runtime principal is required"
            )
        return _id(actor, "authenticated principal")

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
                CREATE TABLE IF NOT EXISTS action_catalog_definitions(
                    tenant_id TEXT NOT NULL,catalog_id TEXT NOT NULL,version INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,catalog_id,version)
                );
                CREATE TABLE IF NOT EXISTS action_catalog_publications(
                    tenant_id TEXT NOT NULL,catalog_id TEXT NOT NULL,version INTEGER NOT NULL,
                    status TEXT NOT NULL,payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,catalog_id,version),
                    FOREIGN KEY(tenant_id,catalog_id,version)
                        REFERENCES action_catalog_definitions(tenant_id,catalog_id,version)
                );
                CREATE TABLE IF NOT EXISTS scope_action_plans(
                    tenant_id TEXT NOT NULL,plan_id TEXT NOT NULL,status TEXT NOT NULL,
                    retained_until REAL NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,PRIMARY KEY(tenant_id,plan_id)
                );
                CREATE INDEX IF NOT EXISTS scope_action_plan_retention
                    ON scope_action_plans(tenant_id,status,retained_until);
                CREATE TABLE IF NOT EXISTS scope_action_plan_history(
                    tenant_id TEXT NOT NULL,plan_id TEXT NOT NULL,revision INTEGER NOT NULL,
                    status TEXT NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,PRIMARY KEY(tenant_id,plan_id,revision),
                    FOREIGN KEY(tenant_id,plan_id)
                        REFERENCES scope_action_plans(tenant_id,plan_id)
                );
                CREATE TABLE IF NOT EXISTS scope_action_exports(
                    tenant_id TEXT NOT NULL,export_id TEXT NOT NULL,plan_id TEXT NOT NULL,
                    retained_until REAL NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,PRIMARY KEY(tenant_id,export_id),
                    FOREIGN KEY(tenant_id,plan_id)
                        REFERENCES scope_action_plans(tenant_id,plan_id)
                );
                CREATE TABLE IF NOT EXISTS scope_action_operations(
                    tenant_id TEXT NOT NULL,idempotency_key TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_kind TEXT NOT NULL,
                    result_id TEXT NOT NULL,result_revision INTEGER NOT NULL,
                    PRIMARY KEY(tenant_id,idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS scope_action_audit_events(
                    tenant_id TEXT NOT NULL,sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS action_catalog_definition_no_update
                    BEFORE UPDATE ON action_catalog_definitions
                    BEGIN SELECT RAISE(ABORT,'immutable catalog definition'); END;
                CREATE TRIGGER IF NOT EXISTS action_catalog_definition_no_delete
                    BEFORE DELETE ON action_catalog_definitions
                    BEGIN SELECT RAISE(ABORT,'immutable catalog definition'); END;
                CREATE TRIGGER IF NOT EXISTS scope_action_history_no_update
                    BEFORE UPDATE ON scope_action_plan_history
                    BEGIN SELECT RAISE(ABORT,'immutable plan history'); END;
                CREATE TRIGGER IF NOT EXISTS scope_action_history_no_delete
                    BEFORE DELETE ON scope_action_plan_history
                    BEGIN SELECT RAISE(ABORT,'immutable plan history'); END;
                CREATE TRIGGER IF NOT EXISTS scope_action_export_no_update
                    BEFORE UPDATE ON scope_action_exports
                    BEGIN SELECT RAISE(ABORT,'immutable signed export'); END;
                CREATE TRIGGER IF NOT EXISTS scope_action_export_no_delete
                    BEFORE DELETE ON scope_action_exports
                    BEGIN SELECT RAISE(ABORT,'immutable signed export'); END;
                CREATE TRIGGER IF NOT EXISTS scope_action_audit_no_update
                    BEFORE UPDATE ON scope_action_audit_events
                    BEGIN SELECT RAISE(ABORT,'immutable audit event'); END;
                CREATE TRIGGER IF NOT EXISTS scope_action_audit_no_delete
                    BEFORE DELETE ON scope_action_audit_events
                    BEGIN SELECT RAISE(ABORT,'immutable audit event'); END;
                """
            )
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, SCHEMA_VERSION):
                raise ComplianceScopeActionConfigError(
                    f"unsupported scope-action schema version {version}"
                )
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        ensure_private_file(self.path)

    @staticmethod
    def _payload(row: sqlite3.Row, label: str, tenant: str) -> tuple[dict[str, Any], str]:
        try:
            value = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ComplianceScopeActionIntegrityError(f"{label} contains invalid JSON") from exc
        if not isinstance(value, dict) or value.get("tenant_id") != tenant:
            raise ComplianceScopeActionIntegrityError(f"{label} tenant binding is invalid")
        digest_value = _sha256(value)
        if not text_equals(digest_value, str(row["integrity_sha256"])):
            raise ComplianceScopeActionIntegrityError(f"{label} integrity check failed")
        return value, digest_value

    def _get(
        self,
        connection: sqlite3.Connection,
        table: str,
        tenant: str,
        key_name: str,
        key_value: str,
        label: str,
        *,
        version: int | None = None,
    ) -> tuple[dict[str, Any], str]:
        where = f"tenant_id=? AND {key_name}=?"  # noqa: S608
        values: list[object] = [tenant, key_value]
        if version is not None:
            where += " AND version=?"
            values.append(version)
        row = connection.execute(
            f"SELECT * FROM {table} WHERE {where}",  # noqa: S608
            values,
        ).fetchone()
        if row is None:
            raise ComplianceScopeActionNotFound(f"{label} was not found")
        return self._payload(row, label, tenant)

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

    @staticmethod
    def _write_plan(
        connection: sqlite3.Connection,
        tenant: str,
        plan_id: str,
        payload: Mapping[str, object],
    ) -> str:
        digest_value = _sha256(payload)
        cursor = connection.execute(
            "UPDATE scope_action_plans SET status=?,retained_until=?,payload_json=?,"
            "integrity_sha256=? WHERE tenant_id=? AND plan_id=?",
            (
                payload["status"],
                payload["retained_until"],
                _canonical(payload).decode("ascii"),
                digest_value,
                tenant,
                plan_id,
            ),
        )
        if cursor.rowcount != 1:
            raise ComplianceScopeActionNotFound("action plan was not found")
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
            "SELECT * FROM scope_action_operations WHERE tenant_id=? AND idempotency_key=?",
            (tenant, operation),
        ).fetchone()
        if row is not None and not text_equals(request_sha, str(row["request_sha256"])):
            raise ComplianceScopeActionConflict(
                "idempotency key was already used for a different request"
            )
        return request_sha, row

    @staticmethod
    def _record_operation(
        connection: sqlite3.Connection,
        tenant: str,
        idempotency_key: str,
        request_sha256: str,
        result_kind: str,
        result_id: str,
        result_revision: int,
    ) -> None:
        connection.execute(
            "INSERT INTO scope_action_operations VALUES(?,?,?,?,?,?)",
            (
                tenant,
                idempotency_key,
                request_sha256,
                result_kind,
                result_id,
                result_revision,
            ),
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        event_type: str,
        object_ref: str,
        actor: str,
        details: Mapping[str, object],
        occurred_at: float,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM scope_action_audit_events "
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
            "actor_ref": actor,
            "details": dict(details),
            "occurred_at": occurred_at,
            "previous_integrity_sha256": previous_sha,
        }
        digest_value = _sha256(payload)
        connection.execute(
            "INSERT INTO scope_action_audit_events VALUES(?,?,?,?)",
            (tenant, sequence, _canonical(payload).decode("ascii"), digest_value),
        )

    @staticmethod
    def _catalog(
        definition: Mapping[str, Any],
        publication: Mapping[str, Any],
        definition_sha256: str,
        publication_sha256: str,
    ) -> ActionCatalogVersion:
        return ActionCatalogVersion(
            tenant_id=str(definition["tenant_id"]),
            catalog_id=str(definition["catalog_id"]),
            version=int(definition["version"]),
            entries=tuple(dict(item) for item in definition["entries"]),
            definition_sha256=definition_sha256,
            status=str(publication["status"]),
            created_by=str(definition["created_by"]),
            reviewed_by=publication["reviewed_by"],
            revision=int(publication["revision"]),
            created_at=float(definition["created_at"]),
            reviewed_at=publication["reviewed_at"],
            integrity_sha256=_sha256(
                {
                    "definition_sha256": definition_sha256,
                    "publication_sha256": publication_sha256,
                }
            ),
        )

    @staticmethod
    def _plan(payload: Mapping[str, Any], digest_value: str) -> ScopeActionPlan:
        values = dict(payload)
        values["responsibility_assignments"] = dict(values["responsibility_assignments"])
        values["control_intents"] = tuple(dict(item) for item in values["control_intents"])
        values["evidence_task_intents"] = tuple(
            dict(item) for item in values["evidence_task_intents"]
        )
        if values["last_receipt"] is not None:
            values["last_receipt"] = dict(values["last_receipt"])
        return ScopeActionPlan(**values, integrity_sha256=digest_value)

    @staticmethod
    def _export(payload: Mapping[str, Any], digest_value: str) -> SignedScopeActionExport:
        values = dict(payload)
        values["body"] = dict(values["body"])
        return SignedScopeActionExport(**values, integrity_sha256=digest_value)

    def _get_catalog(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        catalog_id: str,
        version: int,
    ) -> ActionCatalogVersion:
        definition, definition_sha = self._get(
            connection,
            "action_catalog_definitions",
            tenant,
            "catalog_id",
            catalog_id,
            "catalog definition",
            version=version,
        )
        publication, publication_sha = self._get(
            connection,
            "action_catalog_publications",
            tenant,
            "catalog_id",
            catalog_id,
            "catalog publication",
            version=version,
        )
        if publication["definition_sha256"] != definition_sha:
            raise ComplianceScopeActionIntegrityError(
                "catalog publication is not bound to its immutable definition"
            )
        return self._catalog(definition, publication, definition_sha, publication_sha)

    def _get_plan(
        self, connection: sqlite3.Connection, tenant: str, plan_id: str
    ) -> ScopeActionPlan:
        payload, digest_value = self._get(
            connection,
            "scope_action_plans",
            tenant,
            "plan_id",
            plan_id,
            "action plan",
        )
        return self._plan(payload, digest_value)

    def _resolved_scope(self, tenant: str, scope_id: str) -> ResolvedFinalScope:
        try:
            raw = self._scope_resolver(tenant, scope_id)
        except ComplianceScopeActionError:
            raise
        except Exception as exc:
            raise ComplianceScopeActionConflict(
                "the authoritative finalized scope could not be resolved"
            ) from exc
        fields = frozenset(
            {
                "tenant_id",
                "scope_id",
                "scope_revision",
                "scope_integrity_sha256",
                "assessment_id",
                "assessment_revision",
                "assessment_integrity_sha256",
                "status",
                "applicable_frameworks",
                "control_applicability",
                "responsibility_assignments",
                "retained_until",
            }
        )
        value = _closed_mapping(raw, "resolved scope", fields)
        resolved_tenant = _tenant(value["tenant_id"])
        resolved_scope_id = _id(value["scope_id"], "resolved scope_id")
        if resolved_tenant != tenant or resolved_scope_id != scope_id:
            raise ComplianceScopeActionConflict(
                "the authoritative scope binding does not match the request"
            )
        if value["status"] != "finalized":
            raise ComplianceScopeActionConflict("scope must be finalized")
        responsibilities = _responsibilities(value["responsibility_assignments"])
        frameworks = _id_list(
            value["applicable_frameworks"],
            "applicable_frameworks",
            maximum=_MAX_SCOPE_CONTROLS,
        )
        controls: list[dict[str, object]] = []
        seen: set[tuple[str, str]] = set()
        for raw_control in _sequence(
            value["control_applicability"],
            "control_applicability",
            maximum=_MAX_SCOPE_CONTROLS,
        ):
            control = _closed_mapping(
                raw_control,
                "control applicability",
                frozenset(
                    {
                        "framework_ref",
                        "control_ref",
                        "reason_codes",
                        "responsibilities",
                    }
                ),
            )
            framework_ref = _id(control["framework_ref"], "framework_ref")
            control_ref = _id(control["control_ref"], "control_ref")
            reasons = _id_list(
                control["reason_codes"],
                "reason_codes",
                maximum=_MAX_REASON_CODES,
            )
            item_responsibilities = _responsibilities(control["responsibilities"])
            if item_responsibilities != responsibilities:
                raise ComplianceScopeActionIntegrityError(
                    "control responsibility assignments differ from finalized scope"
                )
            if framework_ref not in frameworks:
                raise ComplianceScopeActionIntegrityError(
                    "control framework is absent from applicable frameworks"
                )
            pair = (framework_ref, control_ref)
            if pair in seen:
                raise ComplianceScopeActionIntegrityError(
                    "resolved scope contains duplicate control applicability"
                )
            seen.add(pair)
            controls.append(
                {
                    "framework_ref": framework_ref,
                    "control_ref": control_ref,
                    "reason_codes": sorted(reasons),
                    "responsibilities": responsibilities,
                }
            )
        return ResolvedFinalScope(
            tenant_id=resolved_tenant,
            scope_id=resolved_scope_id,
            scope_revision=_integer(value["scope_revision"], "scope_revision", 1, 1_000_000),
            scope_integrity_sha256=_digest(
                value["scope_integrity_sha256"], "scope_integrity_sha256"
            ),
            assessment_id=_id(value["assessment_id"], "assessment_id"),
            assessment_revision=_integer(
                value["assessment_revision"], "assessment_revision", 1, 1_000_000
            ),
            assessment_integrity_sha256=_digest(
                value["assessment_integrity_sha256"],
                "assessment_integrity_sha256",
            ),
            status="finalized",
            applicable_frameworks=tuple(sorted(frameworks)),
            control_applicability=tuple(
                sorted(
                    controls,
                    key=lambda item: (str(item["framework_ref"]), str(item["control_ref"])),
                )
            ),
            responsibility_assignments=responsibilities,
            retained_until=_timestamp(value["retained_until"], "scope retained_until"),
        )

    @staticmethod
    def _scope_pin(scope: ResolvedFinalScope) -> dict[str, object]:
        return {
            "scope_id": scope.scope_id,
            "scope_revision": scope.scope_revision,
            "scope_integrity_sha256": scope.scope_integrity_sha256,
            "assessment_id": scope.assessment_id,
            "assessment_revision": scope.assessment_revision,
            "assessment_integrity_sha256": scope.assessment_integrity_sha256,
        }

    @classmethod
    def _assert_scope_pin(cls, plan: ScopeActionPlan, scope: ResolvedFinalScope) -> None:
        expected = {
            "scope_id": plan.scope_id,
            "scope_revision": plan.scope_revision,
            "scope_integrity_sha256": plan.scope_integrity_sha256,
            "assessment_id": plan.assessment_id,
            "assessment_revision": plan.assessment_revision,
            "assessment_integrity_sha256": plan.assessment_integrity_sha256,
        }
        if expected != cls._scope_pin(scope):
            raise ComplianceScopeActionConflict(
                "authoritative scope or assessment changed; create and approve a new plan"
            )

    @staticmethod
    def _assert_scope_active(scope: ResolvedFinalScope, now: float) -> None:
        if scope.retained_until <= now:
            raise ComplianceScopeActionConflict(
                "authoritative scope retention has expired; create a fresh scope"
            )

    def _assert_catalog_pin(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        plan: ScopeActionPlan,
    ) -> None:
        catalog = self._get_catalog(connection, tenant, plan.catalog_id, plan.catalog_version)
        if catalog.status != "published" or not text_equals(
            catalog.definition_sha256, str(plan.catalog_sha256)
        ):
            raise ComplianceScopeActionIntegrityError("plan catalog authority pin is invalid")

    @staticmethod
    def _desired_plan(
        scope: ResolvedFinalScope,
        catalog: ActionCatalogVersion,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        by_source: dict[tuple[str, str], list[Mapping[str, object]]] = {}
        for entry in catalog.entries:
            key = (str(entry["framework_ref"]), str(entry["scope_control_ref"]))
            by_source.setdefault(key, []).append(entry)

        source_pairs = {
            (str(item["framework_ref"]), str(item["control_ref"]))
            for item in scope.control_applicability
        }
        missing = sorted(source_pairs - set(by_source))
        if missing:
            raise ComplianceScopeActionConflict(
                f"published catalog does not map finalized scope controls: {missing}"
            )

        controls: dict[str, dict[str, object]] = {}
        evidence: dict[str, dict[str, object]] = {}
        for applicability in scope.control_applicability:
            source = (
                str(applicability["framework_ref"]),
                str(applicability["control_ref"]),
            )
            for entry in by_source[source]:
                control_ref = str(entry["desired_control_ref"])
                owner_role = str(entry["control_owner_role"])
                desired_state = str(entry["desired_control_state"])
                control = controls.get(control_ref)
                contract = (desired_state, owner_role)
                if (
                    control is not None
                    and (control["desired_state"], control["owner_role"]) != contract
                ):
                    raise ComplianceScopeActionIntegrityError(
                        "shared desired_control_ref has conflicting catalog contracts"
                    )
                if control is None:
                    digest_fragment = hashlib.sha256(
                        f"control:{control_ref}".encode("ascii")
                    ).hexdigest()[:20]
                    control = {
                        "intent_id": f"control-{digest_fragment}",
                        "control_ref": control_ref,
                        "desired_applicable": True,
                        "desired_state": desired_state,
                        "owner_role": owner_role,
                        "owner_ref": scope.responsibility_assignments[owner_role],
                        "first_line_ref": scope.responsibility_assignments["first_line"],
                        "second_line_ref": scope.responsibility_assignments["second_line"],
                        "evidence_owner_ref": scope.responsibility_assignments["evidence_owner"],
                        "source_applicability": [],
                        "reason_codes": [],
                    }
                    controls[control_ref] = control
                source_item = {
                    "framework_ref": source[0],
                    "scope_control_ref": source[1],
                    "reason_codes": sorted(applicability["reason_codes"]),
                    "catalog_entry_id": entry["entry_id"],
                }
                if source_item not in control["source_applicability"]:
                    control["source_applicability"].append(source_item)  # type: ignore[union-attr]
                control["reason_codes"] = sorted(  # type: ignore[index]
                    set(control["reason_codes"]) | set(applicability["reason_codes"])
                )

                for task in entry["evidence_tasks"]:
                    evidence_ref = str(task["evidence_mapping_ref"])
                    task_contract = (
                        str(task["task_kind"]),
                        str(task["owner_role"]),
                        str(task["cadence"]),
                    )
                    intent = evidence.get(evidence_ref)
                    if (
                        intent is not None
                        and (intent["task_kind"], intent["owner_role"], intent["cadence"])
                        != task_contract
                    ):
                        raise ComplianceScopeActionIntegrityError(
                            "shared evidence_mapping_ref has conflicting catalog contracts"
                        )
                    if intent is None:
                        digest_fragment = hashlib.sha256(
                            f"evidence:{evidence_ref}".encode("ascii")
                        ).hexdigest()[:20]
                        task_owner_role = str(task["owner_role"])
                        intent = {
                            "intent_id": f"evidence-{digest_fragment}",
                            "evidence_mapping_ref": evidence_ref,
                            "task_kind": task["task_kind"],
                            "cadence": task["cadence"],
                            "owner_role": task_owner_role,
                            "owner_ref": scope.responsibility_assignments[task_owner_role],
                            "first_line_ref": scope.responsibility_assignments["first_line"],
                            "second_line_ref": scope.responsibility_assignments["second_line"],
                            "evidence_owner_ref": scope.responsibility_assignments[
                                "evidence_owner"
                            ],
                            "control_refs": [],
                            "source_applicability": [],
                            "reason_codes": [],
                        }
                        evidence[evidence_ref] = intent
                    intent["control_refs"] = sorted(  # type: ignore[index]
                        set(intent["control_refs"]) | {control_ref}
                    )
                    if source_item not in intent["source_applicability"]:
                        intent["source_applicability"].append(source_item)  # type: ignore[union-attr]
                    intent["reason_codes"] = sorted(  # type: ignore[index]
                        set(intent["reason_codes"]) | set(applicability["reason_codes"])
                    )

        control_intents = sorted(controls.values(), key=lambda item: str(item["intent_id"]))
        evidence_intents = sorted(evidence.values(), key=lambda item: str(item["intent_id"]))
        for intent in (*control_intents, *evidence_intents):
            intent["source_applicability"] = sorted(
                intent["source_applicability"],  # type: ignore[arg-type]
                key=lambda source: (
                    str(source["framework_ref"]),
                    str(source["scope_control_ref"]),
                    str(source["catalog_entry_id"]),
                ),
            )
        if len(control_intents) + len(evidence_intents) > _MAX_INTENTS:
            raise ComplianceScopeActionConflict("desired plan exceeds its intent bound")
        return control_intents, evidence_intents

    def create_catalog_version(
        self,
        tenant_id: str,
        catalog_id: str,
        *,
        entries: Sequence[Mapping[str, object]],
        expected_latest_version: int,
        idempotency_key: str,
    ) -> ActionCatalogVersion:
        """Append an immutable, closed mapping catalog pending review."""

        tenant = _tenant(tenant_id)
        catalog_key = _id(catalog_id, "catalog_id")
        expected = _integer(expected_latest_version, "expected_latest_version", 0, 1_000_000)
        validated = sorted(
            (
                _catalog_entry(item)
                for item in _sequence(
                    entries,
                    "entries",
                    minimum=1,
                    maximum=_MAX_CATALOG_ENTRIES,
                )
            ),
            key=lambda item: str(item["entry_id"]),
        )
        if len({item["entry_id"] for item in validated}) != len(validated):
            raise ComplianceScopeActionValidationError("entry_id must be unique")
        contracts = [
            (
                item["framework_ref"],
                item["scope_control_ref"],
                item["desired_control_ref"],
            )
            for item in validated
        ]
        if len(set(contracts)) != len(contracts):
            raise ComplianceScopeActionValidationError(
                "catalog source-to-control contracts must be unique"
            )
        control_contracts: dict[str, tuple[object, object]] = {}
        evidence_contracts: dict[str, tuple[object, object, object]] = {}
        for item in validated:
            control_ref = str(item["desired_control_ref"])
            control_contract = (
                item["desired_control_state"],
                item["control_owner_role"],
            )
            if (
                control_ref in control_contracts
                and control_contracts[control_ref] != control_contract
            ):
                raise ComplianceScopeActionValidationError(
                    "shared desired_control_ref must have one closed contract"
                )
            control_contracts[control_ref] = control_contract
            for task in item["evidence_tasks"]:
                evidence_ref = str(task["evidence_mapping_ref"])
                evidence_contract = (task["task_kind"], task["owner_role"], task["cadence"])
                if (
                    evidence_ref in evidence_contracts
                    and evidence_contracts[evidence_ref] != evidence_contract
                ):
                    raise ComplianceScopeActionValidationError(
                        "shared evidence_mapping_ref must have one closed contract"
                    )
                evidence_contracts[evidence_ref] = evidence_contract
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        version = expected + 1
        request = {
            "action": "create_catalog_version",
            "catalog_id": catalog_key,
            "entries": validated,
            "expected_latest_version": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                return self._get_catalog(connection, tenant, catalog_key, version)
            latest = connection.execute(
                "SELECT MAX(version) AS latest FROM action_catalog_definitions "
                "WHERE tenant_id=? AND catalog_id=?",
                (tenant, catalog_key),
            ).fetchone()["latest"]
            latest_version = 0 if latest is None else int(latest)
            if latest_version != expected:
                raise ComplianceScopeActionConflict(
                    f"latest catalog CAS failed: expected {expected}, found {latest_version}"
                )
            definition = {
                "tenant_id": tenant,
                "catalog_id": catalog_key,
                "version": version,
                "entries": validated,
                "created_by": actor,
                "created_at": now,
            }
            definition_sha = self._insert(
                connection,
                "action_catalog_definitions",
                ("tenant_id", "catalog_id", "version"),
                (tenant, catalog_key, version),
                definition,
            )
            publication = {
                "tenant_id": tenant,
                "catalog_id": catalog_key,
                "version": version,
                "definition_sha256": definition_sha,
                "status": "pending_review",
                "reviewed_by": None,
                "revision": 1,
                "reviewed_at": None,
            }
            publication_sha = self._insert(
                connection,
                "action_catalog_publications",
                ("tenant_id", "catalog_id", "version", "status"),
                (tenant, catalog_key, version, "pending_review"),
                publication,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "catalog",
                f"{catalog_key}:{version}",
                1,
            )
            self._audit(
                connection,
                tenant,
                "catalog_version_created",
                f"{catalog_key}:{version}",
                actor,
                {"entry_count": len(validated), "definition_sha256": definition_sha},
                now,
            )
            return self._catalog(definition, publication, definition_sha, publication_sha)

    def approve_catalog_version(
        self,
        tenant_id: str,
        catalog_id: str,
        version: int,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ActionCatalogVersion:
        """Publish a catalog only after independent four-eyes approval."""

        tenant = _tenant(tenant_id)
        catalog_key = _id(catalog_id, "catalog_id")
        catalog_version = _integer(version, "version", 1, 1_000_000)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "approve_catalog_version",
            "catalog_id": catalog_key,
            "version": catalog_version,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            current = self._get_catalog(connection, tenant, catalog_key, catalog_version)
            if operation is not None:
                return current
            if current.revision != expected:
                raise ComplianceScopeActionConflict(
                    f"catalog revision CAS failed: expected {expected}, found {current.revision}"
                )
            if current.status != "pending_review":
                raise ComplianceScopeActionConflict("catalog is not pending review")
            if current.created_by == actor:
                raise ComplianceScopeActionPermissionDenied(
                    "catalog approval requires a principal distinct from its creator"
                )
            publication = {
                "tenant_id": tenant,
                "catalog_id": catalog_key,
                "version": catalog_version,
                "definition_sha256": current.definition_sha256,
                "status": "published",
                "reviewed_by": actor,
                "revision": current.revision + 1,
                "reviewed_at": now,
            }
            publication_sha = _sha256(publication)
            connection.execute(
                "UPDATE action_catalog_publications SET status=?,payload_json=?,"
                "integrity_sha256=? WHERE tenant_id=? AND catalog_id=? AND version=?",
                (
                    "published",
                    _canonical(publication).decode("ascii"),
                    publication_sha,
                    tenant,
                    catalog_key,
                    catalog_version,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "catalog",
                f"{catalog_key}:{catalog_version}",
                publication["revision"],
            )
            self._audit(
                connection,
                tenant,
                "catalog_version_approved",
                f"{catalog_key}:{catalog_version}",
                actor,
                {"definition_sha256": current.definition_sha256},
                now,
            )
            definition, definition_sha = self._get(
                connection,
                "action_catalog_definitions",
                tenant,
                "catalog_id",
                catalog_key,
                "catalog definition",
                version=catalog_version,
            )
            return self._catalog(definition, publication, definition_sha, publication_sha)

    publish_catalog_version = approve_catalog_version

    def get_catalog_version(
        self, tenant_id: str, catalog_id: str, version: int
    ) -> ActionCatalogVersion:
        tenant = _tenant(tenant_id)
        catalog_key = _id(catalog_id, "catalog_id")
        catalog_version = _integer(version, "version", 1, 1_000_000)
        self._actor()
        with self._connect() as connection:
            return self._get_catalog(connection, tenant, catalog_key, catalog_version)

    def create_plan(
        self,
        tenant_id: str,
        scope_id: str,
        plan_id: str,
        *,
        catalog_id: str,
        catalog_version: int,
        expected_scope_revision: int,
        retained_until: float,
        idempotency_key: str,
    ) -> ScopeActionPlan:
        """Resolve the authoritative finalized scope and derive a desired plan."""

        tenant = _tenant(tenant_id)
        scope_key = _id(scope_id, "scope_id")
        plan_key = _id(plan_id, "plan_id")
        catalog_key = _id(catalog_id, "catalog_id")
        version = _integer(catalog_version, "catalog_version", 1, 1_000_000)
        expected_scope = _integer(expected_scope_revision, "expected_scope_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        retained = _retained_until(retained_until, now)
        scope = self._resolved_scope(tenant, scope_key)
        self._assert_scope_active(scope, now)
        if scope.scope_revision != expected_scope:
            raise ComplianceScopeActionConflict(
                f"scope revision CAS failed: expected {expected_scope}, "
                f"found {scope.scope_revision}"
            )
        request = {
            "action": "create_plan",
            "scope_id": scope_key,
            "plan_id": plan_key,
            "catalog_id": catalog_key,
            "catalog_version": version,
            "expected_scope_revision": expected_scope,
            "resolved_scope_pin": self._scope_pin(scope),
            "retained_until": retained,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                return self._get_plan(connection, tenant, plan_key)
            catalog = self._get_catalog(connection, tenant, catalog_key, version)
            if catalog.status != "published":
                raise ComplianceScopeActionConflict(
                    "only independently approved catalogs can create plans"
                )
            control_intents, evidence_intents = self._desired_plan(scope, catalog)
            desired = {
                "responsibility_assignments": dict(scope.responsibility_assignments),
                "control_intents": control_intents,
                "evidence_task_intents": evidence_intents,
            }
            desired_sha = _sha256(desired)
            payload = {
                "tenant_id": tenant,
                "plan_id": plan_key,
                **self._scope_pin(scope),
                "catalog_id": catalog_key,
                "catalog_version": version,
                "catalog_sha256": catalog.definition_sha256,
                **desired,
                "desired_sha256": desired_sha,
                "status": "draft",
                "planned_by": actor,
                "approved_by": None,
                "last_operation": None,
                "last_outcome": None,
                "last_receipt": None,
                "reconciliation_count": 0,
                "rollback_of_revision": None,
                "retained_until": min(retained, scope.retained_until),
                "revision": 1,
                "created_at": now,
                "updated_at": now,
            }
            digest_value = self._insert(
                connection,
                "scope_action_plans",
                ("tenant_id", "plan_id", "status", "retained_until"),
                (tenant, plan_key, "draft", payload["retained_until"]),
                payload,
            )
            self._insert(
                connection,
                "scope_action_plan_history",
                ("tenant_id", "plan_id", "revision", "status"),
                (tenant, plan_key, 1, "draft"),
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "plan",
                plan_key,
                1,
            )
            self._audit(
                connection,
                tenant,
                "desired_plan_created",
                plan_key,
                actor,
                {
                    "scope_integrity_sha256": scope.scope_integrity_sha256,
                    "assessment_integrity_sha256": scope.assessment_integrity_sha256,
                    "catalog_sha256": catalog.definition_sha256,
                    "desired_sha256": desired_sha,
                    "control_intents": len(control_intents),
                    "evidence_task_intents": len(evidence_intents),
                },
                now,
            )
            return self._plan(payload, digest_value)

    def approve_plan(
        self,
        tenant_id: str,
        plan_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ScopeActionPlan:
        """Independently approve an exact desired plan and its authority pins."""

        tenant = _tenant(tenant_id)
        plan_key = _id(plan_id, "plan_id")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "approve_plan",
            "plan_id": plan_key,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            current = self._get_plan(connection, tenant, plan_key)
            if operation is not None:
                return current
            if current.revision != expected:
                raise ComplianceScopeActionConflict(
                    f"plan revision CAS failed: expected {expected}, found {current.revision}"
                )
            if current.status != "draft":
                raise ComplianceScopeActionConflict("plan is not a draft")
            if current.planned_by == actor:
                raise ComplianceScopeActionPermissionDenied(
                    "plan approval requires a principal distinct from its planner"
                )
            scope = self._resolved_scope(tenant, current.scope_id)
            self._assert_scope_pin(current, scope)
            self._assert_scope_active(scope, now)
            self._assert_catalog_pin(connection, tenant, current)
            payload = self._plan_payload(current)
            payload.update(
                {
                    "status": "approved",
                    "approved_by": actor,
                    "revision": current.revision + 1,
                    "updated_at": now,
                }
            )
            digest_value = self._write_plan(connection, tenant, plan_key, payload)
            self._insert(
                connection,
                "scope_action_plan_history",
                ("tenant_id", "plan_id", "revision", "status"),
                (tenant, plan_key, payload["revision"], "approved"),
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "plan",
                plan_key,
                payload["revision"],
            )
            self._audit(
                connection,
                tenant,
                "desired_plan_approved",
                plan_key,
                actor,
                {"desired_sha256": current.desired_sha256},
                now,
            )
            return self._plan(payload, digest_value)

    @staticmethod
    def _plan_payload(plan: ScopeActionPlan) -> dict[str, object]:
        values = dict(plan.__dict__)
        values.pop("integrity_sha256")
        values["responsibility_assignments"] = dict(plan.responsibility_assignments)
        values["control_intents"] = [dict(item) for item in plan.control_intents]
        values["evidence_task_intents"] = [dict(item) for item in plan.evidence_task_intents]
        values["last_receipt"] = None if plan.last_receipt is None else dict(plan.last_receipt)
        return values

    @staticmethod
    def _validate_apply_receipt(
        value: object,
        *,
        operation: str,
        desired_intent_ids: frozenset[str],
        desired_sha256: str,
        operation_ref: str,
    ) -> dict[str, object]:
        receipt = _closed_mapping(
            value,
            "apply callback receipt",
            frozenset(
                {
                    "operation",
                    "operation_ref",
                    "desired_sha256",
                    "outcome",
                    "intent_bindings",
                }
            ),
        )
        if receipt["operation"] != operation:
            raise ComplianceScopeActionIntegrityError("apply callback returned the wrong operation")
        if receipt["operation_ref"] != operation_ref:
            raise ComplianceScopeActionIntegrityError(
                "apply callback returned the wrong operation_ref"
            )
        if receipt["desired_sha256"] != desired_sha256:
            raise ComplianceScopeActionIntegrityError(
                "apply callback returned the wrong desired plan digest"
            )
        outcomes = {
            "apply": {"applied", "no_change"},
            "reconcile": {"reconciled", "no_change"},
            "rollback": {"rolled_back", "no_change"},
        }
        outcome = _id(receipt["outcome"], "outcome")
        if outcome not in outcomes[operation]:
            raise ComplianceScopeActionIntegrityError("apply callback returned an invalid outcome")
        bindings: list[dict[str, str]] = []
        seen: set[str] = set()
        for raw in _sequence(
            receipt["intent_bindings"],
            "intent_bindings",
            maximum=_MAX_INTENTS,
        ):
            binding = _closed_mapping(
                raw,
                "intent binding",
                frozenset({"intent_id", "resource_ref", "change"}),
            )
            intent_id = _id(binding["intent_id"], "intent_id")
            resource_ref = _id(binding["resource_ref"], "resource_ref", _REF_RE)
            change = _id(binding["change"], "change")
            allowed_changes = (
                {"removed", "unchanged"}
                if operation == "rollback"
                else {"created", "updated", "reused", "unchanged"}
            )
            if change not in allowed_changes:
                raise ComplianceScopeActionIntegrityError(
                    "apply callback returned an invalid change"
                )
            if intent_id in seen or intent_id not in desired_intent_ids:
                raise ComplianceScopeActionIntegrityError(
                    "apply callback returned an unknown or duplicate intent"
                )
            seen.add(intent_id)
            bindings.append(
                {
                    "intent_id": intent_id,
                    "resource_ref": resource_ref,
                    "change": change,
                }
            )
        if seen != set(desired_intent_ids):
            raise ComplianceScopeActionIntegrityError(
                "apply callback must account for every desired intent"
            )
        if outcome == "no_change" and any(
            binding["change"] not in {"reused", "unchanged"} for binding in bindings
        ):
            raise ComplianceScopeActionIntegrityError(
                "no_change receipts may contain only reused or unchanged bindings"
            )
        return {
            "operation": operation,
            "operation_ref": operation_ref,
            "desired_sha256": desired_sha256,
            "outcome": outcome,
            "intent_bindings": sorted(bindings, key=lambda item: item["intent_id"]),
        }

    def _execute(
        self,
        tenant_id: str,
        plan_id: str,
        *,
        operation: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> ScopeActionPlan:
        if self._apply_callback is None:
            raise ComplianceScopeActionConfigError(
                "no local apply callback is configured; the desired plan remains write-free"
            )
        tenant = _tenant(tenant_id)
        plan_key = _id(plan_id, "plan_id")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        if operation not in {"apply", "reconcile", "rollback"}:
            raise ComplianceScopeActionValidationError("operation is unsupported")
        request = {
            "action": operation,
            "plan_id": plan_key,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, prior_operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            current = self._get_plan(connection, tenant, plan_key)
            if prior_operation is not None:
                return current
            if current.revision != expected:
                raise ComplianceScopeActionConflict(
                    f"plan revision CAS failed: expected {expected}, found {current.revision}"
                )
            allowed_states = {
                "apply": {"approved"},
                "reconcile": {"applied", "no_change"},
                "rollback": {"applied", "no_change"},
            }
            if current.status not in allowed_states[operation]:
                raise ComplianceScopeActionConflict(
                    f"plan state {current.status} cannot perform {operation}"
                )
            if current.approved_by is None or current.approved_by == current.planned_by:
                raise ComplianceScopeActionIntegrityError("plan lacks independent approval")
            scope = self._resolved_scope(tenant, current.scope_id)
            self._assert_scope_pin(current, scope)
            self._assert_scope_active(scope, now)
            self._assert_catalog_pin(connection, tenant, current)
            operation_ref = (
                "op-"
                + hashlib.sha256(
                    _canonical(
                        {
                            "tenant_id": tenant,
                            "plan_id": plan_key,
                            "operation": operation,
                            "idempotency_key": idempotency_key,
                            "expected_revision": expected,
                            "desired_sha256": current.desired_sha256,
                        }
                    )
                ).hexdigest()[:32]
            )
            callback_request = {
                "schema": APPLY_SCHEMA,
                "operation": operation,
                "operation_ref": operation_ref,
                "tenant_id": tenant,
                "plan_id": plan_key,
                "expected_revision": expected,
                "desired_sha256": current.desired_sha256,
                "responsibility_assignments": dict(current.responsibility_assignments),
                "control_intents": [dict(item) for item in current.control_intents],
                "evidence_task_intents": [dict(item) for item in current.evidence_task_intents],
                "prior_receipt": (
                    None if current.last_receipt is None else dict(current.last_receipt)
                ),
            }
            try:
                raw_receipt = self._apply_callback(callback_request)
            except ComplianceScopeActionError:
                raise
            except Exception as exc:
                raise ComplianceScopeActionConflict(
                    "local apply callback failed; plan state was not advanced"
                ) from exc
            intent_ids = frozenset(
                str(item["intent_id"])
                for item in (*current.control_intents, *current.evidence_task_intents)
            )
            receipt = self._validate_apply_receipt(
                raw_receipt,
                operation=operation,
                desired_intent_ids=intent_ids,
                desired_sha256=current.desired_sha256,
                operation_ref=operation_ref,
            )
            if operation == "rollback":
                next_status = "rolled_back"
            elif receipt["outcome"] == "no_change":
                next_status = "no_change"
            else:
                next_status = "applied"
            payload = self._plan_payload(current)
            payload.update(
                {
                    "status": next_status,
                    "last_operation": operation,
                    "last_outcome": receipt["outcome"],
                    "last_receipt": receipt,
                    "reconciliation_count": current.reconciliation_count
                    + (1 if operation == "reconcile" else 0),
                    "rollback_of_revision": (current.revision if operation == "rollback" else None),
                    "revision": current.revision + 1,
                    "updated_at": now,
                }
            )
            digest_value = self._write_plan(connection, tenant, plan_key, payload)
            self._insert(
                connection,
                "scope_action_plan_history",
                ("tenant_id", "plan_id", "revision", "status"),
                (tenant, plan_key, payload["revision"], next_status),
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "plan",
                plan_key,
                payload["revision"],
            )
            self._audit(
                connection,
                tenant,
                f"plan_{operation}_completed",
                plan_key,
                actor,
                {
                    "outcome": receipt["outcome"],
                    "operation_ref": operation_ref,
                    "desired_sha256": current.desired_sha256,
                    "revision": payload["revision"],
                },
                now,
            )
            return self._plan(payload, digest_value)

    def apply_plan(
        self,
        tenant_id: str,
        plan_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ScopeActionPlan:
        return self._execute(
            tenant_id,
            plan_id,
            operation="apply",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def reconcile_plan(
        self,
        tenant_id: str,
        plan_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ScopeActionPlan:
        return self._execute(
            tenant_id,
            plan_id,
            operation="reconcile",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def rollback_plan(
        self,
        tenant_id: str,
        plan_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ScopeActionPlan:
        return self._execute(
            tenant_id,
            plan_id,
            operation="rollback",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def get_plan(self, tenant_id: str, plan_id: str) -> ScopeActionPlan:
        tenant = _tenant(tenant_id)
        plan_key = _id(plan_id, "plan_id")
        self._actor()
        with self._connect() as connection:
            return self._get_plan(connection, tenant, plan_key)

    def get_plan_history(self, tenant_id: str, plan_id: str) -> tuple[ScopeActionPlan, ...]:
        tenant = _tenant(tenant_id)
        plan_key = _id(plan_id, "plan_id")
        self._actor()
        with self._connect() as connection:
            self._get_plan(connection, tenant, plan_key)
            rows = connection.execute(
                "SELECT * FROM scope_action_plan_history WHERE tenant_id=? "
                "AND plan_id=? ORDER BY revision",
                (tenant, plan_key),
            ).fetchall()
            return tuple(
                self._plan(*self._payload(row, "action plan history", tenant)) for row in rows
            )

    def export_plan(
        self,
        tenant_id: str,
        plan_id: str,
        export_id: str,
        *,
        signing_key_ref: str,
        retained_until: float,
        idempotency_key: str,
    ) -> SignedScopeActionExport:
        """Sign the exact approved/executed desired plan and local history."""

        tenant = _tenant(tenant_id)
        plan_key = _id(plan_id, "plan_id")
        export_key = _id(export_id, "export_id")
        key_ref = _id(signing_key_ref, "signing_key_ref", _KEY_REF_RE)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        retained = _retained_until(retained_until, now)
        request = {
            "action": "export_plan",
            "plan_id": plan_key,
            "export_id": export_key,
            "signing_key_ref": key_ref,
            "retained_until": retained,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                raw, digest_value = self._get(
                    connection,
                    "scope_action_exports",
                    tenant,
                    "export_id",
                    export_key,
                    "scope-action export",
                )
                return self._export(raw, digest_value)
            plan = self._get_plan(connection, tenant, plan_key)
            if plan.status == "draft":
                raise ComplianceScopeActionConflict("draft plans cannot be exported")
            self._assert_catalog_pin(connection, tenant, plan)
            plan_payload = self._plan_payload(plan)
            history_rows = connection.execute(
                "SELECT * FROM scope_action_plan_history WHERE tenant_id=? "
                "AND plan_id=? ORDER BY revision",
                (tenant, plan_key),
            ).fetchall()
            history = [self._payload(row, "action plan history", tenant)[0] for row in history_rows]
            body = {
                "plan": plan_payload,
                "plan_integrity_sha256": plan.integrity_sha256,
                "history": history,
                "limitations": self.product_boundaries(),
            }
            body_sha = _sha256(body)
            key = self._signing_key_resolver(tenant, key_ref)
            if not isinstance(key, bytes) or len(key) < 32:
                raise ComplianceScopeActionConfigError(
                    "scope-action export signing key must contain at least 32 bytes"
                )
            signature = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
            payload = {
                "tenant_id": tenant,
                "export_id": export_key,
                "plan_id": plan_key,
                "schema": EXPORT_SCHEMA,
                "body": body,
                "body_sha256": body_sha,
                "signing_key_ref": key_ref,
                "signature_hmac_sha256": signature,
                "retained_until": min(retained, plan.retained_until),
                "created_by": actor,
                "created_at": now,
            }
            digest_value = self._insert(
                connection,
                "scope_action_exports",
                ("tenant_id", "export_id", "plan_id", "retained_until"),
                (tenant, export_key, plan_key, payload["retained_until"]),
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "export",
                export_key,
                plan.revision,
            )
            self._audit(
                connection,
                tenant,
                "plan_export_signed",
                export_key,
                actor,
                {"plan_id": plan_key, "body_sha256": body_sha},
                now,
            )
            return self._export(payload, digest_value)

    def get_export(self, tenant_id: str, export_id: str) -> SignedScopeActionExport:
        tenant = _tenant(tenant_id)
        export_key = _id(export_id, "export_id")
        self._actor()
        with self._connect() as connection:
            raw, digest_value = self._get(
                connection,
                "scope_action_exports",
                tenant,
                "export_id",
                export_key,
                "scope-action export",
            )
            export = self._export(raw, digest_value)
            self._verify_export_signature(export)
            return export

    def _verify_export_signature(self, export: SignedScopeActionExport) -> None:
        if _sha256(export.body) != export.body_sha256:
            raise ComplianceScopeActionIntegrityError("scope-action export body digest is invalid")
        key = self._signing_key_resolver(export.tenant_id, export.signing_key_ref)
        if not isinstance(key, bytes) or len(key) < 32:
            raise ComplianceScopeActionConfigError(
                "scope-action export signing key must contain at least 32 bytes"
            )
        expected = hmac.new(key, _canonical(export.body), hashlib.sha256).hexdigest()
        if not text_equals(expected, str(export.signature_hmac_sha256)):
            raise ComplianceScopeActionIntegrityError("scope-action export signature is invalid")

    def list_records(self, tenant_id: str, *, limit: int = 200) -> dict[str, tuple]:
        """Read-only, newest-first listing of catalogs, plans and exports,
        each loaded through the integrity-checked single-record readers."""

        tenant = _tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 1_000)
        self._actor()
        with self._connect() as connection:
            catalogs = tuple(
                self._get_catalog(connection, tenant, row[0], int(row[1]))
                for row in connection.execute(
                    "SELECT catalog_id, version FROM action_catalog_definitions "
                    "WHERE tenant_id=? ORDER BY catalog_id, version DESC LIMIT ?",
                    (tenant, bounded),
                ).fetchall()
            )
            plans = tuple(
                self._get_plan(connection, tenant, row[0])
                for row in connection.execute(
                    "SELECT plan_id FROM scope_action_plans WHERE tenant_id=? "
                    "ORDER BY rowid DESC LIMIT ?",
                    (tenant, bounded),
                ).fetchall()
            )
            exports = tuple(
                self._export(*self._get(
                    connection, "scope_action_exports", tenant, "export_id",
                    row[0], "action plan export",
                ))
                for row in connection.execute(
                    "SELECT export_id FROM scope_action_exports WHERE tenant_id=? "
                    "ORDER BY rowid DESC LIMIT ?",
                    (tenant, bounded),
                ).fetchall()
            )
        return {"catalogs": catalogs, "plans": plans, "exports": exports}

    def verify_integrity(self, tenant_id: str) -> IntegrityVerification:
        tenant = _tenant(tenant_id)
        self._actor()
        verified = 0
        with self._connect() as connection:
            for table, label in (
                ("action_catalog_definitions", "catalog definition"),
                ("action_catalog_publications", "catalog publication"),
                ("scope_action_plans", "action plan"),
                ("scope_action_plan_history", "action plan history"),
                ("scope_action_exports", "scope-action export"),
            ):
                rows = connection.execute(
                    f"SELECT * FROM {table} WHERE tenant_id=?",  # noqa: S608
                    (tenant,),
                ).fetchall()
                for row in rows:
                    payload, digest_value = self._payload(row, label, tenant)
                    for column in ("catalog_id", "version", "plan_id", "status"):
                        if column in row.keys() and column in payload:
                            if str(row[column]) != str(payload[column]):
                                raise ComplianceScopeActionIntegrityError(
                                    f"{label} indexed {column} is inconsistent"
                                )
                    if table == "scope_action_exports":
                        self._verify_export_signature(self._export(payload, digest_value))
                    if table in {"scope_action_plans", "scope_action_plan_history"}:
                        plan = self._plan(payload, digest_value)
                        desired = {
                            "responsibility_assignments": dict(plan.responsibility_assignments),
                            "control_intents": [dict(item) for item in plan.control_intents],
                            "evidence_task_intents": [
                                dict(item) for item in plan.evidence_task_intents
                            ],
                        }
                        if not text_equals(_sha256(desired), str(plan.desired_sha256)):
                            raise ComplianceScopeActionIntegrityError(
                                "action plan desired digest is invalid"
                            )
                        if plan.status not in PLAN_STATES:
                            raise ComplianceScopeActionIntegrityError(
                                "action plan state is invalid"
                            )
                        self._assert_catalog_pin(connection, tenant, plan)
                        if table == "scope_action_plans":
                            latest = connection.execute(
                                "SELECT * FROM scope_action_plan_history "
                                "WHERE tenant_id=? AND plan_id=? "
                                "ORDER BY revision DESC LIMIT 1",
                                (tenant, plan.plan_id),
                            ).fetchone()
                            if latest is None:
                                raise ComplianceScopeActionIntegrityError(
                                    "action plan has no immutable history"
                                )
                            latest_payload, latest_sha = self._payload(
                                latest, "action plan history", tenant
                            )
                            if latest_payload != payload or not hmac.compare_digest(
                                latest_sha, digest_value
                            ):
                                raise ComplianceScopeActionIntegrityError(
                                    "action plan differs from its latest immutable history"
                                )
                    verified += 1
            publications = connection.execute(
                "SELECT * FROM action_catalog_publications WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            for row in publications:
                publication, _publication_sha = self._payload(row, "catalog publication", tenant)
                definition, definition_sha = self._get(
                    connection,
                    "action_catalog_definitions",
                    tenant,
                    "catalog_id",
                    str(publication["catalog_id"]),
                    "catalog definition",
                    version=int(publication["version"]),
                )
                del definition
                if not text_equals(definition_sha, str(publication["definition_sha256"])):
                    raise ComplianceScopeActionIntegrityError(
                        "catalog publication definition binding is invalid"
                    )
            audit_rows = connection.execute(
                "SELECT * FROM scope_action_audit_events WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
            previous_sha = "0" * 64
            expected_sequence = 1
            for row in audit_rows:
                payload, digest_value = self._payload(row, "audit event", tenant)
                if (
                    int(payload.get("sequence", 0)) != expected_sequence
                    or int(row["sequence"]) != expected_sequence
                    or payload.get("previous_integrity_sha256") != previous_sha
                ):
                    raise ComplianceScopeActionIntegrityError("scope-action audit chain is invalid")
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
            "scope_source": "injected_finalized_scope_resolver",
            "mapping_catalog": "opaque_refs_only_four_eyes",
            "licensed_framework_content_included": False,
            "raw_evidence_persisted": False,
            "free_text_task_descriptions_persisted": False,
            "arbitrary_code_or_expression_evaluation": False,
            "built_in_provider_writes": False,
            "apply_requires_injected_local_callback": True,
            "callback_must_be_idempotent": True,
            "cross_store_atomicity": False,
            "callback_exception_proves_no_change": False,
            "live_provider_acceptance_verified": False,
            "legal_or_certification_determination": False,
        }


__all__ = [
    "APPLY_SCHEMA",
    "AUDIT_SCHEMA",
    "ActionCatalogVersion",
    "ComplianceScopeActionConfigError",
    "ComplianceScopeActionConflict",
    "ComplianceScopeActionError",
    "ComplianceScopeActionIntegrityError",
    "ComplianceScopeActionNotFound",
    "ComplianceScopeActionPermissionDenied",
    "ComplianceScopeActionStore",
    "ComplianceScopeActionValidationError",
    "EXPORT_SCHEMA",
    "IntegrityVerification",
    "ResolvedFinalScope",
    "SignedScopeActionExport",
    "ScopeActionPlan",
    "enabled",
    "require_enabled",
    "resolver_from_scoping_store",
]
