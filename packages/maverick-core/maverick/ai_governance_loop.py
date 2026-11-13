"""Durable, digest-only AI-governance closed-loop coordination.

The platform already owns authoritative inventory, declaration, dynamic-risk,
policy, runtime-enforcement, and evidence records.  This module does *not*
replace those authorities and never reads their private stores.  Instead an
injected :class:`GovernanceAuthorityReader` returns one closed, safe snapshot.
The coordinator reads that snapshot twice, rejects drift, and records the
exact pins that explain the resulting control-loop state.

Only opaque identifiers, integer revisions, timestamps, decisions,
limitations, and SHA-256 commitments are accepted or persisted.  There is no
prompt/output/telemetry/provider payload field and no provider mutation seam.
Restrict and block decisions therefore produce an escalation until a human
authorizes the exact policy commitment; a later authoritative enforcement
receipt is still required before the control is reported as observed.

The SQLite store supplies per-asset CAS, idempotent operations, fenced leases,
bounded exponential retry, replay, projection-only rollback, and a hash-linked
history.  History rows can be projected into the closed action vocabulary used
by :mod:`maverick.unified_audit` without copying source payloads.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Protocol, runtime_checkable

from .constant_time import text_equals
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import InvalidTenantError, canonical_tenant_id
from .sqlite_closing import ClosingConnection
from .unified_audit import SOURCE_ACTION_CODES, SourceRecord, build_source_record

SCHEMA_VERSION = 1
SOURCE_ID = "ai_governance"
SUITE_ID = "ai_governance"
GENESIS_SHA256 = "0" * 64

TRIGGER_CODES = frozenset(
    {
        "inventory_changed",
        "declaration_changed",
        "risk_changed",
        "policy_changed",
        "enforcement_receipt",
        "evidence_changed",
        "manual_reconcile",
    }
)

STATE_CODES = frozenset(
    {
        "queued",
        "recovery_pending",
        "review_required",
        "escalated",
        "control_pending",
        "restricted",
        "blocked",
        "monitoring",
        "rollback_pending",
        "revoked",
    }
)

DECISION_CODES = frozenset(
    {"unknown", "not_applicable", "allow", "monitor", "review", "restrict", "block"}
)

LIMITATION_CODES = frozenset(
    {
        "authority_unavailable",
        "authority_changed",
        "declaration_unapproved",
        "risk_stale",
        "policy_stale",
        "enforcement_missing",
        "enforcement_mismatch",
        "evidence_incomplete",
        "human_authorization_required",
        "reconciliation_pending",
        "retry_exhausted",
        "rollback_pending",
        "rollback_applied_requires_reconciliation",
        "control_authorization_revoked",
        "source_incomplete",
        "revoked",
    }
)

EVENT_CODES = frozenset(
    {
        "trigger_enqueued",
        "lease_claimed",
        "lease_reclaimed",
        "lease_failed",
        "lease_exhausted",
        "reconciled",
        "reconciliation_no_change",
        "control_authorized",
        "control_authorization_revoked",
        "replay_authorized",
        "rollback_authorized",
        "rollback_authorization_revoked",
        "rollback_applied",
        "case_revoked",
    }
)

AUDIT_ACTION_CODES = SOURCE_ACTION_CODES

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_CANONICAL_BYTES = 2 * 1024 * 1024
_MAX_HISTORY_ROWS = 1_000_000
_MAX_FUTURE_SKEW_SECONDS = 300.0
_MAX_TIMESTAMP = 100_000_000_000.0
_MAX_LEASE_SECONDS = 3600.0
_MAX_ATTEMPTS = 32
_MAX_BACKOFF_SECONDS = 24 * 60 * 60.0
_AUTHORITY_NAMES = (
    "inventory",
    "declaration",
    "risk",
    "policy",
    "enforcement",
    "evidence",
)


class AIGovernanceLoopError(RuntimeError):
    """Base failure for the closed-loop coordinator."""


class AIGovernanceLoopConfigError(AIGovernanceLoopError):
    """The loop or one of its authoritative dependencies is disabled."""


class AIGovernanceLoopValidationError(AIGovernanceLoopError, ValueError):
    """An input is outside a closed, digest-only contract."""


class AIGovernanceLoopConflict(AIGovernanceLoopError):
    """CAS, idempotency, ordering, or authority preconditions conflict."""


class AIGovernanceLoopNotFound(AIGovernanceLoopError):
    """A tenant-bound case or target revision does not exist."""


class AIGovernanceLoopLeaseLost(AIGovernanceLoopConflict):
    """The caller no longer owns the fenced reconciliation lease."""


class AIGovernanceLoopIntegrityError(AIGovernanceLoopError):
    """Persisted history or projection integrity failed validation."""


class AIGovernanceLoopAuthorityDrift(AIGovernanceLoopConflict):
    """The injected authorities changed between the required double reads."""


def enabled(config: Mapping[str, object] | None = None) -> bool:
    """Require the loop and all four authoritative control planes exactly on."""

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
    required = (
        "ai_inventory",
        "ai_dynamic_risk",
        "ai_policy_management",
        "ai_runtime_guardrails",
        "ai_governance_loop",
    )
    return all(
        isinstance(config.get(section), Mapping)
        and config[section].get("enable") is True  # type: ignore[union-attr]
        for section in required
    )


def require_enabled() -> None:
    """Fail closed unless the loop and every authority dependency are enabled."""

    if not enabled():
        raise AIGovernanceLoopConfigError(
            "AI governance loop is disabled; explicitly enable the loop, inventory, "
            "dynamic risk, policy management, and runtime guardrails"
        )


def _canonical(value: object, *, maximum: int = _MAX_CANONICAL_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AIGovernanceLoopValidationError("value must be finite canonical JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise AIGovernanceLoopValidationError("canonical value exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value: object, label: str, *, allow_genesis: bool = False) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise AIGovernanceLoopValidationError(f"{label} must be a lowercase SHA-256 digest")
    if not allow_genesis and value == GENESIS_SHA256:
        raise AIGovernanceLoopValidationError(f"{label} cannot be the genesis digest")
    return value


def _token(value: object, label: str) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise AIGovernanceLoopValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (InvalidTenantError, TypeError, ValueError) as exc:
        raise AIGovernanceLoopValidationError("tenant_id is invalid") from exc


def _revision(value: object, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 2**63 - 1:
        raise AIGovernanceLoopValidationError(f"{label} is outside its revision bound")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise AIGovernanceLoopValidationError(f"{label} is outside its integer bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AIGovernanceLoopValidationError(f"{label} must be a finite timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0 or result >= _MAX_TIMESTAMP:
        raise AIGovernanceLoopValidationError(f"{label} must be a finite timestamp")
    return result


def _positive_number(value: object, label: str, maximum: float) -> float:
    result = _timestamp(value, label)
    if result > maximum:
        raise AIGovernanceLoopValidationError(f"{label} exceeds its bound")
    return result


def _closed(value: object, vocabulary: frozenset[str], label: str) -> str:
    if not isinstance(value, str) or value not in vocabulary:
        raise AIGovernanceLoopValidationError(f"{label} is outside its closed vocabulary")
    return value


def _limitations(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise AIGovernanceLoopValidationError("limitations must be a sorted tuple")
    if (
        len(value) > len(LIMITATION_CODES)
        or any(not isinstance(item, str) or item not in LIMITATION_CODES for item in value)
        or tuple(sorted(set(value))) != value
    ):
        raise AIGovernanceLoopValidationError("limitations are outside the closed vocabulary")
    return value


def _operation_key(value: object) -> str:
    text = _token(value, "idempotency_key")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AuthorityPin:
    """One exact source-owned record commitment.

    Revision zero is reserved for an explicitly committed absence.  It still
    requires a non-genesis digest, so absence cannot be confused with an
    uninitialized value.
    """

    tenant_id: str
    asset_id: str
    record_id: str
    revision: int
    sha256: str

    def normalized(self) -> AuthorityPin:
        return AuthorityPin(
            tenant_id=_tenant(self.tenant_id),
            asset_id=_token(self.asset_id, "asset_id"),
            record_id=_token(self.record_id, "record_id"),
            revision=_revision(self.revision, "authority revision", allow_zero=True),
            sha256=_digest(self.sha256, "authority sha256"),
        )


@dataclass(frozen=True, slots=True)
class AuthoritySnapshot:
    """Closed safe projection of all authorities needed for one loop decision."""

    tenant_id: str
    asset_id: str
    inventory: AuthorityPin
    declaration: AuthorityPin
    risk: AuthorityPin
    policy: AuthorityPin
    enforcement: AuthorityPin
    evidence: AuthorityPin
    declaration_approved: bool
    risk_current: bool
    policy_current: bool
    policy_decision: str
    enforcement_decision: str
    evidence_complete: bool
    limitations: tuple[str, ...]
    captured_at: float

    def normalized(self, *, now: float | None = None) -> AuthoritySnapshot:
        tenant = _tenant(self.tenant_id)
        asset = _token(self.asset_id, "asset_id")
        pins = tuple(
            value.normalized()
            for value in (
                self.inventory,
                self.declaration,
                self.risk,
                self.policy,
                self.enforcement,
                self.evidence,
            )
        )
        if any(pin.tenant_id != tenant or pin.asset_id != asset for pin in pins):
            raise AIGovernanceLoopValidationError(
                "every authority pin must match the exact tenant and asset"
            )
        flags = (
            self.declaration_approved,
            self.risk_current,
            self.policy_current,
            self.evidence_complete,
        )
        if any(type(flag) is not bool for flag in flags):
            raise AIGovernanceLoopValidationError("authority flags must be booleans")
        captured = _timestamp(self.captured_at, "captured_at")
        if now is not None and captured > now + _MAX_FUTURE_SKEW_SECONDS:
            raise AIGovernanceLoopValidationError("authority snapshot is from the future")
        return AuthoritySnapshot(
            tenant_id=tenant,
            asset_id=asset,
            inventory=pins[0],
            declaration=pins[1],
            risk=pins[2],
            policy=pins[3],
            enforcement=pins[4],
            evidence=pins[5],
            declaration_approved=self.declaration_approved,
            risk_current=self.risk_current,
            policy_current=self.policy_current,
            policy_decision=_closed(
                self.policy_decision,
                DECISION_CODES - {"unknown", "not_applicable"},
                "policy_decision",
            ),
            enforcement_decision=_closed(
                self.enforcement_decision, DECISION_CODES, "enforcement_decision"
            ),
            evidence_complete=self.evidence_complete,
            limitations=_limitations(self.limitations),
            captured_at=captured,
        )

    def safe_mapping(self) -> dict[str, object]:
        return asdict(self)


@runtime_checkable
class GovernanceAuthorityReader(Protocol):
    """Injected public authority seam; implementations may only return safe pins."""

    def read_snapshot(self, *, tenant_id: str, asset_id: str) -> AuthoritySnapshot: ...


@dataclass(frozen=True, slots=True)
class GovernanceTrigger:
    tenant_id: str
    asset_id: str
    code: str
    source_revision: int
    source_sha256: str
    occurred_at: float

    def normalized(self, *, now: float | None = None) -> GovernanceTrigger:
        occurred = _timestamp(self.occurred_at, "trigger occurred_at")
        if now is not None and occurred > now + _MAX_FUTURE_SKEW_SECONDS:
            raise AIGovernanceLoopValidationError("trigger is from the future")
        return GovernanceTrigger(
            tenant_id=_tenant(self.tenant_id),
            asset_id=_token(self.asset_id, "asset_id"),
            code=_closed(self.code, TRIGGER_CODES, "trigger code"),
            source_revision=_revision(
                self.source_revision, "trigger source revision", allow_zero=True
            ),
            source_sha256=_digest(self.source_sha256, "trigger source sha256"),
            occurred_at=occurred,
        )


@dataclass(frozen=True, slots=True)
class ReconciliationLease:
    tenant_id: str
    asset_id: str
    generation: int
    token: str
    attempts: int
    lease_until: float


@dataclass(frozen=True, slots=True)
class UnifiedAuditProjectionEvent:
    """Tenant/source envelope around one valid unified-audit source record."""

    tenant_id: str
    source_id: str
    suite_id: str
    sequence: int
    occurred_at: float
    action: str
    actor_sha256: str
    resource_sha256: str
    payload_sha256: str
    previous_sha256: str
    record_sha256: str

    def to_source_record(self) -> SourceRecord:
        """Return the exact public contract consumed by unified audit."""

        return SourceRecord(
            sequence=self.sequence,
            occurred_at=self.occurred_at,
            action=self.action,
            actor_sha256=self.actor_sha256,
            resource_sha256=self.resource_sha256,
            payload_sha256=self.payload_sha256,
            previous_sha256=self.previous_sha256,
            record_sha256=self.record_sha256,
        )


@dataclass(frozen=True, slots=True)
class _DerivedState:
    state: str
    limitations: tuple[str, ...]
    escalation_sha256: str | None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS agl_cases (
    tenant_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    state TEXT NOT NULL,
    trigger_code TEXT NOT NULL,
    trigger_revision INTEGER NOT NULL,
    trigger_sha256 TEXT NOT NULL,
    trigger_occurred_at REAL NOT NULL,
    authorities_json TEXT NOT NULL,
    authorities_sha256 TEXT NOT NULL,
    policy_decision TEXT NOT NULL,
    enforcement_decision TEXT NOT NULL,
    limitations_json TEXT NOT NULL,
    control_authorization_sha256 TEXT,
    authorized_policy_sha256 TEXT,
    authorized_decision TEXT,
    escalation_sha256 TEXT,
    rollback_target_revision INTEGER,
    rollback_authorization_sha256 TEXT,
    last_operation_sha256 TEXT,
    work_pending INTEGER NOT NULL,
    next_attempt_at REAL NOT NULL,
    attempts INTEGER NOT NULL,
    lease_owner_sha256 TEXT,
    lease_token_sha256 TEXT,
    lease_generation INTEGER NOT NULL,
    lease_until REAL,
    last_event_sha256 TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (tenant_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_agl_cases_ready
ON agl_cases(tenant_id, work_pending, next_attempt_at, lease_until);

CREATE TABLE IF NOT EXISTS agl_history (
    tenant_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    case_revision INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_sha256 TEXT NOT NULL,
    event_sha256 TEXT NOT NULL,
    occurred_at REAL NOT NULL,
    PRIMARY KEY (tenant_id, asset_id, sequence),
    UNIQUE (tenant_id, asset_id, event_sha256)
);

CREATE TABLE IF NOT EXISTS agl_operations (
    tenant_id TEXT NOT NULL,
    operation_key_sha256 TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    case_revision INTEGER NOT NULL,
    event_sha256 TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (tenant_id, operation_key_sha256)
);

CREATE TABLE IF NOT EXISTS agl_audit_history (
    tenant_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    asset_id TEXT NOT NULL,
    history_event_sha256 TEXT NOT NULL,
    occurred_at REAL NOT NULL,
    action TEXT NOT NULL,
    actor_sha256 TEXT NOT NULL,
    resource_sha256 TEXT NOT NULL,
    previous_sha256 TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    PRIMARY KEY (tenant_id, sequence),
    UNIQUE (tenant_id, history_event_sha256),
    UNIQUE (tenant_id, record_sha256)
);
"""


class AIGovernanceLoopStore:
    """Tenant-bound durable projection, work queue, and hash-linked history."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        config_gate: Callable[[], None] = require_enabled,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not callable(config_gate):
            raise AIGovernanceLoopConfigError("config_gate must be callable")
        config_gate()
        self.path = Path(path)
        self.tenant_id = _tenant(tenant_id)
        if not callable(clock):
            raise AIGovernanceLoopValidationError("clock must be callable")
        self._clock = clock
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _now(self) -> float:
        try:
            return _timestamp(self._clock(), "store clock")
        except (KeyboardInterrupt, SystemExit):
            raise
        except AIGovernanceLoopError:
            raise
        except Exception as exc:
            raise AIGovernanceLoopValidationError("store clock is unavailable") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30.0, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
        ensure_private_file(self.path)

    @staticmethod
    def _safe_json(value: object) -> str:
        return _canonical(value).decode("ascii")

    @staticmethod
    def _row_public(row: sqlite3.Row | Mapping[str, object]) -> dict[str, object]:
        authorities = json.loads(str(row["authorities_json"]))
        limitations = tuple(json.loads(str(row["limitations_json"])))
        return {
            "schema": "lightwork.ai-governance-loop-case.v1",
            "tenant_id": str(row["tenant_id"]),
            "asset_id": str(row["asset_id"]),
            "revision": int(row["revision"]),
            "state": str(row["state"]),
            "trigger": {
                "code": str(row["trigger_code"]),
                "source_revision": int(row["trigger_revision"]),
                "source_sha256": str(row["trigger_sha256"]),
                "occurred_at": float(row["trigger_occurred_at"]),
            },
            "authorities": authorities,
            "authorities_sha256": str(row["authorities_sha256"]),
            "policy_decision": str(row["policy_decision"]),
            "enforcement_decision": str(row["enforcement_decision"]),
            "limitations": limitations,
            "control_authorized": row["control_authorization_sha256"] is not None,
            "control_authorization_sha256": row["control_authorization_sha256"],
            "authorized_policy_sha256": row["authorized_policy_sha256"],
            "authorized_decision": row["authorized_decision"],
            "escalation_sha256": row["escalation_sha256"],
            "rollback_target_revision": row["rollback_target_revision"],
            "rollback_authorization_sha256": row["rollback_authorization_sha256"],
            "last_operation_sha256": row["last_operation_sha256"],
            "work_pending": bool(row["work_pending"]),
            "next_attempt_at": float(row["next_attempt_at"]),
            "attempts": int(row["attempts"]),
            "lease_generation": int(row["lease_generation"]),
            "lease_until": (float(row["lease_until"]) if row["lease_until"] is not None else None),
            "last_event_sha256": str(row["last_event_sha256"]),
            "updated_at": float(row["updated_at"]),
            "provider_mutation_performed": False,
            "raw_payloads_persisted": False,
        }

    def _case_row(self, connection: sqlite3.Connection, asset_id: str) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM agl_cases WHERE tenant_id=? AND asset_id=?",
            (self.tenant_id, asset_id),
        ).fetchone()

    def get_case(self, asset_id: str) -> dict[str, object] | None:
        asset = _token(asset_id, "asset_id")
        with self._connect() as connection:
            row = self._case_row(connection, asset)
            return self._row_public(row) if row is not None else None

    @staticmethod
    def _event_payload(
        row: Mapping[str, object],
        *,
        event_type: str,
        occurred_at: float,
    ) -> dict[str, object]:
        return {
            "schema": "lightwork.ai-governance-loop-history.v1",
            "tenant_id": str(row["tenant_id"]),
            "asset_id": str(row["asset_id"]),
            "case_revision": int(row["revision"]),
            "event_type": _closed(event_type, EVENT_CODES, "event_type"),
            "state": _closed(row["state"], STATE_CODES, "state"),
            "trigger_code": _closed(row["trigger_code"], TRIGGER_CODES, "trigger code"),
            "trigger_revision": int(row["trigger_revision"]),
            "trigger_sha256": _digest(row["trigger_sha256"], "trigger sha256"),
            "authorities_sha256": _digest(
                row["authorities_sha256"], "authorities sha256", allow_genesis=True
            ),
            "policy_decision": _closed(row["policy_decision"], DECISION_CODES, "policy decision"),
            "enforcement_decision": _closed(
                row["enforcement_decision"], DECISION_CODES, "enforcement decision"
            ),
            "limitations": list(_limitations(tuple(json.loads(str(row["limitations_json"]))))),
            "control_authorization_sha256": row["control_authorization_sha256"],
            "authorized_policy_sha256": row["authorized_policy_sha256"],
            "authorized_decision": row["authorized_decision"],
            "escalation_sha256": row["escalation_sha256"],
            "rollback_target_revision": row["rollback_target_revision"],
            "rollback_authorization_sha256": row["rollback_authorization_sha256"],
            "last_operation_sha256": row["last_operation_sha256"],
            "work_pending": bool(row["work_pending"]),
            "next_attempt_at": float(row["next_attempt_at"]),
            "attempts": int(row["attempts"]),
            "lease_owner_sha256": row["lease_owner_sha256"],
            "lease_token_sha256": row["lease_token_sha256"],
            "lease_generation": int(row["lease_generation"]),
            "lease_until": (float(row["lease_until"]) if row["lease_until"] is not None else None),
            "updated_at": float(row["updated_at"]),
            "occurred_at": occurred_at,
        }

    def _append_history(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row | Mapping[str, object],
        *,
        event_type: str,
        occurred_at: float,
    ) -> str:
        count_row = connection.execute(
            "SELECT COUNT(*) AS n, MAX(sequence) AS sequence FROM agl_history "
            "WHERE tenant_id=? AND asset_id=?",
            (self.tenant_id, str(row["asset_id"])),
        ).fetchone()
        if int(count_row["n"]) >= _MAX_HISTORY_ROWS:
            raise AIGovernanceLoopConflict("asset history exceeds its bound")
        sequence = int(count_row["sequence"] or 0) + 1
        prior_row = connection.execute(
            "SELECT event_sha256 FROM agl_history WHERE tenant_id=? AND asset_id=? "
            "ORDER BY sequence DESC LIMIT 1",
            (self.tenant_id, str(row["asset_id"])),
        ).fetchone()
        previous = str(prior_row["event_sha256"]) if prior_row else GENESIS_SHA256
        payload = self._event_payload(row, event_type=event_type, occurred_at=occurred_at)
        event_sha256 = _sha256(
            {"sequence": sequence, "previous_sha256": previous, "payload": payload}
        )
        connection.execute(
            "INSERT INTO agl_history"
            "(tenant_id,asset_id,sequence,case_revision,event_type,payload_json,"
            "previous_sha256,event_sha256,occurred_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                self.tenant_id,
                str(row["asset_id"]),
                sequence,
                int(row["revision"]),
                event_type,
                self._safe_json(payload),
                previous,
                event_sha256,
                occurred_at,
            ),
        )
        audit_row = connection.execute(
            "SELECT sequence,record_sha256 FROM agl_audit_history "
            "WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
            (self.tenant_id,),
        ).fetchone()
        audit_sequence = int(audit_row["sequence"]) + 1 if audit_row else 1
        audit_previous = str(audit_row["record_sha256"]) if audit_row else GENESIS_SHA256
        action = self._audit_action(event_type, str(row["trigger_code"]))
        if action not in AUDIT_ACTION_CODES:
            raise AIGovernanceLoopIntegrityError("audit action is outside its vocabulary")
        actor_sha256 = hashlib.sha256(b"system:ai-governance-loop").hexdigest()
        resource_sha256 = _sha256(
            {
                "schema": "lightwork.ai-governance-loop-resource.v1",
                "tenant_id": self.tenant_id,
                "asset_id": str(row["asset_id"]),
            }
        )
        audit_record = build_source_record(
            sequence=audit_sequence,
            occurred_at=occurred_at,
            action=action,
            actor_sha256=actor_sha256,
            resource_sha256=resource_sha256,
            payload_sha256=event_sha256,
            previous_sha256=audit_previous,
        )
        connection.execute(
            "INSERT INTO agl_audit_history"
            "(tenant_id,sequence,asset_id,history_event_sha256,occurred_at,action,"
            "actor_sha256,resource_sha256,previous_sha256,record_sha256) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                self.tenant_id,
                audit_record.sequence,
                str(row["asset_id"]),
                event_sha256,
                audit_record.occurred_at,
                audit_record.action,
                audit_record.actor_sha256,
                audit_record.resource_sha256,
                audit_record.previous_sha256,
                audit_record.record_sha256,
            ),
        )
        connection.execute(
            "UPDATE agl_cases SET last_event_sha256=? WHERE tenant_id=? AND asset_id=?",
            (event_sha256, self.tenant_id, str(row["asset_id"])),
        )
        return event_sha256

    def _operation_result(
        self,
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        request_sha256: str,
    ) -> dict[str, object] | None:
        row = connection.execute(
            "SELECT * FROM agl_operations WHERE tenant_id=? AND operation_key_sha256=?",
            (self.tenant_id, key_sha256),
        ).fetchone()
        if row is None:
            return None
        if not text_equals(str(row["request_sha256"]), request_sha256):
            raise AIGovernanceLoopConflict(
                "idempotency key was already used for a different operation"
            )
        case = self._case_row(connection, str(row["asset_id"]))
        if case is None:
            raise AIGovernanceLoopIntegrityError("operation references a missing case")
        return self._row_public(case)

    def _save_operation(
        self,
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        request_sha256: str,
        row: sqlite3.Row | Mapping[str, object],
        event_sha256: str,
        now: float,
    ) -> None:
        connection.execute(
            "INSERT INTO agl_operations"
            "(tenant_id,operation_key_sha256,request_sha256,asset_id,case_revision,"
            "event_sha256,created_at) VALUES (?,?,?,?,?,?,?)",
            (
                self.tenant_id,
                key_sha256,
                request_sha256,
                str(row["asset_id"]),
                int(row["revision"]),
                event_sha256,
                now,
            ),
        )

    def enqueue(
        self,
        trigger: GovernanceTrigger,
        *,
        idempotency_key: str,
        expected_revision: int | None = None,
    ) -> dict[str, object]:
        now = self._now()
        normalized = trigger.normalized(now=now)
        if normalized.tenant_id != self.tenant_id:
            raise AIGovernanceLoopValidationError("trigger tenant does not match this store")
        key_sha256 = _operation_key(idempotency_key)
        request_sha256 = _sha256(
            {
                "operation": "enqueue",
                "trigger": asdict(normalized),
                "expected_revision": expected_revision,
            }
        )
        asset = normalized.asset_id
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                prior = self._operation_result(
                    connection,
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                )
                if prior is not None:
                    connection.commit()
                    return prior
                current = self._case_row(connection, asset)
                if expected_revision is not None:
                    expected = _revision(expected_revision, "expected_revision", allow_zero=True)
                    actual = int(current["revision"]) if current is not None else 0
                    if expected != actual:
                        raise AIGovernanceLoopConflict("case revision is stale")
                event_sha256: str
                if current is not None:
                    old_revision = int(current["trigger_revision"])
                    old_sha = str(current["trigger_sha256"])
                    if normalized.source_revision < old_revision:
                        raise AIGovernanceLoopConflict("trigger is out of order")
                    if normalized.source_revision == old_revision:
                        if not text_equals(normalized.source_sha256, old_sha):
                            raise AIGovernanceLoopConflict(
                                "trigger revision is bound to different content"
                            )
                        event_sha256 = str(current["last_event_sha256"])
                        self._save_operation(
                            connection,
                            key_sha256=key_sha256,
                            request_sha256=request_sha256,
                            row=current,
                            event_sha256=event_sha256,
                            now=now,
                        )
                        connection.commit()
                        return self._row_public(current)
                    revision = int(current["revision"]) + 1
                    connection.execute(
                        "UPDATE agl_cases SET revision=?,"
                        "trigger_code=?,trigger_revision=?,trigger_sha256=?,"
                        "trigger_occurred_at=?,work_pending=1,"
                        "next_attempt_at=?,attempts=0,last_operation_sha256=?,"
                        "lease_owner_sha256=NULL,"
                        "lease_token_sha256=NULL,lease_until=NULL,updated_at=? "
                        "WHERE tenant_id=? AND asset_id=? AND revision=?",
                        (
                            revision,
                            normalized.code,
                            normalized.source_revision,
                            normalized.source_sha256,
                            normalized.occurred_at,
                            now,
                            request_sha256,
                            now,
                            self.tenant_id,
                            asset,
                            int(current["revision"]),
                        ),
                    )
                else:
                    empty_authorities: dict[str, object] = {}
                    connection.execute(
                        "INSERT INTO agl_cases"
                        "(tenant_id,asset_id,revision,state,trigger_code,trigger_revision,"
                        "trigger_sha256,trigger_occurred_at,authorities_json,"
                        "authorities_sha256,policy_decision,enforcement_decision,"
                        "limitations_json,work_pending,next_attempt_at,attempts,"
                        "lease_generation,last_operation_sha256,last_event_sha256,updated_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            self.tenant_id,
                            asset,
                            1,
                            "queued",
                            normalized.code,
                            normalized.source_revision,
                            normalized.source_sha256,
                            normalized.occurred_at,
                            self._safe_json(empty_authorities),
                            _sha256(empty_authorities),
                            "unknown",
                            "unknown",
                            self._safe_json(["reconciliation_pending"]),
                            1,
                            now,
                            0,
                            0,
                            request_sha256,
                            GENESIS_SHA256,
                            now,
                        ),
                    )
                saved = self._case_row(connection, asset)
                if saved is None:
                    raise AIGovernanceLoopIntegrityError("enqueued case disappeared")
                event_sha256 = self._append_history(
                    connection, saved, event_type="trigger_enqueued", occurred_at=now
                )
                saved = self._case_row(connection, asset)
                self._save_operation(
                    connection,
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                    row=saved,
                    event_sha256=event_sha256,
                    now=now,
                )
                connection.commit()
                return self._row_public(saved)
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise

    def claim_next(
        self,
        *,
        worker_id: str,
        lease_seconds: float,
        max_attempts: int,
    ) -> ReconciliationLease | None:
        now = self._now()
        worker = _token(worker_id, "worker_id")
        duration = _positive_number(lease_seconds, "lease_seconds", _MAX_LEASE_SECONDS)
        attempts_limit = _revision(max_attempts, "max_attempts")
        if attempts_limit > _MAX_ATTEMPTS:
            raise AIGovernanceLoopValidationError("max_attempts exceeds its bound")
        owner_sha256 = hashlib.sha256(worker.encode("utf-8")).hexdigest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                candidates = connection.execute(
                    "SELECT * FROM agl_cases WHERE tenant_id=? AND work_pending=1 "
                    "AND next_attempt_at<=? AND (lease_until IS NULL OR lease_until<=?) "
                    "ORDER BY next_attempt_at,asset_id LIMIT 32",
                    (self.tenant_id, now, now),
                ).fetchall()
                for current in candidates:
                    reclaimed = current["lease_until"] is not None
                    attempts = int(current["attempts"])
                    if attempts >= attempts_limit:
                        revision = int(current["revision"]) + 1
                        connection.execute(
                            "UPDATE agl_cases SET revision=?,state='escalated',"
                            "limitations_json=?,work_pending=0,lease_owner_sha256=NULL,"
                            "lease_token_sha256=NULL,lease_until=NULL,updated_at=? "
                            "WHERE tenant_id=? AND asset_id=?",
                            (
                                revision,
                                self._safe_json(["retry_exhausted"]),
                                now,
                                self.tenant_id,
                                current["asset_id"],
                            ),
                        )
                        exhausted = self._case_row(connection, str(current["asset_id"]))
                        self._append_history(
                            connection,
                            exhausted,
                            event_type="lease_exhausted",
                            occurred_at=now,
                        )
                        continue
                    generation = int(current["lease_generation"]) + 1
                    attempt = attempts + 1
                    token = secrets.token_urlsafe(32)
                    token_sha256 = hashlib.sha256(token.encode("utf-8")).hexdigest()
                    lease_until = now + duration
                    changed = connection.execute(
                        "UPDATE agl_cases SET attempts=?,lease_owner_sha256=?,"
                        "lease_token_sha256=?,lease_generation=?,lease_until=?,updated_at=? "
                        "WHERE tenant_id=? AND asset_id=? AND work_pending=1 "
                        "AND lease_generation=? AND (lease_until IS NULL OR lease_until<=?)",
                        (
                            attempt,
                            owner_sha256,
                            token_sha256,
                            generation,
                            lease_until,
                            now,
                            self.tenant_id,
                            current["asset_id"],
                            current["lease_generation"],
                            now,
                        ),
                    )
                    if changed.rowcount != 1:
                        continue
                    claimed = self._case_row(connection, str(current["asset_id"]))
                    self._append_history(
                        connection,
                        claimed,
                        event_type="lease_reclaimed" if reclaimed else "lease_claimed",
                        occurred_at=now,
                    )
                    connection.commit()
                    return ReconciliationLease(
                        tenant_id=self.tenant_id,
                        asset_id=str(current["asset_id"]),
                        generation=generation,
                        token=token,
                        attempts=attempt,
                        lease_until=lease_until,
                    )
                connection.commit()
                return None
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise

    def _assert_lease(
        self,
        row: sqlite3.Row,
        lease: ReconciliationLease,
        *,
        now: float,
    ) -> None:
        if (
            lease.tenant_id != self.tenant_id
            or lease.asset_id != row["asset_id"]
            or lease.generation != int(row["lease_generation"])
            or row["lease_token_sha256"] is None
            or not text_equals(
                hashlib.sha256(lease.token.encode("utf-8")).hexdigest(),
                str(row["lease_token_sha256"]),
            )
            or row["lease_until"] is None
            or float(row["lease_until"]) <= now
        ):
            raise AIGovernanceLoopLeaseLost("reconciliation lease is no longer owned")

    @staticmethod
    def _authorization_matches(row: Mapping[str, object], snapshot: AuthoritySnapshot) -> bool:
        return (
            row["control_authorization_sha256"] is not None
            and row["authorized_decision"] == snapshot.policy_decision
            and row["authorized_policy_sha256"] == snapshot.policy.sha256
        )

    @staticmethod
    def _derive(row: Mapping[str, object], snapshot: AuthoritySnapshot) -> _DerivedState:
        limitations = set(snapshot.limitations)
        escalation: str | None = None
        if not snapshot.declaration_approved:
            limitations.add("declaration_unapproved")
            return _DerivedState("review_required", tuple(sorted(limitations)), None)
        if not snapshot.risk_current:
            limitations.add("risk_stale")
            return _DerivedState("recovery_pending", tuple(sorted(limitations)), None)
        if not snapshot.policy_current:
            limitations.add("policy_stale")
            return _DerivedState("recovery_pending", tuple(sorted(limitations)), None)
        decision = snapshot.policy_decision
        if decision == "review":
            return _DerivedState("review_required", tuple(sorted(limitations)), None)
        if decision in {"restrict", "block"}:
            escalation = _sha256(
                {
                    "schema": "lightwork.ai-governance-loop-escalation.v1",
                    "tenant_id": snapshot.tenant_id,
                    "asset_id": snapshot.asset_id,
                    "policy_sha256": snapshot.policy.sha256,
                    "decision": decision,
                }
            )
            if not AIGovernanceLoopStore._authorization_matches(row, snapshot):
                limitations.add("human_authorization_required")
                return _DerivedState("escalated", tuple(sorted(limitations)), escalation)
            if snapshot.enforcement_decision in {"unknown", "not_applicable"}:
                limitations.add("enforcement_missing")
                return _DerivedState("control_pending", tuple(sorted(limitations)), escalation)
            if snapshot.enforcement_decision != decision:
                limitations.add("enforcement_mismatch")
                return _DerivedState("control_pending", tuple(sorted(limitations)), escalation)
            state = "restricted" if decision == "restrict" else "blocked"
            if not snapshot.evidence_complete:
                limitations.add("evidence_incomplete")
            return _DerivedState(state, tuple(sorted(limitations)), escalation)
        if snapshot.enforcement_decision not in {
            "unknown",
            "not_applicable",
            "allow",
            "monitor",
        }:
            limitations.add("enforcement_mismatch")
            return _DerivedState("recovery_pending", tuple(sorted(limitations)), None)
        if not snapshot.evidence_complete:
            limitations.add("evidence_incomplete")
        return _DerivedState("monitoring", tuple(sorted(limitations)), None)

    @staticmethod
    def _assert_authority_progress(row: Mapping[str, object], snapshot: AuthoritySnapshot) -> None:
        prior = json.loads(str(row["authorities_json"]))
        if prior == {}:
            return
        if not isinstance(prior, dict):
            raise AIGovernanceLoopIntegrityError("stored authorities are invalid")
        current = snapshot.safe_mapping()
        advanced = False
        for name in _AUTHORITY_NAMES:
            old_value = prior.get(name)
            new_value = current[name]
            if not isinstance(old_value, dict) or not isinstance(new_value, dict):
                raise AIGovernanceLoopIntegrityError("stored authority pin is invalid")
            try:
                old_pin = AuthorityPin(**old_value).normalized()
            except (TypeError, AIGovernanceLoopError) as exc:
                raise AIGovernanceLoopIntegrityError("stored authority pin is invalid") from exc
            new_pin = getattr(snapshot, name)
            if new_pin.revision < old_pin.revision:
                raise AIGovernanceLoopAuthorityDrift(f"{name} authority revision regressed")
            if new_pin.revision == old_pin.revision and new_pin != old_pin:
                raise AIGovernanceLoopAuthorityDrift(f"{name} authority changed without a revision")
            advanced = advanced or new_pin.revision > old_pin.revision

        bindings = {
            "declaration": ("declaration_approved",),
            "risk": ("risk_current",),
            "policy": ("policy_current", "policy_decision"),
            "enforcement": ("enforcement_decision",),
            "evidence": ("evidence_complete",),
        }
        for authority_name, fields in bindings.items():
            if prior[authority_name] == current[authority_name] and any(
                prior.get(field) != current[field] for field in fields
            ):
                raise AIGovernanceLoopAuthorityDrift(
                    f"{authority_name} decision changed without an authority revision"
                )
        if tuple(prior.get("limitations", ())) != tuple(current["limitations"]) and not advanced:
            raise AIGovernanceLoopAuthorityDrift(
                "authority limitations changed without an authority revision"
            )

    def commit_reconciliation(
        self,
        lease: ReconciliationLease,
        snapshot: AuthoritySnapshot,
    ) -> dict[str, object]:
        now = self._now()
        normalized = snapshot.normalized(now=now)
        if normalized.tenant_id != self.tenant_id or normalized.asset_id != lease.asset_id:
            raise AIGovernanceLoopValidationError(
                "authority snapshot does not match the claimed tenant and asset"
            )
        authorities = normalized.safe_mapping()
        authorities_json = self._safe_json(authorities)
        authorities_sha256 = _sha256(authorities)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._case_row(connection, lease.asset_id)
                if current is None:
                    raise AIGovernanceLoopNotFound("claimed case does not exist")
                self._assert_lease(current, lease, now=now)
                self._assert_authority_progress(current, normalized)
                derived = self._derive(current, normalized)
                no_change = (
                    text_equals(str(current["authorities_sha256"]), authorities_sha256)
                    and current["state"] == derived.state
                    and current["policy_decision"] == normalized.policy_decision
                    and current["enforcement_decision"] == normalized.enforcement_decision
                    and tuple(json.loads(str(current["limitations_json"]))) == derived.limitations
                    and current["escalation_sha256"] == derived.escalation_sha256
                )
                revision = int(current["revision"]) + (0 if no_change else 1)
                connection.execute(
                    "UPDATE agl_cases SET revision=?,state=?,authorities_json=?,"
                    "authorities_sha256=?,policy_decision=?,enforcement_decision=?,"
                    "limitations_json=?,escalation_sha256=?,work_pending=0,"
                    "next_attempt_at=?,attempts=0,lease_owner_sha256=NULL,"
                    "lease_token_sha256=NULL,lease_until=NULL,updated_at=? "
                    "WHERE tenant_id=? AND asset_id=? AND lease_generation=?",
                    (
                        revision,
                        derived.state,
                        authorities_json,
                        authorities_sha256,
                        normalized.policy_decision,
                        normalized.enforcement_decision,
                        self._safe_json(list(derived.limitations)),
                        derived.escalation_sha256,
                        now,
                        now,
                        self.tenant_id,
                        lease.asset_id,
                        lease.generation,
                    ),
                )
                saved = self._case_row(connection, lease.asset_id)
                self._append_history(
                    connection,
                    saved,
                    event_type=("reconciliation_no_change" if no_change else "reconciled"),
                    occurred_at=now,
                )
                saved = self._case_row(connection, lease.asset_id)
                connection.commit()
                result = self._row_public(saved)
                result["no_change"] = no_change
                return result
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise

    def fail_claim(
        self,
        lease: ReconciliationLease,
        *,
        limitation: str,
        max_attempts: int,
        backoff_base_seconds: float,
    ) -> dict[str, object]:
        now = self._now()
        code = _closed(limitation, LIMITATION_CODES, "failure limitation")
        attempts_limit = _revision(max_attempts, "max_attempts")
        if attempts_limit > _MAX_ATTEMPTS:
            raise AIGovernanceLoopValidationError("max_attempts exceeds its bound")
        base = _positive_number(backoff_base_seconds, "backoff_base_seconds", _MAX_BACKOFF_SECONDS)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current = self._case_row(connection, lease.asset_id)
                if current is None:
                    raise AIGovernanceLoopNotFound("claimed case does not exist")
                self._assert_lease(current, lease, now=now)
                exhausted = int(current["attempts"]) >= attempts_limit
                state = "escalated" if exhausted else "recovery_pending"
                limitations = ("retry_exhausted",) if exhausted else (code,)
                next_attempt = (
                    now
                    if exhausted
                    else now
                    + min(
                        _MAX_BACKOFF_SECONDS,
                        base * (2 ** max(0, int(current["attempts"]) - 1)),
                    )
                )
                revision = int(current["revision"]) + 1
                connection.execute(
                    "UPDATE agl_cases SET revision=?,state=?,limitations_json=?,"
                    "work_pending=?,next_attempt_at=?,lease_owner_sha256=NULL,"
                    "lease_token_sha256=NULL,lease_until=NULL,updated_at=? "
                    "WHERE tenant_id=? AND asset_id=? AND lease_generation=?",
                    (
                        revision,
                        state,
                        self._safe_json(list(limitations)),
                        0 if exhausted else 1,
                        next_attempt,
                        now,
                        self.tenant_id,
                        lease.asset_id,
                        lease.generation,
                    ),
                )
                saved = self._case_row(connection, lease.asset_id)
                self._append_history(
                    connection,
                    saved,
                    event_type="lease_exhausted" if exhausted else "lease_failed",
                    occurred_at=now,
                )
                saved = self._case_row(connection, lease.asset_id)
                connection.commit()
                return self._row_public(saved)
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise

    def _cas_operation(
        self,
        *,
        asset_id: str,
        expected_revision: int,
        idempotency_key: str,
        operation: str,
        request_fields: Mapping[str, object],
        mutate: Callable[[sqlite3.Connection, dict[str, object], float], str],
    ) -> dict[str, object]:
        asset = _token(asset_id, "asset_id")
        expected = _revision(expected_revision, "expected_revision")
        key_sha256 = _operation_key(idempotency_key)
        request_sha256 = _sha256(
            {"operation": operation, "asset_id": asset, **dict(request_fields)}
        )
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                prior = self._operation_result(
                    connection,
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                )
                if prior is not None:
                    connection.commit()
                    return prior
                current = self._case_row(connection, asset)
                if current is None:
                    raise AIGovernanceLoopNotFound("case does not exist")
                if int(current["revision"]) != expected:
                    raise AIGovernanceLoopConflict("case revision is stale")
                values = dict(current)
                event_type = mutate(connection, values, now)
                _closed(event_type, EVENT_CODES, "event_type")
                values["revision"] = expected + 1
                values["updated_at"] = now
                values["last_operation_sha256"] = request_sha256
                connection.execute(
                    "UPDATE agl_cases SET revision=?,state=?,policy_decision=?,"
                    "enforcement_decision=?,limitations_json=?,"
                    "control_authorization_sha256=?,authorized_policy_sha256=?,"
                    "authorized_decision=?,rollback_target_revision=?,"
                    "rollback_authorization_sha256=?,last_operation_sha256=?,"
                    "work_pending=?,next_attempt_at=?,"
                    "attempts=?,lease_owner_sha256=NULL,lease_token_sha256=NULL,"
                    "lease_until=NULL,updated_at=? WHERE tenant_id=? AND asset_id=? "
                    "AND revision=?",
                    (
                        values["revision"],
                        values["state"],
                        values["policy_decision"],
                        values["enforcement_decision"],
                        values["limitations_json"],
                        values.get("control_authorization_sha256"),
                        values.get("authorized_policy_sha256"),
                        values.get("authorized_decision"),
                        values.get("rollback_target_revision"),
                        values.get("rollback_authorization_sha256"),
                        values["last_operation_sha256"],
                        values["work_pending"],
                        values["next_attempt_at"],
                        values["attempts"],
                        now,
                        self.tenant_id,
                        asset,
                        expected,
                    ),
                )
                saved = self._case_row(connection, asset)
                event_sha256 = self._append_history(
                    connection, saved, event_type=event_type, occurred_at=now
                )
                saved = self._case_row(connection, asset)
                self._save_operation(
                    connection,
                    key_sha256=key_sha256,
                    request_sha256=request_sha256,
                    row=saved,
                    event_sha256=event_sha256,
                    now=now,
                )
                connection.commit()
                return self._row_public(saved)
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise

    def authorize_control(
        self,
        asset_id: str,
        *,
        decision: str,
        authorization_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        selected = _closed(decision, frozenset({"restrict", "block"}), "decision")
        authorization = _digest(authorization_sha256, "authorization_sha256")

        def mutate(_connection: sqlite3.Connection, row: dict[str, object], now: float) -> str:
            if row["policy_decision"] != selected or row["state"] not in {
                "escalated",
                "control_pending",
            }:
                raise AIGovernanceLoopConflict(
                    "control authorization does not match the current policy decision"
                )
            authorities = json.loads(str(row["authorities_json"]))
            policy = authorities.get("policy") if isinstance(authorities, dict) else None
            if not isinstance(policy, dict):
                raise AIGovernanceLoopIntegrityError("policy authority is unavailable")
            policy_sha256 = _digest(policy.get("sha256"), "policy authority sha256")
            row["control_authorization_sha256"] = authorization
            row["authorized_policy_sha256"] = policy_sha256
            row["authorized_decision"] = selected
            row["state"] = "control_pending"
            row["limitations_json"] = self._safe_json(["enforcement_missing"])
            row["work_pending"] = 1
            row["next_attempt_at"] = now
            row["attempts"] = 0
            return "control_authorized"

        return self._cas_operation(
            asset_id=asset_id,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            operation="authorize_control",
            request_fields={
                "decision": selected,
                "authorization_sha256": authorization,
            },
            mutate=mutate,
        )

    def revoke_control_authorization(
        self,
        asset_id: str,
        *,
        revocation_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        revocation = _digest(revocation_sha256, "revocation_sha256")

        def mutate(_connection: sqlite3.Connection, row: dict[str, object], now: float) -> str:
            del now
            if row.get("control_authorization_sha256") is None:
                raise AIGovernanceLoopConflict("control authorization is not active")
            # The revocation digest is committed through the operation/history
            # hash; it is not confused with the now-cleared authorization.
            row["control_authorization_sha256"] = None
            row["authorized_policy_sha256"] = None
            row["authorized_decision"] = None
            row["state"] = "escalated"
            row["limitations_json"] = self._safe_json(
                ["control_authorization_revoked", "human_authorization_required"]
            )
            row["work_pending"] = 0
            row["attempts"] = 0
            return "control_authorization_revoked"

        return self._cas_operation(
            asset_id=asset_id,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            operation="revoke_control_authorization",
            request_fields={"revocation_sha256": revocation},
            mutate=mutate,
        )

    def replay(
        self,
        asset_id: str,
        *,
        authorization_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        authorization = _digest(authorization_sha256, "authorization_sha256")

        def mutate(_connection: sqlite3.Connection, row: dict[str, object], now: float) -> str:
            # Replay restarts reconciliation; it must not undo a revocation.
            if row.get("state") == "revoked":
                raise AIGovernanceLoopConflict("a revoked case cannot be replayed")
            row["state"] = "recovery_pending"
            row["limitations_json"] = self._safe_json(["reconciliation_pending"])
            row["work_pending"] = 1
            row["next_attempt_at"] = now
            row["attempts"] = 0
            return "replay_authorized"

        return self._cas_operation(
            asset_id=asset_id,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            operation="replay",
            request_fields={"authorization_sha256": authorization},
            mutate=mutate,
        )

    def authorize_rollback(
        self,
        asset_id: str,
        *,
        target_revision: int,
        authorization_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        target = _revision(target_revision, "target_revision")
        authorization = _digest(authorization_sha256, "authorization_sha256")
        asset = _token(asset_id, "asset_id")

        def mutate(connection: sqlite3.Connection, row: dict[str, object], now: float) -> str:
            del now
            exists = connection.execute(
                "SELECT 1 FROM agl_history WHERE tenant_id=? AND asset_id=? "
                "AND case_revision=? LIMIT 1",
                (self.tenant_id, asset, target),
            ).fetchone()
            if exists is None:
                raise AIGovernanceLoopNotFound("rollback target revision does not exist")
            row["rollback_target_revision"] = target
            row["rollback_authorization_sha256"] = authorization
            row["state"] = "rollback_pending"
            row["limitations_json"] = self._safe_json(["rollback_pending"])
            row["work_pending"] = 0
            return "rollback_authorized"

        return self._cas_operation(
            asset_id=asset,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            operation="authorize_rollback",
            request_fields={
                "target_revision": target,
                "authorization_sha256": authorization,
            },
            mutate=mutate,
        )

    def revoke_rollback_authorization(
        self,
        asset_id: str,
        *,
        revocation_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        revocation = _digest(revocation_sha256, "revocation_sha256")

        def mutate(_connection: sqlite3.Connection, row: dict[str, object], now: float) -> str:
            if row.get("rollback_authorization_sha256") is None:
                raise AIGovernanceLoopConflict("rollback authorization is not active")
            row["rollback_target_revision"] = None
            row["rollback_authorization_sha256"] = None
            row["state"] = "recovery_pending"
            row["limitations_json"] = self._safe_json(["reconciliation_pending"])
            row["work_pending"] = 1
            row["next_attempt_at"] = now
            row["attempts"] = 0
            return "rollback_authorization_revoked"

        return self._cas_operation(
            asset_id=asset_id,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            operation="revoke_rollback_authorization",
            request_fields={"revocation_sha256": revocation},
            mutate=mutate,
        )

    def apply_authorized_rollback(
        self,
        asset_id: str,
        *,
        authorization_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        asset = _token(asset_id, "asset_id")
        authorization = _digest(authorization_sha256, "authorization_sha256")
        expected = _revision(expected_revision, "expected_revision")

        def mutate(connection: sqlite3.Connection, row: dict[str, object], now: float) -> str:
            target = row["rollback_target_revision"]
            if (
                row["rollback_authorization_sha256"] is None
                or not text_equals(str(row["rollback_authorization_sha256"]), authorization)
                or target is None
            ):
                raise AIGovernanceLoopConflict("rollback authorization is stale")
            target_row = connection.execute(
                "SELECT sequence,previous_sha256,event_sha256,payload_json FROM agl_history "
                "WHERE tenant_id=? AND asset_id=? "
                "AND case_revision=? ORDER BY sequence DESC LIMIT 1",
                (self.tenant_id, asset, int(target)),
            ).fetchone()
            if target_row is None:
                raise AIGovernanceLoopIntegrityError("rollback target disappeared")
            target_payload = json.loads(str(target_row["payload_json"]))
            target_event_sha256 = _sha256(
                {
                    "sequence": int(target_row["sequence"]),
                    "previous_sha256": str(target_row["previous_sha256"]),
                    "payload": target_payload,
                }
            )
            if not text_equals(str(target_row["event_sha256"]), target_event_sha256):
                raise AIGovernanceLoopIntegrityError("rollback target commitment is invalid")
            # Restoring a historical *projection* cannot rewind its external
            # authorities. Reconciliation is therefore mandatory before this
            # projection can become current again.
            row["state"] = "recovery_pending"
            row["policy_decision"] = _closed(
                target_payload.get("policy_decision"),
                DECISION_CODES,
                "rollback policy decision",
            )
            row["enforcement_decision"] = _closed(
                target_payload.get("enforcement_decision"),
                DECISION_CODES,
                "rollback enforcement decision",
            )
            row["limitations_json"] = self._safe_json(["rollback_applied_requires_reconciliation"])
            row["rollback_target_revision"] = None
            row["rollback_authorization_sha256"] = None
            row["work_pending"] = 1
            row["next_attempt_at"] = now
            row["attempts"] = 0
            return "rollback_applied"

        return self._cas_operation(
            asset_id=asset,
            expected_revision=expected,
            idempotency_key=idempotency_key,
            operation="apply_authorized_rollback",
            request_fields={"authorization_sha256": authorization},
            mutate=mutate,
        )

    def revoke_case(
        self,
        asset_id: str,
        *,
        revocation_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        revocation = _digest(revocation_sha256, "revocation_sha256")

        def mutate(_connection: sqlite3.Connection, row: dict[str, object], now: float) -> str:
            del now
            row["state"] = "revoked"
            row["limitations_json"] = self._safe_json(["revoked"])
            row["control_authorization_sha256"] = None
            row["authorized_policy_sha256"] = None
            row["authorized_decision"] = None
            row["rollback_target_revision"] = None
            row["rollback_authorization_sha256"] = None
            row["work_pending"] = 0
            row["attempts"] = 0
            return "case_revoked"

        return self._cas_operation(
            asset_id=asset_id,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            operation="revoke_case",
            request_fields={"revocation_sha256": revocation},
            mutate=mutate,
        )

    def history(
        self,
        asset_id: str,
        *,
        limit: int = 1_000,
    ) -> tuple[dict[str, object], ...]:
        asset = _token(asset_id, "asset_id")
        bounded = _integer(limit, "history limit", 1, 10_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM agl_history WHERE tenant_id=? AND asset_id=? "
                "ORDER BY sequence DESC LIMIT ?",
                (self.tenant_id, asset, bounded),
            ).fetchall()
        rows.reverse()
        return tuple(
            {
                "sequence": int(row["sequence"]),
                "case_revision": int(row["case_revision"]),
                "event_type": str(row["event_type"]),
                "payload": json.loads(str(row["payload_json"])),
                "previous_sha256": str(row["previous_sha256"]),
                "event_sha256": str(row["event_sha256"]),
                "occurred_at": float(row["occurred_at"]),
            }
            for row in rows
        )

    @staticmethod
    def _audit_action(event_type: str, trigger_code: str) -> str:
        if event_type == "trigger_enqueued":
            return {
                "risk_changed": "risk_changed",
                "policy_changed": "policy_changed",
                "evidence_changed": "evidence_recorded",
            }.get(trigger_code, "observation_recorded")
        return {
            "control_authorized": "approval_granted",
            "control_authorization_revoked": "approval_denied",
            "rollback_authorized": "approval_granted",
            "rollback_authorization_revoked": "approval_denied",
            "reconciled": "control_evaluated",
            "reconciliation_no_change": "control_evaluated",
            "lease_exhausted": "incident_recorded",
            "lease_failed": "status_changed",
            "lease_claimed": "status_changed",
            "lease_reclaimed": "status_changed",
            "replay_authorized": "approval_granted",
            "rollback_applied": "status_changed",
            "case_revoked": "status_changed",
        }[event_type]

    def unified_audit_events(self) -> tuple[UnifiedAuditProjectionEvent, ...]:
        """Return one tenant-wide contiguous chain of unified-audit records."""

        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM agl_audit_history WHERE tenant_id=? ORDER BY sequence",
                (self.tenant_id,),
            ).fetchall()
        events = tuple(
            UnifiedAuditProjectionEvent(
                tenant_id=self.tenant_id,
                source_id=SOURCE_ID,
                suite_id=SUITE_ID,
                sequence=int(row["sequence"]),
                occurred_at=float(row["occurred_at"]),
                action=str(row["action"]),
                actor_sha256=str(row["actor_sha256"]),
                resource_sha256=str(row["resource_sha256"]),
                payload_sha256=str(row["history_event_sha256"]),
                previous_sha256=str(row["previous_sha256"]),
                record_sha256=str(row["record_sha256"]),
            )
            for row in rows
        )
        for event in events:
            event.to_source_record()
        return events

    def unified_audit_records(self) -> tuple[SourceRecord, ...]:
        """Return the exact records accepted by :mod:`maverick.unified_audit`."""

        return tuple(event.to_source_record() for event in self.unified_audit_events())

    def _verify_asset_history(
        self,
        connection: sqlite3.Connection,
        case: sqlite3.Row,
        asset: str,
    ) -> tuple[int, str]:
        rows = connection.execute(
            "SELECT * FROM agl_history WHERE tenant_id=? AND asset_id=? ORDER BY sequence",
            (self.tenant_id, asset),
        ).fetchall()
        authorities = json.loads(str(case["authorities_json"]))
        if _canonical(authorities).decode("ascii") != str(case["authorities_json"]):
            raise AIGovernanceLoopIntegrityError("case authorities are not canonical")
        if not text_equals(str(case["authorities_sha256"]), _sha256(authorities)):
            raise AIGovernanceLoopIntegrityError("case authority commitment is invalid")
        previous = GENESIS_SHA256
        for expected_sequence, row in enumerate(rows, start=1):
            if int(row["sequence"]) != expected_sequence:
                raise AIGovernanceLoopIntegrityError("history sequence is discontinuous")
            if not text_equals(str(row["previous_sha256"]), previous):
                raise AIGovernanceLoopIntegrityError("history predecessor is invalid")
            payload = json.loads(str(row["payload_json"]))
            if _canonical(payload).decode("ascii") != str(row["payload_json"]):
                raise AIGovernanceLoopIntegrityError("history payload is not canonical")
            if payload.get("tenant_id") != self.tenant_id or payload.get("asset_id") != asset:
                raise AIGovernanceLoopIntegrityError("history identity is invalid")
            _closed(payload.get("event_type"), EVENT_CODES, "history event")
            if (
                int(row["case_revision"]) != payload.get("case_revision")
                or str(row["event_type"]) != payload.get("event_type")
                or float(row["occurred_at"]) != payload.get("occurred_at")
            ):
                raise AIGovernanceLoopIntegrityError("history columns do not match their payload")
            expected = _sha256(
                {
                    "sequence": expected_sequence,
                    "previous_sha256": previous,
                    "payload": payload,
                }
            )
            if not text_equals(str(row["event_sha256"]), expected):
                raise AIGovernanceLoopIntegrityError("history event commitment is invalid")
            previous = expected
        if not rows or not text_equals(str(case["last_event_sha256"]), previous):
            raise AIGovernanceLoopIntegrityError("case history tip is invalid")
        latest = rows[-1]
        expected_projection = self._event_payload(
            case,
            event_type=str(latest["event_type"]),
            occurred_at=float(latest["occurred_at"]),
        )
        if self._safe_json(expected_projection) != str(latest["payload_json"]):
            raise AIGovernanceLoopIntegrityError("case projection does not match its history tip")
        return len(rows), previous

    def _verify_audit_history(self, connection: sqlite3.Connection) -> tuple[int, str]:
        audit_rows = connection.execute(
            "SELECT * FROM agl_audit_history WHERE tenant_id=? ORDER BY sequence",
            (self.tenant_id,),
        ).fetchall()
        history_count = int(
            connection.execute(
                "SELECT COUNT(*) AS n FROM agl_history WHERE tenant_id=?",
                (self.tenant_id,),
            ).fetchone()["n"]
        )
        if len(audit_rows) != history_count:
            raise AIGovernanceLoopIntegrityError(
                "unified-audit coverage does not match source history"
            )
        previous = GENESIS_SHA256
        for sequence, audit_row in enumerate(audit_rows, start=1):
            record = SourceRecord(
                sequence=int(audit_row["sequence"]),
                occurred_at=float(audit_row["occurred_at"]),
                action=str(audit_row["action"]),
                actor_sha256=str(audit_row["actor_sha256"]),
                resource_sha256=str(audit_row["resource_sha256"]),
                payload_sha256=str(audit_row["history_event_sha256"]),
                previous_sha256=str(audit_row["previous_sha256"]),
                record_sha256=str(audit_row["record_sha256"]),
            )
            if record.sequence != sequence or not text_equals(
                record.previous_sha256, previous
            ):
                raise AIGovernanceLoopIntegrityError("unified-audit source chain is discontinuous")
            history_row = connection.execute(
                "SELECT occurred_at FROM agl_history WHERE tenant_id=? "
                "AND asset_id=? AND event_sha256=?",
                (
                    self.tenant_id,
                    str(audit_row["asset_id"]),
                    record.payload_sha256,
                ),
            ).fetchone()
            if history_row is None or float(history_row["occurred_at"]) != record.occurred_at:
                raise AIGovernanceLoopIntegrityError(
                    "unified-audit record is not bound to source history"
                )
            previous = record.record_sha256
        return len(audit_rows), previous

    def _verify_operations(self, connection: sqlite3.Connection) -> None:
        operation_rows = connection.execute(
            "SELECT * FROM agl_operations WHERE tenant_id=?",
            (self.tenant_id,),
        ).fetchall()
        for operation_row in operation_rows:
            _digest(operation_row["operation_key_sha256"], "operation key sha256")
            _digest(operation_row["request_sha256"], "operation request sha256")
            operation_history = connection.execute(
                "SELECT case_revision FROM agl_history WHERE tenant_id=? "
                "AND asset_id=? AND event_sha256=?",
                (
                    self.tenant_id,
                    str(operation_row["asset_id"]),
                    str(operation_row["event_sha256"]),
                ),
            ).fetchone()
            if operation_history is None or int(operation_history["case_revision"]) != int(
                operation_row["case_revision"]
            ):
                raise AIGovernanceLoopIntegrityError(
                    "idempotent operation is not bound to source history"
                )

    def verify_unified_audit_history(self) -> dict[str, object]:
        """Verify every case plus the tenant-wide unified-audit projection."""

        with self._connect() as connection:
            connection.execute("BEGIN")
            try:
                cases = connection.execute(
                    "SELECT * FROM agl_cases WHERE tenant_id=? ORDER BY asset_id",
                    (self.tenant_id,),
                ).fetchall()
                history_count = 0
                for case in cases:
                    count, _tip = self._verify_asset_history(
                        connection,
                        case,
                        str(case["asset_id"]),
                    )
                    history_count += count
                audit_count, audit_tip = self._verify_audit_history(connection)
                self._verify_operations(connection)
                if history_count != audit_count:
                    raise AIGovernanceLoopIntegrityError(
                        "unified-audit coverage does not match verified case history"
                    )
                connection.commit()
                return {
                    "schema": "lightwork.ai-governance-loop-unified-audit-integrity.v1",
                    "tenant_id": self.tenant_id,
                    "valid": True,
                    "case_count": len(cases),
                    "history_count": history_count,
                    "unified_audit_count": audit_count,
                    "unified_audit_tip_sha256": audit_tip,
                    "raw_payloads_returned": False,
                }
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise

    def verify_integrity(self, asset_id: str) -> dict[str, object]:
        asset = _token(asset_id, "asset_id")
        with self._connect() as connection:
            connection.execute("BEGIN")
            try:
                case = self._case_row(connection, asset)
                if case is None:
                    raise AIGovernanceLoopNotFound("case does not exist")
                history_count, history_tip = self._verify_asset_history(connection, case, asset)
                audit_count, audit_tip = self._verify_audit_history(connection)
                self._verify_operations(connection)
                connection.commit()
                return {
                    "schema": "lightwork.ai-governance-loop-integrity.v1",
                    "tenant_id": self.tenant_id,
                    "asset_id": asset,
                    "valid": True,
                    "history_count": history_count,
                    "history_tip_sha256": history_tip,
                    "unified_audit_count": audit_count,
                    "unified_audit_tip_sha256": audit_tip,
                    "provider_mutation_performed": False,
                    "raw_payloads_persisted": False,
                }
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise


class AIGovernanceLoopCoordinator:
    """Double-read authoritative state and advance one claimed case safely."""

    def __init__(
        self,
        *,
        store: AIGovernanceLoopStore,
        authority_reader: GovernanceAuthorityReader,
        lease_seconds: float = 120.0,
        max_attempts: int = 5,
        backoff_base_seconds: float = 30.0,
        after_commit: Callable[[Mapping[str, object]], None] | None = None,
    ) -> None:
        if not isinstance(store, AIGovernanceLoopStore):
            raise AIGovernanceLoopValidationError("store is invalid")
        if not isinstance(authority_reader, GovernanceAuthorityReader):
            raise AIGovernanceLoopValidationError("authority_reader is invalid")
        self.store = store
        self.authority_reader = authority_reader
        self.lease_seconds = _positive_number(lease_seconds, "lease_seconds", _MAX_LEASE_SECONDS)
        self.max_attempts = _revision(max_attempts, "max_attempts")
        if self.max_attempts > _MAX_ATTEMPTS:
            raise AIGovernanceLoopValidationError("max_attempts exceeds its bound")
        self.backoff_base_seconds = _positive_number(
            backoff_base_seconds, "backoff_base_seconds", _MAX_BACKOFF_SECONDS
        )
        if after_commit is not None and not callable(after_commit):
            raise AIGovernanceLoopValidationError("after_commit must be callable")
        self._after_commit = after_commit

    def _read(self, asset_id: str) -> AuthoritySnapshot:
        try:
            value = self.authority_reader.read_snapshot(
                tenant_id=self.store.tenant_id,
                asset_id=asset_id,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except AIGovernanceLoopError:
            raise
        except Exception as exc:
            raise AIGovernanceLoopValidationError("authority reader is unavailable") from exc
        if type(value) is not AuthoritySnapshot:
            raise AIGovernanceLoopValidationError(
                "authority reader must return the closed AuthoritySnapshot contract"
            )
        return value.normalized(now=self.store._now())

    def process_claim(self, lease: ReconciliationLease) -> dict[str, object]:
        if not isinstance(lease, ReconciliationLease):
            raise AIGovernanceLoopValidationError("lease is invalid")
        try:
            before = self._read(lease.asset_id)
            after = self._read(lease.asset_id)
            # Both reads independently pass freshness validation in _read.
            # Their observation times need not be identical; all authority
            # pins, decisions and limitations must still match exactly.
            if replace(before, captured_at=after.captured_at) != after:
                raise AIGovernanceLoopAuthorityDrift("authorities changed during reconciliation")
            result = self.store.commit_reconciliation(lease, after)
        except (KeyboardInterrupt, SystemExit):
            raise
        except AIGovernanceLoopAuthorityDrift:
            self.store.fail_claim(
                lease,
                limitation="authority_changed",
                max_attempts=self.max_attempts,
                backoff_base_seconds=self.backoff_base_seconds,
            )
            raise
        except AIGovernanceLoopLeaseLost:
            raise
        except Exception:
            self.store.fail_claim(
                lease,
                limitation="authority_unavailable",
                max_attempts=self.max_attempts,
                backoff_base_seconds=self.backoff_base_seconds,
            )
            raise
        if self._after_commit is not None:
            self._after_commit(result)
        return result

    def run_once(self, *, worker_id: str) -> dict[str, object] | None:
        lease = self.store.claim_next(
            worker_id=worker_id,
            lease_seconds=self.lease_seconds,
            max_attempts=self.max_attempts,
        )
        if lease is None:
            return None
        return self.process_claim(lease)


__all__ = [
    "AUDIT_ACTION_CODES",
    "AIGovernanceLoopAuthorityDrift",
    "AIGovernanceLoopConfigError",
    "AIGovernanceLoopConflict",
    "AIGovernanceLoopCoordinator",
    "AIGovernanceLoopError",
    "AIGovernanceLoopIntegrityError",
    "AIGovernanceLoopLeaseLost",
    "AIGovernanceLoopNotFound",
    "AIGovernanceLoopStore",
    "AIGovernanceLoopValidationError",
    "AuthorityPin",
    "AuthoritySnapshot",
    "DECISION_CODES",
    "EVENT_CODES",
    "GENESIS_SHA256",
    "GovernanceAuthorityReader",
    "GovernanceTrigger",
    "LIMITATION_CODES",
    "ReconciliationLease",
    "SCHEMA_VERSION",
    "SOURCE_ID",
    "STATE_CODES",
    "SUITE_ID",
    "TRIGGER_CODES",
    "UnifiedAuditProjectionEvent",
    "enabled",
    "require_enabled",
]
