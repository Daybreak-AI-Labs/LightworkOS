"""Revision-CAS finding and investigation store with a durable audit outbox."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from ..file_lock import ensure_private_directory, ensure_private_file
from ..sqlite_closing import ClosingConnection
from .models import ContainmentProposal, Finding, Investigation, canonical_digest

AuditRecorder = Callable[[str, dict[str, Any]], bool]

_AUDIT_CUSTODY_EVENT_ID = "platform-hunt-audit-custody-v1"
_AUDIT_CUSTODY_EVENT_KIND = "platform_hunt_custody_initialized"


class RevisionConflict(RuntimeError):
    """The supplied revision does not match the durable record revision."""


class RecordNotFound(KeyError):
    pass


def _actor_label(actor: str) -> str:
    raw = (actor or "system").encode("utf-8", "replace")
    return f"actor:{hashlib.sha256(raw).hexdigest()[:24]}"


def _plain(value: object) -> dict[str, Any]:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return dict(value)
    raise TypeError("hunter records must be dataclasses or mappings")


def _reject_raw_telemetry(value: object) -> None:
    """Prevent accidental persistence of raw customer sensor payloads."""
    if isinstance(value, dict):
        forbidden = {
            "authorization", "body", "credential", "credentials", "event", "events",
            "log", "logs", "password", "passwd", "payload", "raw", "raw_event",
            "raw_events", "raw_log", "raw_logs", "raw_payload", "raw_telemetry",
            "secret", "secrets", "telemetry", "token", "tokens",
        }
        sensitive_parts = {
            "authorization", "credential", "credentials", "password", "passwd",
            "secret", "secrets", "token", "tokens",
        }
        for key in value:
            normalized = str(key).strip().lower().replace("-", "_")
            parts = {part for part in normalized.split("_") if part}
            if normalized in forbidden or sensitive_parts.intersection(parts):
                raise ValueError(
                    "raw telemetry and credentials cannot be persisted in the hunter store"
                )
        for nested in value.values():
            _reject_raw_telemetry(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _reject_raw_telemetry(nested)


class HuntStore:
    """Private derived-state store; raw telemetry is intentionally unsupported."""

    _TABLES = {"finding": "hunt_findings", "investigation": "hunt_investigations"}

    def __init__(
        self,
        path: str | Path,
        audit_recorder: AuditRecorder | None = None,
        *,
        record_change_event_kind: str = "threat_hunt_record_changed",
    ):
        self.path = Path(path)
        # Findings, investigation timelines, and response receipts are derived
        # security telemetry. Keep both hunter stores behind the same private
        # persistence boundary as the GRC record stores. Check an existing leaf
        # before SQLite follows it, then tighten a newly created database after
        # initialization; the private parent closes the new-leaf creation window.
        ensure_private_directory(self.path.parent)
        if self.path.exists():
            ensure_private_file(self.path, 0o600)
        self._audit_recorder = audit_recorder
        self._record_change_event_kind = str(record_change_event_kind)
        self._initialize()
        ensure_private_file(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS hunt_findings (
                    id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL CHECK(revision > 0),
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS hunt_investigations (
                    id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL CHECK(revision > 0),
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS hunt_journal (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor_label TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS hunt_audit_outbox (
                    event_id TEXT PRIMARY KEY,
                    event_kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    delivered_at REAL
                );
                CREATE TABLE IF NOT EXISTS hunt_response_executions (
                    proposal_id TEXT PRIMARY KEY,
                    proposal_sha256 TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    executor TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('claimed', 'completed', 'ambiguous')),
                    receipt_json TEXT,
                    error_kind TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS hunt_scheduler_leases (
                    name TEXT PRIMARY KEY,
                    owner_label TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
            """)

    @staticmethod
    def _expected_revision(value: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("expected_revision must be a positive integer")
        return value

    def _append_journal(
        self,
        conn: sqlite3.Connection,
        *,
        record_type: str,
        record_id: str,
        revision: int,
        action: str,
        actor_label: str,
        payload_sha256: str,
        timestamp: float,
    ) -> None:
        tail = conn.execute(
            "SELECT entry_hash FROM hunt_journal ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = str(tail[0]) if tail else ""
        body = {
            "ts": timestamp,
            "record_type": record_type,
            "record_id": record_id,
            "revision": revision,
            "action": action,
            "actor_label": actor_label,
            "payload_sha256": payload_sha256,
            "prev_hash": prev_hash,
        }
        entry_hash = canonical_digest(body)
        conn.execute(
            """INSERT INTO hunt_journal
               (ts, record_type, record_id, revision, action, actor_label,
                payload_sha256, prev_hash, entry_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                timestamp, record_type, record_id, revision, action, actor_label,
                payload_sha256, prev_hash, entry_hash,
            ),
        )

    def _queue_audit(
        self,
        conn: sqlite3.Connection,
        *,
        record_type: str,
        record_id: str,
        revision: int,
        action: str,
        actor_label: str,
        payload_sha256: str,
        status: str,
        timestamp: float,
    ) -> None:
        event_id = uuid.uuid4().hex
        payload = {
            "event_id": event_id,
            "record_type": record_type,
            "record_id": record_id,
            "revision": revision,
            "action": action,
            "actor": actor_label,
            "record_sha256": payload_sha256,
            "status": status,
            "occurred_at": timestamp,
        }
        self._queue_event(conn, self._record_change_event_kind, payload, timestamp=timestamp)

    @staticmethod
    def _queue_event(
        conn: sqlite3.Connection,
        event_kind: str,
        payload: dict[str, Any],
        *,
        timestamp: float,
    ) -> None:
        event_id = str(payload.get("event_id") or uuid.uuid4().hex)
        payload = {**payload, "event_id": event_id}
        conn.execute(
            """INSERT INTO hunt_audit_outbox
               (event_id, event_kind, payload_json, created_at, delivered_at)
               VALUES (?, ?, ?, ?, NULL)""",
            (
                event_id, event_kind,
                json.dumps(payload, sort_keys=True, separators=(",", ":")), timestamp,
            ),
        )

    def _create(self, record_type: str, record: object, *, actor: str) -> dict[str, Any]:
        table = self._TABLES[record_type]
        payload = _plain(record)
        _reject_raw_telemetry(payload)
        id_key = f"{record_type}_id"
        record_id = str(payload.get(id_key, ""))
        if not record_id:
            raise ValueError(f"{id_key} is required")
        payload.pop("revision", None)
        revision = 1
        payload["revision"] = revision
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        status = str(payload.get("status", "open"))
        timestamp = time.time()
        label = _actor_label(actor)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    f"INSERT INTO {table} "  # noqa: S608 - table is a closed internal constant
                    "(id, revision, status, payload_json, payload_sha256, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (record_id, revision, status, encoded, digest, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise RevisionConflict(f"{record_type} {record_id} already exists") from exc
            self._append_journal(
                conn, record_type=record_type, record_id=record_id, revision=revision,
                action="create", actor_label=label, payload_sha256=digest,
                timestamp=timestamp,
            )
            self._queue_audit(
                conn, record_type=record_type, record_id=record_id, revision=revision,
                action="create", actor_label=label, payload_sha256=digest,
                status=status, timestamp=timestamp,
            )
        self.flush_audit_outbox()
        return payload

    def _update(
        self,
        record_type: str,
        record_id: str,
        changes: dict[str, Any],
        *,
        expected_revision: int,
        actor: str,
        action: str = "update",
    ) -> dict[str, Any]:
        table = self._TABLES[record_type]
        expected = self._expected_revision(expected_revision)
        forbidden = {"revision", f"{record_type}_id"}
        if forbidden.intersection(changes):
            raise ValueError("record identity and revision cannot be replaced")
        _reject_raw_telemetry(changes)
        timestamp = time.time()
        label = _actor_label(actor)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                f"SELECT revision, payload_json FROM {table} WHERE id = ?",  # noqa: S608
                (record_id,),
            ).fetchone()
            if row is None:
                raise RecordNotFound(record_id)
            current = int(row["revision"])
            if current != expected:
                raise RevisionConflict(
                    f"expected revision {expected}, found {current} for {record_type} {record_id}"
                )
            payload = json.loads(str(row["payload_json"]))
            payload.update(changes)
            revision = current + 1
            payload["revision"] = revision
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            status = str(payload.get("status", "open"))
            cursor = conn.execute(
                f"UPDATE {table} SET revision = ?, status = ?, payload_json = ?, "  # noqa: S608
                "payload_sha256 = ?, updated_at = ? WHERE id = ? AND revision = ?",
                (revision, status, encoded, digest, timestamp, record_id, expected),
            )
            if cursor.rowcount != 1:
                raise RevisionConflict(f"concurrent update to {record_type} {record_id}")
            self._append_journal(
                conn, record_type=record_type, record_id=record_id, revision=revision,
                action=action, actor_label=label, payload_sha256=digest,
                timestamp=timestamp,
            )
            self._queue_audit(
                conn, record_type=record_type, record_id=record_id, revision=revision,
                action=action, actor_label=label, payload_sha256=digest,
                status=status, timestamp=timestamp,
            )
        self.flush_audit_outbox()
        return payload

    def create_finding(self, finding: Finding | dict, *, actor: str) -> dict[str, Any]:
        return self._create("finding", finding, actor=actor)

    def update_finding(
        self,
        finding_id: str,
        changes: dict[str, Any],
        *,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        return self._update(
            "finding", finding_id, changes,
            expected_revision=expected_revision, actor=actor,
        )

    def create_investigation(
        self, investigation: Investigation | dict, *, actor: str,
    ) -> dict[str, Any]:
        return self._create("investigation", investigation, actor=actor)

    def update_investigation(
        self,
        investigation_id: str,
        changes: dict[str, Any],
        *,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        return self._update(
            "investigation", investigation_id, changes,
            expected_revision=expected_revision, actor=actor,
        )

    def propose_containment(
        self,
        investigation_id: str,
        proposal: ContainmentProposal | dict,
        *,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        return self._update(
            "investigation", investigation_id, {"containment": _plain(proposal)},
            expected_revision=expected_revision, actor=actor, action="propose_containment",
        )

    def _get(self, record_type: str, record_id: str) -> dict[str, Any] | None:
        table = self._TABLES[record_type]
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT payload_json, payload_sha256 FROM {table} WHERE id = ?",  # noqa: S608
                (record_id,),
            ).fetchone()
        if row is None:
            return None
        payload_json = str(row["payload_json"])
        if hashlib.sha256(payload_json.encode("utf-8")).hexdigest() != row["payload_sha256"]:
            raise RuntimeError(f"{record_type} {record_id} failed its content commitment")
        return json.loads(payload_json)

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        return self._get("finding", finding_id)

    def get_investigation(self, investigation_id: str) -> dict[str, Any] | None:
        return self._get("investigation", investigation_id)

    def _list(self, record_type: str, *, status: str | None, limit: int) -> list[dict]:
        if not 1 <= limit <= 10_000:
            raise ValueError("limit must be between 1 and 10000")
        table = self._TABLES[record_type]
        query = f"SELECT id FROM {table}"  # noqa: S608
        params: list[Any] = []
        if status is not None:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY updated_at DESC, id LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            ids = [str(row[0]) for row in conn.execute(query, params).fetchall()]
        return [record for item in ids if (record := self._get(record_type, item)) is not None]

    def list_findings(self, *, status: str | None = None, limit: int = 500) -> list[dict]:
        return self._list("finding", status=status, limit=limit)

    def list_investigations(
        self, *, status: str | None = None, limit: int = 500,
    ) -> list[dict]:
        return self._list("investigation", status=status, limit=limit)

    @staticmethod
    def _execution_binding(
        *, proposal_sha256: str, approval_id: str, executor: str,
    ) -> tuple[str, str, str]:
        digest = str(proposal_sha256).strip().lower()
        approval = str(approval_id).strip()
        normalized_executor = str(executor).strip().lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("response proposal digest must be hexadecimal SHA-256")
        if not approval or not normalized_executor:
            raise ValueError("response execution requires an approval and executor")
        return digest, approval, normalized_executor

    def claim_response_execution(
        self,
        *,
        proposal_id: str,
        proposal_sha256: str,
        approval_id: str,
        executor: str,
        actor: str,
    ) -> dict[str, Any]:
        """Atomically claim one proposal before any external side effect.

        A proposal id is a one-shot key.  Replays return the durable state but
        never grant a second claim; a different approval/executor binding is a
        conflict rather than a new execution opportunity.
        """
        proposal = str(proposal_id).strip()
        if not proposal:
            raise ValueError("response execution requires a proposal id")
        digest, approval, normalized_executor = self._execution_binding(
            proposal_sha256=proposal_sha256,
            approval_id=approval_id,
            executor=executor,
        )
        timestamp = time.time()
        created = False
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM hunt_response_executions WHERE proposal_id = ?",
                (proposal,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """INSERT INTO hunt_response_executions
                       (proposal_id, proposal_sha256, approval_id, executor, status,
                        receipt_json, error_kind, created_at, updated_at)
                       VALUES (?, ?, ?, ?, 'claimed', NULL, '', ?, ?)""",
                    (proposal, digest, approval, normalized_executor, timestamp, timestamp),
                )
                self._queue_event(
                    conn,
                    "env_hunt_response_execution_claimed",
                    {
                        "proposal_id": proposal,
                        "proposal_sha256": digest,
                        "approval_id": approval,
                        "executor": normalized_executor,
                        "actor": _actor_label(actor),
                        "phase": "claimed",
                        "occurred_at": timestamp,
                    },
                    timestamp=timestamp,
                )
                created = True
                row = conn.execute(
                    "SELECT * FROM hunt_response_executions WHERE proposal_id = ?",
                    (proposal,),
                ).fetchone()
            elif (
                str(row["proposal_sha256"]) != digest
                or str(row["approval_id"]) != approval
                or str(row["executor"]) != normalized_executor
            ):
                raise RevisionConflict(
                    "response proposal was already claimed under a different binding"
                )
            result = dict(row)
        self.flush_audit_outbox()
        result["new_claim"] = created
        if result.get("receipt_json"):
            result["receipt"] = json.loads(str(result.pop("receipt_json")))
        else:
            result.pop("receipt_json", None)
        return result

    def complete_response_execution(
        self,
        *,
        proposal_id: str,
        proposal_sha256: str,
        approval_id: str,
        executor: str,
        receipt: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        """Commit a bounded receipt and its audit outbox row in one transaction."""
        proposal = str(proposal_id).strip()
        digest, approval, normalized_executor = self._execution_binding(
            proposal_sha256=proposal_sha256,
            approval_id=approval_id,
            executor=executor,
        )
        receipt_payload = dict(receipt)
        _reject_raw_telemetry(receipt_payload)
        encoded = json.dumps(
            receipt_payload, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise ValueError("response receipt exceeds the 64 KiB persistence limit")
        timestamp = time.time()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM hunt_response_executions WHERE proposal_id = ?",
                (proposal,),
            ).fetchone()
            if row is None:
                raise RevisionConflict("response proposal has no durable execution claim")
            if (
                str(row["proposal_sha256"]) != digest
                or str(row["approval_id"]) != approval
                or str(row["executor"]) != normalized_executor
            ):
                raise RevisionConflict("response execution binding changed after claim")
            if str(row["status"]) == "completed":
                return json.loads(str(row["receipt_json"]))
            if str(row["status"]) != "claimed":
                raise RevisionConflict("response execution outcome requires reconciliation")
            updated = conn.execute(
                """UPDATE hunt_response_executions
                   SET status = 'completed', receipt_json = ?, error_kind = '', updated_at = ?
                   WHERE proposal_id = ? AND status = 'claimed'""",
                (encoded, timestamp, proposal),
            )
            if updated.rowcount != 1:
                raise RevisionConflict("concurrent response execution completion")
            self._queue_event(
                conn,
                "env_hunt_response_executed",
                {
                    "proposal_id": proposal,
                    "proposal_sha256": digest,
                    "approval_id": approval,
                    "executor": normalized_executor,
                    "outcome": str(receipt_payload.get("outcome", ""))[:120],
                    "actor": _actor_label(actor),
                    "phase": "completed",
                    "occurred_at": timestamp,
                },
                timestamp=timestamp,
            )
        self.flush_audit_outbox()
        return receipt_payload

    def mark_response_execution_ambiguous(
        self,
        *,
        proposal_id: str,
        proposal_sha256: str,
        approval_id: str,
        executor: str,
        error_kind: str,
        actor: str,
    ) -> None:
        """Persist an unknown external outcome so retries cannot repeat it."""
        proposal = str(proposal_id).strip()
        digest, approval, normalized_executor = self._execution_binding(
            proposal_sha256=proposal_sha256,
            approval_id=approval_id,
            executor=executor,
        )
        safe_error = str(error_kind).strip()[:120] or "execution_error"
        timestamp = time.time()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM hunt_response_executions WHERE proposal_id = ?",
                (proposal,),
            ).fetchone()
            if row is None:
                raise RevisionConflict("response proposal has no durable execution claim")
            if (
                str(row["proposal_sha256"]) != digest
                or str(row["approval_id"]) != approval
                or str(row["executor"]) != normalized_executor
            ):
                raise RevisionConflict("response execution binding changed after claim")
            if str(row["status"]) == "completed":
                return
            if str(row["status"]) == "ambiguous":
                return
            if str(row["status"]) != "claimed":
                raise RevisionConflict("response execution outcome requires reconciliation")
            updated = conn.execute(
                """UPDATE hunt_response_executions
                   SET status = 'ambiguous', error_kind = ?, updated_at = ?
                   WHERE proposal_id = ? AND status = 'claimed'""",
                (safe_error, timestamp, proposal),
            )
            if updated.rowcount != 1:
                raise RevisionConflict("concurrent response execution ambiguity")
            self._queue_event(
                conn,
                "env_hunt_response_ambiguous",
                {
                    "proposal_id": proposal,
                    "proposal_sha256": digest,
                    "approval_id": approval,
                    "executor": normalized_executor,
                    "error_kind": safe_error,
                    "actor": _actor_label(actor),
                    "occurred_at": timestamp,
                },
                timestamp=timestamp,
            )
        self.flush_audit_outbox()

    def get_response_execution(self, proposal_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM hunt_response_executions WHERE proposal_id = ?",
                (str(proposal_id),),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        if result.get("receipt_json"):
            result["receipt"] = json.loads(str(result.pop("receipt_json")))
        else:
            result.pop("receipt_json", None)
        return result

    def try_acquire_scheduler_lease(
        self,
        name: str,
        *,
        owner: str,
        lease_seconds: float,
        now: float | None = None,
    ) -> bool:
        """Acquire one bounded cross-process scheduler turn without blocking."""
        lease_name = str(name).strip().lower()
        if not lease_name or len(lease_name) > 120:
            raise ValueError("scheduler lease requires a short name")
        if isinstance(lease_seconds, bool) or not 30 <= float(lease_seconds) <= 86_400:
            raise ValueError("scheduler lease must be between 30 seconds and one day")
        timestamp = time.time() if now is None else float(now)
        expires_at = timestamp + float(lease_seconds)
        owner_label = _actor_label(owner)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT expires_at FROM hunt_scheduler_leases WHERE name = ?",
                (lease_name,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """INSERT INTO hunt_scheduler_leases
                       (name, owner_label, expires_at, updated_at) VALUES (?, ?, ?, ?)""",
                    (lease_name, owner_label, expires_at, timestamp),
                )
                return True
            if float(row["expires_at"]) > timestamp:
                return False
            updated = conn.execute(
                """UPDATE hunt_scheduler_leases
                   SET owner_label = ?, expires_at = ?, updated_at = ?
                   WHERE name = ? AND expires_at <= ?""",
                (owner_label, expires_at, timestamp, lease_name, timestamp),
            )
            return updated.rowcount == 1

    def _record_audit(self, kind: str, payload: dict[str, Any]) -> bool:
        from ..audit import AuditRefused

        if self._audit_recorder is not None:
            try:
                return bool(self._audit_recorder(kind, payload))
            except AuditRefused:
                raise
            except Exception:  # failure-policy: durable_retry
                return False
        try:
            from ..audit import record

            return bool(record(kind, **payload))
        except AuditRefused:
            raise
        except Exception:  # failure-policy: durable_retry
            return False

    def _deliver_audit_outbox_event(self, event_id: str) -> bool:
        """Attempt one named outbox delivery and report durable acceptance.

        The general outbox flusher is intentionally bounded and ordered.  A
        custody bootstrap cannot wait behind an arbitrary findings backlog,
        because verification must know whether its own audit authority exists
        before issuing a chain-integrity verdict. Concurrent workers retain the
        outbox's at-least-once semantics: they may append the same deterministic
        event id before either delivery acknowledgement commits, but every copy
        is signed and a durable acknowledgement prevents future bootstraps.
        """
        with self._connect() as conn:
            row = conn.execute(
                """SELECT event_kind, payload_json, delivered_at
                   FROM hunt_audit_outbox WHERE event_id = ?""",
                (event_id,),
            ).fetchone()
        if row is None:
            return False
        if row["delivered_at"] is not None:
            return True
        payload = json.loads(str(row["payload_json"]))
        if not self._record_audit(str(row["event_kind"]), payload):
            return False
        with self._connect() as conn:
            conn.execute(
                """UPDATE hunt_audit_outbox SET delivered_at = ?
                   WHERE event_id = ? AND delivered_at IS NULL""",
                (time.time(), event_id),
            )
            delivered = conn.execute(
                "SELECT delivered_at FROM hunt_audit_outbox WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        return delivered is not None and delivered["delivered_at"] is not None

    def ensure_audit_custody_witness(self) -> bool:
        """Anchor the hunter's insert-once audit-custody expectation.

        A brand-new deployment has no audit directory yet.  Treating that
        pre-initialization state as deleted evidence creates a false critical
        finding, and recording the finding then creates the very chain that was
        reported missing.  This durable outbox row establishes custody first.

        Once delivered, it is never emitted again.  Therefore a later missing
        audit directory is still a real integrity failure: the hunter store
        remembers that signed custody previously existed and will not recreate
        a genesis chain before verification.
        """
        timestamp = time.time()
        payload = {
            "event_id": _AUDIT_CUSTODY_EVENT_ID,
            "version": 1,
            "purpose": "platform_hunt_audit_custody",
            "occurred_at": timestamp,
        }
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT 1 FROM hunt_audit_outbox WHERE event_id = ?",
                (_AUDIT_CUSTODY_EVENT_ID,),
            ).fetchone()
            if row is None:
                self._queue_event(
                    conn,
                    _AUDIT_CUSTODY_EVENT_KIND,
                    payload,
                    timestamp=timestamp,
                )
        return self._deliver_audit_outbox_event(_AUDIT_CUSTODY_EVENT_ID)

    def flush_audit_outbox(self, *, limit: int = 32) -> int:
        if not 1 <= limit <= 256:
            raise ValueError("audit flush limit must be between 1 and 256")
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT event_id, event_kind, payload_json
                   FROM hunt_audit_outbox WHERE delivered_at IS NULL
                   ORDER BY created_at, event_id LIMIT ?""",
                (limit,),
            ).fetchall()
        delivered = 0
        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            if not self._record_audit(str(row["event_kind"]), payload):
                continue
            with self._connect() as conn:
                updated = conn.execute(
                    """UPDATE hunt_audit_outbox SET delivered_at = ?
                       WHERE event_id = ? AND delivered_at IS NULL""",
                    (time.time(), str(row["event_id"])),
                )
                delivered += int(updated.rowcount == 1)
        return delivered

    def pending_audit_count(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM hunt_audit_outbox WHERE delivered_at IS NULL"
            ).fetchone()
        return int(row[0])

    def verify_journal(self) -> list[dict[str, Any]]:
        """Verify journal links and the latest record commitments."""
        breaks: list[dict[str, Any]] = []
        previous = ""
        latest: dict[tuple[str, str], tuple[int, str]] = {}
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM hunt_journal ORDER BY seq").fetchall()
            for row in rows:
                body = {
                    "ts": row["ts"],
                    "record_type": row["record_type"],
                    "record_id": row["record_id"],
                    "revision": row["revision"],
                    "action": row["action"],
                    "actor_label": row["actor_label"],
                    "payload_sha256": row["payload_sha256"],
                    "prev_hash": row["prev_hash"],
                }
                expected = canonical_digest(body)
                if row["prev_hash"] != previous:
                    breaks.append({"seq": row["seq"], "reason": "chain_mismatch"})
                if row["entry_hash"] != expected:
                    breaks.append({"seq": row["seq"], "reason": "bad_hash"})
                previous = str(row["entry_hash"])
                latest[(str(row["record_type"]), str(row["record_id"]))] = (
                    int(row["revision"]), str(row["payload_sha256"]),
                )
            for (record_type, record_id), (revision, digest) in latest.items():
                table = self._TABLES.get(record_type)
                if table is None:
                    breaks.append({"record_id": record_id, "reason": "unknown_record_type"})
                    continue
                record = conn.execute(
                    f"SELECT revision, payload_sha256, payload_json "  # noqa: S608
                    f"FROM {table} WHERE id = ?",
                    (record_id,),
                ).fetchone()
                if record is None or (int(record["revision"]), str(record["payload_sha256"])) != (
                    revision, digest,
                ) or hashlib.sha256(str(record["payload_json"]).encode("utf-8")).hexdigest() != digest:
                    breaks.append({"record_id": record_id, "reason": "record_mismatch"})
        return breaks


__all__ = [
    "AuditRecorder",
    "HuntStore",
    "RecordNotFound",
    "RevisionConflict",
]
