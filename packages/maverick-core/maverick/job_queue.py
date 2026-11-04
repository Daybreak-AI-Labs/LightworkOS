"""Persistent job queue for background goals.

A pure-Python SQLite-backed queue that lets the orchestrator (or
the dashboard) enqueue work that should run *later* without keeping
the request thread alive:

  - "schedule this goal for 3am"
  - "retry this failed goal in 10 minutes"
  - "rate-limit me to 1 of these per minute"

Distinct from ``maverick.runner``, which spawns goals immediately
in a thread pool. The queue is the durable layer underneath: it
survives process restarts and gives the dashboard a single place to
see what's pending.

The jobs table stores execution attempts separately from immutable recurrence
identity/template and the committed successor link. SQLite WAL mode supports
concurrent readers (dashboard) and transactionally fenced writers (workers).

Workflow:

  - ``enqueue(kind, payload, run_at=None)`` -> job id
  - ``claim(now, ready_at)``                -> next ready job (atomic UPDATE)
  - ``complete(job_id)``                    -> mark done
  - ``fail(job_id, error, retry_after=60)`` -> bump attempts + reschedule
  - ``list(status='pending')``              -> rows for the dashboard
  - ``purge(older_than_days=7)``            -> sweep terminal rows
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .paths import data_dir

log = logging.getLogger(__name__)


# Compatibility override for callers/tests that historically monkeypatched the
# module constant.  ``None`` means "resolve the active tenant at construction
# time".  Computing ``data_dir("jobs.db")`` here used to freeze whichever
# tenant (usually the shared root) happened to be active when this module was
# first imported, then leak that path into every later tenant scope.
DEFAULT_DB: Path | None = None


def _default_db() -> Path:
    return Path(DEFAULT_DB) if DEFAULT_DB is not None else data_dir("jobs.db")


@dataclass
class Job:
    id: int
    kind: str
    payload: dict
    run_at: float
    status: str
    attempts: int = 0
    last_error: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    recurrence_id: str | None = None
    occurrence: int | None = None
    scheduled_at: float | None = None
    successor_id: int | None = None
    recurrence_reconcile_required: bool = False


class LeaseLost(RuntimeError):
    """The claimed attempt no longer owns this job's running lease."""


class RecurrenceReconciliationRequired(RuntimeError):
    """A legacy occurrence needs an explicit local operator decision."""


_RECURRENCE_COLUMNS = {
    "recurrence_id": "TEXT",
    "occurrence": "INTEGER",
    "scheduled_at": "REAL",
    "successor_id": "INTEGER",
    "recurrence_payload": "TEXT",
    "recurrence_reconcile_required": "INTEGER NOT NULL DEFAULT 0",
}
_RECONCILE_REASON = (
    "recurrence reconciliation required: legacy attempted occurrence has no "
    "durable successor link; stop old workers, inspect job IDs, then use "
    "JobQueue.reconcile_recurrence to link a successor or confirm one future run"
)


def _recurrence_template(kind: str, payload: dict) -> dict:
    template = {k: v for k, v in payload.items() if k != "__rearmed__"}
    # A start_goal checkpoint belongs to this occurrence, not the next goal.
    if kind == "start_goal":
        template.pop("goal_id", None)
        template.pop("_slot_defers", None)
    return template


_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  kind        TEXT NOT NULL,
  payload     TEXT NOT NULL,
  run_at      REAL NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending',
  attempts    INTEGER NOT NULL DEFAULT 0,
  last_error  TEXT NOT NULL DEFAULT '',
  created_at  REAL NOT NULL,
  updated_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_ready ON jobs(status, run_at);
CREATE INDEX IF NOT EXISTS idx_jobs_flow_run ON jobs(
 kind,
 COALESCE(json_extract(CASE WHEN json_valid(payload) THEN payload ELSE '{}' END,'$.tenant'),''),
 json_extract(CASE WHEN json_valid(payload) THEN payload ELSE '{}' END,'$.run_id'), id DESC
);

-- Durable at-most-once claims for authenticated queue dispatch envelopes.
-- The database itself is tenant-scoped by JobQueue's lazy default path.
CREATE TABLE IF NOT EXISTS dispatch_envelope_claims (
  message_id    TEXT PRIMARY KEY,
  nonce_hash    TEXT NOT NULL,
  expires_at    REAL NOT NULL,
  claimed_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dispatch_claim_expiry
  ON dispatch_envelope_claims(expires_at);
-- Admission receipts outlive purged completed jobs. A retry cannot recreate
-- a previously dispatched event after routine queue retention cleanup.
CREATE TABLE IF NOT EXISTS job_admissions (
  admission_key TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  job_id INTEGER NOT NULL,
  created_at REAL NOT NULL
);
-- Reviewed recurrence repair receipts outlive routine completed-job retention.
CREATE TABLE IF NOT EXISTS recurrence_recovery_receipts (
  job_id INTEGER NOT NULL, actor TEXT NOT NULL, operation_id TEXT NOT NULL,
  request_hash TEXT NOT NULL, successor_id INTEGER NOT NULL, created_at REAL NOT NULL,
  PRIMARY KEY(job_id, actor, operation_id)
);

"""


class JobQueue:
    """Thread-safe persistent job queue.

    Multiple ``JobQueue`` instances against the same DB file are
    safe — SQLite WAL handles concurrent writers; the ``claim()``
    method selects, updates and returns the owned attempt in one transaction,
    so workers don't double-claim or return a peer's reclaimed attempt.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        selected = db_path if db_path is not None else _default_db()
        self._workspace_scoped = db_path is None
        self.db_path = Path(selected).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._ensure_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        c = sqlite3.connect(str(self.db_path), isolation_level=None)
        try:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA busy_timeout=5000")
            c.row_factory = sqlite3.Row
            yield c
        finally:
            c.close()

    def _ensure_schema(self) -> None:
        with self._conn() as c:
            from .schedule_definitions import SCHEMA as schedule_schema
            from .schedule_definitions import adopt_existing

            c.executescript(_SCHEMA + schedule_schema)
            c.execute("BEGIN IMMEDIATE")
            columns = {r[1] for r in c.execute("PRAGMA table_info(jobs)")}
            for name, definition in _RECURRENCE_COLUMNS.items():
                if name not in columns:
                    c.execute(f"ALTER TABLE jobs ADD COLUMN {name} {definition}")
            c.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_job_occurrence "
                "ON jobs(recurrence_id, occurrence) WHERE recurrence_id IS NOT NULL"
            )
            c.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_job_successor "
                "ON jobs(successor_id) WHERE successor_id IS NOT NULL"
            )
            # Backfill EVERY cron row without a schedule identity, not only on
            # the first upgrade: rows an older binary inserted after the
            # columns existed (a rollback, a mixed-version rollout) would
            # otherwise run once and silently never re-arm.
            rows = [self._row_to_job(row) for row in c.execute(
                "SELECT * FROM jobs WHERE recurrence_id IS NULL")]
            for job in rows:
                if not job.payload.get("__cron__"):
                    continue
                # Old rows have no reliable schedule identity. Never merge two
                # legitimate schedules merely because their payloads match: a
                # row that ran without its re-arm marker goes to an operator
                # (`maverick queue reconcile`), who links or re-arms it.
                uncertain = job.attempts > 0 and not job.payload.get("__rearmed__")
                c.execute(
                    "UPDATE jobs SET recurrence_id=?, occurrence=0, "
                    "scheduled_at=run_at, recurrence_payload=?, "
                    "recurrence_reconcile_required=?, "
                    "status=CASE WHEN ? THEN 'failed' ELSE status END, "
                    "last_error=CASE WHEN ? THEN ? ELSE last_error END WHERE id=?",
                    (uuid.uuid4().hex, json.dumps(_recurrence_template(job.kind, job.payload),
                                                default=str), int(uncertain), uncertain,
                     uncertain, _RECONCILE_REASON, job.id),
                )
            adopt_existing(c)
            c.commit()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize related writes across processes and roll back all of them."""
        with self._lock, self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                yield c
                c.commit()
            except BaseException:
                c.rollback()
                raise

    @staticmethod
    def _insert_job(c, kind, payload, run_at, now, *, recurrence_id=None,
                    occurrence=None, recurrence_payload=None) -> int:
        if recurrence_id is None and payload.get("__cron__"):
            recurrence_id, occurrence = uuid.uuid4().hex, 0
            recurrence_payload = json.dumps(_recurrence_template(kind, payload), default=str)
        if recurrence_id:
            from .schedule_definitions import register

            register(c, recurrence_id, kind, json.loads(recurrence_payload), now)
            c.execute("UPDATE schedule_definitions SET occurrence_cursor=MAX(occurrence_cursor,?) WHERE id=?", (occurrence + 1, recurrence_id))
        cur = c.execute(
            "INSERT INTO jobs (kind, payload, run_at, created_at, updated_at, "
            "recurrence_id, occurrence, scheduled_at, recurrence_payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (kind, json.dumps(payload, default=str), run_at, now, now,
             recurrence_id, occurrence, run_at if recurrence_id else None, recurrence_payload),
        )
        return int(cur.lastrowid)

    def enqueue(
        self,
        kind: str,
        payload: dict | None = None,
        *,
        run_at: float | None = None,
    ) -> int:
        now = time.time()
        rid = run_at if run_at is not None else now
        from .task_file_recovery import mutation_gate
        with mutation_gate(), self._transaction() as c:
            return self._insert_job(c, kind, payload or {}, rid, now)

    def enqueue_once(self, kind: str, payload: dict, *, idempotency_key: str,
                     run_at: float | None = None, effect_guard=None) -> int:
        """Atomically admit an immutable job once, including after completion.

        Retrying an uncertain enqueue returns its original ID. Reusing a key
        for different work refuses instead of silently substituting payloads.
        """
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise ValueError("job admission key is required")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        from .task_file_recovery import mutation_gate
        now = time.time()
        with mutation_gate(), self._transaction() as conn:
            row = conn.execute(
                "SELECT kind,payload_hash,job_id FROM job_admissions WHERE admission_key=?",
                (idempotency_key,),
            ).fetchone()
            if row is not None:
                if row["kind"] != kind or row["payload_hash"] != digest:
                    raise ValueError("job admission key is bound to different work")
                return int(row["job_id"])
            if effect_guard is not None:
                effect_guard()
            job_id = self._insert_job(
                conn, kind, payload, now if run_at is None else run_at, now)
            conn.execute(
                "INSERT INTO job_admissions(admission_key,kind,payload_hash,job_id,created_at) "
                "VALUES(?,?,?,?,?)", (idempotency_key, kind, digest, job_id, now))
            if effect_guard is not None:
                effect_guard()
            return job_id

    def admission_receipt(self, kind: str, payload: dict, *, idempotency_key: str) -> int | None:
        """Read one exact original admission, without creating or restarting work."""
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise ValueError("job admission key is required")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        with self._conn() as connection:
            row = connection.execute(
                "SELECT kind,payload_hash,job_id FROM job_admissions WHERE admission_key=?",
                (idempotency_key,),
            ).fetchone()
        if row is None:
            return None
        if row["kind"] != kind or row["payload_hash"] != digest:
            raise ValueError("job admission key is bound to different work")
        return int(row["job_id"])

    def claim_dispatch_envelope(
        self,
        message_id: str,
        nonce: str,
        *,
        expires_at: float,
        now: float | None = None,
    ) -> bool:
        """Atomically consume an authenticated dispatch envelope once.

        The claim is intentionally permanent for the lifetime of the signed
        envelope, including when the worker crashes or execution raises after
        this method returns.  Releasing it would turn a broker retry into a
        second opportunity to spend money or repeat side effects.  Operators
        must submit a fresh signed envelope to retry a post-claim failure.

        Only a SHA-256 digest of the nonce is retained.  Expired rows can be
        pruned safely because the worker rejects expired signatures before it
        reaches this store.
        """
        if not isinstance(message_id, str) or not message_id:
            raise ValueError("message_id must be a non-empty string")
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("nonce must be a non-empty string")
        expiry = float(expires_at)
        if not math.isfinite(expiry) or expiry <= 0:
            raise ValueError("expires_at must be positive")
        claimed_at = time.time() if now is None else float(now)
        if not math.isfinite(claimed_at):
            raise ValueError("now must be finite")
        nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
        try:
            with self._lock, self._conn() as c:
                # Keep the replay table bounded. A worker authenticates expiry
                # before calling us, so removing an already-expired claim
                # cannot make its old envelope executable again.
                c.execute(
                    "DELETE FROM dispatch_envelope_claims WHERE expires_at <= ?",
                    (claimed_at,),
                )
                c.execute(
                    "INSERT INTO dispatch_envelope_claims "
                    "(message_id, nonce_hash, expires_at, claimed_at) "
                    "VALUES (?, ?, ?, ?)",
                    (message_id, nonce_hash, expiry, claimed_at),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def prune_dispatch_envelope_claims(self, *, now: float | None = None) -> int:
        """Remove claims whose signed envelope can no longer be accepted."""
        cutoff = time.time() if now is None else float(now)
        with self._lock, self._conn() as c:
            cur = c.execute(
                "DELETE FROM dispatch_envelope_claims WHERE expires_at <= ?",
                (cutoff,),
            )
            return int(cur.rowcount)

    def claim(
        self,
        *,
        now: float | None = None,
        ready_at: float | None = None,
    ) -> Job | None:
        """Atomically pick the next ready pending job + mark it 'running'.

        ``ready_at`` is an optional readiness cutoff for callers that need to
        snapshot queue eligibility, such as one-shot drains. ``now`` remains
        the claim/heartbeat timestamp written to ``updated_at``. Keeping those
        values separate prevents a long-running drain from claiming later jobs
        with a stale heartbeat that another worker could reclaim.
        """
        if self._workspace_scoped:
            from .workspace_recovery import assert_bootstrap_start_allowed

            assert_bootstrap_start_allowed()
        n = now if now is not None else time.time()
        cutoff = ready_at if ready_at is not None else n
        with self._transaction() as c:
            # Pick a candidate.
            row = c.execute(
                "SELECT id FROM jobs WHERE status='pending' AND run_at <= ? "
                "AND (recurrence_id IS NULL OR attempts>0 OR EXISTS "
                "(SELECT 1 FROM schedule_definitions WHERE id=jobs.recurrence_id AND state='active')) "
                "ORDER BY run_at ASC, id ASC LIMIT 1",
                (cutoff,),
            ).fetchone()
            if not row:
                return None
            jid = row[0]
            # Try to mark it running atomically (status check guards
            # against races between SELECT and UPDATE).
            cur = c.execute(
                "UPDATE jobs SET status='running', attempts=attempts+1, "
                "updated_at=? WHERE id=? AND status='pending'",
                (n, jid),
            )
            if cur.rowcount == 0:
                return None
            row = c.execute(
                "SELECT * FROM jobs WHERE id=?", (jid,),
            ).fetchone()
        return self._row_to_job(row)

    def heartbeat(
        self,
        job_id: int,
        *,
        now: float | None = None,
        expected_attempts: int | None = None,
    ) -> bool:
        """Refresh a running job's lease (bump ``updated_at``) mid-run.

        ``claim()`` writes ``updated_at`` exactly once, so without periodic
        refreshes any handler that outlives ``reclaim_stale``'s lease looks
        crashed to a peer worker and its job is stolen -- requeued and
        re-executed WHILE still running. The worker heartbeats from a small
        thread during dispatch; a real crash stops the heartbeat with the
        process, so orphan recovery is unaffected. Fenced on
        ``status='running'`` (and, when given, the attempt the caller claimed
        at) so a stale heartbeat can't refresh a reclaimed/re-claimed or
        terminal row it no longer owns. Returns True if the lease was extended.
        """
        n = now if now is not None else time.time()
        with self._lock, self._conn() as c:
            if expected_attempts is None:
                cur = c.execute(
                    "UPDATE jobs SET updated_at=? WHERE id=? AND status='running'",
                    (n, job_id),
                )
            else:
                cur = c.execute(
                    "UPDATE jobs SET updated_at=? "
                    "WHERE id=? AND attempts=? AND status='running'",
                    (n, job_id, expected_attempts),
                )
            return cur.rowcount == 1

    def complete(self, job_id: int, *, expected_attempts: int | None = None) -> bool:
        """Mark a job 'done'. ``expected_attempts`` fences a stolen lease: a slow
        worker can have its 'running' job reclaimed (``reclaim_stale``) and
        re-claimed by a peer, which bumps ``attempts``. Passing the attempt count
        the worker claimed at makes a stale completion no-op (rowcount 0) instead
        of clobbering the job the current owner is running."""
        with self._lock, self._conn() as c:
            if expected_attempts is None:
                cur = c.execute(
                    "UPDATE jobs SET status='done', updated_at=? WHERE id=?",
                    (time.time(), job_id),
                )
            else:
                # Also fence on status='running': reclaim_stale requeues a
                # stale lease to 'pending' WITHOUT bumping attempts, so an
                # attempts-only guard would still match the now-pending row and
                # wrongly flip a job that must be re-executed to 'done'.
                cur = c.execute(
                    "UPDATE jobs SET status='done', updated_at=? "
                    "WHERE id=? AND attempts=? AND status='running'",
                    (time.time(), job_id, expected_attempts),
                )
            return cur.rowcount == 1

    def set_payload(self, job_id: int, payload: dict, *, expected_attempts: int) -> bool:
        """Replace a job's payload. Lets a handler persist state across retries
        (e.g. a created goal id) so a re-run reuses it instead of redoing work.
        A claimed running attempt is mandatory; False means ownership was lost.
        Recurrence identity, template and advancement live outside this mutable
        checkpoint and cannot be changed by replacing its payload.
        """
        with self._transaction() as c:
            row = c.execute(
                "SELECT payload, successor_id FROM jobs "
                "WHERE id=? AND attempts=? AND status='running'",
                (job_id, expected_attempts),
            ).fetchone()
            if row is None:
                return False
            payload = dict(payload)
            payload.pop("__rearmed__", None)
            if row["successor_id"] or json.loads(row["payload"]).get("__rearmed__"):
                payload["__rearmed__"] = True
            cur = c.execute(
                "UPDATE jobs SET payload=?, updated_at=? "
                "WHERE id=? AND attempts=? AND status='running'",
                (json.dumps(payload, default=str), time.time(), job_id, expected_attempts),
            )
            return cur.rowcount == 1

    @staticmethod
    def _require_attempt(c, job_id: int, expected_attempts: int):
        row = c.execute(
            "SELECT * FROM jobs WHERE id=? AND attempts=? AND status='running'",
            (job_id, expected_attempts),
        ).fetchone()
        if row is None:
            raise LeaseLost(f"job {job_id}: running lease is no longer owned")
        return row

    def _advance_recurrence(self, c, row, *, now: float) -> int:
        from .scheduler import next_run

        definition = c.execute("SELECT * FROM schedule_definitions WHERE id=?", (row["recurrence_id"],)).fetchone()
        if definition is not None and definition["state"] != "active":
            payload = json.loads(row["payload"])
            payload["__rearmed__"] = True
            c.execute("UPDATE jobs SET payload=? WHERE id=?", (json.dumps(payload), row["id"]))
            return 0
        template = json.loads(definition["payload"] if definition is not None else row["recurrence_payload"])
        run_at = next_run(template["__cron__"], after=now,
                          tz=str(template.get("__tz__") or ""))
        successor = self._insert_job(
            c, row["kind"], template, run_at, now,
            recurrence_id=row["recurrence_id"], occurrence=max(row["occurrence"] + 1, definition["occurrence_cursor"] if definition is not None else 0),
            recurrence_payload=json.dumps(template),
        )
        payload = json.loads(row["payload"])
        payload["__rearmed__"] = True
        c.execute(
            "UPDATE jobs SET successor_id=?, payload=?, updated_at=? WHERE id=?",
            (successor, json.dumps(payload, default=str), now, row["id"]),
        )
        return successor

    def rearm(self, job_id: int, *, expected_attempts: int,
              now: float | None = None) -> Job:
        """Atomically create one successor and advance the current occurrence.

        The transaction's running-attempt check fences stale workers. The
        immutable (recurrence_id, occurrence) unique index is an additional
        database invariant; no payload comparison or backlog scan is involved.
        Return the current parent checkpoint so its handler keeps the marker.
        """
        from .task_file_recovery import mutation_gate

        n = time.time() if now is None else now
        with mutation_gate(), self._transaction() as c:
            row = self._require_attempt(c, job_id, expected_attempts)
            if row["recurrence_reconcile_required"]:
                raise RecurrenceReconciliationRequired(_RECONCILE_REASON)
            payload = json.loads(row["payload"])
            # Marked legacy rows have no successor link, but already made the
            # at-most-once decision. Retain it, including a cancelled successor.
            if row["recurrence_id"] and not (row["successor_id"] or payload.get("__rearmed__")):
                self._advance_recurrence(c, row, now=n)
            return self._row_to_job(c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    @staticmethod
    def _recovery_fingerprint(expected_attempts, successor_id, rearm, expected_evidence, rationale):
        return hashlib.sha256(json.dumps({"attempts": expected_attempts, "successor": successor_id,
            "rearm": rearm, "evidence": expected_evidence, "rationale": rationale}, sort_keys=True).encode()).hexdigest()

    def recovery_receipt(self, job_id, *, actor, operation_id, expected_attempts, successor_id,
                         rearm, expected_evidence, rationale):
        digest = self._recovery_fingerprint(expected_attempts, successor_id, rearm, expected_evidence, rationale)
        return self.recovery_receipt_commitment(job_id, actor=actor, operation_id=operation_id,
                                                request_hash=digest)

    def recovery_receipt_commitment(self, job_id, *, actor, operation_id, request_hash):
        """Read one actor-bound exact original receipt; never repair or replay work."""
        if not isinstance(request_hash, str) or len(request_hash) != 64 or any(
                character not in "0123456789abcdef" for character in request_hash):
            raise ValueError("The reviewed request commitment is invalid.")
        with self._conn() as connection:
            row = connection.execute("SELECT request_hash,successor_id FROM recurrence_recovery_receipts "
                "WHERE job_id=? AND actor=? AND operation_id=?", (job_id, actor, operation_id)).fetchone()
        if row is None:
            return None
        if row["request_hash"] != request_hash:
            raise ValueError("This recovery reference belongs to a different reviewed decision.")
        return int(row["successor_id"])

    def reconcile_recurrence(self, job_id: int, *, expected_attempts: int,
                             successor_id: int | None = None,
                             rearm: bool = False, confirm: bool = False,
                             expected_evidence: str | None = None, actor: str = "local operator",
                             rationale: str = "Reviewed future recurrence recovery", operation_id: str | None = None) -> int:
        """Explicit operator recovery; never automatically called by a worker.

        Requires filesystem/operator authority over this queue, explicit
        confirmation and the inspected attempt. Link a reviewed compatible
        successor OR authorize one future occurrence. The ambiguous historical
        job remains failed: this decision never replays its business work.
        """
        if confirm is not True or rearm == (successor_id is not None):
            raise ValueError("confirm exactly one recovery: successor_id or rearm=True")
        from .task_file_recovery import mutation_gate

        digest = self._recovery_fingerprint(expected_attempts, successor_id, rearm, expected_evidence, rationale)
        with mutation_gate(), self._transaction() as c:
            if operation_id:
                prior = c.execute("SELECT request_hash,successor_id FROM recurrence_recovery_receipts "
                    "WHERE job_id=? AND actor=? AND operation_id=?", (job_id, actor, operation_id)).fetchone()
                if prior is not None:
                    if prior["request_hash"] != digest:
                        raise ValueError("This recovery reference belongs to a different reviewed decision.")
                    return int(prior["successor_id"])
            row = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None or row["attempts"] != expected_attempts or row["status"] != "failed":
                raise ValueError("reconciliation state changed; inspect the job again")
            if expected_evidence is not None:
                from .schedule_definitions import recovery_evidence

                current_evidence = recovery_evidence(c, row)
                if current_evidence != expected_evidence:
                    raise ValueError("Recovery evidence changed. Review the occurrence again.")
            from .schedule_definitions import _record_version

            definition = c.execute("SELECT * FROM schedule_definitions WHERE id=?", (row["recurrence_id"],)).fetchone()
            if definition is not None and row["recurrence_reconcile_required"]:
                _record_version(c, definition, payload=json.loads(definition["payload"]),
                                state="active", actor=actor, rationale=rationale, now=time.time())
            if not row["recurrence_reconcile_required"]:
                if row["successor_id"] and (rearm or row["successor_id"] == successor_id):
                    return int(row["successor_id"])
                raise ValueError("job does not require recurrence reconciliation")
            if successor_id is not None:
                child = c.execute("SELECT * FROM jobs WHERE id=?", (successor_id,)).fetchone()
                if child is None or child["id"] <= job_id or child["kind"] != row["kind"]:
                    raise ValueError("successor is missing or incompatible")
                if (json.loads(child["recurrence_payload"] or "null")
                        != json.loads(row["recurrence_payload"])):
                    raise ValueError("successor schedule/authority template differs")
                # A separately identified successor owns its future chain.
                # Retire the source definition to prevent a second chain.
                if definition is not None and child["recurrence_id"] != row["recurrence_id"]:
                    current_definition = c.execute("SELECT * FROM schedule_definitions WHERE id=?", (row["recurrence_id"],)).fetchone()
                    _record_version(c, current_definition, payload=json.loads(current_definition["payload"]),
                                    state="retired", actor=actor, rationale=f"Linked to schedule {child['recurrence_id']}: {rationale}", now=time.time())
                payload = json.loads(row["payload"])
                payload["__rearmed__"] = True
                c.execute("UPDATE jobs SET successor_id=?, payload=? WHERE id=?",
                          (successor_id, json.dumps(payload, default=str), job_id))
            else:
                successor_id = self._advance_recurrence(c, row, now=time.time())
            c.execute(
                "UPDATE jobs SET recurrence_reconcile_required=0, last_error=?, updated_at=? WHERE id=?",
                (f"recurrence reconciled; successor job {successor_id}; "
                 "historical execution not replayed", time.time(), job_id),
            )
            if operation_id:
                c.execute("INSERT INTO recurrence_recovery_receipts "
                    "(job_id,actor,operation_id,request_hash,successor_id,created_at) VALUES(?,?,?,?,?,?)",
                    (job_id, actor, operation_id, digest, successor_id, time.time()))
            return int(successor_id)

    def fail(
        self,
        job_id: int,
        error: str,
        *,
        retry_after: float | None = 60.0,
        max_attempts: int = 5,
        expected_attempts: int | None = None,
    ) -> bool:
        """Either reschedule (retry_after seconds) or mark 'failed' permanently.

        ``expected_attempts`` fences a stolen lease the same way ``complete`` does:
        if a peer re-claimed the job (bumping ``attempts``) this stale failure is
        a no-op instead of rescheduling/failing the job its new owner is running."""
        now = time.time()
        with self._lock, self._conn() as c:
            row = c.execute(
                "SELECT attempts FROM jobs WHERE id=?", (job_id,),
            ).fetchone()
            if not row:
                return False
            attempts = int(row[0])
            if expected_attempts is not None and attempts != expected_attempts:
                return False  # lease lost to a re-claim; the current owner owns it
            # A worker can only fail its current running attempt. Legacy
            # operator calls without a fence can still annotate terminal rows.
            status_guard = "status='running'" if expected_attempts is not None else "status != 'pending'"
            if retry_after is not None and attempts < max_attempts:
                next_run = now + float(retry_after)
                cur = c.execute(
                    "UPDATE jobs SET status='pending', run_at=?, "
                    "last_error=?, updated_at=? "
                    f"WHERE id=? AND attempts=? AND {status_guard}",
                    (next_run, error[:1000], now, job_id, attempts),
                )
            else:
                cur = c.execute(
                    "UPDATE jobs SET status='failed', last_error=?, "
                    f"updated_at=? WHERE id=? AND attempts=? AND {status_guard}",
                    (error[:1000], now, job_id, attempts),
                )
            return cur.rowcount == 1

    def reclaim_stale(
        self,
        lease_seconds: float,
        *,
        now: float | None = None,
        max_attempts: int = 5,
    ) -> int:
        """Requeue jobs stuck in 'running' past the lease TTL.

        ``claim()`` flips a job to 'running' and bumps ``updated_at``. If the
        worker process then dies before ``complete()``/``fail()`` (a hard
        crash, OOM, or ``kill -9`` — none of which run ``run_once``'s
        ``except`` path), the row stays 'running' forever: ``claim()`` only
        ever looks at 'pending' rows, so no worker re-claims it and the job
        is silently orphaned. Run this on worker start to recover them.

        A job whose ``updated_at`` is at or before ``now - lease_seconds`` is
        considered abandoned. Inclusive expiry matters for a zero-second lease
        and for clocks whose resolution makes claim and reclaim timestamps
        equal: once the lease deadline is reached, the work is reclaimable.
        Pick a ``lease_seconds`` larger than the
        longest expected job runtime so a still-running job in a live worker
        is not stolen. Abandoned jobs already at/over ``max_attempts`` are
        marked 'failed' (poison-pill guard, mirroring ``fail()``'s terminal
        path) so a job that reliably crashes the *process* can't be requeued
        forever; the rest go back to 'pending' with ``run_at = now`` so
        they're immediately eligible. ``attempts`` is preserved (not reset)
        so the cap is reached. Returns the number of rows transitioned.
        """
        n = now if now is not None else time.time()
        cutoff = n - float(lease_seconds)
        with self._lock, self._conn() as c:
            failed = c.execute(
                "UPDATE jobs SET status='failed', last_error=?, updated_at=? "
                "WHERE status='running' AND updated_at <= ? AND attempts >= ?",
                ("lease expired (worker presumed crashed)", n, cutoff, max_attempts),
            ).rowcount
            requeued = c.execute(
                "UPDATE jobs SET status='pending', run_at=?, updated_at=? "
                "WHERE status='running' AND updated_at <= ? AND attempts < ?",
                (n, n, cutoff, max_attempts),
            ).rowcount
        return int(failed) + int(requeued)

    def cancel(self, job_id: int) -> bool:
        """Delete a *pending* job (e.g. an armed schedule).

        Only 'pending' rows are removable -- a 'running' job is left for the
        worker to finish, and 'done'/'failed' rows are history. Returns True
        if a row was deleted.
        """
        with self._lock, self._conn() as c:
            cur = c.execute(
                "DELETE FROM jobs WHERE id=? AND status='pending'", (job_id,),
            )
            return cur.rowcount == 1

    def get(self, job_id: int) -> Job | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM jobs WHERE id=?", (job_id,),
            ).fetchone()
        return self._row_to_job(row) if row else None

    def list(self, *, status: str = "", limit: int = 100) -> list[Job]:
        with self._conn() as c:
            if status:
                rows = c.execute(
                    "SELECT * FROM jobs WHERE status=? ORDER BY id DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,),
                ).fetchall()
        return [self._row_to_job(r) for r in rows]

    def iter_pending(self, kind: str | None = None, *, page_size: int = 256,
                     include_running: bool = False) -> Iterator[Job]:
        """Inspect pending jobs of one kind, or all kinds, without a page cutoff.

        Keyset pages tolerate cancellation during reconciliation. A fixed high
        water mark bounds the pass if producers keep appending new jobs.
        """
        if not 1 <= page_size <= 1000:
            raise ValueError("page_size must be between 1 and 1000")
        # Reconciliation also needs claimed occurrences whose successor has
        # not yet been armed. Dashboard callers retain pending-only behavior.
        status = "status IN ('pending','running')" if include_running else "status='pending'"
        with self._conn() as c:
            upper = c.execute("SELECT COALESCE(MAX(id), 0) FROM jobs").fetchone()[0]
        kind_sql = "kind=? AND " if kind is not None else ""
        kind_args = (kind,) if kind is not None else ()
        after = 0
        while after < upper:
            with self._conn() as c:
                rows = c.execute(
                    f"SELECT * FROM jobs WHERE {kind_sql}{status} "
                    "AND id>? AND id<=? ORDER BY id LIMIT ?",
                    (*kind_args, after, upper, page_size),
                ).fetchall()
            if not rows:
                return
            after = rows[-1]["id"]
            yield from (self._row_to_job(row) for row in rows)

    def find_for_run(self, kind: str, run_id: str, tenant: str = "") -> Job | None:
        """Latest exact run delivery, including terminal jobs; never a scan cutoff."""
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM jobs WHERE kind=? "
                "AND COALESCE(json_extract(CASE WHEN json_valid(payload) THEN payload ELSE '{}' END,'$.tenant'),'')=? "
                "AND json_extract(CASE WHEN json_valid(payload) THEN payload ELSE '{}' END,'$.run_id')=? "
                "ORDER BY id DESC LIMIT 1",
                (kind, tenant, run_id),
            ).fetchone()
            return self._row_to_job(row) if row else None

    def counts(self) -> dict[str, int]:
        """``{status: count}`` across the whole queue — backlog + dead-letter
        visibility for metrics/ops (a growing ``pending`` is an alert; ``failed``
        jobs are the dead-letter that ``purge`` would otherwise silently drop)."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT status, COUNT(*) AS n FROM jobs GROUP BY status"
            ).fetchall()
        return {str(r["status"]): int(r["n"]) for r in rows}

    def purge(self, *, older_than_days: float = 7.0) -> int:
        cutoff = time.time() - older_than_days * 86400
        with self._lock, self._conn() as c:
            cur = c.execute(
                "DELETE FROM jobs WHERE status IN ('done','failed','cancelled') AND updated_at < ? "
                "AND recurrence_reconcile_required=0",
                (cutoff,),
            )
            return cur.rowcount

    @staticmethod
    def _row_to_job(row) -> Job:
        try:
            payload = json.loads(row["payload"])
        except (TypeError, ValueError):
            payload = {}
        return Job(
            id=int(row["id"]),
            kind=str(row["kind"]),
            payload=payload if isinstance(payload, dict) else {"_": payload},
            run_at=float(row["run_at"]),
            status=str(row["status"]),
            attempts=int(row["attempts"]),
            last_error=str(row["last_error"] or ""),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            recurrence_id=row["recurrence_id"],
            occurrence=row["occurrence"],
            scheduled_at=row["scheduled_at"],
            successor_id=row["successor_id"],
            recurrence_reconcile_required=bool(row["recurrence_reconcile_required"]),
        )


__all__ = ["JobQueue", "Job", "DEFAULT_DB", "LeaseLost", "RecurrenceReconciliationRequired"]
