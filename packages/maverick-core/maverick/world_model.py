"""Persistent world model. SQLite with FTS5 + per-connection WAL.

Reliability:
  - PRAGMA journal_mode=WAL so the agent process (writer) and dashboard
    process (reader) don't deadlock on each other.
  - PRAGMA busy_timeout=5000 so concurrent commits retry briefly
    instead of raising OperationalError.
  - check_same_thread=False so FastAPI's threadpool can share the connection.
  - Indexes on goals(status) and goals(updated_at) for the dashboard's
    `list goals by status` and `active_goal()` queries.
"""
from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import logging
import math
import os
import secrets
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import fields
from pathlib import Path
from typing import Any

from .approval_checks import SQLITE_SCHEMA as _APPROVAL_CHECK_SCHEMA
from .attachment_submissions import SQLITE_SCHEMA as _ATTACHMENT_SUBMISSION_SCHEMA
from .deadline_alerts import SQLITE_SCHEMA as _DEADLINE_ALERT_SCHEMA
from .event_admission import SQLITE_SCHEMA as _EVENT_ADMISSION_SCHEMA
from .event_admission import (
    EventRegistryUnavailable,
    LegacyEventGoalHeld,
    compatible_event_goal,
    execution_binding_lock,
)
from .file_lock import (
    atomic_create_bytes,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
    prepare_private_directory,
)
from .goal_mutations import SCHEMA as _GOAL_MUTATION_SCHEMA
from .metadata_history import SQLITE_INDEXES as _HISTORY_INDEXES
from .paths import bind_tenant_namespace, current_tenant_id, data_dir
from .personal_alert_revisions import SQLITE_MIGRATION as _PERSONAL_ALERT_MIGRATION
from .webhook_subscriptions import SQLITE_SCHEMA as _WEBHOOK_SUBSCRIPTION_SCHEMA
from .world_model_contracts import GoalLookup, GoalRecord
from .world_records import Approval as Approval
from .world_records import ApprovalAuditEvent as ApprovalAuditEvent
from .world_records import Attachment as Attachment
from .world_records import Conversation as Conversation
from .world_records import EpisodeSpend as EpisodeSpend
from .world_records import FactVersion as FactVersion
from .world_records import Goal as Goal
from .world_records import GoalEvent as GoalEvent
from .world_records import Question as Question
from .world_records import Turn as Turn

log = logging.getLogger(__name__)

# ``DEFAULT_DB`` remains a public override hook for embedders and tests, but
# the built-in default must be resolved at *call time*.  A process can import
# this module while handling tenant A and later serve tenant B (or the shared
# single-tenant root); using the import-time path in that later request would
# cross the tenant boundary.  Identity, rather than equality, distinguishes an
# intentional override from the untouched compatibility constant.
_INITIAL_DEFAULT_DB = data_dir("world.db")
DEFAULT_DB = _INITIAL_DEFAULT_DB
SCHEMA_VERSION = 51
DEFAULT_BUSY_TIMEOUT_MS = 5000
WAL_SWITCH_BUSY_TIMEOUT_MS = 50
WAL_SWITCH_RETRY_SECONDS = 5.0

# Valid PRAGMA synchronous levels (we don't expose OFF — corruption risk).
_SYNC_MODES = {"NORMAL", "FULL", "EXTRA"}


def _synchronous_mode() -> str:
    """The PRAGMA synchronous level: ``MAVERICK_WORLD_SYNCHRONOUS`` /
    ``[world_model] synchronous`` (NORMAL default). FULL/EXTRA make every commit
    durable (no acked-row loss on OS crash) at a write-latency cost."""
    raw = os.environ.get("MAVERICK_WORLD_SYNCHRONOUS")
    if not raw:
        try:
            from .config import load_config
            raw = ((load_config() or {}).get("world_model") or {}).get("synchronous")
        except Exception:
            raw = None
    mode = str(raw or "NORMAL").strip().upper()
    return mode if mode in _SYNC_MODES else "NORMAL"


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS goals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id INTEGER REFERENCES goals(id),
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    deadline REAL,
    result TEXT,
    owner TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    project_id INTEGER
);

-- v19 projects ("matters"): a workspace grouping related goals (a close cycle,
-- an audit, a deal). name + description are encrypted at rest like goal content;
-- owner/domain/status are plaintext for listing + filtering. Goals point at one
-- via goals.project_id (nullable; a goal need not belong to a project).
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    owner TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_at REAL NOT NULL
);

-- v20 share links: a revocable, expiring read-only link to a goal's
-- deliverable for someone without a dashboard login. The token is random and
-- only its SHA-256 is stored (like a password-reset token), so the DB never
-- holds anything that grants access; the clear token is shown to the creator
-- exactly once.
CREATE TABLE IF NOT EXISTS share_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER NOT NULL REFERENCES goals(id),
    token_sha256 TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    expires_at REAL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_goals_status     ON goals(status);
CREATE INDEX IF NOT EXISTS idx_goals_updated_at ON goals(updated_at);

CREATE TABLE IF NOT EXISTS goal_origins (
    goal_id INTEGER PRIMARY KEY REFERENCES goals(id),
    kind TEXT NOT NULL,
    ref TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_goal_origins_ref ON goal_origins(kind, ref);

-- v16 deliverable sign-off: a human's certify/reject decision on a finished,
-- gated deliverable (the review a pack's output-contract gate calls for). One
-- authoritative current decision per goal; the note is encrypted at rest like
-- other free-text. This is the governed hand-off: agents draft, humans certify.
CREATE TABLE IF NOT EXISTS signoffs (
    goal_id INTEGER PRIMARY KEY REFERENCES goals(id),
    decision TEXT NOT NULL,
    decided_by TEXT NOT NULL DEFAULT '',
    note TEXT,
    created_at REAL NOT NULL
);

-- v18 artifacts: versioned, kind-tagged deliverable artifacts a goal produces
-- (markdown / code / table / text), distinct from the single goal.result blob.
-- Re-emitting the same (goal_id, title) appends a new version; title + content
-- are encrypted at rest like other agent output. The render kind drives how the
-- dashboard presents it.
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER NOT NULL REFERENCES goals(id),
    kind TEXT NOT NULL DEFAULT 'text',
    title TEXT,
    content TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_goal ON artifacts(goal_id);

CREATE TABLE IF NOT EXISTS episodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER REFERENCES goals(id),
    started_at REAL NOT NULL,
    ended_at REAL,
    summary TEXT,
    outcome TEXT,
    cost_dollars REAL DEFAULT 0,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    tool_calls INTEGER DEFAULT 0,
    cache_read_tokens INTEGER DEFAULT 0,
    cache_write_tokens INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_episodes_ended_at ON episodes(ended_at);

CREATE TABLE IF NOT EXISTS facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    source_episode_id INTEGER REFERENCES episodes(id),
    updated_at REAL NOT NULL,
    -- v17 Memory Guard provenance (plaintext metadata; the value stays sealed).
    -- source = who authored this fact; trust_tier = maverick.memory_guard.TrustTier
    -- (3=first-party/operator default ... 0=external/untrusted); sensitivity label.
    source TEXT NOT NULL DEFAULT '',
    trust_tier INTEGER NOT NULL DEFAULT 3,
    sensitivity TEXT NOT NULL DEFAULT 'internal',
    UNIQUE(key)
);

-- v17 temporal memory: a bitemporal history of every fact value. `facts` keeps
-- the single CURRENT value (UNIQUE(key)); this table records each value's
-- validity window so "what did we believe on date X, and why" is answerable --
-- non-destructive evolution instead of overwrite. `value` is sealed at rest like
-- facts.value; the window/provenance columns are plaintext so they stay queryable
-- under encryption. Only written when [memory] temporal is enabled.
CREATE TABLE IF NOT EXISTS fact_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    source_episode_id INTEGER REFERENCES episodes(id),
    valid_from REAL NOT NULL,
    valid_to REAL,
    source TEXT NOT NULL DEFAULT '',
    trust_tier INTEGER NOT NULL DEFAULT 3,
    sensitivity TEXT NOT NULL DEFAULT 'internal'
);

CREATE INDEX IF NOT EXISTS idx_fact_history_key ON fact_history(key, valid_from);

CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER REFERENCES goals(id),
    question TEXT NOT NULL,
    asked_at REAL NOT NULL,
    answer TEXT,
    answered_at REAL
);

-- v9 approval queue: high-risk actions parked by safety.consent in
-- 'dashboard' mode. The consent path inserts a 'pending' row and polls
-- status; the dashboard /approvals page flips it to approved/denied.
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    risk TEXT NOT NULL DEFAULT 'medium',
    scope TEXT,
    detail TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_at REAL NOT NULL,
    decided_at REAL,
    claimed_by TEXT,
    claimed_at REAL,
    decided_by TEXT,
    approvals_required INTEGER NOT NULL DEFAULT 1,
    requested_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, id);

-- v21 N-of-M dual control: one row per (approval, approver), so the PK enforces
-- a given approver counting once toward the quorum (segregation of duties).
CREATE TABLE IF NOT EXISTS approval_signoffs (
    approval_id INTEGER NOT NULL,
    approver    TEXT NOT NULL,
    decision    TEXT NOT NULL,
    decided_at  REAL NOT NULL,
    note        TEXT,
    PRIMARY KEY (approval_id, approver)
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER REFERENCES goals(id),
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS goal_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER NOT NULL REFERENCES goals(id),
    agent TEXT NOT NULL,
    kind TEXT NOT NULL,
    content TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_goal_events_goal_id_id ON goal_events(goal_id, id);
CREATE INDEX IF NOT EXISTS idx_goal_events_ts          ON goal_events(ts);

-- v4 multi-turn conversations: one thread per channel user.
-- (channel, user_id) is the natural key, so the same iMessage user
-- across separate Lightwork goals lands in a single conversation.
CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(channel, user_id)
);

CREATE INDEX IF NOT EXISTS idx_conversations_last_seen ON conversations(last_seen);

CREATE TABLE IF NOT EXISTS turns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL REFERENCES conversations(id),
    goal_id INTEGER REFERENCES goals(id),
    role TEXT NOT NULL,     -- 'user' | 'assistant'
    content TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_turns_conv_id ON turns(conversation_id, id);

-- v5 attachments: files/images uploaded with a goal.
-- The actual bytes live on disk under ~/.maverick/attachments/<goal>/<sha>;
-- this row records the metadata and lets the agent enumerate them.
CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER NOT NULL REFERENCES goals(id),
    filename TEXT NOT NULL,
    mime TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attachments_goal_id ON attachments(goal_id);

-- v6 channel idempotency: Twilio / iMessage / other channels retry
-- webhooks on non-2xx (or slow handlers). Without a dedup key the same
-- inbound message triggers N goal runs and N API spends.
CREATE TABLE IF NOT EXISTS processed_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    external_id TEXT NOT NULL,
    goal_id INTEGER REFERENCES goals(id),
    seen_at REAL NOT NULL,
    UNIQUE(channel, external_id)
);

-- v22 cluster-wide killswitch: a shared halt the dashboard arms and every
-- replica's killswitch.check() consults, so an emergency stop propagates across
-- the fleet (the in-process flag + local HALT file only stop the replica that
-- served the request). Untenanted on purpose -- a global emergency stop is not
-- per-tenant; ``scope=''`` is the global row.
CREATE TABLE IF NOT EXISTS halt (
    scope    TEXT PRIMARY KEY,
    reason   TEXT,
    source   TEXT,
    armed_by TEXT,
    armed_at REAL NOT NULL
);

-- v23 cluster-wide provider spend ledger: a shared per-(period, provider) total
-- so the provider_cost_cap ceiling is enforced across the fleet, not per-host.
-- The host-local JSON ledger (provider_spend.json) is per-host and lets N
-- replicas each spend up to the cap; on a shared backend this row is the single
-- authoritative total.
CREATE TABLE IF NOT EXISTS provider_spend (
    period_key TEXT NOT NULL,
    provider   TEXT NOT NULL,
    dollars    REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (period_key, provider)
);

CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    content, content='messages', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, content) VALUES (new.id, new.content);
END;

-- External-content FTS5 requires the delete/update triggers too, or the
-- shadow index drifts out of sync with `messages` on any DELETE/UPDATE
-- (purge already deletes messages), leaving search matching stale/missing rows.
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, content)
    VALUES('delete', old.id, old.content);
END;

CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, content)
    VALUES('delete', old.id, old.content);
    INSERT INTO messages_fts(rowid, content) VALUES (new.id, new.content);
END;

-- v8 hot-query indexes: cover the read paths listed in
-- docs/performance/world-model-indexes.md. MIGRATIONS[8] repeats them so
-- existing databases pick them up on next open.
CREATE INDEX IF NOT EXISTS idx_episodes_goal_started
    ON episodes(goal_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_episodes_started
    ON episodes(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_goals_status_updated
    ON goals(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_goals_parent
    ON goals(parent_id, created_at);

-- v25 fleet learning store: the self-harness addenda / provenance / transfer
-- tried-memory as shared tables, so a multi-host fleet learns as one. Written
-- only when [self_harness] store = "world"; empty tables otherwise.
CREATE TABLE IF NOT EXISTS harness_addenda (
    key        TEXT PRIMARY KEY,
    block      TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS harness_line_meta (
    line_id    TEXT PRIMARY KEY,
    record     TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS harness_transfer_tried (
    line_id TEXT PRIMARY KEY,
    ts      REAL NOT NULL
);

-- v26 fleet learning store, eval corpus: live cases, harvest pending and
-- reject memory, plus "extra" rows preserving a live file's non-list top-level
-- entries. seq preserves row order (review indexes are positional). Written
-- only when [self_harness] store = "world".
CREATE TABLE IF NOT EXISTS harness_corpus (
    kind TEXT NOT NULL,
    key  TEXT NOT NULL,
    seq  INTEGER NOT NULL,
    row  TEXT NOT NULL,
    PRIMARY KEY (kind, key, seq)
);
"""


def _bootstrap_schema(conn: sqlite3.Connection) -> str:
    """Do not recreate v49's retired derived index from the immutable v1 seed.

    From v49 on, the seed is applied without its message-search block: from the
    ``messages_fts`` virtual table up to the first v8 index that follows it.
    """
    if conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone():
        row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        if row and row[0] >= 49:
            start = SCHEMA.index("CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts")
            end = SCHEMA.index("CREATE INDEX IF NOT EXISTS idx_episodes_goal_started", start)
            return SCHEMA[:start] + SCHEMA[end:]
    return SCHEMA


MIGRATIONS: dict[int, list[str]] = {
    # v51: which decisions can still be undone. Only a request a waiting task
    # holds ("open") can be; the task marks it "settled" when it acts on it.
    51: ["ALTER TABLE approvals ADD COLUMN undo_hold TEXT"],
    # v50: ordered per-task question reads avoid scanning unrelated history.
    50: ["CREATE INDEX IF NOT EXISTS idx_questions_goal_id ON questions(goal_id, id)"],
    # v49: retire only unused derived message-search storage. Authoritative
    # messages and conversation turns are untouched; the exact SQL is governed.
    49: [
        "DROP TRIGGER IF EXISTS messages_ai",
        "DROP TRIGGER IF EXISTS messages_ad",
        "DROP TRIGGER IF EXISTS messages_au",
        "DROP TABLE IF EXISTS messages_fts",
    ],
    # v48: one row per approval-gate decision (no content), for previewing a
    # threshold change later (maverick.approval_checks).
    48: _APPROVAL_CHECK_SCHEMA,
    # Reconcile both draft histories without changing their earlier fingerprints.
    # The teardown draft used v42 for these tables, so its databases may have
    # skipped the companion draft's v42 receipt table. Ensure both sets at v47.
    47: [
        _GOAL_MUTATION_SCHEMA,
        *_WEBHOOK_SUBSCRIPTION_SCHEMA,
        *_DEADLINE_ALERT_SCHEMA,
    ],
    46: ["ALTER TABLE goals ADD COLUMN connection_selection TEXT NOT NULL DEFAULT ''"],
    45: _HISTORY_INDEXES,
    44: _PERSONAL_ALERT_MIGRATION,
    43: ["ALTER TABLE facts ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'"],
    42: [_GOAL_MUTATION_SCHEMA],
    40: [statement for statement in _EVENT_ADMISSION_SCHEMA.split(";") if statement.strip()],
    41: [
        "ALTER TABLE event_goal_admissions ADD COLUMN request_digest TEXT",
        "ALTER TABLE event_goal_admissions ADD COLUMN sealed_contract TEXT",
        "CREATE INDEX IF NOT EXISTS idx_event_admission_goal ON event_goal_admissions(goal_id)",
    ],
    # v11: per-goal owner principal for multi-user dashboard authz (owner-scoped
    # reads/mutations). Legacy goals get '' (treated as unowned -> admin-only).
    11: ["ALTER TABLE goals ADD COLUMN owner TEXT NOT NULL DEFAULT ''"],
    2: [
        "ALTER TABLE episodes ADD COLUMN cost_dollars REAL DEFAULT 0",
        "ALTER TABLE episodes ADD COLUMN input_tokens INTEGER DEFAULT 0",
        "ALTER TABLE episodes ADD COLUMN output_tokens INTEGER DEFAULT 0",
        "ALTER TABLE episodes ADD COLUMN tool_calls INTEGER DEFAULT 0",
    ],
    3: [],  # goal_events table is in SCHEMA (idempotent CREATE)
    4: [],  # conversations/turns tables are in SCHEMA (idempotent CREATE)
    5: [],  # attachments table is in SCHEMA (idempotent CREATE)
    6: [],  # processed_messages table is in SCHEMA (idempotent CREATE)
    # episodes.ended_at + goal_events.ts indexes.
    # list_episodes() does `ORDER BY ended_at DESC LIMIT N` which is a
    # full table scan without the index once a workspace holds thousands
    # of episodes (a large evaluation sweep easily does), which slows the
    # dashboard's recent-episodes query. prune_goal_events queries by
    # ts < cutoff.
    7: [
        "CREATE INDEX IF NOT EXISTS idx_episodes_ended_at "
        "ON episodes(ended_at)",
        "CREATE INDEX IF NOT EXISTS idx_goal_events_ts "
        "ON goal_events(ts)",
    ],
    # Schema v8: hot-query indexes identified via EXPLAIN QUERY PLAN.
    #
    # - list_episodes(goal_id=...) filters by goal_id then orders by
    #   started_at: needs idx_episodes_goal_started.
    # - list_episodes() (no goal filter) orders by started_at: full
    #   table scan was OK on small DBs, painful at 100k+ episodes.
    # - monitor.snapshot resolves the active goal by status + ORDER BY
    #   updated_at DESC LIMIT 1: covers via idx_goals_status_updated.
    # - cross_goal_memory.recall scans WHERE status IN (succeeded,
    #   done, failed) ORDER BY updated_at DESC LIMIT 500: covered by
    #   idx_goals_status_updated.
    # - parent_id filter for _fetch_subgoals: needs idx_goals_parent.
    8: [
        "CREATE INDEX IF NOT EXISTS idx_episodes_goal_started "
        "ON episodes(goal_id, started_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_episodes_started "
        "ON episodes(started_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_goals_status_updated "
        "ON goals(status, updated_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_goals_parent "
        "ON goals(parent_id, created_at)",
    ],
    # v9 approval queue: the approvals table + its status index are in
    # SCHEMA (idempotent CREATE). Listed here so existing DBs bump the
    # version and pick them up on next open, matching the goal_events /
    # conversations / attachments migration pattern above.
    9: [],
    # v10: backfill the messages_fts index. The FTS table + its triggers only
    # index FUTURE writes, so a DB whose messages predate the index (created
    # before messages_fts shipped) carried unindexed history that
    # search_messages() silently missed. Rebuild once on upgrade -- a cheap
    # no-op on a DB that's already fully indexed.
    10: ["INSERT INTO messages_fts(messages_fts) VALUES('rebuild')"],
    # v12: trusted approval provenance. Do not infer operator-visible source
    # labels from the free-form detail text, which can contain model-, user-,
    # or remote-server-controlled content.
    12: ["ALTER TABLE approvals ADD COLUMN provenance TEXT"],
    # v13 collaborative supervision: approval claiming (so two supervisors
    # don't double-handle the same pending approval) + decided_by attribution.
    13: [
        "ALTER TABLE approvals ADD COLUMN claimed_by TEXT",
        "ALTER TABLE approvals ADD COLUMN claimed_at REAL",
        "ALTER TABLE approvals ADD COLUMN decided_by TEXT",
    ],
    # v14 department attribution: the domain pack a goal ran as ('' = generic
    # orchestrator). Exact success-side attribution for the learning loops
    # (dreaming, role stats, budget priors) instead of lexical matching.
    14: ["ALTER TABLE goals ADD COLUMN domain TEXT NOT NULL DEFAULT ''"],
    # v15 automation provenance: the goal_origins table (which schedule/trigger
    # spawned a goal) is in SCHEMA (idempotent CREATE). Listed here so existing
    # DBs bump the version and pick it up on next open, matching the v9 pattern.
    15: [],
    # v16 deliverable sign-off: the signoffs table is in SCHEMA (idempotent
    # CREATE); listed here so existing DBs bump the version on next open.
    16: [],
    # v17 governed/temporal memory: provenance + trust tier on the live fact row
    # (Memory Guard), and the bitemporal fact_history table + its index (in SCHEMA
    # as idempotent CREATE) for non-destructive fact evolution. The ALTERs add the
    # provenance columns to existing DBs; legacy facts backfill to trust_tier=3
    # (first-party) so the guard never retroactively hides already-trusted memory.
    17: [
        "ALTER TABLE facts ADD COLUMN source TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE facts ADD COLUMN trust_tier INTEGER NOT NULL DEFAULT 3",
        "ALTER TABLE facts ADD COLUMN sensitivity TEXT NOT NULL DEFAULT 'internal'",
    ],
    # v18 artifacts: the artifacts table + its index are in SCHEMA (idempotent
    # CREATE); listed here so existing DBs bump the version on next open.
    18: [],
    # v19 projects ("matters"): the projects table is in SCHEMA (idempotent
    # CREATE); the ALTER adds the goals.project_id column to pre-existing DBs
    # (legacy goals default to NULL = unfiled). No index -- project filtering
    # scans like the owner/domain filters; goal counts are small.
    19: [
        "ALTER TABLE goals ADD COLUMN project_id INTEGER",
    ],
    # v20 share links: the share_links table is in SCHEMA (idempotent CREATE);
    # listed here so existing DBs bump the version on next open.
    20: [],
    # v21 N-of-M dual control: quorum + requester columns on approvals, and the
    # per-(approval, approver) signoff table (also in SCHEMA for fresh DBs).
    21: [
        "ALTER TABLE approvals ADD COLUMN approvals_required INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE approvals ADD COLUMN requested_by TEXT",
        "CREATE TABLE IF NOT EXISTS approval_signoffs ("
        " approval_id INTEGER NOT NULL, approver TEXT NOT NULL,"
        " decision TEXT NOT NULL, decided_at REAL NOT NULL, note TEXT,"
        " PRIMARY KEY (approval_id, approver))",
    ],
    # v22 cluster-wide killswitch: the halt table is in SCHEMA (idempotent
    # CREATE); listed here so existing DBs bump the version on next open.
    22: [],
    # v23 cluster-wide provider spend ledger: the provider_spend table is in
    # SCHEMA (idempotent CREATE); listed here so existing DBs bump the version.
    23: [],
    # v24 facts provenance columns (source/trust_tier/sensitivity): SQLite's base
    # CREATE and the v17 migration already carry these, so this is empty -- it
    # exists only to keep the SQLite head at v24 to match the Postgres ladder
    # (which adds the columns at v24). See migration_governance head-parity gate.
    24: [],
    # v25 fleet learning store: the harness_* tables are in SCHEMA (idempotent
    # CREATE, applied on every open); listed here so existing DBs bump the
    # version, matching the v9/v15/v22 pattern and the Postgres ladder.
    25: [],
    # v26 fleet learning store eval corpus: harness_corpus is in SCHEMA (idempotent
    # CREATE); listed here so existing DBs bump the version.
    26: [],
    # v27 cache-token spend columns: Budget breaks out cache_read/cache_write
    # tokens (priced at 0.1x / 1.25-2x) but the episode row dropped them, so
    # nothing persisted could answer "how much of this goal's input was cache
    # vs fresh" — the tokens-per-goal efficiency baseline needs both buckets.
    27: [
        "ALTER TABLE episodes ADD COLUMN cache_read_tokens INTEGER DEFAULT 0",
        "ALTER TABLE episodes ADD COLUMN cache_write_tokens INTEGER DEFAULT 0",
    ],
    # v28 Postgres adds goals.owner for SQLite owner-scoped episode parity.
    # SQLite has carried this column since v11, so its matching head is a no-op.
    28: [],
    # v29 immutable, privacy-minimized erasure receipts. The signed manifest
    # contains random receipt identity plus exact pre-delete row IDs, but no
    # channel/user value or subject-derived hash. A trigger prevents updates;
    # rows may only be inserted or retired after their signed retention date.
    29: [
        "CREATE TABLE IF NOT EXISTS erasure_receipts ("
        " receipt_id TEXT PRIMARY KEY,"
        " tenant_id TEXT NOT NULL,"
        " manifest TEXT NOT NULL,"
        " created_at REAL NOT NULL,"
        " retained_until REAL NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_erasure_receipts_retention "
        "ON erasure_receipts(retained_until)",
        "CREATE TRIGGER IF NOT EXISTS erasure_receipts_no_update "
        "BEFORE UPDATE ON erasure_receipts BEGIN "
        "SELECT RAISE(ABORT, 'erasure receipts are immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS erasure_receipts_no_early_delete "
        "BEFORE DELETE ON erasure_receipts "
        "WHEN OLD.retained_until > CAST(strftime('%s', 'now') AS REAL) BEGIN "
        "SELECT RAISE(ABORT, 'erasure receipt retention is active'); END",
    ],
    # v30 approval/audit atomicity: a dashboard vote and its stable audit
    # delivery intent commit together.  The approval remains pending until
    # every queued vote is durably appended to the signed audit chain.
    30: [
        "CREATE TABLE IF NOT EXISTS approval_audit_outbox ("
        " event_id TEXT PRIMARY KEY,"
        " approval_id INTEGER NOT NULL,"
        " status TEXT NOT NULL,"
        " decided_by TEXT NOT NULL,"
        " final_status TEXT,"
        " created_at REAL NOT NULL,"
        " delivered_at REAL)",
        "CREATE INDEX IF NOT EXISTS idx_approval_audit_outbox_pending "
        "ON approval_audit_outbox(delivered_at, approval_id)",
    ],
    # v31 Postgres introduces a dedicated BIGSERIAL fact write clock. SQLite's
    # INTEGER PRIMARY KEY ``facts.id`` already serves as its 64-bit logical
    # write clock and advances on every upsert, so its matching migration is a
    # no-op that keeps the governed backend ladders at the same release head.
    31: [],
    # v32 separates human/resource ownership from execution authority. This
    # lets delegated fleet work remain owner-visible while the exact runtime
    # capability principal is still durably bound before execution.
    32: [
        "ALTER TABLE goals ADD COLUMN execution_principal "
        "TEXT NOT NULL DEFAULT ''",
    ],
    # v33 HALT generation: a clear is a compare-and-delete against the exact
    # shared stop it observed.  A concurrent arm publishes a fresh random token
    # and therefore cannot be erased by an older clear request.
    33: [
        "ALTER TABLE halt ADD COLUMN generation TEXT NOT NULL DEFAULT ''",
    ],
    # v34 durable provider admission receipts share the spend transaction.
    34: [
        "CREATE TABLE IF NOT EXISTS provider_cap_receipts ("
        " period_key TEXT NOT NULL, provider TEXT NOT NULL,"
        " receipts_json TEXT NOT NULL, PRIMARY KEY (period_key, provider))",
    ],
    # v35 prevents crash/replay from admitting the same physical provider
    # operation attempt through another provider or accounting period.
    35: [
        "CREATE TABLE IF NOT EXISTS provider_operation_attempts ("
        " scope_sha256 TEXT NOT NULL, operation_id TEXT NOT NULL,"
        " attempt_no INTEGER NOT NULL, category TEXT NOT NULL,"
        " parent_category TEXT NOT NULL, service TEXT, provider TEXT NOT NULL,"
        " period_key TEXT NOT NULL, request_id TEXT NOT NULL,"
        " PRIMARY KEY (scope_sha256, operation_id, attempt_no),"
        " UNIQUE (provider, period_key, request_id))",
        "CREATE TABLE IF NOT EXISTS provider_operation_attempt_backfill ("
        " singleton INTEGER PRIMARY KEY CHECK(singleton = 1),"
        " completed INTEGER NOT NULL CHECK(completed = 1))",
    ],
    # v36: recorded completion time and exact approval routing. Legacy rows
    # remain unknown instead of fabricating historical SLA/department data.
    36: [
        "ALTER TABLE goals ADD COLUMN completed_at REAL",
        "ALTER TABLE approvals ADD COLUMN goal_id INTEGER",
        "ALTER TABLE approvals ADD COLUMN department TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_goals_domain_completed ON goals(domain, completed_at)",
    ],
    37: [
        "CREATE INDEX IF NOT EXISTS idx_goals_root_owner ON goals(owner, id DESC) WHERE parent_id IS NULL",
        "CREATE INDEX IF NOT EXISTS idx_goals_root_id ON goals(id DESC) WHERE parent_id IS NULL",
    ],
    38: [_ATTACHMENT_SUBMISSION_SCHEMA],
    # PostgreSQL v39 scopes learning keys by tenant; SQLite files already do.
    39: [],
}










def _approval_audit_event_id(
    tenant_id: str | None,
    approval_id: int,
    status: str,
    decided_by: str,
    undo_round: int = 0,
) -> str:
    """Stable, unambiguous id for retrying one supervisor's exact vote.

    ``undo_round`` counts how many times the approval was undone: a vote
    cast after an undo is a new decision and gets a new identity, so the
    signed audit chain records it instead of treating it as a replay of the
    retracted vote. Round 0 keeps the historical id.
    """
    parts = [
        (tenant_id or "").encode("utf-8"),
        str(int(approval_id)).encode("ascii"),
        status.encode("ascii"),
        decided_by.encode("utf-8"),
    ]
    if int(undo_round) > 0:
        parts.append(f"undo-round:{int(undo_round)}".encode("ascii"))
    framed = b"".join(len(part).to_bytes(4, "big") + part for part in parts)
    return "approval-v1-" + hashlib.sha256(framed).hexdigest()


APPROVAL_UNDO_STATUS = "undone"
# ``approvals.undo_hold``: a waiting task holds the decision for undo, or has acted on it.
APPROVAL_UNDO_OPEN = "open"
APPROVAL_UNDO_SETTLED = "settled"


def approval_held_open(approval: Any) -> bool:
    """A request a waiting task holds open for undo (not yet settled)."""
    return getattr(approval, "undo_hold", None) == APPROVAL_UNDO_OPEN


def approval_undo_refusal(status: str, decided_by: str | None, undo_hold: str | None) -> str | None:
    """Why a decided approval cannot be undone, or None when it still can be.

    ``"final"``: no waiting task holds it (its consumer acts on the decision
    at once) or the system decided it (a stopped task, a timed-out wait, a
    recovery); ``"too_late"``: the waiting task has already acted on it.
    """
    if status == "pending":
        return None
    if str(decided_by or "").startswith("system:"):
        return "final"
    if undo_hold == APPROVAL_UNDO_SETTLED:
        return "too_late"
    if undo_hold != APPROVAL_UNDO_OPEN:
        return "final"
    return None


def _approval_undo_marker_id(tenant_id: str | None, approval_id: int, undo_round: int) -> str:
    """Outbox row id for one undo of an approval (never delivered; a counter)."""
    return _approval_audit_event_id(tenant_id, approval_id, APPROVAL_UNDO_STATUS, "", undo_round)


_EPISODE_SPEND_COLS = (
    "e.id, e.goal_id, e.started_at, e.ended_at, e.outcome, "
    "COALESCE(e.cost_dollars, 0) AS cost_dollars, "
    "COALESCE(e.input_tokens, 0) AS input_tokens, "
    "COALESCE(e.output_tokens, 0) AS output_tokens, "
    "COALESCE(e.tool_calls, 0) AS tool_calls, "
    "COALESCE(e.cache_read_tokens, 0) AS cache_read_tokens, "
    "COALESCE(e.cache_write_tokens, 0) AS cache_write_tokens "
)














def _temporal_memory_enabled() -> bool:
    """Whether to keep a bitemporal ``fact_history`` (validity windows) on every
    fact change. OFF by default -- the live-value path is byte-identical when off
    (upsert overwrites, no history rows). Turn on with ``MAVERICK_TEMPORAL_MEMORY=1``
    or ``[memory] temporal = true`` for non-destructive fact evolution and
    ``get_fact(..., as_of=...)`` / ``fact_history(...)`` queries."""
    if (os.environ.get("MAVERICK_TEMPORAL_MEMORY") or "").strip().lower() in {
        "1", "true", "yes", "on",
    }:
        return True
    try:
        from .config import load_config
        return bool(load_config().get("memory", {}).get("temporal", False))
    except Exception:  # pragma: no cover -- config never blocks a write
        return False


def _enc_field(text: str | None) -> str | None:
    """Seal a sensitive text field for storage when at-rest encryption is on.

    Fail-closed: if encryption is enabled but the crypto backend is missing,
    this raises (via ``seal_to_str``) rather than silently storing plaintext.
    Returns the value unchanged when encryption is off (and for ``None``)."""
    if text is None:
        return text
    from .crypto_at_rest import at_rest_enabled, seal_to_str
    return seal_to_str(text) if at_rest_enabled() else text


# Returned in strict mode when a sealed column holds an unsealed value (legacy
# plaintext that wasn't migrated, or tampering) -- never the real plaintext.
_UNSEALED_WITHHELD = "‹withheld: unsealed value in an encrypted store›"


def _refuse_withheld_placeholder(value: str) -> None:
    """Never seal the read-side placeholder over the value it stands in for."""
    if value == _UNSEALED_WITHHELD:
        raise ValueError(
            "This fact's saved value cannot be read yet, so it was left unchanged. "
            "Run 'maverick encryption migrate', then try again."
        )


def _dec_field(text: str | None, *, at_rest: bool | None = None) -> str | None:
    """Unseal a stored field from a sealed column when at-rest encryption is on.

    ``at_rest`` lets a caller that already resolved :func:`at_rest_enabled`
    for a whole result set pass it down: the policy check walks the compliance
    profile configuration each time (~90 us), and a 200-row page read it 400
    times.

    When encryption is disabled, fields are raw plaintext (which may legitimately
    begin with the public seal marker), so they pass through untouched.

    When encryption is on but the stored value is NOT sealed, it is either
    pre-migration legacy plaintext or tampering. By default it is passed through
    (so a not-yet-migrated store stays readable) with a warning; under
    :func:`strict_at_rest` it is withheld and logged as an integrity failure --
    closing the read-side plaintext-passthrough hole.
    """
    if text is None:
        return text
    from .crypto_at_rest import (
        at_rest_enabled,
        is_sealed_str,
        strict_at_rest,
        unseal_from_str,
    )
    if at_rest is None:
        at_rest = at_rest_enabled()
    if not at_rest:
        return text
    if is_sealed_str(text):
        return unseal_from_str(text)
    if strict_at_rest():
        log.error("at-rest strict: withholding an unsealed value in a sealed column "
                  "(run 'maverick encryption migrate'; tampering if already migrated)")
        return _UNSEALED_WITHHELD
    log.warning("at-rest: unsealed value in a sealed column (pre-migration legacy or "
                "tampering); run 'maverick encryption migrate'")
    return text


def _dec_fields(texts: list[str | None]) -> list[str | None]:
    """Decrypt a result set with one policy and key lookup per query."""
    from .crypto_at_rest import (
        at_rest_enabled,
        is_sealed_str,
        strict_at_rest,
        unseal_many_from_str,
    )

    if not at_rest_enabled():
        return list(texts)
    present = [text for text in texts if text is not None]
    decoded_present = unseal_many_from_str(present)
    strict = (
        strict_at_rest()
        if any(not is_sealed_str(text) for text in present)
        else False
    )
    decoded_iter = iter(decoded_present)
    out: list[str | None] = []
    for text in texts:
        if text is None:
            out.append(None)
            continue
        decoded = next(decoded_iter)
        if not is_sealed_str(text):
            if strict:
                log.error(
                    "at-rest strict: withholding an unsealed value in a sealed "
                    "column (run 'maverick encryption migrate'; tampering if "
                    "already migrated)"
                )
                decoded = _UNSEALED_WITHHELD
            else:
                log.warning(
                    "at-rest: unsealed value in a sealed column (pre-migration "
                    "legacy or tampering); run 'maverick encryption migrate'"
                )
        out.append(decoded)
    return out


def _row_for(cls, d: dict) -> dict:
    """Keep only the keys that ``cls`` (a dataclass) declares.

    A live ``world.db`` can carry columns written by a different schema
    version -- e.g. a build that added a ``domain`` column to ``goals``.
    ``cls(**dict(row))`` would then raise ``TypeError`` on that unknown column
    and 500 every page that lists the table. Dropping unmodelled columns keeps
    reads tolerant of schema skew in both directions.
    """
    allowed = {f.name for f in fields(cls)}
    return {k: v for k, v in d.items() if k in allowed}


def _question_from_row(row) -> Question:
    """Build a Question from a row, decrypting the sealed question/answer fields."""
    d = dict(row)
    d["question"] = _dec_field(d.get("question"))
    d["answer"] = _dec_field(d.get("answer"))
    return Question(**_row_for(Question, d))


def _goal_from_row(row, *, at_rest: bool | None = None) -> Goal:
    """Build a Goal from a row, decrypting the sealed content fields."""
    from .crypto_at_rest import at_rest_enabled

    if at_rest is None:
        at_rest = at_rest_enabled()
    d = dict(row)
    d["title"] = _dec_field(d.get("title"), at_rest=at_rest)
    d["description"] = _dec_field(d.get("description"), at_rest=at_rest)
    if "result" in d:
        d["result"] = _dec_field(d.get("result"), at_rest=at_rest)
    return Goal(**_row_for(Goal, d))


def _goals_from_rows(rows) -> list[Goal]:
    """Build Goals from a result set with one at-rest policy and key lookup
    per query (rather than loading the key again for each sealed field)."""
    records = [dict(row) for row in rows]
    texts: list[str | None] = []
    for d in records:
        texts += [d.get("title"), d.get("description")]
        if "result" in d:
            texts.append(d["result"])
    decoded = iter(_dec_fields(texts))
    for d in records:
        d["title"] = next(decoded)
        d["description"] = next(decoded)
        if "result" in d:
            d["result"] = next(decoded)
    return [Goal(**_row_for(Goal, d)) for d in records]


def goals_by_id(world: GoalLookup, goal_ids: Iterable[int]) -> dict[int, GoalRecord]:
    """``{id: goal}`` for the ids that exist, in one read when the world can
    (:meth:`WorldModel.get_goals`), else one :meth:`get_goal` per id."""
    batch = getattr(world, "get_goals", None)
    if callable(batch):
        return batch(goal_ids)
    found: dict[int, GoalRecord] = {}
    for goal_id in dict.fromkeys(goal_ids):
        goal = world.get_goal(goal_id)
        if goal is not None:
            found[goal_id] = goal
    return found


def episodes_by_goal_batch(world, goal_ids, *, per_goal: int) -> dict | None:
    """``{goal_id: newest per_goal runs}`` in one read when the world can batch
    (:meth:`WorldModel.episodes_by_goal`). ``None`` when it cannot, or when the
    batch read fails, so the caller reads goal by goal as it did before."""
    batch = getattr(world, "episodes_by_goal", None)
    if not callable(batch):
        return None
    try:
        return batch(goal_ids, per_goal=per_goal)
    except Exception:
        return None


def _goal_events_from_rows(rows: list) -> list[GoalEvent]:
    """Build goal events while resolving encryption policy and keys once."""
    decoded = _dec_fields([row["content"] for row in rows])
    events: list[GoalEvent] = []
    for row, content in zip(rows, decoded, strict=True):
        d = dict(row)
        d["content"] = content
        events.append(GoalEvent(**_row_for(GoalEvent, d)))
    return events


def _episode_spends_from_rows(rows: list) -> list[EpisodeSpend]:
    """Build run-cost episodes, decrypting the sealed outcome field, while
    resolving encryption policy and keys once."""
    records = [dict(row) for row in rows]
    decoded = iter(_dec_fields([d.get("outcome") for d in records if "outcome" in d]))
    for d in records:
        if "outcome" in d:
            d["outcome"] = next(decoded)
    return [EpisodeSpend(**_row_for(EpisodeSpend, d)) for d in records]


def _notify_approval_created(world, approval_id: int, provenance: str | None) -> None:
    """Best-effort chat notification (Slack and Teams approval cards); never
    raises. Called once, after the approval row is committed."""
    try:
        from .approval_notify import approval_created

        approval_created(int(approval_id), provenance=provenance, world=world)
    except Exception:  # noqa: BLE001 -- the queue row is already durable
        logging.getLogger(__name__).warning("approval notification failed", exc_info=True)


def _approval_from_row(row) -> Approval:
    """Build an Approval from a row, decrypting the sealed action/scope/detail."""
    d = dict(row)
    d["action"] = _dec_field(d.get("action"))
    d["scope"] = _dec_field(d.get("scope"))
    d["detail"] = _dec_field(d.get("detail"))
    return Approval(**_row_for(Approval, d))


def _approvals_from_rows(rows: list) -> list[Approval]:
    """Build approvals while resolving encryption policy and keys once.

    Decoding each row on its own checked the policy (the compliance profile
    configuration) and loaded the key for every sealed field: listing 500
    approvals took 250-450 ms.
    """
    sealed = ("action", "scope", "detail")
    records = [dict(row) for row in rows]
    decoded = iter(_dec_fields([d.get(name) for d in records for name in sealed]))
    for d in records:
        for name in sealed:
            d[name] = next(decoded)
    return [Approval(**_row_for(Approval, d)) for d in records]


def _single_approver(approval, approvers: list[str]) -> list[str]:
    """A one-approver request keeps no sign-off rows: its approver is the decider."""
    if (
        not approvers
        and approval.status == "approved"
        and max(1, int(approval.approvals_required or 1)) <= 1
        and approval.decided_by
    ):
        return [approval.decided_by]
    return approvers


def _approval_state_view(approval, approvers: list[str], audit_pending: int) -> dict:
    """The operator/UI quorum view of one approval (shared by the per-id and
    the batched readers so both return the same shape and values)."""
    return {
        "status": approval.status,
        "approvals_required": max(1, int(approval.approvals_required or 1)),
        "approved_count": len(approvers),
        "approvers": approvers,
        "requested_by": approval.requested_by,
        "audit_pending_count": audit_pending,
        "effective": approval.status != "pending",
    }


def _approval_audit_event_from_row(row) -> ApprovalAuditEvent:
    return ApprovalAuditEvent(**_row_for(ApprovalAuditEvent, dict(row)))


def default_db_path() -> Path:
    """Return the active tenant's world path unless explicitly overridden.

    While practice mode is on (:mod:`maverick.practice`), the practice world
    beside it, so practised tasks never mix with real records."""
    from . import practice

    if DEFAULT_DB is not _INITIAL_DEFAULT_DB:
        override = Path(DEFAULT_DB).expanduser()
        if practice.active():
            return override.with_name(override.stem + ".practice" + override.suffix)
        return override
    tenant = current_tenant_id()
    if practice.active():
        return practice.world_path(bind_tenant_namespace(tenant) if tenant else None)
    if tenant:
        tenant = bind_tenant_namespace(tenant)
        return data_dir("world.db", tenant=tenant)
    return data_dir("world.db", tenant=None)


def _resolve_world_path(path: Path | str | None) -> tuple[Path, bool]:
    if path is None:
        # The built-in dynamic path is Lightwork-owned. A replaced DEFAULT_DB
        # is a public embedder/operator override and therefore caller-owned: it
        # must already have a private parent, never have its ACL seized.
        return default_db_path(), DEFAULT_DB is _INITIAL_DEFAULT_DB
    return Path(path), False


class WorldSchemaCompatibilityError(RuntimeError):
    """The installed release cannot safely open this persisted world."""

    def __init__(self, message: str, *, code: str):
        super().__init__(message)
        self.code = code


def _existing_world_has_data(path: Path) -> bool:
    try:
        return str(path) != ":memory:" and path.exists() and path.stat().st_size > 0
    except OSError:  # pragma: no cover -- stat race; assume fresh
        return False


def _check_world_schema_compatibility(path: Path) -> None:
    """Admit existing worlds read-only, including committed WAL state.

    Called under the existing cross-process initialization lock and before
    opening a writable connection, journal-mode changes or schema bootstrap.
    Do not use immutable=1: it ignores committed versions still in a WAL.
    Missing/empty version tables retain the supported legacy-v1 reader policy.
    """
    invalid = (
        "World database schema metadata is invalid or ambiguous. "
        "Restore a compatible backup or open it with the release that created it; "
        "the database has not been migrated."
    )
    try:
        with contextlib.closing(sqlite3.connect(
            path.resolve().as_uri() + "?mode=ro", uri=True, timeout=10.0,
        )) as conn:
            table = conn.execute(
                "SELECT type FROM sqlite_master WHERE name='schema_version' COLLATE NOCASE",
            ).fetchone()
            if table is None:
                return
            if table[0] != "table":
                raise WorldSchemaCompatibilityError(invalid, code="invalid_world_schema")
            rows = conn.execute("SELECT version FROM schema_version LIMIT 2").fetchall()
    except sqlite3.DatabaseError as exc:
        raise WorldSchemaCompatibilityError(invalid, code="invalid_world_schema") from exc
    if not rows:
        return
    if len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] < 1:
        raise WorldSchemaCompatibilityError(invalid, code="invalid_world_schema")
    current = rows[0][0]
    if current > SCHEMA_VERSION:
        raise WorldSchemaCompatibilityError(
            f"World database uses schema {current}; this release supports up to {SCHEMA_VERSION}. "
            "Install a newer Lightwork release that supports this schema or restore a compatible backup; "
            "the database has not been migrated.",
            code="unsupported_world_schema",
        )


def _serialize_world_initialization(init):
    """Serialize one world's open/WAL/schema bootstrap across processes.

    SQLite's Windows VFS can surface ``SQLITE_READONLY`` when several fresh
    connections race file publication, WAL activation, and schema creation.
    Busy timeouts do not cover that state.  The durable per-world lock also
    keeps permission verification and migrations in the same admission
    transaction; it is released on every constructor exception.  In-memory
    worlds remain independent and never touch the filesystem lock.
    """
    @functools.wraps(init)
    def guarded(self, path: Path | str | None = None, *, _managed_path: bool = False):
        resolved, _ = _resolve_world_path(path)
        if str(resolved) == ":memory:":
            return init(self, path, _managed_path=_managed_path)
        with cross_process_lock(resolved, strict=True):
            return init(self, path, _managed_path=_managed_path)

    return guarded


class WorldModel:
    @_serialize_world_initialization
    def __init__(
        self,
        path: Path | str | None = None,
        *,
        _managed_path: bool = False,
    ):
        from .paths import current_tenant_id_strict
        self._event_admission_tenant = current_tenant_id_strict()
        path, default_managed = _resolve_world_path(path)
        _managed_path = _managed_path or default_managed
        self.path = path
        # Whether this DB already held data before we opened it. Captured BEFORE
        # any file creation below so a brand-new world.db (every fresh
        # install/tenant) is not mistaken for a legacy DB needing a
        # pre-migration backup -- only a pre-existing, non-empty DB gets one.
        self._db_preexisted = _existing_world_has_data(path)
        if self._db_preexisted:
            _check_world_schema_compatibility(path)
        # world.db holds all conversation content, messages, and facts.
        # The audit dir is locked to 0700/0600 but this DB inherited the
        # default umask (often world-readable 0644) — any local user or
        # backup could read everyone's data. Lock the dir + the file.
        if str(path) != ":memory:":
            # Tenant/home context is deliberately resolved at request time.
            # Treat the current managed default as Lightwork-owned and let the
            # tenant factory explicitly mark its paths.  A genuinely
            # caller-supplied parent still goes through
            # ``prepare_private_directory`` so we never seize its ACLs.
            current_default = data_dir("world.db")
            if _managed_path or path == current_default:
                ensure_private_directory(path.parent)
            else:
                prepare_private_directory(path.parent)
        # check_same_thread=False so FastAPI threadpool can share. Combined
        # with WAL + busy_timeout this is safe for the agent+dashboard
        # concurrency pattern (one writer process + many readers).
        #
        # ``check_same_thread=False`` alone
        # is insufficient. Two threadpool workers driving execute()+commit()
        # on the same connection can interleave: thread A opens an implicit
        # transaction with INSERT, thread B's INSERT joins the same
        # transaction, A's commit() flushes both rows, B's commit() is a
        # no-op. If A had raised between execute() and commit() and called
        # rollback(), B's "successful" insert would silently roll back too.
        # The RLock + ``_writing()`` context manager serialises every
        # mutation so each commit() bounds exactly one logical write.
        self._write_lock = threading.RLock()
        self._write_depth = 0
        # Goals whose stored state this transaction changed; their in-process
        # watchers (the chat page's event stream) are woken after it commits.
        self._changed_goals: set[int] = set()
        # Per-thread READ connections: WAL gives each its own connection a
        # consistent committed snapshot, so reads run concurrently with the one
        # writer instead of serialising on the write lock (WAL's many-readers
        # benefit exists only ACROSS connections). The writer thread's own reads
        # must still go through the write connection to see its uncommitted data
        # mid-transaction, tracked by _writer_ident.
        self._is_memory = str(path) == ":memory:"
        self._readers = threading.local()
        # Keyed by thread ident (not a plain list) so a dead thread's
        # connection can be pruned instead of retained for the WorldModel's
        # entire lifetime -- see _prune_dead_reader_conns_locked.
        self._reader_conns: dict[int, sqlite3.Connection] = {}
        self._reader_conns_lock = threading.Lock()
        self._writer_ident: int | None = None
        # Create the DB file 0o600 BEFORE sqlite opens it: connect() would
        # otherwise create it at the umask (often 0644) for a window before the
        # chmod below, briefly exposing all conversation content to co-tenants.
        if str(path) != ":memory:" and not path.exists():
            try:
                atomic_create_bytes(path, b"")
            except FileExistsError:
                # Another opener won the exclusive publication race.
                ensure_private_file(path)
        elif str(path) != ":memory:":
            ensure_private_file(path)
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=10.0)
        if str(path) != ":memory:":
            ensure_private_file(path)
        self.conn.row_factory = sqlite3.Row
        # Arm a short busy handler BEFORE switching journal mode: switching to
        # WAL needs a brief exclusive lock, and when a second connection opens
        # the same DB concurrently (the dashboard and the agent each open one)
        # the switch can surface "database is locked" instead of waiting unless
        # busy_timeout is already set. Keep this timeout small because it is
        # paid on every retry below; restore the normal write timeout after WAL
        # is enabled.
        self.conn.execute(f"PRAGMA busy_timeout = {WAL_SWITCH_BUSY_TIMEOUT_MS}")
        # WAL must be set before any other operation that creates pages. The
        # switch can still race a same-process connection -- SQLITE_LOCKED
        # bypasses the busy handler -- so retry briefly (<=5s) on a locked DB.
        deadline = time.monotonic() + WAL_SWITCH_RETRY_SECONDS
        while True:
            try:
                self.conn.execute("PRAGMA journal_mode = WAL")
                break
            except sqlite3.OperationalError as e:
                if "locked" not in str(e).lower():
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(0.05, remaining))
        self.conn.execute(f"PRAGMA busy_timeout = {DEFAULT_BUSY_TIMEOUT_MS}")
        # WAL/SHM sidecars hold uncommitted conversation content; lock them to
        # 0o600 too (best-effort -- they may not exist until the first write,
        # so this is re-attempted; the 0o700 parent dir covers the gap).
        if str(path) != ":memory:":
            for _suffix in ("-wal", "-shm"):
                try:
                    ensure_private_file(path.parent / (path.name + _suffix))
                except FileNotFoundError:
                    pass
        # synchronous=NORMAL under WAL is safe (no corruption) + much faster
        # than FULL, but a commit acked to the orchestrator can still be lost on
        # an OS crash / power loss before the next checkpoint. A regulated
        # deployment that treats the world DB as the billed Operating Record can
        # opt into FULL (durable on every commit) via [world_model] synchronous
        # / MAVERICK_WORLD_SYNCHRONOUS. Default NORMAL — behaviour unchanged.
        self.conn.execute(f"PRAGMA synchronous = {_synchronous_mode()}")
        # Bound WAL file
        # growth. Default autocheckpoint=1000 pages is fine, but with
        # a dashboard reader holding a snapshot lock, autocheckpoint
        # can stall and the WAL file grows monotonically. Explicit
        # pragma surfaces the setting + makes intent clear.
        self.conn.execute("PRAGMA wal_autocheckpoint = 1000")
        # SQLite default is foreign_keys=OFF; without this, every
        # `REFERENCES goals(id)` clause is decorative and a delete can
        # orphan turns/attachments/episodes silently.
        self.conn.execute("PRAGMA foreign_keys = ON")
        # The schema-setup writes (executescript + version row + migrations) can
        # surface SQLITE_LOCKED -- not SQLITE_BUSY -- when many connections in
        # the SAME process first-open a fresh DB simultaneously; the
        # busy_timeout handler doesn't cover SQLITE_LOCKED (same reason the WAL
        # switch above needs its own retry). The version-row insert is already
        # race-safe (atomic insert-if-empty in _init_schema_version), but
        # executescript/migrations can still lose the lock race -- observed in
        # CI as an intermittent "database is locked" on concurrent first-open.
        # The whole block is idempotent (CREATE TABLE IF NOT EXISTS, the
        # empty-table version insert, re-runnable migrations), so retry it
        # briefly on a transient lock.
        deadline = time.monotonic() + WAL_SWITCH_RETRY_SECONDS
        while True:
            try:
                self.conn.executescript(_bootstrap_schema(self.conn))
                self._init_schema_version()
                self._apply_migrations()
                self.conn.commit()
                break
            except sqlite3.OperationalError as e:
                if "locked" not in str(e).lower():
                    raise
                try:
                    self.conn.rollback()
                except sqlite3.Error:
                    pass
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(0.05, remaining))
        # [memory] temporal is read ONCE at open, not per write: upsert_fact /
        # delete_fact are on the hot path and load_config() is uncached file
        # I/O. A config toggle takes effect on the next WorldModel open.
        self._temporal_memory = _temporal_memory_enabled()

    @contextlib.contextmanager
    def _writing(self) -> Iterator[sqlite3.Connection]:
        """Acquire the write lock, yield the connection, commit on clean exit.

        Use this around every INSERT/UPDATE/DELETE sequence. If the body
        raises, outermost scope rolls back so the next caller sees a
        consistent state. Re-entrant via RLock so methods that compose
        other mutators don't self-deadlock; nested scopes share one
        transaction and only the outermost scope commits/rolls back.
        """
        with self._write_lock:
            is_outermost = self._write_depth == 0
            if is_outermost:
                self._writer_ident = threading.get_ident()
            self._write_depth += 1
            try:
                yield self.conn
                if is_outermost:
                    self.conn.commit()
                    self._wake_changed_goals()
            except Exception:
                if is_outermost:
                    self.conn.rollback()
                    self.__dict__.pop("_changed_goals", None)
                raise
            finally:
                self._write_depth -= 1
                if self._write_depth == 0:
                    self._writer_ident = None

    def _goal_changed(self, goal_id: int) -> None:
        """Note, inside a write, that a watched goal's stored state changes."""
        self.__dict__.setdefault("_changed_goals", set()).add(int(goal_id))

    def _wake_changed_goals(self) -> None:
        """After the commit: wake in-process watchers. Never raises (the write
        already succeeded); a missed wake only leaves a watcher on its timer."""
        changed = self.__dict__.pop("_changed_goals", None)
        if not changed or getattr(self, "_is_memory", True):
            return
        try:
            from .goal_wakeup import notify, watching, world_key

            if not watching():
                return
            world = world_key(self.path)
            for goal_id in changed:
                notify(world, goal_id)
        except Exception:  # noqa: BLE001
            log.debug("goal wake-up skipped", exc_info=True)

    def _prune_dead_reader_conns_locked(self) -> None:
        """Close and drop reader connections whose owning thread has exited.

        Caller must hold ``_reader_conns_lock``. ``threading.local()`` itself
        already frees a dead thread's *slot*, but the strong reference kept
        here (so :meth:`close` can reclaim every connection at shutdown) would
        otherwise retain the connection -- and its WAL/SHM file descriptors --
        for the WorldModel's entire lifetime. A dashboard's WorldModel is
        process-cached for the life of the server while ASGI worker threads
        come and go (an idle anyio worker thread exits after ~10s), so an
        unpruned list grows by one leaked connection and two leaked fds per
        short-lived thread that ever reads -- a slow walk toward EMFILE.
        """
        alive = {t.ident for t in threading.enumerate()}
        for ident in [i for i in self._reader_conns if i not in alive]:
            try:
                self._reader_conns.pop(ident).close()
            except Exception:  # pragma: no cover
                pass

    def _reader(self) -> sqlite3.Connection | None:
        """A per-thread read-only connection, or ``None`` when reads must use the
        shared write connection: a ``:memory:`` DB (which is per-connection, so a
        second connection would be an empty database), or a read issued by the
        thread that currently holds an open write transaction (it must see its
        own uncommitted rows). Otherwise a WAL reader connection that sees the
        latest committed snapshot, lock-free and concurrent with the writer."""
        if self._is_memory or self._writer_ident == threading.get_ident():
            return None
        conn = getattr(self._readers, "conn", None)
        if conn is None:
            # isolation_level=None (autocommit): each SELECT is its own
            # transaction, so the reader always sees the newest commit and never
            # pins a stale snapshot or holds back a WAL checkpoint. WAL mode is a
            # persistent DB property, so a fresh connection is already in WAL.
            conn = sqlite3.connect(self.path, check_same_thread=False,
                                   timeout=10.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute(f"PRAGMA busy_timeout = {DEFAULT_BUSY_TIMEOUT_MS}")
            self._readers.conn = conn
            with self._reader_conns_lock:
                self._prune_dead_reader_conns_locked()
                self._reader_conns[threading.get_ident()] = conn
        return conn

    def _read_all(self, sql: str, params: tuple[Any, ...] = ()) -> list:
        """Eagerly fetch all rows. Uses a per-thread WAL reader connection so
        reads run concurrently with the writer; falls back to the shared
        connection under the write lock for ``:memory:`` and writer-thread reads
        (see :meth:`_reader`)."""
        conn = self._reader()
        if conn is None:
            with self._write_lock:
                return self.conn.execute(sql, params).fetchall()
        return conn.execute(sql, params).fetchall()

    def _read_one(self, sql: str, params: tuple[Any, ...] = ()):
        """Single-row counterpart to :meth:`_read_all`."""
        conn = self._reader()
        if conn is None:
            with self._write_lock:
                return self.conn.execute(sql, params).fetchone()
        return conn.execute(sql, params).fetchone()

    def close(self) -> None:
        """Close the underlying SQLite connection.

        Benchmark runs construct ~1865
        WorldModel instances in one process; without close() the
        FD count climbs and the host eventually OOMs.

        Checkpoint + truncate
        the WAL on close so the sidecar file doesn't persist into the
        next instance's open. Best-effort; close still runs even if
        checkpoint fails.
        """
        with self._reader_conns_lock:
            readers, self._reader_conns = list(self._reader_conns.values()), {}
        for rconn in readers:
            try:
                rconn.close()
            except Exception:  # pragma: no cover
                pass
        try:
            try:
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass
            self.conn.close()
        except Exception:  # pragma: no cover
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def reclaim_orphan_goals(
        self, *, max_age_seconds: float = 60.0,
        statuses: tuple[str, ...] = ("active", "pending"),
        resolved_window_seconds: float | None = None,
    ) -> int:
        """Mark goals stuck in 'active' or 'pending' as 'blocked'.

        Called on startup to recover from SIGKILL / OOM / crash mid-run.
        Without this, a process death between create_goal() and
        set_goal_status('done'/'blocked') leaves the row 'active' forever
        and `active_goal()` returns a ghost.

        The previous default was 0,
        which reclaimed every active row -- including goals running in
        a sibling process (dashboard restarting while `maverick serve`
        is mid-goal would flip the live goal to 'blocked'). Default now
        is 60 seconds: only reclaim goals whose `updated_at` is at
        least a minute stale. Live goals re-touch updated_at via
        set_goal_status('active') and via the runner's status writes,
        so any goal currently being driven won't qualify. Multi-process
        deployments with very slow turns can raise this via
        ``MAVERICK_ORPHAN_RECLAIM_SECONDS``.

        A resolved window of zero explicitly reclaims every active/pending
        goal, even when its monotonic review timestamp is ahead of the wall
        clock. Positive windows continue to require the full stale interval.

        A periodic sweep passes only ``("active",)``; queued ``pending`` goals
        may legitimately wait longer than the stale window.

        Returns rows reclaimed.
        """
        statuses = tuple(statuses)
        if not statuses or not set(statuses) <= {"active", "pending"}:
            raise ValueError("orphan reclaim statuses must be active and/or pending")
        marks = ", ".join("?" for _ in statuses)
        max_age_seconds = (reclaim_window_seconds(default=max_age_seconds)
                           if resolved_window_seconds is None else float(resolved_window_seconds))
        if not math.isfinite(max_age_seconds) or max_age_seconds < 0:
            raise ValueError("orphan reclaim window must be nonnegative and finite")
        cutoff = time.time() - max_age_seconds
        now = time.time()
        marker = " [process restarted mid-run]"
        from .crypto_at_rest import at_rest_enabled
        with self._writing() as conn:
            if not at_rest_enabled():
                cur = conn.execute(
                    "UPDATE goals SET status = 'blocked', "
                    "result = COALESCE(result, '') || ?, "
                    "updated_at = MAX(updated_at + 0.000001, ?) "
                    f"WHERE status IN ({marks}) AND (? = 0 OR updated_at <= ?)",
                    (marker, now, *statuses, max_age_seconds, cutoff),
                )
                return cur.rowcount
            # At-rest encryption on: `result` is sealed ciphertext. Appending the
            # marker in SQL would corrupt the ciphertext (unrecoverable on
            # decrypt) or write bare plaintext into a sealed column (tripped as
            # tampering). Append through the seal layer per row instead. The
            # set of stale orphans on startup is tiny, so the row-by-row cost
            # is negligible.
            rows = conn.execute(
                "SELECT id, result FROM goals "
                f"WHERE status IN ({marks}) AND (? = 0 OR updated_at <= ?)",
                (*statuses, max_age_seconds, cutoff),
            ).fetchall()
            from .crypto_at_rest import EncryptionUnavailable
            reclaimed = 0
            for row in rows:
                try:
                    dec = _dec_field(row["result"])
                    # Strict mode withholds a not-yet-migrated plaintext result
                    # (_dec_field returns the sentinel, never the real value);
                    # re-sealing the sentinel here would overwrite -- and
                    # permanently destroy -- the original. Fall through to the
                    # status-only reclaim below instead.
                    new_result = (
                        None if dec == _UNSEALED_WITHHELD
                        else _enc_field((dec or "") + marker)
                    )
                except EncryptionUnavailable:
                    new_result = None
                if new_result is None:
                    # One orphan whose result can't be recovered -- sealed under
                    # a rotated or foreign at-rest key, or withheld under strict
                    # mode -- must not abort crash-recovery for every other
                    # stuck goal. Reclaim the status; leave the result intact
                    # rather than corrupting or dropping it.
                    cur = conn.execute(
                        "UPDATE goals SET status = 'blocked', updated_at = MAX(updated_at + 0.000001, ?) "
                        f"WHERE id = ? AND status IN ({marks}) "
                        "AND (? = 0 OR updated_at <= ?)",
                        (now, row["id"], *statuses, max_age_seconds, cutoff),
                    )
                    reclaimed += cur.rowcount
                    continue
                cur = conn.execute(
                    "UPDATE goals SET status = 'blocked', result = ?, "
                    "updated_at = MAX(updated_at + 0.000001, ?) "
                    f"WHERE id = ? AND status IN ({marks}) "
                    "AND (? = 0 OR updated_at <= ?)",
                    (new_result, now, row["id"], *statuses, max_age_seconds, cutoff),
                )
                reclaimed += cur.rowcount
            return reclaimed

    def _init_schema_version(self) -> None:
        # Fast path: an already-initialized DB only needs a read. WAL readers
        # never block a concurrent writer, so don't take a write lock on every
        # open -- a second connection opening mid-write would otherwise hit
        # "database is locked".
        row = self.conn.execute(
            "SELECT version FROM schema_version LIMIT 1"
        ).fetchone()
        if row is not None:
            return
        # Fresh DB: seed the single row. Concurrent first-opens raced -- the
        # old check-then-insert keyed on version=1, but a *losing* connection
        # ran its INSERT only AFTER the winner had migrated its row up to
        # SCHEMA_VERSION, so version=1 was free again and it inserted a SECOND
        # row (the try/except only caught a PK collision). Two rows then made
        # the no-WHERE `UPDATE schema_version SET version=?` in
        # _apply_migrations collide on the PK -- the intermittent fresh-open CI
        # flake. Guard on table-emptiness in one atomic statement: the WHERE
        # NOT EXISTS is re-checked under SQLite's single-writer lock, so a
        # loser that saw an empty table above still inserts nothing once the
        # winner's row is committed. At most one row, ever.
        self.conn.execute(
            "INSERT INTO schema_version(version) "
            "SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version)"
        )

    def _backup_before_migration(self, from_version: int) -> None:
        """Best-effort recovery snapshot taken before applying schema migrations.

        Migrations are forward-only and irreversible; an interrupted upgrade can
        leave the world DB partially migrated with no automated rollback. Before
        the first pending migration in this open, snapshot the DB -- via SQLite's
        online-backup API, so it is consistent even under WAL -- to a sibling
        ``<db>.pre-migration-v<from>.bak`` an operator can restore from.

        Best-effort and fail-open: a snapshot failure logs and does NOT block the
        upgrade (startup must still proceed). Skipped for in-memory DBs and when
        ``[world_model] pre_migration_backup = false``.
        """
        path = getattr(self, "path", None)
        if path is None or str(path) == ":memory:":
            return
        # Only a pre-existing DB has data worth protecting; a fresh world.db
        # "migrates" v1->current on first open but has nothing to lose.
        if not getattr(self, "_db_preexisted", False):
            return
        try:
            from .config import load_config
            if load_config().get("world_model", {}).get(
                "pre_migration_backup", True
            ) is False:
                return
        except Exception:  # pragma: no cover -- config never blocks a migration
            pass
        dest = Path(f"{path}.pre-migration-v{from_version}.bak")
        if dest.exists():  # idempotent across the open-time lock-retry loop
            return
        try:
            # Quiesce the source first. executescript(SCHEMA)/_init_schema_version()
            # leave an uncommitted write transaction holding a lock on self.conn,
            # and SQLite's online backup of a connection that is mid-write-
            # transaction deadlocks (observed as a hung migration). Commit so the
            # snapshot is a clean, lock-free read of the pre-migration state; the
            # migration loop opens its own writes immediately after.
            try:
                self.conn.commit()
            except sqlite3.Error:  # pragma: no cover -- best-effort quiesce
                pass
            # Pre-create the sensitive backup with the shared create-time
            # private ACL and no-follow atomic publication before SQLite opens
            # it and writes any customer data.
            atomic_create_bytes(dest, b"")
            bdst = sqlite3.connect(str(dest))
            try:
                self.conn.backup(bdst)
            finally:
                bdst.close()  # sqlite3's context manager commits but never closes
            ensure_private_file(dest)
            log.info(
                "world: wrote pre-migration backup %s (v%s -> v%s)",
                dest, from_version, SCHEMA_VERSION,
            )
        except Exception as e:  # pragma: no cover -- snapshot is best-effort
            log.warning(
                "world: pre-migration backup failed (%s); proceeding with upgrade", e,
            )

    def _apply_migrations(self) -> None:
        current = self.conn.execute(
            "SELECT version FROM schema_version LIMIT 1"
        ).fetchone()[0]
        # A recovery point before any forward-only migration runs.
        if current < SCHEMA_VERSION:
            self._backup_before_migration(current)
        # Temporarily bump busy_timeout for the
        # migration. CREATE INDEX on a multi-million-row table
        # (long-lived production DB) can take 30s+ and the 5s default
        # would raise "database is locked" against a running dashboard.
        # Restore after, even on exception.
        prior = None
        try:
            prior = self.conn.execute(
                "PRAGMA busy_timeout"
            ).fetchone()[0]
            self.conn.execute("PRAGMA busy_timeout = 60000")
        except sqlite3.Error:
            prior = None
        try:
            while current < SCHEMA_VERSION:
                next_version = current + 1
                # Python's sqlite3 legacy driver auto-commits DDL/
                # backfill statements one at a time outside any transaction,
                # so a failing multi-statement migration left EARLIER
                # statements of the SAME version permanently applied while
                # schema_version stayed unbumped -- an interrupted upgrade
                # left the DB in a state no later open could detect or retry
                # cleanly. Wrap each version in its own explicit transaction
                # so a failure rolls back every statement of that version.
                # `commit()` first is a safe no-op except right after a
                # fresh DB's `_init_schema_version()` INSERT, whose
                # transaction is still open here (only committed after this
                # method returns) -- BEGIN inside an open transaction raises
                # `OperationalError: cannot start a transaction within a
                # transaction`.
                self.conn.commit()
                self.conn.execute("BEGIN IMMEDIATE")
                try:
                    for stmt in MIGRATIONS.get(next_version, []):
                        try:
                            self.conn.execute(stmt)
                        except sqlite3.OperationalError as e:
                            msg = str(e).lower()
                            if "duplicate column" not in msg:
                                raise
                    self.conn.execute(
                        "UPDATE schema_version SET version = ?", (next_version,),
                    )
                    self.conn.commit()
                except BaseException:
                    self.conn.rollback()
                    raise
                current = next_version
        finally:
            if prior is not None:
                try:
                    self.conn.execute(
                        f"PRAGMA busy_timeout = {int(prior)}",
                    )
                except sqlite3.Error:
                    pass

    @property
    def schema_version(self) -> int:
        row = self.conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        return row[0] if row else 0

    # ----- goals -----
    def create_goal(self, title: str, description: str = "", parent_id: int | None = None,
                    *, owner: str = "", execution_principal: str = "",
                    domain: str = "", project_id: int | None = None,
                    connection_references: list | None = None) -> int:
        if execution_principal is None:
            execution_principal = ""
        if not isinstance(execution_principal, str):
            raise ValueError("invalid execution principal")
        if execution_principal:
            from .agent_control_plane import valid_principal

            if not valid_principal(execution_principal):
                raise ValueError("invalid execution principal")
        from .template_connections import packed
        selection = packed(owner, connection_references or [])
        now = time.time()
        with self._writing() as conn:
            cur = conn.execute(
                "INSERT INTO goals(parent_id, title, description, status, "
                "created_at, updated_at, owner, execution_principal, domain, project_id, connection_selection) "
                "VALUES(?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)",
                (parent_id, _enc_field(title), _enc_field(description), now, now,
                 owner, execution_principal, domain or "", project_id, _enc_field(selection)),
            )
            goal_id = cur.lastrowid
        # Register after the goal transaction commits: background observation
        # may start immediately, and notification availability must not decide
        # whether a customer's task is accepted.
        from .personal_notification_recipients import enroll_task_owner

        enroll_task_owner(owner)
        return goal_id

    def goal_connection_selection(self, goal_id: int) -> str:
        row = self._read_one("SELECT connection_selection FROM goals WHERE id=?", (goal_id,))
        return _dec_field(row[0]) if row and row[0] else ""

    def record_goal_origin(self, goal_id: int, kind: str, ref: str) -> None:
        """Record which automation spawned a goal, so the Automations page can
        show each automation's run history. ``kind`` is 'schedule' or 'trigger';
        ``ref`` is the stable schedule_id or trigger name. One row per goal."""
        with self._writing() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO goal_origins(goal_id, kind, ref, created_at) "
                "VALUES(?, ?, ?, ?)",
                (int(goal_id), str(kind), str(ref), time.time()),
            )

    def goals_for_origin(self, kind: str, ref: str, *, limit: int = 20) -> list[Goal]:
        """Goals an automation spawned, most-recent first. ``SELECT g.*`` (not
        ``*``) so goal_origins.created_at doesn't shadow goals.created_at."""
        rows = self._read_all(
            "SELECT g.* FROM goals g JOIN goal_origins o ON o.goal_id = g.id "
            "WHERE o.kind = ? AND o.ref = ? ORDER BY g.id DESC LIMIT ?",
            (str(kind), str(ref), max(1, int(limit))),
        )
        return _goals_from_rows(rows)

    def origin_status_counts(self, kind: str, ref: str) -> dict[str, int]:
        """An automation's spawned-goal counts keyed by status (run summary)."""
        rows = self._read_all(
            "SELECT g.status AS status, COUNT(*) AS n FROM goals g "
            "JOIN goal_origins o ON o.goal_id = g.id "
            "WHERE o.kind = ? AND o.ref = ? GROUP BY g.status",
            (str(kind), str(ref)),
        )
        return {r["status"]: int(r["n"]) for r in rows}

    def record_signoff(self, goal_id: int, decision: str, *,
                       decided_by: str = "", note: str | None = None,
                       expected_updated_at: float | None = None, _cursor=None) -> bool:
        """Record a human's certify/reject decision on a finished deliverable --
        the sign-off a pack's output gate calls for. One authoritative row per
        goal (a later decision replaces an earlier one); the note is encrypted
        at rest. ``decision`` is 'approved' or 'rejected'.

        The insert is conditional on the goal still being ``done`` and, when
        supplied, the exact ``expected_updated_at`` the reviewer saw.  This
        closes pre-approval and edit-vs-sign races at the durable boundary.
        Later result/artifact mutations invalidate the row in their own write
        transaction. Returns ``True`` only when the authoritative decision
        transitions (including the first decision); an identical retry is an
        atomic no-op and returns ``False`` so downstream effects stay exactly
        once.
        """
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision must be 'approved' or 'rejected'")
        with (self._writing() if _cursor is None else contextlib.nullcontext(_cursor)) as conn:
            sql = (
                "INSERT INTO signoffs(goal_id, decision, decided_by, "
                "note, created_at) SELECT id, ?, ?, ?, ? FROM goals "
                "WHERE id = ? AND status = 'done'"
            )
            params: list[Any] = [
                str(decision), str(decided_by or ""), _enc_field(note),
                time.time(), int(goal_id),
            ]
            if expected_updated_at is not None:
                sql += " AND updated_at = ?"
                params.append(float(expected_updated_at))
            sql += (
                " ON CONFLICT(goal_id) DO UPDATE SET "
                "decision=excluded.decision, decided_by=excluded.decided_by, "
                "note=excluded.note, created_at=CASE WHEN excluded.created_at > signoffs.created_at "
                "THEN excluded.created_at ELSE signoffs.created_at + 0.000001 END "
                "WHERE signoffs.decision <> excluded.decision"
            )
            cur = conn.execute(sql, tuple(params))
            if cur.rowcount == 1:
                return True
            # Zero rows is either an invalid/stale expected version or an
            # identical retry. Distinguish them while this write transaction
            # still owns the database lock; never call a retry idempotent when
            # the client actually reviewed stale bytes.
            goal = conn.execute(
                "SELECT status, updated_at FROM goals WHERE id = ?",
                (int(goal_id),),
            ).fetchone()
            valid_goal = bool(
                goal
                and goal["status"] == "done"
                and (
                    expected_updated_at is None
                    or float(goal["updated_at"]) == float(expected_updated_at)
                )
            )
            if not valid_goal:
                raise ValueError(
                    "goal is not finished or the deliverable changed before sign-off"
                )
            current = conn.execute(
                "SELECT decision FROM signoffs WHERE goal_id = ?",
                (int(goal_id),),
            ).fetchone()
            if current and current["decision"] == decision:
                return False
            raise RuntimeError("sign-off transition failed")

    def signoff_for(self, goal_id: int) -> dict | None:
        """The current sign-off on a goal's deliverable, or ``None`` if it
        hasn't been reviewed yet."""
        row = self._read_one("SELECT * FROM signoffs WHERE goal_id = ?", (int(goal_id),))
        if not row:
            return None
        return {
            "goal_id": row["goal_id"], "decision": row["decision"],
            "decided_by": row["decided_by"], "note": _dec_field(row["note"]),
            "created_at": row["created_at"],
        }

    def signoffs_for_goals(self, goal_ids) -> dict[int, str]:
        """Map ``goal_id -> decision`` for a batch of goals (the persona inbox,
        so a signed-off deliverable drops out of the awaiting queue). Goals with
        no sign-off are simply absent."""
        ids = [int(g) for g in goal_ids]
        if not ids:
            return {}
        placeholders = ",".join("?" * len(ids))
        rows = self._read_all(
            f"SELECT goal_id, decision FROM signoffs WHERE goal_id IN ({placeholders})",
            tuple(ids),
        )
        return {r["goal_id"]: r["decision"] for r in rows}

    def add_artifact(self, goal_id: int, kind: str, title: str, content: str) -> int:
        """Record an artifact a goal produced (markdown / code / table / text).
        Re-using the same ``(goal_id, title)`` appends the next version, so the
        UI can show history. ``title`` is a plaintext label (versioning keys on
        it); ``content`` is encrypted at rest like other agent output."""
        now = time.time()
        with self._writing() as conn:
            # Compute the next version in the SAME statement as the INSERT so the
            # whole read-modify-write is atomic under SQLite's per-statement write
            # lock. A separate SELECT MAX(version)+1 then INSERT races ACROSS
            # PROCESSES (the dashboard + worker each hold their own _writing lock,
            # and a deferred txn takes no write lock until the INSERT) -> two
            # processes assign the SAME version. The scalar subquery closes that
            # gap; mirrors the per-key serialization done in the Postgres backend.
            cur = conn.execute(
                "INSERT INTO artifacts(goal_id, kind, title, content, version, created_at) "
                "VALUES(?, ?, ?, ?, "
                "(SELECT COALESCE(MAX(version), 0) + 1 FROM artifacts "
                " WHERE goal_id = ? AND title = ?), ?)",
                (int(goal_id), str(kind or "text"), title or "", _enc_field(content),
                 int(goal_id), title or "", now),
            )
            # The goal timestamp is the optimistic release version used by
            # sign-off. Include artifact mutations in that version, not just
            # goal.result edits, so a concurrent attachment cannot be approved
            # by a reviewer who never saw it.
            conn.execute(
                "UPDATE goals SET updated_at = MAX(updated_at + 0.000001, ?) WHERE id = ?",
                (now, int(goal_id)),
            )
            # Approval covers the complete reviewed release payload.  A new
            # artifact version changes that payload and must be reviewed again.
            conn.execute("DELETE FROM signoffs WHERE goal_id = ?", (int(goal_id),))
            return int(cur.lastrowid)

    def artifacts_for_goal(self, goal_id: int) -> list[dict]:
        """Every artifact version for a goal, ordered by title then version."""
        rows = self._read_all(
            "SELECT id, goal_id, kind, title, content, version, created_at "
            "FROM artifacts WHERE goal_id = ? ORDER BY title, version",
            (int(goal_id),),
        )
        return [{"id": r["id"], "goal_id": r["goal_id"], "kind": r["kind"],
                 "title": r["title"] or "", "content": _dec_field(r["content"]) or "",
                 "version": r["version"], "created_at": r["created_at"]} for r in rows]

    def latest_artifacts(self, goal_id: int) -> list[dict]:
        """The latest version of each titled artifact, with a ``versions`` count
        (what the goal page shows; older versions are still in the table)."""
        by_title: dict[str, dict] = {}
        counts: dict[str, int] = {}
        for a in self.artifacts_for_goal(goal_id):  # title, version ascending
            by_title[a["title"]] = a
            counts[a["title"]] = counts.get(a["title"], 0) + 1
        return [{**a, "versions": counts[t]} for t, a in by_title.items()]

    # ---- projects ("matters"): a workspace grouping related goals ----------

    def create_project(self, name: str, *, description: str = "", owner: str = "",
                       domain: str = "") -> int:
        """Create a project. ``name``/``description`` are encrypted at rest;
        ``owner``/``domain`` are plaintext (listing + scoping)."""
        now = time.time()
        with self._writing() as conn:
            cur = conn.execute(
                "INSERT INTO projects(name, description, owner, domain, status, created_at) "
                "VALUES(?, ?, ?, ?, 'active', ?)",
                (_enc_field(name), _enc_field(description), owner or "", domain or "", now),
            )
            return int(cur.lastrowid)

    def _project_from_row(self, row) -> dict:
        return {
            "id": row["id"], "name": _dec_field(row["name"]) or "",
            "description": _dec_field(row["description"]) or "",
            "owner": row["owner"], "domain": row["domain"],
            "status": row["status"], "created_at": row["created_at"],
        }

    def get_project(self, project_id: int) -> dict | None:
        row = self._read_one("SELECT * FROM projects WHERE id = ?", (int(project_id),))
        return self._project_from_row(row) if row else None

    def list_projects(self, *, owner: str | None = None) -> list[dict]:
        """All projects, newest first. ``owner``-scoped like :meth:`list_goals`
        (owner is plaintext); each carries a ``goal_count``."""
        sql = "SELECT * FROM projects"
        params: tuple[Any, ...] = ()
        if owner is not None:
            sql += " WHERE owner = ?"
            params = (owner,)
        sql += " ORDER BY id DESC"
        out = []
        for row in self._read_all(sql, params):
            p = self._project_from_row(row)
            cnt = self._read_one(
                "SELECT COUNT(*) AS n FROM goals WHERE project_id = ?", (p["id"],))
            p["goal_count"] = int(cnt["n"]) if cnt else 0
            out.append(p)
        return out

    def set_goal_project(self, goal_id: int, project_id: int | None) -> None:
        """File a goal under a project (or clear it with ``None``)."""
        with self._writing() as conn:
            conn.execute(
                "UPDATE goals SET project_id = ?, updated_at = MAX(updated_at + 0.000001, ?) WHERE id = ?",
                (int(project_id) if project_id is not None else None, time.time(), int(goal_id)),
            )

    def project_status_counts(self, project_id: int) -> dict[str, int]:
        """Member-goal counts keyed by status (the project summary)."""
        rows = self._read_all(
            "SELECT status, COUNT(*) AS n FROM goals WHERE project_id = ? GROUP BY status",
            (int(project_id),),
        )
        return {r["status"]: int(r["n"]) for r in rows}

    def goal_status_counts(self, *, owner: str | None = None) -> dict[str, int]:
        """All goals keyed by status -- the backend-agnostic source for the
        ``/metrics`` ``maverick_goals_total`` gauge (the dashboard inlined this
        SQL against SQLite, so a Postgres deployment counted a stale local file)."""
        sql = "SELECT status, COUNT(*) AS n FROM goals"
        params: tuple = ()
        if owner is not None:
            sql += " WHERE owner = ?"
            params = (owner,)
        rows = self._read_all(sql + " GROUP BY status", params)
        return {r["status"]: int(r["n"]) for r in rows}

    # -- backend-portable raw reads ------------------------------------------
    # The dashboard's boards and exports need a handful of aggregate queries
    # that have no accessor here. Reaching into ``.conn`` directly only works
    # on SQLite (``?`` paramstyle, ``sqlite3.Row``, ``date(x, 'unixepoch')``)
    # and fails on the Postgres backend. These two
    # methods are the contract both backends implement: write the SQL in
    # SQLite paramstyle and access rows by index or by column name.

    def query(self, sql: str, params: tuple[Any, ...] | list = ()) -> list:
        """Run a read-only statement written in SQLite paramstyle (``?``) and
        return every row. Rows support both ``row[0]`` and ``row["col"]`` and
        unpack like tuples. Mirrored on the Postgres backend, which rewrites
        the paramstyle and wraps its tuple rows the same way."""
        return self._read_all(sql, tuple(params))

    def sql_day_from_epoch(self, column: str) -> str:
        """SQL expression bucketing an epoch-seconds column into a UTC
        ``YYYY-MM-DD`` string -- the dialect-specific half of a daily series."""
        return f"date({column}, 'unixepoch')"

    def ping(self) -> bool:
        """Cheap liveness probe for ``/healthz`` -- confirms the world store
        answers a trivial read. Backend-agnostic (mirrored on Postgres) so the
        deep health check probes the SAME store the app actually uses, not a
        hard-coded local ``world.db``. Raises on failure (the caller reports it)."""
        self._read_one("SELECT 1 AS one", ())
        return True

    # ---- share links: revocable, expiring read-only access to a goal --------

    def create_share_link(self, goal_id: int, *, created_by: str = "",
                          ttl_seconds: float | None = None, token_prefix: str = "") -> tuple[int, str]:
        """Mint a read-only share link for a goal. Returns ``(id, clear_token)``;
        only the token's SHA-256 is persisted, so the clear token is shown to the
        creator exactly once and the DB never holds anything that grants access."""
        if token_prefix not in {"", "r1_"}:
            raise ValueError("Unsupported share token version")
        token = token_prefix + secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        exp = now + float(ttl_seconds) if ttl_seconds else None
        with self._writing() as conn:
            cur = conn.execute(
                "INSERT INTO share_links(goal_id, token_sha256, created_by, created_at, "
                "expires_at) VALUES(?, ?, ?, ?, ?)",
                (int(goal_id), token_hash, created_by or "", now, exp),
            )
            return int(cur.lastrowid), token

    def resolve_share_link(self, token: str) -> int | None:
        """The goal_id a share token grants read access to, or ``None`` if the
        token is unknown, revoked, or expired. Lookup is by hash -- the clear
        token is never stored."""
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        row = self._read_one(
            "SELECT goal_id, expires_at, revoked FROM share_links WHERE token_sha256 = ?",
            (token_hash,),
        )
        if not row or row["revoked"]:
            return None
        if row["expires_at"] is not None and float(row["expires_at"]) < time.time():
            return None
        return int(row["goal_id"])

    def share_links_for_goal(self, goal_id: int) -> list[dict]:
        """Share links for a goal (manage UI), newest first. Tokens are NOT
        returned (only the hash exists); each row carries its lifecycle state."""
        rows = self._read_all(
            "SELECT id, created_by, created_at, expires_at, revoked FROM share_links "
            "WHERE goal_id = ? ORDER BY id DESC",
            (int(goal_id),),
        )
        now = time.time()
        out = []
        for r in rows:
            expired = r["expires_at"] is not None and float(r["expires_at"]) < now
            out.append({
                "id": r["id"], "created_by": r["created_by"], "created_at": r["created_at"],
                "expires_at": r["expires_at"], "revoked": bool(r["revoked"]),
                "expired": expired, "active": not r["revoked"] and not expired,
            })
        return out

    def revoke_share_link(self, link_id: int, *, goal_id: int | None = None) -> bool:
        """Revoke a share link. When ``goal_id`` is given the revoke only applies
        if the link belongs to it (so a caller can't revoke another goal's link).
        Returns whether a row was changed."""
        with self._writing() as conn:
            if goal_id is None:
                cur = conn.execute("UPDATE share_links SET revoked = 1 WHERE id = ?",
                                   (int(link_id),))
            else:
                cur = conn.execute(
                    "UPDATE share_links SET revoked = 1 WHERE id = ? AND goal_id = ?",
                    (int(link_id), int(goal_id)))
            return cur.rowcount > 0

    def set_goal_domain(self, goal_id: int, domain: str) -> None:
        """Record the department (domain pack) a goal is running as.

        Plain-text column (pack names are operator-defined identifiers, not
        user content) so learning loops can filter without decrypting."""
        with self._writing() as conn:
            conn.execute(
                "UPDATE goals SET domain = ? WHERE id = ?",
                (domain or "", goal_id),
            )

    def set_goal_title(self, goal_id: int, title: str) -> None:
        """Rename a goal, sealing the title column like ``create_goal`` does."""
        with self._writing() as conn:
            conn.execute(
                "UPDATE goals SET title = ?, updated_at = MAX(updated_at + 0.000001, ?) WHERE id = ?",
                (_enc_field(title), time.time(), int(goal_id)),
            )

    def set_goal_parent(self, goal_id: int, parent_id: int | None) -> None:
        """Move a goal under a new parent (or to the root with ``None``)."""
        with self._writing() as conn:
            conn.execute(
                "UPDATE goals SET parent_id = ?, updated_at = MAX(updated_at + 0.000001, ?) WHERE id = ?",
                (int(parent_id) if parent_id is not None else None,
                 time.time(), int(goal_id)),
            )

    def goal_parent_pairs(self) -> list[tuple[int, int | None]]:
        """``(id, parent_id)`` for every goal -- the edge list for tree/cycle checks."""
        rows = self._read_all("SELECT id, parent_id FROM goals")
        return [(int(r["id"]), r["parent_id"]) for r in rows]

    def set_goal_status(self, goal_id: int, status: str, result: str | None = None) -> None:
        # updated_at is both a timestamp and the public optimistic review
        # version. All goal timestamp writes advance it atomically in SQL:
        # coarse/repeated or backwards wall time cannot reauthorize stale
        # bytes, even when independent connections mutate the same goal.
        now = time.time()
        legacy_refused = False
        binding_scope = (execution_binding_lock(self, goal_id)
                         if status in {"active", "running"}
                         else contextlib.nullcontext(False))
        with binding_scope as binding_locked, self._writing() as conn:
            if status in {"active", "running"}:
                prior = conn.execute(
                    "SELECT g.status,g.owner,o.kind,o.ref,a.trigger_key FROM goals g "
                    "JOIN goal_origins o ON o.goal_id=g.id "
                    "LEFT JOIN event_goal_admissions a ON a.goal_id=g.id "
                    "WHERE g.id=? AND o.kind IN ('event','event_v2')", (int(goal_id),),
                ).fetchone()
                if prior is None and binding_locked:
                    current = conn.execute("SELECT status FROM goals WHERE id=?", (int(goal_id),)).fetchone()
                    if current is not None and current[0] not in {"active", "running"}:
                        raise EventRegistryUnavailable("Event origin disappeared during execution claim")
                if (prior is not None and prior[0] not in {"active", "running"}
                        and not binding_locked):
                    raise EventRegistryUnavailable("Event binding changed during execution claim")
                if (prior is not None and prior[0] not in {"active", "running"}
                        and not compatible_event_goal(prior[2], prior[3], prior[1], prior[4])):
                    legacy_refused = True
                    if prior[0] == "pending":
                        conn.execute(
                            "UPDATE goals SET status='blocked', completed_at=NULL, "
                            "updated_at=MAX(updated_at + 0.000001, ?), result=? "
                            "WHERE id=? AND status='pending'",
                            (now, _enc_field("Earlier event request held for review"), int(goal_id)),
                        )
                        conn.execute("DELETE FROM signoffs WHERE goal_id=?", (int(goal_id),))
            if not legacy_refused:
                cur = conn.execute(
                "UPDATE goals SET completed_at = CASE WHEN ? <> 'done' THEN NULL "
                "WHEN status = 'done' THEN completed_at "
                "ELSE MAX(updated_at + 0.000001, ?) END, "
                "status = ?, updated_at = MAX(updated_at + 0.000001, ?), "
                "result = COALESCE(?, result) WHERE id = ?",
                (status, now, status, now, _enc_field(result), goal_id),
                )
                self._goal_changed(goal_id)
            # A sign-off is authority over one immutable terminal payload, not
            # over a goal id forever.  Reruns, failures, and any result rewrite
            # revoke it atomically so old approval cannot authorize new bytes.
            if not legacy_refused and cur.rowcount == 1 and (status != "done" or result is not None):
                conn.execute("DELETE FROM signoffs WHERE goal_id = ?", (int(goal_id),))
        if legacy_refused:
            raise LegacyEventGoalHeld("Earlier event request held for review")

    def block_pending_goal(self, goal_id: int, *, result: str) -> bool:
        """Atomically block a pending goal without overwriting an execution claim."""
        with self._writing() as conn:
            cur = conn.execute(
                "UPDATE goals SET status = 'blocked', completed_at = NULL, "
                "updated_at = MAX(updated_at + 0.000001, ?), result = ? "
                "WHERE id = ? AND status = 'pending'",
                (time.time(), _enc_field(result), int(goal_id)),
            )
            changed = cur.rowcount == 1
            if changed:
                conn.execute("DELETE FROM signoffs WHERE goal_id = ?", (int(goal_id),))
                self._goal_changed(goal_id)
            return changed

    def block_goal_admission(self, goal_id: int, *, result: str) -> bool:
        """Record a pre-dispatch refusal without replacing a terminal outcome."""
        with self._writing() as conn:
            cur = conn.execute(
                "UPDATE goals SET status = 'blocked', completed_at = NULL, "
                "updated_at = MAX(updated_at + 0.000001, ?), result = ? "
                "WHERE id = ? AND status IN ('pending', 'active', 'running', 'blocked')",
                (time.time(), _enc_field(result), int(goal_id)),
            )
            changed = cur.rowcount == 1
            if changed:
                conn.execute("DELETE FROM signoffs WHERE goal_id = ?", (int(goal_id),))
            return changed

    def set_goal_partial_result(self, goal_id: int, text: str) -> bool:
        """Replace a RUNNING goal's result with the answer written so far.

        The chat page's live preview. It never touches a terminal goal, so the
        orchestrator's final write wins any race with a late preview; it
        advances the optimistic review version like every goal write; and it
        revokes no sign-off because a non-terminal goal cannot carry one.
        Returns whether a row changed.
        """
        now = time.time()
        with self._writing() as conn:
            cur = conn.execute(
                "UPDATE goals SET result = ?, updated_at = MAX(updated_at + 0.000001, ?) "
                "WHERE id = ? AND status NOT IN "
                "('done', 'completed', 'failed', 'cancelled', 'blocked', 'error')",
                (_enc_field(text), now, goal_id),
            )
            if cur.rowcount == 1:
                self._goal_changed(goal_id)
            return cur.rowcount == 1

    def shoring_measurements(self, department: str, *, since: float, until: float, owner: str | None = None) -> dict:
        """Complete department totals in one read snapshot, without a row cap."""
        from .shoring_metrics import AGGREGATE_SQL, EVENT_TIME_SQL, measurements

        row = self._read_one(
            AGGREGATE_SQL + f" WHERE domain = ? AND {EVENT_TIME_SQL} >= ? AND {EVENT_TIME_SQL} <= ?" + (" AND owner = ?" if owner is not None else ""),
            (department, since, until, *([owner] if owner is not None else [])),
        )
        return measurements(row)

    def bind_goal_execution_principal(self, goal_id: int, principal: str) -> bool:
        """Atomically bind an unbound goal to its execution principal.

        The operation is idempotent for the same principal and refuses a
        non-empty different principal. Keeping the comparison in the write avoids
        a read-then-write race where two dispatchers could each believe an
        unbound goal ran under their authority. ``owner`` remains the separate
        dashboard/resource authorization identity.
        """
        from .agent_control_plane import valid_principal

        if not valid_principal(principal):
            raise ValueError("invalid execution principal")
        with self._writing() as conn:
            cur = conn.execute(
                "UPDATE goals SET execution_principal = ? "
                "WHERE id = ? AND (execution_principal = '' "
                "OR execution_principal = ?)",
                (principal, int(goal_id), principal),
            )
            return cur.rowcount == 1

    def bind_goal_owner(self, goal_id: int, principal: str) -> bool:
        """Backward-compatible binder for the resource owner field.

        Runtime authorization uses :meth:`bind_goal_execution_principal`.
        This method retains the historical owner-assignment behavior for
        embedders that explicitly claim a previously ownerless resource.
        """
        if not isinstance(principal, str) or not principal:
            raise ValueError("principal is required")
        with self._writing() as conn:
            cur = conn.execute(
                "UPDATE goals SET owner = ? "
                "WHERE id = ? AND (owner = '' OR owner = ?)",
                (principal, int(goal_id), principal),
            )
            return cur.rowcount == 1

    def claim_goal_for_run(
        self, goal_id: int, *, expected_owner: str | None = None,
    ) -> bool:
        """Atomically claim one pending goal for execution.

        Remote dispatch is an at-least-once boundary: a worker RPC can be
        repeated after a timeout or a lost response.  The status transition is
        therefore the execution claim, not a preceding read.  Exactly one
        contender can move ``pending`` to ``active``; later calls observe the
        already-active or terminal row and must not execute it again.

        ``expected_owner`` is included in the same compare-and-swap so the
        authorization check cannot be separated from the state change by a
        race.  ``None`` is the administrative scope and intentionally omits the
        owner predicate.
        """
        sql = (
            "UPDATE goals SET status = 'active', updated_at = MAX(updated_at + 0.000001, ?) "
            "WHERE id = ? AND status = 'pending'"
        )
        params: tuple[Any, ...] = (time.time(), int(goal_id))
        if expected_owner is not None:
            sql += " AND owner = ?"
            params += (str(expected_owner),)
        with execution_binding_lock(self, goal_id) as binding_locked, self._writing() as conn:
            owner_clause = " AND g.owner=?" if expected_owner is not None else ""
            legacy = conn.execute(
                "SELECT g.owner,o.kind,o.ref,a.trigger_key FROM goals g "
                "JOIN goal_origins o ON o.goal_id=g.id "
                "LEFT JOIN event_goal_admissions a ON a.goal_id=g.id "
                "WHERE g.id=? AND g.status='pending' "
                "AND o.kind IN ('event','event_v2')" + owner_clause,
                (int(goal_id), *((str(expected_owner),) if expected_owner is not None else ())),
            ).fetchone()
            if legacy is None and binding_locked:
                eligible = conn.execute(
                    "SELECT 1 FROM goals WHERE id=? AND status='pending'" +
                    (" AND owner=?" if expected_owner is not None else ""),
                    (int(goal_id), *((str(expected_owner),) if expected_owner is not None else ())),
                ).fetchone()
                if eligible is not None:
                    raise EventRegistryUnavailable("Event origin disappeared during execution claim")
            if legacy is not None and not binding_locked:
                raise EventRegistryUnavailable("Event binding changed during execution claim")
            if legacy is not None and not compatible_event_goal(
                    legacy[1], legacy[2], legacy[0], legacy[3]):
                conn.execute(
                    "UPDATE goals SET status='blocked', completed_at=NULL, "
                    "updated_at=MAX(updated_at + 0.000001, ?), result=? "
                    "WHERE id=? AND status='pending'",
                    (time.time(), _enc_field("Earlier event request held for review"),
                     int(goal_id)),
                )
                conn.execute("DELETE FROM signoffs WHERE goal_id=?", (int(goal_id),))
                return False
            cur = conn.execute(sql, params)
            return cur.rowcount == 1

    def touch_goal(
        self, goal_id: int, *, expected_owner: str | None = None,
    ) -> bool:
        """Refresh a live goal's ``updated_at`` — the orphan-reclaim liveness
        signal — without any other side effect.

        A pure keep-alive for work running OUTSIDE this process (external
        agents heartbeating a run, remote workers between status writes):
        ``set_goal_status('active')`` would drop signoffs and flip a pending
        row, so liveness gets its own single-statement primitive. Only
        in-flight rows qualify; terminal goals are never revived. The owner
        predicate rides in the same statement so authorization cannot be
        separated from the touch by a race."""
        sql = ("UPDATE goals SET updated_at = MAX(updated_at + 0.000001, ?) "
               "WHERE id = ? AND status IN ('active', 'pending')")
        params: tuple[Any, ...] = (time.time(), int(goal_id))
        if expected_owner is not None:
            sql += " AND owner = ?"
            params += (str(expected_owner),)
        with self._writing() as conn:
            cur = conn.execute(sql, params)
            return cur.rowcount == 1

    def get_goal(self, goal_id: int) -> Goal | None:
        row = self._read_one("SELECT * FROM goals WHERE id = ?", (goal_id,))
        # One at-rest policy and key lookup for the row's sealed fields.
        return _goals_from_rows([row])[0] if row else None

    def get_goals(self, goal_ids) -> dict[int, Goal]:
        """``{id: goal}`` for the ids that exist: one read per 500 ids, each
        decrypted with one at-rest policy and key lookup (a page that read 50
        goals one by one loaded the key for every sealed field of each)."""
        found: dict[int, Goal] = {}
        for chunk in self._chunks(sorted({int(goal_id) for goal_id in goal_ids})):
            placeholders = ",".join("?" * len(chunk))
            rows = self._read_all(f"SELECT * FROM goals WHERE id IN ({placeholders})", tuple(chunk))
            for goal in _goals_from_rows(rows):
                found[goal.id] = goal
        return found

    def recent_goals_by_domain(self, domains: list[str], *, owner: str | None = None,
                               per_domain: int = 5) -> dict[str, list[Goal]]:
        """The newest ``per_domain`` goals of each listed domain, newest first.

        The same answer as one ``list_goals(domain=..., limit=per_domain,
        order="desc")`` per domain, from one grouped query per 500 domains
        (the Results page asks about every deliverable pack, 2,031 of them on a
        full catalog). A domain with no goals is absent from the result.
        """
        wanted = sorted({str(d) for d in domains if d})
        keep = max(1, int(per_domain))
        found: dict[str, list[Goal]] = {}
        for chunk in self._chunks(wanted):
            where = f"domain IN ({','.join('?' * len(chunk))})"
            params: list[Any] = list(chunk)
            if owner is not None:
                where += " AND owner = ?"
                params.append(owner)
            rows = self._read_all(
                "SELECT * FROM goals WHERE id IN (SELECT id FROM ("
                "SELECT id, ROW_NUMBER() OVER (PARTITION BY domain ORDER BY id DESC) AS n "
                f"FROM goals WHERE {where}) WHERE n <= ?) ORDER BY id DESC",
                (*params, keep),
            )
            for row in rows:
                goal = _goal_from_row(row)
                found.setdefault(goal.domain, []).append(goal)
        return found

    def list_goals(
        self,
        status: str | None = None,
        *,
        owner: str | None = None,
        domain: str | None = None,
        project_id: int | None = None,
        limit: int | None = None,
        offset: int = 0,
        order: str = "asc",
        before_id: int | None = None,
        strict_tenant: bool = False,
    ) -> list[Goal]:
        """List goals, optionally filtered + paginated.

        Defaults preserve historical behaviour (``limit=None`` returns
        all rows in ASC id order). Dashboard callers should pass a
        small ``limit`` to avoid loading every goal on every request;
        ``order='desc'`` lets the most-recent slice be fetched cheaply.
        ``domain`` scopes to one department (the pack a goal ran as) -- the
        ``domain`` column is plaintext, so it filters in SQL.
        ``before_id`` excludes that immutable ID and all newer IDs without
        reading an anchor row. Use descending order for continuation; in
        ascending order it remains only an upper ID bound. Existing offset
        callers retain their historical behavior. ``strict_tenant`` is accepted
        for backend parity; SQLite databases are already tenant-scoped.
        """
        if before_id is not None and not 0 < int(before_id) <= 2**63 - 1:
            raise ValueError("before_id must be a positive signed 64-bit goal ID")
        direction = "DESC" if order.lower() == "desc" else "ASC"
        sql = "SELECT * FROM goals"
        clauses: list[str] = []
        params: tuple[Any, ...] = ()
        if status:
            clauses.append("status = ?")
            params = params + (status,)
        if owner is not None:
            clauses.append("owner = ?")
            params = params + (owner,)
        if domain is not None:
            clauses.append("domain = ?")
            params = params + (domain,)
        if project_id is not None:
            clauses.append("project_id = ?")
            params = params + (int(project_id),)
        if before_id is not None:
            clauses.append("id < ?")
            params = params + (int(before_id),)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += f" ORDER BY id {direction}"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params = params + (max(1, int(limit)), max(0, int(offset)))
        rows = self._read_all(sql, params)
        return _goals_from_rows(rows)

    def goal_states(self, *, owner: str | None = None, limit: int = 10_000,
                    offset: int = 0, order: str = "asc") -> list[tuple[int, str, float | None]]:
        """``(id, status, updated_at)`` for the goals ``list_goals`` returns for
        the same owner, limit, offset and order, read without decrypting any
        goal (the callers only count, compare or page on these columns)."""
        direction = "DESC" if order.lower() == "desc" else "ASC"
        where = " WHERE owner = ?" if owner is not None else ""
        params = (owner,) if owner is not None else ()
        rows = self._read_all(
            f"SELECT id, status, updated_at FROM goals{where} ORDER BY id {direction} LIMIT ? OFFSET ?",
            (*params, max(1, int(limit)), max(0, int(offset))),
        )
        return [(int(row[0]), row[1], row[2]) for row in rows]

    def goals_due_by(self, horizon: float, *, owner: str | None = None,
                     limit: int = 2000) -> list[Goal]:
        """The pending or active goals with a non-zero deadline at or before
        ``horizon`` among the ``limit`` oldest goals (owner-scoped), oldest
        first. Filtering happens before decryption, so only matches are decoded."""
        where = " WHERE owner = ?" if owner is not None else ""
        params = (owner,) if owner is not None else ()
        rows = self._read_all(
            "SELECT * FROM (SELECT * FROM goals" + where + " ORDER BY id ASC LIMIT ?) "
            "WHERE status IN ('pending', 'active') AND deadline IS NOT NULL "
            "AND deadline != 0 AND deadline <= ? ORDER BY id ASC",
            (*params, max(1, int(limit)), float(horizon)),
        )
        return _goals_from_rows(rows)

    def list_goal_results(self, *, owner: str, limit: int = 26,
                          offset: int = 0) -> list[Goal]:
        """Completed root tasks with saved output for the owner's Results page.

        Results are encrypted at rest, so filter on presence in SQL and let
        ``_goals_from_rows`` decrypt only the requested page. Subtasks stay in
        their parent conversation instead of crowding out customer work.
        """
        rows = self._read_all(
            "SELECT * FROM goals WHERE owner=? AND parent_id IS NULL "
            "AND status='done' AND result IS NOT NULL "
            "ORDER BY id DESC LIMIT ? OFFSET ?",
            (owner, max(1, min(int(limit), 100)), max(0, int(offset))),
        )
        return _goals_from_rows(rows)

    def personal_alert_goals(self, owner: str, *, since: float, after_id: int = 0,
                             limit: int = 250) -> list[tuple]:
        """Page all current problems and recent changes, scoped before the limit."""
        rows = self._read_all(
            "SELECT * FROM goals WHERE owner=? AND id>? AND "
            "(status NOT IN ('done','cancelled') OR updated_at>=? OR "
            "EXISTS(SELECT 1 FROM questions q WHERE q.goal_id=goals.id AND q.answer IS NULL)) "
            "ORDER BY id LIMIT ?", (owner, after_id, since, max(1, min(500, limit))))
        return [(_goal_from_row(row), int(row["alert_state_revision"]),
                 int(row["alert_result_revision"])) for row in rows]

    def conversation_summaries(self, *, owner: str | None = None,
                               limit: int = 25, before_id: int | None = None):
        """Root creation order, newest first; children never consume the limit."""
        from .goal_views import ConversationSummary

        sql = "SELECT id,title,status,updated_at,owner FROM goals WHERE parent_id IS NULL"
        params: list[Any] = []
        if owner is not None:
            sql += " AND owner=?"
            params.append(owner)
        if before_id is not None:
            sql += " AND id<?"
            params.append(int(before_id))
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(100, int(limit))))
        rows = self._read_all(sql, tuple(params))
        titles = _dec_fields([row["title"] for row in rows])
        return [ConversationSummary(row["id"], title, row["status"], row["updated_at"], row["owner"])
                for row, title in zip(rows, titles, strict=True)]

    def goal_stream_state(self, goal_id: int, *, include_result: bool = False):
        """Read authorization/status fields; decrypt the result only on demand."""
        from .goal_views import GoalStreamState

        columns = "id,status,owner,result" if include_result else "id,status,owner"
        row = self._read_one(f"SELECT {columns} FROM goals WHERE id=?", (goal_id,))
        if row is None:
            return None
        return GoalStreamState(row["id"], row["status"], row["owner"],
                               _dec_field(row["result"]) if include_result else "")

    def search_goals(
        self,
        query: str,
        *,
        owner: str | None = None,
        limit: int = 50,
        scan: int = 1000,
    ) -> list[Goal]:
        """Search across goals (runs) by text in title / description / result.

        Title and description are encrypted at rest, so a SQL ``LIKE`` can't
        match plaintext. We fetch a bounded window of the most-recent goals
        (``scan``), decrypt them via ``_goal_from_row``, and filter in Python on
        a case-insensitive substring match -- the same scan-then-decrypt shape
        as ``candidate_goals``. Owner-scoped like :meth:`list_goals`; returns up
        to ``limit`` matches, newest first.
        """
        q = (query or "").strip().lower()
        if not q:
            return []
        sql = (
            "SELECT id, parent_id, title, description, status, created_at, "
            "updated_at, deadline, result, owner, execution_principal FROM goals"
        )
        params: tuple[Any, ...] = ()
        if owner is not None:
            sql += " WHERE owner = ?"
            params = (owner,)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params = params + (max(1, int(scan)),)
        rows = self._read_all(sql, params)
        out: list[Goal] = []
        cap = max(1, int(limit))
        for r in rows:
            g = _goal_from_row(r)
            hay = " ".join(p for p in (g.title, g.description, g.result) if p).lower()
            if q in hay:
                out.append(g)
                if len(out) >= cap:
                    break
        return out

    def most_recent_goal(self) -> Goal | None:
        """Most-recently-updated goal regardless of status. Locked read."""
        row = self._read_one("SELECT * FROM goals ORDER BY updated_at DESC LIMIT 1")
        return _goal_from_row(row) if row else None

    def active_goal(self) -> Goal | None:
        row = self._read_one(
            "SELECT * FROM goals WHERE status IN ('active', 'blocked') ORDER BY updated_at DESC LIMIT 1"
        )
        return _goal_from_row(row) if row else None

    def inflight_goal(self) -> Goal | None:
        """Most-recently-updated goal still in flight (``active``/``pending``).

        Distinct from :meth:`active_goal` (which includes ``blocked``): the
        monitor wants the currently-running goal, not a stopped one. Locked.
        """
        row = self._read_one(
            "SELECT * FROM goals WHERE status IN ('active', 'pending') "
            "ORDER BY updated_at DESC LIMIT 1"
        )
        return _goal_from_row(row) if row else None

    def candidate_goals(self, include_running: bool, limit: int = 500, *, owner: str = "") -> list[Goal]:
        """Goals with comparable text, for cross-run recall. Locked read.

        ``include_running`` widens to in-flight goals too; otherwise only
        FINISHED ones. The terminal set is the vocabulary the orchestrator
        actually writes (``done``/``blocked``/``cancelled``) -- the old query
        filtered on ``succeeded``/``failed``, statuses that are never written,
        so it silently missed every failed (``blocked``) past goal.
        """
        text_clause = "(COALESCE(title, '') != '' OR COALESCE(description, '') != '')"
        if include_running:
            where = f"WHERE {text_clause}"
        else:
            where = f"WHERE status IN ('done', 'blocked', 'cancelled') AND {text_clause}"
        rows = self._read_all(
            "SELECT id, parent_id, title, description, status, created_at, "
            f"updated_at, deadline, result, owner, execution_principal "
            f"FROM goals {where} AND owner = ? "
            "ORDER BY updated_at DESC LIMIT ?",
            (owner, limit),
        )
        return _goals_from_rows(rows)

    def subgoals(self, parent_id: int, limit: int = 50) -> list[Goal]:
        """Immediate children of a goal, oldest first. Locked read."""
        rows = self._read_all(
            "SELECT id, parent_id, title, description, status, created_at, "
            "updated_at, deadline, result, owner, execution_principal "
            "FROM goals WHERE parent_id = ? "
            "ORDER BY created_at ASC LIMIT ?",
            (parent_id, limit),
        )
        return _goals_from_rows(rows)

    # ----- episodes -----
    def start_episode(self, goal_id: int) -> int:
        with self._writing() as conn:
            cur = conn.execute(
                "INSERT INTO episodes(goal_id, started_at) VALUES(?, ?)",
                (goal_id, time.time()),
            )
            return cur.lastrowid

    def update_episode_spend(
        self,
        episode_id: int,
        cost_dollars: float = 0.0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        tool_calls: int = 0,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> None:
        """Mirror in-flight spend onto a LIVE (not-yet-ended) episode row.

        Read-side observability only: `maverick runs` / `maverick budget`
        read the episode row, which `end_episode` only writes when the run
        finishes -- so a long run showed `$0.00 / 0 tools` for minutes. The
        orchestrator calls this periodically (throttled) so those commands
        reflect accruing spend. Leaves `ended_at`/`outcome`/`summary`
        untouched, so the row still reads as 'running' and `total_spend`
        (which sums only ended episodes) is unaffected -- this is not a new
        billing path. The `ended_at IS NULL` guard means a late mirror write
        can never clobber the authoritative `end_episode` totals.
        """
        with self._writing() as conn:
            conn.execute(
                "UPDATE episodes SET cost_dollars = ?, input_tokens = ?, "
                "output_tokens = ?, tool_calls = ?, cache_read_tokens = ?, "
                "cache_write_tokens = ? "
                "WHERE id = ? AND ended_at IS NULL",
                (cost_dollars, input_tokens, output_tokens, tool_calls,
                 cache_read_tokens, cache_write_tokens, episode_id),
            )

    def end_episode(
        self,
        episode_id: int,
        summary: str,
        outcome: str,
        cost_dollars: float = 0.0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        tool_calls: int = 0,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> None:
        with self._writing() as conn:
            conn.execute(
                "UPDATE episodes SET ended_at = ?, summary = ?, outcome = ?, "
                "cost_dollars = ?, input_tokens = ?, output_tokens = ?, "
                "tool_calls = ?, cache_read_tokens = ?, cache_write_tokens = ? "
                "WHERE id = ?",
                (time.time(), _enc_field(summary), _enc_field(outcome), cost_dollars,
                 input_tokens, output_tokens, tool_calls,
                 cache_read_tokens, cache_write_tokens, episode_id),
            )

    def list_episodes(
        self,
        limit: int = 50,
        goal_id: int | None = None,
        owner: str | None = None,
    ) -> list[EpisodeSpend]:
        """Recent run-cost episodes, newest first.

        ``owner`` scopes to one principal's runs by joining ``episodes`` to the
        owning goal (the episodes table has no owner column of its own).
        ``None`` is the admin / auth-off view — every principal's episodes.
        Without this filter ``/api/v1/spend`` returned every user's runs + cost
        to any caller.
        """
        cols = _EPISODE_SPEND_COLS
        join = ("FROM episodes e JOIN goals g ON e.goal_id = g.id "
                if owner is not None else "FROM episodes e ")
        where, params = [], []
        if goal_id is not None:
            where.append("e.goal_id = ?")
            params.append(goal_id)
        if owner is not None:
            where.append("g.owner = ?")
            params.append(owner)
        sql = "SELECT " + cols + join
        if where:
            sql += "WHERE " + " AND ".join(where) + " "
        sql += "ORDER BY e.started_at DESC LIMIT ?"
        params.append(limit)
        rows = self._read_all(sql, tuple(params))
        return _episode_spends_from_rows(rows)

    def episodes_by_goal(self, goal_ids, *, per_goal: int = 50) -> dict[int, list[EpisodeSpend]]:
        """The newest ``per_goal`` runs of each listed goal, newest first: the
        rows ``list_episodes(goal_id=..., limit=per_goal)`` returns for each
        goal, in the same order. Each goal is read by its own query, which the
        (goal_id, started_at) index stops after ``per_goal`` rows, so a goal
        with many runs is never read in full; the rows are then decoded in one
        pass, resolving the encryption policy and keys once for all of them.
        Every listed goal is a key, with an empty list when it has no runs.
        """
        ids = list(dict.fromkeys(int(goal_id) for goal_id in goal_ids))
        limit = int(per_goal)   # passed to LIMIT as list_episodes does, so 0 and negatives match it
        rows: list = []
        for gid in ids:
            rows.extend(self._read_all(
                "SELECT " + _EPISODE_SPEND_COLS + "FROM episodes e WHERE e.goal_id = ? "
                "ORDER BY e.started_at DESC LIMIT ?",
                (gid, limit),
            ))
        found: dict[int, list[EpisodeSpend]] = {gid: [] for gid in ids}
        for episode in _episode_spends_from_rows(rows):
            found[episode.goal_id].append(episode)
        return found

    def episodes_for_owner_goals(self, owner: str, *, goal_limit: int = 10_000,
                                 limit: int = 500) -> list[EpisodeSpend]:
        """The owner's runs for their newest ``goal_limit`` goals: newest goal
        first, newest run first within a goal, at most ``limit`` rows.

        Same rows and order as ``list_goals(owner=..., limit=goal_limit,
        order="desc")`` followed by ``list_episodes(goal_id=...)`` for each goal
        until ``limit`` rows, in one query and one decode.
        """
        rows = self._read_all(
            "SELECT " + _EPISODE_SPEND_COLS + "FROM episodes e JOIN ("
            "SELECT id FROM goals WHERE owner = ? ORDER BY id DESC LIMIT ?"
            ") g ON e.goal_id = g.id ORDER BY g.id DESC, e.started_at DESC LIMIT ?",
            (owner, max(1, int(goal_limit)), max(1, int(limit))),
        )
        return _episode_spends_from_rows(rows)

    def episode_costs_since(self, since: float, *, limit: int = 100_000) -> list[tuple[str, float, float]]:
        """Finished runs that ended at or after ``since``, oldest first, as
        ``(owner, ended_at, cost_dollars)``. Read-only history for previewing a
        spending limit before it is saved."""
        rows = self._read_all(
            "SELECT COALESCE(g.owner, '') AS owner, e.ended_at AS ended_at, "
            "COALESCE(e.cost_dollars, 0) AS cost FROM episodes e JOIN goals g ON e.goal_id = g.id "
            "WHERE e.ended_at IS NOT NULL AND e.ended_at >= ? ORDER BY e.ended_at ASC, e.id ASC LIMIT ?",
            (float(since), int(limit)),
        )
        return [(str(r["owner"] or ""), float(r["ended_at"]), float(r["cost"] or 0.0)) for r in rows]

    def task_costs_for(self, *, domain: str = "", execution_principal: str = "",
                       limit: int = 500, owner: str = "") -> list[float]:
        """What the most recent finished tasks run by one specialist (``domain``)
        or one agent (``execution_principal``), or started by one person
        (``owner``), cost, newest first: the sum of each task's finished runs.
        Read-only history for "typical cost"."""
        column, value = (("g.domain", domain) if domain else ("g.execution_principal", execution_principal)
                         if execution_principal else ("g.owner", owner))
        if not value:
            return []
        rows = self._read_all(
            "SELECT SUM(COALESCE(e.cost_dollars, 0)) AS cost, MAX(e.ended_at) AS ended "
            f"FROM episodes e JOIN goals g ON e.goal_id = g.id WHERE {column} = ? "
            "AND e.ended_at IS NOT NULL GROUP BY e.goal_id ORDER BY ended DESC LIMIT ?",
            (str(value), int(limit)),
        )
        return [float(r["cost"] or 0.0) for r in rows]

    def episode_exists(self, goal_id: int, episode_id: int) -> bool:
        """True if ``episode_id`` belongs to ``goal_id``. A single indexed
        lookup -- callers must not scan list_episodes to check existence."""
        row = self._read_one(
            "SELECT 1 FROM episodes WHERE id = ? AND goal_id = ? LIMIT 1",
            (episode_id, goal_id),
        )
        return row is not None

    def purge_episodes_before(
        self, cutoff_ts: float, *, dry_run: bool = False, review_binding: dict | None = None,
    ) -> int:
        """Count or delete completed episodes older than an absolute cutoff.

        This is the backend-portable retention primitive.  Keeping the
        operation on the world model (instead of opening its SQLite file behind
        its back) preserves backend selection and transaction ownership.

        ``facts.source_episode_id``/``fact_history.source_episode_id``
        are ``REFERENCES episodes(id)`` with no ``ON DELETE`` clause, and the
        world opens with ``PRAGMA foreign_keys = ON`` -- deleting an episode
        any fact still cites (retention prunes by AGE, not by whether a fact
        still needs it) raised ``sqlite3.IntegrityError`` and aborted the
        whole retention job. Unlike the erasure path (which deletes the
        facts too -- the point there is removing personal data), retention
        just wants the old episode gone; the fact itself is still live, so
        null out the now-dangling provenance reference instead of deleting
        the fact.
        """
        predicate = "ended_at IS NOT NULL AND ended_at < ?"
        with self._writing() as conn:
            if review_binding is not None:
                from .retention_review_bindings import guard_sql

                guard_sql(conn, "episodes", predicate, (float(cutoff_ts),), review_binding, dry_run=dry_run)
                if dry_run:
                    return int(review_binding["count"])
            if dry_run:
                row = conn.execute(
                    f"SELECT COUNT(*) FROM episodes WHERE {predicate}",
                    (float(cutoff_ts),),
                ).fetchone()
                return int(row[0] or 0)
            episode_query = f"SELECT id FROM episodes WHERE {predicate}"
            conn.execute(
                "UPDATE facts SET source_episode_id = NULL "
                f"WHERE source_episode_id IN ({episode_query})",
                (float(cutoff_ts),),
            )
            conn.execute(
                "UPDATE fact_history SET source_episode_id = NULL "
                f"WHERE source_episode_id IN ({episode_query})",
                (float(cutoff_ts),),
            )
            cur = conn.execute(
                f"DELETE FROM episodes WHERE {predicate}",
                (float(cutoff_ts),),
            )
            return int(cur.rowcount or 0)

    def total_spend(self, owner: str | None = None, *,
                    since: float | None = None) -> dict[str, float]:
        """Aggregate spend. ``owner`` scopes to one principal's runs (join to
        the owning goal); ``None`` is the deployment-wide admin / auth-off view.
        ``since`` keeps only runs that started at or after that time (the
        "this month" figure on the My work page and in the daily summary).
        """
        join = ("FROM episodes e JOIN goals g ON e.goal_id = g.id "
                if owner is not None else "FROM episodes e ")
        where = "WHERE e.ended_at IS NOT NULL"
        params: tuple = ()
        if owner is not None:
            where += " AND g.owner = ?"
            params = (owner,)
        if since is not None:
            where += " AND e.started_at >= ?"
            params = (*params, float(since))
        row = self._read_one(
            "SELECT COALESCE(SUM(e.cost_dollars), 0) AS dollars, "
            "COALESCE(SUM(e.input_tokens), 0) AS in_tok, "
            "COALESCE(SUM(e.output_tokens), 0) AS out_tok, "
            "COUNT(*) AS runs " + join + where,
            params,
        )
        return {
            "dollars": row["dollars"],
            "input_tokens": row["in_tok"],
            "output_tokens": row["out_tok"],
            "runs": row["runs"],
        }

    # ----- goal events -----
    def append_event(self, goal_id: int, agent: str, kind: str, content: str) -> int:
        with self._writing() as conn:
            cur = conn.execute(
                "INSERT INTO goal_events(goal_id, agent, kind, content, ts) VALUES(?, ?, ?, ?, ?)",
                (goal_id, agent, kind, _enc_field(content), time.time()),
            )
            self._goal_changed(goal_id)
            return cur.lastrowid

    def goal_events(self, goal_id: int, since_id: int = 0, limit: int = 200) -> list[GoalEvent]:
        rows = self._read_all(
            "SELECT id, goal_id, agent, kind, content, ts FROM goal_events "
            "WHERE goal_id = ? AND id > ? ORDER BY id ASC LIMIT ?",
            (goal_id, since_id, limit),
        )
        return _goal_events_from_rows(rows)

    def recent_goal_events(self, goal_id: int, limit: int = 200) -> list[GoalEvent]:
        """Return the latest goal events, preserving chronological order."""
        rows = self._read_all(
            "SELECT id, goal_id, agent, kind, content, ts FROM ("
            "SELECT id, goal_id, agent, kind, content, ts FROM goal_events "
            "WHERE goal_id = ? ORDER BY id DESC LIMIT ?"
            ") ORDER BY id ASC",
            (goal_id, limit),
        )
        return _goal_events_from_rows(rows)

    def recent_event_contents(self, limit: int = 5000) -> list[str]:
        """Coordination-message bodies across all goals (newest first), the corpus
        the emergent-protocol codebook learns from. Read-only."""
        rows = self._read_all(
            "SELECT content FROM goal_events ORDER BY id DESC LIMIT ?", (int(limit),))
        return [
            value
            for value in _dec_fields([r[0] for r in rows if r and r[0]])
            if value is not None
        ]

    def prune_goal_events(self, older_than_seconds: float = 30 * 24 * 3600) -> int:
        """Delete goal_events rows older than N seconds. Returns rows removed."""
        cutoff = time.time() - older_than_seconds
        with self._writing() as conn:
            cur = conn.execute("DELETE FROM goal_events WHERE ts < ?", (cutoff,))
            return cur.rowcount

    def purge_goal_events_before(
        self, cutoff_ts: float, *, dry_run: bool = False, review_binding: dict | None = None,
    ) -> int:
        """Count or delete goal events older than an absolute cutoff."""
        predicate = "ts IS NOT NULL AND ts < ?"
        with self._writing() as conn:
            if review_binding is not None:
                from .retention_review_bindings import guard_sql

                guard_sql(conn, "goal_events", predicate, (float(cutoff_ts),), review_binding, dry_run=dry_run)
                if dry_run:
                    return int(review_binding["count"])
            if dry_run:
                row = conn.execute(
                    f"SELECT COUNT(*) FROM goal_events WHERE {predicate}",
                    (float(cutoff_ts),),
                ).fetchone()
                return int(row[0] or 0)
            cur = conn.execute(
                f"DELETE FROM goal_events WHERE {predicate}",
                (float(cutoff_ts),),
            )
            return int(cur.rowcount or 0)

    def purge_messages_before(
        self, cutoff_ts: float, *, dry_run: bool = False, review_binding: dict | None = None,
    ) -> int:
        """Count or delete conversation messages older than an absolute cutoff.

        Unlike episodes, nothing references ``messages.id`` via a
        foreign key, so this is a plain age-based delete with no dangling
        provenance to null out first.
        """
        predicate = "ts IS NOT NULL AND ts < ?"
        with self._writing() as conn:
            if review_binding is not None:
                from .retention_review_bindings import guard_sql

                guard_sql(conn, "messages", predicate, (float(cutoff_ts),), review_binding, dry_run=dry_run)
                if dry_run:
                    return int(review_binding["count"])
            if dry_run:
                row = conn.execute(
                    f"SELECT COUNT(*) FROM messages WHERE {predicate}",
                    (float(cutoff_ts),),
                ).fetchone()
                return int(row[0] or 0)
            cur = conn.execute(
                f"DELETE FROM messages WHERE {predicate}",
                (float(cutoff_ts),),
            )
            return int(cur.rowcount or 0)

    # ----- facts -----
    @staticmethod
    def _open_temporal_fact(conn, key: str):
        """Return this key's one open history window under the write lock."""
        return conn.execute(
            "SELECT value, trust_tier, valid_from FROM fact_history "
            "WHERE key = ? AND valid_to IS NULL "
            "ORDER BY valid_from DESC LIMIT 1",
            (key,),
        ).fetchone()

    @staticmethod
    def _temporal_write_time(now: float, open_row) -> float:
        """Keep one key's validity intervals ordered through clock rollback."""
        if open_row is not None and now <= float(open_row[2]):
            return math.nextafter(float(open_row[2]), math.inf)
        return now

    def upsert_fact(
        self, key: str, value: str, episode_id: int | None = None,
        *, source: str = "", trust_tier: int = 3, sensitivity: str = "internal",
        expected_revision: int | None = None, tags: list[str] | None = None,
    ) -> int:
        """Write the current value of ``key``.

        ``source``/``trust_tier``/``sensitivity`` are Memory Guard provenance
        (see :mod:`maverick.memory_guard`); they default to first-party trust so
        existing internal callers are unaffected. When ``[memory] temporal`` is
        on, a *changed* value also appends a :class:`FactVersion` to
        ``fact_history`` and closes the prior open window -- non-destructive
        evolution. An unchanged value refreshes provenance without a new version.
        """
        from .fact_revision import normalize_tags
        _refuse_withheld_placeholder(value)
        encoded_tags = json.dumps(normalize_tags(tags)) if tags is not None else None
        now = time.time()
        enc = _enc_field(value)
        from .fact_revision import check_expected_revision
        with self._writing() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("SELECT id FROM facts WHERE key = ?", (key,)).fetchone()
            check_expected_revision(expected_revision, int(current[0]) if current else 0)
            if self._temporal_memory:
                prior = self._open_temporal_fact(conn, key)
                # A new version is recorded when the value changes OR the trust
                # tier changes -- a higher/lower-trust source re-asserting the
                # same value is a distinct belief worth its own audit window.
                changed = (
                    prior is None
                    or _dec_field(prior[0]) != value
                    or int(prior[1]) != int(trust_tier)
                )
                if changed:
                    # Temporal validity must never run backwards for this key,
                    # even if the host clock rolls back. Clamp against the
                    # indexed open-history row, not MAX(updated_at) over the
                    # entire facts table (which made bulk ingestion O(N^2)).
                    now = self._temporal_write_time(now, prior)
                    # Close the open window, then open a new one for this value:
                    # the prior value is preserved with the instant it stopped
                    # being current instead of being overwritten and lost.
                    conn.execute(
                        "UPDATE fact_history SET valid_to = ? "
                        "WHERE key = ? AND valid_to IS NULL",
                        (now, key),
                    )
                    conn.execute(
                        "INSERT INTO fact_history(key, value, source_episode_id, "
                        "valid_from, valid_to, source, trust_tier, sensitivity) "
                        "VALUES(?, ?, ?, ?, NULL, ?, ?, ?)",
                        (key, enc, episode_id, now, source, int(trust_tier),
                         sensitivity),
                    )
            conn.execute(
                "INSERT INTO facts(key, value, source_episode_id, updated_at, "
                "source, trust_tier, sensitivity) VALUES(?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET "
                "id = excluded.id, "
                "value = excluded.value, "
                "source_episode_id = excluded.source_episode_id, "
                "updated_at = excluded.updated_at, source = excluded.source, "
                "trust_tier = excluded.trust_tier, sensitivity = excluded.sensitivity",
                (key, enc, episode_id, now, source, int(trust_tier), sensitivity),
            )
            if encoded_tags is not None:
                conn.execute("UPDATE facts SET tags_json = ? WHERE key = ?", (encoded_tags, key))
            return int(conn.execute("SELECT id FROM facts WHERE key = ?", (key,)).fetchone()[0])

    def fact_record(self, key: str) -> dict | None:
        row = self._read_one(
            "SELECT key, value, id AS revision, updated_at, source, source_episode_id, "
            "trust_tier, sensitivity, tags_json FROM facts WHERE key = ?", (key,),
        )
        if not row:
            return None
        result = dict(row)
        result["value"] = _dec_field(result["value"])
        result["tags"] = json.loads(result.pop("tags_json"))
        return result

    def fact_records(self, *, query: str = "", source: str = "", tag: str = "",
                     updated_before: float | None = None, limit: int = 50,
                     offset: int = 0, shared_only: bool = False) -> list[dict]:
        """Bounded metadata-filtered page; encrypted values are not indexed."""
        clauses, params = [], []
        if shared_only:
            clauses.extend(("LOWER(key) NOT LIKE 'goal:%'", "LOWER(key) NOT LIKE 'user:%'"))
        for column, value in (("key", query), ("source", source)):
            if value:
                clauses.append(f"{column} LIKE ? ESCAPE '\\'")
                params.append("%" + self._like_escape(value) + "%")
        if updated_before is not None:
            clauses.append("updated_at < ?")
            params.append(float(updated_before))
        if tag:
            clauses.append("EXISTS (SELECT 1 FROM json_each(facts.tags_json) WHERE value = ?)")
            params.append(tag.strip().casefold())
        sql = ("SELECT key, value, id AS revision, updated_at, source, "
               "source_episode_id, trust_tier, sensitivity, tags_json FROM facts")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY key LIMIT ? OFFSET ?"
        rows = self._read_all(sql, (*params, max(1, min(limit, 101)), max(0, offset)))
        values = _dec_fields([row["value"] for row in rows])  # one policy and key lookup
        result = []
        for row, value in zip(rows, values, strict=True):
            item = dict(row)
            item["value"] = value
            item["tags"] = json.loads(item.pop("tags_json"))
            result.append(item)
        return result

    def fact_catalog_revision(self) -> str:
        """Metadata clock for shared facts; never decrypt or count private namespaces."""
        row = self._read_one("SELECT COUNT(*), COALESCE(MAX(id),0) FROM facts "
                             "WHERE LOWER(key) NOT LIKE 'goal:%' AND LOWER(key) NOT LIKE 'user:%'")
        return f"{row[0]}:{row[1]}"

    def get_facts(self) -> dict[str, str]:
        """All current facts as ``{key: value}``, newest first."""
        # ``id`` advances on both insert and upsert, so it is the durable
        # logical write clock. Wall time remains metadata/retention authority
        # and cannot reorder recall after an NTP or VM-clock rollback.
        rows = self._read_all(
            "SELECT key, value FROM facts ORDER BY id DESC"
        )
        values = _dec_fields([r["value"] for r in rows])
        return {r["key"]: value for r, value in zip(rows, values, strict=True)}

    def get_facts_with_trust(self) -> dict[str, tuple[str, int]]:
        """All current facts as ``{key: (value, trust_tier)}``, newest first --
        the provenance the Memory Guard filters on at recall (see
        :func:`maverick.memory_guard.filter_facts`)."""
        rows = self._read_all(
            "SELECT key, value, trust_tier FROM facts "
            "ORDER BY id DESC"
        )
        values = _dec_fields([r["value"] for r in rows])
        return {r["key"]: (value, int(r["trust_tier"]))
                for r, value in zip(rows, values, strict=True)}

    def facts_matching(self, token: str) -> dict[str, str]:
        """Facts explicitly scoped to ``token`` by key prefix.

        Facts are global key/value pairs with no per-user attribution.  To
        avoid disclosing or deleting unrelated global facts, GDPR export/erase
        only considers facts whose key is deliberately namespaced as
        ``user:<token>:<name>``.  Values are never searched and arbitrary
        substrings are ignored because short/common user ids can otherwise
        match unrelated secrets or other users' data.
        """
        if not token:
            return {}
        prefix = f"user:{token}:"
        return {k: v for k, v in self.get_facts().items() if k.startswith(prefix)}

    def delete_facts_matching(self, token: str) -> list[str]:
        """Delete explicitly user-scoped facts (see :meth:`facts_matching`).

        Returns the keys removed so the caller can report exactly what was
        scrubbed.
        """
        if not token:
            return []
        keys = sorted(self.facts_matching(token).keys())
        prefix = f"user:{token}:"
        with self._writing() as conn:
            if keys:
                ph = ",".join("?" * len(keys))
                conn.execute(f"DELETE FROM facts WHERE key IN ({ph})", keys)
            # GDPR Art.17: hard-purge the bitemporal history for the WHOLE
            # subject prefix -- not just the currently-live keys -- so a fact
            # that was individually deleted earlier (window closed, value
            # retained) is erased too and can't be recovered via
            # get_fact(as_of=...). No-op (empty table) when temporal is off.
            conn.execute(
                "DELETE FROM fact_history WHERE substr(key, 1, ?) = ?",
                (len(prefix), prefix),
            )
        return keys

    @staticmethod
    def _like_escape(s: str) -> str:
        """Escape LIKE wildcards so a key/query is matched literally."""
        return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def get_fact(self, key: str, *, as_of: float | None = None) -> str | None:
        """Single fact value by exact key, or None. Locked read.

        With ``as_of`` (a unix timestamp) the value is read from ``fact_history``
        as it stood at that instant (requires ``[memory] temporal``); returns
        None when no recorded version covered that time."""
        if as_of is not None:
            row = self._read_one(
                "SELECT value FROM fact_history WHERE key = ? AND valid_from <= ? "
                "AND (valid_to IS NULL OR valid_to > ?) "
                "ORDER BY valid_from DESC LIMIT 1",
                (key, as_of, as_of),
            )
            return _dec_field(row["value"]) if row else None
        row = self._read_one("SELECT value FROM facts WHERE key = ? LIMIT 1", (key,))
        return _dec_field(row["value"]) if row else None

    def fact_history(self, key: str, *, limit: int = 50,
                     owned_only: bool = False) -> list[FactVersion]:
        """Every recorded version of ``key``, newest first (requires ``[memory]
        temporal``). The entry whose ``valid_to is None`` is the current value;
        the rest are superseded values with the window they were believed in."""
        rows = self._read_all(
            "SELECT value, valid_from, valid_to, source, trust_tier, sensitivity "
            "FROM fact_history WHERE key = ? ORDER BY valid_from DESC LIMIT ?",
            (key, max(1, int(limit))),
        )
        return [
            FactVersion(
                value=_dec_field(r["value"]),
                valid_from=r["valid_from"],
                valid_to=r["valid_to"],
                source=r["source"] or "",
                trust_tier=int(r["trust_tier"]),
                sensitivity=r["sensitivity"] or "internal",
            )
            for r in rows
        ]

    def fact_history_matching(self, token: str) -> dict[str, list[FactVersion]]:
        """All recorded fact versions whose key is under ``user:<token>:`` -- the
        subject's historical fact values (including keys already removed from the
        live table), for the GDPR Art.15 right-of-access export. Empty unless
        ``[memory] temporal`` retained any history."""
        if not token:
            return {}
        prefix = f"user:{token}:"
        rows = self._read_all(
            "SELECT key, value, valid_from, valid_to, source, trust_tier, "
            "sensitivity FROM fact_history WHERE substr(key, 1, ?) = ? "
            "ORDER BY key, valid_from",
            (len(prefix), prefix),
        )
        out: dict[str, list[FactVersion]] = {}
        for r in rows:
            out.setdefault(r["key"], []).append(FactVersion(
                value=_dec_field(r["value"]),
                valid_from=r["valid_from"],
                valid_to=r["valid_to"],
                source=r["source"] or "",
                trust_tier=int(r["trust_tier"]),
                sensitivity=r["sensitivity"] or "internal",
            ))
        return out

    def delete_fact(self, key: str, *, expected_revision: int | None = None) -> int:
        """Delete one fact by exact key; return rows removed (0 or 1).

        When ``[memory] temporal`` is on, the open ``fact_history`` window is
        closed (valid_to = now) rather than erased, so the record that the fact
        existed until this moment survives the delete."""
        from .fact_revision import check_expected_revision
        with self._writing() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("SELECT id FROM facts WHERE key = ?", (key,)).fetchone()
            check_expected_revision(expected_revision, int(current[0]) if current else 0)
            if self._temporal_memory:
                open_row = self._open_temporal_fact(conn, key)
                closed_at = self._temporal_write_time(time.time(), open_row)
                conn.execute(
                    "UPDATE fact_history SET valid_to = ? "
                    "WHERE key = ? AND valid_to IS NULL",
                    (closed_at, key),
                )
            return conn.execute("DELETE FROM facts WHERE key = ?", (key,)).rowcount

    def stale_fact_keys(self, older_than: float, limit: int = 500) -> list[str]:
        """Keys of facts not updated since ``older_than``, oldest first.

        Read-only; the dreaming fact-consolidation phase decides what to
        delete (and is itself opt-in)."""
        rows = self._read_all(
            "SELECT key FROM facts WHERE updated_at < ? "
            "ORDER BY updated_at ASC, id ASC LIMIT ?",
            (older_than, max(1, int(limit))),
        )
        return [r["key"] for r in rows]

    def count_facts(self) -> int:
        row = self._read_one("SELECT COUNT(*) AS n FROM facts", ())
        return int(row["n"]) if row else 0

    def list_facts(self, key_prefix: str, limit: int = 50) -> list[tuple[str, int]]:
        """``(key, value_size)`` for facts whose key starts with ``key_prefix``,
        newest first. Locked read; the prefix is LIKE-escaped."""
        like = self._like_escape(key_prefix) + "%"
        rows = self._read_all(
            "SELECT key, length(value) AS sz FROM facts "
            "WHERE key LIKE ? ESCAPE '\\' "
            "ORDER BY id DESC LIMIT ?",
            (like, limit),
        )
        return [(r["key"], r["sz"]) for r in rows]

    def search_facts(
        self, key_prefix: str, query: str, limit: int = 50,
    ) -> list[tuple[str, str]]:
        """``(key, value)`` for facts under ``key_prefix`` whose key or value
        contains ``query`` (literal substring), newest first. Locked read."""
        pfx = self._like_escape(key_prefix) + "%"
        from .crypto_at_rest import at_rest_enabled
        if not at_rest_enabled():
            q = "%" + self._like_escape(query) + "%"
            rows = self._read_all(
                "SELECT key, value FROM facts WHERE key LIKE ? ESCAPE '\\' "
                "AND (key LIKE ? ESCAPE '\\' OR value LIKE ? ESCAPE '\\') "
                "ORDER BY id DESC LIMIT ?",
                (pfx, q, q, limit),
            )
            return [(r["key"], _dec_field(r["value"])) for r in rows]
        # Encryption on: `value` is sealed ciphertext, so a SQL LIKE over it can
        # never match the plaintext query (the search would silently return
        # nothing). Keys are stored plaintext, so narrow the scan by prefix in
        # SQL, then decrypt and substring-match in Python. Case-insensitive to
        # match SQLite LIKE's ASCII semantics on the plaintext path.
        rows = self._read_all(
            "SELECT key, value FROM facts WHERE key LIKE ? ESCAPE '\\' "
            "ORDER BY id DESC",
            (pfx,),
        )
        needle = query.lower()
        out: list[tuple[str, str]] = []
        for r in rows:
            val = _dec_field(r["value"])
            if needle in r["key"].lower() or (val is not None and needle in val.lower()):
                out.append((r["key"], val))
                if len(out) >= limit:
                    break
        return out

    # ----- questions -----
    def ask(self, question: str, goal_id: int | None = None) -> int:
        with self._writing() as conn:
            cur = conn.execute(
                "INSERT INTO questions(goal_id, question, asked_at) VALUES(?, ?, ?)",
                (goal_id, _enc_field(question), time.time()),
            )
            return cur.lastrowid

    def answer(
        self,
        question_id: int,
        answer: str,
        *,
        expected_owner: str | None = None,
    ) -> bool:
        """Record an answer to a question. Returns False if no question with
        that id exists, so callers can flag a typo'd id instead of reporting
        a false success.

        ``expected_owner`` binds the mutation to the parent goal's owner in
        the same SQL statement.  This is the object-level authorization seam
        used by network adapters; a missing, ownerless, or foreign question is
        deliberately the same zero-row result.
        """
        sql = "UPDATE questions SET answer = ?, answered_at = ? WHERE id = ?"
        params: tuple[Any, ...] = (
            _enc_field(answer),
            time.time(),
            question_id,
        )
        if expected_owner is not None:
            sql += (
                " AND goal_id IN ("
                "SELECT id FROM goals WHERE owner = ?"
                ")"
            )
            params += (str(expected_owner),)
        with self._writing() as conn:
            cur = conn.execute(sql, params)
            return cur.rowcount > 0

    def open_questions(self, goal_id: int | None = None) -> list[Question]:
        if goal_id is not None:
            rows = self._read_all(
                "SELECT * FROM questions WHERE answer IS NULL AND goal_id = ? ORDER BY id", (goal_id,)
            )
        else:
            rows = self._read_all(
                "SELECT * FROM questions WHERE answer IS NULL ORDER BY id"
            )
        return [_question_from_row(r) for r in rows]

    def open_channel_questions(
        self, conversation_id: int, owner: str, execution_principal: str,
    ) -> list[Question]:
        """Only questions from blocked goals started in this exact conversation."""
        rows = self._read_all(
            "SELECT q.* FROM questions q JOIN goals g ON g.id = q.goal_id "
            "WHERE q.answer IS NULL AND g.status = 'blocked' "
            "AND g.owner = ? AND g.execution_principal = ? "
            "AND EXISTS (SELECT 1 FROM turns t WHERE t.goal_id = g.id "
            "AND t.conversation_id = ? AND t.role = 'user') ORDER BY q.id",
            (owner, execution_principal, conversation_id),
        )
        return [_question_from_row(r) for r in rows]

    def answer_open_channel_question(
        self, question_id: int, goal_id: int, answer: str, *,
        conversation_id: int, owner: str, execution_principal: str,
    ) -> bool:
        """Claim an exact open question once, with its conversation and owner."""
        with self._writing() as conn:
            changed = conn.execute(
                "UPDATE questions SET answer = ?, answered_at = ? "
                "WHERE id = ? AND goal_id = ? AND answer IS NULL "
                "AND EXISTS (SELECT 1 FROM goals g WHERE g.id = questions.goal_id "
                "AND g.status = 'blocked' AND g.owner = ? "
                "AND g.execution_principal = ? "
                "AND EXISTS (SELECT 1 FROM turns t WHERE t.goal_id = g.id "
                "AND t.conversation_id = ? AND t.role = 'user'))",
                (_enc_field(answer), time.time(), question_id, goal_id,
                 owner, execution_principal, conversation_id),
            )
            return changed.rowcount == 1

    def all_questions(self, goal_id: int) -> list[Question]:
        rows = self._read_all(
            "SELECT * FROM questions WHERE goal_id = ? ORDER BY id", (goal_id,)
        )
        return [_question_from_row(r) for r in rows]

    # ----- approvals (high-risk action queue) -----
    def create_approval(
        self,
        action: str,
        *,
        risk: str = "medium",
        scope: str | None = None,
        detail: str | None = None,
        provenance: str | None = None,
        approvals_required: int = 1,
        requested_by: str | None = None,
        undoable: bool = False,
    ) -> int:
        """Park a high-risk action for out-of-band (dashboard) approval.

        ``provenance`` is trusted caller-supplied metadata used by operator UIs;
        it must not be inferred from ``detail``, which may contain untrusted
        model, user, or remote-server text.

        ``approvals_required`` is the quorum (N) of DISTINCT approvers needed
        before the action is granted (segregation of duties; 1 = legacy single
        approver). ``requested_by`` is the requesting principal, so a multi-party
        approval can bar the requester from approving their own request.
        ``undoable`` is only for a requester that waits out the undo window
        before acting on a decision (the consent wait, which then calls
        :meth:`settle_approval_decision`); every other decision is final.
        """
        from .logging_config import current_goal_id

        context_goal = current_goal_id()
        with self._writing() as conn:
            goal = conn.execute("SELECT id, domain FROM goals WHERE id = ?", (context_goal,)).fetchone()
            cur = conn.execute(
                "INSERT INTO approvals(action, risk, scope, detail, provenance, "
                "status, requested_at, approvals_required, requested_by, goal_id, department, "
                "undo_hold) VALUES(?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)",
                (_enc_field(action), risk, _enc_field(scope), _enc_field(detail),
                 provenance, time.time(), max(1, int(approvals_required)),
                 (requested_by or None), goal["id"] if goal else None,
                 goal["domain"] if goal else "",
                 APPROVAL_UNDO_OPEN if undoable else None),
            )
            approval_id = cur.lastrowid
        _notify_approval_created(self, approval_id, provenance)
        self._emit_approval_event("approval.created", approval_id, {"risk": risk, "action": action})
        return approval_id

    def _emit_approval_event(self, event: str, approval_id: int, payload: dict) -> None:
        """Webhook subscribers hear about approvals; never raises, and costs one
        read of the subscription table when nobody is subscribed."""
        try:
            from .webhook_events import emit, record_link

            emit(event, record_type="approval", record_id=str(approval_id),
                 title=str(payload.get("action") or "approval")[:200],
                 summary={k: v for k, v in payload.items() if k != "action"},
                 link=record_link("/approvals"), payload=dict(payload), world=self)
        except Exception:  # pragma: no cover - webhooks never block an approval
            pass

    def get_approval(self, approval_id: int, *, strict_tenant: bool = False) -> Approval | None:
        row = self._read_one(
            "SELECT * FROM approvals WHERE id = ?", (approval_id,)
        )
        return _approval_from_row(row) if row else None

    def list_approvals(self, limit: int = 500) -> list[Approval]:
        """All approvals, newest first (the Operating Record's human-decision
        feed); ``pending_approvals`` remains the queue view."""
        rows = self._read_all(
            "SELECT * FROM approvals ORDER BY requested_at DESC, id DESC LIMIT ?",
            (max(1, int(limit)),),
        )
        return _approvals_from_rows(rows)

    def approvals_requested_between(self, since: float, until: float) -> list[Approval]:
        """Approvals with ``since <= requested_at <= until``, in the order
        :meth:`list_approvals` returns them. The window is applied in SQL, so
        rows outside it are never decrypted (the audit binder reads one window)."""
        rows = self._read_all(
            "SELECT * FROM approvals WHERE requested_at >= ? AND requested_at <= ? "
            "ORDER BY requested_at DESC, id DESC",
            (float(since), float(until)),
        )
        return _approvals_from_rows(rows)

    def pending_unattached_approval_ids(self, owner: str, *, limit: int) -> list[int]:
        rows = self._read_all(
            "SELECT id FROM approvals WHERE status='pending' AND goal_id IS NULL "
            "AND requested_by=? ORDER BY id DESC LIMIT ?", (owner, max(1, int(limit))),
        )
        return [int(row[0]) for row in rows]

    def pending_goal_approval_ids(self, goal_ids: list[int], *, limit: int) -> list[int]:
        if not goal_ids:
            return []
        marks = ",".join("?" for _ in goal_ids)
        rows = self._read_all(
            f"SELECT id FROM approvals WHERE status='pending' AND goal_id IN ({marks}) "
            "ORDER BY id DESC LIMIT ?", (*goal_ids, max(1, int(limit))),
        )
        return [int(row[0]) for row in rows]

    def pending_approvals(self) -> list[Approval]:
        rows = self._read_all(
            "SELECT * FROM approvals WHERE status = 'pending' ORDER BY id"
        )
        return _approvals_from_rows(rows)

    def approval_audit_event_id(
        self,
        approval_id: int,
        status: str,
        decided_by: str,
    ) -> str:
        """Deterministic idempotency id for an exact approval vote."""
        return _approval_audit_event_id(
            current_tenant_id(),
            approval_id,
            status,
            (decided_by or "").strip(),
            self._approval_undo_round(approval_id),
        )

    def _approval_undo_round(self, approval_id: int, conn=None) -> int:
        """How many times this approval was undone (see ``undo_approval_decision``)."""
        sql = (
            "SELECT COUNT(*) FROM approval_audit_outbox "
            "WHERE approval_id = ? AND status = ?"
        )
        params = (int(approval_id), APPROVAL_UNDO_STATUS)
        row = conn.execute(sql, params).fetchone() if conn is not None else self._read_one(sql, params)
        return int(row[0]) if row else 0

    def settle_approval_decision(self, approval_id: int, *, decided_before: float) -> Approval | None:
        """The waiting task is about to act on this decision: make it final.

        Only a decision made at or before ``decided_before`` (the end of the
        task's own undo window) is settled. Returns the approval as it stands:
        when settled, an undo from now on is refused (``"too_late"``), whatever
        window the page that offers it reads; when an undo got there first it
        is pending again, and a decision made again since then is still
        ``undo_hold == "open"``, so the task keeps waiting.
        """
        with self._writing() as conn:
            conn.execute(
                "UPDATE approvals SET undo_hold = ? WHERE id = ? AND status <> 'pending' "
                "AND undo_hold = ? AND decided_at <= ?",
                (APPROVAL_UNDO_SETTLED, int(approval_id), APPROVAL_UNDO_OPEN, float(decided_before)),
            )
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (int(approval_id),)).fetchone()
        return _approval_from_row(row) if row else None

    def undo_approval_decision(
        self,
        approval_id: int,
        *,
        undone_by: str,
        within_seconds: float,
    ) -> str:
        """Return a just-decided approval to pending while it can still be undone.

        Outcomes: ``"undone"``, ``"not_found"``, ``"not_decided"`` (still
        pending, or its final vote is awaiting audit delivery), ``"too_late"``
        (the window of ``within_seconds`` after ``decided_at`` has passed, or
        the waiting task already acted on it), ``"final"`` (no waiting task
        holds this request, or the system decided it; see
        :func:`approval_undo_refusal`). On success the sign-offs are
        cleared, the delivered vote rows keep their place in the outbox but no
        longer carry a final status, and an undo marker row bumps the vote
        identity round so the next decision is a new signed audit event.
        """
        with self._writing() as conn:
            row = conn.execute(
                "SELECT status, decided_at, decided_by, undo_hold, action FROM approvals WHERE id = ?",
                (int(approval_id),),
            ).fetchone()
            if row is None:
                return "not_found"
            if row["status"] == "pending":
                return "not_decided"
            refusal = approval_undo_refusal(row["status"], row["decided_by"], row["undo_hold"])
            if refusal is not None:
                return refusal
            decided_at = row["decided_at"]
            if decided_at is None or time.time() - float(decided_at) >= float(within_seconds):
                return "too_late"
            conn.execute(
                "UPDATE approvals SET status = 'pending', decided_at = NULL, "
                "decided_by = NULL WHERE id = ? AND status = ? AND undo_hold = ?",
                (int(approval_id), row["status"], APPROVAL_UNDO_OPEN),
            )
            conn.execute(
                "DELETE FROM approval_signoffs WHERE approval_id = ?",
                (int(approval_id),),
            )
            conn.execute(
                "UPDATE approval_audit_outbox SET final_status = NULL "
                "WHERE approval_id = ? AND status IN ('approved', 'denied')",
                (int(approval_id),),
            )
            undo_round = self._approval_undo_round(approval_id, conn) + 1
            now = time.time()
            conn.execute(
                "INSERT INTO approval_audit_outbox("
                "event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at) VALUES(?, ?, ?, ?, NULL, ?, ?)",
                (
                    _approval_undo_marker_id(current_tenant_id(), approval_id, undo_round),
                    int(approval_id),
                    APPROVAL_UNDO_STATUS,
                    (undone_by or "").strip(),
                    now,
                    now,
                ),
            )
        # approval.decided already went out; subscribers learn it was retracted.
        self._emit_approval_event("approval.undone", int(approval_id), {
            "previous_status": row["status"], "undone_by": (undone_by or "").strip(),
            "action": _dec_field(row["action"])})
        return "undone"

    def get_approval_audit_event(
        self,
        event_id: str,
    ) -> ApprovalAuditEvent | None:
        row = self._read_one(
            "SELECT event_id, approval_id, status, decided_by, final_status, "
            "created_at, delivered_at FROM approval_audit_outbox "
            "WHERE event_id = ?",
            (str(event_id),),
        )
        return _approval_audit_event_from_row(row) if row else None

    def pending_approval_audit_events(
        self,
        *,
        approval_id: int | None = None,
        limit: int = 100,
    ) -> list[ApprovalAuditEvent]:
        """Undelivered approval audit events, oldest first."""
        sql = (
            "SELECT event_id, approval_id, status, decided_by, final_status, "
            "created_at, delivered_at FROM approval_audit_outbox "
            "WHERE delivered_at IS NULL"
        )
        params: tuple[Any, ...] = ()
        if approval_id is not None:
            sql += " AND approval_id = ?"
            params = (int(approval_id),)
        sql += " ORDER BY created_at, event_id LIMIT ?"
        params += (max(1, min(int(limit), 1000)),)
        return [
            _approval_audit_event_from_row(row)
            for row in self._read_all(sql, params)
        ]

    def approval_has_pending_finalization(self, approval_id: int) -> bool:
        """Whether an accepted final vote is waiting on signed audit delivery."""
        row = self._read_one(
            "SELECT 1 FROM approval_audit_outbox "
            "WHERE approval_id = ? AND final_status IS NOT NULL "
            "AND delivered_at IS NULL LIMIT 1",
            (int(approval_id),),
        )
        return row is not None

    @staticmethod
    def _check_effect_guard(effect_guard):
        if effect_guard is not None:
            effect_guard()

    def decide_approval_audited(
        self,
        approval_id: int,
        status: str,
        *,
        decided_by: str,
        reviewed_card: dict | None = None,
        effect_guard=None,
    ) -> ApprovalAuditEvent | None:
        """Atomically accept a vote and queue its signed-audit delivery.

        Unlike :meth:`decide_approval`, this does not make a final approval
        effective in the same transaction.  It records the sign-off plus a
        deterministic outbox event together, and
        :meth:`mark_approval_audit_delivered` applies the final status only once
        every event for this approval has reached the audit chain.

        A retry of the same ``(approval, status, supervisor)`` returns the
        original event even if the approval is now final.  That makes a retry
        safe after a database commit acknowledgement is lost.
        """
        if status not in ("approved", "denied"):
            raise ValueError("status must be 'approved' or 'denied'")
        approver = (decided_by or "").strip()
        if not approver:
            return None
        with self._writing() as conn:
            # The no-op write acquires SQLite's cross-process write reservation
            # before any decision read.  A SELECT-first deferred transaction can
            # otherwise race another process and fail with BUSY_SNAPSHOT.
            pending = conn.execute(
                "UPDATE approvals SET status = status "
                "WHERE id = ? AND status = 'pending'",
                (int(approval_id),),
            ).rowcount > 0
            self._check_effect_guard(effect_guard)
            undo_round = self._approval_undo_round(approval_id, conn)
            event_id = _approval_audit_event_id(
                current_tenant_id(), approval_id, status, approver, undo_round,
            )

            if reviewed_card is not None:
                from .approval_vote_review import require_locked_vote_review

                locked = conn.execute("SELECT * FROM approvals WHERE id = ?", (int(approval_id),)).fetchone()
                approval = _approval_from_row(locked) if locked is not None else None
                signoffs = conn.execute("SELECT approver, decision FROM approval_signoffs WHERE approval_id = ? ORDER BY decided_at", (int(approval_id),)).fetchall()
                approvers = _single_approver(approval, [row["approver"] for row in signoffs if row["decision"] == "approved"]) if approval is not None else []
                audit_pending = int(conn.execute("SELECT COUNT(*) FROM approval_audit_outbox WHERE approval_id = ? AND delivered_at IS NULL", (int(approval_id),)).fetchone()[0])
                content_owner = (approval.requested_by or "") if approval is not None else None
                if approval is not None and approval.goal_id:
                    source = conn.execute("SELECT owner,domain FROM goals WHERE id = ?", (approval.goal_id,)).fetchone()
                    content_owner = (source["owner"] or "") if source is not None else None
                    source_guard = getattr(effect_guard, "approval_source", None)
                    if source_guard is not None:
                        source_guard(approval.goal_id, content_owner, source["domain"] if source is not None else None)
                require_locked_vote_review(approval, reviewed_card, status=status, actor=approver,
                                           event_id=event_id, approvers=approvers, audit_pending=audit_pending,
                                           content_owner=content_owner)

            prior = conn.execute(
                "SELECT event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at FROM approval_audit_outbox "
                "WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if prior is not None:
                prior_event = _approval_audit_event_from_row(prior)
                if not prior_event.matches(approval_id, status, approver):
                    raise RuntimeError(
                        "approval audit outbox event identity is corrupt"
                    )
                return prior_event
            if not pending:
                return None

            row = conn.execute(
                "SELECT approvals_required, requested_by "
                "FROM approvals WHERE id = ? AND status = 'pending'",
                (int(approval_id),),
            ).fetchone()
            if row is None:
                return None

            # Once a vote has selected a final outcome, freeze the approval
            # while its audit row is pending.  A competing approve/deny must not
            # race the signed authority boundary.
            if conn.execute(
                "SELECT 1 FROM approval_audit_outbox "
                "WHERE approval_id = ? AND final_status IS NOT NULL "
                "AND delivered_at IS NULL LIMIT 1",
                (int(approval_id),),
            ).fetchone() is not None:
                return None

            required = max(1, int(row["approvals_required"] or 1))
            requested_by = row["requested_by"]
            if (
                required > 1
                and status == "approved"
                and requested_by
                and approver == requested_by
            ):
                from .safety.dual_control import allow_self_approval

                if not allow_self_approval():
                    return None

            now = time.time()
            final_status: str | None = None
            if required <= 1:
                final_status = status
            else:
                # Upgrade seam: v21-v29 could leave a pending N-of-M approval
                # with one or more signoffs but no transactional outbox rows.
                # Queue those historical votes before accepting a new one, so
                # a quorum can never become effective with only its last vote
                # represented in the signed chain.
                for legacy in conn.execute(
                    "SELECT approver, decision, decided_at "
                    "FROM approval_signoffs WHERE approval_id = ? "
                    "ORDER BY decided_at, approver",
                    (int(approval_id),),
                ).fetchall():
                    legacy_event_id = _approval_audit_event_id(
                        current_tenant_id(),
                        approval_id,
                        legacy["decision"],
                        legacy["approver"],
                        undo_round,
                    )
                    conn.execute(
                        "INSERT OR IGNORE INTO approval_audit_outbox("
                        "event_id, approval_id, status, decided_by, final_status, "
                        "created_at, delivered_at) "
                        "VALUES(?, ?, ?, ?, NULL, ?, NULL)",
                        (
                            legacy_event_id,
                            int(approval_id),
                            legacy["decision"],
                            legacy["approver"],
                            float(legacy["decided_at"]),
                        ),
                    )
                prior = conn.execute(
                    "SELECT event_id, approval_id, status, decided_by, final_status, "
                    "created_at, delivered_at FROM approval_audit_outbox "
                    "WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if prior is not None:
                    prior_event = _approval_audit_event_from_row(prior)
                    if not prior_event.matches(approval_id, status, approver):
                        raise RuntimeError(
                            "approval audit outbox event identity is corrupt"
                        )
                    return prior_event

                existing_signoff = conn.execute(
                    "SELECT decision FROM approval_signoffs "
                    "WHERE approval_id = ? AND approver = ?",
                    (int(approval_id), approver),
                ).fetchone()
                # A signed human vote is immutable.  The old immediate method
                # retains its compatibility semantics, but the governed
                # dashboard path never silently rewrites one decision into the
                # opposite decision.
                if (
                    existing_signoff is not None
                    and existing_signoff["decision"] != status
                ):
                    return None
                conn.execute(
                    "INSERT INTO approval_signoffs(approval_id, approver, decision, "
                    "decided_at) VALUES(?, ?, ?, ?) "
                    "ON CONFLICT(approval_id, approver) DO NOTHING",
                    (int(approval_id), approver, status, now),
                )
                if status == "denied":
                    final_status = "denied"
                else:
                    approved = conn.execute(
                        "SELECT COUNT(*) FROM approval_signoffs "
                        "WHERE approval_id = ? AND decision = 'approved'",
                        (int(approval_id),),
                    ).fetchone()[0]
                    if approved >= required:
                        final_status = "approved"

            conn.execute(
                "INSERT INTO approval_audit_outbox("
                "event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at) VALUES(?, ?, ?, ?, ?, ?, NULL)",
                (
                    event_id,
                    int(approval_id),
                    status,
                    approver,
                    final_status,
                    now,
                ),
            )
            result = ApprovalAuditEvent(
                event_id=event_id,
                approval_id=int(approval_id),
                status=status,
                decided_by=approver,
                final_status=final_status,
                created_at=now,
                delivered_at=None,
            )
            self._check_effect_guard(effect_guard)
            return result

    def mark_approval_audit_delivered(
        self,
        event_id: str,
        *,
        delivered_at: float | None = None,
        effect_guard=None,
    ) -> bool:
        """Acknowledge signed delivery and apply any now-safe final outcome.

        The delivery marker and final approval update share one transaction.
        Repeating the call is idempotent.  If an audit append succeeded but the
        commit acknowledgement is lost, the caller can safely append the same
        stable ``event_id`` again and retry this method.
        """
        finalized: tuple[str, str] | None = None
        with self._writing() as conn:
            if effect_guard is not None:
                conn.execute("UPDATE approval_audit_outbox SET delivered_at=delivered_at WHERE event_id=?", (str(event_id),))
                effect_guard()
            event = conn.execute(
                "SELECT event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at FROM approval_audit_outbox "
                "WHERE event_id = ?",
                (str(event_id),),
            ).fetchone()
            if event is None:
                return False
            source_guard = getattr(effect_guard, "approval_source", None)
            if source_guard is not None:
                source = conn.execute("SELECT g.id,g.owner,g.domain FROM approvals a JOIN goals g ON g.id=a.goal_id WHERE a.id=?", (event["approval_id"],)).fetchone()
                if source is None:
                    raise PermissionError("The original approval task is unavailable")
                source_guard(source[0], source[1] or "", source[2])
            if event["delivered_at"] is None:
                conn.execute(
                    "UPDATE approval_audit_outbox SET delivered_at = ? "
                    "WHERE event_id = ? AND delivered_at IS NULL",
                    (
                        float(delivered_at)
                        if delivered_at is not None
                        else time.time(),
                        str(event_id),
                    ),
                )

            approval_id = int(event["approval_id"])
            still_pending = conn.execute(
                "SELECT 1 FROM approval_audit_outbox "
                "WHERE approval_id = ? AND delivered_at IS NULL LIMIT 1",
                (approval_id,),
            ).fetchone()
            if still_pending is None:
                final = conn.execute(
                    "SELECT final_status, decided_by, created_at "
                    "FROM approval_audit_outbox "
                    "WHERE approval_id = ? AND final_status IS NOT NULL "
                    "ORDER BY created_at DESC, event_id DESC LIMIT 1",
                    (approval_id,),
                ).fetchone()
                if final is not None:
                    applied = conn.execute(
                        "UPDATE approvals SET status = ?, decided_at = ?, "
                        "decided_by = ? WHERE id = ? AND status = 'pending'",
                        (
                            final["final_status"],
                            float(final["created_at"]),
                            final["decided_by"],
                            approval_id,
                        ),
                    ).rowcount
                    if applied:
                        finalized = (final["final_status"], final["decided_by"])
            self._check_effect_guard(effect_guard)
        # Subscribers hear of the decision only once the guard has passed and the
        # transaction has committed; a rollback must not leave "approved" sent.
        if finalized is not None:
            self._emit_approval_event("approval.decided", approval_id,
                                      {"status": finalized[0], "decided_by": finalized[1] or ""})
        return True

    def decide_approval(self, approval_id: int, status: str,
                        decided_by: str | None = None) -> bool:
        """Record one approver's decision on a pending approval.

        Single-approver (``approvals_required <= 1``, the default): flips the row
        to 'approved'/'denied' atomically, exactly as before.

        N-of-M (``approvals_required > 1``): records this approver's sign-off and
        applies **segregation of duties** — a ``denied`` vote rejects immediately;
        an ``approved`` vote counts toward the quorum and the row flips to
        'approved' only once N **distinct** approvers have approved. The requester
        cannot approve their own request unless ``allow_self_approval`` is set.

        Returns True when the vote was accepted (recorded and/or final), False on
        an unknown/already-decided id, a self-approval that is barred, or a
        multi-party vote with no ``decided_by`` (an approver identity is required
        to enforce distinctness). Once :meth:`decide_approval_audited` has
        created an outbox row for an approval, this legacy immediate path also
        returns False; every later vote must remain behind the same signed-audit
        authority boundary.
        """
        if status not in ("approved", "denied"):
            raise ValueError("status must be 'approved' or 'denied'")
        appr = self.get_approval(approval_id)
        if appr is None or appr.status != "pending":
            return False
        required = max(1, int(getattr(appr, "approvals_required", 1) or 1))
        if required <= 1:
            with self._writing() as conn:
                cur = conn.execute(
                    "UPDATE approvals SET status = ?, decided_at = ?, decided_by = ? "
                    "WHERE id = ? AND status = 'pending' "
                    "AND NOT EXISTS (SELECT 1 FROM approval_audit_outbox "
                    "WHERE approval_id = ?)",
                    (
                        status,
                        time.time(),
                        decided_by,
                        approval_id,
                        approval_id,
                    ),
                )
                decided = cur.rowcount > 0
            if decided:
                self._emit_approval_event("approval.decided", approval_id,
                                          {"status": status, "decided_by": decided_by or "",
                                           "action": appr.action})
            return decided

        approver = (decided_by or "").strip()
        if not approver:
            return False   # distinctness needs an attributed approver
        if (status == "approved" and appr.requested_by
                and approver == appr.requested_by):
            from .safety.dual_control import allow_self_approval
            if not allow_self_approval():
                return False   # segregation of duties: no self-approval
        now = time.time()
        with self._writing() as conn:
            # Once the governed dashboard path has queued any audit event, all
            # later votes must stay on that path. This prevents a legacy caller
            # from bypassing the signed-delivery gate between quorum votes.
            locked = conn.execute(
                "UPDATE approvals SET status = status "
                "WHERE id = ? AND status = 'pending'",
                (approval_id,),
            ).rowcount > 0
            if not locked:
                return False
            if conn.execute(
                "SELECT 1 FROM approval_audit_outbox "
                "WHERE approval_id = ? LIMIT 1",
                (approval_id,),
            ).fetchone() is not None:
                return False
            # PK (approval_id, approver) makes a given approver count once; a
            # repeat vote from the same approver updates their recorded decision.
            conn.execute(
                "INSERT INTO approval_signoffs(approval_id, approver, decision, "
                "decided_at) VALUES(?, ?, ?, ?) "
                "ON CONFLICT(approval_id, approver) DO UPDATE SET "
                "decision = excluded.decision, decided_at = excluded.decided_at",
                (approval_id, approver, status, now),
            )
            if status == "denied":
                conn.execute(
                    "UPDATE approvals SET status = 'denied', decided_at = ?, "
                    "decided_by = ? WHERE id = ? AND status = 'pending'",
                    (now, approver, approval_id),
                )
                return True
            approved = conn.execute(
                "SELECT COUNT(*) FROM approval_signoffs "
                "WHERE approval_id = ? AND decision = 'approved'",
                (approval_id,),
            ).fetchone()[0]
            if approved >= required:
                conn.execute(
                    "UPDATE approvals SET status = 'approved', decided_at = ?, "
                    "decided_by = ? WHERE id = ? AND status = 'pending'",
                    (now, approver, approval_id),
                )
            return True

    def approval_state(self, approval_id: int) -> dict | None:
        """Quorum progress for an approval, or None if unknown. Shape:
        ``{status, approvals_required, approved_count, approvers, requested_by}``
        -- the operator/UI view of an in-flight N-of-M decision."""
        appr = self.get_approval(approval_id)
        if appr is None:
            return None
        rows = self._read_all(
            "SELECT approver, decision FROM approval_signoffs "
            "WHERE approval_id = ? ORDER BY decided_at, approver", (approval_id,),
        )
        approvers = [r["approver"] for r in rows if r["decision"] == "approved"]
        approvers = _single_approver(appr, approvers)
        audit_pending = int(
            self._read_one(
                "SELECT COUNT(*) FROM approval_audit_outbox "
                "WHERE approval_id = ? AND delivered_at IS NULL",
                (approval_id,),
            )[0]
        )
        return _approval_state_view(appr, approvers, audit_pending)

    def approval_states(self, approvals) -> dict[int, dict]:
        """:meth:`approval_state` for approvals the caller has already listed,
        in two queries for the whole set instead of three per approval (the
        audit binder spent ~1.2 ms per approval re-reading each one). Each
        value equals ``approval_state(id)`` for that approval."""
        listed = {int(a.id): a for a in approvals}
        approvers: dict[int, list[str]] = {approval_id: [] for approval_id in listed}
        pending: dict[int, int] = dict.fromkeys(listed, 0)
        ids = list(listed)
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            for approval_id, approver, decision in self._read_all(
                "SELECT approval_id, approver, decision FROM approval_signoffs "
                f"WHERE approval_id IN ({marks}) ORDER BY decided_at, approver",
                tuple(chunk),
            ):
                if decision == "approved":
                    approvers[approval_id].append(approver)
            for approval_id, count in self._read_all(
                "SELECT approval_id, COUNT(*) FROM approval_audit_outbox "
                f"WHERE approval_id IN ({marks}) AND delivered_at IS NULL "
                "GROUP BY approval_id",
                tuple(chunk),
            ):
                pending[approval_id] = int(count)
        return {
            approval_id: _approval_state_view(
                appr, _single_approver(appr, approvers[approval_id]), pending[approval_id]
            )
            for approval_id, appr in listed.items()
        }

    def claim_approval(self, approval_id: int, principal: str) -> bool:
        """Atomically claim a pending approval for one supervisor.

        Collaborative supervision: a claim marks "I'm handling this" so two
        supervisors don't double-work the same review. Succeeds when the row
        is pending and unclaimed (or already claimed by the SAME principal —
        re-claiming your own claim is a no-op refresh). Returns False when
        someone else holds it, it's decided, or the id is unknown.
        """
        principal = (principal or "").strip()
        if not principal:
            raise ValueError("principal is required to claim an approval")
        with self._writing() as conn:
            cur = conn.execute(
                "UPDATE approvals SET claimed_by = ?, claimed_at = ? "
                "WHERE id = ? AND status = 'pending' "
                "AND (claimed_by IS NULL OR claimed_by = ?)",
                (principal, time.time(), approval_id, principal),
            )
            return cur.rowcount > 0

    def release_approval(self, approval_id: int, principal: str) -> bool:
        """Release a claim you hold (pending rows only). Only the claim
        holder can release; returns False otherwise."""
        principal = (principal or "").strip()
        if not principal:
            raise ValueError("principal is required to release an approval")
        with self._writing() as conn:
            cur = conn.execute(
                "UPDATE approvals SET claimed_by = NULL, claimed_at = NULL "
                "WHERE id = ? AND status = 'pending' AND claimed_by = ?",
                (approval_id, principal),
            )
            return cur.rowcount > 0

    # ----- messages -----
    def append_message(self, goal_id: int, role: str, content: str) -> None:
        # v49 retires the unused ciphertext-derived FTS index, preserving this
        # authoritative message log and its existing encryption/read behavior.
        with self._writing() as conn:
            conn.execute(
                "INSERT INTO messages(goal_id, role, content, ts) VALUES(?, ?, ?, ?)",
                (goal_id, role, _enc_field(content), time.time()),
            )

    # ----- conversations (multi-turn per channel user) -----
    def get_or_create_conversation(self, channel: str, user_id: str) -> Conversation:
        """Idempotent: same (channel, user_id) always returns the same row.
        last_seen is bumped on every call so prune_conversations can
        retire ones the user has stopped talking to."""
        now = time.time()
        with self._writing() as conn:
            conn.execute(
                "INSERT INTO conversations(channel, user_id, created_at, last_seen) "
                "VALUES(?, ?, ?, ?) "
                "ON CONFLICT(channel, user_id) DO UPDATE SET last_seen = excluded.last_seen",
                (channel, user_id, now, now),
            )
            row = conn.execute(
                "SELECT * FROM conversations WHERE channel = ? AND user_id = ?",
                (channel, user_id),
            ).fetchone()
        return Conversation(**_row_for(Conversation, dict(row)))

    def append_turn(
        self,
        conversation_id: int,
        role: str,
        content: str,
        goal_id: int | None = None,
    ) -> int:
        if role not in ("user", "assistant"):
            raise ValueError(f"role must be 'user' or 'assistant', got {role!r}")
        with self._writing() as conn:
            cur = conn.execute(
                "INSERT INTO turns(conversation_id, goal_id, role, content, ts) "
                "VALUES(?, ?, ?, ?, ?)",
                (conversation_id, goal_id, role, _enc_field(content), time.time()),
            )
            return cur.lastrowid

    def recent_turns(self, conversation_id: int, limit: int = 20) -> list[Turn]:
        """Return the most recent N turns in chronological (ascending) order
        so they can be fed straight into a chat-format prompt."""
        rows = self._read_all(
            "SELECT id, conversation_id, goal_id, role, content, ts FROM turns "
            "WHERE conversation_id = ? ORDER BY id DESC LIMIT ?",
            (conversation_id, limit),
        )
        out: list[Turn] = []
        for r in rows:
            d = dict(r)
            d["content"] = _dec_field(d["content"])
            out.append(Turn(**d))
        return list(reversed(out))

    def list_conversations(self, channel: str | None = None) -> list[Conversation]:
        if channel:
            rows = self._read_all(
                "SELECT * FROM conversations WHERE channel = ? ORDER BY last_seen DESC",
                (channel,),
            )
        else:
            rows = self._read_all(
                "SELECT * FROM conversations ORDER BY last_seen DESC"
            )
        return [Conversation(**_row_for(Conversation, dict(r))) for r in rows]

    @staticmethod
    def _erasure_ids(values: list[int] | tuple[int, ...] | set[int]) -> list[int]:
        ids = sorted(set(values))
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            for value in ids
        ):
            raise ValueError("erasure IDs must be positive integers")
        return ids

    def _conversation_erasure_plan(
        self,
        conn: sqlite3.Connection,
        conversation_ids: list[int],
    ) -> dict[str, Any]:
        if not conversation_ids:
            return {
                "conversation_ids": [],
                "goal_ids": [],
                "episode_ids": [],
                "attachment_paths": [],
            }
        owned: list[int] = []
        for chunk in self._chunks(conversation_ids):
            placeholders = ",".join("?" * len(chunk))
            owned.extend(
                int(row[0])
                for row in conn.execute(
                    "SELECT id FROM conversations "
                    f"WHERE id IN ({placeholders})",
                    chunk,
                ).fetchall()
            )
        owned.sort()
        if not owned:
            return {
                "conversation_ids": [],
                "goal_ids": [],
                "episode_ids": [],
                "attachment_paths": [],
            }
        roots: set[int] = set()
        for chunk in self._chunks(owned):
            placeholders = ",".join("?" * len(chunk))
            roots.update(
                int(row[0])
                for row in conn.execute(
                    "SELECT DISTINCT goal_id FROM turns "
                    f"WHERE conversation_id IN ({placeholders}) "
                    "AND goal_id IS NOT NULL",
                    chunk,
                ).fetchall()
            )
        # Walk descendants in bounded batches. A recursive CTE seeded with the
        # full subject scope can exceed SQLite's compile-time variable ceiling
        # (commonly 32,766) even though receipts allow 100,000 IDs.
        goals = set(roots)
        frontier = set(roots)
        while frontier:
            descendants: set[int] = set()
            for chunk in self._chunks(sorted(frontier)):
                placeholders = ",".join("?" * len(chunk))
                descendants.update(
                    int(row[0])
                    for row in conn.execute(
                        "SELECT id FROM goals "
                        f"WHERE parent_id IN ({placeholders})",
                        chunk,
                    ).fetchall()
                )
            frontier = descendants - goals
            goals.update(frontier)
        goal_ids = sorted(goals)
        episode_ids: list[int] = []
        attachment_paths: list[str] = []
        for chunk in self._chunks(goal_ids):
            placeholders = ",".join("?" * len(chunk))
            episode_ids.extend(
                int(row[0])
                for row in conn.execute(
                    "SELECT id FROM episodes "
                    f"WHERE goal_id IN ({placeholders}) ORDER BY id",
                    chunk,
                ).fetchall()
            )
            attachment_paths.extend(
                str(row[0])
                for row in conn.execute(
                    "SELECT path FROM attachments "
                    f"WHERE goal_id IN ({placeholders}) ORDER BY id",
                    chunk,
                ).fetchall()
            )
        return {
            "conversation_ids": sorted(owned),
            "goal_ids": goal_ids,
            "episode_ids": sorted(episode_ids),
            "attachment_paths": attachment_paths,
        }

    def plan_conversation_erasure(
        self,
        conversation_ids: list[int],
    ) -> dict[str, Any]:
        """Return the exact conversation + descendant-goal closure, read-only."""
        requested = self._erasure_ids(conversation_ids)
        with self._write_lock:
            return self._conversation_erasure_plan(self.conn, requested)

    def store_erasure_receipt(
        self,
        receipt_id: str,
        manifest: str,
        *,
        tenant_id: str,
        created_at: float,
        retained_until: float,
    ) -> None:
        """Insert one immutable signed erasure receipt."""
        with self._writing() as conn:
            conn.execute(
                "INSERT INTO erasure_receipts("
                "receipt_id, tenant_id, manifest, created_at, retained_until"
                ") VALUES(?, ?, ?, ?, ?)",
                (
                    receipt_id,
                    tenant_id,
                    manifest,
                    float(created_at),
                    float(retained_until),
                ),
            )

    def get_erasure_receipt(
        self,
        receipt_id: str,
        *,
        tenant_id: str,
    ) -> str | None:
        row = self._read_one(
            "SELECT manifest FROM erasure_receipts "
            "WHERE receipt_id = ? AND tenant_id = ?",
            (receipt_id, tenant_id),
        )
        return str(row[0]) if row is not None else None

    def retire_erasure_receipts(
        self,
        cutoff: float,
        *,
        tenant_id: str,
    ) -> int:
        """Delete tenant receipts whose signed retention period has elapsed."""
        with self._writing() as conn:
            cursor = conn.execute(
                "DELETE FROM erasure_receipts "
                "WHERE tenant_id = ? AND retained_until <= ?",
                (tenant_id, float(cutoff)),
            )
            return int(cursor.rowcount)

    @staticmethod
    def _chunks(values: list[int], size: int = 500) -> Iterator[list[int]]:
        for index in range(0, len(values), size):
            yield values[index:index + size]

    def count_erasure_receipt_store(
        self,
        store: str,
        conversation_ids: list[int],
        goal_ids: list[int],
        episode_ids: list[int] | None = None,
    ) -> int:
        """Count one exact receipt store, so failures remain per-store."""
        from .erasure_receipts import RECEIPT_STORES

        if store not in RECEIPT_STORES:
            raise ValueError(f"unsupported erasure receipt store {store!r}")
        conversations = self._erasure_ids(conversation_ids)
        goals = self._erasure_ids(goal_ids)
        episodes = self._erasure_ids(episode_ids or [])
        conn = self._reader()
        lock = contextlib.nullcontext() if conn is not None else self._write_lock
        conn = conn or self.conn
        with lock:
            if episode_ids is None:
                discovered: set[int] = set()
                for chunk in self._chunks(goals):
                    placeholders = ",".join("?" * len(chunk))
                    discovered.update(
                        int(row[0])
                        for row in conn.execute(
                            "SELECT id FROM episodes "
                            f"WHERE goal_id IN ({placeholders})",
                            chunk,
                        ).fetchall()
                    )
                episodes = sorted(discovered)
            if store == "conversations":
                count = 0
                for chunk in self._chunks(conversations):
                    placeholders = ",".join("?" * len(chunk))
                    count += int(
                        conn.execute(
                            "SELECT COUNT(*) FROM conversations "
                            f"WHERE id IN ({placeholders})",
                            chunk,
                        ).fetchone()[0]
                    )
                return count
            if store == "turns":
                turn_ids: set[int] = set()
                for field, values in (
                    ("conversation_id", conversations),
                    ("goal_id", goals),
                ):
                    for chunk in self._chunks(values):
                        placeholders = ",".join("?" * len(chunk))
                        turn_ids.update(
                            int(row[0])
                            for row in conn.execute(
                                f"SELECT id FROM turns WHERE {field} "
                                f"IN ({placeholders})",
                                chunk,
                            ).fetchall()
                        )
                return len(turn_ids)
            if store == "goals":
                count = 0
                for chunk in self._chunks(goals):
                    placeholders = ",".join("?" * len(chunk))
                    count += int(
                        conn.execute(
                            f"SELECT COUNT(*) FROM goals "
                            f"WHERE id IN ({placeholders})",
                            chunk,
                        ).fetchone()[0]
                    )
                return count
            if store in (
                "episodes",
                "episode_facts",
                "episode_fact_history",
            ):
                table, field = {
                    "episodes": ("episodes", "id"),
                    "episode_facts": ("facts", "source_episode_id"),
                    "episode_fact_history": (
                        "fact_history",
                        "source_episode_id",
                    ),
                }[store]
                count = 0
                for chunk in self._chunks(episodes):
                    placeholders = ",".join("?" * len(chunk))
                    count += int(
                        conn.execute(
                            f"SELECT COUNT(*) FROM {table} "
                            f"WHERE {field} IN ({placeholders})",
                            chunk,
                        ).fetchone()[0]
                    )
                return count
            count = 0
            for chunk in self._chunks(goals):
                placeholders = ",".join("?" * len(chunk))
                count += int(
                    conn.execute(
                        f"SELECT COUNT(*) FROM {store} "
                        f"WHERE goal_id IN ({placeholders})",
                        chunk,
                    ).fetchone()[0]
                )
            return count

    def count_erasure_receipt_residuals(
        self,
        conversation_ids: list[int],
        goal_ids: list[int],
        episode_ids: list[int] | None = None,
    ) -> dict[str, int]:
        """Count exact receipt IDs in every covered store."""
        from .erasure_receipts import RECEIPT_STORES

        return {
            store: self.count_erasure_receipt_store(
                store,
                conversation_ids,
                goal_ids,
                episode_ids,
            )
            for store in RECEIPT_STORES
        }

    def erase_conversations(
        self,
        conversation_ids: list[int],
        *,
        expected_conversation_ids: list[int] | None = None,
        expected_goal_ids: list[int] | None = None,
        expected_episode_ids: list[int] | None = None,
    ) -> tuple[set[int], list[str], int]:
        """Delete a receipt-race-checked subject closure in one transaction."""
        requested = self._erasure_ids(conversation_ids)
        if not requested:
            return set(), [], 0
        expected_conversations = (
            self._erasure_ids(expected_conversation_ids)
            if expected_conversation_ids is not None
            else None
        )
        expected_goals = (
            self._erasure_ids(expected_goal_ids)
            if expected_goal_ids is not None
            else None
        )
        expected_episodes = (
            self._erasure_ids(expected_episode_ids)
            if expected_episode_ids is not None
            else None
        )
        from .erasure_receipts import ErasurePlanChanged

        with self._writing() as conn:
            # Block every concurrent writer before re-reading the closure. The
            # durable receipt was inserted in an earlier transaction; a new
            # turn/subgoal in between must abort before any deletion.
            conn.execute("BEGIN IMMEDIATE")
            plan = self._conversation_erasure_plan(conn, requested)
            if (
                expected_conversations is not None
                and plan["conversation_ids"] != expected_conversations
            ) or (
                expected_goals is not None
                and plan["goal_ids"] != expected_goals
            ) or (
                expected_episodes is not None
                and plan["episode_ids"] != expected_episodes
            ):
                raise ErasurePlanChanged(
                    "conversation/goal closure changed after receipt issuance"
                )

            conv_ids = plan["conversation_ids"]
            goal_ids = plan["goal_ids"]
            if not conv_ids:
                return set(), [], 0
            conn.execute("PRAGMA defer_foreign_keys = ON")
            removed_turns = 0
            for chunk in self._chunks(conv_ids):
                placeholders = ",".join("?" * len(chunk))
                cursor = conn.execute(
                    "DELETE FROM turns "
                    f"WHERE conversation_id IN ({placeholders})",
                    chunk,
                )
                removed_turns += int(cursor.rowcount)

            if goal_ids:
                for chunk in self._chunks(goal_ids):
                    goal_placeholders = ",".join("?" * len(chunk))
                    conn.execute(
                        "DELETE FROM turns "
                        f"WHERE goal_id IN ({goal_placeholders})",
                        chunk,
                    )
                    for table in (
                        "artifacts",
                        "attachments",
                        "goal_events",
                        "goal_origins",
                        "goal_mutation_receipts",
                        "messages",
                        "processed_messages",
                        "questions",
                        "share_links",
                        "signoffs",
                    ):
                        conn.execute(
                            f"DELETE FROM {table} "
                            f"WHERE goal_id IN ({goal_placeholders})",
                            chunk,
                        )
                    episode_query = (
                        "SELECT id FROM episodes "
                        f"WHERE goal_id IN ({goal_placeholders})"
                    )
                    # Historical fact values can retain the same personal data
                    # and carry the same episode FK, so purge both first.
                    conn.execute(
                        "DELETE FROM fact_history WHERE source_episode_id IN "
                        f"({episode_query})",
                        chunk,
                    )
                    conn.execute(
                        "DELETE FROM facts WHERE source_episode_id IN "
                        f"({episode_query})",
                        chunk,
                    )
                    conn.execute(
                        "DELETE FROM episodes "
                        f"WHERE goal_id IN ({goal_placeholders})",
                        chunk,
                    )
                # With deferred self-referential FKs, goals can be removed in
                # bounded chunks and checked as one transaction at commit.
                for chunk in self._chunks(goal_ids):
                    goal_placeholders = ",".join("?" * len(chunk))
                    conn.execute(
                        "UPDATE event_goal_admissions SET sealed_contract=NULL, "
                        "delivery_state='federation_retired' WHERE admission_key LIKE 'federation:%' "
                        f"AND goal_id IN ({goal_placeholders})", chunk,
                    )
                    conn.execute(
                        f"DELETE FROM goals WHERE id IN ({goal_placeholders})",
                        chunk,
                    )

            for chunk in self._chunks(conv_ids):
                conv_placeholders = ",".join("?" * len(chunk))
                conn.execute(
                    "DELETE FROM conversations "
                    f"WHERE id IN ({conv_placeholders})",
                    chunk,
                )
        return set(goal_ids), list(plan["attachment_paths"]), removed_turns

    # ----- channel dedup -----
    def mark_message_processed(
        self,
        channel: str,
        external_id: str,
        goal_id: int | None = None,
    ) -> bool:
        """Record an inbound message as processed; idempotent.

        Returns True on first-write (the caller should run the goal),
        False on duplicate (the caller should return 200 without
        re-running). Twilio retries within 15s if the webhook is slow
        or non-2xx; the same MessageSid arriving twice was producing
        N goals and N spends before this.
        """
        try:
            with self._writing() as conn:
                conn.execute(
                    "INSERT INTO processed_messages(channel, external_id, goal_id, seen_at) "
                    "VALUES(?, ?, ?, ?)",
                    (channel, external_id, goal_id, time.time()),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def release_processed_message(self, channel: str, external_id: str) -> None:
        """Undo a claim made by ``mark_message_processed`` so a retry can
        re-process the message.

        Channels claim the dedup row BEFORE running the goal (atomic, so a
        Twilio retry that races a slow handler is a no-op instead of a
        double-spend). If that run then fails, the claim must be released or
        the message is stuck marked-as-done and never retried.
        """
        with self._writing() as conn:
            conn.execute(
                "DELETE FROM processed_messages "
                "WHERE channel = ? AND external_id = ?",
                (channel, external_id),
            )

    def lookup_processed_message(
        self,
        channel: str,
        external_id: str,
    ) -> int | None:
        """Return the goal_id for an already-processed message, if any.

        Distinguishes 'no row' (returns None) from 'row exists but goal_id
        is null' (returns 0). Callers that just need "have we seen this?"
        should use ``is_processed_message`` to avoid that ambiguity.
        """
        row = self._read_one(
            "SELECT goal_id FROM processed_messages "
            "WHERE channel = ? AND external_id = ?",
            (channel, external_id),
        )
        if row is None:
            return None
        return row[0] if row[0] is not None else 0

    def prune_processed_messages(self, older_than_seconds: float = 30 * 24 * 3600) -> int:
        """Delete dedup rows older than N seconds.

        Twilio's retry window is minutes, not days, so 30 days is
        generous. Without this, every webhook hit (and every Twilio
        retry attempt) accumulates a row forever; the table grows
        unboundedly and the UNIQUE-index INSERT on the hot path
        eventually slows linearly with channel age. Returns rows
        removed.
        """
        cutoff = time.time() - older_than_seconds
        with self._writing() as conn:
            cur = conn.execute(
                "DELETE FROM processed_messages WHERE seen_at < ?", (cutoff,),
            )
            return cur.rowcount

    def is_processed_message(self, channel: str, external_id: str) -> bool:
        """Returns True iff a row exists for (channel, external_id),
        regardless of whether goal_id is set."""
        row = self._read_one(
            "SELECT 1 FROM processed_messages "
            "WHERE channel = ? AND external_id = ? LIMIT 1",
            (channel, external_id),
        )
        return row is not None

    # ----- cluster-wide killswitch (v22) -----
    # Untenanted, single-row global emergency stop. On a shared backend
    # (Postgres) every replica's killswitch.check() consults this, so a halt
    # armed via the dashboard stops the whole fleet rather than just the replica
    # that served the request.
    def arm_halt(self, reason: str = "", source: str = "manual",
                 armed_by: str = "") -> str:
        generation = secrets.token_urlsafe(24)
        with self._writing() as conn:
            conn.execute(
                "INSERT INTO halt(scope, reason, source, armed_by, armed_at, generation) "
                "VALUES('', ?, ?, ?, ?, ?) "
                "ON CONFLICT(scope) DO UPDATE SET reason=excluded.reason, "
                "source=excluded.source, armed_by=excluded.armed_by, "
                "armed_at=excluded.armed_at, generation=excluded.generation",
                (
                    reason or "",
                    source or "manual",
                    armed_by or "",
                    time.time(),
                    generation,
                ),
            )
        return generation

    def disarm_halt(
        self,
        *,
        expected_generation: str,
        durable_clear: Callable[[], None] | None = None,
    ) -> bool:
        """Atomically bind a durable local clear to the observed shared HALT.

        The write transaction is acquired before ``durable_clear`` runs.  A
        callback failure rolls the shared mutation back; a concurrent arm must
        wait and therefore lands after this generation-bound delete instead of
        being erased by it.
        """
        if not isinstance(expected_generation, str):
            raise TypeError("expected_generation must be a string")
        with self._writing() as conn:
            # ``_writing`` serializes this object; BEGIN IMMEDIATE also claims
            # the SQLite database writer slot before the filesystem callback,
            # covering other WorldModel connections/processes.
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT generation FROM halt WHERE scope = ''",
            ).fetchone()
            if row is None or (row[0] or "") != expected_generation:
                return False
            if durable_clear is not None:
                durable_clear()
            cursor = conn.execute(
                "DELETE FROM halt WHERE scope = '' AND generation = ?",
                (expected_generation,),
            )
            deleted = cursor.rowcount
        return bool(deleted and deleted > 0)

    def active_halt(self) -> dict | None:
        """The shared global halt state, or ``None`` when not armed."""
        row = self._read_one(
            "SELECT reason, source, armed_by, armed_at, generation "
            "FROM halt WHERE scope = ''",
            (),
        )
        if row is None:
            return None
        return {"reason": row[0] or "", "source": row[1] or "",
                "armed_by": row[2] or "", "armed_at": row[3],
                "generation": row[4] or ""}

    # ----- cluster-wide provider spend ledger (v23) -----
    def add_provider_spend(self, period_key: str, provider: str,
                           amount: float) -> float:
        """Atomically add ``amount`` to ``(period_key, provider)``; return the new
        running total. The single authoritative spend total when this world is the
        shared (Postgres) backend, so N replicas can't each spend up to the cap."""
        amt = max(0.0, float(amount or 0.0))
        with self._writing() as conn:
            conn.execute(
                "INSERT INTO provider_spend(period_key, provider, dollars) "
                "VALUES(?, ?, ?) ON CONFLICT(period_key, provider) "
                "DO UPDATE SET dollars = dollars + ?",
                (period_key, provider, amt, amt),
            )
            row = conn.execute(
                "SELECT dollars FROM provider_spend "
                "WHERE period_key = ? AND provider = ?",
                (period_key, provider),
            ).fetchone()
        return float(row[0]) if row else amt

    def get_provider_spend(self, period_key: str, provider: str) -> float:
        """The running spend total for ``(period_key, provider)`` (0.0 if none)."""
        row = self._read_one(
            "SELECT dollars FROM provider_spend "
            "WHERE period_key = ? AND provider = ?",
            (period_key, provider),
        )
        return float(row[0]) if row else 0.0

    def mutate_provider_cap(self, period_key: str, provider: str, operation):
        """Atomically mutate admission receipts and their encumbered spend total."""
        with self._writing() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO provider_spend(period_key, provider, dollars) VALUES(?, ?, 0) "
                "ON CONFLICT(period_key, provider) DO NOTHING", (period_key, provider),
            )
            row = conn.execute(
                "SELECT dollars FROM provider_spend WHERE period_key = ? AND provider = ?",
                (period_key, provider),
            ).fetchone()
            state = conn.execute(
                "SELECT receipts_json FROM provider_cap_receipts WHERE period_key = ? AND provider = ?",
                (period_key, provider),
            ).fetchone()
            total, receipts, result = operation(float(row[0]), json.loads(state[0]) if state else {})
            conn.execute(
                "UPDATE provider_spend SET dollars = ? WHERE period_key = ? AND provider = ?",
                (total, period_key, provider),
            )
            conn.execute(
                "INSERT INTO provider_cap_receipts(period_key, provider, receipts_json) VALUES(?, ?, ?) "
                "ON CONFLICT(period_key, provider) DO UPDATE SET receipts_json = excluded.receipts_json",
                (period_key, provider, json.dumps(receipts, allow_nan=False)),
            )
            return result

    def read_provider_cap(self, period_key: str, provider: str):
        row = self._read_one(
            "SELECT (SELECT dollars FROM provider_spend WHERE period_key = ? AND provider = ?), "
            "(SELECT receipts_json FROM provider_cap_receipts WHERE period_key = ? AND provider = ?)",
            (period_key, provider, period_key, provider),
        )
        if row[0] is None and row[1] is not None:
            raise RuntimeError("Provider accounting total is missing")
        return (float(row[0] or 0), json.loads(row[1]) if row[1] is not None else {})

    @staticmethod
    def _provider_cap_period_sql(period_kind: str) -> str:
        if period_kind == "day":
            return "strftime('%Y-%m-%d', 'now')"
        if period_kind == "month":
            return "strftime('%Y-%m', 'now')"
        raise ValueError("provider cap period kind is invalid")

    def provider_cap_period(self, period_kind: str) -> str:
        """Return the current UTC period from the shared database clock."""
        row = self._read_one(f"SELECT {self._provider_cap_period_sql(period_kind)}")
        if row is None or not isinstance(row[0], str):
            raise RuntimeError("Provider accounting clock is unavailable")
        return row[0]

    def mutate_current_provider_cap(self, period_kind: str, provider: str, operation):
        """Mutate the current provider bucket using one database-clock transaction."""
        period_sql = self._provider_cap_period_sql(period_kind)
        with self._writing() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            period = conn.execute(f"SELECT {period_sql}").fetchone()[0]
            conn.execute(
                "INSERT INTO provider_spend(period_key, provider, dollars) VALUES(?, ?, 0) "
                "ON CONFLICT(period_key, provider) DO NOTHING", (period, provider),
            )
            row = conn.execute(
                "SELECT dollars FROM provider_spend WHERE period_key = ? AND provider = ?",
                (period, provider),
            ).fetchone()
            state = conn.execute(
                "SELECT receipts_json FROM provider_cap_receipts WHERE period_key = ? AND provider = ?",
                (period, provider),
            ).fetchone()
            total, receipts, result = operation(
                period, float(row[0]), json.loads(state[0]) if state else {},
            )
            conn.execute(
                "UPDATE provider_spend SET dollars = ? WHERE period_key = ? AND provider = ?",
                (total, period, provider),
            )
            conn.execute(
                "INSERT INTO provider_cap_receipts(period_key, provider, receipts_json) VALUES(?, ?, ?) "
                "ON CONFLICT(period_key, provider) DO UPDATE SET receipts_json = excluded.receipts_json",
                (period, provider, json.dumps(receipts, allow_nan=False)),
            )
            return period, result

    @staticmethod
    def _backfill_provider_operation_attempts(conn) -> None:
        """Index legacy JSON receipts once, inside the first v35 admission."""
        if conn.execute(
            "SELECT completed FROM provider_operation_attempt_backfill WHERE singleton = 1"
        ).fetchone() is not None:
            return
        # Plain INSERT is intentional: two legacy receipts claiming the same
        # operation attempt abort the transaction and keep admission closed.
        conn.execute(
            "INSERT INTO provider_operation_attempts("
            "scope_sha256, operation_id, attempt_no, category, parent_category, "
            "service, provider, period_key, request_id) "
            "SELECT COALESCE(json_extract(j.value, '$.operation_scope_sha256'), "
            "json_extract(j.value, '$.work_item_sha256'), "
            "'c544f4564db872e0ffb51fa1bb81b3d7089460a7a9a79ad21cd3952e77f0efec'), "  # pragma: allowlist secret
            "json_extract(j.value, '$.operation.operation_id'), "
            "json_extract(j.value, '$.operation.attempt_no'), "
            "json_extract(j.value, '$.operation.category'), "
            "json_extract(j.value, '$.operation.parent_category'), "
            "json_extract(j.value, '$.operation.service'), "
            "p.provider, p.period_key, CAST(j.key AS TEXT) "
            "FROM provider_cap_receipts AS p, json_each(p.receipts_json) AS j "
            "WHERE json_type(j.value, '$.operation') = 'object' "
            "AND NOT EXISTS (SELECT 1 FROM provider_operation_attempts AS a "
            "WHERE a.provider = p.provider AND a.period_key = p.period_key "
            "AND a.request_id = CAST(j.key AS TEXT))"
        )
        conn.execute(
            "INSERT INTO provider_operation_attempt_backfill(singleton, completed) "
            "VALUES(1, 1)"
        )

    def reserve_current_provider_cap(
        self,
        period_kind: str,
        provider: str,
        operation,
        attempt: dict[str, object],
    ):
        """Atomically claim a global operation attempt and reserve its bucket.

        The uniqueness key deliberately excludes provider and period so a
        restored worker cannot replay the same physical attempt by failing over
        or crossing a UTC accounting boundary.
        """
        period_sql = self._provider_cap_period_sql(period_kind)
        with self._writing() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            period = conn.execute(f"SELECT {period_sql}").fetchone()[0]
            self._backfill_provider_operation_attempts(conn)
            existing = conn.execute(
                "SELECT category, parent_category, service, provider, period_key, request_id "
                "FROM provider_operation_attempts "
                "WHERE scope_sha256 = ? AND operation_id = ? AND attempt_no = ?",
                (
                    attempt["scope_sha256"],
                    attempt["operation_id"],
                    attempt["attempt_no"],
                ),
            ).fetchone()
            if existing is not None:
                return period, False, {
                    "category": existing[0],
                    "parent_category": existing[1],
                    "service": existing[2],
                    "provider": existing[3],
                    "period": existing[4],
                    "request_id": existing[5],
                }
            conn.execute(
                "INSERT INTO provider_operation_attempts("
                "scope_sha256, operation_id, attempt_no, category, parent_category, "
                "service, provider, period_key, request_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    attempt["scope_sha256"],
                    attempt["operation_id"],
                    attempt["attempt_no"],
                    attempt["category"],
                    attempt["parent_category"],
                    attempt["service"],
                    provider,
                    period,
                    attempt["request_id"],
                ),
            )
            conn.execute(
                "INSERT INTO provider_spend(period_key, provider, dollars) VALUES(?, ?, 0) "
                "ON CONFLICT(period_key, provider) DO NOTHING",
                (period, provider),
            )
            row = conn.execute(
                "SELECT dollars FROM provider_spend WHERE period_key = ? AND provider = ?",
                (period, provider),
            ).fetchone()
            state = conn.execute(
                "SELECT receipts_json FROM provider_cap_receipts WHERE period_key = ? AND provider = ?",
                (period, provider),
            ).fetchone()
            total, receipts, result = operation(
                period,
                float(row[0]),
                json.loads(state[0]) if state else {},
            )
            conn.execute(
                "UPDATE provider_spend SET dollars = ? WHERE period_key = ? AND provider = ?",
                (total, period, provider),
            )
            conn.execute(
                "INSERT INTO provider_cap_receipts(period_key, provider, receipts_json) VALUES(?, ?, ?) "
                "ON CONFLICT(period_key, provider) DO UPDATE SET receipts_json = excluded.receipts_json",
                (period, provider, json.dumps(receipts, allow_nan=False)),
            )
            return period, True, result

    def read_current_provider_cap(self, period_kind: str, provider: str):
        """Read the database-clock period and its bucket in one statement."""
        period_sql = self._provider_cap_period_sql(period_kind)
        row = self._read_one(
            f"SELECT {period_sql}, "
            f"(SELECT dollars FROM provider_spend WHERE period_key = {period_sql} AND provider = ?), "
            f"(SELECT receipts_json FROM provider_cap_receipts WHERE period_key = {period_sql} AND provider = ?)",
            (provider, provider),
        )
        if row is None or not isinstance(row[0], str):
            raise RuntimeError("Provider accounting clock is unavailable")
        if row[1] is None and row[2] is not None:
            raise RuntimeError("Provider accounting total is missing")
        return row[0], float(row[1] or 0), json.loads(row[2]) if row[2] is not None else {}

    def snapshot_provider_cap_reservations(
        self,
        work_item_sha256: str,
        *,
        limit: int,
    ) -> list[tuple[str, str, float | None, str]]:
        """Return complete matching buckets from one point-in-time SQL snapshot."""
        if (
            not isinstance(work_item_sha256, str)
            or len(work_item_sha256) != 64
            or any(character not in "0123456789abcdef" for character in work_item_sha256)
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 2001
        ):
            raise ValueError("provider reservation snapshot request is invalid")
        sql = (
            "SELECT r.period_key, r.provider, s.dollars, r.receipts_json "
            "FROM provider_cap_receipts AS r "
            "LEFT JOIN provider_spend AS s "
            "ON s.period_key = r.period_key AND s.provider = r.provider "
            "WHERE EXISTS (SELECT 1 FROM json_each(r.receipts_json) AS j "
            "WHERE json_extract(j.value, '$.work_item_sha256') = ?) "
            "ORDER BY r.period_key, r.provider LIMIT ?"
        )
        return [tuple(row) for row in self._read_all(sql, (work_item_sha256, limit))]

    def find_provider_cap_reservations(
        self,
        work_item_sha256: str,
        *,
        limit: int,
        after: tuple[str, str, str] | None = None,
    ) -> list[tuple[str, str, str]]:
        """Return bounded reservation keys for one opaque tenant/work hash."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 201:
            raise ValueError("provider reservation discovery limit is invalid")
        sql = (
            "SELECT p.period_key, p.provider, CAST(j.key AS TEXT) "
            "FROM provider_cap_receipts AS p "
            "JOIN json_each(p.receipts_json) AS j "
            "WHERE json_extract(j.value, '$.work_item_sha256') = ?"
        )
        params: list[object] = [work_item_sha256]
        if after is not None:
            period, provider, request_id = after
            sql += (
                " AND (p.period_key > ? OR (p.period_key = ? AND p.provider > ?) "
                "OR (p.period_key = ? AND p.provider = ? AND CAST(j.key AS TEXT) > ?))"
            )
            params.extend([period, period, provider, period, provider, request_id])
        sql += " ORDER BY p.period_key, p.provider, CAST(j.key AS TEXT) LIMIT ?"
        params.append(limit)
        return [tuple(row) for row in self._read_all(sql, tuple(params))]

    # ----- attachments -----
    def add_attachment(
        self,
        goal_id: int,
        filename: str,
        mime: str,
        size_bytes: int,
        sha256: str,
        path: str,
    ) -> int:
        from .attachment_submissions import AttachmentAdmission, SubmissionStore

        return SubmissionStore(self).admit(
            goal_id, [AttachmentAdmission(filename, mime, size_bytes, sha256, path)],
        )[0]

    def list_attachments(self, goal_id: int) -> list[Attachment]:
        rows = self._read_all(
            "SELECT id, goal_id, filename, mime, size_bytes, sha256, path, created_at "
            "FROM attachments WHERE goal_id = ? ORDER BY id",
            (goal_id,),
        )
        return [Attachment(**dict(r)) for r in rows]

    def prune_conversations(self, idle_for_seconds: float = 90 * 24 * 3600) -> int:
        """Delete conversations idle for N seconds and their turns. Rows removed."""
        cutoff = time.time() - idle_for_seconds
        with self._writing() as conn:
            # Delete turns first so we don't orphan them (no ON DELETE CASCADE).
            conn.execute(
                "DELETE FROM turns WHERE conversation_id IN "
                "(SELECT id FROM conversations WHERE last_seen < ?)",
                (cutoff,),
            )
            cur = conn.execute(
                "DELETE FROM conversations WHERE last_seen < ?", (cutoff,)
            )
            return cur.rowcount


def reclaim_window_seconds(default: float = 60.0) -> float:
    """The orphan-reclaim staleness window in seconds.

    ``MAVERICK_ORPHAN_RECLAIM_SECONDS`` when set and valid, else ``default``
    — exactly the precedence :meth:`WorldModel.reclaim_orphan_goals` has
    always applied. Public so out-of-process work (external-agent
    heartbeats) can tell callers how often they must refresh liveness."""
    import os
    raw = os.environ.get("MAVERICK_ORPHAN_RECLAIM_SECONDS")
    if raw is None:
        # ``[world_model] orphan_reclaim_seconds`` (All settings); env wins.
        try:
            from .config import load_config
            raw = ((load_config() or {}).get("world_model") or {}).get("orphan_reclaim_seconds")
        except Exception:
            raw = None
    if raw is not None:
        try:
            return max(0.0, float(raw))
        except (TypeError, ValueError):
            pass
    return default


def open_world(path: Path | None = None) -> Any:
    """Open the configured world-model backend.

    Returns the SQLite ``WorldModel`` by default. When the user opts into
    Postgres (``[world_model] backend = "postgres"`` in config.toml or
    ``MAVERICK_WORLD_BACKEND=postgres``), returns a ``PostgresWorldModel``
    whose public surface mirrors ``WorldModel``; the ``path`` argument is
    ignored in that case (Postgres uses a DSN, not a file).

    **Client/tenant floor:** when called with no explicit ``path`` and the
    deployment is bound to a client (or a tenant is active), the canonical
    world resolves to that client's isolated ``tenants/<client>/world.db`` via
    :func:`world_for_tenant`, NOT the un-scoped ``~/.maverick/world.db``. This
    keeps the channel server (``serve``), the goal runner/worker, the gRPC goal
    API and the dashboard all opening the SAME per-client world DB (one SQLite
    file = one cached ``WorldModel``); without it a client-bound ``serve`` wrote
    goals to the shared root while the dashboard read the floored path, silently
    splitting the world. Passing an explicit ``path`` (tests, CLI ``--db``)
    bypasses the floor and is unchanged.

    The Postgres backend (and its ``psycopg`` dependency) is imported only
    when selected, so the default SQLite path stays dependency-free and the
    kernel runs without psycopg installed.

    **At-rest encryption:** the Postgres backend now seals the same sensitive
    content columns as SQLite (goal title/description/result, messages, turns,
    episodes, facts, questions, approvals, artifacts, projects, sign-off notes,
    event bodies) with the shared AES-256-GCM field codec, so encryption-at-rest
    is supported on Postgres too. Text search over sealed columns transparently
    falls back to scan-then-decrypt.
    """
    from .world_model_backends import is_postgres_configured

    if is_postgres_configured():
        from . import practice

        if practice.active():  # the practice world is a local file; never write practice live
            raise practice.PracticeUnavailable(practice.POSTGRES_REASON)
        from .world_model_backends import open_postgres_world

        return open_postgres_world()
    if path is None:
        # No explicit path: honor the client/tenant floor so every canonical
        # world entry point opens the one per-client DB (see docstring).
        from .paths import current_tenant_id
        tid = current_tenant_id()
        if tid:
            return world_for_tenant(tid)
        return WorldModel()
    return WorldModel(path, _managed_path=Path(path) == data_dir("world.db"))


# Per-tenant WorldModel cache. Multi-tenancy: each tenant gets its own
# world.db under ~/.maverick/tenants/<t>/, mirroring how cross-session memory
# (tools/memory.py) and the audit log resolve their dirs via data_dir(). Keyed
# by the RESOLVED db path so two raw tenant ids that sanitize to the same dir
# share one connection -- a single SQLite file must have exactly one WorldModel
# (its write lock serialises mutations within the process; two instances on the
# same file would not coordinate). Cached for the life of the process, like the
# audit log's default singleton: WorldModel opens with check_same_thread=False +
# WAL + a write lock, so one instance is safely shared across the FastAPI
# threadpool / goal tasks.
MAX_TENANT_WORLDS = 128
# LRU cache of per-tenant WorldModels (insertion/access order = recency). An
# OrderedDict so a full cache evicts the least-recently-used tenant instead of
# hard-failing the next one.
_tenant_worlds: OrderedDict[str, WorldModel] = OrderedDict()
_tenant_worlds_lock = threading.Lock()


def _world_cache_key(path: Path) -> str:
    """Host-independent key that cannot split a case-insensitive DB path."""
    return os.path.normcase(os.path.abspath(os.fspath(path))).casefold()


def world_for_tenant(tenant: str | None = None) -> WorldModel:
    """Return the process-cached ``WorldModel`` for ``tenant``.

    ``tenant=None`` is the legacy shared world at ``~/.maverick/world.db``
    (single-tenant behaviour unchanged); a tenant ``t`` gets an isolated
    ``~/.maverick/tenants/<t>/world.db``. The path is resolved via
    :func:`maverick.paths.data_dir`, the same primitive memory + audit use, so
    world/memory/audit all land under the same tenant dir.

    Repeated calls for the same tenant return the SAME instance. The cache holds
    up to ``MAX_TENANT_WORLDS`` tenant connections as an LRU: reaching the
    ceiling EVICTS the least-recently-used tenant (so a busy fleet of many
    tenants keeps working) rather than raising. The legacy shared (``None``)
    world is never evicted. Eviction drops the cache reference only -- it does
    not force-close the connection (an in-flight caller may still hold it); the
    underlying SQLite connection is reclaimed when its last reference drops.
    Does NOT consult the Postgres backend -- it is the per-tenant SQLite factory
    the server uses for goal/conversation/turn writes.
    """
    if tenant is not None:
        tenant = bind_tenant_namespace(tenant)
    from . import practice

    path = practice.world_path(tenant) if practice.active() else data_dir("world.db", tenant=tenant)
    key = _world_cache_key(path)
    shared_key = _world_cache_key(data_dir("world.db", tenant=None))
    with _tenant_worlds_lock:
        world = _tenant_worlds.get(key)
        if world is not None:
            _tenant_worlds.move_to_end(key)  # mark most-recently-used
            return world
        if tenant is not None and len(_tenant_worlds) >= MAX_TENANT_WORLDS:
            _evict_lru_tenant_world(shared_key)
        world = WorldModel(path, _managed_path=True)
        # Ownership outlives LRU membership: eviction deliberately drops only
        # the cache reference because an in-flight caller may still hold this
        # connection. Teardown helpers must therefore never close an instance
        # merely because another tenant evicted its key in the meantime.
        world._maverick_cache_owned = True
        _tenant_worlds[key] = world
        _tenant_worlds.move_to_end(key)
        return world


def world_is_cached(world: object) -> bool:
    """Return True when ``world`` was created for the per-tenant cache.

    Ownership is durable across LRU eviction because in-flight callers can
    retain an evicted world after it disappears from ``_tenant_worlds``.
    """
    return bool(getattr(world, "_maverick_cache_owned", False))


def close_world_if_owned(world: object) -> None:
    """Close ``world`` unless it is a process-cached tenant world."""
    if world_is_cached(world):
        return
    close = getattr(world, "close", None)
    if callable(close):
        close()


def _evict_lru_tenant_world(shared_key: str) -> None:
    """Drop the least-recently-used TENANT world from the cache (never the
    shared ``None`` world). Caller holds ``_tenant_worlds_lock``."""
    for k in list(_tenant_worlds):  # oldest-first
        if k == shared_key:
            continue
        _tenant_worlds.pop(k, None)
        return
