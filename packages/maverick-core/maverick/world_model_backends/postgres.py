"""Postgres-backed world model.

A drop-in alternative to the default SQLite WorldModel for users
running Lightwork on a server / cluster who want a shared backend
across processes.

Selected via config:

    [world_model]
    backend = "postgres"
    dsn     = "${MAVERICK_PG_DSN}"   # e.g. postgres://user:pass@host:5432/maverick

Or env:
    MAVERICK_WORLD_BACKEND=postgres
    MAVERICK_PG_DSN=postgres://...

Behind ``maverick-agent[postgres]`` extra (pulls in ``psycopg[binary]``).

Implementation scope: enough to pass the ``conn``-only paths the agent
kernel uses (goals, episodes, events, attachments). For the small
metadata tables that are write-heavy mostly used by channels, we
defer to a future iteration -- this batch ships the shape + the
hot-path methods.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import logging
import math
import os
import secrets
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from urllib.parse import quote

from ..approval_checks import POSTGRES_SCHEMA as _APPROVAL_CHECK_SCHEMA_PG
from ..attachment_submissions import POSTGRES_SCHEMA as _ATTACHMENT_SUBMISSION_SCHEMA
from ..deadline_alerts import POSTGRES_SCHEMA as _DEADLINE_ALERT_SCHEMA_PG
from ..event_admission import POSTGRES_SCHEMA as _EVENT_ADMISSION_SCHEMA
from ..event_admission import (
    EventRegistryUnavailable,
    LegacyEventGoalHeld,
    compatible_event_goal,
    execution_binding_lock,
)
from ..goal_mutations import SCHEMA as _GOAL_MUTATION_SCHEMA
from ..learning_store_pg_schema import LEARNING_TENANT_MIGRATION
from ..metadata_history import POSTGRES_INDEXES as _HISTORY_INDEXES
from ..personal_alert_revisions import POSTGRES_MIGRATION as _PERSONAL_ALERT_MIGRATION
from ..webhook_subscriptions import POSTGRES_SCHEMA as _WEBHOOK_SUBSCRIPTION_SCHEMA_PG

log = logging.getLogger(__name__)

# Read by the schema_version property (health.py / audit events). Driven from
# the migration ladder below: the highest migration version. PG carries the
# tenant-isolation migration (v10), which the SQLite backend implements
# structurally instead (one world.db file per tenant under ~/.maverick/tenants/).


# Schema mirror. Postgres-flavored types; sequence-based PKs instead of
# AUTOINCREMENT, REAL -> DOUBLE PRECISION, TEXT stays TEXT.
SCHEMA: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS goals (
      id            SERIAL PRIMARY KEY,
      parent_id     INTEGER REFERENCES goals(id),
      title         TEXT NOT NULL,
      description   TEXT,
      status        TEXT NOT NULL DEFAULT 'pending',
      created_at    DOUBLE PRECISION NOT NULL,
      updated_at    DOUBLE PRECISION NOT NULL,
      deadline      DOUBLE PRECISION,
      result        TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_goals_status_updated ON goals(status, updated_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_pg_goals_parent ON goals(parent_id, created_at);",
    """
    CREATE TABLE IF NOT EXISTS episodes (
      id            SERIAL PRIMARY KEY,
      goal_id       INTEGER NOT NULL REFERENCES goals(id),
      started_at    DOUBLE PRECISION NOT NULL,
      ended_at      DOUBLE PRECISION,
      summary       TEXT,
      outcome       TEXT,
      cost_dollars  DOUBLE PRECISION DEFAULT 0,
      input_tokens  INTEGER DEFAULT 0,
      output_tokens INTEGER DEFAULT 0,
      tool_calls    INTEGER DEFAULT 0,
      cache_read_tokens  INTEGER DEFAULT 0,
      cache_write_tokens INTEGER DEFAULT 0
    );
    """,
    # Idempotent add for DBs created before `summary` existed.
    "ALTER TABLE episodes ADD COLUMN IF NOT EXISTS summary TEXT;",
    "CREATE INDEX IF NOT EXISTS idx_pg_episodes_goal_started ON episodes(goal_id, started_at DESC);",
    """
    CREATE TABLE IF NOT EXISTS goal_events (
      id        SERIAL PRIMARY KEY,
      goal_id   INTEGER NOT NULL REFERENCES goals(id),
      agent     TEXT NOT NULL,
      kind      TEXT NOT NULL,
      content   TEXT NOT NULL,
      ts        DOUBLE PRECISION NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_goal_events_goal_id_id ON goal_events(goal_id, id);",
    """
    CREATE TABLE IF NOT EXISTS facts (
      id            SERIAL PRIMARY KEY,
      key           TEXT NOT NULL UNIQUE,
      value         TEXT NOT NULL,
      updated_at    DOUBLE PRECISION NOT NULL
    );
    """,
    # Idempotent add to mirror the SQLite facts table's episode attribution.
    "ALTER TABLE facts ADD COLUMN IF NOT EXISTS source_episode_id INTEGER;",
    """
    CREATE TABLE IF NOT EXISTS questions (
      id          SERIAL PRIMARY KEY,
      goal_id     INTEGER REFERENCES goals(id),
      question    TEXT NOT NULL,
      asked_at    DOUBLE PRECISION NOT NULL,
      answer      TEXT,
      answered_at DOUBLE PRECISION
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS approvals (
      id           SERIAL PRIMARY KEY,
      action       TEXT NOT NULL,
      risk         TEXT NOT NULL DEFAULT 'medium',
      scope        TEXT,
      detail       TEXT,
      provenance   TEXT,
      status       TEXT NOT NULL DEFAULT 'pending',
      requested_at DOUBLE PRECISION NOT NULL,
      decided_at   DOUBLE PRECISION
    );
    """,
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS provenance TEXT;",
    # Collaborative supervision (claiming + decider attribution) — mirrors
    # the SQLite v13 migration.
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS claimed_by TEXT;",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS claimed_at DOUBLE PRECISION;",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS decided_by TEXT;",
    # N-of-M dual control (mirrors SQLite v21).
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS approvals_required "
    "INTEGER NOT NULL DEFAULT 1;",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS requested_by TEXT;",
    """
    CREATE TABLE IF NOT EXISTS approval_signoffs (
      approval_id INTEGER NOT NULL,
      approver    TEXT NOT NULL,
      decision    TEXT NOT NULL,
      decided_at  DOUBLE PRECISION NOT NULL,
      note        TEXT,
      PRIMARY KEY (approval_id, approver)
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_approvals_status ON approvals(status, id);",
    """
    CREATE TABLE IF NOT EXISTS conversations (
      id          SERIAL PRIMARY KEY,
      channel     TEXT NOT NULL,
      user_id     TEXT NOT NULL,
      created_at  DOUBLE PRECISION NOT NULL,
      last_seen   DOUBLE PRECISION NOT NULL,
      UNIQUE(channel, user_id)
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_conversations_last_seen ON conversations(last_seen);",
    """
    CREATE TABLE IF NOT EXISTS turns (
      id              SERIAL PRIMARY KEY,
      conversation_id INTEGER NOT NULL REFERENCES conversations(id),
      goal_id         INTEGER REFERENCES goals(id),
      role            TEXT NOT NULL,
      content         TEXT NOT NULL,
      ts              DOUBLE PRECISION NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_turns_conv_id ON turns(conversation_id, id);",
    """
    CREATE TABLE IF NOT EXISTS messages (
      id        SERIAL PRIMARY KEY,
      goal_id   INTEGER REFERENCES goals(id),
      role      TEXT NOT NULL,
      content   TEXT NOT NULL,
      ts        DOUBLE PRECISION NOT NULL
    );
    """,
    # Full-text search index over message content. Postgres has no FTS5; the
    # native equivalent is a GIN index on to_tsvector(...), queried with
    # plainto_tsquery (which safely parses arbitrary natural-language input,
    # the PG analog to the SQLite quoting fix). IMMUTABLE-safe via 'english'.
    "CREATE INDEX IF NOT EXISTS idx_pg_messages_fts "
    "ON messages USING GIN (to_tsvector('english', content));",
    """
    CREATE TABLE IF NOT EXISTS attachments (
      id          SERIAL PRIMARY KEY,
      goal_id     INTEGER NOT NULL REFERENCES goals(id),
      filename    TEXT NOT NULL,
      mime        TEXT NOT NULL,
      size_bytes  INTEGER NOT NULL,
      sha256      TEXT NOT NULL,
      path        TEXT NOT NULL,
      created_at  DOUBLE PRECISION NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_attachments_goal_id ON attachments(goal_id);",
    """
    CREATE TABLE IF NOT EXISTS processed_messages (
      id           SERIAL PRIMARY KEY,
      channel      TEXT NOT NULL,
      external_id  TEXT NOT NULL,
      goal_id      INTEGER REFERENCES goals(id),
      seen_at      DOUBLE PRECISION NOT NULL,
      UNIQUE(channel, external_id)
    );
    """,
]


# --- Tenancy (migration v10) -------------------------------------------------
# Multi-tenant seam for the shared-Postgres backend. The root tables get a
# nullable ``tenant_id``; child rows (episodes, goal_events, turns, ...) inherit
# their tenant through their goal/conversation FK, so they need no column of
# their own for isolation. ``NULL`` is the legacy single-tenant install
# (``paths.current_tenant()`` returns ``None``), so existing rows and every
# default deployment are unaffected. v10 adds the columns + indexes; writes are
# stamped and reads scoped across all root tables (goals/facts/conversations/
# approvals/processed_messages), with v11 making their global UNIQUE constraints
# tenant-aware so one tenant's upsert can't clobber another's row.
_TENANT_TABLES = ("goals", "facts", "conversations", "approvals", "processed_messages")
# Tables that carry their own ``tenant_id`` and so get a DB-enforced RLS policy.
# Superset of _TENANT_TABLES (which also drives the v10 column-add migration):
# ``projects`` (v15) and ``fact_history`` (v18) gained ``tenant_id`` in their own
# later migrations, so they can't ride the v10 ALTER but MUST still be RLS-scoped
# -- otherwise a PG deployment relying on "the database enforces the boundary"
# leaves those two tables app-layer-only. Child tables (episodes/turns/...) carry
# no tenant_id and remain FK-scoped through their parent goal.
_RLS_TABLES = (
    *_TENANT_TABLES,
    "projects",
    "fact_history",
    "erasure_receipts",
    "approval_audit_outbox",
    "attachment_submissions",
    "event_goal_admissions",
    "event_trigger_batches",
    "webhook_subscriptions",
    "webhook_deliveries",
    "deadline_alerts",
)
# Tables whose tenant column is not called ``tenant_id``. The webhook and
# deadline-alert tables (v42) scope rows by ``workspace`` (the same active
# tenant id, written by ``paths.current_tenant_id``), so their RLS policy keys
# on that column; the policy itself is identical.
_RLS_TENANT_COLUMN: dict[str, str] = {
    "webhook_subscriptions": "workspace",
    "webhook_deliveries": "workspace",
    "deadline_alerts": "workspace",
}
_TENANT_MIGRATION: list[str] = [
    f"ALTER TABLE {t} ADD COLUMN IF NOT EXISTS tenant_id TEXT;" for t in _TENANT_TABLES
] + [
    f"CREATE INDEX IF NOT EXISTS idx_pg_{t}_tenant ON {t}(tenant_id);"
    for t in _TENANT_TABLES
]


# --- Tenant-aware uniqueness (migration v11) ---------------------------------
# The root tables with a global UNIQUE (facts.key, conversations(channel,
# user_id), processed_messages(channel, external_id)) need that uniqueness made
# per-tenant -- otherwise two tenants reusing the same key/channel collide and
# one's write clobbers the other's row. We replace each global UNIQUE with a
# expression unique index over ``COALESCE(tenant_id, '')`` + the natural key:
# version-independent (no PG15 NULLS-NOT-DISTINCT needed), and NULL (the legacy
# single-tenant install) collapses to '' so existing dedup/upsert is preserved
# byte-for-byte. The upserts below target the same expression so ON CONFLICT
# still fires. Dropping the old constraint by its deterministic default name is
# IF EXISTS, so a re-run or a differently-named constraint is a safe no-op.
_TENANT_UNIQUE_MIGRATION: list[str] = [
    "ALTER TABLE facts DROP CONSTRAINT IF EXISTS facts_key_key;",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_pg_facts_tenant_key "
    "ON facts (COALESCE(tenant_id, ''), key);",
    "ALTER TABLE conversations DROP CONSTRAINT IF EXISTS conversations_channel_user_id_key;",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_pg_conversations_tenant_chan_user "
    "ON conversations (COALESCE(tenant_id, ''), channel, user_id);",
    "ALTER TABLE processed_messages "
    "DROP CONSTRAINT IF EXISTS processed_messages_channel_external_id_key;",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_pg_processed_tenant_chan_ext "
    "ON processed_messages (COALESCE(tenant_id, ''), channel, external_id);",
]


# --- Collaborative supervision (migration v13) -------------------------------
# Fresh databases receive these through SCHEMA above. Existing Postgres
# databases that already recorded the v1 base migration need a versioned,
# idempotent migration too; otherwise approval listing/claim/decide paths refer
# to columns that were never added. Keep the version aligned with SQLite's v13
# approval-claiming migration.
_APPROVAL_CLAIMS_MIGRATION: list[str] = [
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS claimed_by TEXT;",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS claimed_at DOUBLE PRECISION;",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS decided_by TEXT;",
]


# Ordered schema migrations: ``(version, statements)``. v1 is the consolidated
# base schema (idempotent CREATEs, so a fresh DB and a pre-framework DB both
# converge); higher versions are incremental. The applied set is tracked in the
# ``schema_migrations`` table so a statement runs at most once and the first
# schema change against live customer data has a safe, recorded path.
# --- Goal domain (department pack) (migration v14) ---------------------------
# Parity with the SQLite ``goals.domain`` column: the department pack a goal runs
# as, so learning loops can filter by department without decrypting. Plain-text
# (pack names are operator identifiers, not user content). Fresh DBs add it here;
# existing DBs get the idempotent ALTER.
_GOAL_DOMAIN_MIGRATION: list[str] = [
    "ALTER TABLE goals ADD COLUMN IF NOT EXISTS domain TEXT;",
]


# --- Projects (migration v15) ------------------------------------------------
# Parity with the SQLite ``projects`` table + ``goals.project_id``: a goal can be
# filed under one project (nullable). name/description are sealed at rest via
# ``_seal()`` (encrypted when at-rest encryption is on, same as SQLite); owner/
# domain/status are plaintext for listing + scoping. ``tenant_id`` mirrors the
# v10 tenancy seam so projects isolate per tenant like goals/facts.
_PROJECTS_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS projects (
      id          SERIAL PRIMARY KEY,
      name        TEXT,
      description TEXT,
      owner       TEXT NOT NULL DEFAULT '',
      domain      TEXT NOT NULL DEFAULT '',
      status      TEXT NOT NULL DEFAULT 'active',
      created_at  DOUBLE PRECISION NOT NULL,
      tenant_id   TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_projects_tenant ON projects(tenant_id);",
    "ALTER TABLE goals ADD COLUMN IF NOT EXISTS project_id INTEGER;",
    "CREATE INDEX IF NOT EXISTS idx_pg_goals_project ON goals(project_id);",
]


# --- Artifacts (migration v16) -----------------------------------------------
# Parity with the SQLite ``artifacts`` table: deliverables a goal produced
# (markdown/code/table/text), versioned per (goal_id, title). content is sealed
# at rest via ``_seal()`` (encrypted when at-rest encryption is on, same as
# SQLite). Scoped through goal_id's tenant like other child tables, so no
# tenant_id column of its own.
_ARTIFACTS_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS artifacts (
      id          SERIAL PRIMARY KEY,
      goal_id     INTEGER NOT NULL REFERENCES goals(id),
      kind        TEXT NOT NULL DEFAULT 'text',
      title       TEXT,
      content     TEXT,
      version     INTEGER NOT NULL DEFAULT 1,
      created_at  DOUBLE PRECISION NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_artifacts_goal ON artifacts(goal_id);",
]


# --- Share links / sign-offs / goal origins (migration v17) ------------------
# Parity with the SQLite tables: a revocable expiring read-only share link to a
# goal (only the token's SHA-256 is stored); a human's certify/reject sign-off on
# a deliverable (one row per goal); and which automation spawned a goal. All are
# child tables keyed by goal_id, scoped through the goal's tenant. note is sealed
# at rest via ``_seal()`` (encrypted when at-rest encryption is on, same as SQLite).
_SHARE_SIGNOFF_ORIGIN_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS share_links (
      id           SERIAL PRIMARY KEY,
      goal_id      INTEGER NOT NULL REFERENCES goals(id),
      token_sha256 TEXT NOT NULL UNIQUE,
      created_by   TEXT NOT NULL DEFAULT '',
      created_at   DOUBLE PRECISION NOT NULL,
      expires_at   DOUBLE PRECISION,
      revoked      INTEGER NOT NULL DEFAULT 0
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_share_links_goal ON share_links(goal_id);",
    """
    CREATE TABLE IF NOT EXISTS signoffs (
      goal_id    INTEGER PRIMARY KEY REFERENCES goals(id),
      decision   TEXT NOT NULL,
      decided_by TEXT NOT NULL DEFAULT '',
      note       TEXT,
      created_at DOUBLE PRECISION NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS goal_origins (
      goal_id    INTEGER PRIMARY KEY REFERENCES goals(id),
      kind       TEXT NOT NULL,
      ref        TEXT NOT NULL,
      created_at DOUBLE PRECISION NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_goal_origins_ref ON goal_origins(kind, ref);",
]


# --- Temporal fact history (migration v18) -----------------------------------
# Parity with the SQLite bitemporal fact_history: `facts` keeps the single
# CURRENT value (UNIQUE key); this records each value's validity window so "what
# did we believe on date X, and why" is answerable -- non-destructive evolution
# instead of overwrite. Only written when [memory] temporal is enabled. `value`
# is sealed at rest like facts.value (reusing the shared field codec); the
# window/provenance columns stay plaintext so they remain queryable under
# encryption. tenant_id scopes it like every other table.
_FACT_HISTORY_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS fact_history (
      id                SERIAL PRIMARY KEY,
      key               TEXT NOT NULL,
      value             TEXT NOT NULL,
      source_episode_id INTEGER,
      valid_from        DOUBLE PRECISION NOT NULL,
      valid_to          DOUBLE PRECISION,
      source            TEXT NOT NULL DEFAULT '',
      trust_tier        INTEGER NOT NULL DEFAULT 3,
      sensitivity       TEXT NOT NULL DEFAULT 'internal',
      tenant_id         TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_fact_history_key "
    "ON fact_history (COALESCE(tenant_id, ''), key, valid_from);",
]


# --- Shared rate-limit events (migration v19) --------------------------------
# A cross-replica sliding-window counter for the dashboard's goal-creation rate
# limit. The dashboard's in-process limiter can't hold across replicas (N
# replicas allow N x the cap); on Postgres (the HA backend) the limiter records
# one row per admitted goal here and counts rows inside the window so every
# replica shares one ceiling. ``rl_key`` is the per-client/global bucket; rows
# are pruned past the window. Append-only and tiny; not tenant-scoped (the
# bucket key already encodes principal/source).
_RATE_EVENTS_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS rate_events (
      id      BIGSERIAL PRIMARY KEY,
      rl_key  TEXT NOT NULL,
      ts      DOUBLE PRECISION NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_rate_events_key_ts ON rate_events (rl_key, ts);",
]


# v21 N-of-M dual control: quorum + requester columns on approvals, and the
# per-(approval, approver) signoff table. Mirrors the SQLite v21 migration.
_DUAL_CONTROL_MIGRATION: list[str] = [
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS approvals_required "
    "INTEGER NOT NULL DEFAULT 1;",
    "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS requested_by TEXT;",
    """
    CREATE TABLE IF NOT EXISTS approval_signoffs (
      approval_id INTEGER NOT NULL,
      approver    TEXT NOT NULL,
      decision    TEXT NOT NULL,
      decided_at  DOUBLE PRECISION NOT NULL,
      note        TEXT,
      PRIMARY KEY (approval_id, approver)
    );
    """,
]


# v22 cluster-wide killswitch: an untenanted single-row global halt the
# dashboard arms and every replica's killswitch consults (shared-Postgres
# deployments). Not RLS-scoped on purpose -- a global emergency stop is not
# per-tenant.
_HALT_MIGRATION = [
    "CREATE TABLE IF NOT EXISTS halt ("
    " scope TEXT PRIMARY KEY, reason TEXT, source TEXT, armed_by TEXT,"
    " armed_at DOUBLE PRECISION NOT NULL)",
]

# v23 cluster-wide provider spend ledger: one authoritative per-(period,
# provider) total so provider_cost_cap's ceiling holds across the fleet. Not
# tenant-scoped -- a provider cap is a deployment-wide spend ceiling.
_PROVIDER_SPEND_MIGRATION = [
    "CREATE TABLE IF NOT EXISTS provider_spend ("
    " period_key TEXT NOT NULL, provider TEXT NOT NULL,"
    " dollars DOUBLE PRECISION NOT NULL DEFAULT 0,"
    " PRIMARY KEY (period_key, provider))",
]

# v24 facts provenance columns: persist source / trust_tier / sensitivity on the
# live `facts` table (same defaults as fact_history) so memory_guard reads the
# real recall-trust tier directly from `facts` -- closing the non-temporal
# fallback that defaulted every fact to tier 3. SQLite already carries these in
# its base CREATE (backfilled by its own v17); Postgres adds them here. Additive
# ADD COLUMN IF NOT EXISTS -- passes the migration-governance additive-only gate.
_FACTS_TRUST_MIGRATION: list[str] = [
    "ALTER TABLE facts ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT '';",
    "ALTER TABLE facts ADD COLUMN IF NOT EXISTS trust_tier INTEGER NOT NULL DEFAULT 3;",
    "ALTER TABLE facts ADD COLUMN IF NOT EXISTS sensitivity TEXT NOT NULL DEFAULT 'internal';",
]

# v25 fleet learning store: the self-harness learning stores as shared tables so a multi-host fleet
# learns as one. Additive CREATE IF NOT EXISTS -- passes the
# migration-governance additive-only gate.
_HARNESS_STORE_MIGRATION: list[str] = [
    "CREATE TABLE IF NOT EXISTS harness_addenda ("
    " key TEXT PRIMARY KEY, block TEXT NOT NULL,"
    " updated_at DOUBLE PRECISION NOT NULL);",
    "CREATE TABLE IF NOT EXISTS harness_line_meta ("
    " line_id TEXT PRIMARY KEY, record TEXT NOT NULL,"
    " updated_at DOUBLE PRECISION NOT NULL);",
    "CREATE TABLE IF NOT EXISTS harness_transfer_tried ("
    " line_id TEXT PRIMARY KEY, ts DOUBLE PRECISION NOT NULL);",
]

# v26 fleet learning store eval corpus: the eval-corpus family as shared rows
# (live/pending/rejected + "extra" preserving non-list top-level entries).
# Additive CREATE IF NOT EXISTS -- passes the additive-only gate.
_HARNESS_CORPUS_MIGRATION: list[str] = [
    "CREATE TABLE IF NOT EXISTS harness_corpus ("
    " kind TEXT NOT NULL, key TEXT NOT NULL, seq INTEGER NOT NULL,"
    " row TEXT NOT NULL, PRIMARY KEY (kind, key, seq));",
]

# v27: cache-token spend columns (see world_model.MIGRATIONS[27]).
_EPISODE_CACHE_TOKENS_MIGRATION = [
    "ALTER TABLE episodes ADD COLUMN IF NOT EXISTS cache_read_tokens INTEGER DEFAULT 0;",
    "ALTER TABLE episodes ADD COLUMN IF NOT EXISTS cache_write_tokens INTEGER DEFAULT 0;",
]

# v28: per-principal goal ownership. SQLite has carried ``goals.owner`` since
# v11; Postgres previously exposed only tenant isolation, so authenticated
# callers of owner-scoped episode reads could not get SQLite-equivalent results.
# The empty default preserves legacy/admin semantics for every existing row.
_GOAL_OWNER_MIGRATION = [
    "ALTER TABLE goals ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT '';",
]

# v29: tenant-scoped, insert-only erasure scope receipts. The signed manifest
# contains exact pre-delete row IDs but no raw subject or subject-derived hash.
# UPDATE is forbidden at the database layer; DELETE remains available only to
# the explicit retention/retirement path after ``retained_until``.
_ERASURE_RECEIPTS_MIGRATION = [
    """
    CREATE TABLE IF NOT EXISTS erasure_receipts (
      receipt_id     TEXT NOT NULL,
      tenant_id      TEXT NOT NULL,
      manifest       TEXT NOT NULL,
      created_at     DOUBLE PRECISION NOT NULL,
      retained_until DOUBLE PRECISION NOT NULL,
      PRIMARY KEY (tenant_id, receipt_id)
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_erasure_receipts_retention "
    "ON erasure_receipts(tenant_id, retained_until);",
    """
    CREATE OR REPLACE FUNCTION mvk_erasure_receipts_no_update()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'erasure receipts are immutable';
    END;
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'erasure_receipts_no_update'
          AND tgrelid = 'erasure_receipts'::regclass
      ) THEN
        CREATE TRIGGER erasure_receipts_no_update
        BEFORE UPDATE ON erasure_receipts
        FOR EACH ROW EXECUTE FUNCTION mvk_erasure_receipts_no_update();
      END IF;
    END;
    $$;
    """,
    """
    CREATE OR REPLACE FUNCTION mvk_erasure_receipts_no_early_delete()
    RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF OLD.retained_until > EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) THEN
        RAISE EXCEPTION 'erasure receipt retention is active';
      END IF;
      RETURN OLD;
    END;
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'erasure_receipts_no_early_delete'
          AND tgrelid = 'erasure_receipts'::regclass
      ) THEN
        CREATE TRIGGER erasure_receipts_no_early_delete
        BEFORE DELETE ON erasure_receipts
        FOR EACH ROW EXECUTE FUNCTION mvk_erasure_receipts_no_early_delete();
      END IF;
    END;
    $$;
    """,
]

# v30 approval/audit atomicity: a vote and its audit-delivery intent commit
# together. The final outcome remains pending until all queued vote events are
# durably appended to the signed audit chain.
_APPROVAL_AUDIT_OUTBOX_MIGRATION = [
    """
    CREATE TABLE IF NOT EXISTS approval_audit_outbox (
      event_id     TEXT PRIMARY KEY,
      approval_id  INTEGER NOT NULL REFERENCES approvals(id),
      status       TEXT NOT NULL,
      decided_by   TEXT NOT NULL,
      final_status TEXT,
      created_at   DOUBLE PRECISION NOT NULL,
      delivered_at DOUBLE PRECISION,
      tenant_id    TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_pg_approval_audit_outbox_pending "
    "ON approval_audit_outbox(tenant_id, delivered_at, approval_id);",
]

# v31: a dedicated 64-bit logical write clock for fact recall ordering.
# Conflicting inserts reuse the one sequence value already materialized in
# EXCLUDED.write_seq, avoiding both 32-bit SERIAL exhaustion and primary-key
# churn on every reassertion.
_FACT_WRITE_SEQUENCE_MIGRATION = [
    "ALTER TABLE facts ADD COLUMN IF NOT EXISTS write_seq BIGSERIAL;",
    "CREATE INDEX IF NOT EXISTS idx_pg_facts_write_seq "
    "ON facts(write_seq DESC);",
]

# v32: keep the dashboard/resource owner distinct from the authority that
# executes the goal. The empty default lets the first legitimate dispatcher
# bind legacy rows atomically.
_GOAL_EXECUTION_PRINCIPAL_MIGRATION = [
    "ALTER TABLE goals ADD COLUMN IF NOT EXISTS execution_principal "
    "TEXT NOT NULL DEFAULT '';",
]

# v33: compare-and-delete token for the shared emergency stop.  Every arm
# rotates the token, so an older clear cannot delete a concurrently re-armed
# row.
_HALT_GENERATION_MIGRATION = [
    "ALTER TABLE halt ADD COLUMN IF NOT EXISTS generation "
    "TEXT NOT NULL DEFAULT '';",
]

MIGRATIONS: list[tuple[int, list[str]]] = [
    (1, SCHEMA),
    (10, _TENANT_MIGRATION),
    (11, _TENANT_UNIQUE_MIGRATION),
    (13, _APPROVAL_CLAIMS_MIGRATION),
    (14, _GOAL_DOMAIN_MIGRATION),
    (15, _PROJECTS_MIGRATION),
    (16, _ARTIFACTS_MIGRATION),
    (17, _SHARE_SIGNOFF_ORIGIN_MIGRATION),
    (18, _FACT_HISTORY_MIGRATION),
    (19, _RATE_EVENTS_MIGRATION),
    (21, _DUAL_CONTROL_MIGRATION),
    (22, _HALT_MIGRATION),
    (23, _PROVIDER_SPEND_MIGRATION),
    (24, _FACTS_TRUST_MIGRATION),
    (25, _HARNESS_STORE_MIGRATION),
    (26, _HARNESS_CORPUS_MIGRATION),
    (27, _EPISODE_CACHE_TOKENS_MIGRATION),
    (28, _GOAL_OWNER_MIGRATION),
    (29, _ERASURE_RECEIPTS_MIGRATION),
    (30, _APPROVAL_AUDIT_OUTBOX_MIGRATION),
    (31, _FACT_WRITE_SEQUENCE_MIGRATION),
    (32, _GOAL_EXECUTION_PRINCIPAL_MIGRATION),
    (33, _HALT_GENERATION_MIGRATION),
    (34, [
        "CREATE TABLE IF NOT EXISTS provider_cap_receipts ("
        " period_key TEXT NOT NULL, provider TEXT NOT NULL,"
        " receipts_json TEXT NOT NULL, PRIMARY KEY (period_key, provider))",
    ]),
    (35, [
        "CREATE TABLE IF NOT EXISTS provider_operation_attempts ("
        " scope_sha256 TEXT NOT NULL, operation_id TEXT NOT NULL,"
        " attempt_no BIGINT NOT NULL, category TEXT NOT NULL,"
        " parent_category TEXT NOT NULL, service TEXT, provider TEXT NOT NULL,"
        " period_key TEXT NOT NULL, request_id TEXT NOT NULL,"
        " PRIMARY KEY (scope_sha256, operation_id, attempt_no),"
        " UNIQUE (provider, period_key, request_id))",
        "CREATE TABLE IF NOT EXISTS provider_operation_attempt_backfill ("
        " singleton SMALLINT PRIMARY KEY CHECK(singleton = 1),"
        " completed BOOLEAN NOT NULL CHECK(completed))",
    ]),
    (36, [
        "ALTER TABLE goals ADD COLUMN IF NOT EXISTS completed_at DOUBLE PRECISION",
        "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS goal_id INTEGER",
        "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS department TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_pg_goals_domain_completed "
        "ON goals(tenant_id, domain, completed_at)",
    ]),
    (37, [
        "CREATE INDEX IF NOT EXISTS idx_pg_goals_root_owner "
        "ON goals(tenant_id, owner, id DESC) WHERE parent_id IS NULL",
        "CREATE INDEX IF NOT EXISTS idx_pg_goals_root_shared_owner "
        "ON goals(owner, id DESC) WHERE parent_id IS NULL",
        "CREATE INDEX IF NOT EXISTS idx_pg_goals_root_id "
        "ON goals(id DESC) WHERE parent_id IS NULL",
    ]),
    (38, [_ATTACHMENT_SUBMISSION_SCHEMA]),
    (39, LEARNING_TENANT_MIGRATION),
    (40, [_EVENT_ADMISSION_SCHEMA]),
    (41, [
        "ALTER TABLE event_goal_admissions ADD COLUMN IF NOT EXISTS request_digest TEXT",
        "ALTER TABLE event_goal_admissions ADD COLUMN IF NOT EXISTS sealed_contract TEXT",
        "CREATE INDEX IF NOT EXISTS idx_pg_event_admission_goal ON event_goal_admissions(tenant_id,goal_id)",
    ]),
]

MIGRATIONS.append((42, [_GOAL_MUTATION_SCHEMA]))
MIGRATIONS.append((43, ["ALTER TABLE facts ADD COLUMN IF NOT EXISTS tags_json TEXT NOT NULL DEFAULT '[]'"]))

# Highest migration version = the reported schema version.
MIGRATIONS.append((44, _PERSONAL_ALERT_MIGRATION))
MIGRATIONS.append((45, _HISTORY_INDEXES))
MIGRATIONS.append((46, ["ALTER TABLE goals ADD COLUMN IF NOT EXISTS connection_selection TEXT NOT NULL DEFAULT ''"]))
MIGRATIONS.append((47, [
    # The teardown draft assigned v42 to webhook/alert tables. Its existing
    # databases can therefore lack the companion draft's v42 receipt table.
    # Idempotently ensure both draft additions without rewriting v42..v46.
    _GOAL_MUTATION_SCHEMA,
    *_WEBHOOK_SUBSCRIPTION_SCHEMA_PG,
    *_DEADLINE_ALERT_SCHEMA_PG,
]))
# v48: approval-gate decisions without content (maverick.approval_checks).
MIGRATIONS.append((48, _APPROVAL_CHECK_SCHEMA_PG))

# v49: retire only the unused ciphertext-derived message-search index.
# The authoritative messages table, its contents and tenant policies remain.
MIGRATIONS.append((49, ["DROP INDEX IF EXISTS idx_pg_messages_fts"]))

# Questions inherit tenant scope through their goal; keep that guarded join.
MIGRATIONS.append((50, ["CREATE INDEX IF NOT EXISTS idx_pg_questions_goal_id ON questions(goal_id, id)"]))

# v51: which decisions can still be undone (mirrors SQLite v51).
MIGRATIONS.append((51, ["ALTER TABLE approvals ADD COLUMN IF NOT EXISTS undo_hold TEXT"]))

_PG_SCHEMA_VERSION = MIGRATIONS[-1][0]

_MIGRATIONS_TABLE = (
    "CREATE TABLE IF NOT EXISTS schema_migrations ("
    "  version    INTEGER PRIMARY KEY,"
    "  applied_at DOUBLE PRECISION NOT NULL"
    ");"
)

# Transaction-scoped advisory lock serializing schema migration across replicas.
# Postgres CREATE TABLE/INDEX ... IF NOT EXISTS is NOT concurrency-safe (two
# replicas running it at once can raise "tuple concurrently updated" /
# duplicate-key on the catalog), so concurrent startup of an HA fleet could fail
# or partially-migrate. Holding this lock makes the second replica wait, then
# re-read the version and find nothing to do. Arbitrary fixed key (auto-released
# at COMMIT/ROLLBACK).
_MIGRATION_ADVISORY_LOCK = 0x6D766B6D6967  # 'mvkmig'


def pending_migrations(
    current_version: int,
    migrations: list[tuple[int, list[str]]] | None = None,
) -> list[tuple[int, list[str]]]:
    """Migrations with ``version > current_version``, in ascending order.

    Pure planner (no DB) so the upgrade logic is unit-tested directly.
    """
    migs = MIGRATIONS if migrations is None else migrations
    return [(v, stmts) for v, stmts in sorted(migs) if v > current_version]


def _active_tenant() -> str | None:
    """The tenant scoping this call, or ``None`` for the legacy single-tenant
    store. Lazy import keeps this module free of a hard ``paths`` dependency."""
    # Resolution failures are not equivalent to deliberately unbound legacy
    # mode: swallowing one here removes every app-layer tenant predicate.
    from ..paths import current_tenant_strict
    return current_tenant_strict()


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _explicit_toggle(env_var: str, cfg_key: str) -> bool | None:
    """Resolve an explicitly-set tenant-isolation toggle, or ``None`` if unset.

    Env (``env_var``) wins over ``[world_model] <cfg_key>`` config. Returns
    ``None`` only when neither the env var nor the config key is present, so the
    caller can distinguish "operator chose off" from "operator said nothing" --
    the distinction the enterprise auto-on + boot preflight rely on.
    """
    env = os.environ.get(env_var)
    if env is not None and env.strip() != "":
        return _truthy(env)
    try:
        from ..config import load_config
        cfg = (load_config() or {}).get("world_model") or {}
    except Exception:  # pragma: no cover -- config never blocks construction
        return None
    if cfg_key in cfg:
        v = cfg.get(cfg_key)
        return _truthy(v) if isinstance(v, str) else bool(v)
    return None


def _enterprise_default() -> bool:
    """Enterprise mode auto-enables tenant isolation (off otherwise).

    Lazy + defensive: a missing/raising enterprise module never blocks
    construction of a single-tenant store, it just means "not enterprise".
    """
    try:
        from ..enterprise import enterprise_enabled
        return bool(enterprise_enabled())
    except Exception:  # pragma: no cover -- enterprise never blocks construction
        return False


def _strict_tenant_isolation() -> bool:
    """Strict per-tenant reads. When on, a tenant sees **only** its own rows --
    legacy ``NULL`` rows are no longer visible; safe only after the legacy rows
    have been backfilled with a tenant_id.

    Resolution: ``MAVERICK_STRICT_TENANT_ISOLATION`` env wins over
    ``[world_model] strict_tenant_isolation`` config, which wins over enterprise
    mode (auto-on). Off for the default single-tenant install."""
    explicit = _explicit_toggle("MAVERICK_STRICT_TENANT_ISOLATION", "strict_tenant_isolation")
    if explicit is not None:
        return explicit
    return _enterprise_default()


def _rls_enabled() -> bool:
    """DB-native Row-Level Security. When on, the tenant-scoped tables get a
    Postgres RLS policy keyed on the ``maverick.tenant`` session GUC, so the
    database enforces the tenant boundary even if an app-layer predicate is ever
    missed — defense in depth over ``_tenant_scope``. Implies the legacy
    ``NULL`` rows have been backfilled (RLS scopes strictly to the active
    tenant), which is why enterprise auto-on is gated by a boot preflight.

    Resolution: ``MAVERICK_PG_RLS`` env wins over ``[world_model] rls`` config,
    which wins over enterprise mode (auto-on). Off otherwise."""
    explicit = _explicit_toggle("MAVERICK_PG_RLS", "rls")
    if explicit is not None:
        return explicit
    return _enterprise_default()


def _rls_explicitly_set() -> bool:
    """True when the operator explicitly chose the RLS toggle (env or config).

    The boot preflight only *refuses* to start on legacy ``NULL`` rows when RLS
    was auto-enabled by enterprise mode; an operator who set ``MAVERICK_PG_RLS=1``
    has opted into the strict boundary knowingly, so we keep the existing
    fail-closed install path for them rather than blocking boot."""
    return _explicit_toggle("MAVERICK_PG_RLS", "rls") is not None


def _configured_dsn() -> str:
    """``[world_model] dsn`` (config.toml or the dashboard settings, where it is
    kept sealed); ``MAVERICK_PG_DSN`` in the environment wins over it."""
    try:
        from ..config import load_config
        value = ((load_config() or {}).get("world_model") or {}).get("dsn")
    except Exception:  # pragma: no cover -- config never blocks construction
        return ""
    return str(value).strip() if isinstance(value, str) else ""


def _pool_size() -> int:
    """Max connections for the optional ``psycopg_pool`` connection pool
    (default 0 = no pool, single shared connection as before). A positive value
    opts into pooled mode for horizontal scale under concurrent load.
    ``MAVERICK_PG_POOL_SIZE`` env wins over ``[world_model] pool_size``."""
    raw = os.environ.get("MAVERICK_PG_POOL_SIZE")
    if raw is None or raw.strip() == "":
        try:
            from ..config import load_config
            raw = (load_config() or {}).get("world_model", {}).get("pool_size")
        except Exception:  # pragma: no cover -- config never blocks construction
            raw = None
    try:
        return max(0, int(raw)) if raw is not None else 0
    except (TypeError, ValueError):
        return 0


def _to_pg_paramstyle(sql: str) -> str:
    """Rewrite a SQLite-paramstyle statement for psycopg.

    ``?`` placeholders outside single-quoted literals become ``%s``; every
    literal ``%`` (``LIKE 'agent:%'``) is doubled, because psycopg treats ``%``
    as the placeholder marker whenever parameters are passed -- inside string
    literals too.
    """
    out: list[str] = []
    in_literal = False
    for ch in sql:
        if ch == "'":
            in_literal = not in_literal
            out.append(ch)
        elif ch == "%":
            out.append("%%")
        elif ch == "?" and not in_literal:
            out.append("%s")
        else:
            out.append(ch)
    return "".join(out)


class _PgRow(tuple):
    """A psycopg tuple row that also answers ``row["column"]``.

    ``WorldModel.query`` returns ``sqlite3.Row`` objects, which support index,
    key and unpacking; this keeps the Postgres side interchangeable without
    switching the shared connection's row factory.
    """

    _columns: dict[str, int]

    @classmethod
    def wrap(cls, row: tuple, columns: dict[str, int]) -> _PgRow:
        obj = cls(row)
        obj._columns = columns
        return obj

    def __getitem__(self, key):  # type: ignore[override]
        if isinstance(key, str):
            return tuple.__getitem__(self, self._columns[key])
        return tuple.__getitem__(self, key)

    def keys(self) -> list[str]:
        return list(self._columns)


def _tenant_scope(column: str = "tenant_id") -> tuple[str, list]:
    """Read predicate scoping rows to the active tenant.

    Returns ``(sql_fragment, params)``. With **no** active tenant, only legacy
    unbound rows are visible, preserving single-tenant data without exposing
    named workspaces. With a tenant set,
    the default (NULL-tolerant) predicate matches that tenant's rows **plus**
    legacy ``NULL`` rows; strict mode (``[world_model] strict_tenant_isolation``)
    matches **only** that tenant's rows, the RLS-equivalent hard boundary.
    """
    t = _active_tenant()
    if t is None:
        return f"{column} IS NULL", []
    if _strict_tenant_isolation():
        return f"{column} = %s", [t]
    return f"({column} = %s OR {column} IS NULL)", [t]


def _approval_outbox_scope(column: str = "tenant_id") -> tuple[str, list]:
    """Exact tenant predicate for newly stamped approval-audit rows.

    Unlike compatibility reads of legacy root tables, an active tenant must
    never inherit a legacy/null outbox event. Every v30 write has an explicit
    tenant value (or deliberately unbound ``NULL`` in legacy single-tenant
    mode), so exact matching is both safe and lossless.
    """
    tenant = _active_tenant()
    if tenant is None:
        return f"{column} IS NULL", []
    return f"{column} = %s", [tenant]


def _mutation_tenant_scope(column: str = "tenant_id") -> tuple[str, list]:
    """Exact tenant predicate for ordinary writes and deletes.

    ``_tenant_scope`` may expose legacy NULL rows to compatibility reads.
    That behavior does not grant mutation authority: unbound callers may change
    only legacy NULL rows, and bound callers may change only their exact
    tenant. Legacy ownership must be assigned explicitly before mutation.
    """
    tenant = _active_tenant()
    if tenant is None:
        return f"{column} IS NULL", []
    return f"{column} = %s", [tenant]


def _tenant_precedence(column: str = "tenant_id") -> tuple[str, list]:
    """Ordering expression that prefers an active tenant over legacy NULL."""
    tenant = _active_tenant()
    if tenant is None:
        # An integer literal in a PostgreSQL ORDER BY is a select-list ordinal,
        # not a constant expression.  ``ORDER BY 0`` is therefore invalid SQL.
        # Unbound reads have no tenant to prefer, so callers omit this ordering
        # component and fall back to their normal recency order.
        return "", []
    return f"CASE WHEN {column} = %s THEN 0 ELSE 1 END", [tenant]


def _effective_fact_history_rows(rows: list[tuple], tenant: str | None) -> list[tuple]:
    """Project raw history into the timeline visible to ``tenant``.

    Rows use the internal shape ``(id, key, value, valid_from, valid_to,
    source, trust_tier, sensitivity, tenant_id)``.  In compatibility mode an
    active tenant can read both its own and legacy-NULL facts.  Tenant rows win
    only while their validity window overlaps a legacy row; the non-overlapping
    legacy portions remain point-readable and therefore must remain in history
    and subject-access exports too.
    """
    if tenant is None or not rows:
        return list(rows)

    by_key: dict[str, list[tuple]] = {}
    for row in rows:
        by_key.setdefault(str(row[1]), []).append(row)

    projected: list[tuple] = []
    for key_rows in by_key.values():
        starts: dict[float, list[tuple]] = {}
        ends: dict[float, list[int]] = {}
        points: set[float] = set()
        for row in key_rows:
            row_id = int(row[0])
            valid_from = float(row[3])
            valid_to = None if row[4] is None else float(row[4])
            starts.setdefault(valid_from, []).append(row)
            points.add(valid_from)
            if valid_to is not None:
                ends.setdefault(valid_to, []).append(row_id)
                points.add(valid_to)

        ordered_points = sorted(points)
        active: set[int] = set()
        candidates: list[tuple[int, float, int, tuple]] = []
        key_projection: list[tuple] = []
        for index, start in enumerate(ordered_points):
            for row_id in ends.get(start, ()):
                active.discard(row_id)
            for row in starts.get(start, ()):
                row_id = int(row[0])
                active.add(row_id)
                precedence = 0 if row[8] == tenant else 1
                heapq.heappush(
                    candidates,
                    (precedence, -float(row[3]), -row_id, row),
                )
            while candidates and int(candidates[0][3][0]) not in active:
                heapq.heappop(candidates)

            end = (
                ordered_points[index + 1]
                if index + 1 < len(ordered_points)
                else None
            )
            if not candidates or (end is not None and end <= start):
                continue
            selected = list(candidates[0][3])
            selected[3] = start
            selected[4] = end
            fragment = tuple(selected)
            if (
                key_projection
                and key_projection[-1][0] == fragment[0]
                and key_projection[-1][4] == start
            ):
                previous = list(key_projection[-1])
                previous[4] = end
                key_projection[-1] = tuple(previous)
            else:
                key_projection.append(fragment)
        projected.extend(key_projection)
    return projected


def _erasure_tenant_scope(column: str = "tenant_id") -> tuple[str, list]:
    """Tenant boundary for destructive erasure and its receipt proof.

    An unbound Postgres connection may erase only legacy single-tenant NULL
    rows, never rows belonging to named tenants. A bound tenant follows the normal compatibility policy (its own rows
    plus legacy NULL rows until strict isolation/backfill is enabled).
    """
    tenant = _active_tenant()
    if tenant is None:
        return f"{column} IS NULL", []
    if _strict_tenant_isolation():
        return f"{column} = %s", [tenant]
    return f"({column} = %s OR {column} IS NULL)", [tenant]


def _required_retention_tenant(operation: str) -> str:
    """Concrete tenant for a destructive retention operation.

    Absence of tenant is an administrator read view, not implicit authority to
    delete every tenant. Legacy NULL rows likewise need a separate, explicit
    administrator migration API and are never folded into routine retention.
    """
    tenant = _active_tenant()
    if tenant is None:
        from ..paths import TenantPolicyError
        raise TenantPolicyError(f"refusing unbound Postgres {operation}")
    return tenant


@dataclass
class PGGoal:
    """Mirror of maverick.world_model.Goal — same fields for drop-in compat."""
    id: int
    parent_id: int | None
    title: str
    description: str | None
    status: str
    created_at: float
    updated_at: float
    deadline: float | None
    result: str | None
    owner: str = ""
    execution_principal: str = ""
    domain: str = ""
    project_id: int | None = None


def _seal(text, context=None):
    """Seal a sensitive text column for storage (no-op when at-rest is off).

    Reuses the SQLite backend's field codec so the on-disk format and the
    fail-closed semantics are identical across backends. ``context`` is the
    destination ``table.column``; the value is bound to it and to the tenant."""
    from ..world_model import _enc_field
    return _enc_field(text, context, bind_tenant=True)


def _unseal(text, context=None):
    """Inverse of :func:`_seal` (no-op when at-rest is off; legacy plaintext and
    strict-mode handling identical to the SQLite backend). A value bound to
    another column than ``context`` is withheld."""
    from ..world_model import _dec_field
    return _dec_field(text, context=context)


def _dec_goal_row(row) -> PGGoal:
    """Build a PGGoal from a row, unsealing the at-rest-encrypted text columns
    (title / description / result). Reuses the SQLite backend's field codec so
    sealing semantics (legacy-plaintext passthrough, strict-mode withhold) are
    identical across backends. No-op when at-rest encryption is off."""
    return _goal_from_decoded_row(row, _unseal(row[2], "goals.title"), _unseal(row[3], "goals.description"), _unseal(row[8], "goals.result"))


def _goal_from_decoded_row(row, title, description, result) -> PGGoal:
    return PGGoal(
        row[0], row[1], title, description, row[4],
        row[5], row[6], row[7], result,
        str(row[9] or "") if len(row) > 9 else "",
        str(row[10] or "") if len(row) > 10 else "",
        str(row[11] or "") if len(row) > 11 else "",
        (int(row[12]) if row[12] is not None else None) if len(row) > 12 else None,
    )


def _dec_goal_rows(rows) -> list[PGGoal]:
    """Decode a page with the same shared at-rest policy as SQLite."""
    if not rows:
        return []
    from ..world_model import _dec_fields

    decoded = iter(_dec_fields(
        [value for row in rows for value in (row[2], row[3], row[8])],
        [c for _row in rows for c in ("goals.title", "goals.description", "goals.result")]))
    return [
        _goal_from_decoded_row(row, next(decoded), next(decoded), next(decoded))
        for row in rows
    ]


def _dec_approval_row(r):
    """Build an Approval, unsealing action/scope/detail (provenance is trusted
    plaintext metadata, sealed neither here nor in SQLite). Row order: id,
    action, risk, scope, detail, provenance, status, requested_at, decided_at,
    claimed_by, claimed_at, decided_by, approvals_required, requested_by,
    goal_id, department, undo_hold."""
    from ..world_records import Approval
    return Approval(r[0], _unseal(r[1], "approvals.action"), r[2], _unseal(r[3], "approvals.scope"), _unseal(r[4], "approvals.detail"),
                    r[5], r[6], r[7], r[8], r[9], r[10], r[11],
                    int(r[12]) if len(r) > 12 and r[12] is not None else 1,
                    r[13] if len(r) > 13 else None,
                    r[14] if len(r) > 14 else None,
                    r[15] if len(r) > 15 else "",
                    r[16] if len(r) > 16 else None)


def _dec_approval_audit_row(r):
    from ..world_records import ApprovalAuditEvent

    return ApprovalAuditEvent(
        event_id=str(r[0]),
        approval_id=int(r[1]),
        status=str(r[2]),
        decided_by=str(r[3]),
        final_status=str(r[4]) if r[4] is not None else None,
        created_at=float(r[5]),
        delivered_at=float(r[6]) if r[6] is not None else None,
    )


def _dec_question_row(r):
    """Build a Question, unsealing the question text and the answer. Row order:
    id, goal_id, question, asked_at, answer, answered_at."""
    from ..world_records import Question
    return Question(r[0], r[1], _unseal(r[2], "questions.question"), r[3], _unseal(r[4], "questions.answer"), r[5])


def _connection_kwargs(dsn: str) -> dict:
    """Preserve operator libpq options while bounding unattended transactions."""
    from ..db_timeouts import postgres_connection_kwargs

    return postgres_connection_kwargs(dsn)


class PostgresWorldModel:
    """Postgres adapter. Public surface mirrors SQLite WorldModel.

    Constructed lazily: importing psycopg only happens when the user
    actually configures the postgres backend.
    """

    # The SQLite backend exposes ``.path`` (its on-disk DB file); callers such
    # as the CLI progress poller and ``maverick monitor`` read it. There is no
    # local file for Postgres, and the DSN carries credentials so it must never
    # be surfaced as a path. ``None`` means "no pollable file" -- the poller
    # skips file-based streaming rather than raising AttributeError.
    path = None

    def __init__(self, dsn: str | None = None):
        try:
            import psycopg  # noqa: F401
        except ImportError as e:
            raise ImportError(
                "psycopg not installed. Run: python -m pip install -e './packages/maverick-core[postgres]'"
            ) from e
        self._dsn = dsn or os.environ.get("MAVERICK_PG_DSN") or _configured_dsn()
        if not self._dsn:
            raise RuntimeError(
                "Postgres world model requires MAVERICK_PG_DSN or "
                "[world_model] dsn in config.toml."
            )
        # There is no rebinding migration for this backend, so values sealed
        # before column binding existed must stay readable.
        from ..world_model import _UNREBOUND_BACKENDS
        _UNREBOUND_BACKENDS.add("postgres")
        from ..postgres_io import BoundedConnection, postgres_io_timeout_seconds

        self._rls = _rls_enabled()
        # Optional connection pool (opt-in via [world_model] pool_size). Pooled
        # mode hands each transaction its own connection from the pool, so the
        # backend scales across concurrent callers instead of serialising on one
        # shared connection. Default (pool_size 0) keeps the original
        # single-connection + RLock ownership model.
        self._pool = None
        size = _pool_size()
        # A statement timeout is rolled back by _tx; a terminated idle
        # transaction closes the connection. Retain these options on reconnect.
        self._io_timeout_seconds = postgres_io_timeout_seconds()
        self._connect_kwargs = _connection_kwargs(self._dsn)
        if size > 0:
            try:
                from psycopg_pool import ConnectionPool
            except ImportError as e:
                raise ImportError(
                    "[world_model] pool_size set but psycopg_pool is not "
                    "installed. Run: python -m pip install -e './packages/maverick-core[postgres]'"
                ) from e
            self._pool = ConnectionPool(
                self._dsn, min_size=1, max_size=size, open=True,
                connection_class=BoundedConnection,
                kwargs={**self._connect_kwargs, "io_timeout_seconds": self._io_timeout_seconds},
            )
            self.conn = None
        else:
            self.conn = BoundedConnection.connect(
                self._dsn, io_timeout_seconds=self._io_timeout_seconds, **self._connect_kwargs,
            )
        # One long-lived connection shared across this object (non-pooled mode).
        # psycopg connections are NOT safe for concurrent use by multiple
        # threads, and the kernel drives this from FastAPI's threadpool + the
        # background runner. Serialize every transaction the way the SQLite
        # WorldModel does with its RLock; without it, interleaved
        # execute/commit/rollback corrupt results or raise
        # InFailedSqlTransaction. (Reentrant so a method can nest _tx.) The pool
        # gives each tx its own connection, so the lock is a no-op contention
        # point there but harmless.
        self._lock = threading.RLock()
        self._tx_depth = threading.local()
        self.rls_bypass_reason: str | None = None
        try:
            self._check_database_role()
            self._migrate()
            if self._rls:
                self._preflight_rls_or_die()
                self._apply_rls()
        except BaseException:
            self.close()
            raise

    def _check_database_role(self) -> None:
        """Note, once per open, whether this login bypasses row-level security.

        A superuser or BYPASSRLS role skips every RLS policy, FORCE included.
        With RLS in use, enterprise mode refuses to open; otherwise the problem
        is logged once and reported by the deep health check. With RLS off no
        policy is bypassed, so it is only logged. A failed lookup is only
        logged, so an unreadable catalog never blocks boot.
        """
        try:
            with self._tx() as cur:
                cur.execute(
                    "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user"
                )
                superuser, bypass = cur.fetchone()
        except Exception as e:
            log.warning(
                "Could not check whether the Postgres login bypasses row-level security "
                "(%s); tenant row policies are not verified at this start.", e,
            )
            return
        if not (superuser or bypass):
            return
        problem = (
            "the Postgres login is a superuser, which bypasses row-level security"
            if superuser
            else "the Postgres login has BYPASSRLS, which bypasses row-level security"
        )
        fix = (
            "connect with a dedicated login that is neither a superuser nor BYPASSRLS "
            "(for example CREATE ROLE maverick_app LOGIN NOSUPERUSER NOBYPASSRLS)"
        )
        if not self._rls:
            # No row policy is in use, so nothing is bypassed yet: a hint only.
            log.warning("%s. Turning on [world_model] rls would not protect tenants "
                        "for this login. Fix: %s.", problem, fix)
            return
        self.rls_bypass_reason = f"{problem}; {fix}"
        if _enterprise_default():
            raise RuntimeError(
                "Enterprise mode relies on Postgres row-level security for tenant "
                f"isolation, but {problem}. Fix: {fix}."
            )
        log.warning("%s. Tenant row policies do not apply to this login. Fix: %s.", problem, fix)

    def __enter__(self) -> PostgresWorldModel:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _reconnect_if_broken(self) -> None:
        """Reopen the single shared connection (non-pooled mode) after
        it's been killed out from under us.

        Managed Postgres (RDS/CloudSQL multi-AZ) fails over and resets idle
        connections; without this, the ``psycopg`` driver had already marked
        ``self.conn`` closed (from a PREVIOUS ``_tx()`` that caught the break
        and closed it -- see the ``except`` clause below) and every later
        call would raise ``OperationalError`` forever, turning a transient DB
        blip into an outage that needs a process restart. Only checks the
        cheap, local ``.closed`` flag -- it can't detect a connection the
        server killed but the client hasn't tried to use since; that case is
        caught where it actually surfaces, inside ``_tx``'s try block.
        """
        if self.conn is not None and not self.conn.closed:
            return
        from ..postgres_io import BoundedConnection

        self.conn = BoundedConnection.connect(
            self._dsn, io_timeout_seconds=self._io_timeout_seconds, **self._connect_kwargs,
        )

    @contextmanager
    def _tx(self, *, snapshot: bool = False) -> Iterator:
        """Cursor scope that commits on success and ROLLS BACK on error.

        Critical for autocommit=False: a single failed statement aborts
        the transaction, and without a rollback every later statement on
        this (shared, long-lived) connection fails with
        InFailedSqlTransaction until the process restarts. Rolling back
        keeps the connection usable.

        A rollback can't save a connection the SERVER killed (a
        managed-Postgres failover, or an idle-connection reset) -- the
        rollback itself fails too. In that case, close and drop the
        connection instead of leaving a dead one in ``self.conn``, so
        ``_reconnect_if_broken()`` opens a fresh one on the NEXT call rather
        than repeating ``OperationalError`` forever until the process
        restarts.
        """
        if self._pool is not None:
            # Pooled: each tx gets its own connection; the pool's context
            # commits on success and rolls back on error, so no shared lock.
            # psycopg_pool already detects and replaces a broken connection.
            with self._pool.connection() as conn:
                cur = conn.cursor()
                try:
                    if snapshot:
                        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                    self._set_tenant_guc(cur)
                    self._tx_depth.value = getattr(self._tx_depth, "value", 0) + 1
                    try:
                        yield cur
                    finally:
                        self._tx_depth.value -= 1
                finally:
                    cur.close()
            return
        import psycopg
        with self._lock:
            self._reconnect_if_broken()
            cur = None
            try:
                cur = self.conn.cursor()
                if snapshot:
                    cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                self._set_tenant_guc(cur)
                self._tx_depth.value = getattr(self._tx_depth, "value", 0) + 1
                try:
                    yield cur
                finally:
                    self._tx_depth.value -= 1
                self.conn.commit()
            except (psycopg.OperationalError, psycopg.InterfaceError):
                try:
                    self.conn.close()
                except Exception:  # pragma: no cover
                    pass
                raise
            except Exception:
                try:
                    self.conn.rollback()
                except (psycopg.OperationalError, psycopg.InterfaceError):
                    try:
                        self.conn.close()
                    except Exception:  # pragma: no cover
                        pass
                except Exception:  # pragma: no cover
                    pass
                raise
            finally:
                if cur is not None:
                    cur.close()

    def _set_tenant_guc(self, cur) -> None:
        """Under RLS, bind this transaction to the active tenant.

        RLS is fail-closed: when no tenant is active, set an impossible sentinel
        instead of leaving the GUC unset. Queries that bypass ``_tx`` also fail
        closed because the policy does not grant access for unset/empty GUCs.
        """
        if not self._rls:
            return
        tenant = _active_tenant()
        value = str(tenant) if tenant is not None else "__maverick_no_tenant__"
        # set_config(name, value, is_local=true) is the parameterizable form of
        # SET LOCAL — transaction-scoped, cleared at commit/rollback.
        cur.execute("SELECT set_config('maverick.tenant', %s, true)", (value,))

    def _preflight_rls_or_die(self) -> None:
        """Refuse to boot when enterprise auto-on RLS would silently hide rows.

        When the operator explicitly enabled RLS (``MAVERICK_PG_RLS=1`` /
        ``[world_model] rls = true``) they have knowingly opted into the strict
        boundary, so we skip this gate and let ``_apply_rls`` install the
        fail-closed policy as before. But when RLS was *auto-enabled* by
        enterprise mode, forcing the policy on a store that still holds
        legacy ``tenant_id IS NULL`` rows would freeze those rows invisibly --
        data loss by side effect. So we run the read-only :func:`pg_rls.preflight`
        and raise with a remediation pointer instead of booting.

        Ownership problems are left to ``_apply_rls`` (it tolerates a non-owner
        connection when the policy is already installed); this gate is strictly
        about the NULL-tenant data-safety hazard.
        """
        if _rls_explicitly_set():
            return
        from . import pg_rls
        try:
            if self._pool is not None:
                with self._pool.connection() as conn:
                    report = pg_rls.preflight(conn)
            else:
                report = pg_rls.preflight(self.conn)
        except Exception as e:  # pragma: no cover -- preflight never blocks an explicit opt-in
            log.warning("RLS preflight could not run (%s); proceeding to _apply_rls", e)
            return
        offenders = {
            t: info.get("null_tenant_rows", 0) + info.get("empty_tenant_rows", 0)
            for t, info in report.get("tables", {}).items()
            if info.get("null_tenant_rows") or info.get("empty_tenant_rows")
        }
        if offenders:
            detail = ", ".join(f"{t}={n}" for t, n in sorted(offenders.items()))
            raise RuntimeError(
                "Enterprise mode auto-enabled Postgres RLS, but legacy rows with "
                f"unscoped tenant IDs would be hidden and frozen ({detail}). Assign "
                "them to a tenant first: `maverick tenant backfill <tenant_id>` "
                "(preview with `maverick tenant rls-preflight`). To opt into RLS "
                "knowingly without backfilling, set MAVERICK_PG_RLS=1 explicitly."
            )

    def _apply_rls(self) -> None:
        """Enable Postgres Row-Level Security on the tenant-scoped tables.

        Policy: a row is visible/writable only when its ``tenant_id`` equals the
        transaction-local ``maverick.tenant`` GUC set by ``_tx``. Unset, empty,
        or no-active-tenant GUC values match no rows. Current exact policies
        need only a catalog read; bootstrap/repair retains serialized DDL.

        Only a table's **owner** may ALTER it. A non-owner connection may start
        only if the owner/migration has already installed and forced the exact
        fail-closed policy; otherwise RLS startup raises instead of silently
        running without database-enforced tenant isolation.
        """
        for table in _RLS_TABLES:
            if self._rls_policy_is_active(table):
                continue
            try:
                with self._tx() as cur:
                    cur.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_ADVISORY_LOCK,))
                    # Another replica may have installed the policy while this
                    # connection waited. Inspect again on the writer's cursor.
                    if self._rls_policy_is_active(table, cursor=cur):
                        continue
                    cur.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
                    cur.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
                    cur.execute(f"DROP POLICY IF EXISTS mvk_tenant_isolation ON {table}")
                    cur.execute(self._rls_policy_sql(table))
                    if not self._rls_policy_is_active(table, cursor=cur):
                        raise RuntimeError("The exact tenant policy could not be verified.")
            except Exception as e:  # non-owner / insufficient privilege
                if self._rls_policy_is_active(table):
                    log.info(
                        "RLS already active on %s; continuing after setup error: %s",
                        table, e,
                    )
                    continue
                raise RuntimeError(
                    f"MAVERICK_PG_RLS is enabled but fail-closed RLS could not "
                    f"be installed or verified on {table}: {e}"
                ) from e

    @staticmethod
    def _rls_policy_sql(table: str) -> str:
        column = _RLS_TENANT_COLUMN.get(table, "tenant_id")
        return (
            f"CREATE POLICY mvk_tenant_isolation ON {table} "
            "USING ("
            f"  {column} = nullif(current_setting('maverick.tenant', true), '')"
            ") WITH CHECK ("
            f"  {column} = nullif(current_setting('maverick.tenant', true), '')"
            ")"
        )

    def _rls_policy_is_active(self, table: str, *, cursor=None) -> bool:
        """Verify FORCE and the complete stock policy before skipping DDL.

        Extra restrictive policies can narrow access. Another permissive policy
        can OR around isolation, so it is never evidence of a safe fast path.
        """
        sql = (
            "SELECT c.relrowsecurity,c.relforcerowsecurity,p.polname,p.polcmd,"
            "p.polpermissive,p.polroles,pg_get_expr(p.polqual,p.polrelid),"
            "pg_get_expr(p.polwithcheck,p.polrelid) FROM pg_class c "
            "LEFT JOIN pg_policy p ON p.polrelid=c.oid WHERE c.oid=%s::regclass"
        )
        try:
            if cursor is not None:
                cursor.execute(sql, (table,))
                return self._rls_policy_rows_are_active(table, cursor.fetchall())
            with self._tx() as cur:
                cur.execute(sql, (table,))
                rows = cur.fetchall()
        except Exception:
            return False
        return self._rls_policy_rows_are_active(table, rows)

    @staticmethod
    def _rls_policy_rows_are_active(table, rows) -> bool:
        if not rows or not all(row[0] and row[1] for row in rows):
            return False
        policies = [row for row in rows if row[2] == "mvk_tenant_isolation"]
        if len(policies) != 1 or any(row[4] for row in rows if row[2] != "mvk_tenant_isolation"):
            return False
        policy = policies[0]
        if policy[3] != "*" or policy[4] is not True or list(policy[5] or ()) != [0]:
            return False
        column = _RLS_TENANT_COLUMN.get(table, "tenant_id")
        expected = f"({column}=nullif(current_setting('maverick.tenant'::text,true),''::text))"
        return all("".join(str(expr).lower().split()) == expected for expr in policy[6:8])

    @staticmethod
    def _migration_version(cur) -> int | None:
        cur.execute("SELECT to_regclass('schema_migrations')")
        if not cur.fetchone()[0]:
            return None
        cur.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
        current = int((cur.fetchone() or [0])[0])
        if current > _PG_SCHEMA_VERSION:
            raise RuntimeError("The Postgres database schema is newer than this Lightwork installation.")
        return current

    def _migrate(self) -> None:
        """Apply pending migrations atomically, recording each in
        ``schema_migrations`` so a statement runs at most once.

        A current native migration record requires only a read. Bootstrap and
        upgrades take a transaction-scoped advisory lock so that concurrent
        replica startup serializes -- the second waiter re-reads the version
        after the first commits and applies nothing, rather than racing the
        non-concurrency-safe DDL."""
        with self._tx() as cur:
            if self._migration_version(cur) == _PG_SCHEMA_VERSION:
                return
        with self._tx() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_ADVISORY_LOCK,))
            # Re-read after waiting; an earlier replica may have upgraded it.
            if self._migration_version(cur) == _PG_SCHEMA_VERSION:
                return
            cur.execute(_MIGRATIONS_TABLE)
            cur.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
            current = int((cur.fetchone() or [0])[0])
            for version, statements in pending_migrations(current):
                for stmt in statements:
                    cur.execute(stmt)
                cur.execute(
                    "INSERT INTO schema_migrations(version, applied_at) "
                    "VALUES(%s, %s) ON CONFLICT (version) DO NOTHING",
                    (version, time.time()),
                )

    # ----- goal methods -----

    def create_goal(
        self,
        title: str,
        description: str = "",
        parent_id: int | None = None,
        *,
        owner: str = "",
        execution_principal: str = "",
        domain: str = "",
        project_id: int | None = None,
        connection_references: list | None = None,
    ) -> int:
        # `domain` and `project_id` mirror the SQLite backend's create_goal
        # signature. Both columns already exist on Postgres (migrations above)
        # and were settable after creation via set_goal_domain/set_goal_project,
        # but a caller that passes them AT creation (checkpoint sub-goal
        # spawning, the finance CLI) got a TypeError on this backend instead of
        # a created goal.
        if execution_principal is None:
            execution_principal = ""
        if not isinstance(execution_principal, str):
            raise ValueError("invalid execution principal")
        if execution_principal:
            from ..agent_control_plane import valid_principal

            if not valid_principal(execution_principal):
                raise ValueError("invalid execution principal")
        from ..template_connections import packed
        selection = packed(owner, connection_references or [])
        now = time.time()
        tenant = _active_tenant()
        with self._tx() as cur:
            for table, ref_id in (("goals", parent_id), ("projects", project_id)):
                if ref_id is not None:
                    ref_scope, ref_params = _mutation_tenant_scope()
                    cur.execute(
                        f"SELECT id FROM {table} WHERE id=%s AND " + ref_scope + " FOR SHARE",
                        (int(ref_id), *ref_params),
                    )
                    if cur.fetchone() is None:
                        raise ValueError(f"unknown {table} reference for the active tenant")
            cur.execute(
                "INSERT INTO goals(parent_id, title, description, status, "
                "created_at, updated_at, owner, execution_principal, domain, "
                "project_id, tenant_id, connection_selection) "
                "VALUES(%s, %s, %s, 'pending', %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (
                    parent_id,
                    _seal(title, "goals.title"),
                    _seal(description, "goals.description"),
                    now,
                    now,
                    owner,
                    execution_principal,
                    domain or "",
                    project_id,
                    tenant,
                    _seal(selection, "goals.connection_selection"),
                ),
            )
            row = cur.fetchone()
        return int(row[0])

    def goal_connection_selection(self, goal_id: int) -> str:
        frag, params = _tenant_scope()
        sql, args = "SELECT connection_selection FROM goals WHERE id=%s", [goal_id]
        if frag:
            sql += " AND " + frag
            args += params
        with self._tx() as cur:
            cur.execute(sql, args)
            row = cur.fetchone()
        return _unseal(row[0], "goals.connection_selection") if row and row[0] else ""

    def get_goal(self, goal_id: int) -> PGGoal | None:
        frag, params = _tenant_scope()
        sql = (
            "SELECT id, parent_id, title, description, status, "
            "created_at, updated_at, deadline, result, owner, execution_principal, "
            "domain, project_id "
            "FROM goals WHERE id=%s"
        )
        p: list = [goal_id]
        if frag:
            sql += " AND " + frag
            p += params
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            row = cur.fetchone()
        if row is None:
            return None
        return _dec_goal_row(row)

    def get_goals(self, goal_ids) -> dict[int, PGGoal]:
        """Read existing goals in batches under the current tenant scope.

        This follows the SQLite batch contract and keeps the same field
        decoding and tenant predicate as :meth:`get_goal`. Chunking bounds the
        array sent to PostgreSQL even when a caller supplies a large iterable.
        """
        ids = sorted({int(goal_id) for goal_id in goal_ids})
        if not ids:
            return {}
        scope, scope_params = _tenant_scope()
        sql = (
            "SELECT id, parent_id, title, description, status, "
            "created_at, updated_at, deadline, result, owner, execution_principal, "
            "domain, project_id FROM goals WHERE id = ANY(%s)"
        )
        if scope:
            sql += " AND " + scope
        found: dict[int, PGGoal] = {}
        with self._tx() as cur:
            for start in range(0, len(ids), 500):
                cur.execute(sql, (ids[start:start + 500], *scope_params))
                for goal in _dec_goal_rows(cur.fetchall()):
                    found[goal.id] = goal
        return found

    def set_goal_status(self, goal_id: int, status: str, *, result: str | None = None) -> None:
        # Match SQLite's monotonically advancing optimistic review version.
        # GREATEST is evaluated against the row under the UPDATE lock, not a
        # stale client-side SELECT, including on a stalled/backwards clock.
        now = time.time()
        frag, fparams = _mutation_tenant_scope()
        sql = (
            # COALESCE so a status-only update (result=None) doesn't wipe
            # an existing result -- matches the SQLite backend.
            "UPDATE goals SET completed_at=CASE WHEN %s <> 'done' THEN NULL "
            "WHEN status='done' THEN completed_at "
            "ELSE GREATEST(updated_at + 0.000001, %s) END, "
            "status=%s, result=COALESCE(%s, result), "
            "updated_at=GREATEST(updated_at + 0.000001, %s) WHERE id=%s"
        )
        params: list = [status, now, status, _seal(result, "goals.result"), now, goal_id]
        if frag:
            sql += " AND " + frag
            params += fparams
        legacy_refused = False
        binding_scope = (execution_binding_lock(self, goal_id)
                         if status in {"active", "running"}
                         else nullcontext(False))
        with binding_scope as binding_locked, self._tx() as cur:
            if status in {"active", "running"}:
                scoped, scoped_params = _mutation_tenant_scope("g.tenant_id")
                current_sql = (
                    "SELECT g.status,g.owner,o.kind,o.ref,a.trigger_key FROM goals g "
                    "JOIN goal_origins o ON o.goal_id=g.id "
                    "LEFT JOIN event_goal_admissions a ON a.goal_id=g.id "
                    "AND a.tenant_id=COALESCE(g.tenant_id,'') "
                    "WHERE g.id=%s AND o.kind IN ('event','event_v2')"
                )
                if scoped:
                    current_sql += " AND " + scoped
                current_sql += " FOR UPDATE OF g,o"
                cur.execute(current_sql, (int(goal_id), *scoped_params))
                prior = cur.fetchone()
                if prior is None and binding_locked:
                    cur.execute("SELECT g.status FROM goals g WHERE g.id=%s" +
                                (" AND " + scoped if scoped else "") +
                                " FOR UPDATE OF g", (int(goal_id), *scoped_params))
                    current = cur.fetchone()
                    if current is not None and current[0] not in {"active", "running"}:
                        raise EventRegistryUnavailable("Event origin disappeared during execution claim")
                if (prior is not None and prior[0] not in {"active", "running"}
                        and not binding_locked):
                    raise EventRegistryUnavailable("Event binding changed during execution claim")
                if (prior is not None and prior[0] not in {"active", "running"}
                        and not compatible_event_goal(prior[2], prior[3], prior[1], prior[4])):
                    legacy_refused = True
                    if prior[0] == "pending":
                        cur.execute(
                            "UPDATE goals SET status='blocked', completed_at=NULL, "
                            "updated_at=GREATEST(updated_at + 0.000001, %s), "
                            "result=%s WHERE id=%s AND status='pending'"
                            + (" AND " + frag if frag else ""),
                            (now, _seal("Earlier event request held for review", "goals.result"),
                             int(goal_id), *fparams),
                        )
                        cur.execute("DELETE FROM signoffs WHERE goal_id=%s", (int(goal_id),))
            if not legacy_refused:
                cur.execute(sql, tuple(params))
            # Approval is bound to one terminal payload.  Invalidate it in the
            # same transaction on every rerun/non-terminal transition or result
            # mutation, after tenant-scoped UPDATE proves this goal is ours.
            if not legacy_refused and cur.rowcount == 1 and (status != "done" or result is not None):
                cur.execute("DELETE FROM signoffs WHERE goal_id=%s", (int(goal_id),))
        if legacy_refused:
            raise LegacyEventGoalHeld("Earlier event request held for review")

    def block_pending_goal(self, goal_id: int, *, result: str) -> bool:
        """Atomically block a pending goal in the active tenant only."""
        frag, fparams = _mutation_tenant_scope()
        sql = (
            "UPDATE goals SET status='blocked', completed_at=NULL, "
            "updated_at=GREATEST(updated_at + 0.000001, %s), result=%s "
            "WHERE id=%s AND status='pending' AND " + frag
        )
        with self._tx() as cur:
            cur.execute(sql, tuple([time.time(), _seal(result, "goals.result"), int(goal_id), *fparams]))
            changed = cur.rowcount == 1
            if changed:
                cur.execute("DELETE FROM signoffs WHERE goal_id=%s", (int(goal_id),))
            return changed

    def block_goal_admission(self, goal_id: int, *, result: str) -> bool:
        """Refuse only an exact-tenant, non-terminal goal before dispatch."""
        frag, fparams = _mutation_tenant_scope()
        sql = (
            "UPDATE goals SET status='blocked', completed_at=NULL, "
            "updated_at=GREATEST(updated_at + 0.000001, %s), result=%s "
            "WHERE id=%s AND status IN ('pending','active','running','blocked') AND " + frag
        )
        with self._tx() as cur:
            cur.execute(sql, tuple([time.time(), _seal(result, "goals.result"), int(goal_id), *fparams]))
            changed = cur.rowcount == 1
            if changed:
                cur.execute("DELETE FROM signoffs WHERE goal_id=%s", (int(goal_id),))
            return changed

    def set_goal_partial_result(self, goal_id: int, text: str) -> bool:
        """Replace a running goal's result with the answer written so far;
        matches the SQLite backend (non-terminal rows only, no sign-off effect)."""
        now = time.time()
        frag, fparams = _mutation_tenant_scope()
        sql = (
            "UPDATE goals SET result=%s, updated_at=GREATEST(updated_at + 0.000001, %s) "
            "WHERE id=%s AND status NOT IN "
            "('done','completed','failed','cancelled','blocked','error')"
        )
        params: list = [_seal(text, "goals.result"), now, goal_id]
        if frag:
            sql += " AND " + frag
            params += fparams
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            return cur.rowcount == 1

    def shoring_measurements(self, department: str, *, since: float, until: float, owner: str | None = None) -> dict:
        """Complete department totals, bound to this request's tenant."""
        from ..shoring_metrics import AGGREGATE_SQL, EVENT_TIME_SQL, measurements

        sql = AGGREGATE_SQL + f" WHERE domain = %s AND {EVENT_TIME_SQL} >= %s AND {EVENT_TIME_SQL} <= %s"
        frag, fparams = _tenant_scope()
        if frag:
            sql += " AND " + frag
        if owner is not None:
            sql += " AND owner = %s"
        with self._tx() as cur:
            cur.execute(sql, tuple([department, since, until, *fparams, *([owner] if owner is not None else [])]))
            row = cur.fetchone()
        return measurements(row)

    def bind_goal_execution_principal(self, goal_id: int, principal: str) -> bool:
        """Atomically bind a goal's execution authority and tenant.

        Idempotent same-principal retries succeed; a different established
        principal fails closed. In compatibility mode, claiming a legacy
        ``NULL``-tenant row also stamps the active tenant in the same UPDATE;
        otherwise the newly bound row would remain visible to every tenant.
        """
        from ..agent_control_plane import valid_principal

        if not valid_principal(principal):
            raise ValueError("invalid execution principal")
        tenant = _active_tenant()
        if tenant is None:
            frag, fparams = "tenant_id IS NULL", []
        else:
            # Compatibility mode may claim a legacy NULL row only because the
            # same UPDATE below backfills tenant_id atomically. Strict/RLS mode
            # returns the exact predicate and therefore fails closed instead.
            frag, fparams = _tenant_scope()
        sql = (
            "UPDATE goals SET execution_principal=%s"
        )
        params: list = [principal]
        if tenant is not None:
            sql += ", tenant_id=COALESCE(tenant_id, %s)"
            params.append(tenant)
        sql += (
            " WHERE id=%s AND (execution_principal='' "
            "OR execution_principal=%s) AND " + frag
        )
        params += [int(goal_id), principal, *fparams]
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            return cur.rowcount == 1

    def bind_goal_owner(self, goal_id: int, principal: str) -> bool:
        """Backward-compatible resource-owner binder with exact tenant scope."""
        if not isinstance(principal, str) or not principal:
            raise ValueError("principal is required")
        frag, fparams = _mutation_tenant_scope()
        sql = (
            "UPDATE goals SET owner=%s WHERE id=%s "
            "AND (owner='' OR owner=%s) AND " + frag
        )
        params: list = [principal, int(goal_id), principal, *fparams]
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            return cur.rowcount == 1

    def claim_goal_for_run(
        self, goal_id: int, *, expected_owner: str | None = None,
    ) -> bool:
        """Atomically claim a pending goal at the remote execution boundary.

        ``expected_owner`` rides in the same UPDATE as the pending-to-active
        compare-and-swap. Tenant mutation scope is exact: compatibility reads
        of legacy ``NULL`` rows do not grant authority to claim them.
        """
        now = time.time()
        frag, fparams = _mutation_tenant_scope()
        sql = (
            "UPDATE goals SET status='active', updated_at=GREATEST(updated_at + 0.000001, %s) "
            "WHERE id=%s AND status='pending'"
        )
        params: list = [now, int(goal_id)]
        if expected_owner is not None:
            sql += " AND owner=%s"
            params.append(str(expected_owner))
        sql += " AND " + frag
        params += fparams
        with execution_binding_lock(self, goal_id) as binding_locked, self._tx() as cur:
            scoped, scoped_params = _mutation_tenant_scope("g.tenant_id")
            owner_sql = " AND g.owner=%s" if expected_owner is not None else ""
            cur.execute(
                "SELECT g.owner,o.kind,o.ref,a.trigger_key FROM goals g "
                "JOIN goal_origins o ON o.goal_id=g.id "
                "LEFT JOIN event_goal_admissions a ON a.goal_id=g.id "
                "AND a.tenant_id=COALESCE(g.tenant_id,'') "
                "WHERE g.id=%s AND g.status='pending' "
                "AND o.kind IN ('event','event_v2') "
                "AND " + scoped + owner_sql + " FOR UPDATE OF g,o",
                (int(goal_id), *scoped_params,
                 *((str(expected_owner),) if expected_owner is not None else ())),
            )
            legacy = cur.fetchone()
            if legacy is None and binding_locked:
                cur.execute(
                    "SELECT 1 FROM goals g WHERE g.id=%s AND g.status='pending' "
                    "AND " + scoped + owner_sql + " FOR UPDATE OF g",
                    (int(goal_id), *scoped_params,
                     *((str(expected_owner),) if expected_owner is not None else ())),
                )
                if cur.fetchone() is not None:
                    raise EventRegistryUnavailable("Event origin disappeared during execution claim")
            if legacy is not None and not binding_locked:
                raise EventRegistryUnavailable("Event binding changed during execution claim")
            if legacy is not None and not compatible_event_goal(
                    legacy[1], legacy[2], legacy[0], legacy[3]):
                cur.execute(
                    "UPDATE goals SET status='blocked', completed_at=NULL, "
                    "updated_at=GREATEST(updated_at + 0.000001, %s), result=%s "
                    "WHERE id=%s AND status='pending' AND " + frag,
                    (time.time(), _seal("Earlier event request held for review", "goals.result"),
                     int(goal_id), *fparams),
                )
                cur.execute("DELETE FROM signoffs WHERE goal_id=%s", (int(goal_id),))
                return False
            cur.execute(sql, tuple(params))
            return cur.rowcount == 1

    def touch_goal(
        self, goal_id: int, *, expected_owner: str | None = None,
    ) -> bool:
        """Refresh a live goal's ``updated_at`` (the orphan-reclaim liveness
        signal) with no other side effect — the external-agent heartbeat
        primitive, mirroring the SQLite semantics: only in-flight rows
        qualify, and the owner predicate rides in the same statement."""
        now = time.time()
        frag, fparams = _mutation_tenant_scope()
        sql = ("UPDATE goals SET updated_at=GREATEST(updated_at + 0.000001, %s) "
               "WHERE id=%s AND status IN ('active', 'pending')")
        params: list = [now, int(goal_id)]
        if expected_owner is not None:
            sql += " AND owner=%s"
            params.append(str(expected_owner))
        if frag:
            sql += " AND " + frag
            params += fparams
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            return cur.rowcount == 1

    # --- Backend parity (SQLite v13 -> v20 catch-up): methods on existing
    #     tables that the SQLite WorldModel exposes but the PG backend lacked.
    #     New-table methods (projects/share-links/sign-offs/artifacts/origin)
    #     follow in their own migrations. ----------------------------------

    def set_goal_domain(self, goal_id: int, domain: str) -> None:
        """Record the department (domain pack) a goal runs as (plain text)."""
        frag, fparams = _mutation_tenant_scope()
        sql = "UPDATE goals SET domain=%s WHERE id=%s"
        params: list = [domain or "", goal_id]
        if frag:
            sql += " AND " + frag
            params += fparams
        with self._tx() as cur:
            cur.execute(sql, tuple(params))

    def set_goal_title(self, goal_id: int, title: str) -> None:
        """Rename a goal, sealing the title column like ``create_goal`` does."""
        now = time.time()
        frag, fparams = _mutation_tenant_scope()
        sql = "UPDATE goals SET title=%s, updated_at=GREATEST(updated_at + 0.000001, %s) WHERE id=%s"
        params: list = [_seal(title, "goals.title"), now, goal_id]
        if frag:
            sql += " AND " + frag
            params += fparams
        with self._tx() as cur:
            cur.execute(sql, tuple(params))

    def set_goal_parent(self, goal_id: int, parent_id: int | None) -> None:
        """Move a goal under a new parent (or to the root with ``None``)."""
        now = time.time()
        frag, fparams = _mutation_tenant_scope()
        sql = "UPDATE goals SET parent_id=%s, updated_at=GREATEST(updated_at + 0.000001, %s) WHERE id=%s"
        params: list = [
            int(parent_id) if parent_id is not None else None, now, goal_id]
        if frag:
            sql += " AND " + frag
            params += fparams
        if parent_id is not None:
            sql += " AND EXISTS (SELECT 1 FROM goals parent WHERE parent.id=%s AND "
            # Qualify the column to bind the subquery to the candidate parent.
            parent_scope, parent_params = _mutation_tenant_scope("parent.tenant_id")
            sql += parent_scope + ")"
            params.extend([int(parent_id), *parent_params])
        with self._tx() as cur:
            if parent_id is not None:
                cur.execute("SELECT id FROM goals WHERE id=%s AND " + frag + " FOR SHARE",
                            tuple([int(parent_id), *fparams]))
                if cur.fetchone() is None:
                    return
            cur.execute(sql, tuple(params))

    def goal_parent_pairs(self) -> list[tuple[int, int | None]]:
        """``(id, parent_id)`` for every goal (tenant-scoped) -- the edge list."""
        frag, params = _tenant_scope()
        sql = "SELECT id, parent_id FROM goals"
        if frag:
            sql += " WHERE " + frag
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [(int(r[0]), r[1]) for r in rows]

    def search_goals(
        self, query: str, *, owner: str | None = None,
        limit: int = 50, scan: int = 1000,
    ) -> list[PGGoal]:
        """Search goals by text in title / description / result (newest first).

        When ``owner`` is given the search is scoped to that owner (the
        dashboard's per-user /goals/search relies on this to keep one user from
        reading another's goals); PG additionally isolates by tenant. When
        at-rest encryption is on, title/description/
        result are ciphertext so a SQL ILIKE can't match; we then scan a bounded
        window of the most-recent goals (``scan``) and filter on the decrypted
        text in Python -- the same scan-then-decrypt shape the SQLite backend
        uses. With encryption off, the plaintext ILIKE path runs (cheaper)."""
        q = (query or "").strip()
        if not q:
            return []
        from ..crypto_at_rest import at_rest_enabled
        sealed = at_rest_enabled()
        cols = ("SELECT id, parent_id, title, description, status, "
                "created_at, updated_at, deadline, result, owner, "
                "execution_principal, domain, project_id FROM goals")
        frag, fparams = _tenant_scope()
        cap = max(1, int(limit))
        if sealed:
            # Scan-then-decrypt: fetch a recent window, decrypt, filter in Python.
            sql = cols
            params: list = []
            conds: list[str] = []
            if owner is not None:
                conds.append("owner = %s")
                params.append(str(owner))
            if frag:
                conds.append(frag)
                params += fparams
            if conds:
                sql += " WHERE " + " AND ".join(conds)
            sql += " ORDER BY updated_at DESC LIMIT %s"
            params.append(max(1, int(scan)))
            with self._tx() as cur:
                cur.execute(sql, tuple(params))
                rows = cur.fetchall()
            ql = q.lower()
            out: list[PGGoal] = []
            for r in rows:
                g = _dec_goal_row(r)
                hay = " ".join(p for p in (g.title, g.description, g.result) if p).lower()
                if ql in hay:
                    out.append(g)
                    if len(out) >= cap:
                        break
            return out
        like = f"%{q}%"
        sql = cols + " WHERE (title ILIKE %s OR description ILIKE %s OR result ILIKE %s)"
        params = [like, like, like]
        if owner is not None:
            sql += " AND owner = %s"
            params.append(str(owner))
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " ORDER BY updated_at DESC LIMIT %s"
        params.append(cap)
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [_dec_goal_row(r) for r in rows]

    def count_facts(self) -> int:
        """Number of stored facts (tenant-scoped)."""
        frag, params = _tenant_scope()
        sql = "SELECT COUNT(*) FROM facts"
        if frag:
            sql += " WHERE " + frag
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            row = cur.fetchone()
        return int(row[0]) if row else 0

    def stale_fact_keys(self, older_than: float, limit: int = 500) -> list[str]:
        """Keys of facts not updated since ``older_than``, oldest first."""
        sql = "SELECT key FROM facts WHERE updated_at < %s"
        params: list = [older_than]
        frag, fparams = _tenant_scope()
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " ORDER BY updated_at ASC, id ASC LIMIT %s"
        params.append(max(1, int(limit)))
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [r[0] for r in rows]

    def list_approvals(self, limit: int = 500) -> list:
        """All approvals, newest first (the Operating Record's decision feed)."""
        frag, params = _tenant_scope()
        sql = (
            "SELECT id, action, risk, scope, detail, provenance, status, "
            "requested_at, decided_at, claimed_by, claimed_at, decided_by, "
            "approvals_required, requested_by, goal_id, department, undo_hold "
            "FROM approvals"
        )
        p: list = list(params) if frag else []
        if frag:
            sql += " WHERE " + frag
        sql += " ORDER BY requested_at DESC, id DESC LIMIT %s"
        p.append(max(1, int(limit)))
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            rows = cur.fetchall()
        return [_dec_approval_row(r) for r in rows]

    def approvals_requested_between(self, since: float, until: float) -> list:
        """The SQLite twin's window read: same bounds, same order, same
        tenant scope as :meth:`list_approvals`."""
        frag, params = _tenant_scope()
        where = ["requested_at >= %s", "requested_at <= %s"]
        p: list = [float(since), float(until)]
        if frag:
            where.insert(0, frag)
            p = list(params) + p
        sql = (
            "SELECT id, action, risk, scope, detail, provenance, status, "
            "requested_at, decided_at, claimed_by, claimed_at, decided_by, "
            "approvals_required, requested_by, goal_id, department, undo_hold "
            "FROM approvals WHERE " + " AND ".join(where)
            + " ORDER BY requested_at DESC, id DESC"
        )
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            rows = cur.fetchall()
        return [_dec_approval_row(r) for r in rows]

    def release_processed_message(self, channel: str, external_id: str) -> None:
        """Undo a ``mark_message_processed`` claim so a failed run can retry."""
        with self._tx() as cur:
            cur.execute(
                "DELETE FROM processed_messages "
                "WHERE COALESCE(tenant_id, '') = COALESCE(%s, '') "
                "AND channel = %s AND external_id = %s",
                (_active_tenant(), channel, external_id),
            )

    def recent_event_contents(self, limit: int = 5000) -> list[str]:
        """Coordination-message bodies across THIS tenant's goals (newest first).

        goal_events has no tenant_id; scope through the parent goal so a tenant
        never reads another tenant's event bodies (no-op single-tenant). Mirrors
        the scoping in :meth:`goal_events`."""
        frag, fparams = _tenant_scope("g.tenant_id")
        with self._tx() as cur:
            if frag:
                cur.execute(
                    "SELECT ge.content FROM goal_events ge "
                    "JOIN goals g ON g.id = ge.goal_id WHERE " + frag +
                    " ORDER BY ge.id DESC LIMIT %s",
                    tuple([*fparams, int(limit)]),
                )
            else:
                cur.execute(
                    "SELECT content FROM goal_events ORDER BY id DESC LIMIT %s",
                    (int(limit),),
                )
            rows = cur.fetchall()
        return [_unseal(r[0], "goal_events.content") for r in rows if r and r[0]]

    # ---- Projects (migration v15) -------------------------------------------

    @staticmethod
    def _project_from_row(row) -> dict:
        # row: (id, name, description, owner, domain, status, created_at)
        # name/description are sealed at rest; owner/domain/status are plaintext.
        return {
            "id": row[0], "name": _unseal(row[1], "projects.name") or "",
            "description": _unseal(row[2], "projects.description") or "",
            "owner": row[3], "domain": row[4], "status": row[5],
            "created_at": row[6],
        }

    def create_project(
        self, name: str, *, description: str = "", owner: str = "", domain: str = "",
    ) -> int:
        """Create a project (name/description sealed at rest). Returns its id."""
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO projects(name, description, owner, domain, status, "
                "created_at, tenant_id) VALUES(%s, %s, %s, %s, 'active', %s, %s) "
                "RETURNING id",
                (_seal(name, "projects.name"), _seal(description, "projects.description"), owner or "", domain or "",
                 time.time(), _active_tenant()),
            )
            return int(cur.fetchone()[0])

    _PROJECT_COLS = "id, name, description, owner, domain, status, created_at"

    def get_project(self, project_id: int) -> dict | None:
        frag, params = _tenant_scope()
        sql = f"SELECT {self._PROJECT_COLS} FROM projects WHERE id=%s"
        p: list = [int(project_id)]
        if frag:
            sql += " AND " + frag
            p += params
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            row = cur.fetchone()
        return self._project_from_row(row) if row else None

    def list_projects(self, *, owner: str | None = None) -> list[dict]:
        """All projects newest first; each carries a ``goal_count``.

        When supplied, ``owner`` scopes project metadata to that principal,
        matching the SQLite backend contract used by the dashboard RBAC layer.
        Tenant scoping is still applied independently.
        """
        sql = f"SELECT {self._PROJECT_COLS} FROM projects"
        params: list = []
        clauses: list[str] = []
        if owner is not None:
            clauses.append("owner=%s")
            params.append(owner)
        frag, fparams = _tenant_scope()
        if frag:
            clauses.append(frag)
            params += fparams
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        goal_count_sql = "SELECT COUNT(*) FROM goals WHERE project_id=%s"
        goal_count_params: list = []
        goal_frag, goal_fparams = _tenant_scope()
        if goal_frag:
            goal_count_sql += " AND " + goal_frag
            goal_count_params += goal_fparams
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
            out: list[dict] = []
            for r in rows:
                proj = self._project_from_row(r)
                cur.execute(goal_count_sql, tuple([proj["id"], *goal_count_params]))
                c = cur.fetchone()
                proj["goal_count"] = int(c[0]) if c else 0
                out.append(proj)
        return out

    def set_goal_project(self, goal_id: int, project_id: int | None) -> None:
        """File a goal under a project (or clear it with ``None``)."""
        frag, fparams = _mutation_tenant_scope()
        sql = "UPDATE goals SET project_id=%s, updated_at=GREATEST(updated_at + 0.000001, %s) WHERE id=%s"
        params: list = [
            int(project_id) if project_id is not None else None,
            time.time(), int(goal_id),
        ]
        if frag:
            sql += " AND " + frag
            params += fparams
        if project_id is not None:
            project_scope, project_params = _mutation_tenant_scope("project.tenant_id")
            sql += " AND EXISTS (SELECT 1 FROM projects project WHERE project.id=%s AND "
            sql += project_scope + ")"
            params.extend([int(project_id), *project_params])
        with self._tx() as cur:
            if project_id is not None:
                cur.execute("SELECT id FROM projects WHERE id=%s AND " + frag + " FOR SHARE",
                            tuple([int(project_id), *fparams]))
                if cur.fetchone() is None:
                    return
            cur.execute(sql, tuple(params))

    def project_status_counts(self, project_id: int) -> dict[str, int]:
        """Member-goal counts keyed by status (the project summary)."""
        sql = "SELECT status, COUNT(*) FROM goals WHERE project_id=%s"
        params: list = [int(project_id)]
        frag, fparams = _tenant_scope()
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " GROUP BY status"
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return {r[0]: int(r[1]) for r in rows}

    def goal_status_counts(self, *, owner: str | None = None) -> dict[str, int]:
        """All goals keyed by status (tenant-scoped) -- the backend-agnostic
        source for the ``/metrics`` ``maverick_goals_total`` gauge."""
        sql = "SELECT status, COUNT(*) FROM goals"
        frag, params = _tenant_scope()
        if frag:
            sql += " WHERE " + frag
        if owner is not None:
            sql += " AND owner = %s" if frag else " WHERE owner = %s"
            params.append(owner)
        sql += " GROUP BY status"
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return {r[0]: int(r[1]) for r in rows}

    # -- backend-portable raw reads (mirror of WorldModel.query) -------------

    def query(self, sql: str, params: tuple | list = ()) -> list:
        """Run a read-only statement written in SQLite paramstyle (``?``).

        The statement is rewritten for psycopg (``%s``, ``%%``), executed inside
        :meth:`_tx` (so it takes the connection lock, sets the tenant GUC and
        rolls back on error instead of poisoning the shared connection), and
        every row comes back as a tuple that also supports ``row["column"]``.
        """
        params = tuple(params)
        with self._tx() as cur:
            if params:
                cur.execute(_to_pg_paramstyle(sql), params)
            else:
                cur.execute(sql)
            columns = {d.name: i for i, d in enumerate(cur.description or ())}
            rows = cur.fetchall()
        return [_PgRow.wrap(r, columns) for r in rows]

    def sql_day_from_epoch(self, column: str) -> str:
        """UTC ``YYYY-MM-DD`` text for an epoch-seconds column -- the Postgres
        spelling of SQLite's ``date(col, 'unixepoch')``."""
        return f"to_char(to_timestamp({column}) AT TIME ZONE 'UTC', 'YYYY-MM-DD')"

    def ping(self) -> bool:
        """Cheap liveness probe for ``/healthz`` -- confirms Postgres answers a
        trivial read so the deep health check probes the SAME store the app uses."""
        with self._tx() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return True

    # ---- Artifacts (migration v16) ------------------------------------------

    def add_artifact(self, goal_id: int, kind: str, title: str, content: str) -> int:
        """Record a goal deliverable; re-using (goal_id, title) appends the next
        version so the UI can show history. Returns the new row id."""
        with self._tx() as cur:
            # Serialize concurrent writers for THIS (goal,title) across replicas
            # so the MAX(version)+1 read-modify-write can't assign a duplicate
            # version. Per-key advisory lock (auto-released at COMMIT); distinct
            # (goal,title) pairs hash elsewhere and don't contend.
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (f"artifact:{int(goal_id)}:{title or ''}",),
            )
            cur.execute(
                "SELECT COALESCE(MAX(version), 0) FROM artifacts "
                "WHERE goal_id=%s AND title=%s",
                (int(goal_id), title or ""),
            )
            version = int(cur.fetchone()[0]) + 1
            # Gate the write on the parent goal being in the active tenant (see
            # start_episode) so a write against another tenant's goal_id can't
            # plant a deliverable. Legacy rows require an unbound caller.
            frag, fparams = _mutation_tenant_scope()
            if frag:
                cur.execute(
                    "INSERT INTO artifacts(goal_id, kind, title, content, version, "
                    "created_at) SELECT %s, %s, %s, %s, %s, %s WHERE EXISTS "
                    "(SELECT 1 FROM goals WHERE id=%s AND " + frag + ") RETURNING id",
                    (int(goal_id), str(kind or "text"), title or "", _seal(content, "artifacts.content"),
                     version, time.time(), int(goal_id), *fparams),
                )
            else:
                cur.execute(
                    "INSERT INTO artifacts(goal_id, kind, title, content, version, "
                    "created_at) VALUES(%s, %s, %s, %s, %s, %s) RETURNING id",
                    (int(goal_id), str(kind or "text"), title or "", _seal(content, "artifacts.content"),
                     version, time.time()),
                )
            row = cur.fetchone()
            if row is not None:
                # Keep goal.updated_at as the optimistic version for the whole
                # release payload, including its artifact set.
                cur.execute(
                    "UPDATE goals SET updated_at=GREATEST(updated_at + 0.000001, %s) WHERE id=%s",
                    (time.time(), int(goal_id)),
                )
                # Public release includes artifacts; adding a version changes
                # the reviewed payload and atomically revokes prior approval.
                cur.execute("DELETE FROM signoffs WHERE goal_id=%s", (int(goal_id),))
        if row is None:
            raise ValueError(f"unknown goal_id {goal_id!r} for the active tenant")
        return int(row[0])

    def artifacts_for_goal(self, goal_id: int) -> list[dict]:
        """Every artifact version for a goal, ordered by title then version."""
        # Defense-in-depth: artifacts has no tenant_id (FK-scoped via the goal).
        # Callers already assert goal access, but bound the read to the active
        # tenant's goals at the DB layer too so a future caller can't leak.
        frag, fparams = _tenant_scope()
        sql = ("SELECT id, goal_id, kind, title, content, version, created_at "
               "FROM artifacts WHERE goal_id=%s")
        params: list = [int(goal_id)]
        if frag:
            sql += " AND goal_id IN (SELECT id FROM goals WHERE " + frag + ")"
            params += fparams
        sql += " ORDER BY title, version"
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [{"id": r[0], "goal_id": r[1], "kind": r[2], "title": r[3] or "",
                 "content": _unseal(r[4], "artifacts.content") or "", "version": r[5], "created_at": r[6]}
                for r in rows]

    def latest_artifacts(self, goal_id: int) -> list[dict]:
        """Latest version of each titled artifact, with a ``versions`` count."""
        by_title: dict[str, dict] = {}
        counts: dict[str, int] = {}
        for a in self.artifacts_for_goal(goal_id):  # title, version ascending
            by_title[a["title"]] = a
            counts[a["title"]] = counts.get(a["title"], 0) + 1
        return [{**a, "versions": counts[t]} for t, a in by_title.items()]

    # ---- Share links (migration v17) ----------------------------------------

    def create_share_link(
        self, goal_id: int, *, created_by: str = "", ttl_seconds: float | None = None, token_prefix: str = "",
    ) -> tuple[int, str]:
        """Mint a read-only share link; returns ``(id, clear_token)``. Only the
        token's SHA-256 is persisted, so the clear token is shown exactly once."""
        if token_prefix not in {"", "r1_"}:
            raise ValueError("Unsupported share token version")
        token = token_prefix + secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        exp = now + float(ttl_seconds) if ttl_seconds else None
        # Gate the write on the parent goal being in the active tenant (see
        # start_episode): a tenant must not mint a share link over another
        # tenant's goal_id. Legacy rows require an unbound caller.
        frag, fparams = _mutation_tenant_scope()
        with self._tx() as cur:
            if frag:
                cur.execute(
                    "INSERT INTO share_links(goal_id, token_sha256, created_by, "
                    "created_at, expires_at) SELECT %s, %s, %s, %s, %s WHERE EXISTS "
                    "(SELECT 1 FROM goals WHERE id=%s AND " + frag + ") RETURNING id",
                    (int(goal_id), token_hash, created_by or "", now, exp,
                     int(goal_id), *fparams),
                )
            else:
                cur.execute(
                    "INSERT INTO share_links(goal_id, token_sha256, created_by, "
                    "created_at, expires_at) VALUES(%s, %s, %s, %s, %s) RETURNING id",
                    (int(goal_id), token_hash, created_by or "", now, exp),
                )
            row = cur.fetchone()
        if row is None:
            raise ValueError(f"unknown goal_id {goal_id!r} for the active tenant")
        return int(row[0]), token

    def resolve_share_link(self, token: str) -> int | None:
        """The goal_id a token grants read access to, or None if unknown/revoked/
        expired. Lookup is by hash -- the clear token is never stored.

        Scoped to the active tenant's goals: a share link minted (or planted)
        over another tenant's goal must not resolve cross-tenant."""
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        frag, fparams = _tenant_scope("g.tenant_id")
        sql = ("SELECT s.goal_id, s.expires_at, s.revoked FROM share_links s "
               "JOIN goals g ON g.id = s.goal_id WHERE s.token_sha256=%s")
        params: list = [token_hash]
        if frag:
            sql += " AND " + frag
            params += fparams
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            row = cur.fetchone()
        if not row or row[2]:
            return None
        if row[1] is not None and float(row[1]) < time.time():
            return None
        return int(row[0])

    def share_links_for_goal(self, goal_id: int) -> list[dict]:
        """Share links for a goal (manage UI), newest first. Tokens are NOT
        returned (only the hash exists); each row carries its lifecycle state."""
        frag, fparams = _tenant_scope()  # defense-in-depth: bound to active tenant's goals
        sql = ("SELECT id, created_by, created_at, expires_at, revoked "
               "FROM share_links WHERE goal_id=%s")
        params: list = [int(goal_id)]
        if frag:
            sql += " AND goal_id IN (SELECT id FROM goals WHERE " + frag + ")"
            params += fparams
        sql += " ORDER BY id DESC"
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        now = time.time()
        out = []
        for r in rows:
            expired = r[3] is not None and float(r[3]) < now
            revoked = bool(r[4])
            out.append({
                "id": r[0], "created_by": r[1], "created_at": r[2],
                "expires_at": r[3], "revoked": revoked, "expired": expired,
                "active": not revoked and not expired,
            })
        return out

    def revoke_share_link(self, link_id: int, *, goal_id: int | None = None) -> bool:
        """Revoke a share link (optionally only if it belongs to ``goal_id``).
        Returns whether a row was changed.

        Both branches are scoped to the active tenant's goals so a tenant can't
        revoke (deny access to) another tenant's link by guessing a sequential
        ``link_id``. Legacy rows require an unbound caller."""
        frag, fparams = _mutation_tenant_scope("g.tenant_id")
        tcond = ""
        if frag:
            tcond = (" AND goal_id IN (SELECT g.id FROM goals g WHERE " + frag + ")")
        with self._tx() as cur:
            if goal_id is None:
                cur.execute(
                    "UPDATE share_links SET revoked=1 WHERE id=%s" + tcond,
                    (int(link_id), *fparams))
            else:
                cur.execute(
                    "UPDATE share_links SET revoked=1 WHERE id=%s AND goal_id=%s"
                    + tcond,
                    (int(link_id), int(goal_id), *fparams))
            return cur.rowcount > 0

    # ---- Sign-offs (migration v17) ------------------------------------------

    def record_signoff(
        self, goal_id: int, decision: str, *, decided_by: str = "",
        note: str | None = None, expected_updated_at: float | None = None, _cursor=None,
    ) -> bool:
        """Record a human's certify/reject decision on a deliverable. One row per
        goal (a later decision replaces an earlier one).

        Gated on the parent goal being finished and in the active tenant.  The
        optional ``expected_updated_at`` binds the decision to the exact
        deliverable version the reviewer loaded. ``FOR UPDATE`` makes the
        check + upsert atomic with result/artifact invalidation writes. Returns
        ``True`` for a real decision transition and ``False`` for an identical,
        idempotent retry."""
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision must be 'approved' or 'rejected'")
        frag, fparams = _mutation_tenant_scope()
        with (self._tx() if _cursor is None else nullcontext(_cursor)) as cur:
            check_sql = (
                "SELECT status, updated_at FROM goals WHERE id=%s"
            )
            check_params: list = [int(goal_id)]
            if frag:
                check_sql += " AND " + frag
                check_params += fparams
            check_sql += " FOR UPDATE"
            cur.execute(check_sql, tuple(check_params))
            row = cur.fetchone()
            if (
                row is None
                or row[0] != "done"
                or (
                    expected_updated_at is not None
                    and float(row[1]) != float(expected_updated_at)
                )
            ):
                raise ValueError(
                    "goal is not finished or the deliverable changed before sign-off"
                )
            cur.execute(
                "SELECT decision FROM signoffs WHERE goal_id=%s",
                (int(goal_id),),
            )
            current = cur.fetchone()
            if current is not None and current[0] == decision:
                return False
            cur.execute(
                "INSERT INTO signoffs(goal_id, decision, decided_by, note, "
                "created_at) VALUES(%s, %s, %s, %s, %s) "
                "ON CONFLICT (goal_id) DO UPDATE SET decision=EXCLUDED.decision, "
                "decided_by=EXCLUDED.decided_by, note=EXCLUDED.note, "
                "created_at=EXCLUDED.created_at",
                (int(goal_id), str(decision), str(decided_by or ""), _seal(note, "signoffs.note"),
                 time.time()),
            )
            return True

    def signoff_for(self, goal_id: int) -> dict | None:
        """The current sign-off on a goal's deliverable, or None if unreviewed."""
        with self._tx() as cur:
            cur.execute(
                "SELECT goal_id, decision, decided_by, note, created_at "
                "FROM signoffs WHERE goal_id=%s",
                (int(goal_id),),
            )
            r = cur.fetchone()
        if not r:
            return None
        return {"goal_id": r[0], "decision": r[1], "decided_by": r[2],
                "note": _unseal(r[3], "signoffs.note"), "created_at": r[4]}

    def signoffs_for_goals(self, goal_ids) -> dict[int, str]:
        """Map ``goal_id -> decision`` for a batch of goals (goals with no
        sign-off are absent)."""
        ids = [int(g) for g in goal_ids]
        if not ids:
            return {}
        frag, fparams = _tenant_scope()  # defense-in-depth: only this tenant's goals
        sql = "SELECT goal_id, decision FROM signoffs WHERE goal_id = ANY(%s)"
        params: list = [ids]
        if frag:
            sql += " AND goal_id IN (SELECT id FROM goals WHERE " + frag + ")"
            params += fparams
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return {r[0]: r[1] for r in rows}

    # ---- Goal origins (migration v17) ---------------------------------------

    def record_goal_origin(self, goal_id: int, kind: str, ref: str) -> None:
        """Record which automation spawned a goal (one row per goal).

        Gated on the parent goal being in the active tenant (see start_episode)
        so a write against another tenant's goal_id can't land. Single-tenant
        (empty frag) keeps the direct insert."""
        frag, fparams = _mutation_tenant_scope()
        with self._tx() as cur:
            if frag:
                cur.execute(
                    "INSERT INTO goal_origins(goal_id, kind, ref, created_at) "
                    "SELECT %s, %s, %s, %s WHERE EXISTS "
                    "(SELECT 1 FROM goals WHERE id=%s AND " + frag + ") "
                    "ON CONFLICT (goal_id) DO UPDATE SET kind=EXCLUDED.kind, "
                    "ref=EXCLUDED.ref, created_at=EXCLUDED.created_at",
                    (int(goal_id), str(kind), str(ref), time.time(),
                     int(goal_id), *fparams),
                )
            else:
                cur.execute(
                    "INSERT INTO goal_origins(goal_id, kind, ref, created_at) "
                    "VALUES(%s, %s, %s, %s) "
                    "ON CONFLICT (goal_id) DO UPDATE SET kind=EXCLUDED.kind, "
                    "ref=EXCLUDED.ref, created_at=EXCLUDED.created_at",
                    (int(goal_id), str(kind), str(ref), time.time()),
                )

    def goals_for_origin(self, kind: str, ref: str, *, limit: int = 20) -> list[PGGoal]:
        """Goals an automation spawned, most-recent first.

        Scoped to the active tenant's goals: a trigger/schedule ``ref`` can
        collide across tenants, so this row-returning read must not span them
        (its sibling ``origin_status_counts`` is scoped the same way). Without
        the predicate, a tenant could read another tenant's decrypted goal
        content by guessing a colliding automation ``ref``.
        """
        frag, fparams = _tenant_scope("g.tenant_id")
        sql = ("SELECT g.id, g.parent_id, g.title, g.description, g.status, "
               "g.created_at, g.updated_at, g.deadline, g.result, g.owner, "
               "g.execution_principal, g.domain, g.project_id FROM goals g "
               "JOIN goal_origins o ON o.goal_id = g.id "
               "WHERE o.kind=%s AND o.ref=%s")
        params: list = [str(kind), str(ref)]
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " ORDER BY g.id DESC LIMIT %s"
        params.append(max(1, int(limit)))
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [_dec_goal_row(r) for r in rows]

    def origin_status_counts(self, kind: str, ref: str) -> dict[str, int]:
        """An automation's spawned-goal counts keyed by status (run summary).

        Scoped to the active tenant's goals: a trigger/schedule ``ref`` can
        collide across tenants, so the aggregate must not span them (the
        dashboard owner-scopes too; this is the DB-layer backstop)."""
        frag, fparams = _tenant_scope("g.tenant_id")
        sql = ("SELECT g.status, COUNT(*) FROM goals g "
               "JOIN goal_origins o ON o.goal_id = g.id "
               "WHERE o.kind=%s AND o.ref=%s")
        params: list = [str(kind), str(ref)]
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " GROUP BY g.status"
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return {r[0]: int(r[1]) for r in rows}

    def list_active_goals(self, limit: int = 50) -> list[PGGoal]:
        frag, params = _tenant_scope()
        sql = (
            "SELECT id, parent_id, title, description, status, "
            "created_at, updated_at, deadline, result, owner, execution_principal, "
            "domain, project_id "
            "FROM goals "
            "WHERE status IN ('pending', 'in_progress', 'running')"
        )
        p: list = []
        if frag:
            sql += " AND " + frag
            p += params
        sql += " ORDER BY updated_at DESC LIMIT %s"
        p.append(limit)
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            rows = cur.fetchall()
        return [_dec_goal_row(r) for r in rows]

    def recent_goals_by_domain(self, domains: list[str], *, owner: str | None = None,
                               per_domain: int = 5) -> dict[str, list[PGGoal]]:
        """The newest ``per_domain`` goals of each listed domain, newest first.

        Mirrors SQLite: the same answer as one ``list_goals(domain=...,
        limit=per_domain, order="desc")`` per domain, from one grouped query.
        The Results page asks about every deliverable pack (2,031 on a full
        catalog) and each separate query is a network round trip here. A domain
        with no goals is absent from the result.
        """
        wanted = sorted({str(d) for d in domains if d})
        if not wanted:
            return {}
        conds = ["domain = ANY(%s)"]
        params: list = [wanted]
        if owner is not None:
            conds.append("owner = %s")
            params.append(str(owner))
        frag, fparams = _tenant_scope()
        if frag:
            conds.append(frag)
            params += fparams
        with self._tx() as cur:
            cur.execute(
                "SELECT id, parent_id, title, description, status, "
                "created_at, updated_at, deadline, result, owner, execution_principal, "
                "domain, project_id FROM goals WHERE id IN ("
                "SELECT id FROM (SELECT id, ROW_NUMBER() OVER "
                "(PARTITION BY domain ORDER BY id DESC) AS n "
                f"FROM goals WHERE {' AND '.join(conds)}) ranked WHERE n <= %s) "
                "ORDER BY id DESC",
                (*params, max(1, int(per_domain))),
            )
            rows = cur.fetchall()
        found: dict[str, list[PGGoal]] = {}
        for row in rows:
            goal = _dec_goal_row(row)
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
    ) -> list[PGGoal]:
        """List goals, optionally filtered by status + paginated (mirrors SQLite).

        ``domain``/``project_id`` were missing here (unlike SQLite's
        ``list_goals``), so the dashboard's project-detail page and
        domain-scoped inbox both 500 on this backend --
        ``list_goals(project_id=...)`` / ``list_goals(domain=...)`` raised
        ``TypeError`` for a keyword this method didn't accept.
        ``before_id`` is an exclusive immutable ID bound, combined with all
        current tenant/owner filters without reading its anchor. Descending
        order provides continuation; ascending order only applies the bound.
        ``strict_tenant`` excludes legacy unbound rows for named workspaces,
        regardless of the deployment's compatibility setting.
        """
        if before_id is not None and not 0 < int(before_id) <= 2**63 - 1:
            raise ValueError("before_id must be a positive signed 64-bit goal ID")
        direction = "DESC" if str(order).lower() == "desc" else "ASC"
        sql = (
            "SELECT id, parent_id, title, description, status, "
            "created_at, updated_at, deadline, result, owner, execution_principal, "
            "domain, project_id "
            "FROM goals"
        )
        params: list = []
        conds: list[str] = []
        if status:
            conds.append("status = %s")
            params.append(status)
        if owner is not None:
            conds.append("owner = %s")
            params.append(str(owner))
        if domain is not None:
            conds.append("domain = %s")
            params.append(domain)
        if project_id is not None:
            conds.append("project_id = %s")
            params.append(int(project_id))
        if before_id is not None:
            conds.append("id < %s")
            params.append(int(before_id))
        if strict_tenant:
            tenant = _active_tenant()
            frag, fparams = ("tenant_id = %s", [tenant]) if tenant is not None else ("tenant_id IS NULL", [])
        else:
            frag, fparams = _tenant_scope()
        if frag:
            conds.append(frag)
            params += fparams
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += f" ORDER BY id {direction}"
        if limit is not None:
            sql += " LIMIT %s OFFSET %s"
            params += [max(1, int(limit)), max(0, int(offset))]
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [_dec_goal_row(r) for r in rows]

    def list_goal_results(self, *, owner: str, limit: int = 26,
                          offset: int = 0) -> list[PGGoal]:
        """Completed root tasks with saved output for the owner's Results page
        (mirrors SQLite); subtasks stay in their parent conversation."""
        sql = ("SELECT id, parent_id, title, description, status, created_at, updated_at, "
               "deadline, result, owner, execution_principal, domain, project_id FROM goals "
               "WHERE owner = %s AND parent_id IS NULL AND status = 'done' AND result IS NOT NULL")
        params: list = [str(owner)]
        frag, fparams = _tenant_scope()
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " ORDER BY id DESC LIMIT %s OFFSET %s"
        params += [max(1, min(int(limit), 100)), max(0, int(offset))]
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [_dec_goal_row(r) for r in rows]

    def personal_alert_goals(self, owner: str, *, since: float, after_id: int = 0,
                             limit: int = 250) -> list[tuple]:
        """Tenant and owner predicates precede the bounded keyset page."""
        sql = ("SELECT id,parent_id,title,description,status,created_at,updated_at,deadline,"
               "result,owner,execution_principal,domain,project_id,alert_state_revision,"
               "alert_result_revision FROM goals WHERE owner=%s AND id>%s AND "
               "(status NOT IN ('done','cancelled') OR updated_at>=%s OR "
               "EXISTS(SELECT 1 FROM questions q WHERE q.goal_id=goals.id AND q.answer IS NULL))")
        params = [owner, after_id, since]
        fragment, tenant_params = _tenant_scope()
        if fragment:
            sql += " AND " + fragment
            params.extend(tenant_params)
        sql += " ORDER BY id LIMIT %s"
        params.append(max(1, min(500, limit)))
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [(_dec_goal_row(row[:13]), int(row[13]), int(row[14])) for row in rows]

    def conversation_summaries(self, *, owner: str | None = None,
                               limit: int = 25, before_id: int | None = None):
        """Root creation order with owner/tenant filters before the limit."""
        from ..goal_views import ConversationSummary
        from ..world_model import _dec_fields

        sql = "SELECT id,title,status,updated_at,owner FROM goals WHERE parent_id IS NULL"
        params = []
        if owner is not None:
            sql += " AND owner=%s"
            params.append(str(owner))
        if before_id is not None:
            sql += " AND id<%s"
            params.append(int(before_id))
        scope, scope_params = _tenant_scope()
        if scope:
            sql += " AND " + scope
            params.extend(scope_params)
        sql += " ORDER BY id DESC LIMIT %s"
        params.append(max(1, min(100, int(limit))))
        with self._tx() as cursor:
            cursor.execute(sql, tuple(params))
            rows = cursor.fetchall()
        titles = _dec_fields([row[1] for row in rows], "goals.title")
        return [ConversationSummary(row[0], title, row[2], row[3], str(row[4] or ""))
                for row, title in zip(rows, titles, strict=True)]

    def goal_stream_state(self, goal_id: int, *, include_result: bool = False):
        from ..goal_views import GoalStreamState

        columns = "id,status,owner,result" if include_result else "id,status,owner"
        sql = f"SELECT {columns} FROM goals WHERE id=%s"
        params = [goal_id]
        scope, scope_params = _tenant_scope()
        if scope:
            sql += " AND " + scope
            params.extend(scope_params)
        with self._tx() as cursor:
            cursor.execute(sql, tuple(params))
            row = cursor.fetchone()
        if row is None:
            return None
        return GoalStreamState(row[0], row[1], str(row[2] or ""),
                               _unseal(row[3], "goals.result") if include_result else "")

    def most_recent_goal(self) -> PGGoal | None:
        """Most-recently-updated goal regardless of status; mirrors SQLite."""
        frag, params = _tenant_scope()
        sql = (
            "SELECT id, parent_id, title, description, status, "
            "created_at, updated_at, deadline, result, owner, execution_principal, "
            "domain, project_id "
            "FROM goals"
        )
        if frag:
            sql += " WHERE " + frag
        sql += " ORDER BY updated_at DESC LIMIT 1"
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            row = cur.fetchone()
        return _dec_goal_row(row) if row else None

    def active_goal(self) -> PGGoal | None:
        frag, fparams = _tenant_scope()
        sql = (
            "SELECT id, parent_id, title, description, status, "
            "created_at, updated_at, deadline, result, owner, execution_principal, "
            "domain, project_id "
            "FROM goals "
            "WHERE status IN ('active', 'blocked')"
        )
        params: list = []
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " ORDER BY updated_at DESC LIMIT 1"
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            row = cur.fetchone()
        return _dec_goal_row(row) if row else None

    def inflight_goal(self) -> PGGoal | None:
        """Most-recently-updated in-flight goal (active/pending); mirrors SQLite."""
        frag, fparams = _tenant_scope()
        sql = (
            "SELECT id, parent_id, title, description, status, "
            "created_at, updated_at, deadline, result, owner, execution_principal, "
            "domain, project_id "
            "FROM goals "
            "WHERE status IN ('active', 'pending')"
        )
        params: list = []
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " ORDER BY updated_at DESC LIMIT 1"
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            row = cur.fetchone()
        return _dec_goal_row(row) if row else None

    def candidate_goals(self, include_running: bool, limit: int = 500, *, owner: str = "") -> list[PGGoal]:
        """Goals with comparable text for recall (mirrors SQLite). Finished set
        is the written vocabulary done/blocked/cancelled, not the never-written
        succeeded/failed the old query used."""
        conds = ["(COALESCE(title, '') != '' OR COALESCE(description, '') != '')", "owner = %s"]
        params: list = [owner]
        if not include_running:
            conds.insert(0, "status IN ('done', 'blocked', 'cancelled')")
        frag, fparams = _tenant_scope()
        if frag:
            conds.append(frag)
            params += fparams
        params.append(limit)
        with self._tx() as cur:
            cur.execute(
                "SELECT id, parent_id, title, description, status, created_at, "
                "updated_at, deadline, result, owner, execution_principal, "
                "domain, project_id "
                "FROM goals WHERE "
                + " AND ".join(conds)
                + " ORDER BY updated_at DESC LIMIT %s",
                tuple(params),
            )
            rows = cur.fetchall()
        return [_dec_goal_row(r) for r in rows]

    def subgoals(self, parent_id: int, limit: int = 50) -> list[PGGoal]:
        frag, fparams = _tenant_scope()
        sql = (
            "SELECT id, parent_id, title, description, status, created_at, "
            "updated_at, deadline, result, owner, execution_principal, "
            "domain, project_id "
            "FROM goals WHERE parent_id = %s"
        )
        params: list = [parent_id]
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " ORDER BY created_at ASC LIMIT %s"
        params.append(limit)
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [_dec_goal_row(r) for r in rows]

    def reclaim_orphan_goals(
        self, *, max_age_seconds: float = 60.0,
        statuses: tuple[str, ...] = ("active", "pending"),
        resolved_window_seconds: float | None = None,
        exact_tenant: bool = False,
    ) -> int:
        """Mark stale active/pending goals as 'blocked' after a crash.

        Called on startup to recover from SIGKILL/OOM mid-run. Only rows whose
        ``updated_at`` is at least ``max_age_seconds`` old qualify, so a goal
        being driven live in a sibling process isn't reclaimed. Mirrors the
        SQLite WorldModel (kernel calls this on dashboard/serve startup).
        A resolved zero window explicitly reclaims every active/pending goal
        in scope, including monotonic review timestamps ahead of the wall clock.
        Positive windows continue to require the full stale interval.
        The periodic dashboard sweep passes only ``("active",)`` so queued
        ``pending`` goals are left for their dispatcher. ``exact_tenant``
        excludes compatibility-mode NULL rows from that background sweep.
        Returns the number of rows reclaimed.
        """
        statuses = tuple(statuses)
        if not statuses or not set(statuses) <= {"active", "pending"}:
            raise ValueError("orphan reclaim statuses must be active and/or pending")
        marks = ", ".join("%s" for _ in statuses)
        from ..world_model import reclaim_window_seconds
        max_age_seconds = (reclaim_window_seconds(default=max_age_seconds)
                           if resolved_window_seconds is None else float(resolved_window_seconds))
        if not math.isfinite(max_age_seconds) or max_age_seconds < 0:
            raise ValueError("orphan reclaim window must be nonnegative and finite")
        cutoff = time.time() - max_age_seconds
        now = time.time()
        marker = " [process restarted mid-run]"
        if exact_tenant:
            tenant = _active_tenant()
            if tenant is None:
                raise ValueError("exact orphan reclaim requires a configured tenant")
            frag, fparams = "tenant_id = %s", [tenant]
        else:
            frag, fparams = _mutation_tenant_scope()
        from ..crypto_at_rest import at_rest_enabled
        if not at_rest_enabled():
            sql = (
                "UPDATE goals SET status = 'blocked', "
                "result = COALESCE(result, '') || %s, "
                "updated_at = GREATEST(updated_at + 0.000001, %s) "
                f"WHERE status IN ({marks}) AND (%s = 0 OR updated_at <= %s)"
            )
            params: list = [marker, now, *statuses, max_age_seconds, cutoff]
            if frag:
                sql += " AND " + frag
                params += fparams
            with self._tx() as cur:
                cur.execute(sql, tuple(params))
                return cur.rowcount
        # At-rest encryption on: `result` is sealed ciphertext. Concatenating the
        # marker in SQL would corrupt the ciphertext (unrecoverable on decrypt)
        # or write bare plaintext into a sealed column. Append through the seal
        # layer per row instead -- mirrors the SQLite backend. The stale-orphan
        # set on startup is tiny, so the row-by-row cost is negligible.
        sel = (
            "SELECT id, result FROM goals "
            f"WHERE status IN ({marks}) AND (%s = 0 OR updated_at <= %s)"
        )
        sparams: list = [*statuses, max_age_seconds, cutoff]
        if frag:
            sel += " AND " + frag
            sparams += fparams
        with self._tx() as cur:
            cur.execute(sel, tuple(sparams))
            rows = cur.fetchall()
            from ..crypto_at_rest import EncryptionUnavailable
            from ..world_model import _UNSEALED_WITHHELD
            reclaimed = 0
            for row in rows:
                try:
                    dec = _unseal(row[1], "goals.result")
                    # Strict mode withholds a not-yet-migrated plaintext result
                    # (_unseal returns the sentinel, never the real value);
                    # re-sealing the sentinel here would overwrite -- and
                    # permanently destroy -- the original. Fall through to the
                    # status-only reclaim below instead.
                    new_result = (
                        None if dec == _UNSEALED_WITHHELD
                        else _seal((dec or "") + marker, "goals.result")
                    )
                except EncryptionUnavailable:
                    new_result = None
                if new_result is None:
                    # One orphan whose result can't be recovered -- sealed under
                    # a rotated or foreign at-rest key, or withheld under strict
                    # mode -- must not abort crash-recovery for every other
                    # stuck goal. Reclaim the status; leave the result intact
                    # rather than corrupting or dropping it.
                    update = (
                        "UPDATE goals SET status = 'blocked', updated_at = GREATEST(updated_at + 0.000001, %s) "
                        f"WHERE id = %s AND status IN ({marks}) "
                        "AND (%s = 0 OR updated_at <= %s)"
                    )
                    if frag:
                        update += " AND " + frag
                    cur.execute(update, (now, row[0], *statuses, max_age_seconds, cutoff, *fparams))
                    reclaimed += cur.rowcount
                    continue
                update = (
                    "UPDATE goals SET status = 'blocked', result = %s, "
                    "updated_at = GREATEST(updated_at + 0.000001, %s) "
                    f"WHERE id = %s AND status IN ({marks}) "
                    "AND (%s = 0 OR updated_at <= %s)"
                )
                if frag:
                    update += " AND " + frag
                cur.execute(update, (new_result, now, row[0], *statuses, max_age_seconds, cutoff, *fparams))
                reclaimed += cur.rowcount
            return reclaimed

    # ----- episodes -----

    def start_episode(self, goal_id: int) -> int:
        # Child rows (episodes/events/turns/...) carry no tenant_id; they inherit
        # tenancy through their goal/conversation FK, and reads enforce it via a
        # JOIN. The writes must too: gate the insert on the parent goal being in
        # the active tenant so a write against another tenant's goal_id can't
        # land. Legacy rows require an unbound caller.
        frag, fparams = _mutation_tenant_scope()
        with self._tx() as cur:
            if frag:
                cur.execute(
                    "INSERT INTO episodes(goal_id, started_at) SELECT %s, %s "
                    "WHERE EXISTS (SELECT 1 FROM goals WHERE id=%s AND "
                    + frag + ") RETURNING id",
                    (goal_id, time.time(), goal_id, *fparams),
                )
            else:
                cur.execute(
                    "INSERT INTO episodes(goal_id, started_at) VALUES(%s, %s) "
                    "RETURNING id",
                    (goal_id, time.time()),
                )
            row = cur.fetchone()
        if row is None:
            raise ValueError(f"unknown goal_id {goal_id!r} for the active tenant")
        return int(row[0])

    def _episode_tenant_cond(self) -> tuple[str, list]:
        """SQL fragment + params restricting an episode UPDATE (keyed by
        episode_id) to episodes whose parent goal is owned by the active scope."""
        frag, fparams = _mutation_tenant_scope()
        if not frag:
            return "", []
        return (" AND goal_id IN (SELECT id FROM goals WHERE " + frag + ")", fparams)

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
        """Mirror in-flight spend onto a live (not-yet-ended) episode row.

        Observability mirror only (see the SQLite backend's docstring): the
        `ended_at IS NULL` guard keeps it from clobbering `end_episode`.
        """
        cond, cparams = self._episode_tenant_cond()
        with self._tx() as cur:
            cur.execute(
                "UPDATE episodes SET cost_dollars=%s, input_tokens=%s, "
                "output_tokens=%s, tool_calls=%s, cache_read_tokens=%s, "
                "cache_write_tokens=%s "
                "WHERE id=%s AND ended_at IS NULL" + cond,
                (cost_dollars, input_tokens, output_tokens, tool_calls,
                 cache_read_tokens, cache_write_tokens, episode_id, *cparams),
            )

    def end_episode(
        self,
        episode_id: int,
        summary: str,
        outcome: str,
        *,
        cost_dollars: float = 0.0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        tool_calls: int = 0,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> None:
        cond, cparams = self._episode_tenant_cond()
        with self._tx() as cur:
            cur.execute(
                "UPDATE episodes SET ended_at=%s, summary=%s, outcome=%s, "
                "cost_dollars=%s, input_tokens=%s, output_tokens=%s, "
                "tool_calls=%s, cache_read_tokens=%s, cache_write_tokens=%s "
                "WHERE id=%s" + cond,
                (time.time(), _seal(summary, "episodes.summary"), _seal(outcome, "episodes.outcome"),
                 cost_dollars, input_tokens, output_tokens, tool_calls,
                 cache_read_tokens, cache_write_tokens, episode_id, *cparams),
            )

    def list_episodes(
        self,
        limit: int = 50,
        goal_id: int | None = None,
        owner: str | None = None,
    ) -> list:
        """Recent run-cost episodes, newest first.

        ``owner`` scopes to one principal's runs through the owning goal;
        ``None`` retains the tenant-wide admin/auth-off view. Tenant and owner
        predicates are cumulative, so an owner filter can never widen the
        active tenant boundary.
        """
        from ..world_records import EpisodeSpend
        cols = (
            "e.id, e.goal_id, e.started_at, e.ended_at, e.outcome, "
            "COALESCE(e.cost_dollars, 0), COALESCE(e.input_tokens, 0), "
            "COALESCE(e.output_tokens, 0), COALESCE(e.tool_calls, 0), "
            "COALESCE(e.cache_read_tokens, 0), COALESCE(e.cache_write_tokens, 0)"
        )
        frag, fparams = _tenant_scope("g.tenant_id")
        conds: list[str] = []
        params: list = []
        table = "episodes e"
        if frag or owner is not None:
            table += " JOIN goals g ON g.id = e.goal_id"
        if goal_id is not None:
            conds.append("e.goal_id = %s")
            params.append(goal_id)
        if owner is not None:
            conds.append("g.owner = %s")
            params.append(owner)
        if frag:
            conds.append(frag)
            params += fparams
        sql = f"SELECT {cols} FROM {table}"
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY e.started_at DESC LIMIT %s"
        params.append(limit)
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        # outcome (index 4) is sealed at rest; the rest are numeric/timestamps.
        return [EpisodeSpend(r[0], r[1], r[2], r[3], _unseal(r[4], "episodes.outcome"),
                             r[5], r[6], r[7], r[8], r[9], r[10]) for r in rows]

    def episode_costs_since(self, since: float, *, limit: int = 100_000) -> list[tuple[str, float, float]]:
        """Finished runs that ended at or after ``since``, oldest first, as
        ``(owner, ended_at, cost_dollars)`` -- the SQLite backend's contract,
        inside the active tenant."""
        frag, fparams = _tenant_scope("g.tenant_id")
        sql = ("SELECT COALESCE(g.owner, ''), e.ended_at, COALESCE(e.cost_dollars, 0) "
               "FROM episodes e JOIN goals g ON g.id = e.goal_id "
               "WHERE e.ended_at IS NOT NULL AND e.ended_at >= %s")
        params: list = [float(since)]
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " ORDER BY e.ended_at ASC, e.id ASC LIMIT %s"
        params.append(int(limit))
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [(str(r[0] or ""), float(r[1]), float(r[2] or 0.0)) for r in rows]

    def task_costs_for(self, *, domain: str = "", execution_principal: str = "",
                       limit: int = 500, owner: str = "") -> list[float]:
        """The SQLite backend's contract, inside the active tenant."""
        column, value = (("g.domain", domain) if domain else ("g.execution_principal", execution_principal)
                         if execution_principal else ("g.owner", owner))
        if not value:
            return []
        frag, fparams = _tenant_scope("g.tenant_id")
        sql = ("SELECT SUM(COALESCE(e.cost_dollars, 0)), MAX(e.ended_at) "
               f"FROM episodes e JOIN goals g ON g.id = e.goal_id WHERE {column} = %s "
               "AND e.ended_at IS NOT NULL")
        params: list = [str(value)]
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " GROUP BY e.goal_id ORDER BY 2 DESC LIMIT %s"
        params.append(int(limit))
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [float(r[0] or 0.0) for r in rows]

    def episode_exists(self, goal_id: int, episode_id: int) -> bool:
        frag, fparams = _tenant_scope("g.tenant_id")
        table = "episodes e"
        scope = ""
        if frag:
            table += " JOIN goals g ON g.id = e.goal_id"
            scope = " AND " + frag
        with self._tx() as cur:
            cur.execute(
                f"SELECT 1 FROM {table} "
                f"WHERE e.id = %s AND e.goal_id = %s{scope} LIMIT 1",
                tuple([episode_id, goal_id, *fparams]),
            )
            return cur.fetchone() is not None

    def total_spend(self, owner: str | None = None, *,
                    since: float | None = None) -> dict[str, float]:
        """Aggregate spend. ``owner`` scopes to one principal's runs (join to
        the owning goal), matching the SQLite backend's signature; ``None``
        is the deployment-wide admin / auth-off view; ``since`` keeps only runs
        that started at or after that time, as on SQLite. Owner-scoped callers
        (``/api/v1/spend``, external-agent spend records) rely on ``owner``.
        """
        frag, params = _tenant_scope("g.tenant_id")
        table = "episodes e"
        if frag or owner is not None:
            table += " JOIN goals g ON g.id = e.goal_id"
        sql = (
            "SELECT COALESCE(SUM(e.cost_dollars), 0), COALESCE(SUM(e.input_tokens), 0), "
            "COALESCE(SUM(e.output_tokens), 0), COUNT(*) "
            f"FROM {table} WHERE e.ended_at IS NOT NULL"
        )
        if frag:
            sql += " AND " + frag
        if owner is not None:
            sql += " AND g.owner = %s"
            params = (*params, owner)
        if since is not None:
            sql += " AND e.started_at >= %s"
            params = (*params, float(since))
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            row = cur.fetchone()
        return {
            "dollars": row[0],
            "input_tokens": row[1],
            "output_tokens": row[2],
            "runs": row[3],
        }

    # ----- events -----

    def append_event(self, goal_id: int, agent: str, kind: str, content: str) -> int:
        # Gate on the parent goal being in the active tenant (see start_episode).
        frag, fparams = _mutation_tenant_scope()
        with self._tx() as cur:
            if frag:
                cur.execute(
                    "INSERT INTO goal_events(goal_id, agent, kind, content, ts) "
                    "SELECT %s, %s, %s, %s, %s WHERE EXISTS "
                    "(SELECT 1 FROM goals WHERE id=%s AND " + frag + ") RETURNING id",
                    (goal_id, agent, kind, _seal(content, "goal_events.content"), time.time(),
                     goal_id, *fparams),
                )
            else:
                cur.execute(
                    "INSERT INTO goal_events(goal_id, agent, kind, content, ts) "
                    "VALUES(%s, %s, %s, %s, %s) RETURNING id",
                    (goal_id, agent, kind, _seal(content, "goal_events.content"), time.time()),
                )
            row = cur.fetchone()
        if row is None:
            raise ValueError(f"unknown goal_id {goal_id!r} for the active tenant")
        return int(row[0])

    def goal_events(self, goal_id: int, since_id: int = 0, limit: int = 200) -> list:
        from ..world_records import GoalEvent
        frag, fparams = _tenant_scope("g.tenant_id")
        table = "goal_events ge"
        if frag:
            table += " JOIN goals g ON g.id = ge.goal_id"
        sql = (
            "SELECT ge.id, ge.goal_id, ge.agent, ge.kind, ge.content, ge.ts "
            f"FROM {table} WHERE ge.goal_id=%s AND ge.id > %s"
        )
        params: list = [goal_id, since_id]
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " ORDER BY ge.id ASC LIMIT %s"
        params.append(limit)
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        # content (index 4) is sealed at rest.
        return [GoalEvent(r[0], r[1], r[2], r[3], _unseal(r[4], "goal_events.content"), r[5]) for r in rows]

    def recent_goal_events(self, goal_id: int, limit: int = 200) -> list:
        from ..world_records import GoalEvent
        frag, fparams = _tenant_scope("g.tenant_id")
        table = "goal_events ge"
        scope = ""
        if frag:
            table += " JOIN goals g ON g.id = ge.goal_id"
            scope = " AND " + frag
        params: list = [goal_id, *fparams, limit]
        with self._tx() as cur:
            cur.execute(
                "SELECT id, goal_id, agent, kind, content, ts FROM ("
                "SELECT ge.id, ge.goal_id, ge.agent, ge.kind, ge.content, ge.ts "
                f"FROM {table} WHERE ge.goal_id=%s{scope} "
                "ORDER BY ge.id DESC LIMIT %s"
                ") recent ORDER BY id ASC",
                tuple(params),
            )
            rows = cur.fetchall()
        # content (index 4) is sealed at rest.
        return [GoalEvent(r[0], r[1], r[2], r[3], _unseal(r[4], "goal_events.content"), r[5]) for r in rows]

    # ----- facts (global key/value memory) -----

    def _locked_open_fact_history(self, cur, key: str, tenant: str | None):
        """Lock one temporal key and return its current window + tenant scope."""
        cur.execute(
            "SELECT pg_advisory_xact_lock(hashtext(%s))",
            (f"fact:{tenant or ''}:{key}",),
        )
        frag, params = _mutation_tenant_scope()
        sql = (
            "SELECT value, trust_tier, valid_from FROM fact_history "
            "WHERE key = %s AND valid_to IS NULL"
        )
        p: list = [key]
        if frag:
            sql += " AND " + frag
            p += params
        sql += " ORDER BY valid_from DESC LIMIT 1"
        cur.execute(sql, tuple(p))
        return cur.fetchone(), frag, params

    def _check_fact_revision(self, cur, key: str, expected: int | None) -> None:
        from ..fact_revision import check_expected_revision
        # Also lock unconditional writers so a compare-and-write cannot race
        # an agent or background write when temporal history is disabled.
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",
                    (f"fact:{_active_tenant() or ''}:{key}",))
        frag, params = _mutation_tenant_scope()
        cur.execute(f"SELECT write_seq FROM facts WHERE key = %s AND {frag}",
                    (key, *params))
        row = cur.fetchone()
        check_expected_revision(expected, int(row[0]) if row else 0)

    def fact_record(self, key: str) -> dict | None:
        rows = self.fact_records(query=key, exact=True, limit=1)
        return rows[0] if rows else None

    def fact_records(self, *, query: str = "", source: str = "", tag: str = "",
                     updated_before: float | None = None, limit: int = 50,
                     offset: int = 0, exact: bool = False,
                     shared_only: bool = False) -> list[dict]:
        # Interactive fact editing uses exact tenant ownership, including in
        # legacy compatibility mode. It never offers another tenant's record.
        frag, params = _mutation_tenant_scope()
        clauses, values = [frag], list(params)
        if shared_only:
            clauses.extend(("LOWER(key) NOT LIKE 'goal:%%'", "LOWER(key) NOT LIKE 'user:%%'"))
        if query:
            clauses.append("key = %s" if exact else "key ILIKE %s ESCAPE '\\'")
            values.append(query if exact else "%" + self._like_escape(query) + "%")
        if source:
            clauses.append("source ILIKE %s ESCAPE '\\'")
            values.append("%" + self._like_escape(source) + "%")
        if updated_before is not None:
            clauses.append("updated_at < %s")
            values.append(float(updated_before))
        if tag:
            clauses.append("tags_json::jsonb @> %s::jsonb")
            values.append(json.dumps([tag.strip().casefold()]))
        with self._tx() as cur:
            cur.execute(
                "SELECT key, value, write_seq, updated_at, source, source_episode_id, "
                "trust_tier, sensitivity, tags_json FROM facts WHERE " + " AND ".join(clauses)
                + " ORDER BY key LIMIT %s OFFSET %s",
                (*values, max(1, min(limit, 101)), max(0, offset)),
            )
            rows = cur.fetchall()
        names = ("key", "value", "revision", "updated_at", "source", "source_episode_id",
                 "trust_tier", "sensitivity", "tags")
        return [{**dict(zip(names, row, strict=True)), "value": _unseal(row[1], "facts.value"),
                 "tags": json.loads(row[8])} for row in rows]

    def fact_catalog_revision(self) -> str:
        frag, params = _mutation_tenant_scope()
        with self._tx() as cur:
            cur.execute("SELECT COUNT(*), COALESCE(MAX(write_seq),0) FROM facts WHERE "
                        + frag + " AND LOWER(key) NOT LIKE 'goal:%%' AND LOWER(key) NOT LIKE 'user:%%'", tuple(params))
            row = cur.fetchone()
        return f"{row[0]}:{row[1]}"

    def upsert_fact(
        self, key: str, value: str, episode_id: int | None = None,
        *, source: str = "", trust_tier: int = 3, sensitivity: str = "internal",
        expected_revision: int | None = None, tags: list[str] | None = None,
    ) -> int:
        """Write the current value of ``key``.

        When ``[memory] temporal`` is on, a *changed* value (or a changed trust
        tier) also appends a version to ``fact_history`` and closes the prior
        open window -- non-destructive evolution, mirroring the SQLite backend.
        The Memory Guard provenance kwargs are persisted on the history row; the
        live ``facts`` row keeps its existing columns (the write-time screen in
        kv_memory, the primary ASI06 control, runs regardless of backend).
        """
        from ..fact_revision import normalize_tags
        from ..world_model import _refuse_withheld_placeholder, _temporal_memory_enabled
        _refuse_withheld_placeholder(value)
        encoded_tags = json.dumps(normalize_tags(tags)) if tags is not None else None
        now = time.time()
        tenant = _active_tenant()
        with self._tx() as cur:
            self._check_fact_revision(cur, key, expected_revision)
            if _temporal_memory_enabled():
                # Serialize concurrent writers for THIS key across replicas: the
                # close-prior-window/open-new-window sequence is a read-modify-
                # write that would otherwise leave TWO open windows (valid_to IS
                # NULL) under a race. Per-key advisory lock (auto-released at
                # COMMIT); other keys hash elsewhere and don't contend.
                open_row, frag, params = self._locked_open_fact_history(
                    cur, key, tenant
                )
                # A new version is recorded when the open window's value or trust
                # tier differs (or there is no open window yet) -- the same
                # "distinct belief" rule the SQLite backend applies.
                changed = (
                    open_row is None
                    or _unseal(open_row[0], "facts.value") != value
                    or int(open_row[1]) != int(trust_tier)
                )
                if changed:
                    # Preserve a valid per-key temporal window through clock
                    # rollback without globally serializing every tenant fact
                    # write or scanning MAX(updated_at).
                    if open_row is not None and now <= float(open_row[2]):
                        now = math.nextafter(float(open_row[2]), math.inf)
                    close = "UPDATE fact_history SET valid_to = %s WHERE key = %s AND valid_to IS NULL"
                    cp: list = [now, key]
                    if frag:
                        close += " AND " + frag
                        cp += params
                    cur.execute(close, tuple(cp))
                    cur.execute(
                        "INSERT INTO fact_history(key, value, source_episode_id, "
                        "valid_from, valid_to, source, trust_tier, sensitivity, tenant_id) "
                        "VALUES(%s, %s, %s, %s, NULL, %s, %s, %s, %s)",
                        (key, _seal(value, "facts.value"), episode_id, now, source,
                         int(trust_tier), sensitivity, tenant),
                    )
            cur.execute(
                "INSERT INTO facts(key, value, source_episode_id, updated_at, "
                "source, trust_tier, sensitivity, tenant_id) "
                "VALUES(%s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT ((COALESCE(tenant_id, '')), key) DO UPDATE SET "
                "write_seq = EXCLUDED.write_seq, "
                "value = EXCLUDED.value, "
                "source_episode_id = EXCLUDED.source_episode_id, "
                "updated_at = EXCLUDED.updated_at, "
                "source = EXCLUDED.source, "
                "trust_tier = EXCLUDED.trust_tier, "
                "sensitivity = EXCLUDED.sensitivity RETURNING write_seq",
                (key, _seal(value, "facts.value"), episode_id, now, source,
                 int(trust_tier), sensitivity, tenant),
            )
            revision = int(cur.fetchone()[0])
            if encoded_tags is not None:
                frag, params = _mutation_tenant_scope()
                cur.execute("UPDATE facts SET tags_json = %s WHERE key = %s AND " + frag,
                            (encoded_tags, key, *params))
            return revision

    def get_facts(self) -> dict[str, str]:
        frag, params = _tenant_scope()
        precedence, precedence_params = _tenant_precedence()
        precedence_order = f"{precedence}, " if precedence else ""
        sql = (
            "SELECT key, value FROM ("
            "SELECT key, value, write_seq, "
            "ROW_NUMBER() OVER (PARTITION BY key ORDER BY "
            f"{precedence_order}write_seq DESC) AS fact_rank FROM facts"
        )
        if frag:
            sql += " WHERE " + frag
        sql += ") AS ranked WHERE fact_rank = 1 ORDER BY write_seq DESC"
        with self._tx() as cur:
            cur.execute(sql, tuple(precedence_params + params))
            rows = cur.fetchall()
        return {r[0]: _unseal(r[1], "facts.value") for r in rows}

    def get_facts_with_trust(self) -> dict[str, tuple[str, int]]:
        """Return each fact with its Memory-Guard recall-trust tier.

        ``upsert_fact`` persists the provenance trust_tier directly on the
        ``facts`` table (schema v24), so the Memory Guard (orchestrator ->
        memory_guard.filter_facts) can drop poisoned/external memory below
        ``min_recall_trust`` on this backend whether or not temporal history is
        on -- closing the old non-temporal fallback. A pre-migration row with no
        explicit tier reads as 3 (first-party) via the column DEFAULT, so the
        guard keeps rather than drops memory it cannot tier. Value and tier
        must be selected in the same transaction: separate snapshots could
        pair an older untrusted value with a newer trusted reassertion.
        Read is tenant-scoped identically to ``get_facts``.
        """
        frag, params = _tenant_scope()
        precedence, precedence_params = _tenant_precedence()
        precedence_order = f"{precedence}, " if precedence else ""
        sql = (
            "SELECT key, value, trust_tier FROM ("
            "SELECT key, value, trust_tier, write_seq, "
            "ROW_NUMBER() OVER (PARTITION BY key ORDER BY "
            f"{precedence_order}write_seq DESC) AS fact_rank FROM facts"
        )
        if frag:
            sql += " WHERE " + frag
        sql += ") AS ranked WHERE fact_rank = 1 ORDER BY write_seq DESC"
        with self._tx() as cur:
            cur.execute(sql, tuple(precedence_params + params))
            rows = cur.fetchall()
        return {r[0]: (_unseal(r[1], "facts.value"), int(r[2])) for r in rows}

    def facts_matching(self, token: str) -> dict[str, str]:
        """Facts explicitly scoped to ``token`` by ``user:<token>:`` key prefix.

        Mirrors the SQLite backend: only deliberately namespaced keys are
        considered (never values, never arbitrary substrings), so GDPR
        export/erase can't disclose or delete unrelated global facts.
        """
        if not token:
            return {}
        prefix = f"user:{token}:"
        return {k: v for k, v in self.get_facts().items() if k.startswith(prefix)}

    def delete_facts_matching(self, token: str) -> list[str]:
        """Delete user-scoped facts (see :meth:`facts_matching`); return the keys."""
        prefix = f"user:{token}:" if token else ""
        if not prefix:
            return []
        # A bound compatibility tenant can read legacy NULL rows, so an Art.17
        # erase must purge those rows too. The unbound view has authority over
        # legacy NULL rows only.
        frag, fparams = _erasure_tenant_scope()
        escaped = self._like_escape(prefix) + "%"
        with self._tx() as cur:
            # Match temporal upsert's table-access order. SHARE ROW EXCLUSIVE
            # blocks concurrent INSERT/UPDATE/DELETE on both tables until this
            # live + history purge commits, while ordinary reads remain available.
            cur.execute(
                "LOCK TABLE fact_history, facts IN SHARE ROW EXCLUSIVE MODE"
            )
            delete = (
                "DELETE FROM facts WHERE key LIKE %s ESCAPE '\\'"
            )
            delete_params: list = [escaped]
            if frag:
                delete += " AND " + frag
                delete_params += fparams
            delete += " RETURNING key"
            cur.execute(delete, tuple(delete_params))
            # Compatibility scope can contain an own and legacy row with the
            # same natural key. Preserve the public list-of-unique-keys contract.
            keys = sorted({row[0] for row in cur.fetchall()})
            # GDPR Art.17: hard-purge the bitemporal history for the WHOLE subject
            # prefix (not just live keys) so a value individually deleted earlier
            # -- window closed, row retained -- is erased too and can't be
            # recovered via get_fact(as_of=...). No-op when temporal never wrote.
            sql = "DELETE FROM fact_history WHERE key LIKE %s ESCAPE '\\'"
            params = [escaped]
            if frag:
                sql += " AND " + frag
                params += fparams
            cur.execute(sql, tuple(params))
        return keys

    def fact_history_matching(self, token: str) -> dict[str, list]:
        """All recorded fact versions under ``user:<token>:`` (incl. keys removed
        from the live table) for the GDPR Art.15 export. Empty unless ``[memory]
        temporal`` retained history. Mirrors the SQLite backend."""
        if not token:
            return {}
        from ..world_records import FactVersion
        prefix = f"user:{token}:"
        frag, params = _tenant_scope()
        tenant = _active_tenant()
        compatibility_tenant = (
            tenant if tenant is not None and not _strict_tenant_isolation()
            else None
        )
        sql = (
            "SELECT id, key, value, valid_from, valid_to, source, trust_tier, "
            "sensitivity, tenant_id FROM fact_history "
            "WHERE key LIKE %s ESCAPE '\\'"
        )
        p: list = [self._like_escape(prefix) + "%"]
        if frag:
            sql += " AND " + frag
            p += params
        sql += " ORDER BY key, valid_from, id"
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            rows = _effective_fact_history_rows(
                cur.fetchall(), compatibility_tenant
            )
        rows.sort(key=lambda row: (row[1], row[3], row[0]))
        out: dict[str, list] = {}
        for r in rows:
            out.setdefault(r[1], []).append(FactVersion(
                value=_unseal(r[2], "facts.value"), valid_from=r[3], valid_to=r[4],
                source=r[5] or "", trust_tier=int(r[6]),
                sensitivity=r[7] or "internal",
            ))
        return out

    @staticmethod
    def _like_escape(s: str) -> str:
        return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def get_fact(self, key: str, *, as_of: float | None = None) -> str | None:
        """Single fact value by exact key, or None.

        With ``as_of`` (a unix timestamp) the value is read from
        ``fact_history`` as it stood at that instant (requires ``[memory]
        temporal``); returns None when no recorded version covered that time."""
        frag, params = _tenant_scope()
        precedence, precedence_params = _tenant_precedence()
        precedence_order = f"{precedence}, " if precedence else ""
        if as_of is not None:
            sql = (
                "SELECT value FROM fact_history WHERE key = %s AND valid_from <= %s "
                "AND (valid_to IS NULL OR valid_to > %s)"
            )
            p: list = [key, as_of, as_of]
            if frag:
                sql += " AND " + frag
                p += params
            sql += (
                f" ORDER BY {precedence_order}valid_from DESC, id DESC LIMIT 1"
            )
            p += precedence_params
            with self._tx() as cur:
                cur.execute(sql, tuple(p))
                row = cur.fetchone()
            return _unseal(row[0], "facts.value") if row else None
        sql = "SELECT value FROM facts WHERE key = %s"
        p = [key]
        if frag:
            sql += " AND " + frag
            p += params
        sql += f" ORDER BY {precedence_order}write_seq DESC LIMIT 1"
        p += precedence_params
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            row = cur.fetchone()
        return _unseal(row[0], "facts.value") if row else None

    def fact_history(self, key: str, *, limit: int = 50,
                     owned_only: bool = False) -> list:
        """Every recorded version of ``key``, newest first (requires ``[memory]
        temporal``). The row whose ``valid_to is None`` is the current value."""
        from ..world_records import FactVersion
        frag, params = _mutation_tenant_scope() if owned_only else _tenant_scope()
        tenant = _active_tenant()
        row_limit = max(1, int(limit))
        compatibility_tenant = (
            tenant if not owned_only and tenant is not None and not _strict_tenant_isolation()
            else None
        )
        columns = (
            "id, key, value, valid_from, valid_to, source, trust_tier, "
            "sensitivity, tenant_id"
        )
        if compatibility_tenant is not None:
            # Project the effective compatibility timeline in Postgres so the
            # transfer and Python allocation remain bounded by ``limit``. Every
            # raw interval boundary starts a half-open segment; a lateral lookup
            # applies the same own-over-legacy precedence as ``get_fact(as_of)``.
            # Adjacent segments selecting the same source row are collapsed,
            # while a legacy row interrupted by an own interval stays split.
            sql = (
                f"WITH scoped AS (SELECT {columns} FROM fact_history "
                "WHERE key = %s"
            )
            p: list = [key]
            if frag:
                sql += " AND " + frag
                p += params
            sql += (
                "), points AS ("
                "SELECT valid_from AS point FROM scoped "
                "UNION SELECT valid_to AS point FROM scoped "
                "WHERE valid_to IS NOT NULL"
                "), segments AS ("
                "SELECT point AS segment_start, "
                "LEAD(point) OVER (ORDER BY point) AS segment_end FROM points"
                "), selected AS ("
                "SELECT chosen.*, segments.segment_start, segments.segment_end "
                "FROM segments JOIN LATERAL ("
                f"SELECT {columns} FROM scoped "
                "WHERE valid_from <= segments.segment_start "
                "AND (valid_to IS NULL OR valid_to > segments.segment_start) "
                "ORDER BY CASE WHEN tenant_id = %s THEN 0 ELSE 1 END, "
                "valid_from DESC, id DESC LIMIT 1"
                ") AS chosen ON TRUE"
                "), marked AS ("
                "SELECT selected.*, CASE WHEN "
                "LAG(id) OVER (ORDER BY segment_start) = id THEN 0 ELSE 1 END "
                "AS starts_group FROM selected"
                "), grouped AS ("
                "SELECT marked.*, SUM(starts_group) OVER "
                "(ORDER BY segment_start) AS segment_group FROM marked"
                ") "
                "SELECT id, key, value, MIN(segment_start) AS valid_from, "
                "CASE WHEN COUNT(*) FILTER (WHERE segment_end IS NULL) > 0 "
                "THEN NULL ELSE MAX(segment_end) END AS valid_to, "
                "source, trust_tier, sensitivity, tenant_id FROM grouped "
                "GROUP BY segment_group, id, key, value, source, trust_tier, "
                "sensitivity, tenant_id "
                "ORDER BY MIN(segment_start) DESC, id DESC LIMIT %s"
            )
            p += [compatibility_tenant, row_limit]
        else:
            # Strict and unbound views use the normal database-side limit and
            # do not receive compatibility projection.
            sql = f"SELECT {columns} FROM fact_history WHERE key = %s"
            p = [key]
            if frag:
                sql += " AND " + frag
                p += params
            sql += " ORDER BY valid_from DESC, id DESC LIMIT %s"
            p.append(row_limit)
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            rows = cur.fetchall()
        rows.sort(key=lambda row: (row[3], row[0]), reverse=True)
        return [
            FactVersion(
                value=_unseal(r[2], "facts.value"), valid_from=r[3], valid_to=r[4],
                source=r[5] or "", trust_tier=int(r[6]),
                sensitivity=r[7] or "internal",
            )
            for r in rows
        ]

    def delete_fact(self, key: str, *, expected_revision: int | None = None) -> int:
        """Delete one fact by exact key; return rows removed (0 or 1).

        When ``[memory] temporal`` is on, the open ``fact_history`` window is
        closed (valid_to = now) rather than erased, so the record that the fact
        existed until this moment survives the delete."""
        from ..world_model import _temporal_memory_enabled
        frag, params = _mutation_tenant_scope()
        tenant = _active_tenant()
        with self._tx() as cur:
            self._check_fact_revision(cur, key, expected_revision)
            if _temporal_memory_enabled():
                open_row, frag, params = self._locked_open_fact_history(
                    cur, key, tenant
                )
                closed_at = time.time()
                if open_row is not None and closed_at <= float(open_row[2]):
                    closed_at = math.nextafter(float(open_row[2]), math.inf)
                close = "UPDATE fact_history SET valid_to = %s WHERE key = %s AND valid_to IS NULL"
                cp: list = [closed_at, key]
                if frag:
                    close += " AND " + frag
                    cp += params
                cur.execute(close, tuple(cp))
            sql = "DELETE FROM facts WHERE key = %s"
            p: list = [key]
            if frag:
                sql += " AND " + frag
                p += params
            cur.execute(sql, tuple(p))
            return cur.rowcount

    def list_facts(self, key_prefix: str, limit: int = 50) -> list[tuple[str, int]]:
        like = self._like_escape(key_prefix) + "%"
        frag, params = _tenant_scope()
        precedence, precedence_params = _tenant_precedence()
        precedence_order = f"{precedence}, " if precedence else ""
        sql = (
            "SELECT key, sz FROM ("
            "SELECT key, length(value) AS sz, write_seq, "
            "ROW_NUMBER() OVER (PARTITION BY key ORDER BY "
            f"{precedence_order}write_seq DESC) AS fact_rank FROM facts "
            "WHERE key LIKE %s ESCAPE '\\'"
        )
        p: list = precedence_params + [like]
        if frag:
            sql += " AND " + frag
            p += params
        sql += ") AS ranked WHERE fact_rank = 1 ORDER BY write_seq DESC LIMIT %s"
        p.append(limit)
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            rows = cur.fetchall()
        return [(r[0], r[1]) for r in rows]

    def search_facts(
        self, key_prefix: str, query: str, limit: int = 50,
    ) -> list[tuple[str, str]]:
        pfx = self._like_escape(key_prefix) + "%"
        frag, params = _tenant_scope()
        precedence, precedence_params = _tenant_precedence()
        precedence_order = f"{precedence}, " if precedence else ""
        from ..crypto_at_rest import at_rest_enabled
        if not at_rest_enabled():
            q = "%" + self._like_escape(query) + "%"
            sql = (
                "SELECT key, value FROM (SELECT key, value, write_seq, "
                "ROW_NUMBER() OVER (PARTITION BY key ORDER BY "
                f"{precedence_order}write_seq DESC) AS fact_rank FROM facts "
                "WHERE key LIKE %s ESCAPE '\\'"
            )
            p: list = precedence_params + [pfx]
            if frag:
                sql += " AND " + frag
                p += params
            sql += (
                ") AS ranked WHERE fact_rank = 1 AND "
                "(key LIKE %s ESCAPE '\\' OR value LIKE %s ESCAPE '\\') "
                "ORDER BY write_seq DESC LIMIT %s"
            )
            p += [q, q]
            p.append(limit)
            with self._tx() as cur:
                cur.execute(sql, tuple(p))
                rows = cur.fetchall()
            return [(r[0], _unseal(r[1], "facts.value")) for r in rows]
        # Encryption on: `value` is sealed ciphertext, so a SQL LIKE over it can
        # never match the plaintext query (search would silently return nothing)
        # and the returned value would be ciphertext. Keys are plaintext: narrow
        # the scan by prefix in SQL, then decrypt + substring-match in Python.
        # Mirrors the SQLite backend (case-insensitive, like SQLite LIKE).
        sql = (
            "SELECT key, value FROM (SELECT key, value, write_seq, "
            "ROW_NUMBER() OVER (PARTITION BY key ORDER BY "
            f"{precedence_order}write_seq DESC) AS fact_rank FROM facts "
            "WHERE key LIKE %s ESCAPE '\\'"
        )
        p = precedence_params + [pfx]
        if frag:
            sql += " AND " + frag
            p += params
        sql += ") AS ranked WHERE fact_rank = 1 ORDER BY write_seq DESC"
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            rows = cur.fetchall()
        needle = query.lower()
        out: list[tuple[str, str]] = []
        for r in rows:
            val = _unseal(r[1], "facts.value")
            if needle in r[0].lower() or (val is not None and needle in val.lower()):
                out.append((r[0], val))
                if len(out) >= limit:
                    break
        return out

    # ----- questions (ask_user / human-in-the-loop) -----

    def ask(self, question: str, goal_id: int | None = None) -> int:
        # When attached to a goal, gate on that goal being in the active tenant
        # (matches `answer`, which scopes by the parent goal). A goal-less
        # question has no parent to inherit from, so it inserts directly.
        frag, fparams = _mutation_tenant_scope()
        with self._tx() as cur:
            if frag and goal_id is not None:
                cur.execute(
                    "INSERT INTO questions(goal_id, question, asked_at) "
                    "SELECT %s, %s, %s WHERE EXISTS "
                    "(SELECT 1 FROM goals WHERE id=%s AND " + frag + ") RETURNING id",
                    (goal_id, _seal(question, "questions.question"), time.time(), goal_id, *fparams),
                )
            else:
                cur.execute(
                    "INSERT INTO questions(goal_id, question, asked_at) "
                    "VALUES(%s, %s, %s) RETURNING id",
                    (goal_id, _seal(question, "questions.question"), time.time()),
                )
            row = cur.fetchone()
        if row is None:
            raise ValueError(f"unknown goal_id {goal_id!r} for the active tenant")
        return int(row[0])

    def answer(
        self,
        question_id: int,
        answer: str,
        *,
        expected_owner: str | None = None,
    ) -> bool:
        """Record an answer. Returns False if no question has that id, so a
        typo'd id is flagged instead of reported as a false success.

        Scoped through the parent goal's tenant so a tenant cannot answer
        (overwrite) another tenant's question by id (no-op single-tenant)."""
        frag, fparams = _mutation_tenant_scope("g.tenant_id")
        sql = "UPDATE questions SET answer = %s, answered_at = %s WHERE id = %s"
        params: list = [_seal(answer, "questions.answer"), time.time(), question_id]
        if expected_owner is not None:
            sql += " AND goal_id IN (SELECT id FROM goals WHERE owner = %s)"
            params.append(str(expected_owner))
        if frag:
            sql += " AND goal_id IN (SELECT g.id FROM goals g WHERE " + frag + ")"
            params += fparams
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            affected = cur.rowcount
        return affected > 0

    def open_questions(self, goal_id: int | None = None) -> list:
        cols = "q.id, q.goal_id, q.question, q.asked_at, q.answer, q.answered_at"
        frag, fparams = _tenant_scope("g.tenant_id")
        table = "questions q"
        scope = ""
        if frag:
            table += " JOIN goals g ON g.id = q.goal_id"
            scope = " AND " + frag
        conds = "q.answer IS NULL"
        params: list = []
        if goal_id is not None:
            conds += " AND q.goal_id = %s"
            params.append(goal_id)
        with self._tx() as cur:
            cur.execute(
                f"SELECT {cols} FROM {table} WHERE {conds}{scope} ORDER BY q.id",
                tuple([*params, *fparams]),
            )
            rows = cur.fetchall()
        return [_dec_question_row(r) for r in rows]

    def open_channel_questions(
        self, conversation_id: int, owner: str, execution_principal: str,
    ) -> list:
        """Only blocked questions bound to this tenant's exact conversation."""
        frag, fparams = _tenant_scope("g.tenant_id")
        with self._tx() as cur:
            cur.execute(
                "SELECT q.id, q.goal_id, q.question, q.asked_at, q.answer, q.answered_at "
                "FROM questions q JOIN goals g ON g.id = q.goal_id "
                "WHERE q.answer IS NULL AND g.status = 'blocked' "
                "AND g.owner = %s AND g.execution_principal = %s "
                "AND EXISTS (SELECT 1 FROM turns t WHERE t.goal_id = g.id "
                "AND t.conversation_id = %s AND t.role = 'user')"
                + (" AND " + frag if frag else "") + " ORDER BY q.id",
                (owner, execution_principal, conversation_id, *fparams),
            )
            rows = cur.fetchall()
        return [_dec_question_row(r) for r in rows]

    def answer_open_channel_question(
        self, question_id: int, goal_id: int, answer: str, *,
        conversation_id: int, owner: str, execution_principal: str,
    ) -> bool:
        """Claim one open question under its owner, thread, and tenant."""
        frag, fparams = _mutation_tenant_scope("g.tenant_id")
        with self._tx() as cur:
            cur.execute(
                "UPDATE questions SET answer = %s, answered_at = %s "
                "WHERE id = %s AND goal_id = %s AND answer IS NULL "
                "AND EXISTS (SELECT 1 FROM goals g WHERE g.id = questions.goal_id "
                "AND g.status = 'blocked' AND g.owner = %s "
                "AND g.execution_principal = %s "
                "AND EXISTS (SELECT 1 FROM turns t WHERE t.goal_id = g.id "
                "AND t.conversation_id = %s AND t.role = 'user')"
                + (" AND " + frag if frag else "") + ")",
                (_seal(answer, "questions.answer"), time.time(), question_id, goal_id, owner,
                 execution_principal, conversation_id, *fparams),
            )
            return cur.rowcount == 1

    def all_questions(self, goal_id: int) -> list:
        frag, fparams = _tenant_scope("g.tenant_id")
        table = "questions q"
        scope = ""
        if frag:
            table += " JOIN goals g ON g.id = q.goal_id"
            scope = " AND " + frag
        with self._tx() as cur:
            cur.execute(
                "SELECT q.id, q.goal_id, q.question, q.asked_at, q.answer, q.answered_at "
                f"FROM {table} WHERE q.goal_id = %s{scope} ORDER BY q.id",
                tuple([goal_id, *fparams]),
            )
            rows = cur.fetchall()
        return [_dec_question_row(r) for r in rows]

    # ----- approvals (high-risk action consent queue) -----

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

        ``provenance`` is trusted caller-supplied metadata for operator UIs; it
        is not inferred from ``detail`` (which may carry untrusted text).
        ``approvals_required`` is the N-of-M quorum; ``requested_by`` the
        requester (so a multi-party approval can bar self-approval).
        ``undoable`` mirrors SQLite: only a requester that waits out the undo
        window before acting sets it."""
        from ..logging_config import current_goal_id
        from ..world_model import APPROVAL_UNDO_OPEN

        context_goal = current_goal_id()
        frag, fparams = _mutation_tenant_scope()
        goal_sql = "SELECT id, domain FROM goals WHERE id=%s"
        if frag:
            goal_sql += " AND " + frag
        goal_sql += " FOR SHARE"
        with self._tx() as cur:
            cur.execute(goal_sql, tuple([context_goal, *fparams]))
            goal = cur.fetchone()
            if context_goal is not None and goal is None:
                raise ValueError("approval goal is unavailable for the active tenant")
            cur.execute(
                "INSERT INTO approvals(action, risk, scope, detail, provenance, status, "
                "requested_at, tenant_id, approvals_required, requested_by, goal_id, department, "
                "undo_hold) VALUES(%s, %s, %s, %s, %s, 'pending', %s, %s, %s, %s, %s, %s, %s) "
                "RETURNING id",
                (_seal(action, "approvals.action"), risk, _seal(scope, "approvals.scope"), _seal(detail, "approvals.detail"), provenance,
                 time.time(), _active_tenant(), max(1, int(approvals_required)),
                 (requested_by or None), goal[0] if goal else None, goal[1] if goal else "",
                 APPROVAL_UNDO_OPEN if undoable else None),
            )
            row = cur.fetchone()
        from ..world_model import _notify_approval_created

        _notify_approval_created(self, int(row[0]), provenance)
        self._emit_approval_event("approval.created", int(row[0]), {"risk": risk, "action": action})
        return int(row[0])

    def _emit_approval_event(self, event: str, approval_id: int, payload: dict) -> None:
        """Webhook subscribers hear about approvals, as on SQLite; call it only
        after the transaction has committed. Never raises."""
        from ..world_model import WorldModel

        WorldModel._emit_approval_event(self, event, approval_id, payload)

    def get_approval(self, approval_id: int, *, strict_tenant: bool = False):
        if strict_tenant:
            tenant = _active_tenant()
            frag, params = ("tenant_id = %s", [tenant]) if tenant is not None else ("tenant_id IS NULL", [])
        else:
            frag, params = _tenant_scope()
        sql = (
            "SELECT id, action, risk, scope, detail, provenance, status, "
            "requested_at, decided_at, claimed_by, claimed_at, decided_by, "
            "approvals_required, requested_by, goal_id, department, undo_hold "
            "FROM approvals WHERE id = %s"
        )
        p: list = [approval_id]
        if frag:
            sql += " AND " + frag
            p += params
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            row = cur.fetchone()
        return _dec_approval_row(row) if row else None

    def pending_unattached_approval_ids(self, owner: str, *, limit: int) -> list[int]:
        tenant = _active_tenant()
        scope, params = ("tenant_id = %s", [tenant]) if tenant is not None else ("tenant_id IS NULL", [])
        with self._tx() as cur:
            cur.execute(
                "SELECT id FROM approvals WHERE status='pending' AND goal_id IS NULL "
                f"AND requested_by=%s AND {scope} ORDER BY id DESC LIMIT %s",
                tuple([owner, *params, max(1, int(limit))]),
            )
            rows = cur.fetchall()
        return [int(row[0]) for row in rows]

    def pending_goal_approval_ids(self, goal_ids: list[int], *, limit: int) -> list[int]:
        if not goal_ids:
            return []
        tenant = _active_tenant()
        scope, params = ("tenant_id = %s", [tenant]) if tenant is not None else ("tenant_id IS NULL", [])
        with self._tx() as cur:
            cur.execute(
                "SELECT id FROM approvals WHERE status='pending' AND goal_id = ANY(%s) "
                f"AND {scope} ORDER BY id DESC LIMIT %s",
                tuple([goal_ids, *params, max(1, int(limit))]),
            )
            rows = cur.fetchall()
        return [int(row[0]) for row in rows]

    def pending_approvals(self) -> list:
        frag, params = _tenant_scope()
        sql = (
            "SELECT id, action, risk, scope, detail, provenance, status, "
            "requested_at, decided_at, claimed_by, claimed_at, decided_by, "
            "approvals_required, requested_by, goal_id, department, undo_hold "
            "FROM approvals WHERE status = 'pending'"
        )
        if frag:
            sql += " AND " + frag
        sql += " ORDER BY id"
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [_dec_approval_row(r) for r in rows]

    def approval_audit_event_id(
        self,
        approval_id: int,
        status: str,
        decided_by: str,
    ) -> str:
        from ..world_model import _approval_audit_event_id

        with self._tx() as cur:
            undo_round = self._approval_undo_round(cur, approval_id)
        return _approval_audit_event_id(
            _active_tenant(),
            approval_id,
            status,
            (decided_by or "").strip(),
            undo_round,
        )

    def _approval_undo_round(self, cur, approval_id: int) -> int:
        """How many times this approval was undone (mirrors SQLite)."""
        from ..world_model import APPROVAL_UNDO_STATUS

        outbox_scope, outbox_params = _approval_outbox_scope()
        cur.execute(
            "SELECT COUNT(*) FROM approval_audit_outbox "
            f"WHERE approval_id = %s AND status = %s AND {outbox_scope}",
            tuple([int(approval_id), APPROVAL_UNDO_STATUS, *outbox_params]),
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0

    def settle_approval_decision(self, approval_id: int, *, decided_before: float):
        """The waiting task is about to act on this decision (mirrors SQLite; see there)."""
        from ..world_model import APPROVAL_UNDO_OPEN, APPROVAL_UNDO_SETTLED

        approval_scope, approval_params = _mutation_tenant_scope()
        sql = ("UPDATE approvals SET undo_hold = %s WHERE id = %s AND status <> 'pending' "
               "AND undo_hold = %s AND decided_at <= %s")
        values: list = [APPROVAL_UNDO_SETTLED, int(approval_id), APPROVAL_UNDO_OPEN, float(decided_before)]
        if approval_scope:
            sql += " AND " + approval_scope
            values += approval_params
        with self._tx() as cur:
            cur.execute(sql, tuple(values))
        return self.get_approval(int(approval_id))

    def undo_approval_decision(
        self,
        approval_id: int,
        *,
        undone_by: str,
        within_seconds: float,
    ) -> str:
        """Return a just-decided approval to pending (mirrors SQLite; see there)."""
        from ..world_model import (
            APPROVAL_UNDO_OPEN,
            APPROVAL_UNDO_STATUS,
            _approval_undo_marker_id,
            approval_undo_refusal,
        )

        tenant = _active_tenant()
        approval_scope, approval_params = _mutation_tenant_scope()
        outbox_scope, outbox_params = _approval_outbox_scope()
        sql = "SELECT status, decided_at, decided_by, undo_hold, action FROM approvals WHERE id = %s"
        values: list = [int(approval_id)]
        if approval_scope:
            sql += " AND " + approval_scope
            values += approval_params
        sql += " FOR UPDATE"
        with self._tx() as cur:
            cur.execute(sql, tuple(values))
            row = cur.fetchone()
            if row is None:
                return "not_found"
            if row[0] == "pending":
                return "not_decided"
            refusal = approval_undo_refusal(row[0], row[2], row[3])
            if refusal is not None:
                return refusal
            if row[1] is None or time.time() - float(row[1]) >= float(within_seconds):
                return "too_late"
            cur.execute(
                "UPDATE approvals SET status = 'pending', decided_at = NULL, "
                "decided_by = NULL WHERE id = %s AND status = %s AND undo_hold = %s",
                (int(approval_id), row[0], APPROVAL_UNDO_OPEN),
            )
            cur.execute(
                "DELETE FROM approval_signoffs WHERE approval_id = %s",
                (int(approval_id),),
            )
            cur.execute(
                "UPDATE approval_audit_outbox SET final_status = NULL "
                f"WHERE approval_id = %s AND status IN ('approved', 'denied') AND {outbox_scope}",
                tuple([int(approval_id), *outbox_params]),
            )
            undo_round = self._approval_undo_round(cur, approval_id) + 1
            now = time.time()
            cur.execute(
                "INSERT INTO approval_audit_outbox("
                "event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at, tenant_id) "
                "VALUES(%s, %s, %s, %s, NULL, %s, %s, %s)",
                (
                    _approval_undo_marker_id(tenant, approval_id, undo_round),
                    int(approval_id),
                    APPROVAL_UNDO_STATUS,
                    (undone_by or "").strip(),
                    now,
                    now,
                    tenant,
                ),
            )
        # approval.decided already went out; subscribers learn it was retracted.
        self._emit_approval_event("approval.undone", int(approval_id), {
            "previous_status": row[0], "undone_by": (undone_by or "").strip(),
            "action": _unseal(row[4], "approvals.action")})
        return "undone"

    def get_approval_audit_event(self, event_id: str):
        scope, params = _approval_outbox_scope()
        with self._tx() as cur:
            cur.execute(
                "SELECT event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at FROM approval_audit_outbox "
                f"WHERE event_id = %s AND {scope}",
                tuple([str(event_id), *params]),
            )
            row = cur.fetchone()
        return _dec_approval_audit_row(row) if row else None

    def pending_approval_audit_events(
        self,
        *,
        approval_id: int | None = None,
        limit: int = 100,
    ) -> list:
        scope, params = _approval_outbox_scope()
        sql = (
            "SELECT event_id, approval_id, status, decided_by, final_status, "
            "created_at, delivered_at FROM approval_audit_outbox "
            f"WHERE delivered_at IS NULL AND {scope}"
        )
        values: list = list(params)
        if approval_id is not None:
            sql += " AND approval_id = %s"
            values.append(int(approval_id))
        sql += " ORDER BY created_at, event_id LIMIT %s"
        values.append(max(1, min(int(limit), 1000)))
        with self._tx() as cur:
            cur.execute(sql, tuple(values))
            rows = cur.fetchall()
        return [_dec_approval_audit_row(row) for row in rows]

    def approval_has_pending_finalization(self, approval_id: int) -> bool:
        scope, params = _approval_outbox_scope()
        with self._tx() as cur:
            cur.execute(
                "SELECT 1 FROM approval_audit_outbox "
                "WHERE approval_id = %s AND final_status IS NOT NULL "
                f"AND delivered_at IS NULL AND {scope} LIMIT 1",
                tuple([int(approval_id), *params]),
            )
            row = cur.fetchone()
        return row is not None

    def _require_locked_approval_review(self, cur, approval_id: int, status: str,
                                        approver: str, event_id: str, review: dict, effect_guard=None) -> None:
        """Read reviewed card, quorum and content owner under the held row lock."""
        from ..approval_vote_review import require_locked_vote_review
        from ..world_model import _single_approver

        approval_scope, approval_params = _mutation_tenant_scope()
        outbox_scope, outbox_params = _approval_outbox_scope()
        sql = ("SELECT id, action, risk, scope, detail, provenance, status, requested_at, decided_at, claimed_by, claimed_at, decided_by, approvals_required, requested_by, goal_id, department, undo_hold FROM approvals WHERE id = %s")
        values = [int(approval_id)]
        if approval_scope:
            sql += " AND " + approval_scope
            values += approval_params
        cur.execute(sql, tuple(values))
        locked = cur.fetchone()
        exact = _dec_approval_row(locked) if locked is not None else None
        cur.execute("SELECT approver, decision FROM approval_signoffs WHERE approval_id = %s ORDER BY decided_at", (int(approval_id),))
        approvers = _single_approver(exact, [row[0] for row in cur.fetchall() if row[1] == "approved"]) if exact is not None else []
        cur.execute(f"SELECT COUNT(*) FROM approval_audit_outbox WHERE approval_id = %s AND delivered_at IS NULL AND {outbox_scope}", tuple([int(approval_id), *outbox_params]))
        audit_pending = int(cur.fetchone()[0])
        content_owner = (exact.requested_by or "") if exact is not None else None
        if exact is not None and exact.goal_id:
            owner_sql = "SELECT owner,domain FROM goals WHERE id = %s"
            owner_values = [exact.goal_id]
            if approval_scope:
                owner_sql += " AND " + approval_scope
                owner_values += approval_params
            cur.execute(owner_sql + " FOR SHARE", tuple(owner_values))
            source = cur.fetchone()
            content_owner = (source[0] or "") if source is not None else None
            source_guard = getattr(effect_guard, "approval_source", None)
            if source_guard is not None:
                source_guard(exact.goal_id, content_owner, source[1] if source is not None else None)
        require_locked_vote_review(exact, review, status=status, actor=approver,
                                   event_id=event_id, approvers=approvers, audit_pending=audit_pending,
                                   content_owner=content_owner)

    def decide_approval_audited(
        self,
        approval_id: int,
        status: str,
        *,
        decided_by: str,
        reviewed_card: dict | None = None,
        effect_guard=None,
    ):
        """Atomically accept a vote and queue its signed-audit delivery."""
        if status not in ("approved", "denied"):
            raise ValueError("status must be 'approved' or 'denied'")
        approver = (decided_by or "").strip()
        if not approver:
            return None

        from ..world_model import _approval_audit_event_id
        from ..world_records import ApprovalAuditEvent

        tenant = _active_tenant()
        approval_scope, approval_params = _mutation_tenant_scope()
        outbox_scope, outbox_params = _approval_outbox_scope()
        approval_sql = (
            "SELECT status, approvals_required, requested_by "
            "FROM approvals WHERE id = %s"
        )
        approval_values: list = [int(approval_id)]
        if approval_scope:
            approval_sql += " AND " + approval_scope
            approval_values += approval_params
        approval_sql += " FOR UPDATE"

        with self._tx() as cur:
            # Row lock serializes duplicate and competing votes across replicas.
            cur.execute(approval_sql, tuple(approval_values))
            approval = cur.fetchone()
            if effect_guard:
                effect_guard()
            undo_round = self._approval_undo_round(cur, approval_id)
            event_id = _approval_audit_event_id(
                tenant, approval_id, status, approver, undo_round,
            )

            if reviewed_card is not None:
                self._require_locked_approval_review(cur, approval_id, status, approver, event_id, reviewed_card, effect_guard)

            cur.execute(
                "SELECT event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at FROM approval_audit_outbox "
                f"WHERE event_id = %s AND {outbox_scope}",
                tuple([event_id, *outbox_params]),
            )
            prior = cur.fetchone()
            if prior is not None:
                prior_event = _dec_approval_audit_row(prior)
                if not prior_event.matches(approval_id, status, approver):
                    raise RuntimeError(
                        "approval audit outbox event identity is corrupt"
                    )
                return prior_event
            if approval is None or approval[0] != "pending":
                return None

            cur.execute(
                "SELECT 1 FROM approval_audit_outbox "
                "WHERE approval_id = %s AND final_status IS NOT NULL "
                f"AND delivered_at IS NULL AND {outbox_scope} LIMIT 1",
                tuple([int(approval_id), *outbox_params]),
            )
            if cur.fetchone() is not None:
                return None

            required = max(1, int(approval[1] or 1))
            requested_by = approval[2]
            if (
                required > 1
                and status == "approved"
                and requested_by
                and approver == requested_by
            ):
                from ..safety.dual_control import allow_self_approval

                if not allow_self_approval():
                    return None

            now = time.time()
            final_status = None
            if required <= 1:
                final_status = status
            else:
                # Backfill pending pre-v30 signoffs into the new outbox before
                # a later vote can reach quorum. This keeps upgraded databases
                # from signing only the final vote in an N-of-M decision.
                cur.execute(
                    "SELECT approver, decision, decided_at "
                    "FROM approval_signoffs WHERE approval_id = %s "
                    "ORDER BY decided_at, approver",
                    (int(approval_id),),
                )
                for legacy in cur.fetchall():
                    legacy_event_id = _approval_audit_event_id(
                        tenant, approval_id, legacy[1], legacy[0], undo_round,
                    )
                    cur.execute(
                        "INSERT INTO approval_audit_outbox("
                        "event_id, approval_id, status, decided_by, final_status, "
                        "created_at, delivered_at, tenant_id) "
                        "VALUES(%s, %s, %s, %s, NULL, %s, NULL, %s) "
                        "ON CONFLICT (event_id) DO NOTHING",
                        (
                            legacy_event_id,
                            int(approval_id),
                            legacy[1],
                            legacy[0],
                            float(legacy[2]),
                            tenant,
                        ),
                    )
                cur.execute(
                    "SELECT event_id, approval_id, status, decided_by, final_status, "
                    "created_at, delivered_at FROM approval_audit_outbox "
                    f"WHERE event_id = %s AND {outbox_scope}",
                    tuple([event_id, *outbox_params]),
                )
                prior = cur.fetchone()
                if prior is not None:
                    prior_event = _dec_approval_audit_row(prior)
                    if not prior_event.matches(approval_id, status, approver):
                        raise RuntimeError(
                            "approval audit outbox event identity is corrupt"
                        )
                    return prior_event

                cur.execute(
                    "SELECT decision FROM approval_signoffs "
                    "WHERE approval_id = %s AND approver = %s",
                    (int(approval_id), approver),
                )
                existing_signoff = cur.fetchone()
                if (
                    existing_signoff is not None
                    and existing_signoff[0] != status
                ):
                    return None
                cur.execute(
                    "INSERT INTO approval_signoffs(approval_id, approver, decision, "
                    "decided_at) VALUES(%s, %s, %s, %s) "
                    "ON CONFLICT (approval_id, approver) DO NOTHING",
                    (int(approval_id), approver, status, now),
                )
                if status == "denied":
                    final_status = "denied"
                else:
                    cur.execute(
                        "SELECT COUNT(*) FROM approval_signoffs "
                        "WHERE approval_id = %s AND decision = 'approved'",
                        (int(approval_id),),
                    )
                    if int(cur.fetchone()[0]) >= required:
                        final_status = "approved"

            cur.execute(
                "INSERT INTO approval_audit_outbox("
                "event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at, tenant_id) "
                "VALUES(%s, %s, %s, %s, %s, %s, NULL, %s)",
                (
                    event_id,
                    int(approval_id),
                    status,
                    approver,
                    final_status,
                    now,
                    tenant,
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
            if effect_guard:
                effect_guard()
            return result

    def mark_approval_audit_delivered(
        self,
        event_id: str,
        *,
        delivered_at: float | None = None,
        effect_guard=None,
    ) -> bool:
        """Acknowledge signed delivery and apply any now-safe final outcome."""
        outbox_scope, outbox_params = _approval_outbox_scope()
        approval_scope, approval_params = _mutation_tenant_scope()
        finalized: tuple[str, str] | None = None
        with self._tx() as cur:
            cur.execute(
                "SELECT event_id, approval_id, status, decided_by, final_status, "
                "created_at, delivered_at FROM approval_audit_outbox "
                f"WHERE event_id = %s AND {outbox_scope} FOR UPDATE",
                tuple([str(event_id), *outbox_params]),
            )
            event = cur.fetchone()
            if effect_guard is not None:
                effect_guard()
            if event is None:
                return False
            source_guard = getattr(effect_guard, "approval_source", None)
            if source_guard is not None:
                goal_scope, goal_params = _mutation_tenant_scope("g.tenant_id")
                cur.execute("SELECT g.id,g.owner,g.domain FROM approvals a JOIN goals g ON g.id=a.goal_id WHERE a.id=%s" + (" AND " + goal_scope if goal_scope else "") + " FOR SHARE OF g", tuple([event[1], *goal_params]))
                source = cur.fetchone()
                if source is None:
                    raise PermissionError("The original approval task is unavailable")
                source_guard(source[0], source[1] or "", source[2])
            if event[6] is None:
                cur.execute(
                    "UPDATE approval_audit_outbox SET delivered_at = %s "
                    f"WHERE event_id = %s AND delivered_at IS NULL AND {outbox_scope}",
                    tuple([
                        float(delivered_at)
                        if delivered_at is not None
                        else time.time(),
                        str(event_id),
                        *outbox_params,
                    ]),
                )

            approval_id = int(event[1])
            cur.execute(
                "SELECT 1 FROM approval_audit_outbox "
                f"WHERE approval_id = %s AND delivered_at IS NULL AND {outbox_scope} "
                "LIMIT 1",
                tuple([approval_id, *outbox_params]),
            )
            if cur.fetchone() is None:
                cur.execute(
                    "SELECT final_status, decided_by, created_at "
                    "FROM approval_audit_outbox "
                    f"WHERE approval_id = %s AND final_status IS NOT NULL "
                    f"AND {outbox_scope} "
                    "ORDER BY created_at DESC, event_id DESC LIMIT 1",
                    tuple([approval_id, *outbox_params]),
                )
                final = cur.fetchone()
                if final is not None:
                    sql = (
                        "UPDATE approvals SET status = %s, decided_at = %s, "
                        "decided_by = %s WHERE id = %s AND status = 'pending'"
                    )
                    values: list = [
                        final[0],
                        float(final[2]),
                        final[1],
                        approval_id,
                    ]
                    if approval_scope:
                        sql += " AND " + approval_scope
                        values += approval_params
                    cur.execute(sql, tuple(values))
                    if cur.rowcount > 0:
                        finalized = (final[0], final[1])
            if effect_guard is not None:
                effect_guard()
        # Only after the guard passed and the transaction committed (as on SQLite).
        if finalized is not None:
            self._emit_approval_event("approval.decided", approval_id,
                                      {"status": finalized[0], "decided_by": finalized[1] or ""})
        return True

    def decide_approval(self, approval_id: int, status: str,
                        decided_by: str | None = None) -> bool:
        """Record one approver's decision (N-of-M dual control; mirrors SQLite).

        Single-approver (``approvals_required <= 1``): flips the row atomically.
        N-of-M: records a distinct sign-off, denies on the first deny, bars the
        requester from self-approving (unless allowed), and flips to 'approved'
        only at quorum. Tenant-scoped like get_approval. Returns True when the
        vote was accepted, False on unknown/decided id, a barred self-approval,
        or a multi-party vote with no approver identity. Once the audited path
        has created an outbox row, this legacy immediate path refuses every
        later vote so callers cannot bypass signed delivery between quorum
        votes."""
        if status not in ("approved", "denied"):
            raise ValueError("status must be 'approved' or 'denied'")
        appr = self.get_approval(approval_id)   # already tenant-scoped
        if appr is None or appr.status != "pending":
            return False
        required = max(1, int(getattr(appr, "approvals_required", 1) or 1))
        # Tenant-scope the write so a tenant can't decide another's parked action
        # by enumerating ids it can't see.
        frag, params = _mutation_tenant_scope()
        if required <= 1:
            sql = ("UPDATE approvals SET status = %s, decided_at = %s, "
                   "decided_by = %s WHERE id = %s AND status = 'pending' "
                   "AND NOT EXISTS (SELECT 1 FROM approval_audit_outbox "
                   "WHERE approval_id = %s)")
            p: list = [status, time.time(), decided_by, approval_id]
            p.append(approval_id)
            if frag:
                sql += " AND " + frag
                p += params
            with self._tx() as cur:
                cur.execute(sql, tuple(p))
                decided = cur.rowcount > 0
            if decided:
                self._emit_approval_event("approval.decided", approval_id,
                                          {"status": status, "decided_by": decided_by or "",
                                           "action": appr.action})
            return decided

        approver = (decided_by or "").strip()
        if not approver:
            return False
        if (status == "approved" and appr.requested_by
                and approver == appr.requested_by):
            from ..safety.dual_control import allow_self_approval
            if not allow_self_approval():
                return False
        now = time.time()
        upd = ("UPDATE approvals SET status = %s, decided_at = %s, decided_by = %s "
               "WHERE id = %s AND status = 'pending'")
        up: list = [None, now, approver, approval_id]   # status filled below
        if frag:
            upd += " AND " + frag
        with self._tx() as cur:
            lock_sql = (
                "SELECT id FROM approvals "
                "WHERE id = %s AND status = 'pending'"
            )
            lock_params: list = [approval_id]
            if frag:
                lock_sql += " AND " + frag
                lock_params += params
            lock_sql += " FOR UPDATE"
            cur.execute(lock_sql, tuple(lock_params))
            if cur.fetchone() is None:
                return False
            cur.execute(
                "SELECT 1 FROM approval_audit_outbox "
                "WHERE approval_id = %s LIMIT 1",
                (approval_id,),
            )
            if cur.fetchone() is not None:
                return False
            cur.execute(
                "INSERT INTO approval_signoffs(approval_id, approver, decision, "
                "decided_at) VALUES(%s, %s, %s, %s) "
                "ON CONFLICT (approval_id, approver) DO UPDATE SET "
                "decision = EXCLUDED.decision, decided_at = EXCLUDED.decided_at",
                (approval_id, approver, status, now),
            )
            if status == "denied":
                up[0] = "denied"
                cur.execute(upd, tuple(up + (params if frag else [])))
                return True
            cur.execute(
                "SELECT COUNT(*) FROM approval_signoffs "
                "WHERE approval_id = %s AND decision = 'approved'",
                (approval_id,),
            )
            approved = int(cur.fetchone()[0])
            if approved >= required:
                up[0] = "approved"
                cur.execute(upd, tuple(up + (params if frag else [])))
            return True

    def approval_state(self, approval_id: int) -> dict | None:
        """Quorum progress for an approval (tenant-scoped), or None if unknown.
        Mirrors the SQLite backend's shape."""
        appr = self.get_approval(approval_id)
        if appr is None:
            return None
        with self._tx() as cur:
            cur.execute(
                "SELECT approver, decision FROM approval_signoffs "
                "WHERE approval_id = %s ORDER BY decided_at, approver", (approval_id,),
            )
            rows = cur.fetchall()
        from ..world_model import _approval_state_view, _single_approver

        approvers = _single_approver(appr, [r[0] for r in rows if r[1] == "approved"])
        scope, params = _approval_outbox_scope()
        with self._tx() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM approval_audit_outbox "
                f"WHERE approval_id = %s AND delivered_at IS NULL AND {scope}",
                tuple([approval_id, *params]),
            )
            audit_pending = int(cur.fetchone()[0])
        return _approval_state_view(appr, approvers, audit_pending)

    def approval_states(self, approvals) -> dict[int, dict]:
        """Batched :meth:`approval_state` for approvals the caller has already
        listed (tenant-scoped): two queries for the set, each value equal to
        ``approval_state(id)``."""
        from ..world_model import _approval_state_view, _single_approver

        listed = {int(a.id): a for a in approvals}
        if not listed:
            return {}
        ids = list(listed)
        signoffs: dict[int, list[str]] = {approval_id: [] for approval_id in ids}
        pending: dict[int, int] = dict.fromkeys(ids, 0)
        with self._tx() as cur:
            cur.execute(
                "SELECT approval_id, approver, decision FROM approval_signoffs "
                "WHERE approval_id = ANY(%s) ORDER BY decided_at, approver", (ids,),
            )
            for approval_id, approver, decision in cur.fetchall():
                if decision == "approved":
                    signoffs[int(approval_id)].append(approver)
        scope, params = _approval_outbox_scope()
        with self._tx() as cur:
            cur.execute(
                "SELECT approval_id, COUNT(*) FROM approval_audit_outbox "
                f"WHERE approval_id = ANY(%s) AND delivered_at IS NULL AND {scope} "
                "GROUP BY approval_id",
                tuple([ids, *params]),
            )
            for approval_id, count in cur.fetchall():
                pending[int(approval_id)] = int(count)
        return {
            approval_id: _approval_state_view(
                appr, _single_approver(appr, signoffs[approval_id]), pending[approval_id]
            )
            for approval_id, appr in listed.items()
        }

    def claim_approval(self, approval_id: int, principal: str) -> bool:
        """Atomically claim a pending approval (collaborative supervision).
        Mirrors SQLite: pending + unclaimed-or-mine; tenant-scoped."""
        principal = (principal or "").strip()
        if not principal:
            raise ValueError("principal is required to claim an approval")
        frag, params = _mutation_tenant_scope()
        sql = (
            "UPDATE approvals SET claimed_by = %s, claimed_at = %s "
            "WHERE id = %s AND status = 'pending' "
            "AND (claimed_by IS NULL OR claimed_by = %s)"
        )
        p: list = [principal, time.time(), approval_id, principal]
        if frag:
            sql += " AND " + frag
            p += params
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            affected = cur.rowcount
        return affected > 0

    def release_approval(self, approval_id: int, principal: str) -> bool:
        """Release a claim you hold (pending rows only); tenant-scoped."""
        principal = (principal or "").strip()
        if not principal:
            raise ValueError("principal is required to release an approval")
        frag, params = _mutation_tenant_scope()
        sql = (
            "UPDATE approvals SET claimed_by = NULL, claimed_at = NULL "
            "WHERE id = %s AND status = 'pending' AND claimed_by = %s"
        )
        p: list = [approval_id, principal]
        if frag:
            sql += " AND " + frag
            p += params
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            affected = cur.rowcount
        return affected > 0

    # ----- conversations / turns (multi-turn channel memory) -----

    def get_or_create_conversation(self, channel: str, user_id: str):
        """Idempotent per (channel, user_id); bumps last_seen each call so
        prune_conversations can retire idle ones. Mirrors SQLite."""
        from ..world_records import Conversation
        now = time.time()
        tenant = _active_tenant()
        frag, params = _tenant_scope()
        sel = (
            "SELECT id, channel, user_id, created_at, last_seen "
            "FROM conversations WHERE channel = %s AND user_id = %s"
        )
        sp: list = [channel, user_id]
        if frag:
            sel += " AND " + frag
            sp += params
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO conversations(channel, user_id, created_at, last_seen, tenant_id) "
                "VALUES(%s, %s, %s, %s, %s) "
                "ON CONFLICT ((COALESCE(tenant_id, '')), channel, user_id) "
                "DO UPDATE SET last_seen = EXCLUDED.last_seen",
                (channel, user_id, now, now, tenant),
            )
            cur.execute(sel, tuple(sp))
            row = cur.fetchone()
        return Conversation(*row)

    def append_turn(
        self, conversation_id: int, role: str, content: str,
        goal_id: int | None = None,
    ) -> int:
        if role not in ("user", "assistant"):
            raise ValueError(f"role must be 'user' or 'assistant', got {role!r}")
        # A turn inherits tenancy through its CONVERSATION (conversations carries
        # tenant_id); gate the insert on that conversation being in the active
        # tenant so a write against another tenant's conversation can't land.
        frag, fparams = _mutation_tenant_scope()
        with self._tx() as cur:
            if goal_id is not None:
                goal_scope, goal_params = _mutation_tenant_scope()
                cur.execute("SELECT id FROM goals WHERE id=%s AND " + goal_scope + " FOR SHARE",
                            tuple([int(goal_id), *goal_params]))
                if cur.fetchone() is None:
                    raise ValueError("unknown conversation or goal for the active tenant")
            sql = (
                "INSERT INTO turns(conversation_id, goal_id, role, content, ts) "
                "SELECT %s, %s, %s, %s, %s WHERE EXISTS "
                "(SELECT 1 FROM conversations WHERE id=%s AND " + frag + ")"
            )
            params = [conversation_id, goal_id, role, _seal(content, "turns.content"), time.time(),
                      conversation_id, *fparams]
            if goal_id is not None:
                goal_scope, goal_params = _mutation_tenant_scope("g.tenant_id")
                sql += " AND EXISTS (SELECT 1 FROM goals g WHERE g.id=%s AND " + goal_scope + ")"
                params.extend([int(goal_id), *goal_params])
            cur.execute(sql + " RETURNING id", tuple(params))
            row = cur.fetchone()
        if row is None:
            raise ValueError(
                "unknown conversation or goal for the active tenant"
            )
        return int(row[0])

    def recent_turns(self, conversation_id: int, limit: int = 20) -> list:
        """Most recent N turns in chronological (ascending) order, ready to feed
        into a chat-format prompt. Mirrors SQLite."""
        from ..world_records import Turn
        frag, fparams = _tenant_scope("c.tenant_id")
        table = "turns t"
        scope = ""
        if frag:
            table += " JOIN conversations c ON c.id = t.conversation_id"
            scope = " AND " + frag
        params: list = [conversation_id, *fparams, limit]
        with self._tx() as cur:
            cur.execute(
                "SELECT t.id, t.conversation_id, t.goal_id, t.role, t.content, t.ts "
                f"FROM {table} "
                f"WHERE t.conversation_id = %s{scope} ORDER BY t.id DESC LIMIT %s",
                tuple(params),
            )
            rows = cur.fetchall()
        # content (index 4) is sealed at rest.
        return list(reversed([Turn(r[0], r[1], r[2], r[3], _unseal(r[4], "turns.content"), r[5])
                              for r in rows]))

    def list_conversations(self, channel: str | None = None) -> list:
        from ..world_records import Conversation
        frag, params = _tenant_scope()
        sql = "SELECT id, channel, user_id, created_at, last_seen FROM conversations"
        conds: list[str] = []
        p: list = []
        if channel:
            conds.append("channel = %s")
            p.append(channel)
        if frag:
            conds.append(frag)
            p += params
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY last_seen DESC"
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            rows = cur.fetchall()
        return [Conversation(*r) for r in rows]

    def prune_conversations(self, idle_for_seconds: float = 90 * 24 * 3600) -> int:
        """Delete conversations idle for N seconds and their turns. Turns first
        (no ON DELETE CASCADE). Returns conversations removed. Mirrors SQLite."""
        cutoff = time.time() - idle_for_seconds
        tenant = _required_retention_tenant("conversation retention")
        scope = " AND tenant_id = %s"
        with self._tx() as cur:
            cur.execute(
                "DELETE FROM turns WHERE conversation_id IN "
                f"(SELECT id FROM conversations WHERE last_seen < %s{scope})",
                (cutoff, tenant),
            )
            cur.execute(
                f"DELETE FROM conversations WHERE last_seen < %s{scope}",
                (cutoff, tenant),
            )
            return cur.rowcount

    @staticmethod
    def _erasure_ids(values) -> list[int]:
        ids = sorted(set(values))
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            for value in ids
        ):
            raise ValueError("erasure IDs must be positive integers")
        return ids

    def _conversation_erasure_plan_cursor(
        self,
        cur,
        conversation_ids: list[int],
    ) -> dict:
        cfrag, cfparams = _erasure_tenant_scope()
        csql = (
            "SELECT id, channel, user_id FROM conversations "
            "WHERE id = ANY(%s)"
        )
        if cfrag:
            csql += " AND " + cfrag
        cur.execute(csql, tuple([conversation_ids, *cfparams]))
        owned = cur.fetchall()
        conv_ids = sorted(int(row[0]) for row in owned)
        subjects = [(str(row[1]), str(row[2])) for row in owned]
        if not conv_ids:
            return {
                "conversation_ids": [],
                "goal_ids": [],
                "episode_ids": [],
                "attachment_paths": [],
                "subjects": [],
            }

        gfrag, gfparams = _erasure_tenant_scope("g.tenant_id")
        root_sql = (
            "SELECT DISTINCT t.goal_id FROM turns t "
            "JOIN goals g ON g.id = t.goal_id "
            "WHERE t.conversation_id = ANY(%s) AND t.goal_id IS NOT NULL"
        )
        root_params: list = [conv_ids]
        if gfrag:
            root_sql += " AND " + gfrag
            root_params += gfparams
        cur.execute(root_sql, tuple(root_params))
        root_goal_ids = [int(row[0]) for row in cur.fetchall()]
        goal_ids: list[int] = []
        if root_goal_ids:
            base_scope = f" AND {gfrag}" if gfrag else ""
            child_scope = f" WHERE {gfrag}" if gfrag else ""
            recursive_sql = (
                "WITH RECURSIVE goal_tree(id) AS ("
                " SELECT g.id FROM goals g WHERE g.id = ANY(%s)"
                f"{base_scope}"
                " UNION"
                " SELECT g.id FROM goals g"
                " JOIN goal_tree gt ON g.parent_id = gt.id"
                f"{child_scope}"
                ") SELECT id FROM goal_tree ORDER BY id"
            )
            recursive_params: list = [root_goal_ids]
            if gfrag:
                recursive_params += gfparams
                recursive_params += gfparams
            cur.execute(recursive_sql, tuple(recursive_params))
            goal_ids = [int(row[0]) for row in cur.fetchall()]

        attachment_paths: list[str] = []
        episode_ids: list[int] = []
        if goal_ids:
            cur.execute(
                "SELECT id FROM episodes "
                "WHERE goal_id = ANY(%s) ORDER BY id",
                (goal_ids,),
            )
            episode_ids = [int(row[0]) for row in cur.fetchall()]
            cur.execute(
                "SELECT path FROM attachments "
                "WHERE goal_id = ANY(%s) ORDER BY id",
                (goal_ids,),
            )
            attachment_paths = [str(row[0]) for row in cur.fetchall()]
        return {
            "conversation_ids": conv_ids,
            "goal_ids": goal_ids,
            "episode_ids": episode_ids,
            "attachment_paths": attachment_paths,
            "subjects": subjects,
        }

    def plan_conversation_erasure(self, conversation_ids: list[int]) -> dict:
        """Return the tenant-owned conversation + descendant-goal closure."""
        requested = self._erasure_ids(conversation_ids)
        if not requested:
            return {
                "conversation_ids": [],
                "goal_ids": [],
                "episode_ids": [],
                "attachment_paths": [],
            }
        with self._tx() as cur:
            plan = self._conversation_erasure_plan_cursor(cur, requested)
        return {
            key: plan[key]
            for key in (
                "conversation_ids",
                "goal_ids",
                "episode_ids",
                "attachment_paths",
            )
        }

    @staticmethod
    def _receipt_tenant(tenant_id: str) -> str:
        active = _active_tenant() or "shared"
        if tenant_id != active:
            raise ValueError("erasure receipt belongs to another tenant")
        return active

    def store_erasure_receipt(
        self,
        receipt_id: str,
        manifest: str,
        *,
        tenant_id: str,
        created_at: float,
        retained_until: float,
    ) -> None:
        tenant = self._receipt_tenant(tenant_id)
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO erasure_receipts("
                "receipt_id, tenant_id, manifest, created_at, retained_until"
                ") VALUES(%s, %s, %s, %s, %s)",
                (
                    receipt_id,
                    tenant,
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
        tenant = self._receipt_tenant(tenant_id)
        with self._tx() as cur:
            cur.execute(
                "SELECT manifest FROM erasure_receipts "
                "WHERE tenant_id = %s AND receipt_id = %s",
                (tenant, receipt_id),
            )
            row = cur.fetchone()
        return str(row[0]) if row is not None else None

    def retire_erasure_receipts(
        self,
        cutoff: float,
        *,
        tenant_id: str,
    ) -> int:
        tenant = self._receipt_tenant(tenant_id)
        with self._tx() as cur:
            cur.execute(
                "DELETE FROM erasure_receipts "
                "WHERE tenant_id = %s AND retained_until <= %s",
                (tenant, float(cutoff)),
            )
            return int(cur.rowcount)

    def count_erasure_receipt_store(
        self,
        store: str,
        conversation_ids: list[int],
        goal_ids: list[int],
        episode_ids: list[int] | None = None,
    ) -> int:
        """Count one exact receipt store, preserving per-store failures."""
        from ..erasure_receipts import RECEIPT_STORES

        if store not in RECEIPT_STORES:
            raise ValueError(f"unsupported erasure receipt store {store!r}")
        conversations = self._erasure_ids(conversation_ids)
        goals = self._erasure_ids(goal_ids)
        episodes = self._erasure_ids(episode_ids or [])
        with self._tx() as cur:
            if episode_ids is None and goals:
                efrag, efparams = _erasure_tenant_scope("g.tenant_id")
                episode_sql = (
                    "SELECT e.id FROM episodes e "
                    "JOIN goals g ON g.id = e.goal_id "
                    "WHERE e.goal_id = ANY(%s)"
                )
                episode_params: list = [goals]
                if efrag:
                    episode_sql += " AND " + efrag
                    episode_params += efparams
                cur.execute(episode_sql, tuple(episode_params))
                episodes = sorted(int(row[0]) for row in cur.fetchall())
            if store == "conversations":
                if not conversations:
                    return 0
                cfrag, cfparams = _erasure_tenant_scope()
                sql = "SELECT COUNT(*) FROM conversations WHERE id = ANY(%s)"
                params: list = [conversations]
                if cfrag:
                    sql += " AND " + cfrag
                    params += cfparams
                cur.execute(sql, tuple(params))
                return int(cur.fetchone()[0])
            if store == "turns":
                if not conversations and not goals:
                    return 0
                clauses = []
                params = []
                if conversations:
                    clauses.append("conversation_id = ANY(%s)")
                    params.append(conversations)
                if goals:
                    clauses.append("goal_id = ANY(%s)")
                    params.append(goals)
                cur.execute(
                    "SELECT COUNT(*) FROM turns WHERE " + " OR ".join(clauses),
                    tuple(params),
                )
                return int(cur.fetchone()[0])
            if not goals:
                return 0
            if store == "goals":
                gfrag, gfparams = _erasure_tenant_scope()
                sql = "SELECT COUNT(*) FROM goals WHERE id = ANY(%s)"
                params = [goals]
                if gfrag:
                    sql += " AND " + gfrag
                    params += gfparams
                cur.execute(sql, tuple(params))
                return int(cur.fetchone()[0])
            if store == "episodes":
                if not episodes:
                    return 0
                tfrag, tfparams = _erasure_tenant_scope("g.tenant_id")
                sql = (
                    "SELECT COUNT(*) FROM episodes e "
                    "JOIN goals g ON g.id = e.goal_id "
                    "WHERE e.id = ANY(%s)"
                )
                params = [episodes]
                if tfrag:
                    sql += " AND " + tfrag
                    params += tfparams
                cur.execute(sql, tuple(params))
                return int(cur.fetchone()[0])
            if store in ("episode_facts", "episode_fact_history"):
                if not episodes:
                    return 0
                table, field = {
                    "episode_facts": ("facts", "source_episode_id"),
                    "episode_fact_history": (
                        "fact_history",
                        "source_episode_id",
                    ),
                }[store]
                tfrag, tfparams = _erasure_tenant_scope()
                sql = f"SELECT COUNT(*) FROM {table} WHERE {field} = ANY(%s)"
                params = [episodes]
                if tfrag:
                    sql += " AND " + tfrag
                    params += tfparams
                cur.execute(sql, tuple(params))
                return int(cur.fetchone()[0])
            cur.execute(
                f"SELECT COUNT(*) FROM {store} WHERE goal_id = ANY(%s)",
                (goals,),
            )
            return int(cur.fetchone()[0])

    def count_erasure_receipt_residuals(
        self,
        conversation_ids: list[int],
        goal_ids: list[int],
        episode_ids: list[int] | None = None,
    ) -> dict[str, int]:
        """Count exact receipt IDs across every covered Postgres table."""
        from ..erasure_receipts import RECEIPT_STORES

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
        """Erase conversations and goal-scoped rows for GDPR deletion.

        This is the Postgres equivalent of the CLI's SQLite cascade: gather all
        goals referenced by the selected conversations' turns, expand through
        subgoals, collect attachment paths for post-commit unlinking, then
        delete the database rows in one transaction using psycopg/Postgres SQL.
        Returns ``(goal_ids, attachment_paths, removed_turns)``.
        """
        if not conversation_ids:
            return set(), [], 0

        requested = self._erasure_ids(conversation_ids)
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
        from ..erasure_receipts import ErasurePlanChanged

        with self._tx() as cur:
            # Erasure is rare and correctness-sensitive. Block concurrent
            # inserts into every participating table while the durable plan is
            # re-read, compared, and deleted; otherwise a child could appear
            # after receipt issuance but before its table's DELETE.
            cur.execute(
                "LOCK TABLE conversations, turns, goals, episodes, artifacts, "
                "attachments, goal_events, goal_origins, goal_mutation_receipts, messages, "
                "processed_messages, questions, share_links, signoffs, "
                "fact_history, facts IN SHARE ROW EXCLUSIVE MODE"
            )
            plan = self._conversation_erasure_plan_cursor(cur, requested)
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
            if not conv_ids:
                return set(), [], 0
            gids = plan["goal_ids"]
            subjects = plan["subjects"]
            if gids:
                cur.execute(
                    "DELETE FROM turns WHERE conversation_id = ANY(%s) "
                    "OR goal_id = ANY(%s)",
                    (conv_ids, gids),
                )
            else:
                cur.execute(
                    "DELETE FROM turns WHERE conversation_id = ANY(%s)",
                    (conv_ids,),
                )
            removed_turns = cur.rowcount

            if gids:
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
                    cur.execute(
                        f"DELETE FROM {table} WHERE goal_id = ANY(%s)",
                        (gids,),
                    )
                # Source-linked live and historical facts can retain output
                # derived from the subject's episodes. IDs are globally unique,
                # and the active tenant predicate prevents cross-tenant prefix
                # cleanup below.
                cur.execute(
                    "DELETE FROM fact_history WHERE source_episode_id IN "
                    "(SELECT id FROM episodes WHERE goal_id = ANY(%s))",
                    (gids,),
                )
                cur.execute(
                    "DELETE FROM facts WHERE source_episode_id IN "
                    "(SELECT id FROM episodes WHERE goal_id = ANY(%s))",
                    (gids,),
                )
                cur.execute(
                    "DELETE FROM episodes WHERE goal_id = ANY(%s)",
                    (gids,),
                )
                # Postgres self-referential FKs are checked per statement by
                # default, unlike the SQLite path that defers FK checks for the
                # transaction. Break edges inside the soon-to-be-deleted tree so
                # a single goal DELETE cannot fail on parent_id references.
                gfrag, gfparams = _erasure_tenant_scope("tenant_id")
                edge_sql = (
                    "UPDATE goals SET parent_id = NULL "
                    "WHERE parent_id = ANY(%s)"
                )
                edge_params: list = [gids]
                if gfrag:
                    edge_sql += " AND " + gfrag
                    edge_params += gfparams
                cur.execute(edge_sql, tuple(edge_params))
                cur.execute(
                    "UPDATE event_goal_admissions SET sealed_contract=NULL, "
                    "delivery_state='federation_retired' WHERE admission_key LIKE 'federation:%%' "
                    "AND goal_id = ANY(%s)", (gids,),
                )
                cur.execute("DELETE FROM goals WHERE id = ANY(%s)", (gids,))

            # Scrub the subject's explicitly user-scoped facts. Facts are global
            # UNIQUE(key) memory with no per-episode subject attribution, so the
            # only safe subject-scoped delete is by the deliberate
            # ``user:<token>:`` key prefix -- mirroring delete_facts_matching and
            # the SQLite erase path. The previous source_episode_id-based delete
            # both missed these prefixed keys AND deleted unrelated global facts
            # that merely happened to reference a deleted episode.
            # Scope the fact scrub to the active tenant. Facts are UNIQUE per
            # (tenant, key): another tenant can hold the same user:<token>: key,
            # so a DELETE keyed only on the prefix would erase that tenant's row
            # too -- the same cross-tenant GDPR over-deletion delete_facts_matching
            # guards against. The conv/goal rows above are already tenant-isolated
            # by id; this LIKE-by-prefix path is the one that needs the predicate.
            frag, fparams = _erasure_tenant_scope()
            for channel, user_id in subjects:
                token = f"{quote(channel, safe='')}:{quote(user_id, safe='')}"
                like = self._like_escape(f"user:{token}:") + "%"
                sql = "DELETE FROM facts WHERE key LIKE %s ESCAPE '\\'"
                params = [like]
                if frag:
                    sql += " AND " + frag
                    params += fparams
                cur.execute(sql, tuple(params))
                history_sql = (
                    "DELETE FROM fact_history "
                    "WHERE key LIKE %s ESCAPE '\\'"
                )
                history_params = [like]
                if frag:
                    history_sql += " AND " + frag
                    history_params += fparams
                cur.execute(history_sql, tuple(history_params))

            cur.execute("DELETE FROM conversations WHERE id = ANY(%s)", (conv_ids,))

        return set(gids), list(plan["attachment_paths"]), removed_turns

    # ----- messages (goal-scoped log) -----

    def append_message(self, goal_id: int, role: str, content: str) -> None:
        # v49 retires only the unused GIN message-search index. This log still
        # stores complete content through the same authenticated at-rest codec.
        #
        # Gate on the parent goal being in the active tenant (see start_episode);
        # a cross-tenant write silently no-ops, like set_goal_status.
        frag, fparams = _mutation_tenant_scope()
        with self._tx() as cur:
            if frag:
                cur.execute(
                    "INSERT INTO messages(goal_id, role, content, ts) "
                    "SELECT %s, %s, %s, %s WHERE EXISTS "
                    "(SELECT 1 FROM goals WHERE id=%s AND " + frag + ")",
                    (goal_id, role, _seal(content, "messages.content"), time.time(), goal_id, *fparams),
                )
            else:
                cur.execute(
                    "INSERT INTO messages(goal_id, role, content, ts) "
                    "VALUES(%s, %s, %s, %s)",
                    (goal_id, role, _seal(content, "messages.content"), time.time()),
                )

    # ----- attachments -----

    def add_attachment(
        self, goal_id: int, filename: str, mime: str, size_bytes: int,
        sha256: str, path: str,
    ) -> int:
        from ..attachment_submissions import AttachmentAdmission, SubmissionStore

        return SubmissionStore(self).admit(
            goal_id, [AttachmentAdmission(filename, mime, size_bytes, sha256, path)],
        )[0]

    def list_attachments(self, goal_id: int) -> list:
        from ..world_records import Attachment
        frag, fparams = _tenant_scope("g.tenant_id")
        table = "attachments a"
        if frag:
            table += " JOIN goals g ON g.id = a.goal_id"
        sql = (
            "SELECT a.id, a.goal_id, a.filename, a.mime, a.size_bytes, a.sha256, "
            f"a.path, a.created_at FROM {table} WHERE a.goal_id = %s"
        )
        params: list = [goal_id]
        if frag:
            sql += " AND " + frag
            params += fparams
        sql += " ORDER BY a.id"
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [Attachment(*r) for r in rows]

    # ----- channel dedup (inbound-message idempotency) -----

    def mark_message_processed(
        self, channel: str, external_id: str, goal_id: int | None = None,
    ) -> bool:
        """Record an inbound message as processed; idempotent. Returns True on
        first-write (caller should run the goal), False on duplicate (caller
        returns 200 without re-running). Mirrors SQLite — protects against
        Twilio/iMessage webhook retries producing N goals + N spends."""
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO processed_messages(channel, external_id, goal_id, seen_at, tenant_id) "
                "VALUES(%s, %s, %s, %s, %s) "
                "ON CONFLICT ((COALESCE(tenant_id, '')), channel, external_id) DO NOTHING",
                (channel, external_id, goal_id, time.time(), _active_tenant()),
            )
            # rowcount is 1 on insert, 0 when the conflict skipped it.
            return cur.rowcount == 1

    def is_processed_message(self, channel: str, external_id: str) -> bool:
        frag, params = _tenant_scope()
        sql = "SELECT 1 FROM processed_messages WHERE channel = %s AND external_id = %s"
        p: list = [channel, external_id]
        if frag:
            sql += " AND " + frag
            p += params
        sql += " LIMIT 1"
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            return cur.fetchone() is not None

    def lookup_processed_message(self, channel: str, external_id: str) -> int | None:
        """goal_id for an already-processed message, or None if unseen.
        Distinguishes 'no row' (None) from 'row exists but goal_id null' (0),
        mirroring SQLite."""
        frag, params = _tenant_scope()
        sql = "SELECT goal_id FROM processed_messages WHERE channel = %s AND external_id = %s"
        p: list = [channel, external_id]
        if frag:
            sql += " AND " + frag
            p += params
        with self._tx() as cur:
            cur.execute(sql, tuple(p))
            row = cur.fetchone()
        if row is None:
            return None
        return row[0] if row[0] is not None else 0

    # ----- cluster-wide killswitch (v22) -----
    # Untenanted single-row global emergency stop; on shared Postgres every
    # replica's killswitch.check() consults this so a halt stops the whole fleet.
    def arm_halt(self, reason: str = "", source: str = "manual",
                 armed_by: str = "") -> str:
        generation = secrets.token_urlsafe(24)
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO halt(scope, reason, source, armed_by, armed_at, generation) "
                "VALUES('', %s, %s, %s, %s, %s) "
                "ON CONFLICT(scope) DO UPDATE SET reason=EXCLUDED.reason, "
                "source=EXCLUDED.source, armed_by=EXCLUDED.armed_by, "
                "armed_at=EXCLUDED.armed_at, generation=EXCLUDED.generation",
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
        """Bind a durable local clear to the exact locked shared generation."""
        if not isinstance(expected_generation, str):
            raise TypeError("expected_generation must be a string")
        with self._tx() as cur:
            cur.execute(
                "SELECT generation FROM halt WHERE scope = '' FOR UPDATE"
            )
            row = cur.fetchone()
            if row is None or (row[0] or "") != expected_generation:
                return False
            if durable_clear is not None:
                durable_clear()
            cur.execute(
                "DELETE FROM halt WHERE scope = '' AND generation = %s",
                (expected_generation,),
            )
            deleted = cur.rowcount
        return bool(deleted and deleted > 0)

    def active_halt(self) -> dict | None:
        with self._tx() as cur:
            cur.execute(
                "SELECT reason, source, armed_by, armed_at, generation "
                "FROM halt WHERE scope = ''")
            row = cur.fetchone()
        if row is None:
            return None
        return {"reason": row[0] or "", "source": row[1] or "",
                "armed_by": row[2] or "", "armed_at": row[3],
                "generation": row[4] or ""}

    # ----- cluster-wide provider spend ledger (v23) -----
    def add_provider_spend(self, period_key: str, provider: str,
                           amount: float) -> float:
        """Atomically add ``amount`` and return the new running total. The single
        authoritative spend total on shared Postgres so N replicas can't each
        spend up to the provider cap (ON CONFLICT increment is row-atomic)."""
        amt = max(0.0, float(amount or 0.0))
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO provider_spend(period_key, provider, dollars) "
                "VALUES(%s, %s, %s) ON CONFLICT(period_key, provider) "
                "DO UPDATE SET dollars = provider_spend.dollars + EXCLUDED.dollars "
                "RETURNING dollars",
                (period_key, provider, amt),
            )
            row = cur.fetchone()
        return float(row[0]) if row else amt

    def get_provider_spend(self, period_key: str, provider: str) -> float:
        with self._tx() as cur:
            cur.execute(
                "SELECT dollars FROM provider_spend "
                "WHERE period_key = %s AND provider = %s",
                (period_key, provider),
            )
            row = cur.fetchone()
        return float(row[0]) if row else 0.0

    def mutate_provider_cap(self, period_key: str, provider: str, operation):
        """Lock the provider total before admission, including first-row races."""
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO provider_spend(period_key, provider, dollars) VALUES(%s, %s, 0) "
                "ON CONFLICT(period_key, provider) DO NOTHING", (period_key, provider),
            )
            cur.execute(
                "SELECT dollars FROM provider_spend WHERE period_key = %s AND provider = %s FOR UPDATE",
                (period_key, provider),
            )
            total = float(cur.fetchone()[0])
            cur.execute(
                "SELECT receipts_json FROM provider_cap_receipts WHERE period_key = %s AND provider = %s",
                (period_key, provider),
            )
            state = cur.fetchone()
            total, receipts, result = operation(total, json.loads(state[0]) if state else {})
            cur.execute(
                "UPDATE provider_spend SET dollars = %s WHERE period_key = %s AND provider = %s",
                (total, period_key, provider),
            )
            cur.execute(
                "INSERT INTO provider_cap_receipts(period_key, provider, receipts_json) VALUES(%s, %s, %s) "
                "ON CONFLICT(period_key, provider) DO UPDATE SET receipts_json = EXCLUDED.receipts_json",
                (period_key, provider, json.dumps(receipts, allow_nan=False)),
            )
            return result

    def read_provider_cap(self, period_key: str, provider: str):
        with self._tx() as cur:
            cur.execute(
                "SELECT (SELECT dollars FROM provider_spend WHERE period_key = %s AND provider = %s), "
                "(SELECT receipts_json FROM provider_cap_receipts WHERE period_key = %s AND provider = %s)",
                (period_key, provider, period_key, provider),
            )
            row = cur.fetchone()
        if row[0] is None and row[1] is not None:
            raise RuntimeError("Provider accounting total is missing")
        return (float(row[0] or 0), json.loads(row[1]) if row[1] is not None else {})

    @staticmethod
    def _provider_cap_period_sql(period_kind: str) -> str:
        if period_kind == "day":
            return "to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM-DD')"
        if period_kind == "month":
            return "to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM')"
        raise ValueError("provider cap period kind is invalid")

    def provider_cap_period(self, period_kind: str) -> str:
        """Return the current UTC period from the shared database clock."""
        with self._tx() as cur:
            cur.execute(f"SELECT {self._provider_cap_period_sql(period_kind)}")
            row = cur.fetchone()
        if row is None or not isinstance(row[0], str):
            raise RuntimeError("Provider accounting clock is unavailable")
        return row[0]

    def mutate_current_provider_cap(self, period_kind: str, provider: str, operation):
        """Mutate the current provider bucket using one database-clock transaction."""
        period_sql = self._provider_cap_period_sql(period_kind)
        with self._tx() as cur:
            cur.execute(f"SELECT {period_sql}")
            period = cur.fetchone()[0]
            cur.execute(
                "INSERT INTO provider_spend(period_key, provider, dollars) VALUES(%s, %s, 0) "
                "ON CONFLICT(period_key, provider) DO NOTHING", (period, provider),
            )
            cur.execute(
                "SELECT dollars FROM provider_spend WHERE period_key = %s AND provider = %s FOR UPDATE",
                (period, provider),
            )
            total = float(cur.fetchone()[0])
            cur.execute(
                "SELECT receipts_json FROM provider_cap_receipts WHERE period_key = %s AND provider = %s",
                (period, provider),
            )
            state = cur.fetchone()
            total, receipts, result = operation(
                period, total, json.loads(state[0]) if state else {},
            )
            cur.execute(
                "UPDATE provider_spend SET dollars = %s WHERE period_key = %s AND provider = %s",
                (total, period, provider),
            )
            cur.execute(
                "INSERT INTO provider_cap_receipts(period_key, provider, receipts_json) VALUES(%s, %s, %s) "
                "ON CONFLICT(period_key, provider) DO UPDATE SET receipts_json = EXCLUDED.receipts_json",
                (period, provider, json.dumps(receipts, allow_nan=False)),
            )
            return period, result

    @staticmethod
    def _backfill_provider_operation_attempts(cur) -> None:
        """Index legacy JSON receipts once under a transactional winner row."""
        cur.execute(
            "INSERT INTO provider_operation_attempt_backfill(singleton, completed) "
            "VALUES(1, TRUE) ON CONFLICT (singleton) DO NOTHING RETURNING singleton"
        )
        if cur.fetchone() is None:
            # ON CONFLICT waits for the winning transaction. Its marker and
            # backfill commit together, so no partial state is observable here.
            return
        cur.execute(
            "INSERT INTO provider_operation_attempts("
            "scope_sha256, operation_id, attempt_no, category, parent_category, "
            "service, provider, period_key, request_id) "
            "SELECT COALESCE(j.receipt->>'operation_scope_sha256', "
            "j.receipt->>'work_item_sha256', "
            "'c544f4564db872e0ffb51fa1bb81b3d7089460a7a9a79ad21cd3952e77f0efec'), "  # pragma: allowlist secret
            "j.receipt->'operation'->>'operation_id', "
            "(j.receipt->'operation'->>'attempt_no')::BIGINT, "
            "j.receipt->'operation'->>'category', "
            "j.receipt->'operation'->>'parent_category', "
            "j.receipt->'operation'->>'service', "
            "p.provider, p.period_key, j.request_id "
            "FROM provider_cap_receipts AS p "
            "CROSS JOIN LATERAL jsonb_each(p.receipts_json::jsonb) "
            "AS j(request_id, receipt) "
            "WHERE jsonb_typeof(j.receipt->'operation') = 'object' "
            "AND NOT EXISTS (SELECT 1 FROM provider_operation_attempts AS a "
            "WHERE a.provider = p.provider AND a.period_key = p.period_key "
            "AND a.request_id = j.request_id)"
        )

    def reserve_current_provider_cap(
        self,
        period_kind: str,
        provider: str,
        operation,
        attempt: dict[str, object],
    ):
        """Claim a global operation attempt in the reservation transaction."""
        period_sql = self._provider_cap_period_sql(period_kind)
        with self._tx() as cur:
            cur.execute(f"SELECT {period_sql}")
            period = cur.fetchone()[0]
            self._backfill_provider_operation_attempts(cur)
            cur.execute(
                "INSERT INTO provider_operation_attempts("
                "scope_sha256, operation_id, attempt_no, category, parent_category, "
                "service, provider, period_key, request_id) "
                "VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (scope_sha256, operation_id, attempt_no) DO NOTHING "
                "RETURNING request_id",
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
            admitted = cur.fetchone()
            if admitted is None:
                cur.execute(
                    "SELECT category, parent_category, service, provider, period_key, request_id "
                    "FROM provider_operation_attempts "
                    "WHERE scope_sha256 = %s AND operation_id = %s AND attempt_no = %s",
                    (
                        attempt["scope_sha256"],
                        attempt["operation_id"],
                        attempt["attempt_no"],
                    ),
                )
                existing = cur.fetchone()
                if existing is None:
                    raise RuntimeError("provider operation attempt claim disappeared")
                return period, False, {
                    "category": existing[0],
                    "parent_category": existing[1],
                    "service": existing[2],
                    "provider": existing[3],
                    "period": existing[4],
                    "request_id": existing[5],
                }
            cur.execute(
                "INSERT INTO provider_spend(period_key, provider, dollars) VALUES(%s, %s, 0) "
                "ON CONFLICT(period_key, provider) DO NOTHING",
                (period, provider),
            )
            cur.execute(
                "SELECT dollars FROM provider_spend WHERE period_key = %s AND provider = %s FOR UPDATE",
                (period, provider),
            )
            total = float(cur.fetchone()[0])
            cur.execute(
                "SELECT receipts_json FROM provider_cap_receipts WHERE period_key = %s AND provider = %s",
                (period, provider),
            )
            state = cur.fetchone()
            total, receipts, result = operation(
                period,
                total,
                json.loads(state[0]) if state else {},
            )
            cur.execute(
                "UPDATE provider_spend SET dollars = %s WHERE period_key = %s AND provider = %s",
                (total, period, provider),
            )
            cur.execute(
                "INSERT INTO provider_cap_receipts(period_key, provider, receipts_json) VALUES(%s, %s, %s) "
                "ON CONFLICT(period_key, provider) DO UPDATE SET receipts_json = EXCLUDED.receipts_json",
                (period, provider, json.dumps(receipts, allow_nan=False)),
            )
            return period, True, result

    def read_current_provider_cap(self, period_kind: str, provider: str):
        """Read the database-clock period and its bucket in one statement."""
        period_sql = self._provider_cap_period_sql(period_kind)
        with self._tx() as cur:
            cur.execute(
                f"SELECT {period_sql}, "
                f"(SELECT dollars FROM provider_spend WHERE period_key = {period_sql} AND provider = %s), "
                f"(SELECT receipts_json FROM provider_cap_receipts WHERE period_key = {period_sql} AND provider = %s)",
                (provider, provider),
            )
            row = cur.fetchone()
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
            "WHERE EXISTS (SELECT 1 FROM jsonb_each(r.receipts_json::jsonb) "
            "AS entry(request_id, receipt) "
            "WHERE entry.receipt ->> 'work_item_sha256' = %s) "
            "ORDER BY r.period_key, r.provider LIMIT %s"
        )
        with self._tx() as cur:
            cur.execute(sql, (work_item_sha256, limit))
            return [tuple(row) for row in cur.fetchall()]

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
            "SELECT p.period_key, p.provider, entry.request_id "
            "FROM provider_cap_receipts AS p "
            "CROSS JOIN LATERAL jsonb_each(p.receipts_json::jsonb) "
            "AS entry(request_id, receipt) "
            "WHERE entry.receipt ->> 'work_item_sha256' = %s"
        )
        params: list[object] = [work_item_sha256]
        if after is not None:
            sql += (
                " AND (p.period_key, p.provider, entry.request_id) > (%s, %s, %s)"
            )
            params.extend(after)
        sql += " ORDER BY p.period_key, p.provider, entry.request_id LIMIT %s"
        params.append(limit)
        with self._tx() as cur:
            cur.execute(sql, tuple(params))
            return [tuple(row) for row in cur.fetchall()]

    # ----- pruning -----

    def purge_episodes_before(
        self, cutoff_ts: float, *, dry_run: bool = False, review_binding: dict | None = None,
    ) -> int:
        """Count or delete old completed episodes in the active tenant."""
        tenant = _required_retention_tenant("episode retention")
        predicate = (
            "ended_at IS NOT NULL AND ended_at < %s "
            "AND goal_id IN (SELECT id FROM goals WHERE tenant_id = %s)"
        )
        params: list = [float(cutoff_ts), tenant]
        verb = "SELECT COUNT(*) FROM" if dry_run else "DELETE FROM"
        with self._tx() as cur:
            if review_binding is not None:
                from ..retention_review_bindings import guard_sql

                guard_sql(cur, "episodes", predicate, tuple(params), review_binding, dry_run=dry_run, postgres=True)
                if dry_run:
                    return int(review_binding["count"])
            cur.execute(f"{verb} episodes WHERE {predicate}", tuple(params))
            if dry_run:
                row = cur.fetchone()
                return int(row[0] or 0)
            return int(cur.rowcount or 0)

    def purge_goal_events_before(
        self, cutoff_ts: float, *, dry_run: bool = False, review_binding: dict | None = None,
    ) -> int:
        """Count or delete old goal events in the active tenant."""
        tenant = _required_retention_tenant("goal-event retention")
        predicate = (
            "ts IS NOT NULL AND ts < %s "
            "AND goal_id IN (SELECT id FROM goals WHERE tenant_id = %s)"
        )
        params: list = [float(cutoff_ts), tenant]
        verb = "SELECT COUNT(*) FROM" if dry_run else "DELETE FROM"
        with self._tx() as cur:
            if review_binding is not None:
                from ..retention_review_bindings import guard_sql

                guard_sql(cur, "goal_events", predicate, tuple(params), review_binding, dry_run=dry_run, postgres=True)
                if dry_run:
                    return int(review_binding["count"])
            cur.execute(f"{verb} goal_events WHERE {predicate}", tuple(params))
            if dry_run:
                row = cur.fetchone()
                return int(row[0] or 0)
            return int(cur.rowcount or 0)

    def purge_messages_before(
        self, cutoff_ts: float, *, dry_run: bool = False, review_binding: dict | None = None,
    ) -> int:
        """Count or delete old conversation messages in the active tenant.

        Nothing references ``messages.id`` via foreign key, so this
        is a plain age-based delete scoped through the owning goal's tenant.
        """
        tenant = _required_retention_tenant("message retention")
        predicate = (
            "ts IS NOT NULL AND ts < %s "
            "AND goal_id IN (SELECT id FROM goals WHERE tenant_id = %s)"
        )
        params: list = [float(cutoff_ts), tenant]
        verb = "SELECT COUNT(*) FROM" if dry_run else "DELETE FROM"
        with self._tx() as cur:
            if review_binding is not None:
                from ..retention_review_bindings import guard_sql

                guard_sql(cur, "messages", predicate, tuple(params), review_binding, dry_run=dry_run, postgres=True)
                if dry_run:
                    return int(review_binding["count"])
            cur.execute(f"{verb} messages WHERE {predicate}", tuple(params))
            if dry_run:
                row = cur.fetchone()
                return int(row[0] or 0)
            return int(cur.rowcount or 0)

    def prune_goal_events(self, older_than_seconds: float = 30 * 24 * 3600) -> int:
        cutoff = time.time() - older_than_seconds
        return self.purge_goal_events_before(cutoff)

    def prune_processed_messages(self, older_than_seconds: float = 30 * 24 * 3600) -> int:
        cutoff = time.time() - older_than_seconds
        tenant = _required_retention_tenant("processed-message retention")
        sql = (
            "DELETE FROM processed_messages "
            "WHERE seen_at < %s AND tenant_id = %s"
        )
        with self._tx() as cur:
            cur.execute(sql, (cutoff, tenant))
            return cur.rowcount

    # ----- shared rate-limit window (cross-replica goal-creation cap) -----
    def record_rate_event(self, rl_key: str, ts: float | None = None) -> None:
        """Append one admitted event to the shared sliding-window counter.

        Backs the dashboard's cross-replica goal-creation rate limit: every
        replica records here so the window is shared. Opportunistically prunes
        rows older than two windows so the table can't grow unbounded."""
        now = ts if ts is not None else time.time()
        with self._tx() as cur:
            cur.execute(
                "INSERT INTO rate_events(rl_key, ts) VALUES(%s, %s)", (rl_key, now)
            )
            cur.execute("DELETE FROM rate_events WHERE ts < %s", (now - 120.0,))

    def count_rate_events(self, rl_key: str, since: float) -> int:
        """Count events for ``rl_key`` with ``ts >= since`` (the window count)."""
        with self._tx() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM rate_events WHERE rl_key = %s AND ts >= %s",
                (rl_key, since),
            )
            row = cur.fetchone()
        return int(row[0]) if row else 0

    def reserve_rate_events(
        self,
        key: str,
        cap: int,
        global_key: str,
        global_cap: int,
        ts: float | None = None,
    ) -> str | None:
        """Atomically reserve shared goal-rate capacity for one admitted event.

        Returns ``None`` after inserting both the global and per-client events,
        ``"global"`` when the global bucket is already full, or ``"key"``
        when the per-client bucket is already full. Transaction-scoped advisory
        locks serialize the read-modify-write for the two buckets across
        replicas so concurrent goal creations cannot all observe stale counts
        before recording their reservations.
        """
        now = ts if ts is not None else time.time()
        cutoff = now - 60.0
        with self._tx() as cur:
            cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (f"rate:{global_key}",),
            )
            if key != global_key:
                cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s))",
                    (f"rate:{key}",),
                )
            cur.execute(
                "SELECT COUNT(*) FROM rate_events WHERE rl_key = %s AND ts >= %s",
                (global_key, cutoff),
            )
            row = cur.fetchone()
            global_count = int(row[0]) if row else 0
            if global_count >= global_cap:
                return "global"
            cur.execute(
                "SELECT COUNT(*) FROM rate_events WHERE rl_key = %s AND ts >= %s",
                (key, cutoff),
            )
            row = cur.fetchone()
            key_count = int(row[0]) if row else 0
            if key_count >= cap:
                return "key"
            cur.execute(
                "INSERT INTO rate_events(rl_key, ts) VALUES(%s, %s), (%s, %s)",
                (global_key, now, key, now),
            )
            cur.execute("DELETE FROM rate_events WHERE ts < %s", (now - 120.0,))
        return None

    @property
    def schema_version(self) -> int:
        """Schema version, for parity with SQLite WorldModel.schema_version
        (read as a property by health.py + audit events). Derived from the
        MIGRATIONS ladder (``_PG_SCHEMA_VERSION = MIGRATIONS[-1][0]``)."""
        return _PG_SCHEMA_VERSION

    # ----- close -----

    def close(self) -> None:
        try:
            if self._pool is not None:
                self._pool.close()
            elif self.conn is not None:
                self.conn.close()
        except Exception:  # pragma: no cover
            pass


def open_postgres_world(dsn: str | None = None) -> PostgresWorldModel:
    """Open a Postgres world model. Convenience wrapper that resolves DSN."""
    return PostgresWorldModel(dsn=dsn)


def is_postgres_configured() -> bool:
    """True if config / env requests the postgres backend."""
    if os.environ.get("MAVERICK_WORLD_BACKEND", "").strip().lower() == "postgres":
        return True
    try:
        from ..config import load_config
        cfg = (load_config() or {}).get("world_model") or {}
        return (cfg.get("backend") or "").strip().lower() == "postgres"
    except Exception:
        return False


__all__ = [
    "PostgresWorldModel",
    "PGGoal",
    "open_postgres_world",
    "is_postgres_configured",
    "SCHEMA",
]
