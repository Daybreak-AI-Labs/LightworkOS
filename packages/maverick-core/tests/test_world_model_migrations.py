"""Schema migration tests: forward-only v1 -> v2 -> v3.

Migrations had shipped without tests, so a future
breaking change could silently corrupt a user's ~/.maverick/world.db.

These tests build a *legacy* schema on disk (no schema_version row, no
new columns/tables), then open a `WorldModel` against it and assert:
  - existing rows survive
  - new columns exist and default sensibly
  - new tables are created
  - schema_version lands on `SCHEMA_VERSION`

The same database is reopened a second time to assert migrations are
idempotent (no double-applies, no errors).
"""
from __future__ import annotations

import os
import sqlite3
import time

import pytest
from maverick.file_lock import private_path_is_restricted
from maverick.world_model import SCHEMA, SCHEMA_VERSION, WorldModel, _bootstrap_schema

V1_SCHEMA = """
CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
INSERT INTO schema_version(version) VALUES(1);

CREATE TABLE goals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id INTEGER REFERENCES goals(id),
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    deadline REAL,
    result TEXT
);

CREATE TABLE episodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER REFERENCES goals(id),
    started_at REAL NOT NULL,
    ended_at REAL,
    summary TEXT,
    outcome TEXT
);

CREATE TABLE facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    source_episode_id INTEGER REFERENCES episodes(id),
    updated_at REAL NOT NULL,
    UNIQUE(key)
);

CREATE TABLE questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER REFERENCES goals(id),
    question TEXT NOT NULL,
    asked_at REAL NOT NULL,
    answer TEXT,
    answered_at REAL
);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal_id INTEGER REFERENCES goals(id),
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    ts REAL NOT NULL
);
"""


def _build_legacy_db(path) -> int:
    """Build a v1 DB with one goal, one episode, one fact. Returns goal id."""
    conn = sqlite3.connect(path)
    conn.executescript(V1_SCHEMA)
    now = time.time()
    cur = conn.execute(
        "INSERT INTO goals(title, description, status, created_at, updated_at) "
        "VALUES('legacy goal', 'pre-v2', 'done', ?, ?)",
        (now, now),
    )
    goal_id = cur.lastrowid
    conn.execute(
        "INSERT INTO episodes(goal_id, started_at, ended_at, summary, outcome) "
        "VALUES(?, ?, ?, 'old episode', 'success')",
        (goal_id, now, now),
    )
    conn.execute(
        "INSERT INTO facts(key, value, updated_at) VALUES('user_name', 'alice', ?)",
        (now,),
    )
    conn.commit()
    conn.close()
    return goal_id


def test_pre_migration_backup_written_for_existing_db(tmp_path):
    """Upgrading a pre-existing DB writes a recovery snapshot at the old version
    before the forward-only migrations run."""
    db = tmp_path / "world.db"
    _build_legacy_db(db)  # real data at schema v1

    old_umask = os.umask(0o022)
    try:
        wm = WorldModel(path=db)
    finally:
        os.umask(old_umask)
    assert wm.schema_version == SCHEMA_VERSION

    bak = tmp_path / "world.db.pre-migration-v1.bak"
    assert bak.exists(), "expected a pre-migration backup of the v1 DB"
    assert private_path_is_restricted(bak, 0o600)
    # The snapshot captured the PRE-migration state (v1), not the upgraded one.
    bconn = sqlite3.connect(str(bak))
    try:
        ver = bconn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()[0]
        # And the legacy data is intact in the snapshot.
        title = bconn.execute("SELECT title FROM goals LIMIT 1").fetchone()[0]
    finally:
        bconn.close()
    assert ver == 1
    assert title == "legacy goal"


def test_pre_migration_backup_skipped_for_fresh_db(tmp_path):
    """A brand-new world.db 'migrates' v1->current on first open but has no data
    to protect, so no backup file is written (no per-install/-tenant litter)."""
    db = tmp_path / "world.db"
    wm = WorldModel(path=db)
    assert wm.schema_version == SCHEMA_VERSION
    assert not list(tmp_path.glob("world.db.pre-migration-*.bak"))


def test_pre_migration_backup_can_be_disabled(tmp_path, monkeypatch):
    """[world_model] pre_migration_backup = false opts out."""
    import maverick.config as cfg
    db = tmp_path / "world.db"
    _build_legacy_db(db)
    monkeypatch.setattr(
        cfg, "load_config",
        lambda *a, **k: {"world_model": {"pre_migration_backup": False}},
    )
    wm = WorldModel(path=db)
    assert wm.schema_version == SCHEMA_VERSION
    assert not list(tmp_path.glob("world.db.pre-migration-*.bak"))


def test_migrates_v1_to_current(tmp_path):
    db = tmp_path / "world.db"
    goal_id = _build_legacy_db(db)

    wm = WorldModel(path=db)

    assert wm.schema_version == SCHEMA_VERSION

    # Pre-existing rows survive.
    goal = wm.get_goal(goal_id)
    assert goal is not None
    assert goal.title == "legacy goal"
    assert goal.status == "done"

    # New episodes columns exist with sensible defaults for pre-migration rows.
    spend = wm.total_spend()
    assert spend["dollars"] == 0
    assert spend["input_tokens"] == 0
    assert spend["output_tokens"] == 0
    assert spend["runs"] == 1  # the pre-existing ended episode

    # v3 table goal_events is usable (no rows yet, append works).
    ev_id = wm.append_event(goal_id, "orchestrator", "info", "live event")
    assert ev_id > 0
    events = wm.goal_events(goal_id, since_id=0)
    assert len(events) == 1
    assert events[0].kind == "info"


def test_migrations_are_idempotent(tmp_path):
    db = tmp_path / "world.db"
    _build_legacy_db(db)

    # First open: v1 -> v3
    wm1 = WorldModel(path=db)
    assert wm1.schema_version == SCHEMA_VERSION
    wm1.conn.close()

    # Second open: already at v3, must be a no-op (no duplicate column errors).
    wm2 = WorldModel(path=db)
    assert wm2.schema_version == SCHEMA_VERSION

    # And it must still be writeable end-to-end.
    gid = wm2.create_goal("new", "post-migration")
    assert wm2.get_goal(gid).title == "new"




def test_legacy_db_without_schema_version_row_runs_migrations(tmp_path):
    """Legacy DBs that predate schema_version rows should not skip migrations."""
    db = tmp_path / "legacy-no-version.db"
    _build_legacy_db(db)

    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM schema_version")
    conn.commit()
    conn.close()

    wm = WorldModel(path=db)
    assert wm.schema_version == SCHEMA_VERSION

    cols = {r[1] for r in wm.conn.execute("PRAGMA table_info(episodes)").fetchall()}
    assert {"cost_dollars", "input_tokens", "output_tokens", "tool_calls"}.issubset(cols)

def test_fresh_db_lands_on_current(tmp_path):
    db = tmp_path / "fresh.db"
    wm = WorldModel(path=db)
    assert wm.schema_version == SCHEMA_VERSION

    # All the surface area works end-to-end.
    gid = wm.create_goal("first", "")
    wm.upsert_fact("k", "v")
    eid = wm.start_episode(gid)
    wm.end_episode(eid, "ok", "success", cost_dollars=0.42, input_tokens=10, output_tokens=20, tool_calls=2)
    wm.append_event(gid, "agent", "step", "running")

    assert wm.get_facts() == {"k": "v"}
    spend = wm.total_spend()
    assert spend["dollars"] == 0.42
    assert spend["runs"] == 1
    assert len(wm.goal_events(gid)) == 1


def _object_names(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master").fetchall()}


def test_bootstrap_from_v49_omits_only_the_retired_message_search_block():
    """v49 dropped the message-search table and its triggers. The base schema
    still creates them, so a v49+ database is bootstrapped without exactly that
    block and keeps every other base object, including the v8 indexes after it."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY)")
    conn.execute("INSERT INTO schema_version(version) VALUES(49)")
    trimmed = sqlite3.connect(":memory:")
    trimmed.executescript(_bootstrap_schema(conn))
    full = sqlite3.connect(":memory:")
    full.executescript(SCHEMA)

    kept, everything = _object_names(trimmed), _object_names(full)
    omitted = everything - kept
    search_triggers = {"messages_ai", "messages_ad", "messages_au"}
    assert kept <= everything
    assert {"messages_fts"} | search_triggers <= omitted
    assert all(name.startswith("messages_fts") or name in search_triggers for name in omitted)
    assert {"idx_episodes_goal_started", "idx_goals_parent", "harness_corpus"} <= kept


def test_bootstrap_before_v49_applies_the_whole_base_schema():
    conn = sqlite3.connect(":memory:")
    assert _bootstrap_schema(conn) == SCHEMA
    conn.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY)")
    conn.execute("INSERT INTO schema_version(version) VALUES(48)")
    assert _bootstrap_schema(conn) == SCHEMA


def test_prune_goal_events(tmp_path):
    db = tmp_path / "prune.db"
    wm = WorldModel(path=db)
    gid = wm.create_goal("g", "")

    # Backdate one event by 60 days; keep another recent.
    wm.append_event(gid, "a", "info", "old")
    wm.conn.execute(
        "UPDATE goal_events SET ts = ? WHERE id = (SELECT MAX(id) FROM goal_events)",
        (time.time() - 60 * 24 * 3600,),
    )
    wm.append_event(gid, "a", "info", "recent")
    wm.conn.commit()

    removed = wm.prune_goal_events(older_than_seconds=30 * 24 * 3600)
    assert removed == 1
    assert len(wm.goal_events(gid)) == 1
    assert wm.goal_events(gid)[0].content == "recent"


def test_recent_goal_events_returns_tail_in_chronological_order(tmp_path):
    from maverick.world_model import WorldModel

    wm = WorldModel(tmp_path / "world.db")
    gid = wm.create_goal("long run")
    for i in range(5):
        wm.append_event(gid, "agent", "note", f"event-{i + 1}")

    events = wm.recent_goal_events(gid, limit=3)

    assert [e.content for e in events] == ["event-3", "event-4", "event-5"]


def test_failing_migration_rolls_back_atomically(tmp_path, monkeypatch):
    """Python's sqlite3 legacy driver auto-commits DDL/backfill
    statements one at a time outside any transaction. Without an explicit
    wrapping transaction per version, a migration whose SECOND statement
    fails still left its FIRST statement permanently applied while
    schema_version stayed unbumped -- an interrupted upgrade left the DB
    half-migrated with no way for a later open to detect or retry cleanly.
    """
    import maverick.world_model as wm_mod

    db = tmp_path / "world.db"
    w = WorldModel(db)
    w.conn.execute(
        "UPDATE schema_version SET version = ?", (SCHEMA_VERSION - 1,),
    )
    w.conn.commit()
    w.conn.close()

    monkeypatch.setitem(
        wm_mod.MIGRATIONS, SCHEMA_VERSION,
        ["ALTER TABLE goals ADD COLUMN audit_probe TEXT", "CREATE TABLE goals (x)"],
    )

    with pytest.raises(sqlite3.OperationalError):
        WorldModel(db)

    conn = sqlite3.connect(str(db))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(goals)").fetchall()]
    version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    conn.close()
    assert "audit_probe" not in cols  # first statement rolled back too
    assert version == SCHEMA_VERSION - 1  # never bumped
