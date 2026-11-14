"""Tests for audit + world-model retention enforcement."""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import pytest


def _make_audit_file(audit_dir: Path, day: str, body: str = '{"v": 1}\n') -> Path:
    audit_dir.mkdir(parents=True, exist_ok=True)
    p = audit_dir / f"{day}.ndjson"
    p.write_text(body)
    return p


def test_purge_audit_files_disabled():
    from maverick.audit.retention import purge_audit_files
    res = purge_audit_files(days=0, audit_dir=Path("/nonexistent"))
    assert res["reason"] == "disabled"


def test_purge_audit_files_refuses_boolean_days(tmp_path: Path):
    # `audit_days = true` is int(True) == 1; it must not purge every day but today.
    from maverick.audit.retention import purge_audit_files
    audit_dir = tmp_path / "audit"
    _make_audit_file(audit_dir, "2025-06-01")
    fixed_now = time.mktime(time.strptime("2025-06-30", "%Y-%m-%d"))
    for bad in (True, 1.5, "30"):
        with pytest.raises(ValueError, match="whole number of days"):
            purge_audit_files(days=bad, audit_dir=audit_dir, now=fixed_now)
    assert (audit_dir / "2025-06-01.ndjson").exists()


def test_purge_audit_files_no_dir(tmp_path: Path):
    from maverick.audit.retention import purge_audit_files
    res = purge_audit_files(days=30, audit_dir=tmp_path / "nope")
    assert res["reason"] == "no audit dir"


def test_purge_audit_files_removes_old_keeps_recent(tmp_path: Path):
    from maverick.audit.retention import purge_audit_files
    audit_dir = tmp_path / "audit"
    _make_audit_file(audit_dir, "2025-01-01")
    _make_audit_file(audit_dir, "2025-06-15")
    _make_audit_file(audit_dir, "2025-06-25")
    _make_audit_file(audit_dir, "garbage")  # non-date file is preserved

    fixed_now = time.mktime(time.strptime("2025-06-30", "%Y-%m-%d"))
    res = purge_audit_files(days=10, audit_dir=audit_dir, now=fixed_now)
    removed = set(res["removed"])
    assert "2025-01-01.ndjson" in removed
    assert "2025-06-15.ndjson" in removed
    assert "2025-06-25.ndjson" not in removed
    # File still on disk:
    assert (audit_dir / "2025-06-25.ndjson").exists()
    assert (audit_dir / "garbage.ndjson").exists()
    assert not (audit_dir / "2025-01-01.ndjson").exists()


def test_purge_audit_files_dry_run(tmp_path: Path):
    from maverick.audit.retention import purge_audit_files
    audit_dir = tmp_path / "audit"
    _make_audit_file(audit_dir, "2024-01-01")
    fixed_now = time.mktime(time.strptime("2025-01-01", "%Y-%m-%d"))
    res = purge_audit_files(days=10, audit_dir=audit_dir, dry_run=True, now=fixed_now)
    assert "2024-01-01.ndjson" in res["removed"]
    # Dry run leaves file in place.
    assert (audit_dir / "2024-01-01.ndjson").exists()


def _seed_world_db(path: Path) -> None:
    """Create a minimal world.db with the columns retention.py touches."""
    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE goals (id INTEGER PRIMARY KEY, status TEXT,
                            created_at REAL, updated_at REAL);
        CREATE TABLE episodes (id INTEGER PRIMARY KEY, goal_id INTEGER,
                               started_at REAL, ended_at REAL,
                               summary TEXT, outcome TEXT,
                               cost_dollars REAL, input_tokens INTEGER,
                               output_tokens INTEGER, tool_calls INTEGER);
        CREATE TABLE goal_events (id INTEGER PRIMARY KEY, goal_id INTEGER,
                                  agent TEXT, kind TEXT, content TEXT, ts REAL);
        CREATE TABLE messages (id INTEGER PRIMARY KEY, goal_id INTEGER,
                               role TEXT, content TEXT, ts REAL);
    """)
    conn.commit()
    conn.close()


def _insert_episode(db: Path, ended_at: float) -> None:
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO episodes (started_at, ended_at, outcome) VALUES (?, ?, 'x')",
        (ended_at - 1, ended_at),
    )
    conn.commit()
    conn.close()


def _insert_event(db: Path, ts: float) -> None:
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO goal_events (goal_id, agent, kind, content, ts) VALUES (1, 'a', 'k', '', ?)",
        (ts,),
    )
    conn.commit()
    conn.close()


def _insert_message(db: Path, ts: float) -> None:
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO messages (goal_id, role, content, ts) VALUES (1, 'user', '', ?)",
        (ts,),
    )
    conn.commit()
    conn.close()


def test_purge_world_episodes_removes_old(tmp_path: Path):
    from maverick.audit.retention import purge_world_episodes
    db = tmp_path / "world.db"
    _seed_world_db(db)
    now = 1_700_000_000.0
    _insert_episode(db, now - 100 * 86400)  # old
    _insert_episode(db, now - 10 * 86400)   # recent
    _insert_episode(db, now)                # fresh

    res = purge_world_episodes(days=30, db_path=db, now=now)
    assert res["deleted"] == 1

    conn = sqlite3.connect(str(db))
    (left,) = conn.execute("SELECT COUNT(*) FROM episodes").fetchone()
    conn.close()
    assert left == 2


def test_purge_world_episodes_dry_run(tmp_path: Path):
    from maverick.audit.retention import purge_world_episodes
    db = tmp_path / "world.db"
    _seed_world_db(db)
    now = 1_700_000_000.0
    _insert_episode(db, now - 100 * 86400)

    res = purge_world_episodes(days=30, db_path=db, now=now, dry_run=True)
    assert res["deleted"] == 1
    conn = sqlite3.connect(str(db))
    (left,) = conn.execute("SELECT COUNT(*) FROM episodes").fetchone()
    conn.close()
    assert left == 1  # still there


def test_purge_episodes_before_nulls_dangling_fact_references(tmp_path: Path):
    # Canonical path: facts.source_episode_id / fact_history.source_
    # episode_id REFERENCE episodes(id) with no ON DELETE clause, and the
    # world opens with foreign_keys ON. Deleting an aged-out episode that a
    # still-live fact cites must not raise sqlite3.IntegrityError and abort
    # the whole retention run -- older episodes were never pruned.
    from maverick.world_model import WorldModel

    w = WorldModel(tmp_path / "world.db")
    gid = w.create_goal("t", "d")
    eid = w.start_episode(gid)
    w.end_episode(eid, "s", "ok")
    w.upsert_fact("k", "v", episode_id=eid)

    deleted = w.purge_episodes_before(time.time() + 10)

    assert deleted == 1
    # The fact survives -- retention prunes old episodes, not live facts.
    assert w.get_fact("k") == "v"
    conn = sqlite3.connect(str(tmp_path / "world.db"))
    (episode_id,) = conn.execute(
        "SELECT source_episode_id FROM facts WHERE key = 'k'"
    ).fetchone()
    conn.close()
    assert episode_id is None  # provenance nulled, not left dangling


def test_purge_world_episodes_db_path_nulls_dangling_fact_references(tmp_path: Path):
    # --db-path route: this path opened a raw sqlite3 connection
    # WITHOUT foreign_keys, so it silently deleted the parent episode and
    # left a dangling facts.source_episode_id instead of raising -- the two
    # retention routes disagreed on the same policy.
    from maverick.audit.retention import purge_world_episodes
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    w = WorldModel(db)
    gid = w.create_goal("t", "d")
    eid = w.start_episode(gid)
    w.end_episode(eid, "s", "ok")
    w.upsert_fact("k", "v", episode_id=eid)

    far_future = time.time() + 90 * 86400
    res = purge_world_episodes(days=1, db_path=db, now=far_future)

    assert res["deleted"] == 1
    conn = sqlite3.connect(str(db))
    (ep_count,) = conn.execute(
        "SELECT COUNT(*) FROM episodes WHERE id = ?", (eid,)
    ).fetchone()
    (episode_id,) = conn.execute(
        "SELECT source_episode_id FROM facts WHERE key = 'k'"
    ).fetchone()
    conn.close()
    assert ep_count == 0  # the episode is really gone
    assert episode_id is None  # not left dangling


def test_purge_world_events_removes_old(tmp_path: Path):
    from maverick.audit.retention import purge_world_events
    db = tmp_path / "world.db"
    _seed_world_db(db)
    now = 1_700_000_000.0
    _insert_event(db, now - 200 * 86400)
    _insert_event(db, now - 5 * 86400)

    res = purge_world_events(days=30, db_path=db, now=now)
    assert res["deleted"] == 1


def test_purge_world_messages_removes_old(tmp_path: Path):
    from maverick.audit.retention import purge_world_messages
    db = tmp_path / "world.db"
    _seed_world_db(db)
    now = 1_700_000_000.0
    _insert_message(db, now - 200 * 86400)  # old
    _insert_message(db, now - 5 * 86400)    # recent

    res = purge_world_messages(days=30, db_path=db, now=now)
    assert res["deleted"] == 1

    conn = sqlite3.connect(str(db))
    (left,) = conn.execute("SELECT COUNT(*) FROM messages").fetchone()
    conn.close()
    assert left == 1


def test_purge_world_messages_dry_run(tmp_path: Path):
    from maverick.audit.retention import purge_world_messages
    db = tmp_path / "world.db"
    _seed_world_db(db)
    now = 1_700_000_000.0
    _insert_message(db, now - 100 * 86400)

    res = purge_world_messages(days=30, db_path=db, now=now, dry_run=True)
    assert res["deleted"] == 1
    conn = sqlite3.connect(str(db))
    (left,) = conn.execute("SELECT COUNT(*) FROM messages").fetchone()
    conn.close()
    assert left == 1  # still there


def test_purge_messages_before_canonical(tmp_path: Path):
    """The canonical (--db-path-less) route dispatches through the
    configured world backend, mirroring purge_episodes_before/purge_goal_events_before.
    Unlike episodes, messages have no dependent FK rows to null out first."""
    from maverick.world_model import WorldModel

    w = WorldModel(tmp_path / "world.db")
    gid = w.create_goal("t", "d")
    w.append_message(gid, "user", "hello")
    w.conn.execute("UPDATE messages SET ts = ?", (time.time() - 100 * 86400,))
    w.conn.commit()

    deleted = w.purge_messages_before(time.time())

    assert deleted == 1


def test_enforce_no_config_returns_disabled():
    from maverick.audit.retention import enforce
    res = enforce(config={})
    assert res["status"] == "disabled"


def test_enforce_full_config(tmp_path: Path):
    from maverick.audit.retention import enforce
    audit_dir = tmp_path / "audit"
    db = tmp_path / "world.db"
    _seed_world_db(db)
    _make_audit_file(audit_dir, "2024-01-01")
    now = time.mktime(time.strptime("2025-06-30", "%Y-%m-%d"))
    _insert_episode(db, now - 200 * 86400)
    _insert_event(db, now - 365 * 86400)
    _insert_message(db, now - 400 * 86400)

    cfg = {
        "audit_days": 30, "episodes_days": 30, "events_days": 90,
        "messages_days": 90,
    }
    res = enforce(
        config=cfg, audit_dir=audit_dir, db_path=db, now=now,
    )
    assert res["audit"]["removed"] == ["2024-01-01.ndjson"]
    assert res["episodes"]["deleted"] == 1
    assert res["goal_events"]["deleted"] == 1
    assert res["messages"]["deleted"] == 1


@pytest.mark.parametrize("days", [None, 0, -5])
def test_purge_helpers_disabled_with_bad_days(tmp_path: Path, days):
    from maverick.audit.retention import (
        purge_audit_files,
        purge_world_episodes,
        purge_world_events,
        purge_world_messages,
    )
    db = tmp_path / "world.db"
    _seed_world_db(db)
    assert purge_audit_files(days=days, audit_dir=tmp_path)["reason"] == "disabled"
    assert purge_world_episodes(days=days, db_path=db)["reason"] == "disabled"
    assert purge_world_events(days=days, db_path=db)["reason"] == "disabled"
    assert purge_world_messages(days=days, db_path=db)["reason"] == "disabled"


def test_purge_missing_db_safe(tmp_path: Path):
    """No DB file -> no rows deleted, no exception."""
    from maverick.audit.retention import purge_world_episodes
    res = purge_world_episodes(days=30, db_path=tmp_path / "absent.db")
    assert res["deleted"] == 0


def test_unscoped_postgres_retention_fails_closed(monkeypatch):
    """A maintenance process may not turn an absent tenant into DELETE ALL."""
    from maverick.audit.retention import RetentionScopeError, purge_world_episodes

    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr("maverick.client.client_id", lambda: None)
    with pytest.raises(RetentionScopeError, match="unscoped Postgres"):
        purge_world_episodes(days=30)


def test_enforce_covers_every_registered_tenant(monkeypatch):
    """The operator command fans out under an explicit tenant context."""
    from maverick.audit import retention
    from maverick.paths import current_tenant_id
    from maverick.tenant import registry

    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr("maverick.client.client_id", lambda: None)
    monkeypatch.setattr(
        registry,
        "list_tenants",
        lambda: [SimpleNamespace(id="acme"), SimpleNamespace(id="beta")],
    )
    seen: list[str | None] = []

    def _purge(**_kwargs):
        seen.append(current_tenant_id())
        return {"deleted": 0}

    monkeypatch.setattr(retention, "purge_world_episodes", _purge)
    report = retention.enforce(config={"episodes_days": 30}, dry_run=True)

    assert report["scope"] == "tenant_fleet"
    assert report["tenant_count"] == 2
    assert set(report["tenants"]) == {"acme", "beta"}
    assert seen == ["acme", "beta"]


# ---- usage-ledger (cost telemetry) retention ----

from datetime import datetime, timezone  # noqa: E402

_NOW_2025_06_30 = datetime(2025, 6, 30, tzinfo=timezone.utc).timestamp()


def _ledger(tmp_path: Path):
    from maverick.quotas import UsageLedger
    return UsageLedger(tmp_path / "usage_ledger.json")


def test_usage_ledger_prune_disabled(tmp_path: Path):
    led = _ledger(tmp_path)
    led.record("alice", 1.0, 10, 5, day="2020-01-01")
    assert led.prune(0)["reason"] == "disabled"
    # nothing removed
    assert led.usage("alice", day="2020-01-01")["dollars"] == 1.0


def test_usage_ledger_prune_removes_old_keeps_recent(tmp_path: Path):
    led = _ledger(tmp_path)
    led.record("alice", 1.0, 1, 1, day="2025-01-01")  # very old
    led.record("alice", 2.0, 2, 2, day="2025-06-15")  # before cutoff
    led.record("alice", 3.0, 3, 3, day="2025-06-25")  # after cutoff -> keep
    # now=2025-06-30, keep_days=10 -> cutoff day 2025-06-20
    res = led.prune(10, now=_NOW_2025_06_30)
    assert res["removed_buckets"] == 2
    assert res["cutoff_day"] == "2025-06-20"
    assert led.usage("alice", day="2025-06-25")["dollars"] == 3.0
    assert led.usage("alice", day="2025-06-15")["dollars"] == 0.0
    assert led.usage("alice", day="2025-01-01")["dollars"] == 0.0


def test_usage_ledger_prune_drops_empty_principal(tmp_path: Path):
    led = _ledger(tmp_path)
    led.record("stale", 1.0, 1, 1, day="2025-01-01")   # only old days
    led.record("active", 1.0, 1, 1, day="2025-06-29")  # has a recent day
    res = led.prune(10, now=_NOW_2025_06_30)
    assert res["removed_principals"] == 1
    import json
    data = json.loads((tmp_path / "usage_ledger.json").read_text())
    assert "stale" not in data
    assert "active" in data


def test_usage_ledger_prune_dry_run(tmp_path: Path):
    led = _ledger(tmp_path)
    led.record("alice", 1.0, 1, 1, day="2025-01-01")
    res = led.prune(10, now=_NOW_2025_06_30, dry_run=True)
    assert res["removed_buckets"] == 1
    # untouched on disk
    assert led.usage("alice", day="2025-01-01")["dollars"] == 1.0


def test_purge_usage_ledger_wires_to_prune(tmp_path: Path):
    from maverick.audit.retention import purge_usage_ledger
    led = _ledger(tmp_path)
    led.record("alice", 1.0, 1, 1, day="2025-01-01")
    res = purge_usage_ledger(days=10, ledger_path=tmp_path / "usage_ledger.json",
                             now=_NOW_2025_06_30)
    assert res["removed_buckets"] == 1
    assert led.usage("alice", day="2025-01-01")["dollars"] == 0.0


def test_purge_usage_ledger_disabled(tmp_path: Path):
    from maverick.audit.retention import purge_usage_ledger
    assert purge_usage_ledger(days=0)["reason"] == "disabled"


def test_enforce_includes_usage_ledger(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.audit.retention import enforce
    from maverick.quotas import UsageLedger
    UsageLedger().record("alice", 1.0, 1, 1, day="2020-01-01")
    res = enforce(config={"usage_days": 30}, now=_NOW_2025_06_30)
    assert res["usage_ledger"]["removed_buckets"] == 1


# ---- signed retention marker in the audit chain --------------------------


def _read_marker_rows(audit_dir: Path) -> list[dict]:
    """All retention_purge rows across the live day-files in ``audit_dir``."""
    import json
    rows = []
    for p in audit_dir.glob("*.ndjson"):
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("kind") == "retention_purge":
                rows.append(row)
    return rows


def test_enforce_writes_retention_marker(tmp_path: Path):
    from maverick.audit.retention import enforce
    audit_dir = tmp_path / "audit"
    db = tmp_path / "world.db"
    _seed_world_db(db)
    _make_audit_file(audit_dir, "2024-01-01")
    now = time.mktime(time.strptime("2025-06-30", "%Y-%m-%d"))
    _insert_episode(db, now - 200 * 86400)
    _insert_message(db, now - 200 * 86400)

    res = enforce(
        config={"audit_days": 30, "episodes_days": 30, "messages_days": 30},
        audit_dir=audit_dir, db_path=db, now=now,
    )
    # The report carries the marker, and a tamper-evident row was written.
    assert res["marker"]["audit_files"] == ["2024-01-01.ndjson"]
    assert res["marker"]["episodes_deleted"] == 1
    assert res["marker"]["messages_deleted"] == 1
    rows = _read_marker_rows(audit_dir)
    assert len(rows) == 1
    payload = rows[0].get("payload", rows[0])
    assert payload["audit_files_removed"] == 1
    assert payload["audit_cutoff_day"]


def test_dry_run_writes_no_marker(tmp_path: Path):
    from maverick.audit.retention import enforce
    audit_dir = tmp_path / "audit"
    _make_audit_file(audit_dir, "2024-01-01")
    now = time.mktime(time.strptime("2025-06-30", "%Y-%m-%d"))

    res = enforce(
        config={"audit_days": 30}, audit_dir=audit_dir, dry_run=True, now=now,
    )
    assert "marker" not in res
    assert _read_marker_rows(audit_dir) == []


def test_no_purge_writes_no_marker(tmp_path: Path):
    # Nothing old enough to purge -> no marker noise.
    from maverick.audit.retention import enforce
    audit_dir = tmp_path / "audit"
    _make_audit_file(audit_dir, "2025-06-29")
    now = time.mktime(time.strptime("2025-06-30", "%Y-%m-%d"))
    res = enforce(config={"audit_days": 30}, audit_dir=audit_dir, now=now)
    assert "marker" not in res
    assert _read_marker_rows(audit_dir) == []


def test_retention_marker_is_signed_and_verifies(tmp_path: Path, monkeypatch):
    pytest.importorskip("cryptography")
    from maverick.audit import signing
    from maverick.audit.retention import enforce
    from maverick.audit.signing import verify_chain
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")

    audit_dir = tmp_path / "audit"
    _make_audit_file(audit_dir, "2024-01-01")
    now = time.mktime(time.strptime("2025-06-30", "%Y-%m-%d"))
    enforce(config={"audit_days": 30}, audit_dir=audit_dir, now=now)

    # The marker file (today's day-file) is a clean signed chain.
    marker_files = [
        p for p in audit_dir.glob("*.ndjson") if p.stem != "2024-01-01"
    ]
    assert len(marker_files) == 1
    assert verify_chain(marker_files[0]) == []


# ---------- retention: only the known tables are purgeable ----------

def test_retention_rejects_unknown_table(tmp_path):
    import sqlite3

    from maverick.audit.retention import _purge_table_by_time
    db = tmp_path / "w.db"
    sqlite3.connect(str(db)).close()
    try:
        _purge_table_by_time(db, "goals; DROP TABLE goals", "x", 0.0, dry_run=True)
    except ValueError as e:
        assert "unknown table/column" in str(e)
        return
    raise AssertionError("expected ValueError on non-whitelisted table")


def test_retention_allows_known_table(tmp_path):
    import sqlite3

    from maverick.audit.retention import _purge_table_by_time
    db = tmp_path / "w.db"
    c = sqlite3.connect(str(db))
    c.execute("CREATE TABLE episodes (id INTEGER, ended_at REAL)")
    c.execute("INSERT INTO episodes VALUES (1, 100.0)")
    c.commit()
    c.close()
    removed = _purge_table_by_time(db, "episodes", "ended_at", 200.0, dry_run=True)
    assert removed == 1  # dry run counts the old row, doesn't delete
