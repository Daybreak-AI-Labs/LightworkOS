"""Concurrent WorldModel opens must not raise 'database is locked'.

The dashboard and the agent each open their own connection to the same world
DB. Switching the journal mode to WAL needs a brief exclusive lock, so two
connections opening at the same instant raced and the loser raised
``OperationalError("database is locked")`` -- the root cause of the
intermittent consent-test CI flake (a background thread opened a second
connection). ``__init__`` now arms ``busy_timeout`` before the WAL switch and
retries the switch on a transient lock; these hammer that path with a barrier
so all threads open simultaneously.
"""
import sqlite3
import threading

import pytest
from maverick import world_model as world_model_module
from maverick.world_model import SCHEMA_VERSION, WorldModel


def _hammer_opens(db, n: int) -> list[Exception]:
    barrier = threading.Barrier(n)
    errors: list[Exception] = []

    def _open():
        try:
            barrier.wait()  # release all threads at once -> maximal contention
            wm = WorldModel(path=db)
            wm.conn.execute("SELECT 1").fetchone()  # connection is usable
            wm.close()
        except Exception as e:  # pragma: no cover - only fires on regression
            errors.append(e)

    threads = [threading.Thread(target=_open) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return errors


def test_many_concurrent_opens_never_lock(tmp_path):
    db = tmp_path / "world.db"
    WorldModel(path=db).close()  # seed file + schema, then hammer re-opens
    errors = _hammer_opens(db, 24)
    assert not errors, f"concurrent opens raised: {errors[:3]}"


def test_concurrent_first_open_of_fresh_db(tmp_path):
    """Even with no pre-existing file, concurrent first-opens must not lock.

    Two failure modes raced here: a duplicate schema_version row (fixed by the
    empty-table-guarded seed) and SQLITE_LOCKED from executescript/migrations
    (which bypasses busy_timeout, now retried). Both only fired on a fraction
    of runs -- a single hammer was a weak guard that surfaced as an
    intermittent CI flake. Repeat over fresh DBs so a regression of either
    fails reliably, not ~15% of the time.
    """
    for i in range(15):
        errors = _hammer_opens(tmp_path / f"fresh-{i}.db", 16)
        assert not errors, f"concurrent first-opens raised (iter {i}): {errors[:3]}"


def test_concurrent_first_open_leaves_single_schema_version_row(tmp_path):
    """A concurrent first-open storm must leave exactly ONE schema_version row.

    The loser of the seed race used to insert a duplicate row (version=1 was
    free again once the winner had migrated its row up), and the no-WHERE
    `UPDATE schema_version SET version=?` then collided on the PK -- the
    intermittent IntegrityError CI flake. The seed is now empty-table-guarded.
    """
    db = tmp_path / "fresh.db"
    errors = _hammer_opens(db, 16)
    assert not errors, f"concurrent first-opens raised: {errors[:3]}"
    wm = WorldModel(path=db)
    try:
        rows = wm.conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]
        assert wm.schema_version == SCHEMA_VERSION  # migrated to head, intact
    finally:
        wm.close()
    assert rows == 1, f"expected exactly one schema_version row, got {rows}"


def test_wal_retry_uses_short_busy_timeout(monkeypatch, tmp_path):
    """A sustained lock must not multiply the normal 5s busy timeout by retries."""

    class LockedConnection:
        def __init__(self):
            self.current_busy_timeout_ms = None
            self.wal_attempt_busy_timeouts: list[int | None] = []
            self.row_factory = None

        def execute(self, sql, *args):
            normalized = sql.strip().lower()
            if normalized.startswith("pragma busy_timeout ="):
                self.current_busy_timeout_ms = int(normalized.rsplit("=", 1)[1])
                return self
            if normalized == "pragma journal_mode = wal":
                self.wal_attempt_busy_timeouts.append(self.current_busy_timeout_ms)
                fake_clock["now"] += (self.current_busy_timeout_ms or 0) / 1000
                raise sqlite3.OperationalError("database is locked")
            return self

    fake_clock = {"now": 0.0}
    conn = LockedConnection()

    monkeypatch.setattr(world_model_module.sqlite3, "connect", lambda *args, **kwargs: conn)
    monkeypatch.setattr(world_model_module, "WAL_SWITCH_BUSY_TIMEOUT_MS", 10)
    monkeypatch.setattr(world_model_module, "WAL_SWITCH_RETRY_SECONDS", 0.12)
    monkeypatch.setattr(world_model_module.time, "monotonic", lambda: fake_clock["now"])
    monkeypatch.setattr(
        world_model_module.time,
        "sleep",
        lambda seconds: fake_clock.__setitem__("now", fake_clock["now"] + seconds),
    )

    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        WorldModel(path=tmp_path / "world.db")

    assert conn.wal_attempt_busy_timeouts
    assert set(conn.wal_attempt_busy_timeouts) == {10}
    assert fake_clock["now"] < 0.2
