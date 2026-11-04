"""Regression: WorldModel write serialisation.

The dashboard keeps a per-DB-path WorldModel singleton so requests do
not reopen SQLite and reapply migrations. ``check_same_thread=False``
alone is not thread-safe: two FastAPI threadpool workers driving execute()+commit()
on the same connection can interleave their writes so one transaction
silently includes the other's row. Worst case: thread A errors and
rolls back, thread B's "successful" insert vanishes.

The ``_writing()`` context manager + RLock make every mutating method
commit exactly one logical write. These tests prove
it under load.
"""
from __future__ import annotations

import concurrent.futures
import threading
from pathlib import Path

from maverick.world_model import WorldModel


def test_create_goal_under_thread_storm(tmp_path: Path):
    """1000 create_goal calls across 32 threads on one shared WorldModel.

    Without the lock this is flaky on macOS/Linux (one thread's row
    gets attributed to the other transaction). With the lock, every
    insert is its own committed transaction.
    """
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    try:
        N = 1000
        T = 32

        def one(i: int) -> int:
            return wm.create_goal(f"goal-{i}", f"desc-{i}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=T) as ex:
            ids = list(ex.map(one, range(N)))

        # Every call returned a unique lastrowid.
        assert len(set(ids)) == N

        # Every row is present in the database.
        rows = wm.list_goals()
        assert len(rows) == N

        # Titles round-trip without corruption.
        titles = {g.title for g in rows}
        assert titles == {f"goal-{i}" for i in range(N)}
    finally:
        wm.close()


def test_mixed_writers_dont_lose_rows(tmp_path: Path):
    """Concurrent create_goal + start_episode + upsert_fact + ask + answer.

    Mixed-writer pattern catches a different bug than uniform inserts:
    if the lock weren't held across the full execute+commit window,
    one method's commit() could flush another method's still-in-flight
    statement.
    """
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    try:
        N = 200

        # Pre-create goals so episode + fact + question writers have targets.
        goal_ids = [wm.create_goal(f"g-{i}", "") for i in range(20)]

        def writer(op: str, i: int):
            if op == "goal":
                return wm.create_goal(f"new-{i}", "")
            if op == "episode":
                return wm.start_episode(goal_ids[i % len(goal_ids)])
            if op == "fact":
                wm.upsert_fact(f"k-{i}", f"v-{i}")
                return i
            if op == "question":
                return wm.ask(f"q-{i}", goal_id=goal_ids[i % len(goal_ids)])
            return None

        ops = []
        for i in range(N):
            ops.append(("goal", i))
            ops.append(("episode", i))
            ops.append(("fact", i))
            ops.append(("question", i))

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            list(ex.map(lambda p: writer(*p), ops))

        # Expected counts.
        assert len(wm.list_goals()) == 20 + N            # pre + 'goal' op
        assert len(wm.list_episodes(limit=10_000)) == N  # 'episode' op
        assert len(wm.get_facts()) == N                  # 'fact' op (unique keys)
        questions = sum(len(wm.open_questions(g)) for g in goal_ids)
        assert questions == N                            # 'question' op
    finally:
        wm.close()


def test_writing_helper_releases_lock_on_exception(tmp_path: Path):
    """An exception inside _writing() must release the lock so the next
    caller doesn't deadlock. Verifies RLock semantics + no commit().
    """
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    try:
        # Trigger an error inside the _writing() body.
        try:
            with wm._writing() as conn:
                conn.execute("INSERT INTO this_table_does_not_exist VALUES(1)")
        except Exception:
            pass

        # The lock should be free; this call must not block.
        completed = threading.Event()

        def try_write():
            wm.create_goal("after-error", "")
            completed.set()

        t = threading.Thread(target=try_write, daemon=True)
        t.start()
        t.join(timeout=2.0)
        assert completed.is_set(), "lock leaked from _writing() on exception"

        # The failed write did NOT persist (no implicit commit).
        rows = wm.list_goals()
        assert len(rows) == 1  # only the successful "after-error" goal
    finally:
        wm.close()


def test_writing_rolls_back_successful_dml_when_later_code_raises(tmp_path: Path):
    """A successful statement must not leak into a later writer's commit."""
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    try:
        try:
            with wm._writing() as conn:
                conn.execute(
                    "INSERT INTO goals(title, description, status, created_at, updated_at) "
                    "VALUES(?, ?, 'pending', ?, ?)",
                    ("stale-from-failed-write", "", 1.0, 1.0),
                )
                raise RuntimeError("boom after successful insert")
        except RuntimeError:
            pass

        wm.create_goal("next-successful-writer", "")
        titles = {g.title for g in wm.list_goals()}
        assert "next-successful-writer" in titles
        assert "stale-from-failed-write" not in titles
    finally:
        wm.close()


def test_rlock_allows_nested_calls(tmp_path: Path):
    """RLock (not Lock) means a method that calls another mutator from
    within its own _writing() block doesn't self-deadlock.

    Most kernel code doesn't nest today, but a future refactor that
    does (e.g. set_goal_status calling append_event) shouldn't hang.
    """
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    try:
        with wm._writing() as conn:
            cur = conn.execute(
                "INSERT INTO goals(title, description, status, created_at, updated_at) "
                "VALUES(?, ?, 'pending', ?, ?)",
                ("outer", "", 1.0, 1.0),
            )
            gid = cur.lastrowid
            # Nested call into a public mutator — would deadlock with plain Lock.
            wm.append_event(gid, "agent", "plan", "nested write ok")

        events = wm.goal_events(gid)
        assert len(events) == 1
        assert events[0].content == "nested write ok"
    finally:
        wm.close()


def test_nested_writing_does_not_commit_outer_transaction_early(tmp_path: Path):
    """Inner mutators must not commit outer writes before outer scope exits."""
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    try:
        with wm._writing() as conn:
            cur = conn.execute(
                "INSERT INTO goals(title, description, status, created_at, updated_at) "
                "VALUES(?, ?, 'pending', ?, ?)",
                ("outer", "", 1.0, 1.0),
            )
            gid = cur.lastrowid
            wm.append_event(gid, "agent", "plan", "nested write ok")

            # While still inside outer _writing(), a separate reader must not
            # observe data yet (i.e., inner call did not commit early).
            reader = WorldModel(db)
            try:
                assert reader.conn.execute("SELECT COUNT(*) FROM goals").fetchone()[0] == 0
                assert reader.conn.execute("SELECT COUNT(*) FROM goal_events").fetchone()[0] == 0
            finally:
                reader.close()
    finally:
        wm.close()
