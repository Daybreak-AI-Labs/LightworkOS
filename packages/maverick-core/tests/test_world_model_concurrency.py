"""WorldModel shares one sqlite connection across threads (serve runs many
goal threads). Reads must serialise against the _writing() critical section
on the same RLock, or a read can observe a writer's uncommitted (and
possibly rolled-back) transaction on that connection.
"""
from __future__ import annotations

import threading
import time


def test_read_within_write_does_not_deadlock(tmp_path):
    """A read issued while this thread holds the write lock must return
    (RLock is reentrant), not self-deadlock."""
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    gid = w.create_goal("g")
    with w._writing() as conn:
        conn.execute("UPDATE goals SET title = 'x' WHERE id = ?", (gid,))
        got = w.get_goal(gid)          # read nested inside the open write txn
    assert got is not None
    w.close()


def test_reads_dont_observe_uncommitted_writes(tmp_path):
    """A single read (get_facts -> one SELECT) must never see a writer's
    half-applied multi-statement transaction on the shared connection.

    The writer keeps two facts equal, updating both inside one _writing()
    block; a reader that ran mid-transaction on the same connection (the
    bug) would see them differ. With reads holding the same lock, it can't.
    """
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    w.upsert_fact("a", "0")
    w.upsert_fact("b", "0")

    torn: list[tuple] = []
    stop = threading.Event()

    def writer():
        i = 1
        while not stop.is_set():
            with w._writing() as conn:
                conn.execute("UPDATE facts SET value = ? WHERE key = 'a'", (str(i),))
                conn.execute("UPDATE facts SET value = ? WHERE key = 'b'", (str(i),))
            i += 1

    def reader():
        while not stop.is_set():
            f = w.get_facts()
            if f.get("a") != f.get("b"):
                torn.append((f.get("a"), f.get("b")))

    threads = [
        threading.Thread(target=writer),
        threading.Thread(target=reader),
        threading.Thread(target=reader),
    ]
    for t in threads:
        t.start()
    time.sleep(0.4)
    stop.set()
    for t in threads:
        t.join(timeout=5)
    w.close()

    assert not torn, f"reader saw {len(torn)} torn (uncommitted) states, e.g. {torn[:3]}"


def test_many_threads_read_and_write_without_error(tmp_path):
    """Concurrent reads + writes on one shared WorldModel don't raise."""
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    conv = w.get_or_create_conversation("tg", "u1")
    errors: list[tuple] = []
    stop = threading.Event()

    def writer():
        i = 0
        while not stop.is_set():
            try:
                w.append_turn(conv.id, "user", f"m{i}")
                w.upsert_fact(f"k{i % 4}", f"v{i}")
                i += 1
            except Exception as e:  # noqa: BLE001 - record + surface
                errors.append(("writer", repr(e)))
                return

    def reader():
        while not stop.is_set():
            try:
                w.recent_turns(conv.id, limit=10)
                w.get_facts()
                w.list_conversations("tg")
            except Exception as e:  # noqa: BLE001
                errors.append(("reader", repr(e)))
                return

    threads = [threading.Thread(target=writer) for _ in range(2)]
    threads += [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    time.sleep(0.4)
    stop.set()
    for t in threads:
        t.join(timeout=5)
    w.close()

    assert not errors, errors
