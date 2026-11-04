"""Per-thread WAL reader connections: concurrent reads run off the write lock,
the writer thread still sees its own uncommitted rows, and :memory: (which is
per-connection) keeps using the shared connection."""
from __future__ import annotations

import threading

from maverick.world_model import WorldModel


def test_reader_used_for_file_db(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    try:
        gid = w.create_goal("t", "d")
        # A plain read (different "thread context" not required) goes via a
        # reader connection, distinct from the write connection.
        assert w._reader() is not None
        assert w._reader() is not w.conn
        assert w.get_goal(gid).id == gid
    finally:
        w.close()


def test_writer_thread_sees_own_uncommitted_rows(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    try:
        gid = w.create_goal("t", "d")
        with w._writing() as c:
            c.execute("UPDATE goals SET status='mid' WHERE id=?", (gid,))
            # Mid-transaction read on the writer thread must see the uncommitted
            # value -> served from the write connection, not a reader snapshot.
            row = w._read_one("SELECT status FROM goals WHERE id=?", (gid,))
            assert row["status"] == "mid"
    finally:
        w.close()


def test_concurrent_reads_during_writes(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    gid = w.create_goal("t", "d")
    errors: list[Exception] = []
    stop = threading.Event()

    def reader():
        try:
            while not stop.is_set():
                w.get_goal(gid)
                w.list_goals(limit=10)
        except Exception as e:  # pragma: no cover - failure path
            errors.append(e)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    try:
        for i in range(200):
            w.append_event(gid, "a", "k", f"event-{i}")
    finally:
        stop.set()
        for t in threads:
            t.join(5)
    assert not errors, errors
    assert len(w.goal_events(gid)) >= 1
    w.close()


def test_close_shuts_reader_connections(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    w.create_goal("t", "d")
    w.list_goals()  # open a reader on this thread
    assert w._reader_conns  # at least one reader registered
    w.close()
    assert w._reader_conns == {}  # drained + closed


def test_short_lived_reader_threads_do_not_leak_connections(tmp_path):
    """A short-lived thread's reader connection must not be retained for the
    WorldModel's entire lifetime: FastAPI/Starlette sync-route and template
    work run on anyio worker threads that exit after being idle, and every
    such thread that ever reads used to permanently leak one sqlite3
    connection (plus its WAL/SHM file descriptors) into _reader_conns, which
    was only ever drained in close(). A long-running dashboard with bursty
    traffic walks toward EMFILE / 'unable to open database file'."""
    w = WorldModel(tmp_path / "w.db")
    try:
        gid = w.create_goal("t", "d")
        for _ in range(50):
            t = threading.Thread(target=lambda: w.get_goal(gid))
            t.start()
            t.join()
        # Each thread has already exited by the time the next one's first
        # _reader() call runs, so pruning should keep the live set to at
        # most the handful of threads genuinely alive at any one instant --
        # nowhere near one entry per thread ever spawned.
        assert len(w._reader_conns) <= 2, w._reader_conns
    finally:
        w.close()
