"""Reading the blackboard from a worker thread must not race post().

Concurrency finding: orchestrator._donate runs on a worker thread
(asyncio.to_thread) and read blackboard.entries directly -- a lock-free
iteration racing the event loop's post() append/trim. Concurrent
iterate-vs-append on a plain list raises "list changed size during
iteration", which _donate's blanket except swallowed (silently lost
trajectory donations). by_kind() snapshots under the lock; this pins that
the locked accessors are safe under concurrent posting.
"""
from __future__ import annotations

import threading

from maverick.blackboard import Blackboard


def test_by_kind_is_safe_under_concurrent_post():
    bb = Blackboard()
    stop = threading.Event()
    errors: list[Exception] = []

    def hammer_post():
        i = 0
        while not stop.is_set():
            try:
                bb.post(f"w{i}", "observation", f"finding {i}")
            except Exception as e:  # pragma: no cover
                errors.append(e)
            i += 1

    writer = threading.Thread(target=hammer_post, daemon=True)
    writer.start()
    try:
        # Mirror _donate's read pattern many times while posts stream in.
        for _ in range(3000):
            _ = sorted({e.kind for e in bb.by_kind("observation")})
    finally:
        stop.set()
        writer.join(timeout=5)
    assert not errors, errors
