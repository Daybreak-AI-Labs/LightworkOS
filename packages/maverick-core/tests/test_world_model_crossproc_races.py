"""Cross-process write races on the shared SQLite world.db.

Two WorldModel instances on the same file = two connections + two independent
in-process write locks, which is exactly the dashboard + worker sharing
~/.maverick/world.db. The in-process RLock can't serialize across them, so these
exercise the SQLite-level serialization the artifact-version fix relies on:
computing the next version inside the INSERT (one atomic statement) instead of a
separate SELECT MAX(version)+1 that races across processes.
"""
from __future__ import annotations

import threading

from maverick.world_model import WorldModel


def test_add_artifact_no_cross_process_version_duplicate(tmp_path):
    db = tmp_path / "w.db"
    w0 = WorldModel(db)
    gid = w0.create_goal("g")
    n = 8
    workers = [WorldModel(db) for _ in range(n)]
    barrier = threading.Barrier(n)
    errs: list[str] = []

    def go(w):
        try:
            barrier.wait()  # maximize overlap on the read-modify-write
            w.add_artifact(gid, "text", "report", "body")
        except Exception as e:  # noqa: BLE001
            errs.append(repr(e))

    threads = [threading.Thread(target=go, args=(w,)) for w in workers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errs == [], errs
    versions = sorted(a["version"] for a in w0.artifacts_for_goal(gid)
                      if a["title"] == "report")
    assert versions == list(range(1, n + 1)), versions  # distinct + gapless
    for w in workers:
        w.close()
    w0.close()
