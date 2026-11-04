"""Control/data-plane soak: prove the dispatch substrate holds under concurrent
load.

``control_data_plane_e2e`` proves one goal runs out-of-process. This drives
*many* goals through the real control plane (``QueueDispatcher`` -> SQLite
``JobQueue``) and a pool of concurrent ``Worker`` loops -- each its own queue and
world connection, standing in for separate worker processes -- and asserts the
substrate's load-bearing guarantees:

* **Zero loss** -- every enqueued goal reaches a terminal ``done``.
* **Atomic claims** -- no goal is claimed, and so executed, twice under
  contention. This is the real contention test: ``JobQueue.claim`` flips ``pending -> running`` with a guarded
  ``UPDATE ... WHERE status='pending'``, so two workers racing the same row
  resolve to one winner. A duplicate here would mean the guard is broken (double
  work, double spend). SCOPE: this is DB-level exactly-once on the CLAIM path
  only. It does NOT exercise the reclaim path, which is at-least-once for side
  effects -- a worker frozen past its lease can have its job reclaimed and re-run
  by a peer, so handlers must be idempotent. See the CAVEAT where the metric is
  computed.
* **Drains clean** -- no job left ``pending``/``running``; no worker raised.

No Redis/gRPC network and no LLM: execution is stubbed at the same boundary as
the e2e harness, so this measures the *plumbing under concurrency*, not the agent
loop. Returns a JSON-able evidence dict (``proof.ok``); ``--ci`` fails the build
if a guarantee breaks; ``--out`` writes the artifact.
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
from pathlib import Path

from .control_data_plane_e2e import _WORKER_KIND
from .queue_dispatcher import JOB_NAME, QueueDispatcher
from .worker import Worker
from .world_model import WorldModel

_DEFAULT_GOALS = 60
_DEFAULT_WORKERS = 4


def run_soak(workdir: Path, *, goals: int = _DEFAULT_GOALS,
             workers: int = _DEFAULT_WORKERS) -> dict:
    """Enqueue ``goals`` goals, drain them with ``workers`` concurrent worker
    loops against the shared stores, and return an evidence dict."""
    workdir = Path(workdir)
    world_db = workdir / "world.db"
    jobs_db = workdir / "jobs.db"

    control_world = WorldModel(path=world_db)
    try:
        goal_ids = [control_world.create_goal(f"soak goal {i}", "harness")
                    for i in range(goals)]

        # --- Control plane: enqueue all, execute none --------------------------
        from .job_queue import JobQueue
        control_queue = JobQueue(db_path=jobs_db)

        def _broker(job_name: str, payload: dict) -> None:
            control_queue.enqueue(
                _WORKER_KIND if job_name == JOB_NAME else job_name, payload)

        dispatcher = QueueDispatcher(enqueue=_broker)
        # JobQueue.list() caps at limit=100; size every count to the fleet so a
        # soak larger than 100 goals isn't silently truncated (this very cap
        # tripped an early version of the harness at 300 goals).
        cap = goals + 1
        t_submit = time.time()
        for gid in goal_ids:
            dispatcher.submit(gid, max_dollars=1.0, channel="soak", user_id="soak")
        enqueued = len(control_queue.list(status="pending", limit=cap))
        pending_after_submit = sum(
            1 for g in goal_ids if control_world.get_goal(g).status == "pending")

        # --- Data plane: a pool of concurrent worker loops ---------------------
        # Execution is stubbed; the counter detects any double-execution (a
        # broken claim guard) under contention.
        exec_counts: dict[int, int] = {}
        counter_lock = threading.Lock()
        worker_errors: list[str] = []

        def _worker_loop() -> None:
            # Own queue + world connection == a separate worker process.
            q = JobQueue(db_path=jobs_db)
            w = WorldModel(path=world_db)
            wk = Worker(queue=q)

            def _execute(job) -> None:
                gid = int(job.payload["goal_id"])
                with counter_lock:
                    exec_counts[gid] = exec_counts.get(gid, 0) + 1
                w.set_goal_status(gid, "done", result="soak")

            wk.register(_WORKER_KIND, _execute)
            try:
                while wk.run_once():  # drain until no ready job remains
                    pass
            except Exception as e:  # a contention/lock failure is a real finding
                worker_errors.append(repr(e))
            finally:
                w.close()

        t_drain = time.time()
        threads = [threading.Thread(target=_worker_loop, name=f"soak-w{i}")
                   for i in range(workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
        drain_seconds = time.time() - t_drain

        # --- Results -----------------------------------------------------------
        done = sum(1 for g in goal_ids if control_world.get_goal(g).status == "done")
        duplicates = {g: c for g, c in exec_counts.items() if c > 1}
        lost = [g for g in goal_ids if control_world.get_goal(g).status != "done"]
        remaining = (len(control_queue.list(status="pending", limit=cap))
                     + len(control_queue.list(status="running", limit=cap)))
        stuck_threads = [t.name for t in threads if t.is_alive()]
    finally:
        control_world.close()

    zero_loss = done == goals and not lost
    # CAVEAT: this proves DB-level exactly-once -- claim() atomically flips
    # pending->running under contention, so no two workers execute the same
    # READY job. It does NOT exercise the reclaim path: a worker frozen (not
    # crashed) past its lease can have its job reclaimed and re-run by a peer,
    # which is at-least-once for side effects (handlers must be idempotent). The
    # soak never freezes a worker mid-job, so this metric does not cover that
    # case -- see worker._reclaim_stale for the reclaim-path caveat.
    exactly_once = not duplicates and sum(exec_counts.values()) == goals
    drained_clean = remaining == 0 and not worker_errors and not stuck_threads
    control_did_not_execute = pending_after_submit == goals and enqueued == goals
    ok = bool(zero_loss and exactly_once and drained_clean and control_did_not_execute)

    return {
        "harness": "control_data_plane_soak",
        "scale": {"goals": goals, "workers": workers},
        "control_plane": {
            "enqueued": enqueued,
            "goals_pending_after_submit": pending_after_submit,
            "at": t_submit,
        },
        "data_plane": {
            "executed_total": sum(exec_counts.values()),
            "done": done,
            "duplicates": len(duplicates),
            "lost": len(lost),
            "queue_remaining": remaining,
            "worker_errors": worker_errors,
            "stuck_threads": stuck_threads,
            "drain_seconds": round(drain_seconds, 3),
        },
        "proof": {
            "control_plane_did_not_execute": control_did_not_execute,
            "zero_loss": zero_loss,
            # Proves claim() atomicity (DB-level exactly-once on the claim path),
            # NOT reclaim-path side-effect idempotency under a worker freeze
            # longer than the lease -- see the CAVEAT where this is computed.
            "exactly_once_under_contention": exactly_once,
            "drained_clean": drained_clean,
            "ok": ok,
        },
        "note": (
            "Real QueueDispatcher + SQLite JobQueue + concurrent Workers + shared "
            "WorldModel; no Redis/gRPC, execution stubbed at the LLM boundary. "
            "Measures dispatch plumbing under concurrency (claim atomicity, "
            "zero-loss, clean drain), not the agent loop."
        ),
    }


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    import os
    p = argparse.ArgumentParser(
        prog="maverick.control_data_plane_soak",
        description="Soak the out-of-process dispatch substrate under "
                    "concurrent load.")
    p.add_argument("--ci", action="store_true",
                   help="exit 1 if a soak guarantee breaks")
    p.add_argument("--goals", type=int, default=_DEFAULT_GOALS)
    p.add_argument("--workers", type=int, default=_DEFAULT_WORKERS)
    p.add_argument("--out", default=None, help="write the evidence JSON to PATH")
    args = p.parse_args(argv)

    os.environ.setdefault("MAVERICK_ENCRYPT_AT_REST", "0")  # no crypto extra needed
    with tempfile.TemporaryDirectory() as d:
        evidence = run_soak(Path(d), goals=args.goals, workers=args.workers)
    text = json.dumps(evidence, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    if args.ci and not evidence["proof"]["ok"]:
        return 1
    return 0


__all__ = ["run_soak", "main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
