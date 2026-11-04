"""Control/data-plane end-to-end harness + evidence artifact (regulated-SaaS
data-plane split).

The dispatcher seam lets the control plane (the API/dashboard that *accepts* a
goal) hand execution to a separate data plane (a worker process that *runs* it),
so a tenant's runaway goal can't degrade the request path. The unit tests cover
each piece in isolation; this is the missing *end-to-end* proof that the pieces
compose: a goal submitted through the real ``QueueDispatcher`` is executed by a
separate ``Worker`` against the *shared* stores, never on the control path, and
its terminal status flows back through the shared world DB.

It runs the **real** components — ``QueueDispatcher`` (control plane), the SQLite
``JobQueue`` (broker), ``Worker`` (data plane), and two ``WorldModel`` handles on
one shared DB file (standing in for two processes) — with no Redis/gRPC network.
Only the agent execution itself is stubbed at the LLM boundary: the worker's
handler marks the goal done in the shared world instead of driving a real swarm,
because what we're proving is the *plumbing*, not the agent loop.

``run_e2e`` returns a JSON-serializable evidence dict whose ``proof.ok`` is the
single assertion. ``python -m maverick.control_data_plane_e2e --ci`` runs it in a
temp dir and exits non-zero if the split does not hold; ``--out PATH`` writes the
artifact.
"""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

# The dispatcher's job name (arq function) vs the SQLite worker's handler kind.
# In production arq routes the function to a remote worker; here the broker
# bridge below delivers it to the JobQueue the local Worker polls, so the two
# real substrates compose.
from .queue_dispatcher import JOB_NAME, QUEUED_STATUS, QueueDispatcher
from .worker import Worker
from .world_model import WorldModel

_WORKER_KIND = "run_goal"


def _stub_execute(world_db: Path, goal_id: int) -> None:
    """Stand-in for the agent run: open a SEPARATE world handle (as a worker
    process would) and mark the goal done in the shared store. Proves the worker
    mutates the same world the control plane reads, without invoking an LLM."""
    w = WorldModel(path=world_db)
    try:
        w.set_goal_status(goal_id, "done", result="executed by data-plane worker")
    finally:
        w.close()


def run_e2e(workdir: Path, *, execute=None) -> dict:
    """Drive the full submit -> enqueue -> claim -> execute -> readback path and
    return an evidence dict. ``execute(world_db, goal_id)`` overrides the stubbed
    worker execution (default marks the goal done)."""
    workdir = Path(workdir)
    world_db = workdir / "world.db"
    jobs_db = workdir / "jobs.db"
    execute = execute or _stub_execute

    # Shared world (the control plane's handle). try/finally so an exception
    # anywhere in the harness still closes the SQLite connection instead of
    # leaking it (and masking the real error behind a temp-dir cleanup failure).
    world = WorldModel(path=world_db)
    try:
        goal_id = world.create_goal("e2e: prove control/data-plane split", "harness")
        status_initial = world.get_goal(goal_id).status

        # --- Control plane: submit through the real QueueDispatcher ----------
        # The broker bridge represents "the broker hands the job to a worker":
        # in prod it's arq->Redis; here it writes to the SQLite JobQueue the
        # Worker polls, mapping the dispatcher's job name to the handler kind.
        from .job_queue import JobQueue
        queue = JobQueue(db_path=jobs_db)

        def _broker(job_name: str, payload: dict) -> None:
            queue.enqueue(_WORKER_KIND if job_name == JOB_NAME else job_name, payload)

        dispatcher = QueueDispatcher(enqueue=_broker)
        t_submit = time.time()
        submit_returned = dispatcher.submit(
            goal_id, max_dollars=1.0, channel="harness", user_id="e2e")
        pending = queue.list(status="pending")
        status_after_enqueue = world.get_goal(goal_id).status

        # --- Data plane: a separate Worker claims and executes --------------
        worker = Worker(queue=queue)
        worker.register(_WORKER_KIND, lambda job: execute(world_db, int(job.payload["goal_id"])))
        t_claim = time.time()
        claimed = worker.run_once()
        done_jobs = queue.list(status="done")
        status_after_run = world.get_goal(goal_id).status
    finally:
        # ``get_goal`` opens a per-thread reader in addition to the writer.
        # Close the full WorldModel, not only ``conn``, so Windows can remove
        # the evidence harness's temporary database after the proof finishes.
        world.close()

    # --- Proof ---------------------------------------------------------------
    control_did_not_execute = status_after_enqueue == status_initial == "pending"
    worker_claimed = bool(claimed) and len(done_jobs) == 1
    status_flowed_back = status_after_run == "done"
    enqueued_one = submit_returned == QUEUED_STATUS and len(pending) == 1
    ok = bool(control_did_not_execute and worker_claimed and status_flowed_back
              and enqueued_one)

    return {
        "harness": "control_data_plane_e2e",
        "goal_id": goal_id,
        "shared_stores": {"world_db": world_db.name, "job_queue_db": jobs_db.name},
        "control_plane": {
            "dispatcher": "QueueDispatcher",
            "submit_returned": submit_returned,
            "pending_jobs_after_submit": len(pending),
            "job_kind": pending[0].kind if pending else None,
            "goal_status_after_enqueue": status_after_enqueue,
            "at": t_submit,
        },
        "data_plane": {
            "worker": "Worker",
            "claimed": bool(claimed),
            "done_jobs": len(done_jobs),
            "goal_status_after_run": status_after_run,
            "at": t_claim,
        },
        "proof": {
            "enqueued_exactly_one_job": enqueued_one,
            "control_plane_did_not_execute": control_did_not_execute,
            "worker_claimed_and_completed_out_of_band": worker_claimed,
            "status_flowed_through_shared_world": status_flowed_back,
            "ok": ok,
        },
        "note": (
            "Real QueueDispatcher + SQLite JobQueue + Worker + shared WorldModel; "
            "no Redis/gRPC network. Agent execution is stubbed at the LLM "
            "boundary — this proves the dispatch plumbing, not the agent loop."
        ),
    }


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    import os
    p = argparse.ArgumentParser(
        prog="maverick.control_data_plane_e2e",
        description="End-to-end proof that goals run out-of-process "
                    "(control plane enqueues, data plane executes).")
    p.add_argument("--ci", action="store_true",
                   help="exit 1 if the control/data-plane split does not hold")
    p.add_argument("--out", default=None, help="write the evidence JSON to PATH")
    args = p.parse_args(argv)

    # The harness proves the dispatch plumbing, which is orthogonal to at-rest
    # sealing — so as a standalone gate it must not require the optional
    # 'cryptography' extra (the lint CI job runs without it). Default at-rest off
    # for this run unless the operator explicitly set it.
    os.environ.setdefault("MAVERICK_ENCRYPT_AT_REST", "0")

    with tempfile.TemporaryDirectory() as d:
        evidence = run_e2e(Path(d))
    text = json.dumps(evidence, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    if args.ci and not evidence["proof"]["ok"]:
        return 1
    return 0


__all__ = ["run_e2e", "main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
