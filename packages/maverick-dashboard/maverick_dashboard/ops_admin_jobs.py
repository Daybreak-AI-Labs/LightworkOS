"""Small background-job registry for long installation operations.

Settings > Maintenance and the Workspaces page start a few operations that can
take minutes (preparing connection components, assigning older records to a
workspace, re-protecting workspace keys). Each runs on its own thread so the
request returns at once; the page polls :func:`get` for a plain status.

At most one job of a kind runs at a time, the registry keeps only the most
recent jobs, and a job's stored result is whatever plain summary the caller
returns -- never secrets, which stay in the closure of the running thread.
"""
from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from typing import Any

MAX_JOBS = 50
_LOCK = threading.Lock()
_JOBS: dict[str, dict[str, Any]] = {}
_threads: list[threading.Thread] = []


class JobBusy(RuntimeError):
    """A job of the same kind is already running."""


def _prune() -> None:
    finished = [job for job in _JOBS.values() if job["state"] != "running"]
    finished.sort(key=lambda job: job["started_at"])
    while len(_JOBS) > MAX_JOBS and finished:
        _JOBS.pop(finished.pop(0)["id"], None)
    _threads[:] = [thread for thread in _threads if thread.is_alive()]


def start(kind: str, work: Callable[[], dict[str, Any]], *, failure: Callable[[BaseException], str],
          on_finish: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
    """Run ``work`` on a new thread and return the job record.

    ``work`` returns a plain result dict. ``failure`` turns an exception into
    the sentence the page shows (the exception text itself is never stored).
    ``on_finish`` receives the final record (used for the activity record).
    """
    with _LOCK:
        if any(job["kind"] == kind and job["state"] == "running" for job in _JOBS.values()):
            raise JobBusy(kind)
        job = {"id": secrets.token_hex(8), "kind": kind, "state": "running",
               "started_at": time.time(), "finished_at": None, "result": None, "error": ""}
        _JOBS[job["id"]] = job
        _prune()

    def run() -> None:
        try:
            result = work()
            outcome = {"state": "done", "result": result}
        except BaseException as exc:  # noqa: BLE001 -- every failure becomes a plain status
            outcome = {"state": "failed", "error": failure(exc)}
        outcome["finished_at"] = time.time()
        # The activity record is written before the page can see the job as
        # finished, so "done" always has its record behind it.
        if on_finish is not None:
            with _LOCK:
                final = {**job, **outcome}
            try:
                on_finish(final)
            except Exception:  # noqa: BLE001 -- the job's own status stays authoritative
                outcome["record_warning"] = True
        with _LOCK:
            job.update(outcome)

    thread = threading.Thread(target=run, name=f"lightwork-ops-{kind}", daemon=True)
    with _LOCK:
        _threads.append(thread)
    thread.start()
    return dict(job)


def get(job_id: str) -> dict[str, Any] | None:
    with _LOCK:
        job = _JOBS.get(job_id)
        return dict(job) if job is not None else None


def latest(kind: str) -> dict[str, Any] | None:
    with _LOCK:
        jobs = [job for job in _JOBS.values() if job["kind"] == kind]
        return dict(max(jobs, key=lambda job: job["started_at"])) if jobs else None


def wait(job_id: str, timeout: float = 10.0) -> dict[str, Any] | None:
    """Block until the job finishes or ``timeout`` passes (tests and shutdown)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = get(job_id)
        if job is None or job["state"] != "running":
            return job
        time.sleep(0.01)
    return get(job_id)


def public(job: dict[str, Any] | None) -> dict[str, Any] | None:
    """The job as the page sees it."""
    if job is None:
        return None
    return {key: job.get(key) for key in ("id", "kind", "state", "started_at", "finished_at",
                                          "result", "error", "record_warning")}


__all__ = ["JobBusy", "start", "get", "latest", "wait", "public", "MAX_JOBS"]
