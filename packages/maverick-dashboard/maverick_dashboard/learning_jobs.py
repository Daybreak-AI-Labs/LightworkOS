"""Background jobs for the learning, training and workforce buttons.

A button that runs a learning pass, trains a model or checks every
specialist must not hold the request open, so the route starts a job here
and the page polls its status. Encrypted, bounded observations survive restart;
only this process's live job has a controllable worker. Reading an observation
never resumes it. Each thread retains the request's workspace and identity.

Stopping is cooperative. A job that can stop early says how: ``on_cancel``
tightens its own spending limit (so the kernel's next ``budget.check()``
ends it) and the job's function checks ``job.cancelled`` between steps. A
job with no safe stopping point cannot be stopped, and the page offers no
button for it. Only one job of a kind runs at a time, and at most a few run
at once, so a button pressed twice never doubles the spend.
"""
from __future__ import annotations

import contextvars
import copy
import json
import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import learning_job_observations as retained

log = logging.getLogger(__name__)

MAX_RUNNING = 3
_MAX_KEPT = 40
_FAILED = "This task stopped because of a problem. Work completed before the failure may remain. Read its current result before deciding what to do next; do not repeat it automatically."


class JobRefused(Exception):
    """A job could not start; the message is written for people."""


@dataclass
class Job:
    id: str
    kind: str
    label: str
    started_by: str
    workspace: str
    needs_global: bool
    cancellable: bool
    started_at: float = field(default_factory=time.time)
    state: str = "admitted"  # admitted | running | stopping | done | failed | stopped | not_started
    finished_at: float | None = None
    result: dict | None = None
    problem: str = ""
    on_cancel: Callable[[], None] | None = None
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)
    _stop_receipt: dict | None = field(default=None, repr=False)
    _stop_receipts: dict = field(default_factory=dict, repr=False)
    _live: bool = field(default=True, repr=False)
    _custody: Any = field(default=None, repr=False)
    _durable: bool = field(default=False, repr=False)
    _recorded_at: float | None = field(default=None, repr=False)
    _result_retained: bool = field(default=True, repr=False)
    _retention_problem: str = field(default="", repr=False)

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    @property
    def active(self) -> bool:
        return self.state in ("admitted", "running", "stopping")

    def view(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "label": self.label,
                "state": self.state, "started_at": self.started_at,
                "finished_at": self.finished_at, "can_stop": self._live and self.cancellable and self.state == "running",
                "result": self.result, "problem": self.problem,
                "worker_available": self._live and self.active,
                "observation_saved": self._durable, "recorded_at": self._recorded_at,
                "result_retained": self._result_retained, "retention_problem": self._retention_problem}


_jobs: dict[str, Job] = {}
_lock = threading.Lock()
_worker_lock = threading.Lock()
_workers: list[tuple[threading.Thread, Job]] = []
_accepting = True
_admission_generation = 0


def workers_alive() -> bool:
    with _worker_lock:
        return any(thread.is_alive() for thread, _job in _workers)


def open_admission() -> None:
    """Reopen a restarted dashboard only after its prior workers exited."""
    global _accepting, _admission_generation
    with _worker_lock:
        if any(thread.is_alive() for thread, _job in _workers):
            raise RuntimeError("prior learning workers are still stopping; restart refused")
        _workers.clear()
        _accepting = True
        _admission_generation += 1


def stop(*, timeout: float = 5.0, wait: bool = True) -> None:
    """Close admission, request existing safe stops and drain one deadline.

    No observation is changed to finished by shutdown. Workers keep custody
    and write their own outcomes; an unfinished original remains unfinished.
    Existing stop hooks only signal safe points or tighten their own Budget.
    """
    global _accepting, _admission_generation
    deadline = time.monotonic() + max(0.0, min(float(timeout), 30.0))
    hooks = []
    with _worker_lock:
        if _accepting:
            _admission_generation += 1
        _accepting = False
        workers = list(_workers)
        for thread, job in workers:
            if thread.is_alive() and job.active and job.cancellable and not job.cancelled:
                job._cancel.set()
                if job.on_cancel is not None:
                    hooks.append((job.id, job.on_cancel))
    for job_id, hook in hooks:
        try:
            hook()
        except Exception:  # noqa: BLE001 -- a stop request cannot erase its original
            log.warning("learning task %s shutdown stop hook failed", job_id, exc_info=True)
    if wait:
        for thread, _job in workers:
            if thread is not threading.current_thread():
                thread.join(timeout=max(0.0, deadline - time.monotonic()))


def _prune() -> None:
    finished = sorted((j for j in _jobs.values() if not j.active), key=lambda j: j.started_at)
    while len(_jobs) > _MAX_KEPT and finished:
        _jobs.pop(finished.pop(0).id, None)


def _observation(job):
    return {"id": job.id, "kind": job.kind, "label": job.label,
            "started_by": job.started_by, "workspace": job.workspace,
            "needs_global": job.needs_global, "cancellable": job.cancellable,
            "started_at": job.started_at, "state": job.state, "finished_at": job.finished_at,
            "result": job.result, "problem": job.problem, "stop_receipt": job._stop_receipt, "stop_receipts": job._stop_receipts,
            "recorded_at": job._recorded_at, "result_retained": job._result_retained,
            "retention_problem": job._retention_problem}


def _persist(job, action, *, admit=False):
    previous_recorded = job._recorded_at
    job._recorded_at = time.time()
    if job._result_retained:
        job._retention_problem = ""
    value = _observation(job)
    try:
        if len(json.dumps(value, allow_nan=False).encode("utf-8")) > retained.MAX_RESULT_BYTES:
            raise ValueError("result bound")
    except (TypeError, ValueError):
        if job.active:
            raise JobRefused("This task's observation could not be retained safely. Read its last saved progress; do not repeat the work or stop request automatically.") from None
        job._result_retained = False
        job._retention_problem = "The task finished, but its detailed result could not be retained in recent tasks. Read its underlying learning records; do not repeat it automatically."
        value = _observation(job)
        value["result"] = None
    try:
        retained.write(value, action=action, actor=job.started_by, admit=admit)
    except retained.ObservationUnavailable as exc:
        job._durable = False
        job._recorded_at = previous_recorded
        job._retention_problem = str(exc)
        raise JobRefused(str(exc)) from exc
    job._durable = True


def _restore(value):
    try:
        import math
        import re
        if (not isinstance(value.get("id"), str) or not re.fullmatch(r"[a-f0-9]{16}", value["id"])
                or any(not isinstance(value.get(key), str) for key in ("kind", "label", "started_by", "workspace", "problem", "retention_problem"))
                or any(type(value.get(key)) is not bool for key in ("needs_global", "cancellable", "result_retained"))
                or any(type(value.get(key)) not in {int, float} or not math.isfinite(value[key]) or value[key] < 0
                       for key in ("started_at", "recorded_at"))
                or value.get("finished_at") is not None and (type(value["finished_at"]) not in {int, float}
                       or not math.isfinite(value["finished_at"]) or value["finished_at"] < 0)
                or value.get("result") is not None and not isinstance(value["result"], dict)
                or value.get("stop_receipt") is not None and not isinstance(value["stop_receipt"], dict)):
            raise ValueError
        if value["state"] not in {"admitted", "running", "stopping", "done", "stopped", "failed", "not_started"}:
            raise ValueError
        job = Job(**{key: value[key] for key in ("id", "kind", "label", "started_by", "workspace", "needs_global",
                                                "cancellable", "started_at", "state", "finished_at", "result", "problem")}, _live=False)
        job._stop_receipt = value["stop_receipt"]
        job._stop_receipts = value.get("stop_receipts", {})
        if not isinstance(job._stop_receipts, dict) or len(job._stop_receipts) > 40:
            raise ValueError
        job._recorded_at = value["recorded_at"]
        job._result_retained = value["result_retained"]
        job._retention_problem = value["retention_problem"]
        job._durable = True
        return job
    except (KeyError, TypeError, ValueError) as exc:
        raise JobRefused("The retained task cannot be verified. No work was repeated.") from exc


def _run(job: Job, fn: Callable[[Job], dict], problem: Callable[[Exception], str | None]) -> None:
    try:
        with _lock:
            job._custody.assert_owned()
            job.state = "running"
            _persist(job, "worker_started")
    except Exception:
        with _lock:
            job.state = "not_started"
            job.problem = "This server did not start the work because its admission record could not be confirmed. Read the last recorded progress before making a new decision."
            job._durable = False
        job._custody.release()
        return
    try:
        result = fn(job)
    except Exception as exc:  # noqa: BLE001 -- every failure becomes one plain sentence
        text = None
        try:
            text = problem(exc)
        except Exception:  # noqa: BLE001 -- the mapper must never hide the failure
            text = None
        if text is None:
            log.warning("dashboard job %s (%s) failed", job.id, job.kind, exc_info=True)
        with _lock:
            job.problem = text or _FAILED
            job.state = "failed"
            job.finished_at = time.time()
    else:
        with _lock:
            job.result = result if isinstance(result, dict) else {}
            job.state = "stopped" if job.cancelled else "done"
            job.finished_at = time.time()
    try:
        with _lock:
            _persist(job, "worker_observed")
    except JobRefused:
        log.warning("learning task %s final observation is unconfirmed", job.id)
    finally:
        job._custody.release()


def start(kind: str, label: str, fn: Callable[[Job], dict], *, started_by: str,
          workspace: str = "", needs_global: bool = True, cancellable: bool = False,
          on_cancel: Callable[[], None] | None = None,
          requested_id: str | None = None, initial_result: dict | None = None,
          problem: Callable[[Exception], str | None] = lambda exc: None) -> Job:
    """Start ``fn(job)`` in a thread and return the job.

    ``problem`` turns an exception into a sentence for people (``None`` keeps
    the generic one and logs the failure). Raises :class:`JobRefused` when the
    same kind is already running or too many jobs are running."""
    with _worker_lock:
        if not _accepting:
            raise JobRefused("This server is stopping. No new work was started. Read the original task's recorded progress.")
        generation = _admission_generation
    with _lock:
        running = [j for j in _jobs.values() if j.active]
        if any(j.kind == kind for j in running):
            raise JobRefused("This is already running. Wait for it to finish, or stop it first.")
        if len(running) >= MAX_RUNNING:
            raise JobRefused("Too many jobs are running right now. Try again when one finishes.")
        if requested_id is not None:
            import re
            if not re.fullmatch(r"[a-f0-9]{16}", requested_id):
                raise JobRefused("This original task reference is invalid. No work was started.")
        job = Job(id=requested_id or uuid.uuid4().hex[:16], kind=kind, label=label, started_by=started_by,
                  workspace=workspace, needs_global=needs_global, cancellable=cancellable,
                  on_cancel=on_cancel, result=copy.deepcopy(initial_result))
        try:
            job._custody = retained.acquire(kind, job.id)
            if requested_id is not None and (job.id in retained.read() or job.id in _jobs):
                raise JobRefused("This original task is already recorded. Read it; no work was repeated.")
            _persist(job, "worker_admitted", admit=True)
        except (JobRefused, retained.ObservationUnavailable) as exc:
            if job._custody is not None:
                job._custody.release()
            raise JobRefused(str(exc)) from exc
        except Exception as exc:
            if job._custody is not None:
                job._custody.release()
            raise JobRefused("This task's worker custody or protected admission is unavailable. Nothing was started.") from exc
        _jobs[job.id] = job
        _prune()
    ctx = contextvars.copy_context()
    from ._request_memo import discard_request_memo
    ctx.run(discard_request_memo)
    try:
        thread = threading.Thread(target=ctx.run, args=(_run, job, fn, problem), daemon=True,
                                  name=f"lightwork-job-{kind}")
        with _worker_lock:
            # Observation writes may have waited. The physical launch and
            # shutdown signal share this short lock, with no storage I/O.
            if not _accepting or generation != _admission_generation:
                raise JobRefused("This server stopped accepting work before the worker started.")
            _workers[:] = [(item, owner) for item, owner in _workers if item.is_alive()]
            _workers.append((thread, job))
            thread.start()
    except Exception as exc:
        with _lock:
            job.state = "not_started"
            job.problem = "The worker did not start. Nothing was repeated automatically."
            try:
                _persist(job, "worker_not_started")
            finally:
                job._custody.release()
        raise JobRefused("The worker did not start. Read the recorded task before deciding whether to try again.") from exc
    return job


def get(job_id: str) -> Job | None:
    try:
        observations = retained.read()
    except retained.ObservationUnavailable as exc:
        raise JobRefused(str(exc)) from exc
    with _lock:
        live = _jobs.get(job_id)
        return live if live is not None else _restore(observations[job_id]) if job_id in observations else None


def listed() -> list[Job]:
    try:
        observations = retained.read()
    except retained.ObservationUnavailable as exc:
        raise JobRefused(str(exc)) from exc
    with _lock:
        rows = {key: _restore(value) for key, value in observations.items()}
        rows.update(_jobs)
        return sorted(rows.values(), key=lambda j: j.started_at, reverse=True)[:_MAX_KEPT]


def _live_signature():
    from maverick.governed_operations import digest
    return digest({key: value.view() for key, value in _jobs.items()})


def history_snapshot():
    """One bounded native read, copied under the live-worker lock."""
    try:
        observations, version = retained.snapshot()
    except retained.ObservationUnavailable as exc:
        raise JobRefused(str(exc)) from exc
    with _lock:
        rows = {key: _restore(value) for key, value in observations.items()}
        rows.update(_jobs)
        entries = []
        for job in sorted(rows.values(), key=lambda row: row.started_at, reverse=True)[:_MAX_KEPT]:
            entries.append({"source": job, "job": copy.deepcopy(job.view()), "revision": _revision(job),
                            "stop_receipt": copy.deepcopy(observations.get(job.id, {}).get("stop_receipt"))})
        return {"entries": entries, "version": version, "live_version": _live_signature()}


def history_unchanged(snapshot):
    try:
        if not retained.unchanged(snapshot["version"]):
            return False
    except retained.ObservationUnavailable as exc:
        raise JobRefused(str(exc)) from exc
    with _lock:
        return _live_signature() == snapshot["live_version"]


def current_view(job: Job) -> dict:
    """A coherent retained view; private result values never escape by reference."""
    with _lock:
        if job._live and _jobs.get(job.id) is not job:
            raise JobRefused("The original live result is no longer available. Its absence does not mean the work failed; do not repeat it automatically.")
        return copy.deepcopy(job.view())


def _revision(job: Job) -> str:
    from maverick.governed_operations import digest

    return digest(job.view())


def reviewed_view(job: Job) -> dict:
    with _lock:
        if job._live and _jobs.get(job.id) is not job:
            raise JobRefused("The original result is no longer available. No work was repeated.")
        return {"job": copy.deepcopy(job.view()), "revision": _revision(job)}


def stop_receipt(job: Job, operation: str | None, actor: str, context: str) -> dict | None:
    try:
        value = retained.read().get(job.id)
        row = (value.get("stop_receipts", {}).get(operation) if operation is not None else value.get("stop_receipt")) if value else None
        if row is None or (row["actor"], row["context"]) != (actor, context) or operation is not None and row["operation"] != operation:
            return None
        return copy.deepcopy(row)
    except retained.ObservationUnavailable as exc:
        raise JobRefused(str(exc)) from exc


def cancel_reviewed(job: Job, revision: str, operation: str, actor: str, context: str,
                    before_stop: Callable[[], None]) -> dict:
    """Bind one reviewed stop to its original actor inside the native job lock."""
    persistence_error = None
    with _lock:
        if not job._live or _jobs.get(job.id) is not job:
            raise JobRefused("The active worker is unavailable on this server. Its recorded progress does not prove it finished or failed. No stop or work was repeated.")
        row = job._stop_receipts.get(operation)
        if row is not None and (row["operation"], row["actor"], row["context"]) == (operation, actor, context):
            try:
                saved = retained.read().get(job.id, {}).get("stop_receipts", {}).get(operation)
            except retained.ObservationUnavailable as exc:
                raise JobRefused(str(exc)) from exc
            if saved is None or (saved.get("actor"), saved.get("context"), saved.get("operation")) != (actor, context, operation):
                raise JobRefused("The original stop observation is unconfirmed. Read its original outcome; no stop or work was repeated.")
            return copy.deepcopy(saved)
        if _revision(job) != revision or job.state != "running" or not job.cancellable or job.cancelled:
            raise JobRefused("This task changed or can no longer stop part-way. Read its current progress and review again. Nothing was stopped by this request.")
        if len(job._stop_receipts) >= 40:
            raise JobRefused("This task has reached its retained stop-review limit. Check the original requests and current progress; no stop was repeated.")
        before_stop()
        row = {"operation": operation, "actor": actor, "context": context,
               "job": job.id, "revision": revision, "requested_at": time.time(), "phase": "intent"}
        job._stop_receipt = row
        job._stop_receipts[operation] = row
        _persist(job, "stop_intent")
        job._custody.assert_owned()
        job._cancel.set()
        job.state = "stopping"
        row["phase"] = "requested"
        try:
            _persist(job, "stop_requested")
        except JobRefused as exc:
            persistence_error = exc
        hook = job.on_cancel
    if hook is not None:
        try:
            hook()
        except Exception:  # noqa: BLE001 -- the native safe-point stop flag is retained
            log.debug("job %s stop hook failed", job.id, exc_info=True)
    if persistence_error is not None:
        raise persistence_error
    return copy.deepcopy(row)


def cancel(job: Job) -> bool:
    """Ask a job to stop at its next safe point. False when it cannot stop."""
    with _lock:
        if _jobs.get(job.id) is not job or not (job._live and job.cancellable and job.active):
            return False
        job._cancel.set()
        job.state = "stopping"
        try:
            _persist(job, "legacy_stop_requested")
        except JobRefused:
            log.warning("task %s legacy stop observation is unconfirmed", job.id)
        hook = job.on_cancel
    if hook is not None:
        try:
            hook()
        except Exception:  # noqa: BLE001 -- the stop flag is already set
            log.debug("job %s stop hook failed", job.id, exc_info=True)
    return True


def stop_budget(budget) -> Callable[[], None]:
    """An ``on_cancel`` that ends a kernel run at its next ``budget.check()``:
    it lowers the run's own wall-clock limit to the time already used. It
    only ever tightens the limit, so no spending guard is loosened."""
    def _stop() -> None:
        used = max(0.0, float(budget.elapsed()))
        current = budget.max_wall_seconds
        if current is None or current > used:
            budget.max_wall_seconds = used
    return _stop


def clear_for_tests() -> None:
    with _lock:
        _jobs.clear()


__all__ = ["Job", "JobRefused", "MAX_RUNNING", "cancel", "clear_for_tests", "get",
           "listed", "open_admission", "start", "stop", "stop_budget", "workers_alive"]
