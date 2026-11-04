"""Background thread for deadline alerts and webhook retries.

One daemon thread, started with the dashboard, does two jobs:

* every ``[deadline_alerts] poll_seconds`` (default 15 minutes) it runs
  :func:`maverick.deadline_alerts.run_cycle` for each active workspace, which
  alerts people about requests, incidents, assessments, vendor contracts and
  approvals that are due -- once per record and state, recorded in the ledger;
* every ``_RETRY_PUMP_SECONDS`` it runs
  :func:`maverick.webhook_subscriptions.process_due`, so a webhook delivery
  whose receiver was down is retried on its backoff schedule even when no new
  event arrives;
* every hour it re-checks each active workspace's compliance protections
  (:func:`maverick.compliance_history.recheck_if_due`), so a protection that
  breaks shows as failing within the hour, with when it changed;
* every hour it removes public website chat transcripts past their site's
  retention (:func:`public_chat_store.purge_expired_if_due`), in every
  workspace, so an install with no visits or admin views still purges.

The retry pump runs whenever the thread runs; the deadline evaluation only
when alerts are enabled. Both are wrapped so one bad cycle is logged and the
next one still happens. Stopped through the dashboard's shutdown supervisor
(see ``_lifecycle.register_main_components``).
"""
from __future__ import annotations

import logging
import threading
import time

log = logging.getLogger(__name__)

_scheduler_lock = threading.Lock()
_scheduler_stop: threading.Event | None = None
_scheduler_thread: threading.Thread | None = None
_RETRY_PUMP_SECONDS = 30.0
_last_cycle: dict[str, dict] = {}  # per workspace; one workspace never sees another's


def _world():
    from ._shared import _world as shared_world
    return shared_world()


def _workspace() -> str:
    from maverick.webhook_subscriptions import workspace_id
    return workspace_id()


def run_once(*, now: float | None = None) -> dict:
    """One evaluation cycle plus one retry pump for the active workspace (the
    API's "run now")."""
    from maverick import deadline_alerts, webhook_subscriptions

    world = _world()
    summary = deadline_alerts.run_cycle(now=now, world=world)
    summary["webhook_retries"] = webhook_subscriptions.process_due(world=world, now=now)
    summary["ran_at"] = time.time() if now is None else float(now)
    _last_cycle[_workspace()] = {k: v for k, v in summary.items() if k != "alerts"}
    return summary


def last_cycle() -> dict:
    """The active workspace's last cycle."""
    return dict(_last_cycle.get(_workspace(), {}))


def _sweep_public_chat(now: float) -> None:
    """Remove public chat transcripts past retention, at most once an hour (the store keeps that
    time). The sweep opens every workspace's file itself, so it runs once per pass, not per
    workspace. A failure is logged and the next pass still tries."""
    from . import public_chat_store

    try:
        failed = public_chat_store.purge_expired_if_due(now=now)
    except Exception:
        log.exception("public chat retention sweep failed")
        return
    if failed:
        log.warning("public chat retention sweep did not finish for %d workspace(s); it is tried again "
                    "at the next pass", len(failed))


def _tick(now: float, next_eval: dict[str, float]) -> None:
    """One pass of the thread. The retry pump and the deadline evaluation run
    once per active workspace, each pinned to it like the other background
    schedulers: a thread has no request workspace, so unpinned they would only
    ever see the base one. One workspace's failure does not stop the others."""
    from maverick import compliance_history, deadline_alerts, webhook_subscriptions

    from .automation_queue import _run_for_active_tenants

    _run_for_active_tenants("webhook retry pump",
                            lambda: webhook_subscriptions.process_due(world=_world(), now=now))
    # Each workspace keeps its own history; a failed check is retried next pass.
    _run_for_active_tenants("compliance re-check", lambda: compliance_history.recheck_if_due(now=now))
    _sweep_public_chat(now)

    def evaluate() -> None:
        key = _workspace()
        if now < next_eval.get(key, 0.0):
            return
        try:
            cfg = deadline_alerts.settings()
            if not cfg["enabled"]:
                return
            run_once(now=now)
        except Exception:
            next_eval[key] = now + 300.0
            raise
        next_eval[key] = now + cfg["poll_seconds"]

    _run_for_active_tenants("deadline alert cycle", evaluate)


def _scheduler_loop(stop: threading.Event) -> None:
    next_eval: dict[str, float] = {}
    while not stop.is_set():
        _tick(time.time(), next_eval)
        stop.wait(_RETRY_PUMP_SECONDS)


def start_deadline_alerts_scheduler() -> bool:
    """Start the thread unless it is already running. Returns True when started."""
    global _scheduler_stop, _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return False
        stop = threading.Event()
        worker = threading.Thread(target=_scheduler_loop, args=(stop,),
                                  name="deadline-alerts-scheduler", daemon=True)
        _scheduler_stop = stop
        _scheduler_thread = worker
        worker.start()
        return True


def stop_deadline_alerts_scheduler(*, timeout: float = 5.0, wait: bool = True) -> bool:
    """Signal first; retain a stopping worker until its exit is observed."""
    global _scheduler_stop, _scheduler_thread
    with _scheduler_lock:
        stop = _scheduler_stop
        worker = _scheduler_thread
        if stop is not None:
            stop.set()
    if stop is None or worker is None:
        return False
    if not wait:
        return not worker.is_alive()
    worker.join(max(0.0, min(float(timeout), 30.0)))
    if worker.is_alive():
        return False
    with _scheduler_lock:
        if _scheduler_thread is worker:
            _scheduler_stop = None
            _scheduler_thread = None
    return True


__all__ = ["last_cycle", "run_once", "start_deadline_alerts_scheduler",
           "stop_deadline_alerts_scheduler"]
