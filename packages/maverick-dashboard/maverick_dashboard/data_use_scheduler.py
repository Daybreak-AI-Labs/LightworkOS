"""Runs the background data-use checks (:mod:`maverick.data_use_checks`).

Off by default. Started at dashboard start only when
``[data_use_governance.scheduler] enable`` is on (a change to that switch
takes effect after a restart); how often it runs, how long one process holds
a pass and how many past passes are kept are read again every cycle. Each
cycle asks the job store for the due pass (a leased claim, so two processes
sharing the data folder never both run it), runs the checks for the base
workspace (``MAVERICK_TENANT``, when one is set) and every active workspace
with data-use governance on, records the summary, and adds one
activity-record row. With no base workspace set the shared pass checks
nothing: the checks only read a workspace's own records. Registered with the
dashboard's lifecycle supervisor, so shutdown stops it.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any

log = logging.getLogger(__name__)

_scheduler_lock = threading.Lock()
_scheduler_stop: threading.Event | None = None
_scheduler_thread: threading.Thread | None = None


def job_store():
    from maverick.data_use_checks import CheckJobStore
    from maverick.paths import data_dir

    return CheckJobStore(data_dir("data_use_governance", "background-checks.sqlite3", tenant=None))


def _workspace_counts(results: list) -> None:
    from maverick import config, data_use_checks, data_use_governance
    from maverick.paths import current_tenant_id_strict, data_dir

    tenant = current_tenant_id_strict()
    if tenant is None:
        return  # no workspace selected: nothing the data-use pages could show either
    loaded = config.load_config() or {}
    if not config.data_use_governance_enabled(loaded):
        return
    section = loaded.get("data_use_governance") or {}
    path = data_dir("data_use_governance", "data-use-governance.sqlite3", tenant=tenant)
    try:
        store = data_use_governance.DataUseGovernanceStore(path)
        compiler = None
        comp = section.get("compiler") if isinstance(section, dict) else None
        if isinstance(comp, dict) and comp.get("enable") is True:
            from maverick.data_use_policy_compiler import DataUsePolicyCompiler

            compiler = DataUsePolicyCompiler(store)
        results.append((tenant, data_use_checks.check_workspace(store, tenant, compiler=compiler)))
    except Exception as exc:  # noqa: BLE001 - one workspace never stops the pass
        log.warning("data-use checks could not check a workspace (%s)", type(exc).__name__)
        results.append((tenant, None))


def run_pass() -> dict[str, Any]:
    """Every workspace's checks, summarised."""
    from maverick import data_use_checks

    from .automation_queue import _run_for_active_tenants

    results: list = []
    _run_for_active_tenants("data-use checks", lambda: _workspace_counts(results))
    return data_use_checks.summarize(results)


def _record(summary: dict[str, Any], outcome: str) -> None:
    try:
        from maverick.audit import EventKind, audit_event

        audit_event(EventKind.CONTROL_PLANE_ACTION, agent="dashboard", _global=True,
                    verb="data_use_checks_ran", principal="*", actor="data-use checks",
                    ok=outcome == "done", findings=int(summary.get("findings") or 0),
                    workspaces_checked=int(summary.get("workspaces_checked") or 0))
    except Exception:  # noqa: BLE001 - the stored summary still records the pass
        log.warning("data-use checks could not add their activity-record row")


def cycle(worker_id: str, *, store=None, runner=run_pass) -> bool:
    """Run the pass if it is due and this process claims it. True when it ran."""
    from maverick import data_use_checks

    settings = data_use_checks.check_settings()
    if not settings.enable:
        return False
    store = store or job_store()
    token = store.claim(worker_id, lease_seconds=settings.lease_seconds)
    if token is None:
        return False
    started = time.time()
    try:
        summary, outcome = runner(), "done"
    except Exception as exc:  # noqa: BLE001 - a failed pass is recorded, not raised
        summary, outcome = {"error": type(exc).__name__}, "failed"
    store.complete(token, started_at=started, outcome=outcome, summary=summary,
                   poll_seconds=settings.poll_seconds, history_limit=settings.history_limit)
    _record(summary, outcome)
    return True


def _loop(stop: threading.Event, worker_id: str) -> None:
    from maverick import data_use_checks

    while not stop.is_set():
        wait = data_use_checks.DEFAULTS["poll_seconds"]
        try:
            wait = data_use_checks.check_settings().poll_seconds
            cycle(worker_id)
        except Exception as exc:  # failure-policy: visible_degradation
            log.warning("data-use checks failed safely: %s", type(exc).__name__)
        # Wake at least every minute so another process's expired claim is taken over.
        stop.wait(min(wait, 60))


def start_data_use_scheduler() -> bool:
    """Start the off-by-default background data-use checks."""
    from maverick import data_use_checks

    try:
        if not data_use_checks.check_settings().enable:
            return False
    except data_use_checks.DataUseChecksError:
        log.warning("data-use checks not started: their settings are invalid")
        return False
    global _scheduler_stop, _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return False
        stop = threading.Event()
        worker = threading.Thread(target=_loop, args=(stop, f"data-use-checks:{uuid.uuid4().hex}"),
                                  name="data-use-checks", daemon=True)
        _scheduler_stop, _scheduler_thread = stop, worker
        worker.start()
        return True


def stop_data_use_scheduler(*, timeout: float = 5.0, wait: bool = True) -> bool:
    """Signal first; keep a stopping worker until its exit is seen."""
    global _scheduler_stop, _scheduler_thread
    with _scheduler_lock:
        stop, worker = _scheduler_stop, _scheduler_thread
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
            _scheduler_stop = _scheduler_thread = None
    return True


def status() -> dict[str, Any]:
    from maverick import data_use_checks

    store = job_store()
    return {"enabled": data_use_checks.check_settings().enable,
            "running_here": _scheduler_thread is not None and _scheduler_thread.is_alive(),
            **store.schedule(), "history": store.history(20)}


__all__ = ["cycle", "run_pass", "start_data_use_scheduler", "status", "stop_data_use_scheduler"]
