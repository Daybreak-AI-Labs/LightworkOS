"""Run due Automations schedules inside the dashboard.

A schedule created on the Automations page is a recurring ``start_goal`` job in
its workspace's own queue (``tenants/<id>/jobs.db``). Nothing ran it on a README
install: the dashboard's automation worker starts only for triggers, dreaming,
flows and reports, and ``lightwork worker`` drained the shared root queue. The
dashboard now drains each workspace's queue while scheduling is on and it runs
tasks itself. When tasks go to separate workers (a queue or gRPC dispatcher),
those workers own the queue and nothing starts here. Claims are atomic, so a
worker run alongside cannot run the same job twice.
"""
from __future__ import annotations

import logging
import threading

log = logging.getLogger(__name__)

_LOCK = threading.Lock()
_workers: list = []
_threads: list[threading.Thread] = []


def _workspaces() -> list[str]:
    from maverick.tenant.registry import list_tenants

    return [row.id for row in list_tenants() if getattr(row, "status", "active") == "active"]


def _runs_tasks_here() -> bool:
    from maverick.runner import LocalThreadDispatcher, get_dispatcher

    return isinstance(get_dispatcher(), LocalThreadDispatcher)


def _serve(tenant: str, ready: threading.Event, box: list) -> None:
    from maverick.paths import tenant_scope
    from maverick.worker import Worker

    with tenant_scope(tenant=tenant):
        try:
            worker = Worker(idle_max=30.0)
        finally:
            box.append(locals().get("worker"))
            ready.set()
        worker.run_forever()


def start() -> bool:
    """Start one schedule runner per active workspace. Idempotent."""
    from maverick.config import get_features

    if not get_features().get("scheduling", True) or not _runs_tasks_here():
        return False
    with _LOCK:
        if any(thread.is_alive() for thread in _threads):
            return True
        _workers.clear()
        _threads.clear()
        for tenant in _workspaces():
            ready, box = threading.Event(), []
            thread = threading.Thread(target=_serve, args=(tenant, ready, box),
                                      name=f"schedule-runner-{tenant}", daemon=True)
            thread.start()
            ready.wait(10)
            if box and box[0] is not None:
                _workers.append(box[0])
            _threads.append(thread)
    log.info("schedule runner started for %d workspace(s)", len(_threads))
    return bool(_threads)


def stop(*, timeout: float = 5.0) -> None:
    with _LOCK:
        workers, threads = list(_workers), list(_threads)
        _workers.clear()
        _threads.clear()
    for worker in workers:
        worker.stop()
    for thread in threads:
        thread.join(timeout=timeout)
