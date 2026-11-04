"""Dashboard lifecycle worker for explicitly scheduled native Knowledge sources."""
from __future__ import annotations

import logging
import secrets
import threading
import time

from maverick import config, connections
from maverick import knowledge_sources as native
from maverick.paths import current_tenant_id_strict

from . import auth, rbac, research_workspace_api

log = logging.getLogger(__name__)
_lock = threading.Lock()
_stop = _thread = None
# Saved schedules are hourly at the finest, so a 30-second check finds every
# due refresh; a refresh queued from this dashboard wakes the worker at once.
_POLL_SECONDS = 30.0
_wake = threading.Event()


def wake():
    """Run the next cycle now (a refresh was just queued)."""
    _wake.set()


def owner_authority(owner):
    from maverick.tenant.registry import assert_tenant_active
    tenant = current_tenant_id_strict()
    if not tenant:
        raise PermissionError("The saved Knowledge workspace is unavailable.")
    assert_tenant_active(tenant)
    auth.stored_automation_identity(owner)
    if "admin" not in rbac.permissions_for(auth.role_for_principal(owner)):
        raise PermissionError("The source owner no longer has current workspace administrator authority.")
    if config.config_source_errors(include_tenant=True):
        raise PermissionError("Current Knowledge settings are unavailable.")


def _workspace_cycle():
    tenant = current_tenant_id_strict()
    if not tenant or not native.enabled():
        return
    rows = native.SOURCE_STORE.list(limit=native.MAX_SOURCES + 1)
    if len(rows) > native.MAX_SOURCES:
        raise ValueError("Saved Knowledge sources exceed their configured catalogue bound.")
    for row in rows:
        if row.get("tenant") != tenant or row.get("_audit_pending"):
            continue
        owner = row.get("owner")
        try:
            service = native.KnowledgeSources(tenant, owner, registry=research_workspace_api._registry_service(),
                                              authority=lambda owner=owner: owner_authority(owner))
            with connections.bind_principal(owner):
                if row.get("active_job"):
                    job = native.JOB_STORE.get(row["active_job"])
                    if job and job.get("state") == "queued" and not job.get("_audit_pending"):
                        try:
                            service.run(job["id"])
                        except Exception as exc:
                            # Refused before it started: withheld and backed
                            # off, not retried every cycle.
                            try:
                                native.KnowledgeSources.withhold_queued(job, exc)
                            except Exception as receipt_error:
                                log.warning("Knowledge source withheld receipt unavailable (%s)",
                                            type(receipt_error).__name__)
                            raise
                    elif job and job.get("state") == "withheld" and not job.get("_audit_pending"):
                        # The job receipt may have committed before releasing
                        # its source failed. Finish only that bookkeeping.
                        native.KnowledgeSources.withhold_queued(job)
                    # Running/uncertain claims are never taken over.
                elif (not row.get("paused") and row["plan"]["interval_seconds"]
                      and row.get("next_refresh") is not None and row["next_refresh"] <= time.time()):
                    prepared = service.refresh_review(row["id"])
                    prepared["acknowledge_unknown"] = False
                    job = service.start(prepared, secrets.token_hex(16))
                    if job.get("state") == "queued":
                        service.run(job["id"])
        except Exception as exc:
            # Never log a provider response, URL, token or credential record.
            log.warning("Knowledge source cycle withheld (%s)", type(exc).__name__)
            if not row.get("active_job"):
                try:
                    native.KnowledgeSources.record_scheduled_error(row, exc)
                except Exception as receipt_error:
                    log.warning("Knowledge source withheld receipt unavailable (%s)", type(receipt_error).__name__)


def cycle():
    from .automation_queue import _run_for_active_tenants
    _run_for_active_tenants("saved Knowledge sources", _workspace_cycle)


def _loop(stop):
    while not stop.is_set():
        try:
            cycle()
        except Exception as exc:
            log.warning("Knowledge source worker unavailable (%s)", type(exc).__name__)
        _wake.wait(_POLL_SECONDS)
        _wake.clear()


def start_knowledge_sources_scheduler():
    global _stop, _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            return False
        _stop = threading.Event()
        # A wake from while the worker was stopped (or from that stop) is
        # covered by the first cycle, which runs at once.
        _wake.clear()
        _thread = threading.Thread(target=_loop, args=(_stop,), name="knowledge-sources", daemon=True)
        _thread.start()
        return True


def stop_knowledge_sources_scheduler(*, timeout=5.0, wait=True):
    global _stop, _thread
    with _lock:
        stop, worker = _stop, _thread
        if stop is not None:
            stop.set()
            _wake.set()
    if worker is None:
        return False
    if wait:
        worker.join(max(0, min(float(timeout), 30)))
    if worker.is_alive():
        return False
    with _lock:
        if worker is _thread:
            _stop = _thread = None
    return True


def status():
    return {"running_here": _thread is not None and _thread.is_alive(),
            "detail": "Only explicitly scheduled saved sources and confirmed queued refreshes run. Unknown originals are never resumed automatically."}
