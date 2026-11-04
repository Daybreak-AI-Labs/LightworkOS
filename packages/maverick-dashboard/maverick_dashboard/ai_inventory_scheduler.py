"""Bounded background reconciliation for configured AI-estate connectors."""
from __future__ import annotations

import logging
import math
import threading
import uuid
from collections.abc import Mapping
from typing import Any

log = logging.getLogger(__name__)

_scheduler_lock = threading.Lock()
_scheduler_stop: threading.Event | None = None
_scheduler_thread: threading.Thread | None = None

_DEFAULT_POLL_SECONDS = 15 * 60.0
_MIN_POLL_SECONDS = 60.0
_MAX_POLL_SECONDS = 24 * 60 * 60.0


def _section(config: Mapping[str, Any]) -> dict[str, Any]:
    raw = config.get("ai_inventory")
    return dict(raw) if isinstance(raw, Mapping) else {}


def _poll_seconds(section: Mapping[str, Any]) -> float:
    value = section.get("poll_seconds", _DEFAULT_POLL_SECONDS)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("ai_inventory.poll_seconds must be a number")
    result = float(value)
    if (
        not math.isfinite(result)
        or result < _MIN_POLL_SECONDS
        or result > _MAX_POLL_SECONDS
    ):
        raise ValueError("ai_inventory.poll_seconds must be between 60 and 86400")
    return result


def _tenant_cycle(actor: str) -> dict[str, Any]:
    from maverick import ai_inventory

    if not ai_inventory.enabled():
        return {"skipped": True, "results": [], "failures": []}
    config = ai_inventory.require_enabled()
    results = []
    failures = []
    for connector in config.get("connectors") or []:
        try:
            results.append(ai_inventory.sync_connector(connector, actor=actor))
        except Exception as exc:  # failure-policy: visible_degradation
            log.warning(
                "AI inventory connector %s failed safely: %s",
                connector,
                type(exc).__name__,
            )
            failures.append({
                "connector": connector,
                "error_type": type(exc).__name__,
            })
    return {
        "skipped": False,
        "results": results,
        "failures": failures,
        "connector_count": len(results) + len(failures),
    }


def scheduler_cycle(actor: str) -> bool:
    from maverick.config import config_source_errors, load_global_config

    from .automation_queue import _run_for_active_tenants

    config = load_global_config() or {}
    if config_source_errors(include_tenant=False):
        log.warning("AI inventory scheduler skipped: global config is unreadable")
        return False
    section = _section(config)
    if section.get("enable") is not True:
        return False
    _poll_seconds(section)
    return _run_for_active_tenants(
        "AI inventory reconciliation",
        lambda: _tenant_cycle(actor),
    )


def _scheduler_loop(stop: threading.Event, actor: str, poll_seconds: float) -> None:
    while not stop.is_set():
        try:
            scheduler_cycle(actor)
        except Exception as exc:  # failure-policy: visible_degradation
            log.warning("AI inventory scheduler failed safely: %s", type(exc).__name__)
        stop.wait(poll_seconds)


def start_ai_inventory_scheduler() -> bool:
    from maverick.config import config_source_errors, load_global_config

    config = load_global_config() or {}
    if config_source_errors(include_tenant=False):
        return False
    section = _section(config)
    if section.get("enable") is not True:
        return False
    poll_seconds = _poll_seconds(section)
    global _scheduler_stop, _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return False
        stop = threading.Event()
        worker = threading.Thread(
            target=_scheduler_loop,
            args=(
                stop,
                f"system:ai-inventory-scheduler:{uuid.uuid4().hex}",
                poll_seconds,
            ),
            name="ai-inventory-reconciliation",
            daemon=True,
        )
        _scheduler_stop = stop
        _scheduler_thread = worker
        worker.start()
        return True


def stop_ai_inventory_scheduler(*, timeout: float = 5.0, wait: bool = True) -> bool:
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


__all__ = [
    "scheduler_cycle",
    "start_ai_inventory_scheduler",
    "stop_ai_inventory_scheduler",
]
