"""Tenant-aware background ingestion for complete AI billing periods."""
from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

log = logging.getLogger(__name__)

_scheduler_lock = threading.Lock()
_scheduler_stop: threading.Event | None = None
_scheduler_thread: threading.Thread | None = None


def _section(config: Mapping[str, Any]) -> dict[str, Any]:
    raw = config.get("ai_cost_roi", {})
    if not isinstance(raw, Mapping):
        raise ValueError("ai_cost_roi must be a table")
    return dict(raw)


def _collection_request(
    lookback_days: int,
    *,
    now: datetime | None = None,
):
    """Return the last complete UTC-midnight billing window."""

    from maverick.ai_cost_collectors import CollectorSchedule
    from maverick.ai_cost_roi import CollectionRequest

    validated = CollectorSchedule(lookback_days=lookback_days)
    instant = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(instant, datetime) or instant.tzinfo is None:
        raise ValueError("AI cost scheduler time must be timezone-aware")
    period_end = instant.astimezone(timezone.utc).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
    )
    period_start = period_end - timedelta(days=validated.lookback_days)
    return CollectionRequest(
        period_start=period_start.isoformat().replace("+00:00", "Z"),
        period_end=period_end.isoformat().replace("+00:00", "Z"),
    )


def _tenant_cycle(
    actor: str,
    global_config: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    from maverick import ai_cost_roi
    from maverick.ai_cost_collectors import (
        configured_collector_schedule,
        configured_collectors,
    )
    from maverick.config import load_config

    global_section = _section(global_config)
    if global_section.get("enable") is not True:
        return {
            "skipped": True,
            "reason": "AI cost collection is globally disabled",
            "results": [],
            "failures": [],
        }
    config = load_config() or {}
    if not isinstance(config, Mapping):
        raise ValueError("AI cost tenant configuration must be a table")
    section = _section(config)
    schedule = configured_collector_schedule(section)
    collectors = configured_collectors(section)
    if section.get("enable") is not True or not collectors:
        return {
            "skipped": True,
            "reason": "no AI cost collectors are enabled",
            "results": [],
            "failures": [],
        }

    request = _collection_request(schedule.lookback_days, now=now)
    results: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for collector in collectors:
        provider = collector.provider.value
        try:
            receipt = ai_cost_roi.default_service.collect_and_ingest(
                collector,
                request,
                actor=actor,
            )
            results.append({"provider": provider, "receipt": receipt})
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:  # failure-policy: visible_degradation
            error_type = type(exc).__name__
            log.warning(
                "AI cost collector %s failed safely: %s",
                provider,
                error_type,
            )
            failures.append(
                {
                    "provider": provider,
                    "error_type": error_type,
                }
            )
    return {
        "skipped": False,
        "period_start": request.period_start,
        "period_end": request.period_end,
        "results": results,
        "failures": failures,
        "collector_count": len(collectors),
    }


def _global_configuration() -> tuple[dict[str, Any], dict[str, Any]] | None:
    from maverick.config import config_source_errors, load_global_config

    config = load_global_config() or {}
    if config_source_errors(include_tenant=False):
        log.warning("AI cost scheduler skipped: global config is unreadable")
        return None
    if not isinstance(config, Mapping):
        raise ValueError("global configuration must be a table")
    snapshot = dict(config)
    return snapshot, _section(snapshot)


def scheduler_cycle(actor: str) -> bool:
    """Collect billing evidence in the shared floor and active tenants."""

    from maverick.ai_cost_collectors import (
        configured_collector_schedule,
        configured_collectors,
    )

    from .automation_queue import _run_for_active_tenants

    configured = _global_configuration()
    if configured is None:
        return False
    config, section = configured
    configured_collector_schedule(section)
    collectors = configured_collectors(section)
    if section.get("enable") is not True or not collectors:
        return False
    return _run_for_active_tenants(
        "AI cost collection",
        lambda: _tenant_cycle(actor, config),
    )


def _scheduler_loop(
    stop: threading.Event,
    actor: str,
    poll_seconds: float,
) -> None:
    while not stop.is_set():
        try:
            scheduler_cycle(actor)
        except Exception as exc:  # failure-policy: visible_degradation
            log.warning("AI cost scheduler failed safely: %s", type(exc).__name__)
        stop.wait(poll_seconds)


def start_ai_cost_scheduler() -> bool:
    """Start the off-by-default AI billing collector scheduler."""

    from maverick.ai_cost_collectors import (
        configured_collector_schedule,
        configured_collectors,
    )

    configured = _global_configuration()
    if configured is None:
        return False
    _config, section = configured
    schedule = configured_collector_schedule(section)
    collectors = configured_collectors(section)
    if section.get("enable") is not True or not collectors:
        return False

    global _scheduler_stop, _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return False
        stop = threading.Event()
        worker = threading.Thread(
            target=_scheduler_loop,
            args=(
                stop,
                f"system:ai-cost-scheduler:{uuid.uuid4().hex}",
                schedule.poll_seconds,
            ),
            name="ai-cost-collection",
            daemon=True,
        )
        _scheduler_stop = stop
        _scheduler_thread = worker
        worker.start()
        return True


def stop_ai_cost_scheduler(*, timeout: float = 5.0, wait: bool = True) -> bool:
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
    "start_ai_cost_scheduler",
    "stop_ai_cost_scheduler",
]
