"""Cross-tenant-safe scheduler for approved third-party feed monitors.

The scheduler has no ambient provider or credential authority.  Its caller
must inject tenant-bound store factories, a closed provider factory, and a
credential resolver.  It starts only when every nested scheduler gate is an
exact boolean true.
"""

from __future__ import annotations

import logging
import math
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

_DEFAULT_POLL_SECONDS = 15 * 60.0
_MIN_POLL_SECONDS = 60.0
_MAX_POLL_SECONDS = 24 * 60 * 60.0
_SCHEDULER_KEYS = frozenset({"enable", "poll_seconds"})


@dataclass(frozen=True, slots=True)
class ThirdPartyFeedSchedulerDependencies:
    intelligence_store_for: Callable[[str], Any]
    runtime_store_for: Callable[[str], Any]
    provider_factory: Any
    credential_resolver: Callable[[str, str, str, str], Any]

    def __post_init__(self) -> None:
        for value in (
            self.intelligence_store_for,
            self.runtime_store_for,
            self.credential_resolver,
        ):
            if not callable(value):
                raise TypeError("third-party feed scheduler dependency is not callable")
        if not callable(getattr(self.provider_factory, "create", None)):
            raise TypeError("third-party feed provider factory is unavailable")


def _providers_section(config: Mapping[str, Any]) -> Mapping[str, Any]:
    root = config.get("third_party_management")
    intelligence = root.get("intelligence") if isinstance(root, Mapping) else None
    providers = intelligence.get("providers") if isinstance(intelligence, Mapping) else None
    return providers if isinstance(providers, Mapping) else {}


def _scheduler_section(config: Mapping[str, Any]) -> Mapping[str, Any]:
    providers = _providers_section(config)
    scheduler = providers.get("scheduler")
    return scheduler if isinstance(scheduler, Mapping) else {}


def scheduler_enabled(config: Mapping[str, Any]) -> bool:
    root = config.get("third_party_management")
    intelligence = root.get("intelligence") if isinstance(root, Mapping) else None
    providers = _providers_section(config)
    scheduler = _scheduler_section(config)
    return (
        isinstance(root, Mapping)
        and root.get("enable") is True
        and isinstance(intelligence, Mapping)
        and intelligence.get("enable") is True
        and providers.get("enable") is True
        and scheduler.get("enable") is True
    )


def _poll_seconds(config: Mapping[str, Any]) -> float:
    section = _scheduler_section(config)
    if set(section) - _SCHEDULER_KEYS:
        raise ValueError("third-party feed scheduler configuration key is unsupported")
    value = section.get("poll_seconds", _DEFAULT_POLL_SECONDS)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("third-party feed scheduler poll_seconds must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < _MIN_POLL_SECONDS or result > _MAX_POLL_SECONDS:
        raise ValueError("third-party feed scheduler poll_seconds must be between 60 and 86400")
    return result


def tenant_cycle(
    dependencies: ThirdPartyFeedSchedulerDependencies,
    *,
    actor_ref: str,
    enqueue_limit: int = 100,
    worker_limit: int = 10,
) -> Mapping[str, object]:
    """Queue and execute one cycle only for the active tenant context."""

    from maverick.paths import current_tenant_id_strict
    from maverick.third_party_intelligence_runtime import (
        enqueue_due_monitors,
        run_feed_batch,
    )

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise RuntimeError("third-party feed cycle requires an active tenant")
    from maverick.config import config_source_errors, load_config

    config = load_config() or {}
    if config_source_errors(include_tenant=True):
        raise RuntimeError("third-party feed tenant configuration is unreadable")
    if not isinstance(config, Mapping):
        raise RuntimeError("third-party feed tenant configuration must be a table")
    if not scheduler_enabled(config):
        return {
            "tenant_id": tenant,
            "skipped": True,
            "queued": 0,
            "claimed": 0,
            "completed": 0,
            "retry_pending": 0,
            "dead_lettered": 0,
            "revoked": 0,
        }
    _poll_seconds(config)
    intelligence_store = dependencies.intelligence_store_for(tenant)
    runtime_store = dependencies.runtime_store_for(tenant)
    queued = enqueue_due_monitors(
        runtime_store,
        intelligence_store,
        tenant_id=tenant,
        actor_ref=actor_ref,
        limit=enqueue_limit,
    )
    result = run_feed_batch(
        runtime_store,
        intelligence_store,
        dependencies.provider_factory,
        dependencies.credential_resolver,
        tenant_id=tenant,
        worker_id=actor_ref,
        limit=worker_limit,
    )
    return {
        "tenant_id": tenant,
        "skipped": False,
        "queued": len(queued),
        "claimed": result.claimed,
        "completed": result.completed,
        "retry_pending": result.retry_pending,
        "dead_lettered": result.dead_lettered,
        "revoked": result.revoked,
    }


def scheduler_cycle(
    dependencies: ThirdPartyFeedSchedulerDependencies,
    *,
    actor_ref: str,
) -> bool:
    from maverick.config import config_source_errors, load_global_config

    from .automation_queue import _run_for_active_tenants

    config = load_global_config() or {}
    if config_source_errors(include_tenant=False):
        log.warning("third-party feed scheduler skipped: global config is unreadable")
        return False
    if not scheduler_enabled(config):
        return False
    _poll_seconds(config)
    return _run_for_active_tenants(
        "Third-party intelligence feed collection",
        lambda: tenant_cycle(dependencies, actor_ref=actor_ref),
    )


class ThirdPartyFeedScheduler:
    """One bounded daemon thread around the cross-tenant scheduler cycle."""

    def __init__(self, dependencies: ThirdPartyFeedSchedulerDependencies) -> None:
        self._dependencies = dependencies
        self._lock = threading.Lock()
        self._stop: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._cycles = 0
        self._last_dispatch_complete: bool | None = None
        self._last_error_code: str | None = None

    def start(self) -> bool:
        from maverick.config import config_source_errors, load_global_config

        config = load_global_config() or {}
        if config_source_errors(include_tenant=False) or not scheduler_enabled(config):
            return False
        poll_seconds = _poll_seconds(config)
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            stop = threading.Event()
            actor = f"system-tpi-feed-scheduler-{uuid.uuid4().hex}"
            thread = threading.Thread(
                target=self._loop,
                args=(stop, actor, poll_seconds),
                name="third-party-intelligence-feed",
                daemon=True,
            )
            self._stop = stop
            self._thread = thread
            thread.start()
            return True

    def _loop(self, stop: threading.Event, actor: str, poll_seconds: float) -> None:
        while not stop.is_set():
            try:
                complete = scheduler_cycle(self._dependencies, actor_ref=actor)
                with self._lock:
                    self._cycles += 1
                    self._last_dispatch_complete = bool(complete)
                    self._last_error_code = (
                        None if complete else "tenant_dispatch_incomplete"
                    )
            except Exception as exc:  # noqa: BLE001 - visible tenant-isolated degradation
                with self._lock:
                    self._cycles += 1
                    self._last_dispatch_complete = False
                    self._last_error_code = "scheduler_cycle_failed"
                log.warning(
                    "third-party feed scheduler failed safely: %s",
                    type(exc).__name__,
                )
            stop.wait(poll_seconds)

    def status(self) -> Mapping[str, object]:
        """Return process-local, tenant-free scheduler health only."""

        with self._lock:
            return {
                "schema": "lightwork.third-party-feed-scheduler-status.v1",
                "running": self._thread is not None and self._thread.is_alive(),
                "cycles": self._cycles,
                "last_dispatch_complete": self._last_dispatch_complete,
                "last_error_code": self._last_error_code,
                "tenant_identifiers_returned": False,
                "provider_errors_returned": False,
            }

    def stop(self, *, timeout: float = 5.0, wait: bool = True) -> bool:
        with self._lock:
            stop = self._stop
            thread = self._thread
            if stop is not None:
                stop.set()
        if stop is None or thread is None:
            return False
        if not wait:
            return not thread.is_alive()
        thread.join(max(0.0, min(float(timeout), 30.0)))
        if thread.is_alive():
            return False
        with self._lock:
            if self._thread is thread:
                self._stop = None
                self._thread = None
        return True


__all__ = [
    "ThirdPartyFeedScheduler",
    "ThirdPartyFeedSchedulerDependencies",
    "scheduler_cycle",
    "scheduler_enabled",
    "tenant_cycle",
]
