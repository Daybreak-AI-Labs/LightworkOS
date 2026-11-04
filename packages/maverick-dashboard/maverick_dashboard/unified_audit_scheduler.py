"""Bounded tenant supervisor for the unified-audit projection.

The scheduler is deliberately orchestration-only.  It reads the admitted
tenant roster, applies the global and tenant feature gates, and asks the
server-owned projector to run its fixed six-source sweep.  It does not discover
sources, resolve credentials, perform network I/O, or claim live completeness.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from maverick import unified_audit as audit

log = logging.getLogger(__name__)

_STATUS_SCHEMA = "lightwork.unified-audit-scheduler-status.v1"
_CYCLE_SCHEMA = "lightwork.unified-audit-scheduler-cycle.v1"
_WORKER_SCHEMA = "lightwork.unified-audit-scheduler-worker.v1"
_DEFAULT_POLL_SECONDS = 60.0
_MAX_TENANTS_PER_CYCLE = 1_000
_MAX_STOP_SECONDS = 30.0


class UnifiedAuditSchedulerError(RuntimeError):
    """Base unified-audit scheduler error."""


class UnifiedAuditSchedulerConfigurationError(
    UnifiedAuditSchedulerError,
    ValueError,
):
    """The closed scheduler configuration is unavailable or malformed."""


class UnifiedAuditProjector(Protocol):
    def run_all(self, *, worker_id: str) -> Sequence[object]: ...


@dataclass(frozen=True, slots=True)
class SchedulerSettings:
    poll_seconds: float = _DEFAULT_POLL_SECONDS

    def __post_init__(self) -> None:
        value = self.poll_seconds
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or not 5 <= float(value) <= 3_600
        ):
            raise UnifiedAuditSchedulerConfigurationError(
                "unified-audit scheduler poll_seconds is outside its bound"
            )


@dataclass(frozen=True, slots=True)
class SchedulerCycle:
    started_at: float
    completed_at: float
    tenants_considered: int
    tenants_enabled: int
    tenants_failed: int
    tenant_runs_attempted: int
    tenant_runs_completed: int
    tenants_with_source_failures: int
    sources_committed: int
    sources_unavailable: int
    sources_failed: int
    tenant_limit_reached: bool
    cancelled: bool
    cycle_sha256: str


def scheduler_settings(config: object) -> SchedulerSettings | None:
    """Return settings only for an explicitly enabled, signed global floor."""

    if not isinstance(config, Mapping):
        raise UnifiedAuditSchedulerConfigurationError(
            "unified-audit scheduler configuration must be a table"
        )
    try:
        parsed = audit.config_from(config)
    except audit.UnifiedAuditError as exc:
        raise UnifiedAuditSchedulerConfigurationError(str(exc)) from exc
    if not parsed.enable:
        return None
    audit_section = config.get("audit")
    if not isinstance(audit_section, Mapping) or audit_section.get("sign") is not True:
        raise UnifiedAuditSchedulerConfigurationError(
            "unified-audit scheduler requires signed audit"
        )
    return SchedulerSettings(poll_seconds=float(parsed.poll_seconds))


def _default_config_loader() -> Mapping[str, Any]:
    from maverick.config import config_source_errors, load_global_config

    if config_source_errors(include_tenant=False):
        raise UnifiedAuditSchedulerConfigurationError("global configuration sources are unreadable")
    config = load_global_config() or {}
    if not isinstance(config, Mapping):
        raise UnifiedAuditSchedulerConfigurationError("global configuration must be a table")
    return config


def _default_tenant_supplier() -> Sequence[str]:
    """Return only provisioned tenants whose registry state is active."""

    try:
        from maverick.tenant.registry import list_tenants

        records = tuple(list_tenants())
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise UnifiedAuditSchedulerError("tenant_registry_unavailable") from exc
    return tuple(str(record.id) for record in records if getattr(record, "active", False) is True)


def _default_tenant_admitter(tenant_id: str) -> None:
    """Recheck registry admission immediately before tenant work begins."""

    from maverick.tenant.registry import assert_tenant_active

    assert_tenant_active(tenant_id)


@contextmanager
def _default_tenant_context(tenant_id: str):
    from maverick.paths import tenant_scope

    with tenant_scope(tenant=tenant_id):
        yield


def _clock_value(clock: Callable[[], float]) -> float:
    try:
        value = float(clock())
    except (OverflowError, TypeError, ValueError) as exc:
        raise UnifiedAuditSchedulerError("scheduler_clock_invalid") from exc
    if not math.isfinite(value) or value < 0:
        raise UnifiedAuditSchedulerError("scheduler_clock_invalid")
    return value


def _digest(payload: object) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _worker_id(tenant_id: str) -> str:
    """Stable tenant-bound identity containing no tenant or process label."""

    return _digest({"schema": _WORKER_SCHEMA, "tenant_id": tenant_id})


def _result_field(result: object, field: str) -> object:
    return result.get(field) if isinstance(result, Mapping) else getattr(result, field, None)


def _summarize_fixed_six(results: object) -> dict[str, int]:
    if isinstance(results, (str, bytes)) or not isinstance(results, Sequence):
        raise UnifiedAuditSchedulerError("projector_result_invalid")
    expected = tuple(audit.REQUIRED_SUITES)
    if len(results) != len(expected):
        raise UnifiedAuditSchedulerError("projector_fixed_six_incomplete")
    observed: list[str] = []
    counts = {"committed": 0, "unavailable": 0, "failed": 0}
    for result in results:
        source_id = _result_field(result, "source_id")
        outcome = _result_field(result, "outcome")
        if not isinstance(source_id, str) or outcome not in counts:
            raise UnifiedAuditSchedulerError("projector_result_invalid")
        observed.append(source_id)
        counts[str(outcome)] += 1
    if tuple(observed) != expected:
        raise UnifiedAuditSchedulerError("projector_fixed_six_invalid")
    return counts


class UnifiedAuditScheduler:
    """Thread-safe supervisor for one fixed-six run per enabled tenant/poll."""

    def __init__(
        self,
        *,
        projector_factory: Callable[[str, str], UnifiedAuditProjector],
        enabled_probe: Callable[[str], bool],
        tenant_supplier: Callable[[], Sequence[str]] = _default_tenant_supplier,
        tenant_admitter: Callable[[str], None] = _default_tenant_admitter,
        tenant_context: Callable[[str], Any] = _default_tenant_context,
        config_loader: Callable[[], Mapping[str, Any]] = _default_config_loader,
        clock: Callable[[], float] = time.time,
    ) -> None:
        dependencies = (
            projector_factory,
            enabled_probe,
            tenant_supplier,
            tenant_admitter,
            tenant_context,
            config_loader,
            clock,
        )
        if not all(callable(item) for item in dependencies):
            raise TypeError("unified-audit scheduler dependencies must be callable")
        self._projector_factory = projector_factory
        self._enabled_probe = enabled_probe
        self._tenant_supplier = tenant_supplier
        self._tenant_admitter = tenant_admitter
        self._tenant_context = tenant_context
        self._config_loader = config_loader
        self._clock = clock
        self._lock = threading.RLock()
        self._cycle_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._cycles = 0
        self._last_cycle: SchedulerCycle | None = None
        self._last_error_code: str | None = None

    def _tenants(self) -> tuple[tuple[str, ...], bool]:
        from maverick.paths import canonical_tenant_id

        supplied = self._tenant_supplier()
        if isinstance(supplied, (str, bytes)) or not isinstance(supplied, Sequence):
            raise UnifiedAuditSchedulerError("tenant_supplier_invalid")
        tenants: list[str] = []
        for value in supplied:
            if not isinstance(value, str) or not value or len(value) > 256:
                raise UnifiedAuditSchedulerError("tenant_supplier_invalid")
            try:
                canonical = canonical_tenant_id(value)
            except Exception as exc:
                raise UnifiedAuditSchedulerError("tenant_supplier_invalid") from exc
            if canonical != value or canonical in tenants:
                raise UnifiedAuditSchedulerError("tenant_supplier_invalid")
            tenants.append(canonical)
        bounded = tuple(tenants[:_MAX_TENANTS_PER_CYCLE])
        return bounded, len(tenants) > len(bounded)

    def run_once(self) -> SchedulerCycle | None:
        if not self._cycle_lock.acquire(blocking=False):
            raise UnifiedAuditSchedulerError("scheduler_cycle_already_running")
        try:
            return self._run_once()
        finally:
            self._cycle_lock.release()

    def _run_once(self) -> SchedulerCycle | None:
        settings = scheduler_settings(self._config_loader())
        if settings is None:
            return None
        started = _clock_value(self._clock)
        tenants, limit_reached = self._tenants()
        counts = {
            "tenants_considered": 0,
            "tenants_enabled": 0,
            "tenants_failed": 0,
            "tenant_runs_attempted": 0,
            "tenant_runs_completed": 0,
            "tenants_with_source_failures": 0,
            "sources_committed": 0,
            "sources_unavailable": 0,
            "sources_failed": 0,
        }
        cancelled = False
        for tenant_id in tenants:
            if self._stop.is_set():
                cancelled = True
                break
            counts["tenants_considered"] += 1
            try:
                with self._tenant_context(tenant_id):
                    self._tenant_admitter(tenant_id)
                    enabled = self._enabled_probe(tenant_id)
                    if type(enabled) is not bool:
                        raise UnifiedAuditSchedulerError("tenant_enabled_probe_invalid")
                    if not enabled:
                        continue
                    counts["tenants_enabled"] += 1
                    worker_id = _worker_id(tenant_id)
                    projector = self._projector_factory(tenant_id, worker_id)
                    run_all = getattr(projector, "run_all", None)
                    if not callable(run_all):
                        raise UnifiedAuditSchedulerError("projector_dependency_invalid")
                    counts["tenant_runs_attempted"] += 1
                    summary = _summarize_fixed_six(run_all(worker_id=worker_id))
                    counts["tenant_runs_completed"] += 1
                    counts["sources_committed"] += summary["committed"]
                    counts["sources_unavailable"] += summary["unavailable"]
                    counts["sources_failed"] += summary["failed"]
                    if summary["failed"]:
                        counts["tenants_with_source_failures"] += 1
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001 - retain only a closed code
                counts["tenants_failed"] += 1
                log.warning(
                    "unified-audit tenant projection failed: %s",
                    type(exc).__name__,
                )
        completed = _clock_value(self._clock)
        digest = _digest(
            {
                "schema": _CYCLE_SCHEMA,
                "started_at": started,
                "completed_at": completed,
                "tenant_limit_reached": limit_reached,
                "cancelled": cancelled,
                **counts,
            }
        )
        cycle = SchedulerCycle(
            started_at=started,
            completed_at=completed,
            tenant_limit_reached=limit_reached,
            cancelled=cancelled,
            cycle_sha256=digest,
            **counts,
        )
        with self._lock:
            self._cycles += 1
            self._last_cycle = cycle
            self._last_error_code = "tenant_cycle_failed" if counts["tenants_failed"] else None
        return cycle

    def status(self) -> Mapping[str, object]:
        with self._lock:
            payload: dict[str, object] = {
                "schema": _STATUS_SCHEMA,
                "running": self._thread is not None and self._thread.is_alive(),
                "cycles": self._cycles,
                "last_cycle": (None if self._last_cycle is None else asdict(self._last_cycle)),
                "last_error_code": self._last_error_code,
                "required_source_count": len(audit.REQUIRED_SUITES),
                "tenant_identifiers_retained": False,
                "source_error_details_retained": False,
                "source_registration_performed": False,
                "credentials_resolved": False,
                "network_io_performed": False,
                "live_completeness_verified": False,
                "live_customer_acceptance_verified": False,
            }
        payload["status_sha256"] = _digest(payload)
        return payload

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                settings = scheduler_settings(self._config_loader())
                if settings is None:
                    return
                self.run_once()
                delay = settings.poll_seconds
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001 - retain only a closed code
                with self._lock:
                    self._last_error_code = "scheduler_cycle_failed"
                log.warning(
                    "unified-audit scheduler cycle failed: %s",
                    type(exc).__name__,
                )
                delay = _DEFAULT_POLL_SECONDS
            self._stop.wait(delay)

    def start(self) -> bool:
        settings = scheduler_settings(self._config_loader())
        if settings is None:
            return False
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return True
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop,
                name="unified-audit-scheduler",
                daemon=True,
            )
            self._thread.start()
        return True

    def stop(self, timeout: float = 5.0, *, wait: bool = True) -> bool:
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(float(timeout))
            or not 0 <= float(timeout) <= _MAX_STOP_SECONDS
        ):
            raise ValueError("unified-audit scheduler stop timeout is outside its bound")
        self._stop.set()
        with self._lock:
            thread = self._thread
        if not wait:
            return False
        if thread is not None:
            thread.join(float(timeout))
        stopped = thread is None or not thread.is_alive()
        with self._lock:
            if stopped and self._thread is thread:
                self._thread = None
        return stopped


def attach_unified_audit_scheduler(
    app: Any,
    *,
    runtime: UnifiedAuditScheduler | None = None,
) -> UnifiedAuditScheduler:
    """Wrap an ASGI lifespan around the app's lazy projector composition."""

    router = getattr(app, "router", None)
    state = getattr(app, "state", None)
    previous = getattr(router, "lifespan_context", None)
    if router is None or state is None or not callable(previous):
        raise TypeError("app must expose a lifespan-capable router and state")

    def enabled_probe(tenant_id: str) -> bool:
        probe = getattr(state, "unified_audit_enabled_probe", None)
        if not callable(probe):
            raise UnifiedAuditSchedulerError("tenant_enabled_probe_unavailable")
        return probe(tenant_id)

    def projector_factory(tenant_id: str, worker_id: str) -> UnifiedAuditProjector:
        narrow = getattr(state, "unified_audit_scheduler_projector_factory", None)
        if narrow is not None:
            if not callable(narrow):
                raise UnifiedAuditSchedulerError("projector_factory_unavailable")
            return narrow(tenant_id, worker_id)
        factory = getattr(state, "unified_audit_projector_factory", None)
        if not callable(factory):
            raise UnifiedAuditSchedulerError("projector_factory_unavailable")
        return factory(tenant_id, worker_id, None)

    selected = (
        runtime
        if runtime is not None
        else UnifiedAuditScheduler(
            projector_factory=projector_factory,
            enabled_probe=enabled_probe,
        )
    )
    marker = "unified_audit_scheduler"
    attached = getattr(state, marker, None)
    if attached is not None:
        if attached is selected:
            return selected
        raise RuntimeError("a unified-audit scheduler is already attached")

    @asynccontextmanager
    async def lifespan(target: Any):
        from ._lifecycle import supervised_runtime

        async with previous(target):
            async with supervised_runtime(target, "unified_audit", selected):
                yield

    app.router.lifespan_context = lifespan
    setattr(state, marker, selected)
    return selected


__all__ = [
    "SchedulerCycle",
    "SchedulerSettings",
    "UnifiedAuditScheduler",
    "UnifiedAuditSchedulerConfigurationError",
    "UnifiedAuditSchedulerError",
    "attach_unified_audit_scheduler",
    "scheduler_settings",
]
