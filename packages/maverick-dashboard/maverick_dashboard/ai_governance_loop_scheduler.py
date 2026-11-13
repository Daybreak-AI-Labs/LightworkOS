"""Bounded cross-tenant scheduler for AI-governance reconciliation.

The scheduler owns no authority and retains no tenant identifiers or exception
details in health.  Every tenant is entered through its namespace, the exact
tenant gate is re-read, and only a deployment-composed runtime may process the
bounded batch.  Core fenced leases and retries remain the concurrency source
of truth.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from .ai_governance_loop_composition import (
    AIGovernanceLoopBatchResult,
    AIGovernanceLoopCompositionError,
    AIGovernanceLoopSettings,
    governance_loop_settings,
)

log = logging.getLogger(__name__)

_STATUS_SCHEMA = "lightwork.ai-governance-loop-scheduler-status.v1"
_CYCLE_SCHEMA = "lightwork.ai-governance-loop-scheduler-cycle.v1"
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}\Z")
_DEFAULT_POLL_SECONDS = 300.0
_DEFAULT_TENANT_LIMIT = 1_000
_MAX_TENANT_LIMIT = 10_000
_MAX_STOP_SECONDS = 30.0


class AIGovernanceLoopSchedulerError(RuntimeError):
    """Base scheduler failure with a closed public error code."""


class AIGovernanceLoopSchedulerConfigurationError(
    AIGovernanceLoopSchedulerError,
    ValueError,
):
    """A scheduler dependency or configuration is unsafe."""


class AIGovernanceLoopWorker(Protocol):
    tenant_id: str
    principal_ref: str

    def run_batch(self, *, worker_id: str, limit: int) -> AIGovernanceLoopBatchResult: ...


@dataclass(frozen=True, slots=True)
class AIGovernanceLoopSchedulerCycle:
    started_at: float
    completed_at: float
    tenants_considered: int
    tenants_enabled: int
    tenants_failed: int
    tenant_limit_reached: bool
    processed: int
    failed: int
    no_change: int
    idle_tenants: int
    cycle_sha256: str


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AIGovernanceLoopSchedulerConfigurationError(f"{label} is outside its bound")
    return value


def _sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AIGovernanceLoopSchedulerError("scheduler_commitment_invalid") from exc
    return hashlib.sha256(encoded).hexdigest()


def _clock_value(clock: Callable[[], float]) -> float:
    try:
        value = float(clock())
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise AIGovernanceLoopSchedulerError("scheduler_clock_unavailable") from exc
    if not math.isfinite(value) or value <= 0:
        raise AIGovernanceLoopSchedulerError("scheduler_clock_invalid")
    return value


def _default_config_loader() -> Mapping[str, Any]:
    from maverick.config import config_source_errors, load_global_config

    if config_source_errors(include_tenant=False):
        raise AIGovernanceLoopSchedulerConfigurationError(
            "global configuration sources are unreadable"
        )
    loaded = load_global_config() or {}
    if not isinstance(loaded, Mapping):
        raise AIGovernanceLoopSchedulerConfigurationError("global configuration must be a table")
    return loaded


def _default_tenant_config_loader() -> Mapping[str, Any]:
    from maverick.config import config_source_errors, load_config

    if config_source_errors(include_tenant=True):
        raise AIGovernanceLoopSchedulerConfigurationError(
            "tenant configuration sources are unreadable"
        )
    loaded = load_config() or {}
    if not isinstance(loaded, Mapping):
        raise AIGovernanceLoopSchedulerConfigurationError("tenant configuration must be a table")
    return loaded


def _default_tenant_supplier() -> Sequence[str]:
    floor = os.environ.get("MAVERICK_TENANT", "").strip()
    try:
        from maverick.tenant.registry import list_tenants

        records = tuple(list_tenants())
    except Exception as exc:
        raise AIGovernanceLoopSchedulerError("tenant_registry_unavailable") from exc
    tenants: list[str] = [floor] if floor else []
    for record in records:
        tenant = str(getattr(record, "id", "") or "").strip()
        if tenant and getattr(record, "active", False) and tenant not in tenants:
            tenants.append(tenant)
    return tuple(tenants)


@contextmanager
def _default_tenant_context(tenant_id: str):
    from maverick.paths import reset_tenant, set_tenant

    token = set_tenant(tenant_id or None)
    try:
        yield
    finally:
        reset_tenant(token)


def scheduler_settings(config: object) -> AIGovernanceLoopSettings | None:
    """Public alias for the scheduler's exact default-off feature gate."""

    try:
        return governance_loop_settings(config)
    except AIGovernanceLoopCompositionError as exc:
        raise AIGovernanceLoopSchedulerConfigurationError(str(exc)) from exc


def _batch_result(value: object) -> AIGovernanceLoopBatchResult:
    if type(value) is not AIGovernanceLoopBatchResult:
        raise AIGovernanceLoopSchedulerError("worker_result_invalid")
    if (
        any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in (value.processed, value.failed, value.no_change)
        )
        or type(value.idle) is not bool
        or value.no_change > value.processed
    ):
        raise AIGovernanceLoopSchedulerError("worker_result_invalid")
    return value


class AIGovernanceLoopScheduler:
    """Thread-safe supervisor with explicit tenant and work bounds."""

    def __init__(
        self,
        *,
        worker_factory: Callable[[str, str], AIGovernanceLoopWorker],
        tenant_supplier: Callable[[], Sequence[str]] = _default_tenant_supplier,
        tenant_context: Callable[[str], Any] = _default_tenant_context,
        config_loader: Callable[[], Mapping[str, Any]] = _default_config_loader,
        tenant_config_loader: Callable[[], Mapping[str, Any]] | None = None,
        clock: Callable[[], float] = time.time,
        worker_id: str | None = None,
        tenant_limit: int = _DEFAULT_TENANT_LIMIT,
    ) -> None:
        selected_worker = worker_id or f"ai-governance-loop-{uuid.uuid4().hex}"
        if not isinstance(selected_worker, str) or _REF_RE.fullmatch(selected_worker) is None:
            raise ValueError("worker_id must be an opaque identifier")
        if not all(
            callable(item)
            for item in (worker_factory, tenant_supplier, tenant_context, config_loader, clock)
        ):
            raise TypeError("AI-governance-loop scheduler dependencies must be callable")
        self._tenant_limit = _integer(
            tenant_limit,
            "scheduler tenant_limit",
            1,
            _MAX_TENANT_LIMIT,
        )
        self._worker_factory = worker_factory
        self._tenant_supplier = tenant_supplier
        self._tenant_context = tenant_context
        self._config_loader = config_loader
        self._tenant_config_loader = (
            _default_tenant_config_loader
            if tenant_config_loader is None and config_loader is _default_config_loader
            else (tenant_config_loader or config_loader)
        )
        self._clock = clock
        self._worker_id = selected_worker
        self._worker_principal = (
            "ai-governance-loop-scheduler."
            + _sha256(
                {
                    "schema": "lightwork.ai-governance-loop-worker-principal.v1",
                    "worker": selected_worker,
                }
            )[:40]
        )
        self._lock = threading.RLock()
        self._cycle_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._cycles = 0
        self._last_cycle: AIGovernanceLoopSchedulerCycle | None = None
        self._last_error_code: str | None = None
        self._source_cursors: dict[str, str] = {}

    def _tenants(self) -> tuple[tuple[str, ...], bool]:
        from maverick.paths import canonical_tenant_id

        values = self._tenant_supplier()
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise AIGovernanceLoopSchedulerError("tenant_supplier_invalid")
        result: list[str] = []
        # Inspect at most one item beyond the admitted cap.  A malicious or
        # enormous supplier therefore cannot make one cycle unbounded.
        for value in values[: self._tenant_limit + 1]:
            if not isinstance(value, str) or len(value) > 256:
                raise AIGovernanceLoopSchedulerError("tenant_supplier_invalid")
            try:
                tenant = "" if value == "" else canonical_tenant_id(value)
            except Exception as exc:
                raise AIGovernanceLoopSchedulerError("tenant_supplier_invalid") from exc
            if tenant not in result:
                result.append(tenant)
        return tuple(result[: self._tenant_limit]), len(result) > self._tenant_limit

    def run_once(self) -> AIGovernanceLoopSchedulerCycle | None:
        if not self._cycle_lock.acquire(blocking=False):
            raise AIGovernanceLoopSchedulerError("scheduler_cycle_already_running")
        try:
            return self._run_once()
        finally:
            self._cycle_lock.release()

    def _run_once(self) -> AIGovernanceLoopSchedulerCycle | None:
        global_settings = scheduler_settings(self._config_loader())
        if global_settings is None:
            return None
        started = _clock_value(self._clock)
        counts = {
            "tenants_considered": 0,
            "tenants_enabled": 0,
            "tenants_failed": 0,
            "processed": 0,
            "failed": 0,
            "no_change": 0,
            "idle_tenants": 0,
        }
        tenants, limit_reached = self._tenants()
        for tenant_id in tenants:
            counts["tenants_considered"] += 1
            try:
                with self._tenant_context(tenant_id):
                    settings = scheduler_settings(self._tenant_config_loader())
                    if settings is None:
                        continue
                    counts["tenants_enabled"] += 1
                    worker = self._worker_factory(tenant_id, self._worker_principal)
                    if (
                        not callable(getattr(worker, "run_batch", None))
                        or getattr(worker, "tenant_id", None) != tenant_id
                        or getattr(worker, "principal_ref", None) != self._worker_principal
                    ):
                        raise AIGovernanceLoopSchedulerError("worker_dependency_invalid")
                    discovery = getattr(worker, "discover_sources", None)
                    if callable(discovery):
                        self._source_cursors[tenant_id] = discovery(limit=settings.batch_size,
                            after=self._source_cursors.get(tenant_id, ""))
                    result = _batch_result(
                        worker.run_batch(
                            worker_id=self._worker_id,
                            limit=settings.batch_size,
                        )
                    )
                    counts["processed"] += result.processed
                    counts["failed"] += result.failed
                    counts["no_change"] += result.no_change
                    counts["idle_tenants"] += int(result.idle)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001 - retain only a closed code
                counts["tenants_failed"] += 1
                log.warning("AI-governance-loop tenant cycle failed: %s", type(exc).__name__)
        completed = _clock_value(self._clock)
        payload = {
            "schema": _CYCLE_SCHEMA,
            "started_at": started,
            "completed_at": completed,
            "tenant_limit_reached": limit_reached,
            **counts,
        }
        cycle = AIGovernanceLoopSchedulerCycle(
            started_at=started,
            completed_at=completed,
            tenant_limit_reached=limit_reached,
            cycle_sha256=_sha256(payload),
            **counts,
        )
        with self._lock:
            self._cycles += 1
            self._last_cycle = cycle
            self._last_error_code = "tenant_cycle_failed" if counts["tenants_failed"] else None
        return cycle

    def status(self) -> Mapping[str, object]:
        with self._lock:
            payload = {
                "schema": _STATUS_SCHEMA,
                "running": self._thread is not None and self._thread.is_alive(),
                "cycles": self._cycles,
                "last_cycle": None if self._last_cycle is None else asdict(self._last_cycle),
                "last_error_code": self._last_error_code,
                "tenant_limit": self._tenant_limit,
                "runtime_dependencies_injected": True,
                "tenant_identifiers_retained": False,
                "authority_error_details_retained": False,
                "raw_telemetry_retained": False,
                # max_lag_seconds is admitted and surfaced to deployment
                # monitoring, but the core store does not expose an unbounded
                # cross-case queue scan from which this supervisor could infer
                # per-case lag safely.
                "per_case_lag_inferred": False,
            }
        payload["status_sha256"] = _sha256(payload)
        return payload

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                settings = scheduler_settings(self._config_loader())
                if settings is None:
                    return
                self.run_once()
                delay = float(settings.poll_seconds)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001 - retain only a closed code
                with self._lock:
                    self._last_error_code = "scheduler_cycle_failed"
                log.warning("AI-governance-loop scheduler failed: %s", type(exc).__name__)
                delay = _DEFAULT_POLL_SECONDS
            self._stop.wait(delay)

    def start(self) -> bool:
        if scheduler_settings(self._config_loader()) is None:
            return False
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return True
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop,
                name="ai-governance-loop",
                daemon=True,
            )
            self._thread.start()
        return True

    def stop(self, timeout: float = 5.0, *, wait: bool = True) -> bool:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or not 0 <= float(timeout) <= _MAX_STOP_SECONDS
        ):
            raise ValueError("scheduler stop timeout is outside its bound")
        self._stop.set()
        with self._lock:
            thread = self._thread
        if not wait:
            return False
        if thread is not None:
            thread.join(float(timeout))
        stopped = thread is None or not thread.is_alive()
        with self._lock:
            if self._thread is thread and stopped:
                self._thread = None
        return stopped


def attach_ai_governance_loop_scheduler(
    app: Any,
    *,
    worker_factory: Callable[[str, str], AIGovernanceLoopWorker] | None = None,
    runtime: AIGovernanceLoopScheduler | None = None,
) -> AIGovernanceLoopScheduler:
    """Attach one explicitly gated scheduler to the app lifespan."""

    state = getattr(app, "state", None)
    router = getattr(app, "router", None)
    previous = getattr(router, "lifespan_context", None)
    if state is None or router is None or not callable(previous):
        raise TypeError("app must expose a lifespan-capable router and state")
    selected_factory = worker_factory or getattr(
        state,
        "ai_governance_loop_worker_factory",
        None,
    )
    if runtime is None and not callable(selected_factory):
        raise AIGovernanceLoopSchedulerConfigurationError(
            "AI-governance-loop worker factory is unavailable"
        )
    selected = runtime or AIGovernanceLoopScheduler(worker_factory=selected_factory)
    marker = "ai_governance_loop_scheduler"
    attached = getattr(state, marker, None)
    if attached is not None:
        if attached is selected:
            return selected
        raise RuntimeError("an AI-governance-loop scheduler is already attached")

    @asynccontextmanager
    async def lifespan(target: Any):
        from ._lifecycle import supervised_runtime

        async with previous(target):
            async with supervised_runtime(target, "ai_governance", selected):
                yield

    app.router.lifespan_context = lifespan
    state.ai_governance_loop_scheduler = selected
    return selected


__all__ = [
    "AIGovernanceLoopScheduler",
    "AIGovernanceLoopSchedulerConfigurationError",
    "AIGovernanceLoopSchedulerCycle",
    "AIGovernanceLoopSchedulerError",
    "AIGovernanceLoopWorker",
    "attach_ai_governance_loop_scheduler",
    "scheduler_settings",
]
