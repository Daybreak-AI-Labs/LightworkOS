"""Bounded cross-tenant supervisor for native provider-audit evidence.

The core store owns leases, retries, reconciliation, revocation, retention and
integrity. This supervisor only visits bounded active tenant namespaces, checks
the exact nested opt-in gates, invokes an injected worker, and purges expired
digest-only records. Health never retains tenant identifiers or provider error
details.
"""

from __future__ import annotations

import hashlib
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

log = logging.getLogger(__name__)

_STATUS_SCHEMA = "lightwork.data-use.provider-audit-scheduler-status.v1"
_CYCLE_SCHEMA = "lightwork.data-use.provider-audit-scheduler-cycle.v1"
_SCHEDULER_KEYS = frozenset(
    {
        "enable",
        "poll_seconds",
        "claim_limit",
        "tenant_limit",
        "lease_seconds",
        "event_limit",
        "retry_backoff_seconds",
        "purge_limit",
    }
)
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DEFAULT_POLL_SECONDS = 60.0
_MAX_STOP_SECONDS = 30.0


class DataUseProviderAuditSchedulerError(RuntimeError):
    """Base provider-audit scheduler error."""


class DataUseProviderAuditSchedulerConfigurationError(
    DataUseProviderAuditSchedulerError,
    ValueError,
):
    """The closed provider-audit scheduler configuration is malformed."""


class ProviderAuditStore(Protocol):
    def purge_expired(self, *, cutoff: float, limit: int) -> int: ...  # noqa


class ProviderAuditWorker(Protocol):
    store: ProviderAuditStore

    def run_once(
        self,
        *,
        worker_id: str,
        limit: int,
        lease_seconds: int,
        event_limit: int,
        backoff_seconds: int,  # noqa
    ): ...


@dataclass(frozen=True, slots=True)
class SchedulerSettings:
    poll_seconds: float = _DEFAULT_POLL_SECONDS
    claim_limit: int = 10
    tenant_limit: int = 1_000
    lease_seconds: int = 120
    event_limit: int = 100
    retry_backoff_seconds: int = 30
    purge_limit: int = 100


@dataclass(frozen=True, slots=True)
class SchedulerCycle:
    started_at: float
    completed_at: float
    tenants_considered: int
    tenants_enabled: int
    tenants_failed: int
    tenant_limit_reached: bool
    claimed: int
    converged: int
    no_change: int
    findings: int
    retried: int
    dead_lettered: int
    cancelled: int
    purged: int
    cycle_sha256: str


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise DataUseProviderAuditSchedulerConfigurationError(
            f"provider-audit scheduler {label} is outside its bound"
        )
    return value


def _table(parent: Mapping[str, Any], key: str, label: str) -> Mapping[str, Any] | None:
    value = parent.get(key)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise DataUseProviderAuditSchedulerConfigurationError(f"{label} must be a table")
    return value


def _enabled(table: Mapping[str, Any], label: str) -> bool:
    value = table.get("enable", False)
    if not isinstance(value, bool):
        raise DataUseProviderAuditSchedulerConfigurationError(f"{label}.enable must be boolean")
    return value


def scheduler_settings(config: object) -> SchedulerSettings | None:
    """Return settings only when every audit, enforcement and provider gate is true."""

    if not isinstance(config, Mapping):
        raise DataUseProviderAuditSchedulerConfigurationError("configuration must be a table")
    root = _table(config, "data_use_governance", "data_use_governance")
    if root is None:
        return None
    root_enabled = _enabled(root, "data_use_governance")
    enforcement = _table(root, "enforcement", "data_use_governance.enforcement")
    audit = _table(root, "provider_audit", "data_use_governance.provider_audit")
    if enforcement is None or audit is None:
        return None
    enforcement_enabled = _enabled(enforcement, "data_use_governance.enforcement")
    audit_enabled = _enabled(audit, "data_use_governance.provider_audit")
    scheduler = _table(
        audit,
        "scheduler",
        "data_use_governance.provider_audit.scheduler",
    )
    if scheduler is None:
        return None
    if set(scheduler) - _SCHEDULER_KEYS:
        raise DataUseProviderAuditSchedulerConfigurationError(
            "provider-audit scheduler key is unsupported"
        )
    scheduler_enabled = _enabled(
        scheduler,
        "data_use_governance.provider_audit.scheduler",
    )
    provider_enabled = False
    for provider in ("snowflake", "databricks"):
        section = _table(root, provider, f"data_use_governance.{provider}")
        if section is not None and _enabled(section, f"data_use_governance.{provider}"):
            provider_enabled = True
    if not (
        root_enabled
        and enforcement_enabled
        and audit_enabled
        and scheduler_enabled
        and provider_enabled
    ):
        return None
    poll = scheduler.get("poll_seconds", _DEFAULT_POLL_SECONDS)
    if (
        not isinstance(poll, (int, float))
        or isinstance(poll, bool)
        or not math.isfinite(float(poll))
        or not 5 <= float(poll) <= 3_600
    ):
        raise DataUseProviderAuditSchedulerConfigurationError(
            "provider-audit scheduler poll_seconds is outside its bound"
        )
    return SchedulerSettings(
        poll_seconds=float(poll),
        claim_limit=_integer(scheduler.get("claim_limit", 10), "claim_limit", 1, 100),
        tenant_limit=_integer(
            scheduler.get("tenant_limit", 1_000),
            "tenant_limit",
            1,
            10_000,
        ),
        lease_seconds=_integer(
            scheduler.get("lease_seconds", 120),
            "lease_seconds",
            30,
            86_400,
        ),
        event_limit=_integer(
            scheduler.get("event_limit", 100),
            "event_limit",
            1,
            500,
        ),
        retry_backoff_seconds=_integer(
            scheduler.get("retry_backoff_seconds", 30),
            "retry_backoff_seconds",
            0,
            86_400,
        ),
        purge_limit=_integer(
            scheduler.get("purge_limit", 100),
            "purge_limit",
            1,
            500,
        ),
    )


def _default_config_loader() -> Mapping[str, Any]:
    from maverick.config import config_source_errors, load_global_config

    if config_source_errors(include_tenant=False):
        raise DataUseProviderAuditSchedulerConfigurationError(
            "global configuration sources are unreadable"
        )
    loaded = load_global_config() or {}
    if not isinstance(loaded, Mapping):
        raise DataUseProviderAuditSchedulerConfigurationError(
            "global configuration must be a table"
        )
    return loaded


def _default_tenant_config_loader() -> Mapping[str, Any]:
    from maverick.config import config_source_errors, load_config

    if config_source_errors(include_tenant=True):
        raise DataUseProviderAuditSchedulerConfigurationError(
            "tenant configuration sources are unreadable"
        )
    loaded = load_config() or {}
    if not isinstance(loaded, Mapping):
        raise DataUseProviderAuditSchedulerConfigurationError(
            "tenant configuration must be a table"
        )
    return loaded


def _default_tenant_supplier() -> Sequence[str]:
    floor = os.environ.get("MAVERICK_TENANT", "").strip()
    try:
        from maverick.tenant.registry import list_tenants

        records = tuple(list_tenants())
    except Exception as exc:
        raise DataUseProviderAuditSchedulerError("tenant_registry_unavailable") from exc
    tenants: list[str] = [floor] if floor else []
    for record in records:
        tenant = str(getattr(record, "id", "") or "").strip()
        if tenant and getattr(record, "active", False) and tenant not in tenants:
            tenants.append(tenant)
    return tuple(tenants or [""])


@contextmanager
def _default_tenant_context(tenant_id: str):
    from maverick.paths import reset_tenant, set_tenant

    token = set_tenant(tenant_id or None)
    try:
        yield
    finally:
        reset_tenant(token)


def _sha256(value: object) -> str:
    import json

    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _result_count(result: object, name: str) -> int:
    value = result.get(name) if isinstance(result, Mapping) else getattr(result, name, None)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise DataUseProviderAuditSchedulerError("worker_result_invalid")
    return value


class DataUseProviderAuditScheduler:
    """Thread-safe, bounded supervisor around a deployment-injected worker."""

    def __init__(
        self,
        *,
        worker_factory: Callable[[str, str], ProviderAuditWorker],
        tenant_supplier: Callable[[], Sequence[str]] = _default_tenant_supplier,
        tenant_context: Callable[[str], Any] = _default_tenant_context,
        config_loader: Callable[[], Mapping[str, Any]] = _default_config_loader,
        tenant_config_loader: Callable[[], Mapping[str, Any]] | None = None,
        clock: Callable[[], float] = time.time,
        worker_id: str | None = None,
    ) -> None:
        selected_worker = worker_id or f"provider-audit-{uuid.uuid4().hex}"
        if not isinstance(selected_worker, str) or _REF_RE.fullmatch(selected_worker) is None:
            raise ValueError("worker_id must be an opaque identifier")
        dependencies = (
            worker_factory,
            tenant_supplier,
            tenant_context,
            config_loader,
            clock,
        )
        if not all(callable(item) for item in dependencies):
            raise TypeError("provider-audit scheduler dependencies must be callable")
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
            "provider-audit-scheduler."
            + _sha256(
                {
                    "schema": "lightwork.data-use.provider-audit-worker-principal.v1",
                    "worker": selected_worker,
                }
            )[:32]
        )
        self._lock = threading.RLock()
        self._cycle_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._cycles = 0
        self._last_cycle: SchedulerCycle | None = None
        self._last_error_code: str | None = None

    def _tenants(self, limit: int) -> tuple[tuple[str, ...], bool]:
        from maverick.paths import canonical_tenant_id

        values = self._tenant_supplier()
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise DataUseProviderAuditSchedulerError("tenant_supplier_invalid")
        result: list[str] = []
        for value in values:
            if not isinstance(value, str) or len(value) > 256:
                raise DataUseProviderAuditSchedulerError("tenant_supplier_invalid")
            try:
                tenant_id = "" if value == "" else canonical_tenant_id(value)
            except Exception as exc:
                raise DataUseProviderAuditSchedulerError("tenant_supplier_invalid") from exc
            if tenant_id not in result:
                result.append(tenant_id)
        return tuple(result[:limit]), len(result) > limit

    def run_once(self) -> SchedulerCycle | None:
        if not self._cycle_lock.acquire(blocking=False):
            raise DataUseProviderAuditSchedulerError("scheduler_cycle_already_running")
        try:
            return self._run_once()
        finally:
            self._cycle_lock.release()

    def _run_once(self) -> SchedulerCycle | None:
        global_settings = scheduler_settings(self._config_loader())
        if global_settings is None:
            return None
        started = float(self._clock())
        counts: dict[str, int] = {
            "tenants_considered": 0,
            "tenants_enabled": 0,
            "tenants_failed": 0,
            "claimed": 0,
            "converged": 0,
            "no_change": 0,
            "findings": 0,
            "retried": 0,
            "dead_lettered": 0,
            "cancelled": 0,
            "purged": 0,
        }
        tenants, limit_reached = self._tenants(global_settings.tenant_limit)
        for tenant_id in tenants:
            counts["tenants_considered"] += 1
            try:
                with self._tenant_context(tenant_id):
                    tenant_settings = scheduler_settings(self._tenant_config_loader())
                    if tenant_settings is None:
                        continue
                    counts["tenants_enabled"] += 1
                    worker = self._worker_factory(tenant_id, self._worker_principal)
                    if not callable(getattr(worker, "run_once", None)) or not callable(
                        getattr(getattr(worker, "store", None), "purge_expired", None)
                    ):
                        raise DataUseProviderAuditSchedulerError("worker_dependency_invalid")
                    tenant_failed = False
                    try:
                        result = worker.run_once(
                            worker_id=self._worker_id,
                            limit=tenant_settings.claim_limit,
                            lease_seconds=tenant_settings.lease_seconds,
                            event_limit=tenant_settings.event_limit,
                            backoff_seconds=tenant_settings.retry_backoff_seconds,
                        )
                        for name in (
                            "claimed",
                            "converged",
                            "no_change",
                            "findings",
                            "retried",
                            "dead_lettered",
                            "cancelled",
                        ):
                            counts[name] += _result_count(result, name)
                    except (KeyboardInterrupt, SystemExit):
                        raise
                    except Exception as exc:  # noqa: BLE001 - no raw detail retained
                        tenant_failed = True
                        log.warning("provider-audit worker failed: %s", type(exc).__name__)
                    try:
                        purged = worker.store.purge_expired(
                            cutoff=float(self._clock()),
                            limit=tenant_settings.purge_limit,
                        )
                        if not isinstance(purged, int) or isinstance(purged, bool) or purged < 0:
                            raise DataUseProviderAuditSchedulerError("purge_result_invalid")
                        counts["purged"] += purged
                    except (KeyboardInterrupt, SystemExit):
                        raise
                    except Exception as exc:  # noqa: BLE001 - no raw detail retained
                        tenant_failed = True
                        log.warning("provider-audit retention purge failed: %s", type(exc).__name__)
                    if tenant_failed:
                        counts["tenants_failed"] += 1
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001 - health retains an enum only
                counts["tenants_failed"] += 1
                log.warning("provider-audit tenant cycle failed: %s", type(exc).__name__)
        completed = float(self._clock())
        digest = _sha256(
            {
                "schema": _CYCLE_SCHEMA,
                "started_at": started,
                "completed_at": completed,
                "tenant_limit_reached": limit_reached,
                **counts,
            }
        )
        cycle = SchedulerCycle(
            started_at=started,
            completed_at=completed,
            tenant_limit_reached=limit_reached,
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
            payload = {
                "schema": _STATUS_SCHEMA,
                "running": self._thread is not None and self._thread.is_alive(),
                "cycles": self._cycles,
                "last_cycle": (None if self._last_cycle is None else asdict(self._last_cycle)),
                "last_error_code": self._last_error_code,
                "runtime_dependencies_injected": True,
                "tenant_identifiers_retained": False,
                "provider_error_details_retained": False,
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
                delay = settings.poll_seconds
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001 - status retains an enum only
                with self._lock:
                    self._last_error_code = "scheduler_cycle_failed"
                log.warning("provider-audit scheduler cycle failed: %s", type(exc).__name__)
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
                name="data-use-provider-audit",
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


def attach_data_use_provider_audit_scheduler(
    app: Any,
    *,
    worker_factory: Callable[[str, str], ProviderAuditWorker],
    runtime: DataUseProviderAuditScheduler | None = None,
) -> DataUseProviderAuditScheduler:
    """Compose an explicitly gated scheduler with one ASGI app lifespan."""

    selected = runtime or DataUseProviderAuditScheduler(
        worker_factory=worker_factory,
    )
    router = getattr(app, "router", None)
    previous = getattr(router, "lifespan_context", None)
    state = getattr(app, "state", None)
    if router is None or state is None or not callable(previous):
        raise TypeError("app must expose a lifespan-capable router and state")
    marker = "data_use_provider_audit_scheduler"
    attached = getattr(state, marker, None)
    if attached is not None:
        if attached is selected:
            return selected
        raise RuntimeError("a provider-audit scheduler is already attached")

    @asynccontextmanager
    async def lifespan(target: Any):
        from ._lifecycle import supervised_runtime

        async with previous(target):
            async with supervised_runtime(target, "data_use_audit", selected):
                yield

    app.router.lifespan_context = lifespan
    setattr(state, marker, selected)
    return selected


__all__ = [
    "DataUseProviderAuditScheduler",
    "DataUseProviderAuditSchedulerConfigurationError",
    "DataUseProviderAuditSchedulerError",
    "attach_data_use_provider_audit_scheduler",
    "ProviderAuditStore",
    "ProviderAuditWorker",
    "SchedulerCycle",
    "SchedulerSettings",
    "scheduler_settings",
]
