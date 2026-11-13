"""Bounded cross-tenant supervisor for continuous technology evidence.

The core authority owns schedules, leases, retries, dead letters, observations,
and audit integrity.  This process supervisor only visits active tenant
namespaces, applies each tenant's explicit opt-in, and drives bounded batches.
Collector registries and credential resolvers are server-injected; health state
contains only counts and digests, never tenant identifiers or provider errors.
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

from maverick.trc_continuous_evidence import run_claimed_collection
from maverick.trc_evidence_collectors import CollectorRegistry, LocalSoc2Collector

log = logging.getLogger(__name__)

_STATUS_SCHEMA = "lightwork.trc-continuous-evidence-scheduler-status.v1"
_CYCLE_SCHEMA = "lightwork.trc-continuous-evidence-scheduler-cycle.v1"
_SCHEDULER_KEYS = frozenset(
    {
        "enable",
        "poll_seconds",
        "enqueue_limit",
        "claim_limit",
        "tenant_limit",
        "lease_seconds",
        "retry_backoff_seconds",
    }
)
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_COLLECTOR_RE = re.compile(r"[a-z][a-z0-9_.-]{0,95}\Z")
_DEFAULT_POLL_SECONDS = 60.0
_MAX_STOP_SECONDS = 30.0


class TrcEvidenceSchedulerError(RuntimeError):
    """Base continuous-evidence scheduler error."""


class TrcEvidenceSchedulerConfigurationError(TrcEvidenceSchedulerError, ValueError):
    """The closed scheduler configuration is malformed."""


class EvidenceAuthority(Protocol):
    tenant_id: str

    def enqueue_due(self, *, limit: int, allowed_collector_ids: Sequence[str]): ...

    def claim_jobs(self, *, worker_id: str, limit: int, lease_seconds: int): ...


@dataclass(frozen=True, slots=True)
class SchedulerSettings:
    enabled_collectors: tuple[str, ...]
    poll_seconds: float = _DEFAULT_POLL_SECONDS
    enqueue_limit: int = 50
    claim_limit: int = 10
    tenant_limit: int = 1_000
    lease_seconds: int = 120
    retry_backoff_seconds: int = 30


@dataclass(frozen=True, slots=True)
class SchedulerCycle:
    started_at: float
    completed_at: float
    tenants_considered: int
    tenants_enabled: int
    tenants_failed: int
    jobs_enqueued: int
    jobs_claimed: int
    jobs_completed: int
    jobs_incomplete: int
    jobs_retry_pending: int
    jobs_dead_lettered: int
    cycle_sha256: str


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise TrcEvidenceSchedulerConfigurationError(
            f"continuous-evidence scheduler {label} is outside its bound"
        )
    return value


def configured_collector_ids(config: object) -> tuple[str, ...] | None:
    """Return the exact feature allowlist, failing closed on malformed input."""

    if not isinstance(config, Mapping):
        raise TrcEvidenceSchedulerConfigurationError("configuration must be a table")
    root = config.get("tech_risk_compliance")
    if root is None:
        return None
    if not isinstance(root, Mapping):
        raise TrcEvidenceSchedulerConfigurationError("tech_risk_compliance must be a table")
    feature = root.get("continuous_evidence")
    if feature is None:
        return None
    if not isinstance(feature, Mapping):
        raise TrcEvidenceSchedulerConfigurationError(
            "tech_risk_compliance.continuous_evidence must be a table"
        )
    if root.get("enable") is not True or feature.get("enable") is not True:
        return None
    raw = feature.get("enabled_collectors")
    if (
        not isinstance(raw, list)
        or not raw
        or len(raw) > 32
        or any(not isinstance(item, str) or _COLLECTOR_RE.fullmatch(item) is None for item in raw)
        or len(set(raw)) != len(raw)
    ):
        raise TrcEvidenceSchedulerConfigurationError(
            "continuous evidence requires a unique closed collector allowlist"
        )
    return tuple(raw)


def scheduler_settings(config: object) -> SchedulerSettings | None:
    """Return settings only when root, feature, and scheduler gates are true."""

    if not isinstance(config, Mapping):
        raise TrcEvidenceSchedulerConfigurationError("configuration must be a table")
    root = config.get("tech_risk_compliance")
    if root is None:
        return None
    if not isinstance(root, Mapping):
        raise TrcEvidenceSchedulerConfigurationError("tech_risk_compliance must be a table")
    root_enabled = root.get("enable", False)
    if not isinstance(root_enabled, bool):
        raise TrcEvidenceSchedulerConfigurationError("tech_risk_compliance.enable must be boolean")
    feature = root.get("continuous_evidence")
    if feature is None:
        return None
    if not isinstance(feature, Mapping):
        raise TrcEvidenceSchedulerConfigurationError(
            "tech_risk_compliance.continuous_evidence must be a table"
        )
    feature_enabled = feature.get("enable", False)
    if not isinstance(feature_enabled, bool):
        raise TrcEvidenceSchedulerConfigurationError("continuous_evidence.enable must be boolean")
    raw = feature.get("scheduler")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise TrcEvidenceSchedulerConfigurationError(
            "continuous_evidence.scheduler must be a table"
        )
    if set(raw) - _SCHEDULER_KEYS:
        raise TrcEvidenceSchedulerConfigurationError(
            "continuous-evidence scheduler key is unsupported"
        )
    scheduler_enabled = raw.get("enable", False)
    if not isinstance(scheduler_enabled, bool):
        raise TrcEvidenceSchedulerConfigurationError(
            "continuous_evidence.scheduler.enable must be boolean"
        )
    if not (root_enabled and feature_enabled and scheduler_enabled):
        return None
    enabled_collectors = configured_collector_ids(config)
    if enabled_collectors is None:
        raise TrcEvidenceSchedulerConfigurationError(
            "continuous-evidence collector allowlist is unavailable"
        )
    poll = raw.get("poll_seconds", _DEFAULT_POLL_SECONDS)
    if (
        not isinstance(poll, (int, float))
        or isinstance(poll, bool)
        or not math.isfinite(float(poll))
        or not 5 <= float(poll) <= 3_600
    ):
        raise TrcEvidenceSchedulerConfigurationError(
            "continuous-evidence scheduler poll_seconds is outside its bound"
        )
    return SchedulerSettings(
        enabled_collectors=enabled_collectors,
        poll_seconds=float(poll),
        enqueue_limit=_integer(raw.get("enqueue_limit", 50), "enqueue_limit", 1, 500),
        claim_limit=_integer(raw.get("claim_limit", 10), "claim_limit", 1, 100),
        tenant_limit=_integer(raw.get("tenant_limit", 1_000), "tenant_limit", 1, 10_000),
        lease_seconds=_integer(raw.get("lease_seconds", 120), "lease_seconds", 30, 3_600),
        retry_backoff_seconds=_integer(
            raw.get("retry_backoff_seconds", 30),
            "retry_backoff_seconds",
            1,
            86_400,
        ),
    )


def _default_config_loader() -> Mapping[str, Any]:
    from maverick.config import config_source_errors, load_global_config

    if config_source_errors(include_tenant=False):
        raise TrcEvidenceSchedulerConfigurationError("global configuration sources are unreadable")
    loaded = load_global_config() or {}
    if not isinstance(loaded, Mapping):
        raise TrcEvidenceSchedulerConfigurationError("global configuration must be a table")
    return loaded


def _default_tenant_config_loader() -> Mapping[str, Any]:
    from maverick.config import config_source_errors, load_config

    if config_source_errors(include_tenant=True):
        raise TrcEvidenceSchedulerConfigurationError("tenant configuration sources are unreadable")
    loaded = load_config() or {}
    if not isinstance(loaded, Mapping):
        raise TrcEvidenceSchedulerConfigurationError("tenant configuration must be a table")
    return loaded


def _default_tenant_supplier() -> Sequence[str]:
    floor = os.environ.get("MAVERICK_TENANT", "").strip()
    try:
        from maverick.tenant.registry import list_tenants

        records = tuple(list_tenants())
    except Exception as exc:
        raise TrcEvidenceSchedulerError("tenant_registry_unavailable") from exc
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


def _default_authority_factory(tenant_id: str, worker_principal: str):
    from maverick.paths import data_dir
    from maverick.trc_continuous_evidence import ContinuousEvidenceStore

    return ContinuousEvidenceStore(
        data_dir(
            "tech_risk_compliance",
            "continuous-evidence.sqlite3",
            tenant=tenant_id or None,
        ),
        tenant_id=tenant_id or "default",
        principal_resolver=lambda: worker_principal,
    )


def _default_registry_factory(_tenant_id: str) -> CollectorRegistry:
    local = LocalSoc2Collector()
    return CollectorRegistry({local.collector_id: local})


def _default_credential_resolver(
    _tenant_id: str,
    _enrollment_id: str,
    _enrollment_revision: int,
    _credential_profile_sha256: str,
) -> None:
    return None


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


class TrcContinuousEvidenceScheduler:
    """Thread-safe bounded supervisor with digest-only status."""

    def __init__(
        self,
        *,
        authority_factory: Callable[[str, str], EvidenceAuthority] = _default_authority_factory,
        registry_factory: Callable[[str], CollectorRegistry] = _default_registry_factory,
        credential_resolver: Callable[[str, str, int, str], object | None] = (
            _default_credential_resolver
        ),
        tenant_supplier: Callable[[], Sequence[str]] = _default_tenant_supplier,
        tenant_context: Callable[[str], Any] = _default_tenant_context,
        config_loader: Callable[[], Mapping[str, Any]] = _default_config_loader,
        tenant_config_loader: Callable[[], Mapping[str, Any]] | None = None,
        clock: Callable[[], float] = time.time,
        worker_id: str | None = None,
    ) -> None:
        selected_worker = worker_id or f"trc-evidence-{uuid.uuid4().hex}"
        if not isinstance(selected_worker, str) or not _REF_RE.fullmatch(selected_worker):
            raise ValueError("worker_id must be an opaque identifier")
        dependencies = (
            authority_factory,
            registry_factory,
            credential_resolver,
            tenant_supplier,
            tenant_context,
            config_loader,
            clock,
        )
        if not all(callable(item) for item in dependencies):
            raise TypeError("scheduler dependencies must be callable")
        self._authority_factory = authority_factory
        self._registry_factory = registry_factory
        self._credential_resolver = credential_resolver
        self._custom_collector_dependencies_injected = bool(
            registry_factory is not _default_registry_factory
            and credential_resolver is not _default_credential_resolver
        )
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
            "trc-scheduler."
            + _sha256(
                {"schema": "lightwork.trc-evidence-worker-principal.v1", "worker": selected_worker}
            )[:32]
        )
        self._lock = threading.RLock()
        self._cycle_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._cycles = 0
        self._last_cycle: SchedulerCycle | None = None
        self._last_error_code: str | None = None

    def _tenants(self, limit: int) -> tuple[str, ...]:
        from maverick.paths import canonical_tenant_id

        values = self._tenant_supplier()
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise TrcEvidenceSchedulerError("tenant_supplier_invalid")
        result: list[str] = []
        for value in values:
            if not isinstance(value, str) or len(value) > 256:
                raise TrcEvidenceSchedulerError("tenant_supplier_invalid")
            try:
                tenant_id = "" if value == "" else canonical_tenant_id(value)
            except Exception as exc:
                raise TrcEvidenceSchedulerError("tenant_supplier_invalid") from exc
            if tenant_id not in result:
                result.append(tenant_id)
            if len(result) >= limit:
                break
        return tuple(result)

    def run_once(self) -> SchedulerCycle | None:
        if not self._cycle_lock.acquire(blocking=False):
            raise TrcEvidenceSchedulerError("scheduler_cycle_already_running")
        try:
            return self._run_once()
        finally:
            self._cycle_lock.release()

    def _run_once(self) -> SchedulerCycle | None:
        global_settings = scheduler_settings(self._config_loader())
        if global_settings is None:
            return None
        started = float(self._clock())
        counts = {
            "tenants_considered": 0,
            "tenants_enabled": 0,
            "tenants_failed": 0,
            "jobs_enqueued": 0,
            "jobs_claimed": 0,
            "jobs_completed": 0,
            "jobs_incomplete": 0,
            "jobs_retry_pending": 0,
            "jobs_dead_lettered": 0,
        }
        for tenant_id in self._tenants(global_settings.tenant_limit):
            counts["tenants_considered"] += 1
            try:
                with self._tenant_context(tenant_id):
                    tenant_settings = scheduler_settings(self._tenant_config_loader())
                    if tenant_settings is None:
                        continue
                    counts["tenants_enabled"] += 1
                    authority = self._authority_factory(tenant_id, self._worker_principal)
                    registry = self._registry_factory(tenant_id)
                    enqueued = authority.enqueue_due(
                        limit=tenant_settings.enqueue_limit,
                        allowed_collector_ids=tenant_settings.enabled_collectors,
                    )
                    counts["jobs_enqueued"] += len(enqueued)
                    claimed = authority.claim_jobs(
                        worker_id=self._worker_id,
                        limit=tenant_settings.claim_limit,
                        lease_seconds=tenant_settings.lease_seconds,
                    )
                    counts["jobs_claimed"] += len(claimed)
                    tenant_failed = False
                    for item in claimed:
                        try:
                            outcome = run_claimed_collection(
                                authority,
                                item,
                                registry=registry,
                                resolve_credential=self._credential_resolver,
                                allowed_collector_ids=tenant_settings.enabled_collectors,
                                retry_backoff_seconds=tenant_settings.retry_backoff_seconds,
                            )
                        except (KeyboardInterrupt, SystemExit):
                            raise
                        except Exception as exc:  # noqa: BLE001 - detail is never retained
                            tenant_failed = True
                            log.warning(
                                "continuous-evidence job failed: %s",
                                type(exc).__name__,
                            )
                            continue
                        if outcome.job.state == "completed":
                            counts["jobs_completed"] += 1
                        elif outcome.job.state == "incomplete":
                            counts["jobs_incomplete"] += 1
                        elif outcome.job.state == "dead_letter":
                            counts["jobs_dead_lettered"] += 1
                        elif outcome.job.state == "queued":
                            counts["jobs_retry_pending"] += 1
                    if tenant_failed:
                        counts["tenants_failed"] += 1
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001 - no raw exception leaves health state
                counts["tenants_failed"] += 1
                log.warning(
                    "continuous-evidence tenant cycle failed: %s",
                    type(exc).__name__,
                )
        completed = float(self._clock())
        digest = _sha256(
            {
                "schema": _CYCLE_SCHEMA,
                "started_at": started,
                "completed_at": completed,
                **counts,
            }
        )
        cycle = SchedulerCycle(
            started_at=started,
            completed_at=completed,
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
            cycle = None if self._last_cycle is None else asdict(self._last_cycle)
            payload = {
                "schema": _STATUS_SCHEMA,
                "running": self._thread is not None and self._thread.is_alive(),
                "cycles": self._cycles,
                "last_cycle": cycle,
                "last_error_code": self._last_error_code,
                "custom_collector_dependencies_injected": (
                    self._custom_collector_dependencies_injected
                ),
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
            except Exception as exc:  # noqa: BLE001 - stored error is enumerated only
                with self._lock:
                    self._last_error_code = "scheduler_cycle_failed"
                log.warning("continuous-evidence scheduler cycle failed: %s", type(exc).__name__)
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
                name="trc-continuous-evidence",
                daemon=True,
            )
            self._thread.start()
        return True

    def stop(self, timeout: float = _MAX_STOP_SECONDS, *, wait: bool = True) -> None:
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
            return
        if thread is not None:
            thread.join(float(timeout))
        with self._lock:
            if self._thread is thread and (thread is None or not thread.is_alive()):
                self._thread = None


_default_lock = threading.Lock()
_default_runtime: TrcContinuousEvidenceScheduler | None = None


def default_scheduler() -> TrcContinuousEvidenceScheduler:
    """Return the process singleton used by app lifespan and status routes."""

    global _default_runtime
    with _default_lock:
        if _default_runtime is None:
            _default_runtime = TrcContinuousEvidenceScheduler()
        return _default_runtime


def start_trc_continuous_evidence_scheduler() -> bool:
    return default_scheduler().start()


def stop_trc_continuous_evidence_scheduler(*, timeout: float = 5.0) -> None:
    default_scheduler().stop(timeout=timeout)


def attach_trc_continuous_evidence_scheduler(
    app: Any,
    *,
    runtime: TrcContinuousEvidenceScheduler | None = None,
) -> TrcContinuousEvidenceScheduler:
    """Compose bounded scheduler startup/shutdown with an ASGI lifespan."""

    factory = getattr(
        getattr(app, "state", None),
        "trc_stock_evidence_scheduler_factory",
        None,
    )
    if runtime is not None:
        selected = runtime
    elif callable(factory):
        selected = factory()
    else:
        selected = default_scheduler()
    router = getattr(app, "router", None)
    previous = getattr(router, "lifespan_context", None)
    if router is None or not callable(previous):
        raise TypeError("app must expose a lifespan-capable router")
    marker = "trc_continuous_evidence_scheduler"
    attached = getattr(getattr(app, "state", None), marker, None)
    if attached is not None:
        if attached is selected:
            return selected
        raise RuntimeError("a continuous-evidence scheduler is already attached")

    @asynccontextmanager
    async def lifespan(target: Any):
        from ._lifecycle import supervised_runtime

        async with previous(target):
            async with supervised_runtime(target, "trc_evidence", selected):
                yield

    app.router.lifespan_context = lifespan
    setattr(app.state, marker, selected)
    return selected


__all__ = [
    "SchedulerCycle",
    "SchedulerSettings",
    "TrcContinuousEvidenceScheduler",
    "TrcEvidenceSchedulerConfigurationError",
    "TrcEvidenceSchedulerError",
    "attach_trc_continuous_evidence_scheduler",
    "configured_collector_ids",
    "default_scheduler",
    "scheduler_settings",
    "start_trc_continuous_evidence_scheduler",
    "stop_trc_continuous_evidence_scheduler",
]
