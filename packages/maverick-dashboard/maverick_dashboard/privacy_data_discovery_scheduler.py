"""Managed, bounded supervisor for privacy-discovery data-map remediation.

The supervisor is explicitly opt-in and operates only Lightwork's tenant-local
durable remediation outbox plus the built-in digest-only data-map reconciler.
It never executes a discovery provider adapter, opens a provider credential,
or claims estate completeness.  Core remediation leases, authority checks,
retry/dead-letter transitions, and ambiguity reconciliation remain the source
of truth; this module supplies recurring, bounded invocation only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import secrets
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from maverick.file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

from .privacy_data_discovery_adapters_composition import (
    PrivacyDiscoveryRemediationRuntime,
    RemediationSchedulerSettings,
    build_remediation_runtime,
    remediation_scheduler_settings,
)

log = logging.getLogger(__name__)

_STATUS_SCHEMA = "lightwork.privacy-discovery-remediation-scheduler-status.v1"
_CYCLE_SCHEMA = "lightwork.privacy-discovery-remediation-scheduler-cycle.v1"
_STATE_SCHEMA = "lightwork.privacy-discovery-remediation-scheduler-state.v1"
_MAX_STATE_BYTES = 128 * 1024
_MAX_STOP_SECONDS = 30.0
_DIGEST_ONLY = True


class PrivacyDiscoverySchedulerError(RuntimeError):
    """The bounded remediation scheduler cannot proceed safely."""


@dataclass(frozen=True, slots=True)
class PrivacyDiscoverySchedulerCycle:
    started_at: float
    completed_at: float
    tenants_considered: int
    tenants_enabled: int
    tenants_failed: int
    tenant_limit_reached: bool
    ambiguous_considered: int
    ambiguous_applied: int
    ambiguous_no_change: int
    ambiguous_requeued: int
    ambiguous_unresolved: int
    claimed: int
    applied: int
    no_change: int
    retried: int
    ambiguous: int
    dead_lettered: int
    cancelled: int
    recovery_checked_tenants: int
    next_interval_seconds: int
    cycle_sha256: str


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise PrivacyDiscoverySchedulerError("scheduler_state_invalid") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now(clock: Callable[[], float]) -> float:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PrivacyDiscoverySchedulerError("scheduler_clock_invalid")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise PrivacyDiscoverySchedulerError("scheduler_clock_invalid")
    return result


def _default_global_config_loader() -> Mapping[str, Any]:
    from maverick.config import config_source_errors, load_global_config

    loaded = load_global_config() or {}
    if config_source_errors(include_tenant=False):
        raise PrivacyDiscoverySchedulerError("global_config_unreadable")
    if not isinstance(loaded, Mapping):
        raise PrivacyDiscoverySchedulerError("global_config_invalid")
    return loaded


def _default_tenant_config_loader() -> Mapping[str, Any]:
    from maverick.config import config_source_errors, load_config

    loaded = load_config() or {}
    if config_source_errors(include_tenant=True):
        raise PrivacyDiscoverySchedulerError("tenant_config_unreadable")
    if not isinstance(loaded, Mapping):
        raise PrivacyDiscoverySchedulerError("tenant_config_invalid")
    return loaded


def _default_tenant_supplier() -> Sequence[str]:
    """Return only the deployment floor and currently active tenant records."""

    floor = os.environ.get("MAVERICK_TENANT", "").strip()
    try:
        from maverick.tenant.registry import list_tenants

        records = tuple(list_tenants())
    except Exception as exc:
        raise PrivacyDiscoverySchedulerError("tenant_registry_unavailable") from exc
    registered = {
        str(getattr(record, "id", "") or "").strip(): record for record in records
    }
    tenants: list[str] = []
    if floor and (
        floor not in registered or getattr(registered[floor], "active", False) is True
    ):
        tenants.append(canonical_tenant_id(floor))
    for record in records:
        tenant = str(getattr(record, "id", "") or "").strip()
        if not tenant or getattr(record, "active", False) is not True:
            continue
        canonical = canonical_tenant_id(tenant)
        if canonical not in tenants:
            tenants.append(canonical)
    return tuple(tenants)


def _bounded_tenants(
    supplied: Sequence[str],
    limit: int,
) -> tuple[tuple[str, ...], bool]:
    if isinstance(supplied, (str, bytes)) or not isinstance(supplied, Sequence):
        raise PrivacyDiscoverySchedulerError("tenant_supplier_invalid")
    tenants: list[str] = []
    for raw in supplied:
        if not isinstance(raw, str):
            raise PrivacyDiscoverySchedulerError("tenant_supplier_invalid")
        try:
            tenant = canonical_tenant_id(raw)
        except (TypeError, ValueError) as exc:
            raise PrivacyDiscoverySchedulerError("tenant_supplier_invalid") from exc
        if tenant not in tenants:
            tenants.append(tenant)
        if len(tenants) > limit:
            break
    return tuple(tenants[:limit]), len(tenants) > limit


def _principal_ref(tenant_id: str) -> str:
    digest = hashlib.sha256(
        f"lightwork.privacy-discovery.scheduler-principal.v1:{tenant_id}".encode()
    ).hexdigest()
    return f"pdd-scheduler-principal-{digest[:32]}"


def _worker_ref(tenant_id: str) -> str:
    digest = hashlib.sha256(
        f"lightwork.privacy-discovery.scheduler-worker.v1:{tenant_id}".encode()
    ).hexdigest()
    return f"pdd-scheduler-worker-{digest[:32]}"


def _reconciliation_key(work_id: str, revision: int) -> str:
    digest = hashlib.sha256(
        f"lightwork.privacy-discovery.scheduler-reconcile.v1:{work_id}:{revision}".encode()
    ).hexdigest()
    return f"pdd-scheduler-reconcile-{digest}"


def _default_runtime_factory(
    app: Any,
    tenant_id: str,
    principal_ref: str,
) -> PrivacyDiscoveryRemediationRuntime:
    from maverick import privacy_data_discovery as discovery

    discovery_store = discovery.PrivacyDataDiscoveryStore(
        data_dir(
            "privacy_automation",
            "privacy-data-discovery.sqlite3",
            tenant=tenant_id,
        )
    )
    return build_remediation_runtime(
        app,
        tenant_id=tenant_id,
        discovery_store=discovery_store,
        principal_ref=principal_ref,
    )


def _validate_runtime(
    value: object,
    tenant_id: str,
) -> PrivacyDiscoveryRemediationRuntime:
    if (
        not isinstance(value, PrivacyDiscoveryRemediationRuntime)
        or value.tenant_id != tenant_id
        or value.digest_only_target is not True
        or value.external_side_effect is not False
        or value.provider_network_io is not False
        or value.provider_writes is not False
        or not callable(getattr(value.worker, "run_once", None))
        or not callable(getattr(value.outbox, "list_work", None))
        or not callable(getattr(value.outbox, "reconcile_ambiguous", None))
        or not callable(value.reconciler)
    ):
        raise PrivacyDiscoverySchedulerError("remediation_runtime_invalid")
    return value


def _initial_state(now: float) -> dict[str, object]:
    return {
        "schema": _STATE_SCHEMA,
        "revision": 1,
        "next_run_at": now,
        "last_started_at": 0.0,
        "last_completed_at": 0.0,
        "last_success_at": 0.0,
        "consecutive_failures": 0,
        "interrupted_cycles_recovered": 0,
        "last_error_code": "",
        "last_cycle": None,
    }


def _state_payload(body: Mapping[str, object]) -> dict[str, object]:
    selected = dict(body)
    selected["integrity_sha256"] = _sha256(selected)
    return selected


def _validated_state(raw: object) -> dict[str, object]:
    if not isinstance(raw, Mapping):
        raise PrivacyDiscoverySchedulerError("scheduler_state_invalid")
    expected = {
        "schema",
        "revision",
        "next_run_at",
        "last_started_at",
        "last_completed_at",
        "last_success_at",
        "consecutive_failures",
        "interrupted_cycles_recovered",
        "last_error_code",
        "last_cycle",
        "integrity_sha256",
    }
    if set(raw) != expected or raw.get("schema") != _STATE_SCHEMA:
        raise PrivacyDiscoverySchedulerError("scheduler_state_invalid")
    body = {key: raw[key] for key in expected if key != "integrity_sha256"}
    if raw.get("integrity_sha256") != _sha256(body):
        raise PrivacyDiscoverySchedulerError("scheduler_state_integrity_failed")
    for key in ("revision", "consecutive_failures", "interrupted_cycles_recovered"):
        value = body[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PrivacyDiscoverySchedulerError("scheduler_state_invalid")
    for key in (
        "next_run_at",
        "last_started_at",
        "last_completed_at",
        "last_success_at",
    ):
        value = body[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise PrivacyDiscoverySchedulerError("scheduler_state_invalid")
        if not math.isfinite(float(value)) or float(value) < 0:
            raise PrivacyDiscoverySchedulerError("scheduler_state_invalid")
    if body["last_error_code"] not in {
        "",
        "scheduler_cycle_failed",
        "tenant_cycle_incomplete",
    }:
        raise PrivacyDiscoverySchedulerError("scheduler_state_invalid")
    cycle = body["last_cycle"]
    if cycle is not None and (
        not isinstance(cycle, Mapping)
        or cycle.get("schema") != _CYCLE_SCHEMA
        or len(_canonical(cycle)) > 32 * 1024
    ):
        raise PrivacyDiscoverySchedulerError("scheduler_state_invalid")
    return body


class PrivacyDiscoveryRemediationScheduler:
    """One process-local thread with one durable cross-process cycle lock."""

    def __init__(  # noqa: PLR0913 - explicit scheduler dependency seams
        self,
        state_path: str | Path,
        *,
        app: Any | None = None,
        runtime_factory: Callable[[str, str], object] | None = None,
        tenant_supplier: Callable[[], Sequence[str]] = _default_tenant_supplier,
        config_loader: Callable[[], Mapping[str, Any]] = _default_global_config_loader,
        tenant_config_loader: Callable[[], Mapping[str, Any]] = (
            _default_tenant_config_loader
        ),
        clock: Callable[[], float] = time.time,
        jitter_source: Callable[[int], int] | None = None,
    ) -> None:
        if not all(
            callable(value)
            for value in (
                tenant_supplier,
                config_loader,
                tenant_config_loader,
                clock,
            )
        ):
            raise TypeError("privacy discovery scheduler dependencies must be callable")
        if runtime_factory is None:
            if app is None:
                raise TypeError("privacy discovery scheduler runtime factory is required")

            def app_runtime_factory(tenant: str, principal: str) -> object:
                return _default_runtime_factory(app, tenant, principal)

            runtime_factory = app_runtime_factory
        if not callable(runtime_factory):
            raise TypeError("privacy discovery scheduler runtime factory must be callable")
        self.state_path = Path(state_path)
        self._runtime_factory = runtime_factory
        self._tenant_supplier = tenant_supplier
        self._config_loader = config_loader
        self._tenant_config_loader = tenant_config_loader
        self._clock = clock
        self._jitter_source = jitter_source or (
            lambda maximum: secrets.randbelow(maximum + 1)
        )
        self._process_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._configured_enabled = False
        ensure_private_directory(self.state_path.parent)
        self._state_cache = self._initialize_state()

    def _initialize_state(self) -> dict[str, object]:
        with cross_process_lock(self.state_path, strict=True):
            if self.state_path.exists():
                state = self._read_state()
            else:
                state = _initial_state(_now(self._clock))
                self._write_state(state, increment=False)
        return state

    def _read_state(self) -> dict[str, object]:
        try:
            if self.state_path.stat().st_size > _MAX_STATE_BYTES:
                raise PrivacyDiscoverySchedulerError("scheduler_state_invalid")
            raw = json.loads(atomic_read_text(self.state_path, encoding="utf-8"))
        except PrivacyDiscoverySchedulerError:
            raise
        except Exception as exc:
            raise PrivacyDiscoverySchedulerError("scheduler_state_invalid") from exc
        ensure_private_file(self.state_path)
        return _validated_state(raw)

    def _write_state(
        self,
        state: Mapping[str, object],
        *,
        increment: bool = True,
    ) -> dict[str, object]:
        selected = dict(state)
        if increment:
            selected["revision"] = int(selected["revision"]) + 1
        payload = _state_payload(selected)
        encoded = _canonical(payload).decode("ascii")
        if len(encoded.encode("ascii")) > _MAX_STATE_BYTES:
            raise PrivacyDiscoverySchedulerError("scheduler_state_invalid")
        atomic_write_text(self.state_path, encoded, mode=0o600, encoding="utf-8")
        ensure_private_file(self.state_path)
        with self._state_lock:
            self._state_cache = selected
        return selected

    @contextmanager
    def _tenant(self, tenant_id: str):
        with tenant_scope(tenant=tenant_id):
            yield

    def _run_tenant(
        self,
        tenant_id: str,
        global_settings: RemediationSchedulerSettings,
    ) -> tuple[dict[str, int], int]:
        with self._tenant(tenant_id):
            tenant_settings = remediation_scheduler_settings(
                self._tenant_config_loader()
            )
            if tenant_settings is None:
                return {}, global_settings.interval_seconds
            principal = _principal_ref(tenant_id)
            runtime = _validate_runtime(
                self._runtime_factory(tenant_id, principal),
                tenant_id,
            )
            reconcile_limit = min(
                global_settings.reconcile_limit,
                tenant_settings.reconcile_limit,
            )
            worker_limit = min(
                global_settings.worker_limit,
                tenant_settings.worker_limit,
            )
            lease_seconds = min(
                global_settings.lease_seconds,
                tenant_settings.lease_seconds,
            )
            counts = {
                "ambiguous_considered": 0,
                "ambiguous_applied": 0,
                "ambiguous_no_change": 0,
                "ambiguous_requeued": 0,
                "ambiguous_unresolved": 0,
                "claimed": 0,
                "applied": 0,
                "no_change": 0,
                "retried": 0,
                "ambiguous": 0,
                "dead_lettered": 0,
                "cancelled": 0,
                "recovery_checked_tenants": 1,
            }
            ambiguous = runtime.outbox.list_work(
                state="ambiguous",
                limit=reconcile_limit,
            )
            if not isinstance(ambiguous, tuple) or len(ambiguous) > reconcile_limit:
                raise PrivacyDiscoverySchedulerError("ambiguous_list_invalid")
            counts["ambiguous_considered"] = len(ambiguous)
            for work in ambiguous:
                changed = runtime.outbox.reconcile_ambiguous(
                    work.work_id,
                    expected_revision=work.revision,
                    idempotency_key=_reconciliation_key(work.work_id, work.revision),
                    reconciler=runtime.reconciler,
                    absent_backoff_seconds=0,
                )
                if changed.state == "applied":
                    counts["ambiguous_applied"] += 1
                elif changed.state == "no_change":
                    counts["ambiguous_no_change"] += 1
                elif changed.state in {"queued", "cancelled"}:
                    counts["ambiguous_requeued"] += 1
                else:
                    counts["ambiguous_unresolved"] += 1
            result = runtime.worker.run_once(
                worker_id=_worker_ref(tenant_id),
                limit=worker_limit,
                lease_seconds=lease_seconds,
            )
            from maverick.privacy_data_discovery_remediation import (
                RemediationWorkerResult,
            )

            if type(result) is not RemediationWorkerResult:
                raise PrivacyDiscoverySchedulerError("worker_result_invalid")
            for key in (
                "claimed",
                "applied",
                "no_change",
                "retried",
                "ambiguous",
                "dead_lettered",
                "cancelled",
            ):
                value = getattr(result, key)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise PrivacyDiscoverySchedulerError("worker_result_invalid")
                counts[key] += value
            if counts["claimed"] > worker_limit:
                raise PrivacyDiscoverySchedulerError("worker_bound_exceeded")
            return counts, max(
                global_settings.interval_seconds,
                tenant_settings.interval_seconds,
            )

    def _cycle(
        self,
        settings: RemediationSchedulerSettings,
    ) -> PrivacyDiscoverySchedulerCycle:
        started = _now(self._clock)
        tenants, truncated = _bounded_tenants(
            self._tenant_supplier(),
            settings.tenant_limit,
        )
        totals = {
            "tenants_considered": len(tenants),
            "tenants_enabled": 0,
            "tenants_failed": 0,
            "ambiguous_considered": 0,
            "ambiguous_applied": 0,
            "ambiguous_no_change": 0,
            "ambiguous_requeued": 0,
            "ambiguous_unresolved": 0,
            "claimed": 0,
            "applied": 0,
            "no_change": 0,
            "retried": 0,
            "ambiguous": 0,
            "dead_lettered": 0,
            "cancelled": 0,
            "recovery_checked_tenants": 0,
        }
        next_interval = settings.interval_seconds
        for tenant_id in tenants:
            if self._stop.is_set():
                break
            try:
                counts, tenant_interval = self._run_tenant(tenant_id, settings)
                if counts:
                    totals["tenants_enabled"] += 1
                    next_interval = max(next_interval, tenant_interval)
                    for key, value in counts.items():
                        totals[key] += value
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001 - private detail is discarded
                totals["tenants_failed"] += 1
                log.warning(
                    "Privacy discovery remediation tenant cycle failed: %s",
                    type(exc).__name__,
                )
        completed = _now(self._clock)
        if completed < started:
            raise PrivacyDiscoverySchedulerError("scheduler_clock_changed")
        body = {
            "schema": _CYCLE_SCHEMA,
            "started_at": started,
            "completed_at": completed,
            **totals,
            "tenant_limit_reached": truncated,
            "next_interval_seconds": next_interval,
        }
        return PrivacyDiscoverySchedulerCycle(
            started_at=started,
            completed_at=completed,
            tenant_limit_reached=truncated,
            next_interval_seconds=next_interval,
            cycle_sha256=_sha256(body),
            **totals,
        )

    def run_once(self, *, force: bool = False) -> PrivacyDiscoverySchedulerCycle | None:
        """Run one due cycle with process and cross-process exclusion."""

        if type(force) is not bool:
            raise ValueError("force must be boolean")
        if not self._process_lock.acquire(blocking=False):
            return None
        try:
            settings = remediation_scheduler_settings(self._config_loader())
            self._configured_enabled = settings is not None
            if settings is None:
                return None
            with cross_process_lock(self.state_path, strict=True):
                state = self._read_state()
                now = _now(self._clock)
                if not force and float(state["next_run_at"]) > now:
                    with self._state_lock:
                        self._state_cache = state
                    return None
                if float(state["last_started_at"]) > float(state["last_completed_at"]):
                    state["interrupted_cycles_recovered"] = (
                        int(state["interrupted_cycles_recovered"]) + 1
                    )
                state["last_started_at"] = now
                state = self._write_state(state)
                try:
                    cycle = self._cycle(settings)
                    partial = cycle.tenants_failed > 0
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as exc:  # noqa: BLE001 - raw detail is discarded
                    failures = min(int(state["consecutive_failures"]) + 1, 31)
                    retry = min(
                        settings.retry_max_seconds,
                        5 * (2 ** min(failures - 1, 12)),
                    )
                    state.update(
                        {
                            "last_completed_at": _now(self._clock),
                            "next_run_at": _now(self._clock) + retry,
                            "consecutive_failures": failures,
                            "last_error_code": "scheduler_cycle_failed",
                        }
                    )
                    self._write_state(state)
                    log.warning(
                        "Privacy discovery remediation scheduler failed safely: %s",
                        type(exc).__name__,
                    )
                    return None
                completed = _now(self._clock)
                if partial:
                    failures = min(int(state["consecutive_failures"]) + 1, 31)
                    delay = min(
                        settings.retry_max_seconds,
                        5 * (2 ** min(failures - 1, 12)),
                    )
                    error_code = "tenant_cycle_incomplete"
                    last_success = float(state["last_success_at"])
                else:
                    jitter_bound = min(
                        settings.jitter_seconds,
                        cycle.next_interval_seconds,
                    )
                    jitter = self._jitter_source(jitter_bound)
                    if (
                        isinstance(jitter, bool)
                        or not isinstance(jitter, int)
                        or not 0 <= jitter <= jitter_bound
                    ):
                        raise PrivacyDiscoverySchedulerError("scheduler_jitter_invalid")
                    failures = 0
                    delay = cycle.next_interval_seconds + jitter
                    error_code = ""
                    last_success = completed
                state.update(
                    {
                        "last_completed_at": completed,
                        "last_success_at": last_success,
                        "next_run_at": completed + delay,
                        "consecutive_failures": failures,
                        "last_error_code": error_code,
                        "last_cycle": {"schema": _CYCLE_SCHEMA, **asdict(cycle)},
                    }
                )
                self._write_state(state)
                return cycle
        finally:
            self._process_lock.release()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                settings = remediation_scheduler_settings(self._config_loader())
                self._configured_enabled = settings is not None
                if settings is None:
                    return
                self.run_once()
                with self._state_lock:
                    next_run = float(self._state_cache["next_run_at"])
                delay = max(0.1, min(60.0, next_run - _now(self._clock)))
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001 - raw detail is discarded
                log.warning(
                    "Privacy discovery remediation scheduler loop degraded: %s",
                    type(exc).__name__,
                )
                delay = 5.0
            self._stop.wait(delay)

    def start(self, *, config: Mapping[str, Any] | None = None) -> bool:
        selected = config if config is not None else self._config_loader()
        settings = remediation_scheduler_settings(selected)
        self._configured_enabled = settings is not None
        if settings is None:
            return False
        with self._state_lock:
            if self._thread is not None and self._thread.is_alive():
                return True
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop,
                name="privacy-discovery-remediation",
                daemon=True,
            )
            self._thread.start()
        return True

    def stop(self, *, timeout: float = 5.0, wait: bool = True) -> bool:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
        ):
            raise ValueError("scheduler stop timeout must be finite")
        wait_seconds = max(0.0, min(float(timeout), _MAX_STOP_SECONDS))
        self._stop.set()
        with self._state_lock:
            worker = self._thread
        if worker is None:
            return False
        if not wait:
            return False
        worker.join(wait_seconds)
        if worker.is_alive():
            return False
        with self._state_lock:
            if self._thread is worker:
                self._thread = None
        return True

    def status(self) -> Mapping[str, object]:
        """Return tenant-free cached state; no provider or tenant store is opened."""

        with self._state_lock:
            state = dict(self._state_cache)
            running = self._thread is not None and self._thread.is_alive()
        payload = {
            "schema": _STATUS_SCHEMA,
            "installed": True,
            "configured_enabled": self._configured_enabled,
            "running": running,
            "healthy": bool(
                self._configured_enabled
                and running
                and int(state["consecutive_failures"]) == 0
            ),
            "next_run_at": state["next_run_at"],
            "last_started_at": state["last_started_at"],
            "last_completed_at": state["last_completed_at"],
            "last_success_at": state["last_success_at"],
            "consecutive_failures": state["consecutive_failures"],
            "interrupted_cycles_recovered": state["interrupted_cycles_recovered"],
            "last_error_code": state["last_error_code"] or None,
            "last_cycle": state["last_cycle"],
            "state_revision": state["revision"],
            "process_concurrency_excluded": True,
            "cross_process_concurrency_excluded": True,
            "status_opened_tenant_store": False,
            "status_invoked_provider": False,
            "digest_only_data_map_target": _DIGEST_ONLY,
            "provider_network_io": False,
            "provider_writes": False,
            "estate_completeness_claimed": False,
            "live_provider_acceptance_verified": False,
        }
        return {**payload, "status_sha256": _sha256(payload)}


def _disabled_status(*, configured: bool = False) -> Mapping[str, object]:
    payload = {
        "schema": _STATUS_SCHEMA,
        "installed": True,
        "configured_enabled": configured,
        "running": False,
        "healthy": False,
        "next_run_at": None,
        "last_started_at": None,
        "last_completed_at": None,
        "last_success_at": None,
        "consecutive_failures": 0,
        "interrupted_cycles_recovered": 0,
        "last_error_code": None,
        "last_cycle": None,
        "state_revision": 0,
        "process_concurrency_excluded": True,
        "cross_process_concurrency_excluded": True,
        "status_opened_tenant_store": False,
        "status_invoked_provider": False,
        "digest_only_data_map_target": True,
        "provider_network_io": False,
        "provider_writes": False,
        "estate_completeness_claimed": False,
        "live_provider_acceptance_verified": False,
    }
    return {**payload, "status_sha256": _sha256(payload)}


def install_privacy_data_discovery_scheduler(app: Any) -> None:
    """Install content-free app-state seams without starting or opening stores."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    existing = getattr(
        state,
        "privacy_data_discovery_worker_scheduler_status",
        None,
    )
    if existing is not None and not callable(existing):
        raise TypeError("privacy discovery scheduler status authority is invalid")
    if existing is None:
        state.privacy_data_discovery_worker_scheduler_status = (
            lambda: privacy_data_discovery_scheduler_status(app)
        )
    operational = getattr(
        state,
        "privacy_data_discovery_worker_scheduler_operational",
        False,
    )
    if type(operational) is not bool:
        raise TypeError("privacy discovery scheduler operational marker is invalid")
    state.privacy_data_discovery_worker_scheduler_operational = False


def start_privacy_data_discovery_scheduler(app: Any) -> bool:
    """Start the app-owned scheduler only after the global opt-in is valid."""

    install_privacy_data_discovery_scheduler(app)
    config = _default_global_config_loader()
    settings = remediation_scheduler_settings(config)
    app.state.privacy_data_discovery_worker_scheduler_configured = settings is not None
    if settings is None:
        app.state.privacy_data_discovery_worker_scheduler_operational = False
        return False
    runtime = getattr(
        app.state,
        "privacy_data_discovery_worker_scheduler_runtime",
        None,
    )
    if runtime is None:
        path_factory = getattr(
            app.state,
            "privacy_data_discovery_worker_scheduler_path_factory",
            None,
        )
        if path_factory is not None and not callable(path_factory):
            raise TypeError("privacy discovery scheduler path factory is invalid")
        path = (
            path_factory()
            if callable(path_factory)
            else data_dir(
                "privacy_automation",
                "privacy-discovery-remediation-scheduler.json",
                tenant=None,
            )
        )
        runtime = PrivacyDiscoveryRemediationScheduler(path, app=app)
        app.state.privacy_data_discovery_worker_scheduler_runtime = runtime
    if not isinstance(runtime, PrivacyDiscoveryRemediationScheduler):
        raise TypeError("privacy discovery scheduler runtime is invalid")
    started = runtime.start(config=config)
    running = runtime.status().get("running") is True
    app.state.privacy_data_discovery_worker_scheduler_operational = running
    return bool(started and running)


def stop_privacy_data_discovery_scheduler(
    app: Any,
    *,
    timeout: float = 5.0,
) -> bool:
    runtime = getattr(
        getattr(app, "state", None),
        "privacy_data_discovery_worker_scheduler_runtime",
        None,
    )
    if runtime is None:
        if getattr(app, "state", None) is not None:
            app.state.privacy_data_discovery_worker_scheduler_operational = False
        return False
    if not isinstance(runtime, PrivacyDiscoveryRemediationScheduler):
        raise TypeError("privacy discovery scheduler runtime is invalid")
    stopped = runtime.stop(timeout=timeout)
    app.state.privacy_data_discovery_worker_scheduler_operational = False
    return stopped


def privacy_data_discovery_scheduler_status(app: Any) -> Mapping[str, object]:
    runtime = getattr(
        getattr(app, "state", None),
        "privacy_data_discovery_worker_scheduler_runtime",
        None,
    )
    if runtime is None:
        return _disabled_status(
            configured=(
                getattr(
                    getattr(app, "state", None),
                    "privacy_data_discovery_worker_scheduler_configured",
                    False,
                )
                is True
            )
        )
    if not isinstance(runtime, PrivacyDiscoveryRemediationScheduler):
        raise TypeError("privacy discovery scheduler runtime is invalid")
    return runtime.status()


__all__ = [
    "PrivacyDiscoveryRemediationScheduler",
    "PrivacyDiscoverySchedulerCycle",
    "PrivacyDiscoverySchedulerError",
    "install_privacy_data_discovery_scheduler",
    "privacy_data_discovery_scheduler_status",
    "start_privacy_data_discovery_scheduler",
    "stop_privacy_data_discovery_scheduler",
]
