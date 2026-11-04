"""Bounded app-lifespan scheduler for local notice publication intents.

Only explicitly configured active tenants are considered.  A process-local
mutex and the repository cross-process lock serialize cycles.  Durable,
integrity-bound status records interrupted-cycle recovery and bounded retry
timing without retaining tenant identifiers, lease tokens, release content, or
publication evidence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import threading
import time
from collections.abc import Callable, Mapping, Sequence
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
from maverick.paths import canonical_tenant_id, data_dir

from .privacy_notice_publication_composition import (
    PrivacyNoticePublicationRuntime,
    PrivacyNoticePublicationSettings,
    settings_from_config,
)

log = logging.getLogger(__name__)

_STATE_SCHEMA = "lightwork.privacy-notice-publication-scheduler-state.v1"
_STATUS_SCHEMA = "lightwork.privacy-notice-publication-scheduler-status.v1"
_CYCLE_SCHEMA = "lightwork.privacy-notice-publication-scheduler-cycle.v1"


class PrivacyNoticePublicationSchedulerError(RuntimeError):
    """The managed local publication scheduler cannot proceed safely."""


class PrivacyNoticePublicationSchedulerBusy(PrivacyNoticePublicationSchedulerError):
    """A process-local publication cycle is already running."""


@dataclass(frozen=True, slots=True)
class PublicationSchedulerCycle:
    started_at: float
    completed_at: float
    tenants_considered: int
    tenants_executed: int
    tenants_failed: int
    tenant_limit_reached: bool
    applied: int
    recovered: int
    no_change: int
    idle: int
    ambiguous: int
    failed: int
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
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PrivacyNoticePublicationSchedulerError("scheduler state is invalid") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PrivacyNoticePublicationSchedulerError("scheduler clock is invalid")
    selected = float(value)
    if not math.isfinite(selected) or selected <= 0:
        raise PrivacyNoticePublicationSchedulerError("scheduler clock is invalid")
    return selected


def _load_global_config() -> Mapping[str, Any]:
    try:
        from maverick.config import config_source_errors, load_global_config

        loaded = load_global_config() or {}
        errors = config_source_errors(include_tenant=False)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyNoticePublicationSchedulerError(
            "global publication configuration is unavailable"
        ) from exc
    if errors or not isinstance(loaded, Mapping):
        raise PrivacyNoticePublicationSchedulerError(
            "global publication configuration is invalid"
        )
    return loaded


def _default_active_tenant_supplier() -> Sequence[str]:
    floor = os.environ.get("MAVERICK_TENANT", "").strip()
    values: list[str] = []
    try:
        from maverick.tenant.registry import list_tenants

        records = tuple(list_tenants())
    except Exception as exc:
        if not floor:
            raise PrivacyNoticePublicationSchedulerError(
                "active tenant authority is unavailable"
            ) from exc
        records = ()
    if floor:
        values.append(canonical_tenant_id(floor))
    for record in records:
        raw = str(getattr(record, "id", "") or "").strip()
        if not raw or getattr(record, "active", False) is not True:
            continue
        tenant = canonical_tenant_id(raw)
        if tenant not in values:
            values.append(tenant)
    return tuple(values)


def _initial_state(now: float) -> dict[str, object]:
    return {
        "schema": _STATE_SCHEMA,
        "revision": 1,
        "in_progress": False,
        "last_started_at": 0.0,
        "last_completed_at": 0.0,
        "last_success_at": 0.0,
        "next_run_at": now,
        "consecutive_failures": 0,
        "interrupted_cycles_recovered": 0,
        "last_error_code": "",
        "last_cycle": None,
    }


def _seal(state: Mapping[str, object]) -> dict[str, object]:
    body = dict(state)
    return {**body, "integrity_sha256": _sha256(body)}


def _validate_state(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise PrivacyNoticePublicationSchedulerError("scheduler state is invalid")
    expected = {
        "schema",
        "revision",
        "in_progress",
        "last_started_at",
        "last_completed_at",
        "last_success_at",
        "next_run_at",
        "consecutive_failures",
        "interrupted_cycles_recovered",
        "last_error_code",
        "last_cycle",
        "integrity_sha256",
    }
    if set(value) != expected or value.get("schema") != _STATE_SCHEMA:
        raise PrivacyNoticePublicationSchedulerError("scheduler state is invalid")
    body = {key: value[key] for key in expected if key != "integrity_sha256"}
    if not isinstance(value.get("integrity_sha256"), str) or not hmac_equal(
        str(value["integrity_sha256"]), _sha256(body)
    ):
        raise PrivacyNoticePublicationSchedulerError(
            "scheduler state integrity verification failed"
        )
    if type(body["in_progress"]) is not bool:
        raise PrivacyNoticePublicationSchedulerError("scheduler state is invalid")
    for key in ("revision", "consecutive_failures", "interrupted_cycles_recovered"):
        item = body[key]
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise PrivacyNoticePublicationSchedulerError("scheduler state is invalid")
    for key in (
        "last_started_at",
        "last_completed_at",
        "last_success_at",
        "next_run_at",
    ):
        item = body[key]
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise PrivacyNoticePublicationSchedulerError("scheduler state is invalid")
        if not math.isfinite(float(item)) or float(item) < 0:
            raise PrivacyNoticePublicationSchedulerError("scheduler state is invalid")
    if body["last_error_code"] not in {"", "cycle_failed", "tenant_failed"}:
        raise PrivacyNoticePublicationSchedulerError("scheduler state is invalid")
    return body


def hmac_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode(), right.encode())


class PrivacyNoticePublicationScheduler:
    """One bounded thread and one durable cross-process cycle authority."""

    def __init__(  # noqa: PLR0913 - explicit scheduler seams are intentional
        self,
        state_path: str | Path,
        *,
        runtime_factory: Callable[[str], object],
        config_loader: Callable[[], Mapping[str, Any]] = _load_global_config,
        active_tenant_supplier: Callable[[], Sequence[str]] = (
            _default_active_tenant_supplier
        ),
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not all(
            callable(value)
            for value in (runtime_factory, config_loader, active_tenant_supplier, clock)
        ):
            raise PrivacyNoticePublicationSchedulerError(
                "scheduler dependencies are incomplete"
            )
        self.path = Path(state_path)
        self._runtime_factory = runtime_factory
        self._config_loader = config_loader
        self._active_tenant_supplier = active_tenant_supplier
        self._clock = clock
        self._cycle_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._configured_enabled = False
        self._runtime_enabled = False
        ensure_private_directory(self.path.parent)
        now = _timestamp(self._clock())
        with cross_process_lock(self.path, strict=True):
            if self.path.exists():
                ensure_private_file(self.path, 0o600)
                self._state = self._read_state()
            else:
                self._state = _initial_state(now)
                self._write_state(self._state)

    def _read_state(self) -> dict[str, object]:
        try:
            encoded = atomic_read_text(self.path)
            if not 1 <= len(encoded.encode("utf-8")) <= 128 * 1024:
                raise ValueError("scheduler state exceeds its bound")
            raw = json.loads(encoded)
        except Exception as exc:
            raise PrivacyNoticePublicationSchedulerError(
                "scheduler state is unavailable"
            ) from exc
        return _validate_state(raw)

    def _write_state(self, state: Mapping[str, object]) -> None:
        atomic_write_text(
            self.path,
            _canonical(_seal(state)).decode("ascii"),
            mode=0o600,
        )
        ensure_private_file(self.path, 0o600)
        with self._state_lock:
            self._state = dict(state)

    def _settings(self) -> PrivacyNoticePublicationSettings:
        loaded = self._config_loader()
        if not isinstance(loaded, Mapping):
            raise PrivacyNoticePublicationSchedulerError(
                "scheduler configuration is invalid"
            )
        settings = settings_from_config(loaded)
        self._runtime_enabled = settings.enabled
        self._configured_enabled = bool(settings.enabled and settings.scheduler_enabled)
        return settings

    def _eligible_tenants(
        self,
        settings: PrivacyNoticePublicationSettings,
        requested_tenant: str | None,
    ) -> tuple[tuple[str, ...], bool]:
        try:
            supplied = tuple(self._active_tenant_supplier())
            active = {canonical_tenant_id(item) for item in supplied}
        except (TypeError, ValueError) as exc:
            raise PrivacyNoticePublicationSchedulerError(
                "active tenant authority is invalid"
            ) from exc
        configured = [tenant for tenant in settings.active_tenants if tenant in active]
        if requested_tenant is not None:
            requested = canonical_tenant_id(requested_tenant)
            if requested not in configured:
                raise PrivacyNoticePublicationSchedulerError(
                    "tenant is not an active configured publication target"
                )
            return (requested,), False
        limited = len(configured) > settings.tenant_limit
        return tuple(configured[: settings.tenant_limit]), limited

    def run_once(self, tenant_id: str | None = None) -> PublicationSchedulerCycle:
        """Run one serialized, bounded cycle; the optional tenant is server-derived."""

        if not self._cycle_lock.acquire(blocking=False):
            raise PrivacyNoticePublicationSchedulerBusy(
                "a publication cycle is already running"
            )
        try:
            with cross_process_lock(self.path, strict=True):
                settings = self._settings()
                if not settings.enabled:
                    raise PrivacyNoticePublicationSchedulerError(
                        "publication runtime is disabled"
                    )
                if tenant_id is None and not settings.scheduler_enabled:
                    raise PrivacyNoticePublicationSchedulerError(
                        "publication scheduler is disabled"
                    )
                tenants, limited = self._eligible_tenants(settings, tenant_id)
                now = _timestamp(self._clock())
                prior = self._read_state()
                recovered = int(prior["interrupted_cycles_recovered"]) + int(
                    prior["in_progress"] is True
                )
                started_state = {
                    **prior,
                    "revision": int(prior["revision"]) + 1,
                    "in_progress": True,
                    "last_started_at": now,
                    "interrupted_cycles_recovered": recovered,
                }
                self._write_state(started_state)
                counts = {
                    "applied": 0,
                    "recovered": 0,
                    "no_change": 0,
                    "idle": 0,
                    "ambiguous": 0,
                    "failed": 0,
                }
                tenant_failures = 0
                executed = 0
                for tenant in tenants:
                    try:
                        runtime = self._runtime_factory(tenant)
                        if (
                            not isinstance(runtime, PrivacyNoticePublicationRuntime)
                            or runtime.tenant_id != tenant
                            or runtime.local_only is not True
                            or runtime.provider_network_io is not False
                            or runtime.provider_writes is not False
                            or runtime.site_mutation is not False
                            or runtime.sdk_deployment is not False
                        ):
                            raise PrivacyNoticePublicationSchedulerError(
                                "publication runtime boundary is invalid"
                            )
                        result = runtime.run_once()
                        status = getattr(result, "status", None)
                        if status not in counts:
                            raise PrivacyNoticePublicationSchedulerError(
                                "publication bridge result is invalid"
                            )
                        counts[status] += 1
                        executed += 1
                    except (KeyboardInterrupt, SystemExit):
                        raise
                    except Exception:
                        tenant_failures += 1
                completed = _timestamp(self._clock())
                body = {
                    "started_at": now,
                    "completed_at": completed,
                    "tenants_considered": len(tenants),
                    "tenants_executed": executed,
                    "tenants_failed": tenant_failures,
                    "tenant_limit_reached": limited,
                    **counts,
                }
                cycle = PublicationSchedulerCycle(**body, cycle_sha256=_sha256(body))
                failure_count = int(prior["consecutive_failures"])
                if tenant_failures:
                    failure_count += 1
                    retry = min(
                        settings.retry_max_seconds,
                        settings.poll_seconds * (2 ** min(failure_count - 1, 10)),
                    )
                    error_code = "tenant_failed"
                    success_at = float(prior["last_success_at"])
                else:
                    failure_count = 0
                    retry = settings.poll_seconds
                    error_code = ""
                    success_at = completed
                final_state = {
                    **started_state,
                    "revision": int(started_state["revision"]) + 1,
                    "in_progress": False,
                    "last_completed_at": completed,
                    "last_success_at": success_at,
                    "next_run_at": completed + retry,
                    "consecutive_failures": failure_count,
                    "last_error_code": error_code,
                    "last_cycle": {"schema": _CYCLE_SCHEMA, **asdict(cycle)},
                }
                self._write_state(final_state)
                return cycle
        finally:
            self._cycle_lock.release()

    def _loop(self) -> None:
        while not self._stop.is_set():
            delay = 5.0
            try:
                settings = self._settings()
                if not settings.enabled or not settings.scheduler_enabled:
                    return
                state = self._read_state()
                now = _timestamp(self._clock())
                if now >= float(state["next_run_at"]):
                    self.run_once()
                    state = self._read_state()
                delay = max(0.1, min(5.0, float(state["next_run_at"]) - now))
            except PrivacyNoticePublicationSchedulerBusy:
                delay = 0.25
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001 - detail stays only in logs
                log.warning(
                    "privacy notice publication scheduler degraded: %s",
                    type(exc).__name__,
                )
                delay = 5.0
            self._stop.wait(delay)

    def start(self) -> bool:
        settings = self._settings()
        if not settings.enabled or not settings.scheduler_enabled:
            return False
        with self._state_lock:
            if self._thread is not None and self._thread.is_alive():
                return True
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop,
                name="privacy-notice-publication",
                daemon=True,
            )
            self._thread.start()
        return True

    def stop(self, *, timeout: float = 5.0, wait: bool = True) -> bool:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("scheduler stop timeout is invalid")
        wait_seconds = max(0.0, min(float(timeout), 30.0))
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
        with self._state_lock:
            running = self._thread is not None and self._thread.is_alive()
            state = dict(self._state)
        payload = {
            "schema": _STATUS_SCHEMA,
            "installed": True,
            "runtime_enabled": self._runtime_enabled,
            "scheduler_enabled": self._configured_enabled,
            "configured_enabled": self._configured_enabled,
            "running": running,
            "healthy": bool(
                self._configured_enabled
                and int(state["consecutive_failures"]) == 0
                and state["in_progress"] is False
            ),
            "in_progress": state["in_progress"],
            "last_started_at": state["last_started_at"] or None,
            "last_completed_at": state["last_completed_at"] or None,
            "last_success_at": state["last_success_at"] or None,
            "next_run_at": state["next_run_at"],
            "consecutive_failures": state["consecutive_failures"],
            "interrupted_cycles_recovered": state["interrupted_cycles_recovered"],
            "last_error_code": state["last_error_code"] or None,
            "last_cycle": state["last_cycle"],
            "state_revision": state["revision"],
            "process_concurrency_excluded": True,
            "cross_process_concurrency_excluded": True,
            "status_opened_tenant_store": False,
            "status_processed_intent": False,
            "local_consent_publication_only": True,
            "provider_network_io": False,
            "provider_writes": False,
            "site_mutation": False,
            "sdk_deployment": False,
            "live_acceptance_verified": False,
        }
        return {**payload, "status_sha256": _sha256(payload)}


def _disabled_status(*, configured: bool = False) -> Mapping[str, object]:
    payload = {
        "schema": _STATUS_SCHEMA,
        "installed": True,
        "runtime_enabled": configured,
        "scheduler_enabled": configured,
        "configured_enabled": configured,
        "running": False,
        "healthy": False,
        "in_progress": False,
        "last_started_at": None,
        "last_completed_at": None,
        "last_success_at": None,
        "next_run_at": None,
        "consecutive_failures": 0,
        "interrupted_cycles_recovered": 0,
        "last_error_code": None,
        "last_cycle": None,
        "state_revision": 0,
        "process_concurrency_excluded": True,
        "cross_process_concurrency_excluded": True,
        "status_opened_tenant_store": False,
        "status_processed_intent": False,
        "local_consent_publication_only": True,
        "provider_network_io": False,
        "provider_writes": False,
        "site_mutation": False,
        "sdk_deployment": False,
        "live_acceptance_verified": False,
    }
    return {**payload, "status_sha256": _sha256(payload)}


def install_privacy_notice_publication_scheduler(app: Any) -> None:
    if getattr(app, "state", None) is None:
        raise TypeError("app must expose state")
    status = getattr(app.state, "privacy_notice_publication_scheduler_status", None)
    if status is None:
        app.state.privacy_notice_publication_scheduler_status = lambda: scheduler_status(app)
    elif not callable(status):
        raise TypeError("privacy notice publication scheduler status must be callable")


def start_privacy_notice_publication_scheduler(app: Any) -> bool:
    install_privacy_notice_publication_scheduler(app)
    settings = settings_from_config(_load_global_config())
    app.state.privacy_notice_publication_scheduler_configured = bool(
        settings.enabled and settings.scheduler_enabled
    )
    if not settings.enabled:
        return False
    runtime = _ensure_scheduler_runtime(app)
    if not settings.scheduler_enabled:
        return False
    return runtime.start()


def _ensure_scheduler_runtime(app: Any) -> PrivacyNoticePublicationScheduler:
    runtime = getattr(app.state, "privacy_notice_publication_scheduler_runtime", None)
    if runtime is None:
        factory = getattr(app.state, "privacy_notice_publication_runtime_factory", None)
        if not callable(factory):
            raise TypeError("privacy notice publication runtime factory is unavailable")
        path_factory = getattr(
            app.state, "privacy_notice_publication_scheduler_path_factory", None
        )
        if path_factory is not None and not callable(path_factory):
            raise TypeError("privacy notice publication scheduler path factory is invalid")
        path = (
            path_factory()
            if callable(path_factory)
            else data_dir(
                "privacy_automation",
                "privacy-notice-publication-scheduler.json",
                tenant=None,
            )
        )
        runtime = PrivacyNoticePublicationScheduler(path, runtime_factory=factory)
        app.state.privacy_notice_publication_scheduler_runtime = runtime
    if not isinstance(runtime, PrivacyNoticePublicationScheduler):
        raise TypeError("privacy notice publication scheduler runtime is invalid")
    return runtime


def run_once_for_tenant(app: Any, tenant_id: str) -> PublicationSchedulerCycle:
    """Execute one server-derived tenant cycle through the shared exclusions."""

    install_privacy_notice_publication_scheduler(app)
    return _ensure_scheduler_runtime(app).run_once(canonical_tenant_id(tenant_id))


def stop_privacy_notice_publication_scheduler(app: Any, *, timeout: float = 5.0) -> bool:
    runtime = getattr(
        getattr(app, "state", None),
        "privacy_notice_publication_scheduler_runtime",
        None,
    )
    if runtime is None:
        return False
    if not isinstance(runtime, PrivacyNoticePublicationScheduler):
        raise TypeError("privacy notice publication scheduler runtime is invalid")
    return runtime.stop(timeout=timeout)


def scheduler_status(app: Any) -> Mapping[str, object]:
    runtime = getattr(
        getattr(app, "state", None),
        "privacy_notice_publication_scheduler_runtime",
        None,
    )
    if runtime is None:
        return _disabled_status(
            configured=(
                getattr(
                    getattr(app, "state", None),
                    "privacy_notice_publication_scheduler_configured",
                    False,
                )
                is True
            )
        )
    if not isinstance(runtime, PrivacyNoticePublicationScheduler):
        raise TypeError("privacy notice publication scheduler runtime is invalid")
    return runtime.status()


__all__ = [
    "PrivacyNoticePublicationScheduler",
    "PrivacyNoticePublicationSchedulerBusy",
    "PrivacyNoticePublicationSchedulerError",
    "PublicationSchedulerCycle",
    "install_privacy_notice_publication_scheduler",
    "run_once_for_tenant",
    "scheduler_status",
    "start_privacy_notice_publication_scheduler",
    "stop_privacy_notice_publication_scheduler",
]
