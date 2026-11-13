"""Bounded supervisor for the durable consent scan inventory.

The supervisor is deliberately small.  Scheduling, leases, retries, stale
lease recovery, and report persistence remain authoritative in
``maverick.consent_scan_inventory``.  This module only drives those operations
for active tenant namespaces and keeps digest-only process health.

The runtime is off unless all three gates are exactly ``true``::

    [consent_preferences]
    enable = true

    [consent_preferences.scanner]
    enable = true

    [consent_preferences.scanner.scheduler]
    enable = true

No live-site or production-scale acceptance is implied by starting this local
worker.  The scanner's separately reviewed network and credential seams remain
responsible for external access.
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
from dataclasses import dataclass
from typing import Any, Protocol

log = logging.getLogger(__name__)

_STATUS_SCHEMA = "lightwork.consent-scan-scheduler-status.v1"
_CYCLE_SCHEMA = "lightwork.consent-scan-scheduler-cycle.v1"
_DEFAULT_POLL_SECONDS = 60.0
_MIN_POLL_SECONDS = 5.0
_MAX_POLL_SECONDS = 3_600.0
_DEFAULT_ENQUEUE_LIMIT = 100
_DEFAULT_CLAIM_LIMIT = 4
_DEFAULT_TENANT_LIMIT = 1_000
_MAX_TENANT_LIMIT = 10_000
_MAX_STOP_SECONDS = 30.0
_ERROR_CODE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z")
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SCHEDULER_KEYS = frozenset(
    {"enable", "poll_seconds", "enqueue_limit", "claim_limit", "tenant_limit"}
)


class ConsentScanSchedulerError(RuntimeError):
    """Base error for the consent scan supervisor."""


class ConsentScanSchedulerConfigurationError(ConsentScanSchedulerError, ValueError):
    """The closed scheduler configuration is malformed."""


class InventoryAuthority(Protocol):
    """Operations consumed from ``ConsentScanInventory``."""

    def enqueue_due(self, tenant_id: str, *, limit: int) -> Mapping[str, Any]: ...

    def claim_due(
        self,
        tenant_id: str,
        worker_id: str,
        *,
        limit: int,
    ) -> Mapping[str, Any]: ...

    def renew_lease(
        self,
        tenant_id: str,
        job_id: str,
        worker_id: str,
        lease_token: str,
        *,
        expected_revision: int,  # noqa
    ) -> Mapping[str, Any]: ...

    def run_claim(
        self,
        tenant_id: str,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class SchedulerSettings:
    """Validated, finite supervisor bounds."""

    poll_seconds: float = _DEFAULT_POLL_SECONDS
    enqueue_limit: int = _DEFAULT_ENQUEUE_LIMIT
    claim_limit: int = _DEFAULT_CLAIM_LIMIT
    tenant_limit: int = _DEFAULT_TENANT_LIMIT


def _integer(value: object, name: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ConsentScanSchedulerConfigurationError(
            f"consent scan scheduler {name} must be an integer between {lower} and {upper}"
        )
    return value


def scheduler_settings(config: object) -> SchedulerSettings | None:
    """Validate the direct scheduler table and enforce all parent gates.

    ``None`` means disabled.  An absent table is disabled, never an implicit
    opt-in.  Unknown scheduler keys are rejected so misspellings cannot silently
    change safety or workload bounds.
    """

    if not isinstance(config, Mapping):
        raise ConsentScanSchedulerConfigurationError("configuration must be a table")
    consent = config.get("consent_preferences")
    if consent is None:
        return None
    if not isinstance(consent, Mapping):
        raise ConsentScanSchedulerConfigurationError(
            "consent_preferences must be a table"
        )
    consent_enabled = consent.get("enable", False)
    if not isinstance(consent_enabled, bool):
        raise ConsentScanSchedulerConfigurationError(
            "consent_preferences.enable must be boolean"
        )
    scanner = consent.get("scanner")
    if scanner is None:
        return None
    if not isinstance(scanner, Mapping):
        raise ConsentScanSchedulerConfigurationError(
            "consent_preferences.scanner must be a table"
        )
    scanner_enabled = scanner.get("enable", False)
    if not isinstance(scanner_enabled, bool):
        raise ConsentScanSchedulerConfigurationError(
            "consent_preferences.scanner.enable must be boolean"
        )
    raw = scanner.get("scheduler")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ConsentScanSchedulerConfigurationError(
            "consent_preferences.scanner.scheduler must be a table"
        )
    if set(raw) - _SCHEDULER_KEYS:
        raise ConsentScanSchedulerConfigurationError(
            "consent scan scheduler key is unsupported"
        )
    enabled = raw.get("enable", False)
    if not isinstance(enabled, bool):
        raise ConsentScanSchedulerConfigurationError(
            "consent scan scheduler enable must be boolean"
        )
    if not (consent_enabled and scanner_enabled and enabled):
        return None
    poll = raw.get("poll_seconds", _DEFAULT_POLL_SECONDS)
    if isinstance(poll, bool) or not isinstance(poll, (int, float)):
        raise ConsentScanSchedulerConfigurationError(
            "consent scan scheduler poll_seconds must be a number"
        )
    poll_seconds = float(poll)
    if (
        not math.isfinite(poll_seconds)
        or poll_seconds < _MIN_POLL_SECONDS
        or poll_seconds > _MAX_POLL_SECONDS
    ):
        raise ConsentScanSchedulerConfigurationError(
            "consent scan scheduler poll_seconds must be between 5 and 3600"
        )
    return SchedulerSettings(
        poll_seconds=poll_seconds,
        enqueue_limit=_integer(
            raw.get("enqueue_limit", _DEFAULT_ENQUEUE_LIMIT),
            "enqueue_limit",
            1,
            500,
        ),
        claim_limit=_integer(
            raw.get("claim_limit", _DEFAULT_CLAIM_LIMIT),
            "claim_limit",
            1,
            100,
        ),
        tenant_limit=_integer(
            raw.get("tenant_limit", _DEFAULT_TENANT_LIMIT),
            "tenant_limit",
            1,
            _MAX_TENANT_LIMIT,
        ),
    )


def _safe_error_code(value: object) -> str:
    candidate = value if isinstance(value, str) else type(value).__name__
    return candidate if _ERROR_CODE_RE.fullmatch(candidate) else "scheduler_error"


def _digest(label: str, value: str) -> str:
    return hashlib.sha256(f"{label}\0{value}".encode()).hexdigest()


def _default_config_loader() -> Mapping[str, Any]:
    from maverick.config import config_source_errors, load_global_config

    if config_source_errors(include_tenant=False):
        raise ConsentScanSchedulerConfigurationError(
            "global configuration sources are unreadable"
        )
    loaded = load_global_config() or {}
    if not isinstance(loaded, Mapping):
        raise ConsentScanSchedulerConfigurationError("global configuration must be a table")
    return loaded


def _default_tenant_config_loader() -> Mapping[str, Any]:
    """Load the active tenant overlay after ``_tenant_context`` is entered."""

    from maverick.config import config_source_errors, load_config

    loaded = load_config() or {}
    if config_source_errors(include_tenant=True):
        raise ConsentScanSchedulerConfigurationError(
            "tenant configuration sources are unreadable"
        )
    if not isinstance(loaded, Mapping):
        raise ConsentScanSchedulerConfigurationError("tenant configuration must be a table")
    return loaded


def _default_tenant_supplier() -> Sequence[str]:
    """Return the configured floor and active tenant namespaces without logging IDs."""

    floor = os.environ.get("MAVERICK_TENANT", "").strip()
    if not floor:
        try:
            from maverick.client import client_id

            floor = str(client_id() or "").strip()
        except Exception:
            floor = ""
    try:
        from maverick.tenant.registry import list_tenants

        records = tuple(list_tenants())
    except Exception as exc:
        raise ConsentScanSchedulerError("tenant_registry_unavailable") from exc
    tenants: list[str] = []
    if floor:
        tenants.append(floor)
    for record in records:
        tenant = str(getattr(record, "id", "") or "").strip()
        if tenant and getattr(record, "active", False) and tenant not in tenants:
            tenants.append(tenant)
    # A legacy single-tenant deployment without an explicit namespace uses the
    # shared data root, represented internally by the empty string.
    return tuple(tenants or [""])


@contextmanager
def _tenant_context(tenant_id: str):
    from maverick.paths import reset_tenant, set_tenant

    token = set_tenant(tenant_id or None)
    try:
        yield
    finally:
        reset_tenant(token)


def _default_inventory_factory(tenant_id: str) -> InventoryAuthority:
    """Build the production browser-backed authority for one pinned namespace."""

    from maverick.consent_preferences import ConsentPreferenceStore
    from maverick.consent_scan_inventory import ConsentScanInventory
    from maverick.consent_scanner import ConsentScanner, PlaywrightPageCollector
    from maverick.paths import data_dir

    return ConsentScanInventory(
        data_dir(
            "consent_preferences",
            "consent-scan-inventory.sqlite3",
            tenant=tenant_id or None,
        ),
        ConsentScanner(PlaywrightPageCollector()),
        tracker_authority=ConsentPreferenceStore(
            data_dir(
                "consent_preferences",
                "consent-preferences.sqlite3",
                tenant=tenant_id or None,
            )
        ),
    )


class ConsentScanScheduler:
    """One thread-safe, bounded consent-scan supervisor instance."""

    def __init__(
        self,
        *,
        inventory_factory: Callable[[str], InventoryAuthority] = _default_inventory_factory,
        tenant_supplier: Callable[[], Sequence[str]] = _default_tenant_supplier,
        config_loader: Callable[[], Mapping[str, Any]] = _default_config_loader,
        tenant_config_loader: Callable[[], Mapping[str, Any]] | None = None,
        clock: Callable[[], float] = time.time,
        worker_id: str | None = None,
    ) -> None:
        selected_worker = worker_id or f"consent-scan-{uuid.uuid4().hex}"
        if not isinstance(selected_worker, str) or not _REF_RE.fullmatch(selected_worker):
            raise ValueError("worker_id must be an opaque identifier")
        if not callable(inventory_factory) or not callable(tenant_supplier):
            raise TypeError("scheduler dependencies must be callable")
        self._inventory_factory = inventory_factory
        self._tenant_supplier = tenant_supplier
        self._config_loader = config_loader
        # Injected/no-network runtimes normally supply one closed configuration
        # authority for both scopes.  Production uses ``load_config`` only after
        # the tenant ContextVar is pinned, so a tenant scheduler opt-out cannot
        # be bypassed by the deployment-global worker gate.
        self._tenant_config_loader = (
            _default_tenant_config_loader
            if tenant_config_loader is None and config_loader is _default_config_loader
            else (tenant_config_loader or config_loader)
        )
        self._clock = clock
        self._worker_id = selected_worker
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._stop: threading.Event | None = None
        self._metrics: dict[str, Any] = {
            "configured_enabled": False,
            "started_at": None,
            "stopped_at": None,
            "last_cycle_started_at": None,
            "last_cycle_completed_at": None,
            "cycles": 0,
            "tenants_processed": 0,
            "jobs_enqueued": 0,
            "jobs_claimed": 0,
            "jobs_succeeded": 0,
            "jobs_failed": 0,
            "leases_recovered": 0,
            "lease_renewals": 0,
            "lease_renewal_failures": 0,
            "tenant_truncations": 0,
            "queue_truncations": 0,
            "recovery_truncations": 0,
            "last_tenant_sha256": None,
            "last_job_sha256": None,
            "last_error_code": None,
        }

    def _now(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConsentScanSchedulerError("clock_invalid")
        result = float(value)
        if not math.isfinite(result) or result <= 0:
            raise ConsentScanSchedulerError("clock_invalid")
        return result

    def _record(self, **updates: Any) -> None:
        with self._lock:
            for key, value in updates.items():
                if key in self._metrics:
                    self._metrics[key] = value

    def _increment(self, **deltas: int) -> None:
        with self._lock:
            for key, value in deltas.items():
                if key in self._metrics:
                    self._metrics[key] = int(self._metrics[key]) + int(value)

    def status(self) -> dict[str, Any]:
        """Return sanitized runtime state; no tenant, job, or lease value is exposed."""

        with self._lock:
            thread = self._thread
            stop = self._stop
            return {
                "schema": _STATUS_SCHEMA,
                "running": bool(thread is not None and thread.is_alive()),
                "stop_requested": bool(stop is not None and stop.is_set()),
                "worker_sha256": _digest("consent-scan-worker", self._worker_id),
                **self._metrics,
            }

    @staticmethod
    def _bounded_tenants(values: Sequence[str], limit: int) -> tuple[tuple[str, ...], bool]:
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise ConsentScanSchedulerError("tenant_supplier_invalid")
        tenants: list[str] = []
        for raw in values:
            if not isinstance(raw, str):
                raise ConsentScanSchedulerError("tenant_supplier_invalid")
            tenant = raw.strip()
            if tenant and not _REF_RE.fullmatch(tenant):
                raise ConsentScanSchedulerError("tenant_supplier_invalid")
            if tenant not in tenants:
                tenants.append(tenant)
            if len(tenants) > limit:
                break
        return tuple(tenants[:limit]), len(tenants) > limit

    def _lease_heartbeat(
        self,
        inventory: InventoryAuthority,
        tenant_id: str,
        claim: Mapping[str, Any],
        done: threading.Event,
        result: dict[str, Any],
    ) -> None:
        lease_seconds = claim.get("lease_seconds")
        revision = claim.get("revision")
        job_id = claim.get("job_id")
        lease_token = claim.get("lease_token")
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, (int, float))
            or float(lease_seconds) <= 0
            or isinstance(revision, bool)
            or not isinstance(revision, int)
            or not isinstance(job_id, str)
            or not isinstance(lease_token, str)
        ):
            result["error_code"] = "claim_contract_invalid"
            return
        interval = max(0.05, min(30.0, float(lease_seconds) / 3.0))
        current_revision = revision
        while not done.wait(interval):
            try:
                renewed = inventory.renew_lease(
                    tenant_id,
                    job_id,
                    self._worker_id,
                    lease_token,
                    expected_revision=current_revision,
                )
                next_revision = renewed.get("revision")
                if isinstance(next_revision, bool) or not isinstance(next_revision, int):
                    raise ConsentScanSchedulerError("lease_renewal_contract_invalid")
                current_revision = next_revision
                result["renewals"] = int(result.get("renewals", 0)) + 1
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                result["error_code"] = _safe_error_code(exc)
                return

    def _run_claim(
        self,
        inventory: InventoryAuthority,
        tenant_id: str,
        claim: Mapping[str, Any],
    ) -> bool:
        job_id = claim.get("job_id")
        lease_token = claim.get("lease_token")
        if not isinstance(job_id, str) or not _REF_RE.fullmatch(job_id):
            raise ConsentScanSchedulerError("claim_contract_invalid")
        if not isinstance(lease_token, str):
            raise ConsentScanSchedulerError("claim_contract_invalid")
        done = threading.Event()
        heartbeat_result: dict[str, Any] = {"renewals": 0, "error_code": None}
        heartbeat = threading.Thread(
            target=self._lease_heartbeat,
            args=(inventory, tenant_id, claim, done, heartbeat_result),
            name="consent-scan-lease-heartbeat",
            daemon=True,
        )
        heartbeat.start()
        try:
            outcome = inventory.run_claim(
                tenant_id,
                job_id,
                self._worker_id,
                lease_token,
            )
        finally:
            done.set()
            heartbeat.join(1.0)
        renewals = int(heartbeat_result.get("renewals", 0))
        if renewals:
            self._increment(lease_renewals=renewals)
        heartbeat_error = heartbeat_result.get("error_code")
        if heartbeat_error is not None:
            self._increment(lease_renewal_failures=1)
            self._record(last_error_code=_safe_error_code(heartbeat_error))
        if not isinstance(outcome, Mapping) or not isinstance(outcome.get("succeeded"), bool):
            raise ConsentScanSchedulerError("run_claim_contract_invalid")
        self._record(last_job_sha256=_digest("consent-scan-job", job_id))
        if outcome["succeeded"]:
            self._increment(jobs_succeeded=1)
            return True
        job = outcome.get("job")
        error_code = job.get("last_error_code") if isinstance(job, Mapping) else None
        self._increment(jobs_failed=1)
        self._record(last_error_code=_safe_error_code(error_code or "scan_failed"))
        return False

    def _run_tenant(
        self,
        tenant_id: str,
        settings: SchedulerSettings,
        stop: threading.Event | None,
    ) -> dict[str, int]:
        """Run one tenant under the installation bounds and its own config.

        A tenant's configuration can opt the tenant out and can lower
        ``enqueue_limit`` and ``claim_limit``.  ``poll_seconds`` and
        ``tenant_limit`` describe the one supervisor loop, so only the
        installation values apply; a tenant's values for them are validated
        and otherwise ignored.
        """

        with _tenant_context(tenant_id):
            tenant_settings = scheduler_settings(self._tenant_config_loader())
            if tenant_settings is None:
                return {
                    "enqueued": 0,
                    "claimed": 0,
                    "succeeded": 0,
                    "failed": 0,
                    "recovered": 0,
                }
            effective_settings = SchedulerSettings(
                poll_seconds=settings.poll_seconds,
                enqueue_limit=min(settings.enqueue_limit, tenant_settings.enqueue_limit),
                claim_limit=min(settings.claim_limit, tenant_settings.claim_limit),
                tenant_limit=settings.tenant_limit,
            )
            inventory = self._inventory_factory(tenant_id)
            enqueued = inventory.enqueue_due(
                tenant_id,
                limit=effective_settings.enqueue_limit,
            )
            if not isinstance(enqueued, Mapping):
                raise ConsentScanSchedulerError("enqueue_contract_invalid")
            enqueued_items = enqueued.get("items")
            if not isinstance(enqueued_items, Sequence) or isinstance(
                enqueued_items, (str, bytes)
            ):
                raise ConsentScanSchedulerError("enqueue_contract_invalid")
            # Do not acquire fresh leases after shutdown was requested.  Jobs
            # materialized above remain durably queued for the next process.
            if stop is not None and stop.is_set():
                self._increment(
                    jobs_enqueued=len(enqueued_items),
                    queue_truncations=int(bool(enqueued.get("truncated"))),
                )
                return {
                    "enqueued": len(enqueued_items),
                    "claimed": 0,
                    "succeeded": 0,
                    "failed": 0,
                    "recovered": 0,
                }
            claimed = inventory.claim_due(
                tenant_id,
                self._worker_id,
                limit=effective_settings.claim_limit,
            )
            if not isinstance(claimed, Mapping):
                raise ConsentScanSchedulerError("claim_contract_invalid")
            claimed_items = claimed.get("items")
            if not isinstance(claimed_items, Sequence) or isinstance(
                claimed_items, (str, bytes)
            ):
                raise ConsentScanSchedulerError("claim_contract_invalid")
            if (
                len(enqueued_items) > effective_settings.enqueue_limit
                or len(claimed_items) > effective_settings.claim_limit
            ):
                raise ConsentScanSchedulerError("inventory_bound_exceeded")
            recovered = claimed.get("recovered_leases", 0)
            if isinstance(recovered, bool) or not isinstance(recovered, int) or recovered < 0:
                raise ConsentScanSchedulerError("claim_contract_invalid")
            self._increment(
                jobs_enqueued=len(enqueued_items),
                jobs_claimed=len(claimed_items),
                leases_recovered=recovered,
                queue_truncations=int(bool(enqueued.get("truncated")))
                + int(bool(claimed.get("truncated"))),
                recovery_truncations=int(bool(claimed.get("recovery_truncated"))),
            )
            succeeded = 0
            failed = 0
            for raw_claim in claimed_items:
                try:
                    if not isinstance(raw_claim, Mapping):
                        raise ConsentScanSchedulerError("claim_contract_invalid")
                    if self._run_claim(inventory, tenant_id, raw_claim):
                        succeeded += 1
                    else:
                        failed += 1
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as exc:
                    # If core cannot finish the job, its stale-lease recovery
                    # owns the next attempt.  Continue the already leased batch
                    # so one corrupt/failed claim cannot strand its siblings.
                    failed += 1
                    self._increment(jobs_failed=1)
                    code = _safe_error_code(exc)
                    self._record(last_error_code=code)
                    log.warning("Consent scan claim failed safely: %s", code)
            return {
                "enqueued": len(enqueued_items),
                "claimed": len(claimed_items),
                "succeeded": succeeded,
                "failed": failed,
                "recovered": recovered,
            }

    def run_cycle(
        self,
        *,
        config: Mapping[str, Any] | None = None,
        stop: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Run one bounded cycle, finishing every claim already leased.

        The method intentionally does not implement retry delays or release
        leases itself.  ``ConsentScanInventory.run_claim`` owns that policy,
        while the following ``claim_due`` invocation owns stale recovery.
        """

        started = self._now()
        self._record(last_cycle_started_at=started, last_error_code=None)
        selected_config = config if config is not None else self._config_loader()
        settings = scheduler_settings(selected_config)
        self._record(configured_enabled=settings is not None)
        if settings is None:
            completed = self._now()
            self._increment(cycles=1)
            self._record(last_cycle_completed_at=completed)
            return {
                "schema": _CYCLE_SCHEMA,
                "enabled": False,
                "completed": True,
                "tenants_processed": 0,
                "tenant_truncated": False,
            }
        tenants, truncated = self._bounded_tenants(
            self._tenant_supplier(), settings.tenant_limit
        )
        if truncated:
            self._increment(tenant_truncations=1)
        processed = 0
        cycle_enqueued = 0
        cycle_claimed = 0
        cycle_succeeded = 0
        cycle_failed = 0
        cycle_recovered = 0
        cycle_error: str | None = None
        for tenant_id in tenants:
            if stop is not None and stop.is_set():
                break
            self._record(last_tenant_sha256=_digest("consent-scan-tenant", tenant_id))
            try:
                result = self._run_tenant(tenant_id, settings, stop)
                cycle_enqueued += result["enqueued"]
                cycle_claimed += result["claimed"]
                cycle_succeeded += result["succeeded"]
                cycle_failed += result["failed"]
                cycle_recovered += result["recovered"]
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                cycle_error = _safe_error_code(exc)
                self._record(last_error_code=cycle_error)
                log.warning("Consent scan tenant cycle failed safely: %s", cycle_error)
            processed += 1
            self._increment(tenants_processed=1)
        completed = self._now()
        self._increment(cycles=1)
        self._record(last_cycle_completed_at=completed)
        return {
            "schema": _CYCLE_SCHEMA,
            "enabled": True,
            "completed": cycle_error is None,
            "tenants_processed": processed,
            "tenant_truncated": truncated,
            "jobs_enqueued": cycle_enqueued,
            "jobs_claimed": cycle_claimed,
            "jobs_succeeded": cycle_succeeded,
            "jobs_failed": cycle_failed,
            "leases_recovered": cycle_recovered,
            "last_error_code": cycle_error,
        }

    def _loop(self, stop: threading.Event, initial: SchedulerSettings) -> None:
        poll_seconds = initial.poll_seconds
        try:
            while not stop.is_set():
                try:
                    selected = self._config_loader()
                    current = scheduler_settings(selected)
                    if current is not None:
                        poll_seconds = current.poll_seconds
                    self.run_cycle(config=selected, stop=stop)
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as exc:
                    code = _safe_error_code(exc)
                    self._record(last_error_code=code, configured_enabled=False)
                    log.warning("Consent scan scheduler failed safely: %s", code)
                stop.wait(poll_seconds)
        finally:
            self._record(stopped_at=self._now())

    def start(self, *, config: Mapping[str, Any] | None = None) -> bool:
        """Start this instance once; exact disabled gates are a no-op."""

        selected = config if config is not None else self._config_loader()
        settings = scheduler_settings(selected)
        self._record(configured_enabled=settings is not None)
        if settings is None:
            return False
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            stop = threading.Event()
            worker = threading.Thread(
                target=self._loop,
                args=(stop, settings),
                name="consent-scan-scheduler",
                daemon=True,
            )
            self._stop = stop
            self._thread = worker
            self._metrics["started_at"] = self._now()
            self._metrics["stopped_at"] = None
            worker.start()
            return True

    def stop(self, *, timeout: float = 5.0, wait: bool = True) -> bool:
        """Signal shutdown and wait finitely for any already leased scan."""

        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("timeout must be a finite number")
        wait_seconds = float(timeout)
        if not math.isfinite(wait_seconds):
            raise ValueError("timeout must be a finite number")
        wait_seconds = max(0.0, min(wait_seconds, _MAX_STOP_SECONDS))
        with self._lock:
            stop = self._stop
            worker = self._thread
        if stop is None or worker is None:
            return False
        stop.set()
        if not wait:
            return False
        worker.join(wait_seconds)
        if worker.is_alive():
            return False
        with self._lock:
            if self._thread is worker:
                self._thread = None
                self._stop = None
        return True


_default_lock = threading.Lock()
_default_runtime: ConsentScanScheduler | None = None


def default_scheduler() -> ConsentScanScheduler:
    """Return the one process singleton used by lifespan and status callers."""

    global _default_runtime
    with _default_lock:
        if _default_runtime is None:
            _default_runtime = ConsentScanScheduler()
        return _default_runtime


def start_consent_scan_scheduler() -> bool:
    return default_scheduler().start()


def stop_consent_scan_scheduler(*, timeout: float = 5.0) -> bool:
    return default_scheduler().stop(timeout=timeout)


def consent_scan_scheduler_status() -> dict[str, Any]:
    return default_scheduler().status()


def attach_consent_scan_scheduler(
    app: Any,
    *,
    runtime: ConsentScanScheduler | None = None,
) -> ConsentScanScheduler:
    """Wrap an ASGI application's lifespan with bounded start and shutdown.

    Call this exactly once after constructing the application and before it is
    served.  It composes with the application's existing lifespan instead of
    replacing its startup or shutdown behavior.
    """

    selected = runtime if runtime is not None else default_scheduler()
    router = getattr(app, "router", None)
    previous = getattr(router, "lifespan_context", None)
    if router is None or not callable(previous):
        raise TypeError("app must expose a lifespan-capable router")
    marker = "_lightwork_consent_scan_scheduler"
    attached = getattr(getattr(app, "state", None), marker, None)
    if attached is not None:
        if attached is selected:
            return selected
        raise RuntimeError("a consent scan scheduler is already attached")

    @asynccontextmanager
    async def lifespan(target: Any):
        from ._lifecycle import supervised_runtime

        async with previous(target):
            async with supervised_runtime(target, "consent_scan", selected):
                yield

    app.router.lifespan_context = lifespan
    setattr(app.state, marker, selected)
    return selected


__all__ = [
    "ConsentScanScheduler",
    "ConsentScanSchedulerConfigurationError",
    "ConsentScanSchedulerError",
    "InventoryAuthority",
    "SchedulerSettings",
    "attach_consent_scan_scheduler",
    "consent_scan_scheduler_status",
    "default_scheduler",
    "scheduler_settings",
    "start_consent_scan_scheduler",
    "stop_consent_scan_scheduler",
]
