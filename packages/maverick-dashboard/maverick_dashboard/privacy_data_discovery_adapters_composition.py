"""Lazy tenant-exact composition for privacy discovery and its data map.

Installation opens no store and resolves no credential.  The discovery API's
``privacy_data_discovery_coordinator_factory`` resolves an exact tenant config
snapshot on each execution, builds only that tenant's enabled stock adapters,
and returns a coordinator that rejects configuration drift before provider I/O.

The companion remediation runtime connects the existing approved-review
outbox to the built-in digest-only data-map target.  Its store, target and
maintenance operations are tenant-private.  Shared application state contains
factories and content-free readiness data only -- never a tenant registry,
credential value, provider response, raw finding or cross-tenant cache.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maverick import privacy_data_discovery as discovery
from maverick import privacy_data_discovery_remediation as remediation
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope
from maverick.privacy_data_discovery_adapters import (
    DiscoveryAdapterConfigError,
    DiscoveryHTTPTransport,
    PinnedDiscoveryHTTPTransport,
    StockDiscoveryAdapterRegistry,
    build_stock_discovery_adapter_registry,
    credential_reference_present,
)
from maverick.privacy_discovery_data_map_target import PrivacyDiscoveryDataMapTarget

_MAX_RETENTION_SECONDS = 10 * 366 * 24 * 60 * 60
_scan_read_guard: ContextVar[Callable[[], None] | None] = ContextVar("privacy_scan_read_guard", default=None)


class _ReviewedTransport:
    def __init__(self, transport):
        self._transport = transport

    def request(self, request):
        guard = _scan_read_guard.get()

        def check():
            if guard is None:
                return
            try:
                guard()
            except discovery.PrivacyDataDiscoveryError:
                raise
            except Exception as exc:
                raise discovery.PrivacyDataDiscoveryReadInterrupted("Current scan access could not be verified.") from exc

        check()
        result = self._transport.request(request)
        check()
        return result


class PrivacyDiscoveryAdapterCompositionError(discovery.PrivacyDataDiscoveryConfigError):
    """The tenant-scoped stock composition cannot be resolved safely."""


@dataclass(frozen=True, slots=True)
class RemediationSchedulerSettings:
    enabled: bool
    interval_seconds: int
    jitter_seconds: int
    retry_max_seconds: int
    tenant_limit: int
    worker_limit: int
    reconcile_limit: int
    lease_seconds: int


@dataclass(frozen=True, slots=True)
class RemediationCompositionSettings:
    enabled: bool
    max_attempts: int
    retention_seconds: int
    data_map_enabled: bool
    data_map_retention_seconds: int
    scheduler: RemediationSchedulerSettings


@dataclass(frozen=True, slots=True)
class TenantDiscoverySnapshot:
    tenant_id: str
    config_sha256: str
    registry: StockDiscoveryAdapterRegistry
    remediation: RemediationCompositionSettings


@dataclass(frozen=True, slots=True)
class PrivacyDiscoveryRemediationRuntime:
    tenant_id: str
    config_sha256: str
    outbox: remediation.PrivacyDataDiscoveryRemediationStore
    target: PrivacyDiscoveryDataMapTarget
    worker: remediation.PrivacyDataDiscoveryRemediationWorker
    review_callback: Callable[[discovery.ReviewedClassification], None]
    reconciler: Callable[
        [remediation.RemediationReconciliationProbe],
        remediation.RemediationReconciliationResult,
    ]
    digest_only_target: bool = True
    external_side_effect: bool = False
    provider_network_io: bool = False
    provider_writes: bool = False

    def maintenance(
        self,
        *,
        cutoff: float,
        idempotency_key: str,
        target_limit: int = 500,
    ) -> Mapping[str, object]:
        outbox_purged = self.outbox.purge_expired(
            cutoff=cutoff,
            idempotency_key=idempotency_key,
        )
        target_purged = self.target.purge_expired(now=cutoff, limit=target_limit)
        outbox_integrity = self.outbox.verify_integrity()
        target_integrity = self.target.verify_integrity()
        return {
            "schema": "lightwork.privacy-discovery-maintenance.v1",
            "tenant_id": self.tenant_id,
            "config_sha256": self.config_sha256,
            "outbox_purged": outbox_purged,
            "data_map_purged": target_purged,
            "outbox_integrity": {
                "current_records": outbox_integrity.current_records,
                "history_records": outbox_integrity.history_records,
                "operation_records": outbox_integrity.operation_records,
                "audit_events": outbox_integrity.audit_events,
                "terminal_audit_sha256": outbox_integrity.terminal_audit_sha256,
            },
            "data_map_integrity": {
                "observations": target_integrity.observations,
                "tombstones": target_integrity.tombstones,
            },
            "raw_data_returned": False,
            "provider_side_effect": False,
        }


def _canonical_digest(value: object) -> str:
    try:
        body = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery configuration is not canonical"
        ) from None
    return hashlib.sha256(body).hexdigest()


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            loaded = config_module.load_config()
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery tenant configuration is unavailable"
        ) from exc
    if errors or not isinstance(loaded, Mapping):
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery tenant configuration source is invalid"
        )
    return loaded


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise PrivacyDiscoveryAdapterCompositionError(f"{label} is outside its bound")
    return value


def _remediation_settings(config: Mapping[str, Any]) -> RemediationCompositionSettings:
    privacy = config.get("privacy_automation")
    discovery_config = (
        privacy.get("data_discovery") if isinstance(privacy, Mapping) else None
    )
    section = (
        discovery_config.get("remediation")
        if isinstance(discovery_config, Mapping)
        else None
    )
    if section is None:
        return RemediationCompositionSettings(
            enabled=False,
            max_attempts=5,
            retention_seconds=30 * 24 * 60 * 60,
            data_map_enabled=False,
            data_map_retention_seconds=365 * 24 * 60 * 60,
            scheduler=RemediationSchedulerSettings(
                enabled=False,
                interval_seconds=60,
                jitter_seconds=10,
                retry_max_seconds=300,
                tenant_limit=1_000,
                worker_limit=10,
                reconcile_limit=10,
                lease_seconds=60,
            ),
        )
    if not isinstance(section, Mapping):
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery remediation must be a table"
        )
    if set(section) - {
        "enable",
        "max_attempts",
        "retention_seconds",
        "data_map",
        "scheduler",
    }:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery remediation contains an unknown key"
        )
    enabled = section.get("enable", False)
    if type(enabled) is not bool:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery remediation enable must be boolean"
        )
    data_map = section.get("data_map", {})
    if not isinstance(data_map, Mapping) or set(data_map) - {
        "enable",
        "retention_seconds",
    }:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery data-map configuration is invalid"
        )
    data_map_enabled = data_map.get("enable", False)
    if type(data_map_enabled) is not bool:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery data-map enable must be boolean"
        )
    scheduler = section.get("scheduler", {})
    if not isinstance(scheduler, Mapping) or set(scheduler) - {
        "enable",
        "interval_seconds",
        "jitter_seconds",
        "retry_max_seconds",
        "tenant_limit",
        "worker_limit",
        "reconcile_limit",
        "lease_seconds",
    }:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery remediation scheduler configuration is invalid"
        )
    scheduler_enabled = scheduler.get("enable", False)
    if type(scheduler_enabled) is not bool:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery remediation scheduler enable must be boolean"
        )
    scheduler_settings = RemediationSchedulerSettings(
        enabled=scheduler_enabled,
        interval_seconds=_integer(
            scheduler.get("interval_seconds", 60),
            "privacy discovery remediation scheduler interval_seconds",
            5,
            86_400,
        ),
        jitter_seconds=_integer(
            scheduler.get("jitter_seconds", 10),
            "privacy discovery remediation scheduler jitter_seconds",
            0,
            3_600,
        ),
        retry_max_seconds=_integer(
            scheduler.get("retry_max_seconds", 300),
            "privacy discovery remediation scheduler retry_max_seconds",
            5,
            86_400,
        ),
        tenant_limit=_integer(
            scheduler.get("tenant_limit", 1_000),
            "privacy discovery remediation scheduler tenant_limit",
            1,
            10_000,
        ),
        worker_limit=_integer(
            scheduler.get("worker_limit", 10),
            "privacy discovery remediation scheduler worker_limit",
            1,
            100,
        ),
        reconcile_limit=_integer(
            scheduler.get("reconcile_limit", 10),
            "privacy discovery remediation scheduler reconcile_limit",
            1,
            100,
        ),
        lease_seconds=_integer(
            scheduler.get("lease_seconds", 60),
            "privacy discovery remediation scheduler lease_seconds",
            1,
            3_600,
        ),
    )
    if scheduler_settings.jitter_seconds > scheduler_settings.interval_seconds:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery remediation scheduler jitter exceeds its interval"
        )
    settings = RemediationCompositionSettings(
        enabled=enabled,
        max_attempts=_integer(
            section.get("max_attempts", 5),
            "privacy discovery remediation max_attempts",
            1,
            20,
        ),
        retention_seconds=_integer(
            section.get("retention_seconds", 30 * 24 * 60 * 60),
            "privacy discovery remediation retention_seconds",
            60,
            _MAX_RETENTION_SECONDS,
        ),
        data_map_enabled=data_map_enabled,
        data_map_retention_seconds=_integer(
            data_map.get("retention_seconds", 365 * 24 * 60 * 60),
            "privacy discovery data-map retention_seconds",
            60,
            _MAX_RETENTION_SECONDS,
        ),
        scheduler=scheduler_settings,
    )
    if settings.data_map_enabled and not settings.enabled:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery data-map target requires remediation.enable = true"
        )
    if settings.enabled and not settings.data_map_enabled:
        raise PrivacyDiscoveryAdapterCompositionError(
            "stock privacy discovery remediation requires data_map.enable = true"
        )
    if settings.scheduler.enabled and not settings.enabled:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery remediation scheduler requires remediation.enable = true"
        )
    return settings


def remediation_scheduler_settings(
    config: Mapping[str, Any],
) -> RemediationSchedulerSettings | None:
    """Return exact opt-in scheduler bounds or ``None`` without side effects."""

    privacy = config.get("privacy_automation")
    data_discovery = (
        privacy.get("data_discovery") if isinstance(privacy, Mapping) else None
    )
    settings = _remediation_settings(config)
    if (
        not isinstance(privacy, Mapping)
        or privacy.get("enable") is not True
        or not isinstance(data_discovery, Mapping)
        or data_discovery.get("enable") is not True
        or not settings.enabled
        or not settings.data_map_enabled
        or not settings.scheduler.enabled
    ):
        return None
    return settings.scheduler


def _snapshot_material(config: Mapping[str, Any]) -> Mapping[str, object]:
    privacy = config.get("privacy_automation")
    discovery_config = (
        privacy.get("data_discovery") if isinstance(privacy, Mapping) else None
    )
    return {
        "schema": "lightwork.privacy-discovery-composition-config.v1",
        "privacy_enable": (
            privacy.get("enable") if isinstance(privacy, Mapping) else None
        ),
        "data_discovery": (
            dict(discovery_config) if isinstance(discovery_config, Mapping) else None
        ),
    }


def _transport_for(app: Any, tenant_id: str) -> DiscoveryHTTPTransport | None:
    factory = getattr(
        app.state,
        "privacy_data_discovery_stock_transport_factory",
        None,
    )
    if factory is None:
        return None
    if not callable(factory):
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery stock transport factory is invalid"
        )
    try:
        selected = factory(tenant_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery stock transport is unavailable"
        ) from exc
    if not callable(getattr(selected, "request", None)):
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery stock transport is invalid"
        )
    return selected


def snapshot_for_tenant(
    app: Any,
    tenant_id: str,
    *,
    resolve_transport: bool = True,
) -> TenantDiscoverySnapshot:
    tenant = canonical_tenant_id(tenant_id)
    config = _load_tenant_config(tenant)
    try:
        registry = build_stock_discovery_adapter_registry(config)
        if resolve_transport and registry.enabled:
            transport = _transport_for(app, tenant) or PinnedDiscoveryHTTPTransport()
            registry = build_stock_discovery_adapter_registry(
                config, transport=_ReviewedTransport(transport),
            )
    except DiscoveryAdapterConfigError as exc:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery stock adapter configuration is invalid"
        ) from exc
    return TenantDiscoverySnapshot(
        tenant_id=tenant,
        config_sha256=_canonical_digest(_snapshot_material(config)),
        registry=registry,
        remediation=_remediation_settings(config),
    )


def _same_snapshot(app: Any, expected: TenantDiscoverySnapshot) -> None:
    current = snapshot_for_tenant(
        app,
        expected.tenant_id,
        resolve_transport=False,
    )
    if current.config_sha256 != expected.config_sha256:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery tenant configuration changed"
        )


class _TenantPinnedCoordinator(discovery.PrivacyDataDiscoveryCoordinator):
    def __init__(
        self,
        app: Any,
        snapshot: TenantDiscoverySnapshot,
        store: discovery.PrivacyDataDiscoveryStore,
    ) -> None:
        self._app = app
        self._snapshot = snapshot
        super().__init__(
            store,
            structured_sources=snapshot.registry.structured,
            unstructured_sources=snapshot.registry.unstructured,
            credential_ref_present=credential_reference_present,
        )

    @property
    def tenant_id(self) -> str:
        return self._snapshot.tenant_id

    @property
    def config_sha256(self) -> str:
        return self._snapshot.config_sha256

    def execute_job(
        self,
        job: discovery.ScanJob,
        *,
        worker_id: str,
        expected_source_sha256: str | None = None,
        before_effect=None,
    ) -> discovery.ScanReport:
        if job.tenant_id != self._snapshot.tenant_id:
            raise PrivacyDiscoveryAdapterCompositionError(
                "privacy discovery job crossed its tenant"
            )
        _same_snapshot(self._app, self._snapshot)
        def guard():
            _same_snapshot(self._app, self._snapshot)
            if before_effect is not None:
                before_effect()

        token = _scan_read_guard.set(guard if before_effect is not None else None)
        try:
            with tenant_scope(tenant=self._snapshot.tenant_id):
                return super().execute_job(job, worker_id=worker_id,
                    expected_source_sha256=expected_source_sha256, before_effect=guard)
        finally:
            _scan_read_guard.reset(token)

    def run_once(
        self,
        tenant_id: str,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: float = 600.0,
        now: float | None = None,
    ) -> discovery.DiscoveryRunResult:
        tenant = canonical_tenant_id(tenant_id)
        if tenant != self._snapshot.tenant_id:
            raise PrivacyDiscoveryAdapterCompositionError(
                "privacy discovery run crossed its tenant"
            )
        _same_snapshot(self._app, self._snapshot)
        with tenant_scope(tenant=tenant):
            return super().run_once(
                tenant,
                worker_id=worker_id,
                limit=limit,
                lease_seconds=lease_seconds,
                now=now,
            )


def build_tenant_discovery_coordinator(
    app: Any,
    *,
    tenant_id: str,
    store: discovery.PrivacyDataDiscoveryStore,
) -> discovery.PrivacyDataDiscoveryCoordinator:
    if not isinstance(store, discovery.PrivacyDataDiscoveryStore):
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery store authority is invalid"
        )
    snapshot = snapshot_for_tenant(app, tenant_id)
    if not snapshot.registry.enabled:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery stock adapters are disabled"
        )
    if not snapshot.registry.structured and not snapshot.registry.unstructured:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery stock adapter registry is empty"
        )
    return _TenantPinnedCoordinator(app, snapshot, store)


def _runtime_gate(app: Any, expected: TenantDiscoverySnapshot) -> Callable[[], None]:
    def gate() -> None:
        _same_snapshot(app, expected)
        if (
            not expected.remediation.enabled
            or not expected.remediation.data_map_enabled
        ):
            raise PrivacyDiscoveryAdapterCompositionError(
                "privacy discovery remediation data-map runtime is disabled"
            )

    return gate


def build_remediation_runtime(
    app: Any,
    *,
    tenant_id: str,
    discovery_store: discovery.PrivacyDataDiscoveryStore,
    principal_ref: str,
    outbox_path: str | Path | None = None,
    data_map_path: str | Path | None = None,
    clock: Callable[[], float] = time.time,
) -> PrivacyDiscoveryRemediationRuntime:
    tenant = canonical_tenant_id(tenant_id)
    if not isinstance(discovery_store, discovery.PrivacyDataDiscoveryStore):
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery store authority is invalid"
        )
    if not isinstance(principal_ref, str) or not 1 <= len(principal_ref) <= 512:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery remediation principal is invalid"
        )
    snapshot = snapshot_for_tenant(app, tenant, resolve_transport=False)
    settings = snapshot.remediation
    if not settings.enabled or not settings.data_map_enabled:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery remediation data-map runtime is disabled"
        )
    gate = _runtime_gate(app, snapshot)
    selected_outbox_path = (
        Path(outbox_path)
        if outbox_path is not None
        else data_dir(
            "privacy_automation",
            "privacy-discovery-remediation.sqlite3",
            tenant=tenant,
        )
    )
    selected_target_path = (
        Path(data_map_path)
        if data_map_path is not None
        else data_dir(
            "privacy_automation",
            "privacy-discovery-data-map.sqlite3",
            tenant=tenant,
        )
    )
    with tenant_scope(tenant=tenant):
        outbox = remediation.PrivacyDataDiscoveryRemediationStore(
            selected_outbox_path,
            tenant_id=tenant,
            discovery_store=discovery_store,
            principal_resolver=lambda: principal_ref,
            config_gate=gate,
            clock=clock,
            default_max_attempts=settings.max_attempts,
            default_retention_seconds=settings.retention_seconds,
        )
        target = PrivacyDiscoveryDataMapTarget(
            selected_target_path,
            retention_seconds=settings.data_map_retention_seconds,
            config_gate=gate,
            clock=clock,
        )
    return PrivacyDiscoveryRemediationRuntime(
        tenant_id=tenant,
        config_sha256=snapshot.config_sha256,
        outbox=outbox,
        target=target,
        worker=remediation.PrivacyDataDiscoveryRemediationWorker(
            outbox,
            callback=target,
        ),
        review_callback=outbox.make_review_callback(
            max_attempts=settings.max_attempts,
            retention_seconds=settings.retention_seconds,
        ),
        reconciler=target.reconcile,
    )


def privacy_discovery_readiness(app: Any, tenant_id: str) -> Mapping[str, object]:
    """Side-effect-free tenant readiness; it opens no DB or provider session."""

    tenant = canonical_tenant_id(tenant_id)
    try:
        snapshot = snapshot_for_tenant(app, tenant, resolve_transport=False)
    except Exception:
        return {
            "schema": "lightwork.privacy-discovery-composition-readiness.v1",
            "tenant_id": tenant,
            "enabled": False,
            "configured": False,
            "ready": False,
            "status_probe_opened_store": False,
            "status_probe_invoked_provider": False,
            "live_provider_acceptance_verified": False,
        }
    status = snapshot.registry.status()
    providers = [
        *status["structured_providers"],
        *status["unstructured_providers"],
    ]
    configured = snapshot.registry.enabled and bool(providers)
    return {
        "schema": "lightwork.privacy-discovery-composition-readiness.v1",
        "tenant_id": tenant,
        "config_sha256": snapshot.config_sha256,
        "enabled": snapshot.registry.enabled,
        "configured": configured,
        "ready": configured,
        "structured_providers": status["structured_providers"],
        "unstructured_providers": status["unstructured_providers"],
        "remediation_outbox_enabled": snapshot.remediation.enabled,
        "data_map_target_enabled": snapshot.remediation.data_map_enabled,
        "remediation_scheduler_enabled": (
            snapshot.remediation.scheduler.enabled
            and snapshot.remediation.enabled
            and snapshot.remediation.data_map_enabled
        ),
        "remediation_scheduler_bounds": {
            "interval_seconds": snapshot.remediation.scheduler.interval_seconds,
            "jitter_seconds": snapshot.remediation.scheduler.jitter_seconds,
            "retry_max_seconds": snapshot.remediation.scheduler.retry_max_seconds,
            "tenant_limit": snapshot.remediation.scheduler.tenant_limit,
            "worker_limit": snapshot.remediation.scheduler.worker_limit,
            "reconcile_limit": snapshot.remediation.scheduler.reconcile_limit,
            "lease_seconds": snapshot.remediation.scheduler.lease_seconds,
        },
        "approved_review_callback_factory_installed": callable(
            getattr(
                app.state,
                "privacy_data_discovery_review_callback_factory",
                None,
            )
        ),
        "approved_review_callback_durable_outbox": (
            getattr(
                app.state,
                "privacy_data_discovery_review_callback_durable_outbox",
                False,
            )
            is True
        ),
        "retry_worker_factory_installed": callable(
            getattr(
                app.state,
                "privacy_data_discovery_worker_factory",
                None,
            )
        ),
        "reconciler_factory_installed": callable(
            getattr(
                app.state,
                "privacy_data_discovery_data_map_reconciler_factory",
                None,
            )
        ),
        "maintenance_factory_installed": callable(
            getattr(
                app.state,
                "privacy_data_discovery_maintenance_factory",
                None,
            )
        ),
        "source_credentials_resolved_on_execution_only": True,
        "source_credentials_checked_by_status": False,
        "status_probe_opened_store": False,
        "status_probe_invoked_provider": False,
        "raw_data_returned": False,
        "estate_completeness_claimed": False,
        "live_provider_acceptance_verified": False,
        "limitations": status["limitations"],
    }


def _dispatch_approved_review(
    app: Any,
    update: discovery.ReviewedClassification,
) -> None:
    """Lazily bridge the API's approved-review callback to the durable outbox."""

    if type(update) is not discovery.ReviewedClassification:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery approved review contract is invalid"
        )
    tenant = canonical_tenant_id(update.tenant_id)
    if update.tenant_id != tenant:
        raise PrivacyDiscoveryAdapterCompositionError(
            "privacy discovery approved review tenant is invalid"
        )
    with tenant_scope(tenant=tenant):
        discovery_store = discovery.PrivacyDataDiscoveryStore(
            data_dir(
                "privacy_automation",
                "privacy-data-discovery.sqlite3",
                tenant=tenant,
            )
        )
        runtime = build_remediation_runtime(
            app,
            tenant_id=tenant,
            discovery_store=discovery_store,
            principal_ref="privacy-discovery-approved-review-dispatcher",
        )
        runtime.review_callback(update)


def _install_callable(
    state: Any,
    name: str,
    value: Callable[..., object],
    label: str,
) -> None:
    existing = getattr(state, name, None)
    if existing is None:
        setattr(state, name, value)
    elif not callable(existing):
        raise TypeError(f"{label} must be callable")


def attach_privacy_data_discovery_adapters(app: Any) -> None:
    """Attach tenant-lazy factories; no config/store/credential work happens."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    approved_callback_was_absent = (
        getattr(state, "privacy_data_discovery_review_callback", None) is None
    )

    def coordinator_factory(
        *,
        tenant_id: str,
        store: discovery.PrivacyDataDiscoveryStore,
    ) -> discovery.PrivacyDataDiscoveryCoordinator:
        return build_tenant_discovery_coordinator(
            app,
            tenant_id=tenant_id,
            store=store,
        )

    def runtime_factory(
        *,
        tenant_id: str,
        discovery_store: discovery.PrivacyDataDiscoveryStore,
        principal_ref: str,
    ) -> PrivacyDiscoveryRemediationRuntime:
        return build_remediation_runtime(
            app,
            tenant_id=tenant_id,
            discovery_store=discovery_store,
            principal_ref=principal_ref,
        )

    def review_callback_factory(
        *,
        tenant_id: str,
        discovery_store: discovery.PrivacyDataDiscoveryStore,
        principal_ref: str,
    ) -> Callable[[discovery.ReviewedClassification], None]:
        return state.privacy_data_discovery_remediation_runtime_factory(
            tenant_id=tenant_id,
            discovery_store=discovery_store,
            principal_ref=principal_ref,
        ).review_callback

    def worker_factory(
        *,
        tenant_id: str,
        discovery_store: discovery.PrivacyDataDiscoveryStore,
        principal_ref: str,
    ) -> remediation.PrivacyDataDiscoveryRemediationWorker:
        return state.privacy_data_discovery_remediation_runtime_factory(
            tenant_id=tenant_id,
            discovery_store=discovery_store,
            principal_ref=principal_ref,
        ).worker

    def reconciler_factory(
        *,
        tenant_id: str,
        discovery_store: discovery.PrivacyDataDiscoveryStore,
        principal_ref: str,
    ) -> Callable[
        [remediation.RemediationReconciliationProbe],
        remediation.RemediationReconciliationResult,
    ]:
        return state.privacy_data_discovery_remediation_runtime_factory(
            tenant_id=tenant_id,
            discovery_store=discovery_store,
            principal_ref=principal_ref,
        ).reconciler

    installs = (
        (
            "privacy_data_discovery_coordinator_factory",
            coordinator_factory,
            "privacy discovery coordinator factory",
        ),
        (
            "privacy_data_discovery_remediation_runtime_factory",
            runtime_factory,
            "privacy discovery remediation runtime factory",
        ),
        (
            "privacy_data_discovery_review_callback_factory",
            review_callback_factory,
            "privacy discovery review callback factory",
        ),
        (
            "privacy_data_discovery_worker_factory",
            worker_factory,
            "privacy discovery remediation worker factory",
        ),
        (
            "privacy_data_discovery_data_map_reconciler_factory",
            reconciler_factory,
            "privacy discovery data-map reconciler factory",
        ),
        (
            "privacy_data_discovery_readiness_probe",
            lambda tenant_id: privacy_discovery_readiness(app, tenant_id),
            "privacy discovery readiness probe",
        ),
        (
            "privacy_data_discovery_review_callback",
            lambda update: _dispatch_approved_review(app, update),
            "privacy discovery approved-review callback",
        ),
    )
    for name, value, label in installs:
        _install_callable(state, name, value, label)
    durable_marker = getattr(
        state,
        "privacy_data_discovery_review_callback_durable_outbox",
        None,
    )
    if durable_marker is not None and type(durable_marker) is not bool:
        raise TypeError(
            "privacy discovery approved-review durability marker must be boolean"
        )
    if approved_callback_was_absent:
        state.privacy_data_discovery_review_callback_durable_outbox = True
    elif durable_marker is None:
        state.privacy_data_discovery_review_callback_durable_outbox = False
    _install_callable(
        state,
        "privacy_data_discovery_maintenance_factory",
        state.privacy_data_discovery_remediation_runtime_factory,
        "privacy discovery maintenance factory",
    )


# Backwards-compatible root integration name.  This attaches lazy factories;
# it does not install a global, cross-tenant provider map.
install_privacy_data_discovery_adapters = attach_privacy_data_discovery_adapters


__all__ = [
    "PrivacyDiscoveryAdapterCompositionError",
    "PrivacyDiscoveryRemediationRuntime",
    "RemediationCompositionSettings",
    "RemediationSchedulerSettings",
    "TenantDiscoverySnapshot",
    "attach_privacy_data_discovery_adapters",
    "build_remediation_runtime",
    "build_tenant_discovery_coordinator",
    "install_privacy_data_discovery_adapters",
    "privacy_discovery_readiness",
    "remediation_scheduler_settings",
    "snapshot_for_tenant",
]
