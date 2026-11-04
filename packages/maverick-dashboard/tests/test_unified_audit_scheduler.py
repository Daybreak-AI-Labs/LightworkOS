from __future__ import annotations

import re
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick import unified_audit as audit
from maverick_dashboard import unified_audit_scheduler as scheduler_module
from maverick_dashboard.unified_audit_scheduler import (
    UnifiedAuditScheduler,
    UnifiedAuditSchedulerConfigurationError,
    UnifiedAuditSchedulerError,
    attach_unified_audit_scheduler,
    scheduler_settings,
)


def config(
    *,
    enable: bool = True,
    sign: bool = True,
    poll_seconds: object = 60,
) -> dict[str, object]:
    return {
        "audit": {
            "sign": sign,
            "unified": {
                "enable": enable,
                "page_size": 100,
                "lease_seconds": 120,
                "max_lag_seconds": 300,
                "max_attempts": 5,
                "retry_backoff_seconds": 30,
                "poll_seconds": poll_seconds,
            },
        }
    }


def fixed_six(*, failed_source: str | None = None):
    return tuple(
        SimpleNamespace(
            source_id=source_id,
            outcome="failed" if source_id == failed_source else "committed",
        )
        for source_id in audit.REQUIRED_SUITES
    )


@contextmanager
def null_context():
    yield


def test_settings_are_default_off_bounded_and_require_signed_audit() -> None:
    assert scheduler_settings({}) is None
    assert scheduler_settings(config(enable=False)) is None
    settings = scheduler_settings(config())
    assert settings is not None
    assert settings.poll_seconds == 60.0
    with pytest.raises(UnifiedAuditSchedulerConfigurationError, match="signed"):
        scheduler_settings(config(sign=False))
    for value in (4, 3_601, float("nan"), True):
        with pytest.raises(UnifiedAuditSchedulerConfigurationError):
            scheduler_settings(config(poll_seconds=value))


def test_disabled_scheduler_does_not_touch_tenants_probe_or_factory() -> None:
    touched: list[str] = []
    runtime = UnifiedAuditScheduler(
        projector_factory=lambda *_args: touched.append("factory"),
        enabled_probe=lambda _tenant: touched.append("probe") or True,
        tenant_supplier=lambda: touched.append("tenants") or ("tenant-a",),
        tenant_context=lambda _tenant: null_context(),
        config_loader=lambda: config(enable=False),
    )
    assert runtime.run_once() is None
    assert runtime.start() is False
    assert touched == []


def test_default_supplier_uses_only_active_admitted_registry_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick.tenant import registry

    monkeypatch.setattr(
        registry,
        "list_tenants",
        lambda: [
            SimpleNamespace(id="tenant-active", active=True),
            SimpleNamespace(id="tenant-suspended", active=False),
            SimpleNamespace(id="tenant-ambiguous", active=1),
        ],
    )
    assert scheduler_module._default_tenant_supplier() == ("tenant-active",)


def test_admission_is_rechecked_after_enumeration_and_failure_is_isolated() -> None:
    probes: list[str] = []
    runs: list[str] = []

    def admit(tenant_id: str) -> None:
        if tenant_id == "tenant-suspended-after-list":
            raise PermissionError("tenant no longer active")

    runtime = UnifiedAuditScheduler(
        projector_factory=lambda tenant, _principal: SimpleNamespace(
            run_all=lambda **_kwargs: runs.append(tenant) or fixed_six()
        ),
        enabled_probe=lambda tenant: probes.append(tenant) or True,
        tenant_supplier=lambda: (
            "tenant-suspended-after-list",
            "tenant-still-active",
        ),
        tenant_admitter=admit,
        tenant_context=lambda _tenant: null_context(),
        config_loader=lambda: config(),
        clock=lambda: 1_800_000_000.0,
    )
    cycle = runtime.run_once()
    assert cycle is not None
    assert probes == runs == ["tenant-still-active"]
    assert cycle.tenants_failed == 1
    assert cycle.tenant_runs_completed == 1


def test_cycle_is_tenant_scoped_fixed_six_and_worker_ids_are_stable_digests() -> None:
    active = ["outside"]
    factory_calls: list[tuple[str, str]] = []
    worker_calls: list[tuple[str, str]] = []

    @contextmanager
    def tenant_context(tenant_id: str):
        prior = active[0]
        active[0] = tenant_id
        try:
            yield
        finally:
            active[0] = prior

    def enabled_probe(tenant_id: str) -> bool:
        assert active[0] == tenant_id
        return tenant_id != "tenant-disabled"

    class Projector:
        def __init__(self, tenant_id: str) -> None:
            self.tenant_id = tenant_id

        def run_all(self, *, worker_id: str):
            assert active[0] == self.tenant_id
            worker_calls.append((self.tenant_id, worker_id))
            return fixed_six()

    def factory(tenant_id: str, principal_ref: str):
        assert active[0] == tenant_id
        factory_calls.append((tenant_id, principal_ref))
        return Projector(tenant_id)

    runtime = UnifiedAuditScheduler(
        projector_factory=factory,
        enabled_probe=enabled_probe,
        tenant_supplier=lambda: (
            "tenant-a",
            "tenant-disabled",
            "tenant-b",
        ),
        tenant_context=tenant_context,
        config_loader=lambda: config(),
        clock=lambda: 1_800_000_000.0,
    )
    first = runtime.run_once()
    second = runtime.run_once()
    assert first is not None and second is not None
    assert first.tenants_considered == 3
    assert first.tenants_enabled == 2
    assert first.tenant_runs_attempted == first.tenant_runs_completed == 2
    assert first.sources_committed == 12
    assert first.sources_unavailable == first.sources_failed == 0
    assert active[0] == "outside"
    assert len(factory_calls) == len(worker_calls) == 4
    for (tenant, principal), (worker_tenant, worker) in zip(
        factory_calls,
        worker_calls,
        strict=True,
    ):
        assert tenant == worker_tenant
        assert principal == worker
        assert re.fullmatch(r"[0-9a-f]{64}", worker)
        assert tenant not in worker
    assert worker_calls[0][1] == worker_calls[2][1]
    assert worker_calls[1][1] == worker_calls[3][1]
    assert worker_calls[0][1] != worker_calls[1][1]


def test_tenant_and_source_failures_are_isolated_without_detail_retention() -> None:
    calls: list[str] = []

    class Projector:
        def __init__(self, tenant_id: str) -> None:
            self.tenant_id = tenant_id

        def run_all(self, *, worker_id: str):
            assert re.fullmatch(r"[0-9a-f]{64}", worker_id)
            calls.append(self.tenant_id)
            failed = (
                audit.REQUIRED_SUITES[0]
                if self.tenant_id == "tenant-source-failure"
                else None
            )
            return fixed_six(failed_source=failed)

    def factory(tenant_id: str, _principal_ref: str):
        if tenant_id == "tenant-factory-failure":
            raise RuntimeError("secret-provider-error")
        return Projector(tenant_id)

    runtime = UnifiedAuditScheduler(
        projector_factory=factory,
        enabled_probe=lambda _tenant: True,
        tenant_supplier=lambda: (
            "tenant-factory-failure",
            "tenant-source-failure",
            "tenant-good",
        ),
        tenant_context=lambda _tenant: null_context(),
        config_loader=lambda: config(),
        clock=lambda: 1_800_000_000.0,
    )
    cycle = runtime.run_once()
    assert cycle is not None
    assert calls == ["tenant-source-failure", "tenant-good"]
    assert cycle.tenants_failed == 1
    assert cycle.tenants_with_source_failures == 1
    assert cycle.tenant_runs_completed == 2
    assert cycle.sources_committed == 11
    assert cycle.sources_failed == 1
    status = runtime.status()
    assert status["last_error_code"] == "tenant_cycle_failed"
    assert status["live_completeness_verified"] is False
    assert status["live_customer_acceptance_verified"] is False
    assert status["tenant_identifiers_retained"] is False
    assert status["network_io_performed"] is False
    assert "tenant-" not in repr(status)
    assert "secret-provider-error" not in repr(status)


def test_fixed_six_contract_rejects_missing_duplicate_or_reordered_results() -> None:
    invalid = (
        fixed_six()[:-1],
        fixed_six()[::-1],
        fixed_six()[:-1] + (fixed_six()[0],),
    )
    for result in invalid:
        runtime = UnifiedAuditScheduler(
            projector_factory=lambda *_args, result=result: SimpleNamespace(
                run_all=lambda **_kwargs: result
            ),
            enabled_probe=lambda _tenant: True,
            tenant_supplier=lambda: ("tenant-a",),
            tenant_context=lambda _tenant: null_context(),
            config_loader=lambda: config(),
            clock=lambda: 1_800_000_000.0,
        )
        cycle = runtime.run_once()
        assert cycle is not None
        assert cycle.tenants_failed == 1
        assert cycle.tenant_runs_completed == 0


def test_tenant_cap_overlap_and_stop_bounds_are_explicit() -> None:
    runtime = UnifiedAuditScheduler(
        projector_factory=lambda *_args: SimpleNamespace(run_all=lambda **_kwargs: fixed_six()),
        enabled_probe=lambda _tenant: False,
        tenant_supplier=lambda: tuple(
            f"tenant-{index}" for index in range(scheduler_module._MAX_TENANTS_PER_CYCLE + 1)
        ),
        tenant_context=lambda _tenant: null_context(),
        config_loader=lambda: config(),
        clock=lambda: 1_800_000_000.0,
    )
    cycle = runtime.run_once()
    assert cycle is not None
    assert cycle.tenants_considered == scheduler_module._MAX_TENANTS_PER_CYCLE
    assert cycle.tenant_limit_reached is True
    assert runtime._cycle_lock.acquire(blocking=False)
    try:
        with pytest.raises(UnifiedAuditSchedulerError, match="already_running"):
            runtime.run_once()
    finally:
        runtime._cycle_lock.release()
    with pytest.raises(ValueError, match="stop timeout"):
        runtime.stop(timeout=31)


def test_start_stop_are_bounded_and_do_not_duplicate_threads() -> None:
    ran = threading.Event()

    class Projector:
        @staticmethod
        def run_all(*, worker_id: str):
            assert re.fullmatch(r"[0-9a-f]{64}", worker_id)
            ran.set()
            return fixed_six()

    runtime = UnifiedAuditScheduler(
        projector_factory=lambda *_args: Projector(),
        enabled_probe=lambda _tenant: True,
        tenant_supplier=lambda: ("tenant-a",),
        tenant_context=lambda _tenant: null_context(),
        config_loader=lambda: config(poll_seconds=5),
    )
    assert runtime.start() is True
    thread = runtime._thread
    assert runtime.start() is True
    assert runtime._thread is thread
    assert ran.wait(2.0)
    assert runtime.stop(timeout=2.0) is True
    assert runtime.status()["running"] is False


def test_cancellation_stops_between_tenants_without_partial_source_sweeps() -> None:
    calls: list[str] = []
    holder: list[UnifiedAuditScheduler] = []

    class Projector:
        def __init__(self, tenant_id: str) -> None:
            self.tenant_id = tenant_id

        def run_all(self, *, worker_id: str):
            assert re.fullmatch(r"[0-9a-f]{64}", worker_id)
            calls.append(self.tenant_id)
            holder[0]._stop.set()
            return fixed_six()

    runtime = UnifiedAuditScheduler(
        projector_factory=lambda tenant, _principal: Projector(tenant),
        enabled_probe=lambda _tenant: True,
        tenant_supplier=lambda: ("tenant-a", "tenant-b"),
        tenant_context=lambda _tenant: null_context(),
        config_loader=lambda: config(),
        clock=lambda: 1_800_000_000.0,
    )
    holder.append(runtime)
    cycle = runtime.run_once()
    assert cycle is not None
    assert calls == ["tenant-a"]
    assert cycle.sources_committed == 6
    assert cycle.cancelled is True
    assert cycle.tenants_considered == 1


def test_lifespan_attachment_is_idempotent_and_uses_server_owned_factories() -> None:
    calls: list[tuple[object, ...]] = []
    app = FastAPI()
    app.state.unified_audit_enabled_probe = (
        lambda tenant: calls.append(("probe", tenant)) or True
    )
    generic_projector = object()
    app.state.unified_audit_projector_factory = (
        lambda tenant, principal, request: calls.append(
            ("generic", tenant, principal, request)
        )
        or generic_projector
    )
    attached = attach_unified_audit_scheduler(app)
    worker = "a" * 64
    assert attached._enabled_probe("tenant-a") is True
    assert attached._projector_factory("tenant-a", worker) is generic_projector
    assert calls[-1] == ("generic", "tenant-a", worker, None)

    narrow_projector = object()
    app.state.unified_audit_scheduler_projector_factory = (
        lambda tenant, principal: calls.append(("narrow", tenant, principal))
        or narrow_projector
    )
    assert attached._projector_factory("tenant-a", worker) is narrow_projector
    assert calls[-1] == ("narrow", "tenant-a", worker)
    assert attach_unified_audit_scheduler(app, runtime=attached) is attached

    class OtherRuntime:
        pass

    with pytest.raises(RuntimeError, match="already attached"):
        attach_unified_audit_scheduler(app, runtime=OtherRuntime())


def test_lifespan_starts_and_stops_injected_runtime_once() -> None:
    class Runtime:
        def __init__(self) -> None:
            self.starts = 0
            self.stops = 0

        def start(self):
            self.starts += 1
            return True

        def stop(self):
            self.stops += 1
            return True

    runtime = Runtime()
    app = FastAPI()
    attach_unified_audit_scheduler(app, runtime=runtime)
    with TestClient(app, base_url="http://127.0.0.1"):
        assert runtime.starts == 1
        assert runtime.stops == 0
    assert runtime.stops == 1


def test_shipped_app_attaches_default_off_scheduler_after_composition() -> None:
    from maverick_dashboard.app import app

    assert callable(app.state.unified_audit_enabled_probe)
    assert callable(app.state.unified_audit_projector_factory)
    assert isinstance(app.state.unified_audit_scheduler, UnifiedAuditScheduler)
