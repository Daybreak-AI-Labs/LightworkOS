from __future__ import annotations

import threading
from contextlib import contextmanager

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick import data_use_provider_audit as audit
from maverick_dashboard.data_use_provider_audit_scheduler import (
    DataUseProviderAuditScheduler,
    DataUseProviderAuditSchedulerConfigurationError,
    DataUseProviderAuditSchedulerError,
    attach_data_use_provider_audit_scheduler,
    scheduler_settings,
)


def config(
    *,
    root=True,
    enforcement=True,
    audit_enabled=True,
    scheduler=True,
    provider=True,
    **scheduler_overrides,
):
    scheduler_config = {
        "enable": scheduler,
        "poll_seconds": 60,
        "claim_limit": 10,
        "tenant_limit": 10,
        "lease_seconds": 120,
        "event_limit": 100,
        "retry_backoff_seconds": 30,
        "purge_limit": 100,
        **scheduler_overrides,
    }
    return {
        "data_use_governance": {
            "enable": root,
            "enforcement": {"enable": enforcement},
            "provider_audit": {
                "enable": audit_enabled,
                "scheduler": scheduler_config,
            },
            "snowflake": {"enable": provider},
            "databricks": {"enable": False},
        }
    }


class Clock:
    def __init__(self) -> None:
        self.value = 1_800_000_000.0

    def __call__(self) -> float:
        return self.value


class FakeStore:
    def __init__(self, purged: int = 1) -> None:
        self.purged = purged
        self.purge_calls: list[dict[str, object]] = []

    def purge_expired(self, **kwargs):
        self.purge_calls.append(kwargs)
        return self.purged


class FakeWorker:
    def __init__(self, *, event: threading.Event | None = None) -> None:
        self.store = FakeStore()
        self.calls: list[dict[str, object]] = []
        self.event = event

    def run_once(self, **kwargs):
        self.calls.append(kwargs)
        if self.event is not None:
            self.event.set()
        return audit.ProviderAuditWorkerResult(
            claimed=2,
            converged=1,
            no_change=0,
            findings=1,
            retried=0,
            dead_lettered=0,
            cancelled=0,
        )


def test_settings_are_nested_default_off_and_fail_closed():
    assert scheduler_settings({}) is None
    assert scheduler_settings(config(root=False)) is None
    assert scheduler_settings(config(enforcement=False)) is None
    assert scheduler_settings(config(audit_enabled=False)) is None
    assert scheduler_settings(config(scheduler=False)) is None
    assert scheduler_settings(config(provider=False)) is None
    settings = scheduler_settings(config())
    assert settings is not None
    assert settings.claim_limit == 10
    assert settings.tenant_limit == 10
    assert settings.event_limit == 100

    malformed = config(unknown_key=True)
    with pytest.raises(DataUseProviderAuditSchedulerConfigurationError, match="unsupported"):
        scheduler_settings(malformed)
    for key, value in (
        ("poll_seconds", 4),
        ("claim_limit", 101),
        ("tenant_limit", 0),
        ("lease_seconds", 29),
        ("event_limit", 501),
        ("retry_backoff_seconds", -1),
        ("purge_limit", 501),
    ):
        with pytest.raises(DataUseProviderAuditSchedulerConfigurationError, match="bound"):
            scheduler_settings(config(**{key: value}))


def test_cycle_respects_tenant_gate_context_reset_and_worker_bounds():
    clock = Clock()
    workers = {"tenant-a": FakeWorker(), "tenant-b": FakeWorker()}
    active = ["outside"]

    @contextmanager
    def tenant_context(tenant_id):
        prior = active[0]
        active[0] = tenant_id
        try:
            yield
        finally:
            active[0] = prior

    def tenant_config():
        return config(scheduler=active[0] == "tenant-a")

    def worker_factory(tenant_id, principal_ref):
        assert active[0] == tenant_id
        assert principal_ref.startswith("provider-audit-scheduler.")
        return workers[tenant_id]

    runtime = DataUseProviderAuditScheduler(
        worker_factory=worker_factory,
        tenant_supplier=lambda: ("tenant-a", "tenant-b"),
        tenant_context=tenant_context,
        config_loader=lambda: config(),
        tenant_config_loader=tenant_config,
        clock=clock,
        worker_id="provider-audit-test",
    )
    cycle = runtime.run_once()
    assert cycle is not None
    assert cycle.tenants_considered == 2
    assert cycle.tenants_enabled == 1
    assert cycle.tenants_failed == 0
    assert cycle.claimed == 2
    assert cycle.converged == 1
    assert cycle.findings == 1
    assert cycle.purged == 1
    assert active[0] == "outside"
    assert len(workers["tenant-a"].calls) == 1
    assert workers["tenant-b"].calls == []
    call = workers["tenant-a"].calls[0]
    assert call == {
        "worker_id": "provider-audit-test",
        "limit": 10,
        "lease_seconds": 120,
        "event_limit": 100,
        "backoff_seconds": 30,
    }
    assert workers["tenant-a"].store.purge_calls == [{"cutoff": clock.value, "limit": 100}]


def test_active_tenant_cap_is_explicit_and_status_is_digest_only():
    workers: dict[str, FakeWorker] = {}

    def worker_factory(tenant_id, _principal):
        workers[tenant_id] = FakeWorker()
        return workers[tenant_id]

    runtime = DataUseProviderAuditScheduler(
        worker_factory=worker_factory,
        tenant_supplier=lambda: ("tenant-a", "tenant-b", "tenant-c"),
        tenant_context=lambda _tenant: _null_context(),
        config_loader=lambda: config(tenant_limit=2),
        tenant_config_loader=lambda: config(tenant_limit=2),
        worker_id="provider-audit-test",
    )
    cycle = runtime.run_once()
    assert cycle is not None
    assert cycle.tenants_considered == 2
    assert cycle.tenant_limit_reached is True
    assert set(workers) == {"tenant-a", "tenant-b"}
    status = runtime.status()
    assert status["cycles"] == 1
    assert status["tenant_identifiers_retained"] is False
    assert status["provider_error_details_retained"] is False
    assert "tenant-a" not in repr(status)
    assert "tenant-b" not in repr(status)


@contextmanager
def _null_context():
    yield


def test_one_tenant_failure_does_not_stop_another_or_leak_detail():
    good = FakeWorker()

    def worker_factory(tenant_id, _principal):
        if tenant_id == "tenant-bad":
            raise RuntimeError("provider-secret-must-not-escape")
        return good

    runtime = DataUseProviderAuditScheduler(
        worker_factory=worker_factory,
        tenant_supplier=lambda: ("tenant-bad", "tenant-good"),
        tenant_context=lambda _tenant: _null_context(),
        config_loader=lambda: config(),
        tenant_config_loader=lambda: config(),
        worker_id="provider-audit-test",
    )
    cycle = runtime.run_once()
    assert cycle is not None
    assert cycle.tenants_failed == 1
    assert cycle.claimed == 2
    assert len(good.calls) == 1
    status = runtime.status()
    assert status["last_error_code"] == "tenant_cycle_failed"
    assert "provider-secret-must-not-escape" not in repr(status)
    assert "tenant-bad" not in repr(status)


def test_purge_runs_when_worker_batch_fails_and_failure_is_isolated():
    class FailedWorker(FakeWorker):
        def run_once(self, **kwargs):
            self.calls.append(kwargs)
            raise RuntimeError("raw-provider-payload")

    worker = FailedWorker()
    runtime = DataUseProviderAuditScheduler(
        worker_factory=lambda *_args: worker,
        tenant_supplier=lambda: ("tenant-a",),
        tenant_context=lambda _tenant: _null_context(),
        config_loader=lambda: config(),
        tenant_config_loader=lambda: config(),
        worker_id="provider-audit-test",
    )
    cycle = runtime.run_once()
    assert cycle is not None
    assert cycle.tenants_failed == 1
    assert cycle.claimed == 0
    assert cycle.purged == 1
    assert len(worker.store.purge_calls) == 1
    assert "raw-provider-payload" not in repr(runtime.status())


def test_disabled_scheduler_does_not_touch_tenants_or_worker():
    touched: list[str] = []
    runtime = DataUseProviderAuditScheduler(
        worker_factory=lambda *_args: touched.append("worker"),
        tenant_supplier=lambda: touched.append("tenants") or (),
        config_loader=lambda: config(scheduler=False),
        tenant_config_loader=lambda: config(scheduler=False),
        worker_id="provider-audit-test",
    )
    assert runtime.run_once() is None
    assert runtime.start() is False
    assert touched == []


def test_scheduler_rejects_overlap_invalid_alias_and_unbounded_stop():
    runtime = DataUseProviderAuditScheduler(
        worker_factory=lambda *_args: FakeWorker(),
        tenant_supplier=lambda: ("tenant-a",),
        tenant_context=lambda _tenant: _null_context(),
        config_loader=lambda: config(),
        tenant_config_loader=lambda: config(),
        worker_id="provider-audit-test",
    )
    assert runtime._cycle_lock.acquire(blocking=False)
    try:
        with pytest.raises(DataUseProviderAuditSchedulerError, match="already_running"):
            runtime.run_once()
    finally:
        runtime._cycle_lock.release()

    invalid = DataUseProviderAuditScheduler(
        worker_factory=lambda *_args: FakeWorker(),
        tenant_supplier=lambda: ("tenant-with-space ",),
        tenant_context=lambda _tenant: _null_context(),
        config_loader=lambda: config(),
        tenant_config_loader=lambda: config(),
        worker_id="provider-audit-test",
    )
    with pytest.raises(DataUseProviderAuditSchedulerError, match="tenant_supplier_invalid"):
        invalid.run_once()
    with pytest.raises(ValueError, match="timeout"):
        runtime.stop(timeout=31)


def test_start_and_stop_are_bounded_and_nonduplicating():
    ran = threading.Event()
    worker = FakeWorker(event=ran)
    runtime = DataUseProviderAuditScheduler(
        worker_factory=lambda *_args: worker,
        tenant_supplier=lambda: ("tenant-a",),
        tenant_context=lambda _tenant: _null_context(),
        config_loader=lambda: config(poll_seconds=5),
        tenant_config_loader=lambda: config(poll_seconds=5),
        worker_id="provider-audit-test",
    )
    assert runtime.start() is True
    assert runtime.start() is True
    assert ran.wait(2.0)
    assert runtime.stop(timeout=2.0) is True
    assert runtime.status()["running"] is False


def test_lifespan_attachment_starts_and_stops_exactly_once():
    class LifecycleRuntime:
        def __init__(self) -> None:
            self.starts = 0
            self.stops = 0

        def start(self):
            self.starts += 1
            return True

        def stop(self):
            self.stops += 1
            return True

    app = FastAPI()
    runtime = LifecycleRuntime()
    selected = attach_data_use_provider_audit_scheduler(
        app,
        worker_factory=lambda *_args: FakeWorker(),
        runtime=runtime,
    )
    assert selected is runtime
    assert app.state.data_use_provider_audit_scheduler is runtime
    assert (
        attach_data_use_provider_audit_scheduler(
            app,
            worker_factory=lambda *_args: FakeWorker(),
            runtime=runtime,
        )
        is runtime
    )
    with pytest.raises(RuntimeError, match="already attached"):
        attach_data_use_provider_audit_scheduler(
            app,
            worker_factory=lambda *_args: FakeWorker(),
            runtime=LifecycleRuntime(),
        )

    with TestClient(app, base_url="http://127.0.0.1"):
        assert runtime.starts == 1
        assert runtime.stops == 0
    assert runtime.stops == 1
