from __future__ import annotations

import threading
from contextlib import contextmanager

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick_dashboard.ai_governance_loop_composition import (
    AIGovernanceLoopBatchResult,
)
from maverick_dashboard.ai_governance_loop_scheduler import (
    AIGovernanceLoopScheduler,
    AIGovernanceLoopSchedulerConfigurationError,
    AIGovernanceLoopSchedulerError,
    attach_ai_governance_loop_scheduler,
    scheduler_settings,
)


def config(*, enabled: object = True, **overrides: object) -> dict[str, object]:
    return {
        "ai_inventory": {"enable": True},
        "ai_dynamic_risk": {"enable": True},
        "ai_policy_management": {"enable": True},
        "ai_runtime_guardrails": {"enable": True},
        "ai_governance_loop": {
            "enable": enabled,
            "poll_seconds": 5,
            "batch_size": 7,
            "lease_seconds": 60,
            "max_attempts": 4,
            "retry_base_seconds": 2,
            "max_lag_seconds": 300,
            **overrides,
        },
    }


class Clock:
    def __init__(self) -> None:
        self.value = 1_800_000_000.0

    def __call__(self) -> float:
        self.value += 0.01
        return self.value


class Worker:
    def __init__(
        self,
        tenant_id: str,
        principal_ref: str,
        *,
        event: threading.Event | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.principal_ref = principal_ref
        self.event = event
        self.calls: list[dict[str, object]] = []

    def run_batch(self, **kwargs):
        self.calls.append(kwargs)
        if self.event is not None:
            self.event.set()
        return AIGovernanceLoopBatchResult(
            processed=2,
            failed=1,
            no_change=1,
            idle=True,
        )


@contextmanager
def null_context():
    yield


def test_settings_are_exact_default_off_and_reject_malformed_values() -> None:
    assert scheduler_settings({}) is None
    assert scheduler_settings(config(enabled=False)) is None
    settings = scheduler_settings(config())
    assert settings is not None
    assert settings.batch_size == 7
    with pytest.raises(AIGovernanceLoopSchedulerConfigurationError, match="boolean"):
        scheduler_settings(config(enabled=1))
    with pytest.raises(AIGovernanceLoopSchedulerConfigurationError, match="unsupported"):
        scheduler_settings(config(credential="secret"))
    with pytest.raises(AIGovernanceLoopSchedulerConfigurationError, match="bound"):
        scheduler_settings(config(batch_size=0))


def test_cycle_rechecks_each_tenant_gate_resets_context_and_uses_batch_bound() -> None:
    active = ["outside"]
    workers: dict[str, Worker] = {}

    @contextmanager
    def tenant_context(tenant_id: str):
        prior = active[0]
        active[0] = tenant_id
        try:
            yield
        finally:
            active[0] = prior

    def tenant_config():
        return config(enabled=active[0] == "tenant-a")

    def factory(tenant_id: str, principal_ref: str):
        assert active[0] == tenant_id
        worker = Worker(tenant_id, principal_ref)
        workers[tenant_id] = worker
        return worker

    runtime = AIGovernanceLoopScheduler(
        worker_factory=factory,
        tenant_supplier=lambda: ("tenant-a", "tenant-b"),
        tenant_context=tenant_context,
        config_loader=config,
        tenant_config_loader=tenant_config,
        clock=Clock(),
        worker_id="scheduler-test",
    )
    cycle = runtime.run_once()
    assert cycle is not None
    assert cycle.tenants_considered == 2
    assert cycle.tenants_enabled == 1
    assert cycle.tenants_failed == 0
    assert cycle.processed == 2
    assert cycle.failed == 1
    assert cycle.no_change == 1
    assert cycle.idle_tenants == 1
    assert active[0] == "outside"
    assert set(workers) == {"tenant-a"}
    assert workers["tenant-a"].calls == [{"worker_id": "scheduler-test", "limit": 7}]


def test_explicit_tenant_cap_and_status_retain_no_tenant_identifiers() -> None:
    workers: dict[str, Worker] = {}

    def factory(tenant_id: str, principal_ref: str):
        worker = Worker(tenant_id, principal_ref)
        workers[tenant_id] = worker
        return worker

    runtime = AIGovernanceLoopScheduler(
        worker_factory=factory,
        tenant_supplier=lambda: ("tenant-a", "tenant-b", "tenant-c", "tenant-d"),
        tenant_context=lambda _tenant: null_context(),
        config_loader=config,
        tenant_config_loader=config,
        worker_id="scheduler-test",
        tenant_limit=2,
    )
    cycle = runtime.run_once()
    assert cycle is not None
    assert cycle.tenants_considered == 2
    assert cycle.tenant_limit_reached is True
    assert set(workers) == {"tenant-a", "tenant-b"}
    status = runtime.status()
    assert status["tenant_limit"] == 2
    assert status["tenant_identifiers_retained"] is False
    assert status["authority_error_details_retained"] is False
    assert "tenant-a" not in repr(status)
    assert "tenant-b" not in repr(status)


def test_tenant_failure_is_isolated_and_raw_error_detail_is_not_retained() -> None:
    good: list[Worker] = []

    def factory(tenant_id: str, principal_ref: str):
        if tenant_id == "tenant-bad":
            raise RuntimeError("raw-authority-payload-and-credential")
        worker = Worker(tenant_id, principal_ref)
        good.append(worker)
        return worker

    runtime = AIGovernanceLoopScheduler(
        worker_factory=factory,
        tenant_supplier=lambda: ("tenant-bad", "tenant-good"),
        tenant_context=lambda _tenant: null_context(),
        config_loader=config,
        tenant_config_loader=config,
        worker_id="scheduler-test",
    )
    cycle = runtime.run_once()
    assert cycle is not None
    assert cycle.tenants_failed == 1
    assert cycle.processed == 2
    assert len(good) == 1
    status = runtime.status()
    assert status["last_error_code"] == "tenant_cycle_failed"
    assert "raw-authority-payload-and-credential" not in repr(status)
    assert "tenant-bad" not in repr(status)


def test_an_install_without_a_tenant_has_nothing_to_process_and_nothing_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick.tenant import registry
    from maverick_dashboard import trc_continuous_evidence_scheduler as evidence_scheduler

    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(registry, "list_tenants", list)
    touched: list[str] = []
    runtime = AIGovernanceLoopScheduler(
        worker_factory=lambda *_args: touched.append("worker"),
        tenant_context=lambda _tenant: null_context(),
        config_loader=config,
        tenant_config_loader=config,
        worker_id="scheduler-test",
    )
    cycle = runtime.run_once()
    assert cycle is not None
    assert (cycle.tenants_considered, cycle.tenants_failed) == (0, 0)
    assert touched == []
    assert runtime.status()["last_error_code"] is None
    assert evidence_scheduler._default_tenant_supplier() == ()


def test_disabled_scheduler_does_not_touch_tenants_or_workers() -> None:
    touched: list[str] = []
    runtime = AIGovernanceLoopScheduler(
        worker_factory=lambda *_args: touched.append("worker"),
        tenant_supplier=lambda: touched.append("tenants") or (),
        config_loader=lambda: config(enabled=False),
        tenant_config_loader=lambda: config(enabled=False),
        worker_id="scheduler-test",
    )
    assert runtime.run_once() is None
    assert runtime.start() is False
    assert touched == []


def test_overlap_invalid_supplier_and_invalid_worker_result_fail_closed() -> None:
    runtime = AIGovernanceLoopScheduler(
        worker_factory=lambda tenant, principal: Worker(tenant, principal),
        tenant_supplier=lambda: ("tenant-a",),
        tenant_context=lambda _tenant: null_context(),
        config_loader=config,
        tenant_config_loader=config,
        worker_id="scheduler-test",
    )
    assert runtime._cycle_lock.acquire(blocking=False)
    try:
        with pytest.raises(AIGovernanceLoopSchedulerError, match="already_running"):
            runtime.run_once()
    finally:
        runtime._cycle_lock.release()

    invalid_tenant = AIGovernanceLoopScheduler(
        worker_factory=lambda tenant, principal: Worker(tenant, principal),
        tenant_supplier=lambda: ("tenant-with-space ",),
        tenant_context=lambda _tenant: null_context(),
        config_loader=config,
        tenant_config_loader=config,
        worker_id="scheduler-test",
    )
    with pytest.raises(AIGovernanceLoopSchedulerError, match="tenant_supplier_invalid"):
        invalid_tenant.run_once()

    class InvalidWorker(Worker):
        def run_batch(self, **_kwargs):
            return {"processed": "unbounded"}

    invalid_result = AIGovernanceLoopScheduler(
        worker_factory=lambda tenant, principal: InvalidWorker(tenant, principal),
        tenant_supplier=lambda: ("tenant-a",),
        tenant_context=lambda _tenant: null_context(),
        config_loader=config,
        tenant_config_loader=config,
        worker_id="scheduler-test",
    )
    cycle = invalid_result.run_once()
    assert cycle is not None
    assert cycle.tenants_failed == 1
    assert cycle.processed == 0
    assert invalid_result.status()["last_error_code"] == "tenant_cycle_failed"
    with pytest.raises(ValueError, match="timeout"):
        runtime.stop(timeout=31)


def test_start_stop_are_bounded_and_nonduplicating() -> None:
    ran = threading.Event()
    workers: list[Worker] = []

    def factory(tenant_id: str, principal_ref: str):
        worker = Worker(tenant_id, principal_ref, event=ran)
        workers.append(worker)
        return worker

    runtime = AIGovernanceLoopScheduler(
        worker_factory=factory,
        tenant_supplier=lambda: ("tenant-a",),
        tenant_context=lambda _tenant: null_context(),
        config_loader=config,
        tenant_config_loader=config,
        worker_id="scheduler-test",
    )
    assert runtime.start() is True
    assert runtime.start() is True
    assert ran.wait(2.0)
    assert runtime.stop(timeout=2.0) is True
    assert runtime.status()["running"] is False
    assert workers


def test_lifespan_attachment_starts_and_stops_exactly_once() -> None:
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
    selected = attach_ai_governance_loop_scheduler(app, runtime=runtime)  # type: ignore[arg-type]
    assert selected is runtime
    assert app.state.ai_governance_loop_scheduler is runtime
    assert (
        attach_ai_governance_loop_scheduler(app, runtime=runtime)  # type: ignore[arg-type]
        is runtime
    )
    with pytest.raises(RuntimeError, match="already attached"):
        attach_ai_governance_loop_scheduler(
            app,
            runtime=LifecycleRuntime(),  # type: ignore[arg-type]
        )
    with TestClient(app, base_url="http://127.0.0.1"):
        assert runtime.starts == 1
        assert runtime.stops == 0
    assert runtime.stops == 1
