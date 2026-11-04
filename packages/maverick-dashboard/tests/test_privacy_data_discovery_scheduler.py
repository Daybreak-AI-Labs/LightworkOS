from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from maverick.file_lock import cross_process_lock
from maverick.privacy_data_discovery_remediation import RemediationWorkerResult
from maverick_dashboard import privacy_data_discovery_scheduler as scheduler_module
from maverick_dashboard.privacy_data_discovery_adapters_composition import (
    PrivacyDiscoveryAdapterCompositionError,
    PrivacyDiscoveryRemediationRuntime,
    remediation_scheduler_settings,
)
from maverick_dashboard.privacy_data_discovery_scheduler import (
    PrivacyDiscoveryRemediationScheduler,
    install_privacy_data_discovery_scheduler,
    privacy_data_discovery_scheduler_status,
)


def _config(*, enable: bool = True, tenant_limit: int = 2) -> dict[str, object]:
    return {
        "privacy_automation": {
            "enable": True,
            "data_discovery": {
                "enable": True,
                "remediation": {
                    "enable": True,
                    "data_map": {"enable": True},
                    "scheduler": {
                        "enable": enable,
                        "interval_seconds": 60,
                        "jitter_seconds": 0,
                        "retry_max_seconds": 300,
                        "tenant_limit": tenant_limit,
                        "worker_limit": 3,
                        "reconcile_limit": 2,
                        "lease_seconds": 30,
                    },
                },
            },
        }
    }


class _Outbox:
    def __init__(self, states: tuple[str, ...] = ()) -> None:
        self._states = states
        self.reconciled: list[tuple[str, int, str]] = []

    def list_work(self, *, state: str, limit: int):
        assert state == "ambiguous"
        return tuple(
            SimpleNamespace(work_id=f"work-{index}", revision=index + 1)
            for index, _state in enumerate(self._states[:limit])
        )

    def reconcile_ambiguous(
        self,
        work_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
        reconciler,
        absent_backoff_seconds: int,
    ):
        assert callable(reconciler)
        assert absent_backoff_seconds == 0
        self.reconciled.append((work_id, expected_revision, idempotency_key))
        index = int(work_id.rsplit("-", 1)[1])
        return SimpleNamespace(state=self._states[index])


class _Worker:
    def __init__(
        self,
        result: RemediationWorkerResult | None = None,
        *,
        started: threading.Event | None = None,
        release: threading.Event | None = None,
    ) -> None:
        self.result = result or RemediationWorkerResult(2, 1, 0, 1, 0, 0, 0)
        self.started = started
        self.release = release
        self.calls: list[tuple[str, int, int]] = []

    def run_once(self, *, worker_id: str, limit: int, lease_seconds: int):
        self.calls.append((worker_id, limit, lease_seconds))
        if self.started is not None:
            self.started.set()
        if self.release is not None:
            assert self.release.wait(5)
        return self.result


def _runtime(tenant: str, outbox: _Outbox, worker: _Worker):
    return PrivacyDiscoveryRemediationRuntime(
        tenant_id=tenant,
        config_sha256="0" * 64,
        outbox=outbox,  # type: ignore[arg-type]
        target=SimpleNamespace(),  # type: ignore[arg-type]
        worker=worker,  # type: ignore[arg-type]
        review_callback=lambda _update: None,
        reconciler=lambda _probe: None,  # type: ignore[arg-type]
    )


def test_scheduler_settings_are_exact_opt_in() -> None:
    assert remediation_scheduler_settings(_config()) is not None
    assert remediation_scheduler_settings(_config(enable=False)) is None
    disabled_parent = _config()
    disabled_parent["privacy_automation"]["data_discovery"]["remediation"][  # type: ignore[index]
        "enable"
    ] = False
    with pytest.raises(
        PrivacyDiscoveryAdapterCompositionError,
        match="requires remediation.enable",
    ):
        remediation_scheduler_settings(disabled_parent)


def test_cycle_is_tenant_bounded_reconciles_then_runs_worker(tmp_path) -> None:
    outboxes: dict[str, _Outbox] = {}
    workers: dict[str, _Worker] = {}
    principals: list[tuple[str, str]] = []

    def factory(tenant: str, principal: str):
        principals.append((tenant, principal))
        outbox = outboxes.setdefault(tenant, _Outbox(("applied", "queued")))
        worker = workers.setdefault(tenant, _Worker())
        return _runtime(tenant, outbox, worker)

    scheduler = PrivacyDiscoveryRemediationScheduler(
        tmp_path / "scheduler.json",
        runtime_factory=factory,
        tenant_supplier=lambda: ("tenant-a", "tenant-b", "tenant-c"),
        config_loader=_config,
        tenant_config_loader=_config,
        clock=lambda: 100.0,
        jitter_source=lambda _maximum: 0,
    )
    cycle = scheduler.run_once(force=True)

    assert cycle is not None
    assert cycle.tenants_considered == 2
    assert cycle.tenants_enabled == 2
    assert cycle.tenant_limit_reached is True
    assert cycle.ambiguous_considered == 4
    assert cycle.ambiguous_applied == 2
    assert cycle.ambiguous_requeued == 2
    assert cycle.claimed == 4
    assert cycle.applied == 2
    assert cycle.retried == 2
    assert all(item[1].startswith("pdd-scheduler-principal-") for item in principals)
    assert workers["tenant-a"].calls[0][1:] == (3, 30)
    status = scheduler.status()
    assert status["cross_process_concurrency_excluded"] is True
    assert status["process_concurrency_excluded"] is True
    assert status["provider_network_io"] is False
    assert status["provider_writes"] is False
    assert status["estate_completeness_claimed"] is False
    assert "tenant-a" not in str(status)
    assert "work-0" not in str(status)


def test_process_cycle_exclusion_is_nonblocking(tmp_path) -> None:
    started = threading.Event()
    release = threading.Event()
    worker = _Worker(started=started, release=release)
    scheduler = PrivacyDiscoveryRemediationScheduler(
        tmp_path / "scheduler.json",
        runtime_factory=lambda tenant, _principal: _runtime(
            tenant,
            _Outbox(),
            worker,
        ),
        tenant_supplier=lambda: ("tenant-a",),
        config_loader=_config,
        tenant_config_loader=_config,
        clock=lambda: 100.0,
        jitter_source=lambda _maximum: 0,
    )
    thread = threading.Thread(target=lambda: scheduler.run_once(force=True))
    thread.start()
    assert started.wait(5)
    assert scheduler.run_once(force=True) is None
    release.set()
    thread.join(5)
    assert len(worker.calls) == 1


def test_cross_process_state_excludes_duplicate_due_cycle(tmp_path) -> None:
    started = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def factory(tenant: str, _principal: str):
        calls.append(tenant)
        return _runtime(
            tenant,
            _Outbox(),
            _Worker(started=started, release=release),
        )

    path = tmp_path / "scheduler.json"
    first = PrivacyDiscoveryRemediationScheduler(
        path,
        runtime_factory=factory,
        tenant_supplier=lambda: ("tenant-a",),
        config_loader=_config,
        tenant_config_loader=_config,
        clock=lambda: 100.0,
        jitter_source=lambda _maximum: 0,
    )
    second = PrivacyDiscoveryRemediationScheduler(
        path,
        runtime_factory=factory,
        tenant_supplier=lambda: ("tenant-a",),
        config_loader=_config,
        tenant_config_loader=_config,
        clock=lambda: 100.0,
        jitter_source=lambda _maximum: 0,
    )
    first_thread = threading.Thread(target=first.run_once)
    second_result: list[object] = []
    first_thread.start()
    assert started.wait(5)
    second_thread = threading.Thread(
        target=lambda: second_result.append(second.run_once())
    )
    second_thread.start()
    release.set()
    first_thread.join(5)
    second_thread.join(5)

    assert calls == ["tenant-a"]
    assert second_result == [None]


def test_restart_recovers_interrupted_control_cycle_without_raw_error(tmp_path) -> None:
    now = [100.0]
    path = tmp_path / "scheduler.json"
    first = PrivacyDiscoveryRemediationScheduler(
        path,
        runtime_factory=lambda tenant, _principal: _runtime(
            tenant,
            _Outbox(),
            _Worker(),
        ),
        tenant_supplier=lambda: ("tenant-a",),
        config_loader=_config,
        tenant_config_loader=_config,
        clock=lambda: now[0],
        jitter_source=lambda _maximum: 0,
    )
    with cross_process_lock(path, strict=True):
        state = first._read_state()
        state["last_started_at"] = 100.0
        state["last_completed_at"] = 99.0
        first._write_state(state)
    now[0] = 200.0
    restarted = PrivacyDiscoveryRemediationScheduler(
        path,
        runtime_factory=lambda tenant, _principal: _runtime(
            tenant,
            _Outbox(),
            _Worker(),
        ),
        tenant_supplier=lambda: ("tenant-a",),
        config_loader=_config,
        tenant_config_loader=_config,
        clock=lambda: now[0],
        jitter_source=lambda _maximum: 0,
    )
    assert restarted.run_once(force=True) is not None
    status = restarted.status()
    assert status["interrupted_cycles_recovered"] == 1
    assert status["consecutive_failures"] == 0
    assert "tenant-a" not in str(status)


def test_app_state_install_is_lazy_and_disabled_status_opens_no_store(tmp_path) -> None:
    del tmp_path
    app = SimpleNamespace(state=SimpleNamespace())
    install_privacy_data_discovery_scheduler(app)

    status = privacy_data_discovery_scheduler_status(app)
    assert app.state.privacy_data_discovery_worker_scheduler_operational is False
    assert status["running"] is False
    assert status["status_opened_tenant_store"] is False
    assert status["status_invoked_provider"] is False
    assert status["live_provider_acceptance_verified"] is False


def test_app_owned_start_and_stop_update_truthful_operational_state(
    tmp_path,
    monkeypatch,
) -> None:
    runtime = PrivacyDiscoveryRemediationScheduler(
        tmp_path / "scheduler.json",
        runtime_factory=lambda tenant, _principal: _runtime(
            tenant,
            _Outbox(),
            _Worker(),
        ),
        tenant_supplier=lambda: (),
        config_loader=_config,
        tenant_config_loader=_config,
        clock=lambda: 100.0,
        jitter_source=lambda _maximum: 0,
    )
    app = SimpleNamespace(
        state=SimpleNamespace(
            privacy_data_discovery_worker_scheduler_runtime=runtime,
        )
    )
    monkeypatch.setattr(
        scheduler_module,
        "_default_global_config_loader",
        _config,
    )

    assert scheduler_module.start_privacy_data_discovery_scheduler(app) is True
    assert app.state.privacy_data_discovery_worker_scheduler_operational is True
    assert scheduler_module.privacy_data_discovery_scheduler_status(app)[
        "running"
    ] is True
    assert scheduler_module.stop_privacy_data_discovery_scheduler(app) is True
    assert app.state.privacy_data_discovery_worker_scheduler_operational is False
