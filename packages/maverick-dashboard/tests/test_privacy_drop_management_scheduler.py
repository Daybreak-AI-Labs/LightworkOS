from __future__ import annotations

import threading
from pathlib import Path

from maverick_dashboard.privacy_drop_management_scheduler import (
    DROPManagedMaintenanceScheduler,
    DROPManagementMaintenanceCycle,
    cycle_payload,
    run_drop_maintenance_cycle,
)


def test_cycle_is_bounded_tenant_safe_and_contains_no_private_errors() -> None:
    times = iter((100.0, 101.0))
    calls: list[str] = []

    def reconcile(tenant_id: str):
        if tenant_id == "tenant-bad":
            raise RuntimeError("private registry failure")
        return {"registry_integrity_valid": tenant_id != "tenant-corrupt"}

    def maintain(tenant_id: str, **_kwargs):
        calls.append(tenant_id)
        return {"requests_purged": 2, "registry_objects_purged": 3}

    cycle = run_drop_maintenance_cycle(
        tenant_supplier=lambda: (
            "tenant-good",
            "tenant-good",
            "tenant-corrupt",
            "tenant-bad",
            "",
            "tenant-disabled",
        ),
        readiness_probe=lambda tenant: tenant != "tenant-disabled",
        reconciliation_runner=reconcile,
        maintenance_runner=maintain,
        clock=lambda: next(times),
    )
    payload = cycle_payload(cycle)

    assert cycle.tenants_considered == 4
    assert cycle.tenants_ready == 3
    assert cycle.tenants_failed == 2
    assert cycle.reconciliations_valid == 1
    assert cycle.requests_purged == 2
    assert cycle.registry_objects_purged == 3
    assert calls == ["tenant-good"]
    assert payload["network_io"] is False
    assert payload["external_records_imported"] == 0
    assert payload["terminal_outcomes_inferred"] == 0
    assert payload["live_interoperability_verified"] is False
    assert payload["legal_acceptance_verified"] is False
    serialized = str(payload)
    assert "tenant-good" not in serialized
    assert "private registry failure" not in serialized


def test_cycle_enforces_tenant_and_purge_limits() -> None:
    times = iter((100.0, 101.0))
    seen: list[tuple[str, int]] = []

    def maintain(tenant_id: str, *, before, limit: int):
        assert before == 99.0
        seen.append((tenant_id, limit))
        return {"requests_purged": 0, "registry_objects_purged": 0}

    cycle = run_drop_maintenance_cycle(
        tenant_supplier=lambda: ("tenant-one", "tenant-two", "tenant-three"),
        readiness_probe=lambda _tenant: True,
        reconciliation_runner=lambda _tenant: {"registry_integrity_valid": True},
        maintenance_runner=maintain,
        tenant_limit=2,
        purge_limit=7,
        before=99.0,
        clock=lambda: next(times),
    )

    assert cycle.tenants_considered == 2
    assert seen == [("tenant-one", 7), ("tenant-two", 7)]


def _cycle(now: float) -> DROPManagementMaintenanceCycle:
    return DROPManagementMaintenanceCycle(
        started_at=now,
        completed_at=now + 1,
        tenants_considered=1,
        tenants_ready=1,
        tenants_failed=0,
        reconciliations_valid=1,
        requests_purged=0,
        registry_objects_purged=0,
        cycle_sha256="0" * 64,
    )


def test_managed_scheduler_has_one_cross_process_lease(tmp_path: Path) -> None:
    started = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def run():
        calls.append("run")
        started.set()
        release.wait(5)
        return _cycle(100.0)

    path = tmp_path / "scheduler.sqlite3"
    first = DROPManagedMaintenanceScheduler(
        path,
        cycle_runner=run,
        clock=lambda: 100.0,
        jitter_source=lambda _maximum: 0,
        worker_id="worker-one",
    )
    second = DROPManagedMaintenanceScheduler(
        path,
        cycle_runner=run,
        clock=lambda: 100.0,
        jitter_source=lambda _maximum: 0,
        worker_id="worker-two",
    )
    thread = threading.Thread(target=lambda: first.run_once(force=True))
    thread.start()
    assert started.wait(5)
    assert second.run_once(force=True) is None
    release.set()
    thread.join(5)
    assert calls == ["run"]
    assert first.health()["lease_active"] is False


def test_managed_scheduler_restart_disabled_and_failure_recovery(tmp_path: Path) -> None:
    now = [100.0]
    attempts = [0]

    def flaky():
        attempts[0] += 1
        if attempts[0] == 1:
            raise RuntimeError("private failure detail")
        return _cycle(now[0])

    path = tmp_path / "scheduler.sqlite3"
    first = DROPManagedMaintenanceScheduler(
        path,
        cycle_runner=flaky,
        clock=lambda: now[0],
        jitter_source=lambda _maximum: 0,
        worker_id="worker-one",
    )
    assert first.run_once(force=True) is None
    failed = first.health()
    assert failed["consecutive_failures"] == 1
    assert "private failure detail" not in str(failed)
    now[0] = 200.0
    restarted = DROPManagedMaintenanceScheduler(
        path,
        cycle_runner=flaky,
        clock=lambda: now[0],
        jitter_source=lambda _maximum: 0,
        worker_id="worker-two",
    )
    assert restarted.run_once(force=True) is not None
    assert restarted.health()["consecutive_failures"] == 0
    disabled_calls: list[bool] = []
    disabled = DROPManagedMaintenanceScheduler(
        tmp_path / "disabled.sqlite3",
        cycle_runner=lambda: disabled_calls.append(True),
        enabled=False,
        clock=lambda: now[0],
    )
    assert disabled.start() is False
    assert disabled.run_once(force=True) is None
    assert disabled_calls == []


def test_managed_scheduler_shutdown_clears_owned_lease(tmp_path: Path) -> None:
    scheduler = DROPManagedMaintenanceScheduler(
        tmp_path / "scheduler.sqlite3",
        cycle_runner=lambda: _cycle(100.0),
        interval_seconds=30,
        jitter_seconds=0,
        clock=lambda: 100.0,
        jitter_source=lambda _maximum: 0,
    )
    assert scheduler.start() is True
    scheduler.stop(timeout=5)
    health = scheduler.health()
    assert health["running"] is False
    assert health["lease_owned_by_this_process"] is False
