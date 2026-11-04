from __future__ import annotations

import json
import threading
import time
from collections.abc import Mapping
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick_dashboard.consent_scan_scheduler import (
    ConsentScanScheduler,
    ConsentScanSchedulerConfigurationError,
    attach_consent_scan_scheduler,
    scheduler_settings,
)


def _config(**scheduler_overrides: Any) -> dict[str, Any]:
    scheduler = {
        "enable": True,
        "poll_seconds": 5,
        "enqueue_limit": 3,
        "claim_limit": 2,
        "tenant_limit": 10,
        **scheduler_overrides,
    }
    return {
        "consent_preferences": {
            "enable": True,
            "scanner": {"enable": True, "scheduler": scheduler},
        }
    }


class _Inventory:
    def __init__(
        self,
        *,
        claims: list[dict[str, Any]] | None = None,
        outcome: Mapping[str, Any] | None = None,
        recovered: int = 0,
        recovery_truncated: bool = False,
        enqueue_truncated: bool = False,
        claim_truncated: bool = False,
        run_started: threading.Event | None = None,
        run_release: threading.Event | None = None,
        fail_enqueue: bool = False,
    ) -> None:
        self.claims = list(claims or [])
        self.outcome = dict(outcome or {"succeeded": True, "job": {}})
        self.recovered = recovered
        self.recovery_truncated = recovery_truncated
        self.enqueue_truncated = enqueue_truncated
        self.claim_truncated = claim_truncated
        self.run_started = run_started
        self.run_release = run_release
        self.fail_enqueue = fail_enqueue
        self.enqueues: list[tuple[str, int]] = []
        self.claim_calls: list[tuple[str, str, int]] = []
        self.run_calls: list[tuple[str, str, str, str]] = []
        self.renew_calls: list[tuple[str, str, str, str, int]] = []
        self._revision = int(self.claims[0]["revision"]) if self.claims else 1
        self._lock = threading.Lock()

    def enqueue_due(self, tenant_id: str, *, limit: int) -> Mapping[str, Any]:
        if self.fail_enqueue:
            raise RuntimeError("raw-secret-must-not-be-logged")
        self.enqueues.append((tenant_id, limit))
        return {"items": [{"job_id": "CSI-JOB-enqueued"}], "truncated": self.enqueue_truncated}

    def claim_due(
        self,
        tenant_id: str,
        worker_id: str,
        *,
        limit: int,
    ) -> Mapping[str, Any]:
        self.claim_calls.append((tenant_id, worker_id, limit))
        return {
            "items": list(self.claims),
            "truncated": self.claim_truncated,
            "recovered_leases": self.recovered,
            "recovery_truncated": self.recovery_truncated,
        }

    def renew_lease(
        self,
        tenant_id: str,
        job_id: str,
        worker_id: str,
        lease_token: str,
        *,
        expected_revision: int,
    ) -> Mapping[str, Any]:
        with self._lock:
            assert expected_revision == self._revision
            self.renew_calls.append(
                (tenant_id, job_id, worker_id, lease_token, expected_revision)
            )
            self._revision += 1
            return {"revision": self._revision}

    def run_claim(
        self,
        tenant_id: str,
        job_id: str,
        worker_id: str,
        lease_token: str,
    ) -> Mapping[str, Any]:
        self.run_calls.append((tenant_id, job_id, worker_id, lease_token))
        if self.run_started is not None:
            self.run_started.set()
        if self.run_release is not None:
            assert self.run_release.wait(2.0)
        return self.outcome


def _claim(*, lease_seconds: float = 30.0) -> dict[str, Any]:
    return {
        "job_id": "CSI-JOB-one",
        "lease_token": "lease-token-secret-value-1234567890",
        "lease_seconds": lease_seconds,
        "revision": 2,
    }


def _runtime(
    inventory: _Inventory,
    *,
    tenants: tuple[str, ...] = ("tenant-secret-one",),
    config: Mapping[str, Any] | None = None,
) -> ConsentScanScheduler:
    selected = dict(_config() if config is None else config)
    return ConsentScanScheduler(
        inventory_factory=lambda _tenant: inventory,
        tenant_supplier=lambda: tenants,
        config_loader=lambda: selected,
        worker_id="consent-scan-test-worker",
    )


def test_scheduler_config_is_default_off_and_requires_all_exact_gates() -> None:
    assert scheduler_settings({}) is None
    assert scheduler_settings({"consent_preferences": {"enable": True}}) is None
    assert (
        scheduler_settings(
            {
                "consent_preferences": {
                    "enable": True,
                    "scanner": {"enable": True},
                }
            }
        )
        is None
    )
    for path in ("consent", "scanner", "scheduler"):
        config = _config()
        if path == "consent":
            config["consent_preferences"]["enable"] = False
        elif path == "scanner":
            config["consent_preferences"]["scanner"]["enable"] = False
        else:
            config["consent_preferences"]["scanner"]["scheduler"]["enable"] = False
        assert scheduler_settings(config) is None


def test_scheduler_config_is_closed_and_finitely_bounded() -> None:
    settings = scheduler_settings(_config())
    assert settings is not None
    assert settings.poll_seconds == 5.0
    assert settings.enqueue_limit == 3
    assert settings.claim_limit == 2
    assert settings.tenant_limit == 10

    for overrides in (
        {"unexpected": True},
        {"poll_seconds": float("nan")},
        {"poll_seconds": 4},
        {"enqueue_limit": 501},
        {"claim_limit": 0},
        {"tenant_limit": 10_001},
    ):
        with pytest.raises(ConsentScanSchedulerConfigurationError):
            scheduler_settings(_config(**overrides))


def test_cycle_drives_core_queue_and_exposes_only_digest_identifiers() -> None:
    inventory = _Inventory(
        claims=[_claim()],
        recovered=2,
        recovery_truncated=True,
        enqueue_truncated=True,
        claim_truncated=True,
    )
    runtime = _runtime(inventory)

    cycle = runtime.run_cycle(config=_config())
    status = runtime.status()

    assert cycle == {
        "schema": "lightwork.consent-scan-scheduler-cycle.v1",
        "enabled": True,
        "completed": True,
        "tenants_processed": 1,
        "tenant_truncated": False,
        "jobs_enqueued": 1,
        "jobs_claimed": 1,
        "jobs_succeeded": 1,
        "jobs_failed": 0,
        "leases_recovered": 2,
        "last_error_code": None,
    }
    assert inventory.enqueues == [("tenant-secret-one", 3)]
    assert inventory.claim_calls[0][0] == "tenant-secret-one"
    assert inventory.claim_calls[0][2] == 2
    assert inventory.run_calls[0][0:2] == ("tenant-secret-one", "CSI-JOB-one")
    rendered = json.dumps(status, sort_keys=True)
    assert "tenant-secret-one" not in rendered
    assert "lease-token-secret" not in rendered
    assert "CSI-JOB-one" not in rendered
    assert status["leases_recovered"] == 2
    assert status["queue_truncations"] == 2
    assert status["recovery_truncations"] == 1
    assert len(status["last_tenant_sha256"]) == 64
    assert len(status["last_job_sha256"]) == 64


def test_failure_and_retry_policy_remain_delegated_to_inventory() -> None:
    inventory = _Inventory(
        claims=[_claim()],
        outcome={
            "succeeded": False,
            "job": {"status": "queued", "last_error_code": "ScannerUnavailable"},
        },
    )
    runtime = _runtime(inventory)

    cycle = runtime.run_cycle(config=_config())

    assert cycle["jobs_failed"] == 1
    assert cycle["jobs_succeeded"] == 0
    assert runtime.status()["last_error_code"] == "ScannerUnavailable"
    assert len(inventory.run_calls) == 1


def test_one_claim_crash_leaves_recovery_to_core_and_runs_leased_sibling() -> None:
    class FirstClaimCrashes(_Inventory):
        def run_claim(
            self,
            tenant_id: str,
            job_id: str,
            worker_id: str,
            lease_token: str,
        ) -> Mapping[str, Any]:
            self.run_calls.append((tenant_id, job_id, worker_id, lease_token))
            if len(self.run_calls) == 1:
                raise RuntimeError("secret-error-detail")
            return {"succeeded": True, "job": {}}

    second = {**_claim(), "job_id": "CSI-JOB-two"}
    inventory = FirstClaimCrashes(claims=[_claim(), second])
    runtime = _runtime(inventory)

    cycle = runtime.run_cycle(config=_config())

    assert len(inventory.run_calls) == 2
    assert cycle["jobs_failed"] == 1
    assert cycle["jobs_succeeded"] == 1
    assert runtime.status()["last_error_code"] == "RuntimeError"


def test_heartbeat_renews_a_lease_while_the_injected_scan_is_running() -> None:
    started = threading.Event()
    release = threading.Event()
    inventory = _Inventory(
        claims=[_claim(lease_seconds=0.15)],
        run_started=started,
        run_release=release,
    )
    runtime = _runtime(inventory)
    completed = threading.Event()

    def run() -> None:
        runtime.run_cycle(config=_config())
        completed.set()

    worker = threading.Thread(target=run)
    worker.start()
    assert started.wait(1.0)
    deadline = time.monotonic() + 1.0
    while not inventory.renew_calls and time.monotonic() < deadline:
        time.sleep(0.01)
    release.set()
    worker.join(1.0)

    assert completed.is_set()
    assert inventory.renew_calls
    assert runtime.status()["lease_renewals"] >= 1
    assert runtime.status()["lease_renewal_failures"] == 0


def test_tenant_failure_is_sanitized_and_does_not_starve_next_tenant(caplog) -> None:
    broken = _Inventory(fail_enqueue=True)
    healthy = _Inventory()
    inventories = {
        "tenant-secret-broken": broken,
        "tenant-secret-healthy": healthy,
    }
    runtime = ConsentScanScheduler(
        inventory_factory=lambda tenant: inventories[tenant],
        tenant_supplier=lambda: tuple(inventories),
        config_loader=_config,
        worker_id="consent-scan-test-worker",
    )

    cycle = runtime.run_cycle(config=_config())

    assert cycle["completed"] is False
    assert cycle["tenants_processed"] == 2
    assert healthy.enqueues
    assert cycle["last_error_code"] == "RuntimeError"
    assert "raw-secret-must-not-be-logged" not in caplog.text
    assert "tenant-secret-broken" not in caplog.text


def test_tenant_scheduler_opt_out_prevents_automatic_inventory_work() -> None:
    inventory = _Inventory(claims=[_claim()])
    tenant_config = _config()
    tenant_config["consent_preferences"]["scanner"]["scheduler"]["enable"] = False
    runtime = ConsentScanScheduler(
        inventory_factory=lambda _tenant: inventory,
        tenant_supplier=lambda: ("tenant-secret-one",),
        config_loader=_config,
        tenant_config_loader=lambda: tenant_config,
        worker_id="consent-scan-test-worker",
    )

    cycle = runtime.run_cycle(config=_config())

    assert cycle["enabled"] is True
    assert cycle["tenants_processed"] == 1
    assert cycle["jobs_enqueued"] == 0
    assert cycle["jobs_claimed"] == 0
    assert not inventory.enqueues
    assert not inventory.claim_calls


def test_tenant_scheduler_cannot_expand_global_work_bounds() -> None:
    inventory = _Inventory(claims=[_claim()])
    runtime = ConsentScanScheduler(
        inventory_factory=lambda _tenant: inventory,
        tenant_supplier=lambda: ("tenant-secret-one",),
        config_loader=lambda: _config(enqueue_limit=2, claim_limit=1),
        tenant_config_loader=lambda: _config(enqueue_limit=500, claim_limit=100),
        worker_id="consent-scan-test-worker",
    )

    runtime.run_cycle(config=_config(enqueue_limit=2, claim_limit=1))

    assert inventory.enqueues == [("tenant-secret-one", 2)]
    assert inventory.claim_calls[0][2] == 1


def test_tenant_work_is_bounded_and_reports_truncation() -> None:
    inventories: list[_Inventory] = []

    def factory(_tenant: str) -> _Inventory:
        inventory = _Inventory()
        inventories.append(inventory)
        return inventory

    runtime = ConsentScanScheduler(
        inventory_factory=factory,
        tenant_supplier=lambda: ("tenant-one", "tenant-two", "tenant-three"),
        config_loader=lambda: _config(tenant_limit=2),
        worker_id="consent-scan-test-worker",
    )

    cycle = runtime.run_cycle(config=_config(tenant_limit=2))

    assert cycle["tenants_processed"] == 2
    assert cycle["tenant_truncated"] is True
    assert len(inventories) == 2
    assert runtime.status()["tenant_truncations"] == 1


def test_shutdown_after_enqueue_does_not_acquire_fresh_leases() -> None:
    stop = threading.Event()

    class StopAfterEnqueue(_Inventory):
        def enqueue_due(self, tenant_id: str, *, limit: int) -> Mapping[str, Any]:
            result = super().enqueue_due(tenant_id, limit=limit)
            stop.set()
            return result

    inventory = StopAfterEnqueue(claims=[_claim()])
    runtime = _runtime(inventory)

    cycle = runtime.run_cycle(config=_config(), stop=stop)

    assert cycle["jobs_enqueued"] == 1
    assert cycle["jobs_claimed"] == 0
    assert not inventory.claim_calls


def test_start_is_singleton_per_instance_and_stop_is_graceful() -> None:
    started = threading.Event()
    release = threading.Event()
    inventory = _Inventory(
        claims=[_claim()],
        run_started=started,
        run_release=release,
    )
    runtime = _runtime(inventory)

    assert runtime.start() is True
    assert started.wait(1.0)
    assert runtime.start() is False
    assert runtime.stop(timeout=0.01) is False
    assert runtime.status()["running"] is True
    assert runtime.status()["stop_requested"] is True

    release.set()
    assert runtime.stop(timeout=1.0) is True
    assert runtime.status()["running"] is False
    assert len(inventory.run_calls) == 1


def test_disabled_runtime_does_not_start() -> None:
    inventory = _Inventory()
    runtime = _runtime(inventory, config={})

    assert runtime.start() is False
    assert runtime.status()["configured_enabled"] is False
    assert not inventory.enqueues


def test_lifespan_attachment_starts_and_stops_the_runtime() -> None:
    entered = threading.Event()

    class EmptyInventory(_Inventory):
        def enqueue_due(self, tenant_id: str, *, limit: int) -> Mapping[str, Any]:
            entered.set()
            return {"items": [], "truncated": False}

    runtime = _runtime(EmptyInventory())
    app = FastAPI()
    attach_consent_scan_scheduler(app, runtime=runtime)
    assert attach_consent_scan_scheduler(app, runtime=runtime) is runtime

    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/openapi.json").status_code == 200
        assert entered.wait(1.0)
        assert runtime.status()["running"] is True

    assert runtime.status()["running"] is False
