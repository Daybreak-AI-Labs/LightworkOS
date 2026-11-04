"""Atomic per-tenant daily-budget allocation and raw tenant identity."""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick.quotas import UsageLedger, record_usage
from maverick.tenant import registry


def _provision_capped_tenant(monkeypatch, tenant_id: str = "acme") -> None:
    monkeypatch.setenv("MAVERICK_TENANT", tenant_id)
    registry.create_tenant(tenant_id, plan="free")
    registry.set_quota(tenant_id, 10.0)


def test_punctuation_tenant_uses_raw_registry_id_and_releases_hold(
    monkeypatch,
) -> None:
    tenant_id = "channel:user"
    _provision_capped_tenant(monkeypatch, tenant_id)

    reservation_id = 'explicit-legacy-fixture'
    assert registry.reserve_tenant_budget(tenant_id, 6.0, 3600, reservation_id) == 6.0
    assert registry.tenant_remaining_today(tenant_id) == pytest.approx(4.0)
    reservation_path = registry._reservations_path(tenant_id)
    assert "channel%3Auser" in reservation_path.parts
    assert all("%253A" not in part for part in reservation_path.parts)

    record_usage(
        "user:local",
        1.0,
        reservation_id=reservation_id,
    )

    assert registry.tenant_remaining_today(tenant_id) == pytest.approx(9.0)
    assert registry._load_reservations(tenant_id) == {}


def test_simultaneous_legacy_reservations_cannot_overgrant(monkeypatch) -> None:
    _provision_capped_tenant(monkeypatch)
    workers = 12
    start = threading.Barrier(workers)

    def allocate(index) -> float:
        start.wait(timeout=10)
        return registry.reserve_tenant_budget('acme', 6.0, 3600, f'legacy-{index}')

    with ThreadPoolExecutor(max_workers=workers) as pool:
        grants = list(pool.map(allocate, range(workers)))

    assert sum(grants) <= 10.0 + 1e-9
    assert sorted(grant for grant in grants if grant > 0) == [4.0, 6.0]


def test_cap_change_cannot_publish_between_cap_read_and_reservation(
    monkeypatch,
) -> None:
    """A control-plane cap write is serialized with admission publication."""
    _provision_capped_tenant(monkeypatch)
    cap_read = threading.Event()
    resume_allocator = threading.Event()
    mutation_attempted = threading.Event()
    mutation_published = threading.Event()
    allocator_calls = 0
    grants: list[float | None] = []
    errors: list[BaseException] = []
    real_daily_cap = registry._tenant_daily_cap

    def paused_daily_cap(tenant_id: str) -> float:
        nonlocal allocator_calls
        value = real_daily_cap(tenant_id)
        if threading.current_thread().name == "budget-allocator":
            allocator_calls += 1
            if allocator_calls == 2:
                # This is the authoritative cap read inside the transaction.
                cap_read.set()
                if not resume_allocator.wait(timeout=10):
                    raise TimeoutError("allocator test hook timed out")
        return value

    monkeypatch.setattr(registry, "_tenant_daily_cap", paused_daily_cap)

    def allocate() -> None:
        try:
            grants.append(
                registry.reserve_tenant_budget(
                    "acme", 6.0, 3600.0, "cap-race-reservation",
                )
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    allocator = threading.Thread(target=allocate, name="budget-allocator")
    allocator.start()
    assert cap_read.wait(timeout=10)
    # The allocator must retain the roster lock from its authoritative cap read
    # until after it publishes the reservation. The former split-lock code
    # fails this assertion deterministically.
    assert registry._REGISTRY_LOCK.locked()

    real_mutate = registry._mutate_billing

    def marked_mutate(*args, **kwargs):
        mutation_attempted.set()
        result = real_mutate(*args, **kwargs)
        mutation_published.set()
        return result

    monkeypatch.setattr(registry, "_mutate_billing", marked_mutate)

    def lower_cap() -> None:
        try:
            registry.set_quota("acme", 4.0)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    setter = threading.Thread(target=lower_cap, name="quota-setter")
    setter.start()
    try:
        assert mutation_attempted.wait(timeout=10)
        assert not mutation_published.wait(timeout=0.2)
    finally:
        resume_allocator.set()
        allocator.join(timeout=10)
        setter.join(timeout=10)

    assert not allocator.is_alive()
    assert not setter.is_alive()
    assert errors == []
    assert grants == [pytest.approx(6.0)]
    assert registry.get_tenant("acme").max_daily_dollars == pytest.approx(4.0)


def test_simultaneous_processes_cannot_overgrant(monkeypatch, tmp_path) -> None:
    _provision_capped_tenant(monkeypatch)
    workers = 4
    start_file = tmp_path / "start-budget-workers"
    script = """
import sys
import time
from pathlib import Path
from maverick.tenant import registry

start = Path(sys.argv[1])
deadline = time.monotonic() + 15.0
while not start.exists():
    if time.monotonic() >= deadline:
        raise TimeoutError("budget worker start barrier timed out")
    time.sleep(0.005)
print(registry.reserve_tenant_budget("acme", 6.0, 3600.0, sys.argv[2]))
"""
    env = os.environ.copy()
    env["MAVERICK_HOME"] = str(tmp_path / ".maverick")
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(start_file),
                f"process-{index}",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(workers)
    ]
    start_file.touch()
    rows = [process.communicate(timeout=20) for process in processes]

    assert [process.returncode for process in processes] == [0] * workers, rows
    grants = [float(stdout.strip()) for stdout, _stderr in rows]
    assert sum(grants) <= 10.0 + 1e-9
    assert sorted(grant for grant in grants if grant > 0) == [4.0, 6.0]


def test_failed_usage_write_retains_reservation(monkeypatch) -> None:
    _provision_capped_tenant(monkeypatch)
    reservation_id = 'failed-legacy-fixture'
    registry.reserve_tenant_budget('acme', 6.0, 3600, reservation_id)

    def fail_record(*_args, **_kwargs):
        raise OSError("ledger unavailable")

    monkeypatch.setattr(UsageLedger, "record", fail_record)
    record_usage(
        "user:local",
        1.0,
        reservation_id=reservation_id,
    )

    # No durable charge was written, so fail closed by keeping the hold until
    # its TTL rather than making the unmetered allowance available again.
    assert registry.tenant_remaining_today("acme") == pytest.approx(4.0)
    assert reservation_id in registry._load_reservations("acme")
