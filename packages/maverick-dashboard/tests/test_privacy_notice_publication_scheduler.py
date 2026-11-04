from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from maverick_dashboard.privacy_notice_publication_composition import (
    PrivacyNoticePublicationRuntime,
)
from maverick_dashboard.privacy_notice_publication_scheduler import (
    PrivacyNoticePublicationScheduler,
    PrivacyNoticePublicationSchedulerBusy,
)


def _config(*, scheduler: bool = True):
    return {
        "consent_preferences": {"enable": True, "publishing": {"enable": True}},
        "privacy_automation": {
            "enable": True,
            "notice_governance": {
                "enable": True,
                "publication_runtime": {
                    "enable": True,
                    "scheduler_enable": scheduler,
                    "active_tenants": ["tenant-a"],
                    "poll_seconds": 30,
                    "retry_max_seconds": 120,
                    "tenant_limit": 1,
                    "lease_seconds": 60,
                    "retry_delay_seconds": 30,
                    "bindings": {
                        "primary": {
                            "tenant_id": "tenant-a",
                            "notice_id": "privacy-main",
                            "consent_publication_ref": "consent-binding:1",
                            "property_id": "property-main",
                            "rule_group_id": "production-rules",
                            "rule_group_version": 1,
                            "notice_resource_id": "privacy-notice",
                            "notice_resource_version": 1,
                        }
                    },
                },
            },
        },
    }


def _runtime(run):
    return PrivacyNoticePublicationRuntime(
        tenant_id="tenant-a",
        config_sha256="a" * 64,
        notice_store=object(),  # type: ignore[arg-type]
        consent_store=object(),  # type: ignore[arg-type]
        bridge=SimpleNamespace(process_next=run),  # type: ignore[arg-type]
    )


def test_run_once_is_bounded_status_is_content_free_and_recovery_is_durable(
    tmp_path,
) -> None:
    values = iter((2_400_000_000.0, 2_400_000_001.0, 2_400_000_002.0))
    scheduler = PrivacyNoticePublicationScheduler(
        tmp_path / "scheduler.json",
        runtime_factory=lambda _tenant: _runtime(
            lambda: SimpleNamespace(status="applied")
        ),
        config_loader=lambda: _config(),
        active_tenant_supplier=lambda: ("tenant-a", "tenant-b"),
        clock=lambda: next(values),
    )
    cycle = scheduler.run_once()
    assert cycle.tenants_considered == 1
    assert cycle.tenants_executed == 1
    assert cycle.applied == 1
    status = scheduler.status()
    assert status["process_concurrency_excluded"] is True
    assert status["cross_process_concurrency_excluded"] is True
    assert status["status_opened_tenant_store"] is False
    assert status["provider_network_io"] is False
    assert "tenant-a" not in str(status)

    state = dict(scheduler._state)  # noqa: SLF001 - explicit crash seam
    state["in_progress"] = True
    scheduler._write_state(state)  # noqa: SLF001 - simulate prior process crash
    values = iter((2_400_000_003.0, 2_400_000_004.0))
    scheduler._clock = lambda: next(values)  # noqa: SLF001 - deterministic recovery
    scheduler.run_once("tenant-a")
    assert scheduler.status()["interrupted_cycles_recovered"] == 1


def test_same_scheduler_rejects_overlapping_run_once(tmp_path) -> None:
    entered = threading.Event()
    release = threading.Event()

    def run():
        entered.set()
        assert release.wait(5)
        return SimpleNamespace(status="idle")

    scheduler = PrivacyNoticePublicationScheduler(
        tmp_path / "scheduler.json",
        runtime_factory=lambda _tenant: _runtime(run),
        config_loader=lambda: _config(),
        active_tenant_supplier=lambda: ("tenant-a",),
        clock=lambda: 2_400_000_000.0,
    )
    worker = threading.Thread(target=scheduler.run_once)
    worker.start()
    assert entered.wait(5)
    with pytest.raises(PrivacyNoticePublicationSchedulerBusy):
        scheduler.run_once()
    release.set()
    worker.join(5)
    assert not worker.is_alive()


def test_two_scheduler_instances_serialize_on_cross_process_authority(tmp_path) -> None:
    entered = threading.Event()
    release = threading.Event()
    active = 0
    maximum = 0
    guard = threading.Lock()

    def run():
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        entered.set()
        assert release.wait(5)
        with guard:
            active -= 1
        return SimpleNamespace(status="idle")

    kwargs = {
        "runtime_factory": lambda _tenant: _runtime(run),
        "config_loader": lambda: _config(),
        "active_tenant_supplier": lambda: ("tenant-a",),
        "clock": lambda: 2_400_000_000.0,
    }
    first = PrivacyNoticePublicationScheduler(tmp_path / "scheduler.json", **kwargs)
    second = PrivacyNoticePublicationScheduler(tmp_path / "scheduler.json", **kwargs)
    one = threading.Thread(target=first.run_once)
    two = threading.Thread(target=second.run_once)
    one.start()
    assert entered.wait(5)
    two.start()
    release.set()
    one.join(5)
    two.join(5)
    assert not one.is_alive() and not two.is_alive()
    assert maximum == 1


def test_manual_run_requires_active_exact_tenant_even_when_scheduler_is_off(
    tmp_path,
) -> None:
    scheduler = PrivacyNoticePublicationScheduler(
        tmp_path / "scheduler.json",
        runtime_factory=lambda _tenant: _runtime(
            lambda: SimpleNamespace(status="no_change")
        ),
        config_loader=lambda: _config(scheduler=False),
        active_tenant_supplier=lambda: ("tenant-a",),
        clock=lambda: 2_400_000_000.0,
    )
    assert scheduler.run_once("tenant-a").no_change == 1
    with pytest.raises(Exception, match="not an active configured"):
        scheduler.run_once("tenant-b")
