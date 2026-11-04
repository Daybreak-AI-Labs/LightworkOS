"""Tenant-aware scheduling for governed AI billing ingestion."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from maverick.ai_cost_collectors import CollectorSchedule
from maverick.ai_cost_roi import BillingProvider
from maverick_dashboard import ai_cost_scheduler


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        """[ai_cost_roi]
enable = true
collector_poll_seconds = 3600
collector_lookback_days = 3

[ai_cost_roi.aws]
enable = true
payer_account_id = "123456789012"
services = ["Amazon Bedrock"]
""",
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()
    ai_cost_scheduler.stop_ai_cost_scheduler(timeout=0)
    yield tmp_path
    ai_cost_scheduler.stop_ai_cost_scheduler(timeout=0)
    config.reset_config_cache()


def test_collection_request_uses_only_complete_utc_midnight_days() -> None:
    request = ai_cost_scheduler._collection_request(
        3,
        now=datetime(
            2026,
            8,
            28,
            22,
            45,
            tzinfo=timezone(timedelta(hours=-4)),
        ),
    )

    assert request.period_start == "2026-08-26T00:00:00Z"
    assert request.period_end == "2026-08-29T00:00:00Z"


def test_collection_request_rejects_a_naive_clock() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ai_cost_scheduler._collection_request(1, now=datetime(2026, 8, 28))


def test_tenant_cycle_ingests_through_default_service_and_isolates_providers(
    monkeypatch,
) -> None:
    from maverick import ai_cost_collectors, ai_cost_roi, config

    collectors = (
        SimpleNamespace(
            provider=BillingProvider.AWS,
            collector_id="aws_cost_explorer_v1",
        ),
        SimpleNamespace(
            provider=BillingProvider.AZURE,
            collector_id="azure_cost_management_v1",
        ),
    )
    calls = []
    secret = "credential-value-that-must-not-persist"

    def collect_and_ingest(collector, request, *, actor):
        calls.append((collector.provider.value, request, actor))
        if collector.provider is BillingProvider.AWS:
            raise RuntimeError(secret)
        return {"id": "ACR-safe", "status": "complete"}

    monkeypatch.setattr(
        ai_cost_collectors,
        "configured_collector_schedule",
        lambda _section: CollectorSchedule(poll_seconds=3600, lookback_days=2),
    )
    monkeypatch.setattr(
        ai_cost_collectors,
        "configured_collectors",
        lambda _section: collectors,
    )
    monkeypatch.setattr(
        ai_cost_roi,
        "default_service",
        SimpleNamespace(collect_and_ingest=collect_and_ingest),
    )
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"ai_cost_roi": {"enable": True}},
    )

    result = ai_cost_scheduler._tenant_cycle(
        "system:test",
        {"ai_cost_roi": {"enable": True}},
        now=datetime(2026, 8, 28, 18, tzinfo=timezone.utc),
    )

    assert [(provider, actor) for provider, _request, actor in calls] == [
        ("aws", "system:test"),
        ("azure", "system:test"),
    ]
    assert {call[1].period_start for call in calls} == {"2026-08-26T00:00:00Z"}
    assert {call[1].period_end for call in calls} == {"2026-08-28T00:00:00Z"}
    assert result["results"] == [
        {
            "provider": "azure",
            "receipt": {"id": "ACR-safe", "status": "complete"},
        }
    ]
    assert result["failures"] == [
        {"provider": "aws", "error_type": "RuntimeError"}
    ]
    assert secret not in str(result)


def test_scheduler_cycle_uses_active_tenant_runner(monkeypatch) -> None:
    from maverick import ai_cost_collectors
    from maverick_dashboard import automation_queue

    section = {"enable": True}
    config = {"ai_cost_roi": section}
    collector = SimpleNamespace(provider=BillingProvider.AWS)
    observed = {}

    monkeypatch.setattr(
        ai_cost_scheduler,
        "_global_configuration",
        lambda: (config, section),
    )
    monkeypatch.setattr(
        ai_cost_collectors,
        "configured_collector_schedule",
        lambda _section: CollectorSchedule(),
    )
    monkeypatch.setattr(
        ai_cost_collectors,
        "configured_collectors",
        lambda _section: (collector,),
    )
    monkeypatch.setattr(
        ai_cost_scheduler,
        "_tenant_cycle",
        lambda actor, global_config: {
            "actor": actor,
            "global_config": global_config,
        },
    )

    def run(operation, callback):
        observed["operation"] = operation
        observed["result"] = callback()
        return True

    monkeypatch.setattr(automation_queue, "_run_for_active_tenants", run)

    assert ai_cost_scheduler.scheduler_cycle("system:test") is True
    assert observed == {
        "operation": "AI cost collection",
        "result": {"actor": "system:test", "global_config": config},
    }


def test_start_is_off_when_global_gate_or_collectors_are_disabled(
    _isolate,
) -> None:
    tmp_path = _isolate
    from maverick import config

    (tmp_path / "config.toml").write_text(
        "[ai_cost_roi]\nenable = false\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert ai_cost_scheduler.start_ai_cost_scheduler() is False

    (tmp_path / "config.toml").write_text(
        "[ai_cost_roi]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert ai_cost_scheduler.start_ai_cost_scheduler() is False


def test_start_and_stop_are_bounded(monkeypatch) -> None:
    monkeypatch.setattr(ai_cost_scheduler, "scheduler_cycle", lambda _actor: True)
    assert ai_cost_scheduler.start_ai_cost_scheduler() is True
    assert ai_cost_scheduler.start_ai_cost_scheduler() is False
    assert ai_cost_scheduler.stop_ai_cost_scheduler(timeout=0.1) is True
