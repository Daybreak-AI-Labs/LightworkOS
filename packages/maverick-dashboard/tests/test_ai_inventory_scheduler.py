"""Background AI-estate reconciliation wiring."""
from __future__ import annotations

import pytest
from maverick_dashboard import ai_inventory_scheduler


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        """[ai_inventory]
enable = true
connectors = ["bedrock", "vertex_ai"]
poll_seconds = 900
""",
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()
    ai_inventory_scheduler.stop_ai_inventory_scheduler(timeout=0)
    yield tmp_path
    ai_inventory_scheduler.stop_ai_inventory_scheduler(timeout=0)
    config.reset_config_cache()


@pytest.mark.parametrize("value", [True, 0, 59, 86401, float("inf")])
def test_poll_seconds_is_bounded(value):
    with pytest.raises(ValueError, match="poll_seconds"):
        ai_inventory_scheduler._poll_seconds({"poll_seconds": value})


def test_tenant_cycle_isolates_connector_failures(monkeypatch):
    from maverick import ai_inventory

    monkeypatch.setattr(ai_inventory, "enabled", lambda: True)
    monkeypatch.setattr(
        ai_inventory,
        "require_enabled",
        lambda: {"connectors": ["bedrock", "vertex_ai"]},
    )

    def sync(connector, *, actor):
        if connector == "bedrock":
            raise RuntimeError("credential-value-that-must-not-persist")
        return {"connector": connector, "actor": actor, "status": "complete"}

    monkeypatch.setattr(ai_inventory, "sync_connector", sync)

    result = ai_inventory_scheduler._tenant_cycle("system:test")

    assert result["results"][0]["connector"] == "vertex_ai"
    assert result["failures"] == [{
        "connector": "bedrock",
        "error_type": "RuntimeError",
    }]
    assert "credential-value" not in str(result)


def test_scheduler_cycle_uses_active_tenant_runner(monkeypatch):
    from maverick_dashboard import automation_queue

    observed = {}

    def run(operation, callback):
        observed["operation"] = operation
        observed["result"] = callback()
        return True

    monkeypatch.setattr(automation_queue, "_run_for_active_tenants", run)
    monkeypatch.setattr(
        ai_inventory_scheduler,
        "_tenant_cycle",
        lambda actor: {"actor": actor},
    )

    assert ai_inventory_scheduler.scheduler_cycle("system:test") is True
    assert observed == {
        "operation": "AI inventory reconciliation",
        "result": {"actor": "system:test"},
    }


def test_start_is_off_when_global_gate_is_disabled(_isolate):
    tmp_path = _isolate
    from maverick import config

    (tmp_path / "config.toml").write_text(
        "[ai_inventory]\nenable = false\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert ai_inventory_scheduler.start_ai_inventory_scheduler() is False


def test_start_and_stop_are_bounded(monkeypatch):
    monkeypatch.setattr(ai_inventory_scheduler, "_scheduler_loop", lambda *_args: None)
    assert ai_inventory_scheduler.start_ai_inventory_scheduler() is True
    assert ai_inventory_scheduler.stop_ai_inventory_scheduler(timeout=0.1) is True
