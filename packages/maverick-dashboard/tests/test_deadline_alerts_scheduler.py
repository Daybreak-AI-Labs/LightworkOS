"""The deadline-alerts scheduler: one thread, stop is observed, run_once
evaluates deadlines and pumps webhook retries, and the shutdown supervisor
knows how to stop it."""
from __future__ import annotations

import pytest
from maverick_dashboard import deadline_alerts_scheduler as sched


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    config.reset_config_cache()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    sched.stop_deadline_alerts_scheduler(timeout=5.0)


def test_start_is_idempotent_and_stop_is_observed():
    assert sched.start_deadline_alerts_scheduler() is True
    assert sched.start_deadline_alerts_scheduler() is False  # already running
    assert sched._scheduler_thread is not None and sched._scheduler_thread.is_alive()
    assert sched.stop_deadline_alerts_scheduler(timeout=5.0) is True
    assert sched._scheduler_thread is None
    assert sched.stop_deadline_alerts_scheduler() is False  # nothing to stop


def test_run_once_reports_alerts_and_webhook_retries(monkeypatch):
    from maverick import deadline_alerts, webhook_subscriptions
    monkeypatch.setattr(deadline_alerts, "collect", lambda **kw: [
        deadline_alerts.Deadline("dsar", "R1", "access request from a@b.com", 1.0, "/privacy/dsar/R1")])
    monkeypatch.setattr(deadline_alerts, "deliver", lambda *a, **k: 2)
    monkeypatch.setattr(deadline_alerts, "_emit_webhook", lambda alert, world: None)
    monkeypatch.setattr(webhook_subscriptions, "process_due", lambda **kw: 3)
    summary = sched.run_once(now=1_800_000_000.0)
    assert summary["sent"] == 1 and summary["alerts"][0]["state"] == "overdue"
    assert summary["webhook_retries"] == 3 and summary["ran_at"] == 1_800_000_000.0
    assert sched.last_cycle()["sent"] == 1 and "alerts" not in sched.last_cycle()
    # The ledger holds it: a second run sends nothing.
    assert sched.run_once(now=1_800_000_100.0)["already_sent"] == 1


def test_shutdown_supervisor_registers_the_scheduler():
    from types import SimpleNamespace

    from maverick_dashboard._lifecycle import register_main_components

    registered: dict[str, tuple] = {}
    supervisor = SimpleNamespace(
        register=lambda name, stop, alive: registered.__setitem__(name, (stop, alive)),
        register_final_resource=lambda *a, **k: None,
    )
    register_main_components(SimpleNamespace(state=SimpleNamespace()), supervisor)
    stop, alive = registered["deadline_alerts"]
    assert sched.start_deadline_alerts_scheduler() is True
    assert alive() is True
    assert stop(timeout=5.0) is True and alive() is False


def test_each_workspace_gets_its_own_retry_pump_and_alert_cycle(monkeypatch):
    # The thread has no request workspace: unpinned, a workspace's failed
    # webhook deliveries and due alerts were never handled.
    from maverick import deadline_alerts, webhook_subscriptions
    from maverick.tenant import registry

    registry.create_tenant("acme")
    pumped, evaluated = [], []
    monkeypatch.setattr(webhook_subscriptions, "process_due",
                        lambda **kw: pumped.append(webhook_subscriptions.workspace_id()) or 0)
    monkeypatch.setattr(deadline_alerts, "settings", lambda: {"enabled": True, "poll_seconds": 900})
    monkeypatch.setattr(deadline_alerts, "run_cycle",
                        lambda **kw: evaluated.append(webhook_subscriptions.workspace_id()) or {"sent": 0})
    next_eval: dict = {}
    sched._tick(1_800_000_000.0, next_eval)
    assert "acme" in pumped and "acme" in evaluated
    assert len(evaluated) == len(set(evaluated)) == len(next_eval)
    # Each workspace keeps its own schedule: nothing is due again until its poll interval.
    evaluated.clear()
    sched._tick(1_800_000_030.0, next_eval)
    assert evaluated == []


def test_a_workspace_sees_only_its_own_last_cycle(monkeypatch):
    from maverick import deadline_alerts, webhook_subscriptions
    from maverick.paths import tenant_scope

    monkeypatch.setattr(deadline_alerts, "run_cycle", lambda **kw: {"sent": 4, "alerts": []})
    monkeypatch.setattr(webhook_subscriptions, "process_due", lambda **kw: 0)
    monkeypatch.setattr(sched, "_world", lambda: None)
    with tenant_scope(tenant="acme"):
        sched.run_once(now=1_800_000_000.0)
        assert sched.last_cycle()["sent"] == 4
    with tenant_scope(tenant="globex"):
        assert sched.last_cycle() == {}


def test_each_workspace_gets_its_hourly_compliance_recheck(monkeypatch):
    # The history is kept per workspace; unpinned, only the base workspace's
    # was re-checked, so another workspace's broken protection never showed.
    from maverick import compliance, compliance_history, deadline_alerts, webhook_subscriptions
    from maverick.paths import tenant_scope
    from maverick.tenant import registry

    registry.create_tenant("acme")
    monkeypatch.setattr(compliance, "compliance_report", list)
    monkeypatch.setattr(webhook_subscriptions, "process_due", lambda **kw: 0)
    monkeypatch.setattr(deadline_alerts, "settings", lambda: {"enabled": False, "poll_seconds": 900})
    sched._tick(1_800_000_000.0, {})
    assert compliance_history.state()["checked_at"] == 1_800_000_000.0
    with tenant_scope(tenant="acme"):
        assert compliance_history.state()["checked_at"] == 1_800_000_000.0
