"""Production wiring for the governed red-team schedule dispatcher."""
from __future__ import annotations

import pytest
from maverick_dashboard import red_team_scheduler


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        """[red_team_assurance]
enable = true
scheduler_poll_seconds = 30
""",
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()
    red_team_scheduler.stop_red_team_scheduler(timeout=0)
    yield tmp_path
    red_team_scheduler.stop_red_team_scheduler(timeout=0)
    config.reset_config_cache()


@pytest.mark.parametrize("value", [True, 0, 4.9, 3600.1, float("inf")])
def test_poll_seconds_rejects_unsafe_values(value):
    with pytest.raises(ValueError, match="scheduler_poll_seconds"):
        red_team_scheduler._poll_seconds({"scheduler_poll_seconds": value})


def test_tenant_cycle_dispatches_bounded_due_work(monkeypatch):
    from maverick import red_team_assurance as rta

    observed = {}
    monkeypatch.setattr(rta, "enabled", lambda: True)
    monkeypatch.setattr(
        rta,
        "run_due_schedules",
        lambda **kwargs: observed.setdefault("run", kwargs) or {},
    )

    red_team_scheduler._tenant_cycle("system:test")

    assert observed["run"] == {"actor": "system:test", "limit": 100}


def test_tenant_cycle_skips_disabled_tenant(monkeypatch):
    from maverick import red_team_assurance as rta

    monkeypatch.setattr(rta, "enabled", lambda: False)
    monkeypatch.setattr(
        rta,
        "run_due_schedules",
        lambda **_kwargs: pytest.fail("disabled tenant must not dispatch"),
    )

    result = red_team_scheduler._tenant_cycle("system:test")

    assert result["skipped"] is True


def test_scheduler_cycle_uses_active_tenant_runner(monkeypatch):
    from maverick_dashboard import automation_queue

    observed = {}

    def run(operation, callback):
        observed["operation"] = operation
        observed["result"] = callback()
        return True

    monkeypatch.setattr(automation_queue, "_run_for_active_tenants", run)
    monkeypatch.setattr(
        red_team_scheduler,
        "_tenant_cycle",
        lambda actor: {"actor": actor},
    )

    assert red_team_scheduler.scheduler_cycle("system:test") is True
    assert observed == {
        "operation": "red-team schedule dispatcher",
        "result": {"actor": "system:test"},
    }


def test_start_is_off_when_global_gate_is_disabled(_isolate):
    tmp_path = _isolate
    from maverick import config

    (tmp_path / "config.toml").write_text(
        "[red_team_assurance]\nenable = false\n",
        encoding="utf-8",
    )
    config.reset_config_cache()

    assert red_team_scheduler.start_red_team_scheduler() is False


def test_start_and_stop_are_bounded(monkeypatch):
    monkeypatch.setattr(red_team_scheduler, "_scheduler_loop", lambda *_args: None)

    assert red_team_scheduler.start_red_team_scheduler() is True
    assert red_team_scheduler.stop_red_team_scheduler(timeout=0.1) is True
