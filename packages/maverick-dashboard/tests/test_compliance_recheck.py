"""Compliance protections are re-checked at least hourly, and a
protection that breaks shows as failing at the next check, with when.

The soak test breaks one control (the AI notice), runs the background
re-check one cycle later and finds the status flipped with a timestamp and a
history entry; a re-check inside the hour does nothing. The Compliance page
shows when it checked and since when each status holds."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

NOTICE = "AI transparency disclosure"


@pytest.fixture
def env(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _break_the_notice(tmp_path):
    from maverick import config

    (tmp_path / "config.toml").write_text('[compliance]\ndisclosure_text = ""\n', encoding="utf-8")
    config.reset_config_cache()


def test_a_broken_control_fails_at_the_next_hourly_check(env):
    from maverick import compliance_history

    t0 = 1_800_000_000.0
    first = compliance_history.recheck_if_due(now=t0)
    assert first["controls"][NOTICE] == {"status": "active", "since": t0}
    _break_the_notice(env)
    # Inside the hour nothing runs: the background loop polls every 30 s.
    assert compliance_history.recheck_if_due(now=t0 + 1800) is None
    later = compliance_history.recheck_if_due(now=t0 + 3600)
    assert later["checked_at"] == t0 + 3600
    assert later["controls"][NOTICE] == {"status": "action_needed", "since": t0 + 3600}
    assert {"control": NOTICE, "from": "active", "to": "action_needed", "at": t0 + 3600} in later["changes"]
    # Time to fail: one cycle, at most an hour.
    assert later["controls"][NOTICE]["since"] - t0 <= compliance_history.EVERY_SECONDS


def test_the_background_loop_runs_the_hourly_check():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "maverick_dashboard/deadline_alerts_scheduler.py").read_text()
    assert "recheck_if_due(now=now)" in source


def test_the_page_says_when_it_checked_and_since_when(env):
    from maverick_dashboard.app import app

    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    page = client.get("/compliance").text
    assert 'id="cmp-checked"' in page and "checks every protection again each hour" in page
    assert '<th scope="col">Since</th>' in page
    _break_the_notice(env)
    page = client.get("/compliance").text
    assert "Status changes (" in page
    assert "AI transparency disclosure went from on to needs action" in page
