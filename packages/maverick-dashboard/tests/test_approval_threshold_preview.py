"""Next to "Actions that can't be undone" (the approval threshold), a
report-only preview from the recorded approval checks: how many actions, by
how many agents and specialists, would have needed approval at the chosen
level in the last 30 days. Too little history says so; nothing is saved."""
from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient

API = "/api/v1/settings/catalog/preview/safety.consent_mode"
DAY = 86_400.0


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import approval_checks, config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in list(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")) and name not in {"MAVERICK_HOME", "MAVERICK_ENCRYPT_AT_REST"}:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(approval_checks, "_pruned_at", {})
    config.reset_config_cache()
    from maverick_dashboard.app import _world_cache, app
    _world_cache.clear()
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def _record(*rows):
    from maverick import approval_checks
    from maverick.world_model import close_world_if_owned, open_world
    world = open_world()
    try:
        for risk, agent, outcome, age_days, count in rows:
            for _ in range(count):
                approval_checks.record_check(world, risk=risk, action="shell", outcome=outcome, agent=agent,
                                             now=time.time() - age_days * DAY)
    finally:
        close_world_if_owned(world)


def test_with_no_recorded_checks_the_preview_says_there_is_not_enough(client):
    body = client.get(API, params={"value": "ask"}).json()
    assert body["kind"] == "approval_checks" and body["enough"] is False
    assert body["recording_started_at"] is None
    assert body["days"] == 30


def test_under_30_days_of_history_names_when_recording_started(client):
    _record(("high", "finance_close", "asked", 10, 40))
    body = client.get(API, params={"value": "ask"}).json()
    assert body["enough"] is False and body["reason"] == "history"
    assert body["recording_started_at"] == pytest.approx(time.time() - 10 * DAY, abs=60)


def test_too_few_checks_in_30_days_is_not_enough_either(client):
    _record(("high", "finance_close", "asked", 45, 1), ("low", "", "allowed", 2, 3))
    body = client.get(API, params={"value": "ask"}).json()
    assert body["enough"] is False and body["reason"] == "count"
    assert body["checks"] == 3 and body["minimum"] > 3


def test_each_level_counts_actions_and_agents_from_the_records(client):
    _record(("high", "finance_close", "asked", 31, 1),          # outside the window, but history spans 30 days
            ("high", "finance_close", "asked", 3, 6),
            ("critical", "it_ops", "refused", 4, 2),
            ("low", "finance_close", "allowed", 5, 10),
            ("medium", "", "allowed", 6, 4))
    asked = client.get(API, params={"value": "ask"}).json()
    assert asked["enough"] is True
    assert (asked["actions"], asked["agents"], asked["refused"], asked["checks"]) == (22, 2, 0, 22)
    assert asked["recorded"] == {"asked": 6, "allowed": 14, "refused": 2}
    allowed = client.get(API, params={"value": "auto-approve"}).json()
    assert (allowed["actions"], allowed["agents"], allowed["refused"]) == (0, 0, 0)
    refused = client.get(API, params={"value": "auto-deny"}).json()
    assert (refused["actions"], refused["refused"]) == (0, 22)
    # The default: risky ones (high and critical) go to a person.
    risky = client.get(API, params={"value": ""}).json()
    assert (risky["actions"], risky["agents"]) == (8, 2)


def test_the_preview_saves_nothing(client):
    from maverick.config import load_config, reset_config_cache
    _record(("high", "finance_close", "asked", 31, 30))
    before = (load_config() or {}).get("safety")
    assert client.get(API, params={"value": "auto-deny"}).status_code == 200
    reset_config_cache()
    assert (load_config() or {}).get("safety") == before


def test_an_unknown_level_has_no_preview(client):
    response = client.get(API, params={"value": "sometimes"})
    assert response.status_code == 422


def test_the_setting_row_offers_the_preview_for_every_choice_including_the_default():
    from maverick_dashboard import settings_catalog as catalog
    assert catalog.BY_ID["safety.consent_mode"].preview == "approval_checks"
