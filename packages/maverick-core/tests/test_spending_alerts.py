"""Alerts at 50%, 75% and 100% of a spending limit, once per limit period."""
from __future__ import annotations

import pytest
from maverick import config, spending_alerts, spending_limits
from maverick.quotas import record_usage


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    spending_limits._ACTIVE.clear()
    yield
    spending_limits._ACTIVE.clear()
    config.reset_config_cache()


def _percents(scope=None):
    return sorted((r["scope"], r["principal"], r["percent"]) for r in spending_alerts.current()
                  if scope is None or r["scope"] == scope)


def test_defaults_are_50_75_and_100_percent():
    assert spending_alerts.alert_at() == [50, 75, 100]


def test_each_crossing_alerts_once_per_period_as_spend_is_recorded():
    spending_limits.set_user_limit("user:alice", "10", "month", actor="user:admin")
    record_usage("user:alice", 4.0)
    assert _percents() == []
    record_usage("user:alice", 1.5)  # $5.50 of $10
    assert _percents() == [("person", "user:alice", 50)]
    record_usage("user:alice", 0.1)  # still past 50% only: no second alert
    assert _percents() == [("person", "user:alice", 50)]
    record_usage("user:alice", 5.0)  # past 100%, so 75% and 100% both arrive now
    assert _percents() == [("person", "user:alice", p) for p in (50, 75, 100)]
    assert spending_alerts.observe("user:alice") == []  # nothing new this period


def test_workspace_limit_alerts_once_for_everyone():
    spending_limits.set_workspace_limit("100", "day", actor="user:admin")
    record_usage("user:alice", 30.0)
    record_usage("user:bob", 30.0)
    record_usage("user:carol", 1.0)
    assert _percents("workspace") == [("workspace", "", 50)]


def test_admins_see_every_crossing_and_people_see_their_own():
    spending_limits.set_workspace_limit("100", "month", actor="user:admin")
    spending_limits.set_user_limit("user:alice", "10", "month", actor="user:admin")
    record_usage("user:alice", 8.0)
    record_usage("user:bob", 50.0)
    admin = spending_alerts.sources("user:admin", admin=True)
    alice = spending_alerts.sources("user:alice", admin=False)
    bob = spending_alerts.sources("user:bob", admin=False)
    assert {s["label"] for s in admin} == {
        "alice has used 50% of their $10.00 per month spending limit.",
        "alice has used 75% of their $10.00 per month spending limit.",
        "The workspace has used 50% of its $100.00 per month spending limit."}
    assert {s["label"] for s in alice} == {
        "You have used 50% of your $10.00 per month spending limit.",
        "You have used 75% of your $10.00 per month spending limit."}
    assert bob == []  # no limit of his own crossed; the workspace one goes to administrators
    assert all(s["href"] == "/spending-limits" for s in admin)
    assert all(s["href"] == "/budget" and s["category"] == "blocked" for s in alice)


def test_reaching_the_limit_says_work_stops(tmp_path):
    spending_limits.set_user_limit("user:alice", "10", "day", actor="user:admin")
    record_usage("user:alice", 10.0)
    labels = [s["label"] for s in spending_alerts.sources("user:alice", admin=False)]
    assert ("You have reached your $10.00 per day spending limit. New paid work stops "
            "until it resets or an administrator changes it.") in labels
    # The alert is only a notice: admission still refuses the next paid request.
    assert spending_limits.start_refusal("user:alice") is not None


def test_a_per_task_limit_has_no_running_total_to_alert_on():
    spending_limits.set_user_limit("user:alice", "1", "task", actor="user:admin")
    record_usage("user:alice", 5.0)
    assert spending_alerts.current() == []


def test_alert_points_follow_the_setting(tmp_path):
    (tmp_path / "config.toml").write_text("[spending_limits]\nalert_at = [90]\n")
    config.reset_config_cache()
    assert spending_alerts.alert_at() == [90]
    spending_limits.set_user_limit("user:alice", "10", "month", actor="user:admin")
    record_usage("user:alice", 8.0)
    assert _percents() == []
    record_usage("user:alice", 1.5)
    assert _percents() == [("person", "user:alice", 90)]


def test_empty_setting_turns_alerts_off_but_not_the_limit(tmp_path):
    (tmp_path / "config.toml").write_text("[spending_limits]\nalert_at = []\n")
    config.reset_config_cache()
    spending_limits.set_user_limit("user:alice", "10", "day", actor="user:admin")
    record_usage("user:alice", 12.0)
    assert spending_alerts.current() == []
    assert spending_limits.start_refusal("user:alice") is not None


def test_an_unreadable_setting_keeps_the_defaults(tmp_path):
    (tmp_path / "config.toml").write_text('[spending_limits]\nalert_at = ["lots"]\n')
    config.reset_config_cache()
    assert spending_alerts.alert_at() == [50, 75, 100]


@pytest.mark.parametrize("value", [[0], [101], [50.5], [True], "50", list(range(1, 12))])
def test_alert_points_are_validated(value):
    with pytest.raises(ValueError):
        spending_alerts.validate_alert_at(value)


def test_alert_points_are_normalized():
    assert spending_alerts.validate_alert_at(["75", 50, "100%", 50]) == [50, 75, 100]
    assert spending_alerts.validate_alert_at([]) == []
