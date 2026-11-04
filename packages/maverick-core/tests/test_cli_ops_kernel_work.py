"""Kernel functions shared by commands and their new dashboard controls."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from maverick.cli import main
from maverick.world_model import WorldModel


def test_goal_bundle_is_what_the_export_command_writes(tmp_path, monkeypatch):
    from maverick.goal_bundle import build_goal_bundle

    # Compare the same snapshot preparation instant, including its receipt.
    monkeypatch.setattr("maverick.goal_archive.time.time", lambda: 1_790_000_000.0)

    db = tmp_path / "world.db"
    world = WorldModel(db)
    goal = world.create_goal("Summarise the report", owner="user:a")
    world.append_event(goal, "planner", "plan", "Read the report first")
    bundle = build_goal_bundle(world, goal)
    assert bundle["v"] == 1 and bundle["goal"]["id"] == goal and len(bundle["events"]) == 1
    assert build_goal_bundle(world, 999) is None
    world.close()
    out = tmp_path / "bundle.json"
    result = CliRunner().invoke(main, ["--db", str(db), "export", str(goal), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text()) == json.loads(json.dumps(bundle, default=str))
    missing = CliRunner().invoke(main, ["--db", str(db), "export", "999", "-o", str(tmp_path / "x.json")])
    assert missing.exit_code == 2


@pytest.mark.parametrize("repeat, kwargs, expected", [
    ("daily", {"at": "09:05"}, "5 9 * * *"),
    ("weekdays", {"at": "18:30"}, "30 18 * * 1-5"),
    ("weekly", {"at": "07:00", "days": [5, 1, 1]}, "0 7 * * 1,5"),
    ("monthly", {"at": "00:00", "day_of_month": 28}, "0 0 28 * *"),
    ("hourly", {"every_hours": 1}, "0 * * * *"),
    ("hourly", {"every_hours": 6}, "0 */6 * * *"),
])
def test_timetable_cron(repeat, kwargs, expected):
    from maverick.scheduler import parse_cron, timetable_cron

    cron = timetable_cron(repeat, **kwargs)
    assert cron == expected
    parse_cron(cron)


@pytest.mark.parametrize("repeat, kwargs", [
    ("yearly", {}), ("daily", {"at": "9:00"}), ("daily", {"at": "24:00"}), ("weekly", {"days": []}),
    ("weekly", {"days": [7]}), ("monthly", {"day_of_month": 32}), ("hourly", {"every_hours": 13}),
])
def test_timetable_cron_refuses_bad_choices(repeat, kwargs):
    from maverick.scheduler import CronError, timetable_cron

    with pytest.raises(CronError):
        timetable_cron(repeat, **kwargs)


def test_upcoming_runs_follow_the_zone():
    from maverick.scheduler import upcoming_runs

    after = 1_767_225_600.0  # 2026-01-01 00:00 UTC
    utc = upcoming_runs("0 9 * * *", tz="UTC", after=after)
    ny = upcoming_runs("0 9 * * *", tz="America/New_York", after=after)
    assert len(utc) == 3 and utc == sorted(utc) and ny[0] - utc[0] == 5 * 3600


def test_recipe_domain_from_capture_contract():
    from maverick.flow.recipe_domain import domain_from_contract

    pair = {"arguments": {"type": "object"}, "result": {"type": "object"}}
    contract = {"allowed_tools": ["a", "b", "c"], "input_schema": {"type": "object"},
                "tool_data_schemas": {"a": pair, "b": pair, "c": pair}}
    episodes = [{"steps": [{"tool": "a"}, {"tool": "b"}]}, {"steps": [{"tool": "a"}, {"tool": "c"}]}]
    assert domain_from_contract("transforms", contract, episodes)["steps"] == [pair, pair]
    choice = domain_from_contract("choices", contract, episodes)
    assert choice["prefix"] == pair and set(choice["branches"]) == {"b", "c"}
    assert set(domain_from_contract("workflow", contract, episodes)["tools"]) == {"a", "b", "c"}
    with pytest.raises(ValueError):
        domain_from_contract("transforms", {**contract, "tool_data_schemas": {}}, episodes)
    with pytest.raises(ValueError):
        domain_from_contract("unknown", contract, episodes)


def test_guided_observer_reads_uploaded_text_without_echoing_bad_lines():
    from maverick.ekko_daemon import GuidedJsonlObserver

    observer = GuidedJsonlObserver.from_text(json.dumps({"app": "excel", "action": "open"}) + "\n\n")
    assert observer.observe().to_dict()["app"] == "excel"
    assert observer.observe() is None and observer.exhausted is True
    secret = "window-title-secret"  # pragma: allowlist secret
    bad = GuidedJsonlObserver.from_text(json.dumps({"app": "excel", "action": "open", "window_title": secret}))
    with pytest.raises(ValueError) as caught:
        bad.observe()
    assert "line 1" in str(caught.value) and secret not in str(caught.value)


def test_onboarding_knowledge_base_reports_disabled_without_importing(monkeypatch, tmp_path):
    import sys

    from maverick import config
    from maverick.intake import onboarding_knowledge_base

    cfg = tmp_path / "config.toml"
    cfg.write_text("[knowledge]\nenable = false\n")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    config.reset_config_cache()
    monkeypatch.setitem(sys.modules, "maverick_knowledge", None)
    try:
        assert onboarding_knowledge_base() == (None, "disabled")
    finally:
        config.reset_config_cache()


def test_apply_approved_plan_records_learning_signals(monkeypatch):
    import maverick.factory_learning as factory_learning
    import maverick.provision as provision

    seen = []
    result = SimpleNamespace(acquired=[], generated=[], failed=[])
    monkeypatch.setattr(provision, "apply_plan", lambda plan, *, approved, llm=None: seen.append(approved) or result)
    monkeypatch.setattr(factory_learning, "record_provisioning", lambda profile, plan, res: seen.append(res))
    assert provision.apply_approved_plan("profile", "plan") is result
    assert seen == [True, result]


def test_capture_description_is_closed_bounded_and_admitted():
    from maverick.flow.action_episode_review import _matches, _schema
    from maverick.flow.capture_schema import describe

    value = {"name": "ACME", "count": 3, "rate": 1.5, "ok": True, "tags": ["a", "b"], "nested": {"id": None}}
    schema = describe(value)
    _schema(schema)  # the capture service's own closed language
    _matches(value, schema)
    assert schema["properties"]["tags"]["minItems"] == schema["properties"]["tags"]["maxItems"] == 2
    with pytest.raises(ValueError):
        describe({"x": object()})


def test_budgeted_model_checks_and_passes_the_budget():
    from maverick.budget import Budget, BudgetExceeded
    from maverick.provision import BudgetedLLM

    seen = []
    inner = SimpleNamespace(complete=lambda **kw: seen.append(kw["budget"]) or "ok")
    budget = Budget(max_dollars=1.0)
    assert BudgetedLLM(inner, budget).complete(system="s", messages=[]) == "ok" and seen == [budget]
    spent = Budget(max_dollars=0.01)
    spent.dollars = 1.0
    with pytest.raises(BudgetExceeded):
        BudgetedLLM(inner, spent).complete(system="s", messages=[])
    assert len(seen) == 1, "no model call once the budget is spent"
