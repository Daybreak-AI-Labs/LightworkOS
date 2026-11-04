"""Director mode: outcome -> plan-first goal + autonomy envelope."""
from __future__ import annotations

import pytest
from maverick.director_mode import UnknownProfileError, direct


def test_supervised_envelope():
    run = direct("Ship the Q3 report", profile="supervised",
                 base_max_dollars=10.0)
    assert run.consent_mode == "ask"
    assert run.max_dollars == 5.0          # 0.5x
    assert run.checkpoint == {"dollars": 2.0, "tool_calls": 25}
    assert run.planning_mode == "plan_execute_reflect"
    assert run.goal_description.startswith("Outcome: Ship the Q3 report")
    assert run.env_overrides["MAVERICK_CONSENT_MODE"] == "ask"


def test_autonomous_envelope_scales_budget():
    run = direct("Migrate the data warehouse", profile="autonomous",
                 base_max_dollars=10.0)
    assert run.consent_mode == "auto-approve"
    assert run.max_dollars == 20.0         # 2x
    assert run.checkpoint["dollars"] == 25.0


def test_unknown_profile_refused():
    with pytest.raises(UnknownProfileError, match="unknown autonomy profile"):
        direct("anything", profile="yolo")


def test_empty_outcome_refused():
    with pytest.raises(ValueError, match="outcome statement is required"):
        direct("   ")


def test_long_outcome_titled_safely():
    long = "deliver " + "x" * 200
    run = direct(long, profile="semi", base_max_dollars=5.0)
    assert len(run.goal_title) == 80
    assert run.goal_description.startswith(f"Outcome: {long}")


def test_config_profile_override(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda: {"director": {"profiles": {"semi": {
            "budget_multiplier": 3.0,
            "checkpoint": {"dollars": 4.0},
        }}}})
    run = direct("outcome", profile="semi", base_max_dollars=10.0)
    assert run.max_dollars == 30.0
    assert run.checkpoint["dollars"] == 4.0
    assert run.checkpoint["tool_calls"] == 100  # unoverridden key kept


def test_default_budget_comes_from_config(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    run = direct("outcome", profile="semi")
    assert run.max_dollars is None
    monkeypatch.setattr("maverick.config.get_budget_overrides", lambda: {"max_dollars": 8})
    assert direct("outcome", profile="semi").max_dollars == 8


def test_as_dict_serializable():
    import json
    json.dumps(direct("outcome", profile="semi", base_max_dollars=1.0).as_dict())
