"""Goal risk-tier auto-classifier: signal table, de-escalation, thresholds,
floor + require-human knobs. Deterministic and offline (no model, no clock).
"""
from __future__ import annotations

import pytest
from maverick.safety.goal_risk import (
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
    classify_goal,
    config_floor,
    require_human_for,
)
from maverick.safety.tool_risk import risk_rank


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch, tmp_path):
    for env in ("MAVERICK_GOAL_RISK_FLOOR", "MAVERICK_GOAL_RISK_REQUIRE_HUMAN"):
        monkeypatch.delenv(env, raising=False)
    # Point at a non-existent config so [safety] is empty unless a test writes one.
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "nonexistent.toml"))


def _config(monkeypatch, tmp_path, body: str):
    cfg = tmp_path / "config.toml"
    cfg.write_text(body, encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))


# --- signal classes ---------------------------------------------------------

@pytest.mark.parametrize("title,signal", [
    ("Wire the vendor payment for Q3", "money"),
    ("Delete the staging cluster", "infra_destruction"),
    ("Rotate the AWS access key", "credentials"),
    ("Send the launch newsletter", "bulk_outbound"),
    ("Provide legal advice on the merger", "regulated_domain"),
    ("Export user data to the new CRM", "pii_processing"),
    ("Permanently archive the audit records", "irreversible"),
])
def test_each_signal_class_fires(title, signal):
    risk = classify_goal(title)
    assert signal in risk.signals
    assert risk.score > 0.0


def test_word_boundaries_no_substring_fires():
    # "buyer" must not fire "buy"; "production-adjacent" words don't leak in.
    risk = classify_goal("Debug the buyer profile page styling")
    assert risk.signals == [] and risk.tier == "low" and risk.score == 0.0


def test_description_is_scored_too():
    title_only = classify_goal("Routine maintenance")
    with_desc = classify_goal("Routine maintenance", "then deploy to production")
    assert title_only.tier == "low"
    assert "infra_destruction" in with_desc.signals
    assert "irreversible" in with_desc.signals


# --- de-escalation ----------------------------------------------------------

def test_read_only_verb_deescalates():
    doing = classify_goal("Process the customer refund")
    reading = classify_goal("Research customer refund fraud patterns")
    assert doing.tier == "medium"
    assert reading.tier == "low"
    assert "deescalate:read_only" in reading.signals
    assert reading.score < doing.score


def test_deescalator_alone_is_not_listed():
    risk = classify_goal("Summarize last week's standup notes")
    assert risk.signals == [] and risk.score == 0.0 and risk.tier == "low"


def test_deescalation_never_goes_negative():
    risk = classify_goal("Draft a summary analyzing the research plan")
    assert risk.score == 0.0 and risk.tier == "low"


# --- thresholds -------------------------------------------------------------

def test_threshold_edge_exactly_medium():
    # pii_processing alone is exactly MEDIUM_THRESHOLD (30 points).
    risk = classify_goal("Export user data")
    assert risk.signals == ["pii_processing"]
    assert risk.score == MEDIUM_THRESHOLD / 100.0
    assert risk.tier == "medium"


def test_threshold_edge_just_below_medium():
    # irreversible alone is 25 points -- one short of the medium line.
    risk = classify_goal("Permanently pin the wiki sidebar")
    assert risk.signals == ["irreversible"]
    assert risk.tier == "low"


def test_threshold_edge_exactly_high():
    # regulated_domain (35) + irreversible (25) == HIGH_THRESHOLD (60).
    risk = classify_goal("Give medical advice to all users")
    assert set(risk.signals) == {"regulated_domain", "irreversible"}
    assert risk.score == HIGH_THRESHOLD / 100.0
    assert risk.tier == "high"


def test_hard_signal_plus_irreversibility_is_high():
    risk = classify_goal("Delete all users from the production database")
    assert risk.tier == "high"
    assert "infra_destruction" in risk.signals and "irreversible" in risk.signals


def test_score_clamps_at_one():
    risk = classify_goal(
        "Wire the payment, delete the production database, rotate every "
        "secret, send a mass email with legal advice and export user data "
        "permanently",
    )
    assert risk.score == 1.0 and risk.tier == "high"


def test_signal_fires_once_no_stacking():
    once = classify_goal("Delete the index")
    thrice = classify_goal("Delete, drop and truncate the index")
    assert once.score == thrice.score == 0.45
    assert once.tier == thrice.tier == "medium"


# --- determinism ------------------------------------------------------------

def test_same_input_same_output():
    a = classify_goal("Deploy the billing service", "and refund the overcharge")
    b = classify_goal("Deploy the billing service", "and refund the overcharge")
    assert a == b


# --- config floor -----------------------------------------------------------

def test_floor_defaults_to_low():
    assert config_floor() == "low"


def test_floor_from_config(monkeypatch, tmp_path):
    _config(monkeypatch, tmp_path, '[safety]\ngoal_risk_floor = "medium"\n')
    assert config_floor() == "medium"


def test_floor_env_wins_over_config(monkeypatch, tmp_path):
    _config(monkeypatch, tmp_path, '[safety]\ngoal_risk_floor = "medium"\n')
    monkeypatch.setenv("MAVERICK_GOAL_RISK_FLOOR", "high")
    assert config_floor() == "high"


def test_floor_bogus_value_is_noop(monkeypatch, tmp_path):
    _config(monkeypatch, tmp_path, '[safety]\ngoal_risk_floor = "extreme"\n')
    assert config_floor() == "low"


def test_floor_maxes_with_classified_tier():
    # The documented caller pattern: max(classified, floor) by risk_rank.
    classified = classify_goal("Summarize the meeting").tier
    floor = "medium"
    effective = max(classified, floor, key=risk_rank)
    assert effective == "medium"


# --- require-human knob -----------------------------------------------------

def test_require_human_is_off_until_an_administrator_turns_it_on():
    # Unset means no goal waits for a person, whatever its tier.
    assert require_human_for("high") is False
    assert require_human_for("medium") is False
    assert require_human_for("low") is False


def test_require_human_high_knob(monkeypatch, tmp_path):
    _config(monkeypatch, tmp_path,
            '[safety]\ngoal_risk_require_human = "high"\n')
    assert require_human_for("high") is True
    assert require_human_for("medium") is False
    assert require_human_for("low") is False


def test_start_check_applies_the_floor_and_the_knob(monkeypatch, tmp_path):
    from maverick.safety.goal_risk import plain_reasons, start_check
    classified, effective, needs = start_check("Deploy the new pricing page to production")
    assert (classified.tier, effective, needs) == ("high", "high", False)
    assert plain_reasons(classified.signals) == "deletes or deploys, wide or permanent reach"
    _config(monkeypatch, tmp_path,
            '[safety]\ngoal_risk_floor = "medium"\ngoal_risk_require_human = "medium"\n')
    classified, effective, needs = start_check("Summarize the meeting")
    assert (classified.tier, effective, needs) == ("low", "medium", True)


def test_require_human_medium_knob(monkeypatch, tmp_path):
    _config(monkeypatch, tmp_path,
            '[safety]\ngoal_risk_require_human = "medium"\n')
    assert require_human_for("high") is True
    assert require_human_for("medium") is True
    assert require_human_for("low") is False


def test_require_human_never_knob(monkeypatch, tmp_path):
    _config(monkeypatch, tmp_path,
            '[safety]\ngoal_risk_require_human = "never"\n')
    assert require_human_for("high") is False


def test_require_human_env_wins(monkeypatch, tmp_path):
    _config(monkeypatch, tmp_path,
            '[safety]\ngoal_risk_require_human = "never"\n')
    monkeypatch.setenv("MAVERICK_GOAL_RISK_REQUIRE_HUMAN", "medium")
    assert require_human_for("medium") is True


def test_require_human_bogus_knob_falls_back_to_high(monkeypatch, tmp_path):
    _config(monkeypatch, tmp_path,
            '[safety]\ngoal_risk_require_human = "whenever"\n')
    assert require_human_for("high") is True
    assert require_human_for("medium") is False
