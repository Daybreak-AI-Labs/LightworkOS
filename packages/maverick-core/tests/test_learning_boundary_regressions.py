from __future__ import annotations

import json

import pytest
from maverick.intent_value.opportunities import _forecast
from maverick.skill.distillation_local import distill, to_skill_markdown
from maverick.training import rlaif


def test_distilled_goals_redact_secrets_before_deriving_skill():
    token = "ghp_" + "a" * 36
    skill = distill([{"goal": f"Review repository using {token}", "success": True}])
    assert skill is not None
    assert token not in json.dumps(skill)
    assert token not in to_skill_markdown(skill)
    assert "Review repository" in skill["summary"]


def test_requested_reward_model_failure_refuses_training_but_empty_pairs_succeed(
    monkeypatch, tmp_path, capsys,
):
    monkeypatch.setattr(rlaif, "load_klear", lambda path: [])
    monkeypatch.setattr(rlaif, "build_preference_pairs", lambda *a, **kw: [{"weight": 1}])
    trained = []
    monkeypatch.setattr(rlaif, "train", lambda *a, **kw: trained.append(True) or 0)
    args = ["--data", str(tmp_path / "data"), "--base-model", "unused",
            "--out", str(tmp_path / "out"), "--reward-model", str(tmp_path / "missing")]
    assert rlaif.main(args) == 1
    assert trained == []
    assert "reward model load failed" in capsys.readouterr().err
    monkeypatch.setattr(rlaif, "build_preference_pairs", lambda *a, **kw: [])
    assert rlaif.main(args) == 0
    assert trained == []


@pytest.mark.parametrize("missing_cost", [[], [{"amount": 2, "currency": "EUR"}],
                                         [{"amount": None, "currency": "USD"}]])
def test_incomplete_execution_costs_have_costed_count_and_no_net(missing_cost):
    def row(costs):
        return {"source": {"costs": costs}, "estimates": [{"avoided_minutes": 30,
                "assumptions": {"currency": "USD", "hourly_rate": 60}}]}

    costed = row([{"amount": 1, "currency": "USD"}])
    uncosted = row(missing_cost)
    forecast = _forecast([costed, uncosted, {}], [costed, uncosted])
    assert forecast["sample_count"] == 1
    assert forecast["execution_cost_per_run"] == 1
    assert forecast["incremental_net_per_run"] is None
