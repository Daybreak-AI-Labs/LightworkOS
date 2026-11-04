"""Operator CLI for governed specialist-model planning and scoring."""
from __future__ import annotations

import json

from click.testing import CliRunner
from maverick.cli import main
from maverick.training import environments as env


def test_status_discloses_seed_and_candidate_limits():
    result = CliRunner().invoke(main, ["model-improvement", "status"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["config"]["enable"] is False
    assert payload["catalog"]["candidates"] == 13
    assert payload["catalog"]["claim"].startswith("planning candidates")
    assert all(not row["ready"] for row in payload["environments"])


def test_status_applies_configured_family_floors(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "get_model_improvement", lambda: {
        "enable": False,
        "allow_hosted": False,
        "allow_cross_tenant": False,
        "require_signed_receipt": True,
        "minimum_train_families": 21,
        "minimum_holdout_families": 22,
    })

    result = CliRunner().invoke(main, ["model-improvement", "status"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    reasons = " ".join(
        reason
        for environment in payload["environments"]
        for reason in environment["reasons"]
    )
    assert "need 21 independent train families" in reasons
    assert "need 22 independent holdout families" in reasons


def test_models_returns_planning_estimates_not_a_selection():
    result = CliRunner().invoke(main, [
        "model-improvement",
        "models",
        "--role",
        "reviewer",
        "--memory-gib",
        "24",
    ])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["planning_only"] is True
    assert payload["candidates"]
    assert all("estimate" in row for row in payload["candidates"])


def test_score_uses_the_same_deterministic_environment_contract(tmp_path):
    pack = env.load_environment("dsar_routing_v1")
    outputs = {
        case.case_id: env.expected_output(case)
        for case in pack.split("holdout")
    }
    path = tmp_path / "outputs.json"
    path.write_text(json.dumps(outputs), encoding="utf-8")

    result = CliRunner().invoke(main, [
        "model-improvement",
        "score",
        "dsar_routing_v1",
        str(path),
        "--require-perfect",
    ])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["pass_rate"] == 1.0
    assert len(payload["evaluation_sha256"]) == 64


def test_score_can_fail_a_ci_gate(tmp_path):
    path = tmp_path / "outputs.json"
    path.write_text("{}", encoding="utf-8")

    result = CliRunner().invoke(main, [
        "model-improvement",
        "score",
        "privacy_assessment_v1",
        str(path),
        "--require-perfect",
    ])

    assert result.exit_code != 0
    assert "did not pass perfectly" in result.output


def test_score_refuses_duplicate_case_ids(tmp_path):
    path = tmp_path / "outputs.json"
    path.write_text('{"same": {}, "same": {}}', encoding="utf-8")

    result = CliRunner().invoke(main, [
        "model-improvement",
        "score",
        "privacy_assessment_v1",
        str(path),
    ])

    assert result.exit_code != 0
    assert "duplicate JSON field" in result.output
