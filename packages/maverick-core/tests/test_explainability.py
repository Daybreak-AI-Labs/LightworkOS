"""Model-agnostic explainability: deterministic, bounded, governed.

What matters: Spearman handles ties and monotone relationships exactly,
permutation importance is reproducible for a seed and ranks the truly
predictive feature first, partial dependence recovers a linear effect,
reason codes rank the largest standardized deviation first, and every
surface fails closed when the knob is off.
"""
from __future__ import annotations

import hashlib
import time

import pytest
from maverick import config
from maverick import explainability as xai


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(
        "[explainability]\nenable = true\n", encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def test_disabled_fails_closed(tmp_path):
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert xai.enabled() is False
    with pytest.raises(xai.ExplainabilityConfigError, match="enable"):
        xai.global_sensitivity({"a": [1, 2, 3]}, [1, 2, 3])


def test_spearman_known_values():
    assert xai.spearman_correlation([1, 2, 3, 4], [10, 20, 30, 40]) == 1.0
    assert xai.spearman_correlation([1, 2, 3, 4], [40, 30, 20, 10]) == -1.0
    # A monotone but non-linear relationship is still a perfect rank match.
    assert xai.spearman_correlation([1, 2, 3, 4], [1, 8, 27, 64]) == 1.0
    # A constant series carries no rank information.
    assert xai.spearman_correlation([1, 2, 3, 4], [5, 5, 5, 5]) == 0.0


def test_global_sensitivity_ranks_the_predictive_feature_first():
    signal = [float(index) for index in range(50)]
    noise = [float((index * 37) % 11) for index in range(50)]
    scores = [2.0 * value + 1.0 for value in signal]
    report = xai.global_sensitivity({"signal": signal, "noise": noise}, scores)
    assert report["features"][0]["feature"] == "signal"
    assert report["features"][0]["spearman"] == 1.0
    assert report["features"][0]["rank"] == 1
    with pytest.raises(ValueError, match="align"):
        xai.global_sensitivity({"signal": signal}, scores[:-1])


def test_permutation_importance_is_seeded_and_ranks_correctly():
    rows = 60
    heavy = [float(index % 7) for index in range(rows)]
    light = [float((index * 13) % 5) for index in range(rows)]

    def predict(features):
        return [
            10.0 * a + 0.1 * b
            for a, b in zip(features["heavy"], features["light"], strict=True)
        ]

    first = xai.permutation_importance(
        predict, {"heavy": heavy, "light": light}, seed=7,
    )
    second = xai.permutation_importance(
        predict, {"heavy": heavy, "light": light}, seed=7,
    )
    assert first == second
    assert first["features"][0]["feature"] == "heavy"
    assert first["features"][0]["importance"] > first["features"][1]["importance"]
    assert first["method"] == "permutation_score_change"

    labelled = xai.permutation_importance(
        predict,
        {"heavy": heavy, "light": light},
        labels=[round(10.0 * a + 0.1 * b) for a, b in zip(heavy, light, strict=True)],
        seed=7,
    )
    assert labelled["method"] == "permutation_accuracy_drop"
    assert labelled["baseline_accuracy"] == 1.0
    assert labelled["features"][0]["feature"] == "heavy"


def test_partial_dependence_recovers_a_linear_effect():
    rows = 30
    x = [float(index) for index in range(rows)]
    other = [1.0] * rows

    def predict(features):
        return [3.0 * a + b for a, b in zip(features["x"], features["other"], strict=True)]

    report = xai.partial_dependence(
        predict, {"x": x, "other": other}, "x", grid=[0.0, 1.0, 2.0],
    )
    averages = [point["average_score"] for point in report["curve"]]
    assert averages == [1.0, 4.0, 7.0]
    with pytest.raises(ValueError, match="no data"):
        xai.partial_dependence(predict, {"x": x, "other": other}, "missing")


def test_reason_codes_rank_the_largest_deviation():
    features = {
        "income": [50.0 + (index % 5) for index in range(40)],
        "utilization": [0.3 + 0.01 * (index % 7) for index in range(40)],
    }
    report = xai.reason_codes(
        features, {"income": 52.0, "utilization": 0.95}, top_k=2,
    )
    assert report["reasons"][0]["feature"] == "utilization"
    assert report["reasons"][0]["direction"] == "above"
    assert "standard deviations" in report["reasons"][0]["statement"]
    with pytest.raises(ValueError, match="no reference"):
        xai.reason_codes(features, {"unknown": 1.0})


def test_reports_record_as_governed_evidence(tmp_path):
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\nenable = true\n\n"
        "[model_risk_assurance]\nenable = true\ngate_promotions = false\n\n"
        "[explainability]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    from maverick import model_risk_assurance as mra

    officer = mra.ModelRiskAssuranceOfficer()
    observation = officer.observe_asset(
        asset_type="model",
        source="xai_test",
        source_id="credit-scorer",
        display_name="Credit scorer",
        version_digest=hashlib.sha256(b"credit-v1").hexdigest(),
        actor="inventory-operator",
        observed_at=time.time(),
        metadata={},
        dependencies=[],
    )
    report = xai.global_sensitivity(
        {"income": [1.0, 2.0, 3.0, 4.0]}, [2.0, 4.0, 6.0, 8.0],
    )
    evidence = xai.record_explainability_evidence(
        observation["asset_id"], report,
        source_id="quarterly", actor="model-validator",
    )
    assert evidence["evidence_kind"] == "explainability"
    assert evidence["metrics"]["method"] == "spearman_global_sensitivity"
    with pytest.raises(ValueError, match="explainability report"):
        xai.record_explainability_evidence(
            observation["asset_id"], {"schema": "wrong"},
            source_id="quarterly", actor="model-validator",
        )


def test_fairness_reports_record_as_honest_evidence(tmp_path):
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\nenable = true\n\n"
        "[model_risk_assurance]\nenable = true\ngate_promotions = false\n\n"
        "[explainability]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    from maverick import fairness_monitor
    from maverick import model_risk_assurance as mra

    officer = mra.ModelRiskAssuranceOfficer()
    observation = officer.observe_asset(
        asset_type="model",
        source="xai_test",
        source_id="screener",
        display_name="Screening model",
        version_digest=hashlib.sha256(b"screener-v1").hexdigest(),
        actor="inventory-operator",
        observed_at=time.time(),
        metadata={},
        dependencies=[],
    )
    failing = fairness_monitor.metrics_report({
        "group_a": {"selected": 8, "total": 10},
        "group_b": {"selected": 4, "total": 10},
    })
    evidence = xai.record_fairness_evidence(
        observation["asset_id"], failing,
        source_id="q3", actor="model-validator",
    )
    # A failing report records as FAILED evidence -- never suppressed.
    assert evidence["evidence_kind"] == "fairness"
    assert evidence["result"] == "failed"
    assert evidence["metrics"]["min_impact_ratio"] == 0.5

    passing = fairness_monitor.metrics_report({
        "group_a": {"selected": 8, "total": 10},
        "group_b": {"selected": 7, "total": 10},
    })
    evidence = xai.record_fairness_evidence(
        observation["asset_id"], passing,
        source_id="q4", actor="model-validator",
    )
    assert evidence["result"] == "passed"
    with pytest.raises(ValueError, match="fairness metrics report"):
        xai.record_fairness_evidence(
            observation["asset_id"], {"schema": "wrong"},
            source_id="q5", actor="model-validator",
        )


def test_fairness_evidence_rejects_a_non_numeric_impact_ratio(tmp_path):
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\nenable = true\n\n"
        "[model_risk_assurance]\nenable = true\ngate_promotions = false\n\n"
        "[explainability]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    from maverick import fairness_monitor
    from maverick import model_risk_assurance as mra

    officer = mra.ModelRiskAssuranceOfficer()
    observation = officer.observe_asset(
        asset_type="model", source="xai_test", source_id="screener",
        display_name="Screening model",
        version_digest=hashlib.sha256(b"screener-v1").hexdigest(),
        actor="inventory-operator", observed_at=time.time(),
        metadata={}, dependencies=[],
    )
    report = dict(fairness_monitor.metrics_report({
        "group_a": {"selected": 8, "total": 10},
        "group_b": {"selected": 4, "total": 10},
    }))
    report["min_impact_ratio"] = None
    # A doctored/None ratio must be a clean ValueError, never a
    # TypeError from the summary's :.3f formatting.
    with pytest.raises(ValueError, match="min_impact_ratio"):
        xai.record_fairness_evidence(
            observation["asset_id"], report,
            source_id="q6", actor="model-validator",
        )
