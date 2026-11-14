"""Cost/perf release canary: direction-aware comparison, store, CLI."""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick import release_canary as rc
from maverick.cli import main
from maverick.file_lock import private_path_is_restricted

# ---- compare (pure, direction-aware) ----

def test_cost_increase_beyond_tolerance_regresses():
    res = rc.compare({"cost_usd": 1.0}, {"cost_usd": 1.5}, tolerance=0.1)
    assert not res.passed
    assert res.verdicts[0].verdict == "regressed"


def test_cost_decrease_improves():
    res = rc.compare({"cost_usd": 1.0}, {"cost_usd": 0.8}, tolerance=0.1)
    assert res.passed
    assert res.verdicts[0].verdict == "improved"


def test_within_tolerance_is_ok():
    res = rc.compare({"p95_latency_s": 3.0}, {"p95_latency_s": 3.2}, tolerance=0.1)
    assert res.passed and res.verdicts[0].verdict == "ok"


def test_success_rate_drop_regresses_higher_is_better():
    res = rc.compare({"success_rate": 0.95}, {"success_rate": 0.80}, tolerance=0.1)
    assert not res.passed
    assert res.verdicts[0].verdict == "regressed"


def test_success_rate_rise_improves():
    res = rc.compare({"success_rate": 0.80}, {"success_rate": 0.95}, tolerance=0.05)
    assert res.passed and res.verdicts[0].verdict == "improved"


def test_new_metric_is_informational_not_regression():
    res = rc.compare({}, {"new_metric": 5.0})
    assert res.passed and res.verdicts[0].verdict == "new"


def test_zero_baseline_negative_candidate_signs_the_sentinel():
    # Zero baseline with a negative candidate is a downward move; for a
    # lower-is-better metric that's an improvement, not a regression (an
    # unsigned +inf sentinel would flag it 'regressed').
    res = rc.compare({"net_margin": 0.0}, {"net_margin": -5.0}, tolerance=0.1)
    assert res.verdicts[0].verdict == "improved"
    # Symmetrically, a higher-is-better metric moving 0 -> negative regresses.
    res2 = rc.compare({"success_rate": 0.0}, {"success_rate": -5.0}, tolerance=0.1)
    assert res2.verdicts[0].verdict == "regressed"


def test_non_numeric_metrics_skipped():
    res = rc.compare({"cost_usd": 1.0}, {"cost_usd": 1.0, "note": "x"})
    assert [v.metric for v in res.verdicts] == ["cost_usd"]


def test_dropped_or_non_finite_metric_fails_the_gate(tmp_path):
    # A candidate that omits a baseline metric or records NaN used to pass.
    res = rc.compare({"cost_per_task": 1.0, "success_rate": 0.9},
                     {"cost_per_task": float("nan")})
    assert not res.passed
    assert {v.metric: v.verdict for v in res.verdicts} == {
        "cost_per_task": "invalid", "success_rate": "missing"}
    with pytest.raises(ValueError):
        rc.CanaryStore(tmp_path / "c.json").record("v1", {"cost_per_task": float("inf")})


def test_multiple_metrics_any_regression_fails():
    res = rc.compare(
        {"cost_usd": 1.0, "success_rate": 0.9},
        {"cost_usd": 0.8, "success_rate": 0.5},  # cost improved, success regressed
        tolerance=0.1)
    assert not res.passed
    assert {v.metric: v.verdict for v in res.verdicts} == {
        "cost_usd": "improved", "success_rate": "regressed"}


# ---- store ----

def test_store_roundtrip(tmp_path):
    store = rc.CanaryStore(tmp_path / "canary.json")
    store.record("v1", {"cost_usd": 1.2, "skip": "x"})  # non-numeric dropped
    assert store.get("v1") == {"cost_usd": 1.2}
    store.record("v2", {"cost_usd": 1.4})
    assert store.releases() == ["v1", "v2"]
    assert store.get("absent") is None
    assert private_path_is_restricted(tmp_path / "canary.json", 0o600)


# ---- CLI ----

def test_cli_record_then_compare_regression(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    r = CliRunner()
    assert r.invoke(main, ["canary", "record", "v1", "--metric", "cost_usd=1.0"]).exit_code == 0
    assert r.invoke(main, ["canary", "record", "v2", "--metric", "cost_usd=1.5"]).exit_code == 0
    res = r.invoke(main, ["canary", "compare", "v1", "v2"])
    assert res.exit_code == 1            # regression -> non-zero gate
    assert "FAIL" in res.output and "regressed" in res.output


def test_cli_compare_pass(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    r = CliRunner()
    r.invoke(main, ["canary", "record", "a", "--metric", "cost_usd=1.0"])
    r.invoke(main, ["canary", "record", "b", "--metric", "cost_usd=1.02"])
    res = r.invoke(main, ["canary", "compare", "a", "b"])
    assert res.exit_code == 0 and "PASS" in res.output


def test_cli_compare_missing_baseline(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    res = CliRunner().invoke(main, ["canary", "compare", "nope", "nope2"])
    assert res.exit_code != 0
    assert "no recorded metrics for baseline" in res.output


def test_cli_record_bad_metric(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    res = CliRunner().invoke(main, ["canary", "record", "v", "--metric", "oops"])
    assert res.exit_code != 0 and "name=value" in res.output
