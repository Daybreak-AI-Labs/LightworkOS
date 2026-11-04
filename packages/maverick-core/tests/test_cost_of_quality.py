"""cost_of_quality: cost-of-quality study helper."""
from __future__ import annotations

from maverick.tools.cost_of_quality import cost_of_quality


def _analyze(runs):
    return cost_of_quality().fn({"op": "analyze", "runs": runs})


def test_basic_split():
    runs = [
        {"cost": 1.0, "passed": True},
        {"cost": 2.0, "passed": True},
        {"cost": 3.0, "passed": False},
    ]
    out = _analyze(runs)
    assert out.startswith("OK")
    assert "passed=2 failed=1" in out
    assert "total_spend=$6.0000" in out
    assert "passing_spend=$3.0000" in out
    assert "failing_spend=$3.0000" in out
    assert "cost_per_success=$3.0000" in out  # 6 total / 2 successes
    assert "wasted_spend_ratio=0.5000" in out  # 3 failing / 6 total


def test_retries_summed():
    runs = [
        {"cost": 1.0, "passed": True, "retries": 2},
        {"cost": 1.0, "passed": False, "retries": 3},
    ]
    out = _analyze(runs)
    assert "retries=5" in out


def test_all_passing_zero_waste():
    out = _analyze([{"cost": 5.0, "passed": True}, {"cost": 5.0, "passed": True}])
    assert "wasted_spend_ratio=0.0000" in out
    assert "cost_per_success=$5.0000" in out


def test_no_successes_reports_na():
    out = _analyze([{"cost": 4.0, "passed": False}])
    assert "cost_per_success=n/a (no successes)" in out
    assert "wasted_spend_ratio=1.0000" in out


def test_default_op_is_analyze():
    out = cost_of_quality().fn({"runs": [{"cost": 1.0, "passed": True}]})
    assert out.startswith("OK")


def test_errors():
    t = cost_of_quality()
    assert t.fn({"op": "analyze", "runs": []}).startswith("ERROR")  # empty
    assert _analyze([{"cost": 1.0}]).startswith("ERROR")  # missing passed
    assert _analyze([{"passed": True, "cost": "free"}]).startswith("ERROR")  # bad cost
    assert _analyze([{"cost": 1.0, "passed": "yes"}]).startswith("ERROR")  # non-bool passed
    assert t.fn({"op": "nope", "runs": [{"cost": 1.0, "passed": True}]}).startswith("ERROR")


def test_retries_infinity_does_not_crash():
    out = _analyze([{"cost": 1, "passed": True, "retries": float("inf")}])
    assert out.startswith("ERROR")
