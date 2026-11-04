"""safety_regression_budget: safety regression budget gate."""
from __future__ import annotations

from maverick.tools.safety_regression_budget import safety_regression_budget


def _run(**kw):
    return safety_regression_budget().fn({"op": "check", **kw})


def test_single_pass_within_budget():
    out = _run(baseline=0.90, candidate=0.88, allowed_regression=0.05)
    assert out.startswith("PASS")
    assert "remaining 0.03" in out


def test_single_fail_over_budget():
    out = _run(baseline=0.90, candidate=0.80, allowed_regression=0.05)
    assert out.startswith("FAIL")
    assert "remaining -0.05" in out


def test_improvement_keeps_full_budget():
    out = _run(baseline=0.80, candidate=0.90, allowed_regression=0.05)
    assert out.startswith("PASS")
    # Regression negative; remaining budget is the full budget.
    assert "remaining 0.05" in out


def test_multi_metric_one_fail_overall_fail():
    out = _run(metrics=[
        {"name": "jailbreak", "baseline": 0.9, "candidate": 0.89, "budget": 0.05},
        {"name": "toxicity", "baseline": 0.95, "candidate": 0.80, "budget": 0.05},
    ])
    assert out.startswith("FAIL")
    assert "1/2 metric(s) within budget" in out
    assert "jailbreak: PASS" in out
    assert "toxicity: FAIL" in out


def test_multi_metric_all_pass():
    out = _run(metrics=[
        {"name": "a", "baseline": 0.9, "candidate": 0.9, "budget": 0.01},
        {"name": "b", "baseline": 0.8, "candidate": 0.79, "budget": 0.02},
    ])
    assert out.startswith("PASS")
    assert "2/2 metric(s) within budget" in out


def test_errors_and_unknown_op():
    t = safety_regression_budget()
    assert t.fn({"op": "check", "candidate": 0.8, "allowed_regression": 0.1}).startswith("ERROR")
    assert t.fn({"op": "check", "baseline": 0.9, "candidate": 0.8}).startswith("ERROR")
    assert t.fn({"op": "check", "metrics": []}).startswith("ERROR")
    assert t.fn({"op": "check", "metrics": [{"name": "x", "baseline": 1}]}).startswith("ERROR")
    assert t.fn({"op": "nope", "baseline": 1, "candidate": 1, "allowed_regression": 0}).startswith("ERROR")


def test_factory_identity():
    t = safety_regression_budget()
    assert t.name == "safety_regression_budget"
    assert t.parallel_safe is True
