"""reliability_harness: reliability harness 2.0 reporting."""
from __future__ import annotations

from maverick.tools.reliability_harness import reliability_harness


def _report(runs):
    return reliability_harness().fn({"op": "report", "runs": runs})


def test_stable_pass():
    out = _report([{"name": "t1", "outcomes": [True, True, True]}])
    assert "t1: STABLE-PASS" in out and "pass_rate=100.0%" in out


def test_always_fail():
    out = _report([{"name": "t2", "outcomes": [False, False]}])
    assert "t2: ALWAYS-FAIL" in out and "pass_rate=0.0%" in out


def test_flaky_mixed():
    out = _report([{"name": "t3", "outcomes": [True, False, True, False]}])
    assert "t3: FLAKY" in out and "pass_rate=50.0%" in out


def test_overall_reliability_across_tests():
    out = _report([
        {"name": "a", "outcomes": [True, True]},
        {"name": "b", "outcomes": [False, False]},
    ])
    # 2 of 4 outcomes passed overall; neither test is flaky.
    assert out.startswith("RELIABILITY overall=50.0%")
    assert "0 flaky" in out


def test_flaky_count_in_header():
    out = _report([
        {"name": "a", "outcomes": [True, True]},
        {"name": "b", "outcomes": [True, False]},
    ])
    assert "1 flaky" in out


def test_errors():
    t = reliability_harness()
    assert t.fn({"op": "report"}).startswith("ERROR")  # no runs
    assert t.fn({"op": "nope", "runs": []}).startswith("ERROR")
    assert t.fn({"op": "report", "runs": [{"name": "a", "outcomes": []}]}).startswith("ERROR")
    assert t.fn(
        {"op": "report", "runs": [{"name": "a", "outcomes": [True, "x"]}]}
    ).startswith("ERROR")
