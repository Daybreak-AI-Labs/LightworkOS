"""latency_slo: tail-latency SLO calculator."""
from __future__ import annotations

from maverick.tools.latency_slo import latency_slo


def _report(**kw):
    return latency_slo().fn({"op": "report", **kw})


_TEN = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]


def test_percentiles_nearest_rank():
    out = _report(samples=_TEN, target={"p": 99, "threshold_ms": 1000})
    assert "p50=50ms" in out
    assert "p90=90ms" in out
    assert "p95=100ms" in out
    assert "p99=100ms" in out
    assert "p999=100ms" in out
    assert "mean=55.00ms" in out


def test_pass_when_under_threshold():
    out = _report(samples=_TEN, target={"p": 90, "threshold_ms": 90})
    assert out.startswith("PASS")
    assert "p90=90ms vs threshold 90ms" in out  # boundary is inclusive PASS


def test_fail_when_over_threshold():
    out = _report(samples=_TEN, target={"p": 99, "threshold_ms": 95})
    assert out.startswith("FAIL")
    assert "p99=100ms vs threshold 95ms" in out


def test_unsorted_input_and_single_sample():
    out = _report(samples=[100, 10, 50], target={"p": 50, "threshold_ms": 60})
    assert out.startswith("PASS")  # p50 nearest-rank of [10,50,100] = 50
    one = _report(samples=[42], target={"p": 999 / 10, "threshold_ms": 42})
    assert one.startswith("PASS") and "p999=42ms" in one


def test_p999_label_and_gate():
    out = _report(samples=_TEN, target={"p": 99.9, "threshold_ms": 50})
    assert out.startswith("FAIL")
    assert "p999=100ms vs threshold 50ms" in out


def test_errors():
    t = latency_slo()
    assert t.fn({"op": "report", "target": {"p": 99, "threshold_ms": 1}}).startswith("ERROR")  # no samples
    assert t.fn({"op": "report", "samples": [1, 2]}).startswith("ERROR")  # no target
    assert _report(samples=[1, 2], target={"p": 0, "threshold_ms": 1}).startswith("ERROR")
    assert _report(samples=["a", "b"], target={"p": 50, "threshold_ms": 1}).startswith("ERROR")
    assert t.fn({"op": "nope", "samples": [1], "target": {"p": 50, "threshold_ms": 1}}).startswith("ERROR")
