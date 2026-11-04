"""sla_breach: SLO-breach detection + escalation action."""
from __future__ import annotations

from maverick.tools.sla_breach import sla_breach


def _check(**kw):
    return sla_breach().fn({"op": "check", **kw})


def _ms(values, start=1):
    return [{"t": start + i, "value": v} for i, v in enumerate(values)]


_LT = {"metric": "latency_ms", "threshold": 100, "window": 4, "comparator": "lt"}


def test_ok_when_within_slo():
    out = _check(slo=_LT, measurements=_ms([10, 20, 30, 40]))
    assert out.startswith("OK")
    assert "breaching=0/4" in out


def test_minor_breach_throttles():
    out = _check(slo=_LT, measurements=_ms([10, 20, 30, 150]))
    assert out.startswith("BREACH")
    assert "severity=minor action=throttle" in out
    assert "breaching=1/4" in out


def test_major_breach_pages():
    out = _check(slo=_LT, measurements=_ms([10, 20, 150, 200]))
    assert out.startswith("BREACH")
    assert "severity=major action=page" in out
    assert "breaching=2/4" in out


def test_critical_breach_failovers():
    out = _check(slo=_LT, measurements=_ms([150, 160, 170, 180]))
    assert out.startswith("BREACH")
    assert "severity=critical action=failover" in out
    assert "breaching=4/4" in out


def test_gt_comparator_and_window_tail():
    # uptime SLO: healthy value > threshold; window evaluates the recent tail.
    slo = {"metric": "uptime", "threshold": 99.9, "window": 3, "comparator": "gt"}
    out = _check(slo=slo, measurements=_ms([50.0, 99.95, 99.99, 99.0]))
    # window=3 -> last three [99.95, 99.99, 99.0]; only 99.0 <= 99.9 breaches
    # -> 1/3 (< 50%) minor. The dropped first sample (50.0) would have breached.
    assert out.startswith("BREACH")
    assert "breaching=1/3" in out
    assert "severity=minor action=throttle" in out


def test_errors():
    t = sla_breach()
    assert t.fn({"op": "check", "measurements": _ms([1])}).startswith("ERROR")  # no slo
    assert t.fn({"op": "check", "slo": _LT}).startswith("ERROR")  # no measurements
    assert _check(slo={"metric": "m", "threshold": 1, "window": 1, "comparator": "eq"},
                  measurements=_ms([1])).startswith("ERROR")  # bad comparator
    assert _check(slo={"metric": "m", "threshold": 1, "window": 0, "comparator": "lt"},
                  measurements=_ms([1])).startswith("ERROR")  # window <= 0
    assert _check(slo={"metric": "m", "comparator": "lt", "window": 1},
                  measurements=_ms([1])).startswith("ERROR")  # no threshold
    assert t.fn({"op": "nope", "slo": _LT, "measurements": _ms([1])}).startswith("ERROR")


def test_non_finite_window_does_not_crash():
    # Regression: int(slo["window"]) raised OverflowError on a non-finite,
    # model-supplied window.
    t = sla_breach()
    for bad in (float("inf"), float("-inf")):
        out = t.fn({"op": "check",
                    "slo": {"metric": "m", "threshold": 1, "window": bad, "comparator": "lt"},
                    "measurements": [{"t": 1, "value": 1}]})
        assert out.startswith("ERROR")
