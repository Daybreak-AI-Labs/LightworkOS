"""memleak_quarantine: RSS leak detection via least-squares slope + R^2."""
from __future__ import annotations

from maverick.tools.memleak_quarantine import memleak_quarantine


def _scan(**kw):
    return memleak_quarantine().fn({"op": "scan", **kw})


def _series(values, start=0):
    return [{"t": start + i, "rss_mb": v} for i, v in enumerate(values)]


def test_monotonic_growth_quarantined():
    out = _scan(components=[{"name": "leaky", "series": _series([10, 12, 14, 16])}])
    assert out.startswith("LEAK")
    assert "leaky: QUARANTINE slope=2.0000MB/sample r2=1.0000" in out
    assert "quarantined: [leaky]" in out


def test_flat_series_ok():
    out = _scan(components=[{"name": "steady", "series": _series([100, 100, 100, 100])}])
    assert out.startswith("CLEAN")
    assert "steady: OK slope=0.0000MB/sample" in out
    assert "quarantined: [(none)]" in out


def test_positive_slope_but_noisy_is_ok():
    # rising-then-falling jitter: slope>0 but R^2 well below 0.8 -> not a leak.
    out = _scan(components=[{"name": "jitter", "series": _series([10, 30, 12, 28])}])
    assert "jitter: OK" in out
    assert out.startswith("CLEAN")


def test_mixed_components():
    out = _scan(components=[
        {"name": "good", "series": _series([50, 49, 51, 50])},
        {"name": "bad", "series": _series([20, 40, 60, 80])},
    ])
    assert out.startswith("LEAK")
    assert "quarantine=1/2" in out
    assert "bad: QUARANTINE" in out
    assert "good: OK" in out
    assert "quarantined: [bad]" in out


def test_thresholds_tunable():
    series = _series([10, 12, 14, 16])  # slope 2.0, r2 1.0
    # raise min_slope above the actual slope -> no longer flagged
    out = _scan(components=[{"name": "c", "series": series}], min_slope=5)
    assert "c: OK" in out and out.startswith("CLEAN")


def test_errors():
    t = memleak_quarantine()
    assert t.fn({"op": "scan"}).startswith("ERROR")  # no components
    assert t.fn({"op": "scan", "components": []}).startswith("ERROR")
    assert _scan(components=[{"series": _series([1, 2])}]).startswith("ERROR")  # no name
    assert _scan(components=[{"name": "c", "series": [{"t": 0, "rss_mb": 1}]}]).startswith("ERROR")  # <2 pts
    assert _scan(components=[{"name": "c", "series": [{"t": 0}, {"t": 1}]}]).startswith("ERROR")  # no rss
    assert _scan(components=[{"name": "c", "series": _series([1, 2])}], min_r2=2).startswith("ERROR")
    assert t.fn({"op": "nope", "components": []}).startswith("ERROR")
