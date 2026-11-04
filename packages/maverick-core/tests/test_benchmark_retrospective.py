"""Longitudinal benchmark retrospective: era slicing, trends, coverage."""
from __future__ import annotations

from datetime import datetime, timezone

from maverick.benchmark_retrospective import analyze, coverage, render


def _t(year, month):
    return datetime(year, month, 15, tzinfo=timezone.utc).timestamp()


def _row(name, score, year, month):
    return {"name": name, "score": score, "commit": "c", "t": _t(year, month)}


def _improving_history():
    rows = []
    for i, (y, m) in enumerate([(2026, 1), (2026, 4), (2026, 7), (2026, 10),
                                (2027, 1), (2027, 4)]):
        for _ in range(3):
            rows.append(_row("gaia", 0.50 + 0.05 * i, y, m))
    return rows


def test_era_slicing_and_medians():
    retros = analyze(_improving_history())
    r = retros["gaia"]
    assert r.eras[0] == "2026-Q1" and r.eras[-1] == "2027-Q2"
    assert r.era_median["2026-Q1"] == 0.50
    assert r.era_median["2027-Q2"] == 0.75
    assert r.runs == 18


def test_improving_trend_and_net_change():
    r = analyze(_improving_history())["gaia"]
    assert r.trend == "improving"
    assert r.net_change > 0.4
    assert r.best_era == "2027-Q2" and r.worst_era == "2026-Q1"


def test_declining_trend():
    rows = [_row("swe", 0.9 - 0.1 * i, 2026, 1 + 3 * i) for i in range(4)
            for _ in range(2)]
    r = analyze(rows)["swe"]
    assert r.trend == "declining"
    assert r.net_change < 0


def test_flat_trend():
    rows = [_row("tau2", 0.70, 2026, m) for m in (1, 4, 7, 10) for _ in range(2)]
    r = analyze(rows)["tau2"]
    assert r.trend == "flat" and r.net_change == 0.0


def test_single_era_insufficient():
    r = analyze([_row("x", 0.5, 2026, 1)])["x"]
    assert r.trend == "insufficient data"
    assert r.net_change == 0.0


def test_malformed_rows_skipped():
    rows = [{"name": "x"}, {"score": 1.0}, {"name": "x", "score": "NaNish"},
            _row("x", 0.5, 2026, 1)]
    retros = analyze(rows)
    assert retros["x"].runs == 1


def test_coverage_span():
    assert coverage([]) is None
    span = coverage(_improving_history())
    assert span == ("2026-Q1", "2027-Q2")


def test_render_report():
    out = render(_improving_history())
    assert "coverage 2026-Q1 → 2027-Q2" in out
    assert "gaia: improving" in out
    assert "2026-Q1: median 0.5" in out
    assert render([]) == "benchmark retrospective: no recorded history."
