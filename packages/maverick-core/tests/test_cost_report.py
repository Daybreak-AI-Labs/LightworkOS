"""Cross-run spend rollup for `maverick costs`."""
from __future__ import annotations

from maverick.cost.report import SpendRow, aggregate, daily_series, format_report

_ROWS = [
    {"dollars": 1.0, "day": "2026-06-01", "tag": "acme", "model": "opus"},
    {"dollars": 3.0, "day": "2026-06-02", "tag": "beta", "model": "sonnet"},
    {"dollars": 1.0, "day": "2026-06-01", "tag": "acme", "model": "sonnet"},
]


def test_aggregate_total_and_shares_by_tag():
    agg = aggregate(_ROWS, by="tag")
    assert agg["total"] == 5.0
    assert agg["n"] == 3
    # sorted by dollars desc: beta (3.0) then acme (2.0)
    keys = [g[0] for g in agg["groups"]]
    assert keys == ["beta", "acme"]
    beta = agg["groups"][0]
    assert beta == ("beta", 3.0, 0.6)
    acme = agg["groups"][1]
    assert acme[1] == 2.0 and abs(acme[2] - 0.4) < 1e-9


def test_aggregate_by_day():
    groups = dict((k, (v, s)) for k, v, s in aggregate(_ROWS, by="day")["groups"])
    assert groups["2026-06-01"][0] == 2.0  # two rows on the 1st
    assert groups["2026-06-02"][0] == 3.0


def test_daily_series_is_chronological():
    rows = [
        {"dollars": 2.0, "day": "2026-06-03"},
        {"dollars": 1.0, "day": "2026-06-01"},
        {"dollars": 0.5, "day": "2026-06-03"},
    ]
    assert daily_series(rows) == [("2026-06-01", 1.0), ("2026-06-03", 2.5)]


def test_non_numeric_dollars_coerced_to_zero():
    rows = [{"dollars": "oops", "tag": "x"}, {"dollars": None, "tag": "x"}]
    agg = aggregate(rows, by="tag")
    assert agg["total"] == 0.0
    assert agg["n"] == 2
    assert agg["groups"][0] == ("x", 0.0, 0.0)


def test_top_trimming():
    rows = [{"dollars": float(i), "tag": f"t{i}"} for i in range(1, 6)]
    agg = aggregate(rows, by="tag", top=2)
    keys = [g[0] for g in agg["groups"]]
    assert keys == ["t5", "t4"]  # two highest only
    assert agg["n"] == 5  # n counts all rows, not just kept groups
    assert agg["total"] == 15.0


def test_empty_input():
    assert aggregate([], by="day") == {"total": 0.0, "n": 0, "groups": []}
    assert daily_series([]) == []
    assert format_report([]) == "no spend recorded"


def test_unknown_by_returns_error_dict():
    out = aggregate(_ROWS, by="nope")
    assert "error" in out
    assert "nope" in out["error"]
    assert "total" not in out  # never raises, returns an error dict
    # format_report surfaces the same error rather than crashing
    assert format_report(_ROWS, by="nope") == out["error"]


def test_format_report_contains_total_and_percentage():
    text = format_report(_ROWS, by="tag")
    assert "total" in text
    assert "$5.0000" in text
    assert "60.0%" in text  # beta's share
    assert isinstance(SpendRow(1.0, "2026-06-01"), SpendRow)
