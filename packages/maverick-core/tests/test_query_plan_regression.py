"""query_plan_regression: query-plan regression check."""
from __future__ import annotations

from maverick.tools.query_plan_regression import query_plan_regression


def _compare(baseline, candidate, **kw):
    return query_plan_regression().fn(
        {"op": "compare", "baseline": baseline, "candidate": candidate, **kw}
    )


def test_ok_when_within_tolerance():
    out = _compare(
        {"rows_scanned": 100, "cost": 10.0, "used_index": True},
        {"rows_scanned": 100, "cost": 10.5, "used_index": True},
    )
    assert out.startswith("OK") and "no regression" in out


def test_regression_cost_over_threshold():
    out = _compare(
        {"rows_scanned": 100, "cost": 10.0, "used_index": True},
        {"rows_scanned": 100, "cost": 13.0, "used_index": True},
    )
    assert out.startswith("REGRESSION") and "cost up" in out


def test_regression_index_dropped():
    out = _compare(
        {"rows_scanned": 100, "cost": 10.0, "used_index": True},
        {"rows_scanned": 100, "cost": 10.0, "used_index": False},
    )
    assert out.startswith("REGRESSION") and "index dropped" in out


def test_regression_more_rows_scanned():
    out = _compare(
        {"rows_scanned": 100, "cost": 10.0, "used_index": True},
        {"rows_scanned": 250, "cost": 10.0, "used_index": True},
    )
    assert out.startswith("REGRESSION") and "rows_scanned up" in out


def test_custom_threshold_allows_bigger_jump():
    # 20% jump tolerated when threshold_pct=25.
    out = _compare(
        {"rows_scanned": 100, "cost": 10.0, "used_index": True},
        {"rows_scanned": 100, "cost": 12.0, "used_index": True},
        threshold_pct=25,
    )
    assert out.startswith("OK")


def test_errors():
    t = query_plan_regression()
    assert t.fn({"op": "compare"}).startswith("ERROR")  # no plans
    assert t.fn(
        {"op": "nope", "baseline": {"rows_scanned": 1, "cost": 1},
         "candidate": {"rows_scanned": 1, "cost": 1}}
    ).startswith("ERROR")
    assert t.fn(
        {"op": "compare", "baseline": {"rows_scanned": "x", "cost": 1},
         "candidate": {"rows_scanned": 1, "cost": 1}}
    ).startswith("ERROR")


def test_non_finite_rows_scanned_does_not_crash():
    # Regression: int(plan["rows_scanned"]) raised OverflowError on a non-finite value.
    t = query_plan_regression()
    out = t.fn({"baseline": {"rows_scanned": float("inf"), "cost": 1},
                "candidate": {"rows_scanned": 1, "cost": 1}})
    assert out.startswith("ERROR")
