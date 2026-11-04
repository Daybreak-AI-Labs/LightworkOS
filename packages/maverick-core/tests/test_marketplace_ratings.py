"""marketplace_ratings: rating aggregation + install hash verification."""
from __future__ import annotations

import json

from maverick.tools.marketplace_ratings import marketplace_ratings


def _run(**kw):
    return marketplace_ratings().fn(kw)


def test_aggregate_mean_count_histogram():
    out = json.loads(_run(op="aggregate", ratings=[5, 4, 5, 3, 5]))
    assert out["count"] == 5
    assert out["mean"] == 4.4
    assert out["histogram"] == {"1": 0, "2": 0, "3": 1, "4": 1, "5": 3}
    assert 0.0 <= out["wilson_lower_bound"] <= 1.0


def test_wilson_penalizes_low_count():
    # A single 5-star vote must rank BELOW many 5-star votes (confidence).
    one = json.loads(_run(op="aggregate", ratings=[5]))
    many = json.loads(_run(op="aggregate", ratings=[5] * 100))
    assert one["wilson_lower_bound"] < many["wilson_lower_bound"]
    # All-perfect mean is identical; only the confidence-adjusted score differs.
    assert one["mean"] == many["mean"] == 5.0


def test_wilson_orders_by_quality():
    # More high ratings -> higher lower bound than more low ratings (same count).
    good = json.loads(_run(op="aggregate", ratings=[5, 5, 5, 4, 5]))
    bad = json.loads(_run(op="aggregate", ratings=[1, 2, 1, 2, 1]))
    assert good["wilson_lower_bound"] > bad["wilson_lower_bound"]


def test_aggregate_errors():
    t = marketplace_ratings()
    assert t.fn({"op": "aggregate", "ratings": []}).startswith("ERROR")  # empty
    assert t.fn({"op": "aggregate", "ratings": [6]}).startswith("ERROR")  # out of range
    assert t.fn({"op": "aggregate", "ratings": [0]}).startswith("ERROR")  # out of range
    assert t.fn({"op": "aggregate", "ratings": ["x"]}).startswith("ERROR")  # non-int


def test_verify_install():
    sha = "a" * 64
    assert _run(op="verify_install", declared_sha256=sha, computed_sha256=sha).startswith(
        "VERIFIED"
    )
    # Case-insensitive compare.
    assert _run(
        op="verify_install", declared_sha256="AB" * 32, computed_sha256="ab" * 32
    ).startswith("VERIFIED")
    assert _run(
        op="verify_install", declared_sha256="a" * 64, computed_sha256="b" * 64
    ).startswith("MISMATCH")
    assert _run(op="verify_install", computed_sha256=sha).startswith("ERROR")


def test_factory_contract():
    t = marketplace_ratings()
    assert t.name == "marketplace_ratings"
    assert t.parallel_safe is True
    assert set(t.input_schema["properties"]["op"]["enum"]) == {"aggregate", "verify_install"}
    assert t.fn({"op": "nope"}).startswith("ERROR")
