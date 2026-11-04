"""wal_contention: WAL concurrent-writer contention audit."""
from __future__ import annotations

from maverick.tools.wal_contention import wal_contention


def _analyze(**kw):
    return wal_contention().fn({"op": "analyze", **kw})


def test_detects_superlinear_knee():
    buckets = [
        {"writers": 1, "p50_ms": 5, "p99_ms": 10},
        {"writers": 2, "p50_ms": 10, "p99_ms": 20},   # linear
        {"writers": 4, "p50_ms": 20, "p99_ms": 40},   # linear
        {"writers": 8, "p50_ms": 60, "p99_ms": 120},  # 120 vs linear 80 -> knee
    ]
    out = _analyze(buckets=buckets)
    assert out.startswith("DEGRADES")
    assert "max_writers=4" in out
    assert "writers=8: SUPERLINEAR" in out
    assert "writers=4: OK" in out


def test_all_linear_is_ok():
    buckets = [
        {"writers": 1, "p50_ms": 5, "p99_ms": 10},
        {"writers": 2, "p50_ms": 10, "p99_ms": 20},
        {"writers": 4, "p50_ms": 20, "p99_ms": 40},
    ]
    out = _analyze(buckets=buckets)
    assert out.startswith("OK")
    assert "max_writers=4" in out  # all buckets scale within tolerance


def test_unsorted_input_sorted_by_writers():
    buckets = [
        {"writers": 4, "p50_ms": 20, "p99_ms": 200},  # blows up
        {"writers": 1, "p50_ms": 5, "p99_ms": 10},    # baseline
        {"writers": 2, "p50_ms": 10, "p99_ms": 20},
    ]
    out = _analyze(buckets=buckets)
    assert out.startswith("DEGRADES")
    assert "max_writers=2" in out
    # baseline reported from the lowest writer count even though listed 2nd
    assert "baseline writers=1" in out


def test_tolerance_controls_sensitivity():
    buckets = [
        {"writers": 1, "p50_ms": 5, "p99_ms": 10},
        {"writers": 2, "p50_ms": 10, "p99_ms": 24},  # +20% over linear 20
    ]
    strict = _analyze(buckets=buckets, tolerance=0.1)
    loose = _analyze(buckets=buckets, tolerance=0.5)
    assert strict.startswith("DEGRADES") and "max_writers=1" in strict
    assert loose.startswith("OK") and "max_writers=2" in loose


def test_single_bucket_is_baseline_ok():
    out = _analyze(buckets=[{"writers": 1, "p50_ms": 5, "p99_ms": 10}])
    assert out.startswith("OK")
    assert "max_writers=1" in out


def test_errors():
    t = wal_contention()
    assert t.fn({"op": "analyze"}).startswith("ERROR")  # no buckets
    assert t.fn({"op": "analyze", "buckets": []}).startswith("ERROR")  # empty
    assert _analyze(buckets=[{"writers": 0, "p50_ms": 1, "p99_ms": 1}]).startswith("ERROR")
    assert _analyze(buckets=[{"writers": 1, "p99_ms": 1}]).startswith("ERROR")  # no p50
    assert _analyze(buckets=[{"writers": 1, "p50_ms": 1, "p99_ms": 1}],
                    tolerance=-1).startswith("ERROR")
    dup = _analyze(buckets=[{"writers": 1, "p50_ms": 1, "p99_ms": 1},
                            {"writers": 1, "p50_ms": 2, "p99_ms": 2}])
    assert dup.startswith("ERROR")
    assert t.fn({"op": "nope", "buckets": [{"writers": 1, "p50_ms": 1, "p99_ms": 1}]}).startswith("ERROR")


def test_non_finite_writers_does_not_crash():
    # Regression: int(bucket["writers"]) raised OverflowError on a non-finite value.
    t = wal_contention()
    out = t.fn({"op": "analyze",
                "buckets": [{"writers": float("inf"), "p50_ms": 1, "p99_ms": 2}]})
    assert out.startswith("ERROR")
