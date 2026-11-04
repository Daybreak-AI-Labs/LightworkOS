"""tiered_storage: hot/cold tiering planner."""
from __future__ import annotations

from maverick.tools.tiered_storage import tiered_storage


def _plan(**kw):
    return tiered_storage().fn({"op": "plan", **kw})


_RECS = [
    {"id": "a", "last_access_days": 1, "size_kb": 10},    # hot
    {"id": "b", "last_access_days": 45, "size_kb": 20},   # cold
    {"id": "c", "last_access_days": 90, "size_kb": 30},   # cold
    {"id": "d", "last_access_days": 5, "size_kb": 40},    # hot
]


def test_recency_split():
    out = _plan(records=_RECS, policy={"hot_days": 30})
    assert out.startswith("OK")
    assert "HOT=2" in out
    assert "COLD=2" in out
    # bytes: hot a+d = 50kb*1024=51200 ; cold b+c = 50kb*1024=51200
    assert "HOT=2 (51200 bytes)" in out
    assert "COLD=2 (51200 bytes)" in out
    assert "migrate_to_cold: [b, c]" in out  # sorted ids


def test_boundary_is_hot_inclusive():
    # last_access_days == hot_days stays HOT (strictly greater is cold).
    out = _plan(records=[{"id": "x", "last_access_days": 30, "size_kb": 5}],
                policy={"hot_days": 30})
    assert "HOT=1" in out and "COLD=0" in out
    assert "migrate_to_cold: [(none)]" in out


def test_max_hot_mb_spills_coldest():
    # hot window keeps a,b,c hot (all recent); cap forces spill of the
    # least-recently-accessed hot record(s) to cold.
    recs = [
        {"id": "a", "last_access_days": 1, "size_kb": 1024},   # 1 MB
        {"id": "b", "last_access_days": 2, "size_kb": 1024},   # 1 MB
        {"id": "c", "last_access_days": 3, "size_kb": 1024},   # 1 MB, coldest
    ]
    out = _plan(records=recs, policy={"hot_days": 30, "max_hot_mb": 2})
    # 3 MB hot > 2 MB cap -> spill coldest (c) -> HOT=2, COLD=1
    assert "HOT=2" in out and "COLD=1" in out
    assert "migrate_to_cold: [c]" in out


def test_all_hot_when_window_large():
    out = _plan(records=_RECS, policy={"hot_days": 365})
    assert "HOT=4" in out and "COLD=0" in out


def test_default_op_and_numeric_ids():
    out = tiered_storage().fn({
        "records": [{"id": 7, "last_access_days": 100, "size_kb": 8}],
        "policy": {"hot_days": 10},
    })
    assert out.startswith("OK")
    assert "migrate_to_cold: [7]" in out


def test_errors():
    t = tiered_storage()
    assert t.fn({"op": "plan", "policy": {"hot_days": 1}}).startswith("ERROR")  # no records
    assert t.fn({"op": "plan", "records": []}).startswith("ERROR")  # no policy
    assert _plan(records=[], policy={}).startswith("ERROR")  # no hot_days
    assert _plan(records=[{"id": "a", "size_kb": 1}], policy={"hot_days": 5}).startswith("ERROR")
    assert _plan(records=[{"id": "a", "last_access_days": 1, "size_kb": 1}],
                 policy={"hot_days": -1}).startswith("ERROR")
    assert t.fn({"op": "nope", "records": [], "policy": {"hot_days": 1}}).startswith("ERROR")


def test_non_finite_and_overflow_sizes_do_not_crash():
    # Regression: int(round(sum * 1024)) raised OverflowError/ValueError on
    # non-finite or overflowing size_kb (model-supplied, untrusted).
    t = tiered_storage()
    for bad in (float("inf"), float("-inf"), float("nan")):
        out = t.fn({"op": "plan",
                    "records": [{"id": "a", "last_access_days": 1, "size_kb": bad}],
                    "policy": {"hot_days": 7}})
        assert out.startswith("ERROR")
        out = t.fn({"op": "plan",
                    "records": [{"id": "a", "last_access_days": bad, "size_kb": 1}],
                    "policy": {"hot_days": 7}})
        assert out.startswith("ERROR")
    # negative size rejected
    assert t.fn({"op": "plan",
                 "records": [{"id": "a", "last_access_days": 1, "size_kb": -5}],
                 "policy": {"hot_days": 7}}).startswith("ERROR")
    # finite-but-overflowing total bytes handled cleanly
    assert t.fn({"op": "plan",
                 "records": [{"id": "a", "last_access_days": 1, "size_kb": 1e308},
                             {"id": "b", "last_access_days": 1, "size_kb": 1e308}],
                 "policy": {"hot_days": 7}}).startswith("ERROR")
    # non-finite policy values rejected
    assert t.fn({"op": "plan",
                 "records": [{"id": "a", "last_access_days": 1, "size_kb": 1}],
                 "policy": {"hot_days": float("inf")}}).startswith("ERROR")
