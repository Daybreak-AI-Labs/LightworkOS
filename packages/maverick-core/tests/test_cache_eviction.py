"""cache_eviction: LRU / LFU cache eviction simulator."""
from __future__ import annotations

from maverick.tools.cache_eviction import cache_eviction


def _sim(**kw):
    return cache_eviction().fn({"op": "simulate", **kw})


def test_lru_hits_and_misses():
    out = _sim(capacity=2, accesses=["A", "A", "B", "A", "B", "B"], policy="lru")
    assert "hits=4 misses=2" in out
    assert "hit_rate=0.6667" in out
    assert "cache: [A, B]" in out


def test_lfu_hits_and_misses():
    out = _sim(capacity=2, accesses=["A", "A", "B", "A", "B", "B"], policy="lfu")
    assert "hits=4 misses=2" in out
    assert "cache: [B, A]" in out  # most-frequent/recent first


def test_lru_vs_lfu_evict_differently():
    trace = ["A", "B", "A", "C", "B"]
    lru = _sim(capacity=2, accesses=trace, policy="lru")
    lfu = _sim(capacity=2, accesses=trace, policy="lfu")
    assert "cache: [C, B]" in lru  # LRU evicts B then A
    assert "cache: [A, B]" in lfu  # LFU keeps the hot A


def test_all_misses_when_unique_over_capacity():
    out = _sim(capacity=2, accesses=["A", "B", "C", "D"], policy="lru")
    assert "hits=0 misses=4" in out
    assert "hit_rate=0.0000" in out


def test_default_policy_is_lru_and_numeric_keys():
    out = cache_eviction().fn({"capacity": 1, "accesses": [1, 1, 2, 1]})
    # cap 1: 1(miss) 1(hit) 2(miss,evict) 1(miss) -> 1 hit, 3 miss
    assert "policy=lru" in out
    assert "hits=1 misses=3" in out
    assert "cache: [1]" in out


def test_errors():
    t = cache_eviction()
    assert t.fn({"op": "simulate", "accesses": ["A"]}).startswith("ERROR")  # no capacity
    assert t.fn({"op": "simulate", "capacity": 0, "accesses": ["A"]}).startswith("ERROR")
    assert t.fn({"op": "simulate", "capacity": 2, "accesses": "A"}).startswith("ERROR")
    assert t.fn({"op": "simulate", "capacity": 2, "accesses": ["A"], "policy": "arc"}).startswith("ERROR")
    assert t.fn({"op": "nope", "capacity": 2, "accesses": []}).startswith("ERROR")


def test_capacity_infinity_does_not_crash():
    out = _sim(capacity=float("inf"), accesses=["A"])
    assert out.startswith("ERROR")
