"""kv_cache_offload: KV-cache offload-to-disk planner (LRU under budget)."""
from __future__ import annotations

from maverick.tools.kv_cache_offload import kv_cache_offload


def _plan(**kw):
    return kv_cache_offload().fn({"op": "plan", **kw})


_BLOCKS = [
    {"id": "a", "bytes": 100, "last_used_turn": 9},  # hottest (gap 1)
    {"id": "b", "bytes": 200, "last_used_turn": 8},  # gap 2
    {"id": "c", "bytes": 150, "last_used_turn": 7},  # coldest (gap 3)
]


def test_lru_keeps_hottest_within_budget():
    out = _plan(blocks=_BLOCKS, current_turn=10, mem_budget_bytes=300)
    # keep a(100)+b(200)=300; c(150) doesn't fit -> offload
    assert out.startswith("OK keep=2 offload=1 budget=300 used=300")
    assert "KEEP=[a, b] OFFLOAD=[c]" in out
    assert "bytes kept=300 offloaded=150" in out


def test_everything_fits():
    out = _plan(blocks=_BLOCKS, current_turn=10, mem_budget_bytes=1000)
    assert "keep=3 offload=0" in out
    assert "OFFLOAD=[]" in out
    assert "bytes kept=450 offloaded=0" in out


def test_zero_budget_offloads_all():
    out = _plan(blocks=_BLOCKS, current_turn=10, mem_budget_bytes=0)
    assert "keep=0 offload=3" in out
    assert "KEEP=[] OFFLOAD=[a, b, c]" in out
    assert "bytes kept=0 offloaded=450" in out


def test_block_larger_than_budget_skipped_smaller_kept():
    blocks = [
        {"id": "big", "bytes": 500, "last_used_turn": 9},   # hottest but too big
        {"id": "small", "bytes": 50, "last_used_turn": 1},  # colder, fits
    ]
    out = _plan(blocks=blocks, current_turn=10, mem_budget_bytes=100)
    # big is hottest but 500 > 100 -> offload; small (50) then fits
    assert "KEEP=[small] OFFLOAD=[big]" in out
    assert "bytes kept=50 offloaded=500" in out


def test_tie_broken_by_id():
    blocks = [
        {"id": "z", "bytes": 60, "last_used_turn": 5},
        {"id": "a", "bytes": 60, "last_used_turn": 5},
    ]
    out = _plan(blocks=blocks, current_turn=10, mem_budget_bytes=60)
    # equal recency -> id order: 'a' kept, 'z' offloaded
    assert "KEEP=[a] OFFLOAD=[z]" in out


def test_errors():
    t = kv_cache_offload()
    assert t.fn({"op": "plan", "current_turn": 1, "mem_budget_bytes": 1}).startswith("ERROR")
    assert t.fn({"op": "plan", "blocks": [], "mem_budget_bytes": 1}).startswith("ERROR")
    assert t.fn({"op": "plan", "blocks": [], "current_turn": 1}).startswith("ERROR")
    assert _plan(blocks=[{"id": "a", "bytes": 1}], current_turn=1,
                 mem_budget_bytes=1).startswith("ERROR")  # no last_used_turn
    assert t.fn({"op": "nope", "blocks": [], "current_turn": 1,
                 "mem_budget_bytes": 1}).startswith("ERROR")
