"""async_compaction: history compaction scheduler."""
from __future__ import annotations

from maverick.tools.async_compaction import async_compaction


def _plan(**kw):
    return async_compaction().fn({"op": "plan", **kw})


# index: tokens / age_turns (higher age = older)
_SEGS = [
    {"tokens": 100, "age_turns": 1},   # 0 newest
    {"tokens": 200, "age_turns": 5},   # 1
    {"tokens": 300, "age_turns": 10},  # 2 oldest
]


def test_compacts_oldest_first_to_fit():
    out = _plan(segments=_SEGS, budget={"max_tokens": 400, "keep_recent": 1})
    # total 600 > 400; compact oldest (idx 2): saved 300*0.8=240, projected 360
    assert out.startswith("OK")
    assert "total=600 -> projected=360 (fits max_tokens=400)" in out
    assert "saved=240" in out
    assert "KEEP=1 COMPACT=1 DEFER=1" in out
    assert "compaction_order: [2]" in out


def test_nothing_to_do_when_under_budget():
    out = _plan(segments=_SEGS, budget={"max_tokens": 1000, "keep_recent": 1})
    assert "COMPACT=0" in out
    assert "saved=0" in out
    assert "compaction_order: [(none)]" in out


def test_pinned_and_recent_never_compacted():
    segs = [
        {"tokens": 100, "age_turns": 1},                 # 0 recent-kept
        {"tokens": 500, "age_turns": 9, "pinned": True}, # 1 pinned-kept
        {"tokens": 400, "age_turns": 8},                 # 2 oldest unpinned
    ]
    out = _plan(segments=segs, budget={"max_tokens": 1, "keep_recent": 1})
    # only idx 2 is eligible; idx 0 (recent) + idx 1 (pinned) are KEPT
    assert "KEEP=2" in out
    assert "compaction_order: [2]" in out


def test_keep_recent_zero_allows_all_old():
    out = _plan(segments=_SEGS, budget={"max_tokens": 0, "keep_recent": 0})
    # all eligible, compact oldest->newest until projected<=0 (never), so all 3
    assert "compaction_order: [2, 1, 0]" in out
    assert "COMPACT=3 DEFER=0" in out


def test_custom_compact_ratio():
    out = _plan(segments=[{"tokens": 1000, "age_turns": 5}],
                budget={"max_tokens": 100, "keep_recent": 0, "compact_ratio": 0.5})
    # saved = 1000*(1-0.5)=500, projected=500
    assert "saved=500" in out
    assert "projected=500 (OVER max_tokens=100)" in out


def test_errors():
    t = async_compaction()
    assert t.fn({"op": "plan", "budget": {"max_tokens": 1, "keep_recent": 0}}).startswith("ERROR")
    assert t.fn({"op": "plan", "segments": []}).startswith("ERROR")  # no budget
    assert _plan(segments=[], budget={"keep_recent": 0}).startswith("ERROR")  # no max_tokens
    assert _plan(segments=[{"tokens": 1, "age_turns": 1}],
                 budget={"max_tokens": 1, "keep_recent": 0, "compact_ratio": 2}).startswith("ERROR")
    assert _plan(segments=[{"age_turns": 1}],
                 budget={"max_tokens": 1, "keep_recent": 0}).startswith("ERROR")  # no tokens
    assert t.fn({"op": "nope", "segments": [], "budget": {"max_tokens": 1, "keep_recent": 0}}).startswith("ERROR")
