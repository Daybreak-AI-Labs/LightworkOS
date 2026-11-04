"""misuse_removal: flagged-entry removal + re-ranking."""
from __future__ import annotations

from maverick.tools.misuse_removal import misuse_removal


def _run(entries):
    return misuse_removal().fn({"op": "apply", "entries": entries})


def test_removes_flagged_and_ranks():
    out = _run([
        {"id": "a", "score": 10},
        {"id": "b", "score": 50, "flagged": True, "reason": "cheating"},
        {"id": "c", "score": 30},
    ])
    assert out.startswith("CLEANED: removed 1, kept 2")
    # Ranking by score desc: c (30) before a (10).
    assert "1. c" in out and "2. a" in out
    assert "b" not in out.split("ranking:")[1].split("tombstones:")[0]


def test_tombstone_records_id_and_reason():
    out = _run([{"id": "x", "score": 1, "flagged": True, "reason": "spam"}])
    assert "tombstones:" in out
    assert "x: spam" in out


def test_default_reason_when_missing():
    out = _run([{"id": "x", "score": 1, "flagged": True}])
    assert "flagged for misuse" in out


def test_all_flagged_empty_board():
    out = _run([{"id": "x", "score": 1, "flagged": True}])
    assert "kept 0" in out
    assert "(empty)" in out


def test_ties_stable_insertion_order():
    out = _run([
        {"id": "first", "score": 5},
        {"id": "second", "score": 5},
    ])
    assert out.index("first") < out.index("second")


def test_errors_and_contract():
    assert misuse_removal().fn({"op": "apply", "entries": "nope"}).startswith("ERROR")
    assert _run([{"score": 1}]).startswith("ERROR")  # missing id
    assert misuse_removal().fn({"op": "bad", "entries": []}).startswith("ERROR")
    t = misuse_removal()
    assert t.name == "misuse_removal" and t.parallel_safe is True
