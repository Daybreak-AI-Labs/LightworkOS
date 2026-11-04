"""smart_goal_completion: pure-lexical goal completion from history."""
from __future__ import annotations

from maverick.tools.smart_goal_completion import smart_goal_completion


def _suggest(**kw):
    return smart_goal_completion().fn({"op": "suggest", **kw})


_HISTORY = [
    "deploy the staging server",
    "deploy the production server",
    "write unit tests for the parser",
    "refactor the billing module",
]


def test_prefix_match_ranks_first():
    out = _suggest(partial="deploy the prod", history=_HISTORY)
    lines = [ln for ln in out.splitlines() if ln.startswith("- ")]
    assert lines[0] == "- deploy the production server"


def test_token_overlap_ranking():
    out = _suggest(partial="tests parser", history=_HISTORY)
    lines = [ln for ln in out.splitlines() if ln.startswith("- ")]
    assert lines[0] == "- write unit tests for the parser"


def test_top_k_limits_results():
    out = _suggest(partial="", history=_HISTORY, k=2)
    lines = [ln for ln in out.splitlines() if ln.startswith("- ")]
    assert len(lines) == 2


def test_dedup_keeps_recent_for_blank_partial():
    hist = ["alpha task", "beta task", "alpha task"]
    out = _suggest(partial="", history=hist, k=5)
    lines = [ln for ln in out.splitlines() if ln.startswith("- ")]
    # de-duplicated: "alpha task" appears once
    assert lines.count("- alpha task") == 1


def test_no_candidates_and_errors():
    assert _suggest(partial="x", history=[]) == "SUGGEST: (no candidates)"
    t = smart_goal_completion()
    assert t.fn({"op": "suggest"}).startswith("ERROR")
    assert t.fn({"op": "nope", "history": []}).startswith("ERROR")


def test_factory_shape():
    t = smart_goal_completion()
    assert t.name == "smart_goal_completion"
    assert t.parallel_safe is True
    assert t.input_schema["required"] == ["history"]
