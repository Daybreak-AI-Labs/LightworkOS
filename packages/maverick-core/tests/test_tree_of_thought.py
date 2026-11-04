"""Tests for tree-of-thought search (maverick.tree_of_thought)."""
from __future__ import annotations

import json
from types import SimpleNamespace


def _resp(text: str):
    """Duck-typed LLMResponse stand-in: only .text is used downstream."""
    return SimpleNamespace(text=text)


# ---------- tree of thought ----------

def _seq_llm(text_seq: list[str]):
    calls = {"n": 0}

    class _Stub:
        def complete(self, **kwargs):
            i = calls["n"]
            calls["n"] += 1
            return _resp(text_seq[i] if i < len(text_seq) else "fallback")

    return _Stub(), calls


def test_tree_of_thought_picks_critic_winner():
    from maverick.tree_of_thought import plan_tree_of_thought

    critic = json.dumps({
        "scores": [0.2, 0.9, 0.5],
        "winner": 1,
        "reason": "candidate 1 covers test plan and rollback",
    })
    llm, calls = _seq_llm(["plan-A", "plan-B", "plan-C", critic])
    result = plan_tree_of_thought(llm, "build feature X", n=3)
    assert result.winning_index == 1
    assert result.winning_plan == "plan-B"
    assert "covers test plan" in result.critic_reason
    assert calls["n"] == 4  # n candidates + 1 critic


def test_tree_of_thought_falls_back_when_critic_unparseable():
    from maverick.tree_of_thought import plan_tree_of_thought
    llm, _ = _seq_llm([
        "short",
        "a much longer candidate that should win the heuristic",
        "mid-length",
        "not valid JSON at all",
    ])
    result = plan_tree_of_thought(llm, "goal", n=3)
    # Fallback heuristic picks the longest plan.
    assert result.winning_index == 1


def test_tree_of_thought_n_must_be_positive():
    from maverick.tree_of_thought import plan_tree_of_thought
    llm, _ = _seq_llm([])
    try:
        plan_tree_of_thought(llm, "goal", n=0)
    except ValueError as e:
        assert "n must" in str(e).lower()
        return
    raise AssertionError("expected ValueError")


def test_tree_of_thought_single_candidate_skips_critic():
    from maverick.tree_of_thought import plan_tree_of_thought
    llm, calls = _seq_llm(["only-plan"])
    result = plan_tree_of_thought(llm, "goal", n=1)
    assert result.winning_plan == "only-plan"
    assert result.winning_index == 0
    assert calls["n"] == 1  # critic never invoked


def test_tree_of_thought_reraises_budget_exceeded():
    from maverick.budget import BudgetExceeded
    from maverick.tree_of_thought import plan_tree_of_thought

    class _Stub:
        def complete(self, **kwargs):
            raise BudgetExceeded("$1.00 > $0.50")

    try:
        plan_tree_of_thought(_Stub(), "goal", n=3)
    except BudgetExceeded:
        return
    raise AssertionError("expected BudgetExceeded")


class TestToTScoreCandidatesEmpty:
    def test_empty_candidates_no_crash(self):
        from maverick.tree_of_thought import _score_candidates
        scores, winner, reason = _score_candidates(
            None, "goal", [], budget=None, model=None,
        )
        assert scores == []
        assert winner == 0
