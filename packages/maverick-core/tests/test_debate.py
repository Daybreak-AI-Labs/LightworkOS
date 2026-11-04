"""Tests for multi-agent debate (maverick.debate)."""
from __future__ import annotations

import json
from types import SimpleNamespace


def _resp(text: str):
    """Duck-typed LLMResponse stand-in: only .text is used downstream."""
    return SimpleNamespace(text=text)


# ---------- debate ----------

def test_debate_runs_rounds_and_picks_winner():
    from maverick.debate import DebateParticipant, run_debate

    def _reply(name):
        def _r(**kwargs):
            return _resp(f"{name}-says-something")
        return _r

    def _judge(**kwargs):
        return _resp(json.dumps({
            "winner": "alice",
            "reason": "stronger evidence",
            "key_argument": "cited the original spec",
        }))

    participants = [
        DebateParticipant("alice", "optimist", _reply("alice")),
        DebateParticipant("bob", "skeptic", _reply("bob")),
    ]
    result = run_debate(
        "should we ship?", participants,
        judge_complete=_judge, rounds=2,
    )
    assert result.winner == "alice"
    assert "stronger evidence" in result.judge_reason
    # 2 rounds * 2 participants = 4 turns.
    assert len(result.transcript) == 4
    assert result.rounds_completed == 2


def test_debate_judge_unparseable_yields_draw():
    from maverick.debate import DebateParticipant, run_debate

    def _reply(**kwargs):
        return _resp("argument")

    def _bad_judge(**kwargs):
        return _resp("this is not JSON")

    parts = [
        DebateParticipant("alice", "optimist", _reply),
        DebateParticipant("bob", "skeptic", _reply),
    ]
    result = run_debate("q", parts, judge_complete=_bad_judge, rounds=1)
    assert result.winner == "draw"


def test_debate_requires_two_participants():
    from maverick.debate import DebateParticipant, run_debate
    try:
        run_debate(
            "q",
            [DebateParticipant("solo", "x", lambda **kw: _resp("hi"))],
            judge_complete=lambda **kw: _resp("{}"),
        )
    except ValueError as e:
        assert "at least 2" in str(e)
        return
    raise AssertionError("expected ValueError")


def test_debate_reraises_budget_exceeded():
    from maverick.budget import BudgetExceeded
    from maverick.debate import DebateParticipant, run_debate

    def _boom(**kwargs):
        raise BudgetExceeded("$1.00 > $0.50")

    participants = [
        DebateParticipant("alice", "optimist", _boom),
        DebateParticipant("bob", "skeptic", _boom),
    ]
    try:
        run_debate("q", participants, judge_complete=lambda **kw: _resp("{}"), rounds=1)
    except BudgetExceeded:
        return
    raise AssertionError("expected BudgetExceeded")
