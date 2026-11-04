"""Live-fire smoke: real provider calls, opt-in, never accidental.

Everything else in this suite stubs the LLM boundary; this module is the
one place a REAL key exercises the real path. It runs only when BOTH are
present — a provider key and the explicit MAVERICK_LIVE_SMOKE=1 opt-in —
so CI stays hermetic and no key ever means surprise spend. The moment an
operator hands the environment a key and the flag, live-fire proof
starts accumulating on every run.

Costs are pinned tiny: one completion, single-digit max_tokens, budget-
capped by the kernel's own Budget so even the smoke test runs governed.
"""
from __future__ import annotations

import os

import pytest

_LIVE = bool(os.environ.get("ANTHROPIC_API_KEY")) and (
    os.environ.get("MAVERICK_LIVE_SMOKE") == "1"
)

pytestmark = pytest.mark.skipif(
    not _LIVE,
    reason="live smoke needs ANTHROPIC_API_KEY and MAVERICK_LIVE_SMOKE=1",
)


def test_governed_completion_round_trip():
    from maverick.budget import Budget
    from maverick.llm import LLM

    budget = Budget(max_dollars=0.05, max_output_tokens=64,
                    max_wall_seconds=120, max_tool_calls=1)
    llm = LLM()
    response = llm.complete(
        "Reply with exactly the single word: pong",
        [{"role": "user", "content": "ping"}],
        budget=budget,
        max_tokens=8,
    )
    assert "pong" in (response.text or "").lower()
    # The governed part of the claim: the call metered real tokens.
    assert budget.output_tokens > 0


def test_budget_refuses_before_the_wire_when_exhausted():
    from maverick.budget import Budget, BudgetExceeded
    from maverick.llm import LLM

    budget = Budget(max_dollars=0.000001, max_output_tokens=1,
                    max_wall_seconds=120, max_tool_calls=1)
    budget.record_tokens(0, 1)
    llm = LLM()
    with pytest.raises(BudgetExceeded):
        llm.complete(
            "Reply with one word.",
            [{"role": "user", "content": "ping"}],
            budget=budget,
            max_tokens=8,
        )
