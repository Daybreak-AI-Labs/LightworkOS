"""Tests for the budget_status tool (maverick.tools.budget_status)."""
from __future__ import annotations

# ---------- budget_status ----------

def test_budget_status_no_budget():
    from maverick.tools.budget_status import budget_status
    tool = budget_status(budget=None)
    out = tool.fn({})
    assert "no Budget bound" in out


def test_budget_status_with_budget():
    from maverick.budget import Budget
    from maverick.tools.budget_status import budget_status
    b = Budget(max_dollars=10.0)
    b.record_tokens(1000, 500, model="claude-opus-4-7")
    tool = budget_status(budget=b)
    out = tool.fn({})
    assert "dollars:" in out
    assert "input tokens" in out
    assert "output tokens" in out
    assert "tool calls:" in out
    # Cost recorded -> not zero.
    assert "$0.0000" not in out


def test_budget_status_warns_at_90pct():
    from maverick.budget import Budget
    from maverick.tools.budget_status import budget_status
    b = Budget(max_dollars=1.0)
    # Use atomic update to push spend high without tripping check().
    with b._lock:
        b.dollars = 0.95
    out = budget_status(budget=b).fn({})
    assert "WARNING" in out
