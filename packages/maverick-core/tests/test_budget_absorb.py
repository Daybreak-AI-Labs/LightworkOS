"""Budget.absorb() must enforce the parent cap across child budgets.

Regression: best-of-N rolled child spend into the parent with a raw
``budget.dollars += attempt_budget.dollars``, bypassing both the lock and
check(). A parent with max_dollars=5 could run N attempts that each cost
$4 and never trip the cap (CLAUDE.md rule 3: budget.check() is not
optional). absorb() rolls up atomically AND calls check().
"""
import pytest
from maverick.budget import Budget, BudgetExceeded


def test_absorb_accumulates_counters():
    parent = Budget(max_dollars=100.0)
    child = Budget()
    child.input_tokens = 1000
    child.output_tokens = 500
    child.cache_read_tokens = 10
    child.cache_write_tokens = 20
    child.dollars = 2.0
    child.tool_calls = 3
    parent.absorb(child)
    assert parent.input_tokens == 1000
    assert parent.output_tokens == 500
    assert parent.cache_read_tokens == 10
    assert parent.cache_write_tokens == 20
    assert parent.dollars == pytest.approx(2.0)
    assert parent.tool_calls == 3


def test_absorb_trips_dollar_cap():
    parent = Budget(max_dollars=5.0)
    a1 = Budget()
    a1.dollars = 3.0
    a2 = Budget()
    a2.dollars = 3.0
    parent.absorb(a1)  # $3, under cap
    with pytest.raises(BudgetExceeded):
        parent.absorb(a2)  # $6 > $5 must raise
    # Spend is still recorded even though it tripped (don't lie about cost).
    assert parent.dollars == pytest.approx(6.0)


def test_absorb_trips_token_cap():
    parent = Budget(max_input_tokens=1000)
    child = Budget()
    child.input_tokens = 2000
    with pytest.raises(BudgetExceeded):
        parent.absorb(child)


def test_absorb_rejects_corrupt_child_without_poisoning_parent():
    parent = Budget(max_dollars=1.0)
    child = Budget()
    child.dollars = float("nan")

    with pytest.raises(BudgetExceeded, match="invalid dollars"):
        parent.absorb(child)

    assert parent.dollars == 0
    parent.reserve(1.0)
    with pytest.raises(BudgetExceeded):
        parent.reserve(0.01)
