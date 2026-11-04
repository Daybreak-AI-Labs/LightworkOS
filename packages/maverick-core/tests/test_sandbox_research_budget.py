"""A budget with no wall cap is unlimited, not exhausted: the research
sandbox's own limits still bound every run."""
from __future__ import annotations

import math

import pytest
from maverick.budget import Budget
from maverick.sandbox import research


def test_an_uncapped_budget_gets_the_sandbox_time_limit():
    budget = Budget()
    assert math.isinf(budget.remaining_wall())
    assert research.ResearchContainerRunner._control_time(budget) == 15


def test_a_spent_wall_budget_is_still_refused():
    class Spent(Budget):
        def remaining_wall(self):
            return 0.0
    with pytest.raises(research.ResearchContainerError, match="exhausted"):
        research.ResearchContainerRunner._control_time(Spent())
