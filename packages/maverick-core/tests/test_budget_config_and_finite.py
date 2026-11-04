"""Budget caps must actually bind on the primary CLI paths and reject
non-finite values.

Two regressions:
  1. `maverick start` / `chat` / `resume` built Budget() directly, so a
     user's [budget] config (and, for resume, any raised cap) was silently
     ignored -- only the dashboard/runner path honored config.
  2. A nan/inf cap (TOML 1.0 has native nan/inf; `--max-dollars inf` parses)
     disabled enforcement entirely, because `dollars > nan` is always False.

These pin both: "budget caps are not optional."
"""
from __future__ import annotations

import math

import pytest
from maverick.budget import Budget, BudgetExceeded, budget_from_config

# ---- non-finite caps are coerced to a safe default, never run uncapped ----

@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_dollar_cap_is_not_uncapped(bad):
    b = Budget(max_dollars=bad)
    assert math.isfinite(b.max_dollars)
    # The cap must still bite: spend past the coerced default raises.
    b.dollars = b.max_dollars + 1.0
    with pytest.raises(BudgetExceeded):
        b.check()


@pytest.mark.parametrize("field", ["max_wall_seconds", "max_input_tokens", "max_output_tokens"])
def test_nonfinite_other_caps_coerced(field):
    b = Budget(**{field: float("inf")})
    assert math.isfinite(float(getattr(b, field)))


def test_finite_caps_are_preserved():
    b = Budget(max_dollars=2.5, max_wall_seconds=120.0)
    assert b.max_dollars == 2.5
    assert b.max_wall_seconds == 120.0


# ---- budget_from_config honors [budget], rejects non-finite config ----

def test_config_budget_is_honored(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.get_budget_overrides",
        lambda: {"max_dollars": 1.0, "max_wall_seconds": 90.0},
    )
    b = budget_from_config(defaults={"max_dollars": 5.0, "max_wall_seconds": 3600.0})
    assert b.max_dollars == 1.0          # config beat the default
    assert b.max_wall_seconds == 90.0


def test_explicit_override_beats_config(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.get_budget_overrides",
        lambda: {"max_dollars": 1.0},
    )
    b = budget_from_config(defaults={"max_dollars": 5.0}, max_dollars=3.0)
    assert b.max_dollars == 3.0          # explicit flag wins


def test_none_override_passes_through_to_config(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.get_budget_overrides",
        lambda: {"max_dollars": 2.0},
    )
    # A None flag means "unset" -> config still applies.
    b = budget_from_config(defaults={"max_dollars": 5.0}, max_dollars=None)
    assert b.max_dollars == 2.0


def test_nonfinite_config_value_is_refused(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.get_budget_overrides",
        lambda: {"max_dollars": float("inf")},
    )
    with pytest.raises(ValueError, match="finite non-negative"):
        budget_from_config(defaults={"max_dollars": 5.0})


def test_malformed_config_value_is_refused(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.get_budget_overrides",
        lambda: {"max_dollars": "not-a-number"},
    )
    with pytest.raises(ValueError, match="finite non-negative"):
        budget_from_config(defaults={"max_dollars": 4.0})
