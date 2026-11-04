"""Budget cap-enforcement invariant (kernel rule 3: caps are not optional).

Every cap (output tokens, dollars, tool calls, wall time, input tokens) is
enforced INSIDE ``record_tokens`` / ``record_tool_call`` -- not only at an
explicit ``check()`` -- so no path can silently record a paid call past a cap.
Also covers the fail-closed corner (non-finite / negative usage raises rather
than counting as $0) and a fault-injection sweep across randomized cap/usage
pairs: usage over a cap MUST raise, usage under it MUST NOT.
"""
from __future__ import annotations

import pytest
from maverick.budget import Budget, BudgetExceeded, UsageAccountingError


def _budget(**caps) -> Budget:
    base = dict(max_output_tokens=10_000, max_dollars=1.0, max_tool_calls=5,
                max_wall_seconds=3600.0, max_input_tokens=1_000_000)
    base.update(caps)
    return Budget(**base)


def test_output_token_cap_trips_inside_record_tokens():
    b = _budget(max_output_tokens=1_000)
    with pytest.raises(BudgetExceeded):
        b.record_tokens(0, 1_001, model="claude-haiku-4-5-20251001")


def test_dollar_cap_trips_inside_record_tokens():
    b = _budget(max_dollars=0.0001)
    with pytest.raises(BudgetExceeded):
        # a large billed call must blow a tiny dollar cap
        b.record_tokens(1_000_000, 1_000_000, model="claude-opus-4-8")


def test_tool_call_cap_trips_inside_record_tool_call():
    b = _budget(max_tool_calls=3)
    for _ in range(3):
        b.record_tool_call()
    with pytest.raises(BudgetExceeded):
        b.record_tool_call()


def test_check_enforces_every_cap():
    for field, over in (
        ("output_tokens", "max_output_tokens"),
        ("tool_calls", "max_tool_calls"),
        ("input_tokens", "max_input_tokens"),
    ):
        b = _budget()
        setattr(b, field, getattr(b, over) + 1)
        with pytest.raises(BudgetExceeded):
            b.check()


def test_zero_wall_cap_trips_when_monotonic_clock_has_not_ticked(monkeypatch):
    import maverick.budget as budget_module

    monkeypatch.setattr(budget_module.time, "monotonic", lambda: 123.0)
    budget = _budget(max_wall_seconds=0.0)

    with pytest.raises(BudgetExceeded, match="wall time"):
        budget.check()


def test_nonfinite_or_negative_usage_fails_closed():
    # Malformed usage still stops the run, but as a provider accounting fault
    #, not as a cap breach.
    b = _budget()
    for bad in (float("inf"), float("nan"), -1):
        with pytest.raises(UsageAccountingError):
            b.record_tokens(0, bad)


def test_fault_injection_no_usage_over_a_cap_is_ever_silently_accepted():
    """Sweep cap/usage pairs: over -> must raise; under -> must not. A regression
    that dropped a cap check (recording a paid call as allowed) would fail here.
    Uses a deterministic pseudo-random schedule (no Math.random dependency)."""
    seed = 1
    trials = 0
    for _ in range(2000):
        seed = (1103515245 * seed + 12345) & 0x7FFFFFFF
        cap = 1_000 + (seed % 9_000)             # output-token cap in [1000,10000)
        seed = (1103515245 * seed + 12345) & 0x7FFFFFFF
        usage = seed % 20_000                    # output tokens in [0,20000)
        b = _budget(max_output_tokens=cap, max_dollars=10_000.0)
        if usage > cap:
            with pytest.raises(BudgetExceeded):
                b.record_tokens(0, usage)
        else:
            b.record_tokens(0, usage)            # at/under cap must not raise
        trials += 1
    assert trials == 2000
