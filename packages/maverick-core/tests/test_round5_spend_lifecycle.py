"""Spending and lifecycle boundaries retain paid usage and admission state."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from maverick.budget import Budget, BudgetExceeded


def test_dollar_cap_tolerates_only_float_roundoff():
    budget = Budget(max_dollars=0.3, dollars=0.1 + 0.2)
    budget.check()
    budget.dollars = 0.1
    budget.check_projected(0.2)
    held = budget.reserve(0.2)
    budget.release(held)
    for dollars in (0.30000001, 0.301):
        budget.dollars = dollars
        with pytest.raises(BudgetExceeded):
            budget.check()
    budget.dollars = 0.0
    budget.max_dollars = 0.0
    with pytest.raises(BudgetExceeded):
        budget.reserve(1e-12)


def test_held_breaker_probe_expires_without_admitting_concurrent_calls(monkeypatch):
    from maverick import circuit_breaker as circuits

    clock = [100.0]
    monkeypatch.setattr(circuits.time, "monotonic", lambda: clock[0])
    for cooldown in (0, 10):
        breaker = circuits.CircuitBreaker("expiry", failure_threshold=1, cooldown_seconds=cooldown)
        breaker.record_failure()
        clock[0] += cooldown
        assert breaker.admit()
        with pytest.raises(circuits.CircuitOpen):
            breaker.admit()
        clock[0] += cooldown or circuits._DEFAULT_COOLDOWN
        assert breaker.admit()


def test_episode_internal_typeerror_never_retries_without_spend():
    from maverick.orchestrator import _end_episode_with_spend

    calls = []

    class World:
        def end_episode(self, *args, **kwargs):
            calls.append(kwargs)
            if kwargs:
                raise TypeError("storage encoder failed")

    with pytest.raises(TypeError, match="storage encoder failed"):
        _end_episode_with_spend(World(), 1, "done", "success", Budget())
    assert len(calls) == 1


@pytest.mark.parametrize("error", [asyncio.CancelledError(), KeyboardInterrupt(), BudgetExceeded("cap")])
def test_completed_goal_survives_finalization_error(error):
    from maverick.orchestrator import _RunLifecycle

    writes = []
    world = SimpleNamespace(get_goal=lambda _id: SimpleNamespace(status="done"),
                            set_goal_status=lambda *args, **kwargs: writes.append((args, kwargs)),
                            append_event=lambda *args: None)
    lifecycle = _RunLifecycle(world, 1, Budget())
    lifecycle.started = True
    lifecycle.end_episode("completed", "success")
    lifecycle.finish(error)
    assert writes == []
    assert lifecycle.outcome == "success"


@pytest.mark.parametrize("refusal", ["lease", "pilot"])
def test_federation_claim_survives_pre_execution_refusal(monkeypatch, refusal):
    from maverick import (
        federation_admission,
        human_conversation_handoffs,
        orchestrator,
        outcome_pilot_start_gate,
        task_execution_guard,
        task_handoffs,
    )

    consumed = []
    monkeypatch.setattr(human_conversation_handoffs, "require_ai_open", lambda *args: None)
    monkeypatch.setattr(task_handoffs, "require_open", lambda *args: None)
    monkeypatch.setattr(federation_admission, "require_execution",
                        lambda *args, consume=False, **kwargs: consumed.append(consume))

    def pilot(*args):
        if refusal == "pilot":
            raise outcome_pilot_start_gate.OutcomePilotAdmissionRequired("pilot refused")

    @contextmanager
    def lease(*args):
        raise task_execution_guard.TaskBusy("occupied")
        yield

    monkeypatch.setattr(outcome_pilot_start_gate, "require_work_item_admission", pilot)
    monkeypatch.setattr(task_execution_guard, "lease", lease)
    world = SimpleNamespace(get_goal=lambda _id: SimpleNamespace(status="blocked"))
    result = asyncio.run(orchestrator.run_goal(None, world, Budget(), 1, sandbox=object()))
    assert result.startswith("BLOCKED:")
    assert True not in consumed
