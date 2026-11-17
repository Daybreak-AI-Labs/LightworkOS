"""Per-run agent budget reservation and usage accounting."""
from __future__ import annotations

from collections.abc import Callable
from contextvars import ContextVar
from functools import wraps
from typing import Any

from .run_events import FlowBudgetExceeded

AgentRunner = Callable[[str, dict], "tuple[Any, float | None]"]


class _MeteredAgentResult(tuple):
    """Keep the two-value executor contract with response-local spend."""

    def __new__(cls, result, outcome, dollars):
        value = super().__new__(cls, (result, outcome))
        value.dollars = float(dollars)
        return value


def _budget_gated(agent_runner: AgentRunner, cap: float, per_call: float, spent: list,
                  lock=None) -> AgentRunner:
    """Wrap an agent runner with a per-RUN aggregate spend ceiling. Each agent
    node is reserved at its worst-case per-node budget (``per_call``) against a
    shared, lock-guarded total; once the next reservation would exceed ``cap`` the
    node is held instead of spawning another goal. This bounds fan-out spend --
    a wide ``parallel`` or a long ``foreach`` can't multiply cost without a
    ceiling. Conservative: it counts each node at its cap, so it never
    under-counts real spend. Thread-safe for concurrent branches.

    Production runners meter actual usage and accept the remaining allowance.
    With an explicit aggregate cap they serialize agent admission, so parallel
    children cannot each consume the same remainder. Injected legacy runners
    retain their declared conservative reservation contract. A pre-dispatch
    refusal is a control stop, with no business result or learning outcome."""
    import threading
    lock = lock or threading.Lock()

    @wraps(agent_runner, updated=())
    def run(brief: str, data: dict, **kw) -> tuple:
        with lock:
            if getattr(agent_runner, "_meters_usage", False):
                remaining = cap - spent[0]
                if remaining <= 0:
                    raise FlowBudgetExceeded(f"flow spending allowance reached (${cap:g}) before dispatch")
                result = agent_runner(brief, data, allowance=remaining, **kw)
                spent[0] += result.dollars
                return result
            if spent[0] + per_call > cap:
                raise FlowBudgetExceeded(f"flow spending allowance reached (${cap:g}) before dispatch")
            spent[0] += per_call
        return agent_runner(brief, data, **kw)
    return run


def _spend_tracked(agent_runner: AgentRunner, per_call: float, spent: list,
                   lock=None) -> AgentRunner:
    """Wrap a runner to accumulate reserved spend (``per_call`` per invocation)
    into ``spent`` so the run's total cost can be persisted -- used when there is
    NO ``max_dollars`` gate (the gate already tracks spend itself). ``lock`` is
    shared with the tool-step budget, which adds to ``spent`` under it too."""
    import threading
    lock = lock or threading.Lock()

    @wraps(agent_runner, updated=())
    def run(brief: str, data: dict, **kw) -> tuple:
        if getattr(agent_runner, "_meters_usage", False):
            result = agent_runner(brief, data, **kw)
            with lock:
                spent[0] += result.dollars
            return result
        with lock:
            spent[0] += per_call
        return agent_runner(brief, data, **kw)
    return run


# The run budget a flow's tool step charges paid tool calls to; the action
# runner builds its tool registry with it.
_STEP_BUDGET: ContextVar[Any] = ContextVar("flow_step_budget", default=None)


def current_step_budget():
    """The run budget of the flow tool step being run, else ``None``."""
    return _STEP_BUDGET.get()


def _flow_step_budget_class():
    import math

    from ..budget import Budget, BudgetExceeded

    class _FlowStepBudget(Budget):
        """One tool step's run budget, admitted against the flow's shared
        allowance. A paid call takes the flow's lock only to hold its cost and
        to record its charge, so free steps never wait on each other and two
        paid steps cannot hold the same remainder."""

        def __init__(self, cap: float | None, spent: list, held: list, lock):
            super().__init__()
            self._flow_cap, self._flow_spent, self._flow_held, self._flow_lock = cap, spent, held, lock

        def remaining_dollars(self) -> float | None:
            if self._flow_cap is None:
                return None
            with self._flow_lock:
                return self._flow_cap - self._flow_spent[0] - self._flow_held[0]

        def _over(self, amount: float) -> bool:
            return (self._flow_cap is not None and amount > self._flow_cap
                    and not math.isclose(amount, self._flow_cap, rel_tol=1e-15, abs_tol=0.0))

        def reserve(self, est_cost: float) -> float:
            with self._flow_lock:
                projected = self._flow_spent[0] + self._flow_held[0] + est_cost
                if self._over(projected):
                    raise FlowBudgetExceeded(
                        f"flow spending allowance reached (${self._flow_cap:g}): "
                        f"${self._flow_spent[0]:.2f} spent, ${self._flow_held[0]:.2f} held, "
                        f"${est_cost:.2f} more needed")
                held = super().reserve(est_cost)
                self._flow_held[0] += held
                return held

        def release(self, held: float) -> None:
            with self._flow_lock:
                super().release(held)
                self._flow_held[0] = max(0.0, self._flow_held[0] - held)

        def record_tokens(self, *args, **kwargs):
            try:
                charge, failure = super().record_tokens(*args, **kwargs), None
            except BudgetExceeded as exc:
                charge, failure = getattr(exc, "token_charge", None), exc
                if charge is None:
                    raise
            with self._flow_lock:
                self._flow_spent[0] += charge.dollars
                over = self._over(self._flow_spent[0])
            if failure is not None:
                raise failure
            if over:
                stop = FlowBudgetExceeded(
                    f"flow spending allowance reached (${self._flow_cap:g}) by a paid tool call")
                stop.token_charge = charge
                stop.pricing_evidence = dict(charge.pricing_evidence)
                raise stop
            return charge

    return _FlowStepBudget


def _tool_spend_metered(action_runner: Callable, cap: float | None, spent: list,
                        lock=None) -> Callable:
    """Give each tool step a run budget drawn from the flow's allowance, so a
    paid tool can run inside the flow's limit, and add what it charges to the
    run's total. ``lock`` (shared with the agent gate) is taken only while a
    paid call holds its cost or records its charge; free steps never take it.
    A stop by another spending limit keeps that limit's own message."""
    import threading

    from ..budget import BudgetExceeded
    lock = lock or threading.Lock()
    step_budget = _flow_step_budget_class()
    held = [0.0]
    limit = cap if cap and cap > 0 else None

    @wraps(action_runner, updated=())
    def run(tool: str, params: dict, data: dict) -> tuple:
        token = _STEP_BUDGET.set(step_budget(limit, spent, held, lock))
        try:
            return action_runner(tool, params, data)
        except BudgetExceeded as exc:
            if isinstance(exc, FlowBudgetExceeded):
                raise
            # Another spending limit stopped the step's paid call: the run stops
            # as budget-limited, naming that limit.
            raise FlowBudgetExceeded(f"a spending limit stopped this tool step: {exc}") from exc
        finally:
            _STEP_BUDGET.reset(token)
    return run
