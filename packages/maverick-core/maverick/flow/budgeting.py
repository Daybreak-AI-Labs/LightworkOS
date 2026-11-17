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


def _spend_tracked(agent_runner: AgentRunner, per_call: float, spent: list) -> AgentRunner:
    """Wrap a runner to accumulate reserved spend (``per_call`` per invocation)
    into ``spent`` so the run's total cost can be persisted -- used when there is
    NO ``max_dollars`` gate (the gate already tracks spend itself)."""
    import threading
    lock = threading.Lock()

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


def _tool_spend_metered(action_runner: Callable, cap: float | None, spent: list,
                        lock=None) -> Callable:
    """Give each tool step a run budget of what is left of the flow's
    allowance, so a paid tool can run inside the flow's limit, and add what
    the step spent to the run's total. With an allowance, a step holds
    ``lock`` (shared with the agent gate) while it runs, so two paid steps
    cannot spend the same remainder."""
    import threading

    from ..budget import Budget, BudgetExceeded
    lock = lock or threading.Lock()

    @wraps(action_runner, updated=())
    def run(tool: str, params: dict, data: dict) -> tuple:
        def step():
            remaining = None if not cap or cap <= 0 else max(0.0, cap - spent[0])
            budget = Budget(max_dollars=remaining)
            token = _STEP_BUDGET.set(budget)
            try:
                return action_runner(tool, params, data)
            except BudgetExceeded as exc:
                if isinstance(exc, FlowBudgetExceeded):
                    raise
                # The step's paid call did not fit what was left of the flow's
                # allowance: the run stops as budget-limited.
                raise FlowBudgetExceeded(
                    f"flow spending allowance reached (${cap or 0:g}): {exc}") from exc
            finally:
                _STEP_BUDGET.reset(token)
                spent[0] += budget.dollars

        if cap and cap > 0:
            with lock:
                return step()
        return step()
    return run
