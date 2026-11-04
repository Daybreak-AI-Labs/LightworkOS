"""Per-run agent budget reservation and usage accounting."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .run_events import FlowBudgetExceeded

AgentRunner = Callable[[str, dict], "tuple[Any, float | None]"]


class _MeteredAgentResult(tuple):
    """Keep the two-value executor contract with response-local spend."""

    def __new__(cls, result, outcome, dollars):
        value = super().__new__(cls, (result, outcome))
        value.dollars = float(dollars)
        return value


def _budget_gated(agent_runner: AgentRunner, cap: float, per_call: float, spent: list) -> AgentRunner:
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
    lock = threading.Lock()

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
