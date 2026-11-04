"""Adversarial-cost benchmark suite.

Capability evals ask "can the agent do the work?"; this suite asks "can the
agent be tricked into WASTING money?". It scripts the classic spend-runaway
failure modes -- a tool-call loop, a token bomb, a runaway iteration count --
and asserts the cost-control layer CLAMPS each one. Like ``eval_smoke.py``,
it is the offline regression gate for that machinery: no LLM, no network,
deterministic scripted callables only. If a clamp regresses, ``main()``
exits 1 and the CI job goes red. Self-runnable:
``python benchmarks/eval_adversarial_cost.py``.

Scenarios (each returns ``{"scenario", "clamped", "detail"}``):

  * ``tool-loop``           a scripted agent re-calls the same read tool
                            100x; with the tool-output cache on
                            (``maverick.cache.tool``) paid executions must
                            stay <= 1 -- the cache absorbs the repeats.
  * ``token-bomb``          a tool returns a multi-megabyte string; the
                            agent loop's ``_cap_tool_output`` hook must
                            bound what enters the context window (tokens
                            are spend).
  * ``runaway-iterations``  a 1000-iteration scripted loop against
                            ``Budget(max_tool_calls=K)`` must halt at K
                            via ``BudgetExceeded``.
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile


@contextlib.contextmanager
def _scoped_env(**values: str):
    """Set env vars for the scenario body, restoring prior values exactly."""
    saved = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, old in saved.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


# ---- (a) tool-loop: identical re-reads must be absorbed by the cache ---------

class _ReadTool:
    """Tool-shaped object: exactly what tool_cache keys on (name +
    parallel_safe) plus a paid-execution counter."""

    name = "adversarial_read"
    parallel_safe = True

    def __init__(self) -> None:
        self.paid_executions = 0

    def fn(self, args: dict) -> str:
        self.paid_executions += 1
        return f"contents-of-{args['path']}"


def scenario_tool_loop() -> dict:
    """Re-call the same read tool 100x; the cache must absorb the repeats."""
    from maverick.cache import tool as tool_cache

    tool = _ReadTool()
    args = {"path": "src/big_module.py"}
    # A snapshot path that doesn't exist keeps warm-on-start inert even on a
    # host whose config enables it -- the scenario must be hermetic.
    absent = os.path.join(tempfile.gettempdir(), "maverick-adversarial-no-snapshot.jsonl")
    served = 0
    with _scoped_env(MAVERICK_TOOL_CACHE="1", MAVERICK_TOOL_CACHE_SNAPSHOT_PATH=absent):
        tool_cache.reset()
        try:
            for _ in range(100):
                # The same lookup->execute->store sequence ToolRegistry.run does.
                hit, value = tool_cache.get_cached(tool, args)
                if not hit:
                    value = tool.fn(args)  # the paid execution
                    tool_cache.store_cached(tool, args, value)
                if value:
                    served += 1
        finally:
            tool_cache.reset()
    clamped = tool.paid_executions <= 1 and served == 100
    return {
        "scenario": "tool-loop",
        "clamped": clamped,
        "detail": (
            f"100 identical reads -> {tool.paid_executions} paid execution(s), "
            f"{served} served"
        ),
    }


# ---- (b) token-bomb: a huge tool result must be capped before context --------

def scenario_token_bomb() -> dict:
    """A tool emits a multi-MB string; the truncation hook bounds what enters
    the context window (and therefore the next call's input-token spend)."""
    from maverick.agent import _MAX_TOOL_RESULT_BYTES, _cap_tool_output

    bomb = "$" * (_MAX_TOOL_RESULT_BYTES * 50)  # ~5 MB at the default cap
    entered = _cap_tool_output(bomb)
    limit = _MAX_TOOL_RESULT_BYTES + 1024  # head+tail plus the bounded marker
    clamped = len(entered) <= limit < len(bomb)
    return {
        "scenario": "token-bomb",
        "clamped": clamped,
        "detail": (
            f"{len(bomb)}-char tool result -> {len(entered)} chars entered "
            f"context (cap {_MAX_TOOL_RESULT_BYTES})"
        ),
    }


# ---- (c) runaway-iterations: the Budget ceiling halts the loop ---------------

def scenario_runaway_iterations() -> dict:
    """A scripted 1000-iteration loop must be halted at max_tool_calls=K."""
    from maverick.budget import Budget, BudgetExceeded

    cap = 25
    budget = Budget(max_tool_calls=cap, max_dollars=1e9, max_wall_seconds=3600.0)
    completed = 0
    halted = False
    try:
        for _ in range(1000):
            budget.record_tool_call()  # what the agent loop does per tool call
            completed += 1
    except BudgetExceeded:
        halted = True
    clamped = halted and completed <= cap
    return {
        "scenario": "runaway-iterations",
        "clamped": clamped,
        "detail": (
            f"halted after {completed} of 1000 iterations "
            f"(max_tool_calls={cap})"
        ),
    }


# ---- the gate ----------------------------------------------------------------

SCENARIOS = (scenario_tool_loop, scenario_token_bomb, scenario_runaway_iterations)


def run_suite() -> dict:
    """Run every scenario; green only if every waste vector was clamped."""
    results = [scenario() for scenario in SCENARIOS]
    return {"ok": all(r["clamped"] for r in results), "scenarios": results}


def main() -> int:
    summary = run_suite()
    print(json.dumps(summary, indent=2))
    if not summary["ok"]:
        bad = ", ".join(r["scenario"] for r in summary["scenarios"] if not r["clamped"])
        print(f"eval-adversarial-cost FAILED: unclamped scenario(s): {bad}",
              file=sys.stderr)
        return 1
    print("eval-adversarial-cost OK: every waste scenario was clamped")
    return 0


__all__ = ["SCENARIOS", "run_suite"]


if __name__ == "__main__":
    sys.exit(main())
