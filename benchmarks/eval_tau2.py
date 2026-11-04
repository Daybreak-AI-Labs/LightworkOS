"""tau2-style harness: stateful tool-agent evaluation with outcome+action checks.

GAIA (``eval_gaia.py``) scores a single string answer. tau2-bench is a different
shape -- it needs a *verification environment*, not a string adapter: the agent acts on a stateful tool domain (a DB the tools mutate), and a
task is graded on BOTH the final state (the outcome) AND whether the required
tool actions were taken (the process). This module is that harness, with a small
self-contained "retail" domain so it runs end-to-end in CI; real tau2-bench task
files (same row shape) plug in via ``--dataset``.

Like ``evals.py``, the **solver is injected** so the whole thing runs with a
deterministic stub (no LLM / network): a solver receives a task + the domain's
tools (name -> callable) and drives them to satisfy the request, mutating the
env. The verifier then checks the env. A live run uses ``tau2_solver.py``, which
registers these tools into a Lightwork agent talking to a user simulator; the
env + verifier + task format are the harness.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _load_framework():
    """Path-load ``evals.py`` (benchmarks/ is a flat script dir, not a package)."""
    name = "benchmarks_evals"
    if name in sys.modules:
        return sys.modules[name]
    p = Path(__file__).parent / "evals.py"
    spec = importlib.util.spec_from_file_location(name, p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_E = _load_framework()
EvalResult = _E.EvalResult
FIXTURES = _E.FIXTURES


@dataclass
class Tau2Task:
    """One stateful task: a user request, the starting DB, and the grade keys.

    - ``expected_state``: dotted-path -> value the DB MUST hold at the end
      (e.g. ``{"orders.O1.status": "cancelled"}``). Empty = no state change required.
    - ``required_actions``: tool calls that MUST have happened, each
      ``{"name": ..., "args": {...subset...}}``; a logged call matches if its args
      include that subset.
    """

    task_id: str
    prompt: str
    initial_state: dict = field(default_factory=dict)
    expected_state: dict = field(default_factory=dict)
    required_actions: list = field(default_factory=list)


# ---- the "retail" domain: a stateful tool environment -----------------------

class Tau2Env:
    """Holds the mutable DB plus an append-only log of the tool calls made."""

    def __init__(self, db: dict):
        self.db = copy.deepcopy(db or {})
        self.actions: list[dict] = []

    def _log(self, name: str, args: dict) -> None:
        self.actions.append({"name": name, "args": dict(args)})


def build_retail_tools(env: Tau2Env) -> dict[str, Callable]:
    """Return the retail domain's tools, bound to ``env`` (read + mutate + log)."""

    def get_order(order_id: str):
        env._log("get_order", {"order_id": order_id})
        return env.db.get("orders", {}).get(order_id)

    def cancel_order(order_id: str, reason: str = ""):
        env._log("cancel_order", {"order_id": order_id, "reason": reason})
        order = env.db.get("orders", {}).get(order_id)
        if order is None:
            return f"no such order {order_id!r}"
        order["status"] = "cancelled"
        return "cancelled"

    def update_address(order_id: str, address: str):
        env._log("update_address", {"order_id": order_id, "address": address})
        order = env.db.get("orders", {}).get(order_id)
        if order is None:
            return f"no such order {order_id!r}"
        order["address"] = address
        return "updated"

    def get_user(user_id: str):
        env._log("get_user", {"user_id": user_id})
        return env.db.get("users", {}).get(user_id)

    return {
        "get_order": get_order,
        "cancel_order": cancel_order,
        "update_address": update_address,
        "get_user": get_user,
    }


# A solver drives the domain tools to satisfy the task. Injected for testability.
Tau2Solver = Callable[[Tau2Task, dict], None]

_MISSING = object()


def _resolve(db: dict, dotted: str):
    cur: Any = db
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


def _action_present(actions: list[dict], required: dict) -> bool:
    rname = required.get("name")
    rargs = required.get("args") or {}
    for a in actions:
        if a.get("name") != rname:
            continue
        aargs = a.get("args") or {}
        if all(aargs.get(k) == v for k, v in rargs.items()):
            return True
    return False


def verify(task: Tau2Task, env: Tau2Env) -> tuple[float, str]:
    """Grade a finished task: outcome (final state) AND process (required actions).

    Returns (1.0, "ok") only if every expected-state key matches AND every
    required action was logged; else (0.0, "<what failed>")."""
    state_fails = [
        f"{path}={_resolve(env.db, path)!r} (want {expected!r})"
        for path, expected in (task.expected_state or {}).items()
        if _resolve(env.db, path) != expected
    ]
    action_fails = [
        str(req.get("name"))
        for req in (task.required_actions or [])
        if not _action_present(env.actions, req)
    ]
    if not state_fails and not action_fails:
        return 1.0, "ok"
    parts = []
    if state_fails:
        parts.append("state: " + "; ".join(state_fails))
    if action_fails:
        parts.append("missing actions: " + ", ".join(action_fails))
    return 0.0, " | ".join(parts)


def load_tasks(dataset: Path | None = None, *, limit: int | None = None) -> list[Tau2Task]:
    path = dataset if dataset is not None else FIXTURES / "tau2_retail_sample.jsonl"
    rows = _E._read_jsonl(Path(path))
    tasks = [
        Tau2Task(
            task_id=str(r.get("task_id", r.get("id", ""))),
            prompt=str(r.get("prompt", r.get("instruction", ""))),
            initial_state=r.get("initial_state") or {},
            expected_state=r.get("expected_state") or {},
            required_actions=r.get("required_actions") or [],
        )
        for r in rows
    ]
    return tasks[:limit] if limit is not None else tasks


def run_tau2(
    solver: Tau2Solver,
    *,
    dataset: Path | None = None,
    limit: int | None = None,
) -> dict:
    """Run each task in a fresh env through ``solver``, verify, and aggregate.

    A solver that raises is recorded as a 0-score result (its error text becomes
    ``got``) rather than aborting the whole run."""
    tasks = load_tasks(dataset, limit=limit)
    results: list = []
    for t in tasks:
        env = Tau2Env(t.initial_state)
        tools = build_retail_tools(env)
        try:
            solver(t, tools)
        except Exception as e:  # one bad task != a dead benchmark
            results.append(EvalResult(task_id=t.task_id, score=0.0, passed=False,
                                      expected="ok", got=f"ERROR: {type(e).__name__}: {e}"))
            continue
        score, detail = verify(t, env)
        results.append(EvalResult(task_id=t.task_id, score=score, passed=score >= 1.0,
                                   expected="ok", got=detail))
    n = len(results)
    passed = sum(1 for r in results if r.passed)
    return {
        "benchmark": "tau2",
        "n": n,
        "passed": passed,
        "pass_at_1": round(passed / n, 4) if n else 0.0,
        "mean_score": round(sum(r.score for r in results) / n, 4) if n else 0.0,
        "results": results,
    }


def _dry_run_solver(task: Tau2Task, tools: dict) -> None:
    """No-op solver: structure smoke (every task scores 0)."""


def _load_tau2_solver():
    """Path-load the live solver (benchmarks/ is a flat script dir)."""
    name = "benchmarks_tau2_solver"
    if name in sys.modules:
        return sys.modules[name]
    p = Path(__file__).parent / "tau2_solver.py"
    spec = importlib.util.spec_from_file_location(name, p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    """Run the tau2 harness. By default the LIVE solver runs an agent<->user-
    simulator conversation over the domain tools (needs a provider key);
    ``MAVERICK_EVAL_DRY_RUN=1`` swaps in the no-op stub for CI / smoke."""
    import argparse
    import os
    ap = argparse.ArgumentParser(prog="eval_tau2")
    ap.add_argument("--dataset", type=Path, default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--max-dollars", type=float, default=2.0)
    ap.add_argument("--tag", default="local")
    ap.add_argument("--scores", type=Path, default=Path(__file__).parent / "SCORES.md")
    args = ap.parse_args()
    if os.environ.get("MAVERICK_EVAL_DRY_RUN") == "1":
        solver = _dry_run_solver
    else:
        solver = _load_tau2_solver().make_tau2_solver(max_dollars=args.max_dollars)
    summary = run_tau2(solver, dataset=args.dataset, limit=args.limit)
    _E.append_scores(summary, args.scores, tag=args.tag)
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, indent=2))
    return 0


__all__ = [
    "Tau2Task", "Tau2Env", "Tau2Solver",
    "build_retail_tools", "verify", "load_tasks", "run_tau2",
]


if __name__ == "__main__":
    sys.exit(main())
