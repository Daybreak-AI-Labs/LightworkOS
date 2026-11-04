"""Offline, deterministic eval-harness regression gate.

The real evals (`run_eval.py`, `eval_tau2.py`) drive `maverick start` against
a live provider -- they need models and a network, so they can't run in CI.
But the *machinery* around the model -- the benchmark registry, fixture
loading, the scorers, the tau2 verifier, and the pass@1 aggregation -- is
plain code, and a refactor can silently break it. This module is the gate
that catches that: it runs the same harness end-to-end against scripted
solvers (no LLM, no network) and asserts each benchmark grades a known-good
case as 1.0 and a known-bad case as 0.0.

If grading or wiring regresses, ``run_smoke()`` raises ``SmokeFailure`` and
the ``eval-smoke`` CI job goes red. Self-runnable: ``python benchmarks/eval_smoke.py``.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


class SmokeFailure(AssertionError):
    """A harness check produced an unexpected score -- the wiring regressed."""


def _load(module_file: str):
    """Path-load a sibling benchmarks module.

    ``benchmarks/`` is a flat script dir, not a package, so the modules load
    each other by file path (mirrors ``eval_tau2.py`` / ``run_eval.py``).
    """
    p = Path(__file__).parent / module_file
    name = f"benchmarks_{p.stem}"
    mod = sys.modules.get(name)
    if mod is None:
        spec = importlib.util.spec_from_file_location(name, p)
        mod = importlib.util.module_from_spec(spec)
        # Register before exec so @dataclass can resolve cls.__module__ globals.
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return mod


def _check(label: str, got: float, want: float) -> dict:
    if got != want:
        raise SmokeFailure(f"{label}: pass@1 was {got!r}, expected {want!r}")
    return {"check": label, "pass_at_1": got}


# ---- scripted solvers (no LLM, no network) ----------------------------------

def _gaia_oracle(task) -> str:
    """Answer every GAIA task with its ground truth -> a perfect run."""
    return f"FINAL ANSWER: {task.answer}"


def _gaia_wrong(_task) -> str:
    """Always wrong -> a zero run (exercises the failing scorer branch)."""
    return "FINAL ANSWER: definitely-not-the-answer"


def _tau2_oracle(task, tools) -> None:
    """Drive the retail tools to satisfy each fixture task (state + action)."""
    if task.task_id == "tau2-cancel":
        tools["cancel_order"]("O1")
    elif task.task_id == "tau2-address":
        tools["update_address"]("O2", "42 New St")
    elif task.task_id == "tau2-lookup":
        tools["get_order"]("O3")


def _tau2_noop(_task, _tools) -> None:
    """Touch nothing -> every task fails verification."""


# ---- the gate ----------------------------------------------------------------

def run_smoke() -> dict:
    """Run both benchmarks offline through scripted solvers and assert grading.

    Exercises the real registry + framework (``run_eval`` / ``evals``) and the
    real tau2 env + verifier, so a regression in any of them trips the gate.
    Returns a summary dict; raises ``SmokeFailure`` on the first bad score.
    """
    run_eval = _load("run_eval.py")
    evals = _load("evals.py")

    # GAIA goes through run_eval's registry exactly as a real run does --
    # this asserts the benchmark stays registered and its fixture loadable.
    gaia_cls = run_eval._load(*run_eval._BENCHMARKS["gaia"])
    gaia = gaia_cls()

    checks = [
        _check("gaia/oracle", evals.run_benchmark(gaia, _gaia_oracle)["pass_at_1"], 1.0),
        _check("gaia/wrong", evals.run_benchmark(gaia, _gaia_wrong)["pass_at_1"], 0.0),
    ]

    # tau2 is a different shape (stateful tools + verifier); run it through its
    # own runner so the verifier's both legs (final state AND required action)
    # are exercised end-to-end.
    tau2 = _load("eval_tau2.py")
    checks.append(_check("tau2/oracle", tau2.run_tau2(_tau2_oracle)["pass_at_1"], 1.0))
    checks.append(_check("tau2/noop", tau2.run_tau2(_tau2_noop)["pass_at_1"], 0.0))

    return {"ok": True, "checks": checks}


def main() -> int:
    try:
        summary = run_smoke()
    except SmokeFailure as e:
        print(f"eval-smoke FAILED: {e}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    print("eval-smoke OK: harness wiring + grading intact")
    return 0


__all__ = ["run_smoke", "SmokeFailure"]


if __name__ == "__main__":
    sys.exit(main())
