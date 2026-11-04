"""Run a correctness benchmark and report pass@1.

    python benchmarks/run_eval.py gaia --dataset path/to/gaia.jsonl --limit 20

The solver runs each task as a real goal **in-process** (``agent_solver.py``) --
the same ``run_goal`` path a user hits -- and returns the agent's final answer.
CI has no API keys, so ``MAVERICK_EVAL_DRY_RUN=1`` swaps in a stub solver
(every task "answered" with empty text) to smoke-test the machinery.

Benchmarks register here by name; add an adapter in ``eval_<name>.py`` and
a line to ``_BENCHMARKS``.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path


def _load(module_file: str, attr: str):
    p = Path(__file__).parent / module_file
    name = f"benchmarks_{p.stem}"
    mod = sys.modules.get(name)
    if mod is None:
        spec = importlib.util.spec_from_file_location(name, p)
        mod = importlib.util.module_from_spec(spec)
        # Register before exec so @dataclass can resolve cls.__module__ globals.
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return getattr(mod, attr)


# name -> (module file, Benchmark class attr)
_BENCHMARKS = {
    "gaia": ("eval_gaia.py", "GaiaBenchmark"),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("benchmark", choices=sorted(_BENCHMARKS))
    ap.add_argument("--dataset", type=Path, default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--max-dollars", type=float, default=2.0)
    ap.add_argument("--max-wall-seconds", type=float, default=900)
    ap.add_argument("--tag", default="local")
    ap.add_argument(
        "--scores", type=Path, default=Path(__file__).parent / "SCORES.md"
    )
    args = ap.parse_args()

    module_file, cls_attr = _BENCHMARKS[args.benchmark]
    bench = _load(module_file, cls_attr)()
    run_benchmark = _load("evals.py", "run_benchmark")
    append_scores = _load("evals.py", "append_scores")

    if os.environ.get("MAVERICK_EVAL_DRY_RUN") == "1":
        solver = _load("agent_solver.py", "dry_run_solver")
    else:
        make_agent_solver = _load("agent_solver.py", "make_agent_solver")
        solver = make_agent_solver(
            max_dollars=args.max_dollars, max_wall_seconds=args.max_wall_seconds,
        )

    summary = run_benchmark(
        bench, solver, dataset=args.dataset, limit=args.limit
    )
    append_scores(summary, args.scores, tag=args.tag)
    printable = {k: v for k, v in summary.items() if k != "results"}
    print(json.dumps(printable, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
