"""Correctness-scoring eval harness.

``harness.py`` measures the cost / latency / token use of a goal run; it
does NOT score whether the agent produced the *right* answer. This module
adds per-benchmark **correctness** scoring (pass@1) over a small pluggable
``Benchmark`` interface, so Lightwork can report GAIA / terminal-bench /
tau2 the same way regardless of how each benchmark shapes its tasks.

Two seams keep it testable without API keys or installed datasets:

  * A ``Benchmark`` supplies tasks (``load_tasks``) and a scorer
    (``score`` -> 0.0..1.0). Datasets are read from a path the caller
    provides, with a tiny offline fixture shipped for CI.
  * A ``solver`` callable turns one task into the agent's answer string.
    It is injected, so a test passes a deterministic stub and the whole
    harness runs end-to-end with no LLM and no network.

Run it for real by passing a solver that drives ``maverick start`` (see
``run_eval.py``); run it in CI with a stub (see ``test_evals.py``).
"""
from __future__ import annotations

import json
import math
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@dataclass
class EvalTask:
    """One benchmark task: a prompt to solve plus its ground truth."""

    task_id: str
    prompt: str
    answer: Any = None
    metadata: dict = field(default_factory=dict)


@dataclass
class EvalResult:
    """The outcome of scoring one task."""

    task_id: str
    score: float
    passed: bool
    expected: str
    got: str
    execution_status: str = "completed"
    scoring_status: str = "scored"
    error: str = ""


@runtime_checkable
class Benchmark(Protocol):
    """A scorable benchmark. Implementations live in ``eval_<name>.py``."""

    name: str

    def load_tasks(
        self, dataset: Path | None = None, *, limit: int | None = None
    ) -> list[EvalTask]:
        """Return tasks from ``dataset`` (or the shipped offline fixture)."""
        ...

    def score(self, task: EvalTask, output: str) -> float:
        """Score the agent's ``output`` against ``task`` in [0.0, 1.0]."""
        ...


# A solver turns one task into the agent's answer. Injected for testability.
Solver = Callable[[EvalTask], str]


def run_benchmark(
    bench: Benchmark,
    solver: Solver,
    *,
    dataset: Path | None = None,
    limit: int | None = None,
) -> dict:
    """Run every task through ``solver``, score it, and aggregate.

    A solver that raises is recorded as a 0-score result (its exception
    text becomes the ``got`` value) rather than aborting the whole run --
    one flaky task must not sink the benchmark.
    """
    tasks = bench.load_tasks(dataset, limit=limit)
    results: list[EvalResult] = []
    for t in tasks:
        execution_status, scoring_status, error = "completed", "not_scored", ""
        sc = 0.0
        try:
            out = solver(t)
            if not isinstance(out, str):
                raise TypeError("solver must return answer text")
        except Exception as e:  # one bad task != a dead benchmark
            execution_status = "failed"
            error = f"{type(e).__name__}: {e}"
            out = f"ERROR: {type(e).__name__}: {e}"
        else:
            try:
                raw_score = bench.score(t, out)
                if isinstance(raw_score, bool) or not isinstance(raw_score, (int, float)):
                    raise ValueError("score must be a finite number in [0, 1]")
                if not math.isfinite(raw_score) or not 0 <= raw_score <= 1:
                    raise ValueError("score must be a finite number in [0, 1]")
                sc = float(raw_score)
                scoring_status = "scored"
            except Exception as e:
                scoring_status = "failed"
                error = f"{type(e).__name__}: {e}"
        results.append(
            EvalResult(
                task_id=t.task_id,
                score=sc,
                passed=sc >= 1.0,
                expected=str(t.answer),
                got=out,
                execution_status=execution_status,
                scoring_status=scoring_status,
                error=error,
            )
        )
    n = len(results)
    passed = sum(1 for r in results if r.passed)
    mean = (sum(r.score for r in results) / n) if n else 0.0
    return {
        "benchmark": bench.name,
        "n": n,
        "passed": passed,
        "execution_failures": sum(r.execution_status == "failed" for r in results),
        "scoring_failures": sum(r.scoring_status == "failed" for r in results),
        "pass_at_1": round(passed / n, 4) if n else 0.0,
        "mean_score": round(mean, 4),
        "results": results,
    }


def _read_jsonl(path: Path) -> list[dict]:
    """Parse a JSONL file, skipping blank lines. Raises on malformed JSON."""
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


_SCORE_COLS = ["benchmark", "tag", "n", "passed", "pass_at_1", "mean_score"]


def append_scores(summary: dict, scores_path: Path, *, tag: str = "local") -> None:
    """Append one benchmark summary as a markdown row to ``scores_path``.

    Mirrors ``harness.append_results``: a human-readable markdown table is
    the artifact. Creates the file with a header if it does not exist.
    """
    if not scores_path.exists():
        header = "| " + " | ".join(_SCORE_COLS) + " |\n"
        divider = "|" + "|".join(["---"] * len(_SCORE_COLS)) + "|\n"
        scores_path.write_text(
            "# Lightwork eval scores\n\n"
            "Auto-appended by `benchmarks/evals.py`. Each row is one "
            "benchmark run (pass@1 = fraction of tasks fully solved).\n\n"
            + header + divider,
            encoding="utf-8",
        )
    row = {**summary, "tag": tag}
    line = "| " + " | ".join(str(row.get(c, "")) for c in _SCORE_COLS) + " |\n"
    with scores_path.open("a", encoding="utf-8") as f:
        f.write(line)


FIXTURES = Path(__file__).parent / "eval_fixtures"


__all__ = [
    "EvalTask",
    "EvalResult",
    "Benchmark",
    "Solver",
    "run_benchmark",
    "append_scores",
    "FIXTURES",
]
