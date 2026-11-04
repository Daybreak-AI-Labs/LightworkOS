"""Correctness-scoring eval harness: framework + GAIA adapter.

Path-loads the benchmark modules (benchmarks/ is a flat script dir, not a
package) and exercises the whole harness with a deterministic stub solver,
so it runs in CI with no API keys and no dataset download.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load(name: str):
    p = Path(__file__).parent / name
    spec = importlib.util.spec_from_file_location(f"benchmarks_{p.stem}", p)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass can resolve cls.__module__ globals.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def evals():
    return _load("evals.py")


@pytest.fixture(scope="module")
def gaia():
    return _load("eval_gaia.py")


@pytest.fixture(scope="module")
def run_eval():
    return _load("run_eval.py")


# --- framework ---------------------------------------------------------

@pytest.mark.parametrize("score", [float("nan"), float("inf"), -float("inf"), True, "1", None, 2, -1])
def test_invalid_scores_are_failed_with_provenance(evals, score):
    bench = TestRunBenchmark()._bench(evals)
    bench.score = lambda task, output: score
    report = evals.run_benchmark(bench, lambda task: task.answer)
    assert report["passed"] == report["mean_score"] == 0
    assert report["scoring_failures"] == 2
    assert all(row.scoring_status == "failed" and row.error for row in report["results"])


def test_failed_solver_is_never_graded_as_an_answer(evals):
    bench = TestRunBenchmark()._bench(evals)
    def score(task, output):
        pytest.fail("failed execution must never reach scorer")
    def solver(task):
        raise RuntimeError(f"provider failed while returning {task.answer}")
    bench.score = score
    report = evals.run_benchmark(bench, solver)
    assert report["execution_failures"] == 2
    assert report["passed"] == 0
    assert all(row.execution_status == "failed" and row.scoring_status == "not_scored" for row in report["results"])

class TestRunBenchmark:
    def _bench(self, evals):
        class _Echo:
            name = "echo"

            def load_tasks(self, dataset=None, *, limit=None):
                tasks = [
                    evals.EvalTask(task_id="a", prompt="p", answer="yes"),
                    evals.EvalTask(task_id="b", prompt="p", answer="no"),
                ]
                return tasks[:limit] if limit is not None else tasks

            def score(self, task, output):
                return 1.0 if output == task.answer else 0.0

        return _Echo()

    def test_aggregates_pass_at_1(self, evals):
        # Solver gets "a" right, "b" wrong -> pass@1 = 0.5.
        summary = evals.run_benchmark(self._bench(evals), lambda t: t.answer if t.task_id == "a" else "wrong")
        assert summary["n"] == 2
        assert summary["passed"] == 1
        assert summary["pass_at_1"] == 0.5

    def test_limit_is_respected(self, evals):
        summary = evals.run_benchmark(self._bench(evals), lambda t: t.answer, limit=1)
        assert summary["n"] == 1
        assert summary["pass_at_1"] == 1.0

    def test_solver_exception_scores_zero_not_crash(self, evals):
        def boom(_t):
            raise RuntimeError("solver blew up")
        summary = evals.run_benchmark(self._bench(evals), boom)
        assert summary["passed"] == 0
        assert "solver blew up" in summary["results"][0].got

    def test_append_scores_writes_markdown(self, evals, tmp_path):
        scores = tmp_path / "SCORES.md"
        evals.append_scores(
            {"benchmark": "echo", "n": 2, "passed": 1,
             "pass_at_1": 0.5, "mean_score": 0.5},
            scores, tag="t1",
        )
        text = scores.read_text()
        assert "| benchmark | tag |" in text
        assert "| echo | t1 | 2 | 1 | 0.5 | 0.5 |" in text


# --- GAIA scorer -------------------------------------------------------

class TestGaiaScorer:
    def test_number_match(self, gaia):
        assert gaia.question_scorer("FINAL ANSWER: 60", "60") == 1.0
        assert gaia.question_scorer("FINAL ANSWER: 60 km/h", "60") == 0.0  # extra text
        assert gaia.question_scorer("FINAL ANSWER: $1,234", "1234") == 1.0  # $ , stripped
        assert gaia.question_scorer("FINAL ANSWER: 7", "60") == 0.0

    def test_string_match_normalizes(self, gaia):
        assert gaia.question_scorer("FINAL ANSWER: Paris", "Paris") == 1.0
        assert gaia.question_scorer("FINAL ANSWER:  paris.", "Paris") == 1.0  # case/punct/ws
        assert gaia.question_scorer("FINAL ANSWER: London", "Paris") == 0.0

    def test_list_match_elementwise(self, gaia):
        assert gaia.question_scorer("FINAL ANSWER: red, green, blue", "red, green, blue") == 1.0
        assert gaia.question_scorer("FINAL ANSWER: red; green; blue", "red, green, blue") == 1.0
        assert gaia.question_scorer("FINAL ANSWER: red, green", "red, green, blue") == 0.0  # wrong length

    def test_uses_text_after_final_marker(self, gaia):
        # Chatty reasoning before the marker must not affect the score.
        out = "Let me think... the answer is clearly the capital.\nFINAL ANSWER: Paris"
        assert gaia.question_scorer(out, "Paris") == 1.0


# --- GAIA end-to-end over the offline fixture --------------------------

class TestGaiaEndToEnd:
    def test_fixture_loads_three_tasks(self, gaia):
        tasks = gaia.GaiaBenchmark().load_tasks()
        assert len(tasks) == 3
        assert {t.task_id for t in tasks} == {
            "gaia-sample-num", "gaia-sample-str", "gaia-sample-list"
        }

    def test_perfect_solver_scores_one(self, evals, gaia):
        bench = gaia.GaiaBenchmark()
        # An oracle solver that returns each task's ground truth.
        summary = evals.run_benchmark(bench, lambda t: f"FINAL ANSWER: {t.answer}")
        assert summary["pass_at_1"] == 1.0
        assert summary["n"] == 3

    def test_empty_solver_scores_zero(self, evals, gaia):
        bench = gaia.GaiaBenchmark()
        summary = evals.run_benchmark(bench, lambda t: "")
        assert summary["pass_at_1"] == 0.0


# --- in-process live-solver wiring ------------------------------------

class TestMaverickSolver:
    def test_run_eval_wires_the_in_process_solver(self, run_eval, evals):
        # The brittle `maverick start` subprocess solver was replaced by the
        # in-process agent_solver. run_eval loads both the dry-run stub and the
        # live factory from it; the factory builds a solver without running it.
        # The live path itself is covered end-to-end (FakeLLM) in
        # test_agent_solver.py.
        dry = run_eval._load("agent_solver.py", "dry_run_solver")
        make = run_eval._load("agent_solver.py", "make_agent_solver")
        task = evals.EvalTask(task_id="task", prompt="What is the answer?")
        assert dry(task) == ""
        assert callable(make(max_dollars=0.25, max_wall_seconds=12))
