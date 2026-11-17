"""The factory checker benchmark (benchmarks/eval_factory_checker.py): its
corpus keeps its promises, and its self-test proves the scoring through the
real feature-run path with stub checkers. No model runs here."""
from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

REPO = Path(__file__).resolve().parents[3]
RUNNER = REPO / "benchmarks" / "eval_factory_checker.py"


def _load():
    spec = importlib.util.spec_from_file_location("benchmarks_eval_factory_checker", RUNNER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fc = _load()


def _results_now() -> set[Path]:
    return set(fc.RESULTS.rglob("*")) if fc.RESULTS.exists() else set()


def test_every_case_keeps_its_promises():
    cases = fc.load_cases()
    clean = [c for c in cases if c.verdict == "clean"]
    assert len(cases) >= 24 and 3 * len(clean) >= len(cases)
    assert {c.defect["kind"] for c in cases if c.defect} == set(fc.KINDS)
    # Tests pass on the base and on the change (the factory's own test tier
    # cannot see the defect); each repro passes on the base and fails on the change.
    assert fc.validate() == []


def test_self_test_scores_perfect_silent_and_noisy_stubs(monkeypatch):
    monkeypatch.setenv("MAVERICK_SUPPRESS_SANDBOX_WARNING", "1")
    before = _results_now()
    summary = fc.self_test()
    assert summary["ok"], summary["problems"]
    s = summary["scores"]
    perfect, silent, noisy = s["checker 1"], s["checker 2"], s["checker 3"]
    assert (perfect["recall"], perfect["confirmed_by_repro_rate"], perfect["false_alarms"]) \
        == (1.0, 1.0, 0)
    assert (silent["recall"], silent["false_alarm_rate"]) == (0.0, 0.0)
    # Noise is never a find: its finding names another file, and its repro,
    # which Lightwork confirms on the change, fails on the base as well.
    assert noisy["recall"] == 0.0 and noisy["repros_confirmed"] == summary["cases"]
    assert noisy["false_alarm_rate"] == 1.0
    assert s["panel"]["recall"] == 1.0 and summary["cost"]["tokens_per_case"] == 1650
    assert _results_now() == before  # the self-test writes nothing here


def test_a_live_run_refuses_without_a_model_key(monkeypatch, capsys):
    from maverick import config
    monkeypatch.setattr(config, "any_provider_configured", lambda: False)
    before = _results_now()
    assert fc.main([]) == 2
    assert "No model key is set up" in capsys.readouterr().err
    assert _results_now() == before


def test_a_failed_checker_keeps_the_next_checkers_repro_in_its_own_slot(monkeypatch):
    # Checker 1 stops with an error; checker 2's raw output must still be read
    # as checker 2's, or its repro loses its probe file on the base and the
    # confirmed-by-repro rate is wrong.
    from maverick.budget import Budget
    monkeypatch.setenv("MAVERICK_SUPPRESS_SANDBOX_WARNING", "1")
    case = next(c for c in fc.load_cases() if c.verdict == "defect")
    python = fc.shlex.quote(sys.executable)

    def make(case, budget):
        def broken(_goal_id, _copy):
            raise RuntimeError("the checker stopped")
        return [broken, fc.stub_checkers(case, budget, python)[0]]

    with fc.isolated_home():
        [row] = fc.run_cases([case], make, lambda: Budget(
            max_dollars=10.0, max_wall_seconds=900.0, max_tool_calls=1000),
            sandbox_factory=fc.StandInContainer, python=python)
    first, second = row["checkers"]
    assert first["error"] and not first["ran"]
    assert second["repros_confirmed"] == 1 and second["found_by_repro"]
