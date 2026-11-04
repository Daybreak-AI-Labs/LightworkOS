"""The adversarial-cost regression gate.

``eval_adversarial_cost.run_suite()`` scripts the money-wasting failure modes
(tool loop, token bomb, runaway iterations) against the real cost-control
layer -- no LLM, no network -- and asserts each is clamped. These tests prove
the gate is green today AND that it has teeth: an unclamped scenario must
flip ``main()`` to a non-zero exit.
"""
from __future__ import annotations

import importlib.util
import os
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
def suite():
    return _load("eval_adversarial_cost.py")


def test_every_scenario_clamps(suite):
    summary = suite.run_suite()
    assert summary["ok"] is True
    assert [r["scenario"] for r in summary["scenarios"]] == [
        "tool-loop", "token-bomb", "runaway-iterations",
    ]
    assert all(r["clamped"] is True for r in summary["scenarios"])


def test_harness_shape(suite):
    for result in suite.run_suite()["scenarios"]:
        assert set(result) == {"scenario", "clamped", "detail"}
        assert isinstance(result["clamped"], bool)
        assert isinstance(result["detail"], str) and result["detail"]


def test_tool_loop_pays_at_most_once(suite):
    result = suite.scenario_tool_loop()
    assert result["clamped"] is True
    assert "1 paid execution(s), 100 served" in result["detail"]


def test_tool_loop_leaves_no_residue(suite):
    from maverick.cache import tool as tool_cache

    prior_env = os.environ.get("MAVERICK_TOOL_CACHE")
    suite.scenario_tool_loop()
    assert os.environ.get("MAVERICK_TOOL_CACHE") == prior_env
    assert tool_cache.stats()["size"] == 0  # reset() ran on the way out


def test_token_bomb_is_capped(suite):
    from maverick.agent import _MAX_TOOL_RESULT_BYTES

    result = suite.scenario_token_bomb()
    assert result["clamped"] is True
    assert str(_MAX_TOOL_RESULT_BYTES) in result["detail"]


def test_runaway_iterations_halt_at_the_cap(suite):
    result = suite.scenario_runaway_iterations()
    assert result["clamped"] is True
    assert "halted after 25 of 1000" in result["detail"]


def test_main_returns_zero_when_green(suite, capsys):
    assert suite.main() == 0
    out = capsys.readouterr().out
    assert "eval-adversarial-cost OK" in out


# ---- the gate has teeth -------------------------------------------------------

def test_main_returns_one_on_an_unclamped_scenario(suite, monkeypatch, capsys):
    def _regressed():
        return {"scenario": "regressed", "clamped": False, "detail": "leak"}

    monkeypatch.setattr(suite, "SCENARIOS", (_regressed,))
    assert suite.main() == 1
    assert "regressed" in capsys.readouterr().err


def test_run_suite_reports_not_ok_on_any_unclamped(suite, monkeypatch):
    real = suite.SCENARIOS

    def _regressed():
        return {"scenario": "regressed", "clamped": False, "detail": "leak"}

    monkeypatch.setattr(suite, "SCENARIOS", (*real, _regressed))
    summary = suite.run_suite()
    assert summary["ok"] is False
    assert [r["clamped"] for r in summary["scenarios"]].count(False) == 1
