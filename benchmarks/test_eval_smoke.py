"""The offline eval-harness regression gate.

``eval_smoke.run_smoke()`` drives the real harness (registry + framework +
tau2 verifier) against scripted solvers -- no LLM, no network -- and asserts
each benchmark grades a known-good case 1.0 and a known-bad case 0.0. These
tests prove the gate is green today AND that it has teeth: when a scorer is
broken, the gate raises rather than passing silently.
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
def smoke():
    return _load("eval_smoke.py")


def test_run_smoke_is_green(smoke):
    summary = smoke.run_smoke()
    assert summary["ok"] is True
    labels = {c["check"] for c in summary["checks"]}
    # Both benchmarks, both legs (a known-good and a known-bad each).
    assert labels == {"gaia/oracle", "gaia/wrong", "tau2/oracle", "tau2/noop"}


def test_smoke_asserts_both_good_and_bad(smoke):
    # The known-good checks must report a perfect score and the known-bad
    # ones a zero -- that pairing is what makes a regression detectable.
    by_label = {c["check"]: c["pass_at_1"] for c in smoke.run_smoke()["checks"]}
    assert by_label["gaia/oracle"] == 1.0 and by_label["tau2/oracle"] == 1.0
    assert by_label["gaia/wrong"] == 0.0 and by_label["tau2/noop"] == 0.0


def test_main_returns_zero_when_green(smoke):
    assert smoke.main() == 0


# ---- the gate has teeth -----------------------------------------------------

def test_gate_trips_when_scorer_regresses(smoke, monkeypatch):
    # Simulate a harness regression: a scorer that calls everything correct.
    # The known-bad GAIA case would then score 1.0, so the gate MUST raise.
    evals = smoke._load("evals.py")
    monkeypatch.setattr(evals, "run_benchmark", lambda *a, **k: {"pass_at_1": 1.0})
    with pytest.raises(smoke.SmokeFailure, match="gaia/wrong"):
        smoke.run_smoke()


def test_gate_trips_when_verifier_regresses(smoke, monkeypatch):
    # Same, for tau2: a verifier that passes everything makes the no-op
    # (known-bad) case score 1.0 -- the gate must catch it.
    tau2 = smoke._load("eval_tau2.py")
    monkeypatch.setattr(tau2, "run_tau2", lambda *a, **k: {"pass_at_1": 1.0})
    with pytest.raises(smoke.SmokeFailure, match="tau2/noop"):
        smoke.run_smoke()


def test_main_returns_one_when_gate_trips(smoke, monkeypatch):
    evals = smoke._load("evals.py")
    monkeypatch.setattr(evals, "run_benchmark", lambda *a, **k: {"pass_at_1": 0.0})
    # gaia/oracle now scores 0.0 -> SmokeFailure -> main() exits non-zero.
    assert smoke.main() == 1
