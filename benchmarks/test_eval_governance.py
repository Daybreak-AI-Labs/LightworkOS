"""Offline checks for the governance benchmark suite (no LLM, no network).

These run in CI as part of the normal pytest suite, so a regression in any
governance control (approval gate, egress lock, capabilities, agent-trust,
signed audit) turns this red.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load(name: str):
    p = Path(__file__).parent / name
    spec = importlib.util.spec_from_file_location(f"benchmarks_{p.stem}", p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


gov = _load("eval_governance.py")


def test_suite_all_contained_and_no_false_block():
    s = gov.run_suite()
    failures = [r for r in s["scenarios"] if not (r["contained"] and r["utility_ok"])]
    assert s["ok"], failures
    assert s["prevention_rate"] == 1.0          # every unsafe vector contained
    assert s["utility_rate"] == 1.0             # no legitimate path falsely blocked
    assert s["n"] == len(gov.SCENARIOS)


def test_scenario_shape():
    for fn in gov.SCENARIOS:
        r = fn()
        assert {"scenario", "group", "contained", "utility_ok", "detail"} <= r.keys()
        assert isinstance(r["contained"], bool)
        assert isinstance(r["utility_ok"], bool)


def test_approval_gate_blocks_high_risk_but_not_reads():
    r = gov.scenario_approval_gate()
    assert r["contained"] and r["utility_ok"]
    assert "ERROR" in r["detail"]


def test_signed_evidence_records_and_detects_tamper():
    r = gov.scenario_signed_evidence()
    assert r["contained"]
    assert "recorded=True" in r["detail"]
    assert "clean_verifies=True" in r["detail"]
    assert "tamper_detected=True" in r["detail"]
