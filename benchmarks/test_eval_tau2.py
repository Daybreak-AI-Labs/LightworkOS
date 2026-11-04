"""tau2-style stateful tool-agent harness.

Drives eval_tau2 with deterministic solvers (no LLM): an oracle that performs
the right tool actions, a no-op, and partial solvers -- exercising BOTH grading
legs (final state AND required actions) on the shipped retail fixture.
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
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def tau2():
    return _load("eval_tau2.py")


def _oracle(task, tools):
    if task.task_id == "tau2-cancel":
        tools["cancel_order"]("O1")
    elif task.task_id == "tau2-address":
        tools["update_address"]("O2", "42 New St")
    elif task.task_id == "tau2-lookup":
        tools["get_order"]("O3")


# ---- end-to-end over the fixture --------------------------------------------

def test_oracle_solver_passes_all(tau2):
    s = tau2.run_tau2(_oracle)
    assert s["n"] == 3 and s["pass_at_1"] == 1.0


def test_noop_solver_fails_all(tau2):
    s = tau2.run_tau2(lambda t, tools: None)
    assert s["pass_at_1"] == 0.0


def test_load_tasks(tau2):
    assert {t.task_id for t in tau2.load_tasks()} == {
        "tau2-cancel", "tau2-address", "tau2-lookup"}


# ---- the two grading legs ---------------------------------------------------

def test_action_check_decides_the_pure_lookup(tau2):
    # tau2-lookup has no expected state change, so ONLY the required action
    # (get_order) decides it -- isolating the process check.
    miss = next(r for r in tau2.run_tau2(lambda t, tools: None)["results"]
                if r.task_id == "tau2-lookup")
    assert not miss.passed and "get_order" in miss.got

    def only_lookup(t, tools):
        if t.task_id == "tau2-lookup":
            tools["get_order"]("O3")

    hit = next(r for r in tau2.run_tau2(only_lookup)["results"]
               if r.task_id == "tau2-lookup")
    assert hit.passed


def test_outcome_check_catches_unmet_state(tau2):
    # Peeking at O1 but never cancelling: state stays pending AND the action is
    # missing -> fail, with `got` naming both legs.
    def peek(t, tools):
        tools["get_order"]("O1")

    r = tau2.run_tau2(peek, limit=1)["results"][0]  # limit=1 -> the cancel task
    assert r.task_id == "tau2-cancel" and not r.passed
    assert "state" in r.got and "cancel_order" in r.got


def test_wrong_action_args_fail_both_legs(tau2):
    # Right tool, wrong value: the address doesn't match (state) and the action
    # subset {address: '42 New St'} isn't satisfied (process).
    def wrong(t, tools):
        if t.task_id == "tau2-address":
            tools["update_address"]("O2", "WRONG")

    r = next(r for r in tau2.run_tau2(wrong)["results"] if r.task_id == "tau2-address")
    assert not r.passed and "state" in r.got and "update_address" in r.got


# ---- verify() unit + robustness ---------------------------------------------

def test_verify_requires_state_and_action(tau2):
    task = tau2.Tau2Task(
        task_id="t", prompt="p",
        expected_state={"orders.O1.status": "cancelled"},
        required_actions=[{"name": "cancel_order", "args": {"order_id": "O1"}}],
    )
    env = tau2.Tau2Env({"orders": {"O1": {"status": "cancelled"}}})
    # An extra arg on the logged call doesn't break the subset match.
    env.actions.append({"name": "cancel_order", "args": {"order_id": "O1", "reason": "x"}})
    assert tau2.verify(task, env) == (1.0, "ok")
    # State right, action absent -> fail.
    bare = tau2.Tau2Env({"orders": {"O1": {"status": "cancelled"}}})
    score, detail = tau2.verify(task, bare)
    assert score == 0.0 and "cancel_order" in detail


def test_solver_exception_scores_zero_not_crash(tau2):
    def boom(t, tools):
        raise RuntimeError("solver blew up")

    s = tau2.run_tau2(boom, limit=1)
    assert s["passed"] == 0 and "solver blew up" in s["results"][0].got
