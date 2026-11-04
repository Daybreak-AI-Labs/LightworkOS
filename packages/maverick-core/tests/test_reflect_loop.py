"""reflect_loop: plan-execute-reflect control-flow helper."""
from __future__ import annotations

from maverick.tools.reflect_loop import reflect_loop


def _run(**kw):
    return reflect_loop().fn(kw)


def test_plan_scaffold():
    out = _run(op="plan", goal="ship the feature", max_steps=3)
    lines = out.splitlines()
    assert lines[0] == "Plan for: ship the feature (3 step(s))"
    assert lines[1] == "1. Clarify the goal and success criteria"
    assert len([ln for ln in lines if ln[:1].isdigit()]) == 3


def test_plan_caps_at_phase_count():
    out = _run(op="plan", goal="g", max_steps=99)
    assert "(7 step(s))" in out
    assert "capped at 7 phase(s) (requested 99)" in out


def test_reflect_advance_on_success():
    out = _run(op="reflect", step=2, observation="tests pass", succeeded=True)
    assert out.startswith("ADVANCE: step=2")
    assert "proceed to the next step" in out
    assert "observation: tests pass" in out


def test_reflect_retry_when_attempts_remain():
    out = _run(op="reflect", step=1, observation="flaky",
               succeeded=False, attempts=1, max_attempts=3)
    assert out.startswith("RETRY: step=1")
    assert "attempt 2/3" in out


def test_reflect_replan_when_out_of_retries():
    out = _run(op="reflect", step=1, observation="broken",
               succeeded=False, attempts=3, max_attempts=3)
    assert out.startswith("REPLAN: step=1")
    assert "after 3/3 attempt(s)" in out


def test_errors():
    assert _run(op="plan").startswith("ERROR")  # no goal
    assert _run(op="plan", goal="g", max_steps=0).startswith("ERROR")
    assert _run(op="reflect", step=1, observation="x").startswith("ERROR")  # no succeeded
    assert _run(op="reflect", observation="x", succeeded=True).startswith("ERROR")  # no step
    assert _run(op="reflect", step=1, succeeded=True).startswith("ERROR")  # no observation
    assert _run(op="reflect", step=1, observation="x", succeeded="yes").startswith("ERROR")
    assert _run(op="bogus").startswith("ERROR")
