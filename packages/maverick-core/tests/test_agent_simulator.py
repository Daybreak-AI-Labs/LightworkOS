"""agent_simulator: deterministic scripted-replay harness."""
from __future__ import annotations

from maverick.tools.agent_simulator import agent_simulator


def _run(**kw):
    return agent_simulator().fn({"op": "run", **kw})


def test_all_steps_pass():
    out = _run(
        script=[
            {"step": 1, "action": "read", "expect": "ok"},
            {"step": 2, "action": "write", "expect": "done"},
        ],
        world=[
            {"action": "read", "result": "ok"},
            {"action": "write", "result": "done"},
        ],
    )
    assert out.startswith("PASS: 2/2 step(s) matched expect")
    assert "step 1: PASS" in out and "step 2: PASS" in out


def test_mismatch_fails_step():
    out = _run(
        script=[{"action": "read", "expect": "ok"}],
        world=[{"action": "read", "result": "denied"}],
    )
    assert out.startswith("FAIL: 0/1")
    assert "expected='ok'" in out and "got='denied'" in out


def test_missing_world_response():
    out = _run(
        script=[{"action": "deploy", "expect": "ok"}],
        world=[],
    )
    assert out.startswith("FAIL")
    assert "no world response" in out


def test_repeated_action_consumes_successive_responses():
    out = _run(
        script=[
            {"step": "a", "action": "poll", "expect": "pending"},
            {"step": "b", "action": "poll", "expect": "ready"},
        ],
        world=[
            {"action": "poll", "result": "pending"},
            {"action": "poll", "result": "ready"},
        ],
    )
    assert out.startswith("PASS: 2/2")


def test_partial_summary_counts():
    out = _run(
        script=[
            {"action": "a", "expect": "1"},
            {"action": "b", "expect": "2"},
        ],
        world=[
            {"action": "a", "result": "1"},
            {"action": "b", "result": "X"},
        ],
    )
    assert out.startswith("FAIL: 1/2 step(s) matched expect")


def test_errors():
    t = agent_simulator()
    assert t.fn({"op": "run", "world": []}).startswith("ERROR")  # no script
    assert t.fn({"op": "run", "script": []}).startswith("ERROR")  # no world
    assert t.fn({"op": "nope", "script": [], "world": []}).startswith("ERROR")
