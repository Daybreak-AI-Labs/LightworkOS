"""skill_distill_v2: distill a reusable skill from a successful trace."""
from __future__ import annotations

import json

from maverick.tools.skill_distill import skill_distill_v2


def _distill(trace, goal):
    return skill_distill_v2().fn({"op": "distill", "trace": trace, "goal": goal})


def _spec(out: str):
    return json.loads(out.split("\n", 1)[1])


def test_distill_basic_spec():
    trace = [
        {"action": "open repo", "tool": "read_file", "ok": True},
        {"action": "run tests", "tool": "shell", "ok": True},
    ]
    spec = _spec(_distill(trace, "Fix the failing build"))
    assert spec["triggers"] == ["Fix the failing build"]
    assert spec["tools_needed"] == ["read_file", "shell"]
    assert [s["action"] for s in spec["steps"]] == ["open repo", "run tests"]
    assert spec["name"] == "fix_the_failing_build"


def test_drops_failed_steps():
    trace = [
        {"action": "good", "tool": "shell", "ok": True},
        {"action": "bad", "tool": "shell", "ok": False},
    ]
    spec = _spec(_distill(trace, "g"))
    assert [s["action"] for s in spec["steps"]] == ["good"]


def test_dedupes_tools_preserving_order():
    trace = [
        {"action": "a", "tool": "shell", "ok": True},
        {"action": "b", "tool": "read_file", "ok": True},
        {"action": "c", "tool": "shell", "ok": True},
    ]
    spec = _spec(_distill(trace, "g"))
    assert spec["tools_needed"] == ["shell", "read_file"]
    assert len(spec["steps"]) == 3


def test_drops_noise_actions():
    trace = [
        {"action": "think", "tool": "", "ok": True},
        {"action": "wait", "ok": True},
        {"action": "edit file", "tool": "str_replace_editor", "ok": True},
    ]
    spec = _spec(_distill(trace, "g"))
    assert [s["action"] for s in spec["steps"]] == ["edit file"]
    assert spec["tools_needed"] == ["str_replace_editor"]


def test_no_successful_steps_is_error():
    out = _distill([{"action": "x", "tool": "shell", "ok": False}], "g")
    assert out.startswith("ERROR") and "no successful" in out


def test_errors():
    t = skill_distill_v2()
    assert t.fn({"op": "distill", "trace": [], "goal": "g"}).startswith("ERROR")
    assert t.fn({"op": "distill", "trace": [{"action": "a", "ok": True}]}).startswith("ERROR")
    assert t.fn({"op": "nope", "trace": [{"action": "a", "ok": True}], "goal": "g"}).startswith("ERROR")
