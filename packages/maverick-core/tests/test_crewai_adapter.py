"""crewai_adapter: CrewAI Task <-> Lightwork goal translation."""
from __future__ import annotations

import json

from maverick.tools.crewai_adapter import crewai_adapter


def _run(**kw):
    return crewai_adapter().fn(kw)


def test_task_spec_shape():
    out = _run(
        op="task_spec",
        description="Summarize the quarterly report.",
        expected_output="A 3-bullet summary.",
        agent_role="analyst",
    )
    spec = json.loads(out)
    assert spec == {
        "description": "Summarize the quarterly report.",
        "expected_output": "A 3-bullet summary.",
        "agent": "analyst",
    }


def test_to_maverick_goal_folds_expected_output():
    spec = {
        "description": "Write a blog post about CrewAI.",
        "expected_output": "An 800-word post in markdown.",
        "agent": "writer",
    }
    out = json.loads(_run(op="to_maverick_goal", task_spec=spec))
    assert out["goal"].startswith("Write a blog post about CrewAI.")
    assert "Acceptance criteria: An 800-word post in markdown." in out["goal"]
    assert out["metadata"] == {
        "source": "crewai",
        "agent_role": "writer",
        "expected_output": "An 800-word post in markdown.",
    }


def test_to_maverick_goal_without_expected_output():
    # expected_output is optional on the inbound spec; goal is just the description.
    out = json.loads(_run(op="to_maverick_goal", task_spec={"description": "Do the thing."}))
    assert out["goal"] == "Do the thing."
    assert out["metadata"]["expected_output"] == ""
    assert out["metadata"]["agent_role"] == ""


def test_round_trip():
    spec = json.loads(_run(op="task_spec", description="A", expected_output="B", agent_role="r"))
    goal = json.loads(_run(op="to_maverick_goal", task_spec=spec))
    assert goal["metadata"]["agent_role"] == "r"
    assert "Acceptance criteria: B" in goal["goal"]


def test_errors():
    t = crewai_adapter()
    assert t.fn({"op": "task_spec", "expected_output": "x", "agent_role": "r"}).startswith("ERROR")
    assert t.fn({"op": "task_spec", "description": "d", "agent_role": "r"}).startswith("ERROR")
    assert t.fn({"op": "task_spec", "description": "d", "expected_output": "x"}).startswith("ERROR")
    assert t.fn({"op": "to_maverick_goal", "task_spec": {}}).startswith("ERROR")
    assert t.fn({"op": "nope"}).startswith("ERROR")


def test_factory_contract():
    t = crewai_adapter()
    assert t.name == "crewai_adapter"
    assert t.parallel_safe is True
    assert set(t.input_schema["properties"]["op"]["enum"]) == {"task_spec", "to_maverick_goal"}
