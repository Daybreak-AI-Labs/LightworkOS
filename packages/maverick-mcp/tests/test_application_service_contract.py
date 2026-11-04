"""Application tools use the admitted caller and preserve structured results."""
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from maverick_mcp.application import ApplicationDependencies, MCPApplication
from maverick_mcp.protocol import ProtocolError


def _application(world, *, principal="alice", structured=None):
    @contextmanager
    def open_world():
        yield world

    return MCPApplication(ApplicationDependencies(
        world_factory=open_world,
        shield=None,
        shield_scan_reason=lambda *args, **kwargs: None,
        current_principal=lambda: principal,
        goal_for_principal=lambda *args: None,
        task_budget=lambda *args: None,
        bounded_int=lambda value, **kwargs: int(value),
        setting=lambda name, default: default,
        set_structured=(structured if structured is not None else lambda value: None),
    ))


def test_status_scopes_goals_and_open_questions_to_the_caller():
    calls = []
    goal = SimpleNamespace(id=7, status="active", title="Allowed")
    world = SimpleNamespace(
        list_goals=lambda **kwargs: calls.append(kwargs) or [goal],
        open_questions=lambda: [
            SimpleNamespace(id=1, goal_id=7, question="Visible"),
            SimpleNamespace(id=2, goal_id=8, question="Foreign"),
        ],
    )
    app = _application(world)
    result = app._structured_result("maverick_status")
    assert result["goals"] == [{"id": 7, "status": "active", "title": "Allowed"}]
    assert result["open_questions"] == [{"id": 1, "goal_id": 7, "question": "Visible"}]
    assert calls == [{"owner": "alice"}]


def test_answer_hides_foreign_question_and_does_not_set_structured_result():
    calls = []
    output = []
    world = SimpleNamespace(answer=lambda *args, **kwargs: calls.append((args, kwargs)) or False)
    app = _application(world, structured=output.append)
    with pytest.raises(ProtocolError, match="question not found") as error:
        app._tool_answer({"question_id": 12, "answer": "reply"})
    assert error.value.code == -32602
    assert calls == [((12, "reply"), {"expected_owner": "alice"})]
    assert output == []
