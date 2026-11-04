"""An audit refusal at a twin hold must not become permission to dispatch."""
from __future__ import annotations

from contextlib import contextmanager
from importlib import import_module
from types import SimpleNamespace

import pytest
from maverick.agent import Agent
from maverick.audit import AuditRefused, AuditWriteRefused, EventKind
from maverick.audit.signing import OffHostSigningRequiredError
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.llm import LLMResponse, ToolCall
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel


class _CapturingLLM:
    model = "fake:test"

    def __init__(self, calls):
        self.calls = calls
        self.messages = None
        self.turns = 0

    async def complete_async(self, *, messages, **_kwargs):
        self.messages = messages
        self.turns += 1
        return LLMResponse(
            text="acting" if self.turns == 1 else "FINAL: done",
            thinking=None,
            tool_calls=self.calls if self.turns == 1 else [],
            stop_reason="tool_use" if self.turns == 1 else "end_turn",
        )


def _agent(tmp_path, monkeypatch, gate, names):
    from maverick import data_engine, negative_knowledge, rehearsal, rehearsal_runtime
    from maverick.safety import consent

    tool_risk = import_module("maverick.safety.tool_risk")

    llm = _CapturingLLM([
        ToolCall(id=f"call-{i}", name=name, input={})
        for i, name in enumerate(names)
    ])
    world = WorldModel(tmp_path / "world.db")
    ctx = SwarmContext(
        llm=llm, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=world.create_goal("twin audit refusal", ""),
        max_depth=2, use_skills=False,
    )
    agent = Agent(ctx=ctx, role="researcher", brief="exercise the twin hold")
    held_name = names[0]
    monkeypatch.setattr(rehearsal, "enabled", lambda: gate != "guardrail")
    monkeypatch.setattr(rehearsal, "enforcing", lambda: gate != "guardrail")
    monkeypatch.setattr(data_engine, "enabled", lambda: gate == "guardrail")
    monkeypatch.setattr(tool_risk, "tool_risk", lambda name: "high" if name == held_name else "low")
    monkeypatch.setattr(rehearsal_runtime, "gate_tool", lambda **_kw: SimpleNamespace(
        decision=gate, reason="held by the test twin", known=False,
    ))
    def reject_review(*_args, **_kwargs):
        raise consent.ConsentDenied("rehearsal")

    monkeypatch.setattr(consent, "require_operation_consent", reject_review)
    monkeypatch.setattr(negative_knowledge, "shared", lambda: SimpleNamespace(
        consult=lambda name: SimpleNamespace(rule="held by the test guardrail")
        if name == held_name else None,
    ))
    # Leave the twin and dispatch audit real. Make unrelated later authorization
    # gates permissive so another denial cannot mask the audited-hold regression.
    monkeypatch.setattr(agent, "_autonomy_denial", lambda *_args: None)

    async def allowed(*_args):
        return None, ()

    monkeypatch.setattr(agent, "_governance_denial", allowed)
    dispatched = []

    async def run_tool(name, _args):
        dispatched.append(name)
        return f"completed {name}"

    monkeypatch.setattr(agent.tools, "run", run_tool)
    return agent, llm, dispatched


def _selective_audit(monkeypatch, error):
    import maverick.audit as audit

    seen = []

    def record(kind, **_payload):
        seen.append(kind)
        if kind == EventKind.SHIELD_BLOCK:
            raise error
        return True  # The later TOOL_CALL writer is explicitly healthy.

    monkeypatch.setattr(audit, "record", record)
    return seen


def _answers(llm):
    assistant = next(
        i for i, message in enumerate(llm.messages)
        if message["role"] == "assistant"
        and any(block.get("type") == "tool_use" for block in message["content"])
    )
    reply = llm.messages[assistant + 1]
    assert reply["role"] == "user"
    answers = [block for block in reply["content"] if block.get("type") == "tool_result"]
    assert [block["tool_use_id"] for block in answers] == [call.id for call in llm.calls]
    return answers


@pytest.mark.asyncio
async def test_explicit_hold_stops_when_prediction_is_unavailable(tmp_path, monkeypatch):
    from maverick import rehearsal_runtime

    agent, _llm, dispatched = _agent(tmp_path, monkeypatch, "escalate", ["shell"])

    def unavailable(**_kwargs):
        raise RuntimeError("synthetic prediction unavailable")

    monkeypatch.setattr(rehearsal_runtime, "gate_tool", unavailable)
    denial, prediction = await agent._rehearsal_check("shell", {})
    assert prediction is None
    assert denial is not None and "could not check" in denial
    assert not dispatched


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict", ["escalate", "block"])
@pytest.mark.parametrize("hold", [False, True])
async def test_rehearsal_observation_runs_tool_but_hold_does_not_train_it(
    tmp_path, monkeypatch, hold, verdict,
):
    from maverick import rehearsal, trajectory_store

    agent, llm, dispatched = _agent(tmp_path, monkeypatch, verdict, ["shell"])
    monkeypatch.setattr(rehearsal, "enforcing", lambda: hold)
    captured = []
    monkeypatch.setattr(trajectory_store, "capture_step", captured.append)

    await agent.run()

    answer = str(_answers(llm)[0]["content"])
    tool_steps = [step for step in captured if step.tool == "shell"]
    if hold:
        assert dispatched == []
        assert "not granted or expired" in answer
        assert tool_steps == []
        assert getattr(agent, "_actions", []) == []
    else:
        assert dispatched == ["shell"]
        assert "completed shell" in answer
        assert len(tool_steps) == 1
        assert tool_steps[0].tool_executed is True
        assert agent._actions == ["shell"]


@pytest.mark.asyncio
async def test_observation_does_not_bypass_later_tool_authorization(tmp_path, monkeypatch):
    from maverick import rehearsal

    agent, _llm, dispatched = _agent(tmp_path, monkeypatch, "escalate", ["shell"])
    monkeypatch.setattr(rehearsal, "enforcing", lambda: False)
    monkeypatch.setattr(agent, "_autonomy_denial", lambda *_args: "BLOCKED by autonomy")

    result = await agent._run_tool("shell", {})

    assert "BLOCKED by autonomy" in result
    assert dispatched == []
    assert getattr(agent, "_actions", []) == []


@pytest.mark.asyncio
async def test_hold_review_releases_exact_step_but_not_later_safety_gates(tmp_path, monkeypatch):
    from maverick.safety import consent

    agent, _llm, dispatched = _agent(tmp_path, monkeypatch, "escalate", ["shell"])
    reviewed = []

    def approve(_action, **kwargs):
        reviewed.append(kwargs)
        assert kwargs["require_fresh_person"] is True
        assert kwargs["provenance"] == "rehearsal"
        assert kwargs["parameters"]["arguments"] == {
            "cmd": "first" if len(reviewed) == 1 else "second",
        }
        return object()

    @contextmanager
    def consume(_permit):
        yield {}

    monkeypatch.setattr(consent, "require_operation_consent", approve)
    monkeypatch.setattr(consent, "consume_operation_consent", consume)
    allowed = await agent._run_tool("shell", {"cmd": "first"})
    assert "completed shell" in allowed
    assert len(reviewed) == 1
    assert dispatched == ["shell"]

    monkeypatch.setattr(agent, "_autonomy_denial", lambda *_args: "BLOCKED by autonomy")
    blocked = await agent._run_tool("shell", {"cmd": "second"})
    assert "BLOCKED by autonomy" in blocked
    assert len(reviewed) == 2
    assert dispatched == ["shell"]


@pytest.mark.asyncio
async def test_rehearsal_prediction_is_pinned_only_after_dispatch_gates(tmp_path, monkeypatch):
    from maverick import earned_autonomy, rehearsal, rehearsal_runtime

    agent, _llm, dispatched = _agent(tmp_path, monkeypatch, "proceed", ["shell"])
    monkeypatch.setattr(rehearsal, "enforcing", lambda: False)
    monkeypatch.setattr(rehearsal_runtime, "gate_tool", lambda **_kw: SimpleNamespace(
        decision="proceed", reason="known result", known=True,
        predicted_outcome=0.8,
    ))
    predictions = []
    monkeypatch.setattr(earned_autonomy, "capture_prediction", lambda *_a, **kw: predictions.append(kw))
    monkeypatch.setattr(agent, "_autonomy_denial", lambda *_args: "BLOCKED by autonomy")

    denied = await agent._run_tool("shell", {})

    assert "BLOCKED by autonomy" in denied
    assert dispatched == []
    assert predictions == []

    monkeypatch.setattr(agent, "_autonomy_denial", lambda *_args: None)
    result = await agent._run_tool("shell", {})

    assert "completed shell" in result
    assert dispatched == ["shell"]
    assert len(predictions) == 1
    assert predictions[0]["action"] == "shell"


@pytest.mark.asyncio
@pytest.mark.parametrize("gate", ["block", "escalate", "guardrail"])
@pytest.mark.parametrize("error_type", [AuditWriteRefused, OffHostSigningRequiredError])
async def test_selective_hold_refusal_stops_serial_dispatch_and_answers_history(
    tmp_path, monkeypatch, gate, error_type,
):
    agent, llm, dispatched = _agent(tmp_path, monkeypatch, gate, ["shell", "shell"])
    error = error_type("test signing policy refusal")
    seen = _selective_audit(monkeypatch, error)

    caught = None
    try:
        await agent.run()
    except AuditRefused as exc:
        caught = exc

    assert dispatched == []
    assert caught is error
    assert EventKind.SHIELD_BLOCK in seen and "tool_call" not in seen
    assert llm.turns == 1
    assert all("audit" in str(answer["content"]).lower() for answer in _answers(llm))


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [AuditWriteRefused, OffHostSigningRequiredError])
async def test_parallel_refusal_preserves_completed_sibling_and_stops_next_turn(
    tmp_path, monkeypatch, error_type,
):
    monkeypatch.setenv("MAVERICK_PARALLEL_TOOLS", "1")
    agent, llm, dispatched = _agent(tmp_path, monkeypatch, "guardrail", ["read_file", "list_dir"])
    error = error_type("test signing policy refusal")
    seen = _selective_audit(monkeypatch, error)

    caught = None
    try:
        await agent.run()
    except AuditRefused as exc:
        caught = exc

    assert dispatched == ["list_dir"]
    assert caught is error
    assert "tool_call" in seen  # A parallel sibling can already have run.
    assert llm.turns == 1
    answers = _answers(llm)
    assert "audit" in str(answers[0]["content"]).lower()
    assert "completed list_dir" in str(answers[1]["content"])


@pytest.mark.asyncio
@pytest.mark.parametrize("gate", ["block", "escalate", "guardrail"])
async def test_incidental_audit_failure_keeps_the_existing_hold(
    tmp_path, monkeypatch, gate,
):
    agent, _llm, dispatched = _agent(tmp_path, monkeypatch, gate, ["shell"])
    _selective_audit(monkeypatch, OSError("ordinary writer outage"))

    result = await agent._run_tool("shell", {})

    assert ("paused" if gate != "guardrail" else "held") in result.lower()
    assert dispatched == []


@pytest.mark.asyncio
@pytest.mark.parametrize("stop_kind", ["budget", "halt"])
@pytest.mark.parametrize("reverse", [False, True])
async def test_parallel_mixed_stops_preserve_completed_and_uncertain_results(
    tmp_path, monkeypatch, stop_kind, reverse,
):
    from maverick.budget import BudgetExceeded
    from maverick.killswitch import Halted

    monkeypatch.setenv("MAVERICK_PARALLEL_TOOLS", "1")
    agent, llm, dispatched = _agent(
        tmp_path, monkeypatch, "guardrail", ["read_file", "list_dir", "repo_map"],
    )
    if reverse:
        llm.calls.reverse()
    stop = BudgetExceeded("after dispatch") if stop_kind == "budget" else Halted("after dispatch", "test")
    _selective_audit(monkeypatch, AuditWriteRefused("hold audit refused"))

    async def tool(name, _args):
        dispatched.append(name)
        if name == "repo_map":
            raise stop
        return f"completed {name}"

    monkeypatch.setattr(agent.tools, "run", tool)
    with pytest.raises(type(stop)) as caught:
        await agent.run()

    assert caught.value is stop
    assert sorted(dispatched) == ["list_dir", "repo_map"]
    assert llm.turns == 1
    answers = {call.name: answer for call, answer in zip(llm.calls, _answers(llm), strict=True)}
    assert "completed list_dir" in str(answers["list_dir"]["content"])
    assert "audit" in str(answers["read_file"]["content"]).lower()
    assert "not executed" not in str(answers["repo_map"]["content"]).lower()
    assert "reconcile" in str(answers["repo_map"]["content"]).lower()


@pytest.mark.asyncio
@pytest.mark.parametrize("stop_kind", ["budget", "halt"])
async def test_serial_post_dispatch_stop_does_not_claim_no_execution(
    tmp_path, monkeypatch, stop_kind,
):
    from maverick.budget import BudgetExceeded
    from maverick.killswitch import Halted

    agent, llm, dispatched = _agent(
        tmp_path, monkeypatch, "guardrail", ["list_dir", "shell", "shell"],
    )
    async def no_twin_hold(_name, _args):
        return None, None

    monkeypatch.setattr(agent, "_twin_check", no_twin_hold)
    _selective_audit(monkeypatch, AuditWriteRefused("unused hold refusal"))
    stop = BudgetExceeded("after dispatch") if stop_kind == "budget" else Halted("after dispatch", "test")

    async def tool(name, _args):
        dispatched.append(name)
        if name == "shell":
            raise stop
        return f"completed {name}"

    monkeypatch.setattr(agent.tools, "run", tool)
    with pytest.raises(type(stop)) as caught:
        await agent.run()

    assert caught.value is stop
    assert dispatched == ["list_dir", "shell"]
    assert llm.turns == 1
    answers = _answers(llm)
    assert "completed list_dir" in str(answers[0]["content"])
    assert "not executed" not in str(answers[1]["content"]).lower()
    assert "reconcile" in str(answers[1]["content"]).lower()
