"""A question that already says what the agent would do is not sent."""
from __future__ import annotations

import pytest
from maverick.budget import Budget
from maverick.llm import ToolCall
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.tools.ask_user import ask_user
from maverick.world_model import WorldModel

# Live: a business-plan task stopped to ask this, and waited for an answer.
_OWN_CHOICE = ("Should I base the budget on a conservative, base-case, or aggressive sales ramp? I recommend "
               "base-case. If you have assumptions, send them now; otherwise I'll use reasonable Austin cafe "
               "assumptions.")


@pytest.mark.parametrize("question", [
    _OWN_CHOICE,
    "Which format do you want, PDF or Word? I'd suggest PDF.",
    "Do you have a logo to include? If not, I'll leave a placeholder.",
    "What tone? By default I'll keep it friendly and professional.",
])
def test_a_question_with_the_agents_own_answer_is_not_sent(tmp_path, question):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("business plan", "")
    out = ask_user(world, gid).fn({"question": question})
    assert out.startswith("NOT ASKED") and "say which assumption" in out
    assert world.all_questions(gid) == []


def test_a_question_only_the_person_can_answer_is_queued(tmp_path):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("invoice", "")
    out = ask_user(world, gid).fn({"question": "What is the client's billing address?"})
    assert out.startswith("QUEUED question #") and len(world.all_questions(gid)) == 1


@pytest.mark.asyncio
async def test_a_run_whose_question_had_its_own_answer_finishes(tmp_path, fake_llm, make_llm_response):
    fake_llm.scripted = [
        make_llm_response(text="Checking.", tool_calls=[ToolCall(id="q1", name="ask_user", input={"question": _OWN_CHOICE})]),
        make_llm_response(text="FINAL: Budget on a base-case ramp (assumed)."),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)")]
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("budget for a second cafe", "", owner="alice")

    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)

    assert world.get_goal(gid).status == "done" and world.all_questions(gid) == []
