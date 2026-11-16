"""Decision requests: a run asks a person to choose, pauses, and continues
with the chosen option as a structured record (maverick.decision_requests)."""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import decision_requests as dr
from maverick.budget import Budget
from maverick.llm import ToolCall
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel

_REQUEST = {
    "question": "May this workspace keep chat logs for two years?",
    "options": [
        {"label": "Keep 90 days", "effect": "Logs older than 90 days are erased."},
        {"label": "Keep two years", "effect": "Logs stay for two years, then are erased."},
    ],
    "recommended": 1,
    "why": "The current policy says 90 days.",
    "area": "data_erasure_retention",
}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.delenv("MAVERICK_ALLOW_SELF_APPROVAL", raising=False)
    from maverick import config

    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _world(tmp_path: Path) -> WorldModel:
    return WorldModel(path=tmp_path / "world.db")


def _paused_goal(world, *, owner="alice", area="data_erasure_retention"):
    gid = world.create_goal("tidy the retention settings", "", owner=owner)
    world.set_goal_status(gid, "blocked")
    decision = dr.request(world, gid, **{**dr.validate({**_REQUEST, "area": area})})
    return gid, decision


async def _run(world, gid, fake_llm, tmp_path, budget=None):
    return await run_goal(llm=fake_llm, world=world, budget=budget or Budget(max_dollars=1.0),
                          goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1)


@pytest.mark.asyncio
async def test_a_run_that_asks_pauses_without_spending_even_headless(
        tmp_path, fake_llm, make_llm_response, monkeypatch):
    # Headless runs assume past ask_user; a decision is never auto-answered.
    monkeypatch.setenv("MAVERICK_AUTONOMOUS", "1")
    fake_llm.scripted = [make_llm_response(
        text="A person must decide this.",
        tool_calls=[ToolCall(id="t1", name="request_decision", input=_REQUEST)])]
    world = _world(tmp_path)
    gid = world.create_goal("tidy the retention settings", "", owner="alice")
    budget = Budget(max_dollars=1.0)

    out = await _run(world, gid, fake_llm, tmp_path, budget)

    goal = world.get_goal(gid)
    assert goal.status == "blocked"
    assert goal.result == f"Waiting for a person to decide: {_REQUEST['question']}"
    assert "Paused" in out and "maverick decisions answer" in out
    [waiting] = dr.open_for_goal(world, gid)
    assert (waiting.recommended, waiting.area, waiting.requested_by) == (1, "data_erasure_retention", "alice")
    # run_goal returned instead of waiting: one model call, the episode is
    # closed, and no process holds the budget while a person decides.
    assert len(fake_llm.calls) == 1
    assert all(e.ended_at is not None for e in world.list_episodes())
    from maverick.runner import inflight_goals

    assert inflight_goals() == 0


@pytest.mark.asyncio
async def test_an_answer_resumes_the_run_with_the_chosen_option(
        tmp_path, fake_llm, make_llm_response):
    world = _world(tmp_path)
    gid, decision = _paused_goal(world)

    outcome = dr.answer(world, decision.id, 2, actor="alice", is_admin=False,
                        note="Legal agreed.")

    assert outcome["resume"] is True and world.get_goal(gid).status == "pending"
    fake_llm.scripted = [
        make_llm_response(text="FINAL: kept for two years"),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)"),
    ]
    await _run(world, gid, fake_llm, tmp_path)
    first = str(fake_llm.calls[0].get("messages", ""))
    assert '"outcome": "chosen"' in first and '"option": 2' in first
    assert '"label": "Keep two years"' in first and '"note": "Legal agreed."' in first
    assert world.get_goal(gid).status == "done"


def test_a_person_without_authority_is_refused(tmp_path):
    world = _world(tmp_path)
    gid, decision = _paused_goal(world)

    with pytest.raises(dr.DecisionRefused) as refused:
        dr.answer(world, decision.id, 1, actor="mallory", is_admin=False)

    assert refused.value.reason == "not_permitted"
    assert dr.get(world, decision.id).status == "open"
    assert world.get_goal(gid).status == "blocked"


def test_the_starter_cannot_answer_an_admin_area_unless_self_approval_is_allowed(
        tmp_path, monkeypatch):
    world = _world(tmp_path)
    _gid, decision = _paused_goal(world, area="governance")
    assert decision.admin_required

    with pytest.raises(dr.DecisionRefused) as refused:
        dr.answer(world, decision.id, 1, actor="alice", is_admin=True)
    assert refused.value.reason == "self_answer"
    with pytest.raises(dr.DecisionRefused) as not_admin:
        dr.answer(world, decision.id, 1, actor="bob", is_admin=False)
    assert not_admin.value.reason == "admin_required"

    monkeypatch.setenv("MAVERICK_ALLOW_SELF_APPROVAL", "1")
    assert dr.answer(world, decision.id, 1, actor="alice", is_admin=True)["decision"].chosen == 1


def test_expiry_stops_the_run_without_choosing(tmp_path, monkeypatch):
    import maverick.audit as audit

    written = []
    monkeypatch.setattr(audit, "record", lambda kind, **kw: written.append((kind, kw)) or True)
    world = _world(tmp_path)
    gid, decision = _paused_goal(world)

    assert dr.expire_due(world, now=decision.expires_at + 1) == [decision.id]

    expired = dr.get(world, decision.id)
    assert (expired.status, expired.chosen) == ("expired", None)
    goal = world.get_goal(gid)
    assert goal.status == "failed" and "No option was chosen" in goal.result
    assert ("decision_expired", "system:decision-expiry") in [(k, kw["agent"]) for k, kw in written]
    assert '"outcome": "expired"' in dr.brief_block(world, gid)
    with pytest.raises(dr.DecisionRefused) as late:
        dr.answer(world, decision.id, 1, actor="alice", is_admin=False)
    assert late.value.reason == "expired"


@pytest.mark.asyncio
async def test_an_unsaved_request_stops_the_run_before_it_continues(
        tmp_path, fake_llm, make_llm_response, monkeypatch):
    from maverick.attachment_submissions import SubmissionStore

    def broken(self, lock, **_kw):
        raise OSError("disk full")

    monkeypatch.setattr(SubmissionStore, "transaction", broken)
    fake_llm.scripted = [
        make_llm_response(text="Asking.", tool_calls=[
            ToolCall(id="t1", name="request_decision", input=_REQUEST)]),
        make_llm_response(text="FINAL: I decided myself"),
    ]
    world = _world(tmp_path)
    gid = world.create_goal("tidy the retention settings", "", owner="alice")

    out = await _run(world, gid, fake_llm, tmp_path)

    assert out == dr.STOP_MESSAGE
    assert len(fake_llm.calls) == 1
    goal = world.get_goal(gid)
    assert goal.status == "blocked" and goal.result == dr.STOP_MESSAGE
