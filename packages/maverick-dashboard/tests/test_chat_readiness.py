"""Real HTTP/storage regressions for follow-up admission and chat restarts."""
from __future__ import annotations

import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from maverick.chat_threads import ChatThreads
from maverick.world_model import WorldModel
from maverick_dashboard import api
from maverick_dashboard import app as dashboard


@pytest.fixture
def chat(monkeypatch, tmp_path):
    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    monkeypatch.setattr(api, "_world", lambda: world)
    from maverick_dashboard import _shared
    monkeypatch.setattr(_shared, "_world", lambda: world)
    monkeypatch.setattr(dashboard, "require_provider_or_400", lambda: None)
    monkeypatch.setattr(dashboard, "check_goal_rate_limit", lambda request: None)
    runs = []

    async def run(goal_id, **kwargs):
        runs.append((goal_id, kwargs))

    monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)
    yield TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world, runs
    world.close()


def _send(client):
    response = client.post("/chat/send", data={"title": "Prepare our report", "description": "Budget BUDGET-ALPHA-731 is binding."},
                           follow_redirects=False)
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


def _reply(client, goal_id, text="Revise that report.", token="reply-one"):
    return client.post(f"/chat/goal/{goal_id}/reply", data={"message": text, "submission_key": token}, follow_redirects=False)


def _finish(world, goal_id, text):
    binding = ChatThreads(world).binding(goal_id)
    world.append_turn(binding.conversation_id, "assistant", text, goal_id=goal_id)
    world.set_goal_status(goal_id, "done", result=text)


def test_recents_exposes_current_state_without_guessing_why_a_chat_is_paused(chat):
    client, world, _ = chat
    ids = {}
    for status in ("pending", "running", "blocked", "failed", "cancelled", "done"):
        goal_id = _send(client)
        world.set_goal_status(goal_id, status)
        ids[status] = goal_id

    assert not world.open_questions(ids["blocked"])
    sidebar = client.get("/chat").text.split('id="content"')[0]
    rows = dict(re.findall(
        r'<li><a\b[^>]*data-conversation-root="(\d+)"[^>]*>.*?</a>(.*?)</li>',
        sidebar, re.DOTALL,
    ))
    for status, label in (("pending", "Queued"), ("running", "Working"),
                          ("blocked", "Paused"), ("failed", "Failed"),
                          ("cancelled", "Stopped"), ("done", "Done")):
        row = rows[str(ids[status])]
        assert f'id="chat-status-{ids[status]}"' in row
        assert f'>{label}</span>' in row
        assert f'aria-describedby="chat-status-{ids[status]}"' in sidebar
    assert "Needs your answer" not in rows[str(ids["blocked"])]


def test_recents_reopens_latest_actual_turn_and_keeps_old_work_link(chat):
    client, world, _ = chat
    root = _send(client)
    _finish(world, root, "Original assistant answer")
    response = _reply(client, root)
    child = int(response.headers["location"].rsplit("/", 1)[1])
    _finish(world, child, "Latest assistant answer")
    # A workflow subtask with a larger id must not hijack Recents or block chat.
    world.create_goal("Unrelated internal child", parent_id=root)
    sidebar = client.get("/chat").text.split('id="content"')[0]
    assert f'href="/chat/goal/{child}"' in sidebar
    assert f'href="/chat/goal/{root}"' not in sidebar
    reopened = client.get(f"/chat/goal/{child}")
    assert "Budget BUDGET-ALPHA-731" in reopened.text
    assert "Original assistant answer" in reopened.text
    assert "Revise that report." in reopened.text and "Latest assistant answer" in reopened.text
    earlier_answer = re.search(
        rf'<a\b[^>]*href="/chat/goal/{root}"[^>]*>(.*?)</a>',
        reopened.text,
        re.DOTALL,
    )
    assert earlier_answer is not None
    assert "Open answer" in re.sub(r"<[^>]+>", "", earlier_answer.group(1))
    old = client.get(f"/chat/goal/{root}")
    assert "Original assistant answer" in old.text
    assert "Latest assistant answer" not in old.text
    assert "Open the latest message in this chat" in old.text
    assert _reply(client, root, "Another revision", "reply-two").status_code == 303


@pytest.mark.parametrize("status", ["pending", "running", "active", "draft"])
def test_stale_root_cannot_start_work_when_later_chat_turn_is_active(chat, status):
    client, world, runs = chat
    root = _send(client)
    _finish(world, root, "Original answer")
    reply = _reply(client, root)
    child = int(reply.headers["location"].rsplit("/", 1)[1])
    world.set_goal_status(child, status)
    response = _reply(client, root, "Do more work", "different-key")
    assert response.status_code == 409 and "still working" in response.json()["detail"]
    assert len(world.list_goals()) == len(runs) == 2


def test_two_concurrent_stale_root_submissions_admit_one_turn(chat):
    client, world, runs = chat
    root = _send(client)
    _finish(world, root, "Original answer")
    barrier = Barrier(2)

    def send(index):
        barrier.wait(timeout=10)
        return _reply(client, root, f"Revision {index}", f"key-{index}")

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(send, range(2)))
    assert sorted(response.status_code for response in responses) == [303, 409]
    assert len(world.list_goals()) == len(runs) == 2
    binding = ChatThreads(world).binding(root)
    assert len([turn for turn in world.recent_turns(binding.conversation_id) if turn.role == "user"]) == 2


def test_same_followup_key_replays_without_duplicate_turn_or_dispatch(chat):
    client, world, runs = chat
    root = _send(client)
    _finish(world, root, "Original answer")
    first, retried = _reply(client, root), _reply(client, root)
    assert first.status_code == retried.status_code == 303
    assert first.headers["location"] == retried.headers["location"]
    assert len(world.list_goals()) == len(runs) == 2
    assert len(world.recent_turns(ChatThreads(world).binding(root).conversation_id)) == 3


@pytest.mark.parametrize("mode", ["resume", "answer"])
def test_resumed_followup_keeps_actual_brief_and_original_conversation(chat, monkeypatch, mode):
    from maverick import orchestrator

    client, world, runs = chat
    root = _send(client)
    _finish(world, root, "Original assistant answer")
    response = _reply(client, root)
    child = int(response.headers["location"].rsplit("/", 1)[1])
    initial = runs[-1][1]["conversation_id"]
    world.set_goal_status(child, "blocked")
    if mode == "answer":
        question_id = world.ask("Which audience?", goal_id=child)
        resumed = client.post(f"/api/v1/goals/{child}/answer", json={"question_id": question_id, "answer": "The board"})
    else:
        resumed = client.post(f"/api/v1/goals/{child}/resume", json={})
    assert resumed.status_code == 204, resumed.text
    assert runs[-1][0] == child
    assert runs[-1][1]["conversation_id"] == initial

    async def no_optional_enrichment(brief, **kwargs):
        return brief, "local-test"

    monkeypatch.setattr(orchestrator, "_apply_brief_enrichments", no_optional_enrichment)
    brief, _ = asyncio.run(orchestrator._build_orchestrator_brief(
        llm=None, world=world, budget=None, blackboard=None, goal=world.get_goal(child), goal_id=child,
        conversation_id=runs[-1][1]["conversation_id"], channel=None, user_id=None, domain=None, shield=None))
    assert "Budget BUDGET-ALPHA-731" in brief and "Original assistant answer" in brief
    assert "Prior conversation" in brief
    if mode == "answer":
        assert "The board" in brief


def test_non_chat_goal_resume_never_manufactures_conversation(chat):
    client, world, runs = chat
    goal = world.create_goal("Ordinary API task")
    world.set_goal_status(goal, "blocked")
    assert client.get(f"/chat/goal/{goal}").status_code == 200
    assert not world.list_conversations()
    response = client.post(f"/api/v1/goals/{goal}/resume", json={})
    assert response.status_code == 204
    assert "conversation_id" not in runs[-1][1]
    assert not world.list_conversations()


def test_old_turn_resume_cannot_overlap_a_newer_running_turn(chat):
    client, world, runs = chat
    root = _send(client)
    world.set_goal_status(root, "cancelled")
    assert _reply(client, root).status_code == 303
    response = client.post(f"/api/v1/goals/{root}/resume", json={})
    assert response.status_code == 409
    assert world.get_goal(root).status == "cancelled" and len(runs) == 2


def test_refused_final_answer_remains_open_and_retry_resumes_with_history(chat):
    client, world, runs = chat
    root = _send(client)
    world.set_goal_status(root, "blocked")
    question = world.ask("Which audience?", goal_id=root)
    reply = _reply(client, root)
    child = int(reply.headers["location"].rsplit("/", 1)[1])
    data = {"question_id": question, "answer": "The board"}
    blocked = client.post(f"/api/v1/goals/{root}/answer", json=data)
    assert blocked.status_code == 409
    assert [q.id for q in world.open_questions(root)] == [question]
    assert world.get_goal(root).status == "blocked" and len(runs) == 2
    _finish(world, child, "Completed the newer turn")
    retry = client.post(f"/api/v1/goals/{root}/answer", json=data)
    assert retry.status_code == 204, retry.text
    assert not world.open_questions(root) and world.get_goal(root).status == "pending"
    assert len(runs) == 3 and runs[-1][1]["conversation_id"] == runs[0][1]["conversation_id"]


def test_two_concurrent_clarifications_start_exactly_one_restart(chat):
    client, world, runs = chat
    root = _send(client)
    world.set_goal_status(root, "blocked")
    questions = [world.ask(f"Question {index}?", goal_id=root) for index in range(2)]
    barrier = Barrier(2)

    def answer(question_id):
        barrier.wait(timeout=10)
        return client.post(f"/api/v1/goals/{root}/answer", json={"question_id": question_id, "answer": "Confirmed"})

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(answer, questions))
    assert [r.status_code for r in responses] == [204, 204]
    assert not world.open_questions(root) and len(runs) == 2
    assert world.get_goal(root).status == "pending"


def test_failed_history_write_rolls_back_goal_and_submission(chat, monkeypatch):
    client, world, runs = chat

    def broken(*args, **kwargs):
        raise OSError("history disk failure")

    monkeypatch.setattr(ChatThreads, "record", broken)
    with pytest.raises(OSError, match="history disk failure"):
        _send(client)
    assert not world.list_goals() and not world.list_conversations() and not runs
    assert not world.query("SELECT * FROM attachment_submissions")


def test_foreign_child_neither_binds_nor_appears_in_owner_history(chat):
    client, world, _ = chat
    root = _send(client)
    _finish(world, root, "Original answer")
    binding = ChatThreads(world).binding(root)
    foreign = world.create_goal("Foreign title", owner="user:another", parent_id=root)
    world.append_turn(binding.conversation_id, "user", "Foreign private message", goal_id=foreign)
    world.append_turn(binding.conversation_id, "assistant", "Foreign private answer", goal_id=foreign)
    assert ChatThreads(world).binding(foreign) is None
    assert ChatThreads(world).latest(root) == root
    reply = _reply(client, root)
    assert reply.status_code == 303
    page = client.get(reply.headers["location"])
    assert "Foreign private" not in page.text
