"""Chat saves complete reviewed instructions and rejects oversized drafts."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def chat_env(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dashboard

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = world_model.WorldModel(world_model.DEFAULT_DB)
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    monkeypatch.setattr(dashboard, "require_provider_or_400", lambda: None)
    monkeypatch.setattr(dashboard, "check_goal_rate_limit", lambda request: None)
    calls = []

    async def run(goal_id, **kwargs):
        goal = world.get_goal(goal_id)
        calls.append((goal.title, goal.description, kwargs))

    monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)
    yield TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world, calls
    world.close()


def test_chat_submits_full_prepared_template_at_goal_limits(chat_env):
    from maverick_dashboard.api_schemas import GoalIn

    client, world, calls = chat_env
    title = "T" * 200
    ending = "\nFinal instruction: keep this.\n"
    description = "A" * (16_000 - len(ending)) + ending
    assert len(description) == 16_000
    GoalIn(title=title, description=description)  # Same contract as REST goals.
    response = client.post("/chat/send", data={"title": title, "description": description}, follow_redirects=False)
    assert response.status_code == 303, response.text
    goals = world.list_goals()
    assert len(goals) == 1
    assert goals[0].title == title
    assert goals[0].description == description
    # The first message opens a thread: the run carries the thread's
    # conversation so later messages arrive as prior turns.
    (called_title, called_description, kwargs), = calls
    assert (called_title, called_description) == (title, description)
    conversation = world.get_or_create_conversation("web", f"local/{goals[0].id}")
    assert kwargs == {"allowed_suites": None, "conversation_id": conversation.id}
    turns = world.recent_turns(conversation.id)
    assert [(t.role, t.goal_id) for t in turns] == [("user", goals[0].id)]
    assert turns[0].content == f"{title}\n\n{description}"


@pytest.mark.parametrize("field, value", [("title", "T" * 201), ("description", "D" * 16_001)], ids=["title", "description"])
def test_chat_rejects_oversized_drafts_before_creating_or_running_goal(chat_env, field, value):
    client, world, calls = chat_env
    data = {"title": "Review the report", "description": "Keep the full instructions"}
    data[field] = value
    response = client.post("/chat/send", data=data, follow_redirects=False)
    assert response.status_code == 422, response.text
    assert "shorten" in response.json()["detail"].lower()
    assert not world.list_goals()
    assert not calls


def test_chat_empty_details_keeps_the_title_as_its_brief(chat_env):
    client, world, calls = chat_env
    response = client.post("/chat/send", data={"title": "  Review the report  ", "description": " \n "}, follow_redirects=False)
    assert response.status_code == 303, response.text
    assert world.list_goals()[0].description == "Review the report"
    assert calls[0][:2] == ("Review the report", "Review the report")


def test_chat_composer_keeps_a_long_multiline_message_and_generates_only_a_short_title(chat_env):
    client, world, calls = chat_env
    message = "P" * 240 + "\nKeep these three requirements:\n1. First\n2. Second\n3. Third"
    brief = message + "\n\nUse the attached evidence."
    response = client.post("/chat/send", data={"title": message, "description": "Use the attached evidence.",
                                               "composer_mode": "message"}, follow_redirects=False)
    assert response.status_code == 303, response.text
    goal = world.list_goals()[0]
    assert goal.title == "P" * 200
    assert goal.description == brief
    assert calls[0][:2] == (goal.title, brief)
    conversation = world.get_or_create_conversation("web", f"local/{goal.id}")
    assert world.recent_turns(conversation.id)[0].content == brief
    page = client.get(f"/chat/goal/{goal.id}").text
    assert 'class="bubble__text"' in page and "Keep these three requirements:" in page


def test_overview_first_goal_uses_the_full_message_contract(chat_env):
    client, world, calls = chat_env
    page = client.get("/overview")
    assert page.status_code == 200
    form = page.text.split('action="/chat/send"', 1)[1].split("</form>", 1)[0]
    assert '<textarea name="title"' in form
    assert 'name="composer_mode" value="message"' in form

    message = "\n  \n" + "Review this customer request. " * 10 + "\n1. Keep this line.\n2. Keep this one too.\n"
    response = client.post("/chat/send", data={"title": message, "composer_mode": "message"},
                           follow_redirects=False)
    assert response.status_code == 303, response.text
    goal = world.list_goals()[0]
    assert goal.title == next(line.strip() for line in message.splitlines() if line.strip())[:200]
    assert goal.description == message
    assert calls[0][:2] == (goal.title, message)

    too_long = client.post("/chat/send", data={"title": "A" * 16_001, "composer_mode": "message"},
                           follow_redirects=False)
    assert too_long.status_code == 422
    assert len(world.list_goals()) == 1


def _finish(world, goal_id: int, answer: str) -> None:
    """Simulate the run: the assistant's answer lands on the goal and on the thread."""
    world.set_goal_status(goal_id, "done", result=answer)
    goal = world.get_goal(goal_id)
    root = goal.parent_id or goal.id
    conversation = world.get_or_create_conversation("web", f"local/{root}")
    world.append_turn(conversation.id, "assistant", answer, goal_id=goal_id)


def test_reply_continues_the_thread_as_a_follow_up_goal(chat_env):
    client, world, calls = chat_env
    first = client.post("/chat/send", data={"title": "Draft a launch plan", "description": ""}, follow_redirects=False)
    root_id = int(first.headers["location"].rsplit("/", 1)[1])
    _finish(world, root_id, "## Plan\n\n1. Announce")

    reply = client.post(
        f"/chat/goal/{root_id}/reply",
        data={"message": "Make it shorter and add a budget line.\nKeep the tone."},
        follow_redirects=False,
    )
    assert reply.status_code == 303, reply.text
    new_id = int(reply.headers["location"].rsplit("/", 1)[1])
    follow_up = world.get_goal(new_id)
    assert follow_up.parent_id == root_id
    assert follow_up.title == "Make it shorter and add a budget line."
    assert follow_up.description == "Make it shorter and add a budget line.\nKeep the tone."
    # Same conversation as the root, so the orchestrator threads the history in.
    conversation = world.get_or_create_conversation("web", f"local/{root_id}")
    assert calls[-1][2] == {"allowed_suites": None, "conversation_id": conversation.id}
    assert [(t.role, t.goal_id) for t in world.recent_turns(conversation.id)] == [
        ("user", root_id), ("assistant", root_id), ("user", new_id),
    ]


def test_reply_waits_for_the_running_turn_and_needs_text(chat_env):
    client, world, calls = chat_env
    first = client.post("/chat/send", data={"title": "Draft a launch plan", "description": ""}, follow_redirects=False)
    root_id = int(first.headers["location"].rsplit("/", 1)[1])
    world.set_goal_status(root_id, "running")
    busy = client.post(f"/chat/goal/{root_id}/reply", data={"message": "and then?"}, follow_redirects=False)
    assert busy.status_code == 409
    assert "still working" in busy.json()["detail"]
    _finish(world, root_id, "done")
    empty = client.post(f"/chat/goal/{root_id}/reply", data={"message": "   "}, follow_redirects=False)
    assert empty.status_code == 400
    assert len(world.list_goals()) == 1 and len(calls) == 1


def test_thread_page_shows_earlier_turns_the_composer_and_the_chat_list(chat_env):
    client, world, calls = chat_env
    first = client.post("/chat/send", data={"title": "Draft a launch plan", "description": ""}, follow_redirects=False)
    root_id = int(first.headers["location"].rsplit("/", 1)[1])
    _finish(world, root_id, "## Plan\n\n1. Announce")
    reply = client.post(f"/chat/goal/{root_id}/reply", data={"message": "Shorter, please."}, follow_redirects=False)
    new_id = int(reply.headers["location"].rsplit("/", 1)[1])

    page = client.get(f"/chat/goal/{new_id}").text
    # Earlier turns render above the live one, in order; the live goal's own
    # message is the user bubble, not a duplicated turn.
    assert page.index("Draft a launch plan") < page.index("## Plan") < page.index("Shorter, please.")
    assert page.count("Shorter, please.") == 1
    assert f'action="/chat/goal/{new_id}/reply"' in page
    assert 'name="message"' in page
    # Stable root identity/title, but Recents reopens the latest actual turn.
    assert f'href="/chat/goal/{new_id}" class="active" aria-current="true"' in page
    assert f'href="/chat/goal/{root_id}"' not in page.split('id="content"')[0]
    landing = client.get("/chat").text
    assert f'href="/chat/goal/{new_id}"' in landing.split('id="content"')[0]
