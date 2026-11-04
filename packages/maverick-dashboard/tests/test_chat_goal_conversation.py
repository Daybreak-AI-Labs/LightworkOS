"""The goal page reads as a conversation: withheld steps fold into one line,
the result renders as prose, and the agent's question is answered in place."""
from __future__ import annotations

import json
import re
from html import unescape
from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def page_env(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dash_app._world_cache.clear()
    world = world_model.WorldModel(world_model.DEFAULT_DB)
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world
    world.close()


def test_new_task_page_shows_current_goal_limits(page_env, tmp_path):
    client, _world = page_env
    fresh = client.get("/chat")
    assert fresh.status_code == 200
    assert 'id="goal-task-limits"' in fresh.text
    assert "$2.00" in fresh.text and ">30</bdi> minutes" in fresh.text

    (tmp_path / "config.toml").write_text("[budget]\ntask_limits_enabled = false\n", encoding="utf-8")
    existing = client.get("/chat")
    assert existing.status_code == 200
    assert "No spending or time limit is set for each task." in existing.text


def test_goal_page_folds_the_kernels_withheld_markers_and_renders_prose(page_env):
    from maverick.blackboard import Blackboard

    client, world = page_env
    gid = world.create_goal("create a marketing plan for this app", "")
    world.set_goal_status(gid, "done", result="## Summary\n\n- one\n- two")

    text = client.get(f"/chat/goal/{gid}").text
    # The page learns the placeholder sentence from the kernel, never from a
    # copy of the string, so a reworded placeholder still folds.
    assert json.dumps(Blackboard._WITHHELD_CONTENT) in text
    assert json.dumps(Blackboard._REDACTION_UNAVAILABLE_CONTENT) in text
    # The result is prose the renderer upgrades in place, not a <pre> dump.
    class Elements(HTMLParser):
        def __init__(self):
            super().__init__()
            self.by_id = {}

        def handle_starttag(self, tag, attrs):
            attributes = dict(attrs)
            if attributes.get("id"):
                self.by_id[attributes["id"]] = (tag, attributes)

    elements = Elements()
    elements.feed(text)
    tag, result = elements.by_id["result"]
    assert tag == "div" and result["tabindex"] == "0"
    assert result["class"] == "prose" and "data-markdown" in result
    assert result["aria-labelledby"] in elements.by_id
    assert result["lang"] == "und" and result["dir"] == "auto"
    assert "data-user-content" in result
    assert 'src="/static/lightwork-markdown.js' in text
    # The work log is a step list; the raw "[agent] kind" trace line is gone.
    assert 'id="events" role="log" aria-live="polite" aria-label="Goal progress" tabindex="0"' in text
    assert "class=\"steps\"" in text
    assert "'[' + fmtAgent(e.agent) + '] '" not in text
    # Status stays machine-readable for the scripts; the page shows no raw badge.
    assert re.search(r'id="status" class="badge done" data-status="done"[^>]* hidden>Done<', text)
    # The chat shell exposes the real, role-filtered product navigation.
    assert 'class="chat-shell' in text
    assert 'aria-label="Chats"' in text
    assert 'aria-label="Primary"' in text
    # The rail opens saved flows; the designer is one click from that page.
    assert 'href="/workflows"' in text
    assert 'href="/action-center"' in text


def test_blocked_goal_reads_as_paused_and_keeps_the_question_in_the_conversation(page_env):
    client, world = page_env
    gid = world.create_goal("create a marketing plan for this app", "")
    world.set_goal_status(gid, "blocked")
    world.ask("Which audience first?", goal_id=gid)

    text = client.get(f"/chat/goal/{gid}").text
    assert re.search(r'id="status" class="badge blocked" data-status="blocked"[^>]* hidden>Paused<', text)
    assert "Lightwork needs one thing from you" in text
    assert 'id="qa-thread"' in text
    # Answering re-opens the live stream instead of leaving the page on a
    # finished stream with a Resume button.
    assert "resumeFollowing()" in text
    assert "recordExchange(attempt.question, attempt.answer)" in text


def test_markdown_renderer_is_served_as_javascript(page_env):
    client, _ = page_env
    response = client.get("/static/lightwork-markdown.js")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/javascript")
    assert "innerHTML" not in response.text
    assert "root.lwMarkdown = api" in response.text


def test_answer_actions_download_saved_result_and_keep_current_access(page_env, monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import app as dash_app

    client, world = page_env
    gid = world.create_goal("Quarterly plan", "")
    assert client.get(f"/chat/goal/{gid}/download.md").status_code == 409
    world.set_goal_status(gid, "done", result="## Approved plan\n\n- First step")

    page = client.get(f"/chat/goal/{gid}").text
    assert 'id="copy-result"' in page
    assert 'id="print-result"' in page
    assert 'id="share-open"' in page
    assert f'href="/chat/goal/{gid}/download.md"' in page
    assert '@media print' in page

    download = client.get(f"/chat/goal/{gid}/download.md")
    assert download.status_code == 200
    assert download.text == "## Approved plan\n\n- First step"
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["content-disposition"] == f'attachment; filename="lightwork-answer-{gid}.md"'

    def deny(_request, _goal):
        raise HTTPException(status_code=404, detail="no such goal")

    monkeypatch.setattr(dash_app, "assert_goal_access", deny)
    assert client.get(f"/chat/goal/{gid}/download.md").status_code == 404


def test_paged_history_keeps_answered_clarifications_for_complete_print(page_env):
    client, world = page_env
    root = world.create_goal("First message", "")
    conversation = world.get_or_create_conversation("web", f"local/{root}")
    world.append_turn(conversation.id, "user", "First message", goal_id=root)
    question_id = world.ask("Which year?", goal_id=root)
    world.answer(question_id, "2026")
    world.append_turn(conversation.id, "assistant", "First answer", goal_id=root)
    child = world.create_goal("Second message", "", parent_id=root)
    world.append_turn(conversation.id, "user", "Second message", goal_id=child)

    response = client.get(f"/api/v1/goals/{child}/thread-history")
    assert response.status_code == 200
    user = next(turn for turn in response.json()["turns"] if turn["role"] == "user")
    assert user["questions"] == [{"question": "Which year?", "answer": "2026"}]


def test_markdown_export_enforces_current_review_and_visible_table(page_env):
    client, world = page_env
    gid = world.create_goal("Forecast", "", domain="finance_cash13w")
    result = "UNREVIEWED SURROUNDING TEXT\n\n| Week | Net |\n| --- | --- |\n| W1 | 300 |"
    world.set_goal_status(gid, "done", result=result)
    denied = client.get(f"/chat/goal/{gid}/download.md")
    assert denied.status_code == 403
    page = client.get(f"/chat/goal/{gid}")
    assert f'href="/chat/goal/{gid}/download.md"' not in page.text
    assert "reviewer must approve" in page.text
    world.record_signoff(gid, "approved", decided_by="reviewer")
    download = client.get(f"/chat/goal/{gid}/download.md")
    assert download.status_code == 200
    assert download.text == "| Week | Net |\n| --- | --- |\n| W1 | 300 |"
    assert "UNREVIEWED" not in download.text
    page = client.get(f"/chat/goal/{gid}")
    source = re.search(
        r'<textarea\b(?=[^>]*\bid="saved-answer-source")[^>]*>(.*?)</textarea>',
        page.text,
        re.DOTALL,
    )
    assert source and unescape(source.group(1)) == download.text
    world.set_goal_status(gid, "done", result="changed answer")
    assert client.get(f"/chat/goal/{gid}/download.md").status_code == 403


def test_markdown_export_fails_closed_when_domain_policy_missing(page_env):
    client, world = page_env
    gid = world.create_goal("Removed policy", "", domain="removed_pack")
    world.set_goal_status(gid, "done", result="private result")
    assert client.get(f"/chat/goal/{gid}/download.md").status_code == 409
    page = client.get(f"/chat/goal/{gid}")
    assert f'href="/chat/goal/{gid}/download.md"' not in page.text
    assert "review requirements can be checked" in page.text
    # The live answer panel reads the same way; the export stays withheld.
    panel = client.get(f"/chat/goal/{gid}/answer-panel")
    assert panel.status_code == 200, panel.text
    assert f'href="/chat/goal/{gid}/download.md"' not in panel.text


def test_markdown_export_fails_closed_when_policy_read_fails(page_env, monkeypatch):
    from maverick import domain

    client, world = page_env
    gid = world.create_goal("Forecast", "", domain="finance_cash13w")
    world.set_goal_status(gid, "done", result="private result")

    def unavailable():
        raise RuntimeError("synthetic policy read failure")

    monkeypatch.setattr(domain, "available_domains", unavailable)
    assert client.get(f"/chat/goal/{gid}/download.md").status_code == 503
    page = client.get(f"/chat/goal/{gid}")
    assert page.status_code == 503
    assert "private result" not in page.text


def test_markdown_export_rejects_concurrent_answer_change(page_env, monkeypatch):
    from maverick_dashboard import app as dash_app

    client, world = page_env
    gid = world.create_goal("Forecast", "", domain="finance_cash13w")
    world.set_goal_status(gid, "done", result="reviewed result")
    world.record_signoff(gid, "approved", decided_by="reviewer")
    monkeypatch.setattr(dash_app, "_world", lambda: world)
    original = dash_app._chat_answer_text

    def intervening_edit(goal):
        text = original(goal)
        world.set_goal_status(gid, "done", result="new reviewed result")
        world.record_signoff(gid, "approved", decided_by="reviewer")
        return text

    monkeypatch.setattr(dash_app, "_chat_answer_text", intervening_edit)
    response = client.get(f"/chat/goal/{gid}/download.md")
    assert response.status_code == 409
    assert "reviewed result" not in response.text


def test_historical_answer_download_is_snapshot_bound_and_freshly_gated(page_env):
    client, world = page_env
    gid = world.create_goal("Forecast", "", domain="finance_cash13w")
    original = "| Week | Net |\n| --- | --- |\n| W1 | 300 |"
    world.set_goal_status(gid, "done", result=original)
    conversation = world.get_or_create_conversation("web", f"local/{gid}")
    user_turn = world.append_turn(conversation.id, "user", "Forecast", goal_id=gid)
    answer_turn = world.append_turn(conversation.id, "assistant", original, goal_id=gid)
    endpoint = f"/chat/goal/{gid}/download.md?turn_id={answer_turn}"
    assert client.get(endpoint).status_code == 403
    world.record_signoff(gid, "approved", decided_by="reviewer")
    assert client.get(endpoint).text == original
    assert client.get(f"/chat/goal/{gid}/download.md?turn_id={user_turn}").status_code == 404
    world.set_goal_status(gid, "done", result="updated answer")
    world.record_signoff(gid, "approved", decided_by="reviewer")
    assert client.get(endpoint).status_code == 409


def test_historical_ungated_answer_keeps_original_snapshot(page_env):
    client, world = page_env
    gid = world.create_goal("Original", "")
    world.set_goal_status(gid, "done", result="edited current answer")
    conversation = world.get_or_create_conversation("web", f"local/{gid}")
    world.append_turn(conversation.id, "user", "Original", goal_id=gid)
    turn = world.append_turn(conversation.id, "assistant", "original answer", goal_id=gid)
    response = client.get(f"/chat/goal/{gid}/download.md?turn_id={turn}")
    assert response.status_code == 200
    assert response.text == "original answer"


def test_chat_export_uses_real_owner_authority(page_env, monkeypatch):
    from maverick_dashboard import auth, rbac

    client, world = page_env
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role("user:owner", "operator")
    rbac.set_role("user:colleague", "operator")
    principal = ["user:owner"]
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal[0])
    gid = world.create_goal("Owned answer", "", owner="user:owner")
    world.set_goal_status(gid, "done", result="owner-only content")
    conversation = world.get_or_create_conversation("web", f"user:owner/{gid}")
    world.append_turn(conversation.id, "user", "Owned answer", goal_id=gid)
    turn = world.append_turn(conversation.id, "assistant", "owner-only content", goal_id=gid)
    assert client.get(f"/chat/goal/{gid}/download.md").status_code == 200
    principal[0] = "user:colleague"
    for suffix in ("", f"?turn_id={turn}"):
        response = client.get(f"/chat/goal/{gid}/download.md{suffix}")
        assert response.status_code == 404
        assert "owner-only content" not in response.text


@pytest.mark.parametrize("language, label", [
    ("fr", "Envoyer des consignes pour cette tâche"),
    ("de", "Hinweise an diese Aufgabe senden"),
    ("ja", "このタスクに指示を送る"),
    ("zh", "向此任务发送指导"),
])
def test_conversation_localizes_governed_controls_without_translating_source(page_env, language, label):
    client, world = page_env
    goal_id = world.create_goal("Save مرحبا", "Save <img src=x>")
    world.set_goal_status(goal_id, "done", result="Save مرحبا")
    response = client.get(f"/chat/goal/{goal_id}", params={"lang": language})
    assert response.status_code == 200
    assert f'lang="{language}">{label}</option>' in response.text
    assert '<html lang="en" dir="ltr">' in response.text
    assert '<div class="bubble__title" lang="und" dir="auto" data-user-content>Save مرحبا</div>' in response.text
    assert 'data-user-content>Save &lt;img src=x&gt;</div>' in response.text
    assert 'data-product-copy>Messages and task receipts</span>' not in response.text
    assert 'id="conversation-inbox"' in response.text
    assert '"review_status": "draft_partial"' in response.text
