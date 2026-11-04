"""Copilot introduces itself in a line, suggests tasks, links to the exact control, and
shows status by default while changes stay opt-in behind review and confirmation."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import copilot_tasks
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def test_the_panel_opens_with_one_short_line_and_three_task_suggestions():
    context = client.get("/api/v1/copilot/context", params={"page": "/users"}).json()
    assert context["intro"] == ("I can explain Users, answer questions about it and take you to "
                                "the right control. I don't change anything for you.")
    assert context["suggestions"] == ["Invite a colleague", "Change someone's role", "See who is signed in"]


def test_a_page_without_curated_tasks_still_gets_three_plain_suggestions():
    context = client.get("/api/v1/copilot/context", params={"page": "/perf"}).json()
    assert len(context["suggestions"]) == 3
    joined = " ".join(context["suggestions"]).casefold()
    assert "authority" not in joined and "readiness" not in joined and "inspect" not in joined


def test_the_intro_says_changes_need_confirmation_only_when_copilot_changes_are_on(monkeypatch):
    monkeypatch.setattr("maverick.config.get_features", lambda: {"copilot_operations": True})
    context = client.get("/api/v1/copilot/context", params={"page": "/users"}).json()
    assert context["intro"].endswith("Changes always need your confirmation.")


@pytest.mark.parametrize(("page", "message", "href", "focus", "label"), [
    ("/settings", "Set a spending limit", "/settings", "settings-task-budget", "Open Spending limits"),
    ("/settings", "where do I change the spending limit?", "/settings", "settings-task-budget", "Open Spending limits"),
    ("/users", "Invite a colleague", "/users", "invite-email", "Open Invite someone"),
    ("/goals", "Show tasks that failed", "/goals?status=failed", None, "Show failed tasks"),
    ("/chat", "Start a task", "/chat", "composer-title", "Write your request"),
])
def test_asking_for_a_task_answers_with_steps_and_a_link_that_focuses_the_control(page, message, href, focus, label):
    payload = client.post("/api/v1/copilot", json={"message": message, "page": page, "history": []}).json()
    assert payload["mode"] == "built_in"
    link = payload["action_link"]
    assert (link["href"], link.get("focus"), link["label"]) == (href, focus, label)
    assert "Nothing was changed" in payload["warning"]


def test_unrelated_action_requests_keep_the_plain_cannot_do_that_answer():
    payload = client.post("/api/v1/copilot", json={"message": "Cancel my running goal", "page": "/goals",
                                                   "history": []}).json()
    # The reply says up front that nothing was changed.
    assert payload["reply"].startswith("I can explain the steps, but I haven't changed anything.")


def test_every_focus_target_exists_on_its_page():
    from pathlib import Path

    templates = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"
    source = "\n".join(path.read_text(encoding="utf-8") for path in templates.glob("*.html"))
    for tasks in copilot_tasks.TASKS.values():
        for task in tasks:
            assert re.fullmatch(r"/[a-z0-9/-]*(\?[a-z_]+=[a-z0-9_-]+)?", task.href)
            if task.focus:
                assert f'id="{task.focus}"' in source, task.focus


def test_tasks_people_cannot_carry_out_are_not_suggested():
    viewer = frozenset({"view"})
    assert copilot_tasks.tasks_for("/users", viewer) == []
    assert copilot_tasks.match("/users", "Invite a colleague", viewer) is None
    assert [task.label for task in copilot_tasks.tasks_for("/goals", viewer)][:1] == ["Show my running tasks"]


def _fake_adapters(monkeypatch):
    from maverick_dashboard import product_operations as ops

    def snapshot(request, selection):
        return ops.Snapshot("1", "Your saved layout", "Current source")

    status = ops.Adapter("today.status", "Show my daily work", "preferences", "/today", ("/today",),
                         ops.EmptyInput, snapshot, lambda request, selection, args: ops.Preview("Current"))
    layout = ops.Adapter("today.layout", "Arrange my daily work", "preferences", "/today", ("/today",),
                         ops.EmptyInput, snapshot, lambda request, selection, args: ops.Preview("Change"),
                         lambda *args: ops.Outcome("confirmed", "saved"))
    monkeypatch.setattr(ops, "adapters", lambda: {status.id: status, layout.id: layout})


def test_the_catalogue_no_longer_answers_403_when_copilot_changes_are_off(monkeypatch):
    """The administrator's 403 was a turned-off feature reported as a permission
    failure on every Copilot open. Status-only controls now list by default."""
    from maverick import config

    monkeypatch.setattr(config, "get_features", lambda: {"copilot_operations": False})
    r = client.post("/api/v1/copilot/product-operations/catalog", json={"page": "/users", "selection": {}})
    assert r.status_code == 200, r.text
    assert r.json()["operations"] == []
    _fake_adapters(monkeypatch)
    monkeypatch.setattr("maverick_dashboard.product_operations.enabled_families", lambda: {"preferences"})
    r = client.post("/api/v1/copilot/product-operations/catalog", json={"page": "/today", "selection": {}})
    assert r.status_code == 200, r.text
    listed = {item["id"]: item for item in r.json()["operations"]}
    # Showing status changes nothing, so it is on by default; changing the layout is not listed.
    assert set(listed) == {"today.status"}
    assert listed["today.status"]["available"] is True
    assert listed["today.status"]["confirmation_required"] is False
    # A family the administrator did not choose adds nothing, not even a disabled button.
    monkeypatch.setattr("maverick_dashboard.product_operations.enabled_families", lambda: {"learning"})
    r = client.post("/api/v1/copilot/product-operations/catalog", json={"page": "/today", "selection": {}})
    assert r.json()["operations"] == []


def test_with_copilot_changes_on_the_change_control_is_listed_and_needs_confirmation(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "get_features", lambda: {"copilot_operations": True})
    monkeypatch.setattr(config, "load_global_config", lambda: {"features": {"copilot_operations": True}})
    _fake_adapters(monkeypatch)
    monkeypatch.setattr("maverick_dashboard.product_operations.enabled_families", lambda: {"preferences"})
    r = client.post("/api/v1/copilot/product-operations/catalog", json={"page": "/today", "selection": {}})
    listed = {item["id"]: item for item in r.json()["operations"]}
    assert listed["today.layout"]["confirmation_required"] is True


def test_a_change_through_copilot_still_needs_the_feature_and_a_confirmed_review(monkeypatch):
    from maverick import config
    monkeypatch.setattr(config, "get_features", lambda: {"copilot_operations": False})
    r = client.post("/api/v1/copilot/product-operations/prepare", json={
        "page": "/today", "selection": {}, "operation": "today.layout", "context": "a" * 64,
        "revision": "1", "arguments": {}})
    assert r.status_code == 403
    r = client.post("/api/v1/copilot/product-operations/execute", json={"token": "x", "confirmed": False})
    assert r.status_code == 400
