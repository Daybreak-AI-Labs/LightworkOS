"""Native saved-result projection regression coverage."""
from html.parser import HTMLParser

import pytest
from fastapi import HTTPException
from maverick.oidc import VerifiedPrincipal
from maverick.world_model import WorldModel
from maverick_dashboard import answer_projection as projection
from starlette.requests import Request


@pytest.fixture
def setup(tmp_path, monkeypatch):
    from maverick_dashboard import app

    monkeypatch.setattr(projection, "require_permission", lambda *args: None)
    monkeypatch.setattr(projection, "assert_goal_access", lambda *args: None)
    monkeypatch.setattr(projection, "has_permission", lambda *args: True)
    monkeypatch.setattr(projection, "caller_principal", lambda *args: "user:alice")
    monkeypatch.setattr(projection, "context_for", lambda *args: "a" * 64)
    monkeypatch.setattr(app, "_voice_only_mode", lambda: False)
    with WorldModel(tmp_path / "world.db") as world:
        goal_id = world.create_goal("Task", owner="user:alice")
        world.set_goal_status(goal_id, "running")
        yield world, goal_id


def request():
    value = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    value.state.principal = VerifiedPrincipal(sub="alice", issuer="https://issuer.example",
                                             audience="lightwork", claims={"sub": "alice"})
    return value


def test_completion_projects_current_result_artifacts_and_owner_controls(setup):
    world, goal_id = setup
    running = projection.projection(request(), world, goal_id)
    world.set_goal_status(goal_id, "done", result="Completed result")
    world.add_artifact(goal_id, kind="text", title="Review file", content="First version")
    complete = projection.projection(request(), world, goal_id)
    assert complete["goal"].result == "Completed result"
    assert complete["artifacts"][0]["title"] == "Review file"
    assert complete["can_operate"] is True
    assert complete["answer_version"] != running["answer_version"]


def test_reviewed_content_grant_never_grants_mutation_controls(setup, monkeypatch):
    world, goal_id = setup
    monkeypatch.setattr(projection, "caller_principal", lambda *args: "user:reviewer")
    assert projection.projection(request(), world, goal_id)["can_operate"] is False


def test_access_is_rechecked_after_projection_reads(setup, monkeypatch):
    world, goal_id = setup
    calls = []
    def access(*args):
        calls.append(True)
        if len(calls) > 1:
            raise HTTPException(403, "Access revoked")
    monkeypatch.setattr(projection, "assert_goal_access", access)
    with pytest.raises(HTTPException) as denied:
        projection.projection(request(), world, goal_id)
    assert denied.value.status_code == 403


def test_mid_projection_artifact_change_returns_retryable_stale_state(setup, monkeypatch):
    world, goal_id = setup
    original = projection._snapshot
    calls = []
    def snapshot(w, g):
        result = original(w, g)
        calls.append(True)
        if len(calls) == 1:
            world.add_artifact(goal_id, kind="text", title="Review file", content="Concurrent version")
        return result
    monkeypatch.setattr(projection, "_snapshot", snapshot)
    with pytest.raises(HTTPException) as stale:
        projection.projection(request(), world, goal_id)
    assert stale.value.status_code == 409
    assert stale.value.detail["code"] == "result_changing"


def test_handoff_closure_is_inside_the_replaceable_live_projection(setup, monkeypatch):
    from maverick import task_handoffs
    from maverick_dashboard import app

    world, goal_id = setup
    world.set_goal_status(goal_id, "done", result="Private original result")
    before = projection.projection(request(), world, goal_id)
    monkeypatch.setattr(task_handoffs, "closure", lambda *_: {"actor": "user:bob"})
    closed = projection.projection(request(), world, goal_id)
    assert closed["can_operate"] is False
    assert closed["answer_version"] != before["answer_version"]
    source = app.templates.env.get_template("_chat_answer_panel.html").render(
        **closed, ui=lambda text, **values: text.format(**values), ut=lambda text: text,
    )

    class NoticeParser(HTMLParser):
        in_panel = False
        notice_in_panel = False

        def handle_starttag(self, tag, attrs):
            identifier = dict(attrs).get("id")
            if identifier == "answer-panel":
                self.in_panel = True
            if identifier == "handoff-closed-notice":
                self.notice_in_panel = self.in_panel

        def handle_endtag(self, tag):
            if tag == "section":
                self.in_panel = False

    parser = NoticeParser()
    parser.feed(source)
    assert parser.notice_in_panel, "Live replacement must include the accepted-handoff explanation"
    assert 'id="edit-toggle"' not in source
