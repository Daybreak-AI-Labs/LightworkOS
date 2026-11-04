"""UI hardening (goal_detail_a11y): inline errors + a11y on the goal-detail page."""
from __future__ import annotations

from fastapi.testclient import TestClient

from test_support.element_text import element_attributes, element_texts


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _goal_page(monkeypatch, tmp_path):
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    gid = world_model.WorldModel(db).create_goal("test goal", "desc")
    return _client().get(f"/chat/goal/{gid}")


def test_goal_page_renders(monkeypatch, tmp_path):
    r = _goal_page(monkeypatch, tmp_path)
    assert r.status_code == 200


def test_goal_action_errors_are_inline_not_alert(monkeypatch, tmp_path):
    """Cancel/answer failures show an inline role=status line, not alert()."""
    r = _goal_page(monkeypatch, tmp_path)
    assert 'id="goal-action-msg" role="status" aria-live="polite"' in r.text
    # The two native alert() calls were replaced with the inline region.
    assert "alert(" not in r.text
    # ...and the failure path explains itself in plain words.
    assert "cgErr(response, 'send your message')" in r.text
    assert "cgCopy(actionMsg,cgErr(r, 'stop the task'))" in r.text
    assert "window.mvRenderError(actionMsg, r, 'save your answer', receipt)" in r.text


def test_answer_input_has_accessible_name(monkeypatch, tmp_path):
    """The agent-question input had only a placeholder; give it a real name."""
    r = _goal_page(monkeypatch, tmp_path)
    assert r.status_code == 200
    answer, = element_attributes(r.text, "textarea", {"id": "answer-input"})
    assert answer["aria-labelledby"] == "answer-input-label"
    assert answer["name"] == "message"
    assert element_texts(r.text, "label", {
        "id": answer["aria-labelledby"], "for": "answer-input",
    }) == ["Your answer to the agent's question, or your next message"]
