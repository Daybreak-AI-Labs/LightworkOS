"""The public read-only page shows the answer as formatted prose.

The page must not print the model's markdown inside a monospace ``<pre>``
("## Summary", "**bold**" shown literally). It hands the text to the same
safe renderer the chat page uses, which builds DOM from text only, and the
renderer script is reachable by a recipient who has no dashboard sign-in.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

RESULT = "## Summary\n\n- Request received\n- **bold** next step\n\n<script>alert(1)</script>"


@pytest.fixture(autouse=True)
def _world(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    return world_model.WorldModel(tmp_path / "world.db")


def _shared(w, result: str = RESULT) -> str:
    gid = w.create_goal("Weekly update", "")
    w.set_goal_status(gid, "done", result=result)
    _, token = w.create_share_link(gid, created_by="operator")
    return token


def test_result_is_handed_to_the_markdown_renderer_not_printed_in_a_pre(_world):
    token = _shared(_world)
    page = TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}")
    assert page.status_code == 200
    html = page.text
    # Not a code block: the raw text must not sit inside <pre>.
    assert not re.search(r"<pre[^>]*>\s*## Summary", html)
    # It sits in a container the shared renderer upgrades.
    match = re.search(r"<div[^>]*\bdata-markdown\b[^>]*>(?P<body>.*?)</div>", html, re.DOTALL)
    assert match is not None
    assert "## Summary" in match.group("body")
    assert "/static/lightwork-markdown.js" in html
    assert "lwMarkdown.upgrade" in html


def test_markup_in_the_result_stays_escaped_text(_world):
    token = _shared(_world)
    html = TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_files_on_the_page_are_rendered_the_same_way(_world):
    token = _shared(_world, result="Done.")
    goal_id = _world.resolve_share_link(token)
    _world.add_artifact(goal_id, "text", "Notes", "# File heading\n\n- one")
    html = TestClient(app, base_url="http://127.0.0.1").get(f"/share/{token}").text
    assert not re.search(r"<pre[^>]*>\s*# File heading", html)
    assert re.search(r"<div[^>]*\bdata-markdown\b[^>]*>\s*# File heading", html)


def test_recipient_without_a_sign_in_can_load_the_renderer(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "share-test-token-xyz")  # pragma: allowlist secret
    anonymous = TestClient(app, base_url="http://127.0.0.1")  # no bearer, no Origin: an external recipient
    assert anonymous.get("/goals").status_code == 401  # ordinary pages stay gated
    script = anonymous.get("/static/lightwork-markdown.js")
    assert script.status_code == 200
    assert "lwMarkdown" in script.text


def test_renderer_exemption_is_exactly_one_file_in_both_gates():
    from maverick_dashboard import app as app_module
    from maverick_dashboard import auth

    assert "/static/lightwork-markdown.js" in app_module._AUTH_EXEMPT
    assert auth._self_authenticated_path("/static/lightwork-markdown.js")
    # Neighbouring scripts keep requiring a sign-in.
    assert "/static/lightwork-ui.js" not in app_module._AUTH_EXEMPT
    assert not auth._self_authenticated_path("/static/lightwork-ui.js")
