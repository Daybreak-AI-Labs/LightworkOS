"""The chat composers paint in their final place and keep focus.

Draft recovery used to wrap the composer in a new element and add a note and
a panel about a second after load, which moved the docked composer up on
phones (layout shift 0.11-0.13) and dropped the cursor out of the message
box. The wrapper, a placeholder for the panel and the note are now part of
the page, so the recovery script only fills them in. The greeting, the Chat
page's main content, no longer starts invisible and fades in late.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TEMPLATES = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import onboarding_state

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(onboarding_state, "selected_model_routes_ready", lambda: True)
    monkeypatch.setattr(onboarding_state, "workspace_readiness",
                        lambda: {"verdict": "ready", "reason": "Ready.", "next_action": None})
    from maverick_dashboard import app as dash_app

    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _sign_in(monkeypatch, role):
    from maverick_dashboard import auth, rbac

    rbac.set_role(f"user:{role}-person", role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: f"user:{role}-person")


def _assert_composer_wrapped(body, form_marker):
    """Wrapper, then the panel placeholder (holding the note), then the composer."""
    host = body.index("data-draft-host")
    panel = body.index("data-draft-panel")
    form = body.index(form_marker)
    note = body.index("data-draft-note")
    # Chat's dock starts recovery as one compact row: the note sits inside the
    # placeholder's disclosure, exactly as the live compact panel holds it
    # (lightwork-draft-recovery.js, options.compact).
    assert host < panel < note < form
    # The placeholder starts in the live panel's first state and takes no
    # focus or clicks while it waits to be replaced.
    placeholder = body[panel:form]
    assert '<details class="draft-recovery__compact">' in placeholder
    # The live panel's first state says only "Draft recovery"; "Checking…"
    # appears only if the check is slow (lightwork-draft-recovery.js).
    assert ">Draft recovery</summary>" in placeholder
    assert "Checking draft recovery…" not in placeholder
    assert re.search(r'<section class="draft-recovery" data-draft-panel inert[ >]', body)
    # Both notes are rendered; the second only takes its space until restore.
    block = body[note:]
    assert "Recovery copies keep unsent text." in block
    assert "Text restored for review." in block
    assert 'data-draft-note-for="restored" aria-hidden="true"' in block


def test_chat_composer_markup_is_server_rendered_for_people_who_keep_drafts(client, monkeypatch):
    _sign_in(monkeypatch, "operator")
    body = client.get("/chat").text
    assert 'name="lightwork-draft-context"' in body
    _assert_composer_wrapped(body, 'action="/chat/send"')
    assert body.count("data-draft-host") == 1
    # The panel's own styles load with the page, not after the composer paints:
    # they are part of the one shell stylesheet in the head.
    head = body.split("</head>", 1)[0]
    assert "/static/lightwork.css" in head
    from pathlib import Path
    css = (Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static" / "lightwork.css").read_text(encoding="utf-8")
    recovery = (Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static" / "lightwork-draft-recovery.css").read_text(encoding="utf-8")
    assert recovery.strip() in css


def test_task_reply_composer_markup_is_server_rendered(client, monkeypatch):
    from maverick import world_model

    _sign_in(monkeypatch, "operator")
    world = world_model.WorldModel(world_model.DEFAULT_DB)
    try:
        goal_id = world.create_goal("Prepare the quarterly summary", "", owner="user:operator-person")
    finally:
        world.close()
    page = client.get(f"/chat/goal/{goal_id}")
    assert page.status_code == 200, page.text[:500]
    _assert_composer_wrapped(page.text, 'id="answer-form"')


@pytest.mark.parametrize("role", ["viewer", "auditor"])
def test_people_without_recovery_copies_get_no_recovery_markup(client, monkeypatch, role):
    _sign_in(monkeypatch, role)
    body = client.get("/").text  # read-only roles land on the chat home
    assert "data-draft-host" not in body and "data-draft-note" not in body
    assert "Recovery copies keep unsent text." not in body
    assert 'action="/chat/send"' in body  # the read-only composer itself still renders


def test_recovery_markup_follows_the_recovery_setting(client, monkeypatch, tmp_path):
    from maverick import config

    _sign_in(monkeypatch, "operator")
    monkeypatch.setattr(config, "get_features", lambda *a, **k: {"draft_recovery": False})
    body = client.get("/chat").text
    assert 'name="lightwork-draft-context"' not in body
    # No promise of recovery copies where none are kept.
    assert "data-draft-host" not in body and "Recovery copies keep unsent text." not in body


def test_chat_entrance_motion_never_hides_the_main_content():
    """The greeting is the Chat page's largest content: it must be visible in
    the first frame it is painted. The entrance may move, never fade."""
    shell = (TEMPLATES / "chat_base.html").read_text(encoding="utf-8")
    rules = re.findall(r"\.cs-anim\s*\{([^}]*)\}", shell)
    assert rules, "the entrance rule moved; update this test with it"
    for rule in rules:
        assert "opacity" not in rule
    frames = re.search(r"@keyframes csUp\s*\{(.*?)\}\s*\}", shell, re.DOTALL)
    assert frames is not None and "opacity" not in frames.group(1)
    # Reduced motion still means no entrance animation at all.
    assert re.search(r"@media \(prefers-reduced-motion: no-preference\)\s*\{\s*\.cs-anim", shell)
