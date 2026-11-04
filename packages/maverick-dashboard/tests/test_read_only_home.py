"""Read-only roles land on a home they can use, with no permission errors.

Viewers and auditors open "/" on the chat home but cannot chat. A plain visit
must not try to save a recovery copy (that API needs the operate permission and
would show "Could not save the recovery copy. You do not have permission..."),
and the page must not offer chat controls that would only be refused.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

DRAFT_META = 'name="lightwork-draft-context"'


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import onboarding_state

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    # Past first-run setup with a working AI service, so "/" renders the chat
    # home (not /start) and its controls are not disabled for that reason.
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


@pytest.mark.parametrize("role", ["viewer", "auditor"])
def test_read_only_home_has_no_recovery_save_or_refused_chat_controls(client, monkeypatch, role):
    _sign_in(monkeypatch, role)
    home = client.get("/")
    assert home.status_code == 200
    body = home.text
    assert "Chat is read-only for your account" in body
    # Recovery copies need the operate permission: nothing on the page asks.
    assert DRAFT_META not in body
    # Controls that only start work (and would be refused) are not offered.
    assert 'class="composer__controls" disabled' in body
    assert 'id="vp-form"' not in body and "data-budget-launch" not in body
    assert ">Start a chat<" not in body
    # Nor notes about starting work: readiness, task limits and recovery copies.
    assert 'id="goal-task-limits"' not in body and "lightwork-chat-drafts.js" not in body
    # The pages a read-only role can open are still one click away.
    assert 'href="/goals"' in body and 'href="/deliverables"' in body


def test_people_who_can_chat_keep_recovery_copies_and_chat_controls(client, monkeypatch):
    _sign_in(monkeypatch, "operator")
    body = client.get("/").text
    assert DRAFT_META in body
    assert 'class="composer__controls" disabled' not in body
    assert "data-budget-launch" in body and 'id="vp-form"' in body
    assert ">Start a chat<" in body
    assert 'id="goal-task-limits"' in body and "lightwork-chat-drafts.js" in body


def test_recovery_context_follows_the_drafts_api_permission(client, monkeypatch):
    from types import SimpleNamespace

    from maverick_dashboard import draft_api

    _sign_in(monkeypatch, "viewer")
    request = SimpleNamespace(state=SimpleNamespace(), headers={}, query_params={}, cookies={})
    monkeypatch.setattr(draft_api, "has_permission", lambda req, permission: permission == "view")
    assert draft_api.page_context(request) == {"draft_recovery_context": ""}
