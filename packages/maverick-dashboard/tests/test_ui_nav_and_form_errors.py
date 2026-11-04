"""UI hardening (nav_and_form_errors): active-nav highlighting + graceful goal-form errors."""
from __future__ import annotations

from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _prep(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


class _ActiveNavigation(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.href = None
        self.labels = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("aria-current") == "page":
            self.href = attrs["href"]
            self.labels[self.href] = ""

    def handle_data(self, data):
        if self.href is not None:
            self.labels[self.href] += data

    def handle_endtag(self, tag):
        if tag == "a":
            self.href = None


# ---------- active nav highlighting ----------

@pytest.mark.parametrize("path,label", [
    ("/overview", "Overview"),
    ("/goals", "Tasks"),
    ("/agents", "Agent Factory"),
    ("/ekko", "Ekko"),
    ("/skills", "Skills"),
    ("/spend", "Spend"),
])
def test_current_page_link_is_marked_active(monkeypatch, tmp_path, path, label):
    _prep(monkeypatch, tmp_path)
    r = _client().get(path)
    # Preserve exact selected destination and spoken text through localized spans.
    assert f'<a href="{path}" class="active" aria-current="page">' in r.text
    assert _ActiveNavigation(r.text).labels == {path: label}


def test_exactly_one_nav_link_is_active(monkeypatch, tmp_path):
    """Only the current page is highlighted, never two."""
    _prep(monkeypatch, tmp_path)
    r = _client().get("/goals")
    assert r.text.count('aria-current="page"') == 1
    # The Overview link renders in its inactive form on a non-overview page.
    assert '<a href="/overview"><svg' in r.text
    assert '<a href="/overview" class="active"' not in r.text


def test_home_link_not_active_on_other_pages(monkeypatch, tmp_path):
    """`/` must not match every path via a prefix check."""
    _prep(monkeypatch, tmp_path)
    r = _client().get("/spend")
    assert '<a href="/" class="active"' not in r.text


# ---------- graceful goal-form errors ----------

def test_chat_form_has_inline_error_region(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().get("/chat")
    assert 'id="goal-error"' in r.text
    assert 'role="alert"' in r.text


def test_chat_form_submits_via_fetch(monkeypatch, tmp_path):
    """The form posts with fetch so 4xx surfaces inline, not as raw JSON.

    The handler lives in base.html (shared by the chat + overview forms),
    so it ships on every page render.
    """
    _prep(monkeypatch, tmp_path)
    r = _client().get("/chat")
    assert '/static/lightwork-ui.js' in r.text
    ui = _client().get("/static/lightwork-ui.js").text
    assert "new FormData(form)" in ui
    # It reads Retry-After so a rate-limited user sees the wait time.
    assert "Retry-After" in ui


def test_chat_can_handoff_an_unsaved_flow_or_agent_draft(monkeypatch, tmp_path):
    """Authoring choices stay browser-local until the user explicitly saves."""
    _prep(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    response = _client().get("/chat")
    assert response.status_code == 200
    page = response.text
    assert 'name="authoring_kind"' in page
    from test_support.element_text import element_texts

    assert element_texts(page, "option", {"value": "flow"}) == ["Draft a workflow"]
    assert element_texts(page, "option", {"value": "agent"}) == ["Draft an agent"]

    ui = _client().get("/static/lightwork-ui.js").text
    assert "lightwork.authoring-handoff" in ui
    assert "sessionStorage.setItem" in ui
    assert "kind === 'flow' ? '/flows/designer' : '/workflow-builder'" in ui


def test_chat_workflow_draft_tracks_live_feature_state(monkeypatch, tmp_path):
    from maverick import flow

    _prep(monkeypatch, tmp_path)
    monkeypatch.setattr(flow, "enabled", lambda: False)
    monkeypatch.delenv("MAVERICK_FLOWS", raising=False)
    client = _client()
    page = client.get("/chat").text
    assert '<option value="flow"' not in page
    assert '<option value="agent"' in page
    assert 'href="/learning#lrn-flows-on"' in page

    disabled = client.post(
        "/api/v1/flows/draft",
        json={"description": "Prepare a customer welcome workflow"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert disabled.status_code == 403
    assert disabled.headers["x-lightwork-feature-off"] == "workflows"
    assert disabled.json()["detail"].startswith("Workflows are turned off.")

    monkeypatch.setenv("MAVERICK_FLOWS", "0")
    managed_page = client.get("/chat").text
    assert '<option value="flow"' not in managed_page
    assert 'href="/learning#lrn-flows-on"' not in managed_page


def test_collapsed_sidebar_is_removed_from_keyboard_and_accessibility_navigation(
    monkeypatch,
    tmp_path,
):
    """The visually off-canvas mobile drawer must not remain interactive."""
    _prep(monkeypatch, tmp_path)
    ui = _client().get("/static/lightwork-ui.js").text
    assert "sidebar.toggleAttribute('inert', hidden)" in ui
    assert "sidebar.setAttribute('aria-hidden', 'true')" in ui
    assert "sidebar.removeAttribute('aria-hidden')" in ui
    assert "sidebar.contains(document.activeElement)" in ui


def test_overview_first_run_form_has_inline_error_region(monkeypatch, tmp_path):
    """The overview's first-goal form gets the same graceful errors."""
    _prep(monkeypatch, tmp_path)
    r = _client().get("/overview")
    # Empty DB -> first-run branch with the goal form.
    assert 'action="/chat/send"' in r.text
    assert 'id="goal-error"' in r.text
