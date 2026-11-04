"""One page-header family, one main action per view, tabs with a real selected state."""
from __future__ import annotations

import pathlib
import re

import pytest
from fastapi.testclient import TestClient

TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"

# The top routes: each puts its main action in the header and keeps at most one
# primary button in the server-rendered view.
TOP_ROUTES = ["/goals", "/approvals", "/deliverables", "/workflows", "/agents", "/workforce",
              "/users", "/spending-limits", "/settings", "/privacy", "/security"]


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _view(html: str) -> str:
    """The page's own content, without scripts, styles or closed dialogs (separate views)."""
    main = html[html.index('<main id="content"'):html.index("</main>")]
    for pattern in (r"<script\b.*?</script>", r"<style\b.*?</style>", r"<dialog\b.*?</dialog>"):
        main = re.sub(pattern, "", main, flags=re.DOTALL)
    return main


@pytest.mark.parametrize("path", TOP_ROUTES)
def test_top_routes_keep_one_primary_and_it_lives_in_the_header(client, path):
    page = client.get(path)
    assert page.status_code == 200, path
    view = _view(page.text)
    primaries = re.findall(r'class="btn btn--primary"', view)
    assert len(primaries) <= 1, (path, len(primaries))
    if primaries:
        actions = re.search(r'<div class="hero-actions">(.*?)</div>', view, re.DOTALL)
        assert actions and "btn--primary" in actions.group(1), path


@pytest.mark.parametrize("path", ["/security", "/privacy", "/settings"])
def test_selected_tabs_use_a_selected_state_not_the_primary_style(client, path):
    view = _view(client.get(path).text)
    tabs = re.findall(r'<button class="mv-tab"[^>]*role="tab"[^>]*>', view)
    assert tabs, path
    assert all("btn--primary" not in tab for tab in tabs)
    if path != "/settings":  # Settings selects its tab from the address once loaded.
        assert sum('aria-selected="true"' in tab for tab in tabs) >= 1, path


def test_agent_and_workforce_cards_use_plain_buttons():
    agents = (TEMPLATES / "agents.html").read_text(encoding="utf-8")
    workforce = (TEMPLATES / "workforce.html").read_text(encoding="utf-8")
    assert "btn btn--primary dep-deploy" not in agents
    assert 'class="btn btn--primary" data-key="{{ d.key }}" data-act="deploy"' not in workforce
    assert 'class="btn" data-key="{{ d.key }}" data-act="deploy"' in workforce


# Pages that opened with a bare, inline-styled or missing <h1> now use the
# shared header macro, keeping their title text.
MIGRATED_HEADERS = {
    "404.html": "'Page not found'", "500.html": "'Something went wrong'", "error.html": "title",
    "flow_run.html": "'Flow run'", "budget_guidance.html": "ui('Your budget before work starts')",
    "commitment_viability.html": "'Promise reviews'", "content_access.html": "'Content access'",
    "conversations.html": "'My conversations'", "cost_reconciliation.html": "'Compare cost records'",
    "deliverable_bundles.html": "'Selected deliverable bundles'", "devices.html": "'Your paired devices'",
    "employee_activation.html": 'ui("Your first useful result")',
    "employee_departures.html": "'Employee departures'", "my_work.html": "'My background work'",
    "notification_health.html": "'Notification delivery'", "outcome_pilots.html": "'Workflow pilots'",
    "permission_requests.html": "'Permission requests'", "personal_data.html": "'My data'",
    "personal_notifications.html": "'Your notifications'",
    "project_reviews.html": 'ui("Project team reviews")', "project_workspaces.html": "'Project workspaces'",
    "task_diagnostics.html": "'Review a safe task diagnostic report'", "task_handoffs.html": "'Task handoffs'",
    "plan_tree.html": "'Plan for: ' ~ goal.title", "trajectory.html": "'Step-by-step history: ' ~ goal.title",
    "errors.html": "'Problems in: ' ~ goal.title",
    "rights_form.html": "rf.heading.replace('{organisation}', form.property.organisation)",
    "rights_status.html": "rf.status_title", "rights_unavailable.html": "rf.page_title",
    "rights_verify.html": "rf.verify_title", "form_automation.html": "form.title",
    "form_questionnaire.html": "questionnaire.vendor ~ ' — security & risk questionnaire'",
}


@pytest.mark.parametrize("name, title", sorted(MIGRATED_HEADERS.items()))
def test_page_opens_with_the_shared_header(name, title):
    source = (TEMPLATES / name).read_text(encoding="utf-8")
    assert '{% from "_hero.html" import hero' in source, name
    assert "<h1" not in source, name
    assert re.search(r"hero\('[^']*', " + re.escape(title), source), name


def test_rendered_error_page_uses_the_header_and_its_main_action(client):
    page = client.get("/this/does/not/exist", headers={"Accept": "text/html"}).text
    assert '<h1 class="page-title hero-title" id="page-hero-title">Page not found</h1>' in page
    actions = re.search(r'<div class="hero-actions">(.*?)</div>', page, re.DOTALL).group(1)
    assert 'class="btn btn--primary" href="/">Go to the overview</a>' in actions
