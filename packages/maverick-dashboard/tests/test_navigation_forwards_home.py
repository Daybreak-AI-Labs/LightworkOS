"""Home and work forwards (stream V1). Old addresses that move to their new homes in the job-named navigation.

Each forward fires only in areas mode, keeps the old page exactly as it was in
classic mode, and lands on a page that shows everything the old page showed
(its controls, forms, headings and scripts), under the old page's own access
check: a forward never shows anyone more or less than before.
"""
from __future__ import annotations

from html import unescape
from html.parser import HTMLParser

import pytest

FORWARDS = [
    ("/me", "/home?section=my-work"),
    ("/overview", "/home?section=overview"),
    ("/action-center", "/approvals?view=all"),
    ("/my-work", "/goals?owner=me&include=background"),
    ("/project-workspaces", "/projects"),
    ("/project-workspaces/7", "/projects/7?tab=plan"),
    ("/goal-builder", "/chat?compose=form"),
]


def _client(monkeypatch, tmp_path, *, areas=False, role="admin", action_center=True):
    from fastapi.testclient import TestClient
    from maverick import experience_preferences, world_model
    from maverick_dashboard import app, auth, onboarding_state, rbac

    monkeypatch.setenv("HOME", str(tmp_path))
    config = tmp_path / "config.toml"
    config.write_text(
        f"[features]\naction_center = {str(action_center).lower()}\nproject_workspaces = true\n"
        + ('[dashboard]\nnavigation = "areas"\n' if areas else ""),
        encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(config))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.setattr(experience_preferences, "enabled", lambda: True)
    monkeypatch.setattr(onboarding_state, "selected_model_routes_ready", lambda: True)
    principal = f"user:{role}"
    rbac.set_role(principal, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(app, "caller_principal", lambda request: principal)
    app._world_cache.clear()
    return TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


class _Content(HTMLParser):
    """What a page's main content offers: element ids, form targets, field
    names, section headings and scripts. The shell's navigation is left out."""

    def __init__(self, html):
        super().__init__()
        self.ids, self.forms, self.names, self.headings, self.scripts = set(), set(), set(), set(), set()
        self.in_main, self.skip, self.heading = False, 0, None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "main":
            self.in_main = True
        if tag == "script" and values.get("src"):
            self.scripts.add(values["src"].split("?")[0])
        if not self.in_main:
            return
        if "areanav" in (values.get("class") or "").split() or self.skip:
            self.skip += tag == "div"
            return
        if values.get("id"):
            self.ids.add(values["id"])
        if tag == "form" and values.get("action"):
            self.forms.add(values["action"])
        if tag in ("input", "select", "textarea") and values.get("name"):
            self.names.add(values["name"])
        if tag in ("h2", "h3", "h4"):
            self.heading = ""

    def handle_endtag(self, tag):
        if tag == "main":
            self.in_main = False
        if self.skip and tag == "div":
            self.skip -= 1
        if tag in ("h2", "h3", "h4") and self.heading is not None:
            self.headings.add(" ".join(self.heading.split()))
            self.heading = None

    def handle_data(self, data):
        if self.heading is not None:
            self.heading += data


def _assert_nothing_lost(old_html, new_html, shell_html):
    """Everything the old page itself offered is at the new address. The old
    shell's own scripts (``shell_html``, a plain page in the same shell) are
    the shell's, not the page's: a page moved into the chat shell keeps the
    chat shell's."""
    old, new, shell = _Content(old_html), _Content(new_html), _Content(shell_html)
    assert old.ids, "the old page rendered no content"
    for name in ("ids", "forms", "names", "headings", "scripts"):
        missing = getattr(old, name) - getattr(new, name)
        if name == "scripts":
            missing -= shell.scripts
        assert not missing, f"{name} lost at the new address: {sorted(missing)}"


# -- The table -------------------------------------------------------------------

def test_every_forward_is_ready_and_goal_builder_is_listed():
    from maverick_dashboard import navigation_api

    table = {old: (new, ready) for old, new, ready, _why in navigation_api.REDIRECTS}
    for old, new in FORWARDS:
        pattern = old.replace("/7", "/{id}")
        target, ready = table[pattern]
        assert ready, old
        assert navigation_api.redirect_target(old) == new
        assert target.replace("{id}", "7") == new


def test_a_forward_keeps_the_old_addresses_own_query_values():
    from maverick_dashboard.navigation_api import _with_query

    assert _with_query("/home?section=my-work", "saved=preferences") == "/home?section=my-work&saved=preferences"
    assert _with_query("/approvals?view=all", "view=active&x=1") == "/approvals?view=all&x=1"
    assert _with_query("/projects/7?tab=plan", "view=board") == "/projects/7?tab=plan&view=board"
    assert _with_query("/projects", "") == "/projects"


def test_a_new_address_knows_which_old_page_it_shows():
    from maverick_dashboard.navigation_api import forwarded_from

    assert forwarded_from("/home", {}) == "/today"
    assert forwarded_from("/home", {"section": "my-work"}) == "/me"
    assert forwarded_from("/approvals", {"view": "all"}) == "/action-center"
    assert forwarded_from("/approvals", {}) is None
    assert forwarded_from("/goals", {"owner": "me", "include": "background"}) == "/my-work"
    assert forwarded_from("/projects", {}) is None  # Projects is a page of its own
    assert forwarded_from("/chat", {"compose": "form"}) == "/goal-builder"


# -- Firing ----------------------------------------------------------------------

@pytest.mark.parametrize(("old", "new"), FORWARDS)
def test_forward_fires_in_areas_mode(old, new, monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, areas=True)
    response = client.get(old, follow_redirects=False)
    assert (response.status_code, response.headers.get("location")) == (303, new)


@pytest.mark.parametrize(("old", "new"), FORWARDS)
def test_old_page_stays_in_classic_mode(old, new, monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    response = client.get(old, follow_redirects=False)
    assert response.status_code == 200, old
    assert "location" not in response.headers
    # The merged views are areas-mode addresses; classic keeps its pages.
    assert client.get("/home?section=my-work", follow_redirects=False).status_code == 404


def test_saved_message_survives_the_forward(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, areas=True)
    response = client.get("/me?saved=preferences", follow_redirects=False)
    assert response.headers["location"] == "/home?section=my-work&saved=preferences"
    assert "Your choices are saved." in client.get(response.headers["location"]).text


# -- Nothing lost at the new address -------------------------------------------------

@pytest.mark.parametrize(("old", "new"), FORWARDS)
def test_new_address_shows_everything_the_old_page_showed(old, new, monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    classic, shell = client.get(old), client.get("/deliverables")
    assert classic.status_code == 200
    monkeypatch.undo()
    areas = _client(monkeypatch, tmp_path, areas=True).get(new)
    assert areas.status_code == 200
    _assert_nothing_lost(classic.text, areas.text, shell.text)


def test_home_views_are_page_tabs_in_the_roles_order(monkeypatch, tmp_path):
    from maverick_dashboard import navigation_api, ui_visibility

    def tabs(role):
        nav = ui_visibility.area_nav(ui_visibility.finder_pages(role), role)
        return [navigation_api.redirect_target(link["href"]) or link["href"]
                for link in nav["by_title"]["Home"]["sections"][0]["links"]
                if link["href"] in ("/today", "/me", "/overview")]

    assert tabs("admin") == ["/home", "/home?section=overview", "/home?section=my-work"]
    assert tabs("operator") == ["/home", "/home?section=my-work", "/home?section=overview"]
    client = _client(monkeypatch, tmp_path, areas=True, role="operator")
    html = client.get("/home?section=my-work").text
    item = html[html.index('href="/home?section=my-work"'):]
    assert 'aria-current="true"' in item[:item.index(">")]
    assert 'href="/home?section=overview"' in html and 'href="/home"' in html


def _page_tabs(html):
    """The shell's page tabs for this page's section (areas mode)."""
    pages = html[html.index('class="areanav__pages"'):]
    return pages[:pages.index("</nav>")]


def _current_tab(html):
    return unescape(_page_tabs(html).split('aria-current="true"')[0].rsplit('href="', 1)[1].split('"')[0])


def test_approvals_keeps_its_list_and_count_beside_the_action_center(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, areas=True)
    plain = client.get("/approvals").text
    assert 'id="action-center"' not in plain and "0 requests waiting" in plain
    assert _current_tab(plain) == "/approvals" and 'href="/approvals?view=all"' in plain
    every = client.get("/approvals?view=all").text
    assert 'id="action-center"' in every and "0 requests waiting" in every
    assert _current_tab(every) == "/approvals?view=all"
    # One link per address: Project workspaces now lives at Projects.
    assert _page_tabs(client.get("/projects").text).count('href="/projects"') == 1


def test_tasks_lists_background_work_and_names_the_owner_filter(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, areas=True)
    html = client.get("/goals?owner=me&include=background").text
    assert 'id="my-work"' in html and "Your tasks" in html
    assert "/static/lightwork-my-work.js" in html
    assert _current_tab(html) == "/goals?owner=me&include=background"
    assert 'id="my-work"' not in client.get("/goals").text


def test_projects_hold_project_plans_and_a_project_gets_a_plan_tab(monkeypatch, tmp_path):
    from maverick import world_model

    client = _client(monkeypatch, tmp_path, areas=True)
    assert 'data-plan-href="/projects/{id}?tab=plan"' in client.get("/projects").text
    world = world_model.WorldModel(tmp_path / "world.db")
    pid = world.create_project("Close", owner="user:admin")
    detail = client.get(f"/projects/{pid}").text
    assert f'href="/projects/{pid}?tab=plan"' in detail
    plan = client.get(f"/projects/{pid}?tab=plan").text
    assert f'data-project="{pid}"' in plan and f'href="/projects/{pid}"' in plan
    # Someone else's project: only the plan (its own API decides), never its tasks.
    other = world.create_project("Theirs", owner="user:someone")
    assert client.get(f"/projects/{other}").status_code == 404
    shared = client.get(f"/projects/{other}?tab=plan").text
    assert f'data-project="{other}"' in shared and f'href="/projects/{other}"' not in shared


def test_chat_form_mode_carries_every_builder_field_and_the_same_submit(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, areas=True)
    form = client.get("/chat?compose=form").text
    for marker in ('id="gb-title"', 'data-kind="step"', 'data-kind="budget"', 'data-kind="channel"',
                   'data-kind="priority"', 'id="gb-submit"', '"/api/v1/goals/compose"',
                   '"/chat/goal/" + j.id', "Give the task a title first."):
        assert marker in form, marker
    main = form[form.index("<main"):form.index("</main>")]
    assert main.count('class="btn btn--primary"') == 1
    plain = client.get("/chat").text
    assert 'id="gb-title"' not in plain and 'href="/chat?compose=form"' in plain


# -- Access stays exactly as it was ----------------------------------------------

def test_a_merged_view_checks_its_old_pages_access(monkeypatch, tmp_path):
    from maverick_dashboard import ui_visibility

    client = _client(monkeypatch, tmp_path, areas=True, role="operator")
    ui_visibility.set_visibility("/me", "operator", False)
    ui_visibility.set_visibility("/goal-builder", "operator", False)
    ui_visibility.set_visibility("/my-work", "operator", False)
    try:
        assert client.get("/home?section=my-work").status_code == 403
        assert client.get("/chat?compose=form").status_code == 403
        assert client.get("/goals?owner=me&include=background").status_code == 403
        assert client.get("/home").status_code == 200
        assert 'href="/chat?compose=form"' not in client.get("/chat").text
        assert 'include=background' not in client.get("/goals").text
    finally:
        ui_visibility.clear_overrides()


def test_no_forward_to_a_page_the_person_may_not_open(monkeypatch, tmp_path):
    from maverick_dashboard import ui_visibility

    client = _client(monkeypatch, tmp_path, areas=True, role="operator")
    ui_visibility.set_visibility("/goals", "operator", False)
    try:
        # They keep the old page, which they may still open.
        assert client.get("/my-work", follow_redirects=False).status_code == 200
    finally:
        ui_visibility.clear_overrides()


def test_viewer_cannot_reach_all_decisions_through_approvals(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, areas=True, role="viewer")
    assert client.get("/action-center", follow_redirects=False).status_code == 403
    assert client.get("/approvals?view=all").status_code == 403


def test_all_decisions_is_refused_while_the_action_center_is_off(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path, areas=True, action_center=False)
    refused = client.get("/approvals?view=all")
    assert refused.status_code == 403
    assert refused.headers.get("X-Lightwork-Reason") == "feature-off"
    plain = client.get("/approvals").text
    assert plain.count("0 requests waiting") and 'id="action-center"' not in plain


def test_home_opens_on_the_next_view_when_today_needs_a_named_account(monkeypatch, tmp_path):
    from maverick import experience_preferences

    client = _client(monkeypatch, tmp_path, areas=True)
    monkeypatch.setattr(experience_preferences, "enabled", lambda: False)
    home = client.get("/home", follow_redirects=False)
    assert (home.status_code, home.headers["location"]) == (303, "/home?section=my-work")
    assert client.get("/home?section=my-work").status_code == 200
    # Classic Today still refuses, as it always has.
    monkeypatch.setattr("maverick_dashboard.navigation_api.navigation_settings", lambda: ("classic", False))
    assert client.get("/today", follow_redirects=False).status_code == 403
