"""The finished forwards of the job-named navigation ("areas").

Each retired address keeps working as it is in classic mode (the default). In
areas mode it forwards to a tab or view of its new home, which shows
everything the old page showed -- every control and section, compared here
id by id and heading by heading -- and only to people who could open the old
page. Someone the new home does not admit keeps the old page.
"""
from __future__ import annotations

import re

import pytest
from maverick_dashboard.app import static_url

ROLE_DENIED = "this page is not enabled for your role"


def _client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from maverick import world_model
    from maverick_dashboard import app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    app._world_cache.clear()
    return TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _areas_on(monkeypatch):
    from maverick_dashboard import navigation_api

    monkeypatch.setattr(navigation_api, "navigation_settings", lambda: ("areas", False))


def _as(monkeypatch, role):
    from maverick_dashboard import app, auth, rbac

    principal = f"user:{role}"
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role(principal, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(app, "caller_principal", lambda request: principal)


@pytest.fixture
def knowledge_open(monkeypatch):
    """The Knowledge page admits the caller (switched on, named account,
    selected workspace) without a real registry behind it."""
    from maverick_dashboard import knowledge_access_api as ka

    def binding(request, response, payload=None, *, administrator=False):
        ka.require_permission(request, "operate")
        return "tenant-a", "user:admin", "context"

    monkeypatch.setattr(ka, "_binding", binding)
    monkeypatch.setattr(ka, "_registry_purposes", lambda *args: [])
    monkeypatch.setattr(ka, "_service", lambda request: None)


def _main(html: str) -> str:
    start = html.index('<main id="content"')
    return html[start:html.index("</main>", start)]


def _ids(html: str) -> set[str]:
    return set(re.findall(r'\bid="([^"{}]+)"', _main(html)))


def _headings(html: str) -> set[str]:
    found = re.findall(r"<h[2-4]\b[^>]*>(.*?)</h[2-4]>", _main(html), flags=re.DOTALL)
    return {re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", text)).strip() for text in found} - {""}


# (old address, its new home, the host page's own address)
FORWARDS = [
    ("/plan-tree-3d", "/graph-editor?view=3d"),
    ("/run-tree", "/replay?tab=branches"),
    ("/walkthroughs", "/replay?tab=video"),
    ("/trust", "/external-agents?tab=access"),
    ("/discovery", "/permissions?tab=inventory"),
    ("/autonomous-compliance", "/compliance?tab=overview"),
    ("/cortex", "/knowledge-access?tab=diagnostics"),
    ("/flows/designer", "/workflow-builder?mode=steps"),
]
# The old page's own title block, which its new home replaces with the host's.
HEADER_IDS = {"page-hero-title"}


def test_every_finished_forward_is_on_and_says_nothing_is_held():
    from maverick_dashboard import navigation_api

    table = {old: (new, ready, why) for old, new, ready, why in navigation_api.REDIRECTS}
    for old, new in FORWARDS:
        assert table[old] == (new, True, ""), old
        assert navigation_api.redirect_target(old) == new


@pytest.mark.parametrize("old, new", FORWARDS)
def test_old_address_stays_in_classic_mode(old, new, monkeypatch, tmp_path, knowledge_open):
    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "admin")
    page = client.get(old, follow_redirects=False)
    assert page.status_code == 200, old
    assert "areanav" not in page.text


@pytest.mark.parametrize("old, new", FORWARDS)
def test_old_address_forwards_in_areas_mode_and_the_new_home_shows_everything(
        old, new, monkeypatch, tmp_path, knowledge_open):
    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "admin")
    before = client.get(old).text
    _areas_on(monkeypatch)
    moved = client.get(old, follow_redirects=False)
    assert (moved.status_code, moved.headers["location"]) == (303, new)
    response = client.get(new)
    assert response.status_code == 200, new
    after = response.text
    # Every control, field, section and heading of the old page is there.
    assert (_ids(before) - HEADER_IDS) - _ids(after) == set(), old
    assert _headings(before) - _headings(after) == set(), old
    # ... inside the new home's tab list, with its tab selected.
    assert 'role="tablist"' in after and 'role="tabpanel"' in after
    selected = re.search(r'<a class="mv-tab" role="tab"[^>]*href="([^"]+)"\s[^>]*aria-selected="true"', after)
    assert selected and selected.group(1).replace("&amp;", "&") == new


@pytest.mark.parametrize("old, new", FORWARDS)
def test_the_new_view_also_answers_at_its_address_in_classic_mode(old, new, monkeypatch, tmp_path, knowledge_open):
    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "admin")
    assert client.get(new).status_code == 200


HOSTS = ["/graph-editor", "/replay", "/external-agents", "/permissions", "/compliance", "/knowledge-access",
         "/workflow-builder"]


@pytest.mark.parametrize("host", HOSTS)
def test_host_pages_show_their_tabs_only_in_areas_mode(host, monkeypatch, tmp_path, knowledge_open):
    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "admin")
    classic = client.get(host)
    assert classic.status_code == 200
    assert "data-mv-tabs" not in classic.text  # the classic page is as it was
    _areas_on(monkeypatch)
    areas = client.get(host).text
    assert "data-mv-tabs" in areas and 'role="tablist"' in areas
    assert f'<script src="{static_url("lightwork-tabs.js")}" defer></script>' in areas


def test_old_query_values_carry_over_to_the_new_address(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "admin")
    _areas_on(monkeypatch)
    moved = client.get("/run-tree?goal=7", follow_redirects=False)
    assert moved.headers["location"] == "/replay?tab=branches&goal=7"
    started = client.get("/flows/designer?from_template=weekly-report", follow_redirects=False)
    assert started.headers["location"] == "/workflow-builder?mode=steps&from_template=weekly-report"
    # A saved flow keeps its own address (record links point there).
    assert client.get("/flows/designer/weekly", follow_redirects=False).status_code == 200


def test_branches_tab_keeps_the_selected_task_and_links_inside_task_replay(monkeypatch, tmp_path):
    from maverick_dashboard import app

    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "admin")
    goal = app._world().create_goal("Quarterly summary", "", owner="user:admin")
    _areas_on(monkeypatch)
    replay = client.get(f"/replay?goal={goal}").text
    assert f'href="/replay?tab=branches&amp;goal={goal}"' in replay
    branches = client.get(f"/replay?tab=branches&goal={goal}").text
    assert "/run-tree?" not in branches
    assert '"/replay?tab=branches&" + \'goal=\'' in branches or "/replay?tab=branches\\u0026" in branches


# -- Floors: nobody sees more or less than before ---------------------------------

def test_a_person_the_new_home_does_not_admit_keeps_the_old_page(monkeypatch, tmp_path, knowledge_open):
    # A viewer may open Discovery but not Permissions, the 3D plan view but not
    # the task map, and Branches but not Task replay (the defaults).
    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "viewer")
    _areas_on(monkeypatch)
    for old in ("/discovery", "/plan-tree-3d", "/run-tree", "/cortex"):
        page = client.get(old, follow_redirects=False)
        assert page.status_code == 200, old
    assert client.get("/permissions?tab=inventory").status_code == 403


def test_the_knowledge_page_must_admit_the_person_before_cortex_forwards(monkeypatch, tmp_path):
    from fastapi import HTTPException
    from maverick_dashboard import knowledge_access_api as ka

    def closed(request, response, payload=None, *, administrator=False):
        raise HTTPException(404, "Governed knowledge access is disabled")

    monkeypatch.setattr(ka, "_binding", closed)
    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "admin")
    _areas_on(monkeypatch)
    page = client.get("/cortex", follow_redirects=False)
    assert page.status_code == 200
    assert 'id="ctx-root"' in page.text


@pytest.mark.parametrize("old, host, tab", [
    ("/trust", "/external-agents", "/external-agents?tab=access"),
    ("/autonomous-compliance", "/compliance", "/compliance?tab=overview"),
    ("/discovery", "/permissions", "/permissions?tab=inventory"),
    ("/walkthroughs", "/replay", "/replay?tab=video"),
    ("/plan-tree-3d", "/graph-editor", "/graph-editor?view=3d"),
    ("/flows/designer", "/workflow-builder", "/workflow-builder?mode=steps"),
])
def test_a_tab_shows_only_to_people_who_may_open_the_old_page(old, host, tab, monkeypatch, tmp_path):
    from maverick_dashboard import ui_visibility

    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "admin")
    _areas_on(monkeypatch)
    assert f'href="{tab.replace("&", "&amp;")}"' in client.get(host).text
    ui_visibility.set_visibility(old, "admin", False)
    assert client.get(old).status_code == 403
    page = client.get(host)
    assert page.status_code == 200
    assert f'href="{tab.replace("&", "&amp;")}"' not in page.text
    denied = client.get(tab)
    assert denied.status_code == 403 and ROLE_DENIED in denied.text


def test_cortex_diagnostics_keep_the_audit_tail_behind_the_audit_permission(monkeypatch, tmp_path, knowledge_open):
    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "operator")
    _areas_on(monkeypatch)
    moved = client.get("/cortex", follow_redirects=False)
    assert moved.headers["location"] == "/knowledge-access?tab=diagnostics"
    page = client.get("/knowledge-access?tab=diagnostics")
    assert page.status_code == 200
    assert 'id="ctx-recent-locked"' in page.text  # an operator cannot read the activity log
    assert "nonce-" in page.headers["content-security-policy"]


def test_the_sidebar_links_an_old_page_to_its_new_home_only_for_people_it_admits(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "viewer")
    _areas_on(monkeypatch)
    html = client.get("/discovery").text
    assert 'href="/permissions?tab=inventory"' not in html
    assert 'href="/discovery"' in html


def _area_pages(html: str) -> list[str]:
    start = html.find('class="areanav__pages"')
    if start < 0:
        return []
    block = html[start:html.index("</nav>", start)]
    return [href.replace("&amp;", "&") for href in re.findall(r'href="([^"]+)"', block)]


def test_a_merged_page_is_one_tab_not_a_second_page_beside_its_new_home(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "admin")
    _areas_on(monkeypatch)
    pages = _area_pages(client.get("/permissions?tab=inventory").text)
    assert "/permissions" in pages
    assert "/discovery" not in pages and "/permissions?tab=inventory" not in pages
    # Task replay's section held only Replay, Branches and Video: one page now,
    # so it shows no page list at all -- its views are the tab bar.
    replay = client.get("/replay").text
    assert _area_pages(replay) == []
    assert 'href="/replay?tab=branches"' in replay and 'href="/replay?tab=video"' in replay


# -- Steps mode of the workflow builder ---------------------------------------------

FLOW = {
    "id": "weekly-digest", "name": "Weekly digest", "start": "write",
    "nodes": [
        {"id": "write", "kind": "agent", "brief": "Write the weekly digest", "next": "check", "output": "draft"},
        {"id": "check", "kind": "approval", "prompt": "Send it?", "next": "send"},
        {"id": "send", "kind": "action", "tool": "notify", "params": {"m": "{{draft}}"}},
    ],
}


def _flows_on(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    return _client(monkeypatch, tmp_path)


def test_steps_mode_holds_every_flow_designer_control(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    _as(monkeypatch, "admin")
    designer = client.get("/flows/designer").text
    steps = client.get("/workflow-builder?mode=steps").text
    designer_ids, steps_ids = _ids(designer), _ids(steps)
    assert designer_ids - steps_ids == set()
    # Editing, saving, publishing, testing, running, versions, triggers,
    # drafting from plain English, import and export, and the assistant.
    for control in ("fd-canvas", "fd-save", "fd-publish", "fd-run", "fd-run-real", "fd-history", "fd-triggers",
                    "fd-draft", "fd-export", "fd-import-json", "fd-chat-toggle", "fd-view-canvas", "fd-simple"):
        assert control in steps_ids, control
    # The same editor script, talking to the same flow calls.
    for call in ("'/api/v1/flows'", "'/api/v1/flows/' + encodeURIComponent(rootFlow.id) + '/publish'",
                 "'/api/v1/flows/insights'", "'/flows/designer/' + encodeURIComponent(id)"):
        assert call in steps, call
    assert "<title>Step by step · Workflow builder · Lightwork</title>" in steps
    # One "Steps": the mode tab says "Step by step", the editor's own switch keeps "Steps".
    assert ">Step by step</a>" in steps and ">Steps</a>" not in steps
    assert '<button type="button" id="fd-view-steps" class="is-on" aria-pressed="true">Steps</button>' in steps


def test_a_saved_flow_opens_and_saves_unchanged_in_steps_mode(monkeypatch, tmp_path):
    client = _flows_on(monkeypatch, tmp_path)
    created = client.post("/api/v1/flows", json={"flow": FLOW})
    assert created.status_code == 201, created.text
    saved = client.get("/api/v1/flows/weekly-digest").json()
    page = client.get("/workflow-builder?mode=steps&flow=weekly-digest")
    assert page.status_code == 200
    assert 'data-flow-id="weekly-digest"' in page.text
    assert 'href="/flows/weekly-digest/teach"' in page.text
    # Saving what the editor loaded keeps every step: the same calls, no migration.
    again = client.post("/api/v1/flows", json={"flow": saved})
    assert again.status_code in (200, 201), again.text
    reread = client.get("/api/v1/flows/weekly-digest").json()
    assert reread["nodes"] == saved["nodes"] and reread["start"] == saved["start"]
    assert reread["name"] == saved["name"]
    # A bad id opens a blank editor rather than anything else.
    assert 'data-flow-id=""' in client.get("/workflow-builder?mode=steps&flow=../etc").text


def test_steps_mode_starts_from_a_saved_template_like_the_designer(monkeypatch, tmp_path):
    import maverick.templates as saved_templates

    client = _flows_on(monkeypatch, tmp_path)
    folder = tmp_path / ".maverick" / "templates"
    monkeypatch.setattr(saved_templates, "USER_TEMPLATES", folder)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "weekly-digest.md").write_text(
        "---\nowner: local\ntitle: Weekly digest\nparams: []\n---\nWrite the weekly digest.\n", encoding="utf-8")
    designer = client.get("/flows/designer?from_template=weekly-digest").text
    steps = client.get("/workflow-builder?mode=steps&from_template=weekly-digest").text
    seed = re.compile(r'<script\b[^>]*\bid="fd-seed"[^>]*>(.*?)</script>', re.DOTALL)
    assert seed.search(designer).group(1) == seed.search(steps).group(1)
    assert "Write the weekly digest." in seed.search(steps).group(1)
