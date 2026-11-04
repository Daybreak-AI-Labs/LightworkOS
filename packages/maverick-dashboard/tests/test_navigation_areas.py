"""The job-named navigation ("areas"): one area per page, off by default.

``[dashboard] navigation`` stays "classic" unless an administrator chooses
"areas"; the classic sidebar is untouched (its own tests pin it). In areas
mode every area, section, tab and breadcrumb comes from the registry and only
from pages the viewer may already open -- floors never move.
"""
from __future__ import annotations

import csv
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
TASKS = ROOT / "docs" / "tree-test" / "tasks.csv"
ROLES = ("viewer", "operator", "auditor", "admin")


def _client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from maverick import world_model
    from maverick_dashboard import app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    app._world_cache.clear()
    return TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _areas_on(monkeypatch, personal=False):
    from maverick_dashboard import navigation_api

    monkeypatch.setattr(navigation_api, "navigation_settings", lambda: ("areas", personal))


def _moved(href):
    """Where a link points in areas mode: an old address's new home."""
    from maverick_dashboard import navigation_api

    return navigation_api.redirect_target(href) or href


def _as(monkeypatch, principal, role):
    from maverick_dashboard import auth, rbac

    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role(principal, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)


class _Shell(HTMLParser):
    """Sidebar area entries, section links, breadcrumb and local tabs."""

    def __init__(self, html):
        super().__init__()
        self.areas, self.sections, self.crumbs, self.tabs, self.pages = [], [], [], [], []
        self.where, self.stack = None, []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        classes = (values.get("class") or "").split()
        for name, where in (("navarea__sections", "sections"), ("areanav__crumbs", "crumbs"),
                            ("areanav__tabs", "tabs"), ("areanav__pages", "pages")):
            if name in classes:
                self.where = where
        if tag == "a" and "navarea__link" in classes:
            self.areas.append(values["href"])
            self.stack.append("area")
        elif tag == "a" and self.where:
            getattr(self, self.where).append(values["href"])

    def handle_endtag(self, tag):
        if tag in ("ul", "nav", "ol"):
            self.where = None


# -- The registry --------------------------------------------------------------

def test_every_registered_page_has_exactly_one_area_and_a_known_section():
    from maverick_dashboard import ui_visibility

    paths = [page["path"] for page in ui_visibility.PAGES]
    # One entry per page: no page is placed twice, and none is left out.
    assert sorted(ui_visibility.PAGE_AREAS) == sorted(paths)
    assert len(set(paths)) == len(paths)
    sections = {title: names for title, _hub, names in ui_visibility.AREAS}
    for path, (area, section) in ui_visibility.PAGE_AREAS.items():
        assert area in sections, path
        assert section in sections[area], path
        assert ui_visibility.place(path) == (area, section)
    # The nine sidebar areas plus the Ask button and the account and help menus.
    assert ui_visibility.SIDEBAR_AREAS == (
        "Home", "Work", "Agents", "Rules & safety", "Privacy", "Risk & compliance",
        "Evidence & audit", "Costs & value", "Settings")
    assert set(sections) == {*ui_visibility.SIDEBAR_AREAS, "Ask", "Account", "Help"}


def test_a_newly_registered_page_cannot_ship_without_an_area():
    """Names each registered page that areas mode cannot place, so a new page
    fails here (not only as a sorted-list diff) until it gets an area, an
    existing section of that area and that section's translations."""
    from maverick_dashboard import i18n_journeys, ui_visibility

    sections = {title: set(names) for title, _hub, names in ui_visibility.AREAS}
    translated = {row[0] for row in i18n_journeys.ROWS}
    unplaced = []
    for page in ui_visibility.PAGES:
        spot = ui_visibility.PAGE_AREAS.get(page["path"])
        if spot is None:
            unplaced.append(f"{page['path']}: no entry in PAGE_AREAS")
        elif spot[1] not in sections.get(spot[0], ()):
            unplaced.append(f"{page['path']}: section {spot[1]!r} is not one of {spot[0]!r}'s sections")
        elif not set(spot) <= translated:
            unplaced.append(f"{page['path']}: {spot!r} has no translations")
    assert not unplaced, "\n".join(unplaced)


def test_each_area_hub_is_a_registered_page_of_that_area_and_every_section_is_used():
    from maverick_dashboard import ui_visibility

    for title, hub, names in ui_visibility.AREAS:
        assert ui_visibility.page_for(hub)["path"] == hub
        assert ui_visibility.PAGE_AREAS[hub][0] == title
        used = {section for area, section in ui_visibility.PAGE_AREAS.values() if area == title}
        assert used == set(names), title


def test_areas_never_change_who_may_open_a_page():
    from maverick_dashboard import ui_visibility

    # Floors and defaults are still the only authority; a page keeps them.
    for page in ui_visibility.PAGES:
        assert {"floor", "default"} <= page.keys()
    for role in ROLES:
        finder = ui_visibility.finder_pages(role)
        allowed = {link["href"] for group in finder for link in group["links"]}
        nav = ui_visibility.area_nav(finder, role)
        offered = {link["href"] for area in nav["by_title"].values()
                   for section in area["sections"] for link in section["links"]}
        assert offered == allowed, role


# -- Role presets ----------------------------------------------------------------

@pytest.mark.parametrize("role", ROLES)
def test_each_role_sees_exactly_the_areas_its_floors_allow(role, monkeypatch, tmp_path):
    from maverick_dashboard import ui_visibility

    monkeypatch.setenv("HOME", str(tmp_path))
    finder = ui_visibility.finder_pages(role)
    nav = ui_visibility.area_nav(finder, role)
    allowed = {link["href"] for group in finder for link in group["links"]}
    expected = {area for area in ui_visibility.SIDEBAR_AREAS
                if any(ui_visibility.PAGE_AREAS[path][0] == area for path in allowed)}
    assert {area["title"] for area in nav["sidebar"]} == expected
    for area in nav["sidebar"]:
        # Each entry opens the hub when the viewer may open it, else the
        # area's first page they may open.
        assert area["href"] in allowed
        if area["hub"] in allowed:
            assert area["href"] == area["hub"]
    if role == "admin":
        assert [area["title"] for area in nav["sidebar"]] == list(ui_visibility.SIDEBAR_AREAS)
    if role == "viewer":
        # Admin-only pages never surface for a viewer.
        admin_only = {page["path"] for page in ui_visibility.PAGES if page["floor"] == "admin"}
        assert admin_only.isdisjoint(link["href"] for area in nav["by_title"].values()
                                     for section in area["sections"] for link in section["links"])


def test_role_presets_set_order_open_areas_and_start_page():
    from maverick_dashboard import ui_visibility

    assert ui_visibility.area_preset_name("admin") == "admin"
    assert ui_visibility.area_preset_name("operator") == "employee"
    assert ui_visibility.area_preset_name("viewer") == "employee"
    assert ui_visibility.area_preset_name("auditor") == "approver"
    assert ui_visibility.area_preset_name("privacy-officer") == "privacy-officer"
    assert ui_visibility.area_preset_name("approver") == "approver"
    assert ui_visibility.area_preset_name(None) == "admin"  # the local owner sees everything
    finder = ui_visibility.finder_pages(None)
    privacy = ui_visibility.area_nav(finder, "privacy-officer")
    assert [area["title"] for area in privacy["sidebar"]][:5] == [
        "Home", "Work", "Privacy", "Risk & compliance", "Evidence & audit"]
    assert {area["title"] for area in privacy["sidebar"] if area["open"]} == {"Privacy"}
    assert privacy["start"] == "/privacy"
    approver = ui_visibility.area_nav(finder, "approver")
    work = approver["by_title"]["Work"]
    assert work["sections"][0]["title"] == "Approvals"
    assert work["sections"][0]["href"] == "/approvals"
    assert approver["start"] == "/approvals"
    employee = ui_visibility.area_nav(finder, "operator")
    assert [area["title"] for area in employee["sidebar"]][:3] == ["Home", "Work", "Agents"]


def test_a_persons_own_layout_reorders_and_hides_areas():
    from maverick_dashboard import ui_visibility

    finder = ui_visibility.finder_pages(None)
    nav = ui_visibility.area_nav(finder, "admin", layout=["Privacy", "Work"])
    assert [area["title"] for area in nav["sidebar"]] == ["Privacy", "Work"]
    # A hidden area's pages stay reachable (Ctrl+K, links); only the entry goes.
    assert "Settings" in nav["by_title"]


def test_switched_off_pages_are_dropped_for_people_who_cannot_turn_them_on():
    from maverick_dashboard import ui_visibility

    finder = ui_visibility.finder_pages(None)
    off = frozenset({"/code"})
    hidden = ui_visibility.area_nav(finder, "operator", off=off)
    assert "/code" not in {link["href"] for section in hidden["by_title"]["Work"]["sections"]
                           for link in section["links"]}
    marked = ui_visibility.area_nav(finder, "admin", off=off, can_turn_on=True)
    code = next(section for section in marked["by_title"]["Work"]["sections"] if section["title"] == "Code changes")
    assert code["off"] is True


# -- The setting -----------------------------------------------------------------

def test_navigation_is_classic_unless_the_installation_chooses_areas(monkeypatch):
    from maverick import config
    from maverick_dashboard import navigation_api

    monkeypatch.setattr(config, "load_config", dict)
    assert navigation_api.navigation_settings() == ("classic", False)
    monkeypatch.setattr(config, "load_config", lambda: {"dashboard": {"navigation": "sideways"}})
    assert navigation_api.navigation_settings() == ("classic", False)
    monkeypatch.setattr(config, "load_config", lambda: {"dashboard": {"navigation": "areas",
                                                                        "navigation_personal": True}})
    assert navigation_api.navigation_settings() == ("areas", True)


def test_classic_mode_renders_no_areas_markup(monkeypatch, tmp_path):
    from maverick_dashboard import navigation_api

    client = _client(monkeypatch, tmp_path)
    default = client.get("/goals").text
    monkeypatch.setattr(navigation_api, "navigation_settings", lambda: ("classic", True))
    chosen = client.get("/goals").text
    for html in (default, chosen):
        assert "navareas" not in html and "areanav" not in html
        assert 'class="navgrp"' in html


@pytest.mark.parametrize("path", ["/goals", "/chat"])
def test_both_shells_show_one_sidebar_entry_per_area(path, monkeypatch, tmp_path):
    from maverick_dashboard import ui_visibility

    client = _client(monkeypatch, tmp_path)
    _areas_on(monkeypatch)
    html = client.get(path).text
    shell = _Shell(html)
    nav = ui_visibility.area_nav(ui_visibility.finder_pages(None), None)
    assert shell.areas == [_moved(area["href"]) for area in nav["sidebar"]]
    assert 'class="navgrp"' not in html  # no classic groups beside the areas
    assert 'aria-label="Most used"' not in html


@pytest.mark.parametrize("role", ROLES)
def test_rendered_areas_follow_each_roles_floors(role, monkeypatch, tmp_path):
    from maverick_dashboard import ui_visibility

    client = _client(monkeypatch, tmp_path)
    _areas_on(monkeypatch)
    _as(monkeypatch, f"user:{role}", role)
    response = client.get("/deliverables")
    assert response.status_code == 200
    shell = _Shell(response.text)
    allowed = {link["href"] for group in ui_visibility.finder_pages(role) for link in group["links"]}
    allowed |= {_moved(href) for href in allowed}
    assert shell.areas and set(shell.areas) <= allowed
    assert set(shell.sections) <= allowed
    assert set(shell.tabs) <= allowed


def test_child_page_shows_area_and_section_breadcrumb_and_local_tabs(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    _areas_on(monkeypatch)
    html = client.get("/audit/receipts").text
    shell = _Shell(html)
    assert shell.crumbs == ["/audit"]
    assert 'aria-label="Breadcrumb"' in html
    assert ">Evidence &amp; audit<" in html and ">Trust receipts<" in html
    assert "/audit/receipts" in shell.tabs and "/audit" in shell.tabs


def test_hub_page_lists_its_sections_and_folded_pages_without_a_breadcrumb(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    _areas_on(monkeypatch)
    html = client.get("/privacy").text
    shell = _Shell(html)
    assert shell.crumbs == []
    assert "/privacy/rights-orchestration" in shell.tabs  # folded out of the classic rail
    assert "All pages in" in html


def test_command_menu_shows_area_and_section_in_areas_mode(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    classic = client.get("/nav/finder").text
    assert "Governance" in classic and "Evidence &amp; audit" not in classic
    _areas_on(monkeypatch)
    areas = client.get("/nav/finder").text
    item = areas[areas.index('href="/audit/receipts"'):]
    item = item[:item.index("</a>")]
    assert "Evidence &amp; audit" in item and "Trust receipts" in item and "›" in item


def test_personal_choice_applies_only_when_the_installation_allows_it(monkeypatch, tmp_path):
    from maverick import experience_preferences
    from maverick_dashboard import navigation_api

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(experience_preferences, "enabled", lambda: True)
    _as(monkeypatch, "user:ann", "operator")
    state = experience_preferences.state("user:ann")
    experience_preferences.save("user:ann", scope="personal", changes={"navigation": "areas"},
                                expected_revision=state["revision"])
    monkeypatch.setattr(navigation_api, "navigation_settings", lambda: ("classic", False))
    assert "navareas" not in client.get("/goals").text
    monkeypatch.setattr(navigation_api, "navigation_settings", lambda: ("classic", True))
    assert "navareas" in client.get("/goals").text
    page = client.get("/preferences").text
    assert 'data-pref="navigation"' in page


def test_people_arrange_their_own_areas_and_can_go_back_to_their_roles_layout(monkeypatch, tmp_path):
    from maverick import experience_preferences

    client = _client(monkeypatch, tmp_path)
    _areas_on(monkeypatch)
    monkeypatch.setattr(experience_preferences, "enabled", lambda: True)
    _as(monkeypatch, "user:ann", "admin")
    html = client.get("/goals").text
    assert "Arrange areas" in html
    context = html.split('name="lightwork-preference-context" content="', 1)[1].split('"', 1)[0]
    assert context
    moved = client.post("/navigation/areas", data={"op": "up", "area": "Work", "context": context, "back": "/goals"},
                        follow_redirects=False)
    assert moved.status_code == 303 and moved.headers["location"] == "/goals"
    assert _Shell(client.get("/goals").text).areas[:2] == ["/goals", "/home"]
    hidden = client.post("/navigation/areas", data={"op": "hide", "area": "Settings", "context": context})
    assert hidden.status_code == 200
    assert "/settings" not in _Shell(client.get("/goals").text).areas
    bad = client.post("/navigation/areas", data={"op": "up", "area": "Nowhere", "context": context},
                      follow_redirects=False)
    assert bad.status_code == 403
    away = client.post("/navigation/areas", data={"op": "reset", "context": context, "back": "//evil.example"},
                       follow_redirects=False)
    assert away.headers["location"] == "/"
    assert _Shell(client.get("/goals").text).areas[:2] == ["/home", "/goals"]


def test_arranging_areas_keeps_an_edit_made_in_another_window(monkeypatch, tmp_path):
    """The layout an edit builds on is the one saved now, not the one the request
    first read: hiding one area must not bring back one hidden a moment earlier
    in another window."""
    from maverick import experience_preferences
    from maverick_dashboard import app as app_mod

    client = _client(monkeypatch, tmp_path)
    _areas_on(monkeypatch)
    monkeypatch.setattr(experience_preferences, "enabled", lambda: True)
    _as(monkeypatch, "user:ann", "admin")
    html = client.get("/goals").text
    context = html.split('name="lightwork-preference-context" content="', 1)[1].split('"', 1)[0]

    real, seen = app_mod._nav_context, []

    def racing(request):
        ctx = real(request)
        if not seen:
            seen.append([item["title"] for item in ctx["nav_areas"]["sidebar"]])
            state = experience_preferences.state("user:ann")
            experience_preferences.save(
                "user:ann", scope="personal",
                changes={"navigation_areas": [t for t in seen[0] if t != "Settings"]},
                expected_revision=state["revision"])  # the other window hides Settings
        return ctx

    monkeypatch.setattr(app_mod, "_nav_context", racing)
    hidden = client.post("/navigation/areas", data={"op": "hide", "area": "Work", "context": context},
                         follow_redirects=False)
    assert hidden.status_code == 303, hidden.text
    saved = experience_preferences.state("user:ann")["values"]["navigation_areas"]
    assert "Work" in seen[0] and "Settings" in seen[0]
    assert saved == [t for t in seen[0] if t not in {"Settings", "Work"}]


# -- The tree-test kit -------------------------------------------------------------

@pytest.mark.parametrize("mode", ["classic", "areas"])
def test_every_tree_test_answer_exists_in_the_exported_tree(mode):
    from maverick_dashboard import nav_tree

    tasks = nav_tree.read_tasks(str(TASKS))
    by_role: dict[str, int] = {}
    for task in tasks:
        by_role[task["role"]] = by_role.get(task["role"], 0) + 1
    assert set(by_role) == {"Employee", "Approver", "Privacy officer", "Admin"}
    assert all(count >= 15 for count in by_role.values())
    for row in nav_tree.answers(nav_tree.tree(mode), tasks):
        assert row["nodes"] and not row["missing"], row


def test_tree_exports_are_importable_text_and_csv():
    from maverick_dashboard import nav_tree, ui_visibility

    leaves = nav_tree.tree("areas")
    text = nav_tree.as_text(leaves)
    assert text.splitlines()[0] == "Ask"
    lines = text.splitlines()
    assert "Work" in lines and "\tTasks" in lines and "\t\tTrust receipts" not in lines
    rows = list(csv.reader(nav_tree.as_csv(leaves).splitlines()))
    assert rows[0] == ["Level 1", "Level 2", "Level 3", "Address"]
    ready = {page["path"] for page in ui_visibility.PAGES if ui_visibility.customer_ready(page)}
    assert {row[3] for row in rows[1:]} == ready
    classic = {path for _labels, path in nav_tree.tree("classic")}
    assert classic == ready
    viewer = {path for _labels, path in nav_tree.tree("areas", "viewer")}
    assert viewer < ready and "/settings" not in viewer


def test_exported_tree_files_match_the_registry():
    from maverick_dashboard import nav_tree

    folder = TASKS.parent
    for mode in ("classic", "areas"):
        leaves = nav_tree.tree(mode)
        assert (folder / f"{mode}-tree.txt").read_text(encoding="utf-8") == nav_tree.as_text(leaves)
        assert (folder / f"{mode}-tree.csv").read_text(encoding="utf-8") == nav_tree.as_csv(leaves)


# -- Redirects and Home (areas mode only) ----------------------------------------

def test_redirect_table_covers_report_section_five_and_both_decided_pages():
    from maverick_dashboard import navigation_api

    olds = [old for old, _new, _ready, _why in navigation_api.REDIRECTS]
    assert len(olds) == len(set(olds)) == 17
    assert "/goal-builder" in olds and "/flows/designer" in olds
    for old, new, ready, why in navigation_api.REDIRECTS:
        sample = old.replace("{id}", "7")
        if ready:
            assert navigation_api.redirect_target(sample) == new.replace("{id}", "7"), old
            assert not why
        else:
            # Held until its new address holds the old page's job; says why.
            assert navigation_api.redirect_target(sample) is None, old
            assert why.endswith("."), old
    assert navigation_api.redirect_target("/tasks/abc/diagnostics") is None
    assert navigation_api.redirect_target("/todayish") is None


def _signed_in(monkeypatch, tmp_path, role="operator"):
    from maverick import experience_preferences
    from maverick_dashboard import onboarding_state

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(experience_preferences, "enabled", lambda: True)
    monkeypatch.setattr(onboarding_state, "selected_model_routes_ready", lambda: True)
    _as(monkeypatch, f"user:{role}", role)
    from maverick_dashboard import app

    monkeypatch.setattr(app, "caller_principal", lambda request: f"user:{role}")
    return client


def test_old_addresses_and_root_stay_as_they_are_in_classic_mode(monkeypatch, tmp_path):
    client = _signed_in(monkeypatch, tmp_path)
    today = client.get("/today", follow_redirects=False)
    assert today.status_code == 200
    root = client.get("/", follow_redirects=False)
    assert root.status_code == 200 and 'action="/chat/send"' in root.text  # Chat, as today
    assert client.get("/home", follow_redirects=False).status_code == 404
    assert client.get("/goals/7/diagnostics", follow_redirects=False).status_code == 404


def test_ready_redirects_fire_and_root_opens_home_in_areas_mode(monkeypatch, tmp_path):
    client = _signed_in(monkeypatch, tmp_path)
    _areas_on(monkeypatch)
    today = client.get("/today", follow_redirects=False)
    assert (today.status_code, today.headers["location"]) == (303, "/home")
    root = client.get("/", follow_redirects=False)
    assert (root.status_code, root.headers["location"]) == (303, "/home")
    home = client.get("/home")
    assert home.status_code == 200
    shell = _Shell(home.text)
    assert shell.areas[0] == "/home"  # the sidebar links straight to the new address
    # Held redirects leave their pages where they are.
    assert client.get("/walkthroughs", follow_redirects=False).status_code != 303


def test_a_chosen_start_page_still_wins_in_areas_mode(monkeypatch, tmp_path):
    from maverick import experience_preferences

    client = _signed_in(monkeypatch, tmp_path)
    _areas_on(monkeypatch)
    state = experience_preferences.state("user:operator")
    experience_preferences.save("user:operator", scope="personal", changes={"start_page": "/goals"},
                                expected_revision=state["revision"])
    root = client.get("/", follow_redirects=False)
    assert (root.status_code, root.headers["location"]) == (303, "/goals")


# Words the areas sidebar, tabs and breadcrumb show besides page names.
_AREA_CHROME = ("Areas", "{area} sections", "Arrange areas", "Move {area} up", "Move {area} down",
                "Hide {area}", "Show {area}", "Up", "Down", "Hide", "Show", "hidden",
                "Use the layout for my role", "Breadcrumb", "Pages in {section}", "All pages in {area}")


def test_every_area_and_section_name_has_its_four_translations():
    from maverick_dashboard import i18n_journeys, ui_visibility

    names = {title for title, _hub, _sections in ui_visibility.AREAS}
    names |= {section for _title, _hub, sections in ui_visibility.AREAS for section in sections}
    names |= {name for spot in ui_visibility.PAGE_AREAS.values() for name in spot}
    rows = {row[0]: row[1:] for row in i18n_journeys.ROWS}
    missing = sorted(name for name in names | set(_AREA_CHROME) if name not in rows)
    assert not missing, missing
    for name in names | set(_AREA_CHROME):
        for lang in i18n_journeys.TRANSLATION_LANGS:
            translated, actual = i18n_journeys.entry(name, lang)
            assert actual == lang and translated.strip(), (name, lang)
