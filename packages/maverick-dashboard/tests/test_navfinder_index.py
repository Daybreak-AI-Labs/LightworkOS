"""The page finder (Ctrl+K) indexes every governed page the caller may open,
including pages folded out of the sidebar rail (``in_nav: False``) -- the
sidebar stays the curated subset, the finder is the searchable whole.

Contracts under test:
  * ``finder_pages`` applies exactly nav_groups' RBAC + override filtering but
    ignores ``in_nav``; nav_groups' output is unchanged;
  * the rendered shell's finder lists the folded pages, the sidebar does not;
  * ``/security/report`` and ``/security/assurance`` are governed registry
    pages (previously live routes the visibility matrix did not know about).
"""
from __future__ import annotations

from html.parser import HTMLParser

import pytest

fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient

# Reachable in-page / by URL, deliberately off the rail, previously unsearchable.
FOLDED = (
    "/third-party/intelligence",
    "/third-party/lifecycle",
    "/third-party/collaboration",
    "/security/threats",
    "/security/soc",
)
# Live routes linked from security.html / get_started.html; now registered.
NEWLY_GOVERNED = ("/security/report", "/security/assurance")
# Screens with their own routes that the registry now governs (they were
# missing from the finder). The first four also need a named account.
NAMED_ACCOUNT_SCREENS = ("/notifications", "/access-requests", "/devices", "/get-started/employee",
                         "/human-conversations")
OPEN_SCREENS = ("/help", "/budget", "/my-work", "/conversations", "/cost-reconciliation",
                "/project-workspaces", "/provider-spending")


def _hrefs(groups: list[dict]) -> list[str]:
    return [ln["href"] for g in groups for ln in g["links"]]


# ---------- registry + pure logic (no HTTP) ----------

def test_finder_pages_lists_folded_pages_that_nav_groups_excludes(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick_dashboard import ui_visibility

    nav = set(_hrefs(ui_visibility.nav_groups("admin")))
    finder = _hrefs(ui_visibility.finder_pages("admin"))
    offered = {p for p in FOLDED if ui_visibility.customer_ready(ui_visibility.page_for(p))}
    held = set(FOLDED) - offered
    assert offered and offered <= set(finder)
    # A folded page held back as not ready would be offered nowhere, finder included.
    assert held.isdisjoint(finder)
    assert set(FOLDED).isdisjoint(nav)
    # The sidebar is a strict subset of the finder; nothing is finder-only
    # beyond in_nav=False pages, and the finder has no duplicates.
    assert nav <= set(finder)
    assert len(finder) == len(set(finder))
    assert set(finder) - nav == {
        p["path"] for p in ui_visibility.PAGES
        if not p.get("in_nav", True) and ui_visibility.customer_ready(p)
    }
    # auth off: every customer-ready registered page exactly once (grouped by
    # label like the nav, so a group split in the registry is merged, not
    # duplicated); pages held back as not ready are offered nowhere.
    auth_off = _hrefs(ui_visibility.finder_pages(None))
    assert sorted(auth_off) == sorted(
        p["path"] for p in ui_visibility.PAGES if ui_visibility.customer_ready(p)
    )
    assert set(auth_off).isdisjoint(ui_visibility.not_ready_paths())
    # Groups merge by label like the nav (no duplicate sections).
    labels = [g["label"] for g in ui_visibility.finder_pages("admin")]
    assert len(labels) == len(set(labels))


def test_finder_pages_applies_the_same_rbac_and_overrides_as_nav_groups(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick_dashboard import rbac, ui_visibility

    # Floor: a viewer never reaches operate-floor pages, folded or not.
    viewer = set(_hrefs(ui_visibility.finder_pages("viewer")))
    assert viewer.isdisjoint({"/security/threats", "/security/soc", "/chat", "/settings"})
    assert "/overview" in viewer
    # Overrides: hiding a folded page for a role hides it from that role's finder.
    assert "/fleets" in _hrefs(ui_visibility.finder_pages("operator"))
    ui_visibility.set_visibility("/fleets", "operator", False)
    assert "/fleets" not in _hrefs(ui_visibility.finder_pages("operator"))
    assert "/security/soc" in _hrefs(ui_visibility.finder_pages("admin"))
    # Lockout guard: the store refuses to hide /settings from admins, and the
    # finder keeps it regardless.
    with pytest.raises(ValueError):
        ui_visibility.set_visibility("/settings", "admin", False)
    assert "/settings" in _hrefs(ui_visibility.finder_pages("admin"))
    # For every role the finder is nav_groups plus exactly the folded pages
    # that role may see -- same resolution, in_nav ignored.
    for role in [None, *rbac.ROLES]:
        nav = _hrefs(ui_visibility.nav_groups(role))
        finder = _hrefs(ui_visibility.finder_pages(role))
        assert [h for h in finder if h in set(nav)] == nav
        expected_extra = {
            p["path"] for p in ui_visibility.PAGES
            if not p.get("in_nav", True) and ui_visibility.customer_ready(p)
            and ui_visibility.is_visible(p, role)
        }
        assert set(finder) - set(nav) == expected_extra, role


def test_security_report_and_assurance_are_governed_registry_pages():
    from maverick_dashboard import ui_visibility

    by_path = {p["path"]: p for p in ui_visibility.PAGES}
    threats = by_path["/security/threats"]
    for path in NEWLY_GOVERNED:
        page = by_path[path]
        assert page["in_nav"] is False
        assert page["group"] == threats["group"] == "Govern"
        assert page["icon"] == threats["icon"]
        # Same floor/default as the neighbouring security consoles: the routes
        # themselves require "operate", so the registry must not promise more.
        assert page["floor"] == threats["floor"] == "operate"
        assert page["default"] == threats["default"] == "operate"
        # Longest-prefix governance: the page's own entry wins over /security.
        assert ui_visibility.page_for(path)["path"] == path


# ---------- rendered shell ----------

class _ShellLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_sidebar = 0
        self.in_quick = 0  # the "Most used" shortcuts repeat links from the groups
        self.in_finder = 0
        self.sidebar_hrefs: list[str] = []
        self.finder_hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        if tag == "aside" and values.get("id") == "sidebar":
            self.in_sidebar += 1
        if tag == "dialog" and values.get("id") == "navfinder-dialog":
            self.in_finder += 1
        if tag == "ul" and "navquick-list" in (values.get("class") or "").split():
            self.in_quick += 1
        if tag != "a" or not values.get("href"):
            return
        classes = set((values.get("class") or "").split())
        if self.in_sidebar and not self.in_quick and "navquick" not in classes:
            self.sidebar_hrefs.append(values["href"])
        if self.in_finder and "data-navfinder-target" in values:
            self.finder_hrefs.append(values["href"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "aside" and self.in_sidebar:
            self.in_sidebar -= 1
        if tag == "ul" and self.in_quick:
            self.in_quick -= 1
        if tag == "dialog" and self.in_finder:
            self.in_finder -= 1


def _client(monkeypatch, tmp_path) -> TestClient:
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import world_model
    from maverick_dashboard import app as dashboard_app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    dashboard_app._world_cache.clear()
    return TestClient(dashboard_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_rendered_finder_indexes_folded_pages_and_sidebar_does_not(monkeypatch, tmp_path):
    from maverick_dashboard import employee_companion_api, ui_visibility

    # Companion destinations also require an available configured assignment.
    # Model that gate explicitly; every other authorized registry link stays exact.
    monkeypatch.setattr(employee_companion_api, "navigation_available", lambda request, *, admin: False)
    # The local owner has no named account, which these screens' routes require.
    unavailable = {"/companion", "/companion/admin", *NAMED_ACCOUNT_SCREENS}

    client = _client(monkeypatch, tmp_path)
    response = client.get("/overview")
    assert response.status_code == 200
    markup = _ShellLinks()
    markup.feed(response.text)
    assert markup.finder_hrefs == []  # fetched on first open, not embedded
    items = client.get("/nav/finder")
    assert items.status_code == 200
    markup.feed('<dialog id="navfinder-dialog">' + items.text + "</dialog>")

    registered = set(FOLDED) | set(NEWLY_GOVERNED)
    offered = {p for p in registered if ui_visibility.customer_ready(ui_visibility.page_for(p))}
    assert offered and offered <= set(markup.finder_hrefs)
    # Folded pages held back as not ready never reach the rendered finder.
    assert (registered - offered).isdisjoint(markup.finder_hrefs)
    assert set(FOLDED).isdisjoint(markup.sidebar_hrefs)
    assert set(NEWLY_GOVERNED).isdisjoint(markup.sidebar_hrefs)
    # The sidebar stays the curated rail; the finder is the governed whole.
    assert set(markup.sidebar_hrefs) < set(markup.finder_hrefs)
    assert unavailable.isdisjoint(markup.finder_hrefs)
    assert markup.finder_hrefs == [href for href in _hrefs(ui_visibility.finder_pages(None)) if href not in unavailable]
    # The workspace line at the top of the sidebar (base.html) links to the
    # active workspace; it is not a navigation entry.
    rail = [href for href in markup.sidebar_hrefs if href != "/workspace/tenant"]
    assert rail == [href for href in _hrefs(ui_visibility.nav_groups(None)) if href not in unavailable]


def test_registered_screens_stay_out_of_the_sidebar_and_mirror_their_route_floor():
    from maverick_dashboard import ui_visibility

    for path in NAMED_ACCOUNT_SCREENS + OPEN_SCREENS:
        page = ui_visibility.page_for(path)
        assert page["path"] == path and page["in_nav"] is False
        assert ui_visibility.customer_ready(page)
        expected = ("admin", "admin") if path == "/provider-spending" else ("view", "view")
        assert (page["floor"], page["default"]) == expected, path
    assert ui_visibility.page_for("/provider-spending")["scope"] == "global"
    # Record detail pages under these screens follow their parent.
    assert ui_visibility.page_for("/project-workspaces/7")["path"] == "/project-workspaces"


def test_named_account_screens_are_not_offered_without_a_named_account(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    finder = client.get("/nav/finder").text
    for path in NAMED_ACCOUNT_SCREENS:
        assert f'href="{path}"' not in finder
        assert client.get(path).status_code == 403
    for path in OPEN_SCREENS:
        assert f'href="{path}"' in finder


def test_named_account_screens_follow_their_own_route_checks(monkeypatch, tmp_path):
    from fastapi import Request
    from maverick import config
    from maverick_dashboard import app as dashboard_app
    from maverick_dashboard import auth

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:member")
    finder = client.get("/nav/finder").text
    for path in NAMED_ACCOUNT_SCREENS:
        assert f'href="{path}"' in finder and client.get(path).status_code == 200, path
    # Employee activation also needs its switch: turned off, it is withheld.
    features = config.get_features
    monkeypatch.setattr(config, "get_features", lambda: {**features(), "employee_activation": False})
    assert 'href="/get-started/employee"' not in client.get("/nav/finder").text
    assert client.get("/get-started/employee").status_code == 403
    assert "/get-started/employee" in dashboard_app._account_pages_unavailable(
        Request({"type": "http", "headers": []}))
