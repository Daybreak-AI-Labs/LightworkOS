"""Pinned and recent pages in the sidebar, and the role presets people start with.

Contracts under test:
  * pins are the one ``favorites`` list (Today and Your preferences show it);
    someone who never chose pins starts from their role's preset;
  * pins and recent pages only ever offer pages the person may open now;
  * a page view is remembered for the "Recent pages" list without touching the
    preference revision, and only for pages the person may open;
  * nobody without an account (or with personal preferences off) gets either.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import api, app, auth

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:customer")
    config.reset_config_cache()
    api._world_cache.clear()
    yield TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()
    api._world_cache.clear()


def _as(role: str) -> None:
    from maverick_dashboard import rbac

    rbac.set_role("user:customer", role)


class _Sidebar(HTMLParser):
    """The hrefs of the sidebar's Pinned pages, Most used and Recent pages lists."""

    def __init__(self, html: str) -> None:
        super().__init__()
        self.lists: dict[str, list[str]] = {"pins": [], "quick": [], "recent": []}
        self.current: list[str | None] = []
        self.attrs: dict[str, dict] = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.attrs[values["id"]] = values
        if tag == "ul":
            name = values.get("data-nav-list") or ("quick" if values.get("aria-label") == "Most used" else None)
            self.current.append(name)
        if tag == "a" and self.current and self.current[-1]:
            self.lists[self.current[-1]].append(values["href"])

    def handle_endtag(self, tag):
        if tag == "ul" and self.current:
            self.current.pop()


def _sidebar(client, path="/overview") -> _Sidebar:
    response = client.get(path)
    assert response.status_code == 200, response.text
    return _Sidebar(response.text)


def _context(client) -> str:
    page = client.get("/overview").text
    return re.search(r'name="lightwork-preference-context" content="([0-9a-f]+)"', page).group(1)


def _pin(client, op, href, **extra):
    return client.post("/api/v1/navigation/pins", json={"op": op, "href": href, "context": _context(client), **extra})


# ---------- presets (no HTTP) ----------

def test_presets_follow_each_role_and_name_only_registered_pages():
    from maverick_dashboard import ui_visibility

    everything = {page["path"] for page in ui_visibility.PAGES}
    assert ui_visibility.pin_preset("operator", everything) == ["/goals", "/approvals", "/deliverables"]
    assert ui_visibility.pin_preset("approver", everything)[0] == "/approvals"
    assert ui_visibility.pin_preset("privacy-officer", everything) == ["/privacy/rights-orchestration", "/privacy"]
    assert ui_visibility.pin_preset("admin", everything) == ["/settings", "/users", "/audit"]
    for paths in ui_visibility.PIN_PRESETS.values():
        for path in paths:
            page = ui_visibility.page_for(path)
            assert page is not None and page["path"] == path and ui_visibility.customer_ready(page), path


def test_a_preset_never_offers_a_page_the_person_cannot_open():
    from maverick_dashboard import ui_visibility

    # An employee who cannot decide approvals starts without Approvals.
    assert ui_visibility.pin_preset("operator", {"/goals", "/deliverables"}) == ["/goals", "/deliverables"]
    assert ui_visibility.pin_preset("admin", {"/users"}) == ["/users"]
    assert ui_visibility.pin_preset("", {"/goals"}) == []
    assert ui_visibility.pin_preset(None, {"/goals"}) == []


def test_custom_roles_start_from_the_preset_their_name_or_powers_suggest(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick_dashboard import rbac, ui_visibility

    for name, atoms in (("privacy-lead", ["audit", "operate", "view"]), ("approvals-desk", ["operate", "view"]),
                        ("operations", ["operate", "view"]), ("reviewer", ["audit", "view"]),
                        ("reader", ["view"]), ("superuser", ["admin", "audit", "operate", "view"])):
        rbac.set_custom_role(name, atoms, "", actor="test")
    everything = {page["path"] for page in ui_visibility.PAGES}
    assert ui_visibility.pin_preset("privacy-lead", everything) == list(ui_visibility.PIN_PRESETS["privacy-officer"])
    assert ui_visibility.pin_preset("approvals-desk", everything) == list(ui_visibility.PIN_PRESETS["approver"])
    assert ui_visibility.pin_preset("operations", everything) == list(ui_visibility.PIN_PRESETS["operator"])
    assert ui_visibility.pin_preset("reviewer", everything) == list(ui_visibility.PIN_PRESETS["auditor"])
    assert ui_visibility.pin_preset("reader", everything) == list(ui_visibility.PIN_PRESETS["viewer"])
    assert ui_visibility.pin_preset("superuser", everything) == list(ui_visibility.PIN_PRESETS["admin"])
    # A name that suggests a job the role cannot do falls back to its powers.
    rbac.set_custom_role("privacy-reader", ["view"], "", actor="test")
    viewer_pages = {"/deliverables", "/overview"}
    assert ui_visibility.pin_preset("privacy-reader", viewer_pages) == ["/deliverables", "/overview"]


# ---------- the rendered sidebar ----------

@pytest.mark.parametrize("role,expected", [
    ("operator", ["/goals", "/approvals", "/deliverables"]),
    ("admin", ["/settings", "/users", "/audit"]),
    ("auditor", ["/audit", "/audit/receipts", "/assessments"]),
    ("viewer", ["/deliverables", "/overview"]),
])
def test_people_without_pins_start_from_their_role_preset_in_both_shells(client, role, expected):
    _as(role)
    for path in ("/overview", "/chat") if role in {"operator", "admin"} else ("/overview",):
        sidebar = _sidebar(client, path)
        assert sidebar.lists["pins"] == expected, path
        # Each page appears once among the quick lists: Most used leaves out pins.
        assert not set(sidebar.lists["pins"]) & set(sidebar.lists["quick"])


def test_pins_can_be_added_moved_and_removed_and_are_the_today_list(client):
    _as("operator")
    added = _pin(client, "add", "/overview")
    assert added.status_code == 200, added.text
    # The first change saves the preset as the person's own list.
    assert [pin["href"] for pin in added.json()["pins"]] == ["/goals", "/approvals", "/deliverables", "/overview"]
    assert added.json()["revision"]
    assert _pin(client, "up", "/overview").status_code == 200
    assert _pin(client, "remove", "/approvals").status_code == 200
    assert _sidebar(client).lists["pins"] == ["/goals", "/overview", "/deliverables"]
    assert _pin(client, "down", "/goals").json()["pins"][0]["href"] == "/overview"
    # Today and Your preferences read the same list.
    today = client.get("/today").text
    pinned = re.search(r'<nav\b[^>]*\baria-label="Pinned pages"[^>]*>(.*?)</nav>', today, re.DOTALL).group(1)
    assert re.findall(r'href="([^"]+)"', pinned) == ["/overview", "/goals", "/deliverables"]
    assert client.get("/api/v1/preferences").json()["values"]["favorites"] == ["/overview", "/goals", "/deliverables"]


def test_removing_every_pin_is_kept_and_does_not_bring_the_preset_back(client):
    _as("viewer")
    for href in ("/deliverables", "/overview"):
        assert _pin(client, "remove", href).status_code == 200
    sidebar = _sidebar(client)
    assert sidebar.lists["pins"] == []
    assert sidebar.attrs["navpins-empty"].get("hidden") is None


def test_only_pages_the_person_may_open_can_be_pinned(client):
    _as("viewer")
    for href in ("/settings", "/approvals", "/not-a-page", "https://evil.example/"):
        response = _pin(client, "add", href)
        assert response.status_code == 403, href
    assert _pin(client, "jump", "/overview").status_code == 422
    assert _sidebar(client).lists["pins"] == ["/deliverables", "/overview"]


def test_pin_changes_need_the_same_account_and_workspace_and_page_origin(client):
    _as("operator")
    stale = client.post("/api/v1/navigation/pins", json={"op": "add", "href": "/overview", "context": "0" * 64})
    assert stale.status_code == 409
    other_site = client.post("/api/v1/navigation/pins", headers={"Origin": "https://evil.example"},
                             json={"op": "add", "href": "/overview", "context": _context(client)})
    assert other_site.status_code == 403


def test_a_pin_the_person_can_no_longer_open_disappears(client):
    from maverick_dashboard import ui_visibility

    _as("operator")
    assert _pin(client, "add", "/overview").status_code == 200
    ui_visibility.set_visibility("/overview", "operator", False)
    assert "/overview" not in _sidebar(client, "/goals").lists["pins"]
    assert "/overview" not in client.get("/api/v1/preferences").json()["values"]["favorites"]


def test_recent_pages_show_the_last_five_distinct_pages_the_person_may_open(client):
    from maverick import experience_preferences
    from maverick_dashboard import ui_visibility

    _as("operator")
    context = _context(client)
    for path in ("/me", "/overview", "/workforce", "/spend", "/savings", "/run-tree", "/overview"):
        response = client.post("/api/v1/navigation/recent", json={"path": path, "context": context})
        assert response.status_code == 200 and response.json()["recorded"] is True, path
    sidebar = _sidebar(client, "/goals")
    assert sidebar.lists["recent"] == ["/overview", "/run-tree", "/savings", "/spend", "/workforce"]
    # Never the page being shown, and never a page already one click away above.
    assert _sidebar(client, "/overview").lists["recent"] == ["/run-tree", "/savings", "/spend", "/workforce", "/me"]
    assert _pin(client, "add", "/spend").status_code == 200
    assert "/spend" not in _sidebar(client, "/goals").lists["recent"]
    # A page the person can no longer open is never offered.
    ui_visibility.set_visibility("/run-tree", "operator", False)
    assert "/run-tree" not in _sidebar(client, "/goals").lists["recent"]
    assert experience_preferences.recent_pages("user:customer")[0] == "/overview"


@pytest.mark.parametrize("path", ["/settings", "/goals/12", "/not-a-page", "//evil.example", "/overview?x=1"])
def test_only_pages_the_person_may_open_are_remembered(client, path):
    from maverick import experience_preferences

    _as("operator")
    response = client.post("/api/v1/navigation/recent", json={"path": path, "context": _context(client)})
    assert response.status_code == 200 and response.json()["recorded"] is False
    assert experience_preferences.recent_pages("user:customer") == []


def test_remembering_a_page_keeps_the_preference_revision(client):
    _as("operator")
    before = client.get("/api/v1/preferences").json()["revision"]
    client.post("/api/v1/navigation/recent", json={"path": "/overview", "context": _context(client)})
    assert client.get("/api/v1/preferences").json()["revision"] == before


def test_a_stale_page_records_nothing(client):
    from maverick import experience_preferences

    _as("operator")
    response = client.post("/api/v1/navigation/recent", json={"path": "/overview", "context": "0" * 64})
    assert response.status_code == 200 and response.json()["recorded"] is False
    assert experience_preferences.recent_pages("user:customer") == []


def test_the_shell_offers_pinning_only_on_pages_the_person_may_open(client):
    _as("operator")
    page = _sidebar(client, "/overview")
    assert page.attrs["navpins"]["data-nav-current"] == "/overview"
    toggle = page.attrs["page-pin-toggle"]
    assert toggle["aria-pressed"] == "false"
    _pin(client, "add", "/overview")
    assert _sidebar(client, "/overview").attrs["page-pin-toggle"]["aria-pressed"] == "true"
    # A record page under a destination is not itself a destination.
    from maverick_dashboard import app

    goal = app._world().create_goal("Pinned task", "", owner="user:customer")
    detail = _sidebar(client, f"/goals/{goal}/plan")
    assert "page-pin-toggle" not in detail.attrs
    assert detail.attrs["navpins"].get("data-nav-current", "") == ""


def test_no_account_means_no_pinned_or_recent_pages(client, monkeypatch):
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "caller_principal", lambda _request: None)
    page = client.get("/overview").text
    assert 'id="navpins"' not in page and 'data-nav-list="recent"' not in page
    assert 'id="page-pin-toggle"' not in page
    assert 'aria-label="Most used"' in page  # the shared quick list stays


def test_personal_preferences_off_means_no_pinned_or_recent_pages(client, monkeypatch):
    from maverick import experience_preferences

    _as("operator")
    monkeypatch.setattr(experience_preferences, "enabled", lambda: False)
    page = client.get("/overview").text
    assert 'id="navpins"' not in page and 'id="page-pin-toggle"' not in page
    assert client.post("/api/v1/navigation/recent", json={"path": "/overview", "context": "0" * 64}).json() == {"recorded": False}
