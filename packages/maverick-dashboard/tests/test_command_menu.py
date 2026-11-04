"""The command menu ("Search or run a command"), keyboard shortcuts and help.

Contracts under test:
  * a command is rendered only for people who may use it, and each one leads
    to a page or confirmation that person may open (never a decision);
  * people results (``@``) follow the Users page's own permission, on the server;
  * the shortcuts dialog lists go-to keys only for pages the person may open,
    and the lists the scripts bind are exactly the ones shown;
  * help sits in the same place in both shells, one key (?) away.
"""
from __future__ import annotations

import re
from html import unescape
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
    monkeypatch.delenv("MAVERICK_DASHBOARD_INVITES", raising=False)
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


class _Shell(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.commands: dict[str, dict] = {}
        self.shortcuts: dict[str, str | None] = {}
        self.prefixes: list[str] = []
        self.ids: dict[str, dict] = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids[values["id"]] = values
        if values.get("data-navfinder-action"):
            self.commands[values["data-navfinder-action"]] = values
        if "data-shortcut" in values:
            self.shortcuts[values["data-shortcut"]] = values.get("data-shortcut-href")
        if "data-finder-prefix" in values:
            self.prefixes.append(values["data-finder-prefix"])


def _shell(client, path="/overview") -> tuple[_Shell, str]:
    response = client.get(path)
    assert response.status_code == 200, response.text
    return _Shell(response.text), response.text


@pytest.mark.parametrize("role,expected", [
    ("viewer", ["setting", "pin", "shortcuts"]),
    ("auditor", ["setting", "pin", "shortcuts"]),
    ("operator", ["new-task", "approvals", "halt", "setting", "pin", "shortcuts"]),
    ("admin", ["new-task", "approvals", "halt", "setting", "pin", "shortcuts"]),
])
def test_commands_are_offered_only_to_people_who_may_use_them(client, role, expected):
    _as(role)
    shell, _ = _shell(client)
    assert list(shell.commands) == expected
    for name, attrs in shell.commands.items():
        href = attrs["href"]
        if href.startswith("/"):
            # A command that goes somewhere goes to a page this person may open.
            assert client.get(href.split("#")[0]).status_code == 200, (role, name, href)
        assert attrs["role"] == "option" and attrs["tabindex"] == "-1", name
    # Commands are not page destinations: page lists stay exactly the registry.
    assert all("data-navfinder-target" not in attrs for attrs in shell.commands.values())


def test_invite_someone_needs_an_installation_administrator_and_invitations_on(client, monkeypatch):
    from pathlib import Path

    from maverick_dashboard import navigation_api, rbac

    # Turning invitations on for real also turns on account sign-in, which
    # this fixture's injected account cannot use; model the switch directly.
    monkeypatch.setattr(navigation_api, "_invites_on", lambda: True)
    rbac.set_role("user:another-admin", "admin")  # so this person can step down
    _as("admin")
    invite = _shell(client)[0].commands["invite"]
    assert invite["href"] == "/users#invite-email"
    users = (Path(navigation_api.__file__).parent / "templates" / "users.html").read_text(encoding="utf-8")
    assert '<h2 id="invite-email">' in users  # the invite form's heading on Users
    _as("operator")
    assert "invite" not in _shell(client)[0].commands
    monkeypatch.setattr(navigation_api, "_invites_on", lambda: False)
    _as("admin")
    assert "invite" not in _shell(client)[0].commands


def test_approve_or_reject_lists_only_what_the_approvals_page_would(client):
    _as("operator")
    command = _shell(client)[0].commands["approvals"]
    # The choices come from the Approvals page's own permission-checked list;
    # choosing one opens that item's card there. Nothing here decides.
    assert command["data-navfinder-list"] == "/api/v1/approvals"
    assert client.get("/api/v1/approvals").status_code == 200
    _as("viewer")
    assert client.get("/api/v1/approvals").status_code == 403


def test_the_emergency_stop_command_presses_the_stop_control_and_needs_its_permission(client):
    _as("operator")
    shell, _ = _shell(client)
    assert shell.commands["halt"]["href"] == "#halt-pill"
    assert shell.ids["halt-pill"]["data-can-halt"] == "true"
    _as("viewer")
    shell, _ = _shell(client)
    assert "halt" not in shell.commands
    assert shell.ids["halt-pill"]["data-can-halt"] == "false"


def test_pin_this_page_is_offered_only_on_a_page_that_can_be_pinned(client):
    from maverick_dashboard import app

    _as("operator")
    assert _shell(client)[0].commands["pin"]["data-label-pin"] == "Pin this page"
    goal = app._world().create_goal("A task", "", owner="user:customer")
    assert "pin" not in _shell(client, f"/goals/{goal}/plan")[0].commands


def test_no_account_gets_commands_but_no_pinning(client, monkeypatch):
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "caller_principal", lambda _request: None)
    commands = list(_shell(client)[0].commands)
    assert "pin" not in commands and "invite" not in commands
    assert commands[-1] == "shortcuts"


@pytest.mark.parametrize("path", ["/overview", "/chat"])
def test_both_shells_title_the_menu_and_place_help_right_below_search(client, path):
    _as("operator")
    shell, html = _shell(client, path)
    title = re.search(r'<h2 id="navfinder-title">(.*?)</h2>', html, re.DOTALL).group(1)
    assert " ".join(unescape(re.sub(r"<[^>]+>", "", title)).split()) == "Search or run a command"
    search, help_entry = html.index('id="navfinder-open"'), html.index('id="shortcuts-open"')
    assert search < help_entry < html.index('class="navgrp"')
    # Nothing sits between Search and Help: the help entry is the next control.
    between = html[search:help_entry]
    assert between.count("<button") == 1 and "<a " not in between
    assert shell.ids["shortcuts-open"]["aria-controls"] == "shortcuts-dialog"
    dialog = html[html.index('id="shortcuts-dialog"'):]
    assert 'href="/help"' in dialog[:dialog.index("</dialog>")]


@pytest.mark.parametrize("role,expected", [
    ("viewer", {"g t": "/goals", "g r": "/deliverables"}),
    ("auditor", {"g t": "/goals", "g r": "/deliverables"}),
    ("operator", {"g t": "/goals", "g a": "/approvals", "g r": "/deliverables"}),
    ("admin", {"g t": "/goals", "g a": "/approvals", "g r": "/deliverables", "g s": "/settings"}),
])
def test_go_to_keys_are_listed_only_for_pages_the_person_may_open(client, role, expected):
    _as(role)
    shell, _ = _shell(client)
    assert shell.shortcuts == {"mod+k": None, "/": None, "?": None, "g h": "/", **expected}
    for keys, href in shell.shortcuts.items():
        if href:
            assert client.get(href).status_code == 200, (role, keys, href)


@pytest.mark.parametrize("role,people", [("viewer", False), ("operator", False), ("admin", True)])
def test_people_search_follows_the_users_page_on_the_server(client, role, people):
    from maverick_dashboard import rbac

    rbac.set_role("user:alice-anders", "operator")
    _as(role)
    shell, _ = _shell(client)
    listed = shell.ids["navfinder-results"].get("data-navfinder-people")
    assert (listed == "/nav/finder/people") is people
    assert ("@" in shell.prefixes) is people
    response = client.get("/nav/finder/people", params={"q": "alice"})
    if not people:
        assert response.status_code == 403
        return
    assert response.status_code == 200
    rows = response.json()["people"]
    assert [row["href"] for row in rows] == ["/users"]
    assert "alice" in rows[0]["label"].lower() and rows[0]["role"] == "Operator"
    assert client.get("/nav/finder/people", params={"q": "nobody-matches"}).json()["people"] == []


def test_finder_prefixes_listed_match_what_applies(client, monkeypatch):
    from maverick_dashboard import record_search_api

    _as("operator")
    assert _shell(client)[0].prefixes == [">", "/", "#", ":"]
    # Without record search there is no "#" to list.
    monkeypatch.setattr(record_search_api, "context_for", lambda request: "")
    assert _shell(client)[0].prefixes == [">", "/", ":"]


def _option_text(items: str, href: str) -> str:
    option = re.search(r'<a [^>]*href="' + re.escape(href) + r'".*?</a>', items, re.DOTALL).group(0)
    context = option[option.index('class="navfinder__group"'):]
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", context.split(">", 1)[1])).split())


def test_page_results_show_where_each_page_lives_and_its_go_to_keys(client):
    from maverick_dashboard import navigation_api

    _as("operator")
    items = client.get("/nav/finder").text
    assert _option_text(items, "/goals") == "Work › Tasks G T"
    assert _option_text(items, "/overview") == "Insights › Overview"
    # The keys shown are the ones the shortcuts dialog lists and binds.
    shown = dict(re.findall(r'data-shortcut="g (\w)" data-shortcut-href="([^"]+)"', client.get("/overview").text))
    assert shown == {key: href for key, href, _ in navigation_api.GO_TO_KEYS if href != "/settings"}


@pytest.mark.parametrize("words", ["stop all agents", "stop every agent", "stop everything", "kill switch"])
def test_ways_of_asking_to_stop_everything_find_the_emergency_stop(client, words):
    _as("operator")
    shell, _ = _shell(client)
    synonyms = shell.commands["halt"]["data-synonyms"].split("|")
    assert words in synonyms
