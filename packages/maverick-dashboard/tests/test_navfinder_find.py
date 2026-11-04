"""Ctrl+K finds people, agents and specialists, waiting approvals and help.

Each kind follows its own page's permission on the server, for each request:
no shared index, nothing cached across people.
"""
from __future__ import annotations

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


def _find(client, query):
    response = client.get("/nav/finder/find", params={"q": query})
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "private, no-store"
    return response.json()["results"]


@pytest.mark.parametrize(("role", "listed"), [("viewer", False), ("operator", False), ("admin", True)])
def test_people_are_found_by_name_only_for_those_who_may_see_the_roster(client, role, listed):
    from maverick_dashboard import rbac

    rbac.set_role("user:dana-admin", "operator")
    _as(role)
    people = [row for row in _find(client, "dana") if row["kind"] == "person"]
    assert bool(people) is listed
    if listed:
        assert people[0]["href"].startswith("/users?q=") and people[0]["href"].endswith("#people")
        assert people[0]["context"] == "Operator"


def test_specialists_are_found_by_name_and_word(client):
    _as("admin")
    rows = _find(client, "finance specialist")
    finance = [row for row in rows if row["href"] == "/agents?name=finance"]
    assert finance and finance[0]["kind"] == "specialist"
    assert any(label.casefold() == "finance specialist" for label in finance[0]["labels"])


def test_specialists_stay_within_the_callers_departments(client, monkeypatch):
    from maverick_dashboard import auth

    _as("operator")
    monkeypatch.setattr(auth, "caller_suites", lambda request: frozenset({"privacy"}))
    # Trade Finance belongs to the banking department; general packs stay listed.
    rows = [row for row in _find(client, "trade finance") if row["kind"] in {"agent", "specialist"}]
    assert all(row["href"] != "/agents?name=bank_trade_finance" for row in rows)
    monkeypatch.setattr(auth, "caller_suites", lambda request: None)
    rows = [row for row in _find(client, "trade finance") if row["kind"] in {"agent", "specialist"}]
    assert rows[0]["href"] == "/agents?name=bank_trade_finance" and rows[0]["title"] == "Trade Finance"


def test_waiting_approvals_follow_the_approvals_permission(client, monkeypatch):
    from maverick_dashboard import api, content_access

    world = api._world()
    approval = world.create_approval("shell", risk="high", detail="rm -rf build", requested_by="user:customer")
    _as("operator")
    rows = [row for row in _find(client, "shell") if row["kind"] == "approval"]
    # Titled as the Approvals page names it; the action name is still searched.
    assert rows == [{"kind": "approval", "title": "Run a command", "labels": ["Run a command"], "context": "High risk",
                     "href": f"/approvals#approval-{approval}"}]
    # The request's own detail (it may carry another person's task) is never searched.
    assert not [row for row in _find(client, "build") if row["kind"] == "approval"]
    monkeypatch.setattr(content_access, "can_read_approval", lambda request, item, world=None: False)
    assert not [row for row in _find(client, "shell") if row["kind"] == "approval"]
    monkeypatch.undo()


def test_waiting_approvals_are_titled_as_written(client):
    from maverick_dashboard import api

    api._world().create_approval("Pay invoice INV-20419 from Northwind Supply ($6,150.00)",
                                 risk="medium", requested_by="user:customer")
    _as("operator")
    (row,) = [row for row in _find(client, "northwind") if row["kind"] == "approval"]
    assert row["title"] == "Pay invoice INV-20419 from Northwind Supply ($6,150.00)"
    assert row["labels"] == [row["title"]]


def test_viewers_do_not_find_approvals(client):
    from maverick_dashboard import api

    api._world().create_approval("shell", risk="high", requested_by="user:customer")
    _as("viewer")
    assert not [row for row in _find(client, "shell") if row["kind"] == "approval"]


def test_help_topics_are_found_by_their_steps(client):
    _as("viewer")
    rows = [row for row in _find(client, "invite") if row["kind"] == "help"]
    assert rows[0] == {"kind": "help", "title": "Invite a colleague", "labels": ["Invite a colleague"],
                       "context": "Administrator", "href": "/help#how-invite"}


def test_a_question_finds_its_help_topic(client):
    _as("viewer")
    rows = [row for row in _find(client, "How do I invite someone?") if row["kind"] == "help"]
    assert rows and rows[0]["href"] == "/help#how-invite"


def test_one_letter_finds_nothing_and_results_are_never_cached(client):
    from maverick_dashboard import rbac

    rbac.set_role("user:dana-admin", "operator")
    rbac.set_role("user:another-admin", "admin")  # so the caller can be made a viewer below
    _as("admin")
    assert _find(client, "d") == []
    assert any(row["kind"] == "person" for row in _find(client, "dana"))
    _as("viewer")  # the same query right after, by a person who may not see the roster
    assert not any(row["kind"] == "person" for row in _find(client, "dana"))


def test_a_failing_source_hides_only_its_rows(client, monkeypatch):
    from maverick.domain import available_domains  # noqa: F401 -- imported before patching

    _as("admin")

    def broken():
        raise RuntimeError("catalog unreadable")
    monkeypatch.setattr("maverick.domain.available_domains", broken)
    rows = _find(client, "invite")
    assert [row["kind"] for row in rows] == ["help"]


def test_agents_are_found_by_name_not_by_a_word_in_their_description(client):
    _as("admin")
    rows = [row for row in _find(client, "invite") if row["kind"] in {"agent", "specialist"}]
    assert all("invite" in " ".join(row["labels"]).casefold() for row in rows)


def test_agents_come_from_the_pack_catalogue_without_the_editor_roster(client, monkeypatch):
    """The finder reads the cached pack catalogue, not the editor roster that
    recomputes every pack's readiness on each call; departments still apply."""
    import maverick.domain_edit as domain_edit

    def roster():
        raise AssertionError("the finder must not rebuild the editor roster per search")
    monkeypatch.setattr(domain_edit, "list_agents", roster)
    _as("admin")
    rows = [row for row in _find(client, "finance specialist") if row["kind"] in {"agent", "specialist"}]
    assert rows and rows[0]["href"] == "/agents?name=finance"
