"""The /shoring page: hero, Shoring P&L, book of work, add-a-function form,
and the exception desk. Renders one h1, is a11y-clean, and is in the nav."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick_dashboard import api as api_mod

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_SHORING", raising=False)
    config.reset_config_cache()
    api_mod._world_cache.clear()
    yield
    config.reset_config_cache()
    api_mod._world_cache.clear()


def _add_function(**over):
    body = {
        "key": "ap", "name": "Accounts Payable", "department": "finance_ap",
        "scope": "Invoice to pay", "status": "running", "owner": "cfo",
        "slas": [{"name": "Throughput", "metric": "throughput_per_day", "target": 1.0}],
    }
    body.update(over)
    assert client.post("/api/v1/shoring/function", json=body).status_code == 200


def test_unavailable_book_is_an_explicit_recoverable_page_error(monkeypatch):
    from maverick import shoring

    def unavailable(*args, **kwargs):
        raise RuntimeError("synthetic private storage detail")

    monkeypatch.setattr(shoring, "book_status", unavailable)
    response = client.get("/shoring")
    assert response.status_code == 503
    assert "Restore access" in response.text
    assert "private storage detail" not in response.text


def test_page_renders_pieces():
    resp = client.get("/shoring")
    assert resp.status_code == 200
    html = resp.text
    assert html.count("<h1") == 1                       # exactly one page title
    assert "Autonomous shoring" in html                 # hero title
    assert "Savings estimate" in html                    # the P&L summary
    assert "Book of Work" in html
    assert 'id="sh-form"' in html                       # add-a-function form
    assert "Waiting for a person" in html
    assert "/approvals" in html                         # exception desk links out
    # No slug, free-text department or free-text owner to type.
    assert 'id="sh-department"' in html and '<select class="select" id="sh-department"' in html
    assert '<select class="select" id="sh-owner"' in html
    assert "Key (slug" not in html and "operating tag" not in html
    assert "Add a target" in html and "window.confirm" not in html and "window.alert" not in html
    from test_support.plain_language import developer_terms

    assert developer_terms(html) == []


def test_page_shows_book_and_sla_indicator():
    from maverick import world_model
    w = world_model.WorldModel(world_model.DEFAULT_DB)
    gid = w.create_goal("g", "d", domain="finance_ap")
    ep = w.start_episode(gid)
    w.end_episode(ep, "ran", "success", cost_dollars=1.0)
    w.set_goal_status(gid, "done")
    _add_function()
    html = client.get("/shoring").text
    assert "Accounts Payable" in html
    assert "Finance ap" in html
    # The lifecycle badge and an SLA verdict word are present.
    assert "Running" in html
    assert "Missed" in html   # 1 delivered over 90d is far under 1/day
    assert 'data-edit="ap"' in html and 'data-remove="ap"' in html
    from test_support.plain_language import developer_terms

    assert developer_terms(html) == []


def test_page_exception_desk_lists_department_approvals():
    from maverick import world_model
    from maverick.logging_config import reset_goal_context, set_goal_context
    w = world_model.WorldModel(world_model.DEFAULT_DB)
    goal = w.create_goal("Invoice", domain="finance_ap")
    tokens = set_goal_context(goal_id=goal)
    try:
        w.create_approval("wire.transfer", risk="high", scope="payment")
    finally:
        reset_goal_context(tokens)
    _add_function()
    html = client.get("/shoring").text
    assert "waiting" in html
    assert "Wire transfer" in html
    assert f"/goals/{goal}/trajectory" in html


def test_page_exception_desk_shows_written_actions_as_written():
    # Written actions lost their full stops, hyphens and capitals on the desk
    # ("$48,210 00", "inv 20419 from northwind supply"); only an action name
    # such as ``wire.transfer`` is made readable, as on /approvals.
    from maverick import world_model
    from maverick.logging_config import reset_goal_context, set_goal_context
    w = world_model.WorldModel(world_model.DEFAULT_DB)
    goal = w.create_goal("Payment run", domain="finance_ap")
    tokens = set_goal_context(goal_id=goal)
    try:
        w.create_approval("Release payment run of $48,210.00 to 37 vendors", risk="high", scope="payment")
        w.create_approval("Pay invoice INV-20419 from Northwind Supply ($6,150.00)", risk="medium", scope="invoice")
        w.create_approval("Refund <b>R&D</b> deposit", risk="low", scope="refund")
    finally:
        reset_goal_context(tokens)
    _add_function()
    html = client.get("/shoring").text
    assert "<td>Release payment run of $48,210.00 to 37 vendors</td>" in html
    assert "<td>Pay invoice INV-20419 from Northwind Supply ($6,150.00)</td>" in html
    # Escaped, not rewritten.
    assert "<td>Refund &lt;b&gt;R&amp;D&lt;/b&gt; deposit</td>" in html
    assert "<b>R&D</b>" not in html


def test_page_empty_state():
    html = client.get("/shoring").text
    assert "No functions in the book of work yet" in html


def test_page_is_accessible():
    from maverick import a11y_audit
    _add_function()
    html = client.get("/shoring").text
    findings = a11y_audit.audit_html(html)
    assert not findings, [f"{f.rule}: {f.detail}" for f in findings]


def test_page_in_nav_registry_after_savings():
    from maverick_dashboard import ui_visibility
    paths = [p["path"] for p in ui_visibility.PAGES]
    assert "/shoring" in paths
    entry = next(p for p in ui_visibility.PAGES if p["path"] == "/shoring")
    assert entry["group"] == "Observe"
    assert entry["floor"] == "view"
    assert entry["label"] == "Autonomous shoring"
    # Ordered immediately after /savings (nav order = registry order).
    assert paths.index("/shoring") == paths.index("/savings") + 1


def test_page_disabled_is_404(monkeypatch):
    monkeypatch.setenv("MAVERICK_SHORING", "0")
    response = client.get("/shoring")
    assert response.status_code == 404
    assert "This page is turned off" in response.text
    assert 'id="sh-turn-on"' in response.text          # open-mode viewer is an admin


def test_turn_on_writes_the_setting_for_admins(tmp_path):
    from maverick import config, shoring

    (tmp_path / "config.toml").write_text("[shoring]\nenable = false\n", encoding="utf-8")
    config.reset_config_cache()
    assert not shoring.enabled()
    assert client.get("/shoring").status_code == 404
    assert client.post("/api/v1/shoring/turn-on").status_code == 200
    config.reset_config_cache()
    assert shoring.enabled()
    assert client.get("/shoring").status_code == 200


def test_turn_on_reports_a_pinned_setting(monkeypatch):
    monkeypatch.setenv("MAVERICK_SHORING", "0")
    assert client.post("/api/v1/shoring/turn-on").status_code == 409


def test_turn_on_needs_an_administrator(monkeypatch):
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "has_global_permission", lambda request, permission: permission != "admin")
    from fastapi import HTTPException

    def deny(request, permission):
        if permission == "admin":
            raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(auth, "require_global_permission", deny)
    assert client.post("/api/v1/shoring/turn-on").status_code == 403


def test_turn_on_is_recorded_with_who_did_it(tmp_path, monkeypatch):
    import maverick.audit as audit
    from maverick import config
    from maverick.audit import EventKind

    rows: list[dict] = []
    monkeypatch.setattr(audit, "audit_event",
                        lambda kind, **payload: rows.append({"kind": kind, **payload}) or True)
    (tmp_path / "config.toml").write_text("[shoring]\nenable = false\n", encoding="utf-8")
    config.reset_config_cache()
    assert client.post("/api/v1/shoring/turn-on").status_code == 200
    (row,) = rows
    assert row["kind"] == EventKind.SETTING_CHANGED
    assert (row["section"], row["key"], row["old"], row["new"]) == ("shoring", "enable", False, True)
    assert row["actor"]
