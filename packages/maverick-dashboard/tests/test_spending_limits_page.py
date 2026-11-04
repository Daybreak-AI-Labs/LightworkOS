"""Admin > Spending limits: workspace, everyone and per-person limits."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

_ORIGIN = {"origin": "http://127.0.0.1"}


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers=_ORIGIN)


def test_page_starts_with_no_limits_and_plain_controls(client):
    r = client.get("/spending-limits")
    assert r.status_code == 200
    text = r.text
    assert "By default there is no limit" in text
    for action in ("/spending-limits/workspace", "/spending-limits/default"):
        assert f'action="{action}"' in text
    assert "per task" in text and "per day" in text and "per month" in text
    # No developer language in the page's own content (the shared menu aside).
    body = text[text.index("By default there is no limit"):text.index("reset at midnight UTC")]
    for word in ("principal", "tenant", "JSON", "config.toml", "maverick "):
        assert word not in body


def test_workspace_admin_only_sees_workspace_roster(client, monkeypatch):
    from maverick import paths
    from maverick.quotas import UsageLedger
    from maverick_dashboard import auth, rbac

    monkeypatch.setattr(auth, "has_global_permission", lambda request, permission: False)
    monkeypatch.setattr(paths, "current_tenant_id_strict", lambda: "workspace-a")
    monkeypatch.setattr(rbac, "list_users", lambda: {"user:global-secret": "admin"})  # pragma: allowlist secret
    monkeypatch.setattr(rbac, "list_tenant_roles", lambda tenant: {"user:workspace-member": "viewer"})
    monkeypatch.setattr(UsageLedger, "_load", lambda self: {})
    page = client.get("/spending-limits")
    assert page.status_code == 200
    assert "user:workspace-member" in page.text
    assert "user:global-secret" not in page.text


def test_workspace_spending_roster_failure_does_not_fall_back_to_global(client, monkeypatch):
    from maverick import paths
    from maverick_dashboard import auth, rbac

    monkeypatch.setattr(auth, "has_global_permission", lambda request, permission: False)
    monkeypatch.setattr(paths, "current_tenant_id_strict", lambda: "workspace-a")
    def unavailable(tenant):
        raise OSError("roster unavailable")
    monkeypatch.setattr(rbac, "list_tenant_roles", unavailable)
    monkeypatch.setattr(rbac, "list_users", lambda: pytest.fail("global roster must not be read"))
    assert client.get("/spending-limits").status_code == 503


def test_admin_sets_and_clears_every_kind_of_limit(client):
    from maverick import spending_limits
    from maverick.quotas import UsageLedger
    UsageLedger().record("user:alice", 3.25, 0, 0)

    r = client.post("/spending-limits/workspace",
                    data={"choice": "limit", "amount": "500", "period": "month"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/spending-limits?saved=workspace"
    r = client.post("/spending-limits/default",
                    data={"choice": "limit", "amount": "40", "period": "day"},
                    follow_redirects=False)
    assert r.headers["location"] == "/spending-limits?saved=default"
    r = client.post("/spending-limits/person",
                    data={"principal": "user:alice", "amount": "12.5", "period": "task"},
                    follow_redirects=False)
    assert r.headers["location"] == "/spending-limits?saved=person"
    assert spending_limits.load()["workspace"] == {"amount": 500.0, "period": "month"}
    assert spending_limits.load()["default"] == {"amount": 40.0, "period": "day"}
    assert spending_limits.load()["users"] == {"user:alice": {"amount": 12.5, "period": "task"}}

    page = client.get("/spending-limits?saved=person").text
    assert "Personal limit saved." in page
    assert "$12.50 per task" in page and "$3.25" in page
    assert "Remove personal limit" in page

    client.post("/spending-limits/person", data={"principal": "user:alice", "action": "remove"})
    client.post("/spending-limits/workspace", data={"choice": "none"})
    client.post("/spending-limits/default", data={"choice": "none"})
    assert spending_limits.load() | {"updated_by": "", "updated_at": 0} == {
        "workspace": None, "default": None, "users": {}, "updated_by": "", "updated_at": 0}


def test_bad_input_shows_a_plain_message_never_echoed_text(client):
    r = client.post("/spending-limits/workspace",
                    data={"choice": "limit", "amount": "-4", "period": "month"},
                    follow_redirects=False)
    assert r.headers["location"] == "/spending-limits?error=amount"
    page = client.get("/spending-limits?error=amount").text
    assert "Enter the limit as an amount in dollars, more than $0." in page
    # Arbitrary text in the address is never shown on the page.
    assert "Injected words" not in client.get("/spending-limits?error=Injected+words").text


def test_changes_require_same_origin(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    c = TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"origin": "http://evil.example"})
    r = c.post("/spending-limits/workspace",
               data={"choice": "limit", "amount": "5", "period": "day"},
               follow_redirects=False)
    assert r.status_code == 403
    from maverick import spending_limits
    assert spending_limits.load()["workspace"] is None


def test_spending_limits_is_in_the_admin_menu():
    from maverick_dashboard import ui_visibility
    entry = next(p for p in ui_visibility.PAGES if p["path"] == "/spending-limits")
    assert entry["group"] == "Admin" and entry["floor"] == "admin"


def test_page_says_when_spending_was_updated_and_when_alerts_arrive(client):
    from maverick import spending_limits
    from maverick.quotas import UsageLedger
    page = client.get("/spending-limits").text
    assert "No spending recorded yet." in page
    assert "alert in Lightwork at 50%, 75% and 100% of each daily or monthly limit" in page
    assert 'href="/settings/all?id=spending_limits.alert_at"' in page
    UsageLedger().record("user:alice", 1.0, 0, 0)
    stamp = spending_limits.spend_recorded_at()
    page = client.get("/spending-limits").text
    # The label carries the ledger's own time, which the page script shows as "x minutes ago".
    assert "Spending updated <time" in page and f'data-mv-time="{stamp:.3f}"' in page


def test_spend_page_freshness_comes_from_the_newest_cost(client):
    page = client.get("/spend").text
    assert "No spending recorded yet." in page
    from maverick import world_model
    w = world_model.open_world()
    gid = w.create_goal("Quarterly summary")
    episode = w.start_episode(gid)
    w.end_episode(episode, "Done", "success", cost_dollars=0.42)
    newest = w.list_episodes(limit=1)[0]
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    page = client.get("/spend").text
    assert f'data-mv-time="{(newest.ended_at or newest.started_at):.3f}"' in page


def _finished_task(owner, cost):
    from maverick import world_model
    from maverick.quotas import UsageLedger
    UsageLedger().record(owner, cost, 0, 0)  # so the person is listed for a personal limit
    w = world_model.open_world()
    gid = w.create_goal("Weekly report", owner=owner)
    w.end_episode(w.start_episode(gid), "Done", "success", cost_dollars=cost)


def test_preview_reports_what_a_stricter_limit_would_have_stopped_and_saves_nothing(client):
    import re

    from maverick import spending_limits
    _finished_task("user:alice", 6.0)
    _finished_task("user:alice", 6.0)
    _finished_task("user:bob", 1.0)
    page = client.get("/spending-limits", params={
        "preview": "workspace", "choice": "limit", "amount": "10", "period": "month"}).text
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page))
    assert "Preview only. Nothing changes until you save." in text
    assert "In the last 30 days, 2 tasks by 2 people would have stopped at $10.00 per month, of 3 finished." in text
    assert spending_limits.load()["workspace"] is None  # report-only
    # The form keeps the previewed amount so Save applies exactly that.
    assert 'value="10.00"' in page
    # Every form offers the preview, which never asks the "raise the limit" question.
    assert page.count('name="preview" value=') == 3
    assert "event.submitter.name === 'preview'" in page


def test_preview_for_one_person_and_a_bad_amount(client):
    _finished_task("user:alice", 6.0)
    page = client.get("/spending-limits", params={
        "preview": "person", "principal": "user:alice", "amount": "5", "period": "task"}).text
    assert "1 task</strong> would have stopped at $5.00 per task, of 1 finished." in page
    page = client.get("/spending-limits", params={"preview": "default", "amount": "-3", "period": "day"}).text
    assert "No preview." in page and "Enter the limit as an amount in dollars" in page


def test_saving_a_limit_is_recorded_in_the_audit_log(client, monkeypatch):
    import maverick.audit as audit
    events = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **kw: events.append((kind, kw)) or True)
    r = client.post("/spending-limits/workspace", data={"choice": "limit", "amount": "75", "period": "day"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert events, "saving a spending limit must write an audit record"
