"""Budget warnings join, rather than replace, the personal source projection."""
from types import SimpleNamespace

from maverick import budget_guidance
from maverick_dashboard import personal_notifications_api as api


def test_budget_sources_preserve_current_owned_task_sources(monkeypatch):
    goal = SimpleNamespace(id=9, owner="user:alice", title="Own task", status="blocked",
                           result=None, deadline=None, project_id=None)
    world = SimpleNamespace(personal_alert_goals=lambda actor, **kw: [(goal, 1, 0)] if not kw['after_id'] else [],
                            open_questions=lambda _: [], list_projects=lambda **_: [])
    warning = {"ref": "budget:warning", "version": "first", "category": "blocked",
               "title": "Budget needs attention", "label": "Monthly cap approaching",
               "href": "/budget", "goal_id": None, "project_id": None}
    monkeypatch.setattr(api, "_app", lambda: SimpleNamespace(_world=lambda: world))
    monkeypatch.setattr(api.auth, "can_access_goal", lambda *_: True)
    monkeypatch.setattr(api.auth, "has_permission", lambda *_: False)
    monkeypatch.setattr(api.auth, "caller_suites", lambda *_: None)
    observed = []
    monkeypatch.setattr(budget_guidance, "warning_sources", lambda actor: observed.append(actor) or [warning])
    sources, tasks, _, _ = api._projection(object(), "user:alice")
    assert {source["ref"] for source in sources} == {"goal:9:state", "budget:warning"}
    assert tasks == [{"id": 9, "title": "Own task"}]
    assert observed == ["user:alice"]


def test_spending_limit_alerts_reach_administrators_and_the_person(monkeypatch):
    from maverick import spending_alerts
    world = SimpleNamespace(personal_alert_goals=lambda actor, **kw: [],
                            open_questions=lambda _: [], list_projects=lambda **_: [],
                            pending_approvals=list)
    monkeypatch.setattr(api, "_app", lambda: SimpleNamespace(_world=lambda: world))
    monkeypatch.setattr(api.auth, "caller_suites", lambda *_: None)
    monkeypatch.setattr(budget_guidance, "warning_sources", lambda actor: [])
    seen = []

    def fake_sources(actor, *, admin):
        seen.append((actor, admin))
        return [{"ref": "spending-limit:x", "version": "x", "category": "blocked", "title": "Spending limit",
                 "label": "The workspace has used 50% of its $100.00 per month spending limit.",
                 "href": "/spending-limits", "goal_id": None, "project_id": None}]
    monkeypatch.setattr(spending_alerts, "sources", fake_sources)
    import maverick_dashboard.flow_approval_inbox as flows
    monkeypatch.setattr(flows, "pending_for_request", lambda _r: {"coverage": "current", "items": []})
    for admin in (True, False):
        monkeypatch.setattr(api.auth, "has_permission", lambda _r, atom, admin=admin: admin or atom == "view")
        sources, _, _, _ = api._projection(object(), "user:pat")
        assert [s["ref"] for s in sources] == ["spending-limit:x"]
    assert seen == [("user:pat", True), ("user:pat", False)]
