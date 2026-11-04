"""Workforce packaging: /workforce page + /api/v1 departments/outcomes/marketplace.

Read-only surfaces over the pack registry and the Operating Record. The autouse
fixture points the world DB at a tmp path so these never touch the real one.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _review_team(key):
    """Prepare the reviewed team save the Workforce page shows."""
    context = client.get("/api/v1/department-team-updates/context")
    if context.status_code != 200:
        return context
    return client.post("/api/v1/department-team-updates/review",
                       json={"department": key, "expected_context": context.json()["context"]})


def _save_team(key):
    """Save a department team through its review, as Update team does."""
    review = _review_team(key)
    if review.status_code != 200:
        return review
    return client.post("/api/v1/department-team-updates/save",
                       json={"token": review.json()["token"], "confirmed": True})


@pytest.fixture(autouse=True)
def _isolated_world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    yield


def test_departments_list_includes_finance():
    r = client.get("/api/v1/departments")
    assert r.status_code == 200
    depts = {d["key"]: d for d in r.json()}
    assert "finance" in depts
    assert depts["finance"]["title"] == "Finance"
    assert depts["finance"]["headcount"] > 0
    assert sum(depts["finance"][key] for key in (
        "ready_specialists", "setup_needed_specialists", "unknown_specialists",
    )) == depts["finance"]["headcount"]


def test_department_detail_has_roster():
    r = client.get("/api/v1/departments/finance")
    assert r.status_code == 200
    body = r.json()
    assert body["roster"], "expected a roster"
    assert {"name", "description", "max_risk", "readiness"} <= set(body["roster"][0])
    assert body["roster"][0]["readiness"]["state"] in {
        "action_ready", "needs_setup", "unknown",
    }


def test_team_with_no_usable_specialist_is_not_deployed(monkeypatch):
    import maverick.domain_edit as domain_edit
    from maverick.departments import get_department

    monkeypatch.setattr(domain_edit, "list_agents", lambda: [
        {"name": name, "readiness": {"state": "needs_setup"}}
        for name in get_department("finance").members
    ])
    response = _review_team("finance")
    assert response.status_code == 409
    assert "No specialist in this department passed its action setup check" in response.json()["detail"]


def test_team_with_only_unverified_specialists_is_not_deployed(monkeypatch):
    import maverick.domain_edit as domain_edit
    from maverick.departments import get_department

    monkeypatch.setattr(domain_edit, "list_agents", lambda: [
        {"name": name, "readiness": {"state": "unknown"}}
        for name in get_department("finance").members
    ])
    response = _review_team("finance")
    assert response.status_code == 409
    assert "passed its action setup check" in response.json()["detail"]


def test_unknown_department_404():
    assert client.get("/api/v1/departments/not_a_dept").status_code == 404
    assert client.get("/api/v1/departments/not_a_dept/review").status_code == 404


def test_department_review_composes_sections():
    r = client.get("/api/v1/departments/finance/review")
    assert r.status_code == 200
    body = r.json()
    assert {"department", "delivery", "authority", "learning",
            "governance_note"} <= set(body)
    assert "audit log" in body["governance_note"]


def test_outcomes_has_firm_and_workers():
    r = client.get("/api/v1/outcomes")
    assert r.status_code == 200
    body = r.json()
    assert "firm" in body and "workers" in body
    assert "goals_completed" in body["firm"]


def test_marketplace_packs_grouped_and_searchable():
    grouped = client.get("/api/v1/marketplace/packs").json()
    assert any(d["key"] == "finance" for d in grouped["departments"])
    hits = client.get("/api/v1/marketplace/packs", params={"q": "finance"}).json()
    assert hits["query"] == "finance"
    assert isinstance(hits["results"], list)


def test_marketplace_connectors_count_and_search():
    full = client.get("/api/v1/marketplace/connectors").json()
    assert full["total"] > 50
    filtered = client.get("/api/v1/marketplace/connectors",
                          params={"q": "zendesk"}).json()
    assert filtered["total"] == full["total"]
    assert any(c["name"] == "zendesk" for c in filtered["connectors"])


def test_workforce_page_renders():
    r = client.get("/workforce")
    assert r.status_code == 200
    assert "Workforce" in r.text
    assert "Finance" in r.text
    # The nav link is wired in.
    assert "/workforce" in r.text


def test_workforce_candidate_has_current_revision_and_grant_gate(monkeypatch):
    from types import SimpleNamespace

    import maverick.agent_autonomy as autonomy
    from maverick.departments import get_department

    name = get_department("finance").members[0]
    monkeypatch.setattr(autonomy, "levels_enabled", lambda: True)
    monkeypatch.setattr(autonomy, "graduation_candidates", lambda _history, _names: [
        SimpleNamespace(name=name, sample=12, approve_rate=1.0, confidence=0.95,
                        reason="clean approval record"),
    ])
    response = client.get("/api/v1/workforce/posture")
    assert response.status_code == 200
    candidate = response.json()["graduation_candidates"][0]
    assert candidate["name"] == name
    assert len(candidate["generation"]) == 64
    assert candidate["can_grant"] is True


def test_act_policy_is_review_only_even_with_clean_aggregate_approvals(monkeypatch):
    from types import SimpleNamespace

    import maverick.agent_autonomy as autonomy
    import maverick.domain_edit as domain_edit
    from maverick.departments import get_department

    name = get_department("finance").members[0]
    original_view = domain_edit.resolved_view

    def act_view(candidate: str):
        view = original_view(candidate)
        if candidate == name and view:
            view["autonomy"]["pack"]["high"] = "auto"
        return view

    monkeypatch.setattr(domain_edit, "resolved_view", act_view)
    monkeypatch.setattr(autonomy, "levels_enabled", lambda: True)
    monkeypatch.setattr(autonomy, "graduation_candidates", lambda _history, _names: [
        SimpleNamespace(name=name, sample=100, approve_rate=1.0, confidence=1,
                        reason="clean approval record"),
    ])
    response = client.get("/api/v1/workforce/posture")
    assert response.status_code == 200
    candidate = response.json()["graduation_candidates"][0]
    assert candidate["can_grant"] is False
    assert "overall approval record cannot prove" in candidate["grant_block_reason"]


def test_workforce_connector_search_is_race_safe():
    """The connector search script must only render the latest response.

    Regression: typing "slack" then "jira" rendered the slower, stale Slack
    result because responses were not sequenced; a failed request also left
    the previous list on screen with no error state.
    """
    html = client.get("/workforce").text
    # Monotonic request id, compared before rendering (stale responses drop).
    assert "connSearchSeq" in html
    assert "if (seq !== connSearchSeq) return;" in html
    # Failed request renders an error item instead of leaving stale results.
    assert ".catch(" in html
    assert "Could not search apps right now." in html
    # In-flight state is announced on the results list and cleared afterward.
    assert 'results.setAttribute("aria-busy", "true")' in html
    assert 'results.removeAttribute("aria-busy")' in html


def test_workforce_distinguishes_catalog_from_deployment(monkeypatch):
    from maverick import connections, fleet
    from maverick.fleet import Fleet, FleetAgent

    monkeypatch.setattr(
        fleet,
        "list_fleets",
        lambda: [
            Fleet(
                name="dept-finance",
                owner="",
                agents=(FleetAgent(name="analyst", role="operator", domain="finance"),),
            )
        ],
    )
    monkeypatch.setattr(
        connections,
        "list_connections",
        lambda owner=None: [
            {"connector": "slack"},
            {"connector": "slack"},
            {"connector": "servicenow"},
        ],
    )

    r = client.get("/workforce")

    assert r.status_code == 200
    assert "1 specialists deployed" in r.text
    assert "2 are set up" in r.text
    assert "specialists on staff" not in r.text
    assert "connectors wired" not in r.text
    assert "catalog specialists" in r.text


def test_workforce_explains_missing_department_charter_without_overclaiming(monkeypatch):
    from maverick import connections, departments, fleet

    incomplete = departments.Department(
        key="finance",
        title="Finance",
        charter="",
        members=["finance_fixture"],
    )
    monkeypatch.setattr(departments, "list_departments", lambda: [incomplete])
    monkeypatch.setattr(departments, "department_entitled", lambda _key: True)
    monkeypatch.setattr(fleet, "list_fleets", list)
    monkeypatch.setattr(connections, "list_connections", lambda owner=None: [])

    r = client.get("/workforce")

    assert r.status_code == 200
    assert (
        "No description yet. View the team to see its specialists before you deploy it."
        in r.text
    )
    assert "1 catalog specialists" in r.text
    assert "0 specialists deployed" in r.text
    assert "specialists on staff" not in r.text
    assert "connectors wired" not in r.text


# --- deploy a department as a fleet (plan-gated add-on) ---

def test_departments_list_reports_entitlement():
    rows = client.get("/api/v1/departments").json()
    assert all("entitled" in r for r in rows)


def test_deploy_department_creates_a_fleet(tmp_path, monkeypatch):
    # Self-host (no tenant) is entitled by fail-open; isolate the fleets dir.
    import maverick.domain_edit as domain_edit
    from maverick.departments import get_department

    members = get_department("finance").members
    monkeypatch.setattr(domain_edit, "list_agents", lambda: [
        {"name": name, "readiness": {"state": "action_ready"}}
        for name in members
    ])
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    review = _review_team("finance")
    assert review.status_code == 200 and review.json()["preview"]["Setup still needed"] == []
    r = _save_team("finance")
    assert r.status_code == 200 and r.json()["message"] == "Team set up."
    from maverick.fleet import load_fleet
    fleet = load_fleet("dept-finance")
    assert fleet.name == "dept-finance"
    assert fleet.agents
    # It is now a real, runnable fleet.
    assert any(f["name"] == "dept-finance" for f in client.get("/api/v1/fleets").json()["fleets"])


def test_repeat_deploy_keeps_customer_changes_and_reports_no_new_members(tmp_path, monkeypatch):
    import maverick.domain_edit as domain_edit
    from maverick.departments import get_department
    from maverick.fleet import Fleet, FleetAgent, load_fleet, save_fleet

    members = get_department("finance").members
    monkeypatch.setattr(domain_edit, "list_agents", lambda: [
        {"name": name, "readiness": {"state": "action_ready"}} for name in members
    ])
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    first = _save_team("finance")
    assert first.status_code == 200 and first.json()["message"] == "Team set up."
    original = load_fleet("dept-finance")
    changed = FleetAgent(original.agents[0].name, "customer_role", "Customer instructions", original.agents[0].domain)
    manual = FleetAgent("customer_added", "customer_role", "Customer addition")
    save_fleet(Fleet(name=original.name, owner=original.owner,
                     agents=(changed, *original.agents[2:], manual), created_at=original.created_at))

    again = _save_team("finance")
    assert again.status_code == 200
    assert again.json()["details"]["New specialists at this save"] == 0
    assert again.json()["message"] != "Team set up."
    kept = load_fleet("dept-finance")
    assert kept.agents == (changed, *original.agents[2:], manual)
    assert kept.created_at == original.created_at
    assert next(row for row in client.get("/api/v1/departments").json()
                if row["key"] == "finance")["deployed"] is True

    monkeypatch.setattr(domain_edit, "list_agents", lambda: [
        {"name": name, "readiness": {"state": "needs_setup"}} for name in members
    ])
    unavailable = _save_team("finance")
    assert unavailable.status_code == 200
    assert unavailable.json()["details"]["New specialists at this save"] == 0
    assert load_fleet("dept-finance").agents == kept.agents


def test_deploy_excludes_specialists_that_need_setup_and_reports_them(tmp_path, monkeypatch):
    import maverick.domain_edit as domain_edit
    from maverick.departments import get_department

    members = get_department("finance").members
    ready = members[0]
    monkeypatch.setattr(domain_edit, "list_agents", lambda: [
        {"name": name, "readiness": {
            "state": "action_ready" if name == ready else "needs_setup",
            "label": "Can start" if name == ready else "Needs a connected source",
            "fix_url": None if name == ready else "/connections",
        }}
        for name in members
    ])
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    review = _review_team("finance")
    assert review.status_code == 200, review.text
    skipped = review.json()["preview"]["Setup still needed"]
    assert len(skipped) == len(members) - 1
    assert all(item["Reason"] == "Needs a connected source" and item["Next step"]["href"] == "/connections"
               for item in skipped)
    response = _save_team("finance")
    assert response.status_code == 200, response.text
    assert response.json()["details"]["Team size at this save"] == 1
    from maverick.fleet import load_fleet

    assert [agent.name for agent in load_fleet("dept-finance").agents] == [ready]


def test_deploy_blocked_without_addon_returns_402(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    import maverick.billing as billing
    monkeypatch.setattr(billing, "feature_allowed", lambda feature, **kw: False)
    r = client.post("/api/v1/departments/finance/deploy")
    assert r.status_code == 402
    assert "add-on" in r.json()["detail"]


def test_deploy_unknown_department_404(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    r = client.post("/api/v1/departments/not_a_dept/deploy")
    assert r.status_code == 404


def test_deploy_managed_roster_without_active_tenant_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.paths import reset_tenant, set_tenant
    from maverick.tenant import registry as tenant_registry

    token = set_tenant(None)
    try:
        tenant_registry.create_tenant("acme", plan="free")
        rows = client.get("/api/v1/departments").json()
        assert any(r["key"] == "finance" and r["entitled"] is False for r in rows)
        r = _review_team("finance")
    finally:
        reset_tenant(token)

    assert r.status_code == 402
    assert "Choose your workspace" in r.json()["detail"]


def test_deploy_passes_active_tenant_to_entitlement(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.paths import reset_tenant, set_tenant
    from maverick.tenant import registry as tenant_registry

    tenant_registry.create_tenant("acme", plan="free")
    token = set_tenant("acme")
    try:
        r = client.post("/api/v1/departments/finance/deploy")
    finally:
        reset_tenant(token)

    assert r.status_code == 402
    assert "add-on" in r.json()["detail"]
