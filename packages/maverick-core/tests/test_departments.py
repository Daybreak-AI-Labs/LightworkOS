"""Department bundles: the specialist packs grouped into deployable teams."""
from __future__ import annotations

import pytest
from maverick import departments as dept
from maverick.domain import SUITE_PREFIXES, suite_for


def test_finance_is_a_department_with_finance_packs():
    d = dept.get_department("finance")
    assert d is not None
    assert d.title == "Finance"
    assert d.charter  # authored charter, non-empty
    assert d.headcount > 0
    # Every member resolves back to the finance suite.
    assert all(suite_for(name) == "finance" for name in d.members)
    # Roster is sorted and deduplicated.
    assert d.members == sorted(set(d.members))


def test_every_shipped_suite_has_a_customer_label_and_charter():
    shipped = set(SUITE_PREFIXES.values())
    assert shipped <= set(dept.SUITE_LABELS)
    for key in shipped:
        label, charter = dept.SUITE_LABELS[key]
        assert label.strip() and charter.strip(), key
        assert label == dept.department_title(key)
        assert charter == dept.department_charter(key)


def test_list_departments_covers_only_real_suites_sorted_by_title():
    depts = dept.list_departments()
    assert depts, "expected at least one populated department"
    titles = [d.title for d in depts]
    assert titles == sorted(titles)
    valid_suites = set(SUITE_PREFIXES.values())
    assert all(d.key in valid_suites for d in depts)
    # No empty departments are listed.
    assert all(d.headcount > 0 for d in depts)


def test_roster_returns_domain_profiles_for_the_team():
    profiles = dept.roster("finance")
    assert profiles
    names = {p.name for p in profiles}
    assert names == set(dept.get_department("finance").members)


def test_disabled_suite_drops_the_department():
    cfg = {"suites": {"finance": False}}
    keys = {d.key for d in dept.list_departments(cfg)}
    assert "finance" not in keys
    assert dept.get_department("finance", cfg) is None
    assert dept.roster("finance", cfg) == []


def test_inherited_suite_fork_is_in_its_department(tmp_path, monkeypatch):
    (tmp_path / "client_fork.toml").write_text(
        'name = "client_fork"\nextends = "aero_avionics"\n', encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    assert "client_fork" in dept.get_department("aerospace_defense").members
    assert "client_fork" not in {
        member for department in dept.list_departments({"suites": {"aerospace_defense": False}})
        for member in department.members
    }


def test_unknown_suite_key_is_none():
    assert dept.get_department("not_a_suite") is None


def test_title_and_charter_fallback_for_unlabeled_suite():
    # A suite key with no SUITE_LABELS entry still gets a derived title.
    assert dept.department_title("some_new_suite") == "Some New Suite"
    assert dept.department_charter("some_new_suite") == ""


# --- deploy a department as a fleet (plan-gated add-on) ---

def test_fleet_from_department_maps_packs_to_agents():
    d = dept.get_department("finance")
    fleet = dept.fleet_from_department(d, "user:alice")
    assert fleet.name == dept.fleet_name_for("finance", "user:alice")
    assert fleet.owner == "user:alice"
    assert {a.name for a in fleet.agents} == set(d.members)
    # Every agent is scoped to the department's role and carries its charter line.
    assert all(a.role == "finance" for a in fleet.agents)
    assert any(a.description for a in fleet.agents)
    # Each agent is bound to its specialist pack (domain) for run-time capability.
    assert all(a.domain == a.name for a in fleet.agents)


def test_fleet_agent_domain_survives_serialization():
    from maverick.fleet import FleetAgent
    a = FleetAgent("finance_sox", "finance", "Reconcile", domain="finance_sox")
    assert FleetAgent.from_dict(a.to_dict()).domain == "finance_sox"
    # Backward compatible: a legacy agent dict with no domain reads as "".
    assert FleetAgent.from_dict({"name": "x", "role": "r"}).domain == ""


def test_deployed_agent_domain_narrows_capability():
    # The deployed agent's pack capability must only restrict the base grant.
    from maverick.capability import capability_from_config
    from maverick.domain import available_domains, domain_capability
    d = dept.get_department("finance")
    fleet = dept.fleet_from_department(d, "user:alice")
    agent = fleet.agents[0]
    prof = available_domains()[agent.domain]
    base = capability_from_config("agent:test", user_id="agent:test")
    bound = domain_capability(prof, base, "agent:test")
    # Bound grant can never permit a tool the pack denies.
    for denied in prof.deny_tools:
        assert denied in bound.deny_tools


def test_deploy_is_blocked_without_the_addon(monkeypatch):
    # Simulate a provisioned tenant whose plan lacks the entitlement.
    import maverick.billing as billing
    monkeypatch.setattr(billing, "feature_allowed", lambda feature, **kw: False)
    with pytest.raises(dept.EntitlementError) as exc:
        dept.deploy_department("finance", "user:alice", save=False)
    assert exc.value.feature == "departments"
    assert not dept.department_entitled("finance")


def test_deploy_allowed_per_department_grant(monkeypatch):
    import maverick.billing as billing
    # Only the per-department feature is granted, not the whole add-on.
    monkeypatch.setattr(billing, "feature_allowed",
                        lambda feature, **kw: feature == "department:finance")
    assert dept.department_entitled("finance")
    assert not dept.department_entitled("legal")
    fleet = dept.deploy_department("finance", "user:alice", save=False)
    assert fleet is not None
    assert fleet.name == dept.fleet_name_for("finance", "user:alice")


def test_deploy_saves_when_entitled(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    import maverick.billing as billing
    monkeypatch.setattr(billing, "feature_allowed", lambda feature, **kw: True)
    fleet = dept.deploy_department("finance", "user:alice")
    from maverick.fleet import load_fleet
    saved = load_fleet(dept.fleet_name_for("finance", "user:alice"))
    assert saved is not None and saved.owner == "user:alice"
    assert {a.name for a in saved.agents} == {a.name for a in fleet.agents}


def test_repeat_deploy_keeps_team_edits_and_only_adds_new_catalog_members(monkeypatch, tmp_path):
    from dataclasses import replace

    from maverick.fleet import Fleet, FleetAgent, load_fleet, save_fleet

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    initial = dept.deploy_department("finance", "user:alice")
    original = initial.agents[0]
    edited = replace(original, role="custom_role", description="Customer's own instructions")
    manual = FleetAgent("customer_added", "custom_role", "Customer addition")
    # Mirror an ordinary fleet edit, which rebuilds the object without the
    # department marker and intentionally removes one catalog specialist.
    save_fleet(Fleet(name=initial.name, owner=initial.owner,
                     agents=(edited, *initial.agents[2:], manual), created_at=initial.created_at))
    again = dept.deploy_department("finance", "user:alice")
    assert again.agents == (edited, *initial.agents[2:], manual)
    assert again.created_at == initial.created_at
    assert set(again.department_members_added) == {agent.name for agent in initial.agents}
    legacy, count = dept.merge_department_fleet(
        initial, replace(again, department_members_added=()),
        known_members=dept.get_department("finance").members,
    )
    assert count == 0 and legacy.agents == again.agents

    newcomer = FleetAgent("finance_new", "finance", "New catalog specialist", "finance_new")
    proposed = replace(initial, agents=(*initial.agents, newcomer))
    merged, count = dept.merge_department_fleet(
        proposed, load_fleet(initial.name), known_members=[*dept.get_department("finance").members, newcomer.name],
    )
    assert count == 1 and merged.agents == (*again.agents, newcomer)
    # An administrator may later remove that specialist too; a repeat update
    # must not recreate it.
    removed = replace(merged, agents=again.agents)
    merged_again, count = dept.merge_department_fleet(
        proposed, removed, known_members=[*dept.get_department("finance").members, newcomer.name],
    )
    assert count == 0 and merged_again.agents == again.agents


def test_deploy_unknown_department_is_none(monkeypatch):
    import maverick.billing as billing
    monkeypatch.setattr(billing, "feature_allowed", lambda feature, **kw: True)
    assert dept.deploy_department("not_a_dept", "user:alice", save=False) is None


def test_deploy_namespaces_fleet_per_owner(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    import maverick.billing as billing
    monkeypatch.setattr(billing, "feature_allowed", lambda feature, **kw: True)
    from maverick.fleet import list_fleets
    a = dept.deploy_department("finance", "user:alice")
    b = dept.deploy_department("finance", "user:bob")
    # Two owners deploying the same department get distinct, non-colliding fleets.
    assert a.name != b.name
    names = {f.name for f in list_fleets()}
    assert a.name in names and b.name in names
    assert {f.owner for f in list_fleets()} == {"user:alice", "user:bob"}


def test_fleet_name_for_single_tenant_is_unnamespaced():
    # Auth-off / single-tenant (empty owner) keeps the plain name (unchanged).
    assert dept.fleet_name_for("finance", "") == "dept-finance"
    # A real owner is namespaced and stays a valid fleet name.
    from maverick.fleet import valid_name
    named = dept.fleet_name_for("finance", "user:alice")
    assert named != "dept-finance" and valid_name(named)
