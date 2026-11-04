"""Onboarding ends with current human review, not an execution event."""
from types import SimpleNamespace

import pytest
from maverick_dashboard import guided_outcome as guided
from maverick_dashboard import onboarding_state
from starlette.requests import Request


class World:
    def __init__(self, decision=None):
        self.decision = decision
        self.calls = []

    def list_goals(self, **kwargs):
        self.calls.append(kwargs)
        return [SimpleNamespace(id=1, title="Forecast", domain="finance", status="done")]

    def signoff_for(self, identifier):
        return self.decision


@pytest.mark.parametrize("decision", [None, {"decision":"rejected", "decided_by":"user:alice"},
    {"decision":"approved", "decided_by":"agent:worker"},
    {"decision":"approved", "decided_by":"token:automation"},
    {"decision":"approved", "decided_by":""}])
def test_execution_rejection_or_machine_decision_does_not_complete_onboarding(decision):
    result = guided.reviewed_goal(World(decision), owner="user:alice", principal="user:alice")
    assert result["complete"] is False


def test_reviewed_outcome_binds_existing_owner_filter_and_suite_permissions():
    world = World({"decision":"approved", "decided_by":"user:reviewer", "created_at":42})
    result = guided.reviewed_goal(world, owner="user:alice", principal="user:alice")
    assert result["complete"] and result["href"] == "/chat/goal/1"
    assert world.calls[0]["owner"] == "user:alice" and world.calls[0]["status"] == "done"
    assert not guided.reviewed_goal(world, domain_allowed=lambda domain: False)["complete"]
    world.decision = None  # source mutation invalidates its authoritative sign-off
    assert not guided.reviewed_goal(world)["complete"]


def test_legacy_local_supervision_counts_only_in_local_context():
    world = World({"decision":"approved", "decided_by":"operator", "created_at":42})
    assert guided.reviewed_goal(world)["complete"]
    assert not guided.reviewed_goal(world, principal="user:alice")["complete"]


def test_missing_review_store_is_visible_as_unavailable():
    world = World()
    world.signoff_for = lambda identifier: (_ for _ in ()).throw(OSError("private database details"))
    result = guided.reviewed_goal(world)
    assert not result["complete"] and result["status"] == "unavailable"
    assert "private database details" not in str(result)


def test_readonly_or_suite_restricted_user_gets_only_permitted_guidance(monkeypatch):
    request = Request({"type":"http", "method":"GET", "path":"/start", "headers":[]})
    monkeypatch.setattr(guided, "suite_allowed", lambda request, suite: suite is None)
    monkeypatch.setattr(guided, "has_permission", lambda request, permission: False)
    monkeypatch.setattr(guided, "caller_role", lambda request: "viewer")
    result = guided.for_request(request, World(), "privacy")
    assert list(result["plans"]) == ["deliverable"]
    assert result["selected_plan"] == "deliverable"
    assert result["outcome"]["status"] == "permission_required"


def test_vendor_sample_and_unaccepted_execution_do_not_complete_path(monkeypatch):
    from maverick_dashboard import vendor_onboarding_api as vendor_api

    row = {"stage":"accepted", "vendor_name":"Example", "integration_mode":{"tickets":"offline_synthetic"},
           "outcome":{"accepted":True,"execution_completed":True,"validation":"verified_external_record","reviewer":"user:reviewer"}}
    monkeypatch.setattr(vendor_api, "_binding", lambda request: None)
    monkeypatch.setattr(vendor_api, "_call", lambda *args: [row])
    assert not guided._reviewed_vendor(None)["complete"]
    row["integration_mode"]["tickets"] = "live_unverified"
    assert guided._reviewed_vendor(None)["complete"]
    row["outcome"]["accepted"] = False
    assert not guided._reviewed_vendor(None)["complete"]


def test_scheduling_without_a_started_task_does_not_complete_the_run_step(monkeypatch):
    monkeypatch.setattr(onboarding_state, "selected_model_route_state", lambda: {"configured":True,"status":"configured"})
    monkeypatch.setattr(onboarding_state, "_has_user_template", lambda: True)
    monkeypatch.setattr(onboarding_state, "_has_user_agent", lambda: False)
    monkeypatch.setattr(onboarding_state, "_has_automation", lambda: True)
    monkeypatch.setattr(onboarding_state, "_preflight_state", lambda profile, **kwargs: {"ready":True})
    world = World()
    world.list_goals = lambda **kwargs: []
    result = onboarding_state.build(world)
    assert result["steps"][2]["done"] is False
    assert result["steps"][3]["done"] is False
    assert not result["runtime_all_set"]
