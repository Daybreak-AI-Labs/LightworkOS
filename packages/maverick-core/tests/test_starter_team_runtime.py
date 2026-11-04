"""Offline production-adapter tests for reviewed starter specialist workflows."""
from __future__ import annotations

import asyncio
import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace

import pytest
from maverick import config, governed_records
from maverick import starter_team_runtime as runtime
from maverick.capability import COORDINATION_TOOLS, Capability
from maverick.governed_operations import ServiceContext, digest
from maverick.paths import current_tenant_id
from maverick.runner import DispatchObservation, DispatchState
from maverick.starter_team_checks import catalog
from maverick.starter_teams import StarterTeamService


class FakeWorld:
    def __init__(self):
        self.goals = {}
        self.creates = []

    def create_goal(self, title, description, **kwargs):
        goal_id = len(self.goals) + 1
        self.creates.append((current_tenant_id(), title, description, kwargs))
        self.goals[goal_id] = SimpleNamespace(id=goal_id, title=title, description=description,
            status="pending", result=None, **kwargs)
        return goal_id

    def get_goal(self, goal_id):
        return self.goals.get(goal_id)

    def finish(self, goal_id, result):
        self.goals[goal_id].status = "done"
        self.goals[goal_id].result = result

    def set_goal_status(self, goal_id, status, *, result=None):
        self.goals[goal_id].status, self.goals[goal_id].result = status, result


@pytest.fixture
def harness(tmp_path, monkeypatch):
    from maverick import audit

    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_SHORING", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for name in ("MAVERICK_TENANT", "MAVERICK_REPLICA_COUNT", "MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES",
                 "MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_PG_DSN", "MAVERICK_WORLD_BACKEND"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    monkeypatch.setattr(runtime, "workflow_readiness", lambda profile: {"state": "action_ready"})
    monkeypatch.setattr(runtime, "ensure_suite_allowed", lambda actor, suite: None)
    monkeypatch.setattr(runtime.config, "any_provider_configured", lambda: True)
    caller = Capability("runtime-reviewer", allow_tools=frozenset({
        "knowledge_search", "find_controls", "shell", "write_file", "send_email", "spawn_swarm",
    }), max_risk="high")
    monkeypatch.setattr(runtime, "capability_from_config", lambda *args, **kwargs: caller)
    context = ServiceContext("runtime-tenant", "runtime-reviewer", "runtime-owner", "runtime-reviewer",
        "reviewed-provider", human=True, authorization_role="operator", authorization_policy="operator-policy",
        budget_authority="runtime-budget", workspace_authority="runtime-workspace")
    denied = set()
    operations = []

    def authorize(ctx, operation, team):
        operations.append((ctx, operation, team["id"]))
        return operation not in denied

    service = StarterTeamService(context, authorize)
    monkeypatch.setattr(runtime, "_worker_authorizer", authorize)
    world = FakeWorld()
    submissions = []

    def submit(goal_id, **kwargs):
        # The case has bound the original goal before the effect boundary.
        state = workflow.get_runtime(case["id"])
        assert state["stages"][-1]["goal_id"] == goal_id
        assert state["stages"][-1]["state"] == "submitting"
        submissions.append((current_tenant_id(), goal_id, kwargs))
        return DispatchObservation(goal_id, DispatchState.QUEUED, "queued", owner="queue",
                                   receipt_id=f"sample-receipt-{goal_id}").as_handle()

    team = catalog()[0]
    setup = service.save_setup(service.preview_setup(team["id"], "Taylor", "Reviewed sample evidence"), confirmed=True)
    case = service.run_inputs(setup["id"], team["sample"]["tables"], as_of=team["sample"]["as_of"],
                              idempotency_key="runtime-export-01")
    workflow = runtime.StarterTeamRuntime(service, world_factory=lambda: world, submit=submit)
    value = SimpleNamespace(service=service, context=context, authorize=authorize, denied=denied,
        operations=operations, world=world, submissions=submissions, workflow=workflow,
        team=team, setup=setup, case=case, caller=caller)
    yield value
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def review(h):
    return h.workflow.review_runtime(h.case["id"], max_dollars=3, max_wall_seconds=600)


def test_bundled_samples_never_dispatch_or_create_real_operating_goals(harness):
    h = harness
    sample = h.service.run_sample(h.setup["id"], idempotency_key="bundled-sample-01")
    with pytest.raises(ValueError, match="Bundled samples"):
        h.workflow.review_runtime(sample["id"], 3, 600)
    assert not h.world.creates
    assert not h.submissions


def test_exact_human_approval_is_separate_from_provider_dispatch(harness):
    h = harness
    prepared = review(h)
    assert h.submissions == []
    with pytest.raises(PermissionError, match="Approve the exact"):
        h.workflow.start_runtime(prepared)
    approved = h.workflow.approve_runtime(prepared, confirmed=True)
    assert approved["status"] == "ready"
    assert h.submissions == []
    machine = runtime.StarterTeamRuntime(StarterTeamService(replace(h.context, human=False), h.authorize),
        world_factory=lambda: h.world, submit=h.workflow.submit)
    with pytest.raises(PermissionError, match="authenticated human"):
        machine.approve_runtime(prepared, confirmed=True)
    result = machine.start_runtime(prepared)
    assert result["status"] == "running"
    assert len(h.submissions) == 1


def test_expired_unused_review_can_be_refreshed_without_reusing_old_confirmation(harness):
    h = harness
    now = [1000.0]
    h.service.clock = lambda: now[0]
    old = review(h)
    now[0] += 601
    with pytest.raises(ValueError, match="expired"):
        h.workflow.approve_runtime(old, confirmed=True)
    fresh = review(h)
    assert fresh["id"] != old["id"]
    with pytest.raises(ValueError, match="current runtime review"):
        h.workflow.approve_runtime(old, confirmed=True)
    assert h.workflow.approve_runtime(fresh, confirmed=True)["status"] == "ready"
    assert h.submissions == []


def test_direct_worker_only_advances_an_approved_started_workflow_after_restart(harness):
    from maverick.paths import tenant_scope

    h = harness
    with h.service._scope():
        assert runtime.worker_runtimes() == []
        prepared = review(h)
        assert runtime.worker_runtimes() == []
        h.workflow.approve_runtime(prepared, confirmed=True)
        assert runtime.worker_runtimes() == []
    state = h.workflow.start_runtime(prepared)
    with tenant_scope(tenant="different-runtime-tenant"):
        assert runtime.worker_runtimes() == []
    for index, specialist in enumerate(h.team["specialists"]):
        assert state["stages"][-1]["specialist"] == specialist
        h.world.finish(state["stages"][-1]["goal_id"], f"Actual draft from {specialist}, with retained evidence.")
        if index == 0:
            assert h.workflow.reconcile(h.case["id"])["status"] == "ready"
        with h.service._scope():
            rows = runtime.worker_runtimes()
        assert len(rows) == 1
        assert rows[0]["review"] == prepared and rows[0]["schedule_id"] is None
        # A new trusted worker instance resumes durable state after a restart.
        service = StarterTeamService(replace(h.context, human=False), h.authorize,
                                     workspace_id=rows[0]["workspace"])
        worker = runtime.StarterTeamRuntime(service, world_factory=lambda: h.world, submit=h.workflow.submit)
        state = worker.start_runtime(rows[0]["review"], confirmed=False)
        assert len(h.submissions) == min(index + 2, len(h.team["specialists"]))
    assert state["status"] == "completed"
    with h.service._scope():
        assert runtime.worker_runtimes() == []


@pytest.mark.parametrize("operation", ["review", "approve", "start"])
def test_unbound_and_other_schedule_cannot_adopt_scheduled_runtime(harness, operation):
    h = harness
    scheduled = runtime.StarterTeamRuntime(h.service, world_factory=lambda: h.world,
        submit=h.workflow.submit, schedule_id="SCH-reviewed-schedule")
    prepared = scheduled.review_runtime(h.case["id"], 3, 600)
    assert prepared["schedule_id"] == "SCH-reviewed-schedule"
    for schedule_id in (None, "SCH-another-schedule"):
        other = runtime.StarterTeamRuntime(h.service, world_factory=lambda: h.world,
            submit=h.workflow.submit, schedule_id=schedule_id)
        with pytest.raises(PermissionError, match="different schedule"):
            if operation == "review":
                other.review_runtime(h.case["id"], 3, 600)
            elif operation == "approve":
                other.approve_runtime(prepared, confirmed=True)
            else:
                other.start_runtime(prepared, confirmed=True)
        # Observing original progress remains possible through the ordinary UI.
        assert other.get_runtime(h.case["id"])["review"] == prepared
        assert other.reconcile(h.case["id"])["status"] == "awaiting_approval"
    assert not h.world.creates and not h.submissions


def test_direct_worker_excludes_scheduled_work_and_other_tenants(harness):
    from maverick.paths import tenant_scope

    h = harness
    scheduled = runtime.StarterTeamRuntime(h.service, world_factory=lambda: h.world,
        submit=h.workflow.submit, schedule_id="SCH-reviewed-schedule")
    prepared = scheduled.review_runtime(h.case["id"], 3, 600)
    scheduled.start_runtime(prepared, confirmed=True)
    with h.service._scope():
        assert runtime.worker_runtimes() == []
    with tenant_scope(tenant="different-runtime-tenant"):
        assert runtime.worker_runtimes() == []


def test_worker_inventory_skips_paused_or_missing_setup_and_restores_resumed_work(harness, monkeypatch):
    h = harness
    state = h.workflow.start_runtime(review(h), confirmed=True)
    with h.service._scope():
        assert [row["id"] for row in runtime.worker_runtimes()] == [state["id"]]
    saved = h.service.get_setup(h.setup["id"])
    paused = h.service.set_paused(saved["id"], paused=True, expected_revision=saved["revision"])
    with h.service._scope():
        assert runtime.worker_runtimes() == []
    h.service.set_paused(paused["id"], paused=False, expected_revision=paused["revision"])
    with h.service._scope():
        assert [row["id"] for row in runtime.worker_runtimes()] == [state["id"]]
        monkeypatch.setattr(runtime.native._SETUPS, "get", lambda key: None)
        assert runtime.worker_runtimes() == []
    assert len(h.submissions) == 1


@pytest.mark.parametrize("change", ["unapproved", "unstarted", "no_stage", "blocked", "uncertain", "completed", "binding"])
def test_worker_inventory_excludes_unadmitted_or_stopped_state(harness, change):
    h = harness
    state = h.workflow.start_runtime(review(h), confirmed=True)
    with h.service._scope():
        row = runtime._RUNTIMES.get(state["id"])
        values = {"status": change}
        if change == "unapproved":
            values = {"approval": None}
        elif change == "unstarted":
            values = {"started_at": None}
        elif change == "no_stage":
            values = {"stages": []}
        elif change == "binding":
            values = {"approval": {**row["approval"], "binding_sha256": "0" * 64}}
        runtime._RUNTIMES.update(row["id"], lambda value: value.update(values),
            expected_revision=row["revision"], action="test_worker_state", actor=h.context.actor)
        assert runtime.worker_runtimes() == []


def test_native_submission_preserves_domain_tenant_capability_and_concurrency(harness, monkeypatch):
    from maverick import runner

    h = harness
    monkeypatch.setattr(runner, "start_goal_handle", h.workflow.submit)
    h.workflow.submit = None
    prepared = review(h)
    result = h.workflow.start_runtime(prepared, confirmed=True)
    tenant, goal_id, kwargs = h.submissions[0]
    goal = h.world.goals[goal_id]
    assert tenant == h.context.tenant
    assert goal.domain == h.team["specialists"][0]
    assert goal.owner == h.context.resource_owner
    assert goal.execution_principal == kwargs["user_id"] == result["stages"][0]["principal"]
    assert kwargs["channel"] == "starter-team"
    assert kwargs["concurrency_principal"] == h.context.actor
    assert kwargs["max_depth"] == 0
    assert kwargs["max_dollars"] <= 3 / len(h.team["specialists"])
    assert kwargs["max_wall_seconds"] <= 600 / len(h.team["specialists"])
    assert kwargs["allowed_suites"]
    cap = kwargs["capability"]
    assert cap.principal == goal.execution_principal
    for tool in ("shell", "write_file", "send_email", "jira_create", "browser", *COORDINATION_TOOLS):
        assert not cap.permits(tool)
    assert cap.allow_tools <= runtime.PREPARE_TOOLS or cap.allow_tools == frozenset({"\x00"})
    assert h.context.actor in cap.ancestors


def test_next_stage_receives_actual_reconciled_result_and_source_hash(harness):
    h = harness
    prepared = review(h)
    first = h.workflow.start_runtime(prepared, confirmed=True)
    assert h.workflow.start_runtime(prepared)["status"] == "running"
    assert len(h.submissions) == 1
    h.world.finish(first["stages"][0]["goal_id"], "Actual specialist result cites sample source C2.")
    reconciled = h.workflow.reconcile(h.case["id"])
    assert reconciled["status"] == "ready"
    assert len(h.submissions) == 1
    second = h.workflow.start_runtime(prepared)
    stage = second["stages"][1]
    prompt = h.world.goals[stage["goal_id"]].description
    assert "Actual specialist result cites sample source C2." in prompt
    assert stage["prior_result_sha256"] == digest("Actual specialist result cites sample source C2.")
    assert stage["source_sha256"] == h.case["input_sha256"]
    assert h.world.goals[stage["goal_id"]].domain == h.team["specialists"][1]
    assert stage["prompt_sha256"] == digest(prompt)


def test_unknown_submission_is_never_retried_and_can_be_reconciled(harness):
    h = harness
    calls = []

    def uncertain(goal_id, **kwargs):
        calls.append(goal_id)
        raise TimeoutError("synthetic transport uncertainty")

    h.workflow.submit = uncertain
    prepared = review(h)
    first = h.workflow.start_runtime(prepared, confirmed=True)
    assert first["status"] == "uncertain"
    for _ in range(3):
        assert h.workflow.start_runtime(prepared)["status"] == "uncertain"
    assert len(calls) == 1
    h.world.finish(calls[0], "Original goal completed; reconcile instead of retrying.")
    assert h.workflow.reconcile(h.case["id"])["status"] == "ready"
    assert len(calls) == 1


def test_pause_stops_next_dispatch_without_claiming_active_goal_cancelled(harness):
    h = harness
    prepared = review(h)
    first = h.workflow.start_runtime(prepared, confirmed=True)
    saved = h.service.get_setup(h.setup["id"])
    paused = h.service.set_paused(saved["id"], paused=True, expected_revision=saved["revision"])
    h.world.finish(first["stages"][0]["goal_id"], "First stage completed under its earlier admission.")
    with pytest.raises(ValueError, match="paused"):
        h.workflow.start_runtime(prepared)
    assert len(h.submissions) == 1
    h.service.set_paused(paused["id"], paused=False, expected_revision=paused["revision"])
    assert h.workflow.start_runtime(prepared)["status"] == "running"
    assert len(h.submissions) == 2


def test_pause_after_durable_claim_is_a_known_refusal_before_submission(harness, monkeypatch):
    h = harness
    claim = h.workflow._claim

    def pause_after_claim(*args):
        result = claim(*args)
        setup = h.service.get_setup(h.setup["id"])
        h.service.set_paused(setup["id"], paused=True, expected_revision=setup["revision"])
        return result

    monkeypatch.setattr(h.workflow, "_claim", pause_after_claim)
    state = h.workflow.start_runtime(review(h), confirmed=True)
    assert state["status"] == "blocked"
    assert state["stages"][-1]["submission"]["state"] == "not_accepted"
    assert not h.submissions


@pytest.mark.parametrize("change", ["evidence", "budget", "scope", "capability"])
def test_tampered_runtime_review_never_dispatches(harness, change):
    h = harness
    prepared = review(h)
    altered = copy.deepcopy(prepared)
    if change == "evidence":
        altered["input_sha256"] = "0" * 64
    elif change == "budget":
        altered["max_dollars"] = 100
    elif change == "scope":
        altered["scope"] = "Another workspace"
    else:
        altered["envelope"][0]["capability"]["allow_tools"].append("send_email")
    with pytest.raises(ValueError, match="material changed"):
        h.workflow.start_runtime(altered, confirmed=True)
    assert not h.world.creates
    assert not h.submissions


def test_current_permissions_provider_and_specialist_readiness_are_rechecked(harness, monkeypatch):
    h = harness
    prepared = review(h)
    h.workflow.approve_runtime(prepared, confirmed=True)
    h.denied.add("runtime_start")
    with pytest.raises(PermissionError):
        h.workflow.start_runtime(prepared)
    h.denied.clear()
    monkeypatch.setattr(runtime.config, "any_provider_configured", lambda: False)
    with pytest.raises(ValueError, match="provider"):
        h.workflow.start_runtime(prepared)
    monkeypatch.setattr(runtime.config, "any_provider_configured", lambda: True)
    monkeypatch.setattr(runtime, "workflow_readiness", lambda profile: {"state": "needs_setup"})
    with pytest.raises(ValueError, match="Agent Factory"):
        h.workflow.start_runtime(prepared)
    assert not h.world.creates


@pytest.mark.parametrize("field,value", [("tenant", "other-tenant"), ("resource_owner", "other-owner"),
                                          ("workspace_authority", "other-workspace")])
def test_runtime_never_crosses_tenant_owner_or_workspace(harness, field, value):
    h = harness
    prepared = review(h)
    other = runtime.StarterTeamRuntime(StarterTeamService(replace(h.context, **{field: value}), h.authorize),
                                      world_factory=lambda: h.world, submit=h.workflow.submit)
    with pytest.raises((KeyError, PermissionError)):
        other.start_runtime(prepared, confirmed=True)
    assert not h.submissions


def test_goal_readback_requires_original_owner_domain_principal_and_prompt(harness):
    h = harness
    prepared = review(h)
    first = h.workflow.start_runtime(prepared, confirmed=True)
    goal = h.world.goals[first["stages"][0]["goal_id"]]
    goal.status, goal.result = "done", "Unrelated result must not enter the handoff."
    goal.description += " changed"
    state = h.workflow.reconcile(h.case["id"])
    assert state["status"] == "uncertain"
    assert state["stages"][0]["result"] is None
    assert len(h.submissions) == 1


@pytest.mark.parametrize("dollars,wall", [(0, 600), (float("nan"), 600), (1001, 600),
                                         (3, 0), (3, float("inf")), (3, 86401), (True, 600), (10 ** 1000, 600)])
def test_invalid_or_unbounded_runtime_budget_is_rejected(harness, dollars, wall):
    with pytest.raises(ValueError):
        harness.workflow.review_runtime(harness.case["id"], dollars, wall)
    assert not harness.world.creates


def test_absolute_wall_deadline_prevents_later_stage(harness):
    h = harness
    now = [1000.0]
    h.service.clock = lambda: now[0]
    prepared = review(h)
    first = h.workflow.start_runtime(prepared, confirmed=True)
    h.world.finish(first["stages"][0]["goal_id"], "A valid first result.")
    now[0] += 601
    state = h.workflow.start_runtime(prepared)
    assert state["status"] == "blocked"
    assert "time window expired" in state["reason"]
    assert h.workflow.get_runtime(h.case["id"])["status"] == "blocked"
    assert len(h.submissions) == 1


@pytest.mark.parametrize("goal_status", ["pending", "active", "running", "queued"])
def test_expired_native_task_is_held_after_restart_without_resubmission(harness, goal_status):
    h = harness
    now = [1000.0]
    h.service.clock = lambda: now[0]
    prepared = review(h)
    first = h.workflow.start_runtime(prepared, confirmed=True)
    goal_id = first["stages"][0]["goal_id"]
    goal = h.world.goals[goal_id]
    goal.status = goal_status
    original = copy.deepcopy(vars(goal))
    now[0] += 601
    service = StarterTeamService(replace(h.context, human=False), h.authorize, clock=lambda: now[0])
    worker = runtime.StarterTeamRuntime(service, world_factory=lambda: h.world, submit=h.workflow.submit)
    held = worker.start_runtime(prepared)
    assert held["status"] == held["stages"][0]["state"] == "uncertain"
    assert "time limit expired" in held["reason"]
    assert held["stages"][0]["goal_id"] == goal_id
    with service._scope():
        assert runtime.worker_runtimes() == []
    for _ in range(2):
        assert worker.start_runtime(prepared)["revision"] == held["revision"]
        assert worker.get_runtime(h.case["id"])["status"] == "uncertain"
        assert vars(goal) == original
    assert len(h.submissions) == 1

    # Late evidence is recovered from the same goal, without new execution.
    h.world.finish(goal_id, "Late terminal result from the original specialist.")
    recovered = worker.reconcile(h.case["id"])
    assert recovered["status"] == "ready" and recovered["reason"] is None
    assert recovered["stages"][0]["result"] == goal.result
    assert worker.start_runtime(prepared)["status"] == "blocked"
    assert len(h.submissions) == 1 and len(h.world.goals) == 1


def test_all_real_catalog_rosters_report_their_actual_setup_readiness(harness, monkeypatch):
    from maverick import capability, domain_edit, suite_grants

    h = harness
    monkeypatch.setattr(runtime, "workflow_readiness", domain_edit.workflow_readiness)
    monkeypatch.setattr(runtime, "capability_from_config", capability.capability_from_config)
    monkeypatch.setattr(runtime, "ensure_suite_allowed", suite_grants.ensure_suite_allowed)
    report = {"evidence_mode_ready": [], "full_workflow_prerequisites": {}}
    with h.service._scope():
        profiles = runtime.enabled_domains()
        for team in catalog():
            missing = {name: domain_edit.workflow_readiness(profiles[name])
                       for name in team["specialists"]
                       if domain_edit.workflow_readiness(profiles[name])["state"] != "action_ready"}
            if missing:
                report["full_workflow_prerequisites"][team["id"]] = {
                    name: state.get("missing_tools", []) for name, state in missing.items()}
            envelope = runtime._envelope(team, h.case["id"], h.context.actor)
            assert [row["specialist"] for row in envelope] == team["specialists"]
            for row in envelope:
                grant = runtime._capability(row, deadline=h.service.clock() + 600)
                for tool in ("shell", "write_file", "send_email", "browser", *COORDINATION_TOOLS):
                    assert not grant.permits(tool)
                from maverick.domain import tool_compatibility_errors
                from maverick.starter_team_profiles import effective_profile

                projected = effective_profile(profiles[row["specialist"]], team, row["phase"])
                assert tool_compatibility_errors(projected) == []
                assert domain_edit.workflow_readiness(projected)["state"] == "action_ready"
            report["evidence_mode_ready"].append(team["id"])
    assert len(report["evidence_mode_ready"]) == 37
    print("REAL_ROSTER_READINESS=" + json.dumps(report, sort_keys=True))


def test_disjoint_caller_grant_stays_deny_all(harness, monkeypatch):
    h = harness
    monkeypatch.setattr(runtime, "capability_from_config", lambda *args, **kwargs:
                        Capability(h.context.actor, allow_tools=frozenset({"shell"})))
    prepared = review(h)
    for row in prepared["envelope"]:
        grant = runtime._capability(row, deadline=h.service.clock() + 600)
        assert not any(grant.permits(name) for name in (*runtime.PREPARE_TOOLS, "shell", *COORDINATION_TOOLS))


def test_delayed_receipt_cannot_overwrite_a_later_stage(harness):
    h = harness
    entered, release = threading.Event(), threading.Event()

    def deferred(goal_id, **kwargs):
        if len(h.world.goals) == 1:
            h.world.finish(goal_id, "Completed while the first submission response was delayed.")
            entered.set()
            assert release.wait(10)
        return DispatchObservation(goal_id, DispatchState.QUEUED, "queued", owner="queue",
                                   receipt_id=f"receipt-for-{goal_id}").as_handle()

    h.workflow.submit = deferred
    prepared = review(h)
    h.workflow.approve_runtime(prepared, confirmed=True)
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(h.workflow.start_runtime, prepared)
        assert entered.wait(10)
        second = h.workflow.start_runtime(prepared)
        assert len(second["stages"]) == 2
        release.set()
        final = first.result(timeout=10)
    assert final["stages"][0]["state"] == "done"
    assert final["stages"][0]["submission"]["receipt_id"] == "receipt-for-1"
    assert final["stages"][1]["submission"]["receipt_id"] == "receipt-for-2"
    assert final["stages"][1]["state"] == "running"
    assert final["status"] == "running"


def _native_args(h):
    prepared = review(h)
    state = h.workflow.start_runtime(prepared, confirmed=True)
    stage = state["stages"][0]
    kwargs = h.submissions[0][2]
    budget = SimpleNamespace(max_dollars=stage["max_dollars"], max_wall_seconds=stage["max_wall_seconds"])
    profile = runtime.enabled_domains()[stage["specialist"]]
    return stage, kwargs["capability"], budget, profile


def test_native_worker_consumes_bound_profile_once_without_canary_override(harness, monkeypatch):
    from maverick import domain, orchestrator, specialist_canary

    h = harness
    stage, capability, budget, base = _native_args(h)
    selected = []
    trials = []
    monkeypatch.setattr(domain, "agent_from_profile", lambda profile, *args, **kwargs: selected.append(profile) or object())
    monkeypatch.setattr(specialist_canary, "profile_for_goal", lambda name, profile, *args, **kwargs:
                        trials.append(name) or (profile, "current"))
    monkeypatch.setattr(orchestrator, "_fire_webhook", lambda *args: None)
    episodes = []
    lifecycle = SimpleNamespace(end_episode=lambda *args: episodes.append(args))
    with h.service._scope():
        root, projected, refusal = orchestrator._create_root_agent(world=h.world, goal_id=stage["goal_id"],
            ctx=SimpleNamespace(capability=capability, budget=budget), brief="review supplied evidence", domain=base.name,
            resume=True, allowed_suites=None, model_override=None, lifecycle=lifecycle)
        assert root is not None and refusal is None
        assert projected.name == base.name and projected.compartment == base.compartment
        assert base.persona in projected.persona
        assert projected.refuse == base.refuse
        assert all(not step.tools for step in projected.workflow)
        assert selected == [projected] and trials == []
        with pytest.raises(PermissionError, match="already admitted"):
            runtime.profile_for_starter_goal(h.world, stage["goal_id"], base, capability=capability, budget=budget)
        h.world.finish(stage["goal_id"], "The original completed result must survive duplicate construction.")
        duplicate = orchestrator._create_root_agent(world=h.world, goal_id=stage["goal_id"],
            ctx=SimpleNamespace(capability=capability, budget=budget), brief="duplicate", domain=base.name,
            resume=True, allowed_suites=None, model_override=None, lifecycle=lifecycle)
        assert duplicate[0] is None and "already admitted" in duplicate[2]
        assert h.world.goals[stage["goal_id"]].status == "done"
        assert h.world.goals[stage["goal_id"]].result == "The original completed result must survive duplicate construction."
        assert episodes == []
        ordinary_id = h.world.create_goal("Ordinary", "Ordinary task", owner=h.context.resource_owner,
            execution_principal=h.context.actor, domain=base.name)
        orchestrator._create_root_agent(world=h.world, goal_id=ordinary_id,
            ctx=SimpleNamespace(capability=capability, budget=budget), brief="ordinary", domain=base.name,
            resume=True, allowed_suites=None, model_override=None, lifecycle=lifecycle)
        assert trials == [base.name]


def test_worker_rechecks_authority_at_the_final_durable_admission(harness, monkeypatch):
    h = harness
    stage, capability, budget, profile = _native_args(h)
    checks = []

    def revoke_at_effect(ctx, operation, team):
        checks.append(operation)
        return len(checks) == 1

    monkeypatch.setattr(runtime, "_worker_authorizer", revoke_at_effect)
    with h.service._scope():
        with pytest.raises(PermissionError, match="Current account"):
            runtime.profile_for_starter_goal(h.world, stage["goal_id"], profile,
                                            capability=capability, budget=budget)
        assert len(checks) == 2
        assert runtime._GOAL_BINDINGS.get("STG-" + str(stage["goal_id"])).get("worker_admitted_at") is None


@pytest.mark.parametrize("status", ["active", "done"])
def test_native_reentry_stops_before_lifecycle_and_preserves_original_goal(harness, monkeypatch, tmp_path, status):
    from maverick import orchestrator
    from maverick.budget import Budget
    from maverick.world_model import WorldModel

    h = harness
    monkeypatch.setattr(orchestrator, "_run_goal_accounted", lambda *args, **kwargs:
                        pytest.fail("Duplicate starter execution reached lifecycle/provider setup"))
    with h.service._scope(), WorldModel(tmp_path / "native-world.db") as world:
        workflow = runtime.StarterTeamRuntime(h.service, world_factory=lambda: world,
            submit=lambda goal_id, **kwargs: DispatchObservation(goal_id, DispatchState.QUEUED, "queued").as_handle())
        prepared = workflow.review_runtime(h.case["id"], 3, 600)
        state = workflow.start_runtime(prepared, confirmed=True)
        stage = state["stages"][0]
        cap = runtime._capability(prepared["envelope"][0], deadline=state["deadline"])
        budget = Budget(max_dollars=stage["max_dollars"], max_wall_seconds=stage["max_wall_seconds"])
        runtime.profile_for_starter_goal(world, stage["goal_id"], runtime.enabled_domains()[stage["specialist"]],
                                        capability=cap, budget=budget)
        world.set_goal_status(stage["goal_id"], status, result="Original evidence remains intact.")
        result = asyncio.run(orchestrator.run_goal(object(), world, budget, stage["goal_id"],
            capability=cap, user_id=stage["principal"], domain=stage["specialist"], resume=True))
        assert "already admitted" in result
        original = world.get_goal(stage["goal_id"])
        assert original.status == status
        assert original.result == "Original evidence remains intact."


def test_evidence_profile_rejects_specialist_without_preparation_tools(harness):
    from maverick.starter_team_profiles import effective_profile

    h = harness
    base = runtime.enabled_domains()[h.team["specialists"][0]]
    with pytest.raises(ValueError, match="no approved tools"):
        effective_profile(replace(base, allow_tools=["shell"]), h.team, "intake")


@pytest.mark.parametrize("change", ["missing_binding", "profile_hash", "prompt", "budget", "capability", "paused",
                                    "revoked_role", "revoked_capability", "missing_worker_authorizer"])
def test_native_worker_refuses_missing_changed_or_broader_authority(harness, monkeypatch, change):
    h = harness
    stage, capability, budget, profile = _native_args(h)
    with h.service._scope():
        if change == "missing_binding":
            monkeypatch.setattr(runtime._GOAL_BINDINGS, "get", lambda key: None)
        elif change == "profile_hash":
            binding = runtime._GOAL_BINDINGS.get("STG-" + str(stage["goal_id"]))
            runtime._GOAL_BINDINGS.update(binding["id"], lambda value: value.update(profile_sha256="0" * 64),
                expected_revision=binding["revision"], action="test_binding_change", actor=h.context.actor)
        elif change == "prompt":
            h.world.goals[stage["goal_id"]].description += " altered"
        elif change == "budget":
            budget.max_dollars *= 2
        elif change == "capability":
            capability = Capability(stage["principal"])
        elif change == "revoked_role":
            h.denied.add("runtime_start")
        elif change == "revoked_capability":
            monkeypatch.setattr(runtime, "capability_from_config", lambda *args, **kwargs:
                                Capability(h.context.actor, allow_tools=frozenset({"shell"})))
        elif change == "missing_worker_authorizer":
            monkeypatch.setattr(runtime, "_worker_authorizer", None)
        else:
            setup = h.service.get_setup(h.setup["id"])
            h.service.set_paused(setup["id"], paused=True, expected_revision=setup["revision"])
        with pytest.raises(PermissionError):
            runtime.profile_for_starter_goal(h.world, stage["goal_id"], profile,
                                            capability=capability, budget=budget)


@pytest.mark.parametrize("team", catalog(), ids=lambda team: team["id"])
def test_every_team_runs_its_exact_roster_through_durable_handoffs_offline(harness, team):
    h = harness
    setup = h.service.save_setup(h.service.preview_setup(team["id"], "Taylor", "Synthetic qualification only"), confirmed=True)
    case = h.service.run_inputs(setup["id"], team["sample"]["tables"], as_of=team["sample"]["as_of"],
                                idempotency_key="roster-export-01")
    dispatched = []

    def submit(goal_id, **kwargs):
        dispatched.append((goal_id, kwargs))
        return DispatchObservation(goal_id, DispatchState.QUEUED, "queued", owner="queue").as_handle()

    workflow = runtime.StarterTeamRuntime(h.service, world_factory=lambda: h.world, submit=submit)
    prepared = workflow.review_runtime(case["id"], 4, 600)
    workflow.approve_runtime(prepared, confirmed=True)
    for index, specialist in enumerate(team["specialists"]):
        state = workflow.start_runtime(prepared)
        assert len(dispatched) == index + 1
        stage = state["stages"][-1]
        goal = h.world.goals[stage["goal_id"]]
        assert goal.domain == specialist
        packet = json.loads(goal.description.split("\nEvidence packet:\n", 1)[1])
        assert packet["supplied_evidence"] == case["tables"]
        assert len(packet["prior_specialist_results"]) == index
        for previous in packet["prior_specialist_results"]:
            assert previous["result_sha256"] == digest(previous["result"])
        h.world.finish(goal.id, f"Offline result {index}: {specialist}; sources reviewed from supplied packet.")
        state = workflow.reconcile(case["id"])
    assert state["status"] == "completed"
    assert state["result"] == state["stages"][-1]["result"]
    assert state["provider_qualification"] == "not_qualified"
    assert state["customer_qualification"] == "not_qualified"
    assert sum(kwargs["max_dollars"] for _, kwargs in dispatched) <= prepared["max_dollars"]
    assert sum(kwargs["max_wall_seconds"] for _, kwargs in dispatched) <= prepared["max_wall_seconds"]
    assert workflow.start_runtime(prepared)["status"] == "completed"
    assert len(dispatched) == len(team["specialists"])
