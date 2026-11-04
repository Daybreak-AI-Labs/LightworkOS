"""Current-authority and bounded lifecycle checks for approved team scheduling."""
from __future__ import annotations

import copy
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from maverick.governed_operations import ServiceContext, digest
from maverick_dashboard import starter_team_scheduler as worker


def _context():
    return ServiceContext("tenant-a", "operator@example.test", "operator@example.test",
                          "operator@example.test", "structured-input", human=False,
                          authorization_role="operator", authorization_policy="operator-policy-v1",
                          budget_authority="budget-v1", workspace_authority="workspace-generation-v1")


@pytest.fixture(autouse=True)
def isolated_runtime_authorizer(monkeypatch):
    from maverick import starter_team_runtime

    monkeypatch.setattr(starter_team_runtime, "_worker_authorizer", None)
    monkeypatch.setattr(worker, "_runtime_cursors", {})
    monkeypatch.setattr(worker, "_stopping", False)


@pytest.fixture
def current_authority(monkeypatch):
    from maverick import departments, domain
    from maverick.tenant import registry
    from maverick_dashboard import ui_visibility

    state = {"tenant": "tenant-a", "enabled": True, "errors": [], "active": True,
             "owner": "operator@example.test", "suites": {"it_grc", "legal"},
             "role": "operator", "policy": "operator-policy-v1", "budget": "budget-v1",
             "workspace": True, "visible": True, "entitled": True}
    monkeypatch.setattr(worker, "current_tenant_id_strict", lambda: state["tenant"])
    monkeypatch.setattr(worker.shoring, "enabled", lambda: state["enabled"])
    monkeypatch.setattr(worker.config, "config_source_errors", lambda **kwargs: state["errors"])

    def active(tenant):
        assert tenant == "tenant-a"
        if not state["active"]:
            raise PermissionError("Tenant is inactive")

    monkeypatch.setattr(registry, "assert_tenant_active", active)
    monkeypatch.setattr(worker.auth, "stored_automation_identity", lambda actor: (state["owner"], actor, state["suites"]))
    monkeypatch.setattr(worker.auth, "role_for_principal", lambda owner: state["role"])
    monkeypatch.setattr(worker, "_role_authority", lambda role: state["policy"])
    monkeypatch.setattr(worker, "_budget_authority", lambda tenant: state["budget"])
    monkeypatch.setattr(worker, "_workspace_current", lambda context: state["workspace"])
    monkeypatch.setattr(ui_visibility, "page_for", lambda path: path)
    monkeypatch.setattr(ui_visibility, "is_visible", lambda page, role: state["visible"])
    monkeypatch.setattr(domain, "suites_for_domain", lambda name: {"it_grc"} if name == "control" else {"legal"})
    monkeypatch.setattr(departments, "department_entitled", lambda suite, tenant: state["entitled"])
    return state


def test_worker_uses_exact_current_person_authority(current_authority):
    context = _context()
    team = {"specialists": ["control", "contract"]}
    for operation in ("read", "run", "runtime_read", "runtime_start"):
        assert worker.authorize_worker(context, operation, team) is True
    for operation in ("setup", "pause", "runtime_review", "runtime_approve", "publish", "pay"):
        assert worker.authorize_worker(context, operation, team) is False
    assert worker.authorize_worker(replace(context, human=True), "run", team) is False


def test_runtime_registration_binds_current_worker_authorization(current_authority):
    from maverick import starter_team_runtime

    worker.register_runtime_authorizer()
    authorize = starter_team_runtime._worker_authorizer
    assert authorize is worker.authorize_worker
    team = {"specialists": ["control", "contract"]}
    assert authorize(_context(), "runtime_start", team) is True
    current_authority["policy"] = "revoked-policy"
    assert authorize(_context(), "runtime_start", team) is False


@pytest.mark.parametrize("field,value", [
    ("tenant", "tenant-b"), ("enabled", False), ("errors", ["invalid tenant configuration"]),
    ("active", False), ("owner", "different-owner@example.test"), ("role", "reader"),
    ("policy", "policy-v2"), ("budget", "budget-v2"), ("workspace", False),
    ("visible", False), ("entitled", False), ("suites", {"it_grc"}),
])
def test_revoked_or_changed_current_authority_blocks_worker(current_authority, field, value):
    current_authority[field] = value
    assert worker.authorize_worker(_context(), "run", {"specialists": ["control", "contract"]}) is False


def test_workspace_generation_and_authority_source_are_bound(monkeypatch):
    from maverick_dashboard import trc_stock_evidence_composition as composition

    state = {"tenant": "tenant-a", "generation": 7, "source": "principal_selection"}
    monkeypatch.setattr(composition, "source_workspace_authorized",
                        lambda tenant, actor, source: source == state["source"])
    monkeypatch.setattr(worker.workspace_tenants, "get_selection_binding",
                        lambda actor: (state["tenant"], state["generation"]))
    context = _context()
    binding = "sha256:" + digest({"schema": "lightwork.workspace-authority.v1", "principal": context.actor,
                                  "tenant": context.tenant, "source": "principal_selection", "generation": 7})
    context = replace(context, workspace_authority=binding)
    assert worker._workspace_current(context) is True
    state["generation"] = 8
    assert worker._workspace_current(context) is False
    state.update(generation=7, tenant="tenant-b")
    assert worker._workspace_current(context) is False
    state.update(tenant="tenant-a", source="operator_floor")
    assert worker._workspace_current(context) is False


def _schedule(identity="SCH-synthetic", **changes):
    return {"id": identity, "team_id": "compliance_operations", "workspace": "workspace-stable-id",
            "paused": False, "status": "active", "active_item_id": None, "next_due": 100,
            "definition": {"start_at": 50, "end_at": 1000, "context": _context().binding()}, **changes}


@pytest.fixture
def cycle_setup(monkeypatch):
    from maverick import starter_team_schedule, starter_teams

    state = {"tenant": "tenant-a", "enabled": True, "authorized": True,
             "rows": [_schedule()], "items": [{"status": "approved"}], "calls": [], "factories": []}
    monkeypatch.setattr(worker, "current_tenant_id_strict", lambda: state["tenant"])
    monkeypatch.setattr(worker.shoring, "enabled", lambda: state["enabled"])
    monkeypatch.setattr(starter_team_schedule, "worker_schedules", lambda: copy.deepcopy(state["rows"]))
    monkeypatch.setattr(starter_teams, "get_team", lambda team_id: {"id": team_id, "specialists": ["control"]})
    monkeypatch.setattr(worker, "authorize_worker", lambda context, operation, team: state["authorized"])

    class Service:
        def list_items(self, schedule_id):
            return state["items"]

        def tick(self, schedule_id, *, idempotency_key):
            state["calls"].append((schedule_id, idempotency_key))

    def factory(context, authorize, *, workspace_id):
        state["factories"].append((context, authorize, workspace_id))
        return Service()

    return state, factory


def test_cycle_reconstructs_saved_context_and_passes_current_authorizer(cycle_setup):
    state, factory = cycle_setup
    assert worker.workspace_cycle("tenant-a", schedule_factory=factory, now=120) == 1
    context, authorize, workspace = state["factories"][0]
    assert context.binding() == _context().binding()
    assert context.human is False
    assert authorize is worker.authorize_worker
    assert workspace == "workspace-stable-id"
    expected = "worker:" + digest({"schedule": "SCH-synthetic", "poll": 4})
    assert state["calls"] == [("SCH-synthetic", expected)]
    worker.workspace_cycle("tenant-a", schedule_factory=factory, now=121)
    assert state["calls"][-1][1] == expected


@pytest.mark.parametrize("condition", ["disabled", "foreign_tenant"])
def test_workspace_cycle_registers_runtime_authority_before_early_exit(cycle_setup, condition):
    from maverick import starter_team_runtime

    state, factory = cycle_setup
    if condition == "disabled":
        state["enabled"] = False
    else:
        state["tenant"] = "tenant-b"
    assert worker.workspace_cycle("tenant-a", schedule_factory=factory, now=120) == 0
    assert starter_team_runtime._worker_authorizer is worker.authorize_worker
    assert not state["factories"]
    assert not state["calls"]


@pytest.mark.parametrize("condition", ["foreign_tenant", "disabled", "revoked", "future", "ended", "paused", "review", "not_due", "no_inputs"])
def test_cycle_never_dispatches_without_due_approved_authorized_work(cycle_setup, condition):
    state, factory = cycle_setup
    row = state["rows"][0]
    if condition == "foreign_tenant":
        state["tenant"] = "tenant-b"
    elif condition == "disabled":
        state["enabled"] = False
    elif condition == "revoked":
        state["authorized"] = False
    elif condition == "future":
        row["definition"]["start_at"] = 200
    elif condition == "ended":
        row["definition"]["end_at"] = 120
    elif condition == "paused":
        row["paused"] = True
    elif condition == "review":
        row["status"] = "awaiting_confirmation"
    elif condition == "not_due":
        row["next_due"] = 200
    else:
        state["items"] = [{"status": "awaiting_approval"}]
    assert worker.workspace_cycle("tenant-a", schedule_factory=factory, now=120) == 0
    assert state["calls"] == []


def test_active_item_can_advance_without_reconsuming_a_scheduled_slot(cycle_setup):
    state, factory = cycle_setup
    state["rows"][0].update(active_item_id="STI-existing", next_due=900)
    state["items"] = [{"status": "running"}]
    assert worker.workspace_cycle("tenant-a", schedule_factory=factory, now=120) == 1
    assert len(state["calls"]) == 1


def test_cycle_limits_work_to_five_due_schedules(cycle_setup):
    state, factory = cycle_setup
    state["rows"] = [_schedule(f"SCH-{index}") for index in range(8)]
    assert worker.workspace_cycle("tenant-a", schedule_factory=factory, now=120) == 5
    assert len(state["calls"]) == 5


def test_cycle_failure_does_not_repeat_dispatch_in_same_poll(cycle_setup):
    state, _ = cycle_setup

    class Uncertain:
        def list_items(self, schedule_id):
            return [{"status": "approved"}]

        def tick(self, schedule_id, *, idempotency_key):
            state["calls"].append((schedule_id, idempotency_key))
            raise RuntimeError("Submission outcome is uncertain")

    assert worker.workspace_cycle("tenant-a", schedule_factory=lambda *args, **kwargs: Uncertain(), now=120) == 0
    assert len(state["calls"]) == 1


def test_failed_schedule_attempts_still_consume_the_cycle_limit(cycle_setup):
    state, _ = cycle_setup
    state["rows"] = [_schedule(f"SCH-{index}") for index in range(8)]

    class RuntimeUnavailable:
        def list_items(self, schedule_id):
            return [{"status": "approved"}]

        def tick(self, schedule_id, *, idempotency_key):
            state["calls"].append(schedule_id)
            raise RuntimeError("Synthetic runtime failure")

    assert worker.workspace_cycle("tenant-a", schedule_factory=lambda *args, **kwargs: RuntimeUnavailable(), now=120) == 0
    assert len(state["calls"]) == 5


def test_tenant_cycle_uses_explicit_scope_and_limits_rotation(monkeypatch):
    from maverick.paths import current_tenant_id_strict
    from maverick.tenant import registry
    from maverick_dashboard import automation_queue

    monkeypatch.setattr(worker.config, "config_source_errors", lambda **kwargs: [])
    monkeypatch.setattr(worker.shoring, "enabled", lambda: True)
    monkeypatch.setattr(registry, "list_tenants", lambda: [SimpleNamespace(id=f"tenant-{index:02}", active=True) for index in range(12)])
    monkeypatch.setattr(automation_queue, "_configured_tenant_floor", lambda: None)
    monkeypatch.setattr(worker, "_cursor", "")
    seen = []
    direct_seen = []

    def workspace(tenant):
        assert current_tenant_id_strict() == tenant
        seen.append(tenant)
        return 1

    def direct(tenant):
        assert current_tenant_id_strict() == tenant
        direct_seen.append(tenant)
        return 1

    monkeypatch.setattr(worker, "workspace_cycle", workspace)
    monkeypatch.setattr(worker, "runtime_cycle", direct)
    assert worker.cycle() == 20
    assert len(seen) == 10
    assert direct_seen == seen
    assert worker.cycle() == 20
    assert seen[10:12] == ["tenant-10", "tenant-11"]
    assert direct_seen == seen


def test_worker_start_stop_are_idempotent_and_disabled_gate_blocks_start(monkeypatch):
    worker.stop_starter_team_scheduler(timeout=0.1)
    assert worker._stopping is True
    monkeypatch.setattr(worker.shoring, "enabled", lambda: False)
    assert worker.start_starter_team_scheduler() is False
    assert worker.worker_status()["running"] is False
    monkeypatch.setattr(worker.shoring, "enabled", lambda: True)
    try:
        assert worker.start_starter_team_scheduler() is True
        assert worker._stopping is False
        original_thread = worker._thread
        assert worker.start_starter_team_scheduler() is True
        assert worker._thread is original_thread
        assert worker.worker_status()["running"] is True
    finally:
        worker.stop_starter_team_scheduler(timeout=0.2)
    assert worker.worker_status()["running"] is False
    assert worker._thread is None
    assert worker._stopping is True


def test_disabled_scheduler_still_registers_native_runtime_authority(monkeypatch):
    from maverick import starter_team_runtime

    monkeypatch.setattr(worker, "_thread", None)
    monkeypatch.setattr(worker, "_stop", None)
    monkeypatch.setattr(worker.shoring, "enabled", lambda: False)
    assert worker.start_starter_team_scheduler() is False
    assert starter_team_runtime._worker_authorizer is worker.authorize_worker
    assert worker._thread is None
    assert worker._stop is None


@pytest.mark.parametrize("surface", ["team", "schedule"])
def test_direct_service_registers_native_authority_before_request_context(monkeypatch, surface):
    from maverick import starter_team_runtime
    from maverick_dashboard import starter_team_schedule_api, starter_teams_api

    def context(request):
        assert starter_team_runtime._worker_authorizer is worker.authorize_worker
        raise PermissionError("Synthetic request has no authorized workspace")

    monkeypatch.setattr(starter_teams_api, "context", context)
    api = starter_teams_api if surface == "team" else starter_team_schedule_api
    with pytest.raises(PermissionError, match="Synthetic request"):
        api.service(SimpleNamespace())


def _runtime_row(identity="SRT-synthetic", **changes):
    return {"id": identity, "case_id": "STC-" + identity, "team_id": "compliance_operations",
            "tenant": "tenant-a", "owner": _context().resource_owner,
            "workspace": "workspace-stable-id", "schedule_id": None,
            "status": "ready", "started_at": 100,
            "review": {"id": "SRV-" + identity, "context": _context().binding(),
                       "schedule_id": None, "case_id": "STC-" + identity,
                       "max_dollars": 3, "binding_sha256": "original-exact-review"}, **changes}


@pytest.fixture
def direct_cycle_setup(monkeypatch):
    from maverick import starter_team_runtime, starter_teams

    state = {"tenant": "tenant-a", "enabled": True, "authorized": True,
             "rows": [_runtime_row()], "calls": [], "services": [], "authority": []}
    monkeypatch.setattr(worker, "current_tenant_id_strict", lambda: state["tenant"])
    monkeypatch.setattr(worker.shoring, "enabled", lambda: state["enabled"])
    monkeypatch.setattr(starter_team_runtime, "worker_runtimes", lambda: copy.deepcopy(state["rows"]))
    monkeypatch.setattr(starter_teams, "get_team", lambda team_id: {"id": team_id, "specialists": ["control"]})

    def authorize(context, operation, team):
        state["authority"].append((context, operation, team))
        return state["authorized"]

    monkeypatch.setattr(worker, "authorize_worker", authorize)

    class Runtime:
        def start_runtime(self, review, *, confirmed):
            assert confirmed is False
            state["calls"].append(copy.deepcopy(review))
            return {"status": "running"}

    def factory(service):
        assert isinstance(service, starter_teams.StarterTeamService)
        assert state["authority"], "Current authority must be checked before runtime composition"
        state["services"].append(service)
        return Runtime()

    return state, factory


def test_direct_cycle_uses_saved_review_context_workspace_and_no_new_approval(direct_cycle_setup):
    state, factory = direct_cycle_setup
    assert worker.runtime_cycle("tenant-a", runtime_factory=factory) == 1
    assert state["calls"] == [state["rows"][0]["review"]]
    service = state["services"][0]
    assert service.context.binding() == _context().binding()
    assert service.context.human is False
    assert service.workspace_id == "workspace-stable-id"
    assert service.authorize is worker.authorize_worker
    assert state["authority"][0][1] == "runtime_start"


@pytest.mark.parametrize("condition", ["foreign_tenant", "disabled", "revoked", "schedule_row", "schedule_review"])
def test_direct_cycle_never_advances_foreign_disabled_revoked_or_scheduled_work(direct_cycle_setup, condition):
    state, factory = direct_cycle_setup
    if condition == "foreign_tenant":
        state["tenant"] = "tenant-b"
    elif condition == "disabled":
        state["enabled"] = False
    elif condition == "revoked":
        state["authorized"] = False
    elif condition == "schedule_row":
        state["rows"][0]["schedule_id"] = "SCH-controlled"
    else:
        state["rows"][0]["review"]["schedule_id"] = "SCH-controlled"
    assert worker.runtime_cycle("tenant-a", runtime_factory=factory) == 0
    assert not state["services"]
    assert not state["calls"]


def test_direct_cycle_advances_at_most_five_workflows(direct_cycle_setup):
    state, factory = direct_cycle_setup
    state["rows"] = [_runtime_row(f"SRT-{index}") for index in range(8)]
    assert worker.runtime_cycle("tenant-a", runtime_factory=factory) == 5
    assert len(state["calls"]) == 5


def test_direct_failure_does_not_repeat_or_suppress_other_workflows(direct_cycle_setup):
    state, _ = direct_cycle_setup
    state["rows"] = [_runtime_row("SRT-first"), _runtime_row("SRT-second")]

    class Runtime:
        def start_runtime(self, review, *, confirmed):
            assert confirmed is False
            state["calls"].append(review["id"])
            if review["id"] == "SRV-SRT-first":
                raise RuntimeError("Synthetic runtime cannot confirm progress")
            return {"status": "running"}

    assert worker.runtime_cycle("tenant-a", runtime_factory=lambda service: Runtime()) == 1
    assert state["calls"] == ["SRV-SRT-first", "SRV-SRT-second"]


def test_failed_direct_attempts_still_consume_the_cycle_limit(direct_cycle_setup):
    state, _ = direct_cycle_setup
    state["rows"] = [_runtime_row(f"SRT-{index}") for index in range(8)]

    class RuntimeUnavailable:
        def start_runtime(self, review, *, confirmed):
            assert confirmed is False
            state["calls"].append(review["id"])
            raise RuntimeError("Synthetic runtime failure")

    assert worker.runtime_cycle("tenant-a", runtime_factory=lambda service: RuntimeUnavailable()) == 0
    assert len(state["calls"]) == 5


def test_direct_rotation_reaches_later_workflows_even_when_every_attempt_fails(direct_cycle_setup):
    state, _ = direct_cycle_setup
    state["rows"] = [_runtime_row(f"SRT-{index}") for index in reversed(range(8))]

    class RuntimeUnavailable:
        def start_runtime(self, review, *, confirmed):
            assert confirmed is False
            state["calls"].append(review["id"])
            raise RuntimeError("Synthetic runtime failure")

    for _ in range(2):
        assert worker.runtime_cycle("tenant-a", runtime_factory=lambda service: RuntimeUnavailable()) == 0
    assert state["calls"] == [f"SRV-SRT-{index}" for index in (0, 1, 2, 3, 4, 5, 6, 7, 0, 1)]
    assert worker._runtime_cursors["tenant-a"] == "SRT-1"


def test_direct_rotation_cursor_is_independent_for_each_tenant(direct_cycle_setup):
    state, factory = direct_cycle_setup
    first_rows = [_runtime_row(f"SRT-{index}") for index in range(8)]
    state["rows"] = first_rows
    assert worker.runtime_cycle("tenant-a", runtime_factory=factory) == 5

    state["tenant"] = "tenant-b"
    state["rows"] = copy.deepcopy(first_rows)
    for row in state["rows"]:
        row["tenant"] = "tenant-b"
        row["review"]["context"] = replace(_context(), tenant="tenant-b").binding()
    assert worker.runtime_cycle("tenant-b", runtime_factory=factory) == 5
    assert state["services"][-1].context.tenant == "tenant-b"

    state["tenant"], state["rows"] = "tenant-a", first_rows
    assert worker.runtime_cycle("tenant-a", runtime_factory=factory) == 5
    assert [review["id"] for review in state["calls"]] == [
        f"SRV-SRT-{index}" for index in (0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1)]
    assert worker._runtime_cursors == {"tenant-a": "SRT-1", "tenant-b": "SRT-4"}


@pytest.mark.parametrize("failing", ["workspace_cycle", "runtime_cycle"])
def test_cycle_keeps_direct_and_schedule_progress_independent(monkeypatch, failing):
    from maverick.paths import current_tenant_id_strict
    from maverick.tenant import registry
    from maverick_dashboard import automation_queue

    monkeypatch.setattr(worker.config, "config_source_errors", lambda **kwargs: [])
    monkeypatch.setattr(worker.shoring, "enabled", lambda: True)
    monkeypatch.setattr(registry, "list_tenants", lambda: [SimpleNamespace(id="tenant-a", active=True)])
    monkeypatch.setattr(automation_queue, "_configured_tenant_floor", lambda: None)
    monkeypatch.setattr(worker, "_cursor", "")
    seen = []

    def callback(name):
        def advance(tenant):
            assert current_tenant_id_strict() == tenant == "tenant-a"
            seen.append(name)
            if name == failing:
                raise RuntimeError("Synthetic isolated worker failure")
            return 1
        return advance

    monkeypatch.setattr(worker, "workspace_cycle", callback("workspace_cycle"))
    monkeypatch.setattr(worker, "runtime_cycle", callback("runtime_cycle"))
    assert worker.cycle() == 1
    assert seen == ["workspace_cycle", "runtime_cycle"]


def test_direct_worker_rebuilds_runtime_and_completes_saved_roster(tmp_path, monkeypatch, current_authority):
    from maverick import config, governed_records
    from maverick import starter_team_runtime as runtime
    from maverick.paths import tenant_scope
    from maverick.runner import DispatchObservation, DispatchState
    from maverick.starter_teams import StarterTeamService, get_team

    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_SHORING", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for name in ("MAVERICK_TENANT", "MAVERICK_REPLICA_COUNT", "MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES",
                 "MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_PG_DSN", "MAVERICK_WORLD_BACKEND"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    monkeypatch.setattr(config, "any_provider_configured", lambda: True)

    class World:
        def __init__(self):
            self.goals = {}

        def create_goal(self, title, description, **kwargs):
            goal_id = len(self.goals) + 1
            self.goals[goal_id] = SimpleNamespace(id=goal_id, title=title, description=description,
                status="pending", result=None, **kwargs)
            return goal_id

        def get_goal(self, goal_id):
            return self.goals.get(goal_id)

    world, submissions, rebuilt = World(), [], []

    def submit(goal_id, **kwargs):
        submissions.append(goal_id)
        return DispatchObservation(goal_id, DispatchState.QUEUED, "queued", owner="queue").as_handle()

    def factory(service):
        assert service.context.human is False
        assert service.authorize is worker.authorize_worker
        rebuilt.append(service)
        return runtime.StarterTeamRuntime(service, world_factory=lambda: world, submit=submit)

    context = replace(_context(), human=True)
    service = StarterTeamService(context, lambda ctx, operation, team: ctx.binding() == context.binding(),
                                 workspace_id="workspace-stable-id")
    try:
        team = get_team("compliance_operations")
        setup = service.save_setup(service.preview_setup(team["id"], "Taylor", "Offline direct continuation"), confirmed=True)
        case = service.run_inputs(setup["id"], team["sample"]["tables"], as_of=team["sample"]["as_of"],
                                  idempotency_key="direct-continuation-01")
        workflow = runtime.StarterTeamRuntime(service, world_factory=lambda: world, submit=submit)
        review = workflow.review_runtime(case["id"], max_dollars=4, max_wall_seconds=600)
        workflow.approve_runtime(review, confirmed=True)
        with tenant_scope(tenant=context.tenant):
            assert worker.runtime_cycle(context.tenant, runtime_factory=factory) == 0
        assert not submissions
        state = workflow.start_runtime(review)
        assert state["status"] == "running"
        assert len(submissions) == 1

        for index, specialist in enumerate(team["specialists"]):
            stage = state["stages"][index]
            goal = world.get_goal(stage["goal_id"])
            assert goal.domain == specialist
            packet = json.loads(goal.description.split("\nEvidence packet:\n", 1)[1])
            assert packet["supplied_evidence"] == case["tables"]
            assert len(packet["prior_specialist_results"]) == index
            goal.status, goal.result = "done", f"Offline specialist result {index}; source evidence retained."
            if index == 0:
                paused = service.set_paused(setup["id"], paused=True, expected_revision=setup["revision"])
                with tenant_scope(tenant=context.tenant):
                    assert worker.runtime_cycle(context.tenant, runtime_factory=factory) == 0
                assert len(submissions) == 1
                service.set_paused(setup["id"], paused=False, expected_revision=paused["revision"])
            with tenant_scope(tenant=context.tenant):
                assert runtime.worker_runtimes(), workflow.get_runtime(case["id"])
                assert worker.authorize_worker(replace(context, human=False), "runtime_start", team)
                assert worker.runtime_cycle(context.tenant, runtime_factory=factory) == 1
            recovered = runtime.StarterTeamRuntime(StarterTeamService(context, service.authorize,
                workspace_id="workspace-stable-id"), world_factory=lambda: world, submit=submit)
            state = recovered.get_runtime(case["id"])
            assert state["review"]["binding_sha256"] == review["binding_sha256"]
            assert len(submissions) == min(index + 2, len(team["specialists"]))

        assert state["status"] == "completed"
        assert state["result"] == world.get_goal(submissions[-1]).result
        assert len(set(submissions)) == len(team["specialists"])
        assert len({id(value) for value in rebuilt}) == len(rebuilt)
        with tenant_scope(tenant=context.tenant):
            assert worker.runtime_cycle(context.tenant, runtime_factory=factory) == 0
        assert len(submissions) == len(team["specialists"])
    finally:
        governed_records._reset_process_authority_pin_for_testing()
        config.reset_config_cache()


def test_shutdown_revokes_new_worker_admission_but_keeps_read_authority(current_authority):
    context, team = _context(), {"specialists": ["control", "contract"]}
    assert worker.authorize_worker(context, "runtime_start", team) is True
    worker.stop_starter_team_scheduler(wait=False)
    for operation in ("run", "runtime_start"):
        assert worker.authorize_worker(context, operation, team) is False
    for operation in ("read", "runtime_read"):
        assert worker.authorize_worker(context, operation, team) is True


def test_shutdown_during_authority_reads_refuses_guarded_record_claim(tmp_path, monkeypatch, current_authority):
    from maverick import config, governed_records
    from maverick.starter_teams import StarterTeamService

    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_PG_DSN",
                 "MAVERICK_REPLICA_COUNT", "MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    service = StarterTeamService(_context(), worker.authorize_worker)
    team = {"specialists": ["control", "contract"]}
    service._authorize("runtime_start", team)

    def stop_during_current_authority_read(context):
        worker.stop_starter_team_scheduler(wait=False)
        return True

    monkeypatch.setattr(worker, "_workspace_current", stop_during_current_authority_read)
    store = governed_records.GovernedRecordStore("starter_shutdown_test", "TSS", "starter_shutdown_test",
                                               required_backend="local")
    record_id = "TSS-" + "a" * 32
    try:
        with service._write(record_id):
            with pytest.raises(PermissionError, match="Current authority"):
                store.create({"id": record_id}, action="test_claim", actor=service.context.actor,
                             effect_guard=lambda: service._authorize("runtime_start", team))
            assert store.get(record_id) is None
    finally:
        governed_records._reset_process_authority_pin_for_testing()
        config.reset_config_cache()


def test_shutdown_during_direct_run_leaves_later_rows_unclaimed(direct_cycle_setup):
    state, _ = direct_cycle_setup
    state["rows"] = [_runtime_row("SRT-first"), _runtime_row("SRT-second")]
    untouched = copy.deepcopy(state["rows"][1])

    class StopAfterCurrent:
        def start_runtime(self, review, *, confirmed):
            assert confirmed is False
            state["calls"].append(review["id"])
            worker.stop_starter_team_scheduler(wait=False)
            return {"status": "ready"}

    def factory(service):
        return StopAfterCurrent()

    assert worker.runtime_cycle("tenant-a", runtime_factory=factory) == 1
    assert worker.runtime_cycle("tenant-a", runtime_factory=factory) == 0
    assert state["calls"] == ["SRV-SRT-first"]
    assert state["rows"][1] == untouched
    assert worker._runtime_cursors["tenant-a"] == "SRT-first"


def test_shutdown_during_scheduled_run_leaves_later_rows_unclaimed(cycle_setup):
    state, _ = cycle_setup
    state["rows"] = [_schedule("SCH-first"), _schedule("SCH-second")]
    untouched = copy.deepcopy(state["rows"][1])

    class StopAfterCurrent:
        def list_items(self, schedule_id):
            return [{"status": "approved"}]

        def tick(self, schedule_id, *, idempotency_key):
            state["calls"].append(schedule_id)
            worker.stop_starter_team_scheduler(wait=False)

    def factory(*args, **kwargs):
        state["factories"].append(args)
        return StopAfterCurrent()

    assert worker.workspace_cycle("tenant-a", schedule_factory=factory, now=120) == 1
    assert worker.workspace_cycle("tenant-a", schedule_factory=factory, now=120) == 0
    assert state["calls"] == ["SCH-first"]
    assert len(state["factories"]) == 1
    assert state["rows"][1] == untouched


@pytest.mark.parametrize("stop_after", ["workspace_cycle", "runtime_cycle"])
def test_shutdown_stops_remaining_worker_types_and_tenants(monkeypatch, stop_after):
    from maverick.paths import current_tenant_id_strict
    from maverick.tenant import registry
    from maverick_dashboard import automation_queue

    monkeypatch.setattr(worker.config, "config_source_errors", lambda **kwargs: [])
    monkeypatch.setattr(worker.shoring, "enabled", lambda: True)
    monkeypatch.setattr(registry, "list_tenants", lambda: [SimpleNamespace(id=value, active=True)
                                                        for value in ("tenant-a", "tenant-b")])
    monkeypatch.setattr(automation_queue, "_configured_tenant_floor", lambda: None)
    monkeypatch.setattr(worker, "_cursor", "")
    seen = []

    def callback(name):
        def advance(tenant):
            assert current_tenant_id_strict() == tenant
            seen.append((name, tenant))
            if name == stop_after:
                worker.stop_starter_team_scheduler(wait=False)
            return 1
        return advance

    monkeypatch.setattr(worker, "workspace_cycle", callback("workspace_cycle"))
    monkeypatch.setattr(worker, "runtime_cycle", callback("runtime_cycle"))
    expected = [("workspace_cycle", "tenant-a")]
    if stop_after == "runtime_cycle":
        expected.append(("runtime_cycle", "tenant-a"))
    assert worker.cycle() == len(expected)
    assert worker.cycle() == 0
    assert seen == expected
