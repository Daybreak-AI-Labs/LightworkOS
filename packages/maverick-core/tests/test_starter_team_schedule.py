"""Offline reviewed recurring admission, exact input authority and recovery."""
from __future__ import annotations

import copy
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from maverick.governed_operations import ServiceContext, digest
from maverick.paths import tenant_scope
from maverick.starter_team_checks import catalog
from maverick.starter_team_schedule import StarterTeamScheduleService, worker_schedules
from maverick.starter_teams import StarterTeamService


class RuntimeFixture:
    """Native runtime contract double: no provider or external side effects."""

    def __init__(self):
        self.approvals = set()
        self.starts = []
        self.statuses = []
        self.before_start = None
        self.fail_once = False

    def factory(self, service):
        fixture = self

        class Runtime:
            def review_runtime(self, case_id, *, max_dollars, max_wall_seconds):
                case = service.get_case(case_id)
                service._authorize("runtime_review", next(team for team in catalog() if team["id"] == case["team_id"]))
                return {"case_id": case_id, "team_id": case["team_id"], "runtime_id": "fixture-" + case_id,
                        "input_sha256": case["input_sha256"], "context": service.context.binding(),
                        "max_dollars": max_dollars, "max_wall_seconds": max_wall_seconds,
                        "phases": [{"domain": name} for name in catalog()[0]["specialists"]]}

            def approve_runtime(self, review, *, confirmed):
                if not service.context.human or confirmed is not True:
                    raise PermissionError("Human review required")
                fixture.approvals.add(digest(review))
                return {"id": review["runtime_id"], "status": "ready"}

            def start_runtime(self, review, *, confirmed):
                assert confirmed is False
                if fixture.before_start:
                    fixture.before_start()
                    fixture.before_start = None
                service._authorize("runtime_start", next(team for team in catalog() if team["id"] == review["team_id"]))
                if digest(review) not in fixture.approvals or review["context"] != service.context.binding():
                    raise PermissionError("No exact approval")
                fixture.starts.append(copy.deepcopy(review))
                if fixture.fail_once:
                    fixture.fail_once = False
                    raise RuntimeError("Runtime admission response unavailable")
                return {"id": review["runtime_id"], "status": fixture.statuses.pop(0) if fixture.statuses else "completed"}

        return Runtime()


@pytest.fixture
def setup():
    context = ServiceContext("schedule-test", "owner@example.test", "owner@example.test",
                             "owner@example.test", "approved-exports", human=True,
                             workspace_authority="workspace-generation-1")
    allow = {"value": True}
    def authorize(_context, _operation, _team):
        return allow["value"]
    team = catalog()[0]
    core = StarterTeamService(context, authorize, workspace_id="tenant:schedule-test")
    reviewed = core.preview_setup(team["id"], "Taylor", "Approved supplier export checks")
    saved = core.save_setup(reviewed, confirmed=True)
    clock = [time.time()]
    runtime = RuntimeFixture()
    service = StarterTeamScheduleService(context, authorize, clock=lambda: clock[0],
                                        runtime_factory=runtime.factory, workspace_id="tenant:schedule-test")
    return {"context": context, "authorize": authorize, "allow": allow, "team": team,
            "core": core, "saved": saved, "clock": clock, "runtime": runtime, "service": service}


def _schedule(setup, **overrides):
    clock, service = setup["clock"], setup["service"]
    args = {"interval_hours": 1, "start_at": clock[0] + 1, "end_at": clock[0] + 8 * 3600,
            "max_runs": 3, "max_dollars_per_run": 1.0, "max_total_dollars": 3.0,
            "max_wall_seconds": 120}
    args.update(overrides)
    review = service.preview_schedule(setup["saved"]["id"], **args)
    return service.save_schedule(review, confirmed=True)


def _item(setup, schedule, key="input-0001", *, approve=True):
    sample = setup["team"]["sample"]
    review = setup["service"].preview_item(schedule["id"], copy.deepcopy(sample["tables"]),
                                         as_of=sample["as_of"], idempotency_key=key)
    return setup["service"].approve_item(review, confirmed=True) if approve else review


def _due(setup):
    setup["clock"][0] += 2


def test_schedule_and_each_input_need_separate_exact_human_approval(setup):
    schedule = _schedule(setup)
    item = _item(setup, schedule, approve=False)
    _due(setup)
    result = setup["service"].tick(schedule["id"], idempotency_key="tick-0001")
    assert result["reason"] == "waiting_for_approved_inputs"
    assert setup["runtime"].starts == []
    forged = copy.deepcopy(item)
    forged["runtime_review"]["max_dollars"] = 20
    with pytest.raises(ValueError, match="changed"):
        setup["service"].approve_item(forged, confirmed=True)
    approved = setup["service"].approve_item(item, confirmed=True)
    assert approved["approval_sha256"] == digest(item["runtime_review"])
    result = setup["service"].tick(schedule["id"], idempotency_key="tick-0002")
    assert result["runtime_status"] == "completed"
    assert setup["runtime"].starts[0] == item["runtime_review"]


def test_confirmed_schedule_and_tick_replay_are_exact_after_service_restart(setup):
    schedule = _schedule(setup)
    item = _item(setup, schedule)
    _due(setup)
    service = setup["service"]
    receipt = service.tick(schedule["id"], idempotency_key="tick-0001")
    restarted = StarterTeamScheduleService(setup["context"], setup["authorize"],
        runtime_factory=setup["runtime"].factory, clock=lambda: setup["clock"][0], workspace_id="tenant:schedule-test")
    assert restarted.tick(schedule["id"], idempotency_key="tick-0001") == receipt
    assert restarted.tick_for_key(schedule["id"], "tick-0001") == receipt
    assert len(setup["runtime"].starts) == 1
    assert restarted.item_for_review(item)["status"] == "completed"
    assert restarted.schedule_for_review(schedule)["run_count"] == 1
    setup["clock"][0] += 3601
    assert restarted.tick(schedule["id"], idempotency_key="tick-0002")["reason"] == "waiting_for_approved_inputs"
    assert len(setup["runtime"].starts) == 1


def test_headless_tick_consumes_preapproved_exact_review_without_new_approval(setup):
    schedule = _schedule(setup)
    _item(setup, schedule)
    _due(setup)
    worker = StarterTeamScheduleService(replace(setup["context"], human=False), setup["authorize"],
        runtime_factory=setup["runtime"].factory, clock=lambda: setup["clock"][0], workspace_id="tenant:schedule-test")
    assert worker.tick(schedule["id"], idempotency_key="worker-0001")["runtime_status"] == "completed"
    with pytest.raises(PermissionError, match="person"):
        worker.preview_item(schedule["id"], setup["team"]["sample"]["tables"],
                            as_of=setup["team"]["sample"]["as_of"], idempotency_key="input-0002")


@pytest.mark.parametrize("changed", ["tenant", "owner", "workspace", "authority"])
def test_other_tenant_owner_workspace_or_changed_authority_cannot_dispatch(setup, changed):
    schedule = _schedule(setup)
    _item(setup, schedule)
    _due(setup)
    context, workspace = setup["context"], "tenant:schedule-test"
    if changed == "tenant":
        context = replace(context, tenant="other-tenant")
    elif changed == "owner":
        context = replace(context, actor="other", resource_owner="other")
    elif changed == "workspace":
        workspace = "another-workspace"
    else:
        context = replace(context, authorization_policy="changed-policy")
    service = StarterTeamScheduleService(context, setup["authorize"], runtime_factory=setup["runtime"].factory,
                                        clock=lambda: setup["clock"][0], workspace_id=workspace)
    with pytest.raises((KeyError, PermissionError)):
        service.tick(schedule["id"], idempotency_key="tick-0001")
    assert setup["runtime"].starts == []


def test_revoked_callback_stops_before_admission(setup):
    schedule = _schedule(setup)
    _item(setup, schedule)
    _due(setup)
    setup["allow"]["value"] = False
    with pytest.raises(PermissionError):
        setup["service"].tick(schedule["id"], idempotency_key="tick-0001")
    assert setup["runtime"].starts == []


def test_pause_and_stale_tick_review_stop_before_dispatch(setup):
    schedule = _schedule(setup)
    item = _item(setup, schedule)
    _due(setup)
    paused = setup["service"].set_paused(schedule["id"], paused=True,
        expected_revision=schedule["revision"], idempotency_key="pause-0001")
    with pytest.raises(ValueError, match="changed"):
        setup["service"].tick(schedule["id"], idempotency_key="tick-0001",
                              expected_revision=schedule["revision"], expected_item_id=item["id"])
    assert setup["service"].tick(schedule["id"], idempotency_key="tick-0002")["reason"] == "paused"
    resumed = setup["service"].set_paused(schedule["id"], paused=False,
        expected_revision=paused["revision"], idempotency_key="resume-0001")
    with pytest.raises(ValueError, match="input changed"):
        setup["service"].tick(schedule["id"], idempotency_key="tick-0003",
                              expected_revision=resumed["revision"], expected_item_id="STI-different")
    assert setup["runtime"].starts == []


def test_pause_during_dispatch_preparation_is_rechecked_by_native_authorizer(setup):
    schedule = _schedule(setup)
    _item(setup, schedule)
    _due(setup)
    def pause():
        current = setup["service"].get_schedule(schedule["id"])
        setup["service"].set_paused(schedule["id"], paused=True,
            expected_revision=current["revision"], idempotency_key="pause-race-0001")
    setup["runtime"].before_start = pause
    with pytest.raises(ValueError, match="paused"):
        setup["service"].tick(schedule["id"], idempotency_key="tick-0001")
    assert setup["runtime"].starts == []
    assert setup["service"].tick_for_key(schedule["id"], "tick-0001")["status"] == "needs_review"


@pytest.mark.parametrize("limit,expected", [("count", "run_limit_reached"), ("budget", "total_budget_reserved"), ("window", "schedule_window_ended")])
def test_run_window_and_aggregate_budget_limits_stop_new_occurrences(setup, limit, expected):
    overrides = {"max_runs": 1} if limit == "count" else {"max_total_dollars": 1.0} if limit == "budget" else {}
    schedule = _schedule(setup, **overrides)
    _item(setup, schedule)
    _item(setup, schedule, "input-0002")
    _due(setup)
    setup["service"].tick(schedule["id"], idempotency_key="tick-0001")
    setup["clock"][0] = schedule["end_at"] if limit == "window" else setup["clock"][0] + 3601
    result = setup["service"].tick(schedule["id"], idempotency_key="tick-0002")
    assert result["reason"] == expected
    assert len(setup["runtime"].starts) == 1
    assert setup["service"].get_schedule(schedule["id"])["committed_dollars"] == 1.0


def test_active_runtime_advances_without_new_occurrence_or_budget_reservation(setup):
    schedule = _schedule(setup)
    _item(setup, schedule)
    setup["runtime"].statuses = ["running", "ready", "completed"]
    _due(setup)
    first = setup["service"].tick(schedule["id"], idempotency_key="tick-0001")
    second = setup["service"].tick(schedule["id"], idempotency_key="tick-0002")
    third = setup["service"].tick(schedule["id"], idempotency_key="tick-0003")
    assert [first["runtime_status"], second["runtime_status"], third["runtime_status"]] == ["running", "ready", "completed"]
    current = setup["service"].get_schedule(schedule["id"])
    assert current["run_count"] == 1 and current["committed_dollars"] == 1.0
    assert current["active_item_id"] is None


@pytest.mark.parametrize("status", ["blocked", "uncertain"])
def test_uncertain_or_blocked_runtime_pauses_schedule_and_retains_reservation(setup, status):
    schedule = _schedule(setup)
    _item(setup, schedule)
    setup["runtime"].statuses = [status]
    _due(setup)
    result = setup["service"].tick(schedule["id"], idempotency_key="tick-0001")
    assert result["runtime_status"] == status
    current = setup["service"].get_schedule(schedule["id"])
    assert current["paused"] and current["status"] == "needs_review"
    assert current["committed_dollars"] == 1.0


def test_lost_runtime_response_is_never_repeated_by_same_tick_key(setup):
    schedule = _schedule(setup)
    _item(setup, schedule)
    setup["runtime"].fail_once = True
    _due(setup)
    with pytest.raises(RuntimeError, match="unavailable"):
        setup["service"].tick(schedule["id"], idempotency_key="tick-0001")
    receipt = setup["service"].tick(schedule["id"], idempotency_key="tick-0001")
    assert receipt["status"] == "needs_review"
    assert setup["service"].get_schedule(schedule["id"])["paused"]
    assert len(setup["runtime"].starts) == 1


def test_runtime_expiry_pauses_instead_of_polling_same_permanent_failure(setup):
    schedule = _schedule(setup)
    _item(setup, schedule)
    _due(setup)
    original = setup["runtime"].factory
    def factory(service):
        runtime = original(service)
        def expired(_review, *, confirmed):
            assert confirmed is False
            raise ValueError("The reviewed runtime time window expired")
        runtime.start_runtime = expired
        return runtime
    setup["service"].runtime_factory = factory
    with pytest.raises(ValueError, match="expired"):
        setup["service"].tick(schedule["id"], idempotency_key="tick-0001")
    assert setup["service"].get_schedule(schedule["id"])["status"] == "needs_review"
    assert setup["service"].get_schedule(schedule["id"])["active_item_id"] is not None
    with tenant_scope(tenant=setup["context"].tenant):
        assert worker_schedules(now=setup["clock"][0]) == []


def test_restart_reconciles_completed_input_after_schedule_receipt_failure(setup, monkeypatch):
    from maverick import starter_team_schedule as schedules
    schedule = _schedule(setup)
    _item(setup, schedule)
    _due(setup)
    update = schedules._SCHEDULES.update
    fail = [True]
    def failing_update(*args, **kwargs):
        if kwargs.get("action") == "schedule_occurrence_settled" and fail[0]:
            fail[0] = False
            raise RuntimeError("Schedule receipt temporarily unavailable")
        return update(*args, **kwargs)
    monkeypatch.setattr(schedules._SCHEDULES, "update", failing_update)
    with pytest.raises(RuntimeError, match="receipt temporarily"):
        setup["service"].tick(schedule["id"], idempotency_key="tick-0001")
    setup["clock"][0] += 3601
    assert setup["service"].tick(schedule["id"], idempotency_key="tick-0002")["reason"] == "waiting_for_approved_inputs"
    assert setup["service"].get_schedule(schedule["id"])["active_item_id"] is None
    assert len(setup["runtime"].starts) == 1


def test_same_tick_concurrently_admits_at_most_once(setup):
    schedule = _schedule(setup)
    _item(setup, schedule)
    _due(setup)
    with ThreadPoolExecutor(max_workers=2) as executor:
        values = list(executor.map(lambda _: setup["service"].tick(schedule["id"], idempotency_key="tick-0001"), range(2)))
    assert {value["status"] for value in values} <= {"started", "confirmed"}
    assert len(setup["runtime"].starts) == 1


def test_concurrent_late_running_observation_cannot_reopen_completed_input(setup):
    schedule = _schedule(setup)
    item = _item(setup, schedule)
    _due(setup)
    started = threading.Event()
    completed = threading.Event()
    calls = [0]
    lock = threading.Lock()
    original = setup["runtime"].factory
    def factory(service):
        runtime = original(service)
        def start(review, *, confirmed):
            with lock:
                calls[0] += 1
                ordinal = calls[0]
            service._authorize("runtime_start", setup["team"])
            if ordinal == 1:
                started.set()
                assert completed.wait(15)
                return {"id": review["runtime_id"], "status": "running", "revision": 3}
            return {"id": review["runtime_id"], "status": "completed", "revision": 5}
        runtime.start_runtime = start
        return runtime
    setup["service"].runtime_factory = factory
    with ThreadPoolExecutor(max_workers=2) as executor:
        late = executor.submit(setup["service"].tick, schedule["id"], idempotency_key="tick-race-0001")
        assert started.wait(15)
        fresh = setup["service"].tick(schedule["id"], idempotency_key="tick-race-0002")
        completed.set()
        stale = late.result(timeout=15)
    assert fresh["runtime_status"] == stale["runtime_status"] == "completed"
    assert setup["service"].get_item(item["id"])["status"] == "completed"
    assert setup["service"].get_item(item["id"])["runtime_revision"] == 5
    assert setup["service"].get_schedule(schedule["id"])["active_item_id"] is None


def test_tick_key_is_bound_to_exact_reviewed_preconditions(setup):
    schedule = _schedule(setup)
    _item(setup, schedule)
    _due(setup)
    setup["service"].tick(schedule["id"], idempotency_key="tick-0001")
    with pytest.raises(ValueError, match="different reviewed request"):
        setup["service"].tick(schedule["id"], idempotency_key="tick-0001", expected_item_id="another-item")


@pytest.mark.parametrize("override", [
    {"interval_hours": 0.5}, {"max_runs": True}, {"max_runs": 101},
    {"max_total_dollars": float("inf")}, {"max_dollars_per_run": 10**400},
    {"max_wall_seconds": 0}, {"end_at": 0},
])
def test_invalid_schedule_limits_are_rejected(setup, override):
    with pytest.raises(ValueError):
        _schedule(setup, **override)


def test_input_key_cannot_be_reused_for_different_evidence(setup):
    schedule = _schedule(setup)
    _item(setup, schedule)
    sample = setup["team"]["sample"]
    changed = copy.deepcopy(sample["tables"])
    next(iter(changed.values()))[0]["source"] = "sample://changed"
    with pytest.raises(ValueError, match="different evidence"):
        setup["service"].preview_item(schedule["id"], changed, as_of=sample["as_of"], idempotency_key="input-0001")


def test_trusted_worker_inventory_requires_tenant_and_ignores_paused_schedules(setup):
    schedule = _schedule(setup)
    _item(setup, schedule)
    _due(setup)
    with tenant_scope(tenant=None):
        with pytest.raises(PermissionError):
            worker_schedules()
    with tenant_scope(tenant=setup["context"].tenant):
        assert [row["id"] for row in worker_schedules(now=setup["clock"][0])] == [schedule["id"]]
    setup["service"].set_paused(schedule["id"], paused=True, expected_revision=schedule["revision"], idempotency_key="pause-0001")
    with tenant_scope(tenant=setup["context"].tenant):
        assert worker_schedules(now=setup["clock"][0]) == []


def test_worker_poll_does_not_create_ticks_for_empty_or_not_due_schedules(setup):
    schedule = _schedule(setup)
    with tenant_scope(tenant=setup["context"].tenant):
        assert worker_schedules(now=setup["clock"][0] + 2) == []
    _item(setup, schedule)
    with tenant_scope(tenant=setup["context"].tenant):
        assert worker_schedules(now=setup["clock"][0]) == []


def test_settled_tick_history_archives_without_losing_original_recovery(setup, monkeypatch):
    from maverick import starter_team_schedule as schedules
    schedule = _schedule(setup)
    _due(setup)
    create = schedules._TICKS.create
    def small_capacity(record, **kwargs):
        kwargs["max_records"] = 2
        return create(record, **kwargs)
    monkeypatch.setattr(schedules._TICKS, "create", small_capacity)
    first = setup["service"].tick(schedule["id"], idempotency_key="tick-0001")
    setup["service"].tick(schedule["id"], idempotency_key="tick-0002")
    third = setup["service"].tick(schedule["id"], idempotency_key="tick-0003")
    assert third["status"] == "confirmed"
    recovered = setup["service"].tick_for_key(schedule["id"], "tick-0001")
    # Native archive restoration advances record metadata, not the receipt.
    for key in set(first) - {"revision", "updated_at"}:
        assert recovered[key] == first[key]


@pytest.mark.parametrize("change", ["none", "paused", "ended", "different_active_input", "resumed_after_hold"])
def test_native_queued_stage_rechecks_exact_schedule_before_worker_admission(setup, monkeypatch, tmp_path, change):
    from maverick import starter_team_runtime as runtime
    from maverick import starter_team_schedule as schedules
    from maverick.budget import Budget
    from maverick.capability import Capability
    from maverick.runner import DispatchObservation, DispatchState
    from maverick.world_model import WorldModel

    monkeypatch.setattr(runtime.config, "any_provider_configured", lambda: True)
    monkeypatch.setattr(runtime, "ensure_suite_allowed", lambda *args: None)
    monkeypatch.setattr(runtime, "capability_from_config", lambda *args, **kwargs:
                        Capability(setup["context"].actor, allow_tools=runtime.PREPARE_TOOLS))
    monkeypatch.setattr(runtime, "_worker_authorizer", setup["authorize"])
    monkeypatch.setattr(schedules.time, "time", lambda: setup["clock"][0])
    original_runtime = runtime.StarterTeamRuntime
    submissions = []

    def submit(goal_id, **kwargs):
        submissions.append((goal_id, kwargs))
        return DispatchObservation(goal_id, DispatchState.QUEUED, "queued", owner="queue").as_handle()

    with setup["core"]._scope(), WorldModel(tmp_path / "schedule-native.db") as world:
        def factory(service, *, schedule_id):
            return original_runtime(service, schedule_id=schedule_id, world_factory=lambda: world, submit=submit)
        monkeypatch.setattr(runtime, "StarterTeamRuntime", factory)
        setup["service"].runtime_factory = None
        schedule = _schedule(setup, end_at=setup["clock"][0] + 10)
        item = _item(setup, schedule)
        assert item["runtime_review"]["schedule_id"] == schedule["id"]
        _due(setup)
        receipt = setup["service"].tick(schedule["id"], idempotency_key="native-tick-01")
        assert receipt["runtime_status"] == "running" and len(submissions) == 1
        goal_id, options = submissions[0]
        current = setup["service"].get_schedule(schedule["id"])
        if change == "paused":
            setup["service"].set_paused(schedule["id"], paused=True, expected_revision=current["revision"],
                                        idempotency_key="native-pause-01")
        elif change == "ended":
            setup["clock"][0] += 9
        elif change == "different_active_input":
            schedules._SCHEDULES.update(schedule["id"], lambda row: row.update(active_item_id=None),
                expected_revision=current["revision"], action="test_input_changed", actor=setup["context"].actor)
        elif change == "resumed_after_hold":
            setup["service"]._hold_after_failure(schedule["id"], receipt)
            held = setup["service"].get_schedule(schedule["id"])
            setup["service"].set_paused(schedule["id"], paused=False, expected_revision=held["revision"],
                                        idempotency_key="native-resume-01")
        profile = runtime.enabled_domains()[world.get_goal(goal_id).domain]
        budget = Budget(max_dollars=options["max_dollars"], max_wall_seconds=options["max_wall_seconds"])
        if change in {"none", "resumed_after_hold"}:
            result = runtime.profile_for_starter_goal(world, goal_id, profile, capability=options["capability"], budget=budget)
            assert result.name == profile.name
            assert runtime._GOAL_BINDINGS.get("STG-" + str(goal_id))["worker_admitted_at"] is not None
        else:
            with pytest.raises(PermissionError, match="schedule"):
                runtime.profile_for_starter_goal(world, goal_id, profile, capability=options["capability"], budget=budget)
            assert runtime._GOAL_BINDINGS.get("STG-" + str(goal_id)).get("worker_admitted_at") is None
        assert len(submissions) == 1


@pytest.mark.parametrize("team, interruption", [pytest.param(team, None, id=team["id"]) for team in catalog()] + [
    pytest.param(catalog()[0], "before", id="partial-claim-before-write"),
    pytest.param(catalog()[0], "after", id="partial-claim-after-write"),
])
def test_every_team_completes_approved_schedule_through_native_handoffs(setup, monkeypatch, tmp_path, team, interruption):
    from maverick import starter_team_runtime as runtime
    from maverick import starter_team_schedule as schedules
    from maverick.budget import Budget
    from maverick.capability import Capability
    from maverick.runner import DispatchObservation, DispatchState
    from maverick.world_model import WorldModel

    monkeypatch.setattr(runtime.config, "any_provider_configured", lambda: True)
    monkeypatch.setattr(runtime, "ensure_suite_allowed", lambda *args: None)
    monkeypatch.setattr(runtime, "capability_from_config", lambda *args, **kwargs:
                        Capability(setup["context"].actor, allow_tools=runtime.PREPARE_TOOLS))
    monkeypatch.setattr(runtime, "_worker_authorizer", setup["authorize"])
    monkeypatch.setattr(schedules.time, "time", lambda: setup["clock"][0])
    original_runtime = runtime.StarterTeamRuntime
    submissions = []

    def submit(goal_id, **kwargs):
        submissions.append((goal_id, kwargs))
        return DispatchObservation(goal_id, DispatchState.QUEUED, "queued", owner="queue").as_handle()

    with setup["core"]._scope(), WorldModel(tmp_path / "roster-schedule.db") as world:
        def factory(service, *, schedule_id):
            return original_runtime(service, schedule_id=schedule_id, world_factory=lambda: world, submit=submit)
        monkeypatch.setattr(runtime, "StarterTeamRuntime", factory)
        setup["service"].runtime_factory = None
        setup["team"] = team
        setup["saved"] = setup["core"].save_setup(
            setup["core"].preview_setup(team["id"], "Taylor", "Synthetic roster qualification only"), confirmed=True)
        schedule = _schedule(setup)
        item = _item(setup, schedule)
        prepared = item["runtime_review"]
        assert prepared["specialists"] == team["specialists"]
        assert prepared["schedule_id"] == schedule["id"]
        worker = StarterTeamScheduleService(replace(setup["context"], human=False), setup["authorize"],
            clock=lambda: setup["clock"][0], workspace_id="tenant:schedule-test")
        reader = original_runtime(setup["core"], world_factory=lambda: world)
        case = setup["core"].get_case(item["case_id"])
        _due(setup)
        if interruption:
            update = schedules._ITEMS.update
            interrupted = []
            def fail_claim(*args, **kwargs):
                if kwargs.get("action") == "schedule_input_claimed" and not interrupted:
                    interrupted.append(True)
                    if interruption == "after":
                        update(*args, **kwargs)
                    raise RuntimeError("Interrupted inbox claim write")
                return update(*args, **kwargs)
            monkeypatch.setattr(schedules._ITEMS, "update", fail_claim)
            with pytest.raises(RuntimeError, match="Interrupted inbox claim"):
                worker.tick(schedule["id"], idempotency_key="roster-tick-00")
            reserved = worker.get_schedule(schedule["id"])
            assert reserved["run_count"] == 1 and reserved["committed_dollars"] == 1.0
            assert reserved["active_item_id"] == item["id"] and not submissions
            partial = worker.get_item(item["id"])
            assert partial["status"] == ("approved" if interruption == "before" else "running")
            assert worker.tick(schedule["id"], idempotency_key="roster-tick-00")["status"] == "started"
            assert not submissions
            receipt = worker.tick(schedule["id"], idempotency_key="roster-tick-recovery")
            recovered = worker.get_schedule(schedule["id"])
            assert recovered["run_count"] == reserved["run_count"]
            assert recovered["committed_dollars"] == reserved["committed_dollars"]
            assert recovered["next_due"] == reserved["next_due"]
            assert worker.get_item(item["id"])["occurrence"] == 1
        else:
            receipt = worker.tick(schedule["id"], idempotency_key="roster-tick-00")
        prior = None
        for index, specialist in enumerate(team["specialists"]):
            state = reader.get_runtime(item["case_id"])
            assert state["status"] == receipt["runtime_status"] == "running"
            assert len(state["stages"]) == len(submissions) == index + 1
            stage = state["stages"][-1]
            goal_id, options = submissions[-1]
            goal = world.get_goal(goal_id)
            assert goal.domain == stage["specialist"] == specialist
            assert goal.owner == setup["context"].resource_owner
            assert stage["source_sha256"] == case["input_sha256"]
            assert stage["prompt_sha256"] == digest(goal.description)
            packet = json.loads(goal.description.split("\nEvidence packet:\n", 1)[1])
            assert packet["supplied_evidence"] == team["sample"]["tables"]
            assert packet["structured_checks"] == case["output"]
            assert stage["prior_result_sha256"] == (digest(prior) if prior else None)
            if prior:
                assert packet["prior_specialist_results"][-1]["result"] == prior
            budget = Budget(max_dollars=options["max_dollars"], max_wall_seconds=options["max_wall_seconds"])
            projected = runtime.profile_for_starter_goal(world, goal_id, runtime.enabled_domains()[specialist],
                capability=options["capability"], budget=budget)
            assert projected.name == specialist
            assert options["capability"].allow_tools <= runtime.PREPARE_TOOLS
            prior = f"Synthetic {specialist} result citing supplied evidence {case['input_sha256']}."
            world.set_goal_status(goal_id, "done", result=prior)
            key = f"roster-tick-{index + 1:02d}"
            receipt = worker.tick(schedule["id"], idempotency_key=key)
            count = len(submissions)
            assert worker.tick(schedule["id"], idempotency_key=key) == receipt
            assert len(submissions) == count
        completed = reader.get_runtime(item["case_id"])
        assert completed["status"] == receipt["runtime_status"] == "completed"
        assert completed["result"] == prior
        assert len(submissions) == len(team["specialists"])
        assert all(stage["state"] == "done" and stage["result_sha256"] == digest(stage["result"])
                   for stage in completed["stages"])
        current = worker.get_schedule(schedule["id"])
        assert current["run_count"] == 1 and current["committed_dollars"] == 1.0
        assert current["active_item_id"] is None
        assert worker.get_item(item["id"])["status"] == "completed"
        assert completed["reserved_dollars"] <= prepared["max_dollars"]
        assert worker.tick(schedule["id"], idempotency_key="roster-after-done")["reason"] == "not_due"
        assert len(submissions) == len(team["specialists"])


def test_partial_claim_without_exact_reservation_is_held_for_review(setup, monkeypatch):
    from maverick import starter_team_schedule as schedules

    schedule = _schedule(setup)
    item = _item(setup, schedule)
    _due(setup)
    update = schedules._ITEMS.update
    def fail_claim(*args, **kwargs):
        if kwargs.get("action") == "schedule_input_claimed":
            raise RuntimeError("Interrupted inbox claim write")
        return update(*args, **kwargs)
    monkeypatch.setattr(schedules._ITEMS, "update", fail_claim)
    with pytest.raises(RuntimeError, match="Interrupted inbox claim"):
        setup["service"].tick(schedule["id"], idempotency_key="partial-claim-01")
    reserved = setup["service"].get_schedule(schedule["id"])
    with setup["service"]._scope():
        schedules._SCHEDULES.update(schedule["id"], lambda row: row.update(active_reservation=None),
            expected_revision=reserved["revision"], action="test_reservation_lost", actor=setup["context"].actor)
    receipt = setup["service"].tick(schedule["id"], idempotency_key="partial-claim-02")
    held = setup["service"].get_schedule(schedule["id"])
    assert receipt["reason"] == "paused"
    assert held["paused"] and held["status"] == "needs_review"
    assert held["hold_reason"] == "incomplete_reservation_requires_review"
    assert held["run_count"] == 1 and held["committed_dollars"] == 1.0
    assert setup["service"].get_item(item["id"])["status"] == "approved"
    assert setup["runtime"].starts == []
