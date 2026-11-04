"""A transient automation-registry read error must defer queued work safely."""
from __future__ import annotations

import asyncio

import pytest
from maverick import event_admission, orchestrator, runner
from maverick.budget import Budget
from maverick.event_admission import EventRegistryUnavailable
from maverick.flow import store
from maverick.flow.ir import Flow, FlowNode
from maverick.job_queue import JobQueue
from maverick.paths import reset_tenant, set_tenant
from maverick.templates import Template
from maverick.worker import Worker
from maverick.world_model import WorldModel
from maverick_dashboard import automation_queue, event_poll, event_triggers_store
from maverick_dashboard.triggers_store import snapshot_from_template


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    tenant = set_tenant(None)
    world = WorldModel(tmp_path / "world.db")
    jobs = JobQueue(tmp_path / "jobs.db")
    monkeypatch.setattr(automation_queue, "queue", lambda: jobs)
    try:
        yield world, jobs
    finally:
        world.close()
        reset_tenant(tenant)


def _unreadable_once(monkeypatch):
    original = event_triggers_store.get_trigger
    calls = []

    def get_trigger(*args, **kwargs):
        if kwargs.get("strict") and not calls:
            calls.append(True)
            raise EventRegistryUnavailable("synthetic registry read error")
        return original(*args, **kwargs)

    monkeypatch.setattr(event_triggers_store, "get_trigger", get_trigger)
    return calls


def test_strict_registry_read_distinguishes_unavailable_from_missing(runtime, monkeypatch):
    tpl = Template(name="recover", title="Handle {{title}}", body="Prepare {{title}}",
                   params=["title"])
    event_triggers_store.set_trigger(
        "orders", "recover", "http_json", owner="user:synthetic",
        config={"url": "https://feed.invalid"}, cursor="old",
        template_snapshot=snapshot_from_template(tpl),
    )
    original = event_triggers_store._tomllib

    class Unreadable:
        @staticmethod
        def load(_stream):
            raise OSError("synthetic transient read failure")

    monkeypatch.setattr(event_triggers_store, "_tomllib", lambda: Unreadable)
    with pytest.raises(EventRegistryUnavailable):
        event_triggers_store.get_trigger("orders", strict=True)
    assert event_triggers_store.get_trigger("orders") is None
    monkeypatch.setattr(event_triggers_store, "_tomllib", original)
    assert event_triggers_store.get_trigger("orders", strict=True) is not None
    assert event_triggers_store.get_trigger("deleted", strict=True) is None


def test_legacy_goal_worker_retries_same_pending_reservation(runtime, monkeypatch):
    world, jobs = runtime
    tpl = Template(name="recover", title="Handle {{title}}", body="Prepare {{title}}",
                   params=["title"])
    trigger = event_triggers_store.set_trigger(
        "orders", "recover", "http_json", owner="user:synthetic",
        config={"url": "https://feed.invalid"}, cursor="old",
        template_snapshot=snapshot_from_template(tpl),
    )
    goal_id = event_admission.admit_batch(
        world, [("synthetic-old-order", "Old order", "Prepare order")],
        owner=trigger["owner"], origin=trigger["name"],
        trigger_key=event_poll._trigger_key(trigger),
    )[0][1]
    job_id = jobs.enqueue("run_goal", {"goal_id": goal_id})
    _unreadable_once(monkeypatch)

    def attempt(gid, **_kwargs):
        try:
            world.set_goal_status(gid, "active")
        except EventRegistryUnavailable as exc:
            return runner._goal_run_exception_status(world, gid, exc)
        return world.get_goal(gid).status

    monkeypatch.setattr(runner, "run_goal_in_thread", attempt)
    worker = Worker(queue=jobs, retry_after=0)
    assert worker.run_once()
    assert jobs.get(job_id).status == "pending"
    assert world.get_goal(goal_id).status == "pending"
    assert worker.run_once()
    assert jobs.get(job_id).status == "done"
    assert world.get_goal(goal_id).status == "active"


def test_orchestrator_finalizer_does_not_block_unclaimed_goal(runtime, monkeypatch):
    world, _jobs = runtime
    tpl = Template(name="recover", title="Handle {{title}}", body="Prepare {{title}}",
                   params=["title"])
    trigger = event_triggers_store.set_trigger(
        "orders", "recover", "http_json", owner="user:synthetic",
        config={"url": "https://feed.invalid"}, cursor="old",
        template_snapshot=snapshot_from_template(tpl),
    )
    goal_id = event_admission.admit_batch(
        world, [("synthetic-orchestrator-order", "Old order", "Prepare order")],
        owner=trigger["owner"], origin=trigger["name"],
        trigger_key=event_poll._trigger_key(trigger),
    )[0][1]
    _unreadable_once(monkeypatch)

    async def allowed(*_args, **_kwargs):
        return None, None

    monkeypatch.setattr(orchestrator, "_goal_risk_gate", allowed)
    with pytest.raises(EventRegistryUnavailable):
        asyncio.run(orchestrator._run_goal_accounted(
            None, world, Budget(), goal_id, user_id="local",
        ))
    assert world.get_goal(goal_id).status == "pending"


def test_registry_error_after_an_actual_start_is_reclaimed(runtime):
    world, _jobs = runtime
    goal_id = world.create_goal("Started work")
    world.set_goal_status(goal_id, "active")
    assert runner._goal_run_exception_status(
        world, goal_id, EventRegistryUnavailable("synthetic later failure"),
    ) == "error"
    # The started goal is reclaimed as failed with its stop reason, never left active.
    assert world.get_goal(goal_id).status == "failed"


def test_flow_worker_retries_after_cursor_advanced(runtime, monkeypatch):
    _world, jobs = runtime
    saved = store.save_flow(Flow(
        id="orders-flow", name="Orders", owner="user:synthetic", start="a",
        nodes={"a": FlowNode(id="a", kind="agent", brief="Prepare order")},
    ))
    release = store.publish_flow(
        saved.id, expected_version=saved.version, expected_revision=saved.revision,
    )
    trigger = event_triggers_store.set_trigger(
        "orders", "", "imap_email", owner="user:synthetic", flow=saved.id,
        flow_owner=saved.owner, flow_revision=release["release_id"], cursor="7",
        config={"host": "mail.example.invalid"},
    )
    generation = event_poll._trigger_key(trigger)
    run_id = automation_queue.enqueue_published_flow_run(
        saved.id, {"id": "50:8", "title": "verified"}, trigger["owner"],
        event_poll._event_key(generation, {}, "50:8"),
        f"event:v2:imap_email:{generation}:orders",
        expected_revision=release["release_id"],
    )
    assert event_triggers_store.set_cursor(
        "orders", "8", expected_cursor="7", expected_generation=generation,
    )
    job = next(j for j in jobs.list() if j.payload.get("run_id") == run_id)
    _unreadable_once(monkeypatch)
    worker = Worker(queue=jobs, retry_after=0)
    worker.register(automation_queue.FLOW_RUN_KIND, automation_queue._handle_flow_run)
    assert worker.run_once()
    assert jobs.get(job.id).status == "pending"
    assert store.load_run(run_id).status == "queued"
    assert event_triggers_store.get_trigger("orders")["cursor"] == "8"
    assert automation_queue._event_flow_start_problem(store.load_run(run_id)) == ""
