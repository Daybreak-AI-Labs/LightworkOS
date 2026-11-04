"""Independent adversarial checks of durable federation authority boundaries."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick import federation_admission as admission
from maverick.capability import Capability
from maverick.chat_threads import ChatThreads
from maverick.grpc_api.service import GoalService
from maverick.orchestrator import _execution_principal
from maverick.paths import tenant_scope
from maverick.world_model import WorldModel


def _reserve(world, **changes):
    values = dict(peer="peer-a", correlation="original-correlation", digest="a" * 64,
                  title="Synthetic held delegation", description="Do not run before audit",
                  capability=None, max_dollars=2.5, max_wall_seconds=30.0)
    values.update(changes)
    return admission.reserve(world, **values)


def _ready(world):
    reservation = _reserve(world)
    admission.acknowledge(world, reservation)
    return reservation


def _consume(world, reservation):
    with admission.execution_scope(reservation):
        admission.require_execution(world, reservation.goal_id,
                                    max_dollars=2.5, max_wall_seconds=30, consume=True)


def test_execution_kwargs_roundtrip_ungranted_runtime_principal(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        reservation = _reserve(world)
        kwargs = admission.execution_kwargs(reservation)
        assert _execution_principal(user_id=kwargs["user_id"], capability=kwargs["capability"]) == (
            world.get_goal(reservation.goal_id).execution_principal
        )


def test_changed_request_conflicts_without_creating_another_goal(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        original = _reserve(world)
        with pytest.raises(ValueError, match="different delegation content"):
            _reserve(world, digest="b" * 64)
        assert [goal.id for goal in world.list_goals()] == [original.goal_id]
        assert admission.state(world, original) == admission.HELD


def test_retry_keeps_original_budget_and_capability_after_policy_broadens(tmp_path):
    original_grant = Capability(principal="federation:peer-a", allow_tools=frozenset({"read"}))
    expanded_grant = Capability(principal="federation:peer-a")
    with WorldModel(tmp_path / "world.db") as world:
        original = _reserve(world, capability=original_grant)
        retried = _reserve(world, capability=expanded_grant, max_dollars=999, max_wall_seconds=999)
        assert retried == original
        kwargs = admission.execution_kwargs(retried)
        assert kwargs["capability"] == original_grant
        assert kwargs["max_dollars"] == 2.5 and kwargs["max_wall_seconds"] == 30


@pytest.mark.parametrize("status", ["pending", "active", "blocked", "done"])
def test_visible_goal_status_cannot_release_held_receipt(tmp_path, status):
    with WorldModel(tmp_path / "world.db") as world:
        reservation = _reserve(world)
        world.set_goal_status(reservation.goal_id, status)
        with pytest.raises(admission.FederationAdmissionRequired):
            admission.require_execution(world, reservation.goal_id)
        assert admission.state(world, reservation) == admission.HELD


def test_cancel_and_real_chat_resume_cannot_release_held_receipt(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        reservation = _reserve(world)
        world.set_goal_status(reservation.goal_id, "cancelled")
        ChatThreads(world).resume(reservation.goal_id)
        assert world.get_goal(reservation.goal_id).status == "pending"
        with pytest.raises(admission.FederationAdmissionRequired):
            admission.require_execution(world, reservation.goal_id)
        assert admission.state(world, reservation) == admission.HELD


def test_ready_receipt_requires_its_dispatch_closure(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        reservation = _ready(world)
        with pytest.raises(admission.FederationAdmissionRequired):
            admission.require_execution(world, reservation.goal_id)
        assert admission.claim(world, reservation)
        with pytest.raises(admission.FederationAdmissionRequired):
            admission.require_execution(world, reservation.goal_id)
        _consume(world, reservation)
        assert admission.state(world, reservation) == admission.RUNNING
        with pytest.raises(admission.FederationAdmissionRequired):
            _consume(world, reservation)


def test_orphan_reclaim_and_resume_do_not_reissue_dispatch(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        reservation = _ready(world)
        assert admission.claim(world, reservation)
        assert world.reclaim_orphan_goals(max_age_seconds=0) == 1
        ChatThreads(world).resume(reservation.goal_id)
        assert world.get_goal(reservation.goal_id).status == "pending"
        assert not admission.claim(world, reservation)
        with pytest.raises(admission.FederationAdmissionRequired):
            admission.require_execution(world, reservation.goal_id)
        assert admission.state(world, reservation) == admission.DISPATCHING


def test_receipt_insert_failure_rolls_back_goal_and_origin(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        with world._writing() as connection:
            connection.execute("CREATE TRIGGER reject_receipt BEFORE INSERT ON event_goal_admissions "
                               "BEGIN SELECT RAISE(ABORT, 'synthetic receipt fault'); END")
        with pytest.raises(Exception, match="synthetic receipt fault"):
            _reserve(world)
        assert world.list_goals() == []
        assert world._read_all("SELECT * FROM goal_origins") == []


def test_deleted_goal_is_not_recreated_on_reopen(tmp_path):
    path = tmp_path / "world.db"
    with WorldModel(path) as world:
        reservation = _reserve(world)
        with world._writing() as connection:
            connection.execute("DELETE FROM goal_origins WHERE goal_id=?", (reservation.goal_id,))
            connection.execute("DELETE FROM goals WHERE id=?", (reservation.goal_id,))
    with WorldModel(path) as reopened:
        repeated = _reserve(reopened)
        assert repeated.goal_id == reservation.goal_id
        assert reopened.list_goals() == []
        admission.acknowledge(reopened, repeated)
        assert not admission.claim(reopened, repeated)


def test_native_conversation_erasure_retains_no_recreation_receipt(tmp_path):
    path = tmp_path / "world.db"
    with WorldModel(path) as world:
        reservation = _reserve(world)
        conversation = world.get_or_create_conversation("synthetic", "federation:peer-a")
        world.append_turn(conversation.id, "user", "erase this synthetic conversation", reservation.goal_id)
        world.erase_conversations([conversation.id])
        assert world.get_goal(reservation.goal_id) is None
    with WorldModel(path) as world:
        repeated = _reserve(world)
        assert repeated.goal_id == reservation.goal_id
        assert world.list_goals() == []
        assert "title" not in repeated.contract and "description" not in repeated.contract


def test_world_cannot_be_reused_under_different_tenant(tmp_path):
    with tenant_scope(tenant="alpha"), WorldModel(tmp_path / "world.db") as world:
        reservation = _reserve(world)
        with tenant_scope(tenant="beta"):
            with pytest.raises(ValueError, match="different tenant"):
                _reserve(world)
            with pytest.raises(admission.FederationAdmissionRequired, match="tenant mismatch"):
                with admission.execution_scope(reservation):
                    pytest.fail("cross-tenant permit was issued")


def test_two_independent_world_connections_claim_once(tmp_path):
    path = tmp_path / "world.db"
    with WorldModel(path) as world:
        reservation = _ready(world)

    def claim_once(_):
        with WorldModel(path) as contender:
            return admission.claim(contender, reservation)

    with ThreadPoolExecutor(max_workers=2) as pool:
        claimed = list(pool.map(claim_once, range(2)))
    assert sorted(claimed) == [False, True]


@pytest.mark.parametrize("dollars,seconds", [(None, 30), (3, 30), (2.5, None), (2.5, 31)])
def test_pinned_budget_cannot_be_widened_by_dispatcher(tmp_path, dollars, seconds):
    with WorldModel(tmp_path / "world.db") as world:
        reservation = _ready(world)
        assert admission.claim(world, reservation)
        with admission.execution_scope(reservation), pytest.raises(admission.FederationAdmissionRequired):
            admission.require_execution(world, reservation.goal_id, max_dollars=dollars,
                                        max_wall_seconds=seconds, consume=True)
        assert admission.state(world, reservation) == admission.DISPATCHING


@pytest.mark.parametrize("receipt_state", [admission.HELD, admission.READY,
                                          admission.DISPATCHING, admission.RUNNING])
@pytest.mark.parametrize("entry", ["runner", "orchestrator", "best_of_n", "grpc"])
def test_requeued_goal_cannot_bypass_receipt_at_public_entries(tmp_path, monkeypatch,
                                                            receipt_state, entry):
    from maverick import llm as llm_module
    from maverick import orchestrator, runner, trace_pin, world_model
    from maverick import sandbox as sandbox_module
    from maverick.budget import Budget

    path = tmp_path / "world.db"
    called = []
    with WorldModel(path) as world:
        reservation = _reserve(world)
        if receipt_state != admission.HELD:
            admission.acknowledge(world, reservation)
        if receipt_state in {admission.DISPATCHING, admission.RUNNING}:
            assert admission.claim(world, reservation)
        if receipt_state == admission.RUNNING:
            _consume(world, reservation)
        world.set_goal_status(reservation.goal_id, "cancelled")
        ChatThreads(world).resume(reservation.goal_id)
        before = world.get_goal(reservation.goal_id)

        async def accounted(*args, **kwargs):
            called.append("provider-work")
            return "unexpected execution"

        monkeypatch.setattr(orchestrator, "_run_goal_accounted", accounted)
        monkeypatch.setattr(orchestrator, "_reset_workdir_to_head", lambda *args: called.append("reset"))
        monkeypatch.setattr(world_model, "open_world", lambda **kwargs: WorldModel(path))
        monkeypatch.setattr(llm_module, "LLM", lambda: called.append("llm"))
        monkeypatch.setattr(sandbox_module, "build_sandbox", lambda: called.append("sandbox"))
        monkeypatch.setattr(trace_pin, "pin_trace", lambda *args: called.append("trace"))
        budget = Budget(max_dollars=2.5, max_wall_seconds=30)
        if entry == "runner":
            assert runner.run_goal_in_thread(reservation.goal_id, max_dollars=2.5,
                                            max_wall_seconds=30, user_id="federation:peer-a") == "blocked"
        elif entry == "orchestrator":
            result = orchestrator.run_goal_sync(None, world, budget, reservation.goal_id,
                                                user_id="federation:peer-a")
            assert result.startswith("BLOCKED:")
        elif entry == "best_of_n":
            result = asyncio.run(orchestrator.run_goal_best_of_n(None, world, budget,
                                                                reservation.goal_id, n=2))
            assert result.startswith("BLOCKED:")
        else:
            service = GoalService(world_factory=lambda: WorldModel(path),
                                  dispatch=lambda *args, **kwargs: called.append("dispatch"))
            assert service.run_goal(reservation.goal_id, user_id="federation:peer-a",
                                    max_dollars=2.5, max_wall_seconds=30) is None
        assert called == []
        assert world.get_goal(reservation.goal_id) == before
        assert world.goal_events(reservation.goal_id) == []
        assert world.list_episodes(goal_id=reservation.goal_id) == []
        assert admission.state(world, reservation) == receipt_state


def _accept(service, record):
    return service.accept_federation(peer="peer-a", correlation="original-correlation",
                                     digest="a" * 64, title="Synthetic held delegation",
                                     description="Do not run before audit", capability=None,
                                     max_dollars=2.5, max_wall_seconds=30, record=record)


@pytest.mark.parametrize("failure", ["write_refusal", "off_host_refusal", "ordinary", "false", "none"])
def test_acceptance_failure_then_same_receipt_recovery_runs_once(tmp_path, failure):
    from maverick.audit.signing import OffHostSigningRequiredError
    from maverick.audit.writer import AuditWriteRefused

    path = tmp_path / "world.db"
    calls, audit_attempts = [], []

    def dispatch(goal_id, **kwargs):
        with WorldModel(path) as world:
            admission.require_execution(world, goal_id, capability=kwargs["capability"],
                                        max_dollars=kwargs["max_dollars"],
                                        max_wall_seconds=kwargs["max_wall_seconds"], consume=True)
            calls.append(goal_id)
            world.set_goal_status(goal_id, "done", "synthetic local effect completed")

    def first_record(kind, **kwargs):
        audit_attempts.append(kwargs)
        if failure == "write_refusal":
            raise AuditWriteRefused("synthetic refusal")
        if failure == "off_host_refusal":
            raise OffHostSigningRequiredError("synthetic refusal")
        if failure == "ordinary":
            raise OSError("synthetic writer failure")
        return False if failure == "false" else None

    def recovered_record(kind, **kwargs):
        audit_attempts.append(kwargs)
        return True

    service = GoalService(world_factory=lambda: WorldModel(path), dispatch=dispatch,
                          spawn=lambda function: function())
    first = _accept(service, first_record)
    assert first["outcome_state"] == "pending"
    assert first["execution_state"] == "held"
    assert calls == []
    with WorldModel(path) as world:
        assert len(world.list_goals()) == 1
        assert world.get_goal(first["goal_id"]).status == "federation_held"
    # New service and world instances exercise durable pending state, not a local cache.
    restarted = GoalService(world_factory=lambda: WorldModel(path), dispatch=dispatch,
                            spawn=lambda function: function())
    retry = _accept(restarted, recovered_record)
    again = _accept(restarted, recovered_record)
    assert retry["accepted"] and again["accepted"]
    assert first["goal_id"] == retry["goal_id"] == again["goal_id"]
    assert calls == [first["goal_id"]]
    assert len(audit_attempts) == 2
    assert audit_attempts[0] == audit_attempts[1]
    with WorldModel(path) as world:
        assert len(world.list_goals()) == 1
        assert world.get_goal(first["goal_id"]).status == "done"


def test_native_thread_spawner_preserves_tenant_and_dispatch_permit(tmp_path):
    from maverick.paths import current_tenant_id_strict

    path = tmp_path / "world.db"
    finished = threading.Event()
    results = []

    def dispatch(goal_id, **kwargs):
        try:
            with WorldModel(path) as world:
                admission.require_execution(world, goal_id, capability=kwargs["capability"],
                                            max_dollars=kwargs["max_dollars"],
                                            max_wall_seconds=kwargs["max_wall_seconds"], consume=True)
                results.append((current_tenant_id_strict(), goal_id))
                world.set_goal_status(goal_id, "done", "synthetic thread completed")
        except Exception as exc:
            results.append(exc)
        finally:
            finished.set()

    with tenant_scope(tenant="thread-tenant"):
        service = GoalService(world_factory=lambda: WorldModel(path), dispatch=dispatch)
        reply = _accept(service, lambda *args, **kwargs: True)
    assert finished.wait(5), "native dispatch thread did not complete"
    assert results == [("thread-tenant", reply["goal_id"])]


def test_two_services_race_one_native_audit_receipt_and_effect(tmp_path):
    from maverick.audit import audit_event
    from maverick.paths import data_dir

    path = tmp_path / "world.db"
    effects = []
    barrier = threading.Barrier(2)
    with WorldModel(path):
        pass

    def dispatch(goal_id, **kwargs):
        with WorldModel(path) as world:
            admission.require_execution(world, goal_id, capability=kwargs["capability"],
                                        max_dollars=kwargs["max_dollars"],
                                        max_wall_seconds=kwargs["max_wall_seconds"], consume=True)
            effects.append(goal_id)
            world.set_goal_status(goal_id, "done", "one local effect")

    def accept(_):
        service = GoalService(world_factory=lambda: WorldModel(path), dispatch=dispatch,
                              spawn=lambda function: function())
        barrier.wait(timeout=5)
        return _accept(service, audit_event)

    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(pool.map(accept, range(2)))
    assert all(reply["accepted"] for reply in replies)
    assert len(effects) == 1 and {reply["goal_id"] for reply in replies} == set(effects)
    rows = [json.loads(line) for path in data_dir("audit").glob("*.ndjson")
            for line in path.read_text(encoding="utf-8").splitlines()]
    receipts = [row for row in rows if row.get("kind") == "federation_delegate"
                and row.get("direction") == "received"]
    assert len(receipts) == 1


def test_native_federation_client_reports_pending_then_same_goal_acceptance(tmp_path):
    from maverick.audit import audit_event
    from maverick.audit.writer import AuditWriteRefused
    from maverick.federation import FederationNode, FederationService, Peer

    path = tmp_path / "world.db"
    effects, sender_events = [], []
    healthy = False

    def received(kind, **kwargs):
        if not healthy:
            raise AuditWriteRefused("synthetic acceptance sink refusal")
        return audit_event(kind, **kwargs)

    def dispatch(goal_id, **kwargs):
        with WorldModel(path) as world:
            admission.require_execution(world, goal_id, capability=kwargs["capability"],
                                        max_dollars=kwargs["max_dollars"],
                                        max_wall_seconds=kwargs["max_wall_seconds"], consume=True)
            effects.append(goal_id)
            world.set_goal_status(goal_id, "done", "native federation test effect")

    def sent(kind, **kwargs):
        sender_events.append(kwargs)
        return audit_event(kind, **kwargs)

    receiver = FederationService(node="receiver", peers=[Peer("sender", "unused:1", "token")],
                                 local_grant=None, record=received,
                                 goal_service=GoalService(world_factory=lambda: WorldModel(path),
                                                          dispatch=dispatch, spawn=lambda fn: fn()))
    sender = FederationNode(node="sender", peers=[Peer("receiver", "unused:2", "token")],
                            transport_factory=lambda peer: receiver, record=sent)
    first = sender.delegate("receiver", "Synthetic API work", correlation_id="api-correlation")
    assert first.outcome_state == "pending" and first.goal_id is not None
    assert first.execution_state == "held" and effects == []
    assert sender_events[-1]["accepted"] is None
    healthy = True
    second = sender.delegate("receiver", "Synthetic API work", correlation_id="api-correlation")
    third = sender.delegate("receiver", "Synthetic API work", correlation_id="api-correlation")
    assert second.accepted and third.accepted
    assert first.goal_id == second.goal_id == third.goal_id
    assert effects == [first.goal_id]


@pytest.mark.parametrize("phase", [admission.HELD, admission.READY])
@pytest.mark.parametrize("tightening", ["capability", "dollars", "wall_seconds"])
def test_full_service_retry_cannot_restore_authority_above_current_policy(
    tmp_path, monkeypatch, phase, tightening,
):
    from maverick import runner
    from maverick.audit import audit_event
    from maverick.federation import FederationService, Peer

    path = tmp_path / "world.db"
    policy = {"dollars": 10.0, "wall_seconds": 60.0}
    monkeypatch.setattr(runner, "configured_max_dollars", lambda: policy["dollars"])
    monkeypatch.setattr(runner, "configured_max_wall_seconds", lambda: policy["wall_seconds"])
    effects, audit_attempts = [], []
    healthy = phase == admission.READY

    def record(kind, **kwargs):
        audit_attempts.append(kwargs)
        return audit_event(kind, **kwargs) if healthy else False

    service = FederationService(
        node="receiver", peers=[Peer("sender", "unused:1", "token")], local_grant=None,
        record=record, goal_service=GoalService(world_factory=lambda: WorldModel(path),
                                               dispatch=lambda *args, **kwargs: effects.append(args),
                                               spawn=lambda fn: fn()),
    )
    payload = {"auth_token": "token", "correlation_id": "policy-retry",
               "goal_title": "Synthetic unrestricted reservation", "requested_tools": [],
               "deadline_ms": 50000}
    # READY models an acknowledged receipt before its dispatch claim. Keep that
    # boundary reachable without constructing a receipt by hand.
    with monkeypatch.context() as checkpoint:
        if phase == admission.READY:
            checkpoint.setattr(admission, "claim", lambda *args: False)
        first = service.delegate_goal(payload)
    assert first["goal_id"] > 0 and effects == []
    with WorldModel(path) as world:
        before = tuple(world._read_one(
            "SELECT goal_id,delivery_state,request_digest,sealed_contract FROM event_goal_admissions"))
        assert before[1] == phase
    healthy = True
    if tightening == "capability":
        service._grant = Capability(principal="federation:sender", allow_tools=frozenset({"read_file"}))
    elif tightening == "dollars":
        policy["dollars"] = 1.0
    else:
        policy["wall_seconds"] = 5.0
    retry = service.delegate_goal(dict(payload))
    assert retry["goal_id"] == first["goal_id"]
    assert retry["execution_state"] == "held"
    assert "current policy" in retry["reason"]
    assert effects == [] and len(audit_attempts) == 1
    with WorldModel(path) as world:
        after = tuple(world._read_one(
            "SELECT goal_id,delivery_state,request_digest,sealed_contract FROM event_goal_admissions"))
        assert after == before
        assert len(world.list_goals()) == 1


def _crash_worker(stage, path, output):
    """Child process with real stores/writer, deterministic local effect only."""
    from maverick.audit import audit_event
    from maverick.paths import data_dir

    effects = path.with_suffix(".effects")
    original_acknowledge = admission.acknowledge

    def acknowledge(world, reservation):
        original_acknowledge(world, reservation)
        if stage == "after_ack":
            os._exit(71)

    admission.acknowledge = acknowledge

    def record(kind, **kwargs):
        if stage == "before_audit":
            os._exit(71)
        assert audit_event(kind, **kwargs) is True
        if stage == "after_audit":
            os._exit(71)
        return True

    def dispatch(goal_id, **kwargs):
        with WorldModel(path) as world:
            admission.require_execution(world, goal_id, capability=kwargs["capability"],
                                        max_dollars=kwargs["max_dollars"],
                                        max_wall_seconds=kwargs["max_wall_seconds"], consume=True)
            with effects.open("a", encoding="utf-8") as effect:
                effect.write(str(goal_id) + "\n")
                effect.flush()
                os.fsync(effect.fileno())
            if stage == "after_effect":
                os._exit(71)
            world.set_goal_status(goal_id, "done", "local effect persisted")

    def spawn(function):
        if stage == "after_claim":
            os._exit(71)
        function()

    service = GoalService(world_factory=lambda: WorldModel(path), dispatch=dispatch, spawn=spawn)
    reply = _accept(service, record)
    with WorldModel(path) as world:
        goals = world.list_goals()
        states = [row[0] for row in world._read_all(
            "SELECT delivery_state FROM event_goal_admissions WHERE admission_key LIKE 'federation:%'")]
    rows = []
    for audit_path in data_dir("audit").glob("*.ndjson"):
        rows.extend(json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines())
    receipts = [row for row in rows if row.get("kind") == "federation_delegate"
                and row.get("direction") == "received"]
    output.write_text(json.dumps({"pid": os.getpid(), "reply": reply, "states": states,
                                  "goals": [{"id": goal.id, "status": goal.status} for goal in goals],
                                  "audit_rows": len(receipts),
                                  "effect_ids": effects.read_text().splitlines() if effects.exists() else []}),
                      encoding="utf-8")


@pytest.mark.parametrize("stage,expected_effects,expected_state", [
    ("before_audit", 1, admission.RUNNING),
    ("after_audit", 1, admission.RUNNING),
    ("after_ack", 1, admission.RUNNING),
    ("after_claim", 0, admission.DISPATCHING),
    ("after_effect", 1, admission.RUNNING),
])
def test_process_crash_recovery_never_repeats_effects(tmp_path, stage, expected_effects, expected_state):
    path = tmp_path / "crash-world.db"
    output = tmp_path / "recovered.json"
    crashed = subprocess.run([sys.executable, __file__, "--crash-worker", stage, str(path), str(output)],
                             capture_output=True, text=True, timeout=30)
    assert crashed.returncode == 71, crashed.stdout + crashed.stderr
    recovered = subprocess.run([sys.executable, __file__, "--crash-worker", "recover", str(path), str(output)],
                               capture_output=True, text=True, timeout=30)
    assert recovered.returncode == 0, recovered.stdout + recovered.stderr
    first = json.loads(output.read_text(encoding="utf-8"))
    assert len(first["effect_ids"]) == expected_effects
    assert first["states"] == [expected_state]
    assert first["audit_rows"] == 1  # Includes append-before-ack crash deduplication.
    assert len(first["goals"]) == 1 and first["reply"]["goal_id"] == first["goals"][0]["id"]
    if stage in {"after_claim", "after_effect"}:
        assert first["reply"]["execution_state"] == "unknown"
    repeated = subprocess.run([sys.executable, __file__, "--crash-worker", "recover", str(path), str(output)],
                              capture_output=True, text=True, timeout=30)
    assert repeated.returncode == 0, repeated.stdout + repeated.stderr
    second = json.loads(output.read_text(encoding="utf-8"))
    assert second["pid"] != first["pid"]
    assert second["effect_ids"] == first["effect_ids"]
    assert second["audit_rows"] == 1
    assert second["goals"] == first["goals"]


if __name__ == "__main__":
    assert sys.argv[1] == "--crash-worker"
    _crash_worker(sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4]))
