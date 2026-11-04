"""Federation admission uses real storage and dispatch seams, never a model."""
from __future__ import annotations

import asyncio

import pytest
from maverick.budget import Budget
from maverick.capability import Capability
from maverick.federation import FederationNode, FederationService, Peer
from maverick.grpc_api.service import GoalService
from maverick.world_model import WorldModel


@pytest.fixture
def harness(tmp_path):
    path = tmp_path / "world.db"
    calls = []
    accepted = []
    ack = {"value": False}

    def record(kind, **payload):
        accepted.append(payload)
        return ack["value"]

    def dispatch(goal_id, **kwargs):
        calls.append((goal_id, kwargs))

    def service():
        return FederationService(
            node="receiver", peers=[Peer("sender", "localhost:1", "token")],
            local_grant=Capability("federation:sender", allow_tools=frozenset({"read_file"})),
            state_path=tmp_path / "federation.db", record=record,
            goal_service=GoalService(world_factory=lambda: WorldModel(path),
                                     dispatch=dispatch, spawn=lambda fn: fn()),
        )

    payload = {"auth_token": "token", "correlation_id": "stable-retry",
               "goal_title": "Read the delivery report", "requested_tools": ["read_file"],
               "deadline_ms": 5000}
    return path, service, payload, calls, accepted, ack


def test_audit_failure_holds_one_goal_then_restart_releases_same_goal(harness):
    path, service, payload, calls, audit, ack = harness
    first = service().delegate_goal(payload)
    assert calls == []
    assert first["outcome_state"] == "pending"
    assert first["goal_id"] > 0
    ack["value"] = True
    second = service().delegate_goal(payload)
    third = service().delegate_goal(payload)
    assert second["accepted"] is True
    assert second["goal_id"] == third["goal_id"] == first["goal_id"]
    assert len(calls) == 1
    assert calls[0][1]["max_wall_seconds"] == 5.0
    assert calls[0][1]["capability"].allow_tools == frozenset({"read_file"})
    assert audit[0]["event_id"] == audit[-1]["event_id"]
    with WorldModel(path) as world:
        assert len(world.list_goals()) == 1


def test_held_goal_cannot_run_through_public_orchestrator_after_status_repaint(harness):
    from maverick.orchestrator import run_goal
    path, service, payload, calls, _, _ = harness
    reply = service().delegate_goal(payload)
    with WorldModel(path) as world:
        world.set_goal_status(reply["goal_id"], "pending")
        result = asyncio.run(run_goal(
            object(), world, Budget(max_dollars=1), reply["goal_id"],
            user_id="federation:sender",
            capability=Capability("federation:sender", allow_tools=frozenset({"read_file"})),
        ))
        assert "federation" in result.lower() and "BLOCKED" in result
    assert calls == []


def test_changed_payload_reuses_no_work_and_is_conflict(harness):
    _, service, payload, calls, _, _ = harness
    first = service().delegate_goal(payload)
    changed = service().delegate_goal({**payload, "goal_title": "Different job"})
    assert first["goal_id"] > 0
    assert changed["accepted"] is False
    assert "different delegation content" in changed["reason"]
    assert calls == []


def test_transport_failure_is_unknown_instead_of_confirmed_rejection():
    events = []

    class Broken:
        def call(self, method, payload):
            raise TimeoutError("response lost")

    node = FederationNode(node="sender", peers=[Peer("receiver", "localhost:1", "token")],
                          transport_factory=lambda peer: Broken(),
                          record=lambda kind, **payload: events.append(payload))
    result = node.delegate("receiver", "Read report", correlation_id="unknown")
    assert result.outcome_state == "unknown"
    assert events[-1]["accepted"] is None


def test_dispatch_crash_is_not_replayed_and_retains_accepted_authority(harness):
    path, service, payload, calls, _, ack = harness
    ack["value"] = True
    svc = service()

    def failed_spawn(fn):
        raise RuntimeError("process failed at dispatch boundary")

    svc._goals()._spawn = failed_spawn
    first = svc.delegate_goal(payload)
    second = service().delegate_goal(payload)
    assert first["accepted"] is second["accepted"] is True
    assert second["goal_id"] == first["goal_id"]
    assert second["execution_state"] == "unknown"
    assert calls == []


def test_native_pg_held_contract_reopens_and_claims_once(postgres_test_dsn):
    from maverick import federation_admission as admission
    from maverick.crypto_at_rest import at_rest_enabled, is_sealed_str
    from maverick.paths import tenant_scope
    from maverick.world_model_backends.postgres import PostgresWorldModel
    kwargs = dict(peer="sender", correlation="pg-correlation", digest="a" * 64,
                  title="Read report", description="", capability=None,
                  max_dollars=2, max_wall_seconds=10)
    with tenant_scope(tenant="alpha"), PostgresWorldModel(postgres_test_dsn) as world:
        first = admission.reserve(world, **kwargs)
        assert world.get_goal(first.goal_id).status == "federation_held"
        with world._tx() as cursor:
            cursor.execute("SELECT sealed_contract FROM event_goal_admissions WHERE tenant_id=%s AND admission_key=%s",
                           ("alpha", first.key))
            raw_contract = cursor.fetchone()[0]
        assert is_sealed_str(raw_contract) is at_rest_enabled()
        if at_rest_enabled():
            assert "pg-correlation" not in raw_contract
    with tenant_scope(tenant="alpha"), PostgresWorldModel(postgres_test_dsn) as world:
        second = admission.reserve(world, **kwargs)
        assert first == second
        admission.acknowledge(world, second)
        assert admission.claim(world, second)
        assert not admission.claim(world, second)
        with admission.execution_scope(second):
            admission.require_execution(world, second.goal_id, max_dollars=2, max_wall_seconds=10, consume=True)
        assert admission.state(world, second) == admission.RUNNING
    with tenant_scope(tenant="beta"), PostgresWorldModel(postgres_test_dsn) as world:
        third = admission.reserve(world, **kwargs)
        assert third.goal_id != first.goal_id
        assert world.get_goal(first.goal_id) is None


def test_native_pg_failed_receipt_rolls_back_goal(postgres_test_dsn):
    import psycopg
    from maverick import federation_admission as admission
    from maverick.world_model_backends.postgres import PostgresWorldModel
    with PostgresWorldModel(postgres_test_dsn) as world:
        with psycopg.connect(postgres_test_dsn) as connection:
            connection.execute("ALTER TABLE event_goal_admissions ADD CONSTRAINT synthetic_hold_fail CHECK(goal_id<0)")
        with pytest.raises(psycopg.errors.CheckViolation):
            admission.reserve(world, peer="sender", correlation="rollback", digest="a" * 64,
                              title="Read report", description="", capability=None,
                              max_dollars=2, max_wall_seconds=10)
        assert world.list_goals() == []


def test_native_pg_capacity_race_never_overadmits(postgres_test_dsn, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    from maverick import federation
    from maverick import federation_admission as admission
    from maverick.paths import tenant_scope
    from maverick.world_model_backends.postgres import PostgresWorldModel
    monkeypatch.setattr(federation, "_CORRELATION_CACHE_MAX", 1)
    with PostgresWorldModel(postgres_test_dsn):
        pass

    def attempt(number):
        with tenant_scope(tenant="alpha"), PostgresWorldModel(postgres_test_dsn) as world:
            try:
                return admission.reserve(world, peer="sender", correlation=str(number), digest=str(number) * 64,
                                         title="Read report", description="", capability=None,
                                         max_dollars=2, max_wall_seconds=10).goal_id
            except admission.FederationAdmissionRejected:
                return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))
    assert len([result for result in results if result is not None]) == 1
