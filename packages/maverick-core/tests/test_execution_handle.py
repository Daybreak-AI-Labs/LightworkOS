"""Submission handles must not claim ownership or duplicate effects."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest
from maverick import paths, runner
from maverick.grpc_dispatcher import GrpcDispatcher
from maverick.queue_dispatcher import QueueDispatcher


def test_queue_handle_retains_receipt_without_issuing_control_requests():
    submitted = []
    handle = QueueDispatcher(lambda name, payload: submitted.append(payload)).submit_handle(17)

    assert len(submitted) == 1
    assert handle.goal_id == 17
    assert handle.owner == "queue"
    assert handle.receipt_id == submitted[0]["message_id"]
    assert handle.observation.state is runner.DispatchState.QUEUED
    assert handle.cancel() == runner.ExecutionControlResult("cancel")
    assert handle.settle() == runner.ExecutionControlResult("settle")
    assert len(submitted) == 1
    with pytest.raises(FrozenInstanceError):
        handle.observation = runner.observe_dispatch(17, "done")


def test_unknown_queue_handle_preserves_receipt_and_does_not_resubmit():
    submitted = []

    def enqueue(name, payload):
        submitted.append(payload)
        raise TimeoutError("acknowledgement lost")

    handle = QueueDispatcher(enqueue).submit_handle(17)
    assert handle.observation.state is runner.DispatchState.UNKNOWN
    assert handle.receipt_id == submitted[0]["message_id"]
    assert handle.cancel().outcome == "unsupported"
    assert handle.settle().performed is False
    assert len(submitted) == 1


def test_grpc_handle_does_not_claim_cancellation_or_settlement():
    calls = []

    def run(request, **kwargs):
        calls.append(request)
        return SimpleNamespace(found=True, status="done")

    stub = SimpleNamespace(RunGoal=run)
    pb2 = SimpleNamespace(RunGoalRequest=lambda **kwargs: kwargs)
    handle = GrpcDispatcher("localhost:1234", stub_factory=lambda: (stub, pb2)).submit_handle(17)
    assert handle.owner == "grpc"
    assert handle.receipt_id is None
    assert handle.observation.state is runner.DispatchState.REPORTED
    assert handle.observation.status == "done"
    assert handle.cancel().performed is False
    assert handle.settle().performed is False
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_async_handle_preserves_tenant_context_and_submits_once(monkeypatch):
    tenants = []

    class Adapter:
        def submit_observed(self, goal_id, **kwargs):
            tenants.append(paths.current_tenant_id())
            return runner.DispatchObservation(goal_id, runner.DispatchState.UNKNOWN, None)

    monkeypatch.setattr(runner, "_dispatcher", Adapter())
    token = paths.set_tenant("handle-tenant")
    try:
        handle = await runner.start_goal_handle_async(17)
    finally:
        paths.reset_tenant(token)

    assert tenants == ["handle-tenant"]
    assert handle.observation.state is runner.DispatchState.UNKNOWN
    assert handle.cancel().outcome == "unsupported"
    assert tenants == ["handle-tenant"]


def test_handle_rejects_a_contradictory_observation():
    observation = runner.DispatchObservation(17, runner.DispatchState.UNKNOWN, "done")
    with pytest.raises(ValueError, match="invalid execution observation"):
        observation.as_handle()


def test_sync_handle_keeps_legacy_transport_exception_unknown(monkeypatch):
    calls = []

    class Adapter:
        def submit(self, goal_id, **kwargs):
            calls.append(goal_id)
            raise TimeoutError("acknowledgement lost")

    monkeypatch.setattr(runner, "_dispatcher", Adapter())
    handle = runner.start_goal_handle(17)
    assert handle.observation.state is runner.DispatchState.UNKNOWN
    assert handle.observation.reason == "dispatch_exception"
    assert handle.cancel().performed is False
    assert calls == [17]
