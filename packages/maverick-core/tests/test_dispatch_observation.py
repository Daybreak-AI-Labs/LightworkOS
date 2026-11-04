"""The dispatch boundary must not confuse admission with completion."""
from __future__ import annotations

import pytest
from maverick.runner import DispatchState, observe_dispatch


@pytest.mark.parametrize(
    ("status", "expected"),
    [("queued", DispatchState.QUEUED), ("done", DispatchState.REPORTED),
     ("blocked", DispatchState.REPORTED), (None, DispatchState.UNKNOWN)],
)
def test_observation_preserves_dispatcher_result(status, expected):
    outcome = observe_dispatch(7, status)
    assert outcome.goal_id == 7
    assert outcome.state is expected
    assert outcome.status == status


def test_indeterminate_submission_does_not_assert_absence_of_effects():
    outcome = observe_dispatch(4, None)
    assert outcome.state is DispatchState.UNKNOWN
    assert outcome.status is None


def test_local_submission_observes_the_existing_execution_result(monkeypatch):
    from maverick import runner

    monkeypatch.setattr(runner, "run_goal_in_thread", lambda **kwargs: "done")
    outcome = runner.LocalThreadDispatcher().submit_observed(12)

    assert outcome.goal_id == 12
    assert outcome.state is DispatchState.REPORTED
    assert outcome.status == "done"
    assert outcome.owner == "local"
    assert outcome.receipt_id is None


def test_queue_submission_preserves_one_authenticated_message_identity():
    from maverick.queue_dispatcher import QueueDispatcher

    submitted = []
    dispatcher = QueueDispatcher(lambda name, payload: submitted.append((name, payload)))
    outcome = dispatcher.submit_observed(12)

    assert len(submitted) == 1
    assert submitted[0][1]["goal_id"] == 12
    assert outcome.state is DispatchState.QUEUED
    assert outcome.status == "queued"
    assert outcome.owner == "queue"
    assert outcome.receipt_id == submitted[0][1]["message_id"]


def test_public_dispatch_observation_does_not_guess_acceptance(monkeypatch):
    from maverick import runner

    class UnknownDispatcher:
        def submit(self, goal_id, **kwargs):
            return None

    monkeypatch.setattr(runner, "_dispatcher", UnknownDispatcher())
    result = runner.start_goal_observed(12)

    assert result.state is DispatchState.UNKNOWN
    assert result.status is None
    assert result.owner == "legacy"
    assert result.receipt_id is None


def test_local_slot_refusal_is_definitive_for_this_invocation(monkeypatch):
    from maverick import runner

    monkeypatch.setattr(
        runner, "run_goal_in_thread",
        lambda **kwargs: runner.GoalRunUnavailable("concurrency_slot"),
    )
    result = runner.LocalThreadDispatcher().submit_observed(12)
    assert result.state is DispatchState.NOT_ACCEPTED
    assert result.reason == "concurrency_slot"
    assert result.status is None


def test_queue_exception_after_acceptance_is_unknown_and_never_retried():
    from maverick.queue_dispatcher import QueueDispatcher

    received = []

    def enqueue(name, payload):
        received.append((name, payload))
        raise TimeoutError("acknowledgement lost")

    result = QueueDispatcher(enqueue).submit_observed(12)
    assert len(received) == 1
    assert result.state is DispatchState.UNKNOWN
    assert result.receipt_id == received[0][1]["message_id"]


def test_queue_preflight_failure_is_known_not_to_have_sent():
    from maverick.queue_dispatcher import QueueDispatcher

    received = []
    result = QueueDispatcher(lambda *args: received.append(args)).submit_observed(
        12, allowed_suites=frozenset({"unknown-suite"}),
    )
    assert result.state is DispatchState.NOT_ACCEPTED
    assert result.reason == "queue_preflight"
    assert received == []


def test_grpc_failure_before_rpc_is_definitive_but_timeout_is_unknown():
    from types import SimpleNamespace

    from maverick.grpc_dispatcher import GrpcDispatcher

    def no_stub():
        raise RuntimeError("no channel")

    result = GrpcDispatcher("localhost:1234", stub_factory=no_stub).submit_observed(12)
    assert result.state is DispatchState.NOT_ACCEPTED

    def call(*args, **kwargs):
        raise TimeoutError("response lost")

    fake_stub = SimpleNamespace(RunGoal=call)
    fake_pb2 = SimpleNamespace(RunGoalRequest=lambda **kwargs: kwargs)
    result = GrpcDispatcher("localhost:1234", stub_factory=lambda: (fake_stub, fake_pb2)).submit_observed(12)
    assert result.state is DispatchState.UNKNOWN


@pytest.mark.asyncio
async def test_async_observation_keeps_queue_receipt_after_lost_ack(monkeypatch):
    from maverick import runner
    from maverick.queue_dispatcher import QueueDispatcher

    received = []
    def enqueue(name, payload):
        received.append(payload)
        raise TimeoutError("acknowledgement lost")

    monkeypatch.setattr(runner, "_dispatcher", QueueDispatcher(enqueue))
    result = await runner.start_goal_observed_async(12)
    assert result.state is DispatchState.UNKNOWN
    assert result.receipt_id == received[0]["message_id"]
    assert len(received) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("state", "status"),
    [(DispatchState.UNKNOWN, "queued"),
     (DispatchState.UNKNOWN, "done"),
     (DispatchState.NOT_ACCEPTED, "done"),
     (DispatchState.QUEUED, "done"),
     ("queued", "queued")],
)
async def test_contradictory_adapter_observation_remains_unknown(monkeypatch, state, status):
    from maverick import runner

    class BadAdapter:
        def submit_observed(self, goal_id, **kwargs):
            return runner.DispatchObservation(goal_id, state, status)

    monkeypatch.setattr(runner, "_dispatcher", BadAdapter())
    result = await runner.start_goal_observed_async(12)
    assert result.state is DispatchState.UNKNOWN
    assert result.status == "error"
    assert result.reason == "dispatch_exception"
