"""Approval decisions and their signed audit authority are one durable flow."""
from __future__ import annotations

import contextlib
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

_ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture
def approval_env(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import api

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    api._world_cache.clear()
    yield api, tmp_path
    api._world_cache.clear()


def _client():
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1")


def _create_structured_approval(
    world,
    action: str,
    *,
    risk: str,
    approvals_required: int = 1,
) -> tuple[int, dict[str, str]]:
    from maverick.approval_cards import build_approval_card, encode_approval_detail

    card = build_approval_card(
        action=action,
        summary="Review the exact queued operation",
        target_label="Customer operation",
        target={"action": action},
        parameters={"risk": risk},
        parameter_summary=["Apply the reviewed operation once"],
        actor="u:requester",
        workspace="tenant-a",
        role="operator",
        authority_versions={"role_revision": "role-v1"},
        input_versions={"request_revision": "request-v1"},
        credential_versions={},
        budget={},
        expires_at=time.time() + 300,
        known_effects=["The reviewed operation can take effect."],
        unresolved_assumptions=[],
        before="The operation is awaiting review.",
        after="The reviewed operation may proceed.",
        irreversible=risk == "critical",
    )
    approval_id = world.create_approval(
        action,
        risk=risk,
        detail=encode_approval_detail(card),
        approvals_required=approvals_required,
    )
    return approval_id, {
        **_ORIGIN,
        "X-Lightwork-Approval-Binding": card["binding_sha256"],
    }


def test_openapi_documents_pending_and_uncertain_decision_outcomes(
    approval_env,
):
    _api, _ = approval_env
    schema = _client().get("/openapi.json").json()
    for action in ("approve", "deny"):
        responses = schema["paths"][
            f"/api/v1/approvals/{{approval_id}}/{action}"
        ]["post"]["responses"]
        assert {"202", "204", "409", "503"} <= set(responses)
        assert "non-effective" in responses["202"]["description"]
        assert "retrying" in responses["503"]["description"]


def test_audit_refusal_keeps_final_decision_non_effective_and_retry_is_safe(
    approval_env,
    monkeypatch,
):
    api, _ = approval_env
    world = api._world()
    approval_id, headers = _create_structured_approval(
        world, "wire-funds", risk="critical",
    )

    import maverick.audit as audit
    from maverick.audit import AuditRefused

    attempts: list[str] = []

    def refuse(_kind, **payload):
        attempts.append(payload["approval_event_id"])
        raise AuditRefused("off-host signer unavailable")

    monkeypatch.setattr(audit, "record", refuse)
    first = _client().post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers=headers,
    )

    assert first.status_code == 202
    body = first.json()
    assert body == {
        "decision": "accepted",
        "decision_id": body["decision_id"],
        "audit": "pending",
        "approval_status": "pending",
        "effective": False,
        "retry_safe": True,
    }
    assert first.headers["x-lightwork-approval-audit"] == "pending"
    assert world.get_approval(approval_id).status == "pending"
    pending = world.pending_approval_audit_events(approval_id=approval_id)
    assert len(pending) == 1
    assert pending[0].event_id == body["decision_id"]
    assert pending[0].delivered_at is None

    delivered: list[str] = []

    def accept(_kind, **payload):
        delivered.append(payload["approval_event_id"])
        return True

    monkeypatch.setattr(audit, "record", accept)
    retry = _client().post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers=headers,
    )

    assert retry.status_code == 204
    assert retry.headers["x-lightwork-decision-id"] == body["decision_id"]
    assert retry.headers["x-lightwork-approval-audit"] == "delivered"
    assert world.get_approval(approval_id).status == "approved"
    assert world.pending_approval_audit_events(approval_id=approval_id) == []
    assert attempts == [body["decision_id"]]
    assert delivered == [body["decision_id"]]


def test_transient_false_audit_result_is_retried_without_a_second_vote(
    approval_env,
    monkeypatch,
):
    api, _ = approval_env
    world = api._world()
    approval_id = world.create_approval("publish", risk="high")

    import maverick.audit as audit

    outcomes = iter([False, True])
    event_ids: list[str] = []

    def record(_kind, **payload):
        event_ids.append(payload["approval_event_id"])
        return next(outcomes)

    monkeypatch.setattr(audit, "record", record)
    first = _client().post(
        f"/api/v1/approvals/{approval_id}/deny",
        headers=_ORIGIN,
    )
    second = _client().post(
        f"/api/v1/approvals/{approval_id}/deny",
        headers=_ORIGIN,
    )

    assert first.status_code == 202
    assert second.status_code == 204
    assert event_ids == [first.json()["decision_id"]] * 2
    assert world.get_approval(approval_id).status == "denied"
    with world._writing() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM approval_audit_outbox "
            "WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()[0] == 1


def test_later_quorum_vote_repairs_older_audit_event_before_becoming_effective(
    approval_env,
    monkeypatch,
):
    api, _ = approval_env
    world = api._world()
    approval_id, headers = _create_structured_approval(
        world,
        "wire-funds",
        risk="critical",
        approvals_required=2,
    )
    monkeypatch.setattr(api, "_supervisor", lambda _request: "u:alice")

    import maverick.audit as audit

    delivered: list[str] = []
    healthy = False

    def record(_kind, **payload):
        delivered.append(payload["approval_event_id"])
        return healthy

    monkeypatch.setattr(audit, "record", record)
    first = _client().post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers=headers,
    )
    assert first.status_code == 202
    first_id = first.json()["decision_id"]

    healthy = True
    monkeypatch.setattr(api, "_supervisor", lambda _request: "u:bob")
    second = _client().post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers=headers,
    )

    assert second.status_code == 204
    assert world.get_approval(approval_id).status == "approved"
    # Alice's failed row is retried first, then Bob's quorum row. The failed
    # attempt and successful retry share one stable identity.
    assert delivered[0] == delivered[1] == first_id
    assert delivered[2] == second.headers["x-lightwork-decision-id"]
    assert world.pending_approval_audit_events(approval_id=approval_id) == []


def test_lost_commit_ack_is_reconciled_from_outbox_before_response(
    approval_env,
    monkeypatch,
):
    api, _ = approval_env
    world = api._world()
    approval_id, headers = _create_structured_approval(
        world, "deploy", risk="high",
    )

    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_a, **_k: True)
    original_writing = world._writing
    raise_after_commit = True

    @contextlib.contextmanager
    def uncertain_commit():
        nonlocal raise_after_commit
        with original_writing() as conn:
            yield conn
        if raise_after_commit:
            raise_after_commit = False
            raise RuntimeError("commit acknowledgement lost")

    monkeypatch.setattr(world, "_writing", uncertain_commit)
    response = _client().post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers=headers,
    )

    assert response.status_code == 204
    assert world.get_approval(approval_id).status == "approved"
    assert world.get_approval_audit_event(
        response.headers["x-lightwork-decision-id"]
    ).delivered_at is not None


def test_postcommit_state_read_failure_does_not_turn_success_into_retry(
    approval_env,
    monkeypatch,
):
    api, _ = approval_env
    world = api._world()
    approval_id, headers = _create_structured_approval(
        world, "deploy", risk="high",
    )

    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_a, **_k: True)
    monkeypatch.setattr(
        world,
        "approval_state",
        lambda _approval_id: (_ for _ in ()).throw(
            RuntimeError("read replica unavailable")
        ),
    )
    response = _client().post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers=headers,
    )

    assert response.status_code == 204
    assert response.headers["x-lightwork-approval-state"] == "approved"
    assert world.get_approval(approval_id).status == "approved"


def test_unreconcilable_commit_outcome_is_explicit_and_retry_keyed():
    from maverick_dashboard import api

    class UnavailableWorld:
        @staticmethod
        def get_approval(approval_id):
            # The request someone else asked for: the separate-approver check
            # before the vote has nothing to refuse.
            return SimpleNamespace(id=approval_id, status="pending", risk="high",
                                   approvals_required=1, requested_by="u:bob")

        @staticmethod
        def approval_audit_event_id(*_args):
            return "approval-v1-stable"

        @staticmethod
        def decide_approval_audited(*_args, **_kwargs):
            raise RuntimeError("commit result unavailable")

        @staticmethod
        def get_approval_audit_event(_event_id):
            raise RuntimeError("read replica unavailable")

    with pytest.raises(HTTPException) as caught:
        api._record_vote_or_raise(
            UnavailableWorld(),
            7,
            "approved",
            "u:alice",
        )

    exc = caught.value
    assert exc.status_code == 503
    assert exc.detail == {
        "decision": "outcome_uncertain",
        "decision_id": "approval-v1-stable",
        "retry_safe": True,
    }
    assert exc.headers["X-Lightwork-Decision-Id"] == "approval-v1-stable"
    assert exc.headers["X-Lightwork-Approval-State"] == "uncertain"


def test_duplicate_submits_converge_on_one_outbox_event(tmp_path):
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    approval_id = world.create_approval("ship", risk="high")
    barrier = Barrier(8)

    def submit():
        barrier.wait()
        return world.decide_approval_audited(
            approval_id,
            "approved",
            decided_by="u:alice",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        events = list(pool.map(lambda _i: submit(), range(8)))

    assert all(event is not None for event in events)
    assert len({event.event_id for event in events}) == 1
    assert world.get_approval(approval_id).status == "pending"
    assert len(world.pending_approval_audit_events(approval_id=approval_id)) == 1
    assert world.mark_approval_audit_delivered(events[0].event_id)
    assert world.get_approval(approval_id).status == "approved"


def test_competing_cross_connection_final_decisions_accept_exactly_one(tmp_path):
    from maverick.world_model import WorldModel

    path = tmp_path / "world.db"
    creator = WorldModel(path)
    approval_id = creator.create_approval("irreversible", risk="critical")
    left = WorldModel(path)
    right = WorldModel(path)
    barrier = Barrier(2)

    def vote(world, status, actor):
        barrier.wait()
        return world.decide_approval_audited(
            approval_id,
            status,
            decided_by=actor,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(vote, left, "approved", "u:alice")
        b = pool.submit(vote, right, "denied", "u:bob")
        events = [a.result(), b.result()]

    accepted = [event for event in events if event is not None]
    assert len(accepted) == 1
    assert len(creator.pending_approval_audit_events(approval_id=approval_id)) == 1
    assert creator.mark_approval_audit_delivered(accepted[0].event_id)
    assert creator.get_approval(approval_id).status == accepted[0].status
    left.close()
    right.close()
    creator.close()


def test_decision_id_and_retry_survive_world_reopen(tmp_path):
    from maverick.world_model import WorldModel

    path = tmp_path / "world.db"
    first = WorldModel(path)
    approval_id = first.create_approval("restart-safe", risk="high")
    event = first.decide_approval_audited(
        approval_id,
        "approved",
        decided_by="u:alice",
    )
    first.close()

    second = WorldModel(path)
    assert second.approval_audit_event_id(
        approval_id,
        "approved",
        "u:alice",
    ) == event.event_id
    replay = second.decide_approval_audited(
        approval_id,
        "approved",
        decided_by="u:alice",
    )
    assert replay.event_id == event.event_id
    assert len(second.pending_approval_audit_events(approval_id=approval_id)) == 1
    second.close()
