"""Native action episodes with independent PostgreSQL CAS/RLS adapters."""
from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import audit, governed_records
from maverick.flow import store
from maverick.governed_records import (
    GovernedRecordStore,
    PostgresGovernedRecordBackend,
    RecordConflict,
)
from maverick.paths import tenant_scope

from test_support.action_episode_native import (
    ALLOWED,
    TENANT,
    _calls,
    _context,
    _enroll,
    _resume,
    _start,
)
from test_support.action_episode_native import (
    native as native,
)
from test_support.postgres_authority import authority as authority

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"),
                                reason="dedicated Postgres service unavailable")


@pytest.fixture
def pg_episodes(native, authority, monkeypatch):
    from maverick.flow.action_episode_review import ActionEpisodeReviewService

    factory, _, _ = authority
    dsn = factory()._dsn
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", dsn)

    def independent():
        backend = PostgresGovernedRecordBackend(
            "flow_action_episodes", "LAE", dsn=dsn, require_bound_tenant=True,
        )
        records = GovernedRecordStore(
            "flow_action_episodes", "LAE", "flow_action_episode",
            backend=backend, required_backend="postgres",
        )
        return ActionEpisodeReviewService(
            lambda ctx, _cap, flow_id: ctx == _context() and flow_id == "durable-native-actions",
            records=records,
        )

    with tenant_scope(tenant=TENANT):
        source, initial = _start()
        enrolled = _enroll(source, initial)
        middle = _resume(initial.run_id)
        assert middle.status == "paused_approval"
        completed = _resume(initial.run_id)
        assert completed.status == "completed"
        assert [call["tool"] for call in _calls(native)] == ALLOWED
        ready = independent().get(_context(), source.id, completed.run_id, detail=True)
        assert ready["status"] == "awaiting_review"
        yield independent, source, completed, ready, native, enrolled
    governed_records._reset_process_authority_pin_for_testing()


@pytest.mark.parametrize("receipt", [False, 1])
def test_native_pg_review_receipt_recovers_without_repeating_business_actions(pg_episodes, monkeypatch, receipt):
    from maverick.flow.action_episode_review import ActionEpisodeAuditPending

    factory, source, completed, ready, journal, _enrolled = pg_episodes
    before = _calls(journal)
    original = audit.record
    monkeypatch.setattr(audit, "record", lambda *a, **k: receipt)
    pending = factory().review(
        _context(), source.id, completed.run_id, expected_revision=ready["revision"],
        expected_episode_sha256=ready["episode_sha256"], accepted=True,
        rationale="Independent native PostgreSQL review.",
    )
    assert pending["status"] == "audit_pending" and pending["committed_status"] == "accepted"
    assert "episode" not in pending and "review" not in pending
    with pytest.raises(ActionEpisodeAuditPending):
        factory().export(_context(), source.id, completed.run_id)
    monkeypatch.setattr(audit, "record", original)
    recovered = factory().get(_context(), source.id, completed.run_id, detail=True)
    assert recovered["revision"] == pending["revision"]
    assert recovered["status"] == "accepted" and recovered["audit_status"] == "delivered"
    bundle = factory().export(_context(), source.id, completed.run_id)
    assert [step["tool"] for step in bundle["episode"]["steps"]] == ALLOWED
    assert bundle["review"]["authenticated"] is True
    assert _calls(journal) == before
    with tenant_scope(tenant="different-capture-tenant"):
        assert factory().records.get(ready["id"]) is None


def test_native_pg_conflicting_reviews_commit_one_verdict(pg_episodes):
    factory, source, completed, ready, journal, _enrolled = pg_episodes
    barrier = threading.Barrier(2)

    def review(accepted):
        service = factory()
        barrier.wait(timeout=10)
        try:
            return service.review(
                _context(), source.id, completed.run_id, expected_revision=ready["revision"],
                expected_episode_sha256=ready["episode_sha256"], accepted=accepted,
                rationale="Independent concurrent evidence review.",
            )
        except RecordConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(review, [True, False]))
    winners = [result for result in results if result is not None]
    assert len(winners) == 1
    retained = factory().get(_context(), source.id, completed.run_id, detail=True)
    assert retained["revision"] == ready["revision"] + 1
    assert retained["status"] == winners[0]["status"]
    assert len(_calls(journal)) == 2
    assert store.load_run(completed.run_id).status == "completed"
    if retained["status"] == "accepted":
        assert factory().export(_context(), source.id, completed.run_id)["review"]["authenticated"] is True
    else:
        with pytest.raises((PermissionError, ValueError, RecordConflict)):
            factory().export(_context(), source.id, completed.run_id)
