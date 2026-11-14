"""Adversarial persistence tests for Ekko's local encrypted ledger."""
from __future__ import annotations

import sqlite3
import threading

import pytest
from maverick.work_discovery import CapturePolicy, SessionState, WorkEvent
from maverick.work_discovery_store import (
    CollectorLeaseError,
    EnrollmentRequired,
    EventConflictError,
    EventSequenceError,
    SessionStateError,
    WorkDiscoveryStore,
    WorkDiscoveryStoreError,
)

NOW = 1_800_000_000.0
COLLECTOR = "collector-test-capability"
SESSION_CONTROL_COLUMNS = (
    "tenant_key,owner_key,device_key,session_id,state,policy_digest,"
    "started_at,updated_at,ended_at,last_sequence,session_blob"
)
LEASE_CONTROL_COLUMNS = (
    "tenant_key,owner_key,device_key,collector_key,session_id,state,"
    "claimed_at,heartbeat_at,expires_at,lease_blob"
)


def _no_authority_check(_policy):
    return None


def _policy(**changes) -> CapturePolicy:
    values = {
        "enabled": True,
        "capture_level": "guided",
        "allowed_apps": frozenset({"chrome", "excel", "powerpoint"}),
        "allowed_actions": frozenset({"download", "open", "create", "switch"}),
        "allowed_object_types": frozenset({"none", "report", "presentation"}),
        "retention_days": 14,
        "min_occurrences": 2,
        "min_distinct_days": 2,
        "poll_interval_seconds": 1,
        "provider_egress": False,
    }
    values.update(changes)
    return CapturePolicy(**values)


def _event(session_id: str, *, event_id: str = "event-1", sequence: int = 1, **changes):
    values = {
        "occurred_at": NOW,
        "app": "chrome",
        "action": "download",
        "object_type": "report",
        "duration_seconds": 8,
    }
    values.update(changes)
    return WorkEvent(
        event_id=event_id,
        session_id=session_id,
        sequence=sequence,
        **values,
    )


def _append(store, event: WorkEvent, policy: CapturePolicy):
    # Every reviewed integration uses the same exclusive capability lease as
    # the bundled daemon; there is intentionally no unleased persistence seam.
    store.claim_collector(
        event.session_id,
        COLLECTOR,
        policy=policy,
        ttl_seconds=30,
    )
    return store.append_event(event, policy=policy, collector_id=COLLECTOR)


def _snapshot_control_rows(store, session_id: str):
    with sqlite3.connect(store.path) as conn:
        session_row = conn.execute(
            f"SELECT {SESSION_CONTROL_COLUMNS} FROM ekko_sessions "  # noqa: S608
            "WHERE session_id=?",
            (session_id,),
        ).fetchone()
        lease_row = conn.execute(
            f"SELECT {LEASE_CONTROL_COLUMNS} FROM ekko_collector_leases "  # noqa: S608
            "WHERE session_id=?",
            (session_id,),
        ).fetchone()
    return session_row, lease_row


def _delete_control_rows(store, session_id: str) -> None:
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "DELETE FROM ekko_collector_leases WHERE session_id=?", (session_id,),
        )
        conn.execute("DELETE FROM ekko_sessions WHERE session_id=?", (session_id,))


def _restore_control_rows(store, session_row, lease_row) -> None:
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            f"INSERT INTO ekko_sessions({SESSION_CONTROL_COLUMNS}) "  # noqa: S608
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            session_row,
        )
        conn.execute(
            f"INSERT INTO ekko_collector_leases({LEASE_CONTROL_COLUMNS}) "  # noqa: S608
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            lease_row,
        )


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)
    return WorkDiscoveryStore(
        "alice", "laptop-1", tenant="acme",
        path=tmp_path / "ekko.sqlite3", clock=lambda: NOW,
        authority_check=_no_authority_check,
    )


def test_enrollment_and_event_payloads_are_sealed_at_rest(store):
    policy = _policy()
    enrollment = store.enroll(policy)
    session = store.create_session(policy=policy, session_id="session-1")
    event = _event(session.session_id)

    assert enrollment.active is True
    assert "control_revision" not in session.to_dict()
    assert _append(store, event, policy) is True
    assert store.list_events() == [event]

    raw = store.path.read_bytes().lower()
    for forbidden in (
        b"chrome", b"download", b"report", b"powerpoint", b"allowed_apps",
        b"alice", b"laptop-1", b"acme", COLLECTOR.encode(),
    ):
        assert forbidden not in raw


def test_store_is_owner_device_tenant_scoped_even_with_a_shared_database(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    _append(store, _event(session.session_id), policy)

    foreign = WorkDiscoveryStore(
        "mallory", "laptop-1", tenant="acme", path=store.path, clock=lambda: NOW,
        authority_check=_no_authority_check,
    )
    other_tenant = WorkDiscoveryStore(
        "alice", "laptop-1", tenant="globex", path=store.path, clock=lambda: NOW,
        authority_check=_no_authority_check,
    )

    assert foreign.get_enrollment() is None
    assert foreign.list_sessions() == []
    assert foreign.list_events() == []
    assert other_tenant.get_enrollment() is None
    assert other_tenant.list_events() == []

    own_projection = store.governed_candidate_projection()
    other_tenant.enroll(policy)
    other_projection = other_tenant.governed_candidate_projection()
    assert own_projection["owner_sha256"] != other_projection["owner_sha256"]
    assert own_projection["device_sha256"] != other_projection["device_sha256"]
    assert (
        own_projection["lineage"]["event_sha256"]
        != other_projection["lineage"]["event_sha256"]
    )


def test_governed_candidate_projection_requires_live_exact_consent(store):
    policy = _policy()
    enrollment = store.enroll(policy)

    projection = store.governed_candidate_projection()

    assert projection["schema"] == "lightwork.ekko-knowledge-projection.v1"
    assert projection["consent"] == {
        "policy_sha256": policy.fingerprint(),
        "enrolled_at": enrollment.enrolled_at,
        "valid_until": enrollment.expires_at,
    }
    assert projection["lineage"]["event_count"] == 0
    assert len(projection["lineage"]["event_sha256"]) == 64
    assert projection["candidates"] == []
    assert "alice" not in str(projection)

    store.revoke_enrollment()
    with pytest.raises(EnrollmentRequired, match="not enrolled"):
        store.governed_candidate_projection()


def test_same_tenant_ciphertext_transplant_across_owner_scope_is_rejected(store):
    policy = _policy()
    store.enroll(policy)
    store.create_session(policy=policy, session_id="shared-session")
    _append(store, _event("shared-session"), policy)
    foreign = WorkDiscoveryStore(
        "mallory", "laptop-1", tenant="acme", path=store.path, clock=lambda: NOW,
        authority_check=_no_authority_check,
    )
    foreign.enroll(policy)
    foreign.create_session(policy=policy, session_id="shared-session")

    with sqlite3.connect(store.path) as conn:
        source = conn.execute(
            "SELECT event_id,sequence,payload,event_digest,ingested_at,expires_at "
            "FROM ekko_events WHERE tenant_key=? AND owner_key=? AND device_key=?",
            store._scope,
        ).fetchone()
        conn.execute(
            "INSERT INTO ekko_events(tenant_key,owner_key,device_key,session_id,"
            "event_id,sequence,payload,event_digest,ingested_at,expires_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (*foreign._scope, "shared-session", *source),
        )

    with pytest.raises(WorkDiscoveryStoreError, match="scope"):
        foreign.list_events()


def test_plaintext_enrollment_and_session_authority_tampering_is_rejected(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE ekko_enrollments SET expires_at=expires_at+86400"
        )
    with pytest.raises(WorkDiscoveryStoreError, match="integrity"):
        store.get_policy()

    # Restrictive shutdown does not depend on the corrupted grant. Restore
    # enrollment only after that session is terminal, then prove plaintext
    # session state cannot be flipped independently of its sealed authority.
    store.transition_session(session.session_id, SessionState.STOPPED)
    store.enroll(policy)
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE ekko_sessions SET state='paused' WHERE session_id=?",
            (session.session_id,),
        )
    with pytest.raises(WorkDiscoveryStoreError, match="integrity"):
        store.get_session(session.session_id)


def test_revoked_consent_cannot_be_resurrected_by_replaying_database_row(store):
    policy = _policy()
    store.enroll(policy)
    columns = (
        "tenant_key,owner_key,device_key,active,grant_id,policy_digest,"
        "policy_blob,enrolled_at,updated_at,expires_at"
    )
    with sqlite3.connect(store.path) as conn:
        saved = conn.execute(
            f"SELECT {columns} FROM ekko_enrollments"  # noqa: S608 - fixed columns
        ).fetchone()
    store.revoke_enrollment()
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            f"INSERT INTO ekko_enrollments({columns}) VALUES(?,?,?,?,?,?,?,?,?,?)",  # noqa: S608 - fixed columns
            saved,
        )

    with pytest.raises(EnrollmentRequired, match="revoked|stale"):
        store.get_policy()


def test_concurrent_revoke_cannot_be_overwritten_by_delayed_enroll(store, monkeypatch):
    policy = _policy()
    reached = threading.Event()
    release = threading.Event()
    revoked = threading.Event()
    errors = []
    real_write = store._write_consent_authority

    def delayed_write(payload):
        if payload.get("state") == "active":
            reached.set()
            assert release.wait(5)
        return real_write(payload)

    monkeypatch.setattr(store, "_write_consent_authority", delayed_write)

    def enroll():
        try:
            store.enroll(policy)
        except Exception as exc:  # pragma: no cover - diagnostic collection
            errors.append(exc)

    def revoke():
        try:
            store.revoke_enrollment()
            revoked.set()
        except Exception as exc:  # pragma: no cover - diagnostic collection
            errors.append(exc)

    enroll_thread = threading.Thread(target=enroll)
    revoke_thread = threading.Thread(target=revoke)
    enroll_thread.start()
    assert reached.wait(5)
    revoke_thread.start()
    assert not revoked.wait(0.2)
    release.set()
    enroll_thread.join(5)
    revoke_thread.join(5)

    assert errors == []
    assert revoked.is_set()
    assert store.get_policy() is None
    assert store._read_consent_authority()["state"] == "revoked"


def test_plaintext_event_expiry_extension_is_rejected(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    _append(store, _event(session.session_id), policy)
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE ekko_events SET expires_at=expires_at+86400")

    with pytest.raises(WorkDiscoveryStoreError, match="authority"):
        store.list_events()


def test_store_write_boundary_rechecks_deployment_authority(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ef" * 32)
    enabled = {"value": True}

    def validate(_policy):
        if not enabled["value"]:
            raise ValueError("deployment policy is off")

    monkeypatch.setattr("maverick.config.validate_ekko_policy_ceiling", validate)
    monkeypatch.setattr("maverick.killswitch.check", lambda **_kwargs: None)
    guarded = WorkDiscoveryStore(
        "alice", "laptop-1", tenant="acme",
        path=tmp_path / "guarded.sqlite3", clock=lambda: NOW,
    )
    policy = _policy()
    guarded.enroll(policy)
    session = guarded.create_session(policy=policy)
    enabled["value"] = False

    with pytest.raises(ValueError, match="off"):
        _append(guarded, _event(session.session_id), policy)

    assert guarded.get_session(session.session_id).last_sequence == 0
    assert guarded.list_events() == []


def test_expired_enrollment_halts_stale_running_session(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "12" * 32)
    now = {"value": NOW}
    expiring = WorkDiscoveryStore(
        "alice", "laptop-1", tenant="acme",
        path=tmp_path / "expiring.sqlite3",
        clock=lambda: now["value"],
        authority_check=_no_authority_check,
    )
    policy = _policy()
    expiring.enroll(policy, expires_at=NOW + 60)
    session = expiring.create_session(policy=policy)
    now["value"] = NOW + 61

    status = expiring.status()

    assert status["enrollment"]["active"] is False
    assert status["session"]["state"] == "halted"
    assert expiring.get_session(session.session_id).state == SessionState.HALTED


def test_per_session_quota_bounds_guided_collector_growth(
    store, monkeypatch,
):
    monkeypatch.setattr(
        "maverick.work_discovery_store.MAX_EVENTS_PER_SESSION", 1,
    )
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    _append(store, _event(session.session_id), policy)

    with pytest.raises(WorkDiscoveryStoreError, match="quota"):
        _append(
            store,
            _event(session.session_id, event_id="event-2", sequence=2),
            policy,
        )


def test_event_replay_conflict_gap_and_stopped_session_fail_closed(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    first = _event(session.session_id)

    assert _append(store, first, policy) is True
    assert _append(store, first, policy) is False
    with pytest.raises(EventConflictError):
        _append(
            store,
            _event(session.session_id, app="excel", action="open"),
            policy,
        )
    with pytest.raises(EventSequenceError, match="gap"):
        _append(
            store,
            _event(session.session_id, event_id="event-3", sequence=3),
            policy,
        )

    store.transition_session(session.session_id, SessionState.PAUSED)
    with pytest.raises(SessionStateError, match="running"):
        _append(
            store,
            _event(session.session_id, event_id="event-2", sequence=2),
            policy,
        )


def test_revocation_stops_active_sessions_and_blocks_resume(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)

    revoked = store.revoke_enrollment()

    assert revoked is not None and revoked.active is False
    assert store.get_session(session.session_id).state == SessionState.STOPPED
    with pytest.raises(EnrollmentRequired):
        store.transition_session(session.session_id, SessionState.RUNNING)


def test_policy_narrowing_requires_reenrollment_and_blocklist_wins(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    narrowed = _policy(allowed_apps=frozenset({"excel", "powerpoint"}))

    with pytest.raises(EnrollmentRequired, match="policy changed"):
        _append(
            store,
            _event(session.session_id, app="excel", action="open"),
            narrowed,
        )
    with pytest.raises(EnrollmentRequired, match="outside"):
        _append(
            store,
            _event(session.session_id, app="email", action="open"),
            policy,
        )


def test_expired_enrollment_and_stale_or_future_events_are_rejected(store):
    policy = _policy()
    store.enroll(policy, expires_at=NOW + 60)
    session = store.create_session(policy=policy, started_at=NOW)

    with pytest.raises(ValueError, match="future"):
        _append(
            store, _event(session.session_id, occurred_at=NOW + 301), policy,
        )
    with pytest.raises(ValueError, match="retention"):
        _append(
            store,
            _event(session.session_id, occurred_at=NOW - 15 * 86_400),
            policy,
        )

    expired = WorkDiscoveryStore(
        "alice", "laptop-1", tenant="acme", path=store.path,
        clock=lambda: NOW + 61, authority_check=_no_authority_check,
    )
    assert expired.get_policy() is None
    with pytest.raises(EnrollmentRequired, match="expired"):
        _append(expired, _event(session.session_id), policy)


def test_backfilled_event_expires_from_occurrence_not_ingestion(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(
        policy=policy, started_at=NOW - 13 * 86_400,
    )
    event = _event(
        session.session_id, occurred_at=NOW - 13 * 86_400,
    )
    _append(store, event, policy)
    assert store.list_events() == [event]

    after_ttl = WorkDiscoveryStore(
        "alice", "laptop-1", tenant="acme", path=store.path,
        clock=lambda: NOW + 86_400 + 1,
        authority_check=_no_authority_check,
    )
    assert after_ttl.list_events() == []
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM ekko_events").fetchone()[0] == 0


def test_tampered_ciphertext_is_never_returned_as_observation(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    _append(store, _event(session.session_id), policy)
    with sqlite3.connect(store.path) as conn:
        blob = bytearray(conn.execute("SELECT payload FROM ekko_events").fetchone()[0])
        blob[-1] ^= 1
        conn.execute("UPDATE ekko_events SET payload=?", (bytes(blob),))

    with pytest.raises(WorkDiscoveryStoreError):
        store.list_events()


def test_scoped_erase_cascades_events_and_preserves_other_device(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy, session_id="one")
    _append(store, _event(session.session_id), policy)
    other = WorkDiscoveryStore(
        "alice", "laptop-2", tenant="acme", path=store.path, clock=lambda: NOW,
        authority_check=_no_authority_check,
    )
    other.enroll(policy)
    other_session = other.create_session(policy=policy, session_id="two")
    _append(
        other,
        _event(other_session.session_id, event_id="other-event"),
        policy,
    )

    assert store.erase() == {"events": 1, "sessions": 1}
    assert store.list_events() == []
    assert len(other.list_events()) == 1


def test_collector_lease_is_exclusive_secret_and_required(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    lease = store.claim_collector(
        session.session_id, COLLECTOR, policy=policy, ttl_seconds=30,
    )

    assert lease.collector_key != COLLECTOR
    assert "control_revision" not in lease.to_dict()
    assert store.collector_status(session.session_id)["state"] == "live"
    assert COLLECTOR.encode() not in store.path.read_bytes()
    with pytest.raises(CollectorLeaseError, match="live collector"):
        store.claim_collector(
            session.session_id,
            "collector-second-capability",
            policy=policy,
            ttl_seconds=30,
        )
    with pytest.raises(TypeError, match="collector_id"):
        store.append_event(_event(session.session_id), policy=policy)
    with pytest.raises(CollectorLeaseError, match="does not own"):
        store.append_event(
            _event(session.session_id),
            policy=policy,
            collector_id="collector-wrong-capability",
        )


def test_external_revision_blocks_paired_session_and_lease_rollback(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    store.claim_collector(
        session.session_id, COLLECTOR, policy=policy, ttl_seconds=30,
    )
    with sqlite3.connect(store.path) as conn:
        saved_session = conn.execute(
            "SELECT state,policy_digest,started_at,updated_at,ended_at,"
            "last_sequence,session_blob FROM ekko_sessions WHERE session_id=?",
            (session.session_id,),
        ).fetchone()
        saved_lease = conn.execute(
            "SELECT collector_key,session_id,state,claimed_at,heartbeat_at,"
            "expires_at,lease_blob FROM ekko_collector_leases WHERE session_id=?",
            (session.session_id,),
        ).fetchone()

    store.transition_session(session.session_id, SessionState.PAUSED)
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE ekko_sessions SET state=?,policy_digest=?,started_at=?,"
            "updated_at=?,ended_at=?,last_sequence=?,session_blob=? "
            "WHERE session_id=?",
            (*saved_session, session.session_id),
        )
        conn.execute(
            "UPDATE ekko_collector_leases SET collector_key=?,session_id=?,state=?,"
            "claimed_at=?,heartbeat_at=?,expires_at=?,lease_blob=?",
            saved_lease,
        )

    # Read-only history remains inspectable so an operator can locate and
    # retry a restrictive transition after a marker-ahead crash.
    assert store.get_session(session.session_id).state == SessionState.RUNNING
    with pytest.raises(WorkDiscoveryStoreError, match="stale"):
        store.append_event(
            _event(session.session_id),
            policy=policy,
            collector_id=COLLECTOR,
        )
    with pytest.raises(WorkDiscoveryStoreError, match="stale"):
        store.claim_collector(session.session_id, COLLECTOR, policy=policy)
    with pytest.raises(WorkDiscoveryStoreError, match="stale"):
        store.heartbeat_collector(session.session_id, COLLECTOR, policy=policy)
    with pytest.raises(WorkDiscoveryStoreError, match="stale"):
        store.transition_session(session.session_id, SessionState.RUNNING)
    # Restrictive release is the sole safe marker-ahead reconciliation path.
    assert store.release_collector(session.session_id, COLLECTOR) is True


def test_release_revision_blocks_paired_active_lease_rollback(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    store.claim_collector(session.session_id, COLLECTOR, policy=policy)
    with sqlite3.connect(store.path) as conn:
        saved_session = conn.execute(
            "SELECT state,policy_digest,started_at,updated_at,ended_at,"
            "last_sequence,session_blob FROM ekko_sessions WHERE session_id=?",
            (session.session_id,),
        ).fetchone()
        saved_lease = conn.execute(
            "SELECT collector_key,session_id,state,claimed_at,heartbeat_at,"
            "expires_at,lease_blob FROM ekko_collector_leases WHERE session_id=?",
            (session.session_id,),
        ).fetchone()

    assert store.release_collector(session.session_id, COLLECTOR) is True
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE ekko_sessions SET state=?,policy_digest=?,started_at=?,"
            "updated_at=?,ended_at=?,last_sequence=?,session_blob=? "
            "WHERE session_id=?",
            (*saved_session, session.session_id),
        )
        conn.execute(
            "UPDATE ekko_collector_leases SET collector_key=?,session_id=?,state=?,"
            "claimed_at=?,heartbeat_at=?,expires_at=?,lease_blob=?",
            saved_lease,
        )

    with pytest.raises(WorkDiscoveryStoreError, match="stale"):
        store.append_event(
            _event(session.session_id), policy=policy, collector_id=COLLECTOR,
        )


def test_heartbeat_database_failure_preserves_revision_and_is_retryable(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    store.claim_collector(session.session_id, COLLECTOR, policy=policy)
    revision = store._read_session_authority(session.session_id)["revision"]
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "CREATE TRIGGER fail_ekko_heartbeat BEFORE UPDATE OF heartbeat_at "
            "ON ekko_collector_leases BEGIN "
            "SELECT RAISE(ABORT, 'heartbeat write failed'); END"
        )

    with pytest.raises(sqlite3.IntegrityError, match="heartbeat write failed"):
        store.heartbeat_collector(
            session.session_id, COLLECTOR, policy=policy, at=NOW + 1,
        )
    assert store._read_session_authority(session.session_id)["revision"] == revision

    with sqlite3.connect(store.path) as conn:
        conn.execute("DROP TRIGGER fail_ekko_heartbeat")
    heartbeat = store.heartbeat_collector(
        session.session_id, COLLECTOR, policy=policy, at=NOW + 1,
    )
    assert heartbeat.heartbeat_at == NOW + 1
    assert store._read_session_authority(session.session_id)["revision"] == revision


def test_release_reconciles_exactly_one_marker_ahead_after_failure(
    store, monkeypatch,
):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    store.claim_collector(session.session_id, COLLECTOR, policy=policy)
    prior_revision = store._read_session_authority(session.session_id)["revision"]
    real_bind = store._bind_session_revision

    def fail_after_marker(*_args, **_kwargs):
        raise RuntimeError("simulated release database failure")

    monkeypatch.setattr(store, "_bind_session_revision", fail_after_marker)
    with pytest.raises(RuntimeError, match="release database failure"):
        store.release_collector(session.session_id, COLLECTOR)
    assert (
        store._read_session_authority(session.session_id)["revision"]
        == prior_revision + 1
    )

    monkeypatch.setattr(store, "_bind_session_revision", real_bind)
    assert store.release_collector(session.session_id, COLLECTOR) is True
    assert store.collector_status(session.session_id)["state"] == "waiting"


def test_marker_ahead_restrictive_transition_is_safely_retryable(
    store, monkeypatch,
):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    store.claim_collector(session.session_id, COLLECTOR, policy=policy)
    real_sync = store._sync_lease_session_state

    def fail_after_marker(*_args, **_kwargs):
        raise RuntimeError("simulated sqlite transition failure")

    monkeypatch.setattr(store, "_sync_lease_session_state", fail_after_marker)
    with pytest.raises(RuntimeError, match="simulated sqlite"):
        store.transition_session(session.session_id, SessionState.PAUSED)
    assert store.get_session(session.session_id).state == SessionState.RUNNING

    monkeypatch.setattr(store, "_sync_lease_session_state", real_sync)
    assert store.transition_session(
        session.session_id, SessionState.PAUSED,
    ).state == SessionState.PAUSED
    assert store.collector_status(session.session_id)["state"] == "live"


def test_external_revision_marker_is_bound_to_the_exact_session(store):
    policy = _policy()
    store.enroll(policy)
    first = store.create_session(policy=policy, session_id="marker-first")
    store.transition_session(first.session_id, SessionState.STOPPED)
    second = store.create_session(policy=policy, session_id="marker-second")

    first_marker = store._session_authority_path(first.session_id).read_bytes()
    store._session_authority_path(second.session_id).write_bytes(first_marker)

    with pytest.raises(WorkDiscoveryStoreError, match="invalid.*authority"):
        store.claim_collector(second.session_id, COLLECTOR, policy=policy)


def test_revoke_reenroll_cannot_revive_replayed_session_and_lease(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    store.claim_collector(session.session_id, COLLECTOR, policy=policy)
    with sqlite3.connect(store.path) as conn:
        saved_session = conn.execute(
            "SELECT state,policy_digest,started_at,updated_at,ended_at,"
            "last_sequence,session_blob FROM ekko_sessions WHERE session_id=?",
            (session.session_id,),
        ).fetchone()
        saved_lease = conn.execute(
            "SELECT collector_key,session_id,state,claimed_at,heartbeat_at,"
            "expires_at,lease_blob FROM ekko_collector_leases WHERE session_id=?",
            (session.session_id,),
        ).fetchone()

    store.revoke_enrollment()
    store.enroll(policy)
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE ekko_sessions SET state=?,policy_digest=?,started_at=?,"
            "updated_at=?,ended_at=?,last_sequence=?,session_blob=? "
            "WHERE session_id=?",
            (*saved_session, session.session_id),
        )
        conn.execute(
            "UPDATE ekko_collector_leases SET collector_key=?,session_id=?,state=?,"
            "claimed_at=?,heartbeat_at=?,expires_at=?,lease_blob=?",
            saved_lease,
        )

    with pytest.raises(WorkDiscoveryStoreError, match="stale"):
        store.append_event(
            _event(session.session_id), policy=policy, collector_id=COLLECTOR,
        )


def test_new_grant_blocks_deleted_then_restored_live_session(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy, session_id="old-grant-live")
    store.claim_collector(session.session_id, COLLECTOR, policy=policy)
    store.append_event(
        _event(session.session_id), policy=policy, collector_id=COLLECTOR,
    )
    session_columns = (
        "tenant_key,owner_key,device_key,session_id,state,policy_digest,"
        "started_at,updated_at,ended_at,last_sequence,session_blob"
    )
    lease_columns = (
        "tenant_key,owner_key,device_key,collector_key,session_id,state,"
        "claimed_at,heartbeat_at,expires_at,lease_blob"
    )
    event_columns = (
        "tenant_key,owner_key,device_key,session_id,event_id,sequence,payload,"
        "event_digest,ingested_at,expires_at"
    )
    with sqlite3.connect(store.path) as conn:
        old_grant_id = conn.execute(
            "SELECT grant_id FROM ekko_enrollments"
        ).fetchone()[0]
        saved_session = conn.execute(
            f"SELECT {session_columns} FROM ekko_sessions "  # noqa: S608 - fixed columns
            "WHERE session_id=?",
            (session.session_id,),
        ).fetchone()
        saved_lease = conn.execute(
            f"SELECT {lease_columns} FROM ekko_collector_leases "  # noqa: S608 - fixed columns
            "WHERE session_id=?",
            (session.session_id,),
        ).fetchone()
        saved_event = conn.execute(
            f"SELECT {event_columns} FROM ekko_events "  # noqa: S608 - fixed columns
            "WHERE session_id=?",
            (session.session_id,),
        ).fetchone()
        conn.execute("DELETE FROM ekko_events WHERE session_id=?", (session.session_id,))
        conn.execute(
            "DELETE FROM ekko_collector_leases WHERE session_id=?",
            (session.session_id,),
        )
        conn.execute("DELETE FROM ekko_sessions WHERE session_id=?", (session.session_id,))

    store.enroll(policy)
    with sqlite3.connect(store.path) as conn:
        new_grant_id = conn.execute(
            "SELECT grant_id FROM ekko_enrollments"
        ).fetchone()[0]
        conn.execute(
            f"INSERT INTO ekko_sessions({session_columns}) "  # noqa: S608 - fixed columns
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            saved_session,
        )
        conn.execute(
            f"INSERT INTO ekko_collector_leases({lease_columns}) "  # noqa: S608 - fixed columns
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            saved_lease,
        )
        conn.execute(
            f"INSERT INTO ekko_events({event_columns}) "  # noqa: S608 - fixed columns
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            saved_event,
        )
    assert new_grant_id != old_grant_id

    assert store.collector_status(session.session_id)["state"] == "stale"
    with pytest.raises(EnrollmentRequired, match="enrollment changed"):
        store.append_event(
            _event(session.session_id, event_id="event-2", sequence=2),
            policy=policy,
            collector_id=COLLECTOR,
        )
    with pytest.raises(EnrollmentRequired, match="enrollment changed"):
        store.claim_collector(session.session_id, COLLECTOR, policy=policy)
    with pytest.raises(EnrollmentRequired, match="enrollment changed"):
        store.heartbeat_collector(session.session_id, COLLECTOR, policy=policy)
    with pytest.raises(EnrollmentRequired, match="enrollment changed"):
        store.transition_session(session.session_id, SessionState.RUNNING)
    with pytest.raises(EnrollmentRequired, match="enrollment.*stale"):
        store.list_events(session_id=session.session_id)


def test_enroll_authenticates_existing_session_state_and_marker(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE ekko_sessions SET state='stopped' WHERE session_id=?",
            (session.session_id,),
        )

    with pytest.raises(WorkDiscoveryStoreError, match="integrity"):
        store.enroll(policy)


def test_terminal_prior_grant_history_remains_readable_until_retention(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    event = _event(session.session_id)
    _append(store, event, policy)
    store.transition_session(session.session_id, SessionState.STOPPED)

    store.enroll(policy)

    assert store.list_events(session_id=session.session_id) == [event]


def test_erase_tombstone_blocks_row_replay_and_session_id_reuse(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy, session_id="erase-once")
    store.claim_collector(session.session_id, COLLECTOR, policy=policy)
    store.append_event(
        _event(session.session_id), policy=policy, collector_id=COLLECTOR,
    )
    session_columns = (
        "tenant_key,owner_key,device_key,session_id,state,policy_digest,"
        "started_at,updated_at,ended_at,last_sequence,session_blob"
    )
    lease_columns = (
        "tenant_key,owner_key,device_key,collector_key,session_id,state,"
        "claimed_at,heartbeat_at,expires_at,lease_blob"
    )
    event_columns = (
        "tenant_key,owner_key,device_key,session_id,event_id,sequence,payload,"
        "event_digest,ingested_at,expires_at"
    )
    with sqlite3.connect(store.path) as conn:
        saved_session = conn.execute(
            f"SELECT {session_columns} FROM ekko_sessions "  # noqa: S608 - fixed columns
            "WHERE session_id=?",
            (session.session_id,),
        ).fetchone()
        saved_lease = conn.execute(
            f"SELECT {lease_columns} FROM ekko_collector_leases "  # noqa: S608 - fixed columns
            "WHERE session_id=?",
            (session.session_id,),
        ).fetchone()
        saved_event = conn.execute(
            f"SELECT {event_columns} FROM ekko_events "  # noqa: S608 - fixed columns
            "WHERE session_id=?",
            (session.session_id,),
        ).fetchone()

    assert store.erase(session_id=session.session_id) == {
        "events": 1, "sessions": 1,
    }
    with pytest.raises(SessionStateError, match="prior Ekko control authority"):
        store.create_session(policy=policy, session_id=session.session_id)

    with sqlite3.connect(store.path) as conn:
        conn.execute(
            f"INSERT INTO ekko_sessions({session_columns}) "  # noqa: S608 - fixed columns
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            saved_session,
        )
        conn.execute(
            f"INSERT INTO ekko_collector_leases({lease_columns}) "  # noqa: S608 - fixed columns
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            saved_lease,
        )
        conn.execute(
            f"INSERT INTO ekko_events({event_columns}) "  # noqa: S608 - fixed columns
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            saved_event,
        )

    with pytest.raises(WorkDiscoveryStoreError, match="stale"):
        store.list_events(session_id=session.session_id)
    with pytest.raises(WorkDiscoveryStoreError, match="stale"):
        store.append_event(
            _event(session.session_id), policy=policy, collector_id=COLLECTOR,
        )


def test_explicit_erase_tombstones_session_missing_from_database(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy, session_id="hidden-explicit")
    store.claim_collector(session.session_id, COLLECTOR, policy=policy)
    session_row, lease_row = _snapshot_control_rows(store, session.session_id)
    _delete_control_rows(store, session.session_id)

    assert store.erase(session_id=session.session_id) == {
        "events": 0, "sessions": 0,
    }
    _restore_control_rows(store, session_row, lease_row)

    with pytest.raises(WorkDiscoveryStoreError, match="revoked|stale"):
        store.append_event(
            _event(session.session_id), policy=policy, collector_id=COLLECTOR,
        )


def test_device_erase_tombstones_authority_hidden_from_database(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy, session_id="hidden-device")
    store.claim_collector(session.session_id, COLLECTOR, policy=policy)
    session_row, lease_row = _snapshot_control_rows(store, session.session_id)
    _delete_control_rows(store, session.session_id)

    assert store.erase() == {"events": 0, "sessions": 0}
    _restore_control_rows(store, session_row, lease_row)

    with pytest.raises(WorkDiscoveryStoreError, match="revoked|stale"):
        store.append_event(
            _event(session.session_id), policy=policy, collector_id=COLLECTOR,
        )


def test_corrupt_marker_cannot_block_sqlite_privacy_erasure(store):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy, session_id="corrupt-erase")
    store.claim_collector(session.session_id, COLLECTOR, policy=policy)
    session_row, lease_row = _snapshot_control_rows(store, session.session_id)
    marker_path = store._session_authority_path(session.session_id)
    marker_path.write_bytes(b"corrupt marker")

    assert store.erase(session_id=session.session_id) == {
        "events": 0, "sessions": 1,
    }
    assert marker_path.read_bytes().startswith(b"EKKO-SESSION-REVOKED-V1\n")
    _restore_control_rows(store, session_row, lease_row)

    with pytest.raises(WorkDiscoveryStoreError, match="revoked|stale"):
        store.append_event(
            _event(session.session_id), policy=policy, collector_id=COLLECTOR,
        )


@pytest.mark.parametrize("scoped_read", [True, False])
def test_erase_waits_for_inflight_event_decryption(
    store, monkeypatch, scoped_read,
):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    event = _event(session.session_id)
    _append(store, event, policy)
    decrypt_started = threading.Event()
    allow_decrypt = threading.Event()
    erase_done = threading.Event()
    read_result = []
    errors = []
    real_unseal = store._unseal

    def blocked_unseal(blob, *, purpose):
        if purpose == "event":
            decrypt_started.set()
            if not allow_decrypt.wait(5):
                raise RuntimeError("timed out waiting to finish event read")
        return real_unseal(blob, purpose=purpose)

    monkeypatch.setattr(store, "_unseal", blocked_unseal)

    def read_events():
        try:
            read_result.extend(store.list_events(
                session_id=session.session_id if scoped_read else None,
            ))
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    def erase_session():
        try:
            store.erase(session_id=session.session_id)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)
        finally:
            erase_done.set()

    reader = threading.Thread(target=read_events)
    reader.start()
    assert decrypt_started.wait(5)
    eraser = threading.Thread(target=erase_session)
    eraser.start()
    assert erase_done.wait(0.2) is False

    allow_decrypt.set()
    reader.join(5)
    eraser.join(5)
    assert not reader.is_alive() and not eraser.is_alive()
    assert errors == []
    assert read_result == [event]
    assert erase_done.is_set()
    assert store.list_events(session_id=session.session_id) == []


def test_forget_device_serializes_concurrent_reenrollment(store, monkeypatch):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    _append(store, _event(session.session_id), policy)
    revoke_finished = threading.Event()
    allow_erase = threading.Event()
    enroll_entered = threading.Event()
    allow_enroll = threading.Event()
    forget_result = []
    enroll_result = []
    errors = []
    real_erase = store._erase_authorities_locked
    real_authority_check = store._authority_check

    def delayed_erase(*, session_id):
        revoke_finished.set()
        if not allow_erase.wait(5):
            raise RuntimeError("timed out waiting to erase forgotten device")
        return real_erase(session_id=session_id)

    def gated_authority_check(candidate_policy):
        enroll_entered.set()
        if not allow_enroll.wait(5):
            raise RuntimeError("timed out waiting to re-enroll")
        return real_authority_check(candidate_policy)

    monkeypatch.setattr(store, "_erase_authorities_locked", delayed_erase)
    monkeypatch.setattr(store, "_authority_check", gated_authority_check)

    def forget():
        try:
            forget_result.append(store.forget_device())
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    def reenroll():
        try:
            enroll_result.append(store.enroll(policy))
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    forgetter = threading.Thread(target=forget)
    forgetter.start()
    assert revoke_finished.wait(5)
    enroller = threading.Thread(target=reenroll)
    enroller.start()
    assert enroll_entered.wait(0.2) is False

    allow_erase.set()
    forgetter.join(5)
    assert not forgetter.is_alive()
    assert enroll_entered.wait(5)
    assert store.get_enrollment() is None
    assert forget_result == [{"events": 1, "sessions": 1, "enrollments": 1}]

    allow_enroll.set()
    enroller.join(5)
    assert not enroller.is_alive()
    assert errors == []
    assert len(enroll_result) == 1 and enroll_result[0].active is True


def test_restrictive_transition_survives_audit_outbox_failure(
    store, monkeypatch,
):
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)

    def fail_audit(*_args, **_kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(store, "_queue_audit", fail_audit)
    paused = store.transition_session(session.session_id, SessionState.PAUSED)
    assert paused.state == SessionState.PAUSED
    assert store.get_session(session.session_id).state == SessionState.PAUSED

    with pytest.raises(RuntimeError, match="audit unavailable"):
        store.transition_session(session.session_id, SessionState.RUNNING)
    assert store.get_session(session.session_id).state == SessionState.PAUSED


def test_create_session_enforces_one_nonterminal_observation_window(store):
    policy = _policy()
    store.enroll(policy)
    first = store.create_session(policy=policy, session_id="first-window")

    with pytest.raises(SessionStateError, match="already has an active"):
        store.create_session(policy=policy, session_id="second-window")

    store.transition_session(first.session_id, SessionState.STOPPED)
    second = store.create_session(policy=policy, session_id="second-window")
    assert second.state == SessionState.RUNNING


def test_audit_outbox_is_bounded_and_has_idempotent_delivery(store, monkeypatch):
    policy = _policy()
    store.enroll(policy)
    store.create_session(policy=policy)
    seen = []

    def record(kind, **payload):
        seen.append((kind, payload["ekko_outbox_id"]))
        return True

    pending = store.pending_audit_count()
    result = store.flush_audit_outbox(recorder=record)
    assert result == {"delivered": pending, "pending": 0}
    assert len({outbox_id for _, outbox_id in seen}) == pending
    assert store.flush_audit_outbox(recorder=record) == {
        "delivered": 0,
        "pending": 0,
    }

    monkeypatch.setattr("maverick.work_discovery_store.MAX_AUDIT_OUTBOX", 0)
    session = store.latest_session()
    # Restrictive control still wins even when the bounded outbox is full.
    assert store.transition_session(
        session.session_id, SessionState.PAUSED,
    ).state == SessionState.PAUSED


def test_session_quota_bounds_create_stop_churn(store, monkeypatch):
    policy = _policy()
    store.enroll(policy)
    first = store.create_session(policy=policy)
    store.transition_session(first.session_id, SessionState.STOPPED)
    monkeypatch.setattr(
        "maverick.work_discovery_store.MAX_SESSIONS_PER_DEVICE", 1,
    )

    with pytest.raises(WorkDiscoveryStoreError, match="session quota"):
        store.create_session(policy=policy)


def _raw_event_rows(store):
    with sqlite3.connect(store.path) as conn:
        return conn.execute(
            "SELECT event_id,event_digest,ingested_at,expires_at,payload FROM ekko_events "
            "WHERE tenant_key=? AND owner_key=? AND device_key=? ORDER BY event_id",
            store._scope,
        ).fetchall()


def test_governed_projection_excludes_expired_events_without_deleting_them(store):
    # A read of the knowledge projection must not write: expired ciphertext is
    # left for the store's own maintenance paths (append, list, status, prune).
    policy = _policy()
    store.enroll(policy)
    store.create_session(policy=policy, session_id="expired-session")
    _append(store, _event("expired-session"), policy)
    stored = _raw_event_rows(store)
    assert len(stored) == 1
    # Events keep 14 days; enrollment lasts 30 days. Read 15 days later.
    later = WorkDiscoveryStore(
        "alice", "laptop-1", tenant="acme", path=store.path,
        clock=lambda: NOW + 15 * 86_400.0, authority_check=_no_authority_check,
    )

    projection = later.governed_candidate_projection()

    assert projection["lineage"]["event_count"] == 0
    assert projection["candidates"] == []
    assert _raw_event_rows(later) == stored


def test_an_explicit_purge_deletes_only_this_scopes_expired_ciphertext(store):
    policy = _policy()
    store.enroll(policy)
    store.create_session(policy=policy, session_id="expired-session")
    _append(store, _event("expired-session"), policy)
    assert len(_raw_event_rows(store)) == 1
    # Events keep 14 days. Fifteen days later the explicit write path removes the expired row.
    later = WorkDiscoveryStore(
        "alice", "laptop-1", tenant="acme", path=store.path,
        clock=lambda: NOW + 15 * 86_400.0, authority_check=_no_authority_check,
    )
    other_device = WorkDiscoveryStore(
        "alice", "laptop-2", tenant="acme", path=store.path,
        clock=lambda: NOW + 15 * 86_400.0, authority_check=_no_authority_check,
    )

    assert other_device.purge_expired() == 0
    assert _raw_event_rows(later) != []
    assert later.purge_expired() == 1
    assert _raw_event_rows(later) == []
    assert later.purge_expired() == 0


def test_an_explicit_purge_queues_its_retention_record_with_the_deletion(store):
    policy = _policy()
    store.enroll(policy)
    store.create_session(policy=policy, session_id="expired-session")
    _append(store, _event("expired-session"), policy)
    later = WorkDiscoveryStore(
        "alice", "laptop-1", tenant="acme", path=store.path,
        clock=lambda: NOW + 15 * 86_400.0, authority_check=_no_authority_check,
    )
    queued_before = later.pending_audit_count()

    assert later.purge_expired() == 1
    # The deletion and its record commit together: one new outbox row, and the rows are gone.
    assert later.pending_audit_count() == queued_before + 1
    assert _raw_event_rows(later) == []
    delivered = []
    later.flush_audit_outbox(
        recorder=lambda kind, **payload: delivered.append((kind, payload["lifecycle"])) or True,
    )
    assert ("ekko_retention_purge", {"state": "expired_removed", "removed": 1}) in delivered


def test_a_full_audit_outbox_keeps_the_expired_rows_until_a_purge_can_record_them(store, monkeypatch):
    policy = _policy()
    store.enroll(policy)
    store.create_session(policy=policy, session_id="expired-session")
    _append(store, _event("expired-session"), policy)
    later = WorkDiscoveryStore(
        "alice", "laptop-1", tenant="acme", path=store.path,
        clock=lambda: NOW + 15 * 86_400.0, authority_check=_no_authority_check,
    )

    monkeypatch.setattr("maverick.work_discovery_store.MAX_AUDIT_OUTBOX", 0)
    with pytest.raises(WorkDiscoveryStoreError, match="outbox is full"):
        later.purge_expired()
    assert _raw_event_rows(later) != []

    monkeypatch.setattr("maverick.work_discovery_store.MAX_AUDIT_OUTBOX", 2_000)
    assert later.purge_expired() == 1
    assert _raw_event_rows(later) == []


def test_bounded_event_page_returns_the_newest_events(store):
    # Discovery reads one bounded page; past the cap it must see the newest
    # observations, not the oldest ones, still returned in ingestion order.
    policy = _policy()
    store.enroll(policy)
    session = store.create_session(policy=policy)
    events = [
        _event(session.session_id, event_id=f"event-{n}", sequence=n)
        for n in (1, 2, 3)
    ]
    for event in events:
        _append(store, event, policy)

    assert store.list_events(limit=2) == events[1:]
    assert store.list_events() == events
