from __future__ import annotations

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from maverick import ai_governance_loop as loop

TENANT = "tenant-loop"
OTHER_TENANT = "tenant-other"
ASSET = "MAA-0123456789abcdef0123456789abcdef"
OTHER_ASSET = "MAA-fedcba9876543210fedcba9876543210"


def complete_config() -> dict[str, object]:
    return {
        "ai_inventory": {"enable": True},
        "ai_dynamic_risk": {"enable": True},
        "ai_policy_management": {"enable": True},
        "ai_runtime_guardrails": {"enable": True},
        "ai_governance_loop": {"enable": True},
    }


def test_feature_gate_is_exact_default_off_and_dependency_complete() -> None:
    assert loop.enabled(complete_config())
    assert not loop.enabled({})
    for section in complete_config():
        config = complete_config()
        config[section] = {"enable": False}
        assert not loop.enabled(config)
    config = complete_config()
    config["ai_governance_loop"] = {"enable": 1}
    assert not loop.enabled(config)
    assert issubclass(loop.AIGovernanceLoopConfigError, RuntimeError)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def pin(
    name: str,
    *,
    tenant_id: str = TENANT,
    asset_id: str = ASSET,
    revision: int = 1,
    suffix: str = "v1",
) -> loop.AuthorityPin:
    return loop.AuthorityPin(
        tenant_id=tenant_id,
        asset_id=asset_id,
        record_id=f"{name}-record",
        revision=revision,
        sha256=digest(f"{tenant_id}:{asset_id}:{name}:{suffix}"),
    )


def snapshot(
    clock: Clock,
    *,
    tenant_id: str = TENANT,
    asset_id: str = ASSET,
    declaration_approved: bool = True,
    risk_current: bool = True,
    policy_current: bool = True,
    policy_decision: str = "allow",
    enforcement_decision: str = "allow",
    evidence_complete: bool = True,
    limitations: tuple[str, ...] = (),
    revision: int = 1,
    suffix: str = "v1",
) -> loop.AuthoritySnapshot:
    return loop.AuthoritySnapshot(
        tenant_id=tenant_id,
        asset_id=asset_id,
        inventory=pin(
            "inventory",
            tenant_id=tenant_id,
            asset_id=asset_id,
            revision=revision,
            suffix=suffix,
        ),
        declaration=pin(
            "declaration",
            tenant_id=tenant_id,
            asset_id=asset_id,
            revision=revision,
            suffix=suffix,
        ),
        risk=pin(
            "risk",
            tenant_id=tenant_id,
            asset_id=asset_id,
            revision=revision,
            suffix=suffix,
        ),
        policy=pin(
            "policy",
            tenant_id=tenant_id,
            asset_id=asset_id,
            revision=revision,
            suffix=suffix,
        ),
        enforcement=pin(
            "enforcement",
            tenant_id=tenant_id,
            asset_id=asset_id,
            revision=revision,
            suffix=suffix,
        ),
        evidence=pin(
            "evidence",
            tenant_id=tenant_id,
            asset_id=asset_id,
            revision=revision,
            suffix=suffix,
        ),
        declaration_approved=declaration_approved,
        risk_current=risk_current,
        policy_current=policy_current,
        policy_decision=policy_decision,
        enforcement_decision=enforcement_decision,
        evidence_complete=evidence_complete,
        limitations=limitations,
        captured_at=clock(),
    )


class Reader:
    def __init__(self, current: loop.AuthoritySnapshot) -> None:
        self.current = current
        self.reads: list[tuple[str, str]] = []
        self.sequence: list[loop.AuthoritySnapshot] = []
        self.failure: Exception | None = None

    def read_snapshot(self, *, tenant_id: str, asset_id: str) -> loop.AuthoritySnapshot:
        self.reads.append((tenant_id, asset_id))
        if self.failure is not None:
            raise self.failure
        if self.sequence:
            return self.sequence.pop(0)
        return self.current


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: Path, clock: Clock) -> loop.AIGovernanceLoopStore:
    return loop.AIGovernanceLoopStore(
        tmp_path / "ai-governance-loop.sqlite3",
        tenant_id=TENANT,
        config_gate=lambda: None,
        clock=clock,
    )


def trigger(
    clock: Clock,
    *,
    tenant_id: str = TENANT,
    asset_id: str = ASSET,
    code: str = "inventory_changed",
    revision: int = 1,
    suffix: str = "v1",
) -> loop.GovernanceTrigger:
    return loop.GovernanceTrigger(
        tenant_id=tenant_id,
        asset_id=asset_id,
        code=code,
        source_revision=revision,
        source_sha256=digest(f"trigger:{tenant_id}:{asset_id}:{suffix}"),
        occurred_at=clock(),
    )


def enqueue(store: loop.AIGovernanceLoopStore, clock: Clock, **kwargs) -> dict[str, object]:
    return store.enqueue(
        trigger(clock, **kwargs),
        idempotency_key=f"enqueue-{kwargs.get('revision', 1)}-{kwargs.get('suffix', 'v1')}",
    )


def coordinator(
    store: loop.AIGovernanceLoopStore,
    reader: Reader,
    **kwargs,
) -> loop.AIGovernanceLoopCoordinator:
    return loop.AIGovernanceLoopCoordinator(
        store=store,
        authority_reader=reader,
        lease_seconds=10,
        backoff_base_seconds=2,
        **kwargs,
    )


def test_complete_local_lifecycle_pins_every_authority_and_projects_audit(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock))
    queued = enqueue(store, clock)
    assert queued["state"] == "queued"
    result = coordinator(store, reader).run_once(worker_id="worker-primary")

    assert result is not None
    assert result["state"] == "monitoring"
    assert result["policy_decision"] == "allow"
    assert result["enforcement_decision"] == "allow"
    assert result["limitations"] == ()
    assert result["provider_mutation_performed"] is False
    assert result["raw_payloads_persisted"] is False
    assert set(result["authorities"]) >= {
        "inventory",
        "declaration",
        "risk",
        "policy",
        "enforcement",
        "evidence",
    }
    for name in ("inventory", "declaration", "risk", "policy", "enforcement", "evidence"):
        authority = result["authorities"][name]
        assert authority["tenant_id"] == TENANT
        assert authority["asset_id"] == ASSET
        assert authority["record_id"] == f"{name}-record"
        assert authority["revision"] == 1
        assert len(authority["sha256"]) == 64
    assert reader.reads == [(TENANT, ASSET), (TENANT, ASSET)]

    verified = store.verify_integrity(ASSET)
    assert verified["valid"] is True
    events = store.unified_audit_events()
    assert events
    assert {event.action for event in events} <= loop.AUDIT_ACTION_CODES
    assert all(event.source_id == event.suite_id == "ai_governance" for event in events)
    assert all(event.tenant_id == TENANT for event in events)
    records = store.unified_audit_records()
    assert records == tuple(event.to_source_record() for event in events)
    assert [record.sequence for record in records] == list(range(1, len(records) + 1))
    assert records[0].previous_sha256 == loop.GENESIS_SHA256
    assert all(
        current.previous_sha256 == previous.record_sha256
        for previous, current in zip(records[:-1], records[1:], strict=True)
    )


def test_restrict_and_block_require_human_authorization_and_observed_receipt(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    pending = snapshot(
        clock,
        policy_decision="restrict",
        enforcement_decision="not_applicable",
        evidence_complete=False,
    )
    reader = Reader(pending)
    enqueue(store, clock)
    escalated = coordinator(store, reader).run_once(worker_id="worker-restrict")
    assert escalated["state"] == "escalated"
    assert escalated["escalation_sha256"]
    assert "human_authorization_required" in escalated["limitations"]

    authorized = store.authorize_control(
        ASSET,
        decision="restrict",
        authorization_sha256=digest("human-approval-restrict"),
        expected_revision=escalated["revision"],
        idempotency_key="authorize-restrict",
    )
    assert authorized["state"] == "control_pending"
    assert authorized["control_authorized"] is True
    assert authorized["provider_mutation_performed"] is False

    reader.current = replace(
        pending,
        enforcement=pin("enforcement", revision=2, suffix="restricted"),
        enforcement_decision="restrict",
        evidence=pin("evidence", revision=2, suffix="complete"),
        evidence_complete=True,
    )
    observed = coordinator(store, reader).run_once(worker_id="worker-observe")
    assert observed["state"] == "restricted"
    assert observed["limitations"] == ()
    assert observed["provider_mutation_performed"] is False

    # A block follows the same human gate and cannot be authorized as restrict.
    clock.advance(1)
    reader.current = snapshot(
        clock,
        revision=3,
        suffix="block",
        policy_decision="block",
        enforcement_decision="not_applicable",
    )
    enqueue(store, clock, revision=2, suffix="block", code="policy_changed")
    blocked_pending = coordinator(store, reader).run_once(worker_id="worker-block")
    assert blocked_pending["state"] == "escalated"
    with pytest.raises(loop.AIGovernanceLoopConflict):
        store.authorize_control(
            ASSET,
            decision="restrict",
            authorization_sha256=digest("wrong-decision"),
            expected_revision=blocked_pending["revision"],
            idempotency_key="wrong-control",
        )


def test_control_authority_is_invalidated_by_policy_pin_change(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(
        snapshot(
            clock,
            policy_decision="block",
            enforcement_decision="not_applicable",
        )
    )
    enqueue(store, clock)
    first = coordinator(store, reader).run_once(worker_id="worker-one")
    approved = store.authorize_control(
        ASSET,
        decision="block",
        authorization_sha256=digest("approval-bound-to-policy-v1"),
        expected_revision=first["revision"],
        idempotency_key="approve-v1",
    )
    reader.current = replace(
        reader.current,
        policy=pin("policy", revision=2, suffix="v2"),
    )
    changed = coordinator(store, reader).run_once(worker_id="worker-two")
    assert changed["state"] == "escalated"
    assert "human_authorization_required" in changed["limitations"]
    assert approved["authorized_policy_sha256"] != reader.current.policy.sha256


def test_control_authorization_can_be_revoked_without_provider_mutation(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(
        snapshot(
            clock,
            policy_decision="restrict",
            enforcement_decision="not_applicable",
        )
    )
    enqueue(store, clock)
    escalated = coordinator(store, reader).run_once(worker_id="worker-one")
    authorized = store.authorize_control(
        ASSET,
        decision="restrict",
        authorization_sha256=digest("approval"),
        expected_revision=escalated["revision"],
        idempotency_key="approval",
    )
    revoked = store.revoke_control_authorization(
        ASSET,
        revocation_sha256=digest("revocation"),
        expected_revision=authorized["revision"],
        idempotency_key="revoke-approval",
    )
    assert revoked["state"] == "escalated"
    assert revoked["control_authorized"] is False
    assert revoked["provider_mutation_performed"] is False
    assert revoked["last_operation_sha256"]


@pytest.mark.parametrize(
    ("changes", "state", "limitation"),
    [
        ({"declaration_approved": False}, "review_required", "declaration_unapproved"),
        ({"risk_current": False}, "recovery_pending", "risk_stale"),
        ({"policy_current": False}, "recovery_pending", "policy_stale"),
        ({"evidence_complete": False}, "monitoring", "evidence_incomplete"),
    ],
)
def test_stale_or_incomplete_authorities_remain_explicit(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
    changes: dict[str, object],
    state: str,
    limitation: str,
) -> None:
    reader = Reader(replace(snapshot(clock), **changes))
    enqueue(store, clock)
    result = coordinator(store, reader).run_once(worker_id="worker-stale")
    assert result["state"] == state
    assert limitation in result["limitations"]


def test_double_read_allows_fresh_observation_of_identical_authority(store, clock):
    class RestampingReader(Reader):
        def read_snapshot(self, **kwargs):
            clock.advance(0.1)
            return replace(super().read_snapshot(**kwargs), captured_at=clock())
    reader = RestampingReader(snapshot(clock))
    enqueue(store, clock)
    assert coordinator(store, reader).run_once(worker_id="worker-fresh")["state"] == "monitoring"
    assert len(reader.reads) == 2


def test_double_read_authority_drift_fails_and_retries(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    first = snapshot(clock)
    second = snapshot(clock, revision=2, suffix="changed")
    reader = Reader(first)
    reader.sequence = [first, second]
    enqueue(store, clock)
    service = coordinator(store, reader)
    with pytest.raises(loop.AIGovernanceLoopAuthorityDrift):
        service.run_once(worker_id="worker-drift")
    failed = store.get_case(ASSET)
    assert failed["state"] == "recovery_pending"
    assert failed["limitations"] == ("authority_changed",)
    assert failed["work_pending"] is True

    clock.advance(2)
    reader.current = second
    recovered = service.run_once(worker_id="worker-recovered")
    assert recovered["state"] == "monitoring"


def test_exact_tenant_and_asset_binding_blocks_substitution(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    with pytest.raises(loop.AIGovernanceLoopValidationError):
        store.enqueue(
            trigger(clock, tenant_id=OTHER_TENANT),
            idempotency_key="wrong-tenant-trigger",
        )
    enqueue(store, clock)
    reader = Reader(snapshot(clock, asset_id=OTHER_ASSET))
    with pytest.raises(loop.AIGovernanceLoopValidationError):
        coordinator(store, reader).run_once(worker_id="worker-wrong-asset")
    failed = store.get_case(ASSET)
    assert failed["limitations"] == ("authority_unavailable",)

    other = loop.AIGovernanceLoopStore(
        store.path,
        tenant_id=OTHER_TENANT,
        config_gate=lambda: None,
        clock=clock,
    )
    assert other.get_case(ASSET) is None


def test_every_pin_must_match_the_snapshot_identity(clock: Clock) -> None:
    current = snapshot(clock)
    poisoned = replace(
        current,
        evidence=pin("evidence", tenant_id=OTHER_TENANT),
    )
    with pytest.raises(loop.AIGovernanceLoopValidationError, match="every authority pin"):
        poisoned.normalized(now=clock())


def test_closed_vocabulary_and_closed_snapshot_type_reject_raw_shapes(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    with pytest.raises(loop.AIGovernanceLoopValidationError):
        store.enqueue(
            trigger(clock, code="free form delete everything"),
            idempotency_key="invalid-trigger",
        )
    with pytest.raises(loop.AIGovernanceLoopValidationError):
        replace(snapshot(clock), limitations=("raw_provider_payload",)).normalized(now=clock())
    with pytest.raises(loop.AIGovernanceLoopValidationError):
        replace(snapshot(clock), policy_decision="free_form").normalized(now=clock())

    class RawReader:
        def read_snapshot(self, *, tenant_id: str, asset_id: str):
            del tenant_id, asset_id
            return {
                "prompt": "private prompt",
                "provider_payload": {"credential": "secret"},
            }

    enqueue(store, clock)
    service = loop.AIGovernanceLoopCoordinator(
        store=store,
        authority_reader=RawReader(),
        lease_seconds=10,
        backoff_base_seconds=2,
    )
    with pytest.raises(loop.AIGovernanceLoopValidationError, match="closed AuthoritySnapshot"):
        service.run_once(worker_id="worker-raw-shape")


def test_duplicate_and_out_of_order_triggers_are_stable(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    first = store.enqueue(trigger(clock), idempotency_key="enqueue-first")
    duplicate = store.enqueue(trigger(clock), idempotency_key="enqueue-duplicate")
    assert duplicate["revision"] == first["revision"]
    assert len(store.history(ASSET)) == 1

    with pytest.raises(loop.AIGovernanceLoopConflict, match="different content"):
        store.enqueue(
            trigger(clock, suffix="conflicting-same-revision"),
            idempotency_key="enqueue-conflict",
        )
    clock.advance(1)
    newer = store.enqueue(
        trigger(clock, revision=2, suffix="v2"),
        idempotency_key="enqueue-newer",
    )
    assert newer["revision"] == first["revision"] + 1
    with pytest.raises(loop.AIGovernanceLoopConflict, match="out of order"):
        store.enqueue(
            trigger(clock, revision=1, suffix="v1"),
            idempotency_key="enqueue-old",
        )


def test_authority_revisions_cannot_regress_or_change_decision_in_place(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock, revision=2, suffix="v2"))
    enqueue(store, clock)
    current = coordinator(store, reader).run_once(worker_id="worker-current")
    store.enqueue(
        trigger(clock, revision=2, suffix="trigger-v2"),
        idempotency_key="authority-recheck",
        expected_revision=current["revision"],
    )

    reader.current = snapshot(clock, revision=1, suffix="v1")
    with pytest.raises(loop.AIGovernanceLoopAuthorityDrift, match="regressed"):
        coordinator(store, reader).run_once(worker_id="worker-stale-authority")
    failed = store.get_case(ASSET)
    assert failed["limitations"] == ("authority_changed",)

    clock.advance(2)
    reader.current = snapshot(
        clock,
        revision=2,
        suffix="v2",
        policy_decision="block",
        enforcement_decision="not_applicable",
    )
    with pytest.raises(loop.AIGovernanceLoopAuthorityDrift, match="without an authority"):
        coordinator(store, reader).run_once(worker_id="worker-in-place-change")


def test_unified_audit_sequence_is_tenant_wide_across_assets(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock))
    enqueue(store, clock)
    coordinator(store, reader).run_once(worker_id="worker-first-asset")
    store.enqueue(
        trigger(clock, asset_id=OTHER_ASSET),
        idempotency_key="enqueue-second-asset",
    )
    reader.current = snapshot(clock, asset_id=OTHER_ASSET)
    coordinator(store, reader).run_once(worker_id="worker-second-asset")

    records = store.unified_audit_records()
    assert [record.sequence for record in records] == list(range(1, len(records) + 1))
    assert all(
        current.previous_sha256 == previous.record_sha256
        for previous, current in zip(records[:-1], records[1:], strict=True)
    )
    assert store.verify_integrity(ASSET)["unified_audit_count"] == len(records)
    assert store.verify_integrity(OTHER_ASSET)["unified_audit_count"] == len(records)


def test_idempotency_conflict_and_lost_ack_recovery(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    original = trigger(clock)
    store.enqueue(original, idempotency_key="stable-enqueue")
    with pytest.raises(loop.AIGovernanceLoopConflict, match="idempotency"):
        store.enqueue(
            replace(original, code="risk_changed"),
            idempotency_key="stable-enqueue",
        )

    class LostAcknowledgement(RuntimeError):
        pass

    reader = Reader(snapshot(clock))
    service = coordinator(
        store,
        reader,
        after_commit=lambda _result: (_ for _ in ()).throw(LostAcknowledgement()),
    )
    with pytest.raises(LostAcknowledgement):
        service.run_once(worker_id="worker-lost-ack")
    durable = store.get_case(ASSET)
    assert durable["state"] == "monitoring"
    assert durable["work_pending"] is False

    recovered = store.enqueue(original, idempotency_key="stable-enqueue")
    assert recovered["state"] == "monitoring"
    assert recovered["revision"] == durable["revision"]


def test_no_change_reconciliation_preserves_projection_revision(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock))
    enqueue(store, clock)
    first = coordinator(store, reader).run_once(worker_id="worker-first")
    clock.advance(1)
    queued = store.enqueue(
        trigger(clock, code="manual_reconcile", revision=2, suffix="manual"),
        idempotency_key="manual-reconcile",
        expected_revision=first["revision"],
    )
    result = coordinator(store, reader).run_once(worker_id="worker-no-change")
    assert result["no_change"] is True
    assert result["revision"] == queued["revision"]
    assert result["state"] == "monitoring"
    assert store.history(ASSET)[-1]["event_type"] == "reconciliation_no_change"


def test_expired_lease_is_reclaimed_and_old_worker_is_fenced(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock))
    enqueue(store, clock)
    first = store.claim_next(worker_id="worker-one", lease_seconds=5, max_attempts=5)
    assert first is not None
    clock.advance(6)
    second = store.claim_next(worker_id="worker-two", lease_seconds=5, max_attempts=5)
    assert second is not None
    assert second.generation > first.generation
    with pytest.raises(loop.AIGovernanceLoopLeaseLost):
        store.commit_reconciliation(first, reader.current)
    completed = store.commit_reconciliation(second, reader.current)
    assert completed["state"] == "monitoring"
    assert "lease_reclaimed" in {row["event_type"] for row in store.history(ASSET)}


def test_two_workers_cannot_claim_the_same_live_lease(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    enqueue(store, clock)

    def claim(worker: str):
        return store.claim_next(worker_id=worker, lease_seconds=10, max_attempts=5)

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(claim, ("worker-a", "worker-b")))
    assert sum(item is not None for item in claims) == 1


def test_bounded_retry_exhaustion_replay_and_restart_recovery(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock))
    reader.failure = RuntimeError("provider payload and credential must not persist")
    enqueue(store, clock)
    service = coordinator(store, reader, max_attempts=2)
    with pytest.raises(loop.AIGovernanceLoopValidationError):
        service.run_once(worker_id="worker-fail-one")
    first_failure = store.get_case(ASSET)
    assert first_failure["attempts"] == 1
    assert first_failure["state"] == "recovery_pending"
    clock.advance(2)
    with pytest.raises(loop.AIGovernanceLoopValidationError):
        service.run_once(worker_id="worker-fail-two")
    exhausted = store.get_case(ASSET)
    assert exhausted["state"] == "escalated"
    assert exhausted["limitations"] == ("retry_exhausted",)
    assert exhausted["work_pending"] is False

    replayed = store.replay(
        ASSET,
        authorization_sha256=digest("human-replay-approval"),
        expected_revision=exhausted["revision"],
        idempotency_key="replay-after-exhaustion",
    )
    assert replayed["attempts"] == 0
    assert replayed["work_pending"] is True
    reader.failure = None

    restarted_store = loop.AIGovernanceLoopStore(
        store.path,
        tenant_id=TENANT,
        config_gate=lambda: None,
        clock=clock,
    )
    recovered = coordinator(restarted_store, reader).run_once(worker_id="worker-after-restart")
    assert recovered["state"] == "monitoring"
    assert restarted_store.verify_integrity(ASSET)["valid"] is True


def test_rollback_requires_exact_authorization_and_reconciles_after_apply(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock))
    enqueue(store, clock)
    baseline = coordinator(store, reader).run_once(worker_id="worker-baseline")
    target_revision = baseline["revision"]

    clock.advance(1)
    reader.current = snapshot(
        clock,
        revision=2,
        suffix="review",
        policy_decision="review",
        enforcement_decision="not_applicable",
    )
    store.enqueue(
        trigger(clock, code="policy_changed", revision=2, suffix="review"),
        idempotency_key="policy-review",
    )
    changed = coordinator(store, reader).run_once(worker_id="worker-review")
    assert changed["state"] == "review_required"

    authorization = digest("rollback-authorization")
    pending = store.authorize_rollback(
        ASSET,
        target_revision=target_revision,
        authorization_sha256=authorization,
        expected_revision=changed["revision"],
        idempotency_key="authorize-rollback",
    )
    assert pending["state"] == "rollback_pending"
    with pytest.raises(loop.AIGovernanceLoopConflict):
        store.apply_authorized_rollback(
            ASSET,
            authorization_sha256=digest("wrong-rollback-authorization"),
            expected_revision=pending["revision"],
            idempotency_key="wrong-rollback",
        )
    applied = store.apply_authorized_rollback(
        ASSET,
        authorization_sha256=authorization,
        expected_revision=pending["revision"],
        idempotency_key="apply-rollback",
    )
    assert applied["state"] == "recovery_pending"
    assert applied["policy_decision"] == "allow"
    assert applied["limitations"] == ("rollback_applied_requires_reconciliation",)
    assert applied["provider_mutation_performed"] is False
    recovered_ack = store.apply_authorized_rollback(
        ASSET,
        authorization_sha256=authorization,
        expected_revision=pending["revision"],
        idempotency_key="apply-rollback",
    )
    assert recovered_ack["revision"] == applied["revision"]
    assert recovered_ack["state"] == applied["state"]
    reconciled = coordinator(store, reader).run_once(worker_id="worker-post-rollback")
    assert reconciled["policy_decision"] == "review"
    assert reconciled["state"] == "review_required"


def test_rollback_authorization_can_be_revoked(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock))
    enqueue(store, clock)
    current = coordinator(store, reader).run_once(worker_id="worker")
    pending = store.authorize_rollback(
        ASSET,
        target_revision=current["revision"],
        authorization_sha256=digest("rollback-auth"),
        expected_revision=current["revision"],
        idempotency_key="rollback-auth",
    )
    revoked = store.revoke_rollback_authorization(
        ASSET,
        revocation_sha256=digest("rollback-revocation"),
        expected_revision=pending["revision"],
        idempotency_key="rollback-revoke",
    )
    assert revoked["rollback_target_revision"] is None
    assert revoked["rollback_authorization_sha256"] is None
    assert revoked["state"] == "recovery_pending"
    assert revoked["work_pending"] is True


def test_case_revocation_is_terminal_until_a_new_explicit_trigger(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock))
    enqueue(store, clock)
    current = coordinator(store, reader).run_once(worker_id="worker")
    revoked = store.revoke_case(
        ASSET,
        revocation_sha256=digest("case-revocation"),
        expected_revision=current["revision"],
        idempotency_key="case-revocation",
    )
    assert revoked["state"] == "revoked"
    assert revoked["limitations"] == ("revoked",)
    assert revoked["work_pending"] is False
    assert revoked["provider_mutation_performed"] is False


def test_replay_of_a_revoked_case_is_refused(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock))
    enqueue(store, clock)
    current = coordinator(store, reader).run_once(worker_id="worker")
    revoked = store.revoke_case(
        ASSET,
        revocation_sha256=digest("case-revocation"),
        expected_revision=current["revision"],
        idempotency_key="case-revocation",
    )
    with pytest.raises(loop.AIGovernanceLoopConflict, match="revoked case cannot be replayed"):
        store.replay(
            ASSET,
            authorization_sha256=digest("replay-authorization"),
            expected_revision=revoked["revision"],
            idempotency_key="replay-after-revocation",
        )
    after = store.get_case(ASSET)
    assert after["state"] == "revoked"
    assert after["work_pending"] is False
    assert after["revision"] == revoked["revision"]


def test_history_and_projection_tampering_is_detected(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock))
    enqueue(store, clock)
    coordinator(store, reader).run_once(worker_id="worker")
    assert store.verify_integrity(ASSET)["valid"] is True
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE agl_history SET event_sha256=? WHERE tenant_id=? AND asset_id=? AND sequence=1",
            (digest("tampered-history"), TENANT, ASSET),
        )
    with pytest.raises(loop.AIGovernanceLoopIntegrityError):
        store.verify_integrity(ASSET)

    other = loop.AIGovernanceLoopStore(
        store.path.parent / "projection-tamper.sqlite3",
        tenant_id=TENANT,
        config_gate=lambda: None,
        clock=clock,
    )
    other.enqueue(trigger(clock), idempotency_key="projection-case")
    coordinator(other, reader).run_once(worker_id="worker")
    with sqlite3.connect(other.path) as connection:
        connection.execute(
            "UPDATE agl_cases SET authorities_sha256=? WHERE tenant_id=? AND asset_id=?",
            (digest("tampered-authority-projection"), TENANT, ASSET),
        )
    with pytest.raises(loop.AIGovernanceLoopIntegrityError):
        other.verify_integrity(ASSET)

    projection = loop.AIGovernanceLoopStore(
        store.path.parent / "state-projection-tamper.sqlite3",
        tenant_id=TENANT,
        config_gate=lambda: None,
        clock=clock,
    )
    projection.enqueue(trigger(clock), idempotency_key="state-projection-case")
    coordinator(projection, reader).run_once(worker_id="worker")
    with sqlite3.connect(projection.path) as connection:
        connection.execute(
            "UPDATE agl_cases SET state='blocked' WHERE tenant_id=? AND asset_id=?",
            (TENANT, ASSET),
        )
    with pytest.raises(loop.AIGovernanceLoopIntegrityError, match="projection"):
        projection.verify_integrity(ASSET)


def test_non_ascii_stored_digests_are_refused_not_type_errors(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    # Edited digests must not raise TypeError from hmac.compare_digest instead
    # of the store's idempotency conflict and integrity refusals.
    reader = Reader(snapshot(clock))
    original = trigger(clock)
    store.enqueue(original, idempotency_key="non-ascii-enqueue")
    coordinator(store, reader).run_once(worker_id="worker")
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE agl_operations SET request_sha256=?", ("é" * 64,))
        connection.execute(
            "UPDATE agl_history SET previous_sha256=? WHERE tenant_id=? AND asset_id=?",
            ("é" * 64, TENANT, ASSET),
        )
    with pytest.raises(loop.AIGovernanceLoopConflict, match="idempotency"):
        store.enqueue(original, idempotency_key="non-ascii-enqueue")
    with pytest.raises(loop.AIGovernanceLoopIntegrityError, match="predecessor"):
        store.verify_integrity(ASSET)


def test_raw_data_credentials_principals_and_idempotency_keys_do_not_persist(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock))
    raw_idempotency = "secret-idempotency-material"
    raw_worker = "secret-worker-principal"
    store.enqueue(trigger(clock), idempotency_key=raw_idempotency)
    coordinator(store, reader).run_once(worker_id=raw_worker)

    markers = (
        raw_idempotency,
        raw_worker,
        "private prompt text",
        "private model output",
        "raw provider telemetry",
        "provider credential secret",
    )
    persisted = b""
    for candidate in (store.path, Path(f"{store.path}-wal"), Path(f"{store.path}-shm")):
        if candidate.exists():
            persisted += candidate.read_bytes()
    for marker in markers:
        assert marker.encode("utf-8") not in persisted
    assert store.get_case(ASSET)["raw_payloads_persisted"] is False


def test_history_payload_is_closed_safe_json(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(snapshot(clock))
    enqueue(store, clock)
    coordinator(store, reader).run_once(worker_id="worker")
    allowed = {
        "schema",
        "tenant_id",
        "asset_id",
        "case_revision",
        "event_type",
        "state",
        "trigger_code",
        "trigger_revision",
        "trigger_sha256",
        "authorities_sha256",
        "policy_decision",
        "enforcement_decision",
        "limitations",
        "control_authorization_sha256",
        "authorized_policy_sha256",
        "authorized_decision",
        "escalation_sha256",
        "rollback_target_revision",
        "rollback_authorization_sha256",
        "last_operation_sha256",
        "work_pending",
        "next_attempt_at",
        "attempts",
        "lease_owner_sha256",
        "lease_token_sha256",
        "lease_generation",
        "lease_until",
        "updated_at",
        "occurred_at",
    }
    for event in store.history(ASSET):
        assert set(event["payload"]) == allowed
        canonical = json.dumps(
            event["payload"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        assert "prompt" not in canonical
        assert "credential" not in canonical
        assert "provider_payload" not in canonical
        assert "principal" not in canonical


@pytest.mark.parametrize("limit", [True, 0, 10_001, 1.5, "10"])
def test_history_limit_is_a_closed_bounded_integer(
    store: loop.AIGovernanceLoopStore,
    limit: object,
) -> None:
    with pytest.raises(loop.AIGovernanceLoopValidationError, match="integer bound"):
        store.history(ASSET, limit=limit)  # type: ignore[arg-type]


def test_cas_and_authorization_idempotency_are_exact(
    store: loop.AIGovernanceLoopStore,
    clock: Clock,
) -> None:
    reader = Reader(
        snapshot(
            clock,
            policy_decision="restrict",
            enforcement_decision="not_applicable",
        )
    )
    enqueue(store, clock)
    current = coordinator(store, reader).run_once(worker_id="worker")
    with pytest.raises(loop.AIGovernanceLoopConflict, match="stale"):
        store.authorize_control(
            ASSET,
            decision="restrict",
            authorization_sha256=digest("approval"),
            expected_revision=current["revision"] - 1,
            idempotency_key="stale-approval",
        )
    approved = store.authorize_control(
        ASSET,
        decision="restrict",
        authorization_sha256=digest("approval"),
        expected_revision=current["revision"],
        idempotency_key="exact-approval",
    )
    replayed_ack = store.authorize_control(
        ASSET,
        decision="restrict",
        authorization_sha256=digest("approval"),
        expected_revision=current["revision"],
        idempotency_key="exact-approval",
    )
    assert replayed_ack["revision"] == approved["revision"]
    with pytest.raises(loop.AIGovernanceLoopConflict, match="idempotency"):
        store.authorize_control(
            ASSET,
            decision="restrict",
            authorization_sha256=digest("different-approval"),
            expected_revision=approved["revision"],
            idempotency_key="exact-approval",
        )
