"""Regression attacks for unified-audit recovery, coverage, and minimization.

These tests intentionally describe the fail-closed contract rather than the
current implementation.  Keep the fixtures small and protocol-shaped so they
remain easy to adapt if the source or signed-sink receipt APIs evolve.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from threading import Event, Thread
from typing import Any

import pytest
from maverick.unified_audit import (
    GENESIS_SHA256,
    REQUIRED_SUITES,
    ProjectionReceipt,
    SourceAuthority,
    SourceVerification,
    UnifiedAuditConfig,
    UnifiedAuditError,
    UnifiedAuditIntegrityError,
    UnifiedAuditLeaseLost,
    UnifiedAuditProjector,
    UnifiedAuditRegistry,
    UnifiedAuditStore,
    UnifiedAuditValidationError,
    build_source_page,
    build_source_record,
    canonical_sha256,
)


def _sha(value: object) -> str:
    return canonical_sha256(value)


class Clock:
    def __init__(self, now: float = 10_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class MutableSource:
    def __init__(
        self,
        tenant_id: str,
        source_id: str,
        *,
        count: int = 1,
        watermark: float = 10_000.0,
        action: str = "record_changed",
    ) -> None:
        self.tenant_id = tenant_id
        self.source_id = source_id
        self.watermark = watermark
        self.action = action
        self.authority_revision = 1
        self.authority_sha256 = _sha(
            {"source_id": source_id, "authority_revision": 1}
        )
        self.source_schema_version = 1
        self.records = []
        for _ in range(count):
            self.grow()

    def authority(self) -> SourceAuthority:
        return SourceAuthority(
            tenant_id=self.tenant_id,
            source_id=self.source_id,
            suite_id=self.source_id,
            authority_revision=self.authority_revision,
            authority_sha256=self.authority_sha256,
            source_schema_version=self.source_schema_version,
        )

    def grow(self) -> None:
        sequence = len(self.records) + 1
        previous = self.records[-1].record_sha256 if self.records else GENESIS_SHA256
        self.records.append(
            build_source_record(
                sequence=sequence,
                occurred_at=min(self.watermark, 10_000.0) - 10 + sequence,
                action=self.action,
                actor_sha256=_sha({"actor": sequence}),
                resource_sha256=_sha({"resource": sequence}),
                payload_sha256=_sha({"payload": sequence}),
                previous_sha256=previous,
            )
        )

    def read_page(
        self,
        *,
        after_sequence: int,
        prior_sha256: str,
        previous_page_sha256: str,
        limit: int,
    ):
        selected = tuple(self.records[after_sequence : after_sequence + limit])
        terminal = after_sequence + len(selected) == len(self.records)
        return build_source_page(
            self.authority(),
            after_sequence=after_sequence,
            prior_sha256=prior_sha256,
            previous_page_sha256=previous_page_sha256,
            records=selected,
            terminal=terminal,
            complete=terminal,
            truncated=False,
            watermark=self.watermark,
            limitations=() if terminal else ("more_records_available",),
        )


class AuthorityFailsAfterRegistration(MutableSource):
    def __init__(self, tenant_id: str, source_id: str) -> None:
        super().__init__(tenant_id, source_id)
        self.authority_reads = 0

    def authority(self) -> SourceAuthority:
        self.authority_reads += 1
        if self.authority_reads > 1:
            raise RuntimeError("source authority is offline")
        return super().authority()


class SignedAnchoredVerifier:
    """Protocol-shaped verifier standing in for an independently trusted source."""

    def __init__(
        self,
        source_id: str,
        clock: Clock,
        *,
        revision: int = 1,
    ) -> None:
        self.source_id = source_id
        self.clock = clock
        self.revision = revision
        self._identity = _sha({"verifier": source_id, "revision": revision})

    @property
    def verifier_identity_sha256(self) -> str:
        return self._identity

    def verify_page(
        self,
        *,
        authority: SourceAuthority,
        page,
    ) -> SourceVerification:
        assert authority.source_id == self.source_id
        return SourceVerification(
            tenant_id=authority.tenant_id,
            source_id=authority.source_id,
            authority_revision=authority.authority_revision,
            authority_sha256=authority.authority_sha256,
            source_schema_version=authority.source_schema_version,
            page_sha256=page.page_sha256,
            verified_at=self.clock(),
            assurance_level="signed_anchored",
            verifier_identity_sha256=self._identity,
            trust_root_revision=self.revision,
            key_id_sha256=_sha(
                {"source_key": self.source_id, "revision": self.revision}
            ),
            anchor_sha256=_sha({"source_anchor": page.page_sha256}),
            snapshot_head_sha256=page.head_sha256,
            snapshot_record_count=page.last_sequence,
            retention_complete=True,
            limitations=(),
        )


def _register(
    registry: UnifiedAuditRegistry,
    source: MutableSource,
    clock: Clock,
    *,
    verifier_revision: int = 1,
) -> None:
    registry.register(
        source,
        verifier=SignedAnchoredVerifier(
            source.source_id,
            clock,
            revision=verifier_revision,
        ),
    )


class AppendOnceSink:
    """In-memory model of a durable append with possibly lost acknowledgement."""

    def __init__(self, tenant_id: str = "tenant-a") -> None:
        self.ready = True
        self.events: dict[str, dict[str, Any]] = {}
        self.lose_next_new_ack = False
        self.conflicts = 0
        self._tenant_sha256 = hashlib.sha256(
            f"lightwork.unified-audit.tenant.v1:{tenant_id}".encode()
        ).hexdigest()
        self._sink_identity_sha256 = _sha(
            {"sink": "adversarial-test", "tenant_sha256": self._tenant_sha256}
        )

    @property
    def tenant_sha256(self) -> str:
        return self._tenant_sha256

    @property
    def sink_identity_sha256(self) -> str:
        return self._sink_identity_sha256

    @property
    def signing_ready(self) -> bool:
        return self.ready

    def append(self, event) -> ProjectionReceipt:
        payload = dict(event)
        identity = payload["projection_event_id"]
        current = self.events.get(identity)
        if current is not None:
            if current != payload:
                self.conflicts += 1
                raise UnifiedAuditIntegrityError(
                    "stable projection identity changed during retry"
                )
            return self._receipt(payload)
        self.events[identity] = payload
        if self.lose_next_new_ack:
            self.lose_next_new_ack = False
            raise UnifiedAuditError("durable append acknowledgement was lost")
        return self._receipt(payload)

    def _receipt(self, payload: dict[str, Any]) -> ProjectionReceipt:
        identity = payload["projection_event_id"]
        return ProjectionReceipt(
            projection_event_id=identity,
            event_sha256=canonical_sha256(payload),
            tenant_sha256=self._tenant_sha256,
            sink_identity_sha256=self._sink_identity_sha256,
            key_id_sha256=_sha({"sink_key": "adversarial-test", "revision": 1}),
            chain_sha256=_sha({"chain": identity}),
            signature_sha256=_sha({"signature": identity}),
        )


def _store(tmp_path: Path, clock: Clock) -> UnifiedAuditStore:
    return UnifiedAuditStore(
        tmp_path / "unified-audit.sqlite3",
        tenant_id="tenant-a",
        clock=clock,
    )


def _projector(
    *,
    registry: UnifiedAuditRegistry,
    store: UnifiedAuditStore,
    sink: AppendOnceSink,
    max_attempts: int = 5,
) -> UnifiedAuditProjector:
    return UnifiedAuditProjector(
        registry=registry,
        store=store,
        sink=sink,
        config=UnifiedAuditConfig(
            enable=True,
            retry_backoff_seconds=0,
            max_attempts=max_attempts,
        ),
    )


def test_lost_ack_retry_survives_source_growth_without_projection_collision(
    tmp_path: Path,
) -> None:
    """Record identity must not be coupled to a mutable page envelope."""

    clock = Clock()
    source = MutableSource("tenant-a", "ai_governance", count=1)
    registry = UnifiedAuditRegistry("tenant-a")
    _register(registry, source, clock)
    sink = AppendOnceSink()
    sink.lose_next_new_ack = True
    store = _store(tmp_path, clock)
    projector = _projector(registry=registry, store=store, sink=sink)

    with pytest.raises(UnifiedAuditError):
        projector.run_source("ai_governance", worker_id="worker:one")
    assert next(
        state
        for state in store.source_states()
        if state["source_id"] == "ai_governance"
    )["cursor_sequence"] == 0

    source.grow()
    result = projector.run_source("ai_governance", worker_id="worker:one")

    assert result.cursor_sequence == 2
    assert sink.conflicts == 0
    assert sum(
        event.get("source_sequence") == 1 for event in sink.events.values()
    ) == 1


def test_empty_complete_page_requires_a_signed_page_receipt(tmp_path: Path) -> None:
    """Completeness may not exist only in mutable local cursor state."""

    clock = Clock()
    source = MutableSource("tenant-a", "ai_governance", count=0)
    registry = UnifiedAuditRegistry("tenant-a")
    _register(registry, source, clock)
    sink = AppendOnceSink()
    projector = _projector(
        registry=registry,
        store=_store(tmp_path, clock),
        sink=sink,
    )

    result = projector.run_source("ai_governance", worker_id="worker:one")

    receipts = [
        event
        for event in sink.events.values()
        if event.get("source_page_sha256") == result.page_sha256
        and event.get("source_complete") is True
    ]
    assert receipts, "an empty terminal page needs an append-before-cursor receipt"


def test_future_source_watermark_cannot_make_coverage_current(tmp_path: Path) -> None:
    clock = Clock()
    source = MutableSource(
        "tenant-a",
        "ai_governance",
        count=0,
        watermark=99_000_000_000.0,
    )
    registry = UnifiedAuditRegistry("tenant-a")
    _register(registry, source, clock)
    store = _store(tmp_path, clock)
    projector = _projector(
        registry=registry,
        store=store,
        sink=AppendOnceSink(),
    )

    try:
        projector.run_source("ai_governance", worker_id="worker:one")
    except UnifiedAuditError:
        pass

    state = next(
        item
        for item in store.status(max_lag_seconds=300)["sources"]
        if item["source_id"] == "ai_governance"
    )
    assert state["complete"] is False
    assert state["current"] is False


def test_source_page_cannot_exceed_absolute_500_record_bound() -> None:
    source = MutableSource("tenant-a", "ai_governance", count=0)
    records = []
    previous = GENESIS_SHA256
    for sequence in range(1, 502):
        record = build_source_record(
            sequence=sequence,
            occurred_at=9_000.0 + sequence,
            action="record_changed",
            actor_sha256=_sha({"actor": sequence}),
            resource_sha256=_sha({"resource": sequence}),
            payload_sha256=_sha({"payload": sequence}),
            previous_sha256=previous,
        )
        records.append(record)
        previous = record.record_sha256

    with pytest.raises(UnifiedAuditValidationError, match="absolute record bound"):
        build_source_page(
            source.authority(),
            after_sequence=0,
            prior_sha256=GENESIS_SHA256,
            previous_page_sha256=GENESIS_SHA256,
            records=records,
            terminal=True,
            complete=True,
            truncated=False,
            watermark=10_000.0,
        )


def test_source_record_cannot_occur_after_page_watermark() -> None:
    source = MutableSource("tenant-a", "ai_governance", count=0)
    record = build_source_record(
        sequence=1,
        occurred_at=10_001.0,
        action="record_changed",
        actor_sha256=_sha({"actor": 1}),
        resource_sha256=_sha({"resource": 1}),
        payload_sha256=_sha({"payload": 1}),
        previous_sha256=GENESIS_SHA256,
    )

    with pytest.raises(UnifiedAuditIntegrityError, match="after the page watermark"):
        build_source_page(
            source.authority(),
            after_sequence=0,
            prior_sha256=GENESIS_SHA256,
            previous_page_sha256=GENESIS_SHA256,
            records=(record,),
            terminal=True,
            complete=True,
            truncated=False,
            watermark=10_000.0,
        )


def test_missing_live_registry_source_invalidates_prior_green_coverage(
    tmp_path: Path,
) -> None:
    clock = Clock()
    sources = [
        MutableSource("tenant-a", source_id, count=0)
        for source_id in REQUIRED_SUITES
    ]
    first_registry = UnifiedAuditRegistry("tenant-a")
    for source in sources:
        _register(first_registry, source, clock)
    store = _store(tmp_path, clock)
    sink = AppendOnceSink()
    first = _projector(registry=first_registry, store=store, sink=sink)
    first.run_all(worker_id="worker:one")
    assert first.status()["complete"] is True

    restarted_registry = UnifiedAuditRegistry("tenant-a")
    for source in sources[:-1]:
        _register(restarted_registry, source, clock)
    restarted = _projector(
        registry=restarted_registry,
        store=store,
        sink=sink,
    )
    results = restarted.run_all(worker_id="worker:two")

    assert results[-1].outcome == "unavailable"
    assert restarted.status()["complete"] is False


def test_status_never_goes_green_across_a_sweep_generation_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()
    sources = [
        MutableSource("tenant-a", source_id, count=0)
        for source_id in REQUIRED_SUITES
    ]
    registry = UnifiedAuditRegistry("tenant-a")
    for source in sources:
        _register(registry, source, clock)
    store = _store(tmp_path, clock)
    projector = _projector(
        registry=registry,
        store=store,
        sink=AppendOnceSink(),
    )
    projector.run_all(worker_id="worker:one")
    assert projector.status()["complete"] is True

    original_snapshot = store._verified_snapshot
    writer_start = Event()
    writer_done = Event()

    def begin_next_sweep() -> None:
        assert writer_start.wait(timeout=5)
        store.begin_sweep()
        writer_done.set()

    def snapshot_after_next_sweep():
        writer_start.set()
        assert writer_done.wait(timeout=5)
        return original_snapshot()

    writer = Thread(target=begin_next_sweep)
    writer.start()
    try:
        # The new sweep commits after status starts but before its read
        # snapshot.  Old success generations must not remain green.
        monkeypatch.setattr(store, "_verified_snapshot", snapshot_after_next_sweep)
        assert projector.status()["complete"] is False
    finally:
        writer.join(timeout=5)
    assert not writer.is_alive()


def test_integrity_snapshot_tolerates_a_concurrent_valid_state_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()
    source = MutableSource("tenant-a", "ai_governance")
    store = _store(tmp_path, clock)
    store.bind_source(source.authority())
    original_read = store._read_state_on
    snapshot_started = Event()
    writer_done = Event()
    first_read = True

    def pause_after_first_read(connection, source_id):
        nonlocal first_read
        state = original_read(connection, source_id)
        if first_read:
            first_read = False
            snapshot_started.set()
            assert writer_done.wait(timeout=5)
        return state

    monkeypatch.setattr(store, "_read_state_on", pause_after_first_read)
    reports: list[dict[str, Any]] = []
    errors: list[BaseException] = []

    def verify_snapshot() -> None:
        try:
            reports.append(store.verify_integrity())
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    reader = Thread(target=verify_snapshot)
    reader.start()
    assert snapshot_started.wait(timeout=5)
    store.claim(
        "ai_governance",
        worker_id="worker:concurrent",
        lease_seconds=30,
        max_attempts=5,
    )
    writer_done.set()
    reader.join(timeout=5)

    assert not reader.is_alive()
    assert errors == []
    assert reports and reports[0]["valid"] is True


def test_unapproved_verifier_and_source_key_rotation_fails_closed(
    tmp_path: Path,
) -> None:
    clock = Clock()
    source = MutableSource("tenant-a", "ai_governance", count=0)
    store = _store(tmp_path, clock)
    sink = AppendOnceSink()
    original_registry = UnifiedAuditRegistry("tenant-a")
    _register(original_registry, source, clock, verifier_revision=1)
    original = _projector(registry=original_registry, store=store, sink=sink)
    original.run_source("ai_governance", worker_id="worker:one")
    original_state = next(
        state
        for state in store.source_states()
        if state["source_id"] == "ai_governance"
    )
    assert original_state["complete"] is True

    changed_registry = UnifiedAuditRegistry("tenant-a")
    _register(changed_registry, source, clock, verifier_revision=2)
    changed = _projector(registry=changed_registry, store=store, sink=sink)

    with pytest.raises(UnifiedAuditError):
        changed.run_source("ai_governance", worker_id="worker:two")

    changed_state = next(
        state
        for state in store.source_states()
        if state["source_id"] == "ai_governance"
    )
    assert (
        changed_state["verifier_identity_sha256"]
        == original_state["verifier_identity_sha256"]
    )
    assert changed_state["source_key_id_sha256"] == original_state[
        "source_key_id_sha256"
    ]
    assert changed_state["trust_root_revision"] == original_state[
        "trust_root_revision"
    ]


def test_arbitrary_source_exception_does_not_abort_remaining_suite_sweep(
    tmp_path: Path,
) -> None:
    clock = Clock()
    sources = [AuthorityFailsAfterRegistration("tenant-a", REQUIRED_SUITES[0])]
    sources.extend(
        MutableSource("tenant-a", source_id, count=0)
        for source_id in REQUIRED_SUITES[1:]
    )
    registry = UnifiedAuditRegistry("tenant-a")
    for source in sources:
        _register(registry, source, clock)
    projector = _projector(
        registry=registry,
        store=_store(tmp_path, clock),
        sink=AppendOnceSink(),
    )

    results = projector.run_all(worker_id="worker:one")

    assert len(results) == len(REQUIRED_SUITES)
    assert results[0].outcome == "failed"
    assert all(result.outcome == "committed" for result in results[1:])
    assert projector.status()["complete"] is False


def test_deleted_history_cannot_verify_as_valid_genesis(tmp_path: Path) -> None:
    clock = Clock()
    store = _store(tmp_path, clock)
    source = MutableSource("tenant-a", "ai_governance")
    store.bind_source(source.authority())
    assert store.verify_integrity()["history_events"] > 0

    # Simulate an offline/privileged SQLite rewrite against this disposable DB.
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER unified_history_no_update")
        connection.execute("DROP TRIGGER unified_history_no_delete")
        connection.execute("DELETE FROM unified_history")

    with pytest.raises(UnifiedAuditIntegrityError):
        store.verify_integrity()


def test_expired_lease_reclaims_consume_retry_budget(tmp_path: Path) -> None:
    clock = Clock()
    store = _store(tmp_path, clock)
    source = MutableSource("tenant-a", "ai_governance")
    store.bind_source(source.authority())

    store.claim(
        "ai_governance",
        worker_id="worker:one",
        lease_seconds=30,
        max_attempts=2,
    )
    clock.now += 31
    store.claim(
        "ai_governance",
        worker_id="worker:two",
        lease_seconds=30,
        max_attempts=2,
    )
    clock.now += 31

    with pytest.raises(UnifiedAuditError, match="retry limit|exhausted"):
        store.claim(
            "ai_governance",
            worker_id="worker:three",
            lease_seconds=30,
            max_attempts=2,
        )


def test_expired_claim_cannot_mutate_failure_state(tmp_path: Path) -> None:
    clock = Clock()
    store = _store(tmp_path, clock)
    source = MutableSource("tenant-a", "ai_governance")
    store.bind_source(source.authority())
    claim = store.claim(
        "ai_governance",
        worker_id="worker:one",
        lease_seconds=30,
        max_attempts=5,
    )
    clock.now += 31

    with pytest.raises(UnifiedAuditLeaseLost):
        store.fail_claim(
            claim,
            error_code="source_dependency_unavailable",
            retry_backoff_seconds=0,
        )


def test_adapter_controlled_action_token_is_never_persisted_verbatim(
    tmp_path: Path,
) -> None:
    marker = "patient_jane_doe"
    try:
        source = MutableSource(
            "tenant-a",
            "ai_governance",
            action=marker,
        )
    except UnifiedAuditValidationError:
        return  # Rejecting non-enumerated actions at the contract is acceptable.

    clock = Clock()
    registry = UnifiedAuditRegistry("tenant-a")
    _register(registry, source, clock)
    sink = AppendOnceSink()
    projector = _projector(
        registry=registry,
        store=_store(tmp_path, clock),
        sink=sink,
    )
    projector.run_source("ai_governance", worker_id="worker:one")

    persisted = json.dumps(tuple(sink.events.values()), sort_keys=True)
    assert marker not in persisted
