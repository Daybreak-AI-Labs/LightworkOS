"""Adversarial coverage for the fixed six-suite unified-audit projector."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from maverick.audit.writer import AuditLog
from maverick.paths import data_dir
from maverick.unified_audit import (
    GENESIS_SHA256,
    REQUIRED_SUITES,
    ProjectionReceipt,
    ProjectionRunResult,
    SourceAuthority,
    SourcePage,
    SourceVerification,
    StrictAuditProjectionSink,
    UnifiedAuditConfig,
    UnifiedAuditConfigError,
    UnifiedAuditConflict,
    UnifiedAuditError,
    UnifiedAuditIntegrityError,
    UnifiedAuditLeaseLost,
    UnifiedAuditProjector,
    UnifiedAuditRegistry,
    UnifiedAuditStore,
    build_source_page,
    build_source_record,
    canonical_sha256,
    enabled,
    require_enabled,
)


def _sha(value: object) -> str:
    return canonical_sha256(value)


class Clock:
    def __init__(self, now: float = 10_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class FakeSource:
    def __init__(
        self,
        tenant_id: str,
        source_id: str,
        *,
        count: int = 2,
        watermark: float = 10_000.0,
    ) -> None:
        self.tenant_id = tenant_id
        self.source_id = source_id
        self.authority_revision = 1
        self.authority_sha256 = _sha({"source": source_id, "revision": 1})
        self.source_schema_version = 1
        self.watermark = watermark
        self.authority_reads = 0
        self._records = []
        previous = GENESIS_SHA256
        for sequence in range(1, count + 1):
            record = build_source_record(
                sequence=sequence,
                occurred_at=watermark - count + sequence,
                action="record_changed",
                actor_sha256=_sha({"actor": sequence}),
                resource_sha256=_sha({"resource": sequence}),
                payload_sha256=_sha({"payload": sequence}),
                previous_sha256=previous,
            )
            self._records.append(record)
            previous = record.record_sha256

    def authority(self) -> SourceAuthority:
        self.authority_reads += 1
        return SourceAuthority(
            tenant_id=self.tenant_id,
            source_id=self.source_id,
            suite_id=self.source_id,
            authority_revision=self.authority_revision,
            authority_sha256=self.authority_sha256,
            source_schema_version=self.source_schema_version,
        )

    def read_page(
        self,
        *,
        after_sequence: int,
        prior_sha256: str,
        previous_page_sha256: str,
        limit: int,
    ) -> SourcePage:
        selected = tuple(self._records[after_sequence : after_sequence + limit])
        terminal = after_sequence + len(selected) == len(self._records)
        limitations = () if terminal else ("more_records_available",)
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
            limitations=limitations,
        )


class StaticPageSource(FakeSource):
    def __init__(self, tenant_id: str, source_id: str, page: SourcePage) -> None:
        super().__init__(tenant_id, source_id, count=0, watermark=page.watermark)
        self.page = page
        self.authority_revision = page.authority_revision
        self.authority_sha256 = page.authority_sha256
        self.source_schema_version = page.source_schema_version

    def read_page(self, **_kwargs: Any) -> SourcePage:
        return self.page


class FakeSignedSink:
    def __init__(self, tenant_id: str = "tenant-a") -> None:
        self.ready = True
        self.events: dict[str, dict[str, Any]] = {}
        self.new_appends = 0
        self.lose_ack_on_new_append: int | None = None
        self._tenant_sha256 = hashlib.sha256(
            f"lightwork.unified-audit.tenant.v1:{tenant_id}".encode()
        ).hexdigest()
        self._sink_identity_sha256 = _sha(f"sink:{tenant_id}")

    @property
    def tenant_sha256(self) -> str:
        return self._tenant_sha256

    @property
    def sink_identity_sha256(self) -> str:
        return self._sink_identity_sha256

    @property
    def signing_ready(self) -> bool:
        return self.ready

    def _receipt(self, payload: dict[str, Any]) -> ProjectionReceipt:
        identity = payload["projection_event_id"]
        return ProjectionReceipt(
            projection_event_id=identity,
            event_sha256=canonical_sha256(payload),
            tenant_sha256=self.tenant_sha256,
            sink_identity_sha256=self.sink_identity_sha256,
            key_id_sha256=_sha("fake-sink-key"),
            chain_sha256=_sha({"chain": identity}),
            signature_sha256=_sha({"signature": identity}),
        )

    def append(self, event) -> ProjectionReceipt:
        payload = dict(event)
        identity = payload["projection_event_id"]
        current = self.events.get(identity)
        if current is not None:
            if current != payload:
                raise UnifiedAuditIntegrityError("projection identity collision")
            return self._receipt(payload)
        self.events[identity] = payload
        self.new_appends += 1
        if self.lose_ack_on_new_append == self.new_appends:
            raise UnifiedAuditError("simulated durable append with lost acknowledgement")
        return self._receipt(payload)


class FakeSourceVerifier:
    def __init__(self, tenant_id: str, source_id: str, *, now: float = 10_000.0) -> None:
        self.tenant_id = tenant_id
        self.source_id = source_id
        self.now = now
        self._identity = _sha({"verifier": source_id})

    @property
    def verifier_identity_sha256(self) -> str:
        return self._identity

    def verify_page(
        self,
        *,
        authority: SourceAuthority,
        page: SourcePage,
    ) -> SourceVerification:
        return SourceVerification(
            tenant_id=self.tenant_id,
            source_id=self.source_id,
            authority_revision=authority.authority_revision,
            authority_sha256=authority.authority_sha256,
            source_schema_version=authority.source_schema_version,
            page_sha256=page.page_sha256,
            verified_at=max(self.now, page.watermark),
            assurance_level="signed_anchored",
            verifier_identity_sha256=self.verifier_identity_sha256,
            trust_root_revision=1,
            key_id_sha256=_sha({"source-key": self.source_id}),
            anchor_sha256=_sha({"anchor": page.page_sha256}),
            snapshot_head_sha256=page.head_sha256,
            snapshot_record_count=page.last_sequence,
            retention_complete=True,
        )


class SelfAssertedVerifier(FakeSourceVerifier):
    def verify_page(
        self,
        *,
        authority: SourceAuthority,
        page: SourcePage,
    ) -> SourceVerification:
        return SourceVerification(
            tenant_id=self.tenant_id,
            source_id=self.source_id,
            authority_revision=authority.authority_revision,
            authority_sha256=authority.authority_sha256,
            source_schema_version=authority.source_schema_version,
            page_sha256=page.page_sha256,
            verified_at=max(self.now, page.watermark),
            assurance_level="self_asserted",
            verifier_identity_sha256=self.verifier_identity_sha256,
            trust_root_revision=0,
            key_id_sha256=GENESIS_SHA256,
            anchor_sha256=GENESIS_SHA256,
            snapshot_head_sha256=page.head_sha256,
            snapshot_record_count=page.last_sequence,
            retention_complete=False,
            limitations=("source_integrity_unverified",),
        )


def _store(tmp_path: Path, clock: Clock, tenant: str = "tenant-a") -> UnifiedAuditStore:
    return UnifiedAuditStore(
        tmp_path / f"{tenant}.sqlite3",
        tenant_id=tenant,
        clock=clock,
    )


def _projector(
    tmp_path: Path,
    clock: Clock,
    *,
    sources: tuple[FakeSource, ...],
    sink: FakeSignedSink | None = None,
    config: UnifiedAuditConfig | None = None,
) -> tuple[UnifiedAuditProjector, UnifiedAuditStore, FakeSignedSink]:
    registry = UnifiedAuditRegistry("tenant-a")
    for source in sources:
        registry.register(
            source,
            verifier=FakeSourceVerifier("tenant-a", source.source_id, now=clock.now),
        )
    store = _store(tmp_path, clock)
    selected_sink = sink or FakeSignedSink()
    projector = UnifiedAuditProjector(
        registry=registry,
        store=store,
        sink=selected_sink,
        config=config or UnifiedAuditConfig(enable=True),
    )
    return projector, store, selected_sink


def test_config_is_default_off_closed_and_requires_signing() -> None:
    assert enabled({}) is False
    assert enabled({"audit": {"sign": True, "unified": {"enable": True}}}) is True
    with pytest.raises(UnifiedAuditConfigError):
        require_enabled({"audit": {"unified": {"enable": True}}})
    with pytest.raises(UnifiedAuditConfigError):
        UnifiedAuditConfig.from_mapping(
            {"audit": {"unified": {"enable": False, "sources": ["ai_governance"]}}}
        )


def test_record_and_page_contract_reject_digest_count_and_completeness_lies() -> None:
    authority = SourceAuthority(
        tenant_id="tenant-a",
        source_id="ai_governance",
        suite_id="ai_governance",
        authority_revision=1,
        authority_sha256=_sha("authority"),
    )
    record = build_source_record(
        sequence=1,
        occurred_at=9_999.0,
        action="record_changed",
        actor_sha256=_sha("actor"),
        resource_sha256=_sha("resource"),
        payload_sha256=_sha("payload"),
        previous_sha256=GENESIS_SHA256,
    )
    page = build_source_page(
        authority,
        after_sequence=0,
        prior_sha256=GENESIS_SHA256,
        previous_page_sha256=GENESIS_SHA256,
        records=(record,),
        terminal=True,
        complete=True,
        truncated=False,
        watermark=10_000.0,
    )
    assert page.record_count == 1

    with pytest.raises(UnifiedAuditIntegrityError):
        replace(record, payload_sha256=_sha("changed"))
    with pytest.raises(UnifiedAuditIntegrityError):
        replace(page, record_count=2)
    with pytest.raises((UnifiedAuditConfigError, ValueError)):
        build_source_page(
            authority,
            after_sequence=0,
            prior_sha256=GENESIS_SHA256,
            previous_page_sha256=GENESIS_SHA256,
            records=(),
            terminal=True,
            complete=False,
            truncated=False,
            watermark=10_000.0,
        )


def test_store_bootstraps_exact_six_incomplete_sources_and_tenant_binds_file(
    tmp_path: Path,
) -> None:
    clock = Clock()
    path = tmp_path / "unified.sqlite3"
    store = UnifiedAuditStore(path, tenant_id="tenant-a", clock=clock)
    status = store.status(max_lag_seconds=300)
    assert tuple(item["source_id"] for item in status["sources"]) == REQUIRED_SUITES
    assert status["complete"] is False
    assert all(not item["registered"] for item in status["sources"])
    assert store.verify_integrity()["valid"] is True
    with pytest.raises(UnifiedAuditIntegrityError):
        UnifiedAuditStore(path, tenant_id="tenant-b", clock=clock)


def test_six_suite_run_is_digest_only_and_complete_only_after_every_source(
    tmp_path: Path,
) -> None:
    clock = Clock()
    sources = tuple(FakeSource("tenant-a", source_id) for source_id in REQUIRED_SUITES)
    projector, store, sink = _projector(tmp_path, clock, sources=sources)
    results = projector.run_all(worker_id="scheduler:one")
    assert all(isinstance(item, ProjectionRunResult) for item in results)
    assert all(item.outcome == "committed" and item.complete for item in results)
    status = projector.status()
    assert status["complete"] is True
    assert len(sink.events) == len(REQUIRED_SUITES) * 3
    assert store.verify_integrity()["valid"] is True
    for event in sink.events.values():
        assert event["tenant_sha256"] != "tenant-a"
        assert event["raw_source_payload_persisted"] is False
        assert not any(
            key in event
            for key in ("actor", "actor_id", "resource", "resource_id", "payload")
        )


def test_absent_required_source_never_turns_coverage_green(tmp_path: Path) -> None:
    clock = Clock()
    sources = tuple(FakeSource("tenant-a", source_id) for source_id in REQUIRED_SUITES[:-1])
    projector, _store_value, _sink = _projector(tmp_path, clock, sources=sources)
    results = projector.run_all(worker_id="scheduler:one")
    assert results[-1].outcome == "unavailable"
    assert projector.status()["complete"] is False


def test_self_asserted_source_and_cross_tenant_sink_never_turn_green(
    tmp_path: Path,
) -> None:
    clock = Clock()
    source = FakeSource("tenant-a", "ai_governance", count=0)
    registry = UnifiedAuditRegistry("tenant-a")
    registry.register(
        source,
        verifier=SelfAssertedVerifier("tenant-a", "ai_governance", now=clock.now),
    )
    store = _store(tmp_path, clock)
    sink = FakeSignedSink()
    projector = UnifiedAuditProjector(
        registry=registry,
        store=store,
        sink=sink,
        config=UnifiedAuditConfig(enable=True),
    )
    result = projector.run_source("ai_governance", worker_id="worker:one")
    assert result.complete is False
    state = store.source_states()[0]
    assert state["assurance_level"] == "self_asserted"
    assert state["limitations"] == ["source_integrity_unverified"]
    assert projector.status()["complete"] is False

    with pytest.raises(UnifiedAuditConfigError, match="tenant binding"):
        UnifiedAuditProjector(
            registry=registry,
            store=store,
            sink=FakeSignedSink("tenant-b"),
            config=UnifiedAuditConfig(enable=True),
        )


def test_lost_ack_does_not_advance_cursor_and_replay_appends_once(tmp_path: Path) -> None:
    clock = Clock()
    source = FakeSource("tenant-a", "ai_governance")
    sink = FakeSignedSink()
    sink.lose_ack_on_new_append = 2
    projector, store, _ = _projector(
        tmp_path,
        clock,
        sources=(source,),
        sink=sink,
        config=UnifiedAuditConfig(enable=True, retry_backoff_seconds=0),
    )
    with pytest.raises(Exception, match="lost acknowledgement"):
        projector.run_source("ai_governance", worker_id="worker:one")
    state = {item["source_id"]: item for item in store.source_states()}["ai_governance"]
    assert state["cursor_sequence"] == 0
    assert state["attempts"] == 1
    assert len(sink.events) == 2

    sink.lose_ack_on_new_append = None
    result = projector.run_source("ai_governance", worker_id="worker:one")
    assert result.cursor_sequence == 2
    assert len(sink.events) == 3


def test_tampered_page_is_revalidated_at_projector_boundary(tmp_path: Path) -> None:
    clock = Clock()
    good = FakeSource("tenant-a", "ai_governance")
    page = good.read_page(
        after_sequence=0,
        prior_sha256=GENESIS_SHA256,
        previous_page_sha256=GENESIS_SHA256,
        limit=100,
    )
    object.__setattr__(page, "page_sha256", _sha("tampered-page"))
    bad = StaticPageSource("tenant-a", "ai_governance", page)
    projector, store, _sink = _projector(
        tmp_path,
        clock,
        sources=(bad,),
        config=UnifiedAuditConfig(enable=True, retry_backoff_seconds=0),
    )
    with pytest.raises(UnifiedAuditIntegrityError, match="page digest"):
        projector.run_source("ai_governance", worker_id="worker:one")
    state = {item["source_id"]: item for item in store.source_states()}["ai_governance"]
    assert state["cursor_sequence"] == 0
    assert state["error_code"] == "source_integrity_failed"


def test_signing_readiness_is_required_before_and_after_each_append(tmp_path: Path) -> None:
    clock = Clock()
    source = FakeSource("tenant-a", "ai_governance", count=1)
    sink = FakeSignedSink()
    sink.ready = False
    projector, store, _ = _projector(
        tmp_path,
        clock,
        sources=(source,),
        sink=sink,
        config=UnifiedAuditConfig(enable=True, retry_backoff_seconds=0),
    )
    with pytest.raises(UnifiedAuditConfigError, match="not ready"):
        projector.run_source("ai_governance", worker_id="worker:one")
    assert store.source_states()[0]["cursor_sequence"] == 0


def test_lease_reclaim_and_stale_worker_commit_are_rejected(tmp_path: Path) -> None:
    clock = Clock()
    store = _store(tmp_path, clock)
    source = FakeSource("tenant-a", "ai_governance")
    store.bind_source(source.authority())
    first = store.claim(
        "ai_governance",
        worker_id="worker:one",
        lease_seconds=120,
        max_attempts=5,
    )
    with pytest.raises(UnifiedAuditLeaseLost):
        store.claim(
            "ai_governance",
            worker_id="worker:two",
            lease_seconds=120,
            max_attempts=5,
        )
    clock.now += 121
    second = store.claim(
        "ai_governance",
        worker_id="worker:two",
        lease_seconds=120,
        max_attempts=5,
    )
    assert second.worker_sha256 != first.worker_sha256
    with pytest.raises(UnifiedAuditLeaseLost):
        store.fail_claim(first, error_code="source_conflict", retry_backoff_seconds=0)


def test_authority_rotation_requires_explicit_cas_and_revocation_never_stays_complete(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = _store(tmp_path, clock)
    source = FakeSource("tenant-a", "ai_governance")
    state = store.bind_source(source.authority())
    changed = SourceAuthority(
        tenant_id="tenant-a",
        source_id="ai_governance",
        suite_id="ai_governance",
        authority_revision=2,
        authority_sha256=_sha("rotated"),
        source_schema_version=2,
    )
    with pytest.raises(UnifiedAuditConflict, match="without authorization"):
        store.bind_source(changed)
    authorized = store.authorize_rotation(
        "ai_governance",
        expected_state_revision=state["revision"],
        expected_authority_revision=1,
        expected_authority_sha256=source.authority_sha256,
        new_authority_revision=2,
        new_authority_sha256=changed.authority_sha256,
        new_source_schema_version=changed.source_schema_version,
        new_verifier_identity_sha256=_sha("rotated-verifier"),
        new_trust_root_revision=2,
        new_source_key_id_sha256=_sha("rotated-source-key"),
        reason_sha256=_sha("rotation ceremony"),
    )
    with pytest.raises(UnifiedAuditConflict, match="without authorization"):
        store.bind_source(replace(changed, source_schema_version=3))
    rotated = store.bind_source(changed)
    assert rotated["authority_revision"] == 2
    revoked = store.revoke_source(
        "ai_governance",
        expected_state_revision=rotated["revision"],
        reason_sha256=_sha("revoked"),
    )
    assert revoked["revoked"] is True and revoked["complete"] is False
    assert authorized["pending_authority_revision"] == 2


def test_retry_exhaustion_requires_governed_replay(tmp_path: Path) -> None:
    clock = Clock()
    source = FakeSource("tenant-a", "ai_governance", count=1)
    sink = FakeSignedSink()
    sink.ready = False
    config = UnifiedAuditConfig(enable=True, max_attempts=1, retry_backoff_seconds=0)
    projector, store, _ = _projector(
        tmp_path,
        clock,
        sources=(source,),
        sink=sink,
        config=config,
    )
    with pytest.raises(UnifiedAuditConfigError):
        projector.run_source("ai_governance", worker_id="worker:one")
    with pytest.raises(UnifiedAuditConflict, match="retry limit"):
        projector.run_source("ai_governance", worker_id="worker:one")
    state = store.source_states()[0]
    replayed = store.replay_source(
        "ai_governance",
        expected_state_revision=state["revision"],
        reason_sha256=_sha("operator reviewed outage"),
    )
    assert replayed["attempts"] == 0 and replayed["complete"] is False


def test_persisted_state_and_history_tampering_is_detected(tmp_path: Path) -> None:
    clock = Clock()
    store = _store(tmp_path, clock)
    source = FakeSource("tenant-a", "ai_governance")
    store.bind_source(source.authority())
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT payload_json FROM unified_source_state WHERE source_id='ai_governance'"
        ).fetchone()
        payload = json.loads(row[0])
        payload["cursor_sequence"] = 999
        connection.execute(
            "UPDATE unified_source_state SET payload_json=? WHERE source_id='ai_governance'",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")),),
        )
    with pytest.raises(UnifiedAuditIntegrityError):
        store.verify_integrity()


def test_strict_sink_returns_tenant_key_and_chain_bound_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    tenant_sha256 = hashlib.sha256(
        b"lightwork.unified-audit.tenant.v1:tenant-a"
    ).hexdigest()
    audit_log = AuditLog(data_dir("audit", tenant="tenant-a"), sign=True)
    sink = StrictAuditProjectionSink(
        tenant_id="tenant-a",
        audit_log=audit_log,
        clock=lambda: 10_000.0,
    )
    event = {
        "projection_event_id": _sha("strict-receipt-event"),
        "projection_schema": "lightwork.unified-audit-projection.v1",
        "projection_type": "source_page_receipt",
        "tenant_sha256": tenant_sha256,
        "source_id": "ai_governance",
        "suite_id": "ai_governance",
        "source_sequence": 0,
        "source_page_sha256": _sha("page"),
        "raw_source_payload_persisted": False,
    }

    receipt = sink.append(event)
    assert receipt.projection_event_id == event["projection_event_id"]
    assert receipt.event_sha256 == canonical_sha256(event)
    assert receipt.tenant_sha256 == tenant_sha256
    assert receipt.sink_identity_sha256 == sink.sink_identity_sha256
    assert receipt.key_id_sha256 != GENESIS_SHA256
    assert receipt.chain_sha256 != GENESIS_SHA256
    assert receipt.signature_sha256 != GENESIS_SHA256
    assert sink.append(event) == receipt

    with pytest.raises(UnifiedAuditConfigError, match="outside the tenant"):
        StrictAuditProjectionSink(
            tenant_id="tenant-a",
            audit_log=AuditLog(tmp_path / "wrong-tenant" / "audit", sign=True),
        )


def test_store_reopens_after_history_and_sweep(tmp_path: Path) -> None:
    """Regression: _initialize required the genesis counters, so a second
    store object on the same file failed after any history row or sweep (the
    dashboard opens a new store per request)."""
    clock = Clock()
    store = _store(tmp_path, clock)
    store.bind_source(FakeSource("tenant-a", "ai_governance").authority())
    store.begin_sweep()

    reopened = _store(tmp_path, clock)

    assert reopened.verify_integrity()["valid"] is True
    with pytest.raises(UnifiedAuditIntegrityError):
        UnifiedAuditStore(tmp_path / "tenant-a.sqlite3", tenant_id="tenant-b", clock=clock)
