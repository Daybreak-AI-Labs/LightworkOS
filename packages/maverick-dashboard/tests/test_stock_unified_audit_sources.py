from __future__ import annotations

import hashlib
import json
from dataclasses import fields

import pytest
from fastapi import FastAPI
from maverick import stock_suite_audit_capture as stock_capture
from maverick.audit.events import AuditEvent, EventKind
from maverick.audit.writer import AuditLog
from maverick.paths import data_dir, tenant_scope
from maverick.suite_audit_capture import (
    SuiteAuditCaptureError,
    build_suite_audit_capture,
)
from maverick.unified_audit import GENESIS_SHA256, SourcePage, build_source_record
from maverick_dashboard import stock_unified_audit_sources as stock
from maverick_dashboard import unified_audit_composition as composition
from maverick_dashboard.unified_audit_sources import UnifiedAuditSourceAdapterError


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _capture(*, revision: int = 3):
    records = []
    previous = GENESIS_SHA256
    for sequence in range(1, 4):
        record = build_source_record(
            sequence=sequence,
            occurred_at=1_800_000_000.0 + sequence,
            action="record_changed",
            actor_sha256=_sha(f"actor:{sequence}"),
            resource_sha256=_sha(f"resource:{sequence}"),
            payload_sha256=_sha(f"payload:{sequence}"),
            previous_sha256=previous,
        )
        records.append(record)
        previous = record.record_sha256
    return build_suite_audit_capture(
        tenant_id="tenant-a",
        source_id="ai_governance",
        source_revision=revision,
        source_schema_version=1,
        observed_at=1_800_000_100.0,
        records=tuple(records),
        complete=False,
        retention_complete=False,
        integrity_verified=True,
        limitations=("source_history_incomplete", "source_retention_unverified"),
    )


class _Provider:
    provider_identity_sha256 = _sha("provider")

    def __init__(self) -> None:
        self.value = _capture()
        self.calls = 0
        self.drift = False

    def capture(self, *, tenant_id: str, source_id: str):
        assert tenant_id == "tenant-a"
        assert source_id == "ai_governance"
        self.calls += 1
        if self.drift and self.calls > 1:
            return build_suite_audit_capture(
                tenant_id=self.value.tenant_id,
                source_id=self.value.source_id,
                source_revision=4,
                source_schema_version=self.value.source_schema_version,
                observed_at=self.value.observed_at,
                records=self.value.records,
                complete=self.value.complete,
                retention_complete=self.value.retention_complete,
                integrity_verified=self.value.integrity_verified,
                limitations=self.value.limitations,
            )
        return self.value


def test_reader_and_separate_verifier_bind_exact_partial_capture() -> None:
    reader_provider = _Provider()
    verifier_provider = _Provider()
    reader = stock.StockUnifiedAuditHistoryReader(
        tenant_id="tenant-a",
        source_id="ai_governance",
        provider=reader_provider,
    )
    verifier = stock.StockUnifiedAuditVerifier(
        tenant_id="tenant-a",
        source_id="ai_governance",
        provider=verifier_provider,
        clock=lambda: 1_800_000_200.0,
    )
    authority = reader.resolve_authority(
        tenant_id="tenant-a",
        source_id="ai_governance",
        suite_id="ai_governance",
    )
    first = reader.read_history_page(
        tenant_id="tenant-a",
        source_id="ai_governance",
        suite_id="ai_governance",
        authority_revision=authority.authority_revision,
        authority_sha256=authority.authority_sha256,
        source_schema_version=authority.source_schema_version,
        after_sequence=0,
        prior_sha256=GENESIS_SHA256,
        previous_page_sha256=GENESIS_SHA256,
        limit=2,
    )
    assert first.record_count == 2
    assert first.truncated is True
    assert first.complete is False
    assert first.limitations == (
        "more_records_available",
        "source_history_incomplete",
        "source_retention_unverified",
    )
    core_page = SourcePage(
        **{field.name: getattr(first, field.name) for field in fields(SourcePage)}
    )
    verification = verifier.verify_page(authority=authority, page=core_page)
    assert verification.assurance_level == "self_asserted"
    assert verification.retention_complete is False
    assert verification.snapshot_record_count == 3
    assert verification.snapshot_head_sha256 == _capture().head_sha256
    assert reader_provider is not verifier_provider
    assert "actor:1" not in repr(first)


def test_reader_rejects_capture_drift_between_double_reads() -> None:
    provider = _Provider()
    provider.drift = True
    reader = stock.StockUnifiedAuditHistoryReader(
        tenant_id="tenant-a",
        source_id="ai_governance",
        provider=provider,
    )
    authority = reader.resolve_authority(
        tenant_id="tenant-a",
        source_id="ai_governance",
        suite_id="ai_governance",
    )
    with pytest.raises(
        UnifiedAuditSourceAdapterError,
        match="source_authority_changed",
    ):
        reader.read_history_page(
            tenant_id="tenant-a",
            source_id="ai_governance",
            suite_id="ai_governance",
            authority_revision=authority.authority_revision,
            authority_sha256=authority.authority_sha256,
            source_schema_version=authority.source_schema_version,
            after_sequence=0,
            prior_sha256=GENESIS_SHA256,
            previous_page_sha256=GENESIS_SHA256,
            limit=2,
        )


def test_six_stock_authorities_build_lazily_without_opening_stores(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_paths(*_args, **_kwargs):
        raise AssertionError("lazy authority construction opened a source path")

    monkeypatch.setattr(stock_capture, "data_dir", no_paths)
    readers, verifiers = stock.build_stock_unified_audit_authorities(
        tenant_id="tenant-a"
    )
    assert tuple(readers) == stock.SOURCE_IDS
    assert tuple(verifiers) == stock.SOURCE_IDS
    assert all(
        readers[source_id]._provider is not verifiers[source_id]._provider
        for source_id in stock.SOURCE_IDS
    )
    assert stock.StockSuiteAuditCaptureProvider is (
        stock_capture.StockSuiteAuditCaptureProvider
    )


def test_stock_privacy_capture_verifies_exact_tenant_key_and_rejects_tampering() -> None:
    tenant = "tenant-a"
    audit_dir = data_dir("audit", tenant=tenant)
    event = AuditEvent(
        ts=1_800_000_001.0,
        kind=EventKind.PRIVACY_RECORD_CHANGED,
        payload={
            "event_id": "privacy-event-private",
            "occurred_at": 1_800_000_001.0,
            "actor": "user:private-actor",
            "tenant": tenant,
            "record_type": "incident",
            "action": "incident_created",
            "record_id": "private-record",
            "revision": 1,
            "status": "open",
            "record_sha256": _sha("private-record-payload"),
        },
    )
    with tenant_scope(tenant=tenant):
        assert AuditLog(audit_dir, sign=True).record_strict_signed(event) is True

    provider = stock_capture.StockSuiteAuditCaptureProvider()
    capture = provider.capture(
        tenant_id=tenant,
        source_id="privacy_automation",
    )
    assert capture.record_count == 1
    assert capture.records[0].action == "record_created"
    assert "private-actor" not in repr(capture.records)
    assert "private-record" not in repr(capture.records)

    day_file = next(iter(sorted(audit_dir.glob("????-??-??.ndjson"))))
    row = json.loads(day_file.read_text(encoding="utf-8"))
    row["record_sha256"] = _sha("tampered")
    day_file.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(
        SuiteAuditCaptureError,
        match="source_integrity_unverified",
    ):
        provider.capture(
            tenant_id=tenant,
            source_id="privacy_automation",
        )


def test_default_app_factory_supplies_stock_six_without_injected_factories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    sentinel = object()
    captured = {}
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: {
            "audit": {
                "sign": True,
                "unified": {
                    "enable": True,
                    "page_size": 100,
                    "lease_seconds": 120,
                    "max_lag_seconds": 300,
                    "max_attempts": 5,
                    "retry_backoff_seconds": 30,
                    "poll_seconds": 60,
                },
            }
        },
    )

    def builder(**kwargs):
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(composition, "build_unified_audit_projector", builder)
    composition.attach_unified_audit_composition(app)
    result = app.state.unified_audit_projector_factory(
        "tenant-a",
        "principal-a",
        object(),
    )
    assert result is sentinel
    assert tuple(captured["readers"]) == stock.SOURCE_IDS
    assert tuple(captured["verifiers"]) == stock.SOURCE_IDS
    assert captured["source_authority_mode"] == "stock"
