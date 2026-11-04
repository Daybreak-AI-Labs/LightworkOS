from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from maverick.suite_audit_capture import (
    SuiteAuditCaptureError,
    build_suite_audit_capture,
)
from maverick.unified_audit import GENESIS_SHA256, build_source_record


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _records():
    first = build_source_record(
        sequence=1,
        occurred_at=1_800_000_001.0,
        action="record_created",
        actor_sha256=_sha("private-actor"),
        resource_sha256=_sha("private-resource"),
        payload_sha256=_sha("private-payload"),
        previous_sha256=GENESIS_SHA256,
    )
    return (first,)


def test_capture_binds_exact_tenant_source_revision_head_and_limitations() -> None:
    capture = build_suite_audit_capture(
        tenant_id="tenant-a",
        source_id="ai_governance",
        source_revision=2,
        source_schema_version=1,
        observed_at=1_800_000_100.0,
        records=_records(),
        complete=False,
        retention_complete=False,
        integrity_verified=True,
        limitations=("source_history_incomplete", "source_retention_unverified"),
    )
    assert capture.capture_sha256 != GENESIS_SHA256
    assert capture.head_sha256 == capture.records[-1].record_sha256
    assert capture.record_count == 1
    metadata = capture.public_metadata()
    assert metadata["source_id"] == "ai_governance"
    assert "tenant_id" not in metadata
    assert "records" not in metadata
    assert "private-actor" not in repr(capture)
    assert len(capture.capture_sha256) == 64


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: replace(value, capture_sha256=_sha("tampered")),
        lambda value: replace(value, head_sha256=_sha("wrong-head")),
        lambda value: replace(value, record_count=2),
        lambda value: replace(value, complete=True),
        lambda value: replace(value, limitations=("free-form",)),
    ],
)
def test_capture_rejects_tampering_and_unsupported_completeness(mutation) -> None:
    capture = build_suite_audit_capture(
        tenant_id="tenant-a",
        source_id="privacy_automation",
        source_revision=2,
        source_schema_version=1,
        observed_at=1_800_000_100.0,
        records=_records(),
        complete=False,
        retention_complete=False,
        integrity_verified=True,
        limitations=("source_history_incomplete", "source_retention_unverified"),
    )
    with pytest.raises(SuiteAuditCaptureError):
        mutation(capture).__post_init__()


def test_complete_capture_requires_integrity_and_retention_without_limits() -> None:
    complete = build_suite_audit_capture(
        tenant_id="tenant-a",
        source_id="data_use_governance",
        source_revision=2,
        source_schema_version=1,
        observed_at=1_800_000_100.0,
        records=_records(),
        complete=True,
        retention_complete=True,
        integrity_verified=True,
        limitations=(),
    )
    assert complete.complete is True
    assert complete.retention_complete is True
