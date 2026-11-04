from __future__ import annotations

import hashlib
import json

import pytest
from maverick import governance_agent_context as context


def _record(
    *,
    tenant: str = "tenant-a",
    record_id: str = "record-1",
    revision: int = 1,
    value: str = "safe",
) -> context.AuthoritativeContextRecord:
    return context.AuthoritativeContextRecord(
        tenant_id=tenant,
        record_id=record_id,
        revision=revision,
        updated_at=10.0,
        authority_sha256=hashlib.sha256(
            f"{record_id}:{revision}:{value}".encode()
        ).hexdigest(),
        projection={"status": value},
    )


def _capture(
    *,
    tenant: str = "tenant-a",
    source_id: str = "assessments.register",
    records: tuple[context.AuthoritativeContextRecord, ...] | None = None,
    total: int | None = None,
    availability: str = "available",
    reason: str | None = None,
) -> context.AuthoritativeSourceCapture:
    selected = (_record(tenant=tenant),) if records is None else records
    return context.AuthoritativeSourceCapture(
        tenant_id=tenant,
        source_id=source_id,
        availability=availability,
        records=selected,
        total_records=len(selected) if total is None else total,
        observed_at=20.0,
        reason_code=reason,
    )


class Reader:
    def __init__(self, values):
        self.values = list(values)
        self.calls = 0

    def __call__(self, tenant_id: str, _limit: int):
        value = self.values[min(self.calls, len(self.values) - 1)]
        self.calls += 1
        if isinstance(value, Exception):
            raise value
        return value


def _projection(reader: Reader, **settings):
    return context.AuthoritativeCrossSuiteContextProjection(
        (
            context.ContextSourceDefinition(
                source_id="assessments.register",
                source_kind="assessment",
                agent_kinds=("privacy_risk_assessment",),
                required=True,
                reader=reader,
            ),
        ),
        settings=context.GovernanceContextProjectionSettings(
            enable=True,
            **settings,
        ),
        clock=lambda: 30.0,
    )


def test_settings_are_default_off_and_parse_only_projection_keys() -> None:
    assert context.GovernanceContextProjectionSettings().enable is False
    settings = context.GovernanceContextProjectionSettings.from_mapping(
        {
            "governance_agents": {
                "enable": True,
                "enabled_agents": [
                    "program_copilot",
                    "breach_response",
                ],
                "context_projection_enable": True,
                "context_projection_max_records_per_source": 7,
                "context_projection_max_context_items": 5,
                "context_projection_max_total_bytes": 8_192,
                "context_projection_max_record_bytes": 1_024,
            }
        }
    )
    assert settings.enable is True
    assert settings.max_records_per_source == 7
    assert settings.max_context_items == 5
    assert settings.enabled_agent_kinds == (
        "breach_response",
        "program_copilot",
    )

    with pytest.raises(
        context.GovernanceContextProjectionConfigError,
        match="requires packaged governance agents",
    ):
        context.GovernanceContextProjectionSettings.from_mapping(
            {
                "governance_agents": {
                    "enable": False,
                    "context_projection_enable": True,
                }
            }
        )


def test_disabled_agent_kind_cannot_be_previewed_or_resolved() -> None:
    value = _capture()
    projection = context.AuthoritativeCrossSuiteContextProjection(
        (
            context.ContextSourceDefinition(
                source_id="assessments.register",
                source_kind="assessment",
                agent_kinds=("privacy_risk_assessment",),
                required=True,
                reader=Reader([value, value]),
            ),
        ),
        settings=context.GovernanceContextProjectionSettings(
            enable=True,
            enabled_agent_kinds=("breach_response",),
        ),
    )
    with pytest.raises(
        context.GovernanceContextProjectionConfigError,
        match="disabled for this tenant",
    ):
        projection.capture("tenant-a", "privacy_risk_assessment")


def test_capture_double_reads_and_pins_exact_metadata_without_raw_tenant() -> None:
    value = _capture()
    reader = Reader([value, value])
    result = _projection(reader).capture("tenant-a", "privacy_risk_assessment")

    assert reader.calls == 2
    assert result.complete is True
    assert result.tenant_id == "tenant-a"
    assert len(result.items) == 1
    item = result.items[0]
    payload = json.loads(item.content)
    assert payload["tenant_sha256"] == result.tenant_sha256
    assert "tenant_id" not in payload
    assert payload["records"][0]["authority_sha256"] == value.records[0].authority_sha256
    assert payload["records"][0]["revision"] == 1
    assert payload["source_authority_sha256"] == value.authority_sha256
    manifest = result.public_manifest()
    assert manifest["raw_context_returned"] is False
    assert "content" not in json.dumps(manifest)


def test_partial_and_unavailable_sources_are_explicit_not_invented() -> None:
    partial = _capture(
        records=(_record(),),
        total=2,
        availability="partial",
        reason="record_limit",
    )
    partial_result = _projection(Reader([partial, partial])).capture(
        "tenant-a", "privacy_risk_assessment"
    )
    assert partial_result.complete is False
    assert partial_result.sources[0]["availability"] == "partial"
    assert partial_result.sources[0]["total_records"] == 2

    unavailable = context.SourceUnavailable("feature_disabled")
    unavailable_result = _projection(Reader([unavailable, unavailable])).capture(
        "tenant-a", "privacy_risk_assessment"
    )
    assert unavailable_result.complete is False
    payload = json.loads(unavailable_result.items[0].content)
    assert payload["records"] == []
    assert payload["availability"] == "unavailable"
    assert payload["reason_code"] == "feature_disabled"


def test_source_drift_fails_closed_during_capture() -> None:
    first = _capture(records=(_record(revision=1),))
    second = _capture(records=(_record(revision=2),))
    with pytest.raises(
        context.GovernanceContextProjectionConflict,
        match="changed during capture",
    ):
        _projection(Reader([first, second])).capture(
            "tenant-a", "privacy_risk_assessment"
        )


def test_preview_reference_resolves_only_while_current() -> None:
    first = _capture(records=(_record(revision=1),))
    changed = _capture(records=(_record(revision=2),))
    reader = Reader([first, first, changed, changed])
    projection = _projection(reader)
    preview = projection.capture("tenant-a", "privacy_risk_assessment")

    with pytest.raises(
        context.GovernanceContextProjectionConflict,
        match="stale or misbound",
    ):
        projection.resolve_references(
            "tenant-a",
            preview.references,
            "privacy_risk_assessment",
        )


def test_preview_reference_resolves_current_and_preserves_order() -> None:
    value = _capture()
    reader = Reader([value, value, value, value])
    projection = _projection(reader)
    preview = projection.capture("tenant-a", "privacy_risk_assessment")
    resolved = projection.resolve_references(
        "tenant-a",
        preview.references,
        "privacy_risk_assessment",
    )
    assert [item.item_id for item in resolved] == [
        reference["item_id"] for reference in preview.references
    ]


def test_reference_resolution_requires_the_exact_agent_source_plan() -> None:
    assessment = _capture(source_id="assessments.register")
    document = _capture(source_id="documents.vault")
    projection = context.AuthoritativeCrossSuiteContextProjection(
        (
            context.ContextSourceDefinition(
                source_id="assessments.register",
                source_kind="assessment",
                agent_kinds=("privacy_risk_assessment",),
                required=True,
                reader=Reader([assessment] * 4),
            ),
            context.ContextSourceDefinition(
                source_id="documents.vault",
                source_kind="document",
                agent_kinds=("privacy_risk_assessment",),
                required=True,
                reader=Reader([document] * 4),
            ),
        ),
        settings=context.GovernanceContextProjectionSettings(enable=True),
        clock=lambda: 30.0,
    )
    preview = projection.capture("tenant-a", "privacy_risk_assessment")
    with pytest.raises(
        context.GovernanceContextProjectionValidationError,
        match="exact source plan",
    ):
        projection.resolve_references(
            "tenant-a",
            preview.references[:1],
            "privacy_risk_assessment",
        )


def test_reference_resolution_rejects_policy_agent_kind_mismatch() -> None:
    value = _capture()
    reader = Reader([value] * 4)
    projection = _projection(reader)
    preview = projection.capture("tenant-a", "privacy_risk_assessment")

    with pytest.raises(
        context.GovernanceContextProjectionValidationError,
        match="policy agent kind",
    ):
        projection.resolve_references(
            "tenant-a",
            preview.references,
            "breach_response",
        )


def test_reader_cannot_change_tenant_binding() -> None:
    wrong = _capture(tenant="tenant-b")
    with pytest.raises(
        context.GovernanceContextProjectionValidationError,
        match="tenant or source binding",
    ):
        _projection(Reader([wrong])).capture(
            "tenant-a", "privacy_risk_assessment"
        )


def test_duplicate_unsorted_records_and_oversize_projection_are_rejected() -> None:
    with pytest.raises(
        context.GovernanceContextProjectionValidationError,
        match="unique and sorted",
    ):
        _capture(records=(_record(record_id="z"), _record(record_id="a")))

    oversized = _capture(
        records=(
            context.AuthoritativeContextRecord(
                tenant_id="tenant-a",
                record_id="record-1",
                revision=1,
                updated_at=1.0,
                authority_sha256="a" * 64,
                projection={"value": "x" * 2_000},
            ),
        )
    )
    with pytest.raises(
        context.GovernanceContextProjectionValidationError,
        match="configured byte bound",
    ):
        _projection(
            Reader([oversized, oversized]),
            max_record_projection_bytes=1_024,
        ).capture("tenant-a", "privacy_risk_assessment")


def test_readiness_and_recovery_disclose_local_evidence_boundaries() -> None:
    value = _capture()
    reader = Reader([value] * 20)
    projection = _projection(reader)
    readiness = projection.readiness("tenant-a")
    assert readiness["ready"] is False
    # Only one source plan exists in this focused projection; other packaged
    # kinds cannot be claimed ready and the error is explicit.
    assert readiness["double_read_stability_verified"] is False
    assert readiness["raw_context_persisted"] is False
    assert readiness["live_provider_acceptance_verified"] is False
    recovery = projection.recover("tenant-a")
    assert recovery["recovery_mode"] == "stateless_recapture"
    assert recovery["stale_previews_reused"] is False
