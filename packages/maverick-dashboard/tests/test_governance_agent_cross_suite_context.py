from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from maverick import governance_agent_context as context
from maverick import governance_agents
from maverick_dashboard import governance_agent_cross_suite_context as composition


def _capture(tenant_id: str, source_id: str = "stock.source"):
    record = context.AuthoritativeContextRecord(
        tenant_id=tenant_id,
        record_id="record-1",
        revision=1,
        updated_at=10.0,
        authority_sha256=hashlib.sha256(b"record-1").hexdigest(),
        projection={"status": "open"},
    )
    return context.AuthoritativeSourceCapture(
        tenant_id=tenant_id,
        source_id=source_id,
        availability="available",
        records=(record,),
        total_records=1,
        observed_at=11.0,
    )


def _settings(_tenant_id: str):
    return context.GovernanceContextProjectionSettings(enable=True)


def _definition(reader):
    return context.ContextSourceDefinition(
        source_id="stock.source",
        source_kind="metric",
        agent_kinds=tuple(sorted(governance_agents.AGENT_KINDS)),
        required=True,
        reader=reader,
    )


def test_install_wraps_existing_context_authority_and_is_idempotent() -> None:
    app = FastAPI()

    def legacy(_tenant_id, references):
        return tuple(
            governance_agents.GovernanceContextItem(
                item_id=str(reference["item_id"]),
                source_kind=str(reference["source_kind"]),
                source_ref=str(reference["source_ref"]),
                source_revision=int(reference["source_revision"]),
                collected_at=1.0,
                content=b"legacy",
            )
            for reference in references
        )

    app.state.governance_agent_context_resolver = legacy

    def reader(tenant, _limit):
        return _capture(tenant)

    installed = composition.install_governance_agent_cross_suite_context(
        app,
        definitions=(_definition(reader),),
        settings_resolver=_settings,
        clock=lambda: 20.0,
    )
    assert (
        composition.install_governance_agent_cross_suite_context(app) is installed
    )
    assert app.state.governance_agent_context_resolver == installed.resolve_context
    assert app.state.governance_agent_cross_suite_preview_resolver == installed.preview
    assert app.state.governance_agent_cross_suite_readiness == installed.readiness
    assert app.state.governance_agent_cross_suite_maintenance == installed.verify_sources
    assert app.state.governance_agent_cross_suite_recovery == installed.recover

    preview = installed.preview("tenant-a", "program_copilot")
    mixed = [
        preview.references[0],
        {
            "item_id": "legacy-item",
            "source_kind": "policy",
            "source_ref": "legacy-policy",
            "source_revision": 1,
        },
    ]
    with pytest.raises(
        composition.GovernanceAgentCrossSuiteCompositionError,
        match="policy agent-kind binding",
    ):
        installed.resolve_context("tenant-a", mixed)
    resolved = installed.resolve_context(
        "tenant-a",
        mixed,
        "program_copilot",
    )
    assert [item.item_id for item in resolved] == [
        preview.items[0].item_id,
        "legacy-item",
    ]
    assert json.loads(resolved[0].content)["tenant_sha256"] == preview.tenant_sha256
    assert resolved[1].content == b"legacy"
    legacy_only = installed.resolve_context("tenant-a", mixed[1:])
    assert [item.item_id for item in legacy_only] == ["legacy-item"]


def test_stock_source_plan_covers_each_packaged_agent_and_required_suite() -> None:
    readers = composition.StockCrossSuiteSourceReaders(
        SimpleNamespace(state=SimpleNamespace()),
        clock=lambda: 1.0,
    )
    definitions = readers.definitions()
    assert [definition.source_id for definition in definitions] == sorted(
        definition.source_id for definition in definitions
    )
    by_agent = {
        agent: {
            definition.source_id
            for definition in definitions
            if agent in definition.agent_kinds
        }
        for agent in governance_agents.AGENT_KINDS
    }
    assert by_agent["breach_response"] == {
        "documents.vault",
        "privacy.incidents",
    }
    assert by_agent["privacy_risk_assessment"] == {
        "assessments.register",
        "documents.vault",
        "evidence.analysis",
        "privacy.program",
    }
    assert by_agent["program_copilot"] == {
        "assessments.register",
        "documents.vault",
        "evidence.analysis",
        "privacy.program",
    }
    assert by_agent["knowledgebase_governance"] == {
        "documents.vault",
        "evidence.analysis",
    }
    assert by_agent["third_party_risk"] == {
        "third_party.contracts",
        "third_party.intelligence",
        "third_party.lifecycle",
        "third_party.monitors",
    }
    assert all(definition.required for definition in definitions)


def test_composition_reloads_tenant_settings_for_every_capture() -> None:
    calls: list[str] = []

    def settings(tenant_id: str):
        calls.append(tenant_id)
        return context.GovernanceContextProjectionSettings(enable=True)

    def reader(tenant, _limit):
        return _capture(tenant)

    instance = composition.GovernanceAgentCrossSuiteComposition(
        (_definition(reader),),
        settings_resolver=settings,
        clock=lambda: 30.0,
    )
    first = instance.preview("tenant-a", "breach_response")
    second = instance.preview("tenant-b", "breach_response")
    assert calls == ["tenant-a", "tenant-b"]
    assert first.tenant_sha256 != second.tenant_sha256


def test_privacy_incident_reader_projects_safe_metadata_only(monkeypatch) -> None:
    from maverick import privacy_ops

    raw = {
        "id": "INC-one",
        "revision": 3,
        "status": "open",
        "severity": "high",
        "affected_estimate": 5,
        "notify_deadline_at": 100.0,
        "created_at": 10.0,
        "title": "sensitive title",
        "description": "sensitive narrative",
        "notification": None,
    }
    monkeypatch.setattr(privacy_ops, "enabled", lambda: True)
    monkeypatch.setattr(
        privacy_ops,
        "privacy_program_context_heads",
        lambda **_kwargs: {
            "incidents": {"records": (raw,), "total_records": 1}
        },
    )
    readers = composition.StockCrossSuiteSourceReaders(
        SimpleNamespace(state=SimpleNamespace()),
        clock=lambda: 20.0,
    )
    captured = readers.privacy_incidents("tenant-a", 10)
    projected = captured.records[0]
    rendered = json.dumps(projected.projection)
    assert "sensitive title" not in rendered
    assert "sensitive narrative" not in rendered
    assert projected.projection["narrative_included"] is False
    assert projected.revision == 3


def test_privacy_program_reader_is_globally_bounded_and_omits_raw_fields(
    monkeypatch,
) -> None:
    from maverick import privacy_ops

    raw = {
        "id": "AI-one",
        "revision": 2,
        "status": "active",
        "created_at": 10.0,
        "retention": "keep the raw customer dataset forever",
        "transfers": ["sensitive cross-border narrative"],
    }
    monkeypatch.setattr(privacy_ops, "enabled", lambda: True)
    monkeypatch.setattr(
        privacy_ops,
        "privacy_program_context_heads",
        lambda **_kwargs: {
            register: {"records": (raw,), "total_records": 1}
            for register in ("ai_systems", "dpa_reviews", "dsars", "ropa")
        },
    )
    readers = composition.StockCrossSuiteSourceReaders(
        SimpleNamespace(state=SimpleNamespace()),
        clock=lambda: 20.0,
    )
    captured = readers.privacy_program("tenant-a", 1)
    assert len(captured.records) == 1
    assert captured.total_records == 4
    assert captured.availability == "partial"
    rendered = json.dumps(captured.records[0].projection)
    assert "raw customer dataset" not in rendered
    assert "cross-border narrative" not in rendered


def test_source_metadata_never_invents_revision_or_timestamp() -> None:
    with pytest.raises(context.SourceUnavailable) as revision_failure:
        composition._record(  # noqa: SLF001 - validates the composition boundary
            "tenant-a",
            record_id="record-1",
            revision=None,
            updated_at=1.0,
            authority_sha256=hashlib.sha256(b"record-1").hexdigest(),
            projection={"status": "open"},
        )
    assert revision_failure.value.reason_code == "integrity_unverified"
    with pytest.raises(context.SourceUnavailable) as timestamp_failure:
        composition._record(  # noqa: SLF001 - validates the composition boundary
            "tenant-a",
            record_id="record-1",
            revision=1,
            updated_at=None,
            authority_sha256=hashlib.sha256(b"record-1").hexdigest(),
            projection={"status": "open"},
        )
    assert timestamp_failure.value.reason_code == "integrity_unverified"


def test_enabled_but_unprovisioned_authority_is_explicitly_unavailable(
    monkeypatch,
    tmp_path,
) -> None:
    from maverick import third_party_lifecycle

    monkeypatch.setattr(third_party_lifecycle, "enabled", lambda: True)
    readers = composition.StockCrossSuiteSourceReaders(
        SimpleNamespace(state=SimpleNamespace()),
        clock=lambda: 20.0,
    )
    monkeypatch.setattr(
        readers,
        "_lifecycle_path",
        lambda _tenant: tmp_path / "missing.sqlite3",
    )
    with pytest.raises(context.SourceUnavailable) as failure:
        readers.third_party_lifecycle("tenant-a", 10)
    assert failure.value.reason_code == "store_absent"


def test_partial_source_manifest_does_not_claim_external_acceptance() -> None:
    partial = context.AuthoritativeSourceCapture(
        tenant_id="tenant-a",
        source_id="stock.source",
        availability="partial",
        records=(_capture("tenant-a").records[0],),
        total_records=2,
        observed_at=1.0,
        reason_code="record_limit",
    )
    instance = composition.GovernanceAgentCrossSuiteComposition(
        (_definition(lambda _tenant, _limit: partial),),
        settings_resolver=_settings,
        clock=lambda: 2.0,
    )
    preview = instance.preview("tenant-a", "third_party_risk")
    assert preview.complete is False
    manifest = preview.public_manifest()
    assert manifest["external_writes_performed"] is False
    assert manifest["sources"][0]["availability"] == "partial"
