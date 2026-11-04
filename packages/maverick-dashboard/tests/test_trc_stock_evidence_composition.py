from __future__ import annotations

import pytest
from fastapi import FastAPI
from maverick.trc_stock_evidence_collectors import (
    AWS_CONFIG,
    AWS_CONFIG_COLLECTOR,
    AWS_SECURITY_HUB,
    AWS_SECURITY_HUB_COLLECTOR,
    AZURE_DEFENDER,
    AZURE_DEFENDER_COLLECTOR,
    AZURE_POLICY,
    AZURE_POLICY_COLLECTOR,
    GCP_SCC_COLLECTOR,
    GCP_SECURITY_COMMAND_CENTER,
    GITHUB_SECURITY,
    GITHUB_SECURITY_COLLECTOR,
    OKTA_POSTURE,
    OKTA_POSTURE_COLLECTOR,
    STOCK_COLLECTOR_IDS,
    ProviderControlBinding,
    StockCollectorSource,
)
from maverick_dashboard.trc_stock_evidence_composition import (
    ConfigDrivenTrcStockEvidenceComposition,
    TrcStockEvidenceComposition,
    TrcStockEvidenceCompositionError,
    attach_trc_stock_evidence_composition,
    install_trc_stock_evidence_composition,
    stock_collector_settings,
)

SHA_A = "a" * 64


@pytest.fixture()
def native_sources_enabled(tmp_path, monkeypatch):
    """Readiness also lists managed sources from the native evidence store,
    which keeps its own enable gate; give it an isolated, enabled home."""
    from maverick import config

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[tech_risk_compliance]\nenable = true\n\n"
        "[tech_risk_compliance.continuous_evidence]\nenable = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    config.reset_config_cache()
    yield
    config.reset_config_cache()


class Transport:
    def request(self, _request):
        raise AssertionError("composition attachment must not perform provider I/O")


def source() -> StockCollectorSource:
    return StockCollectorSource(
        tenant_id="tenant-a",
        enrollment_id="azure_defender_enrollment",
        definition_id="azure_defender_definition",
        definition_version=1,
        definition_integrity_sha256=SHA_A,
        collector_key_id="azure_defender_key_v1",
        capability_revision=1,
        provider=AZURE_DEFENDER,
        origin="https://management.azure.com",
        scope_ref="12345678-1234-4123-8123-123456789abc",
        credential_env="LIGHTWORK_AZURE_DEFENDER_CREDENTIAL",
        bindings=(ProviderControlBinding("control-a", "assessment-1"),),
    )


def test_attachment_is_lazy_idempotent_and_exposes_scheduler_dependencies():
    calls = []
    composition = TrcStockEvidenceComposition.from_sources(
        (source(),),
        transport_factory=lambda tenant: calls.append(("transport", tenant)) or Transport(),
        credential_ref_present=lambda name: calls.append(("credential_ref", name)) or True,
    )
    app = FastAPI()
    attached = attach_trc_stock_evidence_composition(app, composition)
    assert attached is composition
    assert attach_trc_stock_evidence_composition(app, composition) is composition
    assert calls == []

    readiness = app.state.trc_stock_evidence_readiness_probe("tenant-a")
    assert readiness["ready"] is True
    assert readiness["provider_io_performed"] is False
    assert calls == [
        ("credential_ref", "LIGHTWORK_AZURE_DEFENDER_CREDENTIAL")
    ]
    registry = app.state.trc_stock_evidence_registry_factory("tenant-a")
    assert "azure_defender_v1" in registry.capabilities()
    assert calls[-1] == ("transport", "tenant-a")

    runtime = app.state.trc_stock_evidence_scheduler_factory(
        worker_id="stock-evidence-worker",
        tenant_supplier=lambda: (),
        config_loader=dict,
        tenant_config_loader=dict,
    )
    assert runtime.status()["custom_collector_dependencies_injected"] is True


def test_attachment_rejects_state_collision_and_scheduler_authority_override():
    composition = TrcStockEvidenceComposition.from_sources((source(),))
    app = FastAPI()
    app.state.trc_stock_evidence_registry_factory = object()
    try:
        with pytest.raises(
            TrcStockEvidenceCompositionError,
            match="authority already exists",
        ):
            attach_trc_stock_evidence_composition(app, composition)
    finally:
        del app.state.trc_stock_evidence_registry_factory

    with pytest.raises(
        TrcStockEvidenceCompositionError,
        match="cannot replace",
    ):
        composition.build_scheduler(registry_factory=lambda _tenant: object())


def stock_source(
    provider: str,
    collector_id: str,
    *,
    origin: str,
    scope_ref: str,
    region: str | None = None,
    stream: str | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "enrollment_id": f"{provider}_enrollment",
        "definition_id": f"{provider}_definition",
        "definition_version": 1,
        "definition_integrity_sha256": SHA_A,
        "collector_key_id": f"{provider}_key_v1",
        "capability_revision": 1,
        "provider": provider,
        "origin": origin,
        "scope_ref": scope_ref,
        "credential_env": f"LIGHTWORK_{provider.upper()}_CREDENTIAL",
        "bindings": [{"control_ref": f"control-{provider}", "source_ref": "selector-1"}],
        "limits": {
            "timeout_seconds": 15,
            "max_elapsed_seconds": 120,
            "max_response_bytes": 262_144,
            "page_size": 100,
            "max_pages": 50,
            "max_records": 10_000,
        },
    }
    if region is not None:
        value["region"] = region
    if stream is not None:
        value["stream"] = stream
    assert collector_id in STOCK_COLLECTOR_IDS
    return value


def production_config(*, omit_last: bool = False) -> dict[str, object]:
    entries = [
        stock_source(
            AWS_SECURITY_HUB,
            AWS_SECURITY_HUB_COLLECTOR,
            origin="https://securityhub.us-east-1.amazonaws.com",
            scope_ref="123456789012",
            region="us-east-1",
        ),
        stock_source(
            AWS_CONFIG,
            AWS_CONFIG_COLLECTOR,
            origin="https://config.us-east-1.amazonaws.com",
            scope_ref="123456789012",
            region="us-east-1",
        ),
        stock_source(
            AZURE_DEFENDER,
            AZURE_DEFENDER_COLLECTOR,
            origin="https://management.azure.com",
            scope_ref="12345678-1234-4123-8123-123456789abc",
        ),
        stock_source(
            AZURE_POLICY,
            AZURE_POLICY_COLLECTOR,
            origin="https://management.azure.com",
            scope_ref="12345678-1234-4123-8123-123456789abc",
        ),
        stock_source(
            GCP_SECURITY_COMMAND_CENTER,
            GCP_SCC_COLLECTOR,
            origin="https://securitycenter.googleapis.com",
            scope_ref="organizations/1234567890",
        ),
        stock_source(
            GITHUB_SECURITY,
            GITHUB_SECURITY_COLLECTOR,
            origin="https://api.github.com",
            scope_ref="lightwork-org",
            stream="code_scanning",
        ),
        stock_source(
            OKTA_POSTURE,
            OKTA_POSTURE_COLLECTOR,
            origin="https://lightwork.okta.com",
            scope_ref="lightwork-org",
            stream="MFA_ENROLL",
        ),
    ]
    selected = list(STOCK_COLLECTOR_IDS)
    if omit_last:
        entries.pop()
    return {
        "tech_risk_compliance": {
            "enable": True,
            "continuous_evidence": {
                "enable": True,
                "enabled_collectors": ["local_soc2_v1", *selected],
                "stock_collectors": {"enable": True, "sources": entries},
                "scheduler": {"enable": True},
            },
        },
    }


def test_config_driven_composition_installs_all_seven_stock_collectors_lazily(native_sources_enabled):
    calls: list[tuple[str, str]] = []
    config = production_config()
    settings = stock_collector_settings(config, tenant_id="tenant-a")
    assert settings.enabled_stock_collector_ids == STOCK_COLLECTOR_IDS
    assert {item.collector_id for item in settings.sources} == set(STOCK_COLLECTOR_IDS)

    composition = ConfigDrivenTrcStockEvidenceComposition(
        config_loader=lambda tenant: calls.append(("config", tenant)) or config,
        transport_factory=lambda tenant: calls.append(("transport", tenant)) or Transport(),
        credential_ref_present=lambda name: calls.append(("reference", name)) or True,
    )
    app = FastAPI()
    assert install_trc_stock_evidence_composition(app, composition) is composition
    assert calls == []

    readiness = app.state.trc_stock_evidence_readiness_probe("tenant-a")
    assert readiness["ready"] is True
    assert readiness["configured_stock_collector_ids"] == sorted(STOCK_COLLECTOR_IDS)
    assert readiness["missing_stock_collector_ids"] == []
    assert readiness["status_secret_resolution"] is False
    assert readiness["status_provider_network_io"] is False
    assert not any(item[0] == "transport" for item in calls)
    registry = app.state.trc_stock_evidence_registry_factory("tenant-a")
    assert set(registry.capabilities()) == {"local_soc2_v1", *STOCK_COLLECTOR_IDS}
    assert calls[-1] == ("transport", "tenant-a")

    runtime = app.state.trc_stock_evidence_scheduler_factory(
        worker_id="stock-production-worker",
        tenant_supplier=lambda: (),
        config_loader=dict,
        tenant_config_loader=dict,
    )
    assert runtime.status()["custom_collector_dependencies_injected"] is True


def test_production_readiness_fails_closed_for_selected_source_without_manifest(native_sources_enabled):
    composition = ConfigDrivenTrcStockEvidenceComposition(
        config_loader=lambda _tenant: production_config(omit_last=True),
        credential_ref_present=lambda _name: True,
    )
    readiness = composition.readiness("tenant-a")
    assert readiness["ready"] is False
    assert readiness["missing_stock_collector_ids"] == [OKTA_POSTURE_COLLECTOR]


def test_config_parser_rejects_unallowlisted_source_and_browser_selected_authority():
    config = production_config()
    feature = config["tech_risk_compliance"]["continuous_evidence"]
    feature["enabled_collectors"] = ["local_soc2_v1"]
    with pytest.raises(TrcStockEvidenceCompositionError, match="not_allowlisted"):
        stock_collector_settings(config, tenant_id="tenant-a")

    with pytest.raises(TrcStockEvidenceCompositionError, match="cannot replace"):
        ConfigDrivenTrcStockEvidenceComposition(
            config_loader=lambda _tenant: production_config(),
        ).build_scheduler(credential_resolver=lambda *_args: object())
