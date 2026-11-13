"""Focused acceptance-boundary tests for live AI provider contracts."""
from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from maverick.grc_outbound_sync import OutboundResponse
from maverick_dashboard import provider_contract_acceptance as acceptance


@pytest.fixture(autouse=True)
def _explicit_lightwork_client_binding(monkeypatch):
    """The governed GRC payload sanitizer requires an explicit tenant binding."""

    from maverick import client

    monkeypatch.setenv("MAVERICK_CLIENT_ID", "provider-contract-acceptance-test")
    client.reset_client_cache()
    yield
    client.reset_client_cache()


def _mapping(**overrides):
    value = acceptance.example_config()
    value.update(overrides)
    return value


def _config(**overrides):
    return acceptance.ProviderContractAcceptanceConfig.from_mapping(
        _mapping(**overrides)
    )


@dataclass(frozen=True)
class _Asset:
    source_id: str
    version_digest: str


class _HFAdapter:
    def discover(self):
        return SimpleNamespace(
            pages=1,
            assets=(_Asset("raw-sensitive-model-id", "a" * 64),),
        )


class _EntraAdapter:
    def collect(self):
        return SimpleNamespace(
            identities=(object(),),
            grants=(object(), object()),
            data_classifications=(),
            source_sha256="b" * 64,
            coverage="bounded_read_only_snapshot",
        )


class _ServiceNowTransport:
    def __init__(self, *, drift: bool = False):
        self.requests = []
        self.drift = drift

    def send(self, request):
        self.requests.append(request)
        revision = "2" if self.drift and len(self.requests) == 2 else "1"
        return OutboundResponse(
            idempotency_key=request.idempotency_key,
            source_revision=request.source_revision,
            source_digest=request.source_digest,
            external_id="a" * 32,
            external_url=(
                "https://dev00000.service-now.com/now/nav/ui/classic/params/"
                "target/sn_grc_issue.do"
            ),
            external_revision=revision,
        )


class _OpenAICollector:
    def __init__(self):
        self.requests = []

    def collect(self, request):
        self.requests.append(request)
        return SimpleNamespace(
            records=(object(),),
            batch_id="raw-sensitive-provider-batch-id",
            manifest_citation=SimpleNamespace(sha256="c" * 64),
        )


def _dependencies(
    *,
    credential_probe=lambda _provider, _reference: True,
    servicenow=None,
):
    snow = servicenow or _ServiceNowTransport()
    openai = _OpenAICollector()
    dependencies = acceptance.ProviderAcceptanceDependencies(
        credential_probe=credential_probe,
        hugging_face_factory=lambda _config: _HFAdapter(),
        entra_factory=lambda _config: _EntraAdapter(),
        servicenow_factory=lambda _config: snow,
        openai_costs_factory=lambda _config: openai,
        clock=lambda: 1_788_000_000.0,
    )
    return dependencies, snow, openai


def test_readiness_reports_missing_credentials_as_blocked_without_factories():
    calls = []

    def forbidden(_config):
        calls.append(True)
        raise AssertionError("readiness-only must never construct a live adapter")

    dependencies = acceptance.ProviderAcceptanceDependencies(
        credential_probe=lambda provider, _reference: provider != "entra",
        hugging_face_factory=forbidden,
        entra_factory=forbidden,
        servicenow_factory=forbidden,
        openai_costs_factory=forbidden,
        clock=lambda: 1_788_000_000.0,
    )
    report = acceptance.run_acceptance(
        _config(), readiness_only=True, dependencies=dependencies
    )

    assert report["status"] == "blocked"
    assert calls == []
    checks = {item["provider"]: item for item in report["checks"]}
    assert checks["entra"]["status"] == "blocked"
    assert checks["entra"]["reason_code"] == "credential_unavailable"
    assert checks["hugging_face"]["status"] == "ready"
    assert report["configured_contracts_live_accepted"] is False


def test_live_mode_requires_exact_test_estate_consent_before_any_provider_call():
    mapping = _mapping(consent_acknowledgement="yes")
    calls = []

    def forbidden(_config):
        calls.append(True)
        raise AssertionError("missing consent must block the live seam")

    dependencies = acceptance.ProviderAcceptanceDependencies(
        credential_probe=lambda _provider, _reference: True,
        hugging_face_factory=forbidden,
        entra_factory=forbidden,
        servicenow_factory=forbidden,
        openai_costs_factory=forbidden,
        clock=lambda: 1_788_000_000.0,
    )
    report = acceptance.run_acceptance(
        acceptance.ProviderContractAcceptanceConfig.from_mapping(mapping),
        dependencies=dependencies,
    )

    assert report["status"] == "blocked"
    assert calls == []
    assert all(
        "live_test_consent_not_acknowledged" in item["blocking_reasons"]
        for item in report["checks"]
    )


@pytest.mark.parametrize(
    ("base_url", "environment", "reason"),
    [
        (
            "https://customer.service-now.com",
            "dev",
            "servicenow_write_origin_not_allowlisted",
        ),
        (
            "https://dev00000-test.service-now.com",
            "dev",
            "servicenow_write_origin_not_allowlisted",
        ),
        (
            "https://customer-test.service-now.com",
            "production",
            "sandbox_environment_not_declared",
        ),
    ],
)
def test_servicenow_non_allowlisted_near_match_or_production_target_cannot_mutate(
    base_url, environment, reason
):
    mapping = _mapping()
    mapping["servicenow"] = {
        **mapping["servicenow"],
        "base_url": base_url,
        "environment": environment,
    }
    dependencies, snow, _openai = _dependencies()

    report = acceptance.run_acceptance(
        acceptance.ProviderContractAcceptanceConfig.from_mapping(mapping),
        dependencies=dependencies,
    )
    check = next(item for item in report["checks"] if item["provider"] == "servicenow")

    assert check["status"] == "blocked"
    assert reason in check["blocking_reasons"]
    assert check["mutation_attempted"] is False
    assert snow.requests == []


def test_servicenow_missing_exact_origin_allowlist_is_blocked_without_io():
    mapping = _mapping()
    mapping["servicenow"] = {
        **mapping["servicenow"],
        "write_origin_allowlist": [],
    }
    dependencies, snow, _openai = _dependencies()

    readiness_report = acceptance.run_acceptance(
        acceptance.ProviderContractAcceptanceConfig.from_mapping(mapping),
        readiness_only=True,
        dependencies=dependencies,
    )
    readiness_check = next(
        item
        for item in readiness_report["checks"]
        if item["provider"] == "servicenow"
    )

    assert readiness_check["status"] == "blocked"
    assert (
        readiness_check["reason_code"]
        == "servicenow_write_origin_not_allowlisted"
    )
    assert readiness_check["live_request_attempted"] is False
    assert readiness_check["mutation_attempted"] is False
    assert snow.requests == []
    assert (
        readiness_report["admission"]["servicenow_write_origin_allowlisted"]
        is False
    )

    live_report = acceptance.run_acceptance(
        acceptance.ProviderContractAcceptanceConfig.from_mapping(mapping),
        dependencies=dependencies,
    )
    live_check = next(
        item for item in live_report["checks"] if item["provider"] == "servicenow"
    )
    assert live_check["status"] == "blocked"
    assert live_check["mutation_attempted"] is False
    assert snow.requests == []


def test_injected_live_contracts_pass_and_emit_only_bounded_hashed_evidence():
    dependencies, snow, openai = _dependencies()
    report = acceptance.run_acceptance(_config(), dependencies=dependencies)

    assert report["status"] == "passed"
    assert report["summary"] == {
        "ready": 0,
        "passed": 4,
        "blocked": 0,
        "failed": 0,
        "skipped": 0,
    }
    assert report["configured_contracts_live_accepted"] is True
    assert report["complete_enterprise_inventory_claimed"] is False
    assert report["admission"] == {
        "consenting_test_estate_declared": True,
        "live_test_consent_acknowledged": True,
        "servicenow_sandbox_write_acknowledged": True,
        "servicenow_write_origin_allowlisted": True,
    }
    assert len(snow.requests) == 2
    assert snow.requests[0] == snow.requests[1]
    assert len(openai.requests) == 1
    service_now = next(
        item for item in report["checks"] if item["provider"] == "servicenow"
    )
    assert service_now["mutation_attempted"] is True
    assert service_now["evidence"]["replay_binding_equal"] is True
    rendered = json.dumps(report, sort_keys=True)
    for forbidden in (
        "raw-sensitive-model-id",
        "raw-sensitive-provider-batch-id",
        "00000000-0000-4000-8000-000000000000",
        "consenting-test-organization",
        "HF_TOKEN",
        "ENTRA_DISCOVERY_TOKEN",
        "SERVICENOW_TOKEN",
        "OPENAI_ADMIN_KEY",
        "dev00000.service-now.com",
    ):
        assert forbidden not in rendered
    assert len(rendered.encode()) < 64 * 1024


def test_servicenow_replay_drift_fails_without_exposing_response_details():
    transport = _ServiceNowTransport(drift=True)
    dependencies, _snow, _openai = _dependencies(servicenow=transport)
    report = acceptance.run_acceptance(_config(), dependencies=dependencies)
    check = next(item for item in report["checks"] if item["provider"] == "servicenow")

    assert report["status"] == "failed"
    assert check["status"] == "failed"
    assert check["reason_code"] == "unexpected_runtime_error"
    assert check["exception_message_included"] is False
    assert check["evidence"] == {}


def test_config_is_closed_and_duplicate_json_fields_are_rejected(tmp_path):
    mapping = _mapping(unknown=True)
    with pytest.raises(
        acceptance.ProviderContractAcceptanceConfigError,
        match="unsupported fields",
    ):
        acceptance.ProviderContractAcceptanceConfig.from_mapping(mapping)

    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"schema":"' + acceptance.CONFIG_SCHEMA + '","schema":"other"}',
        encoding="utf-8",
    )
    with pytest.raises(
        acceptance.ProviderContractAcceptanceConfigError,
        match="duplicate fields",
    ):
        acceptance.load_config_file(path)


def test_cli_readiness_writes_machine_readable_blocked_report(tmp_path, monkeypatch):
    config_path = tmp_path / "provider-contracts.json"
    output_path = tmp_path / "provider-contracts-report.json"
    config_path.write_text(json.dumps(acceptance.example_config()), encoding="utf-8")
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("ENTRA_DISCOVERY_TOKEN", raising=False)
    monkeypatch.delenv("SERVICENOW_TOKEN", raising=False)
    monkeypatch.delenv("OPENAI_ADMIN_KEY", raising=False)

    code = acceptance.main(
        [
            "--config",
            str(config_path),
            "--readiness-only",
            "--output",
            str(output_path),
        ]
    )
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert code == 2
    assert report["status"] == "blocked"
    assert report["summary"]["blocked"] == 4
    assert report["secret_values_included"] is False


def test_default_factories_construct_the_existing_real_adapters_without_io():
    from maverick.ai_cost_openai import OpenAIOrganizationCostCollector
    from maverick.ai_identity_governance_connectors import (
        EntraIdentityGovernanceAdapter,
    )
    from maverick.ai_inventory_connectors import HuggingFaceInventoryAdapter
    from maverick.grc_vendor_transports import ServiceNowIRMTransport

    config = _config()
    dependencies = acceptance.default_dependencies()

    assert isinstance(
        dependencies.hugging_face_factory(config.hugging_face),
        HuggingFaceInventoryAdapter,
    )
    assert isinstance(
        dependencies.entra_factory(config.entra),
        EntraIdentityGovernanceAdapter,
    )
    assert isinstance(
        dependencies.servicenow_factory(config.servicenow),
        ServiceNowIRMTransport,
    )
    assert isinstance(
        dependencies.openai_costs_factory(config.openai_costs),
        OpenAIOrganizationCostCollector,
    )


def test_a_provider_disabled_by_configuration_is_skipped_not_blocked():
    mapping = _mapping()
    mapping["openai_costs"] = {"enable": False}
    dependencies, _snow, openai = _dependencies()
    config = acceptance.ProviderContractAcceptanceConfig.from_mapping(mapping)

    live = acceptance.run_acceptance(config, dependencies=dependencies)
    ready = acceptance.run_acceptance(
        config, readiness_only=True, dependencies=dependencies
    )

    checks = {item["provider"]: item for item in live["checks"]}
    assert checks["openai_costs"]["status"] == "skipped"
    assert checks["openai_costs"]["reason_code"] == "provider_disabled"
    assert live["status"] == "passed" and live["summary"]["skipped"] == 1
    assert ready["status"] == "ready"
    assert openai.requests == []

    for name in ("hugging_face", "entra", "servicenow"):
        mapping[name] = {"enable": False}
    none_enabled = acceptance.run_acceptance(
        acceptance.ProviderContractAcceptanceConfig.from_mapping(mapping),
        dependencies=dependencies,
    )
    assert none_enabled["status"] == "blocked"
