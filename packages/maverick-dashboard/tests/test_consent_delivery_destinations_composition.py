from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick.consent_delivery import ConsentDeliveryStore
from maverick_dashboard import consent_delivery_destinations_composition as composition


def _config() -> dict:
    return {
        "consent_preferences": {
            "enable": True,
            "delivery": {
                "enable": True,
                "destinations": {
                    "enable": True,
                    "enabled_providers": ["salesforce"],
                    "timeout_seconds": 10,
                    "max_response_bytes": 65536,
                    "salesforce": {
                        "destination_id": "salesforce",
                        "origin": "https://tenant.my.salesforce.com",
                        "credential_secret_ref": "$SALESFORCE_CONSENT_TOKEN",
                        "credential_revision": 1,
                        "api_version": "v65.0",
                        "object_api_name": "Lightwork_Consent_Event__c",
                        "external_id_field": "Lightwork_Message_Id__c",
                        "payload_digest_field": "Lightwork_Payload_SHA256__c",
                    },
                },
            },
        }
    }


def _store(path: Path) -> ConsentDeliveryStore:
    return ConsentDeliveryStore(
        path,
        config_gate=lambda: True,
        origin_validator=lambda _origin: None,
    )


def test_attach_is_lazy_and_installs_tenant_factories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = SimpleNamespace(state=SimpleNamespace())
    monkeypatch.setattr(
        composition,
        "_tenant_config",
        lambda _tenant: (_ for _ in ()).throw(AssertionError("config loaded")),
    )
    composition.attach_consent_delivery_destinations(app)
    assert callable(app.state.consent_destination_runtime_factory)
    assert callable(app.state.consent_destination_readiness_probe)


def test_readiness_checks_reference_placement_without_secret_or_store_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = SimpleNamespace(
        state=SimpleNamespace(
            consent_destination_reconciliation_authority_factory=lambda **_kwargs: None
        )
    )
    current = _config()
    monkeypatch.setattr(composition, "_tenant_config", lambda _tenant: current)
    monkeypatch.setenv("SALESFORCE_CONSENT_TOKEN", "placed-but-not-read")
    composition.attach_consent_delivery_destinations(app)
    status = composition.consent_destination_readiness(app, "tenant-a")
    assert status["ready"] is True
    assert status["reconciliation_complete"] is True
    assert status["reconciliation_supported"] == {"salesforce": True}
    assert status["operation_store_opened"] is False
    assert status["credential_values_resolved"] is False
    assert status["provider_session_opened"] is False
    assert status["live_provider_acceptance_verified"] is False


def test_runtime_is_tenant_exact_lazy_and_rejects_config_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = _config()
    monkeypatch.setattr(composition, "_tenant_config", lambda _tenant: current)
    monkeypatch.setattr(
        "maverick.secret_provider.get_secret",
        lambda _name, _default=None: (_ for _ in ()).throw(
            AssertionError("secret resolved during composition")
        ),
    )
    app = SimpleNamespace(state=SimpleNamespace())
    runtime = composition.build_tenant_consent_destination_runtime(
        app,
        tenant_id="tenant-a",
        delivery_store=_store(tmp_path / "delivery.sqlite3"),
        operation_path=tmp_path / "operations.sqlite3",
    )
    assert runtime.tenant_id == "tenant-a"
    assert runtime.registry.binding("salesforce").tenant_id == "tenant-a"
    assert runtime.operation_store.verify_integrity()["records"] == 0
    runtime_status = runtime.transport.readiness()
    assert runtime_status["reconciliation_authority_installed"] is True
    assert runtime_status["reconciliation_supported"] == {"salesforce": True}

    current["consent_preferences"]["delivery"]["destinations"]["salesforce"][
        "credential_revision"
    ] = 2
    with pytest.raises(
        composition.ConsentDestinationCompositionError,
        match="configuration changed",
    ):
        runtime.transport.reconcile(
            destination_id="salesforce",
            message_sha256="0" * 64,
            request_sha256="1" * 64,
        )


def test_custom_transport_and_reconciler_are_resolved_for_exact_tenant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(composition, "_tenant_config", lambda _tenant: _config())
    seen: list[tuple[str, str]] = []

    class HTTP:
        def request(self, _request):
            raise AssertionError("provider I/O is not expected during construction")

    class Reconciler:
        def inspect(self, _probe):
            raise AssertionError("reconciliation is not expected during construction")

    app = SimpleNamespace(
        state=SimpleNamespace(
            consent_destination_http_transport_factory=lambda *, tenant_id: (
                seen.append(("http", tenant_id)) or HTTP()
            ),
            consent_destination_reconciliation_authority_factory=lambda *, tenant_id: (
                seen.append(("reconciler", tenant_id)) or Reconciler()
            ),
        )
    )
    runtime = composition.build_tenant_consent_destination_runtime(
        app,
        tenant_id="tenant-a",
        delivery_store=_store(tmp_path / "delivery.sqlite3"),
        operation_path=tmp_path / "operations.sqlite3",
    )
    assert runtime.transport.readiness()["reconciliation_authority_installed"] is True
    assert seen == [("http", "tenant-a"), ("reconciler", "tenant-a")]


def test_stock_readback_readiness_is_provider_specific_and_aep_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = _config()
    destinations = current["consent_preferences"]["delivery"]["destinations"]
    destinations["enabled_providers"] = ["adobe_experience_platform"]
    destinations.pop("salesforce")
    destinations["adobe_experience_platform"] = {
        "destination_id": "aep",
        "origin": "https://dcs.adobedc.net",
        "credential_secret_ref": "$AEP_CONSENT_CREDENTIAL",
        "credential_revision": 1,
        "connection_id": "connection-123",
        "flow_id": "flow-123",
        "dataset_id": "dataset-123",
        "schema_id": "https://ns.adobe.com/example/schemas/consent",
        "ims_org_id": "123456@AdobeOrg",
    }
    monkeypatch.setattr(composition, "_tenant_config", lambda _tenant: current)
    monkeypatch.setenv("AEP_CONSENT_CREDENTIAL", "placed-but-not-read")
    app = SimpleNamespace(state=SimpleNamespace())
    composition.attach_consent_delivery_destinations(app)

    status = composition.consent_destination_readiness(app, "tenant-a")

    assert status["ready"] is False
    assert status["reconciliation_complete"] is False
    assert status["reconciliation_supported"] == {
        "adobe_experience_platform": False
    }
    assert status["stock_reconciliation_authority_installed"] is True
    assert status["provider_session_opened"] is False
