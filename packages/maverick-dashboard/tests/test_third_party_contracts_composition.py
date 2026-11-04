from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from maverick import third_party_contracts as contracts
from maverick_dashboard import third_party_contracts_composition as composition
from starlette.requests import Request

NOW = 2_000_000_000.0


def _config(**updates: object) -> dict[str, object]:
    section = {
        "enable": True,
        "max_records": 500,
        "retention_seconds": 86_400,
        "authority_max_age_seconds": 3_600,
    }
    section.update(updates)
    return {
        "third_party_management": {
            "enable": True,
            "intelligence": {"enable": True},
            "contracts": section,
        }
    }


def _request(app: FastAPI) -> Request:
    request = Request({"type": "http", "app": app, "state": {}})
    request.state.principal = SimpleNamespace(principal="user:operator")
    return request


def _authority() -> contracts.VendorAuthority:
    return contracts.issue_vendor_authority(
        tenant_id="tenant-a",
        vendor_id="vendor-1",
        vendor_revision=3,
        vendor_type="service_provider",
        criticality="high",
        jurisdiction_codes=("US",),
        classification_refs=("hosting",),
        issuer_ref="vendor-registry",
        issued_at=NOW - 60,
        valid_until=NOW + 3_600,
    )


def test_settings_are_closed_bounded_and_require_vendor_inventory() -> None:
    settings = composition.third_party_contracts_settings(_config())
    assert settings == composition.ThirdPartyContractsSettings(
        max_records=500,
        retention_seconds=86_400,
        authority_max_age_seconds=3_600,
    )
    assert composition.third_party_contracts_settings({}) is None
    with pytest.raises(composition.ThirdPartyContractsCompositionError, match="unknown"):
        composition.third_party_contracts_settings(_config(unknown=True))
    config = _config()
    config["third_party_management"]["intelligence"]["enable"] = False
    with pytest.raises(composition.ThirdPartyContractsCompositionError, match="intelligence"):
        composition.third_party_contracts_settings(config)


def test_install_is_lazy_idempotent_and_readiness_is_store_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    database = tmp_path / "contracts.sqlite3"
    app.state.third_party_contracts_store_path_factory = lambda **_: database
    monkeypatch.setattr(composition, "third_party_contracts_enabled", lambda _tenant: True)
    monkeypatch.setattr(
        composition,
        "settings_for_tenant",
        lambda _tenant: composition.ThirdPartyContractsSettings(500, 86_400, 3_600),
    )
    monkeypatch.setattr(composition.intelligence, "enabled", lambda: True)
    app.state.third_party_contracts_clock = lambda: NOW

    composition.install_third_party_contracts_composition(app)
    composition.install_third_party_contracts_composition(app)

    assert app.state.third_party_contracts_enabled_probe("tenant-a") is True
    assert app.state.third_party_contracts_readiness_probe("tenant-a") is True
    assert database.exists() is False
    assert app.state.third_party_contracts_composition_installed is True


def test_default_vendor_resolver_maps_exact_persisted_profile() -> None:
    app = FastAPI()
    profile = SimpleNamespace(
        vendor_id="vendor-1",
        revision=3,
        criticality=4,
        updated_at=NOW - 60,
        entity_identity_sha256="a" * 64,
        integrity_sha256="b" * 64,
        territories=("US", "CA"),
        service_categories=("hosting", "processor"),
        state="active",
    )
    calls: list[tuple[str, str]] = []

    class Store:
        def get_vendor(self, tenant: str, vendor: str):
            calls.append((tenant, vendor))
            return profile

    app.state.third_party_intelligence_store_factory = lambda **_: Store()
    app.state.third_party_contracts_clock = lambda: NOW
    resolver = composition.VendorProfileAuthorityResolver(
        app,
        tenant_id="tenant-a",
        settings=composition.ThirdPartyContractsSettings(500, 86_400, 3_600),
        request=_request(app),
        clock=lambda: NOW,
    )
    authority = resolver("tenant-a", "vendor-1", 3)
    assert authority.vendor_id == "vendor-1"
    assert authority.vendor_revision == 3
    assert authority.criticality == "high"
    assert authority.jurisdiction_codes == ("CA", "US")
    assert authority.classification_refs == ("hosting", "processor")
    assert calls == [("tenant-a", "vendor-1")]


def test_installed_factory_binds_request_principal_and_real_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    request = _request(app)
    settings = composition.ThirdPartyContractsSettings(500, 86_400, 3_600)
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: settings)
    monkeypatch.setattr(composition, "third_party_contracts_enabled", lambda _tenant: True)
    app.state.third_party_contracts_clock = lambda: NOW
    app.state.third_party_contracts_vendor_authority_resolver_factory = (
        lambda **_: lambda *_args: _authority()
    )
    app.state.third_party_contracts_store_path_factory = (
        lambda **_: tmp_path / "contracts.sqlite3"
    )
    composition.install_third_party_contracts_composition(app)
    principal = composition._expected_principal(request, "tenant-a")
    store = app.state.third_party_contracts_store_factory(
        tenant_id="tenant-a",
        principal_ref=principal,
        request=request,
    )
    record = store.create_contract(
        "tenant-a",
        vendor_id="vendor-1",
        vendor_revision=3,
        record_id="contract-1",
        title_ref="title",
        owner_ref="owner",
        status="draft",
        lifecycle={
            "agreement_type": "subscription",
            "agreement_ref": "agreement-ref",
            "effective_at": None,
            "expires_at": None,
            "renewal_mode": "manual",
            "notice_period_days": 30,
            "governing_law_ref": None,
            "parent_contract_id": None,
        },
        field_schema=[],
        field_values={},
        formulas=[],
        idempotency_key="create-1",
    )
    assert record.created_by_ref == principal
    assert store.verify_integrity("tenant-a")["verified"] is True
