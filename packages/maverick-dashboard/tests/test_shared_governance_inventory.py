from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import shared_governance_inventory as inventory
from maverick_dashboard import shared_governance_inventory_api as api
from maverick_dashboard import shared_governance_inventory_composition as composition


def _config(**updates):
    section = {
        "enable": True,
        "retention_seconds": 86_400,
        "max_source_records": 100,
        "max_entities": 200,
        "max_relationships": 400,
        "max_export_bytes": 65_536,
        "max_snapshots": 50,
    }
    section.update(updates)
    return {"governance_inventory": section, "entity_graph": {"enable": True}}


def test_composition_settings_are_closed_bounded_and_require_entity_graph():
    settings = composition.inventory_settings(_config())
    assert settings == composition.SharedGovernanceInventorySettings(
        retention_seconds=86_400,
        max_source_records=100,
        max_entities=200,
        max_relationships=400,
        max_export_bytes=65_536,
        max_snapshots=50,
    )
    assert composition.inventory_settings({}) is None
    with pytest.raises(composition.SharedGovernanceInventoryCompositionError, match="unknown"):
        composition.inventory_settings(_config(injected=True))
    with pytest.raises(composition.SharedGovernanceInventoryCompositionError, match="entity_graph"):
        composition.inventory_settings(
            {"governance_inventory": {"enable": True}, "entity_graph": {"enable": False}}
        )


def test_install_is_lazy_idempotent_and_exposes_only_closed_runtime_factory(
    monkeypatch: pytest.MonkeyPatch,
):
    app = FastAPI()
    monkeypatch.setattr(composition, "inventory_enabled", lambda tenant: tenant == "tenant-a")
    monkeypatch.setattr(composition, "inventory_readiness", lambda tenant: tenant == "tenant-a")
    composition.install_shared_governance_inventory_composition(app)
    factory = app.state.shared_governance_inventory_runtime_factory
    composition.install_shared_governance_inventory_composition(app)
    assert app.state.shared_governance_inventory_runtime_factory is factory
    assert app.state.shared_governance_inventory_enabled_probe("tenant-a") is True
    assert app.state.shared_governance_inventory_readiness_probe("tenant-a") is True
    assert not hasattr(app.state, "shared_governance_inventory_source_provider_factory")


class _Runtime:
    def status(self):
        return {
            "schema": "lightwork.shared-governance-inventory-status.v1",
            "enabled": True,
            "state": "partial",
            "complete": False,
        }

    def active_authority(self):
        return {"revision": 1, "integrity_sha256": "a" * 64}

    def current_snapshot(self):
        return {
            "metadata": {
                "tenant_id": "tenant-a",
                "snapshot_id": "sgi-one",
                "version": 1,
            },
            "projection": {
                "tenant_id": "tenant-a",
                "state": "partial",
                "entities": [],
                "relationships": [],
            },
        }

    def get_snapshot(self, _snapshot_id):
        return self.current_snapshot()

    def list_snapshots(self, **_kwargs):
        return [self.current_snapshot()["metadata"]]

    def query_entities(self, **_kwargs):
        return {"items": [], "count": 0}

    def query_relationships(self, **_kwargs):
        return {"items": [], "count": 0}

    def export_snapshot(self, _snapshot_id=None):
        return {"schema": inventory.EXPORT_SCHEMA}

    def reconcile(self, **_kwargs):
        return self.current_snapshot()

    def purge_expired(self, **_kwargs):
        return {"purged_count": 0}

    def verify_integrity(self):
        return {"verified": True}

    def write_recovery_checkpoint(self):
        return {"written": True}

    def recover_latest(self):
        return {"recovered": True}


def test_api_is_tenant_derived_minimized_and_has_no_source_registration(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(api, "_principal_ref", lambda _request, _tenant: "principal-a")
    monkeypatch.setattr(api, "require_permission", lambda *_args: None)
    runtime = _Runtime()
    dependencies = api.SharedGovernanceInventoryDependencies(
        runtime_for=lambda **_kwargs: runtime,
        enabled_probe=lambda _tenant: True,
        readiness_probe=lambda _tenant: True,
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="operator")
        return await call_next(request)

    app.include_router(
        api.create_shared_governance_inventory_router(dependencies),
        prefix="/api/v1",
    )
    client = TestClient(app, base_url="http://127.0.0.1")
    assert client.get("/api/v1/governance/inventory/status").status_code == 200
    current = client.get("/api/v1/governance/inventory/snapshots/current")
    assert current.status_code == 200
    assert "tenant_id" not in current.json()["metadata"]
    assert "tenant_id" not in current.json()["projection"]
    injected = client.post(
        "/api/v1/governance/inventory/reconcile",
        json={
            "expected_active_revision": 0,
            "expected_active_integrity_sha256": "0" * 64,
            "operation_id": "reconcile-one",
            "tenant_id": "tenant-b",
        },
    )
    assert injected.status_code == 422
    paths = set(app.openapi()["paths"])
    assert not any("register" in path or "ingest" in path for path in paths)
