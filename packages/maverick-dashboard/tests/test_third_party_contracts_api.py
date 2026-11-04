from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import third_party_contracts as contracts
from maverick_dashboard import third_party_contracts_api as api

BASE = "/api/v1/third-party/contracts"
NOW = 2_000_000_000.0


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state = SimpleNamespace(
        tenant="tenant-a",
        enabled=True,
        ready=True,
        factory_calls=[],
        readiness_calls=[],
        permission_calls=[],
        sensitive_allowed=False,
        maintenance=True,
    )
    authority = contracts.issue_vendor_authority(
        tenant_id=state.tenant,
        vendor_id="vendor-1",
        vendor_revision=4,
        vendor_type="service_provider",
        criticality="high",
        jurisdiction_codes=("US",),
        classification_refs=("processor",),
        issuer_ref="vendor-registry",
        issued_at=NOW - 60,
        valid_until=NOW + 86_400,
    )
    database = tmp_path / "contracts.sqlite3"
    monkeypatch.setattr(api, "_tenant_id", lambda: state.tenant)
    monkeypatch.setattr(
        api,
        "require_permission",
        lambda _request, permission: state.permission_calls.append(("tenant", permission)),
    )
    monkeypatch.setattr(
        api,
        "require_global_permission",
        lambda _request, permission: state.permission_calls.append(("global", permission)),
    )
    monkeypatch.setattr(
        api,
        "has_global_permission",
        lambda _request, permission: state.sensitive_allowed and permission == "audit",
    )

    def factory(*, tenant_id: str, principal_ref: str, request: Request):
        state.factory_calls.append((tenant_id, principal_ref, request))
        return contracts.ThirdPartyContractStore(
            database,
            tenant_id=tenant_id,
            vendor_authority_resolver=lambda *_: authority,
            principal_resolver=lambda: principal_ref,
            maintenance_authorizer=lambda: state.maintenance,
            config_gate=lambda: None,
            clock=lambda: NOW,
        )

    def readiness(tenant_id: str) -> bool:
        state.readiness_calls.append(tenant_id)
        return state.ready

    dependencies = api.ThirdPartyContractDependencies(
        store_factory=factory,
        enabled_probe=lambda _tenant: state.enabled,
        readiness_probe=readiness,
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="user:operator")
        return await call_next(request)

    app.include_router(api.create_third_party_contracts_router(dependencies), prefix="/api/v1")
    return TestClient(app, base_url="http://127.0.0.1"), state


def _contract_body(**updates: object) -> dict[str, object]:
    body: dict[str, object] = {
        "vendor_id": "vendor-1",
        "vendor_revision": 4,
        "record_id": "contract-api-1",
        "title_ref": "contract-title-ref",
        "owner_ref": "owner-1",
        "status": "draft",
        "lifecycle": {
            "agreement_type": "subscription",
            "agreement_ref": "agreement-ref",
            "effective_at": NOW + 100,
            "expires_at": NOW + 10_000,
            "renewal_mode": "automatic",
            "notice_period_days": 30,
            "governing_law_ref": "law-ref",
            "parent_contract_id": None,
        },
        "field_schema": [
            {
                "field_id": "annual_cost",
                "label_ref": "annual-cost-label",
                "field_type": "decimal",
                "required": True,
                "sensitivity": "confidential",
                "options": [],
            },
            {
                "field_id": "regions",
                "label_ref": "regions-label",
                "field_type": "multi_choice",
                "required": True,
                "sensitivity": "internal",
                "options": ["us", "ca"],
            },
        ],
        "field_values": {"annual_cost": 60_000.0, "regions": ["us", "ca"]},
        "formulas": [
            {
                "formula_id": "cost_per_region",
                "operator": "divide",
                "operands": [
                    {"source": "field", "field_id": "annual_cost", "value": None},
                    {"source": "field", "field_id": "regions", "value": None},
                ],
                "round_digits": 2,
            }
        ],
        "idempotency_key": "create-contract-api",
    }
    body.update(updates)
    return body


def _engagement_body() -> dict[str, object]:
    return {
        "vendor_id": "vendor-1",
        "vendor_revision": 4,
        "record_id": "engagement-api-1",
        "title_ref": "engagement-title-ref",
        "owner_ref": "owner-1",
        "status": "planned",
        "lifecycle": {
            "engagement_type": "software",
            "service_category_ref": "ai-service",
            "start_at": NOW + 200,
            "end_at": NOW + 9_000,
            "operational_criticality": "high",
            "data_access": "confidential",
            "hosting_model": "vendor_cloud",
            "linked_contract_ids": ["contract-api-1"],
            "business_owner_ref": "business-owner",
        },
        "field_schema": [],
        "field_values": {},
        "formulas": [],
        "idempotency_key": "create-engagement-api",
    }


def test_status_is_store_free_and_honest(environment) -> None:
    client, state = environment
    response = client.get(f"{BASE}/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is True
    assert payload["ready"] is True
    assert payload["configuration"]["store_opened_for_status"] is False
    assert payload["vendor_authority_caller_controlled"] is False
    assert payload["arbitrary_formula_execution_supported"] is False
    assert payload["licensed_template_content_included"] is False
    assert state.factory_calls == []
    assert response.headers["cache-control"].startswith("no-store")


def test_contract_engagement_round_trip_redaction_history_and_integrity(environment) -> None:
    client, state = environment
    created = client.post(f"{BASE}/contracts", json=_contract_body())
    assert created.status_code == 200
    contract = created.json()
    assert contract["record_kind"] == "contract"
    assert contract["field_values"]["annual_cost"] == {"redacted": True}
    assert contract["computed_values"] == {"cost_per_region": 30_000.0}

    engagement = client.post(f"{BASE}/engagements", json=_engagement_body())
    assert engagement.status_code == 200
    assert engagement.json()["record_kind"] == "engagement"

    listed = client.get(BASE, params={"vendor_id": "vendor-1"})
    assert listed.status_code == 200
    assert listed.json()["count"] == 2

    denied = client.get(
        f"{BASE}/{contract['record_id']}",
        params={"include_sensitive_fields": True},
    )
    assert denied.status_code == 403
    state.sensitive_allowed = True
    sensitive = client.get(
        f"{BASE}/{contract['record_id']}",
        params={"include_sensitive_fields": True},
    )
    assert sensitive.status_code == 200
    assert sensitive.json()["field_values"]["annual_cost"] == 60_000.0

    updated = client.patch(
        f"{BASE}/contracts/{contract['record_id']}",
        json={
            "expected_revision": 1,
            "status": "active",
            "owner_ref": "owner-2",
            "idempotency_key": "update-contract-api",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["revision"] == 2
    history = client.get(f"{BASE}/{contract['record_id']}/history")
    assert history.status_code == 200
    assert [event["event_type"] for event in history.json()["items"]] == [
        "contract_created",
        "contract_updated",
    ]
    integrity = client.get(f"{BASE}/operations/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["verified"] is True
    assert ("tenant", "operate") in state.permission_calls
    assert ("global", "audit") in state.permission_calls


def test_archive_delete_and_tombstone_lifecycle(environment) -> None:
    client, _state = environment
    created = client.post(f"{BASE}/contracts", json=_contract_body()).json()
    archived = client.post(
        f"{BASE}/{created['record_id']}/archive",
        json={"expected_revision": 1, "idempotency_key": "archive-api"},
    )
    assert archived.status_code == 200
    assert archived.json()["status"] == "archived"
    deleted = client.request(
        "DELETE",
        f"{BASE}/{created['record_id']}",
        json={"expected_revision": 2, "idempotency_key": "delete-api"},
    )
    assert deleted.status_code == 200
    assert deleted.json()["record_id"] == created["record_id"]
    assert client.get(f"{BASE}/{created['record_id']}").status_code == 404
    tombstone = client.get(f"{BASE}/{created['record_id']}/tombstone")
    assert tombstone.status_code == 200
    assert tombstone.json()["last_revision"] == 2


def test_schema_rejects_tenant_actor_authority_and_executable_formula(environment) -> None:
    client, _state = environment
    injected = _contract_body(
        tenant_id="tenant-b",
        actor_ref="attacker",
        vendor_authority={"authority_sha256": "0" * 64},
    )
    assert client.post(f"{BASE}/contracts", json=injected).status_code == 422

    unsafe = _contract_body()
    unsafe["formulas"][0]["expression"] = "__import__('os')"
    assert client.post(f"{BASE}/contracts", json=unsafe).status_code == 422

    empty = client.patch(
        f"{BASE}/contracts/contract-api-1",
        json={"expected_revision": 1, "idempotency_key": "empty-update"},
    )
    assert empty.status_code == 422
    assert empty.json()["detail"] == "Contract lifecycle update is empty"


def test_disabled_unready_and_malformed_store_fail_before_use(environment, monkeypatch) -> None:
    client, state = environment
    state.ready = False
    response = client.post(f"{BASE}/contracts", json=_contract_body())
    assert response.status_code == 503
    assert state.factory_calls == []

    state.ready = True
    state.enabled = False
    response = client.post(f"{BASE}/contracts", json=_contract_body())
    assert response.status_code == 403
    assert state.factory_calls == []

    state.enabled = True
    monkeypatch.setattr(
        client.app.state,
        "third_party_contracts_store_factory",
        lambda **_kwargs: SimpleNamespace(tenant_id="tenant-a"),
        raising=False,
    )
    response = client.post(f"{BASE}/contracts", json=_contract_body())
    assert response.status_code == 503
    assert response.json()["detail"] == "Contract lifecycle store is unavailable"
