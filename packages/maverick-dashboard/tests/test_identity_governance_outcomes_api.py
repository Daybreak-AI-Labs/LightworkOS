from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick_dashboard import identity_governance_outcomes_api as api
from maverick_dashboard.identity_governance_runtime import (
    IdentityGovernanceOutcomeRuntime,
)


class Registry:
    def __init__(self) -> None:
        self.enrolled = []

    def resolve_change(self, value):
        return value

    def status(self):
        return {
            "active_binding_count": len(self.enrolled),
            "live_acceptance_verified": False,
        }

    def list_bindings(self, *, provider=None):
        del provider
        return list(self.enrolled)

    def enroll(self, binding, *, actor, expected_record_revision):
        assert actor == "user:admin"
        assert expected_record_revision == 0
        result = {
            "binding_id": "IGAB-" + ("1" * 32),
            "revision": 1,
            "status": "active",
            "binding": binding.__dict__,
            "binding_sha256": binding.binding_sha256,
            "revocation": None,
            "live_acceptance_verified": False,
        }
        self.enrolled.append(result)
        return result

    def revoke(self, *_args, **_kwargs):
        return {"status": "revoked"}


class Consumer:
    def status(self):
        return {"runtime_available": True, "live_acceptance_verified": False}

    def get(self, record_id):
        return {"outcome_id": record_id, "status": "completed"}

    def list(self, **_kwargs):
        return []

    def run_due(self, **_kwargs):
        return {"processed": 0}

    def replay(self, *_args, **_kwargs):
        return {"status": "pending"}

    def revoke(self, *_args, **_kwargs):
        return {"status": "revoked"}


def _client(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    monkeypatch.setattr(api, "require_global_permission", lambda *_args: None)
    monkeypatch.setattr(api, "caller_principal", lambda _request: "user:admin")
    registry = Registry()
    runtime = IdentityGovernanceOutcomeRuntime(
        tenant_sha256="a" * 64,
        asset_registry=registry,
        consumers={"dynamic_risk": Consumer(), "alert": Consumer()},
    )
    app = FastAPI()
    app.include_router(api.router, prefix="/api/v1/security")
    app.state.identity_governance_outcome_runtime_factory = lambda _tenant: runtime
    authorizations = []

    def authorize(tenant, principal, enrollment, approval):
        authorizations.append((tenant, principal, enrollment, approval))
        return True

    app.state.identity_governance_asset_binding_authorizer = authorize
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), registry, authorizations


def test_outcome_router_is_mounted_under_closed_security_path(monkeypatch):
    client, _registry, _authorizations = _client(monkeypatch)
    response = client.get(
        "/api/v1/security/assurance/identity-governance/outcomes/status"
    )
    assert response.status_code == 200
    assert response.json()["provider_writes"] is False
    assert response.json()["live_acceptance_verified"] is False


def test_binding_enrollment_requires_independent_authorization(monkeypatch):
    client, registry, authorizations = _client(monkeypatch)
    payload = {
        "provider": "entra",
        "selector_kind": "identities",
        "selector_sha256": "b" * 64,
        "asset_id": "MAA-" + ("c" * 32),
        "asset_revision": 2,
        "asset_version_digest": "d" * 64,
        "binding_revision": 1,
        "asset_criticality": "high",
        "eu_risk_tier": "high",
        "sensitive_data": "personal",
        "external_exposure": "partner",
        "expected_record_revision": 0,
        "authorization_sha256": "e" * 64,
    }
    response = client.post(
        "/api/v1/security/assurance/identity-governance/outcomes/bindings",
        json=payload,
    )
    assert response.status_code == 201
    assert response.json()["status"] == "active"
    assert len(registry.enrolled) == 1
    assert authorizations[0][0:2] == ("a" * 64, "user:admin")
    assert authorizations[0][3] == "e" * 64

    client.app.state.identity_governance_asset_binding_authorizer = lambda *_args: False
    rejected = client.post(
        "/api/v1/security/assurance/identity-governance/outcomes/bindings",
        json=payload,
    )
    assert rejected.status_code == 403


def test_outcome_api_never_accepts_a_tenant_field(monkeypatch):
    client, _registry, _authorizations = _client(monkeypatch)
    response = client.post(
        "/api/v1/security/assurance/identity-governance/outcomes/bindings",
        json={
            "tenant_sha256": "f" * 64,
            "provider": "entra",
            "selector_kind": "provider",
            "selector_sha256": "b" * 64,
            "asset_id": "MAA-" + ("c" * 32),
            "asset_revision": 1,
            "asset_version_digest": "d" * 64,
            "binding_revision": 1,
            "asset_criticality": "high",
            "eu_risk_tier": "high",
            "sensitive_data": "personal",
            "external_exposure": "partner",
            "expected_record_revision": 0,
            "authorization_sha256": "e" * 64,
        },
    )
    assert response.status_code == 422
