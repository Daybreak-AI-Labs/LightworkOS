from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from maverick.customer_sandbox_lifecycle import (
    CustomerSandboxConfigError,
    CustomerSandboxLifecycleStore,
    LocalCustomerSandboxProvisioner,
    SourceTenantConfiguration,
)
from maverick_dashboard import customer_sandbox_api as api

NOW = 2_100_000_000.0
API = "/api/v1/customer-sandboxes"


def _digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state: dict[str, object] = {
        "enabled": True,
        "factory_calls": [],
        "permission_calls": [],
    }
    config = {"ai_governance": {"enabled": True, "mode": "review"}}

    def source(tenant_id: str) -> SourceTenantConfiguration:
        assert tenant_id == "production-a"
        return SourceTenantConfiguration(tenant_id, 1, _digest(config), config)

    def permission(request: Request, name: str) -> None:
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(name)
        if request.headers.get("X-Global-Admin") != "yes":
            raise HTTPException(status_code=403, detail="global admin required")

    monkeypatch.setattr(api, "require_global_permission", permission)
    monkeypatch.setattr(api, "caller_principal", lambda request: request.headers.get("X-Subject"))
    app = FastAPI()

    def store_factory(**kwargs):
        calls = state["factory_calls"]
        assert isinstance(calls, list)
        calls.append(kwargs)
        def gate() -> None:
            if state["enabled"] is not True:
                raise CustomerSandboxConfigError("customer_sandbox_lifecycle_disabled")

        return CustomerSandboxLifecycleStore(
            tmp_path / "lifecycle.sqlite3",
            source_resolver=source,
            principal_resolver=kwargs["principal_resolver"],
            provisioner=LocalCustomerSandboxProvisioner(tmp_path / "sandboxes"),
            config_gate=gate,
            target_collision_resolver=lambda _target: False,
            clock=lambda: NOW,
        )

    app.state.customer_sandbox_store_factory = store_factory
    app.state.customer_sandbox_capability_probe = lambda: state["enabled"] is True
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    return client, state, tmp_path


def _request_body() -> dict[str, object]:
    return {
        "source_tenant_id": "production-a",
        "target_sandbox_id": "production-a-sandbox",
        "module_allowlist": ["ai_governance"],
        "expires_at": float(NOW + 3_600),
        "retained_until": float(NOW + 7_200),
        "plan": "sandbox-small",
        "quota_bytes": 8_192,
        "max_attempts": 3,
        "idempotency_key": "api-request",
    }


def _headers(subject: str) -> dict[str, str]:
    return {"X-Global-Admin": "yes", "X-Subject": subject}


def test_all_routes_require_global_admin_and_strict_body(environment) -> None:
    client, state, _tmp_path = environment
    denied = client.post(f"{API}/operation-1/request", json=_request_body())
    assert denied.status_code == 403
    assert state["factory_calls"] == []

    malformed = _request_body()
    malformed["principal_ref"] = "attacker-selected"
    rejected = client.post(
        f"{API}/operation-1/request",
        headers=_headers("requester"),
        json=malformed,
    )
    assert rejected.status_code == 422
    assert state["factory_calls"] == []


def test_factory_receives_only_sealed_principal_authority(environment) -> None:
    client, state, _tmp_path = environment
    response = client.post(
        f"{API}/operation-1/request?tenant_id=attacker-query",
        headers={
            **_headers("requester"),
            "X-Tenant-ID": "attacker-header",
            "Cookie": "tenant=attacker-cookie",
        },
        json=_request_body(),
    )
    assert response.status_code == 200, response.text
    calls = state["factory_calls"]
    assert isinstance(calls, list) and calls
    assert set(calls[-1]) == {"principal_ref", "principal_resolver"}
    assert calls[-1]["principal_ref"] == calls[-1]["principal_resolver"]()


def test_four_eyes_lifecycle_and_boundaries(environment) -> None:
    client, _state, tmp_path = environment
    requested = client.post(
        f"{API}/operation-1/request",
        headers=_headers("requester"),
        json=_request_body(),
    )
    assert requested.status_code == 200, requested.text
    same = client.post(
        f"{API}/operation-1/approve",
        headers=_headers("requester"),
        json={"expected_revision": 1, "idempotency_key": "same-approver"},
    )
    assert same.status_code == 403
    approved = client.post(
        f"{API}/operation-1/approve",
        headers=_headers("reviewer"),
        json={"expected_revision": 1, "idempotency_key": "approve"},
    )
    assert approved.status_code == 200, approved.text
    active = client.post(
        f"{API}/operation-1/provision",
        headers=_headers("operator"),
        json={"expected_revision": 2, "idempotency_key": "provision", "retry": False},
    )
    assert active.status_code == 200, active.text
    assert active.json()["state"] == "active"
    assert list((tmp_path / "sandboxes" / "tenants").rglob("*-*.json"))
    status = client.get(f"{API}/status", headers=_headers("auditor"))
    assert status.status_code == 200
    assert status.json()["network_io"] is False
    assert status.json()["execution_sandbox"] is False
    assert status.json()["live_customer_acceptance_verified"] is False
    integrity = client.get(f"{API}/integrity/verify", headers=_headers("auditor"))
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is True


def test_factory_must_return_exact_core_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "require_global_permission", lambda _request, _name: None)
    monkeypatch.setattr(api, "caller_principal", lambda _request: "admin")
    app = FastAPI()
    app.state.customer_sandbox_store_factory = lambda **_kwargs: object()
    app.state.customer_sandbox_capability_probe = lambda: True
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.get(f"{API}/status")
    assert response.status_code == 503
    assert response.json()["detail"] == "customer sandbox authority is unavailable"


def test_disabled_probe_is_side_effect_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api, "require_global_permission", lambda _request, _name: None)
    app = FastAPI()
    calls: list[str] = []
    app.state.customer_sandbox_capability_probe = lambda: False
    app.state.customer_sandbox_store_factory = lambda **_kwargs: calls.append("constructed")
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    status = client.get(f"{API}/status")
    assert status.status_code == 200
    assert status.json()["enabled"] is False
    denied = client.post(f"{API}/operation-1/request", json=_request_body())
    assert denied.status_code == 403
    assert calls == []
    assert list(tmp_path.iterdir()) == []


def test_disabled_api_allows_list_suspend_and_four_eyes_destroy(environment) -> None:
    client, state, _tmp_path = environment
    assert client.post(
        f"{API}/operation-disabled/request",
        headers=_headers("requester"),
        json={**_request_body(), "idempotency_key": "disabled-api-request"},
    ).status_code == 200
    assert client.post(
        f"{API}/operation-disabled/approve",
        headers=_headers("approver"),
        json={"expected_revision": 1, "idempotency_key": "disabled-api-approve"},
    ).status_code == 200
    assert client.post(
        f"{API}/operation-disabled/provision",
        headers=_headers("operator"),
        json={
            "expected_revision": 2,
            "idempotency_key": "disabled-api-provision",
            "retry": False,
        },
    ).status_code == 200
    state["enabled"] = False
    assert client.get(API, headers=_headers("auditor")).status_code == 200
    denied = client.post(
        f"{API}/new-disabled/request",
        headers=_headers("requester"),
        json={**_request_body(), "idempotency_key": "blocked-disabled-request"},
    )
    assert denied.status_code == 403
    suspended = client.post(
        f"{API}/operation-disabled/suspend",
        headers=_headers("operator"),
        json={"expected_revision": 4, "idempotency_key": "disabled-api-suspend"},
    )
    assert suspended.status_code == 200, suspended.text
    requested = client.post(
        f"{API}/operation-disabled/destroy/request",
        headers=_headers("destroy-requester"),
        json={"expected_revision": 5, "idempotency_key": "disabled-api-destroy-request"},
    )
    assert requested.status_code == 200, requested.text
    approved = client.post(
        f"{API}/operation-disabled/destroy/approve",
        headers=_headers("destroy-approver"),
        json={"expected_revision": 6, "idempotency_key": "disabled-api-destroy-approve"},
    )
    assert approved.status_code == 200, approved.text
    destroyed = client.post(
        f"{API}/operation-disabled/destroy",
        headers=_headers("destroy-operator"),
        json={"expected_revision": 7, "idempotency_key": "disabled-api-destroy"},
    )
    assert destroyed.status_code == 200, destroyed.text
    assert destroyed.json()["state"] == "destroyed"


def test_api_exposes_four_eyes_stale_create_abandon(environment) -> None:
    client, _state, _tmp_path = environment
    requested = client.post(
        f"{API}/operation-abandon/request",
        headers=_headers("original-requester"),
        json={**_request_body(), "idempotency_key": "abandon-api-create"},
    )
    assert requested.status_code == 200, requested.text
    cleanup = client.post(
        f"{API}/operation-abandon/abandon/request",
        headers=_headers("cleanup-requester"),
        json={"expected_revision": 1, "idempotency_key": "abandon-api-request"},
    )
    assert cleanup.status_code == 200, cleanup.text
    same = client.post(
        f"{API}/operation-abandon/abandon/approve",
        headers=_headers("cleanup-requester"),
        json={"expected_revision": 2, "idempotency_key": "abandon-api-same"},
    )
    assert same.status_code == 403
    approval = client.post(
        f"{API}/operation-abandon/abandon/approve",
        headers=_headers("cleanup-approver"),
        json={"expected_revision": 2, "idempotency_key": "abandon-api-approve"},
    )
    assert approval.status_code == 200, approval.text
    abandoned = client.post(
        f"{API}/operation-abandon/abandon",
        headers=_headers("cleanup-operator"),
        json={"expected_revision": 3, "idempotency_key": "abandon-api-final"},
    )
    assert abandoned.status_code == 200, abandoned.text
    assert abandoned.json()["schema"] == "lightwork.customer-sandbox-tombstone.v1"


def test_integrity_route_sanitizes_corrupt_snapshot_json(environment) -> None:
    client, _state, tmp_path = environment
    assert client.post(
        f"{API}/operation-corrupt/request",
        headers=_headers("requester"),
        json={**_request_body(), "idempotency_key": "corrupt-api-create"},
    ).status_code == 200
    with sqlite3.connect(tmp_path / "lifecycle.sqlite3") as connection:
        connection.execute("UPDATE customer_sandbox_snapshots SET snapshot_json='{'")
    response = client.get(f"{API}/integrity/verify", headers=_headers("auditor"))
    assert response.status_code == 503
    assert response.json()["detail"] == "customer sandbox integrity verification failed"
