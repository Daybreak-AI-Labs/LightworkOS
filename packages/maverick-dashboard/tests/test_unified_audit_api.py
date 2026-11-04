from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from maverick import unified_audit as audit
from maverick_dashboard import unified_audit_api as api

API = "/api/v1/audit/unified"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


class _Store:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def list_history(self, *, limit: int):
        self.calls.append(("history", limit))
        return ({"sequence": 1, "detail_sha256": DIGEST_A},)

    def verify_integrity(self):
        self.calls.append(("integrity", None))
        return {"valid": True, "history_events": 1}

    def replay_source(self, source_id: str, **kwargs):
        self.calls.append(("replay", (source_id, kwargs)))
        return {"source_id": source_id, "revision": 2, "complete": False}

    def revoke_source(self, source_id: str, **kwargs):
        self.calls.append(("revoke", (source_id, kwargs)))
        return {"source_id": source_id, "revision": 2, "revoked": True}

    def authorize_rotation(self, source_id: str, **kwargs):
        self.calls.append(("rotation", (source_id, kwargs)))
        return {"source_id": source_id, "revision": 2, "complete": False}


class _Projector:
    def __init__(self) -> None:
        self.store = _Store()
        self.calls: list[tuple[str, object]] = []

    def status(self):
        return {
            "enabled": True,
            "complete": False,
            "sources": [
                {"source_id": source_id, "complete": False} for source_id in audit.REQUIRED_SUITES
            ],
            "live_source_interoperability_verified": False,
            "live_customer_acceptance_verified": False,
        }

    def run_all(self, *, worker_id: str):
        self.calls.append(("all", worker_id))
        return ({"source_id": "ai_governance", "outcome": "unavailable"},)

    def run_source(self, source_id: str, *, worker_id: str):
        self.calls.append(("source", (source_id, worker_id)))
        return {"source_id": source_id, "outcome": "unavailable"}


@pytest.fixture()
def environment(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "world"))
    state: dict[str, object] = {
        "enabled": True,
        "tenant": "tenant-a",
        "permissions": [],
        "factory_calls": [],
    }
    projector = _Projector()

    def permission(request: Request, name: str) -> None:
        permissions = state["permissions"]
        assert isinstance(permissions, list)
        permissions.append(name)
        role = request.headers.get("X-Test-Role", "auditor")
        allowed = role == "admin" or (role == "auditor" and name == "audit")
        if not allowed:
            raise HTTPException(status_code=403, detail="denied")

    def require_enabled(_config=None):
        if not state["enabled"]:
            raise audit.UnifiedAuditConfigError("unified_audit_disabled")
        return audit.UnifiedAuditConfig(enable=True)

    monkeypatch.setattr(api, "_tenant_id", lambda: str(state["tenant"]))
    monkeypatch.setattr(api, "require_permission", permission)
    monkeypatch.setattr(audit, "require_enabled", require_enabled)

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(
            principal=request.headers.get("X-Test-Subject", "operator")
        )
        return await call_next(request)

    app.state.unified_audit_enabled_probe = lambda tenant: bool(
        state["enabled"] and tenant == state["tenant"]
    )

    def factory(tenant_id: str, principal_ref: str, request: Request):
        calls = state["factory_calls"]
        assert isinstance(calls, list)
        calls.append((tenant_id, principal_ref, request))
        return projector

    app.state.unified_audit_projector_factory = factory
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={
            "Origin": "http://127.0.0.1",
            "X-Test-Role": "auditor",
            "X-Test-Subject": "operator",
        },
    )
    return client, state, projector


def test_disabled_status_never_opens_projection_store_or_factory(
    environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, state, _projector = environment
    state["enabled"] = False

    def refuse_db(*_args, **_kwargs):
        raise AssertionError("disabled status opened sqlite")

    monkeypatch.setattr(sqlite3, "connect", refuse_db)
    response = client.get(f"{API}/status")
    assert response.status_code == 200
    assert response.json() == {
        "schema": "lightwork.unified-audit-api-status.v1",
        "enabled": False,
        "complete": False,
        "live_source_interoperability_verified": False,
        "live_customer_acceptance_verified": False,
        "required_sources": list(audit.REQUIRED_SUITES),
        "limits": {
            "status_request_opens_projection_store": False,
            "raw_event_ingestion_route": False,
            "caller_source_registration_route": False,
        },
    }
    assert state["factory_calls"] == []


def test_reads_require_audit_and_denial_precedes_factory(environment) -> None:
    client, state, _projector = environment
    for path in ("/status", "/sources", "/history", "/integrity"):
        denied = client.get(f"{API}{path}", headers={"X-Test-Role": "operator"})
        assert denied.status_code == 403
    assert state["factory_calls"] == []

    for path in ("/status", "/sources", "/history", "/integrity"):
        allowed = client.get(f"{API}{path}")
        assert allowed.status_code == 200, allowed.text
    permissions = state["permissions"]
    assert isinstance(permissions, list)
    assert permissions.count("audit") == 8


def test_mutations_require_admin_and_use_server_principal(environment) -> None:
    client, state, projector = environment
    operations = (
        ("/reconcile", {}),
        (
            "/sources/ai_governance/replay",
            {"expected_state_revision": 1, "reason_sha256": DIGEST_A},
        ),
        (
            "/sources/ai_governance/revoke",
            {"expected_state_revision": 1, "reason_sha256": DIGEST_A},
        ),
        (
            "/sources/ai_governance/rotation/authorize",
            {
                "expected_state_revision": 1,
                "expected_authority_revision": 1,
                "expected_authority_sha256": DIGEST_A,
                "new_authority_revision": 2,
                "new_authority_sha256": DIGEST_B,
                "new_source_schema_version": 2,
                "new_verifier_identity_sha256": DIGEST_A,
                "new_trust_root_revision": 2,
                "new_source_key_id_sha256": DIGEST_B,
                "reason_sha256": DIGEST_A,
            },
        ),
    )
    for path, body in operations:
        denied = client.post(f"{API}{path}", json=body)
        assert denied.status_code == 403
    assert state["factory_calls"] == []

    for path, body in operations:
        allowed = client.post(
            f"{API}{path}",
            json=body,
            headers={"X-Test-Role": "admin", "X-Test-Subject": "alice"},
        )
        assert allowed.status_code == 200, allowed.text
    factory_calls = state["factory_calls"]
    assert isinstance(factory_calls, list)
    assert len(factory_calls) == 4
    assert all(call[0] == "tenant-a" for call in factory_calls)
    assert all(str(call[1]).startswith("unified-audit-api.") for call in factory_calls)
    assert all("alice" not in str(call[1]) for call in factory_calls)
    assert projector.calls[0][0] == "all"
    rotation_call = projector.store.calls[-1]
    assert rotation_call[0] == "rotation"
    rotation_kwargs = rotation_call[1][1]
    assert rotation_kwargs["new_source_schema_version"] == 2
    assert rotation_kwargs["new_verifier_identity_sha256"] == DIGEST_A
    assert rotation_kwargs["new_trust_root_revision"] == 2
    assert rotation_kwargs["new_source_key_id_sha256"] == DIGEST_B


def test_source_and_body_contracts_are_closed_before_authority(environment) -> None:
    client, state, _projector = environment
    headers = {"X-Test-Role": "admin"}
    invalid = client.post(
        f"{API}/reconcile",
        json={"source_id": "caller_source", "credential": "secret"},
        headers=headers,
    )
    assert invalid.status_code == 422
    invalid_path = client.post(
        f"{API}/sources/caller_source/replay",
        json={"expected_state_revision": 1, "reason_sha256": DIGEST_A},
        headers=headers,
    )
    assert invalid_path.status_code == 422
    raw_reason = client.post(
        f"{API}/sources/ai_governance/revoke",
        json={"expected_state_revision": 1, "reason": "customer alice"},
        headers=headers,
    )
    assert raw_reason.status_code == 422
    incomplete_rotation = client.post(
        f"{API}/sources/ai_governance/rotation/authorize",
        json={
            "expected_state_revision": 1,
            "expected_authority_revision": 1,
            "expected_authority_sha256": DIGEST_A,
            "new_authority_revision": 2,
            "new_authority_sha256": DIGEST_B,
            "reason_sha256": DIGEST_A,
        },
        headers=headers,
    )
    assert incomplete_rotation.status_code == 422
    assert state["factory_calls"] == []


def test_tenant_and_principal_are_server_derived(environment) -> None:
    client, state, _projector = environment
    response = client.get(
        f"{API}/sources?tenant_id=victim&source_id=caller_source",
        headers={
            "X-Test-Subject": "real-subject",
            "X-Tenant-ID": "victim",
            "Cookie": "tenant=victim",
        },
    )
    assert response.status_code == 200
    calls = state["factory_calls"]
    assert isinstance(calls, list) and len(calls) == 1
    tenant, principal, _request = calls[0]
    assert tenant == "tenant-a"
    assert principal.startswith("unified-audit-api.")
    assert "tenant-a" not in principal
    assert "real-subject" not in principal


def test_injected_authority_failure_is_generic_service_unavailable(environment) -> None:
    client, _state, _projector = environment

    def broken_factory(_tenant, _principal, _request):
        raise audit.UnifiedAuditConfigError("raw-customer-secret")

    client.app.state.unified_audit_projector_factory = broken_factory
    response = client.get(f"{API}/sources")
    assert response.status_code == 503
    assert response.json() == {"detail": "unified-audit authority is unavailable"}
    assert "raw-customer-secret" not in response.text


def test_openapi_exposes_only_closed_operator_control_plane(environment) -> None:
    client, _state, _projector = environment
    paths = client.get("/openapi.json").json()["paths"]
    unified = {path for path in paths if path.startswith(API)}
    assert unified == {
        f"{API}/status",
        f"{API}/sources",
        f"{API}/history",
        f"{API}/integrity",
        f"{API}/reconcile",
        f"{API}/sources/{{source_id}}/replay",
        f"{API}/sources/{{source_id}}/revoke",
        f"{API}/sources/{{source_id}}/rotation/authorize",
    }
    serialized = repr({path: paths[path] for path in unified}).lower()
    assert "ingest" not in serialized
    assert "register" not in serialized
    assert "credential" not in serialized
    assert "tenant_id" not in serialized
