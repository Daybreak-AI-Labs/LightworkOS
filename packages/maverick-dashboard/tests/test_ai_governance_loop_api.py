from __future__ import annotations

import hashlib

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import ai_governance_loop as loop
from maverick_dashboard import ai_governance_loop_api as api

TENANT = "tenant-loop"
ASSET = "MAA-0123456789abcdef0123456789abcdef"
BASE = "/api/v1/assurance/governance-loop"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


class Runtime:
    def __init__(self, tenant_id: str, principal_ref: str) -> None:
        self.tenant_id = tenant_id
        self.principal_ref = principal_ref
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def status(self):
        return {
            "schema": "runtime",
            "enabled": True,
            "principal_bound": True,
            "http_trigger_ingestion_available": False,
        }

    def get_case(self, asset_id):
        self.calls.append(("get_case", asset_id, {}))
        return {"asset_id": asset_id, "tenant_id": self.tenant_id, "revision": 7}

    def history(self, asset_id, **kwargs):
        self.calls.append(("history", asset_id, kwargs))
        return ({"sequence": 1, "event_type": "reconciled"},)

    def verify_integrity(self, asset_id):
        self.calls.append(("verify_integrity", asset_id, {}))
        return {"asset_id": asset_id, "valid": True}

    def _mutation(self, name, asset_id, kwargs):
        self.calls.append((name, asset_id, kwargs))
        return {"asset_id": asset_id, "operation": name, "revision": 8}

    def authorize_control(self, asset_id, **kwargs):
        return self._mutation("authorize_control", asset_id, kwargs)

    def revoke_control_authorization(self, asset_id, **kwargs):
        return self._mutation("revoke_control_authorization", asset_id, kwargs)

    def replay(self, asset_id, **kwargs):
        return self._mutation("replay", asset_id, kwargs)

    def authorize_rollback(self, asset_id, **kwargs):
        return self._mutation("authorize_rollback", asset_id, kwargs)

    def revoke_rollback_authorization(self, asset_id, **kwargs):
        return self._mutation("revoke_rollback_authorization", asset_id, kwargs)

    def apply_authorized_rollback(self, asset_id, **kwargs):
        return self._mutation("apply_authorized_rollback", asset_id, kwargs)

    def revoke_case(self, asset_id, **kwargs):
        return self._mutation("revoke_case", asset_id, kwargs)


@pytest.fixture()
def environment(monkeypatch: pytest.MonkeyPatch):
    state: dict[str, object] = {
        "enabled": True,
        "factory_calls": [],
        "runtimes": [],
    }
    monkeypatch.setattr(api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(
        api,
        "caller_principal",
        lambda request: f"user:{request.headers.get('X-Test-Subject', 'reviewer')}",
    )

    def factory(tenant_id: str, principal_ref: str, request: Request):
        calls = state["factory_calls"]
        assert isinstance(calls, list)
        calls.append((tenant_id, principal_ref, request))
        runtime = Runtime(tenant_id, principal_ref)
        runtimes = state["runtimes"]
        assert isinstance(runtimes, list)
        runtimes.append(runtime)
        return runtime

    deps = api.AIGovernanceLoopDependencies(
        runtime_for=factory,
        enabled_probe=lambda _tenant: bool(state["enabled"]),
    )
    app = FastAPI()
    app.include_router(api.create_ai_governance_loop_router(deps), prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "reviewer"},
    )
    return client, state, app


def test_status_default_off_does_not_construct_runtime(environment) -> None:
    client, state, _app = environment
    state["enabled"] = False
    response = client.get(f"{BASE}/status")
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is False
    assert body["limits"] == {
        "status_request_opens_store": False,
        "http_trigger_ingestion_available": False,
        "raw_telemetry_accepted": False,
        "authority_snapshot_accepted": False,
        "provider_selector_accepted": False,
    }
    assert state["factory_calls"] == []
    assert client.get(f"{BASE}/cases/{ASSET}").status_code == 403
    assert state["factory_calls"] == []


def test_enabled_status_and_reads_use_server_tenant_and_principal(environment) -> None:
    client, state, _app = environment
    status = client.get(f"{BASE}/status")
    assert status.status_code == 200
    assert status.json()["schema"] == "lightwork.ai-governance-loop-api-status.v1"
    case = client.get(f"{BASE}/cases/{ASSET}")
    assert case.status_code == 200
    assert case.json()["tenant_id"] == TENANT
    history = client.get(f"{BASE}/cases/{ASSET}/history?limit=17")
    assert history.status_code == 200
    assert history.json()["count"] == 1
    integrity = client.get(f"{BASE}/cases/{ASSET}/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is True

    calls = state["factory_calls"]
    assert isinstance(calls, list) and calls
    first_tenant, first_principal, first_request = calls[0]
    assert first_tenant == TENANT
    assert first_principal.startswith("ai-governance-loop-api.")
    assert isinstance(first_request, Request)
    other = client.get(
        f"{BASE}/status",
        headers={"X-Test-Subject": "other-reviewer"},
    )
    assert other.status_code == 200
    assert calls[-1][1] != first_principal


@pytest.mark.parametrize(
    ("path", "method", "body"),
    [
        (
            "control/authorize",
            "authorize_control",
            {
                "expected_revision": 7,
                "reason_sha256": digest("reason"),
                "operation_id": "operation-1",
                "decision": "restrict",
            },
        ),
        (
            "control/revoke",
            "revoke_control_authorization",
            {
                "expected_revision": 7,
                "reason_sha256": digest("reason"),
                "operation_id": "operation-2",
            },
        ),
        (
            "replay",
            "replay",
            {
                "expected_revision": 7,
                "reason_sha256": digest("reason"),
                "operation_id": "operation-3",
            },
        ),
        (
            "rollback/authorize",
            "authorize_rollback",
            {
                "expected_revision": 7,
                "target_revision": 3,
                "reason_sha256": digest("reason"),
                "operation_id": "operation-4",
            },
        ),
        (
            "rollback/revoke",
            "revoke_rollback_authorization",
            {
                "expected_revision": 7,
                "reason_sha256": digest("reason"),
                "operation_id": "operation-5",
            },
        ),
        (
            "rollback/apply",
            "apply_authorized_rollback",
            {"expected_revision": 7, "operation_id": "operation-6"},
        ),
        (
            "revoke",
            "revoke_case",
            {
                "expected_revision": 7,
                "reason_sha256": digest("reason"),
                "operation_id": "operation-7",
            },
        ),
    ],
)
def test_every_human_control_is_exposed_without_identity_selectors(
    environment,
    path: str,
    method: str,
    body: dict[str, object],
) -> None:
    client, state, _app = environment
    response = client.post(f"{BASE}/cases/{ASSET}/{path}", json=body)
    assert response.status_code == 200, response.text
    assert response.json()["operation"] == method
    runtimes = state["runtimes"]
    assert isinstance(runtimes, list)
    runtime = runtimes[-1]
    assert runtime.calls[-1][0] == method
    assert runtime.calls[-1][1] == ASSET
    assert "tenant_id" not in runtime.calls[-1][2]
    assert "principal" not in runtime.calls[-1][2]


def test_request_contract_rejects_raw_telemetry_authority_and_actor_fields(environment) -> None:
    client, _state, app = environment
    valid = {
        "expected_revision": 7,
        "reason_sha256": digest("reason"),
        "operation_id": "operation-1",
        "decision": "restrict",
    }
    forbidden = {
        "tenant_id": "tenant-other",
        "principal_ref": "forged-admin",
        "actor": "forged-admin",
        "raw_telemetry": {"prompt": "secret"},
        "authority_snapshot": {"policy": "forged"},
        "provider": "openai",
        "credential": "secret",
        "trigger": {"code": "policy_changed"},
    }
    for field, value in forbidden.items():
        response = client.post(
            f"{BASE}/cases/{ASSET}/control/authorize",
            json={**valid, field: value},
        )
        assert response.status_code == 422, (field, response.text)
    assert (
        client.post(
            f"{BASE}/cases/{ASSET}/control/authorize",
            json={**valid, "expected_revision": "7"},
        ).status_code
        == 422
    )

    paths = app.openapi()["paths"]
    governance_paths = {path for path in paths if "governance-loop" in path}
    assert governance_paths
    assert all("trigger" not in path for path in governance_paths)
    assert client.post(f"{BASE}/triggers", json={}).status_code == 404


def test_missing_or_mismatched_runtime_and_closed_core_errors_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(api, "caller_principal", lambda _request: "user:reviewer")

    app = FastAPI()
    app.include_router(
        api.create_ai_governance_loop_router(
            api.AIGovernanceLoopDependencies(enabled_probe=lambda _tenant: True)
        ),
        prefix="/api/v1",
    )
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get(f"{BASE}/status").status_code == 503

    def mismatched(_tenant, principal, _request):
        return Runtime("tenant-other", principal)

    mismatch = FastAPI()
    mismatch.include_router(
        api.create_ai_governance_loop_router(
            api.AIGovernanceLoopDependencies(
                runtime_for=mismatched,
                enabled_probe=lambda _tenant: True,
            )
        ),
        prefix="/api/v1",
    )
    mismatch_client = TestClient(mismatch, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert mismatch_client.get(f"{BASE}/status").status_code == 503

    class Failing(Runtime):
        def get_case(self, asset_id):
            del asset_id
            raise loop.AIGovernanceLoopNotFound("missing")

        def verify_integrity(self, asset_id):
            del asset_id
            raise loop.AIGovernanceLoopIntegrityError("secret-corruption-detail")

    def failing(tenant, principal, _request):
        return Failing(tenant, principal)

    failed = FastAPI()
    failed.include_router(
        api.create_ai_governance_loop_router(
            api.AIGovernanceLoopDependencies(
                runtime_for=failing,
                enabled_probe=lambda _tenant: True,
            )
        ),
        prefix="/api/v1",
    )
    failed_client = TestClient(failed, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert failed_client.get(f"{BASE}/cases/{ASSET}").status_code == 404
    integrity = failed_client.get(f"{BASE}/cases/{ASSET}/integrity")
    assert integrity.status_code == 503
    assert "secret-corruption-detail" not in integrity.text
