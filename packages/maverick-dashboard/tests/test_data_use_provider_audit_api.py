from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import data_use_provider_audit as audit
from maverick_dashboard import data_use_provider_audit_api as api

API = "/api/v1/data-use/providers/audit"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


class FakeStore:
    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.items = {
            f"expectation-{tenant_id}": {
                "expectation_id": f"expectation-{tenant_id}",
                "state": "dead_letter",
                "revision": 3,
                "integrity_sha256": SHA_A,
                "tenant_sha256": SHA_B,
            }
        }
        self.calls: list[tuple[str, object]] = []

    def state_counts(self):
        return {"queued": 0, "dead_letter": 1, "total": 1}

    def list_expectations(self, *, state, limit):
        self.calls.append(("list", (state, limit)))
        values = tuple(self.items.values())
        return values if state is None else tuple(v for v in values if v["state"] == state)

    def get_expectation(self, expectation_id):
        try:
            return self.items[expectation_id]
        except KeyError as exc:
            raise audit.DataUseProviderAuditNotFound("expectation does not exist") from exc

    def list_event_evidence(self, expectation_id, *, limit):
        self.get_expectation(expectation_id)
        self.calls.append(("evidence", limit))
        return (
            {
                "expectation_id": expectation_id,
                "event_id_sha256": SHA_A,
                "relation": "matched",
                "integrity_sha256": SHA_B,
            },
        )

    def cancel_expectation(self, expectation_id, **kwargs):
        current = self.get_expectation(expectation_id)
        self.calls.append(("cancel", kwargs))
        if kwargs["expected_revision"] != current["revision"]:
            raise audit.DataUseProviderAuditConflict("expectation changed")
        return {**current, "state": "cancelled", "revision": 4}

    def replay_dead_letter(self, expectation_id, **kwargs):
        current = self.get_expectation(expectation_id)
        self.calls.append(("replay", kwargs))
        if kwargs["expected_revision"] != current["revision"]:
            raise audit.DataUseProviderAuditConflict("expectation changed")
        return {**current, "state": "queued", "revision": 4}

    def verify_integrity(self):
        return {
            "expectations": 1,
            "history_records": 3,
            "event_records": 1,
            "operation_records": 2,
            "audit_events": 4,
            "terminal_audit_sha256": SHA_A,
        }


class FakeWorker:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def run_once(self, **kwargs):
        self.calls.append(kwargs)
        return audit.ProviderAuditWorkerResult(
            claimed=1,
            converged=0,
            no_change=0,
            findings=1,
            retried=0,
            dead_lettered=0,
            cancelled=0,
        )


class FakeReadGrants:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.current = {
            "grant_id": "DUAR-current",
            "provider_id": "snowflake",
            "binding_id": "binding-a",
            "binding_revision": 2,
            "binding_sha256": SHA_A,
            "capability": "provider_audit_read",
            "capability_revision": 4,
            "authority_sha256": SHA_B,
            "integrity_sha256": SHA_C,
            "valid_until": 1_800_003_600.0,
            "retained_until": 1_800_086_400.0,
            "revision": 1,
            "revoked": False,
        }
        self.replays: dict[str, dict[str, object]] = {}

    def get_current_read_grant(self, provider_id, binding_id):
        kwargs = {"provider_id": provider_id, "binding_id": binding_id}
        self.calls.append(("get", kwargs))
        return {**self.current, **kwargs}

    def issue_read_grant(
        self,
        *,
        provider_id,
        binding_id,
        expected_binding_revision,
        expected_binding_sha256,
        capability_revision,
        valid_until,
        retained_until,
        expected_revision,
        idempotency_key,
    ):
        kwargs = {
            "provider_id": provider_id,
            "binding_id": binding_id,
            "expected_binding_revision": expected_binding_revision,
            "expected_binding_sha256": expected_binding_sha256,
            "capability_revision": capability_revision,
            "valid_until": valid_until,
            "retained_until": retained_until,
            "expected_revision": expected_revision,
            "idempotency_key": idempotency_key,
        }
        self.calls.append(("issue", kwargs))
        self.current = {
            "grant_id": "DUAR-issued",
            "provider_id": kwargs["provider_id"],
            "binding_id": kwargs["binding_id"],
            "binding_revision": kwargs["expected_binding_revision"],
            "binding_sha256": kwargs["expected_binding_sha256"],
            "capability": "provider_audit_read",
            "capability_revision": kwargs["capability_revision"],
            "valid_until": kwargs["valid_until"],
            "retained_until": kwargs["retained_until"],
            "revision": 1,
            "authority_sha256": SHA_B,
            "integrity_sha256": SHA_C,
            "revoked": False,
        }
        return self.current

    def revoke_read_grant(
        self,
        grant_id,
        *,
        expected_revision,
        expected_integrity_sha256,
        reason_sha256,
        idempotency_key,
    ):
        replay = self.replays.get(idempotency_key)
        if replay is not None:
            return replay
        kwargs = {
            "grant_id": grant_id,
            "expected_revision": expected_revision,
            "expected_integrity_sha256": expected_integrity_sha256,
            "reason_sha256": reason_sha256,
            "idempotency_key": idempotency_key,
        }
        self.calls.append(("revoke", kwargs))
        assert grant_id == self.current["grant_id"]
        assert kwargs["expected_revision"] == self.current["revision"]
        assert kwargs["expected_integrity_sha256"] == self.current["integrity_sha256"]
        result = {
            **self.current,
            "revision": int(self.current["revision"]) + 1,
            "revoked": True,
        }
        self.replays[str(idempotency_key)] = result
        return result


@pytest.fixture()
def environment(monkeypatch: pytest.MonkeyPatch):
    state: dict[str, object] = {
        "enabled": True,
        "tenant": "tenant-a",
        "permissions": [],
    }
    stores: dict[str, FakeStore] = {}
    worker = FakeWorker()
    grants = FakeReadGrants()

    def require_enabled() -> None:
        if not state["enabled"]:
            raise audit.DataUseProviderAuditConfigError("disabled for test")

    def permission(_request, name):
        permissions = state["permissions"]
        assert isinstance(permissions, list)
        permissions.append(name)

    monkeypatch.setattr(audit, "require_enabled", require_enabled)
    monkeypatch.setattr(audit, "enabled", lambda: bool(state["enabled"]))
    monkeypatch.setattr(api, "_tenant_id", lambda: str(state["tenant"]))
    monkeypatch.setattr(api, "require_permission", permission)
    monkeypatch.setattr(api, "require_global_permission", permission)

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(
            principal=request.headers.get("X-Test-Subject", "operator")
        )
        return await call_next(request)

    def store_factory(**kwargs):
        tenant = kwargs["tenant_id"]
        stores.setdefault(tenant, FakeStore(tenant))
        return stores[tenant]

    def worker_factory(**kwargs):
        assert kwargs["tenant_id"] == state["tenant"]
        assert kwargs["store"] is stores[str(state["tenant"])]
        return worker

    def read_grant_factory(**kwargs):
        assert kwargs["tenant_id"] == state["tenant"]
        assert kwargs["store"] is stores[str(state["tenant"])]
        return grants

    app.state.data_use_provider_audit_store_factory = store_factory
    app.state.data_use_provider_audit_worker_factory = worker_factory
    app.state.data_use_provider_audit_read_grant_factory = read_grant_factory
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "operator"},
    )
    return client, state, stores, worker, grants


def test_status_is_candid_and_does_not_open_a_store(environment):
    client, _state, stores, _worker, _grants = environment
    response = client.get(f"{API}/status")
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is True
    assert body["store_dependency_injected"] is True
    assert body["worker_dependency_injected"] is True
    assert body["read_grant_authority_injected"] is True
    assert body["raw_provider_event_ingestion_exposed"] is False
    assert body["credentials_accepted_or_persisted"] is False
    assert body["provider_writes_performed"] is False
    assert body["built_in_network_transport_available"] is True
    assert body["built_in_network_transport"] is True
    assert body["network_transport_activation_verified"] is False
    assert body["live_provider_acceptance_verified"] is False
    assert stores == {}


def test_operator_read_surfaces_are_tenant_scoped_and_digest_only(environment):
    client, state, stores, _worker, _grants = environment
    expectation_id = "expectation-tenant-a"
    assert client.get(f"{API}/counts").json()["total"] == 1
    listed = client.get(f"{API}/expectations?state=dead_letter&limit=10")
    assert listed.status_code == 200
    assert listed.json()["items"][0]["expectation_id"] == expectation_id
    fetched = client.get(f"{API}/expectations/{expectation_id}")
    assert fetched.status_code == 200
    assert "lease_token" not in fetched.json()
    evidence = client.get(f"{API}/expectations/{expectation_id}/evidence")
    assert evidence.status_code == 200
    assert evidence.json()["items"][0]["event_id_sha256"] == SHA_A
    integrity = client.get(f"{API}/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is True

    state["tenant"] = "tenant-b"
    crossed = client.get(f"{API}/expectations/{expectation_id}")
    assert crossed.status_code == 404
    assert set(stores) == {"tenant-a", "tenant-b"}


def test_cancel_replay_require_strict_cas_and_idempotency(environment):
    client, _state, stores, _worker, _grants = environment
    expectation_id = "expectation-tenant-a"
    extra = client.post(
        f"{API}/expectations/{expectation_id}/cancel",
        json={
            "expected_revision": 3,
            "reason_code": "operator_cancelled",
            "idempotency_key": "cancel-1",
            "tenant_id": "victim",
            "credential": "secret",
        },
    )
    assert extra.status_code == 422
    assert stores == {}

    conflict = client.post(
        f"{API}/expectations/{expectation_id}/cancel",
        json={
            "expected_revision": 2,
            "reason_code": "operator_cancelled",
            "idempotency_key": "cancel-2",
        },
    )
    assert conflict.status_code == 409
    cancelled = client.post(
        f"{API}/expectations/{expectation_id}/cancel",
        json={
            "expected_revision": 3,
            "reason_code": "operator_cancelled",
            "idempotency_key": "cancel-3",
        },
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"
    replayed = client.post(
        f"{API}/expectations/{expectation_id}/replay",
        json={"expected_revision": 3, "idempotency_key": "replay-1"},
    )
    assert replayed.status_code == 200
    assert replayed.json()["state"] == "queued"
    permissions = _state["permissions"]
    assert isinstance(permissions, list)
    assert "admin" in permissions


def test_admin_run_once_uses_server_derived_worker_identity(environment):
    client, _state, _stores, worker, _grants = environment
    rejected = client.post(
        f"{API}/admin/run-once",
        json={"limit": 5, "worker_id": "caller", "tenant_id": "victim"},
    )
    assert rejected.status_code == 422
    assert worker.calls == []
    response = client.post(
        f"{API}/admin/run-once",
        json={
            "limit": 5,
            "lease_seconds": 60,
            "event_limit": 25,
            "backoff_seconds": 10,
        },
    )
    assert response.status_code == 200
    assert response.json()["claimed"] == 1
    call = worker.calls[0]
    assert call["limit"] == 5
    assert call["event_limit"] == 25
    assert str(call["worker_id"]).startswith("provider-audit-api.")
    assert "tenant-a" not in str(call["worker_id"])


def test_read_grant_authority_is_injected_and_resolves_credentials_server_side(environment):
    client, _state, _stores, _worker, grants = environment
    issue = client.post(
        f"{API}/read-authorities/snowflake/binding-a/issue",
        json={
            "expected_binding_revision": 2,
            "expected_binding_sha256": SHA_A,
            "capability_revision": 4,
            "valid_until": 1_800_003_600.0,
            "retained_until": 1_800_086_400.0,
            "expected_revision": 0,
            "idempotency_key": "grant-issue-1",
        },
    )
    assert issue.status_code == 200, issue.text
    assert issue.json()["capability"] == "provider_audit_read"
    assert issue.json()["binding_revision"] == 2
    assert issue.json()["binding_sha256"] == SHA_A
    assert issue.json()["capability_revision"] == 4
    assert issue.json()["valid_until"] == 1_800_003_600.0
    assert issue.json()["retained_until"] == 1_800_086_400.0
    status = client.get(f"{API}/read-authorities/snowflake/binding-a")
    assert status.status_code == 200
    assert status.json()["grant_id"] == issue.json()["grant_id"]
    revoke = client.post(
        f"{API}/read-authorities/grants/{issue.json()['grant_id']}/revoke",
        json={
            "expected_revision": 1,
            "expected_integrity_sha256": SHA_C,
            "reason_sha256": SHA_A,
            "idempotency_key": "grant-revoke-1",
        },
    )
    assert revoke.status_code == 200
    assert revoke.json()["revoked"] is True
    replay = client.post(
        f"{API}/read-authorities/grants/{issue.json()['grant_id']}/revoke",
        json={
            "expected_revision": 1,
            "expected_integrity_sha256": SHA_C,
            "reason_sha256": SHA_A,
            "idempotency_key": "grant-revoke-1",
        },
    )
    assert replay.status_code == 200
    assert replay.json() == revoke.json()
    assert [item[0] for item in grants.calls] == ["issue", "get", "revoke"]
    issue_call = grants.calls[0][1]
    assert issue_call == {
        "provider_id": "snowflake",
        "binding_id": "binding-a",
        "expected_binding_revision": 2,
        "expected_binding_sha256": SHA_A,
        "capability_revision": 4,
        "valid_until": 1_800_003_600.0,
        "retained_until": 1_800_086_400.0,
        "expected_revision": 0,
        "idempotency_key": "grant-issue-1",
    }
    revoke_call = grants.calls[2][1]
    assert revoke_call == {
        "grant_id": "DUAR-issued",
        "expected_revision": 1,
        "expected_integrity_sha256": SHA_C,
        "reason_sha256": SHA_A,
        "idempotency_key": "grant-revoke-1",
    }
    assert all("tenant_id" not in payload for _action, payload in grants.calls)
    assert all("credential" not in repr(payload) for _action, payload in grants.calls)


def test_read_grant_contract_rejects_relative_lifetime_and_raw_reason(environment):
    client, _state, stores, _worker, grants = environment
    issue = client.post(
        f"{API}/read-authorities/snowflake/binding-a/issue",
        json={
            "expected_binding_revision": 2,
            "expected_binding_sha256": SHA_A,
            "capability_revision": 4,
            "valid_for_seconds": 600,
            "expected_revision": 0,
            "idempotency_key": "grant-issue-relative",
        },
    )
    assert issue.status_code == 422
    revoke = client.post(
        f"{API}/read-authorities/grants/DUAR-current/revoke",
        json={
            "expected_revision": 1,
            "expected_integrity_sha256": SHA_C,
            "reason_code": "operator_revoked",
            "idempotency_key": "grant-revoke-raw-reason",
        },
    )
    assert revoke.status_code == 422
    assert stores == {}
    assert grants.calls == []


def test_openapi_has_no_raw_ingestion_or_tenant_selector(environment):
    client, _state, _stores, _worker, _grants = environment
    paths = client.get("/openapi.json").json()["paths"]
    audit_paths = {path: operations for path, operations in paths.items() if API[7:] in path}
    assert audit_paths
    assert all("ingest" not in path and "raw" not in path for path in audit_paths)
    assert all("{tenant" not in path for path in audit_paths)
    serialized = repr(audit_paths)
    assert "provider_origin" not in serialized
    assert "authorization" not in serialized


def test_disabled_or_missing_runtime_fails_closed(environment):
    client, state, _stores, _worker, _grants = environment
    state["enabled"] = False
    assert client.get(f"{API}/counts").status_code == 403

    state["enabled"] = True
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="operator")
        return await call_next(request)

    app.include_router(
        api.create_data_use_provider_audit_router(
            api.DataUseProviderAuditDependencies(store_for=lambda *_args: None)
        ),
        prefix="/api/v1",
    )
    isolated = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    # Merely importing/mounting the isolated module grants no store access.
    assert isolated.get(f"{API}/counts").status_code == 503
