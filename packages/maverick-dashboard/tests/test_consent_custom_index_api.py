from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import consent_custom_index as indexes
from maverick_dashboard import consent_custom_index_api as api

from test_support.starlette_state import patch_state

BASE = "/api/v1/consent/custom-indexes"


class Runtime:
    tenant_id = "tenant-a"
    current_key_version = 7
    max_indexes = 2
    max_page_size = 2

    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def create_index(self, tenant_id: str, **payload: object) -> dict[str, object]:
        self.calls.append(("create", (tenant_id, payload)))
        return {
            "tenant_id": tenant_id,
            "index_id": payload["index_id"],
            "element_name": payload["element_name"],
            "state": "pending",
            "revision": 1,
        }

    def get_index(self, tenant_id: str, index_id: str) -> dict[str, object]:
        self.calls.append(("get", (tenant_id, index_id)))
        return {"tenant_id": tenant_id, "index_id": index_id, "revision": 1}

    def list_indexes_page(
        self, tenant_id: str, *, limit: int, cursor: str | None
    ) -> tuple[tuple[dict[str, object], ...], str | None]:
        self.calls.append(("list", (tenant_id, limit, cursor)))
        return (
            (
                {"tenant_id": tenant_id, "index_id": "index-a"},
                {"tenant_id": tenant_id, "index_id": "index-b"},
            ),
            "index-b",
        )

    def build_index(
        self, tenant_id: str, index_id: str, **payload: object
    ) -> dict[str, object]:
        self.calls.append(("build", (tenant_id, index_id, payload)))
        return {"tenant_id": tenant_id, "index_id": index_id, "revision": 2}

    def search(
        self, tenant_id: str, index_id: str, **payload: object
    ) -> dict[str, object]:
        self.calls.append(("search", (tenant_id, index_id, payload)))
        return {
            "tenant_id": tenant_id,
            "index_id": index_id,
            "profile_ids": ["profile-a"],
            "next_cursor": None,
        }

    def revoke_index(
        self, tenant_id: str, index_id: str, **payload: object
    ) -> dict[str, object]:
        self.calls.append(("revoke", (tenant_id, index_id, payload)))
        return {"tenant_id": tenant_id, "index_id": index_id, "state": "revoked"}

    def audit_history(self, tenant_id: str, *, limit: int) -> tuple[dict[str, object], ...]:
        self.calls.append(("history", (tenant_id, limit)))
        return ({"tenant_id": tenant_id, "action": "index_created"},)

    def verify_integrity(self, tenant_id: str) -> dict[str, object]:
        self.calls.append(("integrity", tenant_id))
        return {"tenant_id": tenant_id, "ok": True}


@pytest.fixture()
def environment(monkeypatch: pytest.MonkeyPatch):
    runtime = Runtime()
    state = SimpleNamespace(
        enabled=True,
        ready=True,
        factory_calls=[],
        permission_calls=[],
    )
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
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

    def factory(*, tenant_id: str, principal_ref: str, request: Request):
        state.factory_calls.append((tenant_id, principal_ref, request))
        return runtime

    deps = api.ConsentCustomIndexDependencies(
        store_factory=factory,
        enabled_probe=lambda _tenant: state.enabled,
        readiness_probe=lambda _tenant: state.ready,
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="user:admin")
        return await call_next(request)

    app.include_router(api.create_consent_custom_index_router(deps), prefix="/api/v1")
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), state, runtime


def test_status_is_store_free_literal_and_no_store(environment) -> None:
    client, state, _runtime = environment
    response = client.get(f"{BASE}/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is True
    assert payload["configured"] is True
    assert payload["ready"] is True
    assert payload["configuration"]["store_opened_for_status"] is False
    assert payload["configuration"][
        "tenant_actor_key_version_retention_caller_controlled"
    ] is False
    assert payload["search"]["request_body_only"] is True
    assert state.factory_calls == []
    assert response.headers["cache-control"] == "no-store, private, max-age=0"


def test_all_operations_are_closed_role_gated_and_page_clamped(environment) -> None:
    client, state, runtime = environment
    created = client.post(
        BASE,
        json={
            "index_id": "loyalty-index",
            "element_name": "loyalty-tier",
            "idempotency_key": "create-index-0001",
        },
    )
    assert created.status_code == 201
    assert created.json()["revision"] == 1

    listed = client.get(BASE, params={"limit": 500, "cursor": "index-a"})
    assert listed.status_code == 200
    assert listed.json()["applied_limit"] == 2
    assert ("list", ("tenant-a", 2, "index-a")) in runtime.calls

    assert client.get(f"{BASE}/loyalty-index").status_code == 200
    built = client.post(
        f"{BASE}/loyalty-index/build",
        json={"expected_revision": 1, "idempotency_key": "build-index-0001"},
    )
    assert built.status_code == 200
    searched = client.post(
        f"{BASE}/loyalty-index/search",
        json={"value": "gold", "limit": 500, "cursor": None},
    )
    assert searched.status_code == 200
    assert (
        "search",
        (
            "tenant-a",
            "loyalty-index",
            {"value": "gold", "limit": 2, "cursor": None},
        ),
    ) in runtime.calls
    revoked = client.post(
        f"{BASE}/loyalty-index/revoke",
        json={"expected_revision": 2, "idempotency_key": "revoke-index-0001"},
    )
    assert revoked.status_code == 200
    assert client.get(f"{BASE}/operations/history").status_code == 200
    assert client.get(f"{BASE}/operations/integrity").json()["ok"] is True
    assert ("global", "admin") in state.permission_calls
    assert ("global", "audit") in state.permission_calls


def test_schema_and_transport_reject_caller_authority_key_and_large_json(environment) -> None:
    client, state, _runtime = environment
    body = {
        "index_id": "loyalty-index",
        "element_name": "loyalty-tier",
        "idempotency_key": "create-index-0001",
        "tenant_id": "attacker",
        "actor_ref": "attacker",
        "key_version": 999,
        "key_secret_ref": "ATTACKER_KEY",
        "retention_seconds": 86_400,
    }
    assert client.post(BASE, json=body).status_code == 422
    assert state.factory_calls == []

    oversized = b'{"unknown":"' + (b"x" * (64 * 1024)) + b'"}'
    response = client.post(
        BASE,
        content=oversized,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["detail"] == "consent custom-index request exceeds 64 KiB"
    assert state.factory_calls == []

    unsupported = client.post(BASE, content=b"{}", headers={"Content-Type": "text/plain"})
    assert unsupported.status_code == 415


def test_disabled_unready_and_malformed_composition_never_open_store(
    environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, state, _runtime = environment
    state.ready = False
    assert client.get(BASE).status_code == 503
    assert state.factory_calls == []

    state.ready = True
    state.enabled = False
    assert client.get(BASE).status_code == 403
    assert state.factory_calls == []

    state.enabled = True
    state.ready = 1
    assert client.get(f"{BASE}/status").status_code == 503
    assert state.factory_calls == []

    state.ready = True
    malformed = Runtime()
    malformed.max_page_size = "unbounded"  # type: ignore[assignment]
    patch_state(
        monkeypatch,
        client.app.state,
        "consent_custom_index_store_factory",
        lambda **_kwargs: malformed,
        raising=False,
    )
    response = client.get(BASE)
    assert response.status_code == 503
    assert response.json()["detail"] == "consent custom-index authority is unavailable"


def test_core_errors_are_sanitized(environment, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _state, runtime = environment

    def conflict(*_args, **_kwargs):
        raise indexes.ConsentCustomIndexConflict("sensitive database state")

    monkeypatch.setattr(runtime, "build_index", conflict)
    response = client.post(
        f"{BASE}/loyalty-index/build",
        json={"expected_revision": 1, "idempotency_key": "build-index-0001"},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "consent custom-index state or revision conflicts"
    assert "sensitive" not in response.text
