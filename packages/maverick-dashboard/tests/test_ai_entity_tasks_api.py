from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import ai_entity_tasks as tasks
from maverick_dashboard import ai_entity_tasks_api as api

BASE = "/api/v1/ai-entity-tasks"
NOW = 1_900_000_000.0


class Clock:
    value = NOW

    def __call__(self) -> float:
        return self.value


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state = SimpleNamespace(
        tenant="tenant-a",
        enabled=True,
        ready=True,
        factory_calls=[],
        readiness_calls=[],
        permission_calls=[],
        maintenance=False,
    )
    clock = Clock()
    authority = tasks.issue_entity_authority(
        tenant_id=state.tenant,
        entity_id="model.support",
        entity_revision=8,
        entity_type="model",
        issuer_ref="inventory-authority",
        issued_at=NOW - 60,
        valid_until=NOW + 86_400,
    )
    database = tmp_path / "ai-entity-tasks.sqlite3"
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

    def factory(*, tenant_id: str, principal_ref: str, request: Request):
        state.factory_calls.append((tenant_id, principal_ref, request))
        return tasks.AIEntityTaskStore(
            database,
            tenant_id=tenant_id,
            entity_authority_resolver=lambda *_args: authority,
            principal_resolver=lambda: principal_ref,
            maintenance_authorizer=lambda: state.maintenance,
            config_gate=lambda: None,
            clock=clock,
            id_factory=lambda: "AIT-api-task",
        )

    def readiness(tenant_id: str) -> bool:
        state.readiness_calls.append(tenant_id)
        return state.ready

    deps = api.AIEntityTaskDependencies(
        store_factory=factory,
        enabled_probe=lambda _tenant: state.enabled,
        readiness_probe=readiness,
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="user:operator")
        return await call_next(request)

    app.include_router(api.create_ai_entity_tasks_router(deps), prefix="/api/v1")
    return TestClient(app, base_url="http://127.0.0.1"), state


def _create_body(**updates: object) -> dict[str, object]:
    body: dict[str, object] = {
        "entity_id": "model.support",
        "entity_revision": 8,
        "kind": "remediation",
        "title": "Resolve retrieval-source approval",
        "description": "Obtain independent approval or remove the source.",
        "assignee_ref": "principal.reviewer",
        "collaborator_refs": ["principal.privacy", "principal.security"],
        "priority": "critical",
        "idempotency_key": "create-api-task",
    }
    body.update(updates)
    return body


def test_status_is_store_free_and_reports_literal_readiness(environment) -> None:
    client, state = environment
    response = client.get(f"{BASE}/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is True
    assert payload["configured"] is True
    assert payload["ready"] is True
    assert payload["configuration"]["store_opened_for_status"] is False
    assert payload["entity_authority_caller_controlled"] is False
    assert state.factory_calls == []
    assert state.readiness_calls == ["tenant-a"]
    assert response.headers["cache-control"].startswith("no-store")


def test_real_store_round_trip_update_history_and_integrity(environment) -> None:
    client, state = environment
    created_response = client.post(BASE, json=_create_body())
    assert created_response.status_code == 200
    created = created_response.json()
    assert created["task_id"] == "AIT-api-task"
    assert created["status"] == "open"
    assert created["entity_revision"] == 8

    listed = client.get(BASE, params={"entity_id": "model.support"})
    assert listed.status_code == 200
    assert listed.json()["items"] == [created]

    updated_response = client.patch(
        f"{BASE}/{created['task_id']}",
        json={
            "expected_revision": 1,
            "status": "in_progress",
            "priority": "high",
            "collaborator_refs": ["principal.privacy"],
            "idempotency_key": "update-api-task",
        },
    )
    assert updated_response.status_code == 200
    updated = updated_response.json()
    assert updated["revision"] == 2
    assert updated["status"] == "in_progress"
    assert updated["priority"] == "high"

    history = client.get(f"{BASE}/{created['task_id']}/history")
    assert history.status_code == 200
    assert [item["event_type"] for item in history.json()["items"]] == [
        "created",
        "updated",
    ]
    integrity = client.get(f"{BASE}/operations/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["ok"] is True
    assert ("tenant", "operate") in state.permission_calls
    assert ("tenant", "view") in state.permission_calls
    assert ("global", "audit") in state.permission_calls


def test_disabled_or_unready_composition_never_opens_store(environment) -> None:
    client, state = environment
    state.ready = False
    response = client.post(BASE, json=_create_body())
    assert response.status_code == 503
    assert response.json()["detail"] == (
        "AI-entity task operational readiness is not verified"
    )
    assert state.factory_calls == []

    state.ready = True
    state.enabled = False
    response = client.post(BASE, json=_create_body())
    assert response.status_code == 403
    assert response.json()["detail"] == "AI-entity tasks are disabled"
    assert state.factory_calls == []


def test_schema_rejects_caller_authority_and_empty_updates(environment) -> None:
    client, _state = environment
    body = _create_body(tenant_id="attacker", actor_ref="attacker")
    assert client.post(BASE, json=body).status_code == 422

    created = client.post(BASE, json=_create_body()).json()
    response = client.patch(
        f"{BASE}/{created['task_id']}",
        json={"expected_revision": 1, "idempotency_key": "empty-update"},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "AI-entity task update is empty"


def test_due_date_can_be_updated_and_explicitly_cleared(environment) -> None:
    client, _state = environment
    created = client.post(BASE, json=_create_body(due_at=NOW + 1_000)).json()

    cleared = client.patch(
        f"{BASE}/{created['task_id']}",
        json={
            "expected_revision": 1,
            "due_at": None,
            "idempotency_key": "clear-due-date",
        },
    )

    assert cleared.status_code == 200
    assert cleared.json()["due_at"] is None
    assert cleared.json()["revision"] == 2


def test_malformed_readiness_and_store_contract_fail_closed(
    environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, state = environment
    state.ready = 1
    response = client.get(f"{BASE}/status")
    assert response.status_code == 503
    assert response.json()["detail"] == "AI-entity task readiness is unavailable"

    state.ready = True
    monkeypatch.setattr(
        client.app.state,
        "ai_entity_tasks_store_factory",
        lambda **_kwargs: SimpleNamespace(tenant_id="tenant-a"),
        raising=False,
    )
    response = client.post(BASE, json=_create_body())
    assert response.status_code == 503
    assert response.json()["detail"] == "AI-entity task store is unavailable"
