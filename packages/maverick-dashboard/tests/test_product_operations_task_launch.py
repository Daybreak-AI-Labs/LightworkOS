"""Task search and reviewed starts share current native authority and receipts."""
from contextlib import nullcontext

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from maverick.world_model import WorldModel
from maverick_dashboard import api, app, auth, draft_api
from maverick_dashboard import product_operations as ops
from maverick_dashboard import product_operations_task_launch as actions

BASE = "/api/v1/copilot/product-operations"


@pytest.fixture
def task_actions(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    world = WorldModel(tmp_path / "world.db")
    principal = {"value": "user:owner"}
    runs = []
    codec = Fernet(Fernet.generate_key())

    monkeypatch.setattr(auth, "require_permission", lambda *args: None)
    monkeypatch.setattr(auth, "caller_principal", lambda request: principal["value"])
    monkeypatch.setattr(auth, "goal_owner_filter", lambda request: principal["value"])

    def can_access(_request, goal):
        return goal.owner == principal["value"] and goal.domain != "hidden_suite"

    def assert_access(request, goal):
        if not can_access(request, goal):
            raise HTTPException(404, "no such goal")

    monkeypatch.setattr(auth, "can_access_goal", can_access)
    monkeypatch.setattr(auth, "assert_goal_access", assert_access)
    monkeypatch.setattr(draft_api, "context_for", lambda request: "current-workspace")
    monkeypatch.setattr(actions, "context_for", lambda request: "current-workspace")
    monkeypatch.setattr(api, "_world", lambda: world)
    from maverick_dashboard import _shared
    monkeypatch.setattr(_shared, "_world", lambda: world)
    monkeypatch.setattr(app, "_world", lambda: world)
    monkeypatch.setattr(api, "require_permission", lambda *args: None)
    monkeypatch.setattr(api, "require_provider_or_400", lambda: None)
    monkeypatch.setattr(api, "caller_principal", lambda request: principal["value"])
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: principal["value"])
    monkeypatch.setattr(api, "can_access_goal", can_access)
    monkeypatch.setattr(api, "assert_goal_access", assert_access)
    monkeypatch.setattr(api, "caller_suites", lambda request: None)
    monkeypatch.setattr(app, "check_goal_rate_limit", lambda request: None)
    monkeypatch.setattr(ops, "_same_origin", lambda request: None)
    monkeypatch.setattr(ops, "_gate", lambda request: None)
    monkeypatch.setattr(ops, "_context", lambda request: "a" * 64)
    monkeypatch.setattr(ops, "enabled_families", lambda: {"tasks"})
    monkeypatch.setattr(ops, "adapters", lambda: {item.id: item for item in actions.entries()})
    monkeypatch.setattr(ops.crypto_at_rest, "seal_to_str", lambda value: "sealed:" + codec.encrypt(value.encode()).decode())
    monkeypatch.setattr(ops.crypto_at_rest, "is_sealed_str", lambda value: value.startswith("sealed:"))
    monkeypatch.setattr(ops.crypto_at_rest, "unseal_from_str", lambda value: codec.decrypt(value[7:].encode()).decode())
    monkeypatch.setattr("maverick.authority_effects.authority_effect_fence", nullcontext)

    async def run(goal_id, *args, **kwargs):
        runs.append(goal_id)

    monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)
    app_for_test = FastAPI()
    app_for_test.include_router(ops.router)
    with TestClient(app_for_test, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        yield client, world, runs, principal
    world.close()


def _catalog(client, page="/chat"):
    response = client.post(BASE + "/catalog", json={"page": page, "selection": {}})
    assert response.status_code == 200, response.text
    return response.json()


def _prepare(client, catalog, operation, arguments):
    item = next(row for row in catalog["operations"] if row["id"] == operation)
    return client.post(BASE + "/prepare", json={"page": catalog["page"],
        "selection": {}, "operation": operation, "context": catalog["context"],
        "revision": item["revision"], "arguments": arguments})


def test_reviewed_start_accepts_one_task_and_recovers_exact_receipt(task_actions):
    client, world, runs, _principal = task_actions
    catalog = _catalog(client)
    item = next(row for row in catalog["operations"] if row["id"] == "tasks.start")
    assert item["available"] and item["confirmation_required"]
    review = _prepare(client, catalog, "tasks.start", {"title": "  Prepare report  ",
        "description": "Use current figures", "max_dollars": 0.1, "max_wall_seconds": None})
    assert review.status_code == 200, review.text
    assert review.json()["read_only"] is False and review.json()["changes"][0]["after"] == "Prepare report"
    token = review.json()["token"]
    assert client.post(BASE + "/execute", json={"token": token, "confirmed": False}).status_code == 400
    first = client.post(BASE + "/execute", json={"token": token, "confirmed": True})
    assert first.status_code == 200, first.text
    result = first.json()
    assert result["status"] == "queued" and result["operation_id"]
    assert result["details"]["task"]["href"] == f"/chat/goal/{result['details']['goal_id']}"
    repeated = client.post(BASE + "/execute", json={"token": token, "confirmed": True})
    assert repeated.status_code == 200 and repeated.json()["status"] == "replayed"
    assert len(world.list_goals()) == len(runs) == 1
    assert world.get_goal(result["details"]["goal_id"]).title == "Prepare report"


def test_reviewed_start_shows_rest_safety_ceiling_before_confirming(task_actions):
    client, _world, _runs, _principal = task_actions
    catalog = _catalog(client)
    review = _prepare(client, catalog, "tasks.start", {
        "title": "Large request", "max_dollars": 1000,
        "max_wall_seconds": 1000000,
    })

    assert review.status_code == 200, review.text
    changes = {row["label"]: row["after"] for row in review.json()["changes"]}
    assert changes["Maximum dollars"] == 100.0
    assert changes["Maximum seconds"] == 86400.0


def test_find_returns_only_currently_accessible_task_links(task_actions):
    client, world, _runs, principal = task_actions
    own = world.create_goal("Quarterly accessible report", owner=principal["value"])
    world.create_goal("Quarterly foreign report", owner="user:other")
    world.create_goal("Quarterly hidden report", owner=principal["value"], domain="hidden_suite")
    catalog = _catalog(client, "/goals")
    result = _prepare(client, catalog, "tasks.find", {"query": "Quarterly"})
    assert result.status_code == 200, result.text
    assert result.json()["read_only"] and result.json()["details"]["tasks"] == [{
        "task": {"label": "Quarterly accessible report", "href": f"/chat/goal/{own}"},
        "status": world.get_goal(own).status}]
    from starlette.requests import Request

    request = Request({"type": "http", "method": "GET", "path": "/api/v1/goals/search",
                       "headers": [(b"host", b"127.0.0.1")]})
    assert [goal.id for goal in api.search_goals(request, "Quarterly", limit=1)] == [own]
    principal["value"] = "user:other"
    changed = _prepare(client, catalog, "tasks.find", {"query": "Quarterly"})
    assert changed.status_code == 409
