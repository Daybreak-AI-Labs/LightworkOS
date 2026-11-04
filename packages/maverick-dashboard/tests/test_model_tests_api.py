"""Native/Copilot contract tests with mocked model generation only."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from maverick import model_tests
from maverick_dashboard import model_tests_api as native
from maverick_dashboard import product_operations_models as copilot

CONTEXT = "a" * 64


@pytest.fixture
def ui(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(model_tests, "data_dir", lambda: tmp_path / "data")
    monkeypatch.setattr(model_tests, "policy", lambda: None)
    monkeypatch.setattr(model_tests, "limits", lambda: dict(model_tests.CAPS))
    monkeypatch.setattr(model_tests, "route", lambda model: {"model": model, "provider": "openai", "fingerprint": "same", "tenant": "test"})
    state = {"admin": True, "context": CONTEXT}
    def require(request, permission):
        if not state["admin"]:
            raise HTTPException(403, "Administrator required")
    monkeypatch.setattr(native.auth, "require_global_permission", require)
    monkeypatch.setattr(native.auth, "_authorization_principal", lambda request: "user:alice")
    monkeypatch.setattr(native, "context_for", lambda request: state["context"])
    monkeypatch.setattr(copilot, "context_for", lambda request: state["context"])
    monkeypatch.setattr(native, "_same_origin", lambda request: None)
    calls = []
    async def fake_run(context, identity, actor, tenant, guard):
        guard()
        calls.append(identity)
        model_tests._edit(context, lambda rows: rows[identity].update(state="unknown", message="Original request remains unconfirmed."))
    monkeypatch.setattr(model_tests, "run", fake_run)
    app = FastAPI()
    app.include_router(native.router)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        yield SimpleNamespace(client=client, state=state, calls=calls)


def review(ui):
    response = ui.client.post("/api/v1/models/tests/review", json={"context": CONTEXT, "model": "openai:synthetic", "kind": "generation"})
    assert response.status_code == 200
    return response.json()["check"]


def test_native_requires_review_confirmation_and_durable_receipt_prevents_second_call(ui):
    row = review(ui)
    url = "/api/v1/models/tests/" + row["id"] + "/execute"
    assert ui.calls == []
    assert ui.client.post(url, json={"context": CONTEXT, "confirmed": False}).status_code == 400
    assert ui.client.post(url, json={"context": CONTEXT, "confirmed": True}).status_code == 200
    again = ui.client.post(url, json={"context": CONTEXT, "confirmed": True})
    assert again.json()["recovered"] is True
    assert again.json()["check"]["state"] == "unknown"
    assert ui.calls == [row["id"]]
    status = ui.client.get("/api/v1/models/tests")
    assert status.headers["cache-control"] == "private, no-store"
    assert "fingerprint" not in json.dumps(status.json())


def test_current_admin_and_context_are_rechecked_and_other_context_cannot_read_receipt(ui):
    row = review(ui)
    ui.state["admin"] = False
    assert ui.client.get("/api/v1/models/tests").status_code == 403
    assert ui.client.post("/api/v1/models/tests/" + row["id"] + "/execute", json={"context": CONTEXT, "confirmed": True}).status_code == 403
    ui.state.update(admin=True, context="b" * 64)
    assert ui.client.get("/api/v1/models/tests").json()["checks"] == []
    assert ui.client.post("/api/v1/models/tests/" + row["id"] + "/execute", json={"context": CONTEXT, "confirmed": True}).status_code == 409
    assert not ui.calls


def test_copilot_recovers_exact_native_unknown_receipt_without_regeneration(ui):
    row = review(ui)
    ui.client.post("/api/v1/models/tests/" + row["id"] + "/execute", json={"context": CONTEXT, "confirmed": True})
    result = copilot.recover_test(object(), {}, {}, {"check_id": row["id"]}, "b" * 32)
    # An unknown original outcome is read back as unconfirmed, never re-sent.
    assert result.status == "unconfirmed" and result.details["check"]["state"] == "unknown"
    assert ui.calls == [row["id"]]
    ui.state["admin"] = False
    with pytest.raises(HTTPException):
        copilot.recover_test(object(), {}, {}, {"check_id": row["id"]}, "b" * 32)


def test_native_cancel_is_available_without_ai_and_blocks_queued_dispatch(ui):
    row = review(ui)
    response = ui.client.post("/api/v1/models/tests/" + row["id"] + "/cancel", json={"context": CONTEXT})
    assert response.json()["check"]["state"] == "cancelled"
    ui.client.post("/api/v1/models/tests/" + row["id"] + "/execute", json={"context": CONTEXT, "confirmed": True})
    assert not ui.calls


def test_disabled_policy_keeps_receipts_readable_but_refuses_new_work(ui, monkeypatch):
    review(ui)
    def denied():
        raise PermissionError("Enable bounded model tests")
    monkeypatch.setattr(model_tests, "policy", denied)
    snapshot = ui.client.get("/api/v1/models/tests").json()
    assert snapshot["enabled"] is False and len(snapshot["checks"]) == 1
    assert ui.client.post("/api/v1/models/tests/review", json={"context": CONTEXT, "model": "openai:synthetic", "kind": "generation"}).status_code == 403
    assert not ui.calls


def test_copilot_provider_status_uses_settings_truth_without_exposing_credentials(ui, monkeypatch):
    monkeypatch.setattr(copilot.provider_readiness, "workspace_readiness", lambda: {
        "verdict_label": "Key saved, not tested yet",
        "reason": "Test the connection.",
        "summary": "One AI service needs a test",
        "providers": [{"name": "openai", "label": "OpenAI", "status_label": "Key saved, not tested yet",
                       "routed": True, "configured": True, "reason": "Test the connection.",
                       "api_key": "must-never-leak"}],  # pragma: allowlist secret
    })
    adapter = next(item for item in copilot.entries() if item.id == "models.provider_status")
    assert "/providers" in adapter.pages
    status = copilot.providers_snapshot(object(), None)
    assert status.details["services"][0]["status"] == "Key saved, not tested yet"
    assert "must-never-leak" not in json.dumps(status.details)
    ui.state["admin"] = False
    with pytest.raises(HTTPException) as denied:
        copilot.providers_snapshot(object(), None)
    assert denied.value.status_code == 403
