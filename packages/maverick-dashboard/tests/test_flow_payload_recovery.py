"""Checkpoint failures remain actionable only inside the caller's authority."""
from __future__ import annotations

import asyncio
import hashlib
import json

import pytest
from fastapi.testclient import TestClient
from maverick.flow import payloads, store
from starlette.requests import Request


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick.tenant import kms
    from maverick_dashboard.app import app

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_KMS_KEK", "19" * 32)  # pragma: allowlist secret -- synthetic key
    monkeypatch.setattr(kms, "_dek_cache", {})
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def checkpoint():
    run = store.FlowRun(run_id="private-run", flow_id="example", owner="user:alice",
                        status="paused_delay", data={"rows": list(range(600))})
    store.save_run(run)
    saved = json.loads((store._runs_dir() / "private-run.json").read_text("utf-8"))
    path = (store._runs_dir().parent / "run_payloads"
            / hashlib.sha256(run.run_id.encode()).hexdigest()
            / (saved["data_state"]["sha256"] + ".bin"))
    return run, path


def test_owner_receives_safe_recovery_response_for_missing_checkpoint(client, monkeypatch):
    from maverick_dashboard import api

    run, path = checkpoint()
    path.unlink()
    monkeypatch.setattr(api, "goal_owner_filter", lambda _request: run.owner)
    response = client.get(f"/api/v1/flows/runs/{run.run_id}")
    assert response.status_code == 409
    assert response.json()["code"] == "flow_data_unavailable"
    assert "couldn't open this workflow's saved progress" in response.json()["detail"]
    assert response.headers["Cache-Control"] == "no-store"
    assert str(path) not in response.text and "rows" not in response.text
    history = client.get("/api/v1/flows/runs")
    assert history.status_code == 200
    assert history.json()["runs"][0]["execution_data_status"] == "not_loaded"
    assert history.json()["runs"][0]["data"] == {}


def test_foreign_owner_cannot_distinguish_missing_from_damaged_run(client, monkeypatch):
    from maverick_dashboard import api

    run, path = checkpoint()
    path.unlink()
    monkeypatch.setattr(api, "goal_owner_filter", lambda _request: "user:bob")
    response = client.get(f"/api/v1/flows/runs/{run.run_id}")
    missing = client.get("/api/v1/flows/runs/not-a-run")
    assert response.status_code == missing.status_code == 404
    assert response.json() == missing.json()
    listing = client.get("/api/v1/flows/runs")
    assert listing.status_code == 200 and listing.json()["runs"] == []


def test_foreign_owner_cannot_identify_damaged_run_snapshot(client, monkeypatch):
    from maverick_dashboard import api

    run, _ = checkpoint()
    saved_path = store._runs_dir() / f"{run.run_id}.json"
    saved = json.loads(saved_path.read_text("utf-8"))
    saved["release_digest"] = "f" * 64
    saved_path.write_text(json.dumps(saved), encoding="utf-8")
    monkeypatch.setattr(api, "goal_owner_filter", lambda _request: "user:bob")

    damaged = client.get(f"/api/v1/flows/runs/{run.run_id}")
    missing = client.get("/api/v1/flows/runs/not-a-run")
    assert damaged.status_code == missing.status_code == 404
    assert damaged.json() == missing.json()


def test_permission_denial_precedes_payload_access(client, monkeypatch):
    from maverick_dashboard import auth

    run, path = checkpoint()
    path.unlink()
    monkeypatch.setattr(auth, "has_permission", lambda *_args: False)
    monkeypatch.setattr(store, "load_run", lambda *_a, **_kw: pytest.fail("denied read"))
    assert client.get(f"/api/v1/flows/runs/{run.run_id}").status_code == 403


def test_stream_damage_emits_error_and_releases_slot(client, monkeypatch):
    from maverick_dashboard import api

    run, path = checkpoint()
    real_load = store.load_run
    calls = []

    def load_then_damage(*args, **kwargs):
        calls.append(args)
        if len(calls) == 2:
            path.unlink()
        return real_load(*args, **kwargs)

    slot = asyncio.Semaphore(1)
    monkeypatch.setattr(store, "load_run", load_then_damage)
    monkeypatch.setattr(api, "goal_owner_filter", lambda _request: run.owner)
    monkeypatch.setattr("maverick_dashboard._shared._get_sse_semaphore", lambda: slot)
    response = client.get(f"/api/v1/flows/runs/{run.run_id}/events")
    assert response.status_code == 200
    assert "event: error" in response.text and "flow_data_unavailable" in response.text
    assert str(path) not in response.text and "event: terminal" not in response.text
    assert not slot.locked()


def test_html_recovery_page_never_echoes_exception_details(client):
    from maverick_dashboard.app import flow_payload_exception_handler

    request = Request({"type": "http", "method": "GET", "path": "/flow/approve",
                       "headers": [(b"accept", b"text/html")], "query_string": b"",
                       "scheme": "http", "server": ("127.0.0.1", 80)})
    response = asyncio.run(flow_payload_exception_handler(
        request, payloads.FlowPayloadError("private-key-path-and-customer-content")))
    assert response.status_code == 409
    assert b"Workflow data needs recovery" in response.body
    assert b"private-key-path-and-customer-content" not in response.body
    assert response.headers["Cache-Control"] == "no-store"
