"""One local collection -> exact-package statement -> replay -> close journey."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import dsar_export_handoff_api as api

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    app = FastAPI()
    app.include_router(api.router)
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def test_collected_package_statement_is_exact_durable_and_not_delivery_proof(client, monkeypatch):
    from maverick import audit, privacy_ops
    from maverick_dashboard import dsar_export_handoff_api as api

    request = privacy_ops.open_dsar("person@example.test", "access", channel="email")
    collected = privacy_ops.fulfill_dsar(request["id"])
    assert privacy_ops.dsar_answer(collected) is None
    clock = privacy_ops.dsar_clock(collected, now=collected["due_at"] + 86400)
    assert clock["response_pending"] is True and clock["overdue"] is True
    assert privacy_ops.program_report(assessment_types={"none"})["dsar"]["open"] == 1
    original = Path(collected["fulfillment"]["export_path"])
    before = original.read_bytes()
    url = f"/api/v1/privacy/dsar/{request['id']}/package-handoff"
    state = client.get(url)
    assert state.status_code == 200 and state.json()["package_available"] is True
    from maverick import dsar_export_handoff
    from maverick.paths import tenant_scope
    with tenant_scope(tenant="other-workspace"), pytest.raises(KeyError):
        dsar_export_handoff.state(request["id"], authorize=lambda: None)
    payload = {"binding": state.json()["binding"], "channel": "secure_portal",
               "handed_at": datetime.now(timezone.utc).isoformat(), "reference": "ticket 4521",
               "reviewed": True, "identity_checked": True, "sent": True}
    events = []
    monkeypatch.setattr(audit, "record", lambda kind, **fields: events.append(fields) or True)
    saved = client.post(url, json=payload)
    assert saved.status_code == 200, saved.text
    receipt = saved.json()["receipt"]
    assert receipt["artifact_sha256"] == collected["fulfillment"]["artifact_sha256"]
    assert receipt["requester_receipt_verified"] is False and receipt["operator_recorded"] is True
    assert original.read_bytes() == before
    replay = client.post(url, json=payload)
    assert replay.status_code == 200 and replay.json()["replayed"] is True
    assert len(privacy_ops.get_dsar(request["id"])["package_handoffs"]) == 1
    assert all("person@example.test" not in str(event) and "ticket 4521" not in str(event) for event in events)
    assert privacy_ops.get_dsar(request["id"])["status"] == "fulfilled"
    assert privacy_ops.dsar_answer(privacy_ops.get_dsar(request["id"])) is None
    assert privacy_ops.program_report(assessment_types={"none"})["dsar"]["handled"] == 0
    assert client.post(url, json={**payload, "reviewed": 1}).status_code == 422

    # Missing officer authority and a replaced package cannot attest a handoff.
    with monkeypatch.context() as denied:
        def deny_officer(_request, permission):
            if permission == "audit":
                raise api.HTTPException(403, "not an officer")
        denied.setattr(api.auth, "require_permission", deny_officer)
        assert client.get(url).status_code == 403
    tampered = json.loads(before)
    tampered["counts"]["goals"] = 99
    original.write_text(json.dumps(tampered), encoding="utf-8")
    assert client.get(url).status_code == 503
    assert client.post(url, json=payload).status_code == 503
    original.write_bytes(before)
    privacy_ops.close_dsar(request["id"])
    closed = client.get(url)
    assert closed.status_code == 200 and closed.json()["package_available"] is False
    assert len(closed.json()["receipts"]) == 1
    assert client.post(url, json=payload).status_code == 409


def test_interrupted_audit_replays_the_original_statement_without_a_new_handoff(client, monkeypatch):
    from maverick import audit, privacy_ops

    request = privacy_ops.open_dsar("person@example.test", "portability", channel="email")
    privacy_ops.fulfill_dsar(request["id"])
    url = f"/api/v1/privacy/dsar/{request['id']}/package-handoff"
    payload = {"binding": client.get(url).json()["binding"], "channel": "encrypted_email",
               "handed_at": datetime.now(timezone.utc).isoformat(), "reference": "secure mail 4321",
               "reviewed": True, "identity_checked": True, "sent": True}
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    uncertain = client.post(url, json=payload)
    assert uncertain.status_code == 503
    assert client.get(url).json()["audit_pending"] is True
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    recovered = client.post(url, json=payload)
    assert recovered.status_code == 200 and recovered.json()["replayed"] is True
    assert client.get(url).json()["audit_pending"] is False
    assert len(privacy_ops.get_dsar(request["id"])["package_handoffs"]) == 1
    # A refreshed browser can finish the existing statement without re-attesting.
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    payload = {**payload, "binding": client.get(url).json()["binding"], "reference": "second saved activity"}
    assert client.post(url, json=payload).status_code == 503
    statement = client.get(url).json()["receipts"][-1]
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    assert client.post(url + "/confirm-saved", json={"receipt_id": statement["id"]}).status_code == 200
    assert len(privacy_ops.get_dsar(request["id"])["package_handoffs"]) == 2
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    privacy_ops.close_dsar(request["id"])
    assert client.post(url + "/confirm-saved", json={"receipt_id": statement["id"]}).status_code == 503
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    assert client.post(url + "/confirm-saved", json={"receipt_id": statement["id"]}).status_code == 200
    historical = client.get(url).json()
    assert historical["package_available"] is False and historical["audit_pending"] is False
