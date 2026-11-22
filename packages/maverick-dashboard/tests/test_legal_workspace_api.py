"""Native legal controls and Copilot keep current identity and reviewed revisions."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick import audit, config, governed_records, world_model
from maverick.paths import tenant_scope
from maverick_dashboard import legal_workspace_api as native
from maverick_dashboard import product_operations_legal as copilot
from maverick_dashboard.app import app

BASE = "/api/v1/legal"
ARGS = {"title": "Acme procurement", "area": "commercial", "objective": "Review supplier terms",
        "department": "Procurement", "business_owner": "Taylor", "jurisdiction": "Tennessee"}


@pytest.fixture
def web(tmp_path, monkeypatch):
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    settings = tmp_path / "config.toml"
    settings.write_text('[legal_workspace]\nenable = true\n[enterprise]\nenable = false\n')
    monkeypatch.setenv("MAVERICK_CONFIG", str(settings))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_TENANT", "legal-api-a")
    for name in ("MAVERICK_REPLICA_COUNT", "MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_WORLD_BACKEND", "MAVERICK_PG_DSN", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    config.reset_config_cache()
    bound = {"actor": "user:counsel", "tenant": "legal-api-a", "human": True, "policy": "current"}
    monkeypatch.setattr(native, "context", lambda _request: dict(bound))
    monkeypatch.setattr(native, "member_choices", lambda _request: [{"value": "user:colleague", "label": "Colleague"}])
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    with tenant_scope(tenant="legal-api-a"):
        yield client, bound
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def review(client, action="create_matter", arguments=None, matter=None):
    current = client.get(BASE)
    assert current.status_code == 200, current.text
    return client.post(BASE + "/review", json={"action": action, "arguments": ARGS if arguments is None else arguments,
        "matter_id": matter["id"] if matter else "", "expected_revision": matter["revision"] if matter else 0,
        "context": current.json()["context"]})


def create(client):
    prepared = review(client)
    assert prepared.status_code == 200, prepared.text
    result = client.post(BASE + "/confirm", json={"token": prepared.json()["token"], "confirmed": True})
    assert result.status_code == 200, result.text
    return result.json()["matter"]


def test_all_roles_and_operations_are_exposed_without_provider_claims(web):
    client, _ = web
    response = client.get(BASE)
    assert response.status_code == 200, response.text
    value = response.json()
    assert len(value["workers"]) == 9
    assert {"contract", "engagement", "assignment", "run", "decision", "packet"} <= set(value["operations"])
    assert "no-store" in response.headers["cache-control"]


def test_exact_review_requires_confirmation_and_recovers_original(web):
    client, _ = web
    prepared = review(client)
    assert prepared.status_code == 200, prepared.text
    token = prepared.json()["token"]
    assert client.post(BASE + "/confirm", json={"token": token}).status_code == 403
    first = client.post(BASE + "/confirm", json={"token": token, "confirmed": True})
    assert first.status_code == 200, first.text
    recovered = client.post(BASE + "/original", json={"token": token})
    assert recovered.json()["matter"]["id"] == first.json()["matter"]["id"]
    repeated = client.post(BASE + "/confirm", json={"token": token, "confirmed": True})
    assert repeated.json()["matter"]["id"] == first.json()["matter"]["id"]
    assert len(client.get(BASE).json()["matters"]) == 1


def test_changed_authority_or_machine_cannot_confirm(web):
    client, bound = web
    token = review(client).json()["token"]
    bound["policy"] = "changed"
    assert client.post(BASE + "/confirm", json={"token": token, "confirmed": True}).status_code == 409
    bound["policy"] = "current"
    bound["human"] = False
    assert client.post(BASE + "/confirm", json={"token": token, "confirmed": True}).status_code == 403


def test_cross_origin_and_tampered_token_refused(web):
    client, _ = web
    token = review(client).json()["token"]
    assert client.post(BASE + "/confirm", headers={"Origin": "https://evil.example"}, json={"token": token, "confirmed": True}).status_code == 403
    assert client.post(BASE + "/confirm", json={"token": token[:-10] + "tampered", "confirmed": True}).status_code == 409


def test_scope_filter_applies_to_read_export_and_oversight(web):
    client, bound = web
    row = create(client)
    assert client.get(BASE + "/matters/" + row["id"] + "/export").status_code == 200
    bound["actor"] = "user:other"
    assert client.get(BASE).json()["matters"] == []
    assert client.get(BASE + "/matters/" + row["id"]).status_code == 403
    assert client.get(BASE + "/matters/" + row["id"] + "/export").status_code == 403


def test_copilot_uses_same_service_and_revision_boundary(web):
    client, _ = web
    row = create(client)
    selection = {"kind": "legal_matter", "id": row["id"]}
    source = {"title": "Agreement", "kind": "agreement", "reference": "Section 4", "text": "The notice date is January 1."}
    adapter = next(entry for entry in copilot.entries() if entry.id == "legal.source")
    snapshot = adapter.snapshot(None, selection)
    assert snapshot.revision and any(field["name"] == "text" for field in snapshot.fields)
    preview = adapter.prepare(None, selection, source)
    outcome = adapter.execute(None, selection, source, preview.native, "copilot-source")
    assert outcome.status == "confirmed"
    assert len(client.get(BASE + "/matters/" + row["id"]).json()["matter"]["sources"]) == 1
    assert adapter.recover(None, selection, source, preview.native, "copilot-source").status == "replayed"


def test_every_native_operation_has_copilot_adapter(web):
    client, _ = web
    native_names = set(client.get(BASE).json()["operations"])
    assert {"legal." + name for name in native_names} < {adapter.id for adapter in copilot.entries()}


def test_stale_browser_form_and_invalid_fields_are_refused(web):
    client, _ = web
    row = create(client)
    source = {"title": "Agreement", "kind": "agreement", "reference": "Section 4", "text": "Evidence"}
    token = review(client, "source", source, row).json()["token"]
    assert client.post(BASE + "/confirm", json={"token": token, "confirmed": True}).status_code == 200
    assert review(client, "source", source, row).status_code == 409
    assert review(client, arguments={**ARGS, "admin": True}).status_code == 422


def test_access_grant_rechecks_workspace_membership(web, monkeypatch):
    client, _ = web
    row = create(client)
    result = review(client, "access", {"principal": "user:colleague", "grant": True}, row)
    assert result.status_code == 200, result.text
    monkeypatch.setattr(native, "member_choices", lambda _request: [])
    assert client.post(BASE + "/confirm", json={"token": result.json()["token"], "confirmed": True}).status_code == 409
