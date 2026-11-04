"""Removing a saved fact from the Facts page."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from maverick import world_model
    from maverick_dashboard.app import app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _remove(client, key):
    current = client.get("/api/v1/facts/record", params={"key": key}).json()
    from urllib.parse import quote
    return client.delete("/api/v1/facts/" + quote(key, safe=""), params={
        "expected_revision": current["item"]["revision"], "context": current["context"],
    })


def test_a_saved_fact_can_be_removed(client) -> None:
    assert client.post("/api/v1/facts", json={"key": "business_hours", "value": "9 to 5"}).status_code == 204
    assert client.post("/api/v1/facts", json={"key": "Office/branch", "value": "Leeds"}).status_code == 204
    assert _remove(client, "business_hours").status_code == 204
    facts = client.get("/api/v1/facts").json()
    assert "business_hours" not in facts and facts["Office/branch"] == "Leeds"
    # Names with a slash still address exactly one fact.
    assert _remove(client, "Office/branch").status_code == 204
    assert client.get("/api/v1/facts").json() == {}
    assert client.delete("/api/v1/facts/business_hours").status_code == 422


def test_removing_a_fact_needs_the_same_permission_as_saving_one(client, monkeypatch) -> None:
    from fastapi import HTTPException
    from maverick_dashboard import facts_api

    seen = []

    def deny(_request, permission):
        seen.append(permission)
        raise HTTPException(status_code=403, detail="forbidden")

    client.post("/api/v1/facts", json={"key": "kept", "value": "yes"})
    current = client.get("/api/v1/facts/record", params={"key": "kept"}).json()
    monkeypatch.setattr(facts_api, "require_permission", deny)
    assert client.delete("/api/v1/facts/kept", params={"expected_revision": current["item"]["revision"], "context": current["context"]}).status_code == 403
    assert seen == ["operate"]
    assert client.get("/api/v1/facts").json() == {"kept": "yes"}


def test_removal_only_touches_the_active_workspace(client, tmp_path, monkeypatch) -> None:
    from maverick import world_model

    client.post("/api/v1/facts", json={"key": "shared_name", "value": "workspace A"})
    other = world_model.WorldModel(tmp_path / "other.db")
    other.upsert_fact("shared_name", "workspace B")
    assert _remove(client, "shared_name").status_code == 204
    assert other.get_fact("shared_name") == "workspace B"


def test_facts_page_offers_remove_and_reads_plainly(client) -> None:
    from test_support.plain_language import developer_terms

    client.post("/api/v1/facts", json={"key": "company_name", "value": "Acme"})
    page = client.get("/facts").text
    assert "data-remove-fact" in page and ">Remove fact</button>" in page
    assert 'data-key="company_name"' in page and ">Company name<" in page
    assert developer_terms(page) == []


def test_two_editors_compare_revisions_and_stale_delete_preserves_new_value(client):
    client.post("/api/v1/facts", json={"key": "hours", "value": "nine"})
    original = client.get("/api/v1/facts/record", params={"key": "hours"}).json()
    payload = {"key": "hours", "value": "ten", "context": original["context"],
               "expected_revision": original["item"]["revision"]}
    assert client.post("/api/v1/facts", json=payload).status_code == 204
    assert client.post("/api/v1/facts", json=payload | {"value": "stale draft"}).status_code == 409
    assert client.delete("/api/v1/facts/hours", params={
        "context": original["context"], "expected_revision": original["item"]["revision"],
    }).status_code == 409
    assert client.get("/api/v1/facts").json()["hours"] == "ten"
    assert client.post("/api/v1/facts", json={"key": "hours", "value": "blind overwrite"}).status_code == 409


def test_browsing_and_mutation_never_expose_personal_or_task_namespaces(client):
    from maverick_dashboard.api import _world

    world = _world()
    world.upsert_fact("goal:72:private", "PRIVATE TASK TEXT")
    world.upsert_fact("user:alice:note", "PRIVATE PERSONAL TEXT")
    world.upsert_fact("company_name", "Shared")
    assert client.get("/api/v1/facts").json() == {"company_name": "Shared"}
    page = client.get("/api/v1/facts/records").json()
    assert [row["key"] for row in page["items"]] == ["company_name"]
    assert page["has_more"] is False
    assert "PRIVATE" not in client.get("/facts").text
    for key in ("goal:72:private", "user:alice:note"):
        assert client.get("/api/v1/facts/record", params={"key": key}).status_code == 404
        assert client.post("/api/v1/facts", json={"key": key, "value": "overwrite"}).status_code == 400


def test_fact_save_rejects_stale_workspace_context(client):
    assert client.post("/api/v1/facts", json={
        "key": "company_name", "value": "wrong workspace", "context": "0" * 64,
    }).status_code == 409
    assert client.get("/api/v1/facts").json() == {}


def test_tags_and_page_snapshot_recheck_current_state(client, monkeypatch):
    from maverick_dashboard import facts_api
    monkeypatch.setattr(facts_api, "tags_enabled", lambda: True)
    client.post("/api/v1/facts", json={"key": "company", "value": "Acme"})
    first = client.get("/api/v1/facts/records").json()
    item = first["items"][0]
    payload = {"key": "company", "tags": ["Renewal"], "expected_revision": item["revision"], "context": first["context"]}
    assert client.patch("/api/v1/facts/tags", json=payload).status_code == 200
    assert client.patch("/api/v1/facts/tags", json=payload).status_code == 409
    assert client.get("/api/v1/facts/records", params={"snapshot": first["snapshot"]}).status_code == 409
    page = client.get("/api/v1/facts/records", params={"tag": "renewal"}).json()
    assert page["items"][0]["tags"] == ["renewal"]
    assert client.get("/api/v1/facts/records", params={"offset": 50}).status_code == 409
    monkeypatch.setattr(facts_api, "tags_enabled", lambda: False)
    assert client.patch("/api/v1/facts/tags", json=payload).status_code == 409
