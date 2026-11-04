from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick_dashboard import knowledge_library_api as api


class _KB:
    def __init__(self, state):
        self.state = state
        self.store = SimpleNamespace(count=lambda name: state["chunks"].get(name, 0))

    def collections(self):
        return sorted(self.state["chunks"])

    def reindex(self, collection):
        self.state["reindexed"].append(collection)
        return self.state["chunks"][collection]

    def erase_source(self, source, collections):
        return None

    def ingest(self, *args, **kwargs):
        self.state["ingested"] += 1
        return 1

    def close(self):
        self.state["closed"] += 1


@pytest.fixture()
def client(monkeypatch):
    state = {"chunks": {"gdpr": 12}, "reindexed": [], "ingested": 0, "closed": 0, "permissions": [], "enabled": True}
    monkeypatch.setattr(api, "require_permission", lambda _r, p: state["permissions"].append(p))
    monkeypatch.setattr(api, "_open", lambda: _KB(state) if state["enabled"] else None)
    import maverick.knowledge_admin as admin

    monkeypatch.setattr(admin, "open_knowledge_base", lambda **_kw: _KB(state) if state["enabled"] else None)
    app = FastAPI()
    app.include_router(api.router, prefix="/api/v1")
    return TestClient(app, base_url="http://127.0.0.1"), state


def test_overview_lists_collections_and_starter_content_for_viewers(client) -> None:
    test_client, state = client
    body = test_client.get("/api/v1/knowledge/library").json()
    assert body["enabled"] is True
    assert body["collections"] == [{"name": "gdpr", "chunks": 12}]
    assert body["starter_content"] and all("loaded" in item for item in body["starter_content"])
    assert state["permissions"] == ["view"] and state["closed"] == 1


def test_reindex_requires_a_current_review_and_explicit_confirmation(client, monkeypatch) -> None:
    test_client, state = client
    assert test_client.post("/api/v1/knowledge/library/collections/gdpr/reindex").status_code == 422
    from maverick_dashboard import draft_api
    monkeypatch.setattr(draft_api, "context_for", lambda request: "a" * 64)
    result = test_client.post("/api/v1/knowledge/library/collections/gdpr/reindex", json={
        "context": "a" * 64, "job_id": "b" * 32, "review": "c" * 64, "confirmed": False,
    })
    assert result.status_code == 400
    assert state["permissions"] == ["admin"] and state["reindexed"] == []


def test_seed_refuses_unknown_starter_content_and_reports_when_off(client) -> None:
    test_client, state = client
    assert test_client.post("/api/v1/knowledge/library/seed", json={"collection": "nope"}).status_code == 404
    state["enabled"] = False
    assert test_client.post("/api/v1/knowledge/library/seed", json={}).status_code == 503
    assert test_client.get("/api/v1/knowledge/library").json()["enabled"] is False
    assert "admin" in state["permissions"]
