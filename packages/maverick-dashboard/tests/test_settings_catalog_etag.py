"""``/api/v1/settings/catalog`` revalidates with an ETag instead of shipping
its ~1.5 MB on every load."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_all_page as sap


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dashboard_app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    return TestClient(dashboard_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_catalog_json_carries_an_etag_and_answers_304_when_unchanged(client):
    first = client.get(sap.API_PATH + "?group=safety")
    assert first.status_code == 200
    etag = first.headers["etag"]
    assert etag.startswith('"') and etag.endswith('"')
    assert first.headers["cache-control"] == "private, no-cache"
    assert first.json()["groups"][0]["slug"] == "safety"

    again = client.get(sap.API_PATH + "?group=safety", headers={"If-None-Match": etag})
    assert again.status_code == 304
    assert again.content == b""
    assert again.headers["etag"] == etag

    weak = client.get(sap.API_PATH + "?group=safety", headers={"If-None-Match": "W/" + etag})
    assert weak.status_code == 304
    other = client.get(sap.API_PATH + "?group=safety", headers={"If-None-Match": '"stale"'})
    assert other.status_code == 200


def test_different_filters_have_different_etags(client):
    safety = client.get(sap.API_PATH + "?group=safety").headers["etag"]
    security = client.get(sap.API_PATH + "?group=security").headers["etag"]
    assert safety != security
    assert client.get(sap.API_PATH + "?group=security", headers={"If-None-Match": safety}).status_code == 200


def test_etag_matcher_handles_lists_and_star():
    assert sap._etag_matches('"a", "b"', '"b"')
    assert sap._etag_matches("*", '"b"')
    assert not sap._etag_matches('"a"', '"b"')
    assert not sap._etag_matches("", '"b"')
