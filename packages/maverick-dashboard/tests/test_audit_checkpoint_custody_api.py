"""Independent checkpoint storage on an installation that has not set it up.

The Activity log reads this panel on every visit. A fresh install has no
Connections, encryption or Amazon storage yet, and the read answered 409, so
every visit logged a console error for a state that is not a fault. The read
now reports what to set up; changes still refuse until it is set up.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

ORIGIN = "http://127.0.0.1:8765"
API = "/api/v1/audit/checkpoint-custody"
PASSPHRASE = "a long local owner fixture phrase"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    import os
    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr("maverick.config.load_global_config", lambda *a, **k: {})
    monkeypatch.setattr("maverick.config.config_source_errors", lambda **k: [])
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "world.db")


@pytest.fixture
def owner():
    from maverick_dashboard.app import app
    with TestClient(app, base_url=ORIGIN, client=("127.0.0.1", 53210),
                    headers={"Origin": ORIGIN}, follow_redirects=False) as client:
        enrolled = client.post("/auth/local-owner", data={
            "email": "owner@example.com", "password": PASSPHRASE, "confirm": "yes"})
        assert enrolled.status_code == 303, enrolled.text
        yield client


def test_a_fresh_install_reads_what_to_set_up_instead_of_an_error(owner):
    response = owner.get(API)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "private, no-store"
    body = response.json()
    assert set(body) == {"setup_required", "context"}
    assert body["setup_required"] == ("Enable Connections and encryption for saved data in Settings "
                                      "before using independent checkpoint storage.")
    assert re.fullmatch(r"[0-9a-f]{64}", body["context"])


def test_missing_amazon_storage_is_also_reported_as_setup(owner, monkeypatch):
    from maverick import connections, crypto_at_rest
    monkeypatch.setattr(connections, "enabled", lambda: True)
    monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", lambda: True)
    response = owner.get(API)
    assert response.status_code == 200, response.text
    assert response.json()["setup_required"].startswith("Choose Amazon S3, a bucket, region and Compliance retention")


def test_setup_state_is_only_shown_to_an_installation_administrator(owner):
    owner.cookies.clear()
    refused = owner.get(API)
    assert refused.status_code == 401
    assert "setup_required" not in refused.text


def test_writes_still_refuse_until_storage_is_set_up(owner):
    context = owner.get(API).json()["context"]
    owner.headers["X-Lightwork-Expected-Tenant"] = "local"
    checked = owner.post(API + "/check", json={"context": context, "account": "a", "account_revision": "1"})
    assert checked.status_code == 409, checked.text
    assert checked.json()["detail"].startswith("Enable Connections and encryption")
