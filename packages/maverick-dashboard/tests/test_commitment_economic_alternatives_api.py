"""Financial comparison history reads on single-computer and shared deployments."""
from __future__ import annotations

import logging

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import config, governed_records, world_model
from maverick.governed_records import GovernedRecordLocalOnly
from maverick_dashboard import commitment_economic_alternatives_api as api
from maverick_dashboard import commitment_economic_alternatives_store as store
from maverick_dashboard.app import app

HISTORY = "/api/v1/commitment-economic-alternatives/history"


@pytest.fixture
def client(tmp_path, monkeypatch):
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for name in ("MAVERICK_TENANT", "MAVERICK_REPLICA_COUNT", "MAVERICK_GOVERNED_RECORDS_BACKEND",
                 "MAVERICK_PG_DSN", "MAVERICK_WORLD_BACKEND", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def test_an_empty_history_is_an_empty_list(client):
    response = client.get(HISTORY)
    assert response.status_code == 200, response.text
    assert response.json()["choices"] == []
    assert "available" not in response.json()


def test_a_shared_deployment_says_plainly_that_history_is_not_kept_here(client, monkeypatch):
    # The deployment selector alone; no database is opened.
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", "postgresql://example.invalid/never")
    governed_records._reset_process_authority_pin_for_testing()
    for path in (HISTORY, "/api/v1/commitment-economic-alternatives/choices"):
        response = client.get(path)
        assert response.status_code == 200, response.text
        value = response.json()
        assert value["choices"] == [] and value["available"] is False
        assert "single-computer installation" in value["message"]


def test_other_operations_on_a_shared_deployment_refuse_plainly_not_as_an_outage():
    def local_only():
        raise GovernedRecordLocalOnly("record collection is local only")

    with pytest.raises(HTTPException) as refused:
        api.call(local_only)
    assert refused.value.status_code == 409
    assert "single-computer installation" in refused.value.detail
    assert "Nothing was saved or changed" in refused.value.detail


def test_a_real_store_failure_stays_closed_and_is_logged(client, monkeypatch, caplog):
    def broken(**_kwargs):
        raise governed_records.GovernedRecordBackendError("shared governed-record schema is incompatible")

    monkeypatch.setattr(store.STORE, "list", broken)
    with caplog.at_level(logging.WARNING, logger=api.__name__):
        response = client.get(HISTORY)
    assert response.status_code == 503
    assert "server log" in response.json()["detail"]
    logged = [row for row in caplog.records if row.name == api.__name__]
    assert logged and logged[0].exc_info is not None
    assert "history" in logged[0].getMessage()
