"""One-tap feedback on a flow run's result.

The run's owner rates a finished run up or down. The store keeps one rating
per run in the active workspace's own data folder, holds no written text and
forgets old ratings, and the Learning page counts them per flow.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def runs(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "absent.toml"))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import config, world_model
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    flow = store.save_flow(Flow(id="invoice-flow", name="Invoice follow-up", start="a", owner="user:alice", nodes={
        "a": FlowNode(id="a", kind="agent", brief="Chase the invoice")}))
    release = store.publish_flow(flow.id, expected_version=flow.version, expected_revision=flow.revision)

    def make(run_id, status="completed", owner="user:alice"):
        store.save_run(store.FlowRun(run_id=run_id, flow_id=flow.id, status=status, owner=owner,
                                     data={"answer": "sent"}, definition_digest=release["definition_digest"],
                                     release_digest=release["release_digest"], release_id=release["release_id"],
                                     definition_version=release["definition_version"],
                                     definition_revision=release["definition_revision"],
                                     subflow_digests=release["subflow_digests"]))
        return run_id
    yield make
    config.reset_config_cache()


def _client(monkeypatch, principal="user:alice", role="operator"):
    import importlib

    from maverick_dashboard import rbac

    for name in ("maverick_dashboard.app", "maverick_dashboard.auth"):
        monkeypatch.setattr(importlib.import_module(name), "caller_principal", lambda _request: principal)
    rbac.set_role(principal, role)
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _url(run_id):
    return f"/api/v1/flows/runs/{run_id}/feedback"


def test_the_owner_rates_a_finished_run_and_a_new_tap_replaces_it(runs, monkeypatch):
    run_id = runs("r-done")
    client = _client(monkeypatch)
    assert client.get(_url(run_id)).json() == {"eligible": True, "rating": None}
    saved = client.put(_url(run_id), json={"rating": "up"})
    assert saved.status_code == 200, saved.text
    assert saved.json()["rating"] == "up"
    client.put(_url(run_id), json={"rating": "down"})
    assert client.get(_url(run_id)).json()["rating"] == "down"
    from maverick_dashboard import flow_run_feedback

    assert len(flow_run_feedback.rows()) == 1


def test_a_run_still_working_cannot_be_rated(runs, monkeypatch):
    run_id = runs("r-busy", status="running")
    client = _client(monkeypatch)
    assert client.get(_url(run_id)).json()["eligible"] is False
    assert client.put(_url(run_id), json={"rating": "up"}).status_code == 409


@pytest.mark.parametrize("body", [{"rating": "up", "note": "the vendor was wrong"}, {"rating": "meh"}, {}])
def test_only_a_thumbs_up_or_down_is_accepted_and_no_written_text(runs, monkeypatch, body):
    run_id = runs("r-text")
    assert _client(monkeypatch).put(_url(run_id), json=body).status_code == 422


def test_someone_elses_run_is_not_found(runs, monkeypatch):
    run_id = runs("r-alice")
    client = _client(monkeypatch, principal="user:bob", role="admin")
    assert client.get(_url(run_id)).status_code == 404
    assert client.put(_url(run_id), json={"rating": "up"}).status_code == 404


def test_viewers_cannot_rate(runs, monkeypatch):
    run_id = runs("r-view")
    assert _client(monkeypatch, role="viewer").put(_url(run_id), json={"rating": "up"}).status_code == 403


def test_ratings_stay_in_their_workspace(runs, monkeypatch):
    from maverick import paths
    from maverick_dashboard import flow_run_feedback

    with paths.tenant_scope(tenant="acme"):
        flow_run_feedback.record("r1", flow_id="f", owner="user:alice", rating="up")
        assert flow_run_feedback.latest("r1", owner="user:alice") == "up"
    with paths.tenant_scope(tenant="globex"):
        assert flow_run_feedback.latest("r1", owner="user:alice") is None
    assert flow_run_feedback.latest("r1", owner="user:alice") is None


def test_old_and_surplus_ratings_are_forgotten(runs, monkeypatch):
    from maverick_dashboard import flow_run_feedback

    monkeypatch.setattr(flow_run_feedback, "MAX_RATINGS", 3)
    real_time = time.time
    monkeypatch.setattr(flow_run_feedback.time, "time", lambda: real_time() - flow_run_feedback.KEEP_SECONDS - 60)
    flow_run_feedback.record("old", flow_id="f", owner="o", rating="up")
    monkeypatch.setattr(flow_run_feedback.time, "time", real_time)
    assert flow_run_feedback.latest("old", owner="o") is None, "a rating past the keeping period is not read"
    for index in range(5):
        flow_run_feedback.record(f"r{index}", flow_id="f", owner="o", rating="up")
    kept = flow_run_feedback.rows()
    assert sorted(row["run_id"] for row in kept) == ["r2", "r3", "r4"]


def test_the_run_page_offers_the_rating_and_the_learning_page_counts_it(runs, monkeypatch):
    run_id = runs("r-page")
    client = _client(monkeypatch, role="admin")
    page = client.get(f"/flows/invoice-flow/runs/{run_id}").text
    assert "data-flow-run-feedback" in page and "/static/lightwork-result-feedback.js" in page
    assert client.get("/static/lightwork-result-feedback.js").status_code == 200
    client.put(_url(run_id), json={"rating": "down"})
    learning = client.get("/learning").text
    assert "What people said about each flow" in learning
    assert "Invoice follow-up" in learning
