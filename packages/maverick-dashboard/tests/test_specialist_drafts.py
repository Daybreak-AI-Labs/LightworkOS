"""A refused draft decision keeps its real error; only work that may have begun stays unconfirmed."""
from __future__ import annotations

import time

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

TESTS = "/api/v1/workforce-ops/test-suite"
DRAFTS = "/api/v1/specialist-drafts"
PACK = "proc_po_chaser"
NEW = "You chase overdue purchase orders and always name the supplier to chase."


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import learning_jobs

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr("maverick.config.dashboard_overrides_path", lambda: tmp_path / "dashboard.toml")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    (tmp_path / "config.toml").write_text("[models]\ncapability_tests = true\n", encoding="utf-8")
    config.reset_config_cache()
    dash_app._world_cache.clear()
    learning_jobs.clear_for_tests()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    learning_jobs.clear_for_tests()
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: rows.append(payload) or True)
    return rows


def _answers(monkeypatch):
    from maverick import llm

    def answer(self, system, messages, **kwargs):
        kwargs["dispatch_guard"]()
        return llm.LLMResponse(text="We should chase the supplier today.", thinking=None, tool_calls=[], stop_reason="end_turn")

    monkeypatch.setattr(llm.LLM, "complete", answer)


def _question(app, index):
    row = app.post(TESTS + "/customer", json={
        "specialist": PACK, "task": f"Purchase order example {index}: which supplier should we chase?",
        "includes": ["chase"], "excludes": [], "refusal": False, "citation": False})
    assert row.status_code == 200, row.text


def _review(app, action, **fields):
    context = app.get(DRAFTS + "/history").json()["context"]
    return app.post(DRAFTS + "/review", json={"name": PACK, "action": action, "context": context, **fields})


def _confirm(app, review):
    assert review.status_code == 200, review.text
    return app.post(DRAFTS + "/apply", json={"token": review.json()["token"], "confirmed": True})


def _saved_draft(app, entered):
    saved = _confirm(app, _review(app, "save", entered=entered))
    assert saved.status_code == 200 and saved.json()["confirmed"], saved.text
    return "SPD-" + saved.json()["operation"]


def _passing_check(app, draft):
    checked = _confirm(app, _review(app, "check", selected=draft))
    assert checked.status_code == 200, checked.text
    original, deadline = checked.json(), time.time() + 20
    while not (original["confirmed"] and (original.get("run") or {}).get("state") in {"done", "failed", "stopped", "unknown"}):
        assert time.time() < deadline, original
        time.sleep(.05)
        original = app.get(DRAFTS + "/originals/" + checked.json()["operation"]).json()
    assert original["run"]["state"] == "done" and all(row["passed"] for row in original["run"]["results"]), original


def test_a_guard_refusal_before_any_change_keeps_its_error_and_leaves_no_hold(client, monkeypatch):
    app = client
    for index in range(2):
        _question(app, index)
    _answers(monkeypatch)
    draft = _saved_draft(app, {"persona": NEW})
    _passing_check(app, draft)
    review = _review(app, "publish", selected=draft)
    assert review.status_code == 200, review.text
    # Someone adds a saved question after this review, so the passing check no
    # longer covers every current question. Nothing has been published yet.
    _question(app, 2)
    refused = app.post(DRAFTS + "/apply", json={"token": review.json()["token"], "confirmed": True})
    assert refused.status_code == 409, refused.text
    assert "no longer support" in refused.json()["detail"]
    assert app.get("/api/v1/agents/" + PACK).json()["persona"] != NEW
    original = app.get(DRAFTS + "/originals/" + review.json()["operation"])
    assert original.status_code == 200 and original.json()["confirmed"] is False, original.text
    assert "refused before it changed anything" in original.json()["message"]
    assert "unconfirmed" not in original.json()["message"]
    # The refusal is not a hold: a separate new decision needs no acknowledgement.
    again = _review(app, "save", entered={"persona": NEW + " Again."})
    assert again.status_code == 200, again.text
    # A refused publication is not an earlier definition that can be restored.
    assert not app.get(DRAFTS, params={"name": PACK}).json()["earlier"]


def test_work_that_may_have_begun_stays_unconfirmed_and_blocks_a_new_intent(client, monkeypatch, audit_rows):
    from maverick import domain_edit

    app = client
    _question(app, 0)
    draft = _saved_draft(app, {"persona": NEW})
    real = domain_edit.write_override

    def written_then_failed(*args, **kwargs):
        real(*args, **kwargs)
        raise HTTPException(409, "The reply was lost after the definition was written.")

    monkeypatch.setattr(domain_edit, "write_override", written_then_failed)
    published = _confirm(app, _review(app, "publish", selected=draft, reason="Urgent supplier change approved by finance"))
    assert published.status_code == 200, published.text
    assert published.json()["confirmed"] is False and "unconfirmed" in published.json()["message"]
    assert app.get("/api/v1/agents/" + PACK).json()["persona"] == NEW
    blocked = _review(app, "save", entered={"persona": NEW + " Again."})
    assert blocked.status_code == 409 and "remains unconfirmed" in blocked.json()["detail"]


def test_a_refused_worker_admission_before_any_answer_is_not_a_hold(client, monkeypatch):
    from maverick_dashboard import workforce_ops_api

    app = client
    _question(app, 0)
    draft = _saved_draft(app, {"persona": NEW})
    review = _review(app, "check", selected=draft)
    assert review.status_code == 200, review.text

    def too_busy(*_args, **_kwargs):
        raise HTTPException(409, "Too many background tasks are running. Nothing was started.")

    monkeypatch.setattr(workforce_ops_api, "start_job", too_busy)
    refused = app.post(DRAFTS + "/apply", json={"token": review.json()["token"], "confirmed": True})
    assert refused.status_code == 409 and "Nothing was started" in refused.json()["detail"], refused.text
    assert _review(app, "save", entered={"persona": NEW + " Again."}).status_code == 200
