"""Artifacts on the goal page: a goal's versioned outputs render by kind (table
-> grid, else text), and GET /api/v1/goals/<id>/artifacts lists the latest."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

from test_support.plain_language import visible_text

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    return world_model.WorldModel(tmp_path / "world.db")


def test_goal_page_renders_artifacts(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("Refresh forecast", "", domain="finance_cash13w")
    w.add_artifact(gid, "table", "Cash forecast", "| Week | Net |\n| --- | --- |\n| W1 | 300 |")
    w.add_artifact(gid, "markdown", "Variance memo", "# Memo\n\nNet up 50.")
    t = client.get(f"/chat/goal/{gid}").text
    assert 'class="artifacts"' in t
    assert "Cash forecast" in t and "Variance memo" in t
    assert '<table class="deliverable__table">' in t   # table artifact -> grid
    assert re.search(r"<td\b[^>]*>300</td>", t)
    assert "Net up 50." in t                            # markdown artifact -> text body


def test_artifact_versions_shown(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("g", "", domain="finance_cash13w")
    w.add_artifact(gid, "text", "Note", "ZZZ_BODY_ONE")
    w.add_artifact(gid, "text", "Note", "ZZZ_BODY_TWO")
    t = client.get(f"/chat/goal/{gid}").text
    assert "Version 2 of 2" in visible_text(t)
    assert "ZZZ_BODY_TWO" in t          # latest version rendered
    assert "ZZZ_BODY_ONE" not in t      # older version not rendered (latest only)


def test_artifacts_api_lists_latest(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("g", "")
    w.add_artifact(gid, "table", "T", "| a |\n| - |\n| 1 |")
    r = client.get(f"/api/v1/goals/{gid}/artifacts")
    assert r.status_code == 200
    arts = r.json()["artifacts"]
    assert len(arts) == 1 and arts[0]["title"] == "T" and arts[0]["kind"] == "table"


def test_goal_without_artifacts_has_no_panel(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("plain", "")
    w.set_goal_status(gid, "done", result="just text")
    t = client.get(f"/chat/goal/{gid}").text
    assert 'class="artifacts"' not in t


def test_artifact_history_endpoint_diffs(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("g", "")
    w.add_artifact(gid, "text", "Note", "alpha\nbeta")
    w.add_artifact(gid, "text", "Note", "alpha\ngamma")
    r = client.get(f"/api/v1/goals/{gid}/artifacts/history", params={"title": "Note"})
    assert r.status_code == 200
    vs = r.json()["versions"]
    assert [v["version"] for v in vs] == [1, 2]
    assert vs[0]["diff"] == ""                      # first version, nothing to diff against
    assert "-beta" in vs[1]["diff"] and "+gamma" in vs[1]["diff"]


def test_goal_page_shows_version_history_disclosure(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("g", "", domain="finance_cash13w")
    w.add_artifact(gid, "text", "Note", "v one")
    w.add_artifact(gid, "text", "Note", "v two")     # 2 versions -> disclosure shows
    t = client.get(f"/chat/goal/{gid}").text
    assert "artifact__history" in t and "Version history" in t


def test_version_history_loader_checks_status_and_retries(tmp_path, monkeypatch):
    """The history fetch had no r.ok check and no error path that
    cleared the loaded flag, so any non-2xx or network error left
    'Loading…' forever and re-opening never retried."""
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("g", "", domain="finance_cash13w")
    w.add_artifact(gid, "text", "Note", "v one")
    w.add_artifact(gid, "text", "Note", "v two")
    t = client.get(f"/chat/goal/{gid}").text
    assert "/static/lightwork-answer-panel.js" in t
    response = client.get("/static/lightwork-answer-panel.js")
    assert response.status_code == 200
    loader = response.text
    assert "if (!r.ok)" in loader
    assert "cgErr(r, 'load earlier versions')" in loader
    assert "delete d.dataset.loaded" in loader
    assert "Close and reopen to retry" in loader
