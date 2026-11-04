"""Trajectory timeline filter controls (agent / severity)."""
from __future__ import annotations

import pytest

# Skip the module entirely if FastAPI isn't installed.
fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient


@pytest.fixture
def world_with_events(tmp_path, monkeypatch):
    """A WorldModel with one goal carrying events of distinct kinds."""
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    g1 = w.create_goal("root task", "high-level")
    w.append_event(g1, "orchestrator", "tool", "called shell: ls")
    w.append_event(g1, "coder", "error", "boom")
    w.append_event(g1, "coder", "thinking", "hmm")
    w.commit() if hasattr(w, "commit") else w.conn.commit()
    yield w, g1
    w.close()


@pytest.fixture
def client(world_with_events, monkeypatch):
    """Wired-up TestClient sharing the same world db as the fixture."""
    from maverick_dashboard import app as app_mod
    w, _g1 = world_with_events
    monkeypatch.setattr(app_mod, "_world", lambda: w)
    return TestClient(app_mod.app, base_url="http://127.0.0.1")


def test_trajectory_renders_agent_filter(client, world_with_events):
    _, g1 = world_with_events
    resp = client.get(f"/goals/{g1}/trajectory")
    assert resp.status_code == 200
    body = resp.text
    # The agent filter select element is present with its id/class.
    assert 'id="filter-agent"' in body
    assert "filter-agent" in body
    # Distinct agents from the rendered events become options, named as
    # people know them (the orchestrator role is the Planner).
    assert ">Planner<" in body
    assert ">Coder<" in body


def test_trajectory_renders_severity_filter(client, world_with_events):
    _, g1 = world_with_events
    resp = client.get(f"/goals/{g1}/trajectory")
    assert resp.status_code == 200
    body = resp.text
    # The severity (event kind) filter select element is present.
    assert 'id="filter-severity"' in body
    assert "filter-severity" in body
    # Distinct kinds from the rendered events become options.
    assert ">Action<" in body
    assert ">Problem<" in body
    assert ">Thinking<" in body


def test_trajectory_rows_carry_filter_data_attrs(client, world_with_events):
    _, g1 = world_with_events
    resp = client.get(f"/goals/{g1}/trajectory")
    body = resp.text
    # Rows expose the data-agent attribute so the inline JS can filter them.
    assert 'data-agent="orchestrator"' in body
    assert 'data-kind="error"' in body


def test_trajectory_steps_read_in_plain_words_with_the_recording_folded_away(tmp_path, monkeypatch):
    from maverick.world_model import WorldModel
    from maverick_dashboard import app as app_mod

    w = WorldModel(tmp_path / "plain.db")
    try:
        gid = w.create_goal("Summarize vendor spend", "")
        brief = "role=orchestrator depth=0 brief=Top-level goal: Summarize vendor spend"
        w.append_event(gid, "orchestrator-0-72eb85", "plan", brief)
        w.append_event(gid, "orchestrator-0-72eb85", "verify",
                       "verification skipped (conversational answer: no tools, no code)")
        w.append_event(gid, "orchestrator-0-72eb85", "finding", "**Total:** $412,800")
        monkeypatch.setattr(app_mod, "_world", lambda: w)
        body = TestClient(app_mod.app, base_url="http://127.0.0.1").get(f"/goals/{gid}/trajectory").text
    finally:
        w.close()
    assert '<p class="ev-step">Started working on your request</p>' in body
    assert "Skipped the extra check: a short conversational answer" in body
    assert '<p class="ev-step">Wrote the answer</p>' in body
    # The recorded brief is still there for support, but only under Technical details.
    before, _, after = body.partition('<details class="ev-technical"><summary>Technical details</summary>')
    assert "role=orchestrator depth=0 brief=" not in before
    assert "role=orchestrator depth=0 brief=" in after
    assert ">Orchestrator 0 72eb85<" not in body and ">Planner<" in body


def test_the_offline_archive_viewer_link_downloads_the_viewer(client, world_with_events):
    # The trajectory page offers the viewer for a saved archive. The link must
    # reach the file, sent as a download so it never renders as a page under
    # the dashboard's address (it runs its own inline script from disk).
    _, g1 = world_with_events
    page = client.get(f"/goals/{g1}/trajectory").text
    assert 'href="/static/lightwork-archive-viewer.html"' in page
    resp = client.get("/static/lightwork-archive-viewer.html")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert resp.headers["content-disposition"].startswith("attachment;")
    assert 'filename="lightwork-archive-viewer.html"' in resp.headers["content-disposition"]
    assert "<script" in resp.text
