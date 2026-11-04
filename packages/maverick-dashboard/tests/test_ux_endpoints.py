"""Pins / saved views / annotations / explain / multi-run-compare endpoints."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick.ux_store import MAX_VIEW_PARAMS
from maverick_dashboard import app as app_mod
from maverick_dashboard.app import app

# Mutating requests must carry a matching Origin (the dashboard CSRF contract).
client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app_mod._world_cache.clear()
    # Point the UX store at a temp file and reset the shared instance.
    import maverick.ux_store as ux
    monkeypatch.setattr(ux, "_shared", None)
    real = ux.UxStore

    def _factory(path=None):
        return real(path=tmp_path / "ux.json")

    monkeypatch.setattr(ux, "UxStore", _factory)
    yield
    monkeypatch.setattr(ux, "UxStore", real)
    ux.reset_shared()


def _mk_goal(title="run one"):
    return app_mod._world().create_goal(title, "desc", owner="")


def test_pins_lifecycle():
    gid = _mk_goal()
    assert client.get("/api/v1/pins").json() == {"pins": []}
    assert client.post(f"/api/v1/pins/{gid}").json() == {"pins": [gid]}
    assert client.get("/api/v1/pins").json() == {"pins": [gid]}
    assert client.delete(f"/api/v1/pins/{gid}").json() == {"pins": []}
    assert client.post("/api/v1/pins/99999").status_code == 404


def test_views_lifecycle():
    r = client.post("/api/v1/views/failures", json={"status": "failed"})
    assert r.status_code == 201
    views = client.get("/api/v1/views").json()["views"]
    assert views["failures"]["params"] == {"status": "failed"}
    assert client.delete("/api/v1/views/failures").status_code == 200
    assert client.delete("/api/v1/views/failures").status_code == 404
    assert client.post("/api/v1/views/x", content=b"[1,2]",
                       headers={"Content-Type": "application/json"}).status_code == 400


def test_views_reject_oversized_payloads():
    too_many_params = {f"k{i}": "v" for i in range(MAX_VIEW_PARAMS + 1)}
    r = client.post("/api/v1/views/too-many", json=too_many_params)
    assert r.status_code == 400
    assert "too many saved view params" in r.text
    assert client.get("/api/v1/views").json()["views"] == {}

    r = client.post("/api/v1/views/too-large", json={"q": "x" * (33 * 1024)})
    assert r.status_code == 413
    assert "saved view body too large" in r.text
    assert client.get("/api/v1/views").json()["views"] == {}


def test_annotations_lifecycle():
    gid = _mk_goal()
    r = client.post(f"/api/v1/goals/{gid}/annotations",
                    json={"seq": 4, "note": "diverged here"})
    assert r.status_code == 201
    notes = client.get(f"/api/v1/goals/{gid}/annotations").json()["annotations"]
    assert len(notes) == 1 and notes[0]["seq"] == 4
    assert client.post(f"/api/v1/goals/{gid}/annotations", json={}).status_code == 400
    assert client.get("/api/v1/goals/99999/annotations").status_code == 404


def test_explain_endpoint():
    gid = _mk_goal("Summarize the quarterly report")
    w = app_mod._world()
    w.append_event(gid, "planner", "plan", "1. read 2. summarize")
    r = client.get(f"/api/v1/goals/{gid}/explain")
    assert r.status_code == 200
    text = r.json()["explanation"]
    assert "Summarize the quarterly report" in text and "plan" in text


def test_runs_compare():
    a, b = _mk_goal("alpha"), _mk_goal("beta")
    w = app_mod._world()
    w.append_event(a, "coder", "error", "boom")
    r = client.get(f"/api/v1/runs/compare?ids={a},{b}")
    assert r.status_code == 200
    runs = r.json()["runs"]
    assert [x["goal_id"] for x in runs] == [a, b]
    assert runs[0]["errors"] == 1 and runs[1]["errors"] == 0
    assert client.get("/api/v1/runs/compare?ids=abc").status_code == 400
    assert client.get(f"/api/v1/runs/compare?ids={a},99999").status_code == 404


def test_gallery_endpoints():
    gid = _mk_goal("showcase run")
    r = client.post(f"/api/v1/gallery/{gid}", json={"blurb": "exemplary"})
    assert r.status_code == 201, r.text
    listing = client.get("/api/v1/gallery").json()["gallery"]
    assert listing[0]["goal_id"] == gid
    assert listing[0]["title"] == "showcase run"
    assert listing[0]["tutorial"].endswith("/tutorial.md")
    assert client.delete(f"/api/v1/gallery/{gid}").status_code == 200
    assert client.get("/api/v1/gallery").json()["gallery"] == []
    assert client.post("/api/v1/gallery/99999", json={}).status_code == 404
    assert client.delete(f"/api/v1/gallery/{gid}").status_code == 404
