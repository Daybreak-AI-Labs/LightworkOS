"""Dashboard error-inspector page: /goals/{id}/errors shows failed turns."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _isolate(monkeypatch, tmp_path):
    from maverick import runtime_overrides, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(runtime_overrides, "OVERRIDES_PATH", tmp_path / "ro.toml")
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _new_goal(title="do a thing"):
    # Read the monkeypatched DEFAULT_DB attr at call time (not at import).
    import maverick.world_model as wm
    w = wm.WorldModel(wm.DEFAULT_DB)
    gid = w.create_goal(title)
    return w, gid


def test_errors_page_shows_only_error_events(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    w, gid = _new_goal()
    w.append_event(gid, "coder", "tool_call", "ran a tool fine")
    w.append_event(gid, "coder", "error", "Traceback: boom in widget.py line 42")
    w.close()

    r = _client().get(f"/goals/{gid}/errors")
    assert r.status_code == 200
    body = r.text
    assert "boom in widget.py line 42" in body        # the error is shown...
    assert "ran a tool fine" not in body              # ...non-error events are filtered out
    # The raw message stays folded away as technical details for support.
    assert '<details class="err-item">' in body and "Copy for support" in body


def test_errors_page_empty_state(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    w, gid = _new_goal("clean run")
    w.close()
    r = _client().get(f"/goals/{gid}/errors")
    assert r.status_code == 200
    assert "No problems recorded" in r.text


def test_errors_page_unknown_goal_is_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/goals/999999/errors")
    assert r.status_code == 404
