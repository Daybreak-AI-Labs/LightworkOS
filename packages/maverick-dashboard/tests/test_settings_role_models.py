"""Settings: per-role model overrides (a pin per agent role)."""
from __future__ import annotations

from fastapi.testclient import TestClient

_ORIGIN = {"origin": "http://127.0.0.1"}


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _prep(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def test_settings_shows_per_role_form(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().get("/settings")
    assert r.status_code == 200
    assert "Models for each role" in r.text
    assert 'action="/settings/models/roles"' in r.text
    assert 'name="coder"' in r.text  # a per-role select is present


def test_set_and_clear_per_role_model(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    c = _client()
    r = c.post("/settings/models/roles",
               data={"coder": "claude-opus-4-8", "writer": ""},
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303

    from maverick.llm import model_for_role
    from maverick.runtime_overrides import role_model_override
    assert model_for_role("coder") == "claude-opus-4-8"   # per-role pin applied
    assert role_model_override("coder") == "claude-opus-4-8"
    assert role_model_override("writer") is None           # empty = no pin

    r = c.post("/settings/models/roles", data={"coder": ""},
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    assert role_model_override("coder") is None


def test_per_role_rejects_bad_model(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().post("/settings/models/roles", data={"coder": "bad model!!"},
                       headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 400


def test_per_role_blocks_cross_origin(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().post("/settings/models/roles", data={"coder": "claude-opus-4-8"},
                       headers={"origin": "http://evil.example"},
                       follow_redirects=False)
    assert r.status_code == 403
