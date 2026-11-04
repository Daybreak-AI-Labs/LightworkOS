"""Plugins page: enable / disable / reset a plugin from the UI via the overlay."""
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
    monkeypatch.delenv("MAVERICK_PLUGINS_ALLOW", raising=False)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def test_plugins_page_has_toggle(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    # No third-party plugins are installed in the test env, so inject one so the
    # per-row toggle UI renders.
    import maverick.plugins as plugins

    class _EP:
        name = "weather"
        value = "weather_plugin:tool"

    monkeypatch.setattr(plugins, "_entry_points",
                        lambda group: [_EP()] if group == "maverick.tools" else [])
    r = _client().get("/plugins")
    assert r.status_code == 200
    assert 'action="/plugins/toggle"' in r.text
    assert "weather" in r.text


def test_enable_disable_reset_plugin(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    c = _client()
    from maverick.plugins import _allowed_plugin_names
    from maverick.runtime_overrides import plugin_overlay

    r = c.post("/plugins/toggle", data={"name": "weather", "action": "enable"},
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    assert "weather" in plugin_overlay()[0]            # force-enabled
    al = _allowed_plugin_names()
    assert al is not None and "weather" in al          # loader now allows it

    r = c.post("/plugins/toggle", data={"name": "weather", "action": "disable"},
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    assert "weather" in plugin_overlay()[1] and "weather" not in plugin_overlay()[0]

    r = c.post("/plugins/toggle", data={"name": "weather", "action": "reset"},
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    assert plugin_overlay() == (set(), set())


def test_toggle_rejects_bad_action_and_name(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    c = _client()
    r = c.post("/plugins/toggle", data={"name": "weather", "action": "nope"},
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 400
    r = c.post("/plugins/toggle", data={"name": "bad name!", "action": "enable"},
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 400


def test_toggle_blocks_cross_origin(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().post("/plugins/toggle", data={"name": "weather", "action": "enable"},
                       headers={"origin": "http://evil.example"},
                       follow_redirects=False)
    assert r.status_code == 403


def test_toggle_blocks_dns_rebinding_host(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    c = _client()
    r = c.post(
        "/plugins/toggle",
        data={"name": "weather", "action": "enable"},
        headers={"host": "attacker.example:8000", "origin": "http://attacker.example:8000"},
        follow_redirects=False,
    )
    assert r.status_code == 401
