"""Add / remove MCP servers from the dashboard (no config.toml editing)."""
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
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def test_page_renders_add_forms(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().get("/mcp")
    assert r.status_code == 200
    assert r.text.count('action="/mcp/add"') == 2  # stdio + http
    assert 'name="transport" value="stdio"' in r.text
    assert 'name="transport" value="http"' in r.text


def test_add_stdio_server_then_listed_removable(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    c = _client()
    r = c.post("/mcp/add", headers=_ORIGIN, follow_redirects=False, data={
        "transport": "stdio", "name": "filesystem",
        "command": "npx", "args": "-y\n@modelcontextprotocol/server-filesystem\n/tmp",
        "env": "API_BASE=https://example.com",
    })
    assert r.status_code == 303
    from maverick.runtime_overrides import mcp_overlay
    ov = mcp_overlay()
    assert ov["filesystem"]["command"] == "npx"
    assert ov["filesystem"]["args"] == ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    assert ov["filesystem"]["env"]["API_BASE"] == "https://example.com"
    page = c.get("/mcp").text
    assert "filesystem" in page
    assert 'action="/mcp/remove"' in page  # removable row rendered


def test_add_http_server(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().post("/mcp/add", headers=_ORIGIN, follow_redirects=False, data={
        "transport": "http", "name": "remote",
        "url": "https://host.example/mcp", "auth_token": "t0ken",
        "headers": "X-Org=acme",
    })
    assert r.status_code == 303
    from maverick.runtime_overrides import mcp_overlay
    ov = mcp_overlay()
    assert ov["remote"]["url"] == "https://host.example/mcp"
    assert ov["remote"]["headers"]["X-Org"] == "acme"


def test_remove_server(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    c = _client()
    c.post("/mcp/add", headers=_ORIGIN, data={
        "transport": "stdio", "name": "gone", "command": "true"})
    r = c.post("/mcp/remove", headers=_ORIGIN, follow_redirects=False,
               data={"name": "gone"})
    assert r.status_code == 303
    from maverick.runtime_overrides import mcp_overlay
    assert "gone" not in mcp_overlay()


def test_invalid_command_rejected(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().post("/mcp/add", headers=_ORIGIN, follow_redirects=False, data={
        "transport": "stdio", "name": "evil", "command": "rm; reboot"})
    assert r.status_code == 400


def test_missing_command_rejected(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().post("/mcp/add", headers=_ORIGIN, follow_redirects=False, data={
        "transport": "stdio", "name": "empty", "command": "  "})
    assert r.status_code == 400


def test_cross_origin_post_blocked(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    # no Origin/Referer -> same-origin guard fails closed
    r = _client().post("/mcp/add", follow_redirects=False, data={
        "transport": "stdio", "name": "x", "command": "true"})
    assert r.status_code == 403
