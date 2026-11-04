"""Tool servers: ready-made presets instead of raw commands."""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    main = re.sub(r"<details\b.*?</details>", " ", main, flags=re.DOTALL)  # advanced/technical only
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", main)))


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def test_presets_build_servers_without_typed_commands(client):
    r = client.post("/mcp/add-preset", data={"preset": "files", "folder": "/tmp/projects"}, follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/mcp/add-preset", data={"preset": "files", "folder": "/tmp/other"}, follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/mcp/add-preset", data={"preset": "github", "access_key": "ghp_test"},  # pragma: allowlist secret
                    follow_redirects=False)
    assert r.status_code == 303
    from maverick.runtime_overrides import mcp_overlay
    servers = mcp_overlay()
    assert set(servers) == {"files-in-a-folder", "files-in-a-folder-2", "github"}
    assert servers["files-in-a-folder"]["args"][-1] == "/tmp/projects"
    assert servers["github"]["url"].startswith("https://")


def test_presets_validate_answers_and_stay_admin_only(client, monkeypatch):
    assert client.post("/mcp/add-preset", data={"preset": "files"}).status_code == 422
    assert client.post("/mcp/add-preset", data={"preset": "online", "url": "http://x"}).status_code == 422
    assert client.post("/mcp/add-preset", data={"preset": "nope"}).status_code == 400
    assert TestClient(client.app, base_url="http://127.0.0.1").post("/mcp/add-preset", data={"preset": "memory"}).status_code == 403
    from maverick_dashboard import auth, rbac
    rbac.set_role("user:vic", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vic")
    assert client.post("/mcp/add-preset", data={"preset": "memory"}).status_code == 403


def test_tool_servers_page_reads_plainly(client):
    client.post("/mcp/add-preset", data={"preset": "memory"}, follow_redirects=False)
    text = visible_text(client.get("/mcp").text)
    for word in ("MCP", "npx", "stdio", "bearer", "KEY=VALUE", "Transport", "handshake", "verification unknown"):
        assert word not in text, word
    for label in ("Files in a folder", "GitHub", "Add files in a folder", "Test", "Remove"):
        assert label in text, label
