"""Shared controller dependencies must be reachable through actual HTTP routes."""
import re
from pathlib import Path

from fastapi.testclient import TestClient
from maverick import config, world_model
from maverick_dashboard.app import app


def test_connection_setup_serves_shared_access_state_dependency(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    from maverick import connections
    monkeypatch.setattr(connections, "enabled", lambda: True)  # the form is hidden while off
    try:
        with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
            page = client.get("/connections")
            assert page.status_code == 200
            dependency = "/static/lightwork-access-state.js"
            assert dependency in page.text
            assert page.text.index(dependency) < page.text.index("/static/lightwork-connection-setup.js")
            response = client.get(dependency)
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("application/javascript")
            asset = Path(__file__).resolve().parents[1] / "maverick_dashboard/static/lightwork-access-state.js"
            assert response.content == asset.read_bytes()
            assert "LightworkAccessState" in response.text
    finally:
        config.reset_config_cache()


def test_literal_dashboard_assets_have_registered_http_routes():
    package = Path(__file__).resolve().parents[1] / "maverick_dashboard"
    pattern = re.compile(r'''["'](/static/[A-Za-z0-9_./-]+\.(?:js|css|woff2|png|jpg|svg))(?:[?'" ])''')
    assets = set()
    for directory in (package / "templates", package / "static"):
        for source in directory.rglob("*"):
            if source.suffix in {".html", ".js", ".css"}:
                assets.update(pattern.findall(source.read_text(encoding="utf-8")))
    assert "/static/lightwork-access-state.js" in assets
    # No lifespan or app data are needed to retrieve public, immutable source assets.
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    failures = []
    try:
        for asset in sorted(assets):
            response = client.get(asset)
            if response.status_code != 200:
                failures.append((asset, response.status_code))
            elif asset.endswith(".js"):
                assert response.headers["content-type"].startswith("application/javascript"), asset
    finally:
        client.close()
    assert not failures, failures
