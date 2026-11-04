"""Plugin status must reflect policy admission and a real import."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient


@dataclass
class _EntryPoint:
    name: str
    target: Any
    value: str = "weather_plugin:tool"
    dist: Any = None
    load_calls: int = 0

    def load(self) -> Any:
        self.load_calls += 1
        if isinstance(self.target, BaseException):
            raise self.target
        return self.target


def _prepare(monkeypatch, tmp_path: Path, ep: _EntryPoint) -> TestClient:
    home = tmp_path / "maverick-home"
    monkeypatch.setenv("HOME", str(tmp_path / "user-home"))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(home / "config.toml"))
    for name in (
        "MAVERICK_AUTH_REQUIRED",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_ENTERPRISE",
        "MAVERICK_NO_CLI",
        "MAVERICK_PLUGINS_ALLOW",
        "MAVERICK_PLUGINS_ENFORCE",
        "MAVERICK_TENANT",
    ):
        monkeypatch.delenv(name, raising=False)

    import maverick.runtime_overrides as runtime_overrides
    from maverick import config, plugins, world_model
    from maverick_dashboard import app as dashboard_app

    config.reset_config_cache()
    monkeypatch.setattr(world_model, "DEFAULT_DB", home / "world.db")
    monkeypatch.setattr(
        runtime_overrides,
        "OVERRIDES_PATH",
        home / "runtime-overrides.toml",
    )
    monkeypatch.setattr(
        plugins,
        "_entry_points",
        lambda group: [ep] if group == "maverick.tools" else [],
    )
    dashboard_app._world_cache.clear()
    return TestClient(dashboard_app.app, base_url="http://127.0.0.1")


def _tool_row(client: TestClient) -> dict[str, Any]:
    response = client.get("/api/v1/plugins")
    assert response.status_code == 200
    body = response.json()
    assert body["discovery_errors"] == []
    return body["plugins"]["tools"][0]


def test_missing_dependency_is_allowed_but_not_loaded(monkeypatch, tmp_path: Path):
    ep = _EntryPoint(
        "weather",
        ModuleNotFoundError("No module named 'weather_sdk'"),
    )
    client = _prepare(monkeypatch, tmp_path, ep)
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "weather")

    row = _tool_row(client)
    assert row["discovered"] is True
    assert row["configured"] is True
    assert row["allowed"] is True
    assert row["loaded"] is False
    assert row["state"] == "import_failed"
    assert "ModuleNotFoundError" in row["load_error"]
    assert "weather_sdk" in row["load_error"]
    assert row["readiness"]["dependency"]["status"] == "failed"
    assert row["readiness"]["runtime"]["status"] == "failed"
    assert row["readiness"]["live"]["status"] == "unknown"

    page = client.get("/plugins")
    assert page.status_code == 200
    assert "0 of 1 plugins running" in page.text
    assert "Couldn&#39;t start" in page.text or "Couldn't start" in page.text
    assert "Why it didn" in page.text
    assert "weather_sdk" in page.text


def test_allowlist_denial_never_imports_or_claims_loaded(monkeypatch, tmp_path: Path):
    ep = _EntryPoint("weather", lambda: object())
    client = _prepare(monkeypatch, tmp_path, ep)

    row = _tool_row(client)
    assert row["discovered"] is True
    assert row["configured"] is False
    assert row["allowed"] is False
    assert row["loaded"] is False
    assert row["state"] == "not_configured"
    assert ep.load_calls == 0

    page = client.get("/plugins")
    assert page.status_code == 200
    assert "0 of 1 plugins running" in page.text
    assert "Turned off" in page.text
    assert "Not checked while off" in page.text
    assert ep.load_calls == 0


def test_successful_import_and_tool_contract_are_shown_loaded(monkeypatch, tmp_path: Path):
    ep = _EntryPoint("weather", lambda: object())
    client = _prepare(monkeypatch, tmp_path, ep)
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "weather")

    row = _tool_row(client)
    assert row["discovered"] is True
    assert row["configured"] is True
    assert row["allowed"] is True
    assert row["loaded"] is True
    assert row["state"] == "loaded"
    assert row["readiness"]["runtime"]["status"] == "passed"
    assert row["readiness"]["live"]["status"] == "unknown"

    page = client.get("/plugins")
    assert page.status_code == 200
    assert "1 of 1 plugins running" in page.text
    assert "Running" in page.text
    assert "Allowed" in page.text
    for jargon in ("import failed", "not configured", "allowlist", "HTTP", "discovered"):
        assert jargon not in page.text
    assert 'data-plugin-action="disable" data-plugin-target="weather"' in page.text
    assert 'id="plugin-mutation-status"' in page.text
    assert '/static/lightwork-plugins.js' in page.text
    assert ep.load_calls == 2


def test_plugin_template_wires_every_control_plane_mutation_to_guard():
    template = (
        Path(__file__).parents[1]
        / "maverick_dashboard"
        / "templates"
        / "plugins.html"
    ).read_text(encoding="utf-8")

    assert template.count("data-plugin-mutation") == 4
    for action in (
        "enable",
        "disable",
        "reset",
        "install",
        "replace-approvals",
    ):
        assert f'data-plugin-action="{action}' in template
    assert "install-switch-off" in template
    assert "install-switch-on" in template
    assert 'aria-live="polite"' in template
    assert '/static/lightwork-plugins.js' in template


def test_plugin_mutation_guard_script_is_served(monkeypatch, tmp_path: Path):
    client = _prepare(monkeypatch, tmp_path, _EntryPoint("weather", lambda: object()))

    response = client.get("/static/lightwork-plugins.js")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/javascript")
    expected = (
        Path(__file__).parents[1]
        / "maverick_dashboard"
        / "static"
        / "lightwork-plugins.js"
    ).read_bytes()
    assert response.content == expected
    assert b"LightworkPluginMutations" in response.content
