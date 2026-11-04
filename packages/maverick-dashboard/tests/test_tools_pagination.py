"""The server-rendered tool catalog stays bounded at scale."""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient


class _Registry:
    def __init__(self, tools):
        self._tools = tools

    def all(self):
        return list(self._tools)


def _prepare(monkeypatch, tmp_path: Path, tools) -> TestClient:
    home = tmp_path / "maverick-home"
    monkeypatch.setenv("HOME", str(tmp_path / "user-home"))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(home / "config.toml"))
    for name in (
        "MAVERICK_AUTH_REQUIRED",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_ENTERPRISE",
        "MAVERICK_TENANT",
    ):
        monkeypatch.delenv(name, raising=False)

    from maverick import config
    from maverick import sandbox as sandbox_module
    from maverick import tools as tools_module
    from maverick_dashboard import app as dashboard_app

    config.reset_config_cache()
    monkeypatch.setattr(dashboard_app, "_world", lambda: object())
    monkeypatch.setattr(sandbox_module, "build_sandbox", lambda: object())
    monkeypatch.setattr(
        tools_module,
        "base_registry",
        lambda **_kwargs: _Registry(tools),
    )
    return TestClient(dashboard_app.app, base_url="http://127.0.0.1")


def _large_catalog():
    return [
        SimpleNamespace(
            name=(
                f"alpha-tool-{index:04d}"
                if index < 1200
                else f"omega-tool-{index:04d}"
            ),
            description=(
                "Needle integration for the alpha family"
                if index < 1200
                else "General omega integration"
            ),
        )
        for index in range(2505)
    ]


def _compact(value: str) -> str:
    return re.sub(r"\s+", " ", value)


def test_tools_catalog_is_searched_and_paginated_before_render(monkeypatch, tmp_path):
    client = _prepare(monkeypatch, tmp_path, _large_catalog())

    default = client.get("/tools")
    assert default.status_code == 200
    assert default.text.count('class="tool-row"') == 50
    assert "2505 tools available" in default.text
    assert "Showing 1–50 of 2505 tools" in _compact(default.text)
    assert "Page 1 of 51" in default.text
    assert "Alpha tool 0049" in default.text
    assert "Alpha tool 0050" not in default.text

    searched = client.get(
        "/tools",
        params={"q": "needle", "page": 2, "per_page": 25},
    )
    assert searched.status_code == 200
    assert searched.text.count('class="tool-row"') == 25
    assert "Showing 26–50 of 1200 matching tools" in _compact(searched.text)
    assert "Page 2 of 48" in searched.text
    assert "Alpha tool 0025" in searched.text
    assert "Alpha tool 0000" not in searched.text
    assert (
        'href="/tools?q=needle&amp;per_page=25&amp;page=1"'
        in searched.text
    )
    assert (
        'href="/tools?q=needle&amp;per_page=25&amp;page=3"'
        in searched.text
    )

    exact = client.get("/tools", params={"q": "omega-tool-2499"})
    assert exact.status_code == 200
    assert exact.text.count('class="tool-row"') == 1
    assert "Omega tool 2499" in exact.text
    assert "Showing 1–1 of 1 matching tools" in _compact(exact.text)


def test_tools_invalid_bounds_fail_visibly(monkeypatch, tmp_path):
    client = _prepare(monkeypatch, tmp_path, _large_catalog())
    html = {"Accept": "text/html"}

    for params in (
        {"per_page": 101},
        {"per_page": 0},
        {"page": 0},
        {"q": "x" * 129},
    ):
        response = client.get("/tools", params=params, headers=html)
        assert response.status_code == 400
        assert "Something went wrong" in response.text
        assert 'class="tool-row"' not in response.text

    beyond = client.get(
        "/tools",
        params={"page": 999, "per_page": 100},
        headers=html,
    )
    assert beyond.status_code == 400
    assert "Check this request" in beyond.text
    assert 'class="tool-row"' not in beyond.text


def test_tools_registry_failure_keeps_explicit_unavailable_state(monkeypatch, tmp_path):
    client = _prepare(monkeypatch, tmp_path, [])
    from maverick import tools as tools_module

    def unavailable(**_kwargs):
        raise RuntimeError("synthetic registry unavailable")

    monkeypatch.setattr(tools_module, "base_registry", unavailable)
    response = client.get("/tools")

    assert response.status_code == 200
    assert "Tool list unavailable" in response.text
    assert "The tool list couldn&#39;t be built" in response.text or "The tool list couldn't be built" in response.text
    assert "synthetic registry unavailable" in response.text
    assert "No tools registered" not in response.text
