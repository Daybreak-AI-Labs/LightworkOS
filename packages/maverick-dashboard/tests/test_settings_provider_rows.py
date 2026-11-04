"""Settings > Connections > Provider keys: the page carries what the live row
update and the "Open AI provider keys" link need.

* A stopped task links to ``/settings?focus=ai-provider``; the page marks the
  one provider row that needs attention (the same row the workspace verdict
  names), so the link lands on it. All 14 known providers are considered.
* After Save, Test connection or Remove key, the browser re-renders the row and
  the page header from the page the server answers with, so each row has a
  stable status line and a replaceable details block and button block.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from maverick.config import PROVIDER_BASE_URL_ENV_VARS, PROVIDER_CREDENTIAL_ENV_VARS


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    for name in (*PROVIDER_CREDENTIAL_ENV_VARS, *PROVIDER_BASE_URL_ENV_VARS,
                 "MAVERICK_MODEL_OVERRIDE", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_ENTERPRISE"):
        monkeypatch.delenv(name, raising=False)
    config_path = tmp_path / "config.toml"
    config_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    from maverick import config, world_model
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import integration_readiness

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    integration_readiness._clear_for_testing()
    dash_app._world_cache.clear()

    class Workspace:
        client = TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

        @staticmethod
        def record(name: str, *, verified: bool, detail: str) -> None:
            from maverick.config import get_provider_config

            integration_readiness.record("provider", name, get_provider_config(name) or {},
                                         verified=verified, detail=detail)

    yield Workspace
    config.reset_config_cache()
    integration_readiness._clear_for_testing()


def _marked(page: str) -> list[str]:
    return re.findall(r'id="provider-([a-z_]+)"[^>]*data-ai-provider-focus', page)


def test_fresh_install_focuses_the_provider_the_models_use(workspace):
    from maverick_dashboard.provider_readiness import workspace_readiness

    page = workspace.client.get("/settings?focus=ai-provider").text
    routed = [row["name"] for row in workspace_readiness()["providers"] if row["routed"]]
    assert _marked(page) == [routed[0]]


def test_the_focused_row_is_the_routed_provider_that_needs_attention(workspace, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:gpt-test")
    workspace.record("openai", verified=False, detail="provider probe failed (ConnectError)")
    assert _marked(workspace.client.get("/settings").text) == ["openai"]


def test_a_connected_workspace_still_focuses_the_provider_in_use(workspace, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:gpt-test")
    workspace.record("openai", verified=True, detail="provider accepted the bounded models request")
    assert _marked(workspace.client.get("/settings").text) == ["openai"]


def test_every_provider_row_has_the_live_update_hooks(workspace):
    from maverick.providers import KNOWN_PROVIDERS

    page = workspace.client.get("/settings").text
    rows = re.findall(r'<div class="provider-row"[^>]*id="provider-([a-z_]+)"', page)
    assert rows and set(rows) <= set(KNOWN_PROVIDERS)
    for name in rows:
        block = page.split(f'id="provider-{name}"', 1)[1].split('<div class="provider-row"', 1)[0]
        assert 'class="provider-row__about"' in block, name
        assert 'class="settings-row-form provider-row__buttons"' in block, name
        assert re.search(r'<p[^>]*data-provider-status[^>]*role="status"', block), name
    # The page script maps the stop link's focus name to the marked row.
    assert "'ai-provider'" in page and "data-ai-provider-focus" in page


def test_the_page_answered_after_save_already_shows_the_new_row_state(workspace):
    """The browser re-renders from this answer, so it must carry the new state."""
    saved = workspace.client.post("/settings/providers", data={"provider": "openai", "api_key": "sk-test-0000"})  # pragma: allowlist secret
    assert saved.status_code == 200, saved.text
    row = saved.text.split('id="provider-openai"', 1)[1].split('<div class="provider-row"', 1)[0]
    assert "Key saved, not tested yet" in row
    assert 'action="/settings/providers/test"' in row  # Test connection appears with the key
    header = saved.text.split('class="hero-statebox"', 1)[1].split("</div>\n", 3)
    assert "1 set up" in "".join(header)
