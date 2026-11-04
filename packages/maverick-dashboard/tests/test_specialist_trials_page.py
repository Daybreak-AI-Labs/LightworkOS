"""The Workforce page's Trial versions panel is served, passes the static accessibility audit, and its script builds no markup from strings."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    import maverick.runtime_overrides as runtime_overrides

    monkeypatch.setattr(runtime_overrides, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    config.reset_config_cache()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


def test_the_workforce_page_has_the_trial_panel_and_its_script(client):
    page = client.get("/workforce")
    assert page.status_code == 200, page.text[:200]
    assert 'id="trial-list"' in page.text and 'id="trial-status"' in page.text
    assert "/static/lightwork-specialist-trials.js" in page.text


def test_the_trial_script_is_served_and_builds_no_markup_from_strings(client):
    served = client.get("/static/lightwork-specialist-trials.js")
    assert served.status_code == 200 and "javascript" in served.headers["content-type"]
    script = served.text
    assert "innerHTML" not in script and "outerHTML" not in script and "insertAdjacentHTML" not in script
    assert "document.write" not in script
    assert not re.search(r"\son[a-z]+\s*=\s*[\"']", script)  # no inline event handler attributes
    assert "feedback_complete" in script  # a partial feedback count says so on the panel


def test_the_template_passes_the_static_accessibility_audit():
    import maverick_dashboard
    from maverick.a11y_audit import audit_file

    template = Path(maverick_dashboard.__file__).parent / "templates" / "workforce.html"
    assert audit_file(template) == []
