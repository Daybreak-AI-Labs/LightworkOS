"""Providers and provider spending in plain language, with buttons."""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", main)))


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0000")  # pragma: allowlist secret
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def test_providers_page_has_test_and_add_buttons_and_no_jargon(client):
    page = client.get("/providers").text
    text = visible_text(page)
    for word in ("GET /api", "JSON", "environment:", "OPENAI_API_KEY", "(ms)", "percentile", "verification unknown"):
        assert word not in text, word
    assert "Add a provider" in text and "Test connection" in text
    assert 'name="next" value="providers"' in page


def test_provider_test_from_providers_page_returns_there(client, monkeypatch):
    from maverick_dashboard import integration_readiness
    monkeypatch.setattr(integration_readiness, "test_provider", lambda name: {})
    r = client.post("/settings/providers/test", data={"provider": "openai", "next": "providers"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/providers?tested=1"
    assert "Connection test finished" in client.get("/providers?tested=1").text


def test_provider_spending_page_uses_pickers(client):
    page = client.get("/provider-spending").text
    text = visible_text(page)
    for word in ("UTC day", "YYYY", "PAR-", "lowercase provider", "MiB"):
        assert word not in text, word
    assert 'type="month"' in page and 'type="date"' in page and 'id="spend-provider" class="select"' in page
    assert 'class="btn btn--primary"' in page and "<main id=\"provider-spending\"" not in page
