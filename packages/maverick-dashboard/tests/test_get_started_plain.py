"""Get started: every fix is a button to the page that fixes it."""
from __future__ import annotations

import html as _html
import re

from fastapi.testclient import TestClient


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    # Administrator-only technical details are allowed to keep exact text.
    main = re.sub(r'<details class="gs__tech">.*?</details>', " ", main, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", main)))


def test_start_page_has_no_commands_or_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    page = TestClient(dash_app.app, base_url="http://127.0.0.1").get("/start").text
    text = visible_text(page)
    for word in ("maverick ", "--json", "config.toml", ".maverick", "[evidence_graph]", "preflight",
                 "SYNTHETIC", "operator", "tenant"):
        assert word not in text, word
    assert "Fix next:" in text and "Test connections" in text
    # A switchable module is offered as a Turn on button wired to the shared handler.
    assert 'data-module-gate="evidence_graph"' in page and "mg-on" in page
    config.reset_config_cache()
