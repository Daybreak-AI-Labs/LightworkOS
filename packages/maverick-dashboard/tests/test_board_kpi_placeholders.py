"""Board pages hold the KPI row's place before the numbers arrive.

The KPI row on Overview, Security and Privacy was an empty element until
board.js fetched the numbers, so the charts below jumped down by the row's
height (layout shift 0.36 on Overview, 0.095 on Security). The pages now
render one placeholder tile per KPI, built like the real tiles, which the
page script replaces in place.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

CSS = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static" / "lightwork.css"


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dash_app._world_cache.clear()
    world = world_model.WorldModel(world_model.DEFAULT_DB)
    world.create_goal("Vendor DPA review", domain="legal_privacy")  # Overview shows its board once work exists
    world.close()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _row(page):
    start = page.index('<div class="bd-kpis" id="bd-kpis">')
    end = page.index('<div class="viz-grid">', start)
    return page[start:end]


@pytest.mark.parametrize("path", ["/overview", "/security", "/privacy"])
def test_kpi_row_renders_a_placeholder_for_every_tile_the_script_draws(client, path):
    page = client.get(path)
    assert page.status_code == 200, page.text[:300]
    row = _row(page.text)
    placeholders = re.findall(
        r'<div class="bd-kpi panel" aria-hidden="true">\s*<div class="bd-kpi__top"><div class="bd-kpi__label">([^<]+)</div></div>'
        r'\s*<div class="bd-kpi__num">[^<]+</div>\s*<div class="bd-kpi__foot">', row)
    # The labels the page script draws, in order: B.kpi({ label: '...' ...
    drawn = re.findall(r"B\.kpi\(\{\s*label:\s*'([^']+)'", page.text)
    assert len(drawn) == 4, drawn
    assert placeholders == drawn
    # render() clears the row before drawing, so placeholders never stay beside real tiles.
    assert "k.textContent = '';" in page.text


def test_tiles_reserve_room_for_the_chip_and_a_two_line_note():
    """A placeholder has no change chip, sparkline or note yet; the tile rows
    keep the height those take, so a real tile is the same size."""
    css = CSS.read_text(encoding="utf-8")
    top = re.search(r"\.bd-kpi__top\s*\{([^}]*)\}", css).group(1)
    foot = re.search(r"\.bd-kpi__foot\s*\{([^}]*)\}", css).group(1)
    assert "min-height: calc(var(--text-xs) * var(--leading) + 0.24rem)" in top
    assert "min-height: max(30px, calc(2 * var(--text-xs) * var(--leading)))" in foot
    chip = re.search(r"\.bd-chip\s*\{([^}]*)\}", css).group(1)
    assert "padding: 0.12rem" in chip  # the 0.24rem above is this padding, top and bottom
