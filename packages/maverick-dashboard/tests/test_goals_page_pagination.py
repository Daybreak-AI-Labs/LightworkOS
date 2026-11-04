"""The Tasks page renders one page of goals and loads the rest on demand."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dashboard_app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    dashboard_app._world_cache.clear()
    return TestClient(dashboard_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _seed(n: int) -> None:
    from maverick import world_model

    wm = world_model.WorldModel(world_model.DEFAULT_DB)
    for i in range(n):
        wm.create_goal(f"seed goal {i}", "")


def test_first_page_is_capped_and_offers_show_more(client):
    from maverick_dashboard.app import GOALS_PAGE_SIZE

    _seed(GOALS_PAGE_SIZE + 70)
    page = client.get("/goals")
    assert page.status_code == 200
    assert len(re.findall(r'<div class="g-row" id="\d+"', page.text)) == GOALS_PAGE_SIZE
    assert 'id="run-more"' in page.text
    assert f'data-next-offset="{GOALS_PAGE_SIZE}"' in page.text
    assert f'data-page-size="{GOALS_PAGE_SIZE}"' in page.text
    # The button's target: the API page the browser appends.
    more = client.get(f"/api/v1/goals?limit={GOALS_PAGE_SIZE}&offset={GOALS_PAGE_SIZE}")
    assert more.status_code == 200
    assert len(more.json()) == GOALS_PAGE_SIZE
    assert more.headers["Pagination-Has-More"] == "true"
    assert more.headers["Pagination-Next-Offset"] == str(2 * GOALS_PAGE_SIZE)
    last = client.get(f"/api/v1/goals?limit={GOALS_PAGE_SIZE}&offset={2 * GOALS_PAGE_SIZE}")
    assert len(last.json()) == 20 and last.headers["Pagination-Has-More"] == "false"


def test_a_short_list_has_no_show_more(client):
    _seed(7)
    page = client.get("/goals")
    assert len(re.findall(r'<div class="g-row" id="\d+"', page.text)) == 7
    # The button stays in place for search paging but is hidden here.
    more = re.search(r'<button id="run-more"[^>]*>', page.text).group(0)
    assert re.search(r"\shidden>$", more), more
