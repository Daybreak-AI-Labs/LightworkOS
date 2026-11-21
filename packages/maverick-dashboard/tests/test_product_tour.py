"""The page tours point at controls that exist on their page."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app

    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def test_every_tour_step_names_a_control_on_its_page(client, monkeypatch):
    # Live: "Keep track of background work" pointed at a section that only the
    # background view of Tasks renders, so "Show me" said the control was not
    # available on every ordinary visit. (Connections is checked with
    # Connections on: while it is off the page has no tour.)
    from maverick import connections
    from maverick_dashboard.product_tour import STEPS

    monkeypatch.setattr(connections, "enabled", lambda: True)
    for page, steps in STEPS.items():
        html = client.get(page).text
        for key, _title, _body, target, focus, _permission in steps:
            assert f'id="{target}"' in html, (page, key, target)
            if focus:
                assert f'id="{focus}"' in html, (page, key, focus)


def test_chat_help_step_points_at_the_copilot_button_chat_shows(client):
    # Live: the step pointed at the floating Copilot button, which Chat hides
    # in favour of the Copilot button in its own top bar.
    from maverick_dashboard.product_tour import STEPS

    html = client.get("/chat").text
    target = dict((step[0], step[3]) for step in STEPS["/chat"])["help"]
    assert target == "cs-copilot" and 'id="cs-copilot"' in html and "data-copilot-toggle" in html


def test_tasks_links_to_background_work_both_ways(client):
    plain = client.get("/goals").text
    assert 'id="goals-background-link" href="/goals?owner=me&amp;include=background">My background work<' in plain
    background = client.get("/goals?owner=me&include=background").text
    assert 'id="goals-background-link" href="/goals">Hide background work<' in background
