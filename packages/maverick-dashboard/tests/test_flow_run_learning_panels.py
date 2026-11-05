"""Learning controls appear only when the current person can use them."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def page(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import config, world_model
    from maverick_dashboard import app as dashboard_app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    client = TestClient(dashboard_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

    def render(*, signed_in: bool, capture: bool) -> str:
        monkeypatch.setattr(config, "get_flows", lambda: {
            "enable": True, "action_episode_capture": capture,
        })
        monkeypatch.setattr(dashboard_app, "caller_principal",
                            lambda _request: "user:owner" if signed_in else None)
        response = client.get("/flows/demo/runs/example")
        assert response.status_code == 200, response.text[:300]
        return response.text

    yield render
    config.reset_config_cache()


def test_local_no_sign_in_hides_inaccessible_learning_panels(page):
    html = page(signed_in=False, capture=True)
    assert 'id="le-card"' not in html and 'id="lx-card"' not in html
    assert 'lightwork-learning-example.js' not in html
    assert 'lightwork-learning-capture.js' not in html
    assert 'id="fr-steps"' in html


def test_signed_in_viewer_sees_only_enabled_learning_controls(page):
    # The keep-as-example panel always explains its current state; its
    # enrolment controls stay hidden until the run's status says it can be kept.
    for capture in (False, True):
        html = page(signed_in=True, capture=capture)
        assert 'id="le-card"' in html and 'id="lx-card"' in html
        assert '<div id="lx-enroll" hidden>' in html
        assert "Checking whether this run can be an example" in html


def test_keep_as_example_panel_knows_when_example_collection_is_off(page):
    # With collection off the panel explains that, instead of probing the
    # example APIs and reporting their refusal as missing account access.
    assert 'id="lx-card" aria-labelledby="lx-title" data-capture="off"' in page(signed_in=True, capture=False)
    assert 'id="lx-card" aria-labelledby="lx-title" data-capture="on"' in page(signed_in=True, capture=True)
