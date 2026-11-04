"""The goal page renders a structured result as the deliverable its pack
declares -- a forecast as a real grid with a titled, gated card -- and leaves a
generic goal as today's plain prose."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

from test_support.element_text import element_attributes, element_texts

client = TestClient(app, base_url="http://127.0.0.1")

_FORECAST_RESULT = """\
Rolling 13-week cash forecast, every figure tied to its system of record.

| Week | Inflows | Outflows | Net |
| --- | ---: | ---: | ---: |
| W1 | 1,200 | 900 | 300 |
| W2 | 1,100 | 1,000 | 100 |
"""


def _world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    return world_model.WorldModel(tmp_path / "world.db")


def test_forecast_goal_renders_as_a_deliverable_grid(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("Refresh the cash forecast", "", domain="finance_cash13w")
    w.set_goal_status(gid, "done", result=_FORECAST_RESULT)

    t = client.get(f"/chat/goal/{gid}").text
    # Titled, gated deliverable card keyed off the pack's output contract.
    assert "13-week cash forecast" in t
    assert "Needs review</span>" in t       # plain sign-off label
    assert "Fpa analyst" in t and "fpa_analyst" not in t
    # The result is a real table, not a <pre> dump.
    assert '<table class="deliverable__table">' in t
    assert "<th scope=\"col\">Week</th>" in t
    assert "<td>1,200</td>" in t


def test_generic_goal_keeps_plain_prose(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    gid = w.create_goal("Summarize the meeting", "")  # no domain -> no contract
    w.set_goal_status(gid, "done", result="A short prose summary.")

    response = client.get(f"/chat/goal/{gid}")
    assert response.status_code == 200
    t = response.text
    result, = element_attributes(t, "div", {"id": "result"})
    assert result["tabindex"] == "0"
    assert result["aria-labelledby"] == "answer-result-label"
    assert element_texts(t, "span", {"id": result["aria-labelledby"]}) == ["Goal result"]
    assert "prose" in result["class"].split() and "data-markdown" in result
    assert element_texts(t, "div", {"id": "result"}) == ["A short prose summary."]
    # No deliverable card is rendered (the .deliverable__table *style* is always
    # present in the page's <style> block; assert on the rendered markup).
    assert '<table class="deliverable__table">' not in t
    assert 'class="deliverable__head"' not in t
    assert "Needs review</span>" not in t
