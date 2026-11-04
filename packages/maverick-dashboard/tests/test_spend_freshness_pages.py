"""Every spend view says when its spending was last updated, from the data's
own time: Savings, Billing, Provider spending, Budget and Compare cost records.
Nothing recorded means "No spending recorded yet.", never a made-up time."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

_ORIGIN = {"origin": "http://127.0.0.1"}


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick import provider_cost_cap as cap
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=_ORIGIN)
    config.reset_config_cache()


def _finished_task(cost=0.42):
    from maverick import world_model
    from maverick_dashboard import app as dash_app
    w = world_model.open_world()
    gid = w.create_goal("Quarterly summary")
    episode = w.start_episode(gid)
    w.end_episode(episode, "Done", "success", cost_dollars=cost)
    newest = w.list_episodes(limit=1)[0]
    dash_app._world_cache.clear()
    return newest.ended_at or newest.started_at


def _stamp(page: str) -> str:
    start = page.index("data-mv-freshness")
    return page[start:page.index("</p>", start)]


@pytest.mark.parametrize("path", ["/savings", "/billing"])
def test_task_cost_pages_show_the_newest_recorded_cost(client, path):
    assert "No spending recorded yet." in _stamp(client.get(path).text)
    when = _finished_task()
    label = _stamp(client.get(path).text)
    assert "Spending updated <time" in label and f'data-mv-time="{when:.3f}"' in label


def test_budget_page_shows_when_usage_last_reached_the_ledger(client):
    from maverick import spending_limits
    from maverick.quotas import UsageLedger
    assert "No spending recorded yet." in _stamp(client.get("/budget").text)
    UsageLedger().record("user:alice", 1.0, 0, 0)
    stamp = spending_limits.spend_recorded_at()
    label = _stamp(client.get("/budget").text)
    assert "Spending updated <time" in label and f'data-mv-time="{stamp:.3f}"' in label


def test_compare_cost_records_shows_the_newest_of_its_records(client):
    from maverick import spending_limits
    from maverick.quotas import UsageLedger
    assert "No spending recorded yet." in _stamp(client.get("/cost-reconciliation").text)
    when = _finished_task()
    page = client.get("/cost-reconciliation").text
    assert f'data-mv-time="{when:.3f}"' in _stamp(page)
    UsageLedger().record("user:alice", 1.0, 0, 0)
    newest = max(when, spending_limits.spend_recorded_at())
    data = client.get("/api/v1/cost/reconciliation").json()
    assert data["spend_recorded_at"] == pytest.approx(newest)
    assert f'data-mv-time="{newest:.3f}"' in _stamp(client.get("/cost-reconciliation").text)


def test_provider_spending_shows_when_the_provider_ledger_changed(client):
    from maverick import provider_cost_cap as cap
    assert "No spending recorded yet." in _stamp(client.get("/provider-spending").text)
    cap.record("openai", 0.5)
    stamp = cap.recorded_at()
    assert stamp is not None
    label = _stamp(client.get("/provider-spending").text)
    assert "Spending updated <time" in label and f'data-mv-time="{stamp:.3f}"' in label


def test_provider_spending_on_a_shared_ledger_claims_no_time(client, monkeypatch):
    from maverick import provider_cost_cap as cap
    monkeypatch.setattr(cap, "_shared_world", lambda: object())
    assert cap.recorded_at() is None
    page = client.get("/provider-spending").text
    assert "data-mv-freshness" not in page
