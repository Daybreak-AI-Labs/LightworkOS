"""Practice AI calls cost real provider money: Billing, Spend, Savings,
Budget, Provider spending, Compare cost records and the cost exports show them
on their own labelled line, apart from the real totals, limits and quotas."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

LINE = "(not counted against limits)"


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()
    dash_app._world_cache.clear()


@pytest.fixture
def practised(client):
    """One practice run that cost $0.42 of real provider money."""
    from maverick import practice, provider_cost_cap, quotas
    from maverick.world_model import open_world

    with practice.scope():
        world = open_world()
        goal = world.create_goal("Practice: chase the PO", owner="")
        episode = world.start_episode(goal)
        world.end_episode(episode, "ok", "done", cost_dollars=0.42, input_tokens=1000, output_tokens=200)
        quotas.record_usage("user:local", 0.42)  # a local caller's runs are charged here
        provider_cost_cap.record("anthropic", 0.42)  # what the provider actually charged
    return client


def _rows(text):
    return list(csv.reader(io.StringIO(text)))


def test_billing_page_and_statement_show_practice_on_its_own_line(practised):
    page = practised.get("/billing").text
    assert f"Practice: $0.42 this month {LINE}" in page
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    rows = _rows(practised.get(f"/billing?format=csv&period={month}").text)
    assert [r for r in rows[1:] if r[0] != "practice"] == []  # no real runs
    practice = [r for r in rows if r[0] == "practice"][0]
    assert practice[4] == "Practice runs (not counted against limits)" and practice[5] == "0.420000"
    assert len(practice) == len(rows[0])


def test_cost_export_has_a_labelled_practice_row(practised):
    rows = _rows(practised.get("/api/v1/cost.csv").text)
    assert [r[5] for r in rows if r[0] == "practice"] == ["0.420000"]


def test_spend_reports_practice_apart_from_the_real_total(practised):
    assert f"Practice: $0.42 across all time {LINE}" in practised.get("/spend").text
    data = practised.get("/api/v1/spend").json()
    assert data["total"]["dollars"] == 0 and data["practice"]["dollars"] == pytest.approx(0.42)
    assert data["practice"]["counted_against_limits"] is False


def test_savings_show_practice_spend_outside_the_savings(practised):
    assert ("Practice: $0.42 in the last 90 days, not part of these savings (not counted against limits)"
            in practised.get("/savings").text)
    assert practised.get("/api/v1/savings").json()["practice"]["dollars"] == pytest.approx(0.42)


def test_budget_shows_practice_today_within_its_own_limit(practised):
    assert ("Practice: $0.42 today, within its $1.00 daily practice limit (not counted against limits)"
            in practised.get("/budget").text)


def test_provider_spending_still_adds_up_and_says_how_much_was_practice(practised):
    from maverick import provider_cost_cap

    # The provider ledger is what the provider charged: practice calls stay in it.
    assert provider_cost_cap.check("anthropic").spent == pytest.approx(0.42)
    period = provider_cost_cap.period_key()
    page = practised.get("/provider-spending").text
    assert f"Of this, practice: $0.42 in {period} (real provider charges already in the totals; not counted against limits)" in page
    status = practised.get("/api/v1/recovery/provider-spending", params={"period": period})
    assert status.status_code == 200, status.text
    assert status.json()["practice"]["dollars"] == pytest.approx(0.42)


def test_compare_cost_records_lists_practice_beside_the_runtime_record(practised):
    report = practised.get("/api/v1/cost/reconciliation").json()
    names = {ledger["name"]: ledger for ledger in report["ledgers"]}
    assert names["Runtime episode record"]["amount"] == 0
    assert names["Practice runs"]["amount"] == pytest.approx(0.42)
    assert "not counted against limits" in names["Practice runs"]["basis"]


def test_practice_spend_never_counts_against_limits_or_quotas(practised):
    from maverick import quotas, spending_limits

    spending_limits.set_user_limit("user:local", 0.50, "day", actor="admin")
    assert quotas.UsageLedger().usage("user:local")["dollars"] == 0
    assert spending_limits.start_refusal("user:local") is None
    assert spending_limits.recorded_spend("day", "user:local") == 0.0


def test_invoice_shows_practice_as_information_not_a_charge(practised):
    from maverick_dashboard import billing_invoice_api as invoice

    answer = practised.get(invoice.router.prefix + "/invoice.csv", params={"tenant": "default"})
    assert answer.status_code == 200, answer.text
    rows = _rows(answer.text)
    total = [r for r in rows if r and r[0] == "Total"][0]
    practice = [r for r in rows if r and r[0] == "Practice"][0]
    assert practice[1] == "Practice runs (not counted against limits; not charged on this invoice)"
    assert practice[2] == "0.42" and total[2] in {"0", "0.00"}
