"""One paid tool call charged to the run budget (``maverick.tools._paid_call``)."""
from __future__ import annotations

import socket

import httpx
import pytest
from maverick import provider_cost_cap as cap
from maverick.budget import Budget, BudgetExceeded, ToolCallPrice
from maverick.enterprise import EgressBlocked
from maverick.tools import _paid_call as paid_call


def _priced(monkeypatch, unit=None, dollars=0.0, *, hold=1.00):
    price = ToolCallPrice("replicate", unit, dollars, 0.10)
    monkeypatch.setattr(paid_call, "tool_call_price", lambda _service: price)
    monkeypatch.setattr(paid_call, "max_unmetered_hold", lambda: hold)
    monkeypatch.setattr(paid_call, "metered_provider_call",
                        lambda _provider, callback, **_metadata: callback())


def _failing(error):
    def send(*_args):
        raise error
    return send


@pytest.mark.parametrize("error, charged", [
    # It may have reached the service: charged the hold.
    (httpx.ReadTimeout("read timed out"), True),
    (httpx.RemoteProtocolError("server hung up after the request"), True),
    (OSError("connection reset"), True),
    (Exception("cannot tell"), True),
    # Known never to have left this machine: released.
    (httpx.ConnectError("connection refused"), False),
    (httpx.ConnectTimeout("connect timed out"), False),
    (ConnectionRefusedError("refused"), False),
    (socket.gaierror("name does not resolve"), False),
    (EgressBlocked("api.example.com"), False),
    # A send that cannot say whether its request left: charged.
    (ValueError("bad redirect"), True),
    (RuntimeError("cannot tell"), True),
])
def test_a_send_that_may_have_reached_the_service_is_charged_its_hold(
        monkeypatch, error, charged):
    _priced(monkeypatch)
    budget = Budget(max_dollars=1.0)
    with pytest.raises(type(error)):
        paid_call.charged_call("replicate", _failing(error), budget=budget,
                               label="Replicate", units={"request": 1})
    assert getattr(budget, "_reserved", 0.0) == 0.0
    assert budget.dollars == pytest.approx(0.10 if charged else 0.0)
    assert ("may have billed" in budget.summary()) is charged


def test_a_timed_out_retry_stops_at_the_limit(monkeypatch):
    # The reviewer's case: $0.10 attempts against a $0.10 limit. The first
    # timed out after sending and is charged, so the next ones are refused.
    _priced(monkeypatch)
    budget = Budget(max_dollars=0.10)
    sent = []

    def send():
        sent.append(1)
        raise httpx.ReadTimeout("read timed out")

    with pytest.raises(httpx.ReadTimeout):
        paid_call.charged_call("replicate", send, budget=budget, label="Replicate",
                               units={"request": 1})
    for _ in range(2):
        with pytest.raises(BudgetExceeded):
            paid_call.charged_call("replicate", send, budget=budget, label="Replicate",
                                   units={"request": 1})
    assert len(sent) == 1
    assert budget.dollars == pytest.approx(0.10)
    assert getattr(budget, "_reserved", 0.0) == 0.0


def test_a_failed_send_charges_what_its_receipt_holds_once(monkeypatch, tmp_path):
    # The provider receipt of the failed attempt is settled at the amount the
    # run budget is charged, so each ledger counts it once.
    price = ToolCallPrice("replicate", "second", 0.01, 0.10)
    monkeypatch.setattr(paid_call, "tool_call_price", lambda _service: price)
    monkeypatch.setattr(paid_call, "max_unmetered_hold", lambda: 0.50)
    ledger = tmp_path / "provider-spend.json"
    monkeypatch.setattr(cap, "caps_from_config", dict)
    monkeypatch.setattr(cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(cap, "period_key", lambda now=None, period=None: "2026-11-17")
    budget = Budget(max_dollars=2.0)

    with cap.work_item_scope("flow:paid-timeout"):
        with pytest.raises(httpx.ReadTimeout):
            paid_call.charged_call("replicate", _failing(httpx.ReadTimeout("t")),
                                   budget=budget, label="Replicate", units={"request": 1})
        receipts = cap.reservation_catalogue_for_work_item(
            "flow:paid-timeout", path=ledger).receipts

    assert [r.state for r in receipts] == ["settled"]
    assert receipts[0].actual == pytest.approx(0.50)
    assert receipts[0].operation["attempt_state"] == "failed"
    assert budget.dollars == pytest.approx(0.50)
    assert getattr(budget, "_reserved", 0.0) == 0.0


def test_a_zero_unit_price_holds_and_charges_nothing(monkeypatch):
    # The reviewer's case: Hugging Face priced at $0 per second, which its
    # replies never report. Nothing is held or charged, and a run with no
    # money left may still make the call.
    _priced(monkeypatch, "second", 0.0, hold=0.50)
    budget = Budget(max_dollars=0.50)
    held = []

    def send():
        held.append(getattr(budget, "_reserved", 0.0))
        return "ok"

    assert paid_call.charged_call("huggingface", send, budget=budget, label="Hugging Face",
                                  units={"request": 1}) == "ok"
    assert held == [0.0] and budget.dollars == 0.0
    budget.dollars = 0.50
    assert paid_call.charged_call("huggingface", send, budget=budget, label="Hugging Face",
                                  units={"request": 1}) == "ok"
    assert budget.dollars == pytest.approx(0.50)


def test_a_failed_send_counts_once_against_the_organization_cap(monkeypatch):
    # The organization's receipt is settled at the run's charge, so a $0.10
    # timed-out search leaves $9.90 of a $10 daily cap, not $9.80.
    from maverick.budget import budget_from_config
    from maverick.orchestrator import _QuotaUsageSettlement
    from maverick.tenant import provider_admission as organization
    from maverick.tenant import registry

    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    registry.create_tenant("acme", max_daily_dollars=10)
    monkeypatch.setattr(cap, "caps_from_config", dict)
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    price = ToolCallPrice("tavily", None, 0.0, 0.10)
    monkeypatch.setattr(paid_call, "tool_call_price", lambda _service: price)
    budget = budget_from_config()
    settlement = _QuotaUsageSettlement(principal="user:alice", budget=budget, domain=None)
    with organization.run_scope(budget, "user:alice"):
        with pytest.raises(httpx.ReadTimeout):
            paid_call.charged_call("tavily", _failing(httpx.ReadTimeout("t")), budget=budget,
                                   label="Tavily search", units={"request": 1})
    settlement.record()
    assert budget.dollars == pytest.approx(0.10)
    assert registry.tenant_remaining_today("acme") == pytest.approx(9.90)


def test_a_refusal_before_any_request_is_not_charged(monkeypatch):
    # The governed HTTP layer reports that no request left, whatever the
    # error: a missing key while building the request, or an egress refusal.
    from maverick import egress_guard
    from maverick.governed_http import guarded_sender

    _priced(monkeypatch)
    budget = Budget(max_dollars=1.0)

    def missing_key():
        raise RuntimeError("the service needs a key")

    def deny(_url):
        raise EgressBlocked("api.example.com")

    for send in (lambda: guarded_sender(httpx.post)("https://api.example.com/x",
                                                    headers=missing_key()),
                 lambda: guarded_sender(httpx.post)("https://api.example.com/x")):
        monkeypatch.setattr(egress_guard, "_check", deny)
        with pytest.raises((RuntimeError, EgressBlocked)):
            paid_call.charged_call("replicate", send, budget=budget, label="Replicate",
                                   units={"request": 1})
    assert budget.dollars == 0.0 and getattr(budget, "_reserved", 0.0) == 0.0


@pytest.mark.parametrize("unit, units", [
    ("message", {"request": 1}),           # a Twilio voice call or lookup
    ("image", {"request": 1}),             # a Hugging Face text inference
])
def test_a_zero_price_for_another_unit_does_not_make_a_call_free(monkeypatch, unit, units):
    _priced(monkeypatch, unit, 0.0, hold=0.50)
    budget = Budget(max_dollars=1.0)
    paid_call.charged_call("twilio", lambda: "ok", budget=budget, label="Twilio", units=units)
    assert budget.dollars == pytest.approx(0.50)
    budget = Budget(max_dollars=1.0)
    paid_call.charged_call("twilio", lambda: "ok", budget=budget, label="Twilio",
                           units={**units, unit: 2})
    assert budget.dollars == 0.0
