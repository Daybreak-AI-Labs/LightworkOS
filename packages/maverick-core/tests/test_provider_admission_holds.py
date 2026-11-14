"""Organization provider holds: a call's cost counts against the day it was
admitted, and it is settled under the tenant that admitted it."""
from __future__ import annotations

import pytest
from maverick import provider_cost_cap as provider
from maverick.budget import budget_from_config
from maverick.orchestrator import _QuotaUsageSettlement
from maverick.paths import tenant_scope
from maverick.tenant import provider_admission as organization
from maverick.tenant import registry


@pytest.fixture(autouse=True)
def tenant(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    registry.create_tenant("acme", max_daily_dollars=10)
    registry.create_tenant("other", max_daily_dollars=10)
    monkeypatch.setattr(provider, "caps_from_config", dict)
    monkeypatch.setattr(provider, "_shared_world", lambda: None)


def _next_day(monkeypatch):
    import maverick.quotas as quotas
    monkeypatch.setattr(quotas, "_today", lambda: "2999-01-01")
    monkeypatch.setattr(registry, "tenant_spend_today", lambda t: 0.0)


def test_an_unknown_cost_blocks_today_only(monkeypatch):
    registry.set_quota("acme", 0)
    budget = budget_from_config()
    _QuotaUsageSettlement(principal="user:a", budget=budget, domain=None)
    provider.settle(provider.reserve("openai", 0, projection_known=False,
                                     organization_budget=budget), None)
    registry.set_quota("acme", 1000)
    b2 = budget_from_config()
    _QuotaUsageSettlement(principal="user:b", budget=b2, domain=None)
    with pytest.raises(organization.OrganizationBudgetExceeded):
        provider.reserve("anthropic", 0.01, organization_budget=b2)   # conservative today
    _next_day(monkeypatch)
    assert organization.outstanding("acme") == 0
    provider.reserve("anthropic", 0.01, organization_budget=b2)        # admitted tomorrow


def test_an_unacknowledged_hold_does_not_shrink_later_days(monkeypatch):
    budget = budget_from_config()
    _QuotaUsageSettlement(principal="user:a", budget=budget, domain=None)
    provider.settle(provider.reserve("openai", 6, organization_budget=budget), 6)
    assert organization.outstanding("acme") == 6               # counts today
    _next_day(monkeypatch)
    b2 = budget_from_config()
    _QuotaUsageSettlement(principal="user:b", budget=b2, domain=None)
    provider.reserve("anthropic", 5, organization_budget=b2)    # was refused forever


def test_a_call_is_settled_under_the_tenant_that_admitted_it():
    budget = budget_from_config()
    _QuotaUsageSettlement(principal="user:a", budget=budget, domain=None)
    hold = provider.reserve("openai", 4, organization_budget=budget)
    with tenant_scope(tenant="other"):
        provider.settle(hold, 1)
    states = [c["state"] for c in organization._load("acme")["calls"].values()]
    assert states == ["settled"]


def test_an_earlier_day_hold_leaves_the_hot_store_but_stays_settleable(monkeypatch):
    # A run that died before acknowledgement kept its calls in the hot file
    # forever; past its day the hold counts for nothing, so it is archived
    # with its state instead of growing the file toward its size limit.
    budget = budget_from_config()
    _QuotaUsageSettlement(principal="user:a", budget=budget, domain=None)
    stale = provider.reserve("openai", 6, organization_budget=budget)
    _next_day(monkeypatch)
    b2 = budget_from_config()
    _QuotaUsageSettlement(principal="user:b", budget=b2, domain=None)
    provider.reserve("anthropic", 1, organization_budget=b2)
    hot = organization._load("acme")["calls"]
    assert [call["provider"] for call in hot.values()] == ["anthropic"]
    key = organization._key(stale.provider, stale.request_id)
    archived = organization._load("acme", key=key)["calls"]
    assert {call["state"] for call in archived.values() if call["provider"] == "openai"} == {"held"}
