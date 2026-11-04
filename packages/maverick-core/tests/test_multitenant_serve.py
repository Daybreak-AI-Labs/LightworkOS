"""Multi-tenant `maverick serve`: roster + spend-cap enforcement at the door."""
from __future__ import annotations

import asyncio

import maverick.server as server_mod
from maverick.paths import data_dir
from maverick.quotas import UsageLedger
from maverick.tenant.registry import (
    create_tenant,
    release_tenant_reservation,
    reserve_tenant_budget,
    set_quota,
    suspend_tenant,
    tenant_over_quota,
    tenant_spend_today,
)

# ---- registry-level quota helpers ----

def test_tenant_over_quota_none_without_record(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    assert tenant_over_quota("ghost") is None
    assert tenant_over_quota(None) is None


def test_tenant_spend_sums_all_principals_today(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    ledger = UsageLedger(data_dir("usage", "ledger.json", tenant="acme"))
    ledger.record("user:alice", 3.0, 1, 1)
    ledger.record("user:bob", 2.0, 1, 1)
    ledger.record("user:old", 9.0, 1, 1, day="2020-01-01")  # not today
    assert tenant_spend_today("acme") == 5.0


def test_tenant_over_quota_fires_at_cap(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    create_tenant("acme")
    set_quota("acme", 5.0)
    ledger = UsageLedger(data_dir("usage", "ledger.json", tenant="acme"))
    ledger.record("user:alice", 4.0, 1, 1)
    assert tenant_over_quota("acme") is None  # under
    ledger.record("user:bob", 1.5, 1, 1)
    reason = tenant_over_quota("acme")
    assert reason and "daily spend cap" in reason and "$5.50" in reason


def test_tenant_over_quota_counts_in_flight_reservations(monkeypatch, tmp_path):
    """Holds taken by runs in flight are allowance already committed.
    The gate must refuse when spend + holds reach the cap, not only when
    recorded spend does -- otherwise the run is admitted with a $0 cap and
    dies on its first model call."""
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    create_tenant("acme")
    set_quota("acme", 5.0)
    ledger = UsageLedger(data_dir("usage", "ledger.json", tenant="acme"))
    ledger.record("user:alice", 2.0, 1, 1)
    assert tenant_over_quota("acme") is None
    assert reserve_tenant_budget("acme", 3.0, 600.0, "run-1") == 3.0
    reason = tenant_over_quota("acme")
    assert reason and "held by runs in flight" in reason
    assert "$2.00" in reason and "$3.00" in reason and "$5.00" in reason
    # The hold is released once that run settles: the allowance is back.
    release_tenant_reservation("acme", "run-1")
    assert tenant_over_quota("acme") is None


def test_explicit_zero_cap_means_no_enforcement(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    # New tenants are deliberately bounded by default. Zero is the explicit
    # unlimited contract only while optional plan-cap enforcement is off.
    monkeypatch.setenv("MAVERICK_ENFORCE_PLAN_CAPS", "0")
    create_tenant("free", max_daily_dollars=0)
    ledger = UsageLedger(data_dir("usage", "ledger.json", tenant="free"))
    ledger.record("user:x", 999.0, 1, 1)
    assert tenant_over_quota("free") is None


# ---- serve-level gate (mirrors test_tenancy's Server harness) ----

class _World:
    def get_or_create_conversation(self, channel, user_id):
        raise AssertionError("refused message must not create a conversation")


class _Msg:
    channel = "slack"
    user_id = "CROOM"
    principal_id = "UALICE"
    text = "hello"
    attachments: list = []


def _serve_with_tenancy(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(server_mod, "tenant_by_user_enabled", lambda: True,
                        raising=False)
    import maverick.paths as paths_mod
    monkeypatch.setattr(paths_mod, "tenant_by_user_enabled", lambda: True)
    monkeypatch.setattr(server_mod, "world_for_tenant", lambda _t: _World())
    return server_mod.Server(world=_World(), llm=object(), sandbox=object())


def test_suspended_tenant_refused_at_door(monkeypatch, tmp_path):
    srv = _serve_with_tenancy(monkeypatch, tmp_path)
    # provision + suspend the per-user tenant id serve derives
    create_tenant("slack:UALICE")
    suspend_tenant("slack:UALICE")
    out = asyncio.run(srv._handle_message(_Msg()))
    assert "suspended" in out
    # _World.get_or_create_conversation never ran (no goal, no turn)


def test_over_cap_tenant_refused_at_door(monkeypatch, tmp_path):
    srv = _serve_with_tenancy(monkeypatch, tmp_path)
    create_tenant("slack:UALICE")
    set_quota("slack:UALICE", 1.0)
    ledger = UsageLedger(
        data_dir("usage", "ledger.json", tenant="slack:UALICE"))
    ledger.record("user:slack:UALICE", 2.0, 1, 1)
    out = asyncio.run(srv._handle_message(_Msg()))
    assert "daily spend cap" in out


def test_unprovisioned_tenant_with_roster_refused(monkeypatch, tmp_path):
    # Once a roster exists, unknown tenants are refused (is_active contract).
    srv = _serve_with_tenancy(monkeypatch, tmp_path)
    create_tenant("someone-else")
    out = asyncio.run(srv._handle_message(_Msg()))
    assert "suspended" in out


def test_corrupt_tenant_registry_is_refused_at_door(monkeypatch, tmp_path):
    srv = _serve_with_tenancy(monkeypatch, tmp_path)
    registry = tmp_path / "home" / "tenant_registry.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(
        '{"tenants":[{"id":"slack:UALICE","status":"suspnded"}]}',
        encoding="utf-8",
    )

    out = asyncio.run(srv._handle_message(_Msg()))

    assert "policy is unavailable" in out


def test_active_tenant_without_per_user_is_refused_for_missing_channels(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_TENANT", "freeco")
    monkeypatch.setattr(server_mod, "tenant_by_user_enabled", lambda: False,
                        raising=False)
    import maverick.paths as paths_mod
    monkeypatch.setattr(paths_mod, "tenant_by_user_enabled", lambda: False)
    create_tenant("freeco", plan="free")

    srv = server_mod.Server(world=_World(), llm=object(), sandbox=object())
    out = asyncio.run(srv._handle_message(_Msg()))
    assert "plan does not include channel access" in out
