"""Task limits remain separate from aggregate, physical-attempt admission."""
from __future__ import annotations

import json
import math
import time

import pytest
from maverick.budget import budget_from_config
from maverick.quotas import record_usage
from maverick.sandbox import LocalBackend
from maverick.tenant import registry
from maverick.world_model import WorldModel


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    for env in ("MAVERICK_TENANT", "MAVERICK_ENFORCE_PLAN_CAPS",
                "MAVERICK_BUDGET_DOLLARS"):
        monkeypatch.delenv(env, raising=False)


def test_remaining_today_none_without_cap():
    assert registry.tenant_remaining_today(None) is None
    assert registry.tenant_remaining_today("ghost") is None   # unprovisioned
    registry.create_tenant(
        "acme", plan="free", max_daily_dollars=0
    )  # explicitly provisioned without a cap
    assert registry.tenant_remaining_today("acme") is None


def test_remaining_today_is_cap_minus_spend(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    registry.create_tenant("acme", plan="free")
    registry.set_quota("acme", 10.0)
    record_usage("user:local", 7.0, 0, 0)                     # acme ledger -> $7
    assert registry.tenant_remaining_today("acme") == pytest.approx(3.0)


def test_explicit_task_limit_remains_separate_from_tenant_remainder(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    registry.create_tenant("acme", plan="free")
    registry.set_quota("acme", 10.0)
    record_usage("user:local", 9.0, 0, 0)                     # $1 left today
    # Physical-call admission enforces the remaining $1. Setup preserves the
    # chosen task cap without reserving all of it.
    b = budget_from_config(max_dollars=5.0)
    assert b.max_dollars == pytest.approx(5.0)
    assert registry.tenant_remaining_today('acme') == 1


def test_budget_clamp_only_lowers(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    registry.create_tenant("acme", plan="free")
    registry.set_quota("acme", 100.0)
    record_usage("user:local", 1.0, 0, 0)                     # $99 left
    # A small per-run cap is NOT raised to the big tenant remainder.
    b = budget_from_config(max_dollars=2.0)
    assert b.max_dollars == pytest.approx(2.0)


def test_budget_unchanged_without_tenant():
    # No active tenant -> single-tenant default behavior is untouched.
    b = budget_from_config(max_dollars=5.0)
    assert b.max_dollars == pytest.approx(5.0)


def test_exhausted_tenant_refuses_start_without_rewriting_task_limit(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    registry.create_tenant("acme", plan="free")
    registry.set_quota("acme", 5.0)
    record_usage("user:local", 8.0, 0, 0)                     # over cap
    b = budget_from_config(max_dollars=5.0)
    assert b.max_dollars == 5.0
    assert 'over its daily spend cap' in b._tenant_refusal


def test_clamp_never_raises_an_unset_cap_above_the_default(monkeypatch):
    # No explicit max_dollars + a tenant with a LARGE remainder must NOT raise
    # the per-run cap above Budget's default -- the clamp only ever lowers.
    from maverick.budget import Budget
    default = Budget.__dataclass_fields__["max_dollars"].default
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    registry.create_tenant("acme", plan="free")
    registry.set_quota("acme", 1000.0)
    record_usage("user:local", 1.0, 0, 0)                     # remainder ~999
    b = budget_from_config()                                  # no max_dollars set
    assert b.max_dollars is default is None


# ---- per-tenant daily cap under concurrency ---------------------------------

def test_two_task_starts_do_not_preallocate_organization_funds(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    registry.create_tenant("acme", plan="free")
    registry.set_quota("acme", 10.0)
    b1 = budget_from_config(max_dollars=6.0)
    assert b1.max_dollars == pytest.approx(6.0)
    b2 = budget_from_config(max_dollars=6.0)
    assert b2.max_dollars == pytest.approx(6.0)
    assert registry.tenant_remaining_today('acme') == 10
    # Concurrency is enforced at physical dispatch, covered in
    # test_organization_provider_admission rather than arbitrary task allotments.


def test_expired_reservation_does_not_reduce_remaining():
    # A live in-flight hold reduces the remainder; once its TTL has lapsed it no
    # longer counts (the backstop that stops a crashed run from permanently
    # denting the cap -- remaining self-heals).
    registry.create_tenant("acme", plan="free")
    registry.set_quota("acme", 10.0)
    registry.reserve_tenant_dollars("acme", 3.0, 3600, "rid-live")
    assert registry.tenant_remaining_today("acme") == pytest.approx(7.0)
    # Force its expires_at into the past -> it is ignored, full cap available.
    path = registry._reservations_path("acme")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["rid-live"]["expires_at"] = time.time() - 1.0
    path.write_text(json.dumps(data), encoding="utf-8")
    assert registry.tenant_remaining_today("acme") == pytest.approx(10.0)


def test_record_usage_releases_reservation(monkeypatch):
    # record_usage clears this run's hold when it writes actual spend, so the
    # spend isn't double-counted against the cap for the rest of the TTL.
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    registry.create_tenant("acme", plan="free")
    registry.set_quota("acme", 10.0)
    registry.reserve_tenant_dollars("acme", 4.0, 3600, "rid-x")
    assert registry.tenant_remaining_today("acme") == pytest.approx(6.0)
    record_usage("user:local", 1.0, 0, 0, reservation_id="rid-x")
    # Only the $1 recorded spend now counts; the $4 hold is released.
    assert registry.tenant_remaining_today("acme") == pytest.approx(9.0)


def test_no_reservation_without_active_tenant(tmp_path):
    # Regression: the default single-tenant / no-cap path is untouched -- clamp
    # unchanged AND the reservation machinery stays inert (no hold, no file).
    b = budget_from_config(max_dollars=5.0)
    assert b.max_dollars == pytest.approx(5.0)
    assert not hasattr(b, "_tenant_reservation_id")
    home = tmp_path / ".maverick"
    assert not (home.exists() and list(home.rglob("reservations.json")))


def test_corrupt_legacy_reservations_refuse_start(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    registry.create_tenant("acme", max_daily_dollars=10.0)
    path = registry._reservations_path("acme")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"rid":{"dollars":NaN,"expires_at":9999999999}}', encoding="utf-8")
    budget = budget_from_config(max_dollars=5.0)
    assert budget.max_dollars == 5.0
    assert 'policy unavailable' in budget._tenant_refusal


@pytest.mark.parametrize("amount,ttl", [(math.nan, 60), (1, math.inf), (1, -1)])
def test_nonfinite_or_invalid_reservation_is_rejected(amount, ttl):
    with pytest.raises(ValueError):
        registry.reserve_tenant_dollars("acme", amount, ttl, "rid")


def _reserved_run_budget(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    registry.create_tenant("acme", plan="free")
    registry.set_quota("acme", 10.0)
    budget = budget_from_config(max_dollars=4.0)
    # Preserve release-on-every-exit qualification for an existing legacy hold.
    # Newly constructed budgets no longer reserve an entire task allowance.
    budget._tenant_reservation_id = 'legacy-run-fixture'
    registry.reserve_tenant_dollars('acme', 4, 3600, budget._tenant_reservation_id)
    assert registry.tenant_remaining_today("acme") == pytest.approx(6.0)
    return budget


@pytest.mark.asyncio
async def test_run_goal_halt_settles_tenant_reservation_once(
    monkeypatch, tmp_path, fake_llm,
):
    from maverick import killswitch, quotas
    from maverick.orchestrator import run_goal

    budget = _reserved_run_budget(monkeypatch)
    reservation_id = budget._tenant_reservation_id
    recorded = []
    real_record = quotas.record_usage

    def record_once(*args, **kwargs):
        recorded.append((args, kwargs))
        return real_record(*args, **kwargs)

    monkeypatch.setattr(quotas, "record_usage", record_once)
    monkeypatch.setattr(
        killswitch,
        "check",
        lambda **_kwargs: (_ for _ in ()).throw(
            killswitch.Halted("operator stop", "test")),
    )
    world = WorldModel(path=tmp_path / "world.db")
    goal_id = world.create_goal("halted run", "must not start")

    result = await run_goal(
        llm=fake_llm, world=world, budget=budget, goal_id=goal_id,
        sandbox=LocalBackend(workdir=tmp_path),
    )

    assert "Lightwork is halted" in result
    assert fake_llm.calls == []
    assert len(recorded) == 1
    assert recorded[0][1]["reservation_id"] == reservation_id
    assert registry.tenant_remaining_today("acme") == pytest.approx(10.0)


@pytest.mark.asyncio
async def test_run_goal_setup_exception_settles_tenant_reservation_once(
    monkeypatch, tmp_path, fake_llm,
):
    """Exceptions before the MCP cleanup try still settle the run reservation."""
    from maverick import quotas
    from maverick.orchestrator import run_goal

    budget = _reserved_run_budget(monkeypatch)
    reservation_id = budget._tenant_reservation_id
    recorded = []
    real_record = quotas.record_usage

    def record_once(*args, **kwargs):
        recorded.append((args, kwargs))
        return real_record(*args, **kwargs)

    monkeypatch.setattr(quotas, "record_usage", record_once)
    world = WorldModel(path=tmp_path / "world.db")
    goal_id = world.create_goal("setup failure", "must release its reservation")

    def fail_start_episode(_goal_id):
        raise RuntimeError("pre-main-try boom")

    monkeypatch.setattr(world, "start_episode", fail_start_episode)

    with pytest.raises(RuntimeError, match="^pre-main-try boom$"):
        await run_goal(
            llm=fake_llm, world=world, budget=budget, goal_id=goal_id,
            sandbox=LocalBackend(workdir=tmp_path),
        )

    assert fake_llm.calls == []
    assert len(recorded) == 1
    assert recorded[0][1]["reservation_id"] == reservation_id
    assert registry.tenant_remaining_today("acme") == pytest.approx(10.0)


@pytest.mark.asyncio
async def test_missing_goal_releases_tenant_reservation(
    monkeypatch, tmp_path, fake_llm,
):
    from maverick.orchestrator import run_goal

    budget = _reserved_run_budget(monkeypatch)
    world = WorldModel(path=tmp_path / "world.db")

    result = await run_goal(
        llm=fake_llm, world=world, budget=budget, goal_id=99999,
        sandbox=LocalBackend(workdir=tmp_path),
    )

    assert result == "no such goal: 99999"
    assert registry.tenant_remaining_today("acme") == pytest.approx(10.0)


@pytest.mark.asyncio
async def test_shield_preflight_refusal_releases_tenant_reservation(
    monkeypatch, tmp_path, fake_llm,
):
    from types import SimpleNamespace

    from maverick.orchestrator import run_goal

    class BlockingShield:
        def scan_input(self, _text):
            return SimpleNamespace(allowed=False, reasons=["blocked-test"])

    budget = _reserved_run_budget(monkeypatch)
    monkeypatch.setattr(
        "maverick.orchestrator._build_shield", lambda: BlockingShield())
    world = WorldModel(path=tmp_path / "world.db")
    goal_id = world.create_goal("blocked input", "must not start")

    result = await run_goal(
        llm=fake_llm, world=world, budget=budget, goal_id=goal_id,
        sandbox=LocalBackend(workdir=tmp_path),
    )

    assert "input rejected by Shield" in result
    assert fake_llm.calls == []
    assert registry.tenant_remaining_today("acme") == pytest.approx(10.0)
