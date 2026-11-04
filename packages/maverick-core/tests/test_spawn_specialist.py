"""spawn_specialist / list_specialists -- the bridge from the suite roster to the
running fleet. The orchestrator can look up a curated domain pack and deploy it as
a child via domain.agent_from_profile (persona + compartment + attenuated envelope),
under the same depth/budget/spawn-cap guards as spawn_subagent."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.domain import builtin_dir, enabled_domains, load_domains, suite_for
from maverick.quarantine import QuarantineRegistry
from maverick.tools.spawn import list_specialists_tool, spawn_specialist_tool


def _fake_parent(depth: int = 0, budget: Budget | None = None, cap=None):
    ctx = SimpleNamespace(
        budget=budget or Budget(max_dollars=10.0),
        blackboard=Blackboard(), max_depth=3, goal_id=1, quarantine=None,
        try_reserve_spawns=lambda n: True, release_spawns=lambda n: None,
    )
    return SimpleNamespace(depth=depth, name="orchestrator", role="orchestrator",
                           ctx=ctx, max_steps=17, capability=cap)


@pytest.mark.asyncio
async def test_list_specialists_summary_then_filter():
    summary = await list_specialists_tool().fn({})
    assert "suite=" in summary  # guides the model to filter
    # at least one real suite shows up with a count
    suites = {suite_for(n) for n in enabled_domains() if suite_for(n)}
    assert suites, "no suites discovered"
    a_suite = sorted(suites)[0]
    assert a_suite in summary
    # filtering by that suite lists its packs and points back at spawn_specialist
    listing = await list_specialists_tool().fn({"suite": a_suite})
    assert "spawn_specialist" in listing
    members = [n for n in enabled_domains() if suite_for(n) == a_suite]
    assert any(m in listing for m in members)


@pytest.mark.asyncio
async def test_list_specialists_unknown_filter_is_graceful():
    out = await list_specialists_tool().fn({"suite": "no_such_suite_zzz"})
    assert "No specialist domains" in out


@pytest.mark.asyncio
async def test_spawn_specialist_unknown_domain_errors():
    out = await spawn_specialist_tool(_fake_parent()).fn(
        {"domain": "does_not_exist_xyz", "task": "t"})
    assert "ERROR" in out and "list_specialists" in out


@pytest.mark.asyncio
async def test_fork_cannot_bypass_parent_suite_grant(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    (tmp_path / "client_fork.toml").write_text(
        'name = "client_fork"\nextends = "aero_avionics"\n', encoding="utf-8",
    )
    parent = _fake_parent()
    parent.ctx.allowed_suites = frozenset({"finance"})

    listing = await list_specialists_tool(parent).fn({"suite": "other"})
    assert "client_fork" not in listing
    result = await spawn_specialist_tool(parent).fn(
        {"domain": "client_fork", "task": "work"}
    )
    assert "outside your department grant" in result


@pytest.mark.asyncio
async def test_rejected_pack_has_plain_no_work_started_error(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    (tmp_path / "unsafe.toml").write_text(
        'name = "unsafe"\nallow_tools = []\nmax_risk = "low"\n',
        encoding="utf-8",
    )
    result = await spawn_specialist_tool(_fake_parent()).fn(
        {"domain": "unsafe", "task": "work"}
    )
    assert "setup needs review" in result
    assert "No work was started" in result


@pytest.mark.asyncio
async def test_spawn_specialist_respects_depth_cap():
    dom = sorted(enabled_domains())[0]
    parent = _fake_parent(depth=3)  # depth+1 > max_depth (3)
    out = await spawn_specialist_tool(parent).fn({"domain": dom, "task": "t"})
    assert "ERROR" in out and "max depth" in out


@pytest.mark.asyncio
async def test_spawn_specialist_respects_spawn_cap():
    dom = sorted(enabled_domains())[0]
    parent = _fake_parent()
    parent.ctx.try_reserve_spawns = lambda n: False  # cap hit
    parent.ctx.max_total_spawns = 64
    out = await spawn_specialist_tool(parent).fn({"domain": dom, "task": "t"})
    assert "ERROR" in out and "spawn cap" in out


@pytest.mark.asyncio
async def test_spawn_specialist_deploys_pack_and_inherits_max_steps(monkeypatch):
    dom = sorted(enabled_domains())[0]
    rec: dict = {}

    def fake_agent_from_profile(profile, ctx, task, *, parent=None, depth=0, principal=None):
        async def _run():
            return SimpleNamespace(final="SPECIALIST DONE", blocked_on_user=False, error=None)
        child = SimpleNamespace(role=profile.name, name=f"agent:{profile.name}-{depth}",
                                max_steps=None, run=_run)
        rec.update(profile=profile, task=task, parent=parent, depth=depth, child=child)
        return child

    async def _noop(*a, **k):
        return None

    monkeypatch.setattr("maverick.domain.agent_from_profile", fake_agent_from_profile)
    monkeypatch.setattr("maverick.hooks.emit", _noop)

    parent = _fake_parent(depth=0)
    out = await spawn_specialist_tool(parent).fn({"domain": dom, "task": "do it"})

    assert out == "SPECIALIST DONE"
    assert rec["profile"].name == dom          # looked up the real pack
    assert rec["depth"] == 1                    # spawned one level down
    assert rec["parent"] is parent              # under the orchestrator (attenuation)
    assert rec["child"].max_steps == 17         # inherited the parent's step budget


@pytest.mark.asyncio
async def test_spawn_specialist_withholds_already_sealed_domain_without_running(monkeypatch):
    dom = sorted(enabled_domains())[0]
    ran = False

    def fake_agent_from_profile(profile, ctx, task, *, parent=None, depth=0, principal=None):
        async def _run():
            nonlocal ran
            ran = True
            return SimpleNamespace(final="SHOULD NOT LEAK", blocked_on_user=False, error=None)

        child = SimpleNamespace(
            role=profile.name,
            name=f"agent:{profile.name}-{depth}",
            domain=profile.compartment,
            max_steps=None,
            run=_run,
        )
        return child

    # Containment is COMPARTMENT-scoped: a specialist registers under its pack's
    # compartment (profile.compartment), which may differ from the domain name
    # (e.g. domain 'aero_airworthiness' -> compartment 'aero_mro'). Seal the
    # sector the child actually lands in -- the same key the automatic escalation
    # path (maybe_seal_domain) uses -- not the bare domain name.
    compartment = load_domains(builtin_dir())[dom].compartment
    quarantine = QuarantineRegistry()
    quarantine.seal_domain(compartment, "prior compromise")
    parent = _fake_parent(depth=0)
    parent.ctx.quarantine = quarantine

    monkeypatch.setattr("maverick.domain.agent_from_profile", fake_agent_from_profile)

    out = await spawn_specialist_tool(parent).fn({"domain": dom, "task": "do it"})

    assert not ran
    assert "output is withheld" in out
    assert "SHOULD NOT LEAK" not in out
    assert quarantine.status()["agents_tracked"] == 1
