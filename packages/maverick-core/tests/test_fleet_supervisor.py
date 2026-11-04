"""Supervisor binding (Layer C): governed fleet runs + oversight status.

`capability_for_role` narrows a grant by an RBAC role; the runner threads a
`capability` into the SwarmContext so the root agent runs least-privileged;
`fleet run` creates a goal + run-index entry under the agent principal; and
`fleet status` lists those runs with their live status + governance denials.

Offline (no live LLM): the actual swarm run is monkeypatched out.
"""
from __future__ import annotations

import json

from click.testing import CliRunner


def _cfg(monkeypatch, cfg):
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: cfg)


# --- capability_for_role ---------------------------------------------------

def test_capability_for_role_narrows_by_role(monkeypatch):
    _cfg(monkeypatch, {"roles": {"analyst": {"allow_tools": ["read_file", "search"]}}})
    from maverick.capability import capability_for_role
    cap = capability_for_role("analyst", principal="agent:acme.bob")
    assert cap.principal == "agent:acme.bob"
    assert cap.permits("read_file") is True
    assert cap.permits("shell") is False  # not in the role's allow-list


def test_capability_for_role_cannot_escalate_past_acl(monkeypatch):
    # [security] denies shell; a role "allowing" shell still can't grant it.
    _cfg(monkeypatch, {
        "security": {"denied_tools": ["shell"]},
        "roles": {"power": {"allow_tools": ["shell", "read_file"]}},
    })
    from maverick.capability import capability_for_role
    cap = capability_for_role("power", principal="agent:acme.p")
    assert cap.permits("shell") is False
    assert cap.permits("read_file") is True


def test_capability_for_role_unknown_role_is_rejected(monkeypatch):
    _cfg(monkeypatch, {"roles": {"analyst": {"allow_tools": ["read_file"]}}})
    import pytest
    from maverick.capability import UnknownRoleError, capability_for_role

    with pytest.raises(UnknownRoleError, match="undefined RBAC role"):
        capability_for_role("ghost", principal="agent:acme.g")


def test_capability_for_role_empty_role_is_rejected(monkeypatch):
    _cfg(monkeypatch, {"roles": {"analyst": {"allow_tools": ["read_file"]}}})
    import pytest
    from maverick.capability import UnknownRoleError, capability_for_role

    with pytest.raises(UnknownRoleError, match="undefined RBAC role"):
        capability_for_role("", principal="agent:acme.g")


def test_capability_for_role_default_principal(monkeypatch):
    _cfg(monkeypatch, {"roles": {"analyst": {"allow_tools": ["read_file"]}}})
    from maverick.capability import capability_for_role
    assert capability_for_role("analyst").principal == "agent"


# --- runner threads capability into the SwarmContext -----------------------

def test_run_goal_in_thread_threads_capability_into_ctx(monkeypatch, tmp_path):
    """The capability handed to the runner reaches SwarmContext.capability,
    so the root agent runs least-privileged under it (no real LLM runs)."""
    from maverick import budget as budget_mod
    from maverick import llm as llm_mod
    from maverick import orchestrator, runner, world_model
    from maverick import sandbox as sandbox_mod
    from maverick.capability import Capability
    from maverick.swarm import SwarmContext

    captured: dict = {}

    db = tmp_path / "world.db"
    world = world_model.WorldModel(db)
    goal_id = world.create_goal("fixture task", owner="agent:acme.bob", execution_principal="agent:acme.bob")
    world.close()

    def fake_run_goal_sync(*args, **kwargs):
        args[1].set_goal_status(args[3], "done")
        # Build the ctx exactly as run_goal would and assert the seam carries
        # the capability through. Keeps the test offline (no agent.run()).
        ctx = SwarmContext(
            llm=kwargs.get("llm") or args[0],
            world=args[1],
            budget=args[2],
            blackboard=object(),
            sandbox=object(),
            goal_id=kwargs["goal_id"] if "goal_id" in kwargs else args[3],
            capability=kwargs.get("capability"),
            user_id=kwargs.get("user_id"),
        )
        captured["cap"] = ctx.capability
        captured["user_id"] = ctx.user_id
        return "DONE."

    monkeypatch.setattr(world_model, "open_world", lambda *a, **k: world_model.WorldModel(db))
    monkeypatch.setattr(llm_mod, "LLM", lambda: object())
    monkeypatch.setattr(sandbox_mod, "build_sandbox", lambda: object())
    monkeypatch.setattr(budget_mod, "budget_from_config", lambda **_kwargs: budget_mod.Budget())
    monkeypatch.setattr(orchestrator, "run_goal_sync", fake_run_goal_sync)

    cap = Capability(principal="agent:acme.bob", allow_tools=frozenset({"read_file"}))
    status = runner.run_goal_in_thread(goal_id, capability=cap, user_id="agent:acme.bob")
    assert status == "done"
    assert captured["cap"] is cap
    assert captured["cap"].principal == "agent:acme.bob"
    assert captured["user_id"] == "agent:acme.bob"



def test_run_goal_in_thread_closes_sandbox(monkeypatch, tmp_path):
    from maverick import budget as budget_mod
    from maverick import llm as llm_mod
    from maverick import orchestrator, runner, world_model
    from maverick import sandbox as sandbox_mod

    closed = {"sandbox": False, "world": False}
    completed = []

    db = tmp_path / "world.db"
    world = world_model.WorldModel(db)
    goal_id = world.create_goal("fixture task", owner="user:local", execution_principal="user:local")
    world.close()

    class FakeSandbox:
        def close(self):
            closed["sandbox"] = True

    monkeypatch.setattr(world_model, "open_world", lambda *a, **k: world_model.WorldModel(db))
    monkeypatch.setattr(llm_mod, "LLM", lambda: object())
    monkeypatch.setattr(sandbox_mod, "build_sandbox", lambda: FakeSandbox())
    monkeypatch.setattr(budget_mod, "budget_from_config", lambda **_kwargs: budget_mod.Budget())
    def complete(_llm, world, _budget, goal_id, **_kwargs):
        world.set_goal_status(goal_id, "done")
        completed.append(True)

    def close_world(world):
        world.close()
        closed["world"] = True

    monkeypatch.setattr(world_model, "close_world_if_owned", close_world)
    monkeypatch.setattr(orchestrator, "run_goal_sync", complete)

    assert runner.run_goal_in_thread(goal_id) == "done"
    assert closed == {"sandbox": True, "world": True}

def test_run_goal_in_thread_default_capability_is_none(monkeypatch, tmp_path):
    """Default None == zero behaviour change: no capability reaches the run."""
    from maverick import budget as budget_mod
    from maverick import llm as llm_mod
    from maverick import orchestrator, runner, world_model
    from maverick import sandbox as sandbox_mod

    captured: dict = {}

    db = tmp_path / "world.db"
    world = world_model.WorldModel(db)
    goal_id = world.create_goal("fixture task", owner="user:local", execution_principal="user:local")
    world.close()

    def fake_run_goal_sync(*args, **kwargs):
        args[1].set_goal_status(args[3], "done")
        captured["cap"] = kwargs.get("capability", "MISSING")
        return "DONE."

    monkeypatch.setattr(world_model, "open_world", lambda *a, **k: world_model.WorldModel(db))
    monkeypatch.setattr(llm_mod, "LLM", lambda: object())
    monkeypatch.setattr(sandbox_mod, "build_sandbox", lambda: object())
    monkeypatch.setattr(budget_mod, "budget_from_config", lambda **_kwargs: budget_mod.Budget())
    monkeypatch.setattr(orchestrator, "run_goal_sync", fake_run_goal_sync)

    runner.run_goal_in_thread(goal_id)
    assert captured["cap"] is None


# --- fleet run -------------------------------------------------------------

def _make_fleet(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    _cfg(monkeypatch, {
        "roles": {
            "analyst": {"allow_tools": ["read_file", "search"]},
            "engineer": {"allow_tools": ["read_file", "write_file"]},
        },
    })
    from maverick.fleet import Fleet, FleetAgent, save_fleet
    save_fleet(Fleet(name="acme", owner="user:alice", agents=(
        FleetAgent("researcher", "analyst"),
        FleetAgent("coder", "engineer"),
    )))


def test_fleet_run_creates_goal_and_run_index(monkeypatch, tmp_path):
    _make_fleet(monkeypatch, tmp_path)
    db = tmp_path / "world.db"

    seen: dict = {}

    def fake_run(goal_id, *a, **k):
        seen["goal_id"] = goal_id
        seen["capability"] = k.get("capability")
        seen["user_id"] = k.get("user_id")
        return "done"

    monkeypatch.setattr("maverick.runner.run_goal_in_thread", fake_run)

    from maverick.cli import main
    res = CliRunner().invoke(main, [
        "--db", str(db), "fleet", "run", "acme", "researcher",
        "Summarize the Q3 report",
    ])
    assert res.exit_code == 0, res.output
    assert "agent:acme.researcher" in res.output
    assert "done" in res.output

    # The run was bound to the agent's principal + its role capability.
    assert seen["user_id"] == "agent:acme.researcher"
    assert seen["capability"].principal == "agent:acme.researcher"

    # A goal was created from the prompt...
    from maverick.world_model import open_world
    w = open_world(db)
    try:
        g = w.get_goal(seen["goal_id"])
    finally:
        w.close()
    assert g is not None and g.title == "Summarize the Q3 report"
    assert g.owner == "user:alice"
    assert g.execution_principal == "agent:acme.researcher"

    # ...and recorded in the per-fleet run index, under the agent.
    from maverick.file_lock import private_path_is_restricted
    from maverick.fleet import load_runs, runs_path
    runs = load_runs("acme")
    assert len(runs) == 1
    assert runs[0]["agent"] == "researcher"
    assert runs[0]["goal_id"] == seen["goal_id"]
    assert private_path_is_restricted(runs_path("acme"), 0o600)


def test_fleet_run_rejects_undefined_role(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    _cfg(monkeypatch, {"roles": {"analyst": {"allow_tools": ["read_file"]}}})

    from maverick.fleet import Fleet, FleetAgent, save_fleet
    save_fleet(Fleet(name="acme", owner="user:alice", agents=(
        FleetAgent("ghost", "ghost"),
    )))

    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True
        return "done"

    monkeypatch.setattr("maverick.runner.run_goal_in_thread", fake_run)

    from maverick.cli import main
    res = CliRunner().invoke(main, [
        "--db", str(tmp_path / "w.db"), "fleet", "run", "acme", "ghost", "do it",
    ])
    assert res.exit_code == 2
    assert "undefined RBAC role" in res.output
    assert called is False


def test_fleet_create_rejects_undefined_role(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _cfg(monkeypatch, {"roles": {"analyst": {"allow_tools": ["read_file"]}}})

    from maverick.cli import main
    res = CliRunner().invoke(main, [
        "fleet", "create", "acme", "--owner", "user:alice",
        "--agent", "ghost:ghost",
    ])
    assert res.exit_code == 2
    assert "undefined RBAC role" in res.output


def test_fleet_run_missing_fleet(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.cli import main
    res = CliRunner().invoke(main, [
        "--db", str(tmp_path / "w.db"), "fleet", "run", "ghost", "a", "do it",
    ])
    assert res.exit_code == 1
    assert "no such fleet" in res.output


def test_fleet_run_missing_agent(monkeypatch, tmp_path):
    _make_fleet(monkeypatch, tmp_path)
    monkeypatch.setattr("maverick.runner.run_goal_in_thread",
                        lambda *a, **k: "done")
    from maverick.cli import main
    res = CliRunner().invoke(main, [
        "--db", str(tmp_path / "w.db"), "fleet", "run", "acme", "nobody", "do it",
    ])
    assert res.exit_code == 1
    assert "no such agent" in res.output


# --- fleet status ----------------------------------------------------------

def test_fleet_status_lists_runs_and_denials(monkeypatch, tmp_path):
    _make_fleet(monkeypatch, tmp_path)
    db = tmp_path / "world.db"

    # Two recorded runs for the researcher, with real goals in the world DB.
    from maverick.fleet import record_run
    from maverick.world_model import open_world
    w = open_world(db)
    try:
        g1 = w.create_goal("first task")
        g2 = w.create_goal("second task")
        w.set_goal_status(g1, "done")
        w.set_goal_status(g2, "blocked")
    finally:
        w.close()
    record_run("acme", "researcher", g1)
    record_run("acme", "researcher", g2)

    # One policy denial recorded against the researcher's principal (the tool
    # chokepoint records capability_denied; the status view counts it).
    from maverick.audit import EventKind, record
    record(EventKind.CAPABILITY_DENIED, agent="researcher", goal_id=g1,
           principal="agent:acme.researcher", tool="shell")

    from maverick.cli import main
    res = CliRunner().invoke(main, ["--db", str(db), "fleet", "status", "acme"])
    assert res.exit_code == 0, res.output
    assert f"goal #{g1}: done" in res.output
    assert f"goal #{g2}: blocked" in res.output
    assert "denied=1" in res.output  # researcher's denial counted
    assert "coder" in res.output and "(no runs)" in res.output  # idle agent shown


def test_fleet_status_json(monkeypatch, tmp_path):
    _make_fleet(monkeypatch, tmp_path)
    db = tmp_path / "world.db"
    from maverick.fleet import record_run
    from maverick.world_model import open_world
    w = open_world(db)
    try:
        gid = w.create_goal("task")
        w.set_goal_status(gid, "done")
    finally:
        w.close()
    record_run("acme", "coder", gid)

    from maverick.cli import main
    res = CliRunner().invoke(main, [
        "--db", str(db), "fleet", "status", "acme", "--json",
    ])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data["fleet"] == "acme"
    coder = next(a for a in data["agents"] if a["agent"] == "coder")
    assert coder["principal"] == "agent:acme.coder"
    assert coder["runs"][0]["goal_id"] == gid
    assert coder["runs"][0]["status"] == "done"


def test_fleet_status_missing_fleet(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.cli import main
    res = CliRunner().invoke(main, [
        "--db", str(tmp_path / "w.db"), "fleet", "status", "ghost",
    ])
    assert res.exit_code == 1
    assert "no such fleet" in res.output
