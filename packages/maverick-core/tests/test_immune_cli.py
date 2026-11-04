"""``maverick immune`` renders the kernel surface and fails loudly on bad evidence."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from maverick import config
from maverick.cli import main


def _run(*args):
    return CliRunner().invoke(main, ["immune", *args])


def test_network_on_a_graph_file(tmp_path):
    g = tmp_path / "g.json"
    g.write_text(json.dumps({"agents": {"r": ["knowledge_search"], "s": ["web_search"]},
                             "flows": [["r", "s"]]}))
    out = _run("network", "--graph", str(g))
    assert out.exit_code == 0, out.output
    assert "2 agents, 1 findings" in out.output and "r -> s" in out.output
    rows = json.loads(_run("network", "--graph", str(g), "--json").output)
    assert rows[0]["kind"] == "exfiltration"


def test_network_what_if_output_matches_the_deployment_dials_and_leaves_them_alone(monkeypatch):
    """``--levels/--grounding`` print exactly what the roster shows when the
    deployment itself is set that way, and write nothing to the environment."""
    import os

    from maverick import domain
    from maverick.immune import network as n
    aero = {k: v for k, v in domain.available_domains().items() if k.startswith("aero_")}
    monkeypatch.setattr(domain, "available_domains", lambda: aero)
    monkeypatch.delenv("MAVERICK_WORKFORCE_LEVELS", raising=False)
    monkeypatch.delenv("MAVERICK_WORKFORCE_DATA_GROUNDING", raising=False)
    what_if_text = _run("network", "--levels", "--no-grounding", "--swarm").output
    what_if_json = _run("network", "--levels", "--no-grounding", "--swarm", "--json").output
    assert "MAVERICK_WORKFORCE_LEVELS" not in os.environ
    assert "MAVERICK_WORKFORCE_DATA_GROUNDING" not in os.environ
    # The same roster read with the deployment's own dials set that way.
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "1")
    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "0")
    assert _run("network", "--swarm").output == what_if_text
    assert _run("network", "--swarm", "--json").output == what_if_json
    assert json.loads(what_if_json) == json.loads(json.dumps(
        [f.__dict__ for f in n.findings(n.roster_graph(swarm=True))], default=list))
    assert "agents," in what_if_text and "findings" in what_if_text


def test_title_check_seal_verify_roundtrip(tmp_path):
    d = {"problem": {"statement": "x", "signed_off_by": "h"}, "inputs": [], "priority": [],
         "gates": [{"id": "g", "human": "h", "decision": "framed", "elements": ["e"], "at": 1}],
         "claims": [{"id": "c", "elements": ["e"]}],
         "verification": [{"checker": "lean", "passed": True}], "coverage": {"examined": 1, "total": 1}}
    src, sealed = tmp_path / "d.json", tmp_path / "s.json"
    src.write_text(json.dumps(d))
    assert _run("title", "check", str(src)).exit_code == 0
    assert _run("title", "seal", str(src), "-o", str(sealed)).exit_code == 0
    assert "verifies" in _run("title", "verify", str(sealed)).output
    doc = json.loads(sealed.read_text())
    doc["dossier"]["claims"][0]["elements"].append("unconceived")
    sealed.write_text(json.dumps(doc))
    assert _run("title", "verify", str(sealed)).exit_code != 0
    d["claims"][0]["elements"].append("unconceived")
    src.write_text(json.dumps(d))
    bad = _run("title", "check", str(src))
    assert bad.exit_code == 1 and "unconceived" in bad.output


def test_rules_reports_contradictions_and_replays(tmp_path):
    rules, cand, events = (tmp_path / n for n in ("r.json", "c.json", "e.json"))
    rules.write_text(json.dumps({"rules": [
        {"id": "a", "action": "pay", "modality": "forbid", "when": {"new": True}},
        {"id": "b", "action": "pay", "modality": "require", "when": {}}]}))
    cand.write_text(json.dumps({"rules": [{"id": "c", "action": "pay", "modality": "forbid", "when": {}}]}))
    events.write_text(json.dumps({"events": [{"action": "pay", "incident": True}]}))
    out = _run("rules", str(rules), "--candidate", str(cand), "--events", str(events))
    assert out.exit_code == 0, out.output
    assert "a forbids what b requires" in out.output and '"promote": true' in out.output


def test_canary_refused_until_enabled(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "w.db")
    monkeypatch.setattr(config, "get_immune", lambda: {"canaries": False})
    out = _run("canary", "--action", "a", "--detail", "d", "--class", "c", "--flaw", "f")
    assert out.exit_code != 0 and "canaries are off" in out.output


def test_twin_replay_list_and_awareness(tmp_path, monkeypatch):
    import asyncio

    import maverick.cli as cli_mod
    import maverick.cli._immune_groups as groups
    import maverick.runner as runner
    from maverick.immune import twin
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(config, "get_immune", lambda: {"canaries": False, "twin_record": True})
    db = tmp_path / "w.db"
    world = WorldModel(db)
    gid = world.create_goal("close the books", "")

    async def live(tool, args):
        return "rows=12"
    asyncio.run(_d(twin, gid, "sql_query", {"q": "gl"}, live))
    world.close()

    monkeypatch.setattr(cli_mod, "_require_llm_key", lambda *a, **k: "k")
    monkeypatch.setattr(groups, "open_world", lambda *a, **k: WorldModel(db))
    seen = []

    def fake_run(goal_id, max_dollars=None):
        async def agent():  # stands in for the swarm's tool call
            async def never(tool, args):
                raise AssertionError("a twin must not execute tools")
            return await _d(twin, goal_id, "sql_query", {"q": "gl"}, never)
        seen.append(asyncio.run(agent()))
        return "done"
    monkeypatch.setattr(runner, "run_goal_in_thread", fake_run)

    out = _run("twin", "replay", str(gid), "--max-dollars", "0.5")
    assert out.exit_code == 0, out.output
    assert seen == ["rows=12"] and json.loads(out.output)["served"] == 1
    assert "served 1/1, approximate 0, unmatched 0" in _run("twin", "list").output
    assert _run("twin", "replay", "999").exit_code != 0

    s = tmp_path / "s.json"
    s.write_text(json.dumps({"watched": [False] * 40, "unwatched": [True] * 20 + [False] * 20}))
    gap = json.loads(_run("awareness", str(s)).output)
    assert gap["significant"] and gap["gap"] == 0.5


def _d(twin, goal_id, tool, args, run):
    return twin.dispatch(goal_id, tool, args, lambda: run(tool, args))


def test_canary_auto_prints_ids_but_never_the_flaw(tmp_path, monkeypatch):
    import maverick.cli._immune_groups as groups
    from maverick.immune import oversight
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setattr(config, "get_immune", lambda: {"canaries": True, "twin_record": False})
    db = tmp_path / "w.db"
    import time

    from maverick.approval_cards import build_approval_card, encode_approval_detail
    summary = "Pay $1,200.00 to ops@acme.com"
    WorldModel(db).create_approval("stripe_payout", detail=encode_approval_detail(
        build_approval_card(
            action="stripe_payout", summary=summary, target_label="acme", target={},
            parameters={}, parameter_summary=[summary], actor="agent:ap", workspace="default",
            role="operator", authority_versions={}, input_versions={}, credential_versions={},
            budget={}, expires_at=time.time() + 600, known_effects=["Moves money."],
            unresolved_assumptions=[], before="Unpaid.", after="Paid.", irreversible=True)))
    monkeypatch.setattr(groups, "open_world", lambda *a, **k: WorldModel(db))
    out = _run("canary-auto", "--count", "2")
    assert out.exit_code == 0, out.output
    assert out.output.count("seeded canary approval #") == 2
    assert "inflated" not in out.output and "lookalike" not in out.output
    assert len(oversight.canary_ids()) == 2
    assert _run("canary-auto", "--class", "wire").exit_code != 0


def test_awareness_requires_exactly_one_source():
    assert _run("awareness").exit_code != 0


def test_malformed_inputs_are_clean_errors_not_tracebacks(tmp_path):
    bad = tmp_path / "list.json"
    bad.write_text("[1, 2]")
    empty = tmp_path / "empty.json"
    empty.write_text("{}")
    sealed = tmp_path / "sealed.json"
    sealed.write_text(json.dumps({"dossier": {}}))
    for args in (("title", "check", str(bad)), ("title", "check", str(empty)),
                 ("title", "verify", str(sealed)),
                 ("title", "research", str(empty), str(bad), "-o", str(tmp_path / "o.json")),
                 ("awareness", "--goals", ",")):
        out = _run(*args)
        assert out.exit_code != 0 and not isinstance(out.exception, (KeyError, TypeError,
                                                                     AttributeError,
                                                                     ZeroDivisionError)), (
            args, out.output, out.exception)


def test_oversight_report_strips_terminal_control_from_the_class(tmp_path, monkeypatch):
    import maverick.cli._immune_groups as groups
    from maverick.immune import oversight
    monkeypatch.setattr(oversight, "score", lambda world, kind="canary": {
        ("alice", "pay\rments"): oversight.Stats(caught=1)})
    monkeypatch.setattr(groups, "open_world", lambda *a, **k: None)
    out = _run("oversight")
    assert out.exit_code == 0 and "\r" not in out.output


def test_twin_forget_deletes_a_recording(tmp_path, monkeypatch):
    import asyncio

    from maverick.immune import twin
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(config, "get_immune", lambda: {"canaries": False, "twin_record": True})

    async def live():
        return "out"
    asyncio.run(twin.dispatch(9, "web_search", {"q": "x"}, live))
    assert twin.load(9)
    assert "deleted" in _run("twin", "forget", "9").output
    assert twin.load(9) == [] and "not found" in _run("twin", "forget", "9").output


def test_a_pack_with_no_allowlist_can_call_every_tool(monkeypatch):
    from maverick import domain
    from maverick.capability import Capability
    from maverick.immune import network as n
    monkeypatch.setattr(domain, "domain_capability", lambda *a, **k: Capability(principal="agent:custom"))
    tools = n.runtime_tools(type("P", (), {"name": "custom"})())
    assert {"read_file", "email", "http_fetch"} <= tools


@pytest.mark.parametrize(("flags", "held"), [((), True), (("--acts-at-once",), False)])
def test_the_canary_command_matches_the_undo_of_the_request_it_imitates(tmp_path, monkeypatch, flags, held):
    from maverick import config, world_model
    from maverick.channel_approvals import held_for_undo

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "w.db")
    monkeypatch.setattr(config, "get_immune", lambda: {"canaries": True})
    world = world_model.WorldModel(tmp_path / "w.db")
    import maverick.cli._immune_groups as groups
    monkeypatch.setattr(groups, "open_world", lambda *a, **k: world)
    out = _run("canary", "--action", "a", "--detail", "d", "--class", "c", "--flaw", "f", *flags)
    assert out.exit_code == 0, out.output
    assert held_for_undo(world.pending_approvals()[0]) is held
