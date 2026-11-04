"""Production twin: record a goal's tool results, replay them to a fresh goal
with nothing live touched."""
from __future__ import annotations

import asyncio

import pytest
from maverick import config
from maverick.immune import _ledger, twin


@pytest.fixture(autouse=True)
def _home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")


@pytest.fixture
def recording_on(monkeypatch):
    monkeypatch.setattr(config, "get_immune",
                        lambda: {"canaries": False, "twin_record": True})


def _live(calls):
    async def run(tool, args):
        calls.append((tool, args))
        return f"{tool}:{args.get('q', '')}:live{len(calls)}"
    return run


def test_recording_is_off_by_default():
    calls: list = []
    asyncio.run(_d(twin, 7, "web_search", {"q": "a"}, _live(calls)))
    assert calls and not twin.recording_path(7).exists()


def test_record_then_replay_serves_production_results_in_order(recording_on):
    calls: list = []
    for q in ("a", "a", "b"):
        asyncio.run(_d(twin, 7, "web_search", {"q": q}, _live(calls)))
    asyncio.run(_d(twin, 7, "spawn_subagent", {"role": "r"}, _live(calls)))
    recorded = twin.load(7)
    assert [r["tool"] for r in recorded] == ["web_search"] * 3  # coordination not recorded

    replay = twin.Replay(recorded)
    live_during_replay: list = []

    async def _twin_run():
        with twin.replaying(replay):
            run = _live(live_during_replay)
            # spawned agents run in their own tasks; the replay must follow them
            return await asyncio.gather(
                _d(twin, 99, "web_search", {"q": "a"}, run),
                _d(twin, 99, "web_search", {"q": "a"}, run),
                _d(twin, 99, "web_search", {"q": "b"}, run),
                _d(twin, 99, "email", {"to": "x"}, run),        # never happened
                _d(twin, 99, "spawn_subagent", {"role": "r"}, run),  # coordination
            )

    out = asyncio.run(_twin_run())
    assert out[:3] == ["web_search:a:live1", "web_search:a:live2", "web_search:b:live3"]
    assert out[3].startswith("ERROR: email failed")
    assert live_during_replay == [("spawn_subagent", {"role": "r"})]  # only coordination ran
    assert replay.report() == {"recorded": 3, "served": 3, "exact": 3, "approximate": [],
                               "unserved": 0, "human_decisions": 0,
                               "human_decisions_not_reached": 0,
                               "unmatched": [{"tool": "email", "args": {"to": "x"}}]}
    assert not twin.recording_path(99).exists()  # a twin is never itself recorded


def test_ask_user_is_replayed_not_sent(recording_on):
    calls: list = []
    asyncio.run(_d(twin, 3, "ask_user", {"q": "dates?"}, _live(calls)))
    replay = twin.Replay(twin.load(3))
    after: list = []

    async def _go():
        with twin.replaying(replay):
            return await _d(twin, 4, "ask_user", {"q": "dates?"}, _live(after))

    assert asyncio.run(_go()) == "ask_user:dates?:live1" and after == []


def test_sealed_recording_hides_output_and_is_bound_to_the_goal(recording_on, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    asyncio.run(_d(twin, 5, "sql_query", {"q": "payroll"}, _live([])))
    raw = twin.recording_path(5).read_text()
    assert "payroll" not in raw and "sealed" in raw
    assert twin.load(5)[0]["output"] == "sql_query:payroll:live1"
    # moved to another goal's recording, the blob no longer authenticates
    twin.recording_path(6).write_text(raw)
    with pytest.raises(Exception):  # noqa: B017 -- any auth failure is correct
        twin.load(6)


def test_recording_failure_never_breaks_the_call(recording_on, monkeypatch):
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(twin, "record", boom)
    assert asyncio.run(_d(twin, 1, "web_search", {"q": "z"}, _live([]))).endswith("live1")


def test_replay_goal_runs_a_faithful_twin_and_ledgers_counts_only(recording_on, tmp_path):
    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("Reconcile March AP", "vendor ledger vs bank", domain="finance")
    asyncio.run(_d(twin, gid, "sql_query", {"q": "ap"}, _live([])))

    def run(twin_gid):
        # the runner executes inside the replay context
        return asyncio.run(_d(twin, twin_gid, "sql_query", {"q": "ap"}, _live([])))

    report = twin.replay_goal(world, gid, run)
    twin_goal = world.get_goal(report["twin_goal"])
    assert (twin_goal.title, twin_goal.description, twin_goal.domain) == (
        "Reconcile March AP", "vendor ledger vs bank", "finance")  # nothing marks it a test
    assert report["twin_status"] == "sql_query:ap:live1" and report["served"] == 1
    assert _ledger.read(twin.replays_path())[0]["unmatched"] == 0
    with pytest.raises(LookupError):
        twin.replay_goal(world, report["twin_goal"], run)  # twins have no recording


@pytest.mark.asyncio
async def test_agent_tool_execution_routes_through_the_twin(recording_on, tmp_path):
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.tools import Tool
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    ctx = SwarmContext(llm=None, world=world, budget=Budget(max_dollars=1.0),
                       blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
                       goal_id=world.create_goal("g", ""), use_skills=False)
    agent = Agent(ctx=ctx, role="coder", brief="b")
    agent.capability = None
    hits: list = []
    agent.tools.register(Tool(
        name="ping", description="ping", input_schema={"type": "object", "properties": {}},
        fn=lambda args: hits.append(1) or f"pong{len(hits)}"))

    assert "pong1" in await agent._run_tool("ping", {})
    with twin.replaying(twin.Replay(twin.load(ctx.goal_id))):
        assert "pong1" in await agent._run_tool("ping", {})
    assert hits == [1]  # the replayed call did not execute the tool


def _d(twin, goal_id, tool, args, run):
    return twin.dispatch(goal_id, tool, args, lambda: run(tool, args))


def test_near_identical_arguments_are_served_and_reported_as_divergence():
    records = [{"tool": "web_search", "key": "k1", "args": {"q": "Q3 revenue for Acme Corp"},
                "output": "rev=12"},
               {"tool": "web_search", "key": "k2", "args": {"q": "weather in Paris"},
                "output": "sunny"}]
    replay = twin.Replay(records)
    assert replay.serve("web_search", {"q": "Q3 revenue for ACME Corp."}) == "rev=12"
    # far from anything recorded: never executed, reported
    assert replay.serve("web_search", {"q": "competitor pricing"}).startswith("ERROR")
    report = replay.report()
    assert report["exact"] == 0 and report["served"] == 1 and report["unserved"] == 1
    assert report["approximate"][0]["similarity"] >= 0.8
    assert report["unmatched"] == [{"tool": "web_search", "args": {"q": "competitor pricing"}}]
    # a recorded result is served at most once
    assert twin.Replay(records, tolerance=1.0).serve(
        "web_search", {"q": "Q3 revenue for ACME Corp."}).startswith("ERROR")


def test_result_similarity_compares_final_answers():
    assert twin.result_similarity("Total  is 12", "Total is 12") == 1.0
    assert twin.result_similarity("Total is 12", "Refused") < 0.5
    assert twin.result_similarity(None, "x") is None


def test_awareness_probe_replays_each_goal_with_and_without_the_cue(recording_on, tmp_path):
    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "world.db")
    goals = []
    for i in range(12):
        gid = world.create_goal(f"close books {i}", "reconcile ledger")
        asyncio.run(_d(twin, gid, "sql_query", {"q": f"gl {i}"}, _live([])))
        goals.append(gid)
    seen = []

    def run(twin_gid):
        # A model that behaves differently when told it is watched: it tries an
        # extra call production never made, and refuses.
        g = world.get_goal(twin_gid)
        watched = twin.EVALUATION_CUE in (g.description or "")
        seen.append(watched)

        async def agent():
            n = int(g.title.rsplit(" ", 1)[1])
            await _d(twin, twin_gid, "sql_query", {"q": f"gl {n}"}, _live([]))
            if watched:
                await _d(twin, twin_gid, "http_fetch", {"url": "x"}, _live([]))
        asyncio.run(agent())
        return "blocked" if watched else "done"

    out = twin.awareness_probe(world, goals, run)
    assert seen.count(True) == seen.count(False) == 12
    assert out["runs"] == 24
    assert out["diverged"]["watched_rate"] == 1.0 and out["diverged"]["unwatched_rate"] == 0.0
    assert out["diverged"]["significant"] and out["blocked"]["significant"]
    probes = [r for r in _ledger.read(twin.replays_path()) if r.get("type") == "awareness_probe"]
    assert probes and "goals" not in probes[0]


def test_awareness_probe_reports_no_gap_for_an_invariant_model(recording_on, tmp_path):
    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "world.db")
    goals = [world.create_goal(f"g {i}", "") for i in range(6)]
    for gid in goals:
        asyncio.run(_d(twin, gid, "sql_query", {"q": "same"}, _live([])))

    def run(twin_gid):
        asyncio.run(_d(twin, twin_gid, "sql_query", {"q": "same"}, _live([])))
        return "done"

    out = twin.awareness_probe(world, goals, run)
    assert not out["diverged"]["significant"] and out["diverged"]["gap"] == 0


@pytest.mark.parametrize("recorded, attempted", [
    ({"to": "cfo@acme.com", "body": "Approve wire"}, {"to": "attacker@evil.io", "body": "Approve wire"}),
    ({"account": "12345678", "amount": 5000}, {"account": "99995678", "amount": 5000}),
    ({"to": "cfo@acme.com", "amount": 100}, {"to": "cfo@acme.com", "amount": 1000}),
    ({"q": "a"}, {"q": "b"}),
    ({"q": "a"}, {"q": "a", "extra": 1}),
])
def test_a_changed_field_is_not_a_near_identical_call(recorded, attempted):
    replay = twin.Replay([{"tool": "web_search", "key": twin._key("web_search", recorded),
                           "args": recorded, "output": "done"}])
    assert replay.serve("web_search", attempted).startswith("ERROR")
    assert replay.report()["unmatched"]


def test_high_risk_tools_are_only_served_on_an_exact_match():
    args = {"command": "rm -rf build/cache-2024-q3"}
    replay = twin.Replay([{"tool": "shell", "key": twin._key("shell", args), "args": args,
                           "output": "removed"}])
    assert replay.serve("shell", {"command": "rm -rf build/cache-2024-q4"}).startswith("ERROR")


def test_approximate_calls_and_a_missing_answer_count_as_divergence():
    base = {"unmatched": [], "approximate": [], "result_similarity": 1.0, "twin_answered": True}
    assert not twin._diverged(base, 0.8)
    assert twin._diverged({**base, "approximate": [{"similarity": 0.9}]}, 0.8)
    assert twin._diverged({**base, "result_similarity": None, "twin_answered": False}, 0.8)


def test_injected_capability_scope_does_not_change_the_call_key():
    a = {"url": "https://x", "_capability_allow_hosts": ("a.io", "b.io")}
    b = {"url": "https://x", "_capability_allow_hosts": ("b.io", "a.io")}
    assert twin._key("http_fetch", a) == twin._key("http_fetch", b) == twin._key(
        "http_fetch", {"url": "https://x"})


def test_a_production_call_that_raised_raises_again_in_the_twin(recording_on):
    async def boom():
        raise TimeoutError("upstream timed out")

    async def prod():
        with pytest.raises(TimeoutError):
            await twin.dispatch(5, "web_fetch", {"url": "https://x"}, boom)
    asyncio.run(prod())
    replay = twin.Replay(twin.load(5))
    with pytest.raises(TimeoutError, match="upstream timed out"):
        replay.serve("web_fetch", {"url": "https://x"})
    assert replay.report()["unmatched"] == [] and replay.served == 1


def test_a_goal_bound_to_a_user_replays_as_that_user(recording_on, tmp_path):
    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("t", "d", owner="alice", execution_principal="user:alice")
    assert twin.run_kwargs(world.get_goal(gid)) == {"user_id": "alice"}
    bot = world.create_goal("t", "d", execution_principal="svc:payroll-bot")
    asyncio.run(_d(twin, bot, "web_search", {"q": "x"}, _live([])))
    with pytest.raises(LookupError, match="capability principal"):
        twin.replay_goal(world, bot, lambda g: "done")
    assert len(world.list_goals()) == 2  # refused before creating a twin goal


@pytest.mark.asyncio
async def test_a_twin_never_asks_a_human_for_a_served_tool(recording_on, tmp_path, monkeypatch):
    from maverick import ifc
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.safety import consent
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.tools import Tool
    from maverick.world_model import WorldModel

    asked: list = []
    monkeypatch.setattr(consent, "require_consent",
                        lambda *a, **k: asked.append(a) or type("D", (), {"granted": True})())
    world = WorldModel(tmp_path / "world.db")
    ctx = SwarmContext(llm=None, world=world, budget=Budget(max_dollars=1.0),
                       blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
                       goal_id=world.create_goal("g", ""), use_skills=False)
    ctx.ifc = ifc.FlowTracker(mode="approve")
    agent = Agent(ctx=ctx, role="analyst", brief="b")
    agent.capability = None
    schema = {"type": "object", "properties": {}}
    agent.tools.register(Tool(name="sql_query", description="q", input_schema=schema,
                              fn=lambda args: "rows"))
    agent.tools.register(Tool(name="http_fetch", description="f", input_schema=schema,
                              fn=lambda args: "200 OK"))
    await agent._run_tool("sql_query", {"q": "x"})
    await agent._run_tool("http_fetch", {"url": "https://partner"})
    assert len(asked) == 1                                   # production asked once
    ctx.ifc = ifc.FlowTracker(mode="approve")
    with twin.replaying(twin.Replay(twin.load(ctx.goal_id))):
        await agent._run_tool("sql_query", {"q": "x"})
        assert "200 OK" in await agent._run_tool("http_fetch", {"url": "https://partner"})
    assert len(asked) == 1                                   # the twin did not


def test_a_twin_sends_no_run_webhooks(monkeypatch):
    from maverick import orchestrator, webhooks
    sent: list = []
    monkeypatch.setattr(webhooks, "fire", lambda event, payload: sent.append(event))
    orchestrator._fire_webhook("goal_created", {})
    with twin.replaying(twin.Replay([])):
        orchestrator._fire_webhook("goal_created", {})
    assert sent == ["goal_created"]


@pytest.mark.asyncio
async def test_a_twin_refuses_a_gated_call_production_never_made(recording_on, tmp_path,
                                                                 monkeypatch):
    from maverick import ifc
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.safety import consent
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.tools import Tool
    from maverick.world_model import WorldModel

    asked: list = []
    monkeypatch.setattr(consent, "require_consent",
                        lambda *a, **k: asked.append(a) or type("D", (), {"granted": False})())
    world = WorldModel(tmp_path / "world.db")
    ctx = SwarmContext(llm=None, world=world, budget=Budget(max_dollars=1.0),
                       blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
                       goal_id=world.create_goal("g", ""), use_skills=False)
    ctx.ifc = ifc.FlowTracker(mode="approve")
    agent = Agent(ctx=ctx, role="analyst", brief="b")
    agent.capability = None
    schema = {"type": "object", "properties": {}}
    agent.tools.register(Tool(name="sql_query", description="q", input_schema=schema,
                              fn=lambda args: "rows"))
    agent.tools.register(Tool(name="http_fetch", description="f", input_schema=schema,
                              fn=lambda args: "200 OK"))
    await agent._run_tool("sql_query", {"q": "x"})
    prod = await agent._run_tool("http_fetch", {"url": "https://partner"})
    assert "requires human approval" in prod and len(asked) == 1   # a human refused
    ctx.ifc = ifc.FlowTracker(mode="approve")
    replay = twin.Replay(twin.load(ctx.goal_id))
    with twin.replaying(replay):
        await agent._run_tool("sql_query", {"q": "x"})
        out = await agent._run_tool("http_fetch", {"url": "https://partner"})
    assert "requires human approval" in out and len(asked) == 1     # refused, nobody asked
    assert replay.report()["unmatched"] == []                       # not a divergence


def test_budget_and_halt_stops_are_not_recorded_as_tool_errors(recording_on):
    from maverick.budget import BudgetExceeded

    async def spent():
        raise BudgetExceeded("dollar cap")

    async def prod():
        with pytest.raises(BudgetExceeded):
            await twin.dispatch(6, "web_search", {"q": "x"}, spent)
    asyncio.run(prod())
    assert twin.load(6) == []


def test_a_refused_gate_still_reports_the_call_as_divergence():
    replay = twin.Replay([])
    with twin.replaying(replay):
        assert twin.human_gate("email", {"to": "new@evil.io"}) is False
    assert replay.report()["unmatched"] == [{"tool": "email", "args": {"to": "new@evil.io"}}]
    assert twin._diverged({**replay.report(), "result_similarity": 1.0}, 0.8)


def test_a_connector_deadline_is_not_recorded_as_a_tool_error(recording_on):
    from maverick.connector_attempts import ConnectorDeadlineExceeded

    async def late():
        raise ConnectorDeadlineExceeded("deadline")

    async def prod():
        with pytest.raises(ConnectorDeadlineExceeded):
            await twin.dispatch(8, "web_search", {"q": "x"}, late)
    asyncio.run(prod())
    assert twin.load(8) == []


@pytest.mark.asyncio
async def test_twin_gate_answers_are_not_audited_as_human_decisions(recording_on, tmp_path,
                                                                   monkeypatch):
    from maverick import ifc
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.tools import Tool
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    ctx = SwarmContext(llm=None, world=world, budget=Budget(max_dollars=1.0),
                       blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
                       goal_id=world.create_goal("g", ""), use_skills=False)
    ctx.ifc = ifc.FlowTracker(mode="approve")
    agent = Agent(ctx=ctx, role="analyst", brief="b")
    agent.capability = None
    schema = {"type": "object", "properties": {}}
    agent.tools.register(Tool(name="sql_query", description="q", input_schema=schema,
                              fn=lambda args: "rows"))
    agent.tools.register(Tool(name="http_fetch", description="f", input_schema=schema,
                              fn=lambda args: "200 OK"))
    with twin.replaying(twin.Replay([])):
        await agent._run_tool("sql_query", {"q": "x"})
        await agent._run_tool("http_fetch", {"url": "https://partner"})
    assert [r["outcome"] for r in _ledger.read(ifc.ledger_path())
            if r["outcome"] in ("approved", "denied")] == []


def test_an_approved_call_stopped_later_is_not_divergence_and_refusal_beats_near_match(
        recording_on):
    twin.record_gate(4, "email", {"to": "a@x.io"}, granted=True)     # approved, then a hook stopped it
    twin.record_gate(4, "wire", {"account": "1"}, granted=False)     # refused
    asyncio.run(_d(twin, 4, "wire", {"account": "12"}, _live([])))  # a similar call that ran
    replay = twin.Replay(twin.load(4))
    with twin.replaying(replay):
        assert twin.human_gate("email", {"to": "a@x.io"}) is True
        assert twin.human_gate("wire", {"account": "1"}) is False    # not the near match
    report = replay.report()
    assert report["unmatched"] == [] and report["human_decisions"] == 2
    assert report["human_decisions_not_reached"] == 0 and report["recorded"] == 1
