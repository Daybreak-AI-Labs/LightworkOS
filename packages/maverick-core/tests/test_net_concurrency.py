"""Per-host concurrency caps for parallel network reads.

Same-host network reads in one turn are throttled by a per-host semaphore;
cross-host reads and local reads stay fully concurrent.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from maverick import net_concurrency as nc
from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.llm import LLMResponse, ToolCall
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.tools import Tool
from maverick.world_model import WorldModel


@pytest.fixture(autouse=True)
def _reset_semaphores():
    nc._reset_for_tests()
    yield
    nc._reset_for_tests()


def test_get_semaphore_picks_up_cap_change():
    """MAVERICK_NET_HOST_CONCURRENCY is a live tunable: a changed cap must
    rebuild the per-host semaphore rather than keep the first one seen for the
    loop's lifetime."""
    async def go():
        nc._reset_for_tests()
        s4 = nc._get_semaphore("http:example.com", 4)
        assert s4._mvk_cap == 4
        # Same cap -> same cached object.
        assert nc._get_semaphore("http:example.com", 4) is s4
        # Changed cap -> a fresh semaphore carrying the new limit.
        s8 = nc._get_semaphore("http:example.com", 8)
        assert s8 is not s4 and s8._mvk_cap == 8

    asyncio.run(go())


@pytest.fixture
def ctx(tmp_path: Path, fake_llm):
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("test goal", "")
    return SwarmContext(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id, max_depth=1, use_skills=False,
    )


class TestHostKey:
    def test_http_fetch_parses_host(self):
        assert nc.host_key("http_fetch", {"url": "https://EXAMPLE.com/a"}) == "http:example.com"

    def test_fixed_endpoint_tools(self):
        assert nc.host_key("arxiv", {}) == "svc:arxiv.org"
        assert nc.host_key("wikipedia", {}) == "svc:wikipedia.org"
        assert nc.host_key("semantic_scholar", {}) == "svc:semanticscholar.org"

    def test_local_and_unknown_are_none(self):
        assert nc.host_key("read_file", {"path": "x"}) is None
        assert nc.host_key("totally_unknown", {}) is None

    def test_unparseable_url_is_none(self):
        assert nc.host_key("http_fetch", {"url": ""}) is None
        assert nc.host_key("http_fetch", {}) is None


class TestLimitContext:
    @pytest.mark.asyncio
    async def test_disabled_when_cap_zero(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_NET_HOST_CONCURRENCY", "0")
        # Even a known host returns a no-op context (no throttling).
        import contextlib
        limiter = nc.limit("arxiv", {})
        assert isinstance(limiter, contextlib.nullcontext)

    @pytest.mark.asyncio
    async def test_known_host_returns_semaphore(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_NET_HOST_CONCURRENCY", "2")
        limiter = nc.limit("arxiv", {})
        assert isinstance(limiter, asyncio.Semaphore)


class TestCrossLoopSafety:
    def test_semaphore_not_reused_across_event_loops(self, monkeypatch):
        # A Semaphore binds to the loop it's awaited on; the module-level
        # registry must not hand a loop-A semaphore to loop B (which would raise
        # "bound to a different loop" and break the fetch). Each loop gets its
        # own instance. Refs are kept so the two ids can't alias via GC.
        monkeypatch.setenv("MAVERICK_NET_HOST_CONCURRENCY", "2")
        nc._reset_for_tests()
        captured: list = []

        async def grab():
            async with nc.limit("arxiv", {}):
                pass
            captured.append(nc._get_semaphore("svc:arxiv.org", 2))

        asyncio.run(grab())
        asyncio.run(grab())
        assert captured[0] is not captured[1]


def _net_tool(name: str, tracker: dict) -> Tool:
    async def fn(args: dict) -> str:
        tracker["active"] += 1
        tracker["max"] = max(tracker["max"], tracker["active"])
        await asyncio.sleep(0.05)
        tracker["active"] -= 1
        return "ok"

    return Tool(name=name, description="x",
                input_schema={"type": "object", "properties": {}},
                fn=fn, parallel_safe=True)


class TestThrottlingThroughAgentLoop:
    @pytest.mark.asyncio
    async def test_same_host_is_capped(self, ctx, fake_llm, monkeypatch):
        monkeypatch.setenv("MAVERICK_NET_HOST_CONCURRENCY", "1")
        nc._reset_for_tests()
        tracker = {"active": 0, "max": 0}
        # Two arxiv calls in one turn -> same host -> cap of 1 -> serialized.
        fake_llm.scripted = [
            LLMResponse(
                text="go", thinking=None, stop_reason="tool_use",
                tool_calls=[ToolCall(id="a", name="arxiv", input={}),
                            ToolCall(id="b", name="arxiv", input={})],
            ),
            LLMResponse(text="FINAL: done", thinking=None,
                        stop_reason="end_turn", tool_calls=[]),
        ]
        agent = Agent(ctx=ctx, role="researcher", brief="q")
        # Replace the registered arxiv tool with our instrumented one.
        agent.tools.register(_net_tool("arxiv", tracker))
        result = await agent.run()
        assert result.final == "done"
        assert tracker["max"] == 1  # capped: never two arxiv calls at once

    @pytest.mark.asyncio
    async def test_cross_host_stays_concurrent(self, ctx, fake_llm, monkeypatch):
        monkeypatch.setenv("MAVERICK_NET_HOST_CONCURRENCY", "1")
        nc._reset_for_tests()
        tracker = {"active": 0, "max": 0}
        # arxiv + wikipedia -> different hosts -> both run concurrently
        # despite a per-host cap of 1.
        fake_llm.scripted = [
            LLMResponse(
                text="go", thinking=None, stop_reason="tool_use",
                tool_calls=[ToolCall(id="a", name="arxiv", input={}),
                            ToolCall(id="b", name="wikipedia", input={})],
            ),
            LLMResponse(text="FINAL: done", thinking=None,
                        stop_reason="end_turn", tool_calls=[]),
        ]
        agent = Agent(ctx=ctx, role="researcher", brief="q")
        agent.tools.register(_net_tool("arxiv", tracker))
        agent.tools.register(_net_tool("wikipedia", tracker))
        result = await agent.run()
        assert result.final == "done"
        assert tracker["max"] == 2  # different hosts overlap


def test_concurrent_loops_do_not_collide():
    """Two goals on two threads = two live event loops. Each must get its OWN
    per-host semaphore; the old single shared registry flip-flopped between
    loops, raising "bound to a different loop" or losing the cap. Regression for
    the cross-loop data race.
    """
    import threading

    nc._reset_for_tests()
    errors: list[BaseException] = []
    # Hold the semaphore OBJECTS, not their id()s: a finished loop's semaphore is
    # GC'd, and CPython readily re-allocates the next loop's semaphore at the same
    # address, so comparing id()s of non-co-existing objects flakes between 1 and
    # 2. Keeping a reference to each loop's semaphore keeps both alive until the
    # assertion, so their identities can't alias.
    sems: list = []
    barrier = threading.Barrier(2)

    async def _use() -> None:
        barrier.wait()  # maximise interleaving of the two loops' registry access
        loop_sem = None
        for _ in range(50):
            ctx = nc.limit("http_fetch", {"url": "https://example.com/x"})
            async with ctx:  # awaiting binds the semaphore to THIS loop
                await asyncio.sleep(0)
            # limit() returns the cached per-loop semaphore; it must be stable
            # across calls within a single loop.
            assert loop_sem is None or ctx is loop_sem, "semaphore not stable in loop"
            loop_sem = ctx
        sems.append(loop_sem)

    def _runner() -> None:
        try:
            asyncio.run(_use())  # fresh loop per thread
        except BaseException as e:  # noqa: BLE001 - surface any cross-loop error
            errors.append(e)

    threads = [threading.Thread(target=_runner) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"cross-loop semaphore error: {errors!r}"
    # Each loop kept its OWN stable semaphore for the host (not shared with, or
    # torn down by, the other loop): two distinct live objects across two loops.
    assert len(sems) == 2
    assert sems[0] is not sems[1]
    assert len({id(s) for s in sems}) == 2
