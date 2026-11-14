"""Tool-output cache: memoize side-effect-free tool calls."""
from __future__ import annotations

import asyncio

import pytest
from maverick.cache import tool as tool_cache
from maverick.tools import Tool, ToolRegistry


@pytest.fixture(autouse=True)
def _clean_cache():
    tool_cache.reset()
    yield
    tool_cache.reset()


def _counting_tool(name="read_file", parallel_safe=True):
    calls = {"n": 0}

    def _fn(args):
        calls["n"] += 1
        return f"result-for-{args.get('path', '')}-{calls['n']}"

    return Tool(name=name, description="x", input_schema={"type": "object"},
                fn=_fn, parallel_safe=parallel_safe), calls


def _run(reg, name, args):
    return asyncio.run(reg.run(name, args))


def test_disabled_by_default_no_caching(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TOOL_CACHE", raising=False)
    tool, calls = _counting_tool()
    reg = ToolRegistry()
    reg.register(tool)
    _run(reg, "read_file", {"path": "a"})
    _run(reg, "read_file", {"path": "a"})
    assert calls["n"] == 2  # no memoization when off


def test_noncacheable_tool_never_reads_cache_enablement(monkeypatch):
    tool, _ = _counting_tool(parallel_safe=False)

    def unexpected_config_read():
        raise AssertionError("a write cannot be cached under any configuration")

    monkeypatch.setattr(tool_cache, "enabled", unexpected_config_read)
    assert tool_cache.get_cached(tool, {}) == (False, None)
    tool_cache.store_cached(tool, {}, "a write result")
    assert tool_cache.stats() == {"hits": 0, "misses": 0, "size": 0}


def test_hit_serves_cache_without_reinvoking(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    tool, calls = _counting_tool()
    reg = ToolRegistry()
    reg.register(tool)
    r1 = _run(reg, "read_file", {"path": "a"})
    r2 = _run(reg, "read_file", {"path": "a"})
    assert r1 == r2
    assert calls["n"] == 1  # second call served from cache
    assert tool_cache.stats()["hits"] == 1


def test_distinct_args_miss(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    tool, calls = _counting_tool()
    reg = ToolRegistry()
    reg.register(tool)
    _run(reg, "read_file", {"path": "a"})
    _run(reg, "read_file", {"path": "b"})
    assert calls["n"] == 2  # different args -> distinct keys


def test_authenticated_principals_never_share_cached_output(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")

    calls = {"n": 0}

    def _whoami(principal):
        def _read(_args):
            calls["n"] += 1
            return f"private-for:{principal}"
        return _read

    def _tool(principal):
        return Tool(
            name="account_report",
            description="principal-specific connector read",
            input_schema={"type": "object"},
            fn=_whoami(principal),
            parallel_safe=True,
        )

    alice = ToolRegistry(principal="user:alice")
    bob = ToolRegistry(principal="user:bob")
    alice.register(_tool("user:alice"))
    bob.register(_tool("user:bob"))

    assert _run(alice, "account_report", {}) == "private-for:user:alice"
    assert _run(alice, "account_report", {}) == "private-for:user:alice"
    assert _run(bob, "account_report", {}) == "private-for:user:bob"
    assert calls["n"] == 2


def test_tenants_never_share_cached_output(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")

    from maverick.paths import current_tenant_id, reset_tenant, set_tenant

    calls = {"n": 0}

    def _tenant_report(_args):
        calls["n"] += 1
        return f"private-for:{current_tenant_id()}"

    reg = ToolRegistry(principal="user:operator")
    reg.register(Tool(
        name="tenant_report",
        description="tenant-specific connector read",
        input_schema={"type": "object"},
        fn=_tenant_report,
        parallel_safe=True,
    ))

    token = set_tenant("tenant-a")
    try:
        assert _run(reg, "tenant_report", {}) == "private-for:tenant-a"
        assert _run(reg, "tenant_report", {}) == "private-for:tenant-a"
    finally:
        reset_tenant(token)
    token = set_tenant("tenant-b")
    try:
        assert _run(reg, "tenant_report", {}) == "private-for:tenant-b"
    finally:
        reset_tenant(token)
    assert calls["n"] == 2


def test_non_parallel_safe_never_cached(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    tool, calls = _counting_tool(name="write_file", parallel_safe=False)
    reg = ToolRegistry()
    reg.register(tool)
    _run(reg, "write_file", {"path": "a"})
    _run(reg, "write_file", {"path": "a"})
    assert calls["n"] == 2  # writes are never memoized


def test_error_results_not_cached(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")

    def _boom(args):
        raise RuntimeError("kaboom")

    reg = ToolRegistry()
    reg.register(Tool(name="read_file", description="x",
                      input_schema={"type": "object"}, fn=_boom,
                      parallel_safe=True))
    r1 = _run(reg, "read_file", {"path": "a"})
    assert r1.startswith("ERROR:")
    assert tool_cache.stats()["size"] == 0  # error not stored


@pytest.mark.parametrize("outcome", ["indeterminate", "exception", "cancelled"])
def test_dispatched_write_invalidates_cache_even_without_confirmed_success(
    monkeypatch, tmp_path, outcome,
):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    monkeypatch.setenv("MAVERICK_TOOL_CACHE_SNAPSHOT", "1")
    snapshot = tmp_path / "cache.jsonl"
    monkeypatch.setenv("MAVERICK_TOOL_CACHE_SNAPSHOT_PATH", str(snapshot))
    read, calls = _counting_tool()

    def write(_args):
        if outcome == "exception":
            raise RuntimeError("response lost")
        if outcome == "cancelled":
            raise asyncio.CancelledError
        return "INDETERMINATE: response lost after dispatch"

    reg = ToolRegistry()
    reg.register(read)
    reg.register(Tool(name="write_file", description="write", input_schema={"type": "object"},
                      fn=write, parallel_safe=False))
    _run(reg, "read_file", {"path": "a"})
    assert tool_cache.save_snapshot() == 1
    if outcome == "cancelled":
        with pytest.raises(asyncio.CancelledError):
            _run(reg, "write_file", {})
    else:
        _run(reg, "write_file", {})
    assert not snapshot.exists()
    tool_cache.reset()  # a future process must not reload pre-write results
    _run(reg, "read_file", {"path": "a"})
    assert calls["n"] == 2


def test_read_started_before_write_cannot_repopulate_stale_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    calls = []

    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()

        async def read(_args):
            calls.append(1)
            if len(calls) == 1:
                entered.set()
                await release.wait()
                return "old"
            return "new"

        reg = ToolRegistry()
        reg.register(Tool(name="read_file", description="read", input_schema={"type": "object"},
                          fn=read, parallel_safe=True))
        reg.register(Tool(name="write_file", description="write", input_schema={"type": "object"},
                          fn=lambda _: "ok", parallel_safe=False))
        pending = asyncio.create_task(reg.run("read_file", {}))
        await entered.wait()
        await reg.run("write_file", {})
        release.set()
        assert await pending == "old"
        assert await reg.run("read_file", {}) == "new"
        assert len(calls) == 2

    asyncio.run(scenario())


def test_lru_eviction(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    monkeypatch.setattr(tool_cache, "_maxsize", lambda: 2)
    tool, calls = _counting_tool()
    reg = ToolRegistry()
    reg.register(tool)
    _run(reg, "read_file", {"path": "a"})  # store a
    _run(reg, "read_file", {"path": "b"})  # store b
    _run(reg, "read_file", {"path": "c"})  # store c, evict a (LRU)
    assert tool_cache.stats()["size"] == 2
    _run(reg, "read_file", {"path": "a"})  # a was evicted -> recompute
    assert calls["n"] == 4


def test_ttl_expiry(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    monkeypatch.setattr(tool_cache, "_ttl_s", lambda: 10.0)
    clock = {"t": 1000.0}
    monkeypatch.setattr(tool_cache.time, "monotonic", lambda: clock["t"])
    tool, calls = _counting_tool()
    reg = ToolRegistry()
    reg.register(tool)
    _run(reg, "read_file", {"path": "a"})  # stored at t=1000
    clock["t"] = 1005.0
    _run(reg, "read_file", {"path": "a"})  # within TTL -> hit
    assert calls["n"] == 1
    clock["t"] = 1020.0
    _run(reg, "read_file", {"path": "a"})  # past TTL -> recompute
    assert calls["n"] == 2


class TestWarmOnStart:
    """Cache-warm-on-start: snapshot persistence + reload."""

    def _tool(self):
        import types
        return types.SimpleNamespace(name="repo_map", parallel_safe=True)

    def test_snapshot_roundtrip(self, monkeypatch, tmp_path):
        from maverick.cache import tool as tc
        snap = tmp_path / "snap.jsonl"
        monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
        monkeypatch.setenv("MAVERICK_TOOL_CACHE_SNAPSHOT", "1")
        monkeypatch.setenv("MAVERICK_TOOL_CACHE_SNAPSHOT_PATH", str(snap))
        tc.reset()
        tool = self._tool()
        tc.store_cached(tool, {"path": "."}, "the map")
        assert tc.save_snapshot() == 1
        # New "process": clear memory, then a lookup warms from disk.
        tc.reset()
        hit, value = tc.get_cached(tool, {"path": "."})
        assert hit and value == "the map"
        tc.reset()

    def test_snapshot_off_means_no_warm(self, monkeypatch, tmp_path):
        from maverick.cache import tool as tc
        snap = tmp_path / "snap.jsonl"
        snap.write_text('{"k": "repo_map:abc", "v": "x", "t": 0}\n')
        monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
        monkeypatch.delenv("MAVERICK_TOOL_CACHE_SNAPSHOT", raising=False)
        monkeypatch.setenv("MAVERICK_TOOL_CACHE_SNAPSHOT_PATH", str(snap))
        tc.reset()
        assert tc.warm_on_start() == 0
        tc.reset()

    def test_warm_respects_ttl_and_corrupt_lines(self, monkeypatch, tmp_path):
        import json as _json
        import time as _time

        from maverick.cache import tool as tc
        snap = tmp_path / "snap.jsonl"
        fresh = {"k": "repo_map:fresh", "v": "ok", "t": _time.time(), "generation": tc._sync_epoch()}
        stale = {"k": "repo_map:stale", "v": "old", "t": _time.time() - 9999, "generation": tc._sync_epoch()}
        snap.write_text(
            _json.dumps(fresh) + "\n" + _json.dumps(stale) + "\nnot-json\n"
        )
        monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
        monkeypatch.setenv("MAVERICK_TOOL_CACHE_SNAPSHOT", "1")
        monkeypatch.setenv("MAVERICK_TOOL_CACHE_SNAPSHOT_PATH", str(snap))
        # TTL 60s: 'stale' is expired at load; corrupt line skipped.
        monkeypatch.setattr(tc, "_cfg", lambda: {"output_cache_ttl_s": 60})
        tc.reset()
        assert tc.warm_on_start() == 1
        assert tc.stats()["size"] == 1
        tc.reset()

    def test_warm_is_idempotent_per_process(self, monkeypatch, tmp_path):
        import json as _json
        import time as _time

        from maverick.cache import tool as tc
        snap = tmp_path / "snap.jsonl"
        snap.write_text(_json.dumps({"k": "a:1", "v": "x", "t": _time.time(), "generation": tc._sync_epoch()}) + "\n")
        monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
        monkeypatch.setenv("MAVERICK_TOOL_CACHE_SNAPSHOT", "1")
        monkeypatch.setenv("MAVERICK_TOOL_CACHE_SNAPSHOT_PATH", str(snap))
        tc.reset()
        assert tc.warm_on_start() == 1
        assert tc.warm_on_start() == 0  # second call no-ops
        tc.reset()


def test_workspaces_never_share_cached_output(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    tool_a, calls_a = _counting_tool()
    tool_b, calls_b = _counting_tool()
    reg_a = ToolRegistry(workspace="LocalBackend:/work/a")
    reg_b = ToolRegistry(workspace="LocalBackend:/work/b")
    reg_a.register(tool_a)
    reg_b.register(tool_b)
    _run(reg_a, "read_file", {"path": "notes.txt"})
    _run(reg_b, "read_file", {"path": "notes.txt"})
    assert calls_a["n"] == 1 and calls_b["n"] == 1  # same args, two workspaces
