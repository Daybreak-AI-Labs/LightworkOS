"""Tests for the per-tool rate limiter."""
from __future__ import annotations

import asyncio

import pytest
from maverick.safety.rate_limiter import (
    _Limiter,
    apply_to_registry,
    parse_limit,
)
from maverick.tools import Tool, ToolRegistry


def test_parse_limit_basic():
    assert parse_limit("10/60") == (10, 60.0)
    assert parse_limit("5/0.5") == (5, 0.5)
    assert parse_limit("20/30s") == (20, 30.0)
    assert parse_limit(" 1 / 1 ") == (1, 1.0)


def test_parse_limit_invalid():
    assert parse_limit("") is None
    assert parse_limit("10") is None
    assert parse_limit("ten/sixty") is None
    assert parse_limit("0/60") is None
    assert parse_limit("10/0") is None
    assert parse_limit(None) is None  # type: ignore[arg-type]


def test_limiter_allows_under_cap():
    lim = _Limiter(3, 1.0)
    assert lim.try_consume(now=0.0)
    assert lim.try_consume(now=0.1)
    assert lim.try_consume(now=0.2)
    assert not lim.try_consume(now=0.3)


def test_limiter_recovers_after_window():
    lim = _Limiter(2, 1.0)
    assert lim.try_consume(now=0.0)
    assert lim.try_consume(now=0.5)
    assert not lim.try_consume(now=0.9)
    # Past the window, oldest hit drops off.
    assert lim.try_consume(now=1.1)


def _echo_tool(name: str = "echo") -> Tool:
    return Tool(
        name=name,
        description="echo",
        input_schema={"type": "object"},
        fn=lambda args: f"ok:{args.get('x', '')}",
    )


def _async_echo_tool() -> Tool:
    async def fn(args):
        return f"async:{args.get('x', '')}"
    return Tool(
        name="async_echo",
        description="async echo",
        input_schema={"type": "object"},
        fn=fn,
    )


def test_apply_to_registry_wraps_named_tool():
    reg = ToolRegistry()
    reg.register(_echo_tool("echo"))
    reg.register(_echo_tool("untouched"))

    wrapped = apply_to_registry(reg, limits={"echo": (2, 60.0)})
    assert wrapped == 1

    assert reg.get("echo").fn({"x": "1"}) == "ok:1"
    assert reg.get("echo").fn({"x": "2"}) == "ok:2"
    err = reg.get("echo").fn({"x": "3"})
    assert err.startswith("ERROR: rate limit exceeded for echo")

    # Unmatched tool keeps its identity.
    assert reg.get("untouched").fn({"x": "y"}) == "ok:y"


def test_apply_to_registry_glob_match():
    reg = ToolRegistry()
    reg.register(_echo_tool("mcp_a__x"))
    reg.register(_echo_tool("mcp_a__y"))
    reg.register(_echo_tool("shell"))

    apply_to_registry(reg, limits={"mcp_*": (1, 60.0)})

    assert reg.get("mcp_a__x").fn({}) == "ok:"
    err = reg.get("mcp_a__x").fn({})
    assert err.startswith("ERROR: rate limit exceeded for mcp_a__x")
    # Sibling has its own bucket.
    assert reg.get("mcp_a__y").fn({}) == "ok:"
    # Non-matching name still works freely.
    for _ in range(5):
        assert reg.get("shell").fn({}) == "ok:"


def test_apply_to_registry_no_config_is_noop():
    reg = ToolRegistry()
    reg.register(_echo_tool("echo"))
    n = apply_to_registry(reg, limits={})
    assert n == 0
    for _ in range(50):
        assert reg.get("echo").fn({}).startswith("ok:")


def test_apply_to_registry_preserves_async():
    reg = ToolRegistry()
    reg.register(_async_echo_tool())
    apply_to_registry(reg, limits={"async_echo": (1, 60.0)})

    async def call_twice():
        first = await reg.run("async_echo", {"x": "1"})
        second = await reg.run("async_echo", {"x": "2"})
        return first, second

    first, second = asyncio.run(call_twice())
    assert first == "async:1"
    assert second.startswith("ERROR: rate limit exceeded for async_echo")


@pytest.mark.parametrize("spec", ["bogus", "", "5"])
def test_apply_to_registry_invalid_limits_loaded_from_config(spec, monkeypatch):
    """Bad config entries are skipped, not crashy."""
    from maverick.safety import rate_limiter as rl

    def _fake_load():
        out = {}
        parsed = rl.parse_limit(spec)
        if parsed:
            out["echo"] = parsed
        return out

    monkeypatch.setattr(rl, "_load_limits", _fake_load)
    reg = ToolRegistry()
    reg.register(_echo_tool("echo"))
    rl.apply_to_registry(reg)  # picks up _load_limits, no exception
    # Without a valid limit, the tool stays unwrapped.
    assert reg.get("echo").fn({}) == "ok:"
