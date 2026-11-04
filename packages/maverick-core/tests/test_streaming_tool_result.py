"""Streaming tool_result: generator tools stream chunks to the registry
listener while the model still receives the joined text."""
from __future__ import annotations

import asyncio

from maverick.tools import Tool, ToolRegistry


def _registry(*tools):
    reg = ToolRegistry()
    for t in tools:
        reg.register(t)
    return reg


def _sync_stream_tool():
    def fn(args):
        def gen():
            yield "chunk-1 "
            yield "chunk-2 "
            yield "chunk-3"
        return gen()
    return Tool(name="streamer", description="d", input_schema={}, fn=fn)


def _async_stream_tool():
    async def fn(args):
        for i in (1, 2):
            yield f"a{i} "
    return Tool(name="astreamer", description="d", input_schema={}, fn=fn)


def test_sync_generator_streams_and_joins():
    reg = _registry(_sync_stream_tool())
    seen = []
    reg.set_chunk_listener(lambda name, chunk: seen.append((name, chunk)))
    out = asyncio.run(reg.run("streamer", {}))
    assert out == "chunk-1 chunk-2 chunk-3"
    assert len(seen) == 1 and "Buffering" in seen[0][1]
    assert "chunk-1" not in str(seen)
    reg.deliver_screened("streamer", out)
    assert seen[-1] == ("streamer", out)


def test_async_generator_streams_and_joins():
    reg = _registry(_async_stream_tool())
    seen = []
    reg.set_chunk_listener(lambda name, chunk: seen.append(chunk))
    out = asyncio.run(reg.run("astreamer", {}))
    assert out == "a1 a2 "
    assert len(seen) == 1 and "Buffering" in seen[0]
    reg.deliver_screened("astreamer", out)
    assert seen[-1] == out


def test_streaming_without_listener_still_joins():
    reg = _registry(_sync_stream_tool())
    out = asyncio.run(reg.run("streamer", {}))
    assert out == "chunk-1 chunk-2 chunk-3"


def test_listener_errors_are_swallowed():
    reg = _registry(_sync_stream_tool())

    def bad_listener(name, chunk):
        raise RuntimeError("observer crashed")

    reg.set_chunk_listener(bad_listener)
    out = asyncio.run(reg.run("streamer", {}))
    assert out == "chunk-1 chunk-2 chunk-3"


def test_plain_str_tools_unchanged_and_listener_silent():
    plain = Tool(name="plain", description="d", input_schema={},
                 fn=lambda args: "just text")
    reg = _registry(plain)
    seen = []
    reg.set_chunk_listener(lambda n, c: seen.append(c))
    out = asyncio.run(reg.run("plain", {}))
    assert out == "just text" and seen == []


def test_clearing_listener():
    reg = _registry(_sync_stream_tool())
    seen = []
    reg.set_chunk_listener(lambda n, c: seen.append(c))
    asyncio.run(reg.run("streamer", {}))
    reg.set_chunk_listener(None)
    asyncio.run(reg.run("streamer", {}))
    assert len(seen) == 1  # second run sent progress to no one
