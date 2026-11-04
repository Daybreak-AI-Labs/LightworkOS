"""Local socket downstream, controlled upstream: no provider or network service."""
from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path

import h11
import httpx
import pytest
from maverick.model_proxy import ProxyConfig, build_request, strip_response_headers
from maverick.model_proxy_stream import ProxyHTTPError, ProxyServer, forward_stream


class Stream(httpx.AsyncByteStream):
    def __init__(self, chunks=(b"data: first\n\n", b"data: done\n\n"), *, fail=False):
        self.release = asyncio.Event()
        self.closed = asyncio.Event()
        self.reads = 0
        self.chunks = chunks
        self.fail = fail

    async def __aiter__(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk
            await self.release.wait()
        if self.fail:
            raise httpx.ReadError("fixture stream interrupted")

    async def aclose(self):
        self.closed.set()


@asynccontextmanager
async def fixture_proxy(stream, **limits):
    calls = []

    async def handle(request):
        calls.append(request)
        return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, stream=stream)

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handle))
    config = ProxyConfig(
        upstream="https://fixture.invalid", api_key="fixture-upstream-key", client_token="fixture-client",  # pragma: allowlist secret - synthetic local MockTransport fixture
        listen_port=0, total_seconds=limits.pop("total_seconds", 3), **limits,
    )
    proxy = await ProxyServer(config, client=upstream).start()
    try:
        yield proxy, calls
    finally:
        await proxy.aclose()
        await upstream.aclose()


def url(proxy):
    return f"http://127.0.0.1:{proxy.address[1]}/v1/messages"


@pytest.mark.asyncio
async def test_shared_streaming_parity_fixture():
    fixture = json.loads(
        (Path(__file__).resolve().parents[3] / "go/model-proxy/testdata/stream_parity.json")
        .read_text(encoding="utf-8")
    )
    stream = Stream(chunks=tuple(chunk.encode("utf-8") for chunk in fixture["chunks"]))
    stream.release.set()
    async with fixture_proxy(stream) as (proxy, calls), httpx.AsyncClient(trust_env=False) as client:
        response = await client.post(
            url(proxy), headers={"Authorization": "Bearer fixture-client"}, content=b"{}",
        )
    assert response.status_code == 200
    assert response.headers["Content-Type"] == fixture["content_type"]
    assert response.content == "".join(fixture["chunks"]).encode("utf-8")
    assert len(calls) == 1 and stream.closed.is_set()


@pytest.mark.asyncio
async def test_first_chunk_is_delivered_before_upstream_completion_and_disconnect_closes_owner():
    stream = Stream()
    async with fixture_proxy(stream) as (proxy, calls), httpx.AsyncClient(trust_env=False) as client:
        async with client.stream("POST", url(proxy), headers={"Authorization": "Bearer fixture-client"}, content=b"{}") as response:
            assert response.status_code == 200
            first = await asyncio.wait_for(anext(response.aiter_raw()), .5)
            assert first == b"data: first\n\n"
            assert not stream.release.is_set()
        await asyncio.wait_for(stream.closed.wait(), 1)
        assert len(calls) == 1 and calls[0].headers["Authorization"] == "Bearer fixture-upstream-key"


@pytest.mark.asyncio
async def test_midstream_failure_is_truncated_not_success_or_replay():
    stream = Stream(chunks=(b"data: first\n\n",), fail=True)
    stream.release.set()
    async with fixture_proxy(stream) as (proxy, calls), httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(httpx.RemoteProtocolError):
            await client.post(url(proxy), headers={"Authorization": "Bearer fixture-client"}, content=b"{}")
        assert len(calls) == 1
        assert stream.closed.is_set()


async def raw_request(proxy, body):
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.address[1])
    writer.write(body)
    await writer.drain()
    response = await asyncio.wait_for(reader.read(), 2)
    writer.close()
    await writer.wait_closed()
    return response


@pytest.mark.asyncio
@pytest.mark.parametrize("length", ["-1", "invalid", "9999"])
async def test_upstream_declared_length_is_rejected_before_headers_and_closed(length):
    stream = Stream()
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(
        200, headers={"Content-Length": length}, stream=stream,
    ))) as client:
        config = ProxyConfig(upstream="https://fixture.invalid", api_key="fixture", max_response_bytes=10)
        with pytest.raises(ProxyHTTPError) as error:
            async with forward_stream(config, client, "POST", "/v1/messages", {}, b"{}"):
                pytest.fail("invalid upstream size was admitted")
        assert error.value.status == 502
        assert stream.closed.is_set() and stream.reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("tail", [
    b"Content-Length: 1000000\r\n\r\n",  # Rejected without waiting for this body.
    b"Transfer-Encoding: chunked\r\n\r\n9\r\n123456789\r\n0\r\n\r\n",
    b"Content-Length: 9\r\n\r\n123456789",
])
async def test_admitted_request_bytes_are_bounded_for_declared_and_chunked_bodies(tail):
    async with fixture_proxy(Stream(), max_request_bytes=8) as (proxy, calls):
        response = await raw_request(proxy, b"POST /v1/messages HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer fixture-client\r\n" + tail)
        assert b" 413 " in response
        assert calls == []


@pytest.mark.asyncio
async def test_authentication_happens_before_body_admission():
    async with fixture_proxy(Stream()) as (proxy, calls):
        response = await raw_request(proxy,
            b"POST /v1/messages HTTP/1.1\r\nHost: fixture\r\nContent-Length: 99999999\r\n\r\n")
        assert b" 401 " in response and not calls


@pytest.mark.asyncio
async def test_ambiguous_length_is_rejected_and_route_denial_precedes_body_read():
    async with fixture_proxy(Stream()) as (proxy, calls):
        response = await raw_request(proxy,
            b"POST /v1/messages HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer fixture-client\r\nContent-Length: 1\r\nContent-Length: 999\r\n\r\nx")
        assert b" 400 " in response
        response = await raw_request(proxy,
            b"POST /v1/files HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer fixture-client\r\nContent-Length: 9999999\r\n\r\n")
        assert b" 403 " in response and not calls


@pytest.mark.asyncio
async def test_output_limit_and_total_deadline_close_partial_stream():
    for limited, settings in ((Stream(chunks=(b"0123456789",)), {"max_response_bytes": 8}),
                              (Stream(), {"total_seconds": .1})):
        async with fixture_proxy(limited, **settings) as (proxy, calls), httpx.AsyncClient(trust_env=False) as client:
            with pytest.raises(httpx.RemoteProtocolError):
                await client.post(url(proxy), headers={"Authorization": "Bearer fixture-client"}, content=b"{}")
            assert len(calls) == 1 and limited.closed.is_set()


@pytest.mark.asyncio
async def test_backpressure_stops_upstream_iteration_until_write_completes():
    stream = Stream()
    stream.release.set()
    async with fixture_proxy(stream) as (proxy, calls):
        connection = h11.Connection(h11.SERVER)
        connection.receive_data(b"POST /v1/messages HTTP/1.1\r\nHost: fixture\r\nContent-Length: 0\r\n\r\n")
        connection.next_event()
        connection.next_event()
        blocked = asyncio.Event()
        release = asyncio.Event()

        class Writer:
            writes = 0

            def write(self, _data):
                self.writes += 1

            async def drain(self):
                if self.writes == 2:
                    blocked.set()
                    await release.wait()

        task = asyncio.create_task(proxy._relay(connection, Writer(), ("POST", "/v1/messages", {}, b""), {"started": False}))
        await asyncio.wait_for(blocked.wait(), 1)
        assert stream.reads == 1
        release.set()
        await task
        assert stream.reads == 2 and stream.closed.is_set() and len(calls) == 1


def test_proxy_credential_and_connection_nominated_headers_never_cross_boundary():
    config = ProxyConfig(upstream="https://fixture.invalid", api_key="upstream", client_token="client")
    _, headers = build_request(config, "/v1/messages", {
        "x-maverick-proxy-token": "client", "Connection": "x-private", "x-private": "secret",
        "Authorization": "Bearer client", "Content-Type": "application/json",
    })
    assert headers == {"Authorization": "Bearer upstream", "Content-Type": "application/json"}
    assert strip_response_headers({"Connection": "x-private", "x-private": "secret", "x-api-key": "upstream"}) == {}


@pytest.mark.asyncio
async def test_shutdown_cancels_and_joins_active_upstream_owner():
    stream = Stream()
    async with fixture_proxy(stream) as (proxy, calls), httpx.AsyncClient(trust_env=False) as client:
        async with client.stream("POST", url(proxy), headers={"Authorization": "Bearer fixture-client"}, content=b"{}") as response:
            iterator = response.aiter_raw()
            await anext(iterator)
            assert not stream.closed.is_set()
            started = time.monotonic()
            await proxy.aclose()
            assert time.monotonic() - started < .5
            assert stream.closed.is_set() and not proxy._tasks
            assert len(calls) == 1


@pytest.mark.asyncio
async def test_real_http_upstream_socket_closes_on_downstream_disconnect():
    closed = asyncio.Event()
    calls = []

    async def upstream(reader, writer):
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
            calls.append(headers)
            length = next(int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n") if line.lower().startswith(b"content-length:"))
            await reader.readexactly(length)
            writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\nD\r\ndata: first\n\n\r\n")
            await writer.drain()
            assert await reader.read(1) == b""
        finally:
            writer.close()
            await writer.wait_closed()
            closed.set()

    origin = await asyncio.start_server(upstream, "127.0.0.1", 0)
    origin_port = origin.sockets[0].getsockname()[1]
    proxy = await ProxyServer(ProxyConfig(
        upstream=f"http://127.0.0.1:{origin_port}", api_key="fixture-upstream-key", client_token="fixture-client",  # pragma: allowlist secret - repeated synthetic fixture
        listen_port=0, total_seconds=3,
    )).start()
    try:
        async with httpx.AsyncClient(trust_env=False) as client:
            async with client.stream("POST", url(proxy), headers={"Authorization": "Bearer fixture-client"}, content=b"{}") as response:
                assert await anext(response.aiter_raw()) == b"data: first\n\n"
            await asyncio.wait_for(closed.wait(), 1)
            assert len(calls) == 1
    finally:
        await proxy.aclose()
        origin.close()
        await origin.wait_closed()


@pytest.mark.asyncio
async def test_repeated_shutdown_cancellation_waits_for_response_cleanup():
    entered = asyncio.Event()

    class SlowClose(Stream):
        async def aclose(self):
            entered.set()
            await asyncio.sleep(.05)
            await super().aclose()

    stream = SlowClose()
    async with fixture_proxy(stream) as (proxy, _calls), httpx.AsyncClient(trust_env=False) as client:
        async with client.stream("POST", url(proxy), headers={"Authorization": "Bearer fixture-client"}, content=b"{}") as response:
            iterator = response.aiter_raw()
            await anext(iterator)
            assert not stream.closed.is_set()
            closing = asyncio.create_task(proxy.aclose())
            await asyncio.wait_for(entered.wait(), .5)
            closing.cancel()
            closing.cancel()
            with pytest.raises(asyncio.CancelledError):
                await closing
            assert stream.closed.is_set() and not proxy._tasks


@pytest.mark.asyncio
async def test_capacity_refusal_does_not_affect_active_request():
    stream = Stream()
    async with fixture_proxy(stream, max_connections=1, total_seconds=30) as (proxy, calls), httpx.AsyncClient(trust_env=False) as client:
        async with client.stream("POST", url(proxy), headers={"Authorization": "Bearer fixture-client"}, content=b"{}") as first:
            iterator = first.aiter_raw()
            await anext(iterator)
            response = await client.post(url(proxy), headers={"Authorization": "Bearer fixture-client"}, content=b"{}")
            assert response.status_code == 503
            assert len(calls) == 1 and not stream.closed.is_set()


class RejectionWriter:
    def __init__(self):
        self.output = bytearray()
        self.flushed = asyncio.Event()
        self.closed = False
        self.close_joined = False

    def write(self, data):
        self.output.extend(data)

    async def drain(self):
        self.flushed.set()

    def close(self):
        self.closed = True

    async def wait_closed(self):
        self.close_joined = True


@pytest.mark.asyncio
async def test_capacity_response_precedes_stalled_ingress_and_closes_after_drain():
    headers_ready = asyncio.Event()
    body_ready = asyncio.Event()

    class Reader:
        async def readuntil(self, separator):
            assert separator == b"\r\n\r\n"
            await headers_ready.wait()
            return b"POST /v1/messages HTTP/1.1\r\nContent-Length: 2\r\n\r\n"

        async def readexactly(self, size):
            assert size == 2
            await body_ready.wait()
            return b"{}"

    writer = RejectionWriter()
    task = asyncio.create_task(ProxyServer._reject(Reader(), writer))
    try:
        await asyncio.wait_for(writer.flushed.wait(), 2)
        assert b" 503 " in writer.output
        assert not headers_ready.is_set() and not body_ready.is_set()
        headers_ready.set()
        body_ready.set()
        await asyncio.wait_for(task, 2)
        assert writer.closed and writer.close_joined
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_capacity_stalled_ingress_is_cancelled_and_close_is_joined():
    read_cancelled = asyncio.Event()

    class Reader:
        async def readuntil(self, _separator):
            try:
                await asyncio.Event().wait()
            finally:
                read_cancelled.set()

    writer = RejectionWriter()
    await asyncio.wait_for(ProxyServer._reject(Reader(), writer), 2)
    assert b" 503 " in writer.output
    assert read_cancelled.is_set() and writer.closed and writer.close_joined


@pytest.mark.asyncio
async def test_capacity_response_survives_body_delayed_past_rejection_cleanup(monkeypatch):
    stream = Stream()
    rejected_closed = asyncio.Event()
    async with fixture_proxy(stream, max_connections=1, total_seconds=30) as (proxy, calls), httpx.AsyncClient(trust_env=False) as client:
        original = proxy._reject

        async def observe_rejection(reader, writer):
            try:
                await original(reader, writer)
            finally:
                rejected_closed.set()

        monkeypatch.setattr(proxy, "_reject", observe_rejection)
        async with client.stream("POST", url(proxy), headers={"Authorization": "Bearer fixture-client"}, content=b"{}") as first:
            iterator = first.aiter_raw()
            await anext(iterator)

            async def delayed_body():
                await asyncio.wait_for(rejected_closed.wait(), 5)
                yield b"{}"

            response = await client.post(url(proxy), headers={
                "Authorization": "Bearer fixture-client", "Content-Length": "2",
            }, content=delayed_body())
            assert response.status_code == 503
            assert rejected_closed.is_set() and not proxy._rejections
            assert len(calls) == 1 and not stream.closed.is_set()


@pytest.mark.asyncio
async def test_shutdown_joins_stalled_capacity_rejection_and_active_owner(monkeypatch):
    stream = Stream()
    async with fixture_proxy(stream, max_connections=1, total_seconds=30) as (proxy, calls), httpx.AsyncClient(trust_env=False) as client:
        original = proxy._reject
        rejecting = asyncio.Event()
        rejected_closed = asyncio.Event()

        async def observe_rejection(reader, writer):
            rejecting.set()
            try:
                await original(reader, writer)
                # Keep the observed owner pending until shutdown even if a
                # loaded test host lets the ingress grace expire first.
                await asyncio.Event().wait()
            finally:
                rejected_closed.set()

        monkeypatch.setattr(proxy, "_reject", observe_rejection)
        async with client.stream("POST", url(proxy), headers={"Authorization": "Bearer fixture-client"}, content=b"{}") as first:
            iterator = first.aiter_raw()
            await anext(iterator)
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy.address[1])
            try:
                await asyncio.wait_for(rejecting.wait(), 2)
                assert b" 503 " in await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
                assert proxy._rejections and not rejected_closed.is_set()
                await asyncio.wait_for(proxy.aclose(), 2)
                assert rejected_closed.is_set() and stream.closed.is_set()
                assert not proxy._tasks and not proxy._rejections
                assert len(calls) == 1
                assert await asyncio.wait_for(reader.read(), 2) == b""
            finally:
                writer.close()
                await writer.wait_closed()


@pytest.mark.parametrize("target", ["//evil/v1/messages", "//../v1/messages", "/v1/../v1/messages",
                                    "/v1/%2e%2e/messages", "/v1\\messages"])
def test_only_origin_form_paths_reach_an_allowed_route(target):
    from maverick.model_proxy import route_allowed
    config = ProxyConfig(upstream="https://fixture.invalid/tenant-a/api", api_key="k",
                         client_token="c")  # pragma: allowlist secret
    assert route_allowed(config, "POST", "/v1/messages")
    assert not route_allowed(config, "POST", target)


@pytest.mark.asyncio
async def test_a_client_that_half_closes_still_gets_its_response():
    stream = Stream(chunks=(b"data: whole\n\n",))
    stream.release.set()

    async def slow(request):
        await asyncio.sleep(0.3)             # the client's EOF arrives first
        return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, stream=stream)

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(slow))
    proxy = await ProxyServer(ProxyConfig(
        upstream="https://fixture.invalid", api_key="fixture-upstream-key",  # pragma: allowlist secret
        client_token="fixture-client", listen_port=0, total_seconds=3), client=upstream).start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.address[1])
        body = b'{"model":"x"}'
        writer.write(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer fixture-client\r\n"
                     b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        await writer.drain()
        writer.write_eof()                                   # done sending; still reading
        response = await asyncio.wait_for(reader.read(), 5)
        writer.close()
    finally:
        await proxy.aclose()
        await upstream.aclose()
    assert b"200" in response.split(b"\r\n", 1)[0] and b"data: whole" in response


@pytest.mark.asyncio
async def test_idle_unauthenticated_sockets_cannot_lock_out_new_clients():
    """Before, sockets that never sent headers held every slot for 10 s each;
    now they hold at most half, and a newcomer displaces the oldest one."""
    stream = Stream()
    async with fixture_proxy(stream, max_connections=4, total_seconds=30) as (proxy, calls), \
            httpx.AsyncClient(trust_env=False) as client:
        idle = [await asyncio.open_connection("127.0.0.1", proxy.address[1]) for _ in range(6)]
        await asyncio.sleep(0.1)
        assert len(proxy._pre_auth) <= 2
        # The oldest idle sockets were displaced and closed by the proxy.
        reader, _ = idle[0]
        assert await asyncio.wait_for(reader.read(), 2) == b""
        async with client.stream("POST", url(proxy), headers={"Authorization": "Bearer fixture-client"},
                                 content=b"{}") as response:
            assert response.status_code == 200
            await asyncio.wait_for(anext(response.aiter_raw()), 5)
            assert len(calls) == 1
        for _, writer in idle:
            writer.close()
