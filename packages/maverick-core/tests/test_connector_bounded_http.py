"""Bounded ingestion and real loopback socket deadline/cancellation contracts."""
from __future__ import annotations

import asyncio
import contextlib
import gzip
import json
import threading
import time
import zlib
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import httpx
import pytest
from maverick import connector_attempts as attempts
from maverick.tools import Tool, ToolRegistry, _ssrf
from maverick.tools import _bounded_http as bounded
from maverick.tools._rest_connector import make_rest_tool


class CountedStream(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.reads = 0
        self.closed = False

    def __iter__(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    def close(self):
        self.closed = True


def deadline():
    invocation = attempts.ConnectorInvocation()
    _, expires = invocation.begin_attempt()
    return bounded.AttemptDeadline(invocation, expires)


@pytest.mark.parametrize("encoding,encode", [("identity", lambda b: b), ("gzip", gzip.compress),
                                              ("deflate", zlib.compress),
                                              ("deflate", lambda b: zlib.compress(b)[2:-4])])
def test_small_responses_decode_before_json_with_exact_caps(encoding, encode):
    body = json.dumps({"snowman": "☃", "items": [1, 2]}).encode()
    wire = encode(body)
    stream = CountedStream([wire[:1], wire[1:2], wire[2:]])
    limits = attempts.ConnectorLimits(wire_bytes=len(wire), decoded_bytes=len(body))
    with contextlib.closing(httpx.Response(200, headers={"content-encoding": encoding},
                                          stream=stream)) as response:
        raw = bounded.read_bounded(response, limits, deadline())
        assert bounded.parse_json_bounded(raw, limits, deadline()) == json.loads(body)
    assert stream.closed


@pytest.mark.parametrize("advertised", [False, True])
def test_wire_cap_stops_before_consuming_whole_body(advertised):
    stream = CountedStream([b"x" * 8] * 100)
    headers = {"content-length": "800"} if advertised else {}
    with contextlib.closing(httpx.Response(200, headers=headers, stream=stream)) as response:
        with pytest.raises(attempts.ConnectorResponseLimit, match="wire-byte"):
            bounded.read_bounded(response, attempts.ConnectorLimits(wire_bytes=10), deadline())
    assert stream.reads == (0 if advertised else 2)
    assert stream.closed


def test_compressed_bomb_is_capped_inside_decoder_before_all_wire_chunks():
    wire = gzip.compress(b"x" * 1_000_000)
    stream = CountedStream([wire[i:i + 16] for i in range(0, len(wire), 16)])
    with contextlib.closing(httpx.Response(200, headers={"content-encoding": "gzip"},
                                          stream=stream)) as response:
        with pytest.raises(attempts.ConnectorResponseLimit, match="decoded-byte"):
            bounded.read_bounded(response, attempts.ConnectorLimits(decoded_bytes=32), deadline())
    assert stream.reads < len(stream.chunks)
    assert stream.closed


@pytest.mark.parametrize("encoding,body", [("br", b"unhandled"),
                                           ("gzip", gzip.compress(b"ok", mtime=0)[:-1]),
                                           ("gzip", gzip.compress(b"a", mtime=0) + gzip.compress(b"b", mtime=0))],
                         ids=["unsupported-encoding", "incomplete-gzip", "multiple-gzip-members"])
def test_unsupported_incomplete_or_multiple_compressed_documents_refuse(encoding, body):
    with contextlib.closing(httpx.Response(200, headers={"content-encoding": encoding},
                                          stream=httpx.ByteStream(body))) as response:
        with pytest.raises(attempts.ConnectorResponseLimit):
            bounded.read_bounded(response, attempts.ConnectorLimits(), deadline())


@pytest.mark.parametrize("body,limits", [(b"[[[0]]]", attempts.ConnectorLimits(json_depth=2)),
                                        (b"[1,2,3,4]", attempts.ConnectorLimits(json_items=3))])
def test_json_structure_refused_before_object_allocation(monkeypatch, body, limits):
    def unexpected(_text):
        pytest.fail("JSON allocation must not begin beyond the parse budget")

    monkeypatch.setattr(bounded.json, "loads", unexpected)
    with pytest.raises(attempts.ConnectorResponseLimit, match="JSON structure"):
        bounded.parse_json_bounded(body, limits, deadline())


def test_json_escaped_braces_are_not_counted_as_structure():
    body = json.dumps({"text": '[{\\"' * 100}).encode()
    assert bounded.parse_json_bounded(body, attempts.ConnectorLimits(json_depth=1), deadline())


def test_each_socket_operation_receives_remaining_deadline_and_cancels_only_own_stream(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(bounded.time, "monotonic", lambda: now[0])
    calls = []
    closed = []

    class Stream:
        def read(self, _size, timeout):
            calls.append(timeout)
            return b"x"

        def write(self, _data, timeout):
            calls.append(timeout)

        def close(self):
            closed.append(self)

        def get_extra_info(self, _name):
            return None

    first, second = attempts.ConnectorInvocation(), attempts.ConnectorInvocation()
    own, other = Stream(), Stream()
    wrapped = bounded._DeadlineStream(own, bounded.AttemptDeadline(first, 110.0))
    wrapped_other = bounded._DeadlineStream(other, bounded.AttemptDeadline(second, 110.0))
    wrapped.read(1, timeout=30)
    now[0] = 107
    wrapped.write(b"x", timeout=30)
    assert calls == [10.0, 3.0]
    first.cancel()
    assert closed == [own]
    assert wrapped_other.read(1) == b"x"
    with pytest.raises(asyncio.CancelledError):
        wrapped.read(1)
    wrapped_other.close()


@pytest.fixture
def local_connector(monkeypatch):
    monkeypatch.setenv("BOUNDED_LOCAL_TOKEN", "local-fixture")
    monkeypatch.setattr(attempts, "configured_limits", lambda: attempts.ConnectorLimits(
        max_attempts=1, total_seconds=1.0, attempt_seconds=0.6))
    started = threading.Event()
    stopped = threading.Event()
    mode = {"value": "trickle"}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.close_connection = True
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            started.set()
            try:
                if mode["value"] == "stall":
                    # An owned local fixture only: peer closure wakes recv.
                    self.connection.settimeout(3)
                    self.connection.recv(1)
                else:
                    for _ in range(100):
                        self.wfile.write(b"1\r\n \r\n")
                        self.wfile.flush()
                        time.sleep(0.04)
            except OSError:
                pass
            finally:
                stopped.set()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    monkeypatch.setenv("BOUNDED_LOCAL_URL", f"http://127.0.0.1:{server.server_port}")
    tool = make_rest_tool(name="bounded_local", base_url_env="BOUNDED_LOCAL_URL",
                          token_env="BOUNDED_LOCAL_TOKEN", description="Loopback fixture")
    registry = ToolRegistry()
    registry.register(tool)
    registry.register(Tool("unrelated_fixture", "fixture", {}, lambda _args: "responsive"))
    try:
        yield SimpleNamespace(registry=registry, started=started, stopped=stopped, mode=mode)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_real_transport_trickle_has_absolute_deadline_and_event_loop_stays_live(local_connector):
    ticks = []

    async def exercise():
        with _ssrf.allow_private_hosts(["127.0.0.1"]):
            task = asyncio.create_task(local_connector.registry.run("bounded_local", {"op": "get", "path": "/"}))
            while not task.done():
                assert await local_connector.registry.run("unrelated_fixture", {}) == "responsive"
                ticks.append(time.monotonic())
                await asyncio.sleep(0.01)
            return await task

    began = time.monotonic()
    result = asyncio.run(exercise())
    elapsed = time.monotonic() - began
    assert result in {"ERROR: connector deadline; no complete response was admitted",
                      "ERROR: get request failed (transport failure)"}
    assert elapsed < 2.0
    assert len(ticks) > 5
    assert local_connector.started.is_set()
    assert local_connector.stopped.wait(1)


def test_real_transport_cancellation_closes_its_waiting_socket(local_connector, monkeypatch):
    monkeypatch.setattr(attempts, "configured_limits", lambda: attempts.ConnectorLimits(
        max_attempts=1, total_seconds=20, attempt_seconds=15))
    local_connector.mode["value"] = "stall"

    async def exercise():
        with _ssrf.allow_private_hosts(["127.0.0.1"]):
            task = asyncio.create_task(local_connector.registry.run("bounded_local", {"op": "get", "path": "/"}))
            assert await asyncio.to_thread(local_connector.started.wait, 2)
            began = time.monotonic()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert await asyncio.to_thread(local_connector.stopped.wait, 1)
            return time.monotonic() - began

    began = time.monotonic()
    assert asyncio.run(exercise()) < 1.5
    # asyncio.run joins the default executor too, so this also proves the
    # offloaded driver worker ended rather than merely detaching its awaiter.
    assert time.monotonic() - began < 2.5


def test_dns_timeout_is_checked_before_http_but_resolver_itself_is_synchronous(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(bounded.time, "monotonic", lambda: clock[0])
    invocation = attempts.ConnectorInvocation()
    timed = bounded.AttemptDeadline(invocation, 101.0)
    events = []

    def resolve(_host, *, require_public=False):
        events.append("DNS returned")
        clock[0] = 102
        return "93.184.216.34"

    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", resolve)
    with pytest.raises(attempts.ConnectorDeadlineExceeded):
        _ssrf.safe_client("https://fixture.example", attempt_deadline=timed)
    assert events == ["DNS returned"]


def test_deadline_transport_retains_ip_pin_tls_hostname_and_redirect_denial(monkeypatch):
    seen = []
    monkeypatch.setattr(
        _ssrf, "resolve_pinned_ip", lambda _host, *, require_public=False: "93.184.216.34"
    )

    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={"location": "https://unreviewed.example/"})

    monkeypatch.setattr(bounded, "DeadlineHTTPTransport", lambda _deadline: httpx.MockTransport(handler))
    with _ssrf.safe_client("https://fixture.example/items", attempt_deadline=deadline()) as client:
        assert client.get("https://fixture.example/items").status_code == 302
        with pytest.raises(_ssrf.BlockedHost):
            client.get("https://unreviewed.example/")
    assert len(seen) == 1
    assert seen[0].url.host == "93.184.216.34"
    assert seen[0].headers["host"] == "fixture.example"
    assert seen[0].extensions["sni_hostname"] == "fixture.example"


def test_invalid_limit_configuration_retains_bounded_defaults(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda: {"connector_limits": {
        "wire_bytes": -1, "max_attempts": True, "attempt_seconds": "inf", "json_depth": 99999}})
    assert attempts.configured_limits() == replace(attempts.ConnectorLimits(), json_depth=128)
