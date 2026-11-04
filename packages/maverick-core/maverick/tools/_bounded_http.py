"""Per-call HTTP transport deadlines and bounded connector response ingestion.

Uses public HTTPX/httpcore transport and network-backend contracts. The caller
still resolves and pins DNS through _ssrf; there is no shared connection pool.
Wire bytes are decoded incrementally before any JSON parser sees the body.
"""
from __future__ import annotations

import contextlib
import json
import socket
import time
import zlib

import httpcore
import httpx

from ..connector_attempts import (
    ConnectorDeadlineExceeded,
    ConnectorInvocation,
    ConnectorLimits,
    ConnectorResponseLimit,
)


class AttemptDeadline:
    def __init__(self, invocation: ConnectorInvocation, deadline: float):
        self.invocation = invocation
        self.deadline = deadline

    def remaining(self, timeout: float | None = None) -> float:
        self.invocation.check()
        remaining = min(self.deadline - time.monotonic(), self.invocation.remaining())
        if remaining <= 0:
            raise ConnectorDeadlineExceeded("connector attempt deadline reached")
        return remaining if timeout is None else min(remaining, timeout)


class _DeadlineStream:
    """Every physical I/O wait gets the remaining absolute deadline."""

    def __init__(self, inner, deadline: AttemptDeadline):
        self._inner = inner
        self._deadline = deadline
        self._deadline.invocation.register_cancel(self._cancel)

    def _cancel(self):
        # This stream belongs to this per-invocation pool only. Shutdown wakes
        # an owned socket read; it cannot interrupt another invocation's socket.
        sock = self._inner.get_extra_info("socket")
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        self._inner.close()

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        result = self._inner.read(max_bytes, timeout=self._deadline.remaining(timeout))
        self._deadline.remaining()
        return result

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._inner.write(buffer, timeout=self._deadline.remaining(timeout))
        self._deadline.remaining()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        inner = self._inner.start_tls(ssl_context, server_hostname=server_hostname,
                                      timeout=self._deadline.remaining(timeout))
        self._deadline.invocation.unregister_cancel(self._cancel)
        return _DeadlineStream(inner, self._deadline)

    def get_extra_info(self, info):
        return self._inner.get_extra_info(info)

    def close(self):
        self._deadline.invocation.unregister_cancel(self._cancel)
        self._inner.close()


class _DeadlineBackend:
    def __init__(self, deadline: AttemptDeadline, inner=None):
        self._deadline = deadline
        self._inner = inner if inner is not None else httpcore.SyncBackend()

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        inner = self._inner.connect_tcp(
            host, port, timeout=self._deadline.remaining(timeout),
            local_address=local_address, socket_options=socket_options)
        return _DeadlineStream(inner, self._deadline)

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        inner = self._inner.connect_unix_socket(
            path, timeout=self._deadline.remaining(timeout), socket_options=socket_options)
        return _DeadlineStream(inner, self._deadline)

    def sleep(self, seconds):
        self._inner.sleep(min(seconds, self._deadline.remaining()))
        self._deadline.remaining()


@contextlib.contextmanager
def _httpx_errors():
    # Preserve typed classification without carrying upstream bodies/URLs into
    # the connector's public diagnostic. No private HTTPX exception map is used.
    try:
        yield
    except httpcore.TimeoutException as exc:
        raise httpx.TimeoutException("connector transport timeout") from exc
    except httpcore.NetworkError as exc:
        raise httpx.NetworkError("connector transport network error") from exc
    except httpcore.RemoteProtocolError as exc:
        raise httpx.RemoteProtocolError("connector transport remote protocol error") from exc
    except httpcore.ProtocolError as exc:
        raise httpx.ProtocolError("connector transport protocol error") from exc
    except httpcore.ProxyError as exc:
        raise httpx.ProxyError("connector transport proxy error") from exc


class _ResponseStream(httpx.SyncByteStream):
    def __init__(self, inner):
        self._inner = inner

    def __iter__(self):
        with _httpx_errors():
            yield from self._inner

    def close(self):
        self._inner.close()


class DeadlineHTTPTransport(httpx.BaseTransport):
    """A fresh, non-proxy HTTP/1 pool over a deadline-aware public backend."""

    def __init__(self, deadline: AttemptDeadline):
        deadline.remaining()
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(), max_connections=1,
            max_keepalive_connections=0, retries=0,
            network_backend=_DeadlineBackend(deadline))

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(scheme=request.url.raw_scheme, host=request.url.raw_host,
                             port=request.url.port, target=request.url.raw_path),
            headers=request.headers.raw, content=request.stream,
            extensions=request.extensions)
        with _httpx_errors():
            response = self._pool.handle_request(core_request)
        return httpx.Response(response.status, headers=response.headers,
                              stream=_ResponseStream(response.stream),
                              extensions=response.extensions)

    def close(self):
        self._pool.close()


def _decoder(encoding: str, first_bytes: bytes):
    if encoding == "gzip":
        return zlib.decompressobj(16 + zlib.MAX_WBITS)
    if encoding == "deflate":
        # RFC zlib-wrapped deflate and the common raw-deflate variant. Decide
        # before decoding; never retry an already decoded body without its cap.
        wrapped = (len(first_bytes) >= 2 and first_bytes[0] & 0x0F == 8
                   and int.from_bytes(first_bytes[:2], "big") % 31 == 0)
        return zlib.decompressobj(zlib.MAX_WBITS if wrapped else -zlib.MAX_WBITS)
    return None


def read_bounded(response: httpx.Response, limits: ConnectorLimits,
                 deadline: AttemptDeadline) -> bytes:
    """Read admitted wire bytes and incrementally cap decoded bytes before parse."""
    length = response.headers.get("content-length", "")
    if length.isdecimal() and int(length) > limits.wire_bytes:
        raise ConnectorResponseLimit("connector wire-byte limit exceeded")
    encoding = response.headers.get("content-encoding", "identity").strip().lower()
    if encoding not in {"", "identity", "gzip", "deflate"}:
        raise ConnectorResponseLimit("unsupported bounded content encoding")
    decoded = bytearray()
    wire = 0
    decoder = None
    prefix = b""
    for chunk in response.iter_raw():
        deadline.remaining()
        wire += len(chunk)
        if wire > limits.wire_bytes:
            raise ConnectorResponseLimit("connector wire-byte limit exceeded")
        if encoding in {"gzip", "deflate"}:
            if decoder is None:
                prefix += chunk
                if len(prefix) < 2:
                    continue
                decoder = _decoder(encoding, prefix)
                chunk, prefix = prefix, b""
            # max_length prevents a compressed bomb from materializing beyond
            # the remaining decoded-byte allowance inside zlib itself.
            data = decoder.decompress(chunk, limits.decoded_bytes - len(decoded) + 1)
            if decoder.unused_data:
                raise ConnectorResponseLimit("multiple compressed members are not admitted")
        else:
            data = chunk
        if len(decoded) + len(data) > limits.decoded_bytes:
            raise ConnectorResponseLimit("connector decoded-byte limit exceeded")
        decoded.extend(data)
    deadline.remaining()
    if encoding in {"gzip", "deflate"} and (decoder is None or not decoder.eof):
        raise ConnectorResponseLimit("incomplete compressed response")
    return bytes(decoded)


def parse_json_bounded(body: bytes, limits: ConnectorLimits, deadline: AttemptDeadline):
    """Bound nesting/item work before the JSON object allocator is invoked."""
    text = body.decode("utf-8-sig")
    depth = items = 0
    quoted = escaped = False
    for index, char in enumerate(text):
        if index % 4096 == 0:
            deadline.remaining()
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            items += 1
        elif char in "[{":
            depth += 1
            items += 1
        elif char in "]}":
            depth -= 1
        elif char == ",":
            items += 1
        if depth > limits.json_depth or items > limits.json_items:
            raise ConnectorResponseLimit("connector JSON structure limit exceeded")
    result = json.loads(text)
    deadline.remaining()
    return result
