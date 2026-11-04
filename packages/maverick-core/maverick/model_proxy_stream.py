"""Owned HTTP/1.1 proxy lifecycle: bounded admission and backpressured streams."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

import h11
import httpx

from .model_proxy import authenticate, build_request, route_allowed, strip_response_headers

log = logging.getLogger(__name__)
CHUNK_BYTES = 16384
MAX_HEADER_BYTES = 65536


class ProxyHTTPError(Exception):
    def __init__(self, status: int, message: bytes):
        self.status = status
        self.message = message
        super().__init__(message.decode("ascii", errors="replace"))


@asynccontextmanager
async def forward_stream(config, client, method, path, headers, body):
    """The caller owns this response until its stream finishes or is cancelled."""
    if len(body) > config.max_request_bytes:
        raise ProxyHTTPError(413, b"proxy request body limit exceeded")
    url, forwarded = build_request(config, path, headers)
    from .governed_http import admit_client_request

    admit_client_request(client, url)
    async with client.stream(
        method, url, headers=forwarded, content=body,
        follow_redirects=False, timeout=config.total_seconds,
    ) as response:
        length = response.headers.get("content-length")
        if length is not None:
            try:
                parsed_length = int(length)
                if parsed_length < 0:
                    raise ValueError("negative length")
                if parsed_length > config.max_response_bytes:
                    raise ProxyHTTPError(502, b"proxy upstream body limit exceeded")
            except ValueError as exc:
                raise ProxyHTTPError(502, b"proxy upstream body length invalid") from exc
        yield response.status_code, strip_response_headers(dict(response.headers)), response.aiter_raw()


class ProxyServer:
    """One immutable config, reusable HTTP pool, and explicitly owned requests.

    Connections serve one request and then close. This avoids unbounded pipeline
    buffering and gives the disconnect watcher sole ownership of request EOF.
    """

    def __init__(self, config, *, client=None):
        self.config = config
        self._owned_client = client is None
        self.client = client if client is not None else httpx.AsyncClient(
            follow_redirects=False, trust_env=False,
            limits=httpx.Limits(max_connections=config.max_connections, max_keepalive_connections=20),
        )
        self._tasks: set[asyncio.Task] = set()
        self._rejections: set[asyncio.Task] = set()
        self._server: asyncio.Server | None = None
        self._closing = False
        self._close_task: asyncio.Task | None = None
        # Connections that have not yet sent authenticated headers hold at most
        # half the slots. When that half is full, a new connection displaces
        # the OLDEST such socket: a real client sends its headers within
        # milliseconds, so idle sockets are the ones displaced, and they can
        # neither crowd out authenticated work nor lock out new clients.
        self._pre_auth: dict[asyncio.Task, dict] = {}
        self._pre_auth_cap = max(1, config.max_connections // 2)

    async def start(self):
        self._server = await asyncio.start_server(
            self._accept, self.config.listen_host, self.config.listen_port,
            limit=MAX_HEADER_BYTES, backlog=self.config.max_connections,
        )
        return self

    @property
    def address(self):
        assert self._server is not None and self._server.sockets
        return self._server.sockets[0].getsockname()

    def _accept(self, reader, writer):
        if self._closing or len(self._tasks) >= self.config.max_connections:
            if self._closing or len(self._rejections) >= min(16, self.config.max_connections):
                writer.close()
                return
            rejected = asyncio.create_task(self._reject(reader, writer))
            self._rejections.add(rejected)
            rejected.add_done_callback(self._rejections.discard)
            return
        if len(self._pre_auth) >= self._pre_auth_cap:
            oldest = next(iter(self._pre_auth))
            displaced = self._pre_auth.pop(oldest)
            displaced["pre_auth"] = False
            # Close the socket here too: a task cancelled before it first runs
            # never reaches its own cleanup.
            displaced["writer"].close()
            oldest.cancel()
        state = {"started": False, "pre_auth": True, "writer": writer}
        task = asyncio.create_task(self._serve(reader, writer, state))
        state["task"] = task
        self._pre_auth[task] = state
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    @staticmethod
    async def _reject(reader, writer):
        async def reply():
            # Report capacity before waiting for ingress: the bounded cleanup
            # can expire while a normal client is still sending its body.
            writer.write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            # Drain only a small declared body for graceful close; a hostile or
            # stalled rejection must not become another admitted job.
            headers = await reader.readuntil(b"\r\n\r\n")
            for line in headers.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1])
                    if 0 < length <= CHUNK_BYTES:
                        await reader.readexactly(length)

        try:
            await asyncio.wait_for(reply(), .25)
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), .1)
            except (OSError, asyncio.TimeoutError):
                pass

    async def aclose(self):
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close())
        cancelled = False
        while not self._close_task.done():
            try:
                await asyncio.shield(self._close_task)
            except asyncio.CancelledError:
                cancelled = True
        self._close_task.result()
        if cancelled:
            raise asyncio.CancelledError

    async def _close(self):
        self._closing = True
        if self._server is not None:
            self._server.close()
        tasks = tuple(self._tasks | self._rejections)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.difference_update(tasks)
        self._rejections.difference_update(tasks)
        if self._server is not None:
            # Python 3.12 waits for active connections here. Cancel their owners
            # first; otherwise shutdown waits for every original request timeout.
            await self._server.wait_closed()
        if self._owned_client:
            await self.client.aclose()

    async def serve_forever(self):
        assert self._server is not None
        try:
            await self._server.serve_forever()
        finally:
            await self.aclose()

    @staticmethod
    async def _event(connection, reader):
        while True:
            event = connection.next_event()
            if event is not h11.NEED_DATA:
                return event
            data = await reader.read(CHUNK_BYTES)
            connection.receive_data(data)

    def _authenticated(self, state):
        if state.get("pre_auth"):
            state["pre_auth"] = False
            self._pre_auth.pop(state.get("task"), None)

    async def _admit(self, connection, reader, writer, state=None):
        # An unauthenticated socket holds a slot only until its headers are
        # due: 10 s, not 30, bounds how long idle sockets can crowd out clients.
        request = await asyncio.wait_for(self._event(connection, reader),
                                         min(10, self.config.total_seconds))
        if not isinstance(request, h11.Request):
            raise ProxyHTTPError(400, b"invalid proxy request")
        headers = {key.decode("ascii"): value.decode("latin-1") for key, value in request.headers}
        method = request.method.decode("ascii")
        path = request.target.decode("ascii")
        if not authenticate(self.config, headers):
            raise ProxyHTTPError(401, b"proxy authentication required")
        if state is not None:
            self._authenticated(state)
        if not route_allowed(self.config, method, path):
            raise ProxyHTTPError(403, b"model proxy route not allowed")
        # Validate target before admitting any potentially large request body.
        try:
            build_request(self.config, path, headers)
        except ValueError as exc:
            raise ProxyHTTPError(403, b"model proxy upstream not allowed") from exc
        if int(headers.get("content-length", "0")) > self.config.max_request_bytes:
            raise ProxyHTTPError(413, b"proxy request body limit exceeded")
        if connection.they_are_waiting_for_100_continue:
            writer.write(connection.send(h11.InformationalResponse(status_code=100, headers=[])))
            await writer.drain()
        body = bytearray()
        while True:
            event = await self._event(connection, reader)
            if isinstance(event, h11.EndOfMessage):
                if connection.trailing_data[0]:
                    raise ProxyHTTPError(400, b"proxy pipelining is not supported")
                return method, path, headers, bytes(body)
            if not isinstance(event, h11.Data):
                raise ProxyHTTPError(400, b"incomplete proxy request body")
            if len(body) + len(event.data) > self.config.max_request_bytes:
                raise ProxyHTTPError(413, b"proxy request body limit exceeded")
            body.extend(event.data)

    async def _relay(self, connection, writer, admitted, state):
        method, path, headers, body = admitted
        async with forward_stream(self.config, self.client, method, path, headers, body) as response:
            status, response_headers, chunks = response
            response_headers["connection"] = "close"
            writer.write(connection.send(h11.Response(status_code=status, headers=list(response_headers.items()))))
            state["started"] = True
            await writer.drain()
            received = 0
            async for chunk in chunks:
                received += len(chunk)
                if received > self.config.max_response_bytes:
                    raise ProxyHTTPError(502, b"proxy upstream body limit exceeded")
                for offset in range(0, len(chunk), CHUNK_BYTES):
                    writer.write(connection.send(h11.Data(data=chunk[offset:offset + CHUNK_BYTES])))
                    await writer.drain()
            writer.write(connection.send(h11.EndOfMessage()))
            await writer.drain()

    async def _transaction(self, connection, reader, writer, state):
        admitted = await self._admit(connection, reader, writer, state)
        relay = asyncio.create_task(self._relay(connection, writer, admitted, state))
        disconnected = asyncio.create_task(reader.read(1))
        try:
            done, _ = await asyncio.wait((relay, disconnected), return_when=asyncio.FIRST_COMPLETED)
            if disconnected in done:
                try:
                    early = disconnected.result()
                except OSError:
                    early = None  # reset: the client is gone
                if early != b"" or state["started"]:
                    # A reset, a pipelined byte, or EOF once the response is
                    # streaming ends this owner (a streaming client that left
                    # must not keep a paid upstream stream running). Await
                    # cancellation before releasing its slot.
                    return
                # EOF before any response is a half-close: HTTP lets a client
                # stop sending once its request is complete and still read the
                # response. A client that is really gone surfaces as a write
                # error when the response starts.
            await relay
        finally:
            await _cancel_join(relay, disconnected)

    @staticmethod
    async def _error(writer, status, body):
        writer.write(
            f"HTTP/1.1 {status} Proxy Error\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()

    async def _serve(self, reader, writer, state=None):
        connection = h11.Connection(h11.SERVER, max_incomplete_event_size=MAX_HEADER_BYTES)
        state = {"started": False} if state is None else state
        try:
            await asyncio.wait_for(
                self._transaction(connection, reader, writer, state), self.config.total_seconds,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if not state["started"] and not writer.is_closing():
                if isinstance(exc, ProxyHTTPError):
                    status, body = exc.status, exc.message
                elif isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
                    status, body = 504, b"proxy request deadline exceeded"
                elif isinstance(exc, (h11.RemoteProtocolError, UnicodeError, ValueError)):
                    status, body = 400, b"invalid proxy request"
                else:
                    status, body = 502, b"proxy upstream request failed"
                try:
                    await asyncio.wait_for(self._error(writer, status, body), 1.0)
                except (OSError, asyncio.TimeoutError):
                    pass
            # After headers, closing WITHOUT EndOfMessage makes a broken stream
            # detectable. Never append a JSON error or fabricate a normal end.
            log.debug("model proxy request ended: %s", type(exc).__name__)
        finally:
            self._authenticated(state)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1.0)
            except (OSError, asyncio.TimeoutError):
                pass


async def _cancel_join(*tasks):
    for task in tasks:
        if not task.done():
            task.cancel()
    joined = asyncio.gather(*tasks, return_exceptions=True)
    cancelled = False
    while not joined.done():
        try:
            await asyncio.shield(joined)
        except asyncio.CancelledError:
            cancelled = True
    joined.result()
    if cancelled:
        raise asyncio.CancelledError
