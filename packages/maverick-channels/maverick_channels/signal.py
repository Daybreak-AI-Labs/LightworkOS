"""Signal channel via signal-cli jsonRpc daemon.

Set up (one-time):
  1. Install signal-cli (https://github.com/AsamK/signal-cli)
  2. Register your number:  signal-cli -u +12345550199 register
  3. Verify:                signal-cli -u +12345550199 verify <code>
  4. Set [channels.signal] phone_number = "+12345550199" in config

This adapter spawns signal-cli in jsonRpc mode and pipes JSON over
stdin/stdout. No public network exposure needed; everything happens on
the local machine.

Requires signal-cli installed on PATH (Java runtime under the hood).
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil

from .base import Channel, IncomingMessage, is_allowed, normalize_allowlist
from .delivery import DeliveryNotSent, DeliveryUnknown, send_chunk
from .transport_worker import TransportWorker

log = logging.getLogger(__name__)
RPC_TIMEOUT_SECONDS = 15.0
STOP_TIMEOUT_SECONDS = 5.0


class SignalChannel(Channel):
    name = "signal"

    def __init__(
        self,
        handler,
        phone_number: str,
        signal_cli_path: str | None = None,
        allowed_user_ids=None,
    ):
        super().__init__(handler)
        self.phone_number = phone_number
        # Without an allowlist any Signal sender who knows the number drives
        # the agent. Require one (default-deny via base.is_allowed). Checked
        # before the signal-cli probe so a misconfigured allowlist fails with
        # a clear error.
        self.allowed_user_ids = normalize_allowlist(
            allowed_user_ids, "SIGNAL_ALLOWED_USER_IDS",
        )
        if not self.allowed_user_ids:
            raise ValueError(
                "Set SIGNAL_ALLOWED_USER_IDS to restrict who can drive the agent"
            )
        self.signal_cli_path = signal_cli_path or shutil.which("signal-cli")
        if not self.signal_cli_path:
            raise FileNotFoundError(
                "signal-cli not found on PATH. Install from "
                "https://github.com/AsamK/signal-cli"
            )
        self._proc: asyncio.subprocess.Process | None = None
        self._req_id = 0
        self._pending_rpc = {}
        self._write_lock = asyncio.Lock()
        self._reader_task = None
        self._stderr_task = None
        self._worker = None
        self._stderr_bytes = 0
        self._stopping = False
        self._stop_task = None

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    async def _send_rpc(self, method: str, params: dict | None = None):
        if self._proc is None or self._proc.stdin is None or self._stopping:
            raise DeliveryNotSent("Signal transport is not accepting sends")
        if len(self._pending_rpc) >= 32:
            raise DeliveryNotSent("Signal RPC capacity reached")
        identity = self._next_id()
        request = {"jsonrpc": "2.0", "method": method, "id": identity}
        if params:
            request["params"] = params
        future = asyncio.get_running_loop().create_future()
        self._pending_rpc[identity] = future
        try:
            async with self._write_lock:
                self._proc.stdin.write((json.dumps(request) + "\n").encode())
                await asyncio.wait_for(self._proc.stdin.drain(), timeout=5)
            response = await asyncio.wait_for(future, timeout=RPC_TIMEOUT_SECONDS)
            if "error" in response:
                error = response["error"]
                if isinstance(error, dict) and error.get("code") in {-32600, -32601, -32602}:
                    raise DeliveryNotSent("Signal rejected an invalid RPC request")
                raise DeliveryUnknown("Signal RPC send failed without confirmed nonacceptance")
            if "result" not in response:
                raise DeliveryUnknown("Signal RPC response has no confirmed result")
            return response["result"]
        except DeliveryNotSent:
            raise
        except Exception as exc:
            raise DeliveryUnknown("Signal RPC acceptance is unconfirmed") from exc
        finally:
            self._pending_rpc.pop(identity, None)
            if not future.done():
                future.cancel()
            elif not future.cancelled():
                future.exception()  # Consume a reader failure if the write failed first.

    async def _drain_stderr(self):
        stream = self._proc.stderr
        while True:
            data = await stream.read(4096)
            if not data:
                return
            self._stderr_bytes += len(data)
            # Consume continuously without retaining/logging possible secrets.

    async def _read_transport(self):
        try:
            while True:
                line = await self._proc.stdout.readline()
                if not line:
                    return
                try:
                    data = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if not isinstance(data, dict):
                    continue
                identity = data.get("id")
                if isinstance(identity, int) and identity in self._pending_rpc:
                    future = self._pending_rpc[identity]
                    if not future.done():
                        future.set_result(data)
                    continue
                if data.get("method") != "receive":
                    continue
                try:
                    await self._admit_receive(data)
                except Exception:
                    log.warning("Signal receive was not admitted; transport intake requires review")
        finally:
            for future in self._pending_rpc.values():
                if not future.done():
                    future.set_exception(DeliveryUnknown("Signal transport closed before acknowledgement"))

    async def _admit_receive(self, data):
        envelope = (data.get("params") or {}).get("envelope") or {}
        source = envelope.get("source", "")
        message = envelope.get("dataMessage") or {}
        text = message.get("message")
        if not text or not source or source == self.phone_number or not is_allowed(source, self.allowed_user_ids):
            return None
        timestamp = message.get("timestamp") or envelope.get("timestamp")
        if isinstance(timestamp, bool) or not str(timestamp or "").isdigit():
            raise ValueError("Signal receive has no stable message timestamp")
        identity = source + ":" + str(timestamp)
        incoming = IncomingMessage(user_id=source, sender_id=source, text=text,
                                   channel=self.name, message_id=identity)
        return await self._worker.submit(incoming, external_id=identity)

    async def start(self) -> None:
        self._stopping = False
        self._stop_task = None
        self._proc = await asyncio.create_subprocess_exec(
            self.signal_cli_path, "-u", self.phone_number, "jsonRpc",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, limit=1024 * 1024)
        account = self.phone_number
        async def send_saved(message, reply, route):
            if reply.text:
                return await self.send(message.user_id, reply.text)
        self._worker = TransportWorker(self, account=account, send=send_saved,
            authorize=lambda message: account == self.phone_number and message.sender_id != self.phone_number
                and is_allowed(message.sender_id, self.allowed_user_ids)).start()
        self._reader_task = asyncio.create_task(self._read_transport(), name="signal-rpc-reader")
        self._stderr_task = asyncio.create_task(self._drain_stderr(), name="signal-stderr-drain")
        try:
            await self._reader_task
        except asyncio.CancelledError:
            if not self._stopping:
                raise
        finally:
            await self.stop()

    async def send(self, user_id: str, text: str) -> None:
        async def call():
            result = await self._send_rpc("send", {"recipient": [user_id], "message": text})
            return str(result.get("timestamp", "")) if isinstance(result, dict) else str(result)
        return await send_chunk("signal-0", {"recipient": user_id, "text": text}, call)

    async def _finish_stop(self) -> None:
        # Keep the RPC reader alive while an accepted in-flight reply drains.
        if self._worker is not None:
            await self._worker.close()
        self._stopping = True
        proc = self._proc
        if proc is not None and proc.returncode is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass  # Child exited between EOF observation and termination.
            try:
                await asyncio.wait_for(proc.wait(), timeout=STOP_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                proc.kill()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=STOP_TIMEOUT_SECONDS)
                except asyncio.TimeoutError:
                    log.warning("Signal child exit remains unconfirmed")
        tasks = [task for task in (self._reader_task, self._stderr_task)
                 if task is not None and task is not asyncio.current_task()]
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            done, _ = await asyncio.wait(tasks, timeout=5)
            for task in done:
                try:
                    task.result()
                except (asyncio.CancelledError, Exception):
                    pass
            if len(done) != len(tasks):
                log.warning("Signal reader/drainer exit remains unconfirmed")

    async def stop(self) -> None:
        if self._stop_task is None:
            self._stop_task = asyncio.create_task(self._finish_stop(), name="signal-stop")
        await asyncio.shield(self._stop_task)
