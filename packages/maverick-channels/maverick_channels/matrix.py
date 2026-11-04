"""Matrix channel via matrix-nio (federated, end-to-end encryptable).

Set up:
  1. Create an account on a Matrix homeserver (matrix.org, self-hosted, etc.)
  2. Get an access token (via Element > Settings > Help & About)
  3. Set in config:
        [channels.matrix]
        enabled = true
        homeserver = "https://matrix.org"
        user_id = "@you:matrix.org"
        access_token = "${MATRIX_ACCESS_TOKEN}"

Requires::

    python -m pip install -e './packages/maverick-channels[matrix]'
"""
from __future__ import annotations

import logging
import os

from .base import Channel, IncomingMessage, is_allowed, normalize_allowlist
from .delivery import (
    DeliveryNotSent,
    DeliveryUnknown,
    chunk_idempotency_key,
    delivery_active,
    send_chunk,
)

log = logging.getLogger(__name__)

try:
    from nio import AsyncClient, MatrixRoom, RoomMessageText
    _HAVE_MATRIX = True
except ImportError:
    _HAVE_MATRIX = False
    AsyncClient = MatrixRoom = RoomMessageText = None  # type: ignore


class MatrixChannel(Channel):
    name = "matrix"

    def __init__(
        self,
        handler,
        homeserver: str,
        user_id: str,
        access_token: str | None = None,
        allowed_user_ids=None,
    ):
        super().__init__(handler)
        if not _HAVE_MATRIX:
            raise ImportError(
                "matrix-nio not installed. From the reviewed checkout run: "
                "python -m pip install -e './packages/maverick-channels[matrix]'"
            )
        self.homeserver = homeserver
        self.user_id = user_id
        self.access_token = access_token or os.environ.get("MATRIX_ACCESS_TOKEN")
        if not self.access_token:
            raise ValueError("MATRIX_ACCESS_TOKEN not set")
        # Without an allowlist any member of any room the bot joins drives
        # the agent. Require one (default-deny via base.is_allowed).
        self.allowed_user_ids = normalize_allowlist(
            allowed_user_ids, "MATRIX_ALLOWED_USER_IDS",
        )
        if not self.allowed_user_ids:
            raise ValueError("Set MATRIX_ALLOWED_USER_IDS to restrict access")
        self._client = AsyncClient(homeserver, user_id)
        self._client.access_token = self.access_token
        self._client.add_event_callback(self._on_message, RoomMessageText)
        # Drop messages older than channel start. matrix-nio's initial
        # sync_forever (no stored next_batch) replays each room's recent
        # timeline through this callback, so without a cutoff every restart
        # re-runs the agent swarm on old messages -- duplicate replies + real
        # LLM spend. Seeded in start(); ms epoch to match event.server_timestamp.
        self._start_ts_ms: int | None = None

    def _account(self):
        return self.homeserver.rstrip("/") + "|" + self.user_id

    def _authorized(self, msg, account):
        return (account == self._account() and msg.principal_id != self.user_id
                and is_allowed(msg.principal_id, self.allowed_user_ids))

    async def _send_saved(self, msg, reply, route):
        if reply.text:
            return await self.send(msg.user_id, reply.text)

    async def _on_message(self, room: MatrixRoom, event: RoomMessageText) -> None:
        if event.sender == self.user_id:
            return
        # Ignore backlog replayed by the initial sync (see __init__).
        ts = getattr(event, "server_timestamp", None)
        if self._start_ts_ms is not None and ts is not None and ts < self._start_ts_ms:
            return
        if not is_allowed(event.sender, self.allowed_user_ids):
            log.warning("unauthorized matrix access: sender=%s", event.sender)
            return
        msg = IncomingMessage(
            user_id=room.room_id,
            text=event.body,
            channel="matrix",
            raw=event,
            sender_id=event.sender,
            message_id=event.event_id,
        )
        account = self._account()
        return await self.process_message(msg, external_id=event.event_id, account=account,
            authorize=lambda: self._authorized(msg, account), idempotent=True,
            send=lambda reply: self._send_saved(msg, reply, {}))

    async def start(self) -> None:
        import time
        self._start_ts_ms = int(time.time() * 1000)
        log.info("Matrix channel syncing")
        account = self._account()
        async with self.recovery_worker(account=account,
                authorize=lambda msg: self._authorized(msg, account),
                send=self._send_saved, idempotent=True):
            await self._client.sync_forever(timeout=30000, full_state=True)

    async def send(self, user_id: str, text: str) -> None:
        payload = {"room_id": user_id, "message_type": "m.room.message",
                   "content": {"msgtype": "m.text", "body": text}}
        async def post():
            result = await self._client.room_send(**payload, tx_id=chunk_idempotency_key("text-0"))
            # matrix-nio returns error response objects instead of raising.
            # Only explicit nonacceptance permits a non-ambiguous retry.
            if getattr(result, "status_code", None) in {
                "M_FORBIDDEN", "M_UNKNOWN_TOKEN", "M_MISSING_TOKEN", "M_LIMIT_EXCEEDED",
                "M_BAD_JSON", "M_NOT_JSON", "M_INVALID_PARAM", "M_NOT_FOUND",
            }:
                raise DeliveryNotSent("Matrix rejected the reply")
            provider_id = getattr(result, "event_id", None)
            if delivery_active() and not isinstance(provider_id, str):
                raise DeliveryUnknown("Matrix reply acknowledgement has no event id")
            return provider_id
        return await send_chunk("text-0", payload, post, idempotent=True)

    async def stop(self) -> None:
        await self._client.close()
