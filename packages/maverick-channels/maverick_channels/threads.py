"""Threads channel via Meta's Threads API (graph.threads.net).

Why polling, not webhooks: Threads has a webhook product, but subscribing is
partner-gated (business verification + App Review advanced access) — a wall
for self-hosters. The self-host-friendly path is polling the REST edges with
a plain Threads access token, so that is what this adapter does.

Edge choice: ``GET /v1.0/{user_id}/replies`` — the Reply Management edge for
the configured user — polled every ``poll_seconds``. Replies in the user's
own threads are the conversational surface a self-hosted agent actually
answers (someone replied under the bot's post); the alternative mentions
edge needs an extra permission grant and misses replies that don't
@-mention the account, and Threads has no DM API at all. Each reply carries
``username``/``from`` so the *author* — not the transport — is
allowlist-checked (default-deny), and replies authored by the configured
account itself are skipped so the bot can never loop on its own replies.

Polling persists bounded continuation only after durable inbox admission.
Execution claims remain held after an unknown outcome; saved replies retry
only definitively rejected delivery operations, preserving container ids.

Outbound is the documented two-step publish: create a TEXT media container
(``POST /{user_id}/threads``, with ``reply_to_id`` when the target looks
like a media id — all digits, which is what the inbound flow passes), then
publish it (``POST /{user_id}/threads_publish``). Posts cap at 500 chars;
longer replies are chunked into sibling replies on the same target.

Config::

    [channels.threads]
    enabled = true
    access_token = "${THREADS_ACCESS_TOKEN}"
    user_id      = "17841400000000000"      # numeric Threads user id
    allowed_user_ids = ["yourhandle"]       # Threads usernames, no '@'
    poll_seconds = 30

Requires::

    python -m pip install -e './packages/maverick-channels[threads]'
"""
from __future__ import annotations

import asyncio
import logging
import os

from .base import (
    Channel,
    Handler,
    IncomingMessage,
    backoff_delay,
    is_allowed,
    normalize_allowlist,
)
from .delivery import DeliveryNotSent, DeliveryUnknown, send_chunk
from .polling import PollCheckpoint, PollPage, parse_timestamp, utc_timestamp

log = logging.getLogger(__name__)

THREADS_BASE = "https://graph.threads.net"
API_VERSION = "v1.0"
TEXT_LIMIT = 500  # Threads caps post text at 500 chars


class ThreadsChannel(Channel):
    name = "threads"

    def __init__(
        self,
        handler: Handler,
        access_token: str | None = None,
        user_id: str | None = None,
        allowed_user_ids=None,
        poll_seconds: float = 30,
    ):
        super().__init__(handler)
        self.access_token = access_token or os.environ.get("THREADS_ACCESS_TOKEN")
        self.user_id = user_id or os.environ.get("THREADS_USER_ID")
        if not all([self.access_token, self.user_id]):
            raise ValueError(
                "Threads credentials missing. Set access_token and user_id "
                "([channels.threads] or THREADS_ACCESS_TOKEN / THREADS_USER_ID env)."
            )
        # The token only proves WE can read the account; gate on the reply
        # AUTHOR (Threads username, no '@').
        self.allowed_user_ids = normalize_allowlist(allowed_user_ids, "THREADS_ALLOWED_USER_IDS")
        if not self.allowed_user_ids:
            raise ValueError(
                "Set THREADS_ALLOWED_USER_IDS to restrict who can drive the agent"
            )
        self.poll_seconds = float(poll_seconds)
        self._running = False
        self._stop_event = asyncio.Event()

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.access_token}"}

    # -- inbound (poll loop) ---------------------------------------------------

    async def _poll_once(self) -> list[dict]:
        import httpx

        account = self.user_id
        checkpoint = PollCheckpoint(self.name, account)
        async def initialize():
            return {"initial_page": True, "floor": None}
        row = await checkpoint.load(initialize)
        async def fetch(state):
            if account != self.user_id:
                raise PermissionError("Threads configured account changed during polling")
            params = {"fields": "id,text,username,from,timestamp", "limit": 25}
            if state["cursor"]:
                params["after"] = state["cursor"]
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(f"{THREADS_BASE}/{API_VERSION}/{account}/replies",
                                             headers=self._headers(), params=params)
                response.raise_for_status()
                payload = response.json() or {}
            items = payload.get("data") or []
            paging = payload.get("paging") or {}
            cursor = (paging.get("cursors") or {}).get("after") if paging.get("next") else None
            if paging.get("next") and not cursor:
                raise ValueError("Threads next page has no bounded opaque cursor")
            if state["initial_page"]:
                timestamps = [parse_timestamp(item.get("timestamp", "")) for item in items]
                floor = (min(timestamps).isoformat() if all(timestamps) and timestamps else
                         (utc_timestamp() if not items else None))
                if cursor and floor is None:
                    raise ValueError("Threads startup page requires timestamps before safe pagination")
                # Preserve the existing startup scope: only its first page is
                # eligible. A durable fixed floor prevents later history backfill.
                return PollPage(items, updates={"floor": floor, "initial_page": False})
            if cursor and not state["floor"]:
                raise ValueError("Threads pagination has no established history boundary")
            return PollPage(items, cursor)
        async def admit(item, state):
            if not state["initial_page"] and state["floor"]:
                timestamp = parse_timestamp(item.get("timestamp", ""))
                if timestamp is None:
                    raise ValueError("Threads reply has no valid history boundary")
                if timestamp < parse_timestamp(state["floor"]):
                    return False
            return await self._admit(item) is not None
        results = await checkpoint.drain(row, fetch, admit)
        self.poll_status = (await asyncio.to_thread(checkpoint.store.get, checkpoint.record_id))["status"]
        return results

    def _input(self, reply):
        reply_id, text = str(reply.get("id") or ""), str(reply.get("text") or "")
        sender = reply.get("from") or {}
        sender_id = str(sender.get("id") or "")
        if not text or not sender_id or sender_id == str(self.user_id) or not is_allowed(sender_id, self.allowed_user_ids):
            return None
        if not reply_id:
            raise ValueError("Threads reply requires a stable provider identity")
        return IncomingMessage(user_id=reply_id, text=text, channel=self.name,
                               message_id=reply_id, sender_id=sender_id)

    async def _admit(self, reply):
        incoming = self._input(reply)
        if incoming is None:
            return None
        account = self.user_id
        return await self.admit_message(incoming, external_id=incoming.message_id, account=account,
            authorize=lambda: account == self.user_id and is_allowed(incoming.sender_id, self.allowed_user_ids))

    async def _dispatch(self, reply: dict) -> None:
        receipt = await self._admit(reply)
        if receipt is None:
            return
        incoming, account = self._input(reply), self.user_id
        async def send_saved(result):
            if result.text:
                return await self.send(incoming.user_id, result.text)
        return await self.process_message(incoming, external_id=incoming.message_id, account=account,
            authorize=lambda: account == self.user_id and is_allowed(incoming.sender_id, self.allowed_user_ids),
            receipt=receipt, send=send_saved)

    async def start(self) -> None:
        self._running = True
        log.info("Threads channel started (user_id=%s)", self.user_id)
        errors = 0
        try:
            while not self._stop_event.is_set():
                try:
                    replies = await self._poll_once()
                    errors = 0
                except Exception as e:
                    errors += 1
                    log.warning("threads poll failed: %s", e)
                    replies = []
                for reply in replies:
                    try:
                        await self._dispatch(reply)
                    except Exception:
                        log.warning("threads admitted input requires recovery")
                account = self.user_id
                async def send_saved(msg, reply, route):
                    if reply.text:
                        return await self.send(msg.user_id, reply.text)
                try:
                    await self.recover_messages(account=account, send=send_saved,
                        authorize=lambda msg, account=account: account == self.user_id and is_allowed(msg.sender_id, self.allowed_user_ids))
                except Exception:
                    log.warning("threads saved delivery recovery remains incomplete")
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=backoff_delay(self.poll_seconds, errors),
                    )
                except asyncio.TimeoutError:
                    pass
        finally:
            self._running = False

    # -- outbound --------------------------------------------------------------

    async def send(self, user_id: str, text: str) -> None:
        """Publish ``text``, threaded under ``user_id`` when it is a media id.

        Two-step Threads publish: create a TEXT media container, then publish
        it. An all-digit ``user_id`` is treated as a media id to reply to
        (the inbound flow passes the reply id); anything else (e.g. a
        username — Threads has no DM or post-to-user API) publishes a
        standalone thread on the configured account. Chunks land as sibling
        replies to the same target.
        """
        try:
            import httpx
        except ImportError as e:
            raise RuntimeError(
                "httpx not installed. From the reviewed checkout run: "
                "python -m pip install -e './packages/maverick-channels[threads]'"
            ) from e
        base = f"{THREADS_BASE}/{API_VERSION}/{self.user_id}"
        reply_to = user_id if str(user_id or "").isdigit() else None
        chunks = [text[i:i + TEXT_LIMIT] for i in range(0, max(len(text), 1), TEXT_LIMIT)]
        for idx, chunk in enumerate(chunks):
            data = {"media_type": "TEXT", "text": chunk}
            if reply_to:
                data["reply_to_id"] = reply_to
            async def create(data=data):
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(f"{base}/threads", headers=self._headers(), data=data)
                self._check_send(response)
                identity = (response.json() or {}).get("id")
                if not identity:
                    raise DeliveryUnknown("Threads container identity is unconfirmed")
                return identity
            creation_id = await send_chunk(f"create-{idx}", data, create)
            async def publish(creation_id=creation_id):
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(f"{base}/threads_publish", headers=self._headers(),
                                                  data={"creation_id": creation_id})
                self._check_send(response)
                identity = (response.json() or {}).get("id")
                if not identity:
                    raise DeliveryUnknown("Threads published identity is unconfirmed")
                return identity
            await send_chunk(f"publish-{idx}", {"creation_id": creation_id}, publish)

    @staticmethod
    def _check_send(response):
        if 400 <= response.status_code < 500 and response.status_code != 408:
            raise DeliveryNotSent("Threads rejected the request")
        if response.status_code >= 400:
            raise DeliveryUnknown("Threads request acceptance is unconfirmed")

    async def stop(self) -> None:
        self._stop_event.set()
        self._running = False
