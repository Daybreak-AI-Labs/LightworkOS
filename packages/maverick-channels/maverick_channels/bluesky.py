"""Bluesky / AT Protocol channel adapter.

Polls the user's notifications timeline for mentions + DMs, dispatches
each as an IncomingMessage. Replies go back via the AT Proto REST API.

Auth: env vars BLUESKY_HANDLE + BLUESKY_PASSWORD. The 'password' is an
app password generated at bsky.app -> Settings -> App Passwords; never
the account password.

Heavy deps deferred to import time; the optional install is
``python -m pip install -e './packages/maverick-channels[bluesky]'``
which pulls in httpx
(already a transitive of openai-compat providers).
"""
from __future__ import annotations

import asyncio
import logging
import os
from collections import deque

from .base import (
    Channel,
    Handler,
    IncomingMessage,
    backoff_delay,
    is_allowed,
    normalize_allowlist,
)
from .delivery import DeliveryNotSent, DeliveryUnknown, send_chunk
from .polling import PollCheckpoint, PollPage
from .polling import parse_timestamp as _parse_indexed_at
from .polling import utc_timestamp as _now_iso_z

log = logging.getLogger(__name__)


_API_BASE = "https://bsky.social/xrpc"
_POLL_INTERVAL_SEC = 30.0
# Bound on the recently-seen notification-uri dedup set (FIFO eviction). The
# poll window is the 50 newest notifications, so this is generous headroom.
_MAX_SEEN_URIS = 1000


class BlueskyChannel(Channel):
    """Bluesky AT Proto channel.

    Reuses the same Handler / IncomingMessage shape as the other
    channel adapters. Polls notifications every 30s; on a `mention`
    or `reply` event, dispatches to the handler and posts the reply
    as a thread reply.
    """

    name = "bluesky"

    def __init__(
        self,
        handler: Handler,
        *,
        handle: str | None = None,
        password: str | None = None,
        allowed_user_ids: set[str] | None = None,
        poll_interval: float = _POLL_INTERVAL_SEC,
    ):
        super().__init__(handler)
        self.handle = handle or os.environ.get("BLUESKY_HANDLE", "")
        self.password = password or os.environ.get("BLUESKY_PASSWORD", "")
        self.allowed_user_ids = normalize_allowlist(
            allowed_user_ids, "BLUESKY_ALLOWED_USER_IDS",
        )
        if not self.allowed_user_ids:
            raise ValueError(
                "Set BLUESKY_ALLOWED_USER_IDS to restrict access"
            )
        self.poll_interval = poll_interval
        self._session: dict = {}
        # ``_last_seen_indexed_at`` is a FLOOR seeded to startup time so a cold
        # start doesn't backfill history. Dedup is by notification ``uri`` (a
        # bounded recently-seen set), NOT a strict high-water-mark on the floor:
        # AT-proto indexedAt is not monotonic (clock skew / late server
        # indexing), so advancing a watermark to the newest timestamp silently
        # dropped a genuinely-new notification indexed a moment earlier.
        self._last_seen_indexed_at: str | None = None
        self._seen_uris: set[str] = set()
        self._seen_order: deque[str] = deque()
        self._running = False
        self._stop_event = asyncio.Event()

    async def _ensure_session(self) -> dict:
        if self._session.get("accessJwt"):
            return self._session
        try:
            import httpx
        except ImportError as e:
            raise RuntimeError(
                "httpx not installed. From the reviewed checkout run: "
                "python -m pip install -e './packages/maverick-channels[bluesky]'"
            ) from e
        if not self.handle or not self.password:
            raise RuntimeError(
                "Bluesky channel requires BLUESKY_HANDLE and BLUESKY_PASSWORD."
            )
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{_API_BASE}/com.atproto.server.createSession",
                json={"identifier": self.handle, "password": self.password},
            )
            resp.raise_for_status()
            self._session = resp.json()
        return self._session

    def _account(self):
        did = self._session.get("did")
        if not isinstance(did, str) or not did:
            raise ValueError("Bluesky authenticated account identity is unavailable")
        return _API_BASE + ":" + did

    async def _poll_once(self) -> list[dict]:
        import httpx

        await self._ensure_session()
        account = self._account()
        checkpoint = PollCheckpoint(self.name, account)
        async def initialize():
            return {"floor": self._last_seen_indexed_at or _now_iso_z()}
        row = await checkpoint.load(initialize)
        self._last_seen_indexed_at = row["floor"]
        async def fetch(state):
            params = {"limit": 50}
            if state["cursor"]:
                params["cursor"] = state["cursor"]
            session = await self._ensure_session()
            if account != self._account():
                raise PermissionError("Bluesky configured account changed during polling")
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(f"{_API_BASE}/app.bsky.notification.listNotifications",
                    headers={"Authorization": f"Bearer {session['accessJwt']}"}, params=params)
                if response.status_code == 401:
                    self._session = {}
                response.raise_for_status()
                payload = response.json() or {}
            from .polling import page_before_floor

            items = payload.get("notifications") or []
            cursor = payload.get("cursor") or None
            if page_before_floor(items, "indexedAt", state["floor"], inclusive=True):
                cursor = None
            return PollPage(items, cursor)
        async def admit(item, state):
            if item.get("reason") not in {"mention", "reply"}:
                return False
            timestamp, floor = _parse_indexed_at(item.get("indexedAt", "")), _parse_indexed_at(state["floor"])
            if timestamp is None or floor is None:
                raise ValueError("Bluesky notification has no valid history boundary")
            if timestamp <= floor:
                return False
            receipt = await self._admit(item)
            if receipt is None:
                return False
            uri = item["uri"]
            seen = uri in self._seen_uris
            if not seen:
                self._seen_uris.add(uri)
                self._seen_order.append(uri)
            while len(self._seen_order) > _MAX_SEEN_URIS:
                self._seen_uris.discard(self._seen_order.popleft())
            return not seen
        results = await checkpoint.drain(row, fetch, admit, refresh_head=True)
        self.poll_status = (await asyncio.to_thread(checkpoint.store.get, checkpoint.record_id))["status"]
        return results

    def _input(self, notif):
        author = notif.get("author") or {}
        sender = author.get("did") or author.get("handle") or "anonymous"
        if not is_allowed(sender, self.allowed_user_ids) or sender == self._session.get("did"):
            return None
        identity = str(notif.get("uri") or "")
        if not identity or not notif.get("cid"):
            raise ValueError("Bluesky notification requires a stable identity and reply binding")
        return IncomingMessage(user_id=sender, sender_id=sender,
            text=(notif.get("record") or {}).get("text", ""), channel=self.name, message_id=identity)

    async def _admit(self, notif):
        msg = self._input(notif)
        if msg is None:
            return None
        account = self._account()
        route = {"uri": notif["uri"], "cid": notif["cid"],
                 "record": {"reply": (notif.get("record") or {}).get("reply", {})}}
        return await self.admit_message(msg, external_id=msg.message_id, account=account, route=route,
            authorize=lambda: account == self._account() and is_allowed(msg.sender_id, self.allowed_user_ids))

    async def _dispatch(self, notif: dict) -> None:
        receipt = await self._admit(notif)
        if receipt is None:
            return
        msg, account = self._input(notif), self._account()
        async def send_saved(reply):
            if reply.text:
                return await self._reply(receipt["route"], reply.text)
        return await self.process_message(msg, external_id=msg.message_id, account=account, receipt=receipt,
            authorize=lambda: account == self._account() and is_allowed(msg.sender_id, self.allowed_user_ids), send=send_saved)

    async def _reply(self, parent_notif: dict, text: str) -> None:
        """Post a reply in-thread to a notification."""
        sess = await self._ensure_session()
        try:
            import httpx
        except ImportError:
            log.warning("bluesky: httpx not installed; dropping reply")
            return
        record = parent_notif.get("record") or {}
        reply_root = record.get("reply", {}).get("root") or {
            "uri": parent_notif.get("uri"),
            "cid": parent_notif.get("cid"),
        }
        result = ""
        for index, start in enumerate(range(0, max(len(text), 1), 300)):
            chunk = text[start:start + 300]
            body = {
                "repo": sess.get("did"),
                "collection": "app.bsky.feed.post",
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": chunk,
                    "createdAt": _now_iso_z(),
                    "reply": {
                        "root": reply_root,
                        "parent": {
                            "uri": parent_notif.get("uri"),
                            "cid": parent_notif.get("cid"),
                        },
                    },
                },
            }
            async def create(body=body):
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(f"{_API_BASE}/com.atproto.repo.createRecord",
                        headers={"Authorization": f"Bearer {sess['accessJwt']}"}, json=body)
                if 400 <= resp.status_code < 500 and resp.status_code != 408:
                    raise DeliveryNotSent("Bluesky rejected the reply")
                if resp.status_code >= 400:
                    raise DeliveryUnknown("Bluesky reply acceptance is unconfirmed")
                return (resp.json() or {}).get("uri", "")
            # A fresh transport timestamp is not part of immutable retry identity.
            result = await send_chunk(f"record-{index}", {"text": chunk, "route": parent_notif}, create)
        return result

    async def start(self) -> None:
        self._running = True
        errors = 0
        try:
            await self._ensure_session()
            log.info("Bluesky channel started (handle=%s)", self.handle)
            while not self._stop_event.is_set():
                try:
                    notifs = await self._poll_once()
                    errors = 0
                except Exception as e:
                    errors += 1
                    log.warning("bluesky poll failed: %s", e)
                    notifs = []
                for n in notifs:
                    try:
                        await self._dispatch(n)
                    except Exception:
                        log.warning("bluesky admitted input requires recovery")
                if self._session.get("did"):
                    account = self._account()
                    async def send_saved(msg, reply, route):
                        if reply.text:
                            return await self._reply(route, reply.text)
                    try:
                        await self.recover_messages(account=account, send=send_saved,
                            authorize=lambda msg, account=account: account == self._account() and is_allowed(msg.sender_id, self.allowed_user_ids))
                    except Exception:
                        log.warning("bluesky saved delivery recovery remains incomplete")
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=backoff_delay(self.poll_interval, errors),
                    )
                except asyncio.TimeoutError:
                    pass
        finally:
            self._running = False

    async def send(self, user_id: str, text: str) -> None:
        """Send a stand-alone message to a user (not in-thread)."""
        # Bluesky doesn't have proper DMs in the public API yet;
        # this falls back to a top-level post mentioning the user.
        sess = await self._ensure_session()
        try:
            import httpx
        except ImportError:
            log.warning("bluesky: httpx not installed; dropping message")
            return
        body = {
            "repo": sess.get("did"),
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": f"@{user_id}: {text[:280]}",
                "createdAt": _now_iso_z(),
            },
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            await client.post(
                f"{_API_BASE}/com.atproto.repo.createRecord",
                headers={"Authorization": f"Bearer {sess['accessJwt']}"},
                json=body,
            )

    async def stop(self) -> None:
        self._stop_event.set()
        self._running = False
