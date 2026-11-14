"""Mastodon channel adapter.

Polls the authenticated account's notifications timeline for mentions
+ DMs (direct visibility statuses) and dispatches them as
IncomingMessages.

Auth: env vars MASTODON_INSTANCE (e.g. "mastodon.social") and
MASTODON_ACCESS_TOKEN. Create an access token at
``<instance>/settings/applications`` with the ``read`` + ``write``
scopes.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re

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

log = logging.getLogger(__name__)


_POLL_INTERVAL_SEC = 30.0
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(html: str) -> str:
    """Mastodon returns toots as HTML; for the agent we want plain text."""
    text = _HTML_TAG_RE.sub("", html or "")
    # Decode the two entities Mastodon emits most often.
    return text.replace("&amp;", "&").replace("&quot;", '"').strip()


class MastodonChannel(Channel):
    """Mastodon channel using the public REST API.

    Default scope: mentions + direct-visibility statuses. Other
    notification kinds (favourite, reblog, follow) are ignored.
    """

    name = "mastodon"

    def __init__(
        self,
        handler: Handler,
        *,
        instance: str | None = None,
        access_token: str | None = None,
        allowed_user_ids: set[str] | None = None,
        poll_interval: float = _POLL_INTERVAL_SEC,
    ):
        super().__init__(handler)
        self.instance = (
            instance
            or os.environ.get("MASTODON_INSTANCE", "mastodon.social")
        ).strip().rstrip("/")
        self.access_token = (
            access_token or os.environ.get("MASTODON_ACCESS_TOKEN", "")
        )
        self.allowed_user_ids = normalize_allowlist(
            allowed_user_ids, "MASTODON_ALLOWED_USER_IDS",
        )
        if not self.allowed_user_ids:
            raise ValueError(
                "Set MASTODON_ALLOWED_USER_IDS to restrict access"
            )
        self.poll_interval = poll_interval
        self._last_seen_id: str | None = None
        self._running = False
        self._stop_event = asyncio.Event()

    @property
    def _base_url(self) -> str:
        # Force TLS: bearer tokens must never ride plaintext. An explicit
        # http:// scheme is upgraded to https://; a bare host gets https://.
        if self.instance.startswith("https://"):
            return self.instance
        if self.instance.startswith("http://"):
            return "https://" + self.instance[len("http://"):]
        return f"https://{self.instance}"

    def _headers(self) -> dict:
        if not self.access_token:
            raise RuntimeError(
                "Mastodon channel requires MASTODON_ACCESS_TOKEN."
            )
        return {"Authorization": f"Bearer {self.access_token}"}

    async def _poll_once(self) -> list[dict]:
        import httpx

        checkpoint = PollCheckpoint(self.name, self._account())
        row = await checkpoint.load(self._initialize_poll)
        async def fetch(state):
            params = {"types[]": "mention", "limit": 30, "since_id": state["watermark"]}
            if state["cursor"]:
                params["max_id"] = state["cursor"]
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(f"{self._base_url}/api/v1/notifications",
                                            headers=self._headers(), params=params)
                response.raise_for_status()
                items = response.json() or []
            ids = [int(item["id"]) for item in items]
            if ids != sorted(set(ids), reverse=True) or (state["cursor"] and ids and max(ids) >= int(state["cursor"])):
                raise ValueError("Mastodon notification ordering changed; range remains incomplete")
            candidate = str(max([int(state.get("candidate") or state["watermark"]), *ids]))
            # Requesting one extra empty page for an exact full-page boundary
            # is safe; accepting a short page completes the covered range.
            cursor = str(min(ids)) if len(items) == 30 else None
            return PollPage(items, cursor, {"candidate": candidate}, {"watermark": candidate, "candidate": None})
        async def admit(item, state):
            if int(item["id"]) <= int(state["watermark"]):
                return False
            return await self._admit(item) is not None
        results = await checkpoint.drain(row, fetch, admit)
        latest = await asyncio.to_thread(checkpoint.store.get, checkpoint.record_id)
        self._last_seen_id = latest["watermark"]
        self.poll_status = latest["status"]
        return results

    def _account(self):
        # No inbound envelope chooses the account. Token rotation deliberately
        # establishes a new configured identity when no stable account id is
        # available, while the server origin remains part of the binding.
        return self._base_url + ":" + hashlib.sha256(self.access_token.encode()).hexdigest()

    async def _initialize_poll(self):
        import httpx

        if self._last_seen_id is not None:
            return {"watermark": self._last_seen_id, "candidate": None}
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(f"{self._base_url}/api/v1/notifications", headers=self._headers(),
                                        params={"types[]": "mention", "limit": 1})
            response.raise_for_status()
            latest = response.json() or []
        watermark = str(int(latest[0]["id"])) if latest else "0"
        return {"watermark": watermark, "candidate": None}

    def _input(self, notif):
        source, author = notif.get("status") or {}, notif.get("account") or {}
        sender = author.get("acct") or author.get("username") or "anonymous"
        identity = str(notif.get("id") or "")
        if not is_allowed(sender, self.allowed_user_ids):
            return None
        if not identity or not source.get("id"):
            raise ValueError("Mastodon notification requires a stable identity and reply target")
        return IncomingMessage(user_id=sender, sender_id=sender, text=_strip_html(source.get("content", "")),
                               channel=self.name, message_id=identity)

    async def _admit(self, notif):
        msg = self._input(notif)
        if msg is None:
            return None
        account = self._account()
        source = notif["status"]
        route = {"status": {"id": source["id"], "visibility": source.get("visibility", "public")},
                 "account": {"acct": msg.user_id}}
        return await self.admit_message(msg, external_id=msg.message_id, account=account, route=route,
            authorize=lambda: account == self._account() and is_allowed(msg.sender_id, self.allowed_user_ids))

    async def _dispatch(self, notif: dict) -> None:
        receipt = await self._admit(notif)
        if receipt is None:
            return
        msg, account = self._input(notif), self._account()
        async def send_saved(reply):
            if reply.text:
                return await self._post_reply(receipt["route"]["status"], receipt["route"]["account"], reply.text)
        return await self.process_message(msg, external_id=msg.message_id, account=account, receipt=receipt,
            authorize=lambda: account == self._account() and is_allowed(msg.sender_id, self.allowed_user_ids), send=send_saved)

    async def _post_reply(self, parent_status: dict, account: dict, text: str) -> None:
        try:
            import httpx
        except ImportError:
            log.warning("mastodon: httpx not installed; dropping reply")
            return
        prefix = f"@{account.get('acct')} "
        chunk_size = 480 - len(prefix)
        if chunk_size <= 0:
            raise DeliveryNotSent("Mastodon reply address exceeds the status bound")
        result = ""
        for index, start in enumerate(range(0, max(len(text), 1), chunk_size)):
            body = {
                "status": prefix + text[start:start + chunk_size],
                "in_reply_to_id": parent_status.get("id"),
                "visibility": parent_status.get("visibility", "public"),
            }
            async def create(body=body):
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(f"{self._base_url}/api/v1/statuses", headers=self._headers(), data=body)
                if 400 <= resp.status_code < 500 and resp.status_code != 408:
                    raise DeliveryNotSent("Mastodon rejected the status")
                if resp.status_code >= 400:
                    raise DeliveryUnknown("Mastodon status acceptance is unconfirmed")
                return (resp.json() or {}).get("id", "")
            result = await send_chunk(f"status-{index}", body, create)
        return result

    async def _seed_cursor(self) -> None:
        """Set since_id to the newest existing notification so the first
        poll only returns mentions that arrive AFTER startup — otherwise
        a cold start replays up to 30 historical mentions (duplicate
        swarm runs + replies)."""
        checkpoint = PollCheckpoint(self.name, self._account())
        row = await checkpoint.load(self._initialize_poll)
        self._last_seen_id = row["watermark"]

    async def start(self) -> None:
        self._running = True
        errors = 0
        try:
            await self._seed_cursor()
            log.info("Mastodon channel started (instance=%s)", self.instance)
            while not self._stop_event.is_set():
                try:
                    notifs = await self._poll_once()
                    errors = 0
                except Exception as e:
                    errors += 1
                    log.warning("mastodon poll failed: %s", e)
                    notifs = []
                for n in notifs:
                    try:
                        await self._dispatch(n)
                    except Exception:
                        log.warning("mastodon admitted input requires recovery")
                account = self._account()
                async def send_saved(msg, reply, route):
                    if reply.text:
                        return await self._post_reply(route["status"], route["account"], reply.text)
                try:
                    await self.recover_messages(account=account, send=send_saved,
                        authorize=lambda msg, account=account: account == self._account() and is_allowed(msg.sender_id, self.allowed_user_ids))
                except Exception:
                    log.warning("mastodon saved delivery recovery remains incomplete")
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
        try:
            import httpx
        except ImportError:
            log.warning("mastodon: httpx not installed; dropping message")
            return
        # Direct-visibility status mentioning the user. Mastodon turns
        # this into a thread that the user gets notified about.
        body = {
            "status": f"@{user_id} {text}"[:480],
            "visibility": "direct",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            await client.post(
                f"{self._base_url}/api/v1/statuses",
                headers=self._headers(),
                data=body,
            )

    async def stop(self) -> None:
        self._stop_event.set()
        self._running = False
