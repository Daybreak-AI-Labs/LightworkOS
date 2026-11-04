"""Mattermost channel: a bot account that answers direct messages and @mentions.

Set up:
  1. In Mattermost, System Console > Integrations > Bot Accounts: create a bot
     and copy its access token.
  2. Add the bot to the channels it should listen in (direct messages to the
     bot work without this).
  3. Set in config (or on the dashboard's Channels page):
        [channels.mattermost]
        enabled = true
        url = "https://chat.example.com"
        bot_token = "..."              # MATTERMOST_BOT_TOKEN wins when set
        allowed_user_ids = ["alice"]    # Mattermost usernames or user ids

Uses the Mattermost REST API (v4) over HTTPS with the bot token as a bearer
credential: it polls the channels the bot belongs to for new posts, answers
direct messages and posts that @mention the bot, and replies in the same
thread. Messages older than the channel's start are never replayed, each
post is admitted to the durable delivery journal under its post id (so a
re-read post never runs twice), and saved replies are recovered after a
crash like every other channel.

Requires ``httpx`` (installed with the dashboard and most extras).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import time
from urllib.parse import urlsplit

from .base import (
    Channel,
    Handler,
    IncomingMessage,
    backoff_delay,
    is_allowed,
    normalize_allowlist,
)
from .delivery import DeliveryNotSent, DeliveryUnknown, send_chunk

log = logging.getLogger(__name__)

_API = "/api/v4"
_MAX_CHANNELS = 200
_MAX_POST_CHARS = 16000  # Mattermost's own limit is 16383
_ID_RE = re.compile(r"[a-z0-9]{26}")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def server_origin(url: str) -> str:
    """The Mattermost server address, refused unless it is https (plain http
    only for a server on this computer): the bot token rides every request."""
    text = (url or "").strip().rstrip("/")
    parts = urlsplit(text)
    if not parts.netloc or parts.query or parts.fragment or parts.username or parts.password:
        raise ValueError("Mattermost needs its server address, such as https://chat.example.com")
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in _LOCAL_HOSTS):
        return text
    raise ValueError("Mattermost's server address must start with https://")


class MattermostChannel(Channel):
    name = "mattermost"

    def __init__(
        self,
        handler: Handler,
        *,
        url: str,
        bot_token: str | None = None,
        allowed_user_ids=None,
        poll_interval: float = 10.0,
    ):
        super().__init__(handler)
        self.base_url = server_origin(url)
        self.bot_token = (os.environ.get("MATTERMOST_BOT_TOKEN") or bot_token or "").strip()
        if not self.bot_token:
            raise ValueError("Mattermost needs a bot access token (MATTERMOST_BOT_TOKEN)")
        # Default-deny like every other channel: without an allow list anyone
        # who can message the bot would drive the agent.
        self.allowed_user_ids = normalize_allowlist(
            allowed_user_ids, "MATTERMOST_ALLOWED_USER_IDS",
        )
        if not self.allowed_user_ids:
            raise ValueError("Set MATTERMOST_ALLOWED_USER_IDS to restrict access")
        self.poll_interval = max(2.0, float(poll_interval))
        self._me: dict | None = None
        self._start_ms: int | None = None
        self._since: dict[str, int] = {}
        self._usernames: dict[str, str] = {}
        self._stop_event = asyncio.Event()

    # ------------------------------------------------------------ HTTP
    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.bot_token}"}

    async def _get(self, path: str, params: dict | None = None):
        import httpx

        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(self.base_url + _API + path, headers=self._headers(),
                                        params=params)
            response.raise_for_status()
            return response.json()

    def _account(self) -> str:
        return self.base_url + ":" + hashlib.sha256(self.bot_token.encode()).hexdigest()

    async def _whoami(self) -> dict:
        if self._me is None:
            me = await self._get("/users/me")
            if not isinstance(me, dict) or not _ID_RE.fullmatch(str(me.get("id", ""))):
                raise ValueError("Mattermost did not return the bot account")
            self._me = {"id": me["id"], "username": str(me.get("username") or "")}
        return self._me

    async def _username(self, user_id: str) -> str:
        if user_id not in self._usernames:
            try:
                user = await self._get(f"/users/{user_id}")
                self._usernames[user_id] = str((user or {}).get("username") or "")
            except Exception:  # an unknown sender simply matches by id only
                self._usernames[user_id] = ""
        return self._usernames[user_id]

    # ------------------------------------------------------------ intake
    def _allowed(self, user_id: str, username: str) -> bool:
        return is_allowed(user_id, self.allowed_user_ids)

    def _text_for(self, post: dict, channel_type: str) -> str | None:
        """The request text, or None when the post is not addressed to the bot."""
        text = str(post.get("message") or "").strip()
        if channel_type == "D":
            return text or None
        handle = "@" + (self._me or {}).get("username", "")
        if len(handle) < 2 or handle.lower() not in text.lower():
            return None
        cleaned = re.sub(re.escape(handle) + r"\b", "", text, flags=re.IGNORECASE).strip()
        return cleaned or None

    async def _input(self, post: dict, channel_type: str) -> IncomingMessage | None:
        me = await self._whoami()
        sender = str(post.get("user_id") or "")
        if (not _ID_RE.fullmatch(sender) or sender == me["id"] or post.get("type")
                or post.get("delete_at")):
            return None  # bots' own posts, system messages and deleted posts
        created = int(post.get("create_at") or 0)
        if self._start_ms is not None and created < self._start_ms:
            return None  # never replay history from before the channel started
        text = self._text_for(post, channel_type)
        if text is None:
            return None
        username = await self._username(sender)
        if not self._allowed(sender, username):
            log.warning("unauthorized mattermost access: sender=%s", sender)
            return None
        return IncomingMessage(user_id=str(post.get("channel_id") or ""), sender_id=sender,
                               text=text, channel=self.name, raw=post,
                               message_id=str(post.get("id") or ""))

    async def _dispatch(self, post: dict, channel_type: str) -> None:
        msg = await self._input(post, channel_type)
        if msg is None or not _ID_RE.fullmatch(msg.message_id or "") or not _ID_RE.fullmatch(msg.user_id):
            return
        account = self._account()
        route = {"channel_id": msg.user_id, "root_id": str(post.get("root_id") or msg.message_id)}
        username = self._usernames.get(msg.sender_id or "", "")

        async def send_saved(reply):
            if reply.text:
                return await self._post(route["channel_id"], reply.text, route["root_id"])

        await self.process_message(
            msg, external_id=msg.message_id, account=account, route=route,
            authorize=lambda: account == self._account() and self._allowed(msg.sender_id, username),
            send=send_saved)

    async def _poll_once(self) -> int:
        """Read new posts from every channel the bot belongs to; returns how
        many posts were looked at."""
        me = await self._whoami()
        channels = await self._get(f"/users/{me['id']}/channels")
        if not isinstance(channels, list):
            raise ValueError("Mattermost returned an unexpected channel list")
        seen = 0
        for channel in channels[:_MAX_CHANNELS]:
            channel_id = str((channel or {}).get("id") or "")
            if not _ID_RE.fullmatch(channel_id):
                continue
            since = self._since.get(channel_id, self._start_ms or 0)
            page = await self._get(f"/channels/{channel_id}/posts", {"since": since})
            posts = (page or {}).get("posts") or {}
            if not isinstance(posts, dict):
                continue
            ordered = sorted((p for p in posts.values() if isinstance(p, dict)),
                             key=lambda p: int(p.get("create_at") or 0))
            for post in ordered:
                seen += 1
                stamp = max(int(post.get("update_at") or 0), int(post.get("create_at") or 0))
                self._since[channel_id] = max(self._since.get(channel_id, since), stamp)
                try:
                    await self._dispatch(post, str(channel.get("type") or ""))
                except Exception:
                    log.warning("mattermost admitted input requires recovery")
        return seen

    # ------------------------------------------------------------ replies
    async def _post(self, channel_id: str, text: str, root_id: str = "") -> str:
        import httpx

        body = {"channel_id": channel_id, "message": text[:_MAX_POST_CHARS]}
        if root_id:
            body["root_id"] = root_id

        async def create():
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(self.base_url + _API + "/posts",
                                             headers=self._headers(), json=body)
            if 400 <= response.status_code < 500 and response.status_code not in {408, 429}:
                raise DeliveryNotSent("Mattermost rejected the reply")
            if response.status_code >= 400:
                raise DeliveryUnknown("Mattermost reply acceptance is unconfirmed")
            return str((response.json() or {}).get("id", ""))

        return await send_chunk("post-0", body, create)

    async def send(self, user_id: str, text: str) -> None:
        """Post ``text`` to a Mattermost channel id (the reply target)."""
        await self._post(user_id, text)

    async def send_threaded(self, user_id: str, text: str, *, reply_to: str | None = None) -> None:
        await self._post(user_id, text, reply_to or "")

    # ------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        self._start_ms = int(time.time() * 1000)
        errors = 0
        await self._whoami()
        log.info("Mattermost channel started (server=%s)", self.base_url)

        async def send_saved(msg, reply, route):
            if reply.text:
                return await self._post(route["channel_id"], reply.text, route.get("root_id", ""))

        while not self._stop_event.is_set():
            try:
                await self._poll_once()
                errors = 0
            except Exception as exc:
                errors += 1
                log.warning("mattermost poll failed: %s", exc)
            account = self._account()
            try:
                await self.recover_messages(
                    account=account, send=send_saved,
                    authorize=lambda msg, account=account: account == self._account() and self._allowed(
                        msg.sender_id, self._usernames.get(msg.sender_id or "", "")))
            except Exception:
                log.warning("mattermost saved delivery recovery remains incomplete")
            try:
                await asyncio.wait_for(self._stop_event.wait(),
                                       timeout=backoff_delay(self.poll_interval, errors))
            except asyncio.TimeoutError:
                pass

    async def stop(self) -> None:
        self._stop_event.set()


__all__ = ["MattermostChannel", "server_origin"]
