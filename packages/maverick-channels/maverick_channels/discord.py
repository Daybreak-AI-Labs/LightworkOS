"""Discord bot channel.

Uses the gateway WebSocket so no public webhook is needed. Set up:
  1. Create an application at https://discord.com/developers/applications
  2. Add a Bot user; enable Message Content Intent
  3. Copy the bot token to ${DISCORD_BOT_TOKEN}
  4. Invite the bot to your server with messages.read+send scope

Requires::

    python -m pip install -e './packages/maverick-channels[discord]'
"""
from __future__ import annotations

import asyncio
import logging
import os

from .base import Channel, IncomingMessage, is_allowed, normalize_allowlist
from .delivery import DeliveryNotSent, DeliveryUnknown, delivery_active, send_chunk

log = logging.getLogger(__name__)

try:
    import discord
    _HAVE_DISCORD = True
except ImportError:
    _HAVE_DISCORD = False
    discord = None  # type: ignore


def _no_mentions():
    """``AllowedMentions`` that suppress every ping (``@everyone``/``@here``,
    role, and user mentions) so the agent's reply text cannot be coerced into
    mass-notifying a guild.

    discord.py's default parses ALL mentions in the message content, so a reply
    that contains ``@everyone`` (trivially induced -- the inbound text is fed to
    the agent, and a prompt-injecting message can make it echo one) would ping
    the whole server under the bot's permissions. Pinning this on every send
    closes that amplification. Returns ``None`` when discord.py is absent (the
    real client never runs then; the agent path stays unit-testable)."""
    return discord.AllowedMentions.none() if _HAVE_DISCORD else None


async def _handle_discord_message(message, *, bot_user, channel):
    """Gate and durably dispatch through the Channel, never the SDK Client."""
    if message.author == bot_user:
        return
    # Gate on the AUTHOR id, not the channel id (which is what we reply to).
    author_id = str(getattr(message.author, "id", ""))
    if not is_allowed(author_id, channel.allowed_user_ids):
        log.warning("unauthorized discord access: author_id=%s", author_id)
        return
    msg = IncomingMessage(
        user_id=str(message.channel.id),
        text=message.content,
        channel="discord",
        raw=message,
        sender_id=author_id,
        message_id=str(message.id),
    )
    account = str(bot_user.id)

    async def send(reply):
        if reply.text:
            return await channel._send_chunks(message.channel, reply.text)

    return await channel.process_message(msg, external_id=msg.message_id, account=account,
        authorize=lambda: channel._authorized(msg, account), send=send)


class DiscordChannel(Channel):
    name = "discord"

    def __init__(self, handler, token: str | None = None, allowed_user_ids=None):
        super().__init__(handler)
        if not _HAVE_DISCORD:
            raise ImportError(
                "discord.py not installed. From the reviewed checkout run: "
                "python -m pip install -e './packages/maverick-channels[discord]'"
            )
        self.token = token or os.environ.get("DISCORD_BOT_TOKEN")
        if not self.token:
            raise ValueError("DISCORD_BOT_TOKEN not set")
        # Without an allowlist, ANY user in a channel the bot can see could
        # drive the agent. Require one (matches bluesky/telegram).
        self.allowed_user_ids = normalize_allowlist(
            allowed_user_ids, "DISCORD_ALLOWED_USER_IDS",
        )
        if not self.allowed_user_ids:
            raise ValueError("Set DISCORD_ALLOWED_USER_IDS to restrict access")

        intents = discord.Intents.default()
        intents.message_content = True
        # Belt-and-suspenders: a client-wide default so ANY send (the two here
        # and any future/library-internal one) can never ping @everyone/roles.
        self._client = _MaverickDiscordClient(
            channel=self, intents=intents,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def start(self) -> None:
        log.info("Discord channel starting")
        recovery = asyncio.create_task(self._recover(), name="discord-recovery-owner")
        try:
            await self._client.start(self.token)
        finally:
            recovery.cancel()
            await asyncio.gather(recovery, return_exceptions=True)

    def _authorized(self, msg, account):
        return (str(getattr(self._client.user, "id", "")) == account
                and msg.principal_id != account and is_allowed(msg.principal_id, self.allowed_user_ids))

    async def _send_saved(self, msg, reply, route):
        if reply.text:
            return await self.send(msg.user_id, reply.text)

    async def _recover(self):
        await self._client.wait_until_ready()
        account = str(self._client.user.id)
        async with self.recovery_worker(account=account,
                authorize=lambda msg: self._authorized(msg, account), send=self._send_saved):
            await asyncio.Future()

    @staticmethod
    async def _send_chunks(channel, text):
        from .formatting import split_for_discord
        receipt = None
        for index, chunk in enumerate(split_for_discord(text)):
            async def post(chunk=chunk):
                try:
                    result = await channel.send(chunk, allowed_mentions=_no_mentions())
                except Exception as exc:
                    if (_HAVE_DISCORD and isinstance(exc, discord.HTTPException)
                            and 400 <= exc.status < 500 and exc.status != 408):
                        raise DeliveryNotSent("Discord rejected the reply") from exc
                    raise
                provider_id = getattr(result, "id", None)
                if delivery_active() and not isinstance(provider_id, int):
                    raise DeliveryUnknown("Discord reply acknowledgement has no message id")
                return str(provider_id) if isinstance(provider_id, int) else None
            receipt = await send_chunk("text-" + str(index),
                {"channel": str(channel.id), "text": chunk, "mentions": "none"}, post)
        return receipt

    async def send(self, user_id: str, text: str) -> None:
        await self._client.wait_until_ready()
        channel = self._client.get_channel(int(user_id))
        if channel is None:
            raise DeliveryNotSent("Discord reply channel is unavailable")
        return await self._send_chunks(channel, text)

    async def stop(self) -> None:
        await self._client.close()


if _HAVE_DISCORD:
    class _MaverickDiscordClient(discord.Client):  # type: ignore[misc]
        def __init__(self, channel, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._channel = channel

        async def on_ready(self):  # type: ignore[override]
            log.info("Discord ready as %s", self.user)

        async def on_message(self, message):  # type: ignore[override]
            await _handle_discord_message(
                message, bot_user=self.user,
                channel=self._channel,
            )
else:
    _MaverickDiscordClient = None  # type: ignore
