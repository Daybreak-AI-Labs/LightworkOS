"""IRC channel adapter (RFC 1459 / 2812).

Drives Lightwork from an IRC channel or direct message. The agent joins one or
more channels on a server, answers messages from allow-listed authenticated IRC
accounts, and replies with PRIVMSG. TLS is supported
(``[channels.irc] tls = true``).

Set up (``[channels.irc]``)::

    server   = "irc.libera.chat"
    port     = 6697
    tls      = true
    nick     = "maverickbot"
    channels = ["#maverick"]
    # IRC_ALLOWED_ACCOUNTS, comma-separated, restricts who can drive the agent.
    # The IRC server must support the IRCv3 account-tag capability.

The wire protocol is line-based; the parse/format helpers below are pure and
unit-tested. The socket transport (:meth:`IRCChannel.start`) needs a live IRC
server, the same as every other external-service channel.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass

from .base import Channel, IncomingMessage, is_allowed, normalize_allowlist
from .delivery import DeliveryNotSent, DeliveryUnknown, delivery_active, send_chunk
from .transport_worker import TransportWorker

log = logging.getLogger(__name__)

# IRC lines are capped at 512 bytes including the "\r\n" and the
# ":prefix COMMAND target :" envelope. 400 leaves comfortable headroom.
_MAX_LINE_CHARS = 400


@dataclass(frozen=True)
class IRCMessage:
    prefix: str
    command: str
    params: list[str]
    trailing: str
    tags: dict[str, str]

    @property
    def sender_nick(self) -> str:
        """The nick from ``nick!user@host``, or the bare prefix."""
        return self.prefix.split("!", 1)[0] if self.prefix else ""

    @property
    def sender_account(self) -> str:
        """The authenticated IRCv3 account name, or empty if unauthenticated."""
        account = self.tags.get("account", "").strip()
        return "" if account == "*" else account


def _unescape_tag_value(value: str) -> str:
    """Decode IRCv3 message-tag escapes."""
    replacements = {
        ":": ";",
        "s": " ",
        "\\": "\\",
        "r": "\r",
        "n": "\n",
    }
    out: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value):
            i += 1
            out.append(replacements.get(value[i], value[i]))
        else:
            out.append(char)
        i += 1
    return "".join(out)


def _parse_tags(raw_tags: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for item in raw_tags.split(";"):
        if not item:
            continue
        key, sep, value = item.partition("=")
        tags[key] = _unescape_tag_value(value) if sep else ""
    return tags


def parse_line(line: str) -> IRCMessage | None:
    """Parse one IRC protocol line. Returns ``None`` for blank lines."""
    line = line.rstrip("\r\n")
    if not line:
        return None
    tags: dict[str, str] = {}
    if line.startswith("@"):
        raw_tags, _, line = line[1:].partition(" ")
        tags = _parse_tags(raw_tags)
    prefix = ""
    if line.startswith(":"):
        prefix, _, line = line[1:].partition(" ")
    # The trailing param starts at the first " :".
    head, sep, trailing = line.partition(" :")
    tokens = head.split()
    if not tokens:
        return None
    command = tokens[0].upper()
    params = tokens[1:]
    return IRCMessage(prefix=prefix, command=command, params=params,
                      trailing=trailing if sep else "", tags=tags)


def is_ping(msg: IRCMessage) -> bool:
    return msg.command == "PING"


def pong_for(msg: IRCMessage) -> str:
    """The PONG reply for a PING (echo its token)."""
    token = msg.trailing or (msg.params[0] if msg.params else "")
    return f"PONG :{token}"


def parse_privmsg(msg: IRCMessage, *, own_nick: str) -> tuple[str, str, str] | None:
    """For a PRIVMSG, return ``(sender_account, reply_target, text)``.

    ``sender_account`` is the authenticated account from the IRCv3 account tag.
    ``reply_target`` is the channel for a room message, or the sender nick for a
    DM (a PRIVMSG addressed to our own nick). Returns ``None`` for non-PRIVMSG."""
    if msg.command != "PRIVMSG" or not msg.params:
        return None
    target = msg.params[0]
    sender = msg.sender_account
    text = msg.trailing
    reply_target = msg.sender_nick if target == own_nick else target
    return sender, reply_target, text


def format_privmsg(target: str, text: str, *, max_chars: int = _MAX_LINE_CHARS) -> list[str]:
    """Split ``text`` into PRIVMSG lines for ``target`` (IRC has no newlines and
    a 512-byte line cap). Each physical newline starts a new PRIVMSG; long lines
    are hard-wrapped at ``max_chars``."""
    lines: list[str] = []
    byte_limit = 510 - len(f"PRIVMSG {target} :".encode())
    if max_chars < 1 or byte_limit < 4:
        raise ValueError("IRC reply target leaves no bounded text capacity")
    # Normalize ALL line terminators to \n before splitting. Splitting on \n
    # only left a bare \r embedded mid-line; IRC servers treat \r as a line
    # terminator, so reply text like "hi\rJOIN #evil" injected an arbitrary IRC
    # command under the bot's authenticated session. Each CR/LF now starts a new
    # (safely-prefixed) PRIVMSG instead.
    normalized = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    for raw in normalized.split("\n"):
        if not raw:
            continue
        chunk, size = [], 0
        for character in raw:
            width = len(character.encode("utf-8"))
            if chunk and (len(chunk) >= max_chars or size + width > byte_limit):
                lines.append(f"PRIVMSG {target} :{''.join(chunk)}")
                chunk, size = [], 0
            chunk.append(character)
            size += width
        lines.append(f"PRIVMSG {target} :{''.join(chunk)}")
    return lines or [f"PRIVMSG {target} :(no content)"]


class IRCChannel(Channel):
    name = "irc"

    def __init__(
        self,
        handler,
        server: str,
        *,
        nick: str = "maverick",
        port: int = 6697,
        tls: bool = True,
        channels=None,
        password: str | None = None,
        allowed_user_ids=None,
    ):
        super().__init__(handler)
        if not server:
            raise ValueError("IRC channel requires a server host")
        self.server = server
        self.nick = nick
        self.port = int(port)
        self.tls = bool(tls)
        self.channels = list(channels or [])
        self.password = password
        # Without an account allowlist any authenticated IRC account could drive
        # the agent; default-deny. Do not authorize by nick, which is spoofable.
        self.allowed_user_ids = normalize_allowlist(
            allowed_user_ids, "IRC_ALLOWED_ACCOUNTS",
        )
        if not self.allowed_user_ids:
            raise ValueError(
                "Set IRC_ALLOWED_ACCOUNTS to restrict who can drive the agent",
            )
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._running = False
        self._write_lock = asyncio.Lock()
        self._worker = None
        self._reader_task = None
        self._stop_task = None
        self._whois = {}
        self._session_id = uuid.uuid4().hex
        self._sequence = 0

    def _account(self):
        return f"{self.server.casefold()}:{self.port}:{self.tls}:{self.nick.casefold()}"

    async def _send_line(self, line: str) -> None:
        if self._writer is None:
            raise DeliveryNotSent("IRC transport is not connected")
        line = line.replace("\r", "").replace("\n", "")
        data = (line + "\r\n").encode("utf-8", errors="replace")
        if len(data) > 512:
            raise DeliveryNotSent("IRC line exceeds the wire byte bound")
        # Construction-only test callers may bypass __init__.
        if not hasattr(self, "_write_lock"):
            self._write_lock = asyncio.Lock()
        async with self._write_lock:
            self._writer.write(data)
            await asyncio.wait_for(self._writer.drain(), timeout=5)

    async def _read_transport(self):
        try:
            while self._running:
                raw = await self._reader.readline()
                if not raw:
                    return
                try:
                    await self._handle_raw(raw.decode("utf-8", errors="replace"))
                except Exception:
                    log.warning("IRC input was not admitted; transport intake requires review")
        finally:
            for pending in self._whois.values():
                if not pending["future"].done():
                    pending["future"].set_result(None)

    async def start(self) -> None:
        self._stop_task = None
        self._reader, self._writer = await asyncio.open_connection(self.server, self.port, ssl=self.tls, limit=65536)
        self._running = True
        self._session_id, self._sequence = uuid.uuid4().hex, 0
        account = self._account()
        self._worker = TransportWorker(self, account=account, send=self._send_saved,
            authorize=lambda message: account == self._account() and is_allowed(message.sender_id, self.allowed_user_ids)).start()
        try:
            if self.password:
                await self._send_line(f"PASS {self.password}")
            await self._send_line("CAP LS 302")
            # A CAP REQ is all-or-nothing, so ask for each capability on its
            # own: a server without message-tags must not also drop account-tag.
            await self._send_line("CAP REQ :account-tag")
            await self._send_line("CAP REQ :message-tags")
            await self._send_line(f"NICK {self.nick}")
            await self._send_line(f"USER {self.nick} 0 * :Lightwork agent")
            await self._send_line("CAP END")
            for channel in self.channels:
                await self._send_line(f"JOIN {channel}")
            self._reader_task = asyncio.create_task(self._read_transport(), name="irc-reader")
            await self._reader_task
        except asyncio.CancelledError:
            if self._running:
                raise
        finally:
            await self.stop()

    async def _handle_raw(self, raw: str):
        msg = parse_line(raw)
        if msg is None:
            return None
        if is_ping(msg):
            await self._send_line(pong_for(msg))
            return None
        if msg.command == "CAP" and len(msg.params) >= 2 and msg.params[1] == "NAK":
            log.warning("IRC server refused capability %s (account-tag is needed to authorise senders)",
                        msg.trailing)
            return None
        if msg.command in {"330", "318", "401"} and len(msg.params) >= 2:
            pending = self._whois.get(msg.params[1].casefold())
            if pending:
                if msg.command == "330" and len(msg.params) >= 3:
                    pending["account"] = msg.params[2]
                elif not pending["future"].done():
                    pending["future"].set_result(pending.get("account"))
            return None
        parsed = parse_privmsg(msg, own_nick=self.nick)
        if parsed is None or msg.sender_nick.casefold() == self.nick.casefold():
            return None
        sender, reply_target, text = parsed
        if not is_allowed(sender, self.allowed_user_ids):
            return None
        direct = msg.params[0].casefold() == self.nick.casefold()
        if not direct and reply_target.casefold() not in {channel.casefold() for channel in self.channels}:
            return None
        self._sequence += 1
        identity = msg.tags.get("msgid") or f"session:{self._session_id}:{self._sequence}"
        incoming = IncomingMessage(user_id=reply_target, text=text, channel=self.name,
                                   sender_id=sender, message_id=identity)
        route = {"direct": direct,
                 "identity_scope": "provider" if msg.tags.get("msgid") else "connection"}
        if self._worker is not None:
            return await self._worker.submit(incoming, external_id=identity, route=route)
        account = self._account()
        async def send_saved(reply):
            return await self._send_saved(incoming, reply, route)
        return await self.process_message(incoming, external_id=identity, account=account, route=route,
            authorize=lambda: account == self._account() and is_allowed(sender, self.allowed_user_ids), send=send_saved)

    async def _resolve_account(self, nick):
        key = nick.casefold()
        existing = self._whois.get(key)
        if existing:
            return await asyncio.wait_for(asyncio.shield(existing["future"]), timeout=5)
        future = asyncio.get_running_loop().create_future()
        self._whois[key] = {"future": future}
        try:
            await self._send_line(f"WHOIS {nick}")
            return await asyncio.wait_for(future, timeout=5)
        except Exception as exc:
            raise DeliveryNotSent("IRC reply target account could not be verified") from exc
        finally:
            self._whois.pop(key, None)
            if not future.done():
                future.cancel()

    async def _send_saved(self, message, reply, route):
        if reply.text:
            if not route["direct"] and message.user_id.casefold() not in {channel.casefold() for channel in self.channels}:
                raise DeliveryNotSent("IRC reply channel is no longer configured")
            expected = message.sender_id if route["direct"] else None
            return await self._send_chunks(message.user_id, reply.text, expected_account=expected)

    async def _send_chunks(self, user_id, text, *, expected_account=None):
        for index, line in enumerate(format_privmsg(user_id, text)):
            if expected_account is not None:
                current = await self._resolve_account(user_id)
                if not current or current.casefold() != expected_account.casefold():
                    raise DeliveryNotSent("IRC nickname no longer belongs to the admitted caller")
            async def write(line=line):
                await self._send_line(line)
                return "local-wire-write-only"
            await send_chunk(f"irc-{index}", line, write)
        if delivery_active():
            # drain() only confirms local buffering, not server acceptance or
            # delivery. Hold the outer operation rather than replaying it.
            raise DeliveryUnknown("IRC remote delivery has no acknowledgement")

    async def send(self, user_id: str, text: str) -> None:
        return await self._send_chunks(user_id, text)

    async def _finish_stop(self):
        if self._worker is not None:
            await self._worker.close()
        self._running = False
        if self._writer is not None:
            try:
                await self._send_line("QUIT :Lightwork shutting down")
            except Exception:
                pass
            self._writer.close()
            try:
                await asyncio.wait_for(self._writer.wait_closed(), timeout=5)
            except Exception:
                log.warning("IRC socket closure remains unconfirmed")
        if self._reader_task is not None and not self._reader_task.done():
            self._reader_task.cancel()
            done, _ = await asyncio.wait([self._reader_task], timeout=5)
            if self._reader_task in done:
                try:
                    self._reader_task.result()
                except (asyncio.CancelledError, Exception):
                    pass
            else:
                log.warning("IRC reader shutdown remains unconfirmed")

    async def stop(self) -> None:
        if self._stop_task is None:
            self._stop_task = asyncio.create_task(self._finish_stop(), name="irc-stop")
        await asyncio.shield(self._stop_task)


__all__ = [
    "IRCChannel", "IRCMessage", "parse_line", "parse_privmsg",
    "format_privmsg", "is_ping", "pong_for",
]
