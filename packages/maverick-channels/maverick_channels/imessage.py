"""iMessage channel (macOS only).

Reads incoming messages from ~/Library/Messages/chat.db and sends via
AppleScript. Requires Full Disk Access permission for the Python
process (System Settings > Privacy & Security > Full Disk Access).

Not available on Linux / Windows.

Config::

    [channels.imessage]
    enabled = true
    poll_interval = 5

send() never interpolates message text into AppleScript source: escaping
alone would let LLM-controlled text containing `;`, `\\n`, or `$` break out
of a string literal and execute arbitrary AppleScript / shell. The send
path passes the script via stdin and the user-supplied text + handle as
positional argv to a parameterized `on run argv` script.
AppleScript treats argv items as literal strings -- no interpolation.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import platform
import sqlite3
import subprocess
from contextlib import closing
from pathlib import Path

from .base import Channel, IncomingMessage, is_allowed, normalize_allowlist
from .delivery import DeliveryNotSent, DeliveryUnknown, send_chunk

log = logging.getLogger(__name__)

CHAT_DB = Path.home() / "Library" / "Messages" / "chat.db"


_SEND_SCRIPT = (
    'on run argv\n'
    '    set theText to item 1 of argv\n'
    '    set theHandle to item 2 of argv\n'
    '    tell application "Messages"\n'
    '        send theText to buddy theHandle of '
    '(service 1 whose service type is iMessage)\n'
    '    end tell\n'
    'end run\n'
)


class iMessageChannel(Channel):  # noqa: N801 - product spelling
    name = "imessage"

    def __init__(self, handler, poll_interval: int = 5, allowed_user_ids=None):
        super().__init__(handler)
        if platform.system() != "Darwin":
            raise RuntimeError(
                "iMessage channel is macOS only (current platform: "
                f"{platform.system()})"
            )
        if not CHAT_DB.exists():
            raise FileNotFoundError(
                f"Messages database not found at {CHAT_DB}. Ensure Messages.app "
                "has been opened at least once and grant Full Disk Access."
            )
        self.allowed_user_ids = normalize_allowlist(
            allowed_user_ids, "IMESSAGE_ALLOWED_USER_IDS",
        )
        if not self.allowed_user_ids:
            raise ValueError("Set IMESSAGE_ALLOWED_USER_IDS to restrict access")
        self.poll_interval = poll_interval
        self._last_rowid: int | None = None
        self._stop = False

    @staticmethod
    def _account():
        return str(CHAT_DB.resolve())

    def _authorized(self, msg, account):
        return account == self._account() and is_allowed(msg.principal_id, self.allowed_user_ids)

    def _checkpoint(self, rowid=None):
        from maverick.channel_recovery import assert_checkpoint_ready
        from maverick.governed_records import GovernedRecordStore
        from maverick.privacy_ops import RecordConflict

        store = GovernedRecordStore("imessage-intake-cursors", "imc", "imessage_intake_cursor")
        record_id = "imc-" + hashlib.sha256(self._account().encode()).hexdigest()[:56]
        for _ in range(4):
            current = store.get(record_id)
            if current is not None:
                assert_checkpoint_ready(current)
            try:
                if current is None:
                    # First adoption skips historical Messages; subsequent
                    # restarts resume the durable checkpoint, never MAX(ROWID).
                    value = self._latest_rowid() if rowid is None else rowid
                    current = store.create({"id": record_id, "last_rowid": value},
                        action="initialize", actor="imessage", max_records=100)
                elif rowid is not None and rowid > current["last_rowid"]:
                    current = store.update(record_id, lambda row: row.update(last_rowid=rowid),
                        expected_revision=current["revision"], action="checkpoint", actor="imessage")
                return current["last_rowid"]
            except RecordConflict:
                continue
        raise RuntimeError("iMessage intake checkpoint is busy")

    async def _send_saved(self, msg, reply, route):
        if reply.text:
            return await self.send(msg.user_id, reply.text)

    async def _receive(self, handle, text, rowid, guid):
        account = self._account()
        if not is_allowed(handle, self.allowed_user_ids):
            self._last_rowid = await asyncio.to_thread(self._checkpoint, rowid)
            return
        msg = IncomingMessage(user_id=handle, text=text, channel=self.name, message_id=guid)
        receipt = await self.admit_message(msg, external_id=guid, account=account,
            authorize=lambda: self._authorized(msg, account))
        # Only admitted work can advance polling. A crash after this point is
        # recovered from the inbox, independent of the Messages DB cursor.
        self._last_rowid = await asyncio.to_thread(self._checkpoint, rowid)
        return await self.process_message(msg, external_id=guid, account=account,
            authorize=lambda: self._authorized(msg, account), receipt=receipt,
            send=lambda reply: self._send_saved(msg, reply, {}))

    async def start(self) -> None:
        log.info("iMessage channel polling chat.db every %ds", self.poll_interval)
        self._last_rowid = await asyncio.to_thread(self._checkpoint)
        account = self._account()
        while not self._stop:
            try:
                await self.recover_messages(account=account,
                    authorize=lambda msg: self._authorized(msg, account), send=self._send_saved)
            except Exception:
                log.warning("iMessage durable recovery requires review")
            try:
                messages = await asyncio.to_thread(self._fetch_new)
            except Exception:  # pragma: no cover
                log.exception("iMessage poll failed")
                messages = []
            for handle, text, rowid, guid in messages:
                try:
                    await self._receive(handle, text, rowid, guid)
                except Exception:
                    log.warning("iMessage intake requires retry or review")
                    break  # no checkpoint may skip a failed admission
            await asyncio.sleep(self.poll_interval)

    def _latest_rowid(self) -> int:
        with closing(sqlite3.connect(f"file:{CHAT_DB}?mode=ro", uri=True)) as conn, conn:
            row = conn.execute("SELECT COALESCE(MAX(ROWID), 0) FROM message").fetchone()
            return row[0] if row else 0

    def _fetch_new(self) -> list[tuple[str, str, int, str]]:
        out: list[tuple[str, str, int, str]] = []
        with closing(sqlite3.connect(f"file:{CHAT_DB}?mode=ro", uri=True)) as conn, conn:
            cur = conn.execute(
                """
                SELECT m.ROWID, h.id, m.text, m.guid
                FROM message m
                JOIN handle h ON m.handle_id = h.ROWID
                WHERE m.ROWID > ?
                  AND m.is_from_me = 0
                  AND m.text IS NOT NULL
                ORDER BY m.ROWID ASC
                LIMIT 256
                """,
                (self._last_rowid or 0,),
            )
            for rowid, handle, text, guid in cur.fetchall():
                if text:
                    if not guid:
                        raise ValueError("iMessage message has no stable GUID")
                    out.append((handle, text, rowid, guid))
        return out

    async def send(self, user_id: str, text: str) -> None:
        """Send via parameterized AppleScript (no shell-style interpolation).

        argv items are treated as literal strings by AppleScript, so even
        adversarial LLM output (quotes, semicolons, newlines, `$`) cannot
        escape into command execution.
        """
        async def post():
            try:
                result = await asyncio.to_thread(
                    subprocess.run, ["osascript", "-", text, user_id],
                    input=_SEND_SCRIPT, text=True, check=False, timeout=10, capture_output=True,
                )
            except FileNotFoundError as exc:
                raise DeliveryNotSent("iMessage sender is unavailable") from exc
            if result.returncode != 0:
                raise DeliveryUnknown("iMessage local send was not confirmed")
            # This confirms local Messages acceptance, not recipient delivery.
            return "osascript-accepted"
        return await send_chunk("text-0", {"recipient": user_id, "text": text}, post)

    async def stop(self) -> None:
        self._stop = True
