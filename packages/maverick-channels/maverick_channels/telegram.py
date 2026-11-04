"""Telegram bot channel.

The simplest path to phone-companion mode. Set ``[channels.telegram]
enabled = true`` in ``~/.maverick/config.toml`` and provide a bot token,
and any message you send to your bot reaches the orchestrator.

Requires::

    python -m pip install -e './packages/maverick-channels[telegram]'
"""
from __future__ import annotations

import asyncio
import io
import logging
import os

from .base import Channel, IncomingMessage, normalize_allowlist
from .delivery import (
    DeliveryNotSent,
    DeliveryUnknown,
    delivery_active,
    read_reply_file,
    saved_reply_files,
    send_chunk,
)

log = logging.getLogger(__name__)

# Telegram's Bot API hard-rejects text messages over 4096 chars with a 400
# "message is too long", which (like the empty-reply case below) raises out of
# the handler and the user gets NOTHING despite the completed run. Chunk long
# outbound text on line boundaries instead, like the discord/whatsapp adapters.
TELEGRAM_LIMIT = 4096

try:
    from telegram import Update
    from telegram.ext import Application, ContextTypes, MessageHandler, filters
    _HAVE_TELEGRAM = True
except ImportError:
    _HAVE_TELEGRAM = False
    Update = ContextTypes = Application = MessageHandler = filters = None  # type: ignore


class TelegramChannel(Channel):
    name = "telegram"

    def __init__(
        self,
        handler,
        token: str | None = None,
        allowed_user_ids: set[str] | None = None,
        allowed_chat_ids: set[str] | None = None,
    ):
        super().__init__(handler)
        if not _HAVE_TELEGRAM:
            raise ImportError(
                "python-telegram-bot not installed. Install with: "
                "From the reviewed checkout run: python -m pip install -e "
                "'./packages/maverick-channels[telegram]'"
            )
        self.token = token or os.environ.get("TELEGRAM_BOT_TOKEN")
        if not self.token:
            raise ValueError("TELEGRAM_BOT_TOKEN not set")
        self._app: Application | None = None
        self._recovery_task = None
        self.allowed_user_ids = normalize_allowlist(
            allowed_user_ids, "TELEGRAM_ALLOWED_USER_IDS",
        )
        self.allowed_chat_ids = normalize_allowlist(
            allowed_chat_ids, "TELEGRAM_ALLOWED_CHAT_IDS",
        )
        if not self.allowed_user_ids and not self.allowed_chat_ids:
            raise ValueError(
                "Set TELEGRAM_ALLOWED_USER_IDS or TELEGRAM_ALLOWED_CHAT_IDS to restrict access"
            )

    def _account(self):
        # Bot tokens begin with the stable, public bot id; never persist the
        # credential suffix or make credential rotation a new inbox identity.
        return self.token.split(":", 1)[0]

    def _authorized(self, msg, account, chat_type):
        return account == self._account() and bool(msg.sender_id) and (
            msg.sender_id in self.allowed_user_ids or
            (chat_type == "private" and msg.user_id in self.allowed_chat_ids))

    @staticmethod
    def _file_descriptors(message):
        files = []
        for kind in ("document", "voice", "audio", "video", "photo"):
            obj = getattr(message, kind, None)
            if not obj:
                continue
            if kind == "photo":
                obj = obj[-1]
            file_id = getattr(obj, "file_id", None)
            if not isinstance(file_id, str):
                continue
            defaults = {"photo": ("photo.jpg", "image/jpeg"),
                        "voice": ("voice-note.ogg", "audio/ogg"),
                        "audio": ("audio.mp3", "audio/mpeg"),
                        "video": ("video.mp4", "video/mp4")}
            name, mime = defaults.get(kind, (kind + ".bin", "application/octet-stream"))
            files.append({"file_id": file_id, "filename": getattr(obj, "file_name", None) or name,
                          "mime": getattr(obj, "mime_type", None) or mime,
                          "size": getattr(obj, "file_size", None)})
        return files[:10]

    async def _prepare_saved(self, msg, route):
        if route.get("files") and self._app is None:
            raise RuntimeError("Telegram file recovery requires a running bot")
        for item in route.get("files", []):
            if item.get("size") and item["size"] > 100 * 1024 * 1024:
                continue
            f = await self._app.bot.get_file(item["file_id"])
            data = bytes(await f.download_as_bytearray())
            if data:
                msg.attachments.append({"filename": item["filename"], "mime": item["mime"], "data": data})
        return msg

    async def _send_saved(self, msg, reply, route):
        thread = reply.thread_ref or route["reply_to"]
        if reply.text:
            await self.send_threaded(msg.user_id, reply.text, reply_to=thread)
        return await self._send_files(msg, reply, route)

    async def _send_files(self, msg, reply, route):
        """Upload the files saved with this reply (live and recovered sends alike)."""
        files = await saved_reply_files(reply)
        thread = reply.thread_ref or route["reply_to"]
        receipt = None
        for index, item in enumerate(files):
            async def upload(item=item):
                data = await read_reply_file(item)
                kwargs = {"chat_id": int(msg.user_id), "filename": item["filename"]}
                if thread:
                    kwargs["reply_to_message_id"] = int(thread)
                try:
                    with io.BytesIO(data) as document:
                        result = await self._app.bot.send_document(document=document, **kwargs)
                except Exception as exc:
                    try:
                        from telegram.error import BadRequest, Forbidden, RetryAfter
                    except ImportError:
                        raise exc from None
                    if isinstance(exc, (BadRequest, Forbidden, RetryAfter)):
                        raise DeliveryNotSent("Telegram rejected the file attachment") from exc
                    raise
                identity = getattr(result, "message_id", None)
                if type(identity) is not int:
                    raise DeliveryUnknown("Telegram file attachment has no confirmed receipt")
                return str(identity)
            receipt = await send_chunk("file-" + str(index), {"recipient": msg.user_id,
                "thread": thread, **{key: item[key] for key in ("filename", "mime", "size_bytes", "sha256")}}, upload)
        return receipt

    async def _recover(self):
        account = self._account()
        # The admitted private-chat classification is part of the message
        # route. Human allowlists remain live; private chat ids are identical
        # to their sender ids in the Bot API.
        async with self.recovery_worker(account=account,
                authorize=lambda msg: self._authorized(msg, account,
                    "private" if msg.user_id == msg.sender_id else None),
                send=self._send_saved, prepare=self._prepare_saved):
            await asyncio.Future()

    def _is_authorized(self, update: Update) -> bool:
        user_id = str(update.effective_user.id) if update.effective_user else ""
        chat_id = str(update.effective_chat.id) if update.effective_chat else ""
        chat_type = getattr(update.effective_chat, "type", None)

        # An allowlisted sender is always authorized, in any chat.
        if self.allowed_user_ids and user_id in self.allowed_user_ids:
            return True

        # A chat allowlist must NOT authorize every member of a group: any
        # participant of an allowlisted group could otherwise drive the agent.
        # A private (1:1) chat has a single sender, so an allowlisted private
        # chat is equivalent to an allowlisted user -- honour it there only.
        # In groups, require the sender to be on TELEGRAM_ALLOWED_USER_IDS.
        if (
            chat_type == "private"
            and self.allowed_chat_ids
            and chat_id in self.allowed_chat_ids
        ):
            return True
        return False

    @staticmethod
    async def _collect_attachments(message) -> list[dict]:
        """Download a message's files into IncomingMessage.attachments dicts.

        Documents, photos (largest size), voice notes, audio, and video all
        map to ``{"filename", "mime", "data"}``; the server stores them under
        the same rules as a dashboard upload (and voice notes auto-transcribe
        into the goal context via the companion pipeline). Entirely
        best-effort: any download error just means no attachment.
        """
        candidates: list[tuple[object, str, str]] = []
        if getattr(message, "document", None):
            d = message.document
            candidates.append((d, d.file_name or "document.bin",
                               d.mime_type or "application/octet-stream"))
        if getattr(message, "photo", None):
            candidates.append((message.photo[-1], "photo.jpg", "image/jpeg"))
        if getattr(message, "voice", None):
            candidates.append((message.voice, "voice-note.ogg", "audio/ogg"))
        if getattr(message, "audio", None):
            a = message.audio
            candidates.append((a, a.file_name or "audio.mp3",
                               a.mime_type or "audio/mpeg"))
        if getattr(message, "video", None):
            v = message.video
            candidates.append((v, v.file_name or "video.mp4",
                               v.mime_type or "video/mp4"))
        out: list[dict] = []
        for obj, filename, mime in candidates[:10]:
            size = getattr(obj, "file_size", None)
            if size and size > 100 * 1024 * 1024:
                continue  # attachments.store would reject it anyway
            try:
                f = await obj.get_file()
                data = bytes(await f.download_as_bytearray())
            except Exception:  # noqa: BLE001 -- a broken file never blocks
                log.warning("telegram: attachment download failed", exc_info=True)
                continue
            if data:
                out.append({"filename": filename, "mime": mime, "data": data})
        return out

    async def _on_message(self, update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not update.message:
            return
        if not self._is_authorized(update):
            log.warning("unauthorized telegram access: user_id=%s chat_id=%s",
                        getattr(update.effective_user, "id", None),
                        getattr(update.effective_chat, "id", None))
            return
        # Authorize FIRST, download after — file downloads on behalf of an
        # unauthorized sender would be free resource burn.
        text = update.message.text or update.message.caption or ""
        files = self._file_descriptors(update.message)
        if not text and files:
            # Attachment-only message: give the swarm a working brief.
            text = "Process the attached file(s)."
        if not text:
            return
        # Per the IncomingMessage contract, user_id is the REPLY/SEND TARGET and
        # sender_id is the human identity. For a room-based adapter that means
        # the CHAT id is the target (so a proactive channel.send(msg.user_id, ...)
        # reaches the group, not the sender's private chat -- which the bot often
        # can't even open), and the user id is the sender. Matches the Slack
        # adapter. In a 1:1 chat the two ids coincide, so phone-companion mode is
        # unchanged, and principal_id (sender_id or user_id) stays the human in
        # both cases -- so auth/history/tenant keying is identical to before.
        # effective_user is None for channel posts / anonymous admins;
        # _is_authorized denies those, but guard here too rather than
        # AttributeError.
        msg = IncomingMessage(
            user_id=str(update.effective_chat.id) if update.effective_chat else "",
            text=text,
            channel="telegram",
            raw=update,
            sender_id=str(update.effective_user.id) if update.effective_user else None,
            message_id=str(update.message.message_id),
            conversation_ref=(str(update.message.message_thread_id)
                              if getattr(update.message, "message_thread_id", None) else None),
        )
        account = self._account()
        route = {"reply_to": msg.message_id, "files": files}

        async def prepare(incoming):
            incoming.attachments = await self._collect_attachments(update.message)
            return incoming

        async def send(reply):
            receipt = None
            if reply.text:
                receipt = await self._send_chunks(reply.text, update.message.reply_text,
                    {"chat_id": msg.user_id, "reply_to": msg.message_id})
            return await self._send_files(msg, reply, route) or receipt

        return await self.process_message(msg, external_id=msg.user_id + ":" + msg.message_id,
            account=account, authorize=lambda: self._authorized(msg, account,
                getattr(update.effective_chat, "type", None)), route=route, prepare=prepare, send=send)

    async def start(self) -> None:
        self._app = Application.builder().token(self.token).build()
        # TEXT for plain messages, ATTACHMENT so files/photos/voice notes
        # (with or without a caption) reach the handler too — they become
        # goal attachments via IncomingMessage.attachments.
        self._app.add_handler(MessageHandler(
            (filters.TEXT | filters.ATTACHMENT) & ~filters.COMMAND,
            self._on_message))
        log.info("Telegram channel started")
        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling()
        self._recovery_task = asyncio.create_task(self._recover(), name="telegram-recovery-owner")

    @staticmethod
    async def _send_chunks(text, call, route):
        from .formatting import split_for_discord
        receipt = None
        for index, chunk in enumerate(split_for_discord(text, limit=TELEGRAM_LIMIT)):
            async def post(chunk=chunk):
                try:
                    result = await call(chunk)
                except DeliveryNotSent:
                    raise
                except Exception as exc:
                    # These SDK errors are explicit Bot API nonacceptance;
                    # network/timeouts and unclassified failures stay unknown.
                    try:
                        from telegram.error import BadRequest, Forbidden, RetryAfter
                    except ImportError:
                        raise exc from None
                    if isinstance(exc, (BadRequest, Forbidden, RetryAfter)):
                        raise DeliveryNotSent("Telegram rejected the reply") from exc
                    raise
                message_id = getattr(result, "message_id", None)
                if delivery_active() and not isinstance(message_id, int):
                    raise DeliveryUnknown("Telegram reply acknowledgement has no message id")
                return str(message_id) if isinstance(message_id, int) else None
            receipt = await send_chunk("text-" + str(index), {**route, "text": chunk}, post)
        return receipt

    async def send(self, user_id: str, text: str) -> None:
        if self._app is None:
            raise RuntimeError("channel not started")
        return await self.send_threaded(user_id, text)

    async def send_threaded(
        self, user_id: str, text: str, *, reply_to: str | None = None,
    ) -> None:
        if self._app is None:
            raise RuntimeError("channel not started")
        kwargs = {"chat_id": int(user_id)}
        if reply_to:
            try:
                kwargs["reply_to_message_id"] = int(reply_to)
            except (TypeError, ValueError):
                pass  # un-threadable id -> plain send
        return await self._send_chunks(text, lambda chunk: self._app.bot.send_message(text=chunk, **kwargs),
            {"chat_id": user_id, "reply_to": str(kwargs["reply_to_message_id"])
             if "reply_to_message_id" in kwargs else None})

    async def stop(self) -> None:
        task = self._recovery_task
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            self._recovery_task = None
        if self._app is None:
            return
        await self._app.updater.stop()
        await self._app.stop()
        await self._app.shutdown()
