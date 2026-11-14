"""Email channel: IMAP poll for incoming, SMTP for outgoing.

Both IMAP and SMTP calls have a 30-second connect timeout, so a wedged
Gmail connection cannot pin the channel thread.

Set up:
  1. Use an account with an app password (Gmail / Fastmail / etc.)
  2. Set in config:
        [channels.email]
        enabled = true
        imap_host = "imap.gmail.com"
        imap_user = "${EMAIL_USER}"
        imap_password = "${EMAIL_APP_PASSWORD}"
        smtp_host = "smtp.gmail.com"
        smtp_port = 465
        smtp_user = "${EMAIL_USER}"
        smtp_password = "${EMAIL_APP_PASSWORD}"

No extra dependencies needed (uses stdlib `imaplib` + `smtplib`).
"""
from __future__ import annotations

import asyncio
import email
import email.utils
import imaplib
import logging
import os
import re
import smtplib
import ssl
from email.message import EmailMessage

from maverick.mail_auth import authenticated_from, valid_trusted_mail_server

from .base import Channel, IncomingMessage, backoff_delay, is_allowed, normalize_allowlist

log = logging.getLogger(__name__)

IMAP_TIMEOUT = 30.0
SMTP_TIMEOUT = 30.0

# Reply-noise trimming: a reply carries the whole prior thread as quoted
# text, re-ingested on EVERY message — the classic email token multiplier.
# Markers cut the quoted history; the RFC 3676 "-- " line cuts the signature.
# 300-char middle: long attribution lines (many recipients, localized dates)
# blow past 200 and a missed match re-ingests the whole thread. This marker
# precedes ">"-quoted text, so its cut is guarded by _only_quotes_below —
# bottom-posted answers AFTER the quote block must survive.
_ON_WROTE_RE = re.compile(r"^\s*On .{0,300}wrote:\s*$", re.IGNORECASE)
# Outlook/forward dividers precede an UNQUOTED copy of the old mail (headers
# then body), so these cut unconditionally — bottom-posting below them is not
# a convention.
_DIVIDER_CUT_RES = (
    re.compile(r"^\s*-{3,}\s*Original Message\s*-{3,}", re.IGNORECASE),
    re.compile(r"^\s*Begin forwarded message:\s*$", re.IGNORECASE),
)
_HTML_BREAK_RE = re.compile(r"<\s*(?:br|/p|/div|/tr|/li|/h[1-6])\s*/?\s*>",
                            re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _drop_html_raw_text(html: str) -> str:
    """Remove script/style blocks with a bounded, single-pass scanner."""
    text = html or ""
    lower = text.lower()
    out: list[str] = []
    pos = 0
    length = len(text)
    while pos < length:
        tag_start = text.find("<", pos)
        if tag_start < 0:
            out.append(text[pos:])
            break
        out.append(text[pos:tag_start])
        tag_name_start = tag_start + 1
        tag_name_end = tag_name_start
        while tag_name_end < length and lower[tag_name_end].isalpha():
            tag_name_end += 1
        tag_name = lower[tag_name_start:tag_name_end]
        if tag_name not in {"script", "style"}:
            out.append(text[tag_start:tag_name_end])
            pos = tag_name_end
            continue
        if tag_name_end < length and lower[tag_name_end] not in "\t\n\r\f />":
            out.append(text[tag_start:tag_name_end])
            pos = tag_name_end
            continue
        tag_end = text.find(">", tag_name_end)
        if tag_end < 0:
            break
        close_start = lower.find(f"</{tag_name}", tag_end + 1)
        if close_start < 0:
            break
        close_end = text.find(">", close_start + len(tag_name) + 2)
        if close_end < 0:
            break
        pos = close_end + 1
    return "".join(out)


def _strip_html(html: str) -> str:
    """HTML body -> plain text (tags/CSS/JS are 3-10x the visible text)."""
    import html as _htmllib
    text = _drop_html_raw_text(html or "")
    text = _HTML_BREAK_RE.sub("\n", text)
    text = _HTML_TAG_RE.sub("", text)
    text = _htmllib.unescape(text)
    # collapse the whitespace the markup structure leaves behind
    lines = [ln.strip() for ln in text.splitlines()]
    return "\n".join(ln for ln in lines if ln).strip()


def _only_quotes_below(lines: list[str], start: int) -> bool:
    """True when everything below ``start`` is quoted/blank — i.e. cutting
    there loses no fresh content. A bottom-posted reply (real answer BELOW
    the ``On ... wrote:`` attribution and its quote block) fails this check,
    so the marker cut is skipped and the answer survives."""
    return all(
        not ln.strip() or ln.lstrip().startswith(">")
        for ln in lines[start:]
    )


def _trim_reply_noise(body: str) -> str:
    """Drop quoted-reply history and the signature block from one message.

    Cuts at a reply/forward marker only when nothing but quoted text follows
    it (top-posted replies — the dominant style); at the RFC 3676 ``-- ``
    signature delimiter (dash-dash-SPACE only: a bare ``--`` is a common
    prose divider and cutting there dropped real body text); then drops a
    trailing run of ``>``-quoted lines. Bottom-posted and interleaved
    answers are preserved. Fail-safe: an all-quote body returns unchanged,
    never empty.
    """
    text = body or ""
    lines = text.splitlines()
    cut = len(lines)
    for i, line in enumerate(lines):
        if any(m.match(line) for m in _DIVIDER_CUT_RES):
            cut = i
            break
        if _ON_WROTE_RE.match(line) and _only_quotes_below(lines, i + 1):
            cut = i
            break
        if line.rstrip("\r") == "-- ":
            cut = i
            break
    kept = lines[:cut]
    while kept and (not kept[-1].strip() or kept[-1].lstrip().startswith(">")):
        kept.pop()
    trimmed = "\n".join(kept).strip()
    return trimmed or text


class EmailChannel(Channel):
    name = "email"

    def __init__(
        self,
        handler,
        imap_host: str,
        imap_user: str,
        imap_password: str,
        smtp_host: str,
        smtp_user: str,
        smtp_password: str,
        smtp_port: int = 465,
        poll_interval: int = 30,
        allowed_user_ids=None,
        trusted_authserv_id: str = "",
        oauth_config: dict | None = None,
    ):
        super().__init__(handler)
        # Without an allowlist, ANY inbound sender could drive the agent.
        # Addresses compared case-insensitively. Require one.
        self.allowed_user_ids = {
            a.lower() for a in normalize_allowlist(allowed_user_ids, "EMAIL_ALLOWED_USER_IDS")
        }
        if not self.allowed_user_ids:
            raise ValueError("Set EMAIL_ALLOWED_USER_IDS to restrict access")
        # EMAIL_TRUSTED_AUTHSERV_ID named the server before the saved setting
        # existed; an operator who set it has identified the server explicitly.
        trusted_authserv_id = trusted_authserv_id or os.environ.get("EMAIL_TRUSTED_AUTHSERV_ID", "")
        if not valid_trusted_mail_server(trusted_authserv_id):
            raise ValueError("Set the incoming mail server identity before email can start work")
        self.trusted_authserv_id = trusted_authserv_id.strip()
        self.imap_host = imap_host
        self.imap_user = imap_user
        self.imap_password = imap_password
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self._mail_cfg = {**(oauth_config or {}), "imap_host": imap_host,
                          "imap_user": imap_user, "imap_password": imap_password,
                          "smtp_host": smtp_host, "smtp_user": smtp_user,
                          "smtp_password": smtp_password, "smtp_port": smtp_port,
                          "trusted_authserv_id": self.trusted_authserv_id,
                          "allowed_user_ids": sorted(self.allowed_user_ids)}
        self.poll_interval = poll_interval
        self._stop = False

    async def start(self) -> None:
        log.info("Email channel polling %s every %ds", self.imap_host, self.poll_interval)
        errors = 0
        while not self._stop:
            try:
                messages = await asyncio.wait_for(
                    asyncio.to_thread(self._fetch_unseen),
                    timeout=IMAP_TIMEOUT * 2,
                )
                errors = 0
            except asyncio.TimeoutError:
                log.warning("IMAP poll timed out; continuing")
                messages = []
                errors += 1
            except Exception:  # pragma: no cover
                log.exception("email poll failed")
                messages = []
                errors += 1
            from .delivery import DeliveryJournal

            journal = DeliveryJournal()
            try:
                recovered, checkpoint = await asyncio.to_thread(journal.recovery_window, channel="email", account=self._account())
                batch = {row["id"]: row for row in [*messages, *recovered]}
                for row in batch.values():
                    try:
                        await self._recover(row, journal)
                    except Exception as exc:
                        # One row that keeps failing (an unconfirmed send, a
                        # missing file) must not pin the window: every row
                        # after it would never be handled. It keeps its state.
                        log.warning("Email row %s deferred (%s)", row.get("external_id"), type(exc).__name__)
                await asyncio.to_thread(journal.finish_recovery_window, checkpoint)
            except Exception:
                log.warning("Email durable recovery window requires review")
            await asyncio.sleep(backoff_delay(self.poll_interval, errors))

    async def _recover(self, row, journal) -> None:
        """Run or deliver one saved email from the durable journal."""
        if row.get("restore_hold"):
            return
        if row.get("route", {}).get("sender_auth") != "trusted_dmarc_pass":
            await asyncio.to_thread(
                journal.change, row, restore_hold=True,
                reason="Accepted before the inbound sender-authentication gate; review required",
            )
            return
        sender = row["message"]["user_id"]
        if not is_allowed(sender.lower(), self.allowed_user_ids):
            return
        incoming = IncomingMessage(user_id=sender, text=row["message"]["text"], channel="email",
                                   message_id=row["external_id"])
        def authority():
            return is_allowed(sender.lower(), self.allowed_user_ids)
        async def send_saved(reply):
            if reply.text:
                return await self.send(sender, reply.text, subject=row["route"]["subject"])
            return None
        await self.process_message(incoming, external_id=row["external_id"], account=self._account(),
                                   authorize=authority, send=send_saved, receipt=row, journal=journal)
        current = await asyncio.to_thread(journal.get, row["id"])
        if current and current.get("question_watch"):
            from .delivery import notify_queued_question

            async def send_question(message, reply, route):
                return await self.send(message.user_id, reply.text, subject=route["subject"])

            await notify_queued_question(
                current, authorize=lambda message: authority(),
                send=send_question, journal=journal,
            )

    @staticmethod
    def _extract_attachments(msg) -> list[dict]:
        """File parts of one message as IncomingMessage.attachments dicts.

        Any part with a filename (or an explicit attachment disposition)
        becomes ``{"filename", "mime", "data"}``; the server stores them as
        goal attachments under the same size/mime/magic-byte rules as a
        dashboard upload. Bounded (count + per-file bytes) so one hostile
        email can't balloon the poll loop.
        """
        out: list[dict] = []
        if not msg.is_multipart():
            return out
        for part in msg.walk():
            if len(out) >= 10:
                break
            filename = part.get_filename()
            disposition = (part.get_content_disposition() or "").lower()
            if not filename and disposition != "attachment":
                continue
            payload = part.get_payload(decode=True)
            if not isinstance(payload, (bytes, bytearray)) or not payload:
                continue
            if len(payload) > 100 * 1024 * 1024:
                continue  # attachments.store would reject it anyway
            out.append({
                "filename": str(filename or "attachment.bin"),
                "mime": (part.get_content_type()
                         or "application/octet-stream").lower(),
                "data": bytes(payload),
            })
        return out

    def _account(self):
        return self.imap_host.lower() + ":" + self.imap_user.lower()

    def _admit(self, journal, incoming, external_id, route):
        """Take one email in; None when intake refuses it for good.

        A refusal (a file type or size the store does not accept, or an email
        an earlier build admitted with a different fingerprint) is answered by
        marking the email read: left unread it would come first on every poll
        and no newer email would ever be taken in. Refused files are left out
        and the text says so, so the request itself still runs. Errors that can
        pass (a full intake, a workspace hold) still raise and leave it unread.
        """
        from .delivery import IntakeMessageRejected

        try:
            return journal.admit(incoming, external_id=external_id, account=self._account(), route=route)
        except IntakeMessageRejected as exc:
            if incoming.attachments:
                text_only = IncomingMessage(
                    user_id=incoming.user_id, channel="email", message_id=incoming.message_id,
                    text=incoming.text + "\n\n(The attached files were not accepted: "
                                         "a file type or size is not supported.)")
                try:
                    return journal.admit(text_only, external_id=external_id, account=self._account(), route=route)
                except IntakeMessageRejected:
                    pass
            log.warning("Incoming email refused at intake (%s)", type(exc).__name__)
            return None

    def _fetch_unseen(self) -> list[dict]:
        from maverick.microsoft_mail import authenticate_imap, mail_effect

        from .delivery import DeliveryJournal

        out = []
        journal = DeliveryJournal()
        with imaplib.IMAP4_SSL(self.imap_host, ssl_context=ssl.create_default_context(),
                              timeout=IMAP_TIMEOUT) as mail:
            authenticate_imap(mail, self._mail_cfg)
            with mail_effect(self._mail_cfg):
                status, _ = mail.select("INBOX")
            if status != "OK":
                raise RuntimeError("Email inbox is unavailable")
            with mail_effect(self._mail_cfg):
                _, validity = mail.response("UIDVALIDITY")
            epoch = validity[0].decode("ascii") if validity and isinstance(validity[0], bytes) else ""
            if not epoch.isdecimal():
                raise RuntimeError("Email inbox identity is unavailable")
            with mail_effect(self._mail_cfg):
                status, data = mail.uid("search", None, "UNSEEN")
            if status != "OK" or not data or not isinstance(data[0], bytes):
                raise RuntimeError("Email unread-message query is unavailable")
            for uid in data[0].split()[:50]:
                if not uid.isdigit():
                    raise RuntimeError("Email message identity is invalid")
                with mail_effect(self._mail_cfg):
                    status, msg_data = mail.uid("fetch", uid, "(BODY.PEEK[])")
                if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                    raise RuntimeError("Email source message is unavailable")
                payload = msg_data[0][1]
                if not isinstance(payload, bytes):
                    raise RuntimeError("Email source message has no body")
                parsed = email.message_from_bytes(payload)
                sender = authenticated_from(parsed, self.trusted_authserv_id)
                if not sender or not is_allowed(sender.lower(), self.allowed_user_ids):
                    log.warning("Incoming email refused: sender authentication or access failed")
                    with mail_effect(self._mail_cfg):
                        mail.uid("store", uid, "+FLAGS", "\\Seen")
                    continue
                subject = re.sub(r"\r?\n[ \t]+", " ", str(parsed.get("Subject", "")))
                body = self._extract_body(parsed)
                attachments = self._extract_attachments(parsed)
                if not body and not attachments:
                    with mail_effect(self._mail_cfg):
                        mail.uid("store", uid, "+FLAGS", "\\Seen")
                    continue
                external_id = epoch + ":" + uid.decode("ascii")
                incoming = IncomingMessage(user_id=sender, text=f"Subject: {subject}\n\n{body}" if subject else (body or "Process the attached file(s)."),
                                           channel="email", message_id=external_id, attachments=attachments)
                with mail_effect(self._mail_cfg):
                    row = self._admit(journal, incoming, external_id,
                                      {"subject": f"Re: {subject}" if subject else "Lightwork",
                                       "sender_auth": "trusted_dmarc_pass"})
                # Crash after this acknowledgement is recovered from the
                # bounded rotating journal window, never from a second run.
                with mail_effect(self._mail_cfg):
                    mail.uid("store", uid, "+FLAGS", "\\Seen")
                if row is not None:
                    out.append(row)
        return out

    def _extract_body(self, msg) -> str:
        """Plain text of one message, TRIMMED for context entry.

        The body becomes goal text the whole swarm reads, so per-message noise
        is dropped here: quoted-reply history (every reply in a thread carries
        the entire prior thread), the signature block, and raw HTML markup
        (tags/CSS are 3-10x the visible text). text/plain is preferred; an
        HTML-only message falls back to stripped HTML instead of being lost.
        """
        if msg.is_multipart():
            html_fallback = ""
            for part in msg.walk():
                ctype = part.get_content_type()
                payload = part.get_payload(decode=True)
                if not isinstance(payload, (bytes, bytearray)):
                    continue
                if ctype == "text/plain":
                    return _trim_reply_noise(
                        payload.decode(errors="replace").strip())
                if ctype == "text/html" and not html_fallback:
                    html_fallback = _strip_html(payload.decode(errors="replace"))
            return _trim_reply_noise(html_fallback)
        payload = msg.get_payload(decode=True)
        if isinstance(payload, (bytes, bytearray)):
            text = payload.decode(errors="replace").strip()
        else:
            text = str(payload or "").strip()
        if (msg.get_content_type() or "").lower() == "text/html":
            text = _strip_html(text)
        return _trim_reply_noise(text)

    async def send(self, user_id: str, text: str, subject: str = "Lightwork") -> None:
        from .delivery import chunk_idempotency_key, send_chunk

        message_id = "<" + chunk_idempotency_key("email-0") + "@lightwork.local>"
        async def create():
            return await asyncio.to_thread(self._send_sync, user_id, text, subject, message_id=message_id)
        return await send_chunk("email-0", {"text": text, "subject": subject, "recipient": user_id}, create)

    def _send_sync(self, to_addr: str, text: str, subject: str, *, message_id=None):
        from .delivery import DeliveryNotSent

        msg = EmailMessage()
        msg["From"] = self.smtp_user
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg["Message-ID"] = message_id or email.utils.make_msgid()
        msg.set_content(text)
        sending = False
        try:
            tls = ssl.create_default_context()
            connection = (
                smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=SMTP_TIMEOUT)
                if self.smtp_port == 587 else
                smtplib.SMTP_SSL(self.smtp_host, self.smtp_port,
                                 context=tls, timeout=SMTP_TIMEOUT)
            )
            with connection as smtp:
                if self.smtp_port == 587:
                    smtp.starttls(context=tls)
                from maverick.microsoft_mail import authenticate_smtp, mail_effect
                authenticate_smtp(smtp, self._mail_cfg)
                with mail_effect(self._mail_cfg):
                    sending = True
                    refused = smtp.send_message(msg)
                if refused:
                    raise DeliveryNotSent("SMTP rejected the recipient")
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPDataError) as exc:
            raise DeliveryNotSent("SMTP explicitly rejected the message") from exc
        except Exception as exc:
            if not sending:
                raise DeliveryNotSent("SMTP unavailable before sending") from exc
            raise
        return str(msg["Message-ID"])

    async def stop(self) -> None:
        self._stop = True
