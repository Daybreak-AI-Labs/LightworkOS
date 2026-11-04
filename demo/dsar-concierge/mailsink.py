"""In-process SMTP capture server for the DSAR Concierge demo.

The production email tool (maverick.tools.email_tool) sends over SMTP with
STARTTLS + AUTH. This sink speaks exactly that so the *real* tool delivers here
unmodified — a genuine SMTP+STARTTLS+AUTH transaction — with no external binary
(Mailpit/aiosmtpd) required: stdlib asyncio + a throwaway self-signed cert from
`cryptography` (already a platform dependency). Captured messages live in memory
and are rendered by the concierge's /mail inbox.

Demo scaffolding, not a product component.
"""
from __future__ import annotations

import asyncio
import email
import ssl
import time
from dataclasses import dataclass, field
from email.header import decode_header, make_header

from mailsink_transport import handle as _handle_transport
from mailsink_transport import selfsigned_context as _selfsigned_context


@dataclass
class Captured:
    to: str
    sender: str
    subject: str
    body: str
    at: float = field(default_factory=time.time)


# Shared in-memory inbox; the concierge app imports INBOX to render /mail.
INBOX: list[Captured] = []


def _decode(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _store(raw: bytes) -> None:
    msg = email.message_from_bytes(raw)
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                body = payload.decode("utf-8", "replace") if payload else ""
                break
    else:
        payload = msg.get_payload(decode=True)
        body = payload.decode("utf-8", "replace") if payload else str(msg.get_payload())
    INBOX.insert(0, Captured(
        to=_decode(msg.get("To", "")),
        sender=_decode(msg.get("From", "")),
        subject=_decode(msg.get("Subject", "")),
        body=body,
    ))


_TLS_CTX: ssl.SSLContext | None = None


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    await _handle_transport(reader, writer, store=lambda raw: _store(raw),
                            tls_context=lambda: _TLS_CTX)


async def start_mailsink(host: str = "127.0.0.1", port: int = 1025) -> asyncio.AbstractServer:
    global _TLS_CTX
    _TLS_CTX = _selfsigned_context()
    return await asyncio.start_server(_handle, host, port)
