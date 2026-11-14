"""SMS channel via Twilio.

Same transport pattern as WhatsApp: Twilio webhook -> FastAPI receiver.
Difference is the message format (no `whatsapp:` prefix on numbers).

Incoming webhooks must carry a valid X-Twilio-Signature.

Config::

    [channels.sms]
    enabled = true
    account_sid = "${TWILIO_ACCOUNT_SID}"
    auth_token  = "${TWILIO_AUTH_TOKEN}"
    from_number = "+14155551234"
    port = 8766

Requires::

    python -m pip install -e './packages/maverick-channels[sms]'
"""
from __future__ import annotations

import logging
import os

from .base import (
    Channel,
    IncomingMessage,
    add_webhook_body_limit,
    is_allowed,
    normalize_allowlist,
    public_url_for,
)

log = logging.getLogger(__name__)

TWILIO_BODY_LIMIT = 1600

try:
    from fastapi import FastAPI, Form, HTTPException, Request, Response
    from twilio.request_validator import RequestValidator
    from twilio.rest import Client as TwilioClient
    _HAVE_DEPS = True
except ImportError:
    _HAVE_DEPS = False
    FastAPI = HTTPException = Request = Response = None  # type: ignore
    RequestValidator = TwilioClient = None  # type: ignore

    def Form(*_a, **_k):  # type: ignore  # noqa: N802
        # Placeholder so the webhook method's ``Form(...)`` DEFAULT ARGUMENTS
        # (evaluated at class-definition time) don't crash with a confusing
        # "'NoneType' object is not callable" when fastapi/twilio are absent.
        # __init__ raises the real, actionable ImportError before the method --
        # and these defaults -- is ever used.
        return None


class SMSChannel(Channel):
    name = "sms"

    def __init__(
        self,
        handler,
        account_sid: str | None = None,
        auth_token: str | None = None,
        from_number: str | None = None,
        port: int = 8766,
        allowed_user_ids=None,
        bind_host: str | None = None,
    ):
        super().__init__(handler)
        if not _HAVE_DEPS:
            raise ImportError(
                "fastapi/twilio not installed. From the reviewed checkout run: "
                "python -m pip install -e './packages/maverick-channels[sms]'"
            )
        self.account_sid = account_sid or os.environ.get("TWILIO_ACCOUNT_SID")
        self.auth_token = auth_token or os.environ.get("TWILIO_AUTH_TOKEN")
        self.from_number = from_number
        if not all([self.account_sid, self.auth_token, self.from_number]):
            raise ValueError("Twilio credentials missing for SMS")
        # The Twilio signature only proves Twilio relayed the message, not
        # that the *sender* is authorized. A Twilio number is reachable by
        # any PSTN subscriber, so require a per-sender allowlist (default-deny
        # via base.is_allowed) -- list senders as Twilio delivers them, e.g.
        # "+14155551234".
        self.allowed_user_ids = normalize_allowlist(
            allowed_user_ids, "SMS_ALLOWED_USER_IDS",
        )
        if not self.allowed_user_ids:
            raise ValueError(
                "Set SMS_ALLOWED_USER_IDS to restrict who can drive the agent"
            )
        self.port = port
        # Bind loopback by default: Twilio reaches this through a reverse
        # proxy (see deploy/vps/Caddyfile), so the listener itself needn't be
        # exposed to the LAN/internet. Binding 0.0.0.0 widened the attack
        # surface (signature-validation bugs, unauthenticated request floods)
        # for no benefit. Override with SMS_BIND_HOST=0.0.0.0 if a deploy
        # genuinely needs Twilio to hit the port directly.
        self.bind_host = bind_host or os.environ.get("SMS_BIND_HOST", "127.0.0.1")
        self._twilio = TwilioClient(self.account_sid, self.auth_token)
        self._validator = RequestValidator(self.auth_token)
        self._app = FastAPI()
        add_webhook_body_limit(self._app)
        self._app.post("/webhook/sms")(self._handle_webhook)
        self._uvicorn_server = None

    async def _handle_webhook(
        self,
        request: Request,
        From: str = Form(...),  # noqa: N803
        Body: str = Form(...),  # noqa: N803
        MessageSid: str = Form(""),  # noqa: N803 -- Twilio dedup key
    ):
        signature = request.headers.get("X-Twilio-Signature", "")
        # Validate against the PUBLIC URL Twilio signed, not the loopback URL
        # the reverse proxy forwarded to (see public_url_for).
        url = public_url_for(request)
        form = await request.form()
        form_dict = {k: str(v) for k, v in form.items()}
        if not self._validator.validate(url, form_dict, signature):
            log.warning("SMS webhook signature invalid; ignoring")
            raise HTTPException(status_code=403, detail="signature invalid")

        # A valid signature only proves Twilio relayed this; gate on the
        # actual sender before spending any budget (default-deny).
        if not is_allowed(From, self.allowed_user_ids):
            log.warning("unauthorized sms access: from=%s", From)
            raise HTTPException(status_code=403, detail="sender not allowed")

        if not MessageSid:
            raise HTTPException(status_code=400, detail="message identity required")
        from starlette.background import BackgroundTask

        msg = IncomingMessage(user_id=From, text=Body, channel="sms", message_id=MessageSid)
        def authority():
            return account == self.account_sid + ":" + self.from_number and is_allowed(From, self.allowed_user_ids)
        account = self.account_sid + ":" + self.from_number
        try:
            receipt = await self.admit_message(msg, external_id=MessageSid, account=account, authorize=authority)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="message intake unavailable") from exc

        async def send_saved(reply):
            if reply.text:
                return await self.send(From, reply.text)
            return None

        async def process():
            try:
                await self.process_message(msg, external_id=MessageSid, account=account, authorize=authority,
                                           send=send_saved, receipt=receipt)
            except Exception:
                log.warning("SMS durable processing requires review: %s", receipt["id"])

        return Response(content="", media_type="text/xml", background=BackgroundTask(process),
                        headers={"X-Lightwork-Receipt": receipt["id"]})

    async def start(self) -> None:
        import uvicorn
        log.info("SMS channel listening on %s:%d", self.bind_host, self.port)
        config = uvicorn.Config(
            self._app, host=self.bind_host, port=self.port, log_level="info",
        )
        self._uvicorn_server = uvicorn.Server(config)
        account = self.account_sid + ":" + self.from_number
        def authorize(message):
            return self.account_sid + ":" + self.from_number == account and is_allowed(message.principal_id, self.allowed_user_ids)
        async def send_saved(message, reply, route):
            if reply.text:
                return await self.send(message.user_id, reply.text)
            return None
        async with self.recovery_worker(account=account, authorize=authorize, send=send_saved):
            await self._uvicorn_server.serve()

    async def send(self, user_id: str, text: str) -> None:
        import asyncio

        from .delivery import DeliveryNotSent, send_chunk

        # Twilio rejects a body over 1,600 characters, so a long reply goes
        # out as several messages; each chunk has its own receipt, so a retry
        # never re-sends a chunk Twilio already accepted.
        result = ""
        for index, start in enumerate(range(0, max(len(text), 1), TWILIO_BODY_LIMIT)):
            chunk = text[start:start + TWILIO_BODY_LIMIT]

            async def create(chunk=chunk):
                try:
                    message = await asyncio.to_thread(self._twilio.messages.create,
                                                      body=chunk, from_=self.from_number, to=user_id)
                    return getattr(message, "sid", "")
                except Exception as exc:
                    # An explicit provider 4xx rejects this request. Transport
                    # timeouts and server failures may have accepted it upstream.
                    status = getattr(exc, "status", None)
                    if isinstance(status, int) and 400 <= status < 500 and status != 408:
                        raise DeliveryNotSent("Provider rejected the message") from exc
                    raise
            result = await send_chunk(f"text-{index}", chunk, create)
        return result

    async def stop(self) -> None:
        if self._uvicorn_server is not None:
            self._uvicorn_server.should_exit = True
