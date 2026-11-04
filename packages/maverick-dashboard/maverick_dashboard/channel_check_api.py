"""Chat-app checks from the Channels page: Test connection and Send a test message.

"Test connection" asks the chat service whether the saved credentials are
accepted (a read-only identity call per service). "Send a test message" sends
one fixed sentence to a destination the administrator chose (an email address,
a phone number or a Slack channel). Both record the outcome against the exact
saved configuration, so the page's status changes from "Not tested yet" to
"Working" or "Test failed". Only a pass/fail and a short caller-written summary
are kept; provider responses are never stored or shown.

Global admin only, same-origin checked, bounded timeouts, and outbound HTTP
goes through the egress-guarded client used by the provider checks.
"""
from __future__ import annotations

import base64
import imaplib
import re
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission

router = APIRouter()

TEST_TEXT = "This is a test message from Lightwork. If you can read this, the connection works."
_TIMEOUT = 8.0
SENDABLE = {"email", "sms", "slack"}
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE = re.compile(r"^\+[1-9][0-9]{6,14}$")
_SLACK = re.compile(r"^#?[a-z0-9][a-z0-9._-]{0,79}$")


def _admin(request: Request) -> None:
    from . import app as app_module
    app_module._require_same_origin(request)
    require_global_permission(request, "admin")


def _channel_config(name: str) -> dict[str, Any]:
    from .integration_readiness import require_readable_config
    raw = (require_readable_config().get("channels") or {}).get(name)
    if not isinstance(raw, dict) or not raw.get("enabled"):
        raise HTTPException(409, "Turn this chat app on and save it before testing.")
    return raw


def _get(url: str, headers: dict[str, str]):
    from maverick.tools import _ssrf
    return _ssrf.safe_get(url, headers=headers, timeout=_TIMEOUT)


def _post(url: str, *, headers: dict[str, str], data=None, json=None):
    from maverick.tools import _ssrf
    with _ssrf.safe_client(url, timeout=_TIMEOUT) as client:
        return client.post(url, headers=headers, data=data, json=json)


def _basic(user: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


def _smtp(cfg: dict[str, Any]):
    host = str(cfg.get("smtp_host") or "").strip()
    port = int(cfg.get("smtp_port") or 465)
    context = ssl.create_default_context()
    if port == 587:
        smtp = smtplib.SMTP(host, port, timeout=_TIMEOUT)
        smtp.starttls(context=context)
    else:
        smtp = smtplib.SMTP_SSL(host, port, timeout=_TIMEOUT, context=context)
    from maverick.microsoft_mail import authenticate_smtp
    try:
        authenticate_smtp(smtp, cfg)
    except Exception:
        smtp.close()
        raise
    return smtp


def _check_email(cfg: dict[str, Any]) -> tuple[bool, str]:
    from .integration_readiness import _email_configuration_problem

    problem = _email_configuration_problem(cfg)
    if problem:
        return False, problem
    with imaplib.IMAP4_SSL(
        str(cfg.get("imap_host") or ""), ssl_context=ssl.create_default_context(),
        timeout=_TIMEOUT,
    ) as inbox:
        from maverick.microsoft_mail import authenticate_imap, mail_effect
        result, _ = authenticate_imap(inbox, cfg)
        if result != "OK":
            return False, "the incoming mail server refused the saved details"
        with mail_effect(cfg):
            result, _ = inbox.select("INBOX", readonly=True)
        if result != "OK":
            return False, "the incoming mailbox could not be opened"
        with mail_effect(cfg):
            _kind, validity = inbox.response("UIDVALIDITY")
        if not validity or not validity[0] or not validity[0].decode("ascii", "ignore").isdigit():
            return False, "the incoming mailbox did not confirm its identity"
    smtp = _smtp(cfg)
    smtp.quit()
    return True, "incoming and outgoing mail sign-in worked; a live sender check is still needed"


def check_credentials(name: str, cfg: dict[str, Any]) -> tuple[bool, str]:
    """Ask the chat service whether the saved credentials work."""
    try:
        if name == "telegram":
            token = str(cfg.get("bot_token") or "")
            ok = _get(f"https://api.telegram.org/bot{quote(token, safe=':')}/getMe", {}).status_code == 200
        elif name == "discord":
            ok = _get("https://discord.com/api/v10/users/@me",
                      {"Authorization": "Bot " + str(cfg.get("bot_token") or "")}).status_code == 200
        elif name == "slack":
            response = _get("https://slack.com/api/auth.test",
                            {"Authorization": "Bearer " + str(cfg.get("bot_token") or "")})
            ok = response.status_code == 200 and bool((response.json() or {}).get("ok"))
        elif name == "whatsapp_cloud":
            phone = quote(str(cfg.get("phone_number_id") or ""), safe="")
            ok = _get(f"https://graph.facebook.com/v19.0/{phone}",
                      {"Authorization": "Bearer " + str(cfg.get("access_token") or "")}).status_code == 200
        elif name == "sms":
            sid = str(cfg.get("account_sid") or "")
            ok = _get(f"https://api.twilio.com/2010-04-01/Accounts/{quote(sid, safe='')}.json",
                      {"Authorization": _basic(sid, str(cfg.get("auth_token") or ""))}).status_code == 200
        elif name == "email":
            return _check_email(cfg)
        elif name == "teams":
            return _teams_token_check(cfg)
        else:
            return False, "this chat app has no connection test"
    except Exception as exc:  # noqa: BLE001 -- summarized, never echoed
        return False, f"the connection test could not reach the service ({type(exc).__name__})"
    return ok, ("the service accepted the saved details" if ok else "the service did not accept the saved details")


def _teams_token_check(cfg: dict[str, Any]) -> tuple[bool, str]:
    """Ask Microsoft's sign-in service for a Bot Framework token with the saved
    app id and secret (the same call the channel makes before every reply)."""
    from maverick_channels.teams import (
        TOKEN_SCOPE,
        channel_config,
        explain_token_failure,
        token_endpoint,
    )

    settings = channel_config(cfg)
    if not settings["app_id"] or not settings["app_password"]:
        return False, "enter the app ID and client secret first"
    response = _post(token_endpoint(settings["tenant_id"] or None),
                     headers={"Content-Type": "application/x-www-form-urlencoded"},
                     data={"grant_type": "client_credentials", "client_id": settings["app_id"],
                           "client_secret": settings["app_password"], "scope": TOKEN_SCOPE})
    try:
        body = response.json() or {}
    except ValueError:
        body = {}
    if response.status_code == 200 and body.get("access_token"):
        return True, "Microsoft issued a Bot Framework token for the saved app id and secret"
    return False, explain_token_failure(response.status_code, body)


def send_test(name: str, cfg: dict[str, Any], to: str) -> tuple[bool, str]:
    """Send the fixed test sentence to ``to``."""
    try:
        if name == "email":
            smtp = _smtp(cfg)
            try:
                message = EmailMessage()
                message["From"] = str(cfg.get("smtp_user") or "")
                message["To"] = to
                message["Subject"] = "Lightwork test message"
                message.set_content(TEST_TEXT)
                from maverick.microsoft_mail import mail_effect

                with mail_effect(cfg):
                    refused = smtp.send_message(message)
            finally:
                smtp.quit()
            ok = not refused
        elif name == "sms":
            sid = str(cfg.get("account_sid") or "")
            response = _post(
                f"https://api.twilio.com/2010-04-01/Accounts/{quote(sid, safe='')}/Messages.json",
                headers={"Authorization": _basic(sid, str(cfg.get("auth_token") or ""))},
                data={"To": to, "From": str(cfg.get("from_number") or ""), "Body": TEST_TEXT})
            ok = 200 <= response.status_code < 300
        elif name == "slack":
            response = _post("https://slack.com/api/chat.postMessage",
                             headers={"Authorization": "Bearer " + str(cfg.get("bot_token") or "")},
                             json={"channel": to, "text": TEST_TEXT})
            ok = response.status_code == 200 and bool((response.json() or {}).get("ok"))
        else:
            return False, "this chat app can't send a test message from here"
    except Exception as exc:  # noqa: BLE001
        return False, f"the test message could not be sent ({type(exc).__name__})"
    return ok, ("the test message was accepted for delivery" if ok else "the service refused the test message")


def _valid_destination(name: str, to: str) -> str:
    to = (to or "").strip()
    ok = {"email": _EMAIL, "sms": _PHONE, "slack": _SLACK}[name].fullmatch(to.lower() if name == "slack" else to)
    if not ok:
        raise HTTPException(422, {"email": "Enter an email address.",
                                  "sms": "Enter a mobile number with its country code, like +15551234567.",
                                  "slack": "Enter a Slack channel name, like #general."}[name])
    return to


def _reviewed_http(method, url, headers, guard, *, params=None, body=None):
    """Reuse pinned egress with fresh admission after DNS and bounded replies."""
    import json

    from maverick.tools import _ssrf

    def before_request(_request):
        guard()

    with _ssrf.safe_client(url, timeout=_TIMEOUT, event_hooks={"request": [before_request]}) as client:
        with client.stream(method, url, headers=headers, params=params, json=body) as response:
            raw = bytearray()
            for chunk in response.iter_bytes():
                if len(raw) + len(chunk) > 65536:
                    raise ValueError("The chat service response exceeded the supported bound")
                raw.extend(chunk)
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeError):
                value = {}
            return response.status_code, value if isinstance(value, dict) else {}


def reviewed_account(name, cfg, guard):
    """Read the configured bot's identity; never create a conversation."""
    if name == "telegram":
        status, body = _reviewed_http("GET", _telegram_url(cfg, "getMe"), {}, guard)
        return str((body.get("result") or {}).get("id") or "") if status == 200 and body.get("ok") else ""
    if name == "discord":
        status, body = _reviewed_http("GET", "https://discord.com/api/v10/users/@me", _bot_headers(name, cfg), guard)
        return str(body.get("id") or "") if status == 200 and body.get("bot") is True else ""
    if name == "whatsapp_cloud":
        return str(cfg.get("phone_number_id") or "")
    import hashlib

    from maverick_channels.mattermost import server_origin

    return server_origin(cfg.get("url", "")) + ":" + hashlib.sha256(str(cfg.get("bot_token") or "").encode()).hexdigest()


def _telegram_url(cfg, operation):
    return "https://api.telegram.org/bot" + quote(str(cfg.get("bot_token") or ""), safe=":") + "/" + operation


def _bot_headers(name, cfg):
    return {"Authorization": ("Bot " if name == "discord" else "Bearer ") + str(cfg.get("bot_token") or cfg.get("access_token") or "")}


def reviewed_recipient(name, cfg, destination, guard):
    """Verify a previously admitted conversation using the current bot account."""
    if name == "whatsapp_cloud":
        return {"id": destination, "label": "WhatsApp conversation with +" + destination, "type": "private"}
    if name == "telegram":
        status, value = _reviewed_http("GET", _telegram_url(cfg, "getChat"), {}, guard, params={"chat_id": destination})
        body = value.get("result") or {}
        if status != 200 or value.get("ok") is not True:
            raise HTTPException(409, "This Telegram conversation is no longer available to the saved bot.")
        label = body.get("title") or " ".join(str(body.get(key) or "") for key in ("first_name", "last_name")).strip()
    else:
        from maverick_channels.mattermost import server_origin

        base = "https://discord.com/api/v10" if name == "discord" else server_origin(cfg.get("url", "")) + "/api/v4"
        status, body = _reviewed_http("GET", base + "/channels/" + quote(destination, safe=""), _bot_headers(name, cfg), guard)
        if status != 200:
            raise HTTPException(409, "This conversation is no longer available to the saved bot.")
        label = body.get("display_name") or body.get("name") or "Private conversation"
    if str(body.get("id")) != destination:
        raise HTTPException(409, "The chat service did not confirm this exact conversation.")
    if not isinstance(label, str) or not label.strip() or len(label) > 200 or any(ord(char) < 32 for char in label):
        raise HTTPException(409, "The chat service did not return a readable conversation name.")
    return {"id": destination, "label": label.strip(), "type": str(body.get("type", "conversation"))[:32]}


def reviewed_sender(cfg, sender, guard):
    """Resolve Mattermost's supported username allowlist using the saved bot."""
    from maverick_channels.mattermost import server_origin

    status, body = _reviewed_http("GET", server_origin(cfg.get("url", "")) + "/api/v4/users/" + quote(sender, safe=""),
                                 _bot_headers("mattermost", cfg), guard)
    username = body.get("username")
    if status != 200 or body.get("id") != sender or not isinstance(username, str) or not 0 < len(username) <= 200:
        raise HTTPException(409, "The saved bot could not confirm this conversation's current sender.")
    return username


def send_reviewed_test(name, cfg, destination, guard):
    """Offer one fixed sentence, retaining provider acceptance separately."""
    if name == "telegram":
        url, headers, body = _telegram_url(cfg, "sendMessage"), {}, {"chat_id": destination, "text": TEST_TEXT}
    elif name == "discord":
        url, headers = "https://discord.com/api/v10/channels/" + quote(destination, safe="") + "/messages", _bot_headers(name, cfg)
        body = {"content": TEST_TEXT, "allowed_mentions": {"parse": []}}
    elif name == "whatsapp_cloud":
        from maverick_channels.whatsapp_cloud import API_VERSION, GRAPH_BASE

        version = str(cfg.get("api_version") or API_VERSION)
        if not re.fullmatch(r"v[0-9]{1,2}\.0", version):
            raise HTTPException(409, "The saved WhatsApp API version is unavailable.")
        url = GRAPH_BASE + "/" + version + "/" + quote(str(cfg.get("phone_number_id") or ""), safe="") + "/messages"
        headers = _bot_headers(name, cfg)
        body = {"messaging_product": "whatsapp", "to": destination, "type": "text", "text": {"body": TEST_TEXT}}
    else:
        from maverick_channels.mattermost import server_origin

        url, headers = server_origin(cfg.get("url", "")) + "/api/v4/posts", _bot_headers(name, cfg)
        body = {"channel_id": destination, "message": TEST_TEXT}
    status, value = _reviewed_http("POST", url, headers, guard, body=body)
    if (400 <= status < 500 and status != 408) or (name == "telegram" and value.get("ok") is False):
        return "refused", ""
    receipt = (value.get("result") or {}).get("message_id") if name == "telegram" else (
        (value.get("messages") or [{}])[0].get("id") if name == "whatsapp_cloud" else value.get("id"))
    if 200 <= status < 300 and isinstance(receipt, (str, int)) and not isinstance(receipt, bool) and 0 < len(str(receipt)) <= 512:
        return "accepted", str(receipt)
    return "unknown", ""


def _back(name: str, result: str) -> RedirectResponse:
    return RedirectResponse(f"/channels?saved={result}&channel={quote(name)}#channel-{quote(name)}",
                            status_code=303)


def _wants_json(request: Request) -> bool:
    return "application/json" in (request.headers.get("accept") or "")


def _answer(request: Request, name: str, cfg: dict[str, Any], *, ok: bool, detail: str,
            result: str, sentence: str):
    """Redirect for a plain form post; a JSON answer (with the re-rendered
    status block) when the page asked for one, so the result shows inline."""
    if not _wants_json(request):
        return _back(name, result)
    from .app import templates
    from .integration_readiness import channel_readiness

    readiness = channel_readiness(name, cfg)
    module = templates.get_template("_integration_readiness.html").module
    return {"ok": ok, "detail": detail, "status": "Working" if ok else "Test failed",
            "message": sentence, "readiness_html": str(module.integration_readiness(readiness))}


@router.post("/channels/test", response_model=None)
async def channels_test(request: Request, channel: str = Form(...)):
    _admin(request)
    from .integration_readiness import channel_readiness, record
    name = channel.strip()
    cfg = await run_in_threadpool(_channel_config, name)
    readiness = await run_in_threadpool(channel_readiness, name, cfg)
    for kind in ("dependency", "runtime"):
        preflight = readiness[kind]
        if preflight["status"] == "failed":
            record("channel", name, cfg, verified=False, detail=preflight["detail"],
                   evidence={"kind": f"{kind}_preflight"})
            return _answer(request, name, cfg, ok=False, detail=preflight["detail"],
                           result="test_failed", sentence=preflight["detail"])
    ok, detail = await run_in_threadpool(check_credentials, name, cfg)
    record("channel", name, cfg, verified=ok, detail=detail, evidence={"kind": "credential_check"})
    return _answer(request, name, cfg, ok=ok, detail=detail, result="tested" if ok else "test_failed",
                   sentence=("Mail sign-in passed. This does not verify that your mail server removes forged sender results."
                             if name == "email" and ok else
                             "Connection test passed: the service accepted the saved details.") if ok
                   else "The connection test failed. Check the details, save, and test again.")


@router.post("/channels/send-test", response_model=None)
async def channels_send_test(request: Request, channel: str = Form(...), to: str = Form("")):
    _admin(request)
    from .integration_readiness import channel_readiness, record
    name = channel.strip()
    if name not in SENDABLE:
        raise HTTPException(400, "This chat app can't send a test message from here.")
    destination = _valid_destination(name, to)
    cfg = await run_in_threadpool(_channel_config, name)
    readiness = await run_in_threadpool(channel_readiness, name, cfg)
    for kind in ("dependency", "runtime"):
        preflight = readiness[kind]
        if preflight["status"] == "failed":
            record("channel", name, cfg, verified=False, detail=preflight["detail"],
                   evidence={"kind": f"{kind}_preflight"})
            return _answer(request, name, cfg, ok=False, detail=preflight["detail"],
                           result="send_failed", sentence=preflight["detail"])
    ok, detail = await run_in_threadpool(send_test, name, cfg, destination)
    record("channel", name, cfg, verified=ok, detail=detail,
           evidence={"kind": "test_message", "external_delivery_verified": False})
    return _answer(request, name, cfg, ok=ok, detail=detail, result="sent" if ok else "send_failed",
                   sentence="Test message sent. Check that it arrived." if ok
                   else "The test message could not be sent. Check the details and try again.")
