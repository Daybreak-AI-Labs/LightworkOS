"""Reviewed one-sentence chat checks using native intake and original custody."""
from __future__ import annotations

import json
import math
import os
import re
import secrets
import time
from datetime import datetime, timezone

from fastapi import HTTPException
from maverick.authority_effects import authority_effect_fence
from maverick.crypto_at_rest import (
    EncryptionUnavailable,
    deployment_key_scope,
    is_sealed_str,
    seal_to_str,
    unseal_from_str,
)
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.privacy_ops import RecordConflict
from maverick_channels.base import normalize_allowlist

from . import auth, session_revocation
from . import channel_check_api as transport

CHANNELS = {"telegram": "Telegram", "discord": "Discord", "whatsapp_cloud": "WhatsApp", "mattermost": "Mattermost"}
TTL = 600
PAGE = "/channels#channel-message-tests"
NOTICE = "The chat service accepting a message does not prove it arrived. Check the chosen conversation yourself. An interrupted send is never repeated by reading its original outcome."


def authority(request, expected=None, *, write=False):
    with auth.fresh_configuration():
        auth.require_global_permission(request, "admin")
        principal = getattr(request.state, "principal", None)
        if principal is not None:
            claims = principal.claims or {}
            via = claims.get("via")
            fresh = (auth._session_principal(request) if via == "session" else
                     auth._invite_session_principal(request) if via == "invite" else
                     auth._proxy_principal(request) if via == "proxy" else principal)
            expiry = claims.get("exp")
            if (fresh is None or fresh.principal != principal.principal or
                    (expiry is not None and (type(expiry) not in (int, float) or not time.time() < expiry < math.inf)) or
                    session_revocation.is_revoked(principal.sub, claims.get("iat"))):
                raise HTTPException(401, "Sign in again before checking a chat conversation.")
            auth._enforce_scim_active(fresh)
            auth._enforce_workspace_policies(request, fresh)
        from .app import _channel_form_context

        context = _channel_form_context(request)
        if expected is not None and context != expected:
            raise HTTPException(409, "Your account or workspace changed. Reload Channels before continuing.")
        if write:
            transport._admin(request)
        return context, auth.caller_principal(request) or "local administrator"


def store():
    return GovernedRecordStore("channel-test-requests", "CHT", "channel_test_request")


def intake():
    from maverick_channels.delivery import DeliveryJournal

    return DeliveryJournal().store


def configuration(name):
    if name not in CHANNELS:
        raise HTTPException(422, "Choose a supported chat app.")
    with auth.fresh_configuration():
        cfg = dict(transport._channel_config(name))
    env = {"telegram": {"bot_token": "TELEGRAM_BOT_TOKEN"}, "discord": {"bot_token": "DISCORD_BOT_TOKEN"},
           "whatsapp_cloud": {"access_token": "WHATSAPP_CLOUD_ACCESS_TOKEN", "phone_number_id": "WHATSAPP_CLOUD_PHONE_NUMBER_ID"},
           "mattermost": {"bot_token": "MATTERMOST_BOT_TOKEN"}}[name]
    for field, key in env.items():
        cfg[field] = (os.environ.get(key) or cfg.get(field)) if name == "mattermost" else (cfg.get(field) or os.environ.get(key))
    if not (cfg.get("bot_token") if name != "whatsapp_cloud" else cfg.get("access_token") and cfg.get("phone_number_id")):
        raise HTTPException(409, "Save the chat app's connection details first.")
    _allowed_senders(name, cfg)
    return cfg


def _allowed_senders(name, cfg):
    allowed = normalize_allowlist(cfg.get("allowed_user_ids"), name.upper() + "_ALLOWED_USER_IDS")
    if name == "mattermost" and any(not re.fullmatch(r"[a-z0-9]{26}", person) for person in allowed):
        raise HTTPException(409, "Replace each Mattermost username in the permitted-people list with the person's 26-character user id.")
    return allowed


def _stamp(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= time.time():
        raise HTTPException(409, "This retained conversation has no usable received date.")
    return datetime.fromtimestamp(value, timezone.utc).strftime("%b %d, %Y, %H:%M UTC")


def _source(name, cfg, record, account):
    if (not isinstance(record, dict) or record.get("channel") != name or record.get("account_sha256") != account or
            record.get("restore_hold") or record.get("_audit_pending") or not record.get("message")):
        raise HTTPException(409, "This exact conversation is unavailable to the current chat account.")
    message = record["message"]
    destination, sender = message.get("user_id"), message.get("sender_id") or message.get("user_id")
    pattern = r"-?[0-9]{1,20}" if name == "telegram" else r"[0-9]{1,25}" if name in {"discord", "whatsapp_cloud"} else r"[a-z0-9]{26}"
    if not isinstance(destination, str) or not re.fullmatch(pattern, destination):
        raise HTTPException(409, "The retained conversation has no supported destination.")
    allowed = _allowed_senders(name, cfg)
    chats = normalize_allowlist(cfg.get("allowed_chat_ids"), "TELEGRAM_ALLOWED_CHAT_IDS") if name == "telegram" else set()
    if sender not in allowed and not (name == "telegram" and sender == destination and destination in chats):
        raise HTTPException(403, "The sender of this conversation is no longer permitted to message Lightwork.")
    received = record.get("created_at")
    label = "Incoming conversation retained " + _stamp(received)
    if name == "whatsapp_cloud" and time.time() - received >= 23 * 3600:
        raise HTTPException(409, "This WhatsApp conversation was retained too long ago for this test. Ask the person to message the bot again. WhatsApp also checks its current reply window.")
    return {"record": record["id"], "destination": destination, "sender": sender, "received": received,
            "binding": digest([record.get("fingerprint"), message, record.get("route"), record.get("account_sha256")]), "label": label}


def _encode(value):
    with deployment_key_scope():
        return seal_to_str(json.dumps(value, separators=(",", ":")))


def _decode(value):
    try:
        if not isinstance(value, str) or len(value) > 8192 or not is_sealed_str(value):
            raise ValueError("invalid token")
        with deployment_key_scope():
            result = json.loads(unseal_from_str(value))
        if not isinstance(result, dict):
            raise ValueError("invalid token")
        return result
    except (ValueError, TypeError, KeyError, EncryptionUnavailable) as exc:
        raise HTTPException(409, "This conversation selection changed. Read current conversations again.") from exc


def catalog(request, name, expected, cursor=""):
    context, actor = authority(request, expected, write=True)
    cfg = configuration(name)
    source = digest(cfg)

    def guard():
        authority(request, context)
        if digest(configuration(name)) != source:
            raise HTTPException(409, "Saved chat settings changed. Read current conversations again.")

    if cursor:
        scan = _decode(cursor)
        if any(scan.get(key) != value for key, value in (("context", context), ("actor", actor), ("name", name), ("source", source))) or time.time() >= scan.get("expires", 0):
            raise HTTPException(409, "This page changed or expired. Read current conversations again.")
    else:
        account = transport.reviewed_account(name, cfg, guard)
        if not account:
            raise HTTPException(409, "The chat service did not verify the current bot account.")
        scan = {"context": context, "actor": actor, "name": name, "source": source, "account": digest(account),
                "cursor": "", "first": "", "expires": time.time() + TTL}
    rows = list(intake().iter_record_ids(start_after=scan["cursor"], limit=50))
    choices, destinations = [], set()
    wrapped = False
    for position, record_id in rows:
        if scan["first"] and position == scan["first"]:
            wrapped = True
            break
        if not scan["first"]:
            scan["first"] = position
        scan["cursor"] = position
        record = intake().get(record_id)
        try:
            item = _source(name, cfg, record, scan["account"])
        except HTTPException:
            continue  # Other accounts, expired windows and withdrawn senders are not choices.
        if item["destination"] in destinations:
            continue
        destinations.add(item["destination"])
        token = _encode({**scan, "record": record_id, "binding": item["binding"]})
        choices.append({"value": token, "label": item["label"]})
    guard()
    more = len(rows) == 50 and not wrapped
    return {"context": context, "channel": name, "choices": choices, "next": _encode(scan) if more else "",
            "message": "Choose a conversation, then verify its current name and review the fixed message. More retained conversations are available." if more else
            "Choose a conversation, then verify its current name and review the fixed message." if choices else
            "No currently permitted conversation was found here. Have a permitted person message this bot, then read conversations again."}


def _current(request, value):
    context, actor = authority(request, value["context"], write=True)
    if actor != value["actor"] or time.time() >= value["expires"]:
        raise HTTPException(409, "This message review expired or belongs to another account. Review it again.")
    cfg = configuration(value["name"])
    if digest(cfg) != value["source"]:
        raise HTTPException(409, "Saved chat settings changed. Review the current connection again.")
    selected = _source(value["name"], cfg, intake().get(value["record"]), value["account"])
    if selected["binding"] != value["binding"]:
        raise HTTPException(409, "The selected conversation changed. Read current conversations again.")
    return cfg, selected


def review(request, choice, expected):
    context, _actor = authority(request, expected, write=True)
    value = _decode(choice)
    if value.get("context") != context:
        raise HTTPException(409, "Your account or workspace changed. Read current conversations again.")
    cfg, selected = _current(request, value)
    recipient = transport.reviewed_recipient(value["name"], cfg, selected["destination"], lambda: _current(request, value))
    value.update(id="CHT-" + secrets.token_hex(16), state="reviewed", recipient=recipient, destination=selected["destination"], expires=time.time() + TTL)
    with authority_effect_fence():
        saved = store().create(value, actor=value["actor"], action="channel_test_reviewed", max_records=10000,
                               effect_guard=lambda: _current(request, value))
    if saved.get("_audit_pending"):
        raise HTTPException(503, "The full message review could not be recorded. No message was sent.")
    authority(request, expected)
    return {"operation": saved["id"], "context": context, "review": {
        "Chat app": CHANNELS[value["name"]], "Destination": recipient["label"], "Incoming conversation retained": _stamp(selected["received"]),
        "Message to send": transport.TEST_TEXT, "Effect": "Send this one sentence to the exact selected conversation using the saved bot.",
        "Delivery": NOTICE + (" WhatsApp checks its current reply window and may refuse this test." if value["name"] == "whatsapp_cloud" else "")}}


def history(request, expected, cursor=""):
    context, actor = authority(request, expected)
    scan = _decode(cursor) if cursor else {"context": context, "actor": actor, "kind": "originals", "first": "", "cursor": "", "expires": time.time() + TTL}
    if any(scan.get(key) != value for key, value in (("context", context), ("actor", actor), ("kind", "originals"))) or time.time() >= scan.get("expires", 0):
        raise HTTPException(409, "This request list changed or expired. Read your current originals again.")
    rows = list(store().iter_record_ids(start_after=scan["cursor"], limit=50))
    choices, wrapped = [], False
    for position, record_id in rows:
        if scan["first"] and position == scan["first"]:
            wrapped = True
            break
        if not scan["first"]:
            scan["first"] = position
        scan["cursor"] = position
        row = store().get(record_id)
        if row and row.get("context") == context and row.get("actor") == actor and row.get("state") != "reviewed":
            choices.append({"value": record_id, "label": CHANNELS[row["name"]] + " · " + row["recipient"]["label"] + " · " + _stamp(row["created_at"])})
    authority(request, expected)
    return {"context": context, "choices": choices, "next": _encode(scan) if len(rows) == 50 and not wrapped else ""}


def _owned(request, operation, expected):
    context, actor = authority(request, expected)
    row = store().get(operation)
    if row is None or row.get("context") != context or row.get("actor") != actor:
        raise HTTPException(404, "This original test belongs to another account or workspace, or is unavailable.")
    return row


def original(request, operation, expected):
    row = _owned(request, operation, expected)
    if row.get("_audit_pending"):
        row = store()._flush(row)
    state = row["state"] if not row.get("_audit_pending") else "unknown"
    message = {"reviewed": "This review has not admitted a message send.",
               "accepted": "The chat service accepted your original test message. Check the conversation to confirm arrival.",
               "refused": "The chat service refused your original test message. Nothing was repeated."}.get(
                   state, "The original send is unconfirmed and may have arrived. Check the selected conversation. Nothing was repeated.")
    authority(request, expected)
    return {"operation": operation, "state": state, "confirmed": state in {"accepted", "refused"}, "message": message,
            "destination": row["recipient"]["label"], "channel": row["name"], "notice": NOTICE}


def apply(request, operation, expected):
    with authority_effect_fence():
        row = _owned(request, operation, expected)
        if row["state"] != "reviewed":
            return original(request, operation, expected)
        cfg, selected = _current(request, row)
        recipient = transport.reviewed_recipient(row["name"], cfg, selected["destination"], lambda: _current(request, row))
        if recipient != row["recipient"]:
            raise HTTPException(409, "The selected conversation's current name or identity changed. Review it again.")
        try:
            claimed = store().update(operation, lambda current: current.update(state="started"), expected_revision=row["revision"],
                                     actor=row["actor"], action="channel_test_started", effect_guard=lambda: _current(request, row))
        except RecordConflict:
            return original(request, operation, expected)
        if claimed.get("_audit_pending"):
            return original(request, operation, expected)
        try:
            state, receipt = transport.send_reviewed_test(row["name"], cfg, selected["destination"], lambda: _current(request, row))
            store().update(operation, lambda current: current.update(state=state, receipt_sha256=digest(receipt) if receipt else ""),
                           expected_revision=claimed["revision"], actor=row["actor"], action="channel_test_result_recorded")
        except Exception:
            # A claimed request never becomes another send, even if recording its result failed.
            pass
        return original(request, operation, expected)
