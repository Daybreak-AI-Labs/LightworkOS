"""Private channel delivery uses verified recipients, never organization webhooks.

Call dispatch under the authority fence, with a fresh authorized inbox projection.
No automatic resend follows an uncertain or interrupted provider request.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from .crypto_at_rest import seal, unseal
from .file_lock import atomic_write_bytes, cross_process_lock, ensure_private_directory
from .notifications import retry_delay
from .paths import data_dir
from .personal_notifications import alert_brief, delivery_window

_prune_cursor = 0


def _folder(principal: str):
    if not isinstance(principal, str) or not principal.startswith("user:"):
        raise ValueError("A named account is required.")
    # 128-bit opaque path components keep nested tenant paths portable on Windows.
    return data_dir("personal-notifications", "deliveries", hashlib.sha256(principal.encode()).hexdigest()[:32])


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _settings() -> dict:
    from .config import config_source_errors, load_config
    if config_source_errors(include_tenant=True):
        raise ValueError("Notification policy is unavailable.")
    from .personal_notifications import personal_alerts_on

    value = load_config().get("notifications") or {}
    if not (personal_alerts_on(value)
            and all(value.get(key) is True for key in ("personal_background", "personal_external"))):
        raise ValueError("Personal private-channel delivery is disabled.")
    return value


def _base_url(settings: dict) -> str:
    base = str(settings.get("personal_dashboard_url") or "").strip().rstrip("/")
    parsed = urlsplit(base)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in {"", "/"} or len(base) > 500):
        raise ValueError("Save the HTTPS dashboard origin before private-channel delivery.")
    return base


def teams_destination(reference, account_sha256, sender):
    """A private destination comes only from the signed native Teams receipt."""
    keys = {"service_url", "conversation_id", "tenant_id", "sender_id", "app_id"}
    if (not isinstance(reference, dict) or set(reference) != keys
            or any(not isinstance(value, str) or not value or len(value) > 2048 for value in reference.values())
            or reference["sender_id"] != sender or _digest(reference["app_id"]) != account_sha256):
        raise ValueError("Relink Teams from a private chat with the current Lightwork bot.")
    url = urlsplit(reference["service_url"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("The verified private Teams destination is unavailable.")
    return dict(reference)


def _teams_transport(link):
    from maverick_channels.teams import channel_config, is_allowed

    from .config import load_global_config

    cfg = channel_config((load_global_config().get("channels") or {}).get("teams") or {})
    ref = teams_destination(link.get("private_destination"), link.get("account_sha256"), link.get("sender_id"))
    tenants = {value.lower() for value in cfg["allowed_tenants"]} or {cfg["tenant_id"]}
    if (not cfg["enabled"] or not cfg["app_id"] or not cfg["app_password"]
            or cfg["app_id"] != ref["app_id"] or ref["tenant_id"].lower() not in tenants
            or not is_allowed(ref["sender_id"].lower(), {value.lower() for value in cfg["allowed_users"]})):
        raise ValueError("Review the current Teams bot, organization and permitted person in Channels.")
    return cfg, ref


def _transport(link: dict) -> tuple[str, object]:
    from .config import load_global_config
    channel, sender = link["channel"], link.get("sender_id", "")
    if channel == "teams":
        return channel, _teams_transport(link)
    if channel not in {"slack", "telegram"}:
        raise ValueError("This linked channel does not support private personal alerts.")
    if not isinstance(sender, str) or not re.fullmatch(r"[UW][A-Z0-9]{7,30}" if channel == "slack" else r"[1-9][0-9]{0,15}", sender):
        raise ValueError("The linked identity is not an exact supported private recipient.")
    section = (load_global_config().get("channels") or {}).get(channel) or {}
    if section.get("enabled") is not True:
        raise ValueError("This messaging channel is disabled.")
    def allowlist(key, env):
        values = section.get(key)
        if values is None:
            values = os.environ.get(env, "").split(",")
        return {str(value).strip() for value in values} if isinstance(values, (list, tuple, set)) else set()
    permitted = allowlist("allowed_user_ids", channel.upper() + "_ALLOWED_USER_IDS")
    if channel == "telegram":
        permitted |= allowlist("allowed_chat_ids", "TELEGRAM_ALLOWED_CHAT_IDS")
    if sender not in permitted:
        raise ValueError("The linked person is no longer allowed by this channel.")
    token = section.get("bot_token") or os.environ.get(channel.upper() + "_BOT_TOKEN")
    if (not isinstance(token, str) or not token or any(ord(c) < 33 or ord(c) > 126 for c in token)
            or (channel == "telegram" and not re.fullmatch(r"[1-9][0-9]*:[A-Za-z0-9_-]+", token))):
        raise ValueError("The configured bot credential is unavailable.")
    return channel, token


class Refused(Exception):
    pass


class Unconfirmed(Exception):
    pass


def _post(url, token, payload) -> dict:
    import urllib.error
    import urllib.request
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    # Fixed provider endpoints only, no redirects or environment proxy rerouting.
    # urllib also avoids httpx's INFO request-URL log exposing Telegram bot tokens.
    deadline = time.monotonic() + 5
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    body = bytearray()
    try:
        with opener.open(request, timeout=5) as response:
            while True:
                reader = getattr(response, "read1", None)
                chunk = reader(8192) if reader else response.read(1)
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > 65536 or time.monotonic() > deadline:
                    raise Unconfirmed
    except urllib.error.HTTPError as exc:
        if 400 <= exc.code < 500 and exc.code != 408:
            raise Refused from None
        raise Unconfirmed from None
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise Unconfirmed from exc
    if not isinstance(value, dict):
        raise Unconfirmed
    if value.get("ok") is not True:
        if value.get("error") in {"invalid_auth", "token_revoked", "account_inactive", "missing_scope", "not_authed", "channel_not_found", "user_not_found", "ratelimited"} or value.get("error_code") in {400, 401, 403, 404, 429}:
            raise Refused
        raise Unconfirmed
    return value


def send_private(link: dict, text: str, buttons: list[dict] | None = None, *, effect_guard=None) -> str:
    """Current bot identity must match the account that proved the link.

    ``buttons`` are Slack button elements (the one-action mute); Telegram
    messages carry the same choice as a link in ``text``."""
    channel, token = _transport(link)
    def current_destination():
        from .personal_identity import linked_channels

        _settings()
        principal = link.get("principal", "")
        if (not isinstance(principal, str) or not principal.startswith("user:")
                or next((row for row in linked_channels(principal) if row["id"] == link.get("id")), None) != link
                or _transport(link) != (channel, token)):
            raise Refused
        if effect_guard is not None:
            effect_guard()

    def post(url, credential, payload):
        current_destination()
        return _post(url, credential, payload)

    current_destination()
    sender = link["sender_id"]
    if channel == "teams":
        import asyncio

        from maverick_channels.delivery import DeliveryNotSent, DeliveryUnknown
        from maverick_channels.teams import TeamsAuthError, TeamsConnector, default_transport

        cfg, ref = token
        async def transport(*args, **kwargs):
            current_destination()
            kwargs["timeout"] = min(float(kwargs.get("timeout", 5)), 5)
            return await default_transport(*args, **kwargs)
        connector = TeamsConnector(cfg["app_id"], cfg["app_password"], cfg["tenant_id"] or None, transport=transport)
        try:
            ident = asyncio.run(connector.send_activity(ref["service_url"], ref["conversation_id"],
                                                       {"text": text, "textFormat": "plain"}))
        except (DeliveryNotSent, TeamsAuthError) as exc:
            raise Refused from exc
        except DeliveryUnknown as exc:
            raise Unconfirmed from exc
        if not ident:
            raise Unconfirmed
        return ident
    elif channel == "telegram":
        account = token.split(":", 1)[0]
        if not account.isdigit() or not hmac.compare_digest(_digest(account), link.get("account_sha256", "")):
            raise Refused
        value = post("https://api.telegram.org/bot" + token + "/sendMessage", "",
                      {"chat_id": int(sender), "text": text, "link_preview_options": {"is_disabled": True}})
        result = value.get("result")
        if not isinstance(result, dict) or type(result.get("message_id")) is not int:
            raise Unconfirmed
        return str(result["message_id"])
    else:
        identity = post("https://slack.com/api/auth.test", token, {})
        account = str(identity.get("team_id") or "") + ":" + str(identity.get("user_id") or "")
        if not identity.get("team_id") or not identity.get("user_id") or not hmac.compare_digest(_digest(account), link.get("account_sha256", "")):
            raise Refused
        opened = post("https://slack.com/api/conversations.open", token, {"users": sender, "return_im": True})
        target = opened.get("channel")
        if (not isinstance(target, dict) or target.get("is_im") is not True or target.get("user") != sender
                or not re.fullmatch(r"D[A-Z0-9]{7,30}", str(target.get("id") or ""))):
            raise Refused
        message = {"channel": target["id"], "text": text, "mrkdwn": False, "unfurl_links": False, "unfurl_media": False}
        if buttons:
            message["blocks"] = [{"type": "section", "text": {"type": "plain_text", "text": text[:2900], "emoji": False}},
                                 {"type": "actions", "elements": buttons[:5]}]
        posted = post("https://slack.com/api/chat.postMessage", token, message)
        if not isinstance(posted.get("ts"), str):
            raise Unconfirmed
        return posted["ts"]


class DeliveryStore:
    def __init__(self, principal: str, link: dict, path=None):
        self.principal_sha256 = hashlib.sha256(principal.encode()).hexdigest()
        self.scope = _digest([principal, link["id"], link["verified_at"]]) if link else None
        self.path = path or _folder(principal) / (_digest([link["id"], link["verified_at"]])[:32] + ".enc")

    def _read(self):
        try:
            state = json.loads(unseal(self.path.read_bytes()).decode())
        except FileNotFoundError:
            state = {"consumed": {}, "receipts": [], "digest_day": "",
                     "principal_sha256": self.principal_sha256, "scope": self.scope}
        if (not isinstance(state, dict) or not isinstance(state.get("consumed"), dict)
                or not isinstance(state.get("receipts"), list) or len(state["consumed"]) > 1000
                or state.get("principal_sha256") != self.principal_sha256
                or (self.scope is not None and state.get("scope") != self.scope)
                # In-flight claims and the back-off after a refusal (older files have neither).
                or not isinstance(state.setdefault("claims", {}), dict)
                or not isinstance(state.setdefault("retry", {}), dict)):
            raise ValueError("Personal delivery history is unavailable.")
        threshold = time.time() - 7 * 86400
        state["consumed"] = {key: at for key, at in state["consumed"].items() if at > threshold}
        state["receipts"] = [row for row in state["receipts"] if row["at"] > threshold][-100:]
        for key in ("claims", "retry"):
            state[key] = {name: row for name, row in state[key].items()
                          if isinstance(row, dict) and isinstance(row.get("at"), (int, float)) and row["at"] > threshold}
        return state

    @staticmethod
    def _waiting(state, item_id, now):
        """Still inside the wait after a definite refusal of this alert."""
        entry = state["retry"].get(item_id)
        try:
            return entry is not None and float(entry["at"]) <= now < float(entry.get("next_at") or 0)
        except (TypeError, ValueError):
            return False

    def _write(self, state):
        atomic_write_bytes(self.path, seal(json.dumps(state).encode()), mode=0o600)

    def claim(self, items: list[dict], *, day: str = "") -> tuple[str, list[dict]] | None:
        ensure_private_directory(self.path.parent)
        with cross_process_lock(self.path):
            state = self._read()
            if day and state["digest_day"] == day:
                return None
            now = time.time()
            fresh = [item for item in items
                     if item["id"] not in state["consumed"] and not self._waiting(state, item["id"], now)]
            if not fresh:
                return None
            if len(state["consumed"]) + len(fresh) > 1000:
                raise ValueError("Personal delivery history is full; sends paused to preserve duplicate protection.")
            ident = _digest([day, [item["id"] for item in fresh], now])
            state["consumed"].update({item["id"]: now for item in fresh})
            # Kept until the send's outcome is known: only a definite refusal gives these back.
            state["claims"][ident] = {"items": [item["id"] for item in fresh], "day": day, "at": now}
            state["receipts"].append({"id": ident, "at": now, "state": "sending", "count": len(fresh),
                                      "message": "Waiting for service acceptance; not marked seen."})
            if day:
                state["digest_day"] = day
            self._write(state)
            return ident, fresh

    def finish(self, ident, result, message, *, provider_reference=""):
        with cross_process_lock(self.path):
            state = self._read()
            for row in state["receipts"]:
                if row["id"] == ident:
                    row.update(state=result, message=message)
                    if isinstance(provider_reference, str) and provider_reference:
                        row["provider_reference"] = provider_reference[:512]
            claim = state["claims"].pop(ident, None)
            if claim and result == "failed":
                self._release(state, claim)
            elif claim:
                for item_id in claim["items"]:
                    state["retry"].pop(item_id, None)
            self._write(state)

    @staticmethod
    def _release(state, claim):
        """A definite refusal sent nothing: give the claim back, to be offered again
        after the shared back-off (5, 10, 20, 40, 60 minutes, then hourly). An
        uncertain outcome never comes here, so it is never replayed."""
        now = time.time()
        for item_id in claim["items"]:
            state["consumed"].pop(item_id, None)
            try:
                before = int((state["retry"].get(item_id) or {}).get("failures") or 0)
            except (TypeError, ValueError):
                before = 0
            state["retry"][item_id] = {"failures": before + 1, "next_at": now + retry_delay(before + 1), "at": now}
        if claim["day"] and state["digest_day"] == claim["day"]:
            state["digest_day"] = ""
        newest = sorted(state["retry"], key=lambda key: state["retry"][key]["at"], reverse=True)[:1000]
        state["retry"] = {key: state["retry"][key] for key in newest}


    def recent(self):
        state = self._read()
        return [{**row, **({"state": "unknown", "message": "The send was interrupted; acceptance is unknown. No automatic resend."}
                           if row["state"] == "sending" and row["at"] < time.time() - 120 else {})}
                for row in reversed(state["receipts"][-10:])]

    def pending(self, items):
        state = self._read()
        now = time.time()
        return [item for item in items
                if item["id"] not in state["consumed"] and not self._waiting(state, item["id"], now)]


def _mute_choice(principal: str, base: str, item: dict) -> tuple[str, str, dict] | None:
    """The one-action mute for one alert (NOT-2): its words, link and Slack button."""
    try:
        from .notification_unsubscribe import for_item, sign
        from .slack_interactive import mute_button

        target = for_item(item)
        if target is None:
            return None
        token = sign(principal, *target)
    except Exception:  # noqa: BLE001 -- the alert still goes out without it
        return None
    words = "Mute alerts about this task" if target[0] == "task" else "Mute alerts from this agent"
    return words, base + "/unsubscribe/" + token, mute_button(token, words)


def dispatch(principal: str, inbox: dict, preferences: dict) -> None:
    from . import practice
    if practice.active():  # practice mode: personal messages are recorded, never sent
        practice.record("personal message", "Private chat message", {"items": len(inbox.get("items") or [])})
        return
    from .personal_identity import linked_channels, principal_current
    settings = _settings()
    if preferences["mode"] == "off" or not principal_current(principal):
        return
    base = _base_url(settings)
    now = time.time()
    allowed, _ = delivery_window(preferences, now=now)
    items = inbox["items"]
    if not allowed:
        if settings.get("personal_critical_bypass") is True and preferences["critical_exceptions"]:
            items = [item for item in items if item["category"] in {"needs-decision", "deadline"}]
        else:
            return
    # Something the person already saw in the app is not sent to them again.
    items = [item for item in items if not item.get("seen_at")]
    day = datetime.fromtimestamp(now, timezone.utc).astimezone(ZoneInfo(preferences["timezone"])).date().isoformat()
    links = [link for link in linked_channels(principal) if link["id"] in preferences["external_links"]]
    from .personal_push_devices import active as private_destinations
    links.extend(private_destinations(principal, now=now))
    # Oldest attempted destination first, so one slow person cannot monopolize
    # the observer and multiple selected destinations make bounded progress.
    links.sort(key=lambda link: max((row["at"] for row in DeliveryStore(principal, link).recent()), default=0))
    for link in links:
        store = DeliveryStore(principal, link)
        # Immediate alerts carry one exact-task link per bounded observation;
        # digests claim all current items once per local day in one atomic record.
        pending = store.pending(items)
        batches = [pending] if preferences["mode"] == "digest" and allowed else [[item] for item in pending[:1]]
        for batch in batches:
            claimed = store.claim(batch, day=day if preferences["mode"] == "digest" and allowed else "")
            if claimed is None:
                continue
            ident, fresh = claimed
            lines, buttons = [], []
            for item in fresh[:5]:
                href = item.get("href", "")
                if (isinstance(href, str) and href.startswith("/") and not href.startswith("//")
                        and not any(char in href for char in "\r\n\\")):
                    # Why, what and by when, never task text; then the exact link.
                    line = alert_brief(item, time_zone=preferences["timezone"]) + "\n" + base + href
                    quiet = _mute_choice(principal, base, item)
                    if quiet:
                        line += "\n" + quiet[0] + ": " + quiet[1]
                        if len(buttons) < 4:
                            buttons.append(quiet[2])
                    lines.append(line)
            text = "Lightwork has " + str(len(fresh)) + " update(s) for you. Sign in to review.\n" + "\n".join(lines)
            if len(fresh) > 5 or not lines:
                text += "\n" + base + "/notifications"
            try:
                # The caller's authority fence excludes local revocation across
                # final identity/config checks and this bounded external effect.
                _settings()
                if link["channel"] == "private-topic":
                    from .personal_push_devices import send as send_destination
                    reference = send_destination(principal, link["destination"], text)
                else:
                    current = next((value for value in linked_channels(principal) if value["id"] == link["id"]), None)
                    if current != link:
                        raise Refused
                    if buttons and link["channel"] == "slack":
                        reference = send_private(link, text, buttons)
                    else:
                        reference = send_private(link, text)
            except (Refused, ValueError):
                store.finish(ident, "failed", "Not accepted. Review the linked identity, channel access and bot configuration. Lightwork tries again after a wait.")
            except Exception:
                store.finish(ident, "unknown", "Acceptance is unknown. Check the private conversation before another send; no automatic retry.")
            else:
                store.finish(ident, "accepted", "The service accepted this message. This does not mean you saw it.",
                             provider_reference=reference)
            return  # One bounded provider dispatch per recipient observation.


def status(principal: str) -> dict:
    from .personal_identity import enabled as identity_links_enabled
    from .personal_identity import linked_channels
    try:
        _base_url(_settings())
        ready, reason = True, "Select a verified private channel to opt in."
    except ValueError as exc:
        ready, reason = False, str(exc)
    if ready and not identity_links_enabled():
        ready = False
        reason = "Private delivery needs My Data identity linking. Ask an administrator to enable personal data controls in All settings."
    channels = []
    for link in linked_channels(principal):
        supported, why = True, ""
        try:
            _transport(link)
        except ValueError as exc:
            supported, why = False, str(exc)
        channels.append({"id": link["id"], "channel": link["channel"], "sender_id": link["sender_id"],
                         "available": ready and supported, "reason": why,
                         "receipts": DeliveryStore(principal, link).recent()})
    return {"enabled": ready, "note": reason, "channels": channels}


def remove_link_history(principal: str, link: dict) -> None:
    store = DeliveryStore(principal, link)
    path = store.path
    if path.parent.is_dir():
        with cross_process_lock(path):
            store._read()
            path.unlink(missing_ok=True)


def remove_personal_history(principal: str) -> None:
    folder = _folder(principal)
    failure = None
    if folder.is_dir():
        for path in folder.glob("*.enc"):
            if re.fullmatch(r"[0-9a-f]{32}\.enc", path.name):
                # One unreadable ledger must not stop erasure of the others;
                # it is kept, and the failure is still reported at the end.
                try:
                    with cross_process_lock(path):
                        DeliveryStore(principal, {}, path=path)._read()
                        path.unlink(missing_ok=True)
                except Exception as exc:  # noqa: BLE001 -- re-raised below
                    failure = failure or exc
    if failure is not None:
        raise failure


def personal_history_inventory(principal: str) -> dict:
    """Bounded owned receipt metadata for My Data, without destinations/content."""
    folder = _folder(principal)
    paths = sorted(path for path in folder.glob("*.enc")
                   if re.fullmatch(r"[0-9a-f]{32}\.enc", path.name) and not path.is_symlink()) if folder.is_dir() else []
    records = []
    consumed = 0
    for path in paths[:200]:
        state = DeliveryStore(principal, {}, path=path)._read()
        consumed += len(state["consumed"])
        records.extend({key: row[key] for key in ("at", "state", "count", "message")}
                       for row in state["receipts"])
    return {"files": len(paths), "consumed_items": consumed,
            "receipts": sorted(records, key=lambda row: row["at"], reverse=True)[:1000],
            "partial": len(paths) > 200 or len(records) > 1000, "encrypted": True,
            "retention_days": 7,
            "note": "Content-free send outcomes are separate from seen status. Unlinking stops delivery; My Data erasure removes this history. Physical expiry cleanup runs while the dashboard is running."}


def prune_expired() -> None:
    """Bounded physical cleanup, including unlinked and inactive recipients."""
    global _prune_cursor
    folder = data_dir("personal-notifications", "deliveries")
    paths = sorted(folder.glob("*/*.enc")) if folder.is_dir() else []
    if not paths:
        return
    threshold = time.time() - 7 * 86400
    for _ in range(min(200, len(paths))):
        path = paths[_prune_cursor % len(paths)]
        _prune_cursor += 1
        if (path.is_symlink() or path.parent.is_symlink() or not re.fullmatch(r"[0-9a-f]{32}", path.parent.name)
                or not re.fullmatch(r"[0-9a-f]{32}\.enc", path.name)):
            continue
        with cross_process_lock(path):
            if path.exists() and path.stat().st_mtime < threshold:
                path.unlink()
