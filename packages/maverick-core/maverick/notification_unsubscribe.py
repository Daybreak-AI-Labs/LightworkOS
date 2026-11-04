"""One-action mute and unsubscribe from inside a notification (NOT-2).

An email, Slack or Telegram message about a task carries a signed link (and
in Slack a button) that mutes alerts about that task, or every alert from its
agent, or stops the daily summary, in one action and without signing in. The
link is the authority: an HMAC over the person, the workspace, what it mutes
and when it stops working, made with a key that never leaves this
installation. It can only quiet that one person's own notifications, for at
most the seven days a mute lasts, and every mute can be undone from the page
it lands on or from notification preferences.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time

#: How long a link in a message keeps working.
LINK_SECONDS = 30 * 86400
SCOPES = ("task", "agent", "summary")
_KEY = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z")


class LinkRefused(ValueError):
    """The link is altered, expired, or for something it cannot change."""


def _secret() -> bytes:
    from .file_lock import atomic_write_bytes, cross_process_lock, ensure_private_directory
    from .paths import maverick_home

    path = maverick_home() / "notification-links" / "signing.key"
    try:
        value = path.read_bytes()
        if len(value) == 32:
            return value
    except FileNotFoundError:
        pass
    ensure_private_directory(path.parent)
    with cross_process_lock(path):
        try:
            value = path.read_bytes()
            if len(value) == 32:
                return value
        except FileNotFoundError:
            pass
        value = secrets.token_bytes(32)
        atomic_write_bytes(path, value, mode=0o600)
        return value


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(principal: str, scope: str, key: str = "", *, tenant: str | None = None,
         undo: bool = False, now: float | None = None) -> str:
    """A link token that mutes (or with ``undo`` unmutes) one thing for one person."""
    if not isinstance(principal, str) or not principal.startswith("user:") or len(principal) > 256:
        raise ValueError("A named account is required.")
    if scope not in SCOPES:
        raise ValueError("Choose a task, an agent or the daily summary.")
    if scope != "summary" and not _KEY.fullmatch(str(key)):
        raise ValueError("Choose the task or agent to mute.")
    if tenant is None:
        from .paths import current_tenant_id_strict

        tenant = current_tenant_id_strict()
    current = time.time() if now is None else float(now)
    body = json.dumps({"p": principal, "s": scope, "k": "" if scope == "summary" else str(key),
                       "t": tenant or "", "u": bool(undo), "e": int(current + LINK_SECONDS)},
                      separators=(",", ":"), sort_keys=True).encode()
    mac = hmac.new(_secret(), body, hashlib.sha256).digest()
    return _b64(body) + "." + _b64(mac)


def verify(token: str, *, now: float | None = None) -> dict:
    """``{principal, scope, key, tenant, undo}`` for a genuine, current link."""
    try:
        body_text, mac_text = str(token or "").split(".", 1)
        if len(token) > 1200:
            raise ValueError
        body, mac = _unb64(body_text), _unb64(mac_text)
    except (ValueError, TypeError) as exc:
        raise LinkRefused("This link is not complete. Use the link in the latest message.") from exc
    if not hmac.compare_digest(hmac.new(_secret(), body, hashlib.sha256).digest(), mac):
        raise LinkRefused("This link is not complete. Use the link in the latest message.")
    value = json.loads(body)
    current = time.time() if now is None else float(now)
    if int(value.get("e") or 0) < current:
        raise LinkRefused("This link has expired. Change your notifications in Lightwork instead.")
    return {"principal": value["p"], "scope": value["s"], "key": value["k"],
            "tenant": value["t"] or None, "undo": bool(value["u"])}


def apply(principal: str, scope: str, key: str = "", *, undo: bool = False) -> dict:
    """Mute (or unmute) for this person now. The caller pins the workspace."""
    if scope == "summary":
        from . import user_preferences

        user_preferences.set_preferences(principal, digest_enabled=bool(undo))
        return {"scope": scope, "key": "", "until": None, "undo": undo}
    from . import experience_preferences as preferences
    from .personal_notifications import MUTE_SECONDS, validate_preferences

    field = "muted_tasks" if scope == "task" else "muted_agents"
    until = time.time() + MUTE_SECONDS
    for _attempt in range(3):
        state = preferences.state(principal)
        choice = validate_preferences(state["values"].get("notification_preferences", {}))
        mutes = {k: v for k, v in choice[field].items() if k != key}
        if not undo:
            mutes[key] = until
        try:
            preferences.save(principal, scope="personal",
                             changes={"notification_preferences": {**choice, field: mutes}},
                             expected_revision=state["revision"])
            break
        except preferences.PreferenceConflict:
            continue
    else:
        raise LinkRefused("Your notification settings were changing. Try the link again.")
    return {"scope": scope, "key": key, "until": None if undo else until, "undo": undo}


def link(base: str, principal: str, scope: str, key: str = "") -> str:
    """The full one-action link for a message, or "" without a dashboard address."""
    base = str(base or "").rstrip("/")
    if not base:
        return ""
    return base + "/unsubscribe/" + sign(principal, scope, key)


def for_item(item: dict) -> tuple[str, str] | None:
    """What a "Mute" control in a message about ``item`` should mute."""
    goal = item.get("goal_id")
    if isinstance(goal, int) and not isinstance(goal, bool) and goal > 0:
        return "task", str(goal)
    agent = item.get("agent")
    if isinstance(agent, str) and _KEY.fullmatch(agent):
        return "agent", agent
    return None
