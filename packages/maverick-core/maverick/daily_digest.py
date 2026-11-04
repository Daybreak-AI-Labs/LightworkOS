"""The personal daily summary: the same content as the My work page.

:func:`compose_digest` gathers one person's pending approvals, open
questions an agent is waiting on, recent results and this month's spending.
The dashboard page ``/me`` shows it; :func:`run_digest_cycle` (driven by
``maverick_dashboard.daily_digest_scheduler``) sends it once a day at the
person's own hour in their own time zone through their linked channels:

* Slack DM as Block Kit (``maverick.slack_interactive``),
* email through the platform SMTP backend (``maverick.notifications``),
* any sender another adapter registers with :func:`register_digest_sender`
  (the Teams adapter hooks in here).

An empty summary is skipped unless the person opted into "send even when
empty"; a person can turn the summary off on ``/me``. Every send is written
to the audit log with the recipient, the channel and item counts only.

The day counts as done only once a channel accepted the summary. When every
channel definitely did not send it (nothing set up, or refused), it is tried
again after a growing wait (:data:`RETRY_MINUTES`, then hourly) -- at once
when the person's channels or the channel settings change -- so fixing the
channel still delivers today's summary without an attempt (and an audit
row) on every poll. When a channel may have sent it without confirming, it
is not sent again.
"""
from __future__ import annotations

import html
import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from .notifications import RETRY_MINUTES, retry_delay

log = logging.getLogger(__name__)

RECENT_DAYS = 7
MAX_ITEMS = 25
_STATUS_LABELS = {
    "done": "Finished", "blocked": "Needs attention", "failed": "Did not finish",
    "cancelled": "Cancelled", "active": "In progress", "pending": "Waiting to start",
}
_senders: dict[str, Callable[..., bool]] = {}
_senders_lock = threading.Lock()
DigestSender = Callable[[str, dict[str, Any], list[dict[str, Any]], dict[str, Any]], bool]


def _zone(name: str):
    from zoneinfo import ZoneInfo

    try:
        return ZoneInfo(name or "UTC")
    except Exception:  # noqa: BLE001 -- an unknown zone falls back to UTC
        return timezone.utc


def month_start(now: float, time_zone: str) -> float:
    local = datetime.fromtimestamp(now, tz=_zone(time_zone))
    return local.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp()


def _approvals(world, principal: str, *, can_decide: bool, now: float,
               suites: frozenset[str] | None = None) -> list[dict[str, Any]]:
    from .channel_approvals import card_content

    rows = []
    for row in world.pending_approvals()[:500]:
        mine = row.requested_by == principal
        if can_decide and not mine:
            # The queue the person may decide: not claimed by somebody else,
            # not already voted on by them, and within their departments
            # (``suites``; None is unrestricted), as the bell and reminders do.
            if row.claimed_by and row.claimed_by != principal:
                continue
            department = getattr(row, "department", None)
            if department and suites is not None and department not in suites:
                continue
            state = world.approval_state(row.id) or {}
            if state.get("status") != "pending" or principal in (state.get("approvers") or []):
                continue
        elif not mine:
            continue
        content = card_content(row, now=now)
        content["waiting_on"] = "someone else" if (mine or not can_decide) else "you"
        content["requested_at"] = float(row.requested_at or 0)
        rows.append(content)
        if len(rows) >= MAX_ITEMS:
            break
    return rows


def _results(world, principal: str, *, owner_filter: str | None, now: float,
             seen: set[int] | frozenset[int] = frozenset(),
             muted: set[int] | frozenset[int] = frozenset()) -> tuple[list[dict[str, Any]], int]:
    """Recent results, less those already seen in the app (and how many) and
    those the person muted."""
    since = now - RECENT_DAYS * 86400
    out, skipped = [], 0
    for goal in world.list_goals(owner=owner_filter, limit=200, order="desc"):
        if goal.status in ("active", "pending") or float(goal.updated_at or 0) < since:
            continue
        if goal.id in muted:
            continue
        if goal.id in seen:
            skipped += 1
            continue
        summary = " ".join(str(goal.result or "").split())
        out.append({
            "id": goal.id, "title": str(goal.title)[:200], "status": goal.status,
            "status_label": _STATUS_LABELS.get(goal.status, goal.status.replace("_", " ")),
            "updated_at": float(goal.updated_at or 0),
            "summary": summary[:240] + ("…" if len(summary) > 240 else ""),
            "href": f"/chat/goal/{goal.id}",
        })
        if len(out) >= MAX_ITEMS:
            break
    return out, skipped


def _questions(world, principal: str, *, owner_filter: str | None) -> list[dict[str, Any]]:
    out = []
    goals: dict[int, Any] = {}
    for question in world.open_questions()[:500]:
        goal = None
        if question.goal_id is not None:
            if question.goal_id not in goals:
                goals[question.goal_id] = world.get_goal(question.goal_id)
            goal = goals[question.goal_id]
        owner = getattr(goal, "owner", "") if goal is not None else ""
        if owner_filter is not None and owner != principal:
            continue
        out.append({
            "id": question.id, "goal_id": question.goal_id,
            "goal_title": str(getattr(goal, "title", "") or "")[:200],
            "question": " ".join(str(question.question or "").split())[:400],
            "asked_at": float(question.asked_at or 0),
            # Opens the task with the answer box in view.
            "href": f"/chat/goal/{question.goal_id}#question-panel" if question.goal_id else "/chat",
        })
        if len(out) >= MAX_ITEMS:
            break
    return out


KEY_EXPIRY_DAYS = 7


def _expiring_keys(principal: str, *, owner_filter: str | None, now: float) -> list[dict[str, Any]]:
    """Access keys that stop working within a week (``maverick_dashboard.api_keys``
    when that module is installed; silently nothing otherwise)."""
    try:
        from maverick_dashboard.api_keys import expiring_soon, list_keys
    except ImportError:
        return []
    try:
        keys = expiring_soon(list_keys(owner=owner_filter), within_days=KEY_EXPIRY_DAYS, now=now)
    except Exception:  # noqa: BLE001 -- an unreadable key store never breaks the summary
        log.debug("digest key lookup failed", exc_info=True)
        return []
    rows = []
    for key in sorted(keys, key=lambda k: float(getattr(k, "expires_at", 0) or 0)):
        expires_at = float(getattr(key, "expires_at", 0) or 0)
        rows.append({
            "id": str(getattr(key, "id", "")), "label": str(getattr(key, "label", "") or "")[:200],
            "prefix": str(getattr(key, "prefix", "") or ""), "owner": str(getattr(key, "owner", "") or ""),
            "expires_at": expires_at,
            "days_left": max(0, int((expires_at - now) // 86400)),
            "href": "/api-keys",
        })
        if len(rows) >= MAX_ITEMS:
            break
    return rows


def compose_digest(world, principal: str, *, can_decide: bool, sees_everything: bool = False,
                   suites: frozenset[str] | None = None,
                   now: float | None = None, time_zone: str = "UTC",
                   spend_limit: float | None = None,
                   seen_goal_ids: set[int] | frozenset[int] | None = None,
                   muted_goal_ids: set[int] | frozenset[int] | None = None) -> dict[str, Any]:
    """Everything one person has waiting, as plain data.

    ``can_decide`` (the ``operate`` permission) shows the approvals queue they
    may decide; without it only their own requests appear. ``sees_everything``
    (a break-glass administrator) lifts the owner filter on results, questions
    and spending, exactly like the Goals page. Results in ``seen_goal_ids``
    (already seen in the app) are left out; approvals and questions stay
    because they still need the person.
    """
    current = time.time() if now is None else float(now)
    owner_filter = None if sees_everything else principal
    if spend_limit is None:
        try:
            from .config import get_my_work

            spend_limit = float(get_my_work().get("monthly_spend_limit_dollars") or 0)
        except Exception:  # noqa: BLE001 -- an unreadable config shows no limit
            spend_limit = 0.0
    start = month_start(current, time_zone)
    try:
        spend = world.total_spend(owner=owner_filter, since=start)
    except Exception:  # noqa: BLE001 -- the page still renders without the figure
        log.debug("digest spend lookup failed", exc_info=True)
        spend = {"dollars": 0.0, "runs": 0}
    local = datetime.fromtimestamp(current, tz=_zone(time_zone))
    results, left_out = _results(world, principal, owner_filter=owner_filter, now=current,
                                 seen=frozenset(seen_goal_ids or ()), muted=frozenset(muted_goal_ids or ()))
    digest = {
        "principal": principal,
        "generated_at": current,
        "date_label": local.strftime("%A %d %B %Y"),
        "local_date": local.strftime("%Y-%m-%d"),
        "time_zone": time_zone or "UTC",
        "approvals": _approvals(world, principal, can_decide=can_decide, now=current, suites=suites),
        "results": results,
        "left_out_seen": left_out,
        "questions": _questions(world, principal, owner_filter=owner_filter),
        "expiring_keys": _expiring_keys(principal, owner_filter=owner_filter, now=current),
        "spending": {
            "dollars": round(float(spend.get("dollars") or 0), 4),
            "runs": int(spend.get("runs") or 0),
            "limit_dollars": float(spend_limit or 0),
            "month_label": local.strftime("%B %Y"),
            "over_limit": bool(spend_limit and float(spend.get("dollars") or 0) > spend_limit),
        },
    }
    digest["counts"] = {
        "approvals": len(digest["approvals"]),
        "results": len(digest["results"]),
        "questions": len(digest["questions"]),
        "expiring_keys": len(digest["expiring_keys"]),
    }
    digest["empty"] = not any(digest["counts"].values())
    return digest


def _seen_in_app(principal: str) -> frozenset[int]:
    """Results this person already saw in the app are not repeated (NOT-2)."""
    if not str(principal).startswith("user:"):
        return frozenset()
    try:
        from .personal_notifications import PersonalInbox

        return frozenset(PersonalInbox(principal).seen_goal_ids())
    except Exception:  # noqa: BLE001 -- unreadable history repeats rather than hides
        log.debug("digest seen-state lookup failed", exc_info=True)
        return frozenset()


def _muted_in_app(principal: str, now: float | None = None) -> frozenset[int]:
    """Tasks this person muted from an alert or a message: left out of the summary too."""
    if not str(principal).startswith("user:"):
        return frozenset()
    try:
        from . import experience_preferences
        from .personal_notifications import validate_preferences

        values = experience_preferences.state(principal)["values"].get("notification_preferences", {})
        current = time.time() if now is None else float(now)
        return frozenset(int(goal) for goal, until in validate_preferences(values)["muted_tasks"].items()
                         if until > current)
    except Exception:  # noqa: BLE001 -- unreadable preferences mute nothing
        log.debug("digest mute lookup failed", exc_info=True)
        return frozenset()


def prepare_digest(world, principal: str, *, can_decide: bool, prefs: dict[str, Any],
                   sees_everything: bool = False, suites: frozenset[str] | None = None,
                   now: float | None = None) -> dict[str, Any]:
    """The summary exactly as it is sent: the scheduler, "Send my summary
    now" and "Preview today's summary" all build it here."""
    return compose_digest(world, principal, can_decide=can_decide, sees_everything=sees_everything,
                          suites=suites, now=now, time_zone=str(prefs.get("time_zone") or "UTC"),
                          seen_goal_ids=_seen_in_app(principal), muted_goal_ids=_muted_in_app(principal, now))


def subject(digest: dict[str, Any]) -> str:
    return f"Your Lightwork summary for {digest['date_label']}"


# ----------------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------------

#: Why the person gets the summary at all (NOT-1); each item adds what it needs.
WHY = "You get this because you turned on the daily summary in My work."


def due_text(value: object, time_zone: str, *, label: str = "Decide by",
             none: str = "No expiry is set") -> str:
    from .personal_notifications import local_time_text

    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return none
    return f"{label} {local_time_text(value, time_zone)}"


def approval_line(row: dict[str, Any], time_zone: str) -> str:
    """What one request needs from this person, and by when."""
    need = ("Waiting on someone else's decision" if row.get("waiting_on") == "someone else"
            else "Approve or reject it")
    return f"#{row['id']} {row['action']} ({row['risk_label']}). {need}. {due_text(row.get('decide_by'), time_zone)}."


#: What a result asks of the person, by its status (NOT-1: every line says
#: what is needed and by when, as the in-app alerts do).
_RESULT_ACTION = {
    "done": "Review the result", "blocked": "Open the task to see what it needs",
    "failed": "Open the task to see why it stopped, then run it again",
    "cancelled": "Nothing is needed",
}


def result_line(row: dict[str, Any]) -> str:
    """One result: what happened, what it needs and that nothing is due."""
    action = _RESULT_ACTION.get(str(row.get("status") or ""), "Review the result")
    return f"{row['title']} ({row['status_label']}). {action}. Nothing is due."


def question_line(row: dict[str, Any]) -> str:
    return f"{row['question']} Answer it so the task can continue. The task waits until you answer."


def key_line(row: dict[str, Any]) -> str:
    days = int(row.get("days_left") or 0)
    return (f"{row.get('label') or row.get('prefix')} stops working in {days} day(s). "
            "Replace it before then so your scripts keep running.")


def question_href(row: dict[str, Any]) -> str:
    return f"/chat/goal/{row['goal_id']}#question-panel" if row.get("goal_id") else "/chat"


def _link(base: str, href: str) -> str:
    return base.rstrip("/") + href if base else ""


def _spend_line(spend: dict[str, Any]) -> str:
    limit = spend.get("limit_dollars") or 0
    line = f"Spending this month: ${float(spend.get('dollars') or 0):.2f}"
    if limit:
        line += f" of your ${float(limit):.2f} monthly limit"
        if spend.get("over_limit"):
            line += " (over the limit)"
    return line + "."


def _quiet_link(digest: dict[str, Any], dashboard_url: str, scope: str, key: str = "") -> str:
    """A one-action link that mutes a task, or stops this summary (NOT-2)."""
    principal = str(digest.get("principal") or "")
    if not dashboard_url or not principal.startswith("user:"):
        return ""
    try:
        from .notification_unsubscribe import link

        return link(dashboard_url, principal, scope, key)
    except Exception:  # noqa: BLE001 -- the summary still goes out without it
        log.debug("digest unsubscribe link unavailable", exc_info=True)
        return ""


def render_text(digest: dict[str, Any], *, dashboard_url: str = "") -> str:
    zone = str(digest.get("time_zone") or "UTC")

    def opened(href: str) -> str:
        link = _link(dashboard_url, href)
        return f" Open: {link}" if link else ""

    def muted(row: dict[str, Any]) -> str:
        link = _quiet_link(digest, dashboard_url, "task", str(row.get("id") or ""))
        return f" Mute alerts about this task: {link}" if link else ""

    lines = [f"Your Lightwork summary for {digest['date_label']}", WHY, ""]
    if digest["approvals"]:
        lines.append(f"{len(digest['approvals'])} waiting for your decision:")
        lines += [f"  - {approval_line(a, zone)}{opened('/approvals#approval-' + str(a['id']))}"
                  for a in digest["approvals"]]
        lines.append("")
    if digest["questions"]:
        lines.append(f"{len(digest['questions'])} question(s) an agent is waiting on:")
        lines += [f"  - {question_line(q)}{opened(question_href(q))}"
                  for q in digest["questions"]]
        lines.append("")
    if digest["results"]:
        lines.append(f"{len(digest['results'])} recent result(s):")
        lines += [f"  - {result_line(r)}{opened(r.get('href') or '/goals')}{muted(r)}"
                  for r in digest["results"]]
        lines.append("")
    if digest.get("expiring_keys"):
        lines.append(f"{len(digest['expiring_keys'])} access key(s) stop working within 7 days:")
        lines += [f"  - {key_line(k)}{opened(k.get('href') or '/api-keys')}"
                  for k in digest["expiring_keys"]]
        lines.append("")
    if digest["empty"]:
        lines += ["Nothing is waiting for you today.", ""]
    lines.append(_spend_line(digest["spending"]))
    if dashboard_url:
        lines += ["", f"Open My work: {dashboard_url.rstrip('/')}/me",
                  f"Change or stop this summary: {dashboard_url.rstrip('/')}/me#daily-summary"]
        stop = _quiet_link(digest, dashboard_url, "summary")
        if stop:
            lines.append(f"Stop this summary in one click: {stop}")
    return "\n".join(lines)


def render_html(digest: dict[str, Any], *, dashboard_url: str = "") -> str:
    def esc(value: object) -> str:
        return html.escape(str(value), quote=True)

    def section(title: str, items: list[str]) -> str:
        if not items:
            return ""
        rows = "".join(f"<li>{item}</li>" for item in items)
        return f"<h2 style=\"font-size:16px;margin:18px 0 6px\">{esc(title)}</h2><ul>{rows}</ul>"

    zone = str(digest.get("time_zone") or "UTC")

    def opened(href: str) -> str:
        link = _link(dashboard_url, href)
        return f" <a href=\"{esc(link)}\">Open</a>" if link else ""

    def muted(row: dict[str, Any]) -> str:
        link = _quiet_link(digest, dashboard_url, "task", str(row.get("id") or ""))
        return f" · <a href=\"{esc(link)}\">Mute alerts about this task</a>" if link else ""

    body = [f"<h1 style=\"font-size:20px\">Your Lightwork summary</h1><p>{esc(digest['date_label'])}</p>",
            f"<p>{esc(WHY)}</p>"]
    body.append(section(f"{len(digest['approvals'])} waiting for your decision", [
        esc(approval_line(a, zone)) + opened("/approvals#approval-" + str(a["id"]))
        for a in digest["approvals"]]))
    body.append(section("Questions an agent is waiting on", [
        esc(question_line(q)) + opened(question_href(q))
        for q in digest["questions"]]))
    body.append(section("Recent results", [
        esc(result_line(r)) + opened(r.get("href") or "/goals") + muted(r)
        for r in digest["results"]]))
    body.append(section("Access keys that stop working within 7 days", [
        esc(key_line(k)) + opened(k.get("href") or "/api-keys")
        for k in digest.get("expiring_keys", [])]))
    if digest["empty"]:
        body.append("<p>Nothing is waiting for you today.</p>")
    body.append(f"<p>{esc(_spend_line(digest['spending']))}</p>")
    if dashboard_url:
        link = esc(dashboard_url.rstrip("/") + "/me")
        stop = _quiet_link(digest, dashboard_url, "summary")
        body.append(f"<p><a href=\"{link}\">Open My work</a> · "
                    f"<a href=\"{link}#daily-summary\">Change or stop this summary</a>"
                    + (f" · <a href=\"{esc(stop)}\">Stop this summary in one click</a>" if stop else "")
                    + "</p>")
    return ("<!doctype html><html lang=\"en\"><body style=\"font-family:sans-serif;"
            "max-width:640px;margin:auto;color:#222\">" + "".join(body) + "</body></html>")


# ----------------------------------------------------------------------------
# Sending
# ----------------------------------------------------------------------------

def register_digest_sender(channel: str, sender: DigestSender | None) -> None:
    """Register (or with ``None`` remove) the sender for ``channel``.

    A sender is ``fn(principal, digest, links, prefs) -> bool`` where ``links``
    are that channel's linked accounts for the person. The Teams adapter
    registers ``"teams"`` here; ``"slack"`` and ``"email"`` are built in.
    """
    with _senders_lock:
        if sender is None:
            _senders.pop(channel, None)
        else:
            _senders[channel] = sender


def dashboard_url() -> str:
    try:
        from .env_setting import env_or_config

        return str(env_or_config("MAVERICK_PUBLIC_BASE_URL", "channels", "public_base_url", "") or "").strip()
    except Exception:  # noqa: BLE001 -- no link is better than a wrong one
        return ""


def _send_slack(principal: str, digest: dict[str, Any], links: list[dict[str, Any]],
                prefs: dict[str, Any]) -> bool:
    from .slack_interactive import digest_blocks, send_dm, slack_bot_token

    token = slack_bot_token()
    if not token or not links:
        return False
    base = dashboard_url()
    text = render_text(digest, dashboard_url=base)
    blocks = digest_blocks(digest, dashboard_url=base)
    return any(send_dm(token, link["external_id"], text, blocks) for link in links)


def _send_email(principal: str, digest: dict[str, Any], links: list[dict[str, Any]],
                prefs: dict[str, Any]) -> bool:
    from .notifications import send_email

    addresses = [link["external_id"] for link in links] or (
        [prefs["email"]] if prefs.get("email") else [])
    if not addresses:
        return False
    base = dashboard_url()
    stop = _quiet_link(digest, base, "summary")
    # Mail apps show their own Unsubscribe button for this header and press
    # it with one POST (RFC 8058); it stops this summary.
    extra: dict[str, Any] = {"html_body": render_html(digest, dashboard_url=base)}
    if stop:
        extra["headers"] = {"List-Unsubscribe": f"<{stop}>", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"}
    return any(send_email(address, subject(digest), render_text(digest, dashboard_url=base), **extra)
               for address in addresses)


def digest_senders() -> dict[str, DigestSender]:
    with _senders_lock:
        table = dict(_senders)
    table.setdefault("slack", _send_slack)
    table.setdefault("email", _send_email)
    return table


def send_digest(principal: str, digest: dict[str, Any], *, links: list[dict[str, Any]],
                prefs: dict[str, Any]) -> list[dict[str, Any]]:
    """Send through every channel the person has linked; audit each attempt."""
    from . import audit

    by_channel: dict[str, list[dict[str, Any]]] = {}
    for link in links:
        by_channel.setdefault(link["channel"], []).append(link)
    if prefs.get("email") and "email" not in by_channel:
        by_channel["email"] = []
    outcomes = []
    for channel, sender in digest_senders().items():
        if channel not in by_channel:
            continue
        delivery = _attempt(channel, sender, principal, digest, by_channel[channel], prefs)
        ok = delivery == "accepted"
        try:
            audit.audit_event(
                audit.EventKind.DIGEST_SENT, agent="system:daily-digest", recipient=principal,
                channel=channel, ok=ok, delivery=delivery, **digest["counts"],
            )
        except Exception:  # noqa: BLE001 -- the send already happened; see below
            # The record is written after the send, so a refusal (AuditRefused
            # included) cannot undo it. Raising here would leave the day open and
            # send the same summary again on every poll, and stop everyone after.
            log.warning("digest audit for %s failed after the send", channel, exc_info=True)
        outcomes.append({"channel": channel, "ok": ok, "delivery": delivery})
    return outcomes


def _attempt(channel: str, sender: DigestSender, principal: str, digest: dict[str, Any],
             links: list[dict[str, Any]], prefs: dict[str, Any]) -> str:
    """``accepted``; ``not_sent`` (definitely not: nothing set up, or refused);
    or ``unconfirmed`` (it may have gone out: the sender failed mid-send, or
    the service did not confirm it). An unconfirmed summary is never resent."""
    from .notifications import send_checked

    try:
        ok, unconfirmed = send_checked(lambda: bool(sender(principal, digest, links, prefs)))
    except Exception:  # noqa: BLE001 -- one channel failing never blocks the others
        log.warning("digest send through %s failed", channel, exc_info=True)
        return "unconfirmed"
    if ok:
        return "accepted"
    return "unconfirmed" if unconfirmed else "not_sent"


# ----------------------------------------------------------------------------
# Scheduling
# ----------------------------------------------------------------------------

def channel_setup(links: list[dict[str, Any]], prefs: dict[str, Any]) -> str:
    """A short fingerprint of what decides whether this person's summary can
    go out: their linked accounts and email, the registered channels and the
    shared notification setup (:func:`maverick.notifications.setup_fingerprint`).
    A change ends a back-off at once."""
    from .notifications import setup_fingerprint

    return setup_fingerprint(
        sorted([str(link.get("channel")), str(link.get("external_id"))] for link in links),
        str(prefs.get("email") or ""), sorted(digest_senders()))


def _waiting(retry: dict[str, Any], local_date: str, setup: str, current: float) -> bool:
    """Still inside today's back-off, with the channel setup unchanged."""
    if retry.get("date") != local_date or retry.get("setup") != setup:
        return False
    try:
        return current < float(retry.get("next_at") or 0)
    except (TypeError, ValueError):
        return False


def _back_off(principal: str, retry: dict[str, Any], local_date: str, setup: str, current: float) -> None:
    from . import user_preferences

    same = retry.get("date") == local_date and retry.get("setup") == setup
    try:
        before = int(retry.get("failures") or 0) if same else 0
    except (TypeError, ValueError):
        before = 0
    failures = before + 1
    user_preferences.set_digest_retry(principal, {
        "date": local_date, "failures": failures, "next_at": current + retry_delay(failures), "setup": setup,
    })


def due_now(prefs: dict[str, Any], *, now: float | None = None) -> tuple[bool, str]:
    """Whether the person's summary is due at ``now`` and their local date.

    Due when it is their chosen hour (or later, so a paused scheduler still
    sends once it wakes) and nothing has gone out yet for that local date.
    """
    current = time.time() if now is None else float(now)
    local = datetime.fromtimestamp(current, tz=_zone(str(prefs.get("time_zone") or "UTC")))
    local_date = local.strftime("%Y-%m-%d")
    if not prefs.get("digest_enabled", True):
        return False, local_date
    if local.hour < int(prefs.get("digest_hour", 8)):
        return False, local_date
    return prefs.get("last_digest_date") != local_date, local_date


def run_digest_cycle(world, *, principals: list[str], can_decide: Callable[[str], bool],
                     sees_everything: Callable[[str], bool] | None = None,
                     suites_for: Callable[[str], frozenset[str] | None] | None = None,
                     now: float | None = None) -> dict[str, Any]:
    """Send every due summary once. Returns counts for the scheduler's log."""
    from . import channel_identities, user_preferences

    current = time.time() if now is None else float(now)
    summary = {"checked": 0, "sent": 0, "skipped_empty": 0, "skipped_unlinked": 0, "failed": 0,
               "unconfirmed": 0, "backing_off": 0}
    for principal in principals:
        summary["checked"] += 1
        prefs = user_preferences.get_preferences(principal)
        due, local_date = due_now(prefs, now=current)
        if not due:
            continue
        links = channel_identities.links_for(principal)
        if not links and not prefs.get("email"):
            summary["skipped_unlinked"] += 1
            user_preferences.mark_digest_sent(principal, local_date)
            continue
        setup = channel_setup(links, prefs)
        retry = user_preferences.digest_retry(principal)
        if _waiting(retry, local_date, setup, current):
            summary["backing_off"] += 1
            continue
        digest = prepare_digest(
            world, principal, can_decide=can_decide(principal), prefs=prefs,
            sees_everything=bool(sees_everything and sees_everything(principal)),
            suites=suites_for(principal) if suites_for is not None else None, now=current,
        )
        if digest["empty"] and not prefs.get("send_when_empty"):
            summary["skipped_empty"] += 1
            user_preferences.mark_digest_sent(principal, local_date)
            continue
        deliveries = {o["delivery"] for o in send_digest(principal, digest, links=links, prefs=prefs)}
        if "accepted" in deliveries:
            summary["sent"] += 1
        elif "unconfirmed" in deliveries:
            summary["unconfirmed"] += 1  # it may have gone out: never resent
        else:
            summary["failed"] += 1  # definitely not sent: tried again after a wait
            _back_off(principal, retry, local_date, setup, current)
            continue
        user_preferences.mark_digest_sent(principal, local_date)
    return summary


__all__ = [
    "RECENT_DAYS",
    "RETRY_MINUTES",
    "channel_setup",
    "compose_digest",
    "dashboard_url",
    "digest_senders",
    "due_now",
    "month_start",
    "prepare_digest",
    "register_digest_sender",
    "render_html",
    "render_text",
    "retry_delay",
    "run_digest_cycle",
    "send_digest",
    "subject",
]
