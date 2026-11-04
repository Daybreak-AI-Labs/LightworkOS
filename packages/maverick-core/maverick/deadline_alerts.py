"""Alerts when a privacy or governance record is due.

Nothing used to tell anyone that a data-subject request, an incident's
72-hour notification clock, an assessment renewal, a vendor contract renewal
or an approval was about to run out. This module evaluates every such record
in the workspace and sends plain-language alerts through the notification
backends already configured in ``[notifications]`` (ntfy, Pushover, Slack,
Discord today; e-mail or Teams when those backends exist, since delivery goes
through :func:`maverick.notifications.notify`).

Each record gets at most one alert per *state* (``due_soon_7d``,
``due_soon_2d``, ``due_today``, ``overdue`` ...) per deadline. The ledger
(``deadline_alerts`` table in the world database) records what was sent, so a
restart never re-sends and the record page can show its alert history. A
deadline that moves (an extension) is a new deadline and starts over.

Only a delivery that at least one channel accepted is recorded as sent. A
definite "not sent" (no backend configured, every backend refused) records
nothing in the ledger, so the alert stays due -- but it is retried after a
growing wait (5, 10, 20, 40, 60 minutes, then hourly), kept in its own small
store (``deadline-alert-retries.json``) rather than the ledger or the
delivery receipts, and retried at once when the notification setup changes.
A workspace with no working channel therefore neither floods the delivery
history nor blocks other notifications, and still alerts once it is repaired.
An uncertain outcome (a backend may have sent before failing) is recorded as
*unconfirmed* -- shown in the alert history, never replayed automatically.

Configuration (``~/.maverick/config.toml``)::

    [deadline_alerts]
    enabled = true          # default: on when the privacy register is on
    mode = "immediate"      # or "digest": one message per recipient per cycle
    poll_seconds = 900
    quiet_hours = "22:00-07:00"   # server local time; incidents still go through
    owner = "the privacy owner"   # who is alerted when a record has no assignee

    [deadline_alerts.lead_days]
    dsar = [7, 2]
    assessment = [30, 7]
    vendor = [30, 7]

    [deadline_alerts.lead_hours]
    incident = [24, 4]
    approval = [24, 4]

Routing: a record with an assignee is alerted "for" that person; otherwise
the workspace's privacy/governance owner named above. Per-person channels do
not exist in the notification layer yet, so both go to the workspace's
configured backends with the recipient named in the message; when a
per-recipient backend lands, :func:`deliver` is the single seam to route by
``recipient``.
"""
from __future__ import annotations

import contextlib
import datetime
import hashlib
import json
import logging
import math
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

_DAY = 86_400.0
_HOUR = 3_600.0

SQLITE_SCHEMA: list[str] = [
    "CREATE TABLE IF NOT EXISTS deadline_alerts ("
    " id TEXT PRIMARY KEY, workspace TEXT NOT NULL DEFAULT '',"
    " record_type TEXT NOT NULL, record_id TEXT NOT NULL, state TEXT NOT NULL,"
    " due_at REAL NOT NULL, recipient TEXT NOT NULL DEFAULT '',"
    " recipient_kind TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '',"
    " message TEXT NOT NULL DEFAULT '', link TEXT NOT NULL DEFAULT '',"
    " sent_at REAL NOT NULL, backends INTEGER NOT NULL DEFAULT 0,"
    " mode TEXT NOT NULL DEFAULT 'immediate')",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_deadline_alerts_once"
    " ON deadline_alerts(workspace, record_type, record_id, state, due_at)",
    "CREATE INDEX IF NOT EXISTS idx_deadline_alerts_record"
    " ON deadline_alerts(record_type, record_id, sent_at DESC)",
]
POSTGRES_SCHEMA: list[str] = [s.replace(" REAL", " DOUBLE PRECISION") for s in SQLITE_SCHEMA]

# Record types and the plain words the alerts use for them.
RECORD_LABELS: dict[str, str] = {
    "dsar": "Data request",
    "dsar_acknowledgement": "Data request acknowledgement",
    "incident": "Privacy incident (72-hour notification clock)",
    "assessment_renewal": "Assessment renewal",
    "assessment_review": "Assessment review",
    "vendor_contract": "Vendor contract renewal",
    "approval": "Approval",
}
# Which lead-time table a record type reads: days or hours.
_LEAD_FAMILY: dict[str, tuple[str, str]] = {
    "dsar": ("lead_days", "dsar"),
    "dsar_acknowledgement": ("lead_days", "dsar"),
    "incident": ("lead_hours", "incident"),
    "assessment_renewal": ("lead_days", "assessment"),
    "assessment_review": ("lead_days", "assessment"),
    "vendor_contract": ("lead_days", "vendor"),
    "approval": ("lead_hours", "approval"),
}
# Webhook event per record type for a "due soon" or "overdue" state.
_WEBHOOK_EVENTS: dict[str, tuple[str, str]] = {
    "dsar": ("dsar.due_soon", "dsar.overdue"),
    "dsar_acknowledgement": ("dsar.due_soon", "dsar.overdue"),
    "incident": ("incident.due_soon", "incident.due_soon"),
    "assessment_renewal": ("assessment.renewal_due", "assessment.renewal_due"),
    "assessment_review": ("assessment.renewal_due", "assessment.renewal_due"),
    "vendor_contract": ("vendor.contract_renewal_due", "vendor.contract_renewal_due"),
    "approval": ("", "approval.expired"),
}
# What each alert asks its recipient to do (NOT-1: why, what and by when).
RECORD_ACTIONS: dict[str, str] = {
    "dsar": "Respond to the data request",
    "dsar_acknowledgement": "Acknowledge the data request",
    "incident": "Decide whether to notify the regulator and the people affected",
    "assessment_renewal": "Renew the assessment or retire it",
    "assessment_review": "Review the assessment",
    "vendor_contract": "Renew the contract or end it",
    "approval": "Approve or reject the request",
}
# Types whose alerts ignore quiet hours (a statutory clock keeps running).
_ALWAYS_URGENT = frozenset({"incident"})

DEFAULT_LEAD_DAYS: dict[str, list[int]] = {"dsar": [7, 2], "assessment": [30, 7], "vendor": [30, 7]}
DEFAULT_LEAD_HOURS: dict[str, list[int]] = {"incident": [24, 4], "approval": [24, 4]}
DEFAULT_OWNER = "the privacy owner"


# ------------------------------------------------------------------ settings
def _lead_list(raw: object, fallback: list[int], *, maximum: int) -> list[int]:
    if raw is None:
        return list(fallback)
    if isinstance(raw, str):
        raw = [x for x in raw.split(",")]
    if not isinstance(raw, (list, tuple)):
        return list(fallback)
    out: list[int] = []
    for item in raw:
        try:
            value = int(str(item).strip())
        except (TypeError, ValueError):
            continue
        if 1 <= value <= maximum and value not in out:
            out.append(value)
    return sorted(out, reverse=True) if out else list(fallback)


def _parse_quiet_hours(raw: object) -> tuple[int, int] | None:
    """``"22:00-07:00"`` -> ``(1320, 420)`` minutes; empty -> None."""
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        start, end = text.split("-", 1)
        sh, sm = (int(x) for x in start.strip().split(":"))
        eh, em = (int(x) for x in end.strip().split(":"))
    except ValueError:
        log.warning("deadline_alerts: quiet_hours %r is not HH:MM-HH:MM; ignored", text)
        return None
    if not (0 <= sh < 24 and 0 <= eh < 24 and 0 <= sm < 60 and 0 <= em < 60):
        return None
    return sh * 60 + sm, eh * 60 + em


def settings(config: dict | None = None) -> dict[str, Any]:
    """The ``[deadline_alerts]`` table with defaults filled in."""
    if config is None:
        try:
            from .config import load_config
            config = load_config() or {}
        except Exception:
            config = {}
    section = dict(config.get("deadline_alerts") or {})
    enabled = section.get("enabled")
    if enabled is None:
        try:
            from . import privacy_ops
            enabled = privacy_ops.enabled()
        except Exception:
            enabled = False
    mode = str(section.get("mode") or "immediate").strip().lower()
    if mode not in ("immediate", "digest"):
        mode = "immediate"
    try:
        poll = int(section.get("poll_seconds") or 900)
    except (TypeError, ValueError):
        poll = 900
    days = dict(section.get("lead_days") or {})
    hours = dict(section.get("lead_hours") or {})
    return {
        "enabled": bool(enabled),
        "mode": mode,
        "poll_seconds": max(60, min(poll, 86_400)),
        "quiet_hours": str(section.get("quiet_hours") or ""),
        "owner": str(section.get("owner") or DEFAULT_OWNER)[:200],
        "lead_days": {k: _lead_list(days.get(k), v, maximum=365) for k, v in DEFAULT_LEAD_DAYS.items()},
        "lead_hours": {k: _lead_list(hours.get(k), v, maximum=720) for k, v in DEFAULT_LEAD_HOURS.items()},
    }


# ---------------------------------------------------------------- deadlines
@dataclass(frozen=True)
class Deadline:
    record_type: str
    record_id: str
    title: str
    due_at: float
    link: str = ""
    assignee: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Alert:
    deadline: Deadline
    state: str          # due_soon_7d / due_soon_4h / due_today / overdue
    recipient: str
    recipient_kind: str  # assignee / owner
    urgent: bool


def _link(path: str) -> str:
    from .webhook_events import record_link
    return record_link(path)


def _epoch(value: object) -> float | None:
    """A usable deadline time, or ``None``. A record with a missing or
    malformed time is skipped, so one bad row never hides every other alert
    from its source."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number > 0 else None


def _dsar_deadlines(now: float) -> list[Deadline]:
    from . import privacy_ops
    if not privacy_ops.enabled():
        return []
    out: list[Deadline] = []
    for r in privacy_ops.list_dsars():
        if r.get("status") not in ("open", "awaiting_erasure", "verified"):
            continue
        rid = str(r.get("id") or "")
        title = f"{r.get('kind') or 'access'!s} request from {r.get('subject_id') or 'a person'}"
        link = _link(f"/privacy/dsar/{rid}")
        assignee = str(r.get("assignee") or r.get("assigned_to") or "")
        # Per-jurisdiction fields when present (extended_until wins over due_at);
        # the single due_at is what every record carries today.
        due = _epoch(r.get("extended_until")) or _epoch(r.get("due_at"))
        if due:
            out.append(Deadline("dsar", rid, title, due, link, assignee,
                                {"kind": r.get("kind"), "jurisdiction": r.get("jurisdiction")}))
        ack = _epoch(r.get("acknowledge_by"))
        if ack and not r.get("acknowledged_at"):
            out.append(Deadline("dsar_acknowledgement", rid, title, ack, link, assignee))
    return out


def _incident_deadlines(now: float) -> list[Deadline]:
    from . import privacy_ops
    if not privacy_ops.enabled():
        return []
    out: list[Deadline] = []
    for r in privacy_ops.list_incidents():
        if r.get("status") != "open" or r.get("notification") is not None:
            continue
        rid = str(r.get("id") or "")
        due = _epoch(r.get("notify_deadline_at"))
        if due is None:
            continue
        out.append(Deadline("incident", rid, str(r.get("title") or "privacy incident"),
                            due, _link("/privacy#incidents"),
                            str(r.get("assignee") or ""), {"severity": r.get("severity")}))
    return out


def _assessment_deadlines(now: float) -> list[Deadline]:
    from . import assessment
    out: list[Deadline] = []
    for s in assessment.list_saved():
        if s.get("status") in ("rejected",):
            continue
        rid = str(s.get("id") or "")
        title = f"{s.get('subject') or 'assessment'} ({s.get('type') or 'assessment'})"
        link = _link(f"/assessments#{rid}")
        assignee = str(s.get("assignee") or "")
        renewal = _epoch(s.get("renewal_at"))
        if renewal:
            out.append(Deadline("assessment_renewal", rid, title, renewal, link, assignee))
        review = _epoch(s.get("next_review_at"))
        if s.get("status") == "approved" and review:
            out.append(Deadline("assessment_review", rid, title, review, link, assignee))
    return out


def _vendor_deadlines(now: float) -> list[Deadline]:
    from . import vendor_management as vm
    if not vm.enabled():
        return []
    out: list[Deadline] = []
    for v in vm.list_vendors():
        if v.get("status") == "offboarded":
            continue
        vid = str(v.get("id") or "")
        for c in v.get("contracts") or []:
            renews = _epoch(c.get("renews_at")) if isinstance(c, dict) else None
            if renews is None:
                continue
            kind = str(c.get("kind") or "contract")
            out.append(Deadline("vendor_contract", f"{vid}:{kind}",
                                f"{kind.upper()} with {v.get('name') or vid}", renews,
                                _link(f"/privacy/vendors/{vid}"), str(v.get("owner") or ""),
                                {"vendor_id": vid, "kind": kind}))
    return out


def _approval_deadlines(now: float, world: Any) -> list[Deadline]:
    if world is None:
        return []
    from .approval_cards import ApprovalCardError, decode_approval_detail
    out: list[Deadline] = []
    for appr in world.pending_approvals():
        try:
            card = decode_approval_detail(getattr(appr, "detail", None))
        except ApprovalCardError:
            continue
        if not card or not card.get("expires_at"):
            continue
        out.append(Deadline("approval", str(appr.id), str(getattr(appr, "action", "") or "approval"),
                            float(card["expires_at"]), _link(f"/approvals#approval-{appr.id}"), "",
                            {"risk": getattr(appr, "risk", "")}))
    return out


_COLLECTORS: tuple[tuple[str, Callable[..., list[Deadline]]], ...] = (
    ("dsar", _dsar_deadlines),
    ("incident", _incident_deadlines),
    ("assessment", _assessment_deadlines),
    ("vendor", _vendor_deadlines),
)


def collect(*, now: float | None = None, world: Any = None) -> list[Deadline]:
    """Every open deadline in the workspace. A source that is off or broken
    contributes nothing (and is logged), never an exception."""
    current = time.time() if now is None else float(now)
    found: list[Deadline] = []
    for name, collector in _COLLECTORS:
        try:
            found.extend(collector(current))
        except Exception as exc:
            log.warning("deadline_alerts: %s deadlines unavailable: %s", name, type(exc).__name__)
    try:
        found.extend(_approval_deadlines(current, world))
    except Exception as exc:
        log.warning("deadline_alerts: approval deadlines unavailable: %s", type(exc).__name__)
    return found


# ---------------------------------------------------------------- evaluate
def _same_local_day(a: float, b: float, localtime: Callable[[float], time.struct_time]) -> bool:
    x, y = localtime(a), localtime(b)
    return (x.tm_year, x.tm_yday) == (y.tm_year, y.tm_yday)


def current_state(
    deadline: Deadline, now: float, cfg: dict[str, Any],
    *, localtime: Callable[[float], time.struct_time] = time.localtime,
) -> str | None:
    """The most urgent state the deadline is in right now, or ``None``."""
    remaining = deadline.due_at - now
    if remaining < 0:
        return "overdue"
    family, key = _LEAD_FAMILY.get(deadline.record_type, ("lead_days", "dsar"))
    if family == "lead_days":
        if _same_local_day(deadline.due_at, now, localtime):
            return "due_today"
        # Most urgent lead first: a deadline 1 day out is "2 days", not "7 days".
        for lead in sorted(cfg["lead_days"].get(key) or []):
            if remaining <= lead * _DAY:
                return f"due_soon_{lead}d"
        return None
    for lead in sorted(cfg["lead_hours"].get(key) or []):
        if remaining <= lead * _HOUR:
            return f"due_soon_{lead}h"
    return None


def in_quiet_hours(now: float, cfg: dict[str, Any],
                   *, localtime: Callable[[float], time.struct_time] = time.localtime) -> bool:
    window = _parse_quiet_hours(cfg.get("quiet_hours"))
    if window is None:
        return False
    start, end = window
    local = localtime(now)
    minute = local.tm_hour * 60 + local.tm_min
    if start <= end:
        return start <= minute < end
    return minute >= start or minute < end


def recipient_for(deadline: Deadline, cfg: dict[str, Any]) -> tuple[str, str]:
    if deadline.assignee.strip():
        return deadline.assignee.strip()[:200], "assignee"
    return cfg["owner"], "owner"


def evaluate(
    deadlines: list[Deadline], now: float, cfg: dict[str, Any],
    *, localtime: Callable[[float], time.struct_time] = time.localtime,
) -> list[Alert]:
    alerts: list[Alert] = []
    for d in deadlines:
        state = current_state(d, now, cfg, localtime=localtime)
        if state is None:
            continue
        who, kind = recipient_for(d, cfg)
        urgent = state == "overdue" or d.record_type in _ALWAYS_URGENT
        alerts.append(Alert(d, state, who, kind, urgent))
    return alerts


# ------------------------------------------------------------------ ledger
def _is_sqlite(world: Any) -> bool:
    return hasattr(world, "_writing")


def _rows(world: Any, sql: str, params: tuple = ()) -> list[dict]:
    # PostgresWorldModel has no _read_all; this reads through a cursor there.
    from .webhook_subscriptions import _rows as read_rows

    return read_rows(world, sql, params)


def _write(world: Any, sql: str, params: tuple = ()) -> None:
    if _is_sqlite(world):
        with world._writing() as conn:
            conn.execute(sql, params)
        return
    with world._tx() as cur:
        cur.execute(sql.replace("?", "%s"), params)


def _write_all(world: Any, statements: list[tuple[str, tuple]]) -> None:
    if _is_sqlite(world):
        with world._writing() as conn:
            for sql, params in statements:
                conn.execute(sql, params)
        return
    with world._tx() as cur:
        for sql, params in statements:
            cur.execute(sql.replace("?", "%s"), params)


def _workspace() -> str:
    from .webhook_subscriptions import workspace_id
    return workspace_id()


_UNCONFIRMED = "-unconfirmed"


def _settled(row: dict) -> bool:
    """Accepted by a channel, or an uncertain send that must not be replayed.

    A legacy row with no accepting backend in a plain mode was written by the
    old cycle even when nothing was delivered; it does not suppress a retry.
    """
    return int(row.get("backends") or 0) > 0 or str(row.get("mode") or "").endswith(_UNCONFIRMED)


def _ledger_key(alert: Alert) -> tuple:
    d = alert.deadline
    return (_workspace(), d.record_type, d.record_id, alert.state, float(d.due_at))


_KEY_SQL = " WHERE workspace = ? AND record_type = ? AND record_id = ? AND state = ? AND due_at = ?"


def already_sent(world: Any, alert: Alert) -> bool:
    rows = _rows(world, "SELECT backends, mode FROM deadline_alerts" + _KEY_SQL, _ledger_key(alert))
    return any(_settled(row) for row in rows)


def _record_sent(world: Any, alert: Alert, message: str, *, sent_at: float,
                 backends: int, mode: str, unconfirmed: bool = False) -> dict:
    d = alert.deadline
    alert_id = "dla_" + uuid.uuid4().hex[:16]
    stored_mode = mode + (_UNCONFIRMED if unconfirmed else "")
    # A legacy row for the same key (nothing accepted) is replaced in the same
    # transaction; the unique index keeps one row per alert state.
    _write_all(world, [
        ("DELETE FROM deadline_alerts" + _KEY_SQL + " AND backends = 0 AND mode IN ('immediate', 'digest')",
         _ledger_key(alert)),
        ("INSERT INTO deadline_alerts(id, workspace, record_type, record_id, state, due_at,"
         " recipient, recipient_kind, title, message, link, sent_at, backends, mode)"
         " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
         (alert_id, _workspace(), d.record_type, d.record_id, alert.state, float(d.due_at),
          alert.recipient, alert.recipient_kind, d.title[:300], message[:2000], d.link[:1000],
          sent_at, int(backends), stored_mode)),
    ])
    return {"id": alert_id, "record_type": d.record_type, "record_id": d.record_id,
            "state": alert.state, "due_at": d.due_at, "recipient": alert.recipient,
            "recipient_kind": alert.recipient_kind, "sent_at": sent_at, "backends": backends,
            "delivery": "unconfirmed" if unconfirmed else "accepted"}


_RETRY_KEEP_SECONDS = 30 * 86400
_RETRY_MAX_ENTRIES = 5000


class _RetryBook:
    """Per-alert back-off after a definite failure, outside the ledger and the
    delivery receipts. Keyed by a hash of the alert (no record ids are stored);
    an entry is dropped once the alert is recorded, and stale or surplus
    entries are pruned on every save, so the file stays small."""

    def __init__(self, setup: str):
        self.setup = setup
        self.path = None
        self.entries: dict[str, dict[str, Any]] = {}
        self.dirty = False
        try:
            from .paths import data_dir

            self.path = data_dir("deadline-alert-retries.json")
            self.entries = self._read()
        except Exception as exc:  # noqa: BLE001 -- no back-off beats a failed cycle
            log.warning("deadline_alerts: retry back-off unavailable: %s", type(exc).__name__)

    def _read(self) -> dict[str, dict[str, Any]]:
        from .file_lock import atomic_read_text

        try:
            data = json.loads(atomic_read_text(self.path))
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, dict)}

    @staticmethod
    def key(alert: Alert) -> str:
        return hashlib.sha256("\0".join(map(str, _ledger_key(alert))).encode("utf-8")).hexdigest()[:24]

    def waiting(self, alert: Alert, now: float) -> bool:
        """Still inside the wait after its last definite failure, with the
        notification setup unchanged since."""
        entry = self.entries.get(self.key(alert))
        if not entry or entry.get("setup") != self.setup:
            return False
        try:
            # A failure stamped later than now was recorded by a wrong clock;
            # its wait must not hold the alert back once the clock is right.
            return float(entry.get("at") or 0) <= now < float(entry.get("next_at") or 0)
        except (TypeError, ValueError):
            return False

    def failed(self, alert: Alert, now: float) -> None:
        from .notifications import retry_delay

        key = self.key(alert)
        entry = self.entries.get(key)
        try:
            before = int(entry.get("failures") or 0) if entry and entry.get("setup") == self.setup else 0
        except (TypeError, ValueError):
            before = 0
        self.entries[key] = {"failures": before + 1, "next_at": now + retry_delay(before + 1),
                             "setup": self.setup, "at": now}
        self.dirty = True

    def clear(self, alert: Alert) -> None:
        if self.entries.pop(self.key(alert), None) is not None:
            self.dirty = True

    def sent_unrecorded(self, alert: Alert, *, sent_at: float, backends: int, mode: str,
                        unconfirmed: bool) -> None:
        """The alert went out (or may have) but its ledger row could not be
        written: remember that, so a later cycle records it instead of sending
        it again."""
        self.entries[self.key(alert)] = {
            "unrecorded": {"sent_at": float(sent_at), "backends": int(backends),
                           "mode": str(mode), "unconfirmed": bool(unconfirmed)},
            "setup": self.setup, "at": float(sent_at)}
        self.dirty = True

    def unrecorded(self, alert: Alert) -> dict[str, Any] | None:
        value = (self.entries.get(self.key(alert)) or {}).get("unrecorded")
        if (not isinstance(value, dict) or not isinstance(value.get("sent_at"), (int, float))
                or not isinstance(value.get("backends"), int) or value.get("mode") not in {"immediate", "digest"}):
            return None
        return value

    def save(self, now: float) -> None:
        if not self.dirty or self.path is None:
            return
        from .file_lock import atomic_write_text, ensure_private_directory

        keep = {k: v for k, v in self.entries.items()
                if isinstance(v.get("at"), (int, float)) and v["at"] >= now - _RETRY_KEEP_SECONDS}
        newest = sorted(keep, key=lambda k: keep[k]["at"], reverse=True)[:_RETRY_MAX_ENTRIES]
        try:
            ensure_private_directory(self.path.parent)
            atomic_write_text(self.path, json.dumps({k: keep[k] for k in newest}, separators=(",", ":")))
        except OSError as exc:
            log.warning("deadline_alerts: retry back-off could not be saved: %s", type(exc).__name__)
        self.dirty = False


@contextlib.contextmanager
def _using_world(world: Any):
    """``world`` itself, or one opened here and closed here (a connection to a
    shared database is otherwise left open per call)."""
    if world is not None:
        yield world
        return
    from .world_model import close_world_if_owned, open_world

    opened = open_world()
    try:
        yield opened
    finally:
        close_world_if_owned(opened)


def alerts_for(record_type: str, record_id: str, *, world: Any = None, limit: int = 50) -> list[dict]:
    """What was sent about one record, newest first (the record page's
    "Alerts" section)."""
    with _using_world(world) as active:
        return _rows(active, "SELECT * FROM deadline_alerts WHERE workspace = ? AND record_type = ?"
                             " AND record_id = ? ORDER BY sent_at DESC LIMIT ?",
                     (_workspace(), str(record_type)[:64], str(record_id)[:128], max(1, min(int(limit), 500))))


def recent_alerts(*, world: Any = None, limit: int = 100) -> list[dict]:
    with _using_world(world) as active:
        return _rows(active, "SELECT * FROM deadline_alerts WHERE workspace = ? ORDER BY sent_at DESC LIMIT ?",
                     (_workspace(), max(1, min(int(limit), 500))))


# ---------------------------------------------------------------- messages
def _local_date(moment: float, localtime: Callable[[float], time.struct_time]) -> datetime.date:
    local = localtime(moment)
    return datetime.date(local.tm_year, local.tm_mon, local.tm_mday)


def _when(due_at: float, now: float, localtime: Callable[[float], time.struct_time]) -> str:
    remaining = due_at - now
    stamp = time.strftime("%d %b %Y %H:%M", localtime(due_at))
    if remaining < 0:
        gone = -remaining
        if gone >= _DAY:
            return f"was due {int(gone // _DAY)} day(s) ago ({stamp})"
        return f"was due {max(1, int(gone // _HOUR))} hour(s) ago ({stamp})"
    if remaining >= 2 * _DAY:
        return f"is due in {int(remaining // _DAY)} days ({stamp})"
    if remaining >= _DAY:
        # Between 24 and 48 hours can be tomorrow or the day after.
        ahead = (_local_date(due_at, localtime) - _local_date(now, localtime)).days
        return f"is due tomorrow ({stamp})" if ahead <= 1 else f"is due in {ahead} days ({stamp})"
    return f"is due in {max(1, int(remaining // _HOUR))} hour(s) ({stamp})"


def message_for(alert: Alert, now: float,
                *, localtime: Callable[[float], time.struct_time] = time.localtime) -> tuple[str, str]:
    """``(title, body)`` in plain language, with a link to the record."""
    d = alert.deadline
    label = RECORD_LABELS.get(d.record_type, d.record_type)
    when = _when(d.due_at, now, localtime)
    if alert.state == "overdue":
        title = f"Overdue: {label.lower()} {d.title}"
    elif alert.state == "due_today":
        title = f"Due today: {label.lower()} {d.title}"
    else:
        title = f"Due soon: {label.lower()} {d.title}"
    action = RECORD_ACTIONS.get(d.record_type, "Open the record and act on it")
    why = ("this record is assigned to them" if alert.recipient_kind == "assignee"
           else "no one is assigned to this record")
    body = f"{label}: {d.title} {when}. Needed: {action}. For: {alert.recipient}, because {why}."
    if d.link:
        body += f" Open: {d.link}"
    return title[:200], body


@dataclass(frozen=True)
class Delivery:
    """How one send ended: backends that accepted it, and whether any backend
    may have sent it without confirming (an outcome never replayed)."""

    accepted: int = 0
    uncertain: bool = False

    @property
    def status(self) -> str:
        return "accepted" if self.accepted else ("unconfirmed" if self.uncertain else "not_sent")


def deliver(
    title: str, body: str, *, urgent: bool, recipient: str,
    notify: Callable[..., int] | None = None,
) -> Delivery:
    """Send one alert through the notification backends. ``recipient`` is the
    seam for per-person routing once a backend supports it; today every
    backend configured for the workspace receives it."""
    del recipient  # routed by name inside the message until backends carry recipients
    states: list[str] = []
    kwargs: dict[str, Any] = {"title": title, "priority": "high" if urgent else "default",
                              "category": "deadline", "async_dispatch": False, "batch": False}
    send = notify
    if send is None:
        from .notifications import configured_backends
        from .notifications import notify as send

        if not configured_backends():
            # Nothing is set up to receive it: no attempt, and so no failed
            # delivery receipt for every retry.
            return Delivery()
        kwargs["outcomes"] = states  # per-backend final states
    try:
        fired = int(send(body, **kwargs) or 0)
    except Exception as exc:
        log.warning("deadline_alerts: notification failed: %s", type(exc).__name__)
        # The built-in sender catches every backend failure itself, so an
        # exception before any backend started means nothing went out. A
        # failure after a backend started, or from another sender, may have
        # delivered: never replay it blindly.
        return Delivery(states.count("delivered"), uncertain=notify is not None or bool(states))
    return Delivery(max(fired, states.count("delivered")), uncertain="unknown" in states)


def _emit_webhook(alert: Alert, world: Any) -> int:
    """Webhook deliveries started for this alert (0 when nothing is subscribed)."""
    due_soon_event, overdue_event = _WEBHOOK_EVENTS.get(alert.deadline.record_type, ("", ""))
    event = overdue_event if alert.state == "overdue" else due_soon_event
    if not event:
        return 0
    from .webhook_events import emit
    d = alert.deadline
    return emit(event, record_type=d.record_type, record_id=d.record_id, title=d.title,
                summary={"due_at": d.due_at, "state": alert.state, "assignee": d.assignee, **d.detail},
                link=d.link, payload={"state": alert.state, "due_at": d.due_at,
                                      "recipient": alert.recipient, "recipient_kind": alert.recipient_kind},
                world=world)


# --------------------------------------------------------------- run cycle
@contextlib.contextmanager
def _one_cycle_at_a_time():
    """The scheduler and a manual "run now" must not overlap: both would see an
    alert as unsent and both send it, and the second ledger row would then fail
    on the unique index. A lock that cannot be set up is logged and skipped so
    alerts still go out."""
    with contextlib.ExitStack() as stack:
        try:
            from .file_lock import cross_process_lock
            from .paths import data_dir

            # The lock is taken here, on entry, not when the guard is built.
            stack.enter_context(cross_process_lock(data_dir("deadline-alert-cycle")))
        except Exception as exc:  # noqa: BLE001 -- unsafe to overlap, worse to stop alerting
            log.warning("deadline_alerts: cycles are not serialised: %s", type(exc).__name__)
        yield


def run_cycle(
    *,
    now: float | None = None,
    world: Any = None,
    config: dict | None = None,
    notify: Callable[..., int] | None = None,
    localtime: Callable[[float], time.struct_time] = time.localtime,
) -> dict[str, Any]:
    """Evaluate every deadline and send what is new. Returns a summary.

    One cycle runs at a time; an overlapping call waits for the running one."""
    with _one_cycle_at_a_time(), _using_world(world) as active:
        return _run_cycle(now=now, world=active, config=config, notify=notify, localtime=localtime)


def _run_cycle(
    *,
    now: float | None,
    world: Any,
    config: dict | None,
    notify: Callable[..., int] | None,
    localtime: Callable[[float], time.struct_time],
) -> dict[str, Any]:
    cfg = settings(config)
    current = time.time() if now is None else float(now)
    summary: dict[str, Any] = {"evaluated": 0, "sent": 0, "held_quiet": 0, "already_sent": 0,
                               "not_sent": 0, "unconfirmed": 0, "backing_off": 0, "alerts": [],
                               "enabled": cfg["enabled"]}
    if not cfg["enabled"]:
        return summary
    quiet = in_quiet_hours(current, cfg, localtime=localtime)
    pending: list[Alert] = []
    for alert in evaluate(collect(now=current, world=world), current, cfg, localtime=localtime):
        summary["evaluated"] += 1
        if already_sent(world, alert):
            summary["already_sent"] += 1
            continue
        if quiet and not alert.urgent:
            summary["held_quiet"] += 1
            continue
        pending.append(alert)
    from .notifications import setup_fingerprint

    retries = _RetryBook(setup_fingerprint())
    try:
        due = []
        for alert in pending:
            held = retries.unrecorded(alert)
            if held is not None:
                _record_unrecorded(world, alert, held, current, localtime, summary, retries)
            elif retries.waiting(alert, current):
                summary["backing_off"] += 1
            else:
                due.append(alert)
        if cfg["mode"] == "digest":
            _send_digest(due, current, cfg, world, notify, localtime, summary, retries)
        else:
            for alert in due:
                title, body = message_for(alert, current, localtime=localtime)
                outcome = deliver(title, body, urgent=alert.urgent, recipient=alert.recipient, notify=notify)
                _settle_safely(world, alert, body, outcome, current, "immediate", summary, retries)
    finally:
        retries.save(current)
    return summary


def _settle(world, alert: Alert, message: str, outcome: Delivery | int, current: float, mode: str,
            summary: dict[str, Any], retries: _RetryBook) -> None:
    """Record an accepted or uncertain send; leave a definite failure to retry
    after a wait.

    Subscribed webhooks are a channel too: a started webhook delivery accepts
    the alert, so a webhook-only workspace is alerted once, not every cycle.
    """
    if not isinstance(outcome, Delivery):  # a plain count of accepting backends
        outcome = Delivery(max(int(outcome or 0), 0))
    try:
        hooks = int(_emit_webhook(alert, world) or 0)
    except Exception as exc:  # noqa: BLE001 -- a webhook is a second channel, never the reason an alert is lost
        log.warning("deadline_alerts: webhook delivery failed: %s", type(exc).__name__)
        hooks = 0
    outcome = Delivery(outcome.accepted + max(hooks, 0), outcome.uncertain)
    if outcome.status == "not_sent":
        summary["not_sent"] += 1
        retries.failed(alert, current)
        log.warning("deadline_alerts: %s %s alert was not sent; it will be retried",
                    alert.deadline.record_type, alert.state)
        return
    retries.clear(alert)
    unconfirmed = outcome.status == "unconfirmed"
    try:
        row = _record_sent(world, alert, message, sent_at=current, backends=outcome.accepted,
                           mode=mode, unconfirmed=unconfirmed)
    except Exception:
        retries.sent_unrecorded(alert, sent_at=current, backends=outcome.accepted, mode=mode,
                                unconfirmed=unconfirmed)
        raise
    summary["alerts"].append(row)
    summary["sent" if outcome.status == "accepted" else "unconfirmed"] += 1


def _settle_safely(world, alert: Alert, message: str, outcome: Delivery | int, current: float, mode: str,
                   summary: dict[str, Any], retries: _RetryBook) -> None:
    """Record one sent alert without letting a failure to do so stop the cycle.

    The alert may already have gone out, so it is counted as unconfirmed and a
    later cycle writes its ledger row without sending it again (an uncertain
    send is never replayed); the rest of the cycle carries on."""
    try:
        _settle(world, alert, message, outcome, current, mode, summary, retries)
    except Exception as exc:  # noqa: BLE001 -- e.g. the ledger database is locked
        log.warning("deadline_alerts: could not record the %s %s alert: %s",
                    alert.deadline.record_type, alert.state, type(exc).__name__)
        if retries.unrecorded(alert) is None:
            retries.failed(alert, current)
        summary["unconfirmed"] += 1


def _record_unrecorded(world, alert: Alert, held: dict[str, Any], current: float,
                       localtime: Callable[[float], time.struct_time], summary: dict[str, Any],
                       retries: _RetryBook) -> None:
    """Write the ledger row of an alert sent in an earlier cycle; never resend it."""
    try:
        row = _record_sent(world, alert, message_for(alert, current, localtime=localtime)[1],
                           sent_at=float(held["sent_at"]), backends=int(held["backends"]),
                           mode=str(held["mode"]), unconfirmed=bool(held.get("unconfirmed")))
    except Exception as exc:  # noqa: BLE001 -- still unrecorded; try again next cycle
        log.warning("deadline_alerts: could not record the earlier %s %s alert: %s",
                    alert.deadline.record_type, alert.state, type(exc).__name__)
        summary["unconfirmed"] += 1
        return
    retries.clear(alert)
    summary["alerts"].append(row)
    summary["already_sent"] += 1


# Backends refuse an over-long message (Pushover 1024 characters, Discord 2000),
# and a refusal is a definite failure that is retried: a digest that grew past
# the smallest limit would then never be delivered. A digest is therefore sent
# in parts that each fit.
_DIGEST_LIMIT = 900


def _digest_parts(recipient: str, lines: list[tuple[Alert, str]]) -> list[list[tuple[Alert, str]]]:
    parts: list[list[tuple[Alert, str]]] = [[]]
    size = len(f"{len(lines)} deadline(s) need attention. For: {recipient}.\n")
    for alert, line in lines:
        cost = len(line) + 3
        if parts[-1] and size + cost > _DIGEST_LIMIT:
            parts.append([])
            size = len(f"{len(lines)} deadline(s) need attention. For: {recipient}.\n")
        parts[-1].append((alert, line))
        size += cost
    return parts


def _send_digest(pending, current, cfg, world, notify, localtime, summary, retries) -> None:
    by_recipient: dict[str, list[Alert]] = {}
    for alert in pending:
        by_recipient.setdefault(alert.recipient, []).append(alert)
    for recipient, alerts in by_recipient.items():
        lines = [(a, message_for(a, current, localtime=localtime)[1]) for a in alerts]
        parts = _digest_parts(recipient, lines)
        for number, part in enumerate(parts, 1):
            body = (f"{len(part)} deadline(s) need attention. For: {recipient}.\n"
                    + "\n".join(f"- {line}" for _, line in part))
            title = f"Deadlines for {recipient}" + (f" ({number}/{len(parts)})" if len(parts) > 1 else "")
            urgent = any(a.urgent for a, _ in part)
            outcome = deliver(title, body, urgent=urgent, recipient=recipient, notify=notify)
            for alert, line in part:
                _settle_safely(world, alert, line, outcome, current, "digest", summary, retries)


__all__ = [
    "Alert", "Deadline", "Delivery", "RECORD_LABELS", "alerts_for", "collect", "current_state",
    "deliver", "evaluate", "in_quiet_hours", "message_for", "recent_alerts",
    "recipient_for", "run_cycle", "settings",
]
