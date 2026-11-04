"""In-app alerts as spending nears a workspace or per-person spending limit.

When recorded spend reaches 50%, 75% and 100% of a limit (the percentages are
``[spending_limits] alert_at``), the crossing is remembered once per limit
period. Administrators see every crossing in their workspace in their personal
alerts; each person also sees the crossings of their own limit.

Alerts only tell people. They never raise, lower or lift a limit: admission in
:mod:`maverick.spending_limits` keeps stopping paid work at 100% whatever this
module records, and an empty ``alert_at`` turns the alerts off, not the limits.
Spend totals come from :func:`maverick.spending_limits.standing`, the same
totals admission uses.
"""
from __future__ import annotations

import json
import logging
import math
import time

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from .paths import data_dir

log = logging.getLogger("maverick.spending_alerts")

#: Default alert points, in percent of a limit.
DEFAULT_ALERT_AT = (50, 75, 100)
_FORMAT = "lightwork-spending-alerts-v1"
_MAX_RECORDS = 20_000
#: Crossings are kept a little longer than the longest limit period (a month).
_KEEP_SECONDS = 40 * 86400
_EPSILON = 1e-9


def validate_alert_at(value) -> list[int]:
    """Whole percentages from 1 to 100, at most ten; an empty list means no alerts."""
    message = "Use up to ten whole percentages from 1 to 100, such as 50, 75, 100."
    if not isinstance(value, (list, tuple)) or len(value) > 10:
        raise ValueError(message)
    result = set()
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, float, str)):
            raise ValueError(message)
        try:
            number = float(str(item).strip().rstrip("%"))
        except (ValueError, OverflowError) as exc:
            raise ValueError(message) from exc
        if not math.isfinite(number) or number != int(number) or not 1 <= number <= 100:
            raise ValueError(message)
        result.add(int(number))
    return sorted(result)


def alert_at() -> list[int]:
    """The configured alert percentages. A value that cannot be read keeps the
    defaults, so a typo never silently turns alerts off."""
    from .config import load_config

    section = load_config().get("spending_limits") or {}
    if not isinstance(section, dict) or "alert_at" not in section:
        return list(DEFAULT_ALERT_AT)
    try:
        return validate_alert_at(section["alert_at"])
    except ValueError:
        log.warning("[spending_limits] alert_at is invalid; using 50, 75 and 100 percent")
        return list(DEFAULT_ALERT_AT)


def _path():
    return data_dir("spending-limit-alerts.json")


def _read() -> dict:
    path = _path()
    if not path.exists():
        return {}
    try:
        data = json.loads(atomic_read_text(path))
    except (OSError, ValueError):
        log.warning("spending alerts: the saved alerts could not be read; starting again")
        return {}
    if not isinstance(data, dict) or data.get("format") != _FORMAT or not isinstance(data.get("alerts"), dict):
        return {}
    return {k: v for k, v in data["alerts"].items() if isinstance(v, dict)}


def _crossings(principal: str, percentages: list[int], now: float) -> list[dict]:
    from .spending_limits import _window, standing

    rows = []
    for row in standing(principal)["limits"]:
        if "spent" not in row:  # a per-task limit has no running total to alert on
            continue
        limit = row["limit"]
        amount = float(limit["amount"])
        used = 100.0 * float(row["spent"]) / amount if amount > 0 else 0.0
        workspace = row["kind"] == "workspace"
        whose = "" if workspace else principal
        window = _window(limit["period"])
        for percent in percentages:
            if used + _EPSILON < percent:
                continue
            key = "|".join(("workspace" if workspace else "person", whose, limit["period"],
                            window, f"{amount:.2f}", str(percent)))
            rows.append({"key": key, "scope": "workspace" if workspace else "person",
                         "principal": whose, "period": limit["period"], "window": window,
                         "amount": amount, "percent": percent, "spent": round(float(row["spent"]), 4),
                         "observed_at": now})
    return rows


def observe(principal: str, *, now: float | None = None) -> list[dict]:
    """Record each limit percentage ``principal``'s spend (or the workspace's)
    has newly reached this period. Returns only the new crossings."""
    if not principal:
        return []
    percentages = alert_at()
    if not percentages:
        return []
    now = time.time() if now is None else now
    found = _crossings(principal, percentages, now)
    if not found:
        return []
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path):
        alerts = {k: v for k, v in _read().items()
                  if now - float(v.get("observed_at") or 0) < _KEEP_SECONDS}
        new = [row for row in found if row["key"] not in alerts]
        if not new:
            return []
        for row in new:
            alerts[row["key"]] = row
        if len(alerts) > _MAX_RECORDS:
            newest = sorted(alerts.items(), key=lambda kv: float(kv[1].get("observed_at") or 0))
            alerts = dict(newest[-_MAX_RECORDS:])
        atomic_write_text(path, json.dumps({"format": _FORMAT, "alerts": alerts}, sort_keys=True))
    return new


def current(now: float | None = None) -> list[dict]:
    """Crossings in each limit's current period, newest first."""
    from datetime import datetime, timezone

    from .spending_limits import _window

    moment = datetime.fromtimestamp(time.time() if now is None else now, timezone.utc)
    rows = [row for row in _read().values()
            if row.get("period") in ("day", "month") and row.get("window") == _window(row["period"], moment)]
    return sorted(rows, key=lambda row: (-float(row.get("observed_at") or 0), row.get("key", "")))


def _label(row: dict, viewer: str) -> str:
    from .spending_limits import PERIOD_LABELS, _money

    limit = f"{_money(row['amount'])} {PERIOD_LABELS.get(row['period'], '')} spending limit"
    if row["scope"] == "workspace":
        who, whose = "The workspace", "its"
    elif row["principal"] == viewer:
        who, whose = "You", "your"
    else:
        name = row["principal"].split(":", 1)[-1]
        who, whose = name, "their"
    verb = "have" if who == "You" else "has"
    if row["percent"] >= 100:
        return f"{who} {verb} reached {whose} {limit}. New paid work stops until it resets or an administrator changes it."
    return f"{who} {verb} used {row['percent']}% of {whose} {limit}."


def sources(viewer: str, *, admin: bool) -> list[dict]:
    """Personal-alert sources for ``viewer``: every crossing for an
    administrator, else only the crossings of the viewer's own limit."""
    if not viewer:
        return []
    out = []
    for row in current():
        if not admin and not (row["scope"] == "person" and row["principal"] == viewer):
            continue
        out.append({"ref": "spending-limit:" + row["key"], "version": row["key"],
                    "category": "blocked", "goal_id": None, "project_id": None,
                    "title": "Spending limit", "label": _label(row, viewer),
                    "href": "/spending-limits" if admin else "/budget",
                    "occurred_at": row.get("observed_at"),
                    "reason": ("This is your spending limit"
                               if row["scope"] == "person" and row["principal"] == viewer
                               else "You manage this spending limit"),
                    "action": ("Review spending or change the limit" if admin
                               else "Review your spending, or ask an administrator to change the limit")})
    return out


__all__ = ["DEFAULT_ALERT_AT", "alert_at", "current", "observe", "sources", "validate_alert_at"]
