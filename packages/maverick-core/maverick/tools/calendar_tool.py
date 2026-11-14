"""Calendar tool — list / create / find-slot via CalDAV.

Most calendars (Apple iCloud, Fastmail, Posteo, Nextcloud, etc.)
speak CalDAV out of the box. Google Calendar requires their OAuth
flow — handled separately in a future provider.

Config (env first, then ~/.maverick/config.toml [calendar]):
  CALDAV_URL         — your principal URL (e.g. https://caldav.icloud.com)
  CALDAV_USER        — username / email
  CALDAV_PASSWORD    — app password
  CALDAV_CALENDAR    — optional calendar id (defaults to first)

Optional [calendar] extra installs ``caldav>=1.3``.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_CAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["list_events", "create_event", "find_slot"],
            "description": "Operation.",
        },
        "start": {"type": "string", "description": "ISO 8601 start time."},
        "end": {"type": "string", "description": "ISO 8601 end time."},
        "title": {"type": "string", "description": "Event title (create_event)."},
        "description": {"type": "string", "description": "Event description (create_event)."},
        "duration_minutes": {
            "type": "integer",
            "description": "Duration for find_slot (default 30).",
        },
        "search_days": {
            "type": "integer",
            "description": "How many days ahead to scan for find_slot (default 7).",
        },
        "earliest_hour": {
            "type": "integer",
            "description": "Earliest hour-of-day (0-23) considered for find_slot (default 9).",
        },
        "latest_hour": {
            "type": "integer",
            "description": "Latest hour-of-day (default 18).",
        },
    },
    "required": ["op"],
}


def _cfg(key: str, env: str, default: str = "") -> str:
    val = os.environ.get(env, "").strip()
    if val:
        return val
    try:
        from ..config import load_config
        cfg = (load_config() or {}).get("calendar") or {}
        return str(cfg.get(key, default)).strip()
    except Exception:
        return default


def _get_caldav_calendar():
    """Resolve the user's selected calendar object via caldav."""
    try:
        import caldav
    except ImportError as e:
        raise ImportError(
            "caldav not installed. Run: python -m pip install -e './packages/maverick-core[calendar]'"
        ) from e
    url = _cfg("url", "CALDAV_URL")
    user = _cfg("user", "CALDAV_USER")
    pw = _cfg("password", "CALDAV_PASSWORD")
    if not url or not user or not pw:
        raise RuntimeError(
            "Calendar requires CALDAV_URL + CALDAV_USER + CALDAV_PASSWORD "
            "(use an app password, not your account password)."
        )
    client = caldav.DAVClient(url=url, username=user, password=pw)
    principal = client.principal()
    cals = principal.calendars()
    if not cals:
        raise RuntimeError("No calendars found for this CalDAV principal.")
    target_id = _cfg("calendar", "CALDAV_CALENDAR")
    if target_id:
        for c in cals:
            if target_id in (c.id or "") or target_id in (c.name or ""):
                return c
    return cals[0]



def _escape_ical_text(value: Any) -> str:
    """Escape iCalendar TEXT values to prevent property injection."""
    s = str(value or "")
    s = s.replace("\\", "\\\\")
    s = s.replace("\r\n", "\\n").replace("\r", "\\n").replace("\n", "\\n")
    return s.replace(";", "\\;").replace(",", "\\,")


def _parse_iso(s: str) -> datetime:
    """Parse ISO 8601; treat naive as UTC."""
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _list_events(args: dict[str, Any]) -> str:
    start_s = (args.get("start") or "").strip()
    end_s = (args.get("end") or "").strip()
    now = datetime.now(tz=timezone.utc)
    start = _parse_iso(start_s) if start_s else now
    end = _parse_iso(end_s) if end_s else (start + timedelta(days=7))
    try:
        cal = _get_caldav_calendar()
        events = cal.search(start=start, end=end, event=True, expand=True)
    except ImportError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: caldav list failed: {type(e).__name__}: {e}"
    if not events:
        return f"(no events between {start.isoformat()} and {end.isoformat()})"
    rows: list[str] = []
    for ev in events[:100]:
        try:
            vobj = ev.icalendar_component
            summary = str(vobj.get("summary", ""))
            ev_start = vobj.get("dtstart")
            ev_end = vobj.get("dtend")
            rows.append(f"  {ev_start.dt}  {ev_end.dt if ev_end else '?'}  {summary}")
        except Exception:
            rows.append(f"  {ev.url}")
    return "\n".join(rows)


def _create_event(args: dict[str, Any]) -> str:
    title = (args.get("title") or "").strip()
    start_s = (args.get("start") or "").strip()
    end_s = (args.get("end") or "").strip()
    description = _escape_ical_text(args.get("description") or "")
    title = _escape_ical_text(title)
    if not title or not start_s or not end_s:
        return "ERROR: create_event requires title + start + end"
    try:
        start = _parse_iso(start_s)
        end = _parse_iso(end_s)
    except ValueError as e:
        return f"ERROR: bad ISO timestamp: {e}"
    # strftime ignores tzinfo, so formatting a tz-aware datetime with a
    # literal 'Z' mislabels local wall-clock time as UTC: an event given
    # as 10:00-05:00 was saved as 10:00 UTC — five hours early — while
    # the tool reported success. Normalize to UTC before formatting.
    start = start.astimezone(timezone.utc)
    end = end.astimezone(timezone.utc)
    try:
        cal = _get_caldav_calendar()
        ical = (
            "BEGIN:VCALENDAR\n"
            "VERSION:2.0\n"
            "PRODID:-//Lightwork//CalDAV//EN\n"
            "BEGIN:VEVENT\n"
            f"UID:{__import__('uuid').uuid4()}@maverick\n"
            f"DTSTAMP:{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}\n"
            f"DTSTART:{start.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}\n"
            f"DTEND:{end.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}\n"
            f"SUMMARY:{title}\n"
            f"DESCRIPTION:{description}\n"
            "END:VEVENT\n"
            "END:VCALENDAR\n"
        )
        ev = cal.save_event(ical)
    except ImportError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: caldav save failed: {type(e).__name__}: {e}"
    return (
        f"created event {title!r} at {start.isoformat()} -> {end.isoformat()}\n"
        f"url: {getattr(ev, 'url', '')}"
    )


def _find_slot(args: dict[str, Any]) -> str:
    duration_min = max(15, min(int(args.get("duration_minutes") or 30), 480))
    search_days = max(1, min(int(args.get("search_days") or 7), 60))
    # Clamp latest to a real hour first (<=23), then keep earliest
    # strictly below it. Doing earliest first let latest become 24 when
    # earliest=23 (max(24, ...)) → a later cursor.replace(hour=24) crash.
    latest = max(1, min(int(args.get("latest_hour") or 18), 23))
    raw_earliest = args.get("earliest_hour")
    # An explicit 0 (midnight) is a valid hour, not "unset".
    earliest = max(0, min(int(9 if raw_earliest is None else raw_earliest), latest - 1))
    now = datetime.now(tz=timezone.utc).replace(second=0, microsecond=0)
    window_end = now + timedelta(days=search_days)
    try:
        cal = _get_caldav_calendar()
        events = cal.search(start=now, end=window_end, event=True, expand=True)
    except ImportError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: caldav scan failed: {type(e).__name__}: {e}"
    # Collect [start, end] busy windows.
    busy: list[tuple[datetime, datetime]] = []
    dropped = 0
    for ev in events:
        try:
            vobj = ev.icalendar_component
            # All-day events expose dtstart/dtend as datetime.date (not
            # datetime): no tzinfo, and not comparable with the tz-aware
            # datetimes in the slot walk below. The old hasattr() check left a
            # bare date in `busy`, raising TypeError and crashing find_slot for
            # any calendar with an all-day event. Normalize date -> aware
            # midnight UTC and naive datetime -> aware.
            def _aware(x: object) -> datetime:
                if isinstance(x, datetime):
                    return x if x.tzinfo else x.replace(tzinfo=timezone.utc)
                return datetime(x.year, x.month, x.day, tzinfo=timezone.utc)  # type: ignore[attr-defined]
            s = _aware(vobj.get("dtstart").dt)
            e = (_aware(vobj.get("dtend").dt)
                 if vobj.get("dtend") else s + timedelta(hours=1))
            busy.append((s, e))
        except Exception as ex:
            # Dropping an unparseable event is the UNSAFE direction: a busy
            # block silently becomes free time. Count + log it, and warn the
            # caller in the result so the free/busy view isn't trusted blindly.
            dropped += 1
            log.warning("calendar find_slot: skipped an unparseable event (%s)", ex)
            continue
    busy.sort()
    note = (f"  [warning: {dropped} event(s) could not be parsed and were NOT "
            f"counted as busy]" if dropped else "")
    # Walk day-by-day; emit the first earliest-hour:latest-hour gap of
    # >= duration_min minutes.
    duration = timedelta(minutes=duration_min)
    cursor = now
    for _ in range(search_days * 24):  # safety cap on the inner walk
        day_start = cursor.replace(hour=earliest, minute=0, second=0, microsecond=0)
        if day_start >= window_end:
            break
        day_end = min(cursor.replace(hour=latest, minute=0, second=0, microsecond=0), window_end)
        if day_start < now:
            day_start = max(day_start, now)
        if day_start >= day_end:
            cursor = (cursor + timedelta(days=1)).replace(hour=0, minute=0)
            continue
        # Day busy windows.
        day_busy = sorted([
            (max(s, day_start), min(e, day_end))
            for s, e in busy if s < day_end and e > day_start
        ])
        cur = day_start
        for s, e in day_busy:
            if s - cur >= duration:
                end = cur + duration
                return (
                    f"free slot: {cur.isoformat()} -> {end.isoformat()} "
                    f"({duration_min} min)" + note
                )
            cur = max(cur, e)
        if day_end - cur >= duration:
            end = cur + duration
            return (
                f"free slot: {cur.isoformat()} -> {end.isoformat()} "
                f"({duration_min} min)" + note
            )
        # Move to next day's earliest hour.
        cursor = (cursor + timedelta(days=1)).replace(hour=0, minute=0)
        if cursor >= window_end:
            break
    return f"no {duration_min}-min slot found in next {search_days} days" + note


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    if op == "list_events":
        return _list_events(args)
    if op == "create_event":
        return _create_event(args)
    if op == "find_slot":
        return _find_slot(args)
    return f"ERROR: unknown op {op!r}"


def calendar_tool() -> Tool:
    return Tool(
        name="calendar",
        description=(
            "Read / write calendar events via CalDAV (Apple iCloud, "
            "Fastmail, Posteo, Nextcloud, etc.). ops: list_events "
            "(start + end ISO times), create_event (title, start, end, "
            "optional description), find_slot (duration_minutes + "
            "search_days + earliest_hour + latest_hour). Config: "
            "CALDAV_URL + CALDAV_USER + CALDAV_PASSWORD (app password). "
            "Install with: python -m pip install -e './packages/maverick-core[calendar]'."
        ),
        input_schema=_CAL_SCHEMA,
        fn=_run,
    )
