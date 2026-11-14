"""Calendar tool: create_event must preserve the absolute time of
tz-aware timestamps.

Regression: DTSTART/DTEND were formatted with strftime('%Y%m%dT%H%M%SZ'),
which ignores tzinfo — an event given as 10:00-05:00 was written to the
CalDAV server as 10:00 UTC (five hours early) while the tool reported
success at the intended time.
"""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest


def _fake_caldav(monkeypatch):
    """Wire a fake caldav module + creds; return the calendar mock."""
    monkeypatch.setenv("CALDAV_URL", "https://cal.test")
    monkeypatch.setenv("CALDAV_USER", "me@test")
    monkeypatch.setenv("CALDAV_PASSWORD", "pw")
    fake_caldav = types.ModuleType("caldav")
    fake_calendar = MagicMock()
    fake_saved = MagicMock()
    fake_saved.url = "https://cal.test/event/1"
    fake_calendar.save_event = MagicMock(return_value=fake_saved)
    fake_principal = MagicMock()
    fake_principal.calendars = MagicMock(return_value=[fake_calendar])
    fake_client = MagicMock()
    fake_client.principal = MagicMock(return_value=fake_principal)
    fake_caldav.DAVClient = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "caldav", fake_caldav)
    return fake_calendar


def test_create_event_converts_utc_offset(monkeypatch):
    cal = _fake_caldav(monkeypatch)
    from maverick.tools.calendar_tool import calendar_tool
    out = calendar_tool().fn({
        "op": "create_event",
        "title": "Standup",
        "start": "2026-07-01T10:00:00-05:00",
        "end": "2026-07-01T11:00:00-05:00",
    })
    assert "created event" in out
    ical = cal.save_event.call_args.args[0]
    assert "DTSTART:20260701T150000Z" in ical  # 10:00-05:00 == 15:00 UTC
    assert "DTEND:20260701T160000Z" in ical
    # The local wall-clock fields mislabeled as UTC must be gone.
    assert "DTSTART:20260701T100000Z" not in ical


def test_create_event_keeps_utc_and_naive_unchanged(monkeypatch):
    cal = _fake_caldav(monkeypatch)
    from maverick.tools.calendar_tool import calendar_tool
    calendar_tool().fn({
        "op": "create_event",
        "title": "A",
        "start": "2026-07-01T10:00:00Z",  # explicit UTC
        "end": "2026-07-01T11:00:00",     # naive == UTC by contract
    })
    ical = cal.save_event.call_args.args[0]
    assert "DTSTART:20260701T100000Z" in ical
    assert "DTEND:20260701T110000Z" in ical


@pytest.mark.parametrize("busy_hours,expected", [((10, 11), "free slot"), ((9, 10), "free slot"), ((9, 18), "no 30-min slot")])
def test_find_slot_always_discloses_unparseable_busy_events(monkeypatch, busy_hours, expected):
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from maverick.tools import calendar_tool as module

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 7, 1, 9, tzinfo=timezone.utc)

    monkeypatch.setattr(module, "datetime", Clock)
    start, end = busy_hours
    event = SimpleNamespace(icalendar_component={
        "dtstart": SimpleNamespace(dt=Clock(2026, 7, 1, start, tzinfo=timezone.utc)),
        "dtend": SimpleNamespace(dt=Clock(2026, 7, 1, end, tzinfo=timezone.utc)),
    })
    monkeypatch.setattr(module, "_get_caldav_calendar", lambda: SimpleNamespace(search=lambda **kw: [event, object()]))
    result = module._find_slot({"search_days": 1})
    assert expected in result
    assert "1 event(s) could not be parsed" in result


def test_find_slot_honours_earliest_hour_zero(monkeypatch):
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from maverick.tools import calendar_tool as module

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 7, 1, 1, tzinfo=timezone.utc)

    monkeypatch.setattr(module, "datetime", Clock)
    monkeypatch.setattr(module, "_get_caldav_calendar", lambda: SimpleNamespace(search=lambda **kw: []))
    result = module._find_slot({"search_days": 1, "earliest_hour": 0})
    assert "01:00" in result and "09:00" not in result


# ---------- calendar find_slot: latest_hour=23 must not crash ----------

def test_calendar_find_slot_latest_hour_23(monkeypatch):
    monkeypatch.setenv("CALDAV_URL", "https://cal.test")
    monkeypatch.setenv("CALDAV_USER", "me@test")
    monkeypatch.setenv("CALDAV_PASSWORD", "pw")
    import sys as _sys
    import types as _types
    fake_caldav = _types.ModuleType("caldav")
    fake_calendar = MagicMock()
    fake_calendar.search = MagicMock(return_value=[])
    fake_principal = MagicMock()
    fake_principal.calendars = MagicMock(return_value=[fake_calendar])
    fake_client = MagicMock()
    fake_client.principal = MagicMock(return_value=fake_principal)
    fake_caldav.DAVClient = MagicMock(return_value=fake_client)
    monkeypatch.setitem(_sys.modules, "caldav", fake_caldav)
    from maverick.tools.calendar_tool import calendar_tool
    # earliest=23, latest=23 — previously max(24, min(23,23))=24 →
    # cursor.replace(hour=24) ValueError. Must not crash now.
    out = calendar_tool().fn({
        "op": "find_slot", "earliest_hour": 23, "latest_hour": 23,
    })
    assert "hour must be in 0..23" not in out
    assert "ValueError" not in out


# ---------- calendar tool ----------

def test_calendar_requires_op():
    from maverick.tools.calendar_tool import calendar_tool
    assert "op is required" in calendar_tool().fn({})


def test_calendar_unknown_op():
    from maverick.tools.calendar_tool import calendar_tool
    out = calendar_tool().fn({"op": "garbage"})
    assert "unknown op" in out


def test_calendar_create_requires_fields():
    from maverick.tools.calendar_tool import calendar_tool
    out = calendar_tool().fn({"op": "create_event"})
    assert "requires title + start + end" in out


def test_calendar_requires_credentials(monkeypatch):
    """Without env / config, the tool refuses with a clear message —
    either ImportError-flavored (no caldav lib) OR RuntimeError-
    flavored (lib installed, no creds)."""
    monkeypatch.delenv("CALDAV_URL", raising=False)
    monkeypatch.delenv("CALDAV_USER", raising=False)
    monkeypatch.delenv("CALDAV_PASSWORD", raising=False)
    monkeypatch.setenv("HOME", "/nonexistent-home-for-tests")
    # Force the caldav module to be present so we test the missing-creds
    # path rather than the missing-dep path.
    import sys
    import types
    fake_caldav = types.ModuleType("caldav")
    fake_caldav.DAVClient = MagicMock()
    monkeypatch.setitem(sys.modules, "caldav", fake_caldav)
    from maverick.tools.calendar_tool import calendar_tool
    out = calendar_tool().fn({"op": "list_events"})
    assert "CALDAV_URL" in out


def test_calendar_create_event_calls_caldav(monkeypatch):
    monkeypatch.setenv("CALDAV_URL", "https://cal.test")
    monkeypatch.setenv("CALDAV_USER", "me@test")
    monkeypatch.setenv("CALDAV_PASSWORD", "pw")

    # Build a fake caldav module hierarchy.
    import sys
    import types
    fake_caldav = types.ModuleType("caldav")

    fake_calendar = MagicMock()
    fake_saved = MagicMock()
    fake_saved.url = "https://cal.test/event/123"
    fake_calendar.save_event = MagicMock(return_value=fake_saved)

    fake_principal = MagicMock()
    fake_principal.calendars = MagicMock(return_value=[fake_calendar])

    fake_client = MagicMock()
    fake_client.principal = MagicMock(return_value=fake_principal)
    fake_caldav.DAVClient = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "caldav", fake_caldav)

    from maverick.tools.calendar_tool import calendar_tool
    out = calendar_tool().fn({
        "op": "create_event",
        "title": "Meeting with Alice",
        "start": "2026-06-01T10:00:00",
        "end": "2026-06-01T11:00:00",
        "description": "monthly sync",
    })
    assert "created event" in out
    assert "https://cal.test/event/123" in out
    fake_calendar.save_event.assert_called_once()
    ical_arg = fake_calendar.save_event.call_args.args[0]
    assert "SUMMARY:Meeting with Alice" in ical_arg
    assert "DTSTART:20260601T100000Z" in ical_arg


def test_calendar_create_event_converts_offset_to_utc(monkeypatch):
    # A start/end carrying a non-UTC offset must be converted to UTC before the
    # literal 'Z' is appended -- otherwise 10:00+02:00 is mislabelled as 10:00Z
    # and the event lands two hours off.
    monkeypatch.setenv("CALDAV_URL", "https://cal.test")
    monkeypatch.setenv("CALDAV_USER", "me@test")
    monkeypatch.setenv("CALDAV_PASSWORD", "pw")

    import sys
    import types
    fake_caldav = types.ModuleType("caldav")
    fake_calendar = MagicMock()
    fake_saved = MagicMock()
    fake_saved.url = "https://cal.test/event/789"
    fake_calendar.save_event = MagicMock(return_value=fake_saved)
    fake_principal = MagicMock()
    fake_principal.calendars = MagicMock(return_value=[fake_calendar])
    fake_client = MagicMock()
    fake_client.principal = MagicMock(return_value=fake_principal)
    fake_caldav.DAVClient = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "caldav", fake_caldav)

    from maverick.tools.calendar_tool import calendar_tool
    calendar_tool().fn({
        "op": "create_event",
        "title": "Sync",
        "start": "2026-06-01T10:00:00+02:00",
        "end": "2026-06-01T11:30:00+02:00",
        "description": "x",
    })
    ical_arg = fake_calendar.save_event.call_args.args[0]
    assert "DTSTART:20260601T080000Z" in ical_arg
    assert "DTEND:20260601T093000Z" in ical_arg


def test_calendar_create_event_escapes_text_fields(monkeypatch):
    monkeypatch.setenv("CALDAV_URL", "https://cal.test")
    monkeypatch.setenv("CALDAV_USER", "me@test")
    monkeypatch.setenv("CALDAV_PASSWORD", "pw")

    import sys
    import types
    fake_caldav = types.ModuleType("caldav")

    fake_calendar = MagicMock()
    fake_saved = MagicMock()
    fake_saved.url = "https://cal.test/event/456"
    fake_calendar.save_event = MagicMock(return_value=fake_saved)

    fake_principal = MagicMock()
    fake_principal.calendars = MagicMock(return_value=[fake_calendar])
    fake_client = MagicMock()
    fake_client.principal = MagicMock(return_value=fake_principal)
    fake_caldav.DAVClient = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "caldav", fake_caldav)

    from maverick.tools.calendar_tool import calendar_tool
    calendar_tool().fn({
        "op": "create_event",
        "title": "Team sync\nRRULE:FREQ=DAILY",
        "start": "2026-06-01T10:00:00",
        "end": "2026-06-01T11:00:00",
        "description": "normal\nBEGIN:VALARM",
    })
    ical_arg = fake_calendar.save_event.call_args.args[0]
    assert "SUMMARY:Team sync\\nRRULE:FREQ=DAILY" in ical_arg
    assert "DESCRIPTION:normal\\nBEGIN:VALARM" in ical_arg
    assert "\nRRULE:FREQ=DAILY\n" not in ical_arg
    assert "\nBEGIN:VALARM\n" not in ical_arg


def test_calendar_find_slot_picks_free_window(monkeypatch):
    """find_slot returns the first gap that fits the requested duration."""
    monkeypatch.setenv("CALDAV_URL", "https://cal.test")
    monkeypatch.setenv("CALDAV_USER", "me@test")
    monkeypatch.setenv("CALDAV_PASSWORD", "pw")

    import sys
    import types
    fake_caldav = types.ModuleType("caldav")

    fake_calendar = MagicMock()
    # No events at all -> the first earliest-hour minute on the next
    # search-day is the free slot.
    fake_calendar.search = MagicMock(return_value=[])

    fake_principal = MagicMock()
    fake_principal.calendars = MagicMock(return_value=[fake_calendar])

    fake_client = MagicMock()
    fake_client.principal = MagicMock(return_value=fake_principal)
    fake_caldav.DAVClient = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "caldav", fake_caldav)

    from maverick.tools.calendar_tool import calendar_tool
    out = calendar_tool().fn({
        "op": "find_slot",
        "duration_minutes": 45,
        "search_days": 1,
        "earliest_hour": 9, "latest_hour": 18,
    })
    assert "free slot:" in out
    assert "45 min" in out


class TestCalendarAllDayEvent:
    def test_find_slot_survives_all_day_event(self, monkeypatch):
        # An all-day event yields a datetime.date; the old hasattr() check left
        # it un-normalized and the slot walk crashed with a date/datetime
        # comparison TypeError (out of _find_slot). It must now normalize the
        # date and return a real slot, not raise / report ERROR.
        import datetime as _dt

        from maverick.tools import calendar_tool

        class _DT:
            def __init__(self, v):
                self.dt = v

        class _FakeEvent:
            # all-day event: dtstart is a date, no dtend.
            icalendar_component = {"dtstart": _DT(_dt.date(2030, 1, 1))}

        class _FakeCal:
            def search(self, *a, **k):
                return [_FakeEvent()]

        monkeypatch.setattr(calendar_tool, "_get_caldav_calendar",
                            lambda: _FakeCal())
        out = calendar_tool._find_slot({"duration_minutes": 30, "search_days": 1})
        assert isinstance(out, str)
        assert not out.startswith("ERROR")
