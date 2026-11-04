"""Per-zone cron scheduling: a flow's `0 9 * * *` should fire at 9am in its own
timezone (adjusting across DST), not 9am UTC. The returned value is always a UTC
epoch; UTC stays the default."""
from __future__ import annotations

import datetime as dt

from maverick.scheduler import next_run


def _local(ts: float, tz: str) -> dt.datetime:
    from zoneinfo import ZoneInfo
    return dt.datetime.fromtimestamp(ts, ZoneInfo(tz) if tz else dt.timezone.utc)


def _after(y: int, m: int, d: int) -> float:
    return dt.datetime(y, m, d, 0, 0, tzinfo=dt.timezone.utc).timestamp()


def test_utc_is_the_default_and_unchanged():
    ts = next_run("0 9 * * *", after=_after(2026, 7, 1))
    assert (_local(ts, "").hour, _local(ts, "").minute) == (9, 0)


def test_local_zone_fires_at_local_wall_clock():
    ts = next_run("0 9 * * *", after=_after(2026, 7, 1), tz="America/New_York")
    d = _local(ts, "America/New_York")
    assert (d.hour, d.minute) == (9, 0)      # 9am New York
    assert _local(ts, "").hour == 13         # == 13:00 UTC in summer (EDT, UTC-4)


def test_dst_shifts_the_utc_instant_for_the_same_local_time():
    summer = next_run("0 9 * * *", after=_after(2026, 7, 1), tz="America/New_York")
    winter = next_run("0 9 * * *", after=_after(2026, 1, 1), tz="America/New_York")
    assert _local(summer, "").hour == 13     # EDT (UTC-4)
    assert _local(winter, "").hour == 14     # EST (UTC-5) -- same 9am local, later in UTC


def test_unknown_zone_falls_back_to_utc_not_a_crash():
    ts = next_run("0 9 * * *", after=_after(2026, 7, 1), tz="Not/AZone")
    assert _local(ts, "").hour == 9


def test_schedule_cron_reads_tz_from_payload():
    from maverick.scheduler import schedule_cron

    class _Q:
        def __init__(self):
            self.enqueued = []

        def enqueue(self, kind, payload, run_at=None):
            self.enqueued.append((kind, payload, run_at))
            return 1
    q = _Q()
    _jid, run_at = schedule_cron(q, "0 9 * * *", "flow_cron",
                                 {"__cron__": "0 9 * * *", "__tz__": "America/New_York"},
                                 after=_after(2026, 7, 1))
    assert _local(run_at, "America/New_York").hour == 9   # tz honoured via the payload


def test_dst_fall_back_never_returns_a_past_fold_candidate():
    from zoneinfo import ZoneInfo

    zone = ZoneInfo("America/New_York")
    after_dt = dt.datetime(2026, 11, 1, 1, 30, 30, tzinfo=zone).replace(fold=1)
    after = after_dt.timestamp()

    ts = next_run("31 1 * * *", after=after, tz="America/New_York")
    d = _local(ts, "America/New_York")

    assert ts > after
    assert (d.year, d.month, d.day, d.hour, d.minute) == (2026, 11, 2, 1, 31)
