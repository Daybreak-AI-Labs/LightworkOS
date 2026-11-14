"""Tests for the cron scheduler (maverick.scheduler)."""
from __future__ import annotations

import datetime as dt
import time

from maverick.scheduler import CronError, next_run

# ---------- scheduler: impossible schedule is bounded + fast ----------

def test_scheduler_impossible_schedule_raises_fast():
    from maverick.scheduler import CronError, next_run
    # Feb 30 never exists; must raise CronError quickly (day-skip walk),
    # not hang on ~2M minute iterations.
    t0 = time.time()
    raised = False
    try:
        next_run("0 0 30 2 *")
    except CronError:
        raised = True
    elapsed = time.time() - t0
    assert raised
    assert elapsed < 2.0, f"took {elapsed:.2f}s — should day-skip, not minute-walk"


def test_scheduler_leap_day_still_resolves():
    import datetime as _dt

    from maverick.scheduler import next_run
    # Feb 29 IS valid on leap years; must resolve to 2028-02-29.
    base = _dt.datetime(2026, 6, 1, tzinfo=_dt.timezone.utc).timestamp()
    ts = next_run("0 0 29 2 *", after=base)
    got = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc)
    assert got.month == 2 and got.day == 29


# ---------- cron Feb-29 across the skipped century ----------

def test_cron_feb29_resolves_across_skipped_century():
    # 2100 is NOT a leap year (Gregorian century rule), so the next Feb 29 after
    # 2097 is 2104 — ~7 years out, past the old 4-year (1464-day) horizon.
    base = dt.datetime(2097, 3, 1, 0, 0, tzinfo=dt.timezone.utc).timestamp()
    ts = next_run("0 0 29 2 *", after=base)
    got = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)
    assert (got.month, got.day) == (2, 29)
    assert got.year == 2104


def test_cron_impossible_day_still_raises():
    # Feb 30 never exists — must still terminate with CronError, not hang.
    base = dt.datetime(2026, 1, 1).timestamp()
    try:
        next_run("0 0 30 2 *", after=base)
        raise AssertionError("expected CronError for Feb 30")
    except CronError:
        pass


# ---------- Scheduler ----------

def test_scheduler_parse_basic():
    from maverick.scheduler import parse_cron
    minute, hour, dom, mon, dow = parse_cron("0 9 * * 1-5")
    assert minute == {0}
    assert hour == {9}
    assert dow == {1, 2, 3, 4, 5}


def test_scheduler_rejects_bad_field_count():
    from maverick.scheduler import CronError, parse_cron
    try:
        parse_cron("0 9 * *")
    except CronError as e:
        assert "5 fields" in str(e)
        return
    raise AssertionError("expected CronError")


def test_scheduler_step_syntax():
    from maverick.scheduler import parse_cron
    minute, *_ = parse_cron("*/15 * * * *")
    assert minute == {0, 15, 30, 45}


def test_scheduler_single_value_step_expands():
    """'5/15' means 5,20,35,50 — not just {5}."""
    from maverick.scheduler import parse_cron
    minute, *_ = parse_cron("5/15 * * * *")
    assert minute == {5, 20, 35, 50}


def test_scheduler_sunday_as_7_accepted():
    """'7' and ranges containing 7 are Sunday, folded to 0 — not rejected."""
    from maverick.scheduler import parse_cron
    *_, dow = parse_cron("0 9 * * 7")
    assert dow == {0}
    *_, dow2 = parse_cron("0 9 * * 5-7")
    assert dow2 == {5, 6, 0}


def test_scheduler_next_run_daily_9am_utc():
    import datetime as _dt

    from maverick.scheduler import next_run
    # Monday 2026-06-01 08:00 UTC -> next "0 9 * * *" is same day 09:00 UTC.
    base = _dt.datetime(2026, 6, 1, 8, 0, tzinfo=_dt.timezone.utc).timestamp()
    ts = next_run("0 9 * * *", after=base)
    got = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc)
    assert got.hour == 9 and got.minute == 0
    assert got.date() == _dt.date(2026, 6, 1)


def test_scheduler_next_run_weekday_only_utc():
    import datetime as _dt

    from maverick.scheduler import next_run
    # Friday 2026-06-05 10:00 UTC, "0 9 * * 1-5" -> Monday 2026-06-08 09:00.
    base = _dt.datetime(2026, 6, 5, 10, 0, tzinfo=_dt.timezone.utc).timestamp()
    ts = next_run("0 9 * * 1-5", after=base)
    got = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc)
    assert got.weekday() == 0  # Monday
    assert got.date() == _dt.date(2026, 6, 8)


def test_scheduler_next_run_is_utc():
    """Fields match UTC regardless of host TZ — '0 0 * * *' is 00:00 UTC."""
    import datetime as _dt

    from maverick.scheduler import next_run
    base = _dt.datetime(2026, 6, 1, 12, 0, tzinfo=_dt.timezone.utc).timestamp()
    ts = next_run("0 0 * * *", after=base)
    got = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc)
    assert got.hour == 0 and got.minute == 0
    assert got.date() == _dt.date(2026, 6, 2)


def test_scheduler_star_step_day_field_is_unrestricted_so_days_are_anded():
    """Vixie cron treats a day field starting with ``*`` as unrestricted, so
    ``0 0 */2 * 1`` fires on odd days that are also Mondays (AND), not on any
    odd day or any Monday (OR). Two plainly restricted fields still OR."""
    import datetime as _dt

    # Monday 2026-06-01 12:00 UTC. Odd-day Mondays in June: 1, 15, 29.
    base = _dt.datetime(2026, 6, 1, 12, 0, tzinfo=_dt.timezone.utc).timestamp()
    got = _dt.datetime.fromtimestamp(next_run("0 0 */2 * 1", after=base), tz=_dt.timezone.utc)
    assert got.date() == _dt.date(2026, 6, 15)
    got = _dt.datetime.fromtimestamp(next_run("0 0 13 * 1", after=base), tz=_dt.timezone.utc)
    assert got.date() == _dt.date(2026, 6, 8)  # a Monday, before the 13th


def test_scheduler_schedule_cron_enqueues(tmp_path):
    import datetime as _dt

    from maverick.job_queue import JobQueue
    from maverick.scheduler import schedule_cron
    q = JobQueue(db_path=tmp_path / "jobs.db")
    base = _dt.datetime(2026, 6, 1, 8, 0, 0).timestamp()
    job_id, run_at = schedule_cron(q, "0 9 * * *", "run_goal",
                                    {"goal_id": 1}, after=base)
    assert job_id > 0
    job = q.get(job_id)
    assert job is not None
    assert job.kind == "run_goal"
    assert abs(job.run_at - run_at) < 1.0
    # Not claimable before run_at.
    assert q.claim(now=base) is None
    # Claimable at/after run_at.
    assert q.claim(now=run_at + 1) is not None
