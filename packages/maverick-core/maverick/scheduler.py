"""Cron-style scheduler helper for the job queue.

Computes the next run time for a 5-field cron expression
(``minute hour day-of-month month day-of-week``) without dragging in
a cron dependency. Supports ``*``, ``*/n`` steps, ``a-b`` ranges,
``a,b,c`` lists, and named months/weekdays.

Pairs with :mod:`maverick.job_queue`: ``schedule_cron`` enqueues a
job at the next matching time; a worker that re-schedules after each
run gives you a recurring task.

This is intentionally minimal — no seconds field, no ``@reboot``, no
timezone math beyond the caller's ``now`` (pass a UTC timestamp for
UTC scheduling). Good enough for "every weekday at 9am" without a
dep.
"""
from __future__ import annotations

import datetime as _dt
import logging

log = logging.getLogger(__name__)


_MONTHS = {
    m: i for i, m in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun",
         "jul", "aug", "sep", "oct", "nov", "dec"], start=1)
}
_DOW = {
    d: i for i, d in enumerate(
        ["sun", "mon", "tue", "wed", "thu", "fri", "sat"])
}


class CronError(ValueError):
    """Raised on a malformed cron expression."""


def _parse_field(field: str, lo: int, hi: int, names: dict | None = None) -> set[int]:
    out: set[int] = set()
    for part in field.split(","):
        part = part.strip().lower()
        if not part:
            continue
        step = 1
        has_step = False
        if "/" in part:
            base, _, step_s = part.partition("/")
            try:
                step = int(step_s)
            except ValueError as e:
                raise CronError(f"bad step in {field!r}") from e
            if step <= 0:
                raise CronError(f"step must be > 0 in {field!r}")
            has_step = True
            part = base or "*"
        if part == "*":
            rng = range(lo, hi + 1)
        elif "-" in part:
            a_s, _, b_s = part.partition("-")
            a = _resolve(a_s, names)
            b = _resolve(b_s, names)
            if a > b:
                raise CronError(f"range {part!r} reversed")
            rng = range(a, b + 1)
        else:
            v = _resolve(part, names)
            # `N/step` (single start + step) runs from N up to the field
            # max, matching cron: '5/15' on minutes -> 5,20,35,50. Without
            # a step, a bare N is just that single value.
            rng = range(v, hi + 1) if has_step else range(v, v + 1)
        for i, val in enumerate(rng):
            if i % step == 0:
                if not (lo <= val <= hi):
                    raise CronError(f"value {val} out of [{lo},{hi}] in {field!r}")
                out.add(val)
    if not out:
        raise CronError(f"empty field {field!r}")
    return out


def _resolve(token: str, names: dict | None) -> int:
    token = token.strip().lower()
    if names and token in names:
        return names[token]
    try:
        return int(token)
    except ValueError as e:
        raise CronError(f"bad token {token!r}") from e


def parse_cron(expr: str) -> tuple[set[int], set[int], set[int], set[int], set[int]]:
    fields = expr.split()
    if len(fields) != 5:
        raise CronError(
            f"cron needs 5 fields (min hour dom mon dow), got {len(fields)}"
        )
    minute = _parse_field(fields[0], 0, 59)
    hour = _parse_field(fields[1], 0, 23)
    dom = _parse_field(fields[2], 1, 31)
    mon = _parse_field(fields[3], 1, 12, _MONTHS)
    # Allow 7 as a synonym for Sunday (both 0 and 7 are standard cron):
    # parse with hi=7 so '7' and ranges like '5-7' don't trip the bound
    # check, THEN fold 7 -> 0.
    dow = _parse_field(fields[4], 0, 7, _DOW)
    if 7 in dow:
        dow.discard(7)
        dow.add(0)
    return minute, hour, dom, mon, dow


def _resolve_zone(tz: str):
    """A tzinfo for ``tz`` (an IANA name like 'America/New_York'), or UTC when
    empty/unknown -- an unrecognized zone must never crash a schedule, just fall
    back to the historical UTC behaviour."""
    if not tz:
        return _dt.timezone.utc
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(tz)
    except Exception:
        return _dt.timezone.utc


def next_run(expr: str, *, after: float | None = None, tz: str = "") -> float:
    """Return the next epoch timestamp matching ``expr`` strictly after
    ``after`` (default: now). Searches up to ~9 years forward.

    Cron fields are matched in ``tz`` (an IANA zone name) when given, else in
    **UTC** — so ``0 9 * * *`` with ``tz='America/New_York'`` fires at 09:00 New
    York wall-clock (adjusting across DST), not 09:00 UTC. The returned value is
    always a UTC epoch. Day-of-month and day-of-week follow Vixie cron semantics:
    if BOTH are restricted (not ``*``), a match on EITHER fires. (Across a DST
    transition a local schedule at the skipped/doubled hour may fire irregularly
    that day -- the standard local-cron caveat.)
    """
    minute, hour, dom, mon, dow = parse_cron(expr)
    # Walk the wall-clock in the target zone: the cron fields (hour/minute/day)
    # are matched against LOCAL time, and a zone-aware datetime's .timestamp()
    # yields the correct UTC epoch. UTC (the default) keeps the original
    # DST-free, contract-exact behaviour.
    zone = _resolve_zone(tz)
    after_ts = (
        after if after is not None
        else _dt.datetime.now(_dt.timezone.utc).timestamp()
    )
    base = _dt.datetime.fromtimestamp(after_ts, tz=zone)
    # Round up to the next whole minute.
    t = base.replace(second=0, microsecond=0) + _dt.timedelta(minutes=1)

    dom_restricted = dom != set(range(1, 32))
    dow_restricted = dow != set(range(7))

    def _day_matches(d: _dt.datetime) -> bool:
        if d.month not in mon:
            return False
        # cron weekday: Mon=0..Sun=6 in python; we use Sun=0..Sat=6.
        py_dow = (d.weekday() + 1) % 7  # Mon(0)->1 ... Sun(6)->0
        dom_ok = d.day in dom
        dow_ok = py_dow in dow
        if dom_restricted and dow_restricted:
            return dom_ok or dow_ok
        if dom_restricted:
            return dom_ok
        if dow_restricted:
            return dow_ok
        return True

    # Bound the search. Skip whole non-matching days in one jump instead of
    # walking 1440 dead minutes each — so an impossible schedule
    # ('0 0 30 2 *', Feb 30) costs ~day-steps, not ~2M minute-steps.
    #
    # Horizon must clear the longest gap between two valid Feb-29s. The
    # Gregorian century rule skips leap years at 1900/2100/2200/2300, so e.g.
    # the next Feb 29 after 2096 is 2104 — an 8-year gap. A 4-year (1464-day)
    # cap raised a spurious CronError for '0 0 29 2 *' across a skipped
    # century. Use 9 years to clear the 8-year worst case with margin.
    deadline = base + _dt.timedelta(days=366 * 9)
    while t <= deadline:
        if not _day_matches(t):
            t = (t + _dt.timedelta(days=1)).replace(
                hour=0, minute=0, second=0, microsecond=0)
            continue
        if t.hour in hour and t.minute in minute:
            candidate_ts = t.timestamp()
            if candidate_ts > after_ts:
                return candidate_ts
        t += _dt.timedelta(minutes=1)
    raise CronError(f"no match for {expr!r} within 9 years")


def schedule_cron(queue, expr: str, kind: str, payload: dict | None = None,
                  *, after: float | None = None) -> tuple[int, float]:
    """Enqueue ``kind`` at the next time matching ``expr``.

    Returns ``(job_id, run_at)``. Pair with a worker that calls
    ``schedule_cron`` again after each run to make it recurring. A ``__tz__`` key
    in ``payload`` (an IANA zone name) matches the cron in that zone -- carried on
    the payload so the worker's re-arm (which reuses it) stays timezone-correct.
    """
    tz = str((payload or {}).get("__tz__") or "")
    run_at = next_run(expr, after=after, tz=tz)
    job_id = queue.enqueue(kind, payload or {}, run_at=run_at)
    return job_id, run_at


TIMETABLE_REPEATS = ("hourly", "daily", "weekdays", "weekly", "monthly")


def timetable_cron(repeat: str, *, at: str = "09:00", days: list[int] | None = None,
                   day_of_month: int = 1, every_hours: int = 1) -> str:
    """The 5-field cron for a plain timetable ("every weekday at 09:00").

    Hours and minutes are wall-clock in the schedule's own zone (carried as
    ``__tz__`` beside the cron), so no UTC shifting happens here. ``days`` are
    cron weekdays (0 = Sunday .. 6 = Saturday); ``day_of_month`` is 1-31.
    A monthly date absent from a month is skipped, matching a custom cron.
    Raises :class:`CronError` on bad input.
    """
    if repeat not in TIMETABLE_REPEATS:
        raise CronError("choose how often the schedule repeats")
    if repeat == "hourly":
        if type(every_hours) is not int or not 1 <= every_hours <= 12:
            raise CronError("every_hours must be between 1 and 12")
        return "0 * * * *" if every_hours == 1 else f"0 */{every_hours} * * *"
    parts = str(at or "").split(":")
    if len(parts) != 2 or not all(p.isdigit() and len(p) == 2 for p in parts):
        raise CronError("time must look like 09:00")
    hour, minute = int(parts[0]), int(parts[1])
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise CronError("time must be a real time of day")
    if repeat == "daily":
        return f"{minute} {hour} * * *"
    if repeat == "weekdays":
        return f"{minute} {hour} * * 1-5"
    if repeat == "weekly":
        chosen = sorted(set(days or []))
        if not chosen or any(type(d) is not int or not 0 <= d <= 6 for d in chosen):
            raise CronError("choose at least one day of the week")
        return f"{minute} {hour} * * {','.join(str(d) for d in chosen)}"
    if type(day_of_month) is not int or not 1 <= day_of_month <= 31:
        raise CronError("day_of_month must be between 1 and 31")
    return f"{minute} {hour} {day_of_month} * *"


def upcoming_runs(expr: str, *, tz: str = "", count: int = 3, after: float | None = None) -> list[float]:
    """The next ``count`` (at most 10) run times for ``expr`` in ``tz``, as UTC epochs."""
    out: list[float] = []
    cursor = after
    for _ in range(max(1, min(int(count), 10))):
        cursor = next_run(expr, after=cursor, tz=tz)
        out.append(cursor)
    return out


__all__ = ["parse_cron", "next_run", "schedule_cron", "CronError", "TIMETABLE_REPEATS",
           "timetable_cron", "upcoming_runs"]
