"""Schedules an agent proposes for a person to review and create.

Asked "Every Monday at 9am, remind me to review overdue invoices", an agent
had no way to set up recurring work: it asked the person a question, its
helper stalled and the task ended "blocked on user input". A schedule spends
on every run, so an agent never creates one. It proposes one instead: the
proposal is checked here (the timetable must parse, the time zone must
exist), recorded on the task, and the task page offers "Review and create
this schedule", which opens the Automations form filled in. The person
reviews and creates it there, under the same permission and checks as any
schedule.
"""
from __future__ import annotations

import json
from typing import Any

EVENT_KIND = "schedule_proposal"
EVENT_AGENT = "system"
MAX_TEXT = 4000
MAX_TITLE = 200
MAX_PROPOSALS = 5

_DAYS = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")


class ProposalRejected(ValueError):
    """The proposal cannot be offered; ``str(exc)`` says what to fix."""


def _zone_ok(zone: str) -> bool:
    if not zone:
        return True
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo(zone)
        return True
    except Exception:  # noqa: BLE001 -- an unknown or malformed zone name
        return False


def check(text: Any, cron: Any, title: Any = "", zone: Any = "") -> dict[str, str]:
    """The proposal's fields, checked and trimmed."""
    from .scheduler import CronError, next_run

    text = str(text or "").strip()
    cron = " ".join(str(cron or "").split())
    title = str(title or "").strip()[:MAX_TITLE]
    zone = str(zone or "").strip()
    if not text:
        raise ProposalRejected("say what each run should do in 'text'")
    if len(text) > MAX_TEXT:
        raise ProposalRejected(f"'text' is longer than {MAX_TEXT} characters")
    if not _zone_ok(zone):
        raise ProposalRejected(f"{zone!r} is not a time zone name such as America/Chicago")
    try:
        next_run(cron, tz=zone)
    except CronError as exc:
        raise ProposalRejected(f"'cron' is not a valid five-part timetable: {exc}") from exc
    return {"text": text, "cron": cron, "title": title or text[:80], "zone": zone}


def _clock(minute: str, hour: str) -> str | None:
    if minute.isdigit() and hour.isdigit() and int(hour) < 24 and int(minute) < 60:
        return f"{int(hour):02d}:{int(minute):02d}"
    return None


def describe(cron: str, zone: str = "") -> str:
    """The timetable in plain words, for the common shapes; otherwise the
    five-part timetable itself."""
    parts = cron.split()
    where = f" ({zone})" if zone else " (UTC)"
    if len(parts) != 5:
        return f"on the timetable {cron}"
    minute, hour, dom, month, dow = parts
    clock = _clock(minute, hour)
    if clock and month == "*":
        if dom == "*" and dow == "*":
            return f"every day at {clock}{where}"
        if dom == "*" and dow in ("1-5", "MON-FRI", "mon-fri"):
            return f"every weekday at {clock}{where}"
        if dom == "*" and all(d.isdigit() and int(d) <= 7 for d in dow.split(",")):
            names = [_DAYS[int(d) % 7] for d in dow.split(",")]
            return f"every {', '.join(names)} at {clock}{where}"
        if dow == "*" and dom.isdigit():
            return f"on day {int(dom)} of every month at {clock}{where}"
    return f"on the timetable {cron}{where}"


def scheduled_run(world, goal_id: int) -> bool:
    """Whether ``goal_id`` is itself a run a schedule started."""
    try:
        return bool(world.tenant_query(
            "SELECT 1 FROM goal_origins o JOIN goals g ON g.id=o.goal_id "
            "WHERE o.goal_id=? AND o.kind='schedule' AND {tenant_exact:g.tenant_id} LIMIT 1",
            (int(goal_id),)))
    except Exception:  # noqa: BLE001 -- no origin record: an ordinary task
        return False


def propose(world, goal_id: int, **fields: Any) -> dict[str, str]:
    """Check and record a proposal on the goal; returns it."""
    from .config import get_features

    if not get_features().get("scheduling", True):
        raise ProposalRejected("schedules are turned off here ([features] scheduling); tell the person "
                               "an administrator can turn on automations in Settings")
    if scheduled_run(world, goal_id):
        # Its request still reads "every Monday ..."; proposing again would
        # leave this run's work undone.
        raise ProposalRejected("this task is already a run of a schedule, so do this run's work now "
                               "instead of proposing another schedule")
    proposal = check(**fields)
    if len(for_goal(world, goal_id)) >= MAX_PROPOSALS:
        raise ProposalRejected(f"this task already has {MAX_PROPOSALS} schedule proposals")
    world.append_event(goal_id, EVENT_AGENT, EVENT_KIND, json.dumps(proposal, sort_keys=True))
    return proposal


def for_goal(world, goal_id: int) -> list[dict[str, str]]:
    """The goal's proposals, oldest first, without repeats."""
    from .task_files import iter_goal_events

    seen: list[dict[str, str]] = []
    for event in iter_goal_events(world, goal_id):
        if event.kind != EVENT_KIND or event.agent != EVENT_AGENT:
            continue
        try:
            proposal = check(**json.loads(event.content))
        except (ValueError, TypeError):
            continue
        if proposal not in seen:
            seen.append(proposal)
    return seen
