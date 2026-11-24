"""propose_schedule: offer the person a recurring run to review and create."""
from __future__ import annotations

from . import Tool


def propose_schedule(world, goal_id: int | None = None) -> Tool:
    """Build the tool, scoped to the running goal."""
    from .. import schedule_proposals as sp

    def fn(args: dict) -> str:
        if goal_id is None or world is None:
            return "ERROR: a schedule proposal needs a task; describe the schedule in your answer instead."
        try:
            proposal = sp.propose(world, goal_id, text=args.get("text"), cron=args.get("cron"),
                                  title=args.get("title"), zone=args.get("zone"))
        except sp.ProposalRejected as exc:
            return f"ERROR: {exc}. Fix it and call propose_schedule again."
        when = sp.describe(proposal["cron"], proposal["zone"])
        return (f"PROPOSED: {proposal['title']!r}, {when}. Nothing runs yet: the task page now offers "
                "\"Review and create this schedule\", and the schedule starts once the person creates "
                "it there. In your answer, say what you proposed and when it would run, and that they "
                "can review and create it from this task. Do not ask them to confirm here.")

    return Tool(
        name="propose_schedule",
        description=(
            "Propose recurring work (\"every Monday at 9am ...\", \"each month on the 1st ...\") for "
            "the person to review and create. You cannot create a schedule yourself: this records a "
            "proposal, and the task page offers a button that opens it, filled in, on the Automations "
            "page. 'text' is the work each run does, written as a complete request and not the "
            "timetable (\"List the invoices past their due date today and draft a reminder email "
            "for each client\", not \"Every Monday, remind me ...\"); 'cron' is a "
            "five-part timetable (minute hour day-of-month month weekday, 0=Sunday), for example "
            "'0 9 * * 1' for Mondays at 09:00; 'zone' is an IANA time zone such as America/Chicago "
            "when the person gave one (empty means UTC); 'title' is a short name."),
        input_schema={
            "type": "object",
            "properties": {
                "text": {"type": "string",
                         "description": "The work each run does, as a complete request, not the timetable."},
                "cron": {"type": "string", "description": "Five-part timetable, e.g. '0 9 * * 1'."},
                "zone": {"type": "string", "description": "IANA time zone, e.g. America/Chicago; empty = UTC."},
                "title": {"type": "string", "description": "Short name for the schedule."},
            },
            "required": ["text", "cron"],
        },
        fn=fn,
    )
