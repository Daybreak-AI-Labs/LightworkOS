"""What a person should know about an answer before relying on it.

Three facts, each read from the task's own record and never assumed:

* whether the extra check reviewed the answer (``Checked``) or why it did not
  (``Not checked: <reason>``), from the main agent's recorded check steps;
* which agent answered and when it last changed (:mod:`.agent_changelog`);
* whether the backup AI model was used because the main one was unavailable.
"""
from __future__ import annotations

import re

from .answer_run_details import _episode, _identity, _number
from .step_narration import agent_parts

_TESTS = re.compile(r"FAIL_TO_PASS: (\d+)/(\d+) pass; PASS_TO_PASS: (\d+)/(\d+) pass")
_EVENT_WINDOW = 2000

CHECKED = "A separate AI check compared this answer with your request before it was shown."
# The main agent's recorded check outcomes, newest wins. Coding-mode patch
# checks along the way are not outcomes and are ignored.
_OUTCOMES = (
    ("verifier accepted", "checked", CHECKED),
    ("verifier rejected after retry", "concerns",
     "The extra check still had concerns after one revision."),
    ("verifier rejected", "not_checked",
     "The extra check asked for changes, and the revised answer was not checked again."),
    ("verification skipped (conversational", "not_checked",
     "Short conversational answers that use no tools or files are not sent to the extra check."),
    ("verification skipped (risk-proportional", "not_checked",
     "Your workspace skips the extra check for low-risk answers that use no tools or code."),
    ("verifier did not complete", "not_checked",
     "The extra check started but could not finish within the spending limit. Raise the limit or check fewer items, then try again."),
    ("verifier failed", "not_checked", "The extra check could not run. Try again."),
)
LABELS = {"checked": "Checked", "concerns": "Checked with concerns",
          "not_checked": "Not checked", "not_recorded": "Check result not recorded", "hidden": "Check result not shown"}
NOT_SENT = "No extra check result was recorded for this run."
NO_RECORD = "A completed run matching this saved answer is unavailable. Earlier checks do not establish whether this answer was checked."
HIDDEN = "Step details are withheld in this workspace, so the check result cannot be shown."
FALLBACK = "The backup AI model was used for this answer because the main one was unavailable."


def _recent_events(world, goal_id: int) -> list:
    recent = getattr(world, "recent_goal_events", None)
    if callable(recent):
        return recent(goal_id, limit=_EVENT_WINDOW)
    return world.goal_events(goal_id, limit=_EVENT_WINDOW)


def _latest_root_run(events: list) -> list:
    """Events of the last main-agent run (a resumed task starts a fresh one)."""
    root = None
    for event in events:
        if agent_parts(event.agent)[1] == 0:
            root = event.agent
    return [event for event in events if event.agent == root] if root else []


def _tests_outcome(content: str) -> tuple[str, str]:
    match = _TESTS.search(content)
    if match is None:
        return "not_recorded", "The required test results could not be read from the retained record."
    a, b, c, d = (int(value) for value in match.groups())
    if a == b and c == d:
        return "checked", "The required tests passed."
    return "concerns", "The required tests did not all pass."


def _outcome(event, withheld: frozenset[str]) -> tuple[str, str] | None:
    content = str(event.content or "").strip()
    if event.kind == "verify" and content in withheld:
        return "hidden", HIDDEN
    lowered = content.casefold()
    if event.kind == "verify" and lowered.startswith("test-driven verifier"):
        return _tests_outcome(content)
    for prefix, state, reason in _OUTCOMES:
        if lowered.startswith(prefix) and (event.kind == "verify" or prefix == "verifier failed"):
            return state, reason
    return None


def verification(events: list, withheld: frozenset[str] = frozenset()) -> dict:
    """The check outcome of the latest main-agent run, exactly as recorded."""
    state, reason = "not_recorded", NOT_SENT
    for event in _latest_root_run(events):
        found = _outcome(event, withheld)
        if found is not None:
            state, reason = found
    return {"state": state, "label": LABELS[state], "reason": reason}


def used_backup_model(events: list) -> bool:
    """Whether any step of the latest run was answered by the backup model."""
    root_run = _latest_root_run(events)
    start = root_run[0].id if root_run else 0
    return any(event.kind == "model_fallback" and event.id >= start for event in events)


def _matching_run(world, goal):
    evidence = _episode(world, goal.id)
    if evidence is None:
        return None
    row, summary = evidence
    start, end = _number(row["started_at"]), _number(row["ended_at"])
    if start is None or end is None or end < start or summary != goal.result:
        return None
    return row, start, end


def _since_last_use(world, goal, started: float) -> list[dict]:
    """Changes to this agent between the person's previous task with it
    and this run, newest first, so the next answer says the agent changed."""
    from . import agent_changelog

    try:
        previous = world.list_goals(owner=goal.owner or None, domain=goal.domain, before_id=goal.id,
                                    order="desc", limit=1)
    except Exception:  # an unreadable history makes no claim
        return []
    if not previous:
        return []
    last = previous[0].completed_at or previous[0].updated_at or previous[0].created_at
    return [row for row in agent_changelog.entries(goal.domain, limit=50) if last < row["ts"] <= started][:3]


def answer_facts(world, goal, withheld: frozenset[str] = frozenset(), *, request=None) -> dict:
    """Available recorded history and check evidence for this exact saved answer.

    A dated change list does not prove the exact instructions or model used.
    Only a matching completed native run may carry its check/backup events.
    """
    empty = {"answer_check": None, "answer_agent": None, "answer_fallback": False}
    if getattr(goal, "status", "") != "done" or not getattr(goal, "result", ""):
        return empty
    from . import agent_changelog
    from .auth import assert_goal_access, require_permission

    if request is not None:
        require_permission(request, "view")
        assert_goal_access(request, goal)
    run = _matching_run(world, goal)
    try:
        events = _recent_events(world, goal.id) if run is not None else []
    except Exception:  # an unreadable record never becomes a "checked" claim
        events = []
    if run is not None:
        # Episodes do not retain event-ID boundaries. An event with the exact
        # start/end timestamp may be just outside the run on a coarse clock;
        # ambiguous evidence cannot establish that this answer was checked.
        events = [event for event in events if (stamp := _number(getattr(event, "ts", None))) is not None
                  and run[1] < stamp < run[2]]
    try:
        label = agent_changelog.version_label(goal.domain or "", answered_at=run[1] if run else None)
    except Exception:  # history is optional and never proof of a version
        label = None
    if label is not None:
        from .plain_labels import datetime_text

        label["updated_text"] = datetime_text(label["updated_at"], date_only=True) if label["updated_at"] else ""
        label["update_label"] = "last recorded change before this run" if run else "latest recorded change"
        label["history_note"] = ("Available recorded agent history. It does not identify the exact instructions or AI model used for this answer."
                                 if run else "Available recorded agent history. A matching completed run for this saved answer is unavailable.")
        label["since_last_use"] = _since_last_use(world, goal, run[1]) if run and goal.domain else []
        for row in (*label["changes"], *label["changed_since"], *label["since_last_use"]):
            row["date_text"] = datetime_text(row["ts"], date_only=True)
    # Recheck the caller and exact native source after history/event reads.
    fresh = world.get_goal(goal.id)
    if fresh is None:
        return empty
    if request is not None:
        require_permission(request, "view")
        assert_goal_access(request, fresh)
    if _identity(fresh) != _identity(goal):
        return empty
    latest = _matching_run(world, fresh)
    if run is not None and (latest is None or any(latest[0][key] != run[0][key]
                                                for key in ("id", "started_at", "ended_at", "summary"))):
        run, events = None, []
        label = None
    check = verification(events, withheld) if run else {"state": "not_recorded", "label": LABELS["not_recorded"], "reason": NO_RECORD}
    if request is not None:
        from .usage_measures_api import note_first_result
        note_first_result(request, fresh)
    return {"answer_check": check, "answer_agent": label, "answer_fallback": used_backup_model(events) if run else False}


__all__ = ["CHECKED", "FALLBACK", "HIDDEN", "LABELS", "NOT_SENT", "answer_facts",
           "used_backup_model", "verification"]
