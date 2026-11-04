"""What a stopped task finished, what it had left, and whether it can resume.

The halt card reads this so a person who stops a task (or finds it stopped)
can take over: the planned steps that are done, the ones not done yet, and
whether "Resume" continues from saved progress or "Try again" starts over.
Read-only; nothing here changes the task.
"""
from __future__ import annotations

from .step_narration import narrate

STOPPED = frozenset({"cancelled", "failed", "blocked"})
_SHOWN = 8  # recorded steps listed when the task had no separate plan


def _plan(world, goal_id: int) -> tuple[list[str], list[str]]:
    done, remaining = [], []
    for step in world.subgoals(goal_id):
        title = " ".join(str(step.title or "").split()) or "Untitled step"
        (done if step.status == "done" else remaining).append(title)
    return done, remaining


def _recorded(world, goal_id: int) -> list[str]:
    lines = []
    for event in world.goal_events(goal_id, limit=500):
        text = narrate(event.kind, event.agent, event.content).text
        if text and (not lines or lines[-1] != text):
            lines.append(text)
    return lines


def saved_step(world, goal_id: int) -> int | None:
    """The newest saved progress point, when saving progress is turned on."""
    try:
        from maverick import checkpoint
        if not checkpoint.enabled():
            return None
        store = checkpoint.Checkpointer(world)
        boundary = store.orchestrator_for(goal_id)
        if boundary is None:
            return None
        saved = store.latest(goal_id, boundary[0], episode_id=boundary[1])
        return int(saved.step_seq) if saved is not None else None
    except Exception:  # an unreadable store means "start over", never a guess
        return None


def summarize(world, goal) -> dict | None:
    """Plain progress for a stopped task, or ``None`` while it still runs."""
    if goal is None or goal.status not in STOPPED:
        return None
    done, remaining = _plan(world, goal.id)
    planned = bool(done or remaining)
    recorded = [] if planned else _recorded(world, goal.id)
    if planned:
        total = len(done) + len(remaining)
        headline = ({"text": "Stopped at step {step} of {total}.",
                     "values": {"step": len(done) + 1, "total": total}} if remaining else
                    {"text": "All {total} planned steps were done before it stopped.",
                     "values": {"total": total}})
    elif recorded:
        headline = {"text": "Stopped after {count} recorded steps." if len(recorded) != 1
                    else "Stopped after {count} recorded step.", "values": {"count": len(recorded)}}
        done = recorded[-_SHOWN:]
    else:
        headline = {"text": "Stopped before any step was finished.", "values": {}}
    step = saved_step(world, goal.id)
    return {
        "headline": headline,
        "done": done,
        "done_hidden": max(0, len(recorded) - _SHOWN),
        "remaining": remaining,
        "remaining_note": "" if planned else "Lightwork had not planned the remaining steps yet.",
        "mode": "resume" if step is not None else "retry",
        "saved_step": step,
        "next": ({"text": "Resume continues from saved step {step}; finished steps are not repeated.",
                  "values": {"step": step}} if step is not None else
                 {"text": "Try again starts the task over. This workspace does not save progress, "
                          "so finished steps run again.", "values": {}}),
    }
