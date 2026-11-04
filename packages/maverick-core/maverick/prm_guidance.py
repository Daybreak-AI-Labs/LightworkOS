"""Make the process-reward model *steer*, not just observe.

``maverick.prm`` scores every step's promise/progress, but today the loop only
posts those scores to the blackboard -- a reward model that rewards nothing.
This module is the consumer: given the recent promise scores, decide whether to
nudge the agent to change course (it's been on an unpromising track for a
streak of steps) and what to say. The nudge is a trusted control signal the
agent loop appends to the conversation, exactly like the loop-guard note.

Pure and deterministic so it's trivially testable. ON by default (env
``MAVERICK_PRM_GUIDANCE`` / ``[self_improvement] prm_guidance``); when disabled,
:func:`maybe_nudge` returns None and the loop is byte-identical to today.
"""
from __future__ import annotations

from collections import deque

_LOW_PROMISE = 0.35   # at/below this, a step looks unpromising
_STREAK = 3           # consecutive low steps before we intervene


def enabled() -> bool:
    """Whether PRM guidance may steer the loop. ON by default, fail-closed."""
    try:
        from .config import get_self_improvement, governed_learning_env_flag
        override = governed_learning_env_flag("MAVERICK_PRM_GUIDANCE")
        if override is not None:
            return override
        return bool(get_self_improvement().get("prm_guidance", True))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def should_nudge(promises, *, low: float = _LOW_PROMISE, streak: int = _STREAK) -> bool:
    """True when the last ``streak`` promise scores are all at/below ``low``."""
    recent = list(promises)[-streak:]
    if len(recent) < streak:
        return False
    return all((p is not None and p <= low) for p in recent)


def nudge_text(streak: int = _STREAK) -> str:
    return (
        f"[process-reward] The last {streak} steps have made little progress "
        "toward the goal. Step back: re-read the sub-goal, consider whether the "
        "current approach is wrong, and either change strategy or move to your "
        "FINAL answer rather than continuing down this path."
    )


def maybe_nudge(promises, *, low: float = _LOW_PROMISE, streak: int = _STREAK) -> str | None:
    """Return a nudge string if PRM guidance is on and the track is unpromising."""
    if not enabled():
        return None
    if should_nudge(promises, low=low, streak=streak):
        return nudge_text(streak)
    return None


class PromiseWindow:
    """Bounded record of recent step promise scores for one agent."""

    def __init__(self, maxlen: int = 8) -> None:
        self._d: deque[float] = deque(maxlen=maxlen)

    def push(self, promise: float | None) -> None:
        if promise is not None:
            self._d.append(float(promise))

    def values(self) -> list[float]:
        return list(self._d)


__all__ = ["enabled", "should_nudge", "nudge_text", "maybe_nudge", "PromiseWindow"]
