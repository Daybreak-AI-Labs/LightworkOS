"""Human-correction ingestion: a user's "no, that's wrong" is a lesson.

When a conversation turn that spawns a goal reads as a correction of the
assistant's previous answer, persist it as a reflexion (failure_class
``user_correction``) so the next similar goal verifies before answering the
same way — and the dreaming loop can consolidate repeated corrections into a
department insight.

Detection is a deterministic phrase match over the LATEST user turn only (the
message that triggered the current run), so each correction is recorded at
most once and no LLM ever classifies user text into persisted memory. Scoped
to the conversation's channel/user like every reflexion. Off unless
``[reflexion]`` is enabled; fail-open everywhere.
"""
from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger(__name__)

# Conservative phrasing only: each pattern is an explicit correction of a
# prior answer, not mere disagreement with the world. False negatives are
# fine (we just learn less); false positives poison recall.
_CORRECTION_RE = re.compile(
    r"(?:\bthat(?:'s| is| was)?\s+(?:wrong|incorrect|not right)\b"
    r"|\bnot what i asked\b"
    r"|\byou (?:got|did) (?:it|that|this) wrong\b"
    r"|\bwrong answer\b"
    r"|\bthat(?:'s| is)? not correct\b"
    r"|\bthat did(?:n't| not) work\b"
    r"|\bstill (?:wrong|broken|fails|failing)\b"
    r"|\bredo (?:it|that|this)\b)",
    re.IGNORECASE,
)


def detect_correction(turns: list[Any]) -> tuple[str, str] | None:
    """Return ``(correction_text, prior_answer)`` when the newest turn is a
    user correction of an earlier assistant answer, else ``None``.

    ``turns`` is newest-first (``world.recent_turns`` order), each item
    carrying ``role`` and ``content``. Pure and deterministic for testing.
    """
    if not turns:
        return None
    newest = turns[0]
    if getattr(newest, "role", "") != "user":
        return None
    text = str(getattr(newest, "content", "") or "")
    if not _CORRECTION_RE.search(text):
        return None
    for prior in turns[1:]:
        if getattr(prior, "role", "") == "assistant":
            return text, str(getattr(prior, "content", "") or "")
    return None


def maybe_record_correction(
    world: Any, conversation_id: int | None, goal: Any, *,
    shield: Any | None = None, channel: str | None = None,
    user_id: str | None = None, domain: str | None = None,
) -> bool:
    """Record a ``user_correction`` reflexion for this run's conversation.

    Returns True when a correction was detected AND recorded. Never raises
    into the run.
    """
    if conversation_id is None:
        return False
    try:
        from . import reflexion
        if not reflexion.enabled():
            return False
        turns = world.recent_turns(conversation_id, limit=6)
        # recent_turns may return oldest-first; normalize to newest-first.
        if len(turns) >= 2 and getattr(turns[0], "ts", 0) <= getattr(turns[-1], "ts", 0):
            turns = list(reversed(turns))
        hit = detect_correction(turns)
        if hit is None:
            return False
        correction, prior_answer = hit
        safe_correction = reflexion._sanitize_text(correction, shield=shield)[:200]
        safe_prior = reflexion._sanitize_text(prior_answer, shield=shield)[:200]
        return reflexion.record(
            goal_text=reflexion._sanitize_text(
                f"{getattr(goal, 'title', '')}\n{getattr(goal, 'description', '') or ''}",
                shield=shield,
            )[:500],
            failure_class="user_correction",
            failure_msg=f"user corrected the prior answer: {safe_correction}",
            reflection=(
                "The user rejected a previous answer on this conversation "
                f"(answer began: {safe_prior!r}). Verify the result before "
                "presenting it, and address the correction explicitly."
            ),
            channel=channel, user_id=user_id, domain=domain,
        )
    except Exception as e:  # pragma: no cover -- ingestion never blocks a run
        log.debug("correction ingestion skipped: %s", e)
        return False


__all__ = ["detect_correction", "maybe_record_correction"]
