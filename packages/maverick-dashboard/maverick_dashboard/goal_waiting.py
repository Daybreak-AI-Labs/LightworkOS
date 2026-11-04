"""Whether a blocked goal is waiting for a person's answer.

A goal the agent parked with ``ask_user`` is stored as ``blocked`` with an
unanswered question; a goal that stopped for any other reason (a provider
failure, a policy refusal, a spending limit) is ``blocked`` too. Only the
question queue tells the two apart, so the REST API reads it from there rather
than guessing from the result text. A goal that is waiting is not finished:
answering the question lets it carry on.

Known limit: an open question is the only signal there is. A goal that asked,
was continued without an answer and then stopped for another reason still has
its question open and so still reads as waiting; a stored blocked-reason would
settle that, and does not exist yet.
"""
from __future__ import annotations

from typing import Any


def open_question_ids(world: Any, goal: Any) -> list[int]:
    """Ids of the unanswered questions of ``goal``, oldest first, when it is
    blocked; ``[]`` for any other status (no lookup is made for those)."""
    if goal.status != "blocked":
        return []
    return [int(question.id) for question in world.open_questions(goal_id=int(goal.id))]
