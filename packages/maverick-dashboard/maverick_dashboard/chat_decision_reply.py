"""A chat reply to a task that is waiting on a decision.

The task page asks for the choice on the Approvals page, but people answer in
the chat box: "1" there used to start a new task that saw only "1". A reply
that is nothing but one option (its number or its label) now answers the
decision through the Approvals page's own path (:func:`decision_requests_api.
answer_for_request`, the same authorization rule) and resumes the task. A
person who may not answer is told so instead. Any other reply starts the next
message as before; when this person may answer, that message is given the
question and its options so it can read the reply.
"""
from __future__ import annotations

from fastapi import BackgroundTasks, HTTPException, Request
from maverick import decision_requests as dr

from . import decision_requests_api as decisions


def _waiting(world, goal_id: int) -> dr.Decision | None:
    dr.expire_due(world, goal_id=goal_id)
    found = dr.open_for_goal(world, goal_id)
    return found[0] if len(found) == 1 else None


def answer(request: Request, background: BackgroundTasks, world, goal_id: int, message: str) -> bool:
    """Answer the task's one waiting decision when ``message`` picks an option.

    Returns True when the reply was recorded as the answer. Raises 403 or 409
    with the reason when this person may not answer it."""
    decision = _waiting(world, goal_id)
    option = dr.option_from_reply(decision, message) if decision is not None else None
    if option is None:
        return False
    reason, sentence = dr.refusal(decision, decisions.actor(request), is_admin=decisions.is_admin(request))
    if reason:
        raise HTTPException(403, f"{sentence} Your message was not sent; the task is still waiting.")
    outcome = decisions.answer_for_request(request, decision.id, option, world=world)
    if outcome["resume"]:
        decisions.resume(background, world, decision.goal_id)
    return True


def context(request: Request, world, goal_id: int) -> str:
    """The waiting question for the next message, when this person may answer it."""
    decision = _waiting(world, goal_id)
    if decision is None:
        return ""
    reason, _ = dr.refusal(decision, decisions.actor(request), is_admin=decisions.is_admin(request))
    return "" if reason else dr.reply_context(decision)
