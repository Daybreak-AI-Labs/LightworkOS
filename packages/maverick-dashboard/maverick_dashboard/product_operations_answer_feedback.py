"""Copilot opens the exact authorized answer's ordinary private feedback form."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import answer_feedback_operations as native
from . import task_signoff_operations
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, selection):
    goal_id = task_signoff_operations.selected(selection)
    native.write_authority(request, goal_id)
    current = native.read(request, goal_id)
    feedback = current["feedback"]
    details = {"Task": current["task"], "Saved feedback": "Useful" if feedback and feedback["rating"] == "up" else
               "Needs improvement" if feedback else "None recorded",
               "Answer": "Earlier feedback: the answer version was not recorded" if feedback and feedback["legacy"] else
               "Current saved answer" if not feedback or feedback["current_result"] else "Feedback on an earlier answer",
               "Next step": {"label": "Review the answer and give feedback", "href": f"/chat/goal/{goal_id}#feedback"}}
    # Private feedback text stays in its native form, never in guide history.
    return Snapshot(digest([current["context"], current["revision"], feedback]), "Current saved answer feedback",
                    "Review the saved answer and add an optional note about what should be better.", details,
                    blocked="Wait for a saved result before giving feedback." if not current["eligible"] else "")


def prepare(request, selection, _arguments):
    state = snapshot(request, selection)
    if state.blocked:
        raise HTTPException(409, state.blocked)
    return Preview("Open the answer's feedback form. Nothing is saved until you choose a rating and confirm there.")


def entries():
    return (Adapter("reviews.answer_feedback", "Give feedback on this answer", "reviews", "/chat",
                    ("/chat/goal/*", "/goals/*"), EmptyInput, snapshot, prepare,
                    aliases=("give answer feedback", "this answer needs improvement", "explain what was wrong")),)
