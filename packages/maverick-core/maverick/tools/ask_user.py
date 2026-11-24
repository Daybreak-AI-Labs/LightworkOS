"""Async question-to-user tool.

The agent queues a question into the world model and gets a sentinel back.
The orchestrator decides whether to keep going (with other independent
sub-tasks) or pause. The user answers later via `maverick answer`.
"""
from __future__ import annotations

import re

from . import Tool

#: The start of the result when a question was queued and the run may wait.
QUEUED = "QUEUED question #"
# A question that states the agent's own recommendation or what it will do
# without an answer. A business-plan task asked "conservative, base-case or
# aggressive? I recommend base-case ... otherwise I'll use reasonable
# assumptions" and then waited for the person; such a question is the
# agent's to settle.
_OWN_ANSWER = re.compile(
    r"\bI(?:'d| would)? (?:recommend|suggest)\b|\b(?:otherwise|if not|by default),? I(?:'ll| will)\b",
    re.IGNORECASE)


def ask_user(world, goal_id: int | None = None) -> Tool:
    """Build the ask_user tool, scoped to a goal so /goals/<id> can list
    its open questions and `maverick answer` resolves them correctly."""

    def fn(args: dict) -> str:
        question = str(args.get("question") or "").strip()
        if not question:
            return "ERROR: ask_user needs a 'question'."
        if _OWN_ANSWER.search(question):
            return ("NOT ASKED: your question already says what you would choose or do without an "
                    "answer, so it is yours to settle. Go ahead on that basis, say which assumption "
                    "you made in your answer, and the person can change it with a follow-up. Nothing "
                    "was sent to them.")
        qid = world.ask(question, goal_id=goal_id)
        return (
            f"{QUEUED}{qid}. The user will answer asynchronously. "
            "Continue with independent work if possible; otherwise pause."
        )

    return Tool(
        name="ask_user",
        description=(
            "Queue a question for the user. They will answer asynchronously. "
            "Use sparingly and batch related questions into one. Prefer doing "
            "independent work first; only ask when truly blocked, for facts only "
            "the person has. A question that recommends an option or says what "
            "you will do without an answer is not sent: make that choice yourself."
        ),
        input_schema={
            "type": "object",
            "properties": {"question": {"type": "string"}},
            "required": ["question"],
        },
        fn=fn,
    )
