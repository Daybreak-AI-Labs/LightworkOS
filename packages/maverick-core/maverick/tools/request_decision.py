"""Ask a person to decide between options, then pause until they answer.

The agent files a decision request (:mod:`maverick.decision_requests`) and the
run pauses: the agent loop ends the turn as blocked, the goal waits as
``blocked`` and spends nothing. When a person chooses an option the run starts
again and finds the choice in its brief as a structured record.

Unlike ``ask_user`` this never auto-continues in a headless run: nobody picks
the recommendation for the person. An unanswered decision expires and stops
the run.
"""
from __future__ import annotations

from . import Tool


def request_decision(world, goal_id: int | None = None) -> Tool:
    """Build the tool, scoped to the running goal."""
    from .. import decision_requests as dr

    def fn(args: dict) -> str:
        if goal_id is None:
            return "ERROR: a decision request needs a task; ask in plain text instead."
        try:
            values = dr.validate(args)
        except ValueError as exc:
            return f"ERROR: {exc}. Fix the request and call request_decision again."
        try:
            decision = dr.request(world, goal_id, **values)
        except dr.DecisionRecordError as exc:
            return f"{dr.NOT_RECORDED}: {exc}."
        return (
            f"WAITING for decision #{decision.id}. The run pauses now until a person "
            "chooses an option. Do not act on any option before the answer arrives."
        )

    chosen = dr.areas()
    return Tool(
        name="request_decision",
        description=(
            "Ask a person to choose between options before you act, then pause. "
            "Use it for a judgment call you should not make alone. "
            + dr.rules_text(chosen)
            + " The person's choice comes back to you as a structured record when "
            "the run continues. If nobody answers in time the run stops."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "question": {"type": "string", "description": "The decision, in plain words."},
                "options": {
                    "type": "array", "minItems": dr.MIN_OPTIONS, "maxItems": dr.MAX_OPTIONS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "label": {"type": "string", "description": "A short name for the option."},
                            "effect": {"type": "string",
                                       "description": "What happens if this option is chosen."},
                        },
                        "required": ["label", "effect"],
                    },
                },
                "recommended": {"type": "integer", "minimum": 1, "maximum": dr.MAX_OPTIONS,
                                "description": "The number of the option you recommend (1 is the first)."},
                "why": {"type": "string", "description": "Why you recommend that option."},
                "area": {"type": "string", "enum": [*dr.AREAS, dr.OTHER_AREA],
                         "description": "What the choice concerns."},
            },
            "required": ["question", "options", "recommended", "why", "area"],
        },
        fn=fn,
    )
