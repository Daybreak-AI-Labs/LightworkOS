"""Keep kernel stop text out of the customer-facing conversation history."""
from __future__ import annotations

from dataclasses import asdict

from maverick.stop_reasons import stop_payload


def stop_notes(world, turns) -> dict[int, dict]:
    goals = {}
    copied_cutoffs = {}
    notes = {}
    for turn in turns:
        if turn.role != "assistant":
            continue
        if turn.goal_id not in goals:
            goals[turn.goal_id] = world.get_goal(turn.goal_id)
        goal = goals[turn.goal_id]
        if turn.goal_id not in copied_cutoffs:
            from maverick.attachment_submissions import SubmissionStore
            from maverick.chat_threads import ChatThreads

            receipt = SubmissionStore(world).for_goal(turn.goal_id)
            copied = receipt and receipt["detail"].get("kind") in {"chat_alternative_answer", "chat_alternative_work"}
            copied_cutoffs[turn.goal_id] = (max((row.id for row in ChatThreads(world).selected_turns(turn.goal_id)
                if row.role == "user"), default=0) if copied else 0)
        if turn.id < copied_cutoffs[turn.goal_id]:
            # These answers predate this new attempt. Its stop cannot rewrite
            # the immutable messages the person explicitly copied and reviewed.
            continue
        # A concurrent deletion must not fall back to the unscreened turn text.
        stop = (stop_payload(goal.status, goal.result) if goal is not None
                else stop_payload("failed", None))
        if stop:
            notes[turn.id] = stop
    return notes


def public_turns(world, turns) -> list[dict]:
    notes = stop_notes(world, turns)
    result = []
    for turn in turns:
        public = asdict(turn)
        stop = notes.get(turn.id)
        if stop:
            public["content"] = f"{stop['message']}\n\n{stop['action']}"
            public["stop"] = stop
        result.append(public)
    return result
