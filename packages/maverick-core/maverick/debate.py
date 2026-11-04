"""Debate protocol primitive.

Two (or more) agents argue toward consensus on a question. A judge
agent reads the transcript and picks a winner or pronounces a draw.

Built on top of ``maverick.agent_bus`` for inter-agent messaging.
Round-robin turns; configurable round cap.

This is the topology helper — wiring into actual sub-agents is the
orchestrator's call. The function below works against any objects
that expose a ``.complete(system, messages, ...)`` method, so plain
LLM instances or full Agent objects both fit.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .budget import Budget, BudgetExceeded

log = logging.getLogger(__name__)


_JUDGE_SYSTEM = (
    "You are an impartial judge for a debate. Read the transcript "
    "and decide who won. Reply with STRICT JSON: "
    "{\"winner\": \"<participant-name-or-draw>\", "
    "\"reason\": \"<short>\", \"key_argument\": \"<short>\"}."
)


@dataclass
class DebateTurn:
    speaker: str
    text: str


@dataclass
class DebateResult:
    transcript: list[DebateTurn]
    winner: str           # participant name or "draw"
    judge_reason: str
    key_argument: str
    rounds_completed: int
    total_dollars: float


@dataclass
class DebateParticipant:
    """One side of the debate.

    ``persona`` is a one-sentence stance the agent should defend.
    ``llm_complete`` is a callable matching LLM.complete's signature
    (system, messages, ..., budget=..., max_tokens=..., model=...).
    """
    name: str
    persona: str
    llm_complete: Callable[..., Any]
    model: str | None = None


# Sliding transcript window per speaker turn. Without it every speaker
# received the FULL growing transcript each round — O((P·R)^2) input tokens
# over a debate. Late turns argue against the recent exchange anyway; the
# judge still sees the whole transcript once at the end.
_TRANSCRIPT_WINDOW_TURNS = 8


def _build_messages_for_turn(
    question: str, transcript: list[DebateTurn], speaker: str, persona: str,
) -> list[dict]:
    """Render the running transcript as the next speaker's user message."""
    window = transcript[-_TRANSCRIPT_WINDOW_TURNS:]
    elided = len(transcript) - len(window)
    prior = "\n\n".join(
        f"[{t.speaker}]\n{t.text}" for t in window
    ) or "(opening turn — no prior arguments yet)"
    if elided > 0:
        prior = f"({elided} earlier turn(s) elided)\n\n" + prior
    return [{
        "role": "user",
        "content": (
            f"QUESTION:\n{question}\n\n"
            f"YOUR ROLE: {speaker} — defend the position: {persona}\n\n"
            f"TRANSCRIPT SO FAR:\n{prior}\n\n"
            "Your turn. Be specific. 3-6 sentences."
        ),
    }]


def _ask(
    p: DebateParticipant, question: str, transcript: list[DebateTurn],
    *, budget: Budget, max_tokens: int = 400,
) -> str:
    msgs = _build_messages_for_turn(question, transcript, p.name, p.persona)
    resp = p.llm_complete(
        system=(
            "You are a debater. Stay in role. Argue for your assigned "
            "position. Concede gracefully if the other side is right."
        ),
        messages=msgs,
        budget=budget,
        max_tokens=max_tokens,
        model=p.model,
    )
    return (resp.text or "").strip()


def _judge(
    judge_complete: Callable[..., Any],
    question: str,
    transcript: list[DebateTurn],
    participants: list[str],
    *,
    budget: Budget,
    model: str | None,
) -> tuple[str, str, str]:
    import json
    convo = "\n\n".join(f"[{t.speaker}]\n{t.text}" for t in transcript)
    prompt = (
        f"QUESTION:\n{question}\n\n"
        f"DEBATERS:\n{', '.join(participants)}\n\n"
        f"TRANSCRIPT:\n\n{convo}\n\n"
        "Pick a winner (one of the debater names) or write 'draw'. "
        "Reply with the JSON object only."
    )
    resp = judge_complete(
        system=_JUDGE_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
        budget=budget, max_tokens=300, model=model,
    )
    raw = (resp.text or "").strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        raw = raw.removeprefix("json")
        raw = raw.strip()
    try:
        data = json.loads(raw)
        winner = str(data.get("winner") or "draw")
        reason = str(data.get("reason") or "")
        key_arg = str(data.get("key_argument") or "")
    except (ValueError, TypeError, json.JSONDecodeError) as e:
        log.warning("debate judge returned malformed JSON: %s", e)
        winner = "draw"
        reason = "judge JSON parse failed"
        key_arg = ""
    if winner not in participants and winner.lower() != "draw":
        winner = "draw"
    return winner, reason, key_arg


def run_debate(
    question: str,
    participants: list[DebateParticipant],
    *,
    judge_complete: Callable[..., Any],
    rounds: int = 2,
    budget: Budget | None = None,
    judge_model: str | None = None,
) -> DebateResult:
    """Round-robin debate with N participants for N_ROUNDS rounds.

    Each round: every participant speaks once in declared order. The
    judge runs after the final round. Returns the full transcript +
    judge's verdict.
    """
    if len(participants) < 2:
        raise ValueError("debate requires at least 2 participants")
    if rounds < 1:
        raise ValueError("rounds must be >= 1")
    if budget is None:
        from .budget import budget_from_config
        budget = budget_from_config()
    start_dollars = budget.dollars

    transcript: list[DebateTurn] = []
    rounds_completed = 0
    for r in range(rounds):
        for p in participants:
            try:
                text = _ask(p, question, transcript, budget=budget)
            except BudgetExceeded:
                raise
            except Exception as e:
                log.warning("debate turn (%s) failed: %s", p.name, e)
                text = f"(turn failed: {e})"
            if text:
                transcript.append(DebateTurn(speaker=p.name, text=text))
        rounds_completed = r + 1

    names = [p.name for p in participants]
    winner, reason, key_arg = _judge(
        judge_complete, question, transcript, names,
        budget=budget, model=judge_model,
    )
    return DebateResult(
        transcript=transcript,
        winner=winner,
        judge_reason=reason,
        key_argument=key_arg,
        rounds_completed=rounds_completed,
        total_dollars=budget.dollars - start_dollars,
    )


__all__ = [
    "DebateParticipant",
    "DebateResult",
    "DebateTurn",
    "run_debate",
]
