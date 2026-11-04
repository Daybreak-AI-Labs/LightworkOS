"""Conversational supervisor — natural-language supervision of running work.

Parse short operator utterances ("what's running?", "how much have we spent
today?", "pause goal five", "what failed?", "prioritize the deploy goal") into
intents via a deterministic grammar (the same ``{slot}`` template compiler the
``voice_command_grammar`` tool uses — no model call on the hot path), answer
read intents from the world model + usage ledger, and route mutating intents
through a strict confirm gate.

Honesty notes (read before extending):

* **Pause / resume / priority are not first-class world-model concepts.**
  The goals table has ``status`` (pending/active/blocked/done/cancelled) and
  no priority column. Pause is therefore implemented as
  ``set_goal_status(id, "blocked")`` plus a supervision ``goal_event``; resume
  flips a blocked goal back to ``"pending"``; prioritize records a
  ``goal:<id>:priority`` fact via ``upsert_fact`` plus a supervision event.
  All of those are real, existing ``WorldModel`` methods — nothing here calls
  into machinery that does not exist.
* **"Failed" means status ``blocked``** — that is the vocabulary the
  orchestrator actually writes for a run that stopped without finishing.
* **The optional LLM seam never mutates.** When the grammar misses, an
  injected ``llm(utterance) -> str`` callable may map a paraphrase to one of
  the canonical phrases; the suggestion is re-parsed through the SAME grammar.
  A suggestion that parses to a *read* intent is answered (labelled as
  interpreted); a suggestion that parses to a *mutating* intent is never
  executed — the supervisor replies with the canonical phrase to say
  explicitly. An LLM failure or unparseable suggestion yields the honest
  "didn't understand, try: ..." help, never a guess.
* **Mutations fail closed.** Every mutating intent calls the injected
  ``confirm(description)`` seam and only a literal ``True`` (the shared
  ``tools.as_bool`` gate) authorises the change. No confirm seam => refusal.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from .tools import as_bool
from .tools.voice_command_grammar import _compile, _match

log = logging.getLogger(__name__)

# Canonical command templates: (intent, pattern). First match wins, so put
# more specific patterns before broader ones sharing a prefix.
DEFAULT_GRAMMAR: list[tuple[str, str]] = [
    # ----- read intents -----
    ("status", "what's running"),
    ("status", "what is running"),
    ("status", "status report"),
    ("status", "status"),
    ("spend", "how much have we spent today"),
    ("spend", "how much did we spend today"),
    ("spend", "what's the spend today"),
    ("spend", "spend report"),
    ("failures", "what failed"),
    ("failures", "show failures"),
    ("failures", "summarize overnight failures"),
    # ----- mutating intents (confirm-gated) -----
    ("pause", "pause goal {goal}"),
    ("resume", "resume goal {goal}"),
    ("cancel", "cancel goal {goal}"),
    ("prioritize", "prioritize goal {goal}"),
    ("prioritize", "prioritize the {title} goal"),
]

MUTATING_INTENTS = frozenset({"pause", "resume", "cancel", "prioritize"})

HELP_TEXT = (
    "Sorry, I didn't understand. Try: 'what's running?', "
    "'how much have we spent today?', 'what failed?', 'pause goal 5', "
    "'resume goal 5', 'cancel goal 5', or 'prioritize goal 5'."
)

# Spoken goal references arrive as words ("pause goal five"). Deterministic
# small-number table; anything else must be digits.
_WORD_NUMBERS = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
    "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
    "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19,
    "twenty": 20,
}

# Goal ids are SQLite rowids, so valid numeric references fit in signed 64-bit.
# Bound digit strings before int() to avoid conversion-limit crashes and CPU churn.
MAX_GOAL_REF_DIGITS = 19


def _normalize(utterance: str) -> str:
    """Collapse whitespace and strip trailing sentence punctuation."""
    return " ".join((utterance or "").split()).rstrip("?!. ")


def parse_utterance(
    utterance: str,
    grammar: list[tuple[str, str]] | None = None,
) -> tuple[str, dict[str, str]] | None:
    """Match an utterance against the grammar; ``(intent, slots)`` or None.

    Deterministic: reuses the ``voice_command_grammar`` template compiler
    (case-insensitive, whitespace-loose, anchored). No model call.
    """
    text = _normalize(utterance)
    if not text:
        return None
    for intent, pattern in (grammar if grammar is not None else DEFAULT_GRAMMAR):
        compiled = _compile(pattern)
        if compiled is None:
            raise ValueError(f"duplicate slot in grammar pattern {pattern!r}")
        captures = _match(compiled, text)
        if captures is not None:
            return intent, captures
    return None


def resolve_goal_ref(ref: str) -> int | None:
    """A spoken goal reference ("5", "five", "#5") -> goal id, or None."""
    token = (ref or "").strip().lower().lstrip("#")
    if token.isdigit():
        if len(token) > MAX_GOAL_REF_DIGITS:
            return None
        try:
            return int(token)
        except (OverflowError, ValueError):
            return None
    return _WORD_NUMBERS.get(token)


class Supervisor:
    """Answer supervision utterances from the world model + usage ledger.

    ``world`` is a :class:`maverick.world_model.WorldModel` (or compatible).
    ``ledger`` is a :class:`maverick.quotas.UsageLedger`; None = the default
    tenant ledger. ``confirm`` is the mutation gate: called with a description,
    and only a literal ``True`` return authorises the change (``as_bool``,
    fail-closed — no seam means every mutation is refused). ``llm`` is the
    optional paraphrase->canonical-phrase fallback described in the module
    docstring. ``clock`` is injected for deterministic "today" in tests.
    """

    def __init__(
        self,
        world: Any,
        ledger: Any = None,
        *,
        llm: Callable[[str], str] | None = None,
        confirm: Callable[[str], object] | None = None,
        grammar: list[tuple[str, str]] | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.world = world
        self._ledger = ledger
        self.llm = llm
        self.confirm = confirm
        self.grammar = grammar if grammar is not None else DEFAULT_GRAMMAR
        self.clock = clock

    # ----- entry point -----
    def handle(self, utterance: str) -> str:
        parsed = parse_utterance(utterance, self.grammar)
        if parsed is None:
            return self._llm_fallback(utterance)
        intent, slots = parsed
        if intent in MUTATING_INTENTS:
            return self._mutate(intent, slots)
        return self._answer(intent)

    # ----- LLM fallback (never mutates) -----
    def _llm_fallback(self, utterance: str) -> str:
        if self.llm is None:
            return HELP_TEXT
        try:
            suggestion = self.llm(utterance)
        except Exception as e:
            log.warning("supervisor llm fallback failed: %s", e)
            return HELP_TEXT
        if not isinstance(suggestion, str):
            return HELP_TEXT
        parsed = parse_utterance(suggestion, self.grammar)
        if parsed is None:
            return HELP_TEXT
        intent, _slots = parsed
        if intent in MUTATING_INTENTS:
            canonical = _normalize(suggestion)
            return (
                f"That sounds like {canonical!r}, which changes things. "
                "I don't act on guesses — say it explicitly to proceed."
            )
        return f"(interpreted as {_normalize(suggestion)!r}) " + self._answer(intent)

    # ----- read intents: cheap, indexed world/ledger passes -----
    def _answer(self, intent: str) -> str:
        if intent == "status":
            return self._answer_status()
        if intent == "spend":
            return self._answer_spend()
        if intent == "failures":
            return self._answer_failures()
        return HELP_TEXT  # unreachable with DEFAULT_GRAMMAR

    def _answer_status(self) -> str:
        active = self.world.list_goals(status="active", limit=10, order="desc")
        pending = self.world.list_goals(status="pending", limit=100)
        if not active and not pending:
            return "Nothing is running and nothing is queued."
        parts = []
        if active:
            names = "; ".join(f"goal {g.id} '{g.title}'" for g in active)
            parts.append(f"{len(active)} running: {names}")
        else:
            parts.append("Nothing is running")
        if pending:
            parts.append(f"{len(pending)} queued")
        return ". ".join(parts) + "."

    def _today(self) -> str:
        return datetime.fromtimestamp(self.clock(), timezone.utc).strftime("%Y-%m-%d")

    def _answer_spend(self) -> str:
        ledger = self._ledger
        if ledger is None:
            from .quotas import UsageLedger
            ledger = UsageLedger()
        day = self._today()
        # Same intentional read of the persisted tally billing.rate_ledger does.
        data = ledger._load()  # noqa: SLF001
        dollars = 0.0
        tokens = 0
        for days in data.values():
            cell = (days or {}).get(day) or {}
            dollars += float(cell.get("dollars", 0.0))
            tokens += int(cell.get("in_tokens", 0)) + int(cell.get("out_tokens", 0))
        if dollars == 0 and tokens == 0:
            return "No spend recorded today."
        return f"Today's spend is ${dollars:.2f} across {tokens} tokens."

    def _answer_failures(self) -> str:
        blocked = self.world.list_goals(status="blocked", limit=100, order="desc")
        if not blocked:
            return "No failures. Nothing is blocked."
        shown = blocked[:5]
        names = "; ".join(f"goal {g.id} '{g.title}'" for g in shown)
        more = f" (and {len(blocked) - len(shown)} more)" if len(blocked) > len(shown) else ""
        return f"{len(blocked)} failed or blocked: {names}{more}."

    # ----- mutating intents: strict, fail-closed confirm gate -----
    def _mutate(self, intent: str, slots: dict[str, str]) -> str:
        goal, err = self._resolve_target(intent, slots)
        if err:
            return err
        description = f"{intent} goal {goal.id} ('{goal.title}')"
        if self.confirm is None:
            return f"I need confirmation to {description}, and no confirm channel is set up. Nothing changed."
        try:
            verdict = self.confirm(description)
        except Exception as e:
            log.warning("supervisor confirm seam failed: %s", e)
            return f"Confirmation failed; did not {description}. Nothing changed."
        if not as_bool(verdict):
            return f"Not confirmed; did not {description}. Nothing changed."
        return self._apply(intent, goal)

    def _resolve_target(self, intent: str, slots: dict[str, str]):
        """Resolve the {goal}/{title} slot to a Goal. Returns (goal, error)."""
        if "goal" in slots:
            goal_id = resolve_goal_ref(slots["goal"])
            if goal_id is None:
                return None, f"I couldn't read a goal number in {slots['goal']!r}. Nothing changed."
            goal = self.world.get_goal(goal_id)
            if goal is None:
                return None, f"There is no goal {goal_id}. Nothing changed."
            return goal, None
        # Title reference ("prioritize the deploy goal"): only act on an
        # unambiguous match — never guess between candidates.
        title = slots.get("title", "")
        matches = self.world.search_goals(title, limit=2)
        if not matches:
            return None, f"I couldn't find a goal matching {title!r}. Nothing changed."
        if len(matches) > 1:
            opts = "; ".join(f"goal {g.id} '{g.title}'" for g in matches)
            return None, f"More than one goal matches {title!r}: {opts}. Say the goal number. Nothing changed."
        return matches[0], None

    def _apply(self, intent: str, goal: Any) -> str:
        if intent == "pause":
            # Not first-class: pause = status 'blocked' + a supervision event.
            self.world.set_goal_status(goal.id, "blocked")
            self.world.append_event(goal.id, "supervisor", "supervision", "paused by operator")
            return f"Paused goal {goal.id} ('{goal.title}') — set to blocked."
        if intent == "resume":
            if goal.status != "blocked":
                return f"Goal {goal.id} is {goal.status}, not paused/blocked. Nothing changed."
            self.world.set_goal_status(goal.id, "pending")
            self.world.append_event(goal.id, "supervisor", "supervision", "resumed by operator")
            return f"Resumed goal {goal.id} ('{goal.title}') — set to pending."
        if intent == "cancel":
            self.world.set_goal_status(goal.id, "cancelled")
            self.world.append_event(goal.id, "supervisor", "supervision", "cancelled by operator")
            return f"Cancelled goal {goal.id} ('{goal.title}')."
        if intent == "prioritize":
            # No priority column exists: record it as a fact + an event.
            from .fact_revision import FactConflict
            key = f"goal:{goal.id}:priority"
            current = self.world.fact_record(key)
            try:
                self.world.upsert_fact(key, "high", source="supervisor:operator",
                                       expected_revision=current["revision"] if current else 0)
            except FactConflict:
                return f"Goal {goal.id}'s saved priority changed while handling this request. Review it before trying again; nothing was changed."
            self.world.append_event(goal.id, "supervisor", "supervision", "prioritized by operator")
            return f"Prioritized goal {goal.id} ('{goal.title}') — recorded priority=high."
        return HELP_TEXT  # unreachable with MUTATING_INTENTS


__all__ = [
    "DEFAULT_GRAMMAR",
    "MUTATING_INTENTS",
    "HELP_TEXT",
    "MAX_GOAL_REF_DIGITS",
    "parse_utterance",
    "resolve_goal_ref",
    "Supervisor",
]
