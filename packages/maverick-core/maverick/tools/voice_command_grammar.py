"""Voice command grammar.

A tiny, deterministic intent parser for the voice channel: the operator
declares a grammar of command templates with ``{slot}`` placeholders, and an
incoming (already-transcribed) utterance is matched to an intent + filled
slots. No model call — the point is a fast, predictable mapping for the
high-frequency commands ("pause goal 12", "set budget to 5 dollars") so they
don't round-trip through the LLM.

ops:
  - parse(grammar, utterance)  — grammar: [{intent, pattern}] where pattern is
    free text with {slot} placeholders. Returns the first matching intent and
    its slot values, or "NO MATCH".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from . import Tool

_SLOT = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
_WS = re.compile(r"\s+")
_MAX_RULES = 64
_MAX_PATTERN_LEN = 512
_MAX_UTTERANCE_LEN = 2048
_MAX_SLOTS = 16


@dataclass(frozen=True)
class _Template:
    """A parsed command template that can be matched without backtracking regex."""

    literals: list[str]
    slots: list[str]


def _normalize(text: str) -> str:
    return _WS.sub(" ", text.strip())


def _compile(pattern: str) -> _Template | None:
    """Turn a '{slot}' template into a linear-time matcher description."""
    if len(pattern) > _MAX_PATTERN_LEN:
        return None

    slots: list[str] = []
    literals: list[str] = []
    last = 0
    for m in _SLOT.finditer(pattern):
        literal = _normalize(pattern[last : m.start()]).lower()
        if slots and not literal:
            return None  # adjacent slots are ambiguous and risk expensive matching
        literals.append(literal)
        name = m.group(1)
        if name in slots or len(slots) >= _MAX_SLOTS:
            return None  # duplicate/excess slot name -> invalid grammar
        slots.append(name)
        last = m.end()
    literals.append(_normalize(pattern[last:]).lower())
    return _Template(literals=literals, slots=slots)


def _fold(text: str) -> tuple[str, list[int]]:
    """Lowercase ``text`` while tracking, for every folded-char index, the index
    of the source char in the original ``text``.

    ``str.lower()`` can change length (e.g. Turkish 'İ' -> 2 codepoints), so a
    folded index does not map 1:1 onto ``text``. Matching runs on ``folded`` (so
    indices stay aligned to the lowercased string), but slot VALUES are sliced
    from ``text`` via this map so a proper noun like "John Smith" is returned
    with its original case instead of case-folded to "john smith". The map has a
    trailing sentinel == ``len(text)`` so an end-of-string slice maps cleanly.
    """
    folded_parts: list[str] = []
    fold_map: list[int] = []
    for i, ch in enumerate(text):
        low = ch.lower()
        folded_parts.append(low)
        fold_map.extend([i] * len(low))
    fold_map.append(len(text))
    return "".join(folded_parts), fold_map


def _match(template: _Template, text: str) -> dict[str, str] | None:
    """Match a normalized utterance against a template in linear-ish time."""
    folded, fold_map = _fold(text)
    literals = template.literals
    slots = template.slots
    if not slots:
        return {} if folded == literals[0] else None

    pos = 0
    captures: dict[str, str] = {}
    first = literals[0]
    if first:
        if not folded.startswith(first):
            return None
        pos = len(first)

    for idx, slot in enumerate(slots):
        next_lit = literals[idx + 1]
        # Indices are computed on ``folded`` (length-safe), but the captured
        # value is sliced from ``text`` via ``fold_map`` so its original case is
        # preserved; surrounding whitespace folds 1:1 so ``strip()`` is equivalent.
        if next_lit:
            end = folded.find(next_lit, pos)
            if end < 0:
                return None
            value = text[fold_map[pos]:fold_map[end]].strip()
            pos = end + len(next_lit)
        else:
            value = text[fold_map[pos]:].strip()
            pos = len(folded)
        if not value:
            return None
        captures[slot] = value

    return captures if pos == len(folded) else None


def _parse(args: dict[str, Any]) -> str:
    grammar = args.get("grammar")
    utterance = args.get("utterance")
    if not isinstance(grammar, list) or not grammar:
        return "ERROR: grammar must be a non-empty array of {intent, pattern}"
    if len(grammar) > _MAX_RULES:
        return f"ERROR: grammar must have at most {_MAX_RULES} rules"
    if not isinstance(utterance, str) or not utterance.strip():
        return "ERROR: utterance must be a non-empty string"
    if len(utterance) > _MAX_UTTERANCE_LEN:
        return f"ERROR: utterance must be at most {_MAX_UTTERANCE_LEN} characters"
    text = _normalize(utterance)

    for rule in grammar:
        if not isinstance(rule, dict) or "intent" not in rule or "pattern" not in rule:
            return "ERROR: each grammar rule needs 'intent' and 'pattern'"
        compiled = _compile(str(rule["pattern"]))
        if compiled is None:
            return f"ERROR: invalid pattern {rule['pattern']!r}"
        slots = _match(compiled, text)
        if slots is not None:
            lines = [f"intent: {rule['intent']}"]
            if slots:
                filled = ", ".join(f"{s}={slots[s]}" for s in compiled.slots)
                lines.append(f"slots: {filled}")
            return "\n".join(lines)
    return "NO MATCH"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op", "parse")
    if op != "parse":
        return f"ERROR: unknown op {op!r}"
    return _parse(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["parse"]},
        "grammar": {
            "type": "array",
            "description": "command templates: [{intent, pattern}] with {slot} placeholders",
            "items": {
                "type": "object",
                "properties": {
                    "intent": {"type": "string"},
                    "pattern": {"type": "string"},
                },
                "required": ["intent", "pattern"],
            },
        },
        "utterance": {"type": "string", "description": "transcribed utterance to match"},
    },
    "required": ["grammar", "utterance"],
}


def voice_command_grammar() -> Tool:
    return Tool(
        name="voice_command_grammar",
        description=(
            "Match a transcribed utterance to a command intent + slots. "
            "op=parse with 'grammar' ([{intent, pattern}], patterns use {slot} "
            "placeholders) and an 'utterance'. Returns the first matching "
            "intent and its slot values, or NO MATCH. Deterministic; no model."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
