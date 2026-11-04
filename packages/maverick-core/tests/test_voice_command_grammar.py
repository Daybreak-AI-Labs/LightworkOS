"""Tests for the voice_command_grammar tool (maverick.tools.voice_command_grammar)."""
from __future__ import annotations

from maverick.tools.voice_command_grammar import voice_command_grammar

_GRAMMAR = [
    {"intent": "pause", "pattern": "pause goal {id}"},
    {"intent": "set_budget", "pattern": "set budget to {amount} dollars"},
    {"intent": "halt", "pattern": "stop everything"},
]


# ---- voice_command_grammar ----

def test_grammar_slot_extraction():
    t = voice_command_grammar()
    out = t.fn({"grammar": _GRAMMAR, "utterance": "pause goal 12"})
    assert "intent: pause" in out and "slots: id=12" in out


def test_grammar_loose_whitespace_and_case():
    t = voice_command_grammar()
    out = t.fn({"grammar": _GRAMMAR, "utterance": "  SET   budget  to  5  dollars "})
    assert "intent: set_budget" in out and "amount=5" in out


def test_grammar_length_changing_lowercase():
    """A slot value whose str.lower() changes length (Turkish 'İ' -> 2 chars)
    must still match: indices live in the folded coordinate space, so slicing
    and the trailing length check stay aligned instead of tripping NO MATCH."""
    t = voice_command_grammar()
    grammar = [{"intent": "set_name", "pattern": "set name to {name} now"}]
    out = t.fn({"grammar": grammar, "utterance": "set name to İvan now"})
    assert "intent: set_name" in out
    assert "name=" in out and out != "NO MATCH"


def test_grammar_preserves_slot_value_case():
    """A captured slot value keeps its original case (matching is
    case-insensitive, but a proper noun must not be folded to lowercase)."""
    t = voice_command_grammar()
    grammar = [{"intent": "call", "pattern": "call {name}"}]
    out = t.fn({"grammar": grammar, "utterance": "CALL John Smith"})
    assert "intent: call" in out
    assert "name=John Smith" in out


def test_grammar_no_slot_and_no_match():
    t = voice_command_grammar()
    assert "intent: halt" in t.fn({"grammar": _GRAMMAR, "utterance": "stop everything"})
    assert t.fn({"grammar": _GRAMMAR, "utterance": "make me a sandwich"}) == "NO MATCH"


def test_grammar_validation():
    t = voice_command_grammar()
    assert t.fn({"grammar": [], "utterance": "x"}).startswith("ERROR")
    assert t.fn({"grammar": _GRAMMAR, "utterance": "  "}).startswith("ERROR")
    assert t.fn({"grammar": [{"intent": "x", "pattern": "{a} {a}"}], "utterance": "1 2"}).startswith("ERROR")


def test_grammar_rejects_adjacent_slots_without_backtracking():
    t = voice_command_grammar()
    grammar = [{"intent": "bad", "pattern": "{s0}{s1}{s2}{s3}{s4}{s5}{s6}{s7}{s8}{s9}{s10}{s11}X"}]
    out = t.fn({"grammar": grammar, "utterance": "a" * 30})
    assert out.startswith("ERROR: invalid pattern")


def test_grammar_input_limits():
    t = voice_command_grammar()
    assert t.fn({"grammar": _GRAMMAR * 22, "utterance": "pause goal 12"}).startswith("ERROR")
    assert t.fn({"grammar": _GRAMMAR, "utterance": "x" * 2049}).startswith("ERROR")
    assert t.fn({"grammar": [{"intent": "x", "pattern": "x" * 513}], "utterance": "x"}).startswith("ERROR")
