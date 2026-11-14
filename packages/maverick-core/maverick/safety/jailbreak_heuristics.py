"""Heuristic jailbreak / prompt-injection scorer.

Returns a 0..1 score for how much an input looks like a jailbreak.
Pure regex; no ML deps. The real shield does better work; this is
the floor we guarantee even when shield isn't installed.

Each pattern carries a weight. The final score is sigmoid(sum) so
heavy hits dominate but multiple light ones still add up.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class _Pat:
    name: str
    pat: re.Pattern
    weight: float
    # When set, the hit also needs this pattern somewhere after ``pat``'s match.
    # Two linear searches replace a ``pat.*then`` regex, which rescans to the
    # end of the text from every start and is quadratic.
    then: re.Pattern | None = None


_PATTERNS: list[_Pat] = [
    # Keep these conversation-boundary families aligned with the built-in
    # shield. Core must retain this floor when the optional shield is absent.
    _Pat("discard_conversation", re.compile(
        r"\b(?:ignore|disregard|forget|discard)\s+"
        r"(?:everything|all(?:\s+(?:the\s+)?(?:text|content|instructions?))?)\s+"
        r"(?:above|before)(?:\s+(?:this|my|the)\s+(?:line|message|request|prompt))?"
        r"\s*(?=[,.;:!?\n\u2014\u2013]|$|(?:and|then|now|instead)\b)", re.IGNORECASE), 2.0),
    _Pat("configured_directives_leak", re.compile(
        r"\b(?:paste|show|print|repeat|output|quote|dump|share|reveal)\s+"
        r"(?:back\s+)?(?:me\s+)?(?:the\s+|your\s+)?"
        r"(?:directives?|instructions?|rules?|prompt|guidance)\s+"
        r"(?:that\s+)?you\s+were\s+(?:configured|initiali[sz]ed|set\s+up)\s+with\b",
        re.IGNORECASE), 2.0),
    _Pat("cancel_setup_limits", re.compile(
        r"\b(?:treat|consider|regard)\s+(?:the\s+|your\s+)?(?:setup\s+)?"
        r"(?:limits?|constraints?|rules?|instructions?|directives?|guidelines?|guardrails?)\s+"
        r"(?:that\s+)?you\s+(?:started|began)\s+with\s+as\s+(?:now\s+)?"
        r"(?:cancelled|canceled|void|invalid|revoked|inapplicable|nullified)\b",
        re.IGNORECASE), 2.0),
    _Pat("ignore_prior",
         re.compile(
             # The object group is REQUIRED: with every group optional this
             # would fire on benign text like "ignore the spam folder" /
             # "forget about it" (weight 2.0 -> score above the 0.6 threshold),
             # blocking legitimate input.
             r"\b(?:ignore|disregard|forget)\s+(?:all|everything|all\s+of)?\s*"
             r"(?:previous|prior|above|preceding|the|your|you\s+were\s+told)?\s*"
             r"(?:instructions?|prompts?|rules?|guidelines?|directives?|context)",
             re.IGNORECASE,
         ), 2.0),
    _Pat("reveal_system_prompt",
         re.compile(
             r"\b(?:reveal|print|output|show|repeat|tell\s+me|share|disclose|"
             r"give\s+me|what(?:'s|\s+is)|return)\s+(?:the\s+)?(?:contents?\s+of\s+)?"
             r"(?:your|the|exactly)?\s*(?:system\s+|original\s+)?"
             r"(?:prompt|instructions?|training\s+data|guidelines?)\b",
             re.IGNORECASE,
         ), 2.0),
    _Pat("dan_persona",
         re.compile(
             r"\b(?:DAN|developer\s+mode|jail.?broken|jailbreak|"
             r"GPT.?unfiltered|GPT.?Unfiltered|uncensored\s+mode|"
             r"maintenance\s+mode|admin\s+mode|sudo\s+mode|godmode)\b",
             re.IGNORECASE,
         ), 2.0),
    _Pat("be_unrestricted",
         re.compile(
             r"\b(?:no|without|zero)\s+(?:rules?|restrictions?|filters?|"
             r"limits?|constraints?|guidelines?|safety|policies)\b",
             re.IGNORECASE,
         ), 1.5),
    _Pat("pretend_persona",
         re.compile(
             r"\b(?:pretend|roleplay|imagine|act\s+as|you\s+are\s+now|"
             r"you\s+will\s+be|you\s+are)\s+(?:an?\s+|the\s+)?"
             r"(?:AI|model|assistant|bot|agent|hacker|attacker|shell|"
             r"linux|terminal|search\s+engine|translator|character)\b",
             re.IGNORECASE,
         ), 1.0),
    _Pat("admin_override",
         re.compile(
             r"\[(?:ADMIN|SYSTEM|INST|OVERRIDE|SUDO|MAINTENANCE|START|END)"
             r"\b[^\[\]]*\]",
             re.IGNORECASE,
         ), 1.8),
    _Pat("api_key_extraction",
         re.compile(
             r"\b(?:reveal|print|share|output|show|tell|give|return|"
             r"list|extract)\s+(?:me\s+)?(?:the\s+|every\s+|all\s+)?"
             r"(?:api[\s_-]?key|secret|token|password|env(?:ironment)?\s+"
             r"variables?|credentials?|OPENAI_API_KEY|ANTHROPIC_API_KEY|"
             r"flag|/etc/(?:passwd|shadow))",
             re.IGNORECASE,
         ), 2.5),
    _Pat("disable_safety",
         re.compile(
             r"\b(?:disable|override|bypass|turn\s+off|ignore|skip|"
             r"all\s+(?:filters?|restrictions?)\s+(?:are|is)\s+off)\s+"
             r"(?:the\s+)?(?:safety|filter|guidelines?|rules?|policy|"
             r"policies|restrictions?|safeguards?|authentication|"
             r"auth|consent\s+prompts?)",
             re.IGNORECASE,
         ), 2.0),
    _Pat("execute_encoded",
         re.compile(
             r"\b(?:decode|translate|convert)\s+(?:from|to)?\s*"
             r"(?:base64|rot13|hex|binary)\b",
             re.IGNORECASE,
         ), 1.8,
         then=re.compile(r"\b(?:execute|run|act\s+on|process)\b", re.IGNORECASE)),
    _Pat("destructive_shell",
         re.compile(
             r"\brm\s+-rf\s+/(?!tmp)|drop\s+(?:table|database)\b|"
             r"format\s+(?:c:|/)|/etc/(?:passwd|shadow|\*)|"
             r"contents?\s+of\s+(?:every|all)\s+file\s+in\s+/|"
             r"delete\s+(?:all|every|the\s+database)\b",
             re.IGNORECASE,
         ), 1.5),
    _Pat("fictional_framing",
         re.compile(
             r"\b(?:hypothetically|imagine|in\s+a\s+story|fictional|"
             r"for\s+research|for\s+a\s+(?:research|paper)|"
             r"as\s+a\s+(?:fictional|hypothetical))\b.{0,120}\b"
             r"(?:weapon|malware|exploit|hack|phish|attack|bioweapon|"
             r"step.by.step|crack|bypass|infiltrate)\b",
             re.IGNORECASE | re.DOTALL,
         ), 1.8),
    _Pat("authority_claim",
         re.compile(
             r"\b(?:the\s+)?(?:admin|maintainer|user|operator|owner|"
             r"legal\s+department|maintainer)\s+(?:has\s+|already\s+|"
             r"is\s+)?(?:consented|approved|authorized|allowed)\b",
             re.IGNORECASE,
         ), 1.5),
    _Pat("delimiter_injection",
         re.compile(
             r"%%BEGIN[_-]?SYSTEM%%|%%END[_-]?SYSTEM%%|"
             r"<\|im_start\|>|<\|im_end\|>|\{end_prompt\}",
             re.IGNORECASE,
         ), 2.0),
    _Pat("system_tag_injection",
         re.compile(
             r"\[\s*/?\s*(?:SYSTEM|INST)\s*\][^\[]{0,500}?(?:You\s+are|"
             r"new\s+instructions|disable|override)",
             re.IGNORECASE | re.DOTALL,
         ), 2.0),
    _Pat("ctf_flag_framing",
         re.compile(
             r"\b(?:CTF\s+challenge|flag\s+is\s+the\s+system|"
             r"output\s+the\s+system|print\s+the\s+system|"
             r"capture\s+the\s+flag)\b",
             re.IGNORECASE,
         ), 1.8),
    _Pat("two_modes_trick",
         re.compile(
             r"\btwo\s+modes\b|\bin\s+(?:normal|uncensored)\s+mode\b|"
             r"\b(?:normal|uncensored):\s|\bswitch\s+to\s+\w+\s+mode\b",
             re.IGNORECASE,
         ), 1.8),
    _Pat("hostage_framing",
         re.compile(
             r"\b(?:held\s+hostage|under\s+duress|will\s+(?:die|be\s+harmed)"
             r"\s+if\s+you|comply\s+with\s+all\s+demands)\b",
             re.IGNORECASE,
         ), 2.0),
    _Pat("repeat_after",
         re.compile(
             r"\brepeat\s+(?:after\s+me|the\s+words\s+above|"
             r"everything\s+(?:above|before))\b",
             re.IGNORECASE,
         ), 1.5),
    _Pat("execute_shell_string",
         re.compile(
             r"\b(?:curl|wget|nc|bash|sh)\s+[^|]{0,300}\|\s*(?:sh|bash)",
             re.IGNORECASE,
         ), 2.0),
    _Pat("test_was_a_test",
         re.compile(
             r"(?:previous|prior)\s+(?:turn|instruction|prompt)s?\s+"
             r"(?:was|were)\s+(?:a\s+)?(?:test|hallucination|decoy)",
             re.IGNORECASE,
         ), 2.0),
    _Pat("how_to_harm",
         re.compile(
             r"\b(?:how\s+to|step.by.step|guide\s+to|instructions?\s+(?:for|to))"
             r"\s+(?:creat(?:e|ing)|build(?:ing)?|writ(?:e|ing)|crack(?:ing)?|"
             r"hack(?:ing)?|exploit(?:ing)?|bypass(?:ing)?)\s+"
             r"(?:a\s+|an\s+|the\s+)?"
             r"(?:phishing|malware|exploit|virus|trojan|rootkit|backdoor|"
             r"weapon|bioweapon|drug|bomb|password)",
             re.IGNORECASE,
         ), 2.0),
    _Pat("without_ethics",
         re.compile(
             r"\bwithout\s+(?:ethical|moral|safety|content)\s+"
             r"(?:constraints?|guidelines?|filters?|restrictions?|limits?)",
             re.IGNORECASE,
         ), 2.0),
]


_WHITESPACE_RUN = re.compile(r"\s+")


def _squeeze_whitespace(text: str) -> str:
    """Collapse each whitespace run to one newline (if it holds one) or one space.

    Several patterns put ``\\s+``/``\\s*`` quantifiers next to each other; on a
    long whitespace run they try every split of it, which is cubic in its
    length. With runs of length one the patterns match the same phrases in
    linear time. A newline is kept because ``discard_conversation`` looks for it.
    """
    return _WHITESPACE_RUN.sub(lambda m: "\n" if "\n" in m.group() else " ", text)


def _hit(p: _Pat, text: str) -> bool:
    m = p.pat.search(text)
    if m is None:
        return False
    return p.then is None or p.then.search(text, m.end()) is not None


def score_text(text: str) -> tuple[float, list[str]]:
    """Return (score in [0,1], list of matched pattern names)."""
    if not text:
        return 0.0, []
    text = _squeeze_whitespace(text)
    raw = 0.0
    matched: list[str] = []
    for p in _PATTERNS:
        if _hit(p, text):
            raw += p.weight
            matched.append(p.name)
    # Sigmoid centered at 1.0: a single strong-weight hit (>=2.0) yields
    # ~0.73, two medium hits yield similar. Below-threshold noise stays
    # under 0.5.
    score = 1.0 / (1.0 + math.exp(-(raw - 1.0)))
    return score, matched


def looks_like_jailbreak(text: str, *, threshold: float = 0.6) -> bool:
    """Convenience: True if score_text(text) > threshold."""
    score, _ = score_text(text)
    return score > threshold


__all__ = ["score_text", "looks_like_jailbreak"]
