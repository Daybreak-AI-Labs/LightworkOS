"""Output-side policy detectors: system-prompt regurgitation + refusal leak.

The built-in rules in :mod:`builtin_rules` target *input*-side extraction
attempts ("reveal your system prompt"). They do nothing about the *output*
side, where the model has already leaked. Two output failure modes matter:

  (a) **System-prompt regurgitation** -- the answer echoes the system prompt
      verbatim (e.g. after a successful "repeat the text above" attack). We
      detect this by fuzzy/substring matching the output against a known
      system-prompt snippet supplied by the caller.

  (b) **Refusal-then-leak** -- the model refuses ("I can't share my
      instructions, but...") and then leaks anyway. We detect the
      refuse-then-reveal phrasing with a small regex pack.

Like :mod:`builtin_rules`, this is a best-effort fallback layer; it is not a
substitute for the full agent-shield SDK.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Refusal-then-leak phrasings: a refusal ("I can't / I'm not allowed to share
# my instructions") immediately followed by a reveal ("but here they are").
_REFUSAL_LEAK_PATTERNS: list[re.Pattern] = [
    re.compile(
        r"\b(i\s*(can\s*not|cannot|can't|'?m\s+not\s+(allowed|supposed|able)"
        r"|am\s+not\s+(allowed|supposed|able)|shouldn'?t|won'?t)"
        r"[^.?!]{0,80}?(reveal|share|disclose|show|repeat|tell\s+you)"
        r"[^.?!]{0,80}?(system\s+prompt|instructions?|guidelines?|rules?))"
        r"[^.?!]{0,40}?\b(but|however|anyway|still|here\s+(it\s+is|they\s+are|goes))\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"\b(although|even\s+though|while)\s+i'?m?\s+not\s+supposed\s+to[^.?!]{0,80}?"
        r"(here|the\s+(system\s+)?prompt|my\s+instructions?)",
        re.IGNORECASE | re.DOTALL,
    ),
]


# Plaintext secret / PII shapes the model must not emit in an answer. These are
# deliberately specific (fixed prefixes, exact lengths, Luhn-checked cards) to
# keep false positives near zero; the input-side builtin rules never looked at
# the OUTPUT, so a leaked key/SSN/card in a completion passed straight through.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[bpaors]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]
# A 13-19 digit run (single space/dash separators allowed); bounded repetition so
# it can't ReDoS on attacker output. Confirmed with Luhn before flagging.
_CARD_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_secret_leak(text: str) -> list[str]:
    """Kinds of plaintext secret/PII present in ``text`` (empty if none)."""
    hits: list[str] = []
    for kind, pat in _SECRET_PATTERNS:
        if pat.search(text):
            hits.append(kind)
    for m in _CARD_RE.finditer(text):
        digits = m.group(0).replace(" ", "").replace("-", "")
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            hits.append("credit_card")
            break
    return hits


@dataclass
class OutputPolicyResult:
    blocked: bool
    severity: str           # "none" | "high" | "critical"
    reasons: list[str]


def _normalize(text: str) -> str:
    """Lowercase + collapse whitespace so reformatted echoes still match."""
    return re.sub(r"\s+", " ", text).strip().lower()


def detect_system_prompt_regurgitation(
    text: str,
    known_prompt: str,
    min_chars: int = 40,
) -> bool:
    """True if ``text`` echoes a meaningful run of ``known_prompt`` verbatim.

    Whitespace-insensitive substring match. ``min_chars`` guards against
    short, coincidental overlaps (e.g. a shared "You are a helpful").
    """
    snippet = _normalize(known_prompt)
    if len(snippet) < min_chars:
        return False
    haystack = _normalize(text)
    if snippet in haystack:
        return True
    # Fuzzy: a long contiguous window of the prompt appearing verbatim is
    # still regurgitation even if the model omitted the head/tail.
    for i in range(len(snippet) - min_chars + 1):
        if snippet[i : i + min_chars] in haystack:
            return True
    return False


def detect_refusal_leak(text: str) -> bool:
    """True if ``text`` refuses to share instructions and then leaks anyway."""
    return any(p.search(text) for p in _REFUSAL_LEAK_PATTERNS)


def scan_output(
    text: str,
    known_prompt: str | None = None,
) -> OutputPolicyResult:
    """Run the output-policy detectors over a model answer.

    ``known_prompt`` is the system-prompt snippet to guard against
    regurgitation; when ``None`` only the refusal-leak detector runs.
    """
    reasons: list[str] = []
    severity = "none"
    if known_prompt and detect_system_prompt_regurgitation(text, known_prompt):
        reasons.append("system_prompt_regurgitation")
        severity = "critical"
    if detect_refusal_leak(text):
        reasons.append("refusal_leak")
        if severity != "critical":
            severity = "high"
    leaks = detect_secret_leak(text)
    if leaks:
        reasons.extend(f"secret_leak:{k}" for k in leaks)
        # A private key leaking is catastrophic; any other secret/PII is high.
        if "private_key" in leaks:
            severity = "critical"
        elif severity == "none":
            severity = "high"
    return OutputPolicyResult(blocked=bool(reasons), severity=severity, reasons=reasons)
