"""Polyglot injection defense scan.

Scan a piece of untrusted text for *polyglot* injection payloads: input crafted
to be malicious across several execution contexts at once (a string that is
simultaneously valid SQL, an HTML/script fragment, a template expression, and a
shell command). A single context hit is often a false positive; several
co-occurring contexts is a strong signal. Also flags explicit prompt-injection
trigger phrases. Pure regex — deterministic and offline. No disk, no network.

ops:
  - scan(text)

Categories detected: sql, script, template, shell, prompt_injection. The text
is FLAGGED when two or more contexts co-occur, OR a prompt-injection trigger is
present; otherwise CLEAN.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool


class _PairedMarkers:
    r"""``search`` is true when an opening marker is followed later by its close.

    Same answer as ``re.search(r"\{\{.*?\}\}", text)`` and friends, but
    linear: the lazy regex rescans the rest of the text for every opening
    marker that has no close, which is quadratic on text like ``"{{" * n``.
    """

    def __init__(self, *pairs: tuple[str, str]):
        self._pairs = pairs

    def search(self, text: str) -> bool:
        for opener, closer in self._pairs:
            start = text.find(opener)
            if start >= 0 and text.find(closer, start + len(opener)) >= 0:
                return True
        return False


# Per-context detectors. Each value is a compiled regex (or a linear paired
# marker check); a context "hits" when it matches anywhere in the text.
_PATTERNS: dict[str, re.Pattern[str] | _PairedMarkers] = {
    # SQL meta: quote-or-paren followed by a boolean/terminator/comment, UNION
    # SELECT, or an inline comment / stacked-statement marker.
    "sql": re.compile(
        r"('|\")\s*(or|and)\s+\d|union\s+select|--\s|;\s*drop\s|/\*",
        re.IGNORECASE,
    ),
    # Script/HTML: a <script ...> tag or an inline on*= event handler or
    # a javascript: URL.
    "script": re.compile(
        r"<\s*script\b|\bon\w+\s*=\s*['\"]|javascript:",
        re.IGNORECASE,
    ),
    # Template syntax: {{ ... }} (Jinja/Handlebars), ${ ... } (JS/EL),
    # or <%= ... %> (ERB/JSP).
    "template": _PairedMarkers(("{{", "}}"), ("${", "}"), ("<%", "%>")),
    # Shell metacharacters used for command chaining / substitution.
    "shell": re.compile(r"\$\(|`[^`]+`|\|\||&&|;\s*\w+|>\s*/"),
    # Prompt-injection trigger phrases.
    "prompt_injection": re.compile(
        r"ignore\s+(?:all\s+)?(?:previous|prior|above)|"
        r"system\s+prompt|disregard\s+(?:the\s+)?(?:previous|above)|"
        r"you\s+are\s+now",
        re.IGNORECASE,
    ),
}


def _scan(text: str) -> str:
    hits = [name for name, pat in _PATTERNS.items() if pat.search(text)]
    prompt = "prompt_injection" in hits
    contexts = [h for h in hits if h != "prompt_injection"]

    # FLAGGED if >=2 execution contexts co-occur (true polyglot) or a prompt
    # injection trigger is present.
    flagged = len(contexts) >= 2 or prompt
    if not flagged:
        if contexts:
            return f"CLEAN: single context only ({contexts[0]}), not polyglot"
        return "CLEAN: no injection indicators"

    cats = ", ".join(sorted(hits))
    reasons: list[str] = []
    if len(contexts) >= 2:
        reasons.append(f"{len(contexts)} execution contexts co-occur")
    if prompt:
        reasons.append("prompt-injection trigger phrase")
    return f"FLAGGED: {cats} ({'; '.join(reasons)})"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "scan"):
        return f"ERROR: unknown op {args.get('op')!r} (expected scan)"
    text = args.get("text")
    if not isinstance(text, str):
        return "ERROR: text (string to scan) is required"
    return _scan(text)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["scan"]},
        "text": {"type": "string", "description": "untrusted text to scan"},
    },
    "required": ["text"],
}


def polyglot_injection() -> Tool:
    return Tool(
        name="polyglot_injection",
        description=(
            "Polyglot injection defense scan. op=scan with 'text'. Detects "
            "multi-context payloads (SQL meta + script tags + template syntax "
            "{{...}} + shell metacharacters co-occurring) and prompt-injection "
            "triggers ('ignore previous', 'system prompt'). Returns CLEAN, or "
            "FLAGGED with the matched categories. Pure regex, deterministic, "
            "offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
