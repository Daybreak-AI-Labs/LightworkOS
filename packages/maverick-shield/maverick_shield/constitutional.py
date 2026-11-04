"""Constitutional layer: operator-defined policy rules → runtime classifier.

The built-in shield rules are fixed; this adds a *customisable* layer so a
deployment can declare its own policy in config — e.g. ``no_scrapers`` /
``no_weapons`` / ``no_pii_exfil`` — as ``(name, regex, severity)`` rules that are
checked at the input/output chokepoints alongside the built-ins. Pure regex (no
ML, no external call); invalid patterns are skipped rather than raising.
``scan`` is unit-tested; ``Shield`` loads rules from ``[safety] constitution`` and
composes them at the configured severity threshold.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from .builtin_rules import SEVERITY_ORDER

_DEFAULT_SEVERITY = "high"
_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ConstitutionalRule:
    name: str
    pattern: re.Pattern
    severity: str


def _phrases_pattern(phrases: object) -> str:
    """A pattern matching any of ``phrases`` literally (the dashboard's form)."""
    if not isinstance(phrases, (list, tuple)):
        return ""
    words = [str(p).strip() for p in phrases if isinstance(p, str) and str(p).strip()]
    return "|".join(re.escape(w) for w in words)


def parse_rules(raw: list[dict]) -> list[ConstitutionalRule]:
    """Build rules from ``[{name, pattern, severity?}, ...]``.

    A rule may give ``phrases`` (a list of words or phrases matched literally,
    as the dashboard writes them) instead of a ``pattern``. ``severity``
    defaults to ``high`` and must be a known level; a rule with a bad/empty
    regex or an unknown severity is skipped (never raises).
    """
    out: list[ConstitutionalRule] = []
    for r in raw or []:
        if not isinstance(r, dict):
            _log.warning("constitutional: skipping non-dict policy rule: %r", r)
            continue
        pattern = str(r.get("pattern") or "").strip() or _phrases_pattern(r.get("phrases"))
        if not pattern:
            _log.warning(
                "constitutional: skipping rule %r with empty pattern",
                r.get("name"),
            )
            continue
        severity = str(r.get("severity") or _DEFAULT_SEVERITY).strip().lower()
        if severity not in SEVERITY_ORDER:
            _log.warning(
                "constitutional: skipping rule %r with unknown severity %r "
                "(known: %s)", r.get("name"), severity, sorted(SEVERITY_ORDER),
            )
            continue
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            _log.warning(
                "constitutional: skipping rule %r with invalid regex %r: %s",
                r.get("name"), pattern, e,
            )
            continue
        fallback = ", ".join(
            str(w).strip() for w in (r.get("phrases") or []) if isinstance(w, str)
        )[:48] if not r.get("pattern") and isinstance(r.get("phrases"), (list, tuple)) else ""
        name = str(r.get("name") or fallback or pattern[:24]).strip() or "constitutional_rule"
        out.append(ConstitutionalRule(name=name, pattern=compiled, severity=severity))
    return out


def scan(text: str, rules: list[ConstitutionalRule]) -> tuple[bool, str, list[str]]:
    """Return ``(matched, max_severity, names)`` for rules hitting ``text``.

    ``matched`` is True if any rule matched; ``max_severity`` is the highest
    severity among matches (``"none"`` when none match).
    """
    if not text or not rules:
        return (False, "none", [])
    if not isinstance(text, str):
        text = str(text)
    names: list[str] = []
    max_sev = "none"
    for rule in rules:
        if rule.pattern.search(text):
            names.append(rule.name)
            if SEVERITY_ORDER.get(rule.severity, -1) > SEVERITY_ORDER.get(max_sev, -1):
                max_sev = rule.severity
    return (bool(names), max_sev, names)


__all__ = ["ConstitutionalRule", "parse_rules", "scan"]
