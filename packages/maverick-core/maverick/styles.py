"""User-selectable output styles (the Claude "styles" analog).

A style is a short guidance block appended to every agent's system prompt -- it
shapes *tone and format only*, never capabilities, tools, or the safety surface
(exactly like :mod:`maverick.persona`, but user-picked at runtime rather than
operator-configured). The ACTIVE style is the dashboard runtime overlay
(``styles.active`` in ``runtime-overrides.toml``); unset = no style block, i.e.
today's default voice.

Built-ins live here; there are no custom user styles or per-conversation
selection. This module is the registry + the prompt renderer.
"""
from __future__ import annotations

import logging

from .runtime_overrides import RuntimeOverridesSecurityError

log = logging.getLogger(__name__)

# Output-format styles, framed like Claude's Normal/Concise/Explanatory/Formal.
# Kept short: they're appended verbatim to the system prompt.
BUILTIN_STYLES: dict[str, str] = {
    "concise": "Be brief and direct. Lead with the answer; cut preamble, hedging, and restatement of the question.",
    "explanatory": "Explain the reasoning and context, define key terms, and surface trade-offs — teach the why, not just the what.",
    "formal": "Use formal, professional language: no contractions, slang, or emoji; keep a measured, businesslike tone.",
    "executive": "Open with a one-line bottom line, then 3–5 supporting bullets. Assume a busy reader; no preamble.",
    "technical": "Be precise and exact: correct terminology, concrete specifics (names, numbers, commands), exactness over approachability.",
    "bullet": "Prefer tight bulleted lists over paragraphs — one idea per bullet.",
}

_warned: set[str] = set()


def all_styles() -> dict[str, str]:
    """Every selectable style (the built-ins)."""
    return dict(BUILTIN_STYLES)


def active_style_name() -> str:
    """The currently selected style name, from the dashboard runtime overlay.
    Empty string when none is set (the common case)."""
    try:
        from .runtime_overrides import style_override
        return (style_override() or "").strip()
    except RuntimeOverridesSecurityError:
        raise
    except Exception:  # pragma: no cover -- overlay read never blocks a run
        return ""


def render_active_style_prompt() -> str:
    """The system-prompt block for the active style, or ``""`` when none is set
    (callers concatenate unconditionally). An unknown name is ignored with a
    once-per-process warning rather than hard-erroring (voice-only, low stakes)."""
    name = active_style_name()
    if not name:
        return ""
    guidance = all_styles().get(name)
    if not guidance:
        if name not in _warned:
            _warned.add(name)
            log.warning("active output style %r is not recognized and was ignored; "
                        "valid values: %s", name, " | ".join(sorted(all_styles())))
        return ""
    return f"\n\n# Output style\n\n{guidance}"
