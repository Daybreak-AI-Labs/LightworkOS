"""The plain name of an action waiting for approval.

Approval buttons and titles name what they decide ("Approve "Run a command in
the sandbox""). The best name is the approval card's own plain summary, which
the requester wrote for people. Without a usable one, the plain step words
the task page narrates for the same tool (``step_narration``) are used, and
only then the stored action name, made readable.
"""
from __future__ import annotations

import re

_MAX_SUMMARY = 80
# Summaries the consent layer fills in when the requester gave none: true, but
# they do not name the action.
# A summary phrased as the request itself ("Approve the payment?") would read
# 'Approve "Approve the payment"'; it does not name the action either.
_ASKS = re.compile(r"^(approve|review|confirm|decide|check)\b", re.IGNORECASE)
_GENERIC = re.compile(r"^(review this exact operation|run .+ once for the reviewed scope)\.?$", re.IGNORECASE)


def _summary(card: object) -> str:
    if not isinstance(card, dict):
        return ""
    text = " ".join(str(card.get("summary") or "").split())
    if not text or len(text) > _MAX_SUMMARY or _GENERIC.match(text) or _ASKS.match(text) or text.endswith("?"):
        return ""
    # One sentence, read as a name: no closing full stop.
    if text.count(". ") or "\n" in text:
        return ""
    return text.removesuffix(".")


def _step_words(action: str) -> str:
    from .step_narration import _TOOLS

    words = _TOOLS.get(action)
    if not words:
        return ""
    infinitive = words[1]
    return infinitive[:1].upper() + infinitive[1:]


def _readable(action: str) -> str:
    from .identity_format import humanize

    if " " in action:
        return action
    return humanize(action.replace(".", " ")) or "Reviewed action"


def action_label(action: object, card: object = None) -> str:
    """The card's plain summary, else the step words, else the readable action."""
    raw = " ".join(str(action or "").split())
    return _summary(card) or _step_words(raw) or _readable(raw)
