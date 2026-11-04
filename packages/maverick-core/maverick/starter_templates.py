"""Personalized starter templates.

Ranks the goal-template catalog for *this* user: a pure scorer over the
verb/domain word frequency of their recent goal titles (``world.list_goals``,
injected world — no LLM, no network), so the "start something" surface leads
with the templates that match what they actually run.

Cold start (no history, or no overlapping words) is deterministic: every
template scores 0 and the list falls back to name order.
"""
from __future__ import annotations

import re
from collections import Counter

DEFAULT_HISTORY = 200

# English glue words that carry no verb/domain signal. Small on purpose: the
# scorer only needs to keep "research"/"trip"/"email" while dropping "the".
_STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "into", "that", "this", "then",
    "them", "their", "your", "our", "all", "any", "are", "was", "were",
    "you", "not", "can", "could", "should", "would", "about", "over",
    "under", "out", "per", "via", "use", "using", "new", "get", "make",
})

_WORD = re.compile(r"[a-z][a-z0-9_-]{2,}")


def _tokens(text: str | None) -> list[str]:
    return [w for w in _WORD.findall((text or "").lower()) if w not in _STOPWORDS]


def history_profile(world, *, owner: str | None = None, limit: int = DEFAULT_HISTORY) -> Counter:
    """Word-frequency profile of the user's recent goal titles."""
    profile: Counter = Counter()
    for goal in world.list_goals(owner=owner, limit=max(1, int(limit)), order="desc"):
        profile.update(_tokens(goal.title))
    return profile


def score_template(name: str, title: str, params: list[str], profile: Counter) -> int:
    """Overlap score: sum of profile frequencies over the template's distinct
    name/title/param words (so one hot word can't double-count)."""
    words = set(_tokens(name.replace("-", " ").replace("_", " ")))
    words |= set(_tokens(title))
    for p in params:
        words |= set(_tokens(p))
    return sum(profile[w] for w in words)


def _local_templates(owner: str | None = None) -> list:
    """Parsed templates from the user + bundled dirs (offline catalog)."""
    from .templates import can_read_template, list_templates, load_template
    out = []
    for name in list_templates():
        try:
            template = load_template(name)
            if can_read_template(template, owner):
                out.append(template)
        except (OSError, ValueError, FileNotFoundError):
            continue
    return out


def suggest(world, k: int = 5, *, owner: str | None = None, templates: list | None = None) -> list[dict]:
    """The top-``k`` templates for this user, best match first.

    ``templates=None`` reads the local template catalog (user-installed +
    bundled); pass parsed ``Template`` objects to rank another set. Each row is
    ``{name, title, params, score}``; ties (including the all-zero cold start)
    break on name for a stable order.
    """
    profile = history_profile(world, owner=owner or "")
    candidates = _local_templates(owner) if templates is None else templates
    rows = [
        {
            "name": t.name,
            "title": t.title,
            "params": list(t.params),
            "score": score_template(t.name, t.title, list(t.params), profile),
        }
        for t in candidates
    ]
    rows.sort(key=lambda r: (-r["score"], r["name"]))
    return rows[: max(1, int(k))]


__all__ = ["history_profile", "score_template", "suggest", "DEFAULT_HISTORY"]
