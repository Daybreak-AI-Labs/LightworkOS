"""Scan fetched remote content for injection / hidden-unicode attacks.

Fetched web pages are an untrusted input boundary: a page can hide
zero-width / bidi / tag-block characters or carry prompt-injection text
("ignore previous instructions ...") aimed at the agent reading it.

``scan_remote_content`` is the floor we run on every fetched body before
handing it to the model: it strips dangerous Unicode (via
``unicode_filter.normalize``) and scores the cleaned text for jailbreak
patterns (via ``jailbreak_heuristics.score_text``). It returns the
normalized string plus a suspicion flag/score so callers can annotate
the output. Pure stdlib + regex — no shield dependency, so it works even
when ``agent-shield`` isn't installed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import jailbreak_heuristics, unicode_filter

# Above this jailbreak score the content is flagged suspicious. Matches
# jailbreak_heuristics.looks_like_jailbreak's default threshold so a
# single strong injection pattern (weight >= 2.0 -> score ~0.73) trips it.
_SUSPICION_THRESHOLD = 0.6


@dataclass
class RemoteScanResult:
    cleaned: str
    score: float
    matched_patterns: list[str] = field(default_factory=list)
    removed_unicode: list[str] = field(default_factory=list)
    threshold: float = _SUSPICION_THRESHOLD

    @property
    def suspicious(self) -> bool:
        return self.score >= self.threshold or bool(self.removed_unicode)


def scan_remote_content(text: str, *, threshold: float = _SUSPICION_THRESHOLD) -> RemoteScanResult:
    """Normalize ``text`` and flag injection patterns / hidden unicode.

    Returns ``RemoteScanResult(cleaned, score, matched_patterns,
    removed_unicode)``. ``cleaned`` has dangerous Unicode stripped and is
    NFKC-normalized; jailbreak scoring runs on the *cleaned* text so
    zero-width chars can't hide pattern matches.
    """
    uni = unicode_filter.normalize(text or "")
    score, matched = jailbreak_heuristics.score_text(uni.cleaned)
    return RemoteScanResult(
        cleaned=uni.cleaned,
        score=score,
        matched_patterns=matched,
        removed_unicode=uni.categories,
        threshold=threshold,
    )


__all__ = ["RemoteScanResult", "scan_remote_content"]
