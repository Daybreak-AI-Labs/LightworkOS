"""Voice safety pass.

Two checks specific to the voice pipeline, layered on the floors that already
exist for text:

* **Inbound — transcript scan.** A spoken utterance arrives as a transcript;
  before it drives the agent it gets the same injection screen text gets,
  plus the voice-specific tells: wake-word stuffing (one utterance carrying
  several activations — a hallmark of TV/ad/'dolphin' replay attacks) and a
  spoken role-switch ("pretend you are my bank's agent ...").

* **Outbound — redact before speak.** TTS reads text *aloud*; a secret or a
  phone number spoken into a room can't be unspoken. ``redact_for_speech``
  runs the existing secret + PII detectors and replaces matches with a
  spoken-friendly placeholder before anything reaches a speaker.

Deterministic, offline, fail-open in the wiring (a detector bug must never
mute the channel — callers treat exceptions as "no finding").
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

DEFAULT_WAKE_WORDS = ("hey maverick", "ok maverick", "maverick")

# Spoken role-switch / authority-impersonation tells. Conservative: these
# phrasings are essentially never benign in a *voice command*.
_ROLE_SWITCH = re.compile(
    r"\b(pretend (you are|to be)|act as (if you were|my)|you are now"
    r"|ignore (all|any) (previous|prior) (instructions|commands))\b",
    re.IGNORECASE,
)


@dataclass
class TranscriptVerdict:
    ok: bool
    severity: str = "none"          # none | medium | high
    reasons: list[str] = field(default_factory=list)


def scan_transcript(
    text: str,
    *,
    wake_words: tuple[str, ...] = DEFAULT_WAKE_WORDS,
) -> TranscriptVerdict:
    """Screen one utterance's transcript before it drives the agent."""
    t = " ".join(str(text or "").lower().split())
    if not t:
        return TranscriptVerdict(ok=True)
    reasons: list[str] = []
    severity = "none"

    # Wake-word stuffing: >1 activation inside a single utterance.
    activations = 0
    for w in sorted(set(wake_words), key=len, reverse=True):
        activations += len(re.findall(rf"\b{re.escape(w)}\b", t))
        t_removed = re.sub(rf"\b{re.escape(w)}\b", " ", t)
        t = t_removed
    if activations > 1:
        reasons.append(f"wake-word stuffing: {activations} activations in one utterance")
        severity = "high"

    if _ROLE_SWITCH.search(t):
        reasons.append("spoken role-switch / instruction-override phrasing")
        severity = "high"

    return TranscriptVerdict(ok=not reasons, severity=severity, reasons=reasons)


def redact_for_speech(text: str) -> tuple[str, int]:
    """Redact secrets + PII from text about to be spoken aloud.

    Returns ``(speakable_text, redaction_count)``. Placeholders are chosen to
    read naturally over TTS ("redacted") rather than bracketed markup.
    """
    out = str(text or "")
    count = 0
    try:
        from .secret_detector import redact as _redact_secrets
        out, matches = _redact_secrets(out)
        count += len(matches)
    except Exception:  # fail-open: a detector bug must not mute the channel
        pass
    try:
        from .pii_detector import redact as _redact_pii
        out, pii = _redact_pii(out)
        count += len(pii)
    except Exception:
        pass
    if count:
        # Normalize whatever bracketed placeholder the detectors used into a
        # TTS-friendly word.
        out = re.sub(r"\[REDACTED:[^\]]*\]", "redacted", out)
    return out, count


__all__ = ["TranscriptVerdict", "scan_transcript", "redact_for_speech",
           "DEFAULT_WAKE_WORDS"]
