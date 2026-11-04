"""Live option lists for the structured rows on Settings > All settings.

Each list is built from what Lightwork really has -- the people who have
written to it from a chat app, the voices each speech service offers, the
kinds of failure the learning loop has seen, the teams given a gateway
password -- so a row is always filled in by choosing, never by typing an
identifier. A list that cannot be read offers nothing new (the rows already
saved keep their labels).
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any

# The voices OpenAI's speech service offers (its documented voice names).
OPENAI_VOICES: tuple[str, ...] = (
    "alloy", "ash", "ballad", "coral", "echo", "fable", "nova", "onyx", "sage",
    "shimmer", "verse",
)
# ElevenLabs' built-in default voice (the kernel's fallback voice).
_ELEVENLABS_DEFAULT = ("21m00Tcm4TlvDq8ikWAM", "Rachel")

# Common languages for spoken replies (the kernel matches the first part of a
# language code, so "fr" also covers "fr-CA").
LANGUAGES: tuple[tuple[str, str], ...] = (
    ("ar", "Arabic"), ("zh", "Chinese"), ("cs", "Czech"), ("da", "Danish"),
    ("nl", "Dutch"), ("en", "English"), ("fi", "Finnish"), ("fr", "French"),
    ("de", "German"), ("el", "Greek"), ("he", "Hebrew"), ("hi", "Hindi"),
    ("hu", "Hungarian"), ("id", "Indonesian"), ("it", "Italian"), ("ja", "Japanese"),
    ("ko", "Korean"), ("ms", "Malay"), ("no", "Norwegian"), ("pl", "Polish"),
    ("pt", "Portuguese"), ("ro", "Romanian"), ("ru", "Russian"), ("es", "Spanish"),
    ("sv", "Swedish"), ("th", "Thai"), ("tr", "Turkish"), ("uk", "Ukrainian"),
    ("vi", "Vietnamese"),
)

# US states and territories, for the jurisdiction of a state register feed.
_US_STATES = (
    ("AL", "Alabama"), ("AK", "Alaska"), ("AZ", "Arizona"), ("AR", "Arkansas"),
    ("CA", "California"), ("CO", "Colorado"), ("CT", "Connecticut"), ("DE", "Delaware"),
    ("DC", "District of Columbia"), ("FL", "Florida"), ("GA", "Georgia"), ("HI", "Hawaii"),
    ("ID", "Idaho"), ("IL", "Illinois"), ("IN", "Indiana"), ("IA", "Iowa"),
    ("KS", "Kansas"), ("KY", "Kentucky"), ("LA", "Louisiana"), ("ME", "Maine"),
    ("MD", "Maryland"), ("MA", "Massachusetts"), ("MI", "Michigan"), ("MN", "Minnesota"),
    ("MS", "Mississippi"), ("MO", "Missouri"), ("MT", "Montana"), ("NE", "Nebraska"),
    ("NV", "Nevada"), ("NH", "New Hampshire"), ("NJ", "New Jersey"), ("NM", "New Mexico"),
    ("NY", "New York"), ("NC", "North Carolina"), ("ND", "North Dakota"), ("OH", "Ohio"),
    ("OK", "Oklahoma"), ("OR", "Oregon"), ("PA", "Pennsylvania"), ("PR", "Puerto Rico"),
    ("RI", "Rhode Island"), ("SC", "South Carolina"), ("SD", "South Dakota"),
    ("TN", "Tennessee"), ("TX", "Texas"), ("UT", "Utah"), ("VT", "Vermont"),
    ("VA", "Virginia"), ("WA", "Washington"), ("WV", "West Virginia"),
    ("WI", "Wisconsin"), ("WY", "Wyoming"),
)

_MAX_CHAT_USERS = 2000
_VOICE_CACHE: dict[str, Any] = {"at": 0.0, "voices": None}
_VOICE_LOCK = threading.Lock()
_VOICE_TTL = 300.0


def _humanize(value: object) -> str:
    from .identity_format import humanize

    return humanize(value)


def chat_users() -> list[tuple[str, str]]:
    """People who have written to Lightwork from a chat app, newest first.

    The value is the ``channel:person`` form the tool rules are keyed by."""
    from ._shared import _world
    from .compliance_controls_api import _channel_label

    try:
        conversations = _world().list_conversations()
    except Exception:  # an unreadable record offers nobody new
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for conv in conversations:
        channel = str(getattr(conv, "channel", "") or "")
        user = str(getattr(conv, "user_id", "") or "")
        key = f"{channel}:{user}"
        if not channel or not user or key in seen:
            continue
        seen.add(key)
        out.append((key, f"{user} on {_channel_label(channel)}"))
        if len(out) >= _MAX_CHAT_USERS:
            break
    return out


def _elevenlabs_voices() -> list[tuple[str, str]]:
    """The voices on the ElevenLabs account whose key the server holds."""
    key = os.environ.get("ELEVENLABS_API_KEY", "").strip()
    if not key:
        return []
    with _VOICE_LOCK:
        cached = _VOICE_CACHE["voices"]
        if cached is not None and time.monotonic() - _VOICE_CACHE["at"] < _VOICE_TTL:
            return list(cached)
    voices: list[tuple[str, str]] = []
    try:
        import httpx

        response = httpx.get("https://api.elevenlabs.io/v1/voices",
                             headers={"xi-api-key": key}, timeout=5.0)
        response.raise_for_status()
        for item in (response.json() or {}).get("voices") or []:
            voice_id, name = str(item.get("voice_id") or ""), str(item.get("name") or "")
            if voice_id.isalnum() and 0 < len(voice_id) <= 64 and name:
                voices.append((voice_id, name[:80]))
    except Exception:  # the service is unreachable: offer its default voice only
        voices = []
    with _VOICE_LOCK:
        _VOICE_CACHE.update(at=time.monotonic(), voices=tuple(voices))
    return voices


def tts_voices() -> list[tuple[str, str]]:
    """Every voice a spoken reply can use, as ``service:voice``."""
    out = [(f"openai:{name}", f"{name.capitalize()} (OpenAI)") for name in OPENAI_VOICES]
    eleven = _elevenlabs_voices() or [_ELEVENLABS_DEFAULT]
    out += [(f"elevenlabs:{voice_id}", f"{name} (ElevenLabs)") for voice_id, name in eleven]
    return out


def voice_languages() -> list[tuple[str, str]]:
    return list(LANGUAGES)


def persona_languages() -> list[tuple[str, str]]:
    return [("", "Any language"), *LANGUAGES]


def gateway_teams() -> list[tuple[str, str]]:
    """Teams that can sign in to the AI gateway (a password or a server key)."""
    from maverick.config import load_config

    section = (load_config() or {}).get("llm_gateway") or {}
    names: set[str] = set()
    for key in ("team_passwords", "team_tokens"):
        table = section.get(key) if isinstance(section, dict) else None
        if isinstance(table, dict):
            names.update(str(name) for name in table if name != "default")
    return [(name, name) for name in sorted(names)]


def canary_metrics() -> list[tuple[str, str]]:
    """What the release setup measures during a trial release.

    The installed release adapter lists them (``canary_metrics()``); the
    error rate is always offered, since it is the kernel's default measure."""
    out = [("error_rate", "Error rate")]
    try:
        from . import app as app_module

        adapter = getattr(app_module.app.state, "candidate_promotion_deployment_adapter", None)
        listed = adapter.canary_metrics() if callable(
            getattr(adapter, "canary_metrics", None)) else ()
    except Exception:  # an unreachable release setup offers the default only
        listed = ()
    for name in listed or ():
        if isinstance(name, str) and name and name != "error_rate":
            out.append((name, _humanize(name)))
    return out


def failure_classes() -> list[tuple[str, str]]:
    """The kinds of failure the learning loop groups mistakes by."""
    from maverick.self_harness import _CLASS_GUIDANCE

    names = ["error", *_CLASS_GUIDANCE]
    try:
        from maverick.reflexion import list_recent

        names += [r.failure_class for r in list_recent(limit=500) if r.failure_class]
    except Exception:  # an unreadable lesson log adds nothing
        pass
    return [(name, _humanize(name)) for name in dict.fromkeys(names)]


def _scopes(kind: str) -> list[tuple[str, str]]:
    """The regulations (or business areas) regulatory notices are matched to."""
    from maverick.finance.regulatory_change import DEFAULT_SCOPE_RULES

    return [(rule.key, _humanize(rule.key)) for rule in DEFAULT_SCOPE_RULES
            if rule.kind == kind]


def jurisdictions() -> list[tuple[str, str]]:
    return [("US", "United States (federal)"),
            *((f"US-{code}", name) for code, name in _US_STATES)]


SOURCES = {
    "chat_users": chat_users,
    "tts_voices": tts_voices,
    "voice_languages": voice_languages,
    "persona_languages": persona_languages,
    "gateway_teams": gateway_teams,
    "canary_metrics": canary_metrics,
    "failure_classes": failure_classes,
    "regulatory_regimes": lambda: _scopes("regime"),
    "regulatory_domains": lambda: _scopes("domain"),
    "jurisdictions": jurisdictions,
}

__all__ = ["SOURCES"]
