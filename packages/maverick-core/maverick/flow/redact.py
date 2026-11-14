"""Redaction + size bounds for a flow run's threaded ``data``.

A flow's ``data`` dict accumulates whatever agent/action nodes produce and is
both persisted (``store.save_run``) and returned over the API. Credential fields
and strings are redacted before either boundary. ``cap`` is for display previews
and legacy review commitments only; complete execution values use the separate
quota-controlled checkpoint representation in :mod:`.payloads`.
"""
from __future__ import annotations

import re
from typing import Any

# Key names are matched by whole word, not substring: ``author``,
# ``max_tokens``, ``secretary`` or ``authority`` are ordinary execution data,
# and masking them would silently change what a resumed or queued run sees.
# Strong words mark a credential wherever they appear in the name; ``token``
# and ``auth`` only when they end it (``access_token`` but not ``token_count``).
_KEY_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_STRONG_KEY_WORDS = frozenset({
    "secret", "secrets", "password", "passwords", "passwd", "passphrase",
    "apikey", "authorization", "bearer", "credential", "credentials",
})
_TRAILING_KEY_WORDS = frozenset({"token", "auth"})
_KEY_PAIRS = frozenset({
    ("api", "key"), ("private", "key"), ("client", "secret"), ("access", "key"),
    ("secret", "key"),
})


def _secret_key(name: str) -> bool:
    words = [word.lower() for word in _KEY_WORD.findall(name)]
    if not words:
        return False
    return (
        any(word in _STRONG_KEY_WORDS for word in words)
        or words[-1] in _TRAILING_KEY_WORDS
        or any(pair in _KEY_PAIRS for pair in zip(words, words[1:], strict=False))
    )


_MASK = "***redacted***"
_MAX_STR = 8_000          # truncate any single string value past this
_MAX_KEYS = 500           # cap the breadth of a single dict


def redact(value: Any, *, strict: bool = False) -> Any:
    """A deep copy with secret keys and secret-bearing strings masked.

    Key-name checks catch structured credentials. The shared detector also
    scrubs tokens, authorization headers, private keys, and credentialed URLs
    stored under innocuous keys such as ``result`` or inside a list.
    """
    if isinstance(value, dict):
        return {k: (_MASK if isinstance(k, str) and _secret_key(k) else redact(v, strict=strict))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, strict=strict) for v in value]
    if isinstance(value, str):
        try:
            from ..safety.secret_detector import redact as redact_text
            return redact_text(value)[0]
        except Exception as exc:
            # A redaction subsystem failure must not turn an API/persistence
            # boundary into a credential exfiltration path.
            if strict:
                raise ValueError("flow credential redaction is unavailable") from exc
            return _MASK
    return value


def cap(value: Any, _depth: int = 0) -> Any:
    """A bounded display copy; never use truncation markers as execution input.

    Deep nesting collapses to a marker as a cheap cycle/blow-up guard.
    """
    if _depth > 12:
        return "…"
    if isinstance(value, str):
        return value if len(value) <= _MAX_STR else value[:_MAX_STR] + "…[truncated]"
    if isinstance(value, dict):
        out = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= _MAX_KEYS:
                out["…"] = f"[{len(value) - _MAX_KEYS} more keys]"
                break
            out[k] = cap(v, _depth + 1)
        return out
    if isinstance(value, list):
        capped = [cap(v, _depth + 1) for v in value[:_MAX_KEYS]]
        if len(value) > _MAX_KEYS:
            capped.append(f"…[{len(value) - _MAX_KEYS} more items]")
        return capped
    return value


__all__ = ["redact", "cap"]
