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

_SECRET_KEY = re.compile(
    r"(token|secret|password|passwd|api[_-]?key|apikey|authorization|auth|"
    r"bearer|credential|private[_-]?key|client[_-]?secret|access[_-]?key)", re.IGNORECASE)
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
        return {k: (_MASK if isinstance(k, str) and _SECRET_KEY.search(k) else redact(v, strict=strict))
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
