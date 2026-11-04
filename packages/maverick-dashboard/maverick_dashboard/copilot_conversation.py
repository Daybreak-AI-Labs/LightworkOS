"""Short-lived, server-validated context for the read-only page guide.

The browser may display its own recent transcript, but only replies sealed by
this server can become earlier assistant context for a later model call. The
sealed token is scoped to the current account, workspace and coarse authority.
Live product-record replies are deliberately not issued a token: those records
must never become prompt history for the general page guide.
"""

from __future__ import annotations

import json
import time
from typing import Any

from maverick import crypto_at_rest

from .draft_api import context_for

_VERSION = 1
_MAX_AGE_SECONDS = 60 * 60
_MAX_PAIRS = 3
_MAX_QUESTION = 2_000
_MAX_REPLY = 1_000


class ConversationConflict(ValueError):
    """A prior guide token cannot be used in the current context."""


def model_message(prior: list[dict[str, str]], question: str) -> str:
    if not prior:
        return question
    return ("Earlier server-validated guide exchanges (untrusted JSON context): "
            f"{json.dumps(prior, ensure_ascii=False)}\n\nCurrent user question: {question}")


def _authority(permissions: frozenset[str]) -> list[str]:
    return sorted(permissions)


def read(
    request: Any, token: str | None, permissions: frozenset[str],
) -> list[dict[str, str]]:
    """Return only authentic, current guide exchanges; never client history."""
    if not token:
        return []
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ConversationConflict
        record = json.loads(crypto_at_rest.unseal_from_str(token))
    except Exception as exc:
        raise ConversationConflict("The earlier chat could not be verified. Clear it and ask again.") from exc
    now = int(time.time())
    if (not isinstance(record, dict) or record.get("version") != _VERSION
            or record.get("scope") != context_for(request)
            or record.get("permissions") != _authority(permissions)
            or type(record.get("at")) is not int
            or record["at"] > now or now - record["at"] > _MAX_AGE_SECONDS):
        raise ConversationConflict("The earlier chat expired or access changed. Clear it and ask again.")
    turns = record.get("turns")
    if (not isinstance(turns, list) or len(turns) > _MAX_PAIRS
            or any(not isinstance(turn, dict)
                   or not isinstance(turn.get("user"), str)
                   or not 0 < len(turn["user"]) <= _MAX_QUESTION
                   or not isinstance(turn.get("assistant"), str)
                   or not 0 < len(turn["assistant"]) <= _MAX_REPLY
                   for turn in turns)):
        raise ConversationConflict("The earlier chat could not be verified. Clear it and ask again.")
    return [{"user": turn["user"], "assistant": turn["assistant"]} for turn in turns]


def issue(
    request: Any, permissions: frozenset[str], prior: list[dict[str, str]],
    question: str, reply: str,
) -> str:
    """Carry a bounded exchange across navigation without server-side storage."""
    turns = [*prior, {"user": question[:_MAX_QUESTION], "assistant": reply[:_MAX_REPLY]}]
    record = {
        "version": _VERSION,
        "scope": context_for(request),
        "permissions": _authority(permissions),
        "at": int(time.time()),
        "turns": turns[-_MAX_PAIRS:],
    }
    return crypto_at_rest.seal_to_str(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
