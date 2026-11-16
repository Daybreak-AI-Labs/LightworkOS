"""Optimistic concurrency contract for current facts on every backend."""
from __future__ import annotations

from urllib.parse import quote, unquote


class FactConflict(ValueError):
    """The fact changed after the caller read it; the draft was not written."""


def is_private_fact_key(key: str) -> bool:
    """Reserved agent/user namespaces are not shared business facts."""
    return key.casefold().startswith(("goal:", "user:"))


def subject_fact_prefix(token: str) -> str:
    """The ``user:<channel>:<user>:`` key prefix of one export or erase subject.

    ``token`` must be the two percent-quoted parts the callers build
    (``quote(channel, safe="") + ":" + quote(user, safe="")``). Anything else
    is refused: a single part (``sms``) is a prefix of every person on that
    channel, and a raw colon makes ``sms:alice:ops`` both Alice's ``ops:...``
    facts and the facts of the user ``alice:ops``. Returns ``""`` for no token.
    """
    if not token:
        return ""
    parts = token.split(":")
    if len(parts) != 2 or any(part != quote(unquote(part), safe="") for part in parts):
        raise ValueError(
            "a personal-fact token must name one person as <channel>:<user>, "
            "each part percent-quoted"
        )
    return f"user:{token}:"


def check_expected_revision(expected: int | None, actual: int) -> None:
    if expected is None:
        return  # Trusted internal unconditional writes remain explicit at call sites.
    if isinstance(expected, bool) or not isinstance(expected, int) or expected < 0:
        raise ValueError("expected fact revision must be a nonnegative integer")
    if expected != actual:
        raise FactConflict("The fact changed. Read its current value before trying again.")


def normalize_tags(tags: list[str]) -> list[str]:
    """Shared metadata labels, never an authorization or content classification."""
    if not isinstance(tags, list) or len(tags) > 20:
        raise ValueError("Use up to 20 tags.")
    result = set()
    for tag in tags:
        if not isinstance(tag, str) or not tag.strip() or len(tag.strip()) > 64:
            raise ValueError("Tags must contain 1 to 64 characters.")
        if any(ord(char) < 32 for char in tag):
            raise ValueError("Tags cannot contain control characters.")
        result.add(tag.strip().casefold())
    return sorted(result)


def tags_enabled() -> bool:
    from .config import load_config
    return load_config().get("memory", {}).get("fact_tags", False) is True
