"""Optimistic concurrency contract for current facts on every backend."""
from __future__ import annotations


class FactConflict(ValueError):
    """The fact changed after the caller read it; the draft was not written."""


def is_private_fact_key(key: str) -> bool:
    """Reserved agent/user namespaces are not shared business facts."""
    return key.casefold().startswith(("goal:", "user:"))


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
