"""Optional provider accounting for hosted vector-store transports."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

_T = TypeVar("_T")


class BestEffortTransportError(RuntimeError):
    """A hosted failure whose adapter contract intentionally absorbs it."""


def metered_transport_call(
    provider: str,
    callback: Callable[[], _T],
    *,
    category: str,
    hosted: bool = True,
) -> _T:
    """Meter one physical hosted operation while preserving core-only installs."""

    if not hosted:
        return callback()
    try:
        from maverick_knowledge.provider_accounting import metered_call
    except ModuleNotFoundError as exc:
        # maverick-core can be installed alone. Do not hide an import failure
        # raised by a dependency inside an otherwise present knowledge package.
        if exc.name not in {
            "maverick_knowledge",
            "maverick_knowledge.provider_accounting",
        }:
            raise
        return callback()
    return metered_call(
        provider,
        callback,
        service=f"vector-store:{provider}",
        default_category=category,
    )


__all__ = ["BestEffortTransportError", "metered_transport_call"]
