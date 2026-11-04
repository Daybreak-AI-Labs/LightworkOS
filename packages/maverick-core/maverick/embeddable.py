"""Embeddable-mode markers.

Library users who import ``maverick`` to drive an agent from inside
their own app don't want Lightwork's CLI cost: click imports, command
discovery, plugin entry-point scanning, etc. They can set
``MAVERICK_NO_CLI=1`` in the environment before importing, and the
core kernel skips CLI-only paths.

This module is the source of truth for the flag. Tools and entry-
points that are NOT needed in embedded mode check ``no_cli()`` and
short-circuit.
"""
from __future__ import annotations

from ._envparse import env_bool


def no_cli() -> bool:
    """True if Lightwork is being imported as a library (no CLI needed)."""
    return env_bool("MAVERICK_NO_CLI")


def short_circuit_in_embedded(label: str = "") -> None:
    """Optionally raise an actionable error from CLI-only entry points.

    Not used yet; reserved for callers that want a clearer failure
    than "click not installed". Most CLI-only paths just skip silently.
    """
    if no_cli():
        raise RuntimeError(
            f"maverick: CLI path {label!r} called in embedded mode "
            "(MAVERICK_NO_CLI=1 is set). Use the maverick.* Python API "
            "instead."
        )


__all__ = ["no_cli", "short_circuit_in_embedded"]
