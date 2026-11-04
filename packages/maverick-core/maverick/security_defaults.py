"""Secure-by-default posture — the hardened controls default ON.

"Hardened-but-functional": the protective controls that do NOT break the
zero-config happy path default to enabled — audit signing, at-rest encryption,
fail-closed consent for high/critical-risk actions, and a sane tool-risk
ceiling. Deployment-specific controls that WOULD break the default experience
stay opt-in: the egress lock (it would refuse the cloud LLM a default install
calls) and OIDC (it would lock out the local single-user dashboard). The shield
stays fail-open per kernel rule 1.

This module is ONLY the fallback default. Every control keeps its own explicit
knob (env / config / compliance floor), which always wins — so an operator can
turn any single control off, and a compliance profile can force any on. Flip the
whole cluster off for local/dev with ``MAVERICK_SECURE_DEFAULT=0`` (or
``[security] secure_defaults = false``).

Resolver contract for each control: ``compliance floor > explicit arg > env >
config > secure_by_default()`` (instead of the old hard ``False``).
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

_TRUE = {"1", "true", "yes", "on", "enable", "enabled", "y", "t"}
_FALSE = {"0", "false", "no", "off", "disable", "disabled", "n", "f"}


def secure_by_default() -> bool:
    """Whether the hardened-but-functional controls default ON (they do).

    ``MAVERICK_SECURE_DEFAULT`` env wins over ``[security] secure_defaults`` in
    config; an unrecognized env value is ignored (with a warning) rather than
    silently weakening the posture. True unless explicitly disabled."""
    env = os.environ.get("MAVERICK_SECURE_DEFAULT")
    if env is not None and env.strip() != "":
        v = env.strip().lower()
        if v in _TRUE:
            return True
        if v in _FALSE:
            return False
        log.warning("MAVERICK_SECURE_DEFAULT=%r is not a recognized boolean "
                    "(use 1/0/true/false); ignoring it and reading config", env)
    try:
        from .config import load_config
        val = ((load_config() or {}).get("security") or {}).get("secure_defaults")
    except Exception:  # pragma: no cover -- config never weakens the posture silently
        return True
    if val is None:
        return True
    if isinstance(val, str):
        return val.strip().lower() not in _FALSE
    return bool(val)


__all__ = ["secure_by_default"]
