"""Deployment profile — one named knob that selects the security posture.

Two profiles, so an operator sets *one* thing instead of remembering the whole
cluster of individual switches:

- ``standard`` (default) — the personal / dev posture. The hardened-but-functional
  controls still default ON (see :mod:`maverick.security_defaults`: audit signing,
  at-rest encryption, fail-closed consent, tool-risk ceiling), but the
  deployment-specific controls that would break the zero-config happy path — the
  **egress lock** and the rest of *enterprise mode* — stay off. This is the right
  default for a single user pointing the agent at a cloud LLM on their own machine.

- ``enterprise`` — the regulated / sensitive-data posture. Turns *enterprise mode*
  on by default (egress lock, tool-egress lock, consent fail-closed, capabilities
  enforced — see :mod:`maverick.enterprise`) on top of the always-on hardened
  controls. This is what a Docker / Helm / VPS server deployment for a bank should
  run, and it is what the reference deploy manifests set.

Set it with ``MAVERICK_PROFILE`` (env wins) or ``[profile] name`` in
``~/.maverick/config.toml``, or pick it in the installer wizard.

**Precedence is preserved.** This is only the *default* an unset control falls back
to. Every individual control keeps its own explicit knob (env / config) and a
compliance floor can still force any control on — both win over the profile. So
``profile = "enterprise"`` with ``[enterprise] mode = false`` leaves the boundary
off (the explicit knob wins), and a HIPAA compliance floor locks egress even under
``profile = "standard"``. The shield stays fail-open per kernel rule 1 regardless.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

STANDARD = "standard"
ENTERPRISE = "enterprise"

# Aliases an operator might reasonably type, normalized to the two canonical names.
_STANDARD_ALIASES = frozenset({STANDARD, "default", "dev", "develop", "development",
                               "local", "personal"})
_ENTERPRISE_ALIASES = frozenset({ENTERPRISE, "regulated", "hardened", "prod",
                                 "production"})

_ENV = "MAVERICK_PROFILE"


def _normalize(raw: object) -> str | None:
    """Map a raw profile string to a canonical name, or None if unrecognized."""
    if raw is None:
        return None
    name = str(raw).strip().lower()
    if name == "":
        return None
    if name in _STANDARD_ALIASES:
        return STANDARD
    if name in _ENTERPRISE_ALIASES:
        return ENTERPRISE
    return None


def active_profile() -> str:
    """The active deployment profile: ``"standard"`` (default) or ``"enterprise"``.

    ``MAVERICK_PROFILE`` env wins over ``[profile] name`` in config. An
    unrecognized value is ignored (with a warning) and treated as ``standard``
    rather than silently selecting a posture the operator did not name."""
    env = os.environ.get(_ENV)
    if env is not None and env.strip() != "":
        decided = _normalize(env)
        if decided is not None:
            return decided
        log.warning("%s=%r is not a recognized profile (use 'standard' or "
                    "'enterprise'); ignoring it and reading config", _ENV, env)
    try:
        from .config import load_config
        val = ((load_config() or {}).get("profile") or {}).get("name")
    except Exception:  # pragma: no cover -- config never selects a posture by erroring
        return STANDARD
    decided = _normalize(val)
    if decided is not None:
        return decided
    if val is not None and str(val).strip() != "":
        log.warning("[profile] name=%r is not a recognized profile (use "
                    "'standard' or 'enterprise'); treating as standard", val)
    return STANDARD


def is_enterprise_profile() -> bool:
    """True when the active deployment profile is ``enterprise``."""
    return active_profile() == ENTERPRISE


__all__ = ["STANDARD", "ENTERPRISE", "active_profile", "is_enterprise_profile"]
