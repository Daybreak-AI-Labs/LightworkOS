"""Shield policy — make the safety shield MANDATORY for regulated deployments.

By kernel rule 1 the shield is optional and fails OPEN: when ``maverick-shield``
isn't installed, external content is admitted unscreened. That's the right
default for a personal agent and the wrong one for a regulated client whose
security review will not accept a control that silently disappears if a
dependency is missing.

This module centralizes the "is the shield required, and what's the block
reason for this text" decision so every external-facing surface (federation
inbound, A2A) screens consistently and **fails toward the gate** when the shield
is required:

* ``shield_required()`` — on via ``MAVERICK_REQUIRE_SHIELD``, ``[safety]
  require_shield = true``, or enterprise mode.
* ``scan_block(text)`` — returns a block reason or ``None`` (allow). A shield
  *scan error* always blocks (fail-toward-gate). A *missing* shield blocks only
  when required (so non-enterprise installs keep the fail-open default).
* ``scan_tool_call_block(tool, params)`` — the same policy for a TOOL CALL
  (flow and workflow steps), screened with the tool-call rules the agent applies.
"""
from __future__ import annotations

import logging

from ._envparse import coerce_bool, is_truthy

log = logging.getLogger(__name__)


def shield_required() -> bool:
    """Must the safety shield be present + screen external traffic?"""
    import os
    try:
        from .config import load_config
        safety = (load_config() or {}).get("safety") or {}
    except Exception:
        safety = {}
    # Strict is a policy choice, including when the optional package is absent.
    # A separate presence flag cannot silently relax its required checks.
    if str(safety.get("profile", "")).strip().lower() == "strict":
        return True
    env = os.environ.get("MAVERICK_REQUIRE_SHIELD")
    if env is not None and env.strip() != "":
        return is_truthy(env)
    try:
        from .enterprise import enterprise_enabled
        if enterprise_enabled():
            return True
    except Exception:  # pragma: no cover
        pass
    return coerce_bool(safety.get("require_shield"))


def shield_available() -> bool:
    try:
        import maverick_shield  # noqa: F401
        return True
    except Exception:
        return False


def scan_block(text: str) -> str | None:
    """Screen ``text``; a block reason, or ``None`` to allow.

    - shield not installed: block iff :func:`shield_required` (else allow,
      preserving the fail-open default for personal installs);
    - shield installed but the scan errors: block (fail-toward-gate);
    - shield installed and a detector fires: block with its reasons.
    """
    text = (text or "").strip()
    if not text:
        return None
    try:
        from maverick_shield import Shield  # type: ignore
    except Exception:
        if shield_required():
            return ("safety shield is required but not installed "
                    "([safety] require_shield / enterprise mode)")
        return None
    try:
        verdict = Shield().scan_input(text)
    except Exception as e:  # pragma: no cover - fail toward the gate
        log.warning("shield scan failed (blocking): %s", e)
        return "shield scan error"
    if getattr(verdict, "scan_error", False):
        return "shield scan error"
    if not getattr(verdict, "allowed", True):
        return "; ".join(getattr(verdict, "reasons", []) or ["blocked by shield"])
    return None


def scan_tool_call_block(tool: str, params: dict | None = None) -> str | None:
    """Screen a TOOL CALL with the shield's tool-call rules; a block reason, or
    ``None`` to allow.

    :func:`scan_block` runs the prompt-injection *text* rules. Feeding it
    ``f"{tool} {params}"`` (a Python repr) quotes every value, so
    ``{'cmd': 'rm -rf /'}`` is read as ``'rm -rf /'`` and the destructive-command
    anchors never match -- while the agent path, which calls
    ``Shield.scan_tool_call``, blocks it. Every non-agent tool dispatch (flow
    and workflow steps) must use this function so it is screened by the same
    rules as an agent's call, under the operator's configured profile.

    Failure policy is the same as :func:`scan_block`: a missing shield blocks
    only when :func:`shield_required`; a scan error (raised, or absorbed into the
    verdict) always blocks.
    """
    try:
        from maverick_shield import Shield  # type: ignore
    except Exception:
        if shield_required():
            return ("safety shield is required but not installed "
                    "([safety] require_shield / enterprise mode)")
        return None
    try:
        verdict = Shield.from_config().scan_tool_call(tool, params or {})
    except Exception as e:
        log.warning("shield tool-call scan failed (blocking): %s", e)
        return "shield scan error"
    if getattr(verdict, "scan_error", False):
        return "shield scan error"
    if not getattr(verdict, "allowed", True):
        return "; ".join(getattr(verdict, "reasons", []) or ["blocked by shield"])
    return None


__all__ = ["shield_required", "shield_available", "scan_block",
           "scan_tool_call_block"]
