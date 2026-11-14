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
  require_shield = true``, ``profile = "strict"``, or enterprise mode (which
  ``MAVERICK_REQUIRE_SHIELD=0`` cannot turn off).
* ``scan_block(text)`` — returns a block reason or ``None`` (allow). A shield
  *scan error* always blocks (fail-toward-gate). A *missing* shield blocks only
  when required (so non-enterprise installs keep the fail-open default).
* ``scan_tool_call_block(tool, params)`` — the same policy for a TOOL CALL
  (flow and workflow steps), screened with the tool-call rules the agent applies.
"""
from __future__ import annotations

import json
import logging
import threading

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
    # Enterprise mode is a floor: the env override below can turn the
    # requirement on, but it cannot turn it off for an enterprise deployment.
    try:
        from .enterprise import enterprise_enabled
        if enterprise_enabled():
            return True
    except Exception:  # pragma: no cover
        pass
    env = os.environ.get("MAVERICK_REQUIRE_SHIELD")
    if env is not None and env.strip() != "":
        return is_truthy(env)
    return coerce_bool(safety.get("require_shield"))


_SHIELD_CACHE: dict[tuple, object] = {}
_SHIELD_CACHE_LOCK = threading.Lock()


def _shield_config_key(shield_cls) -> tuple:
    """Everything ``Shield.from_config`` reads, so a cached shield is rebuilt
    exactly when the operator's settings or the staged shared rules change."""
    from .config import get_safety
    from .shield_updates import get_update_config, rules_path

    try:
        st = rules_path().stat()
        rules = (str(rules_path()), st.st_mtime_ns, st.st_size)
    except OSError:
        rules = None
    return (shield_cls, shield_required(),
            json.dumps(get_safety(), sort_keys=True, default=repr),
            json.dumps(get_update_config(), sort_keys=True, default=repr), rules)


def _configured_shield(shield_cls, *, external_text: bool):
    """The operator-configured shield, built once per configuration.

    ``external_text`` keeps input screening on for text from outside this
    deployment (federation, A2A, agent bus): ``[safety] scan_input = false``
    is the operator's choice for their own prompts. ``profile = "off"`` still
    turns every check off; the safety docs describe it as kernel-only mode.
    A configuration ``from_config`` rejects falls back to the default shield
    for external text (screen with defaults rather than fail or skip) and
    raises for tool calls, whose caller blocks.
    """
    try:
        key = (_shield_config_key(shield_cls), external_text)
    except Exception:  # noqa: BLE001 -- an unreadable key never skips screening
        key = None
    if key is not None:
        with _SHIELD_CACHE_LOCK:
            cached = _SHIELD_CACHE.get(key)
        if cached is not None:
            return cached
    try:
        shield = shield_cls.from_config()
        if external_text and not getattr(shield, "_scan_input_enabled", True):
            shield._scan_input_enabled = True
    except Exception as e:
        if not external_text:
            raise
        log.warning("shield configuration rejected; screening external text "
                    "with the default shield: %s", e)
        shield = shield_cls()
    if key is not None:
        with _SHIELD_CACHE_LOCK:
            if len(_SHIELD_CACHE) >= 64:
                _SHIELD_CACHE.clear()
            _SHIELD_CACHE[key] = shield
    return shield


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

    The shield is built from the operator's ``[safety]`` configuration
    (profile, threshold, constitution and signed shared rules), as the agent
    path and :func:`scan_tool_call_block` build it, except that input screening
    stays on (see :func:`_configured_shield`).
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
        verdict = _configured_shield(Shield, external_text=True).scan_input(text)
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
        verdict = _configured_shield(Shield, external_text=False).scan_tool_call(tool, params or {})
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
