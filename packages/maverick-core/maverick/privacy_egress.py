"""Outbound prompt redaction (data-minimization before egress).

The kernel sends the prompt verbatim to whatever provider a role is routed to
(CLAUDE.md rule 1). Enterprise mode's egress lock pins roles to self-hosted
providers so sensitive data never leaves the box at all -- but a deployment that
*does* use a cloud provider may still want to strip detectable PII/secrets from
the prompt before it leaves, the GDPR data-minimization posture.

This is that gate, and it is **opt-in / default-off** so the kernel's behaviour
is unchanged unless an operator turns it on:

    MAVERICK_REDACT_EGRESS=1      (env, wins)         or
    [privacy] redact_egress = true   (~/.maverick/config.toml)

When on, :func:`redact_prompt` runs the system prompt + every message's text
content through :func:`maverick.provable_redaction.redact_proven` (redact to a
fixpoint, then re-scan to prove nothing sensitive survived) before the request
is dispatched. It is applied to the OUTBOUND copy only at the LLM chokepoint --
the stored conversation is untouched -- and is skipped for local/self-hosted
providers, where the data never leaves infrastructure the operator runs.

Composes the existing detectors; no new detection logic. Deterministic, offline.
"""
from __future__ import annotations

import os
from typing import Any

_TRUE = {"1", "true", "yes", "on", "enable", "enabled", "y", "t"}


def redact_egress_enabled() -> bool:
    """True if outbound prompt redaction is turned on. Off by default.

    A recognized ``MAVERICK_REDACT_EGRESS`` env value wins over the
    ``[privacy] redact_egress`` config key (mirrors the other security knobs)."""
    env = os.environ.get("MAVERICK_REDACT_EGRESS")
    if env is not None and env.strip() != "":
        return env.strip().lower() in _TRUE
    try:
        from .config import load_config
        val = ((load_config() or {}).get("privacy") or {}).get("redact_egress")
    except Exception:
        return False
    if isinstance(val, str):
        return val.strip().lower() in _TRUE
    return bool(val)


def _redact_text(text: str) -> str:
    """Provably redact a single string (PII + secrets to a fixpoint)."""
    if not text or not isinstance(text, str):
        return text
    from .provable_redaction import redact_proven
    return redact_proven(text).redacted


def _redact_json(value: Any) -> Any:
    """Redact the string leaves of a JSON-ish structure (tool_use ``input`` args)."""
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, dict):
        return {k: _redact_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_json(v) for v in value]
    return value


def _redact_content(content: Any) -> Any:
    """Redact a message ``content`` (a str, or a list of content blocks).

    Returns a NEW value; the caller's stored messages are never mutated. Covers
    every channel a secret/PII can ride out on: a block's ``text``; a
    ``tool_result`` block's ``content`` (a str or a nested block list -- the
    high-volume tool-output channel, which carries cat/printenv/db-query output);
    and a ``tool_use`` block's ``input`` args (a dict). Image/other blocks pass
    through structurally unchanged."""
    if isinstance(content, str):
        return _redact_text(content)
    if isinstance(content, list):
        out: list[Any] = []
        for block in content:
            if isinstance(block, dict):
                nb = dict(block)
                if isinstance(nb.get("text"), str):
                    nb["text"] = _redact_text(nb["text"])
                # tool_result payload rides in `content`, NOT `text`; recurse so
                # tool output (the highest-volume channel) is redacted too.
                if isinstance(nb.get("content"), (str, list)):
                    nb["content"] = _redact_content(nb["content"])
                # tool_use call args live in `input` (a dict of JSON values).
                if isinstance(nb.get("input"), (dict, list)):
                    nb["input"] = _redact_json(nb["input"])
                out.append(nb)
            else:
                out.append(block)
        return out
    return content


def redact_prompt(
    system: str, messages: list[dict],
) -> tuple[str, list[dict]]:
    """Return a redacted ``(system, messages)`` for outbound dispatch.

    Deep-copies only what it rewrites: the system string and a fresh list of
    message dicts with redacted content, leaving the caller's originals intact."""
    red_system = _redact_text(system) if system else system
    red_messages: list[dict] = []
    for msg in messages or []:
        if isinstance(msg, dict) and "content" in msg:
            nm = dict(msg)
            nm["content"] = _redact_content(msg["content"])
            red_messages.append(nm)
        else:
            red_messages.append(msg)
    return red_system, red_messages


def maybe_redact_egress(
    provider: str, system: str, messages: list[dict],
) -> tuple[str, list[dict]]:
    """Apply outbound redaction iff enabled AND the provider is not local.

    No-op (returns the originals) when the knob is off or the provider is
    self-hosted -- data routed to a local model never leaves the box, so there is
    nothing to minimize and no reason to degrade the prompt the model sees."""
    if not redact_egress_enabled():
        return system, messages
    try:
        from .enterprise import is_local_provider
        if is_local_provider(provider):
            return system, messages
    except Exception:
        pass
    return redact_prompt(system, messages)


__all__ = [
    "redact_egress_enabled",
    "redact_prompt",
    "maybe_redact_egress",
]
