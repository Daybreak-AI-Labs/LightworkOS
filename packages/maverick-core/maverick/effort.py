"""Per-role reasoning effort — the biggest cost/latency lever on Opus 4.7/4.8.

`output_config.effort` controls how much a model thinks *and acts*: lower effort
means fewer, more-consolidated tool calls, less preamble, and terser output.
On Opus 4.7/4.8 it matters more than almost any other knob. Lightwork already
tiers *models* by role (orchestrator/revisor → Opus, the rest → Sonnet/Haiku);
this tiers *effort* the same way — keep the critical reasoning roles
(orchestrator, coder, revisor) at ``high`` and drop the high-volume bulk roles
(researcher, verifier, writer) to ``medium``/``low`` for real token savings with
no loss on the critical path.

**Opt-in** (CLAUDE.md: users own model choice). With nothing configured
:func:`effort_for_role` returns ``None`` and behaviour is unchanged. Any
explicit level applies on its own, with no master switch: a per-role
``MAVERICK_EFFORT_<ROLE>=low``, a global ``MAVERICK_EFFORT=medium``, a per-role
``[effort] <role> = "low"`` or ``[effort] default = "medium"``. ``[effort]
enabled = true`` (or ``MAVERICK_EFFORT_ENABLED=1``) additionally turns on the
built-in role profile below and a domain pack's authored tier.

Model-gated so it never 400s: effort is supported on Opus 4.5+, Sonnet 4.6,
and the current generation (Opus 5, Sonnet 5, Fable 5.x); ``xhigh`` is Opus
4.7+ and the current generation, and ``max`` is Opus-tier (4.6+), Sonnet
4.6, and the current generation -- so a level above the model's ceiling is
clamped down rather than rejected. Verified against
https://platform.claude.com/docs/en/build-with-claude/effort.
"""
from __future__ import annotations

import os

from ._envparse import coerce_bool, env_bool

_LEVELS = ("low", "medium", "high", "xhigh", "max")

# Built-in cost-optimized profile, activated by ``[effort] enabled = true``.
# Intelligence-sensitive roles stay high; bulk/throwaway roles drop down.
_ROLE_DEFAULTS: dict[str, str] = {
    "orchestrator": "high",
    "coder": "high",
    "revisor": "high",
    "researcher": "medium",
    "verifier": "medium",
    "writer": "medium",
    "analyst": "medium",
    "vision": "medium",
    "reflector": "low",
    "skill_distiller": "low",
    "summarizer": "low",
}


def effort_supported(model_id: str) -> bool:
    """Whether ``model_id`` accepts ``output_config.effort`` at all (Opus
    4.5+, Sonnet 4.6, and the current generation -- Opus 5, Sonnet 5, Fable
    5.x; Sonnet 4.5 and Haiku 4.5 reject it with a 400)."""
    m = model_id or ""
    return (
        m.startswith(("claude-opus-4-5", "claude-opus-4-6",
                      "claude-opus-4-7", "claude-opus-4-8",
                      "claude-opus-5", "claude-sonnet-5", "claude-fable-5"))
        or m.startswith("claude-sonnet-4-6")
    )


def _clamp(level: str, model_id: str) -> str:
    """Lower a level the model can't take to one it can (never 400).

    Per https://platform.claude.com/docs/en/build-with-claude/effort:
    ``xhigh`` is available on Opus 4.7+ and the current generation (Opus 5,
    Sonnet 5, Fable 5.x) -- not Opus 4.6 or Sonnet 4.6. ``max`` is available
    on Opus 4.6+, Sonnet 4.6, and the current generation -- not Opus 4.5,
    which supports effort but not ``max``."""
    m = model_id or ""
    xhigh_ok = m.startswith((
        "claude-opus-4-7", "claude-opus-4-8",
        "claude-opus-5", "claude-sonnet-5", "claude-fable-5",
    ))
    max_ok = m.startswith((
        "claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8",
        "claude-opus-5", "claude-sonnet-5", "claude-fable-5",
    )) or m.startswith("claude-sonnet-4-6")
    if level == "xhigh" and not xhigh_ok:
        return "high"
    if level == "max" and not max_ok:
        return "high"
    return level


def _config_effort() -> dict:
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("effort", {})
        return cfg if isinstance(cfg, dict) else {}
    except Exception:  # pragma: no cover -- config never blocks a run
        return {}


def _configured_level(role: str, pack_default: str | None = None) -> str | None:
    """The effort level chosen for ``role``, or ``None`` if the feature is off.

    Precedence, first match wins:

    1. the effort chosen for the current task
       (``task_model_selection.current_effort()``);
    2. per-role env ``MAVERICK_EFFORT_<ROLE>``;
    3. global env ``MAVERICK_EFFORT``;
    4. the per-tenant role override (``role_edit.override_effort``);
    5. per-role config ``[effort] <role>``;
    6. a pack-authored ``effort``, only when ``[effort] enabled`` -- a pack's
       tier is more specific than the deployment default, but it never turns
       the feature on and never overrides a per-role or environment setting;
    7. config ``[effort] default``;
    8. the built-in role profile, only when ``[effort] enabled``."""
    from .task_model_selection import current_effort
    task_effort = current_effort()
    if task_effort:
        return task_effort
    role_l = (role or "").strip().lower()
    env_role = os.environ.get(f"MAVERICK_EFFORT_{role_l.upper()}")
    if env_role:
        return env_role
    env_global = os.environ.get("MAVERICK_EFFORT")
    if env_global:
        return env_global
    # Per-tenant role override (dashboard roles editor / roles.toml) wins over
    # the global [effort] config, but still defers to an explicit env override.
    try:
        from .role_edit import override_effort
        ov = override_effort(role_l)
        if ov:
            return ov
    except Exception:
        pass
    cfg = _config_effort()
    if role_l in cfg and isinstance(cfg[role_l], str):
        return cfg[role_l]
    on = coerce_bool(cfg.get("enabled")) or env_bool("MAVERICK_EFFORT_ENABLED")
    # A pack's authored tier is more specific than the global default, so it is
    # consulted first -- but only once effort is active, so a pack never turns
    # the feature on, it only right-sizes a deployment that already enabled it.
    if on and pack_default:
        return pack_default
    if isinstance(cfg.get("default"), str):
        return cfg["default"]
    if on:
        return _ROLE_DEFAULTS.get(role_l)
    return None


def effort_for_model(level: str | None, model_id: str) -> str | None:
    """Validate and clamp a preselected effort level for ``model_id``.

    This is the provider/failover-side companion to :func:`effort_for_role`: an
    agent may have resolved its configured effort against a primary model, but a
    later failover attempt still has to respect the fallback model's ceiling.
    """
    if not effort_supported(model_id) or not level:
        return None
    level = level.strip().lower()
    if level not in _LEVELS:
        return None
    return _clamp(level, model_id)


def effort_for_role(role: str, model_id: str,
                    pack_default: str | None = None) -> str | None:
    """The effort level to send for ``(role, model)``, or ``None`` to omit it.

    ``pack_default`` is a domain pack's authored effort tier; it applies only
    when the effort feature is enabled, below every per-role and environment
    setting and above the deployment default (see :func:`_configured_level`),
    so it right-sizes an opted-in deployment without ever turning effort on.

    Returns ``None`` (omit ``output_config.effort``, API default applies) when the
    feature is off, the model doesn't support effort, or the configured value is
    invalid — so this can never break a request."""
    return effort_for_model(_configured_level(role, pack_default), model_id)


__all__ = ["effort_for_model", "effort_for_role", "effort_supported"]
