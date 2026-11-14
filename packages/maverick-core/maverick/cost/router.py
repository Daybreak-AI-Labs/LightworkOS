"""Cross-provider cost-aware router.

The existing ``maverick.routing`` cascade picks Anthropic Haiku /
Sonnet / Opus based on signal. This module sits next to it and picks
*provider* — i.e. given a role, which provider/model combination
hits the cheapest viable rate?

Useful when the user has multiple BYOK adapters configured. We pick:

  1. The user's explicit role override (config wins, always).
  2. Otherwise: among configured + healthy providers, the cheapest
     one that exposes a model at the chosen capability tier.
  3. Tie-break by recent error rate (provider_health snapshot).
  4. Final fallback: ``model_for_role(role)`` from llm.py.

Opt-in. Off by default; flipped on via ``MAVERICK_COST_ROUTING=1``
or ``[routing] cost_aware = true`` in config.

Per-million pricing (input + output averaged) comes from the immutable,
versioned provider in :mod:`maverick.llm`. The ``_PRICING`` tuple list is only
a compatibility view; routing decisions retain each quote's provenance and
exclude unverified rates unless explicitly used for planning.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from ..pricing import ModelPrice, UnverifiedRateError

log = logging.getLogger(__name__)


# Capability tiers; higher = stronger. Picker may upgrade tier when
# the signal demands it (verifier confidence low, retry, thinking).
TIER_CHEAP = 0
TIER_BASE = 1
TIER_PREMIUM = 2


# (provider, model_id, tier). The per-million input/output rates are NOT
# duplicated here: llm.MODEL_PRICING_PROVIDER is the source of truth, so the
# router derives every rate and its provenance from it. Every id here
# resolves in the versioned rate card; an id with no canonical quote would
# score against stale rates and bill at the Sonnet fallback.
_TIERS: list[tuple[str, str, int]] = [
    # Anthropic
    ("anthropic", "claude-haiku-4-5",   TIER_CHEAP),
    ("anthropic", "claude-sonnet-4-6",  TIER_BASE),
    ("anthropic", "claude-opus-4-8",    TIER_PREMIUM),
    # Prior Opus kept so price_for_model still resolves a pinned 4-7
    # (same $5/$25). Selection prefers 4-8 above (equal cost, listed first).
    ("anthropic", "claude-opus-4-7",    TIER_PREMIUM),
    # OpenAI
    ("openai",    "gpt-5.4-nano",       TIER_CHEAP),
    ("openai",    "gpt-5.4",            TIER_BASE),
    ("openai",    "gpt-5.4-pro",        TIER_PREMIUM),
    # DeepSeek
    ("deepseek",  "deepseek-v4-flash",  TIER_CHEAP),
    ("deepseek",  "deepseek-v4-pro",    TIER_BASE),
    # Moonshot / Kimi
    ("moonshot",  "moonshot-v1-128k",   TIER_BASE),
    # xAI
    ("xai",       "grok-4.5",           TIER_BASE),
    # Gemini
    ("gemini",    "gemini-3.5-flash",   TIER_CHEAP),
    ("gemini",    "gemini-3.5-pro",     TIER_PREMIUM),
    # OpenRouter: cheap, near-frontier-on-coding open models. Additive/opt-in —
    # only considered when OPENROUTER_API_KEY (or [providers.openrouter]) is set
    # AND cost routing is enabled. These rows remain estimate-only until their
    # OpenRouter sources are verified.
    ("openrouter", "minimax/minimax-m2.5",     TIER_CHEAP),
    ("openrouter", "deepseek/deepseek-v4-pro", TIER_CHEAP),
    ("openrouter", "qwen/qwen3-coder-next",    TIER_CHEAP),
]


def price_quote_for_model(
    model_id: str,
    *,
    estimate_only: bool = False,
) -> ModelPrice | None:
    """Canonical quote for routing, billing-grade unless explicitly estimated."""

    if not model_id:
        return None
    from ..llm import model_price_quote

    keys = [model_id]
    if ":" in model_id:
        keys.append(model_id.split(":", 1)[1])
    for key in keys:
        try:
            quote = model_price_quote(key, estimate_only=estimate_only)
        except UnverifiedRateError:
            # ``None`` is the router's long-standing "not safely priceable"
            # signal. Billing itself raises the more specific hard-stop.
            return None
        if quote is not None:
            return quote
    return None


def _rate_for(
    model_id: str,
    *,
    estimate_only: bool = False,
) -> tuple[float, float] | None:
    """Rates from a provenance-carrying quote, never from a bare tuple."""

    quote = price_quote_for_model(model_id, estimate_only=estimate_only)
    return quote.rates if quote is not None else None


def _estimate_quote_for(model_id: str) -> ModelPrice | None:
    """Import-time helper for the complete planning catalog."""

    try:
        return price_quote_for_model(model_id, estimate_only=True)
    except (ImportError, ValueError):
        return None


# Complete router catalog, including provisional rows for explicit estimate-only
# planning. Live ``pick`` filters those rows unless its caller opts in.
_PRICE_ENTRIES: list[tuple[str, str, int, ModelPrice]] = [
    (provider, mid, tier, quote)
    for provider, mid, tier in _TIERS
    if (quote := _estimate_quote_for(mid)) is not None
]

# Legacy display/test view. It is derived from _PRICE_ENTRIES and is never the
# source for a routing or billing decision.
_PRICING: list[tuple[str, str, int, float, float]] = [
    (provider, mid, tier, quote.input_per_mtok, quote.output_per_mtok)
    for provider, mid, tier, quote in _PRICE_ENTRIES
]


def price_for_model(
    model_id: str,
    *,
    estimate_only: bool = False,
) -> tuple[float, float] | None:
    """Return rates, or ``None`` when absent/unverified for the requested use.

    ``estimate_only=True`` is required to obtain provisional rates. Budget
    billing resolves the quote itself so it can retain provenance evidence.
    """

    return _rate_for(model_id, estimate_only=estimate_only)


@dataclass
class CostSignal:
    role: str = ""
    tier: int = TIER_BASE
    # Output-heavy roles (revisor) weight output rates more.
    output_heavy: bool = False


# Default capability tier per role. Mirrors the intent of ROLE_MODELS
# (orchestrator/revisor on the strongest model, summarizer on the cheapest)
# but expressed as a provider-agnostic tier the router maps to whichever
# configured provider hits that tier cheapest.
_ROLE_TIERS: dict[str, int] = {
    "orchestrator":    TIER_PREMIUM,
    "revisor":         TIER_PREMIUM,
    "summarizer":      TIER_CHEAP,
    "shield_judge":    TIER_CHEAP,
    "cascade_draft":   TIER_CHEAP,
    # Everything else (researcher/coder/writer/analyst/verifier/
    # skill_distiller) is solid mid-tier work.
}

# Roles whose value is mostly in the generated output (longer completions),
# so the cost score should weight the output rate more heavily.
_OUTPUT_HEAVY_ROLES = frozenset({"revisor", "writer", "coder"})


def signal_for_role(role: str) -> CostSignal:
    """Build the default CostSignal for a role (tier + output-weighting)."""
    return CostSignal(
        role=role,
        tier=_ROLE_TIERS.get(role, TIER_BASE),
        output_heavy=role in _OUTPUT_HEAVY_ROLES,
    )


# ---- per-role routing policies (cost-aware router v2) ----------------------
#
# [routing.roles.<role>] in config narrows the router for that role only:
#
#   [routing.roles.summarizer]
#   providers = ["deepseek", "openrouter"]   # only these may serve the role
#   deny_providers = ["openai"]              # never these
#   max_price_per_mtok = 1.5                 # cost ceiling (weighted avg rate)
#   tier = "cheap"                           # tier floor override
#
# All keys optional; an absent table leaves v1 behavior untouched.

_TIER_NAMES = {"cheap": TIER_CHEAP, "base": TIER_BASE, "premium": TIER_PREMIUM}


@dataclass(frozen=True)
class RolePolicy:
    providers: frozenset[str] = frozenset()       # empty = unrestricted
    deny_providers: frozenset[str] = frozenset()
    max_price_per_mtok: float | None = None
    tier: int | None = None

    def is_empty(self) -> bool:
        return (not self.providers and not self.deny_providers
                and self.max_price_per_mtok is None and self.tier is None)


def role_policy(role: str) -> RolePolicy:
    """The configured per-role policy (empty policy when unset)."""
    try:
        from ..config import load_config
        roles = (((load_config() or {}).get("routing") or {}).get("roles") or {})
        raw = roles.get(role)
    except Exception as exc:
        log.warning(
            "cost routing: could not read policy for role %r (%s); "
            "using an empty policy",
            role,
            exc,
        )
        raw = None
    if not isinstance(raw, dict):
        return RolePolicy()

    def _names(key: str) -> frozenset[str]:
        v = raw.get(key)
        if isinstance(v, (list, tuple, set)):
            return frozenset(str(x).strip().lower() for x in v if str(x).strip())
        return frozenset()

    ceiling = raw.get("max_price_per_mtok")
    if isinstance(ceiling, bool) or not isinstance(ceiling, (int, float)) or ceiling <= 0:
        ceiling = None
    tier = _TIER_NAMES.get(str(raw.get("tier", "")).strip().lower())
    return RolePolicy(
        providers=_names("providers"),
        deny_providers=_names("deny_providers"),
        max_price_per_mtok=float(ceiling) if ceiling is not None else None,
        tier=tier,
    )


def _enabled() -> bool:
    from ..config import env_flag

    env_name = "MAVERICK_COST_ROUTING"
    env = env_flag(env_name)
    if env is not None:
        return env
    if os.environ.get(env_name, "").strip():
        log.warning(
            "cost routing: %s must be one of 1/0, true/false, yes/no, or "
            "on/off; disabling cost routing",
            env_name,
        )
        return False
    try:
        from ..config import load_config
        cfg = (load_config() or {}).get("routing") or {}
        value = cfg.get("cost_aware", False)
        if not isinstance(value, bool):
            log.warning(
                "cost routing: routing.cost_aware must be true or false, got "
                "%s; disabling cost routing",
                type(value).__name__,
            )
            return False
        return value
    except Exception as exc:
        log.warning(
            "cost routing: could not read routing.cost_aware (%s); "
            "disabling cost routing",
            exc,
        )
        return False


def _allowed_providers() -> set[str] | None:
    """Return the routing provider allowlist, or None when unrestricted.

    The installer writes this list alongside advanced routing flags so those
    opt-ins only use providers the user selected, even if other API keys are
    present in the shell environment. Hand-written configs without the key keep
    the historical unrestricted behavior.
    """
    try:
        from ..config import load_config
        routing = (load_config() or {}).get("routing") or {}
    except Exception as exc:
        log.warning(
            "cost routing: could not read routing.allowed_providers (%s); "
            "using the unrestricted legacy provider set",
            exc,
        )
        return None
    allowed = routing.get("allowed_providers")
    if not isinstance(allowed, list):
        return None
    names = {str(p).strip() for p in allowed if str(p).strip()}
    return names or set()


def _provider_available(provider: str) -> bool:
    """Heuristic: the BYOK key for this provider is set and allowed.

    Keeps the dependency surface tiny — we don't probe network.
    """
    allowed = _allowed_providers()
    if allowed is not None and provider not in allowed:
        return False

    env_keys = {
        "anthropic": ("ANTHROPIC_API_KEY",),
        "openai":    ("OPENAI_API_KEY",),
        "deepseek":  ("DEEPSEEK_API_KEY",),
        "moonshot":  ("MOONSHOT_API_KEY",),
        "xai":       ("XAI_API_KEY", "GROK_API_KEY"),
        "gemini":    ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        "openrouter": ("OPENROUTER_API_KEY",),
    }
    for var in env_keys.get(provider, ()):
        if os.environ.get(var, "").strip():
            return True
    # Also accept "configured via maverick config" — cheap check.
    try:
        from ..config import load_config
        cfg = (load_config() or {}).get("providers") or {}
        key = (cfg.get(provider) or {}).get("api_key")
        return bool(key.strip()) if isinstance(key, str) else bool(key)
    except Exception:
        return False


def _avg_price(in_rate: float, out_rate: float, *, output_heavy: bool) -> float:
    if output_heavy:
        return (in_rate * 0.3) + (out_rate * 0.7)
    return (in_rate + out_rate) / 2.0


# A provider whose recent error rate is at/above this is EXCLUDED from
# routing, not merely penalized: the multiplicative error surcharge alone
# let a 100%-error (down) provider still win if it was cheap enough. Knob:
# env MAVERICK_ROUTING_MAX_ERROR_RATE or [routing] max_error_rate; default
# 0.5 (>=50% recent failures => unhealthy, route elsewhere).
_DEFAULT_MAX_ERROR_RATE = 0.5
# Require a minimum sample size before excluding, so a single early failure
# (1/1 = 100%) doesn't blacklist a provider that's actually fine.
_MIN_CALLS_FOR_EXCLUSION = 3


def _max_error_rate() -> float:
    """Recent-error-rate ceiling above which a provider is excluded."""
    raw = os.environ.get("MAVERICK_ROUTING_MAX_ERROR_RATE")
    if raw is None:
        try:
            from ..config import load_config
            routing = (load_config() or {}).get("routing") or {}
            raw = routing.get("max_error_rate")
        except Exception:
            raw = None
    if raw is None:
        return _DEFAULT_MAX_ERROR_RATE
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_MAX_ERROR_RATE
    # A non-positive or >1 ceiling would exclude everything / nothing in a
    # surprising way; clamp to a sane (0, 1] band, else fall back to default.
    if not (0.0 < val <= 1.0):
        return _DEFAULT_MAX_ERROR_RATE
    return val


def _is_unhealthy(stat: dict | None, threshold: float) -> bool:
    """True if a provider_health snapshot row is over the error ceiling with
    enough recent samples to trust the rate."""
    if not stat:
        return False
    if (stat.get("calls") or 0) < _MIN_CALLS_FOR_EXCLUSION:
        return False
    return (stat.get("error_rate") or 0.0) >= threshold


def pick(signal: CostSignal, *, estimate_only: bool = False) -> str | None:
    """Return ``"provider:model_id"`` or ``None`` to use the default.

    Returning None means: defer to the legacy ``model_for_role()``
    path. The caller MUST treat None as "no opinion". Provisional rate rows
    are excluded unless the caller explicitly selects planning-only
    ``estimate_only`` mode; a live route therefore cannot be selected from an
    unverified price.
    """
    if not _enabled():
        return None

    # Per-role policy (v2): tier floor override + provider allow/deny + cost
    # ceiling. An unset table is an empty policy and changes nothing.
    policy = role_policy(signal.role) if signal.role else RolePolicy()
    tier = policy.tier if policy.tier is not None else signal.tier

    # Tier-filter then cost-sort. Construct the scoring rows from rich quotes,
    # retaining provisional rows only in explicit planning mode.
    candidates = [
        (
            provider,
            model,
            candidate_tier,
            quote.input_per_mtok,
            quote.output_per_mtok,
        )
        for provider, model, candidate_tier, quote in _PRICE_ENTRIES
        if candidate_tier >= tier and (estimate_only or quote.verified)
    ]
    if policy.providers:
        candidates = [c for c in candidates if c[0] in policy.providers]
    if policy.deny_providers:
        candidates = [c for c in candidates if c[0] not in policy.deny_providers]
    if policy.max_price_per_mtok is not None:
        candidates = [
            c for c in candidates
            if _avg_price(c[3], c[4], output_heavy=signal.output_heavy)
            <= policy.max_price_per_mtok
        ]
    if not candidates:
        return None

    try:
        from ..provider_health import get as _health
        snap = {(r["provider"], r["model"]): r for r in _health().snapshot()}
    except Exception:
        snap = {}

    def _score(row):
        provider, model, _tier, in_rate, out_rate = row
        cost = _avg_price(in_rate, out_rate, output_heavy=signal.output_heavy)
        # Penalize providers with high recent error rate (we want
        # cheap AND working; 10% errors ≈ 1x cost surcharge, 100%
        # errors ≈ 10x surcharge).
        stat = snap.get((provider, model))
        err_rate = (stat.get("error_rate") or 0.0) if stat else 0.0
        err_pen = 1.0 + err_rate * 10.0
        return cost * err_pen

    available = [c for c in candidates if _provider_available(c[0])]
    if not available:
        return None
    # Hard health exclusion: drop any provider/model whose recent error rate
    # is over the threshold (with enough samples to trust it). The error
    # surcharge in _score only multiplies cost, so a cheap-but-down provider
    # could still win; excluding it forces a fallback to the cheapest HEALTHY
    # candidate. If every candidate is unhealthy, keep them all rather than
    # return nothing useful — a degraded pick beats silently routing nowhere.
    threshold = _max_error_rate()
    healthy = [c for c in available if not _is_unhealthy(snap.get((c[0], c[1])), threshold)]
    available = healthy or available
    available.sort(key=_score)
    provider, model, *_ = available[0]
    cheapest = f"{provider}:{model}"
    # [routing] bandit: learn which of these viable arms pays off best for this
    # kind of task. It only reorders within the healthy, affordable set above,
    # limited to the cheapest arm's tier (exploration across every tier at or
    # above the floor sent cheap roles to premium models), and falls back to
    # the cheapest arm; off, the cheapest arm is returned.
    try:
        from . import bandit

        if bandit.enabled():
            arms = [f"{c[0]}:{c[1]}" for c in available if c[2] == available[0][2]]
            return bandit.choose_for(signal.role, tier, arms) or cheapest
    except Exception as exc:  # noqa: BLE001 -- learning never breaks routing
        log.warning("cost routing: bandit unavailable (%s); using the cheapest arm",
                    type(exc).__name__)
    return cheapest


__all__ = [
    "CostSignal", "RolePolicy", "pick", "role_policy", "signal_for_role",
    "price_for_model", "price_quote_for_model",
    "TIER_CHEAP", "TIER_BASE", "TIER_PREMIUM",
]
