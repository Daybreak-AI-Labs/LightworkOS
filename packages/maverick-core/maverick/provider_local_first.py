"""Local-first model routing: prefer a reachable local provider when enabled.

Opt-in (``[system] local_first`` / ``MAVERICK_LOCAL_FIRST=1``); default OFF so
"users own model choice" (CLAUDE.md #2) is preserved — and even when on, this only
applies *after* an explicit per-role / CLI / config model has had its say (see
``model_for_role``). When enabled and a configured local model's server is
reachable, ``pick_local(role)`` returns that spec so privacy-sensitive work stays
on the machine; otherwise it returns ``None`` and resolution falls through to the
remote default (graceful fallback).

``is_local`` / ``reorder`` / ``local_model_for_role`` are pure and unit-tested;
``pick_local`` takes an injectable probe so reachability is testable without a
running server.
"""
from __future__ import annotations

import os
import socket

from .providers import _canonical

LOCAL_PROVIDERS = frozenset({"ollama", "vllm", "tgi"})
# Default local ports for a best-effort reachability probe.
_LOCAL_PORTS = {"ollama": 11434, "vllm": 8000, "tgi": 8080}


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def enabled() -> bool:
    if _env_true("MAVERICK_LOCAL_FIRST"):
        return True
    try:
        from .config import load_config
        return bool((load_config() or {}).get("system", {}).get("local_first", False))
    except Exception:  # pragma: no cover -- config never blocks resolution
        return False


def _provider_of(spec: str) -> str:
    return spec.split(":", 1)[0].strip().lower() if ":" in spec else "anthropic"


def is_local(spec: str) -> bool:
    """True iff ``spec``'s provider is a local inference backend."""
    return _canonical(_provider_of(spec)) in LOCAL_PROVIDERS


def reorder(specs: list[str], *, available_fn=None) -> list[str]:
    """Stable-partition ``specs`` so reachable local providers come first.

    ``available_fn(provider) -> bool`` decides reachability (defaults to a live
    probe). Non-local specs and unreachable local specs keep their relative order
    after the reachable local ones.
    """
    af = available_fn or probe
    local_ok, rest = [], []
    for s in specs:
        (local_ok if (is_local(s) and af(_canonical(_provider_of(s)))) else rest).append(s)
    return local_ok + rest


def local_model_for_role(role: str) -> str | None:
    """The configured local model for ``role`` from ``[local_first]`` (or ``None``).

    Looks up ``[local_first.models].<role>`` then a single ``[local_first] model``
    fallback. Only returns specs that name a local provider.
    """
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("local_first", {}) or {}
    except Exception:  # pragma: no cover
        return None
    models = cfg.get("models") or {}
    spec = models.get(role) or cfg.get("model")
    spec = str(spec).strip() if spec else ""
    return spec if spec and is_local(spec) else None


def probe(provider: str, *, timeout: float = 0.3) -> bool:
    """Best-effort TCP probe of a local provider's default port."""
    port = _LOCAL_PORTS.get(_canonical(provider))
    if not port:
        return False
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def pick_local(role: str, *, probe_fn=None) -> str | None:
    """Return a reachable local model spec for ``role``, or ``None`` (no-op when
    disabled / no local model configured / server unreachable)."""
    if not enabled():
        return None
    spec = local_model_for_role(role)
    if not spec:
        return None
    pf = probe_fn or probe
    return spec if pf(_canonical(_provider_of(spec))) else None


__all__ = [
    "LOCAL_PROVIDERS", "enabled", "is_local", "reorder", "local_model_for_role",
    "probe", "pick_local",
]
