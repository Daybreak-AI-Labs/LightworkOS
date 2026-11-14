"""Opt-in MCP-client language analytics.

This records the *language/SDK* of MCP clients that connect, derived from their
``User-Agent``, into a local tally — so an operator can answer "who actually
drives this over MCP" without shipping any PII. The tally stays on the
installation; nothing is sent to the project.

**Consent-gated and off by default**: with nothing configured
:func:`record_client` is a no-op and nothing is written. Enable with
``[analytics] mcp_client_language = true`` / ``MAVERICK_MCP_ANALYTICS=1``. The
tally lives at the shared (un-namespaced) root so it aggregates across tenants;
it stores only coarse language buckets + counts, never request content.
"""
from __future__ import annotations

import json
import logging
import os

from ._envparse import coerce_bool, is_truthy

log = logging.getLogger(__name__)

# Coarse language buckets keyed by characteristic User-Agent substrings. Order
# matters: more specific tokens first.
_UA_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("typescript", ("node", "undici", "axios", "got (", "node-fetch", "typescript", "javascript", "deno", "bun")),
    ("go", ("go-http-client", "golang", "go/")),
    ("rust", ("reqwest", "rust", "hyper/")),
    ("csharp", (".net", "dotnet", "csharp", "httpclient")),
    ("java", ("okhttp", "java/", "jvm", "kotlin")),
    ("python", ("python", "httpx", "requests", "aiohttp", "urllib")),
)

LANGUAGES = ("python", "typescript", "go", "rust", "java", "csharp", "unknown")


def analytics_enabled() -> bool:
    """Opt-in. ``MAVERICK_MCP_ANALYTICS`` env wins over
    ``[analytics] mcp_client_language``. Off by default."""
    env = os.environ.get("MAVERICK_MCP_ANALYTICS")
    if env is not None and env.strip() != "":
        return is_truthy(env)
    try:
        from .config import load_config
        v = (load_config() or {}).get("analytics", {}).get("mcp_client_language")
    except Exception:  # pragma: no cover -- config never blocks a request
        return False
    return coerce_bool(v)


def classify_user_agent(user_agent: str | None) -> str:
    """Map a ``User-Agent`` to a coarse language bucket (never raises)."""
    ua = (user_agent or "").strip().lower()
    if not ua:
        return "unknown"
    for lang, tokens in _UA_SIGNATURES:
        if any(tok in ua for tok in tokens):
            return lang
    return "unknown"


def _tally_path():
    from .paths import data_dir
    # Shared root: the decision is about the whole install, across tenants.
    return data_dir("analytics", "mcp_clients.json", tenant=None)


def _load() -> dict:
    try:
        data = json.loads(_tally_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def record_client(user_agent: str | None) -> None:
    """Tally one MCP client by language bucket. No-op unless consent is on; the
    whole function is fail-soft (analytics must never break a request)."""
    if not analytics_enabled():
        return
    try:
        from .file_lock import atomic_write_text, cross_process_lock
        lang = classify_user_agent(user_agent)
        path = _tally_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        # One locked read-modify-write with a unique temp file, so concurrent
        # requests neither lose a count nor collide on a shared temp name.
        with cross_process_lock(path):
            data = _load()
            data[lang] = int(data.get(lang, 0)) + 1
            atomic_write_text(path, json.dumps(data), mode=0o600)
    except Exception as e:  # pragma: no cover -- fully fail-soft
        log.debug("mcp analytics record failed: %s", e)


def client_language_counts() -> dict:
    """The recorded ``{language: count}`` tally (empty if never recorded)."""
    return {k: int(v) for k, v in _load().items() if k in LANGUAGES}


def non_python_share() -> float:
    """Fraction of recorded clients that are non-Python (0.0–1.0); 0.0 when
    nothing is recorded."""
    counts = client_language_counts()
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    return round((total - counts.get("python", 0)) / total, 4)


__all__ = [
    "analytics_enabled", "classify_user_agent", "record_client",
    "client_language_counts", "non_python_share", "LANGUAGES",
]
