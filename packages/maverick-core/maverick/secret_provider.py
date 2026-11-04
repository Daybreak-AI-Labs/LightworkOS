"""Pluggable secret resolution.

A single seam for reading deployment secrets so they can be sourced from a
mounted vault instead of only the process environment. The default backend is
``env`` -- byte-for-byte the old ``os.environ.get`` behavior -- so existing
installs are unchanged.

The ``file`` backend reads Docker/Kubernetes-style secret files (one secret per
file under a directory). This is how Vault Agent, the Secrets Store CSI driver,
Docker secrets, and ``podman --secret`` deliver material: the orchestrator
writes ``<dir>/MAVERICK_OIDC_CLIENT_SECRET`` and the value never appears in the
process environment (so it can't leak via ``/proc/<pid>/environ``, ``ps -E``, a
crash dump, or a child process that inherits the env).

Resolution for a name, in order:
  1. the configured backend (``file``), if it holds the secret;
  2. the process environment -- always the final fallback, so partial vault
     adoption works (move the sensitive secrets to files, leave the rest in env).

Backend selection: ``MAVERICK_SECRETS_BACKEND`` env wins over ``[secrets]
backend`` in config; default ``env``. The file directory comes from
``MAVERICK_SECRETS_DIR`` env or ``[secrets] dir`` config.

Deliberately no ``command``/shell backend: the file backend covers every
mainstream vault-injection path without spawning a process, keeping this module
clear of the shell-execution rule (all shell goes through ``sandbox.exec``).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

# Backend names we actually implement. An unrecognized value (e.g. a typo
# like ``vault`` or ``files``) must not silently degrade to ``env`` without a
# trace -- that would defeat the file backend's whole leak-avoidance purpose
# for an operator who believes they pinned secrets to mounted files.
_KNOWN_BACKENDS = frozenset({"env", "file"})
_warned_backends: set[str] = set()

# Secret file names are validated against this before any path join, so a
# crafted name can never traverse out of the secrets dir. Matches the env-var
# shapes we actually look up (UPPER_SNAKE plus a lowercase fallback).
_SAFE_NAME = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"  # pragma: allowlist secret
)


def _normalize_backend(value: str) -> str:
    """Lower/strip ``value`` and validate it against the known backends.

    An unrecognized name is treated as ``env`` (the safe default) but warned
    about once, so a misspelled ``[secrets] backend`` -- which would otherwise
    silently disable file-based secret isolation -- is visible in the logs.
    """
    name = value.strip().lower()
    if name in _KNOWN_BACKENDS:
        return name
    if name not in _warned_backends:
        _warned_backends.add(name)
        log.warning(
            "unknown secrets backend %r; falling back to 'env' "
            "(known backends: %s)",
            name,
            ", ".join(sorted(_KNOWN_BACKENDS)),
        )
    return "env"


def _backend() -> str:
    env = os.environ.get("MAVERICK_SECRETS_BACKEND")
    if env is not None and env.strip() != "":
        return _normalize_backend(env)
    try:
        from .config import load_config
        v = (load_config() or {}).get("secrets", {}).get("backend")
    except Exception:  # pragma: no cover -- config never blocks a secret read
        v = None
    return _normalize_backend(str(v)) if v else "env"


def _secrets_dir() -> Path | None:
    raw = os.environ.get("MAVERICK_SECRETS_DIR")
    if not raw or not raw.strip():
        try:
            from .config import load_config
            raw = (load_config() or {}).get("secrets", {}).get("dir")
        except Exception:  # pragma: no cover
            raw = None
    if not raw or not str(raw).strip():
        return None
    return Path(str(raw)).expanduser()


def _safe(name: str) -> bool:
    return bool(name) and all(ch in _SAFE_NAME for ch in name)


def _from_file(name: str) -> str | None:
    """Read ``<dir>/<name>`` (or its lowercase sibling). Returns the trimmed
    contents, or ``None`` if the file is absent/unreadable. A trailing newline
    -- which ``printf '%s\\n' >secret`` and most editors add -- is stripped so
    the value matches what an env var would carry."""
    base = _secrets_dir()
    if base is None or not _safe(name):
        return None
    for candidate in (name, name.lower()):
        if not _safe(candidate):
            continue
        path = base / candidate
        try:
            if path.is_file():
                return path.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as e:  # unreadable file: fall through to env
            log.warning("secret file %s unreadable (%s); falling back to env", path, e)
    return None


def get_secret(name: str, default: str | None = None) -> str | None:
    """Resolve secret ``name`` from the configured backend, then the env.

    Mirrors ``os.environ.get(name, default)`` exactly under the default ``env``
    backend. Under the ``file`` backend a mounted secret file wins, with the
    process environment as the fallback so a partial migration is safe.
    """
    if _backend() == "file":
        val = _from_file(name)
        if val is not None:
            return val
    return os.environ.get(name, default)


def get_secret_or_saved(name: str, saved: object = None) -> str | None:
    """Resolve ``name`` like :func:`get_secret`, then fall back to ``saved``.

    ``saved`` is a key an administrator stored (sealed) in the dashboard
    settings, already opened by ``load_config``. A value the server holds for
    ``name`` always wins, so a deployment secret is never overridden from the
    app it protects.
    """
    value = get_secret(name) if name else None
    if value:
        return value
    return saved if isinstance(saved, str) and saved else None


__all__ = ["get_secret", "get_secret_or_saved"]
