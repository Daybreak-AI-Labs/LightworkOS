"""Installed versions and the encryption-key fingerprint.

The facts behind ``maverick version`` and ``maverick shared-key-digest``, kept
here so the terminal commands and the dashboard's Settings > Maintenance panels
read them the same way.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import os
import sys
from typing import Any

# (display name, candidate distribution names). PyPI distribution name for the
# core is `maverick-agent` (the `maverick` name was squatted). Fall back to
# `maverick` if the squatter ever releases the original name.
PACKAGES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("maverick-agent", ("maverick-agent", "maverick")),
    ("maverick-shield", ("maverick-shield",)),
    ("maverick-channels", ("maverick-channels",)),
    ("maverick-evolve", ("maverick-evolve",)),
    ("maverick-dashboard", ("maverick-dashboard",)),
    ("maverick-mcp-server", ("maverick-mcp-server",)),
    ("maverick-knowledge", ("maverick-knowledge",)),
    ("maverick-installer", ("maverick-installer",)),
)


def package_versions() -> list[tuple[str, str | None]]:
    """``(display name, version or None)`` for every Lightwork package."""
    out: list[tuple[str, str | None]] = []
    for display, candidates in PACKAGES:
        version = None
        for candidate in candidates:
            try:
                version = importlib.metadata.version(candidate)
                break
            except importlib.metadata.PackageNotFoundError:
                continue
        out.append((display, version))
    return out


def native_acceleration_status(unicode_filter: Any, perceptual_hash: Any) -> dict[str, str]:
    """Describe the optional native wrappers selected when each module loaded.

    The wrappers can still fall back to Python for an individual input if
    the native function raises; this reports availability, not a speed claim.
    """
    unicode_native = getattr(unicode_filter, "_native", None)
    image_native = getattr(perceptual_hash, "_native", None)
    return {
        "unicode": "native with Python fallback" if (
            callable(getattr(unicode_native, "normalize", None))
            and callable(getattr(unicode_filter, "_normalize_py", None))
        ) else "Python",
        "image_hash": "native with Python fallback" if (
            callable(getattr(image_native, "average_hash_from_pixels", None))
            and callable(getattr(perceptual_hash, "_average_hash_from_pixels_py", None))
        ) else "Python",
    }


def runtime_facts() -> dict[str, Any]:
    """Runtime details shown under "Runtime" by ``maverick version``.

    ``schema``, ``providers`` and ``persona`` are None when they could not be
    read (the command then leaves that line out). ``shield_backend`` is None
    when the shield package is not installed.
    """
    facts: dict[str, Any] = {"schema": None, "shield_backend": None, "providers": None,
                             "persona": None, "python": sys.version.split()[0],
                             "platform": sys.platform}
    try:
        from .world_model import SCHEMA_VERSION
        facts["schema"] = SCHEMA_VERSION
    except Exception:
        pass
    try:
        from maverick_shield import Shield
        # warn_if_missing=False: the caller prints the backend itself, so the
        # raw "SDK not installed" log line would just bleed into the output.
        facts["shield_backend"] = Shield.from_config(warn_if_missing=False).backend
    except ImportError:
        facts["shield_backend"] = None
    try:
        from .providers import KNOWN_PROVIDERS
        facts["providers"] = list(KNOWN_PROVIDERS)
    except Exception:
        pass
    try:
        from .persona import load_persona
        facts["persona"] = dict(load_persona())
    except Exception:
        pass
    try:
        from . import perceptual_hash
        from .safety import unicode_filter
        facts["native_acceleration"] = native_acceleration_status(unicode_filter, perceptual_hash)
    except Exception:
        facts["native_acceleration"] = None
    return facts


class KeyDigestError(RuntimeError):
    """The injected at-rest key is missing (``reason="unset"``) or cannot be
    decoded (``reason="undecodable"``)."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def encryption_key_digest(environ: dict[str, str] | None = None) -> str:
    """``sha256:<hex>`` of the injected at-rest key.

    This is the value to set as MAVERICK_ENCRYPTION_KEY_DIGEST -- the operator
    trust anchor a Postgres (shared-authority) deployment requires for governed
    records. A one-way hash of the key, never the key itself. Reads the key
    from the process environment exactly as crypto_at_rest does.
    """
    from .crypto_at_rest import _KEY_ENV, _decode_injected_key

    env = os.environ if environ is None else environ
    raw = env.get(_KEY_ENV, "")
    if not raw.strip():
        raise KeyDigestError("unset", f"{_KEY_ENV} is not set in this environment")
    try:
        key = _decode_injected_key(raw)
    except Exception as exc:  # noqa: BLE001 -- the decoder's own reason is kept
        raise KeyDigestError("undecodable", f"cannot decode {_KEY_ENV}: {exc}") from exc
    return "sha256:" + hashlib.sha256(key).hexdigest()


__all__ = ["PACKAGES", "package_versions", "runtime_facts", "native_acceleration_status", "KeyDigestError",
           "encryption_key_digest"]
