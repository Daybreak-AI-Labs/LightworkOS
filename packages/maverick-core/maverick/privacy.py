"""Anonymous mode: strip user-identifying content from logs.

When ``MAVERICK_ANON=1`` (env) or ``[privacy] anonymous = true``
(config), structured logs + audit events have their identifying
fields replaced with hashes or sentinels.

Categories scrubbed:
  - goal text (title + description)
  - user_id / channel
  - file paths under user's home (keep just the basename)
  - email addresses, phone numbers, SSNs (via pii_detector)

Use:

    from maverick.privacy import anonymize_field, anonymize_dict, anon_enabled

    if anon_enabled():
        log_line = anonymize_dict(log_line)
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_anon_salt_lock = threading.Lock()
_anon_salt_cache: bytes | None = None


def _anon_salt() -> bytes:
    """A persistent per-deployment secret salt for the anonymization HMAC.

    Generated once (32 random bytes) and stored 0600 under the shared,
    un-namespaced home. Without a secret key the old ``sha256(value)`` mapping
    was rainbow-tableable for common identifiers (alice, user-1...). If the salt
    can't be persisted (read-only fs) we fall back to a process-stable random
    salt -- still defeats precomputation, just not stable across restarts.
    """
    global _anon_salt_cache
    if _anon_salt_cache is not None:
        return _anon_salt_cache
    with _anon_salt_lock:
        if _anon_salt_cache is not None:
            return _anon_salt_cache
        try:
            from .file_lock import (
                atomic_read_bytes,
                atomic_write_bytes,
                cross_process_lock,
                ensure_private_directory,
                ensure_private_file,
            )
            from .paths import data_dir

            p = data_dir("keys", "anon.salt", tenant=None)
            ensure_private_directory(p.parent)
            with cross_process_lock(p):
                try:
                    ensure_private_file(p)
                    existing = atomic_read_bytes(p)
                except FileNotFoundError:
                    existing = b""
                if len(existing) >= 16:
                    _anon_salt_cache = existing
                    return _anon_salt_cache
                salt = os.urandom(32)
                atomic_write_bytes(p, salt)
                _anon_salt_cache = salt
        except Exception:  # pragma: no cover -- read-only fs / unwritable home
            _anon_salt_cache = os.urandom(32)
        return _anon_salt_cache


_SENSITIVE_KEYS = frozenset({
    # "text" covers Anthropic/OpenAI content blocks ({"type": "text",
    # "text": ...}) nested under a message's "content" list -- without it the
    # actual message text leaked unscrubbed in anon mode.
    "goal_text", "title", "description", "content", "text",
    "prompt", "system", "messages", "answer", "msg", "message",
    "input_summary", "output_summary", "detail", "reason",
    "channel", "user_id", "goal_id", "conversation_id", "from", "to",
    "email", "username", "principal", "decided_by", "claimed_by", "created_by",
    "result", "summary",
})

_OPAQUE_TEXT_KEYS = frozenset({"goal_text", "title", "description"})

_IDENTITY_KEYS = frozenset({
    "user_id", "username", "channel", "goal_id", "conversation_id",
    "from", "to", "email",
    # Human/API principals that may contain stable user IDs or email-like
    # strings (for example ``user:alice@example.com``).
    "principal", "decided_by", "claimed_by", "created_by",
})


def _home_pattern() -> re.Pattern[str]:
    return re.compile(re.escape(str(Path.home())))


def anon_enabled() -> bool:
    """True if anonymous mode is on or required by an active compliance profile."""
    try:
        from .compliance_profiles import FLOOR_PII_REDACTION, requires_floor
        if requires_floor(FLOOR_PII_REDACTION):
            return True
    except Exception:
        pass
    val = os.environ.get("MAVERICK_ANON", "").strip().lower()
    if val in {"1", "true", "yes", "on"}:
        return True
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("privacy") or {}
        val = cfg.get("anonymous")
        # A TOML string "false"/"no" is truthy under bool(); honor it the way
        # a2a_enabled does so an explicit off-string disables anon mode.
        if isinstance(val, str):
            return val.strip().lower() in {"1", "true", "yes", "on"}
        return bool(val)
    except Exception:
        return False


def _hash_id(value: str, prefix: str = "") -> str:
    """Stable, non-reversible 12-char hash; prefix tags the field type.

    HMAC-keyed with a persistent per-deployment salt and mixed with the active
    tenant, so the mapping is non-invertible even against a small candidate set
    (the old unsalted sha256 was rainbow-tableable) and the SAME id under two
    tenants hashes differently (no cross-tenant correlation in anon logs). Still
    deterministic within a deployment+tenant, so legitimate same-user
    correlation is preserved.
    """
    if not value:
        return "(empty)"
    from .paths import current_tenant_id
    tenant = current_tenant_id() or ""
    msg = f"{tenant}\x00{prefix}\x00{value}".encode()
    h = hmac.new(_anon_salt(), msg, hashlib.sha256).hexdigest()[:12]
    return f"{prefix}#{h}" if prefix else f"#{h}"


def anonymize_text(text: str) -> str:
    """Strip home-path, PII, and obviously-identifying strings."""
    if not text:
        return text
    out = _home_pattern().sub("~", text)
    # Replace email-like patterns + phones via pii_detector if available.
    try:
        from .safety.pii_detector import redact
        out, _ = redact(out)
    except Exception:
        pass
    return out


def anonymize_field(key: str, value: Any) -> Any:
    """Apply per-field anonymization rules.

    - Identity fields (user_id / channel / email / etc.): hash.
    - Goal text fields (title / description / goal_text): hash.
    - Other sensitive text fields (content / summary / msg): scrub PII + paths.
    - Path fields: keep only the basename.
    - Anything else: return as-is.
    """
    lower = key.lower()
    if lower in _IDENTITY_KEYS:
        return _hash_id(value, prefix=lower)
    if lower in _OPAQUE_TEXT_KEYS:
        return _hash_id(value, prefix=lower)
    if lower in ("path", "filepath", "filename"):
        try:
            return Path(str(value)).name
        except (TypeError, ValueError):
            return value
    if lower in _SENSITIVE_KEYS:
        if isinstance(value, str):
            return anonymize_text(value)
        if isinstance(value, list):
            return [
                anonymize_text(v) if isinstance(v, str)
                else (anonymize_dict(v) if isinstance(v, dict) else v)
                for v in value
            ]
        if isinstance(value, dict):
            return anonymize_dict(value)
    if isinstance(value, dict):
        return anonymize_dict(value)
    if isinstance(value, list):
        return [anonymize_dict(v) if isinstance(v, dict) else v for v in value]
    return value


def anonymize_dict(d: dict) -> dict:
    """Return a new dict with sensitive fields scrubbed."""
    if not d:
        return d
    return {k: anonymize_field(k, v) for k, v in d.items()}


def audit_subject_matches(event: dict, channel: str, user_id: str) -> bool:
    """Match raw or HMAC-anonymized structured audit subject fields."""
    observed = (event.get("channel"), event.get("user_id"))
    if observed == (channel, user_id):
        return True
    if not (isinstance(observed[0], str) and observed[0].startswith("channel#")
            and isinstance(observed[1], str) and observed[1].startswith("user_id#")):
        return False
    return observed == (anonymize_field("channel", channel), anonymize_field("user_id", user_id))


def anonymize_iter(items: Iterable[dict]) -> list[dict]:
    return [anonymize_dict(d) for d in items]


__all__ = [
    "anon_enabled",
    "anonymize_text",
    "anonymize_field",
    "anonymize_dict",
    "audit_subject_matches",
    "anonymize_iter",
]
