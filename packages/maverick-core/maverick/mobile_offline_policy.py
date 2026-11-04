"""The effective offline cache ceiling: workspace policy can only narrow it."""
from __future__ import annotations

import hashlib
import json

MAX_AGE_SECONDS = 86400
MAX_BYTES = 2 * 1024 * 1024


def _section(config: dict) -> tuple[bool, int, int]:
    value = config.get("mobile_offline", {})
    if not isinstance(value, dict):
        raise ValueError("Offline policy is unavailable")
    allowed = value.get("enabled", True)
    age, size = value.get("max_age_seconds", MAX_AGE_SECONDS), value.get("max_bytes", MAX_BYTES)
    if (not isinstance(allowed, bool) or type(age) is not int or type(size) is not int
            or not 0 <= age <= MAX_AGE_SECONDS or not 0 <= size <= MAX_BYTES):
        raise ValueError("Offline policy is unavailable")
    return allowed and age > 0 and size > 0, age, size


def effective_policy() -> dict:
    from . import config
    try:
        if config.config_source_errors(include_tenant=True):
            raise ValueError("Offline policy is unavailable")
        organization = _section(config.load_global_config())
        workspace = _section(config.load_config())
        allowed = organization[0] and workspace[0]
        age, size = min(organization[1], workspace[1]), min(organization[2], workspace[2])
        reason = "Organization policy allows a bounded offline copy." if allowed else "Offline saving is disabled by your organization."
    except (OSError, ValueError, TypeError):
        allowed, age, size = False, 0, 0
        reason = "Offline saving is unavailable until organization policy can be checked."
    policy = {"allowed": allowed, "max_age_seconds": age, "max_bytes": size}
    return {**policy, "revision": hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest(), "message": reason}
