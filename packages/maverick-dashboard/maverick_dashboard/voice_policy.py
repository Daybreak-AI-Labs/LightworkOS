"""Runtime policy for dashboard voice-command input."""
from __future__ import annotations

import os


def voice_commands_enabled() -> bool:
    """Respect the environment override, then the default-on voice setting."""
    raw = (os.environ.get("MAVERICK_VOICE_COMMANDS") or "").strip().lower()
    if raw:
        return raw not in {"0", "false", "no", "off"}
    try:
        from maverick.config import load_config

        return bool((load_config().get("voice") or {}).get("dashboard_commands", True))
    except Exception:  # pragma: no cover -- config never blocks the endpoint
        return True
