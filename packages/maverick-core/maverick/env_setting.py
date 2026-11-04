"""One value that an environment variable or the settings can set.

Many runtime switches began life as ``MAVERICK_*`` environment variables
only, so changing them meant editing the server's environment. Each such
switch now also has a config key (``[section] key``) that the dashboard's
All settings page writes. :func:`env_or_config` returns the value exactly as
the old environment read did (text), so every call site keeps its own
parsing, defaults and clamping:

* the environment variable, when it is set to something other than blanks,
  always wins (deployments that pin a value keep it);
* otherwise ``[section] key`` from the merged configuration (installer file,
  dashboard overlay, operator overlay, workspace file) is returned as text:
  ``True``/``False`` become ``"1"``/``"0"`` and a list becomes comma-separated
  text, the forms the environment parsers already accept;
* otherwise ``default``.

An unreadable configuration never blocks a run: the default applies.
"""
from __future__ import annotations

import os


def env_or_config(env_name: str, section: str, key: str,
                  default: str | None = None) -> str | None:
    """The environment value, else ``[section] key`` as text, else ``default``."""
    raw = os.environ.get(env_name)
    if raw is not None and raw.strip():
        return raw
    try:
        from .config import load_config

        table = (load_config() or {}).get(section)
    except Exception:  # an unreadable configuration never blocks a run
        return default
    value = table.get(key) if isinstance(table, dict) else None
    if value is None or isinstance(value, dict):
        return default
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return str(value)


def env_or_config_int(env_name: str, section: str, key: str, default: int) -> int:
    """:func:`env_or_config` as a whole number; unreadable text gives ``default``."""
    raw = env_or_config(env_name, section, key)
    if raw is None:
        return default
    try:
        return int(str(raw).strip())
    except ValueError:
        try:
            number = float(str(raw).strip())
        except ValueError:
            return default
        return int(number) if number.is_integer() else default


def env_or_config_float(env_name: str, section: str, key: str, default: float) -> float:
    """:func:`env_or_config` as a number; unreadable text gives ``default``."""
    raw = env_or_config(env_name, section, key)
    if raw is None:
        return default
    try:
        return float(str(raw).strip())
    except ValueError:
        return default


__all__ = ["env_or_config", "env_or_config_float", "env_or_config_int"]
