"""Bound libpq connection attempts without replacing operator connection options."""
from __future__ import annotations

import os
import re


def configured(env: str, key: str, default: object) -> object:
    """``env`` when set, else ``[world_model] <key>`` (settable on the
    dashboard's All settings page), else ``default``."""
    raw = os.environ.get(env)
    if raw is not None and raw.strip() != "":
        return raw
    try:
        from .config import load_config

        table = (load_config() or {}).get("world_model") or {}
    except Exception:  # an unreadable config keeps the default
        return default
    value = table.get(key) if isinstance(table, dict) else None
    return default if value is None else value


def postgres_connect_timeout(requested: object = None) -> int:
    """Return a finite per-host timeout, including for reconnects and pool workers.

    libpq's omitted/nonpositive timeout means an indefinite wait. A shorter
    DSN or PGCONNECT_TIMEOUT value is retained; the operator's Lightwork cap
    defaults to ten seconds and can be configured from two to 300 seconds.
    The configured minimum is two seconds; this limit applies to each host.
    """
    try:
        cap = int(configured("MAVERICK_PG_CONNECT_TIMEOUT_SECONDS", "connect_timeout_seconds", 10))
    except (TypeError, ValueError):
        cap = 10
    if not 2 <= cap <= 300:
        cap = 10
    if requested is None:
        requested = os.environ.get("PGCONNECT_TIMEOUT", "")
    try:
        seconds = int(requested)
    except (TypeError, ValueError, OverflowError):
        return cap
    return min(cap, max(2, seconds)) if seconds > 0 else cap


def postgres_connection_kwargs(dsn: str) -> dict:
    """Preserve libpq/TLS options and share the bounded connection policy."""
    from psycopg.conninfo import conninfo_to_dict

    parameters = conninfo_to_dict(dsn)
    options = parameters.get("options", os.environ.get("PGOPTIONS", ""))
    defaults = (
        ("statement_timeout", "MAVERICK_PG_STATEMENT_TIMEOUT_MS", "statement_timeout_ms", 30_000),
        ("idle_in_transaction_session_timeout", "MAVERICK_PG_IDLE_TX_TIMEOUT_MS",
         "idle_tx_timeout_ms", 60_000),
    )
    additions = []
    for setting, env_name, key, default in defaults:
        if re.search(r"(?:^|\s)(?:-c\s*|--)?" + setting + r"\s*=", options):
            continue
        try:
            timeout = int(configured(env_name, key, default))
        except (TypeError, ValueError):
            timeout = default
        if not 0 <= timeout <= 2_147_483_647:
            timeout = default
        additions.append(f"-c {setting}={timeout}")
    return {
        "autocommit": False,
        "options": " ".join([options, *additions]).strip(),
        "connect_timeout": postgres_connect_timeout(parameters.get("connect_timeout")),
    }
