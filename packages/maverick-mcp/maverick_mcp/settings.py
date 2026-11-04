"""Tool server settings: a ``MAVERICK_MCP_*`` environment variable or ``[mcp] <key>``.

Every limit and switch of the tool server for outside apps has an environment
variable and a key in the ``[mcp]`` section, which Settings > All settings
writes. Precedence: the environment variable when set, then the ``[mcp]`` key,
then the built-in default. (``[mcp] elicit_allowed_hosts`` was already a setting and is read
in :mod:`maverick_mcp.server`.)
"""
from __future__ import annotations

# ``[mcp]`` key -> the environment variable that overrides it.
ENV: dict[str, str] = {
    "token": "MAVERICK_MCP_TOKEN",
    "max_body_bytes": "MAVERICK_MCP_MAX_BODY",
    "max_resource_sessions": "MAVERICK_MCP_MAX_RESOURCE_SESSIONS",
    "allowed_origins": "MAVERICK_MCP_ALLOWED_ORIGINS",
    "http_tasks": "MAVERICK_MCP_HTTP_TASKS",
    "rate_limit": "MAVERICK_MCP_RATE_LIMIT",
    "sse_heartbeat": "MAVERICK_MCP_SSE_HEARTBEAT",
    "sse_max_progress_events": "MAVERICK_MCP_SSE_MAX_PROGRESS_EVENTS",
    "max_dollars": "MAVERICK_MCP_MAX_DOLLARS",
    "max_wall_seconds": "MAVERICK_MCP_MAX_WALL_SECONDS",
    "elicitation_timeout": "MAVERICK_MCP_ELICITATION_TIMEOUT",
    "max_depth": "MAVERICK_MCP_MAX_DEPTH",
    "max_elicit_rounds": "MAVERICK_MCP_MAX_ELICIT_ROUNDS",
    "max_tasks": "MAVERICK_MCP_MAX_TASKS",
    "max_tasks_per_owner": "MAVERICK_MCP_MAX_TASKS_PER_OWNER",
    "task_ttl_ms": "MAVERICK_MCP_TASK_TTL_MS",
    "task_max_ttl_ms": "MAVERICK_MCP_TASK_MAX_TTL_MS",
    "task_poll_ms": "MAVERICK_MCP_TASK_POLL_MS",
    "task_result_block_ms": "MAVERICK_MCP_TASK_RESULT_BLOCK_MS",
    "task_workers": "MAVERICK_MCP_TASK_WORKERS",
}


def mcp_setting(key: str, default: str | None = None) -> str | None:
    """The environment value, else ``[mcp] <key>`` as text, else ``default``."""
    from maverick.env_setting import env_or_config

    return env_or_config(ENV[key], "mcp", key, default)


__all__ = ["ENV", "mcp_setting"]
