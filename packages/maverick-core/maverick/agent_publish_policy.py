"""Whether changed instructions need a passing test run before they are published.

``[agent_factory] require_passing_tests`` (default on). When on, saving new
instructions for an existing agent or specialist needs a finished run of its
saved test set on exactly those instructions, with every answer passing. A
person can still publish without one, but only by giving a reason, which is
written to the activity record. Creating a new agent is not gated: it has no
saved tests yet and starts under supervision.
"""
from __future__ import annotations


def require_passing_tests() -> bool:
    """The ``[agent_factory] require_passing_tests`` knob. Unreadable settings
    keep the gate on: a broken config must not remove a safety check."""
    try:
        from .config import config_source_errors, load_config

        config = load_config()
        if config_source_errors() or not isinstance(config, dict):
            return True
        section = config.get("agent_factory")
        if section is None:
            return True
        if not isinstance(section, dict):
            return True
        value = section.get("require_passing_tests", True)
        return value if isinstance(value, bool) else True
    except Exception:  # unreadable settings keep the gate on
        return True


__all__ = ["require_passing_tests"]
