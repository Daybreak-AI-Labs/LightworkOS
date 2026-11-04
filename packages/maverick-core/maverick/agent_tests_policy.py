"""The ``[agent_tests]`` switches for the saved answer checks that gate publishing.

``max_cases_per_specialist`` (1 to 200, default 20): how many saved checks one
specialist may hold, and how many one run may check at once. Lowering it never
deletes a saved check; a publish that needs every check on one run waits until
the set fits again.

``require_for_new_specialists`` (default off): a specialist with no published
version cannot be published until it has a saved check and a passing full run
of those checks on exactly the draft being published. No reason overrides it.

``bypass_requires_second_person`` (default off): publishing changed instructions
without a passing run, with a reason, needs another administrator's approval of
that reason first.

``tool_checks`` (default off): lets a saved check ask which tools the specialist
calls. Those checks run against recording stubs only, never the real tools. Off
means such checks cannot be created and are skipped, never counted as passing.

``canary_percent`` (0 to 50, default 0 = off): when above 0, publishing a CHANGED
existing specialist makes the new version a canary candidate instead of replacing
the current one. That share of new goals (chosen by goal id) uses the candidate.
A value that is not a whole number in range reads as 0.

``canary_auto_rollback`` (default off): roll the candidate back automatically once
enough candidate goals have finished and it fails clearly more often than the
current version. Only a true value turns it on; unreadable settings or a value
that is not true leave it off, because this switch acts without a person.

Unreadable settings keep the stricter reading for ``require_for_new_specialists``
and ``bypass_requires_second_person`` and the default for the number. Either of
those switches whose value is not true or false is read as on; ``tool_checks`` and
``canary_auto_rollback`` are only ever on when exactly true.
Publishing is turned away while settings cannot be read, before anything changes,
so an unreadable file cannot publish a changed specialist straight to everyone.
"""
from __future__ import annotations

from .config_contracts import BOOLEAN_SETTINGS, INTEGER_SETTINGS

DEFAULT_MAX_CASES = INTEGER_SETTINGS["agent_tests.max_cases_per_specialist"].default
MAX_CASES_LIMIT = INTEGER_SETTINGS["agent_tests.max_cases_per_specialist"].maximum
MAX_CANARY_PERCENT = INTEGER_SETTINGS["agent_tests.canary_percent"].maximum
_UNREADABLE = object()
NEW_SPECIALIST_NEEDS_TESTS = (
    "A new specialist needs at least one saved check and a full passing run of those checks on its exact draft "
    "before it can be added. Create it in Agent Factory, add checks in Workforce, run them on the draft, then "
    "publish it there. Nothing was saved.")


class NewSpecialistNeedsTests(PermissionError):
    """A specialist with no published version cannot be saved while ``require_for_new_specialists`` is on."""


def _section():
    """The ``[agent_tests]`` table, ``{}`` when absent, or ``_UNREADABLE``."""
    try:
        from .config import config_source_errors, load_config

        config = load_config()
        if config_source_errors() or not isinstance(config, dict):
            return _UNREADABLE
        section = config.get("agent_tests")
        if section is None:
            return {}
        return section if isinstance(section, dict) else _UNREADABLE
    except Exception:  # unreadable settings keep the stricter reading
        return _UNREADABLE


def _switch(key: str) -> bool:
    section = _section()
    if section is _UNREADABLE:
        return True
    value = section.get(key, BOOLEAN_SETTINGS[f"agent_tests.{key}"].default)
    return value if isinstance(value, bool) else True


def max_cases_per_specialist() -> int:
    """The ``[agent_tests] max_cases_per_specialist`` knob."""
    section = _section()
    if section is _UNREADABLE:
        return DEFAULT_MAX_CASES
    value = section.get("max_cases_per_specialist", DEFAULT_MAX_CASES)
    minimum = INTEGER_SETTINGS["agent_tests.max_cases_per_specialist"].minimum
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= MAX_CASES_LIMIT:
        return DEFAULT_MAX_CASES
    return value


def require_for_new_specialists() -> bool:
    """The ``[agent_tests] require_for_new_specialists`` knob."""
    return _switch("require_for_new_specialists")


def bypass_requires_second_person() -> bool:
    """The ``[agent_tests] bypass_requires_second_person`` knob."""
    return _switch("bypass_requires_second_person")


def tool_checks_enabled() -> bool:
    """The ``[agent_tests] tool_checks`` knob: on only when exactly ``true``; unreadable settings keep it off."""
    section = _section()
    if section is _UNREADABLE:
        return False
    return section.get("tool_checks", BOOLEAN_SETTINGS["agent_tests.tool_checks"].default) is True


def canary_percent() -> int:
    """The ``[agent_tests] canary_percent`` knob: 0 (off) or a whole share from 1 to 50."""
    section = _section()
    if section is _UNREADABLE:
        return 0  # An unreadable policy must not enable rollout.
    contract = INTEGER_SETTINGS["agent_tests.canary_percent"]
    value = section.get("canary_percent", contract.default)
    if isinstance(value, bool) or not isinstance(value, int) or not contract.minimum <= value <= MAX_CANARY_PERCENT:
        return 0  # An invalid policy must not enable rollout.
    return value


def canary_auto_rollback() -> bool:
    """The ``[agent_tests] canary_auto_rollback`` knob: on only when it is set to true."""
    section = _section()
    if section is _UNREADABLE:
        return False
    return section.get("canary_auto_rollback", BOOLEAN_SETTINGS["agent_tests.canary_auto_rollback"].default) is True


__all__ = ["DEFAULT_MAX_CASES", "MAX_CANARY_PERCENT", "MAX_CASES_LIMIT", "NEW_SPECIALIST_NEEDS_TESTS",
           "NewSpecialistNeedsTests", "bypass_requires_second_person", "canary_auto_rollback", "canary_percent",
           "max_cases_per_specialist", "require_for_new_specialists", "tool_checks_enabled"]
