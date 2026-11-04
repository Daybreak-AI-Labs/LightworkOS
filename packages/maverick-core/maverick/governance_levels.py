"""Governance levels: what each level the installer offers sets.

``maverick init`` asks one onboarding question (essentials, standard or
regulated) and writes the settings that level stands for -- the learning
lifecycle, signed and tamper-proof records, fairness and memory checks, human
sign-off, how long records are kept -- plus ``[governance] profile`` as a label.

The installer is the source of truth for that expansion (kernel rule 6), so
this module never keeps its own copy: :func:`level_settings` renders the
installer's own sections for a level and returns them as key paths, so the
dashboard can preview a level and apply it through its normal, confirmed and
recorded settings save. When the installer is not installed on this server
the level cannot be expanded and :class:`GovernanceLevelUnavailable` says so.
"""
from __future__ import annotations

from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

LEVELS: tuple[str, ...] = ("essentials", "standard", "regulated")


class GovernanceLevelUnavailable(RuntimeError):
    """The installer that defines the levels is not installed here."""


def current_level() -> str:
    """The level recorded in ``[governance] profile`` ("" when none is)."""
    try:
        from .config import load_config

        section = (load_config() or {}).get("governance") or {}
    except Exception:  # an unreadable configuration names no level
        return ""
    value = section.get("profile") if isinstance(section, dict) else None
    return value if value in LEVELS else ""


def _flatten(table: dict[str, Any], prefix: tuple[str, ...] = ()) -> dict[tuple[str, ...], Any]:
    out: dict[tuple[str, ...], Any] = {}
    for key, value in table.items():
        path = (*prefix, str(key))
        if isinstance(value, dict):
            out.update(_flatten(value, path))
        else:
            out[path] = value
    return out


def level_settings(level: str) -> dict[tuple[str, ...], Any]:
    """Every setting the installer writes for ``level``, as ``{key path: value}``.

    Raises ``ValueError`` for an unknown level and
    :class:`GovernanceLevelUnavailable` when the installer is missing."""
    if level not in LEVELS:
        raise ValueError(f"unknown governance level: {level!r}")
    try:
        from maverick_installer import wizard
    except ImportError as exc:
        raise GovernanceLevelUnavailable(
            "the Lightwork installer is not installed on this server"
        ) from exc
    preset = wizard.GOVERNANCE_PROFILES[level]
    lines: list[str] = []
    lines += wizard._cfg_governance(level, None)
    lines += wizard._cfg_self_learning(dict(preset["self_learning"]))
    lines += wizard._cfg_advanced(dict(preset["advanced"]), [])
    lines += wizard._cfg_table("retention", dict(preset["retention"]))
    return _flatten(tomllib.loads("\n".join(lines)))


__all__ = ["LEVELS", "GovernanceLevelUnavailable", "current_level", "level_settings"]
