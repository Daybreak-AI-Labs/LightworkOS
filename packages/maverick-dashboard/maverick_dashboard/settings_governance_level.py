"""Apply a governance level from Settings > All settings.

Choosing a level (essentials, standard or regulated) and saving it applies
every setting the installer writes for that level, through the page's normal
save: each setting is validated, anything that lowers a protection is listed
for confirmation, a value set in the server's deployment settings is left
alone, and each change writes its own activity-record entry. The learning
systems a level turns on use the Learning page's own switch (with its own
record). :func:`preview` lists what a level would change before anything is
saved. The expansion itself comes from the installer
(:func:`maverick.governance_levels.level_settings`).
"""
from __future__ import annotations

from typing import Any

from . import settings_catalog as catalog

SETTING_ID = "governance.profile"
# A level sets single values; a table or document is never replaced by one.
_SIMPLE = frozenset({"toggle", "number", "select", "text", "list", "multiselect"})


class Unavailable(Exception):
    """The level cannot be expanded on this server (plain sentence)."""


def _expansion(level: str) -> tuple[list[tuple[catalog.Setting, Any]], list[dict]]:
    """The catalog settings and learning switches the installer writes."""
    from maverick.governance_levels import GovernanceLevelUnavailable, level_settings

    from . import settings_store

    try:
        values = level_settings(level)
    except GovernanceLevelUnavailable as exc:
        raise Unavailable(
            "Applying a governance level needs the Lightwork installer on this server. "
            "Install it, or change the settings one by one."
        ) from exc
    by_path = {s.path: s for s in catalog.SETTINGS if s.key_kind == "key"}
    switches = {(spec["section"], spec["config_key"]): spec
                for spec in settings_store.LEARNING_SUBSYSTEMS}
    settings: list[tuple[catalog.Setting, Any]] = []
    learning: list[dict] = []
    for path, value in values.items():
        setting = by_path.get(path)
        if setting is not None and setting.id != SETTING_ID and setting.control in _SIMPLE:
            settings.append((setting, value))
        elif path in switches and value is True:
            learning.append(switches[path])
    return settings, learning


def _switch_off(spec: dict) -> bool:
    """True when a learning system is explicitly off here (the level turns it on)."""
    import os

    from maverick.config import load_config

    if spec.get("env") and os.environ.get(spec["env"], "").strip():
        return False  # the server's deployment settings decide it
    section = (load_config() or {}).get(spec["section"])
    return isinstance(section, dict) and section.get(spec["config_key"]) is False


def expand(body: Any, change_type: type) -> tuple[Any, list[dict]]:
    """``body`` with the chosen level's settings added, and the learning
    systems to turn on after the save. Unchanged when no level is chosen."""
    from . import settings_all_page as page

    chosen = next((item for item in body.changes if item.id == SETTING_ID), None)
    if chosen is None or chosen.reset or not chosen.value:
        return body, []
    from maverick.governance_levels import LEVELS

    if chosen.value not in LEVELS:
        return body, []  # the save refuses an unknown level itself
    settings, learning = _expansion(str(chosen.value))
    layers = page._sources()
    named = {item.id for item in body.changes}
    extra = []
    for setting, value in settings:
        if setting.id in named or page._resolve(setting, layers)["locked"]:
            continue
        extra.append(change_type(id=setting.id, value=page._form_value(setting, value)))
    return body.model_copy(update={"changes": [*body.changes, *extra]}), [
        spec for spec in learning if _switch_off(spec)]


def confirm_items(learning: list[dict]) -> list[dict]:
    return [{"id": f"learning.{spec['key']}", "label": spec["label"], "kind": "learning",
             "warning": "This learning system will be turned on."} for spec in learning]


def turn_on(learning: list[dict], actor: str) -> None:
    from . import settings_store

    for spec in learning:
        settings_store.set_learning_subsystem(spec["key"], True, actor=actor)


def preview(level: str) -> dict[str, Any]:
    """What saving ``level`` would change, in plain words (nothing is saved)."""
    from maverick.governance_levels import LEVELS

    from . import settings_all_page as page

    if level not in LEVELS:
        return {"items": [], "unchanged": 0, "kept": []}
    settings, learning = _expansion(level)
    layers = page._sources()
    items, kept, unchanged = [], [], 0
    for setting, value in settings:
        state = page._resolve(setting, layers)
        if state["locked"]:
            kept.append(setting.label)
            continue
        try:
            new = catalog.coerce(page._resolved(setting, state["value"]),
                                 page._form_value(setting, value))
        except catalog.SettingError:
            kept.append(setting.label)
            continue
        if new == state["value"]:
            unchanged += 1
            continue
        items.append({
            "id": setting.id, "label": setting.label,
            "now": catalog.display_value(setting, state["value"]),
            "new": catalog.display_value(setting, new),
            "lowers": catalog.weakens(setting, state["value"], new),
        })
    for spec in learning:
        if _switch_off(spec):
            items.append({"id": f"learning.{spec['key']}", "label": spec["label"],
                          "now": "Off", "new": "On", "lowers": False})
        else:
            unchanged += 1
    return {"items": items, "unchanged": unchanged, "kept": kept}


__all__ = ["SETTING_ID", "Unavailable", "confirm_items", "expand", "preview", "turn_on"]
