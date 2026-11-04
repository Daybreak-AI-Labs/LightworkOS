"""Who owns each compliance protection that needs action, and by when.

The control-coverage report (:func:`maverick.compliance.compliance_report`)
is recomputed live each time; it has no place to keep people or dates. This
small per-workspace file (``<data>/compliance-control-owners.json``) does:
one entry per protection name with its owner, due date, and who set them and
when. The route that saves an entry writes an activity-record row.

Steps to fix a protection come from the page's own guide (the same button the
page offers), so they never drift from what the page can actually do.
"""
from __future__ import annotations

import json
import re
import time
from datetime import date

from maverick.file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from maverick.paths import data_dir

_FORMAT = "lightwork-compliance-owners-v1"
_MAX_ENTRIES = 500
_CONTROL = re.compile(r"^[^\x00-\x1f\x7f]{1,200}$")


class OwnerError(ValueError):
    """A plain reason an owner or due date cannot be saved."""


def _path():
    return data_dir("compliance-control-owners.json")


def load() -> dict[str, dict]:
    path = _path()
    if not path.exists():
        return {}
    try:
        data = json.loads(atomic_read_text(path))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("format") != _FORMAT or not isinstance(data.get("controls"), dict):
        return {}
    return {k: v for k, v in data["controls"].items() if isinstance(v, dict)}


def _due(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    try:
        return date.fromisoformat(text).isoformat()
    except ValueError as exc:
        raise OwnerError("Choose a due date.") from exc


def save(control: str, *, owner: str, due: str, actor: str, known: set[str]) -> dict:
    """Set (or, with neither, clear) the owner and due date of one protection."""
    name = (control or "").strip()
    if not _CONTROL.fullmatch(name) or name not in known:
        raise OwnerError("Choose a protection from the list.")
    who = (owner or "").strip()
    if len(who) > 1024 or any(ord(ch) < 32 for ch in who):
        raise OwnerError("Choose an owner.")
    entry = {"owner": who, "due": _due(due), "set_by": actor or "local", "set_at": time.time()}
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path):
        controls = load()
        if not entry["owner"] and not entry["due"]:
            controls.pop(name, None)
        else:
            if name not in controls and len(controls) >= _MAX_ENTRIES:
                raise OwnerError("There are too many saved owners. Clear some first.")
            controls[name] = entry
        atomic_write_text(path, json.dumps({"format": _FORMAT, "controls": controls}, sort_keys=True))
    return entry


def steps_for(guide: dict, *, can_global_admin: bool) -> list[str]:
    """Plain steps to fix a protection, from the page's own guide entry."""
    action = guide.get("action") or {}
    kind = action.get("kind")
    if kind == "switch":
        who = "Press" if can_global_admin else "Ask an installation administrator to press"
        return [f"{who} “{action['label']}” in this row and confirm.",
                "This page checks the protection again as soon as it reloads."]
    if kind == "halt":
        return [f"Press \u201c{action['label']}\u201d in this row.",
                "This page checks the protection again as soon as it reloads."]
    if kind in ("link", "people", "retention"):
        return [f"Open “{action['label']}” from this row and finish the steps there.",
                "Come back to this page; it checks the protection again each time it opens."]
    return ["An installation administrator switches this protection on in All settings.",
            "This page checks it again each time it opens."]


def overdue(entry: dict | None, today: date | None = None) -> bool:
    due = (entry or {}).get("due") or ""
    try:
        return bool(due) and date.fromisoformat(due) < (today or date.today())
    except ValueError:
        return False


__all__ = ["OwnerError", "load", "overdue", "save", "steps_for"]
