"""Where this installation's independent audit checkpoints live.

An installation administrator may choose the checkpoint folder and pin the
keys checkpoints must be signed with (the dashboard's audit checkpoint
settings). The choice is stored installation-wide in a private file under
Lightwork's home folder. The folder rule lives here so the dashboard and the
kernel (erasure checks a day against its published checkpoints) agree.

* Folder: by default ``audit-checkpoints`` beside the workspace's activity
  log. A chosen folder gets a ``workspaces/<name>`` folder per active
  workspace, so two workspaces never share one history.
* Pinned keys: with none pinned, checkpoints are trusted when signed by any
  key in this installation's protected key list.
"""
from __future__ import annotations

import json
from pathlib import Path

MAX_KEYS = 20
SETTINGS_FILENAME = "audit-checkpoint-settings.json"


def settings_path() -> Path:
    from ..paths import maverick_home

    return maverick_home() / SETTINGS_FILENAME


def load() -> dict:
    """``{"folder": str | None, "keys": [hex, ...]}``; a missing file means the
    defaults (no chosen folder, no pinned keys)."""
    path = settings_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"folder": None, "keys": []}
    except (OSError, ValueError) as exc:
        # A damaged file must not silently drop pinned keys (that would loosen
        # every check); refuse instead.
        raise RuntimeError("checkpoint settings are unreadable") from exc
    folder = data.get("folder") if isinstance(data, dict) else None
    keys = data.get("keys") if isinstance(data, dict) else None
    if (folder is not None and not isinstance(folder, str)) or not isinstance(keys, list) or not all(
            isinstance(k, str) and len(k) == 64 for k in keys):
        raise RuntimeError("checkpoint settings are unreadable")
    return {"folder": folder or None, "keys": list(keys)[:MAX_KEYS]}


def checkpoint_dir() -> Path:
    """The checkpoint folder for the active workspace."""
    from ..paths import current_tenant, data_dir

    folder = load()["folder"]
    if not folder:
        return data_dir("audit-checkpoints")
    segment = current_tenant()  # the same safe folder name data_dir uses
    return Path(folder) / "workspaces" / segment if segment else Path(folder)


def trusted_pubkeys() -> list[str] | None:
    """The pinned keys, or ``None`` for this installation's own key list
    (what leaving out ``--pubkey`` means)."""
    keys = load()["keys"]
    return list(keys) if keys else None


__all__ = ["MAX_KEYS", "SETTINGS_FILENAME", "checkpoint_dir", "load", "settings_path",
           "trusted_pubkeys"]
