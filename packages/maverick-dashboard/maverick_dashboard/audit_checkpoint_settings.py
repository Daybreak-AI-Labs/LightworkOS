"""Where the activity log's independent checkpoints live, and which keys they
must be signed with -- the ``--checkpoint-dir`` and ``--pubkey`` options of
``maverick audit checkpoint publish / verify / retire``, chosen once in the
app by an installation administrator.

* Folder: by default beside each workspace's activity log. An administrator
  may choose another folder on the server (for example write-once storage)
  with the same server-checked location control Settings uses; only allowed
  places are accepted. With a workspace active its checkpoints go in its own
  ``workspaces/<name>`` folder inside the chosen one, so two workspaces never
  share one history.
* Pinned keys: with none pinned, checkpoints are trusted when signed by any
  key in this installation's protected key list. Pinned keys replace that
  list for publishing, checking and retiring, exactly like ``--pubkey``.

Stored installation-wide in a private file under Lightwork's home folder.
Keys are stored as their hexadecimal form and only ever shown by
fingerprint.
"""
from __future__ import annotations

import json
from pathlib import Path

MAX_KEYS = 20
_FILENAME = "audit-checkpoint-settings.json"


def _store_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / _FILENAME


def load() -> dict:
    """``{"folder": str | None, "keys": [hex, ...]}``; a missing or unreadable
    file means the defaults (no chosen folder, no pinned keys)."""
    path = _store_path()
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


def save(folder: str | None, keys: list[str]) -> None:
    from maverick.file_lock import atomic_write_text

    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps({"folder": folder or None, "keys": list(keys)}, indent=2),
                      mode=0o600)


def checkpoint_dir() -> Path:
    """The checkpoint folder for the active workspace."""
    from maverick.paths import current_tenant, data_dir

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


__all__ = ["MAX_KEYS", "checkpoint_dir", "load", "save", "trusted_pubkeys"]
