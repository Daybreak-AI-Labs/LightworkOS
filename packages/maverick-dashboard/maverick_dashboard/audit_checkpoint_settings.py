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
The folder and key rules live in ``maverick.audit.checkpoint_location`` so the
kernel's erasure checks find the same folder; this module adds saving.
Keys are stored as their hexadecimal form and only ever shown by
fingerprint.
"""
from __future__ import annotations

from maverick.audit.checkpoint_location import (
    MAX_KEYS,
    checkpoint_dir,
    load,
    settings_path,
    trusted_pubkeys,
)


def save(folder: str | None, keys: list[str]) -> None:
    import json

    from maverick.file_lock import atomic_write_text

    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps({"folder": folder or None, "keys": list(keys)}, indent=2),
                      mode=0o600)


__all__ = ["MAX_KEYS", "checkpoint_dir", "load", "save", "trusted_pubkeys"]
