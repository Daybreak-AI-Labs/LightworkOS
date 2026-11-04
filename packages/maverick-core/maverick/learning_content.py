"""Server-derived ownership for learned content and generated executable source."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .file_lock import atomic_read_text, atomic_write_text, ensure_private_file


def current_owner() -> str:
    from .connections import current_principal
    from .logging_config import current_goal_id
    from .memory_ownership import current_owner as goal_owner

    return goal_owner() if current_goal_id() else (current_principal() or "")


def lineage() -> dict:
    from .logging_config import current_goal_id

    return {"content_version": 1, "owner": current_owner(), "goal_id": current_goal_id()}


def allowed(record: dict, *, owner: str | None = None) -> bool:
    """Unknown legacy provenance never grants content authority, including admins."""
    from .memory_ownership import source_allowed

    try:
        expected = current_owner() if owner is None else owner
        if record.get("content_version") != 1 or record.get("owner") != expected:
            return False
        goal_id = record.get("goal_id")
        if goal_id is None:
            return True  # Explicitly stamped direct/local publication.
        return type(goal_id) is int and goal_id > 0 and source_allowed(goal_id, expected)
    except (OSError, RuntimeError, ValueError):
        return False


def metadata_path(source: Path) -> Path:
    return source.with_suffix(".ownership.json")


def publish(source: Path, content: str, record: dict) -> None:
    if not allowed(record):
        raise PermissionError("Learned source ownership is no longer available")
    atomic_write_text(metadata_path(source), json.dumps({**record,
        "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}, sort_keys=True), mode=0o600)


def source_allowed_now(source: Path, digest: str, *, owner: str | None = None) -> bool:
    try:
        path = metadata_path(source)
        ensure_private_file(path, 0o600)
        if path.stat().st_size > 4096:
            return False
        record = json.loads(atomic_read_text(path))
        return isinstance(record, dict) and record.get("sha256") == digest and allowed(record, owner=owner)
    except (OSError, RuntimeError, ValueError):
        return False
