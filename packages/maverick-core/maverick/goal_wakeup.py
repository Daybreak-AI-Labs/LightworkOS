"""Wake in-process watchers of a goal after its stored state changes.

Timing only, never a source of truth: a woken watcher re-reads the database,
and every watcher keeps its own timed re-read for writes this process does not
announce (another process, or a write path that does not call :func:`notify`).
A goal is named by its database file and id, so the same id in two worlds
never wakes the other's watchers.
"""
from __future__ import annotations

import os
import threading
from collections.abc import Callable

_lock = threading.Lock()
_watchers: dict[tuple[str, int], dict[int, Callable[[], None]]] = {}
_tokens = 0


def world_key(path: object) -> str:
    """The name of a world database file, the same for every open of it."""
    return os.path.normcase(os.path.realpath(str(path)))


def watching() -> bool:
    """Whether any goal is watched: a write with no watchers skips the rest
    (read without the lock; a watcher added meanwhile keeps its timer)."""
    return bool(_watchers)


def watch(world: str, goal_id: int, wake: Callable[[], None]) -> int:
    """Call ``wake()`` (from any thread) after each announced change."""
    global _tokens
    with _lock:
        _tokens += 1
        _watchers.setdefault((world, int(goal_id)), {})[_tokens] = wake
        return _tokens


def unwatch(world: str, goal_id: int, token: int) -> None:
    with _lock:
        watchers = _watchers.get((world, int(goal_id)))
        if watchers is not None:
            watchers.pop(token, None)
            if not watchers:
                del _watchers[(world, int(goal_id))]


def notify(world: str, goal_id: int) -> None:
    """Announce a committed change; never raises."""
    with _lock:
        wakes = list(_watchers.get((world, int(goal_id)), {}).values())
    for wake in wakes:
        try:
            wake()
        except Exception:  # noqa: BLE001 - a watcher whose event loop has closed
            pass
