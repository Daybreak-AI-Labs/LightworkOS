"""Compatible bounded v1 task/event/episode bundles from one read snapshot."""
from __future__ import annotations

import json

from .goal_archive import (
    MAX_ARCHIVE_BYTES,
    MAX_EPISODES,
    MAX_EVENTS,
    IncompleteGoalBundle,
    prepare_goal_archive,
)


def build_goal_bundle(world, goal_id: int) -> dict | None:
    """Compatibility adapter; HTTP downloads stream the same prepared file."""
    prepared = prepare_goal_archive(world, goal_id)
    if prepared is None:
        return None
    try:
        return json.load(prepared.stream)
    finally:
        prepared.close()


__all__ = ["IncompleteGoalBundle", "MAX_ARCHIVE_BYTES", "MAX_EPISODES", "MAX_EVENTS", "build_goal_bundle", "prepare_goal_archive"]
