"""Stable, unambiguous labels for existing workspaces with duplicate names."""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from maverick.tenant.registry import workspace_display_key


def duplicate_workspace_ids(choices: Iterable[tuple[str, str]]) -> frozenset[str]:
    """Return IDs whose visible names collide, without exposing other rows."""
    rows = tuple(choices)
    counts = Counter(workspace_display_key(name) for _, name in rows)
    return frozenset(tid for tid, name in rows if counts[workspace_display_key(name)] > 1)
