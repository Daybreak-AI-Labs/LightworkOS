"""Per-goal file-write quota (opt-in, default OFF).

Caps how many bytes a run may write to the workspace, so a runaway agent can't
fill the disk. Off by default (``[limits] file_write_quota_mb`` unset or 0); when
set, `write_file` refuses the write that would cross the cap. Process-global
accounting approximates per-goal for a CLI run (one process = one goal); pass an
explicit ``goal_id`` for finer scoping. Fail-open: any config error disables it.
"""
from __future__ import annotations

import threading

_lock = threading.Lock()
_written: dict[str, int] = {}


def _limit_bytes() -> int:
    """Quota in bytes from ``[limits] file_write_quota_mb`` (0 / unset = off)."""
    try:
        from .config import load_config
        mb = float(((load_config() or {}).get("limits") or {}).get(
            "file_write_quota_mb", 0) or 0)
    except Exception:  # pragma: no cover -- never block writes on a config error
        return 0
    return int(mb * 1024 * 1024) if mb > 0 else 0


def reset(goal_id: str = "default") -> None:
    """Clear a goal's accumulated byte count (new run / test isolation)."""
    with _lock:
        _written.pop(str(goal_id), None)


def check_and_add(
    n_bytes: int, *, goal_id: str = "default", limit: int | None = None
) -> tuple[bool, str]:
    """Account ``n_bytes`` against the goal's quota.

    Returns ``(allowed, message)``: ``(True, "")`` when within the cap (and adds
    the bytes) or when the quota is disabled; ``(False, reason)`` when the write
    would exceed the cap (nothing is added, so the caller can refuse cleanly).
    ``limit`` overrides the configured cap (for tests)."""
    lim = _limit_bytes() if limit is None else limit
    if lim <= 0:  # disabled
        return True, ""
    gid = str(goal_id)
    n = max(0, int(n_bytes))
    with _lock:
        used = _written.get(gid, 0)
        if used + n > lim:
            return False, (
                f"file-write quota exceeded: this write ({n} B) would bring the "
                f"run to {used + n} B, over the {lim} B cap "
                f"([limits] file_write_quota_mb)")
        _written[gid] = used + n
        return True, ""


__all__ = ["check_and_add", "reset"]
