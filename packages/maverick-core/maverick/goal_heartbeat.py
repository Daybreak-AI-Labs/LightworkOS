"""Keep a running goal fresh enough for crash recovery to distinguish live work."""
from __future__ import annotations

import contextvars
import logging
import math
import threading
from collections.abc import Callable
from typing import Any

log = logging.getLogger(__name__)


def heartbeat_interval() -> float:
    """Touch several times per reclaim window, without busy polling."""
    from .world_model import reclaim_window_seconds

    window = reclaim_window_seconds()
    if not math.isfinite(window) or window <= 0:
        return 15.0
    return min(15.0, max(1.0, window / 4.0))


def start_goal_heartbeat(
    world: Any, goal_id: int, *, interval: float | None = None,
) -> Callable[[], None]:
    """Return a stop callback for this run's liveness thread.

    ``touch_goal`` updates only active/pending rows and never revives a finished
    goal. Copy the caller's tenant context for the PostgreSQL backend.
    Heartbeat failures do not change the run's outcome.
    """
    touch = getattr(world, "touch_goal", None)
    if not callable(touch):
        return lambda: None
    try:
        every = heartbeat_interval() if interval is None else float(interval)
        if not math.isfinite(every) or every <= 0:
            raise ValueError("interval must be positive and finite")
    except Exception:
        log.warning("goal heartbeat setup failed for #%s", goal_id, exc_info=True)
        return lambda: None
    stopped = threading.Event()

    def beat() -> None:
        while not stopped.wait(every):
            try:
                if not touch(int(goal_id)):
                    return
            except Exception:
                log.debug("goal heartbeat failed for #%s", goal_id, exc_info=True)

    thread = threading.Thread(
        target=contextvars.copy_context().run, args=(beat,),
        name=f"goal-heartbeat-{goal_id}", daemon=True,
    )
    try:
        thread.start()
    except RuntimeError:
        log.warning("goal heartbeat could not start for #%s", goal_id, exc_info=True)
        return lambda: None

    def stop() -> None:
        stopped.set()
        thread.join(timeout=2.0)

    return stop
