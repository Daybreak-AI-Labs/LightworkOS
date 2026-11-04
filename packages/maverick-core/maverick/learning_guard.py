"""Operational stop boundary shared by every learning loop.

Learning jobs do not run through the agent kernel, so the kernel's turn/tool
checks cannot stop them.  This small boundary deliberately reuses the global
killswitch instead of inventing a second flag: the local HALT file,
in-process halt, and shared Postgres halt therefore stop agents and learning
workers with the same operator action.

Callers check at job start and again immediately before expensive evaluation
or a durable learned-state transition.  ``Halted`` is a control-flow signal;
callers may surface it as a refused report, but must never continue the phase.
Unlike the availability-first agent hot path, this boundary also treats an
unreadable configured HALT authority as active and refuses the transition.
Recovery and rollback code intentionally do not use this guard so an operator
can restore a known-good state while the emergency stop remains armed.
"""
from __future__ import annotations

import logging

from . import killswitch

log = logging.getLogger(__name__)

# Re-export the canonical signal so learning loops can catch it without
# reaching around this boundary.  It remains the exact same exception class
# used by the agent kernel.
Halted = killswitch.Halted


def check_learning_halt(job: str, phase: str) -> None:
    """Raise :class:`Halted` when any global stop source is active.

    ``job`` and ``phase`` are bounded, developer-owned labels used only for
    diagnostics; the authoritative reason/source stay on ``Halted`` itself.
    No exception is swallowed here -- a safety check that cannot refuse the
    phase would be worse than having no shared boundary at all.
    """
    from .pilot_learning import current_excluded
    if current_excluded():
        raise Halted("frozen pilot excludes this task from local learning", "pilot-learning-policy")
    try:
        # Learning checkpoints are infrequent and guard privileged writes.  A
        # fresh read closes the race where a HALT lands during evaluation but
        # the ordinary hot-path cache still contains the preceding "not set".
        killswitch.check(force_refresh=True, fail_closed=True)
    except killswitch.Halted:
        log.warning("learning job %s refused at %s: killswitch active", job, phase)
        raise


def learning_write_allowed(job: str, phase: str = "write") -> bool:
    """Best-effort adapter for optional learning sinks.

    Core promotion paths propagate :class:`Halted`; telemetry-style sinks keep
    their historical non-raising contract and report ``False``/no-op instead.
    """
    from .pilot_learning import current_excluded
    if current_excluded():
        return False
    try:
        # Optional sinks may be on a per-step hot path. Reuse the canonical
        # one/two-second HALT caches while retaining fail-closed shared-authority
        # handling; privileged promotions use the fresh check above.
        killswitch.check(fail_closed=True)
        return True
    except Halted:
        log.warning("learning sink %s refused at %s: killswitch active", job, phase)
        return False


__all__ = ["Halted", "check_learning_halt", "learning_write_allowed"]
