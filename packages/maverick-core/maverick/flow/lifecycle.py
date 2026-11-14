"""Durable queue-delivery serialization and crash quarantine."""
from __future__ import annotations

import logging
from functools import wraps

from . import store
from .ir import Flow
from .run_state import STATUS_INDETERMINATE, STATUS_RESUMING, STATUS_RUNNING
from .transitions import DeliveryDecision, decide_delivery

log = logging.getLogger(__name__)


def _load_or_quarantine(run_id, flow, kwargs, error):
    from .payloads import FlowPayloadError

    try:
        return store.load_run(str(run_id))
    except FlowPayloadError:
        current = store.quarantine_unreadable_run(
            str(run_id), flow_id=flow.id, owner=kwargs.get("owner"),
            error=error + "; saved execution data is unavailable; external effects may have committed",
        )
        if current is None:
            raise
        return current


def _record_crash(run_id, flow, kwargs, error):
    current = _load_or_quarantine(run_id, flow, kwargs, error)
    if current is not None and current.status in {STATUS_RESUMING, STATUS_RUNNING}:
        current.status = STATUS_INDETERMINATE
        current.error = error
        store.save_run(current)


def serialize_runs(fn, *, safe_failure):
    """Hold one durable run lock across state check, execution, and save.

    Queue delivery is intentionally at-least-once.  Without this boundary two
    workers can both load the same paused approval and both execute the approved
    side effect before either publishes ``completed``.  The second worker now
    observes the first worker's terminal state and receives FlowNotResumable.
    """
    @wraps(fn)
    def guarded(flow: Flow, **kwargs):
        resume_id = kwargs.get("resume_run_id")
        run_id = resume_id or kwargs.get("run_id")
        if not run_id:
            return fn(flow, **kwargs)
        with store.run_lock(str(run_id)):
            if not resume_id:
                current = _load_or_quarantine(run_id, flow, kwargs, "fresh run interrupted after execution began")
                delivery = (decide_delivery(current.status) if current is not None
                            else DeliveryDecision.START)
                if delivery is DeliveryDecision.QUARANTINE:
                    # A previous worker crossed the durable execution boundary
                    # and vanished.  Its last tool may have committed, so an
                    # at-least-once delivery must quarantine rather than replay.
                    current.status = STATUS_INDETERMINATE
                    current.error = (
                        current.error
                        or "fresh run interrupted after execution began; external effects may have committed"
                    )
                    store.save_run(current)
                    return current
                if delivery is DeliveryDecision.RETURN_CHECKPOINT:
                    # At-least-once queue redelivery after the first attempt
                    # published a terminal/pause state is a no-op.
                    return current
            try:
                return fn(flow, **kwargs)
            except BaseException as exc:
                # If execution escaped after the durable resume claim, the
                # external-effect boundary is unknowable.  Preserve that honest
                # state and never let queue redelivery replay it automatically.
                phase = "resume" if resume_id else "execution"
                try:
                    _record_crash(run_id, flow, kwargs, (
                        f"{phase} interrupted: {type(exc).__name__}: "
                        f"{safe_failure(exc)}"
                    ))
                except Exception as recovery_error:
                    # Recovery must not replace the original execution error.
                    log.warning("Flow run %s could not be marked indeterminate (%s)",
                                run_id, type(recovery_error).__name__)
                raise
    return guarded
