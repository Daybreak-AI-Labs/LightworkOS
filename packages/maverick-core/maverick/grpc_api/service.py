"""Transport-agnostic goal service backing the gRPC surface.

The gRPC server (``server.py``) is a thin protobuf shim over this class; all the
behaviour lives here so it is unit-tested without grpc installed and could back
a second transport (REST, a queue worker) unchanged.

Three operations make up the gRPC surface:
  - ``start_goal``   -> create a goal and dispatch it for background execution.
  - ``stream_episode`` -> yield the goal's events as they land, until terminal.
  - ``cancel``       -> mark a goal cancelled (honoured at the next dispatch /
    turn boundary; in-flight cooperative cancellation rides the global
    killswitch, which the agent loop already checks).

Dependencies (the world model + the dispatcher + a thread spawner) are injected
so tests drive the whole flow with in-memory fakes.
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

# A goal in one of these states is finished; streaming stops.
TERMINAL_STATUSES = frozenset({"done", "blocked", "failed", "cancelled"})

# Page size for draining goal_events. Matches world_model.goal_events' default
# LIMIT; a full page signals more backlog to drain before the terminal check.
_PAGE = 200

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class EventDTO:
    """One goal event, protobuf-free."""

    id: int
    goal_id: int
    agent: str
    kind: str
    content: str
    ts: float


@dataclass(frozen=True)
class GoalStatusDTO:
    goal_id: int
    status: str
    result: str | None
    owner: str = ""  # who the goal belongs to (e.g. "federation:<peer>")


def _default_world():  # pragma: no cover -- exercised only with a real DB
    from ..world_model import open_world
    return open_world()  # client/tenant-floored canonical world


def _default_dispatch(goal_id: int, **kw) -> None:  # pragma: no cover -- real run
    from ..runner import run_goal_in_background
    run_goal_in_background(goal_id, **kw)


class GoalService:
    """Backing logic for StartGoal / StreamEpisode / Cancel.

    ``world_factory`` returns a WorldModel (a fresh one per call by default, to
    match the per-goal connection discipline the runner uses). ``dispatch``
    runs a goal in the background. ``spawn`` starts the dispatch thread (swapped
    in tests to run inline). ``sleep`` is injected so streaming tests don't wait.
    """

    def __init__(
        self,
        *,
        world_factory: Callable[[], object] = _default_world,
        dispatch: Callable[..., object] = _default_dispatch,
        spawn: Callable[[Callable[[], object]], object] | None = None,
        sleep: Callable[[float], object] = time.sleep,
        poll_interval: float = 0.5,
    ):
        self._world_factory = world_factory
        self._dispatch = dispatch
        self._spawn = spawn or self._thread_spawn
        self._sleep = sleep
        self._poll_interval = poll_interval

    @staticmethod
    def _thread_spawn(fn: Callable[[], object]) -> threading.Thread:
        t = threading.Thread(target=fn, daemon=True)
        t.start()
        return t

    @staticmethod
    def _goal_for_owner(world: object, goal_id: int, expected_owner: str | None):
        """Return a goal only when it belongs to ``expected_owner``.

        ``None`` is the explicit administrative scope used by the shared gRPC
        operator token.  A concrete owner is used for per-agent tokens; an
        ownership mismatch is intentionally indistinguishable from a missing
        goal so callers cannot enumerate another agent's goal ids.
        """
        goal = world.get_goal(goal_id)
        if goal is None:
            return None
        owner = getattr(goal, "owner", "") or ""
        if expected_owner is not None and owner != expected_owner:
            return None
        return goal

    def start_goal(
        self,
        title: str,
        description: str = "",
        *,
        max_dollars: float | None = None,
        max_wall_seconds: float | None = None,
        channel: str | None = None,
        user_id: str | None = None,
        capability: Any | None = None,
        owner: str = "",
    ) -> int:
        """Create a goal and dispatch it for background execution. Returns the
        new goal id immediately (the run proceeds asynchronously).

        ``owner`` is persisted on the goal row so a later status poll can be
        scoped to whoever created it (the federation surface uses this to keep
        one peer from reading another peer's delegated-goal results). Runtime
        authority is persisted separately, so a delegated worker can execute
        without replacing the human/resource owner used for retrieval."""
        if not (title or "").strip():
            raise ValueError("title is required")
        from ..orchestrator import _execution_principal

        runtime_principal = _execution_principal(
            user_id=user_id,
            capability=capability,
        )
        durable_owner = owner or runtime_principal
        world = self._world_factory()
        try:
            goal_id = int(
                world.create_goal(
                    title.strip(),
                    description or "",
                    owner=durable_owner,
                    execution_principal=runtime_principal,
                )
            )
        finally:
            _close(world)

        def _run() -> None:
            self._dispatch(
                goal_id,
                max_dollars=max_dollars,
                max_wall_seconds=max_wall_seconds,
                channel=channel,
                user_id=user_id,
                capability=capability,
            )

        self._spawn(_run)
        return goal_id

    def accept_federation(self, *, peer: str, correlation: str, digest: str,
                          title: str, description: str, capability,
                          max_dollars, max_wall_seconds, record, admit_new=None) -> dict:
        """Reserve, audit, and dispatch once; retries recover only before claim.

        ``record`` must return literal True after accepting the stable receipt.
        A custom dispatcher must execute synchronously inside the captured
        context, just as the built-in runner does here. No startup drain is
        implied: the peer retries this same correlation to repair a held row.
        """
        import contextvars

        from .. import federation_admission as admission
        from ..audit import EventKind
        from ..runner import clamp_task_limit, configured_max_dollars, configured_max_wall_seconds
        max_dollars = clamp_task_limit(max_dollars, configured_max_dollars())
        max_wall_seconds = clamp_task_limit(max_wall_seconds, configured_max_wall_seconds())
        world = self._world_factory()
        try:
            reservation = admission.reserve(
                world, peer=peer, correlation=correlation, digest=digest,
                title=title, description=description, capability=capability,
                max_dollars=max_dollars, max_wall_seconds=max_wall_seconds,
                admit_new=admit_new,
            )
            current = admission.state(world, reservation)
            if current == admission.RETIRED:
                return {"accepted": False, "goal_id": reservation.goal_id,
                        "outcome_state": "unknown", "audit_state": "unknown",
                        "execution_state": "unknown", "reason": "goal was erased; replay is prohibited"}
            if current in {admission.HELD, admission.READY} and not admission.current_ceiling_allows(
                reservation, capability=capability, max_dollars=max_dollars,
                max_wall_seconds=max_wall_seconds,
            ):
                return {"accepted": current == admission.READY, "goal_id": reservation.goal_id,
                        "outcome_state": "accepted" if current == admission.READY else "pending",
                        "audit_state": "accepted" if current == admission.READY else "pending",
                        "execution_state": "held", "reason": "pinned authority exceeds current policy or expired"}
            if current == admission.HELD:
                contract = reservation.contract
                try:
                    acknowledged = record(
                        EventKind.FEDERATION_DELEGATE, agent="federation",
                        goal_id=reservation.goal_id, peer_node=contract["peer"],
                        correlation_id=contract["correlation"], direction="received",
                        accepted=True, reason="", outcome_state="accepted",
                        phase="acceptance_authorized", event_id=contract["event_id"],
                        occurred_at=contract["occurred_at"],
                        request_digest=contract["request_digest"],
                    ) is True
                except Exception:
                    # The reservation remains held even if the sink appended
                    # before losing its ack. Its append-once identity repairs
                    # that boundary on the next same-correlation request.
                    log.warning("federation acceptance audit is pending", exc_info=True)
                    acknowledged = False
                if not acknowledged:
                    return {"accepted": False, "goal_id": reservation.goal_id,
                            "outcome_state": "pending", "audit_state": "pending",
                            "execution_state": "held",
                            "reason": "audit acceptance pending; retry the same correlation_id"}
                admission.acknowledge(world, reservation)
                current = admission.state(world, reservation)
            claimed = current == admission.READY and admission.claim(world, reservation)
        finally:
            _close(world)
        result = {"accepted": True, "goal_id": reservation.goal_id,
                  "outcome_state": "accepted", "audit_state": "accepted",
                  "execution_state": "unknown", "reason": ""}
        if not claimed:
            if current == admission.READY:
                result["execution_state"] = "not_started"
                result["reason"] = "execution was not claimed; inspect the goal status"
            else:
                result["reason"] = "execution previously claimed; automatic replay is prohibited"
            return result
        context = contextvars.copy_context()

        def run():
            with admission.execution_scope(reservation):
                kwargs = admission.execution_kwargs(reservation)
                if self._dispatch is _default_dispatch:
                    from ..runner import run_goal_in_thread
                    return run_goal_in_thread(reservation.goal_id, **kwargs)
                return self._dispatch(reservation.goal_id, **kwargs)

        try:
            self._spawn(lambda: context.run(run))
        except Exception:
            log.exception("federation dispatch acknowledgement unavailable")
            result["reason"] = "dispatch outcome unknown; automatic replay is prohibited"
        else:
            result["execution_state"] = "dispatched"
        return result

    def stream_episode(
        self,
        goal_id: int,
        *,
        since_id: int = 0,
        max_seconds: float | None = None,
        expected_owner: str | None = None,
    ) -> Iterator[EventDTO]:
        """Yield goal events in id order as they land, until the goal reaches a
        terminal status (or ``max_seconds`` elapses). A final synthetic event
        (``kind="status"``) carries the terminal status + result.

        ``expected_owner`` scopes per-agent callers.  ``None`` is reserved for
        the shared operator principal and preserves its administrative access.
        """
        world = self._world_factory()
        started = time.monotonic()
        last = since_id
        try:
            # Authorize before reading even one event: event content can contain
            # goal prompts, tool output, and other tenant-sensitive data.
            if self._goal_for_owner(world, goal_id, expected_owner) is None:
                return
            while True:
                events = world.goal_events(goal_id, since_id=last, limit=_PAGE)
                for e in events:
                    last = e.id
                    yield EventDTO(
                        id=e.id, goal_id=e.goal_id, agent=e.agent,
                        kind=e.kind, content=e.content, ts=e.ts,
                    )
                # A full page means more backlog may be waiting; drain it before
                # evaluating terminal status so a goal that finished while >1 page
                # of events was pending does not strand events 201..N unsent.
                if len(events) == _PAGE:
                    continue
                g = self._goal_for_owner(world, goal_id, expected_owner)
                if g is None:
                    return
                if g.status in TERMINAL_STATUSES:
                    yield EventDTO(
                        id=last + 1, goal_id=goal_id, agent="system",
                        kind="status", content=g.status, ts=time.time(),
                    )
                    return
                if max_seconds is not None and time.monotonic() - started >= max_seconds:
                    return
                self._sleep(self._poll_interval)
        finally:
            _close(world)

    def run_goal(
        self,
        goal_id: int,
        *,
        max_dollars: float | None = None,
        max_wall_seconds: float | None = None,
        channel: str | None = None,
        user_id: str | None = None,
        max_depth: int | None = None,
        capability: Any | None = None,
        expected_owner: str | None = None,
        expected_execution_principal: str | None = None,
    ) -> GoalStatusDTO | None:
        """Run an EXISTING goal row to completion and return its terminal
        status — the worker half of the cross-host gRPC Dispatcher (caller and
        worker must share the world DB, e.g. the Postgres backend). Returns
        None when the goal id doesn't exist here (DBs not shared / bad id),
        does not belong to ``expected_owner``, or is not delegated to
        ``expected_execution_principal``. ``None`` in either scope is the
        shared operator's administrative access. Resource ownership and
        execution authority are intentionally independent: a human-owned fleet
        goal can be run by its bound agent without transferring dashboard
        visibility to that agent.
        """
        world = self._world_factory()
        try:
            goal = self._goal_for_owner(world, goal_id, expected_owner)
            if goal is None:
                return None
            from ..federation_admission import FederationAdmissionRequired, require_execution
            try:
                require_execution(world, goal_id, capability=capability,
                                  max_dollars=max_dollars, max_wall_seconds=max_wall_seconds)
            except FederationAdmissionRequired:
                return None
            bound_execution = (
                getattr(goal, "execution_principal", "") or ""
            )
            if expected_execution_principal is not None:
                if bound_execution:
                    if bound_execution != expected_execution_principal:
                        return None
                elif (getattr(goal, "owner", "") or "") != (
                    expected_execution_principal
                ):
                    # A per-agent bearer may adopt its own legacy unbound goal,
                    # but not an arbitrary human-owned legacy row. New
                    # delegated rows are pre-bound at creation.
                    return None
            # The remote claim is itself a durable status side effect, so bind
            # or verify the exact runtime principal before that compare-and-
            # swap.  The orchestrator repeats this check at its own boundary;
            # doing it here ensures a mismatched RPC cannot even repaint the
            # owner's pending row as active.
            if getattr(goal, "status", "") == "pending":
                from ..orchestrator import (
                    _bind_goal_execution_principal,
                    _execution_principal,
                )

                try:
                    runtime_principal = _execution_principal(
                        user_id=user_id,
                        capability=capability,
                    )
                    if (
                        expected_execution_principal is not None
                        and runtime_principal != expected_execution_principal
                    ):
                        return None
                    if not _bind_goal_execution_principal(
                        world, goal, runtime_principal,
                    ):
                        return None
                    if not (getattr(goal, "execution_principal", "") or ""):
                        rebound = world.get_goal(goal_id)
                        if (
                            rebound is None
                            or (
                                getattr(rebound, "execution_principal", "")
                                or ""
                            )
                            != runtime_principal
                        ):
                            return None
                        goal = rebound
                except Exception:
                    log.exception(
                        "gRPC goal %s runtime-principal binding failed",
                        goal_id,
                    )
                    return None
            # This RPC is the remote worker's at-least-once delivery boundary.
            # Claim in the database, in one pending -> active CAS, before any
            # side effect.  A retry after a timeout/lost response (or a racing
            # second worker) returns the current status without re-running the
            # swarm or spending the budget twice.
            resource_owner = getattr(goal, "owner", "") or ""
            if not world.claim_goal_for_run(
                goal_id, expected_owner=resource_owner,
            ):
                current = self._goal_for_owner(world, goal_id, expected_owner)
                if current is None:
                    return None
                if (
                    expected_execution_principal is not None
                    and (
                        getattr(current, "execution_principal", "") or ""
                    )
                    != expected_execution_principal
                ):
                    return None
                return GoalStatusDTO(
                    goal_id=goal_id,
                    status=current.status,
                    result=getattr(current, "result", None),
                    owner=getattr(current, "owner", "") or "",
                )
        finally:
            _close(world)
        if max_depth is None:
            from ..runner import DEFAULT_MAX_DEPTH
            max_depth = DEFAULT_MAX_DEPTH
        self._dispatch(
            goal_id,
            max_dollars=max_dollars,
            max_wall_seconds=max_wall_seconds,
            channel=channel,
            user_id=user_id,
            max_depth=max_depth,
            capability=capability,
        )
        return self.status(goal_id, expected_owner=expected_owner)

    def status(
        self, goal_id: int, *, expected_owner: str | None = None,
    ) -> GoalStatusDTO | None:
        world = self._world_factory()
        try:
            g = self._goal_for_owner(world, goal_id, expected_owner)
            if g is None:
                return None
            return GoalStatusDTO(
                goal_id=goal_id, status=g.status, result=getattr(g, "result", None),
                owner=getattr(g, "owner", "") or "",
            )
        finally:
            _close(world)

    def cancel(self, goal_id: int, *, expected_owner: str | None = None) -> bool:
        """Mark a goal cancelled. Returns False if the goal doesn't exist or is
        already terminal, or if it belongs to a different scoped owner.
        Honoured at the next dispatch / turn boundary."""
        world = self._world_factory()
        try:
            g = self._goal_for_owner(world, goal_id, expected_owner)
            if g is None or g.status in TERMINAL_STATUSES:
                return False
            world.set_goal_status(goal_id, "cancelled", result="cancelled via API")
            return True
        finally:
            _close(world)


def _close(world: object) -> None:
    from ..world_model import close_world_if_owned

    try:
        close_world_if_owned(world)
    except Exception:  # pragma: no cover -- close must never raise to caller
        pass


__all__ = [
    "EventDTO",
    "GoalStatusDTO",
    "GoalService",
    "TERMINAL_STATUSES",
]
