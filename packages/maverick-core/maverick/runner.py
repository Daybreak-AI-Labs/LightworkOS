"""Background-task runner for goal execution.

Single source of truth for "start a goal in the background and run it to
completion." The dashboard's BackgroundTask, the REST API, the MCP
server's maverick_start tool, and any future channel adapter all funnel
through here.

The dashboard app, the REST API and the MCP server all run goals here,
so every adapter inherits the same concurrency cap,
spend cap, error logging, and goal-status finalization.

Usage::

    from maverick.runner import run_goal_in_background, run_goal_in_thread

    run_goal_in_thread(goal_id=42, max_dollars=2.0)   # blocking, sync
    bg.add_task(run_goal_in_thread, goal_id=42)        # FastAPI BG task
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import functools
import logging
import math
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Protocol

from ._envparse import env_float

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class GoalRunUnavailable:
    """Current invocation's unavailable result; only a slot refusal permits defer.

    This does not certify the absence of effects in earlier task attempts.
    Legacy callers receive ``None`` instead and cannot reconstruct this result.
    """

    reason: Literal["concurrency_slot", "missing", "admission_closed", "unknown"]


def _unavailable_goal_run(reason, *, detailed_outcome: bool):
    return GoalRunUnavailable(reason) if detailed_outcome else None


class DispatchState(str, Enum):
    """What a dispatcher reported about submission, not ownership of effects."""

    QUEUED = "queued"
    REPORTED = "reported"
    NOT_ACCEPTED = "not_accepted"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DispatchObservation:
    """Immutable dispatch result with no implied cancellation guarantee.

    A queued submission is an admission receipt, and an unknown submission
    does not prove the worker had no effect. Callers needing execution state
    must reconcile through the durable goal/worker owner.
    """

    goal_id: int
    state: DispatchState
    status: str | None
    owner: Literal["legacy", "local", "queue", "grpc"] = "legacy"
    receipt_id: str | None = None
    reason: str | None = None

    def as_handle(self) -> ExecutionHandle:
        """Wrap this admission evidence without submitting a second time."""
        return ExecutionHandle(self)


def observe_dispatch(goal_id: int, status: str | None, *,
                     owner: Literal["legacy", "local", "queue", "grpc"] = "legacy",
                     receipt_id: str | None = None) -> DispatchObservation:
    """Classify a legacy result while retaining the status for old callers."""
    state = (DispatchState.UNKNOWN if status is None else
             DispatchState.QUEUED if status == "queued" else DispatchState.REPORTED)
    return DispatchObservation(goal_id=goal_id, state=state, status=status,
                               owner=owner, receipt_id=receipt_id)


def _valid_dispatch_observation(observation: object, goal_id: int) -> bool:
    """Reject contradictory adapter reports before exposing legacy status.

    In particular, an unknown effect cannot carry the legacy ``queued`` or
    terminal-success status: consumers could otherwise mistake uncertainty for
    a confirmed acceptance or completion.
    """
    if not isinstance(observation, DispatchObservation) or observation.goal_id != goal_id:
        return False
    if not isinstance(observation.state, DispatchState):
        return False
    if observation.owner not in {"legacy", "local", "queue", "grpc"}:
        return False
    if observation.receipt_id is not None and not isinstance(observation.receipt_id, str):
        return False
    if observation.reason is not None and not isinstance(observation.reason, str):
        return False
    if observation.state is DispatchState.QUEUED:
        return observation.status == "queued"
    if observation.state is DispatchState.REPORTED:
        return isinstance(observation.status, str) and observation.status != "queued"
    return observation.status is None or observation.status == "error"


@dataclass(frozen=True)
class ExecutionControlResult:
    """A control request that the handle did not send to any owner.

    ``performed`` describes only the control request, not whether the goal has
    already executed or whether its owner later cancels or settles it.
    """

    operation: Literal["cancel", "settle"]
    outcome: Literal["unsupported"] = "unsupported"
    performed: Literal[False] = False


@dataclass(frozen=True)
class ExecutionHandle:
    """Submission evidence shared by local, queue, gRPC and legacy adapters.

    This handle carries no credentials or lease. Its observation is a snapshot,
    not a live status query. Owner-specific authorities remain responsible for
    status, cancellation, and settlement, subject to their own authorization.
    """

    observation: DispatchObservation

    def __post_init__(self) -> None:
        if (not isinstance(self.observation, DispatchObservation)
                or not _valid_dispatch_observation(
                    self.observation, self.observation.goal_id)):
            raise ValueError("invalid execution observation")

    @property
    def goal_id(self) -> int:
        return self.observation.goal_id

    @property
    def owner(self) -> Literal["legacy", "local", "queue", "grpc"]:
        return self.observation.owner

    @property
    def receipt_id(self) -> str | None:
        return self.observation.receipt_id

    def cancel(self) -> ExecutionControlResult:
        """Report that this handle cannot submit a cancellation request."""
        return ExecutionControlResult(operation="cancel")

    def settle(self) -> ExecutionControlResult:
        """Report that this handle cannot settle a worker-owned attempt."""
        return ExecutionControlResult(operation="settle")


def _submission_handle(
    goal_id: int, submit: Callable[[], DispatchObservation], *,
    owner: Literal["legacy", "local", "queue", "grpc"] = "legacy",
) -> ExecutionHandle:
    """Submit once, preserving uncertainty if no valid report comes back."""
    try:
        observation = submit()
        if not _valid_dispatch_observation(observation, goal_id):
            raise RuntimeError("dispatcher returned an invalid submission observation")
        return observation.as_handle()
    except Exception:
        log.exception("goal #%s dispatcher submission failed", goal_id)
        return DispatchObservation(
            goal_id, DispatchState.UNKNOWN, "error", owner=owner,
            reason="dispatch_exception",
        ).as_handle()


# Two-level fair concurrency so people don't wait behind each other:
#
#   * a per-PRINCIPAL lane (MAX_CONCURRENT_GOALS_PER_PRINCIPAL) — one user can
#     run several goals at once but cannot monopolise the host; and
#   * a global ceiling (MAX_CONCURRENT_GOALS) that only protects the box from
#     total overload. It is sized so normal multi-user load never reaches it,
#     so one user's runs do not block another's — only a host-wide saturation
#     queues anyone. Both are env-overridable.
#
# BoundedSemaphore(0) raises ValueError, so clamp to at least 1.
# Also settings ([agent] max_concurrent_goals / max_concurrent_goals_per_principal),
# read once here at startup; the environment still wins.
def _concurrency_settings() -> tuple[int, int]:
    from .env_setting import env_or_config_int

    return (
        max(1, env_or_config_int(
            "MAVERICK_MAX_CONCURRENT_GOALS", "agent", "max_concurrent_goals", 16)),
        max(1, env_or_config_int(
            "MAVERICK_MAX_CONCURRENT_GOALS_PER_PRINCIPAL", "agent",
            "max_concurrent_goals_per_principal", 3)),
    )


MAX_CONCURRENT_GOALS, MAX_CONCURRENT_GOALS_PER_PRINCIPAL = _concurrency_settings()
_run_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_GOALS)
_inflight_lock = threading.Lock()
_inflight_count = 0
_accepting_goals = True

# Run_goal_in_background_async used to hand the ENTIRE goal run (up to
# DEFAULT_MAX_WALL_SECONDS, plus up to 2x _ACQUIRE_TIMEOUT of semaphore
# waiting) to asyncio.to_thread, which uses the event loop's default
# ThreadPoolExecutor -- sized min(32, cpu_count()+4) by CPython, e.g. 8 on a
# 4-core box. That silently capped real concurrency below the advertised
# MAX_CONCURRENT_GOALS=16 ceiling AND queued every other to_thread caller in
# the process (companion generation, MCP elicitation, dispatch-failure
# marking) behind long-running goal threads. A dedicated pool sized to the
# actual concurrency knob keeps goal execution off that shared pool
# entirely. The small allowance covers a submission that is still waiting on
# a per-principal/global semaphore rather than a fresh thread being denied
# outright by pool exhaustion.
_goal_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=MAX_CONCURRENT_GOALS + MAX_CONCURRENT_GOALS_PER_PRINCIPAL,
    thread_name_prefix="maverick-goal",
)

# Per-principal lanes, created on first use. Guarded by _principal_sems_lock.
# The dict grows with the number of distinct principals seen this process — a
# bounded, small set in practice (one per user/agent), so no eviction needed.
_principal_sems: dict[str, threading.BoundedSemaphore] = {}
_principal_sems_lock = threading.Lock()
_ANON_PRINCIPAL = "_anonymous"


def _principal_semaphore(principal: str | None) -> threading.BoundedSemaphore:
    """The concurrency lane for ``principal`` (one shared lane for anon runs)."""
    key = principal or _ANON_PRINCIPAL
    with _principal_sems_lock:
        sem = _principal_sems.get(key)
        if sem is None:
            sem = threading.BoundedSemaphore(MAX_CONCURRENT_GOALS_PER_PRINCIPAL)
            _principal_sems[key] = sem
        return sem

# Cap how long a caller will block waiting for a concurrency slot. Without
# this, a single wedged goal holding a permit blocks the worker's loop
# thread forever (the daemon stops draining the queue entirely). On
# timeout we refuse the run and let the job queue retry later.
_ACQUIRE_TIMEOUT = env_float("MAVERICK_GOAL_ACQUIRE_TIMEOUT", 300.0)


def inflight_goals() -> int:
    """How many goals currently hold a concurrency slot (are running).

    This is tracked explicitly rather than inferred from CPython's private
    ``Semaphore._value`` attribute.  Besides being an implementation detail,
    ``_value`` reports permits rather than accepted runs and is not a portable
    readiness/metrics contract across Python implementations.
    """
    with _inflight_lock:
        return _inflight_count


def close_goal_admission() -> None:
    """Atomically refuse new accepted runs before beginning process drain."""
    global _accepting_goals
    with _inflight_lock:
        _accepting_goals = False


def open_goal_admission() -> None:
    """Reopen only after the dashboard has verified its prior workers exited."""
    global _accepting_goals
    with _inflight_lock:
        if _inflight_count:
            raise RuntimeError("cannot reopen goal admission while prior runs remain")
        _accepting_goals = True


def _mark_inflight_started(*, require_admission: bool = False) -> bool:
    global _inflight_count
    with _inflight_lock:
        if require_admission and not _accepting_goals:
            return False
        _inflight_count += 1
        return True


def _mark_inflight_finished() -> None:
    global _inflight_count
    with _inflight_lock:
        if _inflight_count <= 0:
            # Never publish a negative readiness gauge if an internal caller
            # violates the acquire/release contract.
            log.error("runner in-flight accounting underflow")
            _inflight_count = 0
            return
        _inflight_count -= 1


def drain_inflight(timeout: float = 25.0, poll: float = 0.5) -> int:
    """Block until no goal holds a slot, or ``timeout`` elapses.

    For graceful shutdown: give running goals a bounded chance to finish before
    the worker process exits, instead of hard-killing them mid-LLM-call (which
    bills for work that is then discarded and can leave a goal wedged 'running').
    Returns the count still in-flight at return (0 = fully drained). Synchronous
    (polls the semaphore) -- call it off the event loop. Never raises."""
    deadline = time.monotonic() + max(0.0, timeout)
    while inflight_goals() > 0:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(remaining, max(0.05, poll)))
    return inflight_goals()


def _optional_limit(name: str) -> float | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    value = float(raw)
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be a finite non-negative limit")
    return value


# Product policy for goals started before an installation config exists. Keep
# the optional environment defaults separate: older config files with no task
# caps reflect an operator's existing no-limit choice and must stay that way.
DEFAULT_MAX_DOLLARS = 2.0
DEFAULT_MAX_WALL_SECONDS = 1800.0
_operator_default_dollars = _optional_limit("MAVERICK_DEFAULT_MAX_DOLLARS")
_operator_default_wall_seconds = _optional_limit("MAVERICK_DEFAULT_MAX_WALL_SECONDS")


def goal_budget_defaults() -> dict[str, float | None]:
    """Per-goal fallbacks, preserving no-cap installations already on disk."""
    from .config import config_path

    first_install = not config_path().exists()
    return {
        "max_dollars": (_operator_default_dollars if _operator_default_dollars is not None
                        else DEFAULT_MAX_DOLLARS if first_install else None),
        "max_wall_seconds": (_operator_default_wall_seconds if _operator_default_wall_seconds is not None
                             else DEFAULT_MAX_WALL_SECONDS if first_install else None),
    }


def _default_max_depth_setting() -> int:
    """``[swarm] default_max_depth`` (env ``MAVERICK_DEFAULT_MAX_DEPTH`` wins)."""
    from .env_setting import env_or_config_int

    return env_or_config_int("MAVERICK_DEFAULT_MAX_DEPTH", "swarm", "default_max_depth", 3)


DEFAULT_MAX_DEPTH = _default_max_depth_setting()


class TaskLimitConfigError(ValueError):
    """The deployment's task-limit configuration is malformed (operator fix)."""


def _resolved_cap(field: str, default: float | None) -> float | None:
    from .budget import resolve_budget_caps

    try:
        return resolve_budget_caps(defaults={field: default}).get(field)
    except TaskLimitConfigError:
        raise
    except ValueError as exc:
        raise TaskLimitConfigError(str(exc)) from exc


def configured_max_dollars() -> float | None:
    """The effective spend limit for an omitted goal request, in USD.

    The same precedence a run's budget is built with -- the Settings page's
    spend cap, else the ``[budget]`` config section, else
    ``MAVERICK_BUDGET_DOLLARS``, else the first-install product default --
    resolved without reserving tenant allowance. An explicit request may
    exceed only that first-install default, not an operator-set ceiling.
    """
    return _resolved_cap("max_dollars", goal_budget_defaults()["max_dollars"])


def configured_max_wall_seconds() -> float | None:
    return _resolved_cap("max_wall_seconds", goal_budget_defaults()["max_wall_seconds"])


def configured_goal_ceiling_dollars() -> float | None:
    """An operator-set ceiling, excluding the first-install product default."""
    return _resolved_cap("max_dollars", _operator_default_dollars)


def configured_goal_ceiling_wall_seconds() -> float | None:
    return _resolved_cap("max_wall_seconds", _operator_default_wall_seconds)


def requested_goal_dollars(requested: float | None) -> float | None:
    if requested is None:
        return configured_max_dollars()
    return clamp_task_limit(requested, configured_goal_ceiling_dollars())


def requested_goal_wall_seconds(requested: float | None) -> float | None:
    if requested is None:
        return configured_max_wall_seconds()
    return clamp_task_limit(requested, configured_goal_ceiling_wall_seconds())


def clamp_task_limit(requested: float | None, configured: float | None) -> float | None:
    """An absent task ceiling is not an invented deployment allowance."""
    if requested is None:
        return configured
    return min(requested, configured) if configured is not None else requested


def _allowance_admission(world, goal_id: int, budget):
    """Refuse a known exhausted allowance before entering any goal work.

    Once orchestration starts, any later error remains an ordinary blocked
    result: this boundary cannot certify that the trajectory had no effects.
    """
    from .budget import BudgetExceeded
    from .orchestrator import _budget_stop_message
    from .run_outcome import GoalAdmissionRefused
    from .tenant.provider_admission import OrganizationBudgetExceeded

    goal = world.get_goal(goal_id)
    if goal is None:
        return "blocked"
    if goal.status not in {"pending", "active", "running", "blocked"}:
        return goal.status
    try:
        if reason := getattr(budget, "_tenant_refusal", None):
            raise OrganizationBudgetExceeded(reason)
        budget.check()
    except BudgetExceeded as exc:
        message = _budget_stop_message(budget, goal_id, exc)
        if not world.block_goal_admission(goal_id, result=message):
            # Cancellation/completion may have won after the initial read.
            # This invocation holds no certificate over that outcome.
            return _finished_goal_status(world, goal_id) or "blocked"
        return GoalAdmissionRefused(
            goal_id,
            stop_kind=("organization_budget" if isinstance(exc, OrganizationBudgetExceeded) else "budget"),
            detail=message,
        )
    return None


def _finished_goal_status(world, goal_id: int) -> str | None:
    try:
        goal = world.get_goal(goal_id)
        return goal.status if goal else None
    except Exception:  # pragma: no cover -- read-back may fail independently of execution
        log.exception("run_goal_in_thread: status read-back failed (goal_id=%s)", goal_id)
        return None


def _runner_principal_binding(world, goal, execution_principal):
    """Bind once, then verify a newly bound identity through durable readback."""
    from .orchestrator import _bind_goal_execution_principal
    try:
        matched = _bind_goal_execution_principal(world, goal, execution_principal)
    except Exception:
        log.exception("goal #%s execution-principal binding is unavailable", goal.id)
        return None
    if not matched:
        log.warning("goal #%s execution principal does not match its binding", goal.id)
        return False
    if not (getattr(goal, "execution_principal", "") or ""):
        rebound = world.get_goal(goal.id)
        if rebound is None or (getattr(rebound, "execution_principal", "") or "") != execution_principal:
            log.error("goal #%s execution-principal binding was not observable", goal.id)
            return None
    return True


def _goal_run_exception_status(world, goal_id: int, exc: Exception) -> str:
    """Distinguish an intentional legacy hold from a retryable run crash."""
    from .event_admission import EventRegistryUnavailable, LegacyEventGoalHeld
    from .stop_reasons import exception_stop_text, explain_stop

    if isinstance(exc, LegacyEventGoalHeld):
        return "blocked"
    if isinstance(exc, EventRegistryUnavailable) and _finished_goal_status(world, goal_id) == "pending":
        # The execution claim rolled back before the goal started. Preserve its
        # pending status; the durable worker will retry the same reservation.
        return "error"
    # The swarm crashed after starting; reclaim the visible goal, but leave a
    # retryable queue result so the worker's existing policy can decide.
    log.exception("goal #%s crashed inside run_goal_sync", goal_id)
    try:
        if _finished_goal_status(world, goal_id) not in {"done", "failed", "cancelled"}:
            reason = exception_stop_text(exc)
            world.set_goal_status(goal_id, "failed", result=reason)
            world.append_event(goal_id, "Lightwork", "error", explain_stop(reason).message)
    except Exception:  # pragma: no cover
        log.exception("failed to reclaim goal #%s after crash", goal_id)
    return "error"


def _run_world(db_path: Path | None):
    from .world_model import open_world

    if db_path is None:
        return open_world()
    from .world_model_backends import is_postgres_configured

    if is_postgres_configured():
        raise RuntimeError("An explicit local database cannot run through Postgres.")
    return open_world(db_path)


def run_goal_in_thread(
    goal_id: int,
    max_dollars: float | None = None,
    max_wall_seconds: float | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    *,
    channel: str | None = None,
    user_id: str | None = None,
    conversation_id: int | None = None,
    capability: Any | None = None,
    concurrency_principal: str | None = None,
    allowed_suites: frozenset[str] | None = None,
    acquire_timeout: float | None = None,
    usage_observer=None,
    detailed_outcome: bool = False,
    db_path: Path | None = None,
) -> str | None | GoalRunUnavailable:
    """Synchronously run a goal under the global concurrency semaphore.

    Designed to be passed to ``fastapi.BackgroundTasks.add_task`` or any
    threadpool. Acquires the semaphore (blocking up to ``acquire_timeout``,
    default ``_ACQUIRE_TIMEOUT``, if the cap is reached), runs the swarm,
    releases the semaphore, and never re-raises -- the FastAPI / channel
    callers' contract (return a goal id, poll for result) doesn't surface
    mid-run exceptions.

    ``acquire_timeout`` lets a caller that can cheaply retry later (for
    example the job-queue's run_goal/start_goal handlers, which share a small worker
    pool with cron ticks/flow sweeps) use a short timeout instead of blocking
    a whole worker thread for up to ``_ACQUIRE_TIMEOUT`` per semaphore.

    Returns the goal's terminal status string (``"done"`` / ``"blocked"``
    / ...), or the legacy ``None`` when admission/setup/readback is unavailable.
    With ``detailed_outcome=True`` that unavailable result identifies an actual
    semaphore refusal separately from a missing task or an unconfirmed outcome.
    The worker defers only a semaphore refusal; intentional blocked results do
    not restart the task. Polling callers keep their existing default contract.

    Acquires a fresh WorldModel + LLM + Sandbox per call so each
    background goal gets its own connection (SQLite WAL + check_same_thread
    handles the concurrency), and always closes the WorldModel so the
    per-goal connection + WAL handle don't leak for the process lifetime.
    """
    timeout = acquire_timeout if acquire_timeout is not None else _ACQUIRE_TIMEOUT
    # Per-user lane first: bounds one caller's own fan-out without ever
    # blocking on another caller's runs.  Some execution identities (for
    # example fleet agent audit principals) are derived from user-controlled
    # objects, so callers may pass a separate stable authenticated principal
    # for scheduling while preserving ``user_id`` for audit/governance.
    lane_principal = concurrency_principal if concurrency_principal is not None else user_id
    principal_sem = _principal_semaphore(lane_principal)
    if not principal_sem.acquire(timeout=timeout):
        log.error(
            "run_goal_in_thread: per-user concurrency cap (%d) reached within "
            "%.0fs (goal_id=%s, principal=%s); refusing run",
            MAX_CONCURRENT_GOALS_PER_PRINCIPAL, timeout, goal_id, lane_principal,
        )
        return _unavailable_goal_run("concurrency_slot", detailed_outcome=detailed_outcome)
    # Global ceiling next: only a host-wide saturation makes anyone wait here.
    if not _run_semaphore.acquire(timeout=timeout):
        principal_sem.release()
        log.error(
            "run_goal_in_thread: no global concurrency slot within %.0fs "
            "(goal_id=%s); refusing run", timeout, goal_id,
        )
        return _unavailable_goal_run("concurrency_slot", detailed_outcome=detailed_outcome)
    if not _mark_inflight_started(require_admission=True):
        _run_semaphore.release()
        principal_sem.release()
        log.info("run_goal_in_thread: shutdown admission is closed (goal_id=%s)", goal_id)
        return _unavailable_goal_run("admission_closed", detailed_outcome=detailed_outcome)
    world = None
    sandbox = None
    budget = None
    try:
        from .budget import budget_from_config
        from .llm import LLM
        from .orchestrator import (
            _execution_principal,
            run_goal_sync,
        )
        from .sandbox import build_sandbox
        from .world_model import close_world_if_owned
        world = _run_world(db_path)
        from .federation_admission import FederationAdmissionRequired, require_execution
        try:
            require_execution(world, goal_id, capability=capability,
                              max_dollars=max_dollars, max_wall_seconds=max_wall_seconds)
        except FederationAdmissionRequired:
            return "blocked"
        # Bind/refuse the exact runtime authority before constructing provider
        # or sandbox clients and before trace pinning appends an event. The
        # orchestrator repeats this at its own public boundary; this earlier
        # check protects the runner's setup path too.
        execution_principal = _execution_principal(
            user_id=user_id,
            capability=capability,
        )
        goal = world.get_goal(goal_id)
        if goal is None:
            return _unavailable_goal_run("missing", detailed_outcome=detailed_outcome)
        from .chat_message_actions import runtime_limits, runtime_scope
        alternative, max_dollars, max_wall_seconds, max_depth, capability = runtime_limits(
            world, goal, max_dollars, max_wall_seconds, max_depth, capability)
        from .goal_mutations import GoalMutationConflict
        from .human_conversation_handoffs import require_ai_open
        from .task_handoffs import closure
        try:
            require_ai_open(world, goal_id)
        except GoalMutationConflict:
            return "blocked"
        if closure(world, goal_id):
            return "blocked"
        principal_matches = _runner_principal_binding(world, goal, execution_principal)
        if principal_matches is None:
            return _unavailable_goal_run("unknown", detailed_outcome=detailed_outcome)
        if not principal_matches:
            # A rejected caller has no authority to change the goal. In
            # particular, it must not interrupt another principal's live run.
            return "blocked"
        # Director mode (a dashboard start with an autonomy level): its
        # recorded spending cap can only lower this run's, and its consent
        # mode and review checkpoints (applied around the run below) can only
        # tighten the installation's.
        from .director_mode import recorded_envelope, run_scope, spending_cap
        director = recorded_envelope(world, goal_id)
        max_dollars = spending_cap(director, max_dollars)
        # Precedence: explicit caller arg > [budget] config > the
        # background runner's conservative defaults (tighter than the
        # interactive Budget defaults on purpose).
        budget = budget_from_config(
            defaults=goal_budget_defaults(),
            max_dollars=max_dollars,
            max_wall_seconds=max_wall_seconds,
        )
        admission = _allowance_admission(world, goal_id, budget)
        if admission is not None:
            return admission
        from .task_model_selection import run_scope as task_model_scope
        # Validate retained choices before provider/sandbox construction. The
        # same scope is reinstated below for every normal team role on resume.
        with task_model_scope(world, goal_id):
            llm = LLM()
        sandbox = build_sandbox()
        # Trace pinning: stamp the run with the workspace's git state so the
        # trace/replay ties to an exact commit. Best-effort, never blocks.
        from .trace_pin import pin_trace
        pin_trace(world, goal_id)
        try:
            with run_scope(director), runtime_scope(world, goal_id, alternative), task_model_scope(world, goal_id):
                run_goal_sync(
                    llm, world, budget,
                    goal_id, sandbox=sandbox, max_depth=max_depth,
                    conversation_id=conversation_id, channel=channel,
                    user_id=user_id, capability=capability,
                    allowed_suites=allowed_suites, resume=True,
                )
        except Exception as exc:
            return _goal_run_exception_status(world, goal_id, exc)
        # Read back the terminal status so the worker can decide retry.
        status = _finished_goal_status(world, goal_id)
        return status if status is not None else _unavailable_goal_run(
            "unknown", detailed_outcome=detailed_outcome,
        )
    except Exception:
        log.exception("background goal run failed (goal_id=%s)", goal_id)
        return _unavailable_goal_run("unknown", detailed_outcome=detailed_outcome)
    finally:
        if usage_observer is not None and budget is not None:
            # Internal flow accounting observes the completed meter. It cannot
            # replace the runner's configured spending authority.
            try:
                usage_observer(budget.dollars)
            except Exception:
                log.exception("goal usage observer failed (goal_id=%s)", goal_id)
        if sandbox is not None:
            close = getattr(sandbox, "close", None)
            if close is not None:
                try:
                    close()
                except Exception:  # pragma: no cover
                    log.debug("run_goal_in_thread: sandbox.close() failed", exc_info=True)
        if world is not None:
            try:
                close_world_if_owned(world)
            except Exception:  # pragma: no cover
                log.debug("run_goal_in_thread: world close failed", exc_info=True)
        # The run is no longer doing work once cleanup completes. Publish that
        # truth before returning the permit so a newly-admitted run cannot
        # briefly double-count with this finished one.
        _mark_inflight_finished()
        # Release in reverse acquire order: global ceiling, then the user lane.
        try:
            _run_semaphore.release()
        finally:
            principal_sem.release()


class Dispatcher(Protocol):
    """Where a goal runs. The seam between "execute in-process" (today) and a
    distributed task queue (arq / Celery / Temporal) later.

    ``submit`` returns a terminal status for a waiting dispatcher, ``"queued"``
    for an accepted asynchronous enqueue, or ``None`` for an unavailable or
    indeterminate result. A queued status is an admission receipt, not a
    completion or cancellation handle. ``None`` does not establish that a
    previous attempt had no effects. These return values preserve the legacy
    status contract of :func:`run_goal_in_thread`.
    """

    def submit(
        self,
        goal_id: int,
        *,
        max_dollars: float | None = None,
        max_wall_seconds: float | None = None,
        max_depth: int = DEFAULT_MAX_DEPTH,
        channel: str | None = None,
        user_id: str | None = None,
        conversation_id: int | None = None,
        capability: Any | None = None,
        concurrency_principal: str | None = None,
        allowed_suites: frozenset[str] | None = None,
    ) -> str | None: ...


class LocalThreadDispatcher:
    """Default dispatcher: run the goal in-process under the concurrency
    semaphore (the current behaviour). Delegates to
    :func:`run_goal_in_thread` so there is exactly one execution path."""

    def submit(
        self,
        goal_id: int,
        *,
        max_dollars: float | None = None,
        max_wall_seconds: float | None = None,
        max_depth: int = DEFAULT_MAX_DEPTH,
        channel: str | None = None,
        user_id: str | None = None,
        conversation_id: int | None = None,
        capability: Any | None = None,
        concurrency_principal: str | None = None,
        allowed_suites: frozenset[str] | None = None,
        db_path: Path | None = None,
        _detailed_outcome: bool = False,
    ) -> str | None | GoalRunUnavailable:
        return run_goal_in_thread(
            goal_id=goal_id, max_dollars=max_dollars,
            max_wall_seconds=max_wall_seconds, max_depth=max_depth,
            channel=channel, user_id=user_id, conversation_id=conversation_id,
            capability=capability,
            concurrency_principal=concurrency_principal,
            allowed_suites=allowed_suites,
            **({"detailed_outcome": True} if _detailed_outcome else {}),
            **({"db_path": db_path} if db_path is not None else {}),
        )

    def submit_observed(self, goal_id: int, **kwargs: Any) -> DispatchObservation:
        """Report the synchronous result; it is not a cancellable thread handle."""
        # Subclasses may override submit without the internal detailed option;
        # preserve that legacy override and do not infer refusal from None.
        if type(self) is not LocalThreadDispatcher:
            return observe_dispatch(goal_id, self.submit(goal_id, **kwargs), owner="local")
        result = self.submit(goal_id, _detailed_outcome=True, **kwargs)
        if isinstance(result, GoalRunUnavailable):
            state = (DispatchState.UNKNOWN if result.reason == "unknown"
                     else DispatchState.NOT_ACCEPTED)
            return DispatchObservation(goal_id, state, None, owner="local", reason=result.reason)
        return observe_dispatch(goal_id, result, owner="local")

    def submit_handle(self, goal_id: int, **kwargs: Any) -> ExecutionHandle:
        """Return a handle for the same single synchronous submission."""
        return _submission_handle(
            goal_id, lambda: self.submit_observed(goal_id, **kwargs), owner="local",
        )


_dispatcher: Dispatcher = LocalThreadDispatcher()


def get_dispatcher() -> Dispatcher:
    """The active goal dispatcher (default: in-process thread execution)."""
    return _dispatcher


def set_dispatcher(dispatcher: Dispatcher) -> None:
    """Swap the goal dispatcher process-wide. The hook a queue/worker backend
    (arq / Celery / Temporal) installs at startup to move execution off the API
    process without touching any caller."""
    global _dispatcher
    _dispatcher = dispatcher


def _eligible_dispatcher(goal_id: int, db_path: Path | None) -> Dispatcher | None:
    """Apply deployment restrictions before either submission interface."""
    from . import practice

    dispatcher = get_dispatcher()
    if db_path is not None and not isinstance(dispatcher, LocalThreadDispatcher):
        raise RuntimeError("An explicit local database cannot be sent to a network worker.")
    if practice.active() and not isinstance(dispatcher, LocalThreadDispatcher):
        _mark_dispatch_failure(goal_id, practice.WORKERS_REASON + " This practice task did not start.",
                               **({"db_path": db_path} if db_path is not None else {}))
        return None
    return dispatcher


def start_goal_observed(
    goal_id: int,
    max_dollars: float | None = None,
    max_wall_seconds: float | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    *,
    channel: str | None = None,
    user_id: str | None = None,
    conversation_id: int | None = None,
    capability: Any | None = None,
    concurrency_principal: str | None = None,
    allowed_suites: frozenset[str] | None = None,
    db_path: Path | None = None,
) -> DispatchObservation:
    """Submit once and return only the dispatcher's known acceptance evidence.

    Queue receipts identify a signed submission, not a worker lease. The
    current queue and local adapters do not provide a unified cancellation or
    settlement operation: callers must use the goal/worker owner for those
    actions. A raised transport exception remains an exception and may leave
    the submission outcome unknown; this function never retries it.
    """
    dispatcher = _eligible_dispatcher(goal_id, db_path)
    if dispatcher is None:
        return DispatchObservation(goal_id, DispatchState.NOT_ACCEPTED, "error",
                                   reason="practice_worker_unavailable")
    kwargs = dict(
        max_dollars=max_dollars, max_wall_seconds=max_wall_seconds,
        max_depth=max_depth, channel=channel, user_id=user_id,
        conversation_id=conversation_id, capability=capability,
        concurrency_principal=concurrency_principal, allowed_suites=allowed_suites,
        **({"db_path": db_path} if db_path is not None else {}),
    )
    submit_observed = getattr(dispatcher, "submit_observed", None)
    if callable(submit_observed):
        observation = submit_observed(goal_id, **kwargs)
        if not _valid_dispatch_observation(observation, goal_id):
            raise RuntimeError("dispatcher returned an invalid submission observation")
        return observation
    observation = observe_dispatch(goal_id, dispatcher.submit(goal_id, **kwargs))
    if not _valid_dispatch_observation(observation, goal_id):
        raise RuntimeError("dispatcher returned an invalid submission status")
    return observation


def start_goal_handle(goal_id: int, **kwargs: Any) -> ExecutionHandle:
    """Submit once using the active adapter and retain its typed evidence."""
    return _submission_handle(goal_id, lambda: start_goal_observed(goal_id, **kwargs))


def run_goal_in_background(
    goal_id: int,
    max_dollars: float | None = None,
    max_wall_seconds: float | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    *,
    channel: str | None = None,
    user_id: str | None = None,
    conversation_id: int | None = None,
    capability: Any | None = None,
    concurrency_principal: str | None = None,
    allowed_suites: frozenset[str] | None = None,
    db_path: Path | None = None,
) -> str | None:
    """Dispatch a goal through the active :class:`Dispatcher`. Defaults to
    in-process thread execution; ``set_dispatcher`` swaps in a task queue
    without breaking callers (the contract is unchanged: returns the terminal
    status, ``"queued"`` after asynchronous acceptance, or ``None`` when no
    definitive status is available).

    A practice task (:mod:`maverick.practice`) never goes to an outside
    worker, which would run it live: it is stopped with the reason instead."""
    dispatcher = _eligible_dispatcher(goal_id, db_path)
    if dispatcher is None:
        return "error"
    return dispatcher.submit(
        goal_id, max_dollars=max_dollars,
        max_wall_seconds=max_wall_seconds, max_depth=max_depth,
        channel=channel, user_id=user_id, conversation_id=conversation_id,
        capability=capability,
        concurrency_principal=concurrency_principal,
        allowed_suites=allowed_suites,
        **({"db_path": db_path} if db_path is not None else {}),
    )


async def start_goal_observed_async(
    goal_id: int,
    max_dollars: float | None = None,
    max_wall_seconds: float | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    *,
    channel: str | None = None,
    user_id: str | None = None,
    conversation_id: int | None = None,
    capability: Any | None = None,
    concurrency_principal: str | None = None,
    allowed_suites: frozenset[str] | None = None,
    db_path: Path | None = None,
) -> DispatchObservation:
    """Dispatch without blocking an async channel or HTTP event loop.

    Dispatcher submission is deliberately synchronous: local execution waits
    for the terminal status, queue submission may perform broker I/O, and gRPC
    waits for the worker RPC. Runs on the dedicated ``_goal_executor``
    rather than ``asyncio.to_thread``'s shared default pool, so a long local
    run can't starve other to_thread callers or get starved by them, and the
    advertised MAX_CONCURRENT_GOALS ceiling is actually reachable regardless
    of host core count. Context is propagated the same way
    ``asyncio.to_thread`` does it (``contextvars.copy_context().run(...)``),
    preserving the active tenant across the thread hop.

    Cancelling the waiting coroutine does not stop a submission that has
    already started in the executor, and does not cancel an accepted queued
    job. Callers must use the execution owner's own cancellation and status
    mechanisms instead of treating cancellation of this await as confirmation
    that execution stopped.
    """
    loop = asyncio.get_running_loop()
    ctx = contextvars.copy_context()
    call = functools.partial(
        ctx.run,
        start_goal_observed,
        goal_id,
        max_dollars,
        max_wall_seconds,
        max_depth,
        channel=channel,
        user_id=user_id,
        conversation_id=conversation_id,
        capability=capability,
        concurrency_principal=concurrency_principal,
        allowed_suites=allowed_suites,
        **({"db_path": db_path} if db_path is not None else {}),
    )
    try:
        observation = await loop.run_in_executor(_goal_executor, call)
    except Exception:
        # An exception can follow a remote acceptance or an effect. Preserve the
        # legacy no-raise return without repainting a potentially live goal or
        # falling back locally. A caller must reconcile before another attempt.
        log.exception("goal #%s dispatcher submission failed", goal_id)
        return DispatchObservation(goal_id, DispatchState.UNKNOWN, "error",
                                   reason="dispatch_exception")
    if observation.state is DispatchState.NOT_ACCEPTED:
        # Rejection proves only this invocation did not start. Another pending
        # submission may already have been accepted, so do not repaint its
        # goal without a durable exclusive dispatch reservation.
        log.info("goal #%s dispatch not accepted (%s)", goal_id, observation.reason)
    return observation


async def start_goal_handle_async(goal_id: int, **kwargs: Any) -> ExecutionHandle:
    """Submit once without blocking, retaining the resulting typed evidence."""
    observation = await start_goal_observed_async(goal_id, **kwargs)
    return observation.as_handle()


async def run_goal_in_background_async(
    goal_id: int,
    max_dollars: float | None = None,
    max_wall_seconds: float | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    *,
    channel: str | None = None,
    user_id: str | None = None,
    conversation_id: int | None = None,
    capability: Any | None = None,
    concurrency_principal: str | None = None,
    allowed_suites: frozenset[str] | None = None,
    db_path: Path | None = None,
) -> str | None:
    """Legacy async result; unknown effects must be reconciled before retry."""
    observation = await start_goal_observed_async(
        goal_id, max_dollars, max_wall_seconds, max_depth, channel=channel,
        user_id=user_id, conversation_id=conversation_id, capability=capability,
        concurrency_principal=concurrency_principal, allowed_suites=allowed_suites,
        **({"db_path": db_path} if db_path is not None else {}),
    )
    return observation.status


def _mark_dispatch_failure(goal_id: int, result: str, *, db_path: Path | None = None) -> None:
    """Best-effort terminalization after a dispatcher cannot start a goal."""
    world = None
    try:
        from .world_model import close_world_if_owned

        world = _run_world(db_path)
        # The pending predicate must be part of the update: a worker can claim
        # the goal after a read but before a separate status write.
        block_pending = getattr(world, "block_pending_goal", None)
        if callable(block_pending):
            block_pending(goal_id, result=result)
        else:
            log.warning("world backend cannot atomically repair dispatch failure (goal_id=%s)",
                        goal_id)
    except Exception:  # pragma: no cover - status repair must never mask dispatch
        log.exception("failed to terminalize undispatched goal #%s", goal_id)
    finally:
        if world is not None:
            try:
                close_world_if_owned(world)
            except Exception:  # pragma: no cover - best-effort cleanup
                log.debug("dispatch failure world close failed", exc_info=True)
