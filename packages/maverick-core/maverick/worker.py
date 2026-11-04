"""Job-queue worker daemon.

Drains :class:`maverick.job_queue.JobQueue` by claiming pending jobs
and dispatching them to registered handlers. Designed for one or
more worker processes to share the same SQLite DB safely (claim is
atomic).

A handler is just a callable ``(job: Job) -> None``. Raise to fail;
return cleanly to succeed. The worker handles retry / terminal
failure / sleep-when-empty automatically.

Built-in handlers:
  - ``run_goal``  — payload {"goal_id": int} -> runs an EXISTING goal via
    maverick.runner.run_goal_in_thread (with a sync wait).
  - ``start_goal`` — payload {"text": str, "title"?: str} -> creates a FRESH
    goal from the prompt on each run, then runs it. This is the kind to pair
    with cron for a recurring autonomous task (``maverick schedule goal``).

Custom handlers are registered via :meth:`Worker.register`.

CLI entry: ``maverick worker [--db PATH] [--idle-sleep 2.0]``
(wired in cli.py when shipped; this module just exposes the loop).
"""
from __future__ import annotations

import logging
import signal
import threading
import time
import traceback
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

from ._envparse import env_float, env_int
from .job_queue import Job, JobQueue, LeaseLost

log = logging.getLogger(__name__)

# The automation worker pool shares a handful of threads (default 3)
# across run_goal/start_goal AND control jobs (cron ticks, flow sweeps). The
# default per-semaphore acquire timeout (5 minutes, see runner._ACQUIRE_TIMEOUT)
# is sized for a caller that has nothing better to do but wait; a queue worker
# thread does -- other jobs are waiting behind it -- so it probes for a slot
# only briefly and defers instead of blocking the pool for minutes.
_QUEUE_GOAL_ACQUIRE_TIMEOUT = env_float("MAVERICK_QUEUE_GOAL_ACQUIRE_TIMEOUT", 5.0)


def _queue_goal_acquire_timeout() -> float:
    """The environment's value, else ``[queue] goal_acquire_timeout_seconds``
    (settable on the dashboard's All settings page), else the default."""
    import math
    import os

    if os.environ.get("MAVERICK_QUEUE_GOAL_ACQUIRE_TIMEOUT", "").strip():
        return _QUEUE_GOAL_ACQUIRE_TIMEOUT
    try:
        from .config import load_config

        raw = ((load_config() or {}).get("queue") or {}).get("goal_acquire_timeout_seconds")
        value = float(raw) if raw is not None else _QUEUE_GOAL_ACQUIRE_TIMEOUT
    except Exception:  # an unreadable config keeps the default
        return _QUEUE_GOAL_ACQUIRE_TIMEOUT
    return value if math.isfinite(value) and value >= 0 else _QUEUE_GOAL_ACQUIRE_TIMEOUT
# Bounded like automation_queue._defer_for_slot's flow-concurrency defer, so a
# goal whose principal/global lane never frees up doesn't requeue forever.
_MAX_GOAL_SLOT_DEFERS = env_int("MAVERICK_GOAL_SLOT_MAX_DEFERS", 20)
_GOAL_SLOT_DEFER_SECONDS = env_float("MAVERICK_GOAL_SLOT_DEFER_SECONDS", 15.0)
_SLOT_DEFERS_KEY = "_slot_defers"
_GOAL_CREATION_STARTED_KEY = "_goal_creation_started"


Handler = Callable[[Job], None]

# Job kinds the worker handles out of the box. Embedders add more at runtime
# via Worker.register(); this is the set the bare ``maverick worker`` knows.
# Exposed so ``maverick schedule add`` can warn on a likely-typo'd kind that
# would otherwise sit in the queue and fail terminally only at worker time.
BUILTIN_JOB_KINDS = frozenset({"run_goal", "start_goal"})

def _run_identity_kwargs(payload: dict) -> dict[str, object]:
    """Extract optional runner identity context from a queue payload."""
    run_kwargs: dict[str, object] = {}
    channel = str(payload.get("channel") or "").strip()
    user_id = str(payload.get("user_id") or "").strip()
    if channel:
        run_kwargs["channel"] = channel
    if user_id:
        run_kwargs["user_id"] = user_id
    concurrency_principal = str(payload.get("concurrency_principal") or "").strip()
    if concurrency_principal:
        run_kwargs["concurrency_principal"] = concurrency_principal
    allowed_suites = payload.get("allowed_suites")
    if allowed_suites is not None:
        run_kwargs["allowed_suites"] = frozenset(str(s) for s in allowed_suites)
    return run_kwargs


def _run_budget_kwargs(payload: dict) -> dict[str, float]:
    """Carry optional reviewed schedule ceilings through current native limits."""
    import math

    from .config import config_source_errors
    from .runner import requested_goal_dollars, requested_goal_wall_seconds

    result = {}
    for name, resolve in (("max_dollars", requested_goal_dollars), ("max_wall_seconds", requested_goal_wall_seconds)):
        if name not in payload:
            continue
        value = payload[name]
        if type(value) not in {int, float} or not math.isfinite(value) or value < 0 or (name == "max_wall_seconds" and value == 0):
            raise ValueError("The saved schedule's reviewed spending or time limit is invalid; no task was started.")
        if config_source_errors(include_tenant=True):
            raise ValueError("Current schedule spending settings are unavailable; no task was started.")
        result[name] = resolve(value)
    return result


@contextmanager
def _job_tenant_context(payload: dict):
    """Pin a durable job to its captured tenant before any work begins.

    Queue workers are process-global and run outside the HTTP request task that
    originally selected a tenant.  Merely persisting ``payload['tenant']`` is
    therefore not isolation: without restoring the ContextVar, ``run_goal`` and
    custom handlers open the ambient/shared world.  Validate current tenant
    status before re-arming or dispatching so a suspended tenant cannot keep
    executing autonomous work from an old queue row.
    """
    tenant = str(payload.get("tenant") or "").strip()
    if not tenant:
        yield
        return

    from .tenant.registry import assert_tenant_active

    assert_tenant_active(tenant)
    from .paths import reset_tenant, set_tenant

    token = set_tenant(tenant)
    try:
        yield
    finally:
        reset_tenant(token)

class UnknownJobKind(Exception):
    """Raised when no handler is registered for a job.kind."""


class GoalRunFailed(Exception):
    """Raised by the built-in run_goal handler when the goal did not reach
    a successful terminal status, so run_once() routes it through the
    queue's retry/backoff path instead of marking the job done."""


class GoalRunStopped(Exception):
    """An unavailable task or unconfirmed attempt must not automatically replay."""


class RearmFailed(Exception):
    """Raised by ``_maybe_rearm`` when enqueuing a cron job's next occurrence
    fails (e.g. a transient ``database is locked``). Surfaced through
    ``run_once``'s retry/dead-letter path so a later attempt re-arms the
    schedule -- instead of the old best-effort-once behaviour that logged the
    error and let the recurring schedule die silently."""


class Worker:
    def __init__(
        self,
        queue: JobQueue | None = None,
        *,
        db_path: Path | None = None,
        idle_sleep: float = 2.0,
        idle_backoff_start: float = 0.2,
        max_attempts: int = 5,
        retry_after: float = 60.0,
        reclaim_lease: float = 3600.0,
    ) -> None:
        self._runtime_configuration_native = queue is None and db_path is None
        self.queue = queue or JobQueue(db_path=db_path)
        self.idle_sleep = float(idle_sleep)
        # After an empty claim the loop waits idle_backoff_start, doubling up
        # to idle_sleep while the queue stays empty, and starts over after a
        # job runs: a queued goal is picked up within ~0.2 s of an idle
        # worker rather than up to 2 s, without busy-polling an empty queue.
        self.idle_backoff_start = min(float(idle_backoff_start), self.idle_sleep)
        self.max_attempts = int(max_attempts)
        self.retry_after = float(retry_after)
        # Jobs stuck 'running' longer than this with no lease heartbeat (a
        # prior worker crashed mid-job) are requeued on start. A live worker
        # renews its claimed job's lease while the handler runs (run_once),
        # so a job may outlast the lease without being stolen; only a dead
        # worker stops renewing.
        self.reclaim_lease = float(reclaim_lease)
        self._handlers: dict[str, Handler] = {}
        self._stop = threading.Event()
        self._install_builtin_handlers()

    def register(self, kind: str, handler: Handler) -> None:
        self._handlers[kind] = handler

    def _defer_for_concurrency_slot(self, job: Job) -> bool:
        """Re-enqueue a run_goal/start_goal job because no concurrency slot
        was free within the short queue-probe window, WITHOUT bumping
        job_queue's own attempts/dead-letter counter.

        ``claim()`` bumps ``attempts`` on every claim regardless of outcome,
        so resetting the SAME row's ``run_at`` in place would still march it
        toward ``max_attempts`` even though this attempt never ran. Enqueuing a
        fresh row instead -- mirroring
        ``maverick_dashboard.automation_queue._defer_for_slot``'s pattern for
        flow concurrency caps -- lets the original job complete normally.
        Returns True if deferred, False once the defer budget
        (``_MAX_GOAL_SLOT_DEFERS``) is spent.
        """
        defers = int(job.payload.get(_SLOT_DEFERS_KEY) or 0)
        if defers >= _MAX_GOAL_SLOT_DEFERS:
            return False
        payload = dict(job.payload)
        payload[_SLOT_DEFERS_KEY] = defers + 1
        self.queue.enqueue(
            job.kind, payload, run_at=time.time() + _GOAL_SLOT_DEFER_SECONDS,
        )
        log.info(
            "worker: job %d deferred for a concurrency slot (attempt %d/%d)",
            job.id, defers + 1, _MAX_GOAL_SLOT_DEFERS,
        )
        return True

    def _install_builtin_handlers(self) -> None:
        def _run_goal(job: Job) -> None:
            goal_id = job.payload.get("goal_id")
            if not goal_id:
                raise ValueError("run_goal payload requires goal_id")
            # Sync run so the queue waits before claiming the next job. A
            # short acquire_timeout keeps a busy principal/global
            # concurrency lane from blocking this worker thread -- shared
            # with cron ticks and flow sweeps -- for minutes.
            from .runner import run_goal_in_thread
            status = run_goal_in_thread(
                int(goal_id), acquire_timeout=_queue_goal_acquire_timeout(),
                detailed_outcome=True,
                **_run_identity_kwargs(job.payload),
            )
            self._finish_goal_run(job, goal_id, status)
        self._handlers["run_goal"] = _run_goal

        def _start_goal(job: Job) -> None:
            # A recurring autonomous task creates a FRESH goal from the prompt
            # on every fire -- unlike run_goal, which re-runs one fixed goal_id
            # (re-executing the same world-model row). Pair with cron via
            # `maverick schedule goal "<cron>" "<prompt>"`; _maybe_rearm carries
            # the prompt forward in the payload so each occurrence is new.
            run_budget = _run_budget_kwargs(job.payload)
            text = (job.payload.get("text") or "").strip()
            if not text:
                raise ValueError("start_goal payload requires non-empty 'text'")
            # Idempotent across retries: create the fresh goal only once, then
            # persist its id into the job payload. A retry of THIS job reuses it
            # (re-running the existing goal, like run_goal) instead of minting a
            # duplicate goal row on every transient failure. _maybe_rearm runs
            # before dispatch, so the next cron occurrence still gets the
            # original (goal_id-free) payload and creates its own fresh goal.
            goal_id = job.payload.get("goal_id")
            if not goal_id:
                goal_id = self._create_scheduled_goal(job, text)
            # Same retry contract as run_goal: only a genuine crash requeues;
            # a missing concurrency slot defers instead.
            from .runner import run_goal_in_thread
            status = run_goal_in_thread(
                int(goal_id), acquire_timeout=_queue_goal_acquire_timeout(),
                detailed_outcome=True,
                **_run_identity_kwargs(job.payload),
                **run_budget,
            )
            self._finish_goal_run(job, goal_id, status)
        self._handlers["start_goal"] = _start_goal

    def _finish_goal_run(self, job: Job, goal_id, status) -> None:
        from .runner import GoalRunUnavailable

        if isinstance(status, GoalRunUnavailable):
            if status.reason == "concurrency_slot":
                if self._defer_for_concurrency_slot(job):
                    return
                raise GoalRunStopped(
                    f"Task {goal_id} could not obtain a concurrency slot after "
                    f"{_MAX_GOAL_SLOT_DEFERS} deferrals. Automatic attempts have stopped."
                )
            if status.reason == "missing":
                raise GoalRunStopped(
                    f"Task {goal_id} is no longer available. This job will not restart it."
                )
            if status.reason == "admission_closed":
                raise GoalRunStopped(
                    "This worker has stopped accepting tasks. This job will not restart the task."
                )
        if status is None or isinstance(status, GoalRunUnavailable):
            raise GoalRunStopped(
                f"Task {goal_id}'s outcome could not be confirmed. Check its activity "
                "before starting more work. This job will not restart it."
            )
        # Preserve the existing retry policy for a genuine crash; an intentional
        # blocked result (budget, cancellation, or user input) completes normally.
        if status in ("error", "failed"):
            raise GoalRunFailed(f"goal {goal_id} terminal status={status!r}")

    def _create_scheduled_goal(self, job: Job, text: str) -> int:
        from .template_connections import SelectionUnavailable, validate
        from .world_model import close_world_if_owned, open_world

        world = None
        try:
            if job.payload.get(_GOAL_CREATION_STARTED_KEY):
                raise GoalRunStopped(
                    "An earlier attempt's scheduled task creation could not be confirmed. "
                    "Check task history before starting more work. This job will not create another task."
                )
            # Check the saved account selections first: a read-only refusal
            # (revoked access, changed permissions) is certain no task was
            # created, so it must surface as itself -- before the uncertain
            # creation marker below, which would otherwise block the job as
            # "could not be confirmed".
            owner = str(job.payload.get("owner") or "")
            refs = validate(owner, job.payload.get("connection_references", []))
            # Persist the uncertain boundary before task creation. A reclaimed
            # lease with this marker and no task id cannot mint a second task.
            # Recurrence's immutable clean template was captured before dispatch.
            job.payload[_GOAL_CREATION_STARTED_KEY] = True
            if not self.queue.set_payload(
                job.id, job.payload, expected_attempts=job.attempts,
            ):
                raise LeaseLost(f"job {job.id}: creation admission lease was lost")
            world = open_world()  # client/tenant-floored canonical world
            title = (job.payload.get("title") or text).strip()[:80]
            goal_id = world.create_goal(title, text, owner=owner,
                **({"connection_references": refs} if refs else {}))
            schedule_id = job.payload.get("schedule_id")
            if schedule_id:
                world.record_goal_origin(goal_id, "schedule", str(schedule_id))
            job.payload.pop(_GOAL_CREATION_STARTED_KEY)
            job.payload["goal_id"] = goal_id
            if not self.queue.set_payload(
                job.id, job.payload, expected_attempts=job.attempts,
            ):
                raise LeaseLost(f"job {job.id}: goal checkpoint lease was lost")
            return goal_id
        except (LeaseLost, GoalRunStopped, SelectionUnavailable):
            raise
        except Exception as exc:
            raise GoalRunStopped(
                "The scheduled task's creation or saved link could not be confirmed. "
                "Check task history before starting more work. This job will not create another task."
            ) from exc
        finally:
            if world is not None:
                try:
                    close_world_if_owned(world)
                except Exception:
                    # A connection cleanup failure cannot undo the durable
                    # checkpoint or authorize another task creation.
                    log.warning("worker: scheduled task connection cleanup failed")

    def stop(self) -> None:
        self._stop.set()

    def _dispatch(self, job: Job) -> None:
        handler = self._handlers.get(job.kind)
        if handler is None:
            raise UnknownJobKind(job.kind)
        handler(job)

    def _maybe_rearm(self, job: Job) -> None:
        """Advance the occurrence in one lease-fenced queue transaction.

        Even an already-armed occurrence verifies ownership and reloads its
        checkpoint. A lost lease stops dispatch; transient transaction failures
        still use the normal retry/dead-letter path without losing a schedule.
        """
        try:
            current = self.queue.rearm(job.id, expected_attempts=job.attempts)
        except LeaseLost:
            raise
        except Exception as err:
            raise RearmFailed(
                f"failed to re-arm job {job.id} ({type(err).__name__})"
            ) from err
        job.payload = current.payload
        job.successor_id = current.successor_id

    def run_once(self, *, ready_at: float | None = None) -> bool:
        """Process at most one job. Returns True if a job ran.

        ``ready_at`` bounds which pending rows are considered ready. The
        daemon leaves it unset so each claim uses the current wall clock;
        one-shot drain mode passes its start time so jobs that become due
        while an earlier long-running handler executes wait for the next
        invocation.
        """
        job = self.queue.claim(ready_at=ready_at)
        if job is None:
            return False
        log.info("worker: claimed job %d kind=%s (attempt %d)",
                 job.id, job.kind, job.attempts)
        # Renew the lease while the handler runs: claim() writes updated_at
        # once, so without a heartbeat any job outliving reclaim_lease looked
        # crashed to a peer daemon's periodic reclaim_stale and was requeued +
        # re-executed WHILE still running here (double LLM spend, double side
        # effects). A real crash kills this thread with the process, so
        # orphan recovery is unaffected.
        hb_stop = threading.Event()
        hb = threading.Thread(
            target=self._heartbeat_lease, args=(job, hb_stop),
            name=f"maverick-job-{job.id}-lease", daemon=True,
        )
        hb.start()
        try:
            with _job_tenant_context(job.payload):
                # Re-arm the next cron occurrence INSIDE the tenant + guarded
                # block (before dispatch) so suspended tenants cannot continue
                # autonomous schedules and a re-arm enqueue failure routes
                # through the same retry/dead-letter path as handler failure.
                # It is idempotent, so a retry never duplicates the successor.
                self._maybe_rearm(job)
                self._dispatch(job)
        except LeaseLost:
            # The new owner, not this stale attempt, controls retry/checkpoints.
            log.warning("worker: job %d lease lost; stopped bookkeeping", job.id)
        except UnknownJobKind as e:
            # No retry — terminal.
            self.queue.fail(job.id, f"no handler for kind {e}",
                            retry_after=None, max_attempts=0,
                            expected_attempts=job.attempts)
            log.warning("worker: job %d has no handler (%s)", job.id, e)
        except GoalRunStopped as exc:
            # The fixed native message contains no source bodies or exception
            # details. Fail this owned attempt without replaying uncertain work.
            self.queue.fail(job.id, str(exc), retry_after=None, max_attempts=0,
                            expected_attempts=job.attempts)
            log.warning("worker: job %d stopped: %s", job.id, exc)
        except Exception as exc:
            # Put the actionable exception summary first: JobQueue bounds the
            # durable error, and long Windows paths can otherwise consume that
            # budget before the final traceback line. Scrub both the persisted
            # row and log message because provider/tool failures may carry a
            # credential in their exception text.
            raw = (
                f"{type(exc).__name__}: {exc}\n"
                + traceback.format_exc(limit=4)
            )
            try:
                from .secrets import scrub

                err = scrub(raw)
            except Exception:  # never persist an unredacted fallback
                err = f"{type(exc).__name__}: job handler failed (details redacted)"
            self.queue.fail(
                job.id, err,
                retry_after=self.retry_after,
                max_attempts=self.max_attempts,
                expected_attempts=job.attempts,
            )
            log.warning("worker: job %d failed, requeued: %s",
                        job.id, err.splitlines()[0])
        else:
            # The terminal write is a separate failure domain from the
            # handler. It used to share the try above, so a transient error
            # here (e.g. sqlite "database is locked" past busy_timeout) was
            # routed through the except Exception clause above -- requeuing a
            # job whose handler had ALREADY run to completion, and re-running
            # it on the very next claim. That is a duplicate-side-effect bug
            # on the normal path, not just the documented at-least-once
            # reclaim-path caveat below.
            self._complete_with_retry(job)
        finally:
            hb_stop.set()
            hb.join(timeout=5.0)
        return True

    def _complete_with_retry(self, job: Job, *, attempts: int = 3) -> None:
        """Mark a successfully-dispatched job 'done', retrying the write.

        ``complete()`` is a pure, attempt-fenced UPDATE with no side effects
        of its own, so retrying it on failure is always safe -- unlike
        routing the failure through ``fail()``, which would re-queue (and
        re-run) a handler that already succeeded. If every attempt fails,
        the job is left 'running': the same lease-reclaim path that recovers
        a crashed worker (see ``_reclaim_stale``'s caveat) will eventually
        pick it back up, rather than this call manufacturing an immediate,
        unwarranted re-run.
        """
        delay = 0.05
        for attempt in range(1, attempts + 1):
            try:
                if self.queue.complete(job.id, expected_attempts=job.attempts):
                    log.info("worker: job %d done", job.id)
                else:
                    log.warning("worker: job %d completion ignored after lease loss", job.id)
                return
            except Exception:
                if attempt == attempts:
                    log.exception(
                        "worker: job %d handler succeeded but complete() "
                        "failed after %d attempt(s); leaving it 'running' "
                        "for lease reclaim instead of re-running the handler",
                        job.id, attempts,
                    )
                    return
                time.sleep(delay)
                delay *= 3

    def _heartbeat_lease(self, job: Job, stop: threading.Event) -> None:
        """Bump the claimed job's ``updated_at`` every ``reclaim_lease/4``
        until ``stop`` is set (dispatch finished). Fenced to the attempt we
        claimed at: a False return means the lease was lost anyway (reclaimed
        and re-claimed by a peer), so stop renewing a row we no longer own."""
        interval = max(self.reclaim_lease / 4.0, 0.05)
        while not stop.wait(interval):
            try:
                if not self.queue.heartbeat(job.id, expected_attempts=job.attempts):
                    return
            except Exception:  # transient DB contention must not kill the run
                log.exception("worker: lease heartbeat failed for job %d", job.id)

    def _reclaim_stale(self) -> None:
        """Requeue 'running' jobs orphaned by a crashed worker; log if any.

        CAVEAT -- at-least-once on the reclaim path: reclaim requeues a job whose
        lease expired so a peer can re-claim and re-run it. A worker that only
        *froze* longer than the lease (GC pause, host stall) rather than crashing
        can therefore have its job re-executed while its own side effects are
        still in flight -- the reclaim path is at-least-once for side effects, not
        exactly-once. Handlers must be idempotent (``start_goal`` reuses its
        goal_id across retries; ``complete``/``fail``/``heartbeat`` are
        attempt-fenced so the frozen worker's terminal writes no-op). The soak's
        ``exactly_once_under_contention`` metric proves ``claim()`` atomicity
        (DB-level exactly-once), NOT reclaim-path side-effect idempotency under
        such a freeze.
        """
        reclaimed = self.queue.reclaim_stale(
            self.reclaim_lease, max_attempts=self.max_attempts,
        )
        if reclaimed:
            log.info("worker: reclaimed %d stale job(s) from a prior crash",
                     reclaimed)

    def run_forever(self) -> None:
        """Loop until ``stop()`` is called or SIGTERM is received."""
        self._wire_signals()
        log.info("worker: started; polling %s every %.1fs",
                 self.queue.db_path, self.idle_sleep)
        # Recover jobs orphaned in 'running' by a previously-crashed worker
        # before draining the queue, so they aren't stuck forever.
        self._reclaim_stale()
        # ...then keep re-running it on an interval: claim() only ever picks
        # 'pending' rows, so a *peer* worker's hard crash (kill -9/OOM, which
        # skip run_once's except path) would otherwise leave its job stuck
        # 'running' until THIS daemon restarts -- which, for a long-lived
        # daemon in a multi-worker cluster, may be never. Re-reclaim every
        # reclaim_lease/2 so a still-running job is never stolen but a crashed
        # peer's orphan is recovered within ~one lease without a restart.
        reclaim_interval = max(self.reclaim_lease / 2.0, 1.0)
        last_reclaim = time.monotonic()
        from .runtime_configuration import start as start_runtime_receipt
        runtime_receipt = start_runtime_receipt("worker") if self._runtime_configuration_native else None
        idle_wait = self.idle_backoff_start
        try:
            while not self._stop.is_set():
                now = time.monotonic()
                if now - last_reclaim >= reclaim_interval:
                    try:
                        self._reclaim_stale()
                    except Exception:
                        log.exception("worker: periodic reclaim failed")
                    last_reclaim = now
                ran = False
                try:
                    ran = self.run_once()
                except Exception:
                    log.exception("worker: unexpected error in loop")
                if not ran:
                    # Idle: wait, but wake up cleanly on stop(); back off while
                    # the queue stays empty.
                    self._stop.wait(idle_wait)
                    idle_wait = min(idle_wait * 2.0, self.idle_sleep)
                else:
                    idle_wait = self.idle_backoff_start
        finally:
            if runtime_receipt is not None:
                runtime_receipt.close()
        log.info("worker: stopped")

    def drain(self) -> int:
        """Run every currently-ready job, then return; for cron/systemd timers.

        Reclaims stale jobs once (like ``run_forever``), snapshots the
        drain start time, then processes only jobs whose ``run_at`` was ready
        at that moment. Re-armed cron occurrences, retries, or other jobs
        that become due while a long-running handler is executing wait for
        the next ``--once`` invocation.
        """
        reclaimed = self.queue.reclaim_stale(
            self.reclaim_lease, max_attempts=self.max_attempts,
        )
        if reclaimed:
            log.info("worker: reclaimed %d stale job(s) from a prior crash",
                     reclaimed)
        ready_at = time.time()
        count = 0
        while self.run_once(ready_at=ready_at):
            count += 1
        return count

    def _wire_signals(self) -> None:
        # Only wire signals from the main thread (signal.signal is
        # main-thread-only). Background callers (tests) skip cleanly.
        if threading.current_thread() is not threading.main_thread():
            return

        def _handler(signum, _frame):
            log.info("worker: signal %d -> shutdown", signum)
            self.stop()

        try:
            signal.signal(signal.SIGINT, _handler)
            signal.signal(signal.SIGTERM, _handler)
        except (ValueError, OSError):
            # Some hosts disallow signal.signal (e.g. embedded).
            pass


__all__ = ["Worker", "UnknownJobKind", "GoalRunFailed", "RearmFailed"]
