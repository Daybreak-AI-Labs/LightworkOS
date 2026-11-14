"""JobQueue-backed automation for the dashboard.

Replaces the old bespoke asyncio scheduler with maverick-core's durable
:class:`~maverick.job_queue.JobQueue` + :class:`~maverick.worker.Worker`:

* **One recurring ``automation_tick`` cron job** drives polling. Each run reads
  the event-trigger store and polls only the triggers whose per-trigger interval
  is due, so every trigger has its own cadence (``interval_seconds``) without a
  cron job per trigger -- and create/delete need no queue bookkeeping, the next
  tick just sees the new store.
* **Fired goals are enqueued as durable ``run_goal`` jobs**, so a transient run
  failure is retried with backoff and a poison one lands in the ``failed``
  dead-letter state (``maverick queue failed``) -- instead of a bare daemon
  thread whose failure was lost. A small pool of worker threads drains them so a
  slow goal doesn't stall polling.
* **Dreaming is its own ``dream_cycle`` cron job**, re-armed by the worker.
* JobQueue's atomic ``claim`` hands each tick/dream *job* to one worker at a time
  (at-least-once across a lease reclaim); a blocking cross-process
  lock around the poll body serializes the *poll/cursor* critical section, so
  two overlapping ticks (N dashboard workers, a slow source) can't both advance
  the same cursor and double-create goals.

It runs INSIDE the dashboard process (the only one that can read the dashboard-
owned trigger store) on its OWN ``automation-jobs.db``, so its dashboard-specific
job kinds never reach -- and get dead-lettered by -- a core ``maverick worker``
draining the main queue. TestClient never starts it (the lifespan doesn't run in
tests); the handlers/arming are unit-tested directly.
"""
from __future__ import annotations

import contextlib
import hmac
import logging
import math
import os
import threading
import time

from maverick import config

log = logging.getLogger("maverick_dashboard.automation_queue")

TICK_KIND = "automation_tick"
DREAM_KIND = "dream_cycle"
FLYWHEEL_KIND = "flywheel_cycle"
FLOW_RUN_KIND = "flow_run"       # one-shot: run a flow to its next pause/finish
FLOW_RESUME_KIND = "flow_resume"  # one-shot: resume a paused flow run
FLOW_SWEEP_KIND = "flow_delay_sweep"  # recurring: re-arm flow runs whose delay elapsed
FLOW_EVOLVE_KIND = "flow_evolve"  # recurring: autonomously revert a regressed rewrite
FLOW_CRON_KIND = "flow_cron"     # recurring: fire a scheduled flow on its own cron cadence
ASSESS_SWEEP_KIND = "assessment_sweep"  # recurring: re-assess subjects + flag due reviews
_ASSESS_SWEEP_CRON = "0 3 * * *"  # re-check governance assessments daily at 03:00
_FLOW_SWEEP_CRON = "* * * * *"   # check for due delays every minute
_FLOW_EVOLVE_CRON = "*/30 * * * *"   # re-check applied rewrites every 30 min
_MIN_INTERVAL = 60               # floor for a per-trigger cadence (matches the UI/schema)
_DEFAULT_INTERVAL = 300          # per-trigger poll cadence when unset (5 min)
_TICK_CRON = "* * * * *"         # evaluate due triggers every minute
_DREAM_CRON_DEFAULT = "0 */6 * * *"  # consolidate every 6h
_FLYWHEEL_CRON_DEFAULT = "30 */6 * * *"  # turn the flywheel every 6h (offset from dream)
_DEFAULT_WORKERS = 3             # goal-runner threads (so a slow goal can't stall the tick)

_LOCK = threading.RLock()   # reentrant: start()/stop() call queue(), which also locks
_queue = None
_worker = None
_worker_threads: list = []
_worker_stopping = False


def _db_path():
    return config.dashboard_overrides_path().parent / "automation-jobs.db"


def queue():
    """The dashboard automation JobQueue (its own db). Singleton."""
    global _queue
    with _LOCK:
        if _queue is None:
            from maverick.job_queue import JobQueue
            _queue = JobQueue(db_path=_db_path())
        return _queue


def _cfg_int(section: str, key: str) -> int | None:
    try:
        v = (config.load_config().get(section) or {}).get(key)
        return int(v) if v is not None else None
    except Exception:  # pragma: no cover -- config never blocks the scheduler
        return None


# ---- per-trigger due tracking (a marker mtime, so an idle poll never rewrites
# the trigger store) --------------------------------------------------------

def _poll_marker(name: str):
    return config.dashboard_overrides_path().parent / "automation-poll" / name


def _trigger_poll_key(trigger: dict) -> str:
    """Namespace a cadence marker without placing a tenant id in its path."""
    import hashlib

    tenant = str(trigger.get("tenant") or "")
    if not tenant:
        return str(trigger["name"])
    digest = hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:32]
    return f"{trigger['name']}--{digest}"


def _default_interval() -> int:
    v = _cfg_int("automation", "default_interval_seconds")
    return max(_MIN_INTERVAL, v) if v else _DEFAULT_INTERVAL


def _interval(trig: dict) -> int:
    """Per-trigger cadence: a set value floored at 60s (matching the schema/UI),
    else the configurable default."""
    try:
        v = int(trig.get("interval_seconds") or 0)
    except (TypeError, ValueError):
        return _default_interval()
    return max(_MIN_INTERVAL, v) if v > 0 else _default_interval()


def _due(name: str, interval: int) -> bool:
    p = _poll_marker(name)
    try:
        return (time.time() - p.stat().st_mtime) >= interval
    except FileNotFoundError:
        return True
    except Exception:  # pragma: no cover -- a stat error shouldn't mute a trigger
        return True


def _mark_polled(name: str) -> None:
    p = _poll_marker(name)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch()   # sets mtime to now
    except Exception:  # pragma: no cover
        pass


@contextlib.contextmanager
def _poll_guard():
    """Portable cross-process lock around the poll/cursor transaction.

    A second worker may wait briefly, then re-check due markers under the lock;
    correctness is more important than the old POSIX-only non-blocking shortcut,
    which silently provided no serialization on Windows.
    """
    from maverick.file_lock import cross_process_lock
    p = config.dashboard_overrides_path().parent / "automation-poll.lock"
    with cross_process_lock(p):
        yield True


# ---- handlers ---------------------------------------------------------------

def _world():
    from maverick_dashboard.app import _world as _w
    return _w()


def _job_tenant_payload() -> dict:
    """The active tenant, captured for a queued job's payload -- so a worker
    (which has no request/trigger context of its own) can restore it before
    loading/executing the flow. Empty (omitted) for single-tenant deployments."""
    from maverick.paths import current_tenant_id
    tenant = current_tenant_id()
    return {"tenant": tenant} if tenant else {}


def _run_in_payload_tenant(payload: dict, fn) -> None:
    """Run ``fn`` inside the tenant captured on the job payload (if any), so a
    queued flow_run/flow_resume job loads/executes/persists under the SAME
    tenant namespace its creating trigger ran in -- not whatever tenant the
    worker thread happens to be scoped to."""
    tenant = payload.get("tenant")
    if not tenant:
        fn()
        return
    from maverick.tenant.registry import assert_tenant_active
    assert_tenant_active(str(tenant))
    from maverick.paths import reset_tenant, set_tenant
    token = set_tenant(str(tenant))
    try:
        fn()
    finally:
        reset_tenant(token)


def _configured_tenant_floor() -> str:
    """The deployment's explicit tenant floor, ignoring ambient ContextVars.

    Recurring workers must not inherit whichever request/job tenant happened to
    invoke them.  A deployment-wide ``MAVERICK_TENANT`` or client binding is a
    real namespace floor, however, and remains the base namespace instead of an
    unreachable shared root.
    """
    import os

    tenant = os.environ.get("MAVERICK_TENANT", "").strip()
    if tenant:
        return tenant
    try:
        from maverick.client import client_id

        return str(client_id() or "").strip()
    except Exception:  # pragma: no cover -- a client lookup never blocks maintenance
        return ""


def _run_for_active_tenants(operation: str, fn) -> bool:
    """Run tenant-scoped maintenance in the base + every active namespace.

    The automation queue is process-global while learning/flow stores live under
    :func:`maverick.paths.data_dir`.  One unscoped cron therefore cannot rely on
    a worker thread's ambient ContextVar.  Each namespace is pinned explicitly,
    restored in ``finally``, and isolated so one tenant's failure cannot starve
    the remaining tenants until the next cron.
    """
    from maverick.paths import reset_tenant, set_tenant

    base_tenant = _configured_tenant_floor()

    def _run_one(tenant: str, *, require_active: bool) -> bool:
        token = None
        try:
            if require_active:
                from maverick.tenant.registry import assert_tenant_active

                assert_tenant_active(tenant)
            token = set_tenant(tenant or None)
            fn()
            return True
        except Exception:
            log.exception("%s failed for tenant %s", operation, tenant or "<shared>")
            return False
        finally:
            if token is not None:
                reset_tenant(token)

    try:
        from maverick.tenant.registry import list_tenants

        tenants = list(list_tenants())
    except Exception:
        log.exception("%s could not enumerate active tenants", operation)
        return False
    registered = {
        str(getattr(rec, "id", "") or "").strip(): rec for rec in tenants
    }
    # Explicitly pin even the shared/client-floor pass. This clears a stale
    # request/job ContextVar instead of accidentally learning in that namespace.
    # Provisioned floors must pass the same suspension check as every other
    # tenant; only an unregistered legacy single-tenant floor bypasses it.
    complete = _run_one(base_tenant, require_active=base_tenant in registered)

    seen = {base_tenant} if base_tenant else set()
    for rec in tenants:
        tenant = str(getattr(rec, "id", "") or "").strip()
        if not tenant or not getattr(rec, "active", False) or tenant in seen:
            continue
        seen.add(tenant)
        complete = _run_one(tenant, require_active=True) and complete
    return complete


_SUITES_UNSET = object()


def _initial_flow_identity(
    owner: str,
    *,
    channel: str | None = None,
    user_id: str | None = None,
    allowed_suites=_SUITES_UNSET,
) -> tuple[str, str, list[str] | None]:
    """Capture the authenticated execution identity in the durable run row."""
    uid = str(user_id or _user_id_from_owner(owner) or "").strip()
    run_channel = str(channel or ("api" if uid else "")).strip()
    suites = allowed_suites
    if suites is _SUITES_UNSET:
        suites = None
        if uid and owner.startswith("user:"):
            from maverick.suite_grants import granted_suites

            suites = granted_suites(owner)
    normalized = None if suites is None else sorted({str(s) for s in suites if str(s)})
    return run_channel, uid, normalized


def enqueue_flow_run_once(
    flow_id: str,
    data: dict,
    owner: str = "",
    idem_key: str = "",
    origin: str = "manual",
    *,
    dry_run: bool = False,
    channel: str | None = None,
    user_id: str | None = None,
    allowed_suites=_SUITES_UNSET,
    definition_digest: str = "",
    release_digest: str = "",
    release_id: str = "",
    definition_version: int = 0,
    definition_revision: str = "",
    subflow_digests: dict[str, str | None] | None = None,
    repair_existing: bool = True,
) -> tuple[str, bool]:
    """Start a durable flow run (a pre-assigned, pollable run id + a flow_run job).
    Shared by the background tick and the on-demand poll so a flow-target trigger
    fires the same way on both paths. ``idem_key`` (flow_id + a stable event id)
    deduplicates: a re-delivered event returns the existing run instead of firing
    a second one. ``origin`` records what fired the run (cron/event/form/manual)
    for attribution + trigger-outcome learning. The original inputs are kept so
    the run can be retried."""
    from maverick.flow import store as flow_store

    # Resolve/verify the immutable plan before taking its exact-release claim
    # lock. This lock ordering is deliberate: published live paths hold the
    # definitions lock and then acquire the idempotency lock, so no generic
    # enqueue may acquire them in the opposite order.
    if definition_digest:
        pinned_digest = str(definition_digest)
        pinned_version = int(definition_version or 0)
        pinned_subflows = dict(subflow_digests or {})
        snapshotted_flow = flow_store.load_flow_snapshot(pinned_digest)
        if snapshotted_flow.id != str(flow_id):
            raise flow_store.FlowSnapshotError(
                "flow snapshot identity does not match the requested flow"
            )
        if pinned_version and int(snapshotted_flow.version) != pinned_version:
            raise flow_store.FlowSnapshotError(
                "flow snapshot version does not match the release"
            )
        if (
            definition_revision
            and str(snapshotted_flow.revision or "") != str(definition_revision)
        ):
            raise flow_store.FlowSnapshotError(
                "flow snapshot generation does not match the release"
            )
        flow_store.validate_snapshot_bundle_owners(
            snapshotted_flow, pinned_subflows
        )
    else:
        pinned_digest, pinned_version, pinned_subflows = (
            flow_store.snapshot_current_flow_bundle(flow_id)
        )
        snapshotted_flow = flow_store.load_flow_snapshot(pinned_digest)
    pinned_release_digest = flow_store.release_digest_for(
        pinned_digest, pinned_subflows,
    )
    if release_digest and str(release_digest) != pinned_release_digest:
        raise flow_store.FlowSnapshotError(
            "flow release content does not match its immutable execution plan"
        )
    pinned_release_id = str(release_id or "")
    if not pinned_release_id:
        # Dry/unpublished compatibility paths use a synthetic content-scoped
        # identity. A live producer adopts authority only from the exact active
        # pointer; final dispatch will reject the synthetic id otherwise.
        if not dry_run:
            published = flow_store.load_published_bundle(flow_id)
            if published is not None:
                _active_flow, active_release = published
                if str(active_release.get("release_digest") or "") == pinned_release_digest:
                    pinned_release_id = str(active_release["release_id"])
        pinned_release_id = pinned_release_id or pinned_release_digest

    # The owner + exact-release claim lock spans lookup, run reservation, claim
    # publication, and queue insert. Two users or two published revisions using
    # the same business key cannot observe or suppress one another's run.
    lock = (
        flow_store.idempotency_lock(
            flow_id, idem_key, owner=owner, release_id=pinned_release_id,
        )
        if idem_key else contextlib.nullcontext()
    )
    with lock:
        existing = (
            flow_store.find_run_by_idem(
                flow_id,
                idem_key,
                revision=snapshotted_flow.revision,
                definition_digest=pinned_digest,
                release_id=pinned_release_id,
                owner=owner,
            )
            if idem_key else None
        )
        if existing is not None:
            if repair_existing and existing.status == "queued":
                _ensure_queued_flow_job(existing, tenant=str(
                    _job_tenant_payload().get("tenant") or ""))
            return existing.run_id, True
        run_id = flow_store.new_run_id()
        run_channel, run_user_id, run_suites = _initial_flow_identity(
            owner,
            channel=channel,
            user_id=user_id,
            allowed_suites=allowed_suites,
        )
        flow_store.save_run(flow_store.FlowRun(
            run_id=run_id, flow_id=flow_id, status="queued", owner=owner,
            data=dict(data), input_data=dict(data), idem_key=idem_key, origin=origin,
            dry_run=bool(dry_run),
            definition_digest=pinned_digest,
            release_digest=pinned_release_digest,
            release_id=pinned_release_id,
            definition_version=pinned_version,
            definition_revision=snapshotted_flow.revision,
            subflow_digests=pinned_subflows,
            execution_channel=run_channel,
            execution_user_id=run_user_id,
            allowed_suites=run_suites))
        # Publish the durable first-writer claim before crossing into the SQLite
        # outbox.  A crash after this point deduplicates back to the queued JSON
        # reservation, whose missing job is repaired below/on startup.  A stale
        # claim left by an ordinary enqueue exception is harmless because lookup
        # verifies the referenced run before accepting it.
        if idem_key:
            flow_store.save_idempotency_claim(
                flow_id,
                idem_key,
                run_id,
                definition_digest=pinned_digest,
                release_id=pinned_release_id,
                owner=owner,
            )
        payload = {"flow_id": flow_id, "run_id": run_id, "data": data, "owner": owner,
                   "origin": origin, "dry_run": bool(dry_run)}
        payload.update(_job_tenant_payload())
        try:
            queue().enqueue(FLOW_RUN_KIND, payload)
        except Exception:
            # The exception boundary is ambiguous: SQLite may have committed
            # before a wrapper/driver raised. Keep the JSON outbox reservation
            # and idempotency claim. A caller retry or startup reconciliation
            # detects an existing job or publishes the missing one, but never
            # creates a second run against a possibly committed delivery.
            raise
        return run_id, False


def enqueue_flow_run(
    flow_id: str,
    data: dict,
    owner: str = "",
    idem_key: str = "",
    origin: str = "manual",
    *,
    dry_run: bool = False,
    channel: str | None = None,
    user_id: str | None = None,
    allowed_suites=_SUITES_UNSET,
    definition_digest: str = "",
    release_digest: str = "",
    release_id: str = "",
    definition_version: int = 0,
    definition_revision: str = "",
    subflow_digests: dict[str, str | None] | None = None,
) -> str:
    return enqueue_flow_run_once(
        flow_id,
        data,
        owner,
        idem_key,
        origin,
        dry_run=dry_run,
        channel=channel,
        user_id=user_id,
        allowed_suites=allowed_suites,
        definition_digest=definition_digest,
        release_digest=release_digest,
        release_id=release_id,
        definition_version=definition_version,
        definition_revision=definition_revision,
        subflow_digests=subflow_digests,
    )[0]


def enqueue_published_flow_run_once(
    flow_id: str,
    data: dict,
    owner: str = "",
    idem_key: str = "",
    origin: str = "manual",
    *,
    channel: str | None = None,
    user_id: str | None = None,
    allowed_suites=_SUITES_UNSET,
    expected_revision: str = "",
    legacy_event: dict | None = None,
) -> tuple[str, bool]:
    """Queue the exact active release and report idempotent deduplication.

    Loading and digest-checking publication here keeps every live producer
    (manual, webhook, event, and cron) on one fail-closed reservation boundary.
    Workers still reauthorize the exact release immediately before execution.
    """
    from maverick.flow import store

    published = store.load_published_bundle(flow_id)
    if published is None:
        raise store.FlowSnapshotError(f"flow {flow_id!r} is not published")
    _flow, release = published
    if (
        expected_revision
        and str(release["release_id"]) != str(expected_revision)
    ):
        raise store.FlowSnapshotError(
            f"published flow {flow_id!r} no longer matches the bound revision"
        )
    candidate_release_id = str(release["release_id"])
    # Re-read under the publication lock and keep it through durable run/claim
    # reservation. An unpublish or replacement that wins after the optimistic
    # read is therefore observed. If reservation wins, the queued worker still
    # performs a separate final activation check before building executors.
    with store.published_flow_guard(
        flow_id, expected_release_id=candidate_release_id,
    ) as (_locked_flow, locked_release):
        # A pre-envelope event cursor can have an already committed run under
        # the old display-field key. Read it under the same publication/claim
        # locks as writers, and only adopt an identity proved by retained data.
        legacy_key = str((legacy_event or {}).get("key") or "")
        legacy_lock = (store.idempotency_lock(flow_id, legacy_key, owner=owner,
                                              release_id=str(locked_release["release_id"]))
                       if legacy_key else contextlib.nullcontext())
        with legacy_lock:
            existing = (store.find_run_by_idem(
                flow_id, legacy_key, revision=_locked_flow.revision,
                definition_digest=str(locked_release["definition_digest"]),
                release_id=str(locked_release["release_id"]), owner=owner)
                if legacy_key else None)
            if existing is not None:
                identity = (legacy_event or {}).get("identity")
                original = existing.input_data
                if (not isinstance(identity, dict) or not identity
                        or any(k not in original or len(str(original[k])) >= 2000 for k in identity)):
                    raise store.FlowSnapshotError("Legacy event identity is ambiguous; reconcile the existing run before retrying")
                if all(str(original[k]) == str(v) for k, v in identity.items()):
                    idem_key = legacy_key
        result = enqueue_flow_run_once(
            flow_id,
            data,
            owner,
            idem_key,
            origin,
            channel=channel,
            user_id=user_id,
            allowed_suites=allowed_suites,
            definition_digest=str(locked_release["definition_digest"]),
            release_digest=str(locked_release["release_digest"]),
            release_id=str(locked_release["release_id"]),
            definition_version=int(locked_release["definition_version"]),
            definition_revision=str(locked_release["definition_revision"]),
            subflow_digests=dict(locked_release.get("subflow_digests") or {}),
            repair_existing=False,
        )
    if result[1]:
        # Do not wait for an executing run while holding its definition fence:
        # execution needs that fence to finish its immutable schema checkpoint.
        with store.run_lock(result[0]):
            existing = store.load_run(result[0], owner=owner, flow_id=flow_id)
            if (existing is None
                    or existing.release_id != str(locked_release["release_id"])
                    or existing.definition_digest != str(locked_release["definition_digest"])):
                raise store.FlowSnapshotError("The original queued workflow changed before recovery.")
            if existing.status == "queued":
                _ensure_queued_flow_job(existing, tenant=str(
                    _job_tenant_payload().get("tenant") or ""))
    return result


def enqueue_published_flow_run(
    flow_id: str,
    data: dict,
    owner: str = "",
    idem_key: str = "",
    origin: str = "manual",
    *,
    channel: str | None = None,
    user_id: str | None = None,
    allowed_suites=_SUITES_UNSET,
    expected_revision: str = "",
    legacy_event: dict | None = None,
) -> str:
    return enqueue_published_flow_run_once(
        flow_id,
        data,
        owner,
        idem_key,
        origin,
        channel=channel,
        user_id=user_id,
        allowed_suites=allowed_suites,
        expected_revision=expected_revision,
        legacy_event=legacy_event,
    )[0]


def _flow_job_for_run(run_id: str):
    """Find any durable queue row for ``run_id`` (pending through terminal)."""
    from maverick.paths import current_tenant_id

    return queue().find_for_run(FLOW_RUN_KIND, run_id, current_tenant_id() or "")


def _ensure_queued_flow_job(run, *, tenant: str = "") -> None:
    """Repair the JSON-reservation -> SQLite-job crash gap without replaying.

    The run row is the durable outbox record. If a process died after reserving
    it but before inserting the queue job, startup or an idempotent retry safely
    publishes the missing job. A terminal job is never re-published.
    """
    from maverick.flow import store

    with store.run_lock(run.run_id):
        current = store.load_run(run.run_id)
        if current is None or current.status != "queued":
            return
        if not current.definition_digest:
            current.status = "failed"
            current.error = (
                "immutable execution plan was not captured; create a replacement run"
            )
            store.save_run(current)
            return
        job = _flow_job_for_run(current.run_id)
        if job is not None:
            if job.status in {"done", "failed"}:
                current.status = "failed"
                current.error = "queue delivery ended before execution began"
                store.save_run(current)
            return
        payload = {
            "flow_id": current.flow_id,
            "run_id": current.run_id,
            "data": dict(current.input_data or current.data or {}),
            "owner": current.owner,
            "origin": current.origin,
            "dry_run": bool(current.dry_run),
        }
        if tenant:
            payload["tenant"] = tenant
        queue().enqueue(FLOW_RUN_KIND, payload)


def _repair_queued_flow_outbox() -> None:
    """Recover missing flow jobs across shared and active tenant namespaces."""
    from maverick.flow import store
    from maverick.paths import current_tenant_id

    def _repair() -> None:
        from maverick.flow.payloads import FlowPayloadError

        tenant = current_tenant_id() or ""
        store.rebuild_run_index()  # legacy import / offline restore reconciliation
        # One bounded startup pass indexes pre-claim legacy runs. Afterwards a
        # random idempotency key never forces an attacker-amplifiable full scan.
        for run in store.iter_run_metadata():
            if run.idem_key:
                with store.idempotency_lock(
                    run.flow_id,
                    run.idem_key,
                    owner=run.owner,
                    release_id=run.release_id,
                ):
                    store.save_idempotency_claim(
                        run.flow_id,
                        run.idem_key,
                        run.run_id,
                        definition_digest=run.definition_digest,
                        release_id=run.release_id,
                        owner=run.owner,
                        overwrite=False,
                    )
            if run.status == "queued":
                try:
                    _ensure_queued_flow_job(run, tenant=tenant)
                except FlowPayloadError:
                    # Preserve the affected reservation for explicit recovery;
                    # it must not prevent unrelated complete runs from arming.
                    log.warning("queued flow checkpoint requires recovery: %s", run.run_id)

    # A reconcile invoked inside a tenant-pinned request must not republish that
    # reservation as a tenantless job before the global sweep clears ambient
    # request state. Visit it explicitly, then sweep the configured/active set.
    ambient = current_tenant_id() or ""
    if ambient:
        try:
            _run_in_payload_tenant({"tenant": ambient}, _repair)
        except Exception:
            log.exception("could not repair ambient tenant flow-run outbox")
    _run_for_active_tenants("queued flow-run outbox repair", _repair)


def _user_id_from_owner(owner: str) -> str:
    """Derive a runner ``user_id`` from a trigger owner principal (``user:<id>``),
    mirroring ``execution_user_id_from_request`` for the request path. Empty for
    unowned triggers or non-``user:`` owners (e.g. a future ``tenant:`` scope)."""
    if owner.startswith("user:") and len(owner) > len("user:"):
        return owner[len("user:"):]
    return ""


def enqueue_event_goal(goal_id: int) -> int:
    """Publish an admitted template event to one permanent queue receipt."""
    from maverick_dashboard.auth import stored_automation_identity

    goal = _world().get_goal(goal_id)
    if goal is None:
        raise RuntimeError("event-created goal is unavailable")
    owner, user_id, suites = stored_automation_identity(goal.owner)
    payload: dict = {"goal_id": int(goal_id), **_job_tenant_payload()}
    if user_id:
        payload.update(user_id=user_id, channel="api")
    if owner:
        payload["concurrency_principal"] = owner
    if suites is not None:
        payload["allowed_suites"] = sorted(suites)
    import hashlib
    import json
    identity = json.dumps([payload.get("tenant", ""), int(goal_id)], separators=(",", ":"))
    key = "event-goal:" + hashlib.sha256(identity.encode()).hexdigest()
    return queue().enqueue_once("run_goal", payload, idempotency_key=key)


def _poll_due_triggers() -> None:
    from maverick_dashboard import event_poll, event_triggers_store
    due = [
        t
        for t in event_triggers_store.list_triggers()
        if _due(_trigger_poll_key(t), _interval(t))
    ]
    if not due:
        return

    # Group by owner and poll each group separately so the durable run_goal job
    # carries the trigger owner's execution identity -- otherwise every fired
    # goal runs under the fallback `user:local` principal, bypassing per-user
    # concurrency/quota attribution. Unowned triggers (owner == "") keep the
    # legacy behavior: no user_id, principal="".
    groups: dict[str, list[dict]] = {}
    for t in due:
        groups.setdefault(t.get("owner") or "", []).append(t)

    errored: set[str] = set()
    for owner, triggers in groups.items():
        group_results = event_poll.poll_and_fire(
            _world,
            triggers,
            principal=owner,
            fire=enqueue_event_goal,
            fire_is_durable=True,
            fire_flow=enqueue_published_flow_run,
        )
        for trigger, result in zip(triggers, group_results, strict=True):
            if result.get("poll_error"):
                errored.add(_trigger_poll_key(trigger))

    # Advance the due-marker only for triggers that actually polled; a trigger
    # whose source errored is left un-marked so it retries on the next tick
    # rather than going dark for a full interval.
    for t in due:
        key = _trigger_poll_key(t)
        if key not in errored:
            _mark_polled(key)


def _handle_tick(_job=None) -> None:
    """Poll every DUE event trigger and fire its goals as durable run_goal jobs.
    Fail-open: a raise here must NOT fail the job (which would retry-storm every
    60s); the next cron tick re-runs. Polls are serialized across workers by
    the cross-process poll lock (a second worker waits, then re-checks)."""
    from maverick import automation_events
    if not automation_events.enabled():
        return
    try:
        with _poll_guard() as acquired:
            if acquired:
                _poll_due_triggers()
    except Exception:  # pragma: no cover -- fail-open, never retry-storm
        log.exception("automation tick failed")


def _handle_dream(_job=None) -> None:
    """Fail-open: swallow errors so a partial dream isn't re-applied by the
    worker's retry (dream_cycle is not transactional); the next cron runs it.
    Learning stores are tenant-scoped, so the one process-global cron explicitly
    visits the shared/client floor and every active tenant."""
    from maverick import dreaming
    from maverick.self_improvement_runner import (
        nightly_self_harness_enabled,
        run_nightly_self_harness,
    )

    def _cycle() -> None:
        # Enablement can be overridden per tenant; check it inside the pin.
        if dreaming.enabled() or nightly_self_harness_enabled():
            from maverick.learning_guard import check_learning_halt

            check_learning_halt("dreaming", "scheduled")
            # One required safety copy covers the complete combined cycle.
            # The copy is durable before either learning family may change.
            world = _world()
            with dreaming.learning_mutation_scope():
                try:
                    if dreaming.enabled():
                        dreaming.dream_cycle(world)
                finally:
                    run_nightly_self_harness(world)

    _run_for_active_tenants("scheduled dream cycle", _cycle)


def _handle_assess_sweep(_job=None) -> None:
    """Re-assess every governance subject on a cadence, so drift flips accepted
    reviews back to needs-review and overdue re-reviews surface without a human
    remembering to click. Assessment registers are tenant-scoped, so the global
    cron visits each active namespace explicitly and fails open per tenant."""
    from maverick import assessments

    _run_for_active_tenants("scheduled assessment sweep", assessments.sweep_due)


def _handle_flywheel(_job=None) -> None:
    """Turn the Cognitive Data Engine flywheel over the accumulated Operating
    Record + grounded outcomes. This is the missing scheduled driver: outcomes
    (failures, sign-offs, feedback, real system-of-record results) land
    continuously, but nothing consolidated them into guardrails/habits without a
    manual `maverick flywheel`. Gated (`maybe_run` is a no-op unless
    ``[data_engine]`` is on), tenant-explicit, and fail-open like the dream
    cycle."""
    from maverick import flywheel

    _run_for_active_tenants("scheduled flywheel cycle", flywheel.maybe_run)


def _flow_execution_identity(run) -> tuple[str | None, str | None, frozenset[str] | None]:
    """Resolve a run's identity and apply the current suite grant as a floor.

    A queued grant may narrow but never widen while waiting: if either the
    enqueue-time or current grant is restricted, dispatch uses their
    intersection.  This preserves revocations and prevents deleting a grant
    from silently broadening an already-authorized queued run.
    """
    user_id = str(run.execution_user_id or _user_id_from_owner(run.owner) or "").strip()
    if not user_id:
        return None, None, None
    channel = str(run.execution_channel or "api").strip() or "api"
    initial = (
        None if run.allowed_suites is None else frozenset(str(s) for s in run.allowed_suites)
    )
    from maverick.suite_grants import granted_suites

    current = granted_suites(run.owner) if run.owner.startswith("user:") else None
    if initial is None:
        allowed = current
    elif current is None:
        allowed = initial
    else:
        allowed = initial & current
    return channel, user_id, allowed


def _flow_execution_authorized(run) -> bool:
    """Apply current lifecycle + RBAC policy as a dispatch-time floor."""
    try:
        from maverick_dashboard.auth import stored_automation_identity

        stored_automation_identity(str(run.owner or ""))
        return True
    except Exception:
        # Lifecycle/RBAC policy is a security boundary. An unreadable policy
        # store is not a reason to run an already-queued external side effect.
        return False


def _flow_approval_authority(run) -> dict:
    """Current role, workspace, credential and budget authority for a pause."""
    from maverick.approval_cards import digest
    from maverick.flow import store
    from maverick.paths import current_tenant_id_strict
    from maverick.tenant.registry import assert_tenant_active

    from maverick_dashboard.auth import role_for_principal, stored_automation_identity
    from maverick_dashboard.rbac import permissions_for

    tenant = current_tenant_id_strict() or ""
    try:
        if tenant:
            assert_tenant_active(tenant)
        owner, user_id, suites = stored_automation_identity(str(run.owner or ""))
    except Exception as exc:
        raise store.FlowSnapshotError(
            "flow approval identity authority is unavailable"
        ) from exc
    role = role_for_principal(owner or None)
    if owner and not role:
        raise store.FlowSnapshotError("flow approval role authority is unavailable")
    permissions = sorted(permissions_for(role)) if role else ["local_operator"]
    try:
        from maverick.connections import list_connections

        connections = sorted([
            {
                "name": row.get("name"),
                "connector": row.get("connector"),
                "revision": row.get("revision"),
                "owner": row.get("owner"),
                "access": row.get("access"),
            }
            for row in list_connections()
            if not row.get("owner") or row.get("owner") == owner
        ], key=lambda row: (str(row["name"]), str(row["revision"])))
        environment_credentials = [
            {
                "name_sha256": digest(name),
                "value_sha256": digest(value),
            }
            for name, value in sorted(os.environ.items())
            if value and any(
                marker in name.upper()
                for marker in ("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")
            )
        ]
    except Exception as exc:
        raise store.FlowSnapshotError(
            "flow credential authority is unavailable"
        ) from exc
    budget_material = {
        "configured": config.get_budget_overrides(),
        "environment_dollar_cap": os.environ.get("MAVERICK_BUDGET_DOLLARS"),
    }
    try:
        from maverick.runtime_overrides import budget_override

        budget_material["dashboard_dollar_cap"] = budget_override()
    except Exception as exc:
        raise store.FlowSnapshotError("flow budget authority is unavailable") from exc
    workspace_generation = None
    if owner:
        try:
            from maverick_dashboard.workspace_tenants import get_selection_binding

            workspace_generation = get_selection_binding(owner)
            selected_tenant = workspace_generation[0]
            if selected_tenant is not None and selected_tenant != tenant:
                raise store.FlowSnapshotError(
                    "flow workspace no longer matches the approval tenant"
                )
        except Exception as exc:
            if isinstance(exc, store.FlowSnapshotError):
                raise
            raise store.FlowSnapshotError(
                "flow workspace authority is unavailable"
            ) from exc
    return {
        "schema": "lightwork.flow-approval-authority.v1",
        "tenant": tenant,
        "owner": owner,
        "user_id": user_id or "",
        "role": role or "local_operator",
        "role_permissions_sha256": digest(permissions),
        "suite_grant_sha256": digest(None if suites is None else sorted(suites)),
        "workspace_selection_sha256": digest(workspace_generation),
        "credential_inventory_sha256": digest({
            "named_connections": connections,
            "environment_credentials": environment_credentials,
        }),
        "budget_authority_sha256": digest(budget_material),
    }


def flow_approval_binding(run, *, inputs: dict | None = None) -> str:
    """Bind an approval verdict to the exact pause and current authority."""
    from maverick.flow.approvals import paused_operation_binding

    return paused_operation_binding(
        run, inputs=inputs, authority=_flow_approval_authority(run),
    )


def current_flow_approval_card(run, *, allow_expired: bool = False) -> dict:
    """Validate that the displayed card still describes the durable pause."""
    from maverick.approval_cards import (
        ApprovalCardError,
        digest,
        require_current_approval_card,
        validate_approval_card,
    )
    from maverick.flow import store
    from maverick.flow.payloads import approval_data

    try:
        raw_card = (run.human or {}).get("approval_card")
        card = (
            validate_approval_card(raw_card)
            if allow_expired
            else require_current_approval_card(raw_card)
        )
        flow = store.load_flow_snapshot(str(run.definition_digest or ""))
        paused = flow.node(run.cursor) if run.cursor else None
        if paused is None or paused.kind != "approval":
            raise ApprovalCardError("approval pause target is unavailable")
        next_node = flow.node(paused.next) if paused.next else None
        continuation = (
            next_node.to_dict()
            if next_node is not None
            else {"kind": "complete", "id": "end"}
        )
        persisted_data = approval_data(run.data or {}, card)
        expected_target = digest({
            "flow_id": flow.id,
            "pause_node": paused.id,
            "continuation": continuation,
        })
        expected_parameters = digest({
            "data": persisted_data,
            "continuation": continuation,
        })
        versions = card["authority"]["versions"]
        checks = (
            card["action"] == "flow.resume",
            hmac.compare_digest(card["target"]["sha256"], expected_target),
            hmac.compare_digest(
                card["parameters"]["sha256"], expected_parameters,
            ),
            card["inputs"].get("run_data_sha256") == digest(persisted_data),
            versions.get("definition_digest") == run.definition_digest,
            versions.get("release_digest") == run.release_digest,
            versions.get("release_id") == run.release_id,
            (run.budget_limit_dollars is None or
             card["budget"].get("run_limit_dollars") == run.budget_limit_dollars
            ),
            (
                run.resume_at is None
                or float(card["expires_at"]) == float(run.resume_at)
            ),
        )
        if not all(checks):
            raise ApprovalCardError(
                "approval card no longer describes the durable operation"
            )
        return card
    except (ApprovalCardError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise store.FlowSnapshotError(
            "flow approval card is stale or invalid"
        ) from exc


def _flow_runners(run):
    from maverick.flow import execution
    from maverick.sandbox import build_sandbox
    w = _world()
    sandbox = build_sandbox()
    channel, user_id, allowed_suites = _flow_execution_identity(run)
    return (
        execution.default_agent_runner(
            w,
            owner=run.owner,
            channel=channel,
            user_id=user_id,
            allowed_suites=allowed_suites,
            concurrency_principal=run.owner or user_id,
        ),
        execution.default_action_runner(
            w,
            sandbox=sandbox,
            channel=channel,
            user_id=user_id,
        ),
    )


def _public_base_url() -> str:
    """The externally-reachable dashboard base URL for approval links, from
    ``MAVERICK_PUBLIC_URL`` or ``[dashboard] public_url``. Empty when unset --
    then approval links are omitted and the human uses the dashboard."""
    import os
    url = os.environ.get("MAVERICK_PUBLIC_URL", "").strip()
    if not url:
        try:
            cfg = config.load_config()
            url = str((cfg.get("dashboard") or {}).get("public_url")
                      or (cfg.get("flows") or {}).get("public_url") or "").strip()
        except Exception:  # pragma: no cover
            url = ""
    return url


def enqueue_flow_resume(
    flow_id: str,
    run_id: str,
    decision: str = "",
    owner: str = "",
    *,
    decided_by: str = "",
    tenant: str = "",
    inputs: dict | None = None,
    expired: bool = False,
    from_failure: bool = False,
    budget_limit_dollars: float | None = None,
    run_at: float | None = None,
    approval_binding_sha256: str = "",
    decision_authority: object | None = None,
) -> None:
    """Reserve a resume only while its immutable live release remains active.

    Dry runs stay pinned to their immutable snapshot without publication. For
    real runs, unpublish or republish is a kill boundary: the exact run digest
    is re-verified under the publication lock through durable queue insertion.
    """
    from maverick.flow import store

    payload = {"flow_id": flow_id, "run_id": run_id, "owner": owner}
    if decision:
        payload["decision"] = decision
    if inputs:
        payload["inputs"] = dict(inputs)
    if expired:
        payload["expired"] = True
    if from_failure:
        payload["from_failure"] = True
    if budget_limit_dollars is not None:
        payload["budget_limit_dollars"] = budget_limit_dollars
    payload.update({"tenant": tenant} if tenant else _job_tenant_payload())

    def _reserve() -> None:
        run = store.load_run(run_id)
        if run is None or run.flow_id != str(flow_id):
            raise store.FlowSnapshotError("flow run is unavailable")
        if owner and run.owner != owner:
            raise store.FlowSnapshotError("flow run owner does not match")
        if run.status == "paused_approval" and not expired:
            _validate_approval_actor(run, decision=decision, decided_by=decided_by)
            try:
                card = current_flow_approval_card(run)
            except store.FlowSnapshotError as exc:
                raise store.FlowSnapshotError(
                    "flow approval expired; request a fresh review"
                ) from exc
            reviewed_binding = flow_approval_binding(
                run, inputs=dict(inputs or {}),
            )
            if not approval_binding_sha256 or not hmac.compare_digest(
                reviewed_binding, str(approval_binding_sha256)
            ):
                raise store.FlowSnapshotError(
                    "flow approval changed; review the current operation"
                )
            current_binding = reviewed_binding
            payload["decision"] = str(decision)
            payload["decided_by"] = str(decided_by)
            payload["approval_binding_sha256"] = current_binding
            from maverick.flow.approvals import (
                flow_decision_attestation_material,
                paused_operation_binding,
            )

            from .approval_authority import issue_flow_decision_attestation

            core_binding = paused_operation_binding(
                run, inputs=dict(inputs or {}),
            )
            material = flow_decision_attestation_material(
                run,
                inputs=dict(inputs or {}),
                operation_binding_sha256=core_binding,
                authority_binding_sha256=current_binding,
                decision=str(decision),
                decided_by=str(decided_by),
            )
            payload["approval_decision_attestation"] = (
                issue_flow_decision_attestation(
                    decision_authority,
                    material=material,
                    expires_at=float(card["expires_at"]),
                )
            )
        elif run.status == "paused_approval" and expired:
            if run.resume_at is None or not math.isfinite(float(run.resume_at)):
                raise store.FlowSnapshotError(
                    "flow approval has no valid expiry reservation"
                )
            current_flow_approval_card(run, allow_expired=True)
            payload["approval_expiry_binding_sha256"] = flow_approval_binding(run)
        if not run.definition_digest:
            raise store.FlowSnapshotError(
                "flow run has no immutable definition to resume"
            )
        kwargs = {"run_at": run_at} if run_at is not None else {}
        if run.dry_run:
            queue().enqueue(FLOW_RESUME_KIND, payload, **kwargs)
            return
        with store.published_flow_guard(
            flow_id, expected_release_id=run.release_id,
        ):
            queue().enqueue(FLOW_RESUME_KIND, payload, **kwargs)

    if tenant:
        _run_in_payload_tenant(payload, _reserve)
    else:
        _reserve()


def _principal_aliases(principal: str) -> set[str]:
    value = str(principal or "").strip().casefold()
    if not value:
        return set()
    aliases = {value}
    if value.startswith("user:") and value[5:]:
        subject = value[5:]
        aliases.update({subject, f"@{subject}"})
    return aliases


def _validate_approval_actor(run, *, decision: str, decided_by: str) -> None:
    """Require an explicit verdict and an actor authorized for the pause."""
    from maverick.flow import store

    verdict = str(decision or "").strip()
    allowed = {"approved", "rejected"}
    allowed.update(str(v) for v in (run.human or {}).get("choices") or [])
    if not verdict or verdict not in allowed:
        raise store.FlowSnapshotError("an explicit valid approval decision is required")
    aliases = _principal_aliases(decided_by)
    if not aliases:
        raise store.FlowSnapshotError("an attributable approver identity is required")
    assignee = str((run.human or {}).get("assignee") or "").strip().casefold()
    if assignee and assignee not in aliases:
        raise store.FlowSnapshotError("the approver is not the declared assignee")


def _require_current_flow_approval(run, payload: dict) -> None:
    """Revalidate a queued verdict against this exact pause and authority."""
    from maverick.flow import store

    expected = str(payload.get("approval_binding_sha256") or "")
    current = flow_approval_binding(
        run, inputs=dict(payload.get("inputs") or {}),
    )
    if not expected or not hmac.compare_digest(expected, current):
        raise store.FlowSnapshotError(
            "approval operation or authority changed"
        )
    current_flow_approval_card(run)
    _validate_approval_actor(
        run,
        decision=str(payload.get("decision") or ""),
        decided_by=str(payload.get("decided_by") or ""),
    )


def _require_current_flow_expiry(run, payload: dict) -> None:
    """Accept only the bound scheduler reservation after the exact expiry time."""
    from maverick.flow import store

    try:
        due_at = float(run.resume_at)
    except (TypeError, ValueError) as exc:
        raise store.FlowSnapshotError("approval expiry is unavailable") from exc
    if not math.isfinite(due_at) or time.time() < due_at:
        raise store.FlowSnapshotError("approval expiry is not due")
    if payload.get("decision") or payload.get("decided_by") or payload.get("inputs"):
        raise store.FlowSnapshotError("approval expiry payload is invalid")
    expected = str(payload.get("approval_expiry_binding_sha256") or "")
    current = flow_approval_binding(run)
    if not expected or not hmac.compare_digest(expected, current):
        raise store.FlowSnapshotError("approval expiry reservation changed")
    current_flow_approval_card(run, allow_expired=True)


def _approval_body(name: str, run) -> str:
    """The approval notification text, with clickable approve/reject links when a
    public URL + webhook secret are configured (else just the prompt)."""
    ask = run.prompt or "review and resume"
    base = _public_base_url()
    if base:
        from maverick.flow.approvals import approval_links

        binding = flow_approval_binding(run)
        links = approval_links(
            base,
            run.run_id,
            cursor=run.cursor,
            prompt=run.prompt,
            updated=run.updated,
            assignee=str((run.human or {}).get("assignee") or ""),
            owner=run.owner,
            binding_sha256=binding,
        )
        if links:
            return (f"“{name}” needs your approval: {ask}\n"
                    f"✅ Approve: {links['approve']}\n"
                    f"🚫 Reject: {links['reject']}")
    return f"“{name}” needs your approval: {ask}"


def _notify_flow(flow, run) -> None:
    """Best-effort push when a notify-enabled flow needs a human (paused on an
    approval) or finishes (completed/failed). A no-op unless the flow opted in
    AND notifications are configured; never raises into the worker. An approval
    pause carries actionable approve/reject links when a public URL is set."""
    if flow is None or not getattr(flow, "notify", False):
        return
    from maverick.flow.runner import (
        STATUS_BUDGET_LIMITED,
        STATUS_COMPLETED,
        STATUS_FAILED,
        STATUS_INDETERMINATE,
        STATUS_PAUSED_APPROVAL,
    )
    choice = getattr(flow, "notify_on", "all")
    if not isinstance(choice, str) or choice not in {"all", "problems"}:
        return
    if choice == "problems" and run.status not in {
        STATUS_FAILED, STATUS_BUDGET_LIMITED, STATUS_INDETERMINATE,
    }:
        return
    name = flow.name or flow.id
    if run.status == STATUS_PAUSED_APPROVAL:
        body, prio = _approval_body(name, run), "high"
    elif run.status == STATUS_COMPLETED:
        body, prio = f"“{name}” finished.", "default"
    elif run.status == STATUS_FAILED:
        body, prio = f"“{name}” failed: {run.error or 'see the run'}", "high"
    elif run.status == STATUS_BUDGET_LIMITED:
        body, prio = f"“{name}” is saved and waiting for a larger spending allowance. Review the run to continue.", "high"
    elif run.status == STATUS_INDETERMINATE:
        body = (
            f"“{name}” stopped with an indeterminate external effect. "
            "Reconcile the target system before retrying."
        )
        prio = "high"
    else:
        return
    try:
        from maverick import notifications
        notifications.notify(body, title="Lightwork flow", priority=prio)
    except Exception:  # pragma: no cover -- notification is best-effort
        log.debug("flow notify failed", exc_info=True)


def _schedule_paused_resume(run, source_payload: dict) -> None:
    """Persist the tenant-aware delayed continuation when a run parks.

    This is the primary delay/approval-expiry driver.  The periodic sweep remains
    only as recovery for legacy runs; it cannot safely discover every tenant's
    private run directory from an unscoped worker.
    """
    if not run.resume_at:
        return
    from maverick.flow.runner import STATUS_PAUSED_APPROVAL, STATUS_PAUSED_DELAY
    if run.status not in {STATUS_PAUSED_APPROVAL, STATUS_PAUSED_DELAY}:
        return
    from maverick.flow import store
    tenant = str(source_payload.get("tenant") or "")
    try:
        enqueue_flow_resume(
            run.flow_id,
            run.run_id,
            owner=run.owner,
            tenant=tenant,
            expired=run.status == STATUS_PAUSED_APPROVAL,
            run_at=float(run.resume_at),
        )
    except store.FlowSnapshotError:
        # A concurrent unpublish/republish intentionally kills this pending
        # continuation. The paused run remains inspectable; no stale release is
        # silently re-armed.
        log.info(
            "flow release inactive; paused resume not scheduled: flow=%s run=%s",
            run.flow_id,
            run.run_id,
        )


_SINGLETON_DEFER_SECONDS = 30.0   # how long to wait before re-checking a busy singleton
_SINGLETON_MAX_DEFERS = 40        # ~20 min of deferral before giving up (avoid infinite requeue)


@contextlib.contextmanager
def _flow_slot_guard(flow_id: str):
    """Portable per-flow lock around the max_concurrent check + claim."""
    from maverick.file_lock import cross_process_lock
    from maverick.flow.store import _safe_id
    from maverick.paths import data_dir

    # Tenant-scoped placement prevents a tenant that reuses a flow id from
    # contending on another tenant's singleton lock.
    p = data_dir("flows", "slots", _safe_id(flow_id))
    with cross_process_lock(p):
        yield True


def _active_run_count(flow_id: str, exclude_run_id: str) -> int:
    """In-flight runs of a flow (running / paused), excluding this run. Queued runs
    don't count -- they're exactly what the slot guard gates -- else two queued
    events would each see the other and defer forever."""
    from maverick.flow import store
    from maverick.flow.runner import ACTIVE_STATUSES
    occupying = ACTIVE_STATUSES - {"queued"}
    return sum(1 for r in store.iter_run_metadata(flow_id=flow_id, statuses=occupying)
               if r.run_id != exclude_run_id)


def _defer_for_slot(payload: dict) -> bool:
    """Re-enqueue a flow_run job later because the flow is at its concurrency cap.
    Bounded so a permanently-stuck run (e.g. a run paused on approval forever)
    can't requeue endlessly -- past the cap the run is left queued and skipped.
    Returns True if it deferred, False if the defer budget is exhausted."""
    defers = int(payload.get("_slot_defers") or 0)
    if defers >= _SINGLETON_MAX_DEFERS:
        return False
    nxt = dict(payload)
    nxt["_slot_defers"] = defers + 1
    queue().enqueue(FLOW_RUN_KIND, nxt, run_at=time.time() + _SINGLETON_DEFER_SECONDS)
    return True


def _claim_run_slot(run_id: str) -> None:
    """Claim a queued concurrency slot without impersonating execution.

    ``running`` means an executor crossed the possible-effect boundary; a stale
    delivery that finds it must quarantine rather than replay. ``claimed`` is a
    distinct pre-execution state that the first delivery may safely consume.
    """
    from maverick.flow import store
    from maverick.flow.runner import STATUS_CLAIMED

    run = store.load_run(run_id)
    if run is not None and run.status == "queued":
        run.status = STATUS_CLAIMED
        store.save_run(run)


def _skip_run_at_cap(run_id: str) -> None:
    """Mark a run that never got a concurrency slot as skipped (not failed) -- it
    never executed, so it's not a failure to learn from, just a dropped attempt."""
    from maverick.flow import store
    run = store.load_run(run_id)
    if run is not None and run.status == "queued":
        run.status = "skipped_concurrency"
        store.save_run(run)


def _mark_flow_run_failed(run_id: str, message: str) -> None:
    """Publish a bounded, non-secret terminal failure for a known-safe preflight."""
    from maverick.flow import store

    run = store.load_run(run_id)
    if run is None:
        return
    run.status = "failed"
    run.error = str(message)[:500]
    store.save_run(run)


def _quarantine_interrupted_flow_run(run, message: str) -> None:
    """Preserve ambiguity once an earlier delivery crossed execution claim."""
    from maverick.flow import store
    from maverick.flow.runner import STATUS_INDETERMINATE

    run.status = STATUS_INDETERMINATE
    run.error = str(message)[:500]
    store.save_run(run)


def _initial_delivery_is_executable(run) -> bool:
    """Claim-state check for one at-least-once initial queue delivery."""
    from maverick.flow.runner import STATUS_CLAIMED, STATUS_RUNNING

    if run.status == STATUS_RUNNING:
        _quarantine_interrupted_flow_run(
            run,
            "fresh run delivery resumed after execution began; "
            "external effects may have committed",
        )
        return False
    # Pause/terminal redelivery is inert. Later republish must not rewrite a
    # completed run to failed merely because its old release is gone.
    return run.status in {"queued", STATUS_CLAIMED}


def _legacy_event_flow_compatible(run, current: dict, generation: str) -> bool:
    """Prove an old run was reserved by today's non-mail trigger generation."""
    import re

    from .event_poll import _event_key

    source = current.get("source")
    if (source not in {"http_json", "rss", "oauth_http_json", "github_issues", "file_dir", "form"}
            or current.get("owner") != run.owner
            or current.get("flow") != run.flow_id
            or current.get("flow_revision") != run.release_id
            or not isinstance(run.input_data, dict)):
        return False
    if source == "file_dir":
        # Current file events carry the content identity, not their old path
        # display ID. A legacy file cursor cannot reconstruct that identity.
        field = "id"
    elif source == "github_issues":
        field = "number"
    elif source == "form":
        field = "_seq"
    else:
        field = str((current.get("config") or {}).get("id_field") or "id")
    value = run.input_data.get(field)
    if (not isinstance(value, (str, int, float)) or isinstance(value, bool)
            or not 0 < len(str(value)) < 2000
            or value == "***redacted***"
            or (source == "file_dir" and not re.fullmatch(r"[a-f0-9]{64}", str(value)))):
        return False
    return run.idem_key == _event_key(generation, {}, str(value))


def _event_flow_start_problem(run) -> str:
    """Fail closed unless an event run still has source/binding proof."""
    import re

    origin = str(run.origin or "")
    if not origin.startswith("event:"):
        return ""
    from maverick.paths import current_tenant_id

    from . import event_triggers_store
    from .event_poll import _trigger_key

    if origin.startswith("event:") and not origin.startswith("event:v2:"):
        name = origin.removeprefix("event:")
        current = event_triggers_store.get_trigger(
            name, tenant=current_tenant_id() or "", strict=True,
        )
        if current is not None and _legacy_event_flow_compatible(
            run, current, _trigger_key(current),
        ):
            return ""
        return "This earlier automation run needs review before it can start"
    parts = origin.split(":", 4)
    if (len(parts) != 5 or parts[1] != "v2" or not parts[2]
            or not re.fullmatch(r"[a-f0-9]{64}", parts[3]) or not parts[4]):
        return "This earlier automation run needs review before it can start"
    source, generation, name = parts[2:]
    if source != "imap_email":
        return ""
    # The producer only writes v2 IMAP provenance after verifying the received
    # event. Flow input data is credential-redacted before storage, so it cannot
    # be used as an independent provenance receipt here.
    current = event_triggers_store.get_trigger(
        name, tenant=current_tenant_id() or "", strict=True,
    )
    if (current is None or current.get("source") != source
            or current.get("owner") != run.owner
            or current.get("flow") != run.flow_id
            or current.get("flow_revision") != run.release_id
            or _trigger_key(current) != generation):
        return "Email automation changed before this run started; review and create a new run"
    return ""


def _reserve_initial_flow_slot(flow, payload: dict, run_id: str, dry_run: bool) -> bool:
    """Claim a live concurrency slot, defer, or terminally skip this delivery."""
    if (
        not flow.max_concurrent
        or dry_run
        or not run_id
        or payload.get("_resume")
    ):
        return True
    with _flow_slot_guard(flow.id) as held:
        if not held:
            if _defer_for_slot(payload):
                return False
            _skip_run_at_cap(run_id)
            return False
        if _active_run_count(flow.id, run_id) < flow.max_concurrent:
            _claim_run_slot(run_id)
            return True
        if _defer_for_slot(payload):
            return False
        log.warning(
            "flow_run: %s at concurrency cap, defer budget spent"
            " -- skipping run %s", flow.id, run_id,
        )
        _skip_run_at_cap(run_id)
        return False


def _handle_flow_run(job=None) -> None:
    """Run a stored flow to its next pause/finish (durable one-shot job). An
    agent node becomes a real goal, an action node a tool call; the run state is
    persisted so a pause survives. A refused run is marked failed and returns;
    an unexpected error is logged and re-raised, so the queue's retry and
    dead-letter policy applies (this handler is not fail-open)."""
    payload = getattr(job, "payload", None) or {}
    flow_id = str(payload.get("flow_id") or "")
    if not flow_id:
        return
    try:
        def _run() -> None:
            from maverick.flow import execution, store
            run_id = str(payload.get("run_id") or "")
            placeholder = store.load_run(run_id) if run_id else None
            if placeholder is None:
                log.warning("flow_run: no durable reservation for %s", run_id)
                return
            if placeholder.flow_id != flow_id:
                _mark_flow_run_failed(run_id, "queue reservation does not match flow")
                return
            if not _initial_delivery_is_executable(placeholder):
                return
            event_problem = _event_flow_start_problem(placeholder)
            if event_problem:
                _mark_flow_run_failed(run_id, event_problem)
                return
            if not placeholder.definition_digest:
                _mark_flow_run_failed(
                    run_id,
                    "immutable execution plan was not captured; create a replacement run",
                )
                return
            try:
                flow = store.load_flow_snapshot(placeholder.definition_digest)
            except store.FlowSnapshotError:
                _mark_flow_run_failed(run_id, "immutable execution plan is unavailable")
                return
            if flow is None:
                log.warning("flow_run: no such flow %s", flow_id)
                _mark_flow_run_failed(run_id, "flow definition is unavailable")
                return
            if flow.id != placeholder.flow_id:
                _mark_flow_run_failed(run_id, "immutable execution plan identity mismatch")
                return
            try:
                store.validate_snapshot_bundle_owners(
                    flow, placeholder.subflow_digests)
            except store.FlowSnapshotError:
                _mark_flow_run_failed(run_id, "immutable execution plan is unavailable")
                return
            # The persisted reservation is authoritative. Queue rows are a
            # delivery mechanism and must not be able to upgrade a dry run,
            # swap its owner/inputs, or change learning attribution.
            owner = placeholder.owner
            dry_run = bool(placeholder.dry_run)
            try:
                if not dry_run and not _flow_execution_authorized(placeholder):
                    _mark_flow_run_failed(
                        run_id, "flow execution authorization was revoked",
                    )
                    return
                # Per-flow concurrency cap is decided before final dispatch.
                # A deferred delivery rechecks publication on its next attempt.
                if not _reserve_initial_flow_slot(flow, payload, run_id, dry_run):
                    return
                if not dry_run:
                    # This short per-flow critical section is the execution-start
                    # linearization point. Revocation that wins first refuses the
                    # queued run; one that begins later cannot interrupt work that
                    # has already dispatched. Never hold it across a long executor.
                    with store.active_release_guard(
                        flow_id, expected_release_id=placeholder.release_id,
                    ):
                        pass
                # A dry run exercises the graph with mock executors and records
                # no grounded outcome.
                agent_runner, action_runner = (
                    execution.sandbox_runners()
                    if dry_run else _flow_runners(placeholder)
                )
                run = execution.execute(
                    flow,
                    agent_runner=agent_runner,
                    action_runner=action_runner,
                    owner=owner,
                    data=dict(placeholder.input_data or placeholder.data or {}),
                    run_id=payload.get("run_id"),
                    record_outcomes=not dry_run,
                    origin=placeholder.origin,
                )
                if not dry_run:
                    _notify_flow(flow, run)
                # A continuation performs its own release reservation. A
                # concurrent replacement after dispatch can therefore let this
                # segment finish while still revoking every later segment.
                _schedule_paused_resume(run, payload)
            except store.FlowSnapshotError:
                _mark_flow_run_failed(
                    run_id, "published flow release was revoked before dispatch",
                )
                return
        _run_in_payload_tenant(payload, _run)
    except Exception:
        log.exception("flow run failed for %s", flow_id)
        raise


def _handle_flow_resume(job=None) -> None:  # noqa: C901
    """Resume a paused flow run with a human decision (durable one-shot). A stale
    resume (the run already advanced, e.g. a duplicate delay-sweep enqueue) is a
    clean no-op, not an error."""
    payload = getattr(job, "payload", None) or {}
    run_id = str(payload.get("run_id") or "")
    flow_id = str(payload.get("flow_id") or "")
    if not (run_id and flow_id):
        return
    from maverick.flow import execution
    try:
        def _resume() -> None:  # noqa: C901
            from maverick.flow import store
            prior = store.load_run(run_id)
            if prior is None:
                return
            if prior.flow_id != flow_id:
                _mark_flow_run_failed(run_id, "queue reservation does not match flow")
                return
            from maverick.flow.runner import (
                PAUSED_STATUSES,
                STATUS_BUDGET_LIMITED,
                STATUS_FAILED,
                STATUS_RESUMING,
            )
            if prior.status == STATUS_RESUMING:
                _quarantine_interrupted_flow_run(
                    prior,
                    "resume delivery repeated after execution began; "
                    "external effects may have committed",
                )
                return
            retryable_failure = (
                bool(payload.get("from_failure"))
                and prior.status in {STATUS_FAILED, STATUS_BUDGET_LIMITED}
                and bool(prior.cursor)
            )
            if prior.status not in PAUSED_STATUSES and not retryable_failure:
                return
            if prior.status == "paused_approval":
                try:
                    if payload.get("expired"):
                        _require_current_flow_expiry(prior, payload)
                    else:
                        _require_current_flow_approval(prior, payload)
                except store.FlowSnapshotError:
                    # An untrusted/corrupt queue delivery never consumes or
                    # destroys the legitimate paused approval.
                    log.warning("refused unattributable approval resume for %s", run_id)
                    prior.error = (
                        "Approval changed or expired before execution. "
                        "Review the current operation again."
                    )
                    store.save_run(prior)
                    return
            if not prior.definition_digest:
                _mark_flow_run_failed(
                    run_id,
                    "immutable execution plan was not captured; create a replacement run",
                )
                return
            try:
                flow = store.load_flow_snapshot(prior.definition_digest)
            except store.FlowSnapshotError:
                _mark_flow_run_failed(run_id, "immutable execution plan is unavailable")
                return
            if flow is None:
                _mark_flow_run_failed(run_id, "flow definition is unavailable")
                return
            if flow.id != prior.flow_id:
                _mark_flow_run_failed(run_id, "immutable execution plan identity mismatch")
                return
            try:
                store.validate_snapshot_bundle_owners(flow, prior.subflow_digests)
            except store.FlowSnapshotError:
                _mark_flow_run_failed(run_id, "immutable execution plan is unavailable")
                return
            if retryable_failure:
                from maverick.flow.resume_admission import retry_approval_refusal

                refusal = retry_approval_refusal(flow, prior)
                if refusal:
                    # The run stays failed; keep its failure and say why the
                    # retry was refused.
                    prior.error = (
                        f"{prior.error[:1500]} | {refusal}" if prior.error else refusal
                    )
                    store.save_run(prior)
                    return
            owner = prior.owner
            dry_run = bool(prior.dry_run)
            try:
                if not dry_run and not _flow_execution_authorized(prior):
                    _mark_flow_run_failed(
                        run_id, "flow execution authorization was revoked",
                    )
                    return
                if not dry_run:
                    with store.active_release_guard(
                        flow_id, expected_release_id=prior.release_id,
                    ):
                        pass
                agent_runner, action_runner = (
                    execution.sandbox_runners()
                    if dry_run else _flow_runners(prior)
                )
                # Building an executor does not dispatch it.  Re-read every
                # mutable authority source at the last local boundary before
                # execute can claim the pause and reach a provider or tool.
                if prior.status == "paused_approval":
                    try:
                        if payload.get("expired"):
                            _require_current_flow_expiry(prior, payload)
                        else:
                            _require_current_flow_approval(prior, payload)
                    except store.FlowSnapshotError:
                        prior.error = (
                            "Approval changed before execution. "
                            "Review the current operation again."
                        )
                        store.save_run(prior)
                        return
                from maverick.flow.approvals import paused_operation_binding

                core_approval_binding = ""
                core_expiry_binding = ""
                if prior.status == "paused_approval":
                    submitted_inputs = dict(payload.get("inputs") or {})
                    core_binding = paused_operation_binding(
                        prior,
                        inputs=submitted_inputs,
                    )
                    if payload.get("expired"):
                        core_expiry_binding = core_binding
                    else:
                        core_approval_binding = core_binding
                run = execution.execute(
                    flow,
                    agent_runner=agent_runner,
                    action_runner=action_runner,
                    owner=owner,
                    resume_run_id=run_id,
                    decision=str(payload.get("decision") or ""),
                    decided_by=str(payload.get("decided_by") or ""),
                    expired=bool(payload.get("expired")),
                    approval_binding_sha256=core_approval_binding,
                    approval_expiry_binding_sha256=core_expiry_binding,
                    approval_authority_binding_sha256=str(
                        payload.get("approval_binding_sha256") or ""
                    ),
                    approval_decision_attestation=payload.get(
                        "approval_decision_attestation"
                    ),
                    from_failure=bool(payload.get("from_failure")),
                    budget_limit_dollars=payload.get("budget_limit_dollars"),
                    inputs=dict(payload.get("inputs") or {}),
                    record_outcomes=not dry_run,
                )
                if not dry_run:
                    _notify_flow(flow, run)
                _schedule_paused_resume(run, payload)
            except store.FlowSnapshotError:
                _mark_flow_run_failed(
                    run_id, "published flow release was revoked before resume",
                )
                return
        _run_in_payload_tenant(payload, _resume)
    except execution.FlowNotResumable:
        return  # already resumed/finished -- benign
    except Exception:
        log.exception("flow resume failed for %s", run_id)
        raise


def _handle_flow_sweep(_job=None) -> None:
    """Recover due legacy delays/expiries missed by durable continuation jobs.

    Normal pauses already schedule durable jobs. Keyset paging includes every
    due record regardless of newer completed history; stale resumes are no-ops.
    """
    from maverick import flow
    if not flow.enabled():
        return

    def _sweep_current_tenant() -> None:
        from maverick.flow import runner, store
        from maverick.flow.payloads import FlowPayloadError

        now = time.time()
        for run in store.iter_run_metadata(
            statuses={runner.STATUS_PAUSED_DELAY, runner.STATUS_PAUSED_APPROVAL},
            due_before=now,
        ):
            if run.status == runner.STATUS_PAUSED_DELAY:
                try:
                    enqueue_flow_resume(
                        run.flow_id, run.run_id, owner=run.owner,
                    )
                except (store.FlowSnapshotError, FlowPayloadError):
                    continue
            elif run.status == runner.STATUS_PAUSED_APPROVAL:
                # An approval whose node set an expiry resolves once it lapses.
                # The bound, due-time-checked expiry reservation lets the runner
                # route to the node's `on_expire` escalation lane if set; without
                # one it fails closed (rejected), never a silent approval.
                try:
                    enqueue_flow_resume(
                        run.flow_id,
                        run.run_id,
                        owner=run.owner,
                        expired=True,
                    )
                except (store.FlowSnapshotError, FlowPayloadError):
                    continue
            # paused_event runs are NEVER swept -- only their event resumes them.

    _run_for_active_tenants("flow delay sweep", _sweep_current_tenant)
    # Also re-sync per-flow cron schedules from the store, so a flow scheduled
    # (or unscheduled) after boot is armed/disarmed within a minute -- no restart.
    try:
        _reconcile_flow_crons()
    except Exception:  # pragma: no cover -- fail-open
        log.exception("flow cron reconcile failed")


def _handle_flow_evolve(_job=None) -> None:
    """Autonomous self-correction: for each rewritten flow node, measure its
    grounded outcomes before vs. after the change and REVERT it if it clearly
    regressed -- the arrow that lets the loop undo its own mistakes. Gated on
    ``[flows] auto_evolve`` (off by default); fail-open and idempotent (once a
    node is reverted its newest apply is the revert, so it's skipped next pass).
    The durable cron is process-global but definitions/evidence are tenant-scoped,
    therefore every pass is explicitly pinned to one namespace at a time."""

    _run_for_active_tenants("flow evolve pass", _evolve_current_tenant)


def _evolve_current_tenant() -> None:
    """Run one evolve/revert pass in the already-pinned namespace."""
    from maverick import flow as flow_mod

    if not flow_mod.auto_evolve_enabled():
        return
    from maverick.flow import evolution_log, evolve, store

    for f in store.list_flows():
        for node_id in list(f.nodes):
            last = evolution_log.last_apply(f.id, node_id)
            if not last or last.get("source") == "auto-revert":
                continue  # never applied, or already auto-reverted -> settled
            impact = evolve.measure(
                f.id,
                node_id,
                float(last.get("ts") or 0.0),
                before_revision=str(last.get("before_revision") or ""),
                after_revision=str(last.get("after_revision") or ""),
            )
            if not evolve.regressed(impact):
                continue
            apply_version = int(last.get("version") or 0)
            prior = store.load_version(f.id, apply_version - 1)
            applied = store.load_version(f.id, apply_version)
            if (
                prior is None
                or applied is None
                or node_id not in prior.nodes
                or node_id not in applied.nodes
                or node_id not in f.nodes
            ):
                continue
            # A later save no longer erases the measurement boundary. Preserve
            # all later edits and revert only when this node's work definition
            # still exactly matches what the learner applied.
            if not evolve.same_work_definition(
                f.nodes[node_id], applied.nodes[node_id]
            ):
                continue
            reverted = evolve.revert_node(f, node_id, prior.nodes[node_id])
            if reverted.validate():
                continue  # never save a structurally broken flow
            applied_kind = f.nodes[node_id].kind
            saved = _save_autonomous_flow_change(store, f, reverted)
            if saved is None:
                # A human or another learner won the race. Never overwrite
                # that newer definition with a stale measurement snapshot.
                continue
            evolution_log.record_apply(f.id, node_id, applied_kind,
                                       prior.nodes[node_id].kind, saved.version,
                                       source="auto-revert",
                                       before_revision=store.flow_cohort(f),
                                       after_revision=store.flow_cohort(saved))
            log.info("auto-reverted regressed rewrite: flow=%s node=%s (delta %.2f)",
                     f.id, node_id, impact.get("delta") or 0.0)
    if flow_mod.auto_apply_enabled():
        _auto_apply_proposals()


def _save_autonomous_flow_change(store, current, candidate):
    """Persist learning while preserving the active publication lifecycle."""
    try:
        published = store.load_published_bundle(current.id)
        if published is None:
            return store.save_flow(
                candidate,
                expected_version=current.version,
                expected_revision=current.revision,
            )
        _active_flow, release = published
        saved, _replacement = store.save_and_publish_flow(
            candidate,
            expected_version=current.version,
            expected_revision=current.revision,
            expected_release_id=str(release["release_id"]),
        )
        return saved
    except (store.FlowVersionConflict, store.FlowSnapshotError):
        # A human save/publish, a child edit, or a release revocation invalidates
        # the autonomous predecessor. Never activate or overwrite that change.
        return None


def _auto_apply_proposals() -> None:
    """Deliberately does nothing: automatic apply is retired.

    ``[flows] auto_apply`` is still read and still gates this call, but the
    knob has no effect: no proposal is applied without a person. Current
    proposals require human review of the work definition:

    * SOFTEN (action -> agent): action inputs do not establish replacement AI
      instructions. Preserve the fixed action until a person reviews them.
    * HARDEN (agent -> action): never auto-applied. Even when telemetry infers
      a likely tool, that inference is model-influenced and must remain a
      surfaced proposal for human review before it can persist a direct action.

    Suggestions remain visible through the native proposals reader. Automatic
    measured rollback in the preceding pass is unchanged."""
    return


def _handle_flow_cron(job=None) -> None:
    """Fire a scheduled flow on its cron cadence: enqueue a fresh flow run each
    occurrence. The worker re-arms the next occurrence (payload carries
    ``__cron__``). Re-check the flow still exists and still carries THIS schedule,
    so a schedule that was removed or changed stops firing immediately -- before
    the next reconcile() cancels the now-stale cron job. Durable occurrence
    identity deduplicates retries and pre-existing duplicate cron lineages."""
    payload = getattr(job, "payload", None) or {}
    flow_id = str(payload.get("flow_id") or "")
    if not flow_id:
        return
    scheduled_at = getattr(job, "scheduled_at", None)
    if (
        isinstance(scheduled_at, bool)
        or not isinstance(scheduled_at, (int, float))
        or not math.isfinite(scheduled_at)
    ):
        raise ValueError("flow cron requires a durable scheduled_at occurrence")
    try:
        def _fire() -> None:
            from maverick import flow as flow_mod
            if not flow_mod.enabled():
                return
            from maverick.flow import store
            published = store.load_published_bundle(flow_id)
            if published is None:
                return
            flow, release = published
            if (
                flow.schedule.strip()
                != str(payload.get("__cron__") or "").strip()
                or str(release["release_id"])
                != str(payload.get("__flow_revision__") or "")
            ):
                return  # unpublished, or a newer release superseded this cron
            # The release helper captures the tenant restored from this payload.
            import hashlib
            import json

            from maverick.paths import current_tenant_id

            occurrence_key = hashlib.sha256(json.dumps([
                current_tenant_id() or "", flow_id, release["release_id"],
                float(scheduled_at).hex(),
            ], separators=(",", ":")).encode()).hexdigest()
            enqueue_published_flow_run(
                flow_id,
                {},
                owner=flow.owner,
                origin=f"cron:{flow_id}",
                idem_key=f"cron-occurrence:{occurrence_key}",
                expected_revision=str(payload.get("__flow_revision__") or ""),
            )

        _run_in_payload_tenant(payload, _fire)
    except Exception:
        log.exception("scheduled flow run failed for %s", flow_id)
        raise  # the durable worker retries admission without duplicating a run


# ---- cron seeding -----------------------------------------------------------

def _pending(kind: str) -> list:
    return list(queue().iter_pending(kind))


@contextlib.contextmanager
def _cron_guard():
    from maverick.file_lock import cross_process_lock

    # Startup already holds _LOCK while reconciling. Keep that same order for
    # request/background reconciliation, whose body may call queue() again.
    with _LOCK, cross_process_lock(queue().db_path.with_suffix(".cron.lock"), strict=True):
        yield


def _ensure_cron(kind: str, expr: str) -> None:
    with _cron_guard():
        _ensure_cron_locked(kind, expr)


def _ensure_cron_locked(kind: str, expr: str) -> None:
    """Keep one recurrence lineage, including retries and its future successor."""
    from maverick.scheduler import schedule_cron
    q = queue()
    lineage = None
    for job in q.iter_pending(kind, include_running=True):
        current = job.recurrence_id or f"legacy:{job.id}"
        matches = str(job.payload.get("__cron__") or "").strip() == expr.strip()
        if matches and (lineage is None or current == lineage):
            lineage = current
        else:
            q.cancel(job.id)
    if lineage is None:
        schedule_cron(q, expr, kind, {"__cron__": expr})


def _reconcile_flow_crons() -> None:
    with _cron_guard():
        _reconcile_flow_crons_locked()


def _reconcile_flow_crons_locked() -> None:
    """Seed one ``flow_cron`` job per scheduled flow and cancel the crons of
    flows that lost (or changed) their schedule. Keyed by ``flow_id`` in the
    payload, expression tracked in ``__cron__``: a job whose flow no longer has
    the same schedule is stale and cancelled; a scheduled flow with no matching
    live cron gets one seeded. Idempotent -- safe to run on every reconcile."""
    from maverick.flow import store
    from maverick.scheduler import CronError, next_run, schedule_cron
    want: dict[tuple[str, str], tuple[str, str, str]] = {}

    def _collect_current_tenant() -> None:
        from maverick.paths import current_tenant_id

        tenant = current_tenant_id() or ""
        for f, release in store.list_published_bundles():
            expr = f.schedule.strip()
            if not expr:
                continue
            tz = f.timezone.strip()
            try:
                next_run(expr, tz=tz)  # only schedules with a future occurrence
            except CronError:
                continue
            want[(tenant, f.id)] = (
                expr, tz, str(release["release_id"]),
            )

    # Explicitly clear any ambient request/job tenant for the base pass, then
    # enumerate active named tenants. This prevents a reconcile invoked from a
    # tenant-scoped request from publishing that tenant's cron as tenantless.
    if not _run_for_active_tenants(
        "flow cron collection", _collect_current_tenant
    ):
        # An incomplete inventory is not authority to cancel durable schedules
        # that may belong to the tenant/store we could not read.
        return
    q = queue()
    covered: dict[tuple[str, str], str] = {}
    for j in q.iter_pending(FLOW_CRON_KIND, include_running=True):
        p = j.payload or {}
        fid = str(p.get("flow_id") or "")
        tenant = str(p.get("tenant") or "")
        key = (tenant, fid)
        cur = (
            str(p.get("__cron__") or ""),
            str(p.get("__tz__") or ""),
            str(p.get("__flow_revision__") or ""),
        )
        lineage = j.recurrence_id or f"legacy:{j.id}"
        if want.get(key) == cur and (key not in covered or covered[key] == lineage):
            covered[key] = lineage  # retain retries AND the surviving lineage's successor
        else:
            q.cancel(j.id)            # stale (flow unscheduled, schedule/tz changed, or dup)
    for (tenant, fid), (expr, tz, flow_revision) in want.items():
        if (tenant, fid) not in covered:
            try:
                payload = {
                    "flow_id": fid,
                    "__cron__": expr,
                    "__tz__": tz,
                    "__flow_revision__": flow_revision,
                }
                if tenant:
                    payload["tenant"] = tenant
                schedule_cron(q, expr, FLOW_CRON_KIND,
                              payload)
            except CronError:
                continue


def _dream_cron() -> str:
    try:
        expr = str((config.load_config().get("dreaming") or {}).get("cron") or "").strip()
        return expr or _DREAM_CRON_DEFAULT
    except Exception:  # pragma: no cover
        return _DREAM_CRON_DEFAULT


def refresh_runtime(request) -> None:
    """Apply in-product schedule changes while the dashboard owns its runtime.

    No workers are launched by offline API clients or during shutdown. The
    lifespan's existing supervisor continues to own any newly started workers.
    """
    supervisor = getattr(request.app.state, "lifecycle_supervisor", None)
    if supervisor is None or supervisor.phase != "running":
        return
    try:
        if start():
            reconcile()
    except Exception as exc:
        from fastapi import HTTPException

        log.exception("scheduled work could not apply saved settings")
        raise HTTPException(status_code=503, detail=(
            "Your settings were saved, but scheduled work could not be updated. "
            "Try saving again. If this continues, ask your administrator to check Lightwork."
        )) from exc


def nightly_learning_status() -> dict:
    """Tenant-local scheduled review receipts, with no customer content."""
    from maverick.audit import default_audit_log
    from maverick.self_improvement_runner import nightly_self_harness_enabled

    status = {"enabled": nightly_self_harness_enabled(), "state": "not_run", "when": None}
    try:
        rows = default_audit_log().tail(2000)
        event = next((row for row in reversed(rows)
                      if row.get("agent") == "self_harness_nightly"), None)
        if event is not None:
            phase = event.get("phase")
            status.update(state={"started": "running", "completed": "completed"}.get(phase, "stopped"),
                          when=event.get("ts"))
            for key in ("models_reviewed", "patterns_found", "improvements_adopted",
                        "improvements_retired", "reviews_held_back", "examples_prepared",
                        "inspection_only", "transfer_held_back"):
                if key in event:
                    status[key] = event[key]
    except Exception:
        status["state"] = "unavailable"
    return status


def _flywheel_cron() -> str:
    try:
        expr = str((config.load_config().get("data_engine") or {}).get("cron") or "").strip()
        return expr or _FLYWHEEL_CRON_DEFAULT
    except Exception:  # pragma: no cover
        return _FLYWHEEL_CRON_DEFAULT


def reconcile() -> None:
    """Seed the tick + dream + flywheel cron jobs for whichever subsystems are
    enabled."""
    from maverick import automation_events, data_engine, dreaming, flow
    from maverick.self_improvement_runner import nightly_self_harness_enabled
    if automation_events.enabled():
        _ensure_cron(TICK_KIND, _TICK_CRON)
    if dreaming.enabled() or nightly_self_harness_enabled():
        _ensure_cron(DREAM_KIND, _dream_cron())
    if data_engine.enabled():
        _ensure_cron(FLYWHEEL_KIND, _flywheel_cron())
    if flow.enabled():
        _repair_queued_flow_outbox()
        _ensure_cron(FLOW_SWEEP_KIND, _FLOW_SWEEP_CRON)
        _reconcile_flow_crons()
    if flow.auto_evolve_enabled():
        _ensure_cron(FLOW_EVOLVE_KIND, _FLOW_EVOLVE_CRON)
    # Governance assessments re-check daily whenever the automation worker runs.
    # Cheap and a no-op with an empty register; keeps accepted reviews honest
    # (drift) and surfaces overdue re-reviews without a human remembering to.
    _ensure_cron(ASSESS_SWEEP_KIND, _ASSESS_SWEEP_CRON)


# ---- lifecycle --------------------------------------------------------------

def _worker_count() -> int:
    v = _cfg_int("automation", "workers")
    return max(1, min(8, v)) if v else _DEFAULT_WORKERS


def start() -> bool:
    """Start the automation worker pool + seed cron jobs. No-op when none of
    event triggers, dreaming, the data engine, or flows is enabled, and
    idempotent. Returns whether the pool was started."""
    global _worker, _worker_threads, _worker_stopping
    from maverick import automation_events, data_engine, dreaming, flow
    from maverick.self_improvement_runner import nightly_self_harness_enabled
    from maverick.tenant.registry import list_tenants

    from .executive_report_schedules import KIND as report_kind
    from .executive_report_schedules import execute as execute_report
    from .third_party_executive_reports_composition import third_party_executive_reports_enabled

    try:
        report_enabled = any(third_party_executive_reports_enabled(row.id) for row in list_tenants()
                             if row.status == "active")
    except Exception:
        report_enabled = False
    if not (automation_events.enabled() or dreaming.enabled()
            or data_engine.enabled() or flow.enabled() or nightly_self_harness_enabled() or report_enabled):
        return False
    with _LOCK:
        if any(thread.is_alive() for thread in _worker_threads):
            return not _worker_stopping
        _worker, _worker_threads = None, []
        from maverick.worker import Worker
        w = Worker(queue=queue())
        w.register(TICK_KIND, _handle_tick)
        w.register(DREAM_KIND, _handle_dream)
        w.register(FLYWHEEL_KIND, _handle_flywheel)
        w.register(FLOW_RUN_KIND, _handle_flow_run)
        w.register(FLOW_RESUME_KIND, _handle_flow_resume)
        w.register(FLOW_SWEEP_KIND, _handle_flow_sweep)
        w.register(FLOW_EVOLVE_KIND, _handle_flow_evolve)
        w.register(FLOW_CRON_KIND, _handle_flow_cron)
        w.register(ASSESS_SWEEP_KIND, _handle_assess_sweep)
        from .app import app
        w.register(report_kind, lambda job: execute_report(app, job))
        # Seed the cron jobs + actually start the threads BEFORE committing to the
        # module globals, so a failure in reconcile() (e.g. a boot-time sqlite
        # write error) leaves us cleanly un-started and retryable -- not wedged
        # with recorded-but-never-started threads that stop() would join().
        reconcile()
        # One Worker, N threads sharing it: JobQueue.claim is atomic, so the
        # threads safely divide the jobs -- a slow run_goal on one thread can't
        # block the tick/dream on another.
        threads = [
            threading.Thread(target=w.run_forever, name=f"automation-worker-{i}", daemon=True)
            for i in range(_worker_count())
        ]
        _worker = w
        _worker_stopping = False
        try:
            for t in threads:
                t.start()
                _worker_threads.append(t)
        except BaseException:
            # Started writers remain owned even if a later thread failed to
            # start. Shutdown can observe them; a retry cannot overlap them.
            _worker_stopping = True
            w.stop()
            raise
    log.info("automation worker started (%d threads, db=%s)", len(threads), _db_path())
    return True


def stop(*, timeout: float = 5.0, wait: bool = True) -> None:
    global _worker, _worker_threads, _worker_stopping
    with _LOCK:
        w = _worker
        threads = list(_worker_threads)
        _worker_stopping = True
        if w is not None:
            w.stop()
    if not wait:
        return
    deadline = time.monotonic() + max(0.0, min(float(timeout), 30.0))
    for t in threads:
        t.join(timeout=max(0.0, deadline - time.monotonic()))
    with _LOCK:
        if _worker is w and not any(t.is_alive() for t in threads):
            _worker = None
            _worker_threads = []


__all__ = ["start", "stop", "reconcile", "queue",
           "TICK_KIND", "DREAM_KIND", "FLYWHEEL_KIND",
           "FLOW_RUN_KIND", "FLOW_RESUME_KIND", "FLOW_SWEEP_KIND", "FLOW_EVOLVE_KIND",
           "FLOW_CRON_KIND", "enqueue_flow_run", "enqueue_flow_run_once",
           "enqueue_published_flow_run", "enqueue_published_flow_run_once",
           "enqueue_flow_resume"]
