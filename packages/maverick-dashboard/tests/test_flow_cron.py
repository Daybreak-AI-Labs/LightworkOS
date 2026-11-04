"""Cron-scheduled flows: a saved flow carrying a ``schedule`` cron expression is
armed as a recurring ``flow_cron`` job that fires a fresh flow run each tick."""
from __future__ import annotations

import threading
import types
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def _reset_aq(monkeypatch, aq):
    monkeypatch.setattr(aq, "_queue", None)
    monkeypatch.setattr(aq, "_worker", None)
    monkeypatch.setattr(aq, "_worker_threads", [])


def _save_flow(fid="digest", schedule="", *, publish=True):
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    f = Flow(id=fid, name="Digest", start="a",
             nodes={"a": FlowNode(id="a", kind="agent", brief="daily digest")})
    f.schedule = schedule
    saved = store.save_flow(f)
    if publish:
        store.publish_flow(
            fid,
            expected_version=saved.version,
            expected_revision=saved.revision,
        )
    return saved


def _cron_payload(fid="digest"):
    from maverick.flow import store

    flow, release = store.load_published_bundle(fid)
    return {
        "flow_id": fid,
        "__cron__": flow.schedule,
        "__tz__": flow.timezone,
        "__flow_revision__": release["release_id"],
    }


def test_reconcile_arms_one_cron_per_scheduled_flow(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "0 9 * * *")
    _save_flow("manual", "")                    # no schedule -> no cron
    aq._reconcile_flow_crons()
    crons = aq._pending(aq.FLOW_CRON_KIND)
    assert len(crons) == 1
    assert crons[0].payload["flow_id"] == "digest"
    assert crons[0].payload["__cron__"] == "0 9 * * *"


def test_reconcile_is_idempotent(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "0 9 * * *")
    aq._reconcile_flow_crons()
    aq._reconcile_flow_crons()                  # second pass must not duplicate
    assert len(aq._pending(aq.FLOW_CRON_KIND)) == 1


def test_reconcile_cancels_cron_when_schedule_removed(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "0 9 * * *")
    aq._reconcile_flow_crons()
    assert len(aq._pending(aq.FLOW_CRON_KIND)) == 1
    _save_flow("digest", "")                    # schedule cleared
    aq._reconcile_flow_crons()
    assert aq._pending(aq.FLOW_CRON_KIND) == []


def test_reconcile_reseeds_when_expression_changes(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "0 9 * * *")
    aq._reconcile_flow_crons()
    draft = _save_flow("digest", "0 17 * * *", publish=False)
    aq._reconcile_flow_crons()
    # Saving is authoring, not activation: the old release stays armed.
    crons = aq._pending(aq.FLOW_CRON_KIND)
    assert len(crons) == 1 and crons[0].payload["__cron__"] == "0 9 * * *"
    from maverick.flow import store
    store.publish_flow(
        draft.id,
        expected_version=draft.version,
        expected_revision=draft.revision,
    )
    aq._reconcile_flow_crons()
    crons = aq._pending(aq.FLOW_CRON_KIND)
    assert len(crons) == 1 and crons[0].payload["__cron__"] == "0 17 * * *"


def test_reconcile_skips_unarmable_schedule(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    draft = _save_flow("digest", "0 0 31 2 *", publish=False)
    from maverick.flow import store
    with pytest.raises(store.FlowSnapshotError, match="cannot be published"):
        store.publish_flow(
            draft.id,
            expected_version=draft.version,
            expected_revision=draft.revision,
        )
    aq._reconcile_flow_crons()
    assert aq._pending(aq.FLOW_CRON_KIND) == []


def test_handle_flow_cron_enqueues_a_fresh_run(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "0 9 * * *")
    job = types.SimpleNamespace(scheduled_at=1800000000.0, payload=_cron_payload())
    aq._handle_flow_cron(job)
    runs = aq._pending(aq.FLOW_RUN_KIND)
    assert len(runs) == 1 and runs[0].payload["flow_id"] == "digest"


def test_handle_flow_cron_noops_on_stale_schedule(monkeypatch, tmp_path):
    # The flow's schedule changed since this cron was armed -> don't fire.
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "0 17 * * *")
    stale = _cron_payload()
    stale["__cron__"] = "0 9 * * *"
    job = types.SimpleNamespace(scheduled_at=1800000000.0, payload=stale)
    aq._handle_flow_cron(job)
    assert aq._pending(aq.FLOW_RUN_KIND) == []


def test_named_tenant_cron_is_reconciled_and_fires_in_same_tenant(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.paths import reset_tenant, set_tenant
    from maverick.tenant import registry
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    registry.create_tenant("acme")
    tenant_token = set_tenant("acme")
    try:
        _save_flow("digest", "0 9 * * *")
    finally:
        reset_tenant(tenant_token)

    aq._reconcile_flow_crons()
    crons = aq._pending(aq.FLOW_CRON_KIND)
    assert len(crons) == 1 and crons[0].payload["tenant"] == "acme"

    aq._handle_flow_cron(types.SimpleNamespace(scheduled_at=1800000000.0, payload=crons[0].payload))
    runs = aq._pending(aq.FLOW_RUN_KIND)
    assert len(runs) == 1
    assert runs[0].payload["tenant"] == "acme"
    assert runs[0].payload["flow_id"] == "digest"


def test_reconcile_clears_ambient_tenant_before_shared_collection(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr("maverick.client.client_id", lambda: None)
    from maverick.paths import current_tenant_id, reset_tenant, set_tenant
    from maverick.tenant import registry
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    registry.create_tenant("acme")
    _save_flow("shared", "0 8 * * *")
    token = set_tenant("acme")
    try:
        _save_flow("private", "0 9 * * *")
        aq._reconcile_flow_crons()
        assert current_tenant_id() == "acme"
    finally:
        reset_tenant(token)

    payloads = {job.payload["flow_id"]: job.payload for job in aq._pending(aq.FLOW_CRON_KIND)}
    assert "tenant" not in payloads["shared"]
    assert payloads["private"]["tenant"] == "acme"


@pytest.mark.parametrize("backlog_kind", ["unrelated", "flow_cron"])
def test_reconcile_finds_existing_schedule_behind_large_backlog(monkeypatch, tmp_path, backlog_kind):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "0 9 * * *")
    aq._reconcile_flow_crons()
    original = aq._pending(aq.FLOW_CRON_KIND)[0]
    q = aq.queue()
    for _ in range(1005):
        q.enqueue(backlog_kind, {"flow_id": "deleted-flow"})
    aq._reconcile_flow_crons()
    crons = aq._pending(aq.FLOW_CRON_KIND)
    assert [job.id for job in crons] == [original.id]


def test_concurrent_reconcilers_seed_one_lineage(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "0 9 * * *")
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: aq._reconcile_flow_crons(), range(8)))
    assert len(aq._pending(aq.FLOW_CRON_KIND)) == 1


def test_startup_and_request_reconciliation_do_not_invert_locks(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import file_lock
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "0 9 * * *")
    file_owned, startup_attempted, worker_created = (threading.Event() for _ in range(3))

    class BoundedLock:
        # Bound only the test's lock wait so a regression fails without leaving
        # two permanently deadlocked threads in the rest of the test process.
        def __init__(self):
            self.lock = threading.RLock()

        def __enter__(self):
            if not self.lock.acquire(timeout=3):
                raise TimeoutError("startup/reconcile lock inversion")
            return self

        def __exit__(self, *_args):
            self.lock.release()

    native_fence = file_lock.cross_process_lock

    @contextmanager
    def fence(path, **kwargs):
        with native_fence(path, **kwargs):
            if threading.current_thread().name == "request-reconcile":
                file_owned.set()
                assert startup_attempted.wait(3)
                # Startup either owns the old outer lock (the bad ordering),
                # or waits behind this reconciler (the correct ordering).
                worker_created.wait(0.2)
            yield

    class Worker:
        def __init__(self, **_kwargs):
            worker_created.set()

        def register(self, *_args):
            pass

        def run_forever(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(aq, "_LOCK", BoundedLock())
    monkeypatch.setattr(file_lock, "cross_process_lock", fence)
    monkeypatch.setattr("maverick.worker.Worker", Worker)
    monkeypatch.setattr(aq, "reconcile", aq._reconcile_flow_crons)
    failures = []

    def run(startup=False):
        try:
            if startup:
                assert file_owned.wait(3)
                startup_attempted.set()
                assert aq.start()
            else:
                aq._reconcile_flow_crons()
        except Exception as exc:
            failures.append(exc)

    threads = [threading.Thread(target=run, name="request-reconcile"),
               threading.Thread(target=run, kwargs={"startup": True})]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(8)
        assert not thread.is_alive()
    aq.stop()
    assert failures == []
    assert len(aq._pending(aq.FLOW_CRON_KIND)) == 1


def test_duplicate_cron_lineages_and_retries_share_one_durable_flow_run(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "0 9 * * *")
    q = aq.queue()
    ids = [q.enqueue(aq.FLOW_CRON_KIND, _cron_payload(), run_at=1800000000) for _ in range(2)]
    jobs = [q.get(job_id) for job_id in ids]
    assert jobs[0].recurrence_id != jobs[1].recurrence_id
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(aq._handle_flow_cron, jobs))
    runs = aq._pending(aq.FLOW_RUN_KIND)
    assert len(runs) == 1
    run = store.load_run(runs[0].payload["run_id"])
    assert run.origin == "cron:digest"
    jobs[0].run_at += 60  # a queue retry has a different delivery time
    aq._handle_flow_cron(jobs[0])
    assert len(aq._pending(aq.FLOW_RUN_KIND)) == 1
    later = q.get(q.enqueue(aq.FLOW_CRON_KIND, _cron_payload(), run_at=1800000060))
    aq._handle_flow_cron(later)
    assert len(aq._pending(aq.FLOW_RUN_KIND)) == 2


@pytest.mark.parametrize("scheduled_at", [None, True, float("nan"), float("inf")])
def test_cron_refuses_missing_or_invalid_durable_occurrence(monkeypatch, tmp_path, scheduled_at):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "0 9 * * *")
    with pytest.raises(ValueError, match="durable scheduled_at"):
        aq._handle_flow_cron(types.SimpleNamespace(payload=_cron_payload(), scheduled_at=scheduled_at))
    assert not aq._pending(aq.FLOW_RUN_KIND)


def test_cron_admission_failure_retries_the_same_reservation(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "0 9 * * *")
    job = types.SimpleNamespace(payload=_cron_payload(), scheduled_at=1800000000)
    enqueue = aq.enqueue_published_flow_run

    def response_lost(*args, **kwargs):
        enqueue(*args, **kwargs)
        raise OSError("fixture response lost after commit")

    monkeypatch.setattr(aq, "enqueue_published_flow_run", response_lost)
    with pytest.raises(OSError, match="response lost"):
        aq._handle_flow_cron(job)
    monkeypatch.setattr(aq, "enqueue_published_flow_run", enqueue)
    aq._handle_flow_cron(job)
    assert len(aq._pending(aq.FLOW_RUN_KIND)) == 1


@pytest.mark.parametrize("flow_cron", [False, True])
def test_reconciliation_preserves_retry_and_future_successor(monkeypatch, tmp_path, flow_cron):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "* * * * *")
    kind = aq.FLOW_CRON_KIND if flow_cron else aq.TICK_KIND
    payload = _cron_payload() if flow_cron else {"__cron__": "* * * * *"}
    q = aq.queue()
    original = q.enqueue(kind, payload, run_at=0)
    job = q.claim(now=0)
    armed = q.rearm(job.id, expected_attempts=job.attempts, now=0)
    with monkeypatch.context() as frozen:
        frozen.setattr("maverick.job_queue.time.time", lambda: 10)
        assert q.fail(job.id, "transient admission failure", retry_after=0, expected_attempts=job.attempts)
    duplicate = q.enqueue(kind, payload, run_at=60)
    if flow_cron:
        aq._reconcile_flow_crons()
    else:
        aq._ensure_cron(kind, "* * * * *")
    assert q.get(duplicate) is None
    assert [j.id for j in aq._pending(kind)] == [original, armed.successor_id]
    retry = q.claim(now=10)
    assert retry.id == original
    assert q.rearm(retry.id, expected_attempts=retry.attempts, now=10).successor_id == armed.successor_id
    q.complete(retry.id, expected_attempts=retry.attempts)
    assert [j.id for j in aq._pending(kind)] == [armed.successor_id]


@pytest.mark.parametrize("flow_cron", [False, True])
def test_reconciliation_does_not_seed_a_second_lineage_while_first_is_claimed(monkeypatch, tmp_path, flow_cron):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    _save_flow("digest", "* * * * *")
    kind = aq.FLOW_CRON_KIND if flow_cron else aq.TICK_KIND
    payload = _cron_payload() if flow_cron else {"__cron__": "* * * * *"}
    q = aq.queue()
    original = q.enqueue(kind, payload, run_at=0)
    job = q.claim(now=0)
    assert job.id == original
    if flow_cron:
        aq._reconcile_flow_crons()
    else:
        aq._ensure_cron(kind, "* * * * *")
    assert aq._pending(kind) == []
    armed = q.rearm(job.id, expected_attempts=job.attempts, now=0)
    assert [j.id for j in aq._pending(kind)] == [armed.successor_id]
