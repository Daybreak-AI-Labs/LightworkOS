"""One deadline, signal-before-join, retained writers and partial-start cleanup."""
from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace

import pytest
from maverick import runner
from maverick_dashboard._lifecycle import ShutdownSupervisor, shutdown_seconds, supervised_runtime


@pytest.fixture(autouse=True)
def _isolate_starter_team_admission(monkeypatch):
    from maverick import starter_team_runtime
    from maverick_dashboard import starter_team_scheduler

    monkeypatch.setattr(starter_team_runtime, "_worker_authorizer", None)
    monkeypatch.setattr(starter_team_scheduler, "_stopping", False)


def test_all_signals_precede_joins_and_one_deadline_bounds_many_workers():
    clock = SimpleNamespace(now=0.0)
    order = []
    supervisor = ShutdownSupervisor(20, clock=lambda: clock.now)
    for index in range(8):
        def stop(*, timeout, wait=True, index=index):
            order.append(("join" if wait else "signal", index))
            if wait:
                clock.now += timeout
        supervisor.register(str(index), stop, lambda: True)
    supervisor.shutdown(20)
    assert order[:8] == [("signal", index) for index in range(8)]
    assert order[8:] == [("join", 0)]
    assert clock.now == 20 and supervisor.phase == "degraded"
    assert len(supervisor.missed) == 8
    assert not runner._accepting_goals
    with pytest.raises(RuntimeError, match="still stopping"):
        supervisor.assert_restart_allowed()


def test_cleanup_that_ignores_its_timeout_does_not_extend_async_lifespan_deadline():
    entered, release = threading.Event(), threading.Event()
    supervisor = ShutdownSupervisor(0.05)

    def stop(*, timeout, wait=True):
        if wait:
            entered.set()
            assert release.wait(3)

    supervisor.register("blocked_cleanup", stop, lambda: False)

    async def run():
        started = time.monotonic()
        try:
            await supervisor.stop()
            assert time.monotonic() - started < 0.5
            assert entered.is_set() and supervisor.phase == "degraded"
            with pytest.raises(RuntimeError, match="still stopping"):
                supervisor.assert_restart_allowed()
        finally:
            release.set()
        await supervisor.task
        supervisor.assert_restart_allowed()
    asyncio.run(run())


def test_composed_lifespans_register_before_partial_start_and_wait_for_central_shutdown():
    order = []
    supervisor = ShutdownSupervisor(1)
    app = SimpleNamespace(state=SimpleNamespace(lifecycle_supervisor=supervisor))

    class Runtime:
        _thread = None

        def __init__(self, name, fails=False):
            self.name, self.fails = name, fails

        def start(self):
            order.append(("start", self.name))
            if self.fails:
                raise RuntimeError("partial startup")

        def stop(self, *, timeout, wait=True):
            order.append(("join" if wait else "signal", self.name))

    async def run():
        with pytest.raises(RuntimeError, match="partial startup"):
            async with supervised_runtime(app, "first", Runtime("first")):
                async with supervised_runtime(app, "second", Runtime("second", True)):
                    pytest.fail("failed startup yielded")
        assert order == [("start", "first"), ("start", "second")]
        await supervisor.stop()
        assert order[2:] == [("signal", "first"), ("signal", "second"), ("join", "first"), ("join", "second")]
        assert supervisor.phase == "stopped"
    asyncio.run(run())


def test_cancelled_lifespan_keeps_cleanup_owned_until_exit():
    entered, release = threading.Event(), threading.Event()
    supervisor = ShutdownSupervisor(1)

    def stop(*, timeout, wait=True):
        if wait:
            entered.set()
            assert release.wait(3)

    supervisor.register("cleanup", stop, lambda: False)

    async def run():
        pending = asyncio.create_task(supervisor.stop())
        try:
            assert await asyncio.to_thread(entered.wait, 1)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            assert supervisor.phase == "degraded"
            with pytest.raises(RuntimeError, match="still stopping"):
                supervisor.assert_restart_allowed()
        finally:
            release.set()
        await supervisor.task
        supervisor.assert_restart_allowed()
    asyncio.run(run())


def test_finance_stop_start_cannot_overlap_a_blocked_writer(monkeypatch):
    from maverick import config
    from maverick_dashboard import finance_scheduler as scheduler

    entered, release = threading.Event(), threading.Event()
    monkeypatch.setattr(config, "load_global_config", lambda: {"finance_operations": {"enable": True}})
    monkeypatch.setattr(config, "config_source_errors", lambda **_kwargs: [])
    monkeypatch.setattr(scheduler, "_scheduler_stop", None)
    monkeypatch.setattr(scheduler, "_scheduler_thread", None)

    def blocked(*_args):
        entered.set()
        assert release.wait(3)

    monkeypatch.setattr(scheduler, "_scheduler_loop", blocked)
    assert scheduler.start_finance_scheduler()
    assert entered.wait(1)
    original = scheduler._scheduler_thread
    try:
        assert not scheduler.stop_finance_scheduler(timeout=0.001)
        assert scheduler._scheduler_thread is original and scheduler._scheduler_stop.is_set()
        assert not scheduler.start_finance_scheduler()
        assert scheduler._scheduler_thread is original
    finally:
        release.set()
        assert scheduler.stop_finance_scheduler(timeout=1)
    assert scheduler._scheduler_thread is None


@pytest.mark.parametrize("value", ["nan", "inf", "-1", "301", "", "garbage"])
def test_invalid_total_timeout_refuses_startup(monkeypatch, value):
    monkeypatch.setenv("MAVERICK_SHUTDOWN_TIMEOUT", value)
    with pytest.raises(ValueError, match="finite"):
        shutdown_seconds()


def test_total_timeout_precedence_and_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_SHUTDOWN_TIMEOUT", raising=False)
    monkeypatch.delenv("MAVERICK_DRAIN_TIMEOUT", raising=False)
    assert shutdown_seconds() == 20
    monkeypatch.setenv("MAVERICK_DRAIN_TIMEOUT", "12")
    assert shutdown_seconds() == 12
    monkeypatch.setenv("MAVERICK_SHUTDOWN_TIMEOUT", "0")
    assert shutdown_seconds() == 0


@pytest.mark.parametrize("boundary", ["authentication", "startup"])
def test_actual_base_lifespan_cleans_partial_start_and_preserves_boundary_refusal(monkeypatch, boundary):
    from fastapi import FastAPI
    from maverick import control_plane_lease, deployment, installation_recovery, residency
    from maverick_dashboard import _lifecycle
    from maverick_dashboard import app as app_module

    calls = []
    monkeypatch.setattr(installation_recovery, "assert_normal_start_allowed", lambda: None)
    monkeypatch.setattr(deployment, "require_enterprise_or_die", lambda: None)
    monkeypatch.setattr(residency, "require_residency_or_die", lambda: None)
    monkeypatch.setattr(control_plane_lease, "current", lambda: None)
    monkeypatch.setattr(control_plane_lease, "acquire", lambda **_kwargs: calls.append("acquire"))
    monkeypatch.setattr(control_plane_lease, "release", lambda: calls.append("release"))

    def register(_app, supervisor):
        def stop(*, timeout, wait=True):
            calls.append("join" if wait else "signal")
        supervisor.register("already_started", stop, lambda: False)

    def authenticate():
        if boundary == "authentication":
            raise RuntimeError("mandatory authentication refusal")

    async def reclaim():
        calls.append("reclaim")

    async def fail_start():
        raise RuntimeError("partial startup refusal")

    monkeypatch.setattr(_lifecycle, "register_main_components", register)
    monkeypatch.setattr(app_module, "_assert_dashboard_auth_configured", authenticate)
    monkeypatch.setattr(app_module, "_reclaim_orphans", reclaim)
    monkeypatch.setattr(app_module, "_install_queue_dispatcher", fail_start)

    async def run():
        application = FastAPI()
        with pytest.raises(RuntimeError, match="refusal"):
            async with app_module._lifespan(application):
                pytest.fail("failed startup yielded")
        assert calls == (["acquire"] + (["reclaim"] if boundary == "startup" else [])
                         + ["signal", "join", "release"])
        assert application.state.lifecycle_supervisor.phase == "stopped"
        assert not runner._accepting_goals
    asyncio.run(run())


def test_managed_local_server_stops_only_after_admission_closes_and_goals_drain(monkeypatch):
    from fastapi import FastAPI
    from maverick import control_plane_lease, deployment, installation_recovery, residency
    from maverick_dashboard import _lifecycle, local_runtime_service
    from maverick_dashboard import app as app_module

    calls = []
    monkeypatch.setattr(installation_recovery, "assert_normal_start_allowed", lambda: None)
    monkeypatch.setattr(deployment, "require_enterprise_or_die", lambda: None)
    monkeypatch.setattr(residency, "require_residency_or_die", lambda: None)
    monkeypatch.setattr(control_plane_lease, "current", lambda: None)
    monkeypatch.setattr(control_plane_lease, "acquire", lambda **_kwargs: None)
    monkeypatch.setattr(control_plane_lease, "release", lambda: None)
    monkeypatch.setattr(runner, "drain_inflight", lambda timeout: calls.append("drain") or 0)
    monkeypatch.setattr(_lifecycle, "register_main_components", lambda _app, _supervisor: None)
    monkeypatch.setattr(local_runtime_service, "shutdown",
                        lambda: calls.append(("local_ai", runner._accepting_goals)))

    async def fail_start():
        raise RuntimeError("partial startup refusal")

    monkeypatch.setattr(app_module, "_assert_dashboard_auth_configured", lambda: None)
    monkeypatch.setattr(app_module, "_reclaim_orphans", lambda: asyncio.sleep(0))
    monkeypatch.setattr(app_module, "_install_queue_dispatcher", fail_start)

    async def run():
        with pytest.raises(RuntimeError, match="refusal"):
            async with app_module._lifespan(FastAPI()):
                pytest.fail("failed startup yielded")
        # Goals running against the managed server finish before it is stopped,
        # and nothing new is admitted while it goes.
        assert calls == ["drain", ("local_ai", False)]
    asyncio.run(run())


def test_shutdown_refuses_new_http_work_and_readiness_but_keeps_liveness(monkeypatch):
    from fastapi.testclient import TestClient
    from maverick_dashboard.app import app

    monkeypatch.setattr(app.state, "lifecycle_supervisor", SimpleNamespace(phase="stopping"), raising=False)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get("/readyz").status_code == 503
    assert client.get("/api/v1/facts").status_code == 503
    assert client.get("/livez").status_code == 200


def test_actual_composed_dashboard_registers_all_default_components():
    from fastapi.testclient import TestClient
    from maverick_dashboard.app import app

    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}):
        supervisor = app.state.lifecycle_supervisor
        assert set(supervisor.components) == {
            "automation", "orphan_recovery", "security", "finance", "red_team", "shield_updates", "ai_inventory",
            "ai_cost", "daily_digest", "identity", "data_use_checks", "deadline_alerts",
            "voice", "privacy_discovery", "privacy_publication", "ai_governance",
            "consent_scan", "consent_delivery", "trc_evidence", "data_use_audit", "unified_audit", "third_party_feed",
            "code_watch", "code_sessions", "services",
            "conversation_inbox", "knowledge_sources", "personal_notifications", "learning_jobs", "starter_teams",
        }
        assert supervisor.phase == "running"
    assert supervisor.phase == "stopped" and not supervisor.errors
    assert not runner._accepting_goals


def test_optional_drop_lifespan_joins_the_same_supervisor(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from maverick_dashboard.app import app
    from maverick_dashboard.privacy_drop_management_scheduler import (
        DROPManagedMaintenanceScheduler,
        attach_drop_managed_scheduler,
    )

    # DROP attaches only when explicitly configured at composition time.
    # Retain the actual base/composed lifespans and restore this optional wrapper.
    monkeypatch.setattr(app.router, "lifespan_context", app.router.lifespan_context)
    monkeypatch.setattr(app.state, "privacy_drop_management_scheduler", None, raising=False)
    runtime = DROPManagedMaintenanceScheduler(tmp_path / "drop.sqlite3", cycle_runner=lambda: None, enabled=False)
    attach_drop_managed_scheduler(app, runtime)
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}):
        supervisor = app.state.lifecycle_supervisor
        assert "drop_management" in supervisor.components
    assert supervisor.phase == "stopped" and not supervisor.errors


def test_privacy_discovery_adapter_uses_its_actual_owned_runtime_attribute():
    from maverick_dashboard._lifecycle import register_main_components

    calls = []
    runtime = SimpleNamespace(_thread=SimpleNamespace(is_alive=lambda: True),
                              stop=lambda **kwargs: calls.append(kwargs))
    app = SimpleNamespace(state=SimpleNamespace(privacy_data_discovery_worker_scheduler_runtime=runtime))
    supervisor = ShutdownSupervisor(1)
    register_main_components(app, supervisor)
    component = supervisor.components["privacy_discovery"]
    assert component.alive()
    component.signal()
    component.wait(timeout=0.5)
    assert calls == [{"timeout": 0, "wait": False}, {"timeout": 0.5, "wait": True}]


def test_real_uvicorn_shutdown_and_lifespan_share_the_original_deadline():
    from maverick_dashboard._server import DashboardServer

    supervisor = ShutdownSupervisor(0.25)
    events = []

    def stop(*, timeout, wait=True):
        events.append("join" if wait else "signal")
        if wait:
            time.sleep(timeout)

    supervisor.register("blocked", stop, lambda: True)
    app = SimpleNamespace(state=SimpleNamespace(lifecycle_supervisor=supervisor))
    server = DashboardServer(app, log_config=None)
    server.servers = []  # drive Uvicorn's real shutdown without opening a socket

    async def lifespan_shutdown():
        original_deadline = supervisor.deadline
        assert supervisor.phase in {"stopping", "degraded"}
        assert not runner._accepting_goals
        await supervisor.stop()
        assert supervisor.deadline == original_deadline

    server.lifespan = SimpleNamespace(shutdown=lifespan_shutdown)

    async def run():
        started = time.monotonic()
        await server.shutdown()
        assert time.monotonic() - started < 0.65
        await supervisor.task
        assert events == ["signal", "join"]
        assert supervisor.phase == "degraded"
    asyncio.run(run())


def test_finishing_scheduler_cleanup_does_not_reopen_http_admission_before_lifespan_exit():
    supervisor = ShutdownSupervisor(1)

    async def run():
        supervisor.begin_shutdown()
        await supervisor.task
        assert supervisor.phase == "stopping"
        await supervisor.stop()
        assert supervisor.phase == "stopped"
    asyncio.run(run())


def test_final_resources_stay_usable_until_http_and_goal_drain_complete():
    supervisor = ShutdownSupervisor(1)
    calls = []
    supervisor.register("worker", lambda **kwargs: calls.append(("worker", kwargs)), lambda: False)
    supervisor.register_final_resource("pool", lambda **kwargs: calls.append(("pool", kwargs)), lambda: False)

    async def run():
        supervisor.begin_shutdown()
        await supervisor.task
        assert [name for name, _kwargs in calls] == ["worker", "worker"]
        await supervisor.stop()
        assert [name for name, _kwargs in calls] == ["worker", "worker", "pool", "pool"]
        assert calls[-1][1]["timeout"] <= 1
        assert supervisor.phase == "stopped"
    asyncio.run(run())


@pytest.mark.parametrize("pending_request", [False, True])
def test_resources_not_closed_under_unfinished_callers(pending_request):
    supervisor = ShutdownSupervisor(1)
    supervisor.restart_requires_process_exit = pending_request
    if not pending_request:
        supervisor.register("worker", lambda **_kwargs: None, lambda: True)
    supervisor.register_final_resource("pool", lambda **_kwargs: pytest.fail("pool still owned"), lambda: False)
    asyncio.run(supervisor.stop())
    assert supervisor.resource_task is None


def test_uvicorn_forced_request_cancel_retains_process_ownership_and_refuses_in_process_restart():
    from maverick_dashboard._server import DashboardServer

    supervisor = ShutdownSupervisor(0.05)
    supervisor.release_control_plane = True
    supervisor.register_final_resource("pool", lambda **_kwargs: pytest.fail("cancelled request still owns pool"), lambda: False)
    app = SimpleNamespace(state=SimpleNamespace(lifecycle_supervisor=supervisor))
    server = DashboardServer(app, log_config=None)
    server.servers = []
    server.lifespan = SimpleNamespace(shutdown=supervisor.stop)

    async def run():
        request = asyncio.create_task(asyncio.Event().wait())
        server.server_state.tasks.add(request)
        await server.shutdown()
        await asyncio.gather(request, return_exceptions=True)
        assert request.cancelled()
        assert not supervisor.release_control_plane
        assert supervisor.restart_requires_process_exit
        with pytest.raises(RuntimeError, match="still stopping"):
            supervisor.assert_restart_allowed()
    asyncio.run(run())


@pytest.mark.parametrize("workers,started", [(1, False), (2, True)])
def test_cli_server_retains_nonzero_startup_failure_and_single_worker_contract(monkeypatch, workers, started):
    from maverick_dashboard import _server

    calls = []
    server = SimpleNamespace(config=SimpleNamespace(workers=workers, reload=False), started=started,
                             run=lambda: calls.append("run"))
    monkeypatch.setattr(_server, "DashboardServer", lambda *_args, **_kwargs: server)
    with pytest.raises(SystemExit) as error:
        _server.run_dashboard_server(None)
    assert error.value.code == 3
    assert calls == (["run"] if workers == 1 else [])


def test_automation_partial_thread_start_retains_and_signals_owned_workers(monkeypatch):
    from maverick import flow, worker
    from maverick_dashboard import automation_queue as queue

    monkeypatch.setattr(flow, "enabled", lambda: True)
    monkeypatch.setattr(queue, "_worker_threads", [])
    monkeypatch.setattr(queue, "_worker", None)
    monkeypatch.setattr(queue, "_worker_stopping", False)
    monkeypatch.setattr(queue, "_worker_count", lambda: 2)
    monkeypatch.setattr(queue, "reconcile", lambda: None)
    monkeypatch.setattr(queue, "queue", lambda: None)
    workers = []

    class Worker:
        def __init__(self, **_kwargs):
            self.stopped = False
            workers.append(self)

        def register(self, *_args):
            pass

        def run_forever(self):
            pass

        def stop(self):
            self.stopped = True

    threads = []

    class Thread:
        def __init__(self, **_kwargs):
            self.alive = False
            threads.append(self)

        def start(self):
            if len([thread for thread in threads if thread.alive]):
                raise RuntimeError("synthetic second thread start failure")
            self.alive = True

        def is_alive(self):
            return self.alive

        def join(self, *, timeout):
            self.alive = False

    monkeypatch.setattr(worker, "Worker", Worker)
    monkeypatch.setattr(queue, "threading", SimpleNamespace(Thread=Thread))
    with pytest.raises(RuntimeError, match="second thread"):
        queue.start()
    assert queue._worker_threads == [threads[0]] and workers[0].stopped
    assert not queue.start()  # still owned, though startup failed
    queue.stop(timeout=0)
    assert queue._worker is None and queue._worker_threads == []


def test_live_requests_report_draining_not_stopped():
    """Regression: with a live HTTP request the pools stay open and the lease
    stays held, so the supervisor must not report "stopped"."""
    supervisor = ShutdownSupervisor(1)
    supervisor.release_control_plane = True
    supervisor.requests_quiescent = lambda: False
    supervisor.register_final_resource("pool", lambda **_kw: pytest.fail("pool still owned"), lambda: False)
    asyncio.run(supervisor.stop())
    assert supervisor.phase == "draining"
    assert supervisor.release_control_plane  # lease not released
    with pytest.raises(RuntimeError, match="still stopping"):
        supervisor.assert_restart_allowed()
