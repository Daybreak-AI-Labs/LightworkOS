"""One shutdown budget for all dashboard-owned background components."""
from __future__ import annotations

import asyncio
import logging
import math
import os
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial

from starlette.concurrency import run_in_threadpool

log = logging.getLogger(__name__)


def shutdown_seconds() -> float:
    """New total deadline wins; legacy drain timeout is the explicit fallback."""
    raw = os.environ.get("MAVERICK_SHUTDOWN_TIMEOUT")
    if raw is None:
        raw = os.environ.get("MAVERICK_DRAIN_TIMEOUT")
    if raw is None:
        from ._shared import dashboard_setting

        raw = dashboard_setting("MAVERICK_SHUTDOWN_TIMEOUT", "shutdown_timeout_seconds", 20)
    try:
        value = float(raw)
        if not math.isfinite(value) or not 0 <= value <= 300:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise ValueError("dashboard shutdown timeout must be finite and between 0 and 300 seconds") from exc
    return value


def _thread_alive(thread) -> bool:
    return thread is not None and thread.is_alive()


@dataclass
class Component:
    name: str
    signal: object
    wait: object
    alive: object


class ShutdownSupervisor:
    def __init__(self, timeout, *, clock=time.monotonic):
        self.timeout, self.clock = timeout, clock
        self.components = {}
        self.final_resources = {}
        self.phase = "starting"
        self.missed = []
        self.errors = []
        self.task = None
        self.resource_task = None
        self.deadline = None
        self.release_control_plane = False
        self.restart_requires_process_exit = False
        self.requests_quiescent = lambda: True

    def register(self, name, stop, alive):
        self.components[name] = Component(name, partial(stop, timeout=0, wait=False), stop, alive)

    def register_final_resource(self, name, stop, alive):
        self.final_resources[name] = Component(name, partial(stop, timeout=0, wait=False), stop, alive)

    def assert_restart_allowed(self):
        from maverick.runner import inflight_goals

        if (self.restart_requires_process_exit or (self.task is not None and not self.task.done())
                or (self.resource_task is not None and not self.resource_task.done()) or inflight_goals()
                or any(component.alive() for component in (*self.components.values(), *self.final_resources.values()))):
            raise RuntimeError("prior dashboard workers are still stopping; restart refused")

    def close_final_resources(self):
        # Database pools must remain usable while schedulers, goals or HTTP
        # requests finish their final writes. Lifespan exit is the HTTP barrier.
        for component in self.final_resources.values():
            try:
                component.signal()
            except Exception:
                self.errors.append(component.name)
                log.exception("final resource shutdown signal failed: %s", component.name)
        for component in self.final_resources.values():
            remaining = max(0.0, self.deadline - self.clock())
            if not remaining:
                break
            try:
                component.wait(timeout=remaining)
            except Exception:
                self.errors.append(component.name)
                log.exception("final resource cleanup failed: %s", component.name)
        self.missed.extend(item.name for item in self.final_resources.values() if item.alive())

    def shutdown(self, deadline):
        from maverick import runner

        runner.close_goal_admission()
        # Every signal is sent before the first join or drain. Signal callbacks
        # must not perform cleanup I/O; cleanup belongs to the wait phase.
        for component in self.components.values():
            try:
                component.signal()
            except Exception:
                self.errors.append(component.name)
                log.exception("shutdown signal failed: %s", component.name)
        for component in self.components.values():
            remaining = max(0.0, deadline - self.clock())
            if not remaining:
                break
            try:
                component.wait(timeout=min(remaining, 30.0))
            except Exception:
                self.errors.append(component.name)
                log.exception("shutdown cleanup failed: %s", component.name)
        left = runner.drain_inflight(max(0.0, deadline - self.clock()))
        self.missed = [component.name for component in self.components.values() if component.alive()]
        if left:
            self.missed.append("goals")
        if self.missed or self.errors:
            self.phase = "degraded"
            log.warning("shutdown incomplete: active=%s cleanup_errors=%s", self.missed, self.errors)

    def begin_shutdown(self):
        from maverick.runner import close_goal_admission

        if self.task is not None:
            return
        self.phase = "stopping"
        close_goal_admission()
        self.deadline = self.clock() + self.timeout
        # Keep ownership if a component's cleanup itself blocks. The lifespan
        # deadline does not cancel an OS thread or authorize replacement writers.
        self.task = asyncio.create_task(run_in_threadpool(self.shutdown, self.deadline))

        def finished(task):
            if not task.cancelled() and task.exception() is not None:
                self.phase = "degraded"
                self.errors.append("supervisor")
                log.error("dashboard shutdown supervisor failed: %s", type(task.exception()).__name__)

        self.task.add_done_callback(finished)

    async def stop(self):
        self.begin_shutdown()
        try:
            await asyncio.wait_for(asyncio.shield(self.task), max(0.0, self.deadline - self.clock()))
            if not self.requests_quiescent():
                self.restart_requires_process_exit = True
            if not self.missed and not self.errors and not self.restart_requires_process_exit:
                if self.resource_task is None:
                    self.resource_task = asyncio.create_task(run_in_threadpool(self.close_final_resources))
                await asyncio.wait_for(asyncio.shield(self.resource_task), max(0.0, self.deadline - self.clock()))
            if not self.missed and not self.errors and not self.restart_requires_process_exit:
                self.phase = "stopped"
            elif not self.missed and not self.errors:
                # Schedulers stopped, but a live HTTP request may still write:
                # pools stay open and the lease stays held until process exit.
                self.phase = "draining"
            # CLI request draining precedes lifespan shutdown. Do not release
            # the data-root lease merely because scheduler cleanup finished
            # while an existing HTTP request could still be writing.
            if self.phase == "stopped" and self.release_control_plane:
                from maverick.control_plane_lease import release

                try:
                    release()
                    self.release_control_plane = False
                except Exception:
                    self.phase = "degraded"
                    self.errors.append("control_plane")
                    log.exception("control-plane shutdown cleanup failed")
        except asyncio.TimeoutError:
            self.phase = "degraded"
            log.warning("dashboard shutdown deadline reached; worker ownership retained")
        except asyncio.CancelledError:
            self.phase = "degraded"
            log.warning("dashboard shutdown interrupted; worker ownership retained")
            raise


def register_main_components(app, supervisor):
    from . import learning_jobs

    learning_jobs.open_admission()
    supervisor.register("learning_jobs", learning_jobs.stop, learning_jobs.workers_alive)
    entries = [
        ("automation", "automation_queue", "stop", "_worker_threads"),
        ("orphan_recovery", "orphan_sweeper", "stop_orphan_sweeper", "_sweeper_thread"),
        ("security", "security_api", "stop_hunter_scheduler", "_hunter_scheduler_thread"),
        ("finance", "finance_scheduler", "stop_finance_scheduler", "_scheduler_thread"),
        ("red_team", "red_team_scheduler", "stop_red_team_scheduler", "_scheduler_thread"),
        ("shield_updates", "shield_update_scheduler", "stop_shield_update_scheduler",
         "_scheduler_thread"),
        ("ai_inventory", "ai_inventory_scheduler", "stop_ai_inventory_scheduler", "_scheduler_thread"),
        ("ai_cost", "ai_cost_scheduler", "stop_ai_cost_scheduler", "_scheduler_thread"),
        ("conversation_inbox", "conversation_inbox_scheduler", "stop_conversation_inbox_scheduler", "_threads"),
        ("knowledge_sources", "knowledge_sources_scheduler", "stop_knowledge_sources_scheduler", "_thread"),
        ("consent_delivery", "consent_delivery_scheduler", "stop_consent_delivery_scheduler", "_thread"),
        ("starter_teams", "starter_team_scheduler", "stop_starter_team_scheduler", "_thread"),
        ("personal_notifications", "personal_notification_scheduler", "stop_personal_notification_scheduler", "_scheduler_thread"),
        ("daily_digest", "daily_digest_scheduler", "stop_daily_digest_scheduler",
         "_scheduler_thread"),
        ("identity", "identity_governance_scheduler", "stop_identity_governance_scheduler", "_scheduler_thread"),
        ("data_use_checks", "data_use_scheduler", "stop_data_use_scheduler", "_scheduler_thread"),
        ("deadline_alerts", "deadline_alerts_scheduler", "stop_deadline_alerts_scheduler",
         "_scheduler_thread"),
        ("code_watch", "code_ops_api", "stop_watchers", "_watch_threads"),
        ("code_sessions", "repl_ops_api", "close_all_sessions", "_threads"),
        # Every child program: the Maintenance services and the programs a
        # setting starts (profiling, kernel monitor, model proxy).
        ("services", "service_supervisor", "stop_all", "_threads"),
    ]
    for name, module_name, stop_name, thread_name in entries:
        module_key = f"{__package__}.{module_name}"

        def stop(*, timeout, wait=True, module_key=module_key, stop_name=stop_name):
            # Register before startup without forcing optional module imports.
            # A module that never loaded could not start an owned worker; one
            # that loads later is still covered by this same stop callback.
            module = sys.modules.get(module_key)
            if module is not None:
                return getattr(module, stop_name)(timeout=timeout, wait=wait)
            return None

        def alive(module_key=module_key, field=thread_name):
            thread = getattr(sys.modules.get(module_key), field, None)
            return any(_thread_alive(item) for item in thread) if isinstance(thread, list) else _thread_alive(thread)

        supervisor.register(name, stop, alive)

    from maverick import postgres_transactions

    from . import voice_setup_api

    supervisor.register_final_resource("postgres_pools", postgres_transactions.close_postgres_pools,
                                       postgres_transactions.postgres_pools_pending)

    supervisor.register("voice", partial(voice_setup_api.stop_setup, app),
                        lambda: _thread_alive(getattr(app.state, "voice_warmup_thread", None)) or
                        _thread_alive(getattr(getattr(app.state, "voice_setup", None), "thread", None)))
    for name, attribute in (
        ("privacy_discovery", "privacy_data_discovery_worker_scheduler_runtime"),
        ("privacy_publication", "privacy_notice_publication_scheduler_runtime"),
    ):
        def stop(*, timeout, wait=True, attribute=attribute):
            runtime = getattr(app.state, attribute, None)
            if runtime is not None:
                return runtime.stop(timeout=timeout, wait=wait)
            return None

        supervisor.register(name, stop,
                            lambda attribute=attribute: _thread_alive(getattr(getattr(app.state, attribute, None), "_thread", None)))


@asynccontextmanager
async def supervised_runtime(app, name, runtime, *, scheduler=None):
    """Composed lifespans join the same supervisor; small embedders still work."""
    supervisor = getattr(app.state, "lifecycle_supervisor", None)
    if supervisor is not None:
        selected = scheduler if scheduler is not None else runtime
        supervisor.register(name, selected.stop, lambda: _thread_alive(selected._thread))
    try:
        await run_in_threadpool(runtime.start)
        yield
    finally:
        if supervisor is None:
            await run_in_threadpool(runtime.stop)
