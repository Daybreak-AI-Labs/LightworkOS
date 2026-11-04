"""CLI server adapter starts the shared budget before ASGI connection drain."""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import threading

import uvicorn

log = logging.getLogger(__name__)
DESKTOP_DRAIN = b"LIGHTWORK_DESKTOP_DRAIN_V1\n"


def _read_desktop_control(stream, ready, loop, request_shutdown):
    """Only the spawning desktop holds this stdin pipe; no HTTP authority."""
    try:
        command = stream.readline(128)
        if command not in (DESKTOP_DRAIN, b""):
            log.warning("ignored invalid owned desktop control message")
            return
        # EOF means the owning shell exited. Never invoke shutdown halfway
        # through Uvicorn startup, whose early-exit path skips its lifespan.
        ready.wait()
        if not loop.is_closed():
            loop.call_soon_threadsafe(request_shutdown)
    except (OSError, ValueError, RuntimeError):
        log.warning("owned desktop control channel closed")
    finally:
        stream.close()


class DashboardServer(uvicorn.Server):
    def __init__(self, app, **kwargs):
        super().__init__(uvicorn.Config(app, **kwargs))
        self.dashboard_app = app
        # Consume this child-only launch marker before tools can inherit it.
        self.desktop_control = os.environ.pop("MAVERICK_DESKTOP_CONTROL", "") == "stdin-v1"
        self.control_ready = threading.Event()
        if not self.desktop_control:
            # Settings > Maintenance may ask a supervised copy to restart.
            from .dashboard_restart import register_server
            register_server(app, self)

    async def serve(self, sockets=None):
        if self.desktop_control:
            try:
                # A private raw duplicate avoids a daemon reader holding the
                # interpreter's buffered stdin lock during unrelated SIGTERM.
                stream = os.fdopen(os.dup(sys.stdin.fileno()), "rb", buffering=0)
                # Helpers this server starts (PowerShell, tool workers) inherit
                # standard input: one reading the owned pipe waited until the
                # desktop exited, or took its drain. Give them an empty pipe,
                # not the null device, which Windows reports as a terminal and
                # would send consent prompts to a console nobody sees.
                empty, writer = os.pipe()
                os.close(writer)
                try:
                    os.dup2(empty, sys.stdin.fileno())
                finally:
                    os.close(empty)
            except (AttributeError, OSError, ValueError) as exc:
                raise RuntimeError("owned desktop control pipe is unavailable") from exc
            threading.Thread(target=_read_desktop_control,
                             args=(stream, self.control_ready, asyncio.get_running_loop(), self.request_desktop_shutdown),
                             name="desktop-control", daemon=True).start()
        try:
            await super().serve(sockets=sockets)
        finally:
            self.control_ready.set()

    async def startup(self, sockets=None):
        await super().startup(sockets=sockets)
        self.control_ready.set()

    def request_desktop_shutdown(self):
        supervisor = getattr(self.dashboard_app.state, "lifecycle_supervisor", None)
        if supervisor is not None:
            supervisor.release_control_plane = False
            supervisor.begin_shutdown()
        log.info("owned desktop requested graceful dashboard shutdown")
        self.should_exit = True

    async def shutdown(self, sockets=None):
        supervisor = getattr(self.dashboard_app.state, "lifecycle_supervisor", None)
        requests = list(self.server_state.tasks)
        if supervisor is not None:
            # A cancelled ASGI task may still own a synchronous worker. The CLI
            # retains its process lease until OS exit, even after lifespan ends.
            supervisor.release_control_plane = False
            # Evaluated by lifespan before closing shared DB resources; a
            # cancelled ASGI request may still own its synchronous DB writer.
            supervisor.requests_quiescent = lambda: all(task.done() and not task.cancelled() for task in requests)
            supervisor.begin_shutdown()
            # Give short responses one second to finish, within the same total
            # deadline. Long SSE/read requests then release their stream slots
            # on cancellation while durable goals continue their bounded drain.
            self.config.timeout_graceful_shutdown = min(1.0, max(0.0, supervisor.deadline - supervisor.clock()))
        await super().shutdown(sockets=sockets)
        if supervisor is not None and any(not task.done() or task.cancelled() for task in requests):
            # Do not infer that cancelling a request stopped its external write.
            supervisor.restart_requires_process_exit = True


def run_dashboard_server(app, **kwargs):
    server = DashboardServer(app, **kwargs)
    # Match uvicorn.run's object-app single-worker/startup-failure contract.
    # WEB_CONCURRENCY must not silently create unsupported control planes.
    if server.config.reload or server.config.workers != 1:
        raise SystemExit(3)
    try:
        server.run()
    except KeyboardInterrupt:
        pass
    if not server.started:
        raise SystemExit(3)
    from .dashboard_restart import RESTART_EXIT_CODE, requested
    if requested():
        # A failure code, so the supervisor that runs this copy starts it again.
        raise SystemExit(RESTART_EXIT_CODE)
